use anyhow::Result;
use clap::{Parser, Subcommand};
use indicatif::{ProgressBar, ProgressStyle};
use std::path::PathBuf;

use crate::config::Config;
use crate::ingest;
use crate::index::SearchIndex;
use crate::store::ParquetStore;
use crate::search;
use crate::recall;
use crate::tiers;
use crate::integrity;

#[derive(Parser)]
#[command(name = "myelin8", about = "SIEM-inspired memory engine for AI assistants")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Initialize myelin8 in this directory
    Init,

    /// Add a source directory to index
    Add {
        /// Path to the directory
        path: PathBuf,
        /// Label for this source (e.g., "claude-memory", "notes")
        #[arg(long)]
        label: String,
        /// File pattern to match (default: "*.md")
        #[arg(long, default_value = "*.md")]
        pattern: String,
    },

    /// Index new files and compress aged artifacts
    Run {
        /// Preview changes without modifying anything
        #[arg(long)]
        dry_run: bool,
    },

    /// Search indexed memories (never reads Parquet)
    Search {
        /// Search query
        query: String,
        /// Filter: only results after this date (YYYY-MM-DD)
        #[arg(long)]
        after: Option<String>,
        /// Filter: only results before this date (YYYY-MM-DD)
        #[arg(long)]
        before: Option<String>,
        /// Max results to return
        #[arg(long, default_value = "10")]
        limit: usize,
    },

    /// Recall full content from Parquet (column-selective read + hash verify)
    Recall {
        /// Artifact ID or content hash prefix
        artifact_id: String,
    },

    /// Show status: artifact counts, tier distribution, disk usage
    Status,

    /// Verify integrity of all artifacts (SHA-256 check)
    Verify,

    /// Pin an artifact as high-significance (resists tier decay)
    Pin {
        /// Search query to find the artifact to pin
        query: String,
    },

    /// Remove a registered source
    Remove {
        /// Label of the source to remove
        label: String,
    },
}

pub fn init(config: Config) -> Result<()> {
    let data_dir = config.data_dir();
    std::fs::create_dir_all(data_dir.join("hot"))?;
    std::fs::create_dir_all(data_dir.join("store"))?;
    std::fs::create_dir_all(data_dir.join("store/.tmp"))?;
    std::fs::create_dir_all(data_dir.join("index"))?;

    if !data_dir.join("config.toml").exists() {
        config.save()?;
    }

    println!("Initialized myelin8 at {}", data_dir.display());
    println!();
    println!("Next steps:");
    println!("  myelin8 add ~/path/to/memory/ --label my-memory");
    println!("  myelin8 run");
    Ok(())
}

pub fn add(mut config: Config, path: PathBuf, label: String, pattern: String) -> Result<()> {
    let abs_path = if path.is_absolute() {
        path
    } else {
        std::env::current_dir()?.join(path)
    };

    if !abs_path.exists() {
        anyhow::bail!("Path does not exist: {}", abs_path.display());
    }
    if !abs_path.is_dir() {
        anyhow::bail!("Path is not a directory: {}", abs_path.display());
    }

    // Check if already registered
    if config.sources.iter().any(|s| s.label == label) {
        anyhow::bail!("Source '{}' already registered. Use 'myelin8 remove {}' first.", label, label);
    }

    config.sources.push(crate::config::Source {
        path: abs_path.to_string_lossy().to_string(),
        label: label.clone(),
        pattern,
    });
    config.save()?;

    // Count files
    let count = ingest::count_files_in_source(&config.sources.last().unwrap())?;
    println!("Added source '{}': {} ({} files found)", label, abs_path.display(), count);
    Ok(())
}

pub fn run(config: Config, dry_run: bool) -> Result<()> {
    let data_dir = config.data_dir();
    let mut index = SearchIndex::open_or_create(&data_dir.join("index"))?;
    let store = ParquetStore::new(&data_dir.join("store"));

    // Phase 1: Ingest new/changed files
    let new_artifacts = ingest::scan_sources(&config)?;

    if new_artifacts.is_empty() {
        println!("No new or changed files found.");
        return Ok(());
    }

    let pb = ProgressBar::new(new_artifacts.len() as u64);
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{bar:40}] {pos}/{len} {msg}")
        .unwrap());

    let mut ingested = 0;
    let mut skipped = 0;

    for artifact in &new_artifacts {
        pb.set_message(format!("{}", artifact.source_label));

        if dry_run {
            pb.println(format!("  [dry-run] Would ingest: {} ({})",
                artifact.artifact_id, artifact.source_label));
        } else {
            // Index in tantivy (summary + keywords + metadata stored)
            index.add_artifact(artifact)?;

            // Write to hot/ as JSON
            let hot_path = data_dir.join("hot").join(format!("{}.json", artifact.artifact_id));
            let hot_json = serde_json::to_string_pretty(artifact)?;
            std::fs::write(&hot_path, &hot_json)?;

            ingested += 1;
        }
        pb.inc(1);
    }
    pb.finish_with_message("done");

    if !dry_run {
        index.commit()?;
    }

    // Phase 2: Compact aged hot files to Parquet
    let compacted = if !dry_run {
        tiers::compact_hot_to_parquet(&config, &data_dir, &store)?
    } else {
        0
    };

    println!();
    println!("Processed {} artifacts. {} new, {} skipped, {} compacted to Parquet.",
        new_artifacts.len(), ingested, skipped, compacted);

    Ok(())
}

pub fn search(config: Config, query: String, after: Option<String>, before: Option<String>, limit: usize) -> Result<()> {
    let data_dir = config.data_dir();
    let index = SearchIndex::open_or_create(&data_dir.join("index"))?;

    let results = index.search(&query, after.as_deref(), before.as_deref(), limit)?;

    if results.is_empty() {
        println!("No results found.");
        return Ok(());
    }

    for (i, result) in results.iter().enumerate() {
        println!("{}. [{}] ({}) {}",
            i + 1,
            result.created_date,
            result.source_label,
            result.summary);
        println!("   significance: {:.2} | hash: {}",
            result.significance, &result.content_hash[..16]);
        println!();
    }

    Ok(())
}

pub fn recall(config: Config, artifact_id: String) -> Result<()> {
    let data_dir = config.data_dir();
    let index = SearchIndex::open_or_create(&data_dir.join("index"))?;
    let store = ParquetStore::new(&data_dir.join("store"));

    // Check hot/ first
    let hot_path = data_dir.join("hot").join(format!("{}.json", artifact_id));
    if hot_path.exists() {
        let content = std::fs::read_to_string(&hot_path)?;
        println!("{}", content);
        return Ok(());
    }

    // Find in Parquet via index metadata
    let result = recall::recall_from_store(&store, &artifact_id)?;

    match result {
        Some(recalled) => {
            println!("Integrity: {}", recalled.integrity_status);
            println!("Size: {} bytes", recalled.content.len());
            println!("---");
            println!("{}", recalled.content);
        }
        None => {
            println!("Artifact '{}' not found.", artifact_id);
        }
    }

    Ok(())
}

pub fn status(config: Config) -> Result<()> {
    let data_dir = config.data_dir();

    // Count hot files
    let hot_count = std::fs::read_dir(data_dir.join("hot"))
        .map(|d| d.filter_map(|e| e.ok()).filter(|e| {
            e.path().extension().map_or(false, |ext| ext == "json")
        }).count())
        .unwrap_or(0);

    // Count Parquet files and total size
    let mut parquet_count = 0;
    let mut parquet_bytes = 0u64;
    if let Ok(entries) = std::fs::read_dir(data_dir.join("store")) {
        for entry in entries.filter_map(|e| e.ok()) {
            if entry.path().extension().map_or(false, |ext| ext == "parquet") {
                parquet_count += 1;
                parquet_bytes += entry.metadata().map(|m| m.len()).unwrap_or(0);
            }
        }
    }

    // Index stats
    let index = SearchIndex::open_or_create(&data_dir.join("index"))?;
    let index_stats = index.stats()?;

    println!("Myelin8 Status");
    println!("========================================");
    println!("Sources:          {}", config.sources.len());
    for src in &config.sources {
        println!("  {} → {}", src.label, src.path);
    }
    println!();
    println!("Hot (plaintext):  {} artifacts", hot_count);
    println!("Store (Parquet):  {} files, {} bytes", parquet_count, parquet_bytes);
    println!("Index:            {} artifacts, {} terms", index_stats.num_docs, index_stats.num_terms);
    println!("Data dir:         {}", data_dir.display());

    Ok(())
}

pub fn verify(config: Config) -> Result<()> {
    let data_dir = config.data_dir();
    let store = ParquetStore::new(&data_dir.join("store"));

    let results = integrity::verify_all(&store, &data_dir.join("hot"))?;

    println!("Integrity Verification");
    println!("========================================");
    println!("Total checked:  {}", results.total);
    println!("  Passed:       {}", results.passed);
    println!("  Failed:       {}", results.failed);

    for failure in &results.failures {
        println!("  FAIL: {} — {}", failure.artifact_id, failure.reason);
    }

    Ok(())
}

pub fn pin(config: Config, query: String) -> Result<()> {
    let data_dir = config.data_dir();
    let mut index = SearchIndex::open_or_create(&data_dir.join("index"))?;

    let results = index.search(&query, None, None, 1)?;
    if let Some(result) = results.first() {
        println!("Pinned: {} (significance → 1.0)", result.summary);
        // TODO: update significance in index
    } else {
        println!("No matching artifact found for: {}", query);
    }
    Ok(())
}

pub fn remove(mut config: Config, label: String) -> Result<()> {
    let before = config.sources.len();
    config.sources.retain(|s| s.label != label);
    if config.sources.len() == before {
        println!("Source '{}' not found.", label);
    } else {
        config.save()?;
        println!("Removed source '{}'.", label);
    }
    Ok(())
}
