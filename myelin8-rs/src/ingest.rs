use anyhow::Result;
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use std::collections::HashSet;
use std::path::Path;

use crate::config::{Config, Source};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Artifact {
    pub artifact_id: String,
    pub content: String,
    pub content_hash: String,
    pub summary: String,
    pub keywords: Vec<String>,
    pub significance: f32,
    pub source_label: String,
    pub source_path: String,
    pub created_date: String,
    pub original_size: u64,
}

/// Count files matching a source's pattern.
pub fn count_files_in_source(source: &Source) -> Result<usize> {
    let pattern = format!("{}/{}", source.path, source.pattern);
    Ok(glob::glob(&pattern)?.filter_map(|e| e.ok()).count())
}

/// Scan all registered sources for new/changed files.
pub fn scan_sources(config: &Config) -> Result<Vec<Artifact>> {
    let mut artifacts = Vec::new();

    for source in &config.sources {
        let pattern = format!("{}/{}", source.path, source.pattern);
        let entries: Vec<_> = glob::glob(&pattern)?
            .filter_map(|e| e.ok())
            .collect();

        for path in entries {
            if let Some(artifact) = ingest_file(&path, &source.label)? {
                artifacts.push(artifact);
            }
        }
    }

    Ok(artifacts)
}

/// Ingest a single file into an Artifact.
fn ingest_file(path: &Path, label: &str) -> Result<Option<Artifact>> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return Ok(None), // skip binary/unreadable files
    };

    if content.trim().len() < 50 {
        return Ok(None); // skip trivially small files
    }

    let raw_bytes = content.as_bytes();
    let content_hash = hex::encode(Sha256::digest(raw_bytes));
    let artifact_id = content_hash[..16].to_string();

    let metadata = std::fs::metadata(path)?;
    let mtime = metadata.modified()?;
    let created_date = chrono::DateTime::<chrono::Utc>::from(mtime)
        .format("%Y-%m-%d")
        .to_string();

    Ok(Some(Artifact {
        artifact_id,
        content: content.clone(),
        content_hash,
        summary: extract_summary(&content, path),
        keywords: extract_keywords(&content),
        significance: score_significance(&content),
        source_label: label.to_string(),
        source_path: path.to_string_lossy().to_string(),
        created_date,
        original_size: raw_bytes.len() as u64,
    }))
}

/// Extract ALL unique meaningful tokens. tantivy will index everything,
/// but we also store keywords for the Parquet schema.
fn extract_keywords(text: &str) -> Vec<String> {
    let stops: HashSet<&str> = [
        "the", "and", "for", "are", "but", "not", "you", "all", "can", "has",
        "was", "one", "our", "out", "this", "that", "with", "have", "from",
        "they", "been", "said", "each", "which", "their", "will", "other",
        "about", "many", "then", "them", "these", "some", "would", "make",
        "like", "could", "into", "than", "its", "over", "such", "after",
        "also", "did", "any", "new", "most", "only", "very", "when", "what",
        "how", "use", "used", "using", "does", "none", "just", "should",
    ].into_iter().collect();

    let mut seen = HashSet::new();
    let mut keywords = Vec::new();

    for word in text.split(|c: char| !c.is_alphanumeric() && c != '_') {
        let lower = word.to_lowercase();
        if lower.len() >= 3 && !stops.contains(lower.as_str()) && seen.insert(lower.clone()) {
            keywords.push(lower);
        }
    }

    keywords
}

/// Template-based summary: first heading + first meaningful line.
fn extract_summary(text: &str, path: &Path) -> String {
    let fname = path.file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();

    let mut heading = String::new();
    let mut first_line = String::new();

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') && heading.is_empty() {
            heading = trimmed.trim_start_matches('#').trim().to_string();
        } else if !trimmed.is_empty()
            && !trimmed.starts_with('#')
            && !trimmed.starts_with("---")
            && !trimmed.starts_with('|')
            && first_line.is_empty()
        {
            first_line = if trimmed.len() > 200 {
                format!("{}...", &trimmed[..200])
            } else {
                trimmed.to_string()
            };
        }

        if !heading.is_empty() && !first_line.is_empty() {
            break;
        }
    }

    if !heading.is_empty() {
        format!("{}: {}. {}", fname, heading, first_line)
    } else {
        format!("{}: {}", fname, first_line)
    }
}

/// Simple heuristic significance scoring.
fn score_significance(text: &str) -> f32 {
    let lower = text.to_lowercase();
    let mut score: f32 = 0.3; // baseline

    if lower.contains("decision") || lower.contains("decided") || lower.contains("because") {
        score = score.max(0.85);
    }
    if lower.contains("critical") || lower.contains("important") || lower.contains("must") {
        score = score.max(0.80);
    }
    if lower.contains("error") || lower.contains("fix") || lower.contains("bug") {
        score = score.max(0.60);
    }
    if text.len() > 2000 {
        score = score.max(0.50);
    }

    (score * 100.0).round() / 100.0
}
