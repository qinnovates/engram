use anyhow::Result;
use chrono::Utc;
use std::path::Path;

use crate::config::Config;
use crate::ingest::Artifact;
use crate::store::ParquetStore;

/// Compact aged hot files into Parquet.
///
/// Hot files older than `hot_age_hours` AND idle for `hot_idle_hours`
/// get batched into a Parquet file. The hot files are moved to .recycled/
/// and kept for `recycle_days` before permanent deletion.
///
/// No thawed tier — recalled artifacts reset their timestamps and
/// re-enter hot as if newly created. Hebbian decay handles the rest.
pub fn compact_hot_to_parquet(
    config: &Config,
    data_dir: &Path,
    store: &ParquetStore,
) -> Result<usize> {
    let hot_dir = data_dir.join("hot");
    let recycle_dir = hot_dir.join(".recycled");
    std::fs::create_dir_all(&recycle_dir)?;

    let now = Utc::now().timestamp() as u64;
    let age_threshold = config.tier_policy.hot_age_hours * 3600;
    let idle_threshold = config.tier_policy.hot_idle_hours * 3600;

    let mut eligible: Vec<Artifact> = Vec::new();

    // Find hot files eligible for compaction
    let entries = std::fs::read_dir(&hot_dir)?;
    for entry in entries.filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.extension().map_or(false, |ext| ext == "json") {
            let content = std::fs::read_to_string(&path)?;
            let artifact: Artifact = match serde_json::from_str(&content) {
                Ok(a) => a,
                Err(_) => continue,
            };

            // Check age and idle thresholds
            let metadata = std::fs::metadata(&path)?;
            let mtime = metadata.modified()?
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs();
            let age = now.saturating_sub(mtime);

            // Both conditions must be met
            if age >= age_threshold && age >= idle_threshold {
                eligible.push(artifact);
            }
        }
    }

    if eligible.is_empty() {
        return Ok(0);
    }

    let count = eligible.len();

    // Write batch to Parquet
    let timestamp = Utc::now().format("%Y%m%d-%H%M%S").to_string();
    let filename = format!("batch-{}.parquet", timestamp);
    store.write_batch(&eligible, &filename, config.zstd_level)?;

    // Move hot files to .recycled/
    for artifact in &eligible {
        let hot_path = hot_dir.join(format!("{}.json", artifact.artifact_id));
        let recycle_path = recycle_dir.join(format!("{}.json", artifact.artifact_id));
        if hot_path.exists() {
            std::fs::rename(&hot_path, &recycle_path)?;
        }
    }

    // Clean old recycled files
    clean_recycled(&recycle_dir, config.recycle_days)?;

    Ok(count)
}

/// Remove recycled files older than recycle_days.
fn clean_recycled(recycle_dir: &Path, max_days: u64) -> Result<()> {
    let threshold = std::time::Duration::from_secs(max_days * 86400);

    if let Ok(entries) = std::fs::read_dir(recycle_dir) {
        for entry in entries.filter_map(|e| e.ok()) {
            if let Ok(metadata) = entry.metadata() {
                if let Ok(modified) = metadata.modified() {
                    if let Ok(age) = modified.elapsed() {
                        if age > threshold {
                            let _ = std::fs::remove_file(entry.path());
                        }
                    }
                }
            }
        }
    }

    Ok(())
}
