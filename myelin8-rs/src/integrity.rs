use anyhow::Result;
use sha2::{Sha256, Digest};
use std::path::Path;

use crate::ingest::Artifact;
use crate::store::ParquetStore;

pub struct VerifyResult {
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub failures: Vec<VerifyFailure>,
}

pub struct VerifyFailure {
    pub artifact_id: String,
    pub reason: String,
}

/// Verify integrity of all artifacts across hot files and Parquet store.
/// For each artifact: recompute SHA-256 on content, compare to stored hash.
pub fn verify_all(store: &ParquetStore, hot_dir: &Path) -> Result<VerifyResult> {
    let mut total = 0;
    let mut passed = 0;
    let mut failed = 0;
    let mut failures = Vec::new();

    // Verify hot files
    if let Ok(entries) = std::fs::read_dir(hot_dir) {
        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            if path.extension().map_or(false, |ext| ext == "json") {
                total += 1;
                match verify_hot_file(&path) {
                    Ok(true) => passed += 1,
                    Ok(false) => {
                        failed += 1;
                        let id = path.file_stem()
                            .map(|s| s.to_string_lossy().to_string())
                            .unwrap_or_default();
                        failures.push(VerifyFailure {
                            artifact_id: id,
                            reason: "SHA-256 mismatch in hot file".to_string(),
                        });
                    }
                    Err(e) => {
                        failed += 1;
                        failures.push(VerifyFailure {
                            artifact_id: path.to_string_lossy().to_string(),
                            reason: format!("Error reading: {}", e),
                        });
                    }
                }
            }
        }
    }

    // Verify Parquet files
    for parquet_path in store.list_files()? {
        match verify_parquet_file(&parquet_path) {
            Ok((file_total, file_passed, file_failures)) => {
                total += file_total;
                passed += file_passed;
                failed += file_failures.len();
                failures.extend(file_failures);
            }
            Err(e) => {
                failed += 1;
                failures.push(VerifyFailure {
                    artifact_id: parquet_path.to_string_lossy().to_string(),
                    reason: format!("Error reading Parquet: {}", e),
                });
            }
        }
    }

    Ok(VerifyResult { total, passed, failed, failures })
}

fn verify_hot_file(path: &Path) -> Result<bool> {
    let content = std::fs::read_to_string(path)?;
    let artifact: Artifact = serde_json::from_str(&content)?;

    let recomputed = hex::encode(Sha256::digest(artifact.content.as_bytes()));
    Ok(recomputed == artifact.content_hash)
}

fn verify_parquet_file(path: &Path) -> Result<(usize, usize, Vec<VerifyFailure>)> {
    use arrow::array::StringArray;
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
    use std::fs::File;

    let file = File::open(path)?;
    let builder = ParquetRecordBatchReaderBuilder::try_new(file)?;
    let reader = builder.build()?;

    let mut total = 0;
    let mut passed = 0;
    let mut failures = Vec::new();

    for batch in reader {
        let batch = batch?;
        let ids = batch.column_by_name("artifact_id")
            .and_then(|c| c.as_any().downcast_ref::<StringArray>());
        let contents = batch.column_by_name("content")
            .and_then(|c| c.as_any().downcast_ref::<StringArray>());
        let hashes = batch.column_by_name("content_hash")
            .and_then(|c| c.as_any().downcast_ref::<StringArray>());

        if let (Some(ids), Some(contents), Some(hashes)) = (ids, contents, hashes) {
            for i in 0..batch.num_rows() {
                total += 1;
                let recomputed = hex::encode(Sha256::digest(contents.value(i).as_bytes()));
                if recomputed == hashes.value(i) {
                    passed += 1;
                } else {
                    failures.push(VerifyFailure {
                        artifact_id: ids.value(i).to_string(),
                        reason: format!(
                            "SHA-256 drift. Expected: {}... Got: {}...",
                            &hashes.value(i)[..16],
                            &recomputed[..16]
                        ),
                    });
                }
            }
        }
    }

    Ok((total, passed, failures))
}
