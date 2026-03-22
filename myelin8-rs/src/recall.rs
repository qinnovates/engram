use anyhow::Result;
use sha2::{Sha256, Digest};

use crate::store::ParquetStore;

pub struct RecallResult {
    pub content: String,
    pub content_hash: String,
    pub integrity_status: String,
}

/// Recall full content from Parquet.
/// 1. Find the artifact by ID across all Parquet files
/// 2. Read content column (column-selective — skips everything else)
/// 3. Verify SHA-256: hash(recovered content) == stored content_hash
/// 4. Return content + integrity status
pub fn recall_from_store(store: &ParquetStore, artifact_id: &str) -> Result<Option<RecallResult>> {
    let result = store.read_content(artifact_id)?;

    match result {
        Some((content, stored_hash)) => {
            // Recompute hash on recovered content
            let recovered_hash = hex::encode(Sha256::digest(content.as_bytes()));

            let integrity_status = if recovered_hash == stored_hash {
                "PASS — content identical to original".to_string()
            } else {
                format!(
                    "FAIL — DRIFT DETECTED. Expected: {}... Got: {}...",
                    &stored_hash[..16],
                    &recovered_hash[..16]
                )
            };

            Ok(Some(RecallResult {
                content,
                content_hash: stored_hash,
                integrity_status,
            }))
        }
        None => Ok(None),
    }
}
