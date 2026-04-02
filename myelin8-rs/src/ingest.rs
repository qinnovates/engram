use anyhow::Result;
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use std::collections::HashSet;
use std::path::Path;

use crate::config::{Config, Source};
use crate::semantic::{self, SemanticFields};

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
    /// If this artifact supersedes an older one, this holds the old artifact_id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supersedes: Option<String>,
    /// Semantic KV metadata extracted at ingest time
    pub semantic: SemanticFields,

    // ── SIEMPLE-AI governance fields (v2.0.0) ──────────────────────────
    /// Scoping namespace: user, tenant, project, system
    #[serde(default = "default_namespace")]
    pub namespace: String,
    /// Fact type: preference, identity, goal, constraint, domain_fact, exclusion, episode, note
    #[serde(default = "default_memory_type")]
    pub memory_type: String,
    /// Confidence score 0.0-1.0 (explicit=1.0, inferred ceiling=0.8)
    #[serde(default = "default_confidence")]
    pub confidence: f32,
    /// Provenance: explicit, inferred, imported
    #[serde(default = "default_source_provenance")]
    pub source_provenance: String,
    /// Sensitivity: low, moderate, high
    #[serde(default = "default_sensitivity")]
    pub sensitivity: String,
    /// JSON-encoded string array of semantic tags
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<String>,
    /// ISO 8601 TTL. Null = permanent
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    /// Source session ID for provenance tracing
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
}

fn default_namespace() -> String { "user".to_string() }
fn default_memory_type() -> String { "note".to_string() }
fn default_confidence() -> f32 { 0.5 }
fn default_source_provenance() -> String { "explicit".to_string() }
fn default_sensitivity() -> String { "low".to_string() }

/// Count files matching a source's pattern.
pub fn count_files_in_source(source: &Source) -> Result<usize> {
    let pattern = format!("{}/{}", source.path, source.pattern);
    Ok(glob::glob(&pattern)?.filter_map(|e| e.ok()).count())
}

/// State tracking: which files have been seen and their mtimes.
/// Prevents re-ingesting unchanged files.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IngestState {
    pub seen: std::collections::HashMap<String, SeenFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeenFile {
    pub mtime: u64,
    pub content_hash: String,
}

impl IngestState {
    pub fn load(state_path: &std::path::Path) -> Self {
        if state_path.exists() {
            match std::fs::read_to_string(state_path) {
                Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
                Err(_) => Self::default(),
            }
        } else {
            Self::default()
        }
    }

    pub fn save(&self, state_path: &std::path::Path) -> Result<()> {
        let tmp = state_path.with_extension("json.tmp");
        let content = serde_json::to_string_pretty(self)?;
        std::fs::write(&tmp, &content)?;
        std::fs::rename(&tmp, state_path)?;
        Ok(())
    }

    pub fn is_changed(&self, path: &str, mtime: u64) -> bool {
        match self.seen.get(path) {
            Some(seen) => seen.mtime != mtime,
            None => true, // never seen
        }
    }

    pub fn record(&mut self, path: String, mtime: u64, content_hash: String) {
        self.seen.insert(path, SeenFile { mtime, content_hash });
    }
}

/// Scan all registered sources for new/changed files.
/// Uses state tracking to skip files that haven't changed since last ingest.
pub fn scan_sources(config: &Config) -> Result<(Vec<Artifact>, IngestState)> {
    let state_path = config.data_dir().join("state.json");
    let mut state = IngestState::load(&state_path);
    let mut artifacts = Vec::new();

    for source in &config.sources {
        let pattern = format!("{}/{}", source.path, source.pattern);
        let entries: Vec<_> = glob::glob(&pattern)?
            .filter_map(|e| e.ok())
            .collect();

        for path in entries {
            // Check mtime against state
            let path_str = path.to_string_lossy().to_string();
            let mtime = path.metadata()
                .and_then(|m| m.modified())
                .map(|t| t.duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs())
                .unwrap_or(0);

            if !state.is_changed(&path_str, mtime) {
                continue; // skip unchanged files
            }

            if let Some(artifact) = ingest_file(&path, &source.label)? {
                state.record(path_str, mtime, artifact.content_hash.clone());
                artifacts.push(artifact);
            }
        }
    }

    // Save state after scan
    state.save(&state_path)?;

    Ok((artifacts, state))
}

/// Ingest a single file into an Artifact.
fn ingest_file(path: &Path, label: &str) -> Result<Option<Artifact>> {
    // Read raw bytes first — hash is computed on EXACT file content
    let raw_bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(_) => return Ok(None), // skip unreadable files
    };

    // Reject files with null bytes (binary files disguised as text)
    if raw_bytes.contains(&0x00) {
        tracing::warn!("Skipping file with null bytes: {}", path.display());
        return Ok(None);
    }

    // Hash the raw bytes — this is the permanent content identity
    let content_hash = hex::encode(Sha256::digest(&raw_bytes));

    // Convert to string (will fail on invalid UTF-8)
    let content = match std::str::from_utf8(&raw_bytes) {
        Ok(s) => s.to_string(),
        Err(_) => return Ok(None), // skip non-UTF-8 files
    };

    if content.trim().len() < 50 {
        return Ok(None); // skip trivially small files
    }
    let artifact_id = content_hash[..16].to_string();

    let metadata = std::fs::metadata(path)?;
    let mtime = metadata.modified()?;
    let created_date = chrono::DateTime::<chrono::Utc>::from(mtime)
        .format("%Y-%m-%d")
        .to_string();

    let semantic_fields = semantic::extract(&content);

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
        supersedes: None, // set by SupersessionIndex during ingest
        semantic: semantic_fields,
        // SIEMPLE-AI governance defaults (file-ingest path)
        namespace: "user".to_string(),
        memory_type: "note".to_string(),
        confidence: 0.5,
        source_provenance: "imported".to_string(),
        sensitivity: "low".to_string(),
        tags: None,
        expires_at: None,
        session_id: None,
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
