use anyhow::Result;
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Source {
    pub path: String,
    pub label: String,
    pub pattern: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TierPolicy {
    /// Hours before hot files are eligible for compaction
    pub hot_age_hours: u64,
    /// Hours idle before hot files are eligible for compaction
    pub hot_idle_hours: u64,
}

impl Default for TierPolicy {
    fn default() -> Self {
        Self {
            hot_age_hours: 48,
            hot_idle_hours: 24,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub sources: Vec<Source>,
    pub tier_policy: TierPolicy,
    /// zstd compression level for all Parquet files
    pub zstd_level: i32,
    /// Days to keep hot files in .recycled/ after compaction
    pub recycle_days: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            sources: Vec::new(),
            tier_policy: TierPolicy::default(),
            zstd_level: 9,
            recycle_days: 7,
        }
    }
}

impl Config {
    pub fn data_dir(&self) -> PathBuf {
        if let Some(proj) = ProjectDirs::from("com", "qinnovates", "myelin8") {
            proj.data_dir().to_path_buf()
        } else {
            dirs_fallback()
        }
    }

    pub fn config_path(&self) -> PathBuf {
        self.data_dir().join("config.toml")
    }

    pub fn load_or_default() -> Result<Self> {
        let default = Config::default();
        let config_path = default.config_path();

        if config_path.exists() {
            let content = std::fs::read_to_string(&config_path)?;
            let config: Config = toml::from_str(&content)?;
            Ok(config)
        } else {
            Ok(default)
        }
    }

    pub fn save(&self) -> Result<()> {
        let path = self.config_path();
        std::fs::create_dir_all(path.parent().unwrap())?;
        let content = toml::to_string_pretty(self)?;
        // Atomic write
        let tmp = path.with_extension("toml.tmp");
        std::fs::write(&tmp, &content)?;
        std::fs::rename(&tmp, &path)?;
        Ok(())
    }
}

fn dirs_fallback() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".myelin8")
}
