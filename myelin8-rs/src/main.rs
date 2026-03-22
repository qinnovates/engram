mod cli;
mod config;
mod ingest;
mod index;
mod store;
mod search;
mod recall;
mod tiers;
mod integrity;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Command};

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();
    let config = config::Config::load_or_default()?;

    match cli.command {
        Command::Init => cli::init(config),
        Command::Add { path, label, pattern } => cli::add(config, path, label, pattern),
        Command::Run { dry_run } => cli::run(config, dry_run),
        Command::Search { query, after, before, limit } => cli::search(config, query, after, before, limit),
        Command::Recall { artifact_id } => cli::recall(config, artifact_id),
        Command::Status => cli::status(config),
        Command::Verify => cli::verify(config),
        Command::Pin { query } => cli::pin(config, query),
        Command::Remove { label } => cli::remove(config, label),
    }
}
