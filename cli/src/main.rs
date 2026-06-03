mod cli;
mod commands;
mod config;

use anyhow::Result;
use clap::Parser;

#[compio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let parsed = cli::Cli::parse();
    commands::dispatch(parsed.cmd).await
}
