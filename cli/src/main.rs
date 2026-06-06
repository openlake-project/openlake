mod cli;
mod commands;

use anyhow::Result;
use clap::Parser;

#[compio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,h2=warn,hyper=warn,cyper=warn,axum=warn")),
        )
        .with_target(true)
        .init();

    let parsed = cli::Cli::parse();
    commands::dispatch(parsed.cmd).await
}
