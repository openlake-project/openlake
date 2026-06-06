use anyhow::{Context, Result};
use clap::Args as ClapArgs;
use std::path::PathBuf;

use crate::config;

#[derive(ClapArgs)]
pub struct Args {
    /// Cluster TOML. One TOML describes exactly one cluster.
    #[arg(long)]
    pub config: PathBuf,
}

pub async fn run(args: Args) -> Result<()> {
    let cfg = config::load(&args.config)
        .with_context(|| format!("load {}", args.config.display()))?;

    println!("Configuration loaded successfully");
    println!("Config file: {}", args.config.display());
    println!("Nodes configured: {}", cfg.nodes.len());

    if cfg.nodes.is_empty() {
        println!("Warning: no nodes defined in configuration.");
        return Ok(());
    }

    println!();

    for node in &cfg.nodes {
        println!(
            "[node {:>3}] {}",
            node.id,
            node.rpc_addr
        );
    }

    println!();
    println!("Configuration validation passed.");

    Ok(())
}