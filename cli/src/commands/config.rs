use anyhow::{Context, Result};
use clap::Args as ClapArgs;
use std::path::PathBuf;

use openlake_server::config;

#[derive(ClapArgs)]
pub struct Args {
    /// Cluster TOML. One TOML describes exactly one cluster.
    #[arg(long)]
    pub config: PathBuf,
}

pub async fn run(args: Args) -> Result<()> {
    let text = std::fs::read_to_string(&args.config)
        .with_context(|| format!("read {}", args.config.display()))?;

    let cfg = config::Config::from_toml(&text)
        .with_context(|| format!("prase {}", args.config.display()))?;

    println!("Configuration loaded successfully");
    println!("Config file: {}", args.config.display());
    println!("Nodes configured: {}", cfg.nodes.len());

    if cfg.nodes.is_empty() {
        println!("Warning: no nodes defined in configuration.");
        return Ok(());
    }

    println!();

    for node in &cfg.nodes {
        println!("[node {:>3}] {}", node.id, node.rpc_addr);
    }

    println!();
    println!("Configuration validation passed.");

    Ok(())
}
