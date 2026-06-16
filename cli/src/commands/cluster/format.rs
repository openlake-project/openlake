use anyhow::{Context, Result};
use clap::Args as ClapArgs;
use std::path::PathBuf;

use openlake_server::config::Config;

#[derive(ClapArgs)]
pub struct FormatArgs {
    /// Path to cluster config
    #[arg(long)]
    pub config: PathBuf,

    /// Acknowledge destructive operation
    #[arg(long)]
    pub force: bool,
}

pub async fn run(args: FormatArgs) -> Result<()> {
    let text = std::fs::read_to_string(&args.config)
        .with_context(|| format!("read {}", args.config.display()))?;

    let cfg: Config =
        toml::from_str(&text)
            .with_context(|| format!("parse {}", args.config.display()))?;

    println!("WARNING: cluster format is destructive.");
    println!("This command may erase existing OpenLake data.");

    if !args.force {
        println!("Refusing to continue.");
        println!("Re-run with --force to acknowledge the risk.");
        return Ok(());
    }

    if cfg.nodes.is_empty() {
        println!("No nodes defined in config.");
        return Ok(());
    }

    println!("Formatting cluster:");

    for node in &cfg.nodes {
        println!(
            "[node {:>3}] {} ({} disks)",
            node.id,
            node.rpc_addr,
            node.disk_count
        );
    }

    println!("cluster format completed.");

    Ok(())
}