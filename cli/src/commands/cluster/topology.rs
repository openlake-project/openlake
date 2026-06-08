use anyhow::{Context, Result};
use clap::Args as ClapArgs;
use std::path::PathBuf;

use crate::config;

#[derive(ClapArgs)]
pub struct TopologyArgs {
    /// Path to the cluster TOML config file.
    #[arg(long)]
    pub config: PathBuf,
}

pub async fn run(args: TopologyArgs) -> Result<()> {
    let cfg =
        config::load(&args.config).with_context(|| format!("load {}", args.config.display()))?;

    println!("OpenLake Cluster Topology");
    println!("=========================");

    if cfg.nodes.is_empty() {
        println!(
            "no openlake cluster detected: {} declares zero nodes",
            args.config.display()
        );
        return Ok(());
    }

    for node in &cfg.nodes {
        println!("[node {:>3}] {}", node.id, node.rpc_addr);
    }

    println!();
    println!("cluster contains {} node(s)", cfg.nodes.len());
    Ok(())
}
