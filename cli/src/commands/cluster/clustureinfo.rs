use anyhow::{Context, Result};
use clap::Args as ClapArgs;
use std::path::PathBuf;

use openlake_server::config::Config;


pub struct ClusterInfoArgs {
  
    #[arg(long)]
    pub config: PathBuf,
}

pub async fn run(args: ClusterInfoArgs) -> Result<()> {
    let text = std::fs::read_to_string(&args.config)
        .with_context(|| format!("read {}", args.config.display()))?;

    let cfg: Config =
        toml::from_str(&text)
            .with_context(|| format!("parse {}", args.config.display()))?;

    println!("===== OpenLake Cluster Info =====");
    println!("Total Nodes: {}", cfg.nodes.len());

    for node in &cfg.nodes {
        println!();
        println!("Node ID: {}", node.id);
        println!("RPC Address: {}", node.rpc_addr);
        println!("Disk Count: {}", node.disk_count);
    }

    Ok(())
}
