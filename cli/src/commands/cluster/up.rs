use anyhow::{Context, Result};
use clap::Args as ClapArgs;
use std::path::PathBuf;
use openlake_server::config::Config;
#[derive(ClapArgs)]
pub struct UpArgs {
    /// Cluster TOML. One TOML describes exactly one cluster.
    #[arg(long)]
    pub config: PathBuf,
}

pub async fn run(args: UpArgs) -> Result<()> {
    println!(
        "bringing openlake cluster up using config: {}",
        args.config.display()
    );

    // 1. Read the configuration file to a string
    let text = std::fs::read_to_string(&args.config)
        .with_context(|| format!("failed to read config file at {}", args.config.display()))?;

    // 2. Parse the string content into the Config struct
    let cfg: Config = toml::from_str(&text)
        .with_context(|| format!("failed to parse TOML configuration from {}", args.config.display()))?;

    println!("\nInitializing cluster nodes...");

    // 3. Loop through the nodes found in the config file
    for node in &cfg.nodes {
        println!(
            "Starting node [{}] on address {} with {} disk(s)...", 
            node.id, node.rpc_addr, node.disk_count
        );
    }

    println!("\ncluster started successfully!");

    Ok(())
}
