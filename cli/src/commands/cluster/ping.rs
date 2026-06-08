use anyhow::{Context, Result};
use clap::Args;
use std::time::Duration;
use compio::net::TcpStream;
use openlake_server::config::Config;

#[derive(Args)]
pub struct PingArgs {
    /// Path to the OpenLake node TOML config.
    #[arg(long)]
    pub config: std::path::PathBuf,

    /// The specific node ID to ping (numerical)
    pub node: String,

    /// Per-node probe timeout in seconds.
    #[arg(long, default_value_t = 2)]
    pub probe_timeout_secs: u64,
}

pub async fn run(args: PingArgs) -> Result<()> {
    // 1. Parse the node string argument into a u16 number
    let target_node_id = args.node.parse::<u16>()
        .with_context(|| format!("Invalid node ID '{}'. Node ID must be a number.", args.node))?;

    // 2. Read and parse the configuration file
    let text = std::fs::read_to_string(&args.config)
        .with_context(|| format!("failed to read {}", args.config.display()))?;
        
    let cfg: Config = toml::from_str(&text)
        .with_context(|| format!("failed to parse {}", args.config.display()))?;

    // 3. Find the requested node in the config
    let target_node = cfg.nodes.iter().find(|n| n.id == target_node_id);

    match target_node {
        Some(node) => {
            println!("Pinging node '{}' at {}...", node.id, node.rpc_addr);
            
            let probe_timeout = Duration::from_secs(args.probe_timeout_secs);
            
            // 4. Attempt to connect to the node's rpc_addr with a compio timeout
            let connection_attempt = TcpStream::connect(&node.rpc_addr);
            let is_alive = matches!(
                compio::time::timeout(probe_timeout, connection_attempt).await,
                Ok(Ok(_))
            );

            // 5. Output the result cleanly
            if is_alive {
                println!("Node '{}' is UP and responding!", node.id);
            } else {
                println!("Node '{}' is DOWN or unreachable (Timeout).", node.id);
            }
        }
        None => {
            println!("Error: Node '{}' not found in config.", target_node_id);
        }
    }

    Ok(())
}