use anyhow::{Context, Result};
use clap::Args as ClapArgs;
use compio::net::TcpStream;
use openlake_server::config::Config;
use std::path::PathBuf;
use std::time::{Duration, Instant};

#[derive(ClapArgs)]
pub struct InfoArgs {
    /// openlake.toml file
    #[arg(long)]
    pub config: PathBuf,

    /// Per node probe timeout in seconds
    #[arg(long, default_value_t = 2)]
    pub probe_timeout_secs: u64,
}

pub async fn run(args: InfoArgs) -> Result<()> {
    let text = std::fs::read_to_string(&args.config)
        .with_context(|| format!("read {}", args.config.display()))?;

    let cfg: Config =
        toml::from_str(&text).with_context(|| format!("parse {}", args.config.display()))?;

    println!("Node Information");
    println!("================");

    let timeout = Duration::from_secs(args.probe_timeout_secs);

    for node in &cfg.nodes {
        let start = Instant::now();

        let result = compio::time::timeout(timeout, TcpStream::connect(node.rpc_addr)).await;

        let latency = start.elapsed().as_millis();

        println!();
        println!("Node ID      : {}", node.id);
        println!("RPC Address  : {}", node.rpc_addr);
        println!("Disk Count   : {}", node.disk_count);

        match result {
            Ok(Ok(_)) => {
                println!("Status       : UP");
                println!("Health       : Healthy");
                println!("Latency      : {} ms", latency);
            }
            _ => {
                println!("Status       : DOWN");
                println!("Health       : Unreachable");
                println!("Latency      : timeout");
            }
        }
    }

    Ok(())
}
