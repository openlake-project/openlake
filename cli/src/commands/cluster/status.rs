use anyhow::{Context, Result};
use clap::Args as ClapArgs;
use compio::net::TcpStream;
use std::path::PathBuf;
use std::time::Duration;

use crate::config;

#[derive(ClapArgs)]
pub struct StatusArgs {
    /// Cluster TOML.  One TOML describes exactly one cluster.
    #[arg(long)]
    pub config: PathBuf,

    /// Per-node probe timeout in seconds.
    #[arg(long, default_value_t = 2)]
    pub probe_timeout_secs: u64,
}

pub async fn run(args: StatusArgs) -> Result<()> {
    let cfg = config::load(&args.config)
        .with_context(|| format!("load {}", args.config.display()))?;

    if cfg.nodes.is_empty() {
        println!("no openlake cluster detected: {} declares zero nodes",
                 args.config.display());
        return Ok(());
    }

    let probe_timeout = Duration::from_secs(args.probe_timeout_secs);

    let mut alive = 0usize;
    for node in &cfg.nodes {
        let ok = match compio::time::timeout(
            probe_timeout,
            TcpStream::connect(node.rpc_addr),
        ).await {
            Ok(Ok(_stream)) => true,
            _ => false,
        };
        if ok {
            alive += 1;
            println!("[node {:>3}] up    {}", node.id, node.rpc_addr);
        } else {
            println!("[node {:>3}] DOWN  {}", node.id, node.rpc_addr);
        }
    }

    if alive == 0 {
        println!();
        println!("no openlake cluster detected: 0 / {} nodes responded.",
                 cfg.nodes.len());
        println!("hint: bring the cluster up first, then re-run.");
    } else {
        println!();
        println!("openlake cluster status: {} / {} nodes alive",
                 alive, cfg.nodes.len());
    }
    Ok(())
}
