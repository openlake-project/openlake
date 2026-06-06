use anyhow::{Context, Result};
use clap::Args as ClapArgs;
use compio::net::TcpStream;
use std::path::PathBuf;
use std::time::Duration;

use openlake_server::config::Config;

#[derive(ClapArgs)]
pub struct StatusArgs {
    /// openlake.toml. The same file openlaked reads.
    #[arg(long)]
    pub config: PathBuf,

    /// Per node probe timeout in seconds.
    #[arg(long, default_value_t = 2)]
    pub probe_timeout_secs: u64,
}

pub async fn run(args: StatusArgs) -> Result<()> {
    let text = std::fs::read_to_string(&args.config)
        .with_context(|| format!("read {}", args.config.display()))?;
    let cfg: Config = toml::from_str(&text)
        .with_context(|| format!("parse {}", args.config.display()))?;

    if cfg.nodes.is_empty() {
        println!("no openlake cluster detected: {} declares zero nodes",
                 args.config.display());
        return Ok(());
    }

    let probe_timeout = Duration::from_secs(args.probe_timeout_secs);

    let mut alive = 0usize;
    for node in &cfg.nodes {
        let ok = matches!(
            compio::time::timeout(probe_timeout, TcpStream::connect(node.rpc_addr)).await,
            Ok(Ok(_))
        );
        if ok {
            alive += 1;
            println!("[node {:>3}] up    {} ({} disks)", node.id, node.rpc_addr, node.disk_count);
        } else {
            println!("[node {:>3}] DOWN  {} ({} disks)", node.id, node.rpc_addr, node.disk_count);
        }
    }

    println!();
    if alive == 0 {
        println!("no openlake cluster detected: 0 / {} nodes responded.",
                 cfg.nodes.len());
        println!("hint: bring the cluster up first, then re-run.");
    } else {
        println!("openlake cluster status: {} / {} nodes alive",
                 alive, cfg.nodes.len());
    }
    Ok(())
}
