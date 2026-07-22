use anyhow::{Context, Result};
use clap::Args as ClapArgs;
use compio::net::TcpStream;
use std::path::PathBuf;
use std::time::Duration;

use crate::config;

#[derive(ClapArgs)]
pub struct BenchmarkWebsiteArgs {
    /// Cluster TOML.  One TOML describes exactly one cluster.
    #[arg(long)]
    pub config: PathBuf,

    /// Per-node probe timeout in seconds.
    #[arg(long, default_value_t = 2)]
    pub probe_timeout_secs: u64,
}

pub async fn run(_args: BenchmarkWebsiteArgs) -> Result<()> {
    println!("Benchmark Website command running");
Ok(())
}

  

    