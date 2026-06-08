pub mod up;
pub mod status;
pub mod topology;
pub mod ping;

use anyhow::Result;
use clap::{Args as ClapArgs, Subcommand};

#[derive(ClapArgs)]
pub struct Args {
    #[command(subcommand)]
    pub sub: ClusterCmd,
}

#[derive(Subcommand)]
pub enum ClusterCmd {
    /// Print the live state of every node listed in --config.
    Status(status::StatusArgs),
    
    /// Print the declared node layout from --config.
    Topology(topology::TopologyArgs),
    
    /// Bring the cluster up.
    Up(up::UpArgs),

    /// Ping a specific node.
    Ping(ping::PingArgs),
}

pub async fn run(args: Args) -> Result<()> {
    match args.sub {
        ClusterCmd::Status(a) => status::run(a).await,
        ClusterCmd::Topology(a) => topology::run(a).await,
        ClusterCmd::Up(a) => up::run(a).await,
        ClusterCmd::Ping(a) => ping::run(a).await,
    }
}