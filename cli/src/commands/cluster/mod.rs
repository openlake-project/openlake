mod status;
mod topology;

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

    /// Print cluster topology.
    Topology(topology::TopologyArgs),
}

pub async fn run(args: Args) -> Result<()> {
    match args.sub {
        ClusterCmd::Status(a) => status::run(a).await,
        ClusterCmd::Topology(a) => topology::run(a).await,
    }
}
