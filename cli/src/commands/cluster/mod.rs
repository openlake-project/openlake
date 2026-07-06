mod clusterinfo;
mod down;
mod status;
mod topology;
mod up;

use anyhow::Result;
use clap::{Args as ClapArgs, Subcommand};

#[derive(ClapArgs)]
pub struct Args {
    #[command(subcommand)]
    pub sub: ClusterCmd,
}

#[derive(Subcommand)]
pub enum ClusterCmd {
    /// Display cluster information.
    Clusterinfo(clusterinfo::ClusterInfoArgs),

    /// Print the live state of every node listed in --config.
    Status(status::StatusArgs),

    /// Print the declared node layout from --config; --probe adds live state.
    Topology(topology::TopologyArgs),

    /// Bring the cluster up.
    Up(up::UpArgs),

    /// Bring the cluster down.
    Down(down::DownArgs),
}

pub async fn run(args: Args) -> Result<()> {
    match args.sub {
        ClusterCmd::Clusterinfo(a) => clusterinfo::run(a).await,
        ClusterCmd::Status(a) => status::run(a).await,
        ClusterCmd::Topology(a) => topology::run(a).await,
        ClusterCmd::Up(a) => up::run(a).await,
        ClusterCmd::Down(a) => down::run(a).await,
    }
}