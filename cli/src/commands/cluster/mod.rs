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
   
    Clusterinfo(clusterinfo::ClusterInfoArgs),


    Status(status::StatusArgs),

    Topology(topology::TopologyArgs),

    Up(up::UpArgs),

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
