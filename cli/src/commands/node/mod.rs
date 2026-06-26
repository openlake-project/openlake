mod info;

use anyhow::Result;
use clap::{Args as ClapArgs, Subcommand};

#[derive(ClapArgs)]
pub struct Args {
    #[command(subcommand)]
    pub sub: NodeCmd,
}

#[derive(Subcommand)]
pub enum NodeCmd {
    /// Display node information and health metrics.
    Info(info::InfoArgs),
}

pub async fn run(args: Args) -> Result<()> {
    match args.sub {
        NodeCmd::Info(a) => info::run(a).await,
    }
}
