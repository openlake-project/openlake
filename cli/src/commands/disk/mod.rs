mod info;

use anyhow::Result;
use clap::{Args as ClapArgs, Subcommand};

#[derive(ClapArgs)]
pub struct Args {
    #[command(subcommand)]
    pub sub: DiskCmd,
}

#[derive(Subcommand)]
pub enum DiskCmd {
    /// Display disk information.
    Info(info::InfoArgs),
}

pub async fn run(args: Args) -> Result<()> {
    match args.sub {
        DiskCmd::Info(a) => info::run(a).await,
    }
}
