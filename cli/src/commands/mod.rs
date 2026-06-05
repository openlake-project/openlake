pub mod cluster;
pub mod scrub;

use anyhow::Result;
use clap::Subcommand;

#[derive(Subcommand)]
pub enum Cmd {
    /// Cluster lifecycle and inspection.
    Cluster(cluster::Args),

    /// Run scrub operation.
    Scrub(scrub::ScrubArgs),
}

pub async fn dispatch(cmd: Cmd) -> Result<()> {
    match cmd {
        Cmd::Cluster(a) => cluster::run(a).await,
        Cmd::Scrub(a) => scrub::run(a).await,
    }
}