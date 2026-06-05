pub mod cluster;
pub mod disk;
use anyhow::Result;
use clap::Subcommand;

#[derive(Subcommand)]
pub enum Cmd {
    Cluster(cluster::Args),

    /// Disk inspection commands.
    Disk(disk::Args),
}

pub async fn dispatch(cmd: Cmd) -> Result<()> {
    match cmd {
        Cmd::Cluster(a) => cluster::run(a).await,
        Cmd::Disk(a) => disk::run(a).await,
    }
}
