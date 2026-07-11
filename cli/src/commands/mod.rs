pub mod bench;
pub mod cluster;
pub mod disk;
pub mod node;
pub mod version;

use anyhow::Result;
use clap::Subcommand;

#[derive(Subcommand)]
pub enum Cmd {
    Cluster(cluster::Args),

    /// Disk inspection commands.
    Disk(disk::Args),

    /// Fabric microbench.
    Bench(bench::Args),

    /// Node inspection commands.
    Node(node::Args),
    Version(version::VersionArgs),
}

pub async fn dispatch(cmd: Cmd) -> Result<()> {
    match cmd {
        Cmd::Node(a) => node::run(a).await,
        Cmd::Cluster(a) => cluster::run(a).await,
        Cmd::Disk(a) => disk::run(a).await,
        Cmd::Bench(a) => bench::run(a).await,
        Cmd::Version(a) => version::run(a).await,
    }
}
