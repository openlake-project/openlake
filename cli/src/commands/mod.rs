pub mod bench;
pub mod cluster;
pub mod disk;
pub mod version;
use anyhow::Result;
use clap::Subcommand;

#[derive(Subcommand)]
pub enum Cmd {
    Cluster(cluster::Args),
<<<<<<< HEAD

    /// Disk inspection commands.
    Disk(disk::Args),

    /// Fabric microbench.
    Bench(bench::Args),

    Version(version::VersionArgs),
=======
    Bench(bench::BenchArgs),
>>>>>>> ed46ff9 (Add bench command skeleton)
}

pub async fn dispatch(cmd: Cmd) -> Result<()> {
    match cmd {
        Cmd::Cluster(a) => cluster::run(a).await,
<<<<<<< HEAD
        Cmd::Disk(a) => disk::run(a).await,
        Cmd::Bench(a) => bench::run(a).await,
        Cmd::Version(a) => version::run(a).await,
=======
        Cmd::Bench(a) => bench::run(a).await,
>>>>>>> ed46ff9 (Add bench command skeleton)
    }
}
