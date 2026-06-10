mod client;
#[cfg(feature = "rdma")]
mod dct;
mod mode;
mod report;
mod target;

use std::path::PathBuf;

use anyhow::Result;
use clap::{Args as ClapArgs, Parser, Subcommand, ValueEnum};

#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum ModeArg {
    Auto,
    Rdma,
    Tls,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum OpArg {
    Read,
    Write,
    Mixed,
}

#[derive(ClapArgs)]
pub struct Args {
    #[command(subcommand)]
    pub sub: BenchCmd,
}

#[derive(Subcommand)]
pub enum BenchCmd {
    /// Spin up the bench listener.
    Target(TargetArgs),

    /// Drive traffic against a running bench target peer.
    Client(ClientArgs),
}

#[derive(Parser, Debug)]
pub struct TargetArgs {
    #[arg(long, value_enum, default_value_t = ModeArg::Auto)]
    pub mode: ModeArg,

    #[arg(long, default_value = "0.0.0.0:9090")]
    pub bind: String,

    #[arg(long, default_value = "256MiB")]
    pub buf_size: String,

    #[arg(long)]
    pub config: Option<PathBuf>,
}

#[derive(Parser, Debug)]
pub struct ClientArgs {
    #[arg(long, value_enum, default_value_t = ModeArg::Auto)]
    pub mode: ModeArg,

    #[arg(long)]
    pub target: String,

    #[arg(long, value_enum, default_value_t = OpArg::Read)]
    pub op: OpArg,

    #[arg(
        long,
        default_value = "4KiB,16KiB,32KiB,64KiB,128KiB,256KiB,512KiB,1MiB",
        value_delimiter = ','
    )]
    pub block_sizes: Vec<String>,

    #[arg(long, default_value = "1", value_delimiter = ',')]
    pub batch_sizes: Vec<u32>,

    #[arg(long, default_value = "1", value_delimiter = ',')]
    pub threads: Vec<u32>,

    #[arg(long, default_value_t = 1)]
    pub duration_secs: u64,

    #[arg(long, default_value_t = 0)]
    pub warmup_secs: u64,

    #[arg(long)]
    pub config: Option<PathBuf>,
}

pub async fn run(args: Args) -> Result<()> {
    match args.sub {
        BenchCmd::Target(a) => target::run(a).await,
        BenchCmd::Client(a) => client::run(a).await,
    }
}

pub fn parse_size(s: &str) -> Result<u64> {
    let s = s.trim();
    let (num_part, mul): (&str, u64) = if let Some(p) = s.strip_suffix("GiB") {
        (p, 1u64 << 30)
    } else if let Some(p) = s.strip_suffix("MiB") {
        (p, 1u64 << 20)
    } else if let Some(p) = s.strip_suffix("KiB") {
        (p, 1u64 << 10)
    } else if let Some(p) = s.strip_suffix("B") {
        (p, 1)
    } else {
        (s, 1)
    };
    let n: u64 = num_part.trim().parse()?;
    Ok(n * mul)
}
