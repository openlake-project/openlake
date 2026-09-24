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

    #[arg(
        long,
        default_value = "1",
        value_delimiter = ',',
        value_parser = clap::value_parser!(u32).range(1..)
    )]
    pub batch_sizes: Vec<u32>,

    #[arg(
        long,
        default_value = "1",
        value_delimiter = ',',
        value_parser = clap::value_parser!(u32).range(1..)
    )]
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
    n.checked_mul(mul)
        .ok_or_else(|| anyhow::anyhow!("size {s:?} exceeds the maximum supported byte count"))
}

#[cfg(test)]
mod tests {
    use super::{parse_size, ClientArgs};
    use clap::{error::ErrorKind, Parser};

    #[test]
    fn rejects_size_unit_overflow() {
        for input in [
            "18014398509481984KiB",
            "17592186044416MiB",
            "17179869184GiB",
        ] {
            assert!(parse_size(input).is_err(), "must reject {input}");
        }
    }

    #[test]
    fn accepts_largest_representable_sizes() {
        for (suffix, multiplier) in [
            ("", 1),
            ("B", 1),
            ("KiB", 1 << 10),
            ("MiB", 1 << 20),
            ("GiB", 1 << 30),
        ] {
            let units = u64::MAX / multiplier;
            let input = format!("{units}{suffix}");
            assert_eq!(parse_size(&input).unwrap(), units * multiplier);
        }
    }

    #[test]
    fn parses_supported_size_units() {
        for (input, expected) in [
            ("0", 0),
            ("42", 42),
            ("42B", 42),
            ("4KiB", 4096),
            ("2MiB", 2_097_152),
            ("1GiB", 1_073_741_824),
            (" 4 KiB ", 4096),
        ] {
            assert_eq!(parse_size(input).unwrap(), expected, "input: {input}");
        }
    }

    #[test]
    fn rejects_zero_thread_counts() {
        for value in ["0", "0,1", "1,0", "1,0,2"] {
            let error = ClientArgs::try_parse_from([
                "client",
                "--target",
                "127.0.0.1:9090",
                "--threads",
                value,
            ])
            .expect_err("zero thread counts must be rejected");
            assert_eq!(error.kind(), ErrorKind::ValueValidation);
        }
    }

    #[test]
    fn rejects_zero_batch_sizes() {
        for value in ["0", "0,1", "1,0", "1,0,2"] {
            let error = ClientArgs::try_parse_from([
                "client",
                "--target",
                "127.0.0.1:9090",
                "--batch-sizes",
                value,
            ])
            .expect_err("zero batch sizes must be rejected");
            assert_eq!(error.kind(), ErrorKind::ValueValidation);
        }
    }

    #[test]
    fn accepts_positive_thread_counts_and_batch_sizes() {
        let args = ClientArgs::try_parse_from([
            "client",
            "--target",
            "127.0.0.1:9090",
            "--threads",
            "1,4",
            "--batch-sizes",
            "1,8",
        ])
        .expect("positive thread counts and batch sizes must be accepted");

        assert_eq!(args.threads, vec![1, 4]);
        assert_eq!(args.batch_sizes, vec![1, 8]);
    }

    #[test]
    fn defaults_to_one_thread_and_one_request_per_batch() {
        let args = ClientArgs::try_parse_from(["client", "--target", "127.0.0.1:9090"])
            .expect("default benchmark arguments must be accepted");

        assert_eq!(args.threads, vec![1]);
        assert_eq!(args.batch_sizes, vec![1]);
    }
}
