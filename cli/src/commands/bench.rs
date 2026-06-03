use anyhow::Result;
use clap::Args as ClapArgs;

#[derive(ClapArgs)]
pub struct BenchArgs {
    #[arg(long)]
    pub mixed: bool,

    #[arg(long, default_value_t = 10000)]
    pub n: usize,

    #[arg(long, default_value_t = 4096)]
    pub size: usize,

    #[arg(long, default_value_t = 64)]
    pub concurrency: usize,
}

pub async fn run(args: BenchArgs) -> Result<()> {
    println!(
        "bench: mixed={}, n={}, size={}, concurrency={}",
        args.mixed,
        args.n,
        args.size,
        args.concurrency
    );

    Ok(())
}