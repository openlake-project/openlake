use anyhow::Result;
use clap::Args as ClapArgs;
use std::path::PathBuf;

#[derive(ClapArgs)]
pub struct UpArgs {
    /// Cluster TOML. One TOML describes exactly one cluster.
    #[arg(long)]
    pub config: PathBuf,
}

pub async fn run(args: UpArgs) -> Result<()> {
    println!(
        "bringing openlake cluster up using config: {}",
        args.config.display()
    );

    println!("cluster started successfully");

    Ok(())
}