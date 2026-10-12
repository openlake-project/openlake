use anyhow::Result;
use clap::Args as ClapArgs;
use std::path::PathBuf;

#[derive(ClapArgs)]
pub struct ConfigArgs {
    #[arg(long)]
    pub config: PathBuf,
}

pub async fn run(args: ConfigArgs) -> Result<()> {
    println!("Config command running");
    println!("Config file: {:?}", args.config);

    Ok(())
}