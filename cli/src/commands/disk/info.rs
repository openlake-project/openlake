use anyhow::Result;
use clap::Args as ClapArgs;

#[derive(ClapArgs)]
pub struct InfoArgs {}

pub async fn run(_args: InfoArgs) -> Result<()> {
    println!("Disk information command");
    Ok(())
}
