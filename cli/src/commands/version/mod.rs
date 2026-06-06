use anyhow::Result;
use clap::Parser;

#[derive(Parser)]
pub struct VersionArgs {}

pub async fn run(_args:  VersionArgs) -> Result<()> {
    println!("OpenLake CLI Version 0.1.0");
    Ok(())
}
