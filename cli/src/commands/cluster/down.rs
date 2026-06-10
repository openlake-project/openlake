use anyhow::{Context, Result};
use clap::Args as ClapArgs;
use std::process::Command;

#[derive(ClapArgs)]
pub struct DownArgs {}

pub async fn run(_: DownArgs) -> Result<()> {
    println!("bringing OpenLake cluster down");

    let status = Command::new("pkill")
        .arg("openlaked")
        .status()
        .context("failed to stop openlaked")?;

    if status.success() {
        println!("OpenLake cluster stopped successfully");
    } else {
        println!("No running openlaked process found");
    }

    Ok(())
}
