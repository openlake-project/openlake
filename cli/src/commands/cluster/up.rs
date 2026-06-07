use anyhow::{Context, Result};
use clap::Args as ClapArgs;
use std::path::PathBuf;
use std::process::{Command, Stdio};

#[derive(ClapArgs)]
pub struct UpArgs {
    /// Path to the OpenLake node TOML config.
    #[arg(long)]
    pub config: PathBuf,
}

pub async fn run(args: UpArgs) -> Result<()> {
    println!(
        "bringing openlake cluster up using config: {}",
        args.config.display()
    );

    let mut child = Command::new("openlaked")
        .arg("--config")
        .arg(&args.config)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .context("failed to start openlaked process")?;

    println!("Openlaked process started successfully");

    let status = child.wait()?;

    if status.success() {
        println!("Cluster exited successfully");
    } else {
        println!("Cluster exited with failure: {}", status);
    }

    Ok(())
}
