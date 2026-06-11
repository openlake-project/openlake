use anyhow::{Context, Result};
use clap::Args as ClapArgs;
use std::io::{self, Write};
use std::process::Command;

#[derive(ClapArgs)]
pub struct DownArgs {
    /// Skip confirmation prompt.
    #[arg(long)]
    pub allow: bool,
}

pub async fn run(args: DownArgs) -> Result<()> {
    println!("Bringing OpenLake cluster down");

    println!(
        "Warning: this command only stops local openlaked processes and does not affect remote multi-node clusters."
    );

    if !args.allow {
        print!("Are you sure you want to stop the cluster? (Y/n): ");
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        let input = input.trim().to_lowercase();

        if input == "n" || input == "no" {
            println!("Cluster shutdown aborted.");
            return Ok(());
        }
    }

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
