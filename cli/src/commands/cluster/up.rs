use anyhow::{bail, Context, Result};
use clap::Args as ClapArgs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

#[derive(ClapArgs)]
pub struct UpArgs {
    /// Path to the OpenLake node TOML config.
    #[arg(long)]
    pub config: PathBuf,
}

pub async fn run(args: UpArgs) -> Result<()> {
    run_with_command("openlaked", &args.config).await
}

pub(crate) async fn run_with_command(binary: &str, config: &Path) -> Result<()> {
    println!(
        "bringing openlake cluster up using config: {}",
        config.display()
    );

    let mut child = Command::new(binary)
        .arg("--config")
        .arg(config)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| format!("failed to start {binary} process"))?;

    println!("Openlaked process started successfully");

    let status = child.wait()?;

    if status.success() {
        println!("Cluster exited successfully");
        Ok(())
    } else {
        println!("Cluster exited with failure: {status}");
        bail!("openlaked exited with failure: {status}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[compio::test]
    async fn test_run_with_command_success() {
        let dummy_config = std::env::temp_dir().join(format!(
            "openlake_test_up_success_{}.toml",
            std::process::id()
        ));
        let _ = std::fs::write(&dummy_config, "");

        #[cfg(unix)]
        let binary = "true";
        #[cfg(windows)]
        let binary = "cmd";

        let res = run_with_command(binary, &dummy_config).await;
        assert!(res.is_ok(), "Expected success but got: {res:?}");

        let _ = std::fs::remove_file(dummy_config);
    }

    #[compio::test]
    async fn test_run_with_command_failure_propagates_error() {
        let dummy_config = std::env::temp_dir().join(format!(
            "openlake_test_up_failure_{}.toml",
            std::process::id()
        ));
        let _ = std::fs::write(&dummy_config, "");

        #[cfg(unix)]
        let binary = "false";
        #[cfg(windows)]
        let binary = "cmd";

        let res = run_with_command(binary, &dummy_config).await;
        assert!(res.is_err(), "Expected failure error but succeeded");

        let err_msg = res.unwrap_err().to_string();
        assert!(
            err_msg.contains("exited with failure"),
            "Error message should contain failure status, got: {err_msg}"
        );

        let _ = std::fs::remove_file(dummy_config);
    }
}
