use anyhow::Result;
use clap::Args as ClapArgs;

const CLUSTER_INFO_PATH: &str = "/openlake/admin/v1/cluster/info";

#[derive(ClapArgs)]
pub struct ClusterInfoArgs {
    /// Admin address of the OpenLake node
    #[arg(long)]
    pub admin_addr: String,
}

pub async fn run(args: ClusterInfoArgs) -> Result<()> {
    let url = format!("{}{}", args.admin_addr, CLUSTER_INFO_PATH);

    let response = reqwest::blocking::get(&url)?;

    if !response.status().is_success() {
        anyhow::bail!("Request failed with status: {}", response.status());
    }

    let body = response.text()?;

    println!("{}", body);

    Ok(())
}