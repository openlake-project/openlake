use anyhow::{Context, Result};
use clap::Args as ClapArgs;
use std::path::PathBuf;

use openlake_io::rpc::{self, Request, Response};

use crate::config;

#[derive(ClapArgs)]
pub struct ScrubArgs {
    /// Cluster TOML. One TOML describes exactly one cluster.
    #[arg(long)]
    pub config: PathBuf,

    /// Show what would be deleted without performing deletion.
    #[arg(long)]
    pub dry_run: bool,
}

pub async fn run(args: ScrubArgs) -> Result<()> {
    let cfg = config::load(&args.config)
        .with_context(|| format!("load {}", args.config.display()))?;

    if cfg.nodes.is_empty() {
        println!("No running cluster detected. Run: openlake cluster up");
        return Ok(());
    }

    if args.dry_run {
        let client = cyper::Client::builder().http2_prior_knowledge().build();
        run_dry_run(&cfg.nodes, &client).await?;
        return Ok(());
    }

    let mut last_err: Option<anyhow::Error> = None;
    for node in &cfg.nodes {
        let url = format!("http://{}/v1/rpc", node.rpc_addr);
        let client = cyper::Client::builder().http2_prior_knowledge().build();
        let req = Request::ScrubCluster;
        let body = rpc::encode(&req).map_err(|e| anyhow::anyhow!(e.to_string()))?;
        let resp = match client.post(&url)?.body(body).send().await {
            Ok(resp) => resp,
            Err(e) => {
                last_err = Some(anyhow::anyhow!("node {}: {}", node.id, e));
                continue;
            }
        };
        let status = resp.status();
        let bytes = resp.bytes().await.map_err(|e| anyhow::anyhow!(e.to_string()))?;
        if !status.is_success() {
            if let Ok(Response::Err(e)) = rpc::decode(&bytes) {
                last_err = Some(anyhow::anyhow!("node {}: rpc error: {:?}", node.id, e));
                continue;
            }
            last_err = Some(anyhow::anyhow!("node {}: rpc HTTP status: {}", node.id, status));
            continue;
        }
        match rpc::decode::<Response>(&bytes).map_err(|e| anyhow::anyhow!(e.to_string()))? {
            Response::Scrub(n) => {
                println!("purged {} objects", n);
                return Ok(());
            }
            Response::Err(e) => {
                last_err = Some(anyhow::anyhow!("node {}: rpc error: {:?}", node.id, e));
            }
            other => {
                last_err = Some(anyhow::anyhow!("node {}: unexpected rpc response: {:?}", node.id, other));
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("no openlake cluster node responded")))
}

async fn run_dry_run(nodes: &[config::NodeToml], client: &cyper::Client) -> Result<()> {
    println!(
        "WARNING: This operation will delete all objects and may take several minutes."
    );
    println!("Dry run: no objects will be deleted.");
    println!("Cluster ID: unavailable from current RPC API.");
    println!("Deployment ID: unavailable from current RPC API.");
    println!("Cluster nodes: {}", nodes.len());

    for node in nodes {
        println!("Node {}: {}", node.id, node.rpc_addr);
        match query_node_buckets(node, client).await {
            Ok(summary) => {
                if summary.buckets.is_empty() {
                    println!("  buckets: none detected");
                    continue;
                }
                println!("  buckets: {}", summary.buckets.join(", "));
                println!("  object count: {}", summary.total_objects);
                for bucket in &summary.bucket_counts {
                    println!("    {}: {} objects", bucket.0, bucket.1);
                }
                if !summary.sample_objects.is_empty() {
                    println!("  sample deletions:");
                    for key in &summary.sample_objects {
                        println!("    {}", key);
                    }
                }
            }
            Err(e) => {
                println!("  error querying node: {e}");
            }
        }
    }

    println!("Bucket information: buckets above were discovered from node RPC.");
    println!("Would delete: all objects from all buckets.");
    Ok(())
}

struct BucketSummary {
    buckets: Vec<String>,
    total_objects: usize,
    bucket_counts: Vec<(String, usize)>,
    sample_objects: Vec<String>,
}

async fn query_node_buckets(node: &config::NodeToml, client: &cyper::Client) -> Result<BucketSummary> {
    let buckets = list_buckets(node, client).await?;
    let mut total_objects = 0;
    let mut bucket_counts = Vec::new();
    let mut sample_objects = Vec::new();

    for bucket in buckets.iter() {
        let (count, sample) = count_bucket_objects(node, client, bucket).await?;
        total_objects += count;
        bucket_counts.push((bucket.clone(), count));
        sample_objects.extend(sample.into_iter());
        if sample_objects.len() >= 10 {
            sample_objects.truncate(10);
        }
    }

    Ok(BucketSummary {
        buckets,
        total_objects,
        bucket_counts,
        sample_objects,
    })
}

async fn list_buckets(node: &config::NodeToml, client: &cyper::Client) -> Result<Vec<String>> {
    let response = rpc_call(node, client, Request::ListVols { disk_idx: 0 }).await?;
    match response {
        Response::Vols(vols) => Ok(vols.into_iter().map(|v| v.name).collect()),
        Response::Err(e) => Err(anyhow::anyhow!("node {}: rpc error: {:?}", node.id, e)),
        other => Err(anyhow::anyhow!("node {}: unexpected rpc response: {:?}", node.id, other)),
    }
}

async fn count_bucket_objects(
    node: &config::NodeToml,
    client: &cyper::Client,
    bucket: &str,
) -> Result<(usize, Vec<String>)> {
    let mut total: usize = 0;
    let mut sample = Vec::new();
    let mut start_after: Option<String> = None;
    const PAGE_SIZE: u32 = 1000;

    loop {
        let response = rpc_call(node, client, Request::WalkDir {
            disk_idx: 0,
            volume: bucket.to_owned(),
            base_dir: "".into(),
            recursive: true,
            prefix_filter: "".into(),
            start_after: start_after.clone(),
            max_keys: Some(PAGE_SIZE),
        })
        .await?;

        let entries = match response {
            Response::Walked(entries) => entries,
            Response::Err(e) => return Err(anyhow::anyhow!("node {}: rpc error: {:?}", node.id, e)),
            other => return Err(anyhow::anyhow!("node {}: unexpected rpc response: {:?}", node.id, other)),
        };

        if entries.is_empty() {
            break;
        }

        total += entries.len();
        for (key, _) in entries.iter() {
            if sample.len() < 10 {
                sample.push(key.clone());
            }
        }

        if entries.len() < PAGE_SIZE as usize {
            break;
        }

        start_after = entries.last().map(|(k, _)| k.clone());
    }

    Ok((total, sample))
}

async fn rpc_call(node: &config::NodeToml, client: &cyper::Client, req: Request) -> Result<Response> {
    let url = format!("http://{}/v1/rpc", node.rpc_addr);
    let body = rpc::encode(&req).map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let resp = client.post(&url)?.body(body).send().await.map_err(|e| anyhow::anyhow!("node {}: {}", node.id, e))?;
    let status = resp.status();
    let bytes = resp.bytes().await.map_err(|e| anyhow::anyhow!(e.to_string()))?;

    if !status.is_success() {
        if let Ok(Response::Err(e)) = rpc::decode(&bytes) {
            return Err(anyhow::anyhow!("node {}: rpc error: {:?}", node.id, e));
        }
        return Err(anyhow::anyhow!("node {}: rpc HTTP status: {}", node.id, status));
    }

    let response = rpc::decode::<Response>(&bytes).map_err(|e| anyhow::anyhow!(e.to_string()))?;
    Ok(response)
}
