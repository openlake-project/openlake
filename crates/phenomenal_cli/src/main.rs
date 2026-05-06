//! CLI for manual smoke tests against a local single node engine. The same
//! Engine code path runs in the server with a multi node cluster; here we
//! just degenerate to one node and one local backend.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::rc::Rc;
use std::time::{Duration, Instant};

use anyhow::Result;
use clap::{Parser, Subcommand};
use futures_util::stream::{FuturesUnordered, StreamExt};
use phenomenal_io::stream::{read_full, VecByteStream};
use phenomenal_io::{LocalFsBackend, StorageBackend};
use phenomenal_storage::{ClusterConfig, DiskAddr, Engine, NodeAddr};

#[derive(Parser)]
#[command(about = "phenomenal rust layer 1 storage CLI")]
struct Cli {
    /// Root directory for on disk data.
    #[arg(long, default_value = "/tmp/phenomenal")]
    root: PathBuf,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    CreateBucket { bucket: String },
    DeleteBucket { bucket: String, #[arg(long)] force: bool },

    /// Upload an object. `file` may be `_` for stdin.
    Put {
        bucket: String,
        key: String,
        file: String,
        #[arg(long)]
        content_type: Option<String>,
    },

    /// Download an object to `file`, or `_` for stdout.
    Get {
        bucket: String,
        key: String,
        #[arg(default_value = "_")]
        file: String,
    },

    Stat   { bucket: String, key: String },
    Delete { bucket: String, key: String },
    List   { bucket: String, #[arg(default_value = "")] prefix: String },

    /// In-process microbenchmark: PUT, GET, DELETE phases against the
    /// engine directly. No HTTP, no RPC — measures the storage layer's
    /// own ceiling.
    Bench {
        #[arg(long, default_value_t = 10_000)]  n: usize,
        #[arg(long, default_value_t = 4096)]    size: usize,
        #[arg(long, default_value_t = 64)]      concurrency: usize,
        #[arg(long, default_value = "bench")]   bucket: String,
    },
}

#[compio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    let cluster = ClusterConfig {
        nodes: vec![NodeAddr {
            id: 0,
            rpc_addr: "127.0.0.1:0".parse().unwrap(),
            disk_count: 1,
        }],
        set_drive_count:      1,
        // Single-disk CLI test cluster: no parity, EC[1+0].
        default_parity_count: 0,
    };
    let mut backends: HashMap<DiskAddr, Rc<dyn StorageBackend>> = HashMap::new();
    backends.insert(
        DiskAddr { node_id: 0, disk_idx: 0 },
        Rc::new(LocalFsBackend::new(&cli.root)?),
    );
    // todo: @arnav check this locking server, we need to make this distributed instead of centralized
    // CLI is single-process, single-writer; the no-op dsync grants
    // every acquire instantly. Multi-node deployments use the real
    // dsync client wired in `phenomenald` (see phenomenal_server::main).
    let dsync  = Rc::new(phenomenal_storage::DsyncClient::no_op());
    let engine = Rc::new(Engine::new(cluster, backends, dsync, 0));

    match cli.cmd {
        Cmd::CreateBucket { bucket } => {
            engine.create_bucket(&bucket).await?;
            println!("created {bucket}");
        }
        Cmd::DeleteBucket { bucket, force } => {
            engine.delete_bucket(&bucket, force).await?;
            println!("deleted {bucket}");
        }
        Cmd::Put { bucket, key, file, content_type } => {
            let data = read_input(&file)?;
            let n    = data.len();
            let mut src = VecByteStream::new(data);
            let info = engine.put(&bucket, &key, n as u64, &mut src, content_type).await?;
            println!("{} bytes  etag={}  class={:?}", n, info.etag, info.storage_class);
        }
        Cmd::Get { bucket, key, file } => {
            let (info, mut stream) = engine.get(&bucket, &key).await?;
            let mut buf = vec![0u8; info.size as usize];
            let n = read_full(stream.as_mut(), &mut buf[..]).await?;
            buf.truncate(n);
            write_output(&file, &buf)?;
        }
        Cmd::Stat { bucket, key } => {
            let info = engine.stat(&bucket, &key).await?;
            println!(
                "{}/{}  size={}  etag={}  class={:?}  content_type={:?}  mtime_ms={}",
                info.bucket, info.key, info.size, info.etag,
                info.storage_class, info.content_type, info.modified_ms
            );
        }
        Cmd::Delete { bucket, key } => {
            engine.delete(&bucket, &key).await?;
            println!("deleted {bucket}/{key}");
        }
        Cmd::List { bucket, prefix } => {
            for info in engine.list(&bucket, &prefix).await? {
                println!("{:>12}  {}", info.size, info.key);
            }
        }
        Cmd::Bench { n, size, concurrency, bucket } => {
            run_bench(engine, bucket, n, size, concurrency).await?;
        }
    }
    Ok(())
}

async fn run_bench(
    engine: Rc<Engine>,
    bucket: String,
    n: usize,
    size: usize,
    c: usize,
) -> Result<()> {
    // Idempotent setup: create the bucket if absent, ignore if present.
    match engine.create_bucket(&bucket).await {
        Ok(()) => {}
        Err(e) => {
            // BucketAlreadyExists is fine; any other error is fatal.
            let s = e.to_string();
            if !s.contains("already exists") && !s.contains("VolumeExists") {
                return Err(e.into());
            }
        }
    }

    let payload: Vec<u8> = vec![0xABu8; size];

    let put_times = phase("PUT", n, c, size as u64, |i| {
        let engine = engine.clone();
        let bucket = bucket.clone();
        let data   = payload.clone();
        let total  = data.len() as u64;
        async move {
            let mut src = VecByteStream::new(data);
            engine.put(&bucket, &format!("k{i}"), total, &mut src, None).await?;
            Ok(())
        }
    }).await?;
    drop(put_times);

    let get_times = phase("GET", n, c, size as u64, |i| {
        let engine = engine.clone();
        let bucket = bucket.clone();
        async move {
            let (info, mut stream) = engine.get(&bucket, &format!("k{i}")).await?;
            // Drain by pulling Bytes (refcount only) — bench cares
            // about throughput, not the bytes themselves.
            let mut left = info.size;
            while left > 0 {
                let chunk = stream.read().await?;
                if chunk.is_empty() { break; }
                left = left.saturating_sub(chunk.len() as u64);
            }
            Ok(())
        }
    }).await?;
    drop(get_times);

    let del_times = phase("DELETE", n, c, 0, |i| {
        let engine = engine.clone();
        let bucket = bucket.clone();
        async move {
            engine.delete(&bucket, &format!("k{i}")).await?;
            Ok(())
        }
    }).await?;
    drop(del_times);

    Ok(())
}

/// Drive one bench phase: launch N ops with at most `c` in flight via
/// `FuturesUnordered`, record per-op wall time, then print a summary.
/// `bytes_per_op` is used only for the MiB/s column (0 skips it).
async fn phase<F, Fut>(
    name: &str,
    n: usize,
    c: usize,
    bytes_per_op: u64,
    make_op: F,
) -> Result<Vec<Duration>>
where
    F: Fn(usize) -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    let mut pending: FuturesUnordered<_> = FuturesUnordered::new();
    let mut times   = Vec::with_capacity(n);
    let mut sent    = 0usize;
    let wall_start  = Instant::now();

    while times.len() < n {
        while pending.len() < c && sent < n {
            let i   = sent;
            sent   += 1;
            let fut = make_op(i);
            pending.push(async move {
                let s = Instant::now();
                fut.await?;
                Ok::<_, anyhow::Error>(s.elapsed())
            });
        }
        match pending.next().await {
            Some(r) => times.push(r?),
            None    => break,
        }
    }

    let wall = wall_start.elapsed();
    report(name, n, c, wall, bytes_per_op, &mut times);
    Ok(times)
}

fn report(name: &str, n: usize, c: usize, wall: Duration, bytes_per_op: u64, times: &mut [Duration]) {
    times.sort_unstable();
    let p50 = times[n / 2];
    let p99 = times[(n * 99) / 100];
    let ops = n as f64 / wall.as_secs_f64();
    let mut tail = String::new();
    if bytes_per_op > 0 {
        let mbs = ops * bytes_per_op as f64 / (1024.0 * 1024.0);
        tail = format!("  {mbs:>8.2} MiB/s");
    }
    println!(
        "{name:<6} n={n:<6} c={c:<4} wall={:>6.2}s  {ops:>9.0} ops/s{tail}  p50={:>6.2}ms  p99={:>6.2}ms",
        wall.as_secs_f64(),
        p50.as_secs_f64() * 1000.0,
        p99.as_secs_f64() * 1000.0,
    );
}

fn read_input(path: &str) -> Result<Vec<u8>> {
    if path == "_" {
        let mut buf = Vec::new();
        std::io::stdin().read_to_end(&mut buf)?;
        Ok(buf)
    } else {
        Ok(std::fs::read(path)?)
    }
}

fn write_output(path: &str, data: &[u8]) -> Result<()> {
    if path == "_" {
        std::io::stdout().write_all(data)?;
    } else {
        std::fs::write(path, data)?;
    }
    Ok(())
}
