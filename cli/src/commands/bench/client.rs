use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use bytes::Bytes;
use futures::future::join_all;
use hdrhistogram::Histogram;

use super::mode::{resolve_mode, BenchMode};
use super::report::{
    print_header, print_preamble, print_row, print_table, Cell, ClientPreamble, Report,
};
use super::{parse_size, ClientArgs, OpArg};

pub async fn run(args: ClientArgs) -> Result<()> {
    let mode = resolve_mode(args.config.as_deref(), args.mode)?;
    let block_bytes: Vec<u64> = args
        .block_sizes
        .iter()
        .map(|s| parse_size(s))
        .collect::<Result<_>>()?;

    print_preamble(&ClientPreamble {
        target: args.target.clone(),
        mode,
        duration_secs: args.duration_secs,
        warmup_secs: args.warmup_secs,
    });

    let _report = match mode {
        BenchMode::Tls => run_tls(&args, &block_bytes).await?,
        BenchMode::Rdma => {
            let r = run_rdma(&args, &block_bytes).await?;
            print_table(&r);
            r
        }
    };
    Ok(())
}

async fn run_tls(args: &ClientArgs, block_bytes: &[u64]) -> Result<Report> {
    let cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(0);
    tracing::info!(target: "cpu_probe", "Detected {cores} CPU cores online");
    tracing::info!(target: "transport_selector",
        "Backend selected: h2c (TCP + HTTP/2 prior knowledge, plaintext)");

    let dns_started = std::time::Instant::now();
    let resolved: Vec<std::net::SocketAddr> =
        std::net::ToSocketAddrs::to_socket_addrs(&args.target)
            .map(|i| i.collect())
            .unwrap_or_default();
    let dns_us = dns_started.elapsed().as_micros();
    if let Some(addr) = resolved.first() {
        tracing::info!(target: "dns",
            "Resolved {} -> {addr} in {dns_us} us ({} candidate(s))",
            args.target, resolved.len());
    } else {
        tracing::warn!(target: "dns", "Failed to resolve {} (will let cyper retry)", args.target);
    }

    let url_base = format!("http://{}", args.target);
    let build_started = std::time::Instant::now();
    let client = cyper::Client::builder().http2_prior_knowledge().build();
    let build_us = build_started.elapsed().as_micros();
    tracing::info!(target: "cyper_client",
        "cyper Client built in {build_us} us (h2 prior knowledge, plaintext, idle pool reuse)");

    let warmup = Duration::from_secs(args.warmup_secs);
    let duration = Duration::from_secs(args.duration_secs);
    let op_str: &'static str = match args.op {
        OpArg::Read => "read",
        OpArg::Write => "write",
    };

    let probe_started = std::time::Instant::now();
    let probe = async {
        let resp = client
            .get(format!("{url_base}/bench/echo/4"))?
            .send()
            .await?;
        let status = resp.status();
        let _ = resp.bytes().await?;
        anyhow::Ok(status)
    }
    .await;
    match probe {
        Ok(status) => {
            let probe_us = probe_started.elapsed().as_micros();
            tracing::info!(target: "segment_manager",
                "Opened segment #1: {} (status {}, {} us RTT)",
                args.target, status, probe_us);
        }
        Err(e) => tracing::warn!(target: "segment_manager",
            "Probe to {} failed: {e}", args.target),
    }

    print_header();
    let mut cells: Vec<Cell> = Vec::new();
    for &threads in &args.threads {
        for &batch in &args.batch_sizes {
            for &block in block_bytes {
                let cell = run_cell_tls(
                    &client, &url_base, block, batch, threads, args.op, op_str, warmup, duration,
                )
                .await?;
                print_row(&cell);
                cells.push(cell);
            }
        }
    }
    Ok(Report { cells })
}

async fn run_cell_tls(
    client: &cyper::Client,
    url_base: &str,
    block: u64,
    batch: u32,
    threads: u32,
    op: OpArg,
    op_str: &'static str,
    warmup: Duration,
    duration: Duration,
) -> Result<Cell> {
    let hist = Arc::new(Mutex::new(Histogram::<u64>::new_with_bounds(
        1, 60_000_000, 3,
    )?));
    let iters = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let bytes = Arc::new(std::sync::atomic::AtomicU64::new(0));

    if !warmup.is_zero() {
        drive(
            client, url_base, block, batch, threads, op, warmup, None, None, None,
        )
        .await?;
    }
    let started = Instant::now();
    drive(
        client,
        url_base,
        block,
        batch,
        threads,
        op,
        duration,
        Some(hist.clone()),
        Some(iters.clone()),
        Some(bytes.clone()),
    )
    .await?;
    let elapsed_us = started.elapsed().as_micros();

    let h = std::mem::replace(
        &mut *hist.lock().unwrap(),
        Histogram::<u64>::new_with_bounds(1, 60_000_000, 3)?,
    );
    Ok(Cell {
        block_bytes: block,
        batch,
        threads,
        op: op_str,
        iters: iters.load(std::sync::atomic::Ordering::Relaxed),
        bytes: bytes.load(std::sync::atomic::Ordering::Relaxed) as u128,
        elapsed_us,
        lat: h,
    })
}

async fn drive(
    client: &cyper::Client,
    url_base: &str,
    block: u64,
    batch: u32,
    threads: u32,
    op: OpArg,
    duration: Duration,
    hist: Option<Arc<Mutex<Histogram<u64>>>>,
    iters: Option<Arc<std::sync::atomic::AtomicU64>>,
    bytes: Option<Arc<std::sync::atomic::AtomicU64>>,
) -> Result<()> {
    let deadline = Instant::now() + duration;
    let mut tasks = Vec::with_capacity(threads as usize);
    for _ in 0..threads {
        let client = client.clone();
        let url_base = url_base.to_string();
        let hist = hist.clone();
        let iters = iters.clone();
        let bytes = bytes.clone();
        tasks.push(compio::runtime::spawn(async move {
            worker(
                client, url_base, block, batch, op, deadline, hist, iters, bytes,
            )
            .await
        }));
    }
    for t in tasks {
        t.await
            .map_err(|e| anyhow::anyhow!("worker join: {e:?}"))??;
    }
    Ok(())
}

async fn worker(
    client: cyper::Client,
    url_base: String,
    block: u64,
    batch: u32,
    op: OpArg,
    deadline: Instant,
    hist: Option<Arc<Mutex<Histogram<u64>>>>,
    iters: Option<Arc<std::sync::atomic::AtomicU64>>,
    bytes: Option<Arc<std::sync::atomic::AtomicU64>>,
) -> Result<()> {
    let put_body: Option<Bytes> = match op {
        OpArg::Write => Some(Bytes::from(vec![0u8; block as usize])),
        OpArg::Read => None,
    };

    while Instant::now() < deadline {
        let start = Instant::now();
        let mut calls = Vec::with_capacity(batch as usize);
        for _ in 0..batch {
            calls.push(one_call(&client, &url_base, block, op, put_body.clone()));
        }
        let results = join_all(calls).await;
        let lat_us = start.elapsed().as_micros() as u64;
        for r in results {
            r?;
        }
        if let Some(h) = &hist {
            let _ = h.lock().unwrap().record(lat_us.max(1));
        }
        if let Some(c) = &iters {
            c.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        if let Some(c) = &bytes {
            c.fetch_add(block * batch as u64, std::sync::atomic::Ordering::Relaxed);
        }
    }
    Ok(())
}

async fn one_call(
    client: &cyper::Client,
    url_base: &str,
    block: u64,
    op: OpArg,
    put_body: Option<Bytes>,
) -> Result<()> {
    match op {
        OpArg::Read => {
            let url = format!("{url_base}/bench/echo/{block}");
            let resp = client
                .get(url)
                .context("build GET")?
                .send()
                .await
                .context("GET send")?;
            let bytes = resp.bytes().await.context("GET body")?;
            anyhow::ensure!(bytes.len() as u64 == block, "short GET body");
        }
        OpArg::Write => {
            let url = format!("{url_base}/bench/sink");
            let body = put_body.unwrap();
            let resp = client
                .put(url)
                .context("build PUT")?
                .body(body)
                .send()
                .await
                .context("PUT send")?;
            let status = resp.status();
            let _drain = resp.bytes().await.context("PUT body")?;
            anyhow::ensure!(status.is_success(), "PUT non-2xx");
        }
    }
    Ok(())
}

#[cfg(feature = "rdma")]
async fn run_rdma(args: &ClientArgs, block_bytes: &[u64]) -> Result<Report> {
    super::dct::run_client(args, block_bytes).await
}

#[cfg(not(feature = "rdma"))]
async fn run_rdma(_args: &ClientArgs, _block_bytes: &[u64]) -> Result<Report> {
    anyhow::bail!(
        "rdma client: this build was produced without --features rdma. \
         Rebuild with `cargo build --bin openlake --features rdma` on a Linux \
         host with ibverbs headers, or run `openlake bench client --mode tls` instead."
    )
}
