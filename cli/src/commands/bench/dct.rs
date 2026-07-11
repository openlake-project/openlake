#![cfg(feature = "rdma")]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use compio::io::{AsyncReadExt, AsyncWriteExt};
use compio::net::{TcpListener, TcpStream};
use futures::future::join_all;
use hdrhistogram::Histogram;

use openlake_io::rdma::{
    ClusterRoutingTable, IbSocket, LocalEndpoint, RdmaConfig, RdmaNode, RdmaQos,
};

use super::report::{Cell, Report};
use super::{ClientArgs, OpArg};

const DEV_NAME: &str = "mlx5_ib0";
const DC_KEY: u64 = 0x0BAD_BEEF_C0FFEE_u64;
const BULK_POOL_CAP: usize = 1;
const SELF_TARGET_ID: u16 = 0;
const SELF_CLIENT_ID: u16 = 1;
const NUM_NODES: u16 = 2;
const RUNTIME_ID: u16 = 0;

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
struct BenchHandshake {
    ep: LocalEndpoint,
    vaddr: u64,
    rkey: u32,
    length: u64,
}

fn cfg_for(self_id: u16, buf_size: usize) -> RdmaConfig {
    RdmaConfig {
        self_node_id: self_id,
        runtime_id: RUNTIME_ID,
        dev_name: DEV_NAME.to_string(),
        dc_key: DC_KEY,
        qos: RdmaQos {
            traffic_class: 0,
            service_level: 0,
        },
        bulk_buf_size: buf_size,
        bulk_pool_cap: BULK_POOL_CAP,
        num_cluster_nodes: NUM_NODES,
    }
}

async fn send_json<T: serde::Serialize>(s: &mut TcpStream, msg: &T) -> Result<()> {
    let body = serde_json::to_vec(msg).context("serialize handshake")?;
    let len_v = (body.len() as u32).to_be_bytes().to_vec();
    let r = s.write_all(len_v).await;
    r.0.context("write handshake len")?;
    let r = s.write_all(body).await;
    r.0.context("write handshake body")?;
    Ok(())
}

async fn recv_json<T: for<'de> serde::Deserialize<'de>>(s: &mut TcpStream) -> Result<T> {
    let r = s.read_exact(vec![0u8; 4]).await;
    r.0.context("read handshake len")?;
    let len_buf = r.1;
    let len = u32::from_be_bytes([len_buf[0], len_buf[1], len_buf[2], len_buf[3]]) as usize;
    if len == 0 || len > 1 << 20 {
        anyhow::bail!("handshake len out of range: {len}");
    }
    let r = s.read_exact(vec![0u8; len]).await;
    r.0.context("read handshake body")?;
    serde_json::from_slice(&r.1).context("deserialize handshake")
}

pub async fn serve_target(bind: SocketAddr, buf_size: usize) -> Result<()> {
    let cfg = cfg_for(SELF_TARGET_ID, buf_size);
    let (setup, my_ep) =
        RdmaNode::start_local(&cfg).map_err(|e| anyhow::anyhow!("rdma start_local: {e}"))?;
    let buf = setup
        .bulk_pool
        .acquire()
        .await
        .map_err(|e| anyhow::anyhow!("bulk_pool acquire: {e}"))?;
    let my_buf = BenchHandshake {
        ep: my_ep.clone(),
        vaddr: buf.addr(),
        rkey: buf.rkey(),
        length: buf.capacity() as u64,
    };

    let listener = TcpListener::bind(bind)
        .await
        .with_context(|| format!("bind {bind}"))?;
    print_target_banner(bind, buf_size, &my_ep);

    loop {
        let (mut stream, peer_addr) = listener.accept().await.context("accept handshake")?;
        tracing::info!(?peer_addr, "handshake conn");
        match recv_json::<BenchHandshake>(&mut stream).await {
            Ok(client_msg) => {
                tracing::info!(
                    client_dct = client_msg.ep.dct_num,
                    client_lid = client_msg.ep.lid,
                    "got client handshake"
                );
                if let Err(e) = send_json(&mut stream, &my_buf).await {
                    tracing::error!("send_json: {e:#}");
                }
            }
            Err(e) => tracing::error!("recv_json: {e:#}"),
        }
        let _keep_routing = client_routing_table_unused();
    }
}

fn client_routing_table_unused() -> u32 {
    0
}

pub async fn run_client(args: &ClientArgs, block_bytes: &[u64]) -> Result<Report> {
    let max_block = *block_bytes.iter().max().unwrap_or(&65536);
    let max_batch = *args.batch_sizes.iter().max().unwrap_or(&1);
    let max_threads = *args.threads.iter().max().unwrap_or(&1);
    let scratch_size = (max_block as usize)
        .checked_mul(max_batch as usize)
        .context("buf overflow")?
        .checked_mul(max_threads as usize)
        .context("buf overflow")?;

    let cfg = cfg_for(SELF_CLIENT_ID, scratch_size.max(1 << 20));
    let (setup, my_ep) =
        RdmaNode::start_local(&cfg).map_err(|e| anyhow::anyhow!("rdma start_local: {e}"))?;
    let local_buf = setup
        .bulk_pool
        .acquire()
        .await
        .map_err(|e| anyhow::anyhow!("bulk_pool acquire: {e}"))?;

    let target_addr: SocketAddr = args
        .target
        .parse()
        .with_context(|| format!("parse --target {}", args.target))?;
    let mut stream = TcpStream::connect(target_addr)
        .await
        .with_context(|| format!("connect {target_addr}"))?;
    let my_msg = BenchHandshake {
        ep: my_ep.clone(),
        vaddr: local_buf.addr(),
        rkey: local_buf.rkey(),
        length: local_buf.capacity() as u64,
    };
    send_json(&mut stream, &my_msg).await?;
    let target_msg: BenchHandshake = recv_json(&mut stream).await?;
    drop(stream);

    let mut routing = ClusterRoutingTable::new(SELF_CLIENT_ID);
    routing.insert(SELF_TARGET_ID, &target_msg.ep);
    let routing = Arc::new(routing);
    let node = RdmaNode::finalize(&cfg, setup, routing);

    let peer = node
        .peer(SELF_TARGET_ID)
        .ok_or_else(|| anyhow::anyhow!("peer absent from routing table"))?;
    let ah = node
        .ah_cache
        .get_or_create(peer)
        .map_err(|e| anyhow::anyhow!("ah_cache: {e}"))?;
    let peer_dct = peer.dct_num;
    let peer_dck = peer.dc_key;

    let target_vaddr = target_msg.vaddr;
    let target_rkey = target_msg.rkey;

    let warmup = Duration::from_secs(args.warmup_secs);
    let duration = Duration::from_secs(args.duration_secs);
    let op_str: &'static str = match args.op {
        OpArg::Read => "read",
        OpArg::Write => "write",
    };

    let mut cells: Vec<Cell> = Vec::new();
    for &threads in &args.threads {
        for &batch in &args.batch_sizes {
            for &block in block_bytes {
                let cell = run_cell(
                    &node,
                    ah,
                    peer_dct,
                    peer_dck,
                    local_buf.addr(),
                    local_buf.lkey(),
                    target_vaddr,
                    target_rkey,
                    block,
                    batch,
                    threads,
                    args.op,
                    op_str,
                    warmup,
                    duration,
                )
                .await?;
                cells.push(cell);
            }
        }
    }
    Ok(Report { cells })
}

#[allow(clippy::too_many_arguments)]
async fn run_cell(
    node: &RdmaNode,
    ah: *mut rdma_mummy_sys::ibv_ah,
    peer_dct: u32,
    peer_dck: u64,
    local_addr: u64,
    local_lkey: u32,
    target_vaddr: u64,
    target_rkey: u32,
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
            node,
            ah,
            peer_dct,
            peer_dck,
            local_addr,
            local_lkey,
            target_vaddr,
            target_rkey,
            block,
            batch,
            threads,
            op,
            warmup,
            None,
            None,
            None,
        )
        .await?;
    }
    let started = Instant::now();
    drive(
        node,
        ah,
        peer_dct,
        peer_dck,
        local_addr,
        local_lkey,
        target_vaddr,
        target_rkey,
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

#[allow(clippy::too_many_arguments)]
async fn drive(
    node: &RdmaNode,
    ah: *mut rdma_mummy_sys::ibv_ah,
    peer_dct: u32,
    peer_dck: u64,
    local_addr: u64,
    local_lkey: u32,
    target_vaddr: u64,
    target_rkey: u32,
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
    let sock = node.sock.clone();
    let mut tasks = Vec::with_capacity(threads as usize);
    for t in 0..threads {
        let sock = sock.clone();
        let hist = hist.clone();
        let iters = iters.clone();
        let bytes = bytes.clone();
        let thread_local_off = (t as u64) * block * batch as u64;
        let thread_remote_off = thread_local_off;
        tasks.push(compio::runtime::spawn(async move {
            worker(
                sock,
                ah,
                peer_dct,
                peer_dck,
                local_addr + thread_local_off,
                local_lkey,
                target_vaddr + thread_remote_off,
                target_rkey,
                block,
                batch,
                op,
                deadline,
                hist,
                iters,
                bytes,
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

#[allow(clippy::too_many_arguments)]
async fn worker(
    sock: std::rc::Rc<IbSocket>,
    ah: *mut rdma_mummy_sys::ibv_ah,
    peer_dct: u32,
    peer_dck: u64,
    local_base: u64,
    local_lkey: u32,
    target_base: u64,
    target_rkey: u32,
    block: u64,
    batch: u32,
    op: OpArg,
    deadline: Instant,
    hist: Option<Arc<Mutex<Histogram<u64>>>>,
    iters: Option<Arc<std::sync::atomic::AtomicU64>>,
    bytes: Option<Arc<std::sync::atomic::AtomicU64>>,
) -> Result<()> {
    while Instant::now() < deadline {
        let start = Instant::now();
        let mut calls = Vec::with_capacity(batch as usize);
        for i in 0..batch {
            let local = local_base + (i as u64) * block;
            let remote = target_base + (i as u64) * block;
            let sock = sock.clone();
            let fut = async move {
                match op {
                    OpArg::Write => {
                        sock.rdma_write(
                            local,
                            block as u32,
                            local_lkey,
                            remote,
                            target_rkey,
                            ah,
                            peer_dct,
                            peer_dck,
                        )
                        .await
                    }
                    OpArg::Read => {
                        sock.rdma_read(
                            local,
                            block as u32,
                            local_lkey,
                            remote,
                            target_rkey,
                            ah,
                            peer_dct,
                            peer_dck,
                        )
                        .await
                    }
                }
            };
            calls.push(fut);
        }
        let results = join_all(calls).await;
        let lat_us = start.elapsed().as_micros() as u64;
        for r in results {
            r.map_err(|e| anyhow::anyhow!("rdma op: {e}"))?;
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

fn print_target_banner(bind: SocketAddr, buf_size: usize, ep: &LocalEndpoint) {
    let gid_hex: String = ep.gid.iter().map(|b| format!("{b:02x}")).collect();
    let dial = if bind.ip().is_unspecified() {
        let ip = super::target::primary_ip()
            .map(|i| i.to_string())
            .unwrap_or_else(|| "127.0.0.1".into());
        format!("{ip}:{}", bind.port())
    } else {
        bind.to_string()
    };
    println!("openlake_bench RDMA DCT target listening on {bind} (mlx5dv)");
    println!(
        "Local endpoint: runtime_id=0 lid={} dct_num=0x{:x} gid={gid_hex}",
        ep.lid, ep.dct_num
    );
    println!("Allocated {buf_size} byte preregistered RDMA buffer");
    println!("\x1b[33mTo start the bench, run the following in a second terminal (loopback) or on another host (cross host):");
    println!("  openlake bench client --target {dial} --mode rdma");
    println!("Press Ctrl+C to terminate\x1b[0m");
}
