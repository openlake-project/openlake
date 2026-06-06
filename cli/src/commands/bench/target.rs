use std::net::SocketAddr;

use anyhow::{Context, Result};
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, put};
use axum::Router;
use bytes::Bytes;
use compio::net::TcpListener;

use super::mode::{resolve_mode, BenchMode};
use super::{parse_size, TargetArgs};

#[derive(Clone)]
struct AppState {
    buf: Bytes,
}

pub async fn run(args: TargetArgs) -> Result<()> {
    let mode = resolve_mode(args.config.as_deref(), args.mode)?;
    let bind: SocketAddr = args.bind.parse()
        .with_context(|| format!("parsing --bind {}", args.bind))?;
    let buf_bytes = parse_size(&args.buf_size)
        .with_context(|| format!("parsing --buf-size {}", args.buf_size))?;

    match mode {
        BenchMode::Tls  => serve_tls (bind, buf_bytes as usize).await,
        BenchMode::Rdma => serve_rdma(bind, buf_bytes as usize).await,
    }
}

async fn serve_tls(bind: SocketAddr, buf_bytes: usize) -> Result<()> {
    let cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(0);
    tracing::info!(target: "cpu_probe", "Detected {cores} CPU cores online");
    if let Some(ip) = primary_ip() {
        tracing::info!(target: "if_addrs", "Primary IPv4 interface resolved: {ip} (first non lo, IFF_UP, IFF_RUNNING)");
    } else {
        tracing::warn!(target: "if_addrs", "No active IPv4 interface found (cross host paste line will fall back to 127.0.0.1)");
    }
    tracing::info!(target: "transport_selector", "Backend selected: h2c (TCP + HTTP/2 prior knowledge, plaintext)");
    tracing::info!(target: "axum_router", "Installed 2 routes: GET /bench/echo/{{len}} (echo), PUT /bench/sink (drain)");

    let alloc_started = std::time::Instant::now();
    let buf = Bytes::from(vec![0u8; buf_bytes]);
    let alloc_us = alloc_started.elapsed().as_micros();
    tracing::info!(target: "tent_backend",
        "Allocated {buf_bytes} bytes DRAM buffer in {} ms (heap, not mlocked)",
        alloc_us as f64 / 1000.0);

    let state = AppState { buf };
    let app: Router = Router::new()
        .route("/bench/echo/{len}", get(echo))
        .route("/bench/sink",       put(sink))
        .with_state(state);

    let bind_started = std::time::Instant::now();
    let listener = TcpListener::bind(bind).await
        .with_context(|| format!("binding {bind}"))?;
    let bind_us = bind_started.elapsed().as_micros();
    let actual = listener.local_addr().unwrap_or(bind);
    tracing::info!(target: "tcp_transport", "TCP listener bound on {actual} in {bind_us} us");
    tracing::info!(target: "transfer_engine_impl",
        "Transfer Engine {actual} started successfully");

    print_banner_tls(actual, buf_bytes);

    cyper_axum::serve(listener, app).await
        .map_err(|e| anyhow::anyhow!("h2c serve exited: {e}"))?;
    Ok(())
}

async fn echo(
    State(state): State<AppState>,
    Path(len): Path<usize>,
    body: axum::body::Body,
) -> impl IntoResponse {
    let _ = axum::body::to_bytes(body, 4096).await;
    if len == 0 || len > state.buf.len() {
        return (StatusCode::BAD_REQUEST, "len out of range").into_response();
    }
    let slice = state.buf.slice(..len);
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE,   "application/octet-stream".parse().unwrap());
    headers.insert(header::CONTENT_LENGTH, len.to_string().parse().unwrap());
    (StatusCode::OK, headers, slice).into_response()
}

async fn sink(body: axum::body::Body) -> impl IntoResponse {
    let mut total = 0usize;
    let mut stream = body.into_data_stream();
    use futures::StreamExt;
    while let Some(chunk) = stream.next().await {
        match chunk {
            Ok(b)  => total += b.len(),
            Err(_) => return (StatusCode::BAD_REQUEST, "body read error").into_response(),
        }
    }
    (StatusCode::OK, total.to_string()).into_response()
}

pub(crate) fn primary_ip() -> Option<std::net::IpAddr> {
    use std::ffi::CStr;
    use std::net::Ipv4Addr;
    let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut ifap) } != 0 || ifap.is_null() {
        return None;
    }
    let mut result: Option<std::net::IpAddr> = None;
    let mut cur = ifap;
    while !cur.is_null() {
        unsafe {
            let ifa = &*cur;
            if ifa.ifa_addr.is_null() {
                cur = ifa.ifa_next;
                continue;
            }
            let family = (*ifa.ifa_addr).sa_family as libc::c_int;
            let name = CStr::from_ptr(ifa.ifa_name).to_string_lossy();
            let flags = ifa.ifa_flags as u32;
            if family == libc::AF_INET
                && name != "lo"
                && (flags & libc::IFF_UP      as u32) != 0
                && (flags & libc::IFF_RUNNING as u32) != 0
            {
                let s = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                result = Some(std::net::IpAddr::V4(Ipv4Addr::from(u32::from_be(s.sin_addr.s_addr))));
                break;
            }
            cur = ifa.ifa_next;
        }
    }
    unsafe { libc::freeifaddrs(ifap); }
    result
}

fn resolved_dial(bind: SocketAddr) -> String {
    if bind.ip().is_unspecified() {
        let ip = primary_ip()
            .map(|i| i.to_string())
            .unwrap_or_else(|| "127.0.0.1".into());
        format!("{ip}:{}", bind.port())
    } else {
        bind.to_string()
    }
}

fn print_banner_tls(bind: SocketAddr, buf_bytes: usize) {
    let dial = resolved_dial(bind);
    println!("openlake_bench h2c target listening on {bind}");
    println!("Allocated {buf_bytes} byte preregistered buffer");
    println!("\x1b[33mTo start the bench, run the following in a second terminal (loopback) or on another host (cross host):");
    println!("  openlake bench client --target {dial} --mode tls");
    println!("Press Ctrl+C to terminate\x1b[0m");
}

#[cfg(feature = "rdma")]
async fn serve_rdma(bind: SocketAddr, buf_bytes: usize) -> Result<()> {
    super::dct::serve_target(bind, buf_bytes).await
}

#[cfg(not(feature = "rdma"))]
async fn serve_rdma(_bind: SocketAddr, _buf_bytes: usize) -> Result<()> {
    anyhow::bail!(
        "rdma target: this build was produced without --features rdma. \
         Rebuild with `cargo build --bin openlake --features rdma` on a Linux \
         host with ibverbs headers, or run `openlake bench target --mode tls` instead."
    )
}
