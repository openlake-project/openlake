use std::net::SocketAddr;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use send_wrapper::SendWrapper;
use serde::Serialize;

use openlake_storage::kv_engine::{KvEngineMetrics, KvEngineStats};

use crate::config::{Config, Mode, TransportMode};
use crate::hardware_inventory::{self, HardwareSnapshot};
use crate::s3::listener::TlsTcpListener;
use crate::tls_material::TlsMaterial;

const DEFAULT_VLLM_METRICS_URL: &str = "http://127.0.0.1:8000/metrics";

#[derive(Clone)]
struct StateData {
    base: NodeSnapshot,
    client: cyper::Client,
    vllm_url: String,
    kv: Option<Arc<KvEngineMetrics>>,
}

pub fn spawn(
    cfg: Arc<Config>,
    tls: TlsMaterial,
    kv: Option<Arc<KvEngineMetrics>>,
) -> anyhow::Result<()> {
    let addr = telemetry_addr(cfg.rpc_addr)?;
    thread::Builder::new()
        .name("node-agent".into())
        .spawn(move || {
            let result = crate::create_runtime()
                .and_then(|runtime| runtime.block_on(serve(addr, cfg, tls, kv)));
            if let Err(error) = result {
                tracing::error!("node agent exited: {error:#}");
            }
        })?;
    Ok(())
}

async fn serve(
    addr: SocketAddr,
    cfg: Arc<Config>,
    tls: TlsMaterial,
    kv: Option<Arc<KvEngineMetrics>>,
) -> anyhow::Result<()> {
    let listener = compio::net::TcpListener::bind(addr).await?;
    let kv_cache_capacity_bytes = kv
        .as_deref()
        .map(KvEngineMetrics::snapshot)
        .map(|stats| stats.configured_capacity_bytes);
    let hardware = hardware_inventory::collect(&cfg.data_dirs, kv_cache_capacity_bytes);
    let state = StateData {
        base: NodeSnapshot {
            schema_version: "1.0",
            collected_at_unix_ms: 0,
            node_id: cfg.self_id,
            openlake: OpenLakeSnapshot {
                version: env!("CARGO_PKG_VERSION"),
                mode: match cfg.mode {
                    Mode::Storage => "storage",
                    Mode::Kv => "kv",
                },
                transport: match cfg.transport {
                    TransportMode::H2 => "h2",
                    TransportMode::Rdma => "rdma",
                },
                data_paths: cfg.data_dirs.clone(),
                kv_cache: None,
            },
            hardware,
        },
        client: cyper::Client::new(),
        vllm_url: std::env::var("OPENLAKE_VLLM_METRICS_URL")
            .unwrap_or_else(|_| DEFAULT_VLLM_METRICS_URL.into()),
        kv,
    };
    let app = Router::new()
        .route("/v1/telemetry/vllm", get(vllm))
        .route("/v1/telemetry/openlake", get(openlake))
        .with_state(state);

    tracing::info!(%addr, "node agent serving");
    match tls.rpc_acceptor().map(Rc::new) {
        None => cyper_axum::serve(listener, app).await?,
        Some(acceptor) => {
            cyper_axum::serve(TlsTcpListener::new(listener, (*acceptor).clone()), app).await?
        }
    }
    Ok(())
}

async fn openlake(State(state): State<StateData>) -> Json<NodeSnapshot> {
    let mut snapshot = state.base.clone();
    snapshot.collected_at_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    snapshot.openlake.kv_cache = state.kv.as_deref().map(KvEngineMetrics::snapshot);
    Json(snapshot)
}

async fn vllm(State(state): State<StateData>) -> Response {
    SendWrapper::new(async move {
        let request = match state.client.get(state.vllm_url) {
            Ok(request) => request,
            Err(error) => return (StatusCode::BAD_GATEWAY, error.to_string()).into_response(),
        };
        let upstream = match request.send().await {
            Ok(response) => response,
            Err(error) => return (StatusCode::BAD_GATEWAY, error.to_string()).into_response(),
        };
        let status = upstream.status();
        let content_type = upstream
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .cloned();
        let body = match upstream.bytes().await {
            Ok(bytes) => bytes,
            Err(error) => return (StatusCode::BAD_GATEWAY, error.to_string()).into_response(),
        };
        let mut response = Response::builder().status(status);
        if let Some(content_type) = content_type {
            response = response.header(axum::http::header::CONTENT_TYPE, content_type);
        }
        response
            .body(Body::from(body))
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
    })
    .await
}

fn telemetry_addr(rpc_addr: SocketAddr) -> anyhow::Result<SocketAddr> {
    match std::env::var("OPENLAKE_TELEMETRY_ADDR") {
        Ok(addr) => Ok(addr.parse()?),
        Err(_) => Ok(SocketAddr::new(
            rpc_addr.ip(),
            rpc_addr
                .port()
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("rpc port has no adjacent telemetry port"))?,
        )),
    }
}

#[derive(Clone, Serialize)]
struct NodeSnapshot {
    schema_version: &'static str,
    collected_at_unix_ms: u128,
    node_id: u16,
    openlake: OpenLakeSnapshot,
    hardware: HardwareSnapshot,
}

#[derive(Clone, Serialize)]
struct OpenLakeSnapshot {
    version: &'static str,
    mode: &'static str,
    transport: &'static str,
    data_paths: Vec<PathBuf>,
    kv_cache: Option<KvEngineStats>,
}
