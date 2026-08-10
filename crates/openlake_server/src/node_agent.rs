use std::collections::{BTreeSet, VecDeque};
use std::net::{Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use futures_util::StreamExt;
use send_wrapper::SendWrapper;
use serde::Serialize;

use openlake_io::{PeerClient, RemoteBackend};
use openlake_storage::kv_engine::{KvEngineMetrics, KvEngineStats};

use crate::config::{Config, Mode, RdmaBackend, TransportMode};
use crate::hardware_inventory::{self, HardwareSnapshot};
use crate::s3::listener::TlsTcpListener;
use crate::tls_material::TlsMaterial;

const DEFAULT_VLLM_METRICS_URL: &str = "http://127.0.0.1:8000/metrics";
const HISTORY_INTERVAL: Duration = Duration::from_secs(30);
const HISTORY_BUCKET_COUNT: usize = 2_880;
const REQUEST_COUNTER_NAMES: [&str; 2] = ["vllm:request_success_total", "vllm:request_success"];
const PEER_DISCOVERY_ATTEMPTS: usize = 3;
const PEER_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(2);
const PEER_DISCOVERY_RETRY_INTERVAL: Duration = Duration::from_millis(350);

#[derive(Clone)]
struct StateData {
    base: NodeSnapshot,
    client: cyper::Client,
    vllm_url: String,
    kv: Option<Arc<KvEngineMetrics>>,
    history: Arc<Mutex<TelemetryHistory>>,
    peers: Arc<Mutex<Vec<PeerDiscoverySnapshot>>>,
}

#[derive(Clone, Serialize)]
struct PeerDiscoverySnapshot {
    node_id: u16,
    rpc_addr: SocketAddr,
    status: &'static str,
    latency_ms: Option<u64>,
    complete: Option<bool>,
    rdma_endpoints: Vec<PeerRdmaEndpointSnapshot>,
    error: Option<String>,
}

#[derive(Clone, Serialize)]
struct PeerRdmaEndpointSnapshot {
    runtime_id: u16,
    gid: String,
    lid: u16,
    dct_number: u32,
    kv_slab_ready: bool,
    slot_bytes: Option<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PeerDiscoveryStrategy {
    None,
    DctEndpointMetadata,
}

fn pending_peer(node_id: u16, rpc_addr: SocketAddr) -> PeerDiscoverySnapshot {
    PeerDiscoverySnapshot {
        node_id,
        rpc_addr,
        status: "pending",
        latency_ms: None,
        complete: None,
        rdma_endpoints: Vec::new(),
        error: None,
    }
}

fn peer_from_reply(
    node_id: u16,
    rpc_addr: SocketAddr,
    latency_ms: u64,
    reply: openlake_io::rpc::RdmaEndpointsReply,
) -> PeerDiscoverySnapshot {
    let status = if !reply.complete {
        "metadata_incomplete"
    } else if reply.endpoints.is_empty() {
        "rpc_reachable"
    } else {
        "rdma_metadata_available"
    };
    PeerDiscoverySnapshot {
        node_id,
        rpc_addr,
        status,
        latency_ms: Some(latency_ms),
        complete: Some(reply.complete),
        rdma_endpoints: reply
            .endpoints
            .into_iter()
            .map(|endpoint| PeerRdmaEndpointSnapshot {
                runtime_id: endpoint.runtime_id,
                gid: Ipv6Addr::from(endpoint.gid).to_string(),
                lid: endpoint.lid,
                dct_number: endpoint.dct_num,
                kv_slab_ready: endpoint.kv_slab.is_some(),
                slot_bytes: endpoint.kv_slab.map(|slab| slab.slot_bytes),
            })
            .collect(),
        error: None,
    }
}

fn peer_failure(
    node_id: u16,
    rpc_addr: SocketAddr,
    status: &'static str,
    latency_ms: u64,
    error: String,
) -> PeerDiscoverySnapshot {
    PeerDiscoverySnapshot {
        node_id,
        rpc_addr,
        status,
        latency_ms: Some(latency_ms),
        complete: None,
        rdma_endpoints: Vec::new(),
        error: Some(error),
    }
}

fn elapsed_millis(started: Instant) -> u64 {
    started.elapsed().as_millis().min(u64::MAX as u128) as u64
}

fn configured_peer_targets(cfg: &Config) -> Vec<(u16, SocketAddr)> {
    if cfg.mode == Mode::Kv && !cfg.kv_agents.is_empty() {
        return cfg
            .kv_agents
            .iter()
            .enumerate()
            .filter(|(node_id, _)| *node_id != cfg.self_id as usize)
            .map(|(node_id, rpc_addr)| (node_id as u16, *rpc_addr))
            .collect();
    }
    cfg.nodes
        .iter()
        .filter(|peer| peer.id != cfg.self_id)
        .map(|peer| (peer.id, peer.rpc_addr))
        .collect()
}

fn peer_discovery_strategy(cfg: &Config) -> PeerDiscoveryStrategy {
    match (
        cfg.mode,
        cfg.transport,
        cfg.rdma.as_ref().map(|rdma| rdma.backend),
    ) {
        (_, TransportMode::Rdma, Some(RdmaBackend::Dct)) => {
            PeerDiscoveryStrategy::DctEndpointMetadata
        }
        _ => PeerDiscoveryStrategy::None,
    }
}

struct TelemetryHistory {
    requests_served: VecDeque<u64>,
    cached_tokens_served: VecDeque<u64>,
    samples_collected: usize,
    previous_requests: Option<u64>,
    previous_served_blocks: Option<u64>,
}

impl TelemetryHistory {
    fn new() -> Self {
        Self {
            requests_served: VecDeque::from(vec![0; HISTORY_BUCKET_COUNT]),
            cached_tokens_served: VecDeque::from(vec![0; HISTORY_BUCKET_COUNT]),
            samples_collected: 0,
            previous_requests: None,
            previous_served_blocks: None,
        }
    }

    fn record(
        &mut self,
        requests: Option<u64>,
        served_blocks: Option<u64>,
        tokens_per_block: Option<u64>,
    ) {
        let request_delta = counter_delta(requests, &mut self.previous_requests);
        let block_delta = counter_delta(served_blocks, &mut self.previous_served_blocks);
        let cached_tokens = tokens_per_block
            .map(|block_size| block_delta.saturating_mul(block_size))
            .unwrap_or(0);
        push_bucket(&mut self.requests_served, request_delta);
        push_bucket(&mut self.cached_tokens_served, cached_tokens);
        self.samples_collected = (self.samples_collected + 1).min(HISTORY_BUCKET_COUNT);
    }

    fn snapshot(&self) -> TelemetryHistorySnapshot {
        TelemetryHistorySnapshot {
            interval_seconds: HISTORY_INTERVAL.as_secs(),
            bucket_count: HISTORY_BUCKET_COUNT,
            samples_collected: self.samples_collected,
            requests_served: self.requests_served.iter().copied().collect(),
            cached_tokens_served: self.cached_tokens_served.iter().copied().collect(),
        }
    }
}

#[derive(Clone, Serialize)]
struct TelemetryHistorySnapshot {
    interval_seconds: u64,
    bucket_count: usize,
    samples_collected: usize,
    requests_served: Vec<u64>,
    cached_tokens_served: Vec<u64>,
}

fn push_bucket(history: &mut VecDeque<u64>, value: u64) {
    if history.len() == HISTORY_BUCKET_COUNT {
        history.pop_front();
    }
    history.push_back(value);
}

fn counter_delta(current: Option<u64>, previous: &mut Option<u64>) -> u64 {
    match current {
        None => {
            *previous = None;
            0
        }
        Some(current) => {
            let delta = previous
                .filter(|previous| current >= *previous)
                .map(|previous| current - previous)
                .unwrap_or(0);
            *previous = Some(current);
            delta
        }
    }
}

async fn discover_peer_once(
    node_id: u16,
    rpc_addr: SocketAddr,
    rpc_connector: Option<Arc<rustls::ClientConfig>>,
) -> PeerDiscoverySnapshot {
    let peer = Rc::new(PeerClient::new(rpc_addr, rpc_connector));
    let backend = RemoteBackend::new(peer, 0);
    let mut last = pending_peer(node_id, rpc_addr);

    for attempt in 0..PEER_DISCOVERY_ATTEMPTS {
        let started = Instant::now();
        last = match compio::time::timeout(PEER_DISCOVERY_TIMEOUT, backend.get_rdma_endpoints())
            .await
        {
            Ok(Ok(reply)) => {
                let complete = reply.complete;
                let snapshot = peer_from_reply(node_id, rpc_addr, elapsed_millis(started), reply);
                if complete {
                    return snapshot;
                }
                snapshot
            }
            Ok(Err(error)) => peer_failure(
                node_id,
                rpc_addr,
                "unreachable",
                elapsed_millis(started),
                error.to_string(),
            ),
            Err(_) => peer_failure(
                node_id,
                rpc_addr,
                "timed_out",
                elapsed_millis(started),
                format!("peer metadata lookup exceeded {PEER_DISCOVERY_TIMEOUT:?}"),
            ),
        };
        if attempt + 1 < PEER_DISCOVERY_ATTEMPTS {
            compio::time::sleep(PEER_DISCOVERY_RETRY_INTERVAL).await;
        }
    }
    last
}

async fn discover_peers_once(
    targets: Vec<(u16, SocketAddr)>,
    rpc_connector: Option<Arc<rustls::ClientConfig>>,
    snapshots: Arc<Mutex<Vec<PeerDiscoverySnapshot>>>,
) {
    let mut pending = futures_util::stream::FuturesUnordered::new();
    for (node_id, rpc_addr) in targets {
        pending.push(discover_peer_once(node_id, rpc_addr, rpc_connector.clone()));
    }
    while let Some(discovered) = pending.next().await {
        if let Ok(mut peers) = snapshots.lock() {
            if let Some(peer) = peers
                .iter_mut()
                .find(|peer| peer.node_id == discovered.node_id)
            {
                *peer = discovered;
            }
        }
    }
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
    let history = Arc::new(Mutex::new(TelemetryHistory::new()));
    let discovery_strategy = peer_discovery_strategy(&cfg);
    let configured_peers = match discovery_strategy {
        PeerDiscoveryStrategy::DctEndpointMetadata => configured_peer_targets(&cfg),
        PeerDiscoveryStrategy::None => Vec::new(),
    };
    let peer_targets = match discovery_strategy {
        PeerDiscoveryStrategy::DctEndpointMetadata => configured_peers.clone(),
        PeerDiscoveryStrategy::None => Vec::new(),
    };
    let peers = Arc::new(Mutex::new(match discovery_strategy {
        PeerDiscoveryStrategy::None => Vec::new(),
        PeerDiscoveryStrategy::DctEndpointMetadata => configured_peers
            .iter()
            .map(|(node_id, rpc_addr)| pending_peer(*node_id, *rpc_addr))
            .collect(),
    }));
    let state = StateData {
        base: NodeSnapshot {
            schema_version: "1.2",
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
                history: None,
                peers: Vec::new(),
            },
            hardware,
        },
        client: cyper::Client::new(),
        vllm_url: std::env::var("OPENLAKE_VLLM_METRICS_URL")
            .unwrap_or_else(|_| DEFAULT_VLLM_METRICS_URL.into()),
        kv,
        history,
        peers,
    };
    compio::runtime::spawn(sample_history(state.clone())).detach();
    compio::runtime::spawn(discover_peers_once(
        peer_targets,
        tls.rpc_connector(),
        state.peers.clone(),
    ))
    .detach();
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
    snapshot.openlake.history = state.history.lock().ok().map(|history| history.snapshot());
    snapshot.openlake.peers = state
        .peers
        .lock()
        .map(|peers| peers.clone())
        .unwrap_or_default();
    Json(snapshot)
}

async fn vllm(State(state): State<StateData>) -> Response {
    SendWrapper::new(async move {
        let payload = match fetch_vllm(&state).await {
            Ok(payload) => payload,
            Err(error) => return (StatusCode::BAD_GATEWAY, error).into_response(),
        };
        let mut response = Response::builder().status(payload.status);
        if let Some(content_type) = payload.content_type {
            response = response.header(axum::http::header::CONTENT_TYPE, content_type);
        }
        response
            .body(Body::from(payload.body))
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
    })
    .await
}

struct VllmPayload {
    status: StatusCode,
    content_type: Option<axum::http::HeaderValue>,
    body: bytes::Bytes,
}

async fn fetch_vllm(state: &StateData) -> Result<VllmPayload, String> {
    let request = state
        .client
        .get(state.vllm_url.clone())
        .map_err(|error| error.to_string())?;
    let upstream = request.send().await.map_err(|error| error.to_string())?;
    let status = upstream.status();
    let content_type = upstream
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .cloned();
    let body = upstream.bytes().await.map_err(|error| error.to_string())?;
    Ok(VllmPayload {
        status,
        content_type,
        body,
    })
}

async fn sample_history(state: StateData) {
    let mut next_sample = Instant::now();
    loop {
        let served_blocks = state
            .kv
            .as_deref()
            .map(KvEngineMetrics::snapshot)
            .map(|stats| stats.served_blocks);
        let (requests, tokens_per_block) = match fetch_vllm(&state).await {
            Ok(payload) if payload.status.is_success() => {
                let text = String::from_utf8_lossy(&payload.body);
                (
                    prometheus_counter(&text, &REQUEST_COUNTER_NAMES),
                    prometheus_cache_block_size(&text),
                )
            }
            Ok(payload) => {
                tracing::debug!(status = %payload.status, "vLLM history sample unavailable");
                (None, None)
            }
            Err(error) => {
                tracing::debug!(%error, "vLLM history sample failed");
                (None, None)
            }
        };
        if let Ok(mut history) = state.history.lock() {
            history.record(requests, served_blocks, tokens_per_block);
        }
        next_sample += HISTORY_INTERVAL;
        let now = Instant::now();
        if next_sample <= now {
            next_sample = now + HISTORY_INTERVAL;
        }
        compio::time::sleep(next_sample.saturating_duration_since(now)).await;
    }
}

fn prometheus_counter(text: &str, names: &[&str]) -> Option<u64> {
    for name in names {
        let mut found = false;
        let mut total = 0.0;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut fields = line.split_whitespace();
            let Some(metric) = fields.next() else {
                continue;
            };
            if metric.split_once('{').map_or(metric, |(base, _)| base) != *name {
                continue;
            }
            let Some(value) = fields.next().and_then(|value| value.parse::<f64>().ok()) else {
                continue;
            };
            if value.is_finite() && value >= 0.0 {
                total += value;
                found = true;
            }
        }
        if found && total <= u64::MAX as f64 {
            return Some(total as u64);
        }
    }
    None
}

fn prometheus_cache_block_size(text: &str) -> Option<u64> {
    let mut sizes = BTreeSet::new();
    for line in text.lines() {
        let line = line.trim();
        if !line.starts_with("vllm:cache_config_info{") {
            continue;
        }
        let Some(start) = line.find("block_size=\"") else {
            continue;
        };
        let value = &line[start + "block_size=\"".len()..];
        let Some(end) = value.find('"') else {
            continue;
        };
        if let Ok(size) = value[..end].parse::<u64>() {
            if size > 0 {
                sizes.insert(size);
            }
        }
    }
    (sizes.len() == 1).then(|| *sizes.first().expect("one block size"))
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
    #[serde(skip_serializing_if = "Option::is_none")]
    history: Option<TelemetryHistorySnapshot>,
    peers: Vec<PeerDiscoverySnapshot>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn history_records_deltas_and_rebases_reset_counters() {
        let mut history = TelemetryHistory::new();
        history.record(Some(100), Some(50), Some(16));
        history.record(Some(112), Some(55), Some(16));
        history.record(Some(3), Some(2), Some(16));

        let snapshot = history.snapshot();
        assert_eq!(snapshot.samples_collected, 3);
        assert_eq!(
            &snapshot.requests_served[HISTORY_BUCKET_COUNT - 3..],
            &[0, 12, 0]
        );
        assert_eq!(
            &snapshot.cached_tokens_served[HISTORY_BUCKET_COUNT - 3..],
            &[0, 80, 0]
        );
    }

    #[test]
    fn peer_telemetry_keeps_routing_identity_but_omits_rdma_capabilities() {
        let snapshot = peer_from_reply(
            4,
            "10.0.0.4:9400".parse().unwrap(),
            7,
            openlake_io::rpc::RdmaEndpointsReply {
                complete: true,
                endpoints: vec![openlake_io::rpc::LocalRdmaEndpoint {
                    runtime_id: 2,
                    dct_num: 91,
                    gid: [1; 16],
                    dc_key: 4_919,
                    lid: 12,
                    kv_slab: Some(openlake_io::rpc::SlabMeta {
                        slab_base: 0xfeed,
                        rkey: 0xbeef,
                        slot_bytes: 4096,
                    }),
                }],
            },
        );

        assert_eq!(snapshot.status, "rdma_metadata_available");
        assert_eq!(snapshot.rdma_endpoints[0].dct_number, 91);
        assert_eq!(snapshot.rdma_endpoints[0].slot_bytes, Some(4096));
        let json = serde_json::to_string(&snapshot).unwrap();
        assert!(!json.contains("dc_key"));
        assert!(!json.contains("rkey"));
        assert!(!json.contains("slab_base"));
        assert!(!json.contains("4919"));
        assert!(!json.contains("48879"));
    }

    #[test]
    fn empty_endpoint_reply_only_proves_rpc_reachability() {
        let snapshot = peer_from_reply(
            5,
            "10.0.0.5:9400".parse().unwrap(),
            3,
            openlake_io::rpc::RdmaEndpointsReply {
                complete: true,
                endpoints: Vec::new(),
            },
        );

        assert_eq!(snapshot.status, "rpc_reachable");
        assert!(snapshot.rdma_endpoints.is_empty());
    }

    #[test]
    fn parses_vllm_request_totals_and_unambiguous_block_size() {
        let text = r#"
# TYPE vllm:request_success_total counter
vllm:request_success_total{finished_reason="stop"} 12
vllm:request_success_total{finished_reason="length"} 3
vllm:cache_config_info{block_size="16",cache_dtype="auto"} 1
"#;
        assert_eq!(prometheus_counter(text, &REQUEST_COUNTER_NAMES), Some(15));
        assert_eq!(prometheus_cache_block_size(text), Some(16));
    }

    #[test]
    fn rejects_ambiguous_block_sizes() {
        let text = "vllm:cache_config_info{block_size=\"16\"} 1\n\
                    vllm:cache_config_info{block_size=\"32\"} 1\n";
        assert_eq!(prometheus_cache_block_size(text), None);
    }
}
