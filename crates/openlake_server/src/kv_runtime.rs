use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;

use openlake_io::StorageBackend;
use openlake_storage::KvEngine;

use crate::config;
use crate::lock_server::LockServer;
use crate::node_agent;
use crate::rpc_server;
use crate::tls_material::TlsMaterial;

pub async fn run_tcp(
    cfg: Arc<config::Config>,
    lock_server: Arc<LockServer>,
    tls: TlsMaterial,
) -> anyhow::Result<()> {
    let slab_cfg = cfg.kv_slab.expect("validated: kv mode has [kv_slab]");
    let engine = Rc::new(KvEngine::new_tcp(
        slab_cfg.capacity_bytes()?,
        Duration::from_secs(slab_cfg.reserve_ttl_secs),
    ));
    node_agent::spawn(cfg.clone(), tls.clone(), Some(engine.metrics()))?;

    let listener = rpc_server::bind_reuseport(cfg.rpc_addr)
        .with_context(|| format!("kv-tcp: bind rpc on {}", cfg.rpc_addr))?;
    let disks: Rc<Vec<Rc<dyn StorageBackend>>> = Rc::new(Vec::new());
    let endpoints = Arc::new(std::sync::Mutex::new(
        openlake_io::rpc::RdmaEndpointsReply {
            complete: true,
            endpoints: Vec::new(),
        },
    ));
    let acceptor = tls.rpc_acceptor().map(Rc::new);
    tracing::info!(rpc = %cfg.rpc_addr, "kv node (tcp) serving");
    rpc_server::serve(
        listener,
        disks,
        lock_server,
        acceptor,
        endpoints,
        Some(engine),
    )
    .await
}

#[cfg(all(feature = "rdma", target_os = "linux"))]
pub async fn run_ucx(
    cfg: Arc<config::Config>,
    lock_server: Arc<LockServer>,
    tls: TlsMaterial,
) -> anyhow::Result<()> {
    let worker = openlake_io::ucx::UcxWorker::new().map_err(anyhow::Error::msg)?;
    let slab_cfg = cfg.kv_slab.expect("validated: kv mode has [kv_slab]");
    let engine = Rc::new(KvEngine::new_ucx(
        worker.clone(),
        slab_cfg.capacity_bytes()?,
        Duration::from_secs(slab_cfg.reserve_ttl_secs),
    ));
    node_agent::spawn(cfg.clone(), tls.clone(), Some(engine.metrics()))?;

    let listener = rpc_server::bind_reuseport(cfg.rpc_addr)
        .with_context(|| format!("kv-ucx: bind rpc on {}", cfg.rpc_addr))?;
    let disks: Rc<Vec<Rc<dyn StorageBackend>>> = Rc::new(Vec::new());
    let endpoints = Arc::new(std::sync::Mutex::new(
        openlake_io::rpc::RdmaEndpointsReply {
            complete: true,
            endpoints: Vec::new(),
        },
    ));
    let acceptor = tls.rpc_acceptor().map(Rc::new);

    let control_engine = engine.clone();
    compio::runtime::spawn(async move {
        loop {
            loop {
                match worker.poll_control() {
                    Ok(Some(body)) => {
                        let engine = control_engine.clone();
                        compio::runtime::spawn(
                            async move { handle_ucx_control(engine, &body).await },
                        )
                        .detach();
                    }
                    Ok(None) => break,
                    Err(error) => {
                        tracing::warn!(%error, "UCX control receive failed");
                        return;
                    }
                }
            }
            if let Err(error) = worker.wait_for_event().await {
                tracing::warn!(%error, "UCX event wait failed");
                return;
            }
        }
    })
    .detach();

    tracing::info!(rpc = %cfg.rpc_addr, "kv node (ucx) serving");
    rpc_server::serve(
        listener,
        disks,
        lock_server,
        acceptor,
        endpoints,
        Some(engine),
    )
    .await
}

#[cfg(all(feature = "rdma", target_os = "linux"))]
async fn handle_ucx_control(engine: Rc<KvEngine>, body: &[u8]) {
    use openlake_io::kv_wire::{Envelope, RdmaResponse, ENVELOPE_MAGIC};
    use openlake_io::rpc::{self, Response, WireError};

    let (client, request_id, payload) = match rpc::decode::<Envelope>(body) {
        Ok(Envelope::Req {
            magic,
            from_node_id,
            request_id,
            payload,
            ..
        }) if magic == ENVELOPE_MAGIC => (from_node_id, request_id, payload),
        Ok(_) => {
            tracing::warn!("UCX control received an invalid envelope");
            return;
        }
        Err(error) => {
            tracing::warn!(%error, "UCX control envelope decode failed");
            return;
        }
    };

    let payload = match payload {
        request @ (openlake_io::kv_wire::RdmaRequest::BatchReserve { .. }
        | openlake_io::kv_wire::RdmaRequest::BatchCommit { .. }
        | openlake_io::kv_wire::RdmaRequest::BatchLookup { .. }
        | openlake_io::kv_wire::RdmaRequest::BatchRelease { .. }
        | openlake_io::kv_wire::RdmaRequest::BatchRead { .. }
        | openlake_io::kv_wire::RdmaRequest::Reset) => engine.handle(request),
        _ => RdmaResponse::Generic(Response::Err(WireError::Other(
            "unsupported UCX KV control request".into(),
        ))),
    };
    let response = Envelope::Rsp {
        magic: ENVELOPE_MAGIC,
        request_id,
        payload,
    };
    let response = match rpc::encode(&response) {
        Ok(response) => response,
        Err(error) => {
            tracing::warn!(%error, "UCX control envelope encode failed");
            return;
        }
    };
    match engine.send_ucx_control(client, response) {
        Ok(request) => {
            if let Err(error) = request.await {
                tracing::warn!(client, %error, "UCX control response failed");
            }
        }
        Err(error) => tracing::warn!(client, %error, "UCX control response failed"),
    }
}

#[cfg(all(feature = "rdma", target_os = "linux"))]
pub async fn run(
    cfg: Arc<config::Config>,
    lock_server: Arc<LockServer>,
    tls: TlsMaterial,
    endpoint_registry: Arc<std::sync::Mutex<openlake_io::rpc::RdmaEndpointsReply>>,
) -> anyhow::Result<()> {
    use openlake_io::LocalFsBackend;

    use crate::{build_rdma_config, rdma_server};

    let mut rdma_cfg = build_rdma_config(
        cfg.rdma.as_ref().expect("validated: kv rdma has [rdma]"),
        0,
        cfg.nodes.len() as u16,
    )?;
    rdma_cfg.min_recv_bufs = usize::MAX;
    let (setup, my_endpoint) =
        openlake_io::rdma::RdmaNode::start_local(&rdma_cfg).context("rdma start_local")?;

    {
        let mut reg = endpoint_registry.lock().unwrap();
        reg.endpoints.push(my_endpoint);
        reg.complete = true;
    }

    let slab_cfg = cfg.kv_slab.expect("validated: kv mode has [kv_slab]");
    let r = cfg.rdma.as_ref().expect("validated: kv rdma has [rdma]");
    let max_clients = r.max_clients.unwrap_or(r.srq_depth / (r.peer_credit + 1)) as usize;
    tracing::info!(max_clients, "kv admission cap");
    let kv = Rc::new(KvEngine::new_rdma(
        setup.dev.clone(),
        slab_cfg.capacity_bytes()?,
        Duration::from_secs(slab_cfg.reserve_ttl_secs),
        max_clients,
        endpoint_registry.clone(),
    ));
    node_agent::spawn(cfg.clone(), tls.clone(), Some(kv.metrics()))?;

    let routing = Arc::new(openlake_io::rdma::ClusterRoutingTable::new(cfg.self_id));
    let rpc_listener = rpc_server::bind_reuseport(cfg.rpc_addr)
        .with_context(|| format!("kv node: bind rpc on {}", cfg.rpc_addr))?;
    tracing::info!(rpc = %cfg.rpc_addr, "kv node (rdma) serving");

    let no_disks: Rc<Vec<Rc<dyn StorageBackend>>> = Rc::new(Vec::new());
    let rpc_task = {
        let disks = no_disks.clone();
        let locks = lock_server.clone();
        let acceptor = tls.rpc_acceptor().map(Rc::new);
        let endpoints = endpoint_registry.clone();
        let kv = kv.clone();
        compio::runtime::spawn(async move {
            if let Err(e) =
                rpc_server::serve(rpc_listener, disks, locks, acceptor, endpoints, Some(kv)).await
            {
                tracing::error!("kv node: rpc serve error: {e:#}");
            }
        })
    };

    let node = Rc::new(openlake_io::rdma::RdmaNode::finalize(
        &rdma_cfg, setup, routing,
    ));
    kv.set_on_attach({
        let sock = node.sock.clone();
        move |id, rt| sock.reset_peer(openlake_io::rdma::PeerKey::new(id, rt))
    });
    let local_fs: Rc<Vec<Rc<LocalFsBackend>>> = Rc::new(Vec::new());
    let _rdma_task = compio::runtime::spawn({
        let endpoints = endpoint_registry.clone();
        async move {
            if let Err(e) =
                rdma_server::serve(node, no_disks, local_fs, lock_server, endpoints, Some(kv)).await
            {
                tracing::error!("kv node: rdma serve error: {e:#}");
            }
        }
    });

    let _ = rpc_task.await;
    Ok(())
}
