use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;

use openlake_io::kv::KvSlab;
use openlake_io::{HostSlab, StorageBackend};
use openlake_storage::KvEngine;

use crate::config;
use crate::lock_server::LockServer;
use crate::rpc_server;
use crate::tls_material::TlsMaterial;

pub async fn run_tcp(
    cfg: Arc<config::Config>,
    lock_server: Arc<LockServer>,
    tls: TlsMaterial,
) -> anyhow::Result<()> {
    let slab_cfg = cfg.kv_slab.expect("validated: kv mode has [kv_slab]");
    let slab: Rc<dyn KvSlab> = Rc::new(HostSlab::create(
        slab_cfg.slot_bytes as u32,
        slab_cfg.slot_count as u32,
        Duration::from_secs(slab_cfg.reserve_ttl_secs),
    )?);
    let engine = Rc::new(KvEngine::new(slab, 0));

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
pub async fn run(
    cfg: Arc<config::Config>,
    lock_server: Arc<LockServer>,
    tls: TlsMaterial,
    endpoint_registry: Arc<std::sync::Mutex<openlake_io::rpc::RdmaEndpointsReply>>,
) -> anyhow::Result<()> {
    use openlake_io::{LocalFsBackend, RdmaSlab};

    use crate::{build_rdma_config, rdma_server};

    let mut rdma_cfg = build_rdma_config(
        cfg.rdma.as_ref().expect("validated: kv rdma has [rdma]"),
        0,
        cfg.nodes.len() as u16,
    );
    rdma_cfg.min_recv_bufs = usize::MAX;
    let (setup, mut my_endpoint) =
        openlake_io::rdma::RdmaNode::start_local(&rdma_cfg).context("rdma start_local")?;

    let slab_cfg = cfg.kv_slab.expect("validated: kv mode has [kv_slab]");
    let rdma_slab = RdmaSlab::new(
        setup.dev.clone(),
        slab_cfg.slot_bytes,
        slab_cfg.slot_count,
        Duration::from_secs(slab_cfg.reserve_ttl_secs),
    )?;
    my_endpoint.kv_slab = Some(openlake_io::rpc::SlabMeta {
        slab_base: rdma_slab.slab_base(),
        rkey: rdma_slab.rkey(),
        slot_bytes: rdma_slab.slot_bytes(),
    });
    let slab: Rc<dyn KvSlab> = Rc::new(rdma_slab);
    {
        let mut reg = endpoint_registry.lock().unwrap();
        reg.endpoints.push(my_endpoint);
        reg.complete = true;
    }

    let r = cfg.rdma.as_ref().expect("validated: kv rdma has [rdma]");
    let max_clients = r.max_clients.unwrap_or(r.srq_depth / (r.peer_credit + 1)) as usize;
    tracing::info!(max_clients, "kv admission cap");
    let kv = Rc::new(KvEngine::new(slab, max_clients));

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
