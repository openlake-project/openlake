mod auth;
mod config;
mod hardware_inventory;
mod in_memory_store;
mod kv_runtime;
mod lock_server;
mod node_agent;
#[cfg(all(feature = "rdma", target_os = "linux"))]
mod rdma_server;
mod rpc_server;
mod s3;
mod tls_material;

use std::path::PathBuf;
use std::rc::Rc;
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::Duration;

use anyhow::Context;
use clap::Parser;

use compio::tls::TlsAcceptor;
use openlake_io::{LocalFsBackend, LockPeer, PeerClient, RemoteBackend, StorageBackend};
use openlake_storage::{bootstrap_format, ClusterConfig, DiskAddr, DsyncClient, Engine};
use rustls::ClientConfig;
use uuid::Uuid;

use crate::lock_server::{LocalLockPeer, LockServer};
use crate::tls_material::TlsMaterial;

#[derive(Parser)]
#[command(about = "openlaked: distributed object storage node")]
struct Args {
    /// Path to the TOML config file describing this node and its peers.
    #[arg(long)]
    config: PathBuf,
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    let cfg_text = std::fs::read_to_string(&args.config)
        .with_context(|| format!("reading {}", args.config.display()))?;
    let mut cfg = config::Config::from_toml(&cfg_text)?;

    if let Ok(s) = std::env::var("OPENLAKE_SELF_ID") {
        let ord: u16 = s.parse()?;
        let toml_self_id = cfg.self_id;
        cfg.self_id = ord;
        if let Some(rdma) = cfg
            .rdma
            .as_mut()
            .filter(|rdma| rdma.backend == config::RdmaBackend::Dct)
        {
            rdma.self_node_id = Some(ord);
        }
        tracing::warn!(
            env_self_id = ord,
            toml_self_id,
            "OPENLAKE_SELF_ID override: StatefulSet self_id={ord} \
             picked over config-provided value {toml_self_id}; \
             align the TOML or drop the env var to remove ambiguity"
        );
    }

    let cfg = Arc::new(cfg);

    openlake_io::MemoryPool::init_pool(&(&cfg.memory_pool).into());
    openlake_io::init_purge_worker();

    #[cfg(all(feature = "rdma", target_os = "linux"))]
    if let Some(rdma_cfg) = cfg
        .rdma
        .as_ref()
        .filter(|rdma| rdma.backend == config::RdmaBackend::Dct)
    {
        let to = std::time::Duration::from_secs(rdma_cfg.network_timeout_secs);
        openlake_io::rdma_backend::set_rdma_network_timeout(to);
    }

    let mut cpus = physical_cores().context("enumerate physical cores")?;
    if cfg.mode == config::Mode::Kv {
        cpus.truncate(1);
    }
    let num_runtimes = cpus.len();
    tracing::info!(num_runtimes, ?cpus, "spawning runtimes");

    let lock_server = Arc::new(LockServer::new());

    let tls = TlsMaterial::load(&cfg).context("loading TLS material")?;

    let (done_tx, done_rx) = std::sync::mpsc::channel::<(usize, anyhow::Result<()>)>();

    let bootstrap_id: Arc<OnceLock<Uuid>> = Arc::new(OnceLock::new());

    let endpoint_registry: Arc<std::sync::Mutex<openlake_io::rpc::RdmaEndpointsReply>> = Arc::new(
        std::sync::Mutex::new(openlake_io::rpc::RdmaEndpointsReply {
            complete: num_runtimes == 0,
            endpoints: Vec::with_capacity(num_runtimes),
        }),
    );

    let store = in_memory_store::InMemoryStore::new();

    let mut handles = Vec::with_capacity(num_runtimes);
    for (runtime_id, cpu) in cpus.into_iter().enumerate() {
        let cfg = cfg.clone();
        let done_tx = done_tx.clone();
        let lock_server = lock_server.clone();
        let tls = tls.clone();
        let bootstrap_id = bootstrap_id.clone();
        let endpoint_registry = endpoint_registry.clone();
        let store = store.clone();
        let handle = thread::Builder::new()
            .name(format!("runtime-{runtime_id}"))
            .spawn(move || {
                let result = (|| -> anyhow::Result<()> {
                    if cfg.mode == config::Mode::Storage {
                        bind_cpu(cpu)?;
                    }
                    let rt = create_runtime()?;
                    match cfg.mode {
                        config::Mode::Kv => match cfg.transport {
                            config::TransportMode::Rdma => {
                                #[cfg(all(feature = "rdma", target_os = "linux"))]
                                {
                                    match cfg.rdma.as_ref().expect("validated: [rdma]").backend {
                                        config::RdmaBackend::Dct => rt.block_on(kv_runtime::run(
                                            cfg,
                                            lock_server,
                                            tls,
                                            endpoint_registry,
                                        )),
                                        config::RdmaBackend::Ucx => {
                                            rt.block_on(kv_runtime::run_ucx(cfg, lock_server, tls))
                                        }
                                    }
                                }
                                #[cfg(not(all(feature = "rdma", target_os = "linux")))]
                                {
                                    anyhow::bail!(
                                        "kv rdma transport requires the rdma feature on linux"
                                    )
                                }
                            }
                            config::TransportMode::H2 => {
                                rt.block_on(kv_runtime::run_tcp(cfg, lock_server, tls))
                            }
                        },
                        config::Mode::Storage => rt.block_on(run_storage_runtime(
                            runtime_id,
                            num_runtimes,
                            cfg,
                            lock_server,
                            tls,
                            bootstrap_id,
                            endpoint_registry,
                            store,
                        )),
                    }
                })();
                if let Err(e) = &result {
                    tracing::error!(runtime_id, cpu, "runtime exited with error: {e:#}");
                }
                let _ = done_tx.send((runtime_id, result));
            })
            .with_context(|| format!("spawn runtime-{runtime_id}"))?;
        handles.push(handle);
    }
    drop(done_tx);

    while let Ok((runtime_id, result)) = done_rx.recv() {
        match result {
            Ok(()) => tracing::info!(runtime_id, "runtime exited cleanly"),
            Err(e) => tracing::error!(runtime_id, "runtime exited: {e:#}"),
        }
    }
    for h in handles {
        let _ = h.join();
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn physical_cores() -> anyhow::Result<Vec<usize>> {
    use hwlocality::object::types::ObjectType;
    use hwlocality::Topology;

    let topology = Topology::new().map_err(|e| anyhow::anyhow!("hwloc topology init: {e}"))?;

    let mut cpus: Vec<usize> = Vec::new();
    for core in topology.objects_with_type(ObjectType::Core) {
        if let Some(cpuset) = core.cpuset() {
            if let Some(first) = cpuset.iter_set().min() {
                cpus.push(usize::from(first));
            }
        }
    }
    cpus.sort_unstable();
    if cpus.is_empty() {
        anyhow::bail!("no physical cores detected");
    }
    Ok(cpus)
}

#[cfg(not(target_os = "linux"))]
fn physical_cores() -> anyhow::Result<Vec<usize>> {
    let n = std::thread::available_parallelism()
        .context("available_parallelism")?
        .get();
    Ok((0..n).collect())
}

/// Pin the current OS thread to exactly one CPU. Uses `sched_setaffinity`
/// with a single-bit mask so the kernel never schedules this thread
/// anywhere else. No-op on non-Linux.
fn bind_cpu(cpu: usize) -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    {
        use nix::sched::{sched_setaffinity, CpuSet};
        use nix::unistd::Pid;
        let mut cpuset = CpuSet::new();
        cpuset.set(cpu).context("cpu id out of range for CpuSet")?;
        sched_setaffinity(Pid::from_raw(0), &cpuset).context("sched_setaffinity failed")?;
        tracing::info!(cpu, "thread pinned to cpu");
    }
    #[cfg(not(target_os = "linux"))]
    {
        tracing::debug!(cpu, "cpu pinning skipped on non-Linux platform");
    }
    Ok(())
}

fn create_runtime() -> anyhow::Result<compio::runtime::Runtime> {
    let mut proactor = compio::driver::ProactorBuilder::new();
    proactor
        .capacity(4096) // iouring size
        .coop_taskrun(false)
        .taskrun_flag(false);

    // Only cyper's HTTP client initialisation uses compio's asyncify pool (for getaddrinfo).
    // No other flow should land here. Capped at 1.
    // TODO: route cyper through compio natively and drop this pool entirely.
    #[cfg(not(target_os = "macos"))]
    proactor.thread_pool_limit(1);

    compio::runtime::RuntimeBuilder::new()
        .with_proactor(proactor)
        .event_interval(32) // poll ring cq
        .build()
        .context("build compio runtime")
}

#[allow(clippy::too_many_arguments)]
async fn run_storage_runtime(
    runtime_id: usize,
    #[cfg_attr(
        not(all(feature = "rdma", target_os = "linux")),
        allow(unused_variables)
    )]
    num_runtimes: usize,
    cfg: Arc<config::Config>,
    lock_server: Arc<LockServer>,
    tls: TlsMaterial,
    bootstrap_id: Arc<OnceLock<Uuid>>,
    endpoint_registry: Arc<std::sync::Mutex<openlake_io::rpc::RdmaEndpointsReply>>,
    store: in_memory_store::InMemoryStore,
) -> anyhow::Result<()> {
    if runtime_id == 0 {
        node_agent::spawn(cfg.clone(), tls.clone(), None)?;
    }

    let s3_acceptor: Option<Rc<TlsAcceptor>> = tls.s3_acceptor().map(Rc::new);
    let rpc_acceptor: Option<Rc<TlsAcceptor>> = tls.rpc_acceptor().map(Rc::new);
    let rpc_connector: Option<Arc<ClientConfig>> = tls.rpc_connector();

    let self_node = cfg
        .nodes
        .iter()
        .find(|n| n.id == cfg.self_id)
        .expect("config validation guarantees self_id is in nodes");
    let local_fs_disks: Vec<Rc<LocalFsBackend>> = cfg
        .data_dirs
        .iter()
        .enumerate()
        .map(|(i, dir)| -> anyhow::Result<Rc<LocalFsBackend>> {
            Ok(Rc::new(LocalFsBackend::new(dir).with_context(|| {
                format!(
                    "runtime {runtime_id}: init local disk {i} at {}",
                    dir.display()
                )
            })?))
        })
        .collect::<anyhow::Result<_>>()?;
    let local_disks: Vec<Rc<dyn StorageBackend>> = local_fs_disks
        .iter()
        .map(|rc| rc.clone() as Rc<dyn StorageBackend>)
        .collect();
    debug_assert_eq!(local_disks.len(), self_node.disk_count as usize);

    let mut backends: std::collections::HashMap<DiskAddr, Rc<dyn StorageBackend>> =
        std::collections::HashMap::with_capacity(
            cfg.nodes.iter().map(|n| n.disk_count as usize).sum(),
        );
    let mut lock_peer_by_node: std::collections::HashMap<
        openlake_storage::cluster::NodeId,
        Rc<dyn LockPeer>,
    > = std::collections::HashMap::with_capacity(cfg.nodes.len());
    let local_lock_peer: Rc<dyn LockPeer> = Rc::new(LocalLockPeer::new(lock_server.clone()));

    let mut peer_clients: std::collections::HashMap<
        openlake_storage::cluster::NodeId,
        Rc<PeerClient>,
    > = std::collections::HashMap::with_capacity(cfg.nodes.len().saturating_sub(1));
    for n in &cfg.nodes {
        if n.id == cfg.self_id {
            for (idx, disk_be) in local_disks.iter().enumerate() {
                backends.insert(
                    DiskAddr {
                        node_id: n.id,
                        disk_idx: idx as u16,
                    },
                    disk_be.clone(),
                );
            }
            lock_peer_by_node.insert(n.id, local_lock_peer.clone());
        } else {
            let peer = Rc::new(PeerClient::new(n.rpc_addr, rpc_connector.clone()));
            let lock_rb = Rc::new(RemoteBackend::new(peer.clone(), 0));
            lock_peer_by_node.insert(n.id, lock_rb as Rc<dyn LockPeer>);
            peer_clients.insert(n.id, peer);
        }
    }

    #[cfg(all(feature = "rdma", target_os = "linux"))]
    let rdma_pending: Option<(openlake_io::rdma::RdmaSetup, openlake_io::rdma::RdmaConfig)> =
        match cfg.transport {
            config::TransportMode::Rdma => {
                let rdma_cfg = build_rdma_config(
                    cfg.rdma.as_ref().expect("rdma transport requires [rdma]"),
                    runtime_id as u16,
                    cfg.nodes.len() as u16,
                )?;
                let (setup, my_endpoint) = openlake_io::rdma::RdmaNode::start_local(&rdma_cfg)
                    .context("rdma start_local")?;
                {
                    let mut reg = endpoint_registry.lock().unwrap();
                    reg.endpoints.push(my_endpoint);
                    if reg.endpoints.len() >= num_runtimes {
                        reg.complete = true;
                    }
                }
                Some((setup, rdma_cfg))
            }
            config::TransportMode::H2 => None,
        };

    let auth_state = Rc::new(auth::AuthState::new(cfg.region.clone(), &cfg.credentials));

    let s3_listener = s3::listener::bind_reuseport(cfg.s3_addr)
        .with_context(|| format!("runtime {runtime_id}: bind s3 on {}", cfg.s3_addr))?;
    let rpc_listener = rpc_server::bind_reuseport(cfg.rpc_addr)
        .with_context(|| format!("runtime {runtime_id}: bind rpc on {}", cfg.rpc_addr))?;

    tracing::info!(runtime_id, s3 = %cfg.s3_addr, rpc = %cfg.rpc_addr, "runtime serving");

    // Sweeper: one per process. Pin to runtime 0 to avoid duplicate work.
    if runtime_id == 0 {
        let sweep_target = lock_server.clone();
        compio::runtime::spawn(async move {
            crate::lock_server::run_sweeper(
                sweep_target,
                crate::lock_server::DEFAULT_SWEEP_INTERVAL,
            )
            .await;
        })
        .detach();
    }

    let rpc_disks = Rc::new(local_disks.clone());
    let rpc_locks = lock_server.clone();
    let rpc_acceptor_t = rpc_acceptor.clone();
    let rpc_endpoints = endpoint_registry.clone();
    let rpc_task = compio::runtime::spawn(async move {
        if let Err(e) = rpc_server::serve(
            rpc_listener,
            rpc_disks,
            rpc_locks,
            rpc_acceptor_t,
            rpc_endpoints,
            None,
        )
        .await
        {
            tracing::error!(runtime_id, "rpc serve error: {e:#}");
        }
    });

    #[cfg(all(feature = "rdma", target_os = "linux"))]
    let rdma_node: Option<Rc<openlake_io::rdma::RdmaNode>> =
        if let Some((setup, rdma_cfg)) = rdma_pending {
            let mut routing = openlake_io::rdma::ClusterRoutingTable::new(cfg.self_id);
            loop {
                let reg = endpoint_registry.lock().unwrap();
                if reg.complete {
                    for ep in reg.endpoints.iter() {
                        routing.insert(cfg.self_id, ep);
                    }
                    break;
                }
                drop(reg);
                compio::time::sleep(Duration::from_millis(50)).await;
            }
            let mut remaining: std::collections::HashSet<openlake_storage::cluster::NodeId> =
                peer_clients.keys().copied().collect();
            while !remaining.is_empty() {
                for peer_id in remaining.clone() {
                    let peer = peer_clients.get(&peer_id).expect("peer_id present");
                    let rb = RemoteBackend::new(peer.clone(), 0);
                    match rb.get_rdma_endpoints().await {
                        Ok(reply) if reply.complete => {
                            for ep in &reply.endpoints {
                                routing.insert(peer_id, ep);
                            }
                            remaining.remove(&peer_id);
                        }
                        Ok(_) => {}
                        Err(_) => {}
                    }
                }
                if !remaining.is_empty() {
                    compio::time::sleep(Duration::from_millis(200)).await;
                }
            }
            let routing = Arc::new(routing);
            Some(Rc::new(openlake_io::rdma::RdmaNode::finalize(
                &rdma_cfg, setup, routing,
            )))
        } else {
            None
        };

    for n in &cfg.nodes {
        if n.id == cfg.self_id {
            continue;
        }
        let peer = peer_clients.get(&n.id).expect("peer_id present").clone();
        match cfg.transport {
            config::TransportMode::H2 => {
                for disk_idx in 0..n.disk_count {
                    let rb = Rc::new(RemoteBackend::new(peer.clone(), disk_idx));
                    backends.insert(
                        DiskAddr {
                            node_id: n.id,
                            disk_idx,
                        },
                        rb as Rc<dyn StorageBackend>,
                    );
                }
            }
            #[cfg(all(feature = "rdma", target_os = "linux"))]
            config::TransportMode::Rdma => {
                let node = rdma_node.as_ref().expect("rdma node finalized").clone();
                for disk_idx in 0..n.disk_count {
                    let rpc_backend: Rc<dyn StorageBackend> =
                        Rc::new(RemoteBackend::new(peer.clone(), disk_idx));
                    let rb = Rc::new(openlake_io::rdma_backend::RdmaBackend::new(
                        node.clone(),
                        n.id,
                        disk_idx,
                        rpc_backend,
                    ));
                    backends.insert(
                        DiskAddr {
                            node_id: n.id,
                            disk_idx,
                        },
                        rb as Rc<dyn StorageBackend>,
                    );
                }
            }
            #[cfg(not(all(feature = "rdma", target_os = "linux")))]
            config::TransportMode::Rdma => {
                anyhow::bail!("rdma transport selected but build lacks rdma feature");
            }
        }
    }

    #[cfg(all(feature = "rdma", target_os = "linux"))]
    let _rdma_task = match (cfg.transport, rdma_node.as_ref()) {
        (config::TransportMode::Rdma, Some(node)) => {
            let node = node.clone();
            let disks = Rc::new(local_disks.clone());
            let local_disks = Rc::new(local_fs_disks.clone());
            let locks = lock_server.clone();
            let endpoints = endpoint_registry.clone();
            Some(compio::runtime::spawn(async move {
                if let Err(e) =
                    rdma_server::serve(node, disks, local_disks, locks, endpoints, None).await
                {
                    tracing::error!(runtime_id, "rdma serve error: {e:#}");
                }
            }))
        }
        _ => None,
    };

    let deployment_id: Uuid = if runtime_id == 0 {
        let mut local_b: Vec<Rc<dyn StorageBackend>> = Vec::new();
        let mut local_off: Vec<u32> = Vec::new();
        let mut peer_b: Vec<Rc<dyn StorageBackend>> = Vec::new();
        let mut peer_off: Vec<u32> = Vec::new();
        let mut flat_idx: u32 = 0;
        for n in &cfg.nodes {
            for d in 0..n.disk_count {
                flat_idx += 1; // 1-based per FormatJson contract
                let addr = DiskAddr {
                    node_id: n.id,
                    disk_idx: d,
                };
                let be = backends.get(&addr).expect("backend for every disk").clone();
                if n.id == cfg.self_id {
                    local_b.push(be);
                    local_off.push(flat_idx);
                } else {
                    peer_b.push(be);
                    peer_off.push(flat_idx);
                }
            }
        }
        let mut node_ids: Vec<u16> = cfg.nodes.iter().map(|n| n.id).collect();
        node_ids.sort_unstable();
        let id = bootstrap_format(
            &local_b,
            &peer_b,
            &local_off,
            &peer_off,
            cfg.self_id,
            &node_ids,
            cfg.set_drive_count,
            Duration::from_secs(1),
            Duration::from_secs(300),
        )
        .await
        .with_context(|| format!("runtime {runtime_id}: cluster format bootstrap"))?;
        bootstrap_id
            .set(id)
            .expect("only runtime 0 sets bootstrap_id");
        tracing::info!(deployment_id = %id, "cluster bootstrap complete");
        id
    } else {
        loop {
            if let Some(&id) = bootstrap_id.get() {
                break id;
            }
            compio::time::sleep(Duration::from_millis(50)).await;
        }
    };

    let cluster = ClusterConfig {
        nodes: cfg.nodes.clone(),
        set_drive_count: cfg.set_drive_count,
        default_parity_count: cfg.default_parity_count,
        deployment_id,
    };
    // One DsyncClient per erasure set; peers = the unique nodes that
    // own disks in that set. The coordinator only votes against the
    // target nodes for the data, never the full cluster. `num_sets()`
    // is at least 1 today (single implicit pool), so the `.max(1)`
    // matches Engine's debug assertion when total_disks == 0 in
    // pathological configs.
    let num_sets = cluster.num_sets().max(1);
    let mut dsync_by_set: Vec<Rc<DsyncClient>> = Vec::with_capacity(num_sets);
    for set_idx in 0..num_sets {
        let node_ids = cluster.set_node_ids(set_idx);
        let peers: Vec<Rc<dyn LockPeer>> = node_ids
            .iter()
            .map(|id| {
                lock_peer_by_node
                    .get(id)
                    .expect("every NodeId in set_node_ids must have a LockPeer")
                    .clone()
            })
            .collect();
        dsync_by_set.push(Rc::new(DsyncClient::new(peers)));
    }
    let engine = Rc::new(Engine::new(cluster, backends, dsync_by_set, cfg.self_id));

    let s3_engine = engine.clone();
    let s3_auth = auth_state.clone();
    let s3_acceptor = s3_acceptor.clone();
    let s3_cfg = cfg.clone();
    let s3_task = compio::runtime::spawn(async move {
        let app_state = s3::state::AppState::new(s3_engine, s3_auth, store);
        let _ = s3::app::serve(s3_listener, app_state, s3_acceptor, s3_cfg).await;
        tracing::error!(runtime_id, "s3 serve loop exited");
    });

    let _ = s3_task.await;
    let _ = rpc_task.await;
    Ok(())
}

#[cfg(all(feature = "rdma", target_os = "linux"))]
pub(crate) fn build_rdma_config(
    t: &config::RdmaToml,
    runtime_id: u16,
    num_cluster_nodes: u16,
) -> anyhow::Result<openlake_io::rdma::RdmaConfig> {
    anyhow::ensure!(
        t.backend == config::RdmaBackend::Dct,
        "native RDMA configuration requires backend = \"dct\""
    );
    let qos = t.qos.as_ref().context("[rdma.qos] is required")?;
    Ok(openlake_io::rdma::RdmaConfig {
        self_node_id: t.self_node_id.context("[rdma] self_node_id is required")?,
        runtime_id,
        dev_name: t.dev_name.clone().context("[rdma] dev_name is required")?,
        dc_key: t.dc_key.context("[rdma] dc_key is required")?,
        qos: openlake_io::rdma::RdmaQos {
            traffic_class: qos.traffic_class,
            service_level: qos.service_level,
        },
        bulk_buf_size: openlake_storage::DEFAULT_EC_PER_SHARD_BYTES,
        bulk_pool_cap: t.bulk_pool_cap,
        num_cluster_nodes,
        min_recv_bufs: 0,
        srq_depth: t.srq_depth,
        max_send_wr: t.max_send_wr,
        peer_credit: t.peer_credit,
    })
}
