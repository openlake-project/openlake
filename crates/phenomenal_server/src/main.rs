//! `phenomenald` — thread-per-core S3 + RPC server.
//!
//! Terminology: a runtime here is one pinned OS thread owning one
//! compio runtime on one CPU core. Runtimes do not own data — every
//! runtime can write every drive. The word "runtime" means just
//! "pinned execution context," not an ownership unit.
//!
//! Startup sequence:
//!
//!   1. Main thread parses config and picks `num_runtimes =
//!      available_parallelism()` (one per logical CPU).
//!   2. For each runtime `i` in `0..N`:
//!      - Spawn an OS thread named `runtime-{i}`.
//!      - Inside that thread, call `sched_setaffinity` to pin it
//!        exclusively to CPU `i` (Linux; no-op elsewhere).
//!      - Build a dedicated compio `Runtime` with `coop_taskrun`,
//!        `thread_pool_limit(0)`, `event_interval(128)`.
//!      - Block on `run_runtime(i, cfg)`.
//!   3. `run_runtime` constructs this runtime's own `LocalFsBackend` +
//!      `RemoteBackend`s + `Engine`, binds the S3 and RPC listeners
//!      with `SO_REUSEPORT`, and runs both accept loops concurrently
//!      as tasks on its own compio runtime.
//!
//! After startup: N pinned OS threads, N compio runtimes, N io_urings,
//! N copies of the engine/backends. The kernel spreads incoming
//! connections across runtimes via `SO_REUSEPORT` 4-tuple hashing —
//! every new client lands on exactly one runtime's accept queue and
//! stays on that runtime's thread for its whole life. Every connection
//! handler, every engine call, every disk I/O for that client runs as
//! a task on that runtime's compio scheduler.

mod auth;
mod config;
mod s3;
mod lock_server;
mod rpc_server;
#[cfg(all(feature = "rdma", target_os = "linux"))]
mod rdma_server;
mod tls_material;

use std::path::PathBuf;
use std::rc::Rc;
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::Duration;

use anyhow::Context;
use clap::Parser;

use compio::tls::TlsAcceptor;
use phenomenal_io::{LocalFsBackend, LockPeer, PeerClient, RemoteBackend, StorageBackend};
use rustls::ClientConfig;
use phenomenal_storage::{bootstrap_format, ClusterConfig, DiskAddr, DsyncClient, Engine};
use uuid::Uuid;

use crate::lock_server::{LocalLockPeer, LockServer};
use crate::tls_material::TlsMaterial;

#[derive(Parser)]
#[command(about = "phenomenald: distributed object storage node")]
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
    let cfg = Arc::new(config::Config::from_toml(&cfg_text)?);

    // Initialise the global buffer pool BEFORE any runtime spawns so
    // every per-connection task sees a ready pool from the very first
    // `PooledBuffer::with_capacity` call. Idempotent — repeat invocations
    // are no-ops via `OnceCell::get_or_init`.
    phenomenal_io::MemoryPool::init_pool(&(&cfg.memory_pool).into());
    phenomenal_io::init_purge_worker();

    // One runtime per physical core. Hyperthread siblings are
    // skipped so two runtimes never share a physical core's L1/L2.
    let cpus = physical_cores().context("enumerate physical cores")?;
    let num_runtimes = cpus.len();
    tracing::info!(num_runtimes, ?cpus, "spawning runtimes");

    // One LockServer per node (process), shared across every runtime.
    // The dsync write protocol requires a single source of truth for
    // "who currently holds resource X" — having one map per runtime
    // would let two runtimes grant the same lock to two different
    // writers and silently break correctness.
    let lock_server = Arc::new(LockServer::new());

    // Build TLS material once on the main thread. `TlsMaterial` is a
    // `Clone`-cheap struct holding the three optional handles
    // (s3_acceptor, rpc_acceptor, rpc_connector). Each runtime thread
    // gets its own clone — under the hood that's just an Arc bump on
    // the rustls configs.
    let tls = TlsMaterial::load(&cfg).context("loading TLS material")?;

    // Each runtime reports its final exit status on this channel. The
    // main thread drains it so a runtime panic or error is visible in
    // logs instead of being swallowed by `JoinHandle`.
    let (done_tx, done_rx) = std::sync::mpsc::channel::<(usize, anyhow::Result<()>)>();

    let bootstrap_id: Arc<OnceLock<Uuid>> = Arc::new(OnceLock::new());

    let mut handles = Vec::with_capacity(num_runtimes);
    for (runtime_id, cpu) in cpus.into_iter().enumerate() {
        let cfg          = cfg.clone();
        let done_tx      = done_tx.clone();
        let lock_server  = lock_server.clone();
        let tls          = tls.clone();
        let bootstrap_id = bootstrap_id.clone();
        let handle       = thread::Builder::new()
            .name(format!("runtime-{runtime_id}"))
            .spawn(move || {
                let result = (|| -> anyhow::Result<()> {
                    bind_cpu(cpu)?;
                    let rt = create_runtime()?;
                    rt.block_on(run_runtime(runtime_id, cfg, lock_server, tls, bootstrap_id))
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

    // Block until every runtime thread exits. If one dies, the others
    // keep running — operator decides whether to restart the process
    // (systemd, k8s, etc.). Phenomenald doesn't try to respawn.
    while let Ok((runtime_id, result)) = done_rx.recv() {
        match result {
            Ok(())   => tracing::info!(runtime_id, "runtime exited cleanly"),
            Err(e)   => tracing::error!(runtime_id, "runtime exited: {e:#}"),
        }
    }
    for h in handles {
        let _ = h.join();
    }
    Ok(())
}

/// Enumerate the first logical CPU of each physical core on this
/// machine, in ascending CPU-id order. Returns one CPU id per
/// physical core — hyperthread siblings are filtered out so two
/// runtimes never share a core's L1/L2.
///
/// On a host with 16 physical cores + SMT2, Linux sees 32 logical
/// CPUs (0..31). We return 16 CPU ids, one from each physical
/// core's sibling pair.
///
/// Linux: queries hwloc for real physical-core topology.
/// Other platforms (macOS dev boxes): falls back to
/// `available_parallelism`, which returns logical CPUs. Acceptable
/// because production is Linux bare-metal.
#[cfg(target_os = "linux")]
fn physical_cores() -> anyhow::Result<Vec<usize>> {
    use hwlocality::object::types::ObjectType;
    use hwlocality::Topology;

    let topology = Topology::new()
        .map_err(|e| anyhow::anyhow!("hwloc topology init: {e}"))?;

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
        sched_setaffinity(Pid::from_raw(0), &cpuset)
            .context("sched_setaffinity failed")?;
        tracing::info!(cpu, "thread pinned to cpu");
    }
    #[cfg(not(target_os = "linux"))]
    {
        tracing::debug!(cpu, "cpu pinning skipped on non-Linux platform");
    }
    Ok(())
}

/// Build a compio runtime for a pinned
/// runtime thread.
///
/// - `capacity(4096)` — io_uring SQ/CQ ring size.
/// - `coop_taskrun(true) + taskrun_flag(true)` — kernel delivers CQEs
///   on the submitter's task context, no IPI.
/// - `thread_pool_limit(0)` (Linux only) — disables compio's
///   `AsyncifyPool`, so no accidental worker thread can be spawned.
///   macOS's compio fallback needs the pool for some fs ops, so we
///   leave the default there.
/// - `event_interval(128)` — cap task-poll bursts before re-checking
///   I/O completions.
fn create_runtime() -> anyhow::Result<compio::runtime::Runtime> {
    let mut proactor = compio::driver::ProactorBuilder::new();
    proactor
        .capacity(4096) // iouring size
        .coop_taskrun(false)
        .taskrun_flag(false);

    #[cfg(not(target_os = "macos"))]
    proactor.thread_pool_limit(0);

    compio::runtime::RuntimeBuilder::new()
        .with_proactor(proactor)
        .event_interval(32) // poll ring cq
        .build()
        .context("build compio runtime")
}

/// Per-runtime setup + event loop. Runs on one OS thread pinned to one
/// CPU. Owns its own `LocalFsBackend`, its own `RemoteBackend`s, its
/// own `Engine`, its own accept sockets (bound with `SO_REUSEPORT`),
/// and every connection task spawned from those accept loops.
///
/// Returns only when both accept loops exit (normally: never, until
/// shutdown).
async fn run_runtime(
    runtime_id:   usize,
    cfg:          Arc<config::Config>,
    lock_server:  Arc<LockServer>,
    tls:          TlsMaterial,
    bootstrap_id: Arc<OnceLock<Uuid>>,
) -> anyhow::Result<()> {
    // Extract the three TLS handles from the shared material.
    //
    // S3 acceptor / RPC acceptor go through `Rc` for runtime-local
    // sharing: `TlsAcceptor` is a cheap `Arc<ServerConfig>` wrapper
    // but `Rc` keeps per-connection refcount bumps non-atomic on the
    // single-thread runtime.
    //
    // RPC connector is a bare `Arc<ClientConfig>` because cyper takes
    // it directly via `ClientBuilder::use_rustls(Arc<ClientConfig>)`.
    // No further wrapping is needed — clone the `Arc` per peer.
    let s3_acceptor:   Option<Rc<TlsAcceptor>>     = tls.s3_acceptor()  .map(Rc::new);
    let rpc_acceptor:  Option<Rc<TlsAcceptor>>     = tls.rpc_acceptor() .map(Rc::new);
    let rpc_connector: Option<Arc<ClientConfig>>   = tls.rpc_connector();

    // Each runtime opens its own handle to every local disk. The
    // underlying filesystems are shared across the OS, the kernel
    // serialises concurrent ops at the VFS layer. Per-runtime handles
    // mean each runtime submits I/O to its own io_uring, keeping all
    // kernel completion traffic on this runtime's core.
    //
    // `local_disks[i]` is the backend for `disk_idx = i` on this
    // node. Order matches `cfg.data_dirs`, which on the wire is the
    // disk_idx the cluster topology and other peers reference.
    let self_node = cfg.nodes.iter().find(|n| n.id == cfg.self_id)
        .expect("config validation guarantees self_id is in nodes");
    let local_disks: Vec<Rc<dyn StorageBackend>> = cfg.data_dirs.iter()
        .enumerate()
        .map(|(i, dir)| -> anyhow::Result<Rc<dyn StorageBackend>> {
            Ok(Rc::new(
                LocalFsBackend::new(dir)
                    .with_context(|| format!(
                        "runtime {runtime_id}: init local disk {i} at {}",
                        dir.display()
                    ))?,
            ))
        })
        .collect::<anyhow::Result<_>>()?;
    debug_assert_eq!(local_disks.len(), self_node.disk_count as usize);

    // Build storage backends keyed by `DiskAddr`, plus a per-node
    // `LockPeer` indexed by `NodeId`. The lock plane is per-erasure-set
    // (built below once the cluster topology is finalized), so we
    // memoize one LockPeer per node here and assemble the per-set
    // peer lists by `set_node_ids`. Per-peer `PeerClient` is shared
    // across every `RemoteBackend` targeting the same peer so they
    // ride a single multiplexed h2 connection.
    let mut backends:   std::collections::HashMap<DiskAddr, Rc<dyn StorageBackend>> =
        std::collections::HashMap::with_capacity(cfg.nodes.iter().map(|n| n.disk_count as usize).sum());
    let mut lock_peer_by_node: std::collections::HashMap<phenomenal_storage::cluster::NodeId, Rc<dyn LockPeer>> =
        std::collections::HashMap::with_capacity(cfg.nodes.len());
    let local_lock_peer: Rc<dyn LockPeer> =
        Rc::new(LocalLockPeer::new(lock_server.clone()));

    #[cfg(all(feature = "rdma", target_os = "linux"))]
    let rdma_node: Option<std::rc::Rc<phenomenal_io::rdma::RdmaNode>> = match cfg.transport {
        config::TransportMode::Rdma => Some(std::rc::Rc::new(
            phenomenal_io::rdma::RdmaNode::start(build_rdma_config(cfg.rdma.as_ref().unwrap()))?
        )),
        config::TransportMode::H2 => None,
    };

    for n in &cfg.nodes {
        if n.id == cfg.self_id {
            // Local node — register every local disk.
            for (idx, disk_be) in local_disks.iter().enumerate() {
                backends.insert(
                    DiskAddr { node_id: n.id, disk_idx: idx as u16 },
                    disk_be.clone(),
                );
            }
            lock_peer_by_node.insert(n.id, local_lock_peer.clone());
        } else {
            // `rpc_connector` is `Some` when rpc_tls is configured, `None`
            // for plaintext h2c clusters. PeerClient handles both.
            let peer = Rc::new(PeerClient::new(n.rpc_addr, rpc_connector.clone()));

            let lock_rb = Rc::new(RemoteBackend::new(peer.clone(), 0));
            lock_peer_by_node.insert(n.id, lock_rb as Rc<dyn LockPeer>);

            // Data plane backends: pick per transport.
            match cfg.transport {
                config::TransportMode::H2 => {
                    for disk_idx in 0..n.disk_count {
                        let rb = Rc::new(RemoteBackend::new(peer.clone(), disk_idx));
                        backends.insert(
                            DiskAddr { node_id: n.id, disk_idx },
                            rb as Rc<dyn StorageBackend>,
                        );
                    }
                }
                #[cfg(all(feature = "rdma", target_os = "linux"))]
                config::TransportMode::Rdma => {
                    let node = rdma_node.as_ref().expect("rdma node built in rdma mode").clone();
                    for disk_idx in 0..n.disk_count {
                        let rpc_backend: Rc<dyn StorageBackend> =
                            Rc::new(RemoteBackend::new(peer.clone(), disk_idx));
                        let rb = Rc::new(phenomenal_io::rdma_backend::RdmaBackend::new(
                            node.clone(), n.id, disk_idx, rpc_backend,
                        ));
                        backends.insert(
                            DiskAddr { node_id: n.id, disk_idx },
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
    }

    let auth_state = Rc::new(auth::AuthState::new(
        cfg.region.clone(),
        &cfg.credentials,
    ));

    let s3_listener  = s3::listener::bind_reuseport(cfg.s3_addr)
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
            ).await;
        }).detach();
    }

    let rpc_disks      = Rc::new(local_disks.clone());
    let rpc_locks      = lock_server.clone();
    let rpc_acceptor_t = rpc_acceptor.clone();
    let rpc_task = compio::runtime::spawn(async move {
        if let Err(e) = rpc_server::serve(rpc_listener, rpc_disks, rpc_locks, rpc_acceptor_t).await {
            tracing::error!(runtime_id, "rpc serve error: {e:#}");
        }
    });

    #[cfg(all(feature = "rdma", target_os = "linux"))]
    let _rdma_task = match cfg.transport {
        config::TransportMode::Rdma => {
            let node   = rdma_node.as_ref().expect("rdma node built in rdma mode").clone();
            let disks  = Rc::new(local_disks.clone());
            let locks  = lock_server.clone();
            Some(compio::runtime::spawn(async move {
                if let Err(e) = rdma_server::serve(node, disks, locks).await {
                    tracing::error!(runtime_id, "rdma serve error: {e:#}");
                }
            }))
        }
        config::TransportMode::H2 => None,
    };

    let deployment_id: Uuid = if runtime_id == 0 {
        let mut local_b   : Vec<Rc<dyn StorageBackend>> = Vec::new();
        let mut local_off : Vec<u32>                    = Vec::new();
        let mut peer_b    : Vec<Rc<dyn StorageBackend>> = Vec::new();
        let mut peer_off  : Vec<u32>                    = Vec::new();
        let mut flat_idx  : u32                         = 0;
        for n in &cfg.nodes {
            for d in 0..n.disk_count {
                flat_idx += 1; // 1-based per FormatJson contract
                let addr = DiskAddr { node_id: n.id, disk_idx: d };
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
            &local_b, &peer_b, &local_off, &peer_off,
            cfg.self_id, &node_ids, cfg.set_drive_count,
            Duration::from_secs(1),    
            Duration::from_secs(300), 
        ).await
            .with_context(|| format!("runtime {runtime_id}: cluster format bootstrap"))?;
        bootstrap_id.set(id).expect("only runtime 0 sets bootstrap_id");
        tracing::info!(deployment_id = %id, "cluster bootstrap complete");
        id
    } else {
        loop {
            if let Some(&id) = bootstrap_id.get() { break id; }
            compio::time::sleep(Duration::from_millis(50)).await;
        }
    };

    let cluster = ClusterConfig {
        nodes:                cfg.nodes.clone(),
        set_drive_count:      cfg.set_drive_count,
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
        let peers: Vec<Rc<dyn LockPeer>> = node_ids.iter()
            .map(|id| lock_peer_by_node.get(id)
                .expect("every NodeId in set_node_ids must have a LockPeer")
                .clone())
            .collect();
        dsync_by_set.push(Rc::new(DsyncClient::new(peers)));
    }
    let engine = Rc::new(Engine::new(cluster, backends, dsync_by_set, cfg.self_id));

    let s3_engine     = engine.clone();
    let s3_auth       = auth_state.clone();
    let s3_acceptor   = s3_acceptor.clone();
    let s3_task = compio::runtime::spawn(async move {
        let app_state = s3::state::AppState::new(s3_engine, s3_auth);
        let _ = s3::app::serve(s3_listener, app_state, s3_acceptor).await;
        tracing::error!(runtime_id, "s3 serve loop exited");
    });

    let _ = s3_task.await;
    let _ = rpc_task.await;
    Ok(())
}

#[cfg(all(feature = "rdma", target_os = "linux"))]
fn build_rdma_config(t: &config::RdmaToml) -> phenomenal_io::rdma::RdmaConfig {
    phenomenal_io::rdma::RdmaConfig {
        self_node_id: t.self_node_id,
        dev_name:     t.dev_name.clone(),
        dc_key:       t.dc_key,
        qos: phenomenal_io::rdma::RdmaQos {
            traffic_class: t.qos.traffic_class,
            service_level: t.qos.service_level,
        },
        peers: t.peers.iter().map(|p| phenomenal_io::rdma::PeerEndpoint {
            node_id: p.node_id,
            gid:     p.gid,
            dct_num: p.dct_num,
            dc_key:  p.dc_key,
        }).collect(),
        bulk_buf_size: t.bulk_buf_size,
        bulk_pool_cap: t.bulk_pool_cap,
    }
}
