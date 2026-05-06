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
mod tls_material;

use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;
use std::thread;

use anyhow::Context;
use clap::Parser;

use compio::tls::{TlsAcceptor, TlsConnector};
use phenomenal_io::{LocalFsBackend, LockPeer, PeerConn, RemoteBackend, StorageBackend};
use phenomenal_storage::{ClusterConfig, DiskAddr, DsyncClient, Engine};

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

    let mut handles = Vec::with_capacity(num_runtimes);
    for (runtime_id, cpu) in cpus.into_iter().enumerate() {
        let cfg         = cfg.clone();
        let done_tx     = done_tx.clone();
        let lock_server = lock_server.clone();
        let tls         = tls.clone();
        let handle      = thread::Builder::new()
            .name(format!("runtime-{runtime_id}"))
            .spawn(move || {
                let result = (|| -> anyhow::Result<()> {
                    bind_cpu(cpu)?;
                    let rt = create_runtime()?;
                    rt.block_on(run_runtime(runtime_id, cfg, lock_server, tls))
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
        .coop_taskrun(true)
        .taskrun_flag(true);

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
    runtime_id:  usize,
    cfg:         Arc<config::Config>,
    lock_server: Arc<LockServer>,
    tls:         TlsMaterial,
) -> anyhow::Result<()> {
    // Extract the three optional handles from the shared TLS material.
    // Wrap each in `Rc` for runtime-local sharing — `TlsAcceptor` /
    // `TlsConnector` are themselves cheap (`Arc<*Config>` inside) but
    // `Rc` keeps the shared pointer in single-threaded territory after
    // this point, so per-connection refcount bumps are non-atomic.
    let s3_acceptor:   Option<Rc<TlsAcceptor>>  = tls.s3_acceptor()  .map(Rc::new);
    let rpc_acceptor:  Option<Rc<TlsAcceptor>>  = tls.rpc_acceptor() .map(Rc::new);
    let rpc_connector: Option<Rc<TlsConnector>> = tls.rpc_connector().map(Rc::new);

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

    // Build storage backends keyed by `DiskAddr`, plus a per-peer
    // `PeerConn` so all `RemoteBackend` instances targeting the
    // same peer share one TCP/TLS connection pool. Lock peers stay
    // node-scoped: one entry per node, ordered by `cfg.nodes`.
    let mut backends:   std::collections::HashMap<DiskAddr, Rc<dyn StorageBackend>> =
        std::collections::HashMap::with_capacity(cfg.nodes.iter().map(|n| n.disk_count as usize).sum());
    let mut lock_peers: Vec<Rc<dyn LockPeer>> = Vec::with_capacity(cfg.nodes.len());
    let local_lock_peer: Rc<dyn LockPeer> =
        Rc::new(LocalLockPeer::new(lock_server.clone()));

    for n in &cfg.nodes {
        if n.id == cfg.self_id {
            // Local node — register every local disk.
            for (idx, disk_be) in local_disks.iter().enumerate() {
                backends.insert(
                    DiskAddr { node_id: n.id, disk_idx: idx as u16 },
                    disk_be.clone(),
                );
            }
            lock_peers.push(local_lock_peer.clone());
        } else {
            // Peer node — one shared `PeerConn`, then one
            // `RemoteBackend` per disk on that peer. The same
            // `PeerConn` Rc threads through every disk_idx, so all
            // disks on this peer share one TCP/TLS connection pool.
            //
            // `server_name` for rustls is the peer's IP literal —
            // the cluster CA's leaf certs must include this IP in
            // their SubjectAltName for verification to pass.
            let peer = match &rpc_connector {
                Some(connector) => Rc::new(PeerConn::with_tls(
                    n.rpc_addr,
                    n.rpc_addr.ip().to_string(),
                    connector.clone(),
                )),
                None => Rc::new(PeerConn::new(n.rpc_addr)),
            };
            for disk_idx in 0..n.disk_count {
                let rb = Rc::new(RemoteBackend::new(peer.clone(), disk_idx));
                backends.insert(
                    DiskAddr { node_id: n.id, disk_idx },
                    rb as Rc<dyn StorageBackend>,
                );
            }
            // Lock plane: any RemoteBackend on this peer talks to
            // the same LockServer, so we only need one. Pick
            // disk_idx=0; its disk_idx field is unused by the
            // lock-plane RPCs (they don't carry disk_idx).
            let lock_rb = Rc::new(RemoteBackend::new(peer, 0));
            lock_peers.push(lock_rb as Rc<dyn LockPeer>);
        }
    }

    let cluster = ClusterConfig {
        nodes:                cfg.nodes.clone(),
        set_drive_count:      cfg.set_drive_count,
        default_parity_count: cfg.default_parity_count,
    };
    let dsync  = Rc::new(DsyncClient::new(lock_peers));
    let engine = Rc::new(Engine::new(cluster, backends, dsync, cfg.self_id));

    // Per-runtime SigV4 verifier. Shared as an `Rc` so every connection
    // task on this runtime can look up secrets without a lock or a
    // cross core cache miss.
    let auth_state = Rc::new(auth::AuthState::new(
        cfg.region.clone(),
        &cfg.credentials,
    ));

    // SO_REUSEPORT lets every runtime bind the same (ip, port). The
    // kernel's reuseport hash routes each incoming connection to
    // exactly one runtime's accept queue based on the 4-tuple.
    let s3_listener  = s3::listener::bind_reuseport(cfg.s3_addr)
        .with_context(|| format!("runtime {runtime_id}: bind s3 on {}", cfg.s3_addr))?;
    let rpc_listener = rpc_server::bind_reuseport(cfg.rpc_addr)
        .with_context(|| format!("runtime {runtime_id}: bind rpc on {}", cfg.rpc_addr))?;

    tracing::info!(runtime_id, s3 = %cfg.s3_addr, rpc = %cfg.rpc_addr, "runtime serving");

    // Both accept loops live on this runtime's scheduler as detached
    // tasks. Each spawns per-connection tasks into the same runtime.
    // All connection work stays on this runtime's thread / core / ring.
    //
    // The RPC server gets a single `Rc<Vec<Rc<dyn StorageBackend>>>`
    // — one entry per local disk, indexed by `disk_idx`. Cloning
    // into the spawned task is one Rc bump.
    let rpc_disks    = Rc::new(local_disks.clone());
    let rpc_locks    = lock_server.clone();
    let rpc_acceptor = rpc_acceptor.clone();
    let rpc_task = compio::runtime::spawn(async move {
        if let Err(e) = rpc_server::serve(rpc_listener, rpc_disks, rpc_locks, rpc_acceptor).await {
            tracing::error!(runtime_id, "rpc serve error: {e:#}");
        }
    });

    // S3 frontend. Plaintext and TLS both flow through axum + cyper-
    // axum, with the TLS path going through the `TlsTcpListener`
    // wrapper that completes the rustls handshake during `accept()`
    // before yielding the connection to hyper.
    let s3_engine     = engine.clone();
    let s3_auth       = auth_state.clone();
    let s3_acceptor   = s3_acceptor.clone();
    let s3_task = compio::runtime::spawn(async move {
        let app_state = s3::state::AppState::new(s3_engine, s3_auth);
        let _ = s3::app::serve(s3_listener, app_state, s3_acceptor).await;
        tracing::error!(runtime_id, "s3 serve loop exited");
    });

    // Both loop forever; awaiting either just parks this task.
    let _ = s3_task.await;
    let _ = rpc_task.await;
    Ok(())
}
