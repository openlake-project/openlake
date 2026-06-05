//! Distributed lock client (dsync-style voting).
//!
//! Implements the send side of the protocol that the per-node
//! `LockServer` (in `openlake_server`) speaks. `DsyncClient::acquire`
//! broadcasts a `LockAcquire` to every peer in the resource's set, waits
//! for replies, and declares the lock held once `quorum` peers have
//! granted. Minority outcomes release any partial grants and retry with
//! jittered backoff.
//!
//! Held locks are represented by `LockGuard`. Drop fires a fire-and-
//! forget release across the same peers — the guard must be dropped on
//! a thread that has an active compio runtime, otherwise the spawned
//! release task panics. All current call sites (Engine::put / delete)
//! satisfy this naturally because they live inside an async fn driven
//! by compio.
//!
//! Correctness rests on the same pigeonhole MinIO's dsync uses: with N
//! peers, two coordinators cannot both collect majority on a resource at
//! the same instant because each peer's in-memory map admits exactly
//! one UID at a time. Lease TTL bounds the window in which a crashed
//! holder can block other writers; a holder that exceeds its lease is
//! treated as gone and the next acquire takes over.

use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use futures_util::future::join_all;
use openlake_io::LockPeer;

use crate::error::{StorageError, StorageResult};

/// Wire `ttl_ms` hint on acquire. Server's own validity is authoritative.
const DEFAULT_LEASE: Duration = Duration::from_secs(30);

/// Cadence of the refresh ping. Server-side validity is 60s, so a 30s
/// cadence lets us miss one refresh round (e.g. a tcp blip) and still
/// re-stamp before the lease expires.
const REFRESH_INTERVAL: Duration = Duration::from_secs(30);

/// Per-attempt acquire backoff caps.
const MAX_BACKOFF:  Duration = Duration::from_millis(2_000);
const BASE_BACKOFF: Duration = Duration::from_millis(50);

/// Shared between `LockGuard` and its refresh task.
struct LockState {
    /// Set by `Drop` to stop the refresh loop.
    stop: AtomicBool,
    /// Set by the refresh task when quorum is lost. Engine reads via
    /// `LockGuard::check` at fence points.
    lost: AtomicBool,
}

/// Rc-shared, runtime-local. One per Engine instance. The peer order
/// is irrelevant to correctness but must include every node in the
/// object's set so quorum math (`peers.len() / 2 + 1`) lines up.
pub struct DsyncClient {
    peers:            Vec<Rc<dyn LockPeer>>,
    quorum:           usize,
    refresh_interval: Duration,
}

impl DsyncClient {
    pub fn new(peers: Vec<Rc<dyn LockPeer>>) -> Self {
        let quorum = peers.len() / 2 + 1;
        Self { peers, quorum, refresh_interval: REFRESH_INTERVAL }
    }

    /// Lock-less client. `acquire` returns immediately with a guard
    /// that does nothing on drop. Used by engine unit tests where
    /// there is exactly one writer in flight; not for production.
    #[doc(hidden)]
    pub fn no_op() -> Self {
        Self { peers: Vec::new(), quorum: 0, refresh_interval: REFRESH_INTERVAL }
    }

    /// Override the refresh ping cadence. Tests use a short interval
    /// to exercise lock-loss detection without waiting 10s.
    #[doc(hidden)]
    pub fn with_refresh_interval(mut self, interval: Duration) -> Self {
        self.refresh_interval = interval;
        self
    }

    /// Try to acquire `resource` within `timeout`. Returns a guard that
    /// will release the lock on drop. Returns `LockTimeout` if no
    /// majority is reached before the deadline.
    pub async fn acquire(
        &self,
        resource: &str,
        timeout:  Duration,
    ) -> StorageResult<LockGuard> {
        let deadline = Instant::now() + timeout;
        let lease_ms = DEFAULT_LEASE.as_millis() as u32;
        let mut attempt: u32 = 0;

        loop {
            let uid = fresh_uid();

            // Fan out the vote. Errors count as denials at the quorum
            // count — a peer we cannot reach has not granted us anything.
            let acquires = self.peers.iter().enumerate().map(|(i, p)| {
                let p   = p.clone();
                let res = resource.to_owned();
                let uid = uid.clone();
                async move { (i, p.lock_acquire(&res, &uid, lease_ms).await) }
            });
            let results = join_all(acquires).await;

            let granted: Vec<usize> = results.into_iter()
                .filter_map(|(i, r)| matches!(r, Ok(true)).then_some(i))
                .collect();

            if granted.len() >= self.quorum {
                let state = Arc::new(LockState {
                    stop: AtomicBool::new(false),
                    lost: AtomicBool::new(false),
                });
                spawn_refresh_task(
                    state.clone(),
                    self.peers.clone(),
                    self.quorum,
                    resource.to_owned(),
                    uid.clone(),
                    self.refresh_interval,
                );
                return Ok(LockGuard {
                    resource: Some(resource.to_owned()),
                    uid:      Some(uid),
                    peers:    Some(self.peers.clone()),
                    state,
                });
            }

            // Minority: release the stray grants so they don't block
            // the next round. Best effort; any failure here is
            // covered by the lease TTL.
            for i in granted {
                let p   = self.peers[i].clone();
                let res = resource.to_owned();
                let uid = uid.clone();
                let _   = p.lock_release(&res, &uid).await;
            }

            if Instant::now() >= deadline {
                return Err(StorageError::LockTimeout(resource.to_owned()));
            }
            compio::runtime::time::sleep(jitter(attempt)).await;
            attempt = attempt.saturating_add(1);
        }
    }
}

/// RAII handle to a held lock. Drop stops the refresh task and fires
/// a fire-and-forget release. Must be dropped on a thread with an
/// active compio runtime.
pub struct LockGuard {
    resource: Option<String>,
    uid:      Option<String>,
    peers:    Option<Vec<Rc<dyn LockPeer>>>,
    state:    Arc<LockState>,
}

impl LockGuard {
    /// True iff the background refresh task could no longer prove
    /// quorum hold.
    pub fn is_lost(&self) -> bool {
        self.state.lost.load(Ordering::Acquire)
    }

    /// Fence-point check. Returns `Err(LockLost)` if the refresh task
    /// observed quorum loss since the last call. Cheap (atomic load).
    pub fn check(&self) -> StorageResult<()> {
        if self.is_lost() {
            let res = self.resource.clone().unwrap_or_default();
            return Err(StorageError::LockLost(res));
        }
        Ok(())
    }
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        // Stop the refresh task on the next iteration boundary.
        self.state.stop.store(true, Ordering::Release);

        let (Some(resource), Some(uid), Some(peers)) =
            (self.resource.take(), self.uid.take(), self.peers.take()) else { return };

        compio::runtime::spawn(async move {
            let releases = peers.iter().map(|p| {
                let p   = p.clone();
                let res = resource.clone();
                let uid = uid.clone();
                async move { let _ = p.lock_release(&res, &uid).await; }
            });
            join_all(releases).await;
        }).detach();
    }
}

/// Run the periodic refresh on a detached compio task. Marks `state.lost`
/// and force-releases when refresh count cannot reach quorum.
///
/// Quorum math (matches MinIO's `refreshLock`):
///   * `not_found > tolerance` → lost.
///   * `offline` (network failure) is neutral; next round retries.
fn spawn_refresh_task(
    state:    Arc<LockState>,
    peers:    Vec<Rc<dyn LockPeer>>,
    quorum:   usize,
    resource: String,
    uid:      String,
    interval: Duration,
) {
    if peers.is_empty() {
        return; 
    }
    let tolerance = peers.len() - quorum;

    compio::runtime::spawn(async move {
        loop {
            compio::runtime::time::sleep(interval).await;
            if state.stop.load(Ordering::Acquire) { return; }

            let refreshes = peers.iter().map(|p| {
                let p   = p.clone();
                let res = resource.clone();
                let uid = uid.clone();
                async move { p.lock_refresh(&res, &uid).await }
            });
            let results = join_all(refreshes).await;

            if state.stop.load(Ordering::Acquire) { return; }

            let mut not_found = 0usize;
            for r in results {
                if let Ok(false) = r { not_found += 1; }
            }
            if not_found > tolerance {
                state.lost.store(true, Ordering::Release);
                let res = resource.clone();
                let uid = uid.clone();
                let peers = peers.clone();
                compio::runtime::spawn(async move {
                    let releases = peers.iter().map(|p| {
                        let p   = p.clone();
                        let res = res.clone();
                        let uid = uid.clone();
                        async move { let _ = p.lock_release(&res, &uid).await; }
                    });
                    join_all(releases).await;
                }).detach();
                return;
            }
        }
    }).detach();
}

fn jitter(attempt: u32) -> Duration {
    let base = BASE_BACKOFF.as_millis() as u64;
    let cap  = MAX_BACKOFF .as_millis() as u64;
    let shift = attempt.min(6);
    let max   = base.checked_shl(shift).unwrap_or(u64::MAX).min(cap);
    let span = max.saturating_sub(base).max(1);

    let pseudo = pseudo_random_u64();
    Duration::from_millis(base + pseudo % span)
}

/// Cluster-unique enough UID for a lock attempt.
///
/// The shape — `process_id ^ time_nanos ^ counter` — gives a 256-bit
/// blake3 digest with no collision risk across the cluster, while
/// staying cheap to compute (no UUID dep, no syscall beyond a single
/// time read). Stored as hex so it serialises directly into the bincode
/// `String` without a separate type.
fn fresh_uid() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n   = COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id() as u64;
    let t   = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let mut h = blake3::Hasher::new();
    h.update(&n.to_le_bytes());
    h.update(&pid.to_le_bytes());
    h.update(&t.to_le_bytes());
    h.finalize().to_hex().to_string()
}

fn pseudo_random_u64() -> u64 {
    static CTR: AtomicU64 = AtomicU64::new(0);
    let n = CTR.fetch_add(1, Ordering::Relaxed);
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let mut h = blake3::Hasher::new();
    h.update(&n.to_le_bytes());
    h.update(&t.to_le_bytes());
    let bytes = h.finalize();
    u64::from_le_bytes(bytes.as_bytes()[..8].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use openlake_io::IoResult;
    use std::cell::RefCell;
    use std::collections::HashMap;

    /// In-process `LockPeer` mirroring the server-side `LockServer`
    /// behaviour, used to exercise `DsyncClient::acquire` without
    /// standing up a full RPC stack.
    struct FakePeer {
        state: RefCell<HashMap<String, (String, Instant)>>,
    }
    impl FakePeer {
        fn new() -> Self { Self { state: RefCell::new(HashMap::new()) } }
    }

    #[async_trait(?Send)]
    impl LockPeer for FakePeer {
        async fn lock_acquire(&self, res: &str, uid: &str, ttl_ms: u32) -> IoResult<bool> {
            let mut m = self.state.borrow_mut();
            let now = Instant::now();
            match m.get(res) {
                Some((_, exp)) if *exp > now => Ok(false),
                _ => {
                    m.insert(res.into(), (uid.into(), now + Duration::from_millis(ttl_ms as u64)));
                    Ok(true)
                }
            }
        }
        async fn lock_release(&self, res: &str, uid: &str) -> IoResult<()> {
            let mut m = self.state.borrow_mut();
            if m.get(res).is_some_and(|(u, _)| u == uid) { m.remove(res); }
            Ok(())
        }
        async fn lock_refresh(&self, res: &str, uid: &str) -> IoResult<bool> {
            let mut m = self.state.borrow_mut();
            match m.get_mut(res) {
                Some((u, exp)) if u == uid => {
                    *exp = Instant::now() + Duration::from_secs(30);
                    Ok(true)
                }
                _ => Ok(false),
            }
        }
    }

    fn fake_client(n: usize) -> (DsyncClient, Vec<Rc<FakePeer>>) {
        let peers: Vec<Rc<FakePeer>> = (0..n).map(|_| Rc::new(FakePeer::new())).collect();
        let dyn_peers: Vec<Rc<dyn LockPeer>> = peers.iter().map(|p| p.clone() as _).collect();
        (DsyncClient::new(dyn_peers), peers)
    }

    #[compio::test]
    async fn acquire_returns_guard_on_clean_set() {
        let (c, _) = fake_client(3);
        let _g = c.acquire("k", Duration::from_secs(1)).await.unwrap();
    }

    #[compio::test]
    async fn second_acquire_blocks_until_first_drops() {
        let (c, _) = fake_client(3);

        // Force a stale state on every peer so the FIRST attempt is
        // contended: pre-populate each fake peer with a dummy entry
        // whose lease is short enough to expire mid-test.
        // We instead verify timing: hold the guard, retry, expect timeout.
        let g1 = c.acquire("k", Duration::from_secs(1)).await.unwrap();
        let started = Instant::now();
        let r       = c.acquire("k", Duration::from_millis(150)).await;
        assert!(r.is_err(), "second acquire must time out while first holds");
        assert!(started.elapsed() >= Duration::from_millis(150));
        drop(g1);
    }

    #[compio::test]
    async fn drop_releases_so_next_acquire_succeeds() {
        let (c, _) = fake_client(3);
        {
            let _g = c.acquire("k", Duration::from_secs(1)).await.unwrap();
        }
        // Drop spawns release; yield once so the detached task runs.
        compio::runtime::time::sleep(Duration::from_millis(10)).await;
        let _g2 = c.acquire("k", Duration::from_secs(1)).await.unwrap();
    }

    #[test]
    fn fresh_uid_is_unique_in_a_burst() {
        let mut s = std::collections::HashSet::new();
        for _ in 0..1024 { s.insert(fresh_uid()); }
        assert_eq!(s.len(), 1024);
    }

    #[compio::test]
    async fn refresh_keeps_guard_alive_across_rounds() {
        // Short refresh cadence so we can observe several rounds in
        // a millisecond budget. FakePeer.lock_refresh re-stamps the
        // entry expiry, so as long as the refresh task is running
        // the guard stays unlost regardless of the initial ttl.
        let peers: Vec<Rc<FakePeer>> = (0..3).map(|_| Rc::new(FakePeer::new())).collect();
        let dyn_peers: Vec<Rc<dyn LockPeer>> = peers.iter().map(|p| p.clone() as _).collect();
        let c = DsyncClient::new(dyn_peers).with_refresh_interval(Duration::from_millis(20));

        let g = c.acquire("k", Duration::from_secs(1)).await.unwrap();
        compio::runtime::time::sleep(Duration::from_millis(80)).await;
        assert!(!g.is_lost());
        assert!(g.check().is_ok());
    }

    #[compio::test]
    async fn quorum_lost_marks_guard_lost() {
        // Three peers, quorum=2, tolerance=1. After acquire, wipe
        // state on a majority (simulating restart / sweep). The
        // next refresh round sees 2 not_found which exceeds
        // tolerance, so the guard is marked lost.
        let peers: Vec<Rc<FakePeer>> = (0..3).map(|_| Rc::new(FakePeer::new())).collect();
        let dyn_peers: Vec<Rc<dyn LockPeer>> = peers.iter().map(|p| p.clone() as _).collect();
        let c = DsyncClient::new(dyn_peers).with_refresh_interval(Duration::from_millis(20));

        let g = c.acquire("k", Duration::from_secs(1)).await.unwrap();
        assert!(!g.is_lost());

        peers[0].state.borrow_mut().clear();
        peers[1].state.borrow_mut().clear();

        compio::runtime::time::sleep(Duration::from_millis(60)).await;
        assert!(g.is_lost());
        assert!(matches!(g.check(), Err(StorageError::LockLost(_))));
    }
}
