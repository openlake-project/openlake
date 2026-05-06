//! Distributed lock client (dsync-style voting).
//!
//! Implements the send side of the protocol that the per-node
//! `LockServer` (in `phenomenal_server`) speaks. `DsyncClient::acquire`
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
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use futures_util::future::join_all;
use phenomenal_io::LockPeer;

use crate::error::{StorageError, StorageResult};

/// Default lease applied to every grant. Long enough that a typical
/// PUT (small object, three-disk fan-out, single-digit milliseconds)
/// clears it with a wide margin; short enough that a crashed holder
/// only blocks others for a few seconds.
const DEFAULT_LEASE: Duration = Duration::from_secs(30);

/// Cap on the per-attempt backoff. The full retry budget is set by the
/// caller's `acquire` deadline.
const MAX_BACKOFF: Duration = Duration::from_millis(2_000);

/// Base of the jittered exponential backoff window. The first denied
/// round sleeps somewhere in [BASE, 2·BASE].
const BASE_BACKOFF: Duration = Duration::from_millis(50);

/// Rc-shared, runtime-local. One per Engine instance. The peer order
/// is irrelevant to correctness but must include every node in the
/// object's set so quorum math (`peers.len() / 2 + 1`) lines up.
pub struct DsyncClient {
    peers:  Vec<Rc<dyn LockPeer>>,
    quorum: usize,
}

impl DsyncClient {
    pub fn new(peers: Vec<Rc<dyn LockPeer>>) -> Self {
        let quorum = peers.len() / 2 + 1;
        Self { peers, quorum }
    }

    /// Lock-less client. `acquire` returns immediately with a guard
    /// that does nothing on drop. Used by engine unit tests where
    /// there is exactly one writer in flight; not for production.
    /// Production main.rs must build a real `DsyncClient` against the
    /// set's peer list.
    #[doc(hidden)]
    pub fn no_op() -> Self {
        Self { peers: Vec::new(), quorum: 0 }
    }

    /// Try to acquire `resource` within `timeout`. Returns a guard that
    /// will release the lock on drop. Returns `LockTimeout` if no
    /// majority is reached before the deadline.
    // todo: @arnav lock refreshers and auto release etc needed to prevent race
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
                return Ok(LockGuard {
                    resource: Some(resource.to_owned()),
                    uid:      Some(uid),
                    peers:    Some(self.peers.clone()),
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

/// RAII handle to a held lock. Drop fires a fire-and-forget release
/// across every peer the lock was acquired from. Must be dropped on a
/// thread with an active compio runtime.
pub struct LockGuard {
    resource: Option<String>,
    uid:      Option<String>,
    peers:    Option<Vec<Rc<dyn LockPeer>>>,
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        // Fields are taken out of `Option` so we can move them into the
        // spawned release task; if any are missing the guard already
        // released or never held the lock and there is nothing to do.
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

/// `[base, base * 2^min(attempt, 6)]` capped at `MAX_BACKOFF`. Range is
/// uniformly sampled with a process-local, time-mixed entropy source so
/// concurrent writers desynchronise instead of marching in lockstep.
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
    use phenomenal_io::IoResult;
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
}
