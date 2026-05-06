//! Per-node distributed lock server.
//!
//! Implements the receive side of the dsync-style voting protocol that
//! `phenomenal_storage::dsync` runs across peers. State is a single
//! `HashMap<resource, LockEntry>` guarded by a `std::sync::Mutex`; the
//! whole structure is shared across every runtime on this node so two
//! pinned threads never grant the same lock to two different writers.
//!
//! Three method calls form the protocol:
//!
//!   * `acquire(resource, uid, ttl)` — store `(uid, now + ttl)` if the
//!     resource is free or its current holder's lease has expired,
//!     return `true`. Otherwise return `false`.
//!   * `release(resource, uid)` — drop the entry if and only if the
//!     stored uid matches. Stale releases (from a writer whose lease
//!     already expired and was overwritten) are silently ignored.
//!   * `now()`-driven implicit expiry: a stale entry is replaced on the
//!     next `acquire`, so we never need a background sweeper.
//!
//! Concurrency: every method takes the mutex synchronously, mutates the
//! map, and returns. The mutex is never held across an `await`. Worst
//! case contention is when many runtimes serve lock RPCs simultaneously,
//! which is rare and bounded by the rate at which the cluster issues
//! writes.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use phenomenal_io::{IoResult, LockPeer};

#[derive(Debug)]
struct LockEntry {
    uid:    String,
    expiry: Instant,
}

/// Per-node lock state. Wrap in an `Arc` and share across runtimes.
pub struct LockServer {
    locks: Mutex<HashMap<String, LockEntry>>,
}

impl LockServer {
    pub fn new() -> Self {
        Self { locks: Mutex::new(HashMap::new()) }
    }

    /// Grant the lock to `uid` if free or expired; deny otherwise.
    /// Returns `true` on grant.
    pub fn acquire(&self, resource: &str, uid: &str, ttl: Duration) -> bool {
        let mut map = self.locks.lock().expect("lock map poisoned");
        let now = Instant::now();
        match map.get(resource) {
            Some(e) if e.expiry > now => false,
            _ => {
                map.insert(
                    resource.to_owned(),
                    LockEntry { uid: uid.to_owned(), expiry: now + ttl },
                );
                true
            }
        }
    }

    /// Release the lock on `resource` only if it is still held by `uid`.
    /// A mismatched UID means our lease has already expired and someone
    /// else now holds the lock — we must not clear their entry.
    pub fn release(&self, resource: &str, uid: &str) {
        let mut map = self.locks.lock().expect("lock map poisoned");
        if map.get(resource).is_some_and(|e| e.uid == uid) {
            map.remove(resource);
        }
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.locks.lock().unwrap().len()
    }
}

impl Default for LockServer {
    fn default() -> Self { Self::new() }
}

/// Adapter that lets `phenomenal_storage::DsyncClient` treat the local
/// `LockServer` as just another `LockPeer`. Both methods short-circuit
/// straight to the in-process map r no network, no `await` work
/// happens. Wrap the per-node `Arc<LockServer>` in this when building
/// the engine's peer list for the local node ID.
pub struct LocalLockPeer {
    inner: Arc<LockServer>,
}

impl LocalLockPeer {
    pub fn new(server: Arc<LockServer>) -> Self { Self { inner: server } }
}

#[async_trait::async_trait(?Send)]
impl LockPeer for LocalLockPeer {
    async fn lock_acquire(&self, resource: &str, uid: &str, ttl_ms: u32) -> IoResult<bool> {
        Ok(self.inner.acquire(resource, uid, Duration::from_millis(ttl_ms as u64)))
    }
    async fn lock_release(&self, resource: &str, uid: &str) -> IoResult<()> {
        self.inner.release(resource, uid);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acquire_grants_when_free_and_denies_when_held() {
        let s = LockServer::new();
        assert!( s.acquire("k", "u1", Duration::from_secs(60)));
        assert!(!s.acquire("k", "u2", Duration::from_secs(60)));
    }

    #[test]
    fn release_only_drops_matching_uid() {
        let s = LockServer::new();
        assert!(s.acquire("k", "u1", Duration::from_secs(60)));
        s.release("k", "u2");                       // wrong uid, no effect
        assert!(!s.acquire("k", "u3", Duration::from_secs(60)));
        s.release("k", "u1");                       // correct uid, drops
        assert!( s.acquire("k", "u3", Duration::from_secs(60)));
    }

    #[test]
    fn expired_entry_yields_to_new_writer() {
        let s = LockServer::new();
        assert!(s.acquire("k", "u1", Duration::from_millis(10)));
        std::thread::sleep(Duration::from_millis(20));
        // u1's lease is dead; u2 takes over without an explicit release.
        assert!(s.acquire("k", "u2", Duration::from_secs(60)));
    }

    #[test]
    fn release_after_takeover_is_a_noop() {
        let s = LockServer::new();
        assert!(s.acquire("k", "u1", Duration::from_millis(10)));
        std::thread::sleep(Duration::from_millis(20));
        assert!(s.acquire("k", "u2", Duration::from_secs(60)));
        // u1 wakes up late and tries to release — must not clear u2.
        s.release("k", "u1");
        assert!(!s.acquire("k", "u3", Duration::from_secs(60)));
    }

    #[test]
    fn distinct_resources_are_independent() {
        let s = LockServer::new();
        assert!(s.acquire("a", "u1", Duration::from_secs(60)));
        assert!(s.acquire("b", "u2", Duration::from_secs(60)));
        assert_eq!(s.len(), 2);
    }
}
