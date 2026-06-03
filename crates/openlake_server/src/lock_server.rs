//! Per node distributed lock server.
//!
//! Receive side of the dsync voting protocol. One `HashMap<resource,
//! LockEntry>` under a `std::sync::Mutex`, shared across all runtimes
//! on this node so two pinned threads never grant the same resource.
//!
//! Each entry carries `last_refresh: Instant`. Liveness is `now -
//! last_refresh < validity`; the holder re-stamps via `refresh` every
//! ~10s. Stale entries are reclaimed inline on the next `acquire` for
//! that resource, or in the background by `run_sweeper` for resources
//! nobody re-acquires. Matches MinIO's `lockValidityDuration` model.
//!
//! Defaults: validity 60s, sweep interval 60s. The mutex is never
//! held across an `await`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use openlake_io::{IoResult, LockPeer};

/// Validity window for a held entry. MinIO's `lockValidityDuration`.
pub const DEFAULT_VALIDITY:       Duration = Duration::from_secs(60);
/// Background sweep cadence. MinIO's `lockMaintenanceInterval`.
pub const DEFAULT_SWEEP_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Debug)]
struct LockEntry {
    uid:          String,
    last_refresh: Instant,
}

/// Per-node lock state. Wrap in an `Arc` and share across runtimes.
pub struct LockServer {
    locks:    Mutex<HashMap<String, LockEntry>>,
    validity: Duration,
}

impl LockServer {
    pub fn new() -> Self { Self::with_validity(DEFAULT_VALIDITY) }

    pub fn with_validity(validity: Duration) -> Self {
        Self { locks: Mutex::new(HashMap::new()), validity }
    }

    /// Grant if free or existing entry is past validity. `_ttl_ms` is
    /// wire compat only; server's `validity` is the source of truth.
    pub fn acquire(&self, resource: &str, uid: &str, _ttl_ms: Duration) -> bool {
        let mut map = self.locks.lock().expect("lock map poisoned");
        let now = Instant::now();
        match map.get(resource) {
            Some(e) if now.saturating_duration_since(e.last_refresh) < self.validity => false,
            _ => {
                map.insert(resource.to_owned(), LockEntry { uid: uid.to_owned(), last_refresh: now });
                true
            }
        }
    }

    /// Stamp `last_refresh = now` iff the entry matches `uid`.
    pub fn refresh(&self, resource: &str, uid: &str) -> bool {
        let mut map = self.locks.lock().expect("lock map poisoned");
        match map.get_mut(resource) {
            Some(e) if e.uid == uid => { e.last_refresh = Instant::now(); true }
            _ => false,
        }
    }

    /// Drop entry iff `uid` matches. Stale releases are ignored.
    pub fn release(&self, resource: &str, uid: &str) {
        let mut map = self.locks.lock().expect("lock map poisoned");
        if map.get(resource).is_some_and(|e| e.uid == uid) {
            map.remove(resource);
        }
    }

    /// Drop all entries past validity. Returns count reclaimed.
    pub fn expire_old(&self) -> usize {
        let mut map = self.locks.lock().expect("lock map poisoned");
        let now = Instant::now();
        let validity = self.validity;
        let before = map.len();
        map.retain(|_, e| now.saturating_duration_since(e.last_refresh) < validity);
        before - map.len()
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize { self.locks.lock().unwrap().len() }
}

impl Default for LockServer {
    fn default() -> Self { Self::new() }
}

/// Sweeper loop. Spawn once per process. Cancel by dropping the task.
pub async fn run_sweeper(server: Arc<LockServer>, interval: Duration) {
    loop {
        compio::runtime::time::sleep(interval).await;
        let reclaimed = server.expire_old();
        if reclaimed > 0 {
            tracing::debug!(reclaimed, "lock_server: sweep reclaimed stale entries");
        }
    }
}

/// `LockPeer` adapter for the in-process `LockServer` (no network).
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
    async fn lock_refresh(&self, resource: &str, uid: &str) -> IoResult<bool> {
        Ok(self.inner.refresh(resource, uid))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tests use a short validity so we can age entries by sleeping
    // a few milliseconds instead of a full minute.
    fn short() -> LockServer {
        LockServer::with_validity(Duration::from_millis(30))
    }
    const NO_TTL: Duration = Duration::from_secs(60); // wire ttl is ignored

    #[test]
    fn acquire_grants_when_free_and_denies_when_held() {
        let s = LockServer::new();
        assert!( s.acquire("k", "u1", NO_TTL));
        assert!(!s.acquire("k", "u2", NO_TTL));
    }

    #[test]
    fn release_only_drops_matching_uid() {
        let s = LockServer::new();
        assert!(s.acquire("k", "u1", NO_TTL));
        s.release("k", "u2");                       // wrong uid, no effect
        assert!(!s.acquire("k", "u3", NO_TTL));
        s.release("k", "u1");                       // correct uid, drops
        assert!( s.acquire("k", "u3", NO_TTL));
    }

    #[test]
    fn stale_entry_yields_to_new_writer_on_acquire() {
        let s = short();
        assert!(s.acquire("k", "u1", NO_TTL));
        std::thread::sleep(Duration::from_millis(50));
        // u1's entry is past validity; u2 takes over without an
        // explicit release and without waiting for the sweeper.
        assert!(s.acquire("k", "u2", NO_TTL));
    }

    #[test]
    fn release_after_takeover_is_a_noop() {
        let s = short();
        assert!(s.acquire("k", "u1", NO_TTL));
        std::thread::sleep(Duration::from_millis(50));
        assert!(s.acquire("k", "u2", NO_TTL));
        // u1 wakes up late and tries to release — must not clear u2.
        s.release("k", "u1");
        assert!(!s.acquire("k", "u3", NO_TTL));
    }

    #[test]
    fn distinct_resources_are_independent() {
        let s = LockServer::new();
        assert!(s.acquire("a", "u1", NO_TTL));
        assert!(s.acquire("b", "u2", NO_TTL));
        assert_eq!(s.len(), 2);
    }

    #[test]
    fn refresh_matches_uid_and_extends_lease() {
        let s = short();
        assert!(s.acquire("k", "u1", NO_TTL));
        // Mid lease refresh keeps the entry alive past what would
        // otherwise be expiry.
        std::thread::sleep(Duration::from_millis(20));
        assert!(s.refresh("k", "u1"));
        std::thread::sleep(Duration::from_millis(20));
        // 40 ms since acquire but only 20 ms since the last refresh,
        // so the entry is still live and u2 cannot take it.
        assert!(!s.acquire("k", "u2", NO_TTL));
    }

    #[test]
    fn refresh_rejects_wrong_uid() {
        let s = LockServer::new();
        assert!(s.acquire("k", "u1", NO_TTL));
        assert!(!s.refresh("k", "u2"));
        assert!( s.refresh("k", "u1"));
    }

    #[test]
    fn refresh_on_unknown_resource_returns_false() {
        let s = LockServer::new();
        assert!(!s.refresh("never-locked", "u1"));
    }

    #[test]
    fn expire_old_drops_stale_entries() {
        let s = short();
        assert!(s.acquire("a", "u1", NO_TTL));
        assert!(s.acquire("b", "u2", NO_TTL));
        std::thread::sleep(Duration::from_millis(50));
        // Without inline acquire pressure, the sweeper is what
        // reclaims memory for keys nobody re-acquires.
        assert_eq!(s.expire_old(), 2);
        assert_eq!(s.len(), 0);
    }

    #[test]
    fn expire_old_keeps_fresh_entries() {
        let s = short();
        assert!(s.acquire("a", "u1", NO_TTL));
        s.refresh("a", "u1");
        assert_eq!(s.expire_old(), 0);
        assert_eq!(s.len(), 1);
    }
}
