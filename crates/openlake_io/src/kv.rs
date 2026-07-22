use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

pub type KeyHash = [u8; 54];

const NIL: u32 = u32::MAX;

static SHM_SEQ: AtomicU64 = AtomicU64::new(0);

pub struct SlotPool {
    free: VecDeque<u32>,
    by_hash: HashMap<KeyHash, u32>,
    by_slot: HashMap<u32, KeyHash>,
    pending: HashMap<u32, Instant>,
    reserve_ttl: Duration,
    lru_prev: Vec<u32>,
    lru_next: Vec<u32>,
    lru_head: u32,
    lru_tail: u32,
}

impl SlotPool {
    pub fn new(slot_count: u32, reserve_ttl: Duration) -> Self {
        Self {
            free: (0..slot_count).collect(),
            by_hash: HashMap::with_capacity(slot_count as usize),
            by_slot: HashMap::with_capacity(slot_count as usize),
            pending: HashMap::new(),
            reserve_ttl,
            lru_prev: vec![NIL; slot_count as usize],
            lru_next: vec![NIL; slot_count as usize],
            lru_head: NIL,
            lru_tail: NIL,
        }
    }

    pub fn reserve(&mut self, count: u32) -> Vec<u32> {
        if self.free.len() < count as usize {
            self.reclaim_expired();
        }
        let mut out = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let Some(slot) = self.free.pop_front().or_else(|| self.evict_one()) else {
                break;
            };
            self.pending.insert(slot, Instant::now() + self.reserve_ttl);
            out.push(slot);
        }
        out
    }

    pub fn commit(&mut self, slot_idx: u32, key_hash: KeyHash) -> bool {
        if self.by_slot.get(&slot_idx) == Some(&key_hash) {
            self.pending.remove(&slot_idx);
            self.touch(slot_idx);
            return true;
        }
        if self.pending.remove(&slot_idx).is_none() {
            return false;
        }
        self.by_slot.insert(slot_idx, key_hash);
        if let Some(prev_slot) = self.by_hash.insert(key_hash, slot_idx) {
            self.by_slot.remove(&prev_slot);
            self.lru_detach(prev_slot);
            self.free.push_back(prev_slot);
        }
        self.lru_attach_tail(slot_idx);
        true
    }

    pub fn lookup(&mut self, key_hash: KeyHash) -> Option<u32> {
        let slot = self.by_hash.get(&key_hash).copied()?;
        self.touch(slot);
        Some(slot)
    }

    pub fn release(&mut self, slot_idx: u32) {
        if let Some(hash) = self.by_slot.remove(&slot_idx) {
            self.by_hash.remove(&hash);
            self.lru_detach(slot_idx);
            self.free.push_back(slot_idx);
        } else if self.pending.remove(&slot_idx).is_some() {
            self.free.push_back(slot_idx);
        }
    }

    pub fn clear(&mut self) {
        self.free = (0..self.lru_prev.len() as u32).collect();
        self.by_hash.clear();
        self.by_slot.clear();
        self.pending.clear();
        self.lru_prev.fill(NIL);
        self.lru_next.fill(NIL);
        self.lru_head = NIL;
        self.lru_tail = NIL;
    }

    pub fn commit_bytes(&mut self, entries: &[(u32, Vec<u8>)]) {
        for (slot, kh) in entries {
            if let Ok(k) = KeyHash::try_from(kh.as_slice()) {
                self.commit(*slot, k);
            }
        }
    }

    pub fn lookup_bytes(&mut self, keys: &[Vec<u8>]) -> Vec<Option<u32>> {
        keys.iter()
            .map(|k| {
                KeyHash::try_from(k.as_slice())
                    .ok()
                    .and_then(|kh| self.lookup(kh))
            })
            .collect()
    }

    #[cfg(test)]
    pub fn occupancy(&self) -> usize {
        self.by_hash.len()
    }

    fn reclaim_expired(&mut self) {
        let now = Instant::now();
        let free = &mut self.free;
        self.pending.retain(|&slot, deadline| {
            let live = now < *deadline;
            if !live {
                free.push_back(slot);
            }
            live
        });
    }

    fn evict_one(&mut self) -> Option<u32> {
        let slot = self.lru_head;
        if slot == NIL {
            return None;
        }
        let hash = self.by_slot.remove(&slot).expect("lru slot has a binding");
        self.by_hash.remove(&hash);
        self.lru_detach(slot);
        Some(slot)
    }

    fn touch(&mut self, slot: u32) {
        self.lru_detach(slot);
        self.lru_attach_tail(slot);
    }

    fn lru_attach_tail(&mut self, slot: u32) {
        self.lru_prev[slot as usize] = self.lru_tail;
        self.lru_next[slot as usize] = NIL;
        if self.lru_tail != NIL {
            self.lru_next[self.lru_tail as usize] = slot;
        } else {
            self.lru_head = slot;
        }
        self.lru_tail = slot;
    }

    fn lru_detach(&mut self, slot: u32) {
        if self.lru_prev[slot as usize] == NIL && self.lru_head != slot {
            return;
        }
        let (p, n) = (self.lru_prev[slot as usize], self.lru_next[slot as usize]);
        if p != NIL {
            self.lru_next[p as usize] = n;
        } else {
            self.lru_head = n;
        }
        if n != NIL {
            self.lru_prev[n as usize] = p;
        } else {
            self.lru_tail = p;
        }
        self.lru_prev[slot as usize] = NIL;
        self.lru_next[slot as usize] = NIL;
    }
}

pub trait KvSlab {
    fn reserve(&self, count: u32) -> Vec<u32>;
    fn commit(&self, entries: &[(u32, Vec<u8>)]);
    fn lookup(&self, keys: &[Vec<u8>]) -> Vec<Option<u32>>;
    fn release(&self, slots: &[u32]);
    fn reset(&self);
    fn slot_bytes(&self) -> u32;
    fn slot_count(&self) -> u32;
    fn shm_name(&self) -> Option<&str>;
}

pub struct HostSlab {
    slots: RefCell<SlotPool>,
    base: *mut u8,
    name: String,
    slot_bytes: u32,
    slot_count: u32,
}

unsafe impl Send for HostSlab {}
unsafe impl Sync for HostSlab {}

impl HostSlab {
    pub fn new(slot_bytes: u32, slot_count: u32, reserve_ttl: Duration) -> std::io::Result<Self> {
        let name = format!(
            "/openlake_kv_{}_{}",
            std::process::id(),
            SHM_SEQ.fetch_add(1, Ordering::Relaxed)
        );
        let base = crate::shm::create(&name, slot_bytes as usize * slot_count as usize)?;
        Ok(Self {
            slots: RefCell::new(SlotPool::new(slot_count, reserve_ttl)),
            base,
            name,
            slot_bytes,
            slot_count,
        })
    }
}

impl KvSlab for HostSlab {
    fn reserve(&self, count: u32) -> Vec<u32> {
        self.slots.borrow_mut().reserve(count)
    }
    fn commit(&self, entries: &[(u32, Vec<u8>)]) {
        self.slots.borrow_mut().commit_bytes(entries)
    }
    fn lookup(&self, keys: &[Vec<u8>]) -> Vec<Option<u32>> {
        self.slots.borrow_mut().lookup_bytes(keys)
    }
    fn release(&self, slots: &[u32]) {
        let mut pool = self.slots.borrow_mut();
        for &s in slots {
            pool.release(s);
        }
    }
    fn reset(&self) {
        self.slots.borrow_mut().clear();
    }
    fn slot_bytes(&self) -> u32 {
        self.slot_bytes
    }
    fn slot_count(&self) -> u32 {
        self.slot_count
    }
    fn shm_name(&self) -> Option<&str> {
        Some(&self.name)
    }
}

impl Drop for HostSlab {
    fn drop(&mut self) {
        crate::shm::unmap(
            self.base,
            self.slot_bytes as usize * self.slot_count as usize,
        );
        crate::shm::unlink(&self.name);
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum KvRequest {
    Attach { slot_bytes: u32 },
    Reserve { count: u32 },
    Commit { entries: Vec<(u32, Vec<u8>)> },
    Lookup { keys: Vec<Vec<u8>> },
    Release { slots: Vec<u32> },
    Reset,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum KvResponse {
    Attached {
        shm_name: String,
        slot_bytes: u32,
        slot_count: u32,
    },
    Reserved {
        slots: Vec<u32>,
    },
    Looked {
        slots: Vec<Option<u32>>,
    },
    Ok,
    Err(String),
}

pub fn serve_tcp(slab: &dyn KvSlab, req: KvRequest) -> KvResponse {
    match req {
        KvRequest::Attach { .. } => match slab.shm_name() {
            Some(name) => KvResponse::Attached {
                shm_name: name.to_string(),
                slot_bytes: slab.slot_bytes(),
                slot_count: slab.slot_count(),
            },
            None => KvResponse::Err("slab is not shm-backed".into()),
        },
        KvRequest::Reserve { count } => KvResponse::Reserved {
            slots: slab.reserve(count),
        },
        KvRequest::Commit { entries } => {
            slab.commit(&entries);
            KvResponse::Ok
        }
        KvRequest::Lookup { keys } => KvResponse::Looked {
            slots: slab.lookup(&keys),
        },
        KvRequest::Release { slots } => {
            slab.release(&slots);
            KvResponse::Ok
        }
        KvRequest::Reset => {
            slab.reset();
            KvResponse::Ok
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{HostSlab, KeyHash, KvSlab, SlotPool, NIL};
    use std::time::Duration;

    fn k(b: u8) -> KeyHash {
        [b; 54]
    }

    fn new_pool(n: u32) -> SlotPool {
        SlotPool::new(n, Duration::from_secs(60))
    }

    #[test]
    fn reserve_yields_distinct_slots_until_capacity() {
        let mut pool = new_pool(4);
        assert_eq!(pool.reserve(3), vec![0, 1, 2]);
        assert_eq!(pool.reserve(2), vec![3]);
    }

    #[test]
    fn commit_then_lookup_round_trips() {
        let mut pool = new_pool(8);
        let slots = pool.reserve(3);
        pool.commit(slots[0], k(0xAA));
        pool.commit(slots[1], k(0xCC));
        assert_eq!(pool.lookup(k(0xAA)), Some(slots[0]));
        assert_eq!(pool.lookup(k(0xCC)), Some(slots[1]));
        assert_eq!(pool.lookup(k(0xDE)), None);
    }

    #[test]
    fn release_returns_slot_to_free_list() {
        let mut pool = new_pool(2);
        let slots = pool.reserve(2);
        pool.commit(slots[0], k(1));
        pool.release(slots[0]);
        assert_eq!(pool.lookup(k(1)), None);
        assert_eq!(pool.reserve(1), vec![slots[0]]);
    }

    #[test]
    fn eviction_takes_least_recently_used() {
        let mut pool = new_pool(2);
        let s0 = pool.reserve(1)[0];
        pool.commit(s0, k(1));
        let s1 = pool.reserve(1)[0];
        pool.commit(s1, k(2));
        assert_eq!(pool.reserve(1), vec![s0]);
        assert_eq!(pool.lookup(k(1)), None);
        assert_eq!(pool.lookup(k(2)), Some(s1));
    }

    #[test]
    fn lookup_touch_protects_hot_key_from_eviction() {
        let mut pool = new_pool(2);
        let s0 = pool.reserve(1)[0];
        pool.commit(s0, k(1));
        let s1 = pool.reserve(1)[0];
        pool.commit(s1, k(2));
        assert_eq!(pool.lookup(k(1)), Some(s0));
        assert_eq!(pool.reserve(1), vec![s1]);
        assert_eq!(pool.lookup(k(2)), None);
    }

    #[test]
    fn commit_without_reservation_is_dropped() {
        let mut pool = SlotPool::new(4, Duration::from_secs(60));
        pool.commit(2, k(7));
        pool.commit(9999, k(8));
        assert_eq!(pool.lookup(k(7)), None);
        let mut granted = pool.reserve(4);
        granted.sort_unstable();
        assert_eq!(granted, vec![0, 1, 2, 3]);
    }

    #[test]
    fn expired_reservations_are_reclaimed() {
        let mut pool = SlotPool::new(2, Duration::ZERO);
        let first = pool.reserve(2);
        let mut second = pool.reserve(2);
        second.sort_unstable();
        assert_eq!(second, first);
    }

    #[test]
    fn structure_holds_under_op_storm() {
        use std::collections::HashSet;
        let n = 48u32;
        let mut pool = SlotPool::new(n, Duration::from_secs(60));
        let mut rng = 0x243F_6A88_85A3_08D3u64;
        let mut rand = move |m: u64| {
            rng = rng
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (rng >> 33) % m
        };
        let mut granted: Vec<u32> = Vec::new();
        for i in 0..300_000u64 {
            match rand(12) {
                0..=3 => granted.extend(pool.reserve(rand(4) as u32 + 1)),
                4..=6 if !granted.is_empty() => {
                    let s = granted.swap_remove(rand(granted.len() as u64) as usize);
                    pool.commit(s, k(rand(32) as u8));
                }
                7 => {
                    pool.commit(rand(n as u64 + 20) as u32, k(rand(32) as u8));
                }
                8..=9 => pool.release(rand(n as u64 + 20) as u32),
                _ => {
                    pool.lookup(k(rand(32) as u8));
                }
            }
            if i % 251 == 0 {
                let free: HashSet<u32> = pool.free.iter().copied().collect();
                assert_eq!(free.len(), pool.free.len());
                assert_eq!(
                    free.len() + pool.pending.len() + pool.by_slot.len(),
                    n as usize
                );
                assert_eq!(pool.by_hash.len(), pool.by_slot.len());
                let mut walked = 0;
                let mut cur = pool.lru_head;
                while cur != NIL {
                    assert!(pool.by_slot.contains_key(&cur));
                    walked += 1;
                    assert!(walked <= n);
                    cur = pool.lru_next[cur as usize];
                }
                assert_eq!(walked as usize, pool.by_slot.len());
            }
        }
    }

    #[test]
    fn host_slab_shm_backed_control_plane() {
        let s = HostSlab::new(4096, 8, Duration::from_secs(60)).unwrap();
        assert!(s.shm_name().is_some());
        assert_eq!(s.slot_count(), 8);
        assert_eq!(s.slot_bytes(), 4096);
        let key = vec![7u8; 54];
        let slot = s.reserve(1)[0];
        s.commit(&[(slot, key.clone())]);
        assert_eq!(s.lookup(std::slice::from_ref(&key))[0], Some(slot));
        s.reset();
        assert!(s.lookup(&[key])[0].is_none());
    }
}
