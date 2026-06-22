#![cfg(all(feature = "rdma", target_os = "linux"))]

use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::rc::Rc;

use openlake_io::rdma::wire::CommitEntry;
use openlake_io::rdma::{Buffers, IbDevice};

pub struct SlotPool {
    free: VecDeque<u32>,
    by_hash: HashMap<u64, u32>,
    by_slot: HashMap<u32, u64>,
    fifo: VecDeque<u64>,
}

impl SlotPool {
    pub fn new(slot_count: u32) -> Self {
        Self {
            free: (0..slot_count).collect(),
            by_hash: HashMap::with_capacity(slot_count as usize),
            by_slot: HashMap::with_capacity(slot_count as usize),
            fifo: VecDeque::with_capacity(slot_count as usize),
        }
    }

    pub fn reserve(&mut self, count: u32) -> Vec<u32> {
        let mut out = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let slot = match self.free.pop_front() {
                Some(s) => s,
                None => match self.evict_one() {
                    Some(s) => s,
                    None => break,
                },
            };
            out.push(slot);
        }
        out
    }

    pub fn commit(&mut self, slot_idx: u32, key_hash: u64) {
        if let Some(prev_hash) = self.by_slot.insert(slot_idx, key_hash) {
            self.by_hash.remove(&prev_hash);
        }
        if let Some(prev_slot) = self.by_hash.insert(key_hash, slot_idx) {
            if prev_slot != slot_idx {
                self.by_slot.remove(&prev_slot);
                self.free.push_back(prev_slot);
            }
        }
        self.fifo.push_back(key_hash);
    }

    pub fn lookup(&self, key_hash: u64) -> Option<u32> {
        self.by_hash.get(&key_hash).copied()
    }

    pub fn release(&mut self, slot_idx: u32) {
        if let Some(hash) = self.by_slot.remove(&slot_idx) {
            self.by_hash.remove(&hash);
        }
        self.free.push_back(slot_idx);
    }

    #[cfg(test)]
    pub fn occupancy(&self) -> usize {
        self.by_hash.len()
    }

    fn evict_one(&mut self) -> Option<u32> {
        loop {
            let candidate = self.fifo.pop_front()?;
            if let Some(slot) = self.by_hash.remove(&candidate) {
                self.by_slot.remove(&slot);
                return Some(slot);
            }
        }
    }
}

pub struct KvSlab {
    buffers: Buffers,
    slots: RefCell<SlotPool>,
}

impl KvSlab {
    pub fn new(dev: Rc<IbDevice>, slot_bytes: usize, slot_count: usize) -> std::io::Result<Self> {
        let buffers = Buffers::new(dev, slot_count, slot_bytes)?;
        Ok(Self {
            buffers,
            slots: RefCell::new(SlotPool::new(slot_count as u32)),
        })
    }

    pub fn slab_base(&self) -> u64 {
        self.buffers.slot_addr(0)
    }
    pub fn rkey(&self) -> u32 {
        self.buffers.rkey()
    }
    pub fn slot_bytes(&self) -> u32 {
        self.buffers.buf_size() as u32
    }

    pub fn reserve(&self, count: u32) -> Vec<u32> {
        self.slots.borrow_mut().reserve(count)
    }

    pub fn commit(&self, entries: &[CommitEntry]) {
        let mut slots = self.slots.borrow_mut();
        for e in entries {
            slots.commit(e.slot_idx, e.key_hash);
        }
    }

    pub fn lookup(&self, key_hashes: &[u64]) -> Vec<Option<u32>> {
        let slots = self.slots.borrow();
        key_hashes.iter().map(|&k| slots.lookup(k)).collect()
    }

    pub fn release(&self, slot_idxs: &[u32]) {
        let mut slots = self.slots.borrow_mut();
        for &slot in slot_idxs {
            slots.release(slot);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SlotPool;

    #[test]
    fn reserve_yields_distinct_slots_until_capacity() {
        let mut pool = SlotPool::new(4);
        let first = pool.reserve(3);
        assert_eq!(first, vec![0, 1, 2]);
        let second = pool.reserve(2);
        assert_eq!(second, vec![3]);
    }

    #[test]
    fn commit_then_lookup_round_trips() {
        let mut pool = SlotPool::new(8);
        let slots = pool.reserve(3);
        pool.commit(slots[0], 0xAA);
        pool.commit(slots[1], 0xCC);
        pool.commit(slots[2], 0xEE);
        assert_eq!(pool.lookup(0xAA), Some(slots[0]));
        assert_eq!(pool.lookup(0xCC), Some(slots[1]));
        assert_eq!(pool.lookup(0xEE), Some(slots[2]));
        assert_eq!(pool.lookup(0xDE), None);
    }

    #[test]
    fn release_returns_slot_to_free_list() {
        let mut pool = SlotPool::new(2);
        let slots = pool.reserve(2);
        pool.commit(slots[0], 1);
        pool.commit(slots[1], 2);
        pool.release(slots[0]);
        assert_eq!(pool.lookup(1), None);
        let reborrowed = pool.reserve(1);
        assert_eq!(reborrowed, vec![slots[0]]);
    }

    #[test]
    fn eviction_kicks_in_when_full() {
        let mut pool = SlotPool::new(2);
        let s0 = pool.reserve(1)[0];
        pool.commit(s0, 1);
        let s1 = pool.reserve(1)[0];
        pool.commit(s1, 2);
        assert_eq!(pool.occupancy(), 2);
        let s2 = pool.reserve(1);
        assert_eq!(s2, vec![s0]);
        assert_eq!(pool.lookup(1), None);
        assert_eq!(pool.lookup(2), Some(s1));
        pool.commit(s2[0], 3);
        assert_eq!(pool.lookup(3), Some(s2[0]));
    }

    #[test]
    fn commit_same_hash_to_different_slot_evicts_old_slot() {
        let mut pool = SlotPool::new(4);
        let slots = pool.reserve(2);
        pool.commit(slots[0], 7);
        assert_eq!(pool.lookup(7), Some(slots[0]));
        pool.commit(slots[1], 7);
        assert_eq!(pool.lookup(7), Some(slots[1]));
        assert_eq!(pool.occupancy(), 1);
        let drained = pool.reserve(3);
        assert!(drained.contains(&slots[0]));
        assert_eq!(drained.len(), 3);
    }

    #[test]
    fn eviction_skips_stale_fifo_entries() {
        let mut pool = SlotPool::new(2);
        let s0 = pool.reserve(1)[0];
        pool.commit(s0, 1);
        let s1 = pool.reserve(1)[0];
        pool.commit(s1, 2);
        pool.release(s0);
        let s2 = pool.reserve(1)[0];
        assert_eq!(s2, s0);
        pool.commit(s2, 3);
        let next = pool.reserve(1);
        assert_eq!(next, vec![s1]);
        assert_eq!(pool.lookup(2), None);
        assert_eq!(pool.lookup(3), Some(s2));
    }
}
