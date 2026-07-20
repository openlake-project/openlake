#![cfg(all(feature = "rdma", target_os = "linux"))]

use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

use crate::kv::{KvSlab, SlotPool};
use crate::rdma::{Buffers, IbDevice};

pub struct RdmaSlab {
    buffers: Buffers,
    slots: RefCell<SlotPool>,
}

impl RdmaSlab {
    pub fn new(
        dev: Rc<IbDevice>,
        slot_bytes: usize,
        slot_count: usize,
        reserve_ttl: Duration,
    ) -> std::io::Result<Self> {
        Ok(Self {
            buffers: Buffers::new(dev, slot_count, slot_bytes)?,
            slots: RefCell::new(SlotPool::new(slot_count as u32, reserve_ttl)),
        })
    }

    pub fn slab_base(&self) -> u64 {
        self.buffers.slot_addr(0)
    }
    pub fn rkey(&self) -> u32 {
        self.buffers.rkey()
    }
}

impl KvSlab for RdmaSlab {
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
        self.buffers.buf_size() as u32
    }
    fn slot_count(&self) -> u32 {
        self.buffers.buf_cnt() as u32
    }
    fn shm_name(&self) -> Option<&str> {
        None
    }
}
