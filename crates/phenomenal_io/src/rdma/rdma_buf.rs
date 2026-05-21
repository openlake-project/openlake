use std::alloc::{alloc_zeroed, dealloc, Layout};
use std::io;
use std::ptr::NonNull;
use std::sync::Mutex;

use rdma_mummy_sys::{
    ibv_access_flags, ibv_dereg_mr, ibv_mr, ibv_pd, ibv_reg_mr,
};
use serde::{Deserialize, Serialize};

const PAGE_ALIGN: usize = 4096;

pub struct RdmaBuf {
    base:   NonNull<u8>,
    layout: Layout,
    mr:     NonNull<ibv_mr>,
    capacity: usize,
}

unsafe impl Send for RdmaBuf {}
unsafe impl Sync for RdmaBuf {}

impl RdmaBuf {
    pub fn new(pd: *mut ibv_pd, capacity: usize) -> io::Result<Self> {
        let layout = Layout::from_size_align(capacity, PAGE_ALIGN)
            .map_err(|e| io::Error::other(format!("layout: {e}")))?;
        unsafe {
            let raw = alloc_zeroed(layout);
            let base = NonNull::new(raw).ok_or_else(|| io::Error::other("alloc"))?;
            let flags = ibv_access_flags::IBV_ACCESS_LOCAL_WRITE.0
                      | ibv_access_flags::IBV_ACCESS_REMOTE_WRITE.0
                      | ibv_access_flags::IBV_ACCESS_REMOTE_READ.0
                      | ibv_access_flags::IBV_ACCESS_RELAXED_ORDERING.0;
            let mr = ibv_reg_mr(pd, base.as_ptr() as *mut _, capacity, flags as i32);
            let mr = match NonNull::new(mr) {
                Some(m) => m,
                None => { let e = io::Error::last_os_error(); dealloc(base.as_ptr(), layout); return Err(e); }
            };
            Ok(RdmaBuf { base, layout, mr, capacity })
        }
    }
    pub fn addr(&self)     -> u64   { self.base.as_ptr() as u64 }
    pub fn lkey(&self)     -> u32   { unsafe { (*self.mr.as_ptr()).lkey } }
    pub fn rkey(&self)     -> u32   { unsafe { (*self.mr.as_ptr()).rkey } }
    pub fn capacity(&self) -> usize { self.capacity }
    pub fn as_remote(&self, len: u32) -> RdmaRemoteBuf {
        RdmaRemoteBuf { addr: self.addr(), len, rkey: self.rkey() }
    }
    pub fn as_slice_mut(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.base.as_ptr(), self.capacity) }
    }
    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.base.as_ptr(), self.capacity) }
    }
}

impl Drop for RdmaBuf {
    fn drop(&mut self) {
        unsafe { ibv_dereg_mr(self.mr.as_ptr()); dealloc(self.base.as_ptr(), self.layout); }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct RdmaRemoteBuf {
    pub addr: u64,
    pub len:  u32,
    pub rkey: u32,
}

pub struct RdmaBufPool {
    free: Mutex<Vec<RdmaBuf>>,
}

impl RdmaBufPool {
    pub fn new(pd: *mut ibv_pd, count: usize, capacity: usize) -> io::Result<Self> {
        let mut v = Vec::with_capacity(count);
        for _ in 0..count { v.push(RdmaBuf::new(pd, capacity)?); }
        Ok(RdmaBufPool { free: Mutex::new(v) })
    }
    pub fn acquire(&self) -> Option<RdmaBuf> { self.free.lock().unwrap().pop() }
    pub fn release(&self, buf: RdmaBuf)      { self.free.lock().unwrap().push(buf); }
}
