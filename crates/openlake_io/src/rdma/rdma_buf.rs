use std::alloc::{alloc_zeroed, dealloc, Layout};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::io;
use std::ptr::NonNull;
use std::rc::{Rc, Weak};

use bytes::Bytes;
use futures::channel::oneshot;
use rdma_mummy_sys::{ibv_access_flags, ibv_dereg_mr, ibv_mr, ibv_reg_mr};

use crate::rdma::device::IbDevice;
use crate::rdma::wire::RdmaRemoteBuf;

const PAGE_ALIGN: usize = 4096;

struct RdmaBufInner {
    base: NonNull<u8>,
    layout: Layout,
    mr: NonNull<ibv_mr>,
    capacity: usize,
    pool: Weak<RdmaBufPool>,
    _dev: Rc<IbDevice>,
}

// Required by `Bytes::from_owner`. Compio is thread-per-core; RdmaBuf
// never actually crosses runtimes.
unsafe impl Send for RdmaBufInner {}

impl RdmaBufInner {
    fn new(dev: Rc<IbDevice>, capacity: usize, pool: Weak<RdmaBufPool>) -> io::Result<Self> {
        let pd = dev.pd.as_ptr();
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
                None => {
                    let e = io::Error::last_os_error();
                    dealloc(base.as_ptr(), layout);
                    return Err(e);
                }
            };
            Ok(RdmaBufInner {
                base,
                layout,
                mr,
                capacity,
                pool,
                _dev: dev,
            })
        }
    }
}

impl Drop for RdmaBufInner {
    fn drop(&mut self) {
        unsafe {
            ibv_dereg_mr(self.mr.as_ptr());
            dealloc(self.base.as_ptr(), self.layout);
        }
    }
}

/// Registration over caller-owned memory (e.g. a KV cache). Local access
/// only: the region is a source of WRITEs and destination of READs that we
/// initiate, never remotely addressed. The caller guarantees
/// `[addr, addr+len)` stays valid and mapped for the MR's lifetime.
pub struct ExternalMr {
    mr: NonNull<ibv_mr>,
    pub addr: u64,
    pub len: u64,
    _dev: Rc<IbDevice>,
}

impl ExternalMr {
    pub fn register(dev: Rc<IbDevice>, addr: u64, len: u64) -> io::Result<Self> {
        if addr == 0 || len == 0 {
            return Err(io::Error::other("register: zero addr or len"));
        }
        let flags = ibv_access_flags::IBV_ACCESS_LOCAL_WRITE.0
            | ibv_access_flags::IBV_ACCESS_RELAXED_ORDERING.0;
        let mr = unsafe {
            ibv_reg_mr(
                dev.pd.as_ptr(),
                addr as *mut _,
                len as usize,
                flags as i32,
            )
        };
        let mr = NonNull::new(mr).ok_or_else(io::Error::last_os_error)?;
        Ok(Self {
            mr,
            addr,
            len,
            _dev: dev,
        })
    }

    pub fn lkey(&self) -> u32 {
        unsafe { (*self.mr.as_ptr()).lkey }
    }

    pub fn contains(&self, addr: u64, len: u64) -> bool {
        addr >= self.addr && addr.saturating_add(len) <= self.addr + self.len
    }
}

impl Drop for ExternalMr {
    fn drop(&mut self) {
        unsafe {
            ibv_dereg_mr(self.mr.as_ptr());
        }
    }
}

pub struct RdmaBuf {
    inner: Option<Box<RdmaBufInner>>,
}

impl RdmaBuf {
    pub fn addr(&self) -> u64 {
        self.inner.as_ref().unwrap().base.as_ptr() as u64
    }
    pub fn lkey(&self) -> u32 {
        unsafe { (*self.inner.as_ref().unwrap().mr.as_ptr()).lkey }
    }
    pub fn rkey(&self) -> u32 {
        unsafe { (*self.inner.as_ref().unwrap().mr.as_ptr()).rkey }
    }
    pub fn capacity(&self) -> usize {
        self.inner.as_ref().unwrap().capacity
    }

    pub fn as_slice(&self) -> &[u8] {
        let inner = self.inner.as_ref().unwrap();
        unsafe { std::slice::from_raw_parts(inner.base.as_ptr(), inner.capacity) }
    }
    pub fn as_slice_mut(&mut self) -> &mut [u8] {
        let inner = self.inner.as_mut().unwrap();
        unsafe { std::slice::from_raw_parts_mut(inner.base.as_ptr(), inner.capacity) }
    }

    pub fn as_remote(&self, len: u32) -> RdmaRemoteBuf {
        RdmaRemoteBuf {
            addr: self.addr(),
            len,
            rkey: self.rkey(),
        }
    }

    pub fn into_bytes(self, len: usize) -> Bytes {
        let cap = self.capacity();
        let take = len.min(cap);
        Bytes::from_owner(self).slice(..take)
    }
}

impl AsRef<[u8]> for RdmaBuf {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl Drop for RdmaBuf {
    fn drop(&mut self) {
        if let Some(inner) = self.inner.take() {
            if let Some(pool) = inner.pool.upgrade() {
                pool.return_inner(inner);
            }
            // If the pool was dropped first, `inner` falls out of scope
            // here and its own Drop deregisters the MR and frees memory.
        }
    }
}

struct PoolState {
    free: Vec<Box<RdmaBufInner>>,
    waiters: VecDeque<oneshot::Sender<Box<RdmaBufInner>>>,
    allocated: usize,
}

pub struct RdmaBufPool {
    dev: Rc<IbDevice>,
    buf_size: usize,
    cap: usize,
    state: RefCell<PoolState>,
}

impl RdmaBufPool {
    pub fn new(dev: Rc<IbDevice>, cap: usize, buf_size: usize) -> Rc<Self> {
        Rc::new(Self {
            dev,
            buf_size,
            cap,
            state: RefCell::new(PoolState {
                free: Vec::new(),
                waiters: VecDeque::new(),
                allocated: 0,
            }),
        })
    }

    pub async fn acquire(self: &Rc<Self>) -> io::Result<RdmaBuf> {
        let needs_alloc = {
            let mut s = self.state.borrow_mut();
            if let Some(inner) = s.free.pop() {
                return Ok(RdmaBuf { inner: Some(inner) });
            }
            if s.allocated < self.cap {
                s.allocated += 1;
                true
            } else {
                false
            }
        };
        if needs_alloc {
            match RdmaBufInner::new(self.dev.clone(), self.buf_size, Rc::downgrade(self)) {
                Ok(inner) => {
                    return Ok(RdmaBuf {
                        inner: Some(Box::new(inner)),
                    })
                }
                Err(e) => {
                    self.state.borrow_mut().allocated -= 1;
                    return Err(e);
                }
            }
        }
        let (tx, rx) = oneshot::channel();
        self.state.borrow_mut().waiters.push_back(tx);
        match rx.await {
            Ok(inner) => Ok(RdmaBuf { inner: Some(inner) }),
            Err(_) => Err(io::Error::other(
                "rdma buf pool waiter cancelled or pool dropped",
            )),
        }
    }

    fn return_inner(&self, mut inner: Box<RdmaBufInner>) {
        let mut s = self.state.borrow_mut();
        while let Some(waiter) = s.waiters.pop_front() {
            match waiter.send(inner) {
                Ok(()) => return,
                Err(returned) => {
                    inner = returned;
                }
            }
        }
        s.free.push(inner);
    }

    pub fn cap(&self) -> usize {
        self.cap
    }
    pub fn buf_size(&self) -> usize {
        self.buf_size
    }
    pub fn allocated(&self) -> usize {
        self.state.borrow().allocated
    }
    pub fn free_count(&self) -> usize {
        self.state.borrow().free.len()
    }
}
