use std::alloc::{alloc_zeroed, dealloc, Layout};
use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::io;
use std::ptr::NonNull;
use std::rc::Rc;

use futures::channel::oneshot;
use rdma_mummy_sys::{
    ibv_access_flags, ibv_dereg_mr, ibv_mr, ibv_reg_mr,
};

use super::device::IbDevice;

pub const BUF_SIZE:           usize = 16 * 1024;
pub const SEND_BUF_CNT:       usize = 4;
pub const PEER_CREDIT_BUDGET: u32   = SEND_BUF_CNT as u32;
const PAGE_ALIGN:             usize = 4096;

pub fn buf_ack_batch() -> u32 {
    use std::sync::OnceLock;
    static V: OnceLock<u32> = OnceLock::new();
    *V.get_or_init(|| {
        std::env::var("OPENLAKE_BUF_ACK_BATCH")
            .ok()
            .and_then(|s| s.parse().ok())
            .filter(|n: &u32| *n > 0)
            .unwrap_or(4)
    })
}

pub struct BufferMem {
    base:   NonNull<u8>,
    layout: Layout,
    mr:     NonNull<ibv_mr>,
    _dev:   Rc<IbDevice>,
}

unsafe impl Send for BufferMem {}
unsafe impl Sync for BufferMem {}

impl BufferMem {
    pub fn new(dev: Rc<IbDevice>, total: usize) -> io::Result<Self> {
        let pd = dev.pd.as_ptr();
        let layout = Layout::from_size_align(total, PAGE_ALIGN)
            .map_err(|e| io::Error::other(format!("layout: {e}")))?;
        unsafe {
            let raw = alloc_zeroed(layout);
            let base = NonNull::new(raw).ok_or_else(|| io::Error::other("alloc"))?;
            let flags = ibv_access_flags::IBV_ACCESS_LOCAL_WRITE.0
                      | ibv_access_flags::IBV_ACCESS_REMOTE_WRITE.0
                      | ibv_access_flags::IBV_ACCESS_REMOTE_READ.0
                      | ibv_access_flags::IBV_ACCESS_RELAXED_ORDERING.0;
            let mr = ibv_reg_mr(pd, base.as_ptr() as *mut _, total, flags as i32);
            let mr = match NonNull::new(mr) {
                Some(m) => m,
                None => { let e = io::Error::last_os_error(); dealloc(base.as_ptr(), layout); return Err(e); }
            };
            Ok(BufferMem { base, layout, mr, _dev: dev })
        }
    }
    pub fn lkey(&self) -> u32 { unsafe { (*self.mr.as_ptr()).lkey } }
    pub fn rkey(&self) -> u32 { unsafe { (*self.mr.as_ptr()).rkey } }
    pub fn ptr(&self)  -> *mut u8 { self.base.as_ptr() }
}

impl Drop for BufferMem {
    fn drop(&mut self) {
        unsafe { ibv_dereg_mr(self.mr.as_ptr()); dealloc(self.base.as_ptr(), self.layout); }
    }
}

pub struct Buffers {
    mem:      BufferMem,
    buf_size: usize,
    buf_cnt:  usize,
}

impl Buffers {
    pub fn new(dev: Rc<IbDevice>, buf_cnt: usize, buf_size: usize) -> io::Result<Self> {
        Ok(Buffers { mem: BufferMem::new(dev, buf_cnt * buf_size)?, buf_size, buf_cnt })
    }
    pub fn slot_ptr(&self, idx: usize) -> *mut u8 { unsafe { self.mem.ptr().add(idx * self.buf_size) } }
    pub fn slot_addr(&self, idx: usize) -> u64 { self.slot_ptr(idx) as u64 }
    pub fn lkey(&self)     -> u32   { self.mem.lkey() }
    pub fn buf_size(&self) -> usize { self.buf_size }
    pub fn buf_cnt(&self)  -> usize { self.buf_cnt }
}

pub struct SendBuffers {
    base:    Buffers,
    front:   Cell<u64>,
    tail:    Cell<u64>,
    waiters: RefCell<VecDeque<oneshot::Sender<usize>>>,
}

impl SendBuffers {
    pub fn new(dev: Rc<IbDevice>, buf_cnt: usize, buf_size: usize) -> io::Result<Self> {
        Ok(SendBuffers {
            base:    Buffers::new(dev, buf_cnt, buf_size)?,
            front:   Cell::new(0),
            tail:    Cell::new(buf_cnt as u64),
            waiters: RefCell::new(VecDeque::new()),
        })
    }
    pub fn empty(&self) -> bool {
        self.front.get() >= self.tail.get()
    }
    pub fn try_pop(&self) -> Option<usize> {
        let f = self.front.get();
        if f >= self.tail.get() { return None; }
        self.front.set(f + 1);
        Some((f as usize) % self.base.buf_cnt())
    }
    pub async fn acquire(&self) -> usize {
        if let Some(idx) = self.try_pop() { return idx; }
        let (tx, rx) = oneshot::channel();
        self.waiters.borrow_mut().push_back(tx);
        rx.await.expect("send_bufs waiter cancelled before push")
    }
    pub fn push(&self, n: u64) {
        self.tail.set(self.tail.get() + n);
        let mut waiters = self.waiters.borrow_mut();
        while !waiters.is_empty() {
            let f = self.front.get();
            if f >= self.tail.get() { break; }
            let tx = waiters.pop_front().unwrap();
            self.front.set(f + 1);
            let idx = (f as usize) % self.base.buf_cnt();
            if tx.send(idx).is_err() {
                self.front.set(f);
            }
        }
    }
    pub fn base(&self) -> &Buffers { &self.base }
}

pub struct RecvBuffers {
    base:  Buffers,
    queue: RefCell<VecDeque<(u32, u32)>>,
}

impl RecvBuffers {
    pub fn new(dev: Rc<IbDevice>, buf_cnt: usize, buf_size: usize) -> io::Result<Self> {
        Ok(RecvBuffers {
            base:  Buffers::new(dev, buf_cnt, buf_size)?,
            queue: RefCell::new(VecDeque::with_capacity(buf_cnt)),
        })
    }
    pub fn push(&self, idx: u32, len: u32) { self.queue.borrow_mut().push_back((idx, len)); }
    pub fn pop(&self) -> Option<(u32, u32)> { self.queue.borrow_mut().pop_front() }
    pub fn base(&self) -> &Buffers { &self.base }
}
