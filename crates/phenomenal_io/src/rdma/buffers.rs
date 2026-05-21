use std::alloc::{alloc_zeroed, dealloc, Layout};
use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::io;
use std::ptr::NonNull;

use rdma_mummy_sys::{
    ibv_access_flags, ibv_dereg_mr, ibv_mr, ibv_pd, ibv_reg_mr,
};

pub const BUF_SIZE:         usize = 16 * 1024;   // 16 KiB per slot
pub const SEND_BUF_CNT:     usize = 32;          // slots per direction per QP
pub const BUF_ACK_BATCH:    u32   = 8;           // credit ACK every 8 consumed RECVs
pub const BUF_SIGNAL_BATCH: u32   = 8;           // signal every 8th SEND
const PAGE_ALIGN:           usize = 4096;        // ibv_reg_mr page alignment

pub struct BufferMem {
    base:   NonNull<u8>,
    layout: Layout,
    mr:     NonNull<ibv_mr>,
}

unsafe impl Send for BufferMem {}
unsafe impl Sync for BufferMem {}

impl BufferMem {
    pub fn new(pd: *mut ibv_pd, total: usize) -> io::Result<Self> {
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
            Ok(BufferMem { base, layout, mr })
        }
    }
    pub fn lkey(&self) -> u32 { unsafe { (*self.mr.as_ptr()).lkey } }
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
    pub fn new(pd: *mut ibv_pd, buf_cnt: usize, buf_size: usize) -> io::Result<Self> {
        Ok(Buffers { mem: BufferMem::new(pd, buf_cnt * buf_size)?, buf_size, buf_cnt })
    }
    pub fn slot_ptr(&self, idx: usize) -> *mut u8 { unsafe { self.mem.ptr().add(idx * self.buf_size) } }
    pub fn slot_addr(&self, idx: usize) -> u64 { self.slot_ptr(idx) as u64 }
    pub fn lkey(&self)     -> u32   { self.mem.lkey() }
    pub fn buf_size(&self) -> usize { self.buf_size }
    pub fn buf_cnt(&self)  -> usize { self.buf_cnt }
}

pub struct SendBuffers {
    base:  Buffers,
    front: Cell<u64>,
    tail:  Cell<u64>,
}

impl SendBuffers {
    pub fn new(pd: *mut ibv_pd, buf_cnt: usize, buf_size: usize) -> io::Result<Self> {
        Ok(SendBuffers {
            base:  Buffers::new(pd, buf_cnt, buf_size)?,
            front: Cell::new(0),
            tail:  Cell::new(buf_cnt as u64),
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
    pub fn push(&self, n: u64) { self.tail.set(self.tail.get() + n); }
    pub fn base(&self) -> &Buffers { &self.base }
}

pub struct RecvBuffers {
    base:  Buffers,
    queue: RefCell<VecDeque<(u32, u32)>>,
}

impl RecvBuffers {
    pub fn new(pd: *mut ibv_pd, buf_cnt: usize, buf_size: usize) -> io::Result<Self> {
        Ok(RecvBuffers {
            base:  Buffers::new(pd, buf_cnt, buf_size)?,
            queue: RefCell::new(VecDeque::with_capacity(buf_cnt)),
        })
    }
    pub fn push(&self, idx: u32, len: u32) { self.queue.borrow_mut().push_back((idx, len)); }
    pub fn pop(&self) -> Option<(u32, u32)> { self.queue.borrow_mut().pop_front() }
    pub fn base(&self) -> &Buffers { &self.base }
}
