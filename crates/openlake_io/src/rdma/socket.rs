use std::cell::{Cell, RefCell};
use std::collections::{HashMap, VecDeque};
use std::io;
use std::mem;
use std::ptr::{self, NonNull};
use std::rc::Rc;

use futures::channel::{mpsc, oneshot};

use rdma_mummy_sys::{
    ibv_access_flags, ibv_ack_cq_events, ibv_ah, ibv_comp_channel, ibv_cq,
    ibv_create_comp_channel, ibv_create_cq, ibv_create_srq, ibv_destroy_comp_channel,
    ibv_destroy_cq, ibv_destroy_qp, ibv_destroy_srq, ibv_get_cq_event, ibv_modify_qp,
    ibv_poll_cq, ibv_post_srq_recv, ibv_qp, ibv_qp_attr, ibv_qp_attr_mask,
    ibv_qp_init_attr_ex, ibv_qp_state, ibv_qp_to_qp_ex, ibv_qp_type, ibv_recv_wr,
    ibv_req_notify_cq, ibv_send_flags, ibv_sge, ibv_srq, ibv_srq_init_attr, ibv_wc,
    ibv_wc_flags, ibv_wc_opcode, ibv_wc_status, ibv_wr_complete, ibv_wr_rdma_read,
    ibv_wr_rdma_write, ibv_wr_send, ibv_wr_send_imm, ibv_wr_set_sge, ibv_wr_set_sge_list, ibv_wr_start,
};

use super::buffers::{
    buf_ack_batch, RecvBuffers, SendBuffers, BUF_SIZE, PEER_CREDIT_BUDGET, SEND_BUF_CNT,
};
use super::device::{IbDevice, PORT_NUM};
use super::node::RdmaQos;
use super::mlx5dv_sys::{
    mlx5dv_create_qp, mlx5dv_qp_ex_from_ibv_qp_ex, mlx5dv_qp_init_attr,
    mlx5dv_dc_type_MLX5DV_DCTYPE_DCT, mlx5dv_dc_type_MLX5DV_DCTYPE_DCI,
    mlx5dv_qp_init_attr_mask_MLX5DV_QP_INIT_ATTR_MASK_DC,
};
use super::wr::{ImmData, ImmType, PeerKey, WrId, WrType};

extern "C" {
    fn ibv_wc_status_str(status: u32) -> *const std::os::raw::c_char;
}

fn wc_status_str(status: i32) -> &'static str {
    unsafe { std::ffi::CStr::from_ptr(ibv_wc_status_str(status as u32)) }
        .to_str()
        .unwrap_or("<utf8 invalid>")
}

const CQ_DEPTH:        i32 = 4096;
const MAX_SEND_WR:     u32 = 256;
const SRQ_DEPTH:       u32 = 1024;
const MAX_RD_ATOMIC:   u8  = 16;
const MIN_RNR_TIMER:   u8  = 1;
const QP_TIMEOUT:      u8  = 14;
const QP_RETRY_CNT:    u8  = 7;

pub(super) struct PeerCredit {
    pub sent:      u64,
    pub acked:     u64,
    pub not_acked: u32,
    pub wakers:    VecDeque<oneshot::Sender<()>>,
}

impl PeerCredit {
    fn new() -> Self {
        Self { sent: 0, acked: 0, not_acked: 0, wakers: VecDeque::new() }
    }
}

pub struct IbSocket {
    pub(super) dev:          Rc<IbDevice>,
    pub(super) cq:           NonNull<ibv_cq>,
    pub(super) comp_channel: NonNull<ibv_comp_channel>,
    pub(super) srq:          NonNull<ibv_srq>,
    pub(super) dct:          NonNull<ibv_qp>,
    pub(super) dci:          NonNull<ibv_qp>,
    pub(super) send_bufs:    SendBuffers,
    pub(super) recv_bufs:    RecvBuffers,
    pub(super) dc_key:       u64,
    pub(super) self_dct_identifier:   u32,
    pub(super) self_key:     PeerKey,

    pub(super) per_peer: RefCell<HashMap<PeerKey, PeerCredit>>,

    pub(super) completion: RefCell<HashMap<u64, oneshot::Sender<i32>>>,
    pub(super) next_wr_id: Cell<u64>,
}

impl IbSocket {
    pub fn self_dct_identifier(&self) -> u32 { self.self_dct_identifier }

    pub fn new(
        dev: Rc<IbDevice>, dc_key: u64, qos: RdmaQos, self_key: PeerKey, recv_buf_cnt: usize,
    ) -> io::Result<Self> {
        unsafe {
            let comp_channel = ibv_create_comp_channel(dev.ctx.as_ptr());
            let comp_channel = NonNull::new(comp_channel)
                .ok_or_else(|| io::Error::other("ibv_create_comp_channel returned NULL"))?;
            let cq = ibv_create_cq(dev.ctx.as_ptr(), CQ_DEPTH, ptr::null_mut(),
                                   comp_channel.as_ptr(), 0);
            let cq = match NonNull::new(cq) {
                Some(c) => c,
                None    => { ibv_destroy_comp_channel(comp_channel.as_ptr());
                             return Err(io::Error::other("ibv_create_cq returned NULL")); }
            };
            if ibv_req_notify_cq(cq.as_ptr(), 0) != 0 {
                let e = io::Error::other(format!("ibv_req_notify_cq: {}", io::Error::last_os_error()));
                ibv_destroy_cq(cq.as_ptr());
                ibv_destroy_comp_channel(comp_channel.as_ptr());
                return Err(e);
            }

            let mut srq_attr: ibv_srq_init_attr = mem::zeroed();
            srq_attr.attr.max_wr  = SRQ_DEPTH;
            srq_attr.attr.max_sge = 1;
            let srq = ibv_create_srq(dev.pd.as_ptr(), &mut srq_attr);
            let srq = NonNull::new(srq)
                .ok_or_else(|| io::Error::other(format!("ibv_create_srq: {}", io::Error::last_os_error())))?;

            let dct = create_dct(&dev, cq.as_ptr(), srq.as_ptr(), dc_key)
                .map_err(|e| io::Error::other(format!("create_dct: {e}")))?;
            transition_dct(dct.as_ptr(), &dev, qos)
                .map_err(|e| io::Error::other(format!("transition_dct: {e}")))?;
            // mlx5dv assigns the DCT number during the RTR transition, not at create.
            let self_dct_identifier = (*dct.as_ptr()).qp_num;

            let dci = create_dci(&dev, cq.as_ptr())
                .map_err(|e| io::Error::other(format!("create_dci: {e}")))?;
            transition_dci(dci.as_ptr(), &dev, qos)
                .map_err(|e| io::Error::other(format!("transition_dci: {e}")))?;

            let send_bufs = SendBuffers::new(dev.clone(), SEND_BUF_CNT, BUF_SIZE)?;
            let recv_bufs = RecvBuffers::new(dev.clone(), recv_buf_cnt, BUF_SIZE)?;

            let sock = IbSocket {
                dev, cq, comp_channel, srq, dct, dci,
                send_bufs, recv_bufs, dc_key, self_dct_identifier, self_key,
                per_peer:   RefCell::new(HashMap::new()),
                completion: RefCell::new(HashMap::new()),
                next_wr_id: Cell::new(1),
            };
            for i in 0..recv_buf_cnt { sock.post_recv(i as u32)?; }
            Ok(sock)
        }
    }

    pub async fn send_with_kind(
        &self,
        mut buf:      &[u8],
        peer:         PeerKey,
        ah:           *mut ibv_ah,
        peer_dct_num: u32,
        peer_dc_key:  u64,
        kind:         super::wr::SendKind,
    ) -> io::Result<usize> {
        let mut total = 0;
        let bs = BUF_SIZE;
        let mut waiters: Vec<oneshot::Receiver<i32>> = Vec::new();
        while !buf.is_empty() {
            loop {
                let mut per_peer = self.per_peer.borrow_mut();
                let entry = per_peer.entry(peer).or_insert_with(PeerCredit::new);
                let outstanding = entry.sent.wrapping_sub(entry.acked);
                if outstanding < PEER_CREDIT_BUDGET as u64 {
                    entry.sent = entry.sent.wrapping_add(1);
                    break;
                }
                let (tx, rx) = oneshot::channel();
                entry.wakers.push_back(tx);
                drop(per_peer);
                let _ = rx.await;
            }

            let idx = self.send_bufs.acquire().await;
            let n = buf.len().min(bs);
            unsafe {
                ptr::copy_nonoverlapping(
                    buf.as_ptr(),
                    self.send_bufs.base().slot_ptr(idx),
                    n,
                );
            }
            let seq   = { let id = self.next_wr_id.get(); self.next_wr_id.set(id + 1); id };
            let wr_id = super::wr::WrId::send_with_kind_seq(seq, kind).0;
            let (tx, rx) = oneshot::channel();
            self.completion.borrow_mut().insert(wr_id, tx);

            if let Err(e) = self.post_send_with_id(wr_id, idx as u32, n as u32, ah, peer_dct_num, peer_dc_key) {
                self.completion.borrow_mut().remove(&wr_id);
                self.send_bufs.push(1);
                let mut per_peer = self.per_peer.borrow_mut();
                if let Some(entry) = per_peer.get_mut(&peer) {
                    entry.sent = entry.sent.wrapping_sub(1);
                }
                return Err(e);
            }
            waiters.push(rx);
            total += n;
            buf = &buf[n..];
        }

        for rx in waiters {
            let status = rx.await.map_err(|_| io::Error::other("pump dropped"))?;
            if status != ibv_wc_status::IBV_WC_SUCCESS as i32 {
                return Err(io::Error::other(format!(
                    "send wc.status={status} ({}) kind={kind:?}", wc_status_str(status)
                )));
            }
        }
        Ok(total)
    }

    pub fn attempt_singular_rcv(&self, out: &mut Vec<u8>) -> Option<()> {
        let (idx, len) = self.recv_bufs.pop()?;
        out.resize(len as usize, 0);
        unsafe {
            ptr::copy_nonoverlapping(
                self.recv_bufs.base().slot_ptr(idx as usize),
                out.as_mut_ptr(),
                len as usize,
            );
        }
        Some(())
    }

    pub fn note_drain(
        &self,
        peer:         PeerKey,
        ah:           *mut ibv_ah,
        peer_dct_num: u32,
        peer_dc_key:  u64,
    ) -> io::Result<()> {
        let to_ack = {
            let mut per_peer = self.per_peer.borrow_mut();
            let entry = per_peer.entry(peer).or_insert_with(PeerCredit::new);
            entry.not_acked = entry.not_acked.saturating_add(1);
            if entry.not_acked >= buf_ack_batch() {
                let count = entry.not_acked;
                entry.not_acked = 0;
                count
            } else {
                0
            }
        };
        if to_ack > 0 {
            self.post_ack(ah, peer_dct_num, peer_dc_key, to_ack)?;
        }
        Ok(())
    }

    pub async fn rdma_write(
        &self,
        local_addr: u64, local_len: u32, local_lkey: u32,
        remote_addr: u64, remote_rkey: u32,
        ah: *mut ibv_ah, peer_dct_num: u32, peer_dc_key: u64,
    ) -> io::Result<()> {
        let wr_id = { let id = self.next_wr_id.get(); self.next_wr_id.set(id + 1); id };
        let (tx, rx) = oneshot::channel();
        self.completion.borrow_mut().insert(wr_id, tx);
        // ibv_wr_start..ibv_wr_complete is a contiguous synchronous block.
        // No .await between them, so on a single-threaded runtime no other
        // task can interleave; we don't need an explicit lock.
        unsafe {
            let qpx  = ibv_qp_to_qp_ex(self.dci.as_ptr());
            let mqpx = mlx5dv_qp_ex_from_ibv_qp_ex(qpx);
            ibv_wr_start(qpx);
            (*qpx).wr_id    = wr_id;
            (*qpx).wr_flags = ibv_send_flags::IBV_SEND_SIGNALED.0 as u32;
            ibv_wr_rdma_write(qpx, remote_rkey, remote_addr);
            ibv_wr_set_sge(qpx, local_lkey, local_addr, local_len);
            ((*mqpx).wr_set_dc_addr.expect("wr_set_dc_addr"))(mqpx, ah, peer_dct_num, peer_dc_key);
            let rc = ibv_wr_complete(qpx);
            if rc != 0 {
                self.completion.borrow_mut().remove(&wr_id);
                return Err(io::Error::from_raw_os_error(rc));
            }
        }
        let status = rx.await.map_err(|_| io::Error::other("pump dropped"))?;
        if status != 0 { return Err(io::Error::other(format!("rdma_write wc.status={status} ({})", wc_status_str(status)))); }
        Ok(())
    }

    pub async fn rdma_read(
        &self,
        local_addr: u64, local_len: u32, local_lkey: u32,
        remote_addr: u64, remote_rkey: u32,
        ah: *mut ibv_ah, peer_dct_num: u32, peer_dc_key: u64,
    ) -> io::Result<()> {
        let wr_id = { let id = self.next_wr_id.get(); self.next_wr_id.set(id + 1); id };
        let (tx, rx) = oneshot::channel();
        self.completion.borrow_mut().insert(wr_id, tx);
        unsafe {
            let qpx  = ibv_qp_to_qp_ex(self.dci.as_ptr());
            let mqpx = mlx5dv_qp_ex_from_ibv_qp_ex(qpx);
            ibv_wr_start(qpx);
            (*qpx).wr_id    = wr_id;
            (*qpx).wr_flags = ibv_send_flags::IBV_SEND_SIGNALED.0 as u32;
            ibv_wr_rdma_read(qpx, remote_rkey, remote_addr);
            ibv_wr_set_sge(qpx, local_lkey, local_addr, local_len);
            ((*mqpx).wr_set_dc_addr.expect("wr_set_dc_addr"))(mqpx, ah, peer_dct_num, peer_dc_key);
            let rc = ibv_wr_complete(qpx);
            if rc != 0 {
                self.completion.borrow_mut().remove(&wr_id);
                return Err(io::Error::from_raw_os_error(rc));
            }
        }
        let status = rx.await.map_err(|_| io::Error::other("pump dropped"))?;
        if status != 0 { return Err(io::Error::other(format!("rdma_read wc.status={status} ({})", wc_status_str(status)))); }
        Ok(())
    }

    pub(super) fn post_send_with_id(
        &self, wr_id: u64, buf_idx: u32, len: u32, ah: *mut ibv_ah, peer_dct_num: u32, peer_dc_key: u64,
    ) -> io::Result<()> {
        unsafe {
            let qpx  = ibv_qp_to_qp_ex(self.dci.as_ptr());
            let mqpx = mlx5dv_qp_ex_from_ibv_qp_ex(qpx);
            ibv_wr_start(qpx);
            (*qpx).wr_id    = wr_id;
            (*qpx).wr_flags = ibv_send_flags::IBV_SEND_SIGNALED.0 as u32;
            ibv_wr_send(qpx);
            ibv_wr_set_sge(qpx, self.send_bufs.base().lkey(),
                           self.send_bufs.base().slot_addr(buf_idx as usize), len);
            ((*mqpx).wr_set_dc_addr.expect("wr_set_dc_addr"))(mqpx, ah, peer_dct_num, peer_dc_key);
            let rc = ibv_wr_complete(qpx);
            if rc != 0 { return Err(io::Error::from_raw_os_error(rc)); }
        }
        Ok(())
    }

    pub(super) fn post_ack(
        &self,
        ah:           *mut ibv_ah,
        peer_dct_num: u32,
        peer_dc_key:  u64,
        count:        u32,
    ) -> io::Result<()> {
        let imm_host = ImmData::ack(self.self_key, count).0;
        let imm_wire = imm_host.to_be();
        unsafe {
            let qpx  = ibv_qp_to_qp_ex(self.dci.as_ptr());
            let mqpx = mlx5dv_qp_ex_from_ibv_qp_ex(qpx);
            ibv_wr_start(qpx);
            (*qpx).wr_id    = WrId::ack().0;
            (*qpx).wr_flags = ibv_send_flags::IBV_SEND_SIGNALED.0 as u32;
            ibv_wr_send_imm(qpx, imm_wire);
            ibv_wr_set_sge_list(qpx, 0, std::ptr::null());
            ((*mqpx).wr_set_dc_addr.expect("wr_set_dc_addr"))(mqpx, ah, peer_dct_num, peer_dc_key);
            let rc = ibv_wr_complete(qpx);
            if rc != 0 { return Err(io::Error::from_raw_os_error(rc)); }
        }
        Ok(())
    }

    pub(super) fn post_recv(&self, buf_idx: u32) -> io::Result<()> {
        unsafe {
            let mut sge: ibv_sge = mem::zeroed();
            sge.addr   = self.recv_bufs.base().slot_addr(buf_idx as usize);
            sge.length = BUF_SIZE as u32;
            sge.lkey   = self.recv_bufs.base().lkey();
            let mut wr: ibv_recv_wr = mem::zeroed();
            wr.wr_id   = super::wr::WrId::recv(buf_idx).0;
            wr.sg_list = &mut sge;
            wr.num_sge = 1;
            let mut bad: *mut ibv_recv_wr = ptr::null_mut();
            let rc = ibv_post_srq_recv(self.srq.as_ptr(), &mut wr, &mut bad);
            if rc != 0 { return Err(io::Error::from_raw_os_error(rc)); }
        }
        Ok(())
    }
}

impl Drop for IbSocket {
    fn drop(&mut self) {
        unsafe {
            ibv_destroy_qp(self.dci.as_ptr());
            ibv_destroy_qp(self.dct.as_ptr());
            ibv_destroy_srq(self.srq.as_ptr());
            ibv_destroy_cq(self.cq.as_ptr());
            ibv_destroy_comp_channel(self.comp_channel.as_ptr());
        }
    }
}

unsafe fn create_dct(dev: &IbDevice, cq: *mut ibv_cq, srq: *mut ibv_srq, dc_key: u64)
    -> io::Result<NonNull<ibv_qp>>
{
    let mut a: ibv_qp_init_attr_ex = mem::zeroed();
    a.qp_type   = ibv_qp_type::IBV_QPT_DRIVER as u32;
    a.send_cq   = cq;
    a.recv_cq   = cq;
    a.srq       = srq;
    a.pd        = dev.pd.as_ptr();
    a.comp_mask = rdma_mummy_sys::ibv_qp_init_attr_mask::IBV_QP_INIT_ATTR_PD.0;
    let mut m: mlx5dv_qp_init_attr = mem::zeroed();
    m.comp_mask                                  = mlx5dv_qp_init_attr_mask_MLX5DV_QP_INIT_ATTR_MASK_DC as u64;
    m.dc_init_attr.dc_type                       = mlx5dv_dc_type_MLX5DV_DCTYPE_DCT;
    m.dc_init_attr.__bindgen_anon_1.dct_access_key = dc_key;
    NonNull::new(mlx5dv_create_qp(dev.ctx.as_ptr(), &mut a, &mut m))
        .ok_or_else(io::Error::last_os_error)
}

unsafe fn create_dci(dev: &IbDevice, cq: *mut ibv_cq) -> io::Result<NonNull<ibv_qp>> {
    let mut a: ibv_qp_init_attr_ex = mem::zeroed();
    a.qp_type           = ibv_qp_type::IBV_QPT_DRIVER as u32;
    a.send_cq           = cq;
    a.recv_cq           = cq;
    a.pd                = dev.pd.as_ptr();
    a.cap.max_send_wr   = MAX_SEND_WR;
    a.cap.max_send_sge  = 1;
    a.comp_mask         = rdma_mummy_sys::ibv_qp_init_attr_mask::IBV_QP_INIT_ATTR_PD.0
                        | rdma_mummy_sys::ibv_qp_init_attr_mask::IBV_QP_INIT_ATTR_SEND_OPS_FLAGS.0;
    a.send_ops_flags    = (rdma_mummy_sys::ibv_qp_create_send_ops_flags::IBV_QP_EX_WITH_SEND.0
                         | rdma_mummy_sys::ibv_qp_create_send_ops_flags::IBV_QP_EX_WITH_SEND_WITH_IMM.0
                         | rdma_mummy_sys::ibv_qp_create_send_ops_flags::IBV_QP_EX_WITH_RDMA_WRITE.0
                         | rdma_mummy_sys::ibv_qp_create_send_ops_flags::IBV_QP_EX_WITH_RDMA_WRITE_WITH_IMM.0
                         | rdma_mummy_sys::ibv_qp_create_send_ops_flags::IBV_QP_EX_WITH_RDMA_READ.0) as u64;
    let mut m: mlx5dv_qp_init_attr = mem::zeroed();
    m.comp_mask              = mlx5dv_qp_init_attr_mask_MLX5DV_QP_INIT_ATTR_MASK_DC as u64;
    m.dc_init_attr.dc_type   = mlx5dv_dc_type_MLX5DV_DCTYPE_DCI;
    NonNull::new(mlx5dv_create_qp(dev.ctx.as_ptr(), &mut a, &mut m))
        .ok_or_else(io::Error::last_os_error)
}

unsafe fn transition_dct(qp: *mut ibv_qp, dev: &IbDevice, qos: RdmaQos) -> io::Result<()> {
    let mut a: ibv_qp_attr = mem::zeroed();
    a.qp_state        = ibv_qp_state::IBV_QPS_INIT;
    a.port_num        = PORT_NUM;
    a.qp_access_flags = (ibv_access_flags::IBV_ACCESS_LOCAL_WRITE.0
                       | ibv_access_flags::IBV_ACCESS_REMOTE_WRITE.0
                       | ibv_access_flags::IBV_ACCESS_REMOTE_READ.0) as u32;
    let m = ibv_qp_attr_mask::IBV_QP_STATE.0
          | ibv_qp_attr_mask::IBV_QP_PKEY_INDEX.0
          | ibv_qp_attr_mask::IBV_QP_PORT.0
          | ibv_qp_attr_mask::IBV_QP_ACCESS_FLAGS.0;
    let rc = ibv_modify_qp(qp, &mut a, m as i32);
    if rc != 0 {
        return Err(io::Error::other(format!(
            "ibv_modify_qp rc={rc} errno={}", io::Error::last_os_error()
        )));
    }

    let mut a: ibv_qp_attr = mem::zeroed();
    a.qp_state           = ibv_qp_state::IBV_QPS_RTR;
    a.path_mtu           = dev.port_attr.active_mtu;
    a.min_rnr_timer      = MIN_RNR_TIMER;
    a.max_dest_rd_atomic = MAX_RD_ATOMIC;
    a.ah_attr.is_global         = 1;
    a.ah_attr.port_num          = PORT_NUM;
    a.ah_attr.sl                = qos.service_level;
    a.ah_attr.grh.sgid_index    = dev.gid_index;
    a.ah_attr.grh.hop_limit     = 64;
    a.ah_attr.grh.traffic_class = qos.traffic_class;
    let m = ibv_qp_attr_mask::IBV_QP_STATE.0
          | ibv_qp_attr_mask::IBV_QP_PATH_MTU.0
          | ibv_qp_attr_mask::IBV_QP_AV.0
          | ibv_qp_attr_mask::IBV_QP_MIN_RNR_TIMER.0;
    let rc = ibv_modify_qp(qp, &mut a, m as i32);
    if rc != 0 {
        return Err(io::Error::other(format!(
            "ibv_modify_qp rc={rc} errno={}", io::Error::last_os_error()
        )));
    }
    Ok(())
}

pub struct CqPump {
    _task:   compio::runtime::Task<Result<(), Box<dyn std::any::Any + Send>>>,
    sock:    Rc<IbSocket>,
    recv_rx: RefCell<Option<mpsc::UnboundedReceiver<()>>>,
}

impl CqPump {
    pub fn start(sock: Rc<IbSocket>) -> io::Result<Self> {
        let fd = unsafe { (*sock.comp_channel.as_ptr()).fd };
        let (tx, rx) = mpsc::unbounded();
        let s = sock.clone();
        let task = compio::runtime::spawn(async move { run_pump_compio(s, fd, tx).await });
        Ok(CqPump { _task: task, sock, recv_rx: RefCell::new(Some(rx)) })
    }
    pub fn socket(&self) -> &Rc<IbSocket> { &self.sock }
    pub fn take_recv_rx(&self) -> Option<mpsc::UnboundedReceiver<()>> {
        self.recv_rx.borrow_mut().take()
    }
}

const WC_BATCH: i32 = 16;

struct CompChannelFd(std::os::fd::RawFd);
impl std::os::fd::AsFd for CompChannelFd {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        unsafe { std::os::fd::BorrowedFd::borrow_raw(self.0) }
    }
}

async fn run_pump_compio(sock: Rc<IbSocket>, fd: std::os::fd::RawFd, recv_tx: mpsc::UnboundedSender<()>) {
    let mut wcs: [ibv_wc; WC_BATCH as usize] = unsafe { mem::zeroed() };
    loop {
        let op = compio::driver::op::PollOnce::new(
            CompChannelFd(fd),
            compio::driver::op::Interest::Readable,
        );
        // todo: @arnav pump silently dies on any verbs or poll error, awaiters can hang forever
        if compio::runtime::submit(op).await.0.is_err() { return; }
        unsafe {
            let mut ev_cq: *mut ibv_cq = ptr::null_mut();
            let mut ctx:   *mut std::ffi::c_void = ptr::null_mut();
            if ibv_get_cq_event(sock.comp_channel.as_ptr(), &mut ev_cq, &mut ctx) != 0 { return; }
            ibv_ack_cq_events(ev_cq, 1);
            if ibv_req_notify_cq(sock.cq.as_ptr(), 0) != 0 { return; }
            loop {
                let n = ibv_poll_cq(sock.cq.as_ptr(), WC_BATCH, wcs.as_mut_ptr());
                if n <= 0 { break; }
                for wc in &wcs[..n as usize] {
                    handle_wc(&sock, wc, &recv_tx);
                }
            }
        }
    }
}

fn handle_wc(sock: &IbSocket, wc: &ibv_wc, recv_tx: &mpsc::UnboundedSender<()>) {
    let status_ok = wc.status == ibv_wc_status::IBV_WC_SUCCESS;
    let wr = WrId(wc.wr_id);
    let imm_set = (wc.wc_flags & ibv_wc_flags::IBV_WC_WITH_IMM.0) != 0;
    if !status_ok { tracing::error!(wc_status = wc.status as i32, status_str = wc_status_str(wc.status as i32), vendor_err = wc.vendor_err, wc_opcode = wc.opcode as i32, wr_id = wc.wr_id, wr_ty = ?wr.ty(), send_kind = ?wr.send_kind(), "nic_cq_err"); }
    if !status_ok {
        match wr.ty() {
            WrType::Send => {
                sock.send_bufs.push(1);
                if let Some(tx) = sock.completion.borrow_mut().remove(&wc.wr_id) {
                    let _ = tx.send(wc.status as i32);
                }
            }
            WrType::Recv => {
                let buf_idx = wr.buf_idx();
                let _ = sock.post_recv(buf_idx);
            }
            _ => {
                // RDMA_WRITE / RDMA_READ wr_id (bare counter).
                if let Some(tx) = sock.completion.borrow_mut().remove(&wc.wr_id) {
                    let _ = tx.send(wc.status as i32);
                }
            }
        }
        return;
    }
    match wc.opcode {
        ibv_wc_opcode::IBV_WC_SEND => {
            if wr.ty() == WrType::Send {
                sock.send_bufs.push(1);
            }
            if let Some(tx) = sock.completion.borrow_mut().remove(&wc.wr_id) {
                let _ = tx.send(wc.status as i32);
            }
        }
        ibv_wc_opcode::IBV_WC_RDMA_WRITE | ibv_wc_opcode::IBV_WC_RDMA_READ => {
            if let Some(tx) = sock.completion.borrow_mut().remove(&wc.wr_id) {
                let _ = tx.send(wc.status as i32);
            }
        }
        ibv_wc_opcode::IBV_WC_RECV | ibv_wc_opcode::IBV_WC_RECV_RDMA_WITH_IMM => {
            let buf_idx = (wc.wr_id & ((1 << 56) - 1)) as u32;
            if imm_set {
                let imm = unsafe {
                    ImmData(u32::from_be(wc.imm_data_invalidated_rkey_union.imm_data))
                };
                match imm.ty() {
                    ImmType::Ack => {
                        let src   = imm.src();
                        let count = imm.count();
                        let mut per_peer = sock.per_peer.borrow_mut();
                        let entry = per_peer.entry(src).or_insert_with(PeerCredit::new);
                        entry.acked = entry.acked.wrapping_add(count as u64);
                        for _ in 0..count {
                            match entry.wakers.pop_front() {
                                Some(w) => { let _ = w.send(()); }
                                None    => break,
                            }
                        }
                    }
                    ImmType::Close | ImmType::Other => {}
                }
            } else {
                sock.recv_bufs.push(buf_idx, wc.byte_len);
                let _ = recv_tx.unbounded_send(());
            }
            let _ = sock.post_recv(buf_idx);
        }
        _ => {}
    }
}

unsafe fn transition_dci(qp: *mut ibv_qp, dev: &IbDevice, qos: RdmaQos) -> io::Result<()> {
    let mut a: ibv_qp_attr = mem::zeroed();
    a.qp_state = ibv_qp_state::IBV_QPS_INIT;
    a.port_num = PORT_NUM;
    let m = ibv_qp_attr_mask::IBV_QP_STATE.0
          | ibv_qp_attr_mask::IBV_QP_PKEY_INDEX.0
          | ibv_qp_attr_mask::IBV_QP_PORT.0;
    let rc = ibv_modify_qp(qp, &mut a, m as i32);
    if rc != 0 {
        return Err(io::Error::other(format!(
            "DCI INIT ibv_modify_qp rc={rc} errno={}", io::Error::last_os_error()
        )));
    }

    let mut a: ibv_qp_attr = mem::zeroed();
    a.qp_state                  = ibv_qp_state::IBV_QPS_RTR;
    a.path_mtu                  = dev.port_attr.active_mtu;
    a.ah_attr.is_global         = 1;
    a.ah_attr.port_num          = PORT_NUM;
    a.ah_attr.sl                = qos.service_level;
    a.ah_attr.grh.sgid_index    = dev.gid_index;
    a.ah_attr.grh.hop_limit     = 64;
    a.ah_attr.grh.traffic_class = qos.traffic_class;
    let m = ibv_qp_attr_mask::IBV_QP_STATE.0
          | ibv_qp_attr_mask::IBV_QP_PATH_MTU.0
          | ibv_qp_attr_mask::IBV_QP_AV.0;
    let rc = ibv_modify_qp(qp, &mut a, m as i32);
    if rc != 0 {
        return Err(io::Error::other(format!(
            "DCI RTR ibv_modify_qp rc={rc} errno={}", io::Error::last_os_error()
        )));
    }

    let mut a: ibv_qp_attr = mem::zeroed();
    a.qp_state      = ibv_qp_state::IBV_QPS_RTS;
    a.sq_psn        = 0;
    a.timeout       = QP_TIMEOUT;
    a.retry_cnt     = QP_RETRY_CNT;
    a.rnr_retry     = 0;
    a.max_rd_atomic = MAX_RD_ATOMIC;
    let m = ibv_qp_attr_mask::IBV_QP_STATE.0
          | ibv_qp_attr_mask::IBV_QP_SQ_PSN.0
          | ibv_qp_attr_mask::IBV_QP_TIMEOUT.0
          | ibv_qp_attr_mask::IBV_QP_RETRY_CNT.0
          | ibv_qp_attr_mask::IBV_QP_RNR_RETRY.0
          | ibv_qp_attr_mask::IBV_QP_MAX_QP_RD_ATOMIC.0;
    let rc = ibv_modify_qp(qp, &mut a, m as i32);
    if rc != 0 {
        return Err(io::Error::other(format!(
            "DCI RTS ibv_modify_qp rc={rc} errno={}", io::Error::last_os_error()
        )));
    }
    Ok(())
}
