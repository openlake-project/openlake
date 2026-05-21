use std::collections::HashMap;
use std::io;
use std::mem;
use std::ptr::{self, NonNull};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use futures::channel::{mpsc, oneshot};

use rdma_mummy_sys::{
    ibv_access_flags, ibv_ack_cq_events, ibv_ah, ibv_comp_channel, ibv_cq,
    ibv_create_comp_channel, ibv_create_cq, ibv_create_srq, ibv_destroy_comp_channel,
    ibv_destroy_cq, ibv_destroy_qp, ibv_destroy_srq, ibv_get_cq_event, ibv_modify_qp,
    ibv_poll_cq, ibv_post_srq_recv, ibv_qp, ibv_qp_attr, ibv_qp_attr_mask,
    ibv_qp_init_attr_ex, ibv_qp_state, ibv_qp_to_qp_ex, ibv_qp_type, ibv_recv_wr,
    ibv_req_notify_cq, ibv_send_flags, ibv_sge, ibv_srq, ibv_srq_init_attr, ibv_wc,
    ibv_wc_flags, ibv_wc_opcode, ibv_wc_status, ibv_wr_complete, ibv_wr_rdma_read,
    ibv_wr_rdma_write, ibv_wr_send, ibv_wr_send_imm, ibv_wr_set_sge, ibv_wr_start,
};

use super::buffers::{
    RecvBuffers, SendBuffers, BUF_ACK_BATCH, BUF_SIGNAL_BATCH, BUF_SIZE, SEND_BUF_CNT,
};
use super::device::{IbDevice, PORT_NUM};
use super::node::RdmaQos;
use super::mlx5dv_sys::{
    mlx5dv_create_qp, mlx5dv_qp_ex_from_ibv_qp_ex, mlx5dv_qp_init_attr,
    mlx5dv_dc_type_MLX5DV_DCTYPE_DCT, mlx5dv_dc_type_MLX5DV_DCTYPE_DCI,
    mlx5dv_qp_init_attr_mask_MLX5DV_QP_INIT_ATTR_MASK_DC,
};
use super::wr::{ImmData, ImmType, WrId, WrType};

const CQ_DEPTH:        i32 = 4096;
const MAX_SEND_WR:     u32 = 256;
const SRQ_DEPTH:       u32 = 64;
const MAX_RD_ATOMIC:   u8  = 16;
const MIN_RNR_TIMER:   u8  = 1;
const QP_TIMEOUT:      u8  = 14;
const QP_RETRY_CNT:    u8  = 7;

pub struct IbSocket {
    pub(super) dev:          Arc<IbDevice>,
    pub(super) cq:           NonNull<ibv_cq>,
    pub(super) comp_channel: NonNull<ibv_comp_channel>,
    pub(super) srq:          NonNull<ibv_srq>,
    pub(super) dct:          NonNull<ibv_qp>,
    pub(super) dci:          NonNull<ibv_qp>,
    pub(super) send_bufs:    SendBuffers,
    pub(super) recv_bufs:    RecvBuffers,
    pub(super) dc_key:       u64,
    pub(super) self_dct_identifier:   u32,

    // Credit accounting, mutated by the CQ pump.
    pub(super) send_signaled:     AtomicU64,
    pub(super) send_acked:        AtomicU64,
    pub(super) send_not_signaled: AtomicU32,
    pub(super) recv_not_acked:    AtomicU32,

    // Serialize ibv_wr_start..ibv_wr_complete on the DCI.
    pub(super) post_mu: Mutex<()>,

    // Per-wr_id completion waiters for one-sided RDMA WRITE/READ.
    pub(super) completion: Mutex<HashMap<u64, oneshot::Sender<i32>>>,
    pub(super) next_wr_id: AtomicU64,
}

unsafe impl Send for IbSocket {}
unsafe impl Sync for IbSocket {}

impl IbSocket {
    pub fn self_dct_identifier(&self) -> u32 { self.self_dct_identifier }

    pub fn new(dev: Arc<IbDevice>, dc_key: u64, qos: RdmaQos) -> io::Result<Self> {
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

            let send_bufs = SendBuffers::new(dev.pd.as_ptr(), SEND_BUF_CNT, BUF_SIZE)?;
            let recv_bufs = RecvBuffers::new(dev.pd.as_ptr(), SEND_BUF_CNT, BUF_SIZE)?;

            let sock = IbSocket {
                dev, cq, comp_channel, srq, dct, dci,
                send_bufs, recv_bufs, dc_key, self_dct_identifier,
                send_signaled:     AtomicU64::new(0),
                send_acked:        AtomicU64::new(0),
                send_not_signaled: AtomicU32::new(0),
                recv_not_acked:    AtomicU32::new(0),
                post_mu:           Mutex::new(()),
                completion:        Mutex::new(HashMap::new()),
                next_wr_id:        AtomicU64::new(1),
            };
            for i in 0..SEND_BUF_CNT { sock.post_recv(i as u32)?; }
            Ok(sock)
        }
    }

    pub fn send(
        &self, mut buf: &[u8], ah: *mut ibv_ah, peer_dct_num: u32, peer_dc_key: u64,
    ) -> io::Result<usize> {
        let mut total = 0;
        let bs = BUF_SIZE;
        while !buf.is_empty() {
            let Some(idx) = self.send_bufs.try_pop() else { break; };
            let n = buf.len().min(bs);
            unsafe {
                // todo: @arnav revisit memcp here
                ptr::copy_nonoverlapping(
                    buf.as_ptr(),
                    self.send_bufs.base().slot_ptr(idx),
                    n,
                );
            }
            self.post_send(idx as u32, n as u32, ah, peer_dct_num, peer_dc_key)?;
            total += n;
            buf = &buf[n..];
        }
        Ok(total)
    }

    /// Pop one fully-received envelope from the recv queue. Used by the
    /// rdma_server dispatcher which awaits notification from the pump
    /// and then drains envelopes one at a time.
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

    pub fn recv(
        &self, mut out: &mut [u8], ah: *mut ibv_ah, peer_dct_num: u32, peer_dc_key: u64,
    ) -> io::Result<usize> {
        let mut total = 0;
        while !out.is_empty() {
            let Some((idx, len)) = self.recv_bufs.pop() else { break; };
            let n = (len as usize).min(out.len());
            unsafe {
                // todo: @arnav revisit memcp here
                ptr::copy_nonoverlapping(
                    self.recv_bufs.base().slot_ptr(idx as usize),
                    out.as_mut_ptr(),
                    n,
                );
            }
            out = &mut out[n..];
            total += n;
            let prev = self.recv_not_acked.fetch_add(1, Ordering::Relaxed) + 1;
            if prev >= BUF_ACK_BATCH {
                self.recv_not_acked.store(0, Ordering::Relaxed);
                self.post_ack(ah, peer_dct_num, peer_dc_key)?;
            }
        }
        Ok(total)
    }

    pub async fn rdma_write(
        &self,
        local_addr: u64, local_len: u32, local_lkey: u32,
        remote_addr: u64, remote_rkey: u32,
        ah: *mut ibv_ah, peer_dct_num: u32, peer_dc_key: u64,
    ) -> io::Result<()> {
        let wr_id = self.next_wr_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.completion.lock().unwrap().insert(wr_id, tx);
        {
            let _g = self.post_mu.lock().unwrap();
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
                    self.completion.lock().unwrap().remove(&wr_id);
                    return Err(io::Error::from_raw_os_error(rc));
                }
            }
        }
        let status = rx.await.map_err(|_| io::Error::other("pump dropped"))?;
        if status != 0 { return Err(io::Error::other(format!("rdma_write wc.status={status}"))); }
        Ok(())
    }

    pub async fn rdma_read(
        &self,
        local_addr: u64, local_len: u32, local_lkey: u32,
        remote_addr: u64, remote_rkey: u32,
        ah: *mut ibv_ah, peer_dct_num: u32, peer_dc_key: u64,
    ) -> io::Result<()> {
        let wr_id = self.next_wr_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.completion.lock().unwrap().insert(wr_id, tx);
        {
            let _g = self.post_mu.lock().unwrap();
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
                    self.completion.lock().unwrap().remove(&wr_id);
                    return Err(io::Error::from_raw_os_error(rc));
                }
            }
        }
        let status = rx.await.map_err(|_| io::Error::other("pump dropped"))?;
        if status != 0 { return Err(io::Error::other(format!("rdma_read wc.status={status}"))); }
        Ok(())
    }

    pub(super) fn post_send(
        &self, buf_idx: u32, len: u32, ah: *mut ibv_ah, peer_dct_num: u32, peer_dc_key: u64,
    ) -> io::Result<()> {
        let prev = self.send_not_signaled.fetch_add(1, Ordering::Relaxed) + 1;
        let signal = if prev >= BUF_SIGNAL_BATCH {
            self.send_not_signaled.store(0, Ordering::Relaxed);
            prev
        } else { 0 };
        let _g = self.post_mu.lock().unwrap();
        unsafe {
            let qpx  = ibv_qp_to_qp_ex(self.dci.as_ptr());
            let mqpx = mlx5dv_qp_ex_from_ibv_qp_ex(qpx);
            ibv_wr_start(qpx);
            (*qpx).wr_id    = WrId::send(signal).0;
            (*qpx).wr_flags = if signal > 0 { ibv_send_flags::IBV_SEND_SIGNALED.0 as u32 } else { 0 };
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
        &self, ah: *mut ibv_ah, peer_dct_num: u32, peer_dc_key: u64,
    ) -> io::Result<()> {
        let _g = self.post_mu.lock().unwrap();
        unsafe {
            let qpx  = ibv_qp_to_qp_ex(self.dci.as_ptr());
            let mqpx = mlx5dv_qp_ex_from_ibv_qp_ex(qpx);
            ibv_wr_start(qpx);
            (*qpx).wr_id    = WrId::ack().0;
            (*qpx).wr_flags = ibv_send_flags::IBV_SEND_SIGNALED.0 as u32;
            ibv_wr_send_imm(qpx, ImmData::ack(BUF_ACK_BATCH).0.to_be());
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
    sock:    Arc<IbSocket>,
    recv_rx: Mutex<Option<mpsc::UnboundedReceiver<()>>>,
}

impl CqPump {
    pub fn start(sock: Arc<IbSocket>) -> io::Result<Self> {
        let fd = unsafe { (*sock.comp_channel.as_ptr()).fd };
        let (tx, rx) = mpsc::unbounded();
        let s = sock.clone();
        let task = compio::runtime::spawn(async move { run_pump_compio(s, fd, tx).await });
        Ok(CqPump { _task: task, sock, recv_rx: Mutex::new(Some(rx)) })
    }
    pub fn socket(&self) -> &Arc<IbSocket> { &self.sock }
    pub fn take_recv_rx(&self) -> Option<mpsc::UnboundedReceiver<()>> {
        self.recv_rx.lock().unwrap().take()
    }
}

const WC_BATCH: i32 = 16;

struct CompChannelFd(std::os::fd::RawFd);
impl std::os::fd::AsFd for CompChannelFd {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        unsafe { std::os::fd::BorrowedFd::borrow_raw(self.0) }
    }
}

async fn run_pump_compio(sock: Arc<IbSocket>, fd: std::os::fd::RawFd, recv_tx: mpsc::UnboundedSender<()>) {
    let mut wcs: [ibv_wc; WC_BATCH as usize] = unsafe { mem::zeroed() };
    loop {
        let op = compio::driver::op::PollOnce::new(
            CompChannelFd(fd),
            compio::driver::op::Interest::Readable,
        );
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
                reconcile_credit(&sock);
            }
        }
    }
}

fn handle_wc(sock: &IbSocket, wc: &ibv_wc, recv_tx: &mpsc::UnboundedSender<()>) {
    let status_ok = wc.status == ibv_wc_status::IBV_WC_SUCCESS;
    let wr = WrId(wc.wr_id);
    let imm_set = (wc.wc_flags & ibv_wc_flags::IBV_WC_WITH_IMM.0) != 0;
    match wc.opcode {
        ibv_wc_opcode::IBV_WC_SEND => {
            if status_ok && wr.ty() == WrType::Send {
                let n = wr.signal_count() as u64;
                if n > 0 { sock.send_signaled.fetch_add(n, Ordering::Relaxed); }
            }
        }
        ibv_wc_opcode::IBV_WC_RDMA_WRITE | ibv_wc_opcode::IBV_WC_RDMA_READ => {
            if let Some(tx) = sock.completion.lock().unwrap().remove(&wc.wr_id) {
                let _ = tx.send(wc.status as i32);
            }
        }
        ibv_wc_opcode::IBV_WC_RECV | ibv_wc_opcode::IBV_WC_RECV_RDMA_WITH_IMM => {
            if !status_ok { return; }
            let buf_idx = (wc.wr_id & ((1 << 56) - 1)) as u32;
            if imm_set {
                let imm = unsafe {
                    ImmData(u32::from_be(wc.imm_data_invalidated_rkey_union.imm_data))
                };
                if imm.ty() == ImmType::Ack {
                    sock.send_acked.fetch_add(imm.data() as u64, Ordering::Relaxed);
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

fn reconcile_credit(sock: &IbSocket) {
    let signaled = sock.send_signaled.load(Ordering::Relaxed);
    let acked    = sock.send_acked.load(Ordering::Relaxed);
    let avail    = signaled.min(acked);
    if avail > 0 {
        sock.send_signaled.fetch_sub(avail, Ordering::Relaxed);
        sock.send_acked   .fetch_sub(avail, Ordering::Relaxed);
        sock.send_bufs.push(avail);
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
