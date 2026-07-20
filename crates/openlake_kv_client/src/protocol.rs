use std::cell::{Cell, RefCell};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::rc::Rc;
use std::sync::mpsc as sync_mpsc;
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use futures::channel::{mpsc, oneshot};
use futures::StreamExt;
use openlake_io::rdma::wire::{
    CommitEntry, Envelope, KeyHash, RdmaRequest, RdmaResponse, ENVELOPE_MAGIC,
};
use openlake_io::rdma::wr::SendKind;
use openlake_io::rdma::{
    ClusterRoutingTable, ExternalMr, PeerKey, PendingResponse, RdmaConfig, RdmaNode, RdmaQos,
    RdmaSetup, BUF_SIZE,
};
use openlake_io::rpc::{self, LocalRdmaEndpoint, RdmaEndpointsReply, Request, Response};

const SELF_DC_KEY: u64 = 0x4f4c;
const KEY_BYTES: usize = std::mem::size_of::<KeyHash>();
const VERB_TIMEOUT: Duration = Duration::from_secs(10);
const RPC_PATH: &str = "/v1/rpc";
const ATTACH_TIMEOUT: Duration = Duration::from_secs(10);

use crate::transport::{Protocol, Scatter, Waiter};

enum Cmd {
    Attach {
        addr: String,
        node_id: u16,
        slot_bytes: u32,
        reply: sync_mpsc::Sender<Result<usize, String>>,
    },
    Register {
        addr: u64,
        len: u64,
        reply: sync_mpsc::Sender<Result<(), String>>,
    },
    Exists {
        node: u16,
        keys: Vec<Vec<u8>>,
        reply: sync_mpsc::Sender<Result<Vec<i32>, String>>,
    },
    Put {
        node: u16,
        keys: Vec<Vec<u8>>,
        scatters: Vec<Scatter>,
        reply: sync_mpsc::Sender<Result<Vec<i32>, String>>,
    },
    Get {
        node: u16,
        keys: Vec<Vec<u8>>,
        scatters: Vec<Scatter>,
        reply: sync_mpsc::Sender<Result<Vec<i32>, String>>,
    },
    Reset {
        node: u16,
        reply: sync_mpsc::Sender<Result<(), String>>,
    },
}

pub struct RdmaProtocol {
    tx: Option<mpsc::UnboundedSender<Cmd>>,
    thread: Option<JoinHandle<()>>,
}

impl RdmaProtocol {
    pub fn new(device: String, client_id: u16) -> Result<Self, String> {
        let (tx, rx) = mpsc::unbounded();
        let (ready_tx, ready_rx) = sync_mpsc::channel();
        let cfg = config(device, client_id);

        let thread = thread::Builder::new()
            .name("openlake-client".into())
            .spawn(move || run(cfg, rx, ready_tx))
            .map_err(|e| format!("spawn client thread: {e}"))?;

        match ready_rx.recv() {
            Ok(Ok(())) => Ok(Self {
                tx: Some(tx),
                thread: Some(thread),
            }),
            Ok(Err(e)) => {
                let _ = thread.join();
                Err(e)
            }
            Err(_) => Err("client thread died during startup".into()),
        }
    }

    fn send(&self, cmd: Cmd) -> Result<(), String> {
        self.tx
            .as_ref()
            .ok_or("client is closed")?
            .unbounded_send(cmd)
            .map_err(|_| "client thread died".to_string())
    }

    fn begin<T>(
        &self,
        make: impl FnOnce(sync_mpsc::Sender<Result<T, String>>) -> Cmd,
    ) -> Result<sync_mpsc::Receiver<Result<T, String>>, String> {
        let (reply, wait) = sync_mpsc::channel();
        self.send(make(reply))?;
        Ok(wait)
    }

    fn roundtrip<T>(
        &self,
        make: impl FnOnce(sync_mpsc::Sender<Result<T, String>>) -> Cmd,
    ) -> Result<T, String> {
        self.begin(make)?
            .recv()
            .map_err(|_| "client thread died".to_string())?
    }
}

impl Protocol for RdmaProtocol {
    fn attach(&self, addr: &str, node_id: u16, slot_bytes: u32) -> Result<usize, String> {
        let addr = addr.to_owned();
        self.roundtrip(|reply| Cmd::Attach {
            addr,
            node_id,
            slot_bytes,
            reply,
        })
    }

    fn register_memory(&self, addr: u64, len: u64) -> Result<(), String> {
        self.roundtrip(|reply| Cmd::Register { addr, len, reply })
    }

    fn exists(&self, node: u16, keys: &[Vec<u8>]) -> Result<Waiter, String> {
        let keys = keys.to_vec();
        self.begin(|reply| Cmd::Exists { node, keys, reply })
    }

    fn put(&self, node: u16, keys: &[Vec<u8>], scatters: &[Scatter]) -> Result<Waiter, String> {
        let keys = keys.to_vec();
        let scatters = scatters.to_vec();
        self.begin(|reply| Cmd::Put {
            node,
            keys,
            scatters,
            reply,
        })
    }

    fn get(&self, node: u16, keys: &[Vec<u8>], scatters: &[Scatter]) -> Result<Waiter, String> {
        let keys = keys.to_vec();
        let scatters = scatters.to_vec();
        self.begin(|reply| Cmd::Get {
            node,
            keys,
            scatters,
            reply,
        })
    }

    fn reset(&self, node: u16) -> Result<(), String> {
        self.roundtrip(|reply| Cmd::Reset { node, reply })
    }

    fn close(&mut self) {
        self.tx = None;
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

impl Drop for RdmaProtocol {
    fn drop(&mut self) {
        self.close();
    }
}

fn config(device: String, client_id: u16) -> RdmaConfig {
    RdmaConfig {
        self_node_id: client_id,
        runtime_id: 0,
        dev_name: device,
        dc_key: SELF_DC_KEY,
        qos: RdmaQos {
            traffic_class: 0,
            service_level: 0,
        },
        bulk_buf_size: 64 * 1024,
        bulk_pool_cap: 12,
        num_cluster_nodes: 1,
        min_recv_bufs: usize::MAX,
        srq_depth: 4096,
        max_send_wr: 256,
        peer_credit: 4,
    }
}

enum Phase {
    Attaching {
        setup: RdmaSetup,
        routing: ClusterRoutingTable,
    },
    Ready {
        node: Rc<RdmaNode>,
    },
    Sealed,
}

struct Shared {
    cfg: RdmaConfig,
    endpoint: LocalRdmaEndpoint,
    phase: RefCell<Phase>,
    epoch: Cell<u64>,
    mrs: RefCell<Vec<ExternalMr>>,
}

fn run(
    cfg: RdmaConfig,
    mut rx: mpsc::UnboundedReceiver<Cmd>,
    ready: sync_mpsc::Sender<Result<(), String>>,
) {
    let rt = match runtime() {
        Ok(rt) => rt,
        Err(e) => {
            let _ = ready.send(Err(e));
            return;
        }
    };

    rt.block_on(async move {
        let (setup, endpoint) = match RdmaNode::start_local(&cfg) {
            Ok(v) => v,
            Err(e) => {
                let _ = ready.send(Err(format!("rdma start_local: {e}")));
                return;
            }
        };
        let _ = ready.send(Ok(()));

        let routing = ClusterRoutingTable::new(cfg.self_node_id);
        let shared = Rc::new(Shared {
            cfg,
            endpoint,
            phase: RefCell::new(Phase::Attaching { setup, routing }),
            epoch: Cell::new(0),
            mrs: RefCell::new(Vec::new()),
        });

        while let Some(cmd) = rx.next().await {
            let s = shared.clone();
            compio::runtime::spawn(async move { handle(s, cmd).await }).detach();
        }
    });
}

async fn handle(s: Rc<Shared>, cmd: Cmd) {
    match cmd {
        Cmd::Attach {
            addr,
            node_id,
            slot_bytes,
            reply,
        } => {
            let _ = reply.send(do_attach(&s, &addr, node_id, slot_bytes));
        }
        Cmd::Register { addr, len, reply } => {
            let out = if s
                .mrs
                .borrow()
                .iter()
                .any(|m| m.addr == addr && m.len == len)
            {
                Ok(())
            } else {
                ExternalMr::register(device_of(&s), addr, len)
                    .map(|mr| s.mrs.borrow_mut().push(mr))
                    .map_err(|e| format!("register {addr:#x}+{len}: {e}"))
            };
            let _ = reply.send(out);
        }
        Cmd::Exists { node, keys, reply } => {
            let _ = reply.send(do_exists(&s, node, keys).await);
        }
        Cmd::Put {
            node,
            keys,
            scatters,
            reply,
        } => {
            let _ = reply.send(do_put(&s, node, keys, scatters).await);
        }
        Cmd::Get {
            node,
            keys,
            scatters,
            reply,
        } => {
            let _ = reply.send(do_get(&s, node, keys, scatters).await);
        }
        Cmd::Reset { node, reply } => {
            let _ = reply.send(do_reset(&s, node).await);
        }
    }
}

async fn do_reset(s: &Shared, node_id: u16) -> Result<(), String> {
    let node = ensure_ready(s)?;
    match unary(&node, node_id, RdmaRequest::Reset).await? {
        RdmaResponse::ResetDone => Ok(()),
        other => Err(format!("unexpected reset reply: {other:?}")),
    }
}

fn device_of(s: &Shared) -> Rc<openlake_io::rdma::IbDevice> {
    match &*s.phase.borrow() {
        Phase::Attaching { setup, .. } => setup.dev.clone(),
        Phase::Ready { node } => node.dev.clone(),
        Phase::Sealed => unreachable!("sealed phase"),
    }
}

fn do_attach(s: &Shared, addr: &str, node_id: u16, slot_bytes: u32) -> Result<usize, String> {
    let mut phase = s.phase.borrow_mut();
    let Phase::Attaching { routing, .. } = &mut *phase else {
        return Err("attach after first operation".into());
    };
    s.epoch.set(s.epoch.get() + 1);
    let reply = attach(
        addr,
        s.cfg.self_node_id,
        s.epoch.get(),
        vec![s.endpoint],
        slot_bytes,
    )?;
    for ep in &reply.endpoints {
        routing.insert(node_id, ep);
    }
    Ok(routing.len())
}

fn ensure_ready(s: &Shared) -> Result<Rc<RdmaNode>, String> {
    if let Phase::Ready { node } = &*s.phase.borrow() {
        return Ok(node.clone());
    }
    let mut phase = s.phase.borrow_mut();
    match std::mem::replace(&mut *phase, Phase::Sealed) {
        Phase::Attaching { setup, routing } => {
            if routing.is_empty() {
                *phase = Phase::Attaching { setup, routing };
                return Err("no nodes attached".into());
            }
            let node = Rc::new(RdmaNode::finalize(&s.cfg, setup, Arc::new(routing)));
            let rx = node
                .pump
                .take_recv_rx()
                .ok_or("recv channel already taken")?;
            compio::runtime::spawn(dispatch(node.clone(), rx)).detach();
            *phase = Phase::Ready { node: node.clone() };
            Ok(node)
        }
        Phase::Ready { node } => {
            *phase = Phase::Ready { node: node.clone() };
            Ok(node)
        }
        Phase::Sealed => unreachable!("sealed phase"),
    }
}

async fn dispatch(node: Rc<RdmaNode>, mut rx: mpsc::UnboundedReceiver<()>) {
    let mut buf = Vec::with_capacity(BUF_SIZE);
    loop {
        loop {
            buf.clear();
            if node.sock.attempt_singular_rcv(&mut buf).is_none() {
                break;
            }
            match rpc::decode::<Envelope>(&buf) {
                Ok(Envelope::Rsp {
                    magic,
                    request_id,
                    payload,
                }) => {
                    if magic != ENVELOPE_MAGIC {
                        tracing::warn!("client: bad response magic {magic:#x}");
                        continue;
                    }
                    if let Some(p) = node.pending_responses.borrow_mut().remove(&request_id) {
                        if let Err(e) =
                            node.sock
                                .note_drain(p.peer, p.ah, p.peer_dct_num, p.peer_dc_key)
                        {
                            tracing::warn!("client: note_drain: {e}");
                        }
                        let _ = p.tx.send(payload);
                    }
                }
                Ok(Envelope::Req { .. }) => tracing::warn!("client: unexpected request envelope"),
                Err(e) => tracing::warn!("client: decode: {e}"),
            }
        }
        if rx.next().await.is_none() {
            return;
        }
    }
}

async fn unary(
    node: &Rc<RdmaNode>,
    peer_node: u16,
    payload: RdmaRequest,
) -> Result<RdmaResponse, String> {
    let peer = node
        .peer(peer_node)
        .ok_or_else(|| format!("node {peer_node} not attached"))?
        .clone();
    let ah = node
        .ah_cache
        .get_or_create(&peer)
        .map_err(|e| format!("ah for node {peer_node}: {e}"))?;
    let peer_key = PeerKey::new(peer_node, node.runtime_id);

    let request_id = {
        let id = node.next_request_id.get();
        node.next_request_id.set(id + 1);
        id
    };
    let (tx, rx) = oneshot::channel();
    node.pending_responses.borrow_mut().insert(
        request_id,
        PendingResponse {
            tx,
            peer: peer_key,
            ah,
            peer_dct_num: peer.dct_num,
            peer_dc_key: peer.dc_key,
        },
    );

    let env = Envelope::Req {
        magic: ENVELOPE_MAGIC,
        from_node_id: node.self_id,
        from_runtime_id: node.runtime_id,
        request_id,
        payload,
    };
    let body = rpc::encode(&env).map_err(|e| format!("encode: {e}"))?;
    if let Err(e) = node
        .sock
        .send_with_kind(
            &body,
            peer_key,
            ah,
            peer.dct_num,
            peer.dc_key,
            SendKind::Unary,
        )
        .await
    {
        node.pending_responses.borrow_mut().remove(&request_id);
        return Err(format!("send to node {peer_node}: {e}"));
    }

    match compio::time::timeout(VERB_TIMEOUT, rx).await {
        Ok(Ok(resp)) => Ok(resp),
        Ok(Err(_)) => Err("dispatcher dropped waiter".into()),
        Err(_) => {
            node.pending_responses.borrow_mut().remove(&request_id);
            Err(format!(
                "node {peer_node}: response timeout ({VERB_TIMEOUT:?})"
            ))
        }
    }
}

pub(crate) fn oltrace() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("OPENLAKE_TRACE").is_some())
}

fn to_key_hashes(keys: &[Vec<u8>]) -> Result<Vec<KeyHash>, String> {
    keys.iter()
        .enumerate()
        .map(|(i, k)| {
            <KeyHash>::try_from(k.as_slice())
                .map_err(|_| format!("key {i}: {} bytes, want {KEY_BYTES}", k.len()))
        })
        .collect()
}

fn resolve_plans(
    s: &Shared,
    scatters: &[Scatter],
    payload_cap: u64,
) -> Result<Vec<Vec<(u64, u32, u32)>>, String> {
    let mrs = s.mrs.borrow();
    scatters
        .iter()
        .enumerate()
        .map(|(i, scatter)| {
            let total: u64 = scatter.iter().map(|&(_, len)| len).sum();
            if total == 0 || total > payload_cap {
                return Err(format!(
                    "key {i}: payload {total} not in (0, {payload_cap}]"
                ));
            }
            let mut cur = 0usize;
            let mut plan = Vec::with_capacity(scatter.len());
            for &(addr, len) in scatter {
                if len == 0 || len > u32::MAX as u64 {
                    return Err(format!("key {i}: invalid strip length {len}"));
                }
                if !mrs.get(cur).is_some_and(|m| m.contains(addr, len)) {
                    cur = if mrs.get(cur + 1).is_some_and(|m| m.contains(addr, len)) {
                        cur + 1
                    } else if let Some(k) = mrs.iter().position(|m| m.contains(addr, len)) {
                        k
                    } else {
                        return Err(format!("key {i}: address {addr:#x} not registered"));
                    };
                }
                plan.push((addr, len as u32, mrs[cur].lkey()));
            }
            Ok(plan)
        })
        .collect()
}

async fn do_put(
    s: &Shared,
    node_id: u16,
    keys: Vec<Vec<u8>>,
    scatters: Vec<Scatter>,
) -> Result<Vec<i32>, String> {
    let node = ensure_ready(s)?;
    let key_hashes = to_key_hashes(&keys)?;
    let peer = node
        .peer(node_id)
        .ok_or_else(|| format!("node {node_id} not attached"))?
        .clone();
    let slab = peer
        .kv_slab
        .ok_or_else(|| format!("node {node_id} has no kv slab"))?;
    let ah = node
        .ah_cache
        .get_or_create(&peer)
        .map_err(|e| format!("ah for node {node_id}: {e}"))?;

    let payload_cap = slab.slot_bytes as u64 - KEY_BYTES as u64;
    let t0 = std::time::Instant::now();
    let plans = resolve_plans(s, &scatters, payload_cap)?;
    let t_resolve = t0.elapsed();
    if keys.is_empty() {
        return Ok(Vec::new());
    }

    let t1 = std::time::Instant::now();
    let mut staging = node
        .bulk_pool
        .acquire()
        .await
        .map_err(|e| format!("staging: {e}"))?;
    let t_staging = t1.elapsed();
    if keys.len() * KEY_BYTES > staging.capacity() {
        return Err(format!("batch too large: {} keys", keys.len()));
    }

    let t2 = std::time::Instant::now();
    let slots = match unary(
        &node,
        node_id,
        RdmaRequest::BatchReserve {
            count: keys.len() as u32,
        },
    )
    .await?
    {
        RdmaResponse::BatchReserved { slots } => slots,
        other => return Err(format!("unexpected reserve reply: {other:?}")),
    };
    let t_reserve = t2.elapsed();
    if slots.len() < keys.len() {
        let got = slots.len();
        let _ = unary(
            &node,
            node_id,
            RdmaRequest::BatchRelease { slot_idxs: slots },
        )
        .await;
        return Err(format!(
            "store full: reserved {got} of {} slots",
            keys.len()
        ));
    }

    let t3 = std::time::Instant::now();
    let mut ops: Vec<(u64, u32, u32, u64)> =
        Vec::with_capacity(keys.len() + plans.iter().map(Vec::len).sum::<usize>());
    for (j, (key_hash, &slot)) in key_hashes.iter().zip(&slots).enumerate() {
        let dst = slab.slab_base + slot as u64 * slab.slot_bytes as u64;
        staging.as_slice_mut()[j * KEY_BYTES..(j + 1) * KEY_BYTES].copy_from_slice(key_hash);
        ops.push((
            staging.addr() + (j * KEY_BYTES) as u64,
            KEY_BYTES as u32,
            staging.lkey(),
            dst,
        ));
        let mut off = KEY_BYTES as u64;
        for &(addr, len, lkey) in &plans[j] {
            ops.push((addr, len, lkey, dst + off));
            off += len as u64;
        }
    }
    let t_build = t3.elapsed();
    let t4 = std::time::Instant::now();
    if let Err(e) = node
        .sock
        .rdma_chain(true, &ops, slab.rkey, ah, peer.dct_num, peer.dc_key)
        .await
    {
        let _ = unary(
            &node,
            node_id,
            RdmaRequest::BatchRelease { slot_idxs: slots },
        )
        .await;
        return Err(format!("write failed; batch aborted: {e}"));
    }
    let t_chain = t4.elapsed();
    let commits: Vec<CommitEntry> = key_hashes
        .iter()
        .zip(&slots)
        .map(|(key_hash, &slot)| CommitEntry {
            slot_idx: slot,
            key_hash: key_hash.to_vec(),
        })
        .collect();

    let t5 = std::time::Instant::now();
    match unary(
        &node,
        node_id,
        RdmaRequest::BatchCommit { entries: commits },
    )
    .await?
    {
        RdmaResponse::BatchCommitted => {}
        other => return Err(format!("unexpected commit reply: {other:?}")),
    }
    if oltrace() {
        let bytes: u64 = ops.iter().map(|o| o.1 as u64).sum();
        eprintln!(
            "OLTRACE put node={node_id} keys={} ops={} bytes={bytes} resolve_us={} staging_us={} reserve_us={} build_us={} chain_us={} commit_us={} total_us={}",
            keys.len(),
            ops.len(),
            t_resolve.as_micros(),
            t_staging.as_micros(),
            t_reserve.as_micros(),
            t_build.as_micros(),
            t_chain.as_micros(),
            t5.elapsed().as_micros(),
            t0.elapsed().as_micros(),
        );
    }
    Ok(vec![0i32; keys.len()])
}

async fn do_get(
    s: &Shared,
    node_id: u16,
    keys: Vec<Vec<u8>>,
    scatters: Vec<Scatter>,
) -> Result<Vec<i32>, String> {
    let node = ensure_ready(s)?;
    let key_hashes = to_key_hashes(&keys)?;
    let peer = node
        .peer(node_id)
        .ok_or_else(|| format!("node {node_id} not attached"))?
        .clone();
    let slab = peer
        .kv_slab
        .ok_or_else(|| format!("node {node_id} has no kv slab"))?;
    let ah = node
        .ah_cache
        .get_or_create(&peer)
        .map_err(|e| format!("ah for node {node_id}: {e}"))?;

    let payload_cap = slab.slot_bytes as u64 - KEY_BYTES as u64;
    let plans = resolve_plans(s, &scatters, payload_cap)?;
    if keys.is_empty() {
        return Ok(Vec::new());
    }
    let mut out = vec![0i32; keys.len()];

    let staging = node
        .bulk_pool
        .acquire()
        .await
        .map_err(|e| format!("staging: {e}"))?;
    if keys.len() * KEY_BYTES > staging.capacity() {
        return Err(format!("batch too large: {} keys", keys.len()));
    }

    let tg = std::time::Instant::now();
    let slots = match unary(
        &node,
        node_id,
        RdmaRequest::BatchLookup {
            key_hashes: key_hashes.iter().map(|k| k.to_vec()).collect(),
        },
    )
    .await?
    {
        RdmaResponse::BatchLookedUp { slots } => slots,
        other => return Err(format!("unexpected lookup reply: {other:?}")),
    };
    let t_lookup = tg.elapsed();
    if slots.len() != keys.len() {
        return Err(format!("{} slots for {} keys", slots.len(), keys.len()));
    }

    let mut ops: Vec<(u64, u32, u32, u64)> = Vec::new();
    for (j, slot) in slots.iter().enumerate() {
        let Some(slot) = slot else {
            out[j] = -1;
            continue;
        };
        let dst = slab.slab_base + *slot as u64 * slab.slot_bytes as u64;
        let mut off = KEY_BYTES as u64;
        for &(addr, len, lkey) in &plans[j] {
            ops.push((addr, len, lkey, dst + off));
            off += len as u64;
        }
        ops.push((
            staging.addr() + (j * KEY_BYTES) as u64,
            KEY_BYTES as u32,
            staging.lkey(),
            dst,
        ));
    }
    let tc = std::time::Instant::now();
    if !ops.is_empty() {
        node.sock
            .rdma_chain(false, &ops, slab.rkey, ah, peer.dct_num, peer.dc_key)
            .await
            .map_err(|e| format!("read failed: {e}"))?;
    }
    let t_chain = tc.elapsed();
    for (j, slot) in slots.iter().enumerate() {
        if slot.is_some() && staging.as_slice()[j * KEY_BYTES..(j + 1) * KEY_BYTES] != key_hashes[j]
        {
            out[j] = -1;
        }
    }
    if oltrace() {
        let bytes: u64 = ops.iter().map(|o| o.1 as u64).sum();
        eprintln!(
            "OLTRACE get node={node_id} keys={} ops={} bytes={bytes} lookup_us={} chain_us={} total_us={}",
            keys.len(),
            ops.len(),
            t_lookup.as_micros(),
            t_chain.as_micros(),
            tg.elapsed().as_micros(),
        );
    }
    Ok(out)
}

async fn do_exists(s: &Shared, node_id: u16, keys: Vec<Vec<u8>>) -> Result<Vec<i32>, String> {
    let node = ensure_ready(s)?;
    let key_hashes = to_key_hashes(&keys)?;
    let key_hashes = key_hashes.iter().map(|k| k.to_vec()).collect();
    match unary(&node, node_id, RdmaRequest::BatchLookup { key_hashes }).await? {
        RdmaResponse::BatchLookedUp { slots } => {
            if slots.len() != keys.len() {
                return Err(format!("{} slots for {} keys", slots.len(), keys.len()));
            }
            Ok(slots.iter().map(|slot| slot.is_some() as i32).collect())
        }
        other => Err(format!("unexpected lookup reply: {other:?}")),
    }
}

fn runtime() -> Result<compio::runtime::Runtime, String> {
    let mut proactor = compio::driver::ProactorBuilder::new();
    proactor
        .capacity(4096)
        .coop_taskrun(false)
        .taskrun_flag(false);
    #[cfg(not(target_os = "macos"))]
    proactor.thread_pool_limit(0);

    compio::runtime::RuntimeBuilder::new()
        .with_proactor(proactor)
        .event_interval(32)
        .build()
        .map_err(|e| format!("build compio runtime: {e}"))
}

fn attach(
    addr: &str,
    client_node_id: u16,
    epoch: u64,
    endpoints: Vec<LocalRdmaEndpoint>,
    slot_bytes: u32,
) -> Result<RdmaEndpointsReply, String> {
    let body = rpc::encode(&Request::RdmaAttach {
        client_node_id,
        epoch,
        endpoints,
        slot_bytes,
    })
    .map_err(|e| format!("encode attach: {e}"))?;

    match rpc::decode::<Response>(&post(addr, &body)?).map_err(|e| format!("decode reply: {e}"))? {
        Response::RdmaAttached(reply) => Ok(reply),
        Response::RdmaAttachDenied(why) => Err(format!("attach denied by {addr}: {why}")),
        other => Err(format!("unexpected attach reply from {addr}: {other:?}")),
    }
}

fn post(addr: &str, body: &[u8]) -> Result<Vec<u8>, String> {
    let mut sock = TcpStream::connect(addr).map_err(|e| format!("connect {addr}: {e}"))?;
    sock.set_read_timeout(Some(ATTACH_TIMEOUT)).ok();
    sock.set_write_timeout(Some(ATTACH_TIMEOUT)).ok();

    let head = format!(
        "POST {RPC_PATH} HTTP/1.1\r\nhost: {addr}\r\n\
         content-type: application/octet-stream\r\n\
         content-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    );
    sock.write_all(head.as_bytes())
        .and_then(|()| sock.write_all(body))
        .map_err(|e| format!("send to {addr}: {e}"))?;

    let mut raw = Vec::new();
    sock.read_to_end(&mut raw)
        .map_err(|e| format!("recv from {addr}: {e}"))?;

    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| format!("{addr}: response has no header terminator"))?;
    let status = raw[..split]
        .split(|&b| b == b'\r')
        .next()
        .and_then(|l| std::str::from_utf8(l).ok())
        .unwrap_or_default();
    if !status.contains(" 200 ") {
        return Err(format!("{addr}: http status {status:?}"));
    }
    Ok(raw[split + 4..].to_vec())
}
