#![cfg(all(feature = "rdma", target_os = "linux"))]

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::rc::Rc;
use std::sync::mpsc as sync_mpsc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use futures::channel::{mpsc, oneshot};
use futures::future::try_join_all;
use futures::StreamExt;
use openlake_io::kv_wire::{CommitEntry, Envelope, RdmaRequest, RdmaResponse, ENVELOPE_MAGIC};
use openlake_io::rpc::{self, Request, Response, UcxEndpointReply, UCX_PROTOCOL_VERSION};
use openlake_io::ucx::{UcxEndpoint, UcxMemory, UcxRequest, UcxRkey, UcxWorker};

use crate::transport::{Protocol, Scatter, Waiter};

const KEY_BYTES: usize = 54;
const ATTACH_TIMEOUT: Duration = Duration::from_secs(60);
const OPERATION_TIMEOUT: Duration = Duration::from_secs(60);
const RPC_PATH: &str = "/v1/rpc";

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

struct Node {
    rkey: Option<UcxRkey>,
    endpoint: UcxEndpoint,
    slab_base: u64,
    slot_bytes: u32,
}

struct RegisteredMemory {
    start: u64,
    len: u64,
    _memory: UcxMemory,
}

impl RegisteredMemory {
    fn contains(&self, address: u64, length: u64) -> bool {
        address >= self.start
            && address
                .checked_add(length)
                .is_some_and(|end| end <= self.start.saturating_add(self.len))
    }
}

struct Shared {
    client_id: u16,
    epoch: Cell<u64>,
    next_request_id: Cell<u64>,
    worker: UcxWorker,
    nodes: RefCell<HashMap<u16, Rc<Node>>>,
    memory: RefCell<Vec<RegisteredMemory>>,
    pending: RefCell<HashMap<u64, oneshot::Sender<Result<RdmaResponse, String>>>>,
    control_error: RefCell<Option<String>>,
}

pub struct UcxProtocol {
    tx: Option<mpsc::UnboundedSender<Cmd>>,
    thread: Option<JoinHandle<()>>,
}

impl UcxProtocol {
    pub fn new(client_id: u16) -> Result<Self, String> {
        let (tx, rx) = mpsc::unbounded();
        let (ready_tx, ready_rx) = sync_mpsc::channel();
        let thread = thread::Builder::new()
            .name("openlake-ucx-client".into())
            .spawn(move || run(client_id, rx, ready_tx))
            .map_err(|e| format!("spawn UCX client thread: {e}"))?;
        match ready_rx.recv() {
            Ok(Ok(())) => Ok(Self {
                tx: Some(tx),
                thread: Some(thread),
            }),
            Ok(Err(error)) => {
                let _ = thread.join();
                Err(error)
            }
            Err(_) => Err("UCX client thread died during startup".into()),
        }
    }

    fn begin<T>(
        &self,
        make: impl FnOnce(sync_mpsc::Sender<Result<T, String>>) -> Cmd,
    ) -> Result<sync_mpsc::Receiver<Result<T, String>>, String> {
        let (reply, wait) = sync_mpsc::channel();
        self.tx
            .as_ref()
            .ok_or("UCX client is closed")?
            .unbounded_send(make(reply))
            .map_err(|_| "UCX client thread died".to_string())?;
        Ok(wait)
    }

    fn roundtrip<T>(
        &self,
        make: impl FnOnce(sync_mpsc::Sender<Result<T, String>>) -> Cmd,
    ) -> Result<T, String> {
        self.begin(make)?
            .recv()
            .map_err(|_| "UCX client thread died".to_string())?
    }
}

impl Protocol for UcxProtocol {
    fn attach(&self, addr: &str, node_id: u16, slot_bytes: u32) -> Result<usize, String> {
        self.roundtrip(|reply| Cmd::Attach {
            addr: addr.to_owned(),
            node_id,
            slot_bytes,
            reply,
        })
    }

    fn register_memory(&self, addr: u64, len: u64) -> Result<(), String> {
        self.roundtrip(|reply| Cmd::Register { addr, len, reply })
    }

    fn exists(&self, node: u16, keys: &[Vec<u8>]) -> Result<Waiter, String> {
        self.begin(|reply| Cmd::Exists {
            node,
            keys: keys.to_vec(),
            reply,
        })
    }

    fn put(&self, node: u16, keys: &[Vec<u8>], scatters: &[Scatter]) -> Result<Waiter, String> {
        self.begin(|reply| Cmd::Put {
            node,
            keys: keys.to_vec(),
            scatters: scatters.to_vec(),
            reply,
        })
    }

    fn get(&self, node: u16, keys: &[Vec<u8>], scatters: &[Scatter]) -> Result<Waiter, String> {
        self.begin(|reply| Cmd::Get {
            node,
            keys: keys.to_vec(),
            scatters: scatters.to_vec(),
            reply,
        })
    }

    fn reset(&self, node: u16) -> Result<(), String> {
        self.roundtrip(|reply| Cmd::Reset { node, reply })
    }

    fn close(&mut self) {
        self.tx = None;
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for UcxProtocol {
    fn drop(&mut self) {
        self.close();
    }
}

fn run(
    client_id: u16,
    mut rx: mpsc::UnboundedReceiver<Cmd>,
    ready: sync_mpsc::Sender<Result<(), String>>,
) {
    let runtime = match runtime() {
        Ok(runtime) => runtime,
        Err(error) => {
            let _ = ready.send(Err(error));
            return;
        }
    };
    runtime.block_on(async move {
        let worker = match UcxWorker::new() {
            Ok(worker) => worker,
            Err(error) => {
                let _ = ready.send(Err(error));
                return;
            }
        };
        let shared = Rc::new(Shared {
            client_id,
            epoch: Cell::new(0),
            next_request_id: Cell::new(1),
            worker,
            nodes: RefCell::new(HashMap::new()),
            memory: RefCell::new(Vec::new()),
            pending: RefCell::new(HashMap::new()),
            control_error: RefCell::new(None),
        });
        compio::runtime::spawn(dispatch(shared.clone())).detach();
        let _ = ready.send(Ok(()));

        while let Some(command) = rx.next().await {
            let shared = shared.clone();
            compio::runtime::spawn(async move { handle(shared, command).await }).detach();
        }
    });
}

async fn handle(shared: Rc<Shared>, command: Cmd) {
    match command {
        Cmd::Attach {
            addr,
            node_id,
            slot_bytes,
            reply,
        } => {
            let _ = reply.send(attach(&shared, &addr, node_id, slot_bytes));
        }
        Cmd::Register { addr, len, reply } => {
            let _ = reply.send(register(&shared, addr, len));
        }
        Cmd::Exists { node, keys, reply } => {
            let _ = reply.send(exists(&shared, node, keys).await);
        }
        Cmd::Put {
            node,
            keys,
            scatters,
            reply,
        } => {
            let _ = reply.send(put(&shared, node, keys, scatters).await);
        }
        Cmd::Get {
            node,
            keys,
            scatters,
            reply,
        } => {
            let _ = reply.send(get(&shared, node, keys, scatters).await);
        }
        Cmd::Reset { node, reply } => {
            let _ = reply.send(reset(&shared, node).await);
        }
    }
}

async fn dispatch(shared: Rc<Shared>) {
    std::future::poll_fn(move |cx| {
        for _ in 0..64 {
            match shared.worker.poll_control() {
                Ok(Some(body)) => route_control(&shared, &body),
                Ok(None) => break,
                Err(error) => {
                    fail_control(&shared, error);
                    return std::task::Poll::Ready(());
                }
            }
        }
        cx.waker().wake_by_ref();
        std::task::Poll::Pending
    })
    .await
}

fn route_control(shared: &Shared, body: &[u8]) {
    let response = match rpc::decode::<Envelope>(body) {
        Ok(response) => response,
        Err(error) => {
            tracing::warn!(%error, "decode UCX control response");
            return;
        }
    };
    match response {
        Envelope::Rsp {
            magic,
            request_id,
            payload,
        } => {
            let Some(pending) = shared.pending.borrow_mut().remove(&request_id) else {
                tracing::warn!(request_id, "unmatched UCX control response");
                return;
            };
            let response = if magic == ENVELOPE_MAGIC {
                Ok(payload)
            } else {
                Err(format!("invalid UCX response magic {magic:#x}"))
            };
            let _ = pending.send(response);
        }
        Envelope::Req { .. } => tracing::warn!("client received a UCX request envelope"),
    }
}

fn fail_control(shared: &Shared, error: String) {
    if shared.control_error.borrow().is_some() {
        return;
    }
    tracing::warn!(%error, "UCX control receive failed");
    *shared.control_error.borrow_mut() = Some(error.clone());
    let pending = std::mem::take(&mut *shared.pending.borrow_mut());
    for (_, reply) in pending {
        let _ = reply.send(Err(error.clone()));
    }
}

fn attach(shared: &Shared, addr: &str, node_id: u16, slot_bytes: u32) -> Result<usize, String> {
    shared.epoch.set(shared.epoch.get().wrapping_add(1).max(1));
    let request = Request::UcxAttach {
        protocol_version: UCX_PROTOCOL_VERSION,
        client_node_id: shared.client_id,
        epoch: shared.epoch.get(),
        worker_address: shared.worker.address()?,
        slot_bytes,
    };
    let body = rpc::encode(&request).map_err(|e| format!("encode UCX attach: {e}"))?;
    let response = rpc::decode::<Response>(&post(addr, RPC_PATH, &body)?)
        .map_err(|e| format!("decode UCX attach reply: {e}"))?;
    let reply = match response {
        Response::UcxAttached(reply) => reply,
        Response::UcxAttachDenied(why) => return Err(format!("attach denied by {addr}: {why}")),
        other => {
            return Err(format!(
                "unexpected UCX attach reply from {addr}: {other:?}"
            ))
        }
    };
    validate_reply(&reply, slot_bytes)?;
    let endpoint = shared.worker.connect(&reply.worker_address)?;
    let rkey = if reply.packed_rkey.is_empty() {
        None
    } else {
        Some(endpoint.unpack_rkey(&reply.packed_rkey)?)
    };
    shared.nodes.borrow_mut().insert(
        node_id,
        Rc::new(Node {
            rkey,
            endpoint,
            slab_base: reply.slab_base,
            slot_bytes: reply.slot_bytes,
        }),
    );
    Ok(shared.nodes.borrow().len())
}

fn validate_reply(reply: &UcxEndpointReply, requested_slot_bytes: u32) -> Result<(), String> {
    if reply.protocol_version != UCX_PROTOCOL_VERSION {
        return Err(format!(
            "server UCX protocol version {} does not match {}",
            reply.protocol_version, UCX_PROTOCOL_VERSION
        ));
    }
    if reply.worker_address.is_empty() {
        return Err("server returned an empty UCX worker address".into());
    }
    if requested_slot_bytes == 0 {
        if reply.slot_bytes != 0
            || reply.slot_count != 0
            || reply.slab_base != 0
            || !reply.packed_rkey.is_empty()
        {
            return Err("server returned data-plane metadata for a control-only UCX attach".into());
        }
        return Ok(());
    }
    if reply.slot_bytes != requested_slot_bytes || reply.slot_count == 0 {
        return Err(format!(
            "invalid UCX slab: requested {requested_slot_bytes} bytes, server returned {} bytes x {} slots",
            reply.slot_bytes, reply.slot_count
        ));
    }
    if reply.packed_rkey.is_empty() || reply.slab_base == 0 {
        return Err("server returned incomplete UCX endpoint metadata".into());
    }
    Ok(())
}

fn register(shared: &Shared, addr: u64, len: u64) -> Result<(), String> {
    if shared
        .memory
        .borrow()
        .iter()
        .any(|memory| memory.contains(addr, len))
    {
        return Ok(());
    }
    let memory = shared.worker.register(addr, len)?;
    shared.memory.borrow_mut().push(RegisteredMemory {
        start: addr,
        len,
        _memory: memory,
    });
    Ok(())
}

fn node(shared: &Shared, node_id: u16) -> Result<Rc<Node>, String> {
    shared
        .nodes
        .borrow()
        .get(&node_id)
        .cloned()
        .ok_or_else(|| format!("node {node_id} is not attached"))
}

fn validate_keys(keys: &[Vec<u8>]) -> Result<(), String> {
    for (index, key) in keys.iter().enumerate() {
        if key.len() != KEY_BYTES {
            return Err(format!(
                "key {index}: {} bytes, expected {KEY_BYTES}",
                key.len()
            ));
        }
    }
    Ok(())
}

fn validate_scatters(
    shared: &Shared,
    node: &Node,
    keys: &[Vec<u8>],
    scatters: &[Scatter],
) -> Result<(), String> {
    validate_keys(keys)?;
    if scatters.len() != keys.len() {
        return Err(format!(
            "{} scatter lists for {} keys",
            scatters.len(),
            keys.len()
        ));
    }
    let memory = shared.memory.borrow();
    for (key_index, scatter) in scatters.iter().enumerate() {
        let payload: u64 = scatter.iter().map(|(_, length)| *length).sum();
        if payload == 0 || payload + KEY_BYTES as u64 > u64::from(node.slot_bytes) {
            return Err(format!(
                "key {key_index}: payload {payload} does not fit {}-byte slot",
                node.slot_bytes
            ));
        }
        for &(address, length) in scatter {
            if length == 0 || !memory.iter().any(|region| region.contains(address, length)) {
                return Err(format!(
                    "key {key_index}: address {address:#x}+{length} is not registered"
                ));
            }
        }
    }
    Ok(())
}

async fn unary(
    shared: &Shared,
    node_id: u16,
    payload: RdmaRequest,
) -> Result<RdmaResponse, String> {
    if let Some(error) = shared.control_error.borrow().clone() {
        return Err(error);
    }
    let node = node(shared, node_id)?;
    let request_id = shared.next_request_id.get();
    shared
        .next_request_id
        .set(request_id.wrapping_add(1).max(1));
    let envelope = Envelope::Req {
        magic: ENVELOPE_MAGIC,
        from_node_id: shared.client_id,
        from_runtime_id: 0,
        request_id,
        payload,
    };
    let body = rpc::encode(&envelope).map_err(|e| format!("encode UCX control request: {e}"))?;
    let (reply, wait) = oneshot::channel();
    shared.pending.borrow_mut().insert(request_id, reply);

    let send = match node.endpoint.send_control(body) {
        Ok(send) => send,
        Err(error) => {
            shared.pending.borrow_mut().remove(&request_id);
            return Err(error);
        }
    };
    if let Err(error) = await_request(send, "UCX control send").await {
        shared.pending.borrow_mut().remove(&request_id);
        return Err(error);
    }

    let response = match compio::time::timeout(OPERATION_TIMEOUT, wait).await {
        Ok(Ok(response)) => response?,
        Ok(Err(_)) => return Err("UCX control dispatcher dropped waiter".into()),
        Err(_) => {
            shared.pending.borrow_mut().remove(&request_id);
            return Err(format!(
                "node {node_id}: UCX control response timeout ({OPERATION_TIMEOUT:?})"
            ));
        }
    };
    if let RdmaResponse::Generic(Response::Err(error)) = &response {
        return Err(format!("UCX control request failed: {error:?}"));
    }
    Ok(response)
}

async fn await_requests(requests: Vec<UcxRequest>, operation: &str) -> Result<(), String> {
    match compio::time::timeout(OPERATION_TIMEOUT, try_join_all(requests)).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(error)) => Err(format!("{operation}: {error}")),
        Err(_) => Err(format!("{operation} timeout ({OPERATION_TIMEOUT:?})")),
    }
}

async fn await_request(request: UcxRequest, operation: &str) -> Result<(), String> {
    await_requests(vec![request], operation).await
}

async fn exists(shared: &Shared, node_id: u16, keys: Vec<Vec<u8>>) -> Result<Vec<i32>, String> {
    validate_keys(&keys)?;
    match unary(
        shared,
        node_id,
        RdmaRequest::BatchLookup { key_hashes: keys },
    )
    .await?
    {
        RdmaResponse::BatchLookedUp { slots } => Ok(slots
            .into_iter()
            .map(|slot| slot.is_some() as i32)
            .collect()),
        other => Err(format!("unexpected lookup response: {other:?}")),
    }
}

async fn put(
    shared: &Shared,
    node_id: u16,
    keys: Vec<Vec<u8>>,
    scatters: Vec<Scatter>,
) -> Result<Vec<i32>, String> {
    let node = node(shared, node_id)?;
    validate_scatters(shared, &node, &keys, &scatters)?;
    let rkey = node
        .rkey
        .as_ref()
        .ok_or("UCX node is attached for control operations only")?;
    if keys.is_empty() {
        return Ok(Vec::new());
    }
    let slots = match unary(
        shared,
        node_id,
        RdmaRequest::BatchReserve {
            count: keys.len() as u32,
        },
    )
    .await?
    {
        RdmaResponse::BatchReserved { slots } => slots,
        other => return Err(format!("unexpected reserve response: {other:?}")),
    };
    if slots.len() != keys.len() {
        let _ = unary(
            shared,
            node_id,
            RdmaRequest::BatchRelease {
                slot_idxs: slots.clone(),
            },
        )
        .await;
        return Err(format!(
            "store full: reserved {} of {} slots",
            slots.len(),
            keys.len()
        ));
    }

    let requests = (|| -> Result<Vec<UcxRequest>, String> {
        let mut requests = Vec::new();
        for ((key, scatter), slot) in keys.iter().zip(&scatters).zip(&slots) {
            let remote = node.slab_base + u64::from(*slot) * u64::from(node.slot_bytes);
            requests.push(node.endpoint.put(
                key.as_ptr() as u64,
                KEY_BYTES as u64,
                remote,
                rkey,
            )?);
            let mut offset = KEY_BYTES as u64;
            for &(address, length) in scatter {
                requests.push(node.endpoint.put(address, length, remote + offset, rkey)?);
                offset += length;
            }
        }
        requests.push(node.endpoint.flush()?);
        Ok(requests)
    })();
    let transfer = match requests {
        Ok(requests) => await_requests(requests, "UCX write").await,
        Err(error) => Err(error),
    };
    if let Err(error) = transfer {
        let _ = unary(
            shared,
            node_id,
            RdmaRequest::BatchRelease {
                slot_idxs: slots.clone(),
            },
        )
        .await;
        return Err(format!("UCX write failed; batch released: {error}"));
    }

    let entries = slots
        .iter()
        .zip(keys)
        .map(|(&slot_idx, key_hash)| CommitEntry { slot_idx, key_hash })
        .collect();
    match unary(shared, node_id, RdmaRequest::BatchCommit { entries }).await? {
        RdmaResponse::BatchCommitted => Ok(vec![0; slots.len()]),
        other => Err(format!("unexpected commit response: {other:?}")),
    }
}

async fn get(
    shared: &Shared,
    node_id: u16,
    keys: Vec<Vec<u8>>,
    scatters: Vec<Scatter>,
) -> Result<Vec<i32>, String> {
    let node = node(shared, node_id)?;
    validate_scatters(shared, &node, &keys, &scatters)?;
    let rkey = node
        .rkey
        .as_ref()
        .ok_or("UCX node is attached for control operations only")?;
    if keys.is_empty() {
        return Ok(Vec::new());
    }
    let slots = match unary(
        shared,
        node_id,
        RdmaRequest::BatchRead {
            key_hashes: keys.clone(),
        },
    )
    .await?
    {
        RdmaResponse::BatchLookedUp { slots } => slots,
        other => return Err(format!("unexpected read response: {other:?}")),
    };
    if slots.len() != keys.len() {
        return Err(format!("{} slots for {} keys", slots.len(), keys.len()));
    }

    let mut headers = vec![0u8; keys.len() * KEY_BYTES];
    let mut requests = Vec::new();
    let mut out = vec![0i32; keys.len()];
    for (index, slot) in slots.iter().enumerate() {
        let Some(slot) = slot else {
            out[index] = -1;
            continue;
        };
        let remote = node.slab_base + u64::from(*slot) * u64::from(node.slot_bytes);
        requests.push(node.endpoint.get(
            headers[index * KEY_BYTES..].as_mut_ptr() as u64,
            KEY_BYTES as u64,
            remote,
            rkey,
        )?);
        let mut offset = KEY_BYTES as u64;
        for &(address, length) in &scatters[index] {
            requests.push(node.endpoint.get(address, length, remote + offset, rkey)?);
            offset += length;
        }
    }
    requests.push(node.endpoint.flush()?);
    await_requests(requests, "UCX read").await?;
    for (index, slot) in slots.iter().enumerate() {
        if slot.is_some() && headers[index * KEY_BYTES..(index + 1) * KEY_BYTES] != keys[index][..]
        {
            out[index] = -1;
        }
    }
    Ok(out)
}

async fn reset(shared: &Shared, node_id: u16) -> Result<(), String> {
    match unary(shared, node_id, RdmaRequest::Reset).await? {
        RdmaResponse::ResetDone => Ok(()),
        other => Err(format!("unexpected reset response: {other:?}")),
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

fn post(addr: &str, path: &str, body: &[u8]) -> Result<Vec<u8>, String> {
    let mut socket = TcpStream::connect(addr).map_err(|e| format!("connect {addr}: {e}"))?;
    socket.set_read_timeout(Some(ATTACH_TIMEOUT)).ok();
    socket.set_write_timeout(Some(ATTACH_TIMEOUT)).ok();
    let header = format!(
        "POST {path} HTTP/1.1\r\nhost: {addr}\r\n\
         content-type: application/octet-stream\r\n\
         content-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    );
    socket
        .write_all(header.as_bytes())
        .and_then(|()| socket.write_all(body))
        .map_err(|e| format!("send to {addr}: {e}"))?;
    let mut raw = Vec::new();
    socket
        .read_to_end(&mut raw)
        .map_err(|e| format!("receive from {addr}: {e}"))?;
    let split = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| format!("{addr}: response has no header terminator"))?;
    let status = raw[..split]
        .split(|&byte| byte == b'\r')
        .next()
        .and_then(|line| std::str::from_utf8(line).ok())
        .unwrap_or_default();
    if !status.contains(" 200 ") {
        return Err(format!("{addr}: HTTP status {status:?}"));
    }
    Ok(raw[split + 4..].to_vec())
}
