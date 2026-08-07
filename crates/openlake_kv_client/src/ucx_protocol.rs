#![cfg(all(feature = "rdma", target_os = "linux"))]

use std::cell::Cell;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use openlake_io::kv_wire::{CommitEntry, Envelope, RdmaRequest, RdmaResponse, ENVELOPE_MAGIC};
use openlake_io::rpc::{self, Request, Response, UcxEndpointReply, UCX_PROTOCOL_VERSION};
use openlake_io::ucx::{UcxEndpoint, UcxMemory, UcxRkey, UcxWorker};

use crate::transport::{Protocol, Scatter, Waiter};

const KEY_BYTES: usize = 54;
const ATTACH_TIMEOUT: Duration = Duration::from_secs(60);
const CONTROL_TIMEOUT: Duration = Duration::from_secs(60);
const RPC_PATH: &str = "/v1/rpc";

enum Cmd {
    Attach {
        addr: String,
        node_id: u16,
        slot_bytes: u32,
        reply: mpsc::Sender<Result<usize, String>>,
    },
    Register {
        addr: u64,
        len: u64,
        reply: mpsc::Sender<Result<(), String>>,
    },
    Exists {
        node: u16,
        keys: Vec<Vec<u8>>,
        reply: mpsc::Sender<Result<Vec<i32>, String>>,
    },
    Put {
        node: u16,
        keys: Vec<Vec<u8>>,
        scatters: Vec<Scatter>,
        reply: mpsc::Sender<Result<Vec<i32>, String>>,
    },
    Get {
        node: u16,
        keys: Vec<Vec<u8>>,
        scatters: Vec<Scatter>,
        reply: mpsc::Sender<Result<Vec<i32>, String>>,
    },
    Reset {
        node: u16,
        reply: mpsc::Sender<Result<(), String>>,
    },
}

struct Node {
    rkey: UcxRkey,
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

struct State {
    client_id: u16,
    epoch: u64,
    next_request_id: Cell<u64>,
    worker: UcxWorker,
    nodes: HashMap<u16, Node>,
    memory: Vec<RegisteredMemory>,
}

pub struct UcxProtocol {
    tx: Option<mpsc::Sender<Cmd>>,
    thread: Option<JoinHandle<()>>,
}

impl UcxProtocol {
    pub fn new(client_id: u16) -> Result<Self, String> {
        let (tx, rx) = mpsc::channel();
        let (ready_tx, ready_rx) = mpsc::channel();
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
        make: impl FnOnce(mpsc::Sender<Result<T, String>>) -> Cmd,
    ) -> Result<mpsc::Receiver<Result<T, String>>, String> {
        let (reply, wait) = mpsc::channel();
        self.tx
            .as_ref()
            .ok_or("UCX client is closed")?
            .send(make(reply))
            .map_err(|_| "UCX client thread died".to_string())?;
        Ok(wait)
    }

    fn roundtrip<T>(
        &self,
        make: impl FnOnce(mpsc::Sender<Result<T, String>>) -> Cmd,
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

fn run(client_id: u16, rx: mpsc::Receiver<Cmd>, ready: mpsc::Sender<Result<(), String>>) {
    let worker = match UcxWorker::new() {
        Ok(worker) => worker,
        Err(error) => {
            let _ = ready.send(Err(error));
            return;
        }
    };
    let _ = ready.send(Ok(()));
    let mut state = State {
        client_id,
        epoch: 0,
        next_request_id: Cell::new(1),
        worker,
        nodes: HashMap::new(),
        memory: Vec::new(),
    };
    loop {
        let command = match rx.try_recv() {
            Ok(command) => command,
            Err(mpsc::TryRecvError::Empty) => {
                std::hint::spin_loop();
                continue;
            }
            Err(mpsc::TryRecvError::Disconnected) => break,
        };
        match command {
            Cmd::Attach {
                addr,
                node_id,
                slot_bytes,
                reply,
            } => {
                let _ = reply.send(attach(&mut state, &addr, node_id, slot_bytes));
            }
            Cmd::Register { addr, len, reply } => {
                let result = register(&mut state, addr, len);
                let _ = reply.send(result);
            }
            Cmd::Exists { node, keys, reply } => {
                let _ = reply.send(exists(&state, node, keys));
            }
            Cmd::Put {
                node,
                keys,
                scatters,
                reply,
            } => {
                let _ = reply.send(put(&state, node, keys, scatters));
            }
            Cmd::Get {
                node,
                keys,
                scatters,
                reply,
            } => {
                let _ = reply.send(get(&state, node, keys, scatters));
            }
            Cmd::Reset { node, reply } => {
                let _ = reply.send(reset(&state, node));
            }
        }
    }
}

fn attach(state: &mut State, addr: &str, node_id: u16, slot_bytes: u32) -> Result<usize, String> {
    state.epoch = state.epoch.wrapping_add(1).max(1);
    let request = Request::UcxAttach {
        protocol_version: UCX_PROTOCOL_VERSION,
        client_node_id: state.client_id,
        epoch: state.epoch,
        worker_address: state.worker.address()?,
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
    let endpoint = state.worker.connect(&reply.worker_address)?;
    let rkey = endpoint.unpack_rkey(&reply.packed_rkey)?;
    state.nodes.insert(
        node_id,
        Node {
            rkey,
            endpoint,
            slab_base: reply.slab_base,
            slot_bytes: reply.slot_bytes,
        },
    );
    Ok(state.nodes.len())
}

fn validate_reply(reply: &UcxEndpointReply, requested_slot_bytes: u32) -> Result<(), String> {
    if reply.protocol_version != UCX_PROTOCOL_VERSION {
        return Err(format!(
            "server UCX protocol version {} does not match {}",
            reply.protocol_version, UCX_PROTOCOL_VERSION
        ));
    }
    if reply.slot_bytes != requested_slot_bytes || reply.slot_count == 0 {
        return Err(format!(
            "invalid UCX slab: requested {requested_slot_bytes} bytes, server returned {} bytes x {} slots",
            reply.slot_bytes, reply.slot_count
        ));
    }
    if reply.worker_address.is_empty() || reply.packed_rkey.is_empty() || reply.slab_base == 0 {
        return Err("server returned incomplete UCX endpoint metadata".into());
    }
    Ok(())
}

fn register(state: &mut State, addr: u64, len: u64) -> Result<(), String> {
    if state.memory.iter().any(|memory| memory.contains(addr, len)) {
        return Ok(());
    }
    let memory = state.worker.register(addr, len)?;
    state.memory.push(RegisteredMemory {
        start: addr,
        len,
        _memory: memory,
    });
    Ok(())
}

fn node(state: &State, node_id: u16) -> Result<&Node, String> {
    state
        .nodes
        .get(&node_id)
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
    state: &State,
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
    for (key_index, scatter) in scatters.iter().enumerate() {
        let payload: u64 = scatter.iter().map(|(_, length)| *length).sum();
        if payload == 0 || payload + KEY_BYTES as u64 > u64::from(node.slot_bytes) {
            return Err(format!(
                "key {key_index}: payload {payload} does not fit {}-byte slot",
                node.slot_bytes
            ));
        }
        for &(address, length) in scatter {
            if length == 0
                || !state
                    .memory
                    .iter()
                    .any(|memory| memory.contains(address, length))
            {
                return Err(format!(
                    "key {key_index}: address {address:#x}+{length} is not registered"
                ));
            }
        }
    }
    Ok(())
}

fn unary(state: &State, node_id: u16, payload: RdmaRequest) -> Result<RdmaResponse, String> {
    let node = node(state, node_id)?;
    let request_id = state.next_request_id.get();
    state.next_request_id.set(request_id.wrapping_add(1).max(1));
    let request = Envelope::Req {
        magic: ENVELOPE_MAGIC,
        from_node_id: state.client_id,
        from_runtime_id: 0,
        request_id,
        payload,
    };
    let body = rpc::encode(&request).map_err(|e| format!("encode UCX control request: {e}"))?;
    node.endpoint.send_control(&body)?;

    let deadline = Instant::now() + CONTROL_TIMEOUT;
    loop {
        while state.worker.progress() != 0 {}
        if let Some(body) = state.worker.poll_control()? {
            let response = rpc::decode::<Envelope>(&body)
                .map_err(|e| format!("decode UCX control response: {e}"))?;
            match response {
                Envelope::Rsp {
                    magic,
                    request_id: response_id,
                    payload,
                } if magic == ENVELOPE_MAGIC && response_id == request_id => {
                    if let RdmaResponse::Generic(Response::Err(error)) = &payload {
                        return Err(format!("UCX control request failed: {error:?}"));
                    }
                    return Ok(payload);
                }
                Envelope::Rsp {
                    request_id: response_id,
                    ..
                } => {
                    return Err(format!(
                        "unexpected UCX response id {response_id}, expected {request_id}"
                    ));
                }
                Envelope::Req { .. } => {
                    return Err("client received a UCX request envelope".into());
                }
            }
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "node {node_id}: UCX control response timeout ({CONTROL_TIMEOUT:?})"
            ));
        }
        std::hint::spin_loop();
    }
}

fn exists(state: &State, node_id: u16, keys: Vec<Vec<u8>>) -> Result<Vec<i32>, String> {
    validate_keys(&keys)?;
    match unary(
        state,
        node_id,
        RdmaRequest::BatchLookup { key_hashes: keys },
    )? {
        RdmaResponse::BatchLookedUp { slots } => Ok(slots
            .into_iter()
            .map(|slot| slot.is_some() as i32)
            .collect()),
        other => Err(format!("unexpected lookup response: {other:?}")),
    }
}

fn put(
    state: &State,
    node_id: u16,
    keys: Vec<Vec<u8>>,
    scatters: Vec<Scatter>,
) -> Result<Vec<i32>, String> {
    let node = node(state, node_id)?;
    validate_scatters(state, node, &keys, &scatters)?;
    if keys.is_empty() {
        return Ok(Vec::new());
    }
    let slots = match unary(
        state,
        node_id,
        RdmaRequest::BatchReserve {
            count: keys.len() as u32,
        },
    )? {
        RdmaResponse::BatchReserved { slots } => slots,
        other => return Err(format!("unexpected reserve response: {other:?}")),
    };
    if slots.len() != keys.len() {
        let _ = unary(
            state,
            node_id,
            RdmaRequest::BatchRelease {
                slot_idxs: slots.clone(),
            },
        );
        return Err(format!(
            "store full: reserved {} of {} slots",
            slots.len(),
            keys.len()
        ));
    }

    let transfer = (|| {
        for ((key, scatter), slot) in keys.iter().zip(&scatters).zip(&slots) {
            let remote = node.slab_base + u64::from(*slot) * u64::from(node.slot_bytes);
            node.endpoint
                .put(key.as_ptr() as u64, KEY_BYTES as u64, remote, &node.rkey)?;
            let mut offset = KEY_BYTES as u64;
            for &(address, length) in scatter {
                node.endpoint
                    .put(address, length, remote + offset, &node.rkey)?;
                offset += length;
            }
        }
        node.endpoint.flush()
    })();
    if let Err(error) = transfer {
        let _ = unary(
            state,
            node_id,
            RdmaRequest::BatchRelease {
                slot_idxs: slots.clone(),
            },
        );
        return Err(format!("UCX write failed; batch released: {error}"));
    }

    let entries = slots
        .iter()
        .zip(keys)
        .map(|(&slot_idx, key_hash)| CommitEntry { slot_idx, key_hash })
        .collect();
    match unary(state, node_id, RdmaRequest::BatchCommit { entries })? {
        RdmaResponse::BatchCommitted => Ok(vec![0; slots.len()]),
        other => Err(format!("unexpected commit response: {other:?}")),
    }
}

fn get(
    state: &State,
    node_id: u16,
    keys: Vec<Vec<u8>>,
    scatters: Vec<Scatter>,
) -> Result<Vec<i32>, String> {
    let node = node(state, node_id)?;
    validate_scatters(state, node, &keys, &scatters)?;
    if keys.is_empty() {
        return Ok(Vec::new());
    }
    let slots = match unary(
        state,
        node_id,
        RdmaRequest::BatchRead {
            key_hashes: keys.clone(),
        },
    )? {
        RdmaResponse::BatchLookedUp { slots } => slots,
        other => return Err(format!("unexpected read response: {other:?}")),
    };
    if slots.len() != keys.len() {
        return Err(format!("{} slots for {} keys", slots.len(), keys.len()));
    }

    let mut headers = vec![0u8; keys.len() * KEY_BYTES];
    let mut out = vec![0i32; keys.len()];
    for (index, slot) in slots.iter().enumerate() {
        let Some(slot) = slot else {
            out[index] = -1;
            continue;
        };
        let remote = node.slab_base + u64::from(*slot) * u64::from(node.slot_bytes);
        node.endpoint.get(
            headers[index * KEY_BYTES..].as_mut_ptr() as u64,
            KEY_BYTES as u64,
            remote,
            &node.rkey,
        )?;
        let mut offset = KEY_BYTES as u64;
        for &(address, length) in &scatters[index] {
            node.endpoint
                .get(address, length, remote + offset, &node.rkey)?;
            offset += length;
        }
    }
    node.endpoint.flush()?;
    for (index, slot) in slots.iter().enumerate() {
        if slot.is_some() && headers[index * KEY_BYTES..(index + 1) * KEY_BYTES] != keys[index][..]
        {
            out[index] = -1;
        }
    }
    Ok(out)
}

fn reset(state: &State, node_id: u16) -> Result<(), String> {
    match unary(state, node_id, RdmaRequest::Reset)? {
        RdmaResponse::ResetDone => Ok(()),
        other => Err(format!("unexpected reset response: {other:?}")),
    }
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
