use std::collections::HashMap;
use std::ffi::c_void;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::ptr::copy_nonoverlapping;
use std::slice;
use std::sync::{mpsc, Mutex, OnceLock};
use std::time::Duration;

use openlake_io::kv::{KvRequest, KvResponse};
use openlake_io::{rpc, shm};

use crate::transport::{Protocol, Scatter, Waiter};

const HDR: usize = 54;
const TIMEOUT: Duration = Duration::from_secs(10);
const CUDA_DEFAULT: i32 = 4;

#[derive(Clone, Copy)]
struct CudaFailure {
    operation: &'static str,
    code: i32,
}

impl std::fmt::Display for CudaFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} failed with CUDA error {}", self.operation, self.code)
    }
}

struct Cuda {
    memcpy_async: unsafe extern "C" fn(*mut c_void, *const c_void, usize, i32, *mut c_void) -> i32,
    host_register: unsafe extern "C" fn(*mut c_void, usize, u32) -> i32,
    host_unregister: unsafe extern "C" fn(*mut c_void) -> i32,
    stream_create: unsafe extern "C" fn(*mut *mut c_void) -> i32,
    stream_sync: unsafe extern "C" fn(*mut c_void) -> i32,
    stream_destroy: unsafe extern "C" fn(*mut c_void) -> i32,
}

#[allow(clippy::missing_transmute_annotations)]
fn cuda() -> Option<&'static Cuda> {
    static C: OnceLock<Option<Cuda>> = OnceLock::new();
    C.get_or_init(|| unsafe {
        let mut h = std::ptr::null_mut();
        for name in [c"libcudart.so", c"libcudart.so.12", c"libcudart.so.11"] {
            h = libc::dlopen(name.as_ptr(), libc::RTLD_LAZY | libc::RTLD_GLOBAL);
            if !h.is_null() {
                break;
            }
        }
        if h.is_null() {
            return None;
        }
        let syms = [
            c"cudaMemcpyAsync".as_ptr(),
            c"cudaHostRegister".as_ptr(),
            c"cudaHostUnregister".as_ptr(),
            c"cudaStreamCreate".as_ptr(),
            c"cudaStreamSynchronize".as_ptr(),
            c"cudaStreamDestroy".as_ptr(),
        ]
        .map(|n| libc::dlsym(h, n));
        if syms.iter().any(|&p| p.is_null()) {
            return None;
        }
        Some(Cuda {
            memcpy_async: std::mem::transmute(syms[0]),
            host_register: std::mem::transmute(syms[1]),
            host_unregister: std::mem::transmute(syms[2]),
            stream_create: std::mem::transmute(syms[3]),
            stream_sync: std::mem::transmute(syms[4]),
            stream_destroy: std::mem::transmute(syms[5]),
        })
    })
    .as_ref()
}

#[inline]
unsafe fn xfer(n: &Node, dst: *mut u8, src: *const u8, len: usize) -> Result<(), CudaFailure> {
    match n.cuda {
        Some(c) if !n.stream.is_null() => {
            let code = (c.memcpy_async)(
                dst as *mut c_void,
                src as *const c_void,
                len,
                CUDA_DEFAULT,
                n.stream,
            );
            if code != 0 {
                return Err(CudaFailure {
                    operation: "cudaMemcpyAsync",
                    code,
                });
            }
        }
        _ => copy_nonoverlapping(src, dst, len),
    }
    Ok(())
}

fn sync(n: &Node) -> Result<(), CudaFailure> {
    if let (Some(c), false) = (n.cuda, n.stream.is_null()) {
        let code = unsafe { (c.stream_sync)(n.stream) };
        if code != 0 {
            return Err(CudaFailure {
                operation: "cudaStreamSynchronize",
                code,
            });
        }
    }
    Ok(())
}

struct Node {
    base: *mut u8,
    slot_bytes: usize,
    span: usize,
    addr: String,
    stream: *mut c_void,
    cuda: Option<&'static Cuda>,
}
unsafe impl Send for Node {}

pub struct ShmLocalProtocol {
    nodes: Mutex<HashMap<u16, Node>>,
}

impl ShmLocalProtocol {
    pub fn new() -> Result<Self, String> {
        Ok(Self {
            nodes: Mutex::new(HashMap::new()),
        })
    }
}

fn ready(r: Result<Vec<i32>, String>) -> Waiter {
    let (tx, rx) = mpsc::channel();
    let _ = tx.send(r);
    rx
}

fn call(addr: &str, req: &KvRequest) -> Result<KvResponse, String> {
    let body = rpc::encode(req).map_err(|e| e.to_string())?;
    match rpc::decode::<KvResponse>(&post(addr, &body)?).map_err(|e| e.to_string())? {
        KvResponse::Err(why) => Err(why),
        r => Ok(r),
    }
}

fn post(addr: &str, body: &[u8]) -> Result<Vec<u8>, String> {
    let mut sock = TcpStream::connect(addr).map_err(|e| format!("connect {addr}: {e}"))?;
    sock.set_read_timeout(Some(TIMEOUT)).ok();
    sock.set_write_timeout(Some(TIMEOUT)).ok();
    let head = format!(
        "POST /v1/kv HTTP/1.1\r\nhost: {addr}\r\n\
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

fn put_node(
    n: &Node,
    keys: &[Vec<u8>],
    scatters: &[Scatter],
    mut request: impl FnMut(&str, &KvRequest) -> Result<KvResponse, String>,
) -> Result<Vec<i32>, String> {
    let slots = match request(
        &n.addr,
        &KvRequest::Reserve {
            count: keys.len() as u32,
        },
    )? {
        KvResponse::Reserved { slots } => slots,
        other => return Err(format!("reserve: {other:?}")),
    };
    let transfer = if slots.len() < keys.len() {
        Err(format!(
            "store full: reserved {} of {}",
            slots.len(),
            keys.len()
        ))
    } else {
        let mut copy_error = None;
        'copy: for (i, key) in keys.iter().enumerate() {
            let dst = unsafe { n.base.add(slots[i] as usize * n.slot_bytes) };
            unsafe { copy_nonoverlapping(key.as_ptr(), dst, HDR) };
            let mut off = HDR;
            for &(addr, len) in &scatters[i] {
                if let Err(error) =
                    unsafe { xfer(n, dst.add(off), addr as *const u8, len as usize) }
                {
                    copy_error = Some(error);
                    break 'copy;
                }
                off += len as usize;
            }
        }
        // Drain copies already queued before returning buffers or releasing slots.
        let sync_result = sync(n);
        match (copy_error, sync_result) {
            (Some(copy), Err(sync)) => Err(format!("{copy}; {sync}")),
            (Some(copy), _) => Err(copy.to_string()),
            (None, Err(sync)) => Err(sync.to_string()),
            (None, Ok(())) => Ok(()),
        }
    };
    if let Err(error) = transfer {
        let release = request(&n.addr, &KvRequest::Release { slots });
        return match release {
            Ok(KvResponse::Ok) => Err(error),
            other => Err(format!("{error}; release failed: {other:?}")),
        };
    }
    let entries = slots
        .iter()
        .zip(keys)
        .map(|(&s, k)| (s, k.clone()))
        .collect();
    match request(&n.addr, &KvRequest::Commit { entries })? {
        KvResponse::Ok => Ok(vec![0; keys.len()]),
        other => Err(format!("commit: {other:?}")),
    }
}

fn get_node(
    n: &Node,
    keys: &[Vec<u8>],
    scatters: &[Scatter],
    mut request: impl FnMut(&str, &KvRequest) -> Result<KvResponse, String>,
) -> Result<Vec<i32>, String> {
    let slots = match request(
        &n.addr,
        &KvRequest::Read {
            keys: keys.to_vec(),
        },
    )? {
        KvResponse::Looked { slots } => slots,
        other => return Err(format!("lookup: {other:?}")),
    };
    let mut out = vec![0i32; keys.len()];
    let mut copy_error = None;
    'copy: for (i, slot) in slots.iter().enumerate() {
        let Some(slot) = slot else {
            out[i] = -1;
            continue;
        };
        let src = unsafe { n.base.add(*slot as usize * n.slot_bytes) };
        if unsafe { slice::from_raw_parts(src, HDR) } != &keys[i][..HDR] {
            out[i] = -1;
            continue;
        }
        let mut off = HDR;
        for &(addr, len) in &scatters[i] {
            if let Err(error) = unsafe { xfer(n, addr as *mut u8, src.add(off), len as usize) } {
                copy_error = Some(error);
                break 'copy;
            }
            off += len as usize;
        }
    }
    let sync_result = sync(n);
    match (copy_error, sync_result) {
        (Some(copy), Err(sync)) => Err(format!("{copy}; {sync}")),
        (Some(copy), _) => Err(copy.to_string()),
        (None, Err(sync)) => Err(sync.to_string()),
        (None, Ok(())) => Ok(out),
    }
}

impl Protocol for ShmLocalProtocol {
    fn attach(&self, addr: &str, node_id: u16, slot_bytes: u32) -> Result<usize, String> {
        let (name, slot_bytes, slot_count) = match call(addr, &KvRequest::Attach { slot_bytes })? {
            KvResponse::Attached {
                shm_name,
                slot_bytes,
                slot_count,
            } => (shm_name, slot_bytes as usize, slot_count as usize),
            other => return Err(format!("attach: {other:?}")),
        };
        if slot_bytes == 0 {
            self.nodes.lock().unwrap().insert(
                node_id,
                Node {
                    base: std::ptr::null_mut(),
                    slot_bytes: 0,
                    span: 0,
                    addr: addr.to_string(),
                    stream: std::ptr::null_mut(),
                    cuda: None,
                },
            );
            return Ok(slot_count);
        }
        let span = slot_bytes * slot_count;
        let base = shm::open_map(&name, span).map_err(|e| format!("map {name}: {e}"))?;
        let cuda = cuda();
        let stream = match cuda {
            Some(c) => unsafe {
                (c.host_register)(base as *mut c_void, span, 0);
                let mut s = std::ptr::null_mut();
                (c.stream_create)(&mut s);
                s
            },
            None => std::ptr::null_mut(),
        };
        self.nodes.lock().unwrap().insert(
            node_id,
            Node {
                base,
                slot_bytes,
                span,
                addr: addr.to_string(),
                stream,
                cuda,
            },
        );
        Ok(slot_count)
    }

    fn register_memory(&self, _addr: u64, _len: u64) -> Result<(), String> {
        Ok(())
    }

    fn put(&self, node: u16, keys: &[Vec<u8>], scatters: &[Scatter]) -> Result<Waiter, String> {
        let g = self.nodes.lock().unwrap();
        let n = g
            .get(&node)
            .ok_or_else(|| format!("node {node} not attached"))?;
        put_node(n, keys, scatters, call).map(|out| ready(Ok(out)))
    }

    fn get(&self, node: u16, keys: &[Vec<u8>], scatters: &[Scatter]) -> Result<Waiter, String> {
        let g = self.nodes.lock().unwrap();
        let n = g
            .get(&node)
            .ok_or_else(|| format!("node {node} not attached"))?;
        get_node(n, keys, scatters, call).map(|out| ready(Ok(out)))
    }

    fn exists(&self, node: u16, keys: &[Vec<u8>]) -> Result<Waiter, String> {
        let g = self.nodes.lock().unwrap();
        let n = g
            .get(&node)
            .ok_or_else(|| format!("node {node} not attached"))?;
        match call(
            &n.addr,
            &KvRequest::Lookup {
                keys: keys.to_vec(),
            },
        )? {
            KvResponse::Looked { slots } => Ok(ready(Ok(slots
                .iter()
                .map(|s| s.is_some() as i32)
                .collect()))),
            other => Err(format!("lookup: {other:?}")),
        }
    }

    fn reset(&self, node: u16) -> Result<(), String> {
        let g = self.nodes.lock().unwrap();
        let n = g
            .get(&node)
            .ok_or_else(|| format!("node {node} not attached"))?;
        match call(&n.addr, &KvRequest::Reset)? {
            KvResponse::Ok => Ok(()),
            other => Err(format!("reset: {other:?}")),
        }
    }

    fn close(&mut self) {
        for (_, n) in self.nodes.get_mut().unwrap().drain() {
            if let (Some(c), false) = (n.cuda, n.stream.is_null()) {
                unsafe {
                    (c.stream_destroy)(n.stream);
                    (c.host_unregister)(n.base as *mut c_void);
                }
            }
            if !n.base.is_null() {
                shm::unmap(n.base, n.span);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    thread_local! {
        static COPY_ERROR: Cell<i32> = const { Cell::new(0) };
        static SYNC_ERROR: Cell<i32> = const { Cell::new(0) };
    }

    unsafe extern "C" fn mock_copy(
        dst: *mut c_void,
        src: *const c_void,
        len: usize,
        _: i32,
        _: *mut c_void,
    ) -> i32 {
        let code = COPY_ERROR.with(Cell::get);
        if code == 0 {
            copy_nonoverlapping(src.cast::<u8>(), dst.cast::<u8>(), len);
        }
        code
    }

    unsafe extern "C" fn mock_sync(_: *mut c_void) -> i32 {
        SYNC_ERROR.with(Cell::get)
    }

    unsafe extern "C" fn mock_register(_: *mut c_void, _: usize, _: u32) -> i32 {
        0
    }

    unsafe extern "C" fn mock_unregister(_: *mut c_void) -> i32 {
        0
    }

    unsafe extern "C" fn mock_create(_: *mut *mut c_void) -> i32 {
        0
    }

    unsafe extern "C" fn mock_destroy(_: *mut c_void) -> i32 {
        0
    }

    static MOCK_CUDA: Cuda = Cuda {
        memcpy_async: mock_copy,
        host_register: mock_register,
        host_unregister: mock_unregister,
        stream_create: mock_create,
        stream_sync: mock_sync,
        stream_destroy: mock_destroy,
    };

    fn node(storage: &mut [u8]) -> Node {
        Node {
            base: storage.as_mut_ptr(),
            slot_bytes: storage.len(),
            span: storage.len(),
            addr: "test".into(),
            stream: std::ptr::dangling_mut::<c_void>(),
            cuda: Some(&MOCK_CUDA),
        }
    }

    fn key() -> Vec<u8> {
        vec![7; HDR]
    }

    #[test]
    fn failed_put_copy_or_sync_releases_without_commit() {
        for (copy_code, sync_code, expected) in
            [(11, 0, "cudaMemcpyAsync"), (0, 22, "cudaStreamSynchronize")]
        {
            COPY_ERROR.with(|code| code.set(copy_code));
            SYNC_ERROR.with(|code| code.set(sync_code));
            let mut storage = vec![0; HDR + 4];
            let n = node(&mut storage);
            let payload = [1u8, 2, 3, 4];
            let scatters = vec![vec![(payload.as_ptr() as u64, payload.len() as u64)]];
            let mut requests = Vec::new();
            let error = put_node(&n, &[key()], &scatters, |_, req| {
                requests.push(format!("{req:?}"));
                Ok(match req {
                    KvRequest::Reserve { .. } => KvResponse::Reserved { slots: vec![0] },
                    KvRequest::Release { .. } => KvResponse::Ok,
                    _ => panic!("unexpected request: {req:?}"),
                })
            })
            .unwrap_err();
            assert!(error.contains(expected), "{error}");
            assert!(error.contains(&format!("CUDA error {}", copy_code.max(sync_code))));
            assert_eq!(requests.len(), 2);
            assert!(requests[0].starts_with("Reserve"));
            assert!(requests[1].starts_with("Release"));
        }
        COPY_ERROR.with(|code| code.set(0));
        SYNC_ERROR.with(|code| code.set(0));
    }

    #[test]
    fn failed_get_copy_or_sync_returns_error() {
        for (copy_code, sync_code, expected) in
            [(11, 0, "cudaMemcpyAsync"), (0, 22, "cudaStreamSynchronize")]
        {
            COPY_ERROR.with(|code| code.set(copy_code));
            SYNC_ERROR.with(|code| code.set(sync_code));
            let mut storage = [0u8; HDR + 4];
            storage[..HDR].copy_from_slice(&key());
            storage[HDR..].copy_from_slice(&[1, 2, 3, 4]);
            let n = node(&mut storage);
            let mut output = [0u8; 4];
            let scatters = vec![vec![(output.as_mut_ptr() as u64, output.len() as u64)]];
            let error = get_node(&n, &[key()], &scatters, |_, req| {
                assert!(matches!(req, KvRequest::Read { .. }));
                Ok(KvResponse::Looked {
                    slots: vec![Some(0)],
                })
            })
            .unwrap_err();
            assert!(error.contains(expected), "{error}");
            assert!(error.contains(&format!("CUDA error {}", copy_code.max(sync_code))));
        }
        COPY_ERROR.with(|code| code.set(0));
        SYNC_ERROR.with(|code| code.set(0));
    }

    #[test]
    fn successful_local_transfer_commits_and_reads_payload() {
        let mut storage = vec![0; HDR + 4];
        let n = node(&mut storage);
        let payload = [1u8, 2, 3, 4];
        let scatters = vec![vec![(payload.as_ptr() as u64, payload.len() as u64)]];
        let mut committed = false;
        let result = put_node(&n, &[key()], &scatters, |_, req| {
            Ok(match req {
                KvRequest::Reserve { .. } => KvResponse::Reserved { slots: vec![0] },
                KvRequest::Commit { .. } => {
                    committed = true;
                    KvResponse::Ok
                }
                _ => panic!("unexpected request: {req:?}"),
            })
        });
        assert_eq!(result.unwrap(), vec![0]);
        assert!(committed);
        let mut output = [0u8; 4];
        let scatters = vec![vec![(output.as_mut_ptr() as u64, output.len() as u64)]];
        let result = get_node(&n, &[key()], &scatters, |_, _| {
            Ok(KvResponse::Looked {
                slots: vec![Some(0)],
            })
        });
        assert_eq!(result.unwrap(), vec![0]);
        assert_eq!(output, payload);
    }
}
