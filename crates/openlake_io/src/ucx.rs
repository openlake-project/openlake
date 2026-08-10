#![cfg(all(feature = "rdma", target_os = "linux"))]

use std::ffi::{c_char, c_int, c_uint, c_void, CStr};
use std::future::Future;
use std::os::fd::{FromRawFd, OwnedFd};
use std::pin::Pin;
use std::ptr::NonNull;
use std::rc::Rc;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use compio::net::PollFd;
use futures::task::AtomicWaker;

const ERROR_BYTES: usize = 512;
const IN_PROGRESS: c_int = 1;
const REQUEST_PENDING: c_int = c_int::MIN;
const MAX_TRANSPORTS: usize = 64;

#[repr(C)]
struct RawWorker {
    _private: [u8; 0],
}
#[repr(C)]
struct RawEndpoint {
    _private: [u8; 0],
}
#[repr(C)]
struct RawMemory {
    _private: [u8; 0],
}
#[repr(C)]
struct RawRkey {
    _private: [u8; 0],
}
#[repr(C)]
struct RawRequest {
    _private: [u8; 0],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct RawTransport {
    transport_name: *const c_char,
    device_name: *const c_char,
}

#[repr(C)]
struct RawCompletion {
    complete: unsafe extern "C" fn(*mut c_void, c_int),
    state: Arc<RequestState>,
}

unsafe extern "C" {
    fn ol_ucx_worker_create(
        out: *mut *mut RawWorker,
        error: *mut c_char,
        error_len: usize,
    ) -> c_int;
    fn ol_ucx_worker_destroy(worker: *mut RawWorker);
    fn ol_ucx_worker_progress(worker: *mut RawWorker) -> c_uint;
    fn ol_ucx_worker_get_efd(
        worker: *mut RawWorker,
        out: *mut c_int,
        error: *mut c_char,
        error_len: usize,
    ) -> c_int;
    fn ol_ucx_worker_arm(worker: *mut RawWorker, error: *mut c_char, error_len: usize) -> c_int;
    fn ol_ucx_worker_signal(worker: *mut RawWorker, error: *mut c_char, error_len: usize) -> c_int;
    fn ol_ucx_worker_address(
        worker: *mut RawWorker,
        out: *mut *mut u8,
        out_len: *mut usize,
        error: *mut c_char,
        error_len: usize,
    ) -> c_int;
    fn ol_ucx_free(pointer: *mut c_void);
    fn ol_ucx_endpoint_connect(
        worker: *mut RawWorker,
        address: *const u8,
        address_len: usize,
        out: *mut *mut RawEndpoint,
        error: *mut c_char,
        error_len: usize,
    ) -> c_int;
    fn ol_ucx_endpoint_destroy(endpoint: *mut RawEndpoint);
    fn ol_ucx_endpoint_query_transports(
        endpoint: *mut RawEndpoint,
        transports: *mut RawTransport,
        capacity: usize,
        out_len: *mut usize,
        error: *mut c_char,
        error_len: usize,
    ) -> c_int;
    fn ol_ucx_memory_register(
        worker: *mut RawWorker,
        address: u64,
        length: u64,
        out: *mut *mut RawMemory,
        error: *mut c_char,
        error_len: usize,
    ) -> c_int;
    fn ol_ucx_memory_destroy(memory: *mut RawMemory);
    fn ol_ucx_memory_pack_rkey(
        memory: *mut RawMemory,
        out: *mut *mut u8,
        out_len: *mut usize,
        error: *mut c_char,
        error_len: usize,
    ) -> c_int;
    fn ol_ucx_rkey_unpack(
        endpoint: *mut RawEndpoint,
        packed: *const u8,
        packed_len: usize,
        out: *mut *mut RawRkey,
        error: *mut c_char,
        error_len: usize,
    ) -> c_int;
    fn ol_ucx_rkey_destroy(rkey: *mut RawRkey);
    fn ol_ucx_put_start(
        endpoint: *mut RawEndpoint,
        local_address: u64,
        length: u64,
        remote_address: u64,
        rkey: *mut RawRkey,
        completion: *mut c_void,
        out: *mut *mut RawRequest,
        error: *mut c_char,
        error_len: usize,
    ) -> c_int;
    fn ol_ucx_get_start(
        endpoint: *mut RawEndpoint,
        local_address: u64,
        length: u64,
        remote_address: u64,
        rkey: *mut RawRkey,
        completion: *mut c_void,
        out: *mut *mut RawRequest,
        error: *mut c_char,
        error_len: usize,
    ) -> c_int;
    fn ol_ucx_endpoint_flush_start(
        endpoint: *mut RawEndpoint,
        completion: *mut c_void,
        out: *mut *mut RawRequest,
        error: *mut c_char,
        error_len: usize,
    ) -> c_int;
    fn ol_ucx_tag_send_start(
        endpoint: *mut RawEndpoint,
        data: *const u8,
        length: usize,
        completion: *mut c_void,
        out: *mut *mut RawRequest,
        error: *mut c_char,
        error_len: usize,
    ) -> c_int;
    fn ol_ucx_request_release(request: *mut RawRequest);
    fn ol_ucx_request_cancel(worker: *mut RawWorker, request: *mut RawRequest);
    fn ol_ucx_tag_poll(
        worker: *mut RawWorker,
        out: *mut *mut u8,
        out_len: *mut usize,
        error: *mut c_char,
        error_len: usize,
    ) -> c_int;
}

fn result(operation: &str, status: c_int, error: &[c_char]) -> Result<(), String> {
    if status == 0 {
        return Ok(());
    }
    let detail = unsafe { CStr::from_ptr(error.as_ptr()) }.to_string_lossy();
    if detail.is_empty() {
        Err(format!("{operation}: UCX status {status}"))
    } else {
        Err(detail.into_owned())
    }
}

fn call(operation: &str, f: impl FnOnce(*mut c_char, usize) -> c_int) -> Result<(), String> {
    let mut error = [0 as c_char; ERROR_BYTES];
    let status = f(error.as_mut_ptr(), error.len());
    result(operation, status, &error)
}

struct WorkerInner {
    raw: NonNull<RawWorker>,
    event: PollFd<OwnedFd>,
}

impl Drop for WorkerInner {
    fn drop(&mut self) {
        unsafe { ol_ucx_worker_destroy(self.raw.as_ptr()) }
    }
}

#[derive(Clone)]
pub struct UcxWorker(Rc<WorkerInner>);

impl UcxWorker {
    pub fn new() -> Result<Self, String> {
        let mut raw = std::ptr::null_mut();
        call("create UCX worker", |error, len| unsafe {
            ol_ucx_worker_create(&mut raw, error, len)
        })?;
        let raw = NonNull::new(raw).ok_or("UCX returned a null worker")?;
        let mut event_fd = -1;
        if let Err(error) = call("get UCX event fd", |buffer, len| unsafe {
            ol_ucx_worker_get_efd(raw.as_ptr(), &mut event_fd, buffer, len)
        }) {
            unsafe { ol_ucx_worker_destroy(raw.as_ptr()) };
            return Err(error);
        }
        let duplicate = unsafe { libc::fcntl(event_fd, libc::F_DUPFD_CLOEXEC, 0) };
        if duplicate < 0 {
            unsafe { ol_ucx_worker_destroy(raw.as_ptr()) };
            return Err(format!(
                "duplicate UCX event fd: {}",
                std::io::Error::last_os_error()
            ));
        }
        let event = match PollFd::new(unsafe { OwnedFd::from_raw_fd(duplicate) }) {
            Ok(event) => event,
            Err(error) => {
                unsafe { ol_ucx_worker_destroy(raw.as_ptr()) };
                return Err(format!("register UCX event fd: {error}"));
            }
        };
        Ok(Self(Rc::new(WorkerInner { raw, event })))
    }

    pub fn address(&self) -> Result<Vec<u8>, String> {
        let mut raw = std::ptr::null_mut();
        let mut len = 0;
        call("get UCX worker address", |error, error_len| unsafe {
            ol_ucx_worker_address(self.0.raw.as_ptr(), &mut raw, &mut len, error, error_len)
        })?;
        let bytes = unsafe { std::slice::from_raw_parts(raw, len) }.to_vec();
        unsafe { ol_ucx_free(raw.cast()) };
        Ok(bytes)
    }

    pub fn connect(&self, address: &[u8]) -> Result<UcxEndpoint, String> {
        let mut raw = std::ptr::null_mut();
        call("connect UCX endpoint", |error, len| unsafe {
            ol_ucx_endpoint_connect(
                self.0.raw.as_ptr(),
                address.as_ptr(),
                address.len(),
                &mut raw,
                error,
                len,
            )
        })?;
        Ok(UcxEndpoint(Rc::new(EndpointInner {
            raw: NonNull::new(raw).ok_or("UCX returned a null endpoint")?,
            worker: self.clone(),
        })))
    }

    pub fn register(&self, address: u64, length: u64) -> Result<UcxMemory, String> {
        let mut raw = std::ptr::null_mut();
        call("register UCX memory", |error, len| unsafe {
            ol_ucx_memory_register(self.0.raw.as_ptr(), address, length, &mut raw, error, len)
        })?;
        Ok(UcxMemory {
            raw: NonNull::new(raw).ok_or("UCX returned a null memory handle")?,
            _worker: self.clone(),
        })
    }

    pub fn progress(&self) -> u32 {
        unsafe { ol_ucx_worker_progress(self.0.raw.as_ptr()) }
    }

    pub async fn wait_for_event(&self) -> Result<(), String> {
        loop {
            if self.progress() != 0 {
                return Ok(());
            }
            let mut error = [0 as c_char; ERROR_BYTES];
            let status =
                unsafe { ol_ucx_worker_arm(self.0.raw.as_ptr(), error.as_mut_ptr(), error.len()) };
            if status == IN_PROGRESS {
                continue;
            }
            result("arm UCX worker", status, &error)?;
            self.0
                .event
                .read_ready()
                .await
                .map_err(|error| format!("wait for UCX event: {error}"))?;
            return Ok(());
        }
    }

    fn signal(&self) -> Result<(), String> {
        call("signal UCX worker", |error, len| unsafe {
            ol_ucx_worker_signal(self.0.raw.as_ptr(), error, len)
        })
    }

    pub fn poll_control(&self) -> Result<Option<Vec<u8>>, String> {
        let mut raw = std::ptr::null_mut();
        let mut len = 0;
        let mut error = [0 as c_char; ERROR_BYTES];
        let status = unsafe {
            ol_ucx_tag_poll(
                self.0.raw.as_ptr(),
                &mut raw,
                &mut len,
                error.as_mut_ptr(),
                error.len(),
            )
        };
        if status == IN_PROGRESS {
            return Ok(None);
        }
        result("poll UCX control message", status, &error)?;
        let bytes = unsafe { std::slice::from_raw_parts(raw, len) }.to_vec();
        unsafe { ol_ucx_free(raw.cast()) };
        Ok(Some(bytes))
    }
}

struct EndpointInner {
    raw: NonNull<RawEndpoint>,
    worker: UcxWorker,
}

impl Drop for EndpointInner {
    fn drop(&mut self) {
        unsafe { ol_ucx_endpoint_destroy(self.raw.as_ptr()) }
    }
}

#[derive(Clone)]
pub struct UcxEndpoint(Rc<EndpointInner>);

impl UcxEndpoint {
    pub fn transports(&self) -> Result<Vec<crate::rpc::UcxTransport>, String> {
        let mut raw = vec![RawTransport::default(); MAX_TRANSPORTS];
        let mut count = 0;
        call("query UCX endpoint transports", |error, error_len| unsafe {
            ol_ucx_endpoint_query_transports(
                self.0.raw.as_ptr(),
                raw.as_mut_ptr(),
                raw.len(),
                &mut count,
                error,
                error_len,
            )
        })?;
        raw.truncate(count.min(raw.len()));
        raw.into_iter()
            .map(|entry| unsafe {
                Ok(crate::rpc::UcxTransport {
                    transport: CStr::from_ptr(entry.transport_name)
                        .to_string_lossy()
                        .into_owned(),
                    device: CStr::from_ptr(entry.device_name)
                        .to_string_lossy()
                        .into_owned(),
                })
            })
            .collect()
    }

    pub fn unpack_rkey(&self, packed: &[u8]) -> Result<UcxRkey, String> {
        let mut raw = std::ptr::null_mut();
        call("unpack UCX rkey", |error, len| unsafe {
            ol_ucx_rkey_unpack(
                self.0.raw.as_ptr(),
                packed.as_ptr(),
                packed.len(),
                &mut raw,
                error,
                len,
            )
        })?;
        Ok(UcxRkey(Rc::new(RkeyInner(
            NonNull::new(raw).ok_or("UCX returned a null rkey")?,
        ))))
    }

    pub fn put(
        &self,
        local_address: u64,
        length: u64,
        remote_address: u64,
        rkey: &UcxRkey,
    ) -> Result<UcxRequest, String> {
        let mut raw = std::ptr::null_mut();
        let (state, completion) = request_completion();
        call("start UCX put", |error, len| unsafe {
            ol_ucx_put_start(
                self.0.raw.as_ptr(),
                local_address,
                length,
                remote_address,
                rkey.0 .0.as_ptr(),
                completion.cast(),
                &mut raw,
                error,
                len,
            )
        })?;
        UcxRequest::new(
            raw,
            state,
            self.0.worker.clone(),
            Some(self.clone()),
            Some(rkey.clone()),
            None,
        )
    }

    pub fn get(
        &self,
        local_address: u64,
        length: u64,
        remote_address: u64,
        rkey: &UcxRkey,
    ) -> Result<UcxRequest, String> {
        let mut raw = std::ptr::null_mut();
        let (state, completion) = request_completion();
        call("start UCX get", |error, len| unsafe {
            ol_ucx_get_start(
                self.0.raw.as_ptr(),
                local_address,
                length,
                remote_address,
                rkey.0 .0.as_ptr(),
                completion.cast(),
                &mut raw,
                error,
                len,
            )
        })?;
        UcxRequest::new(
            raw,
            state,
            self.0.worker.clone(),
            Some(self.clone()),
            Some(rkey.clone()),
            None,
        )
    }

    pub fn flush(&self) -> Result<UcxRequest, String> {
        let mut raw = std::ptr::null_mut();
        let (state, completion) = request_completion();
        call("start UCX endpoint flush", |error, len| unsafe {
            ol_ucx_endpoint_flush_start(
                self.0.raw.as_ptr(),
                completion.cast(),
                &mut raw,
                error,
                len,
            )
        })?;
        UcxRequest::new(
            raw,
            state,
            self.0.worker.clone(),
            Some(self.clone()),
            None,
            None,
        )
    }

    pub fn send_control(&self, body: Vec<u8>) -> Result<UcxRequest, String> {
        let mut raw = std::ptr::null_mut();
        let (state, completion) = request_completion();
        call("start UCX control send", |error, len| unsafe {
            ol_ucx_tag_send_start(
                self.0.raw.as_ptr(),
                body.as_ptr(),
                body.len(),
                completion.cast(),
                &mut raw,
                error,
                len,
            )
        })?;
        UcxRequest::new(
            raw,
            state,
            self.0.worker.clone(),
            Some(self.clone()),
            None,
            Some(body),
        )
    }
}

pub struct UcxMemory {
    raw: NonNull<RawMemory>,
    _worker: UcxWorker,
}

impl UcxMemory {
    pub fn packed_rkey(&self) -> Result<Vec<u8>, String> {
        let mut raw = std::ptr::null_mut();
        let mut len = 0;
        call("pack UCX rkey", |error, error_len| unsafe {
            ol_ucx_memory_pack_rkey(self.raw.as_ptr(), &mut raw, &mut len, error, error_len)
        })?;
        let bytes = unsafe { std::slice::from_raw_parts(raw, len) }.to_vec();
        unsafe { ol_ucx_free(raw.cast()) };
        Ok(bytes)
    }
}

impl Drop for UcxMemory {
    fn drop(&mut self) {
        unsafe { ol_ucx_memory_destroy(self.raw.as_ptr()) }
    }
}

struct RkeyInner(NonNull<RawRkey>);

impl Drop for RkeyInner {
    fn drop(&mut self) {
        unsafe { ol_ucx_rkey_destroy(self.0.as_ptr()) }
    }
}

#[derive(Clone)]
pub struct UcxRkey(Rc<RkeyInner>);

struct RequestState {
    status: AtomicI32,
    waker: AtomicWaker,
}

fn request_completion() -> (Arc<RequestState>, *mut RawCompletion) {
    let state = Arc::new(RequestState {
        status: AtomicI32::new(REQUEST_PENDING),
        waker: AtomicWaker::new(),
    });
    let completion = Box::into_raw(Box::new(RawCompletion {
        complete: request_complete,
        state: state.clone(),
    }));
    (state, completion)
}

unsafe extern "C" fn request_complete(completion: *mut c_void, status: c_int) {
    let completion = unsafe { Box::from_raw(completion.cast::<RawCompletion>()) };
    completion.state.status.store(status, Ordering::Release);
    completion.state.waker.wake();
}

#[must_use = "UCX requests must be awaited or dropped"]
pub struct UcxRequest {
    raw: Option<NonNull<RawRequest>>,
    state: Arc<RequestState>,
    worker: UcxWorker,
    _endpoint: Option<UcxEndpoint>,
    _rkey: Option<UcxRkey>,
    _buffer: Option<Vec<u8>>,
}

impl UcxRequest {
    fn new(
        raw: *mut RawRequest,
        state: Arc<RequestState>,
        worker: UcxWorker,
        endpoint: Option<UcxEndpoint>,
        rkey: Option<UcxRkey>,
        buffer: Option<Vec<u8>>,
    ) -> Result<Self, String> {
        let request = Self {
            raw: NonNull::new(raw),
            state,
            worker: worker.clone(),
            _endpoint: endpoint,
            _rkey: rkey,
            _buffer: buffer,
        };
        if request.raw.is_some() {
            worker.signal()?;
        }
        Ok(request)
    }
}

impl Future for UcxRequest {
    type Output = Result<(), String>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut status = self.state.status.load(Ordering::Acquire);
        if status == REQUEST_PENDING {
            self.state.waker.register(cx.waker());
            status = self.state.status.load(Ordering::Acquire);
        }
        if status == REQUEST_PENDING {
            return Poll::Pending;
        }
        if let Some(request) = self.raw.take() {
            unsafe { ol_ucx_request_release(request.as_ptr()) };
        }
        if status == 0 {
            Poll::Ready(Ok(()))
        } else {
            Poll::Ready(Err(format!("UCX request: status {status}")))
        }
    }
}

impl Drop for UcxRequest {
    fn drop(&mut self) {
        if let Some(request) = self.raw.take() {
            unsafe { ol_ucx_request_cancel(self.worker.0.raw.as_ptr(), request.as_ptr()) }
        }
    }
}
