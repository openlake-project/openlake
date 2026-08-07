#![cfg(all(feature = "rdma", target_os = "linux"))]

use std::ffi::{c_char, c_int, c_uint, c_void, CStr};
use std::ptr::NonNull;
use std::rc::Rc;

const ERROR_BYTES: usize = 512;

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

unsafe extern "C" {
    fn ol_ucx_worker_create(
        out: *mut *mut RawWorker,
        error: *mut c_char,
        error_len: usize,
    ) -> c_int;
    fn ol_ucx_worker_destroy(worker: *mut RawWorker);
    fn ol_ucx_worker_progress(worker: *mut RawWorker) -> c_uint;
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
    fn ol_ucx_put(
        endpoint: *mut RawEndpoint,
        local_address: u64,
        length: u64,
        remote_address: u64,
        rkey: *mut RawRkey,
        error: *mut c_char,
        error_len: usize,
    ) -> c_int;
    fn ol_ucx_get(
        endpoint: *mut RawEndpoint,
        local_address: u64,
        length: u64,
        remote_address: u64,
        rkey: *mut RawRkey,
        error: *mut c_char,
        error_len: usize,
    ) -> c_int;
    fn ol_ucx_endpoint_flush(
        endpoint: *mut RawEndpoint,
        error: *mut c_char,
        error_len: usize,
    ) -> c_int;
    fn ol_ucx_tag_send(
        endpoint: *mut RawEndpoint,
        data: *const u8,
        length: usize,
        error: *mut c_char,
        error_len: usize,
    ) -> c_int;
    fn ol_ucx_tag_poll(
        worker: *mut RawWorker,
        out: *mut *mut u8,
        out_len: *mut usize,
        error: *mut c_char,
        error_len: usize,
    ) -> c_int;
}

fn call(operation: &str, f: impl FnOnce(*mut c_char, usize) -> c_int) -> Result<(), String> {
    let mut error = [0 as c_char; ERROR_BYTES];
    let status = f(error.as_mut_ptr(), error.len());
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

struct WorkerInner(NonNull<RawWorker>);

impl Drop for WorkerInner {
    fn drop(&mut self) {
        unsafe { ol_ucx_worker_destroy(self.0.as_ptr()) }
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
        Ok(Self(Rc::new(WorkerInner(
            NonNull::new(raw).ok_or("UCX returned a null worker")?,
        ))))
    }

    pub fn address(&self) -> Result<Vec<u8>, String> {
        let mut raw = std::ptr::null_mut();
        let mut len = 0;
        call("get UCX worker address", |error, error_len| unsafe {
            ol_ucx_worker_address(self.0 .0.as_ptr(), &mut raw, &mut len, error, error_len)
        })?;
        let bytes = unsafe { std::slice::from_raw_parts(raw, len) }.to_vec();
        unsafe { ol_ucx_free(raw.cast()) };
        Ok(bytes)
    }

    pub fn connect(&self, address: &[u8]) -> Result<UcxEndpoint, String> {
        let mut raw = std::ptr::null_mut();
        call("connect UCX endpoint", |error, len| unsafe {
            ol_ucx_endpoint_connect(
                self.0 .0.as_ptr(),
                address.as_ptr(),
                address.len(),
                &mut raw,
                error,
                len,
            )
        })?;
        Ok(UcxEndpoint {
            raw: NonNull::new(raw).ok_or("UCX returned a null endpoint")?,
            _worker: self.clone(),
        })
    }

    pub fn register(&self, address: u64, length: u64) -> Result<UcxMemory, String> {
        let mut raw = std::ptr::null_mut();
        call("register UCX memory", |error, len| unsafe {
            ol_ucx_memory_register(self.0 .0.as_ptr(), address, length, &mut raw, error, len)
        })?;
        Ok(UcxMemory {
            raw: NonNull::new(raw).ok_or("UCX returned a null memory handle")?,
            _worker: self.clone(),
        })
    }

    pub fn progress(&self) -> u32 {
        unsafe { ol_ucx_worker_progress(self.0 .0.as_ptr()) }
    }

    pub fn poll_control(&self) -> Result<Option<Vec<u8>>, String> {
        let mut raw = std::ptr::null_mut();
        let mut len = 0;
        let mut error = [0 as c_char; ERROR_BYTES];
        let status = unsafe {
            ol_ucx_tag_poll(
                self.0 .0.as_ptr(),
                &mut raw,
                &mut len,
                error.as_mut_ptr(),
                error.len(),
            )
        };
        if status == 1 {
            return Ok(None);
        }
        if status != 0 {
            let detail = unsafe { CStr::from_ptr(error.as_ptr()) }.to_string_lossy();
            return if detail.is_empty() {
                Err(format!("poll UCX control message: UCX status {status}"))
            } else {
                Err(detail.into_owned())
            };
        }
        let bytes = unsafe { std::slice::from_raw_parts(raw, len) }.to_vec();
        unsafe { ol_ucx_free(raw.cast()) };
        Ok(Some(bytes))
    }
}

pub struct UcxEndpoint {
    raw: NonNull<RawEndpoint>,
    _worker: UcxWorker,
}

impl UcxEndpoint {
    pub fn unpack_rkey(&self, packed: &[u8]) -> Result<UcxRkey, String> {
        let mut raw = std::ptr::null_mut();
        call("unpack UCX rkey", |error, len| unsafe {
            ol_ucx_rkey_unpack(
                self.raw.as_ptr(),
                packed.as_ptr(),
                packed.len(),
                &mut raw,
                error,
                len,
            )
        })?;
        Ok(UcxRkey(
            NonNull::new(raw).ok_or("UCX returned a null rkey")?,
        ))
    }

    pub fn put(
        &self,
        local_address: u64,
        length: u64,
        remote_address: u64,
        rkey: &UcxRkey,
    ) -> Result<(), String> {
        call("UCX put", |error, len| unsafe {
            ol_ucx_put(
                self.raw.as_ptr(),
                local_address,
                length,
                remote_address,
                rkey.0.as_ptr(),
                error,
                len,
            )
        })
    }

    pub fn get(
        &self,
        local_address: u64,
        length: u64,
        remote_address: u64,
        rkey: &UcxRkey,
    ) -> Result<(), String> {
        call("UCX get", |error, len| unsafe {
            ol_ucx_get(
                self.raw.as_ptr(),
                local_address,
                length,
                remote_address,
                rkey.0.as_ptr(),
                error,
                len,
            )
        })
    }

    pub fn flush(&self) -> Result<(), String> {
        call("flush UCX endpoint", |error, len| unsafe {
            ol_ucx_endpoint_flush(self.raw.as_ptr(), error, len)
        })
    }

    pub fn send_control(&self, body: &[u8]) -> Result<(), String> {
        call("send UCX control message", |error, len| unsafe {
            ol_ucx_tag_send(self.raw.as_ptr(), body.as_ptr(), body.len(), error, len)
        })
    }
}

impl Drop for UcxEndpoint {
    fn drop(&mut self) {
        unsafe { ol_ucx_endpoint_destroy(self.raw.as_ptr()) }
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

pub struct UcxRkey(NonNull<RawRkey>);

impl Drop for UcxRkey {
    fn drop(&mut self) {
        unsafe { ol_ucx_rkey_destroy(self.0.as_ptr()) }
    }
}
