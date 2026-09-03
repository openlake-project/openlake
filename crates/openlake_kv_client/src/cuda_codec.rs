//! FFI bindings to the on-GPU int8 group-quantization codec in
//! `cuda/src/kv_compression.cu`, used by the vLLM connector's *optional*
//! GPU-side KV compression path for low-bandwidth (RDMA/UCX/H2) transfers.
//!
//! This codec is **not** bit-exact: each `group_size`-element chunk is
//! rescaled to a shared absmax and quantized to int8 (see the CUDA smoke
//! test's tolerated `0.05` max error), trading KV-cache precision for a
//! smaller wire payload. Callers that need bit-exact round trips must not
//! enable it.
//!
//! Only compiled with `--features cuda`; requires a CUDA 12+ toolkit and
//! `nvcc` at build time (see build.rs).
#![cfg(feature = "cuda")]

use std::ffi::{c_void, CStr};
use std::os::raw::{c_char, c_int};

pub const MIN_GROUP_SIZE: u32 = 16;
pub const MAX_GROUP_SIZE: u32 = 4096;
pub const GROUP_SIZE_ALIGNMENT: u32 = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dtype {
    Fp16,
    Bf16,
}

impl Dtype {
    pub fn parse(name: &str) -> Result<Self, String> {
        match name {
            "fp16" | "float16" | "half" => Ok(Dtype::Fp16),
            "bf16" | "bfloat16" => Ok(Dtype::Bf16),
            other => Err(format!(
                "unsupported GPU-compression dtype {other:?} (want fp16 or bf16)"
            )),
        }
    }
}

type CudaStream = *mut c_void;

unsafe extern "C" {
    fn openlake_kv_compressed_size(element_count: usize, group_size: u32) -> usize;

    fn openlake_kv_compress_fp16_async(
        input: *const c_void,
        element_count: usize,
        group_size: u32,
        output: *mut c_void,
        output_bytes: usize,
        stream: CudaStream,
    ) -> c_int;
    fn openlake_kv_compress_bf16_async(
        input: *const c_void,
        element_count: usize,
        group_size: u32,
        output: *mut c_void,
        output_bytes: usize,
        stream: CudaStream,
    ) -> c_int;

    fn openlake_kv_decompress_fp16_async(
        input: *const c_void,
        input_bytes: usize,
        element_count: usize,
        group_size: u32,
        output: *mut c_void,
        stream: CudaStream,
    ) -> c_int;
    fn openlake_kv_decompress_bf16_async(
        input: *const c_void,
        input_bytes: usize,
        element_count: usize,
        group_size: u32,
        output: *mut c_void,
        stream: CudaStream,
    ) -> c_int;

    fn cudaGetErrorString(error: c_int) -> *const c_char;
}

fn cuda_result(status: c_int, op: &str) -> Result<(), String> {
    if status == 0 {
        return Ok(());
    }
    let message = unsafe {
        let ptr = cudaGetErrorString(status);
        if ptr.is_null() {
            "unknown CUDA error".to_string()
        } else {
            CStr::from_ptr(ptr).to_string_lossy().into_owned()
        }
    };
    Err(format!("{op} failed: {message} (cudaError_t={status})"))
}

fn validate_group_size(group_size: u32) -> Result<(), String> {
    if group_size < MIN_GROUP_SIZE
        || group_size > MAX_GROUP_SIZE
        || group_size % GROUP_SIZE_ALIGNMENT != 0
    {
        return Err(format!(
            "group_size {group_size} must be in [{MIN_GROUP_SIZE}, {MAX_GROUP_SIZE}] and a \
             multiple of {GROUP_SIZE_ALIGNMENT}"
        ));
    }
    Ok(())
}

/// Worst-case (and, since this is fixed-ratio quantization, *exact*) byte
/// size of the compressed buffer for `element_count` elements of the given
/// `group_size`. Returns 0 for invalid inputs, matching the C ABI.
pub fn compressed_size(element_count: usize, group_size: u32) -> Result<usize, String> {
    validate_group_size(group_size)?;
    if element_count == 0 {
        return Err("element_count must be > 0".to_string());
    }
    let size = unsafe { openlake_kv_compressed_size(element_count, group_size) };
    if size == 0 {
        return Err(format!(
            "no valid compressed layout for element_count={element_count} group_size={group_size}"
        ));
    }
    Ok(size)
}

/// Launches the compression kernel on `stream` (a raw `cudaStream_t` value,
/// e.g. from `torch.cuda.Stream().cuda_stream`; 0 is CUDA's default stream).
///
/// # Safety
/// `input` must point to at least `element_count * sizeof(dtype)` readable
/// device bytes and `output` to at least `output_bytes` writable device
/// bytes, both valid for the lifetime of the (asynchronous) kernel launch.
/// `stream` must be a valid `cudaStream_t` (or 0).
pub unsafe fn compress_async(
    dtype: Dtype,
    input: u64,
    element_count: usize,
    group_size: u32,
    output: u64,
    output_bytes: usize,
    stream: u64,
) -> Result<(), String> {
    validate_group_size(group_size)?;
    let input = input as usize as *const c_void;
    let output = output as usize as *mut c_void;
    let stream = stream as usize as CudaStream;
    let status = unsafe {
        match dtype {
            Dtype::Fp16 => openlake_kv_compress_fp16_async(
                input,
                element_count,
                group_size,
                output,
                output_bytes,
                stream,
            ),
            Dtype::Bf16 => openlake_kv_compress_bf16_async(
                input,
                element_count,
                group_size,
                output,
                output_bytes,
                stream,
            ),
        }
    };
    cuda_result(status, "openlake_kv_compress_async")
}

/// Launches the decompression kernel on `stream`. See [`compress_async`] for
/// the pointer-validity and stream requirements.
///
/// # Safety
/// `input` must point to at least `input_bytes` readable device bytes
/// (the buffer produced by [`compress_async`]) and `output` to at least
/// `element_count * sizeof(dtype)` writable device bytes.
pub unsafe fn decompress_async(
    dtype: Dtype,
    input: u64,
    input_bytes: usize,
    element_count: usize,
    group_size: u32,
    output: u64,
    stream: u64,
) -> Result<(), String> {
    validate_group_size(group_size)?;
    let input = input as usize as *const c_void;
    let output = output as usize as *mut c_void;
    let stream = stream as usize as CudaStream;
    let status = unsafe {
        match dtype {
            Dtype::Fp16 => openlake_kv_decompress_fp16_async(
                input,
                input_bytes,
                element_count,
                group_size,
                output,
                stream,
            ),
            Dtype::Bf16 => openlake_kv_decompress_bf16_async(
                input,
                input_bytes,
                element_count,
                group_size,
                output,
                stream,
            ),
        }
    };
    cuda_result(status, "openlake_kv_decompress_async")
}
