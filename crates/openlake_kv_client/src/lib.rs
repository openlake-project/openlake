mod client;
#[cfg(feature = "cuda")]
mod cuda_codec;
#[cfg(all(feature = "rdma", target_os = "linux"))]
mod protocol;
mod shm_local;
mod transport;
#[cfg(all(feature = "rdma", target_os = "linux"))]
mod ucx_protocol;

use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::wrap_pyfunction;

use crate::client::{KvClient, StoreClient};
#[cfg(all(feature = "rdma", target_os = "linux"))]
use crate::protocol::RdmaProtocol;
use crate::shm_local::ShmLocalProtocol;
use crate::transport::Protocol;
#[cfg(all(feature = "rdma", target_os = "linux"))]
use crate::ucx_protocol::UcxProtocol;

#[pyclass(name = "Client")]
struct PyClient {
    inner: Box<dyn KvClient>,
}

#[pymethods]
impl PyClient {
    #[new]
    fn new(py: Python<'_>, device: &str, client_id: u16) -> PyResult<Self> {
        let device = device.to_owned();
        py.detach(|| {
            let proto: Box<dyn Protocol> = if device == "local" {
                Box::new(ShmLocalProtocol::new()?)
            } else if device == "ucx" {
                #[cfg(all(feature = "rdma", target_os = "linux"))]
                {
                    Box::new(UcxProtocol::new(client_id)?)
                }
                #[cfg(not(all(feature = "rdma", target_os = "linux")))]
                {
                    return Err("device \"ucx\" requires the RDMA-enabled package on Linux".into());
                }
            } else {
                #[cfg(all(feature = "rdma", target_os = "linux"))]
                {
                    Box::new(RdmaProtocol::new(device, client_id)?)
                }
                #[cfg(not(all(feature = "rdma", target_os = "linux")))]
                {
                    return Err(format!("device {device:?} requires the rdma feature"));
                }
            };
            StoreClient::new(proto, client_id)
        })
        .map(|c| Self { inner: Box::new(c) })
        .map_err(PyValueError::new_err)
    }

    #[pyo3(signature = (addr, node_id = 0, slot_bytes = 0))]
    fn attach(&self, py: Python<'_>, addr: &str, node_id: u16, slot_bytes: u32) -> PyResult<usize> {
        py.detach(|| self.inner.attach(addr, node_id, slot_bytes))
            .map_err(PyRuntimeError::new_err)
    }

    fn register_memory(&self, py: Python<'_>, addr: u64, len: u64) -> PyResult<()> {
        py.detach(|| self.inner.register_memory(addr, len))
            .map_err(PyRuntimeError::new_err)
    }

    fn batch_is_exist(&self, py: Python<'_>, keys: Vec<Vec<u8>>) -> PyResult<Vec<i32>> {
        py.detach(|| self.inner.batch_is_exist(&keys))
            .map_err(PyRuntimeError::new_err)
    }

    fn put_batch(
        &self,
        py: Python<'_>,
        keys: Vec<Vec<u8>>,
        addrs: Vec<Vec<u64>>,
        sizes: Vec<Vec<u64>>,
    ) -> PyResult<Vec<i32>> {
        py.detach(|| self.inner.put_batch(&keys, &addrs, &sizes))
            .map_err(PyRuntimeError::new_err)
    }

    fn get_batch(
        &self,
        py: Python<'_>,
        keys: Vec<Vec<u8>>,
        addrs: Vec<Vec<u64>>,
        sizes: Vec<Vec<u64>>,
    ) -> PyResult<Vec<i32>> {
        py.detach(|| self.inner.get_batch(&keys, &addrs, &sizes))
            .map_err(PyRuntimeError::new_err)
    }

    fn reset(&self, py: Python<'_>) -> PyResult<()> {
        py.detach(|| self.inner.reset())
            .map_err(PyRuntimeError::new_err)
    }

    fn close(&mut self, py: Python<'_>) {
        py.detach(|| self.inner.close());
    }

    #[getter]
    fn client_id(&self) -> u16 {
        self.inner.client_id()
    }

    fn __enter__(slf: Py<Self>) -> Py<Self> {
        slf
    }

    fn __exit__(
        &mut self,
        py: Python<'_>,
        _t: &Bound<'_, PyAny>,
        _v: &Bound<'_, PyAny>,
        _tb: &Bound<'_, PyAny>,
    ) -> bool {
        self.close(py);
        false
    }
}

/// True when this extension was built with `--features cuda`, i.e. the
/// `cuda_compressed_size`/`cuda_compress`/`cuda_decompress` functions below
/// are available. Always defined so callers don't need to `hasattr`-probe.
#[pyfunction]
fn cuda_compression_available() -> bool {
    cfg!(feature = "cuda")
}

/// Exact compressed byte size for `element_count` fp16/bf16 elements at
/// `group_size`. This codec is fixed-ratio (int8 group quantization), so the
/// size does not depend on the actual data.
#[cfg(feature = "cuda")]
#[pyfunction]
fn cuda_compressed_size(element_count: u64, group_size: u32) -> PyResult<u64> {
    cuda_codec::compressed_size(element_count as usize, group_size)
        .map(|size| size as u64)
        .map_err(PyValueError::new_err)
}

/// Launches the GPU compression kernel on the given CUDA stream. `input_ptr`
/// and `output_ptr` are raw device addresses (e.g. `tensor.data_ptr()`);
/// `stream_ptr` is a raw `cudaStream_t` (e.g.
/// `torch.cuda.Stream().cuda_stream`, or 0 for the default stream). The
/// launch is asynchronous: the caller must synchronize `stream_ptr` before
/// reading `output_ptr`.
///
/// This is lossy int8 group quantization, not a bit-exact codec: see
/// `cuda/src/kv_compression.cu`.
#[cfg(feature = "cuda")]
#[pyfunction]
#[pyo3(signature = (dtype, input_ptr, element_count, group_size, output_ptr, output_bytes, stream_ptr = 0))]
#[allow(clippy::too_many_arguments)]
fn cuda_compress(
    py: Python<'_>,
    dtype: &str,
    input_ptr: u64,
    element_count: u64,
    group_size: u32,
    output_ptr: u64,
    output_bytes: u64,
    stream_ptr: u64,
) -> PyResult<()> {
    let dtype = cuda_codec::Dtype::parse(dtype).map_err(PyValueError::new_err)?;
    py.detach(|| unsafe {
        cuda_codec::compress_async(
            dtype,
            input_ptr,
            element_count as usize,
            group_size,
            output_ptr,
            output_bytes as usize,
            stream_ptr,
        )
    })
    .map_err(PyRuntimeError::new_err)
}

/// Launches the GPU decompression kernel on the given CUDA stream. See
/// [`cuda_compress`] for pointer/stream conventions.
#[cfg(feature = "cuda")]
#[pyfunction]
#[pyo3(signature = (dtype, input_ptr, input_bytes, element_count, group_size, output_ptr, stream_ptr = 0))]
#[allow(clippy::too_many_arguments)]
fn cuda_decompress(
    py: Python<'_>,
    dtype: &str,
    input_ptr: u64,
    input_bytes: u64,
    element_count: u64,
    group_size: u32,
    output_ptr: u64,
    stream_ptr: u64,
) -> PyResult<()> {
    let dtype = cuda_codec::Dtype::parse(dtype).map_err(PyValueError::new_err)?;
    py.detach(|| unsafe {
        cuda_codec::decompress_async(
            dtype,
            input_ptr,
            input_bytes as usize,
            element_count as usize,
            group_size,
            output_ptr,
            stream_ptr,
        )
    })
    .map_err(PyRuntimeError::new_err)
}

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyClient>()?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add_function(wrap_pyfunction!(cuda_compression_available, m)?)?;
    #[cfg(feature = "cuda")]
    {
        m.add_function(wrap_pyfunction!(cuda_compressed_size, m)?)?;
        m.add_function(wrap_pyfunction!(cuda_compress, m)?)?;
        m.add_function(wrap_pyfunction!(cuda_decompress, m)?)?;
    }
    Ok(())
}
