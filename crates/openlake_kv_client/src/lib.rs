mod client;
#[cfg(all(feature = "rdma", target_os = "linux"))]
mod protocol;
mod shm_local;
mod transport;

use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;

use crate::client::{KvClient, StoreClient};
#[cfg(all(feature = "rdma", target_os = "linux"))]
use crate::protocol::RdmaProtocol;
use crate::shm_local::ShmLocalProtocol;
use crate::transport::Protocol;

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

    #[pyo3(signature = (addr, node_id = 0))]
    fn attach(&self, py: Python<'_>, addr: &str, node_id: u16) -> PyResult<usize> {
        py.detach(|| self.inner.attach(addr, node_id))
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

#[pymodule]
fn openlake_client(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyClient>()?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
