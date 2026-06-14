use std::sync::Arc;

use bytes::Bytes;
use dashmap::DashMap;
use openlake_io::alloc::PooledBuffer;

#[derive(Clone, Default)]
pub struct InMemoryStore {
    inner: Arc<DashMap<String, Bytes>>,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, key: &str) -> Option<Bytes> {
        self.inner.get(key).map(|v| v.value().clone())
    }

    pub fn put(&self, key: String, value: &[u8]) {
        let mut buf = PooledBuffer::with_capacity(value.len());
        buf.extend_from_slice(value);
        self.inner.insert(key, buf.freeze());
    }
}
