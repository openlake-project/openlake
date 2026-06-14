use std::sync::Arc;

use bytes::Bytes;
use dashmap::DashMap;
use openlake_io::alloc::PooledBuffer;

/// Process-wide in-memory blob store keyed by string. Shared across
/// every runtime, so a value written on one core is visible on all
/// others. Cloning is an `Arc` bump. `DashMap` shards the keyspace
/// internally, so reads and writes on different keys do not contend.
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
