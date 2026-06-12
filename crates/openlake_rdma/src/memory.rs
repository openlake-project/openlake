use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use crate::work::ScatterGatherEntry;
use crate::{Result, TransportError};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AccessFlags(u32);

impl AccessFlags {
    pub const LOCAL_WRITE: AccessFlags = AccessFlags(1);
    pub const REMOTE_WRITE: AccessFlags = AccessFlags(1 << 1);
    pub const REMOTE_READ: AccessFlags = AccessFlags(1 << 2);

    pub const fn none() -> Self {
        AccessFlags(0)
    }

    pub fn contains(self, other: AccessFlags) -> bool {
        self.0 & other.0 == other.0
    }
}

impl std::ops::BitOr for AccessFlags {
    type Output = AccessFlags;
    fn bitor(self, other: AccessFlags) -> AccessFlags {
        AccessFlags(self.0 | other.0)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BufferKind {
    HostPinned,
    DeviceResident,
}

pub(crate) struct RegisteredBuffer {
    pub bytes: Mutex<Vec<u8>>,
    pub access: AccessFlags,
}

pub(crate) struct Registry {
    next_key: AtomicU32,
    regions: Mutex<HashMap<u32, Arc<RegisteredBuffer>>>,
}

impl Registry {
    pub(crate) fn new() -> Self {
        Registry {
            next_key: AtomicU32::new(0x1000),
            regions: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) fn register(
        &self,
        length: usize,
        access: AccessFlags,
    ) -> (u32, Arc<RegisteredBuffer>) {
        let key = self.next_key.fetch_add(1, Ordering::Relaxed);
        let buffer = Arc::new(RegisteredBuffer {
            bytes: Mutex::new(vec![0u8; length]),
            access,
        });
        self.regions.lock().unwrap().insert(key, buffer.clone());
        (key, buffer)
    }

    pub(crate) fn lookup(&self, key: u32) -> Option<Arc<RegisteredBuffer>> {
        self.regions.lock().unwrap().get(&key).cloned()
    }

    pub(crate) fn deregister(&self, key: u32) {
        self.regions.lock().unwrap().remove(&key);
    }
}

pub struct ProtectionDomain {
    registry: Arc<Registry>,
}

impl ProtectionDomain {
    pub(crate) fn new(registry: Arc<Registry>) -> Self {
        ProtectionDomain { registry }
    }

    pub fn register_region(&self, length: usize, access: AccessFlags) -> MemoryRegion {
        self.allocate(length, access, BufferKind::HostPinned)
    }

    pub fn register_device_region(&self, length: usize, access: AccessFlags) -> MemoryRegion {
        self.allocate(length, access, BufferKind::DeviceResident)
    }

    fn allocate(&self, length: usize, access: AccessFlags, kind: BufferKind) -> MemoryRegion {
        let (key, buffer) = self.registry.register(length, access);
        MemoryRegion {
            key,
            length,
            access,
            kind,
            buffer,
            registry: self.registry.clone(),
        }
    }
}

pub struct MemoryRegion {
    key: u32,
    length: usize,
    access: AccessFlags,
    kind: BufferKind,
    buffer: Arc<RegisteredBuffer>,
    registry: Arc<Registry>,
}

impl MemoryRegion {
    pub fn lkey(&self) -> u32 {
        self.key
    }

    pub fn rkey(&self) -> u32 {
        self.key
    }

    pub fn len(&self) -> usize {
        self.length
    }

    pub fn is_empty(&self) -> bool {
        self.length == 0
    }

    pub fn access(&self) -> AccessFlags {
        self.access
    }

    pub fn kind(&self) -> BufferKind {
        self.kind
    }

    pub fn remote_addr(&self) -> u64 {
        0
    }

    pub fn scatter_gather(&self, offset: u64, length: usize) -> ScatterGatherEntry {
        ScatterGatherEntry {
            addr: offset,
            length,
            lkey: self.key,
        }
    }

    pub fn fill(&self, value: u8) {
        self.buffer
            .bytes
            .lock()
            .unwrap()
            .iter_mut()
            .for_each(|slot| *slot = value);
    }

    pub fn write_at(&self, offset: usize, data: &[u8]) -> Result<()> {
        let end = offset + data.len();
        if end > self.length {
            return Err(TransportError::LocalLengthMismatch {
                lkey: self.key,
                requested: end,
                region_len: self.length,
            });
        }
        self.buffer.bytes.lock().unwrap()[offset..end].copy_from_slice(data);
        Ok(())
    }

    pub fn read_into(&self, offset: usize, out: &mut [u8]) -> Result<()> {
        let end = offset + out.len();
        if end > self.length {
            return Err(TransportError::LocalLengthMismatch {
                lkey: self.key,
                requested: end,
                region_len: self.length,
            });
        }
        out.copy_from_slice(&self.buffer.bytes.lock().unwrap()[offset..end]);
        Ok(())
    }

    pub fn checksum(&self) -> u64 {
        let mut hash: u64 = 0xcbf29ce484222325;
        for byte in self.buffer.bytes.lock().unwrap().iter() {
            hash ^= *byte as u64;
            hash = hash.wrapping_mul(0x100000001b3);
        }
        hash
    }
}

impl Drop for MemoryRegion {
    fn drop(&mut self) {
        self.registry.deregister(self.key);
    }
}
