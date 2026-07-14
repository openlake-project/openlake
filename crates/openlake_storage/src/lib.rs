//! Object storage engine. Holds one `StorageBackend` per cluster node and
//! runs replicated reads and writes across the chosen replicas. Networking
//! lives in the backend layer; this crate is transport agnostic.

pub mod cluster;
pub mod dsync;
pub mod ec;
pub mod engine;
pub mod error;
pub mod format;
#[cfg(all(feature = "rdma", target_os = "linux"))]
pub mod kv_engine;
pub mod managed;
pub mod object;

pub use cluster::{ClusterConfig, DiskAddr, DiskIdx, NodeAddr, NodeId};
pub use dsync::{DsyncClient, LockGuard};
pub use engine::{ByteRange, Engine, DEFAULT_EC_PER_SHARD_BYTES, DEFAULT_INLINE_THRESHOLD};
pub use error::{StorageError, StorageResult};
pub use format::{bootstrap_format, FormatError};
#[cfg(all(feature = "rdma", target_os = "linux"))]
pub use kv_engine::KvEngine;
pub use managed::{Managed, Stats};
pub use object::{CompletePart, MultipartInit, ObjectInfo, StorageClass};
