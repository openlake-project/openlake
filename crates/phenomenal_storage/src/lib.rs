//! Object storage engine. Holds one `StorageBackend` per cluster node and
//! runs replicated reads and writes across the chosen replicas. Networking
//! lives in the backend layer; this crate is transport agnostic.

pub mod cluster;
pub mod dsync;
pub mod ec;
pub mod engine;
pub mod error;
pub mod format;
pub mod object;

pub use cluster::{ClusterConfig, DiskAddr, DiskIdx, NodeAddr, NodeId};
pub use dsync::{DsyncClient, LockGuard};
pub use engine::{Engine, DEFAULT_INLINE_THRESHOLD};
pub use error::{StorageError, StorageResult};
pub use format::{bootstrap_format, FormatError};
pub use object::{CompletePart, MultipartInit, ObjectInfo, StorageClass};
