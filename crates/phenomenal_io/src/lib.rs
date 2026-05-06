//! Drive level storage backend.
//!
//! Every trait method targets one drive's worth of bytes. The vocabulary
//! is volumes (buckets at this layer), paths within a volume, and
//! `FileInfo` records carrying the contents of `xl.meta`. Higher layers
//! compose multiple `StorageBackend` instances to implement erasure
//! coding, replication, and cluster semantics.
//!
//! Data-path bytes flow through `ByteStream` / `ByteSink` end to end —
//! no layer (S3 frontend, engine, backend, wire) is permitted to
//! materialise an object. See `stream` for the abstraction and
//! `local_fs` / `remote_fs` for the FS and RPC implementations.

pub mod alloc;
pub mod backend;
pub mod error;
pub mod local_fs;
pub mod remote_fs;
pub mod rpc;
pub mod stream;
pub mod tuning;
pub mod types;
pub mod xl_meta;

pub use alloc::{MemoryPool, MemoryPoolConfig, PooledBuffer};
pub use backend::{LockPeer, StorageBackend};
pub use error::{IoError, IoResult};
pub use local_fs::{LocalFsBackend, MULTIPART_VOL, STAGING_VOL, SYSTEM_BUCKET};
pub use remote_fs::{PeerConn, RemoteBackend};
pub use stream::{
    pump_compio_to_sink, pump_n, read_full, ByteSink, ByteStream,
    BytesByteStream, RopeByteStream, VecByteSink, VecByteStream,
};
pub use tuning::{DRAIN_CHUNK_BYTES, FRAME_HEADER_BYTES, STREAM_CHUNK_BYTES, TCP_BUFFER_BYTES};
pub use types::{
    BitrotAlgorithm, BitrotVerifier, BucketMeta, ChecksumInfo, DeleteOptions, DiskInfo,
    ErasureInfo, FileInfo, ObjectPartInfo, RenameDataResp, RenameOptions, UpdateMetadataOpts,
    VersionType, VersioningStatus, VolInfo,
};
