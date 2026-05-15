//! `StorageBackend` is the per drive contract.
//!
//! One instance represents one drive. The trait covers volume lifecycle,
//! streaming byte reads and writes at a path within a volume, and
//! xl.meta-aware operations that read and write `FileInfo` records for
//! object versions. Higher layers hold one instance for single-drive
//! setups or several for erasure-coded sets.
//!
//! Data-path methods (`read_file_stream`, `create_file_stream`) take or
//! return a `ByteStream` so bytes flow through one stripe at a time;
//! the trait deliberately has no whole-buffer read/write surface — the
//! engine is forbidden from materialising an object end-to-end.

use async_trait::async_trait;

use crate::error::IoResult;
use crate::stream::{ByteSink, ByteStream};
use crate::types::{
    DeleteOptions, DiskInfo, FileInfo, FormatJson, RenameDataResp, RenameOptions,
    UpdateMetadataOpts, VolInfo,
};

/// Per-drive storage backend.
///
/// The trait is intentionally NOT `Send + Sync`: compio is thread per core
/// and its sockets/files use `Rc` internally, so backends live entirely
/// within one runtime/thread. Each per-CPU runtime constructs its own
/// `LocalFsBackend` and `RemoteBackend` instances and shares them via
/// `Rc<dyn StorageBackend>`.
#[async_trait(?Send)]
pub trait StorageBackend {
    // -------------------------------------------------------------------
    // Drive identity and health
    // -------------------------------------------------------------------

    /// Human readable label for the drive.
    fn label(&self) -> String;

    /// Capacity and usage information for the drive.
    async fn disk_info(&self) -> IoResult<DiskInfo>;

    // -------------------------------------------------------------------
    // Volume (bucket) level
    // -------------------------------------------------------------------

    async fn make_vol(&self, volume: &str) -> IoResult<()>;
    async fn list_vols(&self) -> IoResult<Vec<VolInfo>>;
    async fn stat_vol(&self, volume: &str) -> IoResult<VolInfo>;
    async fn delete_vol(&self, volume: &str, force_delete: bool) -> IoResult<()>;

    // Bucket meta is stored as an ordinary object under SYSTEM_BUCKET
    // and accessed via the engine's PutObject/GetObject paths — no
    // per-disk trait surface here.

    // -------------------------------------------------------------------
    // File level, streaming bytes
    // -------------------------------------------------------------------

    /// List entries in a single directory, capped at `count` (0 for no cap).
    async fn list_dir(
        &self,
        volume: &str,
        dir_path: &str,
        count: usize,
    ) -> IoResult<Vec<String>>;

    /// Open a streaming read over `[offset, offset+length)` of `(volume,
    /// path)`. The returned stream owns a recycled scratch buffer; bytes
    /// are pulled in caller-sized chunks. Ends with EOF after `length`
    /// bytes; reading past that returns `Ok(0)`.
    async fn read_file_stream(
        &self,
        volume: &str,
        path: &str,
        offset: u64,
        length: u64,
    ) -> IoResult<Box<dyn ByteStream>>;

    /// Open a streaming write at `(volume, path)` and return a sink the
    /// caller pushes bytes into. `size` is the total expected length;
    /// implementations record it so that `finish()` can validate
    /// correct framing on the wire (remote backend) and cleanly close
    /// the file (local backend). The caller MUST push exactly `size`
    /// bytes and then call `finish()`; partial writes leave the
    /// underlying file in an undefined state for the GC layer to
    /// reclaim.
    ///
    /// Used by the engine's EC fan-out: one `ByteSink` per backend in
    /// the set, fed with that backend's shard bytes one stripe at a
    /// time. No per-object materialisation occurs — each push lands
    /// in either an `io_uring` `write_at` (local) or a TCP `write`
    /// (remote) and the buffer is recycled immediately after.
    async fn create_file_writer(
        &self,
        volume: &str,
        path: &str,
        size: u64,
    ) -> IoResult<Box<dyn ByteSink>>;

    /// Atomically rename one file from `src` to `dst`.
    async fn rename_file(
        &self,
        src_volume: &str,
        src_path: &str,
        dst_volume: &str,
        dst_path: &str,
    ) -> IoResult<()>;

    /// Succeeds when `(volume, path)` exists and is accessible.
    async fn check_file(&self, volume: &str, path: &str) -> IoResult<()>;

    /// Remove a file or tree.
    async fn delete(&self, volume: &str, path: &str, recursive: bool) -> IoResult<()>;

    // -------------------------------------------------------------------
    // xl.meta aware
    // -------------------------------------------------------------------

    async fn write_metadata(
        &self,
        orig_volume: &str,
        volume: &str,
        path: &str,
        fi: &FileInfo,
    ) -> IoResult<()>;

    async fn read_version(
        &self,
        orig_volume: &str,
        volume: &str,
        path: &str,
        version_id: Option<&str>,
        read_data: bool,
    ) -> IoResult<FileInfo>;

    async fn update_metadata(
        &self,
        volume: &str,
        path: &str,
        fi: &FileInfo,
        opts: &UpdateMetadataOpts,
    ) -> IoResult<()>;

    // todo: @arnav: implement range based get.
    // todo: @arnav: delete version seems dead code pls remove if not used
    async fn delete_version(
        &self,
        volume: &str,
        path: &str,
        fi: &FileInfo,
        force_del_marker: bool,
        opts: &DeleteOptions,
    ) -> IoResult<()>;

    async fn rename_data(
        &self,
        src_volume: &str,
        src_path: &str,
        fi: &FileInfo,
        dst_volume: &str,
        dst_path: &str,
        opts: &RenameOptions,
    ) -> IoResult<RenameDataResp>;

    async fn verify_file(&self, volume: &str, path: &str, fi: &FileInfo) -> IoResult<()>;

    async fn read_format(&self) -> IoResult<Option<FormatJson>>;

    async fn write_format(&self, fmt: &FormatJson) -> IoResult<()>;

    async fn write_file(&self, volume: &str, path: &str, bytes: Vec<u8>) -> IoResult<()>;

    async fn read_file(&self, volume: &str, path: &str) -> IoResult<Option<Vec<u8>>>;

    async fn make_dir_all(&self, volume: &str, path: &str) -> IoResult<()>;
}

/// Lock-plane peer.
///
/// One vote in the dsync-style quorum protocol the storage layer runs
/// before mutating an object.
#[async_trait(?Send)]
pub trait LockPeer {
    async fn lock_acquire(&self, resource: &str, uid: &str, ttl_ms: u32) -> IoResult<bool>;
    async fn lock_release(&self, resource: &str, uid: &str) -> IoResult<()>;
}
