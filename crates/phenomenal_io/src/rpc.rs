//! Wire envelope for inter-node RPC.
//!
//! The transport is HTTP/2 over rustls (cyper-axum on the server,
//! cyper on the client). Two envelope shapes share that transport:
//!
//!   * **Unary** (`POST /v1/rpc`): the bincode-encoded `Request` is
//!     the full request body; the bincode-encoded `Response` is the
//!     full response body. h2 DATA frames replace the length-prefix
//!     framing this module used to carry — there is no per-call
//!     framing left for this code to define.
//!   * **Streaming** (`PUT /v1/rpc/stream-write`,
//!     `POST /v1/rpc/stream-read`): the bincode-encoded `Request`
//!     rides in a single `x-phenomenal-rpc` request header (URL-safe
//!     base64); the body carries raw object bytes in or out. The
//!     terminal `Response` lands in the response body for writes;
//!     for reads the response body IS the bytes and the closing
//!     `Response` is implicit (success = body completed cleanly,
//!     failure = non-2xx with a bincode `Response::Err` body).
//!
//! The `Request` enum mirrors `StorageBackend` 1:1 so the server side
//! dispatches with one `match` and no separate routing table — see
//! `phenomenal_server::rpc_server::dispatch`.

use serde::{Deserialize, Serialize};

use crate::error::IoError;
use crate::types::{DiskInfo, FileInfo, FormatJson, RenameDataResp, VolInfo};

/// Wire-level disk index. Identifies which physical disk on the
/// receiving node a disk-targeted request applies to. The node
/// itself is implied by the destination URL, so only the index
/// travels in the envelope.
pub type DiskIdx = u16;

#[derive(Debug, Serialize, Deserialize)]
pub enum Request {
    // ---- Disk-targeted variants (carry `disk_idx`). ----
    //
    // The receiver looks up `disk_idx` against its local
    // `Vec<Rc<dyn StorageBackend>>` and dispatches the operation to
    // that backend. Out-of-range `disk_idx` is rejected at the
    // dispatch layer with `Response::Err`.
    DiskInfo  { disk_idx: DiskIdx },

    MakeVol   { disk_idx: DiskIdx, volume: String },
    StatVol   { disk_idx: DiskIdx, volume: String },
    ListVols  { disk_idx: DiskIdx },
    DeleteVol { disk_idx: DiskIdx, volume: String, force_delete: bool },

    ListDir   { disk_idx: DiskIdx, volume: String, dir_path: String, count: u32 },

    /// Streaming write envelope. Travels in the
    /// `x-phenomenal-rpc` header of `PUT /v1/rpc/stream-write`; the
    /// HTTP body carries exactly `size` raw bytes.
    CreateFileStream { disk_idx: DiskIdx, volume: String, path: String, size: u64 },

    /// Streaming read envelope. Travels in the body of
    /// `POST /v1/rpc/stream-read`; on 2xx the response body carries
    /// exactly `length` raw bytes (sanity-checked against the
    /// `x-phenomenal-length` response header).
    ReadFileStream   { disk_idx: DiskIdx, volume: String, path: String, offset: u64, length: u64 },

    RenameFile { disk_idx: DiskIdx, src_volume: String, src_path: String, dst_volume: String, dst_path: String },
    CheckFile  { disk_idx: DiskIdx, volume: String, path: String },
    Delete     { disk_idx: DiskIdx, volume: String, path: String, recursive: bool },

    WriteMetadata  { disk_idx: DiskIdx, orig_volume: String, volume: String, path: String, fi: FileInfo },
    UpdateMetadata { disk_idx: DiskIdx, volume: String, path: String, fi: FileInfo, no_persistence: bool },
    ReadVersion    { disk_idx: DiskIdx, orig_volume: String, volume: String, path: String, version_id: Option<String>, read_data: bool },
    DeleteVersion  { disk_idx: DiskIdx, volume: String, path: String, fi: FileInfo, force_del_marker: bool, undo_write: bool },
    RenameData     { disk_idx: DiskIdx, src_volume: String, src_path: String, fi: FileInfo, dst_volume: String, dst_path: String },
    VerifyFile     { disk_idx: DiskIdx, volume: String, path: String, fi: FileInfo },

    ReadFormat     { disk_idx: DiskIdx },
    WriteFormat    { disk_idx: DiskIdx, fmt: FormatJson },

    /// Atomic write of an arbitrary small blob (multipart sidecars).
    WriteFile      { disk_idx: DiskIdx, volume: String, path: String, bytes: Vec<u8> },
    /// Whole-file read; `Response::FileBytes(None)` if absent.
    ReadFile       { disk_idx: DiskIdx, volume: String, path: String },
    /// Recursive mkdir; idempotent.
    MakeDirAll     { disk_idx: DiskIdx, volume: String, path: String },

    // ---- Node-scoped variants (no `disk_idx`). ----
    //
    // Distributed lock plane: there is one `LockServer` per process,
    // not one per disk, so locks are addressed at node granularity.
    LockAcquire { resource: String, uid: String, ttl_ms: u32 },
    LockRelease { resource: String, uid: String },
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Response {
    Ok,
    Vol(VolInfo),
    Vols(Vec<VolInfo>),
    Strings(Vec<String>),
    File(FileInfo),
    Disk(DiskInfo),
    Renamed(RenameDataResp),
    /// Reply for `Request::ReadFormat`. `None` when the disk has not
    /// been formatted yet; `Some` carries the parsed `format.json`.
    FormatOpt(Option<FormatJson>),
    /// Reply for `Request::ReadFile`. `None` if the file does not exist.
    FileBytes(Option<Vec<u8>>),
    LockGranted,
    LockDenied,
    Err(WireError),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum WireError {
    VolumeNotFound(String),
    VolumeExists(String),
    VolumeNotEmpty(String),
    FileNotFound      { volume: String, path: String },
    FileAlreadyExists { volume: String, path: String },
    Other(String),
}

impl From<IoError> for WireError {
    fn from(e: IoError) -> Self {
        match e {
            IoError::VolumeNotFound(v)                  => WireError::VolumeNotFound(v),
            IoError::VolumeExists(v)                    => WireError::VolumeExists(v),
            IoError::VolumeNotEmpty(v)                  => WireError::VolumeNotEmpty(v),
            IoError::FileNotFound      { volume, path } => WireError::FileNotFound      { volume, path },
            IoError::FileAlreadyExists { volume, path } => WireError::FileAlreadyExists { volume, path },
            other                                       => WireError::Other(other.to_string()),
        }
    }
}

impl From<WireError> for IoError {
    fn from(e: WireError) -> Self {
        match e {
            WireError::VolumeNotFound(v)                  => IoError::VolumeNotFound(v),
            WireError::VolumeExists(v)                    => IoError::VolumeExists(v),
            WireError::VolumeNotEmpty(v)                  => IoError::VolumeNotEmpty(v),
            WireError::FileNotFound      { volume, path } => IoError::FileNotFound      { volume, path },
            WireError::FileAlreadyExists { volume, path } => IoError::FileAlreadyExists { volume, path },
            WireError::Other(s)                           => IoError::Decode(s),
        }
    }
}

pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, IoError> {
    bincode::serde::encode_to_vec(value, bincode::config::standard())
        .map_err(|e| IoError::Encode(e.to_string()))
}

pub fn decode<T: for<'a> Deserialize<'a>>(body: &[u8]) -> Result<T, IoError> {
    let (v, _) = bincode::serde::decode_from_slice::<T, _>(body, bincode::config::standard())
        .map_err(|e| IoError::Decode(e.to_string()))?;
    Ok(v)
}
