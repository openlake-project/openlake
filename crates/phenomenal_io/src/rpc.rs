//! Wire protocol for inter-node RPC.
//!
//! Two transports share one TCP/TLS connection:
//!
//!   * **Control plane**: each call is one length-prefixed bincode
//!     envelope in each direction. Used for metadata-only ops
//!     (`WriteMetadata`, `ReadVersion`, `ListDir`, locks, …) where the
//!     payload fits in a single frame.
//!   * **Data plane**: header frame in (`CreateFileStream`,
//!     `ReadFileStream`), then raw body bytes flow on the same socket
//!     for the duration of the stream, then a status frame back. No
//!     per-chunk envelope inside the body — the TCP socket is the
//!     stream. Mirrors MinIO's storage-rest split between the `grid`
//!     framework and HTTP body handlers.
//!
//! `Request` variants mirror `StorageBackend` 1:1 so the server side
//! dispatches with one `match` and no separate routing table.

use compio::buf::{BufResult, IntoInner, IoBuf};
use compio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use serde::{Deserialize, Serialize};

use crate::alloc::PooledBuffer;
use crate::error::IoError;
use crate::tuning::FRAME_HEADER_BYTES;
use crate::types::{DiskInfo, FileInfo, RenameDataResp, VolInfo};

/// Wire-level disk index. Identifies which physical disk on the
/// receiving node a disk-targeted request applies to. The node
/// itself is implied by the TCP connection's destination, so only
/// the index travels on the wire.
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

    /// Streaming write. After this header frame the client sends
    /// exactly `size` raw bytes on the same socket; the server then
    /// replies with `Response::Ok` or `Response::Err`.
    CreateFileStream { disk_idx: DiskIdx, volume: String, path: String, size: u64 },

    /// Streaming read. The server replies with either
    /// `Response::StreamHeader { length }` followed by `length` raw
    /// bytes, or `Response::Err` and no body.
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
    LockGranted,
    LockDenied,
    /// First reply to `ReadFileStream` on success. After this frame the
    /// server writes exactly `length` raw bytes on the same socket.
    StreamHeader { length: u64 },
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

// ---------------------------------------------------------------------------
// Framing helpers. Owned-buffer in, owned-buffer out via compio's
// `AsyncReadExt::read_exact` and `AsyncWrite::write` — the kernel writes
// directly into the buffer we hand it, with no shadow buffer or memcpy
// bridge in the hot path. Mirrors the iggy server-side framing pattern.
// ---------------------------------------------------------------------------

/// Hard cap on the body of one length-prefixed control envelope. A peer
/// declaring more than this is rejected before allocation, so a buggy
/// or malicious peer cannot force a multi-GiB allocation by lying in
/// the length prefix. Sized large enough for any legitimate control
/// payload (FileInfo blobs, list responses) and far below the inline-
/// payload cap on the data plane.
pub const MAX_FRAME: usize = 8 * 1024 * 1024;

/// Write a `[u32 BE length][body]` frame.
///
/// Constructs the wire bytes in a [`PooledBuffer`] (pool-tracked,
/// returned on drop) and submits via the owned-buffer write loop.
/// `FRAME_HEADER_BYTES` is the on-wire size of the `u32` length
/// prefix (see [`crate::tuning`]). Not a tunable — locked by the
/// wire protocol.
pub async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, body: &[u8]) -> std::io::Result<()> {
    let mut wire = PooledBuffer::with_capacity(FRAME_HEADER_BYTES + body.len());
    wire.extend_from_slice(&(body.len() as u32).to_be_bytes());
    wire.extend_from_slice(body);
    let _ = write_all_owned(w, wire).await?;
    w.flush().await
}

/// Read a `[u32 BE length][body]` frame and return the body bytes
/// in a [`PooledBuffer`].
///
/// The kernel writes directly into the body buffer via compio's
/// `AsyncReadExt::read_exact`. We slice the buffer to exactly `len`
/// bytes before passing it to `read_exact` so the kernel write is
/// bounded to the declared length, regardless of the bucket-rounded
/// capacity of the underlying allocation. Body length is capped at
/// [`MAX_FRAME`] so a malformed length prefix cannot trigger an
/// unbounded allocation. The buffer is acquired from the global
/// memory pool and returned to it on drop, so steady-state framing
/// has zero allocator traffic once the pool is warm.
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> std::io::Result<PooledBuffer> {
    // Header — 4 bytes. The pool's smallest bucket is one page so
    // the underlying allocation is 4 KiB; we slice down to the four
    // bytes the wire format actually carries.
    let header_buf = PooledBuffer::with_capacity(4);
    let header_slice = header_buf.slice(0..4);
    let BufResult(res, header_slice) = r.read_exact(header_slice).await;
    res?;
    let header_buf = header_slice.into_inner();
    let len = u32::from_be_bytes([header_buf[0], header_buf[1], header_buf[2], header_buf[3]]) as usize;
    if len > MAX_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("control frame length {len} exceeds MAX_FRAME ({MAX_FRAME})"),
        ));
    }

    // Body — same slice trick: bucket-rounded capacity, but the read
    // is bounded to exactly `len` bytes via the Slice end bound.
    if len == 0 {
        return Ok(PooledBuffer::empty());
    }
    let body_buf = PooledBuffer::with_capacity(len);
    let body_slice = body_buf.slice(0..len);
    let BufResult(res, body_slice) = r.read_exact(body_slice).await;
    res?;
    Ok(body_slice.into_inner())
}

/// Loop `AsyncWrite::write` until `buf` is fully drained; return the
/// emptied [`PooledBuffer`] so the caller can recycle the allocation
/// across calls in a hot pump loop. Partial writes are handled via
/// `Slice<PooledBuffer>` — `AVec` does not provide a Vec-style
/// `drain`, so we slice the unsent tail forward instead of rotating
/// bytes within the buffer.
pub async fn write_all_owned<W: AsyncWrite + Unpin>(w: &mut W, mut buf: PooledBuffer) -> std::io::Result<PooledBuffer> {
    let total = buf.len();
    let mut written = 0;
    while written < total {
        let slice = buf.slice(written..total);
        let BufResult(res, slice_back) = w.write(slice).await;
        buf = slice_back.into_inner();
        let n = res?;
        if n == 0 {
            return Err(std::io::Error::other("write returned 0"));
        }
        written += n;
    }
    buf.clear();
    Ok(buf)
}

/// Write a `Bytes` in full to an `AsyncWrite`. compio loops the
/// underlying `write_at`/`write` SQE on partial writes via the slice
/// machinery — same shape as `write_all_owned`, but takes `Bytes`
/// (refcounted, free clone) so callers don't need to convert.
pub async fn write_all_bytes<W: AsyncWrite + Unpin>(w: &mut W, mut buf: bytes::Bytes) -> std::io::Result<()> {
    let total = buf.len();
    let mut written = 0;
    while written < total {
        let slice = buf.slice(written..total);
        let BufResult(res, slice_back) = w.write(slice).await;
        buf = slice_back.into_inner();
        let n = res?;
        if n == 0 {
            return Err(std::io::Error::other("write returned 0"));
        }
        written += n;
    }
    Ok(())
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
