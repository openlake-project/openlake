//! Owned-buffer byte streams for the data plane.
//!
//! The data path crosses S3 frontend → engine → backend → wire and must
//! never materialise an object end to end. `ByteStream` and `ByteSink`
//! are the dyn-compatible reader/writer pair every layer hands off to
//! the next; bytes flow through one stripe at a time and never live in
//! a per-object buffer.
//!
//! Why a custom trait rather than `compio::io::AsyncRead`/`AsyncWrite`:
//! compio's traits are generic over the buffer (`B: IoBuf` / `IoBufMut`)
//! so the kernel can pin it for io_uring/kqueue, which makes them not
//! object-safe. We take ownership of a `Vec<u8>` *inside* the impl (so
//! compio's submit-and-recycle model is preserved) but expose a
//! `&mut [u8]` / `&[u8]` surface to the caller so the engine can hold
//! `Box<dyn ByteStream>` / `Box<dyn ByteSink>` heterogeneously.

use async_trait::async_trait;
use bytes::Bytes;
use compio::buf::{BufResult, IntoInner, IoBuf};
use compio::io::AsyncRead;

use crate::alloc::PooledBuffer;
use crate::error::{IoError, IoResult};
use crate::tuning::STREAM_CHUNK_BYTES;

/// Owned-buffer reader. Yields refcounted `Bytes` chunks — the
/// underlying allocation lives in either an axum/hyper `BytesMut`
/// (network sources, refcount-only slice) or a pool-backed
/// `PooledBuffer` frozen via `PooledBuffer::freeze()` (file/socket
/// sources, kernel-written then refcount-handoff).
///
/// Returning `Bytes` instead of forcing a fixed buffer type lets
/// every layer downstream (etag hash, xl.meta tail, writev iovec,
/// HTTP response frame) consume the bytes by reference — no
/// userspace memcpy at the trait boundary. Adapters from
/// `axum::body::Body`, `compio::AsyncRead`, etc. all hand back the
/// allocation they already own.
///
/// Cancellation safety: pool-backed impls hold the `PooledBuffer`
/// across the `await` and only `freeze()` after the io_uring SQE has
/// completed (or been canceled by `OpFuture::drop`). The kernel is
/// provably done with the memory by the time `Bytes` ownership is
/// taken.
#[async_trait(?Send)]
pub trait ByteStream {
    /// Returns the next chunk of bytes. `Ok(bytes)` with `len > 0` is
    /// data; `Ok(empty)` is EOF; `Err(_)` is an I/O failure. The
    /// returned `Bytes` may be 1 byte or up to several MiB — the
    /// caller does not control the size, only consumes the chunk.
    async fn read(&mut self) -> IoResult<Bytes>;
}

/// Owned-buffer writer. Caller hands ownership of a `Bytes` (which
/// may wrap a `PooledBuffer` via `freeze()`, an axum frame, or any
/// owned byte allocation); impl writes the whole buffer to its
/// destination. The `Bytes` Drop (refcount → 0) recycles the
/// underlying allocation back to whichever pool/owner created it.
#[async_trait(?Send)]
pub trait ByteSink {
    /// Write `buf` in full. The impl owns the bytes for the duration
    /// of the call; on completion the `Bytes` refcount is dropped
    /// (returning the allocation to its pool, if pool-backed).
    async fn write_all(&mut self, buf: Bytes) -> IoResult<()>;

    /// Flush any buffered bytes and finalise. Implementations that
    /// front a remote RPC use this to read the peer's status frame;
    /// implementations that front a local file use this to `fsync`
    /// and close. After `finish` returns no more writes are accepted.
    async fn finish(&mut self) -> IoResult<()>;
}

/// Read up to `dst.len()` bytes into `dst` by pulling chunks from `s`
/// until either `dst` is full or `s` hits EOF. Returns the count
/// filled. Used by the CLI/test paths that own a `Vec<u8>` and want
/// it populated; the per-chunk `copy_from_slice` here is a deliberate
/// trade — `dst` is `&mut [u8]`, so we have to write *somewhere* the
/// caller chose. Hot paths should consume `Bytes` from the trait
/// directly and skip this helper.
pub async fn read_full(s: &mut dyn ByteStream, dst: &mut [u8]) -> IoResult<usize> {
    let want = dst.len();
    if want == 0 {
        return Ok(0);
    }
    let mut filled = 0;
    while filled < want {
        let chunk = s.read().await?;
        if chunk.is_empty() {
            return Ok(filled);
        }
        let take = (want - filled).min(chunk.len());
        dst[filled..filled + take].copy_from_slice(&chunk[..take]);
        filled += take;
    }
    Ok(filled)
}

/// Pump exactly `size` bytes from a `ByteStream` source into a
/// `ByteSink` destination. Returns `UnexpectedEof` on a short source.
///
/// Each `src.read()` yields a `Bytes` (refcount-only) that we hand
/// straight to `dst.write_all` — **zero memcpy** at the trait
/// boundary. The chunk size is decided by the source (one HTTP
/// frame, one TCP recv, one disk read, etc.).
pub async fn pump_n(
    src: &mut dyn ByteStream,
    dst: &mut dyn ByteSink,
    size: u64,
) -> IoResult<()> {
    let mut moved = 0u64;
    while moved < size {
        let chunk = src.read().await?;
        if chunk.is_empty() {
            return Err(IoError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                format!("pump_n: source ended at {moved}/{size}"),
            )));
        }
        let n = chunk.len() as u64;
        // Trim if the source over-delivered past `size` (rare, but
        // possible for sources whose chunks aren't bounded by size).
        let chunk = if moved + n > size {
            // bytes::Bytes::slice (zero copy refcount)
            bytes::Bytes::slice(&chunk, ..(size - moved) as usize)
        } else {
            chunk
        };
        let chunk_len = chunk.len() as u64;
        dst.write_all(chunk).await?;
        moved += chunk_len;
    }
    Ok(())
}

/// Pump exactly `size` bytes from a compio `AsyncRead` source into a
/// `ByteSink` destination, using a 1 MiB pool-backed transfer buffer.
/// Returns `UnexpectedEof` on a short source.
///
/// Compared to [`pump_n`], this function avoids the source-side
/// trait-adapter memcpy by reading directly from compio's
/// owned-buffer API into the same `PooledBuffer` we hand to
/// `dst.write_all`. There is no `LimitedCompioReader`-style
/// intermediate scratch.
///
/// The kernel writes directly into `buf.slice(0..want)` via
/// `compio::AsyncRead::read`'s slice machinery, bounded to exactly
/// `want` bytes per iteration — so we don't need a separate
/// "remaining bytes" counter on a wrapper type. The loop's
/// `moved < size` test is the only cap.
pub async fn pump_compio_to_sink<R: AsyncRead + Unpin>(
    src:  &mut R,
    dst:  &mut dyn ByteSink,
    size: u64,
) -> IoResult<()> {
    let mut moved = 0u64;
    while moved < size {
        let want = (size - moved).min(STREAM_CHUNK_BYTES as u64) as usize; // 4 MiB cap
        // Fresh PooledBuffer per iteration: we hand ownership to
        // the sink as a `Bytes` (via `freeze()`), so we can't reuse
        // the same allocation for the next read. The pool recycles
        // it once the sink's `Bytes` is dropped.
        let buf = PooledBuffer::with_capacity(want);
        let slice = buf.slice(0..want);
        let BufResult(res, slice_back) = src.read(slice).await;
        let mut buf = slice_back.into_inner();
        let n = res.map_err(IoError::Io)?;
        if n == 0 {
            return Err(IoError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                format!("pump_compio_to_sink: source ended at {moved}/{size}"),
            )));
        }
        buf.truncate(n);
        // freeze() hands the kernel-filled allocation to a `Bytes`
        // owner without copy. The pool recycles when the Bytes
        // refcount drops to 0 inside the sink.
        dst.write_all(buf.freeze()).await?;
        moved += n as u64;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// In-memory implementations: useful for tests and for the inline (≤128 KiB)
// payload path where the engine still hands a single buffer to xl.meta. The
// streaming surface is uniform so callers don't branch between inline and
// EC paths.
// ---------------------------------------------------------------------------

/// Adapter that exposes a fixed `Vec<u8>` as a `ByteStream`. The
/// `Vec` is wrapped as `Bytes` once at construction (zero copy) and
/// each `read()` returns a refcounted slice — no userspace memcpy.
pub struct VecByteStream {
    buf: Bytes,
}

impl VecByteStream {
    pub fn new(buf: Vec<u8>) -> Self {
        Self { buf: Bytes::from(buf) }
    }
}

#[async_trait(?Send)]
impl ByteStream for VecByteStream {
    async fn read(&mut self) -> IoResult<Bytes> {
        // Yield the whole remaining buffer in one shot (zero copy).
        // Subsequent calls return empty (EOF).
        Ok(std::mem::take(&mut self.buf))
    }
}

/// Adapter that exposes a `bytes::Bytes` as a `ByteStream`. Used by
/// the engine's inline GET path when the payload is a single span
/// (read off xl.meta as one zero-copy slice).
pub struct BytesByteStream {
    buf: bytes::Bytes,
}

impl BytesByteStream {
    pub fn new(buf: bytes::Bytes) -> Self {
        Self { buf }
    }
}

#[async_trait(?Send)]
impl ByteStream for BytesByteStream {
    async fn read(&mut self) -> IoResult<Bytes> {
        Ok(std::mem::take(&mut self.buf))
    }
}

/// Adapter that exposes a `Vec<Bytes>` rope as a `ByteStream`,
/// yielding each frame in order with zero copy. Used by the inline
/// GET path: `fi.data` is already a refcounted rope (one frame per
/// HTTP frame of the original PUT, or one frame from a disk read);
/// we just hand them out.
pub struct RopeByteStream {
    frames: std::collections::VecDeque<bytes::Bytes>,
}

impl RopeByteStream {
    pub fn new(frames: Vec<bytes::Bytes>) -> Self {
        Self { frames: frames.into() }
    }
}

#[async_trait(?Send)]
impl ByteStream for RopeByteStream {
    async fn read(&mut self) -> IoResult<Bytes> {
        Ok(self.frames.pop_front().unwrap_or_default())
    }
}

/// Sink that accumulates writes into a `Vec<u8>`. Used as the inline
/// staging buffer for ≤128 KiB EC reconstructions and in tests.
#[derive(Default)]
pub struct VecByteSink {
    pub buf: Vec<u8>,
}

impl VecByteSink {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }
    pub fn with_capacity(cap: usize) -> Self {
        Self { buf: Vec::with_capacity(cap) }
    }
    pub fn into_inner(self) -> Vec<u8> {
        self.buf
    }
}

#[async_trait(?Send)]
impl ByteSink for VecByteSink {
    async fn write_all(&mut self, buf: Bytes) -> IoResult<()> {
        // VecByteSink is the test/inline-staging Vec<u8> sink; the
        // memcpy here is unavoidable because the destination is a
        // `Vec<u8>` chosen by the test harness, not a writev iovec
        // or pool slot.
        self.buf.extend_from_slice(&buf[..]);
        Ok(())
    }
    async fn finish(&mut self) -> IoResult<()> {
        Ok(())
    }
}

// Compio source/sink adapters used to live here (`LimitedCompioReader`
// and `CompioWriter`) — both have been removed. They were trait
// adapters that bridged compio's owned-buffer `AsyncRead`/`AsyncWrite`
// to our object-safe `ByteStream`/`ByteSink` surface, but each adapter
// pass added one extra memcpy at the trait boundary. The single
// production caller (`rpc_server::handle_create_file_stream`) now uses
// `pump_compio_to_sink` to read directly from the compio TCP/TLS
// stream into the same pool-backed buffer it hands to the sink, with
// no intermediate scratch. `CompioWriter` was unused. If we ever need
// a "bound an `AsyncRead` to N bytes and expose as `ByteStream`"
// helper again, see git history for the implementation.
