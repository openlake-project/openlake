//! `PooledBuffer` — RAII wrapper that returns its backing buffer to
//! the [`memory_pool`] on drop. Implements compio's `IoBuf`,
//! `IoBufMut`, and `SetLen` so it can be passed directly to
//! `AsyncRead::read` / `AsyncReadExt::read_exact` / `AsyncWrite::write`
//! without going through `Vec<u8>`.
//!
//! Port of iggy's `core/common/src/alloc/buffer.rs`. Same shape:
//! acquire on `with_capacity`, return on drop, `freeze` to immutable
//! `Bytes` (refcounted, removes from pool tracking).
//!
//! [`memory_pool`]: super::memory_pool

use std::mem::MaybeUninit;
use std::ops::{Deref, DerefMut};

use bytes::Bytes;
use compio::buf::{IoBuf, IoBufMut, SetLen};

use super::memory_pool::{memory_pool, AlignedBuffer, AlignedBufferExt, ALIGNMENT};

/// Pool-aware owned byte buffer. Constructed via
/// [`PooledBuffer::with_capacity`]; backing storage is a
/// [`AlignedBuffer`] (4 KiB aligned). Dropping the wrapper returns the
/// buffer to its bucket's free queue.
///
/// `from_pool` records whether the underlying allocation is tracked
/// by the pool's accounting; it is set on construction and cleared
/// by `freeze()` / `into_inner()` to suppress the return-on-drop.
#[derive(Debug)]
pub struct PooledBuffer {
    from_pool:           bool,
    original_capacity:   usize,
    inner:               AlignedBuffer,
}

impl Default for PooledBuffer {
    fn default() -> Self {
        Self::empty()
    }
}

impl PooledBuffer {
    /// Acquire a buffer of at least `capacity` bytes. The actual
    /// capacity will be the smallest bucket size ≥ `capacity`, or
    /// `capacity.next_multiple_of(ALIGNMENT)` if no bucket fits.
    /// Length starts at 0 — use `set_len` (unsafe) or
    /// `extend_from_slice` to populate.
    pub fn with_capacity(capacity: usize) -> Self {
        let (buffer, was_pool_allocated) = memory_pool().acquire_buffer(capacity.max(ALIGNMENT));
        let original_capacity = buffer.capacity();
        debug_assert_eq!(
            buffer.as_ptr() as usize % ALIGNMENT, 0,
            "PooledBuffer must be {ALIGNMENT}-byte aligned"
        );
        Self {
            from_pool:         was_pool_allocated,
            original_capacity,
            inner:             buffer,
        }
    }

    /// An empty, zero-capacity buffer. Useful as a placeholder before
    /// the actual size is known. Does not touch the pool.
    pub fn empty() -> Self {
        Self {
            from_pool:         false,
            original_capacity: 0,
            inner:             AlignedBuffer::new(ALIGNMENT),
        }
    }

    /// Append `src` to the buffer, growing if necessary. If a grow
    /// pushes the buffer into a different bucket size, the pool's
    /// `resize_events` counter is incremented on next `release_buffer`.
    pub fn extend_from_slice(&mut self, src: &[u8]) {
        self.inner.extend_from_slice(src);
    }

    /// Inner buffer length (initialised bytes).
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Backing capacity in bytes. May exceed `len()`.
    pub fn capacity(&self) -> usize {
        self.inner.capacity()
    }

    /// True iff `len() == 0`. (Capacity may still be non-zero.)
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Reserve `additional` more bytes of capacity.
    pub fn reserve(&mut self, additional: usize) {
        self.inner.reserve(additional);
    }

    /// Convert to an immutable [`Bytes`]. The whole `PooledBuffer`
    /// becomes the `Bytes` owner — its `Drop` runs when the last
    /// refcount goes away, which **does** return the allocation to
    /// the pool (`from_pool=true` is preserved). So a hot-path
    /// `freeze()` is recycle-safe; the pool slot comes back as soon
    /// as every `Bytes` clone derived from it is dropped.
    ///
    /// Use this when handing buffer ownership across an async
    /// boundary where Drop tracking on the `PooledBuffer` is
    /// impractical (e.g. attaching the bytes to `fi.data`, returning
    /// from a `ByteStream::read`, sending via writev).
    pub fn freeze(self) -> Bytes {
        Bytes::from_owner(self)
    }

    /// Take the underlying `AlignedBuffer`, suppressing the return-to-
    /// pool in Drop. Caller must explicitly call
    /// `AlignedBufferExt::return_to_pool` to recycle the memory, or
    /// drop the buffer to deallocate.
    pub fn into_inner(mut self) -> AlignedBuffer {
        let buf = std::mem::replace(&mut self.inner, AlignedBuffer::new(ALIGNMENT));
        self.from_pool = false;
        self.original_capacity = 0;
        buf
    }
}

impl Deref for PooledBuffer {
    type Target = AlignedBuffer;
    fn deref(&self) -> &Self::Target { &self.inner }
}

impl DerefMut for PooledBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.inner }
}

impl Drop for PooledBuffer {
    fn drop(&mut self) {
        if self.from_pool {
            let buf = std::mem::replace(&mut self.inner, AlignedBuffer::new(ALIGNMENT));
            buf.return_to_pool(self.original_capacity, true);
        }
    }
}

impl AsRef<[u8]> for PooledBuffer {
    fn as_ref(&self) -> &[u8] { &self.inner }
}

impl From<&[u8]> for PooledBuffer {
    fn from(slice: &[u8]) -> Self {
        let mut buf = PooledBuffer::with_capacity(slice.len());
        buf.extend_from_slice(slice);
        buf
    }
}

// ---------------------------------------------------------------------------
// compio I/O trait impls. Lets `PooledBuffer` go directly into
// `AsyncRead::read`, `AsyncReadExt::read_exact`, `AsyncWrite::write`.
// ---------------------------------------------------------------------------

impl SetLen for PooledBuffer {
    unsafe fn set_len(&mut self, len: usize) {
        // SAFETY: forwarded to AlignedBuffer / Vec set_len. Caller
        // upholds the invariant that bytes [self.len, len) are
        // initialised before any read.
        unsafe { self.inner.set_len(len) }
    }
}

impl IoBuf for PooledBuffer {
    fn as_init(&self) -> &[u8] {
        &self.inner[..]
    }
}

impl IoBufMut for PooledBuffer {
    fn as_uninit(&mut self) -> &mut [MaybeUninit<u8>] {
        let ptr = self.inner.as_mut_ptr().cast::<MaybeUninit<u8>>();
        let cap = self.inner.capacity();
        // SAFETY: AlignedBuffer guarantees the data pointer is valid
        // for `cap` bytes.
        unsafe { std::slice::from_raw_parts_mut(ptr, cap) }
    }
}
