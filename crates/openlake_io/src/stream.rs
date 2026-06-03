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

#[async_trait(?Send)]
pub trait ByteStream {
    async fn read(&mut self) -> IoResult<Bytes>;

    async fn read_buffer(&mut self, dst: &mut [u8]) -> IoResult<usize>;
}

#[async_trait(?Send)]
pub trait ByteSink {
    async fn write_all(&mut self, buf: Bytes) -> IoResult<()>;

    async fn finish(&mut self) -> IoResult<()>;
}

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

pub async fn pump_compio_to_sink<R: AsyncRead + Unpin>(
    src:  &mut R,
    dst:  &mut dyn ByteSink,
    size: u64,
) -> IoResult<()> {
    let mut moved = 0u64;
    while moved < size {
        let want = (size - moved).min(STREAM_CHUNK_BYTES as u64) as usize; // 4 MiB cap
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
        dst.write_all(buf.freeze()).await?;
        moved += n as u64;
    }
    Ok(())
}

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
        Ok(std::mem::take(&mut self.buf))
    }

    async fn read_buffer(&mut self, _: &mut [u8]) -> IoResult<usize> {
        unimplemented!("not implemented")
    }
}

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

    async fn read_buffer(&mut self, _: &mut [u8]) -> IoResult<usize> {
        unimplemented!("not implemented")
    }
}

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

    async fn read_buffer(&mut self, _: &mut [u8]) -> IoResult<usize> {
        unimplemented!("not implemented")
    }
}

pub struct SkipTakeStream {
    inner:     Box<dyn ByteStream>,
    to_skip:   u64,
    remaining: u64,
}

impl SkipTakeStream {
    pub fn new(inner: Box<dyn ByteStream>, skip: u64, take: u64) -> Self {
        Self { inner, to_skip: skip, remaining: take }
    }
}

#[async_trait(?Send)]
impl ByteStream for SkipTakeStream {
    async fn read(&mut self) -> IoResult<Bytes> {
        loop {
            if self.remaining == 0 {
                return Ok(Bytes::new());
            }
            let chunk = self.inner.read().await?;
            if chunk.is_empty() {
                return Ok(Bytes::new());
            }
            if self.to_skip >= chunk.len() as u64 {
                self.to_skip -= chunk.len() as u64;
                continue;
            }
            let drop = self.to_skip as usize;
            self.to_skip = 0;
            let kept = if drop == 0 { chunk } else { bytes::Bytes::slice(&chunk, drop..) };
            let take = (self.remaining as usize).min(kept.len());
            self.remaining -= take as u64;
            return Ok(if take == kept.len() { kept } else { bytes::Bytes::slice(&kept, ..take) });
        }
    }

    async fn read_buffer(&mut self, _: &mut [u8]) -> IoResult<usize> {
        unimplemented!("not implemented")
    }
}

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
        self.buf.extend_from_slice(&buf[..]);
        Ok(())
    }
    async fn finish(&mut self) -> IoResult<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    struct ChunkSource(VecDeque<Bytes>);

    #[async_trait(?Send)]
    impl ByteStream for ChunkSource {
        async fn read(&mut self) -> IoResult<Bytes> {
            Ok(self.0.pop_front().unwrap_or_default())
        }

        async fn read_buffer(&mut self, _: &mut [u8]) -> IoResult<usize> {
            unimplemented!("not implemented")
        }
    }

    fn chunks(parts: &[&[u8]]) -> Box<dyn ByteStream> {
        Box::new(ChunkSource(parts.iter().map(|b| Bytes::copy_from_slice(b)).collect()))
    }

    async fn drain(s: &mut dyn ByteStream) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let c = s.read().await.unwrap();
            if c.is_empty() {
                return out;
            }
            out.extend_from_slice(&c);
        }
    }

    #[compio::test]
    async fn skip_take_within_single_chunk() {
        let mut s = SkipTakeStream::new(chunks(&[b"0123456789"]), 2, 5);
        assert_eq!(drain(&mut s).await, b"23456");
    }

    #[compio::test]
    async fn skip_take_across_chunks() {
        let mut s = SkipTakeStream::new(chunks(&[b"01234", b"56789", b"abcde"]), 3, 8);
        assert_eq!(drain(&mut s).await, b"3456789a");
    }

    #[compio::test]
    async fn skip_consumes_full_chunks_then_partial() {
        let mut s = SkipTakeStream::new(chunks(&[b"AAAA", b"BBBB", b"CCCC"]), 8, 4);
        assert_eq!(drain(&mut s).await, b"CCCC");
    }

    #[compio::test]
    async fn take_zero_yields_eof_immediately() {
        let mut s = SkipTakeStream::new(chunks(&[b"data"]), 0, 0);
        assert_eq!(drain(&mut s).await, Vec::<u8>::new());
    }

    #[compio::test]
    async fn take_exceeding_upstream_truncates_at_eof() {
        let mut s = SkipTakeStream::new(chunks(&[b"abc"]), 0, 100);
        assert_eq!(drain(&mut s).await, b"abc");
    }

    #[compio::test]
    async fn skip_past_eof_yields_empty() {
        let mut s = SkipTakeStream::new(chunks(&[b"abc"]), 99, 1);
        assert_eq!(drain(&mut s).await, Vec::<u8>::new());
    }

    #[compio::test]
    async fn zero_skip_returns_prefix_take() {
        let mut s = SkipTakeStream::new(chunks(&[b"hello world"]), 0, 5);
        assert_eq!(drain(&mut s).await, b"hello");
    }
}
