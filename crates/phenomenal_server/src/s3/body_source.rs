//! Streaming-body adapter for `PUT /{bucket}/{key}`.
//!
//! Bridges axum's body type (a stream of `Frame<Bytes>`) into the
//! `ByteStream` trait the engine consumes, with SigV4 body
//! verification layered in on top:
//!
//!   * `AxumBodyStream` — raw adapter. Pulls the next frame on demand
//!     and serves bytes from a leftover slice between calls.
//!   * `ChunkedBodyStream` — aws-chunked decoder. Pulls bytes from an
//!     `AxumBodyStream`, parses the per-chunk
//!     `<hex>;chunk-signature=<hex64>\r\n` framing, verifies each
//!     chunk against the rolling SigV4 chain, surfaces the decoded
//!     payload bytes one chunk at a time.
//!   * `BodySource` — dispatch enum picked by the handler from
//!     `x-amz-content-sha256`: `Plain` (UNSIGNED-PAYLOAD), `HexSha`
//!     (single-shot signed body, end-of-stream hash check), or
//!     `Chunked` (per-chunk signature chain).

use std::time::SystemTime;

use async_trait::async_trait;
use axum::body::Body;
use bytes::Bytes;
use http_body_util::BodyExt;

use phenomenal_io::stream::ByteStream;
use phenomenal_io::{IoError, IoResult};

use crate::auth::{find_crlf, verify_chunk, Sha256VerifyStream};

/// Adapter that exposes an `axum::body::Body` as a `ByteStream`.
///
/// Pulls one body frame at a time. Each frame's `Bytes` lives in
/// `leftover` and is served piecewise across `read` calls until
/// drained, then the next frame is fetched. Trailer frames (no data)
/// are skipped. EOF is recorded on first `None` from `frame()`.
pub struct AxumBodyStream {
    body:     Body,
    leftover: Bytes,
    eof:      bool,
}

impl AxumBodyStream {
    pub fn new(body: Body) -> Self {
        Self {
            body,
            leftover: Bytes::new(),
            eof:      false,
        }
    }
}

#[async_trait(?Send)]
impl ByteStream for AxumBodyStream {
    async fn read(&mut self) -> IoResult<Bytes> {
        loop {
            if !self.leftover.is_empty() {
                // Hand off the entire current frame as a refcounted
                // `Bytes` (zero copy). `mem::take` drains `leftover`
                // so the next call pulls a fresh frame.
                return Ok(std::mem::take(&mut self.leftover));
            }
            if self.eof {
                return Ok(Bytes::new());
            }
            match self.body.frame().await {
                None => {
                    self.eof = true;
                    return Ok(Bytes::new());
                }
                Some(Ok(frame)) => {
                    if let Ok(data) = frame.into_data() {
                        if !data.is_empty() {
                            self.leftover = data;
                        }
                        // Else: empty data frame — pull again.
                    }
                    // Trailers frame: ignore and pull next.
                }
                Some(Err(e)) => {
                    return Err(IoError::Io(std::io::Error::other(e.to_string())));
                }
            }
        }
    }
}

/// aws-chunked body decoder.
///
/// Each chunk on the wire is `<hex-size>;chunk-signature=<hex64>\r\n`
/// followed by `<size>` payload bytes and a trailing `\r\n`. The
/// final chunk has size 0 and a signature covering an empty payload.
/// Per-chunk signatures chain off the seed signature (running_sig
/// starts as the request's seed signature, and each verified chunk
/// produces the next running signature).
///
/// Holds at most one chunk's worth of payload (typically 64 KiB) in
/// memory at a time. EOF is signalled by the trailing zero-length
/// chunk, after which `read` returns `Ok(0)` indefinitely.
pub struct ChunkedBodyStream {
    inner:        AxumBodyStream,
    /// Bytes pulled from `inner` but not yet parsed.
    carry:        Vec<u8>,
    /// Bytes of the current chunk's payload not yet served to caller.
    chunk_buf:    Vec<u8>,
    chunk_pos:    usize,
    running_sig:  String,
    access_key:   String,
    secret:       String,
    region:       String,
    request_time: SystemTime,
    finished:     bool,
}

impl ChunkedBodyStream {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        body:           Body,
        seed_signature: String,
        access_key:     String,
        secret:         String,
        region:         String,
        request_time:   SystemTime,
    ) -> Self {
        Self {
            inner:        AxumBodyStream::new(body),
            carry:        Vec::with_capacity(64 * 1024),
            chunk_buf:    Vec::new(),
            chunk_pos:    0,
            running_sig:  seed_signature,
            access_key,
            secret,
            region,
            request_time,
            finished:     false,
        }
    }

    /// Pull bytes from the inner body until `carry.len() >= need`.
    async fn ensure_in_carry(&mut self, need: usize) -> IoResult<()> {
        while self.carry.len() < need {
            let chunk = self.inner.read().await?;
            if chunk.is_empty() {
                return Err(IoError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "aws-chunked: body ended mid-chunk",
                )));
            }
            self.carry.extend_from_slice(&chunk);
        }
        Ok(())
    }

    /// Consume the next chunk header + payload from the inner body,
    /// verify its signature, and stage the payload in `chunk_buf`.
    /// Returns `false` once the trailing zero-length chunk is
    /// processed (EOF marker).
    async fn fetch_chunk(&mut self) -> IoResult<bool> {
        // Header line: ends at the next `\r\n`. We don't know its
        // exact length up front, so read in 4 KiB rounds until we
        // see CRLF.
        loop {
            if let Some(p) = find_crlf(&self.carry) {
                let line = std::str::from_utf8(&self.carry[..p])
                    .map_err(|_| IoError::Decode("aws-chunked: header not utf-8".into()))?
                    .to_owned();
                self.carry.drain(..p + 2);

                let (size_hex, sig) = line
                    .split_once(';')
                    .ok_or_else(|| IoError::Decode("aws-chunked: header missing ';'".into()))?;
                let size = usize::from_str_radix(size_hex.trim(), 16)
                    .map_err(|_| IoError::Decode("aws-chunked: bad chunk size".into()))?;
                let sig = sig
                    .strip_prefix("chunk-signature=")
                    .ok_or_else(|| IoError::Decode("aws-chunked: missing chunk-signature".into()))?
                    .trim();

                // Read `size + 2` (the trailing CRLF) into carry.
                self.ensure_in_carry(size + 2).await?;
                let payload = &self.carry[..size];
                let new_running = verify_chunk(
                    payload,
                    &self.running_sig,
                    sig,
                    &self.access_key,
                    &self.secret,
                    &self.region,
                    self.request_time,
                )
                .map_err(|e| IoError::Decode(format!("aws-chunked: {e}")))?;

                if &self.carry[size..size + 2] != b"\r\n" {
                    return Err(IoError::Decode(
                        "aws-chunked: chunk not CRLF-terminated".into(),
                    ));
                }

                self.chunk_buf.clear();
                self.chunk_buf.extend_from_slice(payload);
                self.chunk_pos = 0;
                self.carry.drain(..size + 2);
                self.running_sig = new_running;
                return Ok(size != 0);
            }
            // No CRLF yet — read more bytes from the inner body.
            let prev_len = self.carry.len();
            let chunk = self.inner.read().await?;
            if chunk.is_empty() {
                return Err(IoError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "aws-chunked: body ended before chunk header",
                )));
            }
            self.carry.extend_from_slice(&chunk);
            // Defensive: a malicious peer cannot trick us into
            // looping forever without making forward progress.
            if self.carry.len() == prev_len {
                return Err(IoError::Decode(
                    "aws-chunked: header read made no progress".into(),
                ));
            }
        }
    }
}

#[async_trait(?Send)]
impl ByteStream for ChunkedBodyStream {
    async fn read(&mut self) -> IoResult<Bytes> {
        if self.finished {
            return Ok(Bytes::new());
        }
        if self.chunk_pos >= self.chunk_buf.len() {
            if !self.fetch_chunk().await? {
                self.finished = true;
                return Ok(Bytes::new());
            }
        }
        let avail = self.chunk_buf.len() - self.chunk_pos;
        // Slice + memcpy out of `chunk_buf: Vec<u8>` is the one
        // remaining cost of aws-chunked decoding (the chunk's bytes
        // are already in `chunk_buf` because we needed them
        // contiguous to verify the per-chunk signature). Wrap as
        // Bytes so downstream is zero-copy.
        let payload = bytes::Bytes::copy_from_slice(
            &self.chunk_buf[self.chunk_pos..self.chunk_pos + avail],
        );
        self.chunk_pos += avail;
        Ok(payload)
    }
}

/// One of the three SigV4 body-verification modes, dispatched on
/// `x-amz-content-sha256`.
pub enum BodySource {
    /// `UNSIGNED-PAYLOAD` — pass body bytes straight through without
    /// hashing. Seed signature still covers the request-line and
    /// headers (verified by the SigV4 middleware).
    Plain(AxumBodyStream),
    /// Single-shot signed body: the client declared the body's
    /// SHA-256 in `x-amz-content-sha256`. We tee bytes through
    /// `Sha256VerifyStream` and surface a content-mismatch error
    /// when EOF arrives without a digest match.
    HexSha(Sha256VerifyStream<AxumBodyStream>),
    /// `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` — aws-chunked framing,
    /// per-chunk SigV4 signature chained off the seed.
    Chunked(ChunkedBodyStream),
}

impl BodySource {
    pub fn plain(body: Body) -> Self {
        BodySource::Plain(AxumBodyStream::new(body))
    }

    pub fn hex_sha(body: Body, expected_hex: &str) -> Result<Self, IoError> {
        let inner = AxumBodyStream::new(body);
        Sha256VerifyStream::new(inner, expected_hex)
            .map(BodySource::HexSha)
            .map_err(|e| IoError::InvalidArgument(format!("{e}")))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn chunked(
        body:           Body,
        seed_signature: String,
        access_key:     String,
        secret:         String,
        region:         String,
        request_time:   SystemTime,
    ) -> Self {
        BodySource::Chunked(ChunkedBodyStream::new(
            body, seed_signature, access_key, secret, region, request_time,
        ))
    }
}

#[async_trait(?Send)]
impl ByteStream for BodySource {
    async fn read(&mut self) -> IoResult<Bytes> {
        match self {
            BodySource::Plain(s)   => s.read().await,
            BodySource::HexSha(s)  => s.read().await,
            BodySource::Chunked(s) => s.read().await,
        }
    }
}
