//! `StorageBackend` implementation that ships every call to a peer
//! node over a single, multiplexed HTTP/2 connection.
//!
//! The wire is `cyper::Client` for the request side and
//! `cyper::Response` for the reply side. h2 multiplexing (one TCP
//! connection per peer pair, many concurrent streams) eliminates the
//! per-RPC dial that the legacy custom-binary protocol paid: an
//! EC[D+P] read used to mean `D+P` fresh TCP+TLS handshakes per
//! object; here it is `D+P` h2 streams on already-warm connections.
//!
//! Three URL shapes carry the entire `StorageBackend` + `LockPeer`
//! surface:
//!
//!   * `POST /v1/rpc` — unary. Body is bincode-encoded `Request`;
//!     reply body is bincode-encoded `Response`. Used by 20 of the
//!     22 trait methods plus the two lock RPCs.
//!   * `PUT /v1/rpc/stream-write` — `create_file_writer`. The
//!     bincode-encoded `Request::CreateFileStream` rides as a single
//!     URL-safe-base64 header (`x-phenomenal-rpc`); the body is the
//!     object bytes streamed via `cyper::Body::stream(...)` from an
//!     `mpsc::channel` that the returned `RemoteWriteSink` pushes
//!     into. This is the push→pull bridge: cyper's body half pulls
//!     from the channel as the engine half pushes via
//!     `ByteSink::write_all`.
//!   * `POST /v1/rpc/stream-read` — `read_file_stream`. Body carries
//!     the bincode-encoded `Request::ReadFileStream`; on success the
//!     response body IS the object bytes (length cross-checked
//!     against the `x-phenomenal-length` response header).
//!
//! No connection pooling, no `dial()`, no length-prefix framing —
//! cyper's hyper-util-backed pool keeps one h2 connection per peer
//! and multiplexes every concurrent call through it.

use std::net::SocketAddr;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bytes::Bytes;
use compio::runtime::JoinHandle;
use futures::SinkExt;
use futures_util::{Stream, StreamExt};
use http::HeaderName;
use rustls::ClientConfig;

use crate::backend::{LockPeer, StorageBackend};
use crate::error::{IoError, IoResult};
use crate::rpc::{self, DiskIdx, Request, Response};
use crate::stream::{ByteSink, ByteStream};
use crate::types::{
    DeleteOptions, DiskInfo, FileInfo, FormatJson, RenameDataResp, RenameOptions,
    UpdateMetadataOpts, VolInfo,
};

// -----------------------------------------------------------------------------
// Wire conventions.
//
// All three routes live on the same h2 origin per peer; the path
// disambiguates unary from streaming. Header names are fixed strings
// so they const-build to `HeaderName` (no per-call hashing).
// -----------------------------------------------------------------------------

/// URL path for unary RPCs. Bincode-encoded `Request` in the request
/// body, bincode-encoded `Response` in the reply body.
const URL_RPC:    &str = "v1/rpc";
/// URL path for `create_file_writer`. The `Request::CreateFileStream`
/// envelope rides in `HDR_RPC`; the request body is the streamed
/// object bytes.
const URL_WRITE:  &str = "v1/rpc/stream-write";
/// URL path for `read_file_stream`. The `Request::ReadFileStream`
/// envelope rides in the request body; the response body is the
/// streamed object bytes.
const URL_READ:   &str = "v1/rpc/stream-read";

/// Header carrying the URL-safe-base64 bincode-encoded `Request`
/// envelope on the streaming-write route. We use a header rather than
/// a query parameter because the path/volume strings can be long and
/// we want every byte of the body for object content.
const HDR_RPC: HeaderName = HeaderName::from_static("x-phenomenal-rpc");

/// Channel depth feeding the `cyper::Body::stream(...)` adapter for
/// streaming PUTs. Eight buffered chunks keeps the h2 send window
/// fully fed without unbounded memory: at `STREAM_CHUNK_BYTES`
/// (~64 KiB) per chunk the adapter holds at most ~512 KiB in flight,
/// matching the h2 default initial window.
const PUT_CHANNEL_DEPTH: usize = 8;

/// Convert any error type that implements `Display` into an `IoError`
/// suitable for the `StorageBackend` surface. Used for cyper, http,
/// and stream-channel failures uniformly so callers see one error
/// shape.
fn map_http<E: std::fmt::Display>(e: E) -> IoError {
    IoError::Io(std::io::Error::other(e.to_string()))
}

fn unexpected(r: Response) -> IoError {
    IoError::Decode(format!("unexpected response variant: {r:?}"))
}

/// Boxed h2 response body stream. `LocalBoxStream`-shaped — the body
/// is bound to the runtime that issued the request so we pin-box it
/// rather than constraining the trait to `Send`.
type ResponseStream = Pin<Box<dyn Stream<Item = cyper::Result<Bytes>>>>;

// -----------------------------------------------------------------------------
// Per-peer cyper client.
//
// One `PeerClient` per `(self, peer)` pair per runtime. Cloning a
// `cyper::Client` bumps an `Arc` refcount on hyper-util's pooled
// inner client, so the actual h2 connection (one per peer per
// runtime) is created lazily on first request and reused for every
// subsequent request. h2 multiplexing then handles concurrency over
// that single connection.
// -----------------------------------------------------------------------------

pub struct PeerClient {
    /// `https://host:port` — cyper's URL parser concatenates the path
    /// suffix at call time. Stored as `String` because `http::Uri`
    /// doesn't support trivially appending path segments.
    base:   String,
    client: cyper::Client,
}

impl PeerClient {
    /// Build a peer client for `addr` configured with the cluster's
    /// rustls `ClientConfig` (ALPN list = `[b"h2"]`, root CA pinned).
    /// The client is lazy: no socket is opened until the first
    /// request.
    pub fn new(addr: SocketAddr, tls: Arc<ClientConfig>) -> Self {
        let client = cyper::Client::builder()
            .use_rustls(tls)
            .build();
        Self { base: format!("https://{addr}"), client }
    }

    fn url(&self, suffix: &str) -> String {
        format!("{}/{}", self.base, suffix)
    }
}

// -----------------------------------------------------------------------------
// `RemoteBackend`: one instance per `(peer_node, disk_idx)` pair.
// -----------------------------------------------------------------------------

/// `StorageBackend` impl that ships disk-targeted RPCs to a peer
/// node. Each instance is bound to a specific `(peer_node, disk_idx)`
/// pair: the peer node is determined by the shared `Rc<PeerClient>`,
/// and `disk_idx` selects which of the peer's disks every RPC
/// applies to.
///
/// Multiple `RemoteBackend`s for the same peer node share one
/// `PeerClient` (and therefore one h2 connection on first use), so
/// connection cost is `O(peers)` not `O(peers × disks)`.
pub struct RemoteBackend {
    peer:     Rc<PeerClient>,
    disk_idx: DiskIdx,
}

impl RemoteBackend {
    pub fn new(peer: Rc<PeerClient>, disk_idx: DiskIdx) -> Self {
        Self { peer, disk_idx }
    }

    pub fn disk_idx(&self) -> DiskIdx { self.disk_idx }

    /// Send one unary RPC and decode the reply.
    ///
    /// 2xx with a valid bincode `Response` body is the success path.
    /// Non-2xx responses still attempt to decode `Response::Err`
    /// from the body so a richer error reaches the caller; only
    /// undecodable bodies fall back to a generic
    /// `rpc http <status>` error.
    async fn unary(&self, req: Request) -> IoResult<Response> {
        let body = rpc::encode(&req)?;
        let resp = self
            .peer.client
            .post(self.peer.url(URL_RPC))
            .map_err(map_http)?
            .body(body)
            .send().await
            .map_err(map_http)?;
        let status = resp.status();
        let bytes  = resp.bytes().await.map_err(map_http)?;
        if !status.is_success() {
            if let Ok(Response::Err(e)) = rpc::decode::<Response>(&bytes) {
                return Err(e.into());
            }
            return Err(IoError::Io(std::io::Error::other(
                format!("rpc http status: {status}")
            )));
        }
        rpc::decode::<Response>(&bytes)
    }

    /// Lock-plane: acquire. Both lock RPCs ride the same unary route
    /// as every other call — the lock plane gets no special wire
    /// treatment.
    pub async fn lock_acquire(&self, resource: &str, uid: &str, ttl_ms: u32) -> IoResult<bool> {
        match self.unary(Request::LockAcquire {
            resource: resource.into(), uid: uid.into(), ttl_ms,
        }).await? {
            Response::LockGranted => Ok(true),
            Response::LockDenied  => Ok(false),
            Response::Err(e)      => Err(e.into()),
            other                 => Err(unexpected(other)),
        }
    }

    /// Lock-plane: release.
    pub async fn lock_release(&self, resource: &str, uid: &str) -> IoResult<()> {
        match self.unary(Request::LockRelease {
            resource: resource.into(), uid: uid.into(),
        }).await? {
            Response::Ok     => Ok(()),
            Response::Err(e) => Err(e.into()),
            other            => Err(unexpected(other)),
        }
    }
}

// `call_unit!` / `call_typed!` are thin wrappers that the 22-method
// `StorageBackend` impl below uses to keep each method body to a
// single line. They expand to the same match-on-Response shape every
// caller writes by hand otherwise.
macro_rules! call_unit {
    ($self:expr, $req:expr) => {
        match $self.unary($req).await? {
            Response::Ok     => Ok(()),
            Response::Err(e) => Err(e.into()),
            other            => Err(unexpected(other)),
        }
    };
}
macro_rules! call_typed {
    ($self:expr, $req:expr, $variant:ident) => {
        match $self.unary($req).await? {
            Response::$variant(v) => Ok(v),
            Response::Err(e)      => Err(e.into()),
            other                 => Err(unexpected(other)),
        }
    };
}

// -----------------------------------------------------------------------------
// Streaming GET: response body becomes a `ByteStream`.
// -----------------------------------------------------------------------------

pub struct RemoteReadStream {
    inner:     ResponseStream,
    /// Bytes still expected from the peer body. Reaching zero is the
    /// normal EOF path; reaching `None` from `inner` before zero
    /// surfaces as `UnexpectedEof`.
    remaining: u64,
}

#[async_trait(?Send)]
impl ByteStream for RemoteReadStream {
    async fn read(&mut self) -> IoResult<Bytes> {
        if self.remaining == 0 {
            return Ok(Bytes::new());
        }
        match self.inner.next().await {
            Some(Ok(buf)) => {
                if buf.is_empty() {
                    // Empty data frame — pull again so caller
                    // contract ("empty Bytes means EOF") holds.
                    return Box::pin(self.read()).await;
                }
                let n = buf.len() as u64;
                if n > self.remaining {
                    return Err(IoError::Io(std::io::Error::other(
                        format!("remote read overran by {} bytes", n - self.remaining)
                    )));
                }
                self.remaining -= n;
                Ok(buf)
            }
            Some(Err(e)) => Err(map_http(e)),
            None => Err(IoError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                format!("remote stream truncated, {} bytes missing", self.remaining),
            ))),
        }
    }
}

// -----------------------------------------------------------------------------
// Streaming PUT: writes to a `ByteSink` push into an mpsc that
// becomes the cyper request body. The request future is spawned at
// construction time so the body pull and the engine's push run
// concurrently on the same compio runtime.
// -----------------------------------------------------------------------------

pub struct RemoteWriteSink {
    /// Sender side of the body channel. Dropped on `finish()` so
    /// cyper's body stream sees clean EOF.
    tx:       Option<futures::channel::mpsc::Sender<cyper::Result<Bytes>>>,
    /// Pending request future. Resolved by `finish()` once the body
    /// has been fully fed.
    handle:   Option<JoinHandle<cyper::Result<cyper::Response>>>,
    expected: u64,
    written:  u64,
    finished: bool,
}

#[async_trait(?Send)]
impl ByteSink for RemoteWriteSink {
    async fn write_all(&mut self, buf: Bytes) -> IoResult<()> {
        if self.finished {
            return Err(IoError::Io(std::io::Error::other("write after finish")));
        }
        if buf.is_empty() {
            return Ok(());
        }
        let len = buf.len() as u64;
        let tx = self.tx.as_mut()
            .ok_or_else(|| IoError::Io(std::io::Error::other("sink already closed")))?;
        // Channel back-pressure naturally throttles the engine when
        // the network is slower than the writer: mpsc::send awaits
        // until there's slot space (bounded by PUT_CHANNEL_DEPTH).
        tx.send(Ok(buf)).await
            .map_err(|_| IoError::Io(std::io::Error::other("peer body channel closed")))?;
        self.written += len;
        Ok(())
    }

    async fn finish(&mut self) -> IoResult<()> {
        if self.finished { return Ok(()); }
        self.finished = true;
        if self.written != self.expected {
            return Err(IoError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                format!("create_file_writer: wrote {}/{}", self.written, self.expected),
            )));
        }
        // EOF the body channel — cyper's body stream resolves to
        // `None` next, completing the h2 DATA frames with END_STREAM.
        self.tx.take();

        let handle = self.handle.take()
            .ok_or_else(|| IoError::Io(std::io::Error::other("missing request future")))?;
        // `JoinHandle::await` yields `Result<T, Box<dyn Any + Send>>`
        // where the outer error is a runtime panic. Map both layers.
        let resp = handle.await
            .map_err(|_| IoError::Io(std::io::Error::other("rpc body task panicked")))?
            .map_err(map_http)?;

        let status = resp.status();
        let bytes  = resp.bytes().await.map_err(map_http)?;
        if !status.is_success() {
            return Err(match rpc::decode::<Response>(&bytes) {
                Ok(Response::Err(e)) => e.into(),
                _ => IoError::Io(std::io::Error::other(format!("create_file http {status}"))),
            });
        }
        match rpc::decode::<Response>(&bytes)? {
            Response::Ok     => Ok(()),
            Response::Err(e) => Err(e.into()),
            other            => Err(unexpected(other)),
        }
    }
}

// -----------------------------------------------------------------------------
// `StorageBackend` impl. 20 unary methods plus the two streaming
// methods. Every body is one to three lines — the macros + helpers
// above carry the work.
// -----------------------------------------------------------------------------

#[async_trait(?Send)]
impl StorageBackend for RemoteBackend {
    fn label(&self) -> String {
        format!("remote:{}/d{}", self.peer.base, self.disk_idx)
    }

    async fn disk_info(&self) -> IoResult<DiskInfo> {
        call_typed!(self, Request::DiskInfo { disk_idx: self.disk_idx }, Disk)
    }

    async fn make_vol(&self, volume: &str) -> IoResult<()> {
        call_unit!(self, Request::MakeVol { disk_idx: self.disk_idx, volume: volume.into() })
    }

    async fn list_vols(&self) -> IoResult<Vec<VolInfo>> {
        call_typed!(self, Request::ListVols { disk_idx: self.disk_idx }, Vols)
    }

    async fn stat_vol(&self, volume: &str) -> IoResult<VolInfo> {
        call_typed!(self, Request::StatVol { disk_idx: self.disk_idx, volume: volume.into() }, Vol)
    }

    async fn delete_vol(&self, volume: &str, force_delete: bool) -> IoResult<()> {
        call_unit!(self, Request::DeleteVol { disk_idx: self.disk_idx, volume: volume.into(), force_delete })
    }

    async fn list_dir(&self, volume: &str, dir_path: &str, count: usize) -> IoResult<Vec<String>> {
        call_typed!(
            self,
            Request::ListDir { disk_idx: self.disk_idx, volume: volume.into(), dir_path: dir_path.into(), count: count as u32 },
            Strings
        )
    }

    async fn read_file_stream(
        &self, volume: &str, path: &str, offset: u64, length: u64,
    ) -> IoResult<Box<dyn ByteStream>> {
        let req = Request::ReadFileStream {
            disk_idx: self.disk_idx,
            volume: volume.into(), path: path.into(), offset, length,
        };
        let body = rpc::encode(&req)?;
        let resp = self
            .peer.client
            .post(self.peer.url(URL_READ))
            .map_err(map_http)?
            .body(body)
            .send().await
            .map_err(map_http)?;
        let status = resp.status();
        if !status.is_success() {
            // Error path: response body carries an encoded `Response::Err`.
            let bytes = resp.bytes().await.map_err(map_http)?;
            if let Ok(Response::Err(e)) = rpc::decode::<Response>(&bytes) {
                return Err(e.into());
            }
            return Err(IoError::Io(std::io::Error::other(
                format!("read_file_stream http {status}")
            )));
        }
        let inner: ResponseStream = Box::pin(resp.bytes_stream());
        Ok(Box::new(RemoteReadStream { inner, remaining: length }))
    }

    async fn create_file_writer(
        &self, volume: &str, path: &str, size: u64,
    ) -> IoResult<Box<dyn ByteSink>> {
        let env = Request::CreateFileStream {
            disk_idx: self.disk_idx,
            volume: volume.into(), path: path.into(), size,
        };
        let env_b64 = URL_SAFE_NO_PAD.encode(rpc::encode(&env)?);

        let (tx, rx) = futures::channel::mpsc::channel::<cyper::Result<Bytes>>(PUT_CHANNEL_DEPTH);
        let body = cyper::Body::stream(rx);

        // Drive the request future on the same runtime so the body
        // pull (cyper) and body push (sink writes) interleave
        // cooperatively. Spawning is mandatory: if we held the
        // future and only awaited it inside `finish()`, the body
        // channel would deadlock waiting for a reader.
        let url    = self.peer.url(URL_WRITE);
        let client = self.peer.client.clone();
        let handle = compio::runtime::spawn(async move {
            client
                .put(&url)?
                .header(HDR_RPC, env_b64.as_str())?
                .header(http::header::CONTENT_LENGTH, size)?
                .body(body)
                .send().await
        });

        Ok(Box::new(RemoteWriteSink {
            tx:       Some(tx),
            handle:   Some(handle),
            expected: size,
            written:  0,
            finished: false,
        }))
    }

    async fn rename_file(
        &self, src_volume: &str, src_path: &str, dst_volume: &str, dst_path: &str,
    ) -> IoResult<()> {
        call_unit!(self, Request::RenameFile {
            disk_idx: self.disk_idx,
            src_volume: src_volume.into(), src_path: src_path.into(),
            dst_volume: dst_volume.into(), dst_path: dst_path.into(),
        })
    }

    async fn check_file(&self, volume: &str, path: &str) -> IoResult<()> {
        call_unit!(self, Request::CheckFile { disk_idx: self.disk_idx, volume: volume.into(), path: path.into() })
    }

    async fn delete(&self, volume: &str, path: &str, recursive: bool) -> IoResult<()> {
        call_unit!(self, Request::Delete { disk_idx: self.disk_idx, volume: volume.into(), path: path.into(), recursive })
    }

    async fn write_metadata(
        &self, orig_volume: &str, volume: &str, path: &str, fi: &FileInfo,
    ) -> IoResult<()> {
        call_unit!(self, Request::WriteMetadata {
            disk_idx: self.disk_idx,
            orig_volume: orig_volume.into(),
            volume: volume.into(), path: path.into(),
            fi: fi.clone(),
        })
    }

    async fn read_version(
        &self, orig_volume: &str, volume: &str, path: &str,
        version_id: Option<&str>, read_data: bool,
    ) -> IoResult<FileInfo> {
        call_typed!(
            self,
            Request::ReadVersion {
                disk_idx: self.disk_idx,
                orig_volume: orig_volume.into(),
                volume: volume.into(), path: path.into(),
                version_id: version_id.map(str::to_owned),
                read_data,
            },
            File
        )
    }

    async fn update_metadata(
        &self, volume: &str, path: &str, fi: &FileInfo, opts: &UpdateMetadataOpts,
    ) -> IoResult<()> {
        call_unit!(self, Request::UpdateMetadata {
            disk_idx: self.disk_idx,
            volume: volume.into(), path: path.into(),
            fi: fi.clone(), no_persistence: opts.no_persistence,
        })
    }

    async fn delete_version(
        &self, volume: &str, path: &str, fi: &FileInfo,
        force_del_marker: bool, opts: &DeleteOptions,
    ) -> IoResult<()> {
        call_unit!(self, Request::DeleteVersion {
            disk_idx: self.disk_idx,
            volume: volume.into(), path: path.into(),
            fi: fi.clone(),
            force_del_marker,
            undo_write: opts.undo_write,
        })
    }

    async fn rename_data(
        &self, src_volume: &str, src_path: &str, fi: &FileInfo,
        dst_volume: &str, dst_path: &str, _opts: &RenameOptions,
    ) -> IoResult<RenameDataResp> {
        call_typed!(self, Request::RenameData {
            disk_idx: self.disk_idx,
            src_volume: src_volume.into(), src_path: src_path.into(),
            fi: fi.clone(),
            dst_volume: dst_volume.into(), dst_path: dst_path.into(),
        }, Renamed)
    }

    async fn verify_file(&self, volume: &str, path: &str, fi: &FileInfo) -> IoResult<()> {
        call_unit!(self, Request::VerifyFile {
            disk_idx: self.disk_idx,
            volume: volume.into(), path: path.into(), fi: fi.clone(),
        })
    }

    async fn read_format(&self) -> IoResult<Option<FormatJson>> {
        match self.unary(Request::ReadFormat { disk_idx: self.disk_idx }).await? {
            Response::FormatOpt(opt) => Ok(opt),
            Response::Err(e)         => Err(e.into()),
            other                    => Err(unexpected(other)),
        }
    }

    async fn write_format(&self, fmt: &FormatJson) -> IoResult<()> {
        call_unit!(self, Request::WriteFormat {
            disk_idx: self.disk_idx,
            fmt: fmt.clone(),
        })
    }

    async fn write_file(&self, volume: &str, path: &str, bytes: Vec<u8>) -> IoResult<()> {
        call_unit!(self, Request::WriteFile {
            disk_idx: self.disk_idx,
            volume:   volume.into(),
            path:     path.into(),
            bytes,
        })
    }

    async fn read_file(&self, volume: &str, path: &str) -> IoResult<Option<Vec<u8>>> {
        match self.unary(Request::ReadFile {
            disk_idx: self.disk_idx,
            volume:   volume.into(),
            path:     path.into(),
        }).await? {
            Response::FileBytes(opt) => Ok(opt),
            Response::Err(e)         => Err(e.into()),
            other                    => Err(unexpected(other)),
        }
    }

    async fn make_dir_all(&self, volume: &str, path: &str) -> IoResult<()> {
        call_unit!(self, Request::MakeDirAll {
            disk_idx: self.disk_idx,
            volume:   volume.into(),
            path:     path.into(),
        })
    }
}

#[async_trait(?Send)]
impl LockPeer for RemoteBackend {
    async fn lock_acquire(&self, resource: &str, uid: &str, ttl_ms: u32) -> IoResult<bool> {
        RemoteBackend::lock_acquire(self, resource, uid, ttl_ms).await
    }
    async fn lock_release(&self, resource: &str, uid: &str) -> IoResult<()> {
        RemoteBackend::lock_release(self, resource, uid).await
    }
}
