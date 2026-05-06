//! `StorageBackend` implementation that ships every call to a peer node
//! over TCP RPC. The peer's RPC server maps requests 1:1 onto its own
//! `LocalFsBackend`, so the wire boundary is invisible to callers.
//!
//! Two transport profiles share the same TCP listener:
//!   * Control plane (small bincode envelopes both directions) reuses
//!     a small pool of cached connections.
//!   * Data plane (`CreateFileStream`, `ReadFileStream`) dials a fresh
//!     connection per call, holds it open for the duration of the byte
//!     stream, and closes it when the stream is fully drained. Bytes
//!     flow through the socket without per-chunk framing.

use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::Mutex;

use async_trait::async_trait;
use compio::buf::{BufResult, IntoInner, IoBuf, IoBufMut};
use compio::io::{AsyncRead, AsyncWrite};
use compio::net::TcpStream;
use compio::tls::{TlsConnector, TlsStream};

use crate::alloc::PooledBuffer;
use crate::backend::{LockPeer, StorageBackend};
use crate::error::{IoError, IoResult};
use crate::rpc::{self, DiskIdx, Request, Response};
use crate::stream::{ByteSink, ByteStream};
use crate::types::{
    DeleteOptions, DiskInfo, FileInfo, RenameDataResp, RenameOptions,
    UpdateMetadataOpts, VolInfo,
};

/// Soft cap on the cached control-plane connections per peer. Past this
/// the pool drops the oldest connection on release rather than growing
/// without bound. Picked to bound FD usage at `peers × CONTROL_POOL_MAX`
/// while still amortising connect cost across bursty workloads.
const CONTROL_POOL_MAX: usize = 16;

/// One peer connection, plaintext or TLS-wrapped.
pub enum PeerStream {
    Tcp(TcpStream),
    Tls(TlsStream<TcpStream>),
}

impl AsyncRead for PeerStream {
    async fn read<B: IoBufMut>(&mut self, buf: B) -> BufResult<usize, B> {
        match self {
            PeerStream::Tcp(s) => s.read(buf).await,
            PeerStream::Tls(s) => s.read(buf).await,
        }
    }
}

impl AsyncWrite for PeerStream {
    async fn write<B: IoBuf>(&mut self, buf: B) -> BufResult<usize, B> {
        match self {
            PeerStream::Tcp(s) => s.write(buf).await,
            PeerStream::Tls(s) => s.write(buf).await,
        }
    }

    async fn flush(&mut self) -> std::io::Result<()> {
        match self {
            PeerStream::Tcp(s) => s.flush().await,
            PeerStream::Tls(s) => s.flush().await,
        }
    }

    async fn shutdown(&mut self) -> std::io::Result<()> {
        match self {
            PeerStream::Tcp(s) => s.shutdown().await,
            PeerStream::Tls(s) => s.shutdown().await,
        }
    }
}

/// One peer node's connection-pool state. Shared across every
/// `RemoteBackend` instance that targets a disk on this peer (i.e.
/// one `PeerConn` per peer node, with N `RemoteBackend`s referencing
/// it for that node's N disks).
///
/// The synchronous `Mutex` is only held around `pop`/`push` — never
/// across an `await` — so it does not stall the runtime. Concurrent
/// control-plane calls past `CONTROL_POOL_MAX` dial fresh sockets,
/// and the kernel's TCP multiplexing handles the fan-in.
pub struct PeerConn {
    addr:        SocketAddr,
    tls:         Option<Rc<TlsConnector>>,
    server_name: String,
    pool:        Mutex<Vec<PeerStream>>,
}

impl PeerConn {
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            tls:         None,
            server_name: addr.ip().to_string(),
            pool:        Mutex::new(Vec::new()),
        }
    }

    pub fn with_tls(addr: SocketAddr, server_name: String, connector: Rc<TlsConnector>) -> Self {
        Self {
            addr,
            tls:         Some(connector),
            server_name,
            pool:        Mutex::new(Vec::new()),
        }
    }
}

/// `StorageBackend` impl that ships disk-targeted RPCs to a peer
/// node. Each instance is bound to a specific `(peer_node, disk_idx)`
/// pair: the peer node is determined by the shared `Rc<PeerConn>`,
/// and `disk_idx` selects which of the peer's disks every RPC
/// applies to.
///
/// Multiple `RemoteBackend`s for the same peer node share one
/// `PeerConn` (and therefore one TCP/TLS connection pool), so
/// connection cost is `O(peers)` not `O(peers × disks)`.
pub struct RemoteBackend {
    peer:     Rc<PeerConn>,
    disk_idx: DiskIdx,
}

impl RemoteBackend {
    /// Construct a backend targeting `disk_idx` on the peer reachable
    /// via `peer`. Cheap — just an `Rc` clone.
    pub fn new(peer: Rc<PeerConn>, disk_idx: DiskIdx) -> Self {
        Self { peer, disk_idx }
    }

    /// The disk index this backend is bound to.
    pub fn disk_idx(&self) -> DiskIdx { self.disk_idx }

    // -----------------------------------------------------------------
    // Control plane (envelope-shaped RPCs)
    // -----------------------------------------------------------------

    async fn call(&self, req: Request) -> IoResult<Response> {
        for attempt in 0..2 {
            match self.call_once(&req).await {
                Ok(resp)                                              => return Ok(resp),
                Err(e) if attempt == 0 && matches!(e, IoError::Io(_)) => continue,
                Err(e)                                                => return Err(e),
            }
        }
        unreachable!()
    }

    async fn call_once(&self, req: &Request) -> IoResult<Response> {
        let mut conn = self.acquire_control().await?;
        let body = rpc::encode(req)?;
        if let Err(e) = rpc::write_frame(&mut conn, &body).await {
            return Err(IoError::Io(e));
        }
        let resp_bytes = rpc::read_frame(&mut conn).await.map_err(IoError::Io)?;
        let resp: Response = rpc::decode(&resp_bytes)?;
        self.release_control(conn);
        Ok(resp)
    }

    /// Lock-plane: acquire.
    pub async fn lock_acquire(&self, resource: &str, uid: &str, ttl_ms: u32) -> IoResult<bool> {
        match self.call(Request::LockAcquire {
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
        match self.call(Request::LockRelease {
            resource: resource.into(), uid: uid.into(),
        }).await? {
            Response::Ok     => Ok(()),
            Response::Err(e) => Err(e.into()),
            other            => Err(unexpected(other)),
        }
    }

    // -----------------------------------------------------------------
    // Connection management — delegated to the shared `PeerConn`.
    // -----------------------------------------------------------------

    async fn acquire_control(&self) -> IoResult<PeerStream> {
        self.peer.acquire_control().await
    }

    fn release_control(&self, conn: PeerStream) {
        self.peer.release_control(conn)
    }

    async fn dial(&self) -> IoResult<PeerStream> {
        self.peer.dial().await
    }
}

impl PeerConn {
    /// Pop a cached control connection if one is available; otherwise
    /// dial a fresh one.
    async fn acquire_control(&self) -> IoResult<PeerStream> {
        if let Some(c) = self.pool.lock().unwrap().pop() {
            return Ok(c);
        }
        self.dial().await
    }

    /// Return a control connection to the pool, dropping it if the
    /// pool is already at `CONTROL_POOL_MAX` capacity.
    fn release_control(&self, conn: PeerStream) {
        let mut pool = self.pool.lock().unwrap();
        if pool.len() < CONTROL_POOL_MAX {
            pool.push(conn);
        }
        // else drop — bounded FD usage.
    }

    /// Dial a fresh TCP/TLS connection. Used both for control-plane
    /// pool fills and for data-plane streams (which never touch the
    /// pool — they're held open for the duration of one streaming
    /// PUT/GET, then closed).
    async fn dial(&self) -> IoResult<PeerStream> {
        // Build a raw socket so we can set TCP buffer sizes and Nagle
        // off BEFORE the SYN handshake. TCP window-scaling (RFC 1323)
        // is negotiated in SYN — the scale factor cannot change after
        // the connection is established. Without these, every inter-
        // node shard fetch is window-limited to ~1.5 Gbps regardless
        // of NIC speed. `TCP_BUFFER_BYTES` is the central tuning
        // value (see `phenomenal_io::tuning`).
        use crate::tuning::TCP_BUFFER_BYTES;
        let socket = socket2::Socket::new(
            socket2::Domain::for_address(self.addr),
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        ).map_err(IoError::Io)?;
        socket.set_recv_buffer_size(TCP_BUFFER_BYTES).map_err(IoError::Io)?; // 4 MiB
        socket.set_send_buffer_size(TCP_BUFFER_BYTES).map_err(IoError::Io)?; // 4 MiB
        socket.set_tcp_nodelay(true).map_err(IoError::Io)?;
        socket.connect(&self.addr.into()).map_err(IoError::Io)?;
        socket.set_nonblocking(true).map_err(IoError::Io)?;
        let std_stream: std::net::TcpStream = socket.into();
        let tcp = TcpStream::from_std(std_stream).map_err(IoError::Io)?;
        match &self.tls {
            None      => Ok(PeerStream::Tcp(tcp)),
            Some(c)   => {
                let stream = c.connect(&self.server_name, tcp).await.map_err(IoError::Io)?;
                Ok(PeerStream::Tls(stream))
            }
        }
    }
}

fn unexpected(r: Response) -> IoError {
    IoError::Decode(format!("unexpected response variant: {r:?}"))
}

macro_rules! call_unit {
    ($self:expr, $req:expr) => {
        match $self.call($req).await? {
            Response::Ok     => Ok(()),
            Response::Err(e) => Err(e.into()),
            other            => Err(unexpected(other)),
        }
    };
}
macro_rules! call_typed {
    ($self:expr, $req:expr, $variant:ident) => {
        match $self.call($req).await? {
            Response::$variant(v) => Ok(v),
            Response::Err(e)      => Err(e.into()),
            other                 => Err(unexpected(other)),
        }
    };
}

// ---------------------------------------------------------------------------
// Streaming read: a `ByteStream` that owns the TCP/TLS connection for the
// duration of the read. The connection is closed when the stream is
// dropped — data-plane connections are not pooled because they are held
// for the full body transfer.
// ---------------------------------------------------------------------------

pub struct RemoteReadStream {
    conn:      PeerStream,
    remaining: u64,
}

/// `ByteSink` over an open data-plane connection. The header has
/// already been sent by the time this sink is constructed; each
/// `write_all` lands as one or more `compio` socket writes. `finish`
/// flushes (TLS) and reads the status response.
pub struct RemoteWriteSink {
    conn:     PeerStream,
    expected: u64,
    written:  u64,
    finished: bool,
}

#[async_trait(?Send)]
impl ByteSink for RemoteWriteSink {
    async fn write_all(&mut self, buf: bytes::Bytes) -> IoResult<()> {
        if self.finished {
            return Err(IoError::Io(std::io::Error::other("write after finish")));
        }
        if buf.is_empty() {
            return Ok(());
        }
        let len = buf.len();
        rpc::write_all_bytes(&mut self.conn, buf).await.map_err(IoError::Io)?;
        self.written += len as u64;
        Ok(())
    }

    async fn finish(&mut self) -> IoResult<()> {
        if self.finished {
            return Ok(());
        }
        self.finished = true;
        if self.written != self.expected {
            return Err(IoError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                format!("create_file_writer: wrote {}/{}", self.written, self.expected),
            )));
        }
        self.conn.flush().await.map_err(IoError::Io)?;
        let resp_bytes = rpc::read_frame(&mut self.conn).await.map_err(IoError::Io)?;
        let resp: Response = rpc::decode(&resp_bytes)?;
        match resp {
            Response::Ok     => Ok(()),
            Response::Err(e) => Err(e.into()),
            other            => Err(unexpected(other)),
        }
    }
}

#[async_trait(?Send)]
impl ByteStream for RemoteReadStream {
    async fn read(&mut self) -> IoResult<bytes::Bytes> {
        let want = self.remaining.min(crate::tuning::STREAM_CHUNK_BYTES as u64) as usize;
        if want == 0 {
            return Ok(bytes::Bytes::new());
        }
        let buf = PooledBuffer::with_capacity(want);
        let slice = buf.slice(0..want);
        let BufResult(res, slice_back) = self.conn.read(slice).await;
        let mut buf = slice_back.into_inner();
        let n = res.map_err(IoError::Io)?;
        if n == 0 {
            return Err(IoError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "remote stream truncated",
            )));
        }
        self.remaining -= n as u64;
        buf.truncate(n);
        Ok(buf.freeze())
    }
}

#[async_trait(?Send)]
impl StorageBackend for RemoteBackend {
    fn label(&self) -> String { format!("remote:{}/d{}", self.peer.addr, self.disk_idx) }

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

    /// Streaming read. Dials a fresh data-plane connection, sends the
    /// `ReadFileStream` header, reads the response header to learn the
    /// length, then returns a `ByteStream` that owns the connection for
    /// the rest of the read.
    async fn read_file_stream(
        &self, volume: &str, path: &str, offset: u64, length: u64,
    ) -> IoResult<Box<dyn ByteStream>> {
        let mut conn = self.dial().await?;
        let req = Request::ReadFileStream {
            disk_idx: self.disk_idx,
            volume: volume.into(), path: path.into(), offset, length,
        };
        rpc::write_frame(&mut conn, &rpc::encode(&req)?).await.map_err(IoError::Io)?;
        let resp_bytes = rpc::read_frame(&mut conn).await.map_err(IoError::Io)?;
        let resp: Response = rpc::decode(&resp_bytes)?;
        let length = match resp {
            Response::StreamHeader { length } => length,
            Response::Err(e)                  => return Err(e.into()),
            other                             => return Err(unexpected(other)),
        };
        Ok(Box::new(RemoteReadStream {
            conn,
            remaining: length,
        }))
    }

    /// Streaming write. Dials a fresh data-plane connection, sends the
    /// `CreateFileStream` header, and returns a `ByteSink` that pushes
    /// raw body bytes onto the connection. The caller pushes exactly
    /// `size` bytes via `write_all`, then `finish()` flushes and reads
    /// the status response. The connection is dropped (closed) after
    /// the call.
    async fn create_file_writer(
        &self, volume: &str, path: &str, size: u64,
    ) -> IoResult<Box<dyn ByteSink>> {
        let mut conn = self.dial().await?;
        let req = Request::CreateFileStream {
            disk_idx: self.disk_idx,
            volume: volume.into(), path: path.into(), size,
        };
        rpc::write_frame(&mut conn, &rpc::encode(&req)?).await.map_err(IoError::Io)?;
        Ok(Box::new(RemoteWriteSink {
            conn,
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
