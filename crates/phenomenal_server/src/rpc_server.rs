//! Peer-to-peer RPC server. Accepts connections from other nodes'
//! `RemoteBackend` clients and routes each `Request` to one of this
//! node's local `StorageBackend` instances — selected by the
//! `disk_idx` field on every disk-targeted request variant.
//!
//! Two transport profiles share the same TCP listener:
//!   * Control plane (envelope-shaped): one `[u32 len][bincode]` frame
//!     in each direction per call. Connections are reused for back-to-
//!     back control calls.
//!   * Data plane (`CreateFileStream`, `ReadFileStream`): the request
//!     header frame is followed by raw body bytes on the same socket.
//!     For PUT the server pumps the socket bytes straight into the
//!     selected disk's `create_file_stream` (no per-object buffering
//!     anywhere); for GET the server opens `read_file_stream` against
//!     the selected disk and drains the resulting `ByteStream`
//!     straight to the socket.
//!
//! Listener is bound with `SO_REUSEPORT` so every runtime in the
//! process can bind the same port; the kernel spreads inbound RPC
//! connections across runtimes via 4-tuple hash. Multi-disk dispatch
//! is independent of the listener: a single TCP connection from a
//! peer carries requests for multiple disks (each request carries
//! its own `disk_idx`).

use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use compio::buf::BufResult;
use compio::io::{AsyncRead, AsyncWrite};
use compio::net::TcpListener;
use compio::tls::TlsAcceptor;

use phenomenal_io::rpc::{self, DiskIdx, Request, Response};
use phenomenal_io::stream::pump_compio_to_sink;
use phenomenal_io::tuning::{DRAIN_CHUNK_BYTES, TCP_BUFFER_BYTES};
use phenomenal_io::{IoError, StorageBackend};

use crate::lock_server::LockServer;

const LISTEN_BACKLOG: i32 = 1024;
// TCP_BUFFER_BYTES and STREAM_CHUNK_BYTES are imported from
// `phenomenal_io::tuning` — the central source of truth for hot-path
// buffer sizes. See `tuning.rs` for sizing rationale.

pub fn bind_reuseport(addr: SocketAddr) -> std::io::Result<TcpListener> {
    let socket = socket2::Socket::new(
        socket2::Domain::for_address(addr),
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    socket.set_reuse_address(true)?;
    socket.set_reuse_port(true)?;
    socket.set_nonblocking(true)?;
    socket.set_recv_buffer_size(TCP_BUFFER_BYTES)?; // 4 MiB
    socket.set_send_buffer_size(TCP_BUFFER_BYTES)?; // 4 MiB
    socket.set_tcp_nodelay(true)?;
    socket.bind(&addr.into())?;
    socket.listen(LISTEN_BACKLOG)?;
    let std_listener: std::net::TcpListener = socket.into();
    tracing::info!(?addr, recv_buf = TCP_BUFFER_BYTES, send_buf = TCP_BUFFER_BYTES, "rpc listener bound (SO_REUSEPORT)");
    TcpListener::from_std(std_listener)
}

/// Drive the RPC accept loop.
///
/// `disks[i]` is the local `StorageBackend` whose `disk_idx` on the
/// wire equals `i`. The vector's length is this node's
/// `disk_count`; out-of-range `disk_idx` on incoming requests is
/// rejected with `Response::Err` and the connection stays open.
pub async fn serve(
    listener: TcpListener,
    disks:    Rc<Vec<Rc<dyn StorageBackend>>>,
    locks:    Arc<LockServer>,
    tls:      Option<Rc<TlsAcceptor>>,
) -> anyhow::Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        let disks = disks.clone();
        let locks = locks.clone();
        let tls   = tls.clone();
        compio::runtime::spawn(async move {
            match tls {
                Some(acceptor) => match acceptor.accept(stream).await {
                    Ok(tls_stream) => {
                        if let Err(e) = handle_conn(tls_stream, disks, locks).await {
                            tracing::warn!(?peer, "rpc connection ended: {e}");
                        }
                    }
                    Err(e) => tracing::warn!(?peer, "rpc tls handshake failed: {e}"),
                },
                None => {
                    if let Err(e) = handle_conn(stream, disks, locks).await {
                        tracing::warn!(?peer, "rpc connection ended: {e}");
                    }
                }
            }
        }).detach();
    }
}

/// Resolve `disk_idx` against the local disk vector. Returns the
/// backend on success, or an `IoError::InvalidArgument` to surface
/// as `Response::Err` on the wire when the peer references a disk
/// this node doesn't own.
fn disk_at<'a>(
    disks:    &'a [Rc<dyn StorageBackend>],
    disk_idx: DiskIdx,
) -> Result<&'a Rc<dyn StorageBackend>, IoError> {
    disks.get(disk_idx as usize).ok_or_else(|| {
        IoError::InvalidArgument(format!(
            "disk_idx {disk_idx} out of range (this node owns {} disks)",
            disks.len()
        ))
    })
}

async fn handle_conn<S>(
    mut stream: S,
    disks:      Rc<Vec<Rc<dyn StorageBackend>>>,
    locks:      Arc<LockServer>,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        let req_bytes = match rpc::read_frame(&mut stream).await {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e.into()),
        };
        let req: Request = rpc::decode(&req_bytes)?;

        // Streaming variants pump body bytes on the same socket, so they
        // can't go through the envelope-only `dispatch` helper. Handle
        // them here, then loop back to the next request.
        match req {
            Request::CreateFileStream { disk_idx, volume, path, size } => {
                let disk = match disk_at(&disks, disk_idx) {
                    Ok(d) => d.clone(),
                    Err(e) => {
                        // Drain `size` bytes so the peer's framing
                        // stays aligned, then reply with the error.
                        drain_n(&mut stream, size).await?;
                        let resp_bytes = rpc::encode(&Response::Err(e.into()))?;
                        rpc::write_frame(&mut stream, &resp_bytes).await?;
                        continue;
                    }
                };
                handle_create_file_stream(&mut stream, &disk, &volume, &path, size).await?;
            }
            Request::ReadFileStream { disk_idx, volume, path, offset, length } => {
                let disk = match disk_at(&disks, disk_idx) {
                    Ok(d) => d.clone(),
                    Err(e) => {
                        let resp_bytes = rpc::encode(&Response::Err(e.into()))?;
                        rpc::write_frame(&mut stream, &resp_bytes).await?;
                        continue;
                    }
                };
                handle_read_file_stream(&mut stream, &disk, &volume, &path, offset, length).await?;
            }
            other => {
                let resp = dispatch(&disks, &locks, other).await;
                let resp_bytes = rpc::encode(&resp)?;
                rpc::write_frame(&mut stream, &resp_bytes).await?;
            }
        }
    }
}

/// Drain exactly `n` bytes off `stream` and discard them. Used when
/// a streaming PUT references an out-of-range disk: we still need to
/// consume the body so the next request frame lines up.
///
/// Reads directly from the compio `AsyncRead` into a recycled
/// pool-backed buffer; no `LimitedCompioReader` adapter, no
/// source-side memcpy. The kernel writes the bytes; we just
/// overwrite the same buffer each iteration and never look at the
/// contents.
async fn drain_n<S>(stream: &mut S, n: u64) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    use compio::buf::{IntoInner, IoBuf};
    let mut buf = phenomenal_io::PooledBuffer::with_capacity(DRAIN_CHUNK_BYTES); // 64 KiB
    let mut drained = 0u64;
    while drained < n {
        let want = (n - drained).min(DRAIN_CHUNK_BYTES as u64) as usize; // 64 KiB cap
        let slice = buf.slice(0..want);
        let BufResult(res, slice_back) = stream.read(slice).await;
        buf = slice_back.into_inner();
        match res {
            Ok(0)        => break,                  // peer closed mid-body
            Ok(k)        => drained += k as u64,
            Err(_)       => break,                  // connection error — just stop
        }
    }
    Ok(())
}

/// Streaming PUT: open the local writer for `(volume, path, size)`,
/// then pump `size` raw bytes off the socket straight into the writer.
async fn handle_create_file_stream<S>(
    stream: &mut S,
    disk:   &Rc<dyn StorageBackend>,
    volume: &str,
    path:   &str,
    size:   u64,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Open the writer first. If it fails (volume missing, IO error)
    // we still must drain `size` bytes from the socket so the next
    // request frame lines up; or we close the connection. Closing is
    // simpler and safer for malformed states the client retries on
    // its own.
    let result = match disk.create_file_writer(volume, path, size).await {
        Ok(mut sink) => {
            // Direct compio stream to sink pump. Reads bytes off the
            // TCP/TLS connection into the same pool backed
            // buffer that gets handed to `sink.write_all` one fewer
            // memcpy per chunk on the source side. The pump's loop
            // condition (`moved < size`) bounds reads to exactly
            // `size` bytes, keeping the wire framing aligned.
            let pump_res = pump_compio_to_sink(stream, sink.as_mut(), size).await;
            match pump_res {
                Ok(()) => sink.finish().await,
                Err(e) => {
                    // Best-effort finalise so the local backend doesn't
                    // leak partial state — but propagate the original
                    // pump error.
                    let _ = sink.finish().await;
                    Err(e)
                }
            }
        }
        Err(e) => {
            // Couldn't open the writer at all. Drain the body anyway
            // so the connection state stays valid for keepalive, then
            // surface the open error to the client.
            drain_n(stream, size).await?;
            Err(e)
        }
    };

    let resp = match result {
        Ok(())  => Response::Ok,
        Err(e)  => Response::Err(e.into()),
    };
    let resp_bytes = rpc::encode(&resp)?;
    rpc::write_frame(stream, &resp_bytes).await?;
    Ok(())
}

/// Streaming GET: open the local read stream, send the
/// `StreamHeader { length }` frame, then drain the stream straight to
/// the socket. On open failure send the `Err` response and no body.
async fn handle_read_file_stream<S>(
    stream: &mut S,
    disk:   &Rc<dyn StorageBackend>,
    volume: &str,
    path:   &str,
    offset: u64,
    length: u64,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let opened = disk.read_file_stream(volume, path, offset, length).await;
    match opened {
        Ok(mut src) => {
            let hdr = Response::StreamHeader { length };
            rpc::write_frame(stream, &rpc::encode(&hdr)?).await?;

            // Pump the local stream straight to the socket. Each
            // `src.read()` yields a refcounted `Bytes` (no copy at
            // the trait boundary); we hand it to `write_all_bytes`
            // which the kernel writes from the same allocation.
            let mut sent = 0u64;
            while sent < length {
                let chunk = src.read().await?;
                if chunk.is_empty() {
                    return Err(anyhow::anyhow!(
                        "read_file_stream: backend ended at {sent}/{length}"
                    ));
                }
                let n = chunk.len() as u64;
                rpc::write_all_bytes(stream, chunk).await?;
                sent += n;
            }
            // Flush any TLS-buffered records before yielding the conn.
            stream.flush().await?;
        }
        Err(e) => {
            let resp = Response::Err(e.into());
            rpc::write_frame(stream, &rpc::encode(&resp)?).await?;
        }
    }
    Ok(())
}

/// One match arm per envelope-shaped `Request` variant. Streaming
/// variants are handled in-line in `handle_conn` because they consume
/// raw body bytes off the socket between the request header frame and
/// the response frame.
async fn dispatch(
    disks: &[Rc<dyn StorageBackend>],
    locks: &Arc<LockServer>,
    req:   Request,
) -> Response {
    use phenomenal_io::{DeleteOptions, RenameOptions, UpdateMetadataOpts};
    use Request::*;

    // Helper: route a disk-targeted variant through `disk_at` and
    // surface mis-addressed disks as `Response::Err`. We can't use
    // `?` here because the function returns `Response`, not
    // `Result<…, …>` — so each arm explicitly checks before
    // dispatching.
    macro_rules! disk_or_err {
        ($idx:expr) => {
            match disk_at(disks, $idx) {
                Ok(d) => d,
                Err(e) => return Response::Err(e.into()),
            }
        };
    }

    match req {
        DiskInfo { disk_idx } =>
            fold(disk_or_err!(disk_idx).disk_info().await, Response::Disk),

        MakeVol      { disk_idx, volume }                         => fold_unit(disk_or_err!(disk_idx).make_vol(&volume).await),
        StatVol      { disk_idx, volume }                         => fold(disk_or_err!(disk_idx).stat_vol(&volume).await, Response::Vol),
        ListVols     { disk_idx }                                 => fold(disk_or_err!(disk_idx).list_vols().await, Response::Vols),
        DeleteVol    { disk_idx, volume, force_delete }           => fold_unit(disk_or_err!(disk_idx).delete_vol(&volume, force_delete).await),

        ListDir      { disk_idx, volume, dir_path, count }        => fold(disk_or_err!(disk_idx).list_dir(&volume, &dir_path, count as usize).await, Response::Strings),

        // Streaming variants are not dispatched here — `handle_conn`
        // intercepts them before reaching this match. They land in the
        // wildcard arm only if the wire protocol is buggy.
        CreateFileStream { .. } | ReadFileStream { .. } =>
            Response::Err(phenomenal_io::IoError::InvalidArgument(
                "streaming variant routed through envelope dispatch".into()
            ).into()),

        RenameFile   { disk_idx, src_volume, src_path, dst_volume, dst_path } =>
            fold_unit(disk_or_err!(disk_idx).rename_file(&src_volume, &src_path, &dst_volume, &dst_path).await),
        CheckFile    { disk_idx, volume, path }                   => fold_unit(disk_or_err!(disk_idx).check_file(&volume, &path).await),
        Delete       { disk_idx, volume, path, recursive }        => fold_unit(disk_or_err!(disk_idx).delete(&volume, &path, recursive).await),

        WriteMetadata  { disk_idx, orig_volume, volume, path, fi } =>
            fold_unit(disk_or_err!(disk_idx).write_metadata(&orig_volume, &volume, &path, &fi).await),
        UpdateMetadata { disk_idx, volume, path, fi, no_persistence } =>
            fold_unit(disk_or_err!(disk_idx).update_metadata(&volume, &path, &fi, &UpdateMetadataOpts { no_persistence }).await),
        ReadVersion    { disk_idx, orig_volume, volume, path, version_id, read_data } =>
            fold(disk_or_err!(disk_idx).read_version(&orig_volume, &volume, &path, version_id.as_deref(), read_data).await, Response::File),
        DeleteVersion  { disk_idx, volume, path, fi, force_del_marker, undo_write } =>
            fold_unit(disk_or_err!(disk_idx).delete_version(&volume, &path, &fi, force_del_marker,
                &DeleteOptions { force_del_marker, undo_write }).await),
        RenameData     { disk_idx, src_volume, src_path, fi, dst_volume, dst_path } =>
            fold(disk_or_err!(disk_idx).rename_data(&src_volume, &src_path, &fi, &dst_volume, &dst_path,
                &RenameOptions::default()).await, Response::Renamed),
        VerifyFile     { disk_idx, volume, path, fi } =>
            fold_unit(disk_or_err!(disk_idx).verify_file(&volume, &path, &fi).await),

        // Lock plane — node-scoped, no `disk_idx`.
        LockAcquire { resource, uid, ttl_ms } => {
            if locks.acquire(&resource, &uid, Duration::from_millis(ttl_ms as u64)) {
                Response::LockGranted
            } else {
                Response::LockDenied
            }
        }
        LockRelease { resource, uid } => {
            locks.release(&resource, &uid);
            Response::Ok
        }
    }
}

fn fold_unit(r: phenomenal_io::IoResult<()>) -> Response {
    match r { Ok(()) => Response::Ok, Err(e) => Response::Err(e.into()) }
}

fn fold<T>(r: phenomenal_io::IoResult<T>, ok: impl FnOnce(T) -> Response) -> Response {
    match r { Ok(v) => ok(v), Err(e) => Response::Err(e.into()) }
}
