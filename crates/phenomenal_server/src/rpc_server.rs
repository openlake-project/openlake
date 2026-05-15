//! Peer-to-peer RPC server. Routes incoming HTTP/2 requests from
//! other nodes' `RemoteBackend` clients to one of this node's local
//! `StorageBackend` instances — selected by the `disk_idx` field on
//! every disk-targeted request variant.
//!
//! Three axum routes carry the entire RPC surface:
//!
//!   * `POST /v1/rpc` — unary. Body is a bincode-encoded `Request`;
//!     reply body is a bincode-encoded `Response`. Used by 20 of the
//!     22 `StorageBackend` methods plus the two lock RPCs.
//!   * `PUT  /v1/rpc/stream-write` — `create_file_writer`. The
//!     bincode-encoded `Request::CreateFileStream` envelope rides in
//!     the `x-phenomenal-rpc` URL-safe-base64 header; the request
//!     body is the streamed object bytes, pumped frame-by-frame into
//!     the local disk's `ByteSink`.
//!   * `POST /v1/rpc/stream-read` — `read_file_stream`. The
//!     bincode-encoded `Request::ReadFileStream` envelope rides in
//!     the request body; on success the response body is the file
//!     bytes (length echoed in `x-phenomenal-length`).
//!
//! Listener is bound with `SO_REUSEPORT` so every runtime in the
//! process binds the same port; the kernel spreads inbound RPC
//! connections across runtimes via 4-tuple hash. Multi-disk
//! dispatch is independent of the listener: a single h2 connection
//! from a peer carries streams for multiple disks (each request
//! carries its own `disk_idx`).
//!
//! TLS: when `tls` is `Some` the listener is wrapped with the
//! cluster's `TlsAcceptor` (ALPN h2-only). When `tls` is `None`
//! (single-node deployments only — config validation rejects
//! plaintext multi-node clusters) cyper-axum's auto h1+h2 builder
//! still terminates incoming streams correctly.

use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{post, put};
use axum::Router;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bytes::Bytes;
use compio::net::TcpListener;
use compio::tls::TlsAcceptor;
use futures::stream;
use http_body_util::BodyExt;
use send_wrapper::SendWrapper;

use phenomenal_io::rpc::{self, DiskIdx, Request, Response as RpcResponse};
use phenomenal_io::stream::{ByteSink, ByteStream};
use phenomenal_io::tuning::TCP_BUFFER_BYTES;
use phenomenal_io::{IoError, IoResult, StorageBackend};

use crate::lock_server::LockServer;
use crate::s3::listener::TlsTcpListener;

const LISTEN_BACKLOG: i32 = 1024;

/// Per-call upper bound on a unary RPC body. Sized for the largest
/// legitimate `FileInfo` blob (xl.meta plus inline data) and well
/// below any per-stream resource we'd care about. A peer that
/// declares more than this fails with `PAYLOAD_TOO_LARGE`; this
/// replaces the old `MAX_FRAME` ceiling that the framed protocol
/// enforced.
const UNARY_BODY_LIMIT: usize = 8 * 1024 * 1024;

/// Maximum size of the bincode `Request::ReadFileStream` envelope on
/// the streaming-read route. Smaller cap than unary because the
/// envelope holds only `(volume, path, offset, length)` plus the
/// disk index — KiB-class at most.
const STREAM_REQ_LIMIT: usize = 64 * 1024;

/// Header carrying the URL-safe-base64 bincode-encoded `Request`
/// envelope on the streaming-write route. Mirror of
/// `phenomenal_io::remote_fs`'s `HDR_RPC`.
const HDR_RPC: &str = "x-phenomenal-rpc";
/// Response header echoing the streaming GET length so the client
/// can sanity-check the byte stream before consuming it.
const HDR_LEN: &str = "x-phenomenal-length";

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

// -----------------------------------------------------------------------------
// Per-runtime application state.
//
// Identical justification to `s3::state::AppState`: each compio
// runtime is pinned to one OS thread, cyper-axum spawns every
// per-connection task on that runtime via `CompioExecutor`, so the
// `Rc`s never cross thread boundaries even though axum's `State<S>`
// trait bound demands `Send + Sync`.
// -----------------------------------------------------------------------------

#[derive(Clone)]
pub struct RpcAppState {
    inner: Rc<RpcAppStateInner>,
}

struct RpcAppStateInner {
    disks: Vec<Rc<dyn StorageBackend>>,
    locks: Arc<LockServer>,
}

// SAFETY: every `RpcAppState` clone stays on the runtime that
// created it. Single-thread runtime confines the `Rc`.
unsafe impl Send for RpcAppState {}
unsafe impl Sync for RpcAppState {}

impl RpcAppState {
    fn new(disks: Vec<Rc<dyn StorageBackend>>, locks: Arc<LockServer>) -> Self {
        Self { inner: Rc::new(RpcAppStateInner { disks, locks }) }
    }
    fn disks(&self) -> &[Rc<dyn StorageBackend>] { &self.inner.disks }
    fn locks(&self) -> &Arc<LockServer> { &self.inner.locks }
}

// -----------------------------------------------------------------------------
// Public entry — `serve(listener, disks, locks, tls)`.
// -----------------------------------------------------------------------------

pub async fn serve(
    listener: TcpListener,
    disks:    Rc<Vec<Rc<dyn StorageBackend>>>,
    locks:    Arc<LockServer>,
    tls:      Option<Rc<TlsAcceptor>>,
) -> anyhow::Result<()> {
    let state = RpcAppState::new(disks.iter().cloned().collect(), locks);
    let app: Router = Router::new()
        .route("/v1/rpc",              post(handle_unary))
        .route("/v1/rpc/stream-write", put (handle_stream_write))
        .route("/v1/rpc/stream-read",  post(handle_stream_read))
        .with_state(state);

    match tls {
        // Single-node deployments may run plaintext (config
        // validation accepts that case because no peer ever dials
        // this listener). cyper-axum's auto h1+h2 builder accepts
        // either side here.
        None => {
            cyper_axum::serve(listener, app).await
                .map_err(|e| anyhow::anyhow!("rpc serve (plaintext) exited: {e}"))?;
        }
        // Multi-node deployments are TLS-only. ALPN advertises only
        // `h2` (set in `tls_material`), so the handshake terminates
        // a peer that can't speak h2 — there is no h1 fallback on
        // the wire.
        Some(acceptor) => {
            let tls_listener = TlsTcpListener::new(listener, (*acceptor).clone());
            cyper_axum::serve(tls_listener, app).await
                .map_err(|e| anyhow::anyhow!("rpc serve (tls) exited: {e}"))?;
        }
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// Routing handlers.
// -----------------------------------------------------------------------------

/// `POST /v1/rpc` — unary RPCs.
///
/// Body extraction runs first (Send-friendly: the axum `Body` future
/// is Send). The dispatch step holds a borrow into `state.disks()`
/// (`&[Rc<dyn StorageBackend>]` — `!Send` because `Rc` is `!Send`)
/// across an `.await`, so the dispatch future is wrapped in
/// `SendWrapper` to satisfy axum's `Handler` bound. Sound at runtime
/// for the same reason `s3::state::AppState` is sound: every compio
/// runtime is pinned to one OS thread, so the wrapper's panic-on-
/// foreign-thread guard never fires.
async fn handle_unary(
    State(state): State<RpcAppState>,
    body:         Body,
) -> Response {
    let bytes = match axum::body::to_bytes(body, UNARY_BODY_LIMIT).await {
        Ok(b)  => b,
        Err(e) => return error_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            IoError::Io(std::io::Error::other(e.to_string())),
        ),
    };
    let req: Request = match rpc::decode(&bytes) {
        Ok(r)  => r,
        Err(e) => return error_response(StatusCode::BAD_REQUEST, e),
    };
    if matches!(req,
        Request::CreateFileStream { .. } | Request::ReadFileStream { .. }
    ) {
        return error_response(
            StatusCode::BAD_REQUEST,
            IoError::InvalidArgument("streaming variant routed to /v1/rpc".into()),
        );
    }
    let resp = SendWrapper::new(async move {
        dispatch(state.disks(), state.locks(), req).await
    }).await;
    let body_bytes = rpc::encode(&resp).unwrap_or_default();
    rpc_ok(body_bytes)
}

/// `PUT /v1/rpc/stream-write` — streaming PUT.
async fn handle_stream_write(
    State(state): State<RpcAppState>,
    headers:      HeaderMap,
    body:         Body,
) -> Response {
    // 1. Decode the bincode `Request::CreateFileStream` envelope
    //    out of the URL-safe-base64 header.
    let env_b64 = match headers.get(HDR_RPC).and_then(|v| v.to_str().ok()) {
        Some(s) => s,
        None    => return error_response(
            StatusCode::BAD_REQUEST,
            IoError::InvalidArgument(format!("missing {HDR_RPC} header")),
        ),
    };
    let env_bytes = match URL_SAFE_NO_PAD.decode(env_b64) {
        Ok(v)  => v,
        Err(e) => return error_response(
            StatusCode::BAD_REQUEST,
            IoError::InvalidArgument(format!("decode {HDR_RPC}: {e}")),
        ),
    };
    let req: Request = match rpc::decode(&env_bytes) {
        Ok(r)  => r,
        Err(e) => return error_response(StatusCode::BAD_REQUEST, e),
    };
    let (disk_idx, volume, path, size) = match req {
        Request::CreateFileStream { disk_idx, volume, path, size } =>
            (disk_idx, volume, path, size),
        _ => return error_response(
            StatusCode::BAD_REQUEST,
            IoError::InvalidArgument("expected CreateFileStream envelope".into()),
        ),
    };

    // 2. Resolve disk, open the writer, and pump body frames in.
    //    All three steps live inside a `SendWrapper` because they
    //    touch `Rc<dyn StorageBackend>` and the local `ByteSink`,
    //    both `!Send`. Same single-thread-runtime soundness story
    //    as `handle_unary` and `s3::state::AppState`.
    SendWrapper::new(async move {
        let disk = match disk_at(state.disks(), disk_idx) {
            Ok(d)  => d.clone(),
            Err(e) => return error_response(StatusCode::BAD_REQUEST, e),
        };
        let mut sink = match disk.create_file_writer(&volume, &path, size).await {
            Ok(s)  => s,
            Err(e) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, e),
        };
        // Always finalise even on pump failure so the local backend
        // doesn't leak partial state, but propagate the pump error
        // if the body was short.
        let pump_result   = pump_body_into_sink(body, sink.as_mut(), size).await;
        let finish_result = sink.finish().await;
        match (pump_result, finish_result) {
            (Ok(()), Ok(())) => rpc_ok(rpc::encode(&RpcResponse::Ok).unwrap_or_default()),
            (Err(e), _)      => error_response(StatusCode::INTERNAL_SERVER_ERROR, e),
            (Ok(()), Err(e)) => error_response(StatusCode::INTERNAL_SERVER_ERROR, e),
        }
    }).await
}

/// `POST /v1/rpc/stream-read` — streaming GET.
async fn handle_stream_read(
    State(state): State<RpcAppState>,
    body:         Body,
) -> Response {
    let bytes = match axum::body::to_bytes(body, STREAM_REQ_LIMIT).await {
        Ok(b)  => b,
        Err(e) => return error_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            IoError::Io(std::io::Error::other(e.to_string())),
        ),
    };
    let req: Request = match rpc::decode(&bytes) {
        Ok(r)  => r,
        Err(e) => return error_response(StatusCode::BAD_REQUEST, e),
    };
    let (disk_idx, volume, path, offset, length) = match req {
        Request::ReadFileStream { disk_idx, volume, path, offset, length } =>
            (disk_idx, volume, path, offset, length),
        _ => return error_response(
            StatusCode::BAD_REQUEST,
            IoError::InvalidArgument("expected ReadFileStream envelope".into()),
        ),
    };

    // Disk lookup + opening the read stream both touch `Rc<dyn
    // StorageBackend>`, so we run them inside a `SendWrapper`. The
    // returned response value is plain `Response` (Send), so the
    // outer handler future stays Send.
    SendWrapper::new(async move {
        let disk = match disk_at(state.disks(), disk_idx) {
            Ok(d)  => d.clone(),
            Err(e) => return error_response(StatusCode::BAD_REQUEST, e),
        };
        let byte_stream: Box<dyn ByteStream> = match disk
            .read_file_stream(&volume, &path, offset, length).await
        {
            Ok(s)  => s,
            Err(e) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, e),
        };

        // Build the response body as an axum streaming body. Same
        // SendWrapper-around-unfold pattern as
        // `s3::handlers::objects::stream_object_response`: axum's
        // `Body::from_stream` requires `Send + 'static`, but the
        // underlying `ByteStream` and the unfolded state are `!Send`
        // (they hold compio runtime-local handles). The wrapper
        // panics on cross-thread access — which never happens since
        // every compio runtime is pinned to one CPU.
        let frames = SendWrapper::new(stream::unfold(
            (byte_stream, length, 0u64),
            move |(mut s, total, mut sent)| async move {
                if sent >= total { return None; }
                match s.read().await {
                    Ok(b) if b.is_empty() => None,
                    Ok(b) => {
                        let take = (total - sent).min(b.len() as u64) as usize;
                        let frame = if take < b.len() { b.slice(..take) } else { b };
                        sent += frame.len() as u64;
                        Some((Ok::<Bytes, std::io::Error>(frame), (s, total, sent)))
                    }
                    Err(e) => Some((
                        Err(std::io::Error::other(e.to_string())),
                        (s, total, sent),
                    )),
                }
            },
        ));

        let body = Body::from_stream(frames);
        let mut headers = HeaderMap::new();
        headers.insert(axum::http::header::CONTENT_LENGTH, HeaderValue::from(length));
        headers.insert(HDR_LEN, HeaderValue::from(length));
        (StatusCode::OK, headers, body).into_response()
    }).await
}

// -----------------------------------------------------------------------------
// Body pumping for streaming PUT.
// -----------------------------------------------------------------------------

/// Pull frames off the axum `Body` and hand them to the local sink
/// until exactly `expected` bytes have been delivered. Trailers and
/// empty data frames are skipped. A frame that overshoots `expected`
/// is sliced down to fit so we never write more bytes than the
/// envelope declared.
async fn pump_body_into_sink(
    mut body:  Body,
    sink:      &mut dyn ByteSink,
    expected:  u64,
) -> IoResult<()> {
    let mut moved = 0u64;
    while moved < expected {
        match body.frame().await {
            None => break,
            Some(Ok(frame)) => {
                if let Ok(data) = frame.into_data() {
                    if data.is_empty() { continue; }
                    let take = (expected - moved).min(data.len() as u64) as usize;
                    let chunk = if take < data.len() {
                        data.slice(..take)
                    } else {
                        data
                    };
                    let n = chunk.len() as u64;
                    sink.write_all(chunk).await?;
                    moved += n;
                }
                // Trailers frame: ignore and pull next.
            }
            Some(Err(e)) => return Err(IoError::Io(std::io::Error::other(e.to_string()))),
        }
    }
    if moved < expected {
        return Err(IoError::Io(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            format!("stream-write body ended at {moved}/{expected}"),
        )));
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// Response builders.
// -----------------------------------------------------------------------------

fn rpc_ok(body: Vec<u8>) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(axum::http::header::CONTENT_TYPE, "application/octet-stream")
        .body(Body::from(body))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

fn error_response(status: StatusCode, e: IoError) -> Response {
    let body = rpc::encode(&RpcResponse::Err(e.into())).unwrap_or_default();
    Response::builder()
        .status(status)
        .header(axum::http::header::CONTENT_TYPE, "application/octet-stream")
        .body(Body::from(body))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

// -----------------------------------------------------------------------------
// Disk lookup + unary dispatch (unchanged from the legacy server —
// the wire transport changed but the request → backend mapping is
// identical).
// -----------------------------------------------------------------------------

/// Resolve `disk_idx` against the local disk vector. Returns the
/// backend on success, or an `IoError::InvalidArgument` to surface
/// in the response body when the peer references a disk this node
/// doesn't own.
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

/// One match arm per envelope-shaped `Request` variant. Streaming
/// variants are handled by their dedicated routes (and rejected
/// here as a wire-protocol bug).
async fn dispatch(
    disks: &[Rc<dyn StorageBackend>],
    locks: &Arc<LockServer>,
    req:   Request,
) -> RpcResponse {
    use phenomenal_io::{DeleteOptions, RenameOptions, UpdateMetadataOpts};
    use Request::*;

    macro_rules! disk_or_err {
        ($idx:expr) => {
            match disk_at(disks, $idx) {
                Ok(d)  => d,
                Err(e) => return RpcResponse::Err(e.into()),
            }
        };
    }

    match req {
        DiskInfo { disk_idx } =>
            fold(disk_or_err!(disk_idx).disk_info().await, RpcResponse::Disk),

        MakeVol      { disk_idx, volume }                         => fold_unit(disk_or_err!(disk_idx).make_vol(&volume).await),
        StatVol      { disk_idx, volume }                         => fold(disk_or_err!(disk_idx).stat_vol(&volume).await, RpcResponse::Vol),
        ListVols     { disk_idx }                                 => fold(disk_or_err!(disk_idx).list_vols().await, RpcResponse::Vols),
        DeleteVol    { disk_idx, volume, force_delete }           => fold_unit(disk_or_err!(disk_idx).delete_vol(&volume, force_delete).await),

        ListDir      { disk_idx, volume, dir_path, count }        => fold(disk_or_err!(disk_idx).list_dir(&volume, &dir_path, count as usize).await, RpcResponse::Strings),

        // Streaming variants land on dedicated routes; if one
        // arrives here the client is misrouting and we surface a
        // clear error rather than silently doing nothing.
        CreateFileStream { .. } | ReadFileStream { .. } =>
            RpcResponse::Err(IoError::InvalidArgument(
                "streaming variant routed through unary dispatch".into()
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
            fold(disk_or_err!(disk_idx).read_version(&orig_volume, &volume, &path, version_id.as_deref(), read_data).await, RpcResponse::File),
        DeleteVersion  { disk_idx, volume, path, fi, force_del_marker, undo_write } =>
            fold_unit(disk_or_err!(disk_idx).delete_version(&volume, &path, &fi, force_del_marker,
                &DeleteOptions { force_del_marker, undo_write }).await),
        RenameData     { disk_idx, src_volume, src_path, fi, dst_volume, dst_path } =>
            fold(disk_or_err!(disk_idx).rename_data(&src_volume, &src_path, &fi, &dst_volume, &dst_path,
                &RenameOptions::default()).await, RpcResponse::Renamed),
        VerifyFile     { disk_idx, volume, path, fi } =>
            fold_unit(disk_or_err!(disk_idx).verify_file(&volume, &path, &fi).await),

        ReadFormat     { disk_idx } =>
            match disk_or_err!(disk_idx).read_format().await {
                Ok(opt) => RpcResponse::FormatOpt(opt),
                Err(e)  => RpcResponse::Err(e.into()),
            },
        WriteFormat    { disk_idx, fmt } =>
            fold_unit(disk_or_err!(disk_idx).write_format(&fmt).await),

        WriteFile      { disk_idx, volume, path, bytes } =>
            fold_unit(disk_or_err!(disk_idx).write_file(&volume, &path, bytes).await),
        ReadFile       { disk_idx, volume, path } =>
            match disk_or_err!(disk_idx).read_file(&volume, &path).await {
                Ok(opt) => RpcResponse::FileBytes(opt),
                Err(e)  => RpcResponse::Err(e.into()),
            },
        MakeDirAll     { disk_idx, volume, path } =>
            fold_unit(disk_or_err!(disk_idx).make_dir_all(&volume, &path).await),

        // Lock plane — node-scoped, no `disk_idx`.
        LockAcquire { resource, uid, ttl_ms } => {
            if locks.acquire(&resource, &uid, Duration::from_millis(ttl_ms as u64)) {
                RpcResponse::LockGranted
            } else {
                RpcResponse::LockDenied
            }
        }
        LockRelease { resource, uid } => {
            locks.release(&resource, &uid);
            RpcResponse::Ok
        }
    }
}

fn fold_unit(r: IoResult<()>) -> RpcResponse {
    match r { Ok(()) => RpcResponse::Ok, Err(e) => RpcResponse::Err(e.into()) }
}

fn fold<T>(r: IoResult<T>, ok: impl FnOnce(T) -> RpcResponse) -> RpcResponse {
    match r { Ok(v) => ok(v), Err(e) => RpcResponse::Err(e.into()) }
}
