//! `Router` construction and the per-runtime serve helper.
//!
//! The router is rebuilt per runtime so each one carries its own
//! `AppState` (with `Rc<Engine>` / `Rc<AuthState>`). The
//! `cyper_axum::serve` wrapper drives the connection accept loop on
//! the runtime's compio executor.

use std::convert::Infallible;
use std::rc::Rc;

use axum::extract::connect_info::Connected;
use axum::routing::{get, put};
use axum::Router;
use compio::net::TcpListener;
use compio::tls::TlsAcceptor;
use std::net::SocketAddr;

use crate::s3::error::{not_found, AppError};
use crate::s3::handlers::{buckets, objects};
use crate::s3::listener::TlsTcpListener;
use crate::s3::middleware::sigv4::sigv4;
use crate::s3::state::AppState;

/// Build the S3 router for one runtime, with SigV4 verification
/// mounted as a middleware layer over every route.
///
/// Trailing-slash policy: S3 SDKs send bucket-scoped operations as
/// either `/{bucket}` or `/{bucket}/?query` depending on the call.
/// Both shapes route to the same handlers via two registrations
/// here. We deliberately do NOT use `NormalizePathLayer` because
/// stripping trailing slashes uniformly would corrupt object keys
/// that legitimately end with `/` (S3 directory-marker convention).
/// This is the same trailing-slash policy `s3s::path::parse_path_style`
/// implements via explicit split-once matching.
pub fn build_router(state: AppState) -> Router {
    let bucket_routes = put(buckets::put_bucket)
        .delete(buckets::delete_bucket)
        .head(buckets::head_bucket)
        .get(buckets::get_bucket_query)
        .post(objects::delete_objects);

    Router::new()
        // S3 service-root endpoint. The only S3 op defined here is
        // `ListBuckets` (GET /). We don't implement it — return 501
        // explicitly so clients see a clear failure rather than the
        // generic 400 the fallback would return.
        .route("/", get(list_buckets_unimplemented))
        .route("/{bucket}",        bucket_routes.clone())
        .route("/{bucket}/",       bucket_routes)
        .route("/{bucket}/{*key}", get(objects::get_object)
                                   .head(objects::head_object)
                                   .delete(objects::delete_object)
                                   .put(objects::put_object))
        .fallback(not_found)
        .layer(axum::middleware::from_fn_with_state(state.clone(), sigv4))
        .with_state(state)
}

/// Stub handler for `GET /` (ListBuckets). We don't enumerate buckets
/// — bucket discovery is an admin/control-plane concern, not part of
/// the S3 data plane phenomenal targets. Returning 501 with the
/// canonical S3 error shape lets clients distinguish "endpoint
/// reachable but op unsupported" from "wrong path / wrong service".
async fn list_buckets_unimplemented() -> Result<axum::http::Response<axum::body::Body>, AppError> {
    Err(AppError::NotImplemented("ListBuckets is not implemented"))
}

/// Connect-info shim required by `cyper_axum::IncomingStream`.
/// Provided for both the plaintext `TcpListener` and the
/// `TlsTcpListener` so handlers can obtain the peer address via
/// `axum::extract::ConnectInfo<CompioSocketAddr>` when needed.
#[derive(Debug, Clone, Copy)]
pub struct CompioSocketAddr(#[allow(dead_code)] pub SocketAddr);

impl<'a> Connected<cyper_axum::IncomingStream<'a, TcpListener>> for CompioSocketAddr {
    fn connect_info(target: cyper_axum::IncomingStream<'a, TcpListener>) -> Self {
        CompioSocketAddr(*target.remote_addr())
    }
}

impl<'a> Connected<cyper_axum::IncomingStream<'a, TlsTcpListener>> for CompioSocketAddr {
    fn connect_info(target: cyper_axum::IncomingStream<'a, TlsTcpListener>) -> Self {
        CompioSocketAddr(*target.remote_addr())
    }
}

/// Drive the accept loop for one compio runtime. When `tls` is
/// `Some`, every accepted TCP connection is handed to the supplied
/// `TlsAcceptor` for handshake before reaching axum; otherwise the
/// plaintext listener is used directly.
pub async fn serve(
    listener: TcpListener,
    state:    AppState,
    tls:      Option<Rc<TlsAcceptor>>,
) -> Result<(), Infallible> {
    let app = build_router(state);

    match tls {
        None => {
            let service = app.into_make_service_with_connect_info::<CompioSocketAddr>();
            if let Err(err) = cyper_axum::serve(listener, service).await {
                tracing::error!("cyper_axum::serve (plaintext) exited: {err}");
            }
        }
        Some(acceptor) => {
            let acceptor = (*acceptor).clone();
            let tls_listener = TlsTcpListener::new(listener, acceptor);
            let service = app.into_make_service_with_connect_info::<CompioSocketAddr>();
            if let Err(err) = cyper_axum::serve(tls_listener, service).await {
                tracing::error!("cyper_axum::serve (tls) exited: {err}");
            }
        }
    }
    Ok(())
}
