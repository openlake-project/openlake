//! `Router` construction and the per-runtime serve helper.
//!
//! The router is rebuilt per runtime so each one carries its own
//! `AppState` (with `Rc<Engine>` / `Rc<AuthState>`). The
//! `cyper_axum::serve` wrapper drives the connection accept loop on
//! the runtime's compio executor.

use std::convert::Infallible;
use std::rc::Rc;
use std::sync::Arc;

use axum::extract::connect_info::Connected;
use axum::routing::{get, put};
use axum::Router;
use compio::net::TcpListener;
use compio::tls::TlsAcceptor;
use std::net::SocketAddr;

use crate::config::Config;
use crate::s3::error::{not_found, AppError};
use crate::s3::handlers::{buckets, objects};
use crate::s3::listener::TlsTcpListener;
use crate::s3::middleware::sigv4::sigv4;
use crate::s3::state::AppState;

pub fn build_router(state: AppState, cfg: Arc<Config>) -> Router {
    let admin_cfg = cfg.clone();
    let bucket_routes = put(buckets::put_bucket)
        .delete(buckets::delete_bucket)
        .head(buckets::head_bucket)
        .get(buckets::get_bucket_query)
        .post(objects::delete_objects);

    Router::new()
        .route("/", get(list_buckets_unimplemented))
        .route("/openlake/admin/v1/config", get(move || {
            let cfg = admin_cfg.clone();
            async move { serve_admin_config(cfg).await }
        }))
        .route("/{bucket}",        bucket_routes.clone())
        .route("/{bucket}/",       bucket_routes)
        .route("/{bucket}/{*key}", get(objects::get_object)
                                   .head(objects::head_object)
                                   .delete(objects::delete_object)
                                   .put(objects::put_object)
                                   .post(objects::post_object))
        .fallback(not_found)
        .layer(axum::middleware::from_fn_with_state(state.clone(), sigv4))
        .with_state(state)
}

async fn list_buckets_unimplemented() -> Result<axum::http::Response<axum::body::Body>, AppError> {
    Err(AppError::NotImplemented("ListBuckets is not implemented"))
}

async fn serve_admin_config(cfg: Arc<Config>) -> axum::Json<Config> {
    let mut c = (*cfg).clone();
    c.self_id = 0;
    if let Some(r) = c.rdma.as_mut() { r.self_node_id = 0; }
    for cr in &mut c.credentials { cr.secret_key = "***".into(); }
    axum::Json(c)
}

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

pub async fn serve(
    listener: TcpListener,
    state:    AppState,
    tls:      Option<Rc<TlsAcceptor>>,
    cfg:      Arc<Config>,
) -> Result<(), Infallible> {
    let app = build_router(state, cfg);

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
