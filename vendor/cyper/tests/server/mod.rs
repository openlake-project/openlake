use std::net::{Ipv4Addr, SocketAddr};

use axum::{extract::Request, handler::HandlerWithoutStateExt};
use compio::net::TcpListener;
use futures_channel::oneshot;

pub struct Server {
    addr: SocketAddr,
    shutdown_tx: Option<oneshot::Sender<()>>,
}

impl Server {
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

pub async fn http<F, M>(func: F) -> Server
where
    F: axum::handler::Handler<(M, Request), ()>,
    M: 'static,
{
    let (shutdown_tx, shutdown_rx) = oneshot::channel();

    let listener = TcpListener::bind(&(Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();

    let srv = async move {
        cyper_axum::serve(listener, func.into_service())
            .with_graceful_shutdown(async move {
                shutdown_rx.await.ok();
            })
            .await
            .unwrap()
    };

    compio::runtime::spawn(srv).detach();

    Server {
        addr,
        shutdown_tx: Some(shutdown_tx),
    }
}
