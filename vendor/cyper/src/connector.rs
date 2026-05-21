use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use hyper::Uri;
use send_wrapper::SendWrapper;
use tower_service::Service;

use crate::{HttpStream, TlsBackend, resolve::ArcResolver};

/// An HTTP connector service.
///
/// It panics when called in a different thread other than the thread creates
/// it.
#[derive(Debug, Clone)]
pub struct Connector {
    tls: TlsBackend,
    resolver: Option<ArcResolver>,
}

impl Connector {
    /// Creates the connector with specific TLS backend.
    pub fn new(tls: TlsBackend, resolver: Option<ArcResolver>) -> Self {
        Self { tls, resolver }
    }
}

impl Service<Uri> for Connector {
    type Error = crate::Error;
    type Future = Pin<Box<dyn Future<Output = crate::Result<Self::Response>> + Send>>;
    type Response = HttpStream;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Uri) -> Self::Future {
        Box::pin(SendWrapper::new(HttpStream::connect(
            req,
            self.tls.clone(),
            self.resolver.clone(),
        )))
    }
}
