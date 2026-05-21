use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};

use compio::{net::TcpStream, tls::MaybeTlsStream};
use cyper_core::HyperStream;
use futures_util::StreamExt;
use hyper::Uri;
use hyper_util::client::legacy::connect::{Connected, Connection};

use crate::{Error, Result, TlsBackend, resolve::ArcResolver};

/// A HTTP stream wrapper, based on compio, and exposes [`hyper::rt`]
/// interfaces.
pub struct HttpStream(HyperStream<MaybeTlsStream<TcpStream>>);

impl HttpStream {
    /// Create [`HttpStream`] with target uri and TLS backend.
    pub async fn connect(uri: Uri, tls: TlsBackend, resolver: Option<ArcResolver>) -> Result<Self> {
        let scheme = uri.scheme_str().unwrap_or("http");
        let host = uri.host().expect("there should be host");
        // `Uri::host()` includes brackets for IPv6, we must strip them.
        let host = host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(host);
        let port = uri.port_u16();
        let stream = match scheme {
            "http" => {
                let port = port.unwrap_or(80);
                let stream = Self::connect_tcp(&uri, host, port, resolver).await?;
                // Ignore it.
                let _tls = tls;
                MaybeTlsStream::new_plain(stream)
            }
            #[cfg(any(feature = "native-tls", feature = "rustls"))]
            "https" => {
                let port = port.unwrap_or(443);
                let stream = Self::connect_tcp(&uri, host, port, resolver).await?;
                let connector = tls.create_connector()?;
                MaybeTlsStream::new_tls(connector.connect(host, stream).await?)
            }
            _ => return Err(Error::BadScheme(scheme.to_string())),
        };
        Ok(Self(HyperStream::new(stream)))
    }

    async fn connect_tcp(
        uri: &Uri,
        host: &str,
        port: u16,
        resolver: Option<ArcResolver>,
    ) -> Result<TcpStream> {
        let stream = match resolver {
            None => TcpStream::connect((host, port)).await?,

            Some(resolver) => {
                let addrs = resolver
                    .resolve(uri)
                    .await?
                    .map(|ip| SocketAddr::new(ip, port))
                    .collect::<Vec<_>>()
                    .await;

                TcpStream::connect(addrs.as_slice()).await?
            }
        };

        Ok(stream)
    }
}

impl hyper::rt::Read for HttpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        let inner = std::pin::pin!(&mut self.0);
        inner.poll_read(cx, buf)
    }
}

impl hyper::rt::Write for HttpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let inner = std::pin::pin!(&mut self.0);
        inner.poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let inner = std::pin::pin!(&mut self.0);
        inner.poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let inner = std::pin::pin!(&mut self.0);
        inner.poll_shutdown(cx)
    }
}

impl Connection for HttpStream {
    fn connected(&self) -> Connected {
        let conn = Connected::new();
        let is_h2 = self
            .0
            .get_ref()
            .negotiated_alpn()
            .map(|alpn| *alpn == *b"h2")
            .unwrap_or_default();
        if is_h2 { conn.negotiated_h2() } else { conn }
    }
}
