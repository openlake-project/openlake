//! TLS-wrapping listener compatible with `cyper_axum::serve`.
//!
//! `cyper_axum::serve` is generic over its `Listener` trait — accept
//! returns `(Io, Addr)` where `Io: AsyncRead + AsyncWrite + Unpin`.
//! Plaintext uses `compio::net::TcpListener` directly. For HTTPS we
//! wrap a `TcpListener` with a `TlsAcceptor` and run the handshake
//! during `accept()`, returning a `TlsStream<TcpStream>` as the IO
//! channel.
//!
//! Handshake failures are logged at WARN and silently dropped; the
//! accept loop continues so a single misbehaved client never tears
//! down the listener.

use std::io;
use std::net::SocketAddr;

use compio::net::{TcpListener, TcpStream};
use compio::tls::{TlsAcceptor, TlsStream};
use cyper_axum::Listener;
use phenomenal_io::tuning::TCP_BUFFER_BYTES;

const LISTEN_BACKLOG: i32 = 1024;

/// Bind a TCP listener for the S3 plane with `SO_REUSEPORT` so every
/// runtime in the process can bind the same `(ip, port)`. The kernel's
/// reuseport hash routes each incoming connection to exactly one
/// runtime's accept queue based on the 4-tuple.
pub fn bind_reuseport(addr: SocketAddr) -> io::Result<TcpListener> {
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
    tracing::info!(
        ?addr,
        recv_buf = TCP_BUFFER_BYTES,
        send_buf = TCP_BUFFER_BYTES,
        "s3 listener bound (SO_REUSEPORT)"
    );
    TcpListener::from_std(std_listener)
}

/// Listener that completes the TLS handshake before yielding the
/// connection to cyper-axum's HTTP/1.1 driver.
pub struct TlsTcpListener {
    inner:    TcpListener,
    acceptor: TlsAcceptor,
}

impl TlsTcpListener {
    pub fn new(inner: TcpListener, acceptor: TlsAcceptor) -> Self {
        Self { inner, acceptor }
    }
}

impl Listener for TlsTcpListener {
    type Io   = TlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let (tcp, peer) = match self.inner.accept().await {
                Ok(p) => p,
                Err(e) => {
                    if is_connection_drop(&e) {
                        continue;
                    }
                    tracing::warn!(error = %e, "tcp accept failed, sleeping for 10ms");
                    compio::time::sleep(std::time::Duration::from_millis(10)).await;
                    continue;
                }
            };
            match self.acceptor.accept(tcp).await {
                Ok(tls) => return (tls, peer),
                Err(e)  => {
                    tracing::warn!(?peer, error = %e, "tls handshake failed");
                    continue;
                }
            }
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.inner.local_addr()
    }
}

/// Errors that mean "client gave up before the handshake even started"
/// — common with health checkers and load balancers — should not
/// pollute logs at WARN level.
fn is_connection_drop(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::TimedOut
    )
}
