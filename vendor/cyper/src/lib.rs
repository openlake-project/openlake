//! A high level HTTP client based on compio.

#![warn(missing_docs)]
#![cfg_attr(feature = "once_cell_try", feature(once_cell_try))]
#![cfg_attr(docsrs, feature(doc_cfg))]

mod body;
pub use body::*;

mod client;
pub use client::*;

mod request;
pub use request::*;

mod response;
pub use response::*;

mod into_url;
pub use into_url::*;

mod backend;
pub(crate) use backend::*;

mod connector;
pub(crate) use connector::*;

mod stream;
pub(crate) use stream::*;

/// DNS resolution
pub mod resolve;

mod util;

#[cfg(feature = "http3")]
mod http3;

#[cfg(feature = "http3-altsvc")]
mod altsvc;

#[cfg(feature = "multipart")]
pub mod multipart;

#[cfg(feature = "nyquest")]
pub mod nyquest;

/// The error type used in `cyper`.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The request is timeout.
    #[error("request timeout")]
    Timeout,
    /// No TLS backend.
    #[error("no TLS backend available")]
    NoTlsBackend,
    /// Invalid URL.
    #[error("invalid URL: {0}")]
    InvalidUrl(url::Url),
    /// Bad scheme.
    #[error("bad scheme: {0}")]
    BadScheme(String),
    /// IO error occurs.
    #[error("system error: {0}")]
    System(#[from] std::io::Error),
    /// HTTP related parse error.
    #[error("`http` error: {0}")]
    Http(#[from] http::Error),
    /// Hyper error.
    #[error("`hyper` error: {0}")]
    Hyper(#[from] hyper::Error),
    /// Hyper client error.
    #[error("`hyper` client error: {0}")]
    HyperClient(#[from] hyper_util::client::legacy::Error),
    /// URL parse error.
    #[error("url parse error: {0}")]
    UrlParse(#[from] url::ParseError),
    /// URL encoding error.
    #[error("url encode error: {0}")]
    UrlEncoded(#[from] serde_urlencoded::ser::Error),
    /// JSON serialization error.
    #[cfg(feature = "json")]
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    /// `native-tls` error.
    #[cfg(feature = "native-tls")]
    #[error("`native-tls` error: {0}")]
    NativeTls(#[from] compio::native_tls::Error),
    /// Rustls error.
    #[cfg(any(feature = "http3", feature = "rustls"))]
    #[error("`rustls` error: {0}")]
    Rustls(#[from] compio::rustls::Error),
    /// H3 connection error.
    #[cfg(feature = "http3")]
    #[error("`h3` connection error: {0}")]
    H3Connection(#[from] h3::error::ConnectionError),
    /// H3 stream error.
    #[cfg(feature = "http3")]
    #[error("`h3` stream error: {0}")]
    H3Stream(#[from] h3::error::StreamError),
    /// Custom H3 error.
    #[cfg(feature = "http3")]
    #[error("HTTP3 client error: {0}")]
    H3Client(String),
    /// QUIC [`ConnectError`].
    ///
    /// [`ConnectError`]: compio::quic::ConnectError
    #[cfg(feature = "http3")]
    #[error("QUIC connect error: {0}")]
    QuicConnect(#[from] compio::quic::ConnectError),
    /// QUIC [`ConnectionError`].
    ///
    /// [`ConnectionError`]: compio::quic::ConnectionError
    #[cfg(feature = "http3")]
    #[error("QUIC connection error: {0}")]
    QuicConnection(#[from] compio::quic::ConnectionError),
}

/// The result type used in `cyper`.
pub type Result<T, E = Error> = std::result::Result<T, E>;
