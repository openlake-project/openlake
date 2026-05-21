use compio::bytes::Bytes;
#[cfg(feature = "cookies")]
use cookie_store::RawCookie;
use encoding_rs::{Encoding, UTF_8};
use http::{HeaderMap, StatusCode, Version, header::CONTENT_TYPE};
use http_body_util::BodyExt;
use hyper::body::{Body, Incoming};
use mime::Mime;
use url::Url;

use crate::{ResponseBody, Result};

/// A Response to a submitted `Request`.
#[derive(Debug)]
pub struct Response {
    pub(super) res: hyper::Response<()>,
    pub(crate) body: ResponseBody,
    url: Url,
}

impl Response {
    pub(super) fn new(res: hyper::Response<Incoming>, url: Url) -> Self {
        let (res, body) = res.into_parts();
        let res = hyper::Response::from_parts(res, ());
        Self {
            res,
            body: ResponseBody::Incoming(body),
            url,
        }
    }

    #[cfg(feature = "http3")]
    pub(crate) fn with_body(res: hyper::Response<()>, body: Bytes, url: Url) -> Self {
        Self {
            res,
            body: ResponseBody::Blob(body),
            url,
        }
    }

    /// Get the `StatusCode` of this `Response`.
    #[inline]
    pub fn status(&self) -> StatusCode {
        self.res.status()
    }

    /// Get the HTTP `Version` of this `Response`.
    #[inline]
    pub fn version(&self) -> Version {
        self.res.version()
    }

    /// Get the `Headers` of this `Response`.
    #[inline]
    pub fn headers(&self) -> &HeaderMap {
        self.res.headers()
    }

    /// Get a mutable reference to the `Headers` of this `Response`.
    #[inline]
    pub fn headers_mut(&mut self) -> &mut HeaderMap {
        self.res.headers_mut()
    }

    /// Get the content-length of this response, if known.
    ///
    /// Reasons it may not be known:
    ///
    /// - The server didn't send a `content-length` header.
    /// - The response is compressed and automatically decoded (thus changing
    ///   the actual decoded length).
    pub fn content_length(&self) -> Option<u64> {
        self.body.size_hint().exact()
    }

    /// Get the final `Url` of this `Response`.
    #[inline]
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// Returns a reference to the associated extensions.
    pub fn extensions(&self) -> &http::Extensions {
        self.res.extensions()
    }

    /// Returns a mutable reference to the associated extensions.
    pub fn extensions_mut(&mut self) -> &mut http::Extensions {
        self.res.extensions_mut()
    }

    // body methods

    /// Get the full response text.
    ///
    /// This method decodes the response body with BOM sniffing
    /// and with malformed sequences replaced with the REPLACEMENT CHARACTER.
    /// Encoding is determined from the `charset` parameter of `Content-Type`
    /// header, and defaults to `utf-8` if not presented.
    ///
    /// Note that the BOM is stripped from the returned String.
    ///
    /// # Example
    ///
    /// ```
    /// # async fn run() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = cyper::Client::new();
    /// let content = client
    ///     .get("http://httpbin.org/range/26")?
    ///     .send()
    ///     .await?
    ///     .text()
    ///     .await?;
    ///
    /// println!("text: {:?}", content);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn text(self) -> Result<String> {
        self.text_with_charset("utf-8").await
    }

    /// Get the full response text given a specific encoding.
    ///
    /// This method decodes the response body with BOM sniffing
    /// and with malformed sequences replaced with the REPLACEMENT CHARACTER.
    /// You can provide a default encoding for decoding the raw message, while
    /// the `charset` parameter of `Content-Type` header is still
    /// prioritized. For more information about the possible encoding name,
    /// please go to [`encoding_rs`] docs.
    ///
    /// Note that the BOM is stripped from the returned String.
    ///
    /// [`encoding_rs`]: https://docs.rs/encoding_rs/0.8/encoding_rs/#relationship-with-windows-code-pages
    ///
    /// # Example
    ///
    /// ```
    /// # async fn run() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = cyper::Client::new();
    /// let content = client
    ///     .get("http://httpbin.org/range/26")?
    ///     .send()
    ///     .await?
    ///     .text_with_charset("utf-8")
    ///     .await?;
    ///
    /// println!("text: {:?}", content);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn text_with_charset(self, default_encoding: &str) -> Result<String> {
        let content_type = self
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<Mime>().ok());
        let encoding_name = content_type
            .as_ref()
            .and_then(|mime| mime.get_param("charset").map(|charset| charset.as_str()))
            .unwrap_or(default_encoding);
        let encoding = Encoding::for_label(encoding_name.as_bytes()).unwrap_or(UTF_8);

        let full = self.bytes().await?;

        let (text, ..) = encoding.decode(&full);
        Ok(text.into_owned())
    }

    /// Try to deserialize the response body as JSON.
    ///
    /// # Optional
    ///
    /// This requires the optional `json` feature enabled.
    ///
    /// # Examples
    ///
    /// ```
    /// # extern crate cyper_core;
    /// # extern crate serde;
    /// #
    /// # use cyper::Error;
    /// # use serde::Deserialize;
    /// #
    /// // This `derive` requires the `serde` dependency.
    /// #[derive(Deserialize)]
    /// struct Ip {
    ///     origin: String,
    /// }
    ///
    /// # async fn run() -> Result<(), Error> {
    /// let client = cyper::Client::new();
    /// let ip = client
    ///     .get("http://httpbin.org/ip")?
    ///     .send()
    ///     .await?
    ///     .json::<Ip>()
    ///     .await?;
    ///
    /// println!("ip: {}", ip.origin);
    /// # Ok(())
    /// # }
    /// #
    /// # fn main() { }
    /// ```
    ///
    /// # Errors
    ///
    /// This method fails whenever the response body is not in JSON format
    /// or it cannot be properly deserialized to target type `T`. For more
    /// details please see [`serde_json::from_reader`].
    ///
    /// [`serde_json::from_reader`]: https://docs.serde.rs/serde_json/fn.from_reader.html
    #[cfg(feature = "json")]
    pub async fn json<T: serde::de::DeserializeOwned>(self) -> Result<T> {
        let full = self.bytes().await?;

        Ok(serde_json::from_slice(&full)?)
    }

    /// Retrieve the cookies contained in the response.
    ///
    /// Note that invalid 'Set-Cookie' headers will be ignored.
    #[cfg(feature = "cookies")]
    pub fn cookies(&self) -> impl Iterator<Item = RawCookie<'_>> {
        self.res
            .headers()
            .get_all(http::header::SET_COOKIE)
            .into_iter()
            .filter_map(|val| std::str::from_utf8(val.as_bytes()).ok()?.parse().ok())
    }

    /// Get the full response body as `Bytes`.
    ///
    /// # Example
    ///
    /// ```
    /// # async fn run() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = cyper::Client::new();
    /// let bytes = client
    ///     .get("http://httpbin.org/ip")?
    ///     .send()
    ///     .await?
    ///     .bytes()
    ///     .await?;
    ///
    /// println!("bytes: {:?}", bytes);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn bytes(self) -> Result<Bytes> {
        Ok(self.body.collect().await?.to_bytes())
    }

    /// Convert the response into a [`futures_util::Stream`] of [`Bytes`]
    ///
    /// # Example
    ///
    /// ```
    /// use futures_util::StreamExt;
    ///
    /// # async fn run() -> cyper::Result<()> {
    /// let client = cyper::Client::new();
    /// let mut bytes_stream = client
    ///     .get("http://httpbin.org/stream-bytes/16777216")?
    ///     .send()
    ///     .await?
    ///     .bytes_stream();
    ///
    /// while let Some(bytes) = bytes_stream.next().await {
    ///     let bytes = bytes?;
    ///     println!("Collected {} bytes!", bytes.len());
    /// }
    ///
    /// # Ok(())
    /// # }
    /// ```
    #[inline]
    #[cfg(feature = "stream")]
    pub fn bytes_stream(self) -> impl futures_util::Stream<Item = Result<Bytes>> {
        self.body
    }
}

#[cfg(feature = "stream")]
impl futures_util::Stream for Response {
    type Item = Result<Bytes>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        std::pin::Pin::new(&mut self.body).poll_next(cx)
    }
}
