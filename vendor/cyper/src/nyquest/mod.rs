//! Adapters for [`nyquest_interface`].
//!
//! This support is experimental. Not all features are implemented.
//! It might break regardless of semver in future releases.

use std::{borrow::Cow, time::Duration};

use http::{HeaderMap, HeaderName, HeaderValue};
use http_body_util::BodyExt;
#[cfg(feature = "nyquest-multipart")]
use nyquest_interface::PartBody as NyquestPartBody;
use nyquest_interface::{
    Body as NyquestBody, Error as NyquestError, Request, Result, client::ClientOptions,
};
use send_wrapper::SendWrapper;
use url::Url;

/// Register `cyper` as a backend for [`nyquest_interface`].
pub fn register() {
    nyquest_interface::register_backend(CyperBackend);
}

#[cfg(feature = "nyquest-async")]
mod r#async;

#[cfg(feature = "nyquest-blocking")]
mod blocking;

/// An implementation of nyquest backend.
///
/// ## Missing features
/// * `caching_behavior`
/// * `use_default_proxy`: error on use
/// * `follow_redirects`: error on use
pub struct CyperBackend;

impl CyperBackend {
    pub(crate) fn create_client(&self, options: ClientOptions) -> Result<CyperClient> {
        if options.use_default_proxy {
            return Err(NyquestError::Io(std::io::Error::other(
                "cyper nyquest backend does not support use_default_proxy option",
            )));
        }
        if options.follow_redirects {
            return Err(NyquestError::Io(std::io::Error::other(
                "cyper nyquest backend does not support follow_redirects option",
            )));
        }
        let builder = crate::ClientBuilder::new().default_headers({
            let mut headers = HeaderMap::new();
            for (k, v) in options.default_headers {
                headers.insert(convert_header_name(k)?, convert_header_value(v)?);
            }
            headers
        });
        #[cfg(feature = "cookies")]
        let builder = builder.cookie_store(options.use_cookies);
        let builder = if options.ignore_certificate_errors {
            builder.danger_accept_invalid_certs(true)
        } else {
            builder
        };
        let client = builder.build();
        let base_url = if let Some(url) = options.base_url {
            Some(Url::parse(&url).map_err(|_| NyquestError::InvalidUrl)?)
        } else {
            None
        };
        Ok(CyperClient {
            client,
            base_url,
            user_agent: if let Some(v) = options.user_agent {
                Some(convert_header_value(v)?)
            } else {
                None
            },
            timeout: options.request_timeout,
            max_buffer_size: options.max_response_buffer_size,
        })
    }
}

#[doc(hidden)]
#[derive(Clone)]
pub struct CyperClient {
    client: crate::Client,
    user_agent: Option<HeaderValue>,
    base_url: Option<Url>,
    timeout: Option<Duration>,
    max_buffer_size: Option<u64>,
}

impl CyperClient {
    pub(crate) async fn request<
        #[cfg(any(feature = "nyquest-async-stream", feature = "nyquest-blocking-stream"))] S: futures_util::Stream<Item = crate::Result<compio::bytes::Bytes>> + Send + 'static,
        #[cfg(not(any(feature = "nyquest-async-stream", feature = "nyquest-blocking-stream")))] S,
    >(
        &self,
        req: Request<S>,
    ) -> Result<CyperResponse> {
        let fut = async {
            let method = match req.method {
                nyquest_interface::Method::Delete => http::Method::DELETE,
                nyquest_interface::Method::Get => http::Method::GET,
                nyquest_interface::Method::Head => http::Method::HEAD,
                nyquest_interface::Method::Patch => http::Method::PATCH,
                nyquest_interface::Method::Post => http::Method::POST,
                nyquest_interface::Method::Put => http::Method::PUT,
                nyquest_interface::Method::Other(s) => http::Method::from_bytes(s.as_bytes())
                    .map_err(|e| NyquestError::Io(std::io::Error::other(e)))?,
            };
            let url = match self.base_url.as_ref() {
                Some(base) => base.join(&req.relative_uri),
                None => Url::parse(&req.relative_uri),
            }
            .map_err(|_| NyquestError::InvalidUrl)?;
            let builder = self.client.request(method, url)?.headers({
                let mut headers = HeaderMap::new();
                for (k, v) in req.additional_headers {
                    headers.insert(convert_header_name(k)?, convert_header_value(v)?);
                }
                headers
            });
            let (body, content_type) = match req.body {
                Some(body) => match body {
                    NyquestBody::Bytes {
                        content,
                        content_type,
                    } => (
                        crate::body::Body::from(content.into_owned()),
                        Some(content_type),
                    ),
                    #[cfg(any(
                        feature = "nyquest-async-stream",
                        feature = "nyquest-blocking-stream"
                    ))]
                    NyquestBody::Stream {
                        stream,
                        content_type,
                    } => (crate::body::Body::stream(stream), Some(content_type)),
                    #[cfg(not(any(
                        feature = "nyquest-async-stream",
                        feature = "nyquest-blocking-stream"
                    )))]
                    NyquestBody::Stream { .. } => {
                        unreachable!("stream body is not supported without stream feature")
                    }
                    NyquestBody::Form { fields } => {
                        let body = serde_urlencoded::to_string(fields)
                            .map_err(|e| NyquestError::Io(std::io::Error::other(e)))?
                            .into_bytes();
                        (
                            crate::body::Body::from(body),
                            Some("application/x-www-form-urlencoded".into()),
                        )
                    }
                    #[cfg(feature = "nyquest-multipart")]
                    NyquestBody::Multipart { parts } => {
                        let mut form = crate::multipart::Form::new();
                        for part in parts {
                            use std::iter;

                            let headers = part
                                .headers
                                .into_iter()
                                .map(|(k, v)| {
                                    let value = convert_header_value(v)?;
                                    Ok((convert_header_name(k)?, value))
                                })
                                .chain(iter::once(Ok((
                                    http::header::CONTENT_TYPE,
                                    convert_header_value(part.content_type)?,
                                ))))
                                .collect::<Result<HeaderMap>>()?;

                            match part.body {
                                NyquestPartBody::Bytes { content } => {
                                    let mut part_builder = crate::multipart::Part::bytes(content);
                                    if let Some(filename) = part.filename {
                                        part_builder = part_builder.file_name(filename);
                                    }
                                    form = form.part(part.name, part_builder.headers(headers));
                                }
                                NyquestPartBody::Stream(stream) => {
                                    let mut part_builder =
                                        crate::multipart::Part::stream(crate::Body::stream(stream));
                                    if let Some(filename) = part.filename {
                                        part_builder = part_builder.file_name(filename);
                                    }
                                    form = form.part(part.name, part_builder.headers(headers));
                                }
                            }
                        }
                        (form.stream(), None)
                    }
                },
                None => (crate::body::Body::empty(), None),
            };
            let builder = builder.body(body);
            let builder = if let Some(content_type) = content_type {
                builder.header(
                    http::header::CONTENT_TYPE,
                    convert_header_value(content_type)?,
                )?
            } else {
                builder
            };
            let builder = if let Some(user_agent) = &self.user_agent {
                builder.header(http::header::USER_AGENT, user_agent.clone())?
            } else {
                builder
            };
            if let Some(timeout) = self.timeout {
                Result::Ok(
                    compio::time::timeout(timeout, builder.send())
                        .await
                        .map_err(|_| NyquestError::RequestTimeout)??,
                )
            } else {
                Ok(builder.send().await?)
            }
        };
        let resp = SendWrapper::new(fut).await?;
        Ok(CyperResponse {
            resp,
            max_buffer_size: self.max_buffer_size,
        })
    }
}

#[doc(hidden)]
pub struct CyperResponse {
    resp: crate::Response,
    max_buffer_size: Option<u64>,
}

impl CyperResponse {
    pub(crate) fn status(&self) -> u16 {
        self.resp.status().as_u16()
    }

    pub(crate) fn content_length(&self) -> Option<u64> {
        self.resp.content_length()
    }

    pub(crate) fn get_header(&self, header: &str) -> Result<Vec<String>> {
        Ok(self
            .resp
            .headers()
            .get_all(header)
            .into_iter()
            .filter_map(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .collect())
    }

    pub(crate) async fn bytes_impl(&mut self) -> Result<Vec<u8>> {
        let mut bufs = vec![];
        let mut collected_size = 0;
        loop {
            let Some(frame) = self.resp.body.frame().await else {
                break;
            };
            let Ok(frame) = frame?.into_data() else {
                continue;
            };
            if self
                .max_buffer_size
                .is_some_and(|max| collected_size + frame.len() > max as usize)
            {
                return Err(NyquestError::ResponseTooLarge);
            }
            collected_size += frame.len();
            bufs.push(frame);
        }
        Ok(bufs.concat())
    }
}

fn to_io_error(err: crate::Error) -> std::io::Error {
    match err {
        crate::Error::System(e) => e,
        other_err => std::io::Error::other(other_err),
    }
}

fn convert_header_name(s: impl Into<Cow<'static, str>>) -> Result<HeaderName> {
    let s = s.into();
    match &s {
        Cow::Borrowed(s) if !s.bytes().any(|c| c.is_ascii_uppercase()) => {
            return Ok(HeaderName::from_static(s));
        }
        Cow::Borrowed(s) => HeaderName::from_bytes(s.as_bytes()),
        Cow::Owned(s) => HeaderName::from_bytes(s.as_bytes()),
    }
    .map_err(|e| NyquestError::Io(std::io::Error::other(e)))
}

fn convert_header_value(v: impl Into<Cow<'static, str>>) -> Result<HeaderValue> {
    let v = v.into();
    match v {
        Cow::Borrowed(s) => Ok(HeaderValue::from_static(s)),
        Cow::Owned(s) => HeaderValue::from_bytes(s.as_bytes())
            .map_err(|e| NyquestError::Io(std::io::Error::other(e))),
    }
}

impl From<crate::Error> for NyquestError {
    fn from(err: crate::Error) -> Self {
        match err {
            crate::Error::BadScheme(_) | crate::Error::InvalidUrl(_) => NyquestError::InvalidUrl,
            crate::Error::System(e) => NyquestError::Io(e),
            crate::Error::Timeout => NyquestError::RequestTimeout,
            _ => NyquestError::Io(std::io::Error::other(err)),
        }
    }
}
