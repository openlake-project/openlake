use std::{
    pin::Pin,
    task::{Context, Poll},
};

use futures_util::StreamExt;
#[cfg(feature = "nyquest-async-stream")]
use nyquest_interface::{Body, Request};
use nyquest_interface::{
    Result,
    r#async::{AsyncBackend, AsyncClient, AsyncResponse, Request as AsyncRequest},
    client::ClientOptions,
};

use super::{CyperBackend, CyperClient, CyperResponse, to_io_error};

impl AsyncBackend for CyperBackend {
    type AsyncClient = CyperClient;

    async fn create_async_client(&self, options: ClientOptions) -> Result<Self::AsyncClient> {
        self.create_client(options)
    }
}

impl AsyncClient for CyperClient {
    type Response = CyperResponse;

    async fn request(&self, req: AsyncRequest) -> Result<Self::Response> {
        CyperClient::request(
            self,
            #[cfg(not(feature = "nyquest-async-stream"))]
            req,
            #[cfg(feature = "nyquest-async-stream")]
            Request {
                method: req.method,
                relative_uri: req.relative_uri,
                additional_headers: req.additional_headers,
                body: req.body.map(|body| match body {
                    Body::Stream {
                        stream,
                        content_type,
                    } => Body::Stream {
                        stream: WrapBoxedStream(stream),
                        content_type,
                    },
                    Body::Bytes {
                        content,
                        content_type,
                    } => Body::Bytes {
                        content,
                        content_type,
                    },
                    Body::Form { fields } => Body::Form { fields },
                    #[cfg(feature = "nyquest-multipart")]
                    Body::Multipart { parts } => Body::Multipart {
                        parts: parts
                            .into_iter()
                            .map(|part| nyquest_interface::Part {
                                headers: part.headers,
                                name: part.name,
                                filename: part.filename,
                                content_type: part.content_type,
                                body: match part.body {
                                    nyquest_interface::PartBody::Bytes { content } => {
                                        nyquest_interface::PartBody::Bytes { content }
                                    }
                                    nyquest_interface::PartBody::Stream(s) => {
                                        nyquest_interface::PartBody::Stream(WrapBoxedStream(s))
                                    }
                                },
                            })
                            .collect(),
                    },
                }),
            },
        )
        .await
    }
}

#[cfg(feature = "nyquest-async-stream")]
struct WrapBoxedStream(nyquest_interface::r#async::BoxedStream);

#[cfg(feature = "nyquest-async-stream")]
impl futures_util::Stream for WrapBoxedStream {
    type Item = crate::Result<compio::bytes::Bytes>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut buffer = [0u8; 1024];
        let s = std::pin::pin!(&mut self.get_mut().0);
        match futures_util::AsyncRead::poll_read(s, cx, &mut buffer) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(0)) => Poll::Ready(None),
            Poll::Ready(Ok(n)) => {
                let bytes = compio::bytes::Bytes::copy_from_slice(&buffer[..n]);
                Poll::Ready(Some(Ok(bytes)))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Some(Err(e.into()))),
        }
    }
}

impl futures_util::AsyncRead for CyperResponse {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.resp.poll_next_unpin(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(Ok(bytes))) => {
                let len = bytes.len().min(buf.len());
                buf[..len].copy_from_slice(&bytes[..len]);
                Poll::Ready(Ok(len))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(to_io_error(e))),
            Poll::Ready(None) => Poll::Ready(Ok(0)),
        }
    }
}

impl AsyncResponse for CyperResponse {
    fn status(&self) -> u16 {
        CyperResponse::status(self)
    }

    fn content_length(&self) -> Option<u64> {
        CyperResponse::content_length(self)
    }

    fn get_header(&self, header: &str) -> Result<Vec<String>> {
        CyperResponse::get_header(self, header)
    }

    async fn text(self: Pin<&mut Self>) -> Result<String> {
        self.bytes()
            .await
            .map(|b| String::from_utf8_lossy(&b).to_string())
    }

    async fn bytes(mut self: Pin<&mut Self>) -> Result<Vec<u8>> {
        self.bytes_impl().await
    }
}
