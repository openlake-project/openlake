use std::{io::Read, rc::Rc};

#[cfg(feature = "nyquest-blocking-stream")]
use compio::bytes::Bytes;
use compio::runtime::Runtime;
use futures_util::StreamExt;
#[cfg(feature = "nyquest-blocking-stream")]
use nyquest_interface::{Body, Request};
use nyquest_interface::{
    Result,
    blocking::{BlockingBackend, BlockingClient, BlockingResponse, Request as BlockingRequest},
    client::ClientOptions,
};
use send_wrapper::SendWrapper;

use super::{CyperBackend, CyperClient, CyperResponse, to_io_error};

impl BlockingBackend for CyperBackend {
    type BlockingClient = CyperBlockingClient;

    fn create_blocking_client(&self, options: ClientOptions) -> Result<Self::BlockingClient> {
        let client = self.create_client(options)?;
        let runtime = Rc::new(Runtime::new()?);
        Ok(CyperBlockingClient {
            client,
            runtime: SendWrapper::new(runtime),
        })
    }
}

#[derive(Clone)]
pub struct CyperBlockingClient {
    client: CyperClient,
    runtime: SendWrapper<Rc<Runtime>>,
}

impl BlockingClient for CyperBlockingClient {
    type Response = CyperBlockingResponse;

    fn request(&self, req: BlockingRequest) -> Result<Self::Response> {
        let resp = self.runtime.block_on(self.client.request(
            #[cfg(not(feature = "nyquest-blocking-stream"))]
            req,
            #[cfg(feature = "nyquest-blocking-stream")]
            Request {
                method: req.method,
                relative_uri: req.relative_uri,
                additional_headers: req.additional_headers,
                body: req.body.map(|body| {
                    match body {
                        Body::Stream {
                            stream,
                            content_type,
                        } => Body::Stream {
                            stream: futures_util::stream::iter(WrapBoxedStream(stream)),
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
                                            nyquest_interface::PartBody::Stream(
                                                futures_util::stream::iter(WrapBoxedStream(s)),
                                            )
                                        }
                                    },
                                })
                                .collect(),
                        },
                    }
                }),
            },
        ))?;
        Ok(CyperBlockingResponse {
            resp,
            runtime: self.runtime.clone(),
        })
    }
}

#[cfg(feature = "nyquest-blocking-stream")]
struct WrapBoxedStream(nyquest_interface::blocking::BoxedStream);

#[cfg(feature = "nyquest-blocking-stream")]
impl Iterator for WrapBoxedStream {
    type Item = crate::Result<Bytes>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut buffer = [0u8; 1024];
        let res = self.0.read(&mut buffer);
        match res {
            Ok(0) => None,
            Ok(n) => {
                let bytes = Bytes::copy_from_slice(&buffer[..n]);
                Some(Ok(bytes))
            }
            Err(e) => Some(Err(e.into())),
        }
    }
}

pub struct CyperBlockingResponse {
    resp: CyperResponse,
    runtime: SendWrapper<Rc<Runtime>>,
}

impl Read for CyperBlockingResponse {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let res = self.runtime.block_on(self.resp.resp.next());
        match res {
            Some(Ok(bytes)) => {
                let len = bytes.len().min(buf.len());
                buf[..len].copy_from_slice(&bytes[..len]);
                Ok(len)
            }
            Some(Err(e)) => Err(to_io_error(e)),
            None => Ok(0),
        }
    }
}

impl BlockingResponse for CyperBlockingResponse {
    fn status(&self) -> u16 {
        self.resp.status()
    }

    fn content_length(&self) -> Option<u64> {
        self.resp.content_length()
    }

    fn get_header(&self, header: &str) -> Result<Vec<String>> {
        self.resp.get_header(header)
    }

    fn text(&mut self) -> Result<String> {
        BlockingResponse::bytes(self).map(|b| String::from_utf8_lossy(&b).to_string())
    }

    fn bytes(&mut self) -> Result<Vec<u8>> {
        self.runtime.block_on(self.resp.bytes_impl())
    }
}
