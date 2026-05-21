use std::{
    fmt::Debug,
    pin::Pin,
    task::{Context, Poll},
};

use async_stream::try_stream;
use compio::{BufResult, bytes::Bytes, fs::File, io::AsyncReadAt};
use futures_util::{Stream, StreamExt};
use hyper::body::{Frame, Incoming, SizeHint};
use send_wrapper::SendWrapper;

enum BodyInner {
    Bytes(Bytes),
    Stream(Pin<Box<dyn Stream<Item = crate::Result<Bytes>> + Send>>),
}

impl hyper::body::Body for BodyInner {
    type Data = Bytes;
    type Error = crate::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.get_mut() {
            Self::Bytes(b) => {
                if b.is_empty() {
                    Poll::Ready(None)
                } else {
                    Poll::Ready(Some(Ok(Frame::data(std::mem::replace(b, Bytes::new())))))
                }
            }
            Self::Stream(s) => s.poll_next_unpin(cx).map(|b| b.map(|b| b.map(Frame::data))),
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self {
            Self::Bytes(b) => SizeHint::with_exact(b.len() as _),
            Self::Stream(_) => SizeHint::default(),
        }
    }
}

impl Debug for BodyInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bytes(b) => f.debug_tuple("Bytes").field(b).finish(),
            Self::Stream(_) => f.debug_struct("Stream").finish_non_exhaustive(),
        }
    }
}

fn wrap_async_read_at(r: impl AsyncReadAt) -> impl Stream<Item = crate::Result<Bytes>> {
    try_stream! {
        let mut offset = 0;
        loop {
            let buffer = Vec::with_capacity(1024);
            let BufResult(res, buffer) = r.read_at(buffer, offset).await;
            let len = res?;
            if len == 0 {
                break;
            }
            offset += len as u64;
            yield Bytes::from(buffer);
        }
    }
}

/// A request body.
#[derive(Debug)]
pub struct Body(BodyInner);

impl Default for Body {
    fn default() -> Self {
        Self::empty()
    }
}

impl Body {
    /// Create an empty request body.
    pub const fn empty() -> Self {
        Self(BodyInner::Bytes(Bytes::new()))
    }

    /// Wrap a futures [`Stream`] in a box inside [`Body`].
    pub fn stream(s: impl Stream<Item = crate::Result<Bytes>> + Send + 'static) -> Self {
        Self(BodyInner::Stream(Box::pin(s)))
    }

    /// Returns a reference to the internal data of the `Body`.
    ///
    /// [`None`] is returned, if the underlying data is a stream.
    pub fn as_bytes(&self) -> Option<&Bytes> {
        match &self.0 {
            BodyInner::Bytes(b) => Some(b),
            BodyInner::Stream(_) => None,
        }
    }

    /// Returns the content length of the body, if known.
    pub fn content_length(&self) -> Option<u64> {
        match &self.0 {
            BodyInner::Bytes(b) => Some(b.len() as u64),
            BodyInner::Stream(_) => None,
        }
    }
}

impl hyper::body::Body for Body {
    type Data = Bytes;
    type Error = crate::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        unsafe { self.map_unchecked_mut(|this| &mut this.0) }.poll_frame(cx)
    }

    fn size_hint(&self) -> SizeHint {
        self.0.size_hint()
    }
}

impl From<Bytes> for Body {
    fn from(value: Bytes) -> Self {
        Self(BodyInner::Bytes(value))
    }
}

impl From<String> for Body {
    fn from(value: String) -> Self {
        Self(BodyInner::Bytes(Bytes::from(value.into_bytes())))
    }
}

impl From<&'static str> for Body {
    fn from(value: &'static str) -> Self {
        Self(BodyInner::Bytes(Bytes::from_static(value.as_bytes())))
    }
}

impl From<Vec<u8>> for Body {
    fn from(value: Vec<u8>) -> Self {
        Self(BodyInner::Bytes(Bytes::from(value)))
    }
}

impl From<&'static [u8]> for Body {
    fn from(value: &'static [u8]) -> Self {
        Self(BodyInner::Bytes(Bytes::from_static(value)))
    }
}

impl From<File> for Body {
    fn from(value: File) -> Self {
        Self::stream(SendWrapper::new(wrap_async_read_at(value)))
    }
}

#[cfg(feature = "stream")]
impl Stream for Body {
    type Item = Result<Bytes, crate::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        use hyper::body::Body;

        let frame = unsafe { self.as_mut().map_unchecked_mut(|this| &mut this.0) }.poll_frame(cx);
        match frame {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(Ok(frame))) => {
                if let Ok(data) = frame.into_data() {
                    Poll::Ready(Some(Ok(data)))
                } else {
                    self.poll_next(cx)
                }
            }
            Poll::Ready(Some(Err(err))) => Poll::Ready(Some(Err(err))),
            Poll::Ready(None) => Poll::Ready(None),
        }
    }
}

#[derive(Debug)]
pub(crate) enum ResponseBody {
    Incoming(Incoming),
    #[cfg(feature = "http3")]
    Blob(Bytes),
}

impl hyper::body::Body for ResponseBody {
    type Data = Bytes;
    type Error = crate::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = unsafe { self.get_unchecked_mut() };
        match this {
            Self::Incoming(b) => unsafe { Pin::new_unchecked(b) }
                .poll_frame(cx)
                .map_err(|e| e.into()),
            #[cfg(feature = "http3")]
            Self::Blob(b) => {
                if b.is_empty() {
                    Poll::Ready(None)
                } else {
                    Poll::Ready(Some(Ok(Frame::data(std::mem::replace(b, Bytes::new())))))
                }
            }
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self {
            Self::Incoming(b) => b.size_hint(),
            #[cfg(feature = "http3")]
            Self::Blob(b) => SizeHint::with_exact(b.len() as _),
        }
    }
}

#[cfg(feature = "stream")]
impl Stream for ResponseBody {
    type Item = Result<Bytes, crate::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            return match std::task::ready!(hyper::body::Body::poll_frame(self.as_mut(), cx)) {
                Some(Ok(frame)) => {
                    if let Ok(data) = frame.into_data() {
                        Poll::Ready(Some(Ok(data)))
                    } else {
                        continue;
                    }
                }
                Some(Err(err)) => Poll::Ready(Some(Err(err))),
                None => Poll::Ready(None),
            };
        }
    }
}
