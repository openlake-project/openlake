mod server;

#[cfg(feature = "json")]
use std::collections::HashMap;

use cyper::Client;
#[cfg(feature = "json")]
use http::header::CONTENT_TYPE;

#[compio::test]
async fn response_text() {
    let server = server::http(move |_req| async { "Hello" }).await;

    let client = Client::new();

    let res = client
        .get(format!("http://{}/text", server.addr()))
        .expect("cannot create request builder")
        .send()
        .await
        .expect("Failed to get");
    assert_eq!(res.content_length(), Some(5));
    let text = res.text().await.expect("Failed to get text");
    assert_eq!("Hello", text);
}

#[compio::test]
async fn response_bytes() {
    let server = server::http(move |_req| async { "Hello" }).await;

    let client = Client::new();

    let res = client
        .get(format!("http://{}/bytes", server.addr()))
        .expect("cannot create request builder")
        .send()
        .await
        .expect("Failed to get");
    assert_eq!(res.content_length(), Some(5));
    let bytes = res.bytes().await.expect("res.bytes()");
    assert_eq!("Hello", bytes);
}

#[compio::test]
#[cfg(feature = "stream")]
async fn response_bytes_stream() {
    use std::{
        pin::Pin,
        task::{Context, Poll},
    };

    use axum::body::Body;
    use compio::bytes;
    use futures_util::{Stream, StreamExt};

    #[derive(Default)]
    struct ChunkedBody {
        chunks_sent: usize,
    }

    impl Stream for ChunkedBody {
        type Item = Result<bytes::Bytes, std::io::Error>;

        fn poll_next(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            if self.chunks_sent == 10 {
                return Poll::Ready(None);
            }

            let this = self.get_mut();

            this.chunks_sent += 1;
            Poll::Ready(Some(Ok(format!("Chunk {}", this.chunks_sent).into())))
        }
    }

    let server =
        server::http(move |_req| async { Body::from_stream(ChunkedBody::default()) }).await;

    let client = Client::new();

    let res = client
        .get(format!("http://{}/bytes", server.addr()))
        .expect("cannot create request builder")
        .send()
        .await
        .expect("Failed to get");
    assert_eq!(res.content_length(), None);

    let mut bytes_stream = res.bytes_stream().enumerate();
    let mut chunks_received = 0;

    while let Some((i, bytes)) = bytes_stream.next().await {
        chunks_received += 1;
        assert_eq!(
            bytes.unwrap(),
            compio::bytes::Bytes::from(format!("Chunk {}", i + 1))
        );
    }

    assert_eq!(chunks_received, 10);
}

#[compio::test]
#[cfg(feature = "json")]
async fn response_json() {
    let server = server::http(move |_req| async { "\"Hello\"" }).await;

    let client = Client::new();

    let res = client
        .get(format!("http://{}/json", server.addr()))
        .expect("cannot create request builder")
        .send()
        .await
        .expect("Failed to get");
    let text = res.json::<String>().await.expect("Failed to get json");
    assert_eq!("Hello", text);
}

#[compio::test]
async fn test_allowed_methods() {
    let resp = Client::new().get("https://compio.rs").unwrap().send().await;

    assert!(resp.is_ok());
}

#[compio::test]
#[cfg(feature = "native-tls")]
async fn test_native_tls() {
    let resp = Client::builder()
        .use_native_tls()
        .build()
        .get("https://compio.rs")
        .unwrap()
        .send()
        .await
        .unwrap();
    resp.text().await.unwrap();
}

#[compio::test]
#[cfg(feature = "rustls")]
async fn test_rustls() {
    let resp = Client::builder()
        .use_rustls_default()
        .build()
        .get("https://compio.rs")
        .unwrap()
        .send()
        .await
        .unwrap();
    resp.text().await.unwrap();
}

#[compio::test]
#[cfg(feature = "http3")]
async fn test_http3() {
    let resp = Client::builder()
        .build()
        .get("https://http3check.net")
        .unwrap()
        .version(http::Version::HTTP_3)
        .send()
        .await
        .unwrap();
    resp.text().await.unwrap();
}

#[test]
#[cfg(feature = "json")]
fn add_json_default_content_type_if_not_set_manually() {
    let mut map = HashMap::new();
    map.insert("body", "json");
    let content_type = http::HeaderValue::from_static("application/vnd.api+json");
    let req = Client::new()
        .post("https://compio.rs/")
        .expect("cannot create request builder")
        .header(CONTENT_TYPE, &content_type)
        .unwrap()
        .json(&map)
        .unwrap()
        .build();

    assert_eq!(content_type, req.headers().get(CONTENT_TYPE).unwrap());
}

#[test]
#[cfg(feature = "json")]
fn update_json_content_type_if_set_manually() {
    let mut map = HashMap::new();
    map.insert("body", "json");
    let req = Client::new()
        .post("https://compio.rs/")
        .expect("cannot create request builder")
        .json(&map)
        .unwrap()
        .build();

    assert_eq!("application/json", req.headers().get(CONTENT_TYPE).unwrap());
}
