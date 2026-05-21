use std::sync::Once;

use nyquest::{ClientBuilder, Request};

mod server;

static REGISTER: Once = Once::new();

fn register() {
    REGISTER.call_once(|| {
        cyper::nyquest::register();
    })
}

#[test]
fn register_backend() {
    register();
    register(); // should not panic
}

fn builder() -> ClientBuilder {
    register();
    ClientBuilder::default().no_proxy().no_redirects()
}

#[cfg(feature = "nyquest-async")]
#[compio::test]
async fn response_text_async() {
    let server = server::http(move |_req| async { "Hello" }).await;

    let client = builder().build_async().await.unwrap();

    let text = client
        .request(Request::get(format!("http://{}/text", server.addr())))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!("Hello", text);
}

#[cfg(feature = "nyquest-blocking")]
#[compio::test]
async fn response_text_blocking() {
    use futures_channel::oneshot;

    let server = server::http(move |_req| async { "Hello" }).await;

    let (tx, rx) = oneshot::channel();

    let handle = std::thread::spawn(move || {
        let client = builder().build_blocking().unwrap();

        let text = client
            .request(Request::get(format!("http://{}/text", server.addr())))
            .unwrap()
            .text()
            .unwrap();
        assert_eq!("Hello", text);
        tx.send(()).unwrap();
    });

    rx.await.unwrap();

    if let Err(e) = handle.join() {
        std::panic::resume_unwind(e)
    }
}

#[cfg(all(feature = "nyquest-multipart", feature = "nyquest-async"))]
#[compio::test]
async fn multipart_form() {
    use http_body_util::BodyExt;

    let form = nyquest::r#async::Body::multipart([nyquest::Part::new_with_content_type(
        "text",
        "text/plain",
        nyquest::PartBody::text("ttt"),
    )]);

    let server = server::http(move |mut req: http::Request<axum::body::Body>| async move {
        assert_eq!(req.method(), "POST");

        let mut full: Vec<u8> = Vec::new();
        while let Some(item) = req.body_mut().frame().await {
            full.extend(&*item.unwrap().into_data().unwrap());
        }

        full
    })
    .await;

    let url = format!("http://{}/multipart/1", server.addr());

    let client = builder().build_async().await.unwrap();

    let res = client
        .request(Request::post(url).with_body(form))
        .await
        .unwrap();

    let text = res.text().await.unwrap();
    assert!(text.contains(
        "Content-Disposition: form-data; name=\"text\"\r\ncontent-type: text/plain\r\n\r\nttt\r\n"
    ));
}
