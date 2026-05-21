mod server;

use http_body_util::BodyExt;

#[compio::test]
async fn text_part() {
    let form = cyper::multipart::Form::new().text("foo", "bar");

    let expected_body = format!(
        "\
         --{0}\r\nContent-Disposition: form-data; name=\"foo\"\r\n\r\nbar\r\n--{0}--\r\n",
        form.boundary()
    );

    let ct = format!("multipart/form-data; boundary={}", form.boundary());

    let server = server::http(move |mut req: http::Request<axum::body::Body>| {
        let ct = ct.clone();
        let expected_body = expected_body.clone();
        async move {
            assert_eq!(req.method(), "POST");
            assert_eq!(req.headers()["content-type"], ct);
            assert_eq!(
                req.headers()["content-length"],
                expected_body.len().to_string()
            );

            let mut full: Vec<u8> = Vec::new();
            while let Some(item) = req.body_mut().frame().await {
                full.extend(&*item.unwrap().into_data().unwrap());
            }

            assert_eq!(full, expected_body.as_bytes());

            axum::body::Body::default()
        }
    })
    .await;

    let url = format!("http://{}/multipart/1", server.addr());

    let res = cyper::Client::new()
        .post(&url)
        .unwrap()
        .multipart(form)
        .unwrap()
        .send()
        .await
        .unwrap();

    assert_eq!(res.url().as_str(), &url);
    assert_eq!(res.status(), http::StatusCode::OK);
}

#[compio::test]
async fn stream_part() {
    use std::future;

    use futures_util::stream;

    let stream = cyper::Body::stream(stream::once(future::ready(Ok::<_, cyper::Error>(
        "part1 part2".into(),
    ))));
    let part = cyper::multipart::Part::stream(stream);

    let form = cyper::multipart::Form::new()
        .text("foo", "bar")
        .part("part_stream", part);

    let expected_body = format!(
        "\
         --{0}\r\nContent-Disposition: form-data; \
         name=\"foo\"\r\n\r\nbar\r\n--{0}\r\nContent-Disposition: form-data; \
         name=\"part_stream\"\r\n\r\npart1 part2\r\n--{0}--\r\n",
        form.boundary()
    );

    let ct = format!("multipart/form-data; boundary={}", form.boundary());

    let server = server::http(move |req: http::Request<axum::body::Body>| {
        let ct = ct.clone();
        let expected_body = expected_body.clone();
        async move {
            assert_eq!(req.method(), "POST");
            assert_eq!(req.headers()["content-type"], ct);
            assert_eq!(req.headers()["transfer-encoding"], "chunked");

            let full = req.collect().await.unwrap().to_bytes();

            assert_eq!(full, expected_body.as_bytes());

            axum::body::Body::default()
        }
    })
    .await;

    let url = format!("http://{}/multipart/1", server.addr());

    let client = cyper::Client::new();

    let res = client
        .post(&url)
        .unwrap()
        .multipart(form)
        .unwrap()
        .send()
        .await
        .expect("Failed to post multipart");
    assert_eq!(res.url().as_str(), &url);
    assert_eq!(res.status(), http::StatusCode::OK);
}

#[compio::test]
async fn async_impl_file_part() {
    let form = cyper::multipart::Form::new()
        .file("foo", "Cargo.toml")
        .await
        .unwrap();

    let fcontents = std::fs::read_to_string("Cargo.toml").unwrap();

    let expected_body = format!(
        "\
         --{0}\r\nContent-Disposition: form-data; name=\"foo\"; \
         filename=\"Cargo.toml\"\r\nContent-Type: text/x-toml\r\n\r\n{1}\r\n--{0}--\r\n",
        form.boundary(),
        fcontents
    );

    let ct = format!("multipart/form-data; boundary={}", form.boundary());

    let server = server::http(move |req: http::Request<axum::body::Body>| {
        let ct = ct.clone();
        let expected_body = expected_body.clone();
        async move {
            assert_eq!(req.method(), "POST");
            assert_eq!(req.headers()["content-type"], ct);
            // files know their exact size
            assert_eq!(
                req.headers()["content-length"],
                expected_body.len().to_string()
            );
            let full = req.collect().await.unwrap().to_bytes();

            assert_eq!(full, expected_body.as_bytes());

            axum::body::Body::default()
        }
    })
    .await;

    let url = format!("http://{}/multipart/3", server.addr());

    let res = cyper::Client::new()
        .post(&url)
        .unwrap()
        .multipart(form)
        .unwrap()
        .send()
        .await
        .unwrap();

    assert_eq!(res.url().as_str(), &url);
    assert_eq!(res.status(), http::StatusCode::OK);
}
