mod server;

use std::net::{IpAddr, Ipv4Addr};

use cyper::{Client, resolve::Resolve};
use futures_util::{Stream, stream};
use http::Uri;

struct TestResolver;

impl Resolve for TestResolver {
    type Err = cyper::Error;

    async fn resolve(&self, _uri: &Uri) -> Result<impl Stream<Item = IpAddr> + '_, Self::Err> {
        Ok(stream::iter([IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))]))
    }
}

#[compio::test]
async fn resolve() {
    let server = server::http(move |_req| async { "Hello" }).await;

    let client = Client::builder().custom_resolver(TestResolver).build();

    let res = client
        .get(format!("http://abc:{}/text", server.addr().port()))
        .expect("cannot create request builder")
        .send()
        .await
        .expect("Failed to get");
    assert_eq!(res.content_length(), Some(5));
    let text = res.text().await.expect("Failed to get text");
    assert_eq!("Hello", text);
}
