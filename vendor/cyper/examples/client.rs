use clap::Parser;
use cyper::Client;
use http::Version;

#[derive(Debug, Parser)]
#[clap(about, version, author)]
struct Options {
    #[clap(default_value = "https://compio.rs/")]
    url: String,
    #[clap(flatten)]
    ver: VersionOptions,
}

#[derive(Debug, Parser)]
#[group(multiple = false)]
struct VersionOptions {
    #[clap(short = '2', long)]
    http2: bool,
    #[clap(short = '3', long)]
    http3: bool,
}

#[compio::main]
async fn main() {
    let opts = Options::parse();
    let ver = if opts.ver.http3 {
        Version::HTTP_3
    } else if opts.ver.http2 {
        Version::HTTP_2
    } else {
        Version::HTTP_11
    };
    let client = Client::new();
    let response = client
        .get(opts.url)
        .unwrap()
        .version(ver)
        .send()
        .await
        .unwrap();
    println!("{}", response.text().await.unwrap());
}
