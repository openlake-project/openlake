# Cyper

[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/compio-rs/cyper/blob/master/LICENSE)
[![crates.io](https://img.shields.io/crates/v/cyper)](https://crates.io/crates/cyper)
[![docs.rs](https://img.shields.io/badge/docs.rs-cyper-latest)](https://docs.rs/cyper)
[![Check](https://github.com/compio-rs/cyper/actions/workflows/ci_check.yml/badge.svg)](https://github.com/compio-rs/cyper/actions/workflows/ci_check.yml)
[![Test](https://github.com/compio-rs/cyper/actions/workflows/ci_test.yml/badge.svg)](https://github.com/compio-rs/cyper/actions/workflows/ci_test.yml)

An HTTP library based on [compio](https://github.com/compio-rs/compio) and [hyper](https://github.com/hyperium/hyper).

This project references code from [reqwest](https://github.com/seanmonstar/reqwest).

## Quick start

Add `compio` and `cyper` as dependency:

```
compio = { version = "0.17.0", features = ["macros"] }
cyper = "0.7.0"
```

Then we can start a simple HTTP request:

```rust
use cyper::Client;

#[compio::main]
async fn main() {
    let client = Client::new();
    let response = client
        .get("https://compio.rs/")
        .unwrap()
        .send()
        .await
        .unwrap();
    println!("{}", response.text().await.unwrap());
}
```

## Features
- [x] HTTPS - powered by compio-tls
  - [x] native-tls
  - [x] rustls
- [x] HTTP 2
- [x] HTTP 3 - powered by compio-quic
- [x] cookies
- [x] charset
- [x] serde-json
- [x] multipart
- [ ] compression
  - [ ] gzip
  - [ ] brotli

## Nyquest support
`cyper` supports `nyquest` experimentally. Start with registering:
```rust
cyper::nyquest::register();
```

## Contributing

There are opportunities to contribute to Cyper at any level. It doesn't matter if
you are just getting started with Rust or are the most weathered expert, we can
use your help. If you have any question about Cyper, feel free to join our [telegram group](https://t.me/compio_rs). Before contributing, please checkout our [contributing guide](https://github.com/compio-rs/cyper/blob/master/CONTRIBUTING.md).
