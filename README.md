# phenomenal

S3-compatible distributed object storage in Rust. Thread-per-core, io_uring,
Reed-Solomon erasure coding, on-disk layout compatible with the MinIO `xl.meta`
format.

## Status

Early development. Single-node and small-cluster paths are functional; the
project is not yet production-ready.

## Build

```sh
cargo build --release --workspace
```

Targets `rustc 1.88+`. The toolchain is pinned in `rust-toolchain.toml`.

## Run

```sh
cargo run --release -p phenomenal_server -- --help
```

The server binary is `phenomenald`; the CLI is `phenomenal`.

## Workspace layout

```
crates/
├── phenomenal_io/        Local-FS I/O, xl.meta format, on-disk layout
├── phenomenal_storage/   Engine, erasure coding, put/get/list paths
├── phenomenal_server/    S3 HTTP frontend (axum + cyper + compio)
└── phenomenal_cli/       Command-line client
```

## Runtime

phenomenal runs on [`compio`](https://github.com/compio-rs/compio), a
completion-based async runtime backed by `io_uring` on Linux. Each runtime is
single-threaded and pinned to a core; HTTP and storage paths share the runtime
without crossing thread boundaries.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
