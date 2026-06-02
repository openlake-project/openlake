
<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/openlake-project/openlake/refs/heads/main/assets/openlake-wordmark-dark-8192.png">
  <img alt="OpenLake" src="https://raw.githubusercontent.com/openlake-project/openlake/refs/heads/main/assets/openlake-wordmark-light-8192.png" width=55%>
</picture>


<h3 align="center">
The shortest path from NVMe to GPU memory.
</h3>

Distributed object storage for GPU workloads. Built on Rust on `io_uring`, OpenLake beats state of the art and delivers 6x higher throughput and million+ iops within 1ms.


[Discord](https://discord.gg/TNXqVSnP6x)&nbsp;·&nbsp;[Website](https://theopenlake.com)&nbsp;·&nbsp;[Comparison](https://theopenlake.com/compare.html)&nbsp;·&nbsp;[Architecture](#architecture)&nbsp;·&nbsp;[Quickstart](#quickstart)



[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.91%2B-orange.svg)](rust-toolchain.toml)
[![Discord](https://img.shields.io/badge/community-discord-5865F2?logo=discord&logoColor=white)](https://discord.gg/TNXqVSnP6x)
[![Web](https://img.shields.io/badge/web-theopenlake.com-1d4ed8.svg)](https://theopenlake.com)



</div>


---

## What is OpenLake?

OpenLake is an object store for AI infrastructure. Training and inference clusters spend a large fraction of their wall clock time moving bytes from storage into GPU memory, most object stores put the host CPU, the page cache, and several userspace copies directly in that path. OpenLake is a high throughput, low latency storage engine that takes the opposite stance.

- **`io_uring`, thread per core.** Built on the [`compio`](https://github.com/compio-rs/compio) completion based runtime. One runtime per core, pinned, no work stealing. The HTTP frontend and the storage engine run on the *same* thread, so a request never crosses a core boundary on the hot path.
 - **No kernel involvement.** GPUDirect Storage and RDMA, data moves from peer NIC into GPU VRAM zerocopy, eliminating host memory and the page cache. see [Architecture](https://github.com/openlake-project/openlake#quickstart).
 - **Erasure coded.** SIMD Reed Solomon across striped EC. Reduced storage cost for replication, high throughput without the CPU cost of conventional EC.
 - **PacedRDMA.** Novel congestion control algorithm for high throughput RDMA. Credit based memory management to absorb request bursts, minimizing tail latencies.
 <br>

  <p align="center">
    <img src="docs/get_readme_p50_512.png" width="1400">
  </p>
  <p align="center"><sub>OpenLake sustains 225 MiB/s GET at sub 10 ms p50, 3x MinIO and 9x RustFS at c=512.</sub></p>

  ## Quickstart

  ### Prerequisites

  Stable Rust 1.91 or newer (pinned via `rust-toolchain.toml`). Linux gives you the `io_uring` driver; macOS builds and runs against `kqueue` for development.

  ```sh
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  rustup default stable
  ```

  ### Build

  Clone the repo and build the workspace in release mode.

  ```sh
  git clone <repo-url> openlake && cd openlake
  cargo build --release --workspace
  ```

  ### Benchmark

  The `phenomenal` CLI drives a `LocalFsBackend` directly for diagnostics and microbenchmarks. Not an S3 client, but the quickest way to confirm the build works and see local throughput.

  ```sh
  ./target/release/phenomenal bench --n 100000 --size 4096 --concurrency 64
  ```

  ### Start Cluster

  Write one TOML file per node. The full schema lives at the top of [`crates/phenomenal_server/src/config.rs`](crates/phenomenal_server/src/config.rs).

  Start `openlaked` on each host with its own config, then talk to the cluster with any S3 client.

  ```sh
  ./target/release/openlaked --config node0.toml

  aws --endpoint-url http://10.0.0.10:9000 s3 mb s3://demo
  aws --endpoint-url http://10.0.0.10:9000 s3 cp ./checkpoint.safetensors s3://demo/
  aws --endpoint-url http://10.0.0.10:9000 s3 ls s3://demo/
  ```
## Contributing

We welcome and value any contributions and collaborations.
Please check out [Contributing to OpenLake](https://github.com/openlake-project/openlake/blob/main/CONTRIBUTING.md) for how to get involved.

## Contact Us

  - For technical support, please reach out on [discord](https://discord.gg/TNXqVSnP6x).
  - For technical issues, bugs, and feature requests, please open an issue on [GitHub](https://github.com/theopenlake/openlake/issues).
  - For everything else, visit the [website](https://theopenlake.com) or reach out to the maintainers on discord.

## License

[Apache License 2.0](LICENSE).
