# openlake_rdma

A verbs-style reliable connected transport substrate for the inter-node storage data plane.

Today the cluster RPC plane is HTTP/2 over mTLS (see the workspace `compio` / `cyper` notes). This crate models the lower-level primitives a kernel-bypass data path needs, so the engine can later move bulk shard traffic off the socket stack and onto a queue-pair fabric without reshaping its call sites. It is additive and off by default. Nothing in the existing build links it.

## What it provides

A small, faithful model of the InfiniBand verbs object graph, expressed as safe Rust:

- `ProtectionDomain` and `MemoryRegion` with `lkey` / `rkey` handles and `AccessFlags` (local write, remote read, remote write). Regions are tagged `HostPinned` or `DeviceResident` so a GPUDirect-style descriptor can be addressed the same way as host memory.
- `WorkRequest` with a scatter gather list, `Opcode::RdmaWrite` and `Opcode::RdmaRead`, plus a remote address and `rkey` for one-sided operations.
- `QueuePair` carrying the canonical state machine (reset, init, ready to receive, ready to send) and rejecting illegal transitions.
- `CompletionQueue` with bounded depth, `WorkCompletion` entries, and a `poll` drain. One-sided writes and reads raise a single initiator-side completion, which matches verbs semantics.
- A `Fabric` trait that the queue pair drives, so backends are swappable behind one interface.

## Backends

- `SoftFabric` (default, portable): a software RoCE data path. It registers buffers in a shared protection domain and performs the actual gather, transfer, and scatter against those regions, raising `RemoteAccessError` on permission or bounds faults and `LocalProtectionError` on a bad local gather. This compiles and runs on every platform, so it is what exercises the API in CI.
- `backend::verbs` (Linux, `--features rdma`): a libibverbs device probe that enumerates the local RDMA capable NICs through `ibv_get_device_list`. It is the seam where the hardware data path attaches. It is gated so the default build never links `libibverbs`.

## Run it

```
cargo test -p openlake_rdma
cargo run -p openlake_rdma --example rdma_write_bench
cargo run -p openlake_rdma --example rdma_write_bench 4194304 8192
```

The example registers a host source region and a device resident sink, issues a stream of one-sided writes with a bounded number in flight, drains completions, and reports throughput plus matching source and sink checksums.

## Removing it

Delete `crates/openlake_rdma`. The workspace `members = ["crates/*", ...]` glob stops resolving it and no other file references it.
