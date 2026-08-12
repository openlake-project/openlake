# OpenLake for vLLM

`openlake-vllm` packages the OpenLake KV-cache client, the `openlaked` daemon,
and the OpenLake vLLM connector for Linux.

Version 0.8 provides the non-RDMA local/H2 transport as a
`cp310-abi3-manylinux_2_28_x86_64` wheel. It supports regular CPython 3.10 and
newer on x86-64 Linux. Install vLLM separately for the connector runtime.

The RDMA/UCX build, ExANS CUDA codec, control-plane UI, source distribution,
and aarch64 wheel are not included in this package release.

Project source and documentation are available at
[github.com/openlake-project/openlake](https://github.com/openlake-project/openlake).
