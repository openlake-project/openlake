# syntax=docker/dockerfile:1.7

ARG RUST_VERSION=1.91.1
ARG DEBIAN_RELEASE=bookworm
ARG RDMA=0

FROM rust:${RUST_VERSION}-${DEBIAN_RELEASE} AS builder
ARG RDMA
WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config \
        clang \
        cmake \
        libhwloc-dev \
        libudev-dev \
        $( [ "${RDMA}" = "1" ] && echo "libibverbs-dev librdmacm-dev libnuma-dev" ) \
    && rm -rf /var/lib/apt/lists/*

COPY rust-toolchain.toml Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY cli ./cli
COPY vendor ./vendor

RUN --mount=type=cache,target=/build/target,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    set -eux; \
    FEATURES=""; \
    [ "${RDMA}" = "1" ] && FEATURES="--features rdma"; \
    cargo build --release --locked --bin openlaked ${FEATURES}; \
    install -m 0755 target/release/openlaked /openlaked

FROM debian:${DEBIAN_RELEASE}-slim AS runtime
ARG RDMA

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        tini \
        libhwloc15 \
        libudev1 \
        $( [ "${RDMA}" = "1" ] && echo "libibverbs1 librdmacm1 libnuma1" ) \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --system --gid 10001 openlake \
 && useradd  --system --uid 10001 --gid 10001 --no-create-home \
             --home-dir /var/lib/openlake --shell /usr/sbin/nologin openlake \
 && mkdir -p /var/lib/openlake /etc/openlake \
 && chown -R openlake:openlake /var/lib/openlake /etc/openlake

COPY --from=builder /openlaked /usr/local/bin/openlaked

USER openlake:openlake
WORKDIR /var/lib/openlake

ENV RUST_LOG=info \
    RUST_BACKTRACE=1

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/openlaked"]
CMD ["--config", "/etc/openlake/openlake.toml"]
