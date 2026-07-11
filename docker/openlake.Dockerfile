# syntax=docker/dockerfile:1.7

ARG RUST_VERSION=1.91.1
ARG DEBIAN_RELEASE=bookworm

FROM rust:${RUST_VERSION}-${DEBIAN_RELEASE} AS builder
WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config \
        clang \
        cmake \
    && rm -rf /var/lib/apt/lists/*

COPY rust-toolchain.toml Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY cli ./cli
COPY vendor ./vendor

RUN --mount=type=cache,target=/build/target,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    set -eux; \
    cargo build --release --locked --bin openlake; \
    install -m 0755 target/release/openlake /openlake

FROM debian:${DEBIAN_RELEASE}-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        tini \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --system --gid 10001 openlake \
 && useradd  --system --uid 10001 --gid 10001 --no-create-home \
             --home-dir /var/lib/openlake --shell /usr/sbin/nologin openlake \
 && mkdir -p /var/lib/openlake /etc/openlake \
 && chown -R openlake:openlake /var/lib/openlake /etc/openlake

COPY --from=builder /openlake /usr/local/bin/openlake

USER openlake:openlake
WORKDIR /var/lib/openlake

ENV RUST_LOG=info \
    RUST_BACKTRACE=1

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/openlake"]
CMD ["--help"]
