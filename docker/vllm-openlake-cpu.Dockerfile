# syntax=docker/dockerfile:1.7

ARG RUST_VERSION=1.91.1
ARG DEBIAN_RELEASE=bookworm
ARG VLLM_CPU_IMAGE=vllm/vllm-openai-cpu:v0.26.0-x86_64

FROM rust:${RUST_VERSION}-${DEBIAN_RELEASE} AS openlake-wheel
WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
        clang \
        cmake \
        libudev-dev \
        pkg-config \
        python3 \
        python3-venv \
    && rm -rf /var/lib/apt/lists/* \
    && python3 -m venv /opt/maturin \
    && /opt/maturin/bin/pip install --no-cache-dir 'maturin>=1.7,<2.0'

COPY rust-toolchain.toml Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY cli ./cli
COPY vendor ./vendor
COPY external ./external

RUN --mount=type=cache,target=/build/target,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    PATH="/opt/maturin/bin:${PATH}" crates/openlake_kv_client/build.sh cpu

FROM ${VLLM_CPU_IMAGE}
USER root

COPY --from=openlake-wheel /build/crates/openlake_kv_client/dist/*.whl /tmp/openlake-wheels/
RUN uv pip install --system /tmp/openlake-wheels/*.whl \
    && rm -rf /tmp/openlake-wheels

ENTRYPOINT ["vllm", "serve"]
