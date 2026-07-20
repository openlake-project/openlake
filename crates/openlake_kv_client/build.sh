#!/usr/bin/env bash
# Build one wheel that carries all four artifacts:
#   client .so (maturin compiles) + openlaked (cargo) + connector .py + configs.
#   ./build.sh          -> openlake-vllm      (non-RDMA)
#   ./build.sh rdma     -> openlake-vllm-ib   (--features rdma)
set -euo pipefail
cd "$(dirname "$0")"

VARIANT="${1:-cpu}"
PKG="python/openlake_client"
FEAT=""
if [ "$VARIANT" = "rdma" ]; then
  FEAT="--features rdma"
  cp pyproject.toml pyproject.toml.orig
  trap 'mv pyproject.toml.orig pyproject.toml' EXIT
  sed 's/^name = "openlake-vllm"/name = "openlake-vllm-ib"/' pyproject.toml.orig > pyproject.toml
fi

# 1. server binary — cargo compiles it
cargo build --release -p openlake_server --bin openlaked $FEAT
cp ../../target/release/openlaked "$PKG/openlaked"

# 2. connector .py
cp ../../external/connectors/vllm/*.py "$PKG/"

# 3. default configs
mkdir -p "$PKG/configs"
cp ../openlake_server/configs/kv_local.toml ../openlake_server/configs/kv_rdma.toml "$PKG/configs/"

# 4. maturin compiles the client .so and packs the wheel
maturin build --release $FEAT -o dist
