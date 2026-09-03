#!/usr/bin/env bash
# Build one wheel that carries all four artifacts:
#   client .so (maturin compiles) + openlaked (cargo) + connector .py + configs.
#   ./build.sh          -> openlake-vllm      (non-RDMA)
set -euo pipefail
cd "$(dirname "$0")"

VARIANT="${1:-cpu}"
case "$VARIANT" in
  cpu|rdma) ;;
  *) echo "usage: $0 [rdma]" >&2; exit 2 ;;
esac
PKG="python/openlake_client"
FEAT=""
AUDIT=""
if [ "$VARIANT" = "rdma" ]; then
  FEAT="--features rdma"
  AUDIT="--auditwheel skip"
  cp pyproject.toml pyproject.toml.orig
  trap 'mv pyproject.toml.orig pyproject.toml' EXIT
  sed 's/^name = "openlake-vllm"/name = "openlake-vllm-ib"/' pyproject.toml.orig > pyproject.toml
fi

# 1. server binary — cargo compiles it
cargo build --release -p openlake_server --bin openlaked $FEAT --features vendored-hwloc
cp ../../target/release/openlaked "$PKG/openlaked"

# 2. connector .py
cp ../../external/connectors/vllm/*.py "$PKG/"
sed -i 's|vllm\.distributed\.kv_transfer\.kv_connector\.v1\.openlake_|openlake_client.openlake_|g' "$PKG"/openlake_*.py

# 3. default configs
rm -rf "$PKG/configs"
mkdir -p "$PKG/configs"
cp ../openlake_server/configs/kv_local.toml "$PKG/configs/"
if [ "$VARIANT" = "rdma" ]; then
  cp ../openlake_server/configs/kv_rdma.toml ../openlake_server/configs/kv_ucx.toml "$PKG/configs/"
  cp ../openlake_server/configs/kv_rdma.toml "$PKG/configs/default.toml"
else
  cp ../openlake_server/configs/kv_local.toml "$PKG/configs/default.toml"
fi

if command -v nvcc >/dev/null 2>&1 && \
   [ -n "${NVCOMP_ROOT:-}" ] && \
   [ -f "$NVCOMP_ROOT/include/nvcomp/ans.h" ]; then
  cmake -S cuda -B cuda/build \
    -DOPENLAKE_CUDA_CODEC_BUILD_TESTS=OFF \
    -DOPENLAKE_EXPANS_BUILD=ON \
    -DNVCOMP_ROOT="$NVCOMP_ROOT"
  cmake --build cuda/build --config Release --target openlake_expans
  cp cuda/build/libopenlake_expans.so "$PKG/"
fi

# 4. maturin compiles the client .so and packs the wheel
rm -rf ../../target/maturin
maturin build --release $FEAT $AUDIT -o dist
