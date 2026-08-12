#!/usr/bin/env bash
# Prepare the generated files embedded in the OpenLake Python wheel.
# Run this inside the target Linux/manylinux environment before maturin.
set -euo pipefail

cd "$(dirname "$0")"

if [ "$(uname -s)" != "Linux" ]; then
  echo "OpenLake wheels embed a Linux openlaked binary; build on Linux/manylinux." >&2
  exit 1
fi

VARIANT="${1:-cpu}"
TARGET="${2:-}"
case "$VARIANT" in
  cpu|rdma) ;;
  *) echo "usage: $0 [cpu|rdma] [rust-target]" >&2; exit 2 ;;
esac

PKG="python/openlake_client"

# Never allow generated files from an earlier build or variant into a wheel.
rm -f "$PKG/openlaked" "$PKG"/_native*.so "$PKG"/openlake_*.py
rm -rf "$PKG/configs"

FEATURES="vendored-hwloc"
CARGO_TARGET=()
SERVER_BIN="../../target/release/openlaked"
if [ -n "$TARGET" ]; then
  CARGO_TARGET=(--target "$TARGET")
  SERVER_BIN="../../target/$TARGET/release/openlaked"
fi
if [ "$VARIANT" = "rdma" ]; then
  FEATURES+=",rdma"
fi

cargo build \
  --locked \
  --release \
  -p openlake_server \
  --bin openlaked \
  "${CARGO_TARGET[@]}" \
  --features "$FEATURES"
install -m 0755 "$SERVER_BIN" "$PKG/openlaked"

cp ../../external/connectors/vllm/*.py "$PKG/"
sed -i \
  's|vllm\.distributed\.kv_transfer\.kv_connector\.v1\.openlake_|openlake_client.openlake_|g' \
  "$PKG"/openlake_*.py

mkdir -p "$PKG/configs"
cp ../openlake_server/configs/kv_local.toml "$PKG/configs/"
if [ "$VARIANT" = "rdma" ]; then
  cp \
    ../openlake_server/configs/kv_rdma.toml \
    ../openlake_server/configs/kv_ucx.toml \
    "$PKG/configs/"
  cp ../openlake_server/configs/kv_rdma.toml "$PKG/configs/default.toml"
else
  cp ../openlake_server/configs/kv_local.toml "$PKG/configs/default.toml"
fi
