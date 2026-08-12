#!/usr/bin/env bash
# Build one Linux wheel that carries all four artifacts:
#   client .so (maturin compiles) + openlaked (cargo) + connector .py + configs.
#   ./build.sh       -> openlake-vllm      (non-RDMA)
#   ./build.sh rdma  -> openlake-vllm-ib   (environment-specific RDMA build)
set -euo pipefail
cd "$(dirname "$0")"

if [ "$(uname -s)" != "Linux" ]; then
  echo "OpenLake wheels embed a Linux openlaked binary; build on Linux/manylinux." >&2
  exit 1
fi

VARIANT="${1:-cpu}"
case "$VARIANT" in
  cpu|rdma) ;;
  *) echo "usage: $0 [cpu|rdma]" >&2; exit 2 ;;
esac

MATURIN_FEATURES=()
MATURIN_POLICY=(--compatibility pypi --auditwheel repair)
if [ "$VARIANT" = "rdma" ]; then
  MATURIN_FEATURES=(--features rdma)
  # The RDMA artifact has external UCX/verbs/mlx5 runtime requirements and is
  # not currently claimed to be a portable manylinux wheel.
  MATURIN_POLICY=(--auditwheel skip)
  cp pyproject.toml pyproject.toml.orig
  trap 'mv pyproject.toml.orig pyproject.toml' EXIT
  sed 's/^name = "openlake-vllm"/name = "openlake-vllm-ib"/' pyproject.toml.orig > pyproject.toml
fi

# A release directory is single-use: stale wheels must never survive a build.
rm -rf dist ../../target/maturin
bash ./prepare-wheel.sh "$VARIANT"

maturin build \
  --release \
  --locked \
  "${MATURIN_FEATURES[@]}" \
  "${MATURIN_POLICY[@]}" \
  --out dist
