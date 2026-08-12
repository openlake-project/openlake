#!/usr/bin/env bash
# Validate the exact non-RDMA artifact before it can be promoted.
set -euo pipefail

EXPECTED_VERSION="${1:-0.8.0}"
WHEEL_DIR="${2:-dist}"
WHEELS=("$WHEEL_DIR"/*.whl)

if [ "${#WHEELS[@]}" -ne 1 ] || [ ! -f "${WHEELS[0]}" ]; then
  echo "expected exactly one wheel in $WHEEL_DIR" >&2
  exit 1
fi

WHEEL="${WHEELS[0]}"
case "$(basename "$WHEEL")" in
  openlake_vllm-"$EXPECTED_VERSION"-cp310-abi3-manylinux_2_28_x86_64.whl) ;;
  *) echo "unexpected wheel name: $(basename "$WHEEL")" >&2; exit 1 ;;
esac

python -m twine check --strict "$WHEEL"
auditwheel show "$WHEEL"

EXTRACT_DIR="$(mktemp -d /tmp/openlake-wheel.XXXXXX)"
SMOKE_VENV="$(mktemp -d /tmp/openlake-wheel-smoke.XXXXXX)"
LDD_OUTPUT="$(mktemp /tmp/openlake-wheel-ldd.XXXXXX)"
trap 'rm -rf "$EXTRACT_DIR" "$SMOKE_VENV"; rm -f "$LDD_OUTPUT"' EXIT

python - "$WHEEL" "$EXPECTED_VERSION" "$EXTRACT_DIR" <<'PY'
import base64
import csv
import hashlib
import io
import sys
import zipfile

wheel_path, expected_version, extract_dir = sys.argv[1:]
required = {
    "openlake_client/__init__.py",
    "openlake_client/__main__.py",
    "openlake_client/_native.abi3.so",
    "openlake_client/openlaked",
    "openlake_client/openlake_adapter.py",
    "openlake_client/openlake_connector.py",
    "openlake_client/openlake_metrics.py",
    "openlake_client/configs/default.toml",
    "openlake_client/configs/kv_local.toml",
}
forbidden = {
    "openlake_client/configs/kv_rdma.toml",
    "openlake_client/configs/kv_ucx.toml",
}

with zipfile.ZipFile(wheel_path) as archive:
    names = set(archive.namelist())
    missing = required - names
    present_forbidden = forbidden & names
    assert not missing, f"wheel is missing: {sorted(missing)}"
    assert not present_forbidden, (
        f"non-RDMA wheel contains RDMA configs: {sorted(present_forbidden)}"
    )
    configs = {
        name
        for name in names
        if name.startswith("openlake_client/configs/") and name.endswith(".toml")
    }
    expected_configs = {
        "openlake_client/configs/default.toml",
        "openlake_client/configs/kv_local.toml",
    }
    assert configs == expected_configs, f"unexpected configs: {sorted(configs)}"

    elf_files = set()
    for name in names:
        if name.endswith("/"):
            continue
        with archive.open(name) as member:
            if member.read(4) == b"\x7fELF":
                elf_files.add(name)
    assert elf_files == {
        "openlake_client/_native.abi3.so",
        "openlake_client/openlaked",
    }, f"unexpected ELF files: {sorted(elf_files)}"

    daemon = archive.getinfo("openlake_client/openlaked")
    assert (daemon.external_attr >> 16) & 0o111, "openlaked is not executable"

    metadata_name = next(name for name in names if name.endswith(".dist-info/METADATA"))
    metadata = archive.read(metadata_name).decode()
    assert f"Version: {expected_version}\n" in metadata
    assert "Requires-Python: >=3.10\n" in metadata

    wheel_name = next(name for name in names if name.endswith(".dist-info/WHEEL"))
    wheel_metadata = archive.read(wheel_name).decode()
    assert "Tag: cp310-abi3-manylinux_2_28_x86_64\n" in wheel_metadata

    record_name = next(name for name in names if name.endswith(".dist-info/RECORD"))
    record = {
        row[0]: row[1]
        for row in csv.reader(io.StringIO(archive.read(record_name).decode()))
    }
    for name in required:
        algorithm, digest = record[name].split("=", 1)
        assert algorithm == "sha256"
        actual = hashlib.sha256(archive.read(name)).digest()
        encoded = base64.urlsafe_b64encode(actual).rstrip(b"=").decode()
        assert encoded == digest, f"RECORD mismatch for {name}"

    old_import = "vllm.distributed.kv_transfer.kv_connector.v1.openlake_"
    for name in names:
        if name.startswith("openlake_client/openlake_") and name.endswith(".py"):
            assert old_import not in archive.read(name).decode(), name

    archive.extractall(extract_dir)
PY

ELF_FILES=(
  "$EXTRACT_DIR/openlake_client/openlaked"
  "$EXTRACT_DIR/openlake_client/_native.abi3.so"
)
for elf in "${ELF_FILES[@]}"; do
  file "$elf" | grep -Eq 'ELF 64-bit.*x86-64'
  if readelf -d "$elf" | grep -Eiq \
    '\(NEEDED\).*(libucp|libucs|libuct|libucm|libibverbs|libmlx5|libcuda|libcudart)'; then
    echo "non-RDMA wheel links an RDMA or CUDA runtime: $elf" >&2
    readelf -d "$elf" >&2
    exit 1
  fi
  if ! ldd "$elf" > "$LDD_OUTPUT" 2>&1; then
    cat "$LDD_OUTPUT" >&2
    exit 1
  fi
  if grep -q 'not found' "$LDD_OUTPUT"; then
    echo "unresolved shared library in $elf" >&2
    cat "$LDD_OUTPUT" >&2
    exit 1
  fi
  max_glibc="$(
    readelf --version-info "$elf" |
      grep -oE 'GLIBC_[0-9]+(\.[0-9]+)*' |
      sed 's/^GLIBC_//' |
      sort -Vu |
      tail -1
  )"
  if [ -n "$max_glibc" ] &&
     [ "$(printf '%s\n' "$max_glibc" 2.28 | sort -V | tail -1)" != "2.28" ]; then
    echo "$elf requires GLIBC_$max_glibc, above the 2.28 ceiling" >&2
    exit 1
  fi
done

python -m venv "$SMOKE_VENV"
"$SMOKE_VENV/bin/python" -m pip install --disable-pip-version-check \
  --no-deps --no-index "$WHEEL"
"$SMOKE_VENV/bin/python" - "$EXPECTED_VERSION" <<'PY'
import importlib.metadata
import sys

import openlake_client

expected = sys.argv[1]
assert importlib.metadata.version("openlake-vllm") == expected
assert openlake_client.__version__ == expected
PY
"$SMOKE_VENV/bin/openlaked" --version | grep -Fx "openlaked $EXPECTED_VERSION"
