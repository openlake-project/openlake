#!/usr/bin/env bash
# Install and exercise the non-RDMA wheel in a disposable minimal Linux image.
set -euo pipefail

WHEEL_DIR="${1:?usage: $0 WHEEL_DIR EXPECTED_VERSION}"
EXPECTED_VERSION="${2:?usage: $0 WHEEL_DIR EXPECTED_VERSION}"
WHEELS=("$WHEEL_DIR"/*.whl)

if [ "${#WHEELS[@]}" -ne 1 ] || [ ! -f "${WHEELS[0]}" ]; then
  echo "expected exactly one wheel in $WHEEL_DIR" >&2
  exit 1
fi

python -m pip install --disable-pip-version-check \
  --no-deps --no-index "${WHEELS[0]}"

python - "$EXPECTED_VERSION" <<'PY'
import importlib.metadata
import sys

import openlake_client

expected = sys.argv[1]
assert importlib.metadata.version("openlake-vllm") == expected
assert openlake_client.__version__ == expected
PY

openlaked --version | grep -Fx "openlaked $EXPECTED_VERSION"

LDD_OUTPUT="$(mktemp)"
cleanup_ldd() {
  rm -f "$LDD_OUTPUT"
}
trap cleanup_ldd EXIT
while IFS= read -r elf; do
  if ! ldd "$elf" > "$LDD_OUTPUT" 2>&1; then
    cat "$LDD_OUTPUT" >&2
    exit 1
  fi
  if grep -q "not found" "$LDD_OUTPUT"; then
    echo "unresolved shared library in $elf" >&2
    cat "$LDD_OUTPUT" >&2
    exit 1
  fi
done < <(
  python - <<'PY'
from importlib.resources import files

package = files("openlake_client")
print(package / "_native.abi3.so")
print(package / "openlaked")
PY
)

SMOKE_DIR="$(mktemp -d)"
cat > "$SMOKE_DIR/kv.toml" <<'TOML'
self_id = 0
mode = "kv"
transport = "h2"
rpc_addr = "127.0.0.1:19400"
s3_addr = "127.0.0.1:19000"
region = "us-east-1"
data_dirs = []
set_drive_count = 1
default_parity_count = 1

[[credentials]]
access_key = "openlake"
secret_key = "openlake"

[[nodes]]
id = 0
rpc_addr = "127.0.0.1:19400"
disk_count = 0

[kv_slab]
capacity_gb = 1
reserve_ttl_secs = 60
TOML

openlaked --config "$SMOKE_DIR/kv.toml" > "$SMOKE_DIR/openlaked.log" 2>&1 &
DAEMON_PID=$!
cleanup() {
  kill "$DAEMON_PID" 2>/dev/null || true
  wait "$DAEMON_PID" 2>/dev/null || true
  if [ -s "$SMOKE_DIR/openlaked.log" ]; then
    cat "$SMOKE_DIR/openlaked.log"
  fi
  cleanup_ldd
  rm -rf "$SMOKE_DIR"
}
trap cleanup EXIT

python - "$EXPECTED_VERSION" <<'PY'
import ctypes
import json
import socket
import sys
import time
import urllib.request

from openlake_client import Client

for _ in range(100):
    try:
        with socket.create_connection(("127.0.0.1", 19400), 0.2):
            break
    except OSError:
        time.sleep(0.1)
else:
    raise SystemExit("openlaked did not become ready")

for _ in range(100):
    try:
        with urllib.request.urlopen(
            "http://127.0.0.1:19401/v1/telemetry/openlake", timeout=1
        ) as response:
            telemetry = json.load(response)
        break
    except OSError:
        time.sleep(0.1)
else:
    raise SystemExit("openlaked telemetry did not become ready")
assert telemetry["openlake"]["version"] == sys.argv[1]

key = bytes(range(54))
source = bytearray((index * 17) % 256 for index in range(512))
destination = bytearray(len(source))
source_address = ctypes.addressof(ctypes.c_char.from_buffer(source))
destination_address = ctypes.addressof(ctypes.c_char.from_buffer(destination))

client = Client("local", 2048)
assert client.attach("127.0.0.1:19400", 0, 4096) > 0
assert client.batch_is_exist([key]) == [0]
assert client.put_batch([key], [[source_address]], [[len(source)]]) == [0]
assert client.batch_is_exist([key]) == [1]
assert client.get_batch([key], [[destination_address]], [[len(destination)]]) == [0]
assert destination == source
client.reset()
client.close()
PY
