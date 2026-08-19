#!/bin/sh
set -eu

helm_bin=${HELM_BIN:-helm}
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
chart_dir=$(CDPATH= cd -- "${script_dir}/.." && pwd)
test_tmp=$(mktemp -d /tmp/openlake-helm-tests.XXXXXX)
trap 'rm -rf -- "${test_tmp}"' EXIT HUP INT TERM

fail() {
  echo "helm render test failed: $*" >&2
  exit 1
}

assert_contains() {
  file=$1
  expected=$2
  grep -Fq -- "${expected}" "${file}" ||
    fail "${file} does not contain: ${expected}"
}

assert_not_contains() {
  file=$1
  unexpected=$2
  if grep -Fq -- "${unexpected}" "${file}"; then
    fail "${file} unexpectedly contains: ${unexpected}"
  fi
}

expect_render_failure() {
  expected=$1
  shift
  error_file="${test_tmp}/expected-error.txt"
  if "${helm_bin}" template invalid "${chart_dir}" "$@" >"${error_file}" 2>&1; then
    fail "invalid values rendered successfully: $*"
  fi
  assert_contains "${error_file}" "${expected}"
}

validate_toml() {
  render_file=$1
  expected_transport=$2
  expected_backend=${3:-}
  config_file="${test_tmp}/openlake-${expected_transport}-${expected_backend:-none}.toml"

  sed -n '
    /^  openlake.toml.tpl: |$/,/^  entrypoint.sh: |$/ {
      /^  openlake.toml.tpl: |$/d
      /^  entrypoint.sh: |$/d
      s/^    //
      s/__SELF_ID__/0/g
      p
    }
  ' "${render_file}" >"${config_file}"

  python3 -c '
import sys
import tomllib

with open(sys.argv[1], "rb") as stream:
    config = tomllib.load(stream)

expected_transport = sys.argv[2]
expected_backend = sys.argv[3] or None
assert config["self_id"] == 0
assert config["mode"] == "kv"
assert config["transport"] == expected_transport
assert config["kv_agents"] == ["10.0.0.11:9400", "10.0.0.12:9400"]
assert config["nodes"] == [{"id": 0, "rpc_addr": "0.0.0.0:9400", "disk_count": 0}]
assert config["kv_slab"]["capacity_gb"] > 0
if expected_backend:
    assert config["rdma"]["backend"] == expected_backend
    if expected_backend == "dct":
        assert config["rdma"]["self_node_id"] == 0
else:
    assert "rdma" not in config
' "${config_file}" "${expected_transport}" "${expected_backend}"
}

validate_connector() {
  render_file=$1
  expected_device=$2
  expected_nodes=${3:-"10.0.0.11:9400,10.0.0.12:9400"}
  connector_file="${test_tmp}/connector-${expected_device}.json"

  sed -n '
    /^  vllm-kv-transfer-config.json: |$/,/^---$/ {
      /^  vllm-kv-transfer-config.json: |$/d
      /^---$/d
      s/^    //
      p
    }
  ' "${render_file}" >"${connector_file}"

  python3 -c '
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    connector = json.load(stream)

assert connector["kv_connector"] == "OpenLakeConnector"
extra = connector["kv_connector_extra_config"]
assert extra["openlake_nodes"] == sys.argv[3].split(",")
assert extra["openlake_device"] == sys.argv[2]
' "${connector_file}" "${expected_device}" "${expected_nodes}"
}

validate_smoke_script() {
  render_file=$1
  smoke_script="${test_tmp}/vllm-smoke.sh"
  sed -n '
    /^            - |$/,/^          env:$/ {
      /^            - |$/d
      /^          env:$/d
      s/^              //
      p
    }
  ' "${render_file}" >"${smoke_script}"
  sh -n "${smoke_script}"
}

command -v "${helm_bin}" >/dev/null 2>&1 || fail "Helm is not installed"
command -v python3 >/dev/null 2>&1 || fail "Python 3 is not installed"

storage_render="${test_tmp}/storage.yaml"
"${helm_bin}" lint "${chart_dir}"
"${helm_bin}" template storage "${chart_dir}" >"${storage_render}"
assert_contains "${storage_render}" "kind: Secret"
assert_contains "${storage_render}" "volumeClaimTemplates:"
assert_contains "${storage_render}" "openlake.dev/workload: storage"
assert_not_contains "${storage_render}" "-kv-config"

h2_values="${chart_dir}/examples/kv-h2-values.yaml"
h2_render="${test_tmp}/kv-h2.yaml"
"${helm_bin}" lint "${chart_dir}" --values "${h2_values}"
"${helm_bin}" template openlake "${chart_dir}" --values "${h2_values}" >"${h2_render}"
assert_contains "${h2_render}" "name: openlake-openlake-kv-config"
assert_contains "${h2_render}" "target-ips: |"
assert_contains "${h2_render}" "0|gpu-worker-0|10.0.0.11"
assert_contains "${h2_render}" '"10.0.0.11:9400",'
assert_contains "${h2_render}" '"10.0.0.12:9400",'
assert_contains "${h2_render}" "replicas: 2"
assert_contains "${h2_render}" "matchFields:"
assert_contains "${h2_render}" 'key: metadata.name'
assert_contains "${h2_render}" "requiredDuringSchedulingIgnoredDuringExecution:"
assert_contains "${h2_render}" "hostNetwork: true"
assert_contains "${h2_render}" 'sizeLimit: "8Gi"'
assert_not_contains "${h2_render}" "vllm-kv-transfer-config.json"
assert_not_contains "${h2_render}" "/dev/infiniband"
assert_not_contains "${h2_render}" "volumeClaimTemplates:"
assert_not_contains "${h2_render}" "kind: Secret"
validate_toml "${h2_render}" h2

ucx_values="${chart_dir}/examples/kv-ucx-values.yaml"
ucx_render="${test_tmp}/kv-ucx.yaml"
"${helm_bin}" lint "${chart_dir}" --values "${ucx_values}"
"${helm_bin}" template openlake "${chart_dir}" --values "${ucx_values}" >"${ucx_render}"
assert_contains "${ucx_render}" 'transport            = "rdma"'
assert_contains "${ucx_render}" 'backend = "ucx"'
assert_contains "${ucx_render}" '"openlake_device": "ucx"'
assert_contains "${ucx_render}" "vllm-kv-transfer-config.json"
assert_contains "${ucx_render}" "mountPath: /dev/infiniband"
assert_contains "${ucx_render}" 'add: ["IPC_LOCK", "NET_RAW"]'
assert_not_contains "${ucx_render}" "self_node_id = __SELF_ID__"
validate_toml "${ucx_render}" rdma ucx
validate_connector "${ucx_render}" ucx

dct_values="${chart_dir}/examples/kv-dct-values.yaml"
dct_render="${test_tmp}/kv-dct.yaml"
"${helm_bin}" lint "${chart_dir}" --values "${dct_values}"
"${helm_bin}" template openlake "${chart_dir}" --values "${dct_values}" >"${dct_render}"
assert_contains "${dct_render}" 'backend = "dct"'
assert_contains "${dct_render}" "self_node_id = __SELF_ID__"
assert_contains "${dct_render}" 'dev_name     = "mlx5_0"'
assert_contains "${dct_render}" '"openlake_device": "mlx5_0"'
validate_toml "${dct_render}" rdma dct
validate_connector "${dct_render}" mlx5_0

smoke_values="${chart_dir}/examples/kv-vllm-smoke-values.yaml"
smoke_render="${test_tmp}/kv-vllm-smoke.yaml"
"${helm_bin}" lint "${chart_dir}" --values "${smoke_values}"
"${helm_bin}" template openlake "${chart_dir}" --values "${smoke_values}" >"${smoke_render}"
assert_contains "${smoke_render}" "kind: Job"
assert_contains "${smoke_render}" '"helm.sh/hook": test'
assert_contains "${smoke_render}" 'image: "registry.example.com/openlake/vllm-openlake-cpu:0.26.0-openlake-0.8.0"'
assert_contains "${smoke_render}" 'vllm serve "${MODEL_ID}"'
assert_contains "${smoke_render}" 'value: "facebook/opt-125m"'
assert_contains "${smoke_render}" 'value: "http://10.0.0.11:9401/v1/telemetry/openlake"'
assert_contains "${smoke_render}" "key: vllm-kv-transfer-config.json"
assert_contains "${smoke_render}" 'path: "/dev/shm"'
assert_contains "${smoke_render}" '"openlake_device": "local"'
assert_contains "${smoke_render}" 'value: nobind'
validate_connector "${smoke_render}" local "10.0.0.11:9400"
validate_smoke_script "${smoke_render}"

expect_render_failure \
  "minItems: got 0, want 1" \
  --set kv.enabled=true

expect_render_failure \
  'kv.targets contains duplicate ip "10.0.0.11"' \
  --set kv.enabled=true \
  --set kv.transport=rdma \
  --set 'kv.targets[0].nodeName=gpu-worker-0' \
  --set 'kv.targets[0].ip=10.0.0.11' \
  --set 'kv.targets[1].nodeName=gpu-worker-1' \
  --set 'kv.targets[1].ip=10.0.0.11'

expect_render_failure \
  "the H2/local connector supports one same-host KV target only" \
  --set kv.enabled=true \
  --set 'kv.targets[0].nodeName=gpu-worker-0' \
  --set 'kv.targets[0].ip=10.0.0.11' \
  --set 'kv.targets[1].nodeName=gpu-worker-1' \
  --set 'kv.targets[1].ip=10.0.0.12'

expect_render_failure \
  "kv.rdma.devName is required for the dct backend" \
  --set kv.enabled=true \
  --set kv.transport=rdma \
  --set kv.rdma.backend=dct \
  --set 'kv.targets[0].nodeName=gpu-worker-0' \
  --set 'kv.targets[0].ip=10.0.0.11'

expect_render_failure \
  "vllmSmokeTest.enabled=true requires kv.enabled=true" \
  --set vllmSmokeTest.enabled=true

expect_render_failure \
  "the H2/local vLLM smoke test requires kv.sharedMemory.type=hostPath" \
  --values "${smoke_values}" \
  --set kv.sharedMemory.type=emptyDir

echo "Helm render tests passed"
