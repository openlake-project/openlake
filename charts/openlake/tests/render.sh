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

command -v "${helm_bin}" >/dev/null 2>&1 || fail "Helm is not installed"

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

dct_values="${chart_dir}/examples/kv-dct-values.yaml"
dct_render="${test_tmp}/kv-dct.yaml"
"${helm_bin}" lint "${chart_dir}" --values "${dct_values}"
"${helm_bin}" template openlake "${chart_dir}" --values "${dct_values}" >"${dct_render}"
assert_contains "${dct_render}" 'backend = "dct"'
assert_contains "${dct_render}" "self_node_id = __SELF_ID__"
assert_contains "${dct_render}" 'dev_name     = "mlx5_0"'
assert_contains "${dct_render}" '"openlake_device": "mlx5_0"'

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

echo "Helm render tests passed"
