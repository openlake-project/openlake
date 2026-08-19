# OpenLake Helm chart

This chart supports two separate OpenLake workloads:

- Object storage is the existing default deployment.
- External KV-cache offload is enabled with `kv.enabled=true`.

Do not combine the object-storage `nodes`, disks, or credentials with the KV
settings. A KV process owns one in-memory slab and is standalone; `kv_agents`
is only its ordered list of KV peers.

## What the KV deployment creates

Given this ordered target list:

```yaml
kv:
  enabled: true
  targets:
    - nodeName: gpu-worker-0
      ip: 10.0.0.11
    - nodeName: gpu-worker-1
      ip: 10.0.0.12
```

the chart creates:

- one ConfigMap containing the ordered IP set (`target-ips`), the node identity
  mapping, an OpenLake TOML template, and optionally the vLLM connector JSON;
- one headless Service for RPC and telemetry discovery; and
- one host-networked StatefulSet replica on each named Kubernetes node.

Required node affinity limits placement to the listed node names. Required pod
anti-affinity places at most one replica on each node. A pod derives `self_id`
from the node on which Kubernetes schedules it, rather than assuming that a
StatefulSet ordinal maps to a particular machine. Every pod consequently gets:

```text
gpu-worker-0 / 10.0.0.11 -> self_id 0
gpu-worker-1 / 10.0.0.12 -> self_id 1
```

Every generated server configuration has the same ordered `kv_agents` list but
only its own entry in `[[nodes]]`. The generated vLLM `openlake_nodes` list uses
that exact order, so every vLLM instance can attach the same peer IDs.

## Prerequisites

- Kubernetes 1.28 or newer and Helm.
- Exact Kubernetes `.metadata.name` values for all target nodes.
- A unique, stable IPv4 address for each target. It must be reachable by every vLLM
  instance and must belong to the intended host/fabric; the chart deliberately
  does not guess which of a node's addresses is the data-plane address.
- An OpenLake image matching the chosen transport, pushed to a registry that
  every selected node can pull from.
- Enough allocatable RAM for `kv.slab.capacityGB` plus process and operating
  system overhead. Set a memory request/limit above the slab size.

By default, the chart mounts a memory-backed `emptyDir` of
`kv.slab.capacityGB` at `/dev/shm`, where host-backed H2 and UCX slabs are
created. This memory counts against pod/node memory; it is not persistent
storage. The opt-in vLLM smoke test is the sole example that selects a host
`/dev/shm` mount so its two co-located pods can see the same POSIX object.

Inspect the node names and Kubernetes InternalIPs with:

```bash
kubectl get nodes -o wide
```

For RDMA, also verify the actual device and transport on every selected host;
do not infer them from the sample values:

```bash
ibv_devices
ibv_devinfo
rdma link
ucx_info -d
```

## H2 orchestration smoke test

Start with [`examples/kv-h2-values.yaml`](examples/kv-h2-values.yaml). Replace
the placeholder image repository, sample node names, and IPs. An H2 image can
be built from this repository and pushed to your registry with:

```bash
docker build --file docker/openlaked.Dockerfile \
  --tag registry.example.com/openlake/openlaked:0.8.0 .
docker push registry.example.com/openlake/openlaked:0.8.0
```

Then render it before installation:

```bash
helm lint charts/openlake -f charts/openlake/examples/kv-h2-values.yaml
helm template openlake charts/openlake \
  -f charts/openlake/examples/kv-h2-values.yaml
```

Install or update it with:

```bash
helm upgrade --install openlake charts/openlake \
  --namespace openlake \
  --create-namespace \
  -f charts/openlake/examples/kv-h2-values.yaml
```

H2 is useful for validating Helm rendering, placement, process startup, and
health without IB/UCX. It is not a multi-node KV data transport. The `local`
client opens POSIX shared memory on the vLLM host, so it cannot map a remote
server's slab. For that reason the multi-node H2 example disables connector
output, and the chart rejects an enabled H2 connector with multiple targets.

A one-target H2 connector is valid only when vLLM and OpenLake share the host
and compatible IPC/shared-memory access. Kubernetes pod co-location by itself
does not create shared IPC namespaces.

## One-time vLLM CPU startup test

The optional [`vllm-smoke-test.yaml`](templates/vllm-smoke-test.yaml) Helm test
checks the maintainer-facing integration point that static rendering cannot:
a real vLLM process reads the generated connector JSON, initializes against a
running OpenLake H2 server, and reaches its health endpoint. The test Job exits
after success and is not a production vLLM Deployment.

The test uses one target node and mounts that host's `/dev/shm` into both pods.
This is deliberately limited to the H2 smoke test. It does not make H2 a
cross-node transport and should not be copied into the RDMA deployment.

Build and push the OpenLake server image as described above. Then build the
CPU vLLM test image, which adds the locally built `openlake-vllm` wheel to the
[official vLLM CPU image](https://docs.vllm.ai/en/stable/getting_started/installation/cpu/):

```bash
docker build --file docker/vllm-openlake-cpu.Dockerfile \
  --tag registry.example.com/openlake/vllm-openlake-cpu:0.26.0-openlake-0.8.0 .
docker push registry.example.com/openlake/vllm-openlake-cpu:0.26.0-openlake-0.8.0
```

Copy [`examples/kv-vllm-smoke-values.yaml`](examples/kv-vllm-smoke-values.yaml)
and replace its node name, node IP, and two image repositories. If the registry
is private, configure `imagePullSecrets`. Install the single-node H2 release:

```bash
helm upgrade --install openlake charts/openlake \
  --namespace openlake \
  --create-namespace \
  -f charts/openlake/examples/kv-vllm-smoke-values.yaml
kubectl --namespace openlake rollout status statefulset/openlake-openlake
```

Run the test, then read the retained Job logs:

```bash
helm test openlake --namespace openlake --timeout 20m
kubectl --namespace openlake logs job/openlake-openlake-vllm-smoke
```

The completed Job and its logs are retained for 10 minutes. The next test run
also removes the previous Job before creating its replacement.

The default `facebook/opt-125m` model is intentionally small and public because
this test checks startup and connector configuration, not model quality. Set
`vllmSmokeTest.model` to the agreed Llama or Mistral model for a larger test. If
that model needs a Hugging Face token, create a Secret whose `token` key holds
it and set `vllmSmokeTest.hfTokenSecretName` to the Secret name.

The Job passing proves that the command accepts `openlake_nodes` and that the
H2 connector can attach on the same node. It does not validate multi-node KV
transfer, GPU memory registration, RDMA, DCT, or UCX.

## Production P2P transport

Use [`examples/kv-ucx-values.yaml`](examples/kv-ucx-values.yaml) for UCX or
[`examples/kv-dct-values.yaml`](examples/kv-dct-values.yaml) for direct
verbs/DCT. Replace the example image with an OpenLake image built on Linux with
the `rdma` feature and the matching runtime libraries.

For UCX:

```yaml
kv:
  transport: rdma
  rdma:
    backend: ucx
  connector:
    enabled: true
    device: "" # automatically becomes "ucx"
```

For DCT:

```yaml
kv:
  transport: rdma
  rdma:
    backend: dct
    devName: mlx5_0
  connector:
    enabled: true
    device: "" # automatically becomes rdma.devName
```

The RDMA deployment mounts `/dev/infiniband` and grants `IPC_LOCK` and
`NET_RAW`. It does not install drivers, a Kubernetes device plugin, OFED, UCX,
or configure the IB/RoCE fabric. Those remain cluster-operator responsibilities.
`kv.rdma.env` can pass settings such as `UCX_NET_DEVICES` after they have been
verified on the target hosts. The same ordered IP list is available to each KV
pod at `/etc/openlake/target-ips` for cluster-managed handshake automation.

## Give every vLLM instance the peer list

For an RDMA deployment with `kv.connector.enabled=true`, inspect the generated
connector configuration:

```bash
kubectl --namespace openlake get configmap openlake-openlake-kv-config \
  --output jsonpath='{.data.vllm-kv-transfer-config\.json}'
```

The value can be passed to `vllm serve --kv-transfer-config` or mounted from
the ConfigMap by a separately managed vLLM Deployment. Apart from the optional,
short-lived smoke-test Job, this chart does not install or restart vLLM. Every
vLLM instance must receive the same rendered JSON; in particular, do not
reorder `openlake_nodes` in a second manifest.

Example output for UCX is:

```json
{
  "kv_connector": "OpenLakeConnector",
  "kv_connector_module_path": "openlake_client.openlake_connector",
  "kv_role": "kv_both",
  "kv_connector_extra_config": {
    "openlake_nodes": ["10.0.0.11:9400", "10.0.0.12:9400"],
    "openlake_device": "ucx"
  }
}
```

## Validate an installation

Check scheduling and startup without changing the cluster:

```bash
kubectl --namespace openlake get pods \
  --selector app.kubernetes.io/instance=openlake \
  --output wide
kubectl --namespace openlake rollout status statefulset/openlake-openlake
kubectl --namespace openlake logs statefulset/openlake-openlake
```

Each log should report its list-derived node ID and selected Kubernetes node.
The readiness probe requests `/v1/telemetry/openlake` on
`kv.ports.telemetry`. To inspect one response locally:

```bash
kubectl --namespace openlake port-forward pod/openlake-openlake-0 9401:9401
curl http://127.0.0.1:9401/v1/telemetry/openlake
```

For production correctness, health is only the first check. Initialize the
matching OpenLake connector from vLLM, attach every listed peer, register the
same memory type used in production, put known KV blocks, read them into a
cleared destination, synchronize the GPU when applicable, and compare the
retrieved bytes.

## Updates and failure modes

- `helm upgrade` regenerates the ConfigMap and rolls KV pods when any KV value
  changes. There is no continuously running ConfigMap controller.
- Adding, removing, or reordering targets changes peer IDs and cache placement.
  Coordinate that change with all vLLM deployments and restart them with the
  newly generated connector JSON. Treat the KV slab as an ephemeral cache.
- A `Pending` pod usually means a `nodeName` does not exist, a target node is
  unschedulable, another process owns a host port, or requested memory is not
  available. Inspect `kubectl describe pod <pod-name>`.
- An RDMA pod that cannot open `/dev/infiniband` or load UCX needs its host,
  device-plugin, image, library, and permissions checked. The chart cannot make
  a missing or incompatible transport healthy.
- Target IPs are deliberately not required to equal Kubernetes InternalIPs;
  they may be dedicated RDMA addresses. A wrong or unreachable address will
  still render successfully and must be caught by cluster validation.

## Main KV values

| Value | Meaning | Default |
| --- | --- | --- |
| `kv.enabled` | Select external KV-cache mode | `false` |
| `kv.transport` | Server transport: `h2` or `rdma` | `h2` |
| `kv.targets` | Ordered `{nodeName, ip}` identity and placement list | `[]` |
| `kv.ports.rpc` | Host-networked OpenLake RPC port | `9400` |
| `kv.ports.telemetry` | Host-networked health/telemetry port | `9401` |
| `kv.slab.capacityGB` | Explicit per-node in-memory slab capacity | `1` |
| `kv.sharedMemory.type` | `emptyDir`, or test-only shared `hostPath` | `emptyDir` |
| `kv.rdma.backend` | RDMA backend: `ucx` or `dct` | `ucx` |
| `kv.rdma.devName` | Observed device required by DCT | `""` |
| `kv.rdma.env` | Environment-specific UCX/RDMA variables | `{}` |
| `kv.connector.enabled` | Include vLLM connector JSON in the ConfigMap | `true` |
| `kv.connector.device` | Explicit connector device; empty selects by backend | `""` |
| `vllmSmokeTest.enabled` | Render the optional CPU `helm test` Job | `false` |
| `vllmSmokeTest.model` | Model used for startup validation | `facebook/opt-125m` |
