import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { loadControlPlaneConfig, parsePrometheus, TelemetryPoller } from "../server/telemetry.mjs";

process.env.CONTROL_PLANE_LIBRARY_MODE = "1";
const { startControlPlane } = await import("../server/control-plane.mjs");

test("parses Prometheus samples without forwarding comments", () => {
  const samples = parsePrometheus("# HELP requests total\nrequests_total{model=\"test-model\"} 42\nqueue_depth 2\n");
  assert.deepEqual(samples, [
    { name: "requests_total", labels: { model: "test-model" }, value: 42 },
    { name: "queue_depth", labels: {}, value: 2 },
  ]);
});

test("uses the ordered KV agent list as the fleet inventory on every KV host", async context => {
  const directory = await mkdtemp(join(tmpdir(), "openlake-kv-agent-inventory-"));
  context.after(() => rm(directory, { force: true, recursive: true }));
  const agents = ["10.0.0.10:9400", "10.0.0.11:9400"];
  const configs = await Promise.all([0, 1].map(async selfId => {
    const configPath = join(directory, `node-${selfId}.toml`);
    await writeFile(configPath, `
self_id = ${selfId}
mode = "kv"
kv_agents = ["${agents[0]}", "${agents[1]}"]

[[nodes]]
id = ${selfId}
rpc_addr = "${agents[selfId]}"
disk_count = 0
`);
    return loadControlPlaneConfig(configPath);
  }));

  for (const config of configs) {
    assert.deepEqual(config.nodes.map(node => ({
      id: node.id,
      rpcAddress: node.rpcAddress,
      telemetryAddress: node.telemetryAddress,
    })), [
      { id: 0, rpcAddress: agents[0], telemetryAddress: "10.0.0.10:9401" },
      { id: 1, rpcAddress: agents[1], telemetryAddress: "10.0.0.11:9401" },
    ]);
  }
});

test("rejects a console configuration without KV agents", async context => {
  const directory = await mkdtemp(join(tmpdir(), "openlake-missing-kv-agents-"));
  context.after(() => rm(directory, { force: true, recursive: true }));
  const configPath = join(directory, "openlake.toml");
  await writeFile(configPath, `
self_id = 0
mode = "kv"

[[nodes]]
id = 0
rpc_addr = "127.0.0.1:9400"
disk_count = 0
`);

  await assert.rejects(
    loadControlPlaneConfig(configPath),
    /requires a non-empty kv_agents array/,
  );
});

test("loads the existing OpenLake TOML and polls both node-agent routes", async context => {
  const telemetry = createServer((request, response) => {
    if (request.url === "/v1/telemetry/openlake") {
      response.setHeader("content-type", "application/json");
      response.end(JSON.stringify({
        node_id: 7,
        openlake: {
          data_paths: [],
          kv_cache: { attached: true, configured_capacity_bytes: 65536, slot_bytes: 1024, slot_count: 64, used_slots: 8 },
          mode: "kv",
          transport: "h2",
          version: "0.7.0",
        },
        hardware: {
          schema_version: "1.0",
          collected_at_unix_ms: 1,
          collection_status: "available",
          system: { operating_system: "linux", architecture: "x86_64", hostname: "test-node", vendor: "Test Systems", product_name: "Test Accelerator Host" },
          cpu: { architecture: "x86_64", model: "Test CPU", logical_cpu_count: 16, physical_core_count: 8, package_count: 1, packages: [] },
          memory: { total_bytes: 68719476736, available_bytes: 34359738368 },
          numa_nodes: [],
          pci_devices: [],
          gpus: [],
          network_interfaces: [],
          infiniband_devices: [],
          disks: [],
          openlake: { kv_cache_capacity_bytes: 65536, data_paths: [] },
          subsystems: [],
        },
      }));
      return;
    }
    if (request.url === "/v1/telemetry/vllm") {
      response.setHeader("content-type", "text/plain; version=0.0.4");
      response.end("vllm_requests_running 3\n");
      return;
    }
    response.writeHead(404).end();
  });
  await new Promise(resolve => telemetry.listen(0, "127.0.0.1", resolve));
  context.after(() => new Promise(resolve => telemetry.close(resolve)));
  const address = telemetry.address();
  assert.equal(typeof address, "object");

  const directory = await mkdtemp(join(tmpdir(), "openlake-control-plane-"));
  context.after(() => rm(directory, { force: true, recursive: true }));
  const configPath = join(directory, "openlake.toml");
  await writeFile(configPath, `
self_id = 7
mode = "kv"
rpc_addr = "127.0.0.1:${address.port - 1}"
kv_agents = ["127.0.0.1:${address.port - 1}"]

[[credentials]]
access_key = "must-not-leak"
secret_key = "must-not-leak"

[[nodes]]
id = 7
rpc_addr = "127.0.0.1:${address.port - 1}"
disk_count = 0
`);

  const config = await loadControlPlaneConfig(configPath);
  assert.equal(config.nodes[0].telemetryAddress, `127.0.0.1:${address.port}`);
  const poller = new TelemetryPoller(config, { intervalMs: 60_000, timeoutMs: 1000 });
  context.after(() => poller.stop());
  await poller.start();
  const snapshot = poller.snapshot();
  assert.deepEqual(snapshot.totals, { configured: 1, degraded: 0, healthy: 1, unreachable: 0 });
  assert.equal(snapshot.nodes[0].openlake.openlake.kv_cache.used_slots, 8);
  assert.equal(snapshot.nodes[0].openlake.hardware.system.product_name, "Test Accelerator Host");
  assert.equal(snapshot.nodes[0].vllm.samples[0].name, "vllm_requests_running");
  assert.equal(JSON.stringify(snapshot).includes("must-not-leak"), false);
});

test("falls back to the real OpenLake RPC listener when the dedicated telemetry port is absent", async context => {
  const daemon = createServer((request, response) => {
    if (request.url === "/v1/telemetry/openlake") {
      response.setHeader("content-type", "application/json");
      response.end(JSON.stringify({
        node_id: 4,
        openlake: {
          data_paths: [],
          kv_cache: null,
          mode: "kv",
          transport: "h2",
          version: "0.7.0",
        },
      }));
      return;
    }
    response.writeHead(404).end();
  });
  await new Promise(resolve => daemon.listen(0, "127.0.0.1", resolve));
  context.after(() => new Promise(resolve => daemon.close(resolve)));
  const address = daemon.address();
  assert.equal(typeof address, "object");

  const directory = await mkdtemp(join(tmpdir(), "openlake-rpc-telemetry-"));
  context.after(() => rm(directory, { force: true, recursive: true }));
  const configPath = join(directory, "openlake.toml");
  await writeFile(configPath, `
self_id = 0
mode = "kv"
kv_agents = ["127.0.0.1:${address.port}"]

[[nodes]]
id = 0
rpc_addr = "127.0.0.1:${address.port}"
disk_count = 0
`);

  const config = await loadControlPlaneConfig(configPath);
  assert.equal(config.nodes[0].rpcOrigin, `http://127.0.0.1:${address.port}`);
  const poller = new TelemetryPoller(config, { intervalMs: 60_000, timeoutMs: 500 });
  context.after(() => poller.stop());
  await poller.start();

  const snapshot = poller.snapshot();
  assert.deepEqual(snapshot.totals, { configured: 1, degraded: 1, healthy: 0, unreachable: 0 });
  assert.equal(snapshot.nodes[0].openlake.node_id, 4);
  assert.match(snapshot.nodes[0].errors.vllm, /HTTP 404/);
});


test("serves nested RSC routes through the application worker", async context => {
  const telemetry = createServer((_request, response) => response.writeHead(404).end());
  await new Promise(resolve => telemetry.listen(0, "127.0.0.1", resolve));
  context.after(() => new Promise(resolve => telemetry.close(resolve)));
  const telemetryAddress = telemetry.address();
  assert.equal(typeof telemetryAddress, "object");

  const directory = await mkdtemp(join(tmpdir(), "openlake-control-plane-rsc-"));
  context.after(() => rm(directory, { force: true, recursive: true }));
  const configPath = join(directory, "openlake.toml");
  await writeFile(configPath, `
self_id = 0
mode = "kv"
kv_agents = ["127.0.0.1:${telemetryAddress.port - 1}"]

[[nodes]]
id = 0
rpc_addr = "127.0.0.1:${telemetryAddress.port - 1}"
disk_count = 0
`);

  const runtime = await startControlPlane({
    configPath,
    intervalMs: 60_000,
    listen: { host: "127.0.0.1", port: 0 },
    timeoutMs: 1000,
  });
  context.after(() => {
    runtime.poller.stop();
    return new Promise(resolve => runtime.server.close(resolve));
  });
  const controlPlaneAddress = runtime.server.address();
  assert.equal(typeof controlPlaneAddress, "object");

  for (const route of ["/nodes.rsc?_rsc", "/fleet.rsc?_rsc"]) {
    const response = await fetch(`http://127.0.0.1:${controlPlaneAddress.port}${route}`, {
      headers: { accept: "text/x-component", RSC: "1" },
    });
    assert.equal(response.status, 200, route);
    assert.match(response.headers.get("content-type") ?? "", /^text\/x-component\b/i, route);
  }
});
