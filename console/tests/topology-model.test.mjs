import assert from "node:assert/strict";
import test from "node:test";

import { buildTopologyGroups, shouldRenderAsHostDeviceRail } from "../app/nodes/topology-model.ts";

function hardware(overrides = {}) {
  return {
    schema_version: "1.0",
    collected_at_unix_ms: 1,
    collection_status: "available",
    system: { operating_system: "linux", architecture: "x86_64", kernel_release: null, hostname: "host", vendor: null, product_name: null, product_version: null, board_vendor: null, board_name: null },
    cpu: { architecture: "x86_64", model: "AMD EPYC 9654", logical_cpu_count: 16, physical_core_count: 8, package_count: 1, packages: [] },
    memory: { total_bytes: 64 * 1024 ** 3, available_bytes: null },
    numa_nodes: [],
    pci_devices: [],
    gpus: [],
    network_interfaces: [],
    infiniband_devices: [],
    disks: [],
    openlake: { kv_cache_capacity_bytes: null, data_paths: [] },
    subsystems: [],
    ...overrides,
  };
}

function gpu(index, numa_node, pci_address, parent_address) {
  return {
    index,
    name: `GPU ${index}`,
    vendor: "NVIDIA",
    uuid: `GPU-${index}`,
    pci_address,
    numa_node,
    memory_total_bytes: 80 * 1024 ** 3,
    nvlinks: [],
    source: "collector",
    parent_address,
  };
}

function pci(address, device_type, numa_node, parent_address = null) {
  return {
    address,
    vendor_id: "10de",
    vendor_name: "NVIDIA Corporation",
    device_id: null,
    subsystem_vendor_id: null,
    subsystem_device_id: null,
    class_id: null,
    device_type,
    driver: null,
    numa_node,
    parent_address,
    current_link_speed: "32 GT/s",
    current_link_width: 16,
    max_link_speed: "32 GT/s",
    max_link_width: 16,
  };
}

test("keeps non-NUMA hosts in one honest host group", () => {
  const groups = buildTopologyGroups(hardware({
    gpus: [gpu(0, null, null), gpu(1, null, null)],
    network_interfaces: [{ name: "en0", mac_address: null, operational_state: "active", mtu: null, speed_mbps: null, duplex: null, pci_address: null, numa_node: null, driver: null, infiniband_device: null }],
  }));

  assert.equal(groups.length, 1);
  assert.equal(groups[0].locality, "host");
  assert.equal(groups[0].gpus.length, 2);
  assert.equal(groups[0].nics.length, 1);
  assert.deepEqual(groups[0].bridges, []);
});

test("scales eight GPUs into reported NUMA groups and maps only proven parent bridges", () => {
  const gpus = Array.from({ length: 8 }, (_, index) => {
    const numa = index < 4 ? 0 : 1;
    return gpu(index, numa, `0000:${index < 4 ? 41 + index : 81 + (index - 4)}:00.0`);
  });
  const bridge0 = pci("0000:40:00.0", "bridge", 0);
  const bridge1 = pci("0000:80:00.0", "bridge", 1);
  const gpuDevices = gpus.map((entry, index) => pci(entry.pci_address, "display_controller", entry.numa_node, index < 4 ? bridge0.address : bridge1.address));
  const groups = buildTopologyGroups(hardware({
    numa_nodes: [
      { id: 0, logical_cpus: [0, 1, 2, 3], memory_total_bytes: 32 * 1024 ** 3, pci_devices: [] },
      { id: 1, logical_cpus: [4, 5, 6, 7], memory_total_bytes: 32 * 1024 ** 3, pci_devices: [] },
    ],
    pci_devices: [bridge0, bridge1, ...gpuDevices],
    gpus,
    network_interfaces: [
      { name: "mlx5_0", mac_address: null, operational_state: "active", mtu: 4092, speed_mbps: 400000, duplex: "full", pci_address: "0000:41:00.0", numa_node: 0, driver: "mlx5_core", infiniband_device: "mlx5_0" },
      { name: "mlx5_1", mac_address: null, operational_state: "active", mtu: 4092, speed_mbps: 400000, duplex: "full", pci_address: "0000:81:00.0", numa_node: 1, driver: "mlx5_core", infiniband_device: "mlx5_1" },
    ],
  }));

  assert.deepEqual(groups.map(group => group.label), ["NUMA 0", "NUMA 1"]);
  assert.deepEqual(groups.map(group => group.gpus.length), [4, 4]);
  assert.deepEqual(groups.map(group => group.nics.length), [1, 1]);
  assert.deepEqual(groups.map(group => group.bridges.map(bridge => bridge.address)), [[bridge0.address], [bridge1.address]]);
});

test("separates devices whose locality is not reported instead of guessing", () => {
  const groups = buildTopologyGroups(hardware({
    numa_nodes: [{ id: 0, logical_cpus: [0, 1], memory_total_bytes: 32 * 1024 ** 3, pci_devices: [] }],
    gpus: [gpu(0, 0, null), gpu(1, null, null)],
  }));

  assert.deepEqual(groups.map(group => group.locality), ["numa", "unreported"]);
  assert.deepEqual(groups.map(group => group.cpuAffinityReported), [true, false]);
  assert.equal(groups[0].gpus.length, 1);
  assert.equal(groups[1].gpus.length, 1);
});

test("does not invent CPU affinity when a device reports only a NUMA identifier", () => {
  const groups = buildTopologyGroups(hardware({
    gpus: [gpu(0, 3, null)],
  }));

  assert.equal(groups.length, 1);
  assert.equal(groups[0].label, "NUMA 3");
  assert.equal(groups[0].cpuAffinityReported, false);
  assert.equal(groups[0].logicalCpuCount, null);
  assert.deepEqual(groups[0].cpuPackageIds, []);
});

test("keeps a NIC with unknown locality out of the peer locality blocks", () => {
  const groups = buildTopologyGroups(hardware({
    numa_nodes: [{ id: 0, logical_cpus: [0, 1], memory_total_bytes: 32 * 1024 ** 3, pci_devices: [] }],
    network_interfaces: [{ name: "eth0", mac_address: null, operational_state: "up", mtu: 1500, speed_mbps: 100000, duplex: "full", pci_address: null, numa_node: null, driver: "hv_netvsc", infiniband_device: null }],
  }));

  assert.deepEqual(groups.map(group => group.locality), ["numa", "unreported"]);
  assert.deepEqual(groups.map(shouldRenderAsHostDeviceRail), [false, true]);
});

test("keeps an unassigned GPU as a full visible locality group", () => {
  const groups = buildTopologyGroups(hardware({
    numa_nodes: [{ id: 0, logical_cpus: [0, 1], memory_total_bytes: 32 * 1024 ** 3, pci_devices: [] }],
    gpus: [gpu(0, null, null)],
  }));

  assert.equal(shouldRenderAsHostDeviceRail(groups.at(-1)), false);
});
