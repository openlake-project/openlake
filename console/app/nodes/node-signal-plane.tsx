"use client";

import { type CSSProperties, type PointerEvent as ReactPointerEvent, useEffect, useRef, useState } from "react";
import { X } from "lucide-react";
import { activeNodes, formatBytes, type ControlPlaneNode, type HardwareSnapshot, useControlPlaneSnapshot } from "../control-plane-data";
import { ControlPlaneStatus, TelemetryUnavailable } from "../control-plane-status";
import { AppShell } from "../shell";
import { brandFromCpuModel, brandFromVendor } from "./telemetry-brand";
import { TelemetryMark } from "./telemetry-mark";
import { buildFabricTopology, buildTopologyGroups, pcieDeviceForAddress, shouldRenderAsHostDeviceRail, type FabricBackbone, type TopologyBridge, type TopologyGpu, type TopologyGroup, type TopologyNic } from "./topology-model";

type InspectorRecord = {
  nodeId: number;
  kind: string;
  title: string;
  identifier: string;
  summary: string;
  attributes: Array<[string, string]>;
};

type InspectorAttribute = [string, string | number | null | undefined];

const BASE_NODE_WIDTH = 1244;
const NODE_HEIGHT = 850;
const NODE_GAP = 120;
const FABRIC_GROUP_GAP = 180;
const FABRIC_SPINE_HEIGHT = 148;
const HOST_DEVICE_RAIL_HEIGHT = 64;

function topologyNodeWidth(hardware: HardwareSnapshot) {
  const localityCount = buildTopologyGroups(hardware).filter(group => !shouldRenderAsHostDeviceRail(group)).length;
  return Math.max(BASE_NODE_WIDTH, Math.max(1, localityCount) * 570 + 70);
}

function topologyNodeHeight(hardware: HardwareSnapshot) {
  return NODE_HEIGHT + (buildTopologyGroups(hardware).some(shouldRenderAsHostDeviceRail) ? HOST_DEVICE_RAIL_HEIGHT : 0);
}

function fitTopology(viewport: HTMLDivElement | null, stageWidth: number, stageHeight: number, updateZoom: (zoom: number) => void) {
  if (!viewport) return;
  const next = Math.max(0.35, Math.min(1, (viewport.clientWidth - 80) / stageWidth, (viewport.clientHeight - 80) / stageHeight));
  updateZoom(next);
  requestAnimationFrame(() => {
    requestAnimationFrame(() => {
      const stage = viewport.querySelector<HTMLElement>(".operator-stage-space");
      if (!stage) return;
      viewport.scrollLeft = Math.max(0, stage.offsetLeft + (stage.offsetWidth - viewport.clientWidth) / 2);
      viewport.scrollTop = Math.max(0, stage.offsetTop + (stage.offsetHeight - viewport.clientHeight) / 2);
    });
  });
}

function optionalBytes(bytes: number | null | undefined) {
  return bytes === null || bytes === undefined ? "Not reported" : formatBytes(bytes);
}

function timestamp(unixMs: number | null | undefined) {
  if (!unixMs) return null;
  return new Date(unixMs).toLocaleString();
}

function joined(values: Array<string | number | null | undefined>) {
  const reported = values.filter(value => value !== null && value !== undefined && value !== "");
  return reported.length ? reported.join(", ") : null;
}

function pcieGeneration(speed: string | null | undefined) {
  const transfers = Number.parseFloat(speed ?? "");
  const generations = new Map([
    [2.5, "1.0"],
    [5, "2.0"],
    [8, "3.0"],
    [16, "4.0"],
    [32, "5.0"],
    [64, "6.0"],
  ]);
  return generations.get(transfers) ?? null;
}

function pcieCapability(device: HardwareSnapshot["pci_devices"][number] | undefined, includeName = false) {
  if (!device) return includeName ? "PCIe capability unavailable" : "CAPABILITY UNAVAILABLE";
  const speed = device.current_link_speed ?? device.max_link_speed;
  const width = device.current_link_width ?? device.max_link_width;
  const generation = pcieGeneration(speed);
  const prefix = includeName ? "PCIe " : "";
  if (generation && width) return `${prefix}${generation} ×${width}`;
  if (speed && width) return `${prefix}${speed} ×${width}`;
  if (speed) return `${prefix}${speed}`;
  if (width) return `${prefix}×${width}`;
  return includeName ? "PCIe capability unavailable" : "CAPABILITY UNAVAILABLE";
}

function formatNicSpeed(speedMbps: number | null | undefined) {
  if (!speedMbps) return null;
  return speedMbps >= 1000 ? `${speedMbps / 1000} Gb/s` : `${speedMbps} Mb/s`;
}

function nicCapability(network: HardwareSnapshot["network_interfaces"][number], hardware: HardwareSnapshot) {
  const ethernetRate = formatNicSpeed(network.speed_mbps);
  if (ethernetRate) return ethernetRate;
  const infiniband = hardware.infiniband_devices.find(device =>
    device.name === network.infiniband_device ||
    (network.pci_address && device.pci_address === network.pci_address));
  return infiniband?.ports.find(port => port.rate)?.rate ?? null;
}

function inspector(
  nodeId: number,
  kind: string,
  title: string,
  identifier: string,
  summary: string,
  attributes: InspectorAttribute[],
): InspectorRecord {
  const reportedAttributes: Array<[string, string]> = [];
  for (const [label, entry] of attributes) {
    if (entry === null || entry === undefined || entry === "") continue;
    reportedAttributes.push([label, String(entry)]);
  }
  return {
    nodeId,
    kind,
    title,
    identifier,
    summary,
    attributes: reportedAttributes,
  };
}

function DeviceInspector({ record, close }: { record: InspectorRecord; close: () => void }) {
  return <aside className="signal-inspector" aria-label={`${record.title} details`}>
    <header className="inspector-header">
      <span className="inspector-eyebrow">NODE-{record.nodeId} / {record.kind.toUpperCase()}</span>
      <button onClick={close} aria-label="Close component details"><X size={16}/></button>
    </header>
    <div className="device-passport-hero">
      <div className="device-passport-mark"><span>{record.kind.slice(0, 4).toUpperCase()}</span><i/></div>
      <div><span className="device-passport-vendor">Physical inventory</span><strong>{record.title}</strong><p>{record.summary}</p></div>
    </div>
    <div className="device-passport-id"><span>DEVICE ID</span><code>{record.identifier}</code></div>
    <section className="device-passport-section">
      <h3>Reported attributes</h3>
      <dl>{record.attributes.map(([label, entry]) => <div key={label}><dt>{label}</dt><dd>{entry}</dd></div>)}</dl>
    </section>
  </aside>;
}

function FabricSpine({ backbone, columns, nodeWidth, width }: {
  backbone: FabricBackbone;
  columns: number;
  nodeWidth: number;
  width: number;
}) {
  const title = backbone.kind === "rdma"
    ? "RDMA FABRIC"
    : backbone.kind === "tcp" ? "TCP DATA PLANE" : "MULTI-TRANSPORT FABRIC";
  return <div className={`fabric-spine is-${backbone.kind}`} style={{ width }} aria-label={`${title} connecting nodes ${backbone.nodeIds.join(", ")}`}>
    <div className="fabric-spine-track"/>
    {Array.from({ length: columns }, (_, column) => <i
      className="fabric-spine-port"
      key={column}
      style={{ left: column * (nodeWidth + NODE_GAP) + nodeWidth / 2 }}
    />)}
    <div className="fabric-spine-identity">
      <span>OBSERVED BACKBONE</span>
      <strong>{title}</strong>
      <small>{backbone.links.length} RECIPROCAL PATH{backbone.links.length === 1 ? "" : "S"} · {backbone.transports.map(transport => transport.toUpperCase()).join(" + ")}</small>
    </div>
  </div>;
}

function UnverifiedFabric({ count }: { count: number }) {
  return <div className="fabric-unverified" aria-label="No reciprocal fabric path observed">
    <span>FABRIC DISCOVERY</span>
    <strong>NO RECIPROCAL DATA PATH OBSERVED</strong>
    <small>{count ? `${count} ONE-SIDED OBSERVATION${count === 1 ? "" : "S"} HELD OUT OF THE MAP` : "WAITING FOR PEER CAPABILITIES"}</small>
  </div>;
}

function NodeDiagram({ node, hardware, select, selected, width, height }: {
  node: ControlPlaneNode;
  hardware: HardwareSnapshot;
  select: (record: InspectorRecord) => void;
  selected: InspectorRecord | null;
  width: number;
  height: number;
}) {
  const gpus = hardware.gpus;
  const reportedNics = hardware.network_interfaces.filter(network => network.name !== "lo");
  const physicalNics = reportedNics.filter(network => network.pci_address || network.infiniband_device || /^(en|eth|ib|mlx|bond)/.test(network.name));
  const nics = physicalNics.length ? physicalNics : reportedNics;
  const topologyGroups = buildTopologyGroups(hardware);
  const hostDeviceGroup = topologyGroups.find(shouldRenderAsHostDeviceRail) ?? null;
  const localityGroups = topologyGroups.filter(group => !shouldRenderAsHostDeviceRail(group));
  const reportedBridges = [...new Map(topologyGroups.flatMap(group => group.bridges).map(bridge => [bridge.address, bridge])).values()];
  const pciSubsystem = hardware.subsystems.find(subsystem => subsystem.subsystem === "pci");
  const kv = node.openlake?.openlake.kv_cache;
  const kvUsed = kv?.used_bytes ?? (
    kv?.used_slots !== null && kv?.used_slots !== undefined && kv.slot_bytes
      ? kv.used_slots * kv.slot_bytes
      : null
  );
  const kvCapacity = kv?.configured_capacity_bytes ?? hardware.openlake.kv_cache_capacity_bytes;
  const kvUsageReported = kvUsed !== null && Boolean(kvCapacity);
  const kvPercent = kvUsageReported && kvCapacity ? Math.min(100, (kvUsed / kvCapacity) * 100) : 0;
  const diskCapacity = hardware.disks.reduce((total, disk) => total + (disk.size_bytes ?? 0), 0);
  const nvlinkCount = gpus.reduce((total, gpu) => total + gpu.nvlinks.length, 0);
  const systemName = [hardware.system.vendor, hardware.system.product_name].filter(Boolean).join(" ") || hardware.system.hostname || `node-${node.id}`;
  const cpuBrand = brandFromCpuModel(hardware.cpu.model);
  const subsystemAttributes: InspectorAttribute[] = hardware.subsystems.map(subsystem => [
    `Subsystem · ${subsystem.subsystem.replaceAll("_", " ")}`,
    `${subsystem.status.toUpperCase()}${subsystem.detail ? ` · ${subsystem.detail}` : ""}`,
  ]);
  const numaAttributes: InspectorAttribute[] = hardware.numa_nodes.flatMap(numa => [
    [`NUMA ${numa.id} memory`, numa.memory_total_bytes === null ? null : optionalBytes(numa.memory_total_bytes)],
    [`NUMA ${numa.id} CPUs`, joined(numa.logical_cpus)],
    [`NUMA ${numa.id} PCI devices`, joined(numa.pci_devices)],
  ] as InspectorAttribute[]);
  const cpuPackageAttributes: InspectorAttribute[] = hardware.cpu.packages.flatMap(cpuPackage => [
    [`Package ${cpuPackage.id} core IDs`, joined(cpuPackage.cores.map(core => core.id))],
    [`Package ${cpuPackage.id} logical CPUs`, joined(cpuPackage.cores.flatMap(core => core.logical_cpus))],
  ] as InspectorAttribute[]);
  const pciInventoryAttributes: InspectorAttribute[] = hardware.pci_devices.flatMap(device => [
    [`PCI ${device.address} identity`, joined([
      device.vendor_name ?? device.vendor_id,
      device.device_id,
      device.device_type.replaceAll("_", " "),
      device.class_id,
      device.subsystem_vendor_id,
      device.subsystem_device_id,
    ])],
    [`PCI ${device.address} negotiated`, joined([device.current_link_speed, device.current_link_width ? `×${device.current_link_width}` : null])],
    [`PCI ${device.address} maximum`, joined([device.max_link_speed, device.max_link_width ? `×${device.max_link_width}` : null])],
    [`PCI ${device.address} attachment`, joined([device.driver, device.numa_node === null ? null : `NUMA ${device.numa_node}`, device.parent_address])],
  ] as InspectorAttribute[]);
  const networkAttributes: InspectorAttribute[] = nics.flatMap(network => [
    [`${network.name} state`, network.operational_state],
    [`${network.name} MAC`, network.mac_address],
    [`${network.name} MTU`, network.mtu],
    [`${network.name} speed`, formatNicSpeed(network.speed_mbps)],
    [`${network.name} duplex`, network.duplex],
    [`${network.name} PCI`, network.pci_address],
    [`${network.name} NUMA`, network.numa_node],
    [`${network.name} driver`, network.driver],
    [`${network.name} RDMA device`, network.infiniband_device],
  ] as InspectorAttribute[]);
  const infinibandAttributes: InspectorAttribute[] = hardware.infiniband_devices.flatMap(device => [
    [`IB ${device.name} firmware`, device.firmware_version],
    [`IB ${device.name} GUID`, device.node_guid],
    [`IB ${device.name} PCI`, device.pci_address],
    [`IB ${device.name} NUMA`, device.numa_node],
    ...device.ports.flatMap(port => [
      [`IB ${device.name} port ${port.port} state`, port.state],
      [`IB ${device.name} port ${port.port} physical`, port.physical_state],
      [`IB ${device.name} port ${port.port} rate`, port.rate],
      [`IB ${device.name} port ${port.port} layer`, port.link_layer],
    ] as InspectorAttribute[]),
  ] as InspectorAttribute[]);
  const diskAttributes: InspectorAttribute[] = hardware.disks.flatMap(disk => [
    [`Disk ${disk.name} path`, disk.device_path],
    [`Disk ${disk.name} device number`, disk.major_minor],
    [`Disk ${disk.name} capacity`, disk.size_bytes === null ? null : optionalBytes(disk.size_bytes)],
    [`Disk ${disk.name} media`, disk.rotational === null ? null : disk.rotational ? "Rotational" : "Solid state"],
    [`Disk ${disk.name} vendor`, disk.vendor],
    [`Disk ${disk.name} model`, disk.model],
    [`Disk ${disk.name} transport`, disk.transport],
    [`Disk ${disk.name} PCI`, disk.pci_address],
    [`Disk ${disk.name} NUMA`, disk.numa_node],
  ] as InspectorAttribute[]);
  const dataPathAttributes: InspectorAttribute[] = hardware.openlake.data_paths.flatMap((dataPath, index) => [
    [`Data path ${index + 1}`, dataPath.path],
    [`Data path ${index + 1} mount`, dataPath.mount_point],
    [`Data path ${index + 1} filesystem`, dataPath.filesystem],
    [`Data path ${index + 1} mount origin`, dataPath.source],
    [`Data path ${index + 1} device`, dataPath.device],
    [`Data path ${index + 1} disk`, dataPath.disk],
  ] as InspectorAttribute[]);
  const kvAttributes: InspectorAttribute[] = [
    ["Connector state", kv ? kv.attached ? "Attached" : "Waiting for connector" : null],
    ["Configured capacity", kvCapacity == null ? null : optionalBytes(kvCapacity)],
    ["Committed bytes", kvUsed == null ? null : optionalBytes(kvUsed)],
    ["Slot size", kv?.slot_bytes === null || kv?.slot_bytes === undefined ? null : optionalBytes(kv.slot_bytes)],
    ["Slot count", kv?.slot_count],
    ["Committed slots", kv?.used_slots],
  ];

  const selectSystem = () => select(inspector(
    node.id,
    "system",
    systemName,
    hardware.system.hostname ?? `node-${node.id}`,
    "System identity reported by the host firmware and operating system.",
    [
      ["Inventory schema", hardware.schema_version],
      ["Inventory collected", timestamp(hardware.collected_at_unix_ms)],
      ["Collection status", hardware.collection_status],
      ["Node state", node.status],
      ["RPC address", node.rpcAddress],
      ["Telemetry address", node.telemetryAddress],
      ["Observed", node.observedAt],
      ["Last successful poll", node.lastSuccessfulAt],
      ["Poll latency", node.latencyMs === null ? null : `${node.latencyMs} ms`],
      ["OpenLake error", node.errors.openlake],
      ["Inference error", node.errors.vllm],
      ["Vendor", hardware.system.vendor],
      ["Product", hardware.system.product_name],
      ["Version", hardware.system.product_version],
      ["Board vendor", hardware.system.board_vendor],
      ["Board", hardware.system.board_name],
      ["Operating system", hardware.system.operating_system],
      ["Kernel", hardware.system.kernel_release],
      ["Architecture", hardware.system.architecture],
      ...subsystemAttributes,
      ...pciInventoryAttributes,
    ],
  ));

  const selectGpu = (gpu: TopologyGpu, position: number) => select(inspector(
    node.id,
    "gpu",
    gpu.name,
    gpu.uuid ?? gpu.pci_address ?? `gpu-${position}`,
    "Accelerator identity, locality, memory capacity, and reported interconnect inventory.",
    [
      ["GPU", gpu.index ?? position],
      ["Vendor", gpu.vendor],
      ["Telemetry source", gpu.source],
      ["PCI address", gpu.pci_address],
      ["NUMA node", gpu.numa_node],
      [gpu.vendor === "Apple" ? "Memory model" : "HBM", gpu.vendor === "Apple" ? "Unified host memory" : optionalBytes(gpu.memory_total_bytes)],
      ["NVLinks", gpu.nvlinks.length],
      ...gpu.nvlinks.flatMap(link => [
        [`NVLink ${link.link} state`, link.state],
        [`NVLink ${link.link} capability`, link.bandwidth_gbps === null ? null : `${link.bandwidth_gbps} GB/s`],
        [`NVLink ${link.link} peer`, link.peer_pci_address],
      ] as InspectorAttribute[]),
    ],
  ));

  const selectBridge = (bridge: TopologyBridge) => select(inspector(
    node.id,
    "pcie",
    "PCIe bridge",
    bridge.address,
    "A PCI bridge present in the reported parent chain of an accelerator in this locality group.",
    [
      ["Address", bridge.address],
      ["Class ID", bridge.class_id],
      ["Current speed", bridge.current_link_speed],
      ["Current width", bridge.current_link_width ? `×${bridge.current_link_width}` : null],
      ["Maximum speed", bridge.max_link_speed],
      ["Maximum width", bridge.max_link_width ? `×${bridge.max_link_width}` : null],
      ["Vendor", bridge.vendor_name],
      ["Vendor ID", bridge.vendor_id],
      ["Device ID", bridge.device_id],
      ["Driver", bridge.driver],
      ["NUMA node", bridge.numa_node],
      ["Parent", bridge.parent_address],
    ],
  ));

  const selectNic = (network: TopologyNic) => select(inspector(
    node.id,
    "nic",
    network.infiniband_device ?? network.name,
    network.pci_address ?? network.mac_address ?? network.name,
    "Network identity and link capability with reported PCI and NUMA locality.",
    [
      ["Interface", network.name],
      ["State", network.operational_state],
      ["MTU", network.mtu],
      ["MAC address", network.mac_address],
      ["Link capability", nicCapability(network, hardware)],
      ["Duplex", network.duplex],
      ["PCI address", network.pci_address],
      ["NUMA node", network.numa_node],
      ["Driver", network.driver],
      ["InfiniBand device", network.infiniband_device],
      ...networkAttributes,
      ...infinibandAttributes,
    ],
  ));

  const selectCpuGroup = (group: TopologyGroup) => select(inspector(
    node.id,
    "cpu",
    hardware.cpu.model ?? `${hardware.cpu.architecture} processor`,
    group.numaNode === null ? `node-${node.id}-cpu` : `node-${node.id}-numa-${group.numaNode}`,
    group.locality === "numa"
      ? "CPU and memory affinity reported for this NUMA locality group."
      : "Host processor inventory; NUMA locality was not reported.",
    [
      ["Packages", hardware.cpu.package_count],
      ["Package IDs in locality", joined(group.cpuPackageIds)],
      ["Physical cores", hardware.cpu.physical_core_count],
      ["Logical CPUs in locality", group.logicalCpuCount],
      ["Logical CPUs on host", hardware.cpu.logical_cpu_count],
      ["Architecture", hardware.cpu.architecture],
      ["NUMA node", group.numaNode],
      ["Local memory", group.memoryTotalBytes === null ? null : optionalBytes(group.memoryTotalBytes)],
      ...cpuPackageAttributes,
      ...numaAttributes,
    ],
  ));

  const nicModule = (network: TopologyNic, compact = false) => {
    const nicPci = pcieDeviceForAddress(hardware, network.pci_address);
    const nicBrand = brandFromVendor(nicPci?.vendor_name);
    const bandwidth = nicCapability(network, hardware);
    const primaryMetric = bandwidth ?? network.operational_state?.toUpperCase() ?? "UNREPORTED";
    return <button className={`operator-module locality-nic ${compact ? "host-device-nic" : ""} ${selected?.identifier === (network.pci_address ?? network.mac_address ?? network.name) ? "is-selected" : ""}`} key={network.name} onClick={() => selectNic(network)}>
      <span className="locality-device-title">
        {nicBrand ? <TelemetryMark brand={nicBrand} matchedFrom="NIC PCI vendor"/> : null}
        <strong>NIC · {network.name}</strong>
      </span>
      <span className="locality-primary-metric nic-primary-metric">
        <strong className={bandwidth ? undefined : "is-status"}>{primaryMetric}</strong>
        <em>{bandwidth ? "LINK BANDWIDTH" : "LINK STATE"}</em>
      </span>
      <small>{network.infiniband_device ?? network.driver ?? network.pci_address ?? "HOST INTERFACE"}</small>
    </button>;
  };

  return <section className="operator-node" style={{ "--node-width": `${width}px`, "--node-height": `${height}px` } as CSSProperties} aria-label={`Hardware topology for node-${node.id}`}>
    <div className="operator-node-meta">
      <button className="node-identity-button" onClick={selectSystem}><span>NODE-{node.id}</span><b>{systemName}</b></button>
      <span>{topologyGroups.some(group => group.locality === "numa") ? "NUMA LOCALITY REPORTED" : "HOST LOCALITY"} · {hardware.collection_status.toUpperCase()} · {hardware.system.architecture.toUpperCase()}</span>
    </div>

    <div className="topology-configuration-label"><span>REPORTED CONFIGURATION</span><b>{gpus.length} GPU · {hardware.cpu.package_count ?? "—"} CPU PACKAGE · {nics.length} NIC · {hardware.numa_nodes.length || "NO"} NUMA</b></div>

    <div className="locality-groups" style={{ "--topology-groups": Math.max(1, localityGroups.length) } as CSSProperties}>
      {localityGroups.map(group => <section className={`locality-group locality-${group.locality}`} key={group.id}>
        <header className="locality-header">
          <strong>{group.label}</strong>
          <span>{group.gpus.length} GPU · {group.nics.length} NIC{group.memoryTotalBytes ? ` · ${optionalBytes(group.memoryTotalBytes)}` : ""}</span>
        </header>

        {group.gpus.length ? <div className="locality-gpu-grid" style={{ "--locality-gpu-columns": Math.min(group.gpus.length, 4) } as CSSProperties}>
          {group.gpus.map((gpu, position) => {
            const recordIdentifier = gpu.uuid ?? gpu.pci_address ?? `gpu-${position}`;
            const gpuBrand = brandFromVendor(gpu.vendor);
            const pciDevice = pcieDeviceForAddress(hardware, gpu.pci_address);
            return <button className={`operator-module locality-gpu ${selected?.identifier === recordIdentifier ? "is-selected" : ""}`} key={recordIdentifier} onClick={() => selectGpu(gpu, position)}>
              <span className="locality-device-title">
                {gpuBrand && gpuBrand !== "apple" ? <TelemetryMark brand={gpuBrand} matchedFrom="GPU vendor"/> : null}
                <strong>GPU {gpu.index ?? position}</strong>
              </span>
              <span className="locality-device-model">{gpu.name}</span>
              <span className="locality-primary-metric gpu-primary-metric">
                <strong className={gpu.memory_total_bytes === null ? "is-status" : undefined}>{optionalBytes(gpu.memory_total_bytes)}</strong>
                <em>{gpu.vendor === "Apple" ? "UNIFIED MEMORY" : "HBM"}</em>
              </span>
              <small>{pciDevice ? pcieCapability(pciDevice, true) : "LINK NOT REPORTED"}</small>
            </button>;
          })}
        </div> : <div className="locality-empty-device"><strong>NO ACCELERATOR REPORTED</strong><span>The host inventory returned no GPU for this locality.</span></div>}

        {(group.gpus.length || group.bridges.length) ? <div className="locality-fabric-rail">
          <b>{group.bridges.length ? "GPU PCIe HIERARCHY" : nvlinkCount ? `${nvlinkCount} REPORTED NVLINKS` : "ACCELERATOR LINKS UNREPORTED"}</b>
          <span>{group.bridges.length ? `${group.bridges.length} BRIDGE${group.bridges.length === 1 ? "" : "S"} IN REPORTED PARENT CHAIN` : pciSubsystem?.status?.toUpperCase() ?? "UNAVAILABLE"}</span>
        </div> : null}

        <div className="locality-host-grid">
          <div className="locality-io-bank">
            {group.bridges.map(bridge => <button className={`operator-module locality-bridge ${selected?.identifier === bridge.address ? "is-selected" : ""}`} key={bridge.address} onClick={() => selectBridge(bridge)}>
              <span><strong>PCI BRIDGE</strong><b>{pcieCapability(bridge)}</b></span>
              <code>{bridge.address}</code>
              <small>{bridge.vendor_name ?? bridge.vendor_id ?? "VENDOR UNREPORTED"}</small>
            </button>)}
            {group.nics.map(network => nicModule(network))}
            {!group.bridges.length && !group.nics.length ? <span className="locality-io-empty">NO LOCAL PCI BRIDGE OR NIC RELATIONSHIP REPORTED</span> : null}
          </div>

          {group.cpuAffinityReported ? <button className={`operator-module locality-cpu ${selected?.identifier === (group.numaNode === null ? `node-${node.id}-cpu` : `node-${node.id}-numa-${group.numaNode}`) ? "is-selected" : ""}`} onClick={() => selectCpuGroup(group)}>
            <span className="locality-device-title">
              {cpuBrand ? <TelemetryMark brand={cpuBrand} matchedFrom="CPU model signature"/> : null}
              <strong>{group.locality === "numa" ? `CPU AFFINITY / NUMA ${group.numaNode}` : "CPU"}</strong>
            </span>
            <span className="locality-device-model">{hardware.cpu.model ?? hardware.cpu.architecture}</span>
            <div className="locality-cpu-facts">
              <span><b>PACKAGE ID</b><strong>{group.cpuPackageIds.length ? group.cpuPackageIds.join(", ") : "UNREPORTED"}</strong></span>
              <span><b>LOGICAL CPU</b><strong>{group.logicalCpuCount ?? hardware.cpu.logical_cpu_count}</strong></span>
              <span><b>MEMORY</b><strong>{optionalBytes(group.memoryTotalBytes ?? hardware.memory.total_bytes)}</strong></span>
            </div>
          </button> : <div className="locality-cpu-unreported">
            <strong>CPU LOCALITY NOT REPORTED</strong>
            <span>No CPU package or memory affinity is inferred for these devices.</span>
          </div>}
        </div>
      </section>)}
    </div>

    {hostDeviceGroup ? <section className="host-device-rail" aria-label="Host devices with unreported locality">
      <header><strong>HOST DEVICES</strong><span>LOCALITY UNREPORTED · NOT ASSIGNED TO A NUMA DOMAIN</span></header>
      <div className="host-device-modules">{hostDeviceGroup.nics.map(network => nicModule(network, true))}</div>
    </section> : null}

    <div className="topology-certainty-rail">
      <b>{reportedBridges.length ? `${reportedBridges.length} PCI BRIDGE${reportedBridges.length === 1 ? "" : "S"} MAPPED FROM PARENT ADDRESSES` : "PHYSICAL SWITCH TOPOLOGY NOT REPORTED"}</b>
      <span>{nvlinkCount ? `${nvlinkCount} NVLINK RECORDS` : "NO ACCELERATOR INTERCONNECT CLAIMED"}</span>
    </div>

    <section className={`openlake-slab ${kv ? "has-telemetry" : ""} ${selected?.kind === "openlake" && selected.nodeId === node.id ? "is-selected" : ""}`}>
      <button className="openlake-slab-title openlake-runtime-node" onClick={() => select(inspector(
        node.id,
        "openlake",
        "OpenLake KV cache",
        `node-${node.id}-openlake`,
        "OpenLake allocation mapped onto the host memory and configured storage devices.",
        [
          ["Runtime schema", node.openlake?.schema_version],
          ["Runtime collected", timestamp(node.openlake?.collected_at_unix_ms)],
          ["Node ID", node.openlake?.node_id],
          ["Version", node.openlake?.openlake.version],
          ["Mode", node.openlake?.openlake.mode],
          ["Transport", node.openlake?.openlake.transport],
          ...kvAttributes,
          ["Configured runtime paths", joined(node.openlake?.openlake.data_paths ?? [])],
          ["Data paths", hardware.openlake.data_paths.length],
          ["Attached disks", hardware.openlake.data_paths.map(path => path.disk).filter(Boolean).join(", ") || "Not resolved"],
          ...dataPathAttributes,
        ],
      ))}>
        <span className="openlake-runtime-copy"><strong>OPENLAKE</strong><small>KV CACHE</small></span>
        <span className="openlake-runtime-detail">{node.openlake?.openlake.mode.toUpperCase() ?? "KV"} TIER · {node.openlake?.openlake.transport.toUpperCase() ?? "TRANSPORT UNAVAILABLE"}</span>
        <span className={`openlake-runtime-state ${kv?.attached ? "is-attached" : kv ? "is-waiting" : ""}`}><i/>{kv?.attached ? "ATTACHED" : kv ? "WAITING" : "UNAVAILABLE"}</span>
      </button>
      <div className="openlake-resources">
        <button className="operator-module resource-module" onClick={() => select(inspector(
          node.id,
          "memory",
          "OpenLake RAM allocation",
          `node-${node.id}-ram`,
          "KV slab capacity and current committed occupancy inside host memory.",
          [
            ["Host memory", hardware.memory.total_bytes === null ? null : optionalBytes(hardware.memory.total_bytes)],
            ["Available at inventory", hardware.memory.available_bytes === null ? null : optionalBytes(hardware.memory.available_bytes)],
            ...kvAttributes,
            ["NUMA nodes", hardware.numa_nodes.length],
            ...numaAttributes,
          ],
        ))}>
          <strong>RAM <span>{optionalBytes(kvCapacity)}</span></strong>
          <div className="capacity-track"><i style={{ width: `${kvPercent}%` }}/></div>
          <div className="capacity-scale"><span>0</span><span>{kvUsageReported ? `${kvPercent.toFixed(1)}% COMMITTED` : "USAGE UNREPORTED"}</span><span>{optionalBytes(kvCapacity)}</span></div>
          <footer>HOST {optionalBytes(hardware.memory.total_bytes)} · {hardware.numa_nodes.length ? `${hardware.numa_nodes.length} NUMA DOMAIN${hardware.numa_nodes.length === 1 ? "" : "S"}` : "NUMA UNREPORTED"}</footer>
        </button>
        <button className="operator-module resource-module" onClick={() => select(inspector(
          node.id,
          "disk",
          "OpenLake disk allocation",
          `node-${node.id}-disk`,
          "Configured OpenLake data paths resolved through mount tables to host block devices.",
          [
            ["Host devices", hardware.disks.length],
            ["Raw capacity", optionalBytes(diskCapacity)],
            ["Data paths", hardware.openlake.data_paths.length],
            ["Mounts", hardware.openlake.data_paths.map(path => path.mount_point).filter(Boolean).join(", ") || "Not resolved"],
            ["Filesystems", [...new Set(hardware.openlake.data_paths.map(path => path.filesystem).filter(Boolean))].join(", ") || "Not resolved"],
            ...diskAttributes,
            ...dataPathAttributes,
          ],
        ))}>
          <strong>DISK <span>{optionalBytes(diskCapacity)}</span></strong>
          <div className="capacity-track is-inventory"><i style={{ width: "0%" }}/></div>
          <div className="capacity-scale"><span>{hardware.disks.length} DEVICES</span><span>UTILIZATION UNREPORTED</span><span>{hardware.openlake.data_paths.length} PATHS</span></div>
          <footer>{hardware.openlake.data_paths.map(path => path.disk ?? path.source ?? path.path).join(" · ") || "NO DATA PATHS"}</footer>
        </button>
      </div>
    </section>

    <div className="node-boundary-annotation"><span>HOST INVENTORY</span><b>{hardware.subsystems.filter(subsystem => subsystem.status === "available").length}/{hardware.subsystems.length} SUBSYSTEMS AVAILABLE</b><span>OPENLAKE NODE-{node.id}</span></div>
  </section>;
}

function HardwareTopology({ nodes }: { nodes: ControlPlaneNode[] }) {
  const available = nodes.flatMap(node => node.openlake?.hardware ? [{ node, hardware: node.openlake.hardware }] : []);
  const canvas = useRef<HTMLDivElement>(null);
  const drag = useRef<{ x: number; y: number; left: number; top: number } | null>(null);
  const [zoom, setZoom] = useState(0.72);
  const zoomRef = useRef(zoom);
  const [selected, setSelected] = useState<InspectorRecord | null>(null);
  const nodeWidth = Math.max(BASE_NODE_WIDTH, ...available.map(({ hardware }) => topologyNodeWidth(hardware)));
  const nodeHeight = Math.max(NODE_HEIGHT, ...available.map(({ hardware }) => topologyNodeHeight(hardware)));
  const fabric = buildFabricTopology(available.map(({ node }) => node));
  const availableById = new Map(available.map(entry => [entry.node.id, entry]));
  const groups: Array<{ id: string; nodeIds: number[]; backbone: FabricBackbone | null }> = [
    ...fabric.backbones.map(backbone => ({ id: backbone.id, nodeIds: backbone.nodeIds, backbone })),
    ...(fabric.isolatedNodeIds.length ? [{ id: "fabric-unverified", nodeIds: fabric.isolatedNodeIds, backbone: null }] : []),
  ];
  const placements: Array<{
    id: number;
    left: number;
    top: number;
    side: "above" | "below";
    backbone: FabricBackbone | null;
  }> = [];
  const rails: Array<{ id: string; left: number; width: number; columns: number; backbone: FabricBackbone | null }> = [];
  let cursor = 0;
  for (const group of groups) {
    const columns = Math.max(1, Math.ceil(group.nodeIds.length / 2));
    const width = columns * nodeWidth + Math.max(0, columns - 1) * NODE_GAP;
    const splitRows = Boolean(group.backbone) || group.nodeIds.length > 2;
    group.nodeIds.forEach((id, index) => {
      const side = splitRows && index % 2 ? "below" : "above";
      const column = splitRows ? Math.floor(index / 2) : index;
      placements.push({
        id,
        left: cursor + column * (nodeWidth + NODE_GAP),
        top: side === "below" ? nodeHeight + FABRIC_SPINE_HEIGHT : 0,
        side,
        backbone: group.backbone,
      });
    });
    if (group.backbone || splitRows) rails.push({ id: group.id, left: cursor, width, columns, backbone: group.backbone });
    cursor += width + FABRIC_GROUP_GAP;
  }
  const stageWidth = Math.max(nodeWidth, cursor ? cursor - FABRIC_GROUP_GAP : nodeWidth);
  const stageHeight = placements.some(placement => placement.side === "below")
    ? nodeHeight * 2 + FABRIC_SPINE_HEIGHT
    : nodeHeight;

  useEffect(() => { zoomRef.current = zoom; }, [zoom]);
  useEffect(() => { fitTopology(canvas.current, stageWidth, stageHeight, setZoom); }, [stageWidth, stageHeight]);
  useEffect(() => {
    const viewport = canvas.current;
    if (!viewport) return undefined;
    const handleWheel = (event: globalThis.WheelEvent) => {
      event.preventDefault();
      event.stopPropagation();
      const sensitivity = event.ctrlKey ? 0.006 : 0.001;
      const next = Math.max(0.35, Math.min(1.4, zoomRef.current - event.deltaY * sensitivity));
      zoomRef.current = next;
      setZoom(next);
    };
    viewport.addEventListener("wheel", handleWheel, { passive: false });
    return () => viewport.removeEventListener("wheel", handleWheel);
  }, []);

  const pointerDown = (event: ReactPointerEvent<HTMLDivElement>) => {
    if ((event.target as HTMLElement).closest("button")) return;
    const viewport = canvas.current;
    if (!viewport) return;
    viewport.setPointerCapture(event.pointerId);
    drag.current = { x: event.clientX, y: event.clientY, left: viewport.scrollLeft, top: viewport.scrollTop };
    viewport.classList.add("is-dragging");
  };
  const pointerMove = (event: ReactPointerEvent<HTMLDivElement>) => {
    const viewport = canvas.current;
    if (!viewport || !drag.current) return;
    viewport.scrollLeft = drag.current.left - (event.clientX - drag.current.x);
    viewport.scrollTop = drag.current.top - (event.clientY - drag.current.y);
  };
  const pointerUp = (event: ReactPointerEvent<HTMLDivElement>) => {
    canvas.current?.releasePointerCapture(event.pointerId);
    canvas.current?.classList.remove("is-dragging");
    drag.current = null;
  };
  if (!available.length) return <div className="node-topology-empty"><TelemetryUnavailable title="Host inventory unavailable" detail="The connected OpenLake node has not returned the hardware inventory contract."/></div>;

  return <div className="node-console-page">
    <div className="signal-canvas" ref={canvas} onPointerDown={pointerDown} onPointerMove={pointerMove} onPointerUp={pointerUp} onPointerCancel={pointerUp}>
      <div className="operator-scroll-pad">
        <div className="operator-stage-space" style={{ width: stageWidth * zoom, height: stageHeight * zoom }}>
          <div className="operator-stage" style={{ width: stageWidth, height: stageHeight, transform: `scale(${zoom})` }}>
            {rails.map(rail => <div className="fabric-spine-slot" style={{ left: rail.left, top: nodeHeight, width: rail.width, height: FABRIC_SPINE_HEIGHT }} key={rail.id}>
              {rail.backbone
                ? <FabricSpine backbone={rail.backbone} columns={rail.columns} nodeWidth={nodeWidth} width={rail.width}/>
                : <UnverifiedFabric count={fabric.unverifiedLinkCount}/>}
            </div>)}
            {placements.map(placement => {
              const entry = availableById.get(placement.id);
              if (!entry) return null;
              const devices = placement.backbone?.devicesByNode[placement.id] ?? [];
              return <div
                className={`fabric-node-slot is-${placement.side} ${placement.backbone ? "is-connected" : "is-unverified"}`}
                style={{ left: placement.left, top: placement.top, width: nodeWidth, height: nodeHeight, "--fabric-spine-height": `${FABRIC_SPINE_HEIGHT}px` } as CSSProperties}
                key={placement.id}
              >
                <NodeDiagram node={entry.node} hardware={entry.hardware} select={setSelected} selected={selected} width={nodeWidth} height={nodeHeight}/>
                {placement.backbone ? <span className="fabric-node-drop"><i/><b>{devices.join(" + ") || "SELECTED UCX LANE"}</b></span> : null}
              </div>;
            })}
          </div>
        </div>
      </div>
    </div>
    <div className="operator-zoom" aria-label="Topology zoom controls">
      <button onClick={() => setZoom(current => Math.max(0.35, current - 0.1))} aria-label="Zoom out">−</button>
      <span className="zoom-value">{Math.round(zoom * 100)}%</span>
      <button onClick={() => setZoom(current => Math.min(1.4, current + 0.1))} aria-label="Zoom in">+</button>
      <button className="zoom-fit" onClick={() => fitTopology(canvas.current, stageWidth, stageHeight, setZoom)}>FIT</button>
    </div>
    {selected ? <DeviceInspector record={selected} close={() => setSelected(null)}/> : null}
  </div>;
}

export function NodeSignalPlane() {
  const state = useControlPlaneSnapshot();
  const nodes = activeNodes(state.snapshot);

  return <AppShell active="nodes" mainClassName="node-main" showFooter={false}>
    {state.loading || !state.snapshot || nodes.length === 0 ? <ControlPlaneStatus state={state}/> : <HardwareTopology nodes={nodes}/>}
  </AppShell>;
}
