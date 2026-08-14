import type { ControlPlaneNode, HardwareSnapshot, PeerDiscoverySnapshot } from "../control-plane-data";

export type TopologyGpu = HardwareSnapshot["gpus"][number];
export type TopologyNic = HardwareSnapshot["network_interfaces"][number];
export type TopologyBridge = HardwareSnapshot["pci_devices"][number];

export type TopologyGroup = {
  id: string;
  label: string;
  locality: "numa" | "unreported" | "host";
  numaNode: number | null;
  memoryTotalBytes: number | null;
  logicalCpuCount: number | null;
  cpuAffinityReported: boolean;
  cpuPackageIds: number[];
  gpus: TopologyGpu[];
  nics: TopologyNic[];
  bridges: TopologyBridge[];
};

export type FabricLink = {
  nodeIds: [number, number];
  kind: "rdma" | "tcp";
  transports: string[];
  devicesByNode: Record<number, string[]>;
};

export type FabricBackbone = {
  id: string;
  kind: "rdma" | "tcp" | "mixed";
  nodeIds: number[];
  links: FabricLink[];
  transports: string[];
  devicesByNode: Record<number, string[]>;
};

export type FabricTopology = {
  backbones: FabricBackbone[];
  isolatedNodeIds: number[];
  unverifiedLinkCount: number;
};

export type FabricNodePlacement = {
  id: number;
  column: number;
  row: 1 | 3;
  side: "above" | "below";
};

export type FabricLayoutGroup = {
  id: string;
  nodeIds: number[];
  backbone: FabricBackbone | null;
  columns: number;
  splitRows: boolean;
  showRail: boolean;
  placements: FabricNodePlacement[];
};

type PeerPath = {
  kind: "rdma" | "tcp";
  capabilities: Array<{ transport: string; device: string }>;
};

function transportKind(transport: string): "rdma" | "tcp" | null {
  const normalized = transport.toLowerCase();
  if (normalized.includes("tcp")) return "tcp";
  if (/^(?:rc|dc|ud)(?:_|$)/.test(normalized) || normalized.includes("rdma") || normalized.includes("roce") || normalized.includes("ib")) return "rdma";
  return null;
}

function peerPath(peer: PeerDiscoverySnapshot): PeerPath | null {
  if (peer.is_connected === false) return null;
  const capabilities = (peer.capabilities ?? [])
    .filter(capability => transportKind(capability.transport));
  const strongest = capabilities.some(capability => transportKind(capability.transport) === "rdma")
    ? "rdma"
    : capabilities.some(capability => transportKind(capability.transport) === "tcp") ? "tcp" : null;
  if (strongest) {
    return {
      kind: strongest,
      capabilities: capabilities.filter(capability => transportKind(capability.transport) === strongest),
    };
  }
  if (peer.status === "rdma_metadata_available" && (peer.rdma_endpoints?.length ?? 0) > 0) {
    return {
      kind: "rdma",
      capabilities: (peer.rdma_endpoints ?? []).map(endpoint => ({
        transport: "dct",
        device: endpoint.gid,
      })),
    };
  }
  return null;
}

function unique(values: string[]) {
  return [...new Set(values.filter(Boolean))].sort((left, right) => left.localeCompare(right));
}

/**
 * Build logical fabric components only from reciprocal peer observations.
 * A configured address, reachable RPC endpoint, or one-sided probe is not
 * enough to claim that two nodes share a data plane.
 */
export function buildFabricTopology(nodes: ControlPlaneNode[]): FabricTopology {
  const nodeIds = new Set(nodes.map(node => node.id));
  const pairs = new Map<string, Map<number, PeerPath>>();
  for (const node of nodes) {
    for (const peer of node.openlake?.openlake.peers ?? []) {
      if (!nodeIds.has(peer.node_id) || peer.node_id === node.id) continue;
      const path = peerPath(peer);
      if (!path) continue;
      const ordered = [node.id, peer.node_id].sort((left, right) => left - right) as [number, number];
      const key = `${ordered[0]}:${ordered[1]}`;
      const observations = pairs.get(key) ?? new Map<number, PeerPath>();
      observations.set(node.id, path);
      pairs.set(key, observations);
    }
  }

  const links: FabricLink[] = [];
  let unverifiedLinkCount = 0;
  for (const [key, observations] of pairs) {
    const [left, right] = key.split(":").map(Number) as [number, number];
    const leftToRight = observations.get(left);
    const rightToLeft = observations.get(right);
    if (!leftToRight || !rightToLeft || leftToRight.kind !== rightToLeft.kind) {
      unverifiedLinkCount += 1;
      continue;
    }
    // A→B reports B's selected server-side device; B→A reports A's.
    links.push({
      nodeIds: [left, right],
      kind: leftToRight.kind,
      transports: unique([...leftToRight.capabilities, ...rightToLeft.capabilities].map(capability => capability.transport)),
      devicesByNode: {
        [left]: unique(rightToLeft.capabilities.map(capability => capability.device)),
        [right]: unique(leftToRight.capabilities.map(capability => capability.device)),
      },
    });
  }

  const parent = new Map([...nodeIds].map(nodeId => [nodeId, nodeId]));
  const find = (nodeId: number): number => {
    const current = parent.get(nodeId) ?? nodeId;
    if (current === nodeId) return nodeId;
    const root = find(current);
    parent.set(nodeId, root);
    return root;
  };
  for (const link of links) {
    const leftRoot = find(link.nodeIds[0]);
    const rightRoot = find(link.nodeIds[1]);
    if (leftRoot !== rightRoot) parent.set(rightRoot, leftRoot);
  }

  const grouped = new Map<number, number[]>();
  for (const nodeId of nodeIds) {
    const root = find(nodeId);
    const members = grouped.get(root) ?? [];
    members.push(nodeId);
    grouped.set(root, members);
  }

  const backbones: FabricBackbone[] = [];
  const isolatedNodeIds: number[] = [];
  for (const members of grouped.values()) {
    members.sort((left, right) => left - right);
    const memberSet = new Set(members);
    const componentLinks = links.filter(link => link.nodeIds.every(nodeId => memberSet.has(nodeId)));
    if (!componentLinks.length) {
      isolatedNodeIds.push(...members);
      continue;
    }
    const kinds = new Set(componentLinks.map(link => link.kind));
    const devicesByNode = Object.fromEntries(members.map(nodeId => [
      nodeId,
      unique(componentLinks.flatMap(link => link.devicesByNode[nodeId] ?? [])),
    ]));
    backbones.push({
      id: `fabric-${members.join("-")}`,
      kind: kinds.size === 1 ? [...kinds][0] : "mixed",
      nodeIds: members,
      links: componentLinks,
      transports: unique(componentLinks.flatMap(link => link.transports)),
      devicesByNode,
    });
  }

  backbones.sort((left, right) => left.nodeIds[0] - right.nodeIds[0]);
  isolatedNodeIds.sort((left, right) => left - right);
  return { backbones, isolatedNodeIds, unverifiedLinkCount };
}

/**
 * Produce stable grid coordinates for every fabric component. Connection
 * health changes the rail treatment, not the host positions.
 */
export function buildFabricLayoutGroups(fabric: FabricTopology): FabricLayoutGroup[] {
  const groups: Array<{
    id: string;
    nodeIds: number[];
    backbone: FabricBackbone | null;
  }> = [
    ...fabric.backbones.map(backbone => ({
      id: backbone.id,
      nodeIds: backbone.nodeIds,
      backbone,
    })),
    ...(fabric.isolatedNodeIds.length ? [{
      id: "fabric-unverified",
      nodeIds: fabric.isolatedNodeIds,
      backbone: null,
    }] : []),
  ];

  return groups.map(group => {
    const splitRows = group.nodeIds.length > 2;
    const columns = Math.max(1, splitRows
      ? Math.ceil(group.nodeIds.length / 2)
      : group.nodeIds.length);
    return {
      ...group,
      columns,
      splitRows,
      showRail: Boolean(group.backbone),
      placements: group.nodeIds.map((id, index) => {
        const below = splitRows && index % 2 === 1;
        return {
          id,
          column: splitRows ? Math.floor(index / 2) + 1 : index + 1,
          row: below ? 3 : 1,
          side: below ? "below" : "above",
        };
      }),
    };
  });
}

function isPhysicalNic(network: TopologyNic) {
  return network.name !== "lo" && Boolean(
    network.pci_address ||
    network.infiniband_device ||
    /^(?:en|eth|ib|mlx|bond)/i.test(network.name),
  );
}

function cpuPackagesForNuma(hardware: HardwareSnapshot, numaId: number) {
  const numa = hardware.numa_nodes.find(node => node.id === numaId);
  if (!numa?.logical_cpus.length) return [];
  const logicalCpus = new Set(numa.logical_cpus);
  return hardware.cpu.packages
    .filter(cpuPackage => cpuPackage.cores.some(core => core.logical_cpus.some(cpu => logicalCpus.has(cpu))))
    .map(cpuPackage => cpuPackage.id);
}

function bridgesForGpus(hardware: HardwareSnapshot, gpus: TopologyGpu[]) {
  const devices = new Map(hardware.pci_devices.map(device => [device.address, device]));
  const bridgeAddresses = new Set<string>();

  for (const gpu of gpus) {
    if (!gpu.pci_address) continue;
    let device = devices.get(gpu.pci_address);
    const visited = new Set<string>();
    while (device?.parent_address && !visited.has(device.parent_address)) {
      visited.add(device.parent_address);
      const parent = devices.get(device.parent_address);
      if (!parent) break;
      if (parent.device_type === "bridge") bridgeAddresses.add(parent.address);
      device = parent;
    }
  }

  return [...bridgeAddresses]
    .map(address => devices.get(address))
    .filter((device): device is TopologyBridge => Boolean(device))
    .sort((left, right) => left.address.localeCompare(right.address));
}

/**
 * Build only relationships supported by reported inventory. Missing locality
 * becomes an explicit host/unreported group; it is never guessed from names.
 */
export function buildTopologyGroups(hardware: HardwareSnapshot): TopologyGroup[] {
  const gpus = [...hardware.gpus].sort((left, right) => (left.index ?? 0) - (right.index ?? 0));
  const nics = hardware.network_interfaces.filter(isPhysicalNic);
  const reportedNumaIds = new Set<number>(hardware.numa_nodes.map(node => node.id));
  for (const device of [...gpus, ...nics]) {
    if (device.numa_node !== null) reportedNumaIds.add(device.numa_node);
  }

  if (!reportedNumaIds.size) {
    return [{
      id: "host",
      label: "HOST TOPOLOGY",
      locality: "host",
      numaNode: null,
      memoryTotalBytes: hardware.memory.total_bytes,
      logicalCpuCount: hardware.cpu.logical_cpu_count,
      cpuAffinityReported: true,
      cpuPackageIds: hardware.cpu.packages.map(cpuPackage => cpuPackage.id),
      gpus,
      nics,
      bridges: bridgesForGpus(hardware, gpus),
    }];
  }

  const groups: TopologyGroup[] = [...reportedNumaIds]
    .sort((left, right) => left - right)
    .map(numaId => {
      const numa = hardware.numa_nodes.find(node => node.id === numaId);
      const groupGpus = gpus.filter(gpu => gpu.numa_node === numaId);
      return {
        id: `numa-${numaId}`,
        label: `NUMA ${numaId}`,
        locality: "numa" as const,
        numaNode: numaId,
        memoryTotalBytes: numa?.memory_total_bytes ?? null,
        logicalCpuCount: numa?.logical_cpus.length ?? null,
        cpuAffinityReported: Boolean(numa?.logical_cpus.length),
        cpuPackageIds: cpuPackagesForNuma(hardware, numaId),
        gpus: groupGpus,
        nics: nics.filter(network => network.numa_node === numaId),
        bridges: bridgesForGpus(hardware, groupGpus),
      };
    });

  const unassignedGpus = gpus.filter(gpu => gpu.numa_node === null);
  const unassignedNics = nics.filter(network => network.numa_node === null);
  if (unassignedGpus.length || unassignedNics.length) {
    groups.push({
      id: "locality-unreported",
      label: "LOCALITY UNREPORTED",
      locality: "unreported",
      numaNode: null,
      memoryTotalBytes: null,
      logicalCpuCount: null,
      cpuAffinityReported: false,
      cpuPackageIds: [],
      gpus: unassignedGpus,
      nics: unassignedNics,
      bridges: bridgesForGpus(hardware, unassignedGpus),
    });
  }

  return groups;
}

/**
 * A NIC-only unreported group is host-scoped inventory, not a hardware
 * locality. Keep unassigned GPUs as full groups so they remain prominent.
 */
export function shouldRenderAsHostDeviceRail(group: TopologyGroup) {
  return group.locality === "unreported" && group.gpus.length === 0;
}

export function pcieDeviceForAddress(hardware: HardwareSnapshot, address: string | null) {
  if (!address) return null;
  return hardware.pci_devices.find(device => device.address === address) ?? null;
}
