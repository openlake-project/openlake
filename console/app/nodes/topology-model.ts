import type { HardwareSnapshot } from "../control-plane-data";

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
