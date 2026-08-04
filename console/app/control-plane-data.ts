"use client";

import { useEffect, useState } from "react";

export type PrometheusSample = {
  name: string;
  labels: Record<string, string>;
  value: number;
};

export type KvCacheSnapshot = {
  attached: boolean;
  configured_capacity_bytes: number;
  slot_bytes: number | null;
  slot_count: number | null;
  used_slots: number | null;
  used_bytes: number;
  served_blocks?: number;
};

export type HardwareSnapshot = {
  schema_version: string;
  collected_at_unix_ms: number;
  collection_status: "available" | "partial";
  system: {
    operating_system: string;
    architecture: string;
    kernel_release: string | null;
    hostname: string | null;
    vendor: string | null;
    product_name: string | null;
    product_version: string | null;
    board_vendor: string | null;
    board_name: string | null;
  };
  cpu: {
    architecture: string;
    model: string | null;
    logical_cpu_count: number;
    physical_core_count: number | null;
    package_count: number | null;
    packages: Array<{ id: number; cores: Array<{ id: number; logical_cpus: number[] }> }>;
  };
  memory: { total_bytes: number | null; available_bytes: number | null };
  numa_nodes: Array<{
    id: number;
    logical_cpus: number[];
    memory_total_bytes: number | null;
    pci_devices: string[];
  }>;
  pci_devices: Array<{
    address: string;
    vendor_id: string | null;
    vendor_name?: string | null;
    device_id: string | null;
    subsystem_vendor_id: string | null;
    subsystem_device_id: string | null;
    class_id: string | null;
    device_type: string;
    driver: string | null;
    numa_node: number | null;
    parent_address: string | null;
    current_link_speed?: string | null;
    current_link_width?: number | null;
    max_link_speed?: string | null;
    max_link_width?: number | null;
  }>;
  gpus: Array<{
    index: number | null;
    name: string;
    vendor: string;
    uuid: string | null;
    pci_address: string | null;
    numa_node: number | null;
    memory_total_bytes: number | null;
    nvlinks: Array<{
      link: number;
      state: string;
      bandwidth_gbps: number | null;
      peer_pci_address: string | null;
    }>;
    source: string;
  }>;
  network_interfaces: Array<{
    name: string;
    mac_address: string | null;
    operational_state: string | null;
    mtu: number | null;
    speed_mbps: number | null;
    duplex: string | null;
    pci_address: string | null;
    numa_node: number | null;
    driver: string | null;
    infiniband_device: string | null;
  }>;
  infiniband_devices: Array<{
    name: string;
    firmware_version: string | null;
    node_guid: string | null;
    pci_address: string | null;
    numa_node: number | null;
    ports: Array<{
      port: number;
      state: string | null;
      physical_state: string | null;
      rate: string | null;
      link_layer: string | null;
    }>;
  }>;
  disks: Array<{
    name: string;
    device_path: string;
    major_minor: string | null;
    size_bytes: number | null;
    rotational: boolean | null;
    vendor: string | null;
    model: string | null;
    transport: string | null;
    pci_address: string | null;
    numa_node: number | null;
  }>;
  openlake: {
    kv_cache_capacity_bytes: number | null;
    data_paths: Array<{
      path: string;
      mount_point: string | null;
      filesystem: string | null;
      source: string | null;
      device: string | null;
      disk: string | null;
    }>;
  };
  subsystems: Array<{ subsystem: string; status: string; detail: string | null }>;
};

export type ControlPlaneNode = {
  id: number;
  diskCount: number;
  rpcAddress: string;
  telemetryAddress: string;
  status: "healthy" | "degraded" | "unreachable";
  observedAt: string | null;
  lastSuccessfulAt: string | null;
  latencyMs: number | null;
  errors: { openlake: string | null; vllm: string | null };
  openlake: null | {
    schema_version?: string;
    collected_at_unix_ms?: number;
    node_id: number;
    openlake: {
      version: string;
      mode: string;
      transport: string;
      data_paths: string[];
      kv_cache: KvCacheSnapshot | null;
    };
    hardware?: HardwareSnapshot;
  };
  vllm: null | { contentType: string; samples: PrometheusSample[] };
};

export type ControlPlaneSnapshot = {
  schemaVersion: string;
  generatedAt: string;
  pollIntervalMs: number;
  totals: { configured: number; healthy: number; degraded: number; unreachable: number };
  nodes: ControlPlaneNode[];
};

export type ControlPlaneData = {
  snapshot: ControlPlaneSnapshot | null;
  loading: boolean;
  error: string | null;
};

export type HistogramSnapshot = {
  average: number | null;
  buckets: Array<{ upperBound: number; cumulative: number }>;
  count: number;
  p50: number | null;
  p90: number | null;
  p99: number | null;
};

export function useControlPlaneSnapshot(): ControlPlaneData {
  const [state, setState] = useState<ControlPlaneData>({ snapshot: null, loading: true, error: null });

  useEffect(() => {
    let active = true;
    const controller = new AbortController();
    const refresh = async () => {
      try {
        const response = await fetch("/api/control-plane/snapshot", {
          cache: "no-store",
          headers: { accept: "application/json" },
          signal: controller.signal,
        });
        if (!response.ok) throw new Error(`control-plane API returned HTTP ${response.status}`);
        const snapshot = await response.json() as ControlPlaneSnapshot;
        if (active) setState({ snapshot, loading: false, error: null });
      } catch (error) {
        if (active && !controller.signal.aborted) {
          setState({
            snapshot: null,
            loading: false,
            error: error instanceof Error ? error.message : String(error),
          });
        }
      }
    };
    void refresh();
    const timer = window.setInterval(refresh, 5000);
    return () => {
      active = false;
      controller.abort();
      window.clearInterval(timer);
    };
  }, []);

  return state;
}

export function activeNodes(snapshot: ControlPlaneSnapshot | null) {
  return snapshot?.nodes.filter(node => node.status !== "unreachable") ?? [];
}

export function vllmSamples(snapshot: ControlPlaneSnapshot | null) {
  return activeNodes(snapshot)
    .filter(node => node.vllm && !node.errors.vllm)
    .flatMap(node => node.vllm?.samples ?? []);
}

export function sumMetric(snapshot: ControlPlaneSnapshot | null, names: string[]) {
  const values = vllmSamples(snapshot).filter(sample => names.includes(sample.name));
  return values.length ? values.reduce((total, sample) => total + sample.value, 0) : null;
}

export function averageMetric(snapshot: ControlPlaneSnapshot | null, names: string[]) {
  const values = vllmSamples(snapshot).filter(sample => names.includes(sample.name));
  return values.length ? values.reduce((total, sample) => total + sample.value, 0) / values.length : null;
}

export function groupMetricByLabel(snapshot: ControlPlaneSnapshot | null, names: string[], label: string) {
  const grouped = new Map<string, number>();
  for (const sample of vllmSamples(snapshot)) {
    if (!names.includes(sample.name)) continue;
    const value = sample.labels[label];
    if (!value) continue;
    grouped.set(value, (grouped.get(value) ?? 0) + sample.value);
  }
  return [...grouped.entries()].map(([key, value]) => ({ key, value })).sort((a, b) => b.value - a.value);
}

function histogramPercentile(buckets: Array<{ upperBound: number; cumulative: number }>, count: number, percentile: number) {
  if (count <= 0) return null;
  const target = count * percentile;
  const match = buckets.find(bucket => bucket.cumulative >= target && Number.isFinite(bucket.upperBound));
  return match?.upperBound ?? null;
}

export function histogramMetric(snapshot: ControlPlaneSnapshot | null, bases: string[]): HistogramSnapshot | null {
  const samples = vllmSamples(snapshot);
  const bucketNames = bases.map(base => `${base}_bucket`);
  const countNames = bases.map(base => `${base}_count`);
  const sumNames = bases.map(base => `${base}_sum`);
  const cumulative = new Map<number, number>();

  for (const sample of samples) {
    if (!bucketNames.includes(sample.name)) continue;
    const upperBound = sample.labels.le === "+Inf" ? Number.POSITIVE_INFINITY : Number(sample.labels.le);
    if (!Number.isFinite(upperBound) && upperBound !== Number.POSITIVE_INFINITY) continue;
    cumulative.set(upperBound, (cumulative.get(upperBound) ?? 0) + sample.value);
  }
  if (!cumulative.size) return null;

  const buckets = [...cumulative.entries()]
    .map(([upperBound, value]) => ({ upperBound, cumulative: value }))
    .sort((a, b) => a.upperBound - b.upperBound);
  const countSamples = samples.filter(sample => countNames.includes(sample.name));
  const sumSamples = samples.filter(sample => sumNames.includes(sample.name));
  const infiniteCount = buckets.find(bucket => bucket.upperBound === Number.POSITIVE_INFINITY)?.cumulative;
  const count = countSamples.length
    ? countSamples.reduce((total, sample) => total + sample.value, 0)
    : infiniteCount ?? buckets[buckets.length - 1].cumulative;
  const sum = sumSamples.length ? sumSamples.reduce((total, sample) => total + sample.value, 0) : null;

  return {
    average: sum === null || count <= 0 ? null : sum / count,
    buckets,
    count,
    p50: histogramPercentile(buckets, count, .5),
    p90: histogramPercentile(buckets, count, .9),
    p99: histogramPercentile(buckets, count, .99),
  };
}

export function kvUtilization(node: ControlPlaneNode | undefined) {
  const cache = !node?.errors.openlake ? node.openlake?.openlake.kv_cache : null;
  if (!cache) return null;
  const capacityBytes = cache.slot_count && cache.slot_bytes
    ? cache.slot_count * cache.slot_bytes
    : cache.configured_capacity_bytes;
  const usedBytes = cache.used_bytes ?? (
    cache.used_slots !== null && cache.slot_bytes ? cache.used_slots * cache.slot_bytes : 0
  );
  return {
    capacityBytes,
    configuredCapacityBytes: cache.configured_capacity_bytes,
    fraction: capacityBytes > 0 ? usedBytes / capacityBytes : 0,
    usedBytes,
  };
}

export function aggregateKvUtilization(snapshot: ControlPlaneSnapshot | null) {
  const values = activeNodes(snapshot).map(node => kvUtilization(node)).filter(value => value !== null);
  if (!values.length) return null;
  const usedBytes = values.reduce((total, value) => total + value.usedBytes, 0);
  const capacityBytes = values.reduce((total, value) => total + value.capacityBytes, 0);
  return { usedBytes, capacityBytes, fraction: capacityBytes > 0 ? usedBytes / capacityBytes : 0 };
}

export function aggregateOpenLakeTokensServed(snapshot: ControlPlaneSnapshot | null) {
  const nodes = activeNodes(snapshot).filter(node =>
    !node.errors.openlake && node.openlake?.openlake.kv_cache,
  );
  if (!nodes.length) return null;

  let blocks = 0;
  let tokens = 0;
  const blockSizes = new Set<number>();
  for (const node of nodes) {
    const servedBlocks = node.openlake?.openlake.kv_cache?.served_blocks;
    if (typeof servedBlocks !== "number" || !Number.isFinite(servedBlocks) || servedBlocks < 0) {
      return null;
    }

    const reportedBlockSizes = new Set(
      (node.vllm?.samples ?? [])
        .filter(sample => sample.name === "vllm:cache_config_info" && sample.value > 0)
        .map(sample => Number(sample.labels.block_size))
        .filter(size => Number.isInteger(size) && size > 0),
    );
    if (reportedBlockSizes.size !== 1) return null;

    const [blockSize] = reportedBlockSizes;
    blocks += servedBlocks;
    tokens += servedBlocks * blockSize;
    blockSizes.add(blockSize);
  }

  return { blocks, tokens, blockSizes: [...blockSizes].sort((left, right) => left - right) };
}

export function formatBytes(bytes: number) {
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value >= 100 || unit === 0 ? value.toFixed(0) : value.toFixed(1)} ${units[unit]}`;
}

export function formatCount(value: number) {
  return new Intl.NumberFormat("en-US", {
    maximumFractionDigits: value >= 1000 ? 1 : 0,
    notation: value >= 1000 ? "compact" : "standard",
  }).format(value);
}

export function formatDuration(seconds: number) {
  if (seconds < .001) return `${Math.round(seconds * 1_000_000)} µs`;
  if (seconds < 1) return `${(seconds * 1000).toFixed(seconds < .01 ? 1 : 0)} ms`;
  return `${seconds.toFixed(seconds < 10 ? 2 : 1)} s`;
}

export function formatObserved(snapshot: ControlPlaneSnapshot, observedAt: string | null) {
  if (!observedAt) return "Not observed";
  const seconds = Math.max(0, Math.round((new Date(snapshot.generatedAt).getTime() - new Date(observedAt).getTime()) / 1000));
  return seconds === 0 ? "Now" : `${seconds}s ago`;
}
