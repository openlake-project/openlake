"use client";

import { useMemo, useState } from "react";
import { ArrowUpRight, Search } from "lucide-react";
import {
  activeNodes,
  formatBytes,
  formatObserved,
  kvUtilization,
  type ControlPlaneSnapshot,
  useControlPlaneSnapshot,
} from "../control-plane-data";
import { ControlPlaneStatus } from "../control-plane-status";
import { AppShell } from "../shell";

type FleetFilter = "all" | "active" | "unreachable";

type FleetHost = {
  id: number;
  address: string;
  runtime: string;
  runtimeMeta: string;
  cache: string;
  cacheMeta: string;
  allocation: number | null;
  storage: string;
  storageMeta: string;
  status: "Healthy" | "Degraded" | "Unreachable";
  observed: string;
  vllm: string;
};

function FleetSummary({ snapshot }: { snapshot: ControlPlaneSnapshot }) {
  const active = activeNodes(snapshot);
  const openlakeReporting = active.filter(node => node.openlake && !node.errors.openlake).length;
  const vllmReporting = active.filter(node => node.vllm && !node.errors.vllm).length;
  const cards = [
    ["Configured nodes", String(snapshot.totals.configured), "Read from [[nodes]]"],
    ["Active nodes", String(active.length), `${snapshot.totals.unreachable} unreachable`],
    ["OpenLake reporting", String(openlakeReporting), "Runtime telemetry available"],
    ["vLLM reporting", String(vllmReporting), "Metrics endpoint available"],
  ];

  return <section className="fleet-summary" aria-label="Fleet summary">{cards.map(([label, value, note]) => <article className="fleet-summary-card" key={label}><span>{label}</span><strong>{value}</strong><small>{note}</small></article>)}</section>;
}

function fleetHosts(snapshot: ControlPlaneSnapshot): FleetHost[] {
  return snapshot.nodes.map(node => {
    const openlake = !node.errors.openlake ? node.openlake?.openlake : null;
    const usage = kvUtilization(node);
    return {
      id: node.id,
      address: node.rpcAddress,
      runtime: openlake ? `${openlake.mode.toUpperCase()} · v${openlake.version}` : "Not reported",
      runtimeMeta: openlake ? openlake.transport.toUpperCase() : node.errors.openlake ?? "Waiting for OpenLake telemetry",
      cache: usage ? `${formatBytes(usage.usedBytes)} / ${formatBytes(usage.capacityBytes)}` : "Not reported",
      cacheMeta: usage ? "Committed KV slab" : "KV slab telemetry unavailable",
      allocation: usage ? Math.round(usage.fraction * 100) : null,
      storage: `${node.diskCount} configured disk${node.diskCount === 1 ? "" : "s"}`,
      storageMeta: openlake ? `${openlake.data_paths.length} data path${openlake.data_paths.length === 1 ? "" : "s"} reported` : "Data paths not reported",
      status: node.status === "healthy" ? "Healthy" : node.status === "degraded" ? "Degraded" : "Unreachable",
      observed: formatObserved(snapshot, node.observedAt),
      vllm: !node.errors.vllm && node.vllm ? `${node.vllm.samples.length} samples` : "vLLM not reported",
    };
  });
}

function LiveFleet({ snapshot }: { snapshot: ControlPlaneSnapshot }) {
  const [filter, setFilter] = useState<FleetFilter>("all");
  const [query, setQuery] = useState("");
  const hosts = useMemo(() => fleetHosts(snapshot), [snapshot]);
  const filteredHosts = useMemo(() => {
    const normalized = query.trim().toLowerCase();
    return hosts.filter(host => {
      const matchesFilter = filter === "all"
        || (filter === "active" && host.status !== "Unreachable")
        || (filter === "unreachable" && host.status === "Unreachable");
      const matchesQuery = !normalized || [String(host.id), host.address, host.runtime, host.status].some(value => value.toLowerCase().includes(normalized));
      return matchesFilter && matchesQuery;
    });
  }, [filter, hosts, query]);
  const filterCounts = {
    all: hosts.length,
    active: hosts.filter(host => host.status !== "Unreachable").length,
    unreachable: hosts.filter(host => host.status === "Unreachable").length,
  };

  return <div className="page-stack fleet-stack">
    <FleetSummary snapshot={snapshot}/>
    <section className="card fleet-inventory-card" aria-labelledby="fleet-inventory-title">
      <header className="fleet-inventory-head"><div><h2 id="fleet-inventory-title">Configured nodes</h2><p>Live runtime, storage, and telemetry state from the OpenLake node contract</p></div><div className="fleet-controls"><label className="fleet-search"><Search size={15}/><span className="sr-only">Search nodes</span><input value={query} onChange={event => setQuery(event.target.value)} placeholder="Search nodes"/></label><div className="fleet-filter" role="group" aria-label="Filter fleet by reachability">{(["all", "active", "unreachable"] as const).map(value => <button className={filter === value ? "active" : undefined} onClick={() => setFilter(value)} aria-pressed={filter === value} key={value}>{value[0].toUpperCase() + value.slice(1)}<span>{filterCounts[value]}</span></button>)}</div></div></header>
      <div className="fleet-table" role="table" aria-label="Configured OpenLake nodes">
        <div className="fleet-table-head fleet-row-grid" role="row"><span role="columnheader">Node</span><span role="columnheader">OpenLake</span><span role="columnheader">KV cache</span><span role="columnheader">Storage</span><span role="columnheader">Telemetry</span><span aria-hidden="true"/></div>
        <div className="fleet-table-body" role="rowgroup">{filteredHosts.map(host => <article className="fleet-row fleet-row-grid" role="row" key={host.id}>
          <div className="fleet-host-cell" role="cell" data-label="Node"><strong>node-{host.id}</strong><span>{host.address}</span></div>
          <div className="fleet-platform-cell" role="cell" data-label="OpenLake"><strong>{host.runtime}</strong><span>{host.runtimeMeta}</span></div>
          <div className="fleet-allocation" role="cell" data-label="KV cache"><div><strong>{host.cache}</strong><span>{host.cacheMeta}</span></div>{host.allocation === null ? null : <i aria-hidden="true"><span style={{ width: `${host.allocation}%` }}/></i>}</div>
          <div className="fleet-platform-cell" role="cell" data-label="Storage"><strong>{host.storage}</strong><span>{host.storageMeta}</span></div>
          <div className="fleet-health" role="cell" data-label="Telemetry"><span className={host.status.toLowerCase()}><i/>{host.status}</span><small>{host.vllm} · {host.observed}</small></div>
          <a className="fleet-topology-link" href="/nodes" aria-label={`Open topology for node-${host.id}`}><span>Topology</span><ArrowUpRight size={15}/></a>
        </article>)}</div>
        {filteredHosts.length === 0 ? <div className="fleet-empty"><strong>No matching nodes</strong><span>Try a different search or reachability filter.</span></div> : null}
      </div>
    </section>
  </div>;
}

export function FleetView() {
  const state = useControlPlaneSnapshot();
  const active = activeNodes(state.snapshot);
  return <AppShell active="fleet">
    <div className="page-heading fleet-page-heading"><div><h1>Fleet</h1></div>{active.length ? <span className="fleet-reporting"><i/>{active.length} node{active.length === 1 ? "" : "s"} reporting</span> : null}</div>
    {state.loading || !state.snapshot || active.length === 0 ? <div className="page-stack fleet-stack"><ControlPlaneStatus state={state}/></div> : <LiveFleet snapshot={state.snapshot}/>}
  </AppShell>;
}
