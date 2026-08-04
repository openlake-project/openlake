"use client";

import type { ReactNode } from "react";
import {
  activeNodes,
  aggregateOpenLakeTokensServed,
  averageMetric,
  formatBytes,
  formatCount,
  formatDuration,
  groupMetricByLabel,
  histogramMetric,
  kvUtilization,
  sumMetric,
  type ControlPlaneSnapshot,
  type HistogramSnapshot,
  useControlPlaneSnapshot,
  vllmSamples,
} from "./control-plane-data";
import { ControlPlaneStatus, TelemetryUnavailable } from "./control-plane-status";
import { AppShell } from "./shell";

const metricNames = {
  completed: ["vllm:request_success_total", "vllm:request_success"],
  gpuKv: ["vllm:kv_cache_usage_perc", "vllm:gpu_cache_usage_perc"],
  running: ["vllm:num_requests_running"],
  waiting: ["vllm:num_requests_waiting"],
};

type DistributionTelemetry = {
  title: string;
  meta: string;
  detail: string;
  shares: number[];
  labels: string[];
  notes: Array<[string, string]>;
};

function cx(...classes: Array<string | false | null | undefined>) {
  return classes.filter(Boolean).join(" ");
}

function Card({ children, className }: { children: ReactNode; className?: string }) {
  return <section className={cx("card", className)}>{children}</section>;
}

function TelemetryInsight({ children, className, label, value, detail }: { children?: ReactNode; className?: string; label: string; value: string; detail: string }) {
  return <div className={cx("telemetry-insight", className)} role="img" tabIndex={0} aria-label={`${label}: ${value}. ${detail}`}>
    {children}
    <div className="telemetry-tooltip" role="tooltip" aria-hidden="true"><span>{label}</span><strong>{value}</strong><small>{detail}</small></div>
  </div>;
}

function HomeMetric({ label, value, detail, subdetail }: { label: string; value: string; detail: string; subdetail: string }) {
  return <Card className="home-metric"><header><span>{label}</span><strong>{value}</strong></header><footer><b>{detail}</b><span>{subdetail}</span></footer></Card>;
}

function TelemetryHead({ title, meta, total }: { title: string; meta?: string; total?: string }) {
  return <div className="telemetry-head"><span>{title}</span>{total ? <strong>{total}</strong> : meta ? <small>{meta}</small> : null}</div>;
}

function TelemetryBars({ title, total, items }: { title: string; total: string; items: Array<{ label: string; share: number; value: string }> }) {
  const scale = Math.max(...items.map(item => item.share), 1);
  return <Card className="telemetry-card telemetry-bars-card"><TelemetryHead title={title} total={total}/><div className="telemetry-bar-list">{items.map(item => <TelemetryInsight className="telemetry-bar-row" label={item.label} value={`${item.share.toFixed(1)}% · ${item.value}`} detail="Current cumulative vLLM completion counter grouped by its reported finish reason." key={item.label}><div className="telemetry-bar-label"><b>{item.label}</b></div><div className="telemetry-bar-track"><i style={{ width: `${Math.max(1, (item.share / scale) * 100)}%` }}/></div><div className="telemetry-bar-value"><b>{item.share.toFixed(1)}%</b><span>{item.value}</span></div></TelemetryInsight>)}</div></Card>;
}

function DistributionCard({ item }: { item: DistributionTelemetry }) {
  const max = Math.max(...item.shares, 1);
  return <Card className="telemetry-card distribution-card"><TelemetryHead title={item.title} meta={item.meta}/><div className="telemetry-histogram" aria-label={`${item.title} distribution`}>{item.shares.map((share, index) => <TelemetryInsight className="telemetry-hist-column" label={`${item.title} · ${item.labels[index]}`} value={`${share.toFixed(1)}%`} detail={item.detail} key={item.labels[index]}><span>{share.toFixed(1)}%</span><div className="telemetry-hist-bar"><i style={{ height: `${share === 0 ? 0 : Math.max(4, (share / max) * 100)}%` }}/></div><small>{item.labels[index]}</small></TelemetryInsight>)}</div><div className="telemetry-note-row">{item.notes.map(([label, value]) => <div key={label}><span>{label}</span><b>{value}</b></div>)}</div></Card>;
}

function selectHistogramBuckets(histogram: HistogramSnapshot, formatter: (value: number) => string) {
  const finite = histogram.buckets.filter(bucket => Number.isFinite(bucket.upperBound));
  const infinite = histogram.buckets.find(bucket => !Number.isFinite(bucket.upperBound));
  let selected = finite;
  if (finite.length > 5) {
    const indexes = new Set(Array.from({ length: 5 }, (_, index) => Math.min(finite.length - 1, Math.round(((index + 1) * finite.length) / 5) - 1)));
    selected = [...indexes].sort((a, b) => a - b).map(index => finite[index]);
  }
  if (infinite) selected = [...selected, infinite];

  let previous = 0;
  let previousBound: number | null = null;
  return selected.map(bucket => {
    const count = Math.max(0, bucket.cumulative - previous);
    const label = Number.isFinite(bucket.upperBound)
      ? `≤ ${formatter(bucket.upperBound)}`
      : previousBound === null ? "All" : `> ${formatter(previousBound)}`;
    previous = bucket.cumulative;
    if (Number.isFinite(bucket.upperBound)) previousBound = bucket.upperBound;
    return { label, share: histogram.count > 0 ? (count / histogram.count) * 100 : 0 };
  });
}

function distributionFromHistogram(title: string, detail: string, histogram: HistogramSnapshot | null, formatter: (value: number) => string): DistributionTelemetry | null {
  if (!histogram) return null;
  const buckets = selectHistogramBuckets(histogram, formatter);
  const notes: Array<[string, string]> = [];
  if (histogram.average !== null) notes.push(["Average", formatter(histogram.average)]);
  if (histogram.p90 !== null) notes.push(["P90 ≤", formatter(histogram.p90)]);
  if (histogram.p99 !== null) notes.push(["P99 ≤", formatter(histogram.p99)]);
  return {
    title,
    meta: `${formatCount(histogram.count)} observations`,
    detail,
    shares: buckets.map(bucket => bucket.share),
    labels: buckets.map(bucket => bucket.label),
    notes,
  };
}

function readableReason(reason: string) {
  return reason.replaceAll("_", " ").replace(/\b\w/g, letter => letter.toUpperCase());
}

function FleetTelemetryCard({ snapshot }: { snapshot: ControlPlaneSnapshot }) {
  const nodes = activeNodes(snapshot);
  const headings = ["Node", "OpenLake", "KV cache", "vLLM", "Status"];
  return <Card className="telemetry-card telemetry-fleet"><TelemetryHead title="Active nodes" meta={`${nodes.length} reporting`}/><div className="telemetry-fleet-head">{headings.map(label => <span key={label}>{label}</span>)}</div>{nodes.map(node => {
    const openlake = !node.errors.openlake ? node.openlake?.openlake : null;
    const usage = kvUtilization(node);
    const usagePercent = usage ? usage.fraction * 100 : null;
    return <div className="telemetry-fleet-row" key={node.id}>
      <div data-label="Node"><div className="telemetry-node"><b>node-{node.id}</b><small>{node.rpcAddress}</small></div></div>
      <div data-label="OpenLake"><b>{openlake ? `${openlake.mode.toUpperCase()} · v${openlake.version}` : "Not reported"}</b></div>
      <div data-label="KV cache">{usage && usagePercent !== null ? <TelemetryInsight className="telemetry-cache" label="OpenLake KV cache" value={`${formatBytes(usage.usedBytes)} / ${formatBytes(usage.capacityBytes)}`} detail="Live committed KV slab occupancy reported by OpenLake."><b>{formatBytes(usage.usedBytes)} / {formatBytes(usage.capacityBytes)}</b><i><span style={{ width: `${usagePercent}%` }}/></i></TelemetryInsight> : <b>Not reported</b>}</div>
      <div data-label="vLLM"><b>{!node.errors.vllm && node.vllm ? `${node.vllm.samples.length} samples` : "Not reported"}</b></div>
      <div data-label="Status"><span className={cx("telemetry-healthy", node.status === "degraded" && "degraded")}><i/>{readableReason(node.status)}</span></div>
    </div>;
  })}</Card>;
}

function LiveDashboard({ snapshot }: { snapshot: ControlPlaneSnapshot }) {
  const nodes = activeNodes(snapshot);
  const openLakeServed = aggregateOpenLakeTokensServed(snapshot);
  const running = sumMetric(snapshot, metricNames.running);
  const waiting = sumMetric(snapshot, metricNames.waiting);
  const completed = sumMetric(snapshot, metricNames.completed);
  const gpuKvRaw = averageMetric(snapshot, metricNames.gpuKv);
  const gpuKvPercent = gpuKvRaw === null ? null : gpuKvRaw > 1 ? gpuKvRaw : gpuKvRaw * 100;
  const finishReasons = groupMetricByLabel(snapshot, metricNames.completed, "finished_reason");
  const finishTotal = finishReasons.reduce((total, reason) => total + reason.value, 0);
  const vllm = vllmSamples(snapshot);

  const summary = [
    { label: "Active nodes", value: String(nodes.length), detail: `${snapshot.totals.configured} configured`, subdetail: `${snapshot.totals.unreachable} unreachable` },
    ...(completed === null ? [] : [{ label: "Completed requests", value: formatCount(completed), detail: "vLLM process lifetime", subdetail: "Cumulative successful requests" }]),
    ...(running === null ? [] : [{ label: "Running requests", value: formatCount(running), detail: "Currently executing", subdetail: waiting === null ? "Queue metric not reported" : `${formatCount(waiting)} waiting` }]),
    ...(openLakeServed ? [{
      label: "Tokens served by OpenLake",
      value: formatCount(openLakeServed.tokens),
      detail: `${formatCount(openLakeServed.blocks)} confirmed KV blocks`,
      subdetail: `${openLakeServed.blockSizes.join(" / ")} tokens per block · server GET hits`,
    }] : []),
    ...(!openLakeServed && gpuKvPercent !== null ? [{ label: "vLLM GPU KV cache", value: `${gpuKvPercent.toFixed(1)}%`, detail: "Current engine utilization", subdetail: "Reported by vLLM" }] : []),
  ];

  const finishItems = finishTotal > 0 ? finishReasons.map(reason => ({
    label: readableReason(reason.key),
    share: (reason.value / finishTotal) * 100,
    value: formatCount(reason.value),
  })) : [];

  const distributions = [
    distributionFromHistogram("Time to first token", "Current vLLM histogram of time from request arrival to the first generated token.", histogramMetric(snapshot, ["vllm:time_to_first_token_seconds"]), formatDuration),
    distributionFromHistogram("End-to-end latency", "Current vLLM histogram of complete request latency.", histogramMetric(snapshot, ["vllm:e2e_request_latency_seconds"]), formatDuration),
    distributionFromHistogram("Input length", "Current vLLM histogram of prompt tokens per request.", histogramMetric(snapshot, ["vllm:request_prompt_tokens"]), value => `${formatCount(value)} tokens`),
  ].filter(item => item !== null);

  return <>
    <div className="home-metric-grid">{summary.map(metric => <HomeMetric {...metric} key={metric.label}/>)}</div>
    {vllm.length === 0 ? <TelemetryUnavailable title="Inference Engine not detected." detail="Please start vLLM with the OpenLake connector enabled."/> : null}
    {finishItems.length || distributions.length ? <section className="home-telemetry" aria-label="Live request telemetry">
      {finishItems.length ? <div className="telemetry-pair telemetry-single"><TelemetryBars title="Requests by finish reason" total={formatCount(finishTotal)} items={finishItems}/></div> : null}
      {distributions.length ? <div className="telemetry-distribution-grid">{distributions.map(item => <DistributionCard item={item} key={item.title}/>)}</div> : null}
    </section> : null}
    <FleetTelemetryCard snapshot={snapshot}/>
  </>;
}

function Overview() {
  const state = useControlPlaneSnapshot();
  if (state.loading || !state.snapshot || activeNodes(state.snapshot).length === 0) return <ControlPlaneStatus state={state}/>;
  return <LiveDashboard snapshot={state.snapshot}/>;
}

function PageHeading() {
  return <div className="page-heading"><div><h1>Dashboard</h1></div></div>;
}

export function ControlPlane() {
  return <AppShell active="dashboard"><PageHeading/><div className="page-stack"><Overview/></div></AppShell>;
}
