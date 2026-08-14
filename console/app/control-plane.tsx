"use client";

import { useId, type ReactNode } from "react";
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import {
  activeNodes,
  aggregateNodeHistory,
  aggregateOpenLakeTokensServed,
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
  available: boolean;
};

type PreviewTrend = {
  title: string;
  values: number[];
  windowMinutes: number;
  valueSuffix: "tokens/min" | "req/min";
  tone: "cache" | "requests";
  available: boolean;
};

function ghostTrendValues(tone: PreviewTrend["tone"]) {
  return Array.from({ length: 30 }, (_, index) => {
    const conciergeCurve = 20 + index * 2.5 + Math.sin(index * .5) * 8;
    return Math.round(conciergeCurve * (tone === "cache" ? 24 : 1));
  });
}

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

function TelemetryBars({ title, total, items, available }: { title: string; total: string; items: Array<{ label: string; share: number; value: string }>; available: boolean }) {
  const scale = Math.max(...items.map(item => item.share), 1);
  return <Card className={`telemetry-card telemetry-bars-card${available ? "" : " is-empty"}`}>
    <TelemetryHead title={title} total={available ? total : undefined} meta={available ? undefined : "Waiting for requests"}/>
    {!available ? <div className="telemetry-empty-overlay"><strong>No data yet</strong><span>Finish reasons will appear after requests complete</span></div> : null}
    <div className="telemetry-bar-list">{items.map(item => available
      ? <TelemetryInsight className="telemetry-bar-row" label={item.label} value={`${item.share.toFixed(1)}% · ${item.value}`} detail="Current cumulative vLLM completion counter grouped by its reported finish reason." key={item.label}><div className="telemetry-bar-label"><b>{item.label}</b></div><div className="telemetry-bar-track"><i style={{ width: `${Math.max(1, (item.share / scale) * 100)}%` }}/></div><div className="telemetry-bar-value"><b>{item.share.toFixed(1)}%</b><span>{item.value}</span></div></TelemetryInsight>
      : <div className="telemetry-bar-row" aria-hidden="true" key={item.label}><div className="telemetry-bar-label"><b>{item.label}</b></div><div className="telemetry-bar-track"><i style={{ width: `${Math.max(1, (item.share / scale) * 100)}%` }}/></div><div className="telemetry-bar-value"/></div>)}</div>
  </Card>;
}

function formatPreviewValue(trend: PreviewTrend, value: number) {
  return `${formatCount(value)} ${trend.valueSuffix}`;
}

function historyWindowLabel(minutes: number) {
  if (minutes < 60) return `${Math.round(minutes)} min`;
  const hours = minutes / 60;
  return `${Number.isInteger(hours) ? hours.toFixed(0) : hours.toFixed(1)} hr`;
}

function historyAgeLabel(position: number, windowMinutes: number, compact = false) {
  const ageMinutes = Math.max(0, windowMinutes - position);
  if (ageMinutes < .5) return "Now";
  if (ageMinutes >= 60) {
    const hours = ageMinutes / 60;
    const value = Number.isInteger(hours) ? hours.toFixed(0) : hours.toFixed(1);
    return compact ? `${value}h` : `${value} hr ago`;
  }
  return compact ? `${Math.round(ageMinutes)}m` : `${Math.round(ageMinutes)} min ago`;
}

function PreviewTrendCard({ trend }: { trend: PreviewTrend }) {
  const gradientId = `trend-${useId().replaceAll(":", "")}`;
  const minimum = Math.min(...trend.values);
  const maximum = Math.max(...trend.values);
  const padding = Math.max((maximum - minimum) * .18, 1);
  const data = trend.values.map((value, index) => ({
    minute: (index / Math.max(1, trend.values.length - 1)) * trend.windowMinutes,
    value,
  }));
  const ticks = Array.from({ length: 5 }, (_, index) => (trend.windowMinutes * index) / 4);
  return <Card className={`telemetry-card mini-trend-card ${trend.tone}${trend.available ? "" : " is-empty"}`}>
    <TelemetryHead title={trend.title} meta={trend.available ? `${historyWindowLabel(trend.windowMinutes)} · 30s` : "Awaiting data"}/>
    <div className="mini-trend-chart">
      {!trend.available ? <div className="telemetry-empty-overlay"><strong>No traffic yet</strong><span>Activity will appear after the first request</span></div> : null}
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={data} margin={{ top: 8, right: 2, bottom: 0, left: 2 }} accessibilityLayer>
          <defs>
            <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="var(--trend-color)" stopOpacity={.22}/>
              <stop offset="100%" stopColor="var(--trend-color)" stopOpacity={0}/>
            </linearGradient>
          </defs>
          <CartesianGrid vertical={false} stroke="var(--grid)" strokeDasharray="3 4"/>
          <XAxis
            dataKey="minute"
            type="number"
            domain={[0, trend.windowMinutes]}
            ticks={ticks}
            interval={0}
            padding={{ left: 10, right: 10 }}
            axisLine={false}
            tickLine={false}
            tickMargin={7}
            tick={{ fill: "var(--subtle)", fontFamily: "var(--font-geist-mono)", fontSize: 8 }}
            tickFormatter={value => historyAgeLabel(Number(value), trend.windowMinutes, true)}
          />
          <YAxis hide domain={[minimum - padding, maximum + padding]}/>
          {trend.available ? <Tooltip
            cursor={{ stroke: "var(--border-strong)", strokeDasharray: "3 3" }}
            contentStyle={{ background: "var(--card)", border: "1px solid var(--border-strong)", borderRadius: 8, boxShadow: "var(--shadow)", color: "var(--foreground)", fontFamily: "var(--font-geist-mono)", fontSize: 10 }}
            itemStyle={{ color: "var(--foreground)" }}
            labelStyle={{ color: "var(--muted)", fontSize: 9, marginBottom: 4 }}
            labelFormatter={value => historyAgeLabel(Number(value), trend.windowMinutes)}
            formatter={value => [formatPreviewValue(trend, Number(value)), trend.title]}
          /> : null}
          <Area
            type="monotone"
            dataKey="value"
            stroke="var(--trend-color)"
            strokeOpacity={trend.available ? 1 : .8}
            strokeWidth={1}
            fill={`url(#${gradientId})`}
            dot={false}
            activeDot={{ fill: "var(--card)", r: 2.5, stroke: "var(--foreground)", strokeWidth: 1 }}
            isAnimationActive={false}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  </Card>;
}

function DistributionCard({ item }: { item: DistributionTelemetry }) {
  const max = Math.max(...item.shares, 1);
  return <Card className={`telemetry-card distribution-card${item.available ? "" : " is-empty"}`}>
    <TelemetryHead title={item.title} meta={item.available ? item.meta : "Waiting for observations"}/>
    {!item.available ? <div className="telemetry-empty-overlay"><strong>No observations yet</strong><span>The distribution will appear after requests complete</span></div> : null}
    <div className="telemetry-histogram" aria-label={`${item.title} distribution`}>{item.shares.map((share, index) => item.available
      ? <TelemetryInsight className="telemetry-hist-column" label={`${item.title} · ${item.labels[index]}`} value={`${share.toFixed(1)}%`} detail={item.detail} key={item.labels[index]}><span>{share.toFixed(1)}%</span><div className="telemetry-hist-bar"><i style={{ height: `${share === 0 ? 0 : Math.max(4, (share / max) * 100)}%` }}/></div><small>{item.labels[index]}</small></TelemetryInsight>
      : <div className="telemetry-hist-column" aria-hidden="true" key={item.labels[index]}><span/><div className="telemetry-hist-bar"><i style={{ height: `${Math.max(4, (share / max) * 100)}%` }}/></div><small>{item.labels[index]}</small></div>)}</div>
    {item.available ? <div className="telemetry-note-row">{item.notes.map(([label, value]) => <div key={label}><span>{label}</span><b>{value}</b></div>)}</div> : null}
  </Card>;
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
  const available = histogram.count > 0;
  const ghostShares = [18, 68, 44, 27, 13, 6];
  const notes: Array<[string, string]> = [];
  if (histogram.average !== null) notes.push(["Average", formatter(histogram.average)]);
  if (histogram.p90 !== null) notes.push(["P90 ≤", formatter(histogram.p90)]);
  if (histogram.p99 !== null) notes.push(["P99 ≤", formatter(histogram.p99)]);
  return {
    title,
    meta: `${formatCount(histogram.count)} observations`,
    detail,
    shares: available ? buckets.map(bucket => bucket.share) : buckets.map((_, index) => ghostShares[index % ghostShares.length]),
    labels: buckets.map(bucket => bucket.label),
    notes,
    available,
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
  const finishReasons = groupMetricByLabel(snapshot, metricNames.completed, "finished_reason");
  const finishTotal = finishReasons.reduce((total, reason) => total + reason.value, 0);
  const vllm = vllmSamples(snapshot);
  const history = aggregateNodeHistory(snapshot);
  const cacheHistory = history?.cachedTokensPerMinute ?? [];
  const requestHistory = history?.requestsPerMinute ?? [];
  const cacheHistoryAvailable = cacheHistory.some(value => value > 0);
  const requestHistoryAvailable = requestHistory.some(value => value > 0);
  const trends: PreviewTrend[] = [
    {
      title: "Cached tokens served",
      values: cacheHistoryAvailable ? cacheHistory : ghostTrendValues("cache"),
      windowMinutes: history?.windowMinutes ?? 10,
      valueSuffix: "tokens/min",
      tone: "cache",
      available: cacheHistoryAvailable,
    },
    {
      title: "Request throughput",
      values: requestHistoryAvailable ? requestHistory : ghostTrendValues("requests"),
      windowMinutes: history?.windowMinutes ?? 10,
      valueSuffix: "req/min",
      tone: "requests",
      available: requestHistoryAvailable,
    },
  ];

  const summary = [
    { label: "Active nodes", value: String(nodes.length), detail: `${snapshot.totals.configured} configured`, subdetail: `${snapshot.totals.unreachable} unreachable` },
    ...(completed === null ? [] : [{ label: "Completed requests", value: formatCount(completed), detail: "vLLM process lifetime", subdetail: "Cumulative successful requests" }]),
    ...(running === null ? [] : [{ label: "Running requests", value: formatCount(running), detail: "Currently executing", subdetail: waiting === null ? "Queue metric not reported" : `${formatCount(waiting)} waiting` }]),
    {
      label: "Tokens served by OpenLake",
      value: formatCount(openLakeServed?.tokens ?? 0),
      detail: `${formatCount(openLakeServed?.blocks ?? 0)} KV blocks served`,
      subdetail: openLakeServed
        ? `Block size: ${openLakeServed.blockSizes.join(" / ")} tokens`
        : "No KV blocks served",
    },
  ];

  const finishAvailable = finishTotal > 0;
  const finishItems = finishAvailable ? finishReasons.map(reason => ({
    label: readableReason(reason.key),
    share: (reason.value / finishTotal) * 100,
    value: formatCount(reason.value),
  })) : [
    { label: "Stop", share: 56, value: "0" },
    { label: "Length", share: 27, value: "0" },
    { label: "Abort", share: 14, value: "0" },
    { label: "Error", share: 8, value: "0" },
    { label: "Repetition", share: 4, value: "0" },
  ];

  const distributions = [
    distributionFromHistogram("Time to first token", "Current vLLM histogram of time from request arrival to the first generated token.", histogramMetric(snapshot, ["vllm:time_to_first_token_seconds"]), formatDuration),
    distributionFromHistogram("End-to-end latency", "Current vLLM histogram of complete request latency.", histogramMetric(snapshot, ["vllm:e2e_request_latency_seconds"]), formatDuration),
    distributionFromHistogram("Input length", "Current vLLM histogram of prompt tokens per request.", histogramMetric(snapshot, ["vllm:request_prompt_tokens"]), value => `${formatCount(value)} tokens`),
  ].filter(item => item !== null);

  return <>
    <div className="home-metric-grid">{summary.map(metric => <HomeMetric {...metric} key={metric.label}/>)}</div>
    {vllm.length === 0 ? <TelemetryUnavailable title="Inference Engine not detected." detail="Please start vLLM with the OpenLake connector enabled."/> : null}
    {finishItems.length || trends.length || distributions.length ? <section className="home-telemetry" aria-label="Live request telemetry">
      {finishItems.length || trends.length ? <div className="telemetry-overview-grid"><TelemetryBars title="Requests by finish reason" total={formatCount(finishTotal)} items={finishItems} available={finishAvailable}/>{trends.map(trend => <PreviewTrendCard trend={trend} key={trend.title}/>)}</div> : null}
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
