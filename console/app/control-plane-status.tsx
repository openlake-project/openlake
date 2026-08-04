"use client";

import { LoaderCircle, RadioTower } from "lucide-react";
import type { ControlPlaneData } from "./control-plane-data";

export function ControlPlaneStatus({ state }: { state: ControlPlaneData }) {
  if (state.loading) {
    return <section className="control-plane-state is-loading" aria-label="Loading telemetry" aria-live="polite">
      <LoaderCircle className="control-plane-state-spinner" size={22}/>
    </section>;
  }

  if (state.error) {
    return <section className="control-plane-state" aria-live="polite">
      <strong>Control plane unavailable</strong>
      <p>{state.error}</p>
    </section>;
  }

  const configured = state.snapshot?.totals.configured ?? 0;
  if (configured > 0) {
    const unreachable = state.snapshot?.totals.unreachable ?? configured;
    const nodeError = state.snapshot?.nodes
      .flatMap(node => [node.errors.openlake, node.errors.vllm])
      .find(Boolean);
    return <section className="control-plane-state" aria-live="polite">
      <strong>{unreachable} configured node{unreachable === 1 ? " is" : "s are"} not reporting telemetry</strong>
      <p>{nodeError ?? "The control plane loaded its OpenLake configuration, but no node telemetry endpoint responded."}</p>
    </section>;
  }

  return <section className="control-plane-state" aria-live="polite">
    <strong>No nodes available</strong>
    <p>Provide an OpenLake config with node addresses.</p>
  </section>;
}

export function TelemetryUnavailable({ title, detail }: { title: string; detail: string }) {
  return <section className="card telemetry-unavailable"><RadioTower size={18}/><div><strong>{title}</strong><p>{detail}</p></div></section>;
}
