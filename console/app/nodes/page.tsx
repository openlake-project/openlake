import type { Metadata } from "next";
import { NodeSignalPlane } from "./node-signal-plane";

export const metadata: Metadata = {
  title: "Topology · OpenLake Control Plane",
  description: "Interactive hardware topology and OpenLake node telemetry",
};

export default function NodesPage() {
  return <NodeSignalPlane/>;
}
