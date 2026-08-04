import type { Metadata } from "next";
import { FleetView } from "./fleet-view";

export const metadata: Metadata = {
  title: "Fleet · OpenLake Control Plane",
  description: "Managed OpenLake hosts and accelerator inventory.",
};

export default function FleetPage() {
  return <FleetView/>;
}
