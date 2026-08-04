import type { Metadata } from "next";
import { ControlPlane } from "./control-plane";

export const metadata: Metadata = {
  title: "Overview · OpenLake",
  description: "OpenLake storage control plane and observability console.",
};

export default function Home() {
  return <ControlPlane />;
}
