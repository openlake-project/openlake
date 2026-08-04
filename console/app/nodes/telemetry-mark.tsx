import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faMicrosoft, faWindows } from "@fortawesome/free-brands-svg-icons";
import { SiAmd, SiApple, SiIntel, SiLinux, SiNvidia } from "@icons-pack/react-simple-icons";
import type { ComponentType, SVGProps } from "react";
import type { TelemetryBrand } from "./telemetry-brand";

type SimpleIcon = ComponentType<SVGProps<SVGSVGElement> & { size?: string | number; title?: string }>;

const simpleMarks: Partial<Record<TelemetryBrand, SimpleIcon>> = {
  nvidia: SiNvidia,
  amd: SiAmd,
  apple: SiApple,
  intel: SiIntel,
  linux: SiLinux,
};

const brandLabels: Record<TelemetryBrand, string> = {
  nvidia: "NVIDIA",
  amd: "AMD",
  apple: "Apple",
  intel: "Intel",
  microsoft: "Microsoft",
  windows: "Windows",
  linux: "Linux",
};

export function TelemetryMark({
  brand,
  matchedFrom,
}: {
  brand: TelemetryBrand;
  matchedFrom: string;
}) {
  const accessibleLabel = `${brandLabels[brand]} mark; matched from reported ${matchedFrom}`;
  const SimpleMark = simpleMarks[brand];

  return <span className={`telemetry-mark brand-${brand}`} aria-label={accessibleLabel} title={accessibleLabel}>
    {SimpleMark ? <SimpleMark aria-hidden="true"/> : null}
    {brand === "microsoft" ? <FontAwesomeIcon icon={faMicrosoft} aria-hidden="true"/> : null}
    {brand === "windows" ? <FontAwesomeIcon icon={faWindows} aria-hidden="true"/> : null}
  </span>;
}
