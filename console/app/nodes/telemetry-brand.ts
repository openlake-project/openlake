export type TelemetryBrand = "nvidia" | "amd" | "apple" | "intel" | "microsoft" | "windows" | "linux";

const vendorAliases = new Map<string, TelemetryBrand>([
  ["nvidia", "nvidia"],
  ["nvidia corporation", "nvidia"],
  ["amd", "amd"],
  ["amd inc", "amd"],
  ["advanced micro devices", "amd"],
  ["advanced micro devices inc", "amd"],
  ["advanced micro devices inc amd ati", "amd"],
  ["apple", "apple"],
  ["apple inc", "apple"],
  ["intel", "intel"],
  ["intel corporation", "intel"],
  ["microsoft", "microsoft"],
  ["microsoft corporation", "microsoft"],
]);

const operatingSystemAliases = new Map<string, TelemetryBrand>([
  ["windows", "windows"],
  ["microsoft windows", "windows"],
  ["macos", "apple"],
  ["mac os", "apple"],
  ["linux", "linux"],
  ["gnu linux", "linux"],
]);

function normalizeTelemetryIdentity(value: string | null | undefined) {
  return value
    ?.trim()
    .toLowerCase()
    .replace(/[\[\](),./®™_-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim() ?? "";
}

/** Match only explicit vendor telemetry against an exact known alias. */
export function brandFromVendor(vendor: string | null | undefined): TelemetryBrand | null {
  return vendorAliases.get(normalizeTelemetryIdentity(vendor)) ?? null;
}

/** Match only explicit operating-system telemetry against an exact known alias. */
export function brandFromOperatingSystem(operatingSystem: string | null | undefined): TelemetryBrand | null {
  return operatingSystemAliases.get(normalizeTelemetryIdentity(operatingSystem)) ?? null;
}

/** Match only anchored, recognizable CPU product signatures. */
export function brandFromCpuModel(model: string | null | undefined): TelemetryBrand | null {
  const value = model?.trim() ?? "";
  if (/^Apple\s+(?:M\d|A\d|S\d)(?:\s|$)/i.test(value)) return "apple";
  if (/^Intel(?:\(R\))?\s+(?:Xeon(?:\(R\))?|Core(?:\(TM\))?|Atom|Celeron|Pentium)(?:\s|$)/i.test(value)) return "intel";
  if (/^AMD\s+(?:EPYC|Ryzen|Threadripper)(?:\s|$)/i.test(value)) return "amd";
  return null;
}
