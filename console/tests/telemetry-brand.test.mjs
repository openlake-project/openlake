import assert from "node:assert/strict";
import test from "node:test";
import {
  brandFromCpuModel,
  brandFromOperatingSystem,
  brandFromVendor,
} from "../app/nodes/telemetry-brand.ts";

test("matches only exact vendor aliases from explicit telemetry", () => {
  assert.equal(brandFromVendor("NVIDIA"), "nvidia");
  assert.equal(brandFromVendor("Advanced Micro Devices, Inc. [AMD/ATI]"), "amd");
  assert.equal(brandFromVendor("Apple Inc."), "apple");
  assert.equal(brandFromVendor("APPLE, INC."), "apple");
  assert.equal(brandFromVendor("Microsoft Corporation"), "microsoft");
  assert.equal(brandFromVendor("an NVIDIA-compatible accelerator"), null);
  assert.equal(brandFromVendor("AMD-compatible"), null);
  assert.equal(brandFromVendor(null), null);
});

test("matches OS marks only from exact collector values", () => {
  assert.equal(brandFromOperatingSystem("linux"), "linux");
  assert.equal(brandFromOperatingSystem("macos"), "apple");
  assert.equal(brandFromOperatingSystem("windows"), "windows");
  assert.equal(brandFromOperatingSystem("Windows-compatible"), null);
  assert.equal(brandFromOperatingSystem("unknown"), null);
});

test("matches CPU marks only from anchored processor signatures", () => {
  assert.equal(brandFromCpuModel("Apple M5 Pro"), "apple");
  assert.equal(brandFromCpuModel("AMD EPYC 9654"), "amd");
  assert.equal(brandFromCpuModel("Intel(R) Xeon(R) Platinum 8480+"), "intel");
  assert.equal(brandFromCpuModel("Apple-compatible processor"), null);
  assert.equal(brandFromCpuModel("NVIDIA Grace CPU Superchip"), null);
  assert.equal(brandFromCpuModel(null), null);
});
