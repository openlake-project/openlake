import assert from "node:assert/strict";
import { access, readFile } from "node:fs/promises";
import test from "node:test";

const projectRoot = new URL("../", import.meta.url);

async function render(path = "/") {
  const workerUrl = new URL("../dist/server/index.js", import.meta.url);
  workerUrl.searchParams.set("test", `${process.pid}-${Date.now()}-${path}`);
  const { default: worker } = await import(workerUrl.href);
  return worker.fetch(
    new Request(`http://localhost${path}`, { headers: { accept: "text/html" } }),
    { ASSETS: { fetch: async () => new Response("Not found", { status: 404 }) } },
    { waitUntil() {}, passThroughOnException() {} },
  );
}

test("server-renders a strict live-data dashboard", async () => {
  const response = await render();
  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type") ?? "", /^text\/html\b/i);

  const html = await response.text();
  assert.match(html, /Dashboard/);
  assert.doesNotMatch(html, /Live OpenLake and vLLM telemetry from configured nodes/);
  assert.match(html, /aria-label="Loading telemetry"/);
  assert.match(html, /href="\/" class="active"/);
  assert.match(html, /href="\/nodes"/);
  assert.match(html, /href="\/fleet"/);
  assert.doesNotMatch(html, /href="\/(?:performance|storage|activity|settings)"/);
  assert.doesNotMatch(html, /1\.42M|289 \/ 352 GiB|17 of 32|vllm-prod-07|Arnav Kumar|arnav@/i);
  assert.doesNotMatch(html, /NVIDIA DGX|AMD EPYC|H100|H200|mlx5_0|28\.6 \/ 46\.1 TiB/i);
  assert.doesNotMatch(html, /codex-preview|Your site is taking shape|react-loading-skeleton/i);
});

test("ships Dashboard, Topology, and Fleet as the only product routes", async () => {
  const topologyResponse = await render("/nodes");
  assert.equal(topologyResponse.status, 200);
  const topologyHtml = await topologyResponse.text();
  assert.match(topologyHtml, />Topology</);
  assert.match(topologyHtml, /Interactive hardware topology and OpenLake node telemetry/);
  assert.match(topologyHtml, /aria-label="Loading telemetry"/);
  assert.match(topologyHtml, /href="\/nodes" class="active"/);
  assert.match(topologyHtml, /aria-label="Primary navigation"/);
  assert.doesNotMatch(topologyHtml, /NVLINK|EPYC|OPENLAKE KV CACHE|mlx5|GPU (?:<!-- -->)?[0-9]/i);
  assert.doesNotMatch(topologyHtml, /sidebar|Toggle sidebar|Open navigation/i);

  const fleetResponse = await render("/fleet");
  assert.equal(fleetResponse.status, 200);
  const fleetHtml = await fleetResponse.text();
  assert.match(fleetHtml, />Fleet</);
  assert.doesNotMatch(fleetHtml, /Physical identity and OpenLake allocation across the fleet/);
  assert.doesNotMatch(fleetHtml, /Configured OpenLake nodes and their live telemetry state/);
  assert.match(fleetHtml, /aria-label="Loading telemetry"/);
  assert.match(fleetHtml, /href="\/fleet" class="active"/);
  assert.doesNotMatch(fleetHtml, /NVIDIA DGX|H100|H200|Managed GPUs/i);

  for (const path of ["/performance", "/storage", "/activity", "/settings"]) {
    const response = await render(path);
    assert.equal(response.status, 404, path);
  }
});

test("ships no demo telemetry path", async () => {
  const [dataSource, packageJson, layout, styles, shell, gitignore] = await Promise.all([
    readFile(new URL("app/control-plane-data.ts", projectRoot), "utf8"),
    readFile(new URL("package.json", projectRoot), "utf8"),
    readFile(new URL("app/layout.tsx", projectRoot), "utf8"),
    readFile(new URL("app/globals.css", projectRoot), "utf8"),
    readFile(new URL("app/shell.tsx", projectRoot), "utf8"),
    readFile(new URL(".gitignore", projectRoot), "utf8"),
  ]);

  assert.doesNotMatch(dataSource, /demoControlPlane|DEMO_MODE|demo-control-plane/);
  assert.match(dataSource, /snapshot: null,[\s\S]*loading: true,[\s\S]*error: null/);
  assert.match(dataSource, /fetch\("\/api\/control-plane\/snapshot"/);
  assert.match(gitignore, /\/app\/demo\/\*\.json/);
  assert.doesNotMatch(packageJson, /react-loading-skeleton/);
  assert.doesNotMatch(layout, /og\.png|summary_large_image/);
  assert.match(styles, /\.control-plane-state/);
  assert.match(styles, /:root\[data-theme="light"\] \.app-shell\.view-overview/);
  assert.match(shell, /aria-label="Primary navigation"/);
  assert.doesNotMatch(shell, /Sidebar|sidebar|Toggle sidebar|Open navigation/);

  await assert.rejects(access(new URL("app/demo/demo-mode.ts", projectRoot)));
  await assert.rejects(access(new URL("app/demo/demo-control-plane.json", projectRoot)));

  for (const route of ["activity", "performance", "settings", "storage"]) {
    await assert.rejects(access(new URL(`app/${route}/page.tsx`, projectRoot)));
  }
});
