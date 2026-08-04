import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { extname, resolve, sep } from "node:path";
import { Readable } from "node:stream";
import { getAsset, isSea } from "node:sea";
import worker from "../dist/server/index.js";
import { loadControlPlaneConfig, TelemetryPoller } from "./telemetry.mjs";

const VERSION = "0.1.0";
const SEA = isSea();
const ASSET_ROOT = resolve(process.env.CONTROL_PLANE_ASSET_DIR ?? "dist/client");
const MIME_TYPES = {
  ".css": "text/css; charset=utf-8",
  ".gif": "image/gif",
  ".ico": "image/x-icon",
  ".jpeg": "image/jpeg",
  ".jpg": "image/jpeg",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".png": "image/png",
  ".svg": "image/svg+xml",
  ".txt": "text/plain; charset=utf-8",
  ".webp": "image/webp",
  ".woff": "font/woff",
  ".woff2": "font/woff2",
};

function usage() {
  return `OpenLake Control Plane ${VERSION}

Usage:
  openlake-control-plane --config <openlake.toml> [options]

Options:
  --config <path>             Existing OpenLake TOML configuration
  --listen <ip:port>          UI listener (default: 0.0.0.0:3001)
  --poll-interval-ms <ms>     Node polling interval (default: 5000)
  --request-timeout-ms <ms>   Per-endpoint timeout (default: 2000)
  --help                      Show this help
  --version                   Show the version

Environment equivalents:
  OPENLAKE_CONFIG, CONTROL_PLANE_ADDR,
  CONTROL_PLANE_POLL_INTERVAL_MS, CONTROL_PLANE_REQUEST_TIMEOUT_MS`;
}

function readOption(argv, name) {
  const exact = argv.indexOf(name);
  if (exact >= 0) {
    if (!argv[exact + 1] || argv[exact + 1].startsWith("--")) throw new Error(`${name} requires a value`);
    return argv[exact + 1];
  }
  const prefix = `${name}=`;
  const inline = argv.find(value => value.startsWith(prefix));
  return inline?.slice(prefix.length);
}

export function parseListenAddress(value) {
  let parsed;
  try {
    parsed = new URL(`tcp://${value}`);
  } catch {
    throw new Error(`invalid --listen address: ${value}`);
  }
  const port = Number(parsed.port);
  if (!parsed.hostname || !Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`invalid --listen address: ${value}`);
  }
  return { host: parsed.hostname, port };
}

export function parseArguments(argv) {
  if (argv.includes("--help")) return { help: true };
  if (argv.includes("--version")) return { version: true };
  const configPath = readOption(argv, "--config") ?? process.env.OPENLAKE_CONFIG;
  if (!configPath) throw new Error("--config is required (or set OPENLAKE_CONFIG)");
  const listen = parseListenAddress(readOption(argv, "--listen") ?? process.env.CONTROL_PLANE_ADDR ?? "0.0.0.0:3001");
  const intervalMs = Number(readOption(argv, "--poll-interval-ms") ?? process.env.CONTROL_PLANE_POLL_INTERVAL_MS ?? 5000);
  const timeoutMs = Number(readOption(argv, "--request-timeout-ms") ?? process.env.CONTROL_PLANE_REQUEST_TIMEOUT_MS ?? 2000);
  if (!Number.isInteger(intervalMs) || intervalMs < 500) throw new Error("poll interval must be an integer of at least 500ms");
  if (!Number.isInteger(timeoutMs) || timeoutMs < 100) throw new Error("request timeout must be an integer of at least 100ms");
  return { configPath, intervalMs, listen, timeoutMs };
}

function json(value, status = 200) {
  return new Response(JSON.stringify(value), {
    status,
    headers: {
      "cache-control": "no-store",
      "content-type": "application/json; charset=utf-8",
    },
  });
}

function contentType(pathname) {
  return MIME_TYPES[extname(pathname).toLowerCase()] ?? "application/octet-stream";
}

async function assetResponse(request) {
  const pathname = decodeURIComponent(new URL(request.url).pathname);
  if (pathname.includes("\0") || pathname.split("/").includes("..")) return new Response("Not found", { status: 404 });
  const key = pathname.replace(/^\/+/, "");
  try {
    const bytes = SEA
      ? Buffer.from(getAsset(key))
      : await readFile((() => {
          const path = resolve(ASSET_ROOT, key);
          if (path !== ASSET_ROOT && !path.startsWith(`${ASSET_ROOT}${sep}`)) throw new Error("invalid asset path");
          return path;
        })());
    return new Response(request.method === "HEAD" ? null : bytes, {
      headers: {
        "cache-control": key.startsWith("assets/") ? "public, max-age=31536000, immutable" : "public, max-age=300",
        "content-length": String(bytes.byteLength),
        "content-type": contentType(pathname),
      },
    });
  } catch {
    return new Response("Not found", { status: 404 });
  }
}

function apiResponse(request, poller) {
  const url = new URL(request.url);
  if (request.method !== "GET" && request.method !== "HEAD") {
    return new Response("Method Not Allowed", { status: 405, headers: { allow: "GET, HEAD" } });
  }
  if (url.pathname === "/healthz") {
    return json({ status: "ok", service: "openlake-control-plane", version: VERSION });
  }
  if (url.pathname === "/readyz") {
    const snapshot = poller.snapshot();
    const ready = snapshot.totals.healthy + snapshot.totals.degraded > 0;
    return json({ status: ready ? "ready" : "degraded", ...snapshot.totals }, ready ? 200 : 503);
  }
  if (url.pathname === "/api/control-plane/snapshot") return json(poller.snapshot());
  const vllm = url.pathname.match(/^\/api\/control-plane\/nodes\/(\d+)\/vllm$/);
  if (vllm) {
    const body = poller.vllmMetrics(Number(vllm[1]));
    return body === null
      ? json({ error: "vLLM metrics are not available for this node" }, 404)
      : new Response(request.method === "HEAD" ? null : body, {
          headers: { "cache-control": "no-store", "content-type": "text/plain; version=0.0.4; charset=utf-8" },
        });
  }
  return null;
}

async function toWebRequest(request) {
  const host = request.headers.host ?? "localhost";
  const url = new URL(request.url ?? "/", `http://${host}`);
  const init = { headers: request.headers, method: request.method };
  if (request.method !== "GET" && request.method !== "HEAD") {
    init.body = Readable.toWeb(request);
    init.duplex = "half";
  }
  return new Request(url, init);
}

async function writeNodeResponse(response, webResponse) {
  response.statusCode = webResponse.status;
  response.statusMessage = webResponse.statusText;
  for (const [name, value] of webResponse.headers) response.setHeader(name, value);
  if (!webResponse.body) {
    response.end();
    return;
  }
  Readable.fromWeb(webResponse.body).pipe(response);
}

export async function startControlPlane(options) {
  const config = await loadControlPlaneConfig(options.configPath);
  const poller = new TelemetryPoller(config, { intervalMs: options.intervalMs, timeoutMs: options.timeoutMs });
  await poller.start();
  const executionContext = { passThroughOnException() {}, waitUntil() {} };
  const environment = { ASSETS: { fetch: assetResponse } };
  const server = createServer(async (request, response) => {
    try {
      const webRequest = await toWebRequest(request);
      const api = apiResponse(webRequest, poller);
      const pathname = new URL(webRequest.url).pathname;
      const asset = !api && extname(pathname) && !pathname.endsWith(".rsc") ? await assetResponse(webRequest) : null;
      const webResponse = api ?? asset ?? await worker.fetch(webRequest, environment, executionContext);
      await writeNodeResponse(response, webResponse);
    } catch (error) {
      console.error("request failed", error);
      await writeNodeResponse(response, json({ error: "internal control-plane error" }, 500));
    }
  });
  await new Promise((resolveListen, rejectListen) => {
    server.once("error", rejectListen);
    server.listen(options.listen.port, options.listen.host, resolveListen);
  });
  return { config, poller, server };
}

async function main() {
  try {
    const options = parseArguments(process.argv.slice(2));
    if (options.help) {
      console.log(usage());
      return;
    }
    if (options.version) {
      console.log(VERSION);
      return;
    }
    const runtime = await startControlPlane(options);
    const address = runtime.server.address();
    const displayHost = typeof address === "object" && address?.address === "0.0.0.0" ? "localhost" : options.listen.host;
    console.log(`OpenLake Control Plane ${VERSION}`);
    console.log(`UI: http://${displayHost}:${options.listen.port}`);
    console.log("Config: loaded");
    console.log(`Polling ${runtime.config.nodes.length} node${runtime.config.nodes.length === 1 ? "" : "s"} every ${options.intervalMs}ms`);
    const shutdown = signal => {
      console.log(`Received ${signal}; shutting down`);
      runtime.poller.stop();
      runtime.server.close(() => process.exit(0));
    };
    process.once("SIGINT", () => shutdown("SIGINT"));
    process.once("SIGTERM", () => shutdown("SIGTERM"));
  } catch (error) {
    console.error(`openlake-control-plane: ${error instanceof Error ? error.message : error}`);
    console.error("Run with --help for usage.");
    process.exitCode = 1;
  }
}

if (process.env.CONTROL_PLANE_LIBRARY_MODE !== "1") void main();
