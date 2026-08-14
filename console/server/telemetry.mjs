import { readFile } from "node:fs/promises";
import { Agent as HttpAgent, request as httpRequest } from "node:http";
import { Agent as HttpsAgent, request as httpsRequest } from "node:https";
import { dirname, resolve } from "node:path";
import { parse as parseToml } from "smol-toml";

const MAX_RESPONSE_BYTES = 8 * 1024 * 1024;

function parseSocketAddress(value, field) {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`${field} must be an ip:port string`);
  }
  let parsed;
  try {
    parsed = new URL(`tcp://${value}`);
  } catch {
    throw new Error(`${field} is not a valid ip:port address: ${value}`);
  }
  const port = Number(parsed.port);
  if (!parsed.hostname || !Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`${field} is not a valid ip:port address: ${value}`);
  }
  return { host: parsed.hostname, port };
}

function dialHost(host) {
  if (host === "0.0.0.0") return "127.0.0.1";
  if (host === "::" || host === "[::]") return "::1";
  return host;
}

function urlHost(host) {
  return host.includes(":") && !host.startsWith("[") ? `[${host}]` : host;
}

export async function loadControlPlaneConfig(configPath) {
  const absolutePath = resolve(configPath);
  const document = parseToml(await readFile(absolutePath, "utf8"));

  if (document.mode !== "kv") {
    throw new Error(`${absolutePath} console requires mode = "kv"`);
  }
  if (!Array.isArray(document.kv_agents) || document.kv_agents.length === 0) {
    throw new Error(`${absolutePath} requires a non-empty kv_agents array`);
  }

  const tls = document.rpc_tls && typeof document.rpc_tls === "object" ? document.rpc_tls : null;
  const caPath = typeof tls?.client_ca === "string"
    ? resolve(dirname(absolutePath), tls.client_ca)
    : null;
  const ca = caPath ? await readFile(caPath) : undefined;
  const scheme = tls ? "https" : "http";

  const nodes = document.kv_agents.map((rpcAddress, id) => {
    const field = `kv_agents[${id}]`;
    const rpc = parseSocketAddress(rpcAddress, field);
    if (rpc.port === 65535) throw new Error(`${field} cannot derive a telemetry port from 65535`);
    const host = dialHost(rpc.host);
    const telemetryPort = rpc.port + 1;
    return {
      id,
      diskCount: 0,
      rpcAddress,
      telemetryAddress: `${host}:${telemetryPort}`,
      telemetryOrigin: `${scheme}://${urlHost(host)}:${telemetryPort}`,
      rpcOrigin: `${scheme}://${urlHost(host)}:${rpc.port}`,
    };
  });

  return {
    configPath: absolutePath,
    nodes,
    tls: { enabled: Boolean(tls), ca },
  };
}

function parseLabels(value) {
  if (!value) return {};
  const labels = {};
  const expression = /([a-zA-Z_][a-zA-Z0-9_]*)="((?:\\.|[^"\\])*)"/g;
  for (const match of value.matchAll(expression)) {
    labels[match[1]] = match[2]
      .replaceAll("\\n", "\n")
      .replaceAll("\\\"", "\"")
      .replaceAll("\\\\", "\\");
  }
  return labels;
}

export function parsePrometheus(text, sampleLimit = 5000) {
  const samples = [];
  for (const line of text.split(/\r?\n/)) {
    if (!line || line.startsWith("#")) continue;
    const match = line.match(/^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{(.*)\})?\s+([^\s]+)(?:\s+\d+)?$/);
    if (!match) continue;
    const value = Number(match[3]);
    if (!Number.isFinite(value)) continue;
    samples.push({ name: match[1], labels: parseLabels(match[2]), value });
    if (samples.length >= sampleLimit) break;
  }
  return samples;
}

function requestText(url, { agent, timeoutMs }) {
  return new Promise((resolveRequest, rejectRequest) => {
    const request = (url.protocol === "https:" ? httpsRequest : httpRequest)(url, {
      agent,
      headers: { accept: "*/*", "user-agent": "openlake-control-plane/0.1" },
      method: "GET",
    }, response => {
      const chunks = [];
      let size = 0;
      response.on("data", chunk => {
        size += chunk.length;
        if (size > MAX_RESPONSE_BYTES) {
          request.destroy(new Error(`telemetry response exceeded ${MAX_RESPONSE_BYTES} bytes`));
          return;
        }
        chunks.push(chunk);
      });
      response.on("end", () => {
        const body = Buffer.concat(chunks).toString("utf8");
        const status = response.statusCode ?? 500;
        if (status < 200 || status >= 300) {
          rejectRequest(new Error(`HTTP ${status}: ${body.slice(0, 240)}`));
          return;
        }
        resolveRequest({
          body,
          contentType: String(response.headers["content-type"] ?? "application/octet-stream"),
          status,
        });
      });
    });
    request.setTimeout(timeoutMs, () => request.destroy(new Error(`request timed out after ${timeoutMs}ms`)));
    request.on("error", rejectRequest);
    request.end();
  });
}

async function requestNodeText(path, node, poller) {
  const origins = [...new Set([node.telemetryOrigin, node.rpcOrigin])];
  const errors = [];
  for (const origin of origins) {
    const url = new URL(path, origin);
    const agent = url.protocol === "https:" ? poller.httpsAgent : poller.httpAgent;
    try {
      return await requestText(url, { agent, timeoutMs: poller.timeoutMs });
    } catch (error) {
      errors.push(`${origin}: ${error instanceof Error ? error.message : error}`);
    }
  }
  throw new Error(errors.join("; fallback "));
}

function errorMessage(result) {
  return result.status === "rejected"
    ? String(result.reason instanceof Error ? result.reason.message : result.reason)
    : null;
}

export class TelemetryPoller {
  constructor(config, { intervalMs = 5000, timeoutMs = 2000 } = {}) {
    this.config = config;
    this.intervalMs = intervalMs;
    this.timeoutMs = timeoutMs;
    this.polling = false;
    this.timer = null;
    this.nodes = new Map();
    this.httpAgent = new HttpAgent({ keepAlive: true, maxSockets: Math.max(4, config.nodes.length * 2) });
    this.httpsAgent = new HttpsAgent({
      ca: config.tls.ca,
      keepAlive: true,
      maxSockets: Math.max(4, config.nodes.length * 2),
      rejectUnauthorized: true,
    });
  }

  async start() {
    await this.poll();
    this.timer = setInterval(() => void this.poll(), this.intervalMs);
    this.timer.unref?.();
  }

  stop() {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
    this.httpAgent.destroy();
    this.httpsAgent.destroy();
  }

  async poll() {
    if (this.polling) return;
    this.polling = true;
    try {
      await Promise.all(this.config.nodes.map(node => this.pollNode(node)));
    } finally {
      this.polling = false;
    }
  }

  async pollNode(node) {
    const startedAt = Date.now();
    const [openlakeResult, vllmResult] = await Promise.allSettled([
      requestNodeText("/v1/telemetry/openlake", node, this),
      requestNodeText("/v1/telemetry/vllm", node, this),
    ]);
    const previous = this.nodes.get(node.id);
    let openlake = previous?.openlake ?? null;
    let vllm = previous?.vllm ?? null;
    let rawVllm = previous?.rawVllm ?? null;

    let openlakeError = errorMessage(openlakeResult);
    if (openlakeResult.status === "fulfilled") {
      try {
        openlake = JSON.parse(openlakeResult.value.body);
      } catch (error) {
        openlakeError = `invalid OpenLake JSON: ${error instanceof Error ? error.message : error}`;
      }
    }
    if (vllmResult.status === "fulfilled") {
      rawVllm = vllmResult.value.body;
      vllm = {
        contentType: vllmResult.value.contentType,
        samples: parsePrometheus(vllmResult.value.body),
      };
    }

    const vllmError = errorMessage(vllmResult);
    const successful = !openlakeError || !vllmError;
    const status = !openlakeError && !vllmError ? "healthy" : successful ? "degraded" : "unreachable";
    this.nodes.set(node.id, {
      id: node.id,
      diskCount: node.diskCount,
      rpcAddress: node.rpcAddress,
      telemetryAddress: node.telemetryAddress,
      status,
      observedAt: new Date().toISOString(),
      lastSuccessfulAt: successful ? new Date().toISOString() : previous?.lastSuccessfulAt ?? null,
      latencyMs: Date.now() - startedAt,
      openlake,
      vllm,
      rawVllm,
      errors: { openlake: openlakeError, vllm: vllmError },
    });
  }

  snapshot() {
    const nodes = this.config.nodes.map(node => {
      const state = this.nodes.get(node.id) ?? {
        ...node,
        status: "unreachable",
        observedAt: null,
        lastSuccessfulAt: null,
        latencyMs: null,
        openlake: null,
        vllm: null,
        errors: { openlake: "not polled", vllm: "not polled" },
      };
      return Object.fromEntries(Object.entries(state).filter(([key]) => key !== "rawVllm"));
    });
    return {
      schemaVersion: "1.0",
      generatedAt: new Date().toISOString(),
      pollIntervalMs: this.intervalMs,
      totals: {
        configured: nodes.length,
        healthy: nodes.filter(node => node.status === "healthy").length,
        degraded: nodes.filter(node => node.status === "degraded").length,
        unreachable: nodes.filter(node => node.status === "unreachable").length,
      },
      nodes,
    };
  }

  vllmMetrics(nodeId) {
    return this.nodes.get(nodeId)?.rawVllm ?? null;
  }
}
