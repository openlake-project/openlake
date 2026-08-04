import assert from "node:assert/strict";
import test from "node:test";

import { aggregateOpenLakeTokensServed } from "../app/control-plane-data.ts";

function snapshot(options = {}) {
  const servedBlocks = Object.hasOwn(options, "servedBlocks") ? options.servedBlocks : 5;
  const blockSizes = options.blockSizes ?? [16];
  return {
    schemaVersion: "1.0",
    generatedAt: new Date().toISOString(),
    pollIntervalMs: 5000,
    totals: { configured: 1, healthy: 1, degraded: 0, unreachable: 0 },
    nodes: [{
      id: 0,
      diskCount: 0,
      rpcAddress: "127.0.0.1:9400",
      telemetryAddress: "127.0.0.1:9401",
      status: "healthy",
      observedAt: null,
      lastSuccessfulAt: null,
      latencyMs: null,
      errors: { openlake: null, vllm: null },
      openlake: {
        node_id: 0,
        openlake: {
          version: "0.1.0",
          mode: "kv",
          transport: "h2",
          data_paths: [],
          kv_cache: {
            attached: true,
            configured_capacity_bytes: 1024,
            slot_bytes: 128,
            slot_count: 8,
            used_slots: null,
            used_bytes: 0,
            ...(servedBlocks === undefined ? {} : { served_blocks: servedBlocks }),
          },
        },
      },
      vllm: {
        contentType: "text/plain",
        samples: blockSizes.map(blockSize => ({
          name: "vllm:cache_config_info",
          labels: { block_size: String(blockSize) },
          value: 1,
        })),
      },
    }],
  };
}

test("derives tokens only from server-confirmed blocks and the reported token block size", () => {
  assert.deepEqual(aggregateOpenLakeTokensServed(snapshot()), {
    blocks: 5,
    tokens: 80,
    blockSizes: [16],
  });
});

test("does not infer served tokens without the openlaked counter", () => {
  assert.equal(
    aggregateOpenLakeTokensServed(snapshot({ servedBlocks: undefined })),
    null,
  );
});

test("does not guess when an engine reports conflicting block sizes", () => {
  assert.equal(
    aggregateOpenLakeTokensServed(snapshot({ blockSizes: [16, 32] })),
    null,
  );
});
