# SPDX-License-Identifier: Apache-2.0

import dataclasses
import hashlib
import inspect
import os
import queue
import struct
import threading
import time
from dataclasses import dataclass

import torch
import vllm.envs as envs
from vllm.distributed.kv_events import BlockStored
from vllm.distributed.kv_transfer.kv_connector.v1.base import KVConnectorMetadata
from vllm.logger import init_logger
from vllm.utils.math_utils import cdiv
from vllm.v1.core.kv_cache_utils import (
    BlockHashListWithBlockSize,
    KVCacheBlock,
    maybe_convert_block_hash,
    resolve_kv_cache_block_sizes,
)
from vllm.v1.core.single_type_kv_cache_manager import FullAttentionManager
from vllm.v1.kv_cache_interface import (
    FullAttentionSpec,
    KVCacheSpec,
    MLAAttentionSpec,
    MambaSpec,
    SlidingWindowMLASpec,
    UniformTypeKVCacheSpecs,
)
from vllm.v1.kv_cache_spec_registry import KVCacheSpecRegistry

logger = init_logger(__name__)

# support multiple vLLM versions
_RBM_TAKES_BOUNDARIES = (
    "reachable_boundaries"
    in inspect.signature(FullAttentionManager.reachable_block_mask).parameters
)
_FLCH_RETURNS_LENGTH = str(
    inspect.signature(FullAttentionManager.find_longest_cache_hit).return_annotation
).endswith(", int]")

SLOT_HEADER_BYTES = 54
MAX_SLOT_BYTES = (1 << 32) - 1
CLIENT_NODE_ID_BASE = 2_048
CLIENT_NODE_ID_MAX = 0xFFF

_HASH_SEED_HELP = (
    "OpenLake external KV offloading requires PYTHONHASHSEED to be set for "
    "block-hash consistency. Please set it, e.g. "
    "PYTHONHASHSEED=0 vllm serve <model> ..."
)


def _require_fixed_hash_seed() -> None:
    if os.getenv("PYTHONHASHSEED") is None:
        raise RuntimeError(_HASH_SEED_HELP)


def _unwrap(spec):
    if isinstance(spec, UniformTypeKVCacheSpecs):
        return next(iter(spec.kv_cache_specs.values()))
    return spec


class ChunkHashes(BlockHashListWithBlockSize):

    def __init__(self, hashes, hash_bs: int, block_bs: int):
        assert block_bs % hash_bs == 0
        self.block_hashes = hashes
        self.scale_factor = block_bs // hash_bs

    def _get_value_at(self, idx: int):
        return self.block_hashes[idx * self.scale_factor + self.scale_factor - 1]


def chunk_view(hashes, hash_bs: int, block_bs: int):
    return hashes if block_bs == hash_bs else ChunkHashes(hashes, hash_bs, block_bs)


class GroupKeys:

    def __init__(self, g_idx: int, spec, hash_bs: int, model_tag: bytes = bytes(12)):
        self.g_idx = g_idx
        self.spec = spec
        self.manager = KVCacheSpecRegistry.get_manager_class(spec)
        self.block_size = spec.block_size
        self._hash_bs = hash_bs
        self._model_tag = model_tag

    def chunks(self, block_hashes):
        return chunk_view(block_hashes, self._hash_bs, self.block_size)

    def key_for(self, h: bytes, ns: tuple[int, int, int, int]) -> bytes:
        t, c, d, q = ns
        return (
            bytes(h).ljust(32, b"\x00")[:32]
            + self._model_tag
            + struct.pack(
                "<HHHHH", self.g_idx & 0xFFFF, t & 0xFFFF, c & 0xFFFF, d & 0xFFFF,
                q & 0xFFFF,
            )
        )

    def process_tokens(self, token_len, block_hashes, mask_num=0,
                       chunk_mask=None, put_step=1, put_step_rank=0):
        chunks = self.chunks(block_hashes)
        start_chunk = cdiv(mask_num, self.block_size)
        end_chunk = min(len(chunks), token_len // self.block_size)
        if chunk_mask is not None:
            end_chunk = min(end_chunk, start_chunk + len(chunk_mask))
        for chunk_id in range(start_chunk, end_chunk):
            if chunk_mask is not None and not chunk_mask[chunk_id - start_chunk]:
                continue
            if chunk_id % put_step != put_step_rank:
                continue
            start = chunk_id * self.block_size
            yield start, start + self.block_size, bytes(chunks[chunk_id])


class GroupLayout:

    def __init__(self):
        self.base_addrs: list[int] = []
        self.block_len: list[int] = []

    def set(self, base_addrs: list[int], block_len: list[int]) -> None:
        self.base_addrs, self.block_len = base_addrs, block_len

    def addrs_for(self, block_id: int) -> list[tuple[int, int]]:
        return [(b + block_id * n, n) for b, n in zip(self.base_addrs, self.block_len)]


class Coordinator:

    def __init__(self, kv_cache_groups, group_keys, sched_bs, hash_bs, use_eagle,
                 retention_interval):
        assert all(g.spec.block_size % hash_bs == 0 for g in group_keys), (
            "block_size must be divisible by hash_block_size")
        assert sched_bs % hash_bs == 0, (
            f"scheduler_block_size ({sched_bs}) must be a multiple of "
            f"hash_block_size ({hash_bs})")
        assert all(sched_bs % g.spec.block_size == 0 for g in group_keys), (
            "scheduler_block_size must be a multiple of each group's block_size")
        self.kv_cache_groups = kv_cache_groups
        self._group_keys = group_keys
        self._sched_bs = sched_bs
        self._hash_bs = hash_bs
        self.lcm_block_size = sched_bs
        self.use_eagle = use_eagle
        self._retention_interval = retention_interval
        self._verify_and_split_kv_cache_groups()

    def _verify_and_split_kv_cache_groups(self) -> None:
        attention_groups: list[tuple[object, list[int], type]] = []
        for group in self._group_keys:
            spec, manager_cls = group.spec, group.manager
            assert manager_cls is not None, (
                f"no manager registered for kv-cache spec {spec}")
            for existing_spec, group_ids, existing_cls in attention_groups:
                if existing_spec == spec:
                    assert manager_cls is existing_cls, (
                        f"spec {spec} maps to two manager classes: "
                        f"{existing_cls} and {manager_cls}")
                    group_ids.append(group.g_idx)
                    break
            else:
                attention_groups.append((spec, [group.g_idx], manager_cls))
        self.attention_groups = sorted(
            attention_groups, key=lambda x: not isinstance(x[0], FullAttentionSpec))

        self.eagle_group_ids: set[int] = {
            i for i, g in enumerate(self.kv_cache_groups) if g.is_eagle_group}
        if self.use_eagle and not self.eagle_group_ids:
            self.eagle_group_ids = set(range(len(self.kv_cache_groups)))
        self.eagle_attn_group_indices: set[int] = {
            i for i, (_, group_ids, _) in enumerate(self.attention_groups)
            if any(gid in self.eagle_group_ids for gid in group_ids)}
        if self.use_eagle and not self.eagle_attn_group_indices:
            self.eagle_attn_group_indices = set(range(len(self.attention_groups)))

    def block_hashes_for_spec(self, block_hashes, spec):
        return chunk_view(block_hashes, self._hash_bs, spec.block_size)

    def _reachable_masks(
        self,
        aligned_token_len: int,
        start_token: int,
        *,
        retention_interval: int | None,
        num_prompt_tokens: int | None,
    ) -> tuple[list[bool] | None, ...]:
        assert aligned_token_len % self.lcm_block_size == 0, (
            f"aligned_token_len ({aligned_token_len}) must be a multiple of "
            f"lcm_block_size ({self.lcm_block_size})"
        )
        masks: list[list[bool] | None] = []
        for g_idx, g in enumerate(self.kv_cache_groups):
            spec = _unwrap(g.kv_cache_spec)
            end_chunk = aligned_token_len // spec.block_size
            start_chunk = min(end_chunk, max(0, cdiv(start_token, spec.block_size)))
            manager_cls = KVCacheSpecRegistry.get_manager_class(spec)
            assert manager_cls is not None
            use_eagle = g_idx in self.eagle_group_ids
            if _RBM_TAKES_BOUNDARIES:
                boundary_kwargs = {
                    "reachable_boundaries": ()
                    if num_prompt_tokens is None
                    else (num_prompt_tokens - 1,)
                }
            else:
                boundary_kwargs = {"num_prompt_tokens": num_prompt_tokens}
            mask = manager_cls.reachable_block_mask(
                start_block=start_chunk,
                end_block=end_chunk,
                alignment_tokens=self.lcm_block_size,
                kv_cache_spec=spec,
                use_eagle=use_eagle,
                retention_interval=retention_interval,
                **boundary_kwargs,
            )
            if mask is not None:
                assert len(mask) == end_chunk - start_chunk
            masks.append(mask)
        return tuple(masks)

    def store_mask(self, aligned_token_len, start_token=0, num_prompt_tokens=None):
        return self._reachable_masks(
            aligned_token_len,
            start_token,
            retention_interval=self._retention_interval,
            num_prompt_tokens=num_prompt_tokens,
        )

    def lookup_mask(self, aligned_token_len):
        return self._reachable_masks(
            aligned_token_len, 0, retention_interval=None, num_prompt_tokens=None
        )

    def load_mask(self, block_hashes, token_len):
        masks, _ = self.find_longest_cache_hit(
            block_hashes, token_len, _ExistsPool(self._hash_bs), apply_eagle=False)
        return masks

    def find_longest_cache_hit(self, block_hashes, max_length, pool,
                               apply_eagle=True):
        blocks_per_group, hit_length = self._find_hit_blocks(
            block_hashes, max_length, pool, apply_eagle=apply_eagle)
        masks = tuple(
            [blk is not pool.null_block for blk in blocks]
            for blocks in blocks_per_group)
        return masks, hit_length

    def _find_hit_blocks(self, block_hashes, max_length, pool, *, apply_eagle=True):
        num_groups = len(self._group_keys)
        eagle_idx = self.eagle_attn_group_indices if apply_eagle else set()

        if len(self.attention_groups) == 1:
            spec, ids, manager = self.attention_groups[0]
            res = manager.find_longest_cache_hit(
                block_hashes=self.block_hashes_for_spec(block_hashes, spec),
                max_length=max_length, kv_cache_group_ids=ids, block_pool=pool,
                kv_cache_spec=spec, drop_eagle_block=(0 in eagle_idx),
                alignment_tokens=spec.block_size)
            if _FLCH_RETURNS_LENGTH:
                hit_blocks, hit_length = res
            else:
                hit_blocks = res
                hit_length = len(hit_blocks[0]) * spec.block_size
            blocks_by_group: list = [[] for _ in range(num_groups)]
            for gid, blks in zip(ids, hit_blocks, strict=True):
                blocks_by_group[gid] = blks
            return tuple(blocks_by_group), hit_length

        hit_length = max_length
        blocks_by_group = [None] * num_groups
        length_by_group: list[int] = [0] * num_groups
        simple = len(self.attention_groups) == 2 and isinstance(
            self.attention_groups[0][0], FullAttentionSpec)
        verified: set[int] = set()
        while True:
            curr = hit_length
            for i, (spec, ids, manager) in enumerate(self.attention_groups):
                first = ids[0]
                if (isinstance(spec, FullAttentionSpec)
                        and blocks_by_group[first] is not None):
                    curr = min(curr, length_by_group[first])
                    continue
                drop = i in eagle_idx and i not in verified
                bound = min(curr + spec.block_size, max_length) if drop else curr
                res = manager.find_longest_cache_hit(
                    block_hashes=self.block_hashes_for_spec(block_hashes, spec),
                    max_length=bound, kv_cache_group_ids=ids, block_pool=pool,
                    kv_cache_spec=spec, drop_eagle_block=drop,
                    alignment_tokens=self.lcm_block_size)
                if _FLCH_RETURNS_LENGTH:
                    hit_blocks, length = res
                else:
                    hit_blocks = res
                    length = len(hit_blocks[0]) * spec.block_size
                if drop:
                    verified.add(i)
                elif length < curr:
                    verified.clear()
                curr = length
                for gid, blks in zip(ids, hit_blocks, strict=True):
                    blocks_by_group[gid] = blks
                    length_by_group[gid] = length
            if curr >= hit_length:
                break
            hit_length = curr
            if simple:
                break
        spec0, ids0, _ = self.attention_groups[0]
        if isinstance(spec0, FullAttentionSpec):
            n = hit_length // spec0.block_size
            for gid in ids0:
                full_blks = blocks_by_group[gid]
                assert full_blks is not None
                del full_blks[n:]
                length_by_group[gid] = hit_length
        return tuple(b or [] for b in blocks_by_group), hit_length


@dataclass
class PendingLoad:
    local_tokens: int
    external_tokens: int
    can_load: bool = False


def _prefill_tokens(request) -> list[int]:
    if request.prefill_token_ids is not None:
        return request.prefill_token_ids
    assert request.prompt_token_ids is not None
    return request.prompt_token_ids


@dataclass
class RequestTracker:
    req_id: str
    token_len: int
    allocated_block_ids: tuple[list[int], ...]
    num_saved_tokens: int = 0
    token_ids: list[int] | None = None
    prefill_end_tokens: int = 0

    def reset(self) -> None:
        self.token_len = 0
        self.allocated_block_ids = ()
        self.num_saved_tokens = 0
        self.token_ids = None
        self.prefill_end_tokens = 0

    def update(self, new_block_ids: tuple[list[int], ...] | list[int]) -> None:
        if isinstance(new_block_ids, list):
            new_block_ids = (new_block_ids,)
        if len(new_block_ids) != len(self.allocated_block_ids):
            raise ValueError(
                f"group count mismatch: tracker has "
                f"{len(self.allocated_block_ids)}, update has {len(new_block_ids)}"
            )
        for existing, new in zip(self.allocated_block_ids, new_block_ids):
            if new:
                existing.extend(new)


@dataclass
class ReqMeta:
    req_id: str
    token_len_chunk: int
    block_ids: tuple[list[int], ...]
    block_hashes: list
    can_save: bool | None = None
    load: PendingLoad | None = None
    is_last_chunk: bool | None = None
    token_ids: list[int] | None = None
    num_prompt_tokens: int | None = None
    current_event: object | None = None

    @staticmethod
    def from_tracker(
        tracker: RequestTracker,
        block_size: int,
        load: "PendingLoad | None" = None,
        skip_save: "bool | None" = False,
        block_hashes: "list | None" = None,
        is_last_chunk: "bool | None" = None,
    ) -> "ReqMeta | None":
        chunk_boundary = cdiv(tracker.num_saved_tokens + 1, block_size) * block_size
        num_tokens_to_save = tracker.token_len // block_size * block_size
        skip_save = skip_save or num_tokens_to_save < chunk_boundary
        if load is not None and load.can_load:
            skip_save = True
        if skip_save and load is None:
            return None
        if not skip_save:
            tracker.num_saved_tokens = num_tokens_to_save
        if load is not None and not load.can_load:
            load = None
        return ReqMeta(
            req_id=tracker.req_id,
            token_len_chunk=num_tokens_to_save,
            block_ids=tracker.allocated_block_ids,
            block_hashes=block_hashes or [],
            can_save=not skip_save,
            load=load,
            is_last_chunk=is_last_chunk,
            token_ids=tracker.token_ids or None,
            num_prompt_tokens=tracker.prefill_end_tokens,
        )


class OpenLakeConnectorMetadata(KVConnectorMetadata):
    def __init__(self, unfinished_request_ids: set[str], preempted_req_ids: set[str]):
        self.requests: list[ReqMeta] = []
        self.unfinished_request_ids = unfinished_request_ids
        self.preempted_req_ids = preempted_req_ids

    def add_request(self, req_meta: ReqMeta) -> None:
        self.requests.append(req_meta)


class _ExistsPool:

    def __init__(self, hash_block_size: int,
                 exists: set[tuple[int, bytes]] | None = None):
        self._exists = exists
        self.hash_block_size = hash_block_size
        self.null_block = KVCacheBlock(block_id=0)
        self._hit = KVCacheBlock(block_id=1)

    def get_cached_block(self, block_hash, kv_cache_group_ids):
        if self._exists is None:
            return [self._hit] * len(kv_cache_group_ids)
        h = bytes(block_hash)
        if all((g, h) in self._exists for g in kv_cache_group_ids):
            return [self._hit] * len(kv_cache_group_ids)
        return None


def _group_key_spaces(vllm_config, kv_cache_config):
    groups = list(kv_cache_config.kv_cache_groups)
    sched_bs, hash_bs = resolve_kv_cache_block_sizes(kv_cache_config, vllm_config)
    if len(groups) == 1 and groups[0].kv_cache_spec.block_size != sched_bs:
        g = groups[0]
        groups = [
            dataclasses.replace(
                g, kv_cache_spec=dataclasses.replace(
                    g.kv_cache_spec, block_size=sched_bs))
        ]
    speculative = vllm_config.speculative_config
    use_eagle = bool(speculative and speculative.use_eagle())
    model_name = getattr(vllm_config.model_config, "model", "") or ""
    extra = (
        vllm_config.kv_transfer_config.kv_connector_extra_config
        if vllm_config.kv_transfer_config is not None else {}
    )
    cache_prefix = str(extra.get("cache_prefix", ""))
    if model_name or cache_prefix:
        tag_source = model_name if not cache_prefix else f"{cache_prefix}\0{model_name}"
        model_tag = hashlib.blake2b(tag_source.encode(), digest_size=12).digest()
    else:
        model_tag = bytes(12)
    group_keys = [
        GroupKeys(i, _unwrap(g.kv_cache_spec), hash_bs, model_tag)
        for i, g in enumerate(groups)
    ]
    return groups, group_keys, sched_bs, hash_bs, use_eagle


def _group_tp_replication_factors(
    kv_cache_groups,
    *,
    tp_size: int,
    dcp_size: int,
    num_kv_heads: int,
) -> tuple[int, ...]:
    """Return the number of byte-identical TP replicas per cache group."""

    def factor_for(spec: KVCacheSpec) -> int:
        if dcp_size > 1:
            return 1
        inner_specs = (
            tuple(spec.kv_cache_specs.values())
            if isinstance(spec, UniformTypeKVCacheSpecs)
            else (spec,)
        )
        if any(isinstance(inner, MambaSpec) for inner in inner_specs):
            return 1
        if all(
            isinstance(inner, (MLAAttentionSpec, SlidingWindowMLASpec))
            for inner in inner_specs
        ):
            return tp_size
        return max(1, tp_size // num_kv_heads)

    return tuple(factor_for(group.kv_cache_spec) for group in kv_cache_groups)


class GpuBlockCompressor:
    """Optional on-GPU int8 group-quantization codec for the KV transfer
    path (see crates/openlake_kv_client/cuda/src/kv_compression.cu).

    The codec is fixed-ratio: a block's compressed byte size depends only
    on its element count and ``group_size``, never on its contents, so the
    staging layout below can be sized once, at registration time, and every
    (addr, size) pair handed to put_batch/get_batch stays constant for the
    lifetime of the worker.

    This is **not** a bit-exact codec -- each ``group_size``-element chunk
    is rescaled to a shared int8 range, which loses precision. Only enable
    it (``openlake_gpu_compression``) when that KV-cache precision loss is
    an acceptable trade for a smaller wire payload on a bandwidth-limited
    link (e.g. cross-node RDMA/UCX).
    """

    _TORCH_DTYPE_NAMES = {
        "torch.float16": "fp16",
        "torch.bfloat16": "bf16",
    }

    def __init__(self, group_size: int):
        import openlake_client

        if not openlake_client.cuda_compression_available():
            raise RuntimeError(
                "openlake_gpu_compression requires the CUDA-enabled "
                "openlake_client build (built with `--features cuda`)"
            )
        self._native = openlake_client
        self.group_size = group_size
        # Parallel per-segment metadata: (dtype_name, element_count,
        # compressed_block_bytes, raw_block_bytes, raw_base_addr,
        # staging_base_addr).
        self._segments: list[tuple[str, int, int, int, int, int]] = []
        # Keeps the staging tensors alive for the compressor's lifetime.
        self._staging_tensors: list[torch.Tensor] = []
        self._stream = torch.cuda.Stream()

    def add_segment(self, cache, base_addr: int, block_bytes: int, num_blocks: int,
                    register_memory) -> int:
        """Registers one raw KV-cache segment (as produced by
        OpenLakeWorker.register_kv_caches) and allocates its compressed
        staging buffer. Returns the fixed per-block compressed byte size.
        """
        dtype_name = self._TORCH_DTYPE_NAMES.get(str(cache.dtype))
        if dtype_name is None:
            raise ValueError(
                f"openlake_gpu_compression only supports fp16/bf16 KV "
                f"caches, got {cache.dtype}"
            )
        itemsize = cache.element_size()
        if block_bytes % itemsize != 0:
            raise ValueError(
                f"segment block size {block_bytes} is not a whole number "
                f"of {cache.dtype} elements"
            )
        element_count = block_bytes // itemsize
        compressed_bytes = self._native.cuda_compressed_size(
            element_count, self.group_size
        )
        staging = torch.empty(
            num_blocks * compressed_bytes, dtype=torch.uint8, device=cache.device
        )
        register_memory(staging.data_ptr(), staging.numel())
        self._staging_tensors.append(staging)
        self._segments.append((
            dtype_name, element_count, compressed_bytes, block_bytes,
            base_addr, staging.data_ptr(),
        ))
        return compressed_bytes

    def wait_for(self, event) -> None:
        """Makes this compressor's stream wait (GPU-side, non-blocking on
        the host) for `event`, e.g. the event recorded after the model's
        compute stream finished writing the KV cache blocks about to be
        compressed."""
        if event is not None:
            self._stream.wait_event(event)

    def compress_block(self, block_id: int) -> list[tuple[int, int]]:
        """Launches (asynchronously, on this compressor's stream) the
        compression kernel for every segment of `block_id` and returns the
        resulting (staging_addr, compressed_bytes) scatter list. Call
        `synchronize()` before the staging buffers are read (e.g. by
        put_batch)."""
        stream_ptr = self._stream.cuda_stream
        scatter = []
        with torch.cuda.stream(self._stream):
            for dtype_name, element_count, compressed_bytes, block_bytes, \
                    raw_addr, staging_addr in self._segments:
                self._native.cuda_compress(
                    dtype_name,
                    raw_addr + block_id * block_bytes,
                    element_count,
                    self.group_size,
                    staging_addr + block_id * compressed_bytes,
                    compressed_bytes,
                    stream_ptr,
                )
                scatter.append(
                    (staging_addr + block_id * compressed_bytes, compressed_bytes)
                )
        return scatter

    def decompress_block(self, block_id: int) -> list[tuple[int, int]]:
        """Returns the (staging_addr, compressed_bytes) scatter list to
        pass to get_batch for `block_id`. Call `finish_decompress(block_id)`
        once the get completes to launch the decode kernels, then
        `synchronize()` before the raw KV cache is read."""
        return [
            (staging_addr + block_id * compressed_bytes, compressed_bytes)
            for _, _, compressed_bytes, _, _, staging_addr in self._segments
        ]

    def finish_decompress(self, block_id: int) -> None:
        stream_ptr = self._stream.cuda_stream
        with torch.cuda.stream(self._stream):
            for dtype_name, element_count, compressed_bytes, block_bytes, \
                    raw_addr, staging_addr in self._segments:
                self._native.cuda_decompress(
                    dtype_name,
                    staging_addr + block_id * compressed_bytes,
                    compressed_bytes,
                    element_count,
                    self.group_size,
                    raw_addr + block_id * block_bytes,
                    stream_ptr,
                )

    def synchronize(self) -> None:
        self._stream.synchronize()


class KVTransferThread(threading.Thread):

    def __init__(self, client, group_keys, block_size, tp_rank, namespaces, layout,
                 coord, ready_event, name, request_queue=None,
                 record_operation=None):
        super().__init__(daemon=True, name=name)
        self.client = client
        self.coord = coord
        self._record_operation_cb = record_operation
        self.group_keys = group_keys
        self.block_size = block_size
        self.tp_rank = tp_rank
        self.namespaces = namespaces
        self.layout = layout
        self.ready_event = ready_event
        self.done_task_lock = threading.Lock()
        self.request_queue: queue.Queue = (
            request_queue if request_queue is not None else queue.Queue()
        )
        self.finished_requests: set[str] = set()
        self.kv_event_lock = threading.Lock()
        self.kv_events: list = []

    def add_request(self, req_meta: "ReqMeta") -> None:
        self.request_queue.put(req_meta)

    def _record_operation(self, operation, start_time, num_keys, *,
                          num_bytes=0, status="ok", num_failed_keys=0):
        if self._record_operation_cb is None:
            return
        self._record_operation_cb(
            operation, time.perf_counter() - start_time, num_keys,
            num_bytes=num_bytes, status=status, num_failed_keys=num_failed_keys)

    def get_and_clear_finished_requests(self) -> set[str]:
        with self.done_task_lock:
            finished = self.finished_requests.copy()
            self.finished_requests.clear()
        return finished

    def set_finished_request(self, req_id: str) -> None:
        with self.done_task_lock:
            self.finished_requests.add(req_id)

    def update_kv_event(self, events: list) -> None:
        with self.kv_event_lock:
            self.kv_events.extend(events)

    def get_kv_events(self) -> list:
        with self.kv_event_lock:
            events = self.kv_events.copy()
            self.kv_events.clear()
        return events

    def run(self) -> None:
        self.ready_event.set()
        while True:
            request_data = None
            try:
                request_data = self.request_queue.get()
                if request_data is None:
                    logger.warning("received a None request")
                    self.request_queue.task_done()
                    continue
                self._handle_request(request_data)
            except Exception:
                req_id = getattr(request_data, "req_id", "<unknown>")
                logger.exception("error in %s (req=%s)", self.name, req_id)

    def _handle_request(self, req_meta: "ReqMeta"):
        pass


class KVCacheSendingThread(KVTransferThread):

    def __init__(self, client, group_keys, block_size, tp_rank, namespaces, layout,
                 coord, ready_event, replication_factors,
                 enable_kv_event: bool = False, record_operation=None,
                 gpu_compressor: "GpuBlockCompressor | None" = None):
        super().__init__(client, group_keys, block_size, tp_rank, namespaces, layout,
                         coord, ready_event, name="KVCacheSendingThread",
                         record_operation=record_operation)
        self.replication_factors = replication_factors
        self.gpu_compressor = gpu_compressor
        self.stored_requests: dict[str, int] = {}
        self.enable_kv_event = enable_kv_event
        self._store_pressure_active = False
        self._skip_store_requests: set[str] = set()
        self._saved_offset: dict[str, int] = {}

    def add_stored_request(self, req_id: str) -> None:
        with self.done_task_lock:
            self.stored_requests[req_id] = self.stored_requests.get(req_id, 0) + 1

    def dec_stored_request(self, req_id: str) -> None:
        with self.done_task_lock:
            if req_id in self.stored_requests:
                self.stored_requests[req_id] -= 1

    def delete_finished_stored_request(self, req_id: str) -> None:
        with self.done_task_lock:
            self.stored_requests.pop(req_id, None)
            self._skip_store_requests.discard(req_id)
            self._saved_offset.pop(req_id, None)

    def _should_skip_request(self, req_id: str) -> bool:
        with self.done_task_lock:
            return self._store_pressure_active and req_id in self._skip_store_requests

    def _mark_request_skipped_for_pressure(self, req_id: str) -> bool:
        with self.done_task_lock:
            already_skipped = req_id in self._skip_store_requests
            self._store_pressure_active = True
            self._skip_store_requests.add(req_id)
        return already_skipped

    def _clear_store_pressure(self) -> bool:
        with self.done_task_lock:
            if not self._store_pressure_active and not self._skip_store_requests:
                return False
            self._store_pressure_active = False
            self._skip_store_requests.clear()
        return True

    def _record_saved(self, req_id: str, token_len: int) -> None:
        with self.done_task_lock:
            if req_id in self.stored_requests:
                self._saved_offset[req_id] = token_len

    def _handle_request(self, req_meta: "ReqMeta"):
        lcm = self.coord.lcm_block_size
        token_len = req_meta.token_len_chunk // lcm * lcm
        req_id = req_meta.req_id

        with self.done_task_lock:
            live = req_id in self.stored_requests
        if not live:
            self.request_queue.task_done()
            return

        try:
            if token_len == 0:
                return
            if self._should_skip_request(req_id):
                logger.debug(
                    "skipping store for request %s while the store is full",
                    req_id,
                )
                return
            save_start = self._saved_offset.get(req_id, 0)
            if save_start >= token_len:
                return
            store_masks = self.coord.store_mask(
                token_len, save_start, num_prompt_tokens=req_meta.num_prompt_tokens
            )
            entries: list[tuple] = []
            keys: list[bytes] = []
            for group in self.group_keys:
                put_step = self.replication_factors[group.g_idx]
                put_step_rank = (self.tp_rank + group.g_idx) % put_step
                for start, end, block_hash in group.process_tokens(
                    token_len,
                    req_meta.block_hashes,
                    mask_num=save_start,
                    chunk_mask=store_masks[group.g_idx],
                    put_step=put_step,
                    put_step_rank=put_step_rank,
                ):
                    entries.append((group, start // group.block_size, block_hash))
                    keys.append(
                        group.key_for(block_hash, self.namespaces[group.g_idx])
                    )
            if not keys:
                self._record_saved(req_id, token_len)
                return
            exists_start = time.perf_counter()
            exists = self.client.batch_is_exist(keys)
            self._record_operation("save_exists", exists_start, len(keys))
            missing = [i for i, e in enumerate(exists) if e != 1]
            if not missing:
                self._record_saved(req_id, token_len)
                return
            entries = [entries[i] for i in missing]
            keys = [keys[i] for i in missing]

            addrs: list[list[int]] = []
            sizes: list[list[int]] = []
            stored_events: list[BlockStored] = []
            prev_hash_per_group: dict[int, object] = {}
            compressing = self.gpu_compressor is not None
            if compressing:
                # GPU-side wait (non-blocking on the host): the compress
                # kernels below must not read the KV cache blocks until the
                # compute stream has finished writing them.
                self.gpu_compressor.wait_for(req_meta.current_event)
            for group, chunk_idx, block_hash in entries:
                block_id = req_meta.block_ids[group.g_idx][chunk_idx]
                scatter = (
                    self.gpu_compressor.compress_block(block_id)
                    if compressing
                    else self.layout.addrs_for(block_id)
                )
                addrs.append([addr for addr, _ in scatter])
                sizes.append([size for _, size in scatter])
                if self.enable_kv_event:
                    start = chunk_idx * group.block_size
                    event_hash = maybe_convert_block_hash(block_hash)
                    stored_events.append(BlockStored(
                        block_hashes=[event_hash],
                        parent_block_hash=prev_hash_per_group.get(group.g_idx),
                        token_ids=req_meta.token_ids[start : start + group.block_size]
                        if req_meta.token_ids is not None else None,
                        block_size=group.block_size,
                        lora_id=None,
                        medium="external",
                        lora_name=None,
                        group_idx=group.g_idx,
                    ))
                    prev_hash_per_group[group.g_idx] = event_hash

            if compressing:
                # Blocks until the compress kernels finish, so put_batch
                # below reads finished data out of the staging buffers.
                self.gpu_compressor.synchronize()
            elif req_meta.current_event is not None:
                req_meta.current_event.synchronize()

            batch_bytes = sum(sum(seg) for seg in sizes)
            put_start = time.perf_counter()
            try:
                res = self.client.put_batch(keys, addrs, sizes)
            except Exception as err:
                self._record_operation("save_put", put_start, len(keys),
                                       num_bytes=batch_bytes, status="error",
                                       num_failed_keys=len(keys))
                logger.error("put_batch failed (req=%s): %s", req_id, err)
                return
            failed = [i for i, value in enumerate(res) if value < 0]
            self._record_operation(
                "save_put", put_start, len(keys), num_bytes=batch_bytes,
                status="partial_failure" if failed else "ok",
                num_failed_keys=len(failed))
            if failed:
                logger.warning(
                    "put_batch: %d/%d keys failed for request %s",
                    len(failed), len(keys), req_id,
                )
                if not self._mark_request_skipped_for_pressure(req_id):
                    logger.warning(
                        "store full; pausing store batches for request %s", req_id
                    )
            else:
                self._record_saved(req_id, token_len)
                if self._clear_store_pressure():
                    logger.info("store pressure cleared after a full batch")

            if self.enable_kv_event and stored_events:
                self.update_kv_event(stored_events)
        finally:
            self.dec_stored_request(req_id)
            self.request_queue.task_done()


class KVCacheRecvingThread(KVTransferThread):

    def __init__(self, client, group_keys, block_size, tp_rank, namespaces, layout,
                 coord, ready_event, request_queue=None, record_operation=None,
                 gpu_compressor: "GpuBlockCompressor | None" = None):
        super().__init__(client, group_keys, block_size, tp_rank, namespaces, layout,
                         coord, ready_event, name="KVCacheRecvingThread",
                         request_queue=request_queue,
                         record_operation=record_operation)
        self.gpu_compressor = gpu_compressor
        self._invalid_block_ids_lock = threading.Lock()
        self._invalid_block_ids: set[int] = set()

    def _add_load_error_block_ids(self, block_ids) -> None:
        with self._invalid_block_ids_lock:
            self._invalid_block_ids.update(block_ids)

    def get_and_clear_block_ids_with_load_errors(self) -> set[int]:
        with self._invalid_block_ids_lock:
            invalid = self._invalid_block_ids.copy()
            self._invalid_block_ids.clear()
        return invalid

    def _handle_request(self, req_meta: "ReqMeta"):
        load = req_meta.load
        assert load is not None
        req_id = req_meta.req_id
        token_len = load.external_tokens
        lcm = self.coord.lcm_block_size
        loaded_start = load.local_tokens // lcm * lcm
        load_masks = self.coord.load_mask(req_meta.block_hashes, token_len)
        entries: list[tuple] = []
        for group in self.group_keys:
            mask = load_masks[group.g_idx]
            for start, end, block_hash in group.process_tokens(
                token_len, req_meta.block_hashes, mask_num=loaded_start,
            ):
                chunk_idx = start // group.block_size
                if chunk_idx >= len(mask) or not mask[chunk_idx]:
                    continue
                entries.append((req_meta.block_ids[group.g_idx][chunk_idx],
                                group.key_for(
                                    block_hash, self.namespaces[group.g_idx]
                                )))
        if not entries:
            self.set_finished_request(req_id)
            self.request_queue.task_done()
            return
        rotation = self.tp_rank % len(entries)
        entries = entries[rotation:] + entries[:rotation]
        key_list = [key for _, key in entries]
        block_id_list = [block_id for block_id, _ in entries]
        compressing = self.gpu_compressor is not None
        addr_list: list[list[int]] = []
        size_list: list[list[int]] = []
        for block_id, _ in entries:
            scatter = (
                self.gpu_compressor.decompress_block(block_id)
                if compressing
                else self.layout.addrs_for(block_id)
            )
            addr_list.append([addr for addr, _ in scatter])
            size_list.append([size for _, size in scatter])

        load_batches = [(key_list, addr_list, size_list, block_id_list)]
        current_batch_block_ids = block_id_list
        try:
            for batch_keys, batch_addrs, batch_sizes, batch_block_ids in load_batches:
                current_batch_block_ids = batch_block_ids
                batch_bytes = sum(sum(seg) for seg in batch_sizes)
                get_start = time.perf_counter()
                res = self.client.get_batch(batch_keys, batch_addrs, batch_sizes)
                failed = [
                    (key, value, block_id)
                    for key, value, block_id in zip(
                        batch_keys, res, batch_block_ids, strict=True
                    )
                    if value < 0
                ]
                self._record_operation(
                    "load_get", get_start, len(batch_keys), num_bytes=batch_bytes,
                    status="partial_failure" if failed else "ok",
                    num_failed_keys=len(failed))
                if compressing:
                    failed_ids = {block_id for _, _, block_id in failed}
                    for block_id in batch_block_ids:
                        if block_id not in failed_ids:
                            self.gpu_compressor.finish_decompress(block_id)
                if failed:
                    self._add_load_error_block_ids(
                        [block_id for _, _, block_id in failed]
                    )
                    logger.warning(
                        "load: %d/%d keys failed for request %s (first=%s)",
                        len(failed), len(batch_keys), req_id,
                        [(k, v) for k, v, _ in failed[:3]],
                    )
                    break
        except Exception as err:
            self._add_load_error_block_ids(current_batch_block_ids)
            self._record_operation("load_get", get_start, len(current_batch_block_ids),
                                   status="error",
                                   num_failed_keys=len(current_batch_block_ids))
            logger.error("get_batch failed (req=%s): %s", req_id, err)
        if compressing:
            # Blocks until the decompress kernels finish, so the raw KV
            # cache is fully populated before this request is reported done.
            self.gpu_compressor.synchronize()
        self.set_finished_request(req_id)
        self.request_queue.task_done()


class OpenLakeWorker:
    @staticmethod
    def _client_id(base_id: int, parallel_config) -> int:
        if (getattr(parallel_config, "distributed_executor_backend", None)
                == "external_launcher"):
            client_id = base_id + 2 * int(parallel_config.rank) + 1
        else:
            model_world_size = (
                parallel_config.pipeline_parallel_size
                * parallel_config.prefill_context_parallel_size
                * parallel_config.tensor_parallel_size
            )
            dp_rank = int(getattr(parallel_config, "data_parallel_index", 0))
            scheduler_id = base_id + dp_rank * (model_world_size + 1)
            model_rank = int(parallel_config.rank) % model_world_size
            client_id = scheduler_id + 1 + model_rank
        if not CLIENT_NODE_ID_BASE <= client_id <= CLIENT_NODE_ID_MAX:
            raise ValueError(
                f"OpenLake worker client_id {client_id} outside "
                f"[{CLIENT_NODE_ID_BASE}, {CLIENT_NODE_ID_MAX}]"
            )
        return client_id

    def __init__(self, vllm_config, kv_cache_config):
        _require_fixed_hash_seed()
        import openlake_client
        from vllm.distributed.parallel_state import (
            get_dcp_group,
            get_pcp_group,
            get_tensor_model_parallel_rank,
            get_tensor_model_parallel_world_size,
        )

        model_config = vllm_config.model_config
        parallel_config = vllm_config.parallel_config

        self.tp_rank = get_tensor_model_parallel_rank()
        self.tp_size = get_tensor_model_parallel_world_size()
        self.pp_size = parallel_config.pipeline_parallel_size
        self.pp_rank = (parallel_config.rank // self.tp_size) % self.pp_size
        self.pcp_size = get_pcp_group().world_size
        self.pcp_rank = (
            get_pcp_group().rank_in_group if self.pcp_size > 1 else 0
        )
        self.dcp_size = get_dcp_group().world_size
        self.dcp_rank = (
            get_dcp_group().rank_in_group if self.dcp_size > 1 else 0
        )
        self.num_kv_head = model_config.get_total_num_kv_heads()

        self.kv_role = vllm_config.kv_transfer_config.kv_role
        extra = vllm_config.kv_transfer_config.kv_connector_extra_config
        nodes = extra.get("openlake_nodes")
        if not nodes:
            raise ValueError("kv_connector_extra_config.openlake_nodes required")
        base_id = int(extra.get("openlake_client_id", 2048))
        self._client = openlake_client.Client(
            device=extra.get("openlake_device", "mlx5_ib0"),
            client_id=self._client_id(base_id, parallel_config),
        )
        self._nodes = nodes
        self._num_blocks = vllm_config.cache_config.num_gpu_blocks
        groups, self.group_keys, self.block_size, hash_bs, use_eagle = (
            _group_key_spaces(vllm_config, kv_cache_config)
        )
        self._kv_cache_groups = groups
        self._group_tp_replication_factors = _group_tp_replication_factors(
            self._kv_cache_groups,
            tp_size=self.tp_size,
            dcp_size=self.dcp_size,
            num_kv_heads=self.num_kv_head,
        )
        self.namespaces = tuple(
            (
                self.tp_rank // self._group_tp_replication_factors[g_idx],
                self.pcp_rank,
                self.dcp_rank,
                self.pp_rank,
            )
            for g_idx in range(len(self._kv_cache_groups))
        )
        self.coord = Coordinator(
            groups, self.group_keys, self.block_size, hash_bs, use_eagle,
            getattr(envs, "VLLM_PREFIX_CACHE_RETENTION_INTERVAL", None),
        )
        self.load_async = extra.get("load_async", True)
        if "openlake_put_step" in extra:
            logger.warning(
                "openlake_put_step is ignored; TP store striping is derived "
                "from each KV cache group's byte replication"
            )
        self.num_recv_threads = max(1, int(extra.get("openlake_recv_threads", 1)))
        self.enable_kv_events = bool(extra.get("openlake_kv_events", False))
        self.gpu_compression_enabled = bool(extra.get("openlake_gpu_compression", False))
        self.gpu_compression_group_size = int(
            extra.get("openlake_gpu_compression_group_size", 128)
        )
        self._gpu_compressor: "GpuBlockCompressor | None" = None
        self.layout = GroupLayout()
        self.kv_send_thread: "KVCacheSendingThread | None" = None
        self.kv_recv_threads: list[KVCacheRecvingThread] = []
        self.recv_request_queue: queue.Queue = queue.Queue()
        self.finished_store_req: set[str] = set()
        from vllm.distributed.kv_transfer.kv_connector.v1.openlake_metrics import (
            OpenLakeConnectorStats,
        )
        self._stats_cls = OpenLakeConnectorStats
        self.kv_connector_stats = OpenLakeConnectorStats()
        self._kv_connector_stats_lock = threading.Lock()

    @staticmethod
    def _sync_max_slot_bytes(local_slot_bytes: int) -> int:
        """Use one fixed OpenLake slab slot size across all model workers."""
        local_slot_bytes = int(local_slot_bytes)
        if local_slot_bytes < 0 or local_slot_bytes > MAX_SLOT_BYTES:
            raise ValueError(
                f"OpenLake local slot size {local_slot_bytes} is outside the "
                f"u32 range [0, {MAX_SLOT_BYTES}]"
            )
        if 0 < local_slot_bytes <= SLOT_HEADER_BYTES:
            raise ValueError(
                f"OpenLake local slot size {local_slot_bytes} must exceed the "
                f"{SLOT_HEADER_BYTES}-byte key header"
            )

        from vllm.distributed.parallel_state import get_world_group

        world = get_world_group()
        if world.world_size == 1:
            return local_slot_bytes

        value = torch.tensor(local_slot_bytes, dtype=torch.int64, device="cpu")
        torch.distributed.all_reduce(
            value,
            op=torch.distributed.ReduceOp.MAX,
            group=world.cpu_group,
        )
        global_slot_bytes = int(value.item())
        if not local_slot_bytes <= global_slot_bytes <= MAX_SLOT_BYTES:
            raise RuntimeError(
                "OpenLake slot-size MAX reduction returned invalid value "
                f"{global_slot_bytes} for local value {local_slot_bytes}"
            )
        return global_slot_bytes

    def register_cross_layers_kv_caches(self, kv_cache) -> None:
        self.register_kv_caches({"__cross_layer__": kv_cache})

    def register_kv_caches(self, kv_caches) -> None:
        seen_ptrs: set[int] = set()
        addrs: list[int] = []
        block_lens: list[int] = []
        segment_caches: list = []
        for value in kv_caches.values():
            cache = value[0] if isinstance(value, list) else value
            storage = cache.untyped_storage()
            base_addr = storage.data_ptr()
            if base_addr in seen_ptrs:
                continue
            seen_ptrs.add(base_addr)
            region_len = storage.nbytes()
            self._client.register_memory(base_addr, region_len)
            element = cache.element_size()
            page_bytes = region_len // self._num_blocks
            outer = [
                d for d in range(cache.ndim)
                if cache.stride(d) * element > page_bytes
            ]
            if not outer:
                addrs.append(base_addr)
                block_lens.append(page_bytes)
                segment_caches.append(cache)
            else:
                seg_stride = cache.stride(outer[0]) * element
                for idx in range(cache.shape[outer[0]]):
                    addrs.append(base_addr + idx * seg_stride)
                    block_lens.append(seg_stride // self._num_blocks)
                    segment_caches.append(cache)
        self.layout.set(addrs, block_lens)

        compressed_block_lens: list[int] | None = None
        if self.gpu_compression_enabled and addrs:
            try:
                compressor = GpuBlockCompressor(self.gpu_compression_group_size)
                compressed_block_lens = [
                    compressor.add_segment(
                        segment_caches[i], addrs[i], block_lens[i],
                        self._num_blocks, self._client.register_memory,
                    )
                    for i in range(len(addrs))
                ]
                self._gpu_compressor = compressor
                logger.info(
                    "openlake: GPU compression enabled (group_size=%d): "
                    "%d B/block -> %d B/block payload",
                    self.gpu_compression_group_size,
                    sum(block_lens), sum(compressed_block_lens),
                )
            except Exception as err:
                logger.warning(
                    "openlake: GPU compression unavailable, falling back to "
                    "uncompressed KV transfer: %s", err,
                )
                self._gpu_compressor = None
                compressed_block_lens = None

        payload_lens = compressed_block_lens or block_lens
        local_slot_bytes = SLOT_HEADER_BYTES + sum(payload_lens) if addrs else 0
        slot_bytes = self._sync_max_slot_bytes(local_slot_bytes)
        if not addrs:
            logger.warning(
                "openlake: no local kv caches to register; synchronized "
                "%d B/slot across model workers",
                slot_bytes,
            )
            return
        for node_id, addr in enumerate(self._nodes):
            self._client.attach(addr, node_id, slot_bytes)
        logger.info(
            "openlake: registered %d segments over %d blocks, "
            "%d B local payload slot, %d B server slot",
            len(addrs), self._num_blocks, local_slot_bytes, slot_bytes,
        )

        if self.kv_role in ("kv_producer", "kv_both"):
            ready_event_sending = threading.Event()
            self.kv_send_thread = KVCacheSendingThread(
                self._client,
                self.group_keys,
                self.block_size,
                self.tp_rank,
                self.namespaces,
                self.layout,
                self.coord,
                ready_event_sending,
                self._group_tp_replication_factors,
                self.enable_kv_events,
                record_operation=self._record_kv_connector_operation,
                gpu_compressor=self._gpu_compressor,
            )
            self.kv_send_thread.start()

        self.kv_recv_threads = []
        ready_events_recving = []
        for i in range(self.num_recv_threads):
            ready_event_recving = threading.Event()
            recv_thread = KVCacheRecvingThread(
                self._client,
                self.group_keys,
                self.block_size,
                self.tp_rank,
                self.namespaces,
                self.layout,
                self.coord,
                ready_event_recving,
                request_queue=self.recv_request_queue,
                record_operation=self._record_kv_connector_operation,
                gpu_compressor=self._gpu_compressor,
            )
            recv_thread.name = f"KVCacheRecvingThread-{i}"
            recv_thread.start()
            self.kv_recv_threads.append(recv_thread)
            ready_events_recving.append(ready_event_recving)
        for ready_event_recving in ready_events_recving:
            ready_event_recving.wait()
        logger.info(
            "started %d KV-load receive thread(s)", self.num_recv_threads
        )

    def get_finished(self, finished_req_ids: set[str], meta):
        for request in meta.requests:
            if request.load is not None and request.load.can_load:
                self.recv_request_queue.put(request)

        assert self.load_async, "load_async must be True: loads are issued here"
        if self.kv_send_thread is not None:
            current_event = None
            for request in meta.requests:
                if request.can_save:
                    current_event = torch.cuda.Event()
                    current_event.record()
                    break
            for request in meta.requests:
                if not request.can_save:
                    continue
                request.current_event = current_event
                self.kv_send_thread.add_stored_request(request.req_id)
                self.kv_send_thread.add_request(request)

        done_sending = (
            self._get_and_clear_finished_sending(finished_req_ids, meta)
            if self.kv_send_thread is not None
            else set()
        )
        done_recving: set[str] = set()
        if self.load_async:
            for recv_thread in self.kv_recv_threads:
                done_recving |= recv_thread.get_and_clear_finished_requests()
        return done_sending, done_recving

    def close(self) -> None:
        client = getattr(self, "_client", None)
        if client is None:
            return
        self._client = None
        try:
            client.close()
        except Exception as e:
            logger.warning("openlake: error closing store client: %s", e)

    def _get_and_clear_finished_sending(self, finished_req_ids, meta):
        assert self.kv_send_thread is not None
        finished_sending: set[str] = set()

        for req_id in meta.preempted_req_ids:
            self.kv_send_thread.delete_finished_stored_request(req_id)

        for req_id in list(self.kv_send_thread.stored_requests):
            if (self.kv_send_thread.stored_requests.get(req_id) == 0
                    and req_id in self.finished_store_req):
                self.finished_store_req.discard(req_id)
                finished_sending.add(req_id)
                self.kv_send_thread.delete_finished_stored_request(req_id)

        for req_id in finished_req_ids:
            remaining = self.kv_send_thread.stored_requests.get(req_id)
            if remaining == 0:
                finished_sending.add(req_id)
                self.kv_send_thread.delete_finished_stored_request(req_id)
            elif remaining is not None:
                self.finished_store_req.add(req_id)

        return finished_sending

    def get_block_ids_with_load_errors(self) -> set[int]:
        block_ids: set[int] = set()
        for recv_thread in self.kv_recv_threads:
            block_ids |= recv_thread.get_and_clear_block_ids_with_load_errors()
        return block_ids

    def _record_kv_connector_operation(self, operation, duration_seconds, num_keys,
                                       *, num_bytes=0, status="ok",
                                       num_failed_keys=0):
        with self._kv_connector_stats_lock:
            self.kv_connector_stats.record_operation(
                operation, duration_seconds, num_keys, num_bytes=num_bytes,
                status=status, num_failed_keys=num_failed_keys)

    def get_kv_connector_stats(self):
        with self._kv_connector_stats_lock:
            if self.kv_connector_stats.is_empty():
                return None
            stats = self.kv_connector_stats
            self.kv_connector_stats = self._stats_cls()
        return stats

    def get_kv_events(self) -> list:
        if self.kv_send_thread is None:
            return []
        return self.kv_send_thread.get_kv_events()


class OpenLakeScheduler:
    @staticmethod
    def _client_id(base_id: int, parallel_config) -> int:
        if (getattr(parallel_config, "distributed_executor_backend", None)
                == "external_launcher"):
            client_id = base_id + 2 * int(parallel_config.rank)
        else:
            model_world_size = (
                parallel_config.pipeline_parallel_size
                * parallel_config.prefill_context_parallel_size
                * parallel_config.tensor_parallel_size
            )
            dp_rank = int(getattr(parallel_config, "data_parallel_index", 0))
            client_id = base_id + dp_rank * (model_world_size + 1)
        if not CLIENT_NODE_ID_BASE <= client_id <= CLIENT_NODE_ID_MAX:
            raise ValueError(
                f"OpenLake scheduler client_id {client_id} outside "
                f"[{CLIENT_NODE_ID_BASE}, {CLIENT_NODE_ID_MAX}]"
            )
        return client_id

    def __init__(self, vllm_config, kv_cache_config):
        _require_fixed_hash_seed()
        import openlake_client

        self.kv_role = vllm_config.kv_transfer_config.kv_role
        extra = vllm_config.kv_transfer_config.kv_connector_extra_config
        nodes = extra.get("openlake_nodes")
        if not nodes:
            raise ValueError("kv_connector_extra_config.openlake_nodes required")
        self._min_external_lookup_tokens = extra.get(
            "openlake_min_external_lookup_tokens", 1000
        )
        parallel = vllm_config.parallel_config
        base_id = int(extra.get("openlake_client_id", 2048))
        self._client = openlake_client.Client(
            device=extra.get("openlake_device", "mlx5_ib0"),
            client_id=self._client_id(base_id, parallel),
        )
        for node_id, addr in enumerate(nodes):
            self._client.attach(addr, node_id)

        groups, self._group_keys, self._sched_bs, self._hash_bs, use_eagle = (
            _group_key_spaces(vllm_config, kv_cache_config)
        )
        self._kv_cache_groups = groups
        self.tp_size = parallel.tensor_parallel_size
        self.pp_size = parallel.pipeline_parallel_size
        self.pcp_size = parallel.prefill_context_parallel_size
        self.dcp_size = parallel.decode_context_parallel_size
        self.num_kv_head = vllm_config.model_config.get_total_num_kv_heads()
        self.load_async = extra.get("load_async", True)
        self._coord = Coordinator(
            groups, self._group_keys, self._sched_bs, self._hash_bs, use_eagle,
            getattr(envs, "VLLM_PREFIX_CACHE_RETENTION_INTERVAL", None),
        )

        self._group_tp_replication_factors = _group_tp_replication_factors(
            self._kv_cache_groups,
            tp_size=self.tp_size,
            dcp_size=self.dcp_size,
            num_kv_heads=self.num_kv_head,
        )
        self._init_lookup_key_prefixes()
        logger.info(
            "openlake: %d nodes, %d groups, rank namespaces=%s",
            len(nodes), len(self._group_keys),
            [len(value) for value in self._namespaces_by_group],
        )
        self._loads: dict[str, PendingLoad] = {}
        self._request_trackers: dict[str, RequestTracker] = {}
        self._unfinished_requests: dict[str, tuple[object, tuple[list[int], ...]]] = {}
        self._unfinished_request_ids: set[str] = set()

    def _init_lookup_key_prefixes(self) -> None:
        def rank_namespaces(factor: int) -> tuple[tuple[int, int, int, int], ...]:
            assert self.dcp_size == 1 or factor == 1
            return tuple(
                (shard_rank, pcp_rank, shard_rank % self.dcp_size, pp_rank)
                for pcp_rank in range(self.pcp_size)
                for shard_rank in range(self.tp_size // factor)
                for pp_rank in range(self.pp_size)
            )

        self._namespaces_by_group = tuple(
            rank_namespaces(self._group_tp_replication_factors[g_idx])
            for g_idx in range(len(self._kv_cache_groups))
        )

    def _contains(self, keys: list[bytes]) -> list[bool]:
        try:
            return [exists == 1 for exists in self._client.batch_is_exist(keys)]
        except Exception as err:
            logger.error("openlake: batch_is_exist failed (%d keys): %s",
                         len(keys), err)
            return [False] * len(keys)

    def _gather_exists(self, block_hashes, token_len: int) -> set[tuple[int, bytes]]:
        candidates: list[tuple[int, bytes, int]] = []
        candidate_keys: list[bytes] = []
        lookup_masks = self._coord.lookup_mask(token_len)
        for group in self._group_keys:
            chunk_hashes = group.chunks(block_hashes)
            max_chunks = min(len(chunk_hashes), cdiv(token_len, group.block_size))
            mask = lookup_masks[group.g_idx]
            mask_limit = max_chunks if mask is None else min(max_chunks, len(mask))
            for chunk_id in range(mask_limit):
                if mask is not None and not mask[chunk_id]:
                    continue
                chunk_hash = bytes(chunk_hashes[chunk_id])
                namespaces = self._namespaces_by_group[group.g_idx]
                candidates.append((group.g_idx, chunk_hash, len(namespaces)))
                candidate_keys.extend(
                    group.key_for(chunk_hash, ns) for ns in namespaces
                )
        if not candidate_keys:
            return set()
        lookup_start = time.perf_counter()
        hits = self._contains(candidate_keys)
        logger.debug(
            "openlake: %d keys in %.0f us", len(candidate_keys),
            (time.perf_counter() - lookup_start) * 1e6,
        )
        exists: set[tuple[int, bytes]] = set()
        offset = 0
        for group_idx, chunk_hash, namespace_count in candidates:
            if all(hits[offset : offset + namespace_count]):
                exists.add((group_idx, chunk_hash))
            offset += namespace_count
        return exists


    def get_num_new_matched_tokens(
        self, request, num_computed_tokens: int
    ) -> tuple[int | None, bool]:
        if request.num_prompt_tokens < self._min_external_lookup_tokens:
            return 0, False
        token_len = request.num_tokens // self._sched_bs * self._sched_bs
        if token_len < self._sched_bs:
            return 0, False
        exists = self._gather_exists(request.block_hashes, token_len)
        _, ext = self._coord.find_longest_cache_hit(
            request.block_hashes, token_len, _ExistsPool(self._hash_bs, exists))
        if ext == request.num_tokens:
            ext = max(0, (request.num_tokens - 1) // self._sched_bs * self._sched_bs)
        need = ext - num_computed_tokens
        if need <= 0:
            return 0, False
        self._loads[request.request_id] = PendingLoad(num_computed_tokens, ext)
        return need, self.load_async

    def update_state_after_alloc(self, request, blocks, num_external_tokens: int):
        local_block_ids: tuple[list[int], ...] = ()
        if num_external_tokens > 0:
            local_block_ids = blocks.get_block_ids()

        self._unfinished_requests[request.request_id] = (request, local_block_ids)
        self._unfinished_request_ids.add(request.request_id)

        load = self._loads.get(request.request_id)
        if load is None:
            return
        if num_external_tokens == 0:
            load.can_load = False
            return
        assert num_external_tokens == load.external_tokens - load.local_tokens, (
            f"granted {num_external_tokens} != "
            f"{load.external_tokens} - {load.local_tokens} for {request.request_id}"
        )
        load.can_load = True

    def build_connector_meta(self, scheduler_output) -> KVConnectorMetadata:
        force_skip_save = self.kv_role == "kv_consumer"

        for finished_req_id in scheduler_output.finished_req_ids:
            self._loads.pop(finished_req_id, None)
            self._request_trackers.pop(finished_req_id, None)
            self._unfinished_requests.pop(finished_req_id, None)
            self._unfinished_request_ids.discard(finished_req_id)

        preempted_ids = scheduler_output.preempted_req_ids or set()
        for req_id in preempted_ids:
            self._loads.pop(req_id, None)
            if tracker := self._request_trackers.get(req_id):
                tracker.reset()
            self._unfinished_requests.pop(req_id, None)

        meta = OpenLakeConnectorMetadata(self._unfinished_request_ids, preempted_ids)

        for request in scheduler_output.scheduled_new_reqs:
            load = self._loads.pop(request.req_id, None)
            num_tokens_to_compute = (
                request.num_computed_tokens
                + scheduler_output.num_scheduled_tokens[request.req_id]
            )
            assert request.req_id in self._unfinished_requests
            request_real = self._unfinished_requests[request.req_id][0]
            if isinstance(request.block_ids, tuple):
                block_ids = tuple(b.copy() for b in request.block_ids)
            else:
                block_ids = (request.block_ids.copy(),)
            prefill_tokens = _prefill_tokens(request)
            tracker = RequestTracker(
                req_id=request.req_id,
                token_len=num_tokens_to_compute,
                allocated_block_ids=block_ids,
                num_saved_tokens=0,
                token_ids=prefill_tokens[:num_tokens_to_compute],
                prefill_end_tokens=len(prefill_tokens),
            )
            self._request_trackers[request.req_id] = tracker
            last_chunk_tokens = len(prefill_tokens) // self._sched_bs * self._sched_bs
            req_meta = ReqMeta.from_tracker(
                tracker,
                self._sched_bs,
                load=load,
                skip_save=force_skip_save,
                block_hashes=request_real.block_hashes,
                is_last_chunk=tracker.token_len >= last_chunk_tokens,
            )
            if req_meta is not None:
                meta.add_request(req_meta)

        cached_reqs = scheduler_output.scheduled_cached_reqs
        if not force_skip_save:
            for i, req_id in enumerate(cached_reqs.req_ids):
                new_block_ids = cached_reqs.new_block_ids[i]
                if not new_block_ids:
                    continue
                if req_id in cached_reqs.resumed_req_ids:
                    if isinstance(new_block_ids, tuple):
                        block_ids = tuple(b.copy() for b in new_block_ids)
                    else:
                        block_ids = (new_block_ids.copy(),)
                    load = self._loads.pop(req_id, None)
                    request_real = self._unfinished_requests[req_id][0]
                    num_tokens_to_compute = (
                        request_real.num_computed_tokens
                        + scheduler_output.num_scheduled_tokens[req_id]
                    )
                    prefill_tokens = list(request_real.all_token_ids)
                    tracker = RequestTracker(
                        req_id=req_id,
                        token_len=num_tokens_to_compute,
                        allocated_block_ids=block_ids,
                        num_saved_tokens=0,
                        token_ids=prefill_tokens[:num_tokens_to_compute].copy(),
                        prefill_end_tokens=len(prefill_tokens),
                    )
                    self._request_trackers[req_id] = tracker
                    last_chunk_tokens = (
                        len(prefill_tokens) // self._sched_bs * self._sched_bs
                    )
                    req_meta = ReqMeta.from_tracker(
                        tracker,
                        self._sched_bs,
                        load=load,
                        skip_save=force_skip_save,
                        block_hashes=request_real.block_hashes,
                        is_last_chunk=tracker.token_len >= last_chunk_tokens,
                    )
                else:
                    tracker = self._request_trackers[req_id]
                    num_new_tokens = scheduler_output.num_scheduled_tokens[req_id]
                    req_tuple = self._unfinished_requests.get(req_id)
                    if not req_tuple:
                        raise ValueError(f"{req_id} not in _unfinished_requests")
                    unfinished_req = req_tuple[0]
                    current = tracker.token_len
                    new_token_ids = unfinished_req.all_token_ids[
                        current : current + num_new_tokens
                    ]
                    tracker.token_len += len(new_token_ids)
                    if cached_reqs.num_computed_tokens[i] >= tracker.prefill_end_tokens:
                        continue
                    tracker.update(new_block_ids)
                    last_chunk_tokens = (
                        tracker.prefill_end_tokens // self._sched_bs * self._sched_bs
                    )
                    req_meta = ReqMeta.from_tracker(
                        tracker,
                        self._sched_bs,
                        load=None,
                        skip_save=force_skip_save,
                        block_hashes=unfinished_req.block_hashes,
                        is_last_chunk=tracker.token_len >= last_chunk_tokens,
                    )
                if req_meta is not None:
                    meta.add_request(req_meta)

        new_ids = [req.req_id for req in scheduler_output.scheduled_new_reqs]
        for req_id, (unfinished_req, block_ids) in self._unfinished_requests.items():
            if req_id not in new_ids and req_id not in cached_reqs.req_ids:
                load = self._loads.pop(req_id, None)
                if not load:
                    continue
                tracker = RequestTracker(
                    req_id=req_id,
                    token_len=load.external_tokens,
                    allocated_block_ids=block_ids,
                    num_saved_tokens=0,
                )
                self._request_trackers[req_id] = tracker
                req_meta = ReqMeta.from_tracker(
                    tracker,
                    self._sched_bs,
                    load=load,
                    skip_save=None,
                    block_hashes=unfinished_req.block_hashes,
                )
                if req_meta is not None:
                    meta.add_request(req_meta)

        return meta

    def reset_store(self) -> bool:
        self._loads.clear()
        try:
            self._client.reset()
            return True
        except Exception as err:
            logger.error("openlake: store reset failed: %s", err)
            return False

    def close(self) -> None:
        client = getattr(self, "_client", None)
        if client is None:
            return
        self._client = None
        try:
            client.close()
        except Exception as e:
            logger.warning("openlake: error closing lookup client: %s", e)

    def request_finished(
        self, request, block_ids: tuple[list[int], ...]
    ) -> "tuple[bool, dict | None]":
        if self.kv_role == "kv_consumer":
            return False, None
        tracker = self._request_trackers.get(request.request_id)
        if tracker is None or tracker.num_saved_tokens <= 0:
            return False, None
        return sum(len(group) for group in block_ids) > 0, None
