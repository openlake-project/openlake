#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""CPU-only regression tests for OpenLake's vLLM rank namespaces.

The connector normally imports torch and vLLM on GPU serving hosts.  These
tests exercise its pure rank/key logic with small import stubs so they can run
in the repository's standard Python environment as well.
"""

from __future__ import annotations

import importlib.util
import logging
import math
import os
import struct
import sys
import types
import unittest
from pathlib import Path
from types import SimpleNamespace


def _module(name: str) -> types.ModuleType:
    module = types.ModuleType(name)
    sys.modules[name] = module
    if "." in name:
        parent_name, child_name = name.rsplit(".", 1)
        parent = sys.modules.get(parent_name)
        if parent is not None:
            setattr(parent, child_name, module)
    return module


def _install_import_stubs() -> None:
    torch = _module("torch")
    torch.cuda = SimpleNamespace(Event=object)
    torch.int64 = "int64"

    _module("vllm")
    envs = _module("vllm.envs")
    envs.VLLM_PREFIX_CACHE_RETENTION_INTERVAL = None

    _module("vllm.distributed")
    parallel_state = _module("vllm.distributed.parallel_state")
    parallel_state.get_world_group = lambda: SimpleNamespace(
        world_size=1, cpu_group="cpu-world"
    )
    kv_events = _module("vllm.distributed.kv_events")

    class BlockStored:
        def __init__(self, **kwargs):
            self.__dict__.update(kwargs)

    kv_events.BlockStored = BlockStored

    _module("vllm.distributed.kv_transfer")
    _module("vllm.distributed.kv_transfer.kv_connector")
    _module("vllm.distributed.kv_transfer.kv_connector.v1")
    base = _module("vllm.distributed.kv_transfer.kv_connector.v1.base")

    class KVConnectorMetadata:
        pass

    base.KVConnectorMetadata = KVConnectorMetadata

    logger = _module("vllm.logger")
    logger.init_logger = logging.getLogger

    _module("vllm.utils")
    math_utils = _module("vllm.utils.math_utils")
    math_utils.cdiv = lambda a, b: math.ceil(a / b)

    _module("vllm.v1")
    _module("vllm.v1.core")
    kv_cache_utils = _module("vllm.v1.core.kv_cache_utils")

    class BlockHashListWithBlockSize:
        pass

    class KVCacheBlock:
        def __init__(self, block_id):
            self.block_id = block_id

    kv_cache_utils.BlockHashListWithBlockSize = BlockHashListWithBlockSize
    kv_cache_utils.KVCacheBlock = KVCacheBlock
    kv_cache_utils.maybe_convert_block_hash = lambda value: value
    kv_cache_utils.resolve_kv_cache_block_sizes = lambda *_: (16, 16)

    manager_module = _module("vllm.v1.core.single_type_kv_cache_manager")

    class FullAttentionManager:
        @staticmethod
        def reachable_block_mask(**_kwargs):
            return None

        @staticmethod
        def find_longest_cache_hit(**_kwargs):
            return []

    manager_module.FullAttentionManager = FullAttentionManager

    interface = _module("vllm.v1.kv_cache_interface")

    class KVCacheSpec:
        pass

    class FullAttentionSpec(KVCacheSpec):
        pass

    class MLAAttentionSpec(KVCacheSpec):
        pass

    class SlidingWindowMLASpec(KVCacheSpec):
        pass

    class MambaSpec(KVCacheSpec):
        pass

    class UniformTypeKVCacheSpecs(KVCacheSpec):
        def __init__(self, kv_cache_specs=None):
            self.kv_cache_specs = kv_cache_specs or {}

    interface.FullAttentionSpec = FullAttentionSpec
    interface.KVCacheSpec = KVCacheSpec
    interface.MLAAttentionSpec = MLAAttentionSpec
    interface.SlidingWindowMLASpec = SlidingWindowMLASpec
    interface.MambaSpec = MambaSpec
    interface.UniformTypeKVCacheSpecs = UniformTypeKVCacheSpecs

    registry = _module("vllm.v1.kv_cache_spec_registry")

    class KVCacheSpecRegistry:
        @staticmethod
        def get_manager_class(_spec):
            return FullAttentionManager

    registry.KVCacheSpecRegistry = KVCacheSpecRegistry


_install_import_stubs()
MODULE_PATH = Path(__file__).parents[1] / "openlake_adapter.py"
SPEC = importlib.util.spec_from_file_location(
    "openlake_adapter_under_test", MODULE_PATH
)
assert SPEC is not None and SPEC.loader is not None
ADAPTER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = ADAPTER
SPEC.loader.exec_module(ADAPTER)


def _parallel(**overrides):
    values = {
        "rank": 0,
        "tensor_parallel_size": 8,
        "pipeline_parallel_size": 2,
        "prefill_context_parallel_size": 1,
        "decode_context_parallel_size": 1,
        "data_parallel_index": 0,
        "data_parallel_size": 1,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


class OpenLakeRankNamespaceTests(unittest.TestCase):
    def test_cross_layer_cache_uses_the_standard_registration_path(self):
        worker = ADAPTER.OpenLakeWorker.__new__(ADAPTER.OpenLakeWorker)
        captured = []
        worker.register_kv_caches = captured.append
        cache = object()

        worker.register_cross_layers_kv_caches(cache)

        self.assertEqual(captured, [{"__cross_layer__": cache}])

    def test_slot_size_uses_cpu_world_max_for_unequal_pp_stages(self):
        torch = sys.modules["torch"]
        parallel_state = sys.modules["vllm.distributed.parallel_state"]
        calls = []

        class FakeTensor:
            def __init__(self, value):
                self.value = value

            def item(self):
                return self.value

        def all_reduce(value, *, op, group):
            calls.append((value.value, op, group))
            value.value = 4096

        torch.tensor = lambda value, **_kwargs: FakeTensor(value)
        torch.distributed = SimpleNamespace(
            ReduceOp=SimpleNamespace(MAX="max"),
            all_reduce=all_reduce,
        )
        parallel_state.get_world_group = lambda: SimpleNamespace(
            world_size=16, cpu_group="cpu-world"
        )

        self.assertEqual(ADAPTER.OpenLakeWorker._sync_max_slot_bytes(3072), 4096)
        self.assertEqual(calls, [(3072, "max", "cpu-world")])

    def test_slot_size_single_rank_and_range_validation(self):
        parallel_state = sys.modules["vllm.distributed.parallel_state"]
        parallel_state.get_world_group = lambda: SimpleNamespace(
            world_size=1, cpu_group="cpu-world"
        )

        sync_slot_bytes = ADAPTER.OpenLakeWorker._sync_max_slot_bytes
        self.assertEqual(sync_slot_bytes(1024), 1024)
        self.assertEqual(sync_slot_bytes(0), 0)
        with self.assertRaisesRegex(ValueError, "must exceed"):
            sync_slot_bytes(ADAPTER.SLOT_HEADER_BYTES)
        with self.assertRaisesRegex(ValueError, "u32"):
            sync_slot_bytes(1 << 32)

    def test_model_tag_preserves_default_and_isolates_cache_prefix(self):
        interface = sys.modules["vllm.v1.kv_cache_interface"]
        spec = interface.FullAttentionSpec()
        spec.block_size = 16
        kv_cache_config = SimpleNamespace(
            kv_cache_groups=[SimpleNamespace(kv_cache_spec=spec)]
        )

        def model_tag(cache_prefix=""):
            config = SimpleNamespace(
                model_config=SimpleNamespace(model="org/model"),
                kv_transfer_config=SimpleNamespace(
                    kv_connector_extra_config={"cache_prefix": cache_prefix}
                ),
                speculative_config=None,
            )
            return ADAPTER._group_key_spaces(config, kv_cache_config)[1][0]._model_tag

        expected = __import__("hashlib").blake2b(b"org/model", digest_size=12).digest()
        default = model_tag()

        self.assertEqual(default, expected)
        self.assertNotEqual(default, model_tag("tenant-a"))
        self.assertNotEqual(model_tag("tenant-a"), model_tag("tenant-b"))

    def test_replication_factors_match_mooncake(self):
        interface = sys.modules["vllm.v1.kv_cache_interface"]
        full = interface.FullAttentionSpec()
        mla = interface.MLAAttentionSpec()
        sliding_mla = interface.SlidingWindowMLASpec()
        mamba = interface.MambaSpec()
        pure_mla = interface.UniformTypeKVCacheSpecs(
            {"mla": mla, "sliding_mla": sliding_mla}
        )
        mixed_mamba = interface.UniformTypeKVCacheSpecs(
            {"attention": full, "state": mamba}
        )

        groups = [
            SimpleNamespace(kv_cache_spec=full),
            SimpleNamespace(kv_cache_spec=pure_mla),
            SimpleNamespace(kv_cache_spec=mixed_mamba),
        ]

        def factors(dcp_size):
            return ADAPTER._group_tp_replication_factors(
                groups, tp_size=8, dcp_size=dcp_size, num_kv_heads=4)

        self.assertEqual(factors(1), (2, 8, 1))
        self.assertEqual(factors(2), (1, 1, 1))

    def test_tp8_pp2_workers_get_unique_client_ids(self):
        client_ids = {
            ADAPTER.OpenLakeWorker._client_id(2048, _parallel(rank=rank))
            for rank in range(16)
        }

        self.assertEqual(client_ids, set(range(2049, 2065)))
        self.assertNotIn(2048, client_ids)  # Scheduler retains the base ID.

    def test_client_ids_are_unique_across_dp_pcp_pp_tp_and_role(self):
        client_ids = set()
        for dp_rank in range(2):
            base_parallel = _parallel(
                rank=0,
                tensor_parallel_size=2,
                pipeline_parallel_size=2,
                prefill_context_parallel_size=2,
                data_parallel_index=dp_rank,
                data_parallel_size=2,
            )
            client_ids.add(ADAPTER.OpenLakeScheduler._client_id(2048, base_parallel))
            for rank in range(8):
                parallel = _parallel(
                    rank=rank,
                    tensor_parallel_size=2,
                    pipeline_parallel_size=2,
                    prefill_context_parallel_size=2,
                    data_parallel_index=dp_rank,
                    data_parallel_size=2,
                )
                client_ids.add(ADAPTER.OpenLakeWorker._client_id(2048, parallel))

        self.assertEqual(len(client_ids), 18)
        self.assertEqual(client_ids, set(range(2048, 2066)))

    def test_client_ids_normalize_external_launcher_global_rank(self):
        # External launcher creates a complete scheduler+worker engine for
        # every global rank, so every role/rank pair needs a distinct peer ID.
        client_ids = set()
        for dp_rank in range(2):
            first_global_rank = dp_rank * 8
            for model_rank in range(8):
                global_rank = first_global_rank + model_rank
                parallel = _parallel(
                    rank=global_rank,
                    tensor_parallel_size=2,
                    pipeline_parallel_size=2,
                    prefill_context_parallel_size=2,
                    data_parallel_index=dp_rank,
                    data_parallel_size=2,
                    distributed_executor_backend="external_launcher",
                )
                client_ids.add(ADAPTER.OpenLakeScheduler._client_id(2048, parallel))
                client_ids.add(ADAPTER.OpenLakeWorker._client_id(2048, parallel))

        self.assertEqual(len(client_ids), 32)
        self.assertEqual(client_ids, set(range(2048, 2080)))

    def test_client_id_range_is_validated_before_native_client_creation(self):
        with self.assertRaisesRegex(ValueError, "outside"):
            ADAPTER.OpenLakeScheduler._client_id(2047, _parallel())
        with self.assertRaisesRegex(ValueError, "outside"):
            ADAPTER.OpenLakeWorker._client_id(4080, _parallel(rank=15))

    def test_worker_init_builds_mooncake_equivalent_namespace(self):
        interface = sys.modules["vllm.v1.kv_cache_interface"]
        parallel_state = sys.modules["vllm.distributed.parallel_state"]
        parallel_state.get_tensor_model_parallel_rank = lambda: 6
        parallel_state.get_tensor_model_parallel_world_size = lambda: 8
        parallel_state.get_pcp_group = lambda: SimpleNamespace(
            world_size=1, rank_in_group=0
        )
        parallel_state.get_dcp_group = lambda: SimpleNamespace(
            world_size=1, rank_in_group=0
        )

        client_module = _module("openlake_client")
        client_module.Client = lambda **_kwargs: SimpleNamespace()
        metrics = _module(
            "vllm.distributed.kv_transfer.kv_connector.v1.openlake_metrics"
        )
        metrics.OpenLakeConnectorStats = type("OpenLakeConnectorStats", (), {})

        group = SimpleNamespace(kv_cache_spec=interface.FullAttentionSpec())
        config = SimpleNamespace(
            model_config=SimpleNamespace(get_total_num_kv_heads=lambda: 4),
            parallel_config=_parallel(rank=14),
            kv_transfer_config=SimpleNamespace(
                kv_role="kv_both",
                kv_connector_extra_config={"openlake_nodes": ["node"]},
            ),
            cache_config=SimpleNamespace(num_gpu_blocks=1),
        )
        old_group_key_spaces = ADAPTER._group_key_spaces
        old_coordinator = ADAPTER.Coordinator
        old_hash_seed = os.environ.get("PYTHONHASHSEED")
        try:
            os.environ["PYTHONHASHSEED"] = "0"
            ADAPTER._group_key_spaces = lambda *_args: ([group], [], 16, 16, False)
            ADAPTER.Coordinator = lambda *_args: SimpleNamespace()
            worker = ADAPTER.OpenLakeWorker(config, SimpleNamespace())
        finally:
            ADAPTER._group_key_spaces = old_group_key_spaces
            ADAPTER.Coordinator = old_coordinator
            if old_hash_seed is None:
                os.environ.pop("PYTHONHASHSEED", None)
            else:
                os.environ["PYTHONHASHSEED"] = old_hash_seed

        self.assertEqual(worker._group_tp_replication_factors, (2,))
        self.assertEqual(worker.namespaces, ((3, 0, 0, 1),))

    def test_scheduler_namespaces_match_mooncake_dcp_relationship(self):
        scheduler = ADAPTER.OpenLakeScheduler.__new__(ADAPTER.OpenLakeScheduler)
        scheduler.tp_size = 8
        scheduler.pp_size = 2
        scheduler.pcp_size = 2
        scheduler.dcp_size = 2
        scheduler._kv_cache_groups = [object()]
        scheduler._group_tp_replication_factors = (1,)
        scheduler._init_lookup_key_prefixes()
        namespaces = scheduler._namespaces_by_group[0]

        self.assertEqual(len(namespaces), 32)
        self.assertEqual(len(set(namespaces)), 32)
        self.assertTrue(all(dcp == tp % 2 for tp, _pcp, dcp, _pp in namespaces))
        self.assertEqual({pcp for _tp, pcp, _dcp, _pp in namespaces}, {0, 1})
        self.assertEqual({pp for _tp, _pcp, _dcp, pp in namespaces}, {0, 1})
        self.assertEqual({tp for tp, _pcp, _dcp, _pp in namespaces}, set(range(8)))

    def test_scheduler_namespaces_fold_non_dcp_tp_replicas(self):
        scheduler = ADAPTER.OpenLakeScheduler.__new__(ADAPTER.OpenLakeScheduler)
        scheduler.tp_size = 8
        scheduler.pp_size = 2
        scheduler.pcp_size = 2
        scheduler.dcp_size = 1
        scheduler._kv_cache_groups = [object()]
        scheduler._group_tp_replication_factors = (2,)
        scheduler._init_lookup_key_prefixes()
        namespaces = scheduler._namespaces_by_group[0]

        self.assertEqual(len(namespaces), 16)
        self.assertEqual(len(set(namespaces)), 16)
        self.assertEqual({tp for tp, _pcp, _dcp, _pp in namespaces}, set(range(4)))
        self.assertEqual({pcp for _tp, pcp, _dcp, _pp in namespaces}, {0, 1})
        self.assertEqual({dcp for _tp, _pcp, dcp, _pp in namespaces}, {0})
        self.assertEqual({pp for _tp, _pcp, _dcp, pp in namespaces}, {0, 1})

    def test_pp_rank_changes_only_pp_bytes_of_storage_key(self):
        spec = SimpleNamespace(block_size=16)
        key_space = ADAPTER.GroupKeys(7, spec, 16, b"model-tag-12")
        block_hash = bytes(range(32))

        pp0 = key_space.key_for(block_hash, (3, 2, 1, 0))
        pp1 = key_space.key_for(block_hash, (3, 2, 1, 1))

        self.assertEqual(len(pp0), ADAPTER.SLOT_HEADER_BYTES)
        self.assertEqual(pp0[:52], pp1[:52])
        self.assertNotEqual(pp0, pp1)
        self.assertEqual(pp0[52:54], struct.pack("<H", 0))
        self.assertEqual(pp1[52:54], struct.pack("<H", 1))

    def test_scheduler_requires_every_pp_namespace_for_a_hit(self):
        spec = SimpleNamespace(block_size=16)
        key_space = ADAPTER.GroupKeys(0, spec, 16, b"model-tag-12")
        scheduler = ADAPTER.OpenLakeScheduler.__new__(ADAPTER.OpenLakeScheduler)
        scheduler._group_keys = [key_space]
        scheduler._namespaces_by_group = (((0, 0, 0, 0), (0, 0, 0, 1)),)
        scheduler._coord = SimpleNamespace(lookup_mask=lambda _token_len: (None,))
        looked_up = []

        def contains_with_missing_pp1(keys):
            looked_up.extend(keys)
            return [True, False]

        scheduler._contains = contains_with_missing_pp1
        block_hash = b"h" * 32
        self.assertEqual(scheduler._gather_exists([block_hash], 16), set())
        self.assertEqual(len(looked_up), 2)
        self.assertNotEqual(looked_up[0], looked_up[1])

        scheduler._contains = lambda keys: [True] * len(keys)
        self.assertEqual(scheduler._gather_exists([block_hash], 16), {(0, block_hash)})

    def test_scheduler_slices_variable_per_group_namespace_counts(self):
        spec = SimpleNamespace(block_size=16)
        groups = [
            ADAPTER.GroupKeys(0, spec, 16, b"model-tag-12"),
            ADAPTER.GroupKeys(1, spec, 16, b"model-tag-12"),
        ]
        scheduler = ADAPTER.OpenLakeScheduler.__new__(ADAPTER.OpenLakeScheduler)
        scheduler._group_keys = groups
        scheduler._namespaces_by_group = (
            ((0, 0, 0, 0), (0, 0, 0, 1)),
            (
                (0, 0, 0, 0),
                (0, 0, 0, 1),
                (1, 0, 0, 0),
                (1, 0, 0, 1),
            ),
        )
        scheduler._coord = SimpleNamespace(lookup_mask=lambda _token_len: (None, None))
        looked_up = []

        def contains_with_group_one_incomplete(keys):
            looked_up.extend(keys)
            # Group 0 owns the first two keys and is complete. Group 1 owns
            # four keys and is missing one shard.
            return [True, True, True, False, True, True]

        scheduler._contains = contains_with_group_one_incomplete
        block_hash = b"v" * 32
        self.assertEqual(scheduler._gather_exists([block_hash], 16), {(0, block_hash)})
        self.assertEqual(len(looked_up), 6)

        scheduler._contains = lambda keys: [True] * len(keys)
        self.assertEqual(
            scheduler._gather_exists([block_hash], 16),
            {(0, block_hash), (1, block_hash)},
        )


if __name__ == "__main__":
    os.environ.setdefault("PYTHONHASHSEED", "0")
    unittest.main()
