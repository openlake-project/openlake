#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""CPU-only regression tests for OpenLake's vLLM adapter.

The connector normally imports torch and vLLM on GPU serving hosts.  These
tests exercise its scheduling and rank/key logic with small import stubs so
they can run in the repository's standard Python environment as well.
"""

from __future__ import annotations

import importlib.util
import logging
import math
import os
import queue
import struct
import subprocess
import sys
import threading
import types
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch


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
    # The connector evaluates Tensor annotations at import time on Python < 3.14.
    torch.Tensor = type("Tensor", (), {})
    torch.cuda = SimpleNamespace(Event=object)
    torch.bfloat16 = "bfloat16"
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

    # Import the public connector as well, so its pre-forward hook is covered.
    base.KVConnectorBase_V1 = type("KVConnectorBase_V1", (), {
        "handle_preemptions": lambda self, metadata: None,
    })
    base.KVConnectorRole = type("KVConnectorRole", (), {})
    base.SupportsHMA = type("SupportsHMA", (), {})
    kv_events.KVCacheEvent = object
    kv_events.KVConnectorKVEvents = object
    kv_events.KVEventAggregator = object
    interface.KVCacheConfig = object
    for name, attribute in (
        ("vllm.config", "VllmConfig"),
        ("vllm.forward_context", "ForwardContext"),
        ("vllm.v1.attention.backend", "AttentionMetadata"),
        ("vllm.v1.core.kv_cache_manager", "KVCacheBlocks"),
        ("vllm.v1.core.sched.output", "SchedulerOutput"),
        ("vllm.v1.outputs", "KVConnectorOutput"),
        ("vllm.v1.request", "Request"),
    ):
        setattr(_module(name), attribute, object)


_install_import_stubs()
MODULE_PATH = Path(__file__).parents[1] / "openlake_adapter.py"
SPEC = importlib.util.spec_from_file_location(
    "openlake_adapter_under_test", MODULE_PATH
)
assert SPEC is not None and SPEC.loader is not None
ADAPTER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = ADAPTER
SPEC.loader.exec_module(ADAPTER)
sys.modules[
    "vllm.distributed.kv_transfer.kv_connector.v1.openlake_adapter"
] = ADAPTER
CONNECTOR_SPEC = importlib.util.spec_from_file_location(
    "openlake_connector_under_test", MODULE_PATH.with_name("openlake_connector.py")
)
assert CONNECTOR_SPEC is not None and CONNECTOR_SPEC.loader is not None
CONNECTOR = importlib.util.module_from_spec(CONNECTOR_SPEC)
CONNECTOR_SPEC.loader.exec_module(CONNECTOR)


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


class OpenLakeHashSeedTests(unittest.TestCase):
    def test_requires_fixed_in_range_decimal_seed(self):
        for seed in (None, "", "random", "abc", "-1", "4294967296", "1.5", "１２", "9" * 5000):
            with self.subTest(seed=seed), patch.dict(os.environ):
                if seed is None:
                    os.environ.pop("PYTHONHASHSEED", None)
                else:
                    os.environ["PYTHONHASHSEED"] = seed
                with self.assertRaisesRegex(RuntimeError, "before starting every Python worker"):
                    ADAPTER._require_fixed_hash_seed()

    def test_accepts_fixed_seed_including_range_boundaries(self):
        for seed in ("0", "1", "42", "00042", "4294967295"):
            with self.subTest(seed=seed), patch.dict(os.environ, PYTHONHASHSEED=seed):
                ADAPTER._require_fixed_hash_seed()


class OpenLakeRankNamespaceTests(unittest.TestCase):
    def test_compression_config_rejects_non_lossless_codecs(self):
        for field, codec, mode in (
            ("codec", "unknown", "lossless"),
            ("mode", "expans", "lossy"),
        ):
            with self.subTest(field=field), self.assertRaisesRegex(
                ValueError, field
            ):
                ADAPTER._expans_enabled({"openlake_compression": {
                    "enabled": True, "codec": codec, "mode": mode,
                }})

    def test_expans_namespace_isolated_without_changing_default(self):
        interface = sys.modules["vllm.v1.kv_cache_interface"]
        spec = interface.FullAttentionSpec()
        spec.block_size = 16
        kv_cache_config = SimpleNamespace(
            kv_cache_groups=[SimpleNamespace(kv_cache_spec=spec)]
        )

        def tag(compression=None):
            extra = {}
            if compression is not None:
                extra["openlake_compression"] = compression
            config = SimpleNamespace(
                model_config=SimpleNamespace(model="org/model"),
                kv_transfer_config=SimpleNamespace(
                    kv_connector_extra_config=extra
                ),
                speculative_config=None,
            )
            return ADAPTER._group_key_spaces(
                config, kv_cache_config
            )[1][0]._model_tag

        default = tag()
        disabled = tag({"enabled": False})
        enabled = tag({
            "enabled": True,
            "codec": "expans",
            "mode": "lossless",
        })

        self.assertEqual(default, disabled)
        self.assertNotEqual(default, enabled)

    def test_compressed_store_stops_at_first_overflow(self):
        sender = ADAPTER.KVCacheSendingThread.__new__(
            ADAPTER.KVCacheSendingThread
        )
        sender.done_task_lock = __import__("threading").Lock()
        sender.stored_requests = {"request": 1}
        sender._save_generations = {"request": 1}
        sender._compression_stopped_requests = set()
        sender._saved_offset = {}
        sender._store_pressure_active = False
        sender._skip_store_requests = set()
        sender.enable_kv_event = False
        sender._record_operation_cb = None
        sender.layout = SimpleNamespace(
            addrs_for=lambda block_id: [(block_id * 1000, 100)]
        )

        class FakeCompression:
            max_batch_blocks = 8
            record_bytes = 768

            def encode(self, _scatters):
                return (
                    (10_000, 11_000, 12_000, 13_000),
                    (True, True, False, True),
                )

        calls = []
        sender.compression = FakeCompression()
        sender.client = SimpleNamespace(
            put_batch=lambda keys, addrs, sizes: (
                calls.append((keys, addrs, sizes)) or [0] * len(keys)
            )
        )
        group = SimpleNamespace(g_idx=0, block_size=16)
        entries = [
            (group, index, bytes([index])) for index in range(4)
        ]
        keys = [bytes([index]) * ADAPTER.SLOT_HEADER_BYTES for index in range(4)]
        req_meta = SimpleNamespace(
            req_id="request", block_ids=([4, 5, 6, 7],), save_generation=1,
        )

        sender._put_compressed(entries, keys, req_meta, 64, "request")

        self.assertEqual(calls, [(
            keys[:2], [[10_000], [11_000]], [[768], [768]],
        )])
        self.assertIn("request", sender._compression_stopped_requests)
        self.assertNotIn("request", sender._saved_offset)

    def test_compressed_load_uses_fixed_records_and_decodes_hits(self):
        receiver = ADAPTER.KVCacheRecvingThread.__new__(
            ADAPTER.KVCacheRecvingThread
        )
        receiver._invalid_block_ids_lock = __import__("threading").Lock()
        receiver._invalid_block_ids = set()
        receiver._record_operation_cb = None
        receiver.layout = SimpleNamespace(
            addrs_for=lambda block_id: [(block_id * 1000, 100)]
        )

        class FakeCompression:
            max_batch_blocks = 8
            record_bytes = 768

            def __init__(self):
                self.decode_calls = []

            def reserve(self, count):
                return tuple(10_000 + i * 768 for i in range(count))

            def decode(self, indexes, destinations):
                self.decode_calls.append((indexes, destinations))

        get_calls = []
        receiver.compression = FakeCompression()
        receiver.client = SimpleNamespace(
            get_batch=lambda keys, addrs, sizes: (
                get_calls.append((keys, addrs, sizes)) or [0, -1, 0]
            )
        )
        entries = [(4, b"a"), (5, b"b"), (6, b"c")]

        receiver._get_compressed(entries, "request")

        self.assertEqual(
            get_calls,
            [(
                [b"a", b"b", b"c"],
                [[10_000], [10_768], [11_536]],
                [[768], [768], [768]],
            )],
        )
        self.assertEqual(receiver._invalid_block_ids, {5})
        self.assertEqual(receiver.compression.decode_calls, [(
            [0, 2], [[(4000, 100)], [(6000, 100)]],
        )])

    def test_cross_layer_cache_uses_the_standard_registration_path(self):
        worker = ADAPTER.OpenLakeWorker.__new__(ADAPTER.OpenLakeWorker)
        captured = []
        worker.register_kv_caches = captured.append
        cache = object()

        worker.register_cross_layers_kv_caches(cache)

        self.assertEqual(captured, [{"__cross_layer__": cache}])

    def test_worker_registration_honors_exact_compression_json(self):
        raw_block_bytes = 999_424
        parallel_state = sys.modules["vllm.distributed.parallel_state"]
        parallel_state.get_world_group = lambda: SimpleNamespace(
            world_size=1, cpu_group="cpu-world"
        )

        codec_calls = []

        class FakeCodec:
            def __init__(self, **kwargs):
                codec_calls.append(kwargs)

        expans_module = _module("openlake_client.openlake_expans")
        expans_module.ExpansCodec = FakeCodec

        storage = SimpleNamespace(
            data_ptr=lambda: 1_000,
            nbytes=lambda: 2 * raw_block_bytes,
        )
        cache = SimpleNamespace(
            dtype=sys.modules["torch"].bfloat16,
            ndim=1,
            shape=(2,),
            untyped_storage=lambda: storage,
            element_size=lambda: 2,
            stride=lambda _dimension: 1,
        )

        def register(compression):
            attaches = []
            worker = ADAPTER.OpenLakeWorker.__new__(ADAPTER.OpenLakeWorker)
            worker.compression_enabled = ADAPTER._expans_enabled({
                "openlake_compression": compression,
            })
            worker.compression = None
            worker.group_keys = [object()]
            worker.layout = ADAPTER.GroupLayout()
            worker._num_blocks = 2
            worker._nodes = ["node"]
            worker.kv_role = "none"
            worker.num_recv_threads = 0
            worker._client = SimpleNamespace(
                register_memory=lambda *_args: None,
                attach=lambda *args: attaches.append(args),
            )

            worker.register_kv_caches({"layer": cache})
            return worker, attaches

        enabled_worker, enabled_attaches = register({
            "enabled": True,
            "codec": "expans",
            "mode": "lossless",
        })
        self.assertEqual(codec_calls[0]["raw_block_bytes"], raw_block_bytes)
        self.assertEqual(codec_calls[0]["record_bytes"], 770_048)
        self.assertEqual(codec_calls[0]["segment_bytes"], (raw_block_bytes,))
        self.assertIsInstance(enabled_worker.compression, FakeCodec)
        self.assertEqual(
            enabled_attaches,
            [("node", 0, ADAPTER.SLOT_HEADER_BYTES + 770_048)],
        )

        disabled_worker, disabled_attaches = register({"enabled": False})
        self.assertEqual(len(codec_calls), 1)
        self.assertIsNone(disabled_worker.compression)
        self.assertEqual(
            disabled_attaches,
            [("node", 0, ADAPTER.SLOT_HEADER_BYTES + raw_block_bytes)],
        )

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

    @staticmethod
    def _model_key(model_config, extra=None):
        interface = sys.modules["vllm.v1.kv_cache_interface"]
        spec = interface.FullAttentionSpec()
        spec.block_size = 16
        kv_cache_config = SimpleNamespace(
            kv_cache_groups=[SimpleNamespace(kv_cache_spec=spec)]
        )

        config = SimpleNamespace(
            model_config=model_config,
            kv_transfer_config=SimpleNamespace(kv_connector_extra_config=extra or {}),
            speculative_config=None,
        )
        group = ADAPTER._group_key_spaces(config, kv_cache_config)[1][0]
        return group.key_for(b"x" * 32, (0, 0, 0, 0))

    def test_model_revision_isolates_keys_without_changing_key_layout(self):
        model = SimpleNamespace(model="org/model", revision="revision-a")
        first = self._model_key(model)
        self.assertEqual(first, self._model_key(model))
        model.revision = "revision-b"
        second = self._model_key(model)
        self.assertNotEqual(first, second)
        self.assertEqual(len(first), 54)
        self.assertEqual(first[:32], second[:32])
        self.assertEqual(first[44:], second[44:])

    def test_resolved_commit_isolates_updates_to_same_revision_name(self):
        model = SimpleNamespace(
            model="org/model", revision="main", hf_config=SimpleNamespace(_commit_hash="commit-a")
        )
        first = self._model_key(model)
        model.revision = "alias-for-same-commit"
        self.assertEqual(first, self._model_key(model))
        model.hf_config._commit_hash = "commit-b"
        self.assertNotEqual(first, self._model_key(model))

    def test_local_deployment_revision_and_cache_prefix_isolate_keys(self):
        model = SimpleNamespace(model="/models/current")
        key = self._model_key
        default = key(model)
        self.assertNotEqual(default, key(model, {"openlake_model_revision": "weights-a"}))
        self.assertNotEqual(
            key(model, {"openlake_model_revision": "weights-a"}),
            key(model, {"openlake_model_revision": "weights-b"}),
        )
        self.assertNotEqual(default, key(model, {"cache_prefix": "tenant-a"}))
        self.assertNotEqual(key(model, {"cache_prefix": "tenant-a"}),
                            key(model, {"cache_prefix": "tenant-b"}))
        for invalid in (None, "", " ", 42):
            with self.subTest(invalid=invalid), self.assertRaisesRegex(ValueError, "openlake_model_revision"):
                key(model, {"openlake_model_revision": invalid})

    def test_namespace_is_versioned_and_fields_are_unambiguous(self):
        model = SimpleNamespace(model="org/model")
        old_tag = __import__("hashlib").blake2b(b"org/model", digest_size=12).digest()
        self.assertNotEqual(self._model_key(model)[32:44], old_tag)
        self.assertNotEqual(
            self._model_key(SimpleNamespace(model="b\0c"), {"cache_prefix": "a"}),
            self._model_key(SimpleNamespace(model="c"), {"cache_prefix": "a\0b"}),
        )

    def test_revision_keys_are_stable_across_python_processes(self):
        code = (
            "import runpy; from types import SimpleNamespace; "
            f"tests = runpy.run_path({str(Path(__file__).resolve())!r}); "
            "print(tests['OpenLakeRankNamespaceTests']._model_key("
            "SimpleNamespace(model='org/model', revision='commit-a')).hex())"
        )
        keys = [subprocess.check_output(
            [sys.executable, "-B", "-c", code],
            env={**os.environ, "PYTHONHASHSEED": seed}, text=True,
        ).strip() for seed in ("1", "2")]
        expected = self._model_key(SimpleNamespace(model="org/model", revision="commit-a")).hex()
        self.assertEqual(keys, [expected, expected])

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


class OpenLakeSavePreemptionTests(unittest.TestCase):
    def setUp(self):
        self.writes = []
        self.memory = {1000: "old-prefix-bytes", 2000: "resumed-prefix-bytes"}
        group = SimpleNamespace(
            g_idx=0, block_size=16,
            process_tokens=lambda token_len, hashes, **kwargs: [
                (i * 16, (i + 1) * 16, block_hash)
                for i, block_hash in enumerate(hashes)
                if kwargs.get("mask_num", 0) < (i + 1) * 16 <= token_len
            ],
            key_for=lambda block_hash, _namespace: block_hash,
        )

        def put(keys, addresses, _sizes):
            self.writes.extend(
                (key, self.memory[scatter[0]])
                for key, scatter in zip(keys, addresses)
            )
            return [0] * len(keys)

        self.client = SimpleNamespace(
            batch_is_exist=Mock(side_effect=lambda keys: [0] * len(keys)),
            put_batch=Mock(side_effect=put),
        )
        self.sender = ADAPTER.KVCacheSendingThread(
            self.client, [group], 16, 0, [(0, 0, 0, 0)],
            SimpleNamespace(addrs_for=lambda block: [(1000 + block * 1000, 16)]),
            SimpleNamespace(lcm_block_size=16, store_mask=lambda *a, **kw: [None]),
            threading.Event(), [1],
        )
        self.worker = ADAPTER.OpenLakeWorker.__new__(ADAPTER.OpenLakeWorker)
        self.worker._shutdown_lock = threading.Lock()
        self.worker._shutdown_started = False
        self.worker._shutdown_complete = threading.Event()
        self.worker._client = SimpleNamespace(close=Mock())
        self.worker.kv_send_thread = self.sender
        self.worker.kv_recv_threads = []
        self.worker.load_async = True
        self.worker.finished_store_req = set()

    def enqueue(self, block=0, *, req_id="request", hashes=None, preempted=()):
        hashes = hashes or [b"prefix"]
        request = ADAPTER.ReqMeta(
            req_id, 16 * len(hashes), ([block] * len(hashes),), hashes,
            can_save=True, num_prompt_tokens=16 * len(hashes),
        )
        meta = ADAPTER.OpenLakeConnectorMetadata({req_id}, set(preempted))
        meta.add_request(request)
        with patch.object(ADAPTER.torch.cuda, "Event", return_value=Mock()):
            self.worker.get_finished(set(), meta)
        return self.sender.request_queue.get_nowait()

    def finish(self, req_id="request"):
        meta = ADAPTER.OpenLakeConnectorMetadata(set(), set())
        return self.worker._get_and_clear_finished_sending({req_id}, meta)

    def test_stale_queued_save_cannot_write_or_decrement_resumed_request(self):
        old = self.enqueue()
        self.sender.delete_finished_stored_request("request")
        self.memory[1000] = "bytes-reused-by-another-request"
        resumed = self.enqueue(1)

        self.sender._handle_request(old)
        self.assertEqual(self.writes, [])
        self.assertEqual(self.sender.stored_requests["request"], 1)
        self.assertNotIn("request", self.sender._saved_offset)
        self.sender._handle_request(resumed)

        self.assertEqual(self.writes, [(b"prefix", "resumed-prefix-bytes")])
        self.assertEqual(self.sender.stored_requests["request"], 0)
        self.assertEqual(self.finish(), {"request"})
        self.assertEqual(self.sender.request_queue.unfinished_tasks, 0)

    def test_multiple_stale_chunks_do_not_change_new_generation_counters(self):
        stale = [self.enqueue() for _ in range(3)]
        self.sender.delete_finished_stored_request("request")
        resumed = [self.enqueue(1), self.enqueue(1, hashes=[b"prefix", b"next"])]
        for request in stale:
            self.sender._handle_request(request)
        self.assertEqual(self.sender.stored_requests["request"], 2)
        self.assertEqual(self.writes, [])

        self.assertEqual(self.finish(), set())
        for request in resumed:
            self.sender._handle_request(request)
        self.assertEqual(self.writes, [
            (b"prefix", "resumed-prefix-bytes"),
            (b"next", "resumed-prefix-bytes"),
        ])
        self.assertEqual(self.finish(), {"request"})
        self.assertEqual(self.sender.request_queue.unfinished_tasks, 0)

    def cancel_while_active(self, request, entered, release, *,
                            should_wait=True, expected_error=None):
        cancelled = threading.Event()
        started_cancel = threading.Event()
        errors = []

        def run_save():
            try:
                self.sender._handle_request(request)
            except Exception as err:
                errors.append(err)

        def cancel():
            started_cancel.set()
            self.worker.handle_preemptions(
                ADAPTER.OpenLakeConnectorMetadata(set(), {"request"})
            )
            cancelled.set()

        transfer = threading.Thread(target=run_save)
        cancellation = threading.Thread(target=cancel)
        transfer.start()
        try:
            self.assertTrue(entered.wait(3))
            cancellation.start()
            self.assertTrue(started_cancel.wait(3))
            if should_wait:
                self.assertFalse(cancelled.wait(0.05))
            else:
                self.assertTrue(cancelled.wait(3))
        finally:
            release.set()
            transfer.join(3)
            if cancellation.ident is not None:
                cancellation.join(3)
        self.assertFalse(transfer.is_alive())
        self.assertFalse(cancellation.is_alive())
        if expected_error is None:
            self.assertEqual(errors, [])
        else:
            self.assertEqual([str(err) for err in errors], [expected_error])
        self.assertTrue(cancelled.is_set())

    def test_preemption_waits_for_active_gpu_read_before_block_reuse(self):
        entered = threading.Event()
        release = threading.Event()
        old = self.enqueue()

        def synchronize():
            entered.set()
            if not release.wait(3):
                raise TimeoutError("test event was not released")

        old.current_event = SimpleNamespace(synchronize=synchronize)
        self.cancel_while_active(old, entered, release)
        self.assertEqual(self.writes, [(b"prefix", "old-prefix-bytes")])
        self.assertNotIn("request", self.sender.stored_requests)
        self.assertNotIn("request", self.sender._saved_offset)
        self.memory[1000] = "reused-after-preemption-returned"
        resumed = self.enqueue(1)
        self.sender._handle_request(resumed)
        self.assertEqual(self.writes[-1], (b"prefix", "resumed-prefix-bytes"))
        self.assertEqual(self.sender.stored_requests["request"], 0)

    def test_active_transfer_failures_release_preemption_waiter(self):
        normal_put = self.client.put_batch.side_effect
        for result in ("ok", "store_full", "put_error", "encode_error", "overflow"):
            with self.subTest(result=result):
                entered = threading.Event()
                release = threading.Event()
                old = self.enqueue()

                def pause():
                    entered.set()
                    if not release.wait(3):
                        raise TimeoutError("test transfer was not released")

                def put(keys, addresses, sizes):
                    pause()
                    if result == "put_error":
                        raise RuntimeError("injected put error")
                    if result == "store_full":
                        return [-1] * len(keys)
                    return normal_put(keys, addresses, sizes)

                def encode(scatters):
                    pause()
                    if result == "encode_error":
                        raise RuntimeError("injected encode error")
                    return ([s[0][0] for s in scatters], [False] * len(scatters))

                if result in ("encode_error", "overflow"):
                    self.sender.compression = SimpleNamespace(
                        max_batch_blocks=1, record_bytes=16, encode=encode,
                    )
                    self.client.put_batch.side_effect = normal_put
                else:
                    self.sender.compression = None
                    self.client.put_batch.side_effect = put
                self.cancel_while_active(
                    old, entered, release,
                    expected_error=("injected encode error"
                                    if result == "encode_error" else None),
                )
                self.assertNotIn("request", self.sender.stored_requests)
                self.assertNotIn("request", self.sender._saved_offset)
                self.assertNotIn("request", self.sender._skip_store_requests)
                self.assertNotIn("request", self.sender._compression_stopped_requests)
                self.sender.compression = None
                self.client.put_batch.side_effect = normal_put
                self.sender._handle_request(self.enqueue(1))
                self.assertEqual(self.sender.stored_requests["request"], 0)
                self.assertEqual(self.writes[-1], (b"prefix", "resumed-prefix-bytes"))
                self.assertEqual(self.finish(), {"request"})
                self.assertEqual(self.sender.request_queue.unfinished_tasks, 0)

    def test_preemption_does_not_wait_for_an_unrelated_active_request(self):
        entered = threading.Event()
        release = threading.Event()
        request = self.enqueue(req_id="other")

        def synchronize():
            entered.set()
            if not release.wait(3):
                raise TimeoutError("test event was not released")

        request.current_event = SimpleNamespace(synchronize=synchronize)
        self.cancel_while_active(request, entered, release, should_wait=False)
        self.assertEqual(self.writes, [(b"prefix", "old-prefix-bytes")])
        self.assertEqual(self.finish("other"), {"other"})

    def test_connector_hook_cancels_before_same_step_resumed_saves_are_queued(self):
        old = self.enqueue()
        self.worker.finished_store_req.add("request")
        connector = CONNECTOR.OpenLakeConnector.__new__(CONNECTOR.OpenLakeConnector)
        connector._worker = self.worker
        connector._scheduler = None
        connector._get_connector_metadata = Mock(
            side_effect=AssertionError("preemption must use the incoming metadata")
        )
        meta = ADAPTER.OpenLakeConnectorMetadata({"request"}, {"request"})
        connector.handle_preemptions(meta)
        self.assertNotIn("request", self.worker.finished_store_req)
        resumed = self.enqueue(1, preempted={"request"})
        self.sender._handle_request(old)
        self.assertEqual(self.sender.stored_requests["request"], 1)
        self.sender._handle_request(resumed)
        self.assertEqual(self.writes, [(b"prefix", "resumed-prefix-bytes")])
        self.assertEqual(self.finish(), {"request"})

    def test_preemption_without_sender_is_a_noop(self):
        self.worker.kv_send_thread = None
        self.worker.handle_preemptions(
            ADAPTER.OpenLakeConnectorMetadata(set(), {"request"})
        )

    def test_stale_compressed_task_never_reads_gpu_memory(self):
        old = self.enqueue()
        self.sender.compression = SimpleNamespace(encode=Mock())
        self.worker.handle_preemptions(
            ADAPTER.OpenLakeConnectorMetadata(set(), {"request"})
        )
        resumed = self.enqueue(1)
        self.sender._handle_request(old)
        self.sender.compression.encode.assert_not_called()
        self.client.batch_is_exist.assert_not_called()
        self.client.put_batch.assert_not_called()
        self.assertEqual(self.sender.stored_requests["request"], 1)
        self.sender.compression = None
        self.sender._handle_request(resumed)
        self.assertEqual(self.finish(), {"request"})


class OpenLakeSchedulerLookupTests(unittest.TestCase):
    def _make_scheduler(self, num_tokens, *, block_size=16, matched_tokens=None,
                        min_lookup_tokens=1000, load_async=True):
        scheduler = ADAPTER.OpenLakeScheduler.__new__(ADAPTER.OpenLakeScheduler)
        scheduler._sched_bs = block_size
        scheduler._hash_bs = block_size
        scheduler._min_external_lookup_tokens = min_lookup_tokens
        scheduler.load_async = load_async
        scheduler._loads = {}
        scheduler._group_keys = [ADAPTER.GroupKeys(
            0, SimpleNamespace(block_size=block_size), block_size,
        )]
        scheduler._namespaces_by_group = (((0, 0, 0, 0),),)
        scheduler._client = SimpleNamespace(
            batch_is_exist=Mock(side_effect=lambda keys: [1] * len(keys)),
        )
        if matched_tokens is None:
            matched_tokens = num_tokens // block_size * block_size
        scheduler._coord = SimpleNamespace(
            lookup_mask=Mock(return_value=(None,)),
            find_longest_cache_hit=Mock(return_value=(None, matched_tokens)),
        )
        request = SimpleNamespace(
            request_id="request",
            num_tokens=num_tokens,
            num_prompt_tokens=num_tokens,
            block_hashes=[
                index.to_bytes(32, "little")
                for index in range(num_tokens // block_size)
            ],
        )
        return scheduler, request

    def test_local_hits_skip_external_lookup(self):
        for block_size in (16, 32, 128):
            for num_tokens, local_tokens in (
                (1024, 1024 - block_size),
                (1024, 1024),
                (1025, 1024),
                (1024 + block_size - 1, 1024),
            ):
                with self.subTest(block_size=block_size, num_tokens=num_tokens,
                                  local_tokens=local_tokens):
                    scheduler, request = self._make_scheduler(
                        num_tokens, block_size=block_size,
                    )

                    self.assertEqual(scheduler.get_num_new_matched_tokens(
                        request, local_tokens,
                    ), (0, False))

                    scheduler._client.batch_is_exist.assert_not_called()
                    scheduler._coord.lookup_mask.assert_not_called()
                    scheduler._coord.find_longest_cache_hit.assert_not_called()
                    self.assertEqual(scheduler._loads, {})

    def test_prompts_up_to_one_block_have_no_reusable_external_tokens(self):
        for block_size in (16, 32, 128):
            for num_tokens in (0, 1, block_size - 1, block_size):
                with self.subTest(block_size=block_size, num_tokens=num_tokens):
                    scheduler, request = self._make_scheduler(
                        num_tokens, block_size=block_size, min_lookup_tokens=0,
                    )

                    self.assertEqual(
                        scheduler.get_num_new_matched_tokens(request, 0),
                        (0, False),
                    )

                    scheduler._client.batch_is_exist.assert_not_called()
                    scheduler._coord.lookup_mask.assert_not_called()
                    scheduler._coord.find_longest_cache_hit.assert_not_called()
                    self.assertEqual(scheduler._loads, {})

    def test_external_lookup_still_loads_tokens_beyond_local_hit(self):
        for num_tokens, local_tokens, expected_tokens in (
            (1024, 0, 1008),
            (1024, 992, 16),
            (1025, 1008, 16),
            (1039, 1008, 16),
        ):
            for load_async in (False, True):
                with self.subTest(num_tokens=num_tokens, local_tokens=local_tokens,
                                  load_async=load_async):
                    scheduler, request = self._make_scheduler(
                        num_tokens, load_async=load_async,
                    )

                    self.assertEqual(scheduler.get_num_new_matched_tokens(
                        request, local_tokens,
                    ), (expected_tokens, load_async))

                    scheduler._client.batch_is_exist.assert_called_once()
                    self.assertEqual(scheduler._loads[request.request_id],
                                     ADAPTER.PendingLoad(
                                         local_tokens, local_tokens + expected_tokens,
                                     ))

    def test_eagle_lookup_keeps_full_bound_before_coordinator_drops_block(self):
        scheduler, request = self._make_scheduler(1024, matched_tokens=1008)

        self.assertEqual(scheduler.get_num_new_matched_tokens(request, 992),
                         (16, True))

        scheduler._client.batch_is_exist.assert_called_once()
        self.assertEqual(
            scheduler._coord.find_longest_cache_hit.call_args.args[1], 1024,
        )
        self.assertEqual(scheduler._loads[request.request_id],
                         ADAPTER.PendingLoad(992, 1008))


class OpenLakeWorkerShutdownTests(unittest.TestCase):
    def _worker(self, *, receivers=1, before_transfer=None):
        calls = []
        state_lock = threading.Lock()
        closed = False

        def transfer(request):
            nonlocal closed
            if before_transfer is not None:
                before_transfer(request)
            with state_lock:
                if closed:
                    raise AssertionError("transfer used the closed client")
                calls.append(request)

        def close_client():
            nonlocal closed
            with state_lock:
                closed = True

        client = SimpleNamespace(
            transfer=transfer,
            close=Mock(side_effect=close_client),
        )

        class TransferThread(ADAPTER.KVTransferThread):
            def __init__(self, name, request_queue=None):
                super().__init__(
                    client, [], 1, 0, [], None, None, threading.Event(), name,
                    request_queue=request_queue,
                )

            def _handle_request(self, request):
                try:
                    self.client.transfer(request)
                finally:
                    self.request_queue.task_done()

        send_thread = TransferThread("test-save")
        recv_queue = queue.Queue()
        recv_threads = [
            TransferThread(f"test-load-{i}", recv_queue)
            for i in range(receivers)
        ]
        worker = ADAPTER.OpenLakeWorker.__new__(ADAPTER.OpenLakeWorker)
        worker._client = client
        worker._shutdown_lock = threading.Lock()
        worker._shutdown_started = False
        worker._shutdown_complete = threading.Event()
        worker.kv_send_thread = send_thread
        worker.kv_recv_threads = recv_threads
        worker.recv_request_queue = recv_queue
        for thread in [send_thread, *recv_threads]:
            thread.start()
            self.assertTrue(thread.ready_event.wait(1))
        return worker, send_thread, recv_threads, client, calls

    def test_idle_and_repeated_shutdown_joins_every_thread(self):
        worker, sender, receivers, client, _ = self._worker(receivers=3)

        worker.close()
        worker.close()

        self.assertFalse(sender.is_alive())
        self.assertTrue(all(not thread.is_alive() for thread in receivers))
        self.assertEqual(sender.request_queue.unfinished_tasks, 0)
        self.assertEqual(worker.recv_request_queue.unfinished_tasks, 0)
        client.close.assert_called_once_with()

    def test_pending_saves_and_loads_finish_before_client_closes(self):
        save_started = threading.Event()
        allow_save = threading.Event()

        def before_transfer(request):
            if request == "save":
                save_started.set()
                if not allow_save.wait(2):
                    raise AssertionError("timed out waiting to finish save")

        worker, sender, receivers, client, calls = self._worker(
            receivers=3, before_transfer=before_transfer,
        )
        sender.add_request("save")
        self.assertTrue(save_started.wait(1))
        for i in range(5):
            worker.recv_request_queue.put(f"load-{i}")

        closing = threading.Thread(target=worker.close, daemon=True)
        closing.start()
        repeated_close = threading.Thread(target=worker.close, daemon=True)
        try:
            for _ in range(1000):
                if worker._shutdown_started:
                    break
                closing.join(0.001)
            self.assertTrue(worker._shutdown_started)
            self.assertEqual(
                worker.get_finished(set(), SimpleNamespace(requests=[object()])),
                (set(), set()),
            )
            repeated_close.start()
            closing.join(0.05)
            self.assertTrue(closing.is_alive())
            self.assertTrue(repeated_close.is_alive())
            client.close.assert_not_called()
        finally:
            allow_save.set()
            closing.join(2)
            if repeated_close.ident is not None:
                repeated_close.join(2)

        self.assertFalse(closing.is_alive())
        self.assertFalse(repeated_close.is_alive())
        self.assertFalse(sender.is_alive())
        self.assertTrue(all(not thread.is_alive() for thread in receivers))
        self.assertCountEqual(calls, ["save", *(f"load-{i}" for i in range(5))])
        self.assertEqual(sender.request_queue.unfinished_tasks, 0)
        self.assertEqual(worker.recv_request_queue.unfinished_tasks, 0)
        client.close.assert_called_once_with()

    def test_handler_failure_still_allows_shutdown(self):
        def before_transfer(request):
            if request == "bad":
                raise ValueError("injected transfer failure")

        worker, sender, _, client, calls = self._worker(
            before_transfer=before_transfer,
        )
        with patch.object(ADAPTER.logger, "exception") as log_error:
            sender.add_request("bad")
            sender.add_request("good")
            worker.close()

        self.assertEqual(calls, ["good"])
        self.assertEqual(sender.request_queue.unfinished_tasks, 0)
        log_error.assert_called_once()
        client.close.assert_called_once_with()


if __name__ == "__main__":
    os.environ.setdefault("PYTHONHASHSEED", "0")
    unittest.main()
