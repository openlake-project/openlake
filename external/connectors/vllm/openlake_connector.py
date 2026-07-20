# SPDX-License-Identifier: Apache-2.0

from collections.abc import Iterable
from typing import Any

import torch

from vllm.config import VllmConfig
from vllm.distributed.kv_events import (
    KVCacheEvent,
    KVConnectorKVEvents,
    KVEventAggregator,
)
from vllm.distributed.kv_transfer.kv_connector.v1.base import (
    KVConnectorBase_V1,
    KVConnectorMetadata,
    KVConnectorRole,
    SupportsHMA,
)
from vllm.forward_context import ForwardContext
from vllm.logger import init_logger
from vllm.v1.attention.backend import AttentionMetadata
from vllm.v1.core.kv_cache_manager import KVCacheBlocks
from vllm.v1.core.sched.output import SchedulerOutput
from vllm.v1.kv_cache_interface import KVCacheConfig
from vllm.v1.outputs import KVConnectorOutput
from vllm.v1.request import Request

logger = init_logger(__name__)


class OpenLakeKVEvents(KVConnectorKVEvents):

    def __init__(self, num_workers: int) -> None:
        self._aggregator = KVEventAggregator(num_workers)

    def add_events(self, events: list[KVCacheEvent]) -> None:
        self._aggregator.add_events(events)

    def aggregate(self) -> "OpenLakeKVEvents":
        common = self._aggregator.get_common_events()
        self._aggregator.clear_events()
        self._aggregator.add_events(common)
        self._aggregator.reset_workers()
        return self

    def increment_workers(self, count: int = 1) -> None:
        self._aggregator.increment_workers(count)

    def get_all_events(self) -> list[KVCacheEvent]:
        return self._aggregator.get_all_events()

    def get_number_of_workers(self) -> int:
        return self._aggregator.get_number_of_workers()

    def clear_events(self) -> None:
        self._aggregator.clear_events()
        self._aggregator.reset_workers()


class OpenLakeConnector(KVConnectorBase_V1, SupportsHMA):
    def __init__(
        self,
        vllm_config: VllmConfig,
        role: KVConnectorRole,
        kv_cache_config: KVCacheConfig | None = None,
    ):
        super().__init__(
            vllm_config=vllm_config, role=role, kv_cache_config=kv_cache_config
        )
        assert kv_cache_config is not None
        self._validate(vllm_config, kv_cache_config)
        self._kv_cache_events: OpenLakeKVEvents | None = None
        self._scheduler = None
        self._worker = None
        from vllm.distributed.kv_transfer.kv_connector.v1.openlake_adapter import (
            OpenLakeScheduler,
            OpenLakeWorker,
        )

        if role == KVConnectorRole.SCHEDULER:
            self._scheduler = OpenLakeScheduler(vllm_config, kv_cache_config)
        else:
            self._worker = OpenLakeWorker(vllm_config, kv_cache_config)

    @staticmethod
    def _validate(vllm_config: VllmConfig, kv_cache_config: KVCacheConfig) -> None:
        from vllm.v1.kv_cache_interface import CrossAttentionSpec

        p = vllm_config.parallel_config
        bad: list[str] = []
        for g_idx, g in enumerate(kv_cache_config.kv_cache_groups):
            if isinstance(g.kv_cache_spec, CrossAttentionSpec):
                bad.append(f"group {g_idx}: CrossAttentionSpec")
        pcp = p.prefill_context_parallel_size
        dcp = p.decode_context_parallel_size
        if len(kv_cache_config.kv_cache_groups) > 1 and pcp * dcp > 1:
            bad.append(f"PCP/DCP > 1 (pcp={pcp}, dcp={dcp}) with hybrid attention")
        if (len(kv_cache_config.kv_cache_groups) > 255
                or p.tensor_parallel_size > 255
                or p.pipeline_parallel_size > 255 or pcp > 15 or dcp > 15):
            bad.append("parallel/group sizes exceed the key namespace bytes")
        if bad:
            raise ValueError("OpenLakeConnector does not support: " + "; ".join(bad))


    def get_num_new_matched_tokens(
        self, request: Request, num_computed_tokens: int
    ) -> tuple[int | None, bool]:
        return self._scheduler.get_num_new_matched_tokens(
            request, num_computed_tokens
        )

    def update_state_after_alloc(
        self, request: Request, blocks: KVCacheBlocks, num_external_tokens: int
    ) -> None:
        self._scheduler.update_state_after_alloc(request, blocks, num_external_tokens)

    def build_connector_meta(
        self, scheduler_output: SchedulerOutput
    ) -> KVConnectorMetadata:
        return self._scheduler.build_connector_meta(scheduler_output)

    def request_finished(
        self, request: Request, block_ids: list[int]
    ) -> tuple[bool, dict[str, Any] | None]:
        return self.request_finished_all_groups(request, (block_ids,))

    def request_finished_all_groups(
        self, request: Request, block_ids: tuple[list[int], ...]
    ) -> tuple[bool, dict[str, Any] | None]:
        return self._scheduler.request_finished(request, block_ids)

    def update_connector_output(self, connector_output: KVConnectorOutput) -> None:
        events = connector_output.kv_cache_events
        if not events or not isinstance(events, OpenLakeKVEvents):
            return
        if self._kv_cache_events is None:
            self._kv_cache_events = events
        else:
            self._kv_cache_events.add_events(events.get_all_events())
            self._kv_cache_events.increment_workers(events.get_number_of_workers())

    def take_events(self) -> Iterable[KVCacheEvent]:
        if self._kv_cache_events is not None:
            self._kv_cache_events.aggregate()
            yield from self._kv_cache_events.get_all_events()
            self._kv_cache_events.clear_events()
            self._kv_cache_events = None

    def reset_cache(self) -> bool | None:
        if self._scheduler is not None:
            self._kv_cache_events = None
            return self._scheduler.reset_store()
        return None


    def register_kv_caches(self, kv_caches: dict[str, torch.Tensor]) -> None:
        self._worker.register_kv_caches(kv_caches)

    def start_load_kv(self, forward_context: ForwardContext, **kwargs: Any) -> None:
        pass

    def wait_for_layer_load(self, layer_name: str) -> None:
        return

    def save_kv_layer(
        self,
        layer_name: str,
        kv_layer: torch.Tensor,
        attn_metadata: AttentionMetadata,
        **kwargs: Any,
    ) -> None:
        return

    def wait_for_save(self) -> None:
        pass

    def get_finished(
        self, finished_req_ids: set[str]
    ) -> tuple[set[str] | None, set[str] | None]:
        from vllm.distributed.kv_transfer.kv_connector.v1.openlake_adapter import (
            OpenLakeConnectorMetadata,
        )

        metadata = self._get_connector_metadata()
        assert isinstance(metadata, OpenLakeConnectorMetadata)
        return self._worker.get_finished(finished_req_ids, metadata)

    def get_block_ids_with_load_errors(self) -> set[int]:
        return self._worker.get_block_ids_with_load_errors()

    def get_kv_connector_kv_cache_events(self) -> "OpenLakeKVEvents | None":
        events = self._worker.get_kv_events()
        if not events:
            return None
        kv_events = OpenLakeKVEvents(num_workers=1)
        kv_events.add_events(events)
        return kv_events

    def get_kv_connector_stats(self):
        if self._worker is None:
            return None
        return self._worker.get_kv_connector_stats()

    @classmethod
    def build_kv_connector_stats(cls, data: dict[str, Any] | None = None):
        from vllm.distributed.kv_transfer.kv_connector.v1.openlake_metrics import (
            OpenLakeConnectorStats,
        )

        return (OpenLakeConnectorStats(data=data) if data is not None
                else OpenLakeConnectorStats())

    @classmethod
    def build_prom_metrics(cls, vllm_config, metric_types, labelnames,
                           per_engine_labelvalues):
        from vllm.distributed.kv_transfer.kv_connector.v1.openlake_metrics import (
            OpenLakePromMetrics,
        )

        return OpenLakePromMetrics(
            vllm_config, metric_types, labelnames, per_engine_labelvalues)

    def shutdown(self) -> None:
        for half in (getattr(self, "_worker", None), getattr(self, "_scheduler", None)):
            if half is not None:
                half.close()

    def __del__(self) -> None:
        self.shutdown()
