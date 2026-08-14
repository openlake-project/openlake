use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use openlake_io::kv::{self, HostSlab, KvRequest, KvResponse, KvSlab};
use serde::Serialize;

const BLOCK_HASH_BYTES: usize = 32;
const KEY_HEADER_BYTES: usize = std::mem::size_of::<openlake_io::kv::KeyHash>();

fn logical_block_ids(keys: &[Vec<u8>]) -> Option<Vec<[u8; BLOCK_HASH_BYTES]>> {
    keys.iter()
        .map(|key| key.get(..BLOCK_HASH_BYTES)?.try_into().ok())
        .collect()
}

fn successful_logical_blocks(
    logical_ids: &[[u8; BLOCK_HASH_BYTES]],
    slots: &[Option<u32>],
) -> Option<usize> {
    if logical_ids.len() != slots.len() {
        return None;
    }

    let mut complete_hits = HashMap::<[u8; BLOCK_HASH_BYTES], bool>::new();
    for (logical_id, slot) in logical_ids.iter().zip(slots) {
        complete_hits
            .entry(*logical_id)
            .and_modify(|all_groups_hit| *all_groups_hit &= slot.is_some())
            .or_insert_with(|| slot.is_some());
    }
    Some(complete_hits.values().filter(|hit| **hit).count())
}

fn human_bytes(n: u64) -> String {
    const U: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let (mut v, mut i) = (n as f64, 0);
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", U[i])
    }
}

pub struct KvEngine {
    slab: RefCell<Option<Rc<dyn KvSlab>>>,
    capacity_bytes: u64,
    metrics: Arc<KvEngineMetrics>,
    reserve_ttl: Duration,
    #[cfg(all(feature = "rdma", target_os = "linux"))]
    dev: Option<Rc<openlake_io::rdma::IbDevice>>,
    #[cfg(all(feature = "rdma", target_os = "linux"))]
    registry: Option<std::sync::Arc<std::sync::Mutex<openlake_io::rpc::RdmaEndpointsReply>>>,
    #[cfg(all(feature = "rdma", target_os = "linux"))]
    backend: crate::kv_backend::KvBackend,
    #[cfg(all(feature = "rdma", target_os = "linux"))]
    on_attach: RefCell<Option<Box<dyn Fn(u16, u16)>>>,
    #[cfg(all(feature = "rdma", target_os = "linux"))]
    ucx: RefCell<Option<UcxState>>,
}

#[cfg(all(feature = "rdma", target_os = "linux"))]
struct UcxState {
    worker: openlake_io::ucx::UcxWorker,
    memory: Option<openlake_io::ucx::UcxMemory>,
    peers: HashMap<u16, (u64, openlake_io::ucx::UcxEndpoint)>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct KvEngineStats {
    pub configured_capacity_bytes: u64,
    pub attached: bool,
    pub slot_bytes: Option<u32>,
    pub slot_count: Option<u32>,
    pub used_slots: Option<u32>,
    pub used_bytes: u64,
    pub served_blocks: u64,
}

pub struct KvEngineMetrics {
    capacity_bytes: u64,
    attached: AtomicBool,
    slot_bytes: AtomicU32,
    slot_count: AtomicU32,
    used_slots: AtomicU32,
    served_blocks: AtomicU64,
}

impl KvEngineMetrics {
    fn new(capacity_bytes: u64) -> Self {
        Self {
            capacity_bytes,
            attached: AtomicBool::new(false),
            slot_bytes: AtomicU32::new(0),
            slot_count: AtomicU32::new(0),
            used_slots: AtomicU32::new(0),
            served_blocks: AtomicU64::new(0),
        }
    }

    fn update(&self, slab: &dyn KvSlab) {
        self.slot_bytes.store(slab.slot_bytes(), Ordering::Relaxed);
        self.slot_count.store(slab.slot_count(), Ordering::Relaxed);
        self.used_slots.store(slab.used_slots(), Ordering::Relaxed);
        self.attached.store(true, Ordering::Release);
    }

    pub fn snapshot(&self) -> KvEngineStats {
        if self.attached.load(Ordering::Acquire) {
            let slot_bytes = self.slot_bytes.load(Ordering::Relaxed);
            let used_slots = self.used_slots.load(Ordering::Relaxed);
            KvEngineStats {
                configured_capacity_bytes: self.capacity_bytes,
                attached: true,
                slot_bytes: Some(slot_bytes),
                slot_count: Some(self.slot_count.load(Ordering::Relaxed)),
                used_slots: Some(used_slots),
                used_bytes: u64::from(slot_bytes) * u64::from(used_slots),
                served_blocks: self.served_blocks.load(Ordering::Relaxed),
            }
        } else {
            KvEngineStats {
                configured_capacity_bytes: self.capacity_bytes,
                attached: false,
                slot_bytes: None,
                slot_count: None,
                used_slots: None,
                used_bytes: 0,
                served_blocks: self.served_blocks.load(Ordering::Relaxed),
            }
        }
    }

    fn record_served_blocks(&self, count: usize) {
        let count = count as u64;
        let _ = self
            .served_blocks
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                Some(current.saturating_add(count))
            });
    }
}

impl KvEngine {
    pub fn new_tcp(capacity_bytes: u64, reserve_ttl: Duration) -> Self {
        Self {
            slab: RefCell::new(None),
            capacity_bytes,
            metrics: Arc::new(KvEngineMetrics::new(capacity_bytes)),
            reserve_ttl,
            #[cfg(all(feature = "rdma", target_os = "linux"))]
            dev: None,
            #[cfg(all(feature = "rdma", target_os = "linux"))]
            registry: None,
            #[cfg(all(feature = "rdma", target_os = "linux"))]
            backend: crate::kv_backend::KvBackend::new(0),
            #[cfg(all(feature = "rdma", target_os = "linux"))]
            on_attach: RefCell::new(None),
            #[cfg(all(feature = "rdma", target_os = "linux"))]
            ucx: RefCell::new(None),
        }
    }

    #[cfg(all(feature = "rdma", target_os = "linux"))]
    pub fn new_rdma(
        dev: Rc<openlake_io::rdma::IbDevice>,
        capacity_bytes: u64,
        reserve_ttl: Duration,
        max_clients: usize,
        registry: std::sync::Arc<std::sync::Mutex<openlake_io::rpc::RdmaEndpointsReply>>,
    ) -> Self {
        Self {
            slab: RefCell::new(None),
            capacity_bytes,
            metrics: Arc::new(KvEngineMetrics::new(capacity_bytes)),
            reserve_ttl,
            dev: Some(dev),
            registry: Some(registry),
            backend: crate::kv_backend::KvBackend::new(max_clients),
            on_attach: RefCell::new(None),
            ucx: RefCell::new(None),
        }
    }

    #[cfg(all(feature = "rdma", target_os = "linux"))]
    pub fn new_ucx(
        worker: openlake_io::ucx::UcxWorker,
        capacity_bytes: u64,
        reserve_ttl: Duration,
    ) -> Self {
        Self {
            slab: RefCell::new(None),
            capacity_bytes,
            metrics: Arc::new(KvEngineMetrics::new(capacity_bytes)),
            reserve_ttl,
            dev: None,
            registry: None,
            backend: crate::kv_backend::KvBackend::new(0),
            on_attach: RefCell::new(None),
            ucx: RefCell::new(Some(UcxState {
                worker,
                memory: None,
                peers: HashMap::new(),
            })),
        }
    }

    pub fn serve_tcp(&self, req: KvRequest) -> KvResponse {
        #[cfg(all(feature = "rdma", target_os = "linux"))]
        let host_backed = self.dev.is_none();
        #[cfg(not(all(feature = "rdma", target_os = "linux")))]
        let host_backed = true;

        if let KvRequest::Attach { slot_bytes } = &req {
            if *slot_bytes != 0 && *slot_bytes <= KEY_HEADER_BYTES as u32 {
                return KvResponse::Err(format!(
                    "slot_bytes {slot_bytes} must exceed the {KEY_HEADER_BYTES}-byte key header"
                ));
            }
            if *slot_bytes != 0 {
                let slab = self.slab.borrow();
                if let Some(slab) = slab.as_ref() {
                    if slab.slot_bytes() != *slot_bytes {
                        return KvResponse::Err(format!(
                            "slot size mismatch: slab uses {}, client requested {slot_bytes}",
                            slab.slot_bytes()
                        ));
                    }
                }
            }
            if host_backed && *slot_bytes > 0 && self.slab.borrow().is_none() {
                let slot_count = (self.capacity_bytes / *slot_bytes as u64).max(1) as u32;
                match HostSlab::new(*slot_bytes, slot_count, self.reserve_ttl) {
                    Ok(s) => {
                        tracing::info!(
                            "Handshake for mmap slabs, serving demand of {} per block, {} leased capacity, {} blocks.",
                            human_bytes(*slot_bytes as u64),
                            human_bytes(self.capacity_bytes),
                            slot_count,
                        );
                        *self.slab.borrow_mut() = Some(Rc::new(s));
                    }
                    Err(e) => return KvResponse::Err(format!("kv slab create: {e}")),
                }
            }
        }
        let update_metrics = matches!(
            &req,
            KvRequest::Attach { .. }
                | KvRequest::Reserve { .. }
                | KvRequest::Commit { .. }
                | KvRequest::Release { .. }
                | KvRequest::Reset
        );
        match &*self.slab.borrow() {
            Some(slab) => {
                let logical_read_ids = match &req {
                    KvRequest::Read { keys } => logical_block_ids(keys),
                    _ => None,
                };
                let committed = if let KvRequest::Commit { entries } = &req {
                    entries.len()
                } else {
                    0
                };
                let resp = kv::serve_tcp(&**slab, req);
                if update_metrics {
                    self.metrics.update(&**slab);
                }
                match &resp {
                    KvResponse::Looked { slots } => {
                        let hits = slots.iter().filter(|slot| slot.is_some()).count();
                        if let Some(logical_ids) = &logical_read_ids {
                            let logical_hits =
                                successful_logical_blocks(logical_ids, slots).unwrap_or_default();
                            self.metrics.record_served_blocks(logical_hits);
                            tracing::info!(
                                "kv read: {} physical blocks requested, {} hits, {} logical blocks served",
                                slots.len(),
                                hits,
                                logical_hits,
                            );
                        } else {
                            tracing::info!(
                                "kv lookup: {} blocks queried, {} hits found",
                                slots.len(),
                                hits,
                            );
                        }
                    }
                    KvResponse::Ok if committed > 0 => {
                        tracing::info!("kv store: {} blocks committed", committed)
                    }
                    _ => {}
                }
                resp
            }
            None => match req {
                KvRequest::Attach { .. } => KvResponse::Attached {
                    shm_name: String::new(),
                    slot_bytes: 0,
                    slot_count: 0,
                },
                _ => KvResponse::Err(
                    "no kv slab yet: call attach first for client discovery/exchange".into(),
                ),
            },
        }
    }

    pub fn stats(&self) -> KvEngineStats {
        self.metrics.snapshot()
    }

    pub fn metrics(&self) -> Arc<KvEngineMetrics> {
        self.metrics.clone()
    }

    #[cfg(all(feature = "rdma", target_os = "linux"))]
    pub fn attach_ucx(
        &self,
        client: u16,
        epoch: u64,
        client_worker_address: &[u8],
        slot_bytes: u32,
        dry_run: bool,
    ) -> Result<openlake_io::rpc::UcxEndpointReply, String> {
        if slot_bytes != 0 && slot_bytes <= KEY_HEADER_BYTES as u32 {
            return Err(format!(
                "slot_bytes {slot_bytes} must exceed the {KEY_HEADER_BYTES}-byte key header"
            ));
        }

        let mut ucx = self.ucx.borrow_mut();
        let state = ucx.as_mut().ok_or("engine is not configured for UCX")?;
        if dry_run {
            let endpoint = state.worker.connect(client_worker_address)?;
            return Ok(openlake_io::rpc::UcxEndpointReply {
                protocol_version: openlake_io::rpc::UCX_PROTOCOL_VERSION,
                is_connected: true,
                worker_address: state.worker.address()?,
                slab_base: 0,
                packed_rkey: Vec::new(),
                slot_bytes: 0,
                slot_count: 0,
                capabilities: endpoint.transports()?,
            });
        }
        if state
            .peers
            .get(&client)
            .is_some_and(|(held_epoch, _)| *held_epoch > epoch)
        {
            return Err(format!(
                "client {client} has a newer attached epoch than {epoch}"
            ));
        }
        let endpoint = state.worker.connect(client_worker_address)?;
        if slot_bytes == 0 {
            let reply = openlake_io::rpc::UcxEndpointReply {
                protocol_version: openlake_io::rpc::UCX_PROTOCOL_VERSION,
                is_connected: true,
                worker_address: state.worker.address()?,
                slab_base: 0,
                packed_rkey: Vec::new(),
                slot_bytes: 0,
                slot_count: 0,
                capabilities: Vec::new(),
            };
            state.peers.insert(client, (epoch, endpoint));
            return Ok(reply);
        }

        if self.slab.borrow().is_none() {
            let slot_count = (self.capacity_bytes / u64::from(slot_bytes)).max(1) as u32;
            let slab = HostSlab::new(slot_bytes, slot_count, self.reserve_ttl)
                .map_err(|e| format!("UCX slab create: {e}"))?;
            tracing::info!(
                "Handshake for UCX slab from client {client}, serving demand of {} per block, {} leased capacity, {} blocks.",
                human_bytes(u64::from(slot_bytes)),
                human_bytes(self.capacity_bytes),
                slot_count,
            );
            *self.slab.borrow_mut() = Some(Rc::new(slab));
        }

        let slab = self.slab.borrow();
        let slab = slab.as_ref().expect("UCX slab created above");
        if slab.slot_bytes() != slot_bytes {
            return Err(format!(
                "slot size mismatch: slab uses {}, client requested {slot_bytes}",
                slab.slot_bytes()
            ));
        }
        if state.memory.is_none() {
            let base = slab
                .base_address()
                .ok_or("UCX requires a host-addressable slab")?;
            state.memory = Some(state.worker.register(base, slab.byte_len())?);
            self.metrics.update(&**slab);
        }
        let memory = state.memory.as_ref().expect("UCX memory registered above");
        let reply = openlake_io::rpc::UcxEndpointReply {
            protocol_version: openlake_io::rpc::UCX_PROTOCOL_VERSION,
            is_connected: true,
            worker_address: state.worker.address()?,
            slab_base: slab.base_address().expect("host slab has an address"),
            packed_rkey: memory.packed_rkey()?,
            slot_bytes: slab.slot_bytes(),
            slot_count: slab.slot_count(),
            capabilities: Vec::new(),
        };
        state.peers.insert(client, (epoch, endpoint));
        Ok(reply)
    }

    #[cfg(all(feature = "rdma", target_os = "linux"))]
    pub fn send_ucx_control(
        &self,
        client: u16,
        body: Vec<u8>,
    ) -> Result<openlake_io::ucx::UcxRequest, String> {
        let ucx = self.ucx.borrow();
        let state = ucx.as_ref().ok_or("engine is not configured for UCX")?;
        let (_, endpoint) = state
            .peers
            .get(&client)
            .ok_or_else(|| format!("UCX client {client} is not attached"))?;
        endpoint.send_control(body)
    }

    #[cfg(all(feature = "rdma", target_os = "linux"))]
    pub fn set_on_attach(&self, f: impl Fn(u16, u16) + 'static) {
        *self.on_attach.borrow_mut() = Some(Box::new(f));
    }

    #[cfg(all(feature = "rdma", target_os = "linux"))]
    pub fn attach(
        &self,
        client: u16,
        eps: &[openlake_io::rpc::LocalRdmaEndpoint],
        epoch: u64,
        slot_bytes: u32,
    ) -> Result<(), String> {
        if slot_bytes != 0 && slot_bytes <= KEY_HEADER_BYTES as u32 {
            return Err(format!(
                "slot_bytes {slot_bytes} must exceed the {KEY_HEADER_BYTES}-byte key header"
            ));
        }
        if slot_bytes != 0 {
            let slab = self.slab.borrow();
            if let Some(slab) = slab.as_ref() {
                if slab.slot_bytes() != slot_bytes {
                    return Err(format!(
                        "slot size mismatch: slab uses {}, client requested {slot_bytes}",
                        slab.slot_bytes()
                    ));
                }
            }
        }
        eps.iter().try_for_each(|ep| -> Result<(), String> {
            self.backend.attach(client, ep, epoch)?;
            if let Some(f) = &*self.on_attach.borrow() {
                f(client, ep.runtime_id);
            }
            Ok(())
        })?;
        if slot_bytes > 0 && self.slab.borrow().is_none() {
            let dev = self.dev.clone().expect("rdma engine built with a device");
            let slot_count = (self.capacity_bytes / slot_bytes as u64).max(1) as usize;
            let slab =
                openlake_io::RdmaSlab::new(dev, slot_bytes as usize, slot_count, self.reserve_ttl)
                    .map_err(|e| format!("rdma slab create: {e}"))?;
            let meta = openlake_io::rpc::SlabMeta {
                slab_base: slab.slab_base(),
                rkey: slab.rkey(),
                slot_bytes: slab.slot_bytes(),
            };
            tracing::info!(
                "Handshake for RDMA slabs from client {client}, serving demand of {} per block, {} leased capacity, {} blocks.",
                human_bytes(slot_bytes as u64),
                human_bytes(self.capacity_bytes),
                slot_count,
            );
            *self.slab.borrow_mut() = Some(Rc::new(slab));
            if let Some(slab) = self.slab.borrow().as_ref() {
                self.metrics.update(&**slab);
            }
            let registry = self
                .registry
                .as_ref()
                .expect("rdma engine built with a registry");
            for ep in registry.lock().unwrap().endpoints.iter_mut() {
                ep.kv_slab = Some(meta);
            }
        }
        Ok(())
    }

    #[cfg(all(feature = "rdma", target_os = "linux"))]
    pub fn peer_at(
        &self,
        node_id: u16,
        runtime_id: u16,
    ) -> Option<openlake_io::rdma::PeerEndpoint> {
        self.backend.peer_at(node_id, runtime_id)
    }

    #[cfg(all(feature = "rdma", target_os = "linux"))]
    pub fn handle(
        &self,
        req: openlake_io::kv_wire::RdmaRequest,
    ) -> openlake_io::kv_wire::RdmaResponse {
        use openlake_io::kv_wire::{RdmaRequest::*, RdmaResponse};
        use openlake_io::rpc::{Response, WireError};

        let slab = self.slab.borrow();
        let Some(slab) = slab.as_ref() else {
            return RdmaResponse::Generic(Response::Err(WireError::Other(
                "no kv slab yet: call attach first for client discovery/exchange".into(),
            )));
        };
        let update_metrics = matches!(
            &req,
            BatchReserve { .. } | BatchCommit { .. } | BatchRelease { .. } | Reset
        );
        let response = match req {
            BatchReserve { count } => RdmaResponse::BatchReserved {
                slots: slab.reserve(count),
            },
            BatchCommit { entries } => {
                let e: Vec<(u32, Vec<u8>)> = entries
                    .into_iter()
                    .map(|c| (c.slot_idx, c.key_hash))
                    .collect();
                slab.commit(&e);
                RdmaResponse::BatchCommitted
            }
            BatchLookup { key_hashes } => RdmaResponse::BatchLookedUp {
                slots: slab.lookup(&key_hashes),
            },
            BatchRead { key_hashes } => {
                let logical_ids = logical_block_ids(&key_hashes);
                let slots = slab.lookup(&key_hashes);
                let logical_hits = logical_ids
                    .as_deref()
                    .and_then(|ids| successful_logical_blocks(ids, &slots))
                    .unwrap_or_default();
                self.metrics.record_served_blocks(logical_hits);
                RdmaResponse::BatchLookedUp { slots }
            }
            BatchRelease { slot_idxs } => {
                slab.release(&slot_idxs);
                RdmaResponse::BatchReleased
            }
            Reset => {
                slab.reset();
                RdmaResponse::ResetDone
            }
            req => unreachable!("kv engine routed a foreign request: {req:?}"),
        };
        if update_metrics {
            self.metrics.update(&**slab);
        }
        response
    }
}

impl Drop for KvEngine {
    fn drop(&mut self) {
        #[cfg(all(feature = "rdma", target_os = "linux"))]
        self.ucx.get_mut().take();
        self.slab.get_mut().take();
    }
}

#[cfg(test)]
mod tests {
    use super::KvEngine;
    use openlake_io::kv::{KvRequest, KvResponse};
    use std::time::Duration;

    fn attach(e: &KvEngine, slot_bytes: u32) -> (String, u32, u32) {
        match e.serve_tcp(KvRequest::Attach { slot_bytes }) {
            KvResponse::Attached {
                shm_name,
                slot_bytes,
                slot_count,
            } => (shm_name, slot_bytes, slot_count),
            other => panic!("attach: {other:?}"),
        }
    }

    #[test]
    fn attach_sizes_the_slab_from_the_client_request() {
        let e = KvEngine::new_tcp(64 * 1024, Duration::from_secs(60));

        let (name, sb, sc) = attach(&e, 0);
        assert!(name.is_empty());
        assert_eq!((sb, sc), (0, 0));

        assert!(matches!(
            e.serve_tcp(KvRequest::Lookup {
                keys: vec![vec![1u8; 54]],
            }),
            KvResponse::Err(_)
        ));

        let (name, sb, sc) = attach(&e, 4096);
        assert!(!name.is_empty());
        assert_eq!((sb, sc), (4096, 16));

        let key = vec![7u8; 54];
        let slot = match e.serve_tcp(KvRequest::Reserve { count: 1 }) {
            KvResponse::Reserved { slots } => slots[0],
            other => panic!("reserve: {other:?}"),
        };
        e.serve_tcp(KvRequest::Commit {
            entries: vec![(slot, key.clone())],
        });
        match e.serve_tcp(KvRequest::Lookup { keys: vec![key] }) {
            KvResponse::Looked { slots } => assert_eq!(slots, vec![Some(slot)]),
            other => panic!("lookup: {other:?}"),
        }
    }

    #[test]
    fn re_attach_requires_the_existing_slab_geometry() {
        let e = KvEngine::new_tcp(64 * 1024, Duration::from_secs(60));
        let (first, _, _) = attach(&e, 4096);
        let (again, sb, sc) = attach(&e, 4096);
        assert_eq!(again, first);
        assert_eq!((sb, sc), (4096, 16));
        assert!(matches!(
            e.serve_tcp(KvRequest::Attach { slot_bytes: 8192 }),
            KvResponse::Err(message) if message.contains("slot size mismatch")
        ));
    }

    #[test]
    fn stats_report_attached_slab_occupancy() {
        let e = KvEngine::new_tcp(64 * 1024, Duration::from_secs(60));
        assert_eq!(e.stats().used_bytes, 0);
        let (_, slot_bytes, slot_count) = attach(&e, 1024);

        let before = e.stats();
        assert!(before.attached);
        assert_eq!(before.slot_bytes, Some(slot_bytes));
        assert_eq!(before.slot_count, Some(slot_count));
        assert_eq!(before.used_slots, Some(0));
        assert_eq!(before.used_bytes, 0);

        let slot = match e.serve_tcp(KvRequest::Reserve { count: 1 }) {
            KvResponse::Reserved { slots } => slots[0],
            other => panic!("reserve: {other:?}"),
        };
        assert!(matches!(
            e.serve_tcp(KvRequest::Commit {
                entries: vec![(slot, vec![7; 54])],
            }),
            KvResponse::Ok
        ));
        assert_eq!(e.stats().used_slots, Some(1));
        assert_eq!(e.stats().used_bytes, 1024);
    }

    #[test]
    fn stats_count_complete_logical_reads_not_existence_probes() {
        let e = KvEngine::new_tcp(64 * 1024, Duration::from_secs(60));
        attach(&e, 1024);

        let mut group_zero = vec![3u8; 54];
        let mut group_one = group_zero.clone();
        group_zero[32] = 0;
        group_one[32] = 1;
        let slots = match e.serve_tcp(KvRequest::Reserve { count: 2 }) {
            KvResponse::Reserved { slots } => slots,
            other => panic!("reserve: {other:?}"),
        };
        assert!(matches!(
            e.serve_tcp(KvRequest::Commit {
                entries: vec![
                    (slots[0], group_zero.clone()),
                    (slots[1], group_one.clone()),
                ],
            }),
            KvResponse::Ok
        ));

        assert!(matches!(
            e.serve_tcp(KvRequest::Lookup {
                keys: vec![group_zero.clone(), group_one.clone()],
            }),
            KvResponse::Looked { .. }
        ));
        assert_eq!(e.stats().served_blocks, 0);

        assert!(matches!(
            e.serve_tcp(KvRequest::Read {
                keys: vec![group_zero, group_one],
            }),
            KvResponse::Looked { .. }
        ));
        assert_eq!(e.stats().served_blocks, 1);

        let mut partial_hit = vec![4u8; 54];
        let mut partial_miss = partial_hit.clone();
        partial_hit[32] = 0;
        partial_miss[32] = 1;
        let slot = match e.serve_tcp(KvRequest::Reserve { count: 1 }) {
            KvResponse::Reserved { slots } => slots[0],
            other => panic!("reserve: {other:?}"),
        };
        assert!(matches!(
            e.serve_tcp(KvRequest::Commit {
                entries: vec![(slot, partial_hit.clone())],
            }),
            KvResponse::Ok
        ));
        assert!(matches!(
            e.serve_tcp(KvRequest::Read {
                keys: vec![partial_hit, partial_miss],
            }),
            KvResponse::Looked { .. }
        ));
        assert_eq!(e.stats().served_blocks, 1);
    }
}
