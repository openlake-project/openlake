use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

use openlake_io::kv::{self, HostSlab, KvRequest, KvResponse, KvSlab};

pub struct KvEngine {
    slab: RefCell<Option<Rc<dyn KvSlab>>>,
    capacity_bytes: u64,
    reserve_ttl: Duration,
    #[cfg(all(feature = "rdma", target_os = "linux"))]
    dev: Option<Rc<openlake_io::rdma::IbDevice>>,
    #[cfg(all(feature = "rdma", target_os = "linux"))]
    registry: Option<std::sync::Arc<std::sync::Mutex<openlake_io::rpc::RdmaEndpointsReply>>>,
    #[cfg(all(feature = "rdma", target_os = "linux"))]
    backend: crate::kv_backend::KvBackend,
    #[cfg(all(feature = "rdma", target_os = "linux"))]
    on_attach: RefCell<Option<Box<dyn Fn(u16, u16)>>>,
}

impl KvEngine {
    pub fn new_tcp(capacity_bytes: u64, reserve_ttl: Duration) -> Self {
        Self {
            slab: RefCell::new(None),
            capacity_bytes,
            reserve_ttl,
            #[cfg(all(feature = "rdma", target_os = "linux"))]
            dev: None,
            #[cfg(all(feature = "rdma", target_os = "linux"))]
            registry: None,
            #[cfg(all(feature = "rdma", target_os = "linux"))]
            backend: crate::kv_backend::KvBackend::new(0),
            #[cfg(all(feature = "rdma", target_os = "linux"))]
            on_attach: RefCell::new(None),
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
            reserve_ttl,
            dev: Some(dev),
            registry: Some(registry),
            backend: crate::kv_backend::KvBackend::new(max_clients),
            on_attach: RefCell::new(None),
        }
    }

    pub fn serve_tcp(&self, req: KvRequest) -> KvResponse {
        #[cfg(all(feature = "rdma", target_os = "linux"))]
        let host_backed = self.dev.is_none();
        #[cfg(not(all(feature = "rdma", target_os = "linux")))]
        let host_backed = true;

        if let KvRequest::Attach { slot_bytes } = &req {
            if host_backed && *slot_bytes > 0 && self.slab.borrow().is_none() {
                let slot_count = (self.capacity_bytes / *slot_bytes as u64).max(1) as u32;
                match HostSlab::new(*slot_bytes, slot_count, self.reserve_ttl) {
                    Ok(s) => *self.slab.borrow_mut() = Some(Rc::new(s)),
                    Err(e) => return KvResponse::Err(format!("kv slab create: {e}")),
                }
            }
        }
        match &*self.slab.borrow() {
            Some(slab) => kv::serve_tcp(&**slab, req),
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
            *self.slab.borrow_mut() = Some(Rc::new(slab));
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
        req: openlake_io::rdma::wire::RdmaRequest,
    ) -> openlake_io::rdma::wire::RdmaResponse {
        use openlake_io::rdma::wire::{RdmaRequest::*, RdmaResponse};
        use openlake_io::rpc::{Response, WireError};

        let slab = self.slab.borrow();
        let Some(slab) = slab.as_ref() else {
            return RdmaResponse::Generic(Response::Err(WireError::Other(
                "no kv slab yet: call attach first for client discovery/exchange".into(),
            )));
        };
        match req {
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
            BatchRelease { slot_idxs } => {
                slab.release(&slot_idxs);
                RdmaResponse::BatchReleased
            }
            Reset => {
                slab.reset();
                RdmaResponse::ResetDone
            }
            req => unreachable!("kv engine routed a foreign request: {req:?}"),
        }
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
    fn re_attach_returns_the_existing_slab() {
        let e = KvEngine::new_tcp(64 * 1024, Duration::from_secs(60));
        let (first, _, _) = attach(&e, 4096);
        let (again, sb, sc) = attach(&e, 8192);
        assert_eq!(again, first);
        assert_eq!((sb, sc), (4096, 16));
    }
}
