use std::rc::Rc;

use openlake_io::kv::{self, KvRequest, KvResponse, KvSlab};

pub struct KvEngine {
    slab: Rc<dyn KvSlab>,
    #[cfg(all(feature = "rdma", target_os = "linux"))]
    backend: crate::kv_backend::KvBackend,
    #[cfg(all(feature = "rdma", target_os = "linux"))]
    on_attach: std::cell::RefCell<Option<Box<dyn Fn(u16, u16)>>>,
}

impl KvEngine {
    #[cfg_attr(
        not(all(feature = "rdma", target_os = "linux")),
        allow(unused_variables)
    )]
    pub fn new(slab: Rc<dyn KvSlab>, max_clients: usize) -> Self {
        Self {
            slab,
            #[cfg(all(feature = "rdma", target_os = "linux"))]
            backend: crate::kv_backend::KvBackend::new(max_clients),
            #[cfg(all(feature = "rdma", target_os = "linux"))]
            on_attach: std::cell::RefCell::new(None),
        }
    }

    pub fn serve_tcp(&self, req: KvRequest) -> KvResponse {
        kv::serve_tcp(&*self.slab, req)
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
    ) -> Result<(), String> {
        eps.iter().try_for_each(|ep| {
            self.backend.attach(client, ep, epoch)?;
            if let Some(f) = &*self.on_attach.borrow() {
                f(client, ep.runtime_id);
            }
            Ok(())
        })
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
        match req {
            BatchReserve { count } => RdmaResponse::BatchReserved {
                slots: self.slab.reserve(count),
            },
            BatchCommit { entries } => {
                let e: Vec<(u32, Vec<u8>)> = entries
                    .into_iter()
                    .map(|c| (c.slot_idx, c.key_hash))
                    .collect();
                self.slab.commit(&e);
                RdmaResponse::BatchCommitted
            }
            BatchLookup { key_hashes } => RdmaResponse::BatchLookedUp {
                slots: self.slab.lookup(&key_hashes),
            },
            BatchRelease { slot_idxs } => {
                self.slab.release(&slot_idxs);
                RdmaResponse::BatchReleased
            }
            Reset => {
                self.slab.reset();
                RdmaResponse::ResetDone
            }
            req => unreachable!("kv engine routed a foreign request: {req:?}"),
        }
    }
}
