#![cfg(all(feature = "rdma", target_os = "linux"))]

use std::rc::Rc;

use openlake_io::rdma::wire::{RdmaRequest, RdmaResponse};
use openlake_io::rpc::{Response, WireError};
use openlake_io::KvSlab;

pub struct KvEngine {
    slab: Option<Rc<KvSlab>>,
}

impl KvEngine {
    pub fn new(slab: Option<Rc<KvSlab>>) -> Self {
        Self { slab }
    }

    pub fn handle(&self, req: RdmaRequest) -> RdmaResponse {
        use RdmaRequest::*;
        match (req, &self.slab) {
            (BatchReserve { count }, Some(s)) => RdmaResponse::BatchReserved {
                slots: s.reserve(count),
            },
            (BatchCommit { entries }, Some(s)) => {
                s.commit(&entries);
                RdmaResponse::BatchCommitted
            }
            (BatchLookup { key_hashes }, Some(s)) => RdmaResponse::BatchLookedUp {
                slots: s.lookup(&key_hashes),
            },
            (BatchRelease { slot_idxs }, Some(s)) => {
                s.release(&slot_idxs);
                RdmaResponse::BatchReleased
            }
            (
                BatchReserve { .. } | BatchCommit { .. } | BatchLookup { .. } | BatchRelease { .. },
                None,
            ) => RdmaResponse::Generic(Response::Err(WireError::Other("kv_slab disabled".into()))),
            (req, _) => unreachable!("kv engine routed a foreign request: {req:?}"),
        }
    }
}
