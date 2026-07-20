#![cfg(all(feature = "rdma", target_os = "linux"))]

use std::cell::RefCell;
use std::collections::HashMap;

use openlake_io::rdma::PeerEndpoint;
use openlake_io::rpc::LocalRdmaEndpoint;

pub struct KvBackend {
    peers: RefCell<HashMap<(u16, u16), (PeerEndpoint, u64)>>,
    cap: usize,
}

impl KvBackend {
    pub fn new(cap: usize) -> Self {
        Self {
            peers: RefCell::new(HashMap::new()),
            cap,
        }
    }

    pub fn attach(&self, id: u16, ep: &LocalRdmaEndpoint, epoch: u64) -> Result<(), String> {
        let mut peers = self.peers.borrow_mut();
        let key = (id, ep.runtime_id);
        match peers.get(&key) {
            Some((held, e)) if held.gid != ep.gid && *e >= epoch => {
                Err(format!("client id {id} held by another endpoint"))
            }
            None if peers.len() >= self.cap => Err(format!("at capacity ({} clients)", self.cap)),
            _ => {
                peers.insert(key, (to_peer(id, ep), epoch));
                Ok(())
            }
        }
    }

    pub fn peer_at(&self, node_id: u16, runtime_id: u16) -> Option<PeerEndpoint> {
        self.peers
            .borrow()
            .get(&(node_id, runtime_id))
            .map(|(ep, _)| ep.clone())
    }

    pub fn len(&self) -> usize {
        self.peers.borrow().len()
    }
}

fn to_peer(node_id: u16, ep: &LocalRdmaEndpoint) -> PeerEndpoint {
    PeerEndpoint {
        node_id,
        gid: ep.gid,
        dct_num: ep.dct_num,
        dc_key: ep.dc_key,
        lid: ep.lid,
        kv_slab: ep.kv_slab,
    }
}
