use std::collections::HashMap;

use crate::rdma::node::PeerEndpoint;
use crate::rpc::LocalRdmaEndpoint;

pub type LocalEndpoint = LocalRdmaEndpoint;

#[derive(Debug, Default)]
pub struct ClusterRoutingTable {
    pub self_node_id: u16,
    entries: HashMap<(u16, u16), PeerEndpoint>,
}

impl ClusterRoutingTable {
    pub fn new(self_node_id: u16) -> Self {
        Self { self_node_id, entries: HashMap::new() }
    }

    pub fn insert(&mut self, peer_node: u16, ep: &LocalEndpoint) {
        self.entries.insert((peer_node, ep.runtime_id), PeerEndpoint {
            node_id: peer_node,
            gid:     ep.gid,
            dct_num: ep.dct_num,
            dc_key:  ep.dc_key,
            lid:     ep.lid,
        });
    }

    pub fn get(&self, peer_node: u16, peer_runtime: u16) -> Option<&PeerEndpoint> {
        self.entries.get(&(peer_node, peer_runtime))
    }

    pub fn len(&self) -> usize { self.entries.len() }
    pub fn is_empty(&self) -> bool { self.entries.is_empty() }

    pub fn iter(&self) -> impl Iterator<Item = (&(u16, u16), &PeerEndpoint)> {
        self.entries.iter()
    }
}
