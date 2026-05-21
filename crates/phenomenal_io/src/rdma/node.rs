use std::collections::HashMap;
use std::io;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};

use futures::channel::oneshot;
use serde::{Deserialize, Serialize};

use super::ah_cache::AhCache;
use super::device::IbDevice;
use super::socket::{CqPump, IbSocket};
use crate::rpc::Response;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PeerEndpoint {
    pub node_id: u16,
    pub gid:     [u8; 16],
    pub dct_num: u32,
    pub dc_key:  u64,
}

/// QoS for outbound RDMA traffic. Stamped onto every `ibv_ah_attr` we
/// build (peer AH cache + DCT/DCI RTR transitions). Operator-set,
/// no default: lossless RoCE deployments REQUIRE these to match the
/// switch fabric's PFC/ECN configuration. Values of 0 give best-effort.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct RdmaQos {
    /// 8-bit IP TOS byte. Upper 6 bits = DSCP. Switch fabric maps this
    /// DSCP to the PFC priority queue (priority 3 lossless RoCE is
    /// typically traffic_class = 96, i.e. DSCP 24 << 2).
    pub traffic_class: u8,
    /// Service Level. Mellanox HCAs use this to select the egress TC
    /// queue in SL-based PFC mode. For PFC priority 3 set sl=3.
    pub service_level: u8,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RdmaConfig {
    pub self_node_id: u16,
    pub dev_name:     String,
    pub dc_key:       u64,
    pub qos:          RdmaQos,
    pub peers:        Vec<PeerEndpoint>,
}

pub struct RdmaNode {
    pub self_id:           u16,
    pub dev:               Arc<IbDevice>,
    pub sock:              Arc<IbSocket>,
    pub ah_cache:          Arc<AhCache>,
    pub peers:             HashMap<u16, PeerEndpoint>,
    pub pump:              CqPump,
    pub next_request_id:   AtomicU64,
    pub pending_responses: Mutex<HashMap<u64, oneshot::Sender<Response>>>,
}

impl RdmaNode {
    pub fn start(cfg: RdmaConfig) -> io::Result<Self> {
        let dev      = Arc::new(IbDevice::open(&cfg.dev_name)?);
        let sock     = Arc::new(IbSocket::new(dev.clone(), cfg.dc_key, cfg.qos)?);
        let ah_cache = Arc::new(AhCache::new(dev.pd.as_ptr(), cfg.qos, dev.gid_index, dev.port_attr.lid));
        let pump     = CqPump::start(sock.clone())?;
        let self_dct_identifier = sock.self_dct_identifier;
        let my_gid     = dev.gid;
        let mut peers = HashMap::with_capacity(cfg.peers.len());
        for mut p in cfg.peers {
            // Loopback: a peer entry referencing ourselves gets its
            // gid + dct_num patched with the real values discovered at
            // boot (TOML can't predict the DCT number we get from the HCA).
            if p.node_id == cfg.self_node_id {
                p.gid     = my_gid;
                p.dct_num = self_dct_identifier;
                p.dc_key  = cfg.dc_key;
            }
            peers.insert(p.node_id, p);
        }
        Ok(RdmaNode {
            self_id: cfg.self_node_id, dev, sock, ah_cache, peers, pump,
            next_request_id:   AtomicU64::new(1),
            pending_responses: Mutex::new(HashMap::new()),
        })
    }

    pub fn peer(&self, node_id: u16) -> Option<&PeerEndpoint> {
        self.peers.get(&node_id)
    }
}
