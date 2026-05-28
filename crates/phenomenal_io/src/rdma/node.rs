use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::io;
use std::rc::Rc;
use std::sync::Arc;

use futures::channel::oneshot;
use serde::{Deserialize, Serialize};

use super::ah_cache::AhCache;
use super::bootstrap::{ClusterRoutingTable, LocalEndpoint};
use super::device::IbDevice;
use super::rdma_buf::RdmaBufPool;
use super::socket::{CqPump, IbSocket};
use super::wire::RdmaResponse;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PeerEndpoint {
    pub node_id: u16,
    pub gid:     [u8; 16],
    pub dct_num: u32,
    pub dc_key:  u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct RdmaQos {
    pub traffic_class: u8,
    pub service_level: u8,
}

#[derive(Clone, Debug)]
pub struct RdmaConfig {
    pub self_node_id:  u16,
    pub runtime_id:    u16,
    pub dev_name:      String,
    pub dc_key:        u64,
    pub qos:           RdmaQos,
    pub bulk_buf_size: usize,
    pub bulk_pool_cap: usize,
}

pub struct RdmaSetup {
    pub dev:       Rc<IbDevice>,
    pub sock:      Rc<IbSocket>,
    pub ah_cache:  Rc<AhCache>,
    pub pump:      CqPump,
    pub bulk_pool: Rc<RdmaBufPool>,
    pub self_gid:  [u8; 16],
    pub self_dct:  u32,
}

pub struct RdmaNode {
    pub self_id:           u16,
    pub runtime_id:        u16,
    pub dev:               Rc<IbDevice>,
    pub sock:              Rc<IbSocket>,
    pub ah_cache:          Rc<AhCache>,
    pub routing:           Arc<ClusterRoutingTable>,
    pub pump:              CqPump,
    pub next_request_id:   Cell<u64>,
    pub pending_responses: RefCell<HashMap<u64, oneshot::Sender<RdmaResponse>>>,
    pub bulk_pool:         Rc<RdmaBufPool>,
}

impl RdmaNode {
    pub fn start_local(cfg: &RdmaConfig) -> io::Result<(RdmaSetup, LocalEndpoint)> {
        let dev       = Rc::new(IbDevice::open(&cfg.dev_name)?);
        let sock      = Rc::new(IbSocket::new(dev.clone(), cfg.dc_key, cfg.qos)?);
        let ah_cache  = Rc::new(AhCache::new(dev.pd.as_ptr(), cfg.qos, dev.gid_index, dev.port_attr.lid));
        let pump      = CqPump::start(sock.clone())?;
        let self_dct  = sock.self_dct_identifier;
        let self_gid  = dev.gid;
        let bulk_pool = RdmaBufPool::new(dev.pd.as_ptr(), cfg.bulk_pool_cap, cfg.bulk_buf_size);
        let setup = RdmaSetup { dev, sock, ah_cache, pump, bulk_pool, self_gid, self_dct };
        let endpoint = LocalEndpoint {
            runtime_id: cfg.runtime_id,
            dct_num:    self_dct,
            gid:        self_gid,
            dc_key:     cfg.dc_key,
        };
        Ok((setup, endpoint))
    }

    pub fn finalize(
        cfg:     &RdmaConfig,
        setup:   RdmaSetup,
        routing: Arc<ClusterRoutingTable>,
    ) -> Self {
        RdmaNode {
            self_id:           cfg.self_node_id,
            runtime_id:        cfg.runtime_id,
            dev:               setup.dev,
            sock:              setup.sock,
            ah_cache:          setup.ah_cache,
            routing,
            pump:              setup.pump,
            next_request_id:   Cell::new(1),
            pending_responses: RefCell::new(HashMap::new()),
            bulk_pool:         setup.bulk_pool,
        }
    }

    pub fn peer(&self, peer_node: u16) -> Option<&PeerEndpoint> {
        self.routing.get(peer_node, self.runtime_id)
    }

    pub fn peer_at(&self, peer_node: u16, peer_runtime: u16) -> Option<&PeerEndpoint> {
        self.routing.get(peer_node, peer_runtime)
    }
}
