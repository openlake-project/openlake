use std::collections::HashMap;
use std::io;
use std::mem;
use std::ptr::NonNull;
use std::sync::Mutex;

use rdma_mummy_sys::{ibv_ah, ibv_ah_attr, ibv_create_ah, ibv_destroy_ah, ibv_pd};

use super::device::PORT_NUM;
use super::node::{PeerEndpoint, RdmaQos};

pub struct AhCache {
    pd:        *mut ibv_pd,
    qos:       RdmaQos,
    gid_index: u8,
    local_lid: u16,
    table:     Mutex<HashMap<u16, NonNull<ibv_ah>>>,
}

unsafe impl Send for AhCache {}
unsafe impl Sync for AhCache {}

impl AhCache {
    pub fn new(pd: *mut ibv_pd, qos: RdmaQos, gid_index: u8, local_lid: u16) -> Self {
        Self { pd, qos, gid_index, local_lid, table: Mutex::new(HashMap::new()) }
    }

    pub fn get_or_create(&self, peer: &PeerEndpoint) -> io::Result<*mut ibv_ah> {
        if let Some(ah) = self.table.lock().unwrap().get(&peer.node_id) {
            return Ok(ah.as_ptr());
        }
        let ah = unsafe {
            let mut a: ibv_ah_attr = mem::zeroed();
            a.is_global           = 1;
            a.dlid                = self.local_lid;
            a.port_num            = PORT_NUM;
            a.sl                  = self.qos.service_level;
            a.grh.dgid.raw        = peer.gid;
            a.grh.sgid_index      = self.gid_index;
            a.grh.hop_limit       = 64;
            // todo @arnav revisit sl and traffic class for pfc etc on roce
            a.grh.traffic_class   = self.qos.traffic_class;
            ibv_create_ah(self.pd, &mut a)
        };
        let ah = NonNull::new(ah).ok_or_else(io::Error::last_os_error)?;
        let mut t = self.table.lock().unwrap();
        if let Some(e) = t.get(&peer.node_id) {
            unsafe { ibv_destroy_ah(ah.as_ptr()); }
            return Ok(e.as_ptr());
        }
        t.insert(peer.node_id, ah);
        Ok(ah.as_ptr())
    }
}

impl Drop for AhCache {
    fn drop(&mut self) {
        for (_, ah) in self.table.lock().unwrap().drain() {
            unsafe { ibv_destroy_ah(ah.as_ptr()); }
        }
    }
}
