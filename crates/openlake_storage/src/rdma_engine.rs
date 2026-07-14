#![cfg(all(feature = "rdma", target_os = "linux"))]

use openlake_io::rdma::wire::{RdmaRequest, RdmaResponse};

pub trait RdmaEngine {
    fn handle(&self, req: RdmaRequest) -> RdmaResponse;
}
