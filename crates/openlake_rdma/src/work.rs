#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Opcode {
    RdmaWrite,
    RdmaRead,
}

#[derive(Clone, Copy, Debug)]
pub struct ScatterGatherEntry {
    pub addr: u64,
    pub length: usize,
    pub lkey: u32,
}

#[derive(Clone, Debug)]
pub struct WorkRequest {
    pub wr_id: u64,
    pub opcode: Opcode,
    pub local: Vec<ScatterGatherEntry>,
    pub remote_addr: u64,
    pub rkey: u32,
}

impl WorkRequest {
    pub fn rdma_write(wr_id: u64, local: ScatterGatherEntry, remote_addr: u64, rkey: u32) -> Self {
        WorkRequest {
            wr_id,
            opcode: Opcode::RdmaWrite,
            local: vec![local],
            remote_addr,
            rkey,
        }
    }

    pub fn rdma_read(wr_id: u64, local: ScatterGatherEntry, remote_addr: u64, rkey: u32) -> Self {
        WorkRequest {
            wr_id,
            opcode: Opcode::RdmaRead,
            local: vec![local],
            remote_addr,
            rkey,
        }
    }

    pub fn with_scatter_gather(mut self, list: Vec<ScatterGatherEntry>) -> Self {
        self.local = list;
        self
    }

    pub fn gather_length(&self) -> usize {
        self.local.iter().map(|entry| entry.length).sum()
    }
}
