use serde::{Deserialize, Serialize};

use crate::rpc::{DiskIdx, Request, Response};

pub const ENVELOPE_MAGIC: u32 = 0x52444D33;

pub use crate::kv::KeyHash;

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct RdmaRemoteBuf {
    pub addr: u64,
    pub len: u32,
    pub rkey: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitEntry {
    pub slot_idx: u32,
    pub key_hash: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum RdmaRequest {
    ReadFileChunk {
        disk_idx: DiskIdx,
        volume: String,
        path: String,
        offset: u64,
        length: u32,
        target: RdmaRemoteBuf,
    },
    WriteFileChunk {
        disk_idx: DiskIdx,
        volume: String,
        path: String,
        offset: u64,
        length: u32,
        source: RdmaRemoteBuf,
    },
    BatchReserve {
        count: u32,
    },
    BatchCommit {
        entries: Vec<CommitEntry>,
    },
    BatchLookup {
        key_hashes: Vec<Vec<u8>>,
    },
    BatchRelease {
        slot_idxs: Vec<u32>,
    },
    Generic(Request),
    Reset,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum RdmaResponse {
    ChunkReady { bytes_written: u32 },
    ChunkWritten { bytes_written: u32 },
    BatchReserved { slots: Vec<u32> },
    BatchCommitted,
    BatchLookedUp { slots: Vec<Option<u32>> },
    BatchReleased,
    Generic(Response),
    ResetDone,
}

#[derive(Serialize, Deserialize)]
pub enum Envelope {
    Req {
        magic: u32,
        from_node_id: u16,
        from_runtime_id: u16,
        request_id: u64,
        payload: RdmaRequest,
    },
    Rsp {
        magic: u32,
        request_id: u64,
        payload: RdmaResponse,
    },
}
