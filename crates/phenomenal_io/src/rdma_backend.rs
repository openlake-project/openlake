use std::io;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use async_trait::async_trait;
use futures::channel::oneshot;
use serde::{Deserialize, Serialize};

use crate::backend::StorageBackend;
use crate::error::{IoError, IoResult};
use crate::rdma::RdmaNode;
use crate::rpc::{encode, Request, Response};
use crate::stream::{ByteSink, ByteStream};
use crate::types::{
    DeleteOptions, DiskInfo, FileInfo, FormatJson, RenameDataResp, RenameOptions,
    UpdateMetadataOpts, VolInfo,
};

pub const ENVELOPE_MAGIC: u32 = 0x52444D31; // "RDM1"

#[derive(Serialize, Deserialize)]
pub enum Envelope {
    Req { magic: u32, from_node_id: u16, request_id: u64, payload: Request  },
    Rsp { magic: u32, request_id: u64,                   payload: Response },
}

pub struct RdmaBackend {
    node:     Arc<RdmaNode>,
    peer_id:  u16,
    disk_idx: u16,
}

impl RdmaBackend {
    pub fn new(node: Arc<RdmaNode>, peer_id: u16, disk_idx: u16) -> Self {
        Self { node, peer_id, disk_idx }
    }

    async fn unary(&self, payload: Request) -> IoResult<Response> {
        let peer = self.node.peer(self.peer_id)
            .ok_or_else(|| IoError::Io(io::Error::other(
                format!("rdma peer {} not in registry", self.peer_id)
            )))?
            .clone();
        let ah = self.node.ah_cache.get_or_create(&peer).map_err(IoError::Io)?;

        let request_id = self.node.next_request_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.node.pending_responses.lock().unwrap().insert(request_id, tx);

        let env = Envelope::Req {
            magic: ENVELOPE_MAGIC,
            from_node_id: self.node.self_id,
            request_id,
            payload,
        };
        let body = encode(&env)?;
        if let Err(e) = self.node.sock.send(&body, ah, peer.dct_num, peer.dc_key) {
            self.node.pending_responses.lock().unwrap().remove(&request_id);
            return Err(IoError::Io(e));
        }

        rx.await.map_err(|_| IoError::Io(io::Error::other("dispatcher dropped waiter")))
    }
}

fn ns(op: &'static str) -> IoError {
    IoError::Io(io::Error::other(format!("rdma backend: {op} not yet implemented")))
}

#[async_trait(?Send)]
impl StorageBackend for RdmaBackend {
    fn label(&self) -> String { format!("rdma:n{}d{}", self.peer_id, self.disk_idx) }

    async fn stat_vol(&self, volume: &str) -> IoResult<VolInfo> {
        match self.unary(Request::StatVol { disk_idx: self.disk_idx, volume: volume.into() }).await? {
            Response::Vol(v) => Ok(v),
            Response::Err(e) => Err(IoError::from(e)),
            other            => Err(IoError::Decode(format!("expected Vol, got {other:?}"))),
        }
    }

    async fn disk_info(&self)                          -> IoResult<DiskInfo>     { Err(ns("disk_info")) }
    async fn make_vol(&self, _v: &str)                 -> IoResult<()>           { Err(ns("make_vol")) }
    async fn list_vols(&self)                          -> IoResult<Vec<VolInfo>> { Err(ns("list_vols")) }
    async fn delete_vol(&self, _v: &str, _f: bool)     -> IoResult<()>           { Err(ns("delete_vol")) }
    async fn list_dir(&self, _v: &str, _d: &str, _c: usize) -> IoResult<Vec<String>> { Err(ns("list_dir")) }
    async fn read_file_stream(&self, _v: &str, _p: &str, _o: u64, _l: u64) -> IoResult<Box<dyn ByteStream>> { Err(ns("read_file_stream")) }
    async fn create_file_writer(&self, _v: &str, _p: &str, _s: u64)        -> IoResult<Box<dyn ByteSink>>   { Err(ns("create_file_writer")) }
    async fn rename_file(&self, _: &str, _: &str, _: &str, _: &str)        -> IoResult<()> { Err(ns("rename_file")) }
    async fn check_file(&self, _: &str, _: &str)                            -> IoResult<()> { Err(ns("check_file")) }
    async fn delete(&self, _: &str, _: &str, _: bool)                       -> IoResult<()> { Err(ns("delete")) }
    async fn delete_batch(&self, _: &str, _: &[&str], _: bool) -> IoResult<Vec<IoResult<()>>> { Err(ns("delete_batch")) }
    async fn walk_dir(&self, _: &str, _: &str, _: bool, _: &str, _: Option<&str>, _: Option<usize>) -> IoResult<Vec<(String, FileInfo)>> { Err(ns("walk_dir")) }
    async fn write_metadata(&self, _: &str, _: &str, _: &str, _: &FileInfo) -> IoResult<()> { Err(ns("write_metadata")) }
    async fn read_version(&self, _: &str, _: &str, _: &str, _: Option<&str>, _: bool) -> IoResult<FileInfo> { Err(ns("read_version")) }
    async fn update_metadata(&self, _: &str, _: &str, _: &FileInfo, _: &UpdateMetadataOpts) -> IoResult<()> { Err(ns("update_metadata")) }
    async fn delete_version(&self, _: &str, _: &str, _: &FileInfo, _: bool, _: &DeleteOptions) -> IoResult<()> { Err(ns("delete_version")) }
    async fn rename_data(&self, _: &str, _: &str, _: &FileInfo, _: &str, _: &str, _: &RenameOptions) -> IoResult<RenameDataResp> { Err(ns("rename_data")) }
    async fn verify_file(&self, _: &str, _: &str, _: &FileInfo) -> IoResult<()> { Err(ns("verify_file")) }
    async fn read_format(&self) -> IoResult<Option<FormatJson>> { Err(ns("read_format")) }
    async fn write_format(&self, _: &FormatJson)             -> IoResult<()> { Err(ns("write_format")) }
    async fn write_file(&self, _: &str, _: &str, _: Vec<u8>) -> IoResult<()> { Err(ns("write_file")) }
    async fn read_file(&self, _: &str, _: &str)              -> IoResult<Option<Vec<u8>>> { Err(ns("read_file")) }
    async fn make_dir_all(&self, _: &str, _: &str)           -> IoResult<()> { Err(ns("make_dir_all")) }
}
