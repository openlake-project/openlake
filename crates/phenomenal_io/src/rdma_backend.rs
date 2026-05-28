use std::io;
use std::rc::Rc;

use async_trait::async_trait;
use bytes::Bytes;
use futures::channel::oneshot;
use crate::backend::StorageBackend;
use crate::error::{IoError, IoResult};
use crate::rdma::wire::{Envelope, ENVELOPE_MAGIC, RdmaRemoteBuf, RdmaRequest, RdmaResponse};
use crate::rdma::RdmaNode;
use crate::rpc::{encode, Request, Response};
use crate::stream::{ByteSink, ByteStream};
use crate::types::{
    DeleteOptions, DiskInfo, FileInfo, FormatJson, RenameDataResp, RenameOptions,
    UpdateMetadataOpts, VolInfo,
};

#[derive(Clone)]
pub struct RdmaBackend {
    node:     Rc<RdmaNode>,
    peer_id:  u16,
    disk_idx: u16,
    rpc_backend: Rc<dyn StorageBackend>,
}

impl RdmaBackend {
    /// Temporary: `rpc_backend` is the H2 fallback for ops the RDMA endpoint
    /// does not yet implement (currently everything except `stat_vol` and
    /// `read_file_stream`). Remove this parameter and the coupling once the
    /// RDMA backend implements every `StorageBackend` op natively.
    pub fn new(
        node: Rc<RdmaNode>, peer_id: u16, disk_idx: u16, rpc_backend: Rc<dyn StorageBackend>,
    ) -> Self {
        Self { node, peer_id, disk_idx, rpc_backend }
    }

    async fn unary(&self, payload: Request) -> IoResult<Response> {
        let peer = self.node.peer(self.peer_id)
            .ok_or_else(|| IoError::Io(io::Error::other(
                format!("rdma peer {} not in registry", self.peer_id)
            )))?
            .clone();
        let ah = self.node.ah_cache.get_or_create(&peer).map_err(IoError::Io)?;

        let request_id = {
            let id = self.node.next_request_id.get();
            self.node.next_request_id.set(id + 1);
            id
        };
        let (tx, rx) = oneshot::channel();
        self.node.pending_responses.borrow_mut().insert(request_id, tx);

        let env = Envelope::Req {
            magic: ENVELOPE_MAGIC,
            from_node_id: self.node.self_id,
            request_id,
            payload: RdmaRequest::Generic(payload),
        };
        let body = encode(&env)?;
        if let Err(e) = self.node.sock.send(&body, ah, peer.dct_num, peer.dc_key) {
            self.node.pending_responses.borrow_mut().remove(&request_id);
            return Err(IoError::Io(e));
        }

        match rx.await {
            Ok(RdmaResponse::Generic(resp)) => Ok(resp),
            Ok(other) => Err(IoError::Decode(format!("unary expected Generic, got {other:?}"))),
            Err(_)    => Err(IoError::Io(io::Error::other("dispatcher dropped waiter"))),
        }
    }

    async fn read_single_chunk(
        &self, volume: &str, path: &str, offset: u64, length: u32,
    ) -> IoResult<Bytes> {
        let node = self.node.clone();
        let peer = node.peer(self.peer_id)
            .ok_or_else(|| IoError::Io(io::Error::other(
                format!("rdma peer {} not in registry", self.peer_id)
            )))?
            .clone();
        let ah = node.ah_cache.get_or_create(&peer).map_err(IoError::Io)?;

        let buf    = node.bulk_pool.acquire().await.map_err(IoError::Io)?;
        let target = buf.as_remote(length);

        let request_id = {
            let id = node.next_request_id.get();
            node.next_request_id.set(id + 1);
            id
        };
        let (resp_tx, resp_rx) = oneshot::channel();
        node.pending_responses.borrow_mut().insert(request_id, resp_tx);

        let env = Envelope::Req {
            magic: ENVELOPE_MAGIC,
            from_node_id: node.self_id,
            request_id,
            payload: RdmaRequest::ReadFileChunk {
                disk_idx: self.disk_idx,
                volume:   volume.into(),
                path:     path.into(),
                offset,
                length,
                target,
            },
        };
        let body = encode(&env)?;
        if let Err(e) = node.sock.send(&body, ah, peer.dct_num, peer.dc_key) {
            node.pending_responses.borrow_mut().remove(&request_id);
            return Err(IoError::Io(e));
        }

        let (bytes_tx, bytes_rx) = oneshot::channel::<IoResult<Bytes>>();
        compio::runtime::spawn(async move {
            let result: IoResult<Bytes> = match resp_rx.await {
                Ok(RdmaResponse::ChunkReady { bytes_written }) => {
                    Ok(buf.into_bytes(bytes_written as usize))
                }
                Ok(RdmaResponse::Generic(Response::Err(e))) => {
                    drop(buf);
                    Err(IoError::from(e))
                }
                Ok(other) => {
                    drop(buf);
                    Err(IoError::Decode(format!("expected ChunkReady, got {other:?}")))
                }
                Err(_) => {
                    drop(buf);
                    Err(IoError::Io(io::Error::other("dispatcher dropped chunk waiter")))
                }
            };
            let _ = bytes_tx.send(result);
        }).detach();

        match bytes_rx.await {
            Ok(r)  => r,
            Err(_) => Err(IoError::Io(io::Error::other(
                "chunk completion task dropped before producing bytes"
            ))),
        }
    }

    async fn write_single_chunk(
        &self, volume: &str, path: &str, offset: u64, data: Bytes,
    ) -> IoResult<()> {
        let node = self.node.clone();
        let peer = node.peer(self.peer_id)
            .ok_or_else(|| IoError::Io(io::Error::other(
                format!("rdma peer {} not in registry", self.peer_id)
            )))?
            .clone();
        let ah = node.ah_cache.get_or_create(&peer).map_err(IoError::Io)?;

        let len = data.len();
        if len > u32::MAX as usize {
            return Err(IoError::InvalidArgument(format!("write chunk too large: {len}")));
        }
        let mut buf = node.bulk_pool.acquire().await.map_err(IoError::Io)?;
        // todo: @arnav this can be avoided.
        buf.as_slice_mut()[..len].copy_from_slice(&data);
        let source = buf.as_remote(len as u32);

        let request_id = {
            let id = node.next_request_id.get();
            node.next_request_id.set(id + 1);
            id
        };
        let (resp_tx, resp_rx) = oneshot::channel();
        node.pending_responses.borrow_mut().insert(request_id, resp_tx);

        let env = Envelope::Req {
            magic: ENVELOPE_MAGIC,
            from_node_id: node.self_id,
            request_id,
            payload: RdmaRequest::WriteFileChunk {
                disk_idx: self.disk_idx,
                volume:   volume.into(),
                path:     path.into(),
                offset,
                length:   len as u32,
                source,
            },
        };
        let body = encode(&env)?;
        if let Err(e) = node.sock.send(&body, ah, peer.dct_num, peer.dc_key) {
            node.pending_responses.borrow_mut().remove(&request_id);
            return Err(IoError::Io(e));
        }

        let (done_tx, done_rx) = oneshot::channel::<IoResult<()>>();
        compio::runtime::spawn(async move {
            let result: IoResult<()> = match resp_rx.await {
                Ok(RdmaResponse::ChunkWritten { bytes_written }) => {
                    drop(buf);
                    if (bytes_written as usize) != len {
                        Err(IoError::Io(io::Error::other(format!(
                            "short write: server wrote {bytes_written}/{len}"
                        ))))
                    } else {
                        Ok(())
                    }
                }
                Ok(RdmaResponse::Generic(Response::Err(e))) => { drop(buf); Err(IoError::from(e)) }
                Ok(other) => {
                    drop(buf);
                    Err(IoError::Decode(format!("expected ChunkWritten, got {other:?}")))
                }
                Err(_) => {
                    drop(buf);
                    Err(IoError::Io(io::Error::other("dispatcher dropped chunk waiter")))
                }
            };
            let _ = done_tx.send(result);
        }).detach();

        match done_rx.await {
            Ok(r)  => r,
            Err(_) => Err(IoError::Io(io::Error::other(
                "write completion task dropped"
            ))),
        }
    }
}

macro_rules! rdma_backend_storage_impl {
    (
        ib { $($ib:item)* }
        via_rpc { $( async fn $name:ident ( &self $(, $arg:ident : $aty:ty )* ) -> $ret:ty ; )* }
    ) => {
        #[async_trait(?Send)]
        impl StorageBackend for RdmaBackend {
            fn label(&self) -> String { format!("rdma:n{}d{}", self.peer_id, self.disk_idx) }
            $($ib)*
            $(
                async fn $name(&self $(, $arg: $aty)*) -> $ret {
                    self.rpc_backend.$name($($arg),*).await
                }
            )*
        }
    };
}

rdma_backend_storage_impl! {
    ib {
        async fn stat_vol(&self, volume: &str) -> IoResult<VolInfo> {
            match self.unary(Request::StatVol { disk_idx: self.disk_idx, volume: volume.into() }).await? {
                Response::Vol(v) => Ok(v),
                Response::Err(e) => Err(IoError::from(e)),
                other            => Err(IoError::Decode(format!("expected Vol, got {other:?}"))),
            }
        }

        async fn read_file_stream(
            &self, volume: &str, path: &str, offset: u64, length: u64,
        ) -> IoResult<Box<dyn ByteStream>> {
            let chunk_size = self.node.bulk_pool.buf_size() as u32;
            Ok(Box::new(RdmaReadStream {
                backend:    self.clone(),
                volume:     volume.into(),
                path:       path.into(),
                offset,
                remaining:  length,
                chunk_size,
            }))
        }

        async fn create_file_writer(
            &self, volume: &str, path: &str, size: u64,
        ) -> IoResult<Box<dyn ByteSink>> {
            let chunk_size = self.node.bulk_pool.buf_size() as u32;
            Ok(Box::new(RdmaWriteSink {
                backend:    self.clone(),
                volume:     volume.into(),
                path:       path.into(),
                cursor:     0,
                expected:   size,
                chunk_size,
                finished:   false,
            }))
        }

        async fn read_version(
            &self, orig_volume: &str, volume: &str, path: &str,
            version_id: Option<&str>, read_data: bool,
        ) -> IoResult<FileInfo> {
            match self.unary(Request::ReadVersion {
                disk_idx:    self.disk_idx,
                orig_volume: orig_volume.into(),
                volume:      volume.into(),
                path:        path.into(),
                version_id:  version_id.map(str::to_owned),
                read_data,
            }).await? {
                Response::File(fi) => Ok(fi),
                Response::Err(e)   => Err(IoError::from(e)),
                other              => Err(IoError::Decode(format!("expected File, got {other:?}"))),
            }
        }
    }
    via_rpc {
        async fn disk_info(&self) -> IoResult<DiskInfo>;
        async fn make_vol(&self, volume: &str) -> IoResult<()>;
        async fn list_vols(&self) -> IoResult<Vec<VolInfo>>;
        async fn delete_vol(&self, volume: &str, force: bool) -> IoResult<()>;
        async fn list_dir(&self, volume: &str, dir: &str, count: usize) -> IoResult<Vec<String>>;
        async fn rename_file(&self, src_volume: &str, src_path: &str, dst_volume: &str, dst_path: &str) -> IoResult<()>;
        async fn check_file(&self, volume: &str, path: &str) -> IoResult<()>;
        async fn delete(&self, volume: &str, path: &str, recursive: bool) -> IoResult<()>;
        async fn delete_batch(&self, volume: &str, paths: &[&str], recursive: bool) -> IoResult<Vec<IoResult<()>>>;
        async fn walk_dir(&self, volume: &str, base_dir: &str, recursive: bool, prefix: &str, start_after: Option<&str>, max_keys: Option<usize>) -> IoResult<Vec<(String, FileInfo)>>;
        async fn write_metadata(&self, orig_volume: &str, volume: &str, path: &str, fi: &FileInfo) -> IoResult<()>;
        async fn update_metadata(&self, volume: &str, path: &str, fi: &FileInfo, opts: &UpdateMetadataOpts) -> IoResult<()>;
        async fn delete_version(&self, volume: &str, path: &str, fi: &FileInfo, force_del_marker: bool, opts: &DeleteOptions) -> IoResult<()>;
        async fn rename_data(&self, src_volume: &str, src_path: &str, fi: &FileInfo, dst_volume: &str, dst_path: &str, opts: &RenameOptions) -> IoResult<RenameDataResp>;
        async fn verify_file(&self, volume: &str, path: &str, fi: &FileInfo) -> IoResult<()>;
        async fn read_format(&self) -> IoResult<Option<FormatJson>>;
        async fn write_format(&self, fmt: &FormatJson) -> IoResult<()>;
        async fn write_file(&self, volume: &str, path: &str, bytes: Vec<u8>) -> IoResult<()>;
        async fn read_file(&self, volume: &str, path: &str) -> IoResult<Option<Vec<u8>>>;
        async fn make_dir_all(&self, volume: &str, path: &str) -> IoResult<()>;
    }
}

struct RdmaReadStream {
    backend:    RdmaBackend,
    volume:     String,
    path:       String,
    offset:     u64,
    remaining:  u64,
    chunk_size: u32,
}

#[async_trait(?Send)]
impl ByteStream for RdmaReadStream {
    async fn read(&mut self) -> IoResult<Bytes> {
        if self.remaining == 0 {
            return Ok(Bytes::new());
        }
        let request_len = self.remaining.min(self.chunk_size as u64) as u32;
        let chunk = self.backend
            .read_single_chunk(&self.volume, &self.path, self.offset, request_len)
            .await?;
        let got = chunk.len() as u64;
        self.offset    += got;
        self.remaining  = self.remaining.saturating_sub(got);
        if got < request_len as u64 {
            self.remaining = 0;
        }
        Ok(chunk)
    }

    async fn read_buffer(&mut self, _: &mut [u8]) -> IoResult<usize> {
        unimplemented!("not implemented")
    }
}

struct RdmaWriteSink {
    backend:    RdmaBackend,
    volume:     String,
    path:       String,
    cursor:     u64,
    expected:   u64,
    chunk_size: u32,
    finished:   bool,
}

#[async_trait(?Send)]
impl ByteSink for RdmaWriteSink {
    async fn write_all(&mut self, buf: Bytes) -> IoResult<()> {
        if self.finished {
            return Err(IoError::Io(io::Error::other("write after finish")));
        }
        let chunk_size = self.chunk_size as usize;
        let mut remaining = buf;
        while !remaining.is_empty() {
            let take = remaining.len().min(chunk_size);
            let piece = remaining.slice(..take);
            remaining = remaining.slice(take..);
            let offset = self.cursor;
            self.cursor += take as u64;
            self.backend.write_single_chunk(&self.volume, &self.path, offset, piece).await?;
        }
        Ok(())
    }

    async fn finish(&mut self) -> IoResult<()> {
        if self.finished { return Ok(()); }
        if self.cursor != self.expected {
            return Err(IoError::Io(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("rdma create_file_writer: wrote {}/{}", self.cursor, self.expected),
            )));
        }
        self.finished = true;
        Ok(())
    }
}
