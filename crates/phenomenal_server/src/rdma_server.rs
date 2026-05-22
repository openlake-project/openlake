#![cfg(all(feature = "rdma", target_os = "linux"))]

use std::rc::Rc;
use std::sync::Arc;

use futures::stream::StreamExt;
use phenomenal_io::error::IoError;
use phenomenal_io::rdma::{BUF_SIZE, RawAddressHandle, RdmaNode};
use phenomenal_io::rdma_backend::{Envelope, ENVELOPE_MAGIC};
use phenomenal_io::rpc::{decode, encode, RdmaRemoteBuf, Request, Response, WireError};
use phenomenal_io::stream::ByteStream;
use phenomenal_io::StorageBackend;

use crate::lock_server::LockServer;
use crate::rpc_server::{disk_at, dispatch};

pub async fn serve(
    node:  Rc<RdmaNode>,
    disks: Rc<Vec<Rc<dyn StorageBackend>>>,
    locks: Arc<LockServer>,
) -> anyhow::Result<()> {
    let mut rx = node.pump.take_recv_rx()
        .ok_or_else(|| anyhow::anyhow!("rdma_server: pump recv_rx already taken"))?;
    let mut buf = Vec::with_capacity(BUF_SIZE);
    loop {
        // Drain every envelope queued before parking again.
        loop {
            buf.clear();
            if node.sock.attempt_singular_rcv(&mut buf).is_none() { break; }
            handle(&node, &disks, &locks, &buf).await;
        }
        if rx.next().await.is_none() { return Ok(()); }
    }
}

async fn handle(
    node:  &Rc<RdmaNode>,
    disks: &Rc<Vec<Rc<dyn StorageBackend>>>,
    locks: &Arc<LockServer>,
    bytes: &[u8],
) {
    let env: Envelope = match decode(bytes) {
        Ok(e)  => e,
        Err(e) => { tracing::warn!("rdma_server: decode envelope: {e}"); return; }
    };
    match env {
        Envelope::Req { magic, from_node_id, request_id, payload } => {
            if magic != ENVELOPE_MAGIC {
                tracing::warn!("rdma_server: bad request magic {:#x}", magic);
                return;
            }
            let sender = match node.peer(from_node_id) {
                Some(p) => p.clone(),
                None    => { tracing::warn!("rdma_server: unknown sender {from_node_id}"); return; }
            };
            let sender_ah = match node.ah_cache.get_or_create(&sender) {
                Ok(ah) => ah,
                Err(e) => { tracing::warn!("rdma_server: ah for {}: {e}", from_node_id); return; }
            };

            let resp = match payload {
                Request::ReadFileChunk { disk_idx, volume, path, offset, length, target } =>
                    handle_read_file_chunk(
                        node, disks, sender_ah,
                        sender.dct_num, sender.dc_key,
                        disk_idx, volume, path, offset, length, target,
                    ).await,
                other => dispatch(disks, locks, other).await,
            };
            let body = match encode(&Envelope::Rsp {
                magic: ENVELOPE_MAGIC, request_id, payload: resp,
            }) {
                Ok(b)  => b,
                Err(e) => { tracing::warn!("rdma_server: encode response: {e}"); return; }
            };
            if let Err(e) = node.sock.send(&body, sender_ah, sender.dct_num, sender.dc_key) {
                tracing::warn!("rdma_server: send response: {e}");
            }
        }
        Envelope::Rsp { magic, request_id, payload } => {
            if magic != ENVELOPE_MAGIC {
                tracing::warn!("rdma_server: bad response magic {:#x}", magic);
                return;
            }
            if let Some(tx) = node.pending_responses.lock().unwrap().remove(&request_id) {
                let _ = tx.send(payload);
            } else {
                tracing::warn!("rdma_server: unmatched response request_id {request_id}");
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_read_file_chunk(
    node:         &Rc<RdmaNode>,
    disks:        &Rc<Vec<Rc<dyn StorageBackend>>>,
    sender_ah:    RawAddressHandle,
    peer_dct_num: u32,
    peer_dc_key:  u64,
    disk_idx:     u16,
    volume:       String,
    path:         String,
    offset:       u64,
    length:       u32,
    target:       RdmaRemoteBuf,
) -> Response {
    let server_cap = node.bulk_pool.buf_size();
    if length as usize > server_cap {
        return Response::Err(WireError::Other(format!(
            "read_file_chunk length {} exceeds server bulk_buf_size {}",
            length, server_cap
        )));
    }
    if length > target.len {
        return Response::Err(WireError::Other(format!(
            "read_file_chunk length {} exceeds client target.len {}",
            length, target.len
        )));
    }

    let disk = match disk_at(disks, disk_idx) {
        Ok(d)  => d.clone(),
        Err(e) => return Response::Err(e.into()),
    };

    let mut buf = match node.bulk_pool.acquire().await {
        Ok(b)  => b,
        Err(e) => return Response::Err(IoError::Io(e).into()),
    };

    let bytes_filled = {
        let mut stream = match disk.read_file_stream(&volume, &path, offset, length as u64).await {
            Ok(s)  => s,
            Err(e) => return Response::Err(e.into()),
        };
        let dst = &mut buf.as_slice_mut()[..length as usize];
        match stream.read_buffer(dst).await {
            Ok(n)  => n,
            Err(e) => return Response::Err(e.into()),
        }
    };

    if bytes_filled == 0 {
        return Response::ChunkReady { bytes_written: 0 };
    }

    if let Err(e) = node.sock.rdma_write(
        buf.addr(), bytes_filled as u32, buf.lkey(),
        target.addr, target.rkey,
        sender_ah, peer_dct_num, peer_dc_key,
    ).await {
        return Response::Err(IoError::Io(e).into());
    }

    Response::ChunkReady { bytes_written: bytes_filled as u32 }
}
