#![cfg(all(feature = "rdma", target_os = "linux"))]

use std::rc::Rc;
use std::sync::Arc;

use futures::stream::StreamExt;
use openlake_io::error::IoError;
use openlake_io::rdma::wire::{Envelope, ENVELOPE_MAGIC, RdmaRemoteBuf, RdmaRequest, RdmaResponse};
use openlake_io::rdma::{BUF_SIZE, PeerKey, RawAddressHandle, RdmaNode};
use openlake_io::rpc::{decode, encode, Response, WireError};
use openlake_io::stream::ByteStream;
use openlake_io::{LocalFsBackend, StorageBackend};

use crate::lock_server::LockServer;
use crate::rpc_server::{disk_at, dispatch};

pub async fn serve(
    node:        Rc<RdmaNode>,
    disks:       Rc<Vec<Rc<dyn StorageBackend>>>,
    local_disks: Rc<Vec<Rc<LocalFsBackend>>>,
    locks:       Arc<LockServer>,
    endpoints:   Arc<std::sync::Mutex<openlake_io::rpc::RdmaEndpointsReply>>,
) -> anyhow::Result<()> {
    let mut rx = node.pump.take_recv_rx()
        .ok_or_else(|| anyhow::anyhow!("rdma_server: pump recv_rx already taken"))?;
    let mut buf = Vec::with_capacity(BUF_SIZE);
    loop {
        loop {
            buf.clear();
            if node.sock.attempt_singular_rcv(&mut buf).is_none() { break; }
            let bytes = std::mem::take(&mut buf);
            buf = Vec::with_capacity(BUF_SIZE);
            let n = node.clone();
            let d = disks.clone();
            let ld = local_disks.clone();
            let l = locks.clone();
            let ep = endpoints.clone();
            compio::runtime::spawn(async move {
                handle(&n, &d, &ld, &l, &ep, &bytes).await;
            }).detach();
        }
        if rx.next().await.is_none() { return Ok(()); }
    }
}

async fn handle(
    node:        &Rc<RdmaNode>,
    disks:       &Rc<Vec<Rc<dyn StorageBackend>>>,
    local_disks: &Rc<Vec<Rc<LocalFsBackend>>>,
    locks:       &Arc<LockServer>,
    endpoints:   &Arc<std::sync::Mutex<openlake_io::rpc::RdmaEndpointsReply>>,
    bytes:       &[u8],
) {
    let env: Envelope = match decode(bytes) {
        Ok(e)  => e,
        Err(e) => { tracing::warn!("rdma_server: decode envelope: {e}"); return; }
    };
    match env {
        Envelope::Req { magic, from_node_id, from_runtime_id, request_id, payload } => {
            if magic != ENVELOPE_MAGIC {
                tracing::warn!("rdma_server: bad request magic {:#x}", magic);
                return;
            }
            let sender = match node.peer_at(from_node_id, from_runtime_id) {
                Some(p) => p.clone(),
                None    => {
                    tracing::warn!("rdma_server: unknown sender (node={from_node_id}, runtime={from_runtime_id})");
                    return;
                }
            };
            let sender_ah = match node.ah_cache.get_or_create(&sender) {
                Ok(ah) => ah,
                Err(e) => { tracing::warn!("rdma_server: ah for {}: {e}", from_node_id); return; }
            };
            let sender_key = PeerKey::new(from_node_id, from_runtime_id);

            if let Err(e) = node.sock.note_drain(sender_key, sender_ah, sender.dct_num, sender.dc_key) {
                tracing::warn!("rdma_server: note_drain: {e}");
            }

            let resp = match payload {
                RdmaRequest::ReadFileChunk { disk_idx, volume, path, offset, length, target } =>
                    handle_read_file_chunk(
                        node, local_disks, sender_ah,
                        sender.dct_num, sender.dc_key,
                        disk_idx, volume, path, offset, length, target,
                    ).await,
                RdmaRequest::WriteFileChunk { disk_idx, volume, path, offset, length, source } =>
                    handle_write_file_chunk(
                        node, local_disks, sender_ah,
                        sender.dct_num, sender.dc_key,
                        disk_idx, volume, path, offset, length, source,
                    ).await,
                RdmaRequest::Generic(req) => {
                    RdmaResponse::Generic(dispatch(disks, locks, endpoints, req).await)
                }
            };
            let body = match encode(&Envelope::Rsp {
                magic: ENVELOPE_MAGIC, request_id, payload: resp,
            }) {
                Ok(b)  => b,
                Err(e) => { tracing::warn!("rdma_server: encode response: {e}"); return; }
            };
            if let Err(e) = node.sock.send_with_kind(&body, sender_key, sender_ah, sender.dct_num, sender.dc_key, openlake_io::rdma::wr::SendKind::Response).await {
                tracing::warn!("rdma_server: send response: {e}");
            }
        }
        Envelope::Rsp { magic, request_id, payload } => {
            if magic != ENVELOPE_MAGIC {
                tracing::warn!("rdma_server: bad response magic {:#x}", magic);
                return;
            }
            if let Some(pending) = node.pending_responses.borrow_mut().remove(&request_id) {
                if let Err(e) = node.sock.note_drain(pending.peer, pending.ah, pending.peer_dct_num, pending.peer_dc_key) {
                    tracing::warn!("rdma_server: note_drain on rsp: {e}");
                }
                let _ = pending.tx.send(payload);
            } else {
                tracing::warn!("rdma_server: unmatched response request_id {request_id}");
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_read_file_chunk(
    node:         &Rc<RdmaNode>,
    local_disks:  &Rc<Vec<Rc<LocalFsBackend>>>,
    sender_ah:    RawAddressHandle,
    peer_dct_num: u32,
    peer_dc_key:  u64,
    disk_idx:     u16,
    volume:       String,
    path:         String,
    offset:       u64,
    length:       u32,
    target:       RdmaRemoteBuf,
) -> RdmaResponse {
    let err = |e: WireError| RdmaResponse::Generic(Response::Err(e));
    let server_cap = node.bulk_pool.buf_size();
    if length as usize > server_cap {
        return err(WireError::Other(format!(
            "read_file_chunk length {} exceeds server bulk_buf_size {}",
            length, server_cap
        )));
    }
    if length > target.len {
        return err(WireError::Other(format!(
            "read_file_chunk length {} exceeds client target.len {}",
            length, target.len
        )));
    }
    let disk = match local_disks.get(disk_idx as usize) {
        Some(d) => d.clone(),
        None => return err(WireError::from(IoError::Io(std::io::Error::other(
            format!("disk_idx {disk_idx} out of range"),
        )))),
    };

    let mut buf = match node.bulk_pool.acquire().await {
        Ok(b)  => b,
        Err(e) => return err(IoError::Io(e).into()),
    };

    let bytes_filled = {
        let dst = &mut buf.as_slice_mut()[..length as usize];
        match disk.read_chunk_at(&volume, &path, offset, dst).await {
            Ok(n)  => n,
            Err(e) => return err(e.into()),
        }
    };

    if bytes_filled == 0 {
        return RdmaResponse::ChunkReady { bytes_written: 0 };
    }

    if let Err(e) = node.sock.rdma_write(
        buf.addr(), bytes_filled as u32, buf.lkey(),
        target.addr, target.rkey,
        sender_ah, peer_dct_num, peer_dc_key,
    ).await {
        return err(IoError::Io(e).into());
    }

    RdmaResponse::ChunkReady { bytes_written: bytes_filled as u32 }
}

#[allow(clippy::too_many_arguments)]
async fn handle_write_file_chunk(
    node:         &Rc<RdmaNode>,
    local_disks:  &Rc<Vec<Rc<LocalFsBackend>>>,
    sender_ah:    RawAddressHandle,
    peer_dct_num: u32,
    peer_dc_key:  u64,
    disk_idx:     u16,
    volume:       String,
    path:         String,
    offset:       u64,
    length:       u32,
    source:       RdmaRemoteBuf,
) -> RdmaResponse {
    let err = |e: WireError| RdmaResponse::Generic(Response::Err(e));
    let server_cap = node.bulk_pool.buf_size();
    if length as usize > server_cap {
        return err(WireError::Other(format!(
            "write_file_chunk length {} exceeds server bulk_buf_size {}",
            length, server_cap
        )));
    }
    if length > source.len {
        return err(WireError::Other(format!(
            "write_file_chunk length {} exceeds client source.len {}",
            length, source.len
        )));
    }
    let disk = match local_disks.get(disk_idx as usize) {
        Some(d) => d.clone(),
        None => return err(WireError::from(IoError::Io(std::io::Error::other(
            format!("disk_idx {disk_idx} out of range"),
        )))),
    };

    let buf = match node.bulk_pool.acquire().await {
        Ok(b)  => b,
        Err(e) => return err(IoError::Io(e).into()),
    };

    if let Err(e) = node.sock.rdma_read(
        buf.addr(), length, buf.lkey(),
        source.addr, source.rkey,
        sender_ah, peer_dct_num, peer_dc_key,
    ).await {
        return err(IoError::Io(e).into());
    }

    let payload = buf.into_bytes(length as usize);
    if let Err(e) = disk.write_chunk_at(&volume, &path, offset, payload).await {
        return err(e.into());
    }

    RdmaResponse::ChunkWritten { bytes_written: length }
}
