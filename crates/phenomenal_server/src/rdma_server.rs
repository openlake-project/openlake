#![cfg(all(feature = "rdma", target_os = "linux"))]

use std::rc::Rc;
use std::sync::Arc;

use futures::stream::StreamExt;
use phenomenal_io::rdma::{BUF_SIZE, RdmaNode};
use phenomenal_io::rdma_backend::{Envelope, ENVELOPE_MAGIC};
use phenomenal_io::rpc::{decode, encode};
use phenomenal_io::StorageBackend;

use crate::lock_server::LockServer;
use crate::rpc_server::dispatch;

pub async fn serve(
    node:  Arc<RdmaNode>,
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
    node:  &Arc<RdmaNode>,
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
            let resp = dispatch(disks, locks, payload).await;
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
