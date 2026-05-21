//! Single-process RDMA loopback probe.
//!
//! Brings up an RdmaNode, registers ITSELF as the only peer (DCI loops
//! back through the local HCA into the local DCT), serves StatVol on a
//! `LocalFsBackend`, and then drives a `StatVol` request through
//! `RdmaBackend` to prove the wire works end-to-end on real hardware.
//!
//! Run on a host with `/dev/infiniband/uverbs0`:
//!   cargo run --release --features rdma -p phenomenal_io --example rdma_loopback

#![cfg(all(feature = "rdma", target_os = "linux"))]

use std::rc::Rc;
use std::sync::Arc;

use phenomenal_io::rdma::{
    PeerEndpoint, RdmaConfig, RdmaNode, RdmaQos, BUF_SIZE,
};
use phenomenal_io::rdma_backend::{Envelope, RdmaBackend, ENVELOPE_MAGIC};
use phenomenal_io::rpc::{decode, encode, Request, Response};
use phenomenal_io::{LocalFsBackend, StorageBackend};

use anyhow::Context;
use futures::stream::StreamExt;

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let rt = compio::runtime::RuntimeBuilder::new().build()?;
    rt.block_on(async move {
        if let Err(e) = run().await {
            eprintln!("FAIL: {e:#}");
            std::process::exit(1);
        }
    });
    Ok(())
}

async fn run() -> anyhow::Result<()> {
    let dir = std::env::temp_dir().join("phenomenal-rdma-loop");
    let _   = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    let disk: Rc<dyn StorageBackend> = Rc::new(LocalFsBackend::new(&dir)?);
    disk.make_vol("probe").await?;
    eprintln!("local disk ready at {}", dir.display());

    let cfg = RdmaConfig {
        self_node_id: 0,
        dev_name:     std::env::var("PHENOMENAL_RDMA_DEV").unwrap_or_else(|_| "mlx5_0".into()),
        dc_key:       0xdeadbeef_cafef00d,
        qos:          RdmaQos { traffic_class: 0, service_level: 0 },
        // self-loopback: RdmaNode::start patches gid+dct_num with the
        // real local values, so the placeholders here don't matter.
        peers: vec![PeerEndpoint {
            node_id: 0,
            gid:     [0u8; 16],
            dct_num: 0,
            dc_key:  0,
        }],
    };

    let node = Arc::new(RdmaNode::start(cfg).context("RdmaNode::start")?);
    eprintln!(
        "RdmaNode up: self_dct_num={} gid={:02x?}",
        node.sock.self_dct_identifier(), node.dev.gid_bytes(),
    );

    let disks = Rc::new(vec![disk.clone()]);
    let dispatcher = compio::runtime::spawn({
        let node  = node.clone();
        let disks = disks.clone();
        async move {
            if let Err(e) = dispatch_loop(node, disks).await {
                eprintln!("dispatcher exited: {e:#}");
            }
        }
    });

    let backend = RdmaBackend::new(node.clone(), /*peer_id*/ 0, /*disk_idx*/ 0);
    eprintln!("issuing StatVol via RdmaBackend...");
    let vol = backend.stat_vol("probe").await?;
    eprintln!("OK: stat_vol -> {vol:?}");

    drop(dispatcher);
    Ok(())
}

async fn dispatch_loop(
    node:  Arc<RdmaNode>,
    disks: Rc<Vec<Rc<dyn StorageBackend>>>,
) -> anyhow::Result<()> {
    let mut rx = node.pump.take_recv_rx()
        .ok_or_else(|| anyhow::anyhow!("pump recv_rx already taken"))?;
    let mut buf = Vec::with_capacity(BUF_SIZE);
    loop {
        loop {
            buf.clear();
            if node.sock.attempt_singular_rcv(&mut buf).is_none() { break; }
            handle_envelope(&node, &disks, &buf).await;
        }
        if rx.next().await.is_none() { return Ok(()); }
    }
}

async fn handle_envelope(
    node:  &Arc<RdmaNode>,
    disks: &Rc<Vec<Rc<dyn StorageBackend>>>,
    bytes: &[u8],
) {
    let env: Envelope = match decode(bytes) {
        Ok(e)  => e,
        Err(e) => { eprintln!("decode err: {e}"); return; }
    };
    match env {
        Envelope::Req { magic, from_node_id, request_id, payload } => {
            if magic != ENVELOPE_MAGIC { eprintln!("bad req magic"); return; }
            let peer = match node.peer(from_node_id) {
                Some(p) => p.clone(),
                None    => { eprintln!("unknown sender {from_node_id}"); return; }
            };
            let ah = match node.ah_cache.get_or_create(&peer) {
                Ok(a)  => a,
                Err(e) => { eprintln!("ah err: {e}"); return; }
            };
            let resp = match payload {
                Request::StatVol { disk_idx, volume } => {
                    match disks.get(disk_idx as usize) {
                        Some(d) => match d.stat_vol(&volume).await {
                            Ok(v)  => Response::Vol(v),
                            Err(e) => Response::Err(e.into()),
                        },
                        None => Response::Err(phenomenal_io::rpc::WireError::from(
                            phenomenal_io::IoError::Io(std::io::Error::other(
                                format!("disk_idx {disk_idx} out of range"),
                            )),
                        )),
                    }
                }
                other => {
                    eprintln!("loopback dispatcher: unsupported request {other:?}");
                    return;
                }
            };
            let body = match encode(&Envelope::Rsp {
                magic: ENVELOPE_MAGIC, request_id, payload: resp,
            }) {
                Ok(b)  => b,
                Err(e) => { eprintln!("encode rsp: {e}"); return; }
            };
            if let Err(e) = node.sock.send(&body, ah, peer.dct_num, peer.dc_key) {
                eprintln!("send rsp: {e}");
            }
        }
        Envelope::Rsp { magic, request_id, payload } => {
            if magic != ENVELOPE_MAGIC { eprintln!("bad rsp magic"); return; }
            if let Some(tx) = node.pending_responses.lock().unwrap().remove(&request_id) {
                let _ = tx.send(payload);
            } else {
                eprintln!("unmatched rsp request_id {request_id}");
            }
        }
    }
}
