fn main() -> anyhow::Result<()> {
    #[cfg(all(feature = "rdma", target_os = "linux"))]
    { linux::entry() }
    #[cfg(not(all(feature = "rdma", target_os = "linux")))]
    {
        eprintln!("rdma_loopback requires Linux with --features rdma; not building target body on this platform");
        Ok(())
    }
}

#[cfg(all(feature = "rdma", target_os = "linux"))]
mod linux {
    use std::rc::Rc;

    use anyhow::Context;
    use futures::stream::StreamExt;

    use phenomenal_io::rdma::{
        PeerEndpoint, RdmaConfig, RdmaNode, RdmaQos, RawAddressHandle, BUF_SIZE,
    };
    use phenomenal_io::rdma_backend::{Envelope, RdmaBackend, ENVELOPE_MAGIC};
    use phenomenal_io::rpc::{decode, encode, RdmaRemoteBuf, Request, Response, WireError};
    use phenomenal_io::stream::ByteStream;
    use phenomenal_io::{IoError, LocalFsBackend, StorageBackend};

    const DEFAULT_RDMA_DEVICE:           &str = "mlx5_0";
    const DEFAULT_OBJECT_SIZE_BYTES:     usize = 1024 * 1024;
    const DEFAULT_ITERATION_COUNT:       usize = 1;
    const BULK_BUFFER_SIZE_BYTES:        usize = 4 * 1024 * 1024;
    const BULK_POOL_CAPACITY:            usize = 8;
    const LOOPBACK_VOLUME_NAME:          &str = "loopback-volume";
    const LOOPBACK_OBJECT_PATH:          &str = "loopback-object/data";
    const LOOPBACK_DISK_SUBDIRECTORY:    &str = "openlake-rdma-loopback";
    const DC_ACCESS_KEY:                 u64  = 0xdeadbeef_cafef00d;
    const SELF_NODE_ID:                  u16  = 0;
    const LOCAL_DISK_INDEX:              u16  = 0;
    const ENV_RDMA_DEVICE:               &str = "OPENLAKE_RDMA_DEVICE";
    const ENV_OBJECT_SIZE_BYTES:         &str = "OPENLAKE_OBJECT_SIZE_BYTES";
    const ENV_ITERATION_COUNT:           &str = "OPENLAKE_ITERATION_COUNT";

    pub fn entry() -> anyhow::Result<()> {
        tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .init();

        let runtime = compio::runtime::RuntimeBuilder::new().build()?;
        runtime.block_on(async move {
            if let Err(error) = run_loopback_probe().await {
                eprintln!("rdma_loopback: FAILED: {error:#}");
                std::process::exit(1);
            }
        });
        Ok(())
    }

    async fn run_loopback_probe() -> anyhow::Result<()> {
        let object_size_bytes: usize = std::env::var(ENV_OBJECT_SIZE_BYTES)
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(DEFAULT_OBJECT_SIZE_BYTES);
        let iteration_count: usize = std::env::var(ENV_ITERATION_COUNT)
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(DEFAULT_ITERATION_COUNT);

        let local_disk_root = std::env::temp_dir().join(LOOPBACK_DISK_SUBDIRECTORY);
        let _ = std::fs::remove_dir_all(&local_disk_root);
        std::fs::create_dir_all(&local_disk_root)?;

        let local_storage_backend: Rc<dyn StorageBackend> =
            Rc::new(LocalFsBackend::new(&local_disk_root)?);
        local_storage_backend.make_vol(LOOPBACK_VOLUME_NAME).await?;
        eprintln!(
            "rdma_loopback: prepared local disk root at {}",
            local_disk_root.display(),
        );

        let mut payload = vec![0u8; object_size_bytes];
        for (index, byte) in payload.iter_mut().enumerate() {
            *byte = (index.wrapping_mul(2654435761) & 0xFF) as u8;
        }
        local_storage_backend
            .write_file(LOOPBACK_VOLUME_NAME, LOOPBACK_OBJECT_PATH, payload.clone())
            .await
            .context("write_file")?;
        eprintln!(
            "rdma_loopback: wrote object {}/{} ({} bytes)",
            LOOPBACK_VOLUME_NAME, LOOPBACK_OBJECT_PATH, object_size_bytes,
        );

        let rdma_device = std::env::var(ENV_RDMA_DEVICE)
            .unwrap_or_else(|_| DEFAULT_RDMA_DEVICE.to_string());

        let rdma_node = Rc::new(
            RdmaNode::start(RdmaConfig {
                self_node_id:  SELF_NODE_ID,
                dev_name:      rdma_device.clone(),
                dc_key:        DC_ACCESS_KEY,
                qos:           RdmaQos { traffic_class: 0, service_level: 0 },
                peers: vec![PeerEndpoint {
                    node_id: SELF_NODE_ID,
                    gid:     [0u8; 16],
                    dct_num: 0,
                    dc_key:  0,
                }],
                bulk_buf_size: BULK_BUFFER_SIZE_BYTES,
                bulk_pool_cap: BULK_POOL_CAPACITY,
            })
            .context("RdmaNode::start")?,
        );
        eprintln!(
            "rdma_loopback: RdmaNode started on device {} (self_dct_num={}, gid={:02x?})",
            rdma_device,
            rdma_node.sock.self_dct_identifier(),
            rdma_node.dev.gid_bytes(),
        );

        let local_disks: Rc<Vec<Rc<dyn StorageBackend>>> =
            Rc::new(vec![local_storage_backend.clone()]);

        let dispatcher_task = compio::runtime::spawn({
            let rdma_node   = rdma_node.clone();
            let local_disks = local_disks.clone();
            async move {
                if let Err(error) = run_dispatcher_loop(rdma_node, local_disks).await {
                    eprintln!("rdma_loopback: dispatcher exited with error: {error:#}");
                }
            }
        });

        let rdma_backend = RdmaBackend::new(
            rdma_node.clone(),
            SELF_NODE_ID,
            LOCAL_DISK_INDEX,
            local_storage_backend.clone(),
        );

        eprintln!("rdma_loopback: [1/2] StatVol over RDMA loopback ...");
        let volume_info = rdma_backend.stat_vol(LOOPBACK_VOLUME_NAME).await?;
        eprintln!("rdma_loopback:        StatVol succeeded: {volume_info:?}");

        eprintln!(
            "rdma_loopback: [2/2] ReadFileChunk over RDMA loopback ({} iterations, {} bytes each) ...",
            iteration_count, object_size_bytes,
        );

        {
            let mut stream = rdma_backend
                .read_file_stream(LOOPBACK_VOLUME_NAME, LOOPBACK_OBJECT_PATH, 0, object_size_bytes as u64)
                .await?;
            let mut received: Vec<u8> = Vec::with_capacity(object_size_bytes);
            loop {
                let chunk = stream.read().await?;
                if chunk.is_empty() { break; }
                received.extend_from_slice(&chunk[..]);
            }
            if received != payload {
                let bad_offset = received
                    .iter()
                    .zip(payload.iter())
                    .position(|(actual, expected)| actual != expected)
                    .unwrap_or(0);
                anyhow::bail!("content mismatch at offset {bad_offset}");
            }
        }

        let started_at = std::time::Instant::now();
        let mut bytes_transferred_total: u64 = 0;
        for _ in 0..iteration_count {
            let mut stream = rdma_backend
                .read_file_stream(LOOPBACK_VOLUME_NAME, LOOPBACK_OBJECT_PATH, 0, object_size_bytes as u64)
                .await?;
            loop {
                let chunk = stream.read().await?;
                if chunk.is_empty() { break; }
                bytes_transferred_total += chunk.len() as u64;
            }
        }
        let elapsed_seconds   = started_at.elapsed().as_secs_f64();
        let bytes_per_second  = (bytes_transferred_total as f64) / elapsed_seconds;
        let gibibytes_per_sec = bytes_per_second / (1024.0 * 1024.0 * 1024.0);
        let gigabits_per_sec  = (bytes_per_second * 8.0) / 1.0e9;
        eprintln!(
            "rdma_loopback:        ReadFileChunk succeeded: {} iterations, {} bytes in {:.3}s",
            iteration_count, bytes_transferred_total, elapsed_seconds,
        );
        eprintln!(
            "rdma_loopback:        throughput: {:.3} GiB/s ({:.2} Gbps wire)",
            gibibytes_per_sec, gigabits_per_sec,
        );

        drop(dispatcher_task);
        Ok(())
    }

    async fn run_dispatcher_loop(
        rdma_node:   Rc<RdmaNode>,
        local_disks: Rc<Vec<Rc<dyn StorageBackend>>>,
    ) -> anyhow::Result<()> {
        let mut completion_signal = rdma_node
            .pump
            .take_recv_rx()
            .ok_or_else(|| anyhow::anyhow!("recv_rx already taken from CqPump"))?;
        let mut envelope_buffer = Vec::with_capacity(BUF_SIZE);

        loop {
            loop {
                envelope_buffer.clear();
                if rdma_node.sock.attempt_singular_rcv(&mut envelope_buffer).is_none() {
                    break;
                }
                handle_received_envelope(&rdma_node, &local_disks, &envelope_buffer).await;
            }
            if completion_signal.next().await.is_none() {
                return Ok(());
            }
        }
    }

    async fn handle_received_envelope(
        rdma_node:     &Rc<RdmaNode>,
        local_disks:   &Rc<Vec<Rc<dyn StorageBackend>>>,
        encoded_bytes: &[u8],
    ) {
        let envelope: Envelope = match decode(encoded_bytes) {
            Ok(envelope) => envelope,
            Err(error)   => {
                eprintln!("rdma_loopback: failed to decode envelope: {error}");
                return;
            }
        };

        match envelope {
            Envelope::Req { magic, from_node_id, request_id, payload } => {
                if magic != ENVELOPE_MAGIC {
                    eprintln!("rdma_loopback: rejected request envelope with bad magic {magic:#x}");
                    return;
                }
                let peer_endpoint = match rdma_node.peer(from_node_id) {
                    Some(peer) => peer.clone(),
                    None => {
                        eprintln!("rdma_loopback: unknown sender node_id {from_node_id}");
                        return;
                    }
                };
                let address_handle = match rdma_node.ah_cache.get_or_create(&peer_endpoint) {
                    Ok(handle) => handle,
                    Err(error) => {
                        eprintln!(
                            "rdma_loopback: failed to resolve address handle for peer {from_node_id}: {error}",
                        );
                        return;
                    }
                };

                let response = match payload {
                    Request::StatVol { disk_idx, volume } => {
                        match local_disks.get(disk_idx as usize) {
                            Some(disk) => match disk.stat_vol(&volume).await {
                                Ok(info)   => Response::Vol(info),
                                Err(error) => Response::Err(error.into()),
                            },
                            None => Response::Err(WireError::from(IoError::Io(
                                std::io::Error::other(format!("disk_idx {disk_idx} out of range")),
                            ))),
                        }
                    }
                    Request::ReadFileChunk { disk_idx, volume, path, offset, length, target } => {
                        handle_read_file_chunk(
                            rdma_node,
                            local_disks,
                            address_handle,
                            peer_endpoint.dct_num,
                            peer_endpoint.dc_key,
                            disk_idx,
                            volume,
                            path,
                            offset,
                            length,
                            target,
                        )
                        .await
                    }
                    other => {
                        eprintln!(
                            "rdma_loopback: dispatcher does not support request variant {other:?}",
                        );
                        return;
                    }
                };

                let encoded_response = match encode(&Envelope::Rsp {
                    magic: ENVELOPE_MAGIC,
                    request_id,
                    payload: response,
                }) {
                    Ok(encoded) => encoded,
                    Err(error)  => {
                        eprintln!("rdma_loopback: failed to encode response: {error}");
                        return;
                    }
                };

                if let Err(error) = rdma_node.sock.send(
                    &encoded_response,
                    address_handle,
                    peer_endpoint.dct_num,
                    peer_endpoint.dc_key,
                ) {
                    eprintln!("rdma_loopback: failed to send response: {error}");
                }
            }
            Envelope::Rsp { magic, request_id, payload } => {
                if magic != ENVELOPE_MAGIC {
                    eprintln!("rdma_loopback: rejected response envelope with bad magic {magic:#x}");
                    return;
                }
                if let Some(sender) = rdma_node
                    .pending_responses
                    .borrow_mut()
                    .remove(&request_id)
                {
                    let _ = sender.send(payload);
                } else {
                    eprintln!(
                        "rdma_loopback: received response for unknown request_id {request_id}",
                    );
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_read_file_chunk(
        rdma_node:     &Rc<RdmaNode>,
        local_disks:   &Rc<Vec<Rc<dyn StorageBackend>>>,
        sender_ah:     RawAddressHandle,
        peer_dct_num:  u32,
        peer_dc_key:   u64,
        disk_idx:      u16,
        volume:        String,
        path:          String,
        offset:        u64,
        length:        u32,
        target:        RdmaRemoteBuf,
    ) -> Response {
        let server_buffer_size = rdma_node.bulk_pool.buf_size();
        if length as usize > server_buffer_size {
            return Response::Err(WireError::Other(format!(
                "read_file_chunk length {length} exceeds server bulk_buf_size {server_buffer_size}",
            )));
        }
        if length > target.len {
            return Response::Err(WireError::Other(format!(
                "read_file_chunk length {length} exceeds client target.len {}",
                target.len,
            )));
        }

        let disk = match local_disks.get(disk_idx as usize) {
            Some(disk) => disk.clone(),
            None => {
                return Response::Err(WireError::from(IoError::Io(std::io::Error::other(
                    format!("disk_idx {disk_idx} out of range"),
                ))));
            }
        };

        let mut bounce_buffer = match rdma_node.bulk_pool.acquire().await {
            Ok(buffer) => buffer,
            Err(error) => return Response::Err(IoError::Io(error).into()),
        };

        let bytes_filled = {
            let mut stream = match disk.read_file_stream(&volume, &path, offset, length as u64).await {
                Ok(stream) => stream,
                Err(error) => return Response::Err(error.into()),
            };
            let destination_slice = &mut bounce_buffer.as_slice_mut()[..length as usize];
            match stream.read_buffer(destination_slice).await {
                Ok(count)  => count,
                Err(error) => return Response::Err(error.into()),
            }
        };

        if bytes_filled == 0 {
            return Response::ChunkReady { bytes_written: 0 };
        }

        if let Err(error) = rdma_node.sock.rdma_write(
            bounce_buffer.addr(),
            bytes_filled as u32,
            bounce_buffer.lkey(),
            target.addr,
            target.rkey,
            sender_ah,
            peer_dct_num,
            peer_dc_key,
        ).await {
            return Response::Err(IoError::Io(error).into());
        }

        Response::ChunkReady { bytes_written: bytes_filled as u32 }
    }
}
