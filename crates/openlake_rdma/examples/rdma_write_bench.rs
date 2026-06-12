use std::sync::Arc;
use std::time::Instant;

use openlake_rdma::{
    AccessFlags, BufferKind, CompletionQueue, CompletionStatus, Fabric, QueuePair, SoftFabric,
    TransportType, WorkRequest,
};

fn drain(completion_queue: &CompletionQueue) -> u64 {
    let mut succeeded = 0;
    loop {
        let batch = completion_queue.poll(64);
        if batch.is_empty() {
            break;
        }
        for completion in batch {
            if completion.status == CompletionStatus::Success {
                succeeded += 1;
            }
        }
    }
    succeeded
}

fn main() {
    let mut arguments = std::env::args().skip(1);
    let payload_bytes: usize = arguments
        .next()
        .and_then(|value| value.parse().ok())
        .unwrap_or(1 << 20);
    let iterations: u64 = arguments
        .next()
        .and_then(|value| value.parse().ok())
        .unwrap_or(4096);

    let soft = SoftFabric::new();
    let protection_domain = soft.allocate_protection_domain();
    let source = protection_domain.register_region(payload_bytes, AccessFlags::LOCAL_WRITE);
    let sink = protection_domain.register_device_region(payload_bytes, AccessFlags::REMOTE_WRITE);
    source.fill(0xa5);

    let remote_addr = sink.remote_addr();
    let rkey = sink.rkey();
    let scatter_gather = source.scatter_gather(0, payload_bytes);
    let path = match sink.kind() {
        BufferKind::DeviceResident => "nic to gpu device memory",
        BufferKind::HostPinned => "nic to host pinned memory",
    };

    let fabric: Arc<dyn Fabric> = Arc::new(soft);
    let completion_queue = Arc::new(CompletionQueue::new(256));
    let mut queue_pair = QueuePair::new(
        fabric.clone(),
        completion_queue.clone(),
        TransportType::ReliableConnected,
    );
    queue_pair.transition_to_ready().unwrap();

    let inflight_limit = 64;
    let mut completed = 0u64;
    let start = Instant::now();
    for work_request_id in 0..iterations {
        let request = WorkRequest::rdma_write(work_request_id, scatter_gather, remote_addr, rkey);
        queue_pair.post_send(request).unwrap();
        if completion_queue.pending() >= inflight_limit {
            completed += drain(&completion_queue);
        }
    }
    completed += drain(&completion_queue);
    let elapsed = start.elapsed().as_secs_f64();

    let moved_bytes = payload_bytes as f64 * iterations as f64;
    let gibps = moved_bytes / elapsed / (1024.0 * 1024.0 * 1024.0);
    let message_rate = iterations as f64 / elapsed;

    println!("backend {}", fabric.name());
    println!("transport reliable connected");
    println!("path {path}");
    println!("payload bytes {payload_bytes}");
    println!("iterations {iterations}");
    println!("posted work requests {}", queue_pair.posted_work_requests());
    println!("successful completions {completed}");
    println!("elapsed seconds {elapsed:.6}");
    println!("throughput gibibytes per second {gibps:.3}");
    println!("message rate per second {message_rate:.0}");
    println!("source checksum {:#018x}", source.checksum());
    println!("sink checksum {:#018x}", sink.checksum());
}
