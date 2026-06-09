use std::sync::Arc;

use openlake_rdma::{
    AccessFlags, CompletionQueue, CompletionStatus, Fabric, Opcode, QpState, QueuePair, SoftFabric,
    TransportError, TransportType, WorkRequest,
};

fn ready_pair(fabric: Arc<dyn Fabric>) -> (QueuePair, Arc<CompletionQueue>) {
    let completion_queue = Arc::new(CompletionQueue::new(64));
    let mut queue_pair = QueuePair::new(
        fabric,
        completion_queue.clone(),
        TransportType::ReliableConnected,
    );
    queue_pair.transition_to_ready().unwrap();
    (queue_pair, completion_queue)
}

#[test]
fn rdma_write_places_payload_in_remote_region() {
    let soft = SoftFabric::new();
    let protection_domain = soft.allocate_protection_domain();
    let source = protection_domain.register_region(8192, AccessFlags::LOCAL_WRITE);
    let sink = protection_domain.register_device_region(8192, AccessFlags::REMOTE_WRITE);
    source.fill(0x5c);

    let scatter_gather = source.scatter_gather(0, 8192);
    let remote_addr = sink.remote_addr();
    let rkey = sink.rkey();

    let fabric: Arc<dyn Fabric> = Arc::new(soft);
    let (mut queue_pair, completion_queue) = ready_pair(fabric);

    queue_pair
        .post_send(WorkRequest::rdma_write(7, scatter_gather, remote_addr, rkey))
        .unwrap();

    let completions = completion_queue.poll(8);
    assert_eq!(completions.len(), 1);
    assert_eq!(completions[0].wr_id, 7);
    assert_eq!(completions[0].opcode, Opcode::RdmaWrite);
    assert_eq!(completions[0].status, CompletionStatus::Success);
    assert_eq!(completions[0].byte_len, 8192);
    assert_eq!(source.checksum(), sink.checksum());
}

#[test]
fn rdma_read_pulls_remote_region_into_local() {
    let soft = SoftFabric::new();
    let protection_domain = soft.allocate_protection_domain();
    let local = protection_domain.register_region(4096, AccessFlags::LOCAL_WRITE);
    let remote = protection_domain.register_region(4096, AccessFlags::REMOTE_READ);
    remote.write_at(0, &vec![0x3a; 4096]).unwrap();

    let scatter_gather = local.scatter_gather(0, 4096);
    let remote_addr = remote.remote_addr();
    let rkey = remote.rkey();

    let fabric: Arc<dyn Fabric> = Arc::new(soft);
    let (mut queue_pair, completion_queue) = ready_pair(fabric);

    queue_pair
        .post_send(WorkRequest::rdma_read(11, scatter_gather, remote_addr, rkey))
        .unwrap();

    let completions = completion_queue.poll(8);
    assert_eq!(completions[0].status, CompletionStatus::Success);
    assert_eq!(local.checksum(), remote.checksum());
}

#[test]
fn write_without_remote_permission_reports_access_error() {
    let soft = SoftFabric::new();
    let protection_domain = soft.allocate_protection_domain();
    let source = protection_domain.register_region(1024, AccessFlags::LOCAL_WRITE);
    let sink = protection_domain.register_region(1024, AccessFlags::none());

    let scatter_gather = source.scatter_gather(0, 1024);
    let remote_addr = sink.remote_addr();
    let rkey = sink.rkey();

    let fabric: Arc<dyn Fabric> = Arc::new(soft);
    let (mut queue_pair, completion_queue) = ready_pair(fabric);

    queue_pair
        .post_send(WorkRequest::rdma_write(1, scatter_gather, remote_addr, rkey))
        .unwrap();

    let completions = completion_queue.poll(8);
    assert_eq!(completions[0].status, CompletionStatus::RemoteAccessError);
    assert_eq!(completions[0].byte_len, 0);
}

#[test]
fn posting_before_ready_to_send_is_rejected() {
    let soft = SoftFabric::new();
    let protection_domain = soft.allocate_protection_domain();
    let source = protection_domain.register_region(64, AccessFlags::LOCAL_WRITE);
    let sink = protection_domain.register_region(64, AccessFlags::REMOTE_WRITE);
    let scatter_gather = source.scatter_gather(0, 64);
    let remote_addr = sink.remote_addr();
    let rkey = sink.rkey();

    let completion_queue = Arc::new(CompletionQueue::new(8));
    let fabric: Arc<dyn Fabric> = Arc::new(soft);
    let mut queue_pair = QueuePair::new(fabric, completion_queue, TransportType::ReliableConnected);

    let outcome =
        queue_pair.post_send(WorkRequest::rdma_write(1, scatter_gather, remote_addr, rkey));
    assert_eq!(outcome, Err(TransportError::QueuePairNotReady));
}

#[test]
fn skipping_a_state_is_an_invalid_transition() {
    let soft = SoftFabric::new();
    let completion_queue = Arc::new(CompletionQueue::new(8));
    let fabric: Arc<dyn Fabric> = Arc::new(soft);
    let mut queue_pair = QueuePair::new(fabric, completion_queue, TransportType::ReliableConnected);

    let outcome = queue_pair.modify_state(QpState::ReadyToSend);
    assert!(matches!(
        outcome,
        Err(TransportError::InvalidStateTransition { .. })
    ));
}
