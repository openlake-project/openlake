use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    UnknownRemoteKey(u32),
    UnknownLocalKey(u32),
    RemoteAccessViolation {
        rkey: u32,
        requested: usize,
        region_len: usize,
    },
    LocalLengthMismatch {
        lkey: u32,
        requested: usize,
        region_len: usize,
    },
    InvalidStateTransition {
        from: &'static str,
        to: &'static str,
    },
    QueuePairNotReady,
    CompletionQueueOverrun {
        depth: usize,
    },
    BackendUnavailable(&'static str),
}

impl fmt::Display for TransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportError::UnknownRemoteKey(key) => {
                write!(formatter, "no memory region registered for rkey {key}")
            }
            TransportError::UnknownLocalKey(key) => {
                write!(formatter, "no memory region registered for lkey {key}")
            }
            TransportError::RemoteAccessViolation { rkey, requested, region_len } => write!(
                formatter,
                "remote write of {requested} bytes overruns region rkey {rkey} of {region_len} bytes"
            ),
            TransportError::LocalLengthMismatch { lkey, requested, region_len } => write!(
                formatter,
                "local gather of {requested} bytes overruns region lkey {lkey} of {region_len} bytes"
            ),
            TransportError::InvalidStateTransition { from, to } => {
                write!(formatter, "illegal queue pair transition from {from} to {to}")
            }
            TransportError::QueuePairNotReady => {
                write!(formatter, "queue pair must reach the ready to send state before posting work")
            }
            TransportError::CompletionQueueOverrun { depth } => {
                write!(formatter, "completion queue of depth {depth} is full")
            }
            TransportError::BackendUnavailable(reason) => {
                write!(formatter, "transport backend unavailable, {reason}")
            }
        }
    }
}

impl std::error::Error for TransportError {}
