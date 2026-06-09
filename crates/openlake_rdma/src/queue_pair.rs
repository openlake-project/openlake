use std::sync::Arc;

use crate::backend::Fabric;
use crate::completion::CompletionQueue;
use crate::work::WorkRequest;
use crate::{Result, TransportError};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TransportType {
    ReliableConnected,
    UnreliableDatagram,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum QpState {
    Reset,
    Init,
    ReadyToReceive,
    ReadyToSend,
    Error,
}

impl QpState {
    fn label(self) -> &'static str {
        match self {
            QpState::Reset => "reset",
            QpState::Init => "init",
            QpState::ReadyToReceive => "ready_to_receive",
            QpState::ReadyToSend => "ready_to_send",
            QpState::Error => "error",
        }
    }

    fn may_advance_to(self, target: QpState) -> bool {
        if target == QpState::Error {
            return true;
        }
        matches!(
            (self, target),
            (QpState::Reset, QpState::Init)
                | (QpState::Init, QpState::ReadyToReceive)
                | (QpState::ReadyToReceive, QpState::ReadyToSend)
        )
    }
}

pub struct QueuePair {
    fabric: Arc<dyn Fabric>,
    completion_queue: Arc<CompletionQueue>,
    transport: TransportType,
    state: QpState,
    posted: u64,
}

impl QueuePair {
    pub fn new(
        fabric: Arc<dyn Fabric>,
        completion_queue: Arc<CompletionQueue>,
        transport: TransportType,
    ) -> Self {
        QueuePair {
            fabric,
            completion_queue,
            transport,
            state: QpState::Reset,
            posted: 0,
        }
    }

    pub fn state(&self) -> QpState {
        self.state
    }

    pub fn transport(&self) -> TransportType {
        self.transport
    }

    pub fn posted_work_requests(&self) -> u64 {
        self.posted
    }

    pub fn modify_state(&mut self, target: QpState) -> Result<()> {
        if !self.state.may_advance_to(target) {
            return Err(TransportError::InvalidStateTransition {
                from: self.state.label(),
                to: target.label(),
            });
        }
        self.state = target;
        Ok(())
    }

    pub fn transition_to_ready(&mut self) -> Result<()> {
        self.modify_state(QpState::Init)?;
        self.modify_state(QpState::ReadyToReceive)?;
        self.modify_state(QpState::ReadyToSend)
    }

    pub fn post_send(&mut self, request: WorkRequest) -> Result<()> {
        if self.state != QpState::ReadyToSend {
            return Err(TransportError::QueuePairNotReady);
        }
        let completion = self.fabric.execute(&request)?;
        self.completion_queue.push(completion)?;
        self.posted += 1;
        Ok(())
    }
}
