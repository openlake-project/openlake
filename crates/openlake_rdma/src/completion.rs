use std::collections::VecDeque;
use std::sync::Mutex;

use crate::work::Opcode;
use crate::{Result, TransportError};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CompletionStatus {
    Success,
    RemoteAccessError,
    LocalProtectionError,
}

#[derive(Clone, Copy, Debug)]
pub struct WorkCompletion {
    pub wr_id: u64,
    pub opcode: Opcode,
    pub status: CompletionStatus,
    pub byte_len: usize,
}

pub struct CompletionQueue {
    depth: usize,
    entries: Mutex<VecDeque<WorkCompletion>>,
}

impl CompletionQueue {
    pub fn new(depth: usize) -> Self {
        CompletionQueue {
            depth,
            entries: Mutex::new(VecDeque::with_capacity(depth)),
        }
    }

    pub fn depth(&self) -> usize {
        self.depth
    }

    pub(crate) fn push(&self, completion: WorkCompletion) -> Result<()> {
        let mut entries = self.entries.lock().unwrap();
        if entries.len() >= self.depth {
            return Err(TransportError::CompletionQueueOverrun { depth: self.depth });
        }
        entries.push_back(completion);
        Ok(())
    }

    pub fn poll(&self, max: usize) -> Vec<WorkCompletion> {
        let mut entries = self.entries.lock().unwrap();
        let count = max.min(entries.len());
        entries.drain(..count).collect()
    }

    pub fn pending(&self) -> usize {
        self.entries.lock().unwrap().len()
    }
}
