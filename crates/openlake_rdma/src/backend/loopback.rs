use std::sync::Arc;

use super::Fabric;
use crate::completion::{CompletionStatus, WorkCompletion};
use crate::memory::{AccessFlags, ProtectionDomain, Registry};
use crate::work::{Opcode, WorkRequest};
use crate::{Result, TransportError};

pub struct SoftFabric {
    registry: Arc<Registry>,
}

impl SoftFabric {
    pub fn new() -> Self {
        SoftFabric {
            registry: Arc::new(Registry::new()),
        }
    }

    pub fn allocate_protection_domain(&self) -> ProtectionDomain {
        ProtectionDomain::new(self.registry.clone())
    }
}

impl Default for SoftFabric {
    fn default() -> Self {
        SoftFabric::new()
    }
}

impl Fabric for SoftFabric {
    fn name(&self) -> &'static str {
        "soft-roce"
    }

    fn execute(&self, request: &WorkRequest) -> Result<WorkCompletion> {
        let gather_length = request.gather_length();
        let remote = self
            .registry
            .lookup(request.rkey)
            .ok_or(TransportError::UnknownRemoteKey(request.rkey))?;

        let span_end = request.remote_addr as usize + gather_length;
        let remote_len = remote.bytes.lock().unwrap().len();

        let required = match request.opcode {
            Opcode::RdmaWrite => AccessFlags::REMOTE_WRITE,
            Opcode::RdmaRead => AccessFlags::REMOTE_READ,
        };
        if !remote.access.contains(required) || span_end > remote_len {
            return Ok(WorkCompletion {
                wr_id: request.wr_id,
                opcode: request.opcode,
                status: CompletionStatus::RemoteAccessError,
                byte_len: 0,
            });
        }

        let status = match request.opcode {
            Opcode::RdmaWrite => self.gather_then_place(request, &remote)?,
            Opcode::RdmaRead => self.fetch_then_scatter(request, &remote)?,
        };

        Ok(WorkCompletion {
            wr_id: request.wr_id,
            opcode: request.opcode,
            status,
            byte_len: if status == CompletionStatus::Success {
                gather_length
            } else {
                0
            },
        })
    }
}

impl SoftFabric {
    fn gather_then_place(
        &self,
        request: &WorkRequest,
        remote: &crate::memory::RegisteredBuffer,
    ) -> Result<CompletionStatus> {
        let mut staging = Vec::with_capacity(request.gather_length());
        for entry in &request.local {
            let local = self
                .registry
                .lookup(entry.lkey)
                .ok_or(TransportError::UnknownLocalKey(entry.lkey))?;
            let guard = local.bytes.lock().unwrap();
            let start = entry.addr as usize;
            let end = start + entry.length;
            if end > guard.len() {
                return Ok(CompletionStatus::LocalProtectionError);
            }
            staging.extend_from_slice(&guard[start..end]);
        }

        let mut target = remote.bytes.lock().unwrap();
        let offset = request.remote_addr as usize;
        target[offset..offset + staging.len()].copy_from_slice(&staging);
        Ok(CompletionStatus::Success)
    }

    fn fetch_then_scatter(
        &self,
        request: &WorkRequest,
        remote: &crate::memory::RegisteredBuffer,
    ) -> Result<CompletionStatus> {
        let source = remote.bytes.lock().unwrap();
        let mut cursor = request.remote_addr as usize;
        for entry in &request.local {
            let local = self
                .registry
                .lookup(entry.lkey)
                .ok_or(TransportError::UnknownLocalKey(entry.lkey))?;
            let mut guard = local.bytes.lock().unwrap();
            let start = entry.addr as usize;
            let end = start + entry.length;
            if end > guard.len() {
                return Ok(CompletionStatus::LocalProtectionError);
            }
            guard[start..end].copy_from_slice(&source[cursor..cursor + entry.length]);
            cursor += entry.length;
        }
        Ok(CompletionStatus::Success)
    }
}
