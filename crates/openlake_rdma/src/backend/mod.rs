use crate::completion::WorkCompletion;
use crate::work::WorkRequest;
use crate::Result;

pub mod loopback;

#[cfg(all(target_os = "linux", feature = "rdma"))]
pub mod verbs;

pub trait Fabric: Send + Sync {
    fn name(&self) -> &'static str;
    fn execute(&self, request: &WorkRequest) -> Result<WorkCompletion>;
}
