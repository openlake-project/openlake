#[derive(Debug, Default, Clone)]
pub struct Stats {}

pub trait Managed {
    fn shutdown(&self) {}
    fn stats(&self) -> Stats {
        Stats::default()
    }
}

impl Managed for crate::engine::Engine {}

#[cfg(all(feature = "rdma", target_os = "linux"))]
impl Managed for crate::kv_engine::KvEngine {}
