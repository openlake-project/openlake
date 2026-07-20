use std::sync::mpsc;

pub type Scatter = Vec<(u64, u64)>;
pub type Waiter = mpsc::Receiver<Result<Vec<i32>, String>>;

pub trait Protocol: Send + Sync {
    fn attach(&self, addr: &str, node_id: u16) -> Result<usize, String>;
    fn register_memory(&self, addr: u64, len: u64) -> Result<(), String>;
    fn exists(&self, node: u16, keys: &[Vec<u8>]) -> Result<Waiter, String>;
    fn put(&self, node: u16, keys: &[Vec<u8>], scatters: &[Scatter]) -> Result<Waiter, String>;
    fn get(&self, node: u16, keys: &[Vec<u8>], scatters: &[Scatter]) -> Result<Waiter, String>;
    fn reset(&self, node: u16) -> Result<(), String>;
    fn close(&mut self);
}
