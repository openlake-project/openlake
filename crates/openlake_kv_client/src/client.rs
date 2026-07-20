use std::sync::Mutex;

use openlake_io::rpc::{CLIENT_NODE_ID_BASE, CLIENT_NODE_ID_MAX};
use xxhash_rust::xxh64::xxh64;

use crate::transport::{Protocol, Scatter, Waiter};

pub trait KvClient: Send + Sync {
    fn attach(&self, addr: &str, node_id: u16) -> Result<usize, String>;
    fn register_memory(&self, addr: u64, len: u64) -> Result<(), String>;
    fn batch_is_exist(&self, keys: &[Vec<u8>]) -> Result<Vec<i32>, String>;
    fn put_batch(
        &self,
        keys: &[Vec<u8>],
        addrs: &[Vec<u64>],
        sizes: &[Vec<u64>],
    ) -> Result<Vec<i32>, String>;
    fn get_batch(
        &self,
        keys: &[Vec<u8>],
        addrs: &[Vec<u64>],
        sizes: &[Vec<u64>],
    ) -> Result<Vec<i32>, String>;
    fn reset(&self) -> Result<(), String>;
    fn close(&mut self);
    fn client_id(&self) -> u16;
}

pub struct StoreClient {
    proto: Box<dyn Protocol>,
    nodes: Mutex<Vec<u16>>,
    client_id: u16,
}

impl StoreClient {
    pub fn new(proto: Box<dyn Protocol>, client_id: u16) -> Result<Self, String> {
        if !(CLIENT_NODE_ID_BASE..=CLIENT_NODE_ID_MAX).contains(&client_id) {
            return Err(format!(
                "client_id {client_id} outside [{CLIENT_NODE_ID_BASE}, {CLIENT_NODE_ID_MAX}]"
            ));
        }
        Ok(Self {
            proto,
            nodes: Mutex::new(Vec::new()),
            client_id,
        })
    }

    fn owners(&self, keys: &[Vec<u8>]) -> Result<(Vec<u16>, Vec<Vec<usize>>), String> {
        let nodes = self.nodes.lock().unwrap();
        if nodes.is_empty() {
            return Err("no nodes attached".into());
        }
        let mut groups: Vec<Vec<usize>> = vec![Vec::new(); nodes.len()];
        for (i, key) in keys.iter().enumerate() {
            groups[(xxh64(key, 0) % nodes.len() as u64) as usize].push(i);
        }
        Ok((nodes.clone(), groups))
    }

    fn sharded<F>(
        &self,
        keys: &[Vec<u8>],
        scatters: Option<&[Scatter]>,
        op: F,
    ) -> Result<Vec<i32>, String>
    where
        F: Fn(&dyn Protocol, u16, &[Vec<u8>], &[Scatter]) -> Result<Waiter, String>,
    {
        let (nodes, groups) = self.owners(keys)?;
        let mut out = vec![0i32; keys.len()];
        let mut pending: Vec<(u16, &Vec<usize>, Waiter)> = Vec::with_capacity(groups.len());
        for (g, idxs) in groups.iter().enumerate() {
            if idxs.is_empty() {
                continue;
            }
            let node_keys: Vec<Vec<u8>> = idxs.iter().map(|&i| keys[i].clone()).collect();
            let node_scatters: Vec<Scatter> = match scatters {
                Some(s) => idxs.iter().map(|&i| s[i].clone()).collect(),
                None => Vec::new(),
            };
            pending.push((
                nodes[g],
                idxs,
                op(self.proto.as_ref(), nodes[g], &node_keys, &node_scatters)?,
            ));
        }
        let mut first_err = None;
        for (node, idxs, wait) in pending {
            match wait.recv().map_err(|_| "client thread died".to_string())? {
                Ok(results) if results.len() == idxs.len() => {
                    for (&i, r) in idxs.iter().zip(results) {
                        out[i] = r;
                    }
                }
                Ok(results) => {
                    first_err.get_or_insert(format!(
                        "node {node}: {} results for {} keys",
                        results.len(),
                        idxs.len()
                    ));
                }
                Err(e) => {
                    first_err.get_or_insert(e);
                }
            }
        }
        match first_err {
            Some(e) => Err(e),
            None => Ok(out),
        }
    }

    fn zip_scatters(addrs: &[Vec<u64>], sizes: &[Vec<u64>]) -> Vec<Scatter> {
        addrs
            .iter()
            .zip(sizes)
            .map(|(a, s)| a.iter().copied().zip(s.iter().copied()).collect())
            .collect()
    }

    fn validate(keys: &[Vec<u8>], addrs: &[Vec<u64>], sizes: &[Vec<u64>]) -> Result<(), String> {
        if keys.len() != addrs.len() || addrs.len() != sizes.len() {
            return Err(format!(
                "mismatched batch: {} keys, {} addr lists, {} size lists",
                keys.len(),
                addrs.len(),
                sizes.len()
            ));
        }
        for (i, (a, s)) in addrs.iter().zip(sizes).enumerate() {
            if a.len() != s.len() {
                return Err(format!("key {i}: {} addrs but {} sizes", a.len(), s.len()));
            }
        }
        Ok(())
    }
}

impl KvClient for StoreClient {
    fn attach(&self, addr: &str, node_id: u16) -> Result<usize, String> {
        let n = self.proto.attach(addr, node_id)?;
        let mut nodes = self.nodes.lock().unwrap();
        if !nodes.contains(&node_id) {
            nodes.push(node_id);
        }
        Ok(n)
    }

    fn register_memory(&self, addr: u64, len: u64) -> Result<(), String> {
        self.proto.register_memory(addr, len)
    }

    fn batch_is_exist(&self, keys: &[Vec<u8>]) -> Result<Vec<i32>, String> {
        self.sharded(keys, None, |p, node, keys, _| p.exists(node, keys))
    }

    fn put_batch(
        &self,
        keys: &[Vec<u8>],
        addrs: &[Vec<u64>],
        sizes: &[Vec<u64>],
    ) -> Result<Vec<i32>, String> {
        Self::validate(keys, addrs, sizes)?;
        let scatters = Self::zip_scatters(addrs, sizes);
        self.sharded(keys, Some(&scatters), |p, node, keys, sc| {
            p.put(node, keys, sc)
        })
    }

    fn get_batch(
        &self,
        keys: &[Vec<u8>],
        addrs: &[Vec<u64>],
        sizes: &[Vec<u64>],
    ) -> Result<Vec<i32>, String> {
        Self::validate(keys, addrs, sizes)?;
        let scatters = Self::zip_scatters(addrs, sizes);
        self.sharded(keys, Some(&scatters), |p, node, keys, sc| {
            p.get(node, keys, sc)
        })
    }

    fn reset(&self) -> Result<(), String> {
        let nodes = self.nodes.lock().unwrap().clone();
        for node in nodes {
            self.proto.reset(node)?;
        }
        Ok(())
    }

    fn close(&mut self) {
        self.proto.close();
    }

    fn client_id(&self) -> u16 {
        self.client_id
    }
}
