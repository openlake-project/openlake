use anyhow::{Context, Result};
use serde::Deserialize;
use std::net::SocketAddr;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
pub struct ClusterToml {
    #[serde(default)]
    pub nodes: Vec<NodeToml>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NodeToml {
    pub id:       u32,
    pub rpc_addr: SocketAddr,
}

pub fn load(path: &Path) -> Result<ClusterToml> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("read {}", path.display()))?;
    let cfg: ClusterToml = toml::from_str(&text)
        .with_context(|| format!("parse {}", path.display()))?;
    Ok(cfg)
}
