use std::path::Path;

use anyhow::{bail, Result};

use super::ModeArg;

#[derive(Copy, Clone, Debug)]
pub enum BenchMode {
    Rdma,
    Tls,
}

pub fn resolve_mode(cfg_path: Option<&Path>, requested: ModeArg) -> Result<BenchMode> {
    let rdma_in_cfg = match cfg_path {
        Some(p) => {
            let text = std::fs::read_to_string(p)?;
            let v: toml::Value = toml::from_str(&text)?;
            v.get("rdma").map(|x| x.is_table()).unwrap_or(false)
        }
        None => false,
    };
    match (requested, rdma_in_cfg) {
        (ModeArg::Auto, true) => Ok(BenchMode::Rdma),
        (ModeArg::Auto, false) => Ok(BenchMode::Tls),
        (ModeArg::Rdma, _) => {
            if cfg_path.is_some() && !rdma_in_cfg {
                bail!("--mode rdma but supplied --config has no [rdma] section");
            }
            Ok(BenchMode::Rdma)
        }
        (ModeArg::Tls, _) => Ok(BenchMode::Tls),
    }
}
