//! Server config loaded from a TOML file at startup.
//!
//! Example (single-disk-per-node, the legacy default):
//! ```toml
//! self_id              = 0
//! data_dirs            = ["/var/lib/openlake/node0/disk0"]
//! s3_addr              = "0.0.0.0:9000"
//! rpc_addr             = "0.0.0.0:9100"
//! set_drive_count      = 3
//! default_parity_count = 1   # EC[2+1]: tolerates 1 disk failure per set
//! region               = "us-east-1"
//!
//! [[credentials]]
//! access_key = "openlakeaccesskey"
//! secret_key = "openlakesecretkey"
//!
//! [[nodes]]
//! id         = 0
//! rpc_addr   = "127.0.0.1:9100"
//! disk_count = 1
//!
//! [[nodes]]
//! id         = 1
//! rpc_addr   = "127.0.0.1:9101"
//! disk_count = 1
//!
//! [[nodes]]
//! id         = 2
//! rpc_addr   = "127.0.0.1:9102"
//! disk_count = 1
//! ```
//!
//! Multi-disk-per-node example (4 disks per node, three-node cluster,
//! 12 total disks split into four 3-wide erasure sets):
//! ```toml
//! self_id              = 0
//! data_dirs            = [
//!   "/mnt/disk0",
//!   "/mnt/disk1",
//!   "/mnt/disk2",
//!   "/mnt/disk3",
//! ]
//! set_drive_count      = 3
//! default_parity_count = 1   # EC[2+1] within each set
//!
//! [[nodes]]
//! id         = 0
//! rpc_addr   = "127.0.0.1:9100"
//! disk_count = 4
//! # … nodes 1, 2 each with disk_count = 4
//! ```
//! `data_dirs.len()` on this node must equal the local node's
//! `disk_count`; the order of `data_dirs` is the on-wire `disk_idx`
//! order — `data_dirs[0]` serves `disk_idx=0`, etc. Operators must
//! keep this order stable across restarts (a swap renames disk
//! identities and is treated by the engine as a re-format).

use std::net::SocketAddr;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use openlake_storage::NodeAddr;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub self_id: u16,
    /// Local disk mountpoints owned by this node, in `disk_idx`
    /// order. `data_dirs[i]` serves `disk_idx = i` on the wire. The
    /// length of this vector must equal this node's `disk_count` in
    /// the `nodes` table. Each path must be an existing directory
    /// (validated at startup). The legacy single-path TOML field
    /// `data_dir = "/path"` is also accepted via deserialization
    /// shim below for backwards compatibility.
    #[serde(deserialize_with = "deserialize_data_dirs")]
    pub data_dirs: Vec<PathBuf>,
    pub s3_addr: SocketAddr,
    /// Shared S3 listener port across every node in the cluster. Cluster
    /// tooling (e.g. the CLI liveness probe) derives a node's S3 endpoint
    /// from its `rpc_addr` IP plus this port, since the `nodes` table only
    /// carries each peer's RPC address. Optional: defaults to this node's
    /// own `s3_addr` port, which is the common all-nodes-same-port case.
    #[serde(default)]
    pub s3_port: Option<u16>,
    pub rpc_addr: SocketAddr,
    /// Disks per erasure set. `total_disks() % set_drive_count` must
    /// be 0, where `total_disks() = sum(node.disk_count)` across all
    /// nodes. Accept the legacy `replication` key as an alias for
    /// pre-multi-disk configs.
    #[serde(alias = "replication")]
    pub set_drive_count: usize,
    /// Parity shards per erasure set. Operator-chosen storage policy:
    /// trades raw storage overhead (`set_drive_count / data_shards`)
    /// against simultaneous-failure tolerance (`= P`).
    ///
    /// Must satisfy `1 <= default_parity_count <= set_drive_count / 2`.
    /// Suggested default for production: `set_drive_count / 4` rounded
    /// down with a floor of 1 (e.g. `4` for `set_drive_count = 16`).
    /// MUST be identical across every node's TOML — gateway nodes use
    /// it on PUT; mismatched values across gateways would write objects
    /// under different EC layouts depending on which gateway served the
    /// request.
    pub default_parity_count: usize,
    /// SigV4 scope region. Every signed request must present this region
    /// inside its credential scope or it is rejected with
    /// `SignatureDoesNotMatch`. The value is opaque to the storage layer —
    /// it only gates request authentication.
    pub region: String,
    /// Access-key / secret-key pairs accepted by the SigV4 verifier. At
    /// least one entry is required; the server refuses to boot with an
    /// empty credential list so it cannot accidentally run open.
    pub credentials: Vec<Credential>,
    pub nodes: Vec<NodeAddr>,
    /// Ordered KV-agent RPC endpoints used for peer discovery and telemetry.
    /// KV engines remain standalone; this list does not create storage peers.
    #[serde(default)]
    pub kv_agents: Vec<SocketAddr>,
    /// Optional TLS for the customer-facing S3 listener. When absent
    /// the listener serves plaintext HTTP/1.1; when present it serves
    /// only HTTPS with the supplied cert chain + key.
    #[serde(default)]
    pub s3_tls: Option<TlsConfig>,
    /// TLS for the inter-node RPC plane. **Required for any cluster of
    /// `nodes.len() > 1`.** The RPC plane speaks HTTP/2 negotiated via
    /// ALPN over rustls (cyper does not expose `http2_only(true)`, so
    /// ALPN-h2 over TLS is the only path to h2 on the client side).
    /// Single-node deployments never dial peers, so RPC TLS is allowed
    /// to be absent there for development convenience.
    ///
    /// Configures the listener (server side) on this node and the
    /// rustls `ClientConfig` `RemoteBackend`s consume on the cyper
    /// client side. `client_ca` is the cluster CA bundle the connector
    /// pins on; required for any multi-node cluster — without it we'd
    /// either trust everything (insecure) or trust nothing (won't
    /// connect).
    #[serde(default)]
    pub rpc_tls: Option<TlsConfig>,
    /// Optional pool tuning. Defaults to enabled / 4 GiB / 8192-per-
    /// bucket — sane for production. Operators rarely set this.
    #[serde(default)]
    pub memory_pool: MemoryPoolToml,
    #[serde(default)]
    pub mode: Mode,
    #[serde(default)]
    pub transport: TransportMode,
    #[serde(default)]
    pub rdma: Option<RdmaToml>, // required when transport = rdma
    #[serde(default)]
    pub kv_slab: Option<KvSlabToml>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct KvSlabToml {
    #[serde(default)]
    pub capacity_gb: Option<u64>,
    #[serde(default)]
    pub cpu_ram_frac: Option<f64>,
    #[serde(default = "default_kv_reserve_ttl_secs")]
    pub reserve_ttl_secs: u64,
}

impl KvSlabToml {
    pub fn capacity_bytes(&self) -> anyhow::Result<u64> {
        const GIB: u64 = 1024 * 1024 * 1024;
        // cpu_ram_frac (fraction of system RAM, floored to whole GiB) wins over capacity_gb.
        if let Some(frac) = self.cpu_ram_frac {
            anyhow::ensure!(
                frac > 0.0 && frac <= 1.0,
                "[kv_slab] cpu_ram_frac must be in (0.0, 1.0], got {frac}"
            );
            let gb = (total_system_ram_bytes()? as f64 * frac) as u64 / GIB;
            anyhow::ensure!(gb > 0, "[kv_slab] cpu_ram_frac {frac} yields under 1 GiB");
            return Ok(gb * GIB);
        }
        let gb = self
            .capacity_gb
            .ok_or_else(|| anyhow::anyhow!("[kv_slab] set cpu_ram_frac or capacity_gb"))?;
        Ok(gb * GIB)
    }
}

fn default_kv_reserve_ttl_secs() -> u64 {
    60
}

fn total_system_ram_bytes() -> anyhow::Result<u64> {
    for line in std::fs::read_to_string("/proc/meminfo")?.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            let kb: u64 = rest
                .split_whitespace()
                .next()
                .and_then(|v| v.parse().ok())
                .ok_or_else(|| anyhow::anyhow!("malformed MemTotal in /proc/meminfo"))?;
            return Ok(kb * 1024);
        }
    }
    anyhow::bail!("MemTotal not found in /proc/meminfo")
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TransportMode {
    #[default]
    H2,
    Rdma,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RdmaBackend {
    #[default]
    Dct,
    Ucx,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    #[default]
    Storage,
    Kv,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RdmaToml {
    #[serde(default)]
    pub backend: RdmaBackend,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub self_node_id: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dev_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dc_key: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qos: Option<RdmaQosToml>,
    #[serde(default = "default_bulk_pool_cap")]
    pub bulk_pool_cap: usize,
    #[serde(default = "default_network_timeout_secs")]
    pub network_timeout_secs: u64,
    #[serde(default = "default_srq_depth")]
    pub srq_depth: u32,
    #[serde(default = "default_max_send_wr")]
    pub max_send_wr: u32,
    #[serde(default = "default_peer_credit")]
    pub peer_credit: u32,
    pub max_clients: Option<u32>,
}

fn default_bulk_pool_cap() -> usize {
    64
}
fn default_srq_depth() -> u32 {
    4096
}
fn default_max_send_wr() -> u32 {
    256
}
fn default_peer_credit() -> u32 {
    4
}
fn default_network_timeout_secs() -> u64 {
    10 * 60 * 60
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct RdmaQosToml {
    pub traffic_class: u8,
    pub service_level: u8,
}

/// TOML-friendly mirror of `openlake_io::MemoryPoolConfig`. Defaults
/// match the production-tuned values; deviating is rare. `enabled =
/// false` is supported for diff-testing.
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(default)]
pub struct MemoryPoolToml {
    pub enabled: bool,
    /// Total bytes the pool will hold across all buckets.
    pub size_bytes: usize,
    /// Maximum free buffers per bucket. Returns past this are dropped.
    pub bucket_capacity: usize,
}

impl Default for MemoryPoolToml {
    fn default() -> Self {
        // Mirror openlake_io::MemoryPoolConfig::default() so
        // omitting `[memory_pool]` from TOML lands on the same
        // production tuning.
        let d = openlake_io::MemoryPoolConfig::default();
        Self {
            enabled: d.enabled,
            size_bytes: d.size_bytes,
            bucket_capacity: d.bucket_capacity,
        }
    }
}

impl From<&MemoryPoolToml> for openlake_io::MemoryPoolConfig {
    fn from(t: &MemoryPoolToml) -> Self {
        Self {
            enabled: t.enabled,
            size_bytes: t.size_bytes,
            bucket_capacity: t.bucket_capacity,
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Credential {
    pub access_key: String,
    pub secret_key: String,
}

/// Cert + key paths for a TLS-enabled listener. The same struct is used
/// for the S3 plane and the RPC plane; `client_ca` is only meaningful
/// for the RPC plane (the connector side), where it pins which cluster
/// CA the `RemoteBackend` connector trusts when verifying peers.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TlsConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    /// PEM bundle of CA certs the RPC connector trusts when verifying
    /// peer node certs. Required for any cluster larger than one node;
    /// optional in single-node setups (where `RemoteBackend` is unused).
    #[serde(default)]
    pub client_ca: Option<PathBuf>,
}

/// Accept either a single string (`data_dir = "/path"`, legacy) or
/// an array (`data_dirs = ["/p1", "/p2"]`, multi-disk) and produce
/// the canonical `Vec<PathBuf>`. The legacy form is kept for
/// backwards compatibility — single-disk deployments don't need to
/// switch their TOML.
fn deserialize_data_dirs<'de, D>(deserializer: D) -> Result<Vec<PathBuf>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize as _;

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany {
        One(PathBuf),
        Many(Vec<PathBuf>),
    }

    match OneOrMany::deserialize(deserializer)? {
        OneOrMany::One(p) => Ok(vec![p]),
        OneOrMany::Many(v) => Ok(v),
    }
}

impl Config {
    #[allow(clippy::collapsible_if)]
    pub fn from_toml(text: &str) -> anyhow::Result<Self> {
        let cfg: Config = toml::from_str(text)?;
        if !cfg.nodes.iter().any(|n| n.id == cfg.self_id) {
            anyhow::bail!("self_id {} not present in nodes table", cfg.self_id);
        }
        {
            let mut seen_ids: std::collections::HashSet<u16> = std::collections::HashSet::new();
            for n in &cfg.nodes {
                if !seen_ids.insert(n.id) {
                    anyhow::bail!(
                        "duplicate node id {} in nodes table; each node must have a unique id",
                        n.id,
                    );
                }
            }
        }

        if cfg.mode == Mode::Kv {
            if cfg.kv_slab.is_none() {
                anyhow::bail!("mode = \"kv\" requires a [kv_slab] block");
            }
            if cfg.nodes.len() != 1 {
                anyhow::bail!("mode = \"kv\" nodes are standalone; list only this node");
            }
            if cfg.kv_agents.is_empty() {
                anyhow::bail!("mode = \"kv\" requires a non-empty kv_agents list");
            }
            if cfg.kv_agents.len() > u16::MAX as usize + 1 {
                anyhow::bail!(
                    "kv_agents contains more than {} addressable nodes",
                    u16::MAX as usize + 1
                );
            }
            if cfg.self_id as usize >= cfg.kv_agents.len() {
                anyhow::bail!(
                    "self_id {} is outside the ordered kv_agents list ({} entries)",
                    cfg.self_id,
                    cfg.kv_agents.len(),
                );
            }
            let unique_agents = cfg
                .kv_agents
                .iter()
                .collect::<std::collections::HashSet<_>>();
            if unique_agents.len() != cfg.kv_agents.len() {
                anyhow::bail!("kv_agents contains duplicate RPC endpoints");
            }
        } else if !cfg.kv_agents.is_empty() {
            anyhow::bail!("kv_agents is only valid when mode = \"kv\"");
        }
        if let Some(r) = cfg.rdma.as_ref().filter(|r| r.backend == RdmaBackend::Dct) {
            if r.self_node_id.is_none() {
                anyhow::bail!("[rdma] self_node_id is required for backend = \"dct\"");
            }
            if r.dev_name.as_deref().is_none_or(str::is_empty) {
                anyhow::bail!("[rdma] dev_name is required for backend = \"dct\"");
            }
            if r.dc_key.is_none() {
                anyhow::bail!("[rdma] dc_key is required for backend = \"dct\"");
            }
            if r.qos.is_none() {
                anyhow::bail!("[rdma.qos] is required for backend = \"dct\"");
            }
            if r.peer_credit == 0 {
                anyhow::bail!("[rdma] peer_credit must be >= 1");
            }
            if r.max_clients.unwrap_or(0).saturating_mul(r.peer_credit + 1) > r.srq_depth {
                anyhow::bail!("[rdma] max_clients x (peer_credit + 1) exceeds srq_depth");
            }
        }
        if cfg.mode == Mode::Storage {
            let total_disks: usize = cfg.nodes.iter().map(|n| n.disk_count as usize).sum();
            if total_disks == 0 {
                anyhow::bail!("at least one node must declare disk_count >= 1");
            }
            if cfg.set_drive_count == 0 || cfg.set_drive_count > total_disks {
                anyhow::bail!(
                    "set_drive_count must be in [1, {total_disks}] (total disks across cluster)"
                );
            }
            if !total_disks.is_multiple_of(cfg.set_drive_count) {
                anyhow::bail!(
                    "total disks ({total_disks}) must be a multiple of set_drive_count ({})",
                    cfg.set_drive_count,
                );
            }
            if cfg.default_parity_count == 0 {
                anyhow::bail!("default_parity_count must be >= 1; refusing to boot with no parity");
            }
            let max_parity = cfg.set_drive_count / 2;
            if cfg.default_parity_count > max_parity {
                anyhow::bail!(
                    "default_parity_count ({}) must be <= set_drive_count / 2 ({}); \
                 Reed-Solomon requires P <= D",
                    cfg.default_parity_count,
                    max_parity,
                );
            }

            let self_node = cfg
                .nodes
                .iter()
                .find(|n| n.id == cfg.self_id)
                .expect("self_id presence checked above");
            if cfg.data_dirs.len() != self_node.disk_count as usize {
                anyhow::bail!(
                    "data_dirs.len() ({}) must equal this node's disk_count ({})",
                    cfg.data_dirs.len(),
                    self_node.disk_count,
                );
            }
            let mut seen: std::collections::HashSet<&PathBuf> = std::collections::HashSet::new();
            for (i, p) in cfg.data_dirs.iter().enumerate() {
                if !p.is_dir() {
                    anyhow::bail!(
                        "data_dirs[{i}] = {} is not an existing directory",
                        p.display(),
                    );
                }
                if !seen.insert(p) {
                    anyhow::bail!(
                        "data_dirs[{i}] = {} is duplicated; each disk needs a unique mountpoint",
                        p.display(),
                    );
                }
            }
        }

        if cfg.region.trim().is_empty() {
            anyhow::bail!("region must be non-empty");
        }
        if cfg.credentials.is_empty() {
            anyhow::bail!("at least one credential is required; server refuses to run open");
        }
        for c in &cfg.credentials {
            if c.access_key.is_empty() || c.secret_key.is_empty() {
                anyhow::bail!("credential access_key and secret_key must both be non-empty");
            }
        }
        if let Some(t) = &cfg.s3_tls {
            validate_tls_files(t, "s3_tls")?;
        }
        // Multi-node clusters require the inter-node RPC plane to be
        // TLS-terminated. The plane speaks HTTP/2 negotiated via ALPN,
        // and ALPN is only consulted during the TLS handshake — without
        // TLS there is no h2 negotiation surface, and cyper's
        // `ClientBuilder` does not expose `http2_only(true)` to force
        // h2 prior-knowledge over plaintext. Single-node deployments
        // never call `RemoteBackend`, so plaintext is fine there.
        match (cfg.nodes.len(), &cfg.rpc_tls) {
            (1, _) => {}
            // Plaintext multi-node is allowed (trusted private network):
            // PeerClient falls back to h2c (http2_prior_knowledge) when
            // rpc_tls is absent.
            (_, None) => {}
            (_, Some(t)) => {
                validate_tls_files(t, "rpc_tls")?;
                if t.client_ca.is_none() {
                    anyhow::bail!(
                        "rpc_tls.client_ca is required for multi-node clusters \
                         so RemoteBackend can verify peer certificates"
                    );
                }
            }
        }
        if let Some(t) = &cfg.rpc_tls {
            // Single-node case may still set rpc_tls (harmless); validate
            // its files so a typo in cert_path is caught at startup.
            if cfg.nodes.len() == 1 {
                validate_tls_files(t, "rpc_tls")?;
            }
        }
        if cfg.transport == TransportMode::Rdma && cfg.rdma.is_none() {
            anyhow::bail!("transport = \"rdma\" requires an [rdma] config block");
        }
        if cfg.transport == TransportMode::Rdma {
            let rdma = cfg.rdma.as_ref().expect("checked above");
            if !cfg!(all(feature = "rdma", target_os = "linux")) {
                anyhow::bail!(
                    "transport = \"rdma\" requires the `rdma` cargo feature on a Linux build"
                );
            }
            if rdma.backend == RdmaBackend::Ucx && cfg.mode != Mode::Kv {
                anyhow::bail!("[rdma] backend = \"ucx\" currently supports mode = \"kv\" only");
            }
        }
        Ok(cfg)
    }
}

fn validate_tls_files(t: &TlsConfig, label: &str) -> anyhow::Result<()> {
    if !t.cert_path.exists() {
        anyhow::bail!("{label}.cert_path {} does not exist", t.cert_path.display());
    }
    if !t.key_path.exists() {
        anyhow::bail!("{label}.key_path {} does not exist", t.key_path.display());
    }
    if let Some(ca) = &t.client_ca {
        if !ca.exists() {
            anyhow::bail!("{label}.client_ca {} does not exist", ca.display());
        }
    }
    Ok(())
}

#[cfg(test)]
mod kv_slab_tests {
    use super::*;

    fn slab(capacity_gb: Option<u64>, cpu_ram_frac: Option<f64>) -> KvSlabToml {
        KvSlabToml {
            capacity_gb,
            cpu_ram_frac,
            reserve_ttl_secs: 60,
        }
    }

    #[test]
    fn frac_out_of_range_errors() {
        assert!(slab(None, Some(0.0)).capacity_bytes().is_err());
        assert!(slab(None, Some(1.5)).capacity_bytes().is_err());
    }

    #[test]
    fn neither_set_errors() {
        assert!(slab(None, None).capacity_bytes().is_err());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn frac_wins_and_floors_to_whole_gib() {
        const GIB: u64 = 1024 * 1024 * 1024;
        let bytes = slab(Some(1), Some(0.5)).capacity_bytes().unwrap();
        assert_eq!(bytes % GIB, 0);
        assert_eq!(
            bytes,
            (total_system_ram_bytes().unwrap() as f64 * 0.5) as u64 / GIB * GIB
        );
    }

    #[test]
    fn rdma_backend_defaults_to_dct() {
        let rdma: RdmaToml = toml::from_str(
            r#"
self_node_id = 0
dev_name = "mlx5_0"
dc_key = 4919
qos = { traffic_class = 0, service_level = 0 }
"#,
        )
        .unwrap();
        assert_eq!(rdma.backend, RdmaBackend::Dct);
    }

    #[test]
    fn ucx_backend_does_not_require_dct_fields() {
        let rdma: RdmaToml = toml::from_str("backend = \"ucx\"").unwrap();
        assert_eq!(rdma.backend, RdmaBackend::Ucx);
        assert!(rdma.dev_name.is_none());
    }

    #[test]
    fn kv_mode_retains_the_ordered_agent_reference_list() {
        let cfg = Config::from_toml(
            r#"
self_id = 1
mode = "kv"
rpc_addr = "0.0.0.0:9400"
s3_addr = "0.0.0.0:9000"
data_dirs = []
set_drive_count = 1
default_parity_count = 1
region = "us-east-1"
kv_agents = ["10.0.0.1:9400", "10.0.0.2:9400"]

[[credentials]]
access_key = "test"
secret_key = "test"

[[nodes]]
id = 1
rpc_addr = "0.0.0.0:9400"
disk_count = 0

[kv_slab]
capacity_gb = 1
"#,
        )
        .unwrap();

        assert_eq!(cfg.kv_agents[0], "10.0.0.1:9400".parse().unwrap());
        assert_eq!(cfg.kv_agents[1], "10.0.0.2:9400".parse().unwrap());
    }

    #[test]
    fn kv_mode_requires_an_agent_for_a_single_node() {
        let text = include_str!("../configs/kv_local.toml");
        let without_agents = text
            .lines()
            .filter(|line| !line.trim_start().starts_with("kv_agents"))
            .collect::<Vec<_>>()
            .join("\n");

        let error = Config::from_toml(&without_agents).unwrap_err();
        assert!(error
            .to_string()
            .contains("mode = \"kv\" requires a non-empty kv_agents list"));
    }
}
