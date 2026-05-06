//! Server config loaded from a TOML file at startup.
//!
//! Example (single-disk-per-node, the legacy default):
//! ```toml
//! self_id              = 0
//! data_dirs            = ["/var/lib/phenomenal/node0/disk0"]
//! s3_addr              = "0.0.0.0:9000"
//! rpc_addr             = "0.0.0.0:9100"
//! set_drive_count      = 3
//! default_parity_count = 1   # EC[2+1]: tolerates 1 disk failure per set
//! region               = "us-east-1"
//!
//! [[credentials]]
//! access_key = "phenomenalaccesskey"
//! secret_key = "phenomenalsecretkey"
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

use serde::Deserialize;

use phenomenal_storage::NodeAddr;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub self_id:         u16,
    /// Local disk mountpoints owned by this node, in `disk_idx`
    /// order. `data_dirs[i]` serves `disk_idx = i` on the wire. The
    /// length of this vector must equal this node's `disk_count` in
    /// the `nodes` table. Each path must be an existing directory
    /// (validated at startup). The legacy single-path TOML field
    /// `data_dir = "/path"` is also accepted via deserialization
    /// shim below for backwards compatibility.
    #[serde(deserialize_with = "deserialize_data_dirs")]
    pub data_dirs:       Vec<PathBuf>,
    pub s3_addr:         SocketAddr,
    pub rpc_addr:        SocketAddr,
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
    pub region:          String,
    /// Access-key / secret-key pairs accepted by the SigV4 verifier. At
    /// least one entry is required; the server refuses to boot with an
    /// empty credential list so it cannot accidentally run open.
    pub credentials:     Vec<Credential>,
    pub nodes:           Vec<NodeAddr>,
    /// Optional TLS for the customer-facing S3 listener. When absent
    /// the listener serves plaintext HTTP/1.1; when present it serves
    /// only HTTPS with the supplied cert chain + key.
    #[serde(default)]
    pub s3_tls:          Option<TlsConfig>,
    /// Optional TLS for the inter-node RPC plane. Configures the
    /// listener (server side) on this node and the connector (client
    /// side) `RemoteBackend`s use to reach peers. When `client_ca`
    /// is set, the connector verifies peer certs against it; without
    /// it, the connector is rejected at config validation because we
    /// refuse to ship a TLS connector that trusts everything.
    #[serde(default)]
    pub rpc_tls:         Option<TlsConfig>,
    /// Optional pool tuning. Defaults to enabled / 4 GiB / 8192-per-
    /// bucket — sane for production. Operators rarely set this.
    #[serde(default)]
    pub memory_pool:     MemoryPoolToml,
}

/// TOML-friendly mirror of `phenomenal_io::MemoryPoolConfig`. Defaults
/// match the production-tuned values; deviating is rare. `enabled =
/// false` is supported for diff-testing.
#[derive(Debug, Deserialize, Clone)]
#[serde(default)]
pub struct MemoryPoolToml {
    pub enabled:         bool,
    /// Total bytes the pool will hold across all buckets.
    pub size_bytes:      usize,
    /// Maximum free buffers per bucket. Returns past this are dropped.
    pub bucket_capacity: usize,
}

impl Default for MemoryPoolToml {
    fn default() -> Self {
        // Mirror phenomenal_io::MemoryPoolConfig::default() so
        // omitting `[memory_pool]` from TOML lands on the same
        // production tuning.
        let d = phenomenal_io::MemoryPoolConfig::default();
        Self {
            enabled:         d.enabled,
            size_bytes:      d.size_bytes,
            bucket_capacity: d.bucket_capacity,
        }
    }
}

impl From<&MemoryPoolToml> for phenomenal_io::MemoryPoolConfig {
    fn from(t: &MemoryPoolToml) -> Self {
        Self {
            enabled:         t.enabled,
            size_bytes:      t.size_bytes,
            bucket_capacity: t.bucket_capacity,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct Credential {
    pub access_key: String,
    pub secret_key: String,
}

/// Cert + key paths for a TLS-enabled listener. The same struct is used
/// for the S3 plane and the RPC plane; `client_ca` is only meaningful
/// for the RPC plane (the connector side), where it pins which cluster
/// CA the `RemoteBackend` connector trusts when verifying peers.
#[derive(Debug, Deserialize, Clone)]
pub struct TlsConfig {
    pub cert_path:    PathBuf,
    pub key_path:     PathBuf,
    /// PEM bundle of CA certs the RPC connector trusts when verifying
    /// peer node certs. Required for any cluster larger than one node;
    /// optional in single-node setups (where `RemoteBackend` is unused).
    #[serde(default)]
    pub client_ca:    Option<PathBuf>,
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
    use serde::de::Error;
    use serde::Deserialize as _;

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany {
        One(PathBuf),
        Many(Vec<PathBuf>),
    }

    match OneOrMany::deserialize(deserializer)? {
        OneOrMany::One(p) => Ok(vec![p]),
        OneOrMany::Many(v) => {
            if v.is_empty() {
                Err(D::Error::custom("data_dirs must contain at least one path"))
            } else {
                Ok(v)
            }
        }
    }
}

impl Config {
    pub fn from_toml(text: &str) -> anyhow::Result<Self> {
        let cfg: Config = toml::from_str(text)?;
        if !cfg.nodes.iter().any(|n| n.id == cfg.self_id) {
            anyhow::bail!("self_id {} not present in nodes table", cfg.self_id);
        }

        // Total disks across all nodes — sum of each node's disk_count.
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
        // `default_parity_count` constraints: at least 1 (no
        // redundancy is rejected — an unprotected cluster shouldn't
        // boot by accident), at most `set_drive_count / 2` (the
        // `P <= D` invariant Reed-Solomon decode requires).
        if cfg.default_parity_count == 0 {
            anyhow::bail!(
                "default_parity_count must be >= 1; refusing to boot with no parity"
            );
        }
        let max_parity = cfg.set_drive_count / 2;
        if cfg.default_parity_count > max_parity {
            anyhow::bail!(
                "default_parity_count ({}) must be <= set_drive_count / 2 ({}); \
                 Reed-Solomon requires P <= D",
                cfg.default_parity_count, max_parity,
            );
        }

        // Local-node consistency: data_dirs.len() must equal this
        // node's declared disk_count, and each path must be an
        // existing directory.
        let self_node = cfg.nodes.iter().find(|n| n.id == cfg.self_id)
            .expect("self_id presence checked above");
        if cfg.data_dirs.len() != self_node.disk_count as usize {
            anyhow::bail!(
                "data_dirs.len() ({}) must equal this node's disk_count ({})",
                cfg.data_dirs.len(), self_node.disk_count,
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
        if let Some(t) = &cfg.rpc_tls {
            validate_tls_files(t, "rpc_tls")?;
            // For multi-node clusters the connector side needs a CA to
            // verify peers against. Single-node deployments don't talk
            // RPC to themselves, so `client_ca` is allowed to be absent
            // there; we only enforce it when there is more than one node.
            if cfg.nodes.len() > 1 && t.client_ca.is_none() {
                anyhow::bail!(
                    "rpc_tls.client_ca is required for multi-node clusters \
                     so RemoteBackend can verify peer certificates"
                );
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
