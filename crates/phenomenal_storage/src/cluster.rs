//! Cluster topology and erasure-set routing.
//!
//! The cluster is a flat pool of **disks**. A node may own one or
//! many physical disks; each disk is one slot in the topology. Disks
//! are partitioned into fixed-size **sets** at startup; each
//! `(bucket, key)` hashes to exactly one set and is written to
//! every disk in that set. Within a set, quorum decisions
//! (write all, read any) are made by the engine above.
//!
//! Slot identity is `DiskAddr { node_id, disk_idx }` — `node_id` maps
//! to a `rpc_addr` for inter-node RPC; `disk_idx` selects which
//! local disk on that node serves the request.
//!
//! Set composition is positional: nodes are visited in `nodes`-order,
//! disks within a node in `0..disk_count` order, the resulting flat
//! list is chunked into sets of `set_drive_count`. Operators compose
//! the failure profile they want by ordering nodes and choosing
//! `set_drive_count`.
//!
//! Current scope:
//!   - replication today (set-size copies) and EC behind that
//!   - no rebalancer or set expansion
//!   - no pool concept yet (single implicit pool); will be added
//!     when capacity-expansion lands

use std::hash::Hasher;
use std::net::SocketAddr;

use serde::{Deserialize, Serialize};
use siphasher::sip::SipHasher;

/// Cluster-wide SipHash key. Today a fixed zero key — matching
/// rustfs's `DEFAULT_SIP_HASH_KEY`. Once we add a `format.json`
/// per-cluster identity, the deployment UUID becomes the key (the
/// same way rustfs and minio use their cluster ID). Today's fixed
/// key still gives correct + deterministic placement; the only
/// thing it doesn't do is randomise across clusters, which doesn't
/// matter for a single-cluster deployment.
const SET_HASH_KEY: [u8; 16] = [0; 16];

pub type NodeId  = u16;
pub type DiskIdx = u16;

/// Logical address of one physical disk in the cluster. The pair
/// `(node_id, disk_idx)` uniquely identifies a disk — `node_id`
/// resolves to a `rpc_addr` via the `nodes` table; `disk_idx`
/// selects which of that node's local disks serves the request.
///
/// On the wire, only `disk_idx` travels (the connection itself
/// implies which node), so the type is small and serializes via
/// `DiskIdx` alone in the RPC variants.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Deserialize, Serialize)]
pub struct DiskAddr {
    pub node_id:  NodeId,
    pub disk_idx: DiskIdx,
}

impl std::fmt::Display for DiskAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "n{}d{}", self.node_id, self.disk_idx)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NodeAddr {
    pub id:       NodeId,
    /// `ip:port` for this node's peer-to-peer RPC listener. All disks
    /// on this node share this single listener; disk dispatch happens
    /// at the per-RPC `disk_idx` field, not via separate ports.
    pub rpc_addr: SocketAddr,
    /// Number of physical disks this node owns. Each one becomes a
    /// distinct slot in the cluster topology. Must be `>= 1`.
    /// Default `1` keeps single-disk configs ergonomic.
    #[serde(default = "default_disk_count")]
    pub disk_count: DiskIdx,
}

fn default_disk_count() -> DiskIdx { 1 }

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ClusterConfig {
    pub nodes: Vec<NodeAddr>,
    /// Disks per erasure set. Typical values run from 3
    /// (replication factor 3, single set) through 16 (wide EC).
    /// `total_disks()` must be a multiple of this value.
    pub set_drive_count: usize,
    /// Parity shards per erasure set. Operator-chosen at deployment
    /// time; **not** derived from set size at runtime.
    ///
    /// Must satisfy `1 <= default_parity_count <= set_drive_count / 2`
    /// (the `P <= D` invariant Reed-Solomon decode requires).
    /// PUTs use this to compute `data_shards = set_drive_count - P`.
    /// Read-side reconstruction reads parity back from per-object
    /// FileInfo and votes via `common_parity`, so config drift between
    /// write time and read time is detected rather than silently
    /// applied.
    pub default_parity_count: usize,
}

impl ClusterConfig {
    /// Construct a single-set cluster from `nodes`, treating each
    /// `NodeAddr` as a one-disk node. Used by tests and by the
    /// historical "replication = N" callers; multi-disk callers
    /// should build a `ClusterConfig` directly with each node's
    /// `disk_count` populated.
    pub fn flat(nodes: Vec<NodeAddr>, replication: usize) -> Self {
        // Single-set replication factor `R` = total disks; we treat it
        // as `EC[R-1 + 1]` for the parity field so PUT path arithmetic
        // (`D = N - P`) lands on the historical "write to every disk"
        // behavior. Multi-set callers must build `ClusterConfig`
        // directly with their operator-chosen parity.
        let default_parity_count = replication.saturating_sub(1).max(1);
        Self { nodes, set_drive_count: replication, default_parity_count }
    }

    /// Total disks in the cluster across all nodes.
    pub fn total_disks(&self) -> usize {
        self.nodes.iter().map(|n| n.disk_count as usize).sum()
    }

    /// Number of erasure sets the cluster is partitioned into.
    pub fn num_sets(&self) -> usize {
        let total = self.total_disks();
        if total == 0 { 0 } else { total / self.set_drive_count }
    }

    /// Flat ordered list of every disk in the cluster. Nodes are
    /// visited in `nodes`-order; each node's disks in
    /// `0..disk_count` order. The flat index `i` is set
    /// `i / set_drive_count`, slot `i % set_drive_count`.
    pub fn all_disks(&self) -> Vec<DiskAddr> {
        let mut out = Vec::with_capacity(self.total_disks());
        for n in &self.nodes {
            for d in 0..n.disk_count {
                out.push(DiskAddr { node_id: n.id, disk_idx: d });
            }
        }
        out
    }

    /// All disks belonging to set `set_index`, in stable slot order.
    /// Slot 0 of every set is always the same physical disk for the
    /// life of the cluster — EC layouts depend on this stability.
    pub fn set_disks(&self, set_index: usize) -> Vec<DiskAddr> {
        let all   = self.all_disks();
        let start = set_index * self.set_drive_count;
        let end   = start + self.set_drive_count;
        all[start..end].to_vec()
    }

    /// Map `(bucket, key)` to the set that owns it.
    ///
    /// Hash family: **SipHash-2-4** keyed by [`SET_HASH_KEY`].
    /// Same algorithm rustfs uses for its `DistributionAlgoVersion::V2/V3`
    /// (`crates/utils/src/hash.rs::sip_hash`) and minio uses for
    /// `sipHashMod` — the industry default for non-crypto keyed
    /// bucket placement. ~5-10× faster than the blake3 we used
    /// previously, with comparable distribution for short inputs.
    ///
    /// Set membership is internal topology, not an external
    /// contract, so the hash family is free to change without
    /// breaking the wire format. We avoid `format!` to keep the
    /// hot path allocation-free — the SipHasher accepts two
    /// successive `write` calls equivalently.
    pub fn set_index_for(&self, bucket: &str, key: &str) -> usize {
        let mut hasher = SipHasher::new_with_key(&SET_HASH_KEY);
        hasher.write(bucket.as_bytes());
        hasher.write(b"/");
        hasher.write(key.as_bytes());
        let v = hasher.finish();
        (v as usize) % self.num_sets().max(1)
    }

    /// The disks holding `(bucket, key)`. Used by the engine for
    /// fan-out PUT / DELETE and read-with-fallback.
    pub fn disks_for(&self, bucket: &str, key: &str) -> Vec<DiskAddr> {
        let s = self.set_index_for(bucket, key);
        self.set_disks(s)
    }

    /// Write quorum: every disk in the set must succeed today
    /// (replication has no parity slack). Drops to `data + 1`
    /// once the engine's EC tightens this.
    pub fn write_quorum(&self) -> usize { self.set_drive_count }

    /// Read quorum: one live disk in the set is enough today
    /// (replication). Rises to `data` once EC lands.
    pub fn read_quorum(&self) -> usize { 1 }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one_disk_per_node(n: usize, set_size: usize) -> ClusterConfig {
        ClusterConfig {
            nodes: (0..n as u16)
                .map(|i| NodeAddr {
                    id: i,
                    rpc_addr: format!("127.0.0.1:{}", 9100 + i).parse().unwrap(),
                    disk_count: 1,
                })
                .collect(),
            set_drive_count: set_size,
            default_parity_count: (set_size / 4).max(1),
        }
    }

    fn n_nodes_d_disks(n: usize, d: DiskIdx, set_size: usize) -> ClusterConfig {
        ClusterConfig {
            nodes: (0..n as u16)
                .map(|i| NodeAddr {
                    id: i,
                    rpc_addr: format!("127.0.0.1:{}", 9100 + i).parse().unwrap(),
                    disk_count: d,
                })
                .collect(),
            set_drive_count: set_size,
            default_parity_count: (set_size / 4).max(1),
        }
    }

    #[test]
    fn single_disk_per_node_routes_deterministically() {
        let c = one_disk_per_node(6, 3);
        assert_eq!(c.disks_for("b", "k"), c.disks_for("b", "k"));
    }

    #[test]
    fn returns_set_size_disks() {
        let c = one_disk_per_node(6, 3);
        assert_eq!(c.disks_for("b", "k").len(), 3);
    }

    #[test]
    fn keys_split_across_sets() {
        let c = one_disk_per_node(6, 3); // 2 sets
        let mut hits = [0usize; 2];
        for i in 0..1000 {
            hits[c.set_index_for("b", &format!("k{i}"))] += 1;
        }
        assert!(hits[0] > 350 && hits[0] < 650, "imbalanced: {hits:?}");
    }

    #[test]
    fn single_set_routes_every_key_same_place() {
        let c = one_disk_per_node(3, 3); // 1 set
        let r0 = c.disks_for("b", "a");
        let r1 = c.disks_for("b", "z");
        assert_eq!(r0, r1);
        assert_eq!(r0.len(), 3);
    }

    #[test]
    fn multi_disk_per_node_flat_ordering() {
        // 2 nodes × 4 disks = 8 disks; set_drive_count=4 → 2 sets
        // Set 0 = node 0's 4 disks; set 1 = node 1's 4 disks.
        let c = n_nodes_d_disks(2, 4, 4);
        assert_eq!(c.total_disks(), 8);
        assert_eq!(c.num_sets(), 2);

        let s0 = c.set_disks(0);
        let s1 = c.set_disks(1);
        assert_eq!(s0, vec![
            DiskAddr { node_id: 0, disk_idx: 0 },
            DiskAddr { node_id: 0, disk_idx: 1 },
            DiskAddr { node_id: 0, disk_idx: 2 },
            DiskAddr { node_id: 0, disk_idx: 3 },
        ]);
        assert_eq!(s1, vec![
            DiskAddr { node_id: 1, disk_idx: 0 },
            DiskAddr { node_id: 1, disk_idx: 1 },
            DiskAddr { node_id: 1, disk_idx: 2 },
            DiskAddr { node_id: 1, disk_idx: 3 },
        ]);
    }

    #[test]
    fn multi_disk_set_smaller_than_node_disk_count() {
        // 2 nodes × 4 disks = 8 disks; set_drive_count=2 → 4 sets.
        // Sets straddle node boundaries only when total_disks /
        // set_size doesn't align to per-node count.
        let c = n_nodes_d_disks(2, 4, 2);
        assert_eq!(c.num_sets(), 4);
        // Set 0 = node 0 disks 0,1
        assert_eq!(c.set_disks(0), vec![
            DiskAddr { node_id: 0, disk_idx: 0 },
            DiskAddr { node_id: 0, disk_idx: 1 },
        ]);
        // Set 2 = node 1 disks 0,1 — set 1 wholly within node 0,
        // so set 2 starts cleanly on node 1.
        assert_eq!(c.set_disks(2), vec![
            DiskAddr { node_id: 1, disk_idx: 0 },
            DiskAddr { node_id: 1, disk_idx: 1 },
        ]);
    }

    #[test]
    fn disk_addr_display_is_compact() {
        let d = DiskAddr { node_id: 7, disk_idx: 3 };
        assert_eq!(format!("{d}"), "n7d3");
    }
}
