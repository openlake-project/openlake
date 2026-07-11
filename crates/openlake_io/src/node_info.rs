use crate::types::DiskInfo;

/// Aggregated view of a storage node.
/// A node can have multiple physical disks.
#[derive(Debug, Clone, Default)]
pub struct NodeInfo {
    pub node_id: u16,
    pub disks: Vec<DiskInfo>,
}

impl NodeInfo {
    /// Create node from collected disk infos
    pub fn new(node_id: u16, disks: Vec<DiskInfo>) -> Self {
        Self { node_id, disks }
    }

    /// Total capacity across all disks
    pub fn total_capacity(&self) -> u64 {
        self.disks.iter().map(|d| d.total).sum()
    }

    /// Total used space across all disks
    pub fn total_used(&self) -> u64 {
        self.disks.iter().map(|d| d.used).sum()
    }

    /// Total free space across all disks
    pub fn total_free(&self) -> u64 {
        self.disks.iter().map(|d| d.free).sum()
    }
}
