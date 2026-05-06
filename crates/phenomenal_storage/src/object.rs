//! Public object types.

use serde::{Deserialize, Serialize};

/// How the object's bytes are stored on disk.
#[derive(Serialize, Deserialize, Debug, Copy, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StorageClass {
    /// Bytes are embedded in `xl.meta` directly (small objects).
    Inline,
    /// Bytes live in `part.1` next to `xl.meta`.
    Single,
}

/// Information about an object. Returned by `get`, `stat`, `list`.
///
/// `data` is only populated by `get`; `stat`/`list` leave it `None`.
#[derive(Debug, Clone)]
pub struct ObjectInfo {
    pub bucket: String,
    pub key: String,
    pub size: u64,
    pub etag: String,
    pub storage_class: StorageClass,
    /// Milliseconds since UNIX epoch.
    pub modified_ms: u64,
    pub content_type: Option<String>,
    /// The version ID assigned to this object. `"null"` when the
    /// bucket is Unversioned or Suspended; a UUID string when Enabled.
    pub version_id: String,
}
