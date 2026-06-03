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

/// Result of `Engine::create_multipart_upload`. Carries the session
/// identifier the client uses on subsequent `UploadPart` and
/// `CompleteMultipartUpload` requests. Mirrors the `UploadId` field
/// of S3's `<InitiateMultipartUploadResult>` XML.
#[derive(Debug, Clone)]
pub struct MultipartInit {
    pub upload_id: String,
}

/// One entry in the client-supplied `<CompleteMultipartUpload>` body.
/// The client lists every part it wants in the assembled object,
/// in ascending part-number order, with the etag returned from the
/// corresponding `UploadPart` response.
///
/// The server validates each entry against the part's `.meta`
/// sidecar on disk before assembling. ETag mismatch → `InvalidPart`.
#[derive(Debug, Clone)]
pub struct CompletePart {
    pub part_number: u32,
    pub etag:        String,
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
    /// True when the resolved version is a delete-marker (a tombstone
    /// in the version list, not a real object). HEAD against a marker
    /// must respond `405 MethodNotAllowed` per S3 spec; GET responds
    /// 404 when the latest is a marker. Always `false` for `get`/`list`
    /// since those resolve through to non-marker versions.
    pub is_delete_marker: bool,
}
