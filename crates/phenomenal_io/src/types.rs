//! Types that cross the `StorageBackend` boundary.
//!
//! `FileInfo` is the canonical record for one version of one object on one
//! drive: identity, mod time, size, user metadata, part layout, optional
//! inline payload. `VolInfo` and `DiskInfo` describe bucket presence and
//! drive capacity. The remaining structs are parameter and result shapes
//! for the trait methods that mutate or query these records.

use std::collections::BTreeMap;

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{IoError, IoResult};

/// Bucket-meta envelope on the wire / in xl.meta inline data:
/// `b"PBKM"` (4) | format_v u16 LE | schema_v u16 LE | body_len u32 LE
/// | body (rmp-serde) | crc32c u32 LE (covers everything before).
const BUCKET_META_MAGIC:         [u8; 4] = *b"PBKM";
const BUCKET_META_FORMAT_V1:     u16     = 1;
const BUCKET_META_SCHEMA_V1:     u16     = 1;
const BUCKET_META_HEADER_BYTES:  usize   = 4 + 2 + 2 + 4;
const BUCKET_META_TRAILER_BYTES: usize   = 4;

/// Metadata describing one version of an object on one drive.
///
/// Field layout mirrors MinIO's `FileInfo` (`storage-datatypes.go:188-271`)
/// and rustfs's port (`crates/filemeta/src/fileinfo.rs`) so the consensus
/// algorithm can be ported without remapping. We don't ship every MinIO
/// feature yet (encryption, ILM, replication) but the structural slots
/// for them exist on the on-disk format and can be populated when the
/// corresponding feature lands.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct FileInfo {
    /// Bucket the object lives in.
    pub volume: String,

    /// Full object name (the S3 key).
    pub name: String,

    /// Version identifier. Empty string when versioning is off.
    pub version_id: String,

    /// True if this is the current live version.
    pub is_latest: bool,

    /// True if this `FileInfo` represents a delete marker rather than data.
    pub deleted: bool,

    /// Unique per version data directory. Isolates part files when
    /// multiple versions of the same object coexist.
    pub data_dir: String,

    /// Legacy format flag. Always false for our layout.
    pub xl_v1: bool,

    /// Last modified time in milliseconds since the UNIX epoch.
    pub mod_time_ms: u64,

    /// Full object size in bytes.
    pub size: i64,

    /// POSIX mode bits (0 for default).
    pub mode: u32,

    /// Compiler / server version that wrote the record. Informational.
    pub written_by_version: u64,

    /// Arbitrary user or system metadata. Content type is stored under
    /// the `"content-type"` key by convention.
    pub metadata: BTreeMap<String, String>,

    /// Internal system metadata: encryption sealed keys, replication
    /// state, ILM tier transition state. Reserved (always empty) until
    /// the corresponding features ship; the slot is persisted so the
    /// on-disk format does not need a bump when they do.
    #[serde(default)]
    pub meta_sys: BTreeMap<String, Vec<u8>>,

    /// Part layout for multipart objects. Single-part objects carry
    /// exactly one entry. Delete markers leave this empty.
    pub parts: Vec<ObjectPartInfo>,

    /// Erasure-coding contract for this object on this disk. Carried in
    /// every persisted record so `common_parity` consensus can vote on
    /// the EC config across the set, and the EC decoder knows which
    /// shard slot this disk holds (`erasure.index`). Identical across
    /// the set's disks except for the `index` field.
    #[serde(default)]
    pub erasure: ErasureInfo,

    /// Inline payload as a **rope** of refcounted byte spans. Populated
    /// for small objects that fit in xl.meta instead of a separate
    /// part file.
    ///
    /// A `Vec<Bytes>` (rather than a single `Bytes`) so multi-frame
    /// HTTP body input can flow through to disk without consolidation:
    /// each frame's allocation stays alive via refcount, the writer
    /// submits all of them plus the xl.meta header as one io_uring
    /// `writev` SQE — zero userspace memcpy of the inline payload
    /// anywhere from the source to the disk.
    ///
    /// `None` = no inline payload. `Some(empty vec)` shouldn't occur
    /// in practice; treated identically to `None` by readers.
    pub data: Option<Vec<Bytes>>,

    /// Number of versions that exist for this object. Layer 1 keeps at 1.
    pub num_versions: i32,

    /// True when the record is freshly created by this call.
    pub fresh: bool,

    /// Index of this record when a read returns multiple FileInfo entries.
    pub idx: i32,

    /// Per part checksum bytes. Empty when bitrot is off.
    pub checksum: Vec<u8>,

    /// True when the bucket has versioning enabled.
    pub versioned: bool,
}

/// Type of a version record. Mirrors MinIO's `xlMetaV2VersionType`
/// (`xl-storage-format-v2.go`). Today we only emit `Object`; the
/// `DeleteMarker` slot is reserved for when versioned-bucket DELETE
/// support lands.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum VersionType {
    Object       = 0,
    DeleteMarker = 1,
}

impl Default for VersionType {
    fn default() -> Self { VersionType::Object }
}

/// Erasure-coding contract for one (object, disk) record.
///
/// Mirrors MinIO's `ErasureInfo` (`xl-storage-format-v1.go:93-108`) and
/// the relevant fields in rustfs's `FileInfo.erasure`.  Read-side
/// consensus (`common_parity`, `find_file_info_in_quorum`) votes over
/// these fields across the set's disks.
///
/// `index` is the **only** field that legitimately differs per disk —
/// it identifies which shard slot in the EC layout this particular
/// disk holds. Everything else (algorithm, data_blocks, parity_blocks,
/// block_size, distribution) MUST be identical across the set; a
/// per-disk divergence is a corruption signal.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct ErasureInfo {
    /// Encoder algorithm tag. Today always "ReedSolomon".
    pub algorithm: String,

    /// Number of data shards (D). For inline replication-style records
    /// this is `1` and `parity_blocks = N - 1` so any single disk
    /// satisfies the read quorum.
    pub data_blocks: u8,

    /// Number of parity shards (P). Must satisfy `P <= D` (see
    /// `IsValid` in MinIO).
    pub parity_blocks: u8,

    /// Encoder stripe block size in bytes. The EC encoder processes
    /// the body `block_size` bytes at a time; each stripe produces
    /// `D + P` shards of `block_size / D` bytes each.
    pub block_size: u32,

    /// Which slot in the EC layout this disk holds (1-based). Differs
    /// per disk; consensus deliberately excludes this field from the
    /// content-hash check so disks can disagree on `index` without
    /// triggering an inconsistency error.
    pub index: u8,

    /// Permutation mapping shard slot -> disk position within the set.
    /// `distribution[slot - 1] = disk_position`. Same on every disk.
    /// For our identity layout today this is `[1, 2, ..., N]`; once we
    /// load-balance via `hashOrder(object_path, N)` this becomes a
    /// CRC-derived permutation per object.
    pub distribution: Vec<u8>,

    /// Per-part bitrot checksums. Empty until per-shard checksums
    /// land; the slot is persisted so adding them later does not
    /// require a format bump.
    #[serde(default)]
    pub checksums: Vec<ChecksumInfo>,
}

/// Per-part bitrot checksum record. Empty until bitrot lands.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct ChecksumInfo {
    pub part_number: i32,
    pub algorithm:   String,
    pub hash:        Vec<u8>,
}

/// One part of a multipart upload, or the sole part of a single part
/// object.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct ObjectPartInfo {
    pub etag: String,
    pub number: i32,
    pub size: i64,
    pub actual_size: i64,
    pub mod_time_ms: u64,
    pub index: Vec<u8>,
    pub checksums: BTreeMap<String, String>,
}

/// One bucket as seen by a single drive. Authoritative bucket metadata
/// (creation time, versioning state, object-lock flag) lives in
/// [`BucketMeta`] under `SYSTEM_BUCKET`; this type only records the
/// per-disk presence of the volume.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VolInfo {
    pub name: String,
}

/// Bucket-level configuration. One file per bucket on each drive at
/// `{disk_root}/.phenomenal.buckets/{bucket}.meta`. Persisted with a
/// 16-byte envelope (magic + format/schema version + body length +
/// trailing CRC32C) so corruption and format drift are detectable on
/// read.
///
/// Read by every PUT/GET object request to choose the version-id at
/// PUT time and to drive listing/admin endpoints. Written at
/// CreateBucket and rewritten on PutBucketVersioning.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BucketMeta {
    pub created_ms:            u64,
    pub versioning_status:     VersioningStatus,
    pub versioning_updated_ms: u64,
    pub object_lock_enabled:   bool,
}

impl BucketMeta {
    /// Initial state at CreateBucket time. The two valid initial
    /// states under the S3 contract are:
    ///   * `object_lock_enabled = false` → bucket starts Unversioned;
    ///     versioning may be toggled later via PutBucketVersioning.
    ///   * `object_lock_enabled = true`  → bucket starts with
    ///     versioning Enabled (object lock requires it).
    pub fn new(created_ms: u64, object_lock_enabled: bool) -> Self {
        Self {
            created_ms,
            versioning_status: if object_lock_enabled {
                VersioningStatus::Enabled
            } else {
                VersioningStatus::Unversioned
            },
            versioning_updated_ms: created_ms,
            object_lock_enabled,
        }
    }

    /// version_id to stamp on a fresh PUT: UUIDv4 when Enabled,
    /// otherwise the literal `"null"` sentinel (mirrors MinIO's
    /// `nullVersionID`). The on-disk byte representation is the zero
    /// UUID `[0u8; 16]` either way; the string form is what flows
    /// through engine comparisons and the S3 wire — keeping it the
    /// same string AWS uses (`"null"`) eliminates the
    /// translate-at-the-boundary footgun.
    pub fn next_version_id(&self) -> String {
        match self.versioning_status {
            VersioningStatus::Enabled => Uuid::new_v4().to_string(),
            VersioningStatus::Unversioned | VersioningStatus::Suspended =>
                VersioningStatus::NULL_VERSION_ID.to_owned(),
        }
    }

    /// Encode to the `PBKM`-framed wire envelope (header + rmp-serde
    /// body + crc32c trailer). Stable, versioned by `format_v`/`schema_v`.
    pub fn encode(&self) -> IoResult<Vec<u8>> {
        let body = rmp_serde::to_vec_named(self)
            .map_err(|e| IoError::Encode(e.to_string()))?;
        let mut out = Vec::with_capacity(
            BUCKET_META_HEADER_BYTES + body.len() + BUCKET_META_TRAILER_BYTES,
        );
        out.extend_from_slice(&BUCKET_META_MAGIC);
        out.extend_from_slice(&BUCKET_META_FORMAT_V1.to_le_bytes());
        out.extend_from_slice(&BUCKET_META_SCHEMA_V1.to_le_bytes());
        out.extend_from_slice(&(body.len() as u32).to_le_bytes());
        out.extend_from_slice(&body);
        let crc = crc32c::crc32c(&out);
        out.extend_from_slice(&crc.to_le_bytes());
        Ok(out)
    }

    /// Decode from the `PBKM`-framed wire envelope. Validates magic,
    /// format/schema versions, declared size, and crc32c.
    pub fn decode(bytes: &[u8]) -> IoResult<Self> {
        if bytes.len() < BUCKET_META_HEADER_BYTES + BUCKET_META_TRAILER_BYTES {
            return Err(IoError::Decode(format!("bucket meta too short ({} bytes)", bytes.len())));
        }
        if bytes[0..4] != BUCKET_META_MAGIC {
            return Err(IoError::Decode("bucket meta bad magic".into()));
        }
        let format_v = u16::from_le_bytes([bytes[4], bytes[5]]);
        if format_v != BUCKET_META_FORMAT_V1 {
            return Err(IoError::Decode(format!("bucket meta unknown format_version {format_v}")));
        }
        let schema_v = u16::from_le_bytes([bytes[6], bytes[7]]);
        if schema_v != BUCKET_META_SCHEMA_V1 {
            return Err(IoError::Decode(format!("bucket meta unknown schema_version {schema_v}")));
        }
        let body_len = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]) as usize;
        let expected = BUCKET_META_HEADER_BYTES + body_len + BUCKET_META_TRAILER_BYTES;
        if bytes.len() != expected {
            return Err(IoError::Decode(format!(
                "bucket meta size mismatch (got {}, expected {expected})", bytes.len()
            )));
        }
        let crc_recorded = u32::from_le_bytes([
            bytes[BUCKET_META_HEADER_BYTES + body_len],
            bytes[BUCKET_META_HEADER_BYTES + body_len + 1],
            bytes[BUCKET_META_HEADER_BYTES + body_len + 2],
            bytes[BUCKET_META_HEADER_BYTES + body_len + 3],
        ]);
        let crc_computed = crc32c::crc32c(&bytes[..BUCKET_META_HEADER_BYTES + body_len]);
        if crc_recorded != crc_computed {
            return Err(IoError::Decode(format!(
                "bucket meta crc mismatch (recorded {crc_recorded:#010x}, computed {crc_computed:#010x})"
            )));
        }
        let body = &bytes[BUCKET_META_HEADER_BYTES..BUCKET_META_HEADER_BYTES + body_len];
        rmp_serde::from_slice(body).map_err(|e| IoError::Decode(e.to_string()))
    }
}

/// Bucket versioning state. Drives `version_id` selection inside the
/// engine's PUT path via [`BucketMeta::next_version_id`].
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersioningStatus {
    Unversioned,
    Enabled,
    Suspended,
}

impl VersioningStatus {
    /// Sentinel for the null version, used end-to-end: in S3 wire
    /// (`x-amz-version-id: null`), in `BucketMeta::next_version_id`
    /// for Unversioned/Suspended PUTs, and in engine same-vid
    /// comparisons. The on-disk encoding is `[0u8; 16]` (the zero
    /// UUID); the decoder maps that back to this string.
    pub const NULL_VERSION_ID: &'static str = "null";
}

/// Drive health and capacity. Layer 1 populates a small subset of fields.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct DiskInfo {
    pub total: u64,
    pub used: u64,
    pub free: u64,
    pub used_inodes: u64,
    pub free_inodes: u64,
    pub fs_type: String,
    pub root_disk: bool,
    pub healing: bool,
    pub endpoint: String,
    pub mount_path: String,
    pub id: String,
}

/// Options for `update_metadata`.
#[derive(Debug, Clone, Default)]
pub struct UpdateMetadataOpts {
    /// When true the call only rewrites immutable header fields, not the
    /// user metadata map.
    pub no_persistence: bool,
}

/// Options for `delete_version`.
#[derive(Debug, Clone, Default)]
pub struct DeleteOptions {
    pub force_del_marker: bool,
    pub undo_write: bool,
}

/// Options for the internal `rename_data` commit primitive. Not exposed
/// to S3 clients.
#[derive(Debug, Clone, Default)]
pub struct RenameOptions {}

/// Return value of the internal `rename_data` commit primitive. Carries a
/// signature and the previous data directory identifier so the engine can
/// garbage collect the superseded version.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct RenameDataResp {
    pub sign: Vec<u8>,
    pub old_data_dir: String,
}

/// Bitrot check algorithm selector.
///
/// `HighwayHash256` is the default: we are optimising for small-object
/// reads, where its ~3x lower per-hash setup cost on AVX2 x86 hardware
/// dominates any throughput advantage a tree hash could offer. `Blake3`
/// is kept for large objects and non-SIMD targets, where its tree
/// structure parallelises across cores and the portable fallback stays
/// usable. `None` disables verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitrotAlgorithm {
    None,
    Blake3,
    HighwayHash256,
}

impl Default for BitrotAlgorithm {
    fn default() -> Self { BitrotAlgorithm::HighwayHash256 }
}

/// Passed to `read_file` when the caller wants per chunk bitrot checks.
#[derive(Debug, Clone)]
pub struct BitrotVerifier {
    pub algorithm: BitrotAlgorithm,
    /// Expected full file hash, hex encoded.
    pub sum_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FormatJson {
    pub version:         u32,
    pub format:          String,
    pub id:              uuid::Uuid,
    #[serde(rename = "setDriveCount")]
    pub set_drive_count: usize,
    #[serde(rename = "thisDisk")]
    pub this_disk:       u32,
}
