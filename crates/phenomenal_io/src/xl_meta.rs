//! On-disk encoding for `xl.meta`.
//!
//! Format mirrors MinIO's `xl.meta` (`xl-storage-format-v2.go`) and
//! rustfs's port (`crates/filemeta/src/filemeta.rs`) at the structural
//! level — same field set, same multi-version layout, so the consensus
//! algorithm can be ported without remapping. We use msgpack with short
//! field names rather than MinIO's bespoke msgpack-tuple encoding for
//! simplicity; the on-disk byte format is therefore phenomenal-specific
//! but the **records** carry every field MinIO records carry.
//!
//! Layout:
//!
//! ```text
//!   [0..4]      "XL2 "                         magic
//!   [4..6]      u16 LE                          format major (= 1)
//!   [6..8]      u16 LE                          format minor (= 3)
//!   [8]         0xc6                             msgpack bin32 marker
//!   [9..13]     u32 BE L                        length of the body
//!   [13..13+L]  msgpack: OnDiskMeta              multi-version blob
//!   [13+L]      0xce                             crc marker
//!   [13+L+1..5] u32 BE xxhash64(body)[..4]      crc over the body
//!   [13+L+5..]  inline tail                     concatenation of
//!                                                per-version inline
//!                                                payloads in
//!                                                versions[]-order
//! ```
//!
//! **Per-version inline.** Every version independently chooses inline
//! vs on-disk. A version is inline iff its `inline_length > 0`; its
//! bytes occupy `tail[inline_offset .. inline_offset + inline_length]`.
//! A version is EC iff `data_dir` is non-empty and `parts` is
//! non-empty (bytes live at `data_dir/part.N`). The two are mutually
//! exclusive.
//!
//! **Strictness contract**: every field is validated on both encode
//! and decode. No silent defaults, no permissive parses. If anything
//! is off — bad magic, wrong format version, corrupt body, invalid
//! erasure config, missing required field — `decode` returns an error
//! and the caller refuses to use the record.

use std::collections::BTreeMap;

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use xxhash_rust::xxh64::xxh64;

use crate::error::{IoError, IoResult};
use crate::types::{ChecksumInfo, ErasureInfo, FileInfo, ObjectPartInfo, VersionType, VersioningStatus};

/// Decoded record, ready for the caller to splice in its own bucket
/// and key context. We split decode from `FileInfo` construction so
/// the on-disk parser can't smuggle identity strings (volume, path)
/// into a record — those come from where the file was read, not from
/// the file itself.
#[derive(Debug, Clone)]
pub struct DecodedRecord {
    pub version_id:       String,
    pub data_dir:         String,
    pub deleted:          bool,
    pub size:             i64,
    pub mod_time_ms:      u64,
    pub metadata:         BTreeMap<String, String>,
    pub meta_sys:         BTreeMap<String, Vec<u8>>,
    pub erasure:          ErasureInfo,
    pub parts:            Vec<ObjectPartInfo>,
    pub inline:           Option<Vec<Bytes>>,
    pub num_versions:     i32,
}

/// Encoded xl.meta as a **head** + a **rope of inline tail frames**.
/// Kept un-concatenated so the on-disk write submits them as one
/// io_uring `writev` SQE — no userspace memcpy of inline payload bytes
/// anywhere on the path. The `head` is the small fixed-shape prefix
/// (magic + bin32 + msgpack body + crc); `tail` holds zero or more
/// frame allocations that together form the inline payload, in order.
///
/// Round-trip helper [`EncodedXlMeta::to_vec`] flattens to a
/// contiguous `Vec<u8>` for tests and the decode path; production
/// writers should hand `head` and `tail` straight to
/// `write_vectored_at`.
#[derive(Debug)]
pub struct EncodedXlMeta {
    pub head: Bytes,
    pub tail: Vec<Bytes>,
}

impl EncodedXlMeta {
    /// Total wire size (head + sum of tail frame lengths). O(tail.len()).
    pub fn len(&self) -> usize {
        self.head.len() + self.tail.iter().map(|t| t.len()).sum::<usize>()
    }

    pub fn is_empty(&self) -> bool { self.len() == 0 }

    /// Concatenate head and tail into one `Vec<u8>`. Used by tests
    /// and by the in-memory decode round-trip; production writes never
    /// flatten — they submit the segments as a vectored write.
    pub fn to_vec(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.len());
        out.extend_from_slice(&self.head);
        for t in &self.tail {
            out.extend_from_slice(t);
        }
        out
    }
}

pub const MAGIC:        [u8; 4] = *b"XL2 ";
pub const FORMAT_MAJOR: u16     = 1;
pub const FORMAT_MINOR: u16     = 3;

const HEADER_LEN:       usize = 8;
const BIN32_TAG:        u8    = 0xc6;
const BIN32_HEADER_LEN: usize = 5;          // 0xc6 + u32 BE length
const CRC_TAG:          u8    = 0xce;
const CRC_LEN:          usize = 5;          // 0xce + u32 BE digest

/// Top-level on-disk structure. A list of versions, sorted newest-first
/// by `mod_time` (sort-on-insert at write time). Today we always emit
/// exactly one version; the slot for multi-version exists so versioning
/// can be added without an on-disk format break.
#[derive(Serialize, Deserialize, Debug, Default)]
struct OnDiskMeta {
    #[serde(rename = "v")]
    versions: Vec<VersionRecord>,
}

/// One per-version record. Mirrors MinIO's `xlMetaV2Object` /
/// `xlMetaV2DeleteMarker` collapsed into one struct discriminated by
/// `ty`. Field set covers everything the consensus algorithm hashes
/// plus the bookkeeping fields needed to reconstruct a `FileInfo`.
#[derive(Serialize, Deserialize, Debug, Default)]
struct VersionRecord {
    /// Version identifier as 16 raw bytes. `[0; 16]` = null version
    /// (unversioned bucket, the most common case today).
    #[serde(rename = "id")]
    version_id: [u8; 16],

    /// `0` = Object, `1` = DeleteMarker. `u8` not enum so unknown
    /// future variants surface as a strict-decode error rather than
    /// silently mapping to a default.
    #[serde(rename = "ty")]
    ty: u8,

    /// Coordinator-assigned write timestamp, milliseconds since epoch.
    /// Identical across the set's disks for a successful write.
    #[serde(rename = "mt")]
    mod_time: u64,

    /// Per-version data directory UUID (16 raw bytes). `[0; 16]` when
    /// the version has no separate data dir (inline-only objects, our
    /// current default since we don't use data_dir for paths yet).
    #[serde(rename = "dd")]
    data_dir: [u8; 16],

    /// Total logical object size in bytes. `0` for delete markers.
    #[serde(rename = "sz")]
    size: i64,

    /// Erasure coding contract for this disk's view of the object.
    /// `common_parity` votes on `parity_blocks`; `find_file_info_in_quorum`
    /// hashes `data_blocks + parity_blocks + distribution`.
    #[serde(rename = "ec")]
    erasure: ErasureBlock,

    /// Part layout. Single-part objects have `parts.len() == 1`;
    /// multipart can have up to S3's 10000 limit. Empty for delete
    /// markers.
    #[serde(rename = "pt", default)]
    parts: Vec<PartBlock>,

    /// User-facing metadata: etag, content-type, x-amz-meta-*. Returned
    /// to S3 clients as response headers.
    #[serde(rename = "m", default)]
    metadata: BTreeMap<String, String>,

    /// Internal system metadata: encryption sealed keys, replication
    /// state, ILM tier transition state. Empty until the corresponding
    /// features land.
    #[serde(rename = "ms", default)]
    meta_sys: BTreeMap<String, Vec<u8>>,

    /// Byte offset into the inline tail where this version's payload
    /// starts. `0` when the version has no inline data (`inline_length == 0`).
    /// Defaulted on missing field so legacy minor=2 records (which
    /// carried no offset) decode cleanly.
    #[serde(rename = "io", default, skip_serializing_if = "is_zero_u64")]
    inline_offset: u64,

    /// Length of this version's inline payload in the tail.
    /// `0` means this version is *not* inline — its bytes live in
    /// `data_dir/part.N` on disk (EC path) or it is a delete marker.
    #[serde(rename = "il", default, skip_serializing_if = "is_zero_u64")]
    inline_length: u64,
}

fn is_zero_u64(v: &u64) -> bool { *v == 0 }

#[derive(Serialize, Deserialize, Debug, Default)]
struct ErasureBlock {
    #[serde(rename = "alg")]
    algorithm: String,
    #[serde(rename = "d")]
    data_blocks: u8,
    #[serde(rename = "p")]
    parity_blocks: u8,
    #[serde(rename = "i")]
    index: u8,
    #[serde(rename = "bs")]
    block_size: u32,
    #[serde(rename = "ds")]
    distribution: Vec<u8>,
    #[serde(rename = "cs", default)]
    checksums: Vec<ChecksumBlock>,
}

#[derive(Serialize, Deserialize, Debug, Default)]
struct ChecksumBlock {
    #[serde(rename = "n")]
    part_number: i32,
    #[serde(rename = "alg")]
    algorithm: String,
    #[serde(rename = "h")]
    hash: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Default)]
struct PartBlock {
    #[serde(rename = "n")]
    number: i32,
    #[serde(rename = "sz")]
    size: i64,
    #[serde(rename = "asz")]
    actual_size: i64,
    #[serde(rename = "mt")]
    mod_time: u64,
    #[serde(rename = "et", default)]
    etag: String,
    #[serde(rename = "ix", default)]
    index: Vec<u8>,
    #[serde(rename = "cks", default)]
    checksums: BTreeMap<String, String>,
}

/// Encode a single `FileInfo` into a one-version xl.meta. Thin
/// wrapper over [`encode_versions`] for callers that don't care about
/// multi-version semantics yet.
pub fn encode(fi: &FileInfo) -> IoResult<EncodedXlMeta> {
    encode_versions(std::slice::from_ref(fi))
}

/// Encode multiple FileInfo records into a multi-version xl.meta
/// blob. Versions are persisted in input order (caller is expected
/// to pre-sort newest-first by `mod_time_ms`). Each version *may*
/// carry its own inline payload via `fi.data`; the encoded tail is
/// the concatenation of those payloads in input order, and each
/// `VersionRecord` records the `(inline_offset, inline_length)`
/// slice that names its own bytes.
///
/// Field-level invariants checked per version (inline-vs-EC are
/// mutually exclusive on a single version). Encode failure means
/// the caller built an invalid record — never silently coerces.
pub fn encode_versions(versions: &[FileInfo]) -> IoResult<EncodedXlMeta> {
    if versions.is_empty() {
        return Err(IoError::Encode("encode_versions: empty versions slice".into()));
    }
    for fi in versions {
        validate_for_encode(fi)?;
    }

    // Pre-compute each version's inline (offset, length) and stage
    // its frames into the tail rope. Frames are kept un-concatenated
    // so the on-disk write submits them as one io_uring writev SQE.
    let mut tail_frames: Vec<Bytes> = Vec::new();
    let mut inline_meta: Vec<(u64, u64)> = Vec::with_capacity(versions.len());
    let mut tail_pos: u64 = 0;
    for fi in versions {
        let mut version_len: u64 = 0;
        if let Some(frames) = fi.data.as_ref() {
            for f in frames {
                if f.is_empty() { continue; }
                version_len += f.len() as u64;
                tail_frames.push(f.clone());
            }
        }
        inline_meta.push((if version_len == 0 { 0 } else { tail_pos }, version_len));
        tail_pos += version_len;
    }

    let records: Vec<VersionRecord> = versions.iter().zip(inline_meta).map(|(fi, (off, len))| {
        Ok::<_, IoError>(VersionRecord {
            version_id:    parse_uuid_bytes(&fi.version_id, "version_id")?,
            ty:            if fi.deleted { VersionType::DeleteMarker as u8 } else { VersionType::Object as u8 },
            mod_time:      fi.mod_time_ms,
            data_dir:      parse_uuid_bytes(&fi.data_dir, "data_dir")?,
            size:          fi.size,
            erasure:       encode_erasure(&fi.erasure),
            parts:         fi.parts.iter().map(encode_part).collect(),
            metadata:      fi.metadata.clone(),
            meta_sys:      fi.meta_sys.clone(),
            inline_offset: off,
            inline_length: len,
        })
    }).collect::<Result<_, _>>()?;

    let on_disk = OnDiskMeta { versions: records };

    let body = rmp_serde::to_vec_named(&on_disk)
        .map_err(|e| IoError::Encode(format!("xl.meta encode: {e}")))?;

    // Build the head: magic + format + bin32 marker + body + crc.
    let head_len = HEADER_LEN + BIN32_HEADER_LEN + body.len() + CRC_LEN;
    let mut head = Vec::with_capacity(head_len);
    head.extend_from_slice(&MAGIC);
    head.extend_from_slice(&FORMAT_MAJOR.to_le_bytes());
    head.extend_from_slice(&FORMAT_MINOR.to_le_bytes());
    head.push(BIN32_TAG);
    head.extend_from_slice(&(body.len() as u32).to_be_bytes());
    head.extend_from_slice(&body);
    head.push(CRC_TAG);
    head.extend_from_slice(&((xxh64(&body, 0) as u32).to_be_bytes()));

    Ok(EncodedXlMeta {
        head: Bytes::from(head),
        tail: tail_frames,
    })
}

/// Decode the LATEST version (sorted newest-first by `mod_time`) from
/// an xl.meta blob. Thin wrapper over [`decode_all`] for the common
/// case (GET without `?versionId=`).
pub fn decode(bytes: Bytes) -> IoResult<DecodedRecord> {
    let mut all = decode_all(bytes)?;
    if all.is_empty() {
        return Err(IoError::CorruptMetadata {
            volume: String::new(), path: String::new(),
            msg:    "empty versions list".into(),
        });
    }
    Ok(all.remove(0))
}

/// Decode every version from an xl.meta blob, sorted newest-first
/// by `mod_time`. Each version may independently carry an inline
/// payload (via `inline_offset`/`inline_length` into the tail) or
/// reference shards on disk through its `data_dir + parts`.
///
/// **Strict**: any deviation from the format — bad magic, wrong
/// format version, CRC mismatch, missing/malformed field, invalid
/// erasure config, inline range exceeding the tail — is a hard
/// error.
///
/// Takes `Bytes` so each inline range can be returned as a zero-copy
/// `Bytes::slice` of the same allocation.
pub fn decode_all(bytes: Bytes) -> IoResult<Vec<DecodedRecord>> {
    let corrupt = |msg: &str| IoError::CorruptMetadata {
        volume: String::new(),
        path:   String::new(),
        msg:    msg.to_owned(),
    };

    if bytes.len() < HEADER_LEN + BIN32_HEADER_LEN + CRC_LEN {
        return Err(corrupt("too short"));
    }
    if bytes[..4] != MAGIC {
        return Err(corrupt("bad magic"));
    }
    let major = u16::from_le_bytes([bytes[4], bytes[5]]);
    let minor = u16::from_le_bytes([bytes[6], bytes[7]]);
    if major != FORMAT_MAJOR {
        return Err(IoError::UnsupportedMetadataVersion {
            found: major as u32, max: FORMAT_MAJOR as u32,
        });
    }
    if minor != FORMAT_MINOR {
        return Err(corrupt(&format!(
            "format minor mismatch: file has {major}.{minor}, expected {FORMAT_MAJOR}.{FORMAT_MINOR}"
        )));
    }

    if bytes[HEADER_LEN] != BIN32_TAG {
        return Err(corrupt("missing bin32 header"));
    }
    let body_len = u32::from_be_bytes(bytes[HEADER_LEN + 1..HEADER_LEN + 5].try_into().unwrap()) as usize;
    let body_start = HEADER_LEN + BIN32_HEADER_LEN;
    let body_end   = body_start + body_len;
    let crc_end    = body_end + CRC_LEN;
    if bytes.len() < crc_end {
        return Err(corrupt("truncated body or crc"));
    }

    let body     = &bytes[body_start..body_end];
    let crc_slot = &bytes[body_end..crc_end];
    if crc_slot[0] != CRC_TAG {
        return Err(corrupt("missing crc marker"));
    }
    let stored_crc = u32::from_be_bytes(crc_slot[1..5].try_into().unwrap());
    if xxh64(body, 0) as u32 != stored_crc {
        return Err(corrupt("crc mismatch"));
    }

    let mut on_disk: OnDiskMeta = rmp_serde::from_slice(body)
        .map_err(|e| corrupt(&format!("decode body: {e}")))?;

    if on_disk.versions.is_empty() {
        return Err(corrupt("empty versions list"));
    }

    // Sort newest-first by mod_time. Stable sort so writers that
    // pre-sort get the order they meant.
    on_disk.versions.sort_by(|a, b| b.mod_time.cmp(&a.mod_time));

    for v in &on_disk.versions {
        validate_decoded_version(v)?;
    }

    let total_versions = on_disk.versions.len() as i32;
    let mut out: Vec<DecodedRecord> = Vec::with_capacity(on_disk.versions.len());
    let tail_len = bytes.len().saturating_sub(crc_end);

    for v in on_disk.versions.iter() {
        let inline: Option<Vec<Bytes>> = if v.inline_length > 0 {
            let lo_u64 = v.inline_offset;
            let hi_u64 = v.inline_offset.checked_add(v.inline_length).ok_or_else(||
                corrupt("inline range overflow")
            )?;
            if (hi_u64 as usize) > tail_len {
                return Err(corrupt(&format!(
                    "inline range [{lo_u64},{hi_u64}) exceeds tail length {tail_len}"
                )));
            }
            let lo = crc_end + lo_u64 as usize;
            let hi = crc_end + hi_u64 as usize;
            Some(vec![bytes.slice(lo..hi)])
        } else {
            None
        };

        out.push(DecodedRecord {
            version_id:    format_version_id_bytes(&v.version_id),
            data_dir:      format_data_dir_bytes(&v.data_dir),
            deleted:       v.ty == VersionType::DeleteMarker as u8,
            size:          v.size,
            mod_time_ms:   v.mod_time,
            metadata:      v.metadata.clone(),
            meta_sys:      v.meta_sys.clone(),
            erasure:       decode_erasure(&v.erasure),
            parts:         v.parts.iter().map(decode_part).collect(),
            inline,
            num_versions:  total_versions,
        });
    }
    Ok(out)
}

/// Look up a specific version by `version_id` (canonical UUID
/// string). Returns `Ok(None)` if the blob decodes cleanly but the
/// version isn't there.
pub fn find_version(bytes: Bytes, version_id: &str) -> IoResult<Option<DecodedRecord>> {
    Ok(decode_all(bytes)?.into_iter().find(|r| r.version_id == version_id))
}

/// Build a `FileInfo` from a `DecodedRecord` plus the caller's bucket
/// + key context. Identity (volume, name) is **not** read from disk —
/// it comes from the path the caller used to fetch the file.
pub fn file_info_from_record(rec: DecodedRecord, volume: &str, path: &str) -> FileInfo {
    let mut fi = FileInfo::default();
    fi.volume       = volume.to_owned();
    fi.name         = path.to_owned();
    fi.version_id   = rec.version_id;
    fi.data_dir     = rec.data_dir;
    fi.deleted      = rec.deleted;
    fi.size         = rec.size;
    fi.mod_time_ms  = rec.mod_time_ms;
    fi.metadata     = rec.metadata;
    fi.meta_sys     = rec.meta_sys;
    fi.erasure      = rec.erasure;
    fi.parts        = rec.parts;
    fi.data         = rec.inline;
    fi.is_latest    = true;
    fi.num_versions = rec.num_versions.max(1);
    fi
}

// ---------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------

fn validate_for_encode(fi: &FileInfo) -> IoResult<()> {
    if fi.size < 0 {
        return Err(IoError::Encode(format!("size must be >= 0, got {}", fi.size)));
    }
    if fi.mod_time_ms == 0 {
        return Err(IoError::Encode("mod_time_ms must be set (got 0)".into()));
    }
    validate_erasure(&fi.erasure, "encode")?;

    // Delete markers carry no parts, no inline, no data_dir, zero size.
    if fi.deleted {
        if !fi.parts.is_empty() {
            return Err(IoError::Encode("delete marker must have no parts".into()));
        }
        if fi.size != 0 {
            return Err(IoError::Encode(format!(
                "delete marker must have size 0, got {}", fi.size
            )));
        }
        if fi.data.as_ref().is_some_and(|frames| !frames.is_empty()) {
            return Err(IoError::Encode("delete marker must have no inline data".into()));
        }
    } else if fi.size > 0 && fi.parts.is_empty() {
        return Err(IoError::Encode(
            "non-deleted object with size > 0 must have at least one part".into()
        ));
    }

    // Inline-vs-EC are mutually exclusive on a single version. A
    // version EITHER inlines its bytes via `fi.data` (and leaves
    // `data_dir` empty) OR references on-disk shards via
    // `data_dir/part.N` (and leaves `fi.data` empty). Both set
    // would be ambiguous; neither set with a non-zero size is
    // unrepresentable.
    let has_inline = fi.data.as_ref().is_some_and(|frames| !frames.is_empty());
    if has_inline && !fi.data_dir.is_empty() {
        return Err(IoError::Encode(
            "version cannot set both inline data and data_dir; inline-vs-EC is mutually exclusive".into()
        ));
    }
    if !fi.deleted && fi.size > 0 && !has_inline && fi.data_dir.is_empty() {
        return Err(IoError::Encode(
            "non-deleted EC object with size > 0 must have a non-empty data_dir".into()
        ));
    }
    if has_inline {
        let frame_total: i64 = fi.data.as_ref().unwrap().iter()
            .map(|f| f.len() as i64).sum();
        if frame_total != fi.size {
            return Err(IoError::Encode(format!(
                "inline frame total ({frame_total}) must equal size ({})", fi.size
            )));
        }
    }

    // Parts: numbers must be positive, sizes non-negative.
    for (i, p) in fi.parts.iter().enumerate() {
        if p.number <= 0 {
            return Err(IoError::Encode(format!(
                "parts[{i}].number must be > 0, got {}", p.number
            )));
        }
        if p.size < 0 {
            return Err(IoError::Encode(format!(
                "parts[{i}].size must be >= 0, got {}", p.size
            )));
        }
        if p.actual_size < 0 {
            return Err(IoError::Encode(format!(
                "parts[{i}].actual_size must be >= 0, got {}", p.actual_size
            )));
        }
    }
    Ok(())
}

fn validate_decoded_version(v: &VersionRecord) -> IoResult<()> {
    let corrupt = |msg: String| IoError::CorruptMetadata {
        volume: String::new(),
        path:   String::new(),
        msg,
    };
    if v.ty > VersionType::DeleteMarker as u8 {
        return Err(corrupt(format!("invalid version type: {}", v.ty)));
    }
    if v.size < 0 {
        return Err(corrupt(format!("size must be >= 0, got {}", v.size)));
    }
    if v.mod_time == 0 {
        return Err(corrupt("mod_time must be set (got 0)".into()));
    }
    let erasure_info = decode_erasure(&v.erasure);
    validate_erasure(&erasure_info, "decode")
        .map_err(|e| corrupt(format!("erasure validation: {e}")))?;
    if v.ty == VersionType::DeleteMarker as u8 {
        if !v.parts.is_empty() {
            return Err(corrupt("delete marker must have no parts".into()));
        }
        if v.size != 0 {
            return Err(corrupt(format!(
                "delete marker must have size 0, got {}", v.size
            )));
        }
        if v.inline_length != 0 {
            return Err(corrupt("delete marker must have inline_length == 0".into()));
        }
    } else if v.size > 0 && v.parts.is_empty() {
        return Err(corrupt(
            "non-deleted object with size > 0 must have at least one part".into()
        ));
    }
    let has_data_dir = v.data_dir != [0u8; 16];
    if v.inline_length > 0 && has_data_dir {
        return Err(corrupt(
            "version sets both inline_length>0 and a non-zero data_dir; inline-vs-EC is mutually exclusive".into()
        ));
    }
    if v.inline_length > 0 && v.size as u64 != v.inline_length {
        return Err(corrupt(format!(
            "inline_length ({}) must equal size ({}) for inline versions",
            v.inline_length, v.size
        )));
    }
    for (i, p) in v.parts.iter().enumerate() {
        if p.number <= 0 {
            return Err(corrupt(format!(
                "parts[{i}].number must be > 0, got {}", p.number
            )));
        }
        if p.size < 0 {
            return Err(corrupt(format!(
                "parts[{i}].size must be >= 0, got {}", p.size
            )));
        }
    }
    Ok(())
}

fn validate_erasure(ei: &ErasureInfo, ctx: &str) -> IoResult<()> {
    let err = |msg: String| match ctx {
        "encode" => IoError::Encode(format!("erasure: {msg}")),
        _        => IoError::InvalidArgument(format!("erasure: {msg}")),
    };
    if ei.algorithm.is_empty() {
        return Err(err("algorithm must be non-empty".into()));
    }
    if ei.data_blocks == 0 {
        return Err(err("data_blocks must be >= 1".into()));
    }
    if ei.parity_blocks > ei.data_blocks {
        return Err(err(format!(
            "parity_blocks ({}) must be <= data_blocks ({})",
            ei.parity_blocks, ei.data_blocks
        )));
    }
    let n = (ei.data_blocks as usize) + (ei.parity_blocks as usize);
    if n == 0 {
        return Err(err("data_blocks + parity_blocks must be > 0".into()));
    }
    if ei.distribution.len() != n {
        return Err(err(format!(
            "distribution length ({}) must equal data_blocks + parity_blocks ({n})",
            ei.distribution.len()
        )));
    }
    if ei.index == 0 || (ei.index as usize) > n {
        return Err(err(format!(
            "index ({}) must be in [1, {n}]", ei.index
        )));
    }
    if ei.block_size == 0 {
        return Err(err("block_size must be > 0".into()));
    }
    Ok(())
}

// ---------------------------------------------------------------------
// Field encoders / decoders
// ---------------------------------------------------------------------

fn encode_erasure(ei: &ErasureInfo) -> ErasureBlock {
    ErasureBlock {
        algorithm:    ei.algorithm.clone(),
        data_blocks:  ei.data_blocks,
        parity_blocks: ei.parity_blocks,
        index:        ei.index,
        block_size:   ei.block_size,
        distribution: ei.distribution.clone(),
        checksums:    ei.checksums.iter().map(|c| ChecksumBlock {
            part_number: c.part_number,
            algorithm:   c.algorithm.clone(),
            hash:        c.hash.clone(),
        }).collect(),
    }
}

fn decode_erasure(b: &ErasureBlock) -> ErasureInfo {
    ErasureInfo {
        algorithm:    b.algorithm.clone(),
        data_blocks:  b.data_blocks,
        parity_blocks: b.parity_blocks,
        index:        b.index,
        block_size:   b.block_size,
        distribution: b.distribution.clone(),
        checksums:    b.checksums.iter().map(|c| ChecksumInfo {
            part_number: c.part_number,
            algorithm:   c.algorithm.clone(),
            hash:        c.hash.clone(),
        }).collect(),
    }
}

fn encode_part(p: &ObjectPartInfo) -> PartBlock {
    PartBlock {
        number:      p.number,
        size:        p.size,
        actual_size: p.actual_size,
        mod_time:    p.mod_time_ms,
        etag:        p.etag.clone(),
        index:       p.index.clone(),
        checksums:   p.checksums.clone(),
    }
}

fn decode_part(p: &PartBlock) -> ObjectPartInfo {
    ObjectPartInfo {
        etag:        p.etag.clone(),
        number:      p.number,
        size:        p.size,
        actual_size: p.actual_size,
        mod_time_ms: p.mod_time,
        index:       p.index.clone(),
        checksums:   p.checksums.clone(),
    }
}

/// Parse a UUID-like input into 16 raw bytes.
///
/// The two engine-managed fields that round-trip through here have
/// different "null" string forms:
///   * `version_id` — `"null"` (the AWS sentinel) maps to `[0; 16]`
///   * `data_dir`   — `""` (an inline-only object has no on-disk dir) maps to `[0; 16]`
///
/// Both forms are accepted on input so any caller that builds a
/// `FileInfo` with either one decodes to the same on-disk bytes.
/// Anything else is parsed as a canonical UUID hex string (with or
/// without dashes); 32 hex chars after stripping dashes.
fn parse_uuid_bytes(s: &str, field: &str) -> IoResult<[u8; 16]> {
    if s.is_empty() || s == VersioningStatus::NULL_VERSION_ID {
        return Ok([0u8; 16]);
    }
    let hex: String = s.chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 {
        return Err(IoError::Encode(format!(
            "{field}: expected 32 hex chars after stripping dashes, got {}", hex.len()
        )));
    }
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|_| IoError::Encode(format!("{field}: invalid hex")))?;
    }
    Ok(out)
}

/// Format a 16-byte version_id as a string. The zero UUID is the
/// **null version** and serializes to the literal `"null"` sentinel
/// (mirrors MinIO's `nullVersionID`); any other value is the
/// canonical 8-4-4-4-12 UUID hex.
fn format_version_id_bytes(b: &[u8; 16]) -> String {
    if b == &[0u8; 16] {
        return VersioningStatus::NULL_VERSION_ID.to_owned();
    }
    format_uuid_hex(b)
}

/// Format a 16-byte data_dir as a string. The zero UUID means
/// "no data_dir" (inline-only object) and serializes to an empty
/// string; any other value is the canonical UUID hex.
fn format_data_dir_bytes(b: &[u8; 16]) -> String {
    if b == &[0u8; 16] {
        return String::new();
    }
    format_uuid_hex(b)
}

/// Canonical 8-4-4-4-12 UUID hex string. Caller has already
/// determined that `b` is non-zero (i.e. a real UUID, not a
/// sentinel).
fn format_uuid_hex(b: &[u8; 16]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0],  b[1],  b[2],  b[3],  b[4],  b[5],  b[6],  b[7],
        b[8],  b[9],  b[10], b[11], b[12], b[13], b[14], b[15],
    )
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_erasure() -> ErasureInfo {
        ErasureInfo {
            algorithm:    "ReedSolomon".into(),
            data_blocks:  3,
            parity_blocks: 1,
            index:        1,
            block_size:   1_048_576,
            distribution: vec![1, 2, 3, 4],
            checksums:    Vec::new(),
        }
    }

    fn sample() -> FileInfo {
        let mut fi = FileInfo::default();
        fi.volume      = "photos".into();
        fi.name        = "dog.jpg".into();
        fi.size        = 5;
        fi.mod_time_ms = 1_700_000_000_000;
        fi.data        = Some(vec![Bytes::from_static(b"hello")]);
        fi.parts       = vec![ObjectPartInfo {
            etag:        "deadbeef".into(),
            number:      1,
            size:        5,
            actual_size: 5,
            mod_time_ms: 1_700_000_000_000,
            index:       Vec::new(),
            checksums:   BTreeMap::new(),
        }];
        fi.erasure     = sample_erasure();
        fi.metadata.insert("etag".into(),             "deadbeef".into());
        fi.metadata.insert("content-type".into(),     "image/jpeg".into());
        fi.metadata.insert("x-amz-meta-owner".into(), "arnav".into());
        fi
    }

    #[test]
    fn round_trip_with_inline() {
        let enc = encode(&sample()).unwrap();
        let bytes = enc.to_vec();
        assert_eq!(&bytes[..4], b"XL2 ");
        assert_eq!(u16::from_le_bytes([bytes[4], bytes[5]]), FORMAT_MAJOR);
        assert_eq!(u16::from_le_bytes([bytes[6], bytes[7]]), FORMAT_MINOR);
        assert_eq!(bytes[8], BIN32_TAG);

        let rec = decode(Bytes::from(bytes)).unwrap();
        assert_eq!(rec.size, 5);
        assert_eq!(
            rec.inline.as_ref().map(|frames| frames.iter().flat_map(|f| f.iter().copied()).collect::<Vec<u8>>()),
            Some(b"hello".to_vec()),
        );
        assert_eq!(rec.erasure.data_blocks,  3);
        assert_eq!(rec.erasure.parity_blocks, 1);
        assert_eq!(rec.erasure.distribution, vec![1, 2, 3, 4]);
        assert_eq!(rec.parts.len(), 1);
        assert_eq!(rec.parts[0].size, 5);
        assert_eq!(rec.metadata.get("etag").map(String::as_str), Some("deadbeef"));
    }

    #[test]
    fn round_trip_without_inline() {
        // EC object — no inline tail, but data_dir names the
        // per-version on-disk directory holding part.N files.
        let mut fi = sample();
        fi.data     = None;
        fi.data_dir = "deadbeef-cafe-1234-5678-90abcdef0011".into();
        let enc   = encode(&fi).unwrap();
        let rec   = decode(Bytes::from(enc.to_vec())).unwrap();
        assert!(rec.inline.is_none());
        assert_eq!(rec.size, 5);
        assert_eq!(rec.data_dir, "deadbeef-cafe-1234-5678-90abcdef0011");
    }

    #[test]
    fn bad_magic_is_rejected() {
        let mut bytes = encode(&sample()).unwrap().to_vec();
        bytes[0] = b'Y';
        assert!(matches!(decode(Bytes::from(bytes)), Err(IoError::CorruptMetadata { .. })));
    }

    #[test]
    fn future_major_version_is_flagged() {
        let mut bytes = encode(&sample()).unwrap().to_vec();
        bytes[4..6].copy_from_slice(&99u16.to_le_bytes());
        assert!(matches!(decode(Bytes::from(bytes)), Err(IoError::UnsupportedMetadataVersion { .. })));
    }

    #[test]
    fn old_minor_version_is_rejected() {
        let mut bytes = encode(&sample()).unwrap().to_vec();
        bytes[6..8].copy_from_slice(&1u16.to_le_bytes());
        assert!(matches!(decode(Bytes::from(bytes)), Err(IoError::CorruptMetadata { .. })));
    }

    #[test]
    fn body_corruption_is_detected() {
        let mut bytes = encode(&sample()).unwrap().to_vec();
        bytes[20] ^= 0x01;
        assert!(matches!(decode(Bytes::from(bytes)), Err(IoError::CorruptMetadata { .. })));
    }

    #[test]
    fn crc_slot_truncation_is_detected() {
        let bytes     = encode(&sample()).unwrap().to_vec();
        let body_len  = u32::from_be_bytes(bytes[9..13].try_into().unwrap()) as usize;
        let head_only = &bytes[..HEADER_LEN + BIN32_HEADER_LEN + body_len + 2];
        assert!(matches!(
            decode(Bytes::copy_from_slice(head_only)),
            Err(IoError::CorruptMetadata { .. })
        ));
    }

    #[test]
    fn invalid_erasure_is_rejected_on_encode() {
        let mut fi = sample();
        fi.erasure.parity_blocks = fi.erasure.data_blocks + 1;       // P > D
        assert!(matches!(encode(&fi), Err(IoError::Encode(_))));

        let mut fi = sample();
        fi.erasure.distribution = vec![1, 2];                         // wrong length
        assert!(matches!(encode(&fi), Err(IoError::Encode(_))));

        let mut fi = sample();
        fi.erasure.index = 0;                                         // index < 1
        assert!(matches!(encode(&fi), Err(IoError::Encode(_))));

        let mut fi = sample();
        fi.erasure.algorithm.clear();                                 // empty algorithm
        assert!(matches!(encode(&fi), Err(IoError::Encode(_))));
    }

    #[test]
    fn delete_marker_with_size_is_rejected() {
        let mut fi = sample();
        fi.deleted = true;
        // size still 5 from sample → invalid for a delete marker
        assert!(matches!(encode(&fi), Err(IoError::Encode(_))));
    }

    #[test]
    fn delete_marker_round_trips() {
        let mut fi = sample();
        fi.deleted = true;
        fi.size    = 0;
        fi.parts.clear();
        fi.data    = None;
        let enc = encode(&fi).unwrap();
        let rec = decode(Bytes::from(enc.to_vec())).unwrap();
        assert!(rec.deleted);
        assert_eq!(rec.size, 0);
        assert!(rec.parts.is_empty());
    }

    #[test]
    fn version_id_round_trips_through_uuid() {
        let mut fi = sample();
        fi.version_id = "deadbeef-cafe-1234-5678-90abcdef0011".into();
        let enc = encode(&fi).unwrap();
        let rec = decode(Bytes::from(enc.to_vec())).unwrap();
        assert_eq!(rec.version_id, "deadbeef-cafe-1234-5678-90abcdef0011");
    }

    #[test]
    fn meta_sys_round_trips() {
        let mut fi = sample();
        fi.meta_sys.insert("x-internal-test".into(), b"opaque-bytes".to_vec());
        let enc = encode(&fi).unwrap();
        let rec = decode(Bytes::from(enc.to_vec())).unwrap();
        assert_eq!(rec.meta_sys.get("x-internal-test"), Some(&b"opaque-bytes".to_vec()));
    }

    #[test]
    fn file_info_from_record_attaches_caller_context() {
        let enc = encode(&sample()).unwrap();
        let rec = decode(Bytes::from(enc.to_vec())).unwrap();
        let fi    = file_info_from_record(rec, "photos", "dog.jpg");
        assert_eq!(fi.volume, "photos");
        assert_eq!(fi.name,   "dog.jpg");
        assert_eq!(fi.size,   5);
        assert_eq!(fi.erasure.data_blocks, 3);
        assert_eq!(fi.parts.len(), 1);
    }

    /// Build a small inline FileInfo with the given version id, body
    /// bytes, and mod time. Used to compose multi-version test fixtures.
    fn fi_inline(vid: &str, body: &[u8], mod_time_ms: u64) -> FileInfo {
        let mut fi = FileInfo::default();
        fi.volume      = "photos".into();
        fi.name        = "dog.jpg".into();
        fi.version_id  = vid.into();
        fi.size        = body.len() as i64;
        fi.mod_time_ms = mod_time_ms;
        fi.data        = Some(vec![Bytes::copy_from_slice(body)]);
        fi.parts       = vec![ObjectPartInfo {
            etag: "etag".into(), number: 1,
            size: body.len() as i64, actual_size: body.len() as i64,
            mod_time_ms, index: Vec::new(), checksums: BTreeMap::new(),
        }];
        fi.erasure = sample_erasure();
        fi.metadata.insert("etag".into(), "etag".into());
        fi
    }

    /// Two inline versions in the same xl.meta. Each version's bytes
    /// must come back through its own `inline_offset/inline_length`
    /// slice, no spill needed.
    #[test]
    fn round_trip_multi_version_inline() {
        let v_new = fi_inline("11111111-1111-1111-1111-111111111111", b"newer-body!!", 1_700_000_002_000);
        let v_old = fi_inline("22222222-2222-2222-2222-222222222222", b"older",        1_700_000_001_000);
        // Caller pre-sorts newest-first.
        let enc   = encode_versions(&[v_new.clone(), v_old.clone()]).unwrap();
        let recs  = decode_all(Bytes::from(enc.to_vec())).unwrap();

        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].version_id, v_new.version_id);
        assert_eq!(recs[1].version_id, v_old.version_id);

        let body0: Vec<u8> = recs[0].inline.as_ref().unwrap()
            .iter().flat_map(|f| f.iter().copied()).collect();
        let body1: Vec<u8> = recs[1].inline.as_ref().unwrap()
            .iter().flat_map(|f| f.iter().copied()).collect();
        assert_eq!(body0, b"newer-body!!");
        assert_eq!(body1, b"older");
    }

    /// Mixed: a newer EC version (data_dir, no inline) sitting next
    /// to an older inline version. Both must round-trip with their
    /// respective storage choice intact.
    #[test]
    fn round_trip_mixed_inline_and_ec() {
        let mut v_ec = fi_inline("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", b"unused",  1_700_000_002_000);
        v_ec.data    = None;
        v_ec.data_dir = "deadbeef-cafe-1234-5678-90abcdef0011".into();
        v_ec.size    = 1_000_000;
        v_ec.parts[0].size        = 1_000_000;
        v_ec.parts[0].actual_size = 1_000_000;

        let v_inline = fi_inline("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", b"hello", 1_700_000_001_000);

        let enc  = encode_versions(&[v_ec.clone(), v_inline.clone()]).unwrap();
        let recs = decode_all(Bytes::from(enc.to_vec())).unwrap();

        assert_eq!(recs.len(), 2);
        // EC version: no inline, has data_dir.
        assert!(recs[0].inline.is_none());
        assert_eq!(recs[0].data_dir, "deadbeef-cafe-1234-5678-90abcdef0011");
        // Inline version: has inline, empty data_dir.
        let body: Vec<u8> = recs[1].inline.as_ref().unwrap()
            .iter().flat_map(|f| f.iter().copied()).collect();
        assert_eq!(body, b"hello");
        assert_eq!(recs[1].data_dir, "");
    }

    /// `find_version` on a multi-version blob must return inline bytes
    /// for any inline version, not just the newest.
    #[test]
    fn find_version_returns_inline_for_older_version() {
        let v_new = fi_inline("11111111-1111-1111-1111-111111111111", b"new", 1_700_000_002_000);
        let v_old = fi_inline("22222222-2222-2222-2222-222222222222", b"old", 1_700_000_001_000);
        let enc   = encode_versions(&[v_new, v_old]).unwrap();
        let bytes = Bytes::from(enc.to_vec());

        let r_old = find_version(bytes.clone(), "22222222-2222-2222-2222-222222222222")
            .unwrap().expect("older version must be found");
        let body: Vec<u8> = r_old.inline.as_ref().unwrap()
            .iter().flat_map(|f| f.iter().copied()).collect();
        assert_eq!(body, b"old");
    }

    /// Inline + data_dir on the same version is unrepresentable.
    #[test]
    fn inline_plus_data_dir_is_rejected() {
        let mut fi = sample();
        fi.data_dir = "deadbeef-cafe-1234-5678-90abcdef0011".into();
        // sample() already has fi.data populated.
        assert!(matches!(encode(&fi), Err(IoError::Encode(_))));
    }

    /// Inline frame total must equal `fi.size`.
    #[test]
    fn inline_size_mismatch_is_rejected() {
        let mut fi = sample();
        fi.size = 999;   // body is 5 bytes
        assert!(matches!(encode(&fi), Err(IoError::Encode(_))));
    }

    /// Truncating the tail past one version's inline range surfaces
    /// as a corrupt-metadata error rather than a silent short read.
    #[test]
    fn inline_range_exceeding_tail_is_rejected() {
        let v0 = fi_inline("11111111-1111-1111-1111-111111111111", b"twelve-bytes", 1_700_000_002_000);
        let v1 = fi_inline("22222222-2222-2222-2222-222222222222", b"five!",        1_700_000_001_000);
        let enc = encode_versions(&[v0, v1]).unwrap();
        let mut bytes = enc.to_vec();
        // Drop the last 6 bytes of the tail — the second version's
        // inline range now runs past EOF.
        bytes.truncate(bytes.len() - 6);
        assert!(matches!(decode_all(Bytes::from(bytes)), Err(IoError::CorruptMetadata { .. })));
    }
}
