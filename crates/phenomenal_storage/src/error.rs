use phenomenal_io::IoError;
use thiserror::Error;

/// Engine level errors. Storage level errors (file not found, corrupt
/// xl.meta, etc.) come in via `IoError` and bubble through the `Io` variant.
#[derive(Debug, Error)]
pub enum StorageError {
    #[error("bucket not found: {0}")]
    BucketNotFound(String),

    #[error("bucket already exists: {0}")]
    BucketAlreadyExists(String),

    #[error("bucket not empty: {0}")]
    BucketNotEmpty(String),

    #[error("object not found: {bucket}/{key}")]
    ObjectNotFound { bucket: String, key: String },

    /// The key exists but the requested `version_id` does not. Distinct
    /// from `ObjectNotFound` so the S3 frontend can surface
    /// `NoSuchVersion` (instead of `NoSuchKey`) — clients use the code
    /// to decide whether to retry with a different versionId or treat
    /// the whole key as gone.
    #[error("version not found: {bucket}/{key}@{version_id}")]
    VersionNotFound { bucket: String, key: String, version_id: String },

    #[error("invalid bucket name: {0}")]
    InvalidBucketName(String),

    #[error("invalid object key: {0}")]
    InvalidObjectKey(String),

    /// Distributed lock could not be acquired within the caller's
    /// deadline. The S3 frontend translates this into 503 SlowDown so
    /// the client retries with its own backoff.
    #[error("lock timeout on {0}")]
    LockTimeout(String),

    /// Read-side metadata consensus could not reach the per-disk
    /// quorum: enough disks were alive but their metadata records
    /// disagree on content (etag, parts, EC config, etc.). Surfaces
    /// distinctly from `ObjectNotFound` so operators can tell
    /// "object missing" from "object split-brain — needs heal."
    #[error("inconsistent metadata for {bucket}/{key}: {msg}")]
    InconsistentMeta { bucket: String, key: String, msg: String },

    /// Read-side gate failed before content consensus ran: too few
    /// disks responded to even attempt a quorum decision (typically
    /// because the dominant per-disk error was `errDiskNotFound`).
    /// Distinct from `InconsistentMeta` (which means disks responded
    /// but disagreed) and `ObjectNotFound` (which means the disks
    /// agreed the object doesn't exist).
    #[error("insufficient online drives for {bucket}/{key}: {msg}")]
    InsufficientOnlineDrives { bucket: String, key: String, msg: String },

    #[error("io: {0}")]
    Io(#[from] IoError),
}

pub type StorageResult<T> = Result<T, StorageError>;
