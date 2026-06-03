use thiserror::Error;

/// Errors a `StorageBackend` can surface. Variants are intentionally
/// specific (`VolumeNotFound`, `FileAlreadyExists`, `CorruptMetadata`, ...)
/// so callers can pattern match on the failure mode without parsing
/// message strings.
#[derive(Debug, Error)]
pub enum IoError {
    #[error("volume not found: {0}")]
    VolumeNotFound(String),

    #[error("volume already exists: {0}")]
    VolumeExists(String),

    #[error("volume not empty: {0}")]
    VolumeNotEmpty(String),

    #[error("file not found: {volume}/{path}")]
    FileNotFound { volume: String, path: String },

    #[error("file already exists: {volume}/{path}")]
    FileAlreadyExists { volume: String, path: String },

    #[error("file version not found: {volume}/{path}@{version_id}")]
    FileVersionNotFound { volume: String, path: String, version_id: String },

    #[error("corrupt xl.meta at {volume}/{path}: {msg}")]
    CorruptMetadata { volume: String, path: String, msg: String },

    #[error("unsupported xl.meta version {found} (max {max})")]
    UnsupportedMetadataVersion { found: u32, max: u32 },

    #[error("bitrot check failed at {volume}/{path}")]
    BitrotCheckFailed { volume: String, path: String },

    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    #[error("unsupported operation: {0}")]
    Unsupported(&'static str),

    #[error("encode: {0}")]
    Encode(String),

    #[error("decode: {0}")]
    Decode(String),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

pub type IoResult<T> = Result<T, IoError>;
