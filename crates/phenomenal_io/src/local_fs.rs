//! Local filesystem `StorageBackend` on compio.
//!
//! Durability rules:
//!
//!   * `write_metadata` writes to a sibling temp file, `fsync`s the
//!     file, `rename`s it onto the live name, then `fsync`s the parent
//!     directory so the dir-entry update survives a power cut.
//!   * Recursive deletes (`delete_vol(force=true)`, `delete(recursive)`)
//!     do a one-`rename` move into `.phenomenal.trash/{uuid}` and spawn
//!     a detached task on the current compio runtime that walks the
//!     subtree and issues an io_uring `unlinkat` SQE per entry. No OS
//!     thread is created; the work interleaves cooperatively with the
//!     runtime's live traffic between every `.await`.
//!   * `create_file_stream` pumps source bytes straight to the file
//!     fd via repeated `write_at` calls; nothing is buffered above the
//!     compio chunk window. `read_file_stream` mirrors that on the way
//!     out, returning a `ByteStream` that owns the open `File` for the
//!     duration of the read.
//!
//! Current scope: `compio-fs` 0.11 has no async `read_dir` or
//! `remove_dir_all`, so listing paths still use `std::fs`; those are
//! cold paths. Per-part bitrot verification is pending.

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use compio::buf::{BufResult, IntoInner};

use crate::alloc::PooledBuffer;
use compio::fs::{File, OpenOptions};
use compio::io::{AsyncReadAt, AsyncWriteAt, AsyncWriteAtExt};
use uuid::Uuid;

use crate::backend::StorageBackend;
use crate::error::{IoError, IoResult};
use crate::stream::{ByteSink, ByteStream};
use crate::types::{
    DeleteOptions, DiskInfo, FileInfo, RenameDataResp, RenameOptions,
    UpdateMetadataOpts, VolInfo,
};
use crate::xl_meta::{self, DecodedRecord};

const META_FILENAME:         &str = "xl.meta";
/// Cluster-identity file. One per drive root, persisted JSON,
/// written exactly once at first cluster init by the seed node.
/// See [`crate::types::FormatJson`] and the bootstrap state machine
/// in `phenomenal_storage::format`.
const FORMAT_FILENAME:       &str = ".phenomenal.format.json";
/// Backup-of-prior-xl.meta filename written inside the old data_dir
/// on same-`version_id` overwrites (S-6). A crash-recovery scrubber
/// finds this and can reconstruct the pre-PUT state if the live
/// xl.meta got torn between S-5 (data_dir grafted) and S-7 (xl.meta
/// commit). Mirrors MinIO's `xl.meta.bkp` (`xl-storage-format-v2.go`
/// `xlStorageFormatFileBackup`).
const META_BACKUP_FILENAME:  &str = "xl.meta.bkp";
const TRASH_DIRNAME:         &str = ".phenomenal.trash";
/// Reserved system "volume" names — these accept reads/writes without
/// going through `make_vol`. Mirrors MinIO's `.minio.sys/{tmp,multipart}`
/// pattern: in-progress writes land under `STAGING_VOL`, completed
/// objects are atomically promoted via `rename_data`. Multipart upload
/// sessions live under `MULTIPART_VOL` keyed by `sha256(bucket/key)`.
pub const STAGING_VOL:    &str = ".phenomenal.staging";
pub const MULTIPART_VOL:  &str = ".phenomenal.multipart";
/// Holds bucket-meta and other engine-internal config as ordinary
/// objects under it. Mirrors MinIO's `.minio.sys`. Bootstrapped at
/// `LocalFsBackend::new` and never created/deleted via the user API.
pub const SYSTEM_BUCKET:  &str = ".phenomenal.sys";

fn is_system_vol(volume: &str) -> bool {
    volume == STAGING_VOL || volume == MULTIPART_VOL || volume == SYSTEM_BUCKET
}

pub struct LocalFsBackend {
    root:  PathBuf,
    trash: PathBuf,
}

impl LocalFsBackend {
    /// Eagerly ensures the drive root and trash dir exist. Failing here
    /// refuses to initialise the drive — the caller gets the underlying
    /// `io::Error`.
    pub fn new(root: impl Into<PathBuf>) -> std::io::Result<Self> {
        let root: PathBuf = root.into();
        std::fs::create_dir_all(&root)?;
        let trash = root.join(TRASH_DIRNAME);
        std::fs::create_dir_all(&trash)?;
        std::fs::create_dir_all(root.join(STAGING_VOL))?;
        std::fs::create_dir_all(root.join(MULTIPART_VOL))?;
        std::fs::create_dir_all(root.join(SYSTEM_BUCKET))?;
        Ok(Self { root, trash })
    }

    /// Sweep `STAGING_VOL` (and `MULTIPART_VOL` later) for orphan
    /// `{staging_id}/` dirs older than `min_age`. Each entry is the
    /// scratch space of a previous PUT; a successful PUT removes its
    /// own dir at S-8, so anything left behind belongs to a crashed
    /// or aborted call. Mirrors MinIO's startup `cleanupTmpUploads`
    /// (`erasure-multipart.go:225-260`).
    ///
    /// `min_age` guards against racing with active PUTs: a freshly
    /// created staging dir whose mtime is recent is left alone.
    /// One hour matches MinIO's default for tmp scrub.
    ///
    /// Reads the entire `STAGING_VOL` directory once; for each child
    /// older than `min_age`, recursively removes it via `move_to_trash`
    /// (which renames into `.phenomenal.trash` and spawns a detached
    /// purge task — same as `delete(recursive=true)`).
    pub async fn scrub_staging(&self, min_age: std::time::Duration) -> std::io::Result<usize> {
        let staging = self.root.join(STAGING_VOL);
        let rd = match std::fs::read_dir(&staging) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(e),
        };
        let now = std::time::SystemTime::now();
        let mut purged = 0usize;
        for ent in rd {
            let ent  = match ent { Ok(e) => e, Err(_) => continue };
            let meta = match ent.metadata() { Ok(m) => m, Err(_) => continue };
            if !meta.is_dir() {
                // Stray non-dir under STAGING_VOL — unlink unconditionally.
                let _ = std::fs::remove_file(ent.path());
                continue;
            }
            let mtime = meta.modified().unwrap_or(std::time::UNIX_EPOCH);
            let age = now.duration_since(mtime).unwrap_or_default();
            if age < min_age {
                continue; // active or recent — leave alone
            }
            // Move into .phenomenal.trash and detach the recursive
            // purge so the scrub call returns quickly.
            if self.move_to_trash(&ent.path()).await.is_ok() {
                purged += 1;
            }
        }
        Ok(purged)
    }

    fn vol_path(&self, volume: &str) -> PathBuf { self.root.join(volume) }

    fn file_path(&self, volume: &str, path: &str) -> PathBuf {
        let mut p = self.root.join(volume);
        for seg in path.split('/').filter(|s| !s.is_empty()) {
            p.push(seg);
        }
        p
    }

    fn meta_path(&self, volume: &str, path: &str) -> PathBuf {
        self.file_path(volume, path).join(META_FILENAME)
    }

    async fn require_vol(&self, volume: &str) -> IoResult<()> {
        if is_system_vol(volume) {
            // System volumes are auto-created on demand: in-progress
            // writes (STAGING_VOL) and multipart sessions (MULTIPART_VOL)
            // can land before any user action that would trigger
            // `make_vol`. Idempotent `create_dir_all`.
            compio::fs::create_dir_all(self.vol_path(volume)).await
                .map_err(IoError::Io)?;
            return Ok(());
        }
        match compio::fs::metadata(self.vol_path(volume)).await {
            Ok(m) if m.is_dir() => Ok(()),
            Ok(_)               => Err(IoError::VolumeNotFound(volume.to_owned())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound =>
                Err(IoError::VolumeNotFound(volume.to_owned())),
            Err(e) => Err(IoError::Io(e)),
        }
    }

    /// One-syscall rename into the trash dir; the subtree walk and
    /// per-entry unlinks run as a detached compio task on the current
    /// runtime.
    async fn move_to_trash(&self, target: &Path) -> std::io::Result<()> {
        let slot = self.trash.join(Uuid::new_v4().simple().to_string());
        compio::fs::rename(target, &slot).await?;
        compio::runtime::spawn(async move {
            let _ = purge_tree(slot).await;
        })
        .detach();
        Ok(())
    }
}

/// Recursively unlink every entry under `root`, then remove `root`.
async fn purge_tree(root: PathBuf) -> std::io::Result<()> {
    let mut files = Vec::new();
    let mut dirs  = Vec::new();
    let mut stack = vec![root];

    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(it)                                             => it,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e)                                             => return Err(e),
        };
        for entry in entries {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                stack.push(entry.path());
            } else {
                files.push(entry.path());
            }
        }
        dirs.push(dir);
    }

    for f in &files {
        let _ = compio::fs::remove_file(f).await;
    }
    for d in dirs.iter().rev() {
        let _ = compio::fs::remove_dir(d).await;
    }
    Ok(())
}

fn map_open_err(e: std::io::Error, volume: &str, path: &str) -> IoError {
    match e.kind() {
        std::io::ErrorKind::NotFound      => IoError::FileNotFound      { volume: volume.into(), path: path.into() },
        std::io::ErrorKind::AlreadyExists => IoError::FileAlreadyExists { volume: volume.into(), path: path.into() },
        _                                 => IoError::Io(e),
    }
}

async fn fsync_dir(dir: &Path) -> IoResult<()> {
    let f = File::open(dir).await.map_err(IoError::Io)?;
    f.sync_all().await.map_err(IoError::Io)?;
    f.close().await.map_err(IoError::Io)
}

async fn atomic_write_with<F, Fut>(final_path: &Path, write_fn: F) -> IoResult<()>
where
    F:   FnOnce(File) -> Fut,
    Fut: std::future::Future<Output = IoResult<File>>,
{
    let parent = final_path.parent()
        .ok_or_else(|| IoError::InvalidArgument(
            format!("atomic_write_with: no parent for {}", final_path.display())
        ))?
        .to_path_buf();
    let fname = final_path.file_name()
        .ok_or_else(|| IoError::InvalidArgument(
            format!("atomic_write_with: empty filename for {}", final_path.display())
        ))?
        .to_string_lossy()
        .into_owned();
    let tmp_path = parent.join(format!(".{fname}.{}.tmp", Uuid::new_v4().simple()));

    let result: IoResult<()> = async {
        let file = OpenOptions::new()
            .create_new(true).write(true)
            .open(&tmp_path).await.map_err(IoError::Io)?;
        let file = write_fn(file).await?;
        file.sync_all().await.map_err(IoError::Io)?;
        file.close().await.map_err(IoError::Io)?;
        compio::fs::rename(&tmp_path, final_path).await.map_err(IoError::Io)?;
        fsync_dir(&parent).await
    }.await;

    if result.is_err() {
        let _ = compio::fs::remove_file(&tmp_path).await;
    }
    result
}

async fn atomic_write_bytes(final_path: &Path, bytes: Vec<u8>) -> IoResult<()> {
    atomic_write_with(final_path, |mut file| async move {
        let compio::buf::BufResult(res, _) = file.write_all_at(bytes, 0).await;
        res.map_err(IoError::Io)?;
        Ok(file)
    }).await
}

/// `ByteStream` over an open compio `File`, bounded to `[pos, end)`.
/// The `scratch` Vec is recycled across reads so the steady-state read
/// path allocates only on the first call.
struct LocalFileStream {
    file: File,
    pos:  u64,
    end:  u64,
}

#[async_trait(?Send)]
impl ByteStream for LocalFileStream {
    async fn read(&mut self) -> IoResult<bytes::Bytes> {
        use compio::buf::IoBuf;
        let want = (self.end - self.pos).min(crate::tuning::STREAM_CHUNK_BYTES as u64) as usize;
        if want == 0 {
            return Ok(bytes::Bytes::new());
        }
        // Fresh PooledBuffer per read — kernel writes into it, then
        // we `freeze()` to hand ownership to a refcounted `Bytes`.
        // The pool slot is recycled when the Bytes refcount drops.
        let buf = PooledBuffer::with_capacity(want);
        let slice = buf.slice(0..want);
        let BufResult(res, slice_back) = (&self.file).read_at(slice, self.pos).await;
        let mut buf = slice_back.into_inner();
        let n = res.map_err(IoError::Io)?;
        self.pos += n as u64;
        buf.truncate(n);
        Ok(buf.freeze())
    }
}

impl Drop for LocalFileStream {
    fn drop(&mut self) {
        // compio's `File` closes on drop via its Drop impl. No explicit
        // close needed here.
    }
}

/// `ByteSink` over an open compio `File`. Each `write_all` does one or
/// more `write_at` calls at the running offset; `finish` `fsync`s and
/// closes the file. The scratch Vec is recycled across writes so the
/// hot path never re-allocates.
struct LocalFileSink {
    file:    Option<File>,
    pos:     u64,
    expected: u64,
    written:  u64,
}

#[async_trait(?Send)]
impl ByteSink for LocalFileSink {
    async fn write_all(&mut self, buf: bytes::Bytes) -> IoResult<()> {
        if buf.is_empty() {
            return Ok(());
        }
        let file = match self.file.as_ref() {
            Some(f) => f,
            None    => return Err(IoError::Io(std::io::Error::other("write after finish"))),
        };
        let total = buf.len();
        write_all_bytes_at(file, buf, self.pos).await?;
        self.pos     += total as u64;
        self.written += total as u64;
        Ok(())
    }

    async fn finish(&mut self) -> IoResult<()> {
        if self.written != self.expected {
            return Err(IoError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                format!("create_file_writer: wrote {}/{}", self.written, self.expected),
            )));
        }
        if let Some(file) = self.file.take() {
            file.sync_all().await.map_err(IoError::Io)?;
            file.close().await.map_err(IoError::Io)?;
        }
        Ok(())
    }
}

#[async_trait(?Send)]
impl StorageBackend for LocalFsBackend {
    fn label(&self) -> String { format!("local_fs:{}", self.root.display()) }

    async fn disk_info(&self) -> IoResult<DiskInfo> {
        let cpath = CString::new(self.root.as_os_str().as_bytes())
            .map_err(|_| IoError::InvalidArgument("root path contains NUL".into()))?;
        let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::statvfs(cpath.as_ptr(), &mut s) } != 0 {
            return Err(IoError::Io(std::io::Error::last_os_error()));
        }
        let bsize = s.f_frsize as u64;
        let total = s.f_blocks as u64 * bsize;
        let free  = s.f_bavail as u64 * bsize;
        Ok(DiskInfo {
            total,
            free,
            used:        total.saturating_sub(free),
            used_inodes: (s.f_files as u64).saturating_sub(s.f_favail as u64),
            free_inodes: s.f_favail as u64,
            fs_type:     String::new(),
            root_disk:   false,
            healing:     false,
            endpoint:    String::new(),
            mount_path:  self.root.display().to_string(),
            id:          self.root.display().to_string(),
        })
    }

    async fn make_vol(&self, volume: &str) -> IoResult<()> {
        if volume.is_empty() || volume.contains('/') || volume.contains('\0') {
            return Err(IoError::InvalidArgument(format!("volume {volume:?}")));
        }
        match compio::fs::create_dir(self.vol_path(volume)).await {
            Ok(())                                                  => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Err(IoError::VolumeExists(volume.into())),
            Err(e)                                                  => Err(IoError::Io(e)),
        }
    }

    async fn list_vols(&self) -> IoResult<Vec<VolInfo>> {
        let rd = match std::fs::read_dir(&self.root) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(IoError::Io(e)),
        };
        let mut out = Vec::new();
        for ent in rd {
            let ent  = ent.map_err(IoError::Io)?;
            let name = match ent.file_name().into_string() {
                Ok(s)  => s,
                Err(_) => continue,
            };
            if name.starts_with('.') { continue; }
            let meta = ent.metadata().map_err(IoError::Io)?;
            if !meta.is_dir() { continue; }
            out.push(VolInfo { name });
        }
        Ok(out)
    }

    async fn stat_vol(&self, volume: &str) -> IoResult<VolInfo> {
        match compio::fs::metadata(self.vol_path(volume)).await {
            Ok(m) if m.is_dir() => {}
            _                   => return Err(IoError::VolumeNotFound(volume.into())),
        }
        Ok(VolInfo { name: volume.into() })
    }

    async fn delete_vol(&self, volume: &str, force_delete: bool) -> IoResult<()> {
        let p = self.vol_path(volume);
        let result = if force_delete {
            match self.move_to_trash(&p).await {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound =>
                    Err(IoError::VolumeNotFound(volume.into())),
                Err(e) => Err(IoError::Io(e)),
            }
        } else {
            match compio::fs::remove_dir(&p).await {
                Ok(())                                                   => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound       => Err(IoError::VolumeNotFound(volume.into())),
                Err(e) if e.raw_os_error() == Some(libc::ENOTEMPTY)      => Err(IoError::VolumeNotEmpty(volume.into())),
                Err(e)                                                   => Err(IoError::Io(e)),
            }
        };
        result
    }

    async fn list_dir(&self, volume: &str, dir_path: &str, count: usize) -> IoResult<Vec<String>> {
        self.require_vol(volume).await?;
        // todo: @arnav this is dangerous we should probably reconsider/use spawn blocking
        let rd = match std::fs::read_dir(self.file_path(volume, dir_path)) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(IoError::Io(e)),
        };
        let limit = if count == 0 { usize::MAX } else { count };
        let mut out = Vec::new();
        for ent in rd {
            if out.len() >= limit { break; }
            let ent = ent.map_err(IoError::Io)?;
            if let Ok(s) = ent.file_name().into_string() { out.push(s); }
        }
        Ok(out)
    }

    /// Streaming read. Returns a `ByteStream` that owns the open file
    /// for the lifetime of the read; the caller pulls bytes in arbitrary
    /// chunk sizes and the stream EOFs after `length` bytes.
    async fn read_file_stream(
        &self,
        volume: &str,
        path: &str,
        offset: u64,
        length: u64,
    ) -> IoResult<Box<dyn ByteStream>> {
        self.require_vol(volume).await?;
        let file = File::open(self.file_path(volume, path))
            .await
            .map_err(|e| map_open_err(e, volume, path))?;
        Ok(Box::new(LocalFileStream {
            file,
            pos:     offset,
            end:     offset + length,
        }))
    }

    /// Open a streaming writer over the new file. The returned sink
    /// owns the open `File`; each `write_all` lands in `io_uring`'s
    /// `write_at` at the running offset. `finish` `fsync`s and
    /// closes the file. No per-object buffer ever exists.
    async fn create_file_writer(
        &self,
        volume: &str,
        path: &str,
        size: u64,
    ) -> IoResult<Box<dyn ByteSink>> {
        self.require_vol(volume).await?;
        let p = self.file_path(volume, path);
        if let Some(parent) = p.parent() {
            compio::fs::create_dir_all(parent).await.map_err(IoError::Io)?;
        }
        let file = OpenOptions::new()
            .create(true).truncate(true).write(true).read(true)
            .open(&p).await.map_err(|e| map_open_err(e, volume, path))?;
        Ok(Box::new(LocalFileSink {
            file:     Some(file),
            pos:      0,
            expected: size,
            written:  0,
        }))
    }

    async fn rename_file(
        &self, src_volume: &str, src_path: &str, dst_volume: &str, dst_path: &str,
    ) -> IoResult<()> {
        self.require_vol(src_volume).await?;
        self.require_vol(dst_volume).await?;
        let src = self.file_path(src_volume, src_path);
        let dst = self.file_path(dst_volume, dst_path);
        if let Some(parent) = dst.parent() {
            compio::fs::create_dir_all(parent).await.map_err(IoError::Io)?;
        }
        compio::fs::rename(&src, &dst).await.map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => IoError::FileNotFound { volume: src_volume.into(), path: src_path.into() },
            _                            => IoError::Io(e),
        })
    }

    async fn check_file(&self, volume: &str, path: &str) -> IoResult<()> {
        self.require_vol(volume).await?;
        match compio::fs::metadata(self.file_path(volume, path)).await {
            Ok(_)                                              => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound =>
                Err(IoError::FileNotFound { volume: volume.into(), path: path.into() }),
            Err(e) => Err(IoError::Io(e)),
        }
    }

    async fn delete(&self, volume: &str, path: &str, recursive: bool) -> IoResult<()> {
        self.require_vol(volume).await?;
        let p = self.file_path(volume, path);
        let meta = match compio::fs::metadata(&p).await {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound =>
                return Err(IoError::FileNotFound { volume: volume.into(), path: path.into() }),
            Err(e) => return Err(IoError::Io(e)),
        };
        if meta.is_dir() {
            if recursive { self.move_to_trash(&p).await.map_err(IoError::Io) }
            else         { compio::fs::remove_dir(&p).await.map_err(IoError::Io) }
        } else {
            compio::fs::remove_file(&p).await.map_err(IoError::Io)
        }
    }

    async fn write_metadata(
        &self, _orig_volume: &str, volume: &str, path: &str, fi: &FileInfo,
    ) -> IoResult<()> {
        self.require_vol(volume).await?;
        let dir        = self.file_path(volume, path);
        compio::fs::create_dir_all(&dir).await.map_err(IoError::Io)?;
        let encoded    = xl_meta::encode(fi)?;
        let final_path = dir.join(META_FILENAME);
        atomic_write_with(&final_path, |file| async move {
            write_xl_meta_vectored(&file, encoded).await?;
            Ok(file)
        }).await
    }

    async fn read_version(
        &self, _orig_volume: &str, volume: &str, path: &str,
        version_id: Option<&str>, read_data: bool,
    ) -> IoResult<FileInfo> {
        self.require_vol(volume).await?;
        let bytes = match compio::fs::read(self.meta_path(volume, path)).await {
            Ok(b) => bytes::Bytes::from(b),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound =>
                return Err(IoError::FileNotFound { volume: volume.into(), path: path.into() }),
            Err(e) => return Err(IoError::Io(e)),
        };
        // Pick the right version. `None` (latest) goes through
        // `decode`; `Some(id)` looks up that specific version via
        // `find_version`. Each version independently chooses inline
        // (zero-copy `Bytes::slice` into the xl.meta tail) vs
        // `data_dir/part.N` on disk; the decoder populates
        // `rec.inline` for inline versions and leaves it `None`
        // when the version's bytes live on disk.
        let rec = match version_id {
            None => xl_meta::decode(bytes),
            Some(id) => match xl_meta::find_version(bytes, id)? {
                Some(r) => Ok(r),
                None    => return Err(IoError::FileVersionNotFound {
                    volume: volume.into(), path: path.into(), version_id: id.into(),
                }),
            },
        }.map_err(|e| match e {
            IoError::CorruptMetadata { msg, .. } => IoError::CorruptMetadata {
                volume: volume.to_owned(), path: path.to_owned(), msg,
            },
            other => other,
        })?;
        let mut fi = xl_meta::file_info_from_record(rec, volume, path);
        if !read_data { fi.data = None; }
        Ok(fi)
    }

    async fn update_metadata(
        &self, volume: &str, path: &str, fi: &FileInfo, _opts: &UpdateMetadataOpts,
    ) -> IoResult<()> {
        self.write_metadata("", volume, path, fi).await
    }

    /// `undo_write=true` restores `xl.meta.bkp → xl.meta` (atomic
    /// rename, the commit point of the undo) then trashes the orphan
    /// `fi.data_dir`. No bkp on disk → fall through to hard-delete.
    /// `undo_write=false` is the legacy recursive remove.
    async fn delete_version(
        &self, volume: &str, path: &str, fi: &FileInfo,
        _force_del_marker: bool, opts: &DeleteOptions,
    ) -> IoResult<()> {
        if !opts.undo_write {
            return self.delete(volume, path, true).await;
        }

        let object_dir = self.file_path(volume, path);
        let bkp_path   = object_dir.join(META_BACKUP_FILENAME);
        let live_meta  = object_dir.join(META_FILENAME);

        // Step 1 (commit point of the undo): atomically restore prior
        // xl.meta from bkp. NotFound here means there is no backup to
        // restore — fall back to hard-delete so the engine's caller
        // sees a consistent "version is gone" outcome.
        match compio::fs::rename(&bkp_path, &live_meta).await {
            Ok(())                                                 => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound     => {
                return self.delete(volume, path, true).await;
            }
            Err(e)                                                 => return Err(IoError::Io(e)),
        }
        // Persist the rename's dir-entry change.
        fsync_dir(&object_dir).await?;

        // Step 2 (cleanup): the new (rolled-back) xl.meta points at
        // the prior data_dir, leaving `fi.data_dir` orphan. Best-
        // effort move-to-trash; failure here only leaks disk space.
        if !fi.data_dir.is_empty() {
            let new_data_dir = object_dir.join(&fi.data_dir);
            let _ = self.move_to_trash(&new_data_dir).await;
        }
        Ok(())
    }

    /// Atomic per-disk promotion 
    /// Reads the live
    /// xl.meta at `dst`, merges `fi` into the versions array
    /// (preserving prior versions with different `version_id`),
    /// stages the merged xl.meta in the source's staging dir, moves
    /// the staged data dir into place under `dst`, then atomically
    /// renames the staged xl.meta over the live one. Returns the
    /// previous-version `old_data_dir` (if the SAME `version_id` was
    /// being replaced) so the engine can purge it post-commit.
    ///
    /// State transitions (matches the MinIO 8-state trace):
    ///   * S-3 → S-4: write merged xl.meta to
    ///     `STAGING_VOL/{src_path}/xl.meta`
    ///   * S-4 → S-5: rename `STAGING_VOL/{src_path}/{data_dir}` →
    ///     `dst/{data_dir}` (data_dir grafted into live tree)
    ///   * S-5 → S-7: rename `STAGING_VOL/{src_path}/xl.meta` →
    ///     `dst/xl.meta` (commit point — atomic versions-array swap)
    ///   * S-7 → S-8: best-effort rmdir of `STAGING_VOL/{src_path}`
    ///
    /// Failures: each step that errors returns immediately leaving
    /// the live state untouched (no half-applied versions). The
    /// caller's quorum check + per-disk undo handles minority
    /// successes.
    async fn rename_data(
        &self, src_volume: &str, src_path: &str, fi: &FileInfo,
        dst_volume: &str, dst_path: &str, _opts: &RenameOptions,
    ) -> IoResult<RenameDataResp> {
        if !is_system_vol(src_volume) {
            return Err(IoError::InvalidArgument(format!(
                "rename_data: src_volume must be a system volume (got {src_volume})"
            )));
        }
        self.require_vol(dst_volume).await?;

        let dst_meta_path = self.meta_path(dst_volume, dst_path);

        let (pre_xl_meta_raw, existing_versions):
            (Option<bytes::Bytes>, Vec<DecodedRecord>) =
            match compio::fs::read(&dst_meta_path).await {
                Ok(b) => {
                    let raw = bytes::Bytes::from(b);
                    let all = xl_meta::decode_all(raw.clone()).map_err(|e| match e {
                        IoError::CorruptMetadata { msg, .. } => IoError::CorruptMetadata {
                            volume: dst_volume.to_owned(), path: dst_path.to_owned(), msg,
                        },
                        other => other,
                    })?;
                    (Some(raw), all)
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => (None, Vec::new()),
                Err(e) => return Err(IoError::Io(e)),
            };

        let prior_same_vid_existed = existing_versions.iter()
            .any(|r| r.version_id == fi.version_id);
        let old_data_dir: Option<String> = existing_versions.iter()
            .find(|r| r.version_id == fi.version_id)
            .map(|r| r.data_dir.clone())
            .filter(|s| !s.is_empty() && s != &fi.data_dir);

        let new_fi_version = fi.version_id.clone();

        let mut merged: Vec<FileInfo> = Vec::with_capacity(existing_versions.len() + 1);
        for rec in existing_versions.into_iter() {
            if rec.version_id == new_fi_version {
                continue; // this will be recreated below
            }
            let fi_existing = xl_meta::file_info_from_record(rec, dst_volume, dst_path);
            merged.push(fi_existing);
        }
        merged.push(fi.clone());

        // todo: @arnav check if this is redundant nad and dont really need repeated sort.
        merged.sort_by(|a, b| b.mod_time_ms.cmp(&a.mod_time_ms));

        let encoded = xl_meta::encode_versions(&merged)?;
        let staged_object_dir = self.file_path(src_volume, src_path);
        compio::fs::create_dir_all(&staged_object_dir).await.map_err(IoError::Io)?;
        let staged_meta_path = staged_object_dir.join(META_FILENAME);
        {
            let f = OpenOptions::new()
                .create(true).truncate(true).write(true)
                .open(&staged_meta_path).await.map_err(IoError::Io)?;
            write_xl_meta_vectored(&f, encoded).await?;
            f.sync_all().await.map_err(IoError::Io)?;
            f.close().await.map_err(IoError::Io)?;
        }

        // Move the staged data dir into the live
        //              tree. After this point the new BBBB/part.1
        //              lives at dst, but xl.meta still references
        //              only the prior versions — orphan window.
        let src_data_dir = staged_object_dir.join(&fi.data_dir);
        let has_data_dir = !fi.data_dir.is_empty()
            && compio::fs::metadata(&src_data_dir).await
                .map(|m| m.is_dir()).unwrap_or(false);
        if has_data_dir {
            let dst_object_dir = self.file_path(dst_volume, dst_path);
            compio::fs::create_dir_all(&dst_object_dir).await.map_err(IoError::Io)?;
            let dst_data_dir = dst_object_dir.join(&fi.data_dir);
            compio::fs::rename(&src_data_dir, &dst_data_dir).await
                .map_err(IoError::Io)?;
        }

        if prior_same_vid_existed {
            if let Some(raw) = pre_xl_meta_raw.as_ref() {
                let dst_object_dir = self.file_path(dst_volume, dst_path);
                compio::fs::create_dir_all(&dst_object_dir).await.map_err(IoError::Io)?;
                let bkp_path = dst_object_dir.join(META_BACKUP_FILENAME);
                let f = OpenOptions::new()
                    .create(true).truncate(true).write(true)
                    .open(&bkp_path).await.map_err(IoError::Io)?;
                write_all_bytes_at(&f, raw.clone(), 0).await?;
                f.sync_all().await.map_err(IoError::Io)?;
                f.close().await.map_err(IoError::Io)?;
            }
        }

        // Atomic rename
        let dst_object_dir = self.file_path(dst_volume, dst_path);
        compio::fs::create_dir_all(&dst_object_dir).await.map_err(IoError::Io)?;
        compio::fs::rename(&staged_meta_path, &dst_meta_path).await
            .map_err(IoError::Io)?;
        fsync_dir(&dst_object_dir).await?;

        let _ = compio::fs::remove_dir(&staged_object_dir).await;

        Ok(RenameDataResp {
            sign:         Vec::new(),
            old_data_dir: old_data_dir.unwrap_or_default(),
        })
    }

    async fn verify_file(&self, volume: &str, path: &str, _fi: &FileInfo) -> IoResult<()> {
        self.check_file(volume, path).await
    }

    async fn read_format(&self) -> IoResult<Option<crate::types::FormatJson>> {
        let path = self.root.join(FORMAT_FILENAME);
        match compio::fs::read(&path).await {
            Ok(bytes) => {
                let fmt: crate::types::FormatJson = serde_json::from_slice(&bytes)
                    .map_err(|e| IoError::Decode(format!("format.json: {e}")))?;
                Ok(Some(fmt))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(IoError::Io(e)),
        }
    }

    async fn write_file(&self, volume: &str, path: &str, bytes: Vec<u8>) -> IoResult<()> {
        self.require_vol(volume).await?;
        let final_path = self.file_path(volume, path);
        if let Some(parent) = final_path.parent() {
            compio::fs::create_dir_all(parent).await.map_err(IoError::Io)?;
        }
        atomic_write_bytes(&final_path, bytes).await
    }

    async fn read_file(&self, volume: &str, path: &str) -> IoResult<Option<Vec<u8>>> {
        self.require_vol(volume).await?;
        let final_path = self.file_path(volume, path);
        match compio::fs::read(&final_path).await {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(IoError::Io(e)),
        }
    }

    async fn make_dir_all(&self, volume: &str, path: &str) -> IoResult<()> {
        self.require_vol(volume).await?;
        let dir = self.file_path(volume, path);
        compio::fs::create_dir_all(&dir).await.map_err(IoError::Io)
    }

    async fn write_format(&self, fmt: &crate::types::FormatJson) -> IoResult<()> {
        let bytes = serde_json::to_vec_pretty(fmt)
            .map_err(|e| IoError::Encode(format!("format.json: {e}")))?;
        atomic_write_bytes(&self.root.join(FORMAT_FILENAME), bytes).await
    }
}

/// Write an `EncodedXlMeta` (head + optional tail) to `file` at offset
/// 0. When both segments are present, submits them as one io_uring
/// `writev` SQE — kernel scatter-gathers from the two distinct
/// allocations, no userspace memcpy of the inline payload. When there
/// is no inline tail, falls back to a single `write_at`. Partial
/// writes are handled by compio's `write_vectored_all_at`, which
/// loops the SQE for whatever the kernel didn't drain.
async fn write_xl_meta_vectored(
    mut file: &File,
    encoded: xl_meta::EncodedXlMeta,
) -> IoResult<()> {
    let xl_meta::EncodedXlMeta { head, tail } = encoded;

    if tail.is_empty() {
        let BufResult(res, _) = file.write_all_at(head, 0).await;
        return res.map_err(IoError::Io);
    }
    let mut iovecs: Vec<bytes::Bytes> = Vec::with_capacity(1 + tail.len());
    iovecs.push(head);
    iovecs.extend(tail);
    let BufResult(res, _) = file.write_vectored_all_at(iovecs, 0).await;
    res.map_err(IoError::Io)
}

/// Write a `Bytes` at `base_offset` in full. compio's `write_all_at`
/// loops on partial writes internally; we just unwrap the result.
/// `Bytes` impls `IoBuf`, so the kernel writes from the same
/// allocation we hand in — no userspace memcpy.
async fn write_all_bytes_at(mut file: &File, buf: bytes::Bytes, base_offset: u64) -> IoResult<()> {
    let BufResult(res, _) = file.write_all_at(buf, base_offset).await;
    res.map_err(IoError::Io)
}

/// Loop `compio::fs::File::write_at` until the buffer is fully written.
/// Returns the drained [`PooledBuffer`] so callers can recycle the
/// allocation. Partial writes are tracked via `Slice<PooledBuffer>` —
/// `AVec` does not provide a Vec-style `drain`, so we slice the
/// unsent tail forward with an updating `offset`.
#[allow(dead_code)]
async fn write_all_at(mut file: &File, mut buf: PooledBuffer, base_offset: u64) -> IoResult<PooledBuffer> {
    use compio::buf::IoBuf;
    let total = buf.len();
    let mut written = 0;
    while written < total {
        let slice = buf.slice(written..total);
        // todo: @arnav this seems inefficient can we do something optimal for nvme
        let BufResult(res, slice_back) = file.write_at(slice, base_offset + written as u64).await;
        buf = slice_back.into_inner();
        let n = res.map_err(IoError::Io)?;
        if n == 0 {
            return Err(IoError::Io(std::io::Error::other("write returned 0")));
        }
        written += n;
    }
    buf.clear();
    Ok(buf)
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream::{pump_n, read_full, VecByteStream};
    use bytes::Bytes;
    use tempfile::tempdir;

    /// Test helper: open a writer, pump a `Vec<u8>` through it as a
    /// `ByteStream`, finish. Mirrors what the S3 frontend will do for
    /// non-EC paths and what the engine fan-out does per backend.
    async fn put_bytes(be: &LocalFsBackend, vol: &str, path: &str, bytes: &[u8]) -> IoResult<()> {
        let mut sink = be.create_file_writer(vol, path, bytes.len() as u64).await?;
        let mut src  = VecByteStream::new(bytes.to_vec());
        pump_n(&mut src, sink.as_mut(), bytes.len() as u64).await?;
        sink.finish().await
    }

    fn fi_inline(volume: &str, name: &str, data: &[u8]) -> FileInfo {
        use crate::types::{ErasureInfo, ObjectPartInfo};
        let mut fi = FileInfo::default();
        fi.volume       = volume.into();
        fi.name         = name.into();
        fi.size         = data.len() as i64;
        fi.mod_time_ms  = 1_700_000_000_000;
        fi.data         = Some(vec![Bytes::copy_from_slice(data)]);
        fi.is_latest    = true;
        fi.num_versions = 1;
        fi.fresh        = true;
        fi.parts        = vec![ObjectPartInfo {
            etag:        "x".into(),
            number:      1,
            size:        data.len() as i64,
            actual_size: data.len() as i64,
            mod_time_ms: 1_700_000_000_000,
            ..Default::default()
        }];
        // EC[1+0] is the minimal valid erasure layout that satisfies
        // the strict validator for a single-disk test backend.
        fi.erasure = ErasureInfo {
            algorithm:    "ReedSolomon".into(),
            data_blocks:  1,
            parity_blocks: 0,
            index:        1,
            block_size:   1_048_576,
            distribution: vec![1],
            checksums:    Vec::new(),
        };
        fi
    }

    /// Small helper: drain a `ByteStream` into a Vec for assertions.
    /// Tests only — production code never collects a full stream.
    async fn drain(mut s: Box<dyn ByteStream>, expected: usize) -> Vec<u8> {
        let mut buf = vec![0u8; expected];
        let n = read_full(s.as_mut(), &mut buf[..]).await.unwrap();
        buf.truncate(n);
        buf
    }

    #[compio::test]
    async fn vol_crud() {
        let dir = tempdir().unwrap();
        let be = LocalFsBackend::new(dir.path()).unwrap();
        be.make_vol("b").await.unwrap();
        assert!(matches!(be.make_vol("b").await, Err(IoError::VolumeExists(_))));
        assert_eq!(be.stat_vol("b").await.unwrap().name, "b");
        assert_eq!(be.list_vols().await.unwrap().len(), 1);
        be.delete_vol("b", false).await.unwrap();
    }

#[compio::test]
    async fn list_vols_hides_trash_dir() {
        let dir = tempdir().unwrap();
        let be  = LocalFsBackend::new(dir.path()).unwrap();
        be.make_vol("b").await.unwrap();
        let names: Vec<String> = be.list_vols().await.unwrap().into_iter().map(|v| v.name).collect();
        assert_eq!(names, vec!["b".to_string()]);
    }

    #[compio::test]
    async fn write_read_metadata_round_trip() {
        let dir = tempdir().unwrap();
        let be = LocalFsBackend::new(dir.path()).unwrap();
        be.make_vol("b").await.unwrap();
        let fi = fi_inline("b", "k", b"hello");
        be.write_metadata("", "b", "k", &fi).await.unwrap();
        let back = be.read_version("", "b", "k", None, true).await.unwrap();
        assert_eq!(back.size, 5);
        let inline_concat: Vec<u8> = back.data.as_ref().unwrap().iter()
            .flat_map(|f| f.iter().copied()).collect();
        assert_eq!(inline_concat, b"hello".to_vec());
        assert!(be.read_version("", "b", "k", None, false).await.unwrap().data.is_none());
    }

    #[compio::test]
    async fn write_metadata_leaves_no_temp_files() {
        let dir = tempdir().unwrap();
        let be = LocalFsBackend::new(dir.path()).unwrap();
        be.make_vol("b").await.unwrap();
        be.write_metadata("", "b", "k", &fi_inline("b", "k", b"x")).await.unwrap();
        let entries: Vec<String> = std::fs::read_dir(dir.path().join("b").join("k"))
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(entries, vec![META_FILENAME.to_string()]);
    }

    #[compio::test]
    async fn create_and_read_file_stream() {
        let dir = tempdir().unwrap();
        let be = LocalFsBackend::new(dir.path()).unwrap();
        be.make_vol("b").await.unwrap();
        let payload: Vec<u8> = (0..4096).map(|i| (i % 251) as u8).collect();
        put_bytes(&be, "b", "obj/part.1", &payload).await.unwrap();
        let stream = be.read_file_stream("b", "obj/part.1", 0, 4096).await.unwrap();
        let read = drain(stream, 4096).await;
        assert_eq!(read, payload);
    }

    /// Multi-MiB payload — exercises the writer's `write_at` loop
    /// across more than one chunk and confirms the recycled scratch
    /// Vec stays in shape across iterations.
    #[compio::test]
    async fn create_and_read_large_stream() {
        let dir = tempdir().unwrap();
        let be = LocalFsBackend::new(dir.path()).unwrap();
        be.make_vol("b").await.unwrap();
        let size = 3 * 1024 * 1024 + 17;
        let payload: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        put_bytes(&be, "b", "big", &payload).await.unwrap();
        let stream = be.read_file_stream("b", "big", 0, size as u64).await.unwrap();
        let read = drain(stream, size).await;
        assert_eq!(read.len(), payload.len());
        assert_eq!(read, payload);
    }

    #[compio::test]
    async fn rename_file_atomic() {
        let dir = tempdir().unwrap();
        let be = LocalFsBackend::new(dir.path()).unwrap();
        be.make_vol("b").await.unwrap();
        put_bytes(&be, "b", "stage/x", b"abc").await.unwrap();
        be.rename_file("b", "stage/x", "b", "live/x").await.unwrap();
        assert!(matches!(be.check_file("b", "stage/x").await, Err(IoError::FileNotFound { .. })));
        be.check_file("b", "live/x").await.unwrap();
    }

    #[compio::test]
    async fn read_missing_is_not_found() {
        let dir = tempdir().unwrap();
        let be = LocalFsBackend::new(dir.path()).unwrap();
        be.make_vol("b").await.unwrap();
        let err = be.read_version("", "b", "nope", None, true).await.unwrap_err();
        assert!(matches!(err, IoError::FileNotFound { .. }));
    }

    #[compio::test]
    async fn disk_info_reports_real_capacity() {
        let dir = tempdir().unwrap();
        let info = LocalFsBackend::new(dir.path()).unwrap().disk_info().await.unwrap();
        assert!(info.total > 0);
        assert!(info.free <= info.total);
    }

    #[compio::test]
    async fn force_delete_vol_uses_trash_and_purges() {
        let dir = tempdir().unwrap();
        let be  = LocalFsBackend::new(dir.path()).unwrap();
        be.make_vol("b").await.unwrap();
        put_bytes(&be, "b", "k/part.1", b"xyz").await.unwrap();
        be.delete_vol("b", true).await.unwrap();
        assert!(!dir.path().join("b").exists());
        for _ in 0..50 {
            let empty = std::fs::read_dir(dir.path().join(TRASH_DIRNAME))
                .unwrap()
                .next()
                .is_none();
            if empty { return; }
            compio::runtime::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        panic!("trash dir still has entries after purge window");
    }

    /// L2 invariant: same-`version_id` overwrite writes
    /// `xl.meta.bkp` at `{dst_object_dir}/xl.meta.bkp` before the
    /// xl.meta commit. Verifies the S-6 recovery hint: the backup
    /// holds the EXACT pre-PUT xl.meta bytes so
    /// `delete_version(undo_write=true)` can reconstruct the prior
    /// state if the cluster-wide quorum check later fails.
    #[compio::test]
    async fn rename_data_writes_xl_meta_bkp_on_same_version_overwrite() {
        use crate::types::{ErasureInfo, ObjectPartInfo};
        let dir = tempdir().unwrap();
        let be  = LocalFsBackend::new(dir.path()).unwrap();
        be.make_vol("b").await.unwrap();

        // Helper: build an EC-style FileInfo with the given data_dir
        // and version_id. Caller must place a real `part.1` in
        // STAGING_VOL/{staging_id}/{data_dir}/ before calling
        // rename_data.
        fn fi_ec(data_dir: &str, version_id: &str, etag: &str, mtime: u64) -> FileInfo {
            let mut fi = FileInfo::default();
            fi.volume       = "b".into();
            fi.name         = "obj".into();
            fi.size         = 8;
            fi.mod_time_ms  = mtime;
            fi.version_id   = version_id.into();
            fi.data_dir     = data_dir.into();
            fi.is_latest    = true;
            fi.num_versions = 1;
            fi.fresh        = true;
            fi.parts = vec![ObjectPartInfo {
                etag:        etag.into(),
                number:      1,
                size:        8,
                actual_size: 8,
                mod_time_ms: mtime,
                index:       Vec::new(),
                checksums:   Default::default(),
            }];
            fi.metadata.insert("etag".into(), etag.into());
            fi.erasure = ErasureInfo {
                algorithm:    "ReedSolomon".into(),
                data_blocks:  3,
                parity_blocks: 1,
                index:        1,
                block_size:   4096,
                distribution: vec![1, 2, 3, 4],
                checksums:    Vec::new(),
            };
            fi
        }

        // Helper: stage a part.1 file under
        // STAGING_VOL/{staging_id}/{data_dir}/.
        async fn stage(be: &LocalFsBackend, staging_id: &str, data_dir: &str, bytes: &[u8]) {
            let p = format!("{staging_id}/{data_dir}/part.1");
            let mut sink = be.create_file_writer(STAGING_VOL, &p, bytes.len() as u64).await.unwrap();
            sink.write_all(Bytes::copy_from_slice(bytes)).await.unwrap();
            sink.finish().await.unwrap();
        }

        // First PUT: version_id=V, data_dir=D1.
        let v_id = "11111111-1111-1111-1111-111111111111";
        let d1   = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
        let s1   = "1111111111111111ffffffffffffffff";
        stage(&be, s1, d1, b"version1").await;
        let fi1  = fi_ec(d1, v_id, "etag-v1", 1_700_000_000_000);
        let r1 = be.rename_data(STAGING_VOL, s1, &fi1, "b", "obj", &Default::default())
            .await.unwrap();
        assert!(r1.old_data_dir.is_empty(), "first PUT has no prior version");

        // Second PUT: SAME version_id=V (idempotent overwrite),
        // different data_dir=D2.
        let d2 = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
        let s2 = "2222222222222222ffffffffffffffff";
        stage(&be, s2, d2, b"version2").await;
        let fi2 = fi_ec(d2, v_id, "etag-v2", 1_700_000_000_001);
        let r2 = be.rename_data(STAGING_VOL, s2, &fi2, "b", "obj", &Default::default())
            .await.unwrap();
        // Same version_id → old_data_dir is set so the engine cleans D1.
        assert_eq!(r2.old_data_dir, d1, "same-version_id overwrite must surface old_data_dir");

        // S-6: xl.meta.bkp at `{dst_object_dir}/xl.meta.bkp` holds the
        // pre-second-PUT bytes (the xl.meta written after the first PUT).
        let bkp_path = dir.path().join("b").join("obj").join("xl.meta.bkp");
        assert!(bkp_path.exists(), "xl.meta.bkp must exist at object dir top after same-version overwrite");
        // Backup contents = the live xl.meta written after the FIRST PUT.
        // Our rename_data writes a new xl.meta after the first PUT
        // (only one version: V/D1). Decode it to confirm.
        let bkp_bytes = std::fs::read(&bkp_path).unwrap();
        let bkp_recs = xl_meta::decode_all(Bytes::from(bkp_bytes)).unwrap();
        assert_eq!(bkp_recs.len(), 1, "backup should hold the pre-PUT xl.meta");
        assert_eq!(bkp_recs[0].version_id, v_id);
        assert_eq!(bkp_recs[0].data_dir, d1);
    }

    /// Two consecutive PUTs of the same key under different
    /// `version_id`s, both inline. The new design must keep both
    /// versions' bytes inside xl.meta (per-version inline ranges)
    /// and must NOT spill the older version to a `<data_dir>/part.N`
    /// file on disk. After two PUTs the object dir contains only
    /// `xl.meta` (plus `xl.meta.bkp` if a same-version overwrite
    /// happened — it didn't here).
    #[compio::test]
    async fn rename_data_multi_version_inline_no_spill() {
        use crate::types::{ErasureInfo, ObjectPartInfo};
        let dir = tempdir().unwrap();
        let be  = LocalFsBackend::new(dir.path()).unwrap();
        be.make_vol("b").await.unwrap();

        fn fi_inline_for_rename(vid: &str, body: &[u8], mtime: u64) -> FileInfo {
            let mut fi = FileInfo::default();
            fi.volume       = "b".into();
            fi.name         = "obj".into();
            fi.version_id   = vid.into();
            fi.size         = body.len() as i64;
            fi.mod_time_ms  = mtime;
            fi.data         = Some(vec![Bytes::copy_from_slice(body)]);
            fi.is_latest    = true;
            fi.num_versions = 1;
            fi.fresh        = true;
            fi.parts = vec![ObjectPartInfo {
                etag:        "etag".into(),
                number:      1,
                size:        body.len() as i64,
                actual_size: body.len() as i64,
                mod_time_ms: mtime,
                index:       Vec::new(),
                checksums:   Default::default(),
            }];
            fi.metadata.insert("etag".into(), "etag".into());
            fi.erasure = ErasureInfo {
                algorithm:    "ReedSolomon".into(),
                data_blocks:  1, parity_blocks: 0, index: 1,
                block_size:   1_048_576,
                distribution: vec![1],
                checksums:    Vec::new(),
            };
            fi
        }

        // Inline rename_data needs nothing in STAGING_VOL up front:
        // the staged xl.meta is created during S-4. Just hand it a
        // fresh staging_id per call.
        let v1 = "11111111-1111-1111-1111-111111111111";
        let v2 = "22222222-2222-2222-2222-222222222222";
        let s1 = "11111111111111110000000000000000";
        let s2 = "22222222222222220000000000000000";

        let r1 = be.rename_data(
            STAGING_VOL, s1,
            &fi_inline_for_rename(v1, b"hello-v1", 1_700_000_000_000),
            "b", "obj", &Default::default(),
        ).await.unwrap();
        assert!(r1.old_data_dir.is_empty());

        let r2 = be.rename_data(
            STAGING_VOL, s2,
            &fi_inline_for_rename(v2, b"world-v2-longer-than-v1", 1_700_000_000_001),
            "b", "obj", &Default::default(),
        ).await.unwrap();
        assert!(r2.old_data_dir.is_empty(), "different version_id → no old data_dir");

        // No spill: object dir holds exactly `xl.meta`. No data_dir
        // subdirectories, no part.1 files. (Different version_id
        // means no xl.meta.bkp either.)
        let object_dir = dir.path().join("b").join("obj");
        let mut entries: Vec<String> = std::fs::read_dir(&object_dir).unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        entries.sort();
        assert_eq!(entries, vec![META_FILENAME.to_string()],
            "multi-version inline must not spill anything to disk");

        // Both versions' bytes round-trip through their own
        // inline_offset/inline_length slice — no part.N reads.
        let got_v1 = be.read_version("", "b", "obj", Some(v1), true).await.unwrap();
        let got_v2 = be.read_version("", "b", "obj", Some(v2), true).await.unwrap();
        let body1: Vec<u8> = got_v1.data.as_ref().unwrap().iter()
            .flat_map(|f| f.iter().copied()).collect();
        let body2: Vec<u8> = got_v2.data.as_ref().unwrap().iter()
            .flat_map(|f| f.iter().copied()).collect();
        assert_eq!(body1, b"hello-v1");
        assert_eq!(body2, b"world-v2-longer-than-v1");
    }

    /// L2 invariant: `scrub_staging` removes orphan staging dirs
    /// older than the threshold while leaving fresh ones alone.
    /// Mirrors MinIO's startup `cleanupTmpUploads` semantics.
    #[compio::test]
    async fn scrub_staging_purges_old_orphan_dirs_only() {
        let dir = tempdir().unwrap();
        let be  = LocalFsBackend::new(dir.path()).unwrap();
        let staging = dir.path().join(STAGING_VOL);

        // Plant two orphan staging dirs:
        //   * `old/`   — modified now then back-dated via filetime to
        //                 simulate a stale crashed PUT. We use
        //                 `set_file_mtime` from the filetime crate when
        //                 available; here we just use a simple touch +
        //                 manual mtime via std FileTime trick. As that
        //                 isn't in scope, simulate by making the
        //                 threshold zero so anything pre-existing
        //                 looks "old".
        //   * `fresh/` — exists at the moment of the call.
        let old = staging.join("old");
        let fresh = staging.join("fresh");
        std::fs::create_dir_all(&old).unwrap();
        std::fs::create_dir_all(&fresh).unwrap();
        // Plant a sentinel file inside `old` to confirm recursive
        // delete actually clears the contents.
        std::fs::write(old.join("part.1"), b"orphan-bytes").unwrap();

        // Threshold = 0 so both qualify as "old" and both get reaped.
        let purged = be.scrub_staging(std::time::Duration::ZERO).await.unwrap();
        assert_eq!(purged, 2, "both orphan dirs should be reaped");
        // Wait for detached purges to drain.
        for _ in 0..50 {
            let still = std::fs::metadata(&old).is_ok()
                || std::fs::metadata(&fresh).is_ok();
            if !still { break; }
            compio::runtime::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(!std::fs::metadata(&old).is_ok());
        assert!(!std::fs::metadata(&fresh).is_ok());

        // Now plant a fresh dir AND a stale one, threshold=10 minutes.
        std::fs::create_dir_all(&fresh).unwrap();
        let purged_high = be.scrub_staging(std::time::Duration::from_secs(600)).await.unwrap();
        assert_eq!(purged_high, 0, "young dirs must be left alone");
        assert!(std::fs::metadata(&fresh).is_ok());
    }
}
