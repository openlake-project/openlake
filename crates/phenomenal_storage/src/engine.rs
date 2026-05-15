//! Object storage engine.
//!
//! One object is owned by one **set** of disks. PUT either embeds the
//! body in `xl.meta` (≤ `inline_threshold`) or streams Reed-Solomon EC
//! shards across the set one stripe at a time. GET is the mirror:
//! decode stripe-by-stripe from the set. Peak RAM per in-flight PUT
//! is one stripe + one scratch Vec per backend.
//!
//! Multi-version writes are supported (every PUT mints a new
//! version_id; prior versions are preserved in xl.meta's versions
//! array). Not yet implemented: multipart, delete markers, the
//! `PutBucketVersioning` toggle, heal/scan/MRF.

use std::collections::HashMap;
use std::rc::Rc;
use std::time::Duration;

use async_trait::async_trait;
use futures_util::future::join_all;
use phenomenal_io::stream::ByteSink;
use phenomenal_io::{BucketMeta, ByteStream, DeleteOptions, ErasureInfo, FileInfo, IoError, MULTIPART_VOL, ObjectPartInfo, PooledBuffer, RenameDataResp, StorageBackend, STAGING_VOL, UpdateMetadataOpts, VersioningStatus, SYSTEM_BUCKET};
use uuid::Uuid;

use crate::cluster::{ClusterConfig, DiskAddr, NodeId};
use crate::dsync::DsyncClient;
use crate::ec::{self, Erasure};
use crate::error::{StorageError, StorageResult};
use crate::object::{MultipartInit, ObjectInfo, StorageClass};

pub const DEFAULT_INLINE_THRESHOLD: usize = 128 * 1024;

const DEFAULT_EC_PER_SHARD_BYTES: usize = 1024 * 1024;

const LOCK_ACQUIRE_TIMEOUT: Duration = Duration::from_secs(30);

const CONTENT_TYPE_META_KEY: &str = "content-type";
const ETAG_META_KEY:         &str = "etag";
const PART1_PATH_SUFFIX:     &str = "part.1";

pub struct Engine {
    cluster:  ClusterConfig,
    backends: HashMap<DiskAddr, Rc<dyn StorageBackend>>,
    dsync:    Rc<DsyncClient>,
    self_id:  NodeId,
    inline_threshold: usize,
}

impl Engine {
    pub fn new(
        cluster:  ClusterConfig,
        backends: HashMap<DiskAddr, Rc<dyn StorageBackend>>,
        dsync:    Rc<DsyncClient>,
        self_id:  NodeId,
    ) -> Self {
        Self { cluster, backends, dsync, self_id, inline_threshold: DEFAULT_INLINE_THRESHOLD }
    }

    pub fn with_inline_threshold(mut self, bytes: usize) -> Self {
        self.inline_threshold = bytes;
        self
    }

    fn local(&self) -> &Rc<dyn StorageBackend> {
        let disk0 = DiskAddr { node_id: self.self_id, disk_idx: 0 };
        self.backends.get(&disk0)
            .expect("self_id with disk_idx=0 must be in backends")
    }

    fn backend(&self, addr: DiskAddr) -> StorageResult<&Rc<dyn StorageBackend>> {
        self.backends.get(&addr).ok_or_else(|| {
            StorageError::Io(IoError::InvalidArgument(format!("unknown disk {addr}")))
        })
    }

    fn all_backends(&self) -> StorageResult<Vec<Rc<dyn StorageBackend>>> {
        self.cluster.all_disks().into_iter()
            .map(|addr| self.backend(addr).cloned())
            .collect()
    }

    fn set_backends(&self, bucket: &str, key: &str) -> StorageResult<Vec<Rc<dyn StorageBackend>>> {
        self.cluster.disks_for(bucket, key).into_iter()
            .map(|addr| self.backend(addr).cloned())
            .collect()
    }

    fn obj_lock_key(bucket: &str, key: &str) -> String { format!("obj:{bucket}/{key}") }
    fn bkt_lock_key(bucket: &str)              -> String { format!("bkt:{bucket}") }
    /// Per-part lock: serializes concurrent UploadPart calls for the
    /// same `(upload_id, part_number)`. Different part numbers on the
    /// same session run in parallel — each holds its own per-part lock.
    fn part_lock_key(bucket: &str, key: &str, upload_id: &str, part_number: u32) -> String {
        format!("part:{bucket}/{key}/{upload_id}/{part_number}")
    }

    /// Object key under SYSTEM_BUCKET that holds `bucket`'s meta.
    fn bkt_meta_key(bucket: &str) -> String { format!("buckets/{bucket}/.metadata.bin") }

    /// Persist `meta` for `bucket` as an inline object under SYSTEM_BUCKET.
    /// Mirrors MinIO's `BucketMetadata.Save → saveConfig`: a dedicated
    /// engine-internal write that bypasses [`Engine::put`] (and therefore
    /// every user-facing concern: versioning resolution, S3-name
    /// validation, `obj_lock_key`). Same fault tolerance as user objects
    /// — `save_config` reuses `promote_versions`, so we still get
    /// rename_data, xl.meta.bkp, quorum, and per-disk undo on quorum-fail.
    pub(crate) async fn put_bucket_meta(&self, bucket: &str, meta: &BucketMeta) -> StorageResult<()> {
        let body = meta.encode().map_err(StorageError::Io)?;
        self.save_config(SYSTEM_BUCKET, &Self::bkt_meta_key(bucket), body).await
    }

    async fn save_config(&self, volume: &str, key: &str, body: Vec<u8>) -> StorageResult<()> {
        let mod_time_ms   = now_ms();
        let backends      = self.set_backends(volume, key)?;
        let quorum        = self.cluster.write_quorum();
        let n             = backends.len();
        let parity_shards = self.cluster.default_parity_count;
        let data_shards   = n - parity_shards;
        let size          = body.len() as i64;

        let etag   = blake3::hash(&body).to_hex().to_string();
        let frames = vec![bytes::Bytes::from(body)];

        let parts = single_part_info(&etag, size, size, mod_time_ms);
        let mut base_fi = build_file_info(
            volume, key, size, &etag, mod_time_ms, None,
            Some(frames),
            parts,
        );
        base_fi.version_id = VersioningStatus::NULL_VERSION_ID.to_owned();
        let base_erasure = default_erasure_info(data_shards as u8, parity_shards as u8, n as u8);
        let staging_id   = Uuid::new_v4().simple().to_string();
        let per_disk_fis = with_per_disk_index(&base_fi, &base_erasure, n);
        promote_versions(&backends, STAGING_VOL, &staging_id, per_disk_fis, volume, key, quorum).await
    }

    pub(crate) async fn get_bucket_meta(&self, bucket: &str) -> StorageResult<BucketMeta> {
        let (info, mut stream) = self.get(SYSTEM_BUCKET, &Self::bkt_meta_key(bucket)).await?;
        let mut buf = Vec::with_capacity(info.size as usize);
        loop {
            let chunk = stream.read().await.map_err(StorageError::from)?;
            if chunk.is_empty() { break; }
            buf.extend_from_slice(&chunk);
        }
        BucketMeta::decode(&buf).map_err(StorageError::Io)
    }

    pub async fn create_bucket(&self, bucket: &str, meta: BucketMeta) -> StorageResult<()> {
        validate_bucket_name(bucket)?;
        let _lock = self.dsync
            .acquire(&Self::bkt_lock_key(bucket), LOCK_ACQUIRE_TIMEOUT).await?;
        let backends = self.all_backends()?;
        let n        = backends.len();

        let vol_results = join_all(backends.iter().map(|b| {
            let b      = b.clone();
            let bucket = bucket.to_owned();
            async move { b.make_vol(&bucket).await }
        })).await;
        let mut ok      = 0usize;
        let mut exists  = 0usize;
        let mut others: Vec<IoError> = Vec::new();
        for r in vol_results {
            match r {
                Ok(())                          => ok += 1,
                Err(IoError::VolumeExists(_))   => exists += 1,
                Err(e)                          => others.push(e),
            }
        }
        let majority = n / 2 + 1;
        if exists >= majority {
            return Err(StorageError::BucketAlreadyExists(bucket.to_owned()));
        }
        if ok != n {
            let _ = join_all(backends.iter().map(|b| {
                let b      = b.clone();
                let bucket = bucket.to_owned();
                async move { b.delete_vol(&bucket, true).await }
            })).await;
            let modal_err = others.pop()
                .or_else(|| (exists > 0).then(|| IoError::VolumeExists(bucket.to_owned())))
                .unwrap_or_else(|| IoError::InvalidArgument("no results".into()));
            return Err(StorageError::from(modal_err));
        }

        if let Err(e) = self.put_bucket_meta(bucket, &meta).await {
            let _ = join_all(backends.iter().map(|b| {
                let b      = b.clone();
                let bucket = bucket.to_owned();
                async move { b.delete_vol(&bucket, true).await }
            })).await;
            return Err(e);
        }
        Ok(())
    }

    pub async fn get_bucket_versioning(&self, bucket: &str) -> StorageResult<VersioningStatus> {
        validate_bucket_name(bucket)?;
        self.stat_bucket(bucket).await?;
        let meta = self.get_bucket_meta(bucket).await?;
        Ok(meta.versioning_status)
    }

    pub async fn put_bucket_versioning(&self, bucket: &str, new_status: VersioningStatus) -> StorageResult<()> {
        validate_bucket_name(bucket)?;
        let _lock = self.dsync
            .acquire(&Self::bkt_lock_key(bucket), LOCK_ACQUIRE_TIMEOUT).await?;
        self.stat_bucket(bucket).await?;
        let mut meta = self.get_bucket_meta(bucket).await?;
        meta.versioning_status     = new_status;
        meta.versioning_updated_ms = now_ms();
        self.put_bucket_meta(bucket, &meta).await
    }

    pub async fn stat_bucket(&self, bucket: &str) -> StorageResult<()> {
        validate_bucket_name(bucket)?;
        let backends = self.all_backends()?;
        let n        = backends.len();
        let probes   = backends.iter().map(|b| {
            let b      = b.clone();
            let bucket = bucket.to_owned();
            async move { b.stat_vol(&bucket).await }
        });
        let results = join_all(probes).await;

        let mut found    = 0usize;
        let mut missing  = 0usize;
        let mut other_err: Option<IoError> = None;
        for r in results {
            match r {
                Ok(_)                            => found   += 1,
                Err(IoError::VolumeNotFound(_))  => missing += 1,
                Err(e)                           => { if other_err.is_none() { other_err = Some(e); } }
            }
        }

        let read_quorum = self.cluster.read_quorum();
        if found >= read_quorum {
            Ok(())
        } else if missing >= n.saturating_sub(found) && other_err.is_none() {
            Err(StorageError::BucketNotFound(bucket.to_owned()))
        } else if let Some(e) = other_err {
            Err(StorageError::Io(e))
        } else {
            Err(StorageError::BucketNotFound(bucket.to_owned()))
        }
    }

    pub async fn delete_bucket(&self, bucket: &str, force: bool) -> StorageResult<()> {
        validate_bucket_name(bucket)?;
        let _lock = self.dsync
            .acquire(&Self::bkt_lock_key(bucket), LOCK_ACQUIRE_TIMEOUT).await?;
        let backends = self.all_backends()?;

        if !force {
            let probes = backends.iter().map(|b| {
                let b      = b.clone();
                let bucket = bucket.to_owned();
                async move { b.list_dir(&bucket, "", 1).await }
            });
            // todo: @arnav we are waiting for all nodes to complete at many places, can be optimized if the data from 1 or p nodes is enough to make decision
            for r in join_all(probes).await {
                match r {
                    Ok(entries) if !entries.is_empty() =>
                        return Err(StorageError::BucketNotEmpty(bucket.to_owned())),
                    Ok(_)                                => {}
                    Err(IoError::VolumeNotFound(_))      => {}
                    Err(e)                               => return Err(e.into()),
                }
            }
        }

        let _ = self.delete(SYSTEM_BUCKET, &Self::bkt_meta_key(bucket)).await;

        let results = join_all(backends.iter().map(|b| {
            let b      = b.clone();
            let bucket = bucket.to_owned();
            async move { b.delete_vol(&bucket, true).await }
        })).await;
        require_quorum(results, backends.len(), |e| matches!(e, IoError::VolumeNotFound(_)))
            .map_err(Into::into)
    }

    pub async fn create_multipart_upload(
        &self,
        bucket:       &str,
        key:          &str,
        content_type: Option<String>,
    ) -> StorageResult<MultipartInit> {
        validate_bucket_name(bucket)?;

        let bucket_meta = self.get_bucket_meta(bucket).await?;

        let version_id  = bucket_meta.next_version_id();

        let data_dir    = Uuid::new_v4().to_string();
        let mod_time_ms = now_ms();
        let upload_id   = format_upload_id(self.cluster.deployment_id);

        let backends      = self.set_backends(bucket, key)?;
        let n             = backends.len();
        let quorum        = self.cluster.write_quorum();
        let parity_shards = self.cluster.default_parity_count;
        let data_shards   = n - parity_shards;

        let session_path = format!("{bucket}/{key}/{upload_id}");
        let mut session_fi      = FileInfo::default();
        session_fi.volume       = MULTIPART_VOL.to_owned();
        session_fi.name         = session_path.clone();
        session_fi.version_id   = version_id;
        session_fi.is_latest    = true;
        session_fi.mod_time_ms  = mod_time_ms;
        session_fi.data_dir     = data_dir;
        session_fi.fresh        = true;
        if let Some(ct) = content_type {
            session_fi.metadata.insert(CONTENT_TYPE_META_KEY.to_owned(), ct);
        }

        let base_erasure = default_erasure_info(data_shards as u8, parity_shards as u8, n as u8);
        let per_disk_fis = with_per_disk_index(&session_fi, &base_erasure, n);

        let writes = backends.iter().zip(per_disk_fis.into_iter()).map(|(b, fi)| {
            let b    = b.clone();
            let path = session_path.clone();
            async move {
                b.update_metadata(MULTIPART_VOL, &path, &fi, &UpdateMetadataOpts::default()).await
            }
        });
        let results = join_all(writes).await;

        let mut ok       = 0usize;
        let mut first_err: Option<IoError> = None;
        for r in results {
            match r {
                Ok(())  => ok += 1,
                Err(e) => { if first_err.is_none() { first_err = Some(e); } }
            }
        }
        if ok < quorum {
            let cleanups = backends.iter().map(|b| {
                let b    = b.clone();
                let path = session_path.clone();
                async move { let _ = b.delete(MULTIPART_VOL, &path, true).await; }
            });
            let _ = join_all(cleanups).await;
            return Err(StorageError::Io(
                first_err.unwrap_or_else(|| IoError::InvalidArgument("no quorum".into()))
            ));
        }

        Ok(MultipartInit { upload_id })
    }

    pub async fn upload_part(
        &self,
        bucket:      &str,
        key:         &str,
        upload_id:   &str,
        part_number: u32,
        size:        u64,
        src:         &mut dyn ByteStream,
    ) -> StorageResult<ObjectPartInfo> {
        if part_number == 0 || part_number > 10_000 {
            return Err(StorageError::Io(IoError::InvalidArgument(
                format!("partNumber must be in 1..=10000, got {part_number}")
            )));
        }
        validate_bucket_name(bucket)?;

        let backends = self.set_backends(bucket, key)?;
        let n        = backends.len();
        let quorum   = self.cluster.write_quorum();
        let session_path = format!("{bucket}/{key}/{upload_id}");

        let session_fi = read_session_fi(&backends, &session_path).await?;
        let data_dir   = session_fi.data_dir.clone();
        if data_dir.is_empty() {
            return Err(StorageError::Io(IoError::InvalidArgument(
                "session xl.meta missing data_dir".into(),
            )));
        }
        let parity_shards = session_fi.erasure.parity_blocks as usize;
        let data_shards   = session_fi.erasure.data_blocks   as usize;

        let _lock = self.dsync
            .acquire(&Self::part_lock_key(bucket, key, upload_id, part_number),
                     LOCK_ACQUIRE_TIMEOUT).await?;

        let ec = Erasure::new(data_shards, parity_shards).map_err(|e| {
            StorageError::Io(IoError::InvalidArgument(format!(
                "EC init ({data_shards}+{parity_shards}): {e}"
            )))
        })?;
        let stripe_unit = DEFAULT_EC_PER_SHARD_BYTES;
        let stripe_data = data_shards * stripe_unit;
        let stripes     = (size as usize).div_ceil(stripe_data).max(1);
        let per_shard_on_disk = (stripes as u64) * stripe_unit as u64;
        let per_shard_actual  = ec::shard_size(size as usize, data_shards) as u64;
        let mod_time_ms       = now_ms();

        let staging_id    = format!("{}x{}", Uuid::new_v4().simple(), now_nanos());
        let tmp_part_path = format!("{staging_id}/part.{part_number}");

        let final_dir   = format!("{bucket}/{key}/{upload_id}/{data_dir}");
        let final_part  = format!("{final_dir}/part.{part_number}");
        let final_meta  = format!("{final_dir}/part.{part_number}.meta");

        let result: StorageResult<ObjectPartInfo> = async {
            let sinks = open_part_staging_sinks(&backends, &tmp_part_path, per_shard_on_disk)
                .await
                .map_err(map_bucket_or_io(bucket))?;

            let (etag, sinks) = encode_and_write_stripes(
                &ec, src, size, stripe_data, stripes, sinks,
            ).await.map_err(map_bucket_or_io(bucket))?;

            finalize_sinks_quorum(sinks, quorum)
                .await
                .map_err(map_bucket_or_io(bucket))?;

            let part_info = ObjectPartInfo {
                etag:        etag.clone(),
                number:      part_number as i32,
                size:        per_shard_actual as i64,
                actual_size: size as i64,
                mod_time_ms,
                index:       Vec::new(),
                checksums:   std::collections::BTreeMap::new(),
            };
            let sidecar = rmp_serde::to_vec_named(&part_info).map_err(|e| {
                StorageError::Io(IoError::Encode(format!("part sidecar: {e}")))
            })?;

            let cleanups = backends.iter().map(|b| {
                let b    = b.clone();
                let part = final_part.clone();
                let meta = final_meta.clone();
                async move {
                    let _ = b.delete(MULTIPART_VOL, &part, false).await;
                    let _ = b.delete(MULTIPART_VOL, &meta, false).await;
                }
            });
            join_all(cleanups).await;

            let mkdirs = backends.iter().map(|b| {
                let b   = b.clone();
                let dir = final_dir.clone();
                async move { b.make_dir_all(MULTIPART_VOL, &dir).await }
            });
            require_quorum(join_all(mkdirs).await, n, |_| false)
                .map_err(map_bucket_or_io(bucket))?;

            let placements = backends.iter().map(|b| {
                let b     = b.clone();
                let src   = tmp_part_path.clone();
                let dst   = final_part.clone();
                let meta  = final_meta.clone();
                let bytes = sidecar.clone();
                async move {
                    b.rename_file(STAGING_VOL, &src, MULTIPART_VOL, &dst).await?;
                    b.write_file(MULTIPART_VOL, &meta, bytes).await
                }
            });
            require_quorum(join_all(placements).await, n, |_| false)
                .map_err(map_bucket_or_io(bucket))?;

            Ok(part_info)
        }.await;

        if result.is_err() {
            cleanup_src(&backends, STAGING_VOL, &staging_id).await;
        }
        result
    }

    pub async fn complete_multipart_upload(
        &self,
        bucket:    &str,
        key:       &str,
        upload_id: &str,
        parts:     Vec<crate::object::CompletePart>,
    ) -> StorageResult<ObjectInfo> {
        validate_bucket_name(bucket)?;
        if parts.is_empty() {
            return Err(StorageError::Io(IoError::InvalidArgument(
                "CompleteMultipartUpload requires at least one part".into(),
            )));
        }
        for w in parts.windows(2) {
            if w[0].part_number >= w[1].part_number {
                return Err(StorageError::Io(IoError::InvalidArgument(format!(
                    "parts must be ascending by part_number (got {} after {})",
                    w[1].part_number, w[0].part_number,
                ))));
            }
        }

        let _lock = self.dsync
            .acquire(&Self::obj_lock_key(bucket, key), LOCK_ACQUIRE_TIMEOUT).await?;

        let backends     = self.set_backends(bucket, key)?;
        let n            = backends.len();
        let write_quorum = self.cluster.write_quorum();
        let read_quorum  = self.cluster.read_quorum().max(1);
        let session_path = format!("{bucket}/{key}/{upload_id}");

        let session_fi   = read_session_fi(&backends, &session_path).await?;
        let data_dir     = session_fi.data_dir.clone();
        if data_dir.is_empty() {
            return Err(StorageError::Io(IoError::InvalidArgument(
                "session xl.meta missing data_dir".into(),
            )));
        }
        let parity = session_fi.erasure.parity_blocks as usize;
        let data_blocks = session_fi.erasure.data_blocks as usize;

        let part_infos = read_part_sidecars(
            &backends, &session_path, &data_dir, &parts, read_quorum,
        ).await?;

        const MIN_PART_SIZE: i64 = 5 * 1024 * 1024;
        let mut total_actual_size: i64 = 0;
        let mut etag_concat: Vec<u8> = Vec::with_capacity(parts.len() * blake3::OUT_LEN);

        for (i, (claimed, actual)) in parts.iter().zip(part_infos.iter()).enumerate() {
            let claimed_etag = claimed.etag.trim_matches('"').to_ascii_lowercase();
            if claimed_etag != actual.etag.to_ascii_lowercase() {
                return Err(StorageError::Io(IoError::InvalidArgument(format!(
                    "part {} etag mismatch: client {:?}, server {:?}",
                    claimed.part_number, claimed_etag, actual.etag,
                ))));
            }
            if i < parts.len() - 1 && actual.actual_size < MIN_PART_SIZE {
                return Err(StorageError::Io(IoError::InvalidArgument(format!(
                    "part {} below 5 MiB minimum (got {} bytes)",
                    claimed.part_number, actual.actual_size,
                ))));
            }
            total_actual_size += actual.actual_size;
            let raw = hex::decode(&actual.etag).map_err(|e| StorageError::Io(
                IoError::InvalidArgument(format!("part {} etag not hex: {e}", claimed.part_number))
            ))?;
            etag_concat.extend_from_slice(&raw);
        }

        let assembled_etag = format!("{}-{}", blake3::hash(&etag_concat).to_hex(), parts.len());
        let mod_time_ms    = now_ms();

        let parts_for_fi: Vec<ObjectPartInfo> = part_infos.iter().cloned().collect();
        let mut assembled_fi    = FileInfo::default();
        assembled_fi.volume       = bucket.to_owned();
        assembled_fi.name         = key.to_owned();
        assembled_fi.version_id   = session_fi.version_id.clone();
        assembled_fi.is_latest    = true;
        assembled_fi.size         = total_actual_size;
        assembled_fi.mod_time_ms  = mod_time_ms;
        assembled_fi.data_dir     = data_dir.clone();
        assembled_fi.fresh        = true;
        assembled_fi.parts        = parts_for_fi;
        assembled_fi.metadata     = session_fi.metadata.clone();
        assembled_fi.metadata.insert(ETAG_META_KEY.into(), assembled_etag.clone());
        assembled_fi.num_versions = 1;

        let base_erasure = default_erasure_info(data_blocks as u8, parity as u8, n as u8);
        let per_disk_fis = with_per_disk_index(&assembled_fi, &base_erasure, n);

        let cleanup_meta_paths: Vec<String> = parts.iter()
            .map(|p| format!("{session_path}/{data_dir}/part.{}.meta", p.part_number))
            .collect();
        let cleanups = backends.iter().flat_map(|b| {
            let b     = b.clone();
            let paths = cleanup_meta_paths.clone();
            paths.into_iter().map(move |p| {
                let b = b.clone();
                async move { let _ = b.delete(MULTIPART_VOL, &p, false).await; }
            })
        });
        join_all(cleanups).await;

        promote_versions(
            &backends,
            MULTIPART_VOL, &session_path,
            per_disk_fis,
            bucket, key,
            write_quorum,
        ).await?;

        Ok(ObjectInfo {
            bucket:           bucket.to_owned(),
            key:              key.to_owned(),
            size:             total_actual_size as u64,
            etag:             assembled_etag,
            storage_class:    StorageClass::Single,
            modified_ms:      mod_time_ms,
            content_type:     assembled_fi.metadata.get(CONTENT_TYPE_META_KEY).cloned(),
            version_id:       assembled_fi.version_id,
            is_delete_marker: false,
        })
    }

    pub async fn put(
        &self,
        bucket: &str,
        key:    &str,
        size:   u64,
        src:    &mut dyn ByteStream,
        content_type: Option<String>,
    ) -> StorageResult<ObjectInfo> {
        let _lock = self.dsync
            .acquire(&Self::obj_lock_key(bucket, key), LOCK_ACQUIRE_TIMEOUT).await?; // rpc 1

        let mod_time_ms = now_ms();
        let backends    = self.set_backends(bucket, key)?;
        let quorum      = self.cluster.write_quorum();
        let version_id  = self.resolve_put_version_id(bucket).await?; // rpc 2

        if (size as usize) <= self.inline_threshold {
            self.put_inline(bucket, key, size, src, content_type,
                            mod_time_ms, version_id, &backends, quorum).await
        } else {
            self.put_ec(bucket, key, size, src, content_type,
                        mod_time_ms, version_id, &backends, quorum).await
        }
    }

    async fn resolve_put_version_id(&self, bucket: &str) -> StorageResult<String> {
        let meta = self.get_bucket_meta(bucket).await?;
        Ok(meta.next_version_id())
    }

    #[allow(clippy::too_many_arguments)]
    async fn put_inline(
        &self,
        bucket:       &str,
        key:          &str,
        size:         u64,
        src:          &mut dyn ByteStream,
        content_type: Option<String>,
        mod_time_ms:  u64,
        version_id:   String,
        backends:     &[Rc<dyn StorageBackend>],
        quorum:       usize,
    ) -> StorageResult<ObjectInfo> {
        let n             = backends.len();
        let parity_shards = self.cluster.default_parity_count;
        let data_shards   = n - parity_shards;

        // todo: @arnav support chunked put, with no advertised content size header
        let (frames, etag) = drain_inline_payload(src, size as usize).await?;

        let parts = single_part_info(&etag, size as i64, size as i64, mod_time_ms);
        let mut base_fi = build_file_info(
            bucket, key,
            size as i64, &etag, mod_time_ms, content_type.clone(),
            Some(frames),
            parts,
        );
        base_fi.version_id = version_id.clone();
        let base_erasure = default_erasure_info(data_shards as u8, parity_shards as u8, n as u8);

        let staging_id   = Uuid::new_v4().simple().to_string();
        let per_disk_fis = with_per_disk_index(&base_fi, &base_erasure, n);
        promote_versions(backends, STAGING_VOL, &staging_id, per_disk_fis, bucket, key, quorum).await?;

        Ok(ObjectInfo {
            bucket:        bucket.to_owned(),
            key:           key.to_owned(),
            size,
            etag,
            storage_class: StorageClass::Inline,
            modified_ms:   mod_time_ms,
            content_type,
            version_id,
            is_delete_marker: false,
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn put_ec(
        &self,
        bucket:       &str,
        key:          &str,
        size:         u64,
        src:          &mut dyn ByteStream,
        content_type: Option<String>,
        mod_time_ms:  u64,
        version_id:   String,
        backends:     &[Rc<dyn StorageBackend>],
        quorum:       usize,
    ) -> StorageResult<ObjectInfo> {
        let n             = backends.len();
        let parity_shards = self.cluster.default_parity_count;
        let data_shards   = n - parity_shards;
        let ec = Erasure::new(data_shards, parity_shards).map_err(|e| {
            StorageError::Io(IoError::InvalidArgument(format!(
                "EC init ({data_shards}+{parity_shards}): {e}"
            )))
        })?;

        // EC PUT site: only place the engine consults the default
        // per-shard width on the write path. `block_size` = full
        // stripe = D × per-shard, persisted on every record so
        // reads derive the per-shard width from xl.meta.
        let stripe_unit = DEFAULT_EC_PER_SHARD_BYTES;
        let stripe_data = data_shards * stripe_unit;
        let stripes     = (size as usize).div_ceil(stripe_data).max(1);
        // Padded per-shard total = N stripes × stripe_unit. This is
        // the byte count we write on every backend (last stripe is
        // zero-padded). The unpadded per-shard size goes into the
        // part record so the read path knows how much to slice back.
        let per_shard_on_disk = (stripes as u64) * stripe_unit as u64;
        let per_shard_actual  = ec::shard_size(size as usize, data_shards) as u64;

        // Coordinator-issued identifiers: `data_dir` names the
        // per-version on-disk directory; `staging_id` segregates
        // this PUT's in-progress shards from concurrent PUTs to the
        // same key. Both are coordinator-assigned so every disk in
        // the set agrees on layout. Canonical UUID format (dashes)
        // matches what xl.meta's encode/decode round-trips to.
        let data_dir   = Uuid::new_v4().to_string();
        let staging_id = Uuid::new_v4().simple().to_string();

        // From here on every failure leaves bytes scattered across
        // per-disk staging dirs. Wrap the body so a single error
        // handler can sweep `STAGING_VOL/{staging_id}/` on every
        // backend before bubbling up.
        let result: StorageResult<ObjectInfo> = async {
            let sinks = open_staging_sinks(backends, &staging_id, &data_dir, per_shard_on_disk) // rpc 3
                .await
                .map_err(map_bucket_or_io(bucket))?;

            let (etag, sinks) = encode_and_write_stripes(
                &ec, src, size, stripe_data, stripes, sinks,
            ).await.map_err(map_bucket_or_io(bucket))?;

            finalize_sinks_quorum(sinks, quorum) // rpc 4
                .await
                .map_err(map_bucket_or_io(bucket))?;

            let parts = single_part_info(&etag, per_shard_actual as i64, size as i64, mod_time_ms);
            let mut base_fi = build_file_info(
                bucket, key,
                size as i64, &etag, mod_time_ms, content_type.clone(),
                None,
                parts,
            );
            base_fi.version_id = version_id.clone();
            base_fi.data_dir   = data_dir.clone();
            let base_erasure   = default_erasure_info(data_shards as u8, parity_shards as u8, n as u8);
            let per_disk_fis   = with_per_disk_index(&base_fi, &base_erasure, n);
            promote_versions(backends, STAGING_VOL, &staging_id, per_disk_fis, bucket, key, quorum).await?; // rpc 5, 6, 7

            Ok(ObjectInfo {
                bucket:        bucket.to_owned(),
                key:           key.to_owned(),
                size,
                etag,
                storage_class: StorageClass::Single,
                modified_ms:   mod_time_ms,
                content_type,
                version_id,
                is_delete_marker: false,
            })
        }.await;

        if result.is_err() {
            cleanup_src(backends, STAGING_VOL, &staging_id).await; // todo: @arnav check the cleanups we already are cleaning up in promote versions
        }
        result
    }

    /// GET the latest version. Returns the object metadata plus a
    /// `ByteStream` whose `read` yields bytes one stripe at a time.
    /// For inline payloads the stream wraps the embedded `xl.meta`
    /// rope; for EC objects the stream owns one `read_file_stream`
    /// per backend and decodes a stripe per call.
    pub async fn get(
        &self,
        bucket: &str,
        key:    &str,
    ) -> StorageResult<(ObjectInfo, Box<dyn ByteStream>)> {
        self.get_versioned(bucket, key, None).await
    }

    /// GET a specific version. `version_id == None` is identical to
    /// [`get`] (returns the latest). `Some(id)` reads that exact
    /// version's record from xl.meta; older versions read their
    /// shards from `{key}/{data_dir}/part.N` paths just like the
    /// latest does. Surfaces `ObjectNotFound` if the bucket/key
    /// doesn't exist; `FileVersionNotFound` (mapped through error
    /// translation) if the key exists but that version doesn't.
    pub async fn get_version(
        &self,
        bucket: &str,
        key:    &str,
        version_id: &str,
    ) -> StorageResult<(ObjectInfo, Box<dyn ByteStream>)> {
        self.get_versioned(bucket, key, Some(version_id)).await
    }

    // todo: @arnav this should not be an engine specific concern, the respective backend can optianlly accept a version id for get, and can serve it instead of the head.
    async fn get_versioned(
        &self,
        bucket: &str,
        key:    &str,
        version_id: Option<&str>,
    ) -> StorageResult<(ObjectInfo, Box<dyn ByteStream>)> {
        let backends   = self.set_backends(bucket, key)?;
        let (_b, fi)   = self.read_with_consensus(&backends, bucket, key, version_id, true).await?;
        let info       = to_object_info(bucket, &fi);

        // Inline path: the bytes are inside `fi.data` as a refcounted
        // rope. Hand it to a `RopeByteStream` — each frame is yielded
        // as-is by `read()` (zero copy), in order.
        if fi.data.as_ref().is_some_and(|frames| !frames.is_empty()) {
            let stream: Box<dyn ByteStream> = Box::new(
                phenomenal_io::RopeByteStream::new(fi.data.clone().unwrap())
            );
            return Ok((info, stream));
        }
        if fi.size == 0 {
            // Zero-byte object: no inline, no parts.
            let stream: Box<dyn ByteStream> = Box::new(
                phenomenal_io::RopeByteStream::new(Vec::new())
            );
            return Ok((info, stream));
        }

        // EC path. Every layout parameter is read from the per-object
        // record produced by `read_latest`'s consensus — never from
        // the runtime constant. This keeps reads correct across
        // future binary changes that re-tune the default constant
        // (matches MinIO's `xl.meta captures the right blockSize`
        // pattern, `object-api-common.go:25-37`).
        let n             = backends.len();
        let data_shards   = fi.erasure.data_blocks   as usize;
        let parity_shards = fi.erasure.parity_blocks as usize;
        if data_shards + parity_shards != n {
            return Err(StorageError::InconsistentMeta {
                bucket: bucket.into(),
                key:    key.into(),
                msg:    format!(
                    "EC config (D={data_shards}, P={parity_shards}) does not match set size N={n}"
                ),
            });
        }
        let block_size = fi.erasure.block_size as usize;
        if block_size == 0 || block_size % data_shards != 0 {
            return Err(StorageError::InconsistentMeta {
                bucket: bucket.into(),
                key:    key.into(),
                msg:    format!(
                    "block_size {block_size} not a multiple of data_shards {data_shards}"
                ),
            });
        }
        let stripe_unit = block_size / data_shards;            // per-shard byte width
        let ec = Erasure::new(data_shards, parity_shards).map_err(|e| {
            StorageError::Io(IoError::InvalidArgument(format!(
                "EC init ({data_shards}+{parity_shards}): {e}"
            )))
        })?;
        let stripes     = (fi.size as usize).div_ceil(block_size).max(1);
        let on_disk_per_shard = (stripes as u64) * stripe_unit as u64;

        // Per-version data_dir UUID lives in the FileInfo we just
        // resolved via consensus. Each disk has the shard at
        // `{key}/{data_dir}/part.1`. Older PUTs that wrote without
        // a data_dir would fail here — but the L1 migration is a
        // hard cutover (no legacy on-disk data), so an empty
        // data_dir is a corrupt record.
        if fi.data_dir.is_empty() {
            return Err(StorageError::InconsistentMeta {
                bucket: bucket.into(),
                key:    key.into(),
                msg:    "EC object missing data_dir in xl.meta".into(),
            });
        }
        // Multipart-aware read path: walks `fi.parts` in order. For
        // single-shot PUTs `fi.parts` is `[{number:1, actual_size: fi.size}]`
        // so the wrapper opens one EC stream and drains it — same
        // bytes-on-the-wire behavior as before. For multipart-assembled
        // objects (`fi.parts.len() > 1`) the wrapper opens each part's
        // EC streams sequentially, transparently to the caller.
        let _ = (stripes, on_disk_per_shard);  // recomputed per-part inside the wrapper
        let stream = MultiPartEcStream {
            backends:      backends.to_vec(),
            bucket:        bucket.to_owned(),
            key:           key.to_owned(),
            data_dir:      fi.data_dir.clone(),
            parts:         fi.parts.clone(),
            next_idx:      0,
            block_size,
            stripe_unit,
            data_shards,
            parity_shards,
            ec,
            current:       None,
        };
        Ok((info, Box::new(stream)))
    }

    // todo: @arnav check why get object cant serve this
    /// STAT. Same consensus race as GET but without inline payload.
    pub async fn stat(&self, bucket: &str, key: &str) -> StorageResult<ObjectInfo> {
        let backends = self.set_backends(bucket, key)?;
        let (_, fi) = self.read_latest(&backends, bucket, key, false).await?;
        Ok(to_object_info(bucket, &fi))
    }

    /// STAT a specific version. `version_id == "null"` selects the
    /// null-versioned record (the default for objects written under
    /// Unversioned or Suspended buckets); a UUID string selects that
    /// exact version. Surfaces `ObjectNotFound` if the bucket/key
    /// doesn't exist; `VersionNotFound` if the key exists but the
    /// requested version doesn't. The returned `ObjectInfo`'s
    /// `is_delete_marker` reflects whether the resolved version is a
    /// tombstone — callers (e.g. HEAD) translate that to
    /// `405 MethodNotAllowed` per S3 spec.
    pub async fn stat_version(&self, bucket: &str, key: &str, version_id: &str) -> StorageResult<ObjectInfo> {
        let backends = self.set_backends(bucket, key)?;
        let (_, fi) = self.read_with_consensus(&backends, bucket, key, Some(version_id), false).await?;
        Ok(to_object_info(bucket, &fi))
    }

    // todo: @arnav check why were not checking any querym on the delete, and surfacing the error accordingly, check parity against other s3 impls
    /// DELETE. Fan out to every disk in the set.
    pub async fn delete(&self, bucket: &str, key: &str) -> StorageResult<()> {
        let _lock = self.dsync
            .acquire(&Self::obj_lock_key(bucket, key), LOCK_ACQUIRE_TIMEOUT).await?;
        let backends = self.set_backends(bucket, key)?;
        let results = join_all(backends.iter().map(|b| {
            let b      = b.clone();
            let bucket = bucket.to_owned();
            let key    = key.to_owned();
            async move { b.delete(&bucket, &key, true).await }
        })).await;

        let mut found_any = false;
        let mut real_err: Option<IoError> = None;
        for r in results {
            match r {
                Ok(())                         => found_any = true,
                Err(IoError::FileNotFound{..}) => {}
                Err(e)                         => { if real_err.is_none() { real_err = Some(e); } }
            }
        }
        if found_any { Ok(()) }
        else if let Some(e) = real_err { Err(map_object_missing(bucket, key)(e)) }
        else { Err(StorageError::ObjectNotFound { bucket: bucket.into(), key: key.into() }) }
    }

    /// List objects under `prefix`. v0 walks the local node's tree.
    pub async fn list(&self, bucket: &str, prefix: &str) -> StorageResult<Vec<ObjectInfo>> {
        let mut out = Vec::new();
        self.walk(self.local(), bucket, "", prefix, &mut out).await?;
        Ok(out)
    }

    fn walk<'a>(
        &'a self,
        backend: &'a Rc<dyn StorageBackend>,
        bucket: &'a str,
        dir: &'a str,
        prefix: &'a str,
        out: &'a mut Vec<ObjectInfo>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = StorageResult<()>> + 'a>> {
        Box::pin(async move {
            let entries = backend.list_dir(bucket, dir, 0).await
                .map_err(map_bucket_or_io(bucket))?;
            for name in entries {
                let child = if dir.is_empty() { name.clone() } else { format!("{dir}/{name}") };
                match backend.read_version("", bucket, &child, None, false).await {
                    Ok(fi) => {
                        if prefix.is_empty() || fi.name.starts_with(prefix) {
                            out.push(to_object_info(bucket, &fi));
                        }
                    }
                    Err(IoError::FileNotFound { .. }) => {
                        self.walk(backend, bucket, &child, prefix, out).await?;
                    }
                    Err(e) => return Err(e.into()),
                }
            }
            Ok(())
        })
    }
    // todo: @arnav we need to implement health check and healer, we can get away with it today due to strict write consensus but not ideal long term.
    /// Read consensus across the EC set.
    ///
    /// Pipeline (mirrors `getObjectFileInfo` → `calcQuorum` in MinIO's
    /// `erasure-object.go`, with our scope simplifications):
    ///
    ///   1. **Fan-out**: read xl.meta from every backend in parallel.
    ///   2. **Gate 1 (errors >= N/2)**: if a non-nil per-disk error
    ///      dominates at majority threshold (e.g. `FileNotFound`),
    ///      surface that error directly. Lets `ObjectNotFound` flow
    ///      out cleanly instead of being mistaken for an
    ///      inconsistency.
    ///   3. **Parity vote (`common_parity`, threshold = N - parity)**:
    ///      vote on `parity_blocks` declared by each disk's record.
    ///      Refuses if no parity value reaches its corresponding D
    ///      quorum — this catches EC config drift across disks.
    ///   4. **Etag quorum (>= D)**: pick the etag value at least D
    ///      disks share. If none reaches D, the object is split-brain;
    ///      return `InconsistentMeta`.
    ///   5. **Content-hash consensus (>= D)**: BLAKE3 over the
    ///      decode-contract fields (parts, EC config, distribution,
    ///      version_id, deleted-flag) for each record matching the
    ///      winning etag; require ≥D matching hashes. Catches
    ///      parts-table or EC-layout corruption that etag alone can't.
    ///   6. Return canonical FileInfo + the index of one disk that
    ///      passed every check.
    ///
    /// Strict: any disagreement that can't reach D quorum is a hard
    /// error. There are no permissive defaults.
    async fn read_latest(
        &self,
        backends: &[Rc<dyn StorageBackend>],
        bucket: &str,
        key: &str,
        read_data: bool,
    ) -> StorageResult<(Rc<dyn StorageBackend>, FileInfo)> {
        self.read_with_consensus(backends, bucket, key, None, read_data).await
    }
    // todo: @arnav, today we asusme the data dir is not shared among versions which make deleting objects safe. However this should be revisted if we implement healer or copy objects.
    /// Read a specific version with the same consensus algorithm
    /// (Gate 1 + parity vote + etag quorum + content-hash). Each
    /// backend's `read_version` call passes the `version_id` through;
    /// the consensus picks the record version that reaches quorum.
    async fn read_with_consensus(
        &self,
        backends: &[Rc<dyn StorageBackend>],
        bucket: &str,
        key: &str,
        version_id: Option<&str>,
        read_data: bool,
    ) -> StorageResult<(Rc<dyn StorageBackend>, FileInfo)> {
        let probes = backends.iter().enumerate().map(|(i, b)| {
            let b      = b.clone();
            let bucket = bucket.to_owned();
            let key    = key.to_owned();
            let vid    = version_id.map(str::to_owned);
            async move {
                (i, b.read_version("", &bucket, &key, vid.as_deref(), read_data).await)
            }
        });
        let results = join_all(probes).await;

        let n = backends.len();
        let mut metas: Vec<Option<FileInfo>> = (0..n).map(|_| None).collect();
        let mut errs:  Vec<Option<IoError>>  = (0..n).map(|_| None).collect();
        for (i, r) in results {
            match r {
                Ok(fi) => metas[i] = Some(fi),
                Err(e) => errs[i]  = Some(e),
            }
        }

        // Counts non-`nil` errors and `nil` (success) symmetrically.
        // If the dominant value reaches N/2, surface it. Maps
        // `FileNotFound` → `ObjectNotFound`; surfaces other errors
        // (e.g. permission denied) verbatim via the Io variant.
        let half = (n / 2).max(1);
        let (max_err_count, dominant_err) = dominant_error(&errs);
        if dominant_err.is_some() && max_err_count >= half {
            let e = dominant_err.unwrap();
            return Err(map_object_missing(bucket, key)(e));
        }

        // Each disk's metadata declares its parity_blocks count. Pick
        // the parity value that has occurrence >= (N - parity) — i.e.
        // the value supported by enough records to satisfy the read
        // quorum it implies.
        let parity = match common_parity(&metas, n) {
            Some(p) => p as usize,
            None => return Err(StorageError::InsufficientOnlineDrives {
                bucket: bucket.into(),
                key:    key.into(),
                msg:    "no parity value reached its quorum across the set".into(),
            }),
        };
        let data_blocks = n - parity;

        // ----- (4) etag quorum at D -----
        let etag = match common_etag(&metas, data_blocks) {
            Some(e) => e,
            None => return Err(StorageError::InconsistentMeta {
                bucket: bucket.into(),
                key:    key.into(),
                msg:    format!(
                    "no etag reached quorum {data_blocks} (have {} valid records)",
                    metas.iter().filter(|m| m.is_some()).count(),
                ),
            }),
        };

        // ----- (5) content-hash consensus at D -----
        // For every record matching the winning etag, compute a
        // BLAKE3 over the decode-contract fields and tally. The
        // winning hash must reach D occurrences.
        let mut hash_counts: HashMap<[u8; 32], (usize, Vec<usize>)> = HashMap::new();
        for (i, m) in metas.iter().enumerate() {
            let Some(fi) = m else { continue };
            if !record_etag_matches(fi, &etag) { continue }
            let h = decode_contract_hash(fi);
            let entry = hash_counts.entry(h).or_insert_with(|| (0, Vec::new()));
            entry.0 += 1;
            entry.1.push(i);
        }
        let (winner_count, winner_disks) = match hash_counts
            .into_iter()
            .map(|(_, v)| v)
            .max_by_key(|(c, _)| *c)
        {
            Some(v) => v,
            None => return Err(StorageError::InconsistentMeta {
                bucket: bucket.into(),
                key:    key.into(),
                msg:    "no records matched the winning etag".into(),
            }),
        };
        if winner_count < data_blocks {
            return Err(StorageError::InconsistentMeta {
                bucket: bucket.into(),
                key:    key.into(),
                msg:    format!(
                    "decode-contract hash reached only {winner_count}/{data_blocks} disks"
                ),
            });
        }

        // ----- (6) return -----
        // Any disk in `winner_disks` is a valid choice; pick the
        // first (lowest-indexed) for stable behavior.
        let i  = winner_disks[0];
        let fi = metas[i].take().expect("winner index points to Some by construction");
        Ok((backends[i].clone(), fi))
    }
}

// ---------------------------------------------------------------------------
// Consensus helpers (port of MinIO's reduceErrs / commonParity / commonETag /
// findFileInfoInQuorum). Kept module-local — they're not part of the public
// engine surface.
// ---------------------------------------------------------------------------

/// Tally per-disk errors and return `(max_count, dominant_err)`.
/// Errors that look like "transient liveness signals" (DiskNotFound,
/// DiskOngoingReq) are skipped — they should not vote in the error
/// consensus, mirroring MinIO's `objectOpIgnoredErrs`.
fn dominant_error(errs: &[Option<IoError>]) -> (usize, Option<IoError>) {
    use std::collections::HashMap;
    let mut counts: HashMap<&'static str, (usize, &IoError)> = HashMap::new();
    for e_opt in errs.iter() {
        let Some(e) = e_opt else { continue };
        // Liveness-noise errors don't vote.
        if matches!(e, IoError::Io(io) if io.kind() == std::io::ErrorKind::ConnectionRefused
                                       || io.kind() == std::io::ErrorKind::TimedOut) {
            continue;
        }
        let tag = error_tag(e);
        let entry = counts.entry(tag).or_insert((0, e));
        entry.0 += 1;
    }
    counts.into_iter()
        .max_by_key(|(_, (c, _))| *c)
        .map(|(_, (c, e))| (c, Some(clone_io_error(e))))
        .unwrap_or((0, None))
}

/// Stable string tag for an IoError variant — used as the HashMap key
/// when counting common errors.  We don't `derive(Hash)` on `IoError`
/// because some variants carry non-hashable payloads; tagging by
/// variant keeps the consensus comparison precise without requiring
/// the trait.
fn error_tag(e: &IoError) -> &'static str {
    match e {
        IoError::FileNotFound { .. }               => "FileNotFound",
        IoError::FileAlreadyExists { .. }          => "FileAlreadyExists",
        IoError::FileVersionNotFound { .. }        => "FileVersionNotFound",
        IoError::VolumeNotFound(_)                 => "VolumeNotFound",
        IoError::VolumeExists(_)                   => "VolumeExists",
        IoError::VolumeNotEmpty(_)                 => "VolumeNotEmpty",
        IoError::CorruptMetadata { .. }            => "CorruptMetadata",
        IoError::UnsupportedMetadataVersion { .. } => "UnsupportedMetadataVersion",
        IoError::BitrotCheckFailed { .. }          => "BitrotCheckFailed",
        IoError::InvalidArgument(_)                => "InvalidArgument",
        IoError::Unsupported(_)                    => "Unsupported",
        IoError::Encode(_)                         => "Encode",
        IoError::Decode(_)                         => "Decode",
        IoError::Io(_)                             => "Io",
    }
}

/// Clone the dominant error so we can return it without a borrow on
/// the original errors vec. Most variants are cheap to clone; the Io
/// variant requires reconstructing a new `std::io::Error` from kind +
/// string.
fn clone_io_error(e: &IoError) -> IoError {
    match e {
        IoError::FileNotFound { volume, path }      => IoError::FileNotFound { volume: volume.clone(), path: path.clone() },
        IoError::FileAlreadyExists { volume, path } => IoError::FileAlreadyExists { volume: volume.clone(), path: path.clone() },
        IoError::FileVersionNotFound { volume, path, version_id }
            => IoError::FileVersionNotFound { volume: volume.clone(), path: path.clone(), version_id: version_id.clone() },
        IoError::VolumeNotFound(v)                  => IoError::VolumeNotFound(v.clone()),
        IoError::VolumeExists(v)                    => IoError::VolumeExists(v.clone()),
        IoError::VolumeNotEmpty(v)                  => IoError::VolumeNotEmpty(v.clone()),
        IoError::CorruptMetadata { volume, path, msg }
            => IoError::CorruptMetadata { volume: volume.clone(), path: path.clone(), msg: msg.clone() },
        IoError::UnsupportedMetadataVersion { found, max }
            => IoError::UnsupportedMetadataVersion { found: *found, max: *max },
        IoError::BitrotCheckFailed { volume, path }
            => IoError::BitrotCheckFailed { volume: volume.clone(), path: path.clone() },
        IoError::InvalidArgument(s) => IoError::InvalidArgument(s.clone()),
        IoError::Unsupported(s)     => IoError::Unsupported(s),
        IoError::Encode(s)          => IoError::Encode(s.clone()),
        IoError::Decode(s)          => IoError::Decode(s.clone()),
        IoError::Io(io)             => IoError::Io(std::io::Error::new(io.kind(), io.to_string())),
    }
}

/// Vote on the `parity_blocks` value declared per-disk. Returns the
/// parity value whose record-count meets its corresponding read
/// quorum (`D = N - parity`), or `None` if no value reaches its
/// quorum. Mirrors MinIO's `commonParity` (`erasure-metadata.go:460`).
fn common_parity(metas: &[Option<FileInfo>], n: usize) -> Option<u8> {
    let mut parity_counts: HashMap<u8, usize> = HashMap::new();
    for m in metas.iter().flatten() {
        if !erasure_is_valid(&m.erasure) { continue }
        // Delete markers force parity = N/2 (matches MinIO's
        // `listObjectParities` line 514).
        let p = if m.deleted || m.size == 0 { (n / 2) as u8 } else { m.erasure.parity_blocks };
        *parity_counts.entry(p).or_insert(0) += 1;
    }
    let mut best: Option<(u8, usize)> = None;
    for (p, occ) in parity_counts {
        let read_quorum = n - p as usize;
        if occ < read_quorum { continue }
        if best.map_or(true, |(_, prev)| occ > prev) {
            best = Some((p, occ));
        }
    }
    best.map(|(p, _)| p)
}

/// Return the etag value at least `quorum` records share. `None` if
/// no etag reaches the threshold. Records without an etag (delete
/// markers, or corrupt records missing the field) are ignored.
fn common_etag(metas: &[Option<FileInfo>], quorum: usize) -> Option<String> {
    let mut counts: HashMap<&str, usize> = HashMap::new();
    for m in metas.iter().flatten() {
        let Some(e) = m.metadata.get(ETAG_META_KEY) else { continue };
        if e.is_empty() { continue }
        *counts.entry(e.as_str()).or_insert(0) += 1;
    }
    let (winner, count) = counts.into_iter().max_by_key(|&(_, c)| c)?;
    if count >= quorum { Some(winner.to_owned()) } else { None }
}

fn record_etag_matches(fi: &FileInfo, etag: &str) -> bool {
    fi.metadata.get(ETAG_META_KEY).map(String::as_str) == Some(etag)
}

/// BLAKE3 over the decode-contract fields. Combines what MinIO's
/// `findFileInfoInQuorum` (`erasure-metadata.go:289-398`) hashes
/// with the filter signals MinIO splits into a pre-step
/// (`commonTime` / `commonETag`). MinIO uses time/etag as a separate
/// filter to tolerate clock skew across replicas; we fold them into
/// the content hash because our coordinator stamps both atomically
/// per write — if they disagree across disks, that's a real
/// inconsistency, not benign drift.
///
/// Fields included:
///   - version_id   — UUID of the write event (S3 versioning identity)
///   - mod_time_ms  — coordinator-assigned write timestamp
///   - etag         — body fingerprint (MD5 / blake3 hex)
///   - deleted flag
///   - parts table: (number, size) per part
///   - EC config: data_blocks, parity_blocks, block_size, distribution
///
/// Fields explicitly excluded:
///   - data_dir (matches MinIO's intentional removal — allows partial
///     rebalance to not block reads)
///   - erasure.index (per-disk by design; differs across disks even
///     for a correct write)
///   - data (inline body — verified separately by etag match)
fn decode_contract_hash(fi: &FileInfo) -> [u8; 32] {
    use blake3::Hasher;
    let mut h = Hasher::new();
    h.update(fi.version_id.as_bytes());
    h.update(&fi.mod_time_ms.to_le_bytes());
    if let Some(etag) = fi.metadata.get(ETAG_META_KEY) {
        h.update(etag.as_bytes());
    }
    h.update(&[fi.deleted as u8]);
    for p in &fi.parts {
        h.update(&p.number.to_le_bytes());
        h.update(&p.size.to_le_bytes());
    }
    if !fi.deleted && fi.size != 0 {
        h.update(&[fi.erasure.data_blocks, fi.erasure.parity_blocks]);
        h.update(&fi.erasure.block_size.to_le_bytes());
        h.update(&fi.erasure.distribution);
    }
    *h.finalize().as_bytes()
}

/// `IsValid` check for `ErasureInfo` records as returned from disk —
/// matches MinIO's `FileInfo.IsValid()` (`erasure-metadata.go:73-87`).
/// Used as a precondition before counting parity / hashing content.
fn erasure_is_valid(ei: &ErasureInfo) -> bool {
    if ei.data_blocks == 0 { return false; }
    if ei.parity_blocks > ei.data_blocks { return false; }
    let n = (ei.data_blocks as usize) + (ei.parity_blocks as usize);
    if ei.distribution.len() != n { return false; }
    if (ei.index as usize) == 0 || (ei.index as usize) > n { return false; }
    true
}

// ---------------------------------------------------------------------------
// EcReadStream: ByteStream that decodes one EC stripe at a time and yields
// the original payload to the caller. Owns the per-backend ByteStreams; on
// each `read` it pulls one shard's worth from each surviving backend, decodes
// the stripe, and serves bytes from the decoded buffer until the caller has
// consumed it, then advances to the next stripe.
// ---------------------------------------------------------------------------

struct EcReadStream {
    ec:                Erasure,
    sources:           Vec<Option<Box<dyn ByteStream>>>,
    /// Per-source leftover from a prior `src.read()` that returned more
    /// bytes than the in-progress refill needed. Without this, the
    /// over-read tail would be discarded and the next stripe's refill
    /// would short-read against an exhausted source. Empty `Bytes`
    /// when no carry is held. Only ever populated by a successful
    /// over-read; cleared as soon as it's consumed.
    source_carries:    Vec<bytes::Bytes>,
    stripes_remaining: usize,
    stripe_unit:       usize,
    data_shards:       usize,
    parity_shards:     usize,
    /// Total bytes still to surface to the caller (= `fi.size` minus
    /// what we've already returned).
    total_remaining:   u64,
    /// D data shards for the current stripe, refcounted `Bytes` in
    /// slot order. Originals come back from `decode_stripe` as
    /// zero-copy clones of the input, restored shards as fresh
    /// pool-backed `Bytes`. Refilled per stripe.
    decoded:           Vec<bytes::Bytes>,
    /// Current shard index within `decoded` we're serving from.
    decode_shard:      usize,
    /// Bytes already served out of `decoded[decode_shard]`.
    shard_pos:         usize,
    bucket:            String,
    key:               String,
}

impl EcReadStream {
    /// Pull one shard's worth of bytes (`unit`) from every surviving
    /// source, run the SIMD decoder, and stage the D data shards in
    /// `self.decoded`. The caller's `read()` then walks them in order
    /// without copying — each yielded `Bytes` is a refcounted slice
    /// of one of the decoded shards.
    async fn refill(&mut self) -> phenomenal_io::IoResult<()> {
        let n    = self.sources.len();
        let unit = self.stripe_unit;

        // Per-source: pull bytes until we have `unit` and freeze into
        // a single contiguous `Bytes` (the decoder requires
        // contiguous slices). This is the unavoidable shard
        // reassembly memcpy — same shape as 3FS's `localbuf`.
        let mut fan = Vec::with_capacity(n);
        for (i, slot) in self.sources.iter_mut().enumerate() {
            if let Some(src) = slot.take() {
                // Take any leftover from the prior refill — these are
                // bytes the source already yielded but the prior
                // stripe didn't need.
                let initial_carry = std::mem::replace(&mut self.source_carries[i], bytes::Bytes::new());
                fan.push(Box::pin(async move {
                    let mut src   = src;
                    let mut carry = initial_carry;
                    let mut buf   = phenomenal_io::PooledBuffer::with_capacity(unit);
                    // First, drain whatever we already had in carry.
                    if !carry.is_empty() {
                        let take = (unit - buf.len()).min(carry.len());
                        buf.extend_from_slice(&carry[..take]);
                        carry = bytes::Bytes::slice(&carry, take..);
                    }
                    // Pull more chunks until buf == unit. Save the
                    // remainder of any over-read into `carry` for the
                    // next stripe.
                    while buf.len() < unit {
                        match src.read().await {
                            Ok(chunk) if chunk.is_empty() => break,
                            Ok(chunk) => {
                                let take = (unit - buf.len()).min(chunk.len());
                                buf.extend_from_slice(&chunk[..take]);
                                if take < chunk.len() {
                                    carry = bytes::Bytes::slice(&chunk, take..);
                                }
                            }
                            Err(e) => return (i, None::<Box<dyn ByteStream>>, None, carry, Some(e)),
                        }
                    }
                    let frozen = if buf.len() == unit { Some(buf.freeze()) } else { None };
                    (i, Some(src), frozen, carry, None)
                }) as std::pin::Pin<Box<dyn std::future::Future<Output =
                    (usize, Option<Box<dyn ByteStream>>, Option<bytes::Bytes>, bytes::Bytes, Option<IoError>)>>>);
            }
        }
        let results = join_all(fan).await;

        // Reassemble: alive sources & their shard bytes; failed ones
        // become None for the decoder.
        let mut shard_opts: Vec<Option<bytes::Bytes>> = vec![None; n];
        for (i, src_opt, shard, carry, err) in results {
            self.source_carries[i] = carry;
            if err.is_none() {
                if shard.is_some() {
                    self.sources[i] = src_opt;
                    shard_opts[i]   = shard;
                } else {
                    // Short read — mark the source dead; subsequent
                    // stripes still try the rest.
                    self.sources[i] = None;
                }
            } else {
                self.sources[i] = None;
            }
        }

        let alive = shard_opts.iter().filter(|s| s.is_some()).count();
        if alive < self.data_shards {
            return Err(IoError::FileNotFound {
                volume: self.bucket.clone(),
                path:   format!("{}/part.1", self.key),
            });
        }

        // Decode: yields the D data shards as Bytes — originals
        // returned as zero-copy clones, restored ones as fresh
        // pool-backed allocations.
        self.decoded = self.ec.decode_stripe(shard_opts, unit)
            .map_err(|e| IoError::InvalidArgument(format!("EC decode: {e}")))?;
        self.decode_shard      = 0;
        self.shard_pos         = 0;
        self.stripes_remaining = self.stripes_remaining.saturating_sub(1);
        let _ = self.parity_shards; // touch to keep field live for future heal hook
        Ok(())
    }

    /// Bytes still available in the current stripe's `decoded` rope
    /// from the current position onward.
    fn stripe_remaining_bytes(&self) -> usize {
        if self.decode_shard >= self.decoded.len() {
            return 0;
        }
        let mut r = self.decoded[self.decode_shard].len() - self.shard_pos;
        for s in &self.decoded[self.decode_shard + 1..] {
            r += s.len();
        }
        r
    }
}

/// Open one part's EC streams across the set, returning a configured
/// `EcReadStream` ready to yield that part's bytes. Shared by single-
/// part and multipart reads — single-shot PUTs invoke this once
/// (parts == 1); multipart-assembled objects invoke once per part.
async fn open_ec_part_stream(
    backends:      &[Rc<dyn StorageBackend>],
    bucket:        &str,
    key:           &str,
    part_path:     &str,
    actual_size:   u64,
    block_size:    usize,
    stripe_unit:   usize,
    data_shards:   usize,
    parity_shards: usize,
    ec:            Erasure,
) -> StorageResult<EcReadStream> {
    let n       = backends.len();
    let stripes = (actual_size as usize).div_ceil(block_size).max(1);
    let on_disk_per_shard = (stripes as u64) * stripe_unit as u64;

    let opens = backends.iter().map(|b| {
        let b      = b.clone();
        let bucket = bucket.to_owned();
        let pp     = part_path.to_owned();
        async move { b.read_file_stream(&bucket, &pp, 0, on_disk_per_shard).await }
    });
    let opened = join_all(opens).await;
    let mut sources: Vec<Option<Box<dyn ByteStream>>> = Vec::with_capacity(n);
    let mut ok_count = 0usize;
    for r in opened {
        match r {
            Ok(s)  => { sources.push(Some(s)); ok_count += 1; }
            Err(_) => sources.push(None),
        }
    }
    if ok_count < data_shards {
        return Err(StorageError::ObjectNotFound {
            bucket: bucket.to_owned(),
            key:    key.to_owned(),
        });
    }
    let n_carries = sources.len();
    Ok(EcReadStream {
        ec,
        sources,
        source_carries:    vec![bytes::Bytes::new(); n_carries],
        stripes_remaining: stripes,
        stripe_unit,
        data_shards,
        parity_shards,
        total_remaining:   actual_size,
        decoded:           Vec::new(),
        decode_shard:      0,
        shard_pos:         0,
        bucket:            bucket.to_owned(),
        key:               key.to_owned(),
    })
}

/// `ByteStream` that walks `fi.parts` in order and drains each part's
/// own `EcReadStream` before opening the next. Single-part objects
/// (single-shot PUTs) and multipart-assembled objects share this
/// path — only the part count differs.
///
/// Lazy: at most one part's set of per-disk streams is open at a
/// time, so file-descriptor count stays at N (set size) even for
/// objects with thousands of parts.
struct MultiPartEcStream {
    backends:      Vec<Rc<dyn StorageBackend>>,
    bucket:        String,
    key:           String,
    data_dir:      String,
    parts:         Vec<ObjectPartInfo>,
    next_idx:      usize,
    block_size:    usize,
    stripe_unit:   usize,
    data_shards:   usize,
    parity_shards: usize,
    ec:            Erasure,
    current:       Option<EcReadStream>,
}

impl MultiPartEcStream {
    /// Ensure `self.current` is populated with the next part's stream.
    /// Returns `Ok(false)` once every part has been drained.
    async fn advance(&mut self) -> phenomenal_io::IoResult<bool> {
        if self.current.is_some() { return Ok(true); }
        if self.next_idx >= self.parts.len() { return Ok(false); }
        let p    = &self.parts[self.next_idx];
        let path = format!("{}/{}/part.{}", self.key, self.data_dir, p.number);
        let s    = open_ec_part_stream(
            &self.backends, &self.bucket, &self.key, &path,
            p.actual_size as u64,
            self.block_size, self.stripe_unit,
            self.data_shards, self.parity_shards,
            self.ec.clone(),
        ).await.map_err(|e| match e {
            StorageError::ObjectNotFound { .. } => IoError::FileNotFound {
                volume: self.bucket.clone(), path: path.clone(),
            },
            StorageError::Io(io) => io,
            other                => IoError::InvalidArgument(other.to_string()),
        })?;
        self.current  = Some(s);
        self.next_idx += 1;
        Ok(true)
    }
}

#[async_trait(?Send)]
impl ByteStream for MultiPartEcStream {
    async fn read(&mut self) -> phenomenal_io::IoResult<bytes::Bytes> {
        loop {
            if !self.advance().await? {
                return Ok(bytes::Bytes::new());
            }
            let chunk = self.current.as_mut().unwrap().read().await?;
            if !chunk.is_empty() { return Ok(chunk); }
            // Current part fully drained — close and let the next loop
            // iteration open the next part.
            self.current = None;
        }
    }
}

#[async_trait(?Send)]
impl ByteStream for EcReadStream {
    async fn read(&mut self) -> phenomenal_io::IoResult<bytes::Bytes> {
        if self.total_remaining == 0 {
            return Ok(bytes::Bytes::new());
        }
        if self.stripe_remaining_bytes() == 0 {
            if self.stripes_remaining == 0 {
                return Ok(bytes::Bytes::new());
            }
            self.refill().await?;
        }
        // Yield the next slice of the current shard as `Bytes` —
        // refcount-only handoff, no userspace memcpy. If the caller
        // needs less than what the shard has left we slice; if the
        // shard is fully drained we advance to the next shard on the
        // next call.
        let shard      = &self.decoded[self.decode_shard];
        let shard_len  = shard.len();
        let avail      = shard_len - self.shard_pos;
        let serve      = avail.min(self.total_remaining as usize);
        let frame      = bytes::Bytes::slice(shard, self.shard_pos..self.shard_pos + serve);
        self.shard_pos     += serve;
        self.total_remaining -= serve as u64;
        if self.shard_pos == shard_len {
            self.decode_shard += 1;
            self.shard_pos = 0;
        }
        Ok(frame)
    }
}

/// S3 bucket-name rules. 
fn validate_bucket_name(name: &str) -> StorageResult<()> {
    static VALID_BUCKET_NAME_STRICT: std::sync::LazyLock<regex::Regex> =
        std::sync::LazyLock::new(|| {
            regex::Regex::new(r"^[a-z0-9][a-z0-9\.\-]{1,61}[a-z0-9]$").unwrap()
        });
    static IP_ADDRESS: std::sync::LazyLock<regex::Regex> =
        std::sync::LazyLock::new(|| {
            regex::Regex::new(r"^(\d+\.){3}\d+$").unwrap()
        });

    let bad = || StorageError::InvalidBucketName(name.to_owned());
    let trimmed = name.trim();

    if trimmed.is_empty()      { return Err(bad()); }
    if trimmed.len() < 3       { return Err(bad()); }
    if trimmed.len() > 63      { return Err(bad()); }
    if trimmed == "phenomenal" { return Err(bad()); }
    if IP_ADDRESS.is_match(trimmed) { return Err(bad()); }
    if trimmed.contains("..")
        || trimmed.contains(".-")
        || trimmed.contains("-.")
    {
        return Err(bad());
    }
    if !VALID_BUCKET_NAME_STRICT.is_match(trimmed) {
        return Err(bad());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// Reduce a fan-out's per-disk results to a single quorum verdict.
///
/// Successes and `benign` errors (e.g. `VolumeExists` on idempotent
/// CreateBucket retry) both count toward `ok`. If `ok >= quorum` the
/// call succeeded.
///
/// On failure we return the **modal** error — the variant most disks
/// agreed on — not whichever happened to land in the result vec
/// first. Mirrors MinIO's `reduceWriteQuorumErrs`
/// (erasure-metadata-utils.go:120). One flaky disk's spurious IO
/// error no longer masks the cluster-wide truth (e.g. 6/8 say "exists").
fn require_quorum<T>(
    results: Vec<Result<T, IoError>>,
    quorum: usize,
    benign: impl Fn(&IoError) -> bool,
) -> Result<(), IoError> {
    let mut ok    = 0usize;
    // (discriminant_count, exemplar_error). N is small (cluster disk
    // count, typically <=16) so a flat Vec scan beats hashing.
    let mut buckets: Vec<(std::mem::Discriminant<IoError>, usize, IoError)> = Vec::new();
    for r in results {
        match r {
            Ok(_)                => ok += 1,
            Err(e) if benign(&e) => ok += 1,
            Err(e) => {
                let d = std::mem::discriminant(&e);
                if let Some(slot) = buckets.iter_mut().find(|(disc, _, _)| *disc == d) {
                    slot.1 += 1;
                } else {
                    buckets.push((d, 1, e));
                }
            }
        }
    }
    if ok >= quorum { return Ok(()); }
    let modal = buckets.into_iter()
        .max_by_key(|(_, count, _)| *count)
        .map(|(_, _, e)| e);
    Err(modal.unwrap_or_else(|| IoError::InvalidArgument("no results".into())))
}

fn build_file_info(
    volume: &str, name: &str, size: i64, etag: &str, mod_time_ms: u64,
    content_type: Option<String>, inline: Option<Vec<bytes::Bytes>>,
    parts: Vec<ObjectPartInfo>,
) -> FileInfo {
    let mut fi = FileInfo::default();
    fi.volume       = volume.to_owned();
    fi.name         = name.to_owned();
    fi.size         = size;
    fi.mod_time_ms  = mod_time_ms;
    fi.is_latest    = true;
    fi.num_versions = 1;
    fi.fresh        = true;
    fi.parts        = parts;
    fi.data         = inline;
    fi.metadata.insert(ETAG_META_KEY.into(), etag.to_owned());
    if let Some(ct) = content_type {
        fi.metadata.insert(CONTENT_TYPE_META_KEY.into(), ct);
    }
    fi
}

fn to_object_info(bucket: &str, fi: &FileInfo) -> ObjectInfo {
    let storage_class = if fi.data.is_some() { StorageClass::Inline } else { StorageClass::Single };
    ObjectInfo {
        bucket:        bucket.to_owned(),
        key:           fi.name.clone(),
        size:          fi.size.max(0) as u64,
        etag:          fi.metadata.get(ETAG_META_KEY).cloned().unwrap_or_default(),
        storage_class,
        modified_ms:   fi.mod_time_ms,
        content_type:  fi.metadata.get(CONTENT_TYPE_META_KEY).cloned(),
        version_id:    fi.version_id.clone(),
        is_delete_marker: fi.deleted,
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn now_nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

fn format_upload_id(deployment_id: uuid::Uuid) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    let payload = format!(
        "{}.{}x{}",
        deployment_id.simple(),
        Uuid::new_v4().simple(),
        now_nanos(),
    );
    URL_SAFE_NO_PAD.encode(payload.as_bytes())
}

async fn drain_inline_payload(
    src:         &mut dyn ByteStream,
    payload_len: usize,
) -> phenomenal_io::IoResult<(Vec<bytes::Bytes>, String)> {
    let mut frames: Vec<bytes::Bytes> = Vec::new();
    let mut hasher = blake3::Hasher::new();
    let mut total  = 0usize;
    while total < payload_len {
        let chunk = src.read().await?;
        if chunk.is_empty() {
            return Err(IoError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                format!("inline put: source ended at {total}/{payload_len}"),
            )));
        }
        let take  = (payload_len - total).min(chunk.len());
        let frame = if take < chunk.len() { bytes::Bytes::slice(&chunk, ..take) } else { chunk };
        hasher.update(&frame);
        total += frame.len();
        frames.push(frame);
    }
    Ok((frames, hasher.finalize().to_hex().to_string()))
}

/// Cluster-wide nominal EC contract recorded on every persisted
/// `FileInfo`, inline or EC. Mirrors MinIO's `Erasure.BlockSize`
/// semantics: `block_size` = full stripe = `D × per-shard`. The
/// per-disk slot index is stamped later by [`with_per_disk_index`].
fn default_erasure_info(data_shards: u8, parity_shards: u8, n: u8) -> ErasureInfo {
    ErasureInfo {
        algorithm:    "ReedSolomon".into(),
        data_blocks:  data_shards,
        parity_blocks: parity_shards,
        index:        0, // overridden per-disk by with_per_disk_index
        block_size:   (DEFAULT_EC_PER_SHARD_BYTES * data_shards as usize) as u32,
        distribution: (1..=n).collect(),
        checksums:    Vec::new(),
    }
}

/// Clone the base `FileInfo` once per backend, stamping each
/// clone's `erasure.index` with its 1-based slot in the set.
fn with_per_disk_index(base_fi: &FileInfo, base_erasure: &ErasureInfo, n: usize) -> Vec<FileInfo> {
    (0..n).map(|i| {
        let mut fi     = base_fi.clone();
        let mut ec_per = base_erasure.clone();
        ec_per.index   = (i + 1) as u8;
        fi.erasure     = ec_per;
        fi
    }).collect()
}

/// Single-part record. Inline objects use `on_disk_size = full size`;
/// EC objects use `on_disk_size = padded per-shard width` and
/// `actual_size = full size` so the GET path knows how much to
/// trim back after EC decode.
fn single_part_info(etag: &str, on_disk_size: i64, actual_size: i64, mod_time_ms: u64) -> Vec<ObjectPartInfo> {
    vec![ObjectPartInfo {
        etag:        etag.to_owned(),
        number:      1,
        size:        on_disk_size,
        actual_size,
        mod_time_ms,
        index:       Vec::new(),
        checksums:   Default::default(),
    }]
}

async fn open_staging_sinks(
    backends:       &[Rc<dyn StorageBackend>],
    staging_id:     &str,
    data_dir:       &str,
    per_shard_size: u64,
) -> phenomenal_io::IoResult<Vec<Box<dyn ByteSink>>> {
    use phenomenal_io::STAGING_VOL;
    let part_path = format!("{staging_id}/{data_dir}/{PART1_PATH_SUFFIX}");
    let opens = backends.iter().map(|b| {
        let b  = b.clone();
        let pp = part_path.clone();
        async move { b.create_file_writer(STAGING_VOL, &pp, per_shard_size).await }
    });
    join_all(opens).await.into_iter().collect()
}

async fn read_part_sidecars(
    backends:     &[Rc<dyn StorageBackend>],
    session_path: &str,
    data_dir:     &str,
    parts:        &[crate::object::CompletePart],
    min_present:  usize,
) -> StorageResult<Vec<ObjectPartInfo>> {
    let mut out: Vec<ObjectPartInfo> = Vec::with_capacity(parts.len());
    for p in parts {
        let path = format!("{session_path}/{data_dir}/part.{}.meta", p.part_number);
        let reads = backends.iter().map(|b| {
            let b    = b.clone();
            let path = path.clone();
            async move { b.read_file(MULTIPART_VOL, &path).await }
        });
        let results = join_all(reads).await;

        let mut decoded: Option<ObjectPartInfo> = None;
        let mut present = 0usize;
        for r in results {
            if let Ok(Some(bytes)) = r {
                present += 1;
                if decoded.is_none() {
                    decoded = Some(rmp_serde::from_slice(&bytes).map_err(|e| {
                        StorageError::Io(IoError::Decode(format!(
                            "part.{}.meta: {e}", p.part_number
                        )))
                    })?);
                }
            }
        }
        if present < min_present || decoded.is_none() {
            return Err(StorageError::Io(IoError::InvalidArgument(format!(
                "part.{} sidecar missing or below read quorum ({present}/{min_present})",
                p.part_number
            ))));
        }
        out.push(decoded.unwrap());
    }
    Ok(out)
}

async fn open_part_staging_sinks(
    backends:       &[Rc<dyn StorageBackend>],
    tmp_part_path:  &str,
    per_shard_size: u64,
) -> phenomenal_io::IoResult<Vec<Box<dyn ByteSink>>> {
    use phenomenal_io::STAGING_VOL;
    let opens = backends.iter().map(|b| {
        let b  = b.clone();
        let pp = tmp_part_path.to_owned();
        async move { b.create_file_writer(STAGING_VOL, &pp, per_shard_size).await }
    });
    join_all(opens).await.into_iter().collect()
}

fn majority_key<I, K>(items: I, threshold: usize) -> Option<K>
where
    I: IntoIterator<Item = K>,
    K: Eq + std::hash::Hash + Clone,
{
    let mut counts: HashMap<K, usize> = HashMap::new();
    for k in items {
        let entry = counts.entry(k.clone()).or_insert(0);
        *entry += 1;
        if *entry >= threshold { return Some(k); }
    }
    None
}

async fn read_session_fi(
    backends:     &[Rc<dyn StorageBackend>],
    session_path: &str,
) -> StorageResult<FileInfo> {
    let metas: Vec<phenomenal_io::IoResult<FileInfo>> = join_all(
        backends.iter().map(|b| {
            let b    = b.clone();
            let path = session_path.to_owned();
            async move { b.read_version("", MULTIPART_VOL, &path, None, false).await }
        })
    ).await;

    let mut valid: Vec<FileInfo>     = Vec::with_capacity(metas.len());
    let mut last_err: Option<IoError> = None;
    for r in metas {
        match r {
            Ok(fi) => valid.push(fi),
            Err(e) => last_err = Some(e),
        }
    }

    let needed = (backends.len() / 2) + 1;
    let key_of = |fi: &FileInfo| {
        (fi.data_dir.clone(), fi.erasure.data_blocks, fi.erasure.parity_blocks)
    };
    let winner = majority_key(valid.iter().map(key_of), needed).ok_or_else(|| {
        StorageError::Io(last_err.unwrap_or_else(|| IoError::InvalidArgument(
            format!("session {session_path}: no quorum on data_dir/erasure")
        )))
    })?;
    Ok(valid.into_iter().find(|fi| key_of(fi) == winner)
        .expect("majority_key returned a key with at least one matching record"))
}

async fn encode_and_write_stripes(
    ec:          &Erasure,
    src:         &mut dyn ByteStream,
    size:        u64,
    stripe_data: usize,
    stripes:     usize,
    sinks:       Vec<Box<dyn ByteSink>>,
) -> phenomenal_io::IoResult<(String, Vec<Box<dyn ByteSink>>)> {
    let mut slots: Vec<Option<Box<dyn ByteSink>>> = sinks.into_iter().map(Some).collect();
    let n = slots.len();
    let mut etag_hasher = blake3::Hasher::new();
    let mut consumed: u64 = 0;
    let mut carry: bytes::Bytes = bytes::Bytes::new();

    for _ in 0..stripes {
        let mut stripe_buf = PooledBuffer::with_capacity(stripe_data);
        unsafe { stripe_buf.set_len(stripe_data); }

        let want = ((size - consumed) as usize).min(stripe_data);
        let mut filled = 0usize;
        while filled < want {
            if carry.is_empty() {
                carry = src.read().await?;
                if carry.is_empty() {
                    return Err(IoError::Io(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        format!("EC put: source ended at {}/{size}", consumed + filled as u64),
                    )));
                }
            }
            let take = (want - filled).min(carry.len());
            stripe_buf[filled..filled + take].copy_from_slice(&carry[..take]);
            filled += take;
            carry = bytes::Bytes::slice(&carry, take..);
        }
        etag_hasher.update(&stripe_buf[..want]);
        for b in &mut stripe_buf[want..stripe_data] { *b = 0; }
        consumed += want as u64;

        let shards = ec.encode_stripe(stripe_buf.freeze())
            .map_err(|e| IoError::InvalidArgument(format!("EC encode: {e}")))?;

        let mut fan = Vec::with_capacity(n);
        for (i, (slot, shard)) in slots.iter_mut().zip(shards.into_iter()).enumerate() {
            let mut sink = slot.take().expect("sink slot must be filled between stripes");
            fan.push(Box::pin(async move {
                let res = sink.write_all(shard).await;
                (i, sink, res)
            }) as std::pin::Pin<Box<dyn std::future::Future<Output = (usize, Box<dyn ByteSink>, phenomenal_io::IoResult<()>)>>>);
        }
        let results = join_all(fan).await;
        let mut first_err: Option<IoError> = None;
        for (i, sink, res) in results {
            slots[i] = Some(sink);
            if let Err(e) = res {
                if first_err.is_none() { first_err = Some(e); }
            }
        }
        if let Some(e) = first_err { return Err(e); }
    }

    let sinks: Vec<Box<dyn ByteSink>> = slots.into_iter()
        .map(|s| s.expect("every sink slot must hold a sink at end of stripe loop"))
        .collect();
    Ok((etag_hasher.finalize().to_hex().to_string(), sinks))
}

/// Drive every sink's `finish` in parallel — flush + read the
/// status frame on remote sinks — and require write quorum.
/// Without a healer `quorum == N`, so this is effectively
/// "all-or-error".
async fn finalize_sinks_quorum(
    sinks:  Vec<Box<dyn ByteSink>>,
    quorum: usize,
) -> phenomenal_io::IoResult<()> {
    let n = sinks.len();
    let mut fan = Vec::with_capacity(n);
    for (i, mut sink) in sinks.into_iter().enumerate() {
        fan.push(Box::pin(async move {
            (i, sink.finish().await)
        }) as std::pin::Pin<Box<dyn std::future::Future<Output = (usize, phenomenal_io::IoResult<()>)>>>);
    }
    let results = join_all(fan).await;
    require_quorum(
        results.into_iter().map(|(_, r)| r).collect(),
        quorum,
        |_| false,
    )
}

/// Atomic per-disk PUT promotion. Each `per_disk_fis[i]` is fanned out
/// to `backends[i].rename_data(...)`. Behavior:
///
///   * If at least `quorum` disks succeed, the call returns `Ok(())`.
///     For each successful disk that returned a non-empty
///     `old_data_dir`, fire off a best-effort recursive delete of
///     `{key}/{old_data_dir}` on that disk so the prior version's
///     bytes don't linger. (Inline payloads always have an empty
///     `old_data_dir`; EC overwrites by inline correctly clean up the
///     prior EC `data_dir`.)
///
///   * If fewer than `quorum` disks succeed, issue compensating undo
///     on the disks that DID succeed — recursive delete of
///     `{key}/{new_data_dir}` to roll back the partial promotion.
///     Mirrors MinIO's `renameData` post-failure cleanup
///     (`erasure-object.go:1086-1103`).
///
/// `staging_id` is also cleaned up on every disk after the call: on
/// success the staging dir is already empty (rename_data moved the
/// data dir out); we issue a best-effort dir remove for both the
/// success and quorum-fail paths.
/// Atomic per-disk promotion of a staged object into its final
/// `(bucket, key)` location. The staged dir lives at
/// `src_volume/src_path/` and contains the object's `data_dir/` subdir
/// plus any session metadata; this function fans out a `rename_data`
/// RPC across all backends to move both the data_dir and a synthesized
/// `xl.meta` into the user bucket atomically per-disk.
///
/// On quorum failure: undo every successful disk via `delete_version
/// (undo_write=true)` (which restores the prior `xl.meta.bkp`) and
/// best-effort wipe the source staging dir.
///
/// On quorum success: trash any prior version's `data_dir` for which
/// `rename_data` returned an `old_data_dir` (Suspended/Unversioned
/// overwrite path), then wipe the source staging dir.
///
/// Used by:
///   - `Engine::put_ec`        with `src_volume = STAGING_VOL`,  `src_path = <staging_id>`
///   - `Engine::complete_multipart_upload` with
///     `src_volume = MULTIPART_VOL`, `src_path = <bucket>/<key>/<upload_id>`
async fn promote_versions(
    backends:     &[Rc<dyn StorageBackend>],
    src_volume:   &str,
    src_path:     &str,
    per_disk_fis: Vec<FileInfo>,
    bucket:       &str,
    key:          &str,
    quorum:       usize,
) -> StorageResult<()> {
    assert_eq!(per_disk_fis.len(), backends.len());

    let promotes = backends.iter().zip(per_disk_fis.into_iter()).enumerate().map(
        |(i, (b, fi))| {
            let b          = b.clone();
            let src_volume = src_volume.to_owned();
            let src_path   = src_path.to_owned();
            let bucket     = bucket.to_owned();
            let key        = key.to_owned();
            async move {
                let res = b.rename_data(
                    &src_volume, &src_path,
                    &fi,
                    &bucket, &key,
                    &Default::default(),
                ).await;
                (i, fi, res)
            }
        }
    );
    let results = join_all(promotes).await;

    let mut successes: Vec<(usize, FileInfo, RenameDataResp)> = Vec::new();
    let mut first_err: Option<IoError> = None;
    for (i, fi, r) in results {
        match r {
            Ok(resp) => successes.push((i, fi, resp)),
            Err(e)   => { if first_err.is_none() { first_err = Some(e); } }
        }
    }

    if successes.len() < quorum {
        let undo_opts = DeleteOptions { undo_write: true, ..Default::default() };
        let undos = successes.iter().map(|(i, fi, _)| {
            let b      = backends[*i].clone();
            let bucket = bucket.to_owned();
            let key    = key.to_owned();
            let fi     = fi.clone();
            let opts   = undo_opts.clone();
            async move {
                let _ = b.delete_version(&bucket, &key, &fi, false, &opts).await;
            }
        });
        let _ = join_all(undos).await;
        cleanup_src(backends, src_volume, src_path).await;
        return Err(map_bucket_or_io(bucket)(
            first_err.unwrap_or_else(|| IoError::InvalidArgument("no quorum".into()))
        ));
    }

    let stale_cleanups = successes.iter()
        .filter(|(_, fi, resp)| {
            !resp.old_data_dir.is_empty() && resp.old_data_dir != fi.data_dir
        })
        .map(|(i, _, resp)| {
            let b           = backends[*i].clone();
            let bucket      = bucket.to_owned();
            let stale_path  = format!("{key}/{}", resp.old_data_dir);
            async move {
                let _ = b.delete(&bucket, &stale_path, true).await;
            }
        });
    let _ = join_all(stale_cleanups).await;

    cleanup_src(backends, src_volume, src_path).await;

    Ok(())
}

/// Best-effort recursive remove of `(src_volume, src_path)` on every
/// backend. Used both on failure (errors before promotion / quorum
/// not reached) and as a defensive sweep after a successful promote.
/// Generic over the source volume so it can clean STAGING_VOL after a
/// regular PUT and MULTIPART_VOL after a CompleteMultipartUpload.
async fn cleanup_src(backends: &[Rc<dyn StorageBackend>], src_volume: &str, src_path: &str) {
    let _ = join_all(backends.iter().map(|b| {
        let b   = b.clone();
        let vol = src_volume.to_owned();
        let p   = src_path.to_owned();
        async move {
            let _ = b.delete(&vol, &p, true).await;
        }
    })).await;
}

fn map_bucket_or_io(bucket: &str) -> impl Fn(IoError) -> StorageError + '_ {
    move |e| match e {
        IoError::VolumeNotFound(_) => StorageError::BucketNotFound(bucket.to_owned()),
        other                      => other.into(),
    }
}

fn map_object_missing<'a>(bucket: &'a str, key: &'a str) -> impl Fn(IoError) -> StorageError + 'a {
    move |e| match e {
        IoError::FileNotFound { .. } => StorageError::ObjectNotFound {
            bucket: bucket.to_owned(),
            key:    key.to_owned(),
        },
        IoError::FileVersionNotFound { version_id, .. } => StorageError::VersionNotFound {
            bucket:     bucket.to_owned(),
            key:        key.to_owned(),
            version_id,
        },
        IoError::VolumeNotFound(_)   => StorageError::BucketNotFound(bucket.to_owned()),
        other                        => other.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster::NodeAddr;
    use phenomenal_io::stream::{read_full, VecByteStream};
    use phenomenal_io::LocalFsBackend;
    use tempfile::TempDir;

    fn local_cluster(n: usize, set_size: usize) -> ClusterConfig {
        ClusterConfig {
            nodes: (0..n as u16)
                .map(|i| NodeAddr {
                    id: i,
                    rpc_addr: format!("127.0.0.1:{}", 9100 + i).parse().unwrap(),
                    disk_count: 1,
                })
                .collect(),
            set_drive_count:      set_size,
            default_parity_count: (set_size / 4).max(1),
            deployment_id:        Uuid::nil(),
        }
    }

    async fn eng(n: usize, set_size: usize) -> (Vec<TempDir>, Engine) {
        let cluster = local_cluster(n, set_size);
        let dirs: Vec<TempDir> = (0..n).map(|_| TempDir::new().unwrap()).collect();
        let mut backends: HashMap<DiskAddr, Rc<dyn StorageBackend>> = HashMap::new();
        for (i, d) in dirs.iter().enumerate() {
            // One disk per node for these tests — disk_idx is always 0.
            let addr = DiskAddr { node_id: i as NodeId, disk_idx: 0 };
            backends.insert(addr, Rc::new(LocalFsBackend::new(d.path()).unwrap()));
        }
        let dsync = Rc::new(crate::dsync::DsyncClient::no_op());
        let e = Engine::new(cluster, backends, dsync, 0);
        e.create_bucket("buk", BucketMeta::new(0, false)).await.unwrap();
        (dirs, e)
    }

    /// Test helper: streaming PUT from a Vec.
    async fn put_bytes(e: &Engine, bucket: &str, key: &str, bytes: Vec<u8>, ct: Option<String>) -> ObjectInfo {
        let size = bytes.len() as u64;
        let mut src = VecByteStream::new(bytes);
        e.put(bucket, key, size, &mut src, ct).await.unwrap()
    }

    /// Test helper: drain a GET into a Vec.
    async fn get_bytes(e: &Engine, bucket: &str, key: &str) -> (ObjectInfo, Vec<u8>) {
        let (info, mut stream) = e.get(bucket, key).await.unwrap();
        let mut buf = vec![0u8; info.size as usize];
        let n = read_full(stream.as_mut(), &mut buf[..]).await.unwrap();
        buf.truncate(n);
        (info, buf)
    }

    #[compio::test]
    async fn put_replicates_to_every_disk_in_set() {
        let (_dirs, e) = eng(3, 3).await;
        put_bytes(&e, "buk", "k", b"hello".to_vec(), None).await;
        let (_, data) = get_bytes(&e, "buk", "k").await;
        assert_eq!(&data[..], b"hello");
    }

    #[compio::test]
    async fn delete_removes_from_every_disk_in_set() {
        let (_dirs, e) = eng(3, 3).await;
        put_bytes(&e, "buk", "k", b"hello".to_vec(), None).await;
        e.delete("buk", "k").await.unwrap();
        assert!(matches!(e.get("buk", "k").await,
            Err(StorageError::ObjectNotFound { .. })));
    }

    /// 1 MiB payload — straight onto the EC streaming path with the
    /// default inline cutoff (128 KiB). EC(2+1) on a 3-disk set, no
    /// faults, exact-bytes round trip via streaming.
    #[compio::test]
    async fn ec_round_trip_one_mib() {
        let (_dirs, e) = eng(3, 3).await;
        let payload: Vec<u8> = (0..1024 * 1024u32).map(|i| (i % 251) as u8).collect();
        put_bytes(&e, "buk", "big", payload.clone(), None).await;
        let (_, data) = get_bytes(&e, "buk", "big").await;
        assert_eq!(data.len(), payload.len());
        assert_eq!(data, payload);
    }

    #[compio::test]
    async fn ec_boundary_just_above_inline_threshold() {
        let (_dirs, e) = eng(3, 3).await;
        let size = DEFAULT_INLINE_THRESHOLD + 1;
        let payload: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        put_bytes(&e, "buk", "boundary", payload.clone(), None).await;
        let info = e.stat("buk", "boundary").await.unwrap();
        assert_eq!(info.size, size as u64);
        assert!(matches!(info.storage_class, StorageClass::Single));
        let (_, data) = get_bytes(&e, "buk", "boundary").await;
        assert_eq!(data.len(), size);
        assert_eq!(data, payload);
    }

    #[compio::test]
    async fn ec_get_survives_parity_budget_offline() {
        let (dirs, e) = eng(8, 8).await;
        // EC[6+2] from the test cluster builder.
        let parity_shards = 2;

        let payload: Vec<u8> = (0..512 * 1024u32).map(|i| (i % 251) as u8).collect();
        put_bytes(&e, "buk", "survivor", payload.clone(), None).await;

        for d in dirs.iter().take(parity_shards) {
            std::fs::remove_dir_all(d.path().join("buk")).unwrap();
        }

        let (_, data) = get_bytes(&e, "buk", "survivor").await;
        assert_eq!(data.len(), payload.len());
        assert_eq!(data, payload);
    }

    #[compio::test]
    async fn ec_get_fails_past_parity_budget() {
        let (dirs, e) = eng(8, 8).await;
        let parity_shards = 2;

        let payload: Vec<u8> = vec![0x77u8; 256 * 1024];
        put_bytes(&e, "buk", "doomed", payload, None).await;

        for d in dirs.iter().take(parity_shards + 1) {
            std::fs::remove_dir_all(d.path().join("buk")).unwrap();
        }

        let res = e.get("buk", "doomed").await;
        let kind = match &res {
            Ok(_)  => "Ok".to_string(),
            Err(e) => format!("{e}"),
        };
        // Either error variant signals "GET cannot succeed because too
        // few disks are reachable / agree". Pre-consensus this surfaced
        // as `ObjectNotFound`; the new consensus distinguishes
        // `InsufficientOnlineDrives` (parity vote couldn't reach
        // quorum) from `ObjectNotFound` (disks agree the object is
        // gone). For this test — disks are wiped so xl.meta is missing
        // on the deleted ones — the parity-vote path fires first.
        assert!(matches!(res,
            Err(StorageError::ObjectNotFound { .. })
            | Err(StorageError::InsufficientOnlineDrives { .. })),
            "GET must fail when more than parity_shards disks are offline, got {kind}");
    }

    #[compio::test]
    async fn inline_and_ec_objects_coexist() {
        let (_dirs, e) = eng(4, 4).await;
        let small = b"tiny inline payload".to_vec();
        let large: Vec<u8> = vec![0x42u8; 200 * 1024];
        put_bytes(&e, "buk", "small", small.clone(), None).await;
        put_bytes(&e, "buk", "large", large.clone(), None).await;

        let (info_s, data_s) = get_bytes(&e, "buk", "small").await;
        let (info_l, data_l) = get_bytes(&e, "buk", "large").await;
        assert_eq!(data_s, small);
        assert_eq!(data_l, large);
        assert!(matches!(info_s.storage_class, StorageClass::Inline));
        assert!(matches!(info_l.storage_class, StorageClass::Single));
    }

    #[compio::test]
    async fn ec_overwrite_returns_latest() {
        let (_dirs, e) = eng(3, 3).await;
        let v1: Vec<u8> = vec![0x11u8; 200 * 1024];
        let v2: Vec<u8> = vec![0x22u8; 300 * 1024];
        put_bytes(&e, "buk", "ovw", v1, None).await;
        std::thread::sleep(std::time::Duration::from_millis(2));
        put_bytes(&e, "buk", "ovw", v2.clone(), None).await;
        let (info, data) = get_bytes(&e, "buk", "ovw").await;
        assert_eq!(info.size, v2.len() as u64);
        assert_eq!(data, v2);
    }

    /// L2 invariant: distinct-`version_id` PUTs preserve prior
    /// versions on disk. Each disk holds one `{data_dir}/` per
    /// version (no cleanup of the prior). The single-`data_dir`
    /// cleanup behavior from L1 only applies when the SAME
    /// `version_id` is replaced (idempotent overwrite); the engine
    /// always generates a fresh `version_id` per PUT today, so
    /// every PUT to an existing key creates a new version slot.
    #[compio::test]
    async fn ec_overwrite_preserves_prior_version_data_dir() {
        let (dirs, e) = eng(3, 3).await;
        e.put_bucket_versioning("buk", VersioningStatus::Enabled).await.unwrap();
        let v1: Vec<u8> = vec![0x11u8; 200 * 1024];
        let v2: Vec<u8> = vec![0x22u8; 300 * 1024];
        put_bytes(&e, "buk", "ovw", v1, None).await;
        std::thread::sleep(std::time::Duration::from_millis(2));
        put_bytes(&e, "buk", "ovw", v2, None).await;
        for d in &dirs {
            let obj_dir = d.path().join("buk").join("ovw");
            let entries: Vec<_> = std::fs::read_dir(&obj_dir).unwrap()
                .map(|e| e.unwrap().file_name().into_string().unwrap())
                .collect();
            let data_dirs: Vec<&String> = entries.iter()
                .filter(|n| *n != "xl.meta" && !n.starts_with('.'))
                .collect();
            assert_eq!(
                data_dirs.len(), 2,
                "disk {:?} should have BOTH versions' data_dirs (got {}: {:?})",
                d.path(), data_dirs.len(), data_dirs,
            );
        }
    }

    /// L2 invariant: xl.meta versions array is sorted newest-first
    /// after a multi-version PUT. Verifies the `decode_all` ordering
    /// and `rename_data`'s merge step.
    #[compio::test]
    async fn ec_multi_version_xl_meta_sorted_newest_first() {
        let (dirs, e) = eng(3, 3).await;
        e.put_bucket_versioning("buk", VersioningStatus::Enabled).await.unwrap();
        put_bytes(&e, "buk", "mv2", vec![0x11u8; 200 * 1024], None).await;
        std::thread::sleep(std::time::Duration::from_millis(5));
        put_bytes(&e, "buk", "mv2", vec![0x22u8; 250 * 1024], None).await;
        std::thread::sleep(std::time::Duration::from_millis(5));
        put_bytes(&e, "buk", "mv2", vec![0x33u8; 300 * 1024], None).await;

        for d in &dirs {
            let bytes = std::fs::read(d.path().join("buk").join("mv2").join("xl.meta")).unwrap();
            let recs = phenomenal_io::xl_meta::decode_all(bytes::Bytes::from(bytes)).unwrap();
            assert_eq!(recs.len(), 3, "expected 3 versions, got {}", recs.len());
            // mod_time strictly decreasing
            assert!(recs[0].mod_time_ms > recs[1].mod_time_ms);
            assert!(recs[1].mod_time_ms > recs[2].mod_time_ms);
            // sizes match: latest is 300K, older 250K, oldest 200K
            assert_eq!(recs[0].size, 300 * 1024);
            assert_eq!(recs[1].size, 250 * 1024);
            assert_eq!(recs[2].size, 200 * 1024);
            // each version has its own data_dir
            let dirs_set: std::collections::HashSet<_> =
                recs.iter().map(|r| r.data_dir.clone()).collect();
            assert_eq!(dirs_set.len(), 3, "version data_dirs must be distinct");
        }
    }

    /// L2 invariant: after PUT v1 then PUT v2, both versions are
    /// readable. GET (without version_id) returns v2 (latest). GET
    /// with each version_id returns the right body. Mirrors MinIO's
    /// versioning semantics: a fresh `version_id` per PUT, all
    /// versions preserved in the xl.meta versions array.
    #[compio::test]
    async fn ec_multi_version_get_by_version_id() {
        let (_dirs, e) = eng(3, 3).await;
        e.put_bucket_versioning("buk", VersioningStatus::Enabled).await.unwrap();
        let v1: Vec<u8> = vec![0xAAu8; 200 * 1024];
        let v2: Vec<u8> = vec![0xBBu8; 250 * 1024];
        let info1 = e.put("buk", "mv", v1.len() as u64,
            &mut VecByteStream::new(v1.clone()), None).await.unwrap();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let info2 = e.put("buk", "mv", v2.len() as u64,
            &mut VecByteStream::new(v2.clone()), None).await.unwrap();

        // Fetch each version's id from the live xl.meta on disk.
        // (Engine doesn't return version_id today; we read it back
        // via stat once we hook it up — for now we use the etags
        // returned and identify by content.)
        let _ = (info1, info2);

        // GET (latest) returns v2.
        let (info_latest, data_latest) = get_bytes(&e, "buk", "mv").await;
        assert_eq!(info_latest.size, v2.len() as u64);
        assert_eq!(data_latest, v2);

        // Inspect xl.meta directly to find both version_ids.
        // (Engine consensus doesn't expose this yet; pull from disk.)
        use bytes::Bytes;
        use phenomenal_io::xl_meta;
        let any_disk = std::fs::read(_dirs[0].path().join("buk").join("mv").join("xl.meta")).unwrap();
        let recs = xl_meta::decode_all(Bytes::from(any_disk)).unwrap();
        assert_eq!(recs.len(), 2, "xl.meta should hold two versions");
        let v_latest = &recs[0];   // newest (v2)
        let v_prior  = &recs[1];   // older (v1)

        // GET by version_id v2 → v2 body.
        let (_, mut s) = e.get_version("buk", "mv", &v_latest.version_id).await.unwrap();
        let mut got = Vec::new();
        loop {
            let chunk = phenomenal_io::ByteStream::read(&mut *s).await.unwrap();
            if chunk.is_empty() { break; }
            got.extend_from_slice(&chunk);
        }
        assert_eq!(got, v2, "GET by latest version_id should return v2");

        // GET by version_id v1 → v1 body.
        let (_, mut s) = e.get_version("buk", "mv", &v_prior.version_id).await.unwrap();
        let mut got = Vec::new();
        loop {
            let chunk = phenomenal_io::ByteStream::read(&mut *s).await.unwrap();
            if chunk.is_empty() { break; }
            got.extend_from_slice(&chunk);
        }
        assert_eq!(got, v1, "GET by prior version_id should return v1");
    }

    /// L1 invariant: PUT-then-DELETE cleans up the staging volume so
    /// stale staging dirs don't accumulate. After a successful PUT
    /// the `STAGING_VOL` directory should hold no `{staging_id}/`
    /// children — `rename_data` moved the data out and removed the
    /// shell, and `promote_versions`'s defensive sweep catches any
    /// straggler.
    #[compio::test]
    async fn staging_dir_is_empty_after_successful_put() {
        let (dirs, e) = eng(3, 3).await;
        let v: Vec<u8> = vec![0x55u8; 200 * 1024];
        put_bytes(&e, "buk", "obj", v, None).await;
        for d in &dirs {
            let staging = d.path().join(phenomenal_io::STAGING_VOL);
            if staging.exists() {
                let entries: Vec<_> = std::fs::read_dir(&staging).unwrap()
                    .map(|e| e.unwrap().file_name().into_string().unwrap())
                    .collect();
                assert!(
                    entries.is_empty(),
                    "disk {:?} staging dir not empty after PUT: {entries:?}",
                    d.path(),
                );
            }
        }
    }

    #[compio::test]
    async fn empty_payload_round_trip_inline() {
        let (_dirs, e) = eng(3, 3).await;
        put_bytes(&e, "buk", "empty", Vec::new(), None).await;
        let (info, data) = get_bytes(&e, "buk", "empty").await;
        assert_eq!(info.size, 0);
        assert!(data.is_empty());
    }

    #[test]
    fn rejects_bad_bucket_names() {
        for bad in ["", "ab", "AB", "a..b", ".ab", "ab.", "-ab", "ab-",
                    "with_underscore", &"x".repeat(64),
                    "192.168.0.1", "10.0.0.1", "1.2.3.4",
                    "foo.-bar", "foo-.bar",
                    "phenomenal",
                    "  ab  "] {
            assert!(validate_bucket_name(bad).is_err(), "should reject {bad:?}");
        }
        for ok in ["abc", "a-b-c", "a.b.c", "1234", &"x".repeat(63),
                   "foo--bar", "1234.5678"] {
            validate_bucket_name(ok).unwrap();
        }
    }

    #[compio::test]
    async fn delete_bucket_blocks_when_non_empty() {
        let (_dirs, e) = eng(3, 3).await;
        put_bytes(&e, "buk", "k", b"x".to_vec(), None).await;
        assert!(matches!(e.delete_bucket("buk", false).await,
            Err(StorageError::BucketNotEmpty(_))));
        e.delete("buk", "k").await.unwrap();
        e.delete_bucket("buk", false).await.unwrap();
    }

    #[compio::test]
    async fn delete_bucket_force_purges_content() {
        let (_dirs, e) = eng(3, 3).await;
        put_bytes(&e, "buk", "k", b"x".to_vec(), None).await;
        e.delete_bucket("buk", true).await.unwrap();
    }

    /// CMU + UploadPart end-to-end round-trip: initiate a session,
    /// upload three parts, verify each part lands at
    /// `MULTIPART_VOL/buk/k/<uploadId>/<dataDir>/part.{N}` with a
    /// sibling `.meta` sidecar, and confirm the session `xl.meta`
    /// itself was not touched (its mtime stays at the CMU value).
    #[compio::test]
    async fn upload_part_round_trip() {
        let (dirs, e) = eng(3, 3).await;

        let init = e.create_multipart_upload("buk", "k", Some("text/plain".into()))
            .await.expect("CMU");

        // Upload 3 parts with distinct payloads.
        let payloads: [Vec<u8>; 3] = [
            (0..1024usize).map(|i| (i % 251) as u8).collect(),
            (0..2048usize).map(|i| ((i + 17) % 251) as u8).collect(),
            (0..4096usize).map(|i| ((i + 91) % 251) as u8).collect(),
        ];
        for (i, payload) in payloads.iter().enumerate() {
            let part_no = (i + 1) as u32;
            let mut src = VecByteStream::new(payload.clone());
            let info = e.upload_part(
                "buk", "k", &init.upload_id, part_no,
                payload.len() as u64, &mut src,
            ).await.expect("upload_part");
            assert_eq!(info.number, part_no as i32);
            assert_eq!(info.actual_size, payload.len() as i64);
            assert!(!info.etag.is_empty(), "etag must be populated");
        }

        // The session xl.meta on every disk must carry parts=[] still
        // (UploadPart never touches the session record). The data_dir
        // and (per-disk) part.{N}/part.{N}.meta files exist.
        for d in &dirs {
            let session_dir = d.path()
                .join(".phenomenal.multipart")
                .join("buk").join("k")
                .join(&init.upload_id);
            assert!(session_dir.join("xl.meta").exists(), "session xl.meta missing");

            // Scan one level down to find the dataDir UUID dir, then
            // verify each part + .meta sidecar is present.
            let mut found_data_dir: Option<std::path::PathBuf> = None;
            for entry in std::fs::read_dir(&session_dir).unwrap() {
                let p = entry.unwrap().path();
                if p.is_dir() { found_data_dir = Some(p); break; }
            }
            let dd = found_data_dir.expect("dataDir not found under session");
            for part_no in 1..=3 {
                assert!(dd.join(format!("part.{part_no}")).exists(),
                        "part.{part_no} missing on disk {:?}", d.path());
                assert!(dd.join(format!("part.{part_no}.meta")).exists(),
                        "part.{part_no}.meta sidecar missing on disk {:?}", d.path());
            }
        }
    }

    /// Out-of-range partNumber is rejected before any disk work.
    #[compio::test]
    async fn upload_part_rejects_invalid_part_number() {
        let (_dirs, e) = eng(3, 3).await;
        let init = e.create_multipart_upload("buk", "k", None).await.unwrap();
        let mut src = VecByteStream::new(b"x".to_vec());
        assert!(e.upload_part("buk", "k", &init.upload_id, 0, 1, &mut src).await.is_err());
        let mut src = VecByteStream::new(b"x".to_vec());
        assert!(e.upload_part("buk", "k", &init.upload_id, 10_001, 1, &mut src).await.is_err());
    }

    /// Full multipart round-trip: CMU → 3 UploadParts (each ≥ 5 MiB
    /// except the last) → CompleteMultipartUpload. Verifies the
    /// assembled object is GET-able with the expected payload, the
    /// session dir under MULTIPART_VOL is gone, and the dataDir +
    /// xl.meta land at `{bucket}/{key}/`.
    #[compio::test]
    async fn complete_multipart_full_roundtrip() {
        let (dirs, e) = eng(3, 3).await;
        let init = e.create_multipart_upload("buk", "k", Some("application/octet-stream".into()))
            .await.unwrap();

        let part_size: usize = 5 * 1024 * 1024;
        let payloads: [Vec<u8>; 3] = [
            (0..part_size).map(|i| (i % 251) as u8).collect(),
            (0..part_size).map(|i| ((i + 17) % 251) as u8).collect(),
            (0..1024).map(|i| ((i + 91) % 251) as u8).collect(),  // tail < 5 MiB OK
        ];
        let mut part_etags: Vec<(u32, String)> = Vec::new();
        for (i, payload) in payloads.iter().enumerate() {
            let part_no = (i + 1) as u32;
            let mut src = VecByteStream::new(payload.clone());
            let info = e.upload_part("buk", "k", &init.upload_id, part_no,
                                     payload.len() as u64, &mut src).await.unwrap();
            part_etags.push((part_no, info.etag));
        }

        let parts: Vec<crate::object::CompletePart> = part_etags.into_iter()
            .map(|(n, etag)| crate::object::CompletePart { part_number: n, etag })
            .collect();
        let info = e.complete_multipart_upload("buk", "k", &init.upload_id, parts)
            .await.expect("Complete");

        // Assembled etag has the multipart suffix `-N`.
        assert!(info.etag.ends_with("-3"), "etag {:?} missing -N suffix", info.etag);
        // Total size sums all parts.
        let expected_size: usize = payloads.iter().map(|p| p.len()).sum();
        assert_eq!(info.size as usize, expected_size);

        // Session dir is gone on every disk.
        for d in &dirs {
            let session_dir = d.path()
                .join(".phenomenal.multipart")
                .join("buk").join("k").join(&init.upload_id);
            assert!(!session_dir.exists(), "session dir survived on {:?}", d.path());
        }

        // Object xl.meta lives at bucket/key on every disk.
        for d in &dirs {
            let meta_path = d.path().join("buk").join("k").join("xl.meta");
            assert!(meta_path.exists(), "xl.meta missing at {:?}", meta_path);
        }

        // Each part landed at bucket/key/{data_dir}/part.{N} on every disk.
        for d in &dirs {
            let object_dir = d.path().join("buk").join("k");
            let mut data_dir: Option<std::path::PathBuf> = None;
            for entry in std::fs::read_dir(&object_dir).unwrap() {
                let p = entry.unwrap().path();
                if p.is_dir() { data_dir = Some(p); break; }
            }
            let dd = data_dir.expect("dataDir not found under bucket/key");
            for part_no in 1..=3 {
                assert!(dd.join(format!("part.{part_no}")).exists(),
                        "part.{part_no} missing under {:?}", dd);
            }
            assert!(!dd.join("part.1.meta").exists(), "stale sidecar at {:?}", dd);
        }

        // GET assembles a stream that yields exactly the concatenation
        // of all parts in order — `MultiPartEcStream` walks `fi.parts`
        // and drains each part's EC stream sequentially.
        let (get_info, mut stream) = e.get("buk", "k").await.expect("GET");
        assert_eq!(get_info.size, info.size);
        assert_eq!(get_info.etag, info.etag);
        let mut got = vec![0u8; info.size as usize];
        let n = read_full(stream.as_mut(), &mut got[..]).await.unwrap();
        got.truncate(n);
        let mut expected: Vec<u8> = Vec::with_capacity(info.size as usize);
        for p in &payloads { expected.extend_from_slice(p); }
        assert_eq!(got.len(), expected.len(), "GET length mismatch");
        assert_eq!(got, expected, "GET payload mismatch — multi-part stream walk");
    }

    /// On a Versioning=Enabled bucket, CreateMultipartUpload must
    /// stamp a real UUID into the session FI (not the "null" sentinel),
    /// and Complete must inherit it onto the assembled object.
    /// Mirrors MinIO's `fi.VersionID = mustGetUUID()` at CMU time.
    #[compio::test]
    async fn complete_multipart_versioned_bucket_uses_uuid_version() {
        let (_dirs, e) = eng(3, 3).await;
        e.put_bucket_versioning("buk", VersioningStatus::Enabled).await.unwrap();

        let init = e.create_multipart_upload("buk", "k", None).await.unwrap();

        let payload = vec![0xAAu8; 5 * 1024 * 1024];
        let mut src = VecByteStream::new(payload.clone());
        let part = e.upload_part("buk", "k", &init.upload_id, 1, payload.len() as u64, &mut src)
            .await.unwrap();

        let info = e.complete_multipart_upload("buk", "k", &init.upload_id,
            vec![crate::object::CompletePart { part_number: 1, etag: part.etag }],
        ).await.unwrap();

        assert_ne!(info.version_id, "null",
            "Versioning=Enabled bucket must mint a UUID version_id, got {:?}",
            info.version_id);
        // UUID v4 simple form is 32 hex chars, dashed form is 36.
        assert!(info.version_id.len() >= 32,
            "version_id {:?} doesn't look like a UUID", info.version_id);

        // On Suspended/Unversioned the original "null" behavior holds.
        e.put_bucket_versioning("buk", VersioningStatus::Suspended).await.unwrap();
        let init2 = e.create_multipart_upload("buk", "k2", None).await.unwrap();
        let mut src = VecByteStream::new(payload.clone());
        let part2 = e.upload_part("buk", "k2", &init2.upload_id, 1, payload.len() as u64, &mut src)
            .await.unwrap();
        let info2 = e.complete_multipart_upload("buk", "k2", &init2.upload_id,
            vec![crate::object::CompletePart { part_number: 1, etag: part2.etag }],
        ).await.unwrap();
        assert_eq!(info2.version_id, "null",
            "Suspended bucket should keep null version_id");
    }

    /// Complete with an etag that doesn't match the sidecar must fail
    /// before the rename step, leaving the session intact for retry.
    #[compio::test]
    async fn complete_multipart_rejects_etag_mismatch() {
        let (_dirs, e) = eng(3, 3).await;
        let init = e.create_multipart_upload("buk", "k", None).await.unwrap();

        let payload = vec![0xCDu8; 5 * 1024 * 1024];
        let mut src = VecByteStream::new(payload.clone());
        let _ = e.upload_part("buk", "k", &init.upload_id, 1, payload.len() as u64, &mut src)
            .await.unwrap();

        let bad_parts = vec![crate::object::CompletePart {
            part_number: 1,
            etag: "0000000000000000000000000000000000000000000000000000000000000000".into(),
        }];
        let r = e.complete_multipart_upload("buk", "k", &init.upload_id, bad_parts).await;
        assert!(r.is_err(), "expected etag-mismatch error, got {r:?}");
    }

    /// Non-tail part below 5 MiB must fail.
    #[compio::test]
    async fn complete_multipart_rejects_small_part() {
        let (_dirs, e) = eng(3, 3).await;
        let init = e.create_multipart_upload("buk", "k", None).await.unwrap();

        let small = vec![0xEEu8; 1024];
        let mut src = VecByteStream::new(small.clone());
        let info = e.upload_part("buk", "k", &init.upload_id, 1, small.len() as u64, &mut src)
            .await.unwrap();

        let tail = vec![0xFFu8; 1024];
        let mut src = VecByteStream::new(tail.clone());
        let info2 = e.upload_part("buk", "k", &init.upload_id, 2, tail.len() as u64, &mut src)
            .await.unwrap();

        let parts = vec![
            crate::object::CompletePart { part_number: 1, etag: info.etag },
            crate::object::CompletePart { part_number: 2, etag: info2.etag },
        ];
        let r = e.complete_multipart_upload("buk", "k", &init.upload_id, parts).await;
        assert!(r.is_err(), "non-tail < 5 MiB should be rejected");
    }

    /// Re-uploading the same part number replaces both the data file
    /// and the sidecar atomically per-disk. Verifies A4 (pre-cleanup)
    /// and A3 (per-disk grouping): after the second upload, every
    /// disk must hold the new etag's data + new sidecar — no torn
    /// (stale data, fresh meta) or (fresh data, stale meta) state.
    #[compio::test]
    async fn upload_part_reupload_replaces_atomically() {
        let (dirs, e) = eng(3, 3).await;
        let init = e.create_multipart_upload("buk", "k", None).await.unwrap();

        let payload_a: Vec<u8> = vec![0xAAu8; 4096];
        let payload_b: Vec<u8> = vec![0xBBu8; 8192];

        let mut src = VecByteStream::new(payload_a.clone());
        let info_a = e.upload_part("buk", "k", &init.upload_id, 1, payload_a.len() as u64, &mut src)
            .await.unwrap();

        let mut src = VecByteStream::new(payload_b.clone());
        let info_b = e.upload_part("buk", "k", &init.upload_id, 1, payload_b.len() as u64, &mut src)
            .await.unwrap();

        // Etags must differ — different payloads.
        assert_ne!(info_a.etag, info_b.etag);

        // On every disk, the sidecar's etag matches the SECOND upload.
        // (If A4's pre-cleanup or A3's per-disk grouping were missing,
        // we could observe info_a's sidecar racing with info_b's data.)
        for d in &dirs {
            let session_dir = d.path()
                .join(".phenomenal.multipart")
                .join("buk").join("k")
                .join(&init.upload_id);
            let mut data_dir: Option<std::path::PathBuf> = None;
            for entry in std::fs::read_dir(&session_dir).unwrap() {
                let p = entry.unwrap().path();
                if p.is_dir() { data_dir = Some(p); break; }
            }
            let dd = data_dir.expect("dataDir not found");
            let meta_bytes = std::fs::read(dd.join("part.1.meta"))
                .expect("sidecar present");
            let parsed: phenomenal_io::ObjectPartInfo = rmp_serde::from_slice(&meta_bytes)
                .expect("sidecar decodes");
            assert_eq!(parsed.etag, info_b.etag,
                "disk {:?} sidecar must reflect the second upload", d.path());
            assert_eq!(parsed.actual_size, payload_b.len() as i64);
            assert!(dd.join("part.1").exists(), "part data missing on {:?}", d.path());
        }
    }

    /// Unknown upload_id (no session xl.meta on any disk) must fail
    /// before allocating staging — the session-FI consensus read
    /// returns no quorum on a missing path.
    #[compio::test]
    async fn upload_part_unknown_upload_id() {
        let (_dirs, e) = eng(3, 3).await;
        let mut src = VecByteStream::new(b"x".to_vec());
        let r = e.upload_part("buk", "k", "no-such-upload", 1, 1, &mut src).await;
        assert!(r.is_err());
    }
}
