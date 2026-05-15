//! Cluster-identity bootstrap. One-time at first init, polling check
//! on every subsequent boot.

use std::rc::Rc;
use std::time::{Duration, Instant};

use phenomenal_io::{FormatJson, IoError, StorageBackend};
use uuid::Uuid;

use crate::cluster::NodeId;

#[derive(Debug, thiserror::Error)]
pub enum FormatError {
    #[error("bootstrap timed out after {0:?} waiting for seed node to publish format.json")]
    Timeout(Duration),

    #[error("cluster disks disagree on deployment_id (cannot reach quorum)")]
    QuorumDisagreement,

    #[error("local disk(s) missing format.json on non-fresh cluster — refusing to mount")]
    LocalDiskMissingFormat,

    #[error("local disk has deployment_id {local} but cluster majority is {cluster} — refusing to mount")]
    LocalDiskWrongDeploymentId { local: Uuid, cluster: Uuid },

    #[error("non-seed node could not contact seed: {0}")]
    SeedUnreachable(String),

    #[error(transparent)]
    Io(#[from] IoError),
}

pub async fn bootstrap_format(
    local:              &[Rc<dyn StorageBackend>],
    peers:              &[Rc<dyn StorageBackend>],
    local_disk_offsets: &[u32],
    peer_disk_offsets:  &[u32],
    my_id:              NodeId,
    node_ids:           &[NodeId],
    set_drive_count:    usize,
    poll_interval:      Duration,
    timeout:            Duration,
) -> Result<Uuid, FormatError> {
    debug_assert_eq!(local.len(),  local_disk_offsets.len());
    debug_assert_eq!(peers.len(),  peer_disk_offsets.len());

    let seed_id = *node_ids.first().expect("at least one node configured");
    let am_seed = my_id == seed_id;
    let total   = local.len() + peers.len();
    let quorum  = (total / 2) + 1;
    let deadline = Instant::now() + timeout;

    loop {
        let local_fmts = read_all(local).await;
        let peer_fmts  = read_all(peers).await;
        let formatted  = local_fmts.iter().chain(peer_fmts.iter())
            .filter(|r| matches!(r, Ok(Some(_))))
            .count();

        if formatted == 0 && all_ok_none(&local_fmts) && all_ok_none(&peer_fmts) {
            if am_seed {
                let id = Uuid::new_v4();
                tracing::info!(deployment_id = %id, "seed: generating cluster deployment UUID");
                write_all_disks(
                    local, peers,
                    local_disk_offsets, peer_disk_offsets,
                    id, set_drive_count,
                ).await?;
                return Ok(id);
            }
            tracing::debug!(seed = %seed_id, "non-seed: waiting for seed to publish format.json");
        }

        if formatted >= quorum {
            if local_fmts.iter().any(|r| matches!(r, Ok(None))) {
                return Err(FormatError::LocalDiskMissingFormat);
            }
            let id = vote_majority(&local_fmts, &peer_fmts)?;
            for r in &local_fmts {
                if let Ok(Some(f)) = r {
                    if f.id != id {
                        return Err(FormatError::LocalDiskWrongDeploymentId {
                            local:   f.id,
                            cluster: id,
                        });
                    }
                }
            }
            return Ok(id);
        }

        if Instant::now() >= deadline {
            return Err(FormatError::Timeout(timeout));
        }
        compio::time::sleep(poll_interval).await;
    }
}

async fn read_all(backends: &[Rc<dyn StorageBackend>]) -> Vec<Result<Option<FormatJson>, IoError>> {
    let mut out = Vec::with_capacity(backends.len());
    for b in backends {
        out.push(b.read_format().await);
    }
    out
}

fn all_ok_none(results: &[Result<Option<FormatJson>, IoError>]) -> bool {
    results.iter().all(|r| matches!(r, Ok(None)))
}

async fn write_all_disks(
    local:              &[Rc<dyn StorageBackend>],
    peers:              &[Rc<dyn StorageBackend>],
    local_disk_offsets: &[u32],
    peer_disk_offsets:  &[u32],
    id:                 Uuid,
    set_drive_count:    usize,
) -> Result<(), FormatError> {
    for (be, &this) in local.iter().zip(local_disk_offsets.iter()) {
        let fmt = FormatJson {
            version:         1,
            format:          "phenomenal".into(),
            id,
            set_drive_count,
            this_disk:       this,
        };
        be.write_format(&fmt).await.map_err(FormatError::Io)?;
    }
    for (be, &this) in peers.iter().zip(peer_disk_offsets.iter()) {
        let fmt = FormatJson {
            version:         1,
            format:          "phenomenal".into(),
            id,
            set_drive_count,
            this_disk:       this,
        };
        be.write_format(&fmt).await.map_err(|e| {
            FormatError::Io(e)
        })?;
    }
    Ok(())
}

fn vote_majority(
    local_fmts: &[Result<Option<FormatJson>, IoError>],
    peer_fmts:  &[Result<Option<FormatJson>, IoError>],
) -> Result<Uuid, FormatError> {
    let mut counts: std::collections::HashMap<Uuid, usize> = std::collections::HashMap::new();
    for r in local_fmts.iter().chain(peer_fmts.iter()) {
        if let Ok(Some(f)) = r {
            *counts.entry(f.id).or_insert(0) += 1;
        }
    }
    let total_formatted: usize = counts.values().sum();
    let majority = total_formatted / 2 + 1;
    for (&id, &n) in &counts {
        if n >= majority { return Ok(id); }
    }
    Err(FormatError::QuorumDisagreement)
}

#[cfg(test)]
mod tests {
    use super::*;
    use phenomenal_io::LocalFsBackend;
    use tempfile::TempDir;

    #[compio::test]
    async fn seed_first_init_then_idempotent_reboot() {
        let dirs: Vec<TempDir> = (0..3).map(|_| TempDir::new().unwrap()).collect();
        let local: Vec<Rc<dyn StorageBackend>> = dirs.iter()
            .map(|d| Rc::new(LocalFsBackend::new(d.path()).unwrap()) as Rc<dyn StorageBackend>)
            .collect();
        let local_off = vec![1, 2, 3];
        let peers: Vec<Rc<dyn StorageBackend>> = Vec::new();
        let peer_off:  Vec<u32> = Vec::new();

        let id = bootstrap_format(
            &local, &peers, &local_off, &peer_off,
            0, &[0], 3,
            std::time::Duration::from_millis(50),
            std::time::Duration::from_secs(2),
        ).await.expect("seed first-init");

        assert_ne!(id, Uuid::nil());

        for be in &local {
            let fmt = be.read_format().await.unwrap().expect("format written");
            assert_eq!(fmt.id, id);
            assert_eq!(fmt.version, 1);
            assert_eq!(fmt.format, "phenomenal");
            assert_eq!(fmt.set_drive_count, 3);
        }

        let id2 = bootstrap_format(
            &local, &peers, &local_off, &peer_off,
            0, &[0], 3,
            std::time::Duration::from_millis(50),
            std::time::Duration::from_secs(2),
        ).await.expect("reboot");
        assert_eq!(id, id2);
    }

    #[compio::test]
    async fn local_disk_with_foreign_id_is_rejected() {
        let dirs: Vec<TempDir> = (0..5).map(|_| TempDir::new().unwrap()).collect();
        let cluster_id = Uuid::new_v4();
        let foreign_id = Uuid::new_v4();

        // Pre-seed disks: dirs[0..4] = cluster_id, dirs[4] = foreign_id.
        for (i, d) in dirs.iter().enumerate() {
            let be = LocalFsBackend::new(d.path()).unwrap();
            let id = if i == 4 { foreign_id } else { cluster_id };
            be.write_format(&FormatJson {
                version:         1,
                format:          "phenomenal".into(),
                id,
                set_drive_count: 5,
                this_disk:       (i as u32) + 1,
            }).await.unwrap();
        }

        let local: Vec<Rc<dyn StorageBackend>> = dirs.iter()
            .map(|d| Rc::new(LocalFsBackend::new(d.path()).unwrap()) as Rc<dyn StorageBackend>)
            .collect();
        let local_off = vec![1, 2, 3, 4, 5];

        let result = bootstrap_format(
            &local, &[], &local_off, &[],
            0, &[0], 5,
            std::time::Duration::from_millis(50),
            std::time::Duration::from_secs(2),
        ).await;

        match result {
            Err(FormatError::LocalDiskWrongDeploymentId { local: l, cluster: c }) => {
                assert_eq!(l, foreign_id);
                assert_eq!(c, cluster_id);
            }
            other => panic!("expected LocalDiskWrongDeploymentId, got {other:?}"),
        }
    }

    #[compio::test]
    async fn non_seed_times_out_without_seed() {
        let dirs: Vec<TempDir> = (0..2).map(|_| TempDir::new().unwrap()).collect();
        let local: Vec<Rc<dyn StorageBackend>> = dirs.iter()
            .map(|d| Rc::new(LocalFsBackend::new(d.path()).unwrap()) as Rc<dyn StorageBackend>)
            .collect();
        let local_off = vec![3, 4];
        let peers: Vec<Rc<dyn StorageBackend>> = Vec::new();
        let peer_off:  Vec<u32> = Vec::new();

        let result = bootstrap_format(
            &local, &peers, &local_off, &peer_off,
            1, &[0, 1], 2,
            std::time::Duration::from_millis(50),
            std::time::Duration::from_millis(200),
        ).await;
        assert!(matches!(result, Err(FormatError::Timeout(_))),
                "expected Timeout, got {result:?}");
    }
}
