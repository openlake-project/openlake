//! Global background purge worker: one OS thread, drains a bounded
//! queue of paths and removes each via blocking `remove_dir_all`.
//! `getdents64` has no io_uring opcode, so directory removal must
//! happen off the compio runtime threads.

use std::path::{Path, PathBuf};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::OnceLock;

static PURGE_TX: OnceLock<SyncSender<PathBuf>> = OnceLock::new();

pub fn init_purge_worker() {
    PURGE_TX.get_or_init(|| {
        let (tx, rx) = sync_channel::<PathBuf>(65_536);
        std::thread::Builder::new()
            .name("phen-purge".into())
            .stack_size(256 * 1024)
            .spawn(move || worker_loop(rx))
            .expect("spawn phen-purge thread");
        tx
    });
}

pub fn register_drive(trash_dir: &Path) {
    let Ok(rd) = std::fs::read_dir(trash_dir) else { return };
    for ent in rd.flatten() {
        try_enqueue(ent.path());
    }
}

pub fn try_enqueue(path: PathBuf) {
    let Some(tx) = PURGE_TX.get() else {
        tracing::warn!(?path, "purge worker not initialised");
        return;
    };
    if let Err(TrySendError::Full(p)) = tx.try_send(path) {
        tracing::warn!(?p, "purge queue full");
    }
}

fn worker_loop(rx: Receiver<PathBuf>) {
    while let Ok(path) = rx.recv() {
        if let Err(e) = std::fs::remove_dir_all(&path) {
            if e.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!(?path, error = %e, "purge failed");
            }
        }
    }
}
