//! Read-only, bounded recovery of already-persisted application receipts.
//!
//! No record is appended and no file is created, repaired or synchronized here.
//! The destination is selected from protected local history, never from the
//! peer. A claim alone is always refused. The caller retains the original inbox
//! mapping and protects it against replacement/mutation throughout serving.

use super::super::settings;
use super::{
    AlreadyClaimed, Entry, HEADER_BYTES, Ledger, RECORD_BYTES, corrupt, unavailable,
    verify_identity,
};
use asupersync::net::atp::sdk::native_auth::live::LiveStreamReceipt;
use asupersync::net::atp::sdk::native_auth::live::commit::resume::service::ResumeSessionKey;
use asupersync::runtime::spawn_blocking_io;
use sha2::{Digest, Sha256};
use std::fs::{File, Metadata};
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use zeroize::Zeroizing;

// Includes queued reads and reads whose awaiting factory timed out. The actual
// blocking closure retains its slot until it exits; no unbounded rehash queue.
const MAX_RECOVERY_READS: usize = 64;
struct ReadPermit(Arc<Ledger>);
impl ReadPermit {
    // `fetch_update` is deprecated on the pinned nightly (renamed to
    // `try_update`), which is a `-D warnings` error in the all-features lint
    // gate. `try_update` does not exist on the stable subset, so keep the call
    // and allow the deprecation, matching `database::sqlite` and `runtime::state`.
    #[allow(deprecated)]
    fn reserve(ledger: &Arc<Ledger>) -> io::Result<Self> {
        ledger
            .recovery_reads
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                (used < MAX_RECOVERY_READS).then(|| used + 1)
            })
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "receipt recovery read capacity exhausted",
                )
            })?;
        Ok(Self(Arc::clone(ledger)))
    }
}
impl Drop for ReadPermit {
    fn drop(&mut self) {
        self.0.recovery_reads.fetch_sub(1, Ordering::Release);
    }
}
struct StopRead(Arc<AtomicBool>);
impl Drop for StopRead {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}
fn check_stop(stopped: &AtomicBool) -> io::Result<()> {
    if stopped.load(Ordering::Acquire) {
        Err(io::Error::from(io::ErrorKind::Interrupted))
    } else {
        Ok(())
    }
}

impl Ledger {
    /// A missing key may enter normal claim admission; an unresolved key cannot.
    /// A successful Some contains only a saved commit whose current file was
    /// rehashed. This neither restores the sink nor reclaims storage/key capacity.
    pub async fn recover_committed(
        self: &Arc<Self>,
        key: ResumeSessionKey,
        directory: PathBuf,
        maximum_bytes: u64,
    ) -> io::Result<Option<LiveStreamReceipt>> {
        let permit = ReadPermit::reserve(self)?;
        let stopped = Arc::new(AtomicBool::new(false));
        let stop = StopRead(Arc::clone(&stopped));
        let result = spawn_blocking_io(move || {
            // Even cancellation before/after an OS read cannot release ownership
            // while that syscall is running. Check cancellation between reads.
            let _permit = permit;
            _permit
                .0
                .recover_sync(key, &directory, maximum_bytes, &stopped)
        })
        .await;
        drop(stop);
        result
    }

    fn checked_entry(&self, key: ResumeSessionKey) -> io::Result<Option<Entry>> {
        let state = self.state.lock();
        if state.poisoned {
            return Err(unavailable());
        }
        verify_identity(&self.path, &state.file, &self.directory)?;
        if state.file.metadata()?.len() != HEADER_BYTES as u64 + state.records * RECORD_BYTES as u64
        {
            return Err(corrupt());
        }
        Ok(state.entries.get(&key).cloned())
    }

    fn recover_sync(
        &self,
        key: ResumeSessionKey,
        directory: &Path,
        maximum_bytes: u64,
        stopped: &AtomicBool,
    ) -> io::Result<Option<LiveStreamReceipt>> {
        check_stop(stopped)?;
        let Some(entry) = self.checked_entry(key)? else {
            return Ok(None);
        };
        let Some(receipt) = &entry.receipt else {
            return Err(io::Error::new(io::ErrorKind::AlreadyExists, AlreadyClaimed));
        };
        if receipt.prefix.bytes > maximum_bytes {
            return Err(corrupt());
        }
        verify_file(directory, &entry, stopped)?;
        check_stop(stopped)?;
        // Do not publish cached evidence after concurrent persistence trouble.
        let current = self.checked_entry(key)?.ok_or_else(corrupt)?;
        if current.receipt != entry.receipt || current.filename != entry.filename {
            return Err(corrupt());
        }
        Ok(entry.receipt)
    }
}

fn file_identity(metadata: &Metadata) -> (u64, u64, u64, i64, i64, i64, i64) {
    (
        metadata.dev(),
        metadata.ino(),
        metadata.len(),
        metadata.mtime(),
        metadata.mtime_nsec(),
        metadata.ctime(),
        metadata.ctime_nsec(),
    )
}
fn private_directory(metadata: &Metadata) -> bool {
    metadata.is_dir() && metadata.permissions().mode().trailing_zeros() >= 6
}
fn verify_file(directory: &Path, entry: &Entry, stopped: &AtomicBool) -> io::Result<()> {
    if !directory.is_absolute() || !super::valid_filename(entry.filename.as_bytes()) {
        return Err(corrupt());
    }
    let named_parent = std::fs::symlink_metadata(directory)?;
    if !private_directory(&named_parent) {
        return Err(corrupt());
    }
    let parent = File::open(directory)?;
    let held_parent = parent.metadata()?;
    if (named_parent.dev(), named_parent.ino()) != (held_parent.dev(), held_parent.ino()) {
        return Err(corrupt());
    }
    let path = directory.join(&entry.filename);
    let mut file = settings::open_regular(&path, true)?;
    let before = file.metadata()?;
    let receipt = entry.receipt.as_ref().ok_or_else(corrupt)?;
    if before.len() != receipt.prefix.bytes {
        return Err(corrupt());
    }
    let mut remaining = receipt.prefix.bytes;
    let mut hash = Sha256::new();
    let mut buffer = Zeroizing::new(vec![0_u8; 64 * 1024]);
    while remaining != 0 {
        check_stop(stopped)?;
        let window = buffer
            .len()
            .min(usize::try_from(remaining).unwrap_or(usize::MAX));
        let count = file.read(&mut buffer[..window])?;
        if count == 0 {
            return Err(corrupt());
        }
        hash.update(&buffer[..count]);
        remaining -= count as u64;
    }
    check_stop(stopped)?;
    let actual: [u8; 32] = hash.finalize().into();
    if file.read(&mut buffer[..1])? != 0 || actual != receipt.source_sha256 {
        return Err(corrupt());
    }
    let after = file.metadata()?;
    let named = std::fs::symlink_metadata(&path)?;
    let current_parent = std::fs::symlink_metadata(directory)?;
    if !named.is_file()
        || !private_directory(&current_parent)
        || after.permissions().mode() & 0o077 != 0
        || file_identity(&before) != file_identity(&after)
        || file_identity(&after) != file_identity(&named)
        || (current_parent.dev(), current_parent.ino()) != (held_parent.dev(), held_parent.ino())
    {
        return Err(corrupt());
    }
    check_stop(stopped)
}

#[cfg(test)]
#[path = "ledger_recovery_tests.rs"]
mod tests;
