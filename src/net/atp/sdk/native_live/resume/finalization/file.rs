//! Create-only private Unix storage for a sender's finalization intent.
//!
//! A complete checksum is not proof of fsync. The store confirms file and parent
//! directory synchronization before allowing ObjectComplete. Reopening validates
//! and synchronizes again. No truncation, replacement, repair or deletion occurs.
//! Trusted ancestors, ACLs and immutable retained files are caller obligations.

use super::{FinalProofCheckpoint, FinalProofStore, MAX_FINAL_PROOF_CHECKPOINT_BYTES};
use crate::runtime::spawn_blocking_io;
use parking_lot::Mutex;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::future::Future;
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

type Persist = Pin<Box<dyn Future<Output = io::Result<()>> + Send>>;
type Terminal = Result<(), (io::ErrorKind, Option<i32>)>;

struct Storage {
    path: PathBuf,
    directory: File,
    file: Mutex<File>,
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid private sender checkpoint file")
}
impl Storage {
    fn open(path: &Path, create: bool) -> io::Result<Self> {
        if !path.is_absolute() { return Err(invalid()); }
        let name = path.file_name().ok_or_else(invalid)?;
        let parent = path.parent().ok_or_else(invalid)?;
        let metadata = std::fs::symlink_metadata(parent)?;
        if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 { return Err(invalid()); }
        let parent = std::fs::canonicalize(parent)?;
        let directory = File::open(&parent)?;
        let path = parent.join(name);
        let file = OpenOptions::new().read(true).write(true).create_new(create)
            .mode(0o600).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(&path)?;
        file.try_lock().map_err(io::Error::from)?;
        let storage = Self { path, directory, file: Mutex::new(file) };
        storage.verify(&storage.file.lock())?;
        Ok(storage)
    }

    fn verify(&self, file: &File) -> io::Result<()> {
        let held = file.metadata()?;
        let named = std::fs::symlink_metadata(&self.path)?;
        let directory = self.directory.metadata()?;
        let parent = std::fs::symlink_metadata(self.path.parent().ok_or_else(invalid)?)?;
        if !held.is_file() || !named.is_file() || held.nlink() != 1
            || held.permissions().mode() & 0o077 != 0
            || (held.dev(), held.ino()) != (named.dev(), named.ino())
            || !parent.is_dir() || parent.permissions().mode() & 0o077 != 0
            || (directory.dev(), directory.ino()) != (parent.dev(), parent.ino())
        { return Err(invalid()); }
        Ok(())
    }

    fn write_once(&self, bytes: &[u8]) -> io::Result<()> {
        FinalProofCheckpoint::from_canonical_bytes(bytes)?;
        let mut file = self.file.lock();
        self.verify(&file)?;
        if file.metadata()?.len() != 0 { return Err(invalid()); }
        file.write_all(bytes)?;
        file.sync_all()?;
        self.directory.sync_all()?;
        self.verify(&file)
    }

    fn read_existing(&self) -> io::Result<Vec<u8>> {
        let mut file = self.file.lock();
        self.verify(&file)?;
        if file.metadata()?.len() > MAX_FINAL_PROOF_CHECKPOINT_BYTES as u64 { return Err(invalid()); }
        let mut bytes = Vec::with_capacity(MAX_FINAL_PROOF_CHECKPOINT_BYTES);
        (&mut *file).take(MAX_FINAL_PROOF_CHECKPOINT_BYTES as u64 + 1).read_to_end(&mut bytes)?;
        FinalProofCheckpoint::from_canonical_bytes(&bytes)?;
        // A complete record might have survived an earlier uncertain sync.
        file.sync_all()?;
        self.directory.sync_all()?;
        self.verify(&file)?;
        Ok(bytes)
    }
}

/// One exclusively owned, never-overwritten sender checkpoint file.
///
/// Provision/open synchronously before entering the runtime, like TLS settings.
/// Async persistence uses the runtime blocking pool; one bounded write is in
/// flight. Its Arc retains the descriptor/lock if an awaiting wrapper is dropped.
/// Files remain on every success/failure path. A crash before EOF leaves an
/// empty file, which open_existing refuses rather than inventing a checkpoint.
pub struct FinalProofFile {
    storage: Arc<Storage>,
    bytes: Option<Vec<u8>>,
    pending: Option<Persist>,
    terminal: Option<Terminal>,
}
impl fmt::Debug for FinalProofFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FinalProofFile").field("persisted", &self.is_persisted())
            .finish_non_exhaustive()
    }
}
impl FinalProofFile {
    /// Create a new 0600 file in an existing private directory; never overwrite.
    pub fn create_new(path: &Path) -> io::Result<Self> {
        Ok(Self { storage: Arc::new(Storage::open(path, true)?), bytes: None, pending: None, terminal: None })
    }

    /// Exclusively reopen, validate, and synchronize an existing complete record.
    /// Keep this owner alive while using its checkpoint. No fresh file is created.
    pub fn open_existing(path: &Path) -> io::Result<Self> {
        let storage = Arc::new(Storage::open(path, false)?);
        let bytes = storage.read_existing()?;
        Ok(Self { storage, bytes: Some(bytes), pending: None, terminal: Some(Ok(())) })
    }

    /// True only after this owner confirmed file and directory synchronization.
    /// This is local evidence, not remote commit or universal power-loss proof.
    #[must_use]
    pub fn is_persisted(&self) -> bool { matches!(self.terminal, Some(Ok(()))) }

    /// Retrieve the validated intent after successful persistence or reopen.
    pub fn checkpoint(&self) -> io::Result<FinalProofCheckpoint> {
        if !self.is_persisted() { return Err(io::Error::from(io::ErrorKind::WouldBlock)); }
        FinalProofCheckpoint::from_canonical_bytes(self.bytes.as_ref().expect("persisted bytes"))
    }
}

impl FinalProofStore for FinalProofFile {
    fn poll_store(
        self: Pin<&mut Self>, cx: &mut Context<'_>, checkpoint: &FinalProofCheckpoint,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let bytes = match checkpoint.to_canonical_bytes() {
            Ok(bytes) => bytes,
            Err(error) => return Poll::Ready(Err(error)),
        };
        if this.bytes.as_ref().is_some_and(|previous| previous != &bytes) {
            return Poll::Ready(Err(invalid()));
        }
        if let Some(terminal) = this.terminal {
            return Poll::Ready(terminal.map_err(|(kind, raw)| raw.map_or_else(|| io::Error::from(kind), io::Error::from_raw_os_error)));
        }
        if this.pending.is_none() {
            let storage = Arc::clone(&this.storage);
            this.bytes = Some(bytes.clone());
            this.pending = Some(Box::pin(async move {
                spawn_blocking_io(move || storage.write_once(&bytes)).await
            }));
        }
        let result = ready!(this.pending.as_mut().expect("one checkpoint write").as_mut().poll(cx));
        this.pending = None;
        this.terminal = Some(result.as_ref().map(|()| ()).map_err(|error| (error.kind(), error.raw_os_error())));
        Poll::Ready(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::{Hello, initial, offer};
    use sha2::{Digest, Sha256};

    fn checkpoint() -> FinalProofCheckpoint {
        let hello = Hello { nonce: [4; 32], epoch_bytes: 8, max_bytes: 64 };
        FinalProofCheckpoint {
            offered: offer(&hello).try_into().unwrap(), agreed: offer(&hello).try_into().unwrap(),
            receipt: super::super::LiveStreamReceipt { prefix: initial(&hello), source_sha256: Sha256::digest(b"").into() },
            server_certificate: [3; 32], remote: "127.0.0.1:8443".parse().unwrap(), domain: "localhost".to_owned(),
        }
    }
    fn path() -> PathBuf {
        let directory = tempfile::tempdir().unwrap().keep();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        directory.join("sender.checkpoint")
    }

    #[test]
    fn create_only_lock_and_reopen_preserve_exact_intent() {
        let path = path(); let store = FinalProofFile::create_new(&path).unwrap();
        assert!(!store.is_persisted()); assert!(store.checkpoint().is_err());
        let bytes = checkpoint().to_canonical_bytes().unwrap();
        store.storage.write_once(&bytes).unwrap();
        assert!(store.storage.write_once(&bytes).is_err());
        assert!(FinalProofFile::create_new(&path).is_err());
        assert!(FinalProofFile::open_existing(&path).is_err());
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        drop(store);
        let reopened = FinalProofFile::open_existing(&path).unwrap();
        assert!(reopened.is_persisted());
        assert_eq!(reopened.checkpoint().unwrap().to_canonical_bytes().unwrap(), bytes);
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
    }

    #[test]
    fn missing_empty_torn_and_oversized_files_never_become_success() {
        let missing = path(); assert!(FinalProofFile::open_existing(&missing).is_err());
        assert!(!missing.exists());
        let valid = checkpoint().to_canonical_bytes().unwrap();
        for bytes in [vec![], valid[..valid.len() - 1].to_vec(), vec![0; MAX_FINAL_PROOF_CHECKPOINT_BYTES + 1]] {
            let path = path(); let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path).unwrap();
            file.write_all(&bytes).unwrap(); drop(file);
            assert!(FinalProofFile::open_existing(&path).is_err());
            assert_eq!(std::fs::read(&path).unwrap(), bytes);
        }
    }

    #[test]
    fn public_mode_symlinks_and_extra_hard_links_are_refused() {
        let path = path(); let store = FinalProofFile::create_new(&path).unwrap();
        store.storage.write_once(&checkpoint().to_canonical_bytes().unwrap()).unwrap(); drop(store);
        let alias = path.with_extension("alias");
        std::os::unix::fs::symlink(&path, &alias).unwrap();
        assert!(FinalProofFile::open_existing(&alias).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(FinalProofFile::open_existing(&path).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::hard_link(&path, path.with_extension("hard-link")).unwrap();
        assert!(FinalProofFile::open_existing(&path).is_err());
    }
}
