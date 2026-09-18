//! Private append-only receiver WAL paired with its original data inode.
//!
//! The data file is private but visible while partial; completion is a persisted
//! journal receipt, NOT an atomic rename/publication. This profile does not use
//! LiveFileSink's destination-link semantics. Neither file is ever deleted,
//! truncated, replaced or repaired. Protect both files and their ancestry.

use super::{
    MAX_RECEIVER_CHECKPOINT_BYTES, ReceiverCheckpoint, ReceiverCheckpointPhase,
    ReceiverCheckpointStore, ResumableReceiver, ResumeError, ResumeReport,
};
use super::super::{LiveStreamCommitSink, LiveStreamError, LiveStreamReceipt, LiveStreamReceiver, NativeClientCertificateId};
use crate::cx::Cx;
use crate::fs::File as AsyncFile;
use crate::io::AsyncWrite;
use crate::runtime::spawn_blocking_io;
use parking_lot::Mutex;
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::{File, OpenOptions};
use std::future::Future;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::net::SocketAddr;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};
use zeroize::Zeroizing;

const HEADER: usize = 96;
const MAGIC: &[u8; 8] = b"ATPRFL01";
const MAX_WAL: u64 = 128 * 1024 * 1024;
type Failure = (io::ErrorKind, Option<i32>);
type Job<T> = Pin<Box<dyn Future<Output = io::Result<T>> + Send>>;

/// Explicit persistent storage ceilings; neither is reset on reopen.
#[derive(Debug, Clone, Copy)]
pub struct ReceiverFileLimits {
    /// Maximum data-file length, independent of the journal byte budget.
    pub max_data_bytes: u64,
    /// Maximum distinct snapshots, including intent and completion records.
    pub max_snapshots: u32,
    /// Total journal bytes including framing; 96 through 134,217,728.
    pub max_journal_bytes: u64,
}
impl ReceiverFileLimits {
    fn validate(self) -> io::Result<()> {
        if !(1..=65_536).contains(&self.max_snapshots) || !(HEADER as u64..=MAX_WAL).contains(&self.max_journal_bytes) {
            return Err(invalid());
        }
        Ok(())
    }
}
fn invalid() -> io::Error { io::Error::new(io::ErrorKind::InvalidData, "invalid receiver journal or data file") }
fn restore_error((kind, code): Failure) -> io::Error {
    code.map_or_else(|| io::Error::from(kind), io::Error::from_raw_os_error)
}
fn hash(previous: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"asupersync.atp.receiver-file-journal.v1");
    hash.update(previous); hash.update(bytes); hash.finalize().into()
}
fn private_parent(path: &Path) -> io::Result<(PathBuf, File)> {
    if !path.is_absolute() { return Err(invalid()); }
    let name = path.file_name().ok_or_else(invalid)?;
    let parent = path.parent().ok_or_else(invalid)?;
    let named = std::fs::symlink_metadata(parent)?;
    if !named.is_dir() || named.permissions().mode() & 0o077 != 0 { return Err(invalid()); }
    let parent = std::fs::canonicalize(parent)?;
    let directory = OpenOptions::new().read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_NONBLOCK).open(&parent)?;
    Ok((parent.join(name), directory))
}
fn identity(file: &File, path: &Path, directory: &File, single_link: bool) -> io::Result<()> {
    let held = file.metadata()?;
    let named = std::fs::symlink_metadata(path)?;
    let parent = std::fs::symlink_metadata(path.parent().ok_or_else(invalid)?)?;
    let held_parent = directory.metadata()?;
    if !held.is_file() || !named.is_file() || held.permissions().mode() & 0o077 != 0
        || (single_link && held.nlink() != 1) || (held.dev(), held.ino()) != (named.dev(), named.ino())
        || !parent.is_dir() || parent.permissions().mode() & 0o077 != 0
        || (parent.dev(), parent.ino()) != (held_parent.dev(), held_parent.ino())
    { return Err(invalid()); }
    Ok(())
}

struct State {
    file: File,
    latest: Option<ReceiverCheckpoint>,
    records: u32,
    bytes: u64,
    previous: [u8; 32],
    poisoned: bool,
}
struct Storage {
    journal_path: PathBuf,
    journal_directory: File,
    data_path: PathBuf,
    data_directory: File,
    data: File,
    limits: ReceiverFileLimits,
    state: Mutex<State>,
}
impl Storage {
    fn open(journal_path: &Path, data_path: &Path, create: Option<ReceiverFileLimits>) -> io::Result<Self> {
        if let Some(limits) = create { limits.validate()?; }
        let (journal_path, journal_directory) = private_parent(journal_path)?;
        let (data_path, data_directory) = private_parent(data_path)?;
        if journal_path == data_path { return Err(invalid()); }
        // No automatic cleanup on partial creation failure. Each file is create-only.
        let mut file = OpenOptions::new().read(true).write(true).create_new(create.is_some())
            .mode(0o600).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(&journal_path)?;
        file.try_lock().map_err(io::Error::from)?;
        identity(&file, &journal_path, &journal_directory, true)?;
        let data = OpenOptions::new().read(true).append(true).create_new(create.is_some())
            .mode(0o600).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(&data_path)?;
        data.try_lock().map_err(io::Error::from)?;
        identity(&data, &data_path, &data_directory, true)?;
        let metadata = data.metadata()?;
        let parent = data_directory.metadata()?;
        let mut header = [0; HEADER];
        if let Some(limits) = create {
            header[..8].copy_from_slice(MAGIC);
            header[8..12].copy_from_slice(&limits.max_snapshots.to_be_bytes());
            header[16..24].copy_from_slice(&limits.max_journal_bytes.to_be_bytes());
            header[24..32].copy_from_slice(&limits.max_data_bytes.to_be_bytes());
            for (offset, value) in [(32, metadata.dev()), (40, metadata.ino()), (48, parent.dev()), (56, parent.ino())] {
                header[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
            }
            let checksum = hash(&[], &header[..64]); header[64..].copy_from_slice(&checksum);
            data.sync_all()?; data_directory.sync_all()?;
            file.write_all(&header)?; file.sync_all()?; journal_directory.sync_all()?;
        } else {
            file.read_exact(&mut header)?;
        }
        let number = |offset: usize| u64::from_be_bytes(header[offset..offset + 8].try_into().expect("bounded header"));
        let limits = ReceiverFileLimits {
            max_snapshots: u32::from_be_bytes(header[8..12].try_into().expect("bounded count")),
            max_journal_bytes: number(16), max_data_bytes: number(24),
        };
        limits.validate()?;
        if &header[..8] != MAGIC || header[12..16] != [0; 4] || header[64..] != hash(&[], &header[..64])
            || (number(32), number(40)) != (metadata.dev(), metadata.ino())
            || (number(48), number(56)) != (parent.dev(), parent.ino()) || metadata.len() > limits.max_data_bytes
        { return Err(invalid()); }
        let length = file.metadata()?.len();
        if length < HEADER as u64 || length > limits.max_journal_bytes { return Err(invalid()); }
        let mut state = State { file, latest: None, records: 0, bytes: HEADER as u64,
            previous: header[64..].try_into().expect("bounded checksum"), poisoned: false };
        while state.bytes < length {
            if state.records >= limits.max_snapshots { return Err(invalid()); }
            let mut frame = [0; 16]; state.file.read_exact(&mut frame)?;
            let size = u32::from_be_bytes(frame[8..12].try_into().expect("bounded record")) as usize;
            if u64::from_be_bytes(frame[..8].try_into().expect("bounded sequence")) != u64::from(state.records)
                || frame[12..] != [0; 4] || !(super::FIXED + 32..=MAX_RECEIVER_CHECKPOINT_BYTES).contains(&size)
                || state.bytes + 16 + size as u64 + 32 > length
            { return Err(invalid()); }
            let mut record = Zeroizing::new(vec![0; 16 + size]);
            record[..16].copy_from_slice(&frame); state.file.read_exact(&mut record[16..])?;
            let mut checksum = [0; 32]; state.file.read_exact(&mut checksum)?;
            if checksum != hash(&state.previous, &record) { return Err(invalid()); }
            let checkpoint = ReceiverCheckpoint::from_canonical_bytes(&record[16..])?;
            Self::check_transition(&checkpoint, state.latest.as_ref(), limits)?;
            state.latest = Some(checkpoint); state.previous = checksum;
            state.records += 1; state.bytes += record.len() as u64 + 32;
        }
        if create.is_none() && state.latest.is_none() { return Err(invalid()); }
        identity(&state.file, &journal_path, &journal_directory, true)?;
        identity(&data, &data_path, &data_directory, true)?;
        state.file.sync_all()?; journal_directory.sync_all()?;
        Ok(Self { journal_path, journal_directory, data_path, data_directory, data, limits, state: Mutex::new(state) })
    }

    fn check_transition(saved: &ReceiverCheckpoint, previous: Option<&ReceiverCheckpoint>, limits: ReceiverFileLimits) -> io::Result<()> {
        let agreed = saved.validate()?;
        if agreed.max_bytes > limits.max_data_bytes { return Err(invalid()); }
        if let Some(previous) = previous { saved.validate_successor(previous)?; }
        else if saved.prefix.bytes != 0 || !saved.pending.is_empty() || saved.phase != ReceiverCheckpointPhase::Receiving {
            return Err(invalid());
        }
        Ok(())
    }

    fn verify(&self, file: &File) -> io::Result<()> {
        identity(file, &self.journal_path, &self.journal_directory, true)?;
        identity(&self.data, &self.data_path, &self.data_directory, true)
    }

    fn append(&self, checkpoint: ReceiverCheckpoint) -> io::Result<()> {
        let payload = checkpoint.to_canonical_bytes()?;
        let mut state = self.state.lock();
        if state.poisoned { return Err(io::Error::other("receiver journal persistence is unconfirmed")); }
        Self::check_transition(&checkpoint, state.latest.as_ref(), self.limits)?;
        let duplicate = state.latest.as_ref().map(|old| old.to_canonical_bytes())
            .transpose()?.is_some_and(|old| old.as_slice() == payload.as_slice());
        let additional = 16 + payload.len() as u64 + 32;
        if !duplicate && (state.records >= self.limits.max_snapshots || state.bytes + additional > self.limits.max_journal_bytes) {
            return Err(io::Error::from(io::ErrorKind::StorageFull));
        }
        state.poisoned = true;
        self.verify(&state.file)?;
        if state.file.metadata()?.len() != state.bytes { return Err(invalid()); }
        let size = self.data.metadata()?.len();
        if size < checkpoint.prefix.bytes || size > checkpoint.prefix.bytes + checkpoint.pending_bytes() as u64 {
            return Err(invalid());
        }
        // This ordering is the ACK durability boundary: data before WAL prefix.
        self.data.sync_all()?; self.data_directory.sync_all()?;
        if !duplicate {
            let mut record = Zeroizing::new(vec![0; 16 + payload.len()]);
            record[..8].copy_from_slice(&u64::from(state.records).to_be_bytes());
            record[8..12].copy_from_slice(&(payload.len() as u32).to_be_bytes());
            record[16..].copy_from_slice(&payload);
            let checksum = hash(&state.previous, &record);
            state.file.seek(SeekFrom::End(0))?;
            state.file.write_all(&record)?; state.file.write_all(&checksum)?;
            state.file.sync_all()?; self.journal_directory.sync_all()?;
            state.records += 1; state.bytes += additional; state.previous = checksum;
            state.latest = Some(checkpoint);
        }
        self.verify(&state.file)?;
        state.poisoned = false;
        Ok(())
    }

    fn reader(&self) -> io::Result<File> {
        let file = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(&self.data_path)?;
        identity(&file, &self.data_path, &self.data_directory, true)?;
        let expected = self.data.metadata()?; let actual = file.metadata()?;
        if (expected.dev(), expected.ino()) != (actual.dev(), actual.ino()) { return Err(invalid()); }
        Ok(file)
    }

    fn commit(&self, receipt: &LiveStreamReceipt) -> io::Result<()> {
        let mut file = self.reader()?;
        if file.metadata()?.len() != receipt.prefix.bytes { return Err(invalid()); }
        let mut remaining = receipt.prefix.bytes;
        let mut digest = Sha256::new(); let mut bytes = Zeroizing::new(vec![0; 65_536]);
        while remaining != 0 {
            let window = usize::try_from(remaining).unwrap_or(usize::MAX).min(bytes.len());
            let count = file.read(&mut bytes[..window])?;
            if count == 0 { return Err(invalid()); }
            digest.update(&bytes[..count]); remaining -= count as u64;
        }
        let actual: [u8; 32] = digest.finalize().into();
        if actual != receipt.source_sha256 || file.read(&mut bytes[..1])? != 0 { return Err(invalid()); }
        self.data.sync_all()?; self.data_directory.sync_all()?;
        identity(&self.data, &self.data_path, &self.data_directory, true)
    }
}

/// Locked, bounded journal and data-file owner. Provision/open before runtime startup.
/// Data stays partial until an actual committed checkpoint; no atomic name publication.
pub struct ReceiverJournalFile {
    storage: Arc<Storage>,
    pending: Option<Job<ReceiverCheckpoint>>,
    latest: Option<ReceiverCheckpoint>,
    failure: Option<Failure>,
}
impl fmt::Debug for ReceiverJournalFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReceiverJournalFile").field("pending", &self.pending.is_some())
            .field("failed", &self.failure.is_some()).finish_non_exhaustive()
    }
}
impl ReceiverJournalFile {
    /// Create both private files without replacing either path. Partial failures retain files.
    pub fn create_new(journal: &Path, data: &Path, limits: ReceiverFileLimits) -> io::Result<Self> {
        Ok(Self { storage: Arc::new(Storage::open(journal, data, Some(limits))?), pending: None, latest: None, failure: None })
    }
    /// Read the entire protected WAL and bind the exact original data inode. No repairs.
    /// Payload revalidation occurs in bind_restored before a socket is created.
    pub fn open_existing(journal: &Path, data: &Path) -> io::Result<Self> {
        let storage = Arc::new(Storage::open(journal, data, None)?);
        let latest = storage.state.lock().latest.clone();
        Ok(Self { storage, pending: None, latest, failure: None })
    }
    /// Last successfully persisted local checkpoint, never a peer delivery assertion.
    pub fn checkpoint(&self) -> io::Result<ReceiverCheckpoint> {
        if let Some(error) = self.failure { return Err(restore_error(error)); }
        if self.pending.is_some() { return Err(io::Error::from(io::ErrorKind::WouldBlock)); }
        self.latest.clone().ok_or_else(|| io::Error::from(io::ErrorKind::WouldBlock))
    }
    fn sink(&self) -> io::Result<ReceiverFileSink> {
        Ok(ReceiverFileSink { file: AsyncFile::from_std(self.storage.data.try_clone()?),
            storage: Arc::clone(&self.storage), written: self.storage.data.metadata()?.len(),
            receipt: None, job: None, failed: false, terminal: None })
    }
    /// Bind a newly created empty file pair for one explicitly selected client.
    pub async fn bind_new(self, authority: &LiveStreamReceiver, cx: &Cx, address: SocketAddr,
        client: NativeClientCertificateId, attempts: u32) -> Result<JournaledFileReceiver, ResumeError>
    {
        if self.latest.is_some() || self.pending.is_some() || self.storage.data.metadata().map_err(LiveStreamError::from)?.len() != 0 {
            return Err(LiveStreamError::from(invalid()).into());
        }
        let sink = self.sink().map_err(LiveStreamError::from)?;
        let receiver = authority.bind_resumable_committing(cx, address, client, sink, attempts).await?;
        Ok(JournaledFileReceiver { receiver, journal: self })
    }
    /// Restore the same file, including an exactly matching partially written epoch.
    /// A Finalizing checkpoint is unresolved and cannot be rebound for more writes.
    pub async fn bind_restored(self, authority: &LiveStreamReceiver, cx: &Cx, address: SocketAddr,
        client: NativeClientCertificateId) -> Result<JournaledFileReceiver, ResumeError>
    {
        let saved = self.checkpoint().map_err(LiveStreamError::from)?;
        let sink = self.sink().map_err(LiveStreamError::from)?;
        let reader = AsyncFile::from_std(self.storage.reader().map_err(LiveStreamError::from)?);
        let receiver = authority.bind_restored_receiver(cx, address, client, sink, reader, saved).await?;
        Ok(JournaledFileReceiver { receiver, journal: self })
    }
}
impl ReceiverCheckpointStore for ReceiverJournalFile {
    fn poll_store(self: Pin<&mut Self>, cx: &mut Context<'_>, checkpoint: &ReceiverCheckpoint) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Some(error) = this.failure { return Poll::Ready(Err(restore_error(error))); }
        if let Some(pending) = &mut this.pending {
            let result = ready!(pending.as_mut().poll(cx)); this.pending = None;
            match result {
                Ok(saved) => this.latest = Some(saved),
                Err(error) => {
                    this.failure = Some((error.kind(), error.raw_os_error()));
                    return Poll::Ready(Err(error));
                }
            }
            if this.latest.as_ref().and_then(|old| old.to_canonical_bytes().ok())
                .zip(checkpoint.to_canonical_bytes().ok()).is_some_and(|(a, b)| a.as_slice() == b.as_slice())
            { return Poll::Ready(Ok(())); }
            // The previous dropped wait completed. Validate and store this successor,
            // not a replacement of the still-running operation.
        }
        let storage = Arc::clone(&this.storage); let saved = checkpoint.clone();
        this.pending = Some(Box::pin(async move {
            spawn_blocking_io(move || { storage.append(saved.clone())?; Ok(saved) }).await
        }));
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

struct ReceiverFileSink {
    file: AsyncFile,
    storage: Arc<Storage>,
    written: u64,
    receipt: Option<LiveStreamReceipt>,
    job: Option<Job<()>>,
    failed: bool,
    terminal: Option<Result<(), Failure>>,
}
impl AsyncWrite for ReceiverFileSink {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.failed || this.receipt.is_some() { return Poll::Ready(Err(invalid())); }
        if bytes.is_empty() { return Poll::Ready(Ok(0)); }
        let count = bytes.len().min(65_536).min(usize::try_from(this.storage.limits.max_data_bytes.saturating_sub(this.written)).unwrap_or(usize::MAX));
        if count == 0 { return Poll::Ready(Err(io::Error::from(io::ErrorKind::StorageFull))); }
        match ready!(Pin::new(&mut this.file).poll_write(cx, &bytes[..count])) {
            Ok(count) => { this.written += count as u64; Poll::Ready(Ok(count)) }
            Err(error) => { this.failed = true; Poll::Ready(Err(error)) }
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.failed || this.receipt.is_some() { return Poll::Ready(Err(invalid())); }
        Pin::new(&mut this.file).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::Error::from(io::ErrorKind::Unsupported)))
    }
}
impl LiveStreamCommitSink for ReceiverFileSink {
    fn poll_commit(self: Pin<&mut Self>, cx: &mut Context<'_>, receipt: &LiveStreamReceipt) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.failed || receipt.prefix.bytes != this.written || this.receipt.as_ref().is_some_and(|old| old != receipt) {
            return Poll::Ready(Err(invalid()));
        }
        if let Some(result) = this.terminal { return Poll::Ready(result.map_err(restore_error)); }
        this.receipt = Some(receipt.clone());
        if this.job.is_none() {
            if let Err(error) = ready!(Pin::new(&mut this.file).poll_flush(cx)) {
                this.failed = true; return Poll::Ready(Err(error));
            }
            let storage = Arc::clone(&this.storage); let receipt = receipt.clone();
            this.job = Some(Box::pin(async move { spawn_blocking_io(move || storage.commit(&receipt)).await }));
        }
        let result = ready!(this.job.as_mut().expect("one file commit").as_mut().poll(cx));
        this.job = None;
        this.terminal = Some(result.as_ref().copied().map_err(|error| (error.kind(), error.raw_os_error())));
        Poll::Ready(result)
    }
}

/// One socket/session, journal, and private data inode. All receive attempts journal.
/// Keep this owner in a scope-owned task and join it; no detached work is created.
#[must_use = "drive authenticated receive attempts and inspect their complete results"]
pub struct JournaledFileReceiver {
    receiver: ResumableReceiver<ReceiverFileSink>,
    journal: ReceiverJournalFile,
}
impl fmt::Debug for JournaledFileReceiver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JournaledFileReceiver").field("journal", &self.journal).finish_non_exhaustive()
    }
}
impl JournaledFileReceiver {
    /// Actual bound socket address; resume requires the sender's original endpoint.
    pub fn local_addr(&self) -> io::Result<SocketAddr> { self.receiver.local_addr() }
    /// Retained private data path. It can contain a partial transfer until committed.
    #[must_use]
    pub fn data_path(&self) -> &Path { &self.journal.storage.data_path }
    /// Historical successfully persisted receiver state, not proof of peer receipt.
    pub fn checkpoint(&self) -> io::Result<ReceiverCheckpoint> { self.journal.checkpoint() }
    /// One bounded, freshly authenticated attempt, with the same journal and inode.
    pub async fn receive(&mut self, cx: &Cx) -> ResumeReport {
        self.receiver.receive_journaled(cx, &mut self.journal).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::super::{Hello, advance, digest, encode_epoch, initial, offer};

    fn files() -> (PathBuf, PathBuf) {
        let directory = tempfile::tempdir().unwrap().keep();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        (directory.join("receiver.wal"), directory.join("receiver.data"))
    }
    fn limits() -> ReceiverFileLimits {
        ReceiverFileLimits { max_data_bytes: 64, max_snapshots: 16, max_journal_bytes: 65536 }
    }
    fn checkpoints() -> (ReceiverCheckpoint, ReceiverCheckpoint, ReceiverCheckpoint) {
        let hello = Hello { nonce: [9; 32], epoch_bytes: 8, max_bytes: 64 };
        let start = ReceiverCheckpoint {
            client: NativeClientCertificateId::from_sha256([3; 32]),
            offered: offer(&hello).try_into().unwrap(), agreed: offer(&hello).try_into().unwrap(),
            prefix: initial(&hello), prefix_hash: digest(&Sha256::new()), pending_hash: digest(&Sha256::new()),
            used: 1, maximum: 4, phase: ReceiverCheckpointPhase::Receiving, pending: Zeroizing::new(Vec::new()),
        };
        let mut pending = start.clone();
        pending.pending = Zeroizing::new(encode_epoch(&start.prefix, b"abcdefgh"));
        pending.pending_hash = Sha256::digest(b"abcdefgh").into();
        let mut stable = pending.clone();
        stable.prefix = advance(&start.prefix, &pending.pending, 8, 64).unwrap();
        stable.prefix_hash = pending.pending_hash; stable.pending = Zeroizing::new(Vec::new());
        (start, pending, stable)
    }
    fn append_data(store: &ReceiverJournalFile, bytes: &[u8]) {
        (&store.storage.data).write_all(bytes).unwrap();
        store.storage.data.sync_all().unwrap();
    }

    #[test]
    fn exact_inode_and_pending_intent_survive_reopen_with_partial_data() {
        let (journal, data) = files(); let (start, pending, stable) = checkpoints();
        let store = ReceiverJournalFile::create_new(&journal, &data, limits()).unwrap();
        store.storage.append(start).unwrap(); store.storage.append(pending.clone()).unwrap();
        append_data(&store, b"abc");
        assert!(ReceiverJournalFile::open_existing(&journal, &data).is_err());
        let before = std::fs::read(&journal).unwrap(); let inode = std::fs::metadata(&data).unwrap().ino();
        drop(store);
        let reopened = ReceiverJournalFile::open_existing(&journal, &data).unwrap();
        assert_eq!(reopened.checkpoint().unwrap().to_canonical_bytes().unwrap().as_slice(), pending.to_canonical_bytes().unwrap().as_slice());
        assert_eq!(std::fs::read(&data).unwrap(), b"abc");
        append_data(&reopened, b"defgh"); reopened.storage.append(stable).unwrap();
        drop(reopened);
        let complete = ReceiverJournalFile::open_existing(&journal, &data).unwrap();
        assert_eq!(complete.checkpoint().unwrap().prefix().bytes, 8);
        assert_eq!(std::fs::metadata(&data).unwrap().ino(), inode);
        assert_eq!(std::fs::read(&data).unwrap(), b"abcdefgh");
        assert!(std::fs::read(&journal).unwrap().starts_with(&before));
    }

    #[test]
    fn snapshot_exhaustion_is_persistent_and_identical_records_are_idempotent() {
        let (journal, data) = files(); let (start, pending, _) = checkpoints();
        let store = ReceiverJournalFile::create_new(&journal, &data, ReceiverFileLimits { max_snapshots: 1, ..limits() }).unwrap();
        store.storage.append(start.clone()).unwrap(); let bytes = std::fs::read(&journal).unwrap();
        store.storage.append(start).unwrap();
        assert_eq!(std::fs::read(&journal).unwrap(), bytes);
        assert_eq!(store.storage.append(pending.clone()).unwrap_err().kind(), io::ErrorKind::StorageFull);
        drop(store);
        let reopened = ReceiverJournalFile::open_existing(&journal, &data).unwrap();
        assert_eq!(reopened.storage.append(pending).unwrap_err().kind(), io::ErrorKind::StorageFull);
        assert_eq!(std::fs::read(&journal).unwrap(), bytes);
        assert_eq!(std::fs::metadata(&data).unwrap().len(), 0);
    }

    #[test]
    fn torn_history_and_inode_replacement_are_refused_without_repairs() {
        let (journal, data) = files(); let (start, _, _) = checkpoints();
        let store = ReceiverJournalFile::create_new(&journal, &data, limits()).unwrap();
        store.storage.append(start).unwrap(); drop(store);
        let pristine = std::fs::read(&journal).unwrap();
        let broken = journal.with_extension("torn");
        let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&broken).unwrap();
        file.write_all(&pristine).unwrap(); file.write_all(&[0]).unwrap(); drop(file);
        assert!(ReceiverJournalFile::open_existing(&broken, &data).is_err());
        assert_eq!(std::fs::read(&broken).unwrap().len(), pristine.len() + 1);
        let other = data.with_extension("other");
        OpenOptions::new().write(true).create_new(true).mode(0o600).open(&other).unwrap();
        assert!(ReceiverJournalFile::open_existing(&journal, &other).is_err());
        let alias = data.with_extension("alias"); std::os::unix::fs::symlink(&data, &alias).unwrap();
        assert!(ReceiverJournalFile::open_existing(&journal, &alias).is_err());
        assert_eq!(std::fs::read(&journal).unwrap(), pristine);
    }

    #[test]
    fn uncertain_append_is_sticky_and_commit_cannot_skip_its_intent_record() {
        let (journal, data) = files(); let (start, pending, _) = checkpoints();
        let store = ReceiverJournalFile::create_new(&journal, &data, limits()).unwrap();
        store.storage.append(start.clone()).unwrap();
        let mut committed = start.clone(); committed.phase = ReceiverCheckpointPhase::Committed;
        assert!(store.storage.append(committed).is_err());
        let mut external = OpenOptions::new().append(true).open(&journal).unwrap();
        external.write_all(&[0]).unwrap(); external.sync_all().unwrap();
        assert!(store.storage.append(pending).is_err());
        assert!(store.storage.append(start).is_err());
        assert!(store.storage.state.lock().poisoned);
        assert_eq!(std::fs::metadata(&data).unwrap().len(), 0);
    }
}
