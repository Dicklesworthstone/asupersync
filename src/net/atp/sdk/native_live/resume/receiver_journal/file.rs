//! Private append-only receiver WAL paired with its original data inode.
//!
//! The data file is private but visible while partial; completion is a persisted
//! journal receipt, NOT an atomic rename/publication. This profile does not use
//! LiveFileSink's destination-link semantics. Neither file is ever deleted,
//! truncated, replaced or repaired. Protect both files and their ancestry.
//! The separately selected compact profile also owns a fixed-size intent file;
//! only its two pending-epoch slots are reused, after their prior work is durable.

mod compact;

use super::super::{
    LiveStreamCommitSink, LiveStreamError, LiveStreamReceipt, LiveStreamReceiver,
    NativeClientCertificateId,
};
use super::{
    EPOCH_HEADER_BYTES, MAX_RECEIVER_CHECKPOINT_BYTES, ReceiverCheckpoint, ReceiverCheckpointPhase,
    ReceiverCheckpointStore, ResumableReceiver, ResumeError, ResumeReport,
};
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
use std::sync::{Arc, Weak};
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
        if !(1..=65_536).contains(&self.max_snapshots)
            || !(HEADER as u64..=MAX_WAL).contains(&self.max_journal_bytes)
        {
            return Err(invalid());
        }
        Ok(())
    }
}
/// Immutable budgets for the separately selected compact receiver file profile.
///
/// The WAL stores metadata and commitments. One additional private intent file
/// has two fixed slots totaling 131,328 bytes, outside `max_journal_bytes`.
/// Full 64 KiB epochs can carry 4 GiB with 131,075 snapshots and less than 53 MiB
/// of WAL before retries. Smaller epochs and retries consume additional records.
/// Reopen never resets either budget or recycles WAL history.
#[derive(Debug, Clone, Copy)]
pub struct ReceiverCompactFileLimits {
    /// Maximum length of the original private data file.
    pub max_data_bytes: u64,
    /// Maximum distinct snapshots; 1 through 1,048,576.
    pub max_snapshots: u32,
    /// WAL bytes including its 128-byte header; at most 134,217,728.
    pub max_journal_bytes: u64,
}

impl Default for ReceiverCompactFileLimits {
    fn default() -> Self {
        Self {
            max_data_bytes: 4 * 1024 * 1024 * 1024,
            max_snapshots: 262_144,
            max_journal_bytes: MAX_WAL,
        }
    }
}

impl ReceiverCompactFileLimits {
    fn validate(self) -> io::Result<()> {
        if !(1..=compact::MAX_SNAPSHOTS).contains(&self.max_snapshots)
            || !(compact::HEADER as u64..=MAX_WAL).contains(&self.max_journal_bytes)
        {
            return Err(invalid());
        }
        Ok(())
    }

    fn storage_limits(self) -> ReceiverFileLimits {
        ReceiverFileLimits {
            max_data_bytes: self.max_data_bytes,
            max_snapshots: self.max_snapshots,
            max_journal_bytes: self.max_journal_bytes,
        }
    }
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid receiver journal or data file",
    )
}
fn restore_error((kind, code): Failure) -> io::Error {
    code.map_or_else(|| io::Error::from(kind), io::Error::from_raw_os_error)
}
fn hash(previous: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"asupersync.atp.receiver-file-journal.v1");
    hash.update(previous);
    hash.update(bytes);
    hash.finalize().into()
}
fn private_parent(path: &Path) -> io::Result<(PathBuf, File)> {
    if !path.is_absolute() {
        return Err(invalid());
    }
    let name = path.file_name().ok_or_else(invalid)?;
    let parent = path.parent().ok_or_else(invalid)?;
    let named = std::fs::symlink_metadata(parent)?;
    if !named.is_dir() || named.permissions().mode() & 0o077 != 0 {
        return Err(invalid());
    }
    let parent = std::fs::canonicalize(parent)?;
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_NONBLOCK)
        .open(&parent)?;
    Ok((parent.join(name), directory))
}
fn identity(file: &File, path: &Path, directory: &File, single_link: bool) -> io::Result<()> {
    let held = file.metadata()?;
    let named = std::fs::symlink_metadata(path)?;
    let parent = std::fs::symlink_metadata(path.parent().ok_or_else(invalid)?)?;
    let held_parent = directory.metadata()?;
    if !held.is_file()
        || !named.is_file()
        || held.permissions().mode() & 0o077 != 0
        || (single_link && held.nlink() != 1)
        || (held.dev(), held.ino()) != (named.dev(), named.ino())
        || !parent.is_dir()
        || parent.permissions().mode() & 0o077 != 0
        || (parent.dev(), parent.ino()) != (held_parent.dev(), held_parent.ino())
    {
        return Err(invalid());
    }
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
    intent: Option<compact::Intent>,
    limits: ReceiverFileLimits,
    state: Mutex<State>,
}
impl Storage {
    fn open(
        journal_path: &Path,
        data_path: &Path,
        create: Option<ReceiverFileLimits>,
        intent_path: Option<&Path>,
    ) -> io::Result<Self> {
        let validate_limits = |limits: ReceiverFileLimits| {
            if intent_path.is_some() {
                ReceiverCompactFileLimits {
                    max_data_bytes: limits.max_data_bytes,
                    max_snapshots: limits.max_snapshots,
                    max_journal_bytes: limits.max_journal_bytes,
                }
                .validate()
            } else {
                limits.validate()
            }
        };
        if let Some(limits) = create {
            validate_limits(limits)?;
        }
        let (journal_path, journal_directory) = private_parent(journal_path)?;
        let (data_path, data_directory) = private_parent(data_path)?;
        let intent_path = intent_path
            .map(|path| private_parent(path).map(|(path, _)| path))
            .transpose()?;
        if journal_path == data_path
            || intent_path
                .as_ref()
                .is_some_and(|path| *path == journal_path || *path == data_path)
        {
            return Err(invalid());
        }
        // No automatic cleanup on partial creation failure. Each file is create-only.
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(create.is_some())
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&journal_path)?;
        file.try_lock().map_err(io::Error::from)?;
        identity(&file, &journal_path, &journal_directory, true)?;
        let data = OpenOptions::new()
            .read(true)
            .append(true)
            .create_new(create.is_some())
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&data_path)?;
        data.try_lock().map_err(io::Error::from)?;
        identity(&data, &data_path, &data_directory, true)?;
        let intent = intent_path
            .as_ref()
            .map(|path| compact::Intent::open(path, create.is_some()))
            .transpose()?;
        let metadata = data.metadata()?;
        let parent = data_directory.metadata()?;
        let header_length = if intent.is_some() { compact::HEADER } else { HEADER };
        let checksum_at = header_length - 32;
        let magic = if intent.is_some() { compact::MAGIC } else { MAGIC };
        let journal_hash: fn(&[u8], &[u8]) -> [u8; 32] =
            if intent.is_some() { compact::hash } else { hash };
        let mut header = vec![0; header_length];
        if let Some(limits) = create {
            header[..8].copy_from_slice(magic);
            header[8..12].copy_from_slice(&limits.max_snapshots.to_be_bytes());
            header[16..24].copy_from_slice(&limits.max_journal_bytes.to_be_bytes());
            header[24..32].copy_from_slice(&limits.max_data_bytes.to_be_bytes());
            for (offset, value) in [
                (32, metadata.dev()),
                (40, metadata.ino()),
                (48, parent.dev()),
                (56, parent.ino()),
            ] {
                header[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
            }
            if let Some(intent) = &intent {
                intent.write_identity(&mut header)?;
            }
            let checksum = journal_hash(&[], &header[..checksum_at]);
            header[checksum_at..].copy_from_slice(&checksum);
            data.sync_all()?;
            data_directory.sync_all()?;
            file.write_all(&header)?;
            file.sync_all()?;
            journal_directory.sync_all()?;
        } else {
            file.read_exact(&mut header)?;
        }
        let number = |offset: usize| {
            u64::from_be_bytes(
                header[offset..offset + 8]
                    .try_into()
                    .expect("bounded header"),
            )
        };
        let limits = ReceiverFileLimits {
            max_snapshots: u32::from_be_bytes(header[8..12].try_into().expect("bounded count")),
            max_journal_bytes: number(16),
            max_data_bytes: number(24),
        };
        validate_limits(limits)?;
        let intent_matches = intent
            .as_ref()
            .map(|intent| intent.matches_identity(&header))
            .transpose()?
            .unwrap_or(true);
        // Reopen compares the recorded inode numbers but not the device
        // numbers: a device number is assigned at mount time and can differ
        // after a reboot (btrfs subvolumes, dynamically numbered partitions),
        // which refused exactly the crash recovery this journal exists for.
        // The same-boot identity checks still compare devices, and restore
        // re-hashes and byte-compares the data itself.
        if &header[..8] != magic
            || header[12..16] != [0; 4]
            || header[checksum_at..] != journal_hash(&[], &header[..checksum_at])
            || !intent_matches
            || number(40) != metadata.ino()
            || number(56) != parent.ino()
            || metadata.len() > limits.max_data_bytes
        {
            return Err(invalid());
        }
        let length = file.metadata()?.len();
        if length < header_length as u64 || length > limits.max_journal_bytes {
            return Err(invalid());
        }
        let slots = intent.as_ref().map(compact::Intent::slots).transpose()?;
        let max_checkpoint = if intent.is_some() {
            compact::MAX_CHECKPOINT
        } else {
            MAX_RECEIVER_CHECKPOINT_BYTES
        };
        let mut state = State {
            file,
            latest: None,
            records: 0,
            bytes: header_length as u64,
            previous: header[checksum_at..].try_into().expect("bounded checksum"),
            poisoned: false,
        };
        while state.bytes < length {
            if state.records >= limits.max_snapshots {
                return Err(invalid());
            }
            let mut frame = [0; 16];
            state.file.read_exact(&mut frame)?;
            let size =
                u32::from_be_bytes(frame[8..12].try_into().expect("bounded record")) as usize;
            if u64::from_be_bytes(frame[..8].try_into().expect("bounded sequence"))
                != u64::from(state.records)
                || frame[12..] != [0; 4]
                || !(super::FIXED + 32..=max_checkpoint).contains(&size)
                || state.bytes + 16 + size as u64 + 32 > length
            {
                return Err(invalid());
            }
            let mut record = Zeroizing::new(vec![0; 16 + size]);
            record[..16].copy_from_slice(&frame);
            state.file.read_exact(&mut record[16..])?;
            let mut checksum = [0; 32];
            state.file.read_exact(&mut checksum)?;
            if checksum != journal_hash(&state.previous, &record) {
                return Err(invalid());
            }
            let checkpoint = if let Some(slots) = &slots {
                compact::decode(&record[16..], &data, slots)?
            } else {
                ReceiverCheckpoint::from_canonical_bytes(&record[16..])?
            };
            Self::check_transition(&checkpoint, state.latest.as_ref(), limits)?;
            state.latest = Some(checkpoint);
            state.previous = checksum;
            state.records += 1;
            state.bytes += record.len() as u64 + 32;
        }
        if create.is_none() && state.latest.is_none() {
            return Err(invalid());
        }
        identity(&state.file, &journal_path, &journal_directory, true)?;
        identity(&data, &data_path, &data_directory, true)?;
        if let Some(intent) = &intent {
            intent.verify()?;
        }
        state.file.sync_all()?;
        journal_directory.sync_all()?;
        Ok(Self {
            journal_path,
            journal_directory,
            data_path,
            data_directory,
            data,
            intent,
            limits,
            state: Mutex::new(state),
        })
    }

    fn check_transition(
        saved: &ReceiverCheckpoint,
        previous: Option<&ReceiverCheckpoint>,
        limits: ReceiverFileLimits,
    ) -> io::Result<()> {
        let agreed = saved.validate()?;
        if agreed.max_bytes > limits.max_data_bytes {
            return Err(invalid());
        }
        if let Some(previous) = previous {
            saved.validate_successor(previous)?;
        } else if saved.prefix.bytes != 0
            || !saved.pending.is_empty()
            || saved.phase != ReceiverCheckpointPhase::Receiving
        {
            return Err(invalid());
        }
        Ok(())
    }

    fn verify(&self, file: &File) -> io::Result<()> {
        identity(file, &self.journal_path, &self.journal_directory, true)?;
        identity(&self.data, &self.data_path, &self.data_directory, true)?;
        if let Some(intent) = &self.intent {
            intent.verify()?;
        }
        Ok(())
    }

    fn append(&self, checkpoint: ReceiverCheckpoint) -> io::Result<()> {
        let mut payload = checkpoint.to_canonical_bytes()?;
        let mut state = self.state.lock();
        if state.poisoned {
            return Err(io::Error::other(
                "receiver journal persistence is unconfirmed",
            ));
        }
        Self::check_transition(&checkpoint, state.latest.as_ref(), self.limits)?;
        let duplicate = state
            .latest
            .as_ref()
            .map(|old| old.to_canonical_bytes())
            .transpose()?
            .is_some_and(|old| old.as_slice() == payload.as_slice());
        if self.intent.is_some() {
            payload = compact::encode(&payload)?;
        }
        let additional = 16 + payload.len() as u64 + 32;
        if !duplicate
            && (state.records >= self.limits.max_snapshots
                || state.bytes + additional > self.limits.max_journal_bytes)
        {
            return Err(io::Error::from(io::ErrorKind::StorageFull));
        }
        state.poisoned = true;
        self.verify(&state.file)?;
        if state.file.metadata()?.len() != state.bytes {
            return Err(invalid());
        }
        let size = self.data.metadata()?.len();
        if size < checkpoint.prefix.bytes
            || size > checkpoint.prefix.bytes + checkpoint.pending_bytes() as u64
        {
            return Err(invalid());
        }
        // This ordering is the ACK durability boundary: data before WAL prefix.
        self.data.sync_all()?;
        self.data_directory.sync_all()?;
        if !duplicate {
            if let Some(intent) = &self.intent {
                // Never rewrite an active pending slot on a connection retry:
                // that slot is the last durable copy after a partial write.
                // A new epoch uses the other slot; its predecessor's completed
                // prefix was synchronized before this transition was admitted.
                if !checkpoint.pending.is_empty()
                    && state.latest.as_ref().is_none_or(|old| old.pending.is_empty())
                {
                    intent.stage(&checkpoint)?;
                }
            }
            // One buffer, so the record and its checksum go out in one write:
            // a kill between two writes left a checksum-less frame that every
            // later reopen refuses.
            let end = 16 + payload.len();
            let mut record = Zeroizing::new(vec![0; end + 32]);
            record[..8].copy_from_slice(&u64::from(state.records).to_be_bytes());
            record[8..12].copy_from_slice(&(payload.len() as u32).to_be_bytes());
            record[16..end].copy_from_slice(&payload);
            let checksum = if self.intent.is_some() {
                compact::hash(&state.previous, &record[..end])
            } else {
                hash(&state.previous, &record[..end])
            };
            record[end..].copy_from_slice(&checksum);
            state.file.seek(SeekFrom::End(0))?;
            state.file.write_all(&record)?;
            state.file.sync_all()?;
            self.journal_directory.sync_all()?;
            state.records += 1;
            state.bytes += additional;
            state.previous = checksum;
            state.latest = Some(checkpoint);
        }
        self.verify(&state.file)?;
        state.poisoned = false;
        Ok(())
    }

    fn reader(&self) -> io::Result<File> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&self.data_path)?;
        identity(&file, &self.data_path, &self.data_directory, true)?;
        let expected = self.data.metadata()?;
        let actual = file.metadata()?;
        if (expected.dev(), expected.ino()) != (actual.dev(), actual.ino()) {
            return Err(invalid());
        }
        Ok(file)
    }

    fn commit(&self, receipt: &LiveStreamReceipt) -> io::Result<()> {
        let mut file = self.reader()?;
        if file.metadata()?.len() != receipt.prefix.bytes {
            return Err(invalid());
        }
        let mut remaining = receipt.prefix.bytes;
        let mut digest = Sha256::new();
        let mut bytes = Zeroizing::new(vec![0; 65_536]);
        while remaining != 0 {
            let window = usize::try_from(remaining)
                .unwrap_or(usize::MAX)
                .min(bytes.len());
            let count = file.read(&mut bytes[..window])?;
            if count == 0 {
                return Err(invalid());
            }
            digest.update(&bytes[..count]);
            remaining -= count as u64;
        }
        let actual: [u8; 32] = digest.finalize().into();
        if actual != receipt.source_sha256 || file.read(&mut bytes[..1])? != 0 {
            return Err(invalid());
        }
        self.data.sync_all()?;
        self.data_directory.sync_all()?;
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

/// Non-owning observation of the latest confirmed journal checkpoint.
///
/// Keep this before moving a file pair into a standalone or shared receiver.
/// It cannot write, bind, retry, publish, or release the owner's locks. Clones
/// do not prolong the data/WAL lifetime, and reads never wait on its state mutex.
/// A checkpoint is historical local state, not a peer acknowledgment or
/// evidence that all current work is durable. On reopen, retained data still
/// requires the normal restoration content checks.
#[derive(Clone)]
pub struct ReceiverJournalObserver {
    storage: Weak<Storage>,
}

impl fmt::Debug for ReceiverJournalObserver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReceiverJournalObserver")
            .finish_non_exhaustive()
    }
}

impl ReceiverJournalObserver {
    /// Copy the latest completed append/reopen observation without reading files.
    ///
    /// `WouldBlock` means either no checkpoint exists yet or the storage owner
    /// is updating it; this is not an asynchronous readiness notification.
    /// `NotConnected` means the paired storage owner is gone, not that all
    /// descriptor-owned I/O finished; only the runtime's joins/drain establish that.
    /// Unconfirmed persistence returns an error rather than a possibly advanced
    /// record. A queued operation may not have begun: success here never means
    /// quiescence, that a pending operation succeeded, or that Proof was received.
    /// Retain the returned snapshot separately when it is needed after drain.
    /// The snapshot can contain one plaintext pending epoch; protect all copies.
    pub fn checkpoint(&self) -> io::Result<ReceiverCheckpoint> {
        let storage = self
            .storage
            .upgrade()
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotConnected))?;
        let state = storage
            .state
            .try_lock()
            .ok_or_else(|| io::Error::from(io::ErrorKind::WouldBlock))?;
        if state.poisoned {
            return Err(io::Error::other("receiver journal persistence is unconfirmed"));
        }
        state
            .latest
            .clone()
            .ok_or_else(|| io::Error::from(io::ErrorKind::WouldBlock))
    }
}

impl fmt::Debug for ReceiverJournalFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReceiverJournalFile")
            .field("pending", &self.pending.is_some())
            .field("failed", &self.failure.is_some())
            .finish_non_exhaustive()
    }
}
impl ReceiverJournalFile {
    /// Observe confirmed WAL state after this owner moves into a receiver.
    /// The observer does not extend file-lock ownership or expose mutable state.
    #[must_use]
    pub fn observer(&self) -> ReceiverJournalObserver {
        ReceiverJournalObserver {
            storage: Arc::downgrade(&self.storage),
        }
    }

    /// Create both private files without replacing either path. Partial failures retain files.
    pub fn create_new(journal: &Path, data: &Path, limits: ReceiverFileLimits) -> io::Result<Self> {
        Ok(Self {
            storage: Arc::new(Storage::open(journal, data, Some(limits), None)?),
            pending: None,
            latest: None,
            failure: None,
        })
    }
    /// Read the entire protected WAL and bind the exact original data inode. No repairs.
    /// Payload revalidation occurs in bind_restored before a socket is created.
    pub fn open_existing(journal: &Path, data: &Path) -> io::Result<Self> {
        let storage = Arc::new(Storage::open(journal, data, None, None)?);
        let latest = storage.state.lock().latest.clone();
        Ok(Self {
            storage,
            pending: None,
            latest,
            failure: None,
        })
    }
    /// Create the compact metadata profile with a third, fixed-size intent file.
    ///
    /// All three paths must be distinct, absent, and inside trusted private
    /// directories. The data and WAL remain append-only; two slots in the intent
    /// file retain the pending epoch while completed historical payloads are
    /// recovered from their original data offsets. A slot is synchronized before
    /// its WAL record, and the preceding slot survives preparation of the next
    /// epoch. No file is replaced, truncated, deleted, or repaired.
    ///
    /// This separately versioned profile leaves `create_new` and its immutable
    /// V1 limits unchanged. Use `open_existing_compact` with the same three
    /// original inodes after restart. Provision before runtime startup.
    pub fn create_new_compact(
        journal: &Path,
        data: &Path,
        intent: &Path,
        limits: ReceiverCompactFileLimits,
    ) -> io::Result<Self> {
        limits.validate()?;
        Ok(Self {
            storage: Arc::new(Storage::open(
                journal,
                data,
                Some(limits.storage_limits()),
                Some(intent),
            )?),
            pending: None,
            latest: None,
            failure: None,
        })
    }

    /// Stream a compact WAL and reopen the original data and intent inodes.
    ///
    /// Replay retains two fixed pending slots and the previous/current bounded
    /// checkpoints, rather than loading the WAL or data file. Historical epochs are
    /// read at their exact data offsets and checked against both their payload
    /// commitment and original canonical checkpoint checksum. The ordinary
    /// restore path still rehashes the stable prefix and compares every actual
    /// tail byte before binding a socket. Incomplete or corrupted history is
    /// refused; neither snapshot nor byte budgets are reset.
    pub fn open_existing_compact(journal: &Path, data: &Path, intent: &Path) -> io::Result<Self> {
        let storage = Arc::new(Storage::open(journal, data, None, Some(intent))?);
        let latest = storage.state.lock().latest.clone();
        Ok(Self {
            storage,
            pending: None,
            latest,
            failure: None,
        })
    }

    /// Last successfully persisted local checkpoint, never a peer delivery assertion.
    pub fn checkpoint(&self) -> io::Result<ReceiverCheckpoint> {
        if let Some(error) = self.failure {
            return Err(restore_error(error));
        }
        if self.pending.is_some() {
            return Err(io::Error::from(io::ErrorKind::WouldBlock));
        }
        self.latest
            .clone()
            .ok_or_else(|| io::Error::from(io::ErrorKind::WouldBlock))
    }

    /// Resolve a crash during this file profile's final verification and sync.
    ///
    /// Call after reopening the original protected pair, before moving it into a
    /// receiver. This synchronously re-hashes the exact retained data inode,
    /// requires its length and SHA-256 to equal the final intent, synchronizes
    /// data and its parent, then appends and synchronizes the Committed checkpoint.
    /// Run before runtime startup or on a blocking thread, as with open_existing.
    /// No bytes are written to the data file, and neither file is repaired,
    /// replaced or truncated. A Receiving checkpoint cannot be promoted.
    ///
    /// This operation is specific to the built-in file sink: its application
    /// commit only verifies and syncs this file. It cannot establish the outcome
    /// of an external application commit when this journal was paired with a
    /// different sink. Such effects require their own recovery evidence.
    ///
    /// A completed pair is revalidated and returns the same historical receipt
    /// without adding another record. The receipt does not assert peer delivery.
    /// Normal restoration continues to refuse unresolved Finalizing checkpoints;
    /// after success, bind_restored/into_service_session can resend only Proof.
    pub fn resolve_finalizing(&mut self) -> io::Result<LiveStreamReceipt> {
        let mut saved = self.checkpoint()?;
        if saved.phase == ReceiverCheckpointPhase::Receiving {
            return Err(io::Error::other("receiver has no final commit intent"));
        }
        {
            let state = self.storage.state.lock();
            if state.poisoned || state.file.metadata()?.len() != state.bytes {
                return Err(invalid());
            }
            self.storage.verify(&state.file)?;
            let current = state.latest.as_ref().ok_or_else(invalid)?;
            if current.to_canonical_bytes()?.as_slice() != saved.to_canonical_bytes()?.as_slice() {
                return Err(invalid());
            }
        }
        let receipt = saved.receipt();
        self.storage.commit(&receipt)?;
        if saved.phase == ReceiverCheckpointPhase::Finalizing {
            saved.phase = ReceiverCheckpointPhase::Committed;
            if let Err(error) = self.storage.append(saved.clone()) {
                self.failure = Some((error.kind(), error.raw_os_error()));
                return Err(error);
            }
            self.latest = Some(saved);
        }
        Ok(receipt)
    }

    fn sink(&self) -> io::Result<ReceiverFileSink> {
        Ok(ReceiverFileSink {
            file: AsyncFile::from_std(self.storage.data.try_clone()?),
            storage: Arc::clone(&self.storage),
            written: self.storage.data.metadata()?.len(),
            receipt: None,
            job: None,
            failed: false,
            terminal: None,
        })
    }

    /// Transfer this paired owner into a factory for `ResumableService::next_journaled`.
    ///
    /// A newly created empty pair becomes a new session; a reopened pair retains
    /// its complete checkpoint and original data reader. This never binds another
    /// listener, creates a file, or acquires another SDK transfer credit. Metadata
    /// and descriptor work runs on the blocking pool. The service then checks the
    /// authenticated key, current limits and actual retained bytes under its one
    /// factory/revalidation deadline before replying. A pending/failed store or
    /// uncertain application commit cannot become a new writable session.
    ///
    /// Select create versus reopen from a protected application catalog, never
    /// by treating a missing old file as permission to create another transfer.
    /// Both files remain private in-place data; no atomic publication is added.
    pub async fn into_service_session(
        self,
    ) -> io::Result<
        super::shared::JournaledSession<impl LiveStreamCommitSink + Send + Unpin + 'static>,
    > {
        spawn_blocking_io(move || self.service_session()).await
    }

    fn service_session(self) -> io::Result<super::shared::JournaledSession<ReceiverFileSink>> {
        if let Some(error) = self.failure {
            return Err(restore_error(error));
        }
        if self.pending.is_some() {
            return Err(io::Error::from(io::ErrorKind::WouldBlock));
        }
        {
            let state = self.storage.state.lock();
            if state.poisoned || state.file.metadata()?.len() != state.bytes {
                return Err(invalid());
            }
            self.storage.verify(&state.file)?;
        }
        if self.latest.is_some() {
            let saved = self.checkpoint()?;
            if saved.phase() == ReceiverCheckpointPhase::Finalizing {
                return Err(io::Error::other("receiver application commit remains unresolved"));
            }
            let sink = self.sink()?;
            let retained = AsyncFile::from_std(self.storage.reader()?);
            Ok(super::shared::JournaledSession::restore(sink, self, retained, saved))
        } else {
            if self.storage.data.metadata()?.len() != 0
                || self.storage.state.lock().latest.is_some()
            {
                return Err(invalid());
            }
            let sink = self.sink()?;
            Ok(super::shared::JournaledSession::new(sink, self))
        }
    }

    /// Bind a newly created empty file pair for one explicitly selected client.
    pub async fn bind_new(
        self,
        authority: &LiveStreamReceiver,
        cx: &Cx,
        address: SocketAddr,
        client: NativeClientCertificateId,
        attempts: u32,
    ) -> Result<JournaledFileReceiver, ResumeError> {
        if self.latest.is_some()
            || self.pending.is_some()
            || self
                .storage
                .data
                .metadata()
                .map_err(LiveStreamError::from)?
                .len()
                != 0
        {
            return Err(LiveStreamError::from(invalid()).into());
        }
        let sink = self.sink().map_err(LiveStreamError::from)?;
        let receiver = authority
            .bind_resumable_committing(cx, address, client, sink, attempts)
            .await?;
        Ok(JournaledFileReceiver {
            receiver,
            journal: self,
        })
    }
    /// Restore the same file, including an exactly matching partially written epoch.
    /// A Finalizing checkpoint is unresolved and cannot be rebound for more writes.
    pub async fn bind_restored(
        self,
        authority: &LiveStreamReceiver,
        cx: &Cx,
        address: SocketAddr,
        client: NativeClientCertificateId,
    ) -> Result<JournaledFileReceiver, ResumeError> {
        let saved = self.checkpoint().map_err(LiveStreamError::from)?;
        let sink = self.sink().map_err(LiveStreamError::from)?;
        let reader = AsyncFile::from_std(self.storage.reader().map_err(LiveStreamError::from)?);
        let receiver = authority
            .bind_restored_receiver(cx, address, client, sink, reader, saved)
            .await?;
        Ok(JournaledFileReceiver {
            receiver,
            journal: self,
        })
    }
}
impl ReceiverCheckpointStore for ReceiverJournalFile {
    fn poll_store(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        checkpoint: &ReceiverCheckpoint,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Some(error) = this.failure {
            return Poll::Ready(Err(restore_error(error)));
        }
        if let Some(pending) = &mut this.pending {
            let result = ready!(pending.as_mut().poll(cx));
            this.pending = None;
            match result {
                Ok(saved) => this.latest = Some(saved),
                Err(error) => {
                    this.failure = Some((error.kind(), error.raw_os_error()));
                    return Poll::Ready(Err(error));
                }
            }
            if this
                .latest
                .as_ref()
                .and_then(|old| old.to_canonical_bytes().ok())
                .zip(checkpoint.to_canonical_bytes().ok())
                .is_some_and(|(a, b)| a.as_slice() == b.as_slice())
            {
                return Poll::Ready(Ok(()));
            }
            // The previous dropped wait completed. Validate and store this successor,
            // not a replacement of the still-running operation.
        }
        let storage = Arc::clone(&this.storage);
        let saved = checkpoint.clone();
        this.pending = Some(Box::pin(async move {
            spawn_blocking_io(move || {
                storage.append(saved.clone())?;
                Ok(saved)
            })
            .await
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
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.failed || this.receipt.is_some() {
            return Poll::Ready(Err(invalid()));
        }
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let count = bytes.len().min(65_536).min(
            usize::try_from(
                this.storage
                    .limits
                    .max_data_bytes
                    .saturating_sub(this.written),
            )
            .unwrap_or(usize::MAX),
        );
        if count == 0 {
            return Poll::Ready(Err(io::Error::from(io::ErrorKind::StorageFull)));
        }
        match ready!(Pin::new(&mut this.file).poll_write(cx, &bytes[..count])) {
            Ok(count) => {
                this.written += count as u64;
                Poll::Ready(Ok(count))
            }
            Err(error) => {
                this.failed = true;
                Poll::Ready(Err(error))
            }
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.failed || this.receipt.is_some() {
            return Poll::Ready(Err(invalid()));
        }
        Pin::new(&mut this.file).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::Error::from(io::ErrorKind::Unsupported)))
    }
}
impl LiveStreamCommitSink for ReceiverFileSink {
    fn poll_commit(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        receipt: &LiveStreamReceipt,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.failed
            || receipt.prefix.bytes != this.written
            || this.receipt.as_ref().is_some_and(|old| old != receipt)
        {
            return Poll::Ready(Err(invalid()));
        }
        if let Some(result) = this.terminal {
            return Poll::Ready(result.map_err(restore_error));
        }
        this.receipt = Some(receipt.clone());
        if this.job.is_none() {
            if let Err(error) = ready!(Pin::new(&mut this.file).poll_flush(cx)) {
                this.failed = true;
                return Poll::Ready(Err(error));
            }
            let storage = Arc::clone(&this.storage);
            let receipt = receipt.clone();
            this.job = Some(Box::pin(async move {
                spawn_blocking_io(move || storage.commit(&receipt)).await
            }));
        }
        let result = ready!(
            this.job
                .as_mut()
                .expect("one file commit")
                .as_mut()
                .poll(cx)
        );
        this.job = None;
        this.terminal = Some(
            result
                .as_ref()
                .copied()
                .map_err(|error| (error.kind(), error.raw_os_error())),
        );
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
        f.debug_struct("JournaledFileReceiver")
            .field("journal", &self.journal)
            .finish_non_exhaustive()
    }
}
impl JournaledFileReceiver {
    /// Observe persisted state separately from newer in-memory transfer progress.
    #[must_use]
    pub fn observer(&self) -> ReceiverJournalObserver {
        self.journal.observer()
    }

    /// Actual bound socket address; resume requires the sender's original endpoint.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.receiver.local_addr()
    }
    /// Retained private data path. It can contain a partial transfer until committed.
    #[must_use]
    pub fn data_path(&self) -> &Path {
        &self.journal.storage.data_path
    }
    /// Historical successfully persisted receiver state, not proof of peer receipt.
    pub fn checkpoint(&self) -> io::Result<ReceiverCheckpoint> {
        self.journal.checkpoint()
    }
    /// One bounded, freshly authenticated attempt, with the same journal and inode.
    pub async fn receive(&mut self, cx: &Cx) -> ResumeReport {
        self.receiver.receive_journaled(cx, &mut self.journal).await
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::{Hello, advance, digest, encode_epoch, initial, offer};
    use super::*;

    fn files() -> (PathBuf, PathBuf) {
        let directory = tempfile::tempdir().unwrap().keep();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        (
            directory.join("receiver.wal"),
            directory.join("receiver.data"),
        )
    }
    fn limits() -> ReceiverFileLimits {
        ReceiverFileLimits {
            max_data_bytes: 64,
            max_snapshots: 16,
            max_journal_bytes: 65536,
        }
    }
    fn checkpoints() -> (ReceiverCheckpoint, ReceiverCheckpoint, ReceiverCheckpoint) {
        let hello = Hello {
            nonce: [9; 32],
            epoch_bytes: 8,
            max_bytes: 64,
        };
        let start = ReceiverCheckpoint {
            client: NativeClientCertificateId::from_sha256([3; 32]),
            offered: offer(&hello).try_into().unwrap(),
            agreed: offer(&hello).try_into().unwrap(),
            prefix: initial(&hello),
            prefix_hash: digest(&Sha256::new()),
            pending_hash: digest(&Sha256::new()),
            used: 1,
            maximum: 4,
            phase: ReceiverCheckpointPhase::Receiving,
            pending: Zeroizing::new(Vec::new()),
        };
        let mut pending = start.clone();
        pending.pending = Zeroizing::new(encode_epoch(&start.prefix, b"abcdefgh"));
        pending.pending_hash = Sha256::digest(b"abcdefgh").into();
        let mut stable = pending.clone();
        stable.prefix = advance(&start.prefix, &pending.pending, 8, 64).unwrap();
        stable.prefix_hash = pending.pending_hash;
        stable.pending = Zeroizing::new(Vec::new());
        (start, pending, stable)
    }
    fn append_data(store: &ReceiverJournalFile, bytes: &[u8]) {
        (&store.storage.data).write_all(bytes).unwrap();
        store.storage.data.sync_all().unwrap();
    }

    fn finalizing_files(
        limits: ReceiverFileLimits,
        empty: bool,
    ) -> (PathBuf, PathBuf, LiveStreamReceipt) {
        let (journal, data) = files();
        let (start, pending, stable) = checkpoints();
        let store = ReceiverJournalFile::create_new(&journal, &data, limits).unwrap();
        store.storage.append(start.clone()).unwrap();
        let mut finalizing = if empty {
            start
        } else {
            store.storage.append(pending).unwrap();
            append_data(&store, b"abcdefgh");
            store.storage.append(stable.clone()).unwrap();
            stable
        };
        finalizing.phase = ReceiverCheckpointPhase::Finalizing;
        store.storage.append(finalizing.clone()).unwrap();
        (journal, data, finalizing.receipt())
    }

    #[test]
    fn resolve_finalizing_revalidates_and_records_completion_without_replacing_files() {
        for empty in [false, true] {
            let (journal, data, expected) = finalizing_files(limits(), empty);
            let history = std::fs::read(&journal).unwrap();
            let payload = std::fs::read(&data).unwrap();
            let journal_inode = std::fs::metadata(&journal).unwrap().ino();
            let data_inode = std::fs::metadata(&data).unwrap().ino();
            let mut store = ReceiverJournalFile::open_existing(&journal, &data).unwrap();
            let before = store.checkpoint().unwrap();
            let observer = store.observer();
            assert_eq!(before.phase(), ReceiverCheckpointPhase::Finalizing);
            assert!(before.committed_receipt().is_none());
            let records = store.storage.state.lock().records;
            assert_eq!(store.resolve_finalizing().unwrap(), expected);
            assert_eq!(store.storage.state.lock().records, records + 1);
            let saved = store.checkpoint().unwrap();
            assert_eq!(saved.phase(), ReceiverCheckpointPhase::Committed);
            assert_eq!(saved.committed_receipt(), Some(expected.clone()));
            assert_eq!(saved.attempts(), before.attempts());
            assert_eq!(saved.maximum_attempts(), before.maximum_attempts());
            assert_eq!(
                observer.checkpoint().unwrap().committed_receipt(),
                Some(expected.clone())
            );
            let committed_history = std::fs::read(&journal).unwrap();
            assert!(committed_history.starts_with(&history));
            assert!(committed_history.len() > history.len());
            assert_eq!(store.resolve_finalizing().unwrap(), expected);
            assert_eq!(std::fs::read(&journal).unwrap(), committed_history);
            assert_eq!(store.storage.state.lock().records, records + 1);
            assert_eq!(std::fs::read(&data).unwrap(), payload);
            assert_eq!(std::fs::metadata(&journal).unwrap().ino(), journal_inode);
            assert_eq!(std::fs::metadata(&data).unwrap().ino(), data_inode);
            drop(store);
            let reopened = ReceiverJournalFile::open_existing(&journal, &data).unwrap();
            assert_eq!(
                reopened.checkpoint().unwrap().committed_receipt(),
                Some(expected)
            );
            // Ordinary handoff still rejects Finalizing, but this durable
            // completion is eligible for authenticated Proof-only restoration.
            let session = reopened.service_session().unwrap();
            assert_eq!(std::fs::read(&journal).unwrap(), committed_history);
            assert!(ReceiverJournalFile::open_existing(&journal, &data).is_err());
            drop(session);
        }
    }

    #[test]
    fn resolve_finalizing_refuses_modified_data_length_and_replaced_identity() {
        for corruption in ["hash", "short", "extra", "inode", "link"] {
            let (journal, data, _) = finalizing_files(limits(), false);
            let history = std::fs::read(&journal).unwrap();
            let mut store = ReceiverJournalFile::open_existing(&journal, &data).unwrap();
            match corruption {
                "hash" => {
                    let mut file = OpenOptions::new().write(true).open(&data).unwrap();
                    file.write_all(b"X").unwrap();
                    file.sync_all().unwrap();
                }
                "short" => {
                    let file = OpenOptions::new().write(true).open(&data).unwrap();
                    file.set_len(4).unwrap();
                    file.sync_all().unwrap();
                }
                "extra" => append_data(&store, b"X"),
                "inode" => {
                    std::fs::rename(&data, data.with_extension("retained-original")).unwrap();
                    let mut replacement = OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(&data)
                        .unwrap();
                    replacement.write_all(b"abcdefgh").unwrap();
                    replacement.sync_all().unwrap();
                }
                "link" => std::fs::hard_link(&data, data.with_extension("second-link")).unwrap(),
                _ => unreachable!(),
            }
            assert_eq!(
                store.resolve_finalizing().unwrap_err().kind(),
                io::ErrorKind::InvalidData,
                "{corruption}"
            );
            assert_eq!(std::fs::read(&journal).unwrap(), history, "{corruption}");
            assert_eq!(
                store.observer().checkpoint().unwrap().phase(),
                ReceiverCheckpointPhase::Finalizing
            );
        }
    }

    #[test]
    fn resolve_finalizing_requires_intent_and_confirmed_journal_ownership() {
        let (journal, data) = files();
        let (start, _, _) = checkpoints();
        let store = ReceiverJournalFile::create_new(&journal, &data, limits()).unwrap();
        store.storage.append(start).unwrap();
        drop(store);
        let mut store = ReceiverJournalFile::open_existing(&journal, &data).unwrap();
        let history = std::fs::read(&journal).unwrap();
        assert_eq!(
            store.resolve_finalizing().unwrap_err().to_string(),
            "receiver has no final commit intent"
        );
        assert_eq!(std::fs::read(&journal).unwrap(), history);

        let (journal, data, _) = finalizing_files(limits(), false);
        let mut store = ReceiverJournalFile::open_existing(&journal, &data).unwrap();
        let history = std::fs::read(&journal).unwrap();
        // A pending checkpoint owns the storage operation. Resolution must not
        // run concurrently with it or discard a dropped wait's pending result.
        store.pending = Some(Box::pin(std::future::pending()));
        assert_eq!(
            store.resolve_finalizing().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(std::fs::read(&journal).unwrap(), history);
        drop(store);

        let mut store = ReceiverJournalFile::open_existing(&journal, &data).unwrap();
        let mut external = OpenOptions::new().append(true).open(&journal).unwrap();
        external.write_all(&[0]).unwrap();
        external.sync_all().unwrap();
        let modified = std::fs::read(&journal).unwrap();
        assert_eq!(
            store.resolve_finalizing().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(std::fs::read(&journal).unwrap(), modified);
        store.storage.state.lock().poisoned = true;
        assert_eq!(
            store.resolve_finalizing().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(std::fs::read(&journal).unwrap(), modified);
    }

    #[test]
    fn resolve_finalizing_cannot_claim_completion_when_the_terminal_record_does_not_fit() {
        let (journal, data, _) = finalizing_files(
            ReceiverFileLimits {
                max_snapshots: 4,
                ..limits()
            },
            false,
        );
        let history = std::fs::read(&journal).unwrap();
        let mut store = ReceiverJournalFile::open_existing(&journal, &data).unwrap();
        assert_eq!(store.storage.state.lock().records, 4);
        assert_eq!(
            store.resolve_finalizing().unwrap_err().kind(),
            io::ErrorKind::StorageFull
        );
        assert_eq!(
            store.checkpoint().unwrap_err().kind(),
            io::ErrorKind::StorageFull
        );
        assert_eq!(
            store.observer().checkpoint().unwrap().phase(),
            ReceiverCheckpointPhase::Finalizing
        );
        assert_eq!(std::fs::read(&journal).unwrap(), history);
        assert_eq!(std::fs::read(&data).unwrap(), b"abcdefgh");
        drop(store);
        let mut reopened = ReceiverJournalFile::open_existing(&journal, &data).unwrap();
        assert_eq!(
            reopened.checkpoint().unwrap().phase(),
            ReceiverCheckpointPhase::Finalizing
        );
        assert_eq!(
            reopened.resolve_finalizing().unwrap_err().kind(),
            io::ErrorKind::StorageFull
        );
        assert_eq!(std::fs::read(&journal).unwrap(), history);
    }

    #[test]
    fn exact_inode_and_pending_intent_survive_reopen_with_partial_data() {
        let (journal, data) = files();
        let (start, pending, stable) = checkpoints();
        let store = ReceiverJournalFile::create_new(&journal, &data, limits()).unwrap();
        store.storage.append(start).unwrap();
        store.storage.append(pending.clone()).unwrap();
        append_data(&store, b"abc");
        assert!(ReceiverJournalFile::open_existing(&journal, &data).is_err());
        let before = std::fs::read(&journal).unwrap();
        let inode = std::fs::metadata(&data).unwrap().ino();
        drop(store);
        let reopened = ReceiverJournalFile::open_existing(&journal, &data).unwrap();
        assert_eq!(
            reopened
                .checkpoint()
                .unwrap()
                .to_canonical_bytes()
                .unwrap()
                .as_slice(),
            pending.to_canonical_bytes().unwrap().as_slice()
        );
        assert_eq!(std::fs::read(&data).unwrap(), b"abc");
        append_data(&reopened, b"defgh");
        reopened.storage.append(stable).unwrap();
        drop(reopened);
        let complete = ReceiverJournalFile::open_existing(&journal, &data).unwrap();
        assert_eq!(complete.checkpoint().unwrap().prefix().bytes, 8);
        assert_eq!(std::fs::metadata(&data).unwrap().ino(), inode);
        assert_eq!(std::fs::read(&data).unwrap(), b"abcdefgh");
        assert!(std::fs::read(&journal).unwrap().starts_with(&before));
    }

    #[test]
    fn snapshot_exhaustion_is_persistent_and_identical_records_are_idempotent() {
        let (journal, data) = files();
        let (start, pending, _) = checkpoints();
        let store = ReceiverJournalFile::create_new(
            &journal,
            &data,
            ReceiverFileLimits {
                max_snapshots: 1,
                ..limits()
            },
        )
        .unwrap();
        store.storage.append(start.clone()).unwrap();
        let bytes = std::fs::read(&journal).unwrap();
        store.storage.append(start).unwrap();
        assert_eq!(std::fs::read(&journal).unwrap(), bytes);
        assert_eq!(
            store.storage.append(pending.clone()).unwrap_err().kind(),
            io::ErrorKind::StorageFull
        );
        drop(store);
        let reopened = ReceiverJournalFile::open_existing(&journal, &data).unwrap();
        assert_eq!(
            reopened.storage.append(pending).unwrap_err().kind(),
            io::ErrorKind::StorageFull
        );
        assert_eq!(std::fs::read(&journal).unwrap(), bytes);
        assert_eq!(std::fs::metadata(&data).unwrap().len(), 0);
    }

    #[test]
    fn a_device_number_changed_by_a_reboot_does_not_refuse_recovery() {
        let (journal, data) = files();
        let (start, _, _) = checkpoints();
        let store = ReceiverJournalFile::create_new(&journal, &data, limits()).unwrap();
        store.storage.append(start).unwrap();
        drop(store);
        // Change both recorded device numbers, then reseal the header and the
        // record chain the way a writer before the reboot would have sealed
        // them.
        let mut bytes = std::fs::read(&journal).unwrap();
        bytes[39] ^= 1;
        bytes[55] ^= 1;
        let mut previous = hash(&[], &bytes[..64]);
        bytes[64..HEADER].copy_from_slice(&previous);
        let mut at = HEADER;
        while at < bytes.len() {
            let size = u32::from_be_bytes(bytes[at + 8..at + 12].try_into().unwrap()) as usize;
            let end = at + 16 + size;
            previous = hash(&previous, &bytes[at..end]);
            bytes[end..end + 32].copy_from_slice(&previous);
            at = end + 32;
        }
        std::fs::write(&journal, &bytes).unwrap();
        let reopened = ReceiverJournalFile::open_existing(&journal, &data)
            .expect("the recorded inodes still match");
        assert_eq!(reopened.checkpoint().unwrap().prefix().bytes, 0);
    }

    #[test]
    fn torn_history_and_inode_replacement_are_refused_without_repairs() {
        let (journal, data) = files();
        let (start, _, _) = checkpoints();
        let store = ReceiverJournalFile::create_new(&journal, &data, limits()).unwrap();
        store.storage.append(start).unwrap();
        drop(store);
        let pristine = std::fs::read(&journal).unwrap();
        let broken = journal.with_extension("torn");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&broken)
            .unwrap();
        file.write_all(&pristine).unwrap();
        file.write_all(&[0]).unwrap();
        drop(file);
        assert!(ReceiverJournalFile::open_existing(&broken, &data).is_err());
        assert_eq!(std::fs::read(&broken).unwrap().len(), pristine.len() + 1);
        let other = data.with_extension("other");
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&other)
            .unwrap();
        assert!(ReceiverJournalFile::open_existing(&journal, &other).is_err());
        let alias = data.with_extension("alias");
        std::os::unix::fs::symlink(&data, &alias).unwrap();
        assert!(ReceiverJournalFile::open_existing(&journal, &alias).is_err());
        assert_eq!(std::fs::read(&journal).unwrap(), pristine);
    }

    #[test]
    fn uncertain_append_is_sticky_and_commit_cannot_skip_its_intent_record() {
        let (journal, data) = files();
        let (start, pending, _) = checkpoints();
        let store = ReceiverJournalFile::create_new(&journal, &data, limits()).unwrap();
        store.storage.append(start.clone()).unwrap();
        let mut committed = start.clone();
        committed.phase = ReceiverCheckpointPhase::Committed;
        assert!(store.storage.append(committed).is_err());
        let mut external = OpenOptions::new().append(true).open(&journal).unwrap();
        external.write_all(&[0]).unwrap();
        external.sync_all().unwrap();
        assert!(store.storage.append(pending).is_err());
        assert!(store.storage.append(start).is_err());
        assert!(store.storage.state.lock().poisoned);
        assert_eq!(std::fs::metadata(&data).unwrap().len(), 0);
    }

    #[test]
    fn shared_factory_handoff_keeps_both_locks_without_writing_or_binding() {
        let (journal, data) = files();
        let store = ReceiverJournalFile::create_new(&journal, &data, limits()).unwrap();
        let before = std::fs::read(&journal).unwrap();
        let session = store.service_session().unwrap();
        assert_eq!(std::fs::read(&journal).unwrap(), before);
        assert_eq!(std::fs::metadata(&data).unwrap().len(), 0);
        for path in [&journal, &data] {
            let other = OpenOptions::new().read(true).write(true).open(path).unwrap();
            assert!(other.try_lock().is_err());
        }
        drop(session);
        for path in [&journal, &data] {
            let other = OpenOptions::new().read(true).write(true).open(path).unwrap();
            assert!(other.try_lock().is_ok());
        }
        assert_eq!(std::fs::read(&journal).unwrap(), before);
    }

    #[test]
    fn shared_handoff_retains_history_and_refuses_uncertain_or_unrecorded_state() {
        let (journal, data) = files();
        let (start, pending, _) = checkpoints();
        let store = ReceiverJournalFile::create_new(&journal, &data, limits()).unwrap();
        store.storage.append(start).unwrap();
        store.storage.append(pending).unwrap();
        append_data(&store, b"abc");
        drop(store);
        let before = std::fs::read(&journal).unwrap();
        let reopened = ReceiverJournalFile::open_existing(&journal, &data).unwrap();
        let session = reopened.service_session().unwrap();
        assert_eq!(std::fs::read(&journal).unwrap(), before);
        assert_eq!(std::fs::read(&data).unwrap(), b"abc");
        assert!(ReceiverJournalFile::open_existing(&journal, &data).is_err());
        drop(session);

        let (journal, data) = files();
        let (start, _, _) = checkpoints();
        let store = ReceiverJournalFile::create_new(&journal, &data, limits()).unwrap();
        store.storage.append(start.clone()).unwrap();
        let mut uncertain = start;
        uncertain.phase = ReceiverCheckpointPhase::Finalizing;
        store.storage.append(uncertain).unwrap();
        drop(store);
        let before = std::fs::read(&journal).unwrap();
        assert!(ReceiverJournalFile::open_existing(&journal, &data).unwrap().service_session().is_err());
        assert_eq!(std::fs::read(&journal).unwrap(), before);

        let (journal, data) = files();
        let store = ReceiverJournalFile::create_new(&journal, &data, limits()).unwrap();
        append_data(&store, b"unrecorded");
        assert!(store.service_session().is_err());
        assert_eq!(std::fs::read(&data).unwrap(), b"unrecorded");
    }

    #[test]
    fn observer_is_nonblocking_nonowning_and_distinguishes_commit_intent() {
        let (journal, data) = files();
        let store = ReceiverJournalFile::create_new(&journal, &data, limits()).unwrap();
        let observer = store.observer();
        let copy = observer.clone();
        assert_eq!(observer.checkpoint().unwrap_err().kind(), io::ErrorKind::WouldBlock);
        let (start, _, _) = checkpoints();
        store.storage.append(start.clone()).unwrap();
        let snapshot = observer.checkpoint().unwrap();
        assert_eq!(snapshot.prefix().bytes, 0);
        assert!(snapshot.committed_receipt().is_none());
        {
            // Calling from the thread that already owns this lock must not deadlock.
            let _updating = store.storage.state.lock();
            assert_eq!(copy.checkpoint().unwrap_err().kind(), io::ErrorKind::WouldBlock);
        }
        let mut finalizing = start;
        finalizing.phase = ReceiverCheckpointPhase::Finalizing;
        store.storage.append(finalizing.clone()).unwrap();
        assert_eq!(observer.checkpoint().unwrap().phase(), ReceiverCheckpointPhase::Finalizing);
        assert!(observer.checkpoint().unwrap().committed_receipt().is_none());
        store.storage.commit(&finalizing.receipt()).unwrap();
        let mut committed = finalizing;
        committed.phase = ReceiverCheckpointPhase::Committed;
        store.storage.append(committed.clone()).unwrap();
        let confirmed = copy.checkpoint().unwrap();
        assert_eq!(confirmed.committed_receipt(), committed.committed_receipt());
        let history = std::fs::read(&journal).unwrap();
        assert!(!format!("{observer:?}").contains("receiver.wal"));
        drop(store);
        assert_eq!(observer.checkpoint().unwrap_err().kind(), io::ErrorKind::NotConnected);
        assert_eq!(copy.checkpoint().unwrap_err().kind(), io::ErrorKind::NotConnected);
        // Neither observers nor returned snapshots keep the original locks alive.
        for path in [&journal, &data] {
            assert!(OpenOptions::new().read(true).write(true).open(path).unwrap().try_lock().is_ok());
        }
        assert_eq!(std::fs::read(&journal).unwrap(), history);
        assert_eq!(confirmed.phase(), ReceiverCheckpointPhase::Committed);
        assert_eq!(snapshot.phase(), ReceiverCheckpointPhase::Receiving);
    }

    #[test]
    fn observer_refuses_unconfirmed_persistence_without_fabricating_a_new_snapshot() {
        let (journal, data) = files();
        let store = ReceiverJournalFile::create_new(&journal, &data, limits()).unwrap();
        let observer = store.observer();
        let (start, pending, _) = checkpoints();
        store.storage.append(start).unwrap();
        let prior = observer.checkpoint().unwrap();
        let mut corruptor = OpenOptions::new().append(true).open(&journal).unwrap();
        corruptor.write_all(&[0]).unwrap();
        corruptor.sync_all().unwrap();
        assert!(store.storage.append(pending).is_err());
        assert!(store.storage.state.lock().poisoned);
        assert_eq!(observer.checkpoint().unwrap_err().kind(), io::ErrorKind::Other);
        assert_eq!(prior.pending_bytes(), 0);
        assert!(prior.committed_receipt().is_none());
        assert_eq!(std::fs::metadata(&data).unwrap().len(), 0);
    }

    fn compact_limits() -> ReceiverCompactFileLimits {
        ReceiverCompactFileLimits {
            max_data_bytes: 64,
            max_snapshots: 32,
            max_journal_bytes: 65_536,
        }
    }

    fn compact_epoch(
        previous: &ReceiverCheckpoint,
        bytes: &[u8],
        hash: &mut Sha256,
    ) -> (ReceiverCheckpoint, ReceiverCheckpoint) {
        let agreed = super::super::decode_offer(&previous.agreed).unwrap();
        let mut pending = previous.clone();
        pending.pending = Zeroizing::new(encode_epoch(&previous.prefix, bytes));
        hash.update(bytes);
        pending.pending_hash = digest(hash);
        let mut stable = pending.clone();
        stable.prefix = advance(
            &previous.prefix,
            &pending.pending,
            agreed.epoch_bytes,
            agreed.max_bytes,
        )
        .unwrap();
        stable.prefix_hash = pending.pending_hash;
        stable.pending = Zeroizing::new(Vec::new());
        (pending, stable)
    }

    #[test]
    fn compact_default_budgets_cover_four_gib_of_full_epochs_without_payload_history() {
        let limits = ReceiverCompactFileLimits::default();
        limits.validate().unwrap();
        let hello = Hello {
            nonce: [9; 32],
            epoch_bytes: 65_536,
            max_bytes: 4 * 1024 * 1024 * 1024,
        };
        let mut start = checkpoints().0;
        start.offered = offer(&hello).try_into().unwrap();
        start.agreed = start.offered;
        start.prefix = initial(&hello);
        let (pending, stable) = compact_epoch(&start, &vec![42; 65_536], &mut Sha256::new());
        let start_bytes = compact::encode(&start.to_canonical_bytes().unwrap()).unwrap();
        let pending_bytes = compact::encode(&pending.to_canonical_bytes().unwrap()).unwrap();
        let stable_bytes = compact::encode(&stable.to_canonical_bytes().unwrap()).unwrap();
        assert_eq!(pending.to_canonical_bytes().unwrap().len(), 65_933);
        assert_eq!(pending_bytes.len(), 429);
        assert_eq!(stable_bytes.len(), 317);
        let epochs = hello.max_bytes / hello.epoch_bytes as u64;
        let snapshots = 2 * epochs + 3;
        let wal_bytes = compact::HEADER as u64
            + epochs * (pending_bytes.len() + stable_bytes.len() + 96) as u64
            + 3 * (start_bytes.len() + 48) as u64;
        assert_eq!(snapshots, 131_075);
        assert_eq!(wal_bytes, 55_182_535);
        assert!(snapshots <= u64::from(limits.max_snapshots));
        assert!(wal_bytes <= limits.max_journal_bytes);
        assert_eq!(compact::INTENT_BYTES, 131_328);
        // The legacy limits and V1 admission remain unchanged.
        assert!(limits.storage_limits().validate().is_err());
    }

    #[test]
    fn compact_history_rehydrates_after_both_slots_are_reused_and_rejects_changed_old_data() {
        let (journal, data) = files();
        let intent = data.with_extension("intent");
        let store =
            ReceiverJournalFile::create_new_compact(&journal, &data, &intent, compact_limits())
                .unwrap();
        let mut stable = checkpoints().0;
        store.storage.append(stable.clone()).unwrap();
        let mut hash = Sha256::new();
        let mut content = Vec::new();
        for epoch in 0..8_u8 {
            let bytes = [epoch + 1; 8];
            let (pending, next) = compact_epoch(&stable, &bytes, &mut hash);
            store.storage.append(pending).unwrap();
            append_data(&store, &bytes);
            store.storage.append(next.clone()).unwrap();
            content.extend_from_slice(&bytes);
            stable = next;
        }
        let inodes: Vec<_> = [&journal, &data, &intent]
            .iter()
            .map(|path| std::fs::metadata(path).unwrap().ino())
            .collect();
        stable.phase = ReceiverCheckpointPhase::Finalizing;
        store.storage.append(stable.clone()).unwrap();
        drop(store);
        let history = std::fs::read(&journal).unwrap();
        let mut reopened =
            ReceiverJournalFile::open_existing_compact(&journal, &data, &intent).unwrap();
        assert_eq!(reopened.checkpoint().unwrap().prefix().bytes, 64);
        assert_eq!(reopened.checkpoint().unwrap().attempts(), 1);
        assert_eq!(reopened.resolve_finalizing().unwrap(), stable.receipt());
        assert_eq!(std::fs::read(&data).unwrap(), content);
        assert!(std::fs::read(&journal).unwrap().starts_with(&history));
        for (path, inode) in [&journal, &data, &intent].iter().zip(inodes) {
            assert_eq!(std::fs::metadata(path).unwrap().ino(), inode);
        }
        assert_eq!(std::fs::metadata(&intent).unwrap().len(), 131_328);
        drop(reopened);
        assert!(ReceiverJournalFile::open_existing(&journal, &data).is_err());

        // Epoch zero's slot has been overwritten several times. Its original
        // data bytes must still match the commitment in its historical record.
        let history = std::fs::read(&journal).unwrap();
        let mut corruptor = OpenOptions::new().write(true).open(&data).unwrap();
        corruptor.write_all(b"X").unwrap();
        corruptor.sync_all().unwrap();
        assert_eq!(
            ReceiverJournalFile::open_existing_compact(&journal, &data, &intent)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(std::fs::read(&journal).unwrap(), history);
    }

    #[test]
    fn compact_pending_slots_restore_every_surviving_tail_and_keep_all_three_locks() {
        for surviving in 0..=8 {
            let (journal, data) = files();
            let intent = data.with_extension("intent");
            let (start, pending, _) = checkpoints();
            let store =
                ReceiverJournalFile::create_new_compact(&journal, &data, &intent, compact_limits())
                    .unwrap();
            store.storage.append(start).unwrap();
            store.storage.append(pending.clone()).unwrap();
            append_data(&store, &b"abcdefgh"[..surviving]);
            let history = std::fs::read(&journal).unwrap();
            drop(store);
            let reopened =
                ReceiverJournalFile::open_existing_compact(&journal, &data, &intent).unwrap();
            assert_eq!(
                reopened.checkpoint().unwrap().to_canonical_bytes().unwrap().as_slice(),
                pending.to_canonical_bytes().unwrap().as_slice()
            );
            let session = reopened.service_session().unwrap();
            for path in [&journal, &data, &intent] {
                assert!(
                    OpenOptions::new().read(true).write(true).open(path).unwrap().try_lock().is_err()
                );
            }
            assert_eq!(std::fs::read(&data).unwrap(), b"abcdefgh"[..surviving]);
            assert_eq!(std::fs::read(&journal).unwrap(), history);
            drop(session);
            for path in [&journal, &data, &intent] {
                assert!(
                    OpenOptions::new().read(true).write(true).open(path).unwrap().try_lock().is_ok()
                );
            }
        }
    }

    #[test]
    fn compact_prepared_or_torn_next_slot_does_not_erase_the_last_checkpoint() {
        for torn in [false, true] {
            let (journal, data) = files();
            let intent = data.with_extension("intent");
            let (start, pending, stable) = checkpoints();
            let store =
                ReceiverJournalFile::create_new_compact(&journal, &data, &intent, compact_limits())
                    .unwrap();
            store.storage.append(start).unwrap();
            store.storage.append(pending).unwrap();
            append_data(&store, b"abcdefgh");
            store.storage.append(stable.clone()).unwrap();
            let history = std::fs::read(&journal).unwrap();
            let slots = std::fs::read(&intent).unwrap();
            let mut hash = Sha256::new();
            hash.update(b"abcdefgh");
            let (next, _) = compact_epoch(&stable, b"ijklmnop", &mut hash);
            // The precise boundary is after next-slot synchronization and
            // before its intent WAL append. A process death loses only that
            // unrecorded preparation; the completed prefix remains authoritative.
            store.storage.intent.as_ref().unwrap().stage(&next).unwrap();
            if torn {
                let mut corruptor = OpenOptions::new().write(true).open(&intent).unwrap();
                corruptor.seek(SeekFrom::Start((compact::INTENT_BYTES / 2) as u64)).unwrap();
                corruptor.write_all(b"torn").unwrap();
                corruptor.sync_all().unwrap();
            }
            assert_eq!(
                &std::fs::read(&intent).unwrap()[..compact::INTENT_BYTES / 2],
                &slots[..compact::INTENT_BYTES / 2]
            );
            drop(store);
            let reopened =
                ReceiverJournalFile::open_existing_compact(&journal, &data, &intent).unwrap();
            assert_eq!(
                reopened.checkpoint().unwrap().to_canonical_bytes().unwrap().as_slice(),
                stable.to_canonical_bytes().unwrap().as_slice()
            );
            assert_eq!(std::fs::read(&journal).unwrap(), history);
            assert_eq!(std::fs::read(&data).unwrap(), b"abcdefgh");
        }
    }

    #[test]
    fn compact_retry_and_persistent_quotas_never_rewrite_the_active_pending_slot() {
        for snapshot_limit in [false, true] {
            let (journal, data) = files();
            let intent = data.with_extension("intent");
            let (start, pending, _) = checkpoints();
            let limits = ReceiverCompactFileLimits {
                max_snapshots: if snapshot_limit { 3 } else { 32 },
                max_journal_bytes: if snapshot_limit { 65_536 } else { 128 + 365 + 2 * 477 },
                ..compact_limits()
            };
            let store =
                ReceiverJournalFile::create_new_compact(&journal, &data, &intent, limits).unwrap();
            store.storage.append(start).unwrap();
            store.storage.append(pending.clone()).unwrap();
            append_data(&store, b"abc");
            let slots = std::fs::read(&intent).unwrap();
            let mut retry = pending;
            retry.used = 2;
            store.storage.append(retry.clone()).unwrap();
            let history = std::fs::read(&journal).unwrap();
            store.storage.append(retry.clone()).unwrap();
            assert_eq!(std::fs::read(&journal).unwrap(), history);
            assert_eq!(std::fs::read(&intent).unwrap(), slots);
            retry.used = 3;
            assert_eq!(store.storage.append(retry.clone()).unwrap_err().kind(), io::ErrorKind::StorageFull);
            drop(store);
            let reopened =
                ReceiverJournalFile::open_existing_compact(&journal, &data, &intent).unwrap();
            assert_eq!(reopened.checkpoint().unwrap().attempts(), 2);
            assert_eq!(reopened.storage.append(retry).unwrap_err().kind(), io::ErrorKind::StorageFull);
            assert_eq!(std::fs::read(&journal).unwrap(), history);
            assert_eq!(std::fs::read(&intent).unwrap(), slots);
            assert_eq!(std::fs::read(&data).unwrap(), b"abc");
        }
    }

    #[test]
    fn compact_partial_recovery_refuses_corrupt_or_replaced_intent_without_repair() {
        for damage in ["payload", "short", "inode", "link", "permissions"] {
            let (journal, data) = files();
            let intent = data.with_extension("intent");
            let (start, pending, _) = checkpoints();
            let store =
                ReceiverJournalFile::create_new_compact(&journal, &data, &intent, compact_limits())
                    .unwrap();
            store.storage.append(start).unwrap();
            store.storage.append(pending).unwrap();
            append_data(&store, b"abc");
            let slots = std::fs::read(&intent).unwrap();
            let history = std::fs::read(&journal).unwrap();
            drop(store);
            match damage {
                "payload" => {
                    let mut file = OpenOptions::new().write(true).open(&intent).unwrap();
                    file.seek(SeekFrom::Start(48 + 80 + 4)).unwrap();
                    file.write_all(b"X").unwrap();
                    file.sync_all().unwrap();
                }
                "short" => {
                    let file = OpenOptions::new().write(true).open(&intent).unwrap();
                    file.set_len(131_327).unwrap();
                    file.sync_all().unwrap();
                }
                "inode" => {
                    std::fs::rename(&intent, intent.with_extension("retained-original")).unwrap();
                    let mut replacement = OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(&intent)
                        .unwrap();
                    replacement.write_all(&slots).unwrap();
                    replacement.sync_all().unwrap();
                }
                "link" => std::fs::hard_link(&intent, intent.with_extension("second-link")).unwrap(),
                "permissions" => {
                    std::fs::set_permissions(&intent, std::fs::Permissions::from_mode(0o640)).unwrap();
                }
                _ => unreachable!(),
            }
            assert_eq!(
                ReceiverJournalFile::open_existing_compact(&journal, &data, &intent)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidData,
                "{damage}"
            );
            assert_eq!(std::fs::read(&journal).unwrap(), history, "{damage}");
            assert_eq!(std::fs::read(&data).unwrap(), b"abc", "{damage}");
        }
    }

    #[test]
    fn compact_torn_reused_payload_falls_back_to_durable_history_and_continues() {
        let (journal, data) = files();
        let intent = data.with_extension("intent");
        let store =
            ReceiverJournalFile::create_new_compact(&journal, &data, &intent, compact_limits())
                .unwrap();
        let mut stable = checkpoints().0;
        store.storage.append(stable.clone()).unwrap();
        let mut hash = Sha256::new();
        for bytes in [b"abcdefgh", b"ijklmnop"] {
            let (pending, next) = compact_epoch(&stable, bytes, &mut hash);
            store.storage.append(pending).unwrap();
            append_data(&store, bytes);
            store.storage.append(next.clone()).unwrap();
            stable = next;
        }
        let history = std::fs::read(&journal).unwrap();
        let slots = std::fs::read(&intent).unwrap();
        let (pending, next) = compact_epoch(&stable, b"qrstuvwx", &mut hash);
        store.storage.intent.as_ref().unwrap().stage(&pending).unwrap();
        // Model torn sector persistence during epoch two's reuse of slot zero:
        // retain epoch zero's matching header/checksum and epoch header, but
        // leave the new payload underneath. No epoch-two intent record exists.
        let mut torn = OpenOptions::new().write(true).open(&intent).unwrap();
        torn.write_all(&slots[..48 + 80]).unwrap();
        torn.sync_all().unwrap();
        let mixed = std::fs::read(&intent).unwrap();
        assert_eq!(&mixed[..48 + 80], &slots[..48 + 80]);
        assert_ne!(&mixed[48 + 80..48 + 88], &slots[48 + 80..48 + 88]);
        assert_eq!(std::fs::read(&journal).unwrap(), history);
        drop(torn);
        drop(store);

        let reopened =
            ReceiverJournalFile::open_existing_compact(&journal, &data, &intent).unwrap();
        assert_eq!(
            reopened.checkpoint().unwrap().to_canonical_bytes().unwrap().as_slice(),
            stable.to_canonical_bytes().unwrap().as_slice()
        );
        assert_eq!(std::fs::read(&data).unwrap(), b"abcdefghijklmnop");
        assert_eq!(std::fs::read(&journal).unwrap(), history);
        // The next admitted epoch can reuse the unrecorded slot and continue.
        reopened.storage.append(pending).unwrap();
        append_data(&reopened, b"qrstuvwx");
        reopened.storage.append(next).unwrap();
        drop(reopened);
        let restored =
            ReceiverJournalFile::open_existing_compact(&journal, &data, &intent).unwrap();
        assert_eq!(restored.checkpoint().unwrap().prefix().bytes, 24);
        assert_eq!(std::fs::read(&data).unwrap(), b"abcdefghijklmnopqrstuvwx");
        assert!(std::fs::read(&journal).unwrap().starts_with(&history));
    }
}
