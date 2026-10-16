//! Bounded append-only Unix storage for write-ahead sender checkpoints.
//!
//! Each complete record is synchronized before the sender may transmit its
//! pending epoch. Reopening validates every record and legal transition, keeping
//! only the latest snapshot. Torn tails are refused, never repaired or ignored.
//! Protect this file and its ancestors against deletion, replacement and rollback.

use super::{MAX_SENDER_CHECKPOINT_BYTES, SenderCheckpoint, SenderCheckpointStore};
use crate::runtime::spawn_blocking_io;
use parking_lot::Mutex;
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::{File, OpenOptions};
use std::future::Future;
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"ATPSJL01";
const HEADER: usize = 48;
const BODY: usize = 688;
const RECORD: usize = BODY + 32;
/// Maximum lifetime snapshots in one journal. Identical snapshots use no slot.
pub const MAX_SENDER_JOURNAL_SNAPSHOTS: u32 = 65_536;

type Persist = Pin<Box<dyn Future<Output = io::Result<u32>> + Send>>;
type Failure = (io::ErrorKind, Option<i32>);

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid sender checkpoint journal",
    )
}

fn checksum(previous: &[u8], body: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"asupersync.atp.sender-journal.v1");
    hash.update(previous);
    hash.update(body);
    hash.finalize().into()
}

fn restore_error((kind, raw): Failure) -> io::Error {
    raw.map_or_else(|| io::Error::from(kind), io::Error::from_raw_os_error)
}

struct State {
    file: File,
    records: u32,
    previous: [u8; 32],
    latest: Option<SenderCheckpoint>,
    poisoned: bool,
}

struct Storage {
    path: PathBuf,
    directory: File,
    maximum: u32,
    state: Mutex<State>,
}

impl Storage {
    fn open(path: &Path, create: Option<u32>) -> io::Result<Self> {
        if !path.is_absolute()
            || create.is_some_and(|maximum| !(1..=MAX_SENDER_JOURNAL_SNAPSHOTS).contains(&maximum))
        {
            return Err(invalid());
        }
        let name = path.file_name().ok_or_else(invalid)?;
        let parent = path.parent().ok_or_else(invalid)?;
        let metadata = std::fs::symlink_metadata(parent)?;
        if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
            return Err(invalid());
        }
        let parent = std::fs::canonicalize(parent)?;
        let directory = File::open(&parent)?;
        let path = parent.join(name);
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(create.is_some())
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&path)?;
        file.try_lock().map_err(io::Error::from)?;
        Self::verify(&path, &directory, &file)?;
        let mut header = [0; HEADER];
        if let Some(maximum) = create {
            header[..8].copy_from_slice(MAGIC);
            header[8..12].copy_from_slice(&maximum.to_be_bytes());
            let hash = checksum(&[], &header[..16]);
            header[16..].copy_from_slice(&hash);
            file.write_all(&header)?;
        } else {
            file.read_exact(&mut header)?;
        }
        let maximum = u32::from_be_bytes(header[8..12].try_into().expect("fixed header"));
        let length = file.metadata()?.len();
        if &header[..8] != MAGIC
            || header[12..16] != [0; 4]
            || header[16..] != checksum(&[], &header[..16])
            || !(1..=MAX_SENDER_JOURNAL_SNAPSHOTS).contains(&maximum)
            || length < HEADER as u64
            || (length - HEADER as u64) % RECORD as u64 != 0
            || length > HEADER as u64 + u64::from(maximum) * RECORD as u64
        {
            return Err(invalid());
        }
        let records = ((length - HEADER as u64) / RECORD as u64) as u32;
        let mut previous: [u8; 32] = header[16..].try_into().expect("fixed checksum");
        let mut latest: Option<SenderCheckpoint> = None;
        {
            let mut reader = BufReader::new(&mut file);
            for sequence in 0..records {
                let mut record = Zeroizing::new([0; RECORD]);
                reader.read_exact(&mut record[..])?;
                let count = usize::from(u16::from_be_bytes([record[8], record[9]]));
                if record[..8] != u64::from(sequence).to_be_bytes()
                    || record[10..16] != [0; 6]
                    || count > MAX_SENDER_CHECKPOINT_BYTES
                    || record[16 + count..BODY].iter().any(|byte| *byte != 0)
                    || record[BODY..] != checksum(&previous, &record[..BODY])
                {
                    return Err(invalid());
                }
                let next = SenderCheckpoint::from_canonical_bytes(&record[16..16 + count])?;
                if let Some(old) = &latest {
                    next.validate_successor(old)?;
                }
                previous.copy_from_slice(&record[BODY..]);
                latest = Some(next);
            }
            if reader.read(&mut [0; 1])? != 0 {
                return Err(invalid());
            }
        }
        // A header alone contains no resumable operation. Never invent a nonce
        // or restart the producer as a fresh transfer when reopening it.
        if create.is_none() && latest.is_none() {
            return Err(invalid());
        }
        if file.metadata()?.len() != length {
            return Err(invalid());
        }
        // A complete tail may have survived an uncertain sync in another process.
        file.sync_all()?;
        directory.sync_all()?;
        Self::verify(&path, &directory, &file)?;
        Ok(Self {
            path,
            directory,
            maximum,
            state: Mutex::new(State {
                file,
                records,
                previous,
                latest,
                poisoned: false,
            }),
        })
    }

    fn verify(path: &Path, directory: &File, file: &File) -> io::Result<()> {
        let held = file.metadata()?;
        let named = std::fs::symlink_metadata(path)?;
        let parent = std::fs::symlink_metadata(path.parent().ok_or_else(invalid)?)?;
        let held_parent = directory.metadata()?;
        if !held.is_file()
            || !named.is_file()
            || held.nlink() != 1
            || held.permissions().mode() & 0o077 != 0
            || (held.dev(), held.ino()) != (named.dev(), named.ino())
            || !parent.is_dir()
            || parent.permissions().mode() & 0o077 != 0
            || (parent.dev(), parent.ino()) != (held_parent.dev(), held_parent.ino())
        {
            return Err(invalid());
        }
        Ok(())
    }

    fn append(&self, checkpoint: SenderCheckpoint) -> io::Result<u32> {
        let bytes = checkpoint.to_canonical_bytes()?;
        let mut state = self.state.lock();
        if state.poisoned {
            return Err(io::Error::other(
                "sender journal persistence is unconfirmed",
            ));
        }
        if let Some(old) = &state.latest {
            checkpoint.validate_successor(old)?;
            if old.to_canonical_bytes()?.as_slice() == bytes.as_slice() {
                return Ok(state.records);
            }
        }
        if state.records >= self.maximum {
            return Err(io::Error::from(io::ErrorKind::StorageFull));
        }
        let mut record = Zeroizing::new([0; RECORD]);
        record[..8].copy_from_slice(&u64::from(state.records).to_be_bytes());
        record[8..10].copy_from_slice(&(bytes.len() as u16).to_be_bytes());
        record[16..16 + bytes.len()].copy_from_slice(&bytes);
        let hash = checksum(&state.previous, &record[..BODY]);
        record[BODY..].copy_from_slice(&hash);
        // From the first filesystem check onwards, any error or unwind is sticky.
        // No later append can hide an uncertain write beneath a successful one.
        state.poisoned = true;
        Self::verify(&self.path, &self.directory, &state.file)?;
        let expected = HEADER as u64 + u64::from(state.records) * RECORD as u64;
        if state.file.metadata()?.len() != expected {
            return Err(invalid());
        }
        state.file.seek(SeekFrom::End(0))?;
        state.file.write_all(&record[..])?;
        state.file.sync_all()?;
        self.directory.sync_all()?;
        Self::verify(&self.path, &self.directory, &state.file)?;
        state.records += 1;
        state.previous = hash;
        state.latest = Some(checkpoint);
        state.poisoned = false;
        Ok(state.records)
    }
}

/// Exclusive append-only history for one replayable sender source.
///
/// Open/create synchronously before entering the runtime. Writes run on the
/// blocking pool with one operation in flight. That operation retains the file
/// descriptor and lock through a dropped wait or dropped wrapper. Retain this
/// owner across all attempts, and protect unread source bytes against mutation.
/// No automatic compaction, deletion, tail repair, or journal replacement occurs.
pub struct SenderJournalFile {
    storage: Arc<Storage>,
    latest: Option<SenderCheckpoint>,
    records: u32,
    pending: Option<Persist>,
    pending_bytes: Option<Zeroizing<Vec<u8>>>,
    failure: Option<Failure>,
}

impl fmt::Debug for SenderJournalFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SenderJournalFile")
            .field("snapshots", &self.records)
            .field("maximum_snapshots", &self.storage.maximum)
            .field("pending", &self.pending.is_some())
            .field("failed", &self.failure.is_some())
            .finish_non_exhaustive()
    }
}

impl SenderJournalFile {
    /// Create a new private journal with a fixed lifetime snapshot ceiling.
    /// Existing paths are refused. At most 65,536 snapshots, 720 bytes each.
    pub fn create_new(path: &Path, maximum_snapshots: u32) -> io::Result<Self> {
        Ok(Self::from_storage(Storage::open(
            path,
            Some(maximum_snapshots),
        )?))
    }

    /// Exclusively validate and synchronize an existing complete history.
    /// Missing/empty/torn/corrupt history is refused, never replaced or shortened.
    pub fn open_existing(path: &Path) -> io::Result<Self> {
        Ok(Self::from_storage(Storage::open(path, None)?))
    }

    fn from_storage(storage: Storage) -> Self {
        let state = storage.state.lock();
        let latest = state.latest.clone();
        let records = state.records;
        drop(state);
        Self {
            storage: Arc::new(storage),
            latest,
            records,
            pending: None,
            pending_bytes: None,
            failure: None,
        }
    }

    /// Latest confirmed local continuation, not remote delivery evidence.
    /// Pending/failed persistence never exposes an older snapshot as current.
    pub fn checkpoint(&self) -> io::Result<SenderCheckpoint> {
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

    /// Successfully synchronized snapshots observed by this owner.
    #[must_use]
    pub const fn persisted_snapshots(&self) -> u32 {
        self.records
    }

    /// Lifetime snapshot limit, preserved across reopen.
    #[must_use]
    pub fn maximum_snapshots(&self) -> u32 {
        self.storage.maximum
    }
}

impl SenderCheckpointStore for SenderJournalFile {
    fn poll_store(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        checkpoint: &SenderCheckpoint,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Some(error) = this.failure {
            return Poll::Ready(Err(restore_error(error)));
        }
        let bytes = match checkpoint.to_canonical_bytes() {
            Ok(bytes) => bytes,
            Err(error) => return Poll::Ready(Err(error)),
        };
        if this
            .pending_bytes
            .as_ref()
            .is_some_and(|pending| pending.as_slice() != bytes.as_slice())
        {
            // Preserve the original in-flight operation and ownership. A changed
            // poll request must not cancel it or start a competing write.
            return Poll::Ready(Err(invalid()));
        }
        if this.pending.is_none() {
            let storage = Arc::clone(&this.storage);
            let checkpoint = checkpoint.clone();
            this.pending_bytes = Some(bytes);
            this.pending = Some(Box::pin(async move {
                spawn_blocking_io(move || storage.append(checkpoint)).await
            }));
        }
        let result = ready!(
            this.pending
                .as_mut()
                .expect("one journal append")
                .as_mut()
                .poll(cx)
        );
        this.pending = None;
        let bytes = this.pending_bytes.take().expect("owned pending snapshot");
        match result {
            Ok(records) => {
                this.records = records;
                this.latest = Some(SenderCheckpoint::from_canonical_bytes(&bytes)?);
                Poll::Ready(Ok(()))
            }
            Err(error) => {
                this.failure = Some((error.kind(), error.raw_os_error()));
                Poll::Ready(Err(error))
            }
        }
    }
}

#[cfg(test)]
#[path = "file_inline_tests.rs"]
mod tests;
