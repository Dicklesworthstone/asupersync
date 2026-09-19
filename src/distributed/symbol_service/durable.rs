//! Append-only, restartable storage for authenticated replica symbol batches.
//!
//! The caller supplies a regular, read/write file and owns its pathname, access
//! policy and durable directory linkage. This module never opens another file,
//! truncates, renames, deletes or compacts anything. An exclusive file lock is
//! retained for the store's lifetime; do not retain cloned/inherited handles or
//! modify the file through actors that ignore that lock.
//!
//! A new batch becomes visible only after its complete authenticated record has
//! been written and `File::sync_all` succeeds. Reopening reauthenticates the whole
//! admitted journal and every symbol, then syncs before exposing recovered data.
//! A partial trailing record preserves the valid prefix in read-only mode. A
//! complete malformed or unauthenticated record rejects the entire open instead
//! of silently rolling back acknowledged state. No automatic repair is performed.
//!
//! These are synchronous disk APIs: run them on a blocking worker, not an async
//! executor thread. Filesystem/hardware guarantees and a durably linked file are
//! prerequisites for crash durability. Authentication is NOT encryption or an
//! external anti-rollback witness: deletion/replay of a complete valid suffix is
//! not detectable without a separately retained trusted journal head.

use super::{
    EncodedSymbolBatch, State, SymbolBatchKey, SymbolBatchLimits, SymbolStoreError,
    SymbolStoreLimits, SymbolStoreStats, batch, valid_identity,
};
use crate::remote::NodeId;
use crate::security::{AuthKey, AuthenticationTag};
use parking_lot::Mutex;
use std::fmt;
use std::fs::{File, TryLockError};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::sync::Arc;
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"ASUPJNL\0";
const HEADER_DOMAIN: &[u8] = b"asupersync.symbol-journal.header.v1";
const RECORD_DOMAIN: &[u8] = b"asupersync.symbol-journal.record.v1";
const PREFIX_DOMAIN: &[u8] = b"asupersync.symbol-journal.length.v1";
const TAG_BYTES: usize = 32;
const PREFIX_BYTES: usize = 8 + TAG_BYTES;
const RECORD_FIXED: usize = 8 + TAG_BYTES + 1;

/// Independent persistent-file, retained-memory and per-batch admission limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DurableSymbolLimits {
    /// Existing canonical batch count, payload and decoded-storage bounds.
    pub batch: SymbolBatchLimits,
    /// Existing aggregate/per-origin retained-batch and byte bounds.
    pub store: SymbolStoreLimits,
    /// Entire file, including authentication/framing and an incomplete tail.
    pub max_journal_bytes: u64,
}

/// Whether the journal can accept new immutable objects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JournalStatus {
    /// Complete journal; new objects may be appended within limits.
    Writable,
    /// A partial final record was retained untouched; only committed data is served.
    ReadOnlyTail,
    /// An append, sync, or external-length check failed; reopen before further use.
    Poisoned,
}

/// Payload-free journal diagnostics, without file paths, keys or symbol contents.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DurableSymbolError {
    /// Canonical batch, immutable-key, or retained-storage admission failed.
    #[error(transparent)]
    Store(#[from] SymbolStoreError),
    /// System I/O failed; a failed append may have reached persistent storage.
    #[error("symbol journal I/O failed; an attempted append may have committed")]
    Io(#[source] io::Error),
    /// Another file handle owns a conflicting lock.
    #[error("symbol journal is already locked")]
    Locked,
    /// The supplied handle does not refer to a regular file.
    #[error("symbol journal requires a regular file")]
    NotRegular,
    /// Creation never overwrites an existing journal or any other nonempty file.
    #[error("symbol journal creation requires an empty file")]
    NotEmpty,
    /// Invalid framing, sequence, replica binding, or duplicate journal entry.
    #[error("invalid symbol journal format or sequence")]
    Format,
    /// The independent journal key failed to authenticate the header or a record.
    #[error("symbol journal authentication failed")]
    Authentication,
    /// File size exceeds the caller's explicit ceiling.
    #[error("symbol journal byte limit exceeded")]
    JournalLimit,
    /// File length changed outside the exclusive owner.
    #[error("symbol journal changed outside its owner")]
    Changed,
    /// New writes are refused after incomplete recovery or uncertain persistence.
    #[error("symbol journal is not writable: {0:?}")]
    NotWritable(JournalStatus),
}

impl From<io::Error> for DurableSymbolError {
    fn from(error: io::Error) -> Self { Self::Io(error) }
}

/// Restartable immutable symbol store. All operations serialize on one disk owner.
///
/// File contents and returned batch owners are plaintext. Retained canonical
/// buffers and temporary record buffers zeroize on drop; disk contents do not.
/// The memory index retains at most `limits.store` bytes/batches; recovery also
/// needs one bounded record plus the existing batch decoder's temporary storage.
/// No unbounded queue, automatic retry, recovery discovery or background thread
/// is created. A retained receipt says nothing about restoration of task futures.
pub struct DurableSymbolReplicaStore {
    replica: String,
    state: Mutex<Journal<File>>,
}

impl fmt::Debug for DurableSymbolReplicaStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DurableSymbolReplicaStore")
            .field("stats", &self.stats()).field("status", &self.status())
            .finish_non_exhaustive()
    }
}

impl DurableSymbolReplicaStore {
    /// Initialize an empty, exclusively owned file and sync its authenticated header.
    ///
    /// The file must be durably linked by its caller (including directory sync
    /// where required), opened read/write and not cloned or already locked. The
    /// journal key authenticates origin labels and sequence independently of the
    /// symbol key. No entropy, directory or path authority is acquired here.
    pub fn create(
        file: File, replica: impl Into<String>, symbol_key: AuthKey,
        journal_key: AuthKey, limits: DurableSymbolLimits,
    ) -> Result<Self, DurableSymbolError> {
        let replica = replica.into();
        validate_identity(&replica)?;
        lock(&file)?;
        let journal = Journal::create(file, &replica, symbol_key, journal_key, limits)?;
        Ok(Self { replica, state: Mutex::new(journal) })
    }

    /// Reopen, authenticate and sync a bounded journal before serving any data.
    ///
    /// The expected replica and both keys are explicit local authority. A valid
    /// partial tail is preserved and reported as `ReadOnlyTail`; previous records
    /// remain fetchable and identical puts remain idempotent. New objects refuse.
    /// Complete corrupt records, wrong keys, changed limits and invalid headers
    /// fail closed. This function never creates or repairs the file.
    pub fn open(
        file: File, replica: impl Into<String>, symbol_key: AuthKey,
        journal_key: AuthKey, limits: DurableSymbolLimits,
    ) -> Result<Self, DurableSymbolError> {
        let replica = replica.into();
        validate_identity(&replica)?;
        lock(&file)?;
        let journal = Journal::open(file, &replica, symbol_key, journal_key, limits)?;
        Ok(Self { replica, state: Mutex::new(journal) })
    }

    /// Receiver identity used by the existing symbol-service receipt.
    #[must_use]
    pub fn replica_id(&self) -> &str { &self.replica }

    /// Retained committed batches and canonical bytes (not on-disk framing).
    #[must_use]
    pub fn stats(&self) -> SymbolStoreStats {
        let state = self.state.lock();
        SymbolStoreStats { batches: state.entries.entries.len(), bytes: state.entries.bytes }
    }

    /// Current append posture; read-only recovery is never reported as writable.
    #[must_use]
    pub fn status(&self) -> JournalStatus { self.state.lock().status }

    /// Byte offset just after the last completely authenticated, synced record.
    #[must_use]
    pub fn committed_bytes(&self) -> u64 { self.state.lock().offset }

    /// Verify and durably append, or return an already committed identical batch.
    ///
    /// The peer is local authority, not an authenticated string. Network adapters
    /// must derive it from the admitted certificate-bound invocation. Every symbol
    /// is reverified. Quotas are checked before disk mutation. A write/sync failure
    /// poisons this owner and publishes no new in-memory entry, even if a subsequent
    /// reopen finds that the entire record reached disk. Do not infer rollback.
    pub fn put(
        &self, peer: &NodeId, bytes: &[u8],
    ) -> Result<Arc<EncodedSymbolBatch>, DurableSymbolError> {
        self.state.lock().put(peer, bytes)
    }

    /// Retrieve an exact committed batch from the admitted origin's namespace.
    pub fn get(
        &self, peer: &NodeId, key: SymbolBatchKey,
    ) -> Result<Arc<EncodedSymbolBatch>, DurableSymbolError> {
        self.state.lock().get(peer, key)
    }
}

fn validate_identity(value: &str) -> Result<(), DurableSymbolError> {
    if !valid_identity(value) { return Err(SymbolStoreError::InvalidIdentity.into()); }
    Ok(())
}

fn lock(file: &File) -> Result<(), DurableSymbolError> {
    match file.try_lock() {
        Ok(()) => {}
        Err(TryLockError::WouldBlock) => return Err(DurableSymbolError::Locked),
        Err(TryLockError::Error(error)) => return Err(error.into()),
    }
    if !file.metadata()?.is_file() { return Err(DurableSymbolError::NotRegular); }
    Ok(())
}

// Kept private: fault tests exercise the actual commit/recovery engine without
// pretending an in-memory file establishes filesystem or power-failure behavior.
trait JournalIo: Read + Write + Seek {
    fn length(&self) -> io::Result<u64>;
    fn sync(&mut self) -> io::Result<()>;
}
impl JournalIo for File {
    fn length(&self) -> io::Result<u64> { Ok(self.metadata()?.len()) }
    fn sync(&mut self) -> io::Result<()> { self.sync_all() }
}

struct Journal<F> {
    file: F,
    symbol_key: AuthKey,
    journal_key: AuthKey,
    limits: DurableSymbolLimits,
    entries: State,
    offset: u64,
    sequence: u64,
    last: AuthenticationTag,
    status: JournalStatus,
}

fn reserve(length: usize) -> Result<Zeroizing<Vec<u8>>, DurableSymbolError> {
    let mut bytes = Zeroizing::new(Vec::new());
    bytes.try_reserve_exact(length).map_err(|_| SymbolStoreError::Allocation)?;
    Ok(bytes)
}
fn add(a: usize, b: usize) -> Result<usize, DurableSymbolError> {
    a.checked_add(b).ok_or_else(|| SymbolStoreError::Overflow.into())
}
fn size64(length: usize) -> Result<u64, DurableSymbolError> {
    u64::try_from(length).map_err(|_| SymbolStoreError::Overflow.into())
}
fn header(replica: &str) -> Result<Zeroizing<Vec<u8>>, DurableSymbolError> {
    let mut bytes = reserve(13 + replica.len() + TAG_BYTES)?;
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    bytes.push(replica.len() as u8);
    bytes.extend_from_slice(replica.as_bytes());
    Ok(bytes)
}

fn prefix_payload(length: u64, sequence: u64, previous: AuthenticationTag) -> [u8; 48] {
    let mut bytes = [0; 48];
    bytes[..8].copy_from_slice(&length.to_le_bytes());
    bytes[8..16].copy_from_slice(&sequence.to_le_bytes());
    bytes[16..].copy_from_slice(previous.as_bytes());
    bytes
}

impl<F: JournalIo> Journal<F> {
    fn create(
        mut file: F, replica: &str, symbol_key: AuthKey,
        journal_key: AuthKey, limits: DurableSymbolLimits,
    ) -> Result<Self, DurableSymbolError> {
        if file.length()? != 0 { return Err(DurableSymbolError::NotEmpty); }
        let mut bytes = header(replica)?;
        let tag = AuthenticationTag::compute_for_domain_payload(&journal_key, HEADER_DOMAIN, &bytes);
        bytes.extend_from_slice(tag.as_bytes());
        let offset = size64(bytes.len())?;
        if offset > limits.max_journal_bytes { return Err(DurableSymbolError::JournalLimit); }
        file.seek(SeekFrom::Start(0))?;
        file.write_all(&bytes)?;
        file.sync()?;
        Ok(Self { file, symbol_key, journal_key, limits, entries: State::default(),
            offset, sequence: 0, last: tag, status: JournalStatus::Writable })
    }

    fn open(
        mut file: F, replica: &str, symbol_key: AuthKey,
        journal_key: AuthKey, limits: DurableSymbolLimits,
    ) -> Result<Self, DurableSymbolError> {
        let length = file.length()?;
        if length > limits.max_journal_bytes { return Err(DurableSymbolError::JournalLimit); }
        let expected = header(replica)?;
        let header_len = expected.len() + TAG_BYTES;
        if length < size64(header_len)? { return Err(DurableSymbolError::Format); }
        let mut bytes = reserve(header_len)?;
        bytes.resize(header_len, 0);
        file.seek(SeekFrom::Start(0))?;
        file.read_exact(&mut bytes)?;
        if bytes[..expected.len()] != expected[..] { return Err(DurableSymbolError::Format); }
        let tag = AuthenticationTag::from_bytes(bytes[expected.len()..].try_into().expect("header tag"));
        if !tag.verify_domain_payload(&journal_key, HEADER_DOMAIN, &bytes[..expected.len()]) {
            return Err(DurableSymbolError::Authentication);
        }
        let mut journal = Self { file, symbol_key, journal_key, limits, entries: State::default(),
            offset: size64(header_len)?, sequence: 0, last: tag, status: JournalStatus::Writable };
        while journal.offset < length {
            let remaining = length - journal.offset;
            if remaining < PREFIX_BYTES as u64 { journal.status = JournalStatus::ReadOnlyTail; break; }
            let mut prefix = [0; PREFIX_BYTES];
            journal.file.read_exact(&mut prefix)?;
            let body_len = u64::from_le_bytes(prefix[..8].try_into().expect("length bytes"));
            let next = journal.sequence.checked_add(1).ok_or(SymbolStoreError::Overflow)?;
            let length_tag = AuthenticationTag::from_bytes(prefix[8..].try_into().expect("length tag"));
            if !length_tag.verify_domain_payload(&journal.journal_key, PREFIX_DOMAIN,
                &prefix_payload(body_len, next, journal.last)) {
                return Err(DurableSymbolError::Authentication);
            }
            let max_body = size64(add(RECORD_FIXED + 255, limits.batch.max_encoded_bytes)?)?;
            if body_len < (RECORD_FIXED + 1 + 32) as u64 || body_len > max_body {
                return Err(DurableSymbolError::Format);
            }
            let record_len = body_len.checked_add((PREFIX_BYTES + TAG_BYTES) as u64).ok_or(SymbolStoreError::Overflow)?;
            if record_len > remaining { journal.status = JournalStatus::ReadOnlyTail; break; }
            let n = usize::try_from(record_len).map_err(|_| SymbolStoreError::Overflow)?;
            let mut record = reserve(n)?;
            record.extend_from_slice(&prefix);
            record.resize(n, 0);
            journal.file.read_exact(&mut record[PREFIX_BYTES..])?;
            journal.replay_record(&record)?;
            journal.offset = journal.offset.checked_add(record_len).ok_or(SymbolStoreError::Overflow)?;
        }
        if journal.file.length()? != length { return Err(DurableSymbolError::Changed); }
        // A complete unacknowledged record may be present after a crash. Make
        // every admitted prefix durable before exposing it as committed storage.
        journal.file.sync()?;
        Ok(journal)
    }

    fn replay_record(&mut self, record: &[u8]) -> Result<(), DurableSymbolError> {
        let signed_end = record.len() - TAG_BYTES;
        let tag = AuthenticationTag::from_bytes(record[signed_end..].try_into().expect("record tag"));
        if !tag.verify_domain_payload(&self.journal_key, RECORD_DOMAIN, &record[..signed_end]) {
            return Err(DurableSymbolError::Authentication);
        }
        let body = &record[PREFIX_BYTES..signed_end];
        let sequence = u64::from_le_bytes(body[..8].try_into().expect("sequence"));
        let expected = self.sequence.checked_add(1).ok_or(SymbolStoreError::Overflow)?;
        if sequence != expected || &body[8..40] != self.last.as_bytes() {
            return Err(DurableSymbolError::Format);
        }
        let peer_len = usize::from(body[40]);
        let peer_end = add(RECORD_FIXED, peer_len)?;
        if peer_len == 0 || peer_end > body.len() { return Err(DurableSymbolError::Format); }
        let peer = std::str::from_utf8(&body[RECORD_FIXED..peer_end]).map_err(|_| DurableSymbolError::Format)?;
        let peer = NodeId::new(peer);
        let batch = Arc::new(batch::verified_bytes(&body[peer_end..], &self.symbol_key, self.limits.batch)?);
        if self.entries.entries.contains_key(&(peer.clone(), batch.key().object_id)) {
            return Err(DurableSymbolError::Format);
        }
        let total = self.admit(&peer, &batch)?;
        self.entries.entries.insert((peer, batch.key().object_id), batch);
        self.entries.bytes = total;
        self.sequence = sequence;
        self.last = tag;
        Ok(())
    }

    fn admit(&self, peer: &NodeId, batch: &EncodedSymbolBatch) -> Result<usize, DurableSymbolError> {
        let bounds = self.limits.store;
        if self.entries.entries.len() >= bounds.max_batches { return Err(SymbolStoreError::Limit("batches").into()); }
        let total = add(self.entries.bytes, batch.as_ref().len())?;
        if total > bounds.max_bytes { return Err(SymbolStoreError::Limit("stored bytes").into()); }
        let mut count = 0usize;
        let mut bytes = 0usize;
        for ((origin, _), existing) in &self.entries.entries {
            if origin == peer { count = add(count, 1)?; bytes = add(bytes, existing.as_ref().as_ref().len())?; }
        }
        if count >= bounds.max_batches_per_peer { return Err(SymbolStoreError::Limit("peer batches").into()); }
        if add(bytes, batch.as_ref().len())? > bounds.max_bytes_per_peer {
            return Err(SymbolStoreError::Limit("peer bytes").into());
        }
        Ok(total)
    }

    fn get(&self, peer: &NodeId, key: SymbolBatchKey) -> Result<Arc<EncodedSymbolBatch>, DurableSymbolError> {
        validate_identity(peer.as_str())?;
        if self.status == JournalStatus::Poisoned { return Err(DurableSymbolError::NotWritable(self.status)); }
        self.entries.entries.get(&(peer.clone(), key.object_id)).filter(|batch| batch.key() == key)
            .map(Arc::clone).ok_or_else(|| SymbolStoreError::NotFound.into())
    }

    fn put(&mut self, peer: &NodeId, bytes: &[u8]) -> Result<Arc<EncodedSymbolBatch>, DurableSymbolError> {
        validate_identity(peer.as_str())?;
        if self.status == JournalStatus::Poisoned { return Err(DurableSymbolError::NotWritable(self.status)); }
        let batch = Arc::new(batch::verified_bytes(bytes, &self.symbol_key, self.limits.batch)?);
        let id = (peer.clone(), batch.key().object_id);
        if let Some(existing) = self.entries.entries.get(&id) {
            return if existing.as_ref().as_ref() == bytes { Ok(Arc::clone(existing)) }
                else { Err(SymbolStoreError::Conflict.into()) };
        }
        if self.status != JournalStatus::Writable { return Err(DurableSymbolError::NotWritable(self.status)); }
        let total = self.admit(peer, &batch)?;
        let sequence = self.sequence.checked_add(1).ok_or(SymbolStoreError::Overflow)?;
        let body_len = add(add(RECORD_FIXED, peer.as_str().len())?, bytes.len())?;
        let record_len = add(PREFIX_BYTES + TAG_BYTES, body_len)?;
        let end = self.offset.checked_add(size64(record_len)?).ok_or(SymbolStoreError::Overflow)?;
        if end > self.limits.max_journal_bytes { return Err(DurableSymbolError::JournalLimit); }
        let mut record = reserve(record_len)?;
        record.extend_from_slice(&size64(body_len)?.to_le_bytes());
        let length_tag = AuthenticationTag::compute_for_domain_payload(&self.journal_key, PREFIX_DOMAIN,
            &prefix_payload(size64(body_len)?, sequence, self.last));
        record.extend_from_slice(length_tag.as_bytes());
        record.extend_from_slice(&sequence.to_le_bytes());
        record.extend_from_slice(self.last.as_bytes());
        record.push(peer.as_str().len() as u8);
        record.extend_from_slice(peer.as_str().as_bytes());
        record.extend_from_slice(bytes);
        let tag = AuthenticationTag::compute_for_domain_payload(&self.journal_key, RECORD_DOMAIN, &record);
        record.extend_from_slice(tag.as_bytes());

        // From here on, both errors and unwinding leave a poisoned owner. Never
        // return an in-memory success after an uncertain write or failed fsync.
        self.status = JournalStatus::Poisoned;
        if self.file.length()? != self.offset || self.file.seek(SeekFrom::End(0))? != self.offset {
            return Err(DurableSymbolError::Changed);
        }
        self.file.write_all(&record)?;
        self.file.sync()?;
        self.entries.entries.insert(id, Arc::clone(&batch));
        self.entries.bytes = total;
        self.offset = end;
        self.sequence = sequence;
        self.last = tag;
        self.status = JournalStatus::Writable;
        Ok(batch)
    }
}

#[cfg(test)]
mod tests;
