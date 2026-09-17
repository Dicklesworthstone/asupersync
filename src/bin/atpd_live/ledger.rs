//! Durable refusal claims and publication receipts for the shared resume CLI.
//!
//! A synchronized claim precedes every possible sink effect. Reopening never
//! recreates an old key, even when only its claim survived. Successful receipts
//! are appended after file publication and before the receiver sends Proof.
//! This is duplicate suppression and reconciliation, NOT continuation restore.
//!
//! The operator must protect this existing private file and its directory from
//! deletion, rollback, replacement and concurrent non-cooperating writers. Hash
//! chaining detects corruption, not malicious rewriting or suffix rollback.
//! Torn records fail closed; nothing is truncated, repaired, evicted or deleted.

use super::settings::{hex, invalid};
use asupersync::net::atp::sdk::NativeClientCertificateId;
use asupersync::net::atp::sdk::native_auth::live::{LiveStreamPrefix, LiveStreamReceipt};
use asupersync::net::atp::sdk::native_auth::live::commit::resume::service::ResumeSessionKey;
use asupersync::runtime::spawn_blocking_io;
use parking_lot::Mutex;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

const MAGIC: &[u8; 8] = b"ATPRJ001";
const HEADER_BYTES: usize = 48;
const RECORD_BYTES: usize = 256;
const BODY_BYTES: usize = 224;
const MAX_KEYS: u32 = 65_536;

#[derive(Debug, Clone)]
pub(super) struct Entry {
    pub key: ResumeSessionKey,
    pub filename: String,
    pub maximum_bytes: u64,
    /// Historical local publication, never proof that a sender received Proof.
    pub receipt: Option<LiveStreamReceipt>,
}

struct State {
    file: File,
    entries: BTreeMap<ResumeSessionKey, Entry>,
    records: u64,
    previous: [u8; 32],
    poisoned: bool,
}

/// Its lock remains held by every asynchronous operation and claim owner.
pub(super) struct Ledger {
    path: PathBuf,
    directory: File,
    maximum_keys: u32,
    state: Mutex<State>,
}

impl fmt::Debug for Ledger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.state.lock();
        f.debug_struct("SessionLedger").field("keys", &state.entries.len())
            .field("maximum_keys", &self.maximum_keys).field("poisoned", &state.poisoned)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, thiserror::Error)]
#[error("session was already durably claimed; reconcile instead of recreating its sink")]
struct AlreadyClaimed;

pub(super) fn is_replay_refusal(error: &io::Error) -> bool {
    error.get_ref().is_some_and(|source| source.is::<AlreadyClaimed>())
}

#[derive(Clone)]
pub(super) struct Claim {
    ledger: Arc<Ledger>,
    key: ResumeSessionKey,
}

fn corrupt() -> io::Error { io::Error::new(io::ErrorKind::InvalidData, "invalid or torn session ledger") }
fn unavailable() -> io::Error { io::Error::other("session ledger persistence is unconfirmed; restart and reconcile") }
fn hash(previous: &[u8], body: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"asupersync.atpd.session-ledger.v1");
    hash.update(previous);
    hash.update(body);
    hash.finalize().into()
}

fn parent(path: &Path) -> io::Result<(PathBuf, File)> {
    if !path.is_absolute() { return Err(invalid("session ledger requires an absolute path")); }
    let name = path.file_name().ok_or_else(|| invalid("session ledger needs a filename"))?;
    let parent = path.parent().ok_or_else(|| invalid("session ledger needs a parent"))?;
    let metadata = std::fs::symlink_metadata(parent)?;
    if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
        return Err(io::Error::from(io::ErrorKind::PermissionDenied));
    }
    let parent = std::fs::canonicalize(parent)?;
    let directory = File::open(&parent)?;
    Ok((parent.join(name), directory))
}

fn verify_identity(path: &Path, file: &File, directory: &File) -> io::Result<()> {
    let held = file.metadata()?;
    let named = std::fs::symlink_metadata(path)?;
    let parent = std::fs::symlink_metadata(path.parent().ok_or_else(corrupt)?)?;
    let held_parent = directory.metadata()?;
    if !held.is_file() || !named.is_file() || held.nlink() != 1
        || held.permissions().mode() & 0o077 != 0
        || (held.dev(), held.ino()) != (named.dev(), named.ino())
        || !parent.is_dir() || parent.permissions().mode() & 0o077 != 0
        || (parent.dev(), parent.ino()) != (held_parent.dev(), held_parent.ino())
    { return Err(corrupt()); }
    Ok(())
}

impl Ledger {
    /// Explicit create-only provisioning. Never silently create on server restart.
    pub fn initialize(path: &Path, maximum_keys: u32) -> io::Result<()> {
        if !(1..=MAX_KEYS).contains(&maximum_keys) { return Err(invalid("ledger key limit must be 1..=65536")); }
        let (path, directory) = parent(path)?;
        let mut file = OpenOptions::new().read(true).write(true).create_new(true)
            .mode(0o600).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(&path)?;
        file.try_lock().map_err(io::Error::from)?;
        verify_identity(&path, &file, &directory)?;
        let mut header = [0; HEADER_BYTES];
        header[..8].copy_from_slice(MAGIC);
        header[8..12].copy_from_slice(&maximum_keys.to_be_bytes());
        let checksum = hash(&[], &header[..16]);
        header[16..].copy_from_slice(&checksum);
        file.write_all(&header)?;
        file.sync_all()?;
        directory.sync_all()
    }

    /// Validate the entire existing bounded journal before admitting any effect.
    pub fn open(path: &Path) -> io::Result<Arc<Self>> {
        let (path, directory) = parent(path)?;
        let mut file = OpenOptions::new().read(true).write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(&path)?;
        file.try_lock().map_err(io::Error::from)?;
        verify_identity(&path, &file, &directory)?;
        let length = file.metadata()?.len();
        let mut header = [0; HEADER_BYTES];
        file.read_exact(&mut header)?;
        let maximum_keys = u32::from_be_bytes(header[8..12].try_into().expect("fixed header"));
        if &header[..8] != MAGIC || header[12..16] != [0; 4]
            || !(1..=MAX_KEYS).contains(&maximum_keys)
            || header[16..] != hash(&[], &header[..16])
            || length < HEADER_BYTES as u64
            || (length - HEADER_BYTES as u64) % RECORD_BYTES as u64 != 0
            || length > HEADER_BYTES as u64 + u64::from(maximum_keys) * 2 * RECORD_BYTES as u64
        { return Err(corrupt()); }
        let records = (length - HEADER_BYTES as u64) / RECORD_BYTES as u64;
        let mut previous: [u8; 32] = header[16..].try_into().expect("header checksum");
        let mut entries = BTreeMap::new();
        {
            let mut reader = BufReader::new(&mut file);
            for sequence in 0..records {
                let mut record = [0; RECORD_BYTES];
                reader.read_exact(&mut record)?;
                if record[..8] != sequence.to_be_bytes() || record[9..16] != [0; 7]
                    || record[196..BODY_BYTES] != [0; 28]
                    || record[BODY_BYTES..] != hash(&previous, &record[..BODY_BYTES])
                { return Err(corrupt()); }
                let (kind, entry) = decode(&record)?;
                apply(&mut entries, maximum_keys, kind, entry)?;
                previous.copy_from_slice(&record[BODY_BYTES..]);
            }
            if reader.read(&mut [0; 1])? != 0 { return Err(corrupt()); }
        }
        // A complete last record may have survived a failed sync in another
        // process. Synchronize it now before treating its refusal as durable.
        file.sync_all()?;
        directory.sync_all()?;
        Ok(Arc::new(Self { path, directory, maximum_keys, state: Mutex::new(State {
            file, entries, records, previous, poisoned: false,
        }) }))
    }

    pub fn maximum_keys(&self) -> u32 { self.maximum_keys }

    pub fn snapshot(&self) -> io::Result<Vec<Entry>> {
        let state = self.state.lock();
        if state.poisoned { return Err(unavailable()); }
        Ok(state.entries.values().cloned().collect())
    }

    /// Runs on the blocking pool; caller must have authenticated and authorized key.
    pub async fn claim(self: &Arc<Self>, key: ResumeSessionKey, filename: String, maximum_bytes: u64) -> io::Result<Claim> {
        let ledger = Arc::clone(self);
        spawn_blocking_io(move || {
            ledger.claim_sync(key, filename, maximum_bytes)?;
            Ok(Claim { ledger, key })
        }).await
    }

    fn claim_sync(&self, key: ResumeSessionKey, filename: String, maximum_bytes: u64) -> io::Result<()> {
        if !valid_filename(filename.as_bytes()) { return Err(invalid("invalid ledger publication filename")); }
        let mut state = self.state.lock();
        if state.poisoned { return Err(unavailable()); }
        if state.entries.contains_key(&key) {
            return Err(io::Error::new(io::ErrorKind::AlreadyExists, AlreadyClaimed));
        }
        if state.entries.len() >= self.maximum_keys as usize { return Err(io::Error::from(io::ErrorKind::StorageFull)); }
        self.append(&mut state, 1, Entry { key, filename, maximum_bytes, receipt: None })
    }

    fn commit_sync(&self, key: ResumeSessionKey, receipt: LiveStreamReceipt) -> io::Result<()> {
        let mut state = self.state.lock();
        if state.poisoned { return Err(unavailable()); }
        let mut entry = state.entries.get(&key).cloned().ok_or_else(corrupt)?;
        if let Some(earlier) = &entry.receipt {
            return if earlier == &receipt { Ok(()) } else { Err(corrupt()) };
        }
        validate_receipt(&entry, &receipt)?;
        entry.receipt = Some(receipt);
        self.append(&mut state, 2, entry)
    }

    fn append(&self, state: &mut State, kind: u8, entry: Entry) -> io::Result<()> {
        if state.records >= u64::from(self.maximum_keys) * 2 { return Err(corrupt()); }
        let mut record = encode(state.records, kind, &entry);
        let checksum = hash(&state.previous, &record[..BODY_BYTES]);
        record[BODY_BYTES..].copy_from_slice(&checksum);
        // Any unwind or uncertain syscall leaves a sticky refusal. Do not
        // append beyond a failed record or release its logical reservation.
        state.poisoned = true;
        verify_identity(&self.path, &state.file, &self.directory)?;
        let expected = HEADER_BYTES as u64 + state.records * RECORD_BYTES as u64;
        if state.file.metadata()?.len() != expected { return Err(corrupt()); }
        state.file.seek(SeekFrom::End(0))?;
        state.file.write_all(&record)?;
        state.file.sync_all()?;
        apply(&mut state.entries, self.maximum_keys, kind, entry)?;
        state.records += 1;
        state.previous = checksum;
        state.poisoned = false;
        Ok(())
    }
}

impl Claim {
    pub async fn commit(&self, receipt: LiveStreamReceipt) -> io::Result<()> {
        let claim = self.clone();
        spawn_blocking_io(move || claim.ledger.commit_sync(claim.key, receipt)).await
    }
}

fn valid_filename(bytes: &[u8]) -> bool {
    bytes.len() == 36 && &bytes[32..] == b".bin"
        && bytes[..32].iter().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

fn validate_receipt(entry: &Entry, receipt: &LiveStreamReceipt) -> io::Result<()> {
    let prefix = &receipt.prefix;
    if prefix.stream_nonce != entry.key.nonce || prefix.bytes > entry.maximum_bytes
        || (prefix.bytes == 0) != (prefix.epochs == 0) || prefix.epochs > prefix.bytes
    { return Err(corrupt()); }
    Ok(())
}

fn encode(sequence: u64, kind: u8, entry: &Entry) -> [u8; RECORD_BYTES] {
    let mut record = [0; RECORD_BYTES];
    record[..8].copy_from_slice(&sequence.to_be_bytes());
    record[8] = kind;
    record[16..48].copy_from_slice(entry.key.client.as_bytes());
    record[48..80].copy_from_slice(&entry.key.nonce);
    record[80..116].copy_from_slice(entry.filename.as_bytes());
    record[116..124].copy_from_slice(&entry.maximum_bytes.to_be_bytes());
    if let Some(receipt) = &entry.receipt {
        record[116..124].copy_from_slice(&receipt.prefix.bytes.to_be_bytes());
        record[124..132].copy_from_slice(&receipt.prefix.epochs.to_be_bytes());
        record[132..164].copy_from_slice(&receipt.prefix.chain);
        record[164..196].copy_from_slice(&receipt.source_sha256);
    }
    record
}

fn decode(record: &[u8; RECORD_BYTES]) -> io::Result<(u8, Entry)> {
    if !valid_filename(&record[80..116]) { return Err(corrupt()); }
    let key = ResumeSessionKey {
        client: NativeClientCertificateId::from_sha256(record[16..48].try_into().expect("fixed client")),
        nonce: record[48..80].try_into().expect("fixed nonce"),
    };
    let count = u64::from_be_bytes(record[116..124].try_into().expect("fixed count"));
    let receipt = match record[8] {
        1 if record[124..196] == [0; 72] => None,
        2 => Some(LiveStreamReceipt { prefix: LiveStreamPrefix {
            stream_nonce: key.nonce, bytes: count,
            epochs: u64::from_be_bytes(record[124..132].try_into().expect("fixed epochs")),
            chain: record[132..164].try_into().expect("fixed chain"),
        }, source_sha256: record[164..196].try_into().expect("fixed digest") }),
        _ => return Err(corrupt()),
    };
    Ok((record[8], Entry { key, filename: String::from_utf8(record[80..116].to_vec()).map_err(|_| corrupt())?,
        maximum_bytes: count, receipt }))
}

fn apply(entries: &mut BTreeMap<ResumeSessionKey, Entry>, maximum: u32, kind: u8, entry: Entry) -> io::Result<()> {
    if kind == 1 {
        if entries.contains_key(&entry.key) || entries.len() >= maximum as usize { return Err(corrupt()); }
        entries.insert(entry.key, entry);
    } else {
        let earlier = entries.get_mut(&entry.key).ok_or_else(corrupt)?;
        if earlier.receipt.is_some() || earlier.filename != entry.filename { return Err(corrupt()); }
        let receipt = entry.receipt.ok_or_else(corrupt)?;
        validate_receipt(earlier, &receipt)?;
        earlier.receipt = Some(receipt);
    }
    Ok(())
}

pub(super) fn inspect(path: &Path) -> io::Result<()> {
    let ledger = Ledger::open(path)?;
    let entries = ledger.snapshot()?;
    super::emit(serde_json::json!({"schema_version": 1, "event": "session_ledger",
        "keys": entries.len(), "maximum_keys": ledger.maximum_keys(), "continuation_restored": false}))?;
    for entry in entries {
        super::emit(serde_json::json!({"schema_version": 1, "event": "session_record",
            "client_certificate_sha256": hex(entry.key.client.as_bytes()), "stream_nonce": hex(&entry.key.nonce),
            "filename": entry.filename, "maximum_bytes": entry.maximum_bytes,
            "state": if entry.receipt.is_some() { "committed" } else { "claimed_unresolved" },
            "receipt": entry.receipt.as_ref().map(super::receipt_json), "historical": true,
            "sender_receipt_observed": false}))?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "ledger_tests.rs"]
mod tests;
