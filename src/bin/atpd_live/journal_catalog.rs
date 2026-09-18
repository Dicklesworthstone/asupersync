//! Durable claims and refusal tombstones for shared receiver file journals.
//!
//! This is a catalog, not transfer progress or a successful-delivery ledger.
//! A claim precedes file creation. Existing claims only reopen their original
//! pairs; a missing/torn pair is never permission to start over. Retiring a key
//! is durable before its live sink is released. No file or history is removed.

use super::settings::invalid;
use asupersync::net::atp::sdk::NativeClientCertificateId;
use asupersync::net::atp::sdk::native_auth::live::commit::resume::receiver_journal::file::ReceiverFileLimits;
use asupersync::net::atp::sdk::native_auth::live::commit::resume::service::ResumeSessionKey;
use parking_lot::Mutex;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

const MAGIC: &[u8; 8] = b"ATPCAT01";
const HEADER: u64 = 80;
const RECORD: u64 = 160;
const BODY: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct FilePolicy {
    pub data_bytes: u64,
    pub journal_bytes: u64,
    pub snapshots: u32,
}
impl FilePolicy {
    pub fn validate(self) -> io::Result<()> {
        if !(96..=128 * 1024 * 1024).contains(&self.journal_bytes)
            || !(1..=65_536).contains(&self.snapshots)
        {
            return Err(invalid("invalid per-session receiver journal limits"));
        }
        Ok(())
    }
    pub fn limits(self) -> ReceiverFileLimits {
        ReceiverFileLimits {
            max_data_bytes: self.data_bytes,
            max_journal_bytes: self.journal_bytes,
            max_snapshots: self.snapshots,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(super) enum Retirement {
    LocalFailure = 1,
    Attempts = 2,
    Idle = 3,
    ProofWindow = 4,
    Revoked = 5,
    Initialization = 6,
}
impl Retirement {
    fn decode(value: u8) -> io::Result<Option<Self>> {
        Ok(match value {
            0 => None,
            1 => Some(Self::LocalFailure),
            2 => Some(Self::Attempts),
            3 => Some(Self::Idle),
            4 => Some(Self::ProofWindow),
            5 => Some(Self::Revoked),
            6 => Some(Self::Initialization),
            _ => return Err(invalid("invalid receiver catalog retirement")),
        })
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::LocalFailure => "local_failure",
            Self::Attempts => "attempts_exhausted",
            Self::Idle => "idle_retention_expired",
            Self::ProofWindow => "proof_recovery_expired",
            Self::Revoked => "client_revoked",
            Self::Initialization => "initialization_failed",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Entry {
    pub id: u64,
    pub key: ResumeSessionKey,
    pub directory: (u64, u64),
    pub policy: FilePolicy,
    pub retired: Option<Retirement>,
}
impl Entry {
    pub fn data_path(&self, directory: &Path) -> PathBuf {
        directory.join(format!("transfer-{:016x}.data", self.id))
    }
    fn wal_name(&self) -> String { format!("transfer-{:016x}.wal", self.id) }
}

struct State {
    file: File,
    entries: BTreeMap<ResumeSessionKey, Entry>,
    records: u64,
    reserved_wal: u64,
    hash: [u8; 32],
    poisoned: bool,
}

pub(super) struct Catalog {
    path: PathBuf,
    directory: File,
    maximum_keys: u32,
    maximum_wal: u64,
    state: Mutex<State>,
    failed: AtomicBool,
}

fn checksum(previous: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"asupersync.atpd.receiver-catalog.v1");
    hash.update(previous);
    hash.update(bytes);
    hash.finalize().into()
}
fn number(bytes: &[u8], at: usize) -> u64 {
    u64::from_be_bytes(bytes[at..at + 8].try_into().expect("fixed catalog field"))
}
fn directory_id(path: &Path) -> io::Result<(u64, u64)> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
        return Err(invalid("receiver catalog directories must be private and not symlinks"));
    }
    Ok((metadata.dev(), metadata.ino()))
}

impl Catalog {
    /// Explicit initialization requires an empty, dedicated private WAL directory.
    pub fn initialize(path: &Path, keys: u32, wal_bytes: u64) -> io::Result<()> {
        Self::open_mode(path, Some((keys, wal_bytes))).map(|_| ())
    }
    /// Never create or repair missing history. Call before starting the runtime.
    pub fn open(path: &Path) -> io::Result<Arc<Self>> {
        Self::open_mode(path, None).map(Arc::new)
    }
    fn open_mode(path: &Path, create: Option<(u32, u64)>) -> io::Result<Self> {
        if !path.is_absolute() {
            return Err(invalid("absolute receiver catalog path required"));
        }
        let name = path.file_name().and_then(|n| n.to_str())
            .ok_or_else(|| invalid("receiver catalog filename required"))?;
        if name.starts_with("transfer-") {
            return Err(invalid("receiver catalog name conflicts with reserved journal names"));
        }
        let parent = path.parent().ok_or_else(|| invalid("receiver catalog parent required"))?;
        let expected_directory = directory_id(parent)?;
        let directory = OpenOptions::new().read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK).open(parent)?;
        let held = directory.metadata()?;
        if (held.dev(), held.ino()) != expected_directory {
            return Err(invalid("receiver catalog directory changed"));
        }
        if let Some((keys, wal_bytes)) = create {
            if !(1..=65_536).contains(&keys) || wal_bytes < 96 {
                return Err(invalid("invalid persistent receiver catalog budgets"));
            }
            if std::fs::read_dir(parent)?.next().transpose()?.is_some() {
                return Err(invalid("initialize receiver catalog only in an empty directory"));
            }
        }
        let mut file = OpenOptions::new().read(true).write(true).create_new(create.is_some())
            .mode(0o600).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.nlink() != 1 || metadata.permissions().mode() & 0o077 != 0 {
            return Err(invalid("receiver catalog must be a private single-link regular file"));
        }
        file.try_lock().map_err(io::Error::from)?;
        let mut header = [0; HEADER as usize];
        if let Some((keys, wal_bytes)) = create {
            header[..8].copy_from_slice(MAGIC);
            header[8..12].copy_from_slice(&keys.to_be_bytes());
            header[16..24].copy_from_slice(&wal_bytes.to_be_bytes());
            header[24..32].copy_from_slice(&expected_directory.0.to_be_bytes());
            header[32..40].copy_from_slice(&expected_directory.1.to_be_bytes());
            let hash = checksum(&[], &header[..48]);
            header[48..].copy_from_slice(&hash);
            file.write_all(&header)?;
            file.sync_all()?;
            directory.sync_all()?;
        } else { file.read_exact(&mut header)?; }
        let maximum_keys = u32::from_be_bytes(header[8..12].try_into().expect("fixed key limit"));
        let maximum_wal = number(&header, 16);
        if &header[..8] != MAGIC || header[12..16] != [0; 4] || header[40..48] != [0; 8]
            || !(1..=65_536).contains(&maximum_keys) || maximum_wal < 96
            || (number(&header, 24), number(&header, 32)) != expected_directory
            || header[48..] != checksum(&[], &header[..48])
        { return Err(invalid("invalid receiver catalog header")); }
        let length = file.metadata()?.len();
        let maximum_length = HEADER + 2 * u64::from(maximum_keys) * RECORD;
        if length < HEADER || length > maximum_length || (length - HEADER) % RECORD != 0 {
            return Err(invalid("torn or oversized receiver catalog"));
        }
        let mut state = State { file, entries: BTreeMap::new(), records: 0,
            reserved_wal: 0, hash: header[48..].try_into().expect("fixed header hash"), poisoned: false };
        while HEADER + state.records * RECORD < length {
            let mut record = [0; RECORD as usize];
            state.file.read_exact(&mut record)?;
            if number(&record, 0) != state.records || record[9..16] != [0; 7]
                || record[125..128] != [0; 3] || record[BODY..] != checksum(&state.hash, &record[..BODY])
            { return Err(invalid("invalid receiver catalog record")); }
            let entry = Entry {
                id: number(&record, 16),
                key: ResumeSessionKey {
                    client: NativeClientCertificateId::from_sha256(record[24..56].try_into().expect("fixed client")),
                    nonce: record[56..88].try_into().expect("fixed nonce"),
                },
                directory: (number(&record, 88), number(&record, 96)),
                policy: FilePolicy { data_bytes: number(&record, 104), journal_bytes: number(&record, 112),
                    snapshots: u32::from_be_bytes(record[120..124].try_into().expect("fixed snapshots")) },
                retired: Retirement::decode(record[124])?,
            };
            entry.policy.validate()?;
            match record[8] {
                1 if entry.retired.is_none() && entry.id == state.entries.len() as u64
                    && state.entries.len() < maximum_keys as usize && !state.entries.contains_key(&entry.key) => {
                    state.reserved_wal = state.reserved_wal.checked_add(entry.policy.journal_bytes)
                        .filter(|bytes| *bytes <= maximum_wal)
                        .ok_or_else(|| invalid("receiver catalog WAL budget exceeded"))?;
                    state.entries.insert(entry.key, entry);
                }
                2 if entry.retired.is_some() => {
                    let old = state.entries.get_mut(&entry.key)
                        .ok_or_else(|| invalid("retirement without receiver catalog claim"))?;
                    let mut expected = old.clone(); expected.retired = entry.retired;
                    if old.retired.is_some() || expected != entry {
                        return Err(invalid("receiver catalog retirement changed its claim"));
                    }
                    *old = entry;
                }
                _ => return Err(invalid("illegal receiver catalog transition")),
            }
            state.hash = record[BODY..].try_into().expect("fixed record hash");
            state.records += 1;
        }
        let catalog = Self { path: path.to_owned(), directory, maximum_keys, maximum_wal,
            state: Mutex::new(state), failed: AtomicBool::new(false) };
        {
            let state = catalog.state.lock();
            catalog.verify(&state.file)?;
            catalog.census(&state)?;
            state.file.sync_all()?;
            catalog.directory.sync_all()?;
        }
        Ok(catalog)
    }

    fn verify(&self, file: &File) -> io::Result<()> {
        let held = file.metadata()?;
        let named = std::fs::symlink_metadata(&self.path)?;
        let directory = self.directory.metadata()?;
        if !held.is_file() || !named.is_file() || held.nlink() != 1
            || held.permissions().mode() & 0o077 != 0
            || (held.dev(), held.ino()) != (named.dev(), named.ino())
            || directory_id(self.parent())? != (directory.dev(), directory.ino())
        { return Err(invalid("receiver catalog identity or permissions changed")); }
        Ok(())
    }
    fn census(&self, state: &State) -> io::Result<()> {
        let by_name: BTreeMap<_, _> = state.entries.values().map(|entry| (entry.wal_name(), entry)).collect();
        let mut count = 0;
        for item in std::fs::read_dir(self.parent())? {
            let item = item?; count += 1;
            if count > state.entries.len() + 1 { return Err(invalid("untracked receiver catalog files")); }
            if item.file_name() == self.path.file_name().expect("catalog filename") { continue; }
            let name = item.file_name();
            let entry = name.to_str().and_then(|name| by_name.get(name))
                .ok_or_else(|| invalid("unknown file in dedicated receiver WAL directory"))?;
            let metadata = std::fs::symlink_metadata(item.path())?;
            if !metadata.is_file() || metadata.nlink() != 1 || metadata.permissions().mode() & 0o077 != 0
                || metadata.len() > entry.policy.journal_bytes
            { return Err(invalid("receiver catalog contains an invalid WAL file")); }
        }
        Ok(())
    }
    pub fn parent(&self) -> &Path { self.path.parent().expect("validated catalog parent") }
    pub fn wal_path(&self, entry: &Entry) -> PathBuf { self.parent().join(entry.wal_name()) }
    pub fn maximum_keys(&self) -> u32 { self.maximum_keys }
    pub fn maximum_wal(&self) -> u64 { self.maximum_wal }
    pub fn failed(&self) -> bool { self.failed.load(Ordering::Acquire) }
    /// Before runtime startup or in a blocking worker, never on a latency-sensitive poll.
    pub fn entries(&self) -> Vec<Entry> { self.state.lock().entries.values().cloned().collect() }

    /// Called on the blocking pool after authenticated registry admission.
    pub fn admit(&self, key: ResumeSessionKey, directory: &Path, policy: FilePolicy) -> io::Result<(Entry, bool)> {
        policy.validate()?;
        let directory = directory_id(directory)?;
        let mut state = self.state.lock();
        self.check_current(&mut state)?;
        if let Some(entry) = state.entries.get(&key) {
            if entry.retired.is_some() { return Err(io::Error::from(io::ErrorKind::PermissionDenied)); }
            if entry.directory != directory { return Err(invalid("receiver catalog inbox identity changed")); }
            return Ok((entry.clone(), false));
        }
        let reserved = state.reserved_wal.checked_add(policy.journal_bytes)
            .filter(|bytes| *bytes <= self.maximum_wal);
        if state.entries.len() >= self.maximum_keys as usize || reserved.is_none() {
            return Err(io::Error::from(io::ErrorKind::StorageFull));
        }
        let entry = Entry { id: state.entries.len() as u64, key, directory, policy, retired: None };
        self.append(&mut state, &entry, 1)?;
        state.reserved_wal = reserved.expect("checked reservation");
        state.entries.insert(key, entry.clone());
        Ok((entry, true))
    }

    /// Persist a denial before releasing an idle sink. Unknown keys have no files.
    /// Retired reservations are never refunded and duplicate retirement is idempotent.
    pub fn retire(&self, key: ResumeSessionKey, reason: Retirement) -> io::Result<bool> {
        let mut state = self.state.lock();
        self.check_current(&mut state)?;
        let Some(mut entry) = state.entries.get(&key).cloned() else { return Ok(false); };
        if entry.retired.is_some() { return Ok(false); }
        entry.retired = Some(reason);
        self.append(&mut state, &entry, 2)?;
        state.entries.insert(key, entry);
        Ok(true)
    }

    fn check_current(&self, state: &mut State) -> io::Result<()> {
        if state.poisoned { return Err(io::Error::other("receiver catalog persistence unconfirmed")); }
        let result = self.verify(&state.file).and_then(|()| {
            if state.file.metadata()?.len() != HEADER + state.records * RECORD {
                return Err(invalid("receiver catalog length changed"));
            }
            Ok(())
        });
        if result.is_err() {
            state.poisoned = true;
            self.failed.store(true, Ordering::Release);
        }
        result
    }

    fn append(&self, state: &mut State, entry: &Entry, kind: u8) -> io::Result<()> {
        struct Failure<'a>(&'a AtomicBool, bool);
        impl Drop for Failure<'_> {
            fn drop(&mut self) { if self.1 { self.0.store(true, Ordering::Release); } }
        }
        let mut failure = Failure(&self.failed, true);
        state.poisoned = true;
        self.verify(&state.file)?;
        if state.file.metadata()?.len() != HEADER + state.records * RECORD
            || state.records >= 2 * u64::from(self.maximum_keys)
        { return Err(invalid("receiver catalog length changed")); }
        let mut record = [0; RECORD as usize];
        record[..8].copy_from_slice(&state.records.to_be_bytes()); record[8] = kind;
        record[16..24].copy_from_slice(&entry.id.to_be_bytes());
        record[24..56].copy_from_slice(entry.key.client.as_bytes()); record[56..88].copy_from_slice(&entry.key.nonce);
        for (at, value) in [(88, entry.directory.0), (96, entry.directory.1),
            (104, entry.policy.data_bytes), (112, entry.policy.journal_bytes)] {
            record[at..at + 8].copy_from_slice(&value.to_be_bytes());
        }
        record[120..124].copy_from_slice(&entry.policy.snapshots.to_be_bytes());
        record[124] = entry.retired.map_or(0, |reason| reason as u8);
        let hash = checksum(&state.hash, &record[..BODY]); record[BODY..].copy_from_slice(&hash);
        state.file.seek(SeekFrom::End(0))?; state.file.write_all(&record)?;
        state.file.sync_all()?; self.directory.sync_all()?;
        self.verify(&state.file)?;
        state.hash = hash; state.records += 1; state.poisoned = false; failure.1 = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (PathBuf, PathBuf) {
        let root = tempfile::tempdir().unwrap().keep();
        let catalog = root.join("state"); let inbox = root.join("inbox");
        for path in [&catalog, &inbox] {
            std::fs::create_dir(path).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        (catalog.join("catalog.log"), inbox)
    }
    fn key(n: u8) -> ResumeSessionKey {
        ResumeSessionKey { client: NativeClientCertificateId::from_sha256([1; 32]), nonce: [n; 32] }
    }
    fn policy() -> FilePolicy { FilePolicy { data_bytes: 64, journal_bytes: 4096, snapshots: 16 } }

    #[test]
    fn claims_and_retirement_survive_restart_without_reusing_names_or_budgets() {
        let (path, inbox) = fixture(); Catalog::initialize(&path, 3, 8192).unwrap();
        let catalog = Catalog::open(&path).unwrap();
        let (first, fresh) = catalog.admit(key(1), &inbox, policy()).unwrap(); assert!(fresh);
        let before = std::fs::read(&path).unwrap();
        let (again, fresh) = catalog.admit(key(1), &inbox, FilePolicy { data_bytes: 128, ..policy() }).unwrap();
        assert!(!fresh); assert_eq!(again, first); assert_eq!(std::fs::read(&path).unwrap(), before);
        assert!(catalog.retire(key(1), Retirement::Idle).unwrap());
        assert!(!catalog.retire(key(1), Retirement::Revoked).unwrap());
        drop(catalog);
        let catalog = Catalog::open(&path).unwrap();
        assert_eq!(catalog.admit(key(1), &inbox, policy()).unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        let (second, fresh) = catalog.admit(key(2), &inbox, policy()).unwrap(); assert!(fresh);
        assert_ne!(first.data_path(&inbox), second.data_path(&inbox));
        assert_eq!(catalog.admit(key(3), &inbox, policy()).unwrap_err().kind(), io::ErrorKind::StorageFull);
        assert_eq!(catalog.entries()[0].retired, Some(Retirement::Idle));
        assert_eq!(std::fs::metadata(&path).unwrap().len(), HEADER + 3 * RECORD);
        assert!(std::fs::read_dir(inbox).unwrap().next().is_none());
    }

    #[test]
    fn exact_client_and_inbox_identity_are_part_of_the_claim() {
        let (path, inbox) = fixture(); Catalog::initialize(&path, 4, 16384).unwrap();
        let catalog = Catalog::open(&path).unwrap();
        let (first, _) = catalog.admit(key(1), &inbox, policy()).unwrap();
        let other = ResumeSessionKey { client: NativeClientCertificateId::from_sha256([2; 32]), ..key(1) };
        let (second, _) = catalog.admit(other, &inbox, policy()).unwrap(); assert_ne!(first.id, second.id);
        let (_, changed_directory) = fixture();
        assert!(catalog.admit(key(1), &changed_directory, policy()).is_err());
        assert_eq!(catalog.entries().len(), 2);
    }

    #[test]
    fn missing_torn_unknown_and_exclusively_owned_history_never_becomes_empty() {
        let (path, inbox) = fixture(); assert!(Catalog::open(&path).is_err()); assert!(!path.exists());
        Catalog::initialize(&path, 2, 8192).unwrap(); let catalog = Catalog::open(&path).unwrap();
        assert!(Catalog::open(&path).is_err()); assert!(Catalog::initialize(&path, 2, 8192).is_err());
        catalog.admit(key(1), &inbox, policy()).unwrap(); drop(catalog);
        let mut file = OpenOptions::new().append(true).open(&path).unwrap(); file.write_all(&[0]).unwrap(); file.sync_all().unwrap();
        let broken = std::fs::read(&path).unwrap(); assert!(Catalog::open(&path).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), broken);
        let (other, _) = fixture(); Catalog::initialize(&other, 2, 8192).unwrap();
        std::fs::write(other.parent().unwrap().join("untracked"), b"keep").unwrap();
        assert!(Catalog::open(&other).is_err());
    }

    #[test]
    fn append_uncertainty_poison_is_sticky_but_admission_limits_are_not() {
        let (path, inbox) = fixture(); Catalog::initialize(&path, 2, 8192).unwrap();
        let catalog = Catalog::open(&path).unwrap(); catalog.admit(key(1), &inbox, policy()).unwrap();
        let mut file = OpenOptions::new().append(true).open(&path).unwrap(); file.write_all(&[0]).unwrap(); file.sync_all().unwrap();
        assert!(catalog.retire(key(1), Retirement::LocalFailure).is_err()); assert!(catalog.failed());
        assert!(catalog.admit(key(2), &inbox, policy()).is_err());
        assert!(catalog.admit(key(1), &inbox, policy()).is_err());
        assert_eq!(catalog.entries().len(), 1);
        let (path, inbox) = fixture(); Catalog::initialize(&path, 1, 4096).unwrap();
        let catalog = Catalog::open(&path).unwrap(); catalog.admit(key(1), &inbox, policy()).unwrap();
        assert!(catalog.admit(key(2), &inbox, policy()).is_err()); assert!(!catalog.failed());
        assert!(!catalog.admit(key(1), &inbox, policy()).unwrap().1);
    }

    #[test]
    fn directory_census_accepts_only_bounded_claimed_wals() {
        let (path, inbox) = fixture(); Catalog::initialize(&path, 2, 8192).unwrap();
        let catalog = Catalog::open(&path).unwrap(); let (entry, _) = catalog.admit(key(1), &inbox, policy()).unwrap();
        let wal = catalog.wal_path(&entry);
        OpenOptions::new().write(true).create_new(true).mode(0o600).open(&wal).unwrap(); drop(catalog);
        // A header-only/empty claimed WAL is not validated here. Admission must
        // still refuse it through ReceiverJournalFile::open_existing, never recreate it.
        assert!(Catalog::open(&path).is_ok());
        OpenOptions::new().write(true).open(&wal).unwrap().set_len(4097).unwrap();
        assert!(Catalog::open(&path).is_err());
    }

    #[test]
    fn decoding_rejects_changed_checksums_and_nonprivate_catalogs() {
        let (path, inbox) = fixture(); Catalog::initialize(&path, 2, 8192).unwrap();
        let catalog = Catalog::open(&path).unwrap(); catalog.admit(key(1), &inbox, policy()).unwrap(); drop(catalog);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(Catalog::open(&path).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut file = OpenOptions::new().write(true).open(&path).unwrap();
        file.seek(SeekFrom::Start(HEADER + 56)).unwrap(); file.write_all(&[99]).unwrap(); file.sync_all().unwrap();
        let corrupted = std::fs::read(&path).unwrap(); assert!(Catalog::open(&path).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), corrupted);
    }
}
