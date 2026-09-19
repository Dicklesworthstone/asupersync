use super::*;
use crate::security::SecurityContext;
use crate::types::symbol::Symbol;
use std::fs::OpenOptions;
use std::io::Cursor;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Default)]
struct FaultFile {
    bytes: Cursor<Vec<u8>>,
    write_budget: Option<usize>,
    fail_sync: bool,
    panic_sync: bool,
    syncs: usize,
}
impl Read for FaultFile {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> { self.bytes.read(out) }
}
impl Seek for FaultFile {
    fn seek(&mut self, at: SeekFrom) -> io::Result<u64> { self.bytes.seek(at) }
}
impl Write for FaultFile {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        let n = if let Some(left) = &mut self.write_budget {
            if *left == 0 { return Err(io::Error::other("injected write failure")); }
            let n = (*left).min(input.len());
            *left -= n;
            n
        } else { input.len() };
        self.bytes.write(&input[..n])
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}
impl JournalIo for FaultFile {
    fn length(&self) -> io::Result<u64> { Ok(self.bytes.get_ref().len() as u64) }
    fn sync(&mut self) -> io::Result<()> {
        self.syncs += 1;
        assert!(!self.panic_sync, "injected sync panic");
        if self.fail_sync { Err(io::Error::other("injected sync failure")) } else { Ok(()) }
    }
}
fn limits() -> DurableSymbolLimits {
    DurableSymbolLimits {
        batch: SymbolBatchLimits { max_encoded_bytes: 4096, max_symbols: 16,
            max_payload_bytes: 1024, max_decoded_bytes: 4096 },
        store: SymbolStoreLimits { max_batches: 8, max_bytes: 32768,
            max_batches_per_peer: 4, max_bytes_per_peer: 16384 },
        max_journal_bytes: 65536,
    }
}
fn batch(object: u64, payload: &[u8]) -> EncodedSymbolBatch {
    let security = SecurityContext::new(AuthKey::from_seed(42));
    let symbols = [security.sign_symbol(&Symbol::new_for_test(object, 0, 0, payload))];
    super::super::encode_symbol_batch(&symbols, limits().batch).unwrap()
}
fn journal() -> Journal<FaultFile> {
    Journal::create(FaultFile::default(), "replica", AuthKey::from_seed(42),
        AuthKey::from_seed(99), limits()).unwrap()
}
fn reopen(bytes: Vec<u8>, bounds: DurableSymbolLimits) -> Result<Journal<FaultFile>, DurableSymbolError> {
    Journal::open(FaultFile { bytes: Cursor::new(bytes), ..Default::default() }, "replica",
        AuthKey::from_seed(42), AuthKey::from_seed(99), bounds)
}
fn peer() -> NodeId { NodeId::new("origin") }

#[test]
fn commit_requires_sync_and_reopen_rebuilds_exact_namespaces() {
    let mut log = journal();
    assert_eq!(log.file.syncs, 1);
    let first = batch(1, b"durable contents");
    let second = batch(2, b"second object");
    log.put(&peer(), first.as_ref()).unwrap();
    log.put(&peer(), second.as_ref()).unwrap();
    assert_eq!(log.file.syncs, 3);
    let original = log.file.bytes.get_ref().clone();
    let restored = reopen(original.clone(), limits()).unwrap();
    assert_eq!(restored.file.syncs, 1, "recovery syncs before exposure");
    assert_eq!(restored.sequence, 2);
    assert_eq!(restored.get(&peer(), first.key()).unwrap().as_ref().as_ref(), first.as_ref());
    assert!(matches!(restored.get(&NodeId::new("other"), first.key()),
        Err(DurableSymbolError::Store(SymbolStoreError::NotFound))));
    let mut key = first.key(); key.digest[0] ^= 1;
    assert!(restored.get(&peer(), key).is_err());
    assert_eq!(restored.file.bytes.get_ref(), &original);
}

#[test]
fn idempotence_at_exact_capacity_never_appends_and_conflicts_never_overwrite() {
    let mut log = journal();
    let first = batch(1, b"one");
    log.put(&peer(), first.as_ref()).unwrap();
    log.limits.store.max_batches = 1;
    log.limits.store.max_batches_per_peer = 1;
    log.limits.store.max_bytes = first.as_ref().len();
    log.limits.store.max_bytes_per_peer = first.as_ref().len();
    log.limits.max_journal_bytes = log.offset;
    let bytes = log.file.bytes.get_ref().clone();
    let syncs = log.file.syncs;
    log.put(&peer(), first.as_ref()).unwrap();
    assert_eq!(log.file.syncs, syncs);
    assert!(matches!(log.put(&peer(), batch(1, b"different").as_ref()),
        Err(DurableSymbolError::Store(SymbolStoreError::Conflict))));
    assert!(log.put(&peer(), batch(2, b"new").as_ref()).is_err());
    assert_eq!(log.file.bytes.get_ref(), &bytes);
    assert_eq!(log.status, JournalStatus::Writable);
}

#[test]
fn failed_sync_publishes_nothing_and_reopen_resolves_complete_ambiguous_append() {
    let mut log = journal();
    let first = batch(1, b"ambiguous");
    let old_offset = log.offset;
    log.file.fail_sync = true;
    assert!(matches!(log.put(&peer(), first.as_ref()), Err(DurableSymbolError::Io(_))));
    assert_eq!(log.entries.entries.len(), 0);
    assert_eq!(log.offset, old_offset);
    assert_eq!(log.status, JournalStatus::Poisoned);
    assert!(log.get(&peer(), first.key()).is_err());
    assert!(matches!(log.put(&peer(), first.as_ref()), Err(DurableSymbolError::NotWritable(JournalStatus::Poisoned))));
    let recovered = reopen(log.file.bytes.into_inner(), limits()).unwrap();
    assert_eq!(recovered.status, JournalStatus::Writable);
    assert_eq!(recovered.get(&peer(), first.key()).unwrap().as_ref().as_ref(), first.as_ref());
}

#[test]
fn sync_unwind_keeps_owner_poisoned_without_publishing() {
    let mut log = journal();
    log.file.panic_sync = true;
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = log.put(&peer(), batch(1, b"secret").as_ref());
    })).is_err());
    assert_eq!(log.status, JournalStatus::Poisoned);
    assert!(log.entries.entries.is_empty());
}

#[test]
fn partial_write_preserves_committed_prefix_and_reopens_read_only() {
    let mut log = journal();
    let first = batch(1, b"first");
    log.put(&peer(), first.as_ref()).unwrap();
    let committed = log.offset;
    log.file.write_budget = Some(PREFIX_BYTES + 5);
    assert!(log.put(&peer(), batch(2, b"interrupted").as_ref()).is_err());
    assert_eq!(log.entries.entries.len(), 1);
    let bytes = log.file.bytes.into_inner();
    let mut restored = reopen(bytes.clone(), limits()).unwrap();
    assert_eq!(restored.status, JournalStatus::ReadOnlyTail);
    assert_eq!(restored.offset, committed);
    assert!(restored.get(&peer(), first.key()).is_ok());
    // Existing durable bytes remain an idempotent result even with a torn tail.
    restored.put(&peer(), first.as_ref()).unwrap();
    assert!(matches!(restored.put(&peer(), batch(3, b"new").as_ref()),
        Err(DurableSymbolError::NotWritable(JournalStatus::ReadOnlyTail))));
    assert_eq!(restored.file.bytes.get_ref(), &bytes, "no repair, truncation or append");
}

#[test]
fn every_incomplete_last_record_preserves_only_the_complete_prefix() {
    let mut log = journal();
    let first = batch(1, b"first");
    let second = batch(2, b"second");
    log.put(&peer(), first.as_ref()).unwrap();
    let first_end = log.offset as usize;
    log.put(&peer(), second.as_ref()).unwrap();
    let bytes = log.file.bytes.into_inner();
    for cut in first_end + 1..bytes.len() {
        let recovered = reopen(bytes[..cut].to_vec(), limits()).unwrap();
        assert_eq!(recovered.status, JournalStatus::ReadOnlyTail, "cut {cut}");
        assert_eq!(recovered.offset, first_end as u64);
        assert_eq!(recovered.entries.entries.len(), 1);
        assert!(recovered.get(&peer(), first.key()).is_ok());
        assert!(recovered.get(&peer(), second.key()).is_err());
        assert_eq!(recovered.file.bytes.get_ref(), &bytes[..cut]);
    }
}

#[test]
fn every_single_bit_mutation_in_a_complete_record_is_refused_including_lengths() {
    let mut log = journal();
    let header_end = log.offset as usize;
    log.put(&peer(), batch(1, b"authenticated payload").as_ref()).unwrap();
    let bytes = log.file.bytes.into_inner();
    for index in header_end..bytes.len() {
        for bit in 0..8 {
            let mut changed = bytes.clone(); changed[index] ^= 1 << bit;
            assert!(reopen(changed, limits()).is_err(), "byte {index} bit {bit}");
        }
    }
}

#[test]
fn wrong_journal_key_replica_and_symbol_key_refuse_recovery() {
    let mut log = journal();
    log.put(&peer(), batch(1, b"one").as_ref()).unwrap();
    let bytes = log.file.bytes.into_inner();
    for (replica, symbols, journal) in [("other", 42, 99), ("replica", 43, 99), ("replica", 42, 100)] {
        let result = Journal::open(FaultFile { bytes: Cursor::new(bytes.clone()), ..Default::default() },
            replica, AuthKey::from_seed(symbols), AuthKey::from_seed(journal), limits());
        assert!(result.is_err());
    }
}

#[test]
fn reordered_and_duplicated_authenticated_records_do_not_form_a_valid_chain() {
    let mut log = journal(); let h = log.offset as usize;
    log.put(&peer(), batch(1, b"a").as_ref()).unwrap(); let first_end = log.offset as usize;
    log.put(&peer(), batch(2, b"b").as_ref()).unwrap();
    let bytes = log.file.bytes.into_inner();
    let mut reordered = bytes[..h].to_vec();
    reordered.extend_from_slice(&bytes[first_end..]); reordered.extend_from_slice(&bytes[h..first_end]);
    assert!(reopen(reordered, limits()).is_err());
    let mut duplicated = bytes[..first_end].to_vec(); duplicated.extend_from_slice(&bytes[h..first_end]);
    assert!(reopen(duplicated, limits()).is_err());
}

#[test]
fn each_quota_refuses_before_mutation_and_applies_again_on_reopen() {
    let first = batch(1, b"bounded");
    for field in 0..5 {
        let mut log = journal();
        match field {
            0 => log.limits.store.max_batches = 0,
            1 => log.limits.store.max_batches_per_peer = 0,
            2 => log.limits.store.max_bytes = first.as_ref().len() - 1,
            3 => log.limits.store.max_bytes_per_peer = first.as_ref().len() - 1,
            _ => log.limits.max_journal_bytes = log.offset,
        }
        let before = log.file.bytes.get_ref().clone();
        assert!(log.put(&peer(), first.as_ref()).is_err());
        assert_eq!(log.file.bytes.get_ref(), &before);
        assert_eq!(log.status, JournalStatus::Writable);
    }
    let mut log = journal(); log.put(&peer(), first.as_ref()).unwrap();
    let bytes = log.file.bytes.into_inner();
    let mut bounds = limits(); bounds.store.max_batches = 0;
    assert!(reopen(bytes.clone(), bounds).is_err());
    bounds = limits(); bounds.max_journal_bytes = bytes.len() as u64 - 1;
    assert!(matches!(reopen(bytes, bounds), Err(DurableSymbolError::JournalLimit)));
}

#[test]
fn distinct_authenticated_origins_have_separate_immutable_object_keys() {
    let mut log = journal();
    log.limits.store.max_batches_per_peer = 1;
    let first = batch(1, b"origin-one"); let second = batch(1, b"origin-two");
    let other = NodeId::new("other");
    log.put(&peer(), first.as_ref()).unwrap(); log.put(&other, second.as_ref()).unwrap();
    let recovered = reopen(log.file.bytes.into_inner(), limits()).unwrap();
    assert!(recovered.get(&peer(), first.key()).is_ok());
    assert!(recovered.get(&other, second.key()).is_ok());
    assert!(recovered.get(&peer(), second.key()).is_err());
}

#[test]
fn corruption_and_failed_recovery_sync_never_expose_a_store() {
    let mut log = journal(); log.put(&peer(), batch(1, b"one").as_ref()).unwrap();
    let bytes = log.file.bytes.into_inner();
    let bad = FaultFile { bytes: Cursor::new(bytes), fail_sync: true, ..Default::default() };
    assert!(matches!(Journal::open(bad, "replica", AuthKey::from_seed(42), AuthKey::from_seed(99), limits()),
        Err(DurableSymbolError::Io(_))));
    let mut log = journal(); let before = log.file.bytes.get_ref().clone();
    let mut bad = batch(1, b"one").as_ref().to_vec(); let n = bad.len(); bad[n - 1] ^= 1;
    assert!(matches!(log.put(&peer(), &bad), Err(DurableSymbolError::Store(SymbolStoreError::Authentication))));
    assert_eq!(log.file.bytes.get_ref(), &before);
}

#[test]
fn unexpected_external_growth_poisoning_does_not_publish_an_append() {
    let mut log = journal();
    log.file.bytes.get_mut().push(0);
    let bytes = log.file.bytes.get_ref().clone();
    assert!(matches!(log.put(&peer(), batch(1, b"one").as_ref()), Err(DurableSymbolError::Changed)));
    assert_eq!(log.status, JournalStatus::Poisoned);
    assert_eq!(log.file.bytes.get_ref(), &bytes);
}

// Retain owned test artifacts deliberately. No TempDir cleanup or file deletion.
fn owned_file() -> (PathBuf, File) {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    loop {
        let path = std::env::temp_dir().join(format!("asupersync-symbol-journal-{}-{}",
            std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        match OpenOptions::new().read(true).write(true).create_new(true).open(&path) {
            Ok(file) => return (path, file),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => panic!("create owned journal: {error}"),
        }
    }
}
fn file_at(path: &PathBuf) -> File { OpenOptions::new().read(true).write(true).open(path).unwrap() }

#[test]
fn actual_file_reopens_with_exact_batches_and_exclusive_lock() {
    let (path, file) = owned_file();
    let store = DurableSymbolReplicaStore::create(file, "replica", AuthKey::from_seed(42),
        AuthKey::from_seed(99), limits()).unwrap();
    let first = batch(1, b"actual disk data");
    store.put(&peer(), first.as_ref()).unwrap();
    let committed = store.committed_bytes();
    assert!(matches!(DurableSymbolReplicaStore::open(file_at(&path), "replica", AuthKey::from_seed(42),
        AuthKey::from_seed(99), limits()), Err(DurableSymbolError::Locked)));
    drop(store);
    let restored = DurableSymbolReplicaStore::open(file_at(&path), "replica", AuthKey::from_seed(42),
        AuthKey::from_seed(99), limits()).unwrap();
    assert_eq!(restored.get(&peer(), first.key()).unwrap().as_ref().as_ref(), first.as_ref());
    assert_eq!(restored.committed_bytes(), committed);
    assert_eq!(restored.status(), JournalStatus::Writable);
    assert!(!format!("{restored:?}").contains("actual disk data"));
}

#[test]
fn actual_nonempty_file_is_never_reinitialized_or_truncated() {
    let (path, mut file) = owned_file();
    file.write_all(b"existing unrelated data").unwrap(); file.sync_all().unwrap();
    assert!(matches!(DurableSymbolReplicaStore::create(file, "replica", AuthKey::from_seed(42),
        AuthKey::from_seed(99), limits()), Err(DurableSymbolError::NotEmpty)));
    assert_eq!(std::fs::read(path).unwrap(), b"existing unrelated data");
}

#[test]
fn actual_file_torn_tail_is_preserved_and_committed_data_is_readable() {
    let (path, file) = owned_file();
    let first = batch(1, b"first");
    let store = DurableSymbolReplicaStore::create(file, "replica", AuthKey::from_seed(42),
        AuthKey::from_seed(99), limits()).unwrap();
    store.put(&peer(), first.as_ref()).unwrap(); drop(store);
    let mut writer = OpenOptions::new().append(true).open(&path).unwrap();
    writer.write_all(&[1, 2, 3]).unwrap(); writer.sync_all().unwrap(); drop(writer);
    let before = std::fs::read(&path).unwrap();
    let store = DurableSymbolReplicaStore::open(file_at(&path), "replica", AuthKey::from_seed(42),
        AuthKey::from_seed(99), limits()).unwrap();
    assert_eq!(store.status(), JournalStatus::ReadOnlyTail);
    assert!(store.get(&peer(), first.key()).is_ok());
    assert!(store.put(&peer(), batch(2, b"new").as_ref()).is_err());
    drop(store);
    assert_eq!(std::fs::read(path).unwrap(), before);
}
