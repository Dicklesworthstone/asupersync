use super::*;
use crate::distributed::membership::{MembershipEvent, MembershipKind};
use crate::distributed::membership::authority::MembershipUpdate;
use std::fs::OpenOptions;
use std::io::Cursor;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Default)]
struct FaultFile { bytes: Cursor<Vec<u8>>, budget: Option<usize>, fail_sync: bool, panic_sync: bool, syncs: usize }
impl Read for FaultFile { fn read(&mut self, out: &mut [u8]) -> io::Result<usize> { self.bytes.read(out) } }
impl Seek for FaultFile { fn seek(&mut self, at: SeekFrom) -> io::Result<u64> { self.bytes.seek(at) } }
impl Write for FaultFile {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        let n = if let Some(left) = &mut self.budget {
            if *left == 0 { return Err(io::Error::other("injected write failure")); }
            let n = (*left).min(input.len()); *left -= n; n
        } else { input.len() };
        self.bytes.write(&input[..n])
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}
impl JournalIo for FaultFile {
    fn length(&self) -> io::Result<u64> { Ok(self.bytes.get_ref().len() as u64) }
    fn sync(&mut self) -> io::Result<()> {
        self.syncs += 1; assert!(!self.panic_sync, "injected sync panic");
        if self.fail_sync { Err(io::Error::other("injected sync failure")) } else { Ok(()) }
    }
}
fn config() -> MembershipJournalConfig {
    MembershipJournalConfig {
        authority: NodeId::new("authority"), epoch: 7,
        statement_key: AuthKey::from_seed(42), journal_key: AuthKey::from_seed(99),
        floors: vec![MembershipFloor { node: node(), incarnation: 0, sequence: 0 }],
        controller_limits: MembershipControllerLimits { max_members: 4, max_lease_ids: 8 },
        max_journal_bytes: 65536,
    }
}
fn node() -> NodeId { NodeId::new("worker") }
fn statement(incarnation: u64, sequence: u64, kind: MembershipKind) -> Vec<u8> {
    MembershipUpdate { event: MembershipEvent { node: node(), incarnation, kind }, sequence }
        .authenticated_bytes(&NodeId::new("authority"), 7, &AuthKey::from_seed(42)).unwrap()
}
fn log() -> Journal<FaultFile> { Journal::create(FaultFile::default(), config()).unwrap() }
fn reopen(bytes: Vec<u8>) -> Result<Journal<FaultFile>, MembershipJournalError> {
    Journal::open(FaultFile { bytes: Cursor::new(bytes), ..Default::default() }, config())
}

#[test]
fn restart_retains_terminal_state_and_requires_fresh_incarnation() {
    let mut log = log(); let alive = statement(1, 1, MembershipKind::Alive);
    let dead = statement(1, 2, MembershipKind::Dead);
    log.append(&alive).unwrap(); log.append(&dead).unwrap();
    assert_eq!(log.file.syncs, 3);
    let mut restored = reopen(log.file.bytes.into_inner()).unwrap();
    assert_eq!(restored.file.syncs, 1);
    assert_eq!(restored.policy.stamp(&node()).unwrap().kind, MembershipKind::Dead);
    assert!(matches!(restored.append(&alive), Err(MembershipJournalError::Control(MembershipControlError::Stale))));
    assert!(matches!(restored.append(&statement(1, 3, MembershipKind::Alive)),
        Err(MembershipJournalError::Control(MembershipControlError::Terminal))));
    restored.append(&statement(2, 3, MembershipKind::Alive)).unwrap();
    assert!(matches!(restored.append(&statement(1, 4, MembershipKind::Dead)),
        Err(MembershipJournalError::Control(MembershipControlError::Stale))));
    assert_eq!(restored.policy.stamp(&node()).unwrap().incarnation, 2);
}

#[test]
fn latest_duplicate_is_idempotent_at_capacity_but_conflict_cannot_append() {
    let mut log = log(); let alive = statement(1, 1, MembershipKind::Alive);
    log.append(&alive).unwrap(); log.config.max_journal_bytes = log.offset;
    let before = log.file.bytes.get_ref().clone(); let syncs = log.file.syncs;
    assert_eq!(log.append(&alive).unwrap(), MembershipApplied::Duplicate);
    assert!(matches!(log.append(&statement(1, 1, MembershipKind::Dead)),
        Err(MembershipJournalError::Control(MembershipControlError::Conflict))));
    assert!(matches!(log.append(&statement(1, 2, MembershipKind::Dead)), Err(MembershipJournalError::Limit)));
    assert_eq!(log.file.bytes.get_ref(), &before); assert_eq!(log.file.syncs, syncs);
}

#[test]
fn failed_sync_does_not_publish_but_reopen_resolves_an_ambiguous_append() {
    let mut log = log(); let offset = log.offset;
    log.file.fail_sync = true;
    assert!(matches!(log.append(&statement(1, 1, MembershipKind::Dead)), Err(MembershipJournalError::Io(_))));
    assert_eq!(log.offset, offset); assert!(log.policy.stamp(&node()).is_none());
    assert_eq!(log.status, MembershipJournalStatus::Poisoned);
    assert!(matches!(log.append(&statement(2, 2, MembershipKind::Alive)), Err(MembershipJournalError::NotWritable(_))));
    let restored = reopen(log.file.bytes.into_inner()).unwrap();
    assert_eq!(restored.policy.stamp(&node()).unwrap().kind, MembershipKind::Dead);
}

#[test]
fn sync_panic_poisoning_prevents_volatile_success() {
    let mut log = log(); log.file.panic_sync = true;
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = log.append(&statement(1, 1, MembershipKind::Alive));
    })).is_err());
    assert_eq!(log.status, MembershipJournalStatus::Poisoned);
    assert!(log.policy.stamp(&node()).is_none());
}

#[test]
fn partial_write_preserves_bytes_and_reopens_read_only() {
    let mut log = log(); let first = statement(1, 1, MembershipKind::Dead);
    log.append(&first).unwrap(); let committed = log.offset;
    log.file.budget = Some(PREFIX + 3);
    assert!(log.append(&statement(2, 2, MembershipKind::Alive)).is_err());
    let bytes = log.file.bytes.into_inner(); let mut restored = reopen(bytes.clone()).unwrap();
    assert_eq!(restored.offset, committed); assert_eq!(restored.status, MembershipJournalStatus::ReadOnlyTail);
    assert_eq!(restored.append(&first).unwrap(), MembershipApplied::Duplicate);
    assert!(matches!(restored.append(&statement(2, 2, MembershipKind::Alive)), Err(MembershipJournalError::NotWritable(_))));
    assert_eq!(restored.file.bytes.get_ref(), &bytes);
}

#[test]
fn every_last_record_truncation_keeps_terminal_prefix_without_repair() {
    let mut log = log(); log.append(&statement(1, 1, MembershipKind::Dead)).unwrap();
    let start = log.offset as usize;
    log.append(&statement(2, 2, MembershipKind::Alive)).unwrap();
    let bytes = log.file.bytes.into_inner();
    for end in start + 1..bytes.len() {
        let restored = reopen(bytes[..end].to_vec()).unwrap();
        assert_eq!(restored.status, MembershipJournalStatus::ReadOnlyTail, "cut {end}");
        assert_eq!(restored.offset, start as u64);
        assert_eq!(restored.policy.stamp(&node()).unwrap().kind, MembershipKind::Dead);
        assert_eq!(restored.file.bytes.get_ref(), &bytes[..end]);
    }
}

#[test]
fn every_complete_file_bit_mutation_is_refused_including_length_prefixes() {
    let mut log = log(); log.append(&statement(1, 1, MembershipKind::Alive)).unwrap();
    let bytes = log.file.bytes.into_inner();
    for index in 0..bytes.len() { for bit in 0..8 {
        let mut changed = bytes.clone(); changed[index] ^= 1 << bit;
        assert!(reopen(changed).is_err(), "byte {index} bit {bit}");
    }}
}

#[test]
fn wrong_keys_authority_epoch_or_initial_floor_cannot_reopen() {
    let mut log = log(); log.append(&statement(1, 1, MembershipKind::Alive)).unwrap();
    let bytes = log.file.bytes.into_inner();
    for variant in 0..6 {
        let mut cfg = config();
        match variant {
            0 => cfg.statement_key = AuthKey::from_seed(43), 1 => cfg.journal_key = AuthKey::from_seed(100),
            2 => cfg.authority = NodeId::new("different"), 3 => cfg.epoch += 1,
            4 => cfg.floors[0].sequence = 1, _ => cfg.floors[0].incarnation = 1,
        }
        assert!(Journal::open(FaultFile { bytes: Cursor::new(bytes.clone()), ..Default::default() }, cfg).is_err());
    }
}

#[test]
fn complete_record_reorder_or_duplication_is_not_an_incomplete_tail() {
    let mut log = log(); let header = log.offset as usize;
    log.append(&statement(1, 1, MembershipKind::Alive)).unwrap(); let one = log.offset as usize;
    log.append(&statement(1, 2, MembershipKind::Dead)).unwrap();
    let bytes = log.file.bytes.into_inner();
    let mut changed = bytes[..header].to_vec(); changed.extend_from_slice(&bytes[one..]); changed.extend_from_slice(&bytes[header..one]);
    assert!(reopen(changed).is_err());
    let mut changed = bytes[..one].to_vec(); changed.extend_from_slice(&bytes[header..one]);
    assert!(reopen(changed).is_err());
}

#[test]
fn rejected_statement_never_changes_file_or_remembered_stamp() {
    let mut log = log(); let alive = statement(1, 1, MembershipKind::Alive);
    let mut bad = alive.clone(); let end = bad.len(); bad[end-1] ^= 1;
    let before = log.file.bytes.get_ref().clone();
    for bytes in [&bad[..], &alive[..alive.len()-1], &[0; MAX_MEMBERSHIP_UPDATE_BYTES + 1][..]] {
        assert!(log.append(bytes).is_err()); assert_eq!(log.file.bytes.get_ref(), &before);
        assert!(log.policy.stamp(&node()).is_none());
    }
}

#[test]
fn header_order_is_canonical_and_members_progress_independently() {
    let mut cfg = config(); cfg.floors.push(MembershipFloor { node: NodeId::new("another"), incarnation: 0, sequence: 0 });
    let header1 = header(&cfg).unwrap(); cfg.floors.reverse(); assert_eq!(&header1[..], &header(&cfg).unwrap()[..]);
    let mut log = Journal::create(FaultFile::default(), cfg).unwrap();
    log.append(&statement(1, 1, MembershipKind::Dead)).unwrap();
    let bytes = MembershipUpdate { event: MembershipEvent { node: NodeId::new("another"), incarnation: 4,
        kind: MembershipKind::Alive }, sequence: 1 }.authenticated_bytes(&NodeId::new("authority"), 7, &AuthKey::from_seed(42)).unwrap();
    log.append(&bytes).unwrap();
    assert_eq!(log.policy.stamp(&node()).unwrap().kind, MembershipKind::Dead);
    assert_eq!(log.latest.len(), 2);
}

#[test]
fn changed_length_and_failed_recovery_sync_fail_closed() {
    let mut log = log(); log.file.bytes.get_mut().push(0);
    assert!(matches!(log.append(&statement(1, 1, MembershipKind::Alive)), Err(MembershipJournalError::Changed)));
    assert_eq!(log.status, MembershipJournalStatus::Poisoned);
    let mut valid = self::log(); valid.append(&statement(1, 1, MembershipKind::Dead)).unwrap();
    let file = FaultFile { bytes: Cursor::new(valid.file.bytes.into_inner()), fail_sync: true, ..Default::default() };
    assert!(matches!(Journal::open(file, config()), Err(MembershipJournalError::Io(_))));
}

// Retain test files deliberately; never delete, truncate, or reset a journal.
fn file() -> (std::path::PathBuf, File) {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    loop {
        let path = std::env::temp_dir().join(format!("asupersync-membership-journal-{}-{}",
            std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        match OpenOptions::new().read(true).write(true).create_new(true).open(&path) {
            Ok(file) => return (path, file),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {},
            Err(error) => panic!("owned journal creation: {error}"),
        }
    }
}
#[test]
fn real_file_locks_and_restores_revocation_after_all_owners_are_dropped() {
    let (path, file) = file(); let mut log = MembershipJournal::create(file, config()).unwrap();
    log.append(&statement(1, 1, MembershipKind::Dead)).unwrap();
    let second = OpenOptions::new().read(true).write(true).open(&path).unwrap();
    assert!(matches!(MembershipJournal::open(second, config()), Err(MembershipJournalError::Locked)));
    drop(log);
    let file = OpenOptions::new().read(true).write(true).open(&path).unwrap();
    let restored = MembershipJournal::open(file, config()).unwrap();
    assert_eq!(restored.stamp(&node()).unwrap().kind, MembershipKind::Dead);
    assert_eq!(restored.records(), 1);
    assert!(!format!("{restored:?}").contains("worker"));
}
#[test]
fn real_nonempty_file_is_never_reinitialized() {
    let (path, mut file) = file(); file.write_all(b"not a journal").unwrap(); file.sync_all().unwrap();
    assert!(matches!(MembershipJournal::create(file, config()), Err(MembershipJournalError::NotEmpty)));
    assert_eq!(std::fs::read(path).unwrap(), b"not a journal");
}
