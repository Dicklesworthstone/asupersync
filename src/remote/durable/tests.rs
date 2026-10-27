use super::*;
use crate::types::CancelReason;
use std::io::Cursor as IoCursor;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Default)]
struct FaultFile {
    bytes: IoCursor<Vec<u8>>,
    budget: Option<usize>,
    fail_sync: bool,
    panic_sync: bool,
    syncs: usize,
}

impl From<Vec<u8>> for FaultFile {
    fn from(bytes: Vec<u8>) -> Self {
        Self {
            bytes: IoCursor::new(bytes),
            ..Self::default()
        }
    }
}

impl Read for FaultFile {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.bytes.read(bytes)
    }
}

impl Seek for FaultFile {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.bytes.seek(position)
    }
}

impl Write for FaultFile {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let length = if let Some(remaining) = &mut self.budget {
            if *remaining == 0 {
                return Err(io::Error::other("injected write failure"));
            }
            let length = (*remaining).min(bytes.len());
            *remaining -= length;
            length
        } else {
            bytes.len()
        };
        self.bytes.write(&bytes[..length])
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl JournalIo for FaultFile {
    fn length(&self) -> io::Result<u64> {
        Ok(self.bytes.get_ref().len() as u64)
    }

    fn sync(&mut self) -> io::Result<()> {
        self.syncs += 1;
        assert!(!self.panic_sync, "injected sync panic");
        if self.fail_sync {
            Err(io::Error::other("injected sync failure"))
        } else {
            Ok(())
        }
    }
}

const COMPUTATION: &str = "durable.test.v1";
const APPLICATION_VERSION: [u8; 32] = [7; 32];

fn limits() -> DurableRemoteLimits {
    DurableRemoteLimits {
        max_entries: 8,
        max_peer_entries: 4,
        max_input_bytes: 2048,
        max_outcome_bytes: 4096,
        max_retained_bytes: 8 * 4096,
        max_journal_bytes: 1 << 20,
        retention_ms: 100,
    }
}

fn config(limits: DurableRemoteLimits) -> Config {
    Config::new::<Vec<u8>, Vec<u8>>(
        COMPUTATION.to_owned(),
        APPLICATION_VERSION,
        AuthKey::from_seed(99),
        limits,
    )
    .unwrap()
}

fn journal(limits: DurableRemoteLimits) -> Journal<FaultFile> {
    Journal::create(FaultFile::default(), config(limits)).unwrap()
}

fn reopen(
    bytes: Vec<u8>,
    limits: DurableRemoteLimits,
) -> Result<Journal<FaultFile>, DurableRemoteError> {
    Journal::open(FaultFile::from(bytes), config(limits))
}

fn key(value: u128) -> IdempotencyKey {
    IdempotencyKey::from_raw(value)
}

fn execute(
    admission: Result<DurableRemoteAdmission, DurableRemoteError>,
) -> DurableRemoteReservation {
    match admission.unwrap() {
        DurableRemoteAdmission::Execute(reservation) => reservation,
        DurableRemoteAdmission::Replay(_) => panic!("expected a new durable reservation"),
    }
}

fn replay(admission: Result<DurableRemoteAdmission, DurableRemoteError>) -> RemoteServiceWireOutcome {
    match admission.unwrap() {
        DurableRemoteAdmission::Replay(outcome) => outcome.into(),
        DurableRemoteAdmission::Execute(_) => panic!("expected an exact durable replay"),
    }
}

fn success() -> RemoteOutcome {
    RemoteOutcome::Success(b"committed-result".to_vec())
}

// The parent module is test-gated; retain that boundary for the source audit too.
#[cfg(test)]
fn linked_file() -> (PathBuf, File) {
    static NEXT_FILE: AtomicU64 = AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "asupersync-remote-durable-{}-{}.journal",
        std::process::id(),
        NEXT_FILE.fetch_add(1, Ordering::Relaxed),
    ));
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(&path).unwrap();
    file.sync_all().unwrap();
    #[cfg(unix)]
    File::open(path.parent().unwrap())
        .unwrap()
        .sync_all()
        .unwrap();
    (path, file)
}

#[cfg(test)]
fn open_file(path: &Path) -> File {
    std::fs::OpenOptions::new().read(true).write(true).open(path).unwrap()
}

#[test]
fn real_file_replays_exact_outcomes_with_peer_isolation_and_exclusive_ownership() {
    let (path, file) = linked_file();
    let mut journal = DurableRemoteJournal::create::<Vec<u8>, Vec<u8>>(
        file,
        COMPUTATION,
        APPLICATION_VERSION,
        AuthKey::from_seed(99),
        limits(),
    )
    .unwrap();
    let alice = NodeId::new("authenticated-alice");
    let bob = NodeId::new("authenticated-bob");
    let private_input = b"raw request plaintext must never be retained in the journal";
    let reservation = execute(journal.admit(&alice, key(1), private_input, 10));
    let first = journal.complete(reservation, success(), 11).unwrap();
    assert_eq!(RemoteServiceWireOutcome::from(first), success().into());
    assert!(matches!(
        journal.admit(&alice, key(1), b"different request", 12),
        Err(DurableRemoteError::Conflict)
    ));
    let reservation = execute(journal.admit(&bob, key(1), b"different request", 12));
    let second = RemoteOutcome::Failed("application refused".to_owned());
    journal.complete(reservation, second.clone(), 13).unwrap();
    let size = journal.committed_bytes();
    assert_eq!(journal.records(), 4);
    assert_eq!(journal.retained_entries(), 2);
    assert_eq!(journal.computation(), COMPUTATION);
    assert_eq!(journal.schema_fingerprint(), config(limits()).schema);
    assert_eq!(journal.limits(), limits());
    assert!(matches!(
        DurableRemoteJournal::open::<Vec<u8>, Vec<u8>>(
            open_file(&path),
            COMPUTATION,
            APPLICATION_VERSION,
            AuthKey::from_seed(99),
            limits(),
        ),
        Err(DurableRemoteError::Locked)
    ));
    drop(journal);
    let original = std::fs::read(&path).unwrap();
    assert!(!original.windows(private_input.len()).any(|bytes| bytes == private_input));

    let mut restored = DurableRemoteJournal::open::<Vec<u8>, Vec<u8>>(
        open_file(&path),
        COMPUTATION,
        APPLICATION_VERSION,
        AuthKey::from_seed(99),
        limits(),
    )
    .unwrap();
    assert_eq!(replay(restored.admit(&alice, key(1), private_input, 14)), success().into());
    assert_eq!(replay(restored.admit(&bob, key(1), b"different request", 14)), second.into());
    assert_eq!(restored.status(), DurableRemoteJournalStatus::Writable);
    assert_eq!(restored.records(), 4);
    assert_eq!(restored.committed_bytes(), size);
    drop(restored);
    assert_eq!(std::fs::read(&path).unwrap(), original);
}

#[test]
fn terminal_expiry_is_exact_but_pending_survives_retention_and_restart() {
    let mut journal = journal(limits());
    let peer = NodeId::new("peer");
    let complete = execute(journal.admit(&peer, key(1), b"original", 10));
    journal.complete(complete, success(), 20).unwrap();
    let _pending = execute(journal.admit(&peer, key(2), b"uncertain", 21));
    assert_eq!(replay(journal.admit(&peer, key(1), b"original", 119)), success().into());
    assert!(matches!(
        journal.admit(&peer, key(2), b"uncertain", 118),
        Err(DurableRemoteError::ClockRegression)
    ));
    // Completion at 20 expires exactly at 120. An unresolved reservation does not.
    let _replacement = execute(journal.admit(&peer, key(1), b"replacement", 120));
    assert!(matches!(
        journal.admit(&peer, key(1), b"original", 120),
        Err(DurableRemoteError::Conflict)
    ));
    let original = journal.file.bytes.get_ref().clone();
    let mut restored = reopen(original.clone(), limits()).unwrap();
    assert!(matches!(
        restored.admit(&peer, key(2), b"uncertain", 119),
        Err(DurableRemoteError::ClockRegression)
    ));
    for value in [1, 2] {
        let input: &[u8] = if value == 1 { b"replacement" } else { b"uncertain" };
        assert!(matches!(
            restored.admit(&peer, key(value), input, 100_000),
            Err(DurableRemoteError::InDoubt)
        ));
    }
    assert_eq!(restored.retained_bytes, 2 * limits().max_outcome_bytes);
    assert_eq!(restored.entries.len(), 2);
    assert_eq!(restored.file.bytes.get_ref(), &original);
    assert!(matches!(
        restored.admit(&peer, key(3), b"clock overflow", u64::MAX),
        Err(DurableRemoteError::Limit)
    ));
    assert_eq!(restored.file.bytes.get_ref(), &original);
}

#[test]
fn pending_reservations_preserve_exact_terminal_capacity_across_reopen() {
    let peer = NodeId::new("peer");
    let exact_outcome = RemoteOutcome::Failed("x".repeat(48));
    let cap = serde_json::to_vec(&RemoteServiceWireOutcome::from(exact_outcome.clone()))
        .unwrap()
        .len();
    for disk_bound in [false, true] {
        for restart in [false, true] {
            let mut bounds = limits();
            bounds.max_outcome_bytes = cap;
            bounds.max_retained_bytes = if disk_bound { 3 * cap } else { 2 * cap };
            let header = config(bounds).header().unwrap().len() as u64;
            let reservation_size = record_size(peer.as_str().len(), RESERVATION_BYTES).unwrap();
            let terminal_size = record_size(peer.as_str().len(), TERMINAL_BYTES + cap).unwrap();
            let slots = if disk_bound { 2 } else { 3 };
            bounds.max_journal_bytes = header + slots * (reservation_size + terminal_size);
            let mut journal = journal(bounds);
            let mut first = Some(execute(journal.admit(&peer, key(1), b"one", 1)));
            if restart {
                journal = reopen(journal.file.bytes.into_inner(), bounds).unwrap();
                assert!(matches!(
                    journal.complete(first.take().unwrap(), exact_outcome.clone(), 1),
                    Err(DurableRemoteError::InvalidReservation)
                ));
            }
            let second = execute(journal.admit(&peer, key(2), b"two", 2));
            assert_eq!(journal.retained_bytes, 2 * cap);
            assert_eq!(journal.reserved_terminal_bytes, 2 * terminal_size);
            let before = journal.file.bytes.get_ref().clone();
            assert!(matches!(
                journal.admit(&peer, key(3), b"three", 3),
                Err(DurableRemoteError::Limit)
            ));
            assert_eq!(journal.file.bytes.get_ref(), &before);
            let completed = journal.complete(second, exact_outcome.clone(), 3).unwrap();
            assert_eq!(RemoteServiceWireOutcome::from(completed), exact_outcome.clone().into());
            assert_eq!(journal.reserved_terminal_bytes, terminal_size);
            assert_eq!(journal.retained_bytes, 2 * cap);
            if let Some(first) = first {
                journal.complete(first, exact_outcome.clone(), 3).unwrap();
                assert_eq!(journal.reserved_terminal_bytes, 0);
                if disk_bound {
                    assert_eq!(journal.offset, bounds.max_journal_bytes);
                }
            }
            let mut restored = reopen(journal.file.bytes.into_inner(), bounds).unwrap();
            assert_eq!(replay(restored.admit(&peer, key(2), b"two", 4)), exact_outcome.clone().into());
            if restart {
                assert_eq!(restored.reserved_terminal_bytes, terminal_size);
                assert!(matches!(
                    restored.admit(&peer, key(1), b"one", 4),
                    Err(DurableRemoteError::InDoubt)
                ));
            } else {
                assert_eq!(restored.reserved_terminal_bytes, 0);
                assert_eq!(replay(restored.admit(&peer, key(1), b"one", 4)), exact_outcome.clone().into());
            }
        }
    }
}

#[test]
fn sync_uncertainty_poisoning_requires_reopen_before_exposing_results() {
    let peer = NodeId::new("peer");
    for terminal in [false, true] {
        let mut journal = journal(limits());
        let reservation = if terminal {
            Some(execute(journal.admit(&peer, key(1), b"input", 1)))
        } else {
            None
        };
        let committed = journal.offset;
        let records = journal.sequence;
        journal.file.fail_sync = true;
        let failed = if let Some(reservation) = reservation {
            journal.complete(reservation, success(), 2).map(|_| ())
        } else {
            journal.admit(&peer, key(1), b"input", 2).map(|_| ())
        };
        assert!(matches!(failed, Err(DurableRemoteError::Io(_))));
        assert_eq!(journal.offset, committed);
        assert_eq!(journal.sequence, records);
        assert_eq!(journal.status, DurableRemoteJournalStatus::Poisoned);
        assert!(matches!(
            journal.admit(&peer, key(1), b"input", 3),
            Err(DurableRemoteError::NotWritable(DurableRemoteJournalStatus::Poisoned))
        ));
        let bytes = journal.file.bytes.into_inner();
        let mut restored = reopen(bytes, limits()).unwrap();
        assert_eq!(restored.file.syncs, 1);
        assert_eq!(restored.sequence, records + 1);
        if terminal {
            assert_eq!(replay(restored.admit(&peer, key(1), b"input", 3)), success().into());
        } else {
            assert!(matches!(
                restored.admit(&peer, key(1), b"input", 3),
                Err(DurableRemoteError::InDoubt)
            ));
        }
    }

    let mut journal = journal(limits());
    journal.file.panic_sync = true;
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = journal.admit(&peer, key(2), b"panic during sync", 1);
    }))
    .is_err());
    assert_eq!(journal.status, DurableRemoteJournalStatus::Poisoned);
    assert_eq!(journal.sequence, 0);
    let mut file = FaultFile::from(journal.file.bytes.into_inner());
    file.fail_sync = true;
    assert!(matches!(
        Journal::open(file, config(limits())),
        Err(DurableRemoteError::Io(_))
    ));
}

#[test]
fn torn_tail_preserves_exact_replay_and_unresolved_reservations_without_repair() {
    let peer = NodeId::new("peer");
    let mut journal = journal(limits());
    let first = execute(journal.admit(&peer, key(1), b"complete", 1));
    journal.complete(first, success(), 2).unwrap();
    let second = execute(journal.admit(&peer, key(2), b"uncertain", 3));
    let committed = journal.offset;
    journal.file.budget = Some(PREFIX_BYTES + 3);
    assert!(matches!(
        journal.complete(second, success(), 4),
        Err(DurableRemoteError::Io(_))
    ));
    let bytes = journal.file.bytes.into_inner();
    let mut restored = reopen(bytes.clone(), limits()).unwrap();
    assert_eq!(restored.status, DurableRemoteJournalStatus::ReadOnlyTail);
    assert_eq!(restored.offset, committed);
    assert_eq!(restored.sequence, 3);
    assert_eq!(replay(restored.admit(&peer, key(1), b"complete", 5)), success().into());
    assert!(matches!(
        restored.admit(&peer, key(2), b"uncertain", 5),
        Err(DurableRemoteError::InDoubt)
    ));
    assert!(matches!(
        restored.admit(&peer, key(3), b"new", 5),
        Err(DurableRemoteError::NotWritable(DurableRemoteJournalStatus::ReadOnlyTail))
    ));
    assert_eq!(restored.file.bytes.get_ref(), &bytes);

    // Exercise short length-prefix, body and authentication-tag boundaries.
    let mut complete_log = reopen(bytes[..committed as usize].to_vec(), limits()).unwrap();
    let third = execute(complete_log.admit(&peer, key(3), b"third", 5));
    let start = complete_log.offset as usize;
    complete_log.complete(third, success(), 6).unwrap();
    let complete_bytes = complete_log.file.bytes.into_inner();
    for end in [start + 1, start + PREFIX_BYTES - 1, start + PREFIX_BYTES, complete_bytes.len() - TAG_BYTES, complete_bytes.len() - 1] {
        let prefix = complete_bytes[..end].to_vec();
        let mut restored = reopen(prefix.clone(), limits()).unwrap();
        assert_eq!(restored.status, DurableRemoteJournalStatus::ReadOnlyTail);
        assert_eq!(restored.offset, start as u64);
        assert!(matches!(
            restored.admit(&peer, key(3), b"third", 7),
            Err(DurableRemoteError::InDoubt)
        ));
        assert_eq!(restored.file.bytes.get_ref(), &prefix);
    }
}

#[test]
fn complete_corruption_and_authenticated_semantic_damage_fail_the_entire_open() {
    let peer = NodeId::new("peer");
    let mut original_log = journal(limits());
    let header = original_log.offset as usize;
    let reservation = execute(original_log.admit(&peer, key(1), b"input", 1));
    let reserved = original_log.offset as usize;
    original_log.complete(reservation, success(), 2).unwrap();
    let bytes = original_log.file.bytes.into_inner();
    for index in [0, header - 1, header, header + 8, header + PREFIX_BYTES, reserved - 1, reserved, bytes.len() - 1] {
        let mut changed = bytes.clone();
        changed[index] ^= 1;
        assert!(reopen(changed, limits()).is_err(), "corrupt byte {index}");
    }
    let mut reordered = bytes[..header].to_vec();
    reordered.extend_from_slice(&bytes[reserved..]);
    reordered.extend_from_slice(&bytes[header..reserved]);
    assert!(reopen(reordered, limits()).is_err());
    let mut duplicated = bytes[..reserved].to_vec();
    duplicated.extend_from_slice(&bytes[header..reserved]);
    assert!(reopen(duplicated, limits()).is_err());

    // A valid length MAC cannot authorize an unbounded allocation or disguise
    // an impossible complete length as an ordinary torn tail.
    let mut log = journal(limits());
    let body_len = size64(log.config.max_body_bytes().unwrap()).unwrap() + 1;
    let tag = AuthenticationTag::compute_for_domain_payload(
        &log.config.key,
        LENGTH_DOMAIN,
        &prefix_payload(body_len, 1, log.last),
    );
    log.file.bytes.get_mut().extend_from_slice(&body_len.to_le_bytes());
    log.file.bytes.get_mut().extend_from_slice(tag.as_bytes());
    assert!(matches!(
        reopen(log.file.bytes.into_inner(), limits()),
        Err(DurableRemoteError::Format)
    ));

    for variant in 0..4 {
        let mut log = reopen(bytes[..reserved].to_vec(), limits()).unwrap();
        let encoded = if variant == 2 {
            br#"{"outcome":"success","value":[],"unknown":true}"#.to_vec()
        } else {
            serde_json::to_vec(&RemoteServiceWireOutcome::from(success())).unwrap()
        };
        let reservation_sequence = if variant == 0 { 2_u64 } else { 1_u64 };
        let expires_at = if variant == 1 { 103_u64 } else { 102_u64 };
        let mut payload = Vec::new();
        payload.extend_from_slice(&reservation_sequence.to_le_bytes());
        payload.extend_from_slice(&expires_at.to_le_bytes());
        payload.extend_from_slice(&(encoded.len() as u64).to_le_bytes());
        payload.extend_from_slice(&encoded);
        let timestamp = if variant == 3 { 0 } else { 2 };
        log.append_record(COMPLETE, &peer, key(1), &payload, timestamp).unwrap();
        assert!(reopen(log.file.bytes.into_inner(), limits()).is_err(), "semantic variant {variant}");
    }
}

#[test]
fn header_requires_original_key_schema_version_name_and_every_limit() {
    let bytes = journal(limits()).file.bytes.into_inner();
    for variant in 0..11 {
        let mut cfg = config(limits());
        match variant {
            0 => cfg.key = AuthKey::from_seed(100),
            1 => cfg.application_version[31] ^= 1,
            2 => cfg.computation = "durable.test.v2".to_owned(),
            3 => {
                cfg = Config::new::<u64, Vec<u8>>(
                    COMPUTATION.to_owned(),
                    APPLICATION_VERSION,
                    AuthKey::from_seed(99),
                    limits(),
                )
                .unwrap();
            }
            4 => cfg.limits.max_entries += 1,
            5 => cfg.limits.max_peer_entries += 1,
            6 => cfg.limits.max_input_bytes += 1,
            7 => cfg.limits.max_outcome_bytes += 1,
            8 => cfg.limits.max_retained_bytes += 1,
            9 => cfg.limits.max_journal_bytes += 1,
            _ => cfg.limits.retention_ms += 1,
        }
        assert!(Journal::open(FaultFile::from(bytes.clone()), cfg).is_err(), "configuration variant {variant}");
    }
    assert!(matches!(
        Journal::create(FaultFile::from(bytes), config(limits())),
        Err(DurableRemoteError::NotEmpty)
    ));
    let mut bounds = limits();
    bounds.retention_ms = 0;
    assert!(matches!(
        Config::new::<Vec<u8>, Vec<u8>>(COMPUTATION.to_owned(), APPLICATION_VERSION, AuthKey::from_seed(99), bounds),
        Err(DurableRemoteError::Configuration)
    ));
}

#[test]
fn foreign_tokens_and_oversized_outcomes_leave_the_original_reservation_in_doubt() {
    let peer = NodeId::new("peer");
    let mut first = journal(limits());
    let mut second = journal(limits());
    let foreign = execute(first.admit(&peer, key(1), b"input", 1));
    let old = execute(second.admit(&peer, key(1), b"input", 1));
    let before = second.file.bytes.get_ref().clone();
    assert!(matches!(
        second.complete(foreign, success(), 2),
        Err(DurableRemoteError::InvalidReservation)
    ));
    assert_eq!(second.file.bytes.get_ref(), &before);
    let mut restored = reopen(before, limits()).unwrap();
    assert!(matches!(
        restored.complete(old, success(), 2),
        Err(DurableRemoteError::InvalidReservation)
    ));
    for log in [&mut first, &mut restored] {
        assert!(matches!(
            log.admit(&peer, key(1), b"input", 3),
            Err(DurableRemoteError::InDoubt)
        ));
    }

    let mut bounds = limits();
    bounds.max_outcome_bytes = 64;
    let mut log = journal(bounds);
    let reservation = execute(log.admit(&peer, key(2), b"input", 1));
    let before = log.file.bytes.get_ref().clone();
    let reserved = log.reserved_terminal_bytes;
    assert!(matches!(
        log.complete(reservation, RemoteOutcome::Success(vec![255; 65]), 2),
        Err(DurableRemoteError::Limit)
    ));
    assert_eq!(log.file.bytes.get_ref(), &before);
    assert_eq!(log.status, DurableRemoteJournalStatus::Writable);
    assert_eq!(log.retained_bytes, 64);
    assert_eq!(log.reserved_terminal_bytes, reserved);
    assert!(matches!(
        log.admit(&peer, key(2), b"input", 3),
        Err(DurableRemoteError::InDoubt)
    ));
}

#[test]
fn terminal_variants_round_trip_through_the_existing_strict_wire_codec() {
    let peer = NodeId::new("peer");
    let outcomes = [
        success(),
        RemoteOutcome::Failed("application error".to_owned()),
        RemoteOutcome::Cancelled(CancelReason::user("caller cancelled")),
        RemoteOutcome::Panicked("handler failed".to_owned()),
    ];
    let mut journal = journal(limits());
    for (index, expected) in outcomes.iter().enumerate() {
        let reservation = execute(journal.admit(&peer, key(index as u128), b"input", 1));
        let result = journal.complete(reservation, expected.clone(), 1).unwrap();
        assert_eq!(RemoteServiceWireOutcome::from(result), expected.clone().into());
    }
    let mut restored = reopen(journal.file.bytes.into_inner(), limits()).unwrap();
    for (index, expected) in outcomes.into_iter().enumerate() {
        assert_eq!(replay(restored.admit(&peer, key(index as u128), b"input", 2)), expected.into());
    }
}

#[test]
fn cache_growth_capacity_is_compacted_charged_and_released_at_expiry() {
    let peer = NodeId::new("peer");
    let outcome = RemoteOutcome::Failed("x".repeat(1000));
    let encoded_len = serde_json::to_vec(&RemoteServiceWireOutcome::from(outcome.clone()))
        .unwrap()
        .len();
    assert!(encoded_len > 1024 && encoded_len < 2048);
    let mut bounds = limits();
    bounds.max_outcome_bytes = 2048;
    bounds.max_retained_bytes = encoded_len + bounds.max_outcome_bytes;
    let mut journal = journal(bounds);
    let first = execute(journal.admit(&peer, key(1), b"one", 1));
    journal.complete(first, outcome.clone(), 2).unwrap();
    let EntryState::Terminal { outcome: cached, .. } =
        &journal.entries.get(&(peer.clone(), key(1).raw())).unwrap().state
    else {
        panic!("completion did not retain an outcome");
    };
    assert_eq!(cached.capacity(), encoded_len);
    assert_eq!(journal.retained_bytes, cached.capacity());
    let second = execute(journal.admit(&peer, key(2), b"two", 3));
    assert_eq!(journal.retained_bytes, bounds.max_retained_bytes);
    journal.complete(second, outcome, 4).unwrap();
    assert_eq!(journal.retained_bytes, 2 * encoded_len);
    let mut restored = reopen(journal.file.bytes.into_inner(), bounds).unwrap();
    assert_eq!(restored.retained_bytes, 2 * encoded_len);
    // Both completed entries have expired at 104; only the new pending budget remains.
    let _third = execute(restored.admit(&peer, key(3), b"three", 104));
    assert_eq!(restored.entries.len(), 1);
    assert_eq!(restored.retained_bytes, bounds.max_outcome_bytes);
}

#[test]
fn admission_limits_and_external_file_growth_refuse_before_handler_permission() {
    let peer = NodeId::new("peer");
    for variant in 0..6 {
        let mut bounds = limits();
        match variant {
            0 => bounds.max_entries = 0,
            1 => bounds.max_peer_entries = 0,
            2 => bounds.max_input_bytes = 0,
            3 => bounds.max_outcome_bytes = 0,
            4 => bounds.max_retained_bytes = 0,
            _ => bounds.max_journal_bytes = config(bounds).header().unwrap().len() as u64,
        }
        let mut journal = journal(bounds);
        let before = journal.file.bytes.get_ref().clone();
        assert!(matches!(
            journal.admit(&peer, key(1), b"input", 1),
            Err(DurableRemoteError::Limit)
        ));
        assert_eq!(journal.file.bytes.get_ref(), &before);
        assert_eq!(journal.sequence, 0);
    }
    let mut journal = journal(limits());
    for peer in [NodeId::new(""), NodeId::new("x".repeat(256))] {
        assert!(matches!(
            journal.admit(&peer, key(1), b"input", 1),
            Err(DurableRemoteError::Configuration)
        ));
        assert_eq!(journal.sequence, 0);
    }
    journal.file.bytes.get_mut().push(0);
    let original = journal.file.bytes.get_ref().clone();
    assert!(matches!(
        journal.admit(&peer, key(1), b"input", 1),
        Err(DurableRemoteError::Changed)
    ));
    assert_eq!(journal.status, DurableRemoteJournalStatus::Poisoned);
    assert_eq!(journal.file.bytes.get_ref(), &original);
    assert_eq!(journal.sequence, 0);
}

fn reconciliation(
    decision: Result<DurableRemoteReconciliation, DurableRemoteError>,
) -> DurableRemoteReconciliationPermit {
    match decision.unwrap() {
        DurableRemoteReconciliation::Pending(permit) => permit,
        DurableRemoteReconciliation::Replay(_) => panic!("expected an uncertain request"),
    }
}

fn reconciled(decision: Result<DurableRemoteReconciliation, DurableRemoteError>)
    -> RemoteServiceWireOutcome
{
    match decision.unwrap() {
        DurableRemoteReconciliation::Replay(outcome) => outcome.into(),
        DurableRemoteReconciliation::Pending(_) => panic!("expected a saved terminal result"),
    }
}

#[test]
fn reconciliation_refuses_live_current_owners_and_requires_exact_pending_identity() {
    let mut journal = journal(limits());
    let peer = NodeId::new("authenticated-peer");
    let first = execute(journal.admit(&peer, key(1), b"original", 10));
    let second = execute(journal.admit(&peer, key(2), b"other", 10));
    let original = journal.file.bytes.get_ref().clone();
    assert!(matches!(journal.prepare_reconciliation(&peer, key(1), b"original", 10),
        Err(DurableRemoteError::Busy)));
    assert!(matches!(journal.prepare_reconciliation(&peer, key(1), b"changed", 10),
        Err(DurableRemoteError::Conflict)));
    assert!(matches!(journal.prepare_reconciliation(&NodeId::new("foreign"), key(1), b"original", 10),
        Err(DurableRemoteError::InvalidReservation)));
    assert!(matches!(journal.prepare_reconciliation(&peer, key(3), b"missing", 10),
        Err(DurableRemoteError::InvalidReservation)));
    drop(first);
    assert!(matches!(journal.prepare_reconciliation(&peer, key(1), b"original", 10),
        Err(DurableRemoteError::Busy)), "another live key conservatively owns the journal instance");
    drop(second);
    let permit = reconciliation(journal.prepare_reconciliation(&peer, key(1), b"original", 10));
    assert!(matches!(journal.prepare_reconciliation(&peer, key(1), b"original", 10),
        Err(DurableRemoteError::Busy)), "two resolvers cannot race the same terminal publication");
    assert_eq!(journal.file.bytes.get_ref(), &original, "preparation writes nothing");
    drop(permit);
    assert!(matches!(journal.admit(&peer, key(1), b"original", 10), Err(DurableRemoteError::InDoubt)));
    let permit = reconciliation(journal.prepare_reconciliation(&peer, key(1), b"original", 11));
    assert_eq!(RemoteServiceWireOutcome::from(journal.complete_reconciliation(permit, success(), 11).unwrap()), success().into());
    assert_eq!(journal.sequence, 3, "two reservations and exactly one terminal record");
    let committed = journal.file.bytes.get_ref().clone();
    assert_eq!(reconciled(journal.prepare_reconciliation(&peer, key(1), b"original", 12)), success().into());
    assert_eq!(replay(journal.admit(&peer, key(1), b"original", 12)), success().into());
    assert_eq!(journal.file.bytes.get_ref(), &committed);
    assert!(matches!(journal.admit(&peer, key(2), b"other", 12), Err(DurableRemoteError::InDoubt)));
}

#[test]
fn reconciliation_permits_cannot_cross_reopen_identity_or_replaced_reservation() {
    let peer = NodeId::new("peer");
    let mut original = journal(limits());
    drop(execute(original.admit(&peer, key(1), b"input", 10)));
    let old_instance = reconciliation(original.prepare_reconciliation(&peer, key(1), b"input", 10));
    let bytes = original.file.bytes.get_ref().clone();
    drop(original);
    let mut journal = reopen(bytes.clone(), limits()).unwrap();
    assert!(matches!(journal.complete_reconciliation(old_instance, success(), 11),
        Err(DurableRemoteError::InvalidReservation)));
    assert_eq!(journal.file.bytes.get_ref(), &bytes);

    let mut bad_input = reconciliation(journal.prepare_reconciliation(&peer, key(1), b"input", 11));
    bad_input.digest[0] ^= 1;
    assert!(matches!(journal.complete_reconciliation(bad_input, success(), 11),
        Err(DurableRemoteError::InvalidReservation)));
    let mut bad_version = reconciliation(journal.prepare_reconciliation(&peer, key(1), b"input", 11));
    bad_version.application_version[0] ^= 1;
    assert!(matches!(journal.complete_reconciliation(bad_version, success(), 11),
        Err(DurableRemoteError::InvalidReservation)));

    let permit = reconciliation(journal.prepare_reconciliation(&peer, key(1), b"input", 11));
    // A public permit is deliberately not Clone. Forge a duplicate inside the
    // private test module to exercise the generation fence independently.
    let stale = DurableRemoteReconciliationPermit {
        reservation: DurableRemoteReservation {
            instance: Arc::clone(&permit.reservation.instance), peer: peer.clone(), key: key(1),
            sequence: permit.reservation.sequence,
        },
        input_len: permit.input_len, digest: permit.digest, schema: permit.schema,
        application_version: permit.application_version,
    };
    journal.complete_reconciliation(permit, success(), 11).unwrap();
    let completed = journal.file.bytes.get_ref().clone();
    assert!(matches!(journal.prepare_reconciliation(&peer, key(1), b"input", 111),
        Err(DurableRemoteError::InvalidReservation)), "expiry must not create recovery authority");
    assert_eq!(journal.file.bytes.get_ref(), &completed);
    let replacement = execute(journal.admit(&peer, key(1), b"input", 111));
    assert!(matches!(journal.complete_reconciliation(stale, success(), 112),
        Err(DurableRemoteError::InvalidReservation)), "old permits cannot complete a new reservation");
    journal.complete(replacement, RemoteOutcome::Failed("new result".into()), 112).unwrap();
    assert_eq!(journal.sequence, 4);
}

#[test]
fn reconciliation_write_uncertainty_requires_reopen_and_never_repairs_a_torn_tail() {
    let peer = NodeId::new("peer");
    for partial in [false, true] {
        let mut journal = journal(limits());
        drop(execute(journal.admit(&peer, key(1), b"input", 10)));
        let permit = reconciliation(journal.prepare_reconciliation(&peer, key(1), b"input", 11));
        if partial { journal.file.budget = Some(1); } else { journal.file.fail_sync = true; }
        assert!(journal.complete_reconciliation(permit, success(), 11).is_err());
        assert_eq!(journal.status, DurableRemoteJournalStatus::Poisoned);
        assert!(matches!(journal.prepare_reconciliation(&peer, key(1), b"input", 12),
            Err(DurableRemoteError::NotWritable(DurableRemoteJournalStatus::Poisoned))));
        let bytes = journal.file.bytes.get_ref().clone();
        let mut reopened = reopen(bytes.clone(), limits()).unwrap();
        if partial {
            assert_eq!(reopened.status, DurableRemoteJournalStatus::ReadOnlyTail);
            assert!(matches!(reopened.prepare_reconciliation(&peer, key(1), b"input", 12),
                Err(DurableRemoteError::NotWritable(DurableRemoteJournalStatus::ReadOnlyTail))));
            assert!(matches!(reopened.admit(&peer, key(1), b"input", 12), Err(DurableRemoteError::InDoubt)));
        } else {
            assert_eq!(reconciled(reopened.prepare_reconciliation(&peer, key(1), b"input", 12)), success().into());
            assert_eq!(replay(reopened.admit(&peer, key(1), b"input", 12)), success().into());
        }
        assert_eq!(reopened.file.bytes.get_ref(), &bytes);
    }
}

#[test]
fn refused_reconciliation_completion_preserves_reserved_capacity_and_pending_fence() {
    let peer = NodeId::new("peer");
    let mut journal = journal(limits());
    drop(execute(journal.admit(&peer, key(1), b"input", 10)));
    let original = journal.file.bytes.get_ref().clone();
    let bytes = journal.retained_bytes;
    let capacity = journal.reserved_terminal_bytes;
    let permit = reconciliation(journal.prepare_reconciliation(&peer, key(1), b"input", 11));
    assert!(matches!(journal.complete_reconciliation(permit,
        RemoteOutcome::Success(vec![0; limits().max_outcome_bytes + 1]), 11), Err(DurableRemoteError::Limit)));
    let permit = reconciliation(journal.prepare_reconciliation(&peer, key(1), b"input", 11));
    assert!(matches!(journal.complete_reconciliation(permit, success(), 10),
        Err(DurableRemoteError::ClockRegression)));
    assert_eq!(journal.file.bytes.get_ref(), &original);
    assert_eq!(journal.retained_bytes, bytes);
    assert_eq!(journal.reserved_terminal_bytes, capacity);
    assert!(matches!(journal.admit(&peer, key(1), b"input", 12), Err(DurableRemoteError::InDoubt)));
    let permit = reconciliation(journal.prepare_reconciliation(&peer, key(1), b"input", 12));
    journal.complete_reconciliation(permit, success(), 12).unwrap();
    assert_eq!(journal.reserved_terminal_bytes, 0);
}
