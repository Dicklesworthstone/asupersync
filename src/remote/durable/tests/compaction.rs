//! Capacity recovery and publication failures use the actual journal engine.

use super::*;
use std::cell::Cell;
use std::panic::{AssertUnwindSafe, catch_unwind};

#[test]
fn compaction_recovers_exhausted_capacity_and_persists_an_empty_clock_floor() {
    let mut bounds = limits();
    bounds.max_outcome_bytes = 256;
    bounds.max_retained_bytes = 2048;
    bounds.max_journal_bytes = 1400;
    let peer = NodeId::new("peer");
    let mut log = journal(bounds);
    let mut completed = 0;
    let mut now = 0;
    for attempt in 1..100_u64 {
        now = attempt * 1000;
        match log.admit(&peer, key(u128::from(attempt)), b"input", now) {
            Ok(DurableRemoteAdmission::Execute(reservation)) => {
                log.complete(reservation, success(), now).unwrap();
                completed += 1;
            }
            Err(DurableRemoteError::Limit) => break,
            other => panic!("unexpected capacity fixture admission: {other:?}"),
        }
    }
    assert!(completed >= 2, "fixture must exhaust a used journal");
    assert!(log.entries.is_empty(), "all completed keys expired before refusal");
    assert!(matches!(
        log.admit(&peer, key(999), b"input", now),
        Err(DurableRemoteError::Limit)
    ));
    let original_bytes = log.offset;
    let published = Cell::new(0);
    let report = log
        .compact(FaultFile::default(), now, || {
            published.set(published.get() + 1);
            Ok(())
        })
        .unwrap();
    assert_eq!(published.get(), 1);
    assert_eq!(report.previous_bytes, original_bytes);
    assert!(report.committed_bytes < original_bytes, "{report:?}");
    assert_eq!(report.retained_entries, 0);
    assert_eq!(log.sequence, 1, "the empty journal must retain its clock floor");

    let mut restored = reopen(log.file.bytes.into_inner(), bounds).unwrap();
    assert!(matches!(
        restored.admit(&peer, key(999), b"input", now - 1),
        Err(DurableRemoteError::ClockRegression)
    ));
    let reservation = execute(restored.admit(&peer, key(999), b"input", now));
    restored.complete(reservation, success(), now).unwrap();
    assert_eq!(
        replay(restored.admit(&peer, key(999), b"input", now)),
        success().into()
    );
}

#[test]
fn compaction_preserves_same_timestamp_completion_order_and_capacity() {
    let small = RemoteOutcome::Success(Vec::new());
    let large = RemoteOutcome::Failed("x".repeat(100));
    let small_len = encode_outcome(small.clone(), 4096).unwrap().0.capacity();
    let large_len = encode_outcome(large.clone(), 4096).unwrap().0.capacity();
    assert!(large_len > small_len);
    let mut bounds = limits();
    bounds.max_outcome_bytes = large_len;
    bounds.max_retained_bytes = small_len + large_len;
    let peer = NodeId::new("peer");
    let mut log = journal(bounds);
    // Key order deliberately reverses completion order. Reconstructing the
    // large result first would leave insufficient allowance to reserve small.
    let first = execute(log.admit(&peer, key(9), b"small", 10));
    log.complete(first, small.clone(), 10).unwrap();
    let second = execute(log.admit(&peer, key(1), b"large", 10));
    log.complete(second, large.clone(), 10).unwrap();
    assert_eq!(log.retained_bytes, bounds.max_retained_bytes);
    log.compact(FaultFile::default(), 20, || Ok(())).unwrap();
    let mut restored = reopen(log.file.bytes.into_inner(), bounds).unwrap();
    assert_eq!(replay(restored.admit(&peer, key(9), b"small", 20)), small.into());
    assert_eq!(replay(restored.admit(&peer, key(1), b"large", 20)), large.into());
    assert_eq!(restored.retained_bytes, bounds.max_retained_bytes);
}

#[test]
fn compaction_keeps_pending_fences_and_their_reserved_capacity_at_maximum_clock() {
    let peer = NodeId::new("peer");
    let mut log = journal(limits());
    drop(execute(log.admit(&peer, key(7), b"uncertain", 1)));
    let reserved = log.reserved_terminal_bytes;
    log.compact(FaultFile::default(), u64::MAX, || Ok(())).unwrap();
    assert_eq!(log.reserved_terminal_bytes, reserved);
    assert_eq!(log.retained_bytes, limits().max_outcome_bytes);
    let mut restored = reopen(log.file.bytes.into_inner(), limits()).unwrap();
    assert_eq!(restored.reserved_terminal_bytes, reserved);
    assert!(matches!(
        restored.admit(&peer, key(7), b"uncertain", u64::MAX),
        Err(DurableRemoteError::InDoubt)
    ));
    assert!(matches!(
        restored.admit(&peer, key(7), b"different", u64::MAX),
        Err(DurableRemoteError::Conflict)
    ));
}

#[test]
fn compaction_refuses_live_permits_and_cannot_spend_pending_completion_reserve() {
    let peer = NodeId::new("peer");
    let mut bounds = limits();
    bounds.max_journal_bytes = config(bounds).header().unwrap().len() as u64
        + record_size(peer.as_str().len(), RESERVATION_BYTES).unwrap()
        + record_size(peer.as_str().len(), TERMINAL_BYTES + bounds.max_outcome_bytes).unwrap();
    let mut log = journal(bounds);
    let reservation = execute(log.admit(&peer, key(1), b"input", 1));
    let original = log.file.bytes.get_ref().clone();
    let publishes = Cell::new(0);
    let publish = || {
        publishes.set(publishes.get() + 1);
        Ok(())
    };
    assert!(matches!(
        log.compact(FaultFile::default(), 2, &publish),
        Err(DurableRemoteError::Busy)
    ));
    drop(reservation);
    let permit = reconciliation(log.prepare_reconciliation(&peer, key(1), b"input", 2));
    assert!(matches!(
        log.compact(FaultFile::default(), 3, &publish),
        Err(DurableRemoteError::Busy)
    ));
    drop(permit);
    assert!(matches!(
        log.compact(FaultFile::default(), 3, publish),
        Err(DurableRemoteError::Limit)
    ));
    assert_eq!(publishes.get(), 0);
    assert_eq!(log.file.bytes.get_ref(), &original);
    assert_eq!(log.status, DurableRemoteJournalStatus::Writable);
    let permit = reconciliation(log.prepare_reconciliation(&peer, key(1), b"input", 3));
    log.complete_reconciliation(permit, success(), 3).unwrap();
}

#[test]
fn compaction_preparation_failures_leave_the_original_writable_and_unpublished() {
    let peer = NodeId::new("peer");
    let mut log = journal(limits());
    drop(execute(log.admit(&peer, key(1), b"input", 1)));
    let original = log.file.bytes.get_ref().clone();
    let header_bytes = config(limits()).header().unwrap().len();
    let mut partial = FaultFile::default();
    partial.budget = Some(header_bytes + 10);
    let mut failed_sync = FaultFile::default();
    failed_sync.fail_sync = true;
    for candidate in [partial, failed_sync, FaultFile::from(vec![1])] {
        let published = Cell::new(false);
        let result = log.compact(candidate, 2, || {
            published.set(true);
            Ok(())
        });
        assert!(matches!(result, Err(DurableRemoteError::Io(_) | DurableRemoteError::NotEmpty)));
        assert!(!published.get());
        assert_eq!(log.file.bytes.get_ref(), &original);
        assert_eq!(log.status, DurableRemoteJournalStatus::Writable);
    }
    let mut panic_sync = FaultFile::default();
    panic_sync.panic_sync = true;
    let panic = catch_unwind(AssertUnwindSafe(|| {
        let _ = log.compact(panic_sync, 2, || panic!("publication must not start"));
    }));
    assert!(panic.is_err());
    assert_eq!(log.file.bytes.get_ref(), &original);
    assert_eq!(log.status, DurableRemoteJournalStatus::Writable);
    log.compact(FaultFile::default(), 2, || Ok(())).unwrap();
    assert!(matches!(
        log.admit(&peer, key(1), b"input", 2),
        Err(DurableRemoteError::InDoubt)
    ));
}

#[test]
fn compaction_publication_error_or_panic_poison_the_original_without_clearing_fences() {
    for panic in [false, true] {
        let peer = NodeId::new("peer");
        let mut log = journal(limits());
        drop(execute(log.admit(&peer, key(1), b"input", 1)));
        let original = log.file.bytes.get_ref().clone();
        let result = catch_unwind(AssertUnwindSafe(|| {
            log.compact(FaultFile::default(), 2, || {
                assert!(!panic, "injected publication panic");
                Err(io::Error::other("injected publication failure"))
            })
        }));
        if panic {
            assert!(result.is_err());
        } else {
            assert!(matches!(result.unwrap(), Err(DurableRemoteError::Io(_))));
        }
        assert_eq!(log.status, DurableRemoteJournalStatus::Poisoned);
        assert_eq!(log.file.bytes.get_ref(), &original);
        assert!(matches!(
            log.admit(&peer, key(1), b"input", 2),
            Err(DurableRemoteError::NotWritable(DurableRemoteJournalStatus::Poisoned))
        ));
        let mut restored = reopen(log.file.bytes.into_inner(), limits()).unwrap();
        assert!(matches!(
            restored.admit(&peer, key(1), b"input", 2),
            Err(DurableRemoteError::InDoubt)
        ));
    }
}

#[test]
fn compaction_clock_records_reject_noncanonical_identity_payload_and_regression() {
    for (peer, id, payload) in [
        (NodeId::new("identity-is-forbidden-on-a-clock-record"), key(0), Vec::new()),
        (NodeId::new(""), key(1), Vec::new()),
        (NodeId::new(""), key(0), vec![0; TERMINAL_BYTES + 1]),
    ] {
        let mut log = journal(limits());
        log.append_record(CLOCK_FLOOR, &peer, id, &payload, 10).unwrap();
        assert!(matches!(
            reopen(log.file.bytes.into_inner(), limits()),
            Err(DurableRemoteError::Format)
        ));
    }
    let mut log = journal(limits());
    log.append_record(CLOCK_FLOOR, &NodeId::new(""), key(0), &[], 10).unwrap();
    log.append_record(CLOCK_FLOOR, &NodeId::new(""), key(0), &[], 9).unwrap();
    assert!(matches!(
        reopen(log.file.bytes.into_inner(), limits()),
        Err(DurableRemoteError::ClockRegression)
    ));
}

#[test]
#[cfg(unix)]
fn real_compaction_atomic_publication_reopens_exact_results_expiry_and_pending_identity() {
    for fail_after_rename in [false, true] {
        let (path, file) = linked_file();
        let mut journal = DurableRemoteJournal::create::<Vec<u8>, Vec<u8>>(
            file, COMPUTATION, APPLICATION_VERSION, AuthKey::from_seed(99), limits(),
        )
        .unwrap();
        let peer = NodeId::new("peer");
        let expired = execute(journal.admit(&peer, key(1), b"old", 1));
        journal.complete(expired, success(), 2).unwrap();
        drop(execute(journal.admit(&peer, key(2), b"uncertain", 3)));
        let retained = execute(journal.admit(&peer, key(3), b"retained", 70));
        journal.complete(retained, success(), 80).unwrap();
        let (replacement_path, replacement) = linked_file();
        let original_bytes = journal.committed_bytes();
        let result = journal.compact(replacement, 120, || {
            std::fs::rename(&replacement_path, &path)?;
            File::open(path.parent().unwrap())?.sync_all()?;
            if fail_after_rename {
                Err(io::Error::other("rename completed before publication failed"))
            } else {
                Ok(())
            }
        });
        if fail_after_rename {
            assert!(matches!(result, Err(DurableRemoteError::Io(_))));
            assert_eq!(journal.status(), DurableRemoteJournalStatus::Poisoned);
        } else {
            let report = result.unwrap();
            assert!(report.committed_bytes < original_bytes, "{report:?}");
            assert_eq!(report.retained_entries, 2);
            assert_eq!(journal.status(), DurableRemoteJournalStatus::Writable);
        }
        drop(journal);
        let mut restored = DurableRemoteJournal::open::<Vec<u8>, Vec<u8>>(
            open_file(&path), COMPUTATION, APPLICATION_VERSION, AuthKey::from_seed(99), limits(),
        )
        .unwrap();
        assert!(matches!(
            restored.admit(&peer, key(3), b"retained", 119),
            Err(DurableRemoteError::ClockRegression)
        ));
        assert_eq!(replay(restored.admit(&peer, key(3), b"retained", 120)), success().into());
        assert!(matches!(
            restored.admit(&peer, key(3), b"different", 120),
            Err(DurableRemoteError::Conflict)
        ));
        assert!(matches!(
            restored.admit(&peer, key(2), b"uncertain", 120),
            Err(DurableRemoteError::InDoubt)
        ));
        let permit = reconciliation(restored.prepare_reconciliation(&peer, key(2), b"uncertain", 121));
        restored.complete_reconciliation(permit, success(), 121).unwrap();
        assert_eq!(replay(restored.admit(&peer, key(3), b"retained", 179)), success().into());
        drop(execute(restored.admit(&peer, key(3), b"retained", 180)));
        assert_eq!(replay(restored.admit(&peer, key(2), b"uncertain", 180)), success().into());
    }
}
