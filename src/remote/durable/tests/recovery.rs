//! Torn append recovery preserves execution fences and the exact authenticated head.

use super::*;
use std::cell::Cell;
use std::panic::{AssertUnwindSafe, catch_unwind};

fn completed_and_uncertain_bytes() -> (Vec<u8>, usize) {
    let mut log = journal(limits());
    let peer = NodeId::new("peer");
    let first = execute(log.admit(&peer, key(1), b"complete", 1));
    log.complete(first, success(), 2).unwrap();
    let second = execute(log.admit(&peer, key(2), b"uncertain", 3));
    let prefix = log.offset as usize;
    log.complete(
        second,
        RemoteOutcome::Failed("uncommitted tail outcome".into()),
        4,
    )
    .unwrap();
    (log.file.bytes.into_inner(), prefix)
}

#[test]
fn every_torn_completion_boundary_recovers_only_the_authenticated_prefix() {
    let (complete, prefix) = completed_and_uncertain_bytes();
    let peer = NodeId::new("peer");
    // Every nonempty incomplete suffix, including length, authenticated length
    // tag, body and final MAC boundaries. A complete record is a separate case.
    for end in prefix + 1..complete.len() {
        let mut log = reopen(complete[..end].to_vec(), limits()).unwrap();
        assert_eq!(log.status, DurableRemoteJournalStatus::ReadOnlyTail);
        let reserved = log.reserved_terminal_bytes;
        let retained = log.retained_bytes;
        let published = Cell::new(0);
        let report = log
            .recover_tail(FaultFile::default(), || {
                published.set(published.get() + 1);
                Ok(())
            })
            .unwrap();
        assert_eq!(published.get(), 1, "cut={end}");
        assert_eq!(report.source_bytes, end as u64);
        assert_eq!(report.committed_bytes, prefix as u64);
        assert_eq!(report.discarded_tail_bytes, (end - prefix) as u64);
        assert_eq!(report.records, 3);
        assert_eq!(report.retained_entries, 2);
        assert_eq!(log.status, DurableRemoteJournalStatus::Writable);
        assert_eq!(log.file.bytes.get_ref(), &complete[..prefix]);
        assert_eq!(log.reserved_terminal_bytes, reserved);
        assert_eq!(log.retained_bytes, retained);
        assert_eq!(
            replay(log.admit(&peer, key(1), b"complete", 5)),
            success().into()
        );
        assert!(matches!(
            log.admit(&peer, key(2), b"uncertain", 5),
            Err(DurableRemoteError::InDoubt)
        ));
        assert!(matches!(
            log.admit(&peer, key(2), b"different", 5),
            Err(DurableRemoteError::Conflict)
        ));
        let mut restored = reopen(log.file.bytes.into_inner(), limits()).unwrap();
        assert!(matches!(
            restored.admit(&peer, key(2), b"uncertain", 5),
            Err(DurableRemoteError::InDoubt)
        ));
    }
}

#[test]
fn recovered_pending_request_requires_explicit_reconciliation_while_new_work_can_run() {
    let (complete, prefix) = completed_and_uncertain_bytes();
    let peer = NodeId::new("peer");
    let mut log = reopen(complete[..prefix + PREFIX_BYTES + 1].to_vec(), limits()).unwrap();
    assert!(matches!(
        log.prepare_reconciliation(&peer, key(2), b"uncertain", 5),
        Err(DurableRemoteError::NotWritable(
            DurableRemoteJournalStatus::ReadOnlyTail
        ))
    ));
    assert!(matches!(
        log.compact(FaultFile::default(), 5, || panic!(
            "legacy compaction must refuse"
        )),
        Err(DurableRemoteError::NotWritable(
            DurableRemoteJournalStatus::ReadOnlyTail
        ))
    ));
    log.recover_tail(FaultFile::default(), || Ok(())).unwrap();
    let fresh = execute(log.admit(&peer, key(3), b"fresh", 6));
    log.complete(fresh, RemoteOutcome::Success(b"new work".to_vec()), 7)
        .unwrap();
    let permit = reconciliation(log.prepare_reconciliation(&peer, key(2), b"uncertain", 8));
    log.complete_reconciliation(
        permit,
        RemoteOutcome::Success(b"verified externally".to_vec()),
        9,
    )
    .unwrap();
    let mut restored = reopen(log.file.bytes.into_inner(), limits()).unwrap();
    assert_eq!(
        replay(restored.admit(&peer, key(2), b"uncertain", 10)),
        RemoteOutcome::Success(b"verified externally".to_vec()).into()
    );
    assert_eq!(
        replay(restored.admit(&peer, key(3), b"fresh", 10)),
        RemoteOutcome::Success(b"new work".to_vec()).into()
    );
}

#[test]
fn tail_recovery_needs_no_capacity_beyond_the_full_pending_completion_reserve() {
    let peer = NodeId::new("peer");
    let mut bounds = limits();
    bounds.max_journal_bytes = config(bounds).header().unwrap().len() as u64
        + record_size(peer.as_str().len(), RESERVATION_BYTES).unwrap()
        + record_size(
            peer.as_str().len(),
            TERMINAL_BYTES + bounds.max_outcome_bytes,
        )
        .unwrap();
    let mut log = journal(bounds);
    let pending = execute(log.admit(&peer, key(1), b"input", 1));
    let prefix = log.offset;
    let reserved = log.reserved_terminal_bytes;
    assert_eq!(prefix + reserved, bounds.max_journal_bytes);
    log.file.budget = Some(1);
    assert!(matches!(
        log.complete(pending, success(), 2),
        Err(DurableRemoteError::Io(_))
    ));
    let mut restored = reopen(log.file.bytes.into_inner(), bounds).unwrap();
    restored
        .recover_tail(FaultFile::default(), || Ok(()))
        .unwrap();
    assert_eq!(restored.offset, prefix);
    assert_eq!(restored.reserved_terminal_bytes, reserved);
    assert!(matches!(
        restored.admit(&peer, key(2), b"other", 3),
        Err(DurableRemoteError::Limit)
    ));
    let permit = reconciliation(restored.prepare_reconciliation(&peer, key(1), b"input", 3));
    restored
        .complete_reconciliation(permit, success(), 4)
        .unwrap();
    assert_eq!(
        replay(restored.admit(&peer, key(1), b"input", 4)),
        success().into()
    );
}

#[test]
fn tail_recovery_keeps_persisted_clock_records_and_transient_clock_and_expiry_state() {
    let peer = NodeId::new("peer");
    let mut log = journal(limits());
    let completed = execute(log.admit(&peer, key(1), b"completed", 1));
    log.complete(completed, success(), 2).unwrap();
    drop(execute(log.admit(&peer, key(2), b"pending", 3)));
    log.compact(FaultFile::default(), 50, || Ok(())).unwrap();
    let prefix = log.offset as usize;
    log.file.budget = Some(1);
    assert!(log.admit(&peer, key(3), b"never admitted", 51).is_err());
    let mut log = reopen(log.file.bytes.into_inner(), limits()).unwrap();
    let prefix_bytes = log.file.bytes.get_ref()[..prefix].to_vec();
    assert_eq!(log.last_time, 50);
    assert!(matches!(
        log.admit(&peer, key(2), b"pending", 150),
        Err(DurableRemoteError::InDoubt)
    ));
    assert_eq!(
        log.entries.len(),
        1,
        "terminal expiry has already been observed"
    );
    let report = log.recover_tail(FaultFile::default(), || Ok(())).unwrap();
    assert_eq!(report.retained_entries, 1);
    assert_eq!(log.last_time, 150);
    assert_eq!(
        log.entries.len(),
        1,
        "candidate replay must not resurrect the in-process cache"
    );
    assert_eq!(log.file.bytes.get_ref(), &prefix_bytes);
    assert!(matches!(
        log.admit(&peer, key(2), b"pending", 149),
        Err(DurableRemoteError::ClockRegression)
    ));
    let mut reopened = reopen(log.file.bytes.into_inner(), limits()).unwrap();
    assert!(matches!(
        reopened.admit(&peer, key(2), b"pending", 49),
        Err(DurableRemoteError::ClockRegression)
    ));
    assert!(matches!(
        reopened.admit(&peer, key(2), b"pending", 50),
        Err(DurableRemoteError::InDoubt)
    ));
}

#[test]
fn recovery_refuses_writable_poisoned_or_live_owned_journals_without_publication() {
    let mut log = journal(limits());
    let published = Cell::new(false);
    let publish = || {
        published.set(true);
        Ok(())
    };
    assert!(matches!(
        log.recover_tail(FaultFile::default(), publish),
        Err(DurableRemoteError::NotWritable(
            DurableRemoteJournalStatus::Writable
        ))
    ));
    let pending = execute(log.admit(&NodeId::new("peer"), key(1), b"input", 1));
    log.file.budget = Some(1);
    assert!(log.complete(pending, success(), 2).is_err());
    assert!(matches!(
        log.recover_tail(FaultFile::default(), publish),
        Err(DurableRemoteError::NotWritable(
            DurableRemoteJournalStatus::Poisoned
        ))
    ));
    let mut log = reopen(log.file.bytes.into_inner(), limits()).unwrap();
    let retained_owner = Arc::clone(&log.instance);
    assert!(matches!(
        log.recover_tail(FaultFile::default(), publish),
        Err(DurableRemoteError::Busy)
    ));
    assert!(!published.get());
    drop(retained_owner);
    log.recover_tail(FaultFile::default(), publish).unwrap();
    assert!(published.get());
}

#[test]
fn replacement_write_sync_and_panic_failures_preserve_the_read_only_source() {
    let (complete, prefix) = completed_and_uncertain_bytes();
    let source = complete[..prefix + 1].to_vec();
    let mut log = reopen(source.clone(), limits()).unwrap();
    let mut partial = FaultFile::default();
    partial.budget = Some(13);
    let mut failed_sync = FaultFile::default();
    failed_sync.fail_sync = true;
    for candidate in [partial, failed_sync, FaultFile::from(vec![1])] {
        let result = log.recover_tail(candidate, || panic!("preparation cannot publish"));
        assert!(matches!(
            result,
            Err(DurableRemoteError::Io(_) | DurableRemoteError::NotEmpty)
        ));
        assert_eq!(log.status, DurableRemoteJournalStatus::ReadOnlyTail);
        assert_eq!(log.file.bytes.get_ref(), &source);
    }
    let mut panic_sync = FaultFile::default();
    panic_sync.panic_sync = true;
    let result = catch_unwind(AssertUnwindSafe(|| {
        let _ = log.recover_tail(panic_sync, || panic!("preparation cannot publish"));
    }));
    assert!(result.is_err());
    assert_eq!(log.status, DurableRemoteJournalStatus::ReadOnlyTail);
    assert_eq!(log.file.bytes.get_ref(), &source);
    log.recover_tail(FaultFile::default(), || Ok(())).unwrap();
}

#[test]
fn recovery_publication_error_or_panic_poison_without_releasing_pending_fences() {
    let (complete, prefix) = completed_and_uncertain_bytes();
    for panic in [false, true] {
        let source = complete[..prefix + 1].to_vec();
        let mut log = reopen(source.clone(), limits()).unwrap();
        let result = catch_unwind(AssertUnwindSafe(|| {
            log.recover_tail(FaultFile::default(), || {
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
        assert_eq!(log.file.bytes.get_ref(), &source);
        assert!(matches!(
            log.admit(&NodeId::new("peer"), key(2), b"uncertain", 5),
            Err(DurableRemoteError::NotWritable(
                DurableRemoteJournalStatus::Poisoned
            ))
        ));
        let mut reopened = reopen(log.file.bytes.into_inner(), limits()).unwrap();
        assert!(matches!(
            reopened.admit(&NodeId::new("peer"), key(2), b"uncertain", 5),
            Err(DurableRemoteError::InDoubt)
        ));
    }
}

#[test]
fn source_reads_and_length_changes_are_fenced_before_publication() {
    let (complete, prefix) = completed_and_uncertain_bytes();
    for change in 0..3 {
        let mut log = reopen(complete[..prefix + 1].to_vec(), limits()).unwrap();
        match change {
            0 => log.file.bytes.get_mut().push(0),
            1 => log.file.grow_on_read = true,
            _ => log.file.fail_read = true,
        }
        let result = log.recover_tail(FaultFile::default(), || {
            panic!("changed source cannot publish")
        });
        assert!(matches!(
            result,
            Err(DurableRemoteError::Changed | DurableRemoteError::Io(_))
        ));
        assert_eq!(log.status, DurableRemoteJournalStatus::Poisoned);
    }
}

#[test]
fn recovery_reauthenticates_the_complete_prefix_and_refuses_a_different_valid_head() {
    let (complete, prefix) = completed_and_uncertain_bytes();
    let source = complete[..prefix + 1].to_vec();
    let mut log = reopen(source.clone(), limits()).unwrap();
    log.file.bytes.get_mut()[prefix - 1] ^= 1;
    assert!(matches!(
        log.recover_tail(FaultFile::default(), || panic!(
            "corrupt prefix cannot publish"
        )),
        Err(DurableRemoteError::Authentication)
    ));
    assert_eq!(log.status, DurableRemoteJournalStatus::Poisoned);

    let mut other = journal(limits());
    let peer = NodeId::new("peer");
    let first = execute(other.admit(&peer, key(1), b"altered!", 1));
    other.complete(first, success(), 2).unwrap();
    drop(execute(other.admit(&peer, key(2), b"uncertain", 3)));
    assert_eq!(
        other.offset, prefix as u64,
        "valid replacement has the same length and sequence"
    );
    let mut substituted = other.file.bytes.into_inner();
    substituted.push(0);
    let mut log = reopen(source, limits()).unwrap();
    log.file.bytes = IoCursor::new(substituted);
    assert!(matches!(
        log.recover_tail(FaultFile::default(), || panic!(
            "different authenticated head cannot publish"
        )),
        Err(DurableRemoteError::Changed)
    ));
    assert_eq!(log.status, DurableRemoteJournalStatus::Poisoned);
}

#[test]
fn complete_terminal_records_replay_and_complete_corruption_still_refuses_open() {
    let (mut complete, _) = completed_and_uncertain_bytes();
    let mut log = reopen(complete.clone(), limits()).unwrap();
    assert_eq!(log.status, DurableRemoteJournalStatus::Writable);
    assert_eq!(
        replay(log.admit(&NodeId::new("peer"), key(2), b"uncertain", 5)),
        RemoteOutcome::Failed("uncommitted tail outcome".into()).into()
    );
    assert!(matches!(
        log.recover_tail(FaultFile::default(), || panic!(
            "complete tail needs no recovery"
        )),
        Err(DurableRemoteError::NotWritable(
            DurableRemoteJournalStatus::Writable
        ))
    ));
    *complete.last_mut().unwrap() ^= 1;
    assert!(matches!(
        reopen(complete, limits()),
        Err(DurableRemoteError::Authentication)
    ));
}

#[test]
#[cfg(unix)]
fn real_tail_replacement_reopens_after_atomic_publication_even_if_acknowledgement_fails() {
    let (complete, prefix) = completed_and_uncertain_bytes();
    for fail_after_rename in [false, true] {
        let source = complete[..prefix + PREFIX_BYTES + 1].to_vec();
        let (path, mut file) = linked_file();
        file.write_all(&source).unwrap();
        file.sync_all().unwrap();
        let mut log = DurableRemoteJournal::open::<Vec<u8>, Vec<u8>>(
            file,
            COMPUTATION,
            APPLICATION_VERSION,
            AuthKey::from_seed(99),
            limits(),
        )
        .unwrap();
        let (replacement_path, replacement) = linked_file();
        let result = log.recover_tail(replacement, || {
            assert_eq!(std::fs::read(&path)?, source);
            assert_eq!(std::fs::read(&replacement_path)?, complete[..prefix]);
            std::fs::rename(&replacement_path, &path)?;
            File::open(path.parent().unwrap())?.sync_all()?;
            if fail_after_rename {
                Err(io::Error::other("publication already replaced the path"))
            } else {
                Ok(())
            }
        });
        if fail_after_rename {
            assert!(matches!(result, Err(DurableRemoteError::Io(_))));
            assert_eq!(log.status(), DurableRemoteJournalStatus::Poisoned);
        } else {
            assert_eq!(
                result.unwrap().discarded_tail_bytes,
                (PREFIX_BYTES + 1) as u64
            );
            assert_eq!(log.status(), DurableRemoteJournalStatus::Writable);
        }
        drop(log);
        assert_eq!(std::fs::read(&path).unwrap(), complete[..prefix]);
        let mut reopened = DurableRemoteJournal::open::<Vec<u8>, Vec<u8>>(
            open_file(&path),
            COMPUTATION,
            APPLICATION_VERSION,
            AuthKey::from_seed(99),
            limits(),
        )
        .unwrap();
        let peer = NodeId::new("peer");
        assert_eq!(
            replay(reopened.admit(&peer, key(1), b"complete", 5)),
            success().into()
        );
        assert!(matches!(
            reopened.admit(&peer, key(2), b"uncertain", 5),
            Err(DurableRemoteError::InDoubt)
        ));
        let permit =
            reconciliation(reopened.prepare_reconciliation(&peer, key(2), b"uncertain", 6));
        reopened
            .complete_reconciliation(permit, success(), 7)
            .unwrap();
    }
}
