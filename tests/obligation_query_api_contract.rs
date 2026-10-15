//! Runnable contract proof for the obligation audit/query API
//! (bead asupersync-core-introspection-nc8h0u.1).
//!
//! The query surface (`ObligationLedger::counts*`, `obligation_state`, `audit*`)
//! landed in `ca5e5c45a`, validated by doctests and an inline `#[cfg(test)]`
//! test — but that inline `audit_counts` test was never observed green (it was
//! cancelled in RCH's stale-build tail). This integration crate re-proves the
//! epic's success metric ("region R holds exactly N obligations of kind K via
//! the public API") through the published surface, so it stays runnable
//! independent of the lib-unittest binary.
//!
//! Acceptance-criteria coverage (nc8h0u.1):
//!   AC1 — region×kind discrimination: counts_for_region / counts_for_kind /
//!         counts_for_region_and_kind / counts_for_task partition the same
//!         ledger consistently.
//!   AC2 — determinism: audit listings are ordered by `ObligationId` (the
//!         BTreeMap backing guarantees it) and identical across repeated calls.
//!   plus the lifecycle contract: commit/abort transitions are reflected in
//!   counts, `obligation_state`, and the audit snapshot (resolved_at /
//!   abort_reason), and audit records carry the acquisition context.
//!
//! AC4 (panic-leak snapshot through a controlled panic) is covered by the
//! inline test added alongside `graded::panic_leaks()`; it is global-static
//! and not reproduced here to keep this crate deterministic under parallel
//! test execution.
//!
//! Requires `--features test-internals` for the `*::new_for_test` id
//! constructors (distinct regions/tasks); `testing_default()` alone cannot
//! exercise the discrimination criteria.

#![cfg(feature = "test-internals")]

use asupersync::obligation::ledger::ObligationLedger;
use asupersync::record::{ObligationAbortReason, ObligationKind, ObligationState};
use asupersync::types::{RegionId, TaskId, Time};

fn region(index: u32) -> RegionId {
    RegionId::new_for_test(index, 0)
}

fn task(index: u32) -> TaskId {
    TaskId::new_for_test(index, 0)
}

/// AC1 (the epic's success metric): the public query API partitions a single
/// ledger by region, task, and kind without double-counting or bleed-across.
#[test]
fn region_task_and_kind_counts_discriminate() {
    let mut ledger = ObligationLedger::new();
    let region_a = region(1);
    let region_b = region(2);
    let task_x = task(1);
    let task_y = task(2);
    let t = Time::from_nanos(10);

    // region_a / task_x: 3 leases + 2 acks (all left pending).
    for _ in 0..3 {
        let _ = ledger
            .acquire(ObligationKind::Lease, task_x, region_a, t)
            .id();
    }
    for _ in 0..2 {
        let _ = ledger
            .acquire(ObligationKind::Ack, task_x, region_a, t)
            .id();
    }
    // region_b / task_y: 1 lease.
    let _ = ledger
        .acquire(ObligationKind::Lease, task_y, region_b, t)
        .id();

    // The literal success metric: region_a holds exactly 3 obligations of kind Lease.
    assert_eq!(
        ledger
            .counts_for_region_and_kind(region_a, ObligationKind::Lease)
            .pending,
        3
    );
    assert_eq!(
        ledger
            .counts_for_region_and_kind(region_a, ObligationKind::Ack)
            .pending,
        2
    );
    assert_eq!(
        ledger
            .counts_for_region_and_kind(region_b, ObligationKind::Lease)
            .pending,
        1
    );

    // Region partition.
    assert_eq!(ledger.counts_for_region(region_a).total(), 5);
    assert_eq!(ledger.counts_for_region(region_b).total(), 1);
    // Task partition.
    assert_eq!(ledger.counts_for_task(task_x).total(), 5);
    assert_eq!(ledger.counts_for_task(task_y).total(), 1);
    // Kind partition spans regions: 3 (region_a) + 1 (region_b) leases.
    assert_eq!(ledger.counts_for_kind(ObligationKind::Lease).total(), 4);
    assert_eq!(ledger.counts_for_kind(ObligationKind::Ack).total(), 2);
    // Whole ledger.
    assert_eq!(ledger.counts().total(), 6);
    assert_eq!(ledger.counts().pending, 6);

    // audit_region/audit_kind agree with the count partition.
    assert_eq!(ledger.audit_region(region_a, t).len(), 5);
    assert_eq!(ledger.audit_kind(ObligationKind::Lease, t).len(), 4);
    assert_eq!(ledger.audit_task(task_y, t).len(), 1);
}

/// AC2: audit listings are deterministically ordered by `ObligationId` and the
/// ordering is stable across repeated calls; the filtered views are ordered
/// subsequences of the full listing.
#[test]
fn audit_listings_are_deterministically_ordered_by_id() {
    let mut ledger = ObligationLedger::new();
    let r = region(7);
    let task_x = task(7);
    let now = Time::from_nanos(100);

    for i in 0..8u64 {
        let _ = ledger
            .acquire(ObligationKind::Lease, task_x, r, Time::from_nanos(i))
            .id();
    }

    let first = ledger.audit(now);
    let second = ledger.audit(now);

    // Strictly ascending by id within a single listing.
    let ids: Vec<_> = first.iter().map(|rec| rec.id).collect();
    let mut sorted = ids.clone();
    sorted.sort();
    assert_eq!(ids, sorted, "audit() must be ordered by ObligationId");
    for window in ids.windows(2) {
        assert!(
            window[0] < window[1],
            "ids must be strictly ascending (no dups)"
        );
    }

    // Repeated calls produce an identical id sequence (deterministic).
    let ids_again: Vec<_> = second.iter().map(|rec| rec.id).collect();
    assert_eq!(ids, ids_again);

    // The region-filtered view is the same ordered set here (single region).
    let region_ids: Vec<_> = ledger
        .audit_region(r, now)
        .iter()
        .map(|rec| rec.id)
        .collect();
    assert_eq!(region_ids, ids);
}

/// Lifecycle: commit and abort move obligations out of `pending` and are
/// reflected consistently in counts, `obligation_state`, and the audit record
/// (resolved_at populated, abort_reason captured).
#[test]
fn lifecycle_transitions_reflected_in_counts_state_and_audit() {
    let mut ledger = ObligationLedger::new();
    let r = region(3);
    let task_x = task(3);
    let acquired = Time::from_nanos(10);

    // One stays pending, one commits, one aborts (Cancel).
    let pending_id = ledger
        .acquire(ObligationKind::Lease, task_x, r, acquired)
        .id();

    let commit_tok = ledger.acquire(ObligationKind::Ack, task_x, r, acquired);
    let committed_id = commit_tok.id();
    ledger.commit(commit_tok, Time::from_nanos(20));

    let abort_tok = ledger.acquire(ObligationKind::Lease, task_x, r, acquired);
    let aborted_id = abort_tok.id();
    ledger.abort(
        abort_tok,
        Time::from_nanos(30),
        ObligationAbortReason::Cancel,
    );

    // Counts reflect the partition across lifecycle states.
    let counts = ledger.counts_for_region(r);
    assert_eq!(counts.pending, 1);
    assert_eq!(counts.committed, 1);
    assert_eq!(counts.aborted, 1);
    assert_eq!(counts.leaked, 0);
    assert_eq!(counts.total(), 3);
    assert_eq!(counts.resolved(), 2);

    // obligation_state agrees per id.
    assert_eq!(
        ledger.obligation_state(pending_id),
        Some(ObligationState::Reserved)
    );
    assert_eq!(
        ledger.obligation_state(committed_id),
        Some(ObligationState::Committed)
    );
    assert_eq!(
        ledger.obligation_state(aborted_id),
        Some(ObligationState::Aborted)
    );

    // Audit snapshot carries resolution metadata.
    let now = Time::from_nanos(50);
    let records = ledger.audit(now);
    let aborted = records
        .iter()
        .find(|rec| rec.id == aborted_id)
        .expect("aborted record present");
    assert_eq!(aborted.state, ObligationState::Aborted);
    assert_eq!(aborted.abort_reason, Some(ObligationAbortReason::Cancel));
    assert_eq!(aborted.resolved_at, Some(Time::from_nanos(30)));

    let pending = records
        .iter()
        .find(|rec| rec.id == pending_id)
        .expect("pending record present");
    assert_eq!(pending.state, ObligationState::Reserved);
    assert_eq!(pending.abort_reason, None);
    assert_eq!(pending.resolved_at, None);
}

/// Audit records capture the acquisition context: reserved_at is the acquire
/// time and age_ns is measured from it against the query time.
#[test]
fn audit_record_captures_acquisition_context() {
    let mut ledger = ObligationLedger::new();
    let r = region(4);
    let task_x = task(4);
    let _ = ledger
        .acquire(ObligationKind::IoOp, task_x, r, Time::from_nanos(10))
        .id();

    let records = ledger.audit(Time::from_nanos(50));
    assert_eq!(records.len(), 1);
    let rec = &records[0];
    assert_eq!(rec.kind, ObligationKind::IoOp);
    assert_eq!(rec.holder, task_x);
    assert_eq!(rec.region, r);
    assert_eq!(rec.state, ObligationState::Reserved);
    assert_eq!(rec.reserved_at, Time::from_nanos(10));
    assert_eq!(rec.resolved_at, None);
    assert_eq!(rec.age_ns, 40, "age is query_time - reserved_at");
}

/// `obligation_state` returns None for an id this ledger never tracked.
#[test]
fn obligation_state_unknown_id_is_none() {
    let mut source = ObligationLedger::new();
    let foreign_id = source
        .acquire(
            ObligationKind::Lease,
            task(9),
            region(9),
            Time::from_nanos(1),
        )
        .id();

    let empty = ObligationLedger::new();
    assert_eq!(empty.obligation_state(foreign_id), None);
    assert_eq!(empty.counts().total(), 0);
    assert!(empty.audit(Time::from_nanos(1)).is_empty());
}
