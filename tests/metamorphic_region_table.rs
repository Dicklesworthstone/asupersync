#![allow(warnings)]
#![allow(clippy::all)]
use asupersync::record::region::{RegionRecord, RegionState};
use asupersync::runtime::{RegionCreateError, RegionTable};
use asupersync::types::cancel::CancelReason;
use asupersync::types::{Budget, RegionId, TaskId, Time};

#[derive(Clone, Copy)]
enum CleanupStep {
    Child,
    Task,
    Obligation,
}

fn drive_close(order: &[CleanupStep]) -> (Vec<bool>, RegionState) {
    let mut table = RegionTable::new();
    let root = table.create_root(Budget::default(), Time::ZERO);
    let child = table
        .create_child(root, Budget::default(), Time::ZERO)
        .expect("child region");

    let root_record = table.get(root.arena_index()).expect("root record");
    let task = TaskId::new_for_test(7, 0);
    root_record.add_task(task).expect("task admission");
    root_record
        .try_reserve_obligation()
        .expect("obligation admission");

    assert!(root_record.begin_close(None));
    assert!(root_record.begin_drain());
    assert!(root_record.begin_finalize());

    let mut gate_results = vec![root_record.complete_close()];
    for step in order {
        match step {
            CleanupStep::Child => root_record.remove_child(child),
            CleanupStep::Task => root_record.remove_task(task),
            CleanupStep::Obligation => root_record.resolve_obligation(),
        }
        gate_results.push(root_record.complete_close());
    }

    (gate_results, root_record.state())
}

#[test]
fn metamorphic_close_quiescence_gate_is_cleanup_order_independent() {
    let remove_child_first = [
        CleanupStep::Child,
        CleanupStep::Task,
        CleanupStep::Obligation,
    ];
    let resolve_obligation_first = [
        CleanupStep::Obligation,
        CleanupStep::Task,
        CleanupStep::Child,
    ];

    let (child_first_gates, child_first_state) = drive_close(&remove_child_first);
    let (obligation_first_gates, obligation_first_state) = drive_close(&resolve_obligation_first);

    assert_eq!(child_first_gates, vec![false, false, false, true]);
    assert_eq!(obligation_first_gates, vec![false, false, false, true]);
    assert_eq!(child_first_state, RegionState::Closed);
    assert_eq!(obligation_first_state, RegionState::Closed);
}

#[test]
fn metamorphic_repeated_close_stays_fail_closed_for_child_admission() {
    let mut table = RegionTable::new();
    let root = table.create_root(Budget::default(), Time::ZERO);

    {
        let root_record = table.get(root.arena_index()).expect("root record");
        assert!(root_record.begin_close(None));
        assert!(!root_record.begin_close(None));
    }

    for _ in 0..2 {
        let err = table
            .create_child(root, Budget::default(), Time::ZERO)
            .expect_err("closed parent must reject child admission");
        assert_eq!(err, RegionCreateError::ParentClosed(root));
        assert_eq!(
            table.len(),
            1,
            "failed child admission must not leak a record"
        );
    }

    {
        let root_record = table.get(root.arena_index()).expect("root record");
        assert!(root_record.begin_drain());
        assert!(root_record.begin_finalize());
        assert!(root_record.complete_close());
        assert_eq!(root_record.state(), RegionState::Closed);
    }

    for _ in 0..2 {
        let err = table
            .create_child(root, Budget::default(), Time::ZERO)
            .expect_err("closed parent must continue rejecting child admission");
        assert_eq!(err, RegionCreateError::ParentClosed(root));
        assert_eq!(table.len(), 1, "repeated failures must not leak a record");
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// MRs added per bead: IDENTITY + LINEAR + DRAIN + INDEPENDENCE.
//
// The lifecycle these tests drive (per src/record/region.rs:72):
//     Open → Closing → (Draining →)? Finalizing → Closed
//
// Draining is only required when there are still live children to wait
// for; the state machine permits Closing → Finalizing directly when the
// region is already quiescent. These tests intentionally do NOT spin up
// a runtime — they drive RegionTable + RegionRecord APIs directly so the
// metamorphic invariants are isolated from scheduler / cancel-propagation
// noise. The runtime-driven "tasks actually transition to Cancelled"
// surface is covered by the lab oracle suite (src/lab/oracle/).
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, PartialEq, Eq)]
struct TableSnapshot {
    len: usize,
    is_empty: bool,
    draining: usize,
}

fn snapshot(table: &RegionTable) -> TableSnapshot {
    TableSnapshot {
        len: table.len(),
        is_empty: table.is_empty(),
        draining: table.draining_region_count(),
    }
}

fn snapshot_record(r: &RegionRecord) -> (RegionState, usize, usize, bool) {
    (
        r.state(),
        r.task_count(),
        r.child_count(),
        r.cancel_reason().is_some(),
    )
}

/// Walk a region from Open straight through Closing → Finalizing → Closed.
/// Skips the Draining step (only required when children are live), so the
/// caller must ensure the region is already quiescent.
fn close_region_no_drain(table: &RegionTable, id: RegionId) {
    let r = table.get(id.arena_index()).expect("region must exist");
    assert!(r.begin_close(None), "begin_close must succeed on Open");
    assert!(r.begin_finalize(), "begin_finalize must succeed from Closing");
    assert!(r.complete_close(), "complete_close must succeed when quiescent");
    assert_eq!(r.state(), RegionState::Closed);
}

fn close_and_remove(table: &mut RegionTable, id: RegionId) {
    close_region_no_drain(table, id);
    let removed = table.remove(id.arena_index());
    assert!(removed.is_some(), "remove must return the closed record");
}

// ─── MR-IDENTITY ─────────────────────────────────────────────────────────────
// open(R) then close(R) returns to initial state.

#[test]
fn mr_identity_create_then_close_round_trips_to_initial_state() {
    let mut table = RegionTable::new();
    let pre = snapshot(&table);
    assert_eq!(pre, TableSnapshot { len: 0, is_empty: true, draining: 0 });

    let r = table.create_root(Budget::default(), Time::ZERO);
    assert_eq!(table.len(), 1);
    assert_eq!(
        table.get(r.arena_index()).unwrap().state(),
        RegionState::Open,
        "newly created region must be Open"
    );

    close_and_remove(&mut table, r);

    assert_eq!(
        snapshot(&table),
        pre,
        "MR-IDENTITY: post-close+remove state must equal pre-creation state"
    );
}

#[test]
fn mr_identity_repeated_create_close_remains_idempotent() {
    // Identity should hold over repeated rounds — there should be no
    // hidden monotonic counter that drifts.
    let mut table = RegionTable::new();
    let pre = snapshot(&table);
    for _ in 0..16 {
        let r = table.create_root(Budget::default(), Time::ZERO);
        close_and_remove(&mut table, r);
    }
    assert_eq!(snapshot(&table), pre, "MR-IDENTITY: 16 rounds must return to initial");
}

// ─── MR-LINEAR ───────────────────────────────────────────────────────────────
// open R, open child(R), close child, close R  ≡  open R, close R

#[test]
fn mr_linear_child_close_then_parent_close_equals_parent_alone() {
    // Path A: with a child.
    let mut table_a = RegionTable::new();
    let r_a = table_a.create_root(Budget::default(), Time::ZERO);
    let c_a = table_a
        .create_child(r_a, Budget::default(), Time::ZERO)
        .expect("create_child must succeed under an Open parent");
    assert_eq!(
        table_a.get(r_a.arena_index()).unwrap().child_count(),
        1,
        "child must register with parent's child set"
    );
    close_region_no_drain(&table_a, c_a);
    table_a.get(r_a.arena_index()).unwrap().remove_child(c_a);
    assert_eq!(
        table_a.get(r_a.arena_index()).unwrap().child_count(),
        0,
        "parent's child set must be empty after child removal"
    );
    table_a.remove(c_a.arena_index());
    close_and_remove(&mut table_a, r_a);

    // Path B: parent alone.
    let mut table_b = RegionTable::new();
    let r_b = table_b.create_root(Budget::default(), Time::ZERO);
    close_and_remove(&mut table_b, r_b);

    assert_eq!(
        snapshot(&table_a),
        snapshot(&table_b),
        "MR-LINEAR: child-then-parent close ≡ parent-alone close on table state"
    );
    assert_eq!(snapshot(&table_a), TableSnapshot { len: 0, is_empty: true, draining: 0 });
}

#[test]
fn mr_linear_parent_cannot_complete_close_with_live_child() {
    // Negative companion to MR-LINEAR: complete_close on a parent that
    // still has a live child MUST fail (otherwise the linearity property
    // could be vacuously satisfied by closing parent first and silently
    // dropping the child).
    let mut table = RegionTable::new();
    let r = table.create_root(Budget::default(), Time::ZERO);
    let _c = table
        .create_child(r, Budget::default(), Time::ZERO)
        .expect("create_child");
    let parent = table.get(r.arena_index()).unwrap();
    assert!(parent.begin_close(None));
    assert!(parent.begin_finalize());
    assert!(
        !parent.complete_close(),
        "complete_close MUST refuse while a child is registered"
    );
    let _ = table;
}

// ─── MR-DRAIN ────────────────────────────────────────────────────────────────
// cancel(R) → all owned tasks reach Cancelled (request-phase invariants).
//
// Without a running scheduler we can't observe tasks transitioning to
// Cancelled. What we CAN test is the table-side and record-side
// bookkeeping that any scheduler must honour:
//   * cancel_request records the reason exactly once (idempotent
//     strengthening on subsequent calls).
//   * begin_close transitions to Closing, after which admission rejects
//     new tasks (so the drain set is bounded — no new tasks leak in).
//   * draining_region_count reflects {Draining, Finalizing} regions.

#[test]
fn mr_drain_cancel_request_records_reason_and_closes_admission() {
    let mut table = RegionTable::new();
    let r = table.create_root(Budget::default(), Time::ZERO);
    let region = table.get(r.arena_index()).unwrap();
    let t1 = TaskId::new_for_test(101, 0);
    let t2 = TaskId::new_for_test(102, 0);
    region.add_task(t1).expect("add_task open");
    region.add_task(t2).expect("add_task open");
    assert_eq!(region.task_count(), 2);

    // Phase 1: cancel_request must atomically record the reason.
    // Idempotent strengthening on subsequent calls.
    assert!(
        region.cancel_request(CancelReason::user("test-cancel")),
        "first cancel_request must report 'newly applied'"
    );
    assert!(
        !region.cancel_request(CancelReason::user("test-cancel")),
        "duplicate cancel_request must report 'already applied' (idempotent)"
    );
    assert!(region.cancel_reason().is_some());

    // Phase 2: transitioning to Closing closes admission. Any new
    // add_task must fail — the drain set is now bounded to {t1, t2}.
    assert!(region.begin_close(None));
    assert_eq!(region.state(), RegionState::Closing);
    let admit_err = region.add_task(TaskId::new_for_test(103, 0));
    assert!(
        admit_err.is_err(),
        "add_task after Closing must be rejected so the drain set is bounded"
    );

    // Phase 3: drain models the scheduler's Cancelled-resolution by
    // removing exactly the snapshot taken at cancel time.
    region.remove_task(t1);
    region.remove_task(t2);
    assert_eq!(region.task_count(), 0);
}

#[test]
fn mr_drain_table_draining_count_tracks_in_flight_drain() {
    let mut table = RegionTable::new();
    let r1 = table.create_root(Budget::default(), Time::ZERO);
    let r2 = table.create_root(Budget::default(), Time::ZERO);
    let r3 = table.create_root(Budget::default(), Time::ZERO);
    assert_eq!(table.draining_region_count(), 0, "no regions are draining yet");

    {
        let r = table.get(r1.arena_index()).unwrap();
        assert!(r.begin_close(None));
        assert!(r.begin_drain());
        assert_eq!(r.state(), RegionState::Draining);
    }
    {
        let r = table.get(r2.arena_index()).unwrap();
        assert!(r.begin_close(None));
        assert!(r.begin_finalize());
        assert_eq!(r.state(), RegionState::Finalizing);
    }
    assert_eq!(
        table.draining_region_count(),
        2,
        "draining_region_count must equal |{{Draining, Finalizing}}|"
    );
    let _ = r3;
}

// ─── MR-INDEPENDENCE ─────────────────────────────────────────────────────────
// Regions R1 and R2 with no parent-child link are independent: mutating
// one is invisible to the other on every observable dimension.

#[test]
fn mr_independence_mutating_one_region_does_not_perturb_the_other() {
    let mut table = RegionTable::new();
    let r1 = table.create_root(Budget::default(), Time::ZERO);
    let r2 = table.create_root(Budget::default(), Time::ZERO);

    let r2_pre = snapshot_record(table.get(r2.arena_index()).unwrap());
    assert_eq!(r2_pre, (RegionState::Open, 0, 0, false));

    // Aggressive mutation of R1: tasks, cancel, transition.
    {
        let r = table.get(r1.arena_index()).unwrap();
        r.add_task(TaskId::new_for_test(1, 0)).unwrap();
        r.add_task(TaskId::new_for_test(2, 0)).unwrap();
        r.add_task(TaskId::new_for_test(3, 0)).unwrap();
        r.cancel_request(CancelReason::user("only-r1"));
        assert!(r.begin_close(None));
    }

    let r2_post = snapshot_record(table.get(r2.arena_index()).unwrap());
    assert_eq!(
        r2_post, r2_pre,
        "MR-INDEPENDENCE: R2 state must be unchanged after R1 mutations"
    );

    // Symmetric direction.
    let r1_pre = snapshot_record(table.get(r1.arena_index()).unwrap());
    assert_eq!(r1_pre, (RegionState::Closing, 3, 0, true));
    {
        let r = table.get(r2.arena_index()).unwrap();
        r.add_task(TaskId::new_for_test(99, 0)).unwrap();
        r.cancel_request(CancelReason::user("only-r2"));
    }
    let r1_post = snapshot_record(table.get(r1.arena_index()).unwrap());
    assert_eq!(
        r1_post, r1_pre,
        "MR-INDEPENDENCE (symmetric): R1 state must be unchanged after R2 mutations"
    );
}

#[test]
fn mr_independence_table_draining_count_is_additive_across_independent_regions() {
    let mut table = RegionTable::new();
    let r1 = table.create_root(Budget::default(), Time::ZERO);
    let r2 = table.create_root(Budget::default(), Time::ZERO);
    let r3 = table.create_root(Budget::default(), Time::ZERO);

    {
        let r = table.get(r1.arena_index()).unwrap();
        assert!(r.begin_close(None));
        assert!(r.begin_drain());
    }
    let after_r1 = table.draining_region_count();
    assert_eq!(after_r1, 1);

    {
        let r = table.get(r2.arena_index()).unwrap();
        assert!(r.begin_close(None));
        assert!(r.begin_finalize());
    }
    let after_r2 = table.draining_region_count();
    assert_eq!(
        after_r2,
        after_r1 + 1,
        "MR-INDEPENDENCE: each draining transition adds exactly 1 to the count"
    );
    let _ = r3;
}
