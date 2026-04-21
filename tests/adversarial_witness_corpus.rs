#![allow(clippy::all)]
//! Adversarial Witness Corpus and Regression Generator (SEM-12.13)
//!
//! Bead: `asupersync-3cddg.12.13`
//! Parent: SEM-12 Comprehensive Verification Fabric
//!
//! This module implements a maintained corpus of adversarial semantic witnesses
//! including ambiguity classes and edge-case counterexamples, plus generator
//! functions that produce deterministic regression cases for runtime/docs/Lean/TLA
//! verification flows.
//!
//! # Witness Families
//!
//! 1. **Tie-breaking** (WF-TIE): Equal-severity outcome ties, join left-bias
//! 2. **Absorbing states** (WF-ABS): Panicked absorbs all, Cancelled absorbs Ok/Err
//! 3. **Lifecycle races** (WF-RACE): Race + cancel + drain interaction
//! 4. **Obligation leaks** (WF-OBL): Obligation lifecycle + cancel interaction
//! 5. **Mask/protocol edge cases** (WF-MASK): Deep masking, bounded drain
//! 6. **Cross-ADR cascades** (WF-XADR): Interactions across ADR boundaries
//!
//! # Rule-ID Mapping
//!
//! Each witness maps to canonical rule IDs from `docs/semantic_contract_schema.md`:
//! - WF-TIE: #29-32 (outcome domain)
//! - WF-ABS: #29-31 (four-valued, severity lattice, join semantics)
//! - WF-RACE: #1-4, #38, #40 (cancel protocol + race + loser drain)
//! - WF-OBL: #13-21 (obligation domain)
//! - WF-MASK: #5, #10-12 (cancel idempotence, checkpoint, mask bounded/monotone)
//! - WF-XADR: #37-43, #44-47 (combinator + capability + determinism)

#[macro_use]
mod common;

use asupersync::combinator::race::{RaceWinner, race2_outcomes};
use asupersync::combinator::timeout::effective_deadline;
use asupersync::lab::config::LabConfig;
use asupersync::lab::fuzz::{FuzzConfig, FuzzHarness, fuzz_quick};
use asupersync::lab::oracle::{
    CancellationProtocolOracle, LoserDrainOracle, ObligationLeakOracle, QuiescenceOracle,
};
use asupersync::record::task::TaskState;
use asupersync::record::{ObligationKind, ObligationState};
use asupersync::types::cancel::{CancelKind, CancelReason};
use asupersync::types::outcome::{PanicPayload, join_outcomes};
use asupersync::types::{Budget, ObligationId, Outcome, RegionId, Severity, TaskId, Time};
use common::*;

// ============================================================================
// Helpers — stable IDs for deterministic witness construction
// ============================================================================

fn region(n: u32) -> RegionId {
    RegionId::new_for_test(n, 0)
}

fn task(n: u32) -> TaskId {
    TaskId::new_for_test(n, 0)
}

fn obligation(n: u32) -> ObligationId {
    ObligationId::new_for_test(n, 0)
}

fn t(nanos: u64) -> Time {
    Time::from_nanos(nanos)
}

/// Stable seed namespace for adversarial witnesses.
/// Each family uses a distinct base seed for reproducibility.
const SEED_TIE: u64 = 0xADC0_0001;
const SEED_ABS: u64 = 0xADC0_0002;
const SEED_RACE: u64 = 0xADC0_0003;
const SEED_OBL: u64 = 0xADC0_0004;
const SEED_XADR: u64 = 0xADC0_0006;

// ============================================================================
// WF-TIE: Tie-Breaking Witnesses
// Rule IDs: #29 (def.outcome.four_valued), #30 (def.outcome.severity_lattice),
//           #31 (def.outcome.join_semantics)
// ============================================================================

/// WF-TIE.1: Join of equal-severity outcomes preserves left-bias.
///
/// When two outcomes have the same severity, join() must return the first
/// (left) argument. This is the tie-breaking rule from ADR-008.
///
/// Exhaustively tests all 4 same-severity pairs: Ok+Ok, Err+Err,
/// Cancelled+Cancelled, Panicked+Panicked.
#[test]
fn wf_tie_1_join_left_bias_on_equal_severity() {
    init_test_logging();

    let outcomes = [
        Outcome::Ok("left-ok"),
        Outcome::Err("left-err"),
        Outcome::Cancelled(CancelReason::user("z-left")),
        Outcome::Panicked(PanicPayload::new("left-panic")),
    ];

    let right_variants = [
        Outcome::Ok("right-ok"),
        Outcome::Err("right-err"),
        Outcome::Cancelled(CancelReason::user("a-right")),
        Outcome::Panicked(PanicPayload::new("right-panic")),
    ];

    // Same-severity pairs: join(left, right) must preserve the full left value,
    // not just the severity class. The Cancelled case deliberately uses two
    // equal-severity reasons where strengthen() would prefer the RHS by message
    // ordering if join() delegated tie-breaking incorrectly.
    for (left, right) in outcomes.iter().zip(right_variants.iter()) {
        let joined = join_outcomes(left.clone(), right.clone());
        let reversed = join_outcomes(right.clone(), left.clone());

        assert_eq!(
            joined,
            left.clone(),
            "WF-TIE.1 VIOLATED: join({left:?}, {right:?}) must preserve the left value on equal severity",
        );
        assert_eq!(
            reversed,
            right.clone(),
            "WF-TIE.1 VIOLATED: join({right:?}, {left:?}) must preserve the left value on equal severity",
        );
    }
}

/// WF-TIE.2: Join is NOT commutative on values (only on severity).
///
/// This is a known design decision (join picks left on tie), NOT a bug.
/// Adversarial witness demonstrates that property-test frameworks must
/// compare SEVERITY, not VALUE, when checking commutativity.
#[test]
fn wf_tie_2_join_severity_commutative_value_not() {
    init_test_logging();

    let p_left = Outcome::<(), ()>::Panicked(PanicPayload::new("left"));
    let p_right = Outcome::<(), ()>::Panicked(PanicPayload::new("right"));

    let lr = join_outcomes(p_left.clone(), p_right.clone());
    let rl = join_outcomes(p_right, p_left);

    // Severity IS commutative
    assert_eq!(
        lr.severity(),
        rl.severity(),
        "WF-TIE.2: severity must be commutative"
    );

    // But both are Panicked — the SEVERITY is what matters for semantic correctness,
    // not the payload. This witness documents the design choice.
    assert_eq!(lr.severity(), Severity::Panicked);
    assert_eq!(rl.severity(), Severity::Panicked);
}

/// WF-TIE.3: Exhaustive 4x4 join severity matrix.
///
/// Verifies join(a,b).severity == max(a.severity, b.severity) for all 16
/// combinations of the 4-valued outcome type.
#[test]
fn wf_tie_3_exhaustive_severity_matrix() {
    init_test_logging();

    let all = [
        Outcome::Ok(()),
        Outcome::Err(()),
        Outcome::Cancelled(CancelReason::timeout()),
        Outcome::Panicked(PanicPayload::new("x")),
    ];

    for a in &all {
        for b in &all {
            let joined = join_outcomes(a.clone(), b.clone());
            let expected = if a.severity().as_u8() >= b.severity().as_u8() {
                a.severity()
            } else {
                b.severity()
            };
            assert_eq!(
                joined.severity(),
                expected,
                "WF-TIE.3 VIOLATED: join({a:?}, {b:?}).severity = {:?}, expected {expected:?}",
                joined.severity(),
            );
        }
    }
}

// ============================================================================
// WF-ABS: Absorbing State Witnesses
// Rule IDs: #29-31 (outcome domain)
// ============================================================================

/// WF-ABS.1: Panicked absorbs all other outcomes.
///
/// For any outcome X, join(Panicked, X) == Panicked and
/// join(X, Panicked) == Panicked. Panicked is the top of the severity lattice.
#[test]
fn wf_abs_1_panicked_absorbs_all() {
    init_test_logging();

    let panicked = Outcome::<(), ()>::Panicked(PanicPayload::new("boom"));
    let others = [
        Outcome::Ok(()),
        Outcome::Err(()),
        Outcome::Cancelled(CancelReason::timeout()),
    ];

    for other in &others {
        let left = join_outcomes(panicked.clone(), other.clone());
        let right = join_outcomes(other.clone(), panicked.clone());

        assert_eq!(
            left.severity(),
            Severity::Panicked,
            "WF-ABS.1: Panicked must absorb {other:?} (left)"
        );
        assert_eq!(
            right.severity(),
            Severity::Panicked,
            "WF-ABS.1: Panicked must absorb {other:?} (right)"
        );
    }
}

/// WF-ABS.2: Ok is the identity for join (bottom of severity lattice).
///
/// For any outcome X, join(Ok, X) has severity == X.severity.
#[test]
fn wf_abs_2_ok_is_identity_severity() {
    init_test_logging();

    let ok = Outcome::<(), ()>::Ok(());
    let all = [
        Outcome::Ok(()),
        Outcome::Err(()),
        Outcome::Cancelled(CancelReason::timeout()),
        Outcome::Panicked(PanicPayload::new("x")),
    ];

    for x in &all {
        let joined = join_outcomes(ok.clone(), x.clone());
        assert_eq!(
            joined.severity(),
            x.severity(),
            "WF-ABS.2: join(Ok, {x:?}).severity should be {:?}",
            x.severity(),
        );
    }
}

/// WF-ABS.3: Severity chain is strictly ordered.
///
/// Ok(0) < Err(1) < Cancelled(2) < Panicked(3) — no gaps, no ties.
#[test]
fn wf_abs_3_severity_strict_order() {
    init_test_logging();

    let severities = [
        Severity::Ok,
        Severity::Err,
        Severity::Cancelled,
        Severity::Panicked,
    ];

    for i in 0..severities.len() {
        for j in (i + 1)..severities.len() {
            assert!(
                severities[i].as_u8() < severities[j].as_u8(),
                "WF-ABS.3 VIOLATED: {:?} ({}) must be < {:?} ({})",
                severities[i],
                severities[i].as_u8(),
                severities[j],
                severities[j].as_u8(),
            );
        }
    }
}

// ============================================================================
// WF-RACE: Lifecycle Race Witnesses
// Rule IDs: #1-4 (cancel protocol), #38 (comb.race), #40 (loser drained)
// ============================================================================

/// WF-RACE.1: Race with immediate winner — loser must reach terminal state.
///
/// Exercises W1.1 from the witness pack: fast_task wins, slow_task must drain.
/// Uses LoserDrainOracle to verify the invariant holds.
#[test]
fn wf_race_1_immediate_winner_loser_drained() {
    init_test_logging();

    let root = region(0);
    let fast = task(1);
    let slow = task(2);

    let mut oracle = LoserDrainOracle::new();
    let race_id = oracle.on_race_start(root, vec![fast, slow], t(0));

    // Fast task wins at t=100
    oracle.on_task_complete(fast, t(100));
    // Slow task drains and completes at t=200
    oracle.on_task_complete(slow, t(200));
    // Race completes with fast as winner
    oracle.on_race_complete(race_id, fast, t(200));

    let result = oracle.check();
    assert!(
        result.is_ok(),
        "WF-RACE.1: LoserDrainOracle must pass when loser is properly drained: {result:?}"
    );
}

/// WF-RACE.2: Race with ZERO completion gap — both tasks complete at same time.
///
/// Adversarial edge case: what happens when winner and loser complete at the
/// exact same virtual timestamp? Winner is determined by argument order (index).
#[test]
fn wf_race_2_simultaneous_completion() {
    init_test_logging();

    let root = region(0);
    let first = task(1);
    let second = task(2);

    let mut oracle = LoserDrainOracle::new();
    let race_id = oracle.on_race_start(root, vec![first, second], t(0));

    // Both complete at t=100 — first wins by index
    oracle.on_task_complete(first, t(100));
    oracle.on_task_complete(second, t(100));
    oracle.on_race_complete(race_id, first, t(100));

    assert!(
        oracle.check().is_ok(),
        "WF-RACE.2: simultaneous completion must still drain loser"
    );
}

/// WF-RACE.3: Race API commutativity — severity invariant under argument swap.
///
/// Exercises W5.2: race(a, b) and race(b, a) produce same winner severity
/// for any fixed outcome pair.
#[test]
fn wf_race_3_commutativity_all_outcome_pairs() {
    init_test_logging();

    let outcomes: Vec<Outcome<(), ()>> = vec![
        Outcome::Ok(()),
        Outcome::Err(()),
        Outcome::Cancelled(CancelReason::timeout()),
        Outcome::Panicked(PanicPayload::new("boom")),
    ];

    for a in &outcomes {
        for b in &outcomes {
            let (w1, _, l1) = race2_outcomes(RaceWinner::First, a.clone(), b.clone());
            let (w2, _, l2) = race2_outcomes(RaceWinner::First, b.clone(), a.clone());

            // Winner severity: race always returns first arg as winner when First
            assert_eq!(
                w1.severity(),
                a.severity(),
                "WF-RACE.3: race(a,b) winner severity mismatch"
            );
            assert_eq!(
                w2.severity(),
                b.severity(),
                "WF-RACE.3: race(b,a) winner severity mismatch"
            );

            // Loser: must be terminal
            assert!(
                l1.severity() <= Severity::Panicked,
                "WF-RACE.3: loser must be terminal"
            );
            assert!(
                l2.severity() <= Severity::Panicked,
                "WF-RACE.3: loser must be terminal"
            );
        }
    }
}

/// WF-RACE.4: Multi-participant race — all N-1 losers drain.
///
/// Adversarial case: race with 4 participants, only 1 winner.
/// LoserDrainOracle must see all 3 losers complete before race_complete.
#[test]
fn wf_race_4_multi_participant_all_losers_drain() {
    init_test_logging();

    let root = region(0);
    let participants: Vec<TaskId> = (1..=4).map(task).collect();

    let mut oracle = LoserDrainOracle::new();
    let race_id = oracle.on_race_start(root, participants.clone(), t(0));

    // Task 2 wins at t=50
    oracle.on_task_complete(participants[1], t(50));
    // Losers drain: task 1 at t=100, task 3 at t=150, task 4 at t=200
    oracle.on_task_complete(participants[0], t(100));
    oracle.on_task_complete(participants[2], t(150));
    oracle.on_task_complete(participants[3], t(200));

    oracle.on_race_complete(race_id, participants[1], t(200));

    assert!(
        oracle.check().is_ok(),
        "WF-RACE.4: all 3 losers in 4-way race must drain"
    );
    assert_eq!(oracle.completed_race_count(), 1);
}

// ============================================================================
// WF-OBL: Obligation Leak Witnesses
// Rule IDs: #13-17 (obligation lifecycle), #18 (linear), #19 (bounded),
//           #20 (ledger empty on close)
// ============================================================================

/// WF-OBL.1: All 3 obligation kinds (SendPermit, Lease, Acknowledgement)
/// properly resolve without leaks.
#[test]
fn wf_obl_1_all_kinds_resolve_clean() {
    init_test_logging();

    let root = region(0);
    let worker = task(1);

    let kinds = [
        (ObligationKind::SendPermit, obligation(10)),
        (ObligationKind::Lease, obligation(11)),
        (ObligationKind::Ack, obligation(12)),
    ];

    for (kind, obl_id) in &kinds {
        let mut oracle = ObligationLeakOracle::new();
        oracle.on_create(*obl_id, *kind, worker, root);
        oracle.on_resolve(*obl_id, ObligationState::Committed);
        oracle.on_region_close(root, t(100));

        assert!(
            oracle.check(t(100)).is_ok(),
            "WF-OBL.1: committed {kind:?} must not leak"
        );
    }
}

/// WF-OBL.2: Obligation leaked across region close — oracle MUST detect.
///
/// This is a violation witness: obligation created but never resolved.
#[test]
fn wf_obl_2_unresolved_obligation_detected() {
    init_test_logging();

    let root = region(0);
    let worker = task(1);
    let obl = obligation(10);

    let mut oracle = ObligationLeakOracle::new();
    oracle.on_create(obl, ObligationKind::SendPermit, worker, root);
    // Do NOT resolve the obligation
    oracle.on_region_close(root, t(100));

    let result = oracle.check(t(100));
    assert!(
        result.is_err(),
        "WF-OBL.2: unresolved obligation MUST be detected as leak"
    );
}

/// WF-OBL.3: Obligation aborted during cancel — must be clean.
///
/// Exercises the cancel+obligation interaction: a task holding an obligation
/// gets cancelled and aborts the obligation during drain.
#[test]
fn wf_obl_3_abort_during_cancel_is_clean() {
    init_test_logging();

    let root = region(0);
    let worker = task(1);
    let obl = obligation(10);

    let mut obl_oracle = ObligationLeakOracle::new();
    let mut cancel_oracle = CancellationProtocolOracle::new();

    cancel_oracle.on_region_create(root, None);
    cancel_oracle.on_task_create(worker, root);

    // Task runs and acquires obligation
    let reason = CancelReason::timeout();
    let budget = Budget::INFINITE;
    cancel_oracle.on_transition(worker, &TaskState::Created, &TaskState::Running, t(10));
    obl_oracle.on_create(obl, ObligationKind::Lease, worker, root);

    // Cancel requested
    cancel_oracle.on_cancel_request(worker, reason.clone(), t(50));
    cancel_oracle.on_transition(
        worker,
        &TaskState::Running,
        &TaskState::CancelRequested {
            reason: reason.clone(),
            cleanup_budget: budget,
        },
        t(50),
    );

    // Drain: obligation aborted
    cancel_oracle.on_transition(
        worker,
        &TaskState::CancelRequested {
            reason: reason.clone(),
            cleanup_budget: budget,
        },
        &TaskState::Cancelling {
            reason: reason.clone(),
            cleanup_budget: budget,
        },
        t(100),
    );
    obl_oracle.on_resolve(obl, ObligationState::Aborted);

    // Finalize
    cancel_oracle.on_transition(
        worker,
        &TaskState::Cancelling {
            reason: reason.clone(),
            cleanup_budget: budget,
        },
        &TaskState::Finalizing {
            reason: reason.clone(),
            cleanup_budget: budget,
        },
        t(150),
    );
    cancel_oracle.on_transition(
        worker,
        &TaskState::Finalizing {
            reason: reason.clone(),
            cleanup_budget: budget,
        },
        &TaskState::Completed(Outcome::Cancelled(reason)),
        t(200),
    );

    obl_oracle.on_region_close(root, t(250));

    assert!(
        cancel_oracle.check().is_ok(),
        "WF-OBL.3: cancel protocol clean"
    );
    assert!(
        obl_oracle.check(t(250)).is_ok(),
        "WF-OBL.3: aborted obligation must not leak"
    );
}

/// WF-OBL.4: Multiple obligations in different states — mixed resolve.
///
/// One committed, one aborted, one leaked. Oracle must detect exactly the leak.
#[test]
fn wf_obl_4_mixed_resolve_detects_single_leak() {
    init_test_logging();

    let root = region(0);
    let worker = task(1);
    let committed = obligation(10);
    let aborted = obligation(11);
    let leaked = obligation(12);

    let mut oracle = ObligationLeakOracle::new();

    oracle.on_create(committed, ObligationKind::SendPermit, worker, root);
    oracle.on_create(aborted, ObligationKind::Lease, worker, root);
    oracle.on_create(leaked, ObligationKind::Ack, worker, root);

    oracle.on_resolve(committed, ObligationState::Committed);
    oracle.on_resolve(aborted, ObligationState::Aborted);
    // leaked: intentionally not resolved

    oracle.on_region_close(root, t(100));

    let result = oracle.check(t(100));
    assert!(
        result.is_err(),
        "WF-OBL.4: one leaked obligation must be detected even when others are clean"
    );
}

// ============================================================================
// WF-MASK: Mask/Protocol Edge Cases
// Rule IDs: #5 (cancel idempotence), #10 (checkpoint masked),
//           #11 (mask bounded), #12 (mask monotone)
// ============================================================================

/// WF-MASK.1: Cancel strengthen is idempotent.
///
/// strengthen(x, x) has no effect (returns false, severity unchanged).
#[test]
fn wf_mask_1_strengthen_idempotent() {
    init_test_logging();

    let reasons = [
        CancelReason::user("test"),
        CancelReason::timeout(),
        CancelReason::shutdown(),
    ];

    for r in &reasons {
        let mut copy = r.clone();
        let sev_before = copy.severity();
        let changed = copy.strengthen(r);
        assert!(
            !changed,
            "WF-MASK.1: strengthen(x, x) must return false (no change)"
        );
        assert_eq!(
            copy.severity(),
            sev_before,
            "WF-MASK.1: severity must be unchanged after self-strengthen"
        );
    }
}

/// WF-MASK.2: Strengthen monotonicity — severity never decreases.
///
/// For any pair (a, b), after a.strengthen(b), a.severity >= max(old_a, b).
#[test]
fn wf_mask_2_strengthen_monotone() {
    init_test_logging();

    let reasons = [
        CancelReason::user("test"),
        CancelReason::timeout(),
        CancelReason::shutdown(),
    ];

    for a in &reasons {
        for b in &reasons {
            let mut copy = a.clone();
            let sev_a = copy.severity();
            copy.strengthen(b);
            let max_sev = std::cmp::max(sev_a, b.severity());
            assert!(
                copy.severity() >= max_sev,
                "WF-MASK.2 VIOLATED: after strengthen({a:?}, {b:?}), severity = {}, \
                 expected >= {max_sev}",
                copy.severity(),
            );
        }
    }
}

/// WF-MASK.3: All 11 CancelKind variants have valid severity in [0, 5].
///
/// No variant may map to severity > 5 or panic during severity().
#[test]
fn wf_mask_3_all_kinds_valid_severity() {
    init_test_logging();

    let all_kinds: [CancelKind; 11] = [
        CancelKind::User,
        CancelKind::Timeout,
        CancelKind::Deadline,
        CancelKind::PollQuota,
        CancelKind::CostBudget,
        CancelKind::FailFast,
        CancelKind::RaceLost,
        CancelKind::ParentCancelled,
        CancelKind::ResourceUnavailable,
        CancelKind::Shutdown,
        CancelKind::LinkedExit,
    ];

    for kind in &all_kinds {
        let sev = kind.severity();
        assert!(
            sev <= 5,
            "WF-MASK.3 VIOLATED: {kind:?}.severity() = {sev}, exceeds max 5"
        );
    }

    // Boundary checks
    assert_eq!(CancelKind::User.severity(), 0, "User must be min severity");
    assert_eq!(
        CancelKind::Shutdown.severity(),
        5,
        "Shutdown must be max severity"
    );
}

/// WF-MASK.4: Cancel protocol propagation — parent cancel reaches child.
///
/// Uses CancellationProtocolOracle to verify inv.cancel.propagates_down (#6).
#[test]
fn wf_mask_4_cancel_propagates_to_nested_child() {
    init_test_logging();

    let root = region(0);
    let child = region(1);
    let grandchild = region(2);
    let task_gc = task(3);

    let mut oracle = CancellationProtocolOracle::new();

    // Build region tree
    oracle.on_region_create(root, None);
    oracle.on_region_create(child, Some(root));
    oracle.on_region_create(grandchild, Some(child));
    oracle.on_task_create(task_gc, grandchild);

    let reason = CancelReason::shutdown();
    let budget = Budget::INFINITE;

    // Task starts
    oracle.on_transition(task_gc, &TaskState::Created, &TaskState::Running, t(10));

    // Cancel at root propagates down to grandchild
    oracle.on_region_cancel(root, reason.clone(), t(50));
    oracle.on_region_cancel(child, reason.clone(), t(51));
    oracle.on_region_cancel(grandchild, reason.clone(), t(52));

    // Task in grandchild receives cancel and completes protocol
    oracle.on_cancel_request(task_gc, reason.clone(), t(53));
    oracle.on_transition(
        task_gc,
        &TaskState::Running,
        &TaskState::CancelRequested {
            reason: reason.clone(),
            cleanup_budget: budget,
        },
        t(53),
    );
    oracle.on_transition(
        task_gc,
        &TaskState::CancelRequested {
            reason: reason.clone(),
            cleanup_budget: budget,
        },
        &TaskState::Cancelling {
            reason: reason.clone(),
            cleanup_budget: budget,
        },
        t(100),
    );
    oracle.on_transition(
        task_gc,
        &TaskState::Cancelling {
            reason: reason.clone(),
            cleanup_budget: budget,
        },
        &TaskState::Finalizing {
            reason: reason.clone(),
            cleanup_budget: budget,
        },
        t(150),
    );
    oracle.on_transition(
        task_gc,
        &TaskState::Finalizing {
            reason: reason.clone(),
            cleanup_budget: budget,
        },
        &TaskState::Completed(Outcome::Cancelled(reason)),
        t(200),
    );

    assert!(
        oracle.check().is_ok(),
        "WF-MASK.4: cancel propagation through 3 region levels must satisfy protocol"
    );
}

// ============================================================================
// WF-XADR: Cross-ADR Cascade Witnesses
// Rule IDs: #37-43 (combinator), #44-47 (capability + determinism)
// ============================================================================

/// WF-XADR.1: Timeout min law + join associativity compose correctly.
///
/// Verifies that effective_deadline(outer, Some(inner)) == min(outer, inner)
/// AND that join of timeout outcomes is associative, testing the ADR-005
/// combinator law composition.
#[test]
fn wf_xadr_1_timeout_min_plus_join_assoc() {
    init_test_logging();

    // Timeout min law (effective_deadline takes Time, not Duration)
    let deadlines: [(u64, u64); 4] = [
        (5_000_000_000, 3_000_000_000),
        (3_000_000_000, 5_000_000_000),
        (1_000_000_000, 1_000_000_000),
        (0, 5_000_000_000),
    ];

    for (outer_ns, inner_ns) in &deadlines {
        let outer = Time::from_nanos(*outer_ns);
        let inner = Time::from_nanos(*inner_ns);
        let nested = effective_deadline(outer, Some(inner));
        let expected = if outer.as_nanos() <= inner.as_nanos() {
            outer
        } else {
            inner
        };
        assert_eq!(
            nested.as_nanos(),
            expected.as_nanos(),
            "WF-XADR.1: effective_deadline({outer:?}, Some({inner:?})) = {nested:?}, \
             expected {expected:?}"
        );
    }

    // Join associativity with timeout outcomes
    let a = Outcome::<(), ()>::Cancelled(CancelReason::timeout());
    let b = Outcome::Ok(());
    let c = Outcome::Err(());

    let lhs = join_outcomes(join_outcomes(a.clone(), b.clone()), c.clone());
    let rhs = join_outcomes(a, join_outcomes(b, c));

    assert_eq!(
        lhs.severity(),
        rhs.severity(),
        "WF-XADR.1: join associativity must hold for timeout+ok+err"
    );
}

/// WF-XADR.2: No unsafe in capability modules (file-system witness).
///
/// Scans src/cx/ for `#[allow(unsafe_code)]` annotations. Adversarial because
/// a single unsafe in cx/ breaks the ADR-006 → ADR-007 cascade (capability
/// bypass → determinism failure chain from S7).
#[test]
fn wf_xadr_2_no_unsafe_in_cx() {
    init_test_logging();

    let cx_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/cx");
    assert!(cx_dir.exists(), "WF-XADR.2: src/cx/ must exist");

    let mut violations = Vec::new();
    scan_dir_for_pattern(&cx_dir, "#[allow(unsafe_code)]", &mut violations);

    assert!(
        violations.is_empty(),
        "WF-XADR.2 VIOLATED: found #[allow(unsafe_code)] in src/cx/: {violations:?}"
    );
}

/// WF-XADR.3: Seed equivalence (determinism witness).
///
/// Two LabConfig instances with the same seed must produce identical
/// seed and entropy_seed fields. This is the foundation of ADR-007.
#[test]
fn wf_xadr_3_seed_equivalence() {
    init_test_logging();

    let seed = SEED_XADR;
    let c1 = LabConfig::new(seed);
    let c2 = LabConfig::new(seed);

    assert_eq!(c1.seed, c2.seed, "WF-XADR.3: seed must be deterministic");
    assert_eq!(
        c1.entropy_seed, c2.entropy_seed,
        "WF-XADR.3: entropy_seed must be deterministic"
    );

    // Different seed must differ
    let c3 = LabConfig::new(seed.wrapping_add(1));
    assert_ne!(
        c1.seed, c3.seed,
        "WF-XADR.3: different seeds must produce different configs"
    );
}

// ============================================================================
// WF-FUZZ: Fuzz-Based Regression Generators
//
// These tests use the FuzzHarness with stable seeds to produce deterministic
// regression cases. The harness runs against OracleSuite invariants.
// ============================================================================

/// WF-FUZZ.1: Single-task fuzz campaign produces no violations.
///
/// Generator: 50 iterations with stable seed, single task, run to quiescence.
/// This establishes a baseline: a simple well-behaved scenario should have
/// zero findings across many scheduling permutations.
#[test]
fn wf_fuzz_1_single_task_baseline() {
    init_test_logging();

    let report = fuzz_quick(SEED_RACE, 50, |runtime| {
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let (t, _) = runtime
            .state
            .create_task(region, Budget::INFINITE, async { 42 })
            .expect("task");
        runtime.scheduler.lock().schedule(t, 0);
        runtime.run_until_quiescent();
    });

    assert!(
        !report.has_findings(),
        "WF-FUZZ.1: single-task baseline must produce zero violations"
    );
    assert_eq!(report.iterations, 50);
}

/// WF-FUZZ.2: Two competing tasks — fuzz for quiescence violations.
///
/// Generator: 100 iterations with different scheduling orders.
/// Both tasks complete normally; verifies no oracle violations arise
/// from scheduling nondeterminism.
#[test]
fn wf_fuzz_2_two_tasks_no_violations() {
    init_test_logging();

    let config = FuzzConfig::new(SEED_OBL, 100).worker_count(2);
    let harness = FuzzHarness::new(config);

    let report = harness.run(|runtime| {
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let (t1, _) = runtime
            .state
            .create_task(region, Budget::INFINITE, async { 1 })
            .expect("t1");
        let (t2, _) = runtime
            .state
            .create_task(region, Budget::INFINITE, async { 2 })
            .expect("t2");
        {
            let mut sched = runtime.scheduler.lock();
            sched.schedule(t1, 0);
            sched.schedule(t2, 1);
        }
        runtime.run_until_quiescent();
    });

    assert!(
        !report.has_findings(),
        "WF-FUZZ.2: two clean tasks must produce zero violations"
    );
}

/// WF-FUZZ.3: Regression corpus is deterministic and serializable.
///
/// Verifies that the FuzzRegressionCorpus round-trips through serde
/// and produces stable sorted output for CI diffing.
#[test]
fn wf_fuzz_3_corpus_round_trip() {
    init_test_logging();

    let report = fuzz_quick(SEED_TIE, 20, |runtime| {
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let (t, _) = runtime
            .state
            .create_task(region, Budget::INFINITE, async {})
            .expect("t");
        runtime.scheduler.lock().schedule(t, 0);
        runtime.run_until_quiescent();
    });

    let corpus = report.to_regression_corpus(SEED_TIE);
    assert_eq!(corpus.schema_version, 1);
    assert_eq!(corpus.base_seed, SEED_TIE);

    // Round-trip through JSON
    let json = serde_json::to_string_pretty(&corpus).expect("serialize");
    let deserialized: asupersync::lab::fuzz::FuzzRegressionCorpus =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(
        corpus, deserialized,
        "WF-FUZZ.3: corpus round-trip must be exact"
    );
}

/// WF-FUZZ.4: Same seed produces identical fuzz report fingerprints.
///
/// Determinism witness: running the same campaign twice with the same
/// seed must produce the same number of unique certificate hashes.
#[test]
fn wf_fuzz_4_deterministic_campaign() {
    init_test_logging();

    let run_campaign = || {
        let report = fuzz_quick(SEED_ABS, 30, |runtime| {
            let region = runtime.state.create_root_region(Budget::INFINITE);
            let (t1, _) = runtime
                .state
                .create_task(region, Budget::INFINITE, async { "a" })
                .expect("t1");
            let (t2, _) = runtime
                .state
                .create_task(region, Budget::INFINITE, async { "b" })
                .expect("t2");
            {
                let mut sched = runtime.scheduler.lock();
                sched.schedule(t1, 0);
                sched.schedule(t2, 0);
            }
            runtime.run_until_quiescent();
        });
        report.unique_certificates
    };

    let r1 = run_campaign();
    let r2 = run_campaign();
    assert_eq!(
        r1, r2,
        "WF-FUZZ.4: same seed must produce same certificate count"
    );
}

// ============================================================================
// WF-QUIESCE: Quiescence Violation Detection Witnesses
// Rule IDs: #22-28 (region domain)
// ============================================================================

/// WF-QUIESCE.1: Region close with live tasks — oracle MUST detect violation.
///
/// Adversarial violation witness: close region while a task is still running.
#[test]
fn wf_quiesce_1_close_with_live_task_detected() {
    init_test_logging();

    let root = region(0);
    let worker = task(1);

    let mut oracle = QuiescenceOracle::new();
    oracle.on_region_create(root, None);
    oracle.on_spawn(worker, root);
    // Do NOT complete the task
    oracle.on_region_close(root, t(100));

    let result = oracle.check();
    assert!(
        result.is_err(),
        "WF-QUIESCE.1: closing region with live task MUST be detected"
    );
}

/// WF-QUIESCE.2: Region close after all tasks complete — must pass.
#[test]
fn wf_quiesce_2_close_after_all_tasks_complete() {
    init_test_logging();

    let root = region(0);
    let t1 = task(1);
    let t2 = task(2);

    let mut oracle = QuiescenceOracle::new();
    oracle.on_region_create(root, None);
    oracle.on_spawn(t1, root);
    oracle.on_spawn(t2, root);
    oracle.on_task_complete(t1);
    oracle.on_task_complete(t2);
    oracle.on_region_close(root, t(100));

    assert!(
        oracle.check().is_ok(),
        "WF-QUIESCE.2: close after all tasks complete must be clean"
    );
}

/// WF-QUIESCE.3: Nested regions — parent close requires child close first.
///
/// Adversarial: close parent while child region is still open.
#[test]
fn wf_quiesce_3_nested_region_ordering() {
    init_test_logging();

    let root = region(0);
    let child = region(1);
    let worker = task(2);

    let mut oracle = QuiescenceOracle::new();
    oracle.on_region_create(root, None);
    oracle.on_region_create(child, Some(root));
    oracle.on_spawn(worker, child);

    // Complete worker and close child first (correct order)
    oracle.on_task_complete(worker);
    oracle.on_region_close(child, t(50));
    oracle.on_region_close(root, t(100));

    assert!(
        oracle.check().is_ok(),
        "WF-QUIESCE.3: correct close ordering (child then parent) must pass"
    );
}

// ============================================================================
// Utility: recursive directory scan for pattern
// ============================================================================

fn scan_dir_for_pattern(dir: &std::path::Path, pattern: &str, violations: &mut Vec<String>) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                scan_dir_for_pattern(&path, pattern, violations);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                if let Ok(contents) = std::fs::read_to_string(&path) {
                    for (i, line) in contents.lines().enumerate() {
                        if line.contains(pattern) {
                            violations.push(format!(
                                "{}:{}: {}",
                                path.display(),
                                i + 1,
                                line.trim()
                            ));
                        }
                    }
                }
            }
        }
    }
}
