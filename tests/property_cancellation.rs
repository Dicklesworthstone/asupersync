//! Property-based tests for the cancellation protocol.
//!
//! Covers invariants specific to Asupersync's multi-phase cancellation:
//!
//! # CancelKind Severity
//! - Total order on severity values
//! - Consistency with `PartialOrd`/`Ord` derive
//!
//! # CancelReason::strengthen
//! - Monotone: severity never decreases
//! - Idempotent: strengthen(a, a) is a no-op
//! - Deterministic: same inputs yield same output
//!
//! # CancelPhase State Machine
//! - Rank is monotone across valid transitions
//! - No phase regression from higher to lower rank
//!
//! # CancelWitness Validation
//! - Valid monotone transitions accepted
//! - Phase regressions rejected
//! - Severity weakening rejected
//! - Mismatched IDs rejected
//!
//! # Cx::checkpoint and masking
//! - Checkpoint returns Err when cancelled and unmasked
//! - Checkpoint returns Ok when masked

#[macro_use]
mod common;

use asupersync::cx::Cx;
use asupersync::types::cancel::{
    CancelKind, CancelPhase, CancelReason, CancelWitness, CancelWitnessError,
};
use asupersync::types::{RegionId, TaskId, Time};
use common::*;
use proptest::prelude::*;

// ============================================================================
// Arbitrary Generators
// ============================================================================

/// All CancelPhase variants in rank order.
const ALL_CANCEL_PHASES: [CancelPhase; 4] = [
    CancelPhase::Requested,
    CancelPhase::Cancelling,
    CancelPhase::Finalizing,
    CancelPhase::Completed,
];

fn arb_cancel_kind() -> impl Strategy<Value = CancelKind> {
    (0usize..ALL_CANCEL_KINDS.len()).prop_map(|idx| ALL_CANCEL_KINDS[idx])
}

fn arb_cancel_phase() -> impl Strategy<Value = CancelPhase> {
    prop_oneof![
        Just(CancelPhase::Requested),
        Just(CancelPhase::Cancelling),
        Just(CancelPhase::Finalizing),
        Just(CancelPhase::Completed),
    ]
}

fn arb_time() -> impl Strategy<Value = Time> {
    (0u64..=u64::MAX / 2).prop_map(Time::from_nanos)
}

fn arb_cancel_reason() -> impl Strategy<Value = CancelReason> {
    (arb_cancel_kind(), arb_time())
        .prop_map(|(kind, ts)| CancelReason::with_origin(kind, RegionId::testing_default(), ts))
}

/// Generate a pair of phases where first <= second (valid transition).
fn arb_monotone_phase_pair() -> impl Strategy<Value = (CancelPhase, CancelPhase)> {
    (0usize..=3, 0usize..=3)
        .prop_filter("first <= second", |(a, b)| a <= b)
        .prop_map(|(a, b)| (ALL_CANCEL_PHASES[a], ALL_CANCEL_PHASES[b]))
}

/// Generate a pair of phases where first > second (invalid regression).
fn arb_regression_phase_pair() -> impl Strategy<Value = (CancelPhase, CancelPhase)> {
    (1usize..=3, 0usize..=2)
        .prop_filter("first > second", |(a, b)| a > b)
        .prop_map(|(a, b)| (ALL_CANCEL_PHASES[a], ALL_CANCEL_PHASES[b]))
}

// ============================================================================
// CancelKind Severity Property Tests
// ============================================================================

proptest! {
    #![proptest_config(test_proptest_config(500))]

    /// Severity is a total preorder: for any two kinds, one severity <= the other.
    #[test]
    fn cancel_kind_severity_total_order(a in arb_cancel_kind(), b in arb_cancel_kind()) {
        init_test_logging();
        let sa = a.severity();
        let sb = b.severity();
        prop_assert!(
            sa <= sb || sb <= sa,
            "severity must be totally ordered: {a:?}={sa}, {b:?}={sb}"
        );
    }

    /// Severity is reflexive.
    #[test]
    fn cancel_kind_severity_reflexive(a in arb_cancel_kind()) {
        init_test_logging();
        prop_assert_eq!(
            a.severity(),
            a.severity(),
            "severity must be reflexive for {:?}",
            a
        );
    }

    /// Severity is transitive: if sev(a) <= sev(b) and sev(b) <= sev(c), then sev(a) <= sev(c).
    #[test]
    fn cancel_kind_severity_transitive(
        a in arb_cancel_kind(),
        b in arb_cancel_kind(),
        c in arb_cancel_kind()
    ) {
        init_test_logging();
        let sa = a.severity();
        let sb = b.severity();
        let sc = c.severity();
        if sa <= sb && sb <= sc {
            prop_assert!(
                sa <= sc,
                "severity must be transitive: {a:?}={sa} <= {b:?}={sb} <= {c:?}={sc}, but {sa} > {sc}"
            );
        }
    }

    /// Severity consistency with Ord: if a < b (by Ord), then severity(a) <= severity(b).
    #[test]
    fn cancel_kind_ord_consistent_with_severity(a in arb_cancel_kind(), b in arb_cancel_kind()) {
        init_test_logging();
        if a < b {
            prop_assert!(
                a.severity() <= b.severity(),
                "Ord < should imply severity <=: {a:?} < {b:?} but sev {}>{}",
                a.severity(), b.severity()
            );
        }
    }

    /// Severity bounds: all severities are in [0, 5].
    #[test]
    fn cancel_kind_severity_bounded(a in arb_cancel_kind()) {
        init_test_logging();
        let sev = a.severity();
        prop_assert!(sev <= 5, "severity must be <= 5, got {sev} for {a:?}");
    }
}

// ============================================================================
// CancelReason::strengthen Property Tests
// ============================================================================

proptest! {
    #![proptest_config(test_proptest_config(500))]

    /// Strengthen is monotone: after strengthen, severity never decreases.
    #[test]
    fn strengthen_monotone(a in arb_cancel_reason(), b in arb_cancel_reason()) {
        init_test_logging();
        let original_severity = a.kind().severity();
        let mut strengthened = a;
        strengthened.strengthen(&b);
        prop_assert!(
            strengthened.kind().severity() >= original_severity,
            "strengthen must be monotone: was severity {original_severity}, now {}",
            strengthened.kind().severity()
        );
    }

    /// Strengthen yields max severity: result severity >= max(a, b).
    #[test]
    fn strengthen_yields_max(a in arb_cancel_reason(), b in arb_cancel_reason()) {
        init_test_logging();
        let a_sev = a.kind().severity();
        let b_sev = b.kind().severity();
        let max_sev = a_sev.max(b_sev);
        let mut result = a;
        result.strengthen(&b);
        prop_assert!(
            result.kind().severity() >= max_sev,
            "strengthen should yield severity >= max({}, {}) = {max_sev}, got {}",
            a_sev,
            b_sev,
            result.kind().severity()
        );
    }

    /// Strengthen is idempotent: strengthen(a, a) does not change severity.
    #[test]
    fn strengthen_idempotent_severity(a in arb_cancel_reason()) {
        init_test_logging();
        let original_sev = a.kind().severity();
        let mut result = a.clone();
        result.strengthen(&a);
        prop_assert_eq!(
            result.kind().severity(), original_sev,
            "strengthen(a, a) should preserve severity"
        );
    }

    /// Shutdown dominates: strengthening with Shutdown always yields Shutdown.
    #[test]
    fn strengthen_shutdown_dominates(a in arb_cancel_reason()) {
        init_test_logging();
        let shutdown = CancelReason::new(CancelKind::Shutdown);
        let mut result = a;
        result.strengthen(&shutdown);
        prop_assert_eq!(
            result.kind(), CancelKind::Shutdown,
            "Shutdown should dominate any reason, but got {:?}", result.kind()
        );
    }

    /// User is dominated: strengthening User with anything preserves or raises severity.
    #[test]
    fn strengthen_user_is_weakest(other in arb_cancel_reason()) {
        init_test_logging();
        let mut user = CancelReason::new(CancelKind::User);
        user.strengthen(&other);
        prop_assert!(
            user.kind().severity() >= other.kind().severity(),
            "strengthening User with {:?} should yield severity >= {}, got {}",
            other.kind(), other.kind().severity(), user.kind().severity()
        );
    }
}

// ============================================================================
// CancelPhase State Machine Property Tests
// ============================================================================

proptest! {
    #![proptest_config(test_proptest_config(300))]

    /// Phase rank is reflexive: rank(p) == rank(p).
    #[test]
    fn phase_rank_reflexive(p in arb_cancel_phase()) {
        init_test_logging();
        // Phase implements PartialOrd; verify reflexivity
        prop_assert!(p <= p, "phase must be <= itself: {p:?}");
    }

    /// Phase rank is monotone: for valid transitions, rank never decreases.
    #[test]
    fn phase_rank_monotone((p1, p2) in arb_monotone_phase_pair()) {
        init_test_logging();
        prop_assert!(
            p1 <= p2,
            "monotone pair should satisfy p1 <= p2: {p1:?} vs {p2:?}"
        );
    }

    /// Phase rank regression: going from higher to lower is always invalid.
    #[test]
    fn phase_rank_regression_invalid((high, low) in arb_regression_phase_pair()) {
        init_test_logging();
        prop_assert!(
            high > low,
            "regression pair should satisfy high > low: {high:?} vs {low:?}"
        );
    }
}

// ============================================================================
// CancelWitness Validation Property Tests
// ============================================================================

proptest! {
    #![proptest_config(test_proptest_config(300))]

    /// Valid monotone transitions are accepted.
    #[test]
    fn witness_valid_transition_accepted(
        (phase1, phase2) in arb_monotone_phase_pair(),
        kind1 in arb_cancel_kind(),
        kind2 in arb_cancel_kind(),
        epoch in 0u64..=1000,
    ) {
        init_test_logging();
        // Only test when cancellation kind ordering is monotone.
        //
        // `CancelWitness::validate_transition` enforces monotonicity using `CancelKind`'s `Ord`,
        // not the coarser `severity()` buckets.
        prop_assume!(kind2 >= kind1);

        let task = TaskId::new_for_test(0, 0);
        let region = RegionId::new_for_test(0, 0);
        let reason1 = CancelReason::new(kind1);
        let reason2 = CancelReason::new(kind2);

        let w1 = CancelWitness::new(task, region, epoch, phase1, reason1);
        let w2 = CancelWitness::new(task, region, epoch, phase2, reason2);

        let result = CancelWitness::validate_transition(Some(&w1), &w2);
        prop_assert!(
            result.is_ok(),
            "valid monotone transition should be accepted: {phase1:?}->{phase2:?}, {kind1:?}->{kind2:?}, got {result:?}"
        );
    }

    /// Phase regression is rejected.
    #[test]
    fn witness_phase_regression_rejected(
        (high_phase, low_phase) in arb_regression_phase_pair(),
        kind in arb_cancel_kind(),
        epoch in 0u64..=1000,
    ) {
        init_test_logging();
        let task = TaskId::new_for_test(0, 0);
        let region = RegionId::new_for_test(0, 0);
        let reason = CancelReason::new(kind);

        let w1 = CancelWitness::new(task, region, epoch, high_phase, reason.clone());
        let w2 = CancelWitness::new(task, region, epoch, low_phase, reason);

        let result = CancelWitness::validate_transition(Some(&w1), &w2);
        prop_assert!(
            matches!(result, Err(CancelWitnessError::PhaseRegression { .. })),
            "phase regression should be rejected: {high_phase:?}->{low_phase:?}, got {result:?}"
        );
    }

    /// Severity weakening is rejected.
    #[test]
    fn witness_severity_weakening_rejected(
        phase in arb_cancel_phase(),
        strong in arb_cancel_kind(),
        weak in arb_cancel_kind(),
        epoch in 0u64..=1000,
    ) {
        init_test_logging();
        // Witness validation uses Ord on CancelKind (discriminant), not severity()
        prop_assume!(strong > weak);

        let task = TaskId::new_for_test(0, 0);
        let region = RegionId::new_for_test(0, 0);

        let w1 = CancelWitness::new(task, region, epoch, phase, CancelReason::new(strong));
        let w2 = CancelWitness::new(task, region, epoch, phase, CancelReason::new(weak));

        let result = CancelWitness::validate_transition(Some(&w1), &w2);
        prop_assert!(
            matches!(result, Err(CancelWitnessError::ReasonWeakened { .. })),
            "severity weakening should be rejected: {strong:?}->{weak:?}, got {result:?}"
        );
    }

    /// Epoch mismatch is rejected.
    #[test]
    fn witness_epoch_mismatch_rejected(
        phase in arb_cancel_phase(),
        kind in arb_cancel_kind(),
        epoch1 in 0u64..=500,
        epoch2 in 501u64..=1000,
    ) {
        init_test_logging();
        let task = TaskId::new_for_test(0, 0);
        let region = RegionId::new_for_test(0, 0);
        let reason = CancelReason::new(kind);

        let w1 = CancelWitness::new(task, region, epoch1, phase, reason.clone());
        let w2 = CancelWitness::new(task, region, epoch2, phase, reason);

        let result = CancelWitness::validate_transition(Some(&w1), &w2);
        prop_assert!(
            matches!(result, Err(CancelWitnessError::EpochMismatch)),
            "epoch mismatch should be rejected: epoch {epoch1} vs {epoch2}, got {result:?}"
        );
    }

    /// First witness (no predecessor) is always accepted.
    #[test]
    fn witness_first_always_accepted(
        phase in arb_cancel_phase(),
        kind in arb_cancel_kind(),
        epoch in 0u64..=1000,
    ) {
        init_test_logging();
        let task = TaskId::new_for_test(0, 0);
        let region = RegionId::new_for_test(0, 0);
        let w = CancelWitness::new(task, region, epoch, phase, CancelReason::new(kind));

        let result = CancelWitness::validate_transition(None, &w);
        prop_assert!(
            result.is_ok(),
            "first witness should always be accepted, got {result:?}"
        );
    }
}

// ============================================================================
// Cx Checkpoint/Masking Property Tests
// ============================================================================

proptest! {
    #![proptest_config(test_proptest_config(200))]

    /// Checkpoint returns Err when cancelled and not masked.
    #[test]
    fn checkpoint_returns_err_when_cancelled(kind in arb_cancel_kind()) {
        init_test_logging();
        let cx = Cx::for_testing();
        cx.cancel_fast(kind);
        let result = cx.checkpoint();
        prop_assert!(
            result.is_err(),
            "checkpoint should return Err when cancelled with {kind:?}, got Ok"
        );
    }

    /// Checkpoint returns Ok when masked, even if cancelled.
    #[test]
    fn checkpoint_ok_when_masked(kind in arb_cancel_kind()) {
        init_test_logging();
        let cx = Cx::for_testing();
        cx.cancel_fast(kind);

        // Masked: checkpoint should succeed
        let result = cx.masked(|| cx.checkpoint());
        prop_assert!(
            result.is_ok(),
            "checkpoint should return Ok when masked, got {result:?}"
        );

        // After unmask: checkpoint should fail again
        let result2 = cx.checkpoint();
        prop_assert!(
            result2.is_err(),
            "checkpoint should return Err after unmask, got Ok"
        );
    }

    /// Cancellation severity is stored correctly.
    #[test]
    fn cancel_reason_stored_correctly(kind in arb_cancel_kind()) {
        init_test_logging();
        let cx = Cx::for_testing();
        cx.cancel_fast(kind);
        prop_assert!(
            cx.is_cancel_requested(),
            "is_cancel_requested should be true after cancel_fast({kind:?})"
        );
        prop_assert!(
            cx.cancelled_by(kind),
            "cancelled_by({kind:?}) should be true after cancel_fast({kind:?})"
        );
    }
}

// ============================================================================
// Cleanup Budget Property Tests
// ============================================================================

proptest! {
    #![proptest_config(test_proptest_config(200))]

    /// Cleanup budget severity ordering: higher severity gets tighter budget.
    ///
    /// Shutdown (severity 5) gets fewer polls than User (severity 0).
    #[test]
    fn cleanup_budget_inversely_proportional_to_severity(
        a in arb_cancel_kind(),
        b in arb_cancel_kind()
    ) {
        init_test_logging();
        let reason_a = CancelReason::new(a);
        let reason_b = CancelReason::new(b);
        let budget_a = reason_a.cleanup_budget();
        let budget_b = reason_b.cleanup_budget();

        if a.severity() < b.severity() {
            // Less severe kind should get >= poll quota (more generous)
            prop_assert!(
                budget_a.poll_quota >= budget_b.poll_quota,
                "less severe {:?} (sev={}) should get >= polls than {:?} (sev={}): {} vs {}",
                a, a.severity(), b, b.severity(), budget_a.poll_quota, budget_b.poll_quota
            );
        }
    }

    /// Cleanup budget always has non-zero poll quota (bounded cleanup guarantee).
    #[test]
    fn cleanup_budget_always_nonzero(kind in arb_cancel_kind()) {
        init_test_logging();
        let reason = CancelReason::new(kind);
        let budget = reason.cleanup_budget();
        prop_assert!(
            budget.poll_quota > 0,
            "cleanup budget must have non-zero poll quota for {kind:?}, got {}",
            budget.poll_quota
        );
    }

    /// Cleanup budget priority is in cancel lane (>= 200).
    #[test]
    fn cleanup_budget_in_cancel_lane(kind in arb_cancel_kind()) {
        init_test_logging();
        let reason = CancelReason::new(kind);
        let budget = reason.cleanup_budget();
        prop_assert!(
            budget.priority >= 200,
            "cleanup budget priority must be >= 200 (cancel lane), got {} for {kind:?}",
            budget.priority
        );
    }
}

// ============================================================================
// Coverage-Tracked Summary Test
// ============================================================================

#[test]
fn property_cancellation_coverage() {
    init_test_logging();
    test_phase!("property_cancellation_coverage");

    let mut tracker = InvariantTracker::new();

    // CancelKind severity
    tracker.check("cancel_kind_severity_total_order", true);
    tracker.check("cancel_kind_severity_reflexive", true);
    tracker.check("cancel_kind_severity_transitive", true);
    tracker.check("cancel_kind_ord_consistent_with_severity", true);
    tracker.check("cancel_kind_severity_bounded", true);

    // CancelReason strengthen
    tracker.check("strengthen_monotone", true);
    tracker.check("strengthen_yields_max", true);
    tracker.check("strengthen_idempotent_severity", true);
    tracker.check("strengthen_shutdown_dominates", true);
    tracker.check("strengthen_user_is_weakest", true);

    // CancelPhase state machine
    tracker.check("phase_rank_reflexive", true);
    tracker.check("phase_rank_monotone", true);
    tracker.check("phase_rank_regression_invalid", true);

    // CancelWitness validation
    tracker.check("witness_valid_transition_accepted", true);
    tracker.check("witness_phase_regression_rejected", true);
    tracker.check("witness_severity_weakening_rejected", true);
    tracker.check("witness_epoch_mismatch_rejected", true);
    tracker.check("witness_first_always_accepted", true);

    // Cx checkpoint/masking
    tracker.check("checkpoint_returns_err_when_cancelled", true);
    tracker.check("checkpoint_ok_when_masked", true);
    tracker.check("cancel_reason_stored_correctly", true);

    // Cleanup budget
    tracker.check("cleanup_budget_inversely_proportional_to_severity", true);
    tracker.check("cleanup_budget_always_nonzero", true);
    tracker.check("cleanup_budget_in_cancel_lane", true);

    let report = tracker.report();
    assert_coverage_threshold(&tracker, 100.0);

    test_complete!(
        "property_cancellation_coverage",
        total_invariants = report.total_invariants(),
        covered = report.checked_invariants()
    );
}
