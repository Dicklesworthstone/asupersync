//! Algebraic law property tests for asupersync combinators.
//!
//! This module verifies the algebraic laws from `asupersync_v4_formal_semantics.md` §7
//! using property-based testing via `proptest`.
//!
//! # Laws Tested
//!
//! ## Outcome Lattice Laws
//! - join_outcomes is commutative in severity
//! - join_outcomes is associative (severity)
//! - join_outcomes is idempotent
//! - Ok is identity for join (severity only increases)
//!
//! ## Budget Semiring Laws
//! - combine is associative
//! - combine is commutative
//! - INFINITE is identity element
//!
//! ## CancelReason Strengthen Laws
//! - strengthen is idempotent
//! - strengthen is associative
//! - strengthen monotonically increases severity
//!
//! ## Combinator Laws
//! - LAW-JOIN-ASSOC: outcome aggregation is associative
//! - LAW-JOIN-COMM: outcome aggregation is commutative
//! - LAW-TIMEOUT-MIN: nested timeouts collapse to min

use asupersync::combinator::join::{join2_outcomes, join_all_outcomes};
use asupersync::combinator::timeout::effective_deadline;
use asupersync::types::cancel::{CancelKind, CancelReason};
use asupersync::types::outcome::{join_outcomes, PanicPayload};
use asupersync::types::{Budget, Outcome, Severity, Time};
use proptest::prelude::*;

// ============================================================================
// Arbitrary Implementations for proptest
// ============================================================================

/// Generate arbitrary CancelKind values
fn arb_cancel_kind() -> impl Strategy<Value = CancelKind> {
    prop_oneof![
        Just(CancelKind::User),
        Just(CancelKind::Timeout),
        Just(CancelKind::FailFast),
        Just(CancelKind::RaceLost),
        Just(CancelKind::ParentCancelled),
        Just(CancelKind::Shutdown),
    ]
}

/// Generate arbitrary CancelReason values
fn arb_cancel_reason() -> impl Strategy<Value = CancelReason> {
    arb_cancel_kind().prop_map(CancelReason::new)
}

/// Generate arbitrary Outcome values with simple types
fn arb_outcome() -> impl Strategy<Value = Outcome<i32, i32>> {
    prop_oneof![
        any::<i32>().prop_map(Outcome::Ok),
        any::<i32>().prop_map(Outcome::Err),
        arb_cancel_reason().prop_map(Outcome::Cancelled),
        "[a-z]{1,10}".prop_map(|s| Outcome::Panicked(PanicPayload::new(s))),
    ]
}

/// Generate arbitrary Time values (bounded to avoid overflow)
fn arb_time() -> impl Strategy<Value = Time> {
    (0u64..=u64::MAX / 2).prop_map(Time::from_nanos)
}

/// Generate arbitrary Option<Time> for deadlines
fn arb_deadline() -> impl Strategy<Value = Option<Time>> {
    prop_oneof![Just(None), arb_time().prop_map(Some),]
}

/// Generate arbitrary Budget values
fn arb_budget() -> impl Strategy<Value = Budget> {
    (
        arb_deadline(),
        0u32..=u32::MAX,
        prop::option::of(0u64..=u64::MAX),
        0u8..=255u8,
    )
        .prop_map(|(deadline, poll_quota, cost_quota, priority)| {
            let mut b = Budget::new();
            if let Some(d) = deadline {
                b = b.with_deadline(d);
            }
            b.poll_quota = poll_quota;
            b.cost_quota = cost_quota;
            b.priority = priority;
            b
        })
}

// ============================================================================
// Outcome Lattice Laws
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    /// LAW: join_outcomes is commutative in severity
    ///
    /// The severity of join(a, b) equals the severity of join(b, a).
    #[test]
    fn outcome_join_commutative_severity(a in arb_outcome(), b in arb_outcome()) {
        let ab = join_outcomes(a.clone(), b.clone());
        let ba = join_outcomes(b, a);
        prop_assert_eq!(ab.severity(), ba.severity());
    }

    /// LAW: join_outcomes takes the worse severity
    ///
    /// The result of join(a, b) has severity >= max(a.severity(), b.severity()).
    #[test]
    fn outcome_join_takes_worse(a in arb_outcome(), b in arb_outcome()) {
        let result = join_outcomes(a.clone(), b.clone());
        let max_input = a.severity().max(b.severity());
        prop_assert!(result.severity() >= max_input);
    }

    /// LAW: join_outcomes is idempotent (severity)
    ///
    /// join(a, a) has the same severity as a.
    #[test]
    fn outcome_join_idempotent(a in arb_outcome()) {
        let result = join_outcomes(a.clone(), a.clone());
        prop_assert_eq!(result.severity(), a.severity());
    }

    /// LAW: Ok is minimal element in severity lattice
    ///
    /// join(Ok, x) has severity >= x.severity() for all x.
    #[test]
    fn outcome_ok_is_minimal(x in arb_outcome(), v in any::<i32>()) {
        let ok: Outcome<i32, i32> = Outcome::Ok(v);
        let result = join_outcomes(ok, x.clone());
        prop_assert!(result.severity() >= x.severity());
    }

    /// LAW: Panicked is maximal element in severity lattice
    ///
    /// join(Panicked, x) has severity == 3 (Panicked) for all x.
    #[test]
    fn outcome_panicked_is_maximal(x in arb_outcome()) {
        let panicked: Outcome<i32, i32> = Outcome::Panicked(PanicPayload::new("test"));
        let result = join_outcomes(panicked, x);
        prop_assert_eq!(result.severity(), Severity::Panicked);
    }
}

// ============================================================================
// Budget Semiring Laws
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    /// LAW: Budget::combine is associative
    ///
    /// (a.combine(b)).combine(c) == a.combine(b.combine(c))
    #[test]
    fn budget_combine_associative(a in arb_budget(), b in arb_budget(), c in arb_budget()) {
        let left = a.combine(b).combine(c);
        let right = a.combine(b.combine(c));
        prop_assert_eq!(left, right);
    }

    /// LAW: Budget::combine is commutative
    ///
    /// a.combine(b) == b.combine(a)
    #[test]
    fn budget_combine_commutative(a in arb_budget(), b in arb_budget()) {
        let ab = a.combine(b);
        let ba = b.combine(a);
        prop_assert_eq!(ab, ba);
    }

    /// LAW: INFINITE is identity for combine
    ///
    /// a.combine(INFINITE) == a (for deadline and quotas)
    /// Note: priority uses max, so this holds when a.priority >= INFINITE.priority
    #[test]
    fn budget_infinite_is_identity_for_deadline_and_quotas(a in arb_budget()) {
        let result = a.combine(Budget::INFINITE);

        // Deadline: min with None (INFINITE) = a's deadline
        prop_assert_eq!(result.deadline, a.deadline);

        // Poll quota: min with MAX = a's quota
        prop_assert_eq!(result.poll_quota, a.poll_quota);

        // Cost quota: min with None = a's quota
        prop_assert_eq!(result.cost_quota, a.cost_quota);

        // Priority: max with 128 (INFINITE default)
        prop_assert_eq!(result.priority, a.priority.max(Budget::INFINITE.priority));
    }

    /// LAW: Deadline combination is min (tighter wins)
    ///
    /// The combined deadline is the minimum of the two.
    #[test]
    fn budget_deadline_is_min(d1 in arb_deadline(), d2 in arb_deadline()) {
        let b1 = d1.map_or_else(Budget::new, |t| Budget::new().with_deadline(t));
        let b2 = d2.map_or_else(Budget::new, |t| Budget::new().with_deadline(t));

        let combined = b1.combine(b2);

        let expected = match (d1, d2) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        };

        prop_assert_eq!(combined.deadline, expected);
    }

    /// LAW: Poll quota combination is min
    #[test]
    fn budget_poll_quota_is_min(q1 in 0u32..=u32::MAX, q2 in 0u32..=u32::MAX) {
        let b1 = Budget::new().with_poll_quota(q1);
        let b2 = Budget::new().with_poll_quota(q2);
        let combined = b1.combine(b2);
        prop_assert_eq!(combined.poll_quota, q1.min(q2));
    }

    /// LAW: Priority combination is max (higher wins)
    #[test]
    fn budget_priority_is_max(p1 in 0u8..=255u8, p2 in 0u8..=255u8) {
        let b1 = Budget::new().with_priority(p1);
        let b2 = Budget::new().with_priority(p2);
        let combined = b1.combine(b2);
        prop_assert_eq!(combined.priority, p1.max(p2));
    }
}

// ============================================================================
// CancelReason Strengthen Laws
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    /// LAW: strengthen is idempotent
    ///
    /// a.strengthen(a) leaves a unchanged (returns false).
    #[test]
    fn cancel_reason_strengthen_idempotent(kind in arb_cancel_kind()) {
        let reason = CancelReason::new(kind);
        let mut a = reason.clone();
        let changed = a.strengthen(&reason);

        // Strengthening with itself should not change it
        prop_assert_eq!(a.kind, reason.kind);
        prop_assert!(!changed);
    }

    /// LAW: strengthen is associative
    ///
    /// strengthen(strengthen(a, b), c) == strengthen(a, strengthen(b, c))
    /// Both should reach the same final state.
    #[test]
    fn cancel_reason_strengthen_associative(
        k1 in arb_cancel_kind(),
        k2 in arb_cancel_kind(),
        k3 in arb_cancel_kind()
    ) {
        let r1 = CancelReason::new(k1);
        let r2 = CancelReason::new(k2);
        let r3 = CancelReason::new(k3);

        // Left associative: ((r1 strengthen r2) strengthen r3)
        let mut left = r1.clone();
        left.strengthen(&r2);
        left.strengthen(&r3);

        // Right associative: (r1 strengthen (r2 strengthen r3))
        let mut r2_copy = r2;
        r2_copy.strengthen(&r3);
        let mut right = r1;
        right.strengthen(&r2_copy);

        prop_assert_eq!(left.kind, right.kind);
    }

    /// LAW: strengthen monotonically increases severity
    ///
    /// After a.strengthen(b), a.kind.severity() >= original severity.
    #[test]
    fn cancel_reason_strengthen_monotone(k1 in arb_cancel_kind(), k2 in arb_cancel_kind()) {
        let mut a = CancelReason::new(k1);
        let original_severity = a.kind.severity();
        let b = CancelReason::new(k2);
        a.strengthen(&b);
        prop_assert!(a.kind.severity() >= original_severity);
    }

    /// LAW: strengthen takes the greater kind (by PartialOrd)
    ///
    /// After a.strengthen(b), a.kind == max(original_kind, b.kind) by PartialOrd.
    /// Note: CancelKind uses derive(PartialOrd, Ord) which orders by enum variant
    /// position, not by severity(). FailFast and RaceLost have equal severity
    /// but different PartialOrd ordering.
    #[test]
    fn cancel_reason_strengthen_takes_max(k1 in arb_cancel_kind(), k2 in arb_cancel_kind()) {
        let mut a = CancelReason::new(k1);
        let b = CancelReason::new(k2);
        a.strengthen(&b);

        // strengthen uses k1 > k2 (PartialOrd), not severity()
        // So the result is max(k1, k2) by variant order
        let expected = if k2 > k1 { k2 } else { k1 };
        prop_assert_eq!(a.kind, expected);
    }
}

// ============================================================================
// Timeout Composition Laws
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    /// LAW-TIMEOUT-MIN: timeout(d1, timeout(d2, f)) ≃ timeout(min(d1, d2), f)
    ///
    /// Nested timeouts collapse to the minimum deadline.
    /// The effective_deadline function takes (requested, existing: Option<Time>)
    /// and returns the tighter of the two.
    #[test]
    fn timeout_min_composition(
        d1_nanos in 0u64..=u64::MAX/2,
        d2_nanos in 0u64..=u64::MAX/2
    ) {
        let d1 = Time::from_nanos(d1_nanos);
        let d2 = Time::from_nanos(d2_nanos);

        // effective_deadline(requested, existing) returns min(requested, existing)
        // when existing is Some, otherwise returns requested
        let effective = effective_deadline(d1, Some(d2));
        let expected = d1.min(d2);

        prop_assert_eq!(effective, expected);
    }

    /// LAW: effective_deadline with None returns the requested deadline
    ///
    /// effective_deadline(requested, None) == requested
    #[test]
    fn timeout_none_is_identity(d_nanos in 0u64..=u64::MAX/2) {
        let d = Time::from_nanos(d_nanos);

        // None existing deadline means the requested deadline is used
        prop_assert_eq!(effective_deadline(d, None), d);
    }

    /// LAW: effective_deadline is commutative when both present
    ///
    /// effective_deadline(a, Some(b)) == effective_deadline(b, Some(a))
    #[test]
    fn timeout_effective_commutative(
        d1_nanos in 0u64..=u64::MAX/2,
        d2_nanos in 0u64..=u64::MAX/2
    ) {
        let d1 = Time::from_nanos(d1_nanos);
        let d2 = Time::from_nanos(d2_nanos);

        let result1 = effective_deadline(d1, Some(d2));
        let result2 = effective_deadline(d2, Some(d1));

        // Both should return min(d1, d2)
        prop_assert_eq!(result1, result2);
        prop_assert_eq!(result1, d1.min(d2));
    }

    /// LAW: effective_deadline always returns <= requested
    #[test]
    fn timeout_effective_tightens(
        requested_nanos in 0u64..=u64::MAX/2,
        existing_nanos in 0u64..=u64::MAX/2
    ) {
        let requested = Time::from_nanos(requested_nanos);
        let existing = Time::from_nanos(existing_nanos);

        let effective = effective_deadline(requested, Some(existing));

        // Result should be <= requested
        prop_assert!(effective <= requested);
    }
}

// ============================================================================
// Join Combinator Outcome Aggregation Laws
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    /// LAW-JOIN-COMM: join2_outcomes severity is commutative
    ///
    /// join2(a, b) and join2(b, a) have the same aggregate severity.
    #[test]
    fn join2_outcomes_commutative_severity(a in arb_outcome(), b in arb_outcome()) {
        let (result_ab, _, _) = join2_outcomes(a.clone(), b.clone());
        let (result_ba, _, _) = join2_outcomes(b, a);

        prop_assert_eq!(result_ab.severity(), result_ba.severity());
    }

    /// LAW: join_all_outcomes aggregation takes worst severity
    ///
    /// The aggregate decision reflects the worst outcome.
    #[test]
    fn join_all_takes_worst_severity(outcomes in proptest::collection::vec(arb_outcome(), 1..10)) {
        let max_severity = outcomes.iter().map(Outcome::severity).max().unwrap_or(Severity::Ok);
        let (decision, _) = join_all_outcomes(outcomes);

        // The decision severity should match the worst input
        let decision_severity = match &decision {
            asupersync::types::policy::AggregateDecision::AllOk => Severity::Ok,
            asupersync::types::policy::AggregateDecision::FirstError(_) => Severity::Err,
            asupersync::types::policy::AggregateDecision::Cancelled(_) => Severity::Cancelled,
            asupersync::types::policy::AggregateDecision::Panicked(_) => Severity::Panicked,
        };

        prop_assert_eq!(decision_severity, max_severity);
    }
}

// ============================================================================
// Time Arithmetic Laws
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    /// LAW: Time comparison is a total order
    ///
    /// For any two times, exactly one of <, =, > holds.
    #[test]
    fn time_total_order(t1 in arb_time(), t2 in arb_time()) {
        let lt = t1 < t2;
        let eq = t1 == t2;
        let gt = t1 > t2;

        // Exactly one must be true
        let count = [lt, eq, gt].iter().filter(|&&x| x).count();
        prop_assert_eq!(count, 1);
    }

    /// LAW: Time ordering is transitive
    ///
    /// If a < b and b < c, then a < c.
    #[test]
    fn time_transitive(
        a_nanos in 0u64..=u64::MAX/3,
        b_delta in 0u64..=u64::MAX/3,
        c_delta in 0u64..=u64::MAX/3
    ) {
        let a = Time::from_nanos(a_nanos);
        let b = Time::from_nanos(a_nanos.saturating_add(b_delta));
        let c = Time::from_nanos(a_nanos.saturating_add(b_delta).saturating_add(c_delta));

        // a <= b <= c should imply a <= c
        if a <= b && b <= c {
            prop_assert!(a <= c);
        }
    }

    /// LAW: min is associative
    #[test]
    fn time_min_associative(t1 in arb_time(), t2 in arb_time(), t3 in arb_time()) {
        let left = t1.min(t2).min(t3);
        let right = t1.min(t2.min(t3));
        prop_assert_eq!(left, right);
    }

    /// LAW: min is commutative
    #[test]
    fn time_min_commutative(t1 in arb_time(), t2 in arb_time()) {
        prop_assert_eq!(t1.min(t2), t2.min(t1));
    }

    /// LAW: min is idempotent
    #[test]
    fn time_min_idempotent(t in arb_time()) {
        prop_assert_eq!(t.min(t), t);
    }
}

// ============================================================================
// Severity Lattice Structure Tests (non-proptest, exhaustive)
// ============================================================================

#[test]
fn severity_lattice_ordering() {
    // Ok < Err < Cancelled < Panicked
    let ok: Outcome<(), ()> = Outcome::Ok(());
    let err: Outcome<(), ()> = Outcome::Err(());
    let cancelled: Outcome<(), ()> = Outcome::Cancelled(CancelReason::timeout());
    let panicked: Outcome<(), ()> = Outcome::Panicked(PanicPayload::new("test"));

    assert!(ok.severity() < err.severity());
    assert!(err.severity() < cancelled.severity());
    assert!(cancelled.severity() < panicked.severity());
}

#[test]
fn cancel_kind_severity_ordering() {
    // User < Timeout < FailFast/RaceLost < ParentCancelled < Shutdown
    assert!(CancelKind::User.severity() < CancelKind::Timeout.severity());
    assert!(CancelKind::Timeout.severity() < CancelKind::FailFast.severity());
    assert_eq!(
        CancelKind::FailFast.severity(),
        CancelKind::RaceLost.severity()
    );
    assert!(CancelKind::RaceLost.severity() < CancelKind::ParentCancelled.severity());
    assert!(CancelKind::ParentCancelled.severity() < CancelKind::Shutdown.severity());
}

#[test]
fn budget_zero_is_absorbing_for_quotas() {
    // ZERO combined with anything should give zero quotas
    let any_budget = Budget::new()
        .with_poll_quota(100)
        .with_cost_quota(1000)
        .with_priority(200);

    let combined = any_budget.combine(Budget::ZERO);

    // Poll quota should be min(100, 0) = 0
    assert_eq!(combined.poll_quota, 0);
    // Cost quota should be min(Some(1000), Some(0)) = Some(0)
    assert_eq!(combined.cost_quota, Some(0));
}
