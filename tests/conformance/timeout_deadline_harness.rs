//! Conformance test harness for timeout and deadline implementations.
//!
//! Tests the actual timeout and deadline implementations against
//! mathematically pure reference implementations using differential testing.

#![cfg(test)]

mod timeout_deadline_reference;

use timeout_deadline_reference::*;
use asupersync::{
    combinator::timeout::*,
    time::deadline::*,
    types::{Time, Budget},
    cx::Scope,
    util::ArenaIndex,
};
use std::time::Duration;
use proptest::prelude::*;

/// Convert reference time to actual time for comparison.
fn ref_to_actual_time(ref_time: RefTime) -> Time {
    Time::from_nanos(ref_time.as_nanos())
}

/// Convert actual time to reference time for comparison.
fn actual_to_ref_time(actual_time: Time) -> RefTime {
    RefTime::from_nanos(actual_time.as_nanos())
}

/// Convert reference budget to actual budget.
fn ref_to_actual_budget(ref_budget: RefBudget) -> Budget {
    let mut budget = Budget::new()
        .with_poll_quota(ref_budget.poll_quota)
        .with_priority(ref_budget.priority);

    if let Some(deadline) = ref_budget.deadline {
        budget = budget.with_deadline(ref_to_actual_time(deadline));
    }

    if let Some(cost) = ref_budget.cost_quota {
        budget = budget.with_cost_quota(cost);
    }

    budget
}

/// Test region ID for scope creation.
fn test_region() -> asupersync::types::RegionId {
    asupersync::types::RegionId::from_arena(ArenaIndex::new(0, 0))
}

/// CONFORMANCE TEST 1: Timeout creation and timing
#[test]
fn conformance_timeout_creation() {
    let test_cases = [
        (0, 0, 0),
        (0, 1, 1_000_000_000),
        (100, 5, 105_000_000_000),
        (u64::MAX / 2, 1, (u64::MAX / 2).saturating_add(1_000_000_000)),
    ];

    for (now_secs, timeout_secs, expected_nanos) in test_cases {
        let ref_now = RefTime::from_secs(now_secs);
        let actual_now = Time::from_secs(now_secs);

        let ref_timeout = RefTimeout::after_secs(ref_now, timeout_secs);
        let actual_timeout = Timeout::<()>::after_secs(actual_now, timeout_secs);

        assert_eq!(
            ref_timeout.deadline.as_nanos(),
            actual_timeout.deadline.as_nanos(),
            "Timeout creation mismatch for now={}, timeout={}",
            now_secs, timeout_secs
        );

        assert_eq!(
            ref_timeout.deadline.as_nanos(),
            expected_nanos,
            "Expected deadline mismatch for now={}, timeout={}",
            now_secs, timeout_secs
        );
    }
}

/// CONFORMANCE TEST 2: Duration saturation behavior
#[test]
fn conformance_duration_saturation() {
    let ref_now = RefTime::from_secs(1);
    let actual_now = Time::from_secs(1);

    // Test Duration::MAX saturation
    let ref_timeout = RefTimeout::after(ref_now, Duration::MAX);
    let actual_timeout = Timeout::<()>::after(actual_now, Duration::MAX);

    assert_eq!(ref_timeout.deadline, RefTime::MAX);
    assert_eq!(actual_timeout.deadline, Time::MAX);
    assert_eq!(
        ref_timeout.deadline.as_nanos(),
        actual_timeout.deadline.as_nanos()
    );
}

/// CONFORMANCE TEST 3: Expiration and remaining time
#[test]
fn conformance_expiration_logic() {
    let test_cases = [
        (100, 105, false, 5_000_000_000), // 5 seconds remaining
        (105, 105, true, 0),               // Exactly at deadline
        (110, 105, true, 0),               // Past deadline
        (0, 0, true, 0),                   // Zero case
    ];

    for (now_secs, deadline_secs, should_expire, expected_remaining_nanos) in test_cases {
        let ref_now = RefTime::from_secs(now_secs);
        let ref_deadline = RefTime::from_secs(deadline_secs);
        let ref_timeout = RefTimeout::new(ref_deadline);

        let actual_now = Time::from_secs(now_secs);
        let actual_deadline = Time::from_secs(deadline_secs);
        let actual_timeout = Timeout::<()>::new(actual_deadline);

        // Test expiration
        assert_eq!(
            ref_timeout.is_expired(ref_now),
            actual_timeout.is_expired(actual_now),
            "Expiration mismatch for now={}, deadline={}",
            now_secs, deadline_secs
        );

        assert_eq!(
            ref_timeout.is_expired(ref_now),
            should_expire,
            "Expected expiration mismatch for now={}, deadline={}",
            now_secs, deadline_secs
        );

        // Test remaining time
        let ref_remaining = ref_timeout.remaining(ref_now);
        let actual_remaining = actual_timeout.remaining(actual_now);

        assert_eq!(
            ref_remaining.as_nanos(),
            actual_remaining.as_nanos(),
            "Remaining time mismatch for now={}, deadline={}",
            now_secs, deadline_secs
        );

        assert_eq!(
            ref_remaining.as_nanos() as u64,
            expected_remaining_nanos,
            "Expected remaining time mismatch for now={}, deadline={}",
            now_secs, deadline_secs
        );
    }
}

/// CONFORMANCE TEST 4: Effective deadline computation (algebraic law)
#[test]
fn conformance_effective_deadline() {
    let test_cases = [
        (10, None, 10),
        (10, Some(5), 5),      // Existing is tighter
        (5, Some(10), 5),      // Requested is tighter
        (7, Some(7), 7),       // Equal deadlines
        (0, Some(0), 0),       // Zero deadlines
        (u64::MAX, None, u64::MAX),
    ];

    for (requested_secs, existing_secs, expected_secs) in test_cases {
        let ref_requested = RefTime::from_secs(requested_secs);
        let ref_existing = existing_secs.map(RefTime::from_secs);
        let ref_result = ref_effective_deadline(ref_requested, ref_existing);

        let actual_requested = Time::from_secs(requested_secs);
        let actual_existing = existing_secs.map(Time::from_secs);
        let actual_result = effective_deadline(actual_requested, actual_existing);

        assert_eq!(
            ref_result.as_nanos(),
            actual_result.as_nanos(),
            "Effective deadline mismatch for requested={}, existing={:?}",
            requested_secs, existing_secs
        );

        assert_eq!(
            ref_result.as_nanos(),
            expected_secs * 1_000_000_000,
            "Expected effective deadline mismatch for requested={}, existing={:?}",
            requested_secs, existing_secs
        );
    }
}

/// CONFORMANCE TEST 5: Deadline propagation with budget preservation
#[test]
fn conformance_deadline_propagation() {
    let test_cases = [
        // (initial_deadline_secs, new_deadline_secs, expected_deadline_secs, poll_quota, cost_quota, priority)
        (None, 10, Some(10), 42, Some(7), 99),
        (Some(15), 10, Some(10), 64, None, 0),    // New is tighter
        (Some(5), 10, Some(5), 32, Some(100), 200), // Existing is tighter
        (Some(10), 10, Some(10), 1, None, 1),     // Equal deadlines
        (None, 0, Some(0), 128, Some(0), 0),      // Zero deadline
    ];

    for (initial_deadline, new_deadline_secs, expected_deadline, poll_quota, cost_quota, priority) in test_cases {
        // Reference implementation
        let mut ref_budget = RefBudget::new()
            .with_poll_quota(poll_quota)
            .with_priority(priority);

        if let Some(deadline_secs) = initial_deadline {
            ref_budget = ref_budget.with_deadline(RefTime::from_secs(deadline_secs));
        }

        if let Some(cost) = cost_quota {
            ref_budget = ref_budget.with_cost_quota(cost);
        }

        let ref_new_deadline = RefTime::from_secs(new_deadline_secs);
        let ref_result = ref_with_deadline(ref_budget.clone(), ref_new_deadline);

        // Actual implementation
        let mut actual_budget = Budget::new()
            .with_poll_quota(poll_quota)
            .with_priority(priority);

        if let Some(deadline_secs) = initial_deadline {
            actual_budget = actual_budget.with_deadline(Time::from_secs(deadline_secs));
        }

        if let Some(cost) = cost_quota {
            actual_budget = actual_budget.with_cost_quota(cost);
        }

        let scope = Scope::<asupersync::types::policy::FailFast>::new(test_region(), actual_budget);
        let actual_new_deadline = Time::from_secs(new_deadline_secs);
        let actual_result_scope = with_deadline(&scope, actual_new_deadline);
        let actual_result = actual_result_scope.budget();

        // Compare results
        assert_eq!(
            ref_result.deadline.map(|d| d.as_nanos()),
            actual_result.deadline.map(|d| d.as_nanos()),
            "Deadline mismatch for initial={:?}, new={}, expected={:?}",
            initial_deadline, new_deadline_secs, expected_deadline
        );

        assert_eq!(ref_result.poll_quota, actual_result.poll_quota);
        assert_eq!(ref_result.cost_quota, actual_result.cost_quota);
        assert_eq!(ref_result.priority, actual_result.priority);

        // Verify against expected
        let expected_nanos = expected_deadline.map(|s| s * 1_000_000_000);
        assert_eq!(
            ref_result.deadline.map(|d| d.as_nanos()),
            expected_nanos,
            "Expected deadline mismatch for initial={:?}, new={}",
            initial_deadline, new_deadline_secs
        );
    }
}

/// CONFORMANCE TEST 6: Timeout from duration
#[test]
fn conformance_timeout_from_duration() {
    let test_cases = [
        (100, 5, 105), // Basic case
        (0, 10, 10),   // From zero
        (u64::MAX - 1000, 1, u64::MAX), // Near saturation
    ];

    for (now_secs, duration_secs, expected_secs) in test_cases {
        let duration = Duration::from_secs(duration_secs);

        // Reference
        let ref_now = RefTime::from_secs(now_secs);
        let ref_budget = RefBudget::INFINITE;
        let ref_result = ref_with_timeout(ref_budget, duration, ref_now);

        // Actual
        let scope = Scope::<asupersync::types::policy::FailFast>::new(test_region(), Budget::INFINITE);
        let actual_now = Time::from_secs(now_secs);
        let actual_result_scope = with_timeout(&scope, duration, actual_now);
        let actual_result = actual_result_scope.budget();

        assert_eq!(
            ref_result.deadline.map(|d| d.as_nanos()),
            actual_result.deadline.map(|d| d.as_nanos()),
            "Timeout from duration mismatch for now={}, duration={}",
            now_secs, duration_secs
        );

        let expected_nanos = expected_secs * 1_000_000_000;
        assert_eq!(
            ref_result.deadline.map(|d| d.as_nanos()),
            Some(expected_nanos),
            "Expected timeout from duration mismatch for now={}, duration={}",
            now_secs, duration_secs
        );
    }
}

/// PROPERTY-BASED CONFORMANCE TEST 7: Timeout composition law
proptest! {
    #[test]
    fn property_timeout_composition_law(
        now_secs in 0u64..1000,
        d1_secs in 1u64..100,
        d2_secs in 1u64..100,
    ) {
        let ref_now = RefTime::from_secs(now_secs);
        let actual_now = Time::from_secs(now_secs);

        let d1 = Duration::from_secs(d1_secs);
        let d2 = Duration::from_secs(d2_secs);

        // Reference: timeout(d1, timeout(d2, f)) ≃ timeout(min(d1, d2), f)
        let (ref_nested, ref_min) = ref_timeout_composition_law(d1, d2, ref_now);

        // Actual: simulate nested timeouts
        let actual_inner_deadline = Timeout::<()>::after(actual_now, d2).deadline;
        let actual_outer_deadline = Timeout::<()>::after(actual_now, d1).deadline;
        let actual_nested = effective_deadline(actual_outer_deadline, Some(actual_inner_deadline));

        let actual_min_duration = Duration::from_nanos(d1.as_nanos().min(d2.as_nanos()) as u64);
        let actual_min = Timeout::<()>::after(actual_now, actual_min_duration).deadline;

        // Verify law holds for both reference and actual
        prop_assert_eq!(ref_nested, ref_min);
        prop_assert_eq!(actual_nested, actual_min);

        // Verify reference matches actual
        prop_assert_eq!(ref_nested.as_nanos(), actual_nested.as_nanos());
        prop_assert_eq!(ref_min.as_nanos(), actual_min.as_nanos());
    }
}

/// PROPERTY-BASED CONFORMANCE TEST 8: Saturation behavior
proptest! {
    #[test]
    fn property_saturation_behavior(
        now_nanos in 0u64..u64::MAX,
        duration_nanos in 0u64..u64::MAX,
    ) {
        let ref_now = RefTime::from_nanos(now_nanos);
        let actual_now = Time::from_nanos(now_nanos);

        let duration = Duration::from_nanos(duration_nanos);

        let ref_timeout = RefTimeout::after(ref_now, duration);
        let actual_timeout = Timeout::<()>::after(actual_now, duration);

        // Both should handle saturation identically
        prop_assert_eq!(ref_timeout.deadline.as_nanos(), actual_timeout.deadline.as_nanos());

        // If either input is near MAX, result should be MAX
        if now_nanos > u64::MAX - 1000 || duration_nanos > u64::MAX - 1000 {
            prop_assert_eq!(ref_timeout.deadline, RefTime::MAX);
            prop_assert_eq!(actual_timeout.deadline, Time::MAX);
        }
    }
}

/// PROPERTY-BASED CONFORMANCE TEST 9: Remaining time accuracy
proptest! {
    #[test]
    fn property_remaining_time_accuracy(
        deadline_nanos in 0u64..u64::MAX,
        now_nanos in 0u64..u64::MAX,
    ) {
        let ref_deadline = RefTime::from_nanos(deadline_nanos);
        let ref_now = RefTime::from_nanos(now_nanos);
        let ref_timeout = RefTimeout::new(ref_deadline);

        let actual_deadline = Time::from_nanos(deadline_nanos);
        let actual_now = Time::from_nanos(now_nanos);
        let actual_timeout = Timeout::<()>::new(actual_deadline);

        let ref_remaining = ref_timeout.remaining(ref_now);
        let actual_remaining = actual_timeout.remaining(actual_now);

        prop_assert_eq!(ref_remaining.as_nanos(), actual_remaining.as_nanos());

        // Verify expiration logic matches
        prop_assert_eq!(ref_timeout.is_expired(ref_now), actual_timeout.is_expired(actual_now));
    }
}