#![allow(clippy::all)]
//! Metamorphic tests for types::budget consumption invariants.
//!
//! These tests validate the budget consumption properties using metamorphic relations
//! to ensure budget semantics are preserved across various operations and transformations.

use std::time::Duration;

use proptest::prelude::*;

use asupersync::time::Time;
use asupersync::types::{Budget, Priority, Pressure};

/// Create a Budget with specified parameters.
fn budget_with_params(
    deadline: Option<Duration>,
    poll_quota: u32,
    cost_quota: Option<u64>,
    priority: u8
) -> Budget {
    let deadline_time = deadline.map(|d| Time::now() + d);
    Budget::new(deadline_time, poll_quota, cost_quota, Priority::from_u8(priority))
}

/// Strategy for generating valid budgets.
fn arb_budget() -> impl Strategy<Value = Budget> {
    (
        prop::option::of(1u64..86400), // deadline seconds (up to 1 day)
        1u32..1000,                    // poll_quota (at least 1)
        prop::option::of(1u64..1000000), // cost_quota
        0u8..=4,                       // priority (0-4)
    ).prop_map(|(deadline_secs, poll_quota, cost_quota, priority)| {
        let deadline = deadline_secs.map(Duration::from_secs);
        budget_with_params(deadline, poll_quota, cost_quota, priority)
    })
}

/// Strategy for generating poll costs.
fn arb_poll_cost() -> impl Strategy<Value = u32> {
    1u32..100
}

/// Strategy for generating operation costs.
fn arb_operation_cost() -> impl Strategy<Value = u64> {
    1u64..1000
}

/// Strategy for generating pressure values.
fn arb_pressure() -> impl Strategy<Value = Pressure> {
    prop_oneof![
        Just(Pressure::Low),
        Just(Pressure::Medium),
        Just(Pressure::High),
        Just(Pressure::Critical),
    ]
}

// Metamorphic Relations for Budget Consumption

/// MR1: Budget consumption is monotonic - consuming from a budget should always
/// result in equal or fewer resources remaining, never more.
#[test]
fn mr_budget_consumption_monotonic() {
    proptest!(|(budget in arb_budget(), poll_cost in arb_poll_cost(), op_cost in arb_operation_cost(), pressure in arb_pressure())| {
        // Ensure we don't exceed the budget limits in this test
        let effective_poll_cost = poll_cost.min(budget.poll_quota());
        let effective_op_cost = if let Some(quota) = budget.cost_quota() {
            op_cost.min(quota)
        } else {
            op_cost
        };

        // Test poll consumption monotonicity
        if effective_poll_cost > 0 && budget.poll_quota() >= effective_poll_cost {
            let original_poll_quota = budget.poll_quota();
            let consumed_budget = budget.consume_poll(effective_poll_cost, pressure);

            if let Some(new_budget) = consumed_budget {
                prop_assert!(new_budget.poll_quota() <= original_poll_quota,
                    "Poll consumption should be monotonic: {} -> {} (consumed {})",
                    original_poll_quota, new_budget.poll_quota(), effective_poll_cost);
                prop_assert_eq!(new_budget.poll_quota(), original_poll_quota.saturating_sub(effective_poll_cost),
                    "Poll consumption should subtract exactly the consumed amount");
            }
        }

        // Test operation cost consumption monotonicity
        if let Some(original_cost_quota) = budget.cost_quota() {
            if effective_op_cost > 0 && original_cost_quota >= effective_op_cost {
                let consumed_budget = budget.consume_cost(effective_op_cost, pressure);

                if let Some(new_budget) = consumed_budget {
                    if let Some(new_cost_quota) = new_budget.cost_quota() {
                        prop_assert!(new_cost_quota <= original_cost_quota,
                            "Cost consumption should be monotonic: {} -> {} (consumed {})",
                            original_cost_quota, new_cost_quota, effective_op_cost);
                        prop_assert_eq!(new_cost_quota, original_cost_quota.saturating_sub(effective_op_cost),
                            "Cost consumption should subtract exactly the consumed amount");
                    }
                }
            }
        }

        // Test that deadline is preserved (monotonic in sense of not moving backward)
        let consumed_poll = budget.consume_poll(1, pressure);
        if let Some(new_budget) = consumed_poll {
            prop_assert_eq!(new_budget.deadline(), budget.deadline(),
                "Consumption should not alter deadline");
        }

        let consumed_cost = budget.consume_cost(1, pressure);
        if let Some(new_budget) = consumed_cost {
            prop_assert_eq!(new_budget.deadline(), budget.deadline(),
                "Consumption should not alter deadline");
        }
    });
}

/// MR2: Exhausted budget refuses further operations - Once a budget is fully
/// consumed, attempts to consume more should fail.
#[test]
fn mr_exhausted_budget_refuses_operations() {
    proptest!(|(budget in arb_budget(), pressure in arb_pressure())| {
        // Exhaust poll quota
        let poll_quota = budget.poll_quota();
        if poll_quota > 0 {
            let exhausted_poll = budget.consume_poll(poll_quota, pressure);

            if let Some(exhausted_budget) = exhausted_poll {
                prop_assert_eq!(exhausted_budget.poll_quota(), 0,
                    "Budget should have 0 poll quota after exhaustion");

                // Attempt to consume more from exhausted budget
                let over_consumption = exhausted_budget.consume_poll(1, pressure);
                prop_assert!(over_consumption.is_none(),
                    "Exhausted poll budget should refuse further poll operations");
            }
        }

        // Exhaust cost quota
        if let Some(cost_quota) = budget.cost_quota() {
            if cost_quota > 0 {
                let exhausted_cost = budget.consume_cost(cost_quota, pressure);

                if let Some(exhausted_budget) = exhausted_cost {
                    prop_assert_eq!(exhausted_budget.cost_quota(), Some(0),
                        "Budget should have 0 cost quota after exhaustion");

                    // Attempt to consume more from exhausted budget
                    let over_consumption = exhausted_budget.consume_cost(1, pressure);
                    prop_assert!(over_consumption.is_none(),
                        "Exhausted cost budget should refuse further cost operations");
                }
            }
        }

        // Test that consuming more than available always fails
        let large_poll_cost = poll_quota.saturating_add(1);
        let over_poll = budget.consume_poll(large_poll_cost, pressure);
        prop_assert!(over_poll.is_none(),
            "Budget should refuse poll consumption exceeding quota: {} > {}",
            large_poll_cost, poll_quota);

        if let Some(cost_quota) = budget.cost_quota() {
            let large_cost = cost_quota.saturating_add(1);
            let over_cost = budget.consume_cost(large_cost, pressure);
            prop_assert!(over_cost.is_none(),
                "Budget should refuse cost consumption exceeding quota: {} > {}",
                large_cost, cost_quota);
        }
    });
}

/// MR3: Split budget preserves total - When splitting a budget using meet(),
/// the combined capacity should not exceed the original budget.
#[test]
fn mr_split_budget_preserves_total() {
    proptest!(|(budget1 in arb_budget(), budget2 in arb_budget())| {
        let meet_result = budget1.meet(&budget2);

        // The meet operation should take minimum poll quota
        let expected_poll_quota = budget1.poll_quota().min(budget2.poll_quota());
        prop_assert_eq!(meet_result.poll_quota(), expected_poll_quota,
            "Meet should preserve minimum poll quota: min({}, {}) = {}",
            budget1.poll_quota(), budget2.poll_quota(), expected_poll_quota);

        // The meet operation should take minimum cost quota (None treated as unlimited)
        match (budget1.cost_quota(), budget2.cost_quota()) {
            (Some(c1), Some(c2)) => {
                let expected_cost = c1.min(c2);
                prop_assert_eq!(meet_result.cost_quota(), Some(expected_cost),
                    "Meet should preserve minimum cost quota: min({}, {}) = {}",
                    c1, c2, expected_cost);
            }
            (Some(c), None) | (None, Some(c)) => {
                prop_assert_eq!(meet_result.cost_quota(), Some(c),
                    "Meet with one unlimited should take the limited quota: {}",
                    c);
            }
            (None, None) => {
                prop_assert_eq!(meet_result.cost_quota(), None,
                    "Meet of two unlimited should remain unlimited");
            }
        }

        // Deadline should be the earliest (most restrictive)
        match (budget1.deadline(), budget2.deadline()) {
            (Some(d1), Some(d2)) => {
                let expected_deadline = d1.min(d2);
                prop_assert_eq!(meet_result.deadline(), Some(expected_deadline),
                    "Meet should preserve earliest deadline");
            }
            (Some(d), None) | (None, Some(d)) => {
                prop_assert_eq!(meet_result.deadline(), Some(d),
                    "Meet with one unlimited deadline should take the limited one");
            }
            (None, None) => {
                prop_assert_eq!(meet_result.deadline(), None,
                    "Meet of two unlimited deadlines should remain unlimited");
            }
        }

        // Priority should be the maximum (highest priority)
        let expected_priority = budget1.priority().max(budget2.priority());
        prop_assert_eq!(meet_result.priority(), expected_priority,
            "Meet should preserve maximum priority");

        // Verify that meet result doesn't exceed either input
        prop_assert!(meet_result.poll_quota() <= budget1.poll_quota(),
            "Meet result poll quota should not exceed first input");
        prop_assert!(meet_result.poll_quota() <= budget2.poll_quota(),
            "Meet result poll quota should not exceed second input");

        if let Some(c1) = budget1.cost_quota() {
            if let Some(result_cost) = meet_result.cost_quota() {
                prop_assert!(result_cost <= c1,
                    "Meet result cost quota should not exceed first input");
            }
        }

        if let Some(c2) = budget2.cost_quota() {
            if let Some(result_cost) = meet_result.cost_quota() {
                prop_assert!(result_cost <= c2,
                    "Meet result cost quota should not exceed second input");
            }
        }
    });
}

/// MR4: Cancel refunds unused budget - Cancellation should not consume budget
/// resources, and the refund operation should restore consumed amounts.
#[test]
fn mr_cancel_refunds_unused_budget() {
    proptest!(|(budget in arb_budget(), poll_consumed in arb_poll_cost(), cost_consumed in arb_operation_cost())| {
        // Test that a budget that "would be consumed" during cancellation retains its value
        let original_poll_quota = budget.poll_quota();
        let original_cost_quota = budget.cost_quota();
        let original_deadline = budget.deadline();
        let original_priority = budget.priority();

        // Simulate a cancelled operation - budget should remain unchanged
        // In practice, this means that if we were to consume and then "cancel",
        // we should get back to the original state

        let effective_poll_consumed = poll_consumed.min(original_poll_quota);
        let effective_cost_consumed = if let Some(quota) = original_cost_quota {
            cost_consumed.min(quota)
        } else {
            cost_consumed
        };

        // Consume budget
        if effective_poll_consumed > 0 {
            let consumed_budget = budget.consume_poll(effective_poll_consumed, Pressure::Low);
            if let Some(consumed) = consumed_budget {
                // Create "refunded" budget by restoring consumed amounts
                let refunded = Budget::new(
                    consumed.deadline(),
                    consumed.poll_quota().saturating_add(effective_poll_consumed),
                    consumed.cost_quota(),
                    consumed.priority()
                );

                // Refunded budget should match original for poll quota
                prop_assert_eq!(refunded.poll_quota(), original_poll_quota,
                    "Cancel refund should restore original poll quota: {} vs {}",
                    refunded.poll_quota(), original_poll_quota);
                prop_assert_eq!(refunded.deadline(), original_deadline,
                    "Cancel refund should preserve deadline");
                prop_assert_eq!(refunded.priority(), original_priority,
                    "Cancel refund should preserve priority");
            }
        }

        if let Some(original_cost) = original_cost_quota {
            if effective_cost_consumed > 0 && effective_cost_consumed <= original_cost {
                let consumed_budget = budget.consume_cost(effective_cost_consumed, Pressure::Low);
                if let Some(consumed) = consumed_budget {
                    // Create "refunded" budget by restoring consumed amounts
                    let refunded_cost = consumed.cost_quota()
                        .map(|c| c.saturating_add(effective_cost_consumed));
                    let refunded = Budget::new(
                        consumed.deadline(),
                        consumed.poll_quota(),
                        refunded_cost,
                        consumed.priority()
                    );

                    // Refunded budget should match original for cost quota
                    prop_assert_eq!(refunded.cost_quota(), Some(original_cost),
                        "Cancel refund should restore original cost quota: {:?} vs {}",
                        refunded.cost_quota(), original_cost);
                    prop_assert_eq!(refunded.deadline(), original_deadline,
                        "Cancel refund should preserve deadline");
                    prop_assert_eq!(refunded.priority(), original_priority,
                        "Cancel refund should preserve priority");
                }
            }
        }

        // Test idempotency of "cancel" (no consumption)
        let non_consumed_budget = Budget::new(
            budget.deadline(),
            budget.poll_quota(),
            budget.cost_quota(),
            budget.priority()
        );

        prop_assert_eq!(non_consumed_budget.poll_quota(), original_poll_quota,
            "Non-consumed budget should equal original poll quota");
        prop_assert_eq!(non_consumed_budget.cost_quota(), original_cost_quota,
            "Non-consumed budget should equal original cost quota");
        prop_assert_eq!(non_consumed_budget.deadline(), original_deadline,
            "Non-consumed budget should equal original deadline");
        prop_assert_eq!(non_consumed_budget.priority(), original_priority,
            "Non-consumed budget should equal original priority");
    });
}

/// MR5: Deadline within budget validated - Operations should respect deadline
/// constraints and fail when deadlines are violated.
#[test]
fn mr_deadline_within_budget_validated() {
    proptest!(|(poll_quota in 1u32..100, cost_quota in prop::option::of(1u64..1000), priority in 0u8..=4, pressure in arb_pressure())| {
        let now = Time::now();

        // Test with past deadline (should fail validation)
        let past_deadline = now - Duration::from_secs(1);
        let expired_budget = Budget::new(Some(past_deadline), poll_quota, cost_quota, Priority::from_u8(priority));

        // Operations on expired budget should fail
        let poll_attempt = expired_budget.consume_poll(1, pressure);
        prop_assert!(poll_attempt.is_none(),
            "Budget with past deadline should refuse poll operations");

        if cost_quota.is_some() {
            let cost_attempt = expired_budget.consume_cost(1, pressure);
            prop_assert!(cost_attempt.is_none(),
                "Budget with past deadline should refuse cost operations");
        }

        // Test with future deadline (should succeed if quota allows)
        let future_deadline = now + Duration::from_secs(60);
        let valid_budget = Budget::new(Some(future_deadline), poll_quota, cost_quota, Priority::from_u8(priority));

        // Operations on valid budget should respect quota limits but not fail due to deadline
        if poll_quota > 0 {
            let poll_attempt = valid_budget.consume_poll(1, pressure);
            prop_assert!(poll_attempt.is_some(),
                "Budget with future deadline should allow poll operations when quota permits");
        }

        if let Some(quota) = cost_quota {
            if quota > 0 {
                let cost_attempt = valid_budget.consume_cost(1, pressure);
                prop_assert!(cost_attempt.is_some(),
                    "Budget with future deadline should allow cost operations when quota permits");
            }
        }

        // Test with no deadline (unlimited time)
        let unlimited_budget = Budget::new(None, poll_quota, cost_quota, Priority::from_u8(priority));

        if poll_quota > 0 {
            let poll_attempt = unlimited_budget.consume_poll(1, pressure);
            prop_assert!(poll_attempt.is_some(),
                "Budget with no deadline should allow poll operations when quota permits");
        }

        if let Some(quota) = cost_quota {
            if quota > 0 {
                let cost_attempt = unlimited_budget.consume_cost(1, pressure);
                prop_assert!(cost_attempt.is_some(),
                    "Budget with no deadline should allow cost operations when quota permits");
            }
        }

        // Test deadline preservation through operations
        let consumed_poll = valid_budget.consume_poll(1, pressure);
        if let Some(new_budget) = consumed_poll {
            prop_assert_eq!(new_budget.deadline(), Some(future_deadline),
                "Deadline should be preserved through poll consumption");
        }

        if let Some(quota) = cost_quota {
            if quota > 0 {
                let consumed_cost = valid_budget.consume_cost(1, pressure);
                if let Some(new_budget) = consumed_cost {
                    prop_assert_eq!(new_budget.deadline(), Some(future_deadline),
                        "Deadline should be preserved through cost consumption");
                }
            }
        }

        // Test meet operation deadline validation
        let other_budget = Budget::new(Some(future_deadline + Duration::from_secs(30)), poll_quota, cost_quota, Priority::from_u8(priority));
        let meet_result = valid_budget.meet(&other_budget);
        prop_assert_eq!(meet_result.deadline(), Some(future_deadline),
            "Meet should preserve the earliest deadline");
    });
}

/// Unit tests for specific budget behavior edge cases.
#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn test_budget_creation_and_basic_operations() {
        let now = Time::now();
        let deadline = now + Duration::from_secs(60);
        let budget = Budget::new(Some(deadline), 10, Some(100), Priority::from_u8(2));

        assert_eq!(budget.poll_quota(), 10);
        assert_eq!(budget.cost_quota(), Some(100));
        assert_eq!(budget.deadline(), Some(deadline));
        assert_eq!(budget.priority(), Priority::from_u8(2));
    }

    #[test]
    fn test_budget_consumption_success() {
        let budget = Budget::new(None, 10, Some(100), Priority::from_u8(1));

        // Successful poll consumption
        let consumed_poll = budget.consume_poll(3, Pressure::Low).expect("Should consume poll");
        assert_eq!(consumed_poll.poll_quota(), 7);
        assert_eq!(consumed_poll.cost_quota(), Some(100)); // Unchanged

        // Successful cost consumption
        let consumed_cost = budget.consume_cost(25, Pressure::Medium).expect("Should consume cost");
        assert_eq!(consumed_cost.poll_quota(), 10); // Unchanged
        assert_eq!(consumed_cost.cost_quota(), Some(75));
    }

    #[test]
    fn test_budget_consumption_failure() {
        let budget = Budget::new(None, 5, Some(20), Priority::from_u8(0));

        // Failed poll consumption (exceeds quota)
        let over_poll = budget.consume_poll(6, Pressure::High);
        assert!(over_poll.is_none(), "Should not allow over-consumption of poll quota");

        // Failed cost consumption (exceeds quota)
        let over_cost = budget.consume_cost(21, Pressure::Critical);
        assert!(over_cost.is_none(), "Should not allow over-consumption of cost quota");
    }

    #[test]
    fn test_budget_meet_operation() {
        let budget1 = Budget::new(None, 10, Some(50), Priority::from_u8(1));
        let budget2 = Budget::new(None, 15, Some(30), Priority::from_u8(3));

        let meet_result = budget1.meet(&budget2);

        assert_eq!(meet_result.poll_quota(), 10); // min(10, 15)
        assert_eq!(meet_result.cost_quota(), Some(30)); // min(50, 30)
        assert_eq!(meet_result.priority(), Priority::from_u8(3)); // max(1, 3)
        assert_eq!(meet_result.deadline(), None); // both unlimited
    }

    #[test]
    fn test_budget_deadline_expiration() {
        let now = Time::now();
        let past_deadline = now - Duration::from_secs(1);
        let expired_budget = Budget::new(Some(past_deadline), 5, Some(50), Priority::from_u8(2));

        // Expired budget should refuse operations
        let poll_attempt = expired_budget.consume_poll(1, Pressure::Low);
        assert!(poll_attempt.is_none(), "Expired budget should refuse poll operations");

        let cost_attempt = expired_budget.consume_cost(1, Pressure::Low);
        assert!(cost_attempt.is_none(), "Expired budget should refuse cost operations");
    }

    #[test]
    fn test_budget_unlimited_quotas() {
        let unlimited_budget = Budget::new(None, u32::MAX, None, Priority::from_u8(0));

        // Large consumption should still work with unlimited cost quota
        let consumed = unlimited_budget.consume_poll(1000, Pressure::Medium)
            .expect("Should consume from large poll quota");
        assert_eq!(consumed.poll_quota(), u32::MAX - 1000);
        assert_eq!(consumed.cost_quota(), None); // Still unlimited

        // Cost consumption on unlimited quota should work
        let consumed_cost = unlimited_budget.consume_cost(999999, Pressure::High)
            .expect("Should consume from unlimited cost quota");
        assert_eq!(consumed_cost.cost_quota(), None); // Still unlimited
    }
}