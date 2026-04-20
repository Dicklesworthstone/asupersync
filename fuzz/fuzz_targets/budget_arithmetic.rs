#![no_main]

use arbitrary::Arbitrary;
use asupersync::types::{Budget, Time};
use libfuzzer_sys::fuzz_target;
use std::time::Duration;

#[derive(Arbitrary, Clone, Copy, Debug)]
struct BudgetSpec {
    deadline_nanos: Option<u64>,
    poll_quota: u32,
    cost_quota: Option<u64>,
    priority: u8,
}

#[derive(Arbitrary, Clone, Copy, Debug)]
enum Operation {
    ConsumePoll,
    ConsumeCost(u16),
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    left: BudgetSpec,
    right: BudgetSpec,
    now_nanos: u64,
    operations: Vec<Operation>,
}

fuzz_target!(|input: FuzzInput| {
    if input.operations.len() > 32 {
        return;
    }

    let left = budget_from_spec(input.left);
    let right = budget_from_spec(input.right);
    let now = Time::from_nanos(input.now_nanos);

    let combined = left.combine(right);
    let reverse_combined = right.combine(left);
    let met = left.meet(right);

    let expected = expected_combine(left, right);
    assert_eq!(combined, expected);
    assert_eq!(reverse_combined, expected);
    assert_eq!(met, expected);

    assert_eq!(combined.remaining_polls(), combined.poll_quota);
    assert_eq!(combined.remaining_cost(), combined.cost_quota);
    assert_eq!(
        combined.is_exhausted(),
        combined.poll_quota == 0 || matches!(combined.cost_quota, Some(0))
    );

    let expected_remaining = expected_remaining_time(combined.deadline, now);
    assert_eq!(combined.remaining_time(now), expected_remaining);
    assert_eq!(combined.to_timeout(now), expected_remaining);
    assert_eq!(
        combined.is_past_deadline(now),
        combined.deadline.is_some_and(|deadline| now >= deadline)
    );

    let mut mutated = combined;
    let mut shadow = combined;
    for op in input.operations {
        match op {
            Operation::ConsumePoll => {
                let observed = mutated.consume_poll();
                let expected = expected_consume_poll(&mut shadow);
                assert_eq!(observed, expected);
                assert_eq!(mutated, shadow);
            }
            Operation::ConsumeCost(cost) => {
                let cost = u64::from(cost);
                let observed = mutated.consume_cost(cost);
                let expected = expected_consume_cost(&mut shadow, cost);
                assert_eq!(observed, expected);
                assert_eq!(mutated, shadow);
            }
        }

        assert_eq!(mutated.remaining_polls(), mutated.poll_quota);
        assert_eq!(mutated.remaining_cost(), mutated.cost_quota);
        assert_eq!(
            mutated.is_exhausted(),
            mutated.poll_quota == 0 || matches!(mutated.cost_quota, Some(0))
        );
        assert_eq!(
            mutated.remaining_time(now),
            expected_remaining_time(mutated.deadline, now)
        );
        assert_eq!(mutated.to_timeout(now), mutated.remaining_time(now));
    }
});

fn budget_from_spec(spec: BudgetSpec) -> Budget {
    let mut budget = Budget::new()
        .with_poll_quota(spec.poll_quota)
        .with_priority(spec.priority);
    if let Some(deadline_nanos) = spec.deadline_nanos {
        budget = budget.with_deadline(Time::from_nanos(deadline_nanos));
    }
    if let Some(cost_quota) = spec.cost_quota {
        budget = budget.with_cost_quota(cost_quota);
    }
    budget
}

fn expected_combine(left: Budget, right: Budget) -> Budget {
    Budget {
        deadline: match (left.deadline, right.deadline) {
            (Some(a), Some(b)) => Some(if a < b { a } else { b }),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        },
        poll_quota: left.poll_quota.min(right.poll_quota),
        cost_quota: match (left.cost_quota, right.cost_quota) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        },
        priority: left.priority.max(right.priority),
    }
}

fn expected_remaining_time(deadline: Option<Time>, now: Time) -> Option<Duration> {
    deadline.and_then(|deadline| {
        if now < deadline {
            Some(Duration::from_nanos(
                deadline.as_nanos().saturating_sub(now.as_nanos()),
            ))
        } else {
            None
        }
    })
}

fn expected_consume_poll(budget: &mut Budget) -> Option<u32> {
    if budget.poll_quota > 0 {
        let old = budget.poll_quota;
        budget.poll_quota -= 1;
        Some(old)
    } else {
        None
    }
}

fn expected_consume_cost(budget: &mut Budget, cost: u64) -> bool {
    match budget.cost_quota {
        None => true,
        Some(remaining) if remaining >= cost => {
            budget.cost_quota = Some(remaining - cost);
            true
        }
        Some(_) => false,
    }
}
