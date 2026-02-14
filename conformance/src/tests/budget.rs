//! Budget Conformance Test Suite
//!
//! Tests for the Budget type with product semiring semantics.
//! Validates deadlines, poll quotas, cost quotas, and their combination behavior.
//!
//! # Spec References
//!
//! - §3.2 Budget System: Product semiring for deadline/quota propagation
//! - §3.2.1 Deadline: Absolute time by which work must complete
//! - §3.2.2 Poll Quota: Maximum number of poll operations
//! - §3.2.3 Cost Quota: Abstract cost units for scheduling
//! - §3.2.4 Meet Operation: Combines budgets (tighter constraints win)
//!
//! # Test IDs
//!
//! ## Deadline Tests (bd-001 to bd-006)
//! - BD-001: Deadline construction and access
//! - BD-002: Deadline expiration detection
//! - BD-003: Deadline inheritance (tighter wins)
//! - BD-004: Remaining time calculation
//! - BD-005: No deadline vs deadline combination
//! - BD-006: Runtime timeout approximates deadline behavior
//!
//! ## Poll Quota Tests (pq-001 to pq-006)
//! - PQ-001: Poll quota construction and access
//! - PQ-002: Poll consumption decrements quota
//! - PQ-003: Poll exhaustion detection
//! - PQ-004: Poll quota inheritance (tighter wins)
//! - PQ-005: Zero poll quota is exhausted
//! - PQ-006: Unlimited poll quota
//!
//! ## Cost Quota Tests (cq-001 to cq-006)
//! - CQ-001: Cost quota construction and access
//! - CQ-002: Cost consumption decrements quota
//! - CQ-003: Cost exhaustion detection
//! - CQ-004: Cost quota inheritance (tighter wins)
//! - CQ-005: Unlimited cost quota (None)
//! - CQ-006: Cost over-consumption fails
//!
//! ## Combined Budget Tests (cb-001 to cb-004)
//! - CB-001: Combined constraints all enforced
//! - CB-002: INFINITE budget is identity
//! - CB-003: ZERO budget absorbs all
//! - CB-004: Priority uses max (not min)

use crate::{checkpoint, ConformanceTest, RuntimeInterface, TestCategory, TestMeta, TestResult};
use std::time::Duration;

// Re-export the Budget type from the main crate for testing
// Note: In a real implementation, we'd import from asupersync::Budget
// For now, we define inline helpers that mirror Budget behavior

/// Get all budget conformance tests.
pub fn all_tests<RT: RuntimeInterface>() -> Vec<ConformanceTest<RT>> {
    let mut tests = Vec::new();
    tests.extend(deadline_tests::<RT>());
    tests.extend(poll_quota_tests::<RT>());
    tests.extend(cost_quota_tests::<RT>());
    tests.extend(combined_tests::<RT>());
    tests
}

/// Get deadline conformance tests.
pub fn deadline_tests<RT: RuntimeInterface>() -> Vec<ConformanceTest<RT>> {
    vec![
        bd_001_deadline_construction::<RT>(),
        bd_002_deadline_expiration::<RT>(),
        bd_003_deadline_inheritance::<RT>(),
        bd_004_remaining_time::<RT>(),
        bd_005_no_deadline_combination::<RT>(),
        bd_006_timeout_deadline_behavior::<RT>(),
    ]
}

/// Get poll quota conformance tests.
pub fn poll_quota_tests<RT: RuntimeInterface>() -> Vec<ConformanceTest<RT>> {
    vec![
        pq_001_poll_quota_construction::<RT>(),
        pq_002_poll_consumption::<RT>(),
        pq_003_poll_exhaustion::<RT>(),
        pq_004_poll_quota_inheritance::<RT>(),
        pq_005_zero_poll_quota::<RT>(),
        pq_006_unlimited_poll_quota::<RT>(),
    ]
}

/// Get cost quota conformance tests.
pub fn cost_quota_tests<RT: RuntimeInterface>() -> Vec<ConformanceTest<RT>> {
    vec![
        cq_001_cost_quota_construction::<RT>(),
        cq_002_cost_consumption::<RT>(),
        cq_003_cost_exhaustion::<RT>(),
        cq_004_cost_quota_inheritance::<RT>(),
        cq_005_unlimited_cost_quota::<RT>(),
        cq_006_cost_over_consumption::<RT>(),
    ]
}

/// Get combined budget conformance tests.
pub fn combined_tests<RT: RuntimeInterface>() -> Vec<ConformanceTest<RT>> {
    vec![
        cb_001_combined_constraints::<RT>(),
        cb_002_infinite_identity::<RT>(),
        cb_003_zero_absorbs::<RT>(),
        cb_004_priority_uses_max::<RT>(),
    ]
}

// ============================================================================
// Inline Budget simulation for conformance testing
// In a full implementation, this would import asupersync::Budget
// ============================================================================

/// Simulated Time type for conformance testing.
/// Spec §3.2.1: Time is represented as nanoseconds from epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Time(u64);

impl Time {
    const ZERO: Self = Self(0);

    const fn from_secs(secs: u64) -> Self {
        Self(secs * 1_000_000_000)
    }

    #[allow(dead_code)]
    const fn from_nanos(nanos: u64) -> Self {
        Self(nanos)
    }

    const fn as_nanos(&self) -> u64 {
        self.0
    }

    fn saturating_sub(&self, other: &Self) -> Self {
        Self(self.0.saturating_sub(other.0))
    }
}

/// Simulated Budget type for conformance testing.
/// Spec §3.2: Budget constrains resource usage with product semiring semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Budget {
    deadline: Option<Time>,
    poll_quota: u32,
    cost_quota: Option<u64>,
    priority: u8,
}

impl Budget {
    const INFINITE: Self = Self {
        deadline: None,
        poll_quota: u32::MAX,
        cost_quota: None,
        priority: 128,
    };

    const ZERO: Self = Self {
        deadline: Some(Time::ZERO),
        poll_quota: 0,
        cost_quota: Some(0),
        priority: 0,
    };

    const fn new() -> Self {
        Self::INFINITE
    }

    const fn with_deadline(mut self, deadline: Time) -> Self {
        self.deadline = Some(deadline);
        self
    }

    const fn with_poll_quota(mut self, quota: u32) -> Self {
        self.poll_quota = quota;
        self
    }

    const fn with_cost_quota(mut self, quota: u64) -> Self {
        self.cost_quota = Some(quota);
        self
    }

    const fn with_priority(mut self, priority: u8) -> Self {
        self.priority = priority;
        self
    }

    const fn is_exhausted(&self) -> bool {
        self.poll_quota == 0 || matches!(self.cost_quota, Some(0))
    }

    fn is_past_deadline(&self, now: Time) -> bool {
        self.deadline.is_some_and(|d| now >= d)
    }

    fn consume_poll(&mut self) -> Option<u32> {
        if self.poll_quota > 0 {
            let old = self.poll_quota;
            self.poll_quota -= 1;
            Some(old)
        } else {
            None
        }
    }

    fn consume_cost(&mut self, cost: u64) -> bool {
        match self.cost_quota {
            None => true,
            Some(remaining) if remaining >= cost => {
                self.cost_quota = Some(remaining - cost);
                true
            }
            Some(_) => false,
        }
    }

    fn remaining_time(&self, now: Time) -> Option<Time> {
        self.deadline.and_then(|d| {
            if now < d {
                Some(d.saturating_sub(&now))
            } else {
                None
            }
        })
    }

    /// Spec §3.2.4: Meet operation combines budgets.
    /// - Deadlines: min (tighter wins)
    /// - Quotas: min (tighter wins)
    /// - Priority: max (higher wins)
    fn meet(self, other: Self) -> Self {
        Self {
            deadline: match (self.deadline, other.deadline) {
                (Some(a), Some(b)) => Some(if a < b { a } else { b }),
                (Some(a), None) => Some(a),
                (None, Some(b)) => Some(b),
                (None, None) => None,
            },
            poll_quota: self.poll_quota.min(other.poll_quota),
            cost_quota: match (self.cost_quota, other.cost_quota) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (Some(a), None) => Some(a),
                (None, Some(b)) => Some(b),
                (None, None) => None,
            },
            priority: self.priority.max(other.priority),
        }
    }
}

// ============================================================================
// Deadline Tests (BD-001 to BD-006)
// ============================================================================

/// BD-001: Deadline construction and access
///
/// Spec §3.2.1: Deadline is an absolute time by which work must complete.
pub fn bd_001_deadline_construction<RT: RuntimeInterface>() -> ConformanceTest<RT> {
    ConformanceTest::new(
        TestMeta {
            id: "bd-001".to_string(),
            name: "Deadline construction and access".to_string(),
            description: "Verify deadline can be set and read back correctly".to_string(),
            category: TestCategory::Time,
            tags: vec![
                "budget".to_string(),
                "deadline".to_string(),
                "construction".to_string(),
            ],
            expected: "Deadline value matches what was set".to_string(),
        },
        |rt| {
            rt.block_on(async {
                let deadline = Time::from_secs(30);
                let budget = Budget::new().with_deadline(deadline);

                checkpoint(
                    "deadline_set",
                    serde_json::json!({
                        "deadline_nanos": deadline.as_nanos(),
                        "budget_deadline": budget.deadline.map(|t| t.as_nanos()),
                    }),
                );

                if budget.deadline != Some(deadline) {
                    return TestResult::failed(format!(
                        "Deadline mismatch: expected {:?}, got {:?}",
                        Some(deadline),
                        budget.deadline
                    ));
                }

                // Default budget should have no deadline
                let default_budget = Budget::new();
                if default_budget.deadline.is_some() {
                    return TestResult::failed("Default budget should have no deadline");
                }

                TestResult::passed()
            })
        },
    )
}

/// BD-002: Deadline expiration detection
///
/// Spec §3.2.1: When now >= deadline, the budget is past deadline.
pub fn bd_002_deadline_expiration<RT: RuntimeInterface>() -> ConformanceTest<RT> {
    ConformanceTest::new(
        TestMeta {
            id: "bd-002".to_string(),
            name: "Deadline expiration detection".to_string(),
            description: "Verify is_past_deadline correctly detects expired deadlines".to_string(),
            category: TestCategory::Time,
            tags: vec![
                "budget".to_string(),
                "deadline".to_string(),
                "expiration".to_string(),
            ],
            expected: "Past deadline detected when now >= deadline".to_string(),
        },
        |rt| {
            rt.block_on(async {
                let deadline = Time::from_secs(10);
                let budget = Budget::new().with_deadline(deadline);

                // Before deadline
                let before = Time::from_secs(5);
                let past_before = budget.is_past_deadline(before);

                checkpoint(
                    "before_deadline",
                    serde_json::json!({
                        "now": before.as_nanos(),
                        "deadline": deadline.as_nanos(),
                        "is_past": past_before,
                    }),
                );

                if past_before {
                    return TestResult::failed("Should not be past deadline when now < deadline");
                }

                // At deadline (should be past)
                let at = deadline;
                let past_at = budget.is_past_deadline(at);

                if !past_at {
                    return TestResult::failed("Should be past deadline when now == deadline");
                }

                // After deadline
                let after = Time::from_secs(15);
                let past_after = budget.is_past_deadline(after);

                checkpoint(
                    "after_deadline",
                    serde_json::json!({
                        "now": after.as_nanos(),
                        "deadline": deadline.as_nanos(),
                        "is_past": past_after,
                    }),
                );

                if !past_after {
                    return TestResult::failed("Should be past deadline when now > deadline");
                }

                TestResult::passed()
            })
        },
    )
}

/// BD-003: Deadline inheritance (tighter wins)
///
/// Spec §3.2.4: When combining budgets, min deadline wins.
pub fn bd_003_deadline_inheritance<RT: RuntimeInterface>() -> ConformanceTest<RT> {
    ConformanceTest::new(
        TestMeta {
            id: "bd-003".to_string(),
            name: "Deadline inheritance - tighter wins".to_string(),
            description: "Verify child deadline is min(parent, child)".to_string(),
            category: TestCategory::Time,
            tags: vec![
                "budget".to_string(),
                "deadline".to_string(),
                "inheritance".to_string(),
                "meet".to_string(),
            ],
            expected: "Combined deadline is the earlier of the two".to_string(),
        },
        |rt| {
            rt.block_on(async {
                let parent = Budget::new().with_deadline(Time::from_secs(30));
                let child = Budget::new().with_deadline(Time::from_secs(10));

                let combined = parent.meet(child);

                checkpoint(
                    "deadline_combination",
                    serde_json::json!({
                        "parent_deadline_secs": 30,
                        "child_deadline_secs": 10,
                        "combined_deadline_nanos": combined.deadline.map(|t| t.as_nanos()),
                    }),
                );

                if combined.deadline != Some(Time::from_secs(10)) {
                    return TestResult::failed(format!(
                        "Combined deadline should be 10s (tighter), got {:?}",
                        combined.deadline
                    ));
                }

                // Test reverse order (should be same result)
                let combined_rev = child.meet(parent);
                if combined_rev.deadline != combined.deadline {
                    return TestResult::failed("Meet should be commutative for deadlines");
                }

                TestResult::passed()
            })
        },
    )
}

/// BD-004: Remaining time calculation
///
/// Spec §3.2.1: Remaining time is deadline - now when deadline > now.
pub fn bd_004_remaining_time<RT: RuntimeInterface>() -> ConformanceTest<RT> {
    ConformanceTest::new(
        TestMeta {
            id: "bd-004".to_string(),
            name: "Remaining time calculation".to_string(),
            description: "Verify remaining_time computes deadline - now correctly".to_string(),
            category: TestCategory::Time,
            tags: vec![
                "budget".to_string(),
                "deadline".to_string(),
                "remaining".to_string(),
            ],
            expected: "Remaining time = deadline - now when valid".to_string(),
        },
        |rt| {
            rt.block_on(async {
                let budget = Budget::new().with_deadline(Time::from_secs(30));
                let now = Time::from_secs(10);

                let remaining = budget.remaining_time(now);

                checkpoint(
                    "remaining_time",
                    serde_json::json!({
                        "deadline_secs": 30,
                        "now_secs": 10,
                        "remaining_nanos": remaining.map(|t| t.as_nanos()),
                    }),
                );

                if remaining != Some(Time::from_secs(20)) {
                    return TestResult::failed(format!(
                        "Remaining time should be 20s, got {:?}",
                        remaining
                    ));
                }

                // Past deadline should return None
                let past_now = Time::from_secs(40);
                let remaining_past = budget.remaining_time(past_now);
                if remaining_past.is_some() {
                    return TestResult::failed("Remaining time should be None when past deadline");
                }

                // No deadline should return None
                let no_deadline = Budget::new();
                let remaining_none = no_deadline.remaining_time(now);
                if remaining_none.is_some() {
                    return TestResult::failed("Remaining time should be None when no deadline");
                }

                TestResult::passed()
            })
        },
    )
}

/// BD-005: No deadline vs deadline combination
///
/// Spec §3.2.4: None deadline combined with Some deadline yields Some.
pub fn bd_005_no_deadline_combination<RT: RuntimeInterface>() -> ConformanceTest<RT> {
    ConformanceTest::new(
        TestMeta {
            id: "bd-005".to_string(),
            name: "No deadline + deadline combination".to_string(),
            description: "Verify None deadline combined with Some yields Some".to_string(),
            category: TestCategory::Time,
            tags: vec![
                "budget".to_string(),
                "deadline".to_string(),
                "meet".to_string(),
            ],
            expected: "Defined deadline takes precedence over None".to_string(),
        },
        |rt| {
            rt.block_on(async {
                let no_deadline = Budget::new(); // deadline = None
                let has_deadline = Budget::new().with_deadline(Time::from_secs(10));

                // Either order should produce the deadline
                let combined1 = no_deadline.meet(has_deadline);
                let combined2 = has_deadline.meet(no_deadline);

                checkpoint(
                    "none_some_combination",
                    serde_json::json!({
                        "combined1_deadline": combined1.deadline.map(|t| t.as_nanos()),
                        "combined2_deadline": combined2.deadline.map(|t| t.as_nanos()),
                    }),
                );

                if combined1.deadline != Some(Time::from_secs(10)) {
                    return TestResult::failed("None.meet(Some) should yield Some");
                }

                if combined2.deadline != Some(Time::from_secs(10)) {
                    return TestResult::failed("Some.meet(None) should yield Some");
                }

                // None.meet(None) should stay None
                let both_none = no_deadline.meet(Budget::new());
                if both_none.deadline.is_some() {
                    return TestResult::failed("None.meet(None) should be None");
                }

                TestResult::passed()
            })
        },
    )
}

/// BD-006: Timeout as deadline behavior proxy
///
/// Runtime timeouts approximate budget deadline behavior.
/// When a timeout expires, it's analogous to deadline-based cancellation.
pub fn bd_006_timeout_deadline_behavior<RT: RuntimeInterface>() -> ConformanceTest<RT> {
    ConformanceTest::new(
        TestMeta {
            id: "bd-006".to_string(),
            name: "Timeout approximates deadline behavior".to_string(),
            description: "Verify runtime timeout behaves like budget deadline".to_string(),
            category: TestCategory::Time,
            tags: vec![
                "budget".to_string(),
                "deadline".to_string(),
                "timeout".to_string(),
            ],
            expected: "Timeout expiration mirrors deadline cancellation".to_string(),
        },
        |rt| {
            rt.block_on(async {
                // Use a short timeout to verify expiration behavior
                let timeout_duration = Duration::from_millis(50);

                // Create a future that takes too long
                let long_sleep = rt.sleep(Duration::from_secs(10));

                // Task that would take longer than timeout
                let result = rt.timeout(timeout_duration, long_sleep).await;

                checkpoint(
                    "timeout_result",
                    serde_json::json!({
                        "timed_out": result.is_err(),
                    }),
                );

                if result.is_ok() {
                    return TestResult::failed("Long task should timeout");
                }

                // Create a quick future
                let quick_sleep = rt.sleep(Duration::from_millis(10));

                // Task that completes within timeout
                let quick_result = rt.timeout(Duration::from_secs(10), quick_sleep).await;

                if quick_result.is_err() {
                    return TestResult::failed("Quick task should complete without timeout");
                }

                TestResult::passed()
            })
        },
    )
}

// ============================================================================
// Poll Quota Tests (PQ-001 to PQ-006)
// ============================================================================

/// PQ-001: Poll quota construction and access
///
/// Spec §3.2.2: Poll quota limits the number of poll operations.
pub fn pq_001_poll_quota_construction<RT: RuntimeInterface>() -> ConformanceTest<RT> {
    ConformanceTest::new(
        TestMeta {
            id: "pq-001".to_string(),
            name: "Poll quota construction".to_string(),
            description: "Verify poll quota can be set and accessed".to_string(),
            category: TestCategory::Spawn,
            tags: vec![
                "budget".to_string(),
                "poll_quota".to_string(),
                "construction".to_string(),
            ],
            expected: "Poll quota value matches what was set".to_string(),
        },
        |rt| {
            rt.block_on(async {
                let budget = Budget::new().with_poll_quota(100);

                checkpoint(
                    "poll_quota_set",
                    serde_json::json!({
                        "poll_quota": budget.poll_quota,
                    }),
                );

                if budget.poll_quota != 100 {
                    return TestResult::failed(format!(
                        "Poll quota should be 100, got {}",
                        budget.poll_quota
                    ));
                }

                // Default should be MAX
                let default = Budget::new();
                if default.poll_quota != u32::MAX {
                    return TestResult::failed("Default poll quota should be u32::MAX");
                }

                TestResult::passed()
            })
        },
    )
}

/// PQ-002: Poll consumption decrements quota
///
/// Spec §3.2.2: Each poll consumes one quota unit.
pub fn pq_002_poll_consumption<RT: RuntimeInterface>() -> ConformanceTest<RT> {
    ConformanceTest::new(
        TestMeta {
            id: "pq-002".to_string(),
            name: "Poll consumption".to_string(),
            description: "Verify consume_poll decrements quota correctly".to_string(),
            category: TestCategory::Spawn,
            tags: vec![
                "budget".to_string(),
                "poll_quota".to_string(),
                "consume".to_string(),
            ],
            expected: "Quota decrements by 1 per consume_poll call".to_string(),
        },
        |rt| {
            rt.block_on(async {
                let mut budget = Budget::new().with_poll_quota(5);

                // Consume polls and track
                let mut consumed = Vec::new();
                for i in 0..6 {
                    let result = budget.consume_poll();
                    consumed.push((i, result, budget.poll_quota));
                }

                checkpoint(
                    "poll_consumption",
                    serde_json::json!({
                        "consumption_sequence": consumed,
                    }),
                );

                // First 5 should succeed
                for (i, item) in consumed.iter().enumerate().take(5) {
                    if item.1 != Some(5 - i as u32) {
                        return TestResult::failed(format!(
                            "consume_poll #{} should return Some({}), got {:?}",
                            i,
                            5 - i,
                            item.1
                        ));
                    }
                }

                // 6th should fail
                if consumed[5].1.is_some() {
                    return TestResult::failed("consume_poll at 0 should return None");
                }

                TestResult::passed()
            })
        },
    )
}

/// PQ-003: Poll exhaustion detection
///
/// Spec §3.2.2: Budget is exhausted when poll_quota == 0.
pub fn pq_003_poll_exhaustion<RT: RuntimeInterface>() -> ConformanceTest<RT> {
    ConformanceTest::new(
        TestMeta {
            id: "pq-003".to_string(),
            name: "Poll exhaustion detection".to_string(),
            description: "Verify is_exhausted returns true when poll_quota is 0".to_string(),
            category: TestCategory::Spawn,
            tags: vec![
                "budget".to_string(),
                "poll_quota".to_string(),
                "exhausted".to_string(),
            ],
            expected: "is_exhausted true when poll_quota reaches 0".to_string(),
        },
        |rt| {
            rt.block_on(async {
                let mut budget = Budget::new().with_poll_quota(1);

                let before = budget.is_exhausted();
                budget.consume_poll();
                let after = budget.is_exhausted();

                checkpoint(
                    "poll_exhaustion",
                    serde_json::json!({
                        "exhausted_before": before,
                        "exhausted_after": after,
                    }),
                );

                if before {
                    return TestResult::failed("Budget with quota=1 should not be exhausted");
                }

                if !after {
                    return TestResult::failed("Budget with quota=0 should be exhausted");
                }

                TestResult::passed()
            })
        },
    )
}

/// PQ-004: Poll quota inheritance (tighter wins)
///
/// Spec §3.2.4: When combining, min poll quota wins.
pub fn pq_004_poll_quota_inheritance<RT: RuntimeInterface>() -> ConformanceTest<RT> {
    ConformanceTest::new(
        TestMeta {
            id: "pq-004".to_string(),
            name: "Poll quota inheritance - tighter wins".to_string(),
            description: "Verify combined poll quota is min of the two".to_string(),
            category: TestCategory::Spawn,
            tags: vec![
                "budget".to_string(),
                "poll_quota".to_string(),
                "meet".to_string(),
            ],
            expected: "Combined poll quota = min(a, b)".to_string(),
        },
        |rt| {
            rt.block_on(async {
                let a = Budget::new().with_poll_quota(100);
                let b = Budget::new().with_poll_quota(50);

                let combined = a.meet(b);

                checkpoint(
                    "poll_quota_inheritance",
                    serde_json::json!({
                        "a_quota": a.poll_quota,
                        "b_quota": b.poll_quota,
                        "combined_quota": combined.poll_quota,
                    }),
                );

                if combined.poll_quota != 50 {
                    return TestResult::failed(format!(
                        "Combined poll quota should be 50, got {}",
                        combined.poll_quota
                    ));
                }

                // Commutative check
                let combined_rev = b.meet(a);
                if combined_rev.poll_quota != combined.poll_quota {
                    return TestResult::failed("Meet should be commutative for poll quota");
                }

                TestResult::passed()
            })
        },
    )
}

/// PQ-005: Zero poll quota is exhausted
///
/// Spec §3.2.2: Zero quota means immediate exhaustion.
pub fn pq_005_zero_poll_quota<RT: RuntimeInterface>() -> ConformanceTest<RT> {
    ConformanceTest::new(
        TestMeta {
            id: "pq-005".to_string(),
            name: "Zero poll quota is exhausted".to_string(),
            description: "Verify budget with poll_quota=0 is immediately exhausted".to_string(),
            category: TestCategory::Spawn,
            tags: vec![
                "budget".to_string(),
                "poll_quota".to_string(),
                "zero".to_string(),
            ],
            expected: "Zero poll quota means is_exhausted=true".to_string(),
        },
        |rt| {
            rt.block_on(async {
                let budget = Budget::new().with_poll_quota(0);

                checkpoint(
                    "zero_poll_quota",
                    serde_json::json!({
                        "poll_quota": budget.poll_quota,
                        "is_exhausted": budget.is_exhausted(),
                    }),
                );

                if !budget.is_exhausted() {
                    return TestResult::failed("Budget with poll_quota=0 should be exhausted");
                }

                TestResult::passed()
            })
        },
    )
}

/// PQ-006: Unlimited poll quota (u32::MAX)
///
/// Spec §3.2.2: MAX quota is effectively unlimited.
pub fn pq_006_unlimited_poll_quota<RT: RuntimeInterface>() -> ConformanceTest<RT> {
    ConformanceTest::new(
        TestMeta {
            id: "pq-006".to_string(),
            name: "Unlimited poll quota".to_string(),
            description: "Verify u32::MAX poll quota is not exhausted".to_string(),
            category: TestCategory::Spawn,
            tags: vec![
                "budget".to_string(),
                "poll_quota".to_string(),
                "unlimited".to_string(),
            ],
            expected: "MAX poll quota means not exhausted".to_string(),
        },
        |rt| {
            rt.block_on(async {
                let budget = Budget::new(); // poll_quota = u32::MAX

                checkpoint(
                    "unlimited_poll_quota",
                    serde_json::json!({
                        "poll_quota": budget.poll_quota,
                        "is_max": budget.poll_quota == u32::MAX,
                        "is_exhausted": budget.is_exhausted(),
                    }),
                );

                if budget.poll_quota != u32::MAX {
                    return TestResult::failed("Default poll quota should be u32::MAX");
                }

                if budget.is_exhausted() {
                    return TestResult::failed("Unlimited poll quota should not be exhausted");
                }

                TestResult::passed()
            })
        },
    )
}

// ============================================================================
// Cost Quota Tests (CQ-001 to CQ-006)
// ============================================================================

/// CQ-001: Cost quota construction and access
///
/// Spec §3.2.3: Cost quota is an abstract cost limit.
pub fn cq_001_cost_quota_construction<RT: RuntimeInterface>() -> ConformanceTest<RT> {
    ConformanceTest::new(
        TestMeta {
            id: "cq-001".to_string(),
            name: "Cost quota construction".to_string(),
            description: "Verify cost quota can be set and accessed".to_string(),
            category: TestCategory::Spawn,
            tags: vec![
                "budget".to_string(),
                "cost_quota".to_string(),
                "construction".to_string(),
            ],
            expected: "Cost quota value matches what was set".to_string(),
        },
        |rt| {
            rt.block_on(async {
                let budget = Budget::new().with_cost_quota(1000);

                checkpoint(
                    "cost_quota_set",
                    serde_json::json!({
                        "cost_quota": budget.cost_quota,
                    }),
                );

                if budget.cost_quota != Some(1000) {
                    return TestResult::failed(format!(
                        "Cost quota should be Some(1000), got {:?}",
                        budget.cost_quota
                    ));
                }

                // Default should be None (unlimited)
                let default = Budget::new();
                if default.cost_quota.is_some() {
                    return TestResult::failed("Default cost quota should be None");
                }

                TestResult::passed()
            })
        },
    )
}

/// CQ-002: Cost consumption decrements quota
///
/// Spec §3.2.3: consume_cost subtracts from available quota.
pub fn cq_002_cost_consumption<RT: RuntimeInterface>() -> ConformanceTest<RT> {
    ConformanceTest::new(
        TestMeta {
            id: "cq-002".to_string(),
            name: "Cost consumption".to_string(),
            description: "Verify consume_cost decrements quota correctly".to_string(),
            category: TestCategory::Spawn,
            tags: vec![
                "budget".to_string(),
                "cost_quota".to_string(),
                "consume".to_string(),
            ],
            expected: "Cost quota decrements by consumed amount".to_string(),
        },
        |rt| {
            rt.block_on(async {
                let mut budget = Budget::new().with_cost_quota(100);

                // Consume 30
                let success1 = budget.consume_cost(30);
                let after1 = budget.cost_quota;

                // Consume another 50
                let success2 = budget.consume_cost(50);
                let after2 = budget.cost_quota;

                checkpoint(
                    "cost_consumption",
                    serde_json::json!({
                        "consume_30_success": success1,
                        "after_30": after1,
                        "consume_50_success": success2,
                        "after_80": after2,
                    }),
                );

                if !success1 || after1 != Some(70) {
                    return TestResult::failed(format!(
                        "After consuming 30 from 100, should have 70, got {:?}",
                        after1
                    ));
                }

                if !success2 || after2 != Some(20) {
                    return TestResult::failed(format!(
                        "After consuming 50 from 70, should have 20, got {:?}",
                        after2
                    ));
                }

                TestResult::passed()
            })
        },
    )
}

/// CQ-003: Cost exhaustion detection
///
/// Spec §3.2.3: Budget is exhausted when cost_quota == Some(0).
pub fn cq_003_cost_exhaustion<RT: RuntimeInterface>() -> ConformanceTest<RT> {
    ConformanceTest::new(
        TestMeta {
            id: "cq-003".to_string(),
            name: "Cost exhaustion detection".to_string(),
            description: "Verify is_exhausted returns true when cost_quota is 0".to_string(),
            category: TestCategory::Spawn,
            tags: vec![
                "budget".to_string(),
                "cost_quota".to_string(),
                "exhausted".to_string(),
            ],
            expected: "is_exhausted true when cost_quota reaches 0".to_string(),
        },
        |rt| {
            rt.block_on(async {
                let mut budget = Budget::new().with_cost_quota(50).with_poll_quota(u32::MAX); // Keep poll unlimited

                let before = budget.is_exhausted();
                budget.consume_cost(50);
                let after = budget.is_exhausted();

                checkpoint(
                    "cost_exhaustion",
                    serde_json::json!({
                        "exhausted_before": before,
                        "exhausted_after": after,
                        "final_cost_quota": budget.cost_quota,
                    }),
                );

                if before {
                    return TestResult::failed("Budget with cost_quota=50 should not be exhausted");
                }

                if !after {
                    return TestResult::failed("Budget with cost_quota=0 should be exhausted");
                }

                TestResult::passed()
            })
        },
    )
}

/// CQ-004: Cost quota inheritance (tighter wins)
///
/// Spec §3.2.4: When combining, min cost quota wins.
pub fn cq_004_cost_quota_inheritance<RT: RuntimeInterface>() -> ConformanceTest<RT> {
    ConformanceTest::new(
        TestMeta {
            id: "cq-004".to_string(),
            name: "Cost quota inheritance - tighter wins".to_string(),
            description: "Verify combined cost quota is min of the two".to_string(),
            category: TestCategory::Spawn,
            tags: vec![
                "budget".to_string(),
                "cost_quota".to_string(),
                "meet".to_string(),
            ],
            expected: "Combined cost quota = min(a, b)".to_string(),
        },
        |rt| {
            rt.block_on(async {
                let a = Budget::new().with_cost_quota(1000);
                let b = Budget::new().with_cost_quota(500);

                let combined = a.meet(b);

                checkpoint(
                    "cost_quota_inheritance",
                    serde_json::json!({
                        "a_quota": a.cost_quota,
                        "b_quota": b.cost_quota,
                        "combined_quota": combined.cost_quota,
                    }),
                );

                if combined.cost_quota != Some(500) {
                    return TestResult::failed(format!(
                        "Combined cost quota should be Some(500), got {:?}",
                        combined.cost_quota
                    ));
                }

                TestResult::passed()
            })
        },
    )
}

/// CQ-005: Unlimited cost quota (None)
///
/// Spec §3.2.3: None means no cost limit.
pub fn cq_005_unlimited_cost_quota<RT: RuntimeInterface>() -> ConformanceTest<RT> {
    ConformanceTest::new(
        TestMeta {
            id: "cq-005".to_string(),
            name: "Unlimited cost quota".to_string(),
            description: "Verify None cost quota allows unlimited consumption".to_string(),
            category: TestCategory::Spawn,
            tags: vec![
                "budget".to_string(),
                "cost_quota".to_string(),
                "unlimited".to_string(),
            ],
            expected: "None cost quota allows any consumption".to_string(),
        },
        |rt| {
            rt.block_on(async {
                let mut budget = Budget::new(); // cost_quota = None

                // Should succeed even with large cost
                let success = budget.consume_cost(1_000_000);

                checkpoint(
                    "unlimited_cost_quota",
                    serde_json::json!({
                        "cost_quota_before": "None",
                        "consume_large_success": success,
                        "cost_quota_after": budget.cost_quota,
                    }),
                );

                if !success {
                    return TestResult::failed("Unlimited cost quota should allow any consumption");
                }

                // Should still be None after consumption
                if budget.cost_quota.is_some() {
                    return TestResult::failed("Unlimited cost quota should remain None");
                }

                TestResult::passed()
            })
        },
    )
}

/// CQ-006: Cost over-consumption fails
///
/// Spec §3.2.3: Cannot consume more than remaining quota.
pub fn cq_006_cost_over_consumption<RT: RuntimeInterface>() -> ConformanceTest<RT> {
    ConformanceTest::new(
        TestMeta {
            id: "cq-006".to_string(),
            name: "Cost over-consumption fails".to_string(),
            description: "Verify consuming more than available fails".to_string(),
            category: TestCategory::Spawn,
            tags: vec![
                "budget".to_string(),
                "cost_quota".to_string(),
                "overflow".to_string(),
            ],
            expected: "Cannot consume more than remaining cost quota".to_string(),
        },
        |rt| {
            rt.block_on(async {
                let mut budget = Budget::new().with_cost_quota(50);

                // Try to consume more than available
                let over_success = budget.consume_cost(100);

                checkpoint(
                    "cost_over_consumption",
                    serde_json::json!({
                        "initial_quota": 50,
                        "attempted_consume": 100,
                        "success": over_success,
                        "final_quota": budget.cost_quota,
                    }),
                );

                if over_success {
                    return TestResult::failed("Over-consumption should fail");
                }

                // Quota should be unchanged
                if budget.cost_quota != Some(50) {
                    return TestResult::failed("Failed consumption should not modify quota");
                }

                TestResult::passed()
            })
        },
    )
}

// ============================================================================
// Combined Budget Tests (CB-001 to CB-004)
// ============================================================================

/// CB-001: Combined constraints all enforced
///
/// Spec §3.2.4: All budget dimensions are combined independently.
pub fn cb_001_combined_constraints<RT: RuntimeInterface>() -> ConformanceTest<RT> {
    ConformanceTest::new(
        TestMeta {
            id: "cb-001".to_string(),
            name: "Combined constraints enforced".to_string(),
            description: "Verify all budget dimensions are combined".to_string(),
            category: TestCategory::Time,
            tags: vec![
                "budget".to_string(),
                "combined".to_string(),
                "meet".to_string(),
            ],
            expected: "Each dimension uses appropriate combining rule".to_string(),
        },
        |rt| {
            rt.block_on(async {
                let a = Budget::new()
                    .with_deadline(Time::from_secs(30))
                    .with_poll_quota(1000)
                    .with_cost_quota(10000)
                    .with_priority(100);

                let b = Budget::new()
                    .with_deadline(Time::from_secs(10))
                    .with_poll_quota(500)
                    .with_cost_quota(5000)
                    .with_priority(200);

                let combined = a.meet(b);

                checkpoint(
                    "combined_constraints",
                    serde_json::json!({
                        "deadline": combined.deadline.map(|t| t.as_nanos()),
                        "poll_quota": combined.poll_quota,
                        "cost_quota": combined.cost_quota,
                        "priority": combined.priority,
                    }),
                );

                // Deadline: min
                if combined.deadline != Some(Time::from_secs(10)) {
                    return TestResult::failed("Combined deadline should be 10s (min)");
                }

                // Poll quota: min
                if combined.poll_quota != 500 {
                    return TestResult::failed("Combined poll quota should be 500 (min)");
                }

                // Cost quota: min
                if combined.cost_quota != Some(5000) {
                    return TestResult::failed("Combined cost quota should be 5000 (min)");
                }

                // Priority: max
                if combined.priority != 200 {
                    return TestResult::failed("Combined priority should be 200 (max)");
                }

                TestResult::passed()
            })
        },
    )
}

/// CB-002: INFINITE budget is identity
///
/// Spec §3.2.4: INFINITE is the identity element for meet.
pub fn cb_002_infinite_identity<RT: RuntimeInterface>() -> ConformanceTest<RT> {
    ConformanceTest::new(
        TestMeta {
            id: "cb-002".to_string(),
            name: "INFINITE is identity".to_string(),
            description: "Verify INFINITE.meet(x) == x (except priority)".to_string(),
            category: TestCategory::Time,
            tags: vec![
                "budget".to_string(),
                "infinite".to_string(),
                "identity".to_string(),
            ],
            expected: "INFINITE budget doesn't constrain other budgets".to_string(),
        },
        |rt| {
            rt.block_on(async {
                let budget = Budget::new()
                    .with_deadline(Time::from_secs(10))
                    .with_poll_quota(100)
                    .with_cost_quota(1000)
                    .with_priority(50);

                let combined = budget.meet(Budget::INFINITE);

                checkpoint(
                    "infinite_identity",
                    serde_json::json!({
                        "original_deadline": budget.deadline.map(|t| t.as_nanos()),
                        "combined_deadline": combined.deadline.map(|t| t.as_nanos()),
                        "original_poll_quota": budget.poll_quota,
                        "combined_poll_quota": combined.poll_quota,
                    }),
                );

                // Deadline preserved
                if combined.deadline != budget.deadline {
                    return TestResult::failed("INFINITE should preserve deadline");
                }

                // Poll quota preserved
                if combined.poll_quota != budget.poll_quota {
                    return TestResult::failed("INFINITE should preserve poll quota");
                }

                // Cost quota preserved
                if combined.cost_quota != budget.cost_quota {
                    return TestResult::failed("INFINITE should preserve cost quota");
                }

                // Priority uses max (INFINITE has 128, budget has 50, result is 128)
                if combined.priority != 128 {
                    return TestResult::failed("Combined priority should be max(50, 128) = 128");
                }

                TestResult::passed()
            })
        },
    )
}

/// CB-003: ZERO budget absorbs all
///
/// Spec §3.2.4: ZERO provides tightest possible constraints.
pub fn cb_003_zero_absorbs<RT: RuntimeInterface>() -> ConformanceTest<RT> {
    ConformanceTest::new(
        TestMeta {
            id: "cb-003".to_string(),
            name: "ZERO absorbs all".to_string(),
            description: "Verify x.meet(ZERO) is tightly constrained".to_string(),
            category: TestCategory::Time,
            tags: vec![
                "budget".to_string(),
                "zero".to_string(),
                "absorb".to_string(),
            ],
            expected: "ZERO provides tightest constraints".to_string(),
        },
        |rt| {
            rt.block_on(async {
                let budget = Budget::new()
                    .with_deadline(Time::from_secs(100))
                    .with_poll_quota(1000)
                    .with_cost_quota(10000)
                    .with_priority(200);

                let combined = budget.meet(Budget::ZERO);

                checkpoint(
                    "zero_absorbs",
                    serde_json::json!({
                        "combined_deadline_is_zero": combined.deadline == Some(Time::ZERO),
                        "combined_poll_quota": combined.poll_quota,
                        "combined_cost_quota": combined.cost_quota,
                        "combined_priority": combined.priority,
                    }),
                );

                // Deadline: ZERO has Time::ZERO
                if combined.deadline != Some(Time::ZERO) {
                    return TestResult::failed("Combined with ZERO should have ZERO deadline");
                }

                // Poll quota: ZERO has 0
                if combined.poll_quota != 0 {
                    return TestResult::failed("Combined with ZERO should have 0 poll quota");
                }

                // Cost quota: ZERO has Some(0)
                if combined.cost_quota != Some(0) {
                    return TestResult::failed("Combined with ZERO should have 0 cost quota");
                }

                // Priority: max(200, 0) = 200
                if combined.priority != 200 {
                    return TestResult::failed("Priority should be max(200, 0) = 200");
                }

                TestResult::passed()
            })
        },
    )
}

/// CB-004: Priority uses max (not min)
///
/// Spec §3.2.4: Priority is the only dimension using max.
pub fn cb_004_priority_uses_max<RT: RuntimeInterface>() -> ConformanceTest<RT> {
    ConformanceTest::new(
        TestMeta {
            id: "cb-004".to_string(),
            name: "Priority uses max".to_string(),
            description: "Verify priority combines via max, not min".to_string(),
            category: TestCategory::Spawn,
            tags: vec![
                "budget".to_string(),
                "priority".to_string(),
                "max".to_string(),
            ],
            expected: "Combined priority = max(a, b)".to_string(),
        },
        |rt| {
            rt.block_on(async {
                let low = Budget::new().with_priority(50);
                let high = Budget::new().with_priority(200);

                let combined1 = low.meet(high);
                let combined2 = high.meet(low);

                checkpoint(
                    "priority_max",
                    serde_json::json!({
                        "low_priority": low.priority,
                        "high_priority": high.priority,
                        "combined1_priority": combined1.priority,
                        "combined2_priority": combined2.priority,
                    }),
                );

                if combined1.priority != 200 {
                    return TestResult::failed("Priority should use max: expected 200");
                }

                // Should be commutative
                if combined2.priority != combined1.priority {
                    return TestResult::failed("Priority max should be commutative");
                }

                TestResult::passed()
            })
        },
    )
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_id_convention() {
        // Verify test IDs follow the expected pattern
        let deadline_ids = ["bd-001", "bd-002", "bd-003", "bd-004", "bd-005", "bd-006"];
        let poll_ids = ["pq-001", "pq-002", "pq-003", "pq-004", "pq-005", "pq-006"];
        let cost_ids = ["cq-001", "cq-002", "cq-003", "cq-004", "cq-005", "cq-006"];
        let combined_ids = ["cb-001", "cb-002", "cb-003", "cb-004"];

        for id in deadline_ids {
            assert!(
                id.starts_with("bd-"),
                "Deadline test ID should start with 'bd-'"
            );
        }
        for id in poll_ids {
            assert!(
                id.starts_with("pq-"),
                "Poll quota test ID should start with 'pq-'"
            );
        }
        for id in cost_ids {
            assert!(
                id.starts_with("cq-"),
                "Cost quota test ID should start with 'cq-'"
            );
        }
        for id in combined_ids {
            assert!(
                id.starts_with("cb-"),
                "Combined test ID should start with 'cb-'"
            );
        }
    }
}
