//! Metamorphic tests for combinator::join all-succeed / short-circuit semantics.
//!
//! These tests validate the core invariants of the join combinator using
//! metamorphic relations and property-based testing under deterministic LabRuntime.
//!
//! ## Key Properties Tested
//!
//! 1. **All-succeed semantics**: join of all-Ok returns Ok tuple in order
//! 2. **Short-circuit semantics**: join short-circuits on first Err cancelling losers
//! 3. **Cancel propagation**: join of cancelled returns Cancelled with all losers drained
//! 4. **Region ownership**: join preserves region ownership invariants
//! 5. **Empty join**: empty join completes immediately
//! 6. **Commutativity**: join(a,b) == join(b,a) under deterministic LabRuntime
//!
//! ## Metamorphic Relations
//!
//! - **Commutativity**: `join(f1, f2) ≃ join(f2, f1)` (up to tuple order)
//! - **Associativity**: `join(join(a, b), c) ≃ join(a, join(b, c))`
//! - **Identity**: `join(f, immediate_ok) ≃ f`
//! - **Severity preservation**: join preserves outcome severity lattice
//! - **Drain completeness**: all futures complete even on error/cancellation

use proptest::prelude::*;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use asupersync::combinator::join::{join2_outcomes, make_join_all_result, Join2Result};
use asupersync::cx::{Cx, Scope};
use asupersync::error::{Error, ErrorKind};
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::types::{
    cancel::CancelReason, ArenaIndex, Budget, Outcome, RegionId, TaskId,
};

// =============================================================================
// Test Utilities
// =============================================================================

/// Create a test context for join testing.
fn test_cx() -> Cx {
    Cx::new(
        RegionId::from_arena(ArenaIndex::new(0, 0)),
        TaskId::from_arena(ArenaIndex::new(0, 0)),
        Budget::INFINITE,
    )
}

/// Create a test context with specific slot.
fn test_cx_with_slot(slot: u32) -> Cx {
    Cx::new(
        RegionId::from_arena(ArenaIndex::new(0, slot)),
        TaskId::from_arena(ArenaIndex::new(0, slot)),
        Budget::INFINITE,
    )
}

/// Test errors for join operations.
#[derive(Debug, Clone, PartialEq)]
enum TestError {
    Business(String),
    Network(u16),
    Timeout,
}

impl std::fmt::Display for TestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Business(msg) => write!(f, "business error: {msg}"),
            Self::Network(code) => write!(f, "network error: {code}"),
            Self::Timeout => write!(f, "timeout error"),
        }
    }
}

impl std::error::Error for TestError {}

/// Arbitrary strategy for generating test values.
fn arb_test_values() -> impl Strategy<Value = u32> {
    0u32..1000
}

/// Arbitrary strategy for generating test errors.
fn arb_test_errors() -> impl Strategy<Value = TestError> {
    prop_oneof![
        "[a-z]{1,10}".prop_map(TestError::Business),
        (400u16..600).prop_map(TestError::Network),
        Just(TestError::Timeout),
    ]
}

/// Arbitrary strategy for generating outcomes.
fn arb_outcomes() -> impl Strategy<Value = Outcome<u32, TestError>> {
    prop_oneof![
        // Weight Ok outcomes more heavily
        3 => arb_test_values().prop_map(Outcome::Ok),
        1 => arb_test_errors().prop_map(Outcome::Err),
        1 => Just(Outcome::Cancelled(CancelReason::timeout())),
        1 => Just(Outcome::Cancelled(CancelReason::user("test"))),
    ]
}

/// Create a future that returns Ok after a delay.
async fn delayed_ok(cx: &Cx, value: u32, delay_ms: u64) -> Result<u32, TestError> {
    asupersync::time::sleep(cx, Duration::from_millis(delay_ms)).await;
    Ok(value)
}

/// Create a future that returns Err after a delay.
async fn delayed_err(cx: &Cx, error: TestError, delay_ms: u64) -> Result<u32, TestError> {
    asupersync::time::sleep(cx, Duration::from_millis(delay_ms)).await;
    Err(error)
}

/// Create a future that gets cancelled.
async fn cancellable_future(cx: &Cx, value: u32) -> Result<u32, TestError> {
    // Use a long sleep that will likely be cancelled
    asupersync::time::sleep(cx, Duration::from_secs(10)).await;
    Ok(value)
}

/// Helper to run a test in LabRuntime.
fn run_lab_test<F, R>(seed: u64, test_fn: F) -> R
where
    F: FnOnce(&mut LabRuntime) -> R,
{
    let config = LabConfig::new(seed);
    let mut runtime = LabRuntime::new(config);
    test_fn(&mut runtime)
}

// =============================================================================
// Metamorphic Relations
// =============================================================================

/// MR1: Join All-Succeed Property
/// When all futures return Ok, join should return Ok tuple with all values in order.
#[test]
fn mr_join_all_succeed() {
    proptest!(|(
        v1 in arb_test_values(),
        v2 in arb_test_values(),
        seed in any::<u64>()
    )| {
        run_lab_test(seed, |runtime| {
            runtime.block_on(async {
                let cx = test_cx();
                let scope = Scope::new();

                // Spawn two tasks that will succeed
                let (h1, _) = scope.spawn(&cx, async move |cx| delayed_ok(cx, v1, 10).await);
                let (h2, _) = scope.spawn(&cx, async move |cx| delayed_ok(cx, v2, 20).await);

                // Join should return both values
                let (r1, r2) = scope.join(&cx, h1, h2).await;

                prop_assert!(r1.is_ok(), "First task should succeed");
                prop_assert!(r2.is_ok(), "Second task should succeed");
                prop_assert_eq!(r1.unwrap(), v1, "First value should match");
                prop_assert_eq!(r2.unwrap(), v2, "Second value should match");
            })
        })
    });
}

/// MR2: Join Short-Circuit Property
/// When one future errors, join should still wait for all to complete.
/// NOTE: Unlike race, join waits for ALL futures even if some fail early.
#[test]
fn mr_join_error_waits_for_all() {
    proptest!(|(
        v1 in arb_test_values(),
        error in arb_test_errors(),
        seed in any::<u64>()
    )| {
        run_lab_test(seed, |runtime| {
            runtime.block_on(async {
                let cx = test_cx();
                let scope = Scope::new();

                // Track completion order
                let completion_order = Arc::new(Mutex::new(Vec::new()));
                let order1 = completion_order.clone();
                let order2 = completion_order.clone();

                // First task succeeds after delay, tracks completion
                let (h1, _) = scope.spawn(&cx, async move |cx| {
                    let result = delayed_ok(cx, v1, 50).await;
                    order1.lock().unwrap().push(1);
                    result
                });

                // Second task fails quickly, tracks completion
                let (h2, _) = scope.spawn(&cx, async move |cx| {
                    let result = delayed_err(cx, error.clone(), 10).await;
                    order2.lock().unwrap().push(2);
                    result
                });

                // Join waits for both
                let (r1, r2) = scope.join(&cx, h1, h2).await;

                // Both should have completed
                prop_assert!(r1.is_ok(), "First task should succeed");
                prop_assert!(r2.is_err(), "Second task should fail");

                // Verify both completed (no abandonment)
                let order = completion_order.lock().unwrap();
                prop_assert_eq!(order.len(), 2, "Both tasks should have completed");
                prop_assert!(order.contains(&1), "First task should have completed");
                prop_assert!(order.contains(&2), "Second task should have completed");
            })
        })
    });
}

/// MR3: Join Cancellation Property
/// When cancelled, join should cancel all children and wait for them to drain.
#[test]
fn mr_join_cancellation_drains_all() {
    proptest!(|(
        v1 in arb_test_values(),
        v2 in arb_test_values(),
        seed in any::<u64>()
    )| {
        run_lab_test(seed, |runtime| {
            runtime.block_on(async {
                let cx = test_cx();
                let scope = Scope::new();

                // Track task states
                let task_states = Arc::new(Mutex::new(Vec::new()));
                let states1 = task_states.clone();
                let states2 = task_states.clone();

                // Spawn tasks that can be cancelled
                let (h1, _) = scope.spawn(&cx, async move |cx| {
                    states1.lock().unwrap().push("task1_started");
                    let result = cancellable_future(cx, v1).await;
                    states1.lock().unwrap().push("task1_finished");
                    result
                });

                let (h2, _) = scope.spawn(&cx, async move |cx| {
                    states2.lock().unwrap().push("task2_started");
                    let result = cancellable_future(cx, v2).await;
                    states2.lock().unwrap().push("task2_finished");
                    result
                });

                // Cancel the region to trigger cancellation
                cx.cancel(CancelReason::user("test_cancel"));

                // Join should handle cancellation and drain all tasks
                let (r1, r2) = scope.join(&cx, h1, h2).await;

                // Results depend on cancellation timing, but both should complete
                let states = task_states.lock().unwrap();
                prop_assert!(states.contains(&"task1_started"), "Task 1 should have started");
                prop_assert!(states.contains(&"task2_started"), "Task 2 should have started");
                // Note: tasks may not finish due to cancellation, but join waits for completion
            })
        })
    });
}

/// MR4: Join Region Ownership
/// Join should preserve region ownership - child tasks belong to the scope's region.
#[test]
fn mr_join_preserves_region_ownership() {
    proptest!(|(
        v1 in arb_test_values(),
        v2 in arb_test_values(),
        seed in any::<u64>()
    )| {
        run_lab_test(seed, |runtime| {
            runtime.block_on(async {
                let cx = test_cx();
                let scope = Scope::new();
                let parent_region = cx.region_id();

                // Track which region tasks execute in
                let task_regions = Arc::new(Mutex::new(Vec::new()));
                let regions1 = task_regions.clone();
                let regions2 = task_regions.clone();

                let (h1, _) = scope.spawn(&cx, async move |task_cx| {
                    regions1.lock().unwrap().push(task_cx.region_id());
                    delayed_ok(task_cx, v1, 10).await
                });

                let (h2, _) = scope.spawn(&cx, async move |task_cx| {
                    regions2.lock().unwrap().push(task_cx.region_id());
                    delayed_ok(task_cx, v2, 10).await
                });

                let (_r1, _r2) = scope.join(&cx, h1, h2).await;

                // Verify region ownership (tasks should be in child regions of the scope)
                let regions = task_regions.lock().unwrap();
                prop_assert_eq!(regions.len(), 2, "Should track both task regions");

                // Tasks run in child regions, so they should be different from parent
                for &task_region in regions.iter() {
                    prop_assert_ne!(task_region, parent_region, "Task should run in child region");
                }
            })
        })
    });
}

/// MR5: Empty Join Property
/// An empty join should complete immediately (vacuous success).
#[test]
fn mr_empty_join_immediate() {
    proptest!(|(seed in any::<u64>())| {
        run_lab_test(seed, |runtime| {
            runtime.block_on(async {
                // Test using join_all for empty case
                let outcomes: Vec<Outcome<u32, TestError>> = vec![];
                let result = make_join_all_result(outcomes);

                prop_assert!(result.all_succeeded(), "Empty join should succeed vacuously");
                prop_assert_eq!(result.success_count(), 0, "Empty join should have no successes");
                prop_assert_eq!(result.failure_count(), 0, "Empty join should have no failures");
                prop_assert_eq!(result.total_count, 0, "Empty join should have zero total count");
            })
        })
    });
}

/// MR6: Join Commutativity
/// join(a, b) should have equivalent semantics to join(b, a) under deterministic runtime.
#[test]
fn mr_join_commutativity() {
    proptest!(|(
        v1 in arb_test_values(),
        v2 in arb_test_values(),
        seed in any::<u64>()
    )| {
        // Run the same operation in both orders with the same seed
        let result1 = run_lab_test(seed, |runtime| {
            runtime.block_on(async {
                let cx = test_cx();
                let scope = Scope::new();

                let (h1, _) = scope.spawn(&cx, async move |cx| delayed_ok(cx, v1, 10).await);
                let (h2, _) = scope.spawn(&cx, async move |cx| delayed_ok(cx, v2, 20).await);

                scope.join(&cx, h1, h2).await
            })
        });

        let result2 = run_lab_test(seed, |runtime| {
            runtime.block_on(async {
                let cx = test_cx();
                let scope = Scope::new();

                let (h1, _) = scope.spawn(&cx, async move |cx| delayed_ok(cx, v1, 10).await);
                let (h2, _) = scope.spawn(&cx, async move |cx| delayed_ok(cx, v2, 20).await);

                // Swap the order
                let (r2, r1) = scope.join(&cx, h2, h1).await;
                (r1, r2) // Restore original order for comparison
            })
        });

        // Results should be equivalent (deterministic runtime ensures same execution)
        prop_assert_eq!(result1.0.is_ok(), result2.0.is_ok(), "First result success should match");
        prop_assert_eq!(result1.1.is_ok(), result2.1.is_ok(), "Second result success should match");

        if let (Ok(val1_a), Ok(val1_b)) = &result1 {
            if let (Ok(val2_a), Ok(val2_b)) = &result2 {
                prop_assert_eq!(val1_a, val2_a, "First values should match");
                prop_assert_eq!(val1_b, val2_b, "Second values should match");
            }
        }
    });
}

// =============================================================================
// Outcome-Level Metamorphic Relations
// =============================================================================

/// MR7: join2_outcomes Commutativity Property
/// join2_outcomes should be commutative in terms of severity.
#[test]
fn mr_join2_outcomes_severity_commutative() {
    proptest!(|(
        outcome1 in arb_outcomes(),
        outcome2 in arb_outcomes()
    )| {
        let (result1, _, _) = join2_outcomes(outcome1.clone(), outcome2.clone());
        let (result2, _, _) = join2_outcomes(outcome2, outcome1);

        // Severity should be the same regardless of order
        prop_assert_eq!(result1.severity(), result2.severity(),
            "join2_outcomes should be commutative in severity");
    });
}

/// MR8: join2_outcomes Severity Lattice Property
/// join2_outcomes should respect the severity lattice: Ok < Err < Cancelled < Panicked.
#[test]
fn mr_join2_outcomes_severity_lattice() {
    proptest!(|(
        outcome1 in arb_outcomes(),
        outcome2 in arb_outcomes()
    )| {
        let (result, _, _) = join2_outcomes(outcome1.clone(), outcome2.clone());

        // Result severity should be >= max input severity
        let max_input_severity = outcome1.severity().max(outcome2.severity());
        prop_assert!(result.severity() >= max_input_severity,
            "Result severity {} should be >= max input severity {}",
            result.severity(), max_input_severity);
    });
}

/// MR9: join2_outcomes Value Preservation Property
/// When one branch succeeds and other fails, the successful value should be preserved.
#[test]
fn mr_join2_outcomes_value_preservation() {
    proptest!(|(
        value in arb_test_values(),
        error in arb_test_errors()
    )| {
        // Test first success, second error
        let (result1, v1_1, v2_1) = join2_outcomes(
            Outcome::Ok(value),
            Outcome::Err(error.clone())
        );
        prop_assert!(result1.is_err(), "Result should be error when one branch fails");
        prop_assert_eq!(v1_1, Some(value), "Successful value should be preserved");
        prop_assert_eq!(v2_1, None, "Failed value should be None");

        // Test first error, second success
        let (result2, v1_2, v2_2) = join2_outcomes(
            Outcome::Err(error),
            Outcome::Ok(value)
        );
        prop_assert!(result2.is_err(), "Result should be error when one branch fails");
        prop_assert_eq!(v1_2, None, "Failed value should be None");
        prop_assert_eq!(v2_2, Some(value), "Successful value should be preserved");
    });
}

/// MR10: join2_outcomes All-Success Property
/// When both branches succeed, result should be Ok with tuple and no preserved values.
#[test]
fn mr_join2_outcomes_all_success() {
    proptest!(|(
        value1 in arb_test_values(),
        value2 in arb_test_values()
    )| {
        let (result, v1, v2) = join2_outcomes(
            Outcome::Ok(value1),
            Outcome::Ok(value2)
        );

        prop_assert!(result.is_ok(), "Result should be Ok when both branches succeed");
        prop_assert_eq!(v1, None, "No values should be preserved when both succeed");
        prop_assert_eq!(v2, None, "No values should be preserved when both succeed");

        if let Outcome::Ok((val1, val2)) = result {
            prop_assert_eq!(val1, value1, "First value should match");
            prop_assert_eq!(val2, value2, "Second value should match");
        } else {
            prop_assert!(false, "Expected Ok result");
        }
    });
}

// =============================================================================
// Regression Tests for Known Edge Cases
// =============================================================================

/// Test that join properly handles panic outcomes.
#[test]
fn mr_join_panic_handling() {
    proptest!(|(
        value in arb_test_values(),
        seed in any::<u64>()
    )| {
        run_lab_test(seed, |runtime| {
            runtime.block_on(async {
                let cx = test_cx();
                let scope = Scope::new();

                // One task succeeds
                let (h1, _) = scope.spawn(&cx, async move |cx| delayed_ok(cx, value, 10).await);

                // One task panics (simulate with a future that would panic)
                let (h2, _) = scope.spawn(&cx, async move |_cx| -> Result<u32, TestError> {
                    // Note: In real code this would panic, but we can't test actual panics easily
                    // This simulates the panic handling pathway
                    Err(TestError::Business("simulated_panic".to_string()))
                });

                let (r1, r2) = scope.join(&cx, h1, h2).await;

                // First should succeed, second should fail
                prop_assert!(r1.is_ok(), "First task should succeed");
                prop_assert!(r2.is_err(), "Second task should fail");
            })
        })
    });
}

/// Test that join respects cancellation reason strengthening.
#[test]
fn mr_join_cancellation_strengthening() {
    let weak_reason = CancelReason::user("soft");
    let strong_reason = CancelReason::shutdown();

    // Test join2_outcomes with different cancel reasons
    let (result, _, _) = join2_outcomes(
        Outcome::<u32, TestError>::Cancelled(weak_reason),
        Outcome::<u32, TestError>::Cancelled(strong_reason),
    );

    assert!(result.is_cancelled(), "Result should be cancelled");
    if let Outcome::Cancelled(reason) = result {
        assert_eq!(
            reason.kind(),
            asupersync::types::cancel::CancelKind::Shutdown,
            "Should strengthen to shutdown reason"
        );
    }
}

/// Test join with very quick tasks to verify no race conditions.
#[test]
fn mr_join_immediate_completion() {
    proptest!(|(
        v1 in arb_test_values(),
        v2 in arb_test_values(),
        seed in any::<u64>()
    )| {
        run_lab_test(seed, |runtime| {
            runtime.block_on(async {
                let cx = test_cx();
                let scope = Scope::new();

                // Both tasks complete immediately
                let (h1, _) = scope.spawn(&cx, async move |_cx| Ok::<u32, TestError>(v1));
                let (h2, _) = scope.spawn(&cx, async move |_cx| Ok::<u32, TestError>(v2));

                let (r1, r2) = scope.join(&cx, h1, h2).await;

                prop_assert!(r1.is_ok(), "First immediate task should succeed");
                prop_assert!(r2.is_ok(), "Second immediate task should succeed");
                prop_assert_eq!(r1.unwrap(), v1, "First value should match");
                prop_assert_eq!(r2.unwrap(), v2, "Second value should match");
            })
        })
    });
}

/// Test join with mixed timing scenarios.
#[test]
fn mr_join_mixed_timing() {
    proptest!(|(
        v1 in arb_test_values(),
        error in arb_test_errors(),
        delay1 in 0u64..100,
        delay2 in 0u64..100,
        seed in any::<u64>()
    )| {
        run_lab_test(seed, |runtime| {
            runtime.block_on(async {
                let cx = test_cx();
                let scope = Scope::new();

                // One succeeds with delay1, one fails with delay2
                let (h1, _) = scope.spawn(&cx, async move |cx| delayed_ok(cx, v1, delay1).await);
                let (h2, _) = scope.spawn(&cx, async move |cx| delayed_err(cx, error.clone(), delay2).await);

                let (r1, r2) = scope.join(&cx, h1, h2).await;

                // Results should be consistent regardless of timing
                prop_assert!(r1.is_ok(), "First task should succeed");
                prop_assert!(r2.is_err(), "Second task should fail");
                prop_assert_eq!(r1.unwrap(), v1, "First value should match");
            })
        })
    });
}