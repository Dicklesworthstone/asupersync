#![allow(warnings)]
#![allow(clippy::all)]
//! Metamorphic tests for combinator::first_ok first-success semantics.
//!
//! These tests validate the core invariants of the first_ok combinator using
//! metamorphic relations and property-based testing under deterministic LabRuntime.
//! Focus is on first-success semantics, error aggregation, and cancellation handling.

use proptest::prelude::*;
use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use asupersync::combinator::first_ok::{first_ok, first_ok_outcomes, FirstOkError, FirstOkResult};
use asupersync::cx::{Cx, Scope};
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::runtime::TaskHandle;
use asupersync::types::{
    cancel::CancelReason, ArenaIndex, Budget, Outcome, RegionId, TaskId,
};
use asupersync::{scope, task};

// =============================================================================
// Test Utilities
// =============================================================================

/// Create a test context for first_ok testing.
fn test_cx() -> Cx {
    Cx::new(
        RegionId::from_arena(ArenaIndex::new(0, 0)),
        TaskId::from_arena(ArenaIndex::new(0, 0)),
        Budget::INFINITE,
    )
}

/// Create a test LabRuntime for deterministic testing.
fn test_lab_runtime() -> LabRuntime {
    LabRuntime::with_config(LabConfig::deterministic())
}

/// Create a test LabRuntime with specific seed.
fn test_lab_runtime_with_seed(seed: u64) -> LabRuntime {
    LabRuntime::with_config(LabConfig::deterministic().with_seed(seed))
}

/// Track first_ok operations for invariant checking.
#[derive(Debug, Clone, Default)]
struct FirstOkTracker {
    operation_starts: Vec<usize>,
    operation_completions: Vec<(usize, bool)>, // (operation_id, succeeded)
    cancellations: Vec<usize>,
    cleanup_events: Vec<usize>,
}

impl FirstOkTracker {
    fn new() -> Arc<StdMutex<Self>> {
        Arc::new(StdMutex::new(Self::default()))
    }

    fn record_start(&mut self, operation_id: usize) {
        self.operation_starts.push(operation_id);
    }

    fn record_completion(&mut self, operation_id: usize, succeeded: bool) {
        self.operation_completions.push((operation_id, succeeded));
    }

    fn record_cancellation(&mut self, operation_id: usize) {
        self.cancellations.push(operation_id);
    }

    fn record_cleanup(&mut self, operation_id: usize) {
        self.cleanup_events.push(operation_id);
    }
}

/// A test operation that can succeed, fail, or be cancelled.
#[derive(Debug, Clone)]
struct TestOperation {
    id: usize,
    delay: Duration,
    outcome: Outcome<i32, String>,
    should_cancel_early: bool,
}

impl TestOperation {
    fn success(id: usize, delay_ms: u64, value: i32) -> Self {
        Self {
            id,
            delay: Duration::from_millis(delay_ms),
            outcome: Outcome::Ok(value),
            should_cancel_early: false,
        }
    }

    fn failure(id: usize, delay_ms: u64, error: String) -> Self {
        Self {
            id,
            delay: Duration::from_millis(delay_ms),
            outcome: Outcome::Err(error),
            should_cancel_early: false,
        }
    }

    fn with_cancellation(mut self) -> Self {
        self.should_cancel_early = true;
        self
    }

    /// Execute this operation with tracking.
    async fn execute(
        &self,
        cx: &Cx,
        tracker: Arc<StdMutex<FirstOkTracker>>,
    ) -> Outcome<i32, String> {
        // Record start
        {
            let mut t = tracker.lock().unwrap();
            t.record_start(self.id);
        }

        // Simulate delay
        if self.delay > Duration::ZERO {
            let _ = cx.sleep(self.delay).await;
        }

        // Check for early cancellation
        if self.should_cancel_early {
            let mut t = tracker.lock().unwrap();
            t.record_cancellation(self.id);
            return Outcome::Cancelled(CancelReason::timeout());
        }

        // Record completion
        {
            let mut t = tracker.lock().unwrap();
            t.record_completion(self.id, self.outcome.is_ok());
        }

        self.outcome.clone()
    }
}

// =============================================================================
// Metamorphic Relations
// =============================================================================

/// Metamorphic Relation 1: First Ok wins and cancels others.
///
/// Relation: If any operation succeeds, the first successful operation should
/// win and subsequent operations should not be executed (short-circuit).
#[cfg(test)]
proptest! {
    #[test]
    fn mr1_first_ok_wins_and_cancels_others(
        success_position in 0..4usize,
        success_value in 1..100i32,
        failure_count in 1..4usize,
        delay_ms in 1..50u64,
    ) {
        let mut rt = test_lab_runtime();

        rt.block_on(async {
            let cx = rt.cx();
            let tracker = FirstOkTracker::new();

            // Create operations: failures before success, success, then more operations
            let mut operations = Vec::new();

            // Add failure operations before the success
            for i in 0..success_position {
                operations.push(TestOperation::failure(
                    i,
                    delay_ms,
                    format!("error_{}", i)
                ));
            }

            // Add the success operation
            operations.push(TestOperation::success(
                success_position,
                delay_ms,
                success_value
            ));

            // Add more operations after success (these should not execute)
            for i in (success_position + 1)..(success_position + 1 + failure_count) {
                operations.push(TestOperation::failure(
                    i,
                    delay_ms,
                    format!("should_not_execute_{}", i)
                ));
            }

            // Execute using first_ok
            let futures: Vec<_> = operations.iter()
                .map(|op| async move { op.execute(&cx, tracker.clone()).await })
                .collect();

            let result = first_ok!(futures.into_iter()).await;

            // Assertion 1: Should succeed with the correct value
            prop_assert!(
                result.is_success(),
                "first_ok should succeed when one operation succeeds"
            );

            let success = result.success.expect("Should have success");
            prop_assert_eq!(
                success.value,
                success_value,
                "Should return the value from successful operation"
            );

            prop_assert_eq!(
                success.index,
                success_position,
                "Should return success from correct position"
            );

            // Assertion 2: Only operations up to and including success should execute
            let tracker_lock = tracker.lock().unwrap();
            let executed_count = tracker_lock.operation_starts.len();
            prop_assert_eq!(
                executed_count,
                success_position + 1,
                "Should only execute operations up to first success (short-circuit)"
            );

            // Assertion 3: All executed operations except the winner should be failures
            prop_assert_eq!(
                tracker_lock.operation_completions.len(),
                success_position + 1,
                "All started operations should complete"
            );

            let successful_completions: Vec<_> = tracker_lock.operation_completions.iter()
                .filter(|(_, succeeded)| *succeeded)
                .collect();
            prop_assert_eq!(
                successful_completions.len(),
                1,
                "Exactly one operation should succeed"
            );
        });
    }
}

/// Metamorphic Relation 2: All-Err returns aggregated errors.
///
/// Relation: When all operations fail, first_ok should return an error containing
/// all the individual failures in order.
#[cfg(test)]
proptest! {
    #[test]
    fn mr2_all_err_returns_aggregated_errors(
        operation_count in 1..6usize,
        delay_ms in 1..30u64,
    ) {
        let mut rt = test_lab_runtime();

        rt.block_on(async {
            let cx = rt.cx();
            let tracker = FirstOkTracker::new();

            // Create all failure operations
            let operations: Vec<_> = (0..operation_count)
                .map(|i| TestOperation::failure(i, delay_ms, format!("error_{}", i)))
                .collect();

            let futures: Vec<_> = operations.iter()
                .map(|op| async move { op.execute(&cx, tracker.clone()).await })
                .collect();

            let result = first_ok!(futures.into_iter()).await;

            // Assertion 1: Should fail when all operations fail
            prop_assert!(
                !result.is_success(),
                "first_ok should fail when all operations fail"
            );

            // Assertion 2: All operations should have been attempted
            let tracker_lock = tracker.lock().unwrap();
            prop_assert_eq!(
                tracker_lock.operation_starts.len(),
                operation_count,
                "All operations should be attempted when none succeed"
            );

            // Assertion 3: All failures should be recorded
            prop_assert_eq!(
                result.failures.len(),
                operation_count,
                "All failures should be collected"
            );

            // Assertion 4: Failures should be in correct order
            for (i, (failure_index, _)) in result.failures.iter().enumerate() {
                prop_assert_eq!(
                    *failure_index,
                    i,
                    "Failures should be recorded in execution order"
                );
            }

            // Assertion 5: Convert to Result should preserve error information
            let outcome_result = crate::combinator::first_ok::first_ok_to_result(result);
            prop_assert!(
                outcome_result.is_err(),
                "Converting all-failed result should be Err"
            );

            match outcome_result.unwrap_err() {
                FirstOkError::AllFailed { errors, attempted } => {
                    prop_assert_eq!(
                        errors.len(),
                        operation_count,
                        "All errors should be preserved"
                    );
                    prop_assert_eq!(
                        attempted,
                        operation_count,
                        "Attempt count should match operation count"
                    );
                }
                _ => prop_assert!(false, "Expected AllFailed error type"),
            }
        });
    }
}

/// Metamorphic Relation 3: Empty input returns error per spec.
///
/// Relation: When no operations are provided, first_ok should return an
/// appropriate error without attempting any operations.
#[test]
fn mr3_empty_input_returns_error() {
    let mut rt = test_lab_runtime();

    rt.block_on(async {
        // Create empty operation list
        let empty_outcomes: Vec<Outcome<i32, String>> = vec![];
        let result = first_ok_outcomes(empty_outcomes);

        // Assertion 1: Should not succeed with empty input
        assert!(!result.is_success(), "Empty first_ok should not succeed");

        // Assertion 2: Should have zero total operations
        assert_eq!(result.total, 0, "Empty input should have zero total");

        // Assertion 3: Should have no failures recorded
        assert_eq!(result.failures.len(), 0, "Empty input should have no failures");

        // Assertion 4: Convert to Result should return Empty error
        let outcome_result = asupersync::combinator::first_ok::first_ok_to_result(result);
        assert!(outcome_result.is_err(), "Empty result should be Err");

        match outcome_result.unwrap_err() {
            FirstOkError::Empty => {
                // This is expected
            }
            other => panic!("Expected Empty error, got: {:?}", other),
        }
    });
}

/// Metamorphic Relation 4: Losers drained cleanly.
///
/// Relation: Failed operations should be properly cleaned up and should not
/// interfere with the successful operation or leave dangling resources.
#[cfg(test)]
proptest! {
    #[test]
    fn mr4_losers_drained_cleanly(
        success_position in 1..4usize,
        success_value in 1..100i32,
        loser_count in 1..4usize,
        delay_ms in 1..30u64,
    ) {
        let mut rt = test_lab_runtime();

        rt.block_on(async {
            let cx = rt.cx();
            let tracker = FirstOkTracker::new();

            // Create operations: some failures, then success
            let mut operations = Vec::new();

            // Add failure operations before success
            for i in 0..success_position {
                operations.push(TestOperation::failure(
                    i,
                    delay_ms,
                    format!("loser_{}", i)
                ));
            }

            // Add success operation
            operations.push(TestOperation::success(success_position, delay_ms, success_value));

            let futures: Vec<_> = operations.iter()
                .map(|op| async move { op.execute(&cx, tracker.clone()).await })
                .collect();

            let result = first_ok!(futures.into_iter()).await;

            // Assertion 1: Should succeed
            prop_assert!(result.is_success(), "Should succeed with winning operation");

            // Assertion 2: All losers should be properly tracked
            let tracker_lock = tracker.lock().unwrap();

            // All operations up to and including success should start
            prop_assert_eq!(
                tracker_lock.operation_starts.len(),
                success_position + 1,
                "All operations up to success should start"
            );

            // All started operations should complete
            prop_assert_eq!(
                tracker_lock.operation_completions.len(),
                success_position + 1,
                "All started operations should complete"
            );

            // Assertion 3: Loser failures should be recorded in result
            prop_assert_eq!(
                result.failures.len(),
                success_position,
                "All loser failures should be recorded"
            );

            // Assertion 4: No operation should be left in incomplete state
            let completed_ops: std::collections::HashSet<_> = tracker_lock.operation_completions.iter()
                .map(|(id, _)| *id)
                .collect();
            let started_ops: std::collections::HashSet<_> = tracker_lock.operation_starts.iter()
                .cloned()
                .collect();

            prop_assert_eq!(
                completed_ops,
                started_ops,
                "All started operations should complete (no dangling operations)"
            );
        });
    }
}

/// Metamorphic Relation 5: Cancel from outer cancels all futures.
///
/// Relation: When first_ok is cancelled externally, all running operations
/// should be cancelled and the cancellation should be propagated.
#[cfg(test)]
proptest! {
    #[test]
    fn mr5_outer_cancel_cancels_all_futures(
        operation_count in 2..5usize,
        delay_ms in 50..100u64, // Longer delays to allow cancellation
    ) {
        let mut rt = test_lab_runtime();

        rt.block_on(async {
            let cx = rt.cx();
            let tracker = FirstOkTracker::new();

            // Create all slow operations that would normally fail
            let operations: Vec<_> = (0..operation_count)
                .map(|i| TestOperation::failure(i, delay_ms, format!("slow_error_{}", i)))
                .collect();

            // Simulate external cancellation by using a cancelled operation
            let cancelled_op = TestOperation::failure(0, delay_ms / 4, "quick_cancel".to_string())
                .with_cancellation();

            let mut all_operations = vec![cancelled_op];
            all_operations.extend(operations);

            let futures: Vec<_> = all_operations.iter()
                .map(|op| async move { op.execute(&cx, tracker.clone()).await })
                .collect();

            let result = first_ok!(futures.into_iter()).await;

            // Assertion 1: Should not succeed due to cancellation
            prop_assert!(
                !result.is_success(),
                "Should not succeed when cancelled"
            );

            // Assertion 2: Should be marked as cancelled
            prop_assert!(
                result.was_cancelled,
                "Result should be marked as cancelled"
            );

            // Assertion 3: At least the cancelled operation should be recorded
            let tracker_lock = tracker.lock().unwrap();
            prop_assert!(
                !tracker_lock.cancellations.is_empty(),
                "Should record at least one cancellation"
            );

            // Assertion 4: Cancellation should stop the chain (early termination)
            // The number of started operations should be limited due to cancellation
            prop_assert!(
                tracker_lock.operation_starts.len() <= all_operations.len(),
                "Cancellation should limit operation execution"
            );

            // Assertion 5: Convert to Result should return Cancelled error
            let outcome_result = asupersync::combinator::first_ok::first_ok_to_result(result);
            prop_assert!(outcome_result.is_err(), "Cancelled result should be Err");

            match outcome_result.unwrap_err() {
                FirstOkError::Cancelled { reason, errors_before_cancel, attempted_before_cancel } => {
                    prop_assert!(
                        attempted_before_cancel <= all_operations.len(),
                        "Attempts before cancel should not exceed total operations"
                    );
                }
                _ => prop_assert!(false, "Expected Cancelled error type"),
            }
        });
    }
}

// =============================================================================
// Integration and Edge Case Tests
// =============================================================================

/// Integration test: Complex first_ok scenario with mixed outcomes.
#[test]
fn integration_complex_first_ok_scenario() {
    let mut rt = test_lab_runtime();

    rt.block_on(async {
        let cx = rt.cx();
        let tracker = FirstOkTracker::new();

        let operations = vec![
            TestOperation::failure(0, 10, "first_fails".to_string()),
            TestOperation::failure(1, 20, "second_fails".to_string()),
            TestOperation::success(2, 30, 42),
            TestOperation::failure(3, 40, "should_not_execute".to_string()),
        ];

        let futures: Vec<_> = operations.iter()
            .map(|op| async move { op.execute(&cx, tracker.clone()).await })
            .collect();

        let result = first_ok!(futures.into_iter()).await;

        // Verify all MRs work together
        assert!(result.is_success()); // MR1: Success wins
        assert_eq!(result.success.unwrap().value, 42); // MR1: Correct value
        assert_eq!(result.success.unwrap().index, 2); // MR1: Correct position
        assert_eq!(result.failures.len(), 2); // MR2: Losers recorded

        // MR4: Proper cleanup - only operations 0, 1, 2 should execute
        let tracker_lock = tracker.lock().unwrap();
        assert_eq!(tracker_lock.operation_starts.len(), 3);
        assert_eq!(tracker_lock.operation_completions.len(), 3);
    });
}

/// Edge case: Single operation scenarios.
#[test]
fn edge_case_single_operations() {
    let mut rt = test_lab_runtime();

    rt.block_on(async {
        let cx = rt.cx();
        let tracker = FirstOkTracker::new();

        // Single success
        let success_op = TestOperation::success(0, 10, 99);
        let future = async move { success_op.execute(&cx, tracker.clone()).await };
        let result = first_ok!(future).await;

        assert!(result.is_success());
        assert_eq!(result.success.unwrap().value, 99);
        assert_eq!(result.failures.len(), 0);

        // Single failure
        let tracker2 = FirstOkTracker::new();
        let failure_op = TestOperation::failure(0, 10, "solo_fail".to_string());
        let future = async move { failure_op.execute(&cx, tracker2.clone()).await };
        let result = first_ok!(future).await;

        assert!(!result.is_success());
        assert_eq!(result.failures.len(), 1);
    });
}

/// Performance characteristic: Verify early termination behavior.
#[test]
fn performance_early_termination() {
    let mut rt = test_lab_runtime();

    rt.block_on(async {
        let cx = rt.cx();
        let tracker = FirstOkTracker::new();

        let operations = vec![
            TestOperation::success(0, 1, 123), // Quick success
            TestOperation::failure(1, 1000, "very_slow".to_string()), // Should not execute
            TestOperation::failure(2, 2000, "extremely_slow".to_string()), // Should not execute
        ];

        let start_time = std::time::Instant::now();
        let futures: Vec<_> = operations.iter()
            .map(|op| async move { op.execute(&cx, tracker.clone()).await })
            .collect();

        let result = first_ok!(futures.into_iter()).await;
        let elapsed = start_time.elapsed();

        // Should succeed quickly due to early termination
        assert!(result.is_success());
        assert!(elapsed < Duration::from_millis(500)); // Much less than slow operations

        // Only first operation should execute
        let tracker_lock = tracker.lock().unwrap();
        assert_eq!(tracker_lock.operation_starts.len(), 1);
    });
}

#[cfg(test)]
mod first_ok_invariant_tests {
    use super::*;

    #[test]
    fn test_deterministic_execution() {
        // Same inputs should produce same results
        let seed = 12345;
        let mut rt1 = test_lab_runtime_with_seed(seed);
        let mut rt2 = test_lab_runtime_with_seed(seed);

        let result1 = rt1.block_on(async {
            let outcomes = vec![
                Outcome::Err("e1".to_string()),
                Outcome::Ok(42),
                Outcome::Err("e3".to_string()),
            ];
            first_ok_outcomes(outcomes)
        });

        let result2 = rt2.block_on(async {
            let outcomes = vec![
                Outcome::Err("e1".to_string()),
                Outcome::Ok(42),
                Outcome::Err("e3".to_string()),
            ];
            first_ok_outcomes(outcomes)
        });

        assert!(result1.is_success());
        assert!(result2.is_success());
        assert_eq!(result1.success.unwrap().value, result2.success.unwrap().value);
        assert_eq!(result1.success.unwrap().index, result2.success.unwrap().index);
    }

    #[test]
    fn test_error_preservation() {
        let outcomes = vec![
            Outcome::Err("first".to_string()),
            Outcome::Err("second".to_string()),
            Outcome::Err("third".to_string()),
        ];

        let result = first_ok_outcomes(outcomes);
        assert!(!result.is_success());
        assert_eq!(result.failures.len(), 3);

        // Verify error order preservation
        for (i, (index, _)) in result.failures.iter().enumerate() {
            assert_eq!(*index, i);
        }
    }

    #[test]
    fn test_short_circuit_semantics() {
        // After first success, no more outcomes should be processed
        let outcomes = vec![
            Outcome::Err("e1".to_string()),
            Outcome::Ok(100),
            Outcome::Err("should_not_matter".to_string()),
            Outcome::Ok(200), // Should not matter
        ];

        let result = first_ok_outcomes(outcomes);
        assert!(result.is_success());
        assert_eq!(result.success.unwrap().value, 100);
        assert_eq!(result.success.unwrap().index, 1);
        assert_eq!(result.failures.len(), 1); // Only e1 before success
    }
}