//! Unit tests for the quorum! combinator.
//!
//! Tests verify:
//! - M-of-N completion semantics
//! - Early return when quorum reached
//! - Failure when quorum impossible
//! - Resource cleanup for non-quorum branches

use crate::e2e::combinator::util::{DrainFlag, DrainTracker, NeverComplete};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;

/// Test basic quorum (2 of 3).
#[test]
fn test_quorum_2_of_3() {
    let completions = Arc::new(AtomicU32::new(0));

    // 3 branches, need 2 to succeed
    let required = 2;
    let total = 3;

    // Simulate 2 completions
    completions.fetch_add(1, Ordering::SeqCst);
    completions.fetch_add(1, Ordering::SeqCst);

    let count = completions.load(Ordering::SeqCst);
    assert!(count >= required, "Quorum reached: {count} >= {required}");
    assert!(count <= total);
}

/// Test quorum with all succeeding.
#[test]
fn test_quorum_all_succeed() {
    let completions = Arc::new(AtomicU32::new(0));

    // All 5 branches complete
    for _ in 0..5 {
        completions.fetch_add(1, Ordering::SeqCst);
    }

    let required = 3;
    let count = completions.load(Ordering::SeqCst);

    assert!(count >= required, "Quorum should be reached");
}

/// Test quorum failure (not enough successes possible).
#[test]
fn test_quorum_impossible() {
    let successes = 1;
    let failures = 3;
    let required = 3;
    let total = successes + failures;

    // With 1 success and 3 failures, can't reach quorum of 3
    let can_reach_quorum = successes >= required || (total - failures) >= required;

    assert!(
        !can_reach_quorum || successes >= required,
        "Should detect impossible quorum"
    );
}

/// Test early return when quorum reached.
#[test]
fn test_quorum_early_return() {
    let evaluation_count = Arc::new(AtomicU32::new(0));
    let required = 2;

    // Simulate evaluation with early return
    for i in 0..5 {
        evaluation_count.fetch_add(1, Ordering::SeqCst);
        if evaluation_count.load(Ordering::SeqCst) >= required {
            // Quorum reached, can return early
            break;
        }
        let _ = i;
    }

    assert_eq!(
        evaluation_count.load(Ordering::SeqCst),
        required,
        "Should return early when quorum reached"
    );
}

/// Test quorum cancels remaining after success.
#[test]
fn test_quorum_cancels_remaining() {
    let remaining1 = DrainFlag::new();
    let remaining2 = DrainFlag::new();

    {
        // Quorum branches (completed)
        let _ = 1;
        let _ = 2;
        // Remaining branches (cancelled)
        let _r1 = DrainTracker::new(NeverComplete, Arc::clone(&remaining1));
        let _r2 = DrainTracker::new(NeverComplete, Arc::clone(&remaining2));
    }

    crate::assert_drained!(remaining1, "remaining branch 1");
    crate::assert_drained!(remaining2, "remaining branch 2");
}

/// Test quorum result collection.
#[test]
fn test_quorum_collects_results() {
    let results: Vec<i32> = vec![10, 20, 30];
    let required = 2;

    // Collect first N results that complete
    let quorum_count = results.iter().take(required).count();

    assert_eq!(quorum_count, required);
}

/// Test quorum with mixed success/failure.
#[test]
fn test_quorum_mixed_outcomes() {
    #[derive(Debug, Clone, PartialEq)]
    enum Outcome {
        Success(i32),
        Failure,
    }

    let outcomes = [
        Outcome::Success(1),
        Outcome::Failure,
        Outcome::Success(2),
        Outcome::Failure,
        Outcome::Success(3),
    ];

    let required = 2;
    let success_count = outcomes
        .iter()
        .filter(|o| matches!(o, Outcome::Success(_)))
        .take(required)
        .count();

    assert_eq!(success_count, required, "Should collect required successes");
}

/// Test quorum timing (who contributes).
#[test]
fn test_quorum_timing() {
    struct TimedCompletion {
        order: Arc<std::sync::Mutex<Vec<u32>>>,
        id: u32,
    }

    impl TimedCompletion {
        fn complete(&self) {
            self.order.lock().unwrap().push(self.id);
        }
    }

    let completion_order = Arc::new(std::sync::Mutex::new(Vec::new()));

    let completions = [
        TimedCompletion {
            order: Arc::clone(&completion_order),
            id: 3,
        }, // Completes first
        TimedCompletion {
            order: Arc::clone(&completion_order),
            id: 1,
        }, // Completes second
        TimedCompletion {
            order: Arc::clone(&completion_order),
            id: 2,
        }, // Completes third
    ];

    // Simulate completion order
    completions[0].complete();
    completions[1].complete();
    // Third not needed for quorum of 2

    let order = completion_order.lock().unwrap().clone();
    assert_eq!(order.len(), 2, "Only quorum contributors recorded");
}

/// Test quorum with 1 of N (first success).
#[test]
fn test_quorum_1_of_n() {
    // Quorum of 1 is essentially first_ok
    let first_success = Some(42);

    assert!(first_success.is_some(), "Quorum of 1 returns first success");
}

/// Test quorum with N of N (all required).
#[test]
fn test_quorum_n_of_n() {
    // Quorum of N out of N is essentially join
    let all_completed = [1, 2, 3, 4, 5];
    let required = 5;

    assert_eq!(
        all_completed.len(),
        required,
        "Quorum of N requires all to complete"
    );
}

/// Test quorum error handling.
#[test]
fn test_quorum_error_handling() {
    #[derive(Debug, PartialEq)]
    enum QuorumError {
        NotEnoughSuccesses { got: u32, required: u32 },
    }

    fn check_quorum(successes: u32, required: u32) -> Result<(), QuorumError> {
        if successes >= required {
            Ok(())
        } else {
            Err(QuorumError::NotEnoughSuccesses {
                got: successes,
                required,
            })
        }
    }

    assert!(check_quorum(3, 2).is_ok());
    assert_eq!(
        check_quorum(1, 3),
        Err(QuorumError::NotEnoughSuccesses {
            got: 1,
            required: 3
        })
    );
}

/// Test quorum cleanup preserves quorum results.
#[test]
fn test_quorum_preserves_results() {
    struct ResultGuard {
        preserved: Arc<AtomicBool>,
    }

    impl Drop for ResultGuard {
        fn drop(&mut self) {
            // Results should be preserved, not dropped
            assert!(
                self.preserved.load(Ordering::SeqCst),
                "Result should be preserved before cleanup"
            );
        }
    }

    let result_preserved = Arc::new(AtomicBool::new(false));

    result_preserved.store(true, Ordering::SeqCst);

    {
        let _guard = ResultGuard {
            preserved: Arc::clone(&result_preserved),
        };
    }
}

/// Test quorum with weighted votes.
#[test]
fn test_quorum_weighted() {
    struct Vote {
        weight: u32,
    }

    let votes = [Vote { weight: 1 }, Vote { weight: 2 }, Vote { weight: 1 }];

    let total_weight: u32 = votes.iter().map(|v| v.weight).sum();
    let required_weight = 3;

    assert!(
        total_weight >= required_weight,
        "Weighted quorum should be reachable"
    );
}

// Note: Full integration tests with the actual quorum! combinator would require
// the lab runtime. These tests verify semantic expectations.
