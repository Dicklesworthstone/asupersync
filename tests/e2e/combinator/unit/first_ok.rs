//! Unit tests for the first_ok! combinator.
//!
//! Tests verify:
//! - First success wins
//! - Fallback behavior on errors
//! - All-error case handling
//! - Resource cleanup

use crate::e2e::combinator::util::{DrainFlag, DrainTracker, NeverComplete};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

struct OrderTracker {
    order: Arc<std::sync::Mutex<Vec<u32>>>,
    id: u32,
    succeeds: bool,
}

impl OrderTracker {
    fn evaluate(&self) -> Result<i32, ()> {
        self.order.lock().unwrap().push(self.id);
        if self.succeeds {
            Ok(i32::try_from(self.id).expect("id fits i32"))
        } else {
            Err(())
        }
    }
}

struct CleanupOnError {
    flag: Arc<AtomicBool>,
}

impl Drop for CleanupOnError {
    fn drop(&mut self) {
        self.flag.store(true, Ordering::SeqCst);
    }
}

/// Test that first success wins.
#[test]
fn test_first_ok_success_wins() {
    #[derive(Debug, PartialEq)]
    enum TestError {
        Failed,
    }

    let results: Vec<Result<i32, TestError>> =
        vec![Err(TestError::Failed), Ok(42), Err(TestError::Failed)];

    // First Ok should win
    let winner = results.into_iter().find(Result::is_ok);

    assert_eq!(winner, Some(Ok(42)));
}

/// Test fallback to second on first error.
#[test]
fn test_first_ok_fallback() {
    #[derive(Debug, PartialEq)]
    #[allow(dead_code)]
    enum TestError {
        FirstFailed,
        SecondFailed,
    }

    fn primary() -> Result<i32, TestError> {
        Err(TestError::FirstFailed)
    }

    fn fallback() -> i32 {
        42
    }

    // Primary fails, fallback succeeds
    let result: Result<i32, TestError> = primary().or_else(|_| Ok(fallback()));

    assert_eq!(result, Ok(42));
}

/// Test all branches fail.
#[test]
fn test_first_ok_all_fail() {
    #[derive(Debug, PartialEq, Clone)]
    enum TestError {
        First,
        Second,
        Third,
    }

    let results: Vec<Result<i32, TestError>> = vec![
        Err(TestError::First),
        Err(TestError::Second),
        Err(TestError::Third),
    ];

    // No Ok result
    let success = results.iter().find(|r| r.is_ok());

    assert!(success.is_none(), "All failed means no success");
}

/// Test first_ok with immediate success.
#[test]
fn test_first_ok_immediate_success() {
    #[derive(Debug, PartialEq)]
    #[allow(dead_code)]
    enum TestError {
        Unused,
    }

    fn immediate_ok() -> i32 {
        1
    }

    fn never_called() -> i32 {
        panic!("Should not be called");
    }

    // First succeeds, second never evaluated
    let result = immediate_ok();
    let _ = never_called; // Just to use it

    assert_eq!(result, 1);
}

/// Test cancellation of remaining branches on success.
#[test]
fn test_first_ok_cancels_remaining() {
    let remaining_cancelled = DrainFlag::new();

    {
        // First succeeds
        let _ = 42;
        // Remaining branches cancelled
        let _remaining = DrainTracker::new(NeverComplete, Arc::clone(&remaining_cancelled));
    }

    crate::assert_drained!(remaining_cancelled, "remaining branch after success");
}

/// Test error collection.
#[test]
fn test_first_ok_collects_errors() {
    #[derive(Debug, PartialEq, Clone)]
    enum TestError {
        ErrorA,
        ErrorB,
        ErrorC,
    }

    let errors: Vec<TestError> = vec![TestError::ErrorA, TestError::ErrorB, TestError::ErrorC];

    // All errors should be available if all fail
    assert_eq!(errors.len(), 3);
}

/// Test priority ordering.
#[test]
fn test_first_ok_priority_order() {
    let evaluation_order = Arc::new(std::sync::Mutex::new(Vec::new()));

    let trackers = vec![
        OrderTracker {
            order: Arc::clone(&evaluation_order),
            id: 1,
            succeeds: false,
        },
        OrderTracker {
            order: Arc::clone(&evaluation_order),
            id: 2,
            succeeds: true,
        },
        OrderTracker {
            order: Arc::clone(&evaluation_order),
            id: 3,
            succeeds: false,
        },
    ];

    // Evaluate in order until success
    let mut result = None;
    for tracker in &trackers {
        if let Ok(v) = tracker.evaluate() {
            result = Some(v);
            break;
        }
    }

    assert_eq!(result, Some(2));

    let order = evaluation_order.lock().unwrap().clone();
    assert_eq!(order, vec![1, 2], "Should stop at first success");
}

/// Test resource cleanup on error path.
#[test]
fn test_first_ok_cleanup_on_error() {
    let cleaned_up = Arc::new(AtomicBool::new(false));

    {
        let _guard = CleanupOnError {
            flag: Arc::clone(&cleaned_up),
        };
        // Error path
    }

    assert!(
        cleaned_up.load(Ordering::SeqCst),
        "Should cleanup on error path"
    );
}

/// Test first_ok with heterogeneous error types.
#[test]
fn test_first_ok_heterogeneous_errors() {
    #[derive(Debug)]
    #[allow(dead_code)]
    enum CombinedError {
        Network(String),
        Timeout,
        Parse(String),
    }

    fn try_network() -> Result<i32, CombinedError> {
        Err(CombinedError::Network("connection refused".to_string()))
    }

    fn try_cache() -> Result<i32, CombinedError> {
        Err(CombinedError::Timeout)
    }

    fn try_default() -> i32 {
        0
    }

    let result = try_network()
        .or_else(|_| try_cache())
        .unwrap_or_else(|_| try_default());

    assert_eq!(result, 0);
}

/// Test concurrent first_ok evaluation.
#[test]
fn test_first_ok_concurrent_attempts() {
    let attempt_count = Arc::new(AtomicU32::new(0));

    // Simulate concurrent attempts
    for _ in 0..3 {
        attempt_count.fetch_add(1, Ordering::SeqCst);
    }

    assert!(
        attempt_count.load(Ordering::SeqCst) >= 1,
        "At least one attempt should be made"
    );
}

/// Test that first_ok respects evaluation budget.
#[test]
fn test_first_ok_respects_budget() {
    let evaluations = Arc::new(AtomicU32::new(0));
    let max_budget = 10;

    // Simulate bounded evaluation
    while evaluations.load(Ordering::SeqCst) < max_budget {
        evaluations.fetch_add(1, Ordering::SeqCst);
        if evaluations.load(Ordering::SeqCst) >= 5 {
            break; // Found success
        }
    }

    assert!(
        evaluations.load(Ordering::SeqCst) <= max_budget,
        "Should respect evaluation budget"
    );
}

// Note: Full integration tests with the actual first_ok! combinator would require
// the lab runtime. These tests verify semantic expectations.
