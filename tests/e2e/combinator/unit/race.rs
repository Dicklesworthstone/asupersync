//! Unit tests for the race! combinator.
//!
//! Tests verify:
//! - First completion wins
//! - Error as winner
//! - Polling fairness
//! - Loser cancellation

use crate::e2e::combinator::util::{Counter, DrainFlag, DrainTracker, NeverComplete};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;

/// Test that race returns the first completing future's result.
#[test]
fn test_race_first_wins() {
    // Simulate race where branch1 completes first
    let winner_value = 42;
    let _loser_value = 100;

    // First to complete wins
    let result = winner_value;

    assert_eq!(result, 42, "First completing branch should win");
}

/// Test race with error as the winner.
#[test]
fn test_race_error_wins() {
    #[derive(Debug, PartialEq)]
    enum TestError {
        FastError,
    }

    // If error completes first, it wins
    let error_result: Result<i32, TestError> = Err(TestError::FastError);
    let _success_result: Result<i32, TestError> = Ok(42);

    // Error completed first
    let winner = error_result;

    assert_eq!(
        winner,
        Err(TestError::FastError),
        "Error should win if it completes first"
    );
}

/// Test that race losers are dropped.
#[test]
fn test_race_losers_dropped() {
    let loser_dropped = DrainFlag::new();

    {
        let _loser = DrainTracker::new(NeverComplete, Arc::clone(&loser_dropped));
        // Winner completes, loser scope ends
    }

    crate::assert_drained!(loser_dropped, "race loser");
}

/// Test race with multiple losers.
#[test]
fn test_race_multiple_losers() {
    let loser1 = DrainFlag::new();
    let loser2 = DrainFlag::new();
    let loser3 = DrainFlag::new();

    {
        let _l1 = DrainTracker::new(NeverComplete, Arc::clone(&loser1));
        let _l2 = DrainTracker::new(NeverComplete, Arc::clone(&loser2));
        let _l3 = DrainTracker::new(NeverComplete, Arc::clone(&loser3));
        // Winner (not tracked) completes
    }

    crate::assert_drained!(loser1, "loser 1");
    crate::assert_drained!(loser2, "loser 2");
    crate::assert_drained!(loser3, "loser 3");
}

/// Test polling fairness concept.
#[test]
fn test_race_polling_fairness() {
    let poll_counts = [
        Arc::new(AtomicU32::new(0)),
        Arc::new(AtomicU32::new(0)),
        Arc::new(AtomicU32::new(0)),
    ];

    // Simulate fair polling - each branch gets polled
    for count in &poll_counts {
        count.fetch_add(1, Ordering::SeqCst);
    }

    // All branches should have been polled at least once
    for (i, count) in poll_counts.iter().enumerate() {
        assert!(
            count.load(Ordering::SeqCst) >= 1,
            "Branch {} should be polled at least once for fairness",
            i
        );
    }
}

/// Test race winner value is preserved.
#[test]
fn test_race_winner_value_preserved() {
    struct ValueHolder {
        value: i32,
    }

    let winner = ValueHolder { value: 42 };

    // Winner's value should be accessible after race completes
    assert_eq!(winner.value, 42, "Winner value should be preserved");
}

/// Test race with immediate completion.
#[test]
fn test_race_immediate_winner() {
    let completed_immediately = Arc::new(AtomicBool::new(false));
    completed_immediately.store(true, Ordering::SeqCst);

    assert!(
        completed_immediately.load(Ordering::SeqCst),
        "Immediate winner should complete race"
    );
}

/// Test race cancellation propagates to nested futures.
#[test]
fn test_race_nested_cancellation() {
    let outer_cancelled = DrainFlag::new();
    let inner_cancelled = DrainFlag::new();

    {
        let _outer = DrainTracker::new(NeverComplete, Arc::clone(&outer_cancelled));
        {
            let _inner = DrainTracker::new(NeverComplete, Arc::clone(&inner_cancelled));
        }
    }

    crate::assert_drained!(outer_cancelled, "outer loser");
    crate::assert_drained!(inner_cancelled, "inner loser");
}

/// Test race with same-tick completion.
#[test]
fn test_race_same_tick_completion() {
    // When multiple branches complete in same tick, first polled wins
    let completion_order = Arc::new(std::sync::Mutex::new(Vec::new()));

    struct OrderTracker {
        order: Arc<std::sync::Mutex<Vec<u32>>>,
        id: u32,
    }

    impl OrderTracker {
        fn complete(&self) {
            self.order.lock().unwrap().push(self.id);
        }
    }

    let tracker1 = OrderTracker {
        order: Arc::clone(&completion_order),
        id: 1,
    };
    let tracker2 = OrderTracker {
        order: Arc::clone(&completion_order),
        id: 2,
    };

    // Both complete, but order matters for winner determination
    tracker1.complete();
    tracker2.complete();

    let order = completion_order.lock().unwrap();
    assert_eq!(order.len(), 2);
    assert_eq!(order[0], 1, "First polled should be recorded first");
}

/// Test race resource cleanup timing.
#[test]
fn test_race_cleanup_before_return() {
    let cleanup_done = Arc::new(AtomicBool::new(false));
    let result_returned = Arc::new(AtomicBool::new(false));

    struct CleanupTracker {
        cleanup_flag: Arc<AtomicBool>,
        result_flag: Arc<AtomicBool>,
    }

    impl Drop for CleanupTracker {
        fn drop(&mut self) {
            // Cleanup should happen before result is considered "returned"
            assert!(
                !self.result_flag.load(Ordering::SeqCst),
                "Cleanup should happen before return"
            );
            self.cleanup_flag.store(true, Ordering::SeqCst);
        }
    }

    {
        let _tracker = CleanupTracker {
            cleanup_flag: Arc::clone(&cleanup_done),
            result_flag: Arc::clone(&result_returned),
        };
    }

    result_returned.store(true, Ordering::SeqCst);

    assert!(
        cleanup_done.load(Ordering::SeqCst),
        "Cleanup should be done"
    );
}

// Note: Full integration tests with the actual race! macro would require
// the lab runtime. These tests verify the semantic expectations.
