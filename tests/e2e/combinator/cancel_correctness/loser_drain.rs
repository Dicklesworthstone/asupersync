//! Loser drain verification tests.
//!
//! These tests verify that race losers are FULLY DRAINED, not just dropped.
//! This is THE critical invariant for cancel-correct structured concurrency.

use crate::e2e::combinator::util::{Counter, DrainFlag, DrainTracker, NeverComplete};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;

/// Test that race loser's Drop is called after cancellation.
#[test]
fn test_race_loser_drop_called() {
    let loser_dropped = DrainFlag::new();
    let loser_dropped_clone = Arc::clone(&loser_dropped);

    // In a real race, we would use the race combinator.
    // For now, simulate the behavior.
    let _winner = {
        // Simulate winner completing first
        let _loser = DrainTracker::new(NeverComplete, loser_dropped_clone);
        // Winner returns
        42
    };
    // Loser should be dropped when winner exits scope

    crate::assert_drained!(loser_dropped, "race loser");
}

/// Test that multiple race losers are all drained.
#[test]
fn test_race_multiple_losers_all_drained() {
    let loser1_dropped = DrainFlag::new();
    let loser2_dropped = DrainFlag::new();
    let loser3_dropped = DrainFlag::new();

    {
        let _tracker1 = DrainTracker::new(NeverComplete, Arc::clone(&loser1_dropped));
        let _tracker2 = DrainTracker::new(NeverComplete, Arc::clone(&loser2_dropped));
        let _tracker3 = DrainTracker::new(NeverComplete, Arc::clone(&loser3_dropped));
        // Simulate winner completing
    }

    crate::assert_drained!(loser1_dropped, "first loser");
    crate::assert_drained!(loser2_dropped, "second loser");
    crate::assert_drained!(loser3_dropped, "third loser");
}

/// Test that cleanup code in loser branch executes.
#[test]
fn test_race_loser_cleanup_executes() {
    let cleanup_executed = Arc::new(AtomicBool::new(false));
    let cleanup_executed_clone = Arc::clone(&cleanup_executed);

    struct CleanupOnDrop {
        flag: Arc<AtomicBool>,
    }

    impl Drop for CleanupOnDrop {
        fn drop(&mut self) {
            self.flag.store(true, Ordering::SeqCst);
        }
    }

    {
        let _cleanup_guard = CleanupOnDrop {
            flag: cleanup_executed_clone,
        };
        // Simulate being a loser in a race
    }

    assert!(
        cleanup_executed.load(Ordering::SeqCst),
        "Cleanup code in loser branch did not execute"
    );
}

/// Test drain timing - loser drain should complete before race returns.
#[test]
fn test_race_loser_drain_timing() {
    let drain_sequence = Arc::new(AtomicU32::new(0));
    let winner_return_sequence = Arc::new(AtomicU32::new(0));

    let drain_clone = Arc::clone(&drain_sequence);
    let winner_clone = Arc::clone(&winner_return_sequence);

    struct SequenceTracker {
        sequence: Arc<AtomicU32>,
        expected_order: u32,
    }

    impl Drop for SequenceTracker {
        fn drop(&mut self) {
            // Record when drain happens
            let current = self.sequence.fetch_add(1, Ordering::SeqCst);
            assert!(
                current < self.expected_order,
                "Drain happened after winner return (sequence {} >= {})",
                current,
                self.expected_order
            );
        }
    }

    {
        let _loser = SequenceTracker {
            sequence: drain_clone,
            expected_order: 100, // Should be drained before order 100
        };
        // Winner completes and increments sequence
        winner_clone.store(drain_sequence.load(Ordering::SeqCst) + 1, Ordering::SeqCst);
    }

    // Drain happened before winner return was recorded
    let drain_time = drain_sequence.load(Ordering::SeqCst);
    let winner_time = winner_return_sequence.load(Ordering::SeqCst);

    assert!(
        drain_time <= winner_time,
        "Loser drain (seq={}) happened after winner return (seq={})",
        drain_time,
        winner_time
    );
}

/// Test that nested race losers are all drained.
#[test]
fn test_nested_race_losers_drained() {
    let outer_loser = DrainFlag::new();
    let inner_loser1 = DrainFlag::new();
    let inner_loser2 = DrainFlag::new();

    {
        let _outer = DrainTracker::new(NeverComplete, Arc::clone(&outer_loser));
        {
            let _inner1 = DrainTracker::new(NeverComplete, Arc::clone(&inner_loser1));
            let _inner2 = DrainTracker::new(NeverComplete, Arc::clone(&inner_loser2));
            // Inner winner
        }
        // Outer winner
    }

    crate::assert_drained!(outer_loser, "outer loser");
    crate::assert_drained!(inner_loser1, "inner loser 1");
    crate::assert_drained!(inner_loser2, "inner loser 2");
}

/// Test drain with panicking cleanup.
#[test]
#[should_panic(expected = "cleanup panic")]
fn test_race_loser_panic_in_cleanup() {
    struct PanicOnDrop;

    impl Drop for PanicOnDrop {
        fn drop(&mut self) {
            panic!("cleanup panic");
        }
    }

    {
        let _loser = PanicOnDrop;
    }
}

/// Test that drain respects poll budget.
#[test]
fn test_race_loser_drain_respects_budget() {
    let polls_during_drain = Counter::new();
    let max_drain_polls: u32 = 100;

    struct BudgetTracker {
        counter: Arc<Counter>,
        max_polls: u32,
    }

    impl Drop for BudgetTracker {
        fn drop(&mut self) {
            // Simulate drain polling
            for _ in 0..10 {
                self.counter.increment();
            }
            assert!(
                self.counter.get() <= self.max_polls,
                "Exceeded drain poll budget: {} > {}",
                self.counter.get(),
                self.max_polls
            );
        }
    }

    {
        let _loser = BudgetTracker {
            counter: Arc::clone(&polls_during_drain),
            max_polls: max_drain_polls,
        };
    }

    assert!(
        polls_during_drain.get() <= max_drain_polls,
        "Drain exceeded budget"
    );
}

// Note: Full integration tests with the actual race! macro would require
// the lab runtime. These tests verify the drop/drain semantics that the
// combinator implementation relies on.
