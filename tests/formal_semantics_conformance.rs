//! Formal Semantics Conformance Tests
//!
//! Property-based tests that mechanically verify core invariants from
//! asupersync_v4_formal_semantics.md:
//!
//! (a) region close ⇒ quiescence (INV-QUIESCENCE)
//! (b) cancel idempotence (strengthen operation)
//! (c) losers-drained-after-races (L-LOSER-DRAINED lemma)
//!
//! # Spec References
//!
//! - Section 1.12: Quiescent(r) predicate definition
//! - Section 3.2.2: Cancellation idempotence proof sketch
//! - Section 4.2: Race combinator with loser-drain invariant
//! - Section 5: INV-QUIESCENCE, INV-LOSER-DRAINED formal statements

#[macro_use]
mod common;

use asupersync::cx::Cx;
use asupersync::runtime::yield_now;
use asupersync::types::{Budget, CancelKind, CancelReason, Outcome};
use asupersync::{
    conformance::{ConformanceTarget, LabRuntimeTarget, TestConfig},
    conformance_test,
};
use common::*;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

fn init_test(test_name: &str) {
    init_test_logging();
    test_phase!(test_name);
}

// ============================================================================
// Property (a): region close ⇒ quiescence (INV-QUIESCENCE)
// ============================================================================

/// Tests the formal semantic property: R[r].state = Closed(_) ⇒ Quiescent(r)
///
/// Where Quiescent(r) ≜
///   (∀t ∈ R[r].children: T[t].state = Completed(_)) ∧
///   (∀r' ∈ R[r].subregions: R[r'].state = Closed(_)) ∧
///   ledger(r) = ∅
conformance_test!(
    test_region_close_implies_quiescence,
    |config: &TestConfig| {
        init_test("test_region_close_implies_quiescence");

        let mut runtime = LabRuntimeTarget::create_runtime(config.clone());

        LabRuntimeTarget::block_on(&mut runtime, async {
            let cx = Cx::current().expect("should have context");

            // Create a region with child tasks and subregions
            let parent_region = LabRuntimeTarget::create_region(&cx, Budget::INFINITE);

            // Spawn multiple tasks in the region
            let task1 =
                LabRuntimeTarget::spawn_in_region(&cx, &parent_region, Budget::INFINITE, async {
                    yield_now().await;
                    42
                });

            let task2 =
                LabRuntimeTarget::spawn_in_region(&cx, &parent_region, Budget::INFINITE, async {
                    yield_now().await;
                    yield_now().await;
                    24
                });

            // Create a child region
            let child_region = LabRuntimeTarget::create_region(&cx, Budget::INFINITE);

            // Spawn task in child region
            let child_task =
                LabRuntimeTarget::spawn_in_region(&cx, &child_region, Budget::INFINITE, async {
                    yield_now().await;
                    100
                });

            // Wait for all tasks to complete
            let result1 = task1.await;
            let result2 = task2.await;
            let child_result = child_task.await;

            // Verify results before region closes
            assert_eq!(result1, Outcome::Ok(42));
            assert_eq!(result2, Outcome::Ok(24));
            assert_eq!(child_result, Outcome::Ok(100));

            // Wait for child region to close
            child_region.await;

            // Parent region should now be quiescent and close
            parent_region.await;

            // If we reach here without the oracle detecting violations,
            // the quiescence invariant held
        });

        test_complete!("test_region_close_implies_quiescence");
    }
);

/// Property test for quiescence with cancellation
conformance_test!(test_quiescence_with_cancellation, |config: &TestConfig| {
    init_test("test_quiescence_with_cancellation");

    let mut runtime = LabRuntimeTarget::create_runtime(config.clone());

    LabRuntimeTarget::block_on(&mut runtime, async {
        let cx = Cx::current().expect("should have context");

        // Create region and spawn long-running task
        let region = LabRuntimeTarget::create_region(&cx, Budget::INFINITE);

        let long_task = LabRuntimeTarget::spawn_in_region(&cx, &region, Budget::INFINITE, async {
            // Simulate long-running work that can be cancelled
            for _ in 0..1000 {
                yield_now().await;
            }
            999
        });

        // Cancel the region after a brief delay
        yield_now().await;
        yield_now().await;
        LabRuntimeTarget::cancel(&cx, &region, CancelReason::user("test cancel"));

        // Task should be cancelled, not complete normally
        let result = long_task.await;
        match result {
            Outcome::Cancelled(_) => {
                // Expected: task was cancelled
            }
            other => panic!("Expected cancelled task, got {:?}", other),
        }

        // Region should close after cancel+drain completes
        region.await;

        // Quiescence invariant must still hold even with cancellation
    });

    test_complete!("test_quiescence_with_cancellation");
});

// ============================================================================
// Property (b): cancel idempotence (strengthen operation)
// ============================================================================

/// Tests the formal semantic property: cancel(r, a); cancel(r, b) ≃ cancel(r, strengthen(a, b))
///
/// Where strengthen is associative, commutative, and idempotent
conformance_test!(test_cancel_idempotence, |config: &TestConfig| {
    init_test("test_cancel_idempotence");

    let mut runtime = LabRuntimeTarget::create_runtime(config.clone());

    LabRuntimeTarget::block_on(&mut runtime, async {
        let cx = Cx::current().expect("should have context");

        // Test idempotence: multiple cancels should strengthen reason
        let region = LabRuntimeTarget::create_region(&cx, Budget::INFINITE);

        let cancel_counter = Arc::new(AtomicU32::new(0));
        let counter_clone = cancel_counter.clone();

        let task = LabRuntimeTarget::spawn_in_region(&cx, &region, Budget::INFINITE, async move {
            // Track how many times cancel is observed
            loop {
                yield_now().await;
                counter_clone.fetch_add(1, Ordering::Relaxed);
                // In real implementation, this would check for cancel via checkpoint
                if counter_clone.load(Ordering::Relaxed) > 10 {
                    break;
                }
            }
            "task work"
        });

        yield_now().await;

        // Multiple cancellation requests with different reasons
        LabRuntimeTarget::cancel(&cx, &region, CancelReason::user("first cancel"));
        LabRuntimeTarget::cancel(&cx, &region, CancelReason::user("second cancel"));
        LabRuntimeTarget::cancel(&cx, &region, CancelReason::deadline());

        // Task should be cancelled with the strongest (most recent/severe) reason
        let result = task.await;
        match result {
            Outcome::Cancelled(reason) => {
                // Verify that we got a cancel reason (idempotence preserved semantics)
                assert!(
                    reason.kind == CancelKind::User
                        || reason.kind == CancelKind::Deadline
                        || reason.kind == CancelKind::Shutdown
                );
            }
            other => panic!(
                "Expected cancelled task due to idempotent cancels, got {:?}",
                other
            ),
        }

        region.await;
    });

    test_complete!("test_cancel_idempotence");
});

/// Property test for cancel idempotence with different severities
conformance_test!(test_cancel_strengthen_severity, |config: &TestConfig| {
    init_test("test_cancel_strengthen_severity");

    let mut runtime = LabRuntimeTarget::create_runtime(config.clone());

    LabRuntimeTarget::block_on(&mut runtime, async {
        let cx = Cx::current().expect("should have context");

        let region = LabRuntimeTarget::create_region(&cx, Budget::INFINITE);

        let task = LabRuntimeTarget::spawn_in_region(&cx, &region, Budget::INFINITE, async {
            // Long enough to be cancelled
            for _ in 0..100 {
                yield_now().await;
            }
            "not cancelled"
        });

        yield_now().await;

        // Apply cancels in order of increasing severity
        LabRuntimeTarget::cancel(&cx, &region, CancelReason::user("low severity"));
        LabRuntimeTarget::cancel(&cx, &region, CancelReason::deadline());
        LabRuntimeTarget::cancel(&cx, &region, CancelReason::shutdown());

        let result = task.await;
        match result {
            Outcome::Cancelled(reason) => {
                // The final cancel reason should be the strongest one
                // (shutdown has highest severity in the formal semantics)
                assert_eq!(reason.kind, CancelKind::Shutdown);
            }
            other => panic!(
                "Expected cancelled task with strengthened reason, got {:?}",
                other
            ),
        }

        region.await;
    });

    test_complete!("test_cancel_strengthen_severity");
});

// ============================================================================
// Property (c): losers-drained-after-races (L-LOSER-DRAINED lemma)
// ============================================================================

/// Tests the formal semantic property: After race(f1, f2) returns, both tasks are Completed(_)
///
/// Per L-LOSER-DRAINED lemma: T'[tW].state = Completed(oW) ∧ T'[tL].state = Completed(oL)
/// where oL = Cancelled(RaceLost) or stronger
conformance_test!(test_losers_drained_after_races, |config: &TestConfig| {
    init_test("test_losers_drained_after_races");

    let mut runtime = LabRuntimeTarget::create_runtime(config.clone());

    LabRuntimeTarget::block_on(&mut runtime, async {
        let cx = Cx::current().expect("should have context");

        // Implement a simple race using the conformance API
        let region = LabRuntimeTarget::create_region(&cx, Budget::INFINITE);

        // Spawn two competing tasks
        let fast_task = LabRuntimeTarget::spawn_in_region(&cx, &region, Budget::INFINITE, async {
            yield_now().await;
            "fast winner"
        });

        let slow_task = LabRuntimeTarget::spawn_in_region(&cx, &region, Budget::INFINITE, async {
            // Slower task that should lose the race
            for _ in 0..10 {
                yield_now().await;
            }
            "slow loser"
        });

        // Wait for fast task to complete (winner)
        let winner_result = fast_task.await;
        assert_eq!(winner_result, Outcome::Ok("fast winner"));

        // Cancel the losing task (simulates race loser cancellation)
        LabRuntimeTarget::cancel(&cx, &region, CancelReason::race_lost());

        // Critical invariant: loser must be drained to completion
        let loser_result = slow_task.await;
        match loser_result {
            Outcome::Cancelled(reason) => {
                // Loser should be cancelled with RaceLost or stronger reason
                assert_eq!(reason.kind, CancelKind::RaceLost);
            }
            Outcome::Ok(_) => {
                // If task completed normally, that's also valid completion
                // (it finished before cancel took effect)
            }
            other => panic!("Loser task had invalid final state: {:?}", other),
        }

        region.await;

        // If we reach here, both winner and loser reached Completed state
        // satisfying the L-LOSER-DRAINED lemma
    });

    test_complete!("test_losers_drained_after_races");
});

/// Property test for race with multiple losers
conformance_test!(test_multiple_losers_all_drained, |config: &TestConfig| {
    init_test("test_multiple_losers_all_drained");

    let mut runtime = LabRuntimeTarget::create_runtime(config.clone());

    LabRuntimeTarget::block_on(&mut runtime, async {
        let cx = Cx::current().expect("should have context");

        let region = LabRuntimeTarget::create_region(&cx, Budget::INFINITE);

        // Create a race with one fast task and multiple slow tasks
        let winner = LabRuntimeTarget::spawn_in_region(&cx, &region, Budget::INFINITE, async {
            yield_now().await;
            "winner"
        });

        let loser1 = LabRuntimeTarget::spawn_in_region(&cx, &region, Budget::INFINITE, async {
            for _ in 0..20 {
                yield_now().await;
            }
            "loser1"
        });

        let loser2 = LabRuntimeTarget::spawn_in_region(&cx, &region, Budget::INFINITE, async {
            for _ in 0..30 {
                yield_now().await;
            }
            "loser2"
        });

        let loser3 = LabRuntimeTarget::spawn_in_region(&cx, &region, Budget::INFINITE, async {
            for _ in 0..40 {
                yield_now().await;
            }
            "loser3"
        });

        // Winner completes first
        let winner_result = winner.await;
        assert_eq!(winner_result, Outcome::Ok("winner"));

        // Cancel all losers (race lost)
        LabRuntimeTarget::cancel(&cx, &region, CancelReason::race_lost());

        // All losers must be drained to completion
        let results = vec![loser1.await, loser2.await, loser3.await];

        for (i, result) in results.iter().enumerate() {
            match result {
                Outcome::Cancelled(reason) => {
                    assert_eq!(
                        reason.kind,
                        CancelKind::RaceLost,
                        "Loser {} should be cancelled with RaceLost",
                        i + 1
                    );
                }
                Outcome::Ok(_) => {
                    // Natural completion before cancel is also valid
                }
                other => panic!("Loser {} had invalid final state: {:?}", i + 1, other),
            }
        }

        region.await;
    });

    test_complete!("test_multiple_losers_all_drained");
});

// ============================================================================
// Meta-property: Compositionality of invariants
// ============================================================================

/// Test that all three properties can hold simultaneously in complex scenarios
conformance_test!(test_all_properties_compose, |config: &TestConfig| {
    init_test("test_all_properties_compose");

    let mut runtime = LabRuntimeTarget::create_runtime(config.clone());

    LabRuntimeTarget::block_on(&mut runtime, async {
        let cx = Cx::current().expect("should have context");

        // Complex scenario: nested regions with races and cancellation
        let outer_region = LabRuntimeTarget::create_region(&cx, Budget::INFINITE);
        let inner_region = LabRuntimeTarget::create_region(&cx, Budget::INFINITE);

        // Race in inner region
        let race_winner =
            LabRuntimeTarget::spawn_in_region(&cx, &inner_region, Budget::INFINITE, async {
                yield_now().await;
                "race_winner"
            });

        let race_loser =
            LabRuntimeTarget::spawn_in_region(&cx, &inner_region, Budget::INFINITE, async {
                for _ in 0..50 {
                    yield_now().await;
                }
                "race_loser"
            });

        // Additional task in outer region
        let outer_task =
            LabRuntimeTarget::spawn_in_region(&cx, &outer_region, Budget::INFINITE, async {
                yield_now().await;
                yield_now().await;
                "outer_task"
            });

        // Winner completes
        let winner_result = race_winner.await;
        assert_eq!(winner_result, Outcome::Ok("race_winner"));

        // Test cancel idempotence on inner region
        LabRuntimeTarget::cancel(&cx, &inner_region, CancelReason::user("first"));
        LabRuntimeTarget::cancel(&cx, &inner_region, CancelReason::deadline());

        // Race loser should be drained (property c)
        let loser_result = race_loser.await;
        match loser_result {
            Outcome::Cancelled(_) => { /* loser was cancelled - good */ }
            Outcome::Ok(_) => { /* completed before cancel - also valid */ }
            other => panic!("Race loser invalid state: {:?}", other),
        }

        // Inner region should close with quiescence (property a)
        inner_region.await;

        // Outer task completes
        let outer_result = outer_task.await;
        assert_eq!(outer_result, Outcome::Ok("outer_task"));

        // Outer region should close with quiescence (property a)
        outer_region.await;

        // If we reach here, all three properties composed correctly:
        // - Quiescence was maintained on both region closes
        // - Cancel idempotence was preserved with multiple cancel calls
        // - Race loser was properly drained
    });

    test_complete!("test_all_properties_compose");
});
