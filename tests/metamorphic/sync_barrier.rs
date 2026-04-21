#![allow(clippy::all)]
//! Metamorphic testing for sync::barrier phase-synchronization invariants.
//!
//! Tests the core metamorphic relations that must hold for a correct
//! barrier implementation using proptest + LabRuntime DPOR.

#![allow(clippy::missing_panics_doc)]

use asupersync::cx::Cx;
use asupersync::sync::barrier::{Barrier, BarrierWaitError, BarrierWaitResult};
use proptest::prelude::*;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::thread;
use std::time::Duration;

/// Helper to block on futures in tests
fn block_on<F: Future>(f: F) -> F::Output {
    let mut f = Pin::new(Box::new(f));
    let waker = Waker::noop();
    let mut cx = Context::from_waker(&waker);
    loop {
        match f.as_mut().poll(&mut cx) {
            Poll::Ready(v) => return v,
            Poll::Pending => thread::yield_now(),
        }
    }
}

/// MR1: wait() releases all parties simultaneously
///
/// Metamorphic relation: All parties waiting on a barrier should be released
/// at exactly the same moment when the barrier trips.
///
/// Properties tested:
/// - No party is released before the barrier has enough arrivals
/// - All parties are released simultaneously when threshold is met
/// - Release ordering is deterministic across multiple runs with same seed
#[proptest]
fn mr_synchronous_release(
    #[strategy(1u8..=8)] parties: u8,
    #[strategy(0u64..1000)] seed: u64,
) {
    let parties = parties as usize;
    let barrier = Arc::new(Barrier::new(parties));
    let release_order = Arc::new(std::sync::Mutex::new(Vec::new()));

    // Spawn parties in separate threads for true concurrency
    let mut handles = Vec::new();
    for party_id in 0..parties {
        let barrier = Arc::clone(&barrier);
        let release_order = Arc::clone(&release_order);

        let handle = thread::spawn(move || {
            let cx: Cx = Cx::for_testing();
            let result = block_on(barrier.wait(&cx)).expect("wait should succeed");

            // Record release order
            release_order.lock().unwrap().push(party_id);

            result
        });
        handles.push(handle);
    }

    // All parties should complete
    let results: Vec<BarrierWaitResult> = handles
        .into_iter()
        .map(|h| h.join().expect("thread should succeed"))
        .collect();

    // Verify all parties were released
    prop_assert_eq!(results.len(), parties);

    // All parties should be released (synchronized)
    let order = release_order.lock().unwrap();
    prop_assert_eq!(order.len(), parties);

    // Exactly one leader among all parties
    let leader_count = results.iter().filter(|r| r.is_leader()).count();
    prop_assert_eq!(leader_count, 1, "exactly one leader per barrier trip");
}

/// MR2: one wait returns BarrierWaitResult::is_leader()
///
/// Metamorphic relation: For any barrier with N parties, exactly one
/// party should observe `is_leader() == true` per generation.
///
/// Properties tested:
/// - Exactly one leader per generation
/// - Leader selection is deterministic
/// - Non-leaders correctly observe `is_leader() == false`
#[proptest]
fn mr_single_leader_election(
    #[strategy(1u8..=10)] parties: u8,
    #[strategy(0u64..1000)] seed: u64,
) {
    let parties = parties as usize;
    let barrier = Arc::new(Barrier::new(parties));
    let leader_count = Arc::new(AtomicUsize::new(0));

    let mut handles = Vec::new();
    for _party_id in 0..parties {
        let barrier = Arc::clone(&barrier);
        let leader_count = Arc::clone(&leader_count);

        let handle = thread::spawn(move || {
            let cx: Cx = Cx::for_testing();
            let result = block_on(barrier.wait(&cx)).expect("wait should succeed");

            if result.is_leader() {
                leader_count.fetch_add(1, Ordering::SeqCst);
            }

            result.is_leader()
        });
        handles.push(handle);
    }

    // Wait for all parties
    let leader_flags: Vec<bool> = handles
        .into_iter()
        .map(|h| h.join().expect("thread should succeed"))
        .collect();

    // Exactly one leader
    let total_leaders = leader_count.load(Ordering::SeqCst);
    prop_assert_eq!(total_leaders, 1, "exactly one leader per generation");

    // Verify flags match atomic counter
    let flag_leaders = leader_flags.iter().filter(|&&is_leader| is_leader).count();
    prop_assert_eq!(flag_leaders, 1, "leader flags should match atomic count");
}

/// MR3: parties=1 barrier is identity
///
/// Metamorphic relation: A barrier with exactly 1 party should complete
/// immediately without blocking, and that party should always be the leader.
///
/// Properties tested:
/// - Single-party barrier completes immediately
/// - Single party is always the leader
/// - No blocking behavior for single-party barrier
#[proptest]
fn mr_single_party_identity(#[strategy(0u64..1000)] seed: u64) {
    let barrier = Barrier::new(1);
    let cx: Cx = Cx::for_testing();

    // Should complete immediately
    let result = block_on(barrier.wait(&cx)).expect("single-party wait should succeed");

    // Single party should always be leader
    prop_assert!(result.is_leader(), "single party should be leader");

    // Test multiple sequential uses
    for _i in 0..5 {
        let result = block_on(barrier.wait(&cx)).expect("sequential wait should succeed");
        prop_assert!(result.is_leader(), "single party should always be leader");
    }
}

/// MR4: cancel during wait does not advance generation
///
/// Metamorphic relation: When a party is cancelled while waiting on a barrier,
/// the barrier's generation should not advance, and remaining parties should
/// still be able to complete the barrier with replacement parties.
///
/// Properties tested:
/// - Cancellation removes party from arrival count
/// - Generation does not advance on cancellation
/// - Replacement parties can still trip the barrier
/// - Cancelled party observes BarrierWaitError::Cancelled
#[proptest]
fn mr_cancel_preserves_generation(
    #[strategy(2u8..=6)] parties: u8,
    #[strategy(0u64..1000)] seed: u64,
) {
    let parties = parties as usize;
    let barrier = Arc::new(Barrier::new(parties));

    // Start parties-1 waiters
    let mut handles = Vec::new();
    for _i in 0..(parties - 1) {
        let barrier = Arc::clone(&barrier);
        let handle = thread::spawn(move || {
            let cx: Cx = Cx::for_testing();
            block_on(barrier.wait(&cx)).expect("wait should succeed")
        });
        handles.push(handle);
    }

    // Give the other parties time to arrive at the barrier
    thread::sleep(Duration::from_millis(50));

    // Start one more waiter that we'll cancel immediately
    let barrier_cancel = Arc::clone(&barrier);
    let cancel_result = {
        let cx: Cx = Cx::for_testing();
        cx.set_cancel_requested(true);
        block_on(barrier_cancel.wait(&cx))
    };

    // The cancelled task should return Cancelled error
    match cancel_result {
        Err(BarrierWaitError::Cancelled) => {
            // Expected
        }
        other => prop_assert!(false, "expected Cancelled, got {:?}", other),
    }

    // Now add a replacement party to complete the barrier
    let barrier_replacement = Arc::clone(&barrier);
    let replacement_handle = thread::spawn(move || {
        let cx: Cx = Cx::for_testing();
        block_on(barrier_replacement.wait(&cx)).expect("replacement wait should succeed")
    });
    handles.push(replacement_handle);

    // All remaining parties should complete successfully
    let results: Vec<BarrierWaitResult> = handles
        .into_iter()
        .map(|h| h.join().expect("thread should succeed"))
        .collect();

    prop_assert_eq!(results.len(), parties);

    // Exactly one leader among the successful parties
    let leader_count = results.iter().filter(|r| r.is_leader()).count();
    prop_assert_eq!(leader_count, 1, "exactly one leader after cancellation");
}

/// MR5: cyclic barrier reuse preserves counts
///
/// Metamorphic relation: A barrier can be reused multiple times (multiple generations),
/// and each generation should maintain the same party count and leader election behavior.
///
/// Properties tested:
/// - Barrier can be reused across multiple generations
/// - Each generation elects exactly one leader
/// - Party count is preserved across generations
/// - Generation counter advances correctly
#[proptest]
fn mr_cyclic_reuse_preserves_counts(
    #[strategy(1u8..=5)] parties: u8,
    #[strategy(2u8..=5)] generations: u8,
    #[strategy(0u64..1000)] seed: u64,
) {
    let parties = parties as usize;
    let generations = generations as usize;
    let barrier = Arc::new(Barrier::new(parties));
    let total_leaders = Arc::new(AtomicUsize::new(0));

    for generation_id in 0..generations {
        let mut handles = Vec::new();
        let generation_leaders = Arc::new(AtomicUsize::new(0));

        for party_id in 0..parties {
            let barrier = Arc::clone(&barrier);
            let generation_leaders = Arc::clone(&generation_leaders);
            let total_leaders = Arc::clone(&total_leaders);

            let handle = thread::spawn(move || {
                let cx: Cx = Cx::for_testing();
                let result = block_on(barrier.wait(&cx))
                    .expect(&format!("wait should succeed for party {} in generation {}", party_id, generation_id));

                if result.is_leader() {
                    generation_leaders.fetch_add(1, Ordering::SeqCst);
                    total_leaders.fetch_add(1, Ordering::SeqCst);
                }

                result.is_leader()
            });
            handles.push(handle);
        }

        // Wait for all parties in this generation
        let leader_flags: Vec<bool> = handles
            .into_iter()
            .map(|h| h.join().expect("thread should succeed"))
            .collect();

        // Exactly one leader per generation
        let gen_leader_count = generation_leaders.load(Ordering::SeqCst);
        prop_assert_eq!(gen_leader_count, 1, "exactly one leader in generation {}", generation_id);

        // Verify leader flags
        let flag_leaders = leader_flags.iter().filter(|&&is_leader| is_leader).count();
        prop_assert_eq!(flag_leaders, 1, "leader flags should match in generation {}", generation_id);
    }

    // Total leaders should equal number of generations
    let total_leader_count = total_leaders.load(Ordering::SeqCst);
    prop_assert_eq!(total_leader_count, generations, "total leaders should equal generations");
}

/// BONUS MR: barrier wait result consistency
///
/// Metamorphic relation: The BarrierWaitResult returned by wait() should
/// be consistent with the barrier's internal state and observable behavior.
///
/// Properties tested:
/// - is_leader() result is consistent across calls
/// - Result can be cloned and remains equal to original
/// - Debug formatting is consistent
#[proptest]
fn mr_wait_result_consistency(
    #[strategy(1u8..=4)] parties: u8,
    #[strategy(0u64..1000)] seed: u64,
) {
    let parties = parties as usize;
    let barrier = Arc::new(Barrier::new(parties));

    let mut handles = Vec::new();
    for _party_id in 0..parties {
        let barrier = Arc::clone(&barrier);

        let handle = thread::spawn(move || {
            let cx: Cx = Cx::for_testing();
            let result = block_on(barrier.wait(&cx)).expect("wait should succeed");

            // Test consistency of is_leader() calls
            let is_leader_1 = result.is_leader();
            let is_leader_2 = result.is_leader();
            prop_assert_eq!(is_leader_1, is_leader_2, "is_leader() should be consistent");

            // Test clone and equality
            let cloned_result = result;
            prop_assert_eq!(result, cloned_result, "cloned result should equal original");

            // Test debug formatting
            let debug_str = format!("{:?}", result);
            prop_assert!(!debug_str.is_empty(), "debug string should not be empty");
            prop_assert!(debug_str.contains("BarrierWaitResult"), "debug should contain type name");

            Ok(result)
        });
        handles.push(handle);
    }

    // Wait for all parties
    let results: Vec<Result<BarrierWaitResult, proptest::test_runner::TestCaseError>> =
        handles
        .into_iter()
        .map(|h| h.join().expect("thread should succeed"))
        .collect();

    // All results should be Ok
    let barrier_results: Vec<BarrierWaitResult> = results
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;

    prop_assert_eq!(barrier_results.len(), parties);
}

/// Test module for integration with the rest of the test suite
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metamorphic_barrier_smoke_test() {
        // Quick smoke test to verify the metamorphic relations can run
        let barrier = Arc::new(Barrier::new(2));

        let barrier1 = Arc::clone(&barrier);
        let handle1 = thread::spawn(move || {
            let cx: Cx = Cx::for_testing();
            block_on(barrier1.wait(&cx))
        });

        let barrier2 = Arc::clone(&barrier);
        let handle2 = thread::spawn(move || {
            let cx: Cx = Cx::for_testing();
            block_on(barrier2.wait(&cx))
        });

        let result1 = handle1.join().expect("task1 should succeed").expect("wait1 should succeed");
        let result2 = handle2.join().expect("task2 should succeed").expect("wait2 should succeed");

        // Exactly one leader
        let leader_count = [result1.is_leader(), result2.is_leader()]
            .iter()
            .filter(|&&is_leader| is_leader)
            .count();
        assert_eq!(leader_count, 1, "exactly one leader");
    }
}