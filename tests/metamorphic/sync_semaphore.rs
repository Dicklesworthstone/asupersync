#![allow(warnings)]
#![allow(clippy::all)]
//! Metamorphic Tests: sync::Semaphore Invariants (Five Relations)
//!
//! Tests five critical metamorphic relations for semaphore correctness using LabRuntime + proptest:
//! 1. MR1: acquire(n) blocks until n permits available (bounded counter)
//! 2. MR2: try_acquire(n) returns None (no block) if <n available
//! 3. MR3: close() wakes all waiters with Outcome::Cancelled
//! 4. MR4: cancel during acquire releases reservation (no deadlock)
//! 5. MR5: FIFO fairness — waiters woken in registration order when permits released

#![cfg(test)]

use asupersync::{
    cx::Cx,
    lab::LabRuntime,
    sync::semaphore::{AcquireError, Semaphore, SemaphorePermit},
    types::{Budget, Outcome, RegionId, TaskId},
    util::ArenaIndex,
    test_utils::init_test_logging,
};
use proptest::prelude::*;
use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

/// Helper to create a test context
fn test_cx() -> Cx {
    Cx::new(
        RegionId::from_arena(ArenaIndex::new(0, 0)),
        TaskId::from_arena(ArenaIndex::new(0, 0)),
        Budget::INFINITE,
    )
}

/// Helper to poll a future once
fn poll_once<T, F>(future: &mut F) -> Option<T>
where
    F: Future<Output = T> + Unpin,
{
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    match Pin::new(future).poll(&mut cx) {
        Poll::Ready(v) => Some(v),
        Poll::Pending => None,
    }
}

/// MR1: acquire(n) blocks until n permits available (bounded counter)
///
/// Property: acquire(n) should block when permits < n and complete immediately
/// when permits >= n. The semaphore acts as a bounded counter.

#[test]
fn mr1_acquire_blocks_until_permits_available() {
    LabRuntime::test(|lab| async {
        init_test_logging();

        proptest!(|(
            initial_permits in 1usize..=10,
            acquire_count in 1usize..=15,
            release_count in 0usize..=20
        )| {
            let sem = Semaphore::new(initial_permits);
            let cx = test_cx();

            // Test immediate acquire when permits available
            if acquire_count <= initial_permits {
                let mut fut = sem.acquire(&cx, acquire_count);
                let result = poll_once(&mut fut);
                prop_assert!(
                    result.is_some() && result.unwrap().is_ok(),
                    "acquire({}) should succeed immediately when {} permits available",
                    acquire_count, initial_permits
                );

                let available_after = sem.available_permits();
                prop_assert_eq!(
                    available_after,
                    initial_permits - acquire_count,
                    "permits should be decremented by acquire count"
                );
            } else {
                // Test blocking when insufficient permits
                let mut fut = sem.acquire(&cx, acquire_count);
                let result = poll_once(&mut fut);
                prop_assert!(
                    result.is_none(),
                    "acquire({}) should block when only {} permits available",
                    acquire_count, initial_permits
                );

                // Add permits to satisfy the acquire
                let needed = acquire_count - initial_permits;
                sem.add_permits(needed);

                let result_after = poll_once(&mut fut);
                prop_assert!(
                    result_after.is_some() && result_after.unwrap().is_ok(),
                    "acquire should complete after adding {} permits",
                    needed
                );
            }
        });

        // Edge case: zero permits semaphore
        let zero_sem = Semaphore::new(0);
        let cx = test_cx();

        let mut fut = zero_sem.acquire(&cx, 1);
        assert!(
            poll_once(&mut fut).is_none(),
            "acquire should block on zero-permit semaphore"
        );

        zero_sem.add_permits(1);
        assert!(
            poll_once(&mut fut).is_some(),
            "acquire should complete after adding permit"
        );
    });
}

/// MR2: try_acquire(n) returns None (no block) if <n available
///
/// Property: try_acquire is always immediate (non-blocking) and returns
/// Err when insufficient permits, Ok when sufficient permits.
#[test]
fn mr2_try_acquire_never_blocks() {
    LabRuntime::test(|lab| async {
        init_test_logging();

        proptest!(|(
            initial_permits in 0usize..=20,
            try_acquire_count in 1usize..=25
        )| {
            let sem = Semaphore::new(initial_permits);

            // Measure execution time to ensure non-blocking
            let start = Instant::now();
            let result = sem.try_acquire(try_acquire_count);
            let elapsed = start.elapsed();

            // Should complete very quickly (< 1ms typically, allow 10ms for CI)
            prop_assert!(
                elapsed < Duration::from_millis(10),
                "try_acquire should be immediate, took {:?}",
                elapsed
            );

            if try_acquire_count <= initial_permits {
                prop_assert!(
                    result.is_ok(),
                    "try_acquire({}) should succeed when {} permits available",
                    try_acquire_count, initial_permits
                );

                let permit = result.unwrap();
                prop_assert_eq!(
                    permit.count(),
                    try_acquire_count,
                    "permit count should match acquire count"
                );

                let available_after = sem.available_permits();
                prop_assert_eq!(
                    available_after,
                    initial_permits - try_acquire_count,
                    "permits should be decremented"
                );
            } else {
                prop_assert!(
                    result.is_err(),
                    "try_acquire({}) should fail when only {} permits available",
                    try_acquire_count, initial_permits
                );

                let available_unchanged = sem.available_permits();
                prop_assert_eq!(
                    available_unchanged,
                    initial_permits,
                    "permits should be unchanged on failed try_acquire"
                );
            }
        });

        // Edge case: try_acquire on closed semaphore should be immediate
        let closed_sem = Semaphore::new(5);
        closed_sem.close();

        let start = Instant::now();
        let result = closed_sem.try_acquire(1);
        let elapsed = start.elapsed();

        assert!(
            elapsed < Duration::from_millis(10),
            "try_acquire on closed semaphore should be immediate"
        );
        assert!(
            result.is_err(),
            "try_acquire should fail on closed semaphore"
        );
    });
}

/// MR3: close() wakes all waiters with Outcome::Cancelled
///
/// Property: Closing a semaphore should immediately wake all pending waiters
/// with AcquireError::Closed, regardless of permit availability.
#[test]
fn mr3_close_wakes_all_waiters() {
    LabRuntime::test(|lab| async {
        init_test_logging();

        proptest!(|(
            initial_permits in 1usize..=5,
            num_waiters in 1usize..=8
        )| {
            let sem = Semaphore::new(initial_permits);

            // Exhaust permits so waiters will queue
            let _held_permits: Vec<_> = (0..initial_permits)
                .map(|_| sem.try_acquire(1).unwrap())
                .collect();

            prop_assert_eq!(
                sem.available_permits(),
                0,
                "all permits should be held"
            );

            // Create waiters
            let mut futures = Vec::new();
            let contexts: Vec<_> = (0..num_waiters)
                .map(|i| Cx::new(
                    RegionId::from_arena(ArenaIndex::new(0, i as u32)),
                    TaskId::from_arena(ArenaIndex::new(0, i as u32)),
                    Budget::INFINITE,
                ))
                .collect();

            for ctx in &contexts {
                let mut fut = sem.acquire(ctx, 1);
                let pending = poll_once(&mut fut).is_none();
                prop_assert!(pending, "waiter should be pending");
                futures.push(fut);
            }

            // Close the semaphore
            sem.close();

            // All waiters should wake with Closed error
            let mut closed_count = 0;
            for mut fut in futures {
                let result = poll_once(&mut fut);
                prop_assert!(
                    result.is_some(),
                    "waiter should wake immediately after close"
                );

                match result.unwrap() {
                    Err(AcquireError::Closed) => closed_count += 1,
                    other => prop_assert!(
                        false,
                        "expected Closed error, got {:?}",
                        other
                    ),
                }
            }

            prop_assert_eq!(
                closed_count,
                num_waiters,
                "all waiters should receive Closed error"
            );

            // Semaphore should be closed and have zero permits
            prop_assert!(sem.is_closed(), "semaphore should be closed");
            prop_assert_eq!(
                sem.available_permits(),
                0,
                "closed semaphore should have zero permits"
            );
        });
    });
}

/// MR4: cancel during acquire releases reservation (no deadlock)
///
/// Property: Cancelling an acquire operation should not leak permits or
/// corrupt semaphore state. Other waiters should still be served correctly.
#[test]
fn mr4_cancel_during_acquire_no_deadlock() {
    LabRuntime::test(|lab| async {
        init_test_logging();

        proptest!(|(
            initial_permits in 1usize..=5,
            num_cancellations in 1usize..=6
        )| {
            let sem = Semaphore::new(initial_permits);

            // Hold all permits to force queueing
            let held_permits: Vec<_> = (0..initial_permits)
                .map(|_| sem.try_acquire(1).unwrap())
                .collect();

            // Create cancellable contexts
            let cancel_contexts: Vec<_> = (0..num_cancellations)
                .map(|i| Cx::new(
                    RegionId::from_arena(ArenaIndex::new(0, (100 + i) as u32)),
                    TaskId::from_arena(ArenaIndex::new(0, (100 + i) as u32)),
                    Budget::INFINITE,
                ))
                .collect();

            // Create regular context for verification
            let verify_cx = Cx::new(
                RegionId::from_arena(ArenaIndex::new(0, 200)),
                TaskId::from_arena(ArenaIndex::new(0, 200)),
                Budget::INFINITE,
            );

            // Start cancellable acquires
            let mut cancel_futures = Vec::new();
            for ctx in &cancel_contexts {
                let mut fut = sem.acquire(ctx, 1);
                let pending = poll_once(&mut fut).is_none();
                prop_assert!(pending, "acquire should be pending");
                cancel_futures.push(fut);
            }

            // Start verification acquire
            let mut verify_fut = sem.acquire(&verify_cx, 1);
            prop_assert!(
                poll_once(&mut verify_fut).is_none(),
                "verification acquire should be pending"
            );

            let permits_before_cancel = sem.available_permits();

            // Cancel all pending acquires
            for ctx in &cancel_contexts {
                ctx.set_cancel_requested(true);
            }

            let mut cancelled_count = 0;
            for mut fut in cancel_futures {
                let result = poll_once(&mut fut);
                if let Some(Err(AcquireError::Cancelled)) = result {
                    cancelled_count += 1;
                }
            }

            prop_assert!(
                cancelled_count > 0,
                "at least one acquire should be cancelled"
            );

            let permits_after_cancel = sem.available_permits();
            prop_assert_eq!(
                permits_after_cancel,
                permits_before_cancel,
                "permit count should be unchanged by cancellation"
            );

            // Release one permit - verification acquire should complete
            drop(held_permits.into_iter().next().unwrap());

            let verify_result = poll_once(&mut verify_fut);
            prop_assert!(
                verify_result.is_some() && verify_result.unwrap().is_ok(),
                "verification acquire should succeed after permit release"
            );
        });
    });
}

/// MR5: FIFO fairness — waiters woken in registration order when permits released
///
/// Property: When multiple waiters are queued and permits become available,
/// waiters should be served in the order they registered (FIFO fairness).
#[test]
fn mr5_fifo_fairness_ordering() {
    LabRuntime::test(|lab| async {
        init_test_logging();

        proptest!(|(
            num_waiters in 2usize..=6
        )| {
            let sem = Semaphore::new(0); // Start with no permits to force queueing

            // Create contexts and futures for waiters
            let contexts: Vec<_> = (0..num_waiters)
                .map(|i| Cx::new(
                    RegionId::from_arena(ArenaIndex::new(0, (300 + i) as u32)),
                    TaskId::from_arena(ArenaIndex::new(0, (300 + i) as u32)),
                    Budget::INFINITE,
                ))
                .collect();

            let mut futures = Vec::new();
            let mut completion_order = Vec::new();

            // Queue all waiters in order
            for (i, ctx) in contexts.iter().enumerate() {
                let mut fut = sem.acquire(ctx, 1);
                let pending = poll_once(&mut fut).is_none();
                prop_assert!(pending, "waiter {} should be pending", i);
                futures.push((i, fut));
            }

            // Release permits one by one and track completion order
            for round in 0..num_waiters {
                sem.add_permits(1);

                // Check which waiter completed
                for (waiter_id, fut) in futures.iter_mut() {
                    if completion_order.contains(waiter_id) {
                        continue; // Already completed
                    }

                    if let Some(result) = poll_once(fut) {
                        prop_assert!(
                            result.is_ok(),
                            "waiter {} should acquire successfully",
                            waiter_id
                        );
                        completion_order.push(*waiter_id);
                        break; // Only one should complete per permit release
                    }
                }

                prop_assert_eq!(
                    completion_order.len(),
                    round + 1,
                    "exactly one waiter should complete per permit release"
                );
            }

            // Verify FIFO order: completion order should match registration order
            for (expected_order, actual_waiter_id) in completion_order.iter().enumerate() {
                prop_assert_eq!(
                    *actual_waiter_id,
                    expected_order,
                    "waiter {} completed out of FIFO order (expected position {})",
                    actual_waiter_id, expected_order
                );
            }

            prop_assert_eq!(
                completion_order.len(),
                num_waiters,
                "all waiters should complete"
            );
        });

        // Edge case: FIFO fairness with cancellations
        let sem = Semaphore::new(0);

        let contexts: Vec<_> = (0..4)
            .map(|i| Cx::new(
                RegionId::from_arena(ArenaIndex::new(0, (400 + i) as u32)),
                TaskId::from_arena(ArenaIndex::new(0, (400 + i) as u32)),
                Budget::INFINITE,
            ))
            .collect();

        // Queue: 0, 1, 2, 3
        let mut futures = Vec::new();
        for ctx in &contexts {
            let mut fut = sem.acquire(ctx, 1);
            assert!(poll_once(&mut fut).is_none(), "should be pending");
            futures.push(fut);
        }

        // Cancel waiters 1 and 2 (middle cancellations)
        contexts[1].set_cancel_requested(true);
        contexts[2].set_cancel_requested(true);

        let result1 = poll_once(&mut futures[1]);
        let result2 = poll_once(&mut futures[2]);
        assert!(matches!(result1, Some(Err(AcquireError::Cancelled))));
        assert!(matches!(result2, Some(Err(AcquireError::Cancelled))));

        // Release permits - should serve remaining waiters in order: 0, then 3
        sem.add_permits(1);
        let result0 = poll_once(&mut futures[0]);
        assert!(result0.is_some() && result0.unwrap().is_ok(), "waiter 0 should complete first");
        assert!(poll_once(&mut futures[3]).is_none(), "waiter 3 should still be pending");

        sem.add_permits(1);
        let result3 = poll_once(&mut futures[3]);
        assert!(result3.is_some() && result3.unwrap().is_ok(), "waiter 3 should complete second");
    });
}

/// Composite test: All metamorphic relations working together
#[test]
fn composite_semaphore_invariants() {
    LabRuntime::test(|lab| async {
        init_test_logging();

        let sem = Semaphore::new(3);

        // MR2: try_acquire immediate behavior
        let permit1 = sem.try_acquire(2).expect("should acquire 2 permits");
        assert_eq!(sem.available_permits(), 1);

        // MR1: acquire blocks when insufficient permits
        let ctx = test_cx();
        let mut blocking_fut = sem.acquire(&ctx, 2);
        assert!(poll_once(&mut blocking_fut).is_none(), "should block for 2 permits");

        // MR4: cancel during acquire doesn't affect permit count
        ctx.set_cancel_requested(true);
        let cancel_result = poll_once(&mut blocking_fut);
        assert!(matches!(cancel_result, Some(Err(AcquireError::Cancelled))));
        assert_eq!(sem.available_permits(), 1, "permits unchanged by cancellation");

        // MR1: acquire succeeds when permits available
        drop(permit1); // Release 2 permits -> total 3
        let ctx2 = test_cx();
        let mut success_fut = sem.acquire(&ctx2, 2);
        let success_result = poll_once(&mut success_fut);
        assert!(success_result.is_some() && success_result.unwrap().is_ok());

        // MR3: close wakes all waiters
        let ctx3 = test_cx();
        let mut final_fut = sem.acquire(&ctx3, 1);
        assert!(poll_once(&mut final_fut).is_none(), "should block when permits exhausted");

        sem.close();
        let close_result = poll_once(&mut final_fut);
        assert!(matches!(close_result, Some(Err(AcquireError::Closed))));

        // MR2: try_acquire still immediate on closed semaphore
        let start = Instant::now();
        let closed_try = sem.try_acquire(1);
        let elapsed = start.elapsed();
        assert!(elapsed < Duration::from_millis(10), "try_acquire should be immediate");
        assert!(closed_try.is_err(), "should fail on closed semaphore");
    });
}