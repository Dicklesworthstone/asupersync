#![allow(warnings)]
#![allow(clippy::all)]
//! Metamorphic Tests: sync::Semaphore Invariants
//!
//! Tests metamorphic relations for semaphore correctness using LabRuntime + proptest.

#![cfg(test)]

use asupersync::{
    cx::Cx,
    lab::{LabConfig, LabRuntime},
    sync::semaphore::{AcquireError, Semaphore, SemaphorePermit},
    types::{Budget, Outcome, RegionId, TaskId},
    util::ArenaIndex,
};
use proptest::prelude::*;
use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

/// Helper to create a test context
fn test_cx() -> Cx {
    Cx::for_testing()
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
#[test]
fn mr1_acquire_blocks_until_permits_available() {
    proptest!(|(
        initial_permits in 1usize..=10,
        acquire_count in 1usize..=15
    )| {
        let sem = Semaphore::new(initial_permits);
        let cx = test_cx();

        // Test immediate acquire when permits available
        if acquire_count <= initial_permits {
            let mut fut = sem.acquire(&cx, acquire_count);
            let result = poll_once(&mut fut);
            prop_assert!(result.is_some(), "should succeed immediately");
            let permit_res = result.unwrap();
            prop_assert!(permit_res.is_ok(), "should be ok");
            let _permit = permit_res.unwrap();

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
            prop_assert!(result_after.is_some(), "should succeed after adding permits");
            let _permit = result_after.unwrap().unwrap();
        }
    });
}

/// MR2: try_acquire(n) returns Err (no block) if <n available
#[test]
fn mr2_try_acquire_never_blocks() {
    proptest!(|(
        initial_permits in 0usize..=20,
        try_acquire_count in 1usize..=25
    )| {
        let sem = Semaphore::new(initial_permits);

        let result = sem.try_acquire(try_acquire_count);

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
}

/// MR3: close() wakes all waiters with Outcome::Cancelled
#[test]
fn mr3_close_wakes_all_waiters() {
    proptest!(|(
        initial_permits in 1usize..=5,
        num_waiters in 1usize..=8
    )| {
        let sem = Semaphore::new(initial_permits);

        // Exhaust permits so waiters will queue
        let _held_permits: Vec<_> = (0..initial_permits)
            .map(|_| sem.try_acquire(1).unwrap())
            .collect();

        // Create waiters
        let contexts: Vec<_> = (0..num_waiters)
            .map(|_| test_cx())
            .collect();
        let mut futures = Vec::new();

        for ctx in &contexts {
            let mut fut = sem.acquire(ctx, 1);
            let pending = poll_once(&mut fut).is_none();
            prop_assert!(pending, "waiter should be pending");
            futures.push(fut);
        }

        // Close the semaphore
        sem.close();

        // All waiters should wake with Closed error
        for mut fut in futures {
            let result = poll_once(&mut fut);
            prop_assert!(
                result.is_some(),
                "waiter should wake immediately after close"
            );

            match result.unwrap() {
                Err(AcquireError::Closed) => {},
                _ => prop_assert!(false, "expected Closed error"),
            }
        }
    });
}

/// MR4: cancel during acquire releases reservation (no deadlock)
#[test]
fn mr4_cancel_during_acquire_no_deadlock() {
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
            .map(|_| test_cx())
            .collect();

        // Create regular context for verification
        let verify_cx = test_cx();

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

        // Cancel all pending acquires
        for ctx in &cancel_contexts {
            ctx.set_cancel_requested(true);
        }

        for mut fut in cancel_futures {
            let result = poll_once(&mut fut);
            prop_assert!(matches!(result, Some(Err(AcquireError::Cancelled))));
        }

        // Release one permit - verification acquire should complete
        drop(held_permits.into_iter().next().unwrap());

        let verify_result = poll_once(&mut verify_fut);
        prop_assert!(verify_result.is_some());
        let _permit = verify_result.unwrap().unwrap();
    });
}

/// MR5: FIFO fairness
#[test]
fn mr5_fifo_fairness_ordering() {
    proptest!(|(
        num_waiters in 2usize..=6
    )| {
        let sem = Semaphore::new(0);

        let contexts: Vec<_> = (0..num_waiters)
            .map(|_| test_cx())
            .collect();

        let mut futures = Vec::new();
        let mut completion_order = Vec::new();

        for (i, ctx) in contexts.iter().enumerate() {
            let mut fut = sem.acquire(ctx, 1);
            futures.push((i, fut));
        }

        for round in 0..num_waiters {
            sem.add_permits(1);

            for (waiter_id, fut) in futures.iter_mut() {
                if completion_order.contains(waiter_id) {
                    continue;
                }

                if let Some(result) = poll_once(fut) {
                    prop_assert!(result.is_ok());
                    completion_order.push(*waiter_id);
                    break;
                }
            }
        }

        for (expected_order, actual_waiter_id) in completion_order.iter().enumerate() {
            prop_assert_eq!(*actual_waiter_id, expected_order);
        }
    });
}

/// MR6: Permit Conservation
#[test]
fn mr6_permit_conservation_stress() {
    proptest!(|(
        initial_permits in 1usize..=50,
        num_tasks in 10usize..=40
    )| {
        let mut lab = LabRuntime::new(LabConfig::new(0xDEADBEEF));
        let root = lab.state.create_root_region(Budget::INFINITE);
        let sem = Arc::new(Semaphore::new(initial_permits));

        for i in 0..num_tasks {
            let sem = Arc::clone(&sem);
            let (task_id, _) = lab.state.create_task(root, Budget::INFINITE, async move {
                let cx = Cx::for_testing();

                if i % 3 == 0 {
                    let mut fut = sem.acquire(&cx, 1);
                    let _ = poll_once(&mut fut);
                    cx.set_cancel_requested(true);
                    let _ = poll_once(&mut fut);
                } else if i % 3 == 1 {
                    if let Ok(permit) = sem.try_acquire(1) {
                        drop(permit);
                    }
                } else {
                    if let Ok(permit) = sem.acquire(&cx, 1).await {
                        drop(permit);
                    }
                }
            }).unwrap();
            lab.scheduler.lock().schedule(task_id, 0);
        }

        lab.run_until_quiescent();

        prop_assert_eq!(
            sem.available_permits(),
            initial_permits,
            "Permits must be conserved"
        );
    });
}

/// MR7: FIFO Fairness under High Contention (32+ waiters)
#[test]
fn mr7_high_contention_fifo() {
    let num_waiters = 64;
    let sem = Semaphore::new(0);

    let contexts: Vec<_> = (0..num_waiters).map(|_| test_cx()).collect();
    let mut futures = Vec::new();

    for i in 0..num_waiters {
        let mut fut = sem.acquire(&contexts[i], 1);
        assert!(poll_once(&mut fut).is_none());
        futures.push(fut);
    }

    for i in 0..num_waiters {
        sem.add_permits(1);
        let result = poll_once(&mut futures[i]);
        assert!(result.is_some());
        let _permit = result.unwrap().unwrap();
    }
}

/// MR8: try_acquire vs acquire consistency
#[test]
fn mr8_try_acquire_consistency() {
    proptest!(|(
        initial_permits in 2usize..=10
    )| {
        let sem = Semaphore::new(initial_permits);
        let cx1 = test_cx();
        let cx2 = test_cx();

        let mut fut1 = sem.acquire(&cx1, initial_permits + 1);
        prop_assert!(poll_once(&mut fut1).is_none());

        let try_res = sem.try_acquire(1);
        prop_assert!(try_res.is_err());

        let mut fut2 = sem.acquire(&cx2, 1);
        prop_assert!(poll_once(&mut fut2).is_none());

        cx1.set_cancel_requested(true);
        let _ = poll_once(&mut fut1);

        let try_res2 = sem.try_acquire(1);
        if try_res2.is_err() {
            let res2 = poll_once(&mut fut2);
            prop_assert!(res2.is_some());
        }
    });
}
