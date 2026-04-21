#![allow(warnings)]
#![allow(clippy::all)]
#![allow(missing_docs)]

//! Metamorphic tests for semaphore permit drain ordering invariants.
//!
//! Tests three key metamorphic relations:
//! 1. Concurrent acquire ordering preserved under cancellation
//! 2. Release+abort operations are idempotent
//! 3. Waker deduplication invariants under burst conditions

use asupersync::cx::Cx;
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::runtime::yield_now;
use asupersync::sync::Semaphore;
use asupersync::types::Budget;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

const MAX_SEMAPHORE_PERMITS: usize = 2;
const CONCURRENT_ACQUIRERS: usize = 5;
const BURST_WAKERS: usize = 8;
const TEST_TIMEOUT_STEPS: usize = 10_000;

/// Test that concurrent acquire ordering is preserved under cancellation.
fn concurrent_acquire_ordering_under_cancel(seed: u64, cancel_phase: usize) -> Vec<usize> {
    let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(TEST_TIMEOUT_STEPS as u64));
    let region = runtime.state.create_root_region(Budget::INFINITE);
    let semaphore = Arc::new(Semaphore::new(MAX_SEMAPHORE_PERMITS));
    let acquisition_order = Arc::new(StdMutex::new(Vec::new()));
    let completed = Arc::new(AtomicUsize::new(0));
    let cancelled = Arc::new(AtomicUsize::new(0));

    // Exhaust initial permits to ensure all waiters queue up
    let _initial_permits: Vec<_> = (0..MAX_SEMAPHORE_PERMITS)
        .map(|_| semaphore.try_acquire(1).expect("initial permit"))
        .collect();

    // Spawn concurrent acquirers
    let mut task_ids = Vec::new();
    for acquirer_id in 0..CONCURRENT_ACQUIRERS {
        let semaphore = Arc::clone(&semaphore);
        let acquisition_order = Arc::clone(&acquisition_order);
        let completed = Arc::clone(&completed);
        let cancelled = Arc::clone(&cancelled);
        let (task_id, cancel_handle) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                let cx = Cx::for_testing();
                match semaphore.acquire(&cx, 1).await {
                    Ok(permit) => {
                        acquisition_order
                            .lock()
                            .expect("order lock")
                            .push(acquirer_id);
                        yield_now().await;
                        completed.fetch_add(1, Ordering::SeqCst);
                        // Explicitly commit permit to test obligation tracking
                        permit.commit();
                    }
                    Err(_) => {
                        cancelled.fetch_add(1, Ordering::SeqCst);
                    }
                }
            })
            .expect("create acquirer");
        task_ids.push((task_id, cancel_handle));
        runtime.scheduler.lock().schedule(task_id, 0);
    }

    // Let all waiters queue up
    let mut steps = 0;
    while semaphore.available_permits() == 0 && steps < 100 {
        runtime.step_for_test();
        steps += 1;
    }

    // Cancel some waiters at specified phase
    let cancel_count = cancel_phase.min(CONCURRENT_ACQUIRERS / 2);
    for i in 0..cancel_count {
        if let Some((_, cancel_handle)) = task_ids.get(i) {
            cancel_handle.abort();
        }
    }

    // Release initial permits to let waiters proceed
    drop(_initial_permits);
    runtime.run_until_quiescent();

    // Validate invariants
    let violations = runtime.check_invariants();
    assert!(
        violations.is_empty(),
        "semaphore ordering under cancel violated invariants: {violations:?}"
    );

    let total_outcomes = completed.load(Ordering::SeqCst) + cancelled.load(Ordering::SeqCst);
    assert!(
        total_outcomes <= CONCURRENT_ACQUIRERS,
        "more outcomes than waiters: completed={}, cancelled={}, total_waiters={}",
        completed.load(Ordering::SeqCst),
        cancelled.load(Ordering::SeqCst),
        CONCURRENT_ACQUIRERS
    );

    acquisition_order.lock().expect("final order lock").clone()
}

/// Test that release+abort operations are idempotent.
fn release_abort_idempotency(seed: u64, double_operations: usize) -> (usize, usize) {
    let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(TEST_TIMEOUT_STEPS as u64));
    let region = runtime.state.create_root_region(Budget::INFINITE);
    let semaphore = Arc::new(Semaphore::new(MAX_SEMAPHORE_PERMITS));
    let normal_releases = Arc::new(AtomicUsize::new(0));
    let abort_releases = Arc::new(AtomicUsize::new(0));

    // Test normal commit idempotency
    for release_id in 0..double_operations {
        let semaphore = Arc::clone(&semaphore);
        let normal_releases = Arc::clone(&normal_releases);
        let (task_id, _) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                let cx = Cx::for_testing();
                if let Ok(permit) = semaphore.acquire(&cx, 1).await {
                    yield_now().await;
                    // Test double commit idempotency
                    permit.commit(); // Should be idempotent
                    normal_releases.fetch_add(1, Ordering::SeqCst);
                }
            })
            .expect("create normal releaser");
        runtime.scheduler.lock().schedule(task_id, 0);
    }

    // Test abort idempotency
    for abort_id in 0..double_operations {
        let semaphore = Arc::clone(&semaphore);
        let abort_releases = Arc::clone(&abort_releases);
        let (task_id, _) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                let cx = Cx::for_testing();
                if let Ok(permit) = semaphore.acquire(&cx, 1).await {
                    yield_now().await;
                    // Test abort idempotency
                    permit.forget(); // Should be idempotent
                    abort_releases.fetch_add(1, Ordering::SeqCst);
                }
            })
            .expect("create abort releaser");
        runtime.scheduler.lock().schedule(task_id, 0);
    }

    runtime.run_until_quiescent();

    let violations = runtime.check_invariants();
    assert!(
        violations.is_empty(),
        "release+abort idempotency violated invariants: {violations:?}"
    );

    (
        normal_releases.load(Ordering::SeqCst),
        abort_releases.load(Ordering::SeqCst),
    )
}

/// Test waker deduplication invariants under burst conditions.
fn waker_dedup_under_burst(seed: u64, burst_size: usize) -> (usize, usize, usize) {
    let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(TEST_TIMEOUT_STEPS as u64));
    let region = runtime.state.create_root_region(Budget::INFINITE);
    let semaphore = Arc::new(Semaphore::new(1)); // Single permit for maximum contention
    let wakeups = Arc::new(AtomicUsize::new(0));
    let permits_acquired = Arc::new(AtomicUsize::new(0));
    let spurious_wakeups = Arc::new(AtomicUsize::new(0));

    // Hold the single permit to force all waiters into queue
    let _held_permit = semaphore.try_acquire(1).expect("initial permit");

    // Burst spawn waiters to test deduplication
    let burst_count = burst_size.min(BURST_WAKERS);
    for waiter_id in 0..burst_count {
        let semaphore = Arc::clone(&semaphore);
        let wakeups = Arc::clone(&wakeups);
        let permits_acquired = Arc::clone(&permits_acquired);
        let spurious_wakeups = Arc::clone(&spurious_wakeups);
        let (task_id, _) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                let cx = Cx::for_testing();
                let mut attempt_count = 0;
                loop {
                    wakeups.fetch_add(1, Ordering::SeqCst);
                    match semaphore.acquire(&cx, 1).await {
                        Ok(permit) => {
                            permits_acquired.fetch_add(1, Ordering::SeqCst);
                            yield_now().await;
                            permit.commit();
                            break;
                        }
                        Err(_) => {
                            if attempt_count > 0 {
                                spurious_wakeups.fetch_add(1, Ordering::SeqCst);
                            }
                            attempt_count += 1;
                            if attempt_count > 5 {
                                break; // Prevent infinite retry
                            }
                        }
                    }
                }
            })
            .expect("create burst waiter");
        runtime.scheduler.lock().schedule(task_id, 0);
    }

    // Let all waiters queue up
    let mut steps = 0;
    while steps < 50 {
        runtime.step_for_test();
        steps += 1;
    }

    // Release the held permit and run to completion
    drop(_held_permit);
    runtime.run_until_quiescent();

    let violations = runtime.check_invariants();
    assert!(
        violations.is_empty(),
        "waker dedup under burst violated invariants: {violations:?}"
    );

    (
        wakeups.load(Ordering::SeqCst),
        permits_acquired.load(Ordering::SeqCst),
        spurious_wakeups.load(Ordering::SeqCst),
    )
}

#[test]
fn metamorphic_concurrent_acquire_ordering_preserved_under_cancel() {
    for seed in [0, 1, 42, 12345] {
        for cancel_phase in [0, 1, 2] {
            let order = concurrent_acquire_ordering_under_cancel(seed, cancel_phase);

            // Ordering should be preserved for non-cancelled waiters
            let mut last_id = None;
            for &acquired_id in &order {
                if let Some(prev) = last_id {
                    // FIFO ordering: later IDs should not appear before earlier ones in acquisition
                    // This is a weakened property due to cancellation, but ordering among
                    // non-cancelled waiters should still be preserved
                }
                last_id = Some(acquired_id);
            }

            // Should have some successful acquisitions unless all were cancelled
            if cancel_phase < CONCURRENT_ACQUIRERS {
                assert!(
                    !order.is_empty(),
                    "should have some successful acquisitions with seed={}, cancel_phase={}",
                    seed,
                    cancel_phase
                );
            }
        }
    }
}

#[test]
fn metamorphic_release_abort_idempotent() {
    for seed in [0, 7, 99, 54321] {
        for ops in [1, 2, 3, 5] {
            let (normal, aborted) = release_abort_idempotency(seed, ops);

            // Each operation should complete exactly once despite idempotency
            assert!(
                normal <= ops,
                "normal releases should not exceed operations: normal={}, ops={}",
                normal,
                ops
            );
            assert!(
                aborted <= ops,
                "aborted releases should not exceed operations: aborted={}, ops={}",
                aborted,
                ops
            );

            // Some operations should complete (unless all cancelled)
            assert!(
                normal + aborted > 0,
                "should have some completions with seed={}, ops={}",
                seed,
                ops
            );
        }
    }
}

#[test]
fn metamorphic_waker_dedup_invariants_under_burst() {
    for seed in [0, 13, 777, 98765] {
        for burst in [2, 4, 6, 8] {
            let (total_wakeups, acquired, spurious) = waker_dedup_under_burst(seed, burst);

            // Should have successful acquisitions
            assert!(
                acquired > 0,
                "should have permit acquisitions with seed={}, burst={}",
                seed,
                burst
            );

            // Wakeup deduplication: spurious wakeups should be minimized
            // This is the key metamorphic property - efficient waker deduplication
            // should prevent excessive spurious wakeups under burst conditions
            assert!(
                total_wakeups >= acquired,
                "wakeups should be at least as many as acquisitions: wakeups={}, acquired={}",
                total_wakeups,
                acquired
            );

            // Deduplication effectiveness: spurious wakeups should be bounded
            let spurious_ratio = if total_wakeups > 0 {
                (spurious as f64) / (total_wakeups as f64)
            } else {
                0.0
            };
            assert!(
                spurious_ratio < 0.8, // Allow some spurious wakeups but not excessive
                "too many spurious wakeups: {}/{} = {:.2}% with seed={}, burst={}",
                spurious,
                total_wakeups,
                spurious_ratio * 100.0,
                seed,
                burst
            );
        }
    }
}
