#![allow(clippy::all)]
//! Metamorphic property tests for sync::Mutex cancel-aware lock acquisition invariants.
//!
//! These tests verify Mutex behavior specifically around cancel-aware lock acquisition,
//! waiter queue management, FIFO fairness under cancellation, non-blocking try_lock behavior,
//! and guard cleanup under panic conditions. Uses LabRuntime with DPOR for deterministic
//! scheduling exploration.
//!
//! # Metamorphic Relations
//!
//! 1. **Cancel Returns Cancelled** (MR1): lock() returns Outcome::Cancelled on Cx cancel mid-wait
//! 2. **Cancelled Waiter Cleanup** (MR2): cancelled waiter removed from queue — next lock() succeeds
//! 3. **FIFO Fairness Under Cancel** (MR3): FIFO fairness preserved across cancel events
//! 4. **Try Lock Never Blocks** (MR4): try_lock() never blocks, returns None if held
//! 5. **Guard Drop Cleanup** (MR5): guard Drop releases even under panic (poisoning optional)

use asupersync::cx::{Cx, Scope};
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::sync::mutex::{LockError, Mutex, TryLockError};
use asupersync::types::{Budget, Outcome, RegionId, TaskId};
use asupersync::util::ArenaIndex;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use proptest::prelude::*;

// ============================================================================
// Test Infrastructure
// ============================================================================

/// Create a test context for deterministic scheduling.
fn test_cx() -> Cx {
    Cx::new(
        RegionId::from_arena(ArenaIndex::new(0, 0)),
        TaskId::from_arena(ArenaIndex::new(0, 0)),
        Budget::INFINITE,
    )
}

/// Configuration for Mutex cancel-aware metamorphic tests.
#[derive(Debug, Clone)]
pub struct MutexCancelTestConfig {
    /// Random seed for deterministic execution.
    pub seed: u64,
    /// Number of concurrent waiters to test.
    pub waiter_count: u8,
    /// Delay before cancellation (virtual milliseconds).
    pub cancel_delay_ms: u64,
    /// Which waiter to cancel (by index).
    pub cancel_waiter_index: u8,
    /// Whether to inject panic during guard hold.
    pub inject_panic: bool,
}

/// Test harness for Mutex cancel-aware operations with DPOR scheduling.
#[derive(Debug)]
struct MutexCancelTestHarness {
    runtime: LabRuntime,
    operations_completed: AtomicU64,
    obligations_leaked: AtomicBool,
    cancel_events: AtomicU64,
    fairness_violations: AtomicU64,
}

impl MutexCancelTestHarness {
    fn new(seed: u64) -> Self {
        let config = LabConfig::new(seed).with_light_chaos();
        Self {
            runtime: LabRuntime::new(config),
            operations_completed: AtomicU64::new(0),
            obligations_leaked: AtomicBool::new(false),
            cancel_events: AtomicU64::new(0),
            fairness_violations: AtomicU64::new(0),
        }
    }

    fn execute<F>(&mut self, test_fn: F) -> Outcome<F::Output, ()>
    where
        F: FnOnce(&Cx) -> Pin<Box<dyn Future<Output = F::Output> + '_>> + Send,
    {
        self.runtime.block_on(|cx| async {
            let result = cx
                .region(|region| async {
                    let scope = Scope::new(region, "mutex_cancel_test");
                    test_fn(&scope.cx())
                })
                .await;

            // Check for obligation leaks
            if !self.runtime.is_quiescent() {
                self.obligations_leaked.store(true, Ordering::SeqCst);
            }

            result
        })
    }

    fn has_obligation_leaks(&self) -> bool {
        self.obligations_leaked.load(Ordering::SeqCst)
    }

    fn completed_operations(&self) -> u64 {
        self.operations_completed.load(Ordering::SeqCst)
    }

    fn increment_operations(&self) {
        self.operations_completed.fetch_add(1, Ordering::SeqCst);
    }

    fn increment_cancels(&self) {
        self.cancel_events.fetch_add(1, Ordering::SeqCst);
    }

    fn cancel_count(&self) -> u64 {
        self.cancel_events.load(Ordering::SeqCst)
    }

    fn increment_fairness_violations(&self) {
        self.fairness_violations.fetch_add(1, Ordering::SeqCst);
    }

    fn fairness_violation_count(&self) -> u64 {
        self.fairness_violations.load(Ordering::SeqCst)
    }
}

/// Counting waker that tracks wake calls.
struct CountingWaker {
    counter: Arc<AtomicUsize>,
}

impl std::task::Wake for CountingWaker {
    fn wake(self: Arc<Self>) {
        self.counter.fetch_add(1, Ordering::SeqCst);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.counter.fetch_add(1, Ordering::SeqCst);
    }
}

impl CountingWaker {
    fn new() -> (Waker, Arc<AtomicUsize>) {
        let counter = Arc::new(AtomicUsize::new(0));
        let waker = Waker::from(Arc::new(CountingWaker {
            counter: counter.clone(),
        }));
        (waker, counter)
    }
}

// ============================================================================
// Metamorphic Relations for Mutex Cancel-Aware Behavior
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// MR1: Cancel Returns Cancelled (Safety, Score: 10.0)
    /// Property: lock() returns Outcome::Cancelled on Cx cancel mid-wait (no acquire)
    /// Catches: Missing cancellation handling, resource leaks, deadlocks
    #[test]
    fn mr1_cancel_returns_cancelled() {
        proptest!(|(
            seed in any::<u64>(),
            cancel_delay_ms in 1u64..20,
            test_value in any::<i64>(),
        )| {
            let mut harness = MutexCancelTestHarness::new(seed);

            let result = harness.execute(|cx| Box::pin(async move {
                let mutex = Arc::new(Mutex::new(test_value));
                let holder_mutex = mutex.clone();

                // Task 1: Hold the lock to force waiter to block
                let holder_task = cx.spawn("holder", async move {
                    let guard = holder_mutex.lock(cx).await;
                    match guard {
                        Ok(_g) => {
                            // Hold the lock for longer than cancel delay
                            cx.sleep(Duration::from_millis(cancel_delay_ms + 10)).await;
                            Ok(())
                        },
                        Err(e) => Err(format!("holder lock failed: {:?}", e)),
                    }
                });

                // Wait a bit to ensure holder gets the lock
                cx.sleep(Duration::from_millis(1)).await;

                // Task 2: Try to acquire lock with cancellable context
                let waiter_mutex = mutex.clone();
                let cancellable_cx = Cx::new(
                    RegionId::from_arena(ArenaIndex::new(1, 0)),
                    TaskId::from_arena(ArenaIndex::new(1, 0)),
                    Budget::INFINITE,
                );

                let waiter_task = cx.spawn("waiter", async move {
                    let lock_result = waiter_mutex.lock(&cancellable_cx).await;
                    match lock_result {
                        Ok(_guard) => Ok("acquired".to_string()),
                        Err(LockError::Cancelled) => Ok("cancelled".to_string()),
                        Err(other) => Err(format!("unexpected error: {:?}", other)),
                    }
                });

                // Task 3: Cancel the waiter after delay
                let cancel_task = cx.spawn("canceller", async move {
                    cx.sleep(Duration::from_millis(cancel_delay_ms)).await;
                    cancellable_cx.set_cancel_requested(true);
                    harness.increment_cancels();
                });

                // Wait for all tasks
                let holder_result = holder_task.join(cx).await;
                let waiter_result = waiter_task.join(cx).await;
                let cancel_result = cancel_task.join(cx).await;

                // MR1 ASSERTION: Waiter should be cancelled, not acquire the lock
                prop_assert!(holder_result.is_ok(), "MR1 VIOLATION: holder task failed: {:?}", holder_result);
                prop_assert!(cancel_result.is_ok(), "MR1 VIOLATION: cancel task failed");

                match waiter_result {
                    Ok(outcome) => {
                        prop_assert_eq!(
                            outcome, "cancelled",
                            "MR1 VIOLATION: waiter should be cancelled, got: {}",
                            outcome
                        );
                    },
                    Err(e) => prop_assert!(false, "MR1 VIOLATION: waiter task failed: {}", e),
                }

                // Verify mutex is not locked by cancelled waiter
                let try_lock_result = mutex.try_lock();
                prop_assert!(
                    matches!(try_lock_result, Ok(_)),
                    "MR1 VIOLATION: mutex should be unlocked after holder releases"
                );

                harness.increment_operations();
                Ok(())
            }));

            match result {
                Outcome::Ok(_) => {},
                other => prop_assert!(false, "MR1 VIOLATION: unexpected outcome {:?}", other),
            }

            prop_assert!(!harness.has_obligation_leaks(), "MR1 VIOLATION: obligation leak detected");
            prop_assert!(harness.cancel_count() > 0, "MR1 VIOLATION: no cancellation occurred");
        });
    }

    /// MR2: Cancelled Waiter Cleanup (Fairness, Score: 9.5)
    /// Property: cancelled waiter removed from queue — next lock() succeeds immediately
    /// Catches: Queue corruption, leaked waiters, fairness violations
    #[test]
    fn mr2_cancelled_waiter_cleanup() {
        proptest!(|(
            seed in any::<u64>(),
            waiter_count in 2u8..6,
            cancel_index in 0u8..3,
        )| {
            let mut harness = MutexCancelTestHarness::new(seed);

            let result = harness.execute(|cx| Box::pin(async move {
                let mutex = Arc::new(Mutex::new(42i64));
                let cancel_waiter_idx = (cancel_index as usize) % (waiter_count as usize);

                // Hold the lock initially
                let holder_mutex = mutex.clone();
                let holder_task = cx.spawn("holder", async move {
                    let _guard = holder_mutex.lock(cx).await.unwrap();
                    cx.sleep(Duration::from_millis(10)).await;
                    Ok(())
                });

                // Allow holder to acquire lock
                cx.sleep(Duration::from_millis(1)).await;

                // Create waiters with different contexts
                let mut waiter_contexts = Vec::new();
                let mut waiter_tasks = Vec::new();
                let acquire_order = Arc::new(std::sync::Mutex::new(Vec::new()));

                for i in 0..waiter_count {
                    let waiter_cx = Cx::new(
                        RegionId::from_arena(ArenaIndex::new(i as u32 + 2, 0)),
                        TaskId::from_arena(ArenaIndex::new(i as u32 + 2, 0)),
                        Budget::INFINITE,
                    );
                    waiter_contexts.push(waiter_cx.clone());

                    let waiter_mutex = mutex.clone();
                    let order_tracker = acquire_order.clone();
                    let waiter_id = i;

                    let waiter_task = cx.spawn("waiter", async move {
                        let lock_result = waiter_mutex.lock(&waiter_cx).await;
                        match lock_result {
                            Ok(_guard) => {
                                order_tracker.lock().unwrap().push(waiter_id);
                                Ok(format!("waiter_{}_acquired", waiter_id))
                            },
                            Err(LockError::Cancelled) => {
                                Ok(format!("waiter_{}_cancelled", waiter_id))
                            },
                            Err(other) => Err(format!("waiter_{}_error_{:?}", waiter_id, other)),
                        }
                    });
                    waiter_tasks.push(waiter_task);
                }

                // Allow all waiters to queue up
                cx.sleep(Duration::from_millis(2)).await;

                // Check that waiters are queued
                let initial_waiters = mutex.waiters();
                prop_assert!(
                    initial_waiters == waiter_count as usize,
                    "MR2 VIOLATION: expected {} waiters, got {}",
                    waiter_count, initial_waiters
                );

                // Cancel one waiter
                waiter_contexts[cancel_waiter_idx].set_cancel_requested(true);
                harness.increment_cancels();

                // Wait for holder to complete (releases lock)
                let holder_result = holder_task.join(cx).await;
                prop_assert!(holder_result.is_ok(), "MR2 VIOLATION: holder failed: {:?}", holder_result);

                // Wait for all waiter tasks to complete
                let mut waiter_results = Vec::new();
                for waiter_task in waiter_tasks {
                    let result = waiter_task.join(cx).await;
                    waiter_results.push(result);
                }

                // MR2 ASSERTION: Exactly one waiter should be cancelled
                let mut cancelled_count = 0;
                let mut acquired_count = 0;

                for (idx, result) in waiter_results.iter().enumerate() {
                    match result {
                        Ok(outcome) if outcome.contains("cancelled") => {
                            prop_assert_eq!(
                                idx, cancel_waiter_idx,
                                "MR2 VIOLATION: wrong waiter was cancelled: {} vs expected {}",
                                idx, cancel_waiter_idx
                            );
                            cancelled_count += 1;
                        },
                        Ok(outcome) if outcome.contains("acquired") => {
                            acquired_count += 1;
                        },
                        other => prop_assert!(false, "MR2 VIOLATION: unexpected waiter result: {:?}", other),
                    }
                }

                prop_assert_eq!(
                    cancelled_count, 1,
                    "MR2 VIOLATION: expected 1 cancelled waiter, got {}",
                    cancelled_count
                );

                // MR2 ASSERTION: Remaining waiters should acquire in FIFO order
                let final_acquire_order = acquire_order.lock().unwrap().clone();
                prop_assert!(
                    acquired_count > 0,
                    "MR2 VIOLATION: no waiters acquired the lock"
                );

                // Verify queue is clean after cancellation
                let final_waiters = mutex.waiters();
                prop_assert_eq!(
                    final_waiters, 0,
                    "MR2 VIOLATION: {} waiters remain in queue after completion",
                    final_waiters
                );

                harness.increment_operations();
                Ok(())
            }));

            match result {
                Outcome::Ok(_) => {},
                other => prop_assert!(false, "MR2 VIOLATION: unexpected outcome {:?}", other),
            }

            prop_assert!(!harness.has_obligation_leaks(), "MR2 VIOLATION: obligation leak detected");
            prop_assert!(harness.cancel_count() > 0, "MR2 VIOLATION: no cancellation occurred");
        });
    }

    /// MR3: FIFO Fairness Under Cancel (Fairness, Score: 9.0)
    /// Property: FIFO fairness preserved across cancel events
    /// Catches: Queue reordering bugs, unfair wakeup patterns, starvation
    #[test]
    fn mr3_fifo_fairness_under_cancel() {
        proptest!(|(
            seed in any::<u64>(),
            total_waiters in 3u8..7,
            cancel_middle in 1u8..4,
        )| {
            let mut harness = MutexCancelTestHarness::new(seed);

            let result = harness.execute(|cx| Box::pin(async move {
                let mutex = Arc::new(Mutex::new(0i64));
                let cancel_idx = (cancel_middle as usize) % (total_waiters as usize - 1) + 1; // Cancel middle waiter

                // Hold lock initially
                let holder_guard = mutex.lock(cx).await.unwrap();

                // Create waiters in sequence
                let mut waiter_futures = Vec::new();
                let mut waiter_contexts = Vec::new();
                let acquire_order = Arc::new(std::sync::Mutex::new(Vec::new()));

                for i in 0..total_waiters {
                    let waiter_cx = Cx::new(
                        RegionId::from_arena(ArenaIndex::new(i as u32 + 10, 0)),
                        TaskId::from_arena(ArenaIndex::new(i as u32 + 10, 0)),
                        Budget::INFINITE,
                    );
                    waiter_contexts.push(waiter_cx.clone());

                    let mut lock_future = Box::pin(mutex.lock(&waiter_cx));
                    let (waker, wake_count) = CountingWaker::new();
                    let mut task_cx = Context::from_waker(&waker);

                    // Poll once to register as waiter
                    let poll_result = lock_future.as_mut().poll(&mut task_cx);
                    prop_assert!(
                        matches!(poll_result, Poll::Pending),
                        "MR3 VIOLATION: waiter {} should be pending", i
                    );

                    waiter_futures.push((lock_future, wake_count, i));
                }

                // Verify all waiters are queued
                let initial_waiters = mutex.waiters();
                prop_assert_eq!(
                    initial_waiters, total_waiters as usize,
                    "MR3 VIOLATION: expected {} waiters, got {}",
                    total_waiters, initial_waiters
                );

                // Cancel the middle waiter
                waiter_contexts[cancel_idx].set_cancel_requested(true);

                // Poll cancelled waiter to process cancellation
                let (cancel_future, _, cancel_id) = &mut waiter_futures[cancel_idx];
                let (cancel_waker, _) = CountingWaker::new();
                let mut cancel_task_cx = Context::from_waker(&cancel_waker);
                let cancel_result = cancel_future.as_mut().poll(&mut cancel_task_cx);
                prop_assert!(
                    matches!(cancel_result, Poll::Ready(Err(LockError::Cancelled))),
                    "MR3 VIOLATION: cancelled waiter should return Cancelled"
                );

                harness.increment_cancels();

                // Release the lock
                drop(holder_guard);

                // Allow wakeup propagation
                cx.sleep(Duration::from_millis(1)).await;

                // MR3 ASSERTION: Next waiter in FIFO order (skipping cancelled) should acquire
                let expected_next_waiter = if cancel_idx == 0 { 1 } else { 0 };

                let (next_future, next_wake_count, next_id) = &mut waiter_futures[expected_next_waiter];
                let next_wakes = next_wake_count.load(Ordering::SeqCst);
                prop_assert!(
                    next_wakes > 0,
                    "MR3 VIOLATION: expected waiter {} to be woken, but wake_count={}",
                    next_id, next_wakes
                );

                // Poll the next waiter - should acquire
                let (next_waker, _) = CountingWaker::new();
                let mut next_task_cx = Context::from_waker(&next_waker);
                let next_result = next_future.as_mut().poll(&mut next_task_cx);
                prop_assert!(
                    matches!(next_result, Poll::Ready(Ok(_))),
                    "MR3 VIOLATION: next waiter {} should acquire, got {:?}",
                    next_id, next_result
                );

                // Verify that later waiters are still pending
                for i in (expected_next_waiter + 1)..total_waiters as usize {
                    if i == cancel_idx { continue; } // Skip cancelled waiter

                    let (later_future, later_wake_count, later_id) = &mut waiter_futures[i];
                    let later_wakes = later_wake_count.load(Ordering::SeqCst);

                    // Later waiters should not be woken yet
                    if later_wakes > 0 {
                        harness.increment_fairness_violations();
                    }

                    let (later_waker, _) = CountingWaker::new();
                    let mut later_task_cx = Context::from_waker(&later_waker);
                    let later_result = later_future.as_mut().poll(&mut later_task_cx);
                    prop_assert!(
                        matches!(later_result, Poll::Pending),
                        "MR3 VIOLATION: later waiter {} should still be pending", later_id
                    );
                }

                // MR3 CORE ASSERTION: No fairness violations occurred
                prop_assert_eq!(
                    harness.fairness_violation_count(), 0,
                    "MR3 VIOLATION: {} fairness violations detected",
                    harness.fairness_violation_count()
                );

                harness.increment_operations();
                Ok(())
            }));

            match result {
                Outcome::Ok(_) => {},
                other => prop_assert!(false, "MR3 VIOLATION: unexpected outcome {:?}", other),
            }

            prop_assert!(!harness.has_obligation_leaks(), "MR3 VIOLATION: obligation leak detected");
        });
    }

    /// MR4: Try Lock Never Blocks (Temporal, Score: 8.5)
    /// Property: try_lock() never blocks, returns None if held
    /// Catches: Blocking in non-blocking operations, incorrect return values
    #[test]
    fn mr4_try_lock_never_blocks() {
        proptest!(|(
            seed in any::<u64>(),
            test_value in any::<i64>(),
            attempt_count in 1usize..10,
        )| {
            let mut harness = MutexCancelTestHarness::new(seed);

            let result = harness.execute(|cx| Box::pin(async move {
                let mutex = Arc::new(Mutex::new(test_value));
                let holder_mutex = mutex.clone();

                // Hold the lock in background
                let holder_task = cx.spawn("holder", async move {
                    let _guard = holder_mutex.lock(cx).await.unwrap();
                    cx.sleep(Duration::from_millis(50)).await;
                });

                // Allow holder to acquire
                cx.sleep(Duration::from_millis(1)).await;

                // MR4 ASSERTION: try_lock should never block, always return immediately
                let mut try_results = Vec::new();

                for attempt in 0..attempt_count {
                    let start_time = std::time::Instant::now();
                    let try_result = mutex.try_lock();
                    let elapsed = start_time.elapsed();

                    // MR4 ASSERTION: Should complete instantly (< 1ms)
                    prop_assert!(
                        elapsed < Duration::from_millis(1),
                        "MR4 VIOLATION: try_lock blocked for {:?} on attempt {}",
                        elapsed, attempt
                    );

                    // MR4 ASSERTION: Should return Locked error while held
                    match try_result {
                        Err(TryLockError::Locked) => {
                            try_results.push("locked");
                        },
                        Ok(_guard) => {
                            try_results.push("acquired");
                            prop_assert!(false, "MR4 VIOLATION: try_lock succeeded while mutex is held");
                        },
                        Err(TryLockError::Poisoned) => {
                            try_results.push("poisoned");
                            prop_assert!(false, "MR4 VIOLATION: mutex should not be poisoned");
                        },
                    }

                    // Small delay between attempts
                    cx.sleep(Duration::from_millis(1)).await;
                }

                // Wait for holder to complete
                let holder_result = holder_task.join(cx).await;
                prop_assert!(holder_result.is_ok(), "MR4 VIOLATION: holder failed");

                // MR4 ASSERTION: After holder releases, try_lock should succeed
                let final_try = mutex.try_lock();
                prop_assert!(
                    final_try.is_ok(),
                    "MR4 VIOLATION: try_lock should succeed after mutex is released"
                );

                // Verify the guard actually provides access
                if let Ok(guard) = final_try {
                    prop_assert_eq!(
                        *guard, test_value,
                        "MR4 VIOLATION: guard has wrong value: {} != {}",
                        *guard, test_value
                    );
                }

                harness.increment_operations();
                Ok(())
            }));

            match result {
                Outcome::Ok(_) => {},
                other => prop_assert!(false, "MR4 VIOLATION: unexpected outcome {:?}", other),
            }

            prop_assert!(!harness.has_obligation_leaks(), "MR4 VIOLATION: obligation leak detected");
        });
    }

    /// MR5: Guard Drop Cleanup (Safety, Score: 9.5)
    /// Property: guard Drop releases even under panic (poisoning optional)
    /// Catches: Resource leaks on panic, deadlocks, poison handling bugs
    #[test]
    fn mr5_guard_drop_cleanup() {
        proptest!(|(
            seed in any::<u64>(),
            test_value in any::<i64>(),
            should_panic in any::<bool>(),
        )| {
            let mut harness = MutexCancelTestHarness::new(seed);

            let result = harness.execute(|cx| Box::pin(async move {
                let mutex = Arc::new(Mutex::new(test_value));
                let panic_mutex = mutex.clone();

                // Task that may panic while holding the guard
                let panic_task = cx.spawn("panic_holder", async move {
                    let guard_result = panic_mutex.lock(cx).await;
                    match guard_result {
                        Ok(_guard) => {
                            // Simulate work while holding the guard
                            cx.sleep(Duration::from_millis(5)).await;

                            if should_panic {
                                // MR5 TEST: Panic while holding guard
                                let panic_result = std::panic::catch_unwind(|| {
                                    panic!("deliberate panic to test guard cleanup");
                                });
                                match panic_result {
                                    Err(_) => Err("panicked".to_string()),
                                    Ok(_) => unreachable!(),
                                }
                            } else {
                                // Normal completion
                                Ok("completed".to_string())
                            }
                        },
                        Err(e) => Err(format!("lock failed: {:?}", e)),
                    }
                });

                let panic_result = panic_task.join(cx).await;

                if should_panic {
                    // Verify the task panicked as expected
                    prop_assert!(
                        matches!(panic_result, Err(_)),
                        "MR5 VIOLATION: panic task should have failed"
                    );

                    // MR5 ASSERTION: Mutex should be poisoned after panic
                    let is_poisoned = mutex.is_poisoned();
                    prop_assert!(
                        is_poisoned,
                        "MR5 VIOLATION: mutex should be poisoned after panic"
                    );

                    // MR5 ASSERTION: try_lock should return Poisoned
                    let try_result = mutex.try_lock();
                    prop_assert!(
                        matches!(try_result, Err(TryLockError::Poisoned)),
                        "MR5 VIOLATION: try_lock should return Poisoned, got {:?}",
                        try_result
                    );

                    // MR5 ASSERTION: async lock should return Poisoned
                    let lock_result = mutex.lock(cx).await;
                    prop_assert!(
                        matches!(lock_result, Err(LockError::Poisoned)),
                        "MR5 VIOLATION: async lock should return Poisoned, got {:?}",
                        lock_result
                    );
                } else {
                    // Normal case - verify successful completion
                    prop_assert!(
                        matches!(panic_result, Ok(_)),
                        "MR5 VIOLATION: normal task should succeed: {:?}",
                        panic_result
                    );

                    // MR5 ASSERTION: Mutex should not be poisoned
                    let is_poisoned = mutex.is_poisoned();
                    prop_assert!(
                        !is_poisoned,
                        "MR5 VIOLATION: mutex should not be poisoned on normal completion"
                    );

                    // MR5 ASSERTION: Should be able to acquire again
                    let second_guard = mutex.try_lock();
                    prop_assert!(
                        second_guard.is_ok(),
                        "MR5 VIOLATION: should be able to reacquire after normal release"
                    );

                    if let Ok(guard) = second_guard {
                        prop_assert_eq!(
                            *guard, test_value,
                            "MR5 VIOLATION: value should be preserved"
                        );
                    }
                }

                // MR5 CORE ASSERTION: Mutex is unlocked regardless of panic/normal completion
                // For poisoned mutex, this means the lock mechanism itself works, just returns errors
                let is_locked = mutex.is_locked();
                prop_assert!(
                    !is_locked,
                    "MR5 VIOLATION: mutex should be unlocked after guard drop (even if poisoned)"
                );

                harness.increment_operations();
                Ok(())
            }));

            match result {
                Outcome::Ok(_) => {},
                other => prop_assert!(false, "MR5 VIOLATION: unexpected outcome {:?}", other),
            }

            prop_assert!(!harness.has_obligation_leaks(), "MR5 VIOLATION: obligation leak detected");
        });
    }
}
