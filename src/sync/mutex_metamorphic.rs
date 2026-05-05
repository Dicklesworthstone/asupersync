//! Metamorphic Testing: Mutex poisoning across cancel boundaries
//!
//! This module implements metamorphic relations (MRs) to verify that mutex
//! poisoning behavior is consistent across panic/cancel interactions and that
//! all waiters see consistent poisoned state.
//!
//! # Metamorphic Relations
//!
//! - **MR1 (Panic Poisoning Consistency)**: panic inside lock guard poisons
//!   mutex for ALL future acquirers
//! - **MR2 (Cancel Non-Poisoning)**: cancel inside lock guard does NOT poison
//!   (cleanup is semantically normal)
//! - **MR3 (Poison State Stability)**: once poisoned, every subsequent query
//!   (`is_poisoned`, `try_lock`, async `lock`) reports the poisoned state
//!   consistently across repeated calls and across the sync/async API surface
//! - **MR4 (Concurrent Poison Consistency)**: concurrent waiters on poisoned
//!   mutex all see consistent Err rather than partial state
//!
//! # Property Coverage
//!
//! These MRs ensure that:
//! - Panic-based poisoning is consistently detected across all access patterns
//! - Cancellation does not interfere with poison semantics
//! - The poisoned bit is monotonic and observable through every public query
//! - Race conditions don't lead to inconsistent poison state

use crate::lab::LabConfig;
use crate::lab::runtime::LabRuntime;
use crate::sync::mutex::{LockError, Mutex, TryLockError};
use crate::types::Budget;
use crate::util::ArenaIndex;
use crate::{Cx, RegionId, TaskId};
use proptest::prelude::*;
use std::future::Future;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

/// Test data structure for mutex operations
#[derive(Debug, Clone, PartialEq)]
struct TestData {
    value: u32,
    counter: u64,
}

impl Default for TestData {
    fn default() -> Self {
        Self {
            value: 42,
            counter: 0,
        }
    }
}

/// Inject a controlled panic during mutex operations
fn panic_injector(should_panic: bool, panic_message: &str) {
    assert!(!should_panic, "{}", panic_message);
}

/// Create a test context with unique identifiers
fn create_test_context(region_id: u32, task_id: u32) -> Cx {
    Cx::new(
        RegionId::from_arena(ArenaIndex::new(region_id, 0)),
        TaskId::from_arena(ArenaIndex::new(task_id, 0)),
        Budget::INFINITE,
    )
}

fn poll_pinned_once<T, F: Future<Output = T>>(mut future: Pin<&mut F>) -> Option<T> {
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    match future.as_mut().poll(&mut cx) {
        Poll::Ready(value) => Some(value),
        Poll::Pending => None,
    }
}

/// **MR1: Panic Poisoning Consistency**
///
/// If a panic occurs while holding a mutex guard, then ALL subsequent
/// access attempts (lock, try_lock, get_mut, into_inner) must consistently
/// report the poisoned state.
///
/// **Property**: f(mutex_after_panic_in_guard) = Poisoned for all f ∈ {lock, try_lock}
#[test]
fn mr1_panic_poisoning_consistency() {
    proptest!(|(
        initial_value in 0u32..1000,
        panic_after_operations in 0usize..5,
        num_subsequent_accesses in 1usize..10
    )| {
        let mutex = Arc::new(Mutex::new(TestData {
            value: initial_value,
            counter: 0,
        }));

        // Phase 1: Panic while holding the guard
        let mutex_clone = Arc::clone(&mutex);
        let handle = std::thread::spawn(move || {
            let cx = create_test_context(1, 1);
            futures_lite::future::block_on(async {
                let mut guard = mutex_clone.lock(&cx).await.expect("initial lock should succeed");

                // Perform some operations before panic
                for _ in 0..panic_after_operations {
                    guard.counter += 1;
                    guard.value = guard.value.wrapping_add(1);
                }

                // Inject panic while holding the guard
                panic_injector(true, "deliberate panic to test poisoning");
            });
        });

        // Wait for the thread to panic
        let _ = handle.join();

        // Phase 2: Verify ALL subsequent access methods report poison consistently
        for i in 0..num_subsequent_accesses {
            let cx = create_test_context(2, i as u32 + 2);

            // MR1.1: try_lock must return Poisoned
            let try_result = mutex.try_lock();
            prop_assert!(matches!(try_result, Err(TryLockError::Poisoned)),
                "try_lock attempt {} should return Poisoned, got {:?}", i, try_result);

            // MR1.2: async lock must return Poisoned
            let lock_result = futures_lite::future::block_on(async {
                mutex.lock(&cx).await
            });
            match lock_result {
                Err(LockError::Poisoned) => {
                    // Expected: Poisoned error
                }
                other => {
                    prop_assert!(false, "async lock attempt {} should return Poisoned, got {:?}", i, other);
                }
            }

            // MR1.3: is_poisoned() must return true
            prop_assert!(mutex.is_poisoned(), "is_poisoned() should return true after panic");
        }

        // MR1.4: Verify that get_mut and into_inner panic on poisoned mutex
        // (These require owned access so we test them separately)
        {
            let mut mutex_owned = Arc::try_unwrap(mutex).expect("should be sole owner now");

            // get_mut should panic
            let get_mut_result = catch_unwind(AssertUnwindSafe(|| {
                let _ = mutex_owned.get_mut();
            }));
            prop_assert!(get_mut_result.is_err(), "get_mut should panic on poisoned mutex");

            // into_inner should panic
            let into_inner_result = catch_unwind(AssertUnwindSafe(|| {
                let _ = mutex_owned.into_inner();
            }));
            prop_assert!(into_inner_result.is_err(), "into_inner should panic on poisoned mutex");
        }
    });
}

/// **MR2: Cancel Non-Poisoning**
///
/// If a cancellation occurs while waiting for or holding a mutex guard,
/// then the mutex should NOT be poisoned, and subsequent access should
/// succeed normally.
///
/// **Property**: f(mutex_after_cancel) ≠ Poisoned for all f ∈ {lock, try_lock}
#[test]
fn mr2_cancel_non_poisoning() {
    proptest!(|(
        initial_value in 0u32..1000,
        operations_before_cancel in 0usize..3,
        cancel_during_wait in prop::bool::ANY
    )| {
        let mutex = Arc::new(Mutex::new(TestData {
            value: initial_value,
            counter: 0,
        }));

        let _lab = LabRuntime::new(LabConfig::default());

        if cancel_during_wait {
            // MR2.1: Cancel while waiting for lock (not holding)
            futures_lite::future::block_on(async {
                let mutex_clone = Arc::clone(&mutex);
                let cx1 = create_test_context(1, 1);
                let cx2 = create_test_context(1, 2);

                // Hold the lock on first context
                let guard1 = mutex.lock(&cx1).await.expect("first lock should succeed");

                // Poll once so the second lock future is actually queued behind `guard1`
                // before cancellation is requested.
                let mut lock_future = std::pin::pin!(mutex_clone.lock(&cx2));
                let pending = poll_pinned_once(lock_future.as_mut()).is_none();
                prop_assert!(pending, "second waiter should pend behind the held guard");

                cx2.set_cancel_requested(true);

                let result = poll_pinned_once(lock_future.as_mut())
                    .expect("cancelled waiter should resolve on the next poll");
                prop_assert!(matches!(result, Err(LockError::Cancelled)),
                    "cancelled wait should return Cancelled, got {:?}", result);

                // Release first lock
                drop(guard1);
                Ok::<(), TestCaseError>(())
            })?;
        } else {
            // MR2.2: Cancel while holding lock (during operations)
            futures_lite::future::block_on(async {
                let cx = create_test_context(1, 1);
                let mut guard = mutex.lock(&cx).await.expect("lock should succeed");

                // Perform some operations
                for _ in 0..operations_before_cancel {
                    guard.counter += 1;
                    guard.value = guard.value.wrapping_add(1);
                }

                // Request cancellation while holding the lock
                cx.set_cancel_requested(true);

                // Continue operations (guard is still valid)
                guard.value = guard.value.wrapping_mul(2);

                // Drop the guard normally (no panic should occur)
                drop(guard);
                Ok::<(), TestCaseError>(())
            })?;
        }

        // MR2.3: Verify mutex is NOT poisoned after cancellation
        prop_assert!(!mutex.is_poisoned(), "mutex should not be poisoned after cancel");

        // MR2.4: Verify subsequent operations succeed
        let cx = create_test_context(2, 1);
        let try_result = mutex.try_lock();
        prop_assert!(try_result.is_ok(), "try_lock should succeed after cancel, got {:?}", try_result);
        // Release the guard held inside `try_result` BEFORE re-locking
        // asynchronously below. Without this drop, the guard is still
        // alive when `block_on(mutex.lock(&cx))` is called on the same
        // single-threaded executor, and the async acquire future pends
        // forever waiting for a lock that will never be released —
        // deadlocking the whole test (seen as "running for over 60
        // seconds" then binary stall).
        drop(try_result);

        let _lab2 = LabRuntime::new(LabConfig::default());
        let lock_result = futures_lite::future::block_on(async {
            mutex.lock(&cx).await
        });
        match lock_result {
            Ok(_guard) => {
                // Expected: successful lock
            }
            other => {
                prop_assert!(false, "async lock should succeed after cancel, got {:?}", other);
            }
        }
    });
}

/// **MR3: Poison State Stability**
///
/// Once a mutex has been poisoned, the poisoned bit is monotonic — every
/// subsequent observation through every public query reports the same
/// poisoned state. This is the recovery-adjacent property the asupersync
/// `Mutex` actually exposes: `into_inner` and `get_mut` both panic on a
/// poisoned mutex (recovery is intentionally not supported), so the
/// metamorphic relation worth verifying is that observers cannot disagree
/// about whether poisoning has happened.
///
/// **Property**:
///   ∀k ∈ ℕ. is_poisoned(mutex) ∧
///   try_lock(mutex)ₖ = Err(Poisoned) ∧
///   lock(mutex)ₖ.await = Err(Poisoned)
///   after poison(mutex)
#[test]
fn mr3_poison_state_stability() {
    proptest!(|(
        initial_value in 0u32..1000,
        operations_before_panic in 0usize..5,
        final_operation_value in 0u32..100,
        repeat_query_count in 2usize..8,
    )| {
        let mutex = Arc::new(Mutex::new(TestData {
            value: initial_value,
            counter: 0,
        }));

        // Phase 1: Poison the mutex by panicking while holding the guard.
        let mutex_clone = Arc::clone(&mutex);
        let handle = std::thread::spawn(move || {
            let cx = create_test_context(2, 1);
            let _lab = LabRuntime::new(LabConfig::default());

            futures_lite::future::block_on(async {
                let mut guard = mutex_clone.lock(&cx).await.expect("lock for poison should succeed");

                for i in 0..operations_before_panic {
                    guard.counter += 1;
                    guard.value = guard.value.wrapping_add(i as u32);
                }
                guard.value = guard.value.wrapping_add(final_operation_value);

                panic!("deliberate panic to poison mutex");
            });
        });

        let _ = handle.join().expect_err("poisoning thread should panic");

        // MR3.1: is_poisoned reports true and never spuriously transitions back.
        for k in 0..repeat_query_count {
            prop_assert!(mutex.is_poisoned(),
                "is_poisoned must remain true on query {} after poisoning", k);
        }

        // MR3.2: try_lock consistently returns Poisoned across repeated calls.
        for k in 0..repeat_query_count {
            let result = mutex.try_lock();
            prop_assert!(matches!(result, Err(TryLockError::Poisoned)),
                "try_lock query {} should return Poisoned, got {:?}", k, result);
        }

        // MR3.3: The async lock surface agrees with try_lock — every awaited
        // lock attempt resolves immediately to Err(Poisoned). This is the
        // sync/async parity half of the stability relation.
        let _lab = LabRuntime::new(LabConfig::default());
        for k in 0..repeat_query_count {
            let cx = create_test_context(3 + k as u32, 1);
            let result = futures_lite::future::block_on(async {
                mutex.lock(&cx).await.map(|_| ())
            });
            prop_assert!(matches!(result, Err(LockError::Poisoned)),
                "async lock query {} should return Poisoned, got {:?}", k, result);
        }

        // MR3.4: Stability is preserved after observing the poison through
        // both APIs — the final query still reports poisoned.
        prop_assert!(mutex.is_poisoned(),
            "poison state must remain stable after mixed sync/async observations");
    });
}

/// **MR4: Concurrent Poison Consistency**
///
/// When a mutex is poisoned, ALL concurrent waiters should see the same
/// poisoned error state, not a mix of successful locks and poison errors.
/// This tests that poison state propagation is atomic and consistent.
///
/// **Property**: ∀w ∈ waiters: f(w, poisoned_mutex) = Poisoned
#[test]
fn mr4_concurrent_poison_consistency() {
    proptest!(|(
        num_waiters in 2usize..8,
        operations_before_poison in 0usize..3,
        stagger_delay_ms in 0u64..10
    )| {
        let mutex = Arc::new(Mutex::new(TestData {
            value: 100,
            counter: 0,
        }));
        let _lab = LabRuntime::new(LabConfig::default());

        // Phase 1: Create multiple waiters
        let waiter_handles = Arc::new(std::sync::Mutex::new(Vec::new()));
        let waiter_results = Arc::new(std::sync::Mutex::new(Vec::new()));
        // br-asupersync-0fqp0s: include the poisoner in the release barrier so
        // every waiter contends behind an already-held lock instead of racing
        // ahead of the panic thread during its old fixed sleep.
        let barrier = Arc::new(std::sync::Barrier::new(num_waiters + 2));
        let (poison_ready_tx, poison_ready_rx) = std::sync::mpsc::channel();

        // Spawn waiter threads
        for i in 0..num_waiters {
            let mutex_clone = Arc::clone(&mutex);
            let results_clone = Arc::clone(&waiter_results);
            let barrier_clone = Arc::clone(&barrier);

            let handle = std::thread::spawn(move || {
                // Wait for all waiters to be ready
                barrier_clone.wait();

                // Small stagger to create different timing
                if i > 0 {
                    std::thread::sleep(Duration::from_millis(stagger_delay_ms * i as u64));
                }

                let cx = create_test_context(i as u32 + 10, i as u32 + 10);

                let result = futures_lite::future::block_on(async move {
                    mutex_clone.lock(&cx).await.map(|_| ())
                });

                // Store the result
                results_clone.lock().unwrap().push((i, result));
            });

            waiter_handles.lock().unwrap().push(handle);
        }

        // Phase 2: Start poison process in parallel
        let mutex_for_poison = Arc::clone(&mutex);
        let barrier_for_poison = Arc::clone(&barrier);
        let poison_handle = std::thread::spawn(move || {
            let cx = create_test_context(1, 1);
            let mut guard =
                futures_lite::future::block_on(mutex_for_poison.lock(&cx))
                    .expect("poison thread should lock");

            poison_ready_tx
                .send(())
                .expect("poison thread should signal readiness");
            barrier_for_poison.wait();

            // Perform operations while waiters are blocked behind the held lock.
            for _ in 0..operations_before_poison {
                guard.counter += 1;
                guard.value = guard.value.wrapping_add(1);
            }

            // Poison the mutex while still holding the guard so queued waiters
            // observe a consistent poisoned state once they are released.
            panic!("deliberate panic to test concurrent poison consistency");
        });

        // Phase 3: Release waiters only after the poisoner is already holding
        // the mutex.
        poison_ready_rx
            .recv()
            .expect("poison thread should become ready");
        barrier.wait();

        // Phase 4: Wait for poison to complete
        let _ = poison_handle.join().expect_err("poison thread should panic");

        // Phase 5: Wait for all waiters to complete
        for handle in waiter_handles.lock().unwrap().drain(..) {
            let _ = handle.join();
        }

        // Phase 6: Analyze results for consistency
        let results = waiter_results.lock().unwrap();

        // MR4.1: All waiters should see consistent error state
        let mut poison_count = 0;
        let mut success_count = 0;
        let mut cancel_count = 0;
        let mut timeout_count = 0;
        let mut other_count = 0;

        for (_waiter_id, result) in results.iter() {
            match result {
                Err(LockError::Poisoned) => poison_count += 1,
                Ok(_) => success_count += 1,
                Err(LockError::Cancelled) => cancel_count += 1,
                Err(LockError::TimedOut(_)) => timeout_count += 1,
                Err(LockError::PolledAfterCompletion) => other_count += 1,
            }
        }

        // MR4.2: At most one waiter should have succeeded (acquired lock before poison)
        prop_assert!(success_count <= 1,
            "at most 1 waiter should succeed before poison, got {} successes", success_count);

        // MR4.3: All other waiters should see poison (not mixed states)
        if success_count == 0 {
            // No one got the lock before poison - all should see poison
            prop_assert!(poison_count == num_waiters,
                "all {} waiters should see poison when no one succeeded, got {} poison",
                num_waiters, poison_count);
        } else {
            // One waiter got lock before poison - all others should see poison
            prop_assert!(poison_count == num_waiters - 1,
                "remaining {} waiters should see poison, got {} poison",
                num_waiters - 1, poison_count);
        }

        // MR4.4: No inconsistent states (cancellation should not occur in this test)
        prop_assert!(cancel_count == 0 && timeout_count == 0 && other_count == 0,
            "no unexpected states: {} cancels, {} timeouts, {} others",
            cancel_count, timeout_count, other_count);

        // MR4.5: Final state should be poisoned
        prop_assert!(mutex.is_poisoned(), "mutex should be poisoned at end");
    });
}

/// **Composite MR: Cancel During Poison Recovery**
///
/// Combines MR2 and MR3: if cancellation occurs during attempted recovery
/// of a poisoned mutex, the cancellation should be handled correctly without
/// masking the poison state.
#[test]
fn mr_composite_cancel_during_poison_recovery() {
    proptest!(|(
        initial_value in 0u32..1000,
        recovery_attempts in 1usize..5
    )| {
        let mutex = Arc::new(Mutex::new(TestData {
            value: initial_value,
            counter: 0,
        }));

        // Phase 1: Poison the mutex
        let mutex_clone = Arc::clone(&mutex);
        let handle = std::thread::spawn(move || {
            let cx = create_test_context(1, 1);
            let _lab = LabRuntime::new(LabConfig::default());

            futures_lite::future::block_on(async {
                let _guard = mutex_clone.lock(&cx).await.expect("lock for poison should succeed");
                panic!("poison for recovery test");
            });
        });

        let _ = handle.join().expect_err("should panic");
        prop_assert!(mutex.is_poisoned(), "mutex should be poisoned");

        // Phase 2: Attempt recovery with cancellation
        for i in 0..recovery_attempts {
            let cx = create_test_context(2, i as u32 + 2);
            let _lab = LabRuntime::new(LabConfig::default());

            // Cancel during recovery attempt
            cx.set_cancel_requested(true);

            let result = futures_lite::future::block_on(async {
                mutex.lock(&cx).await
            });

            match result {
                Err(LockError::Cancelled) => {
                    // Expected: cancellation takes precedence over poison detection
                    // when cancel is requested before lock attempt
                }
                Err(LockError::Poisoned) => {
                    // Also acceptable: poison detected before cancel check
                }
                other => {
                    prop_assert!(false, "recovery attempt {} should return Cancelled or Poisoned, got {:?}", i, other);
                }
            }

            // MR: Poison state should remain stable despite cancellation
            prop_assert!(mutex.is_poisoned(), "poison state should persist through cancel attempts");
        }

        // Phase 3: Verify normal recovery still works after cancelled attempts
        let try_result = mutex.try_lock();
        prop_assert!(matches!(try_result, Err(TryLockError::Poisoned)),
            "try_lock should still return Poisoned after cancel attempts");
    });
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    /// Integration test to verify all metamorphic relations work together
    #[test]
    fn integration_all_mrs_together() {
        // This is a smaller, deterministic version of the property tests
        // to ensure they can run in CI without property test infrastructure

        let mutex = Arc::new(Mutex::new(TestData::default()));

        // Test MR1: Basic poison behavior
        let mutex_clone = Arc::clone(&mutex);
        let handle = std::thread::spawn(move || {
            let cx = create_test_context(1, 1);
            let _lab = LabRuntime::new(LabConfig::default());

            futures_lite::future::block_on(async {
                let _guard = mutex_clone.lock(&cx).await.expect("lock");
                panic!("test poison");
            });
        });

        let _ = handle.join().expect_err("should panic");
        assert!(mutex.is_poisoned());
        assert!(matches!(mutex.try_lock(), Err(TryLockError::Poisoned)));

        // Test MR2: Verify cancel doesn't poison (create a new mutex)
        let clean_mutex = Arc::new(Mutex::new(TestData::default()));
        let cx = create_test_context(2, 2);

        futures_lite::future::block_on(async {
            let _guard = clean_mutex.lock(&cx).await.expect("clean lock");
            cx.set_cancel_requested(true);
            // Guard drops normally, shouldn't poison
        });

        assert!(!clean_mutex.is_poisoned());
        assert!(clean_mutex.try_lock().is_ok());
    }
}
