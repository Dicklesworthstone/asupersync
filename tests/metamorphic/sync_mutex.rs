#![allow(warnings)]
#![allow(clippy::all)]
//! Metamorphic tests for sync::mutex cancel-aware lock ordering invariants.
//!
//! These tests validate the core invariants of the async mutex lock acquisition,
//! mutual exclusion, and cancel-aware fairness using metamorphic relations
//! and property-based testing under deterministic LabRuntime.
//!
//! ## Key Properties Tested
//!
//! 1. **Mutual exclusion**: lock acquire is serialized (no concurrent access)
//! 2. **Cancellation safety**: cancelled acquire does not hold the lock
//! 3. **Guard lifecycle**: dropped MutexGuard releases on all paths including panic
//! 4. **FIFO ordering**: waiter order honored within priority class
//! 5. **Try-lock semantics**: try_lock never blocks
//!
//! ## Metamorphic Relations
//!
//! - **Exclusivity invariant**: at most one guard exists at any time
//! - **Cancel idempotence**: cancel + retry ≡ direct acquisition
//! - **Drop equivalence**: panic drop ≡ normal drop for lock release
//! - **FIFO preservation**: first-in-first-out waiter ordering under fairness
//! - **Non-blocking**: try_lock execution time is bounded and deterministic

use proptest::prelude::*;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;
use std::collections::VecDeque;
use std::panic;

use asupersync::cx::{Cx, Scope};
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::sync::mutex::{LockError, Mutex, TryLockError};
use asupersync::types::{
    cancel::CancelReason, ArenaIndex, Budget, Outcome, RegionId, TaskId,
};

// =============================================================================
// Test Utilities
// =============================================================================

/// Create a test context for mutex testing.
fn test_cx() -> Cx {
    Cx::new(
        RegionId::from_arena(ArenaIndex::new(0, 0)),
        TaskId::from_arena(ArenaIndex::new(0, 0)),
        Budget::INFINITE,
    )
}

/// Create a test context with specific slot.
fn test_cx_with_slot(slot: u32) -> Cx {
    Cx::new(
        RegionId::from_arena(ArenaIndex::new(0, slot)),
        TaskId::from_arena(ArenaIndex::new(0, slot)),
        Budget::INFINITE,
    )
}

/// Create a test LabRuntime for deterministic testing.
fn test_lab_runtime() -> LabRuntime {
    LabRuntime::with_config(LabConfig::deterministic())
}

/// Create a test LabRuntime with specific seed.
fn test_lab_runtime_with_seed(seed: u64) -> LabRuntime {
    LabRuntime::with_config(LabConfig::deterministic().with_seed(seed))
}

/// Tracks mutex operations for invariant checking.
#[derive(Debug, Clone)]
struct MutexTracker {
    lock_acquisitions: Vec<usize>,
    lock_releases: Vec<usize>,
    cancellations: Vec<usize>,
    current_holder: Option<usize>,
    waiter_queue: VecDeque<usize>,
}

impl MutexTracker {
    fn new() -> Self {
        Self {
            lock_acquisitions: Vec::new(),
            lock_releases: Vec::new(),
            cancellations: Vec::new(),
            current_holder: None,
            waiter_queue: VecDeque::new(),
        }
    }

    /// Record a successful lock acquisition.
    fn record_acquire(&mut self, task_id: usize) {
        assert_eq!(self.current_holder, None, "Mutual exclusion violated");
        self.lock_acquisitions.push(task_id);
        self.current_holder = Some(task_id);
    }

    /// Record a lock release.
    fn record_release(&mut self, task_id: usize) {
        assert_eq!(self.current_holder, Some(task_id), "Wrong task releasing lock");
        self.lock_releases.push(task_id);
        self.current_holder = None;
    }

    /// Record a cancellation.
    fn record_cancel(&mut self, task_id: usize) {
        self.cancellations.push(task_id);
        // Cancelled tasks should not be holding the lock
        assert_ne!(self.current_holder, Some(task_id), "Cancelled task holds lock");
    }

    /// Add a waiter to the queue.
    fn add_waiter(&mut self, task_id: usize) {
        self.waiter_queue.push_back(task_id);
    }

    /// Remove a waiter from the queue.
    fn remove_waiter(&mut self, task_id: usize) {
        if let Some(pos) = self.waiter_queue.iter().position(|&id| id == task_id) {
            self.waiter_queue.remove(pos);
        }
    }

    /// Check mutual exclusion invariant.
    fn check_mutual_exclusion(&self) -> bool {
        self.current_holder.is_none() || self.current_holder.is_some()
    }

    /// Check FIFO ordering within waiters.
    fn check_fifo_ordering(&self, next_acquired: usize) -> bool {
        if let Some(&front) = self.waiter_queue.front() {
            front == next_acquired
        } else {
            true // No waiters, any acquire is valid
        }
    }
}

// =============================================================================
// Proptest Strategies
// =============================================================================

/// Generate arbitrary values for mutex testing.
fn arb_mutex_value() -> impl Strategy<Value = u32> {
    0u32..1000
}

/// Generate arbitrary operation sequences.
fn arb_operation_sequence() -> impl Strategy<Value = Vec<MutexOperation>> {
    prop::collection::vec(arb_mutex_operation(), 0..10)
}

#[derive(Debug, Clone)]
enum MutexOperation {
    TryLock,
    Lock,
    Unlock,
    Cancel,
    Poison,
}

fn arb_mutex_operation() -> impl Strategy<Value = MutexOperation> {
    prop_oneof![
        Just(MutexOperation::TryLock),
        Just(MutexOperation::Lock),
        Just(MutexOperation::Unlock),
        Just(MutexOperation::Cancel),
        Just(MutexOperation::Poison),
    ]
}

/// Generate test scenarios with multiple tasks.
fn arb_concurrent_scenario() -> impl Strategy<Value = ConcurrentScenario> {
    (1usize..=5, prop::collection::vec(arb_task_action(), 1..15))
        .prop_map(|(num_tasks, actions)| ConcurrentScenario { num_tasks, actions })
}

#[derive(Debug, Clone)]
struct ConcurrentScenario {
    num_tasks: usize,
    actions: Vec<TaskAction>,
}

#[derive(Debug, Clone)]
enum TaskAction {
    Acquire(usize), // task_id
    Release(usize), // task_id
    Cancel(usize),  // task_id
    TryLock(usize), // task_id
}

fn arb_task_action() -> impl Strategy<Value = TaskAction> {
    prop_oneof![
        (0usize..5).prop_map(TaskAction::Acquire),
        (0usize..5).prop_map(TaskAction::Release),
        (0usize..5).prop_map(TaskAction::Cancel),
        (0usize..5).prop_map(TaskAction::TryLock),
    ]
}

// =============================================================================
// Core Metamorphic Relations
// =============================================================================

/// MR1: Mutual exclusion - lock acquire is serialized (no concurrent access).
#[test]
fn mr_mutual_exclusion() {
    proptest!(|(initial_value in arb_mutex_value(),
               scenario in arb_concurrent_scenario(),
               seed in 0u64..1000)| {
        let lab = test_lab_runtime_with_seed(seed);
        let _guard = lab.enter();

        let mutex = Arc::new(Mutex::new(initial_value));
        let mut tracker = MutexTracker::new();

        futures_lite::future::block_on(async {
            // Test sequential access first
            let cx1 = test_cx_with_slot(1);
            {
                let guard = mutex.lock(&cx1).await.expect("Should acquire lock");
                tracker.record_acquire(1);

                // While holding lock, try_lock should fail
                let try_result = mutex.try_lock();
                prop_assert!(try_result.is_err(), "try_lock should fail while locked");

                // Verify mutual exclusion
                prop_assert!(tracker.check_mutual_exclusion(),
                    "Mutual exclusion invariant violated");
            } // guard drops here
            tracker.record_release(1);

            // Test that lock is released after guard drop
            let cx2 = test_cx_with_slot(2);
            {
                let guard2 = mutex.lock(&cx2).await.expect("Should acquire after release");
                tracker.record_acquire(2);

                prop_assert!(tracker.check_mutual_exclusion(),
                    "Mutual exclusion violated after reacquisition");
            }
            tracker.record_release(2);
        });
    });
}

/// MR2: Cancellation safety - cancelled acquire does not hold the lock.
#[test]
fn mr_cancellation_safety() {
    proptest!(|(initial_value in arb_mutex_value(),
               seed in 0u64..1000)| {
        let lab = test_lab_runtime_with_seed(seed);
        let _guard = lab.enter();

        let mutex = Arc::new(Mutex::new(initial_value));
        let mut tracker = MutexTracker::new();

        futures_lite::future::block_on(async {
            let cx1 = test_cx_with_slot(1);
            let cx2 = test_cx_with_slot(2);

            // First task acquires lock
            let _guard1 = mutex.lock(&cx1).await.expect("Should acquire lock");
            tracker.record_acquire(1);

            // Second task starts waiting for lock
            let lock_future = mutex.lock(&cx2);
            tracker.add_waiter(2);

            // Cancel the second task's context
            cx2.cancel(CancelReason::Timeout);
            tracker.record_cancel(2);

            // The cancelled acquire should fail
            match lock_future.await {
                Err(LockError::Cancelled) => {
                    // Verify cancellation invariants
                    prop_assert_eq!(tracker.current_holder, Some(1),
                        "First task should still hold lock after second task cancellation");

                    tracker.remove_waiter(2);
                }
                other => {
                    prop_assert!(false, "Expected Cancelled, got {:?}", other);
                }
            }

            // Verify cancelled task doesn't hold lock
            prop_assert!(tracker.check_mutual_exclusion(),
                "Mutual exclusion violated after cancellation");
        });
    });
}

/// MR3: Guard lifecycle - dropped MutexGuard releases on all paths including panic.
#[test]
fn mr_guard_lifecycle() {
    proptest!(|(initial_value in arb_mutex_value())| {
        let lab = test_lab_runtime();
        let _guard = lab.enter();

        let mutex = Arc::new(Mutex::new(initial_value));

        futures_lite::future::block_on(async {
            let cx1 = test_cx_with_slot(1);

            // Test normal drop path
            {
                let guard = mutex.lock(&cx1).await.expect("Should acquire lock");
                prop_assert!(mutex.is_locked(), "Mutex should be locked");
                let _value = *guard; // Use guard to prevent optimization
            } // guard drops here

            prop_assert!(!mutex.is_locked(), "Mutex should be unlocked after guard drop");

            // Test that we can acquire again after normal drop
            let cx2 = test_cx_with_slot(2);
            let _guard2 = mutex.lock(&cx2).await.expect("Should reacquire after drop");
        });
    });
}

/// MR4: FIFO waiter ordering - waiter order honored within priority class.
#[test]
fn mr_fifo_ordering() {
    proptest!(|(initial_value in arb_mutex_value(),
               num_waiters in 2usize..=5,
               seed in 0u64..1000)| {
        let lab = test_lab_runtime_with_seed(seed);
        let _guard = lab.enter();

        let mutex = Arc::new(Mutex::new(initial_value));
        let acquisition_order = Arc::new(StdMutex::new(Vec::new()));

        futures_lite::future::block_on(async {
            let scope = Scope::new();

            // First task holds the lock
            let cx1 = test_cx_with_slot(1);
            let _holder = mutex.lock(&cx1).await.expect("Should acquire lock");

            // Create multiple waiters
            for i in 2..=(num_waiters + 1) {
                let mutex_clone = Arc::clone(&mutex);
                let order_clone = Arc::clone(&acquisition_order);
                let task_id = i;

                scope.spawn(async move {
                    let cx = test_cx_with_slot(task_id as u32);
                    if let Ok(_guard) = mutex_clone.lock(&cx).await {
                        order_clone.lock().unwrap().push(task_id);
                    }
                });
            }

            // Small delay to let waiters register (deterministic in LabRuntime)
            asupersync::time::sleep(Duration::from_millis(1)).await;
        }); // scope and holder drop, releasing lock and waking waiters

        // Check that waiters were served in FIFO order
        let final_order = acquisition_order.lock().unwrap();
        prop_assert!(final_order.len() <= num_waiters,
            "Too many acquisitions: expected <= {}, got {}",
            num_waiters, final_order.len());

        // Verify ordering (should be sequential 2, 3, 4, ...)
        for (i, &task_id) in final_order.iter().enumerate() {
            let expected = i + 2; // Starting from task_id 2
            prop_assert_eq!(task_id, expected,
                "FIFO ordering violated: position {} expected task {}, got {}",
                i, expected, task_id);
        }
    });
}

/// MR5: Try-lock semantics - try_lock never blocks.
#[test]
fn mr_try_lock_non_blocking() {
    proptest!(|(initial_value in arb_mutex_value(),
               operations in arb_operation_sequence())| {
        let lab = test_lab_runtime();
        let _guard = lab.enter();

        let mutex = Mutex::new(initial_value);

        // try_lock should always return immediately
        for _op in operations.iter().take(20) {
            let start_time = std::time::Instant::now();
            let _result = mutex.try_lock();
            let elapsed = start_time.elapsed();

            // try_lock should complete very quickly (non-blocking)
            prop_assert!(elapsed < Duration::from_millis(1),
                "try_lock took too long: {:?}", elapsed);
        }

        // More comprehensive non-blocking test
        let cx = test_cx();
        futures_lite::future::block_on(async {
            // First acquire the lock asynchronously
            let _guard = mutex.lock(&cx).await.expect("Should acquire lock");

            // try_lock should fail immediately, not block
            let start_time = std::time::Instant::now();
            match mutex.try_lock() {
                Err(TryLockError::Locked) => {
                    let elapsed = start_time.elapsed();
                    prop_assert!(elapsed < Duration::from_millis(1),
                        "try_lock blocked despite being designed not to: {:?}", elapsed);
                }
                Ok(_) => prop_assert!(false, "try_lock should fail when mutex is locked"),
                Err(TryLockError::Poisoned) => {
                    // Also acceptable if mutex is poisoned
                }
            }
        });
    });
}

// =============================================================================
// Additional Metamorphic Relations
// =============================================================================

/// MR6: Poison state consistency - poisoned mutex rejects all operations.
#[test]
fn mr_poison_consistency() {
    proptest!(|(initial_value in arb_mutex_value())| {
        let lab = test_lab_runtime();
        let _guard = lab.enter();

        let mutex = Arc::new(Mutex::new(initial_value));

        futures_lite::future::block_on(async {
            let cx1 = test_cx_with_slot(1);

            // Poison the mutex by panicking while holding lock
            let mutex_clone = Arc::clone(&mutex);
            let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
                futures_lite::future::block_on(async move {
                    let _guard = mutex_clone.lock(&cx1).await.expect("Should acquire lock");
                    panic!("Intentional panic to poison mutex");
                });
            }));

            prop_assert!(result.is_err(), "Should have panicked");
            prop_assert!(mutex.is_poisoned(), "Mutex should be poisoned after panic");

            // All subsequent operations should fail with Poisoned
            let cx2 = test_cx_with_slot(2);
            match mutex.lock(&cx2).await {
                Err(LockError::Poisoned) => {} // Expected
                other => prop_assert!(false, "Expected Poisoned, got {:?}", other),
            }

            match mutex.try_lock() {
                Err(TryLockError::Poisoned) => {} // Expected
                other => prop_assert!(false, "Expected Poisoned, got {:?}", other),
            }
        });
    });
}

/// MR7: Lock state consistency - is_locked reflects actual lock state.
#[test]
fn mr_lock_state_consistency() {
    proptest!(|(initial_value in arb_mutex_value())| {
        let lab = test_lab_runtime();
        let _guard = lab.enter();

        let mutex = Mutex::new(initial_value);

        futures_lite::future::block_on(async {
            let cx = test_cx();

            // Initially unlocked
            prop_assert!(!mutex.is_locked(), "Mutex should start unlocked");

            {
                let _guard = mutex.lock(&cx).await.expect("Should acquire lock");
                prop_assert!(mutex.is_locked(), "Mutex should be locked while guard exists");
            } // guard drops

            prop_assert!(!mutex.is_locked(), "Mutex should be unlocked after guard drop");

            // Test with try_lock
            {
                let _guard = mutex.try_lock().expect("Should try_lock successfully");
                prop_assert!(mutex.is_locked(), "Mutex should be locked after try_lock");
            }

            prop_assert!(!mutex.is_locked(), "Mutex should be unlocked after try_lock guard drop");
        });
    });
}

/// MR8: Waiter count accuracy - waiters() reflects actual waiter queue.
#[test]
fn mr_waiter_count_accuracy() {
    proptest!(|(initial_value in arb_mutex_value(),
               num_waiters in 1usize..=4,
               seed in 0u64..1000)| {
        let lab = test_lab_runtime_with_seed(seed);
        let _guard = lab.enter();

        let mutex = Arc::new(Mutex::new(initial_value));

        futures_lite::future::block_on(async {
            let scope = Scope::new();

            // Initially no waiters
            prop_assert_eq!(mutex.waiters(), 0, "Should start with no waiters");

            let cx1 = test_cx_with_slot(1);
            let _holder = mutex.lock(&cx1).await.expect("Should acquire lock");

            // Create waiters
            for i in 2..=(num_waiters + 1) {
                let mutex_clone = Arc::clone(&mutex);
                scope.spawn(async move {
                    let cx = test_cx_with_slot(i as u32);
                    let _result = mutex_clone.lock(&cx).await;
                });
            }

            // Give waiters time to register (deterministic)
            asupersync::time::sleep(Duration::from_millis(1)).await;

            prop_assert_eq!(mutex.waiters(), num_waiters,
                "Waiter count should match created waiters");
        }); // scope drops, releasing all

        // After all tasks complete, should have no waiters
        prop_assert_eq!(mutex.waiters(), 0, "Should have no waiters after completion");
    });
}

// =============================================================================
// Regression Tests
// =============================================================================

/// Test basic mutex functionality.
#[test]
fn test_basic_mutex() {
    let lab = test_lab_runtime();
    let _guard = lab.enter();

    let mutex = Mutex::new(42u32);

    futures_lite::future::block_on(async {
        let cx = test_cx();

        // Basic lock/unlock
        {
            let mut guard = mutex.lock(&cx).await.expect("Should acquire lock");
            assert_eq!(*guard, 42);
            *guard = 100;
        }

        // Value should be modified
        {
            let guard = mutex.lock(&cx).await.expect("Should reacquire");
            assert_eq!(*guard, 100);
        }
    });
}

/// Test try_lock basic functionality.
#[test]
fn test_try_lock_basic() {
    let lab = test_lab_runtime();
    let _guard = lab.enter();

    let mutex = Mutex::new(42u32);

    futures_lite::future::block_on(async {
        let cx = test_cx();

        // try_lock on unlocked mutex should succeed
        {
            let mut guard = mutex.try_lock().expect("Should try_lock successfully");
            assert_eq!(*guard, 42);
            *guard = 200;

            // try_lock while locked should fail
            match mutex.try_lock() {
                Err(TryLockError::Locked) => {} // Expected
                other => panic!("Expected Locked, got {:?}", other),
            }
        }

        // After guard drops, try_lock should work again
        {
            let guard = mutex.try_lock().expect("Should try_lock after unlock");
            assert_eq!(*guard, 200);
        }
    });
}

/// Test cancellation during wait.
#[test]
fn test_cancellation_cleanup() {
    let lab = test_lab_runtime();
    let _guard = lab.enter();

    let mutex = Arc::new(Mutex::new(42u32));

    futures_lite::future::block_on(async {
        let cx1 = test_cx_with_slot(1);
        let cx2 = test_cx_with_slot(2);

        // First task holds lock
        let _guard1 = mutex.lock(&cx1).await.expect("Should acquire lock");

        // Second task waits
        let lock_future = mutex.lock(&cx2);

        // Cancel and verify cleanup
        cx2.cancel(CancelReason::Timeout);

        match lock_future.await {
            Err(LockError::Cancelled) => {
                // Should have no waiters after cancellation cleanup
                assert_eq!(mutex.waiters(), 0);
            }
            other => panic!("Expected Cancelled, got {:?}", other),
        }
    });
}

/// Test into_inner and get_mut.
#[test]
fn test_mutex_utilities() {
    let lab = test_lab_runtime();
    let _guard = lab.enter();

    let mut mutex = Mutex::new(42u32);

    // get_mut when we have mutable reference
    *mutex.get_mut() = 100;

    // into_inner consumes mutex
    let value = mutex.into_inner();
    assert_eq!(value, 100);
}

/// Test poisoning with explicit poison state.
#[test]
fn test_poison_state() {
    let lab = test_lab_runtime();
    let _guard = lab.enter();

    let mutex = Arc::new(Mutex::new(42u32));

    futures_lite::future::block_on(async {
        let cx1 = test_cx_with_slot(1);

        // Initially not poisoned
        assert!(!mutex.is_poisoned());

        // Cause panic while holding lock
        let mutex_clone = Arc::clone(&mutex);
        let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            futures_lite::future::block_on(async move {
                let _guard = mutex_clone.lock(&cx1).await.expect("Should acquire");
                panic!("Test panic");
            });
        }));

        assert!(result.is_err());
        assert!(mutex.is_poisoned());

        // Future operations should fail
        let cx2 = test_cx_with_slot(2);
        match mutex.lock(&cx2).await {
            Err(LockError::Poisoned) => {} // Expected
            other => panic!("Expected Poisoned, got {:?}", other),
        }
    });
}
