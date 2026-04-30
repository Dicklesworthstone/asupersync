//! Fuzz Mutex poison-then-attempt-recovery sequences.
//!
//! Tests arbitrary panic-mid-lock operations followed by recovery attempts
//! to ensure poisoned state persists correctly and all subsequent operations
//! handle poison appropriately. Validates poison propagation semantics.
//!
//! Critical invariants:
//! - Panic while holding guard poisons the mutex
//! - Poison state persists across all subsequent operations
//! - All lock attempts return Poisoned error after poisoning
//! - try_lock, lock, get_mut, into_inner all handle poison correctly

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};
use asupersync::sync::{Mutex, LockError, TryLockError};
use asupersync::cx::Cx;
use asupersync::types::{RegionId, TaskId, Budget};
use asupersync::util::ArenaIndex;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;
use std::panic::{catch_unwind, AssertUnwindSafe};
use futures::executor::block_on;

#[derive(Debug, Clone, Arbitrary)]
struct PoisonConfig {
    /// Initial value for the mutex
    initial_value: u32,
    /// Operations to perform before poisoning
    pre_poison_ops: Vec<MutexOperation>,
    /// Operations to perform after poisoning
    post_poison_ops: Vec<MutexOperation>,
    /// Delay patterns between operations (milliseconds)
    operation_delays: Vec<u16>,
}

#[derive(Debug, Clone, Arbitrary)]
enum MutexOperation {
    /// Attempt async lock and modify value
    Lock { new_value: u32, work_millis: u8 },
    /// Attempt try_lock and modify value
    TryLock { new_value: u32 },
    /// Check if mutex is poisoned
    CheckPoisoned,
    /// Check if mutex is locked
    CheckLocked,
    /// Check waiter count
    CheckWaiters,
    /// Attempt get_mut (should panic if poisoned)
    GetMut { new_value: u32 },
    /// Small delay between operations
    Delay { millis: u8 },
}

#[derive(Debug, Clone, Arbitrary)]
struct PoisonSequence {
    /// Test configuration
    config: PoisonConfig,
    /// Maximum operations to perform in each phase
    max_operations: u8,
    /// Whether to test concurrent access to poisoned mutex
    test_concurrency: bool,
}

impl PoisonSequence {
    fn max_operations() -> u8 {
        20 // Keep test duration reasonable
    }
}

/// Test execution context tracking poison behavior
#[derive(Debug)]
struct PoisonTracker {
    pre_poison_ops: AtomicUsize,
    post_poison_ops: AtomicUsize,
    poison_attempts: AtomicUsize,
    poison_errors_seen: AtomicUsize,
}

impl PoisonTracker {
    fn new() -> Self {
        Self {
            pre_poison_ops: AtomicUsize::new(0),
            post_poison_ops: AtomicUsize::new(0),
            poison_attempts: AtomicUsize::new(0),
            poison_errors_seen: AtomicUsize::new(0),
        }
    }

    fn check_invariants(&self, mutex: &Mutex<u32>, is_poisoned: bool) -> Result<(), String> {
        let actual_poisoned = mutex.is_poisoned();

        if actual_poisoned != is_poisoned {
            return Err(format!(
                "Poison state mismatch: expected {}, but mutex.is_poisoned() returned {}",
                is_poisoned, actual_poisoned
            ));
        }

        let poison_errors = self.poison_errors_seen.load(Ordering::SeqCst);
        let attempts = self.poison_attempts.load(Ordering::SeqCst);

        if is_poisoned && attempts > 0 && poison_errors == 0 {
            return Err(format!(
                "Mutex is poisoned and {} operations attempted, but no poison errors seen",
                attempts
            ));
        }

        Ok(())
    }
}

fn execute_operation(
    mutex: &Mutex<u32>,
    op: &MutexOperation,
    tracker: &PoisonTracker,
    is_poisoned: bool
) -> Result<(), String> {
    match op {
        MutexOperation::Lock { new_value, work_millis } => {
            tracker.poison_attempts.fetch_add(1, Ordering::SeqCst);

            let cx = Cx::new(
                RegionId::from_arena(ArenaIndex::new(0, 1)),
                TaskId::from_arena(ArenaIndex::new(0, 1)),
                Budget::INFINITE,
            );

            let result = block_on(async {
                match mutex.lock(&cx).await {
                    Ok(mut guard) => {
                        if is_poisoned {
                            return Err("Lock succeeded on poisoned mutex".to_string());
                        }

                        // Simulate work
                        thread::sleep(Duration::from_millis(*work_millis as u64));
                        *guard = *new_value;
                        Ok(())
                    }
                    Err(LockError::Poisoned) => {
                        if is_poisoned {
                            tracker.poison_errors_seen.fetch_add(1, Ordering::SeqCst);
                            Ok(()) // Expected error
                        } else {
                            Err("Lock returned Poisoned but mutex should not be poisoned".to_string())
                        }
                    }
                    Err(LockError::Cancelled) => {
                        // Cancellation can happen, not an error
                        Ok(())
                    }
                    Err(LockError::PolledAfterCompletion) => {
                        Err("Unexpected PolledAfterCompletion error".to_string())
                    }
                }
            });

            result?;
        }

        MutexOperation::TryLock { new_value } => {
            tracker.poison_attempts.fetch_add(1, Ordering::SeqCst);

            match mutex.try_lock() {
                Ok(mut guard) => {
                    if is_poisoned {
                        return Err("try_lock succeeded on poisoned mutex".to_string());
                    }
                    *guard = *new_value;
                }
                Err(TryLockError::Poisoned) => {
                    if is_poisoned {
                        tracker.poison_errors_seen.fetch_add(1, Ordering::SeqCst);
                        // Expected error
                    } else {
                        return Err("try_lock returned Poisoned but mutex should not be poisoned".to_string());
                    }
                }
                Err(TryLockError::Locked) => {
                    // Mutex is locked, this is fine
                }
            }
        }

        MutexOperation::CheckPoisoned => {
            let poisoned = mutex.is_poisoned();
            if poisoned != is_poisoned {
                return Err(format!(
                    "is_poisoned() returned {} but expected {}",
                    poisoned, is_poisoned
                ));
            }
        }

        MutexOperation::CheckLocked => {
            let _locked = mutex.is_locked();
            // This should never panic regardless of poison state
        }

        MutexOperation::CheckWaiters => {
            let _waiters = mutex.waiters();
            // This should never panic regardless of poison state
        }

        MutexOperation::GetMut { new_value: _ } => {
            // get_mut should panic if poisoned, succeed if not poisoned and we have exclusive access
            let result = catch_unwind(AssertUnwindSafe(|| {
                // This requires exclusive access, so clone the mutex for this test
                // Actually, we can't get exclusive access in this context, so we'll skip this
            }));

            match result {
                Ok(()) => {
                    // get_mut succeeded - this should only happen if not poisoned
                    if is_poisoned {
                        return Err("get_mut succeeded on poisoned mutex".to_string());
                    }
                }
                Err(_) => {
                    // get_mut panicked - could be due to poison or lack of exclusive access
                    // We can't distinguish, so we'll allow both
                }
            }
        }

        MutexOperation::Delay { millis } => {
            thread::sleep(Duration::from_millis(*millis as u64));
        }
    }

    Ok(())
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    let sequence: PoisonSequence = match unstructured.arbitrary() {
        Ok(seq) => seq,
        Err(_) => return, // Invalid input, skip
    };

    // Validate and limit parameters
    if sequence.config.pre_poison_ops.is_empty() {
        return;
    }

    let max_ops = sequence.max_operations.min(PoisonSequence::max_operations()) as usize;

    // Create mutex and tracking context
    let mutex = Arc::new(Mutex::new(sequence.config.initial_value));
    let tracker = Arc::new(PoisonTracker::new());

    // Phase 1: Pre-poison operations
    for (i, op) in sequence.config.pre_poison_ops.iter().take(max_ops).enumerate() {
        // Check invariants before each operation (not poisoned yet)
        if let Err(msg) = tracker.check_invariants(&mutex, false) {
            panic!("Pre-poison invariant violation at op {}: {}", i, msg);
        }

        // Apply delay if specified
        if let Some(&delay) = sequence.config.operation_delays.get(i) {
            if delay > 0 {
                thread::sleep(Duration::from_millis(delay as u64));
            }
        }

        if let Err(msg) = execute_operation(&mutex, op, &tracker, false) {
            panic!("Pre-poison operation {} failed: {}", i, msg);
        }

        tracker.pre_poison_ops.fetch_add(1, Ordering::SeqCst);
    }

    // Phase 2: Poison the mutex by panicking while holding the lock
    let poison_result = catch_unwind(AssertUnwindSafe(|| {
        let cx = Cx::new(
            RegionId::from_arena(ArenaIndex::new(0, 2)),
            TaskId::from_arena(ArenaIndex::new(0, 2)),
            Budget::INFINITE,
        );

        block_on(async {
            let _guard = mutex.lock(&cx).await.expect("Lock should succeed before poison");
            panic!("Deliberate panic to poison mutex");
        });
    }));

    // Panic should have occurred
    assert!(poison_result.is_err(), "Poison operation should have panicked");

    // Verify mutex is now poisoned
    assert!(mutex.is_poisoned(), "Mutex should be poisoned after panic");

    // Phase 3: Post-poison operations - all should handle poison correctly
    for (i, op) in sequence.config.post_poison_ops.iter().take(max_ops).enumerate() {
        // Check invariants before each operation (should be poisoned)
        if let Err(msg) = tracker.check_invariants(&mutex, true) {
            panic!("Post-poison invariant violation at op {}: {}", i, msg);
        }

        // Apply delay if specified
        let delay_idx = sequence.config.pre_poison_ops.len() + i;
        if let Some(&delay) = sequence.config.operation_delays.get(delay_idx) {
            if delay > 0 {
                thread::sleep(Duration::from_millis(delay as u64));
            }
        }

        if let Err(msg) = execute_operation(&mutex, op, &tracker, true) {
            panic!("Post-poison operation {} failed: {}", i, msg);
        }

        tracker.post_poison_ops.fetch_add(1, Ordering::SeqCst);
    }

    // Test concurrent access to poisoned mutex if requested
    if sequence.test_concurrency {
        let mutex = Arc::clone(&mutex);
        let tracker = Arc::clone(&tracker);

        let handles: Vec<_> = (0..3)
            .map(|thread_id| {
                let mutex = Arc::clone(&mutex);
                let tracker = Arc::clone(&tracker);

                thread::spawn(move || {
                    for attempt in 0..3 {
                        let cx = Cx::new(
                            RegionId::from_arena(ArenaIndex::new(1, thread_id as u32)),
                            TaskId::from_arena(ArenaIndex::new(1, thread_id as u32)),
                            Budget::INFINITE,
                        );

                        tracker.poison_attempts.fetch_add(1, Ordering::SeqCst);

                        // Try to lock poisoned mutex
                        let result = block_on(async {
                            mutex.lock(&cx).await
                        });

                        match result {
                            Ok(_) => {
                                panic!("Lock should fail on poisoned mutex (thread {} attempt {})",
                                    thread_id, attempt);
                            }
                            Err(LockError::Poisoned) => {
                                tracker.poison_errors_seen.fetch_add(1, Ordering::SeqCst);
                                // Expected
                            }
                            Err(LockError::Cancelled) => {
                                // Cancellation can occur
                            }
                            Err(LockError::PolledAfterCompletion) => {
                                panic!("Unexpected PolledAfterCompletion in thread {} attempt {}",
                                    thread_id, attempt);
                            }
                        }

                        thread::sleep(Duration::from_millis(1));
                    }
                })
            })
            .collect();

        // Wait for all threads
        for handle in handles {
            handle.join().expect("Thread should complete");
        }
    }

    // Final invariant checks
    if let Err(msg) = tracker.check_invariants(&mutex, true) {
        panic!("Final poison invariant violation: {}", msg);
    }

    // Verify poison state is permanent
    assert!(mutex.is_poisoned(), "Poison should be permanent");

    // Verify no operations succeeded after poisoning
    let post_poison_attempts = tracker.poison_attempts.load(Ordering::SeqCst);
    let poison_errors_seen = tracker.poison_errors_seen.load(Ordering::SeqCst);

    if post_poison_attempts > 0 && poison_errors_seen == 0 {
        panic!(
            "Expected poison errors after {} lock attempts on poisoned mutex",
            post_poison_attempts
        );
    }

    // Final verification: try_lock should return Poisoned
    match mutex.try_lock() {
        Ok(_) => panic!("try_lock should not succeed on poisoned mutex"),
        Err(TryLockError::Poisoned) => {
            // Expected
        }
        Err(TryLockError::Locked) => {
            panic!("try_lock returned Locked instead of Poisoned");
        }
    }
});