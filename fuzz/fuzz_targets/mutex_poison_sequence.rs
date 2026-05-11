#![no_main]

use arbitrary::Arbitrary;
use asupersync::cx::Cx;
use asupersync::sync::{LockError, Mutex, TryLockError};
use asupersync::types::Budget;
use asupersync::util::ArenaIndex;
use asupersync::{RegionId, TaskId};
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Structure-aware fuzzer for Mutex acquire/release/poison sequences
///
/// Tests the mutex poison correctness properties:
/// 1. Poisoned mutex returns Err on subsequent acquire attempts
/// 2. Operations on poisoned mutex behave consistently
/// 3. Non-poisoned mutex operations work correctly
/// 4. Guards can be acquired and released properly
#[derive(Arbitrary, Debug)]
struct MutexPoisonFuzz {
    /// Whether to start with a poisoned mutex
    start_poisoned: bool,
    /// Sequence of mutex operations to perform
    operations: Vec<MutexOperation>,
    /// Test configuration parameters
    config: TestConfig,
}

#[derive(Arbitrary, Debug, Clone)]
enum MutexOperation {
    /// Try to acquire the mutex synchronously (try_lock)
    TryAcquire {
        guard_id: u8, // Guard identifier for tracking (0-15)
    },
    /// Release a specific guard (drop)
    Release {
        guard_id: u8, // Guard to drop (0-15)
    },
    /// Check if mutex is currently poisoned
    CheckPoisoned,
    /// Check if mutex is currently locked
    CheckLocked,
    /// Get waiter count
    CheckWaiters,
    /// Brief delay for timing variations
    Delay {
        milliseconds: u8, // Delay duration (0-5ms)
    },
}

#[derive(Arbitrary, Debug)]
struct TestConfig {
    /// Maximum number of operations to execute
    max_operations: u8,
    /// Test duration timeout
    timeout_seconds: u8,
}

// Resource limits to prevent fuzzer timeouts
const MAX_OPERATIONS: usize = 100;
const MAX_GUARDS: usize = 16;
const MAX_DELAY_MS: u64 = 3;
const OPERATION_TIMEOUT: Duration = Duration::from_secs(5);

fuzz_target!(|input: MutexPoisonFuzz| {
    // Apply resource limits
    let max_ops = (input.config.max_operations as usize)
        .min(MAX_OPERATIONS)
        .max(1);
    let operations: Vec<_> = input.operations.into_iter().take(max_ops).collect();

    if operations.is_empty() {
        return; // Skip empty operation sequences
    }

    // Execute the poison sequence test
    execute_and_verify_poison_correctness(input.start_poisoned, operations);
});

/// Tracks mutex operations during testing
struct MutexTracker {
    /// Whether the mutex should be poisoned
    is_poisoned: bool,
    /// Currently held guards by ID
    held_guards: HashMap<u8, GuardInfo>,
    /// Total operation counts
    acquire_attempts: usize,
    successful_acquires: usize,
    /// Operation log for debugging
    operation_log: Vec<OperationEvent>,
}

#[derive(Debug, Clone)]
struct GuardInfo {
    acquired_at: Instant,
}

#[derive(Debug, Clone)]
enum OperationEvent {
    TryAcquireSuccess {
        guard_id: u8,
        timestamp: Instant,
    },
    TryAcquireFailed {
        guard_id: u8,
        reason: String,
        timestamp: Instant,
    },
    GuardReleased {
        guard_id: u8,
        timestamp: Instant,
    },
    StateChecked {
        check_type: String,
        value: String,
        timestamp: Instant,
    },
}

impl MutexTracker {
    fn new(is_poisoned: bool) -> Self {
        Self {
            is_poisoned,
            held_guards: HashMap::new(),
            acquire_attempts: 0,
            successful_acquires: 0,
            operation_log: Vec::new(),
        }
    }

    fn record_try_acquire_success(&mut self, guard_id: u8) {
        self.acquire_attempts += 1;
        self.successful_acquires += 1;
        self.held_guards.insert(
            guard_id,
            GuardInfo {
                acquired_at: Instant::now(),
            },
        );
        self.operation_log.push(OperationEvent::TryAcquireSuccess {
            guard_id,
            timestamp: Instant::now(),
        });
    }

    fn record_try_acquire_failed(&mut self, guard_id: u8, reason: String) {
        self.acquire_attempts += 1;
        self.operation_log.push(OperationEvent::TryAcquireFailed {
            guard_id,
            reason,
            timestamp: Instant::now(),
        });
    }

    fn record_release(&mut self, guard_id: u8) -> bool {
        if self.held_guards.remove(&guard_id).is_some() {
            self.operation_log.push(OperationEvent::GuardReleased {
                guard_id,
                timestamp: Instant::now(),
            });
            true
        } else {
            false
        }
    }

    fn record_state_check(&mut self, check_type: String, value: String) {
        self.operation_log.push(OperationEvent::StateChecked {
            check_type,
            value,
            timestamp: Instant::now(),
        });
    }

    /// Verify poison correctness properties
    fn verify_poison_invariants(&self) {
        // Basic sanity checks
        assert!(
            self.successful_acquires <= self.acquire_attempts,
            "More successful acquires than attempts: success={}, attempts={}",
            self.successful_acquires,
            self.acquire_attempts
        );

        // If poisoned, successful acquires should be 0
        if self.is_poisoned {
            assert_eq!(
                self.successful_acquires, 0,
                "Poisoned mutex should have no successful acquires: success={}",
                self.successful_acquires
            );
        }
    }
}

/// Create a poisoned mutex by having a thread panic while holding it
fn create_poisoned_mutex() -> Arc<Mutex<u32>> {
    let mutex = Arc::new(Mutex::new(42_u32));
    let m = Arc::clone(&mutex);

    let handle = std::thread::spawn(move || {
        let cx = Cx::new(
            RegionId::from_arena(ArenaIndex::new(0, 99)),
            TaskId::from_arena(ArenaIndex::new(0, 99)),
            Budget::INFINITE,
        );

        // This is a blocking helper for tests - poll until ready
        let mut future = m.lock(&cx);
        let waker = std::task::Waker::noop();
        let mut context = std::task::Context::from_waker(waker);
        loop {
            match std::pin::Pin::new(&mut future).poll(&mut context) {
                std::task::Poll::Ready(Ok(_guard)) => {
                    // Panic while holding the guard to poison the mutex
                    panic!("Deliberate panic to poison mutex");
                }
                std::task::Poll::Ready(Err(_)) => {
                    panic!("Failed to acquire mutex for poisoning");
                }
                std::task::Poll::Pending => {
                    // Yield and try again
                    std::thread::yield_now();
                }
            }
        }
    });

    // Wait for the thread to panic. An Ok join means the helper exited
    // without poisoning the mutex, so make that outcome fuzz-visible.
    assert!(
        handle.join().is_err(),
        "poison helper exited without panicking"
    );

    // Verify the mutex is actually poisoned
    assert!(mutex.is_poisoned(), "Mutex should be poisoned after panic");

    mutex
}

/// Execute poison operations and verify correctness
fn execute_and_verify_poison_correctness(start_poisoned: bool, operations: Vec<MutexOperation>) {
    // Create mutex (poisoned or clean)
    let mutex = if start_poisoned {
        create_poisoned_mutex()
    } else {
        Arc::new(Mutex::new(42_u32))
    };

    let mut tracker = MutexTracker::new(start_poisoned);
    let mut guards: HashMap<u8, asupersync::sync::MutexGuard<'_, u32>> = HashMap::new();

    let start_time = Instant::now();

    for operation in operations {
        // Check timeout
        if start_time.elapsed() > OPERATION_TIMEOUT {
            break;
        }

        match operation {
            MutexOperation::TryAcquire { guard_id } => {
                let guard_key = guard_id % (MAX_GUARDS as u8);

                // Skip if guard already exists
                if guards.contains_key(&guard_key) {
                    continue;
                }

                match mutex.try_lock() {
                    Ok(guard) => {
                        // Should only succeed if mutex is not poisoned
                        assert!(!tracker.is_poisoned, "try_lock succeeded on poisoned mutex");

                        tracker.record_try_acquire_success(guard_key);
                        guards.insert(guard_key, guard);
                    }
                    Err(TryLockError::Poisoned) => {
                        // Should only happen if mutex is poisoned
                        assert!(
                            tracker.is_poisoned,
                            "try_lock failed with Poisoned but mutex should not be poisoned"
                        );

                        tracker.record_try_acquire_failed(guard_key, "poisoned".to_string());
                    }
                    Err(TryLockError::Locked) => {
                        // Should only happen if mutex is not poisoned but locked
                        assert!(
                            !tracker.is_poisoned,
                            "try_lock failed with Locked on poisoned mutex"
                        );

                        tracker.record_try_acquire_failed(guard_key, "locked".to_string());
                    }
                }
            }

            MutexOperation::Release { guard_id } => {
                let guard_key = guard_id % (MAX_GUARDS as u8);

                if guards.remove(&guard_key).is_some() {
                    tracker.record_release(guard_key);
                }
            }

            MutexOperation::CheckPoisoned => {
                let actual_poisoned = mutex.is_poisoned();
                tracker.record_state_check("poisoned".to_string(), actual_poisoned.to_string());

                // Verify poison state matches expectation
                assert_eq!(
                    actual_poisoned, tracker.is_poisoned,
                    "Poison state mismatch: expected={}, actual={}",
                    tracker.is_poisoned, actual_poisoned
                );
            }

            MutexOperation::CheckLocked => {
                let is_locked = mutex.is_locked();
                tracker.record_state_check("locked".to_string(), is_locked.to_string());

                // If poisoned, the locked state is undefined, so we don't assert anything
                // If not poisoned, locked should match whether we have guards
                if !tracker.is_poisoned {
                    let expected_locked = !guards.is_empty();
                    assert_eq!(
                        is_locked, expected_locked,
                        "Lock state mismatch on non-poisoned mutex: expected={}, actual={}",
                        expected_locked, is_locked
                    );
                }
            }

            MutexOperation::CheckWaiters => {
                let waiter_count = mutex.waiters();
                tracker.record_state_check("waiters".to_string(), waiter_count.to_string());

                // Waiter count should always be 0 in this test since we're not doing async waits
                assert_eq!(
                    waiter_count, 0,
                    "Expected 0 waiters in sync-only test, got {}",
                    waiter_count
                );
            }

            MutexOperation::Delay { milliseconds } => {
                let delay = Duration::from_millis((milliseconds as u64).min(MAX_DELAY_MS));
                std::thread::sleep(delay);
            }
        }
    }

    // Final verification
    tracker.verify_poison_invariants();

    // Clean up any remaining guards
    guards.clear();

    // Final poison state check
    let final_poisoned = mutex.is_poisoned();
    assert_eq!(
        final_poisoned, tracker.is_poisoned,
        "Final poison state changed unexpectedly"
    );

    // Verify behavior after all operations
    if tracker.is_poisoned {
        // Poisoned mutex should always return Poisoned error
        match mutex.try_lock() {
            Err(TryLockError::Poisoned) => {
                // Expected
            }
            other => {
                panic!(
                    "Expected try_lock to fail with Poisoned on poisoned mutex, got: {:?}",
                    other
                );
            }
        }
    } else {
        // Non-poisoned mutex should be lockable (if no guards held)
        if guards.is_empty() {
            match mutex.try_lock() {
                Ok(_guard) => {
                    // Expected
                }
                Err(err) => {
                    panic!(
                        "Expected try_lock to succeed on non-poisoned, unlocked mutex, got: {:?}",
                        err
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clean_mutex_operations() {
        let operations = vec![
            MutexOperation::CheckPoisoned, // Should be false
            MutexOperation::TryAcquire { guard_id: 1 },
            MutexOperation::CheckLocked,  // Should be true
            MutexOperation::CheckWaiters, // Should be 0
            MutexOperation::Release { guard_id: 1 },
            MutexOperation::CheckLocked, // Should be false
        ];
        execute_and_verify_poison_correctness(false, operations);
    }

    #[test]
    fn test_poisoned_mutex_operations() {
        let operations = vec![
            MutexOperation::CheckPoisoned,              // Should be true
            MutexOperation::TryAcquire { guard_id: 1 }, // Should fail with Poisoned
            MutexOperation::CheckLocked,                // State undefined but shouldn't crash
            MutexOperation::CheckWaiters,               // Should be 0
        ];
        execute_and_verify_poison_correctness(true, operations);
    }

    #[test]
    fn test_multiple_acquire_attempts_on_poisoned() {
        let operations = vec![
            MutexOperation::TryAcquire { guard_id: 1 }, // Should fail
            MutexOperation::TryAcquire { guard_id: 2 }, // Should fail
            MutexOperation::TryAcquire { guard_id: 3 }, // Should fail
            MutexOperation::CheckPoisoned,              // Should be true
        ];
        execute_and_verify_poison_correctness(true, operations);
    }

    #[test]
    fn test_release_nonexistent_guard() {
        let operations = vec![
            MutexOperation::Release { guard_id: 99 }, // Should be no-op
            MutexOperation::CheckLocked,              // Should be false
            MutexOperation::TryAcquire { guard_id: 1 }, // Should succeed
            MutexOperation::Release { guard_id: 1 },  // Should work
            MutexOperation::Release { guard_id: 1 },  // Should be no-op
        ];
        execute_and_verify_poison_correctness(false, operations);
    }

    #[test]
    fn test_mixed_operations_clean_mutex() {
        let operations = vec![
            MutexOperation::CheckPoisoned,
            MutexOperation::TryAcquire { guard_id: 1 },
            MutexOperation::Delay { milliseconds: 1 },
            MutexOperation::CheckLocked,
            MutexOperation::TryAcquire { guard_id: 2 }, // Should fail with Locked
            MutexOperation::Release { guard_id: 1 },
            MutexOperation::TryAcquire { guard_id: 2 }, // Should now succeed
            MutexOperation::Release { guard_id: 2 },
            MutexOperation::CheckWaiters,
        ];
        execute_and_verify_poison_correctness(false, operations);
    }
}
