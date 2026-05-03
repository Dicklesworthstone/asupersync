#![no_main]

use arbitrary::Arbitrary;
use asupersync::sync::Semaphore;
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Structure-aware fuzzer for Semaphore permit acquire/forget/drop equivalence
///
/// Tests the permit lifecycle correctness under arbitrary operations:
/// 1. Total permits remain stable (initial = available + held + forgotten)
/// 2. No permit leaks (except intentional via forget)
/// 3. Proper RAII release semantics on drop
/// 4. Permit count consistency under mixed acquire/release patterns
#[derive(Arbitrary, Debug)]
struct SemaphorePermitFuzz {
    /// Initial semaphore capacity
    initial_permits: u8,
    /// Sequence of permit operations to perform
    operations: Vec<PermitOperation>,
    /// Test configuration parameters
    config: TestConfig,
}

#[derive(Arbitrary, Debug, Clone)]
enum PermitOperation {
    /// Try to acquire N permits (try_acquire)
    TryAcquire {
        permit_id: u8, // Permit identifier for tracking (0-31)
        count: u8,     // Number of permits to acquire (1-8)
    },
    /// Drop a specific permit (RAII release)
    Drop {
        permit_id: u8, // Permit to drop (0-31)
    },
    /// Forget a specific permit (intentional leak)
    Forget {
        permit_id: u8, // Permit to forget (0-31)
    },
    /// Commit a specific permit (explicit release)
    Commit {
        permit_id: u8, // Permit to commit (0-31)
    },
    /// Check current available permits
    CheckAvailable,
    /// Brief delay for interleaving
    Delay {
        milliseconds: u8, // Delay duration (0-10ms)
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
const MAX_PERMITS: usize = 32;
const MAX_PERMIT_COUNT: usize = 8;
const MAX_DELAY_MS: u64 = 5;
const OPERATION_TIMEOUT: Duration = Duration::from_secs(10);

fuzz_target!(|input: SemaphorePermitFuzz| {
    // Apply resource limits
    let initial_permits = (input.initial_permits as usize).min(MAX_PERMITS).max(1);
    let max_ops = (input.config.max_operations as usize)
        .min(MAX_OPERATIONS)
        .max(1);
    let operations: Vec<_> = input.operations.into_iter().take(max_ops).collect();

    if operations.is_empty() {
        return; // Skip empty operation sequences
    }

    // Execute the permit lifecycle test
    execute_and_verify_permit_lifecycle(initial_permits, operations);
});

/// Tracks permit lifecycle state during operations
struct PermitTracker {
    /// Initial permit capacity
    initial_permits: usize,
    /// Currently held permits by ID
    held_permits: HashMap<u8, HeldPermit>,
    /// Total permits acquired
    permits_acquired: usize,
    /// Total permits forgotten (intentionally leaked)
    permits_forgotten: usize,
    /// Total permits dropped/committed (released)
    permits_released: usize,
    /// Operation sequence for debugging
    operation_log: Vec<OperationEvent>,
}

#[derive(Debug, Clone)]
struct HeldPermit {
    count: usize,
    acquired_at: Instant,
}

#[derive(Debug, Clone)]
enum OperationEvent {
    TryAcquireSuccess {
        permit_id: u8,
        count: usize,
        timestamp: Instant,
    },
    TryAcquireFailed {
        permit_id: u8,
        count: usize,
        available: usize,
        timestamp: Instant,
    },
    PermitDropped {
        permit_id: u8,
        count: usize,
        timestamp: Instant,
    },
    PermitForgotten {
        permit_id: u8,
        count: usize,
        timestamp: Instant,
    },
    PermitCommitted {
        permit_id: u8,
        count: usize,
        timestamp: Instant,
    },
    AvailableCheck {
        available: usize,
        timestamp: Instant,
    },
}

impl PermitTracker {
    fn new(initial_permits: usize) -> Self {
        Self {
            initial_permits,
            held_permits: HashMap::new(),
            permits_acquired: 0,
            permits_forgotten: 0,
            permits_released: 0,
            operation_log: Vec::new(),
        }
    }

    fn record_acquire_success(&mut self, permit_id: u8, count: usize) {
        self.permits_acquired += count;
        self.held_permits.insert(
            permit_id,
            HeldPermit {
                count,
                acquired_at: Instant::now(),
            },
        );
        self.operation_log.push(OperationEvent::TryAcquireSuccess {
            permit_id,
            count,
            timestamp: Instant::now(),
        });
    }

    fn record_acquire_failed(&mut self, permit_id: u8, count: usize, available: usize) {
        self.operation_log.push(OperationEvent::TryAcquireFailed {
            permit_id,
            count,
            available,
            timestamp: Instant::now(),
        });
    }

    fn record_drop(&mut self, permit_id: u8) -> Option<usize> {
        if let Some(held) = self.held_permits.remove(&permit_id) {
            self.permits_released += held.count;
            self.operation_log.push(OperationEvent::PermitDropped {
                permit_id,
                count: held.count,
                timestamp: Instant::now(),
            });
            Some(held.count)
        } else {
            None
        }
    }

    fn record_forget(&mut self, permit_id: u8) -> Option<usize> {
        if let Some(held) = self.held_permits.remove(&permit_id) {
            self.permits_forgotten += held.count;
            self.operation_log.push(OperationEvent::PermitForgotten {
                permit_id,
                count: held.count,
                timestamp: Instant::now(),
            });
            Some(held.count)
        } else {
            None
        }
    }

    fn record_commit(&mut self, permit_id: u8) -> Option<usize> {
        if let Some(held) = self.held_permits.remove(&permit_id) {
            self.permits_released += held.count;
            self.operation_log.push(OperationEvent::PermitCommitted {
                permit_id,
                count: held.count,
                timestamp: Instant::now(),
            });
            Some(held.count)
        } else {
            None
        }
    }

    fn record_available_check(&mut self, available: usize) {
        self.operation_log.push(OperationEvent::AvailableCheck {
            available,
            timestamp: Instant::now(),
        });
    }

    /// Verify permit lifecycle conservation laws
    fn verify_permit_conservation(&self, final_available: usize) {
        // Law 1: Total permits are conserved
        let held_permits: usize = self.held_permits.values().map(|h| h.count).sum();
        let total_accounted = final_available + held_permits + self.permits_forgotten;

        assert_eq!(
            total_accounted,
            self.initial_permits,
            "Permit conservation violated: initial={}, available={}, held={}, forgotten={}, total_accounted={}",
            self.initial_permits,
            final_available,
            held_permits,
            self.permits_forgotten,
            total_accounted
        );

        // Law 2: Acquired permits = released + forgotten + currently held
        let total_disposed = self.permits_released + self.permits_forgotten + held_permits;
        assert_eq!(
            self.permits_acquired,
            total_disposed,
            "Permit accounting violated: acquired={}, released={}, forgotten={}, held={}, total_disposed={}",
            self.permits_acquired,
            self.permits_released,
            self.permits_forgotten,
            held_permits,
            total_disposed
        );

        // Law 3: Available + held + forgotten = initial (basic conservation)
        assert!(
            final_available <= self.initial_permits,
            "Available permits ({}) exceeds initial capacity ({})",
            final_available,
            self.initial_permits
        );

        // Law 4: No negative permits
        assert!(
            held_permits <= self.initial_permits,
            "Held permits ({}) exceeds total capacity ({})",
            held_permits,
            self.initial_permits
        );
    }
}

/// Execute permit lifecycle operations and verify conservation laws
fn execute_and_verify_permit_lifecycle(initial_permits: usize, operations: Vec<PermitOperation>) {
    // Create semaphore and tracker
    let semaphore = Semaphore::new(initial_permits);
    let mut tracker = PermitTracker::new(initial_permits);
    let mut active_permits: HashMap<u8, asupersync::sync::SemaphorePermit<'_>> = HashMap::new();

    let start_time = Instant::now();

    for operation in operations {
        // Check timeout
        if start_time.elapsed() > OPERATION_TIMEOUT {
            break;
        }

        match operation {
            PermitOperation::TryAcquire { permit_id, count } => {
                let permit_count = (count as usize).min(MAX_PERMIT_COUNT).max(1);

                // Skip if permit ID already exists
                if active_permits.contains_key(&permit_id) {
                    continue;
                }

                match semaphore.try_acquire(permit_count) {
                    Ok(permit) => {
                        tracker.record_acquire_success(permit_id, permit_count);
                        active_permits.insert(permit_id, permit);
                    }
                    Err(_) => {
                        let available = semaphore.available_permits();
                        tracker.record_acquire_failed(permit_id, permit_count, available);
                    }
                }
            }

            PermitOperation::Drop { permit_id } => {
                if let Some(permit) = active_permits.remove(&permit_id) {
                    let count = permit.count();
                    tracker.record_drop(permit_id);
                    drop(permit); // Explicit RAII drop
                }
            }

            PermitOperation::Forget { permit_id } => {
                if let Some(permit) = active_permits.remove(&permit_id) {
                    let count = permit.count();
                    tracker.record_forget(permit_id);
                    permit.forget(); // Intentional leak
                }
            }

            PermitOperation::Commit { permit_id } => {
                if let Some(permit) = active_permits.remove(&permit_id) {
                    let count = permit.count();
                    tracker.record_commit(permit_id);
                    permit.commit(); // Explicit release
                }
            }

            PermitOperation::CheckAvailable => {
                let available = semaphore.available_permits();
                tracker.record_available_check(available);
            }

            PermitOperation::Delay { milliseconds } => {
                let delay = Duration::from_millis((milliseconds as u64).min(MAX_DELAY_MS));
                std::thread::sleep(delay);
            }
        }
    }

    // Final permit accounting - ensure any remaining permits are properly tracked
    for (&permit_id, permit) in &active_permits {
        tracker.held_permits.entry(permit_id).or_insert(HeldPermit {
            count: permit.count(),
            acquired_at: Instant::now(),
        });
    }

    // Get final available permits
    let final_available = semaphore.available_permits();

    // Verify permit conservation laws
    tracker.verify_permit_conservation(final_available);

    // Explicitly drop remaining permits to test RAII behavior
    for (_permit_id, permit) in active_permits {
        drop(permit);
    }

    // Final conservation check after cleanup
    let final_available_after_cleanup = semaphore.available_permits();
    let expected_after_cleanup = initial_permits - tracker.permits_forgotten;

    assert_eq!(
        final_available_after_cleanup,
        expected_after_cleanup,
        "After cleanup: available={}, expected={} (initial={} - forgotten={})",
        final_available_after_cleanup,
        expected_after_cleanup,
        initial_permits,
        tracker.permits_forgotten
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_acquire_and_drop() {
        let operations = vec![
            PermitOperation::TryAcquire {
                permit_id: 1,
                count: 2,
            },
            PermitOperation::Drop { permit_id: 1 },
        ];
        execute_and_verify_permit_lifecycle(5, operations);
    }

    #[test]
    fn test_acquire_and_forget() {
        let operations = vec![
            PermitOperation::TryAcquire {
                permit_id: 1,
                count: 2,
            },
            PermitOperation::Forget { permit_id: 1 },
        ];
        execute_and_verify_permit_lifecycle(5, operations);
    }

    #[test]
    fn test_acquire_and_commit() {
        let operations = vec![
            PermitOperation::TryAcquire {
                permit_id: 1,
                count: 2,
            },
            PermitOperation::Commit { permit_id: 1 },
        ];
        execute_and_verify_permit_lifecycle(5, operations);
    }

    #[test]
    fn test_mixed_operations() {
        let operations = vec![
            PermitOperation::TryAcquire {
                permit_id: 1,
                count: 2,
            },
            PermitOperation::TryAcquire {
                permit_id: 2,
                count: 1,
            },
            PermitOperation::Drop { permit_id: 1 },
            PermitOperation::TryAcquire {
                permit_id: 3,
                count: 1,
            },
            PermitOperation::Forget { permit_id: 2 },
            PermitOperation::Commit { permit_id: 3 },
            PermitOperation::CheckAvailable,
        ];
        execute_and_verify_permit_lifecycle(5, operations);
    }

    #[test]
    fn test_try_acquire_exhaustion() {
        let operations = vec![
            PermitOperation::TryAcquire {
                permit_id: 1,
                count: 3,
            },
            PermitOperation::TryAcquire {
                permit_id: 2,
                count: 3,
            }, // Should fail
            PermitOperation::CheckAvailable,
        ];
        execute_and_verify_permit_lifecycle(3, operations);
    }

    #[test]
    fn test_forget_leak_behavior() {
        let operations = vec![
            PermitOperation::TryAcquire {
                permit_id: 1,
                count: 2,
            },
            PermitOperation::TryAcquire {
                permit_id: 2,
                count: 1,
            },
            PermitOperation::Forget { permit_id: 1 }, // Leak 2 permits
            PermitOperation::Drop { permit_id: 2 },   // Release 1 permit
            PermitOperation::CheckAvailable,          // Should have initial - 2
        ];
        execute_and_verify_permit_lifecycle(5, operations);
    }

    #[test]
    fn test_all_operations_single_permit() {
        let operations = vec![
            PermitOperation::TryAcquire {
                permit_id: 1,
                count: 1,
            },
            PermitOperation::CheckAvailable,
            PermitOperation::Drop { permit_id: 1 },
            PermitOperation::TryAcquire {
                permit_id: 2,
                count: 1,
            },
            PermitOperation::Commit { permit_id: 2 },
            PermitOperation::TryAcquire {
                permit_id: 3,
                count: 1,
            },
            PermitOperation::Forget { permit_id: 3 },
            PermitOperation::CheckAvailable,
        ];
        execute_and_verify_permit_lifecycle(1, operations);
    }
}
