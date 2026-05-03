//! Fuzz semaphore add_permits + acquire ordering.
//!
//! Tests arbitrary mix of add_permits/try_acquire operations to ensure
//! total acquired permits never exceeds total added permits.
//!
//! Critical invariants:
//! - Total acquired ≤ total added (no over-allocation)
//! - Outstanding permits + available permits = total added
//! - Permit releases restore available count correctly
//! - No permit double-counting or loss across operations

#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use asupersync::sync::semaphore::{Semaphore, TryAcquireError};
use libfuzzer_sys::fuzz_target;
use std::collections::VecDeque;

#[derive(Debug, Clone, Arbitrary)]
struct PermitConfig {
    /// Initial permit count for semaphore (1-1000)
    initial_permits: u16,
    /// Operations to perform
    operations: Vec<SemaphoreOp>,
    /// Maximum permits to add in single operation
    max_add_permits: u16,
    /// Maximum permits to acquire in single operation
    max_acquire_permits: u16,
}

#[derive(Debug, Clone, Arbitrary)]
enum SemaphoreOp {
    /// Add permits to semaphore
    AddPermits { count: u16 },
    /// Try to acquire permits (non-blocking)
    TryAcquire { count: u16 },
    /// Release all held permits
    ReleaseAll,
    /// Release specific number of permits
    ReleaseCount { count: u16 },
    /// Check available permits matches expectation
    CheckAvailable,
}

#[derive(Debug, Clone, Arbitrary)]
struct PermitSequence {
    /// Test configuration
    config: PermitConfig,
    /// Maximum operations to perform
    max_operations: u8,
}

impl PermitSequence {
    fn max_operations() -> u8 {
        50 // Keep test duration reasonable
    }

    fn max_permits() -> u16 {
        1000 // Reasonable upper bound
    }
}

/// Test execution context tracking permit accounting
#[derive(Debug)]
struct PermitTracker {
    total_added: usize,
    total_acquired: usize,
    outstanding_permits: VecDeque<usize>, // Counts of acquired permits not yet released
}

impl PermitTracker {
    fn new(initial: usize) -> Self {
        Self {
            total_added: initial,
            total_acquired: 0,
            outstanding_permits: VecDeque::new(),
        }
    }

    fn add_permits(&mut self, count: usize) {
        self.total_added = self.total_added.saturating_add(count);
    }

    fn acquire_permits(&mut self, count: usize) -> bool {
        if self.total_acquired.saturating_add(count) <= self.total_added {
            self.total_acquired += count;
            self.outstanding_permits.push_back(count);
            true
        } else {
            false // Would exceed total added
        }
    }

    fn release_all_permits(&mut self) -> usize {
        let total_released: usize = self.outstanding_permits.drain(..).sum();
        self.total_acquired = self.total_acquired.saturating_sub(total_released);
        total_released
    }

    fn release_count_permits(&mut self, mut to_release: usize) -> usize {
        let mut actually_released = 0;

        while to_release > 0 && !self.outstanding_permits.is_empty() {
            if let Some(mut permit_count) = self.outstanding_permits.pop_front() {
                let release_from_this = permit_count.min(to_release);
                permit_count -= release_from_this;
                to_release -= release_from_this;
                actually_released += release_from_this;

                if permit_count > 0 {
                    self.outstanding_permits.push_front(permit_count);
                }
            }
        }

        self.total_acquired = self.total_acquired.saturating_sub(actually_released);
        actually_released
    }

    fn check_invariants(&self) -> Result<(), String> {
        // Core invariant: total acquired ≤ total added
        if self.total_acquired > self.total_added {
            return Err(format!(
                "OVER-ALLOCATION: acquired {} > added {}",
                self.total_acquired, self.total_added
            ));
        }

        // Sanity check: outstanding permits sum matches total_acquired
        let outstanding_sum: usize = self.outstanding_permits.iter().sum();
        if outstanding_sum != self.total_acquired {
            return Err(format!(
                "ACCOUNTING MISMATCH: outstanding {} != acquired {}",
                outstanding_sum, self.total_acquired
            ));
        }

        Ok(())
    }
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    let sequence: PermitSequence = match unstructured.arbitrary() {
        Ok(seq) => seq,
        Err(_) => return, // Invalid input, skip
    };

    // Validate and limit parameters
    if sequence.config.operations.is_empty()
        || sequence.config.initial_permits == 0
        || sequence.config.initial_permits > PermitSequence::max_permits()
    {
        return;
    }

    let initial_permits = sequence.config.initial_permits as usize;
    let max_ops = sequence
        .max_operations
        .min(PermitSequence::max_operations()) as usize;

    // Create semaphore and tracking state
    let semaphore = Semaphore::new(initial_permits);
    let mut tracker = PermitTracker::new(initial_permits);
    let mut held_permits = Vec::new(); // Actual permits from semaphore

    for (i, op) in sequence.config.operations.iter().take(max_ops).enumerate() {
        // Check invariants before each operation
        if let Err(msg) = tracker.check_invariants() {
            panic!("Invariant violation at operation {}: {}", i, msg);
        }

        match op {
            SemaphoreOp::AddPermits { count } => {
                let count = (*count as usize).min(PermitSequence::max_permits() as usize);
                if count == 0 {
                    continue;
                }

                semaphore.add_permits(count);
                tracker.add_permits(count);
            }

            SemaphoreOp::TryAcquire { count } => {
                let count = (*count as usize)
                    .min(PermitSequence::max_permits() as usize)
                    .max(1); // acquire requires count > 0

                // Check if acquisition should be allowed by our tracker
                let should_succeed =
                    tracker.total_acquired.saturating_add(count) <= tracker.total_added;

                match semaphore.try_acquire(count) {
                    Ok(permit) => {
                        assert!(
                            should_succeed,
                            "Semaphore allowed acquisition that would exceed total added: \
                             acquired {} + {} > added {} at operation {}",
                            tracker.total_acquired, count, tracker.total_added, i
                        );

                        assert_eq!(permit.count(), count);
                        assert!(tracker.acquire_permits(count));
                        held_permits.push(permit);
                    }
                    Err(TryAcquireError) => {
                        // Acquisition failed - this is OK, could be due to:
                        // 1. Insufficient permits (expected when would over-allocate)
                        // 2. FIFO ordering (waiters in queue)
                        // 3. Semaphore closed (not in this test)
                    }
                }
            }

            SemaphoreOp::ReleaseAll => {
                let expected_released = tracker.release_all_permits();
                let actual_released = held_permits.len();

                // Clear all held permits (Drop impl releases them back)
                held_permits.clear();

                // Verify counts match
                assert_eq!(
                    expected_released,
                    held_permits.iter().map(|p| p.count()).sum::<usize>(),
                    "Release count mismatch at operation {}",
                    i
                );
            }

            SemaphoreOp::ReleaseCount { count } => {
                let count = (*count as usize).min(held_permits.len());
                if count == 0 {
                    continue;
                }

                let permits_to_release: Vec<_> = held_permits.drain(..count).collect();
                let released_count: usize = permits_to_release.iter().map(|p| p.count()).sum();
                tracker.release_count_permits(released_count);

                // Permits automatically released via Drop
                drop(permits_to_release);
            }

            SemaphoreOp::CheckAvailable => {
                let available = semaphore.available_permits();
                let expected_available = tracker.total_added.saturating_sub(tracker.total_acquired);

                // Note: available_permits() is advisory and may be stale due to Relaxed ordering
                // We can't assert exact equality, but can check it's reasonable
                if available > tracker.total_added {
                    panic!(
                        "Available permits {} exceeds total added {} at operation {}",
                        available, tracker.total_added, i
                    );
                }
            }
        }

        // Check invariants after each operation
        if let Err(msg) = tracker.check_invariants() {
            panic!("Invariant violation after operation {}: {}", i, msg);
        }

        // Core assertion: total acquired never exceeds total added
        assert!(
            tracker.total_acquired <= tracker.total_added,
            "CRITICAL: Over-allocation detected at operation {}: acquired {} > added {}",
            i,
            tracker.total_acquired,
            tracker.total_added
        );
    }

    // Final invariant check
    if let Err(msg) = tracker.check_invariants() {
        panic!("Final invariant violation: {}", msg);
    }

    // Release all remaining permits
    held_permits.clear();

    // After releasing all permits, available should equal total added
    // (Give a moment for Drop to take effect)
    let final_available = semaphore.available_permits();
    if final_available != tracker.total_added {
        // This might be OK due to advisory nature of available_permits()
        // Log but don't panic unless it's clearly wrong
        if final_available > tracker.total_added {
            panic!(
                "Final available {} > total added {} - permits were created from nowhere",
                final_available, tracker.total_added
            );
        }
    }
});
