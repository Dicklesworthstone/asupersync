//! Fuzz semaphore forget+reacquire scenarios.
//!
//! Tests arbitrary forget+acquire patterns to ensure forgotten permits
//! are never re-counted and the semaphore's total invariant is preserved.
//! Forgotten permits should permanently reduce available capacity.
//!
//! Critical invariants:
//! - Forgotten permits never return to available pool
//! - available + acquired + forgotten = initial_permits
//! - Semaphore state remains consistent after forget operations
//! - No double-counting when permits are forgotten then more are acquired

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};
use asupersync::sync::Semaphore;
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Debug, Clone, Arbitrary)]
struct ForgetReacquireConfig {
    /// Initial permits for the semaphore
    initial_permits: u8,
    /// Operations to perform on permits
    operations: Vec<PermitOperation>,
    /// Maximum operations to perform
    max_operations: u8,
    /// Whether to test concurrent scenarios
    test_concurrency: bool,
}

#[derive(Debug, Clone, Arbitrary)]
enum PermitOperation {
    /// Try to acquire N permits
    Acquire { count: u8 },
    /// Forget the permit at index N in held permits
    Forget { permit_index: u8 },
    /// Commit/release the permit at index N in held permits
    Release { permit_index: u8 },
    /// Check available permits matches expectation
    CheckAvailable,
    /// Sequence of rapid acquire+forget cycles
    RapidForgetCycle { cycles: u8, count: u8 },
}

impl ForgetReacquireConfig {
    fn max_initial_permits() -> u8 {
        50 // Keep reasonable for testing
    }

    fn max_operations() -> u8 {
        30 // Limit test duration
    }

    fn max_rapid_cycles() -> u8 {
        10 // Limit rapid cycle count
    }
}

/// Tracks permit accounting to verify invariants
#[derive(Debug)]
struct PermitTracker {
    initial_permits: usize,
    acquired_count: AtomicUsize,
    forgotten_count: AtomicUsize,
    released_count: AtomicUsize,
    operations_performed: AtomicUsize,
}

impl PermitTracker {
    fn new(initial_permits: usize) -> Self {
        Self {
            initial_permits,
            acquired_count: AtomicUsize::new(0),
            forgotten_count: AtomicUsize::new(0),
            released_count: AtomicUsize::new(0),
            operations_performed: AtomicUsize::new(0),
        }
    }

    fn record_acquire(&self, count: usize) {
        self.acquired_count.fetch_add(count, Ordering::SeqCst);
        self.operations_performed.fetch_add(1, Ordering::SeqCst);
    }

    fn record_forget(&self, count: usize) {
        self.forgotten_count.fetch_add(count, Ordering::SeqCst);
        self.operations_performed.fetch_add(1, Ordering::SeqCst);
    }

    fn record_release(&self, count: usize) {
        self.released_count.fetch_add(count, Ordering::SeqCst);
        self.operations_performed.fetch_add(1, Ordering::SeqCst);
    }

    fn check_invariants(&self, semaphore: &Semaphore) -> Result<(), String> {
        let acquired = self.acquired_count.load(Ordering::SeqCst);
        let forgotten = self.forgotten_count.load(Ordering::SeqCst);
        let released = self.released_count.load(Ordering::SeqCst);
        let available = semaphore.available_permits();

        // Core invariant: available + currently_held + forgotten = initial
        let currently_held = acquired.saturating_sub(released.saturating_add(forgotten));
        let total_accounted = available + currently_held + forgotten;

        if total_accounted != self.initial_permits {
            return Err(format!(
                "Permit invariant violation: available({}) + held({}) + forgotten({}) = {} != initial({})",
                available, currently_held, forgotten, total_accounted, self.initial_permits
            ));
        }

        // Forgotten permits should never return to available pool
        let expected_available = self.initial_permits.saturating_sub(currently_held + forgotten);
        if available != expected_available {
            return Err(format!(
                "Available permits mismatch: expected {} (initial - held - forgotten), got {}",
                expected_available, available
            ));
        }

        // Sanity check: counts should be reasonable
        if forgotten > self.initial_permits {
            return Err(format!(
                "More permits forgotten ({}) than initial ({})",
                forgotten, self.initial_permits
            ));
        }

        if acquired > (self.initial_permits * 10) {
            return Err(format!(
                "Suspiciously high acquire count ({}), possible double-counting",
                acquired
            ));
        }

        Ok(())
    }
}

/// Test forget+reacquire scenarios
fn test_forget_reacquire_scenario(
    config: &ForgetReacquireConfig,
    tracker: &PermitTracker,
) -> Result<(), String> {
    use std::collections::VecDeque;

    let initial_permits = config.initial_permits.min(ForgetReacquireConfig::max_initial_permits()) as usize;
    if initial_permits == 0 {
        return Ok(()); // No permits to test
    }

    let semaphore = Semaphore::new(initial_permits);
    let mut held_permits = VecDeque::new();

    let max_ops = config.max_operations.min(ForgetReacquireConfig::max_operations()) as usize;

    for operation in config.operations.iter().take(max_ops) {
        match operation {
            PermitOperation::Acquire { count } => {
                let acquire_count = (*count as usize).min(initial_permits);
                if acquire_count == 0 {
                    continue;
                }

                match semaphore.try_acquire(acquire_count) {
                    Ok(permit) => {
                        tracker.record_acquire(acquire_count);
                        held_permits.push_back(permit);
                    }
                    Err(_) => {
                        // Failed to acquire - this is expected when no permits available
                    }
                }
            }

            PermitOperation::Forget { permit_index } => {
                if held_permits.is_empty() {
                    continue;
                }

                let index = (*permit_index as usize) % held_permits.len();
                if let Some(permit) = held_permits.remove(index) {
                    let count = permit.count();
                    tracker.record_forget(count);
                    permit.forget(); // This should permanently remove permits from pool
                }
            }

            PermitOperation::Release { permit_index } => {
                if held_permits.is_empty() {
                    continue;
                }

                let index = (*permit_index as usize) % held_permits.len();
                if let Some(permit) = held_permits.remove(index) {
                    let count = permit.count();
                    tracker.record_release(count);
                    // Normal drop will release permits back to semaphore
                    drop(permit);
                }
            }

            PermitOperation::CheckAvailable => {
                if let Err(msg) = tracker.check_invariants(&semaphore) {
                    return Err(format!("Invariant check failed: {}", msg));
                }
            }

            PermitOperation::RapidForgetCycle { cycles, count } => {
                let cycle_count = (*cycles).min(ForgetReacquireConfig::max_rapid_cycles()) as usize;
                let permit_count = (*count as usize).max(1).min(5);

                for _ in 0..cycle_count {
                    // Try acquire
                    if let Ok(permit) = semaphore.try_acquire(permit_count) {
                        tracker.record_acquire(permit_count);

                        // Immediately forget
                        tracker.record_forget(permit_count);
                        permit.forget();
                    }

                    // Check invariants after each cycle
                    if let Err(msg) = tracker.check_invariants(&semaphore) {
                        return Err(format!("Rapid cycle invariant violation: {}", msg));
                    }
                }
            }
        }

        // Check invariants after each operation
        if let Err(msg) = tracker.check_invariants(&semaphore) {
            return Err(format!("Post-operation invariant violation: {}", msg));
        }
    }

    // Release all remaining permits
    while let Some(permit) = held_permits.pop_front() {
        let count = permit.count();
        tracker.record_release(count);
        drop(permit);
    }

    // Final invariant check
    if let Err(msg) = tracker.check_invariants(&semaphore) {
        return Err(format!("Final invariant violation: {}", msg));
    }

    Ok(())
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    let config: ForgetReacquireConfig = match unstructured.arbitrary() {
        Ok(cfg) => cfg,
        Err(_) => return, // Invalid input, skip
    };

    // Validate and limit parameters
    if config.operations.is_empty() || config.initial_permits == 0 {
        return;
    }

    let initial_permits = config.initial_permits.min(ForgetReacquireConfig::max_initial_permits()) as usize;
    let tracker = PermitTracker::new(initial_permits);

    // Test the forget+reacquire scenario
    if let Err(msg) = test_forget_reacquire_scenario(&config, &tracker) {
        panic!("Forget+reacquire scenario test failed: {}", msg);
    }

    // Test concurrent scenarios if requested
    if config.test_concurrency {
        use std::thread;

        let tracker2 = PermitTracker::new(initial_permits);
        let config2 = config.clone();

        // Run a concurrent test
        let handle = thread::spawn(move || {
            test_forget_reacquire_scenario(&config2, &tracker2)
        });

        match handle.join() {
            Ok(Ok(())) => {
                // Concurrent test succeeded
            }
            Ok(Err(msg)) => {
                panic!("Concurrent forget+reacquire test failed: {}", msg);
            }
            Err(_) => {
                panic!("Concurrent test thread panicked");
            }
        }
    }

    // Ensure we actually performed some operations
    let operations_performed = tracker.operations_performed.load(Ordering::SeqCst);
    if operations_performed == 0 {
        panic!("No operations were performed during the test");
    }
});