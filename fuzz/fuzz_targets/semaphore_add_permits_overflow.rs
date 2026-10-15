//! Fuzz semaphore add_permits overflow handling.
//!
//! Tests arbitrary add_permits values approaching usize::MAX to ensure
//! the implementation uses saturating addition rather than wrapping overflow.
//! Validates no undefined behavior occurs when adding permits that would
//! mathematically exceed usize::MAX.
//!
//! Critical invariants:
//! - add_permits never causes integer overflow (uses saturating_add)
//! - Available permits never exceed usize::MAX
//! - Multiple add_permits calls with large values remain stable
//! - Semaphore state remains consistent after overflow attempts

#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use asupersync::sync::Semaphore;
use libfuzzer_sys::fuzz_target;
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Debug, Clone, Arbitrary)]
struct OverflowConfig {
    /// Initial permits for the semaphore
    initial_permits: PermitCount,
    /// Sequence of add_permits operations to perform
    operations: Vec<AddPermitsOperation>,
    /// Maximum operations to perform (prevent excessive test duration)
    max_operations: u8,
}

#[derive(Debug, Clone, Arbitrary)]
enum PermitCount {
    /// Small initial count
    Small(u8),
    /// Medium initial count
    Medium(u16),
    /// Large initial count
    Large(u32),
    /// Near maximum initial count
    NearMax(u8), // Will be converted to usize::MAX - value
    /// Exactly maximum
    Maximum,
}

impl PermitCount {
    fn to_usize(&self) -> usize {
        match self {
            PermitCount::Small(n) => *n as usize,
            PermitCount::Medium(n) => *n as usize,
            PermitCount::Large(n) => *n as usize,
            PermitCount::NearMax(offset) => usize::MAX.saturating_sub(*offset as usize),
            PermitCount::Maximum => usize::MAX,
        }
    }
}

#[derive(Debug, Clone, Arbitrary)]
enum AddPermitsOperation {
    /// Add a small number of permits
    AddSmall(u8),
    /// Add a medium number of permits
    AddMedium(u16),
    /// Add a large number of permits
    AddLarge(u32),
    /// Add a value near usize::MAX
    AddNearMax(u8), // Will be converted to usize::MAX - value
    /// Add exactly usize::MAX
    AddMaximum,
    /// Add zero permits (should be no-op)
    AddZero,
    /// Sequence of rapid small additions
    AddSequence { count: u8, value: u8 },
}

impl AddPermitsOperation {
    fn to_usize(&self) -> usize {
        match self {
            AddPermitsOperation::AddSmall(n) => *n as usize,
            AddPermitsOperation::AddMedium(n) => *n as usize,
            AddPermitsOperation::AddLarge(n) => *n as usize,
            AddPermitsOperation::AddNearMax(offset) => usize::MAX.saturating_sub(*offset as usize),
            AddPermitsOperation::AddMaximum => usize::MAX,
            AddPermitsOperation::AddZero => 0,
            AddPermitsOperation::AddSequence { value, .. } => *value as usize,
        }
    }
}

impl OverflowConfig {
    fn max_operations() -> u8 {
        50 // Keep test duration reasonable while exploring edge cases
    }
}

/// Tracks overflow behavior to detect inconsistencies
#[derive(Debug)]
struct OverflowTracker {
    operations_performed: AtomicUsize,
    max_observed_permits: AtomicUsize,
    overflow_attempts: AtomicUsize,
}

impl OverflowTracker {
    fn new() -> Self {
        Self {
            operations_performed: AtomicUsize::new(0),
            max_observed_permits: AtomicUsize::new(0),
            overflow_attempts: AtomicUsize::new(0),
        }
    }

    fn record_operation(&self, permits_added: usize, available_after: usize) {
        self.operations_performed.fetch_add(1, Ordering::SeqCst);

        // Update max observed permits
        self.max_observed_permits
            .fetch_max(available_after, Ordering::SeqCst);

        // Track potential overflow attempts
        if permits_added >= usize::MAX / 2 {
            self.overflow_attempts.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn check_overflow_invariants(&self) -> Result<(), String> {
        let operations = self.operations_performed.load(Ordering::SeqCst);
        let max_permits = self.max_observed_permits.load(Ordering::SeqCst);
        let overflow_attempts = self.overflow_attempts.load(Ordering::SeqCst);

        // Permits should never exceed usize::MAX
        if max_permits > usize::MAX {
            return Err(format!(
                "Available permits exceeded usize::MAX: observed {}",
                max_permits
            ));
        }

        // If we performed operations, we should have observed some permits
        if operations > 0 && max_permits == 0 {
            return Err(format!(
                "No permits observed despite {} operations",
                operations
            ));
        }

        Ok(())
    }
}

/// Validates semaphore behavior remains consistent across add_permits operations
fn validate_semaphore_consistency(
    semaphore: &Semaphore,
    expected_minimum: usize,
) -> Result<(), String> {
    let available = semaphore.available_permits();

    // Available permits should never be less than what we expect based on saturating addition
    if available < expected_minimum {
        return Err(format!(
            "Available permits ({}) less than expected minimum ({})",
            available, expected_minimum
        ));
    }

    // Available permits should never exceed usize::MAX
    if available > usize::MAX {
        return Err(format!(
            "Available permits ({}) exceeded usize::MAX",
            available
        ));
    }

    Ok(())
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    let config: OverflowConfig = match unstructured.arbitrary() {
        Ok(cfg) => cfg,
        Err(_) => return, // Invalid input, skip
    };

    // Validate and limit parameters
    if config.operations.is_empty() {
        return;
    }

    let max_ops = config.max_operations.min(OverflowConfig::max_operations()) as usize;
    let initial_permits = config.initial_permits.to_usize();

    // Create semaphore with initial permits
    let semaphore = Semaphore::new(initial_permits);
    let tracker = OverflowTracker::new();

    // Track expected minimum permits (using saturating arithmetic)
    let mut expected_permits = initial_permits;

    // Perform add_permits operations
    for operation in config.operations.iter().take(max_ops) {
        match operation {
            AddPermitsOperation::AddSequence { count, value } => {
                // Perform rapid sequence of small additions
                let add_value = *value as usize;
                let sequence_count = (*count).min(20) as usize; // Limit to prevent excessive duration

                for _ in 0..sequence_count {
                    let before_permits = semaphore.available_permits();
                    semaphore.add_permits(add_value);
                    let after_permits = semaphore.available_permits();

                    expected_permits = expected_permits.saturating_add(add_value);
                    tracker.record_operation(add_value, after_permits);

                    // Validate consistency after each addition
                    if let Err(msg) =
                        validate_semaphore_consistency(&semaphore, expected_permits.min(usize::MAX))
                    {
                        panic!("Semaphore consistency violation in sequence: {}", msg);
                    }

                    // Ensure permits only increase or stay the same (if at MAX)
                    if after_permits < before_permits {
                        panic!(
                            "Permits decreased: {} -> {} after adding {}",
                            before_permits, after_permits, add_value
                        );
                    }
                }
            }

            _ => {
                // Single add_permits operation
                let add_value = operation.to_usize();
                let before_permits = semaphore.available_permits();

                semaphore.add_permits(add_value);
                let after_permits = semaphore.available_permits();

                expected_permits = expected_permits.saturating_add(add_value);
                tracker.record_operation(add_value, after_permits);

                // Validate consistency
                if let Err(msg) =
                    validate_semaphore_consistency(&semaphore, expected_permits.min(usize::MAX))
                {
                    panic!("Semaphore consistency violation: {}", msg);
                }

                // Ensure permits only increase or stay the same (if at MAX)
                if after_permits < before_permits {
                    panic!(
                        "Permits decreased: {} -> {} after adding {}",
                        before_permits, after_permits, add_value
                    );
                }

                // Special validation for overflow cases
                if add_value >= usize::MAX / 2 && before_permits >= usize::MAX / 2 {
                    // This should definitely saturate at usize::MAX
                    if after_permits != usize::MAX {
                        panic!(
                            "Expected saturation at usize::MAX, got {} (before: {}, added: {})",
                            after_permits, before_permits, add_value
                        );
                    }
                }
            }
        }
    }

    // Final consistency check
    if let Err(msg) = tracker.check_overflow_invariants() {
        panic!("Overflow invariant violation: {}", msg);
    }

    // Verify final state is reasonable
    let final_permits = semaphore.available_permits();
    if final_permits > usize::MAX {
        panic!("Final permits ({}) exceeded usize::MAX", final_permits);
    }

    // Test that the semaphore is still functional after overflow attempts
    if final_permits > 0 {
        // Try to acquire a permit if any are available
        if let Ok(_permit) = semaphore.try_acquire(1) {
            // Successfully acquired - semaphore is still functional
            let after_acquire = semaphore.available_permits();
            if after_acquire >= final_permits {
                panic!(
                    "Permits did not decrease after acquisition: {} -> {}",
                    final_permits, after_acquire
                );
            }
        }
    }
});
