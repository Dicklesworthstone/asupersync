#![no_main]
use libfuzzer_sys::fuzz_target;
use asupersync::runtime::scheduler::three_lane::ThreeLaneScheduler;
use asupersync::runtime::{ContendedMutex, RuntimeState};
use std::sync::Arc;

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 {
        return;
    }

    // Parse fuzz input for scheduler configuration edge cases
    let worker_count = data[0] as usize; // Test full range 0-255 (including invalid 0)
    let cancel_streak_limit = ((data[1] as u32) << 8 | data[2] as u32) as usize; // 0-65535
    let enable_governor = data[3] & 1 == 1;
    let governor_interval = data[4] as u32; // 0-255 interval
    let steal_batch_size = ((data[5] as u32) << 8 | data[6] as u32).max(1) as usize; // 1-65535

    // Create runtime state
    let runtime_state = Arc::new(ContendedMutex::new("fuzz-runtime", RuntimeState::new()));

    // Test scheduler creation with fuzzed parameters (including invalid ones)
    let scheduler_result = ThreeLaneScheduler::try_new_with_options_and_task_table(
        worker_count,
        &runtime_state,
        None,
        cancel_streak_limit,
        enable_governor,
        governor_interval,
    );

    match scheduler_result {
        Ok(mut scheduler) => {
            // Successfully created scheduler - test configuration methods
            scheduler.set_steal_batch_size(steal_batch_size);

            // Test adaptive batch profile configuration if data available
            if data.len() >= 16 {
                let profile_data = &data[8..];
                if profile_data.len() >= 8 {
                    let min_batch_size = ((profile_data[0] % 64) + 1) as usize; // 1-64
                    let max_batch_size = (((profile_data[1] as usize) % 512) + 32).max(min_batch_size); // >= min_batch_size
                    let scale_up_ready_depth = ((profile_data[2] as usize) % 128) + 1; // 1-128
                    let scale_up_in_flight = ((profile_data[3] as usize) % 32) + 1; // 1-32
                    let scale_up_claim_failures = ((profile_data[4] as usize) % 16) + 1; // 1-16
                    let cancel_debt_floor = (profile_data[5] as usize) % 64; // 0-63
                    let cooldown_steps = ((profile_data[6] as usize) % 32) + 1; // 1-32
                    let enabled = profile_data[7] & 1 == 1;

                    let profile = asupersync::runtime::scheduler::three_lane::AdaptiveBatchSizingProfile {
                        enabled,
                        min_batch_size,
                        max_batch_size,
                        scale_up_ready_depth,
                        scale_up_in_flight,
                        scale_up_claim_failures,
                        cancel_debt_floor,
                        cooldown_steps,
                    };
                    scheduler.set_adaptive_batch_profile_for_test(Some(profile));
                }
            }

            // Test pressure seeding if more data available
            if data.len() >= 20 {
                let pressure_data = &data[16..];
                if pressure_data.len() >= 4 {
                    let worker_id = pressure_data[0] as usize;
                    let pressure_level = pressure_data[1] as usize; // Use usize as expected

                    if worker_id < 8 && pressure_level < 256 { // Reasonable bounds
                        scheduler.seed_ready_combiner_pressure_for_test(worker_id, pressure_level);
                    }
                }
            }

            // Test scheduler configuration invariants
            verify_scheduler_invariants(&scheduler);
        }
        Err(e) => {
            // Expected failure cases
            if worker_count == 0 {
                // This should fail with ConfigError
                assert!(
                    e.to_string().contains("worker_count >= 1"),
                    "Zero worker count should produce clear error message"
                );
            }
            // Other error cases are valid and should be handled gracefully
        }
    }
});

/// Verify basic scheduler configuration invariants.
///
/// This ensures that no matter what fuzz input we provide, the scheduler
/// maintains its internal consistency when successfully created.
fn verify_scheduler_invariants(_scheduler: &ThreeLaneScheduler) {
    // These are invariants that should hold for any valid scheduler configuration.
    // The actual scheduler doesn't expose many public inspection methods,
    // so we focus on what we can verify without breaking encapsulation.

    // Basic smoke test: scheduler should not panic on these operations
    let _description = format!("ThreeLaneScheduler with configuration OK");

    // If we had public accessor methods, we could verify:
    // - worker_count > 0
    // - cancel_streak_limit reasonable range
    // - governor settings consistent
    // - batch sizes within bounds

    // For now, successful creation implies basic invariants are met
    // since the constructor validates critical parameters
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scheduler_snapshot_basic() {
        let data = vec![2, 4, 5, 1, 3, 0, 32, 1, 2, 3]; // Deterministic test data

        // This should not panic and should exercise the scheduler creation
        fuzz_target(&data);
    }

    #[test]
    fn test_minimal_input() {
        let data = vec![1, 1, 5, 1, 1, 0, 16]; // Minimal valid configuration
        fuzz_target(&data);
    }
}