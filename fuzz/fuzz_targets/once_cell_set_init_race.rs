//! Fuzz OnceCell set + get_or_init race conditions.
//!
//! Tests arbitrary mix of set/get_or_init operations across threads to ensure
//! result consistency: either set wins or first init wins, never partial state.
//!
//! Critical invariants:
//! - If set() succeeds, all get_or_init() calls return the set value
//! - If get_or_init() starts first, set() returns Err(value)
//! - No partial initialization or inconsistent states
//! - Exactly one successful initialization per cell

#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use asupersync::sync::once_cell::OnceCell;
use libfuzzer_sys::fuzz_target;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;

#[derive(Debug, Clone, Arbitrary)]
struct RaceConfig {
    /// Number of threads to spawn (2-8)
    thread_count: u8,
    /// Operations each thread will perform
    operations: Vec<ThreadOps>,
    /// Values to use for set operations
    set_values: Vec<u32>,
    /// Delay patterns for threads (microseconds)
    thread_delays: Vec<u32>,
}

#[derive(Debug, Clone, Arbitrary)]
enum ThreadOps {
    /// Call set() with specified value index
    Set { value_index: u8 },
    /// Call get_or_init_blocking() with specified init value
    GetOrInit { init_value: u32 },
    /// Call get() to read current value
    Get,
    /// Small delay before next operation
    Delay { micros: u16 },
}

#[derive(Debug, Clone, Arbitrary)]
struct RaceSequence {
    /// Test configuration
    config: RaceConfig,
    /// Maximum operations per thread
    max_ops_per_thread: u8,
}

impl RaceSequence {
    fn max_threads() -> u8 {
        8 // Reasonable upper bound for thread testing
    }

    fn max_operations() -> u8 {
        20 // Keep test duration reasonable
    }
}

/// Result of a race test operation
#[derive(Debug, Clone, PartialEq)]
enum OpResult {
    SetOk,
    SetErr,
    InitComplete(u32),
    GetSome(u32),
    GetNone,
}

/// Thread execution result
#[derive(Debug, Clone)]
struct ThreadResult {
    thread_id: usize,
    results: Vec<OpResult>,
    final_value: Option<u32>,
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    let sequence: RaceSequence = match unstructured.arbitrary() {
        Ok(seq) => seq,
        Err(_) => return, // Invalid input, skip
    };

    // Validate and limit parameters
    if sequence.config.thread_count == 0
        || sequence.config.thread_count > RaceSequence::max_threads()
        || sequence.config.operations.is_empty()
        || sequence.config.set_values.is_empty()
    {
        return;
    }

    let thread_count = sequence.config.thread_count as usize;
    let max_ops = sequence
        .max_ops_per_thread
        .min(RaceSequence::max_operations()) as usize;

    // Create shared OnceCell and synchronization primitives
    let cell = Arc::new(OnceCell::<u32>::new());
    let start_barrier = Arc::new(Barrier::new(thread_count));
    let completion_count = Arc::new(AtomicUsize::new(0));
    let set_success_count = Arc::new(AtomicUsize::new(0));
    let init_success_count = Arc::new(AtomicUsize::new(0));
    let inconsistent_state_detected = Arc::new(AtomicBool::new(false));

    // Track all observed values for consistency checking
    let observed_values = Arc::new(parking_lot::Mutex::new(Vec::new()));

    let handles: Vec<_> = (0..thread_count)
        .map(|thread_id| {
            let cell = Arc::clone(&cell);
            let start_barrier = Arc::clone(&start_barrier);
            let completion_count = Arc::clone(&completion_count);
            let set_success_count = Arc::clone(&set_success_count);
            let init_success_count = Arc::clone(&init_success_count);
            let inconsistent_state_detected = Arc::clone(&inconsistent_state_detected);
            let observed_values = Arc::clone(&observed_values);

            let operations = sequence.config.operations.clone();
            let set_values = sequence.config.set_values.clone();
            let initial_delay = sequence
                .config
                .thread_delays
                .get(thread_id)
                .copied()
                .unwrap_or(0);

            thread::spawn(move || {
                // Wait for all threads to be ready
                start_barrier.wait();

                // Apply initial thread delay for staggered execution
                if initial_delay > 0 {
                    thread::sleep(Duration::from_micros(initial_delay as u64));
                }

                let mut thread_results = Vec::new();
                let mut operation_count = 0;

                for op in &operations {
                    if operation_count >= max_ops {
                        break; // Respect operation limit
                    }

                    let result = match op {
                        ThreadOps::Set { value_index } => {
                            let value = set_values
                                .get(*value_index as usize % set_values.len())
                                .copied()
                                .unwrap_or(42); // Fallback value

                            match cell.set(value) {
                                Ok(()) => {
                                    set_success_count.fetch_add(1, Ordering::SeqCst);
                                    observed_values.lock().push(value);
                                    OpResult::SetOk
                                }
                                Err(_) => OpResult::SetErr,
                            }
                        }

                        ThreadOps::GetOrInit { init_value } => {
                            let value = *init_value;
                            let result_value = cell.get_or_init_blocking(|| value);

                            // Check if this was the successful initializer
                            if *result_value == value {
                                init_success_count.fetch_add(1, Ordering::SeqCst);
                            }

                            observed_values.lock().push(*result_value);
                            OpResult::InitComplete(*result_value)
                        }

                        ThreadOps::Get => match cell.get() {
                            Some(value) => {
                                observed_values.lock().push(*value);
                                OpResult::GetSome(*value)
                            }
                            None => OpResult::GetNone,
                        },

                        ThreadOps::Delay { micros } => {
                            thread::sleep(Duration::from_micros(*micros as u64));
                            continue; // Don't count delays as operations
                        }
                    };

                    thread_results.push(result);
                    operation_count += 1;

                    // Consistency check: if cell is initialized, all gets should return same value
                    if cell.is_initialized() {
                        let current_value = cell.get();
                        if let Some(val) = current_value {
                            // Check against previous observations from this thread
                            for prev_result in &thread_results {
                                match prev_result {
                                    OpResult::GetSome(prev_val)
                                    | OpResult::InitComplete(prev_val) => {
                                        if prev_val != val {
                                            inconsistent_state_detected
                                                .store(true, Ordering::SeqCst);
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                }

                completion_count.fetch_add(1, Ordering::SeqCst);

                ThreadResult {
                    thread_id,
                    results: thread_results,
                    final_value: cell.get().copied(),
                }
            })
        })
        .collect();

    // Wait for all threads to complete
    let thread_results: Vec<_> = handles
        .into_iter()
        .map(|h| h.join().expect("Thread should complete"))
        .collect();

    // Post-execution consistency checks
    let final_set_successes = set_success_count.load(Ordering::SeqCst);
    let final_init_successes = init_success_count.load(Ordering::SeqCst);
    let inconsistent_detected = inconsistent_state_detected.load(Ordering::SeqCst);

    // Critical invariant: exactly one successful initialization
    assert_eq!(
        final_set_successes + final_init_successes,
        1,
        "Exactly one initialization should succeed: {} set + {} init = {}",
        final_set_successes,
        final_init_successes,
        final_set_successes + final_init_successes
    );

    // Critical invariant: no inconsistent state detected
    assert!(
        !inconsistent_detected,
        "Inconsistent state detected during race"
    );

    // Check all observed values are identical
    let all_values = observed_values.lock();
    if !all_values.is_empty() {
        let first_value = all_values[0];
        for &value in all_values.iter() {
            assert_eq!(
                value, first_value,
                "All observed values should be identical: got {} and {} (first)",
                value, first_value
            );
        }
    }

    // Check final state consistency across all threads
    let final_values: Vec<_> = thread_results
        .iter()
        .filter_map(|r| r.final_value)
        .collect();

    if !final_values.is_empty() {
        let expected_final = final_values[0];
        for &final_value in &final_values {
            assert_eq!(
                final_value, expected_final,
                "All threads should observe same final value: got {} and {} (expected)",
                final_value, expected_final
            );
        }

        // Final value should match all observed values
        for &observed in all_values.iter() {
            assert_eq!(
                observed, expected_final,
                "Final value {} should match all observed values, got {}",
                expected_final, observed
            );
        }
    }

    // State machine invariant: if cell is initialized, it stays initialized
    if cell.is_initialized() {
        assert!(cell.get().is_some(), "Initialized cell should have a value");
    }

    // Validate that set/init operations followed expected patterns
    for result in &thread_results {
        let mut saw_successful_op = false;
        let mut value_after_success: Option<u32> = None;

        for op_result in &result.results {
            match op_result {
                OpResult::SetOk | OpResult::InitComplete(_) => {
                    assert!(
                        !saw_successful_op,
                        "Thread {} had multiple successful initializations",
                        result.thread_id
                    );
                    saw_successful_op = true;
                    if let OpResult::InitComplete(val) = op_result {
                        value_after_success = Some(*val);
                    }
                }
                OpResult::GetSome(val) => {
                    if let Some(expected) = value_after_success {
                        assert_eq!(
                            *val, expected,
                            "Thread {} saw inconsistent value after successful op",
                            result.thread_id
                        );
                    }
                }
                _ => {} // SetErr, GetNone are normal
            }
        }
    }
});
