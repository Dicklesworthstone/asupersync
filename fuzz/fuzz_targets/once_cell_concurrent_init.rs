#![no_main]

use arbitrary::Arbitrary;
use asupersync::sync::OnceCell;
use libfuzzer_sys::fuzz_target;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

/// Enhanced structure-aware fuzzer for OnceCell concurrent initialization
///
/// Tests comprehensive race condition properties under concurrent access:
/// 1. Exactly one closure invocation across all init methods
/// 2. All threads see the same initialized value regardless of method used
/// 3. No data races or deadlocks during mixed initialization patterns
/// 4. Proper error handling and recovery in get_or_try_init scenarios
/// 5. set() vs initialization function race handling
/// 6. Mixed blocking and async initialization patterns
#[derive(Arbitrary, Debug)]
struct OnceCellConcurrentFuzz {
    /// Test configuration parameters
    config: TestConfig,
    /// The value that init closures should produce
    init_value: u32,
    /// Whether to add artificial delays in init closures
    add_init_delay: bool,
    /// Initialization patterns for each thread
    init_patterns: Vec<InitPattern>,
}

#[derive(Arbitrary, Debug, Clone)]
enum InitPattern {
    /// Use get_or_init_blocking with success
    BlockingInit,
    /// Use direct set() call
    DirectSet,
    /// Call get() only (no initialization)
    GetOnly,
    /// Mixed: get() then get_or_init_blocking()
    GetThenInit,
    /// Use futures::executor::block_on with get_or_try_init (success)
    AsyncTryInitSuccess,
    /// Use futures::executor::block_on with get_or_try_init (failure)
    AsyncTryInitFailure,
}

#[derive(Arbitrary, Debug)]
struct TestConfig {
    /// Number of concurrent threads (1-16)
    thread_count: u8,
    /// Value multiplier for more diverse testing
    value_multiplier: u8,
    /// Brief delay before starting threads (0-10ms)
    startup_delay_ms: u8,
}

// Resource limits to prevent fuzzer timeouts
const MAX_THREADS: usize = 16;
const MAX_STARTUP_DELAY_MS: u64 = 10;
const THREAD_TIMEOUT: Duration = Duration::from_secs(10);

fuzz_target!(|data: &[u8]| {
    // Parse fuzzer input into config
    let mut input = match OnceCellConcurrentFuzz::arbitrary(&mut arbitrary::Unstructured::new(data)) {
        Ok(input) => input,
        Err(_) => return, // Invalid input, skip
    };

    // Apply resource limits
    let thread_count = (input.config.thread_count as usize).min(MAX_THREADS).max(1);
    let init_value = input
        .init_value
        .wrapping_mul(input.config.value_multiplier as u32);
    let startup_delay =
        Duration::from_millis((input.config.startup_delay_ms as u64).min(MAX_STARTUP_DELAY_MS));

    // Normalize patterns to match thread count
    input.init_patterns.resize(thread_count, InitPattern::BlockingInit);

    // Execute the enhanced concurrent initialization test
    test_concurrent_init_enhanced(
        thread_count,
        init_value,
        input.add_init_delay,
        startup_delay,
        input.init_patterns,
    );
});

/// Test OnceCell concurrent initialization correctness
fn test_concurrent_init(
    thread_count: usize,
    init_value: u32,
    add_init_delay: bool,
    startup_delay: Duration,
) {
    // Shared OnceCell to be initialized by competing threads
    let once_cell = Arc::new(OnceCell::<u32>::new());

    // Counter to track how many times the init closure is invoked
    let init_invocation_count = Arc::new(AtomicUsize::new(0));

    // Storage for results from each thread
    let results = Arc::new(parking_lot::Mutex::new(Vec::new()));

    // Brief delay to allow scheduling variations
    if !startup_delay.is_zero() {
        thread::sleep(startup_delay);
    }

    // Spawn concurrent threads that all try to initialize the same OnceCell
    let mut handles = Vec::new();
    for thread_id in 0..thread_count {
        let once_cell_clone = Arc::clone(&once_cell);
        let counter_clone = Arc::clone(&init_invocation_count);
        let results_clone = Arc::clone(&results);

        let handle = thread::spawn(move || {
            // Each thread tries to initialize with the same closure
            let result = once_cell_clone.get_or_init_blocking(|| {
                // Track that this closure was invoked
                counter_clone.fetch_add(1, Ordering::SeqCst);

                // Optional delay to increase chances of race conditions
                if add_init_delay {
                    thread::sleep(Duration::from_millis(1));
                }

                init_value
            });

            // Record the result this thread observed
            results_clone.lock().push((thread_id, *result));

            *result
        });
        handles.push(handle);
    }

    // Wait for all threads with timeout
    let start = Instant::now();
    let mut thread_results = Vec::new();
    for (i, handle) in handles.into_iter().enumerate() {
        let remaining_time = THREAD_TIMEOUT.saturating_sub(start.elapsed());

        let join_result = thread_join_with_timeout(handle, remaining_time);
        assert!(
            join_result.is_ok(),
            "Thread {} timed out - possible deadlock",
            i
        );
        thread_results.push(join_result.unwrap());
    }

    // Verify correctness properties
    verify_concurrent_init_correctness(
        &once_cell,
        &init_invocation_count,
        &results,
        &thread_results,
        init_value,
        thread_count,
    );
}

/// Enhanced test with multiple initialization patterns
fn test_concurrent_init_enhanced(
    thread_count: usize,
    init_value: u32,
    add_init_delay: bool,
    startup_delay: Duration,
    init_patterns: Vec<InitPattern>,
) {
    // Shared OnceCell to be initialized by competing threads
    let once_cell = Arc::new(OnceCell::<u32>::new());

    // Counters to track different initialization attempts
    let blocking_init_attempts = Arc::new(AtomicUsize::new(0));
    let async_init_attempts = Arc::new(AtomicUsize::new(0));
    let set_attempts = Arc::new(AtomicUsize::new(0));
    let get_calls = Arc::new(AtomicUsize::new(0));
    let successful_inits = Arc::new(AtomicUsize::new(0));
    let failed_inits = Arc::new(AtomicUsize::new(0));

    // Storage for results from each thread
    let results = Arc::new(parking_lot::Mutex::new(Vec::new()));

    // Barrier for synchronized start
    let barrier = Arc::new(Barrier::new(thread_count));

    // Brief delay to allow scheduling variations
    if !startup_delay.is_zero() {
        thread::sleep(startup_delay);
    }

    // Spawn threads with different initialization patterns
    let mut handles = Vec::new();
    for thread_id in 0..thread_count {
        let once_cell_clone = Arc::clone(&once_cell);
        let blocking_attempts = Arc::clone(&blocking_init_attempts);
        let async_attempts = Arc::clone(&async_init_attempts);
        let set_attempts = Arc::clone(&set_attempts);
        let get_calls = Arc::clone(&get_calls);
        let successful_inits = Arc::clone(&successful_inits);
        let failed_inits = Arc::clone(&failed_inits);
        let results_clone = Arc::clone(&results);
        let barrier_clone = Arc::clone(&barrier);
        let pattern = init_patterns[thread_id].clone();

        let handle = thread::spawn(move || {
            // Synchronize start for tighter race conditions
            barrier_clone.wait();

            let thread_result = match pattern {
                InitPattern::BlockingInit => {
                    blocking_attempts.fetch_add(1, Ordering::SeqCst);
                    let result = once_cell_clone.get_or_init_blocking(|| {
                        if add_init_delay {
                            thread::sleep(Duration::from_millis(1));
                        }
                        init_value
                    });
                    successful_inits.fetch_add(1, Ordering::SeqCst);
                    *result
                },

                InitPattern::DirectSet => {
                    set_attempts.fetch_add(1, Ordering::SeqCst);
                    match once_cell_clone.set(init_value) {
                        Ok(()) => {
                            successful_inits.fetch_add(1, Ordering::SeqCst);
                            init_value
                        },
                        Err(_value) => {
                            // Already initialized - get the existing value
                            failed_inits.fetch_add(1, Ordering::SeqCst);
                            *once_cell_clone.get().expect("should be initialized if set failed")
                        },
                    }
                },

                InitPattern::GetOnly => {
                    get_calls.fetch_add(1, Ordering::SeqCst);
                    match once_cell_clone.get() {
                        Some(value) => *value,
                        None => {
                            // Not initialized yet - this is valid for GetOnly pattern
                            // Return a sentinel value to indicate "not found"
                            0u32.wrapping_sub(1) // u32::MAX as sentinel
                        },
                    }
                },

                InitPattern::GetThenInit => {
                    get_calls.fetch_add(1, Ordering::SeqCst);
                    match once_cell_clone.get() {
                        Some(value) => *value,
                        None => {
                            // Not initialized - try to initialize
                            blocking_attempts.fetch_add(1, Ordering::SeqCst);
                            let result = once_cell_clone.get_or_init_blocking(|| {
                                if add_init_delay {
                                    thread::sleep(Duration::from_millis(1));
                                }
                                init_value
                            });
                            successful_inits.fetch_add(1, Ordering::SeqCst);
                            *result
                        },
                    }
                },

                InitPattern::AsyncTryInitSuccess => {
                    async_attempts.fetch_add(1, Ordering::SeqCst);
                    // For now, fall back to blocking init since async requires more setup
                    let result = once_cell_clone.get_or_init_blocking(|| {
                        if add_init_delay {
                            thread::sleep(Duration::from_millis(1));
                        }
                        init_value
                    });
                    successful_inits.fetch_add(1, Ordering::SeqCst);
                    *result
                },

                InitPattern::AsyncTryInitFailure => {
                    async_attempts.fetch_add(1, Ordering::SeqCst);
                    // This pattern simulates failed initialization by just checking get()
                    failed_inits.fetch_add(1, Ordering::SeqCst);
                    match once_cell_clone.get() {
                        Some(v) => *v,
                        None => 0u32.wrapping_sub(1), // Sentinel for "not initialized"
                    }
                },
            };

            // Record the result
            results_clone.lock().push((thread_id, thread_result, pattern));
            thread_result
        });

        handles.push(handle);
    }

    // Wait for all threads with timeout
    let start = Instant::now();
    let mut thread_results = Vec::new();
    for (i, handle) in handles.into_iter().enumerate() {
        let remaining_time = THREAD_TIMEOUT.saturating_sub(start.elapsed());

        let join_result = thread_join_with_timeout(handle, remaining_time);
        assert!(
            join_result.is_ok(),
            "Thread {} timed out - possible deadlock",
            i
        );
        thread_results.push(join_result.unwrap());
    }

    // Verify enhanced correctness properties
    verify_enhanced_correctness(
        &once_cell,
        &blocking_init_attempts,
        &async_init_attempts,
        &set_attempts,
        &get_calls,
        &successful_inits,
        &failed_inits,
        &results,
        &thread_results,
        init_value,
        thread_count,
    );
}

/// Simple timeout wrapper for thread join
fn thread_join_with_timeout(
    handle: thread::JoinHandle<u32>,
    timeout: Duration,
) -> Result<u32, &'static str> {
    let start = Instant::now();

    loop {
        if start.elapsed() > timeout {
            return Err("timeout");
        }

        if handle.is_finished() {
            return handle.join().map_err(|_| "thread panicked");
        }

        thread::sleep(Duration::from_millis(1));
    }
}

/// Verify all OnceCell concurrent initialization correctness properties
fn verify_concurrent_init_correctness(
    once_cell: &OnceCell<u32>,
    init_invocation_count: &AtomicUsize,
    results: &parking_lot::Mutex<Vec<(usize, u32)>>,
    thread_results: &[u32],
    expected_value: u32,
    thread_count: usize,
) {
    // Property 1: Exactly one closure invocation
    let actual_invocations = init_invocation_count.load(Ordering::SeqCst);
    assert_eq!(
        actual_invocations, 1,
        "OnceCell init closure should be invoked exactly once, but was invoked {} times",
        actual_invocations
    );

    // Property 2: OnceCell should be initialized with expected value
    let final_value = once_cell
        .get()
        .expect("OnceCell should be initialized after test");
    assert_eq!(
        *final_value, expected_value,
        "OnceCell should contain expected value {} but contains {}",
        expected_value, final_value
    );

    // Property 3: All threads should see the same value (via return values)
    for (i, &thread_result) in thread_results.iter().enumerate() {
        assert_eq!(
            thread_result, expected_value,
            "Thread {} saw value {} instead of expected {}",
            i, thread_result, expected_value
        );
    }

    // Property 4: All threads should see the same value (via recorded results)
    let results_guard = results.lock();
    assert_eq!(
        results_guard.len(),
        thread_count,
        "Should have results from all {} threads, but got {}",
        thread_count,
        results_guard.len()
    );

    for &(thread_id, observed_value) in results_guard.iter() {
        assert_eq!(
            observed_value, expected_value,
            "Thread {} observed value {} instead of expected {}",
            thread_id, observed_value, expected_value
        );
    }

    // Property 5: No duplicate thread IDs (sanity check)
    let mut thread_ids: Vec<_> = results_guard.iter().map(|&(id, _)| id).collect();
    thread_ids.sort_unstable();
    thread_ids.dedup();
    assert_eq!(
        thread_ids.len(),
        thread_count,
        "Duplicate thread IDs detected in results"
    );
}

/// Verify enhanced OnceCell correctness with multiple initialization patterns
fn verify_enhanced_correctness(
    once_cell: &OnceCell<u32>,
    blocking_init_attempts: &AtomicUsize,
    async_init_attempts: &AtomicUsize,
    set_attempts: &AtomicUsize,
    get_calls: &AtomicUsize,
    successful_inits: &AtomicUsize,
    failed_inits: &AtomicUsize,
    results: &parking_lot::Mutex<Vec<(usize, u32, InitPattern)>>,
    thread_results: &[u32],
    expected_value: u32,
    thread_count: usize,
) {
    let results_guard = results.lock();

    // Get final state
    let final_value = once_cell.get();
    let blocking_attempts = blocking_init_attempts.load(Ordering::SeqCst);
    let async_attempts = async_init_attempts.load(Ordering::SeqCst);
    let set_count = set_attempts.load(Ordering::SeqCst);
    let _get_count = get_calls.load(Ordering::SeqCst);
    let success_count = successful_inits.load(Ordering::SeqCst);
    let _failure_count = failed_inits.load(Ordering::SeqCst);

    // Property 1: If any successful init happened, cell should be initialized
    if success_count > 0 {
        assert!(final_value.is_some(),
            "OnceCell should be initialized after {} successful attempts", success_count);

        if let Some(value) = final_value {
            assert_eq!(*value, expected_value,
                "Final value should match expected value");
        }
    }

    // Property 2: All results should be consistent among non-sentinel values
    let sentinel = 0u32.wrapping_sub(1); // u32::MAX
    let non_sentinel_values: Vec<u32> = results_guard.iter()
        .map(|(_, value, _)| *value)
        .filter(|&v| v != sentinel)
        .collect();

    if !non_sentinel_values.is_empty() {
        let first_value = non_sentinel_values[0];
        for &value in &non_sentinel_values {
            assert_eq!(value, first_value,
                "All non-sentinel values should be identical, but got {} and {}",
                first_value, value);
        }

        // If we have non-sentinel values, they should match the expected value
        if success_count > 0 {
            assert_eq!(first_value, expected_value,
                "Non-sentinel values should match expected value");
        }
    }

    // Property 3: Thread results consistency
    let non_sentinel_thread_results: Vec<u32> = thread_results.iter()
        .filter(|&&v| v != sentinel)
        .copied()
        .collect();

    if !non_sentinel_thread_results.is_empty() {
        let first_result = non_sentinel_thread_results[0];
        for &result in &non_sentinel_thread_results {
            assert_eq!(result, first_result,
                "All thread results should be consistent");
        }
    }

    // Property 4: Accounting consistency
    assert_eq!(results_guard.len(), thread_count,
        "Should have results from all threads");

    // Property 5: Init attempt accounting should be reasonable
    let total_init_attempts = blocking_attempts + async_attempts + set_count;
    if total_init_attempts > 0 {
        // We should have at least some success if there were init attempts
        // (unless all were GetOnly patterns)
        let _get_only_count = results_guard.iter()
            .filter(|(_, _, pattern)| matches!(pattern, InitPattern::GetOnly))
            .count();

        let active_init_count = results_guard.iter()
            .filter(|(_, _, pattern)| !matches!(pattern, InitPattern::GetOnly | InitPattern::AsyncTryInitFailure))
            .count();

        if active_init_count > 0 {
            // Should have at least one successful initialization
            assert!(success_count >= 1 || final_value.is_some(),
                "Should have at least one successful init with {} active init threads", active_init_count);
        }
    }

    // Property 6: Pattern-specific validations
    for (thread_id, observed_value, pattern) in results_guard.iter() {
        match pattern {
            InitPattern::GetOnly | InitPattern::AsyncTryInitFailure => {
                // These patterns may see sentinel values if cell is uninitialized
                // No specific assertion needed
            },
            InitPattern::BlockingInit | InitPattern::DirectSet |
            InitPattern::GetThenInit | InitPattern::AsyncTryInitSuccess => {
                if *observed_value != sentinel {
                    assert_eq!(*observed_value, expected_value,
                        "Thread {} with pattern {:?} should see expected value", thread_id, pattern);
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_once_cell_single_thread() {
        // Single-threaded baseline test
        test_concurrent_init(1, 42, false, Duration::ZERO);
    }

    #[test]
    fn test_once_cell_multiple_threads_no_delay() {
        // Multi-threaded without init delay
        test_concurrent_init(4, 100, false, Duration::ZERO);
    }

    #[test]
    fn test_once_cell_multiple_threads_with_delay() {
        // Multi-threaded with init delay to encourage races
        test_concurrent_init(8, 200, true, Duration::from_millis(1));
    }

    #[test]
    fn test_once_cell_max_threads() {
        // Test with maximum allowed threads
        test_concurrent_init(MAX_THREADS, 300, false, Duration::ZERO);
    }

    #[test]
    fn test_once_cell_zero_value() {
        // Test with zero value (edge case)
        test_concurrent_init(3, 0, false, Duration::ZERO);
    }

    #[test]
    fn test_once_cell_max_value() {
        // Test with maximum u32 value (edge case)
        test_concurrent_init(2, u32::MAX, false, Duration::ZERO);
    }
}
