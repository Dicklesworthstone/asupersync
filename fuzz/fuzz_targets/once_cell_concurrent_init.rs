#![no_main]

use arbitrary::Arbitrary;
use asupersync::sync::OnceCell;
use libfuzzer_sys::fuzz_target;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// Structure-aware fuzzer for OnceCell concurrent initialization correctness
///
/// Tests the race condition properties of OnceCell under concurrent access:
/// 1. Exactly one closure invocation (not zero, not multiple)
/// 2. All threads see the same initialized value
/// 3. No data races or deadlocks during initialization
/// 4. Proper synchronization between competing initializers
#[derive(Arbitrary, Debug)]
struct OnceCellConcurrentFuzz {
    /// Test configuration parameters
    config: TestConfig,
    /// The value that the init closure should produce
    init_value: u32,
    /// Whether to add artificial delays in the init closure
    add_init_delay: bool,
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
const MAX_INIT_DELAY_MS: u64 = 50;
const MAX_STARTUP_DELAY_MS: u64 = 10;
const THREAD_TIMEOUT: Duration = Duration::from_secs(10);

fuzz_target!(|input: OnceCellConcurrentFuzz| {
    // Apply resource limits
    let thread_count = (input.config.thread_count as usize).min(MAX_THREADS).max(1);
    let init_value = input
        .init_value
        .wrapping_mul(input.config.value_multiplier as u32);
    let startup_delay =
        Duration::from_millis((input.config.startup_delay_ms as u64).min(MAX_STARTUP_DELAY_MS));

    // Execute the concurrent initialization test
    test_concurrent_init(
        thread_count,
        init_value,
        input.add_init_delay,
        startup_delay,
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
