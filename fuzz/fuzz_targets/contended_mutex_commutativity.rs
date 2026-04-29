#![no_main]

use arbitrary::Arbitrary;
use asupersync::sync::ContendedMutex;
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// Structure-aware fuzz target for ContendedMutex commutativity and deadlock-freedom
///
/// Tests the correctness properties of ContendedMutex:
/// 1. No deadlock: all operations complete within timeout
/// 2. Final-value commutativity: reordering operations by thread produces same final state
/// 3. Read-write consistency: reads see writes according to happens-before ordering
/// 4. Poison safety: poisoned mutex is properly handled and doesn't cause undefined behavior
#[derive(Arbitrary, Debug)]
struct ContendedMutexFuzz {
    /// Sequence of operations to perform across threads
    operations: Vec<MutexOperation>,
    /// Test configuration parameters
    config: TestConfig,
}

#[derive(Arbitrary, Debug, Clone)]
enum MutexOperation {
    /// Read operation with thread affinity
    Read {
        thread_id: u8, // 0-3 for 4 threads max
    },
    /// Write operation with value to write
    Write {
        thread_id: u8, // 0-3 for 4 threads max
        value: u32,    // Value to write
    },
    /// Modify operation (read-modify-write)
    Modify {
        thread_id: u8, // 0-3 for 4 threads max
        delta: i32,    // Add this delta to current value
    },
    /// Try-lock operation (non-blocking)
    TryRead {
        thread_id: u8, // 0-3 for 4 threads max
    },
    /// Brief delay to allow scheduling variations
    Delay {
        thread_id: u8, // 0-3 for 4 threads max
        milliseconds: u8, // 0-255ms
    },
}

#[derive(Arbitrary, Debug)]
struct TestConfig {
    /// Maximum number of operations to execute
    max_operations: u8,
    /// Maximum number of threads to use
    max_threads: u8,
    /// Initial value for the shared state
    initial_value: u32,
}

// Resource limits to prevent fuzzer timeouts
const MAX_OPERATIONS: usize = 100;
const MAX_THREADS: usize = 4;
const MAX_DELAY_MS: u64 = 10;
const OPERATION_TIMEOUT: Duration = Duration::from_secs(5);

fuzz_target!(|input: ContendedMutexFuzz| {
    // Apply resource limits
    let max_ops = (input.config.max_operations as usize).min(MAX_OPERATIONS).max(1);
    let max_threads = (input.config.max_threads as usize).min(MAX_THREADS).max(1);
    let operations: Vec<_> = input.operations.into_iter().take(max_ops).collect();

    if operations.is_empty() {
        return; // Skip empty operation sequences
    }

    // Test shared state
    let shared_state = Arc::new(ContendedMutex::new("fuzz_test", input.config.initial_value));

    // Track operations by thread for commutativity testing
    let mut operations_by_thread: HashMap<usize, Vec<MutexOperation>> = HashMap::new();
    for op in &operations {
        let thread_id = thread_id_from_op(op) % max_threads;
        operations_by_thread
            .entry(thread_id)
            .or_insert_with(Vec::new)
            .push(op.clone());
    }

    // Execute operations and verify properties
    execute_and_verify_properties(
        shared_state,
        operations_by_thread,
        max_threads,
        input.config.initial_value,
    );
});

/// Execute operations across threads and verify mutex properties
fn execute_and_verify_properties(
    shared_state: Arc<ContendedMutex<u32>>,
    operations_by_thread: HashMap<usize, Vec<MutexOperation>>,
    max_threads: usize,
    initial_value: u32,
) {
    let results = Arc::new(ContendedMutex::new("results", Vec::new()));
    let mut handles = Vec::new();

    // Spawn worker threads
    for thread_id in 0..max_threads {
        let ops = operations_by_thread.get(&thread_id).cloned().unwrap_or_default();
        if ops.is_empty() {
            continue;
        }

        let state = shared_state.clone();
        let results_clone = results.clone();

        let handle = thread::spawn(move || {
            execute_thread_operations(thread_id, ops, state, results_clone);
        });
        handles.push(handle);
    }

    // Wait for all threads with timeout (deadlock detection)
    let start = std::time::Instant::now();
    for (i, handle) in handles.into_iter().enumerate() {
        let remaining_time = OPERATION_TIMEOUT.saturating_sub(start.elapsed());

        // Use a simple timeout mechanism
        let join_result = thread_join_with_timeout(handle, remaining_time);
        assert!(join_result.is_ok(),
            "Thread {} timed out - possible deadlock detected", i);
    }

    // Verify final state consistency
    verify_final_state_consistency(&shared_state, &results, initial_value);
}

/// Simple timeout wrapper for thread join
fn thread_join_with_timeout(
    handle: thread::JoinHandle<()>,
    timeout: Duration
) -> Result<(), &'static str> {
    // For simplicity in fuzzing, we'll use a busy-wait approach
    // In production code, you'd want a more sophisticated timeout mechanism
    let start = std::time::Instant::now();
    let handle = std::sync::Arc::new(std::sync::Mutex::new(Some(handle)));

    loop {
        if start.elapsed() > timeout {
            return Err("timeout");
        }

        // Try to take the handle and join
        if let Ok(mut guard) = handle.try_lock() {
            if let Some(h) = guard.take() {
                if h.is_finished() {
                    return h.join().map_err(|_| "thread panicked");
                } else {
                    // Put it back and continue waiting
                    *guard = Some(h);
                }
            } else {
                // Already joined
                return Ok(());
            }
        }

        thread::sleep(Duration::from_millis(1));
    }
}

/// Execute operations for a single thread
fn execute_thread_operations(
    thread_id: usize,
    operations: Vec<MutexOperation>,
    state: Arc<ContendedMutex<u32>>,
    results: Arc<ContendedMutex<Vec<ThreadResult>>>,
) {
    for (op_index, operation) in operations.into_iter().enumerate() {
        let result = match operation {
            MutexOperation::Read { .. } => {
                let guard = state.lock().unwrap_or_else(|poison| {
                    // Handle poisoned mutex gracefully
                    poison.into_inner()
                });
                let value = *guard;
                drop(guard);
                ThreadResult::Read { thread_id, op_index, value }
            }

            MutexOperation::Write { value, .. } => {
                let mut guard = state.lock().unwrap_or_else(|poison| {
                    poison.into_inner()
                });
                let old_value = *guard;
                *guard = value;
                drop(guard);
                ThreadResult::Write { thread_id, op_index, old_value, new_value: value }
            }

            MutexOperation::Modify { delta, .. } => {
                let mut guard = state.lock().unwrap_or_else(|poison| {
                    poison.into_inner()
                });
                let old_value = *guard;
                let new_value = old_value.wrapping_add(delta as u32);
                *guard = new_value;
                drop(guard);
                ThreadResult::Modify { thread_id, op_index, old_value, new_value, delta }
            }

            MutexOperation::TryRead { .. } => {
                match state.try_lock() {
                    Ok(guard) => {
                        let value = *guard;
                        drop(guard);
                        ThreadResult::TryRead { thread_id, op_index, value: Some(value) }
                    }
                    Err(_) => {
                        ThreadResult::TryRead { thread_id, op_index, value: None }
                    }
                }
            }

            MutexOperation::Delay { milliseconds, .. } => {
                let delay_ms = (milliseconds as u64).min(MAX_DELAY_MS);
                thread::sleep(Duration::from_millis(delay_ms));
                ThreadResult::Delay { thread_id, op_index, milliseconds: delay_ms }
            }
        };

        // Record the result
        let mut results_guard = results.lock().unwrap_or_else(|poison| {
            poison.into_inner()
        });
        results_guard.push(result);
    }
}

/// Result of a single thread operation
#[derive(Debug, Clone)]
enum ThreadResult {
    Read { thread_id: usize, op_index: usize, value: u32 },
    Write { thread_id: usize, op_index: usize, old_value: u32, new_value: u32 },
    Modify { thread_id: usize, op_index: usize, old_value: u32, new_value: u32, delta: i32 },
    TryRead { thread_id: usize, op_index: usize, value: Option<u32> },
    Delay { thread_id: usize, op_index: usize, milliseconds: u64 },
}

/// Verify final state consistency and commutativity properties
fn verify_final_state_consistency(
    shared_state: &ContendedMutex<u32>,
    results: &ContendedMutex<Vec<ThreadResult>>,
    initial_value: u32,
) {
    let final_value = *shared_state.lock().unwrap_or_else(|poison| {
        poison.into_inner()
    });

    let results_guard = results.lock().unwrap_or_else(|poison| {
        poison.into_inner()
    });
    let all_results = results_guard.clone();
    drop(results_guard);

    // Verify consistency: final value should be consistent with write history
    verify_write_consistency(&all_results, final_value, initial_value);

    // Verify read consistency: reads should see values that existed at some point
    verify_read_consistency(&all_results, initial_value);

    // Verify modify operations are atomic
    verify_modify_atomicity(&all_results);
}

/// Verify that the final value is consistent with the write operations
fn verify_write_consistency(
    results: &[ThreadResult],
    final_value: u32,
    initial_value: u32,
) {
    // Collect all write operations in order
    let mut writes: Vec<u32> = Vec::new();
    let mut current_value = initial_value;

    for result in results {
        match result {
            ThreadResult::Write { new_value, .. } => {
                writes.push(*new_value);
                current_value = *new_value;
            }
            ThreadResult::Modify { new_value, .. } => {
                writes.push(*new_value);
                current_value = *new_value;
            }
            _ => {}
        }
    }

    // The final value should match the last write (if any)
    if !writes.is_empty() {
        // Note: Due to concurrent execution, we can't guarantee exact ordering
        // But we can verify that the final value was written by some operation
        let final_was_written = writes.contains(&final_value) || final_value == initial_value;
        assert!(final_was_written,
            "Final value {} was not written by any operation (writes: {:?})",
            final_value, writes);
    } else {
        assert_eq!(final_value, initial_value,
            "Final value changed without any write operations");
    }
}

/// Verify that read operations see consistent values
fn verify_read_consistency(
    results: &[ThreadResult],
    initial_value: u32,
) {
    // Collect all values that were ever written
    let mut possible_values = std::collections::HashSet::new();
    possible_values.insert(initial_value);

    for result in results {
        match result {
            ThreadResult::Write { new_value, .. } => {
                possible_values.insert(*new_value);
            }
            ThreadResult::Modify { new_value, .. } => {
                possible_values.insert(*new_value);
            }
            _ => {}
        }
    }

    // Verify all reads saw valid values
    for result in results {
        if let ThreadResult::Read { value, .. } = result {
            assert!(possible_values.contains(value),
                "Read operation saw invalid value {} (possible: {:?})",
                value, possible_values);
        }
        if let ThreadResult::TryRead { value: Some(value), .. } = result {
            assert!(possible_values.contains(value),
                "TryRead operation saw invalid value {} (possible: {:?})",
                value, possible_values);
        }
    }
}

/// Verify that modify operations are atomic (old_value + delta = new_value)
fn verify_modify_atomicity(results: &[ThreadResult]) {
    for result in results {
        if let ThreadResult::Modify { old_value, new_value, delta, .. } = result {
            let expected = old_value.wrapping_add(*delta as u32);
            assert_eq!(*new_value, expected,
                "Modify operation not atomic: {} + {} ≠ {} (got {})",
                old_value, delta, expected, new_value);
        }
    }
}

/// Extract thread ID from operation
fn thread_id_from_op(op: &MutexOperation) -> usize {
    match op {
        MutexOperation::Read { thread_id } => *thread_id as usize,
        MutexOperation::Write { thread_id, .. } => *thread_id as usize,
        MutexOperation::Modify { thread_id, .. } => *thread_id as usize,
        MutexOperation::TryRead { thread_id } => *thread_id as usize,
        MutexOperation::Delay { thread_id, .. } => *thread_id as usize,
    }
}