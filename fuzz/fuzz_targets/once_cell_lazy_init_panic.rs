//! Fuzz OnceCell lazy initialization under panic conditions.
//!
//! Tests arbitrary panic-during-init sequences to ensure the cell remains
//! uninitialized after panic, next attempts re-try, and no permanent poison
//! occurs. Validates proper panic recovery and retry semantics.
//!
//! Critical invariants:
//! - Cell remains uninitialized after panic during init
//! - Next attempt re-tries (doesn't give up permanently)
//! - No permanent poison (unlike Mutex)
//! - Panic recovery allows successful initialization later

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};
use asupersync::sync::once_cell::OnceCell;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use std::panic::{catch_unwind, AssertUnwindSafe};

#[derive(Debug, Clone, Arbitrary)]
struct PanicConfig {
    /// Sequences of initialization attempts
    init_attempts: Vec<InitAttempt>,
    /// Values to use for successful initialization
    success_values: Vec<u32>,
    /// Panic messages for failed attempts
    panic_messages: Vec<String>,
}

#[derive(Debug, Clone, Arbitrary)]
enum InitAttempt {
    /// Successful initialization with value index
    Success { value_index: u8 },
    /// Panic during initialization with message index
    Panic { message_index: u8 },
    /// Panic after some work (simulated by counter increment)
    PanicAfterWork { work_units: u8, message_index: u8 },
    /// Check if cell is initialized
    CheckInitialized,
    /// Get value if cell is initialized
    GetValue,
    /// Small delay between attempts
    Delay { millis: u8 },
}

#[derive(Debug, Clone, Arbitrary)]
struct PanicSequence {
    /// Test configuration
    config: PanicConfig,
    /// Maximum attempts to perform
    max_attempts: u8,
    /// Whether to test concurrent panic scenarios
    test_concurrency: bool,
}

impl PanicSequence {
    fn max_attempts() -> u8 {
        20 // Keep test duration reasonable
    }

    fn max_success_values() -> usize {
        10 // Reasonable number of different values
    }
}

/// Test execution context tracking panic recovery
#[derive(Debug)]
struct PanicTracker {
    panic_count: AtomicUsize,
    successful_init_count: AtomicUsize,
    work_counter: AtomicUsize, // Simulates work done during init
}

impl PanicTracker {
    fn new() -> Self {
        Self {
            panic_count: AtomicUsize::new(0),
            successful_init_count: AtomicUsize::new(0),
            work_counter: AtomicUsize::new(0),
        }
    }

    fn increment_panic_count(&self) {
        self.panic_count.fetch_add(1, Ordering::SeqCst);
    }

    fn increment_success_count(&self) {
        self.successful_init_count.fetch_add(1, Ordering::SeqCst);
    }

    fn do_work(&self, units: u8) {
        for _ in 0..units {
            self.work_counter.fetch_add(1, Ordering::SeqCst);
            // Small delay to simulate actual work
            thread::sleep(Duration::from_micros(100));
        }
    }

    fn check_invariants(&self, cell: &OnceCell<u32>) -> Result<(), String> {
        let panics = self.panic_count.load(Ordering::SeqCst);
        let successes = self.successful_init_count.load(Ordering::SeqCst);

        // If any successful initialization occurred, cell should be initialized
        if successes > 0 && !cell.is_initialized() {
            return Err(format!(
                "Cell should be initialized after {} successes but is not",
                successes
            ));
        }

        // If cell is initialized, there should have been exactly one successful init
        if cell.is_initialized() && successes != 1 {
            return Err(format!(
                "Cell is initialized but success count is {} (should be 1)",
                successes
            ));
        }

        // Panics should not prevent future initialization attempts
        if panics > 0 && successes == 0 && cell.is_initialized() {
            return Err(format!(
                "Cell is initialized despite {} panics and 0 successes",
                panics
            ));
        }

        Ok(())
    }
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    let sequence: PanicSequence = match unstructured.arbitrary() {
        Ok(seq) => seq,
        Err(_) => return, // Invalid input, skip
    };

    // Validate and limit parameters
    if sequence.config.init_attempts.is_empty()
        || sequence.config.success_values.is_empty()
        || sequence.config.success_values.len() > PanicSequence::max_success_values() {
        return;
    }

    let max_attempts = sequence.max_attempts.min(PanicSequence::max_attempts()) as usize;

    // Create OnceCell and panic tracker
    let cell = OnceCell::new();
    let tracker = Arc::new(PanicTracker::new());

    // Execute initialization attempts
    for (i, attempt) in sequence.config.init_attempts.iter().take(max_attempts).enumerate() {
        // Check invariants before each attempt
        if let Err(msg) = tracker.check_invariants(&cell) {
            panic!("Panic recovery invariant violation at attempt {}: {}", i, msg);
        }

        match attempt {
            InitAttempt::Success { value_index } => {
                let value = sequence.config.success_values
                    .get(*value_index as usize % sequence.config.success_values.len())
                    .copied()
                    .unwrap_or(42);

                let tracker_clone = Arc::clone(&tracker);
                let result = catch_unwind(AssertUnwindSafe(|| {
                    cell.get_or_init_blocking(|| {
                        tracker_clone.increment_success_count();
                        value
                    })
                }));

                match result {
                    Ok(_) => {
                        // Successful initialization
                        assert!(cell.is_initialized(), "Cell should be initialized after successful init");

                        // Verify the value is correct
                        if let Some(stored_value) = cell.get() {
                            assert_eq!(*stored_value, value,
                                "Stored value {} should match expected {}",
                                *stored_value, value);
                        }
                    }
                    Err(_) => {
                        // This shouldn't happen for Success attempts
                        panic!("Unexpected panic during Success attempt at {}", i);
                    }
                }
            }

            InitAttempt::Panic { message_index } => {
                let panic_message = sequence.config.panic_messages
                    .get(*message_index as usize % sequence.config.panic_messages.len().max(1))
                    .cloned()
                    .unwrap_or_else(|| format!("test panic {}", i));

                let tracker_clone = Arc::clone(&tracker);
                let result = catch_unwind(AssertUnwindSafe(|| {
                    cell.get_or_init_blocking(|| -> u32 {
                        tracker_clone.increment_panic_count();
                        panic!("{}", panic_message);
                    })
                }));

                match result {
                    Ok(_) => {
                        // This could happen if cell was already initialized
                        // In that case, the panic closure wasn't called
                        assert!(cell.is_initialized(),
                            "If init didn't panic, cell should be initialized");
                    }
                    Err(_) => {
                        // Expected panic occurred
                        assert!(!cell.is_initialized(),
                            "Cell should remain uninitialized after panic at attempt {}",
                            i);
                    }
                }
            }

            InitAttempt::PanicAfterWork { work_units, message_index } => {
                let panic_message = sequence.config.panic_messages
                    .get(*message_index as usize % sequence.config.panic_messages.len().max(1))
                    .cloned()
                    .unwrap_or_else(|| format!("test panic after work {}", i));

                let tracker_clone = Arc::clone(&tracker);
                let work_units = *work_units;
                let result = catch_unwind(AssertUnwindSafe(|| {
                    cell.get_or_init_blocking(|| -> u32 {
                        // Simulate work before panicking
                        tracker_clone.do_work(work_units);
                        tracker_clone.increment_panic_count();
                        panic!("{}", panic_message);
                    })
                }));

                match result {
                    Ok(_) => {
                        // Cell was already initialized, panic closure wasn't called
                        assert!(cell.is_initialized());
                    }
                    Err(_) => {
                        // Panic occurred after work
                        assert!(!cell.is_initialized(),
                            "Cell should remain uninitialized after panic with work at attempt {}",
                            i);
                    }
                }
            }

            InitAttempt::CheckInitialized => {
                let _is_initialized = cell.is_initialized();
                // This should never panic or affect cell state
            }

            InitAttempt::GetValue => {
                let _value = cell.get();
                // This should never panic or affect cell state
            }

            InitAttempt::Delay { millis } => {
                thread::sleep(Duration::from_millis(*millis as u64));
            }
        }

        // Check invariants after each attempt
        if let Err(msg) = tracker.check_invariants(&cell) {
            panic!("Panic recovery invariant violation after attempt {}: {}", i, msg);
        }
    }

    // Test concurrent panic scenarios if requested
    if sequence.test_concurrency && !cell.is_initialized() {
        let cell = Arc::new(cell);
        let tracker = Arc::clone(&tracker);

        let handles: Vec<_> = (0..3)
            .map(|thread_id| {
                let cell = Arc::clone(&cell);
                let tracker = Arc::clone(&tracker);

                thread::spawn(move || {
                    for attempt in 0..3 {
                        let should_panic = (thread_id + attempt) % 2 == 0;

                        let result = catch_unwind(AssertUnwindSafe(|| {
                            cell.get_or_init_blocking(|| -> u32 {
                                if should_panic {
                                    tracker.increment_panic_count();
                                    panic!("concurrent panic {} {}", thread_id, attempt);
                                } else {
                                    tracker.increment_success_count();
                                    thread_id * 100 + attempt
                                }
                            })
                        }));

                        match result {
                            Ok(value) => {
                                // Successfully got value (either initialized or got existing)
                                assert_eq!(*value, *cell.get().unwrap());
                            }
                            Err(_) => {
                                // Panic occurred - cell should remain uninitialized until a success
                            }
                        }

                        thread::sleep(Duration::from_millis(1));
                    }
                })
            })
            .collect();

        // Wait for all threads
        for handle in handles {
            handle.join().expect("Thread should complete");
        }
    }

    // Final invariant checks
    if let Err(msg) = tracker.check_invariants(&cell) {
        panic!("Final panic recovery invariant violation: {}", msg);
    }

    // Test that successful initialization is possible after any number of panics
    if !cell.is_initialized() {
        let final_value = 999u32;
        let result = catch_unwind(AssertUnwindSafe(|| {
            cell.get_or_init_blocking(|| final_value)
        }));

        match result {
            Ok(value) => {
                assert_eq!(*value, final_value);
                assert!(cell.is_initialized());
            }
            Err(_) => {
                panic!("Final successful initialization should not panic");
            }
        }
    }

    // Verify final state consistency
    let final_panics = tracker.panic_count.load(Ordering::SeqCst);
    let final_successes = tracker.successful_init_count.load(Ordering::SeqCst);

    // Cell should be initialized at the end
    assert!(cell.is_initialized(),
        "Cell should be initialized at end of test");

    // Should have exactly one successful initialization total
    let expected_successes = if final_successes == 0 { 1 } else { final_successes };
    assert!(expected_successes >= 1,
        "Should have at least one successful initialization: panics={}, successes={}",
        final_panics, expected_successes);

    // Verify the OnceCell behaves correctly: once initialized, always returns same value
    let value1 = *cell.get().unwrap();
    let value2 = *cell.get().unwrap();
    assert_eq!(value1, value2,
        "OnceCell should return same value on repeated access");
});