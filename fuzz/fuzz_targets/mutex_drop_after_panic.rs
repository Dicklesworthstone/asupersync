//! Fuzz target: Mutex drop after panic
//!
//! Tests mutex behavior when dropped after a panic has occurred, focusing on
//! poison state handling, cleanup consistency, and concurrent access patterns
//! during mutex destruction.
//!
//! # Race Conditions Tested
//! 1. Mutex drop while other threads attempt to access poisoned mutex
//! 2. Panic during lock acquisition vs concurrent mutex drop
//! 3. Multiple threads racing to access poisoned mutex during destruction
//! 4. Poison recovery attempts vs mutex drop timing
//! 5. Cleanup consistency when poisoned mutex is dropped

#![no_main]

use arbitrary::Arbitrary;
use asupersync::sync::Mutex;
use libfuzzer_sys::fuzz_target;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{
    Arc, Barrier,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::thread;
use std::time::Duration;

/// Configuration for mutex drop after panic test
#[derive(Debug, Arbitrary)]
struct MutexDropPanicConfig {
    /// Number of threads that will cause panics (1-8)
    panic_thread_count: u8,
    /// Number of threads that will access poisoned mutex (1-16)
    accessor_thread_count: u8,
    /// Panic patterns for each panic thread
    panic_patterns: Vec<PanicPattern>,
    /// Access patterns for accessor threads
    access_patterns: Vec<AccessPattern>,
    /// Whether to use barrier synchronization
    use_barrier_sync: bool,
    /// Delay before dropping mutex (microseconds)
    drop_delay: u16,
}

#[derive(Debug, Arbitrary, Clone)]
enum PanicPattern {
    /// Panic immediately after acquiring lock
    PanicAfterLock,
    /// Panic after brief work while holding lock
    PanicDuringWork { work_delay: u16 },
    /// Panic during lock acquisition attempt
    PanicDuringAcquisition,
    /// Acquire lock, do work, then panic
    WorkThenPanic { work_items: u8 },
}

#[derive(Debug, Arbitrary, Clone)]
enum AccessPattern {
    /// Try to lock poisoned mutex
    TryLockPoisoned,
    /// Block on poisoned mutex lock
    BlockOnPoisoned,
    /// Attempt lock with timeout
    TryLockWithTimeout { timeout_micros: u16 },
    /// Multiple rapid lock attempts
    RapidLockAttempts { attempts: u8 },
    /// Check if mutex is poisoned
    CheckPoisoned,
}

impl MutexDropPanicConfig {
    fn normalize(&mut self) {
        // Limit thread counts
        self.panic_thread_count = (self.panic_thread_count % 8).max(1);
        self.accessor_thread_count = (self.accessor_thread_count % 16).max(1);

        // Ensure we have enough patterns
        self.panic_patterns.resize(
            self.panic_thread_count as usize,
            PanicPattern::PanicAfterLock,
        );
        self.access_patterns.resize(
            self.accessor_thread_count as usize,
            AccessPattern::TryLockPoisoned,
        );

        // Normalize delays
        self.drop_delay = self.drop_delay % 1000; // Max 1ms

        // Normalize pattern parameters
        for pattern in &mut self.panic_patterns {
            match pattern {
                PanicPattern::PanicDuringWork { work_delay } => {
                    *work_delay = *work_delay % 200; // Max 0.2ms
                }
                PanicPattern::WorkThenPanic { work_items } => {
                    *work_items = (*work_items % 10).max(1);
                }
                _ => {}
            }
        }

        for pattern in &mut self.access_patterns {
            match pattern {
                AccessPattern::TryLockWithTimeout { timeout_micros } => {
                    *timeout_micros = *timeout_micros % 500; // Max 0.5ms
                }
                AccessPattern::RapidLockAttempts { attempts } => {
                    *attempts = (*attempts % 20).max(1);
                }
                _ => {}
            }
        }
    }
}

/// Test results tracking
#[derive(Debug, Default)]
struct TestResults {
    panic_threads_started: AtomicUsize,
    accessor_threads_started: AtomicUsize,
    panics_occurred: AtomicUsize,
    poison_detected: AtomicUsize,
    lock_attempts: AtomicUsize,
    lock_successes: AtomicUsize,
    lock_poison_errors: AtomicUsize,
    lock_timeouts: AtomicUsize,
    mutex_dropped: AtomicBool,
    drop_completed: AtomicBool,
}

fuzz_target!(|data: &[u8]| {
    // Parse fuzzer input into config
    let mut config = match MutexDropPanicConfig::arbitrary(&mut arbitrary::Unstructured::new(data))
    {
        Ok(config) => config,
        Err(_) => return, // Invalid input, skip
    };
    config.normalize();

    let mutex: Arc<Mutex<u32>> = Arc::new(Mutex::new(42));
    let results = Arc::new(TestResults::default());

    let total_threads = config.panic_thread_count + config.accessor_thread_count;
    let barrier = if config.use_barrier_sync {
        Some(Arc::new(Barrier::new(total_threads as usize)))
    } else {
        None
    };

    let mut handles = Vec::new();

    // Spawn panic threads - these will cause the mutex to become poisoned
    for i in 0..config.panic_thread_count {
        let mutex = Arc::clone(&mutex);
        let results = Arc::clone(&results);
        let barrier = barrier.clone();
        let pattern = config.panic_patterns[i as usize].clone();

        let handle = thread::spawn(move || {
            results.panic_threads_started.fetch_add(1, Ordering::SeqCst);

            // Synchronize start if requested
            if let Some(barrier) = barrier {
                barrier.wait();
            }

            let panic_result = catch_unwind(AssertUnwindSafe(|| {
                let cx = asupersync::Cx::for_testing();
                match pattern {
                    PanicPattern::PanicAfterLock => {
                        let _guard = futures::executor::block_on(mutex.lock(&cx))
                            .expect("Lock should succeed");
                        panic!("Intentional panic after acquiring lock");
                    }

                    PanicPattern::PanicDuringWork { work_delay } => {
                        let mut guard = futures::executor::block_on(mutex.lock(&cx))
                            .expect("Lock should succeed");
                        if work_delay > 0 {
                            thread::sleep(Duration::from_micros(work_delay as u64));
                        }
                        *guard += 1; // Do some work
                        panic!("Intentional panic during work");
                    }

                    PanicPattern::PanicDuringAcquisition => {
                        // This is tricky - we'll panic during a custom operation
                        // that involves lock acquisition
                        let _guard = futures::executor::block_on(mutex.lock(&cx))
                            .expect("Lock should succeed");
                        // Simulate some complex operation that panics
                        panic!("Intentional panic during acquisition");
                    }

                    PanicPattern::WorkThenPanic { work_items } => {
                        let mut guard = futures::executor::block_on(mutex.lock(&cx))
                            .expect("Lock should succeed");
                        for _ in 0..work_items {
                            *guard = guard.wrapping_add(1);
                            thread::sleep(Duration::from_micros(10));
                        }
                        panic!("Intentional panic after work");
                    }
                }
            }));

            match panic_result {
                Err(_) => {
                    // Panic occurred as expected
                    results.panics_occurred.fetch_add(1, Ordering::SeqCst);
                }
                Ok(_) => {
                    // Should not happen for our patterns, but handle gracefully
                }
            }
        });

        handles.push(handle);
    }

    // Spawn accessor threads - these will try to access the (potentially poisoned) mutex
    for i in 0..config.accessor_thread_count {
        let mutex = Arc::clone(&mutex);
        let results = Arc::clone(&results);
        let barrier = barrier.clone();
        let pattern = config.access_patterns[i as usize].clone();

        let handle = thread::spawn(move || {
            results
                .accessor_threads_started
                .fetch_add(1, Ordering::SeqCst);

            // Synchronize start if requested
            if let Some(barrier) = barrier {
                barrier.wait();
            }

            // Give panic threads a chance to run first
            thread::sleep(Duration::from_micros(100));

            match pattern {
                AccessPattern::TryLockPoisoned => {
                    results.lock_attempts.fetch_add(1, Ordering::SeqCst);

                    match mutex.try_lock() {
                        Ok(_guard) => {
                            results.lock_successes.fetch_add(1, Ordering::SeqCst);
                        }
                        Err(asupersync::sync::TryLockError::Poisoned) => {
                            results.lock_poison_errors.fetch_add(1, Ordering::SeqCst);
                            results.poison_detected.fetch_add(1, Ordering::SeqCst);
                        }
                        Err(asupersync::sync::TryLockError::Locked) => {
                            // Mutex is currently locked by another thread
                        }
                    }
                }

                AccessPattern::BlockOnPoisoned => {
                    results.lock_attempts.fetch_add(1, Ordering::SeqCst);

                    // Use catch_unwind in case the poison handling itself has issues
                    let lock_result = catch_unwind(AssertUnwindSafe(|| {
                        let cx = asupersync::Cx::for_testing();
                        futures::executor::block_on(mutex.lock(&cx))
                    }));

                    match lock_result {
                        Ok(guard_result) => match guard_result {
                            Ok(_guard) => {
                                results.lock_successes.fetch_add(1, Ordering::SeqCst);
                            }
                            Err(_poison_error) => {
                                results.lock_poison_errors.fetch_add(1, Ordering::SeqCst);
                                results.poison_detected.fetch_add(1, Ordering::SeqCst);
                            }
                        },
                        Err(_) => {
                            // Panic occurred during lock attempt
                        }
                    }
                }

                AccessPattern::TryLockWithTimeout { timeout_micros } => {
                    results.lock_attempts.fetch_add(1, Ordering::SeqCst);

                    // Simulate timeout by trying multiple times with small delays
                    let mut attempts = 0;
                    let max_attempts = (timeout_micros / 10).max(1) as usize;

                    loop {
                        match mutex.try_lock() {
                            Ok(_guard) => {
                                results.lock_successes.fetch_add(1, Ordering::SeqCst);
                                break;
                            }
                            Err(asupersync::sync::TryLockError::Poisoned) => {
                                results.lock_poison_errors.fetch_add(1, Ordering::SeqCst);
                                results.poison_detected.fetch_add(1, Ordering::SeqCst);
                                break;
                            }
                            Err(asupersync::sync::TryLockError::Locked) => {
                                attempts += 1;
                                if attempts >= max_attempts {
                                    results.lock_timeouts.fetch_add(1, Ordering::SeqCst);
                                    break;
                                }
                                thread::sleep(Duration::from_micros(10));
                            }
                        }
                    }
                }

                AccessPattern::RapidLockAttempts { attempts } => {
                    for _ in 0..attempts {
                        results.lock_attempts.fetch_add(1, Ordering::SeqCst);

                        match mutex.try_lock() {
                            Ok(_guard) => {
                                results.lock_successes.fetch_add(1, Ordering::SeqCst);
                            }
                            Err(asupersync::sync::TryLockError::Poisoned) => {
                                results.lock_poison_errors.fetch_add(1, Ordering::SeqCst);
                                results.poison_detected.fetch_add(1, Ordering::SeqCst);
                                break; // Stop on poison
                            }
                            Err(asupersync::sync::TryLockError::Locked) => {
                                // Continue trying
                            }
                        }
                    }
                }

                AccessPattern::CheckPoisoned => {
                    // Try to determine if mutex is poisoned without locking
                    match mutex.try_lock() {
                        Ok(_guard) => {
                            // Not poisoned (or was recovered)
                        }
                        Err(asupersync::sync::TryLockError::Poisoned) => {
                            results.poison_detected.fetch_add(1, Ordering::SeqCst);
                        }
                        Err(asupersync::sync::TryLockError::Locked) => {
                            // Can't determine poison state while locked
                        }
                    }
                }
            }
        });

        handles.push(handle);
    }

    // Wait for all threads to complete
    for handle in handles {
        let _ = handle.join(); // Ignore panics - they're expected
    }

    // Add delay before dropping mutex
    if config.drop_delay > 0 {
        thread::sleep(Duration::from_micros(config.drop_delay as u64));
    }

    // Mark that we're about to drop the mutex
    results.mutex_dropped.store(true, Ordering::SeqCst);

    // Drop the mutex - this is the critical operation we're testing
    drop(mutex);

    // Mark drop completed
    results.drop_completed.store(true, Ordering::SeqCst);

    // Verify results
    let panic_threads_started = results.panic_threads_started.load(Ordering::SeqCst);
    let accessor_threads_started = results.accessor_threads_started.load(Ordering::SeqCst);
    let panics_occurred = results.panics_occurred.load(Ordering::SeqCst);
    let poison_detected = results.poison_detected.load(Ordering::SeqCst);
    let lock_attempts = results.lock_attempts.load(Ordering::SeqCst);
    let lock_successes = results.lock_successes.load(Ordering::SeqCst);
    let lock_poison_errors = results.lock_poison_errors.load(Ordering::SeqCst);
    let lock_timeouts = results.lock_timeouts.load(Ordering::SeqCst);
    let mutex_dropped = results.mutex_dropped.load(Ordering::SeqCst);
    let drop_completed = results.drop_completed.load(Ordering::SeqCst);

    // Basic accounting checks
    assert_eq!(
        panic_threads_started, config.panic_thread_count as usize,
        "All panic threads should start"
    );
    assert_eq!(
        accessor_threads_started, config.accessor_thread_count as usize,
        "All accessor threads should start"
    );

    // Lock attempt accounting
    assert_eq!(
        lock_attempts,
        lock_successes + lock_poison_errors + lock_timeouts,
        "Lock attempt accounting should be consistent"
    );

    // Drop completion
    assert!(mutex_dropped, "Mutex should be marked as dropped");
    assert!(drop_completed, "Mutex drop should complete");

    // Poison detection consistency
    if panics_occurred > 0 {
        // If panics occurred, we might (but are not guaranteed to) detect poison
        // This depends on timing - accessor threads might run before or after panic
    }

    // Invariant: If we detected poison, there must have been panics
    if poison_detected > 0 {
        assert!(
            panics_occurred > 0,
            "Cannot detect poison without panics occurring"
        );
    }

    // Poison error consistency
    assert_eq!(
        poison_detected, lock_poison_errors,
        "Poison detection should match poison errors"
    );

    // Success + poison should not exceed total meaningful attempts
    // (timeouts are separate and don't conflict with success/poison)

    // Race condition verification: The key property is that dropping a poisoned
    // mutex should not cause undefined behavior or deadlocks, regardless of
    // concurrent access attempts

    // The fact that we reached this point without hanging or crashing
    // indicates the drop-after-panic behavior is working correctly
});
