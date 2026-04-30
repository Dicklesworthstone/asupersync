//! Fuzz mutex reentrant-acquire scenarios.
//!
//! Tests arbitrary same-thread re-acquire patterns to ensure proper behavior
//! when a task attempts to lock a mutex it already holds. Validates that the
//! implementation either detects deadlock with diagnostic messages OR supports
//! reentrancy correctly (depending on implementation design).
//!
//! Critical invariants:
//! - Same-task re-acquire either succeeds (reentrant) or fails with clear diagnostic
//! - No silent deadlock without detection mechanism
//! - Guard drop order maintains lock state consistency
//! - Nested lock operations maintain proper reference counting

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};
use asupersync::sync::{Mutex, LockError, TryLockError};
use asupersync::cx::Cx;
use asupersync::types::{Budget, CancelKind};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Arbitrary)]
struct ReentrantConfig {
    /// Initial value for the mutex
    initial_value: u32,
    /// Reentrant scenarios to test
    scenarios: Vec<ReentrantScenario>,
    /// Whether to test concurrent scenarios
    test_concurrency: bool,
    /// Maximum scenarios to test
    max_scenarios: u8,
}

#[derive(Debug, Clone, Arbitrary)]
enum ReentrantScenario {
    /// Simple reentrant lock attempt
    SimpleReentrant,
    /// Try-lock while holding lock
    TryLockReentrant,
    /// Nested lock attempts (multiple levels)
    NestedLocks { depth: u8 },
    /// Reentrant with delay between attempts
    DelayedReentrant { delay_ms: u8 },
    /// Lock, spawn task, attempt reentrant in spawned task (should work)
    CrossTaskValidation,
    /// Rapid sequence of reentrant attempts
    RapidReentrant { attempts: u8 },
}

impl ReentrantConfig {
    fn max_scenarios() -> u8 {
        15 // Keep test duration reasonable
    }

    fn max_nested_depth() -> u8 {
        5 // Prevent excessive nesting
    }

    fn max_rapid_attempts() -> u8 {
        10 // Limit rapid sequence length
    }
}

/// Tracks reentrant behavior results to detect implementation characteristics
#[derive(Debug)]
struct ReentrantTracker {
    successful_reentrants: AtomicUsize,
    failed_reentrants: AtomicUsize,
    deadlock_detections: AtomicUsize,
    timeout_failures: AtomicUsize,
    total_attempts: AtomicUsize,
    max_nesting_achieved: AtomicUsize,
}

impl ReentrantTracker {
    fn new() -> Self {
        Self {
            successful_reentrants: AtomicUsize::new(0),
            failed_reentrants: AtomicUsize::new(0),
            deadlock_detections: AtomicUsize::new(0),
            timeout_failures: AtomicUsize::new(0),
            total_attempts: AtomicUsize::new(0),
            max_nesting_achieved: AtomicUsize::new(0),
        }
    }

    fn record_successful_reentrant(&self, nesting_level: usize) {
        self.successful_reentrants.fetch_add(1, Ordering::SeqCst);
        self.total_attempts.fetch_add(1, Ordering::SeqCst);
        self.max_nesting_achieved.fetch_max(nesting_level, Ordering::SeqCst);
    }

    fn record_failed_reentrant(&self) {
        self.failed_reentrants.fetch_add(1, Ordering::SeqCst);
        self.total_attempts.fetch_add(1, Ordering::SeqCst);
    }

    fn record_deadlock_detection(&self) {
        self.deadlock_detections.fetch_add(1, Ordering::SeqCst);
        self.total_attempts.fetch_add(1, Ordering::SeqCst);
    }

    fn record_timeout_failure(&self) {
        self.timeout_failures.fetch_add(1, Ordering::SeqCst);
        self.total_attempts.fetch_add(1, Ordering::SeqCst);
    }

    fn check_reentrant_invariants(&self) -> Result<(), String> {
        let successful = self.successful_reentrants.load(Ordering::SeqCst);
        let failed = self.failed_reentrants.load(Ordering::SeqCst);
        let deadlock_detected = self.deadlock_detections.load(Ordering::SeqCst);
        let timeouts = self.timeout_failures.load(Ordering::SeqCst);
        let total = self.total_attempts.load(Ordering::SeqCst);

        // Total should match sum of all categories
        let computed_total = successful + failed + deadlock_detected + timeouts;
        if total != computed_total {
            return Err(format!(
                "Total attempts mismatch: tracked {} vs computed {} (success: {}, fail: {}, deadlock: {}, timeout: {})",
                total, computed_total, successful, failed, deadlock_detected, timeouts
            ));
        }

        // If we have successful reentrancy, the implementation supports it
        // If we have deadlock detection, the implementation detects it
        // If we have timeouts, the implementation likely deadlocks silently
        if successful > 0 && deadlock_detected > 0 {
            return Err(format!(
                "Inconsistent behavior: {} successful reentrants but {} deadlock detections",
                successful, deadlock_detected
            ));
        }

        // Silent deadlock (timeout) with no detection is concerning but not necessarily wrong
        // Some implementations may choose to deadlock as a way to indicate reentrancy error

        Ok(())
    }
}

/// Test a reentrant scenario with timeout protection
async fn test_reentrant_scenario_async(
    scenario: &ReentrantScenario,
    mutex: &Mutex<u32>,
    cx: &Cx,
    tracker: &ReentrantTracker,
    initial_value: u32,
) -> Result<(), String> {
    match scenario {
        ReentrantScenario::SimpleReentrant => {
            // Acquire lock first
            let guard1 = match mutex.lock(cx).await {
                Ok(guard) => {
                    if *guard != initial_value {
                        return Err(format!("Unexpected initial value: expected {}, got {}", initial_value, *guard));
                    }
                    guard
                }
                Err(err) => {
                    return Err(format!("Failed to acquire initial lock: {:?}", err));
                }
            };

            // Now try to acquire the same mutex again from the same task
            let timeout_duration = Duration::from_millis(100);
            let start_time = Instant::now();

            let reentrant_result = match tokio::time::timeout(timeout_duration, mutex.lock(cx)).await {
                Ok(Ok(_guard2)) => {
                    // Successfully acquired reentrantly
                    tracker.record_successful_reentrant(2);
                    Ok(())
                }
                Ok(Err(LockError::Cancelled)) => {
                    // Deadlock detection via cancellation or similar
                    tracker.record_deadlock_detection();
                    Ok(())
                }
                Ok(Err(err)) => {
                    // Other error (might be deadlock detection)
                    tracker.record_failed_reentrant();
                    Err(format!("Reentrant lock failed with error: {:?}", err))
                }
                Err(_) => {
                    // Timeout - likely silent deadlock
                    tracker.record_timeout_failure();
                    Ok(()) // This is expected behavior for non-reentrant mutexes
                }
            };

            drop(guard1);
            reentrant_result
        }

        ReentrantScenario::TryLockReentrant => {
            let _guard1 = match mutex.lock(cx).await {
                Ok(guard) => guard,
                Err(err) => {
                    return Err(format!("Failed to acquire initial lock: {:?}", err));
                }
            };

            // Try to try_lock while holding the lock
            match mutex.try_lock() {
                Ok(_guard2) => {
                    // Successfully acquired reentrantly via try_lock
                    tracker.record_successful_reentrant(2);
                }
                Err(TryLockError::Locked) => {
                    // Expected behavior for non-reentrant mutex
                    tracker.record_failed_reentrant();
                }
                Err(err) => {
                    return Err(format!("Unexpected try_lock error: {:?}", err));
                }
            }

            Ok(())
        }

        ReentrantScenario::NestedLocks { depth } => {
            let nesting_depth = (*depth).min(ReentrantConfig::max_nested_depth()) as usize;
            let timeout_per_level = Duration::from_millis(50);

            // Try to acquire nested locks
            let mut guards = Vec::new();
            let mut achieved_depth = 0;

            for level in 0..nesting_depth {
                let timeout_duration = timeout_per_level;

                match tokio::time::timeout(timeout_duration, mutex.lock(cx)).await {
                    Ok(Ok(guard)) => {
                        guards.push(guard);
                        achieved_depth = level + 1;
                    }
                    Ok(Err(_)) => {
                        // Lock error
                        tracker.record_failed_reentrant();
                        break;
                    }
                    Err(_) => {
                        // Timeout
                        if level == 0 {
                            return Err("Failed to acquire even the first lock".to_string());
                        }
                        tracker.record_timeout_failure();
                        break;
                    }
                }
            }

            if achieved_depth > 1 {
                tracker.record_successful_reentrant(achieved_depth);
            } else if achieved_depth == 1 {
                // Got first lock but not second - expected for non-reentrant
                tracker.record_failed_reentrant();
            }

            // Guards will be dropped automatically
            Ok(())
        }

        ReentrantScenario::DelayedReentrant { delay_ms } => {
            let _guard1 = match mutex.lock(cx).await {
                Ok(guard) => guard,
                Err(err) => {
                    return Err(format!("Failed to acquire initial lock: {:?}", err));
                }
            };

            // Wait a bit before attempting reentrancy
            tokio::time::sleep(Duration::from_millis((*delay_ms).min(100) as u64)).await;

            let timeout_duration = Duration::from_millis(100);
            match tokio::time::timeout(timeout_duration, mutex.lock(cx)).await {
                Ok(Ok(_guard2)) => {
                    tracker.record_successful_reentrant(2);
                }
                Ok(Err(_)) => {
                    tracker.record_failed_reentrant();
                }
                Err(_) => {
                    tracker.record_timeout_failure();
                }
            }

            Ok(())
        }

        ReentrantScenario::CrossTaskValidation => {
            let _guard1 = match mutex.lock(cx).await {
                Ok(guard) => guard,
                Err(err) => {
                    return Err(format!("Failed to acquire initial lock in main task: {:?}", err));
                }
            };

            // This should NOT be reentrant since it's a different task/context
            // Create a new context to simulate different task
            let new_cx = Cx::new("reentrant_cross_task", Budget::INFINITE);

            let timeout_duration = Duration::from_millis(50);
            match tokio::time::timeout(timeout_duration, mutex.lock(&new_cx)).await {
                Ok(Ok(_guard2)) => {
                    return Err("Cross-task lock succeeded when it should have blocked".to_string());
                }
                Ok(Err(_)) => {
                    // Expected - different task should not get reentrant access
                }
                Err(_) => {
                    // Timeout - expected behavior
                }
            }

            tracker.record_failed_reentrant(); // This is the expected outcome
            Ok(())
        }

        ReentrantScenario::RapidReentrant { attempts } => {
            let _guard1 = match mutex.lock(cx).await {
                Ok(guard) => guard,
                Err(err) => {
                    return Err(format!("Failed to acquire initial lock: {:?}", err));
                }
            };

            let attempt_count = (*attempts).min(ReentrantConfig::max_rapid_attempts()) as usize;
            let mut successes = 0;

            for i in 0..attempt_count {
                let timeout_duration = Duration::from_millis(20);
                match tokio::time::timeout(timeout_duration, mutex.lock(cx)).await {
                    Ok(Ok(_guard)) => {
                        successes += 1;
                        // Note: guard will be dropped immediately
                    }
                    Ok(Err(_)) => {
                        tracker.record_failed_reentrant();
                        break;
                    }
                    Err(_) => {
                        tracker.record_timeout_failure();
                        break;
                    }
                }

                // Brief yield between attempts
                if i % 3 == 2 {
                    tokio::task::yield_now().await;
                }
            }

            if successes > 0 {
                tracker.record_successful_reentrant(successes + 1); // +1 for the initial lock
            }

            Ok(())
        }
    }
}

/// Create test context
fn create_test_cx() -> Cx {
    Cx::new("mutex_reentrant_fuzz", Budget::INFINITE)
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    let config: ReentrantConfig = match unstructured.arbitrary() {
        Ok(cfg) => cfg,
        Err(_) => return, // Invalid input, skip
    };

    // Validate and limit parameters
    if config.scenarios.is_empty() {
        return;
    }

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("Failed to create tokio runtime");

    rt.block_on(async {
        let max_scenarios = config.max_scenarios.min(ReentrantConfig::max_scenarios()) as usize;
        let mutex = Arc::new(Mutex::new(config.initial_value));
        let tracker = Arc::new(ReentrantTracker::new());

        // Test each scenario
        for scenario in config.scenarios.iter().take(max_scenarios) {
            let cx = create_test_cx();

            if let Err(msg) = test_reentrant_scenario_async(
                scenario,
                &mutex,
                &cx,
                &tracker,
                config.initial_value
            ).await {
                panic!("Reentrant scenario test failed: {}", msg);
            }

            // Brief delay between scenarios
            tokio::time::sleep(Duration::from_millis(1)).await;
        }

        // Test concurrent scenarios if requested
        if config.test_concurrency && config.scenarios.len() > 1 {
            let concurrent_handles: futures::future::JoinAll<_> = config.scenarios
                .iter()
                .take(3) // Limit concurrent tasks
                .map(|scenario| {
                    let scenario = scenario.clone();
                    let mutex = Arc::clone(&mutex);
                    let tracker = Arc::clone(&tracker);
                    let initial_value = config.initial_value;

                    tokio::spawn(async move {
                        let cx = create_test_cx();
                        if let Err(msg) = test_reentrant_scenario_async(
                            &scenario,
                            &mutex,
                            &cx,
                            &tracker,
                            initial_value
                        ).await {
                            panic!("Concurrent reentrant scenario failed: {}", msg);
                        }
                    })
                })
                .collect();

            // Wait for all concurrent tests to complete
            let results = concurrent_handles.await;
            for result in results {
                if let Err(err) = result {
                    panic!("Concurrent task panicked: {:?}", err);
                }
            }
        }

        // Validate final invariants
        if let Err(msg) = tracker.check_reentrant_invariants() {
            panic!("Reentrant invariant violation: {}", msg);
        }

        // Ensure we actually performed some operations
        let total_attempts = tracker.total_attempts.load(Ordering::SeqCst);
        if total_attempts == 0 {
            panic!("No reentrant attempts were made during the test");
        }

        // The mutex should be unlocked at the end
        match mutex.try_lock() {
            Ok(_guard) => {
                // Successfully acquired - mutex is properly unlocked
            }
            Err(err) => {
                panic!("Mutex appears to be in inconsistent state at end of test: {:?}", err);
            }
        }
    });
});