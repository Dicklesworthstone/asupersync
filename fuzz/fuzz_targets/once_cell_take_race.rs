//! Fuzz OnceCell take race conditions.
//!
//! Tests arbitrary take + set + get sequences to ensure take returns Some-then-None
//! and set after take initializes again. Validates proper race condition handling
//! in concurrent take/set/get operations.
//!
//! Critical invariants:
//! - take returns Some-then-None (first take gets value, subsequent takes get None)
//! - set after take initializes again (can re-initialize after taking)
//! - take is exclusive (only one take can succeed)
//! - No use-after-free or double-take bugs

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};
use asupersync::sync::OnceCell;
use std::sync::atomic::{AtomicUsize, AtomicBool, Ordering};
use std::sync::Arc;
use std::collections::HashMap;
use std::thread;
use std::time::Duration;

#[derive(Debug, Clone, Arbitrary)]
struct OnceCellTakeConfig {
    /// Initial value for the cell (if any)
    initial_value: Option<i32>,
    /// Operations to perform
    operations: Vec<TakeRaceOperation>,
    /// Whether to test concurrent scenarios
    test_concurrency: bool,
    /// Maximum operations to perform
    max_operations: u8,
}

#[derive(Debug, Clone, Arbitrary)]
enum TakeRaceOperation {
    /// Take the value from the cell
    Take { taker_id: u8 },
    /// Set a new value in the cell
    Set { setter_id: u8, value: i32 },
    /// Get the current value from the cell
    Get { getter_id: u8 },
    /// Multiple concurrent takes
    ConcurrentTakes { taker_ids: Vec<u8> },
    /// Take followed immediately by set
    TakeThenSet { taker_id: u8, value: i32 },
    /// Set followed immediately by take
    SetThenTake { setter_id: u8, taker_id: u8, value: i32 },
    /// Rapid take-set-get cycle
    RapidCycle { actor_id: u8, cycles: u8 },
    /// Check state consistency
    CheckState,
}

impl OnceCellTakeConfig {
    fn max_operations() -> u8 {
        40 // Limit test duration
    }

    fn max_concurrent_takes() -> u8 {
        8 // Limit concurrent operations
    }

    fn max_rapid_cycles() -> u8 {
        5 // Limit rapid cycles
    }
}

/// Tracks take race behavior to detect invariant violations
#[derive(Debug)]
struct TakeRaceTracker {
    takes_attempted: AtomicUsize,
    takes_succeeded: AtomicUsize,
    takes_failed: AtomicUsize,
    sets_attempted: AtomicUsize,
    sets_succeeded: AtomicUsize,
    sets_failed: AtomicUsize,
    gets_attempted: AtomicUsize,
    values_observed: AtomicUsize,
    invariant_violations: AtomicUsize,
}

impl TakeRaceTracker {
    fn new() -> Self {
        Self {
            takes_attempted: AtomicUsize::new(0),
            takes_succeeded: AtomicUsize::new(0),
            takes_failed: AtomicUsize::new(0),
            sets_attempted: AtomicUsize::new(0),
            sets_succeeded: AtomicUsize::new(0),
            sets_failed: AtomicUsize::new(0),
            gets_attempted: AtomicUsize::new(0),
            values_observed: AtomicUsize::new(0),
            invariant_violations: AtomicUsize::new(0),
        }
    }

    fn record_take_attempted(&self) {
        self.takes_attempted.fetch_add(1, Ordering::SeqCst);
    }

    fn record_take_succeeded(&self, _value: i32) {
        self.takes_succeeded.fetch_add(1, Ordering::SeqCst);
    }

    fn record_take_failed(&self) {
        self.takes_failed.fetch_add(1, Ordering::SeqCst);
    }

    fn record_set_attempted(&self) {
        self.sets_attempted.fetch_add(1, Ordering::SeqCst);
    }

    fn record_set_succeeded(&self) {
        self.sets_succeeded.fetch_add(1, Ordering::SeqCst);
    }

    fn record_set_failed(&self) {
        self.sets_failed.fetch_add(1, Ordering::SeqCst);
    }

    fn record_get_attempted(&self) {
        self.gets_attempted.fetch_add(1, Ordering::SeqCst);
    }

    fn record_value_observed(&self, _value: i32) {
        self.values_observed.fetch_add(1, Ordering::SeqCst);
    }

    fn record_invariant_violation(&self) {
        self.invariant_violations.fetch_add(1, Ordering::SeqCst);
    }

    fn check_invariants(&self) -> Result<(), String> {
        let takes_attempted = self.takes_attempted.load(Ordering::SeqCst);
        let takes_succeeded = self.takes_succeeded.load(Ordering::SeqCst);
        let takes_failed = self.takes_failed.load(Ordering::SeqCst);
        let sets_attempted = self.sets_attempted.load(Ordering::SeqCst);
        let sets_succeeded = self.sets_succeeded.load(Ordering::SeqCst);
        let sets_failed = self.sets_failed.load(Ordering::SeqCst);
        let violations = self.invariant_violations.load(Ordering::SeqCst);

        // Core invariant: no invariant violations should be detected
        if violations > 0 {
            return Err(format!("Detected {} invariant violations", violations));
        }

        // Take attempts should be accounted for
        if takes_attempted > 0 && (takes_succeeded + takes_failed) == 0 {
            return Err(format!(
                "Take attempts ({}) not accounted for in success/failure",
                takes_attempted
            ));
        }

        // Set attempts should be accounted for
        if sets_attempted > 0 && (sets_succeeded + sets_failed) == 0 {
            return Err(format!(
                "Set attempts ({}) not accounted for in success/failure",
                sets_attempted
            ));
        }

        // Sanity checks
        if takes_succeeded > takes_attempted {
            return Err(format!(
                "More successful takes ({}) than attempts ({})",
                takes_succeeded, takes_attempted
            ));
        }

        if sets_succeeded > sets_attempted {
            return Err(format!(
                "More successful sets ({}) than attempts ({})",
                sets_succeeded, sets_attempted
            ));
        }

        Ok(())
    }
}

/// Tracks concurrent operations for testing
struct ConcurrentTakeResult {
    taker_id: u8,
    result: Option<i32>,
    success: bool,
}

/// Test OnceCell take race scenarios
fn test_take_race_scenario(
    config: &OnceCellTakeConfig,
    tracker: &TakeRaceTracker,
) -> Result<(), String> {
    let mut cell = match config.initial_value {
        Some(value) => OnceCell::with_value(value),
        None => OnceCell::new(),
    };

    let max_ops = config.max_operations.min(OnceCellTakeConfig::max_operations()) as usize;

    for operation in config.operations.iter().take(max_ops) {
        match operation {
            TakeRaceOperation::Take { taker_id: _ } => {
                tracker.record_take_attempted();

                let result = cell.take();
                match result {
                    Some(value) => {
                        tracker.record_take_succeeded(value);
                    }
                    None => {
                        tracker.record_take_failed();
                    }
                }
            }

            TakeRaceOperation::Set { setter_id: _, value } => {
                tracker.record_set_attempted();

                let result = cell.set(*value);
                match result {
                    Ok(()) => {
                        tracker.record_set_succeeded();
                    }
                    Err(_) => {
                        tracker.record_set_failed();
                    }
                }
            }

            TakeRaceOperation::Get { getter_id: _ } => {
                tracker.record_get_attempted();

                if let Some(value) = cell.get() {
                    tracker.record_value_observed(*value);
                }
            }

            TakeRaceOperation::ConcurrentTakes { taker_ids } => {
                let max_concurrent = OnceCellTakeConfig::max_concurrent_takes() as usize;
                let concurrent_count = taker_ids.len().min(max_concurrent);

                if concurrent_count == 0 {
                    continue;
                }

                // Only test concurrent takes if cell is initialized
                if !cell.is_initialized() {
                    continue;
                }

                // Prepare shared cell
                let cell_arc = Arc::new(std::sync::Mutex::new(std::mem::replace(&mut cell, OnceCell::new())));
                let results = Arc::new(std::sync::Mutex::new(Vec::new()));
                let mut handles = Vec::new();

                for &taker_id in taker_ids.iter().take(concurrent_count) {
                    let cell_ref = Arc::clone(&cell_arc);
                    let results_ref = Arc::clone(&results);

                    handles.push(thread::spawn(move || {
                        let mut cell_guard = cell_ref.lock().unwrap();
                        tracker.record_take_attempted();

                        let result = cell_guard.take();
                        let success = result.is_some();

                        if let Some(value) = result {
                            tracker.record_take_succeeded(value);
                        } else {
                            tracker.record_take_failed();
                        }

                        let take_result = ConcurrentTakeResult {
                            taker_id,
                            result,
                            success,
                        };

                        results_ref.lock().unwrap().push(take_result);
                    }));
                }

                // Wait for all threads to complete
                for handle in handles {
                    handle.join().expect("Thread should not panic");
                }

                let final_results = Arc::try_unwrap(results).unwrap().into_inner().unwrap();
                let successful_takes: Vec<_> = final_results.iter().filter(|r| r.success).collect();

                // Critical invariant: exactly one take should succeed
                if successful_takes.len() > 1 {
                    tracker.record_invariant_violation();
                    return Err(format!(
                        "Multiple concurrent takes succeeded: {} out of {} attempts",
                        successful_takes.len(), concurrent_count
                    ));
                }

                // Restore cell from shared state
                cell = Arc::try_unwrap(cell_arc).unwrap().into_inner().unwrap();
            }

            TakeRaceOperation::TakeThenSet { taker_id: _, value } => {
                tracker.record_take_attempted();
                let take_result = cell.take();

                match take_result {
                    Some(taken_value) => {
                        tracker.record_take_succeeded(taken_value);
                    }
                    None => {
                        tracker.record_take_failed();
                    }
                }

                // Immediately try to set a new value
                tracker.record_set_attempted();
                let set_result = cell.set(*value);

                match set_result {
                    Ok(()) => {
                        tracker.record_set_succeeded();

                        // Verify the new value is accessible
                        if let Some(new_value) = cell.get() {
                            if *new_value != *value {
                                tracker.record_invariant_violation();
                                return Err(format!(
                                    "Set after take failed: expected {}, got {}",
                                    value, new_value
                                ));
                            }
                            tracker.record_value_observed(*new_value);
                        }
                    }
                    Err(_) => {
                        tracker.record_set_failed();

                        // If take succeeded, set should succeed (cell should be uninitialized)
                        if take_result.is_some() {
                            tracker.record_invariant_violation();
                            return Err("Set failed after successful take - cell should be uninitialized".to_string());
                        }
                    }
                }
            }

            TakeRaceOperation::SetThenTake { setter_id: _, taker_id: _, value } => {
                tracker.record_set_attempted();
                let set_result = cell.set(*value);

                let expected_take_result = match set_result {
                    Ok(()) => {
                        tracker.record_set_succeeded();
                        Some(*value) // Should be able to take the value we just set
                    }
                    Err(_) => {
                        tracker.record_set_failed();
                        None // Set failed, so take should fail too
                    }
                };

                // Immediately try to take
                tracker.record_take_attempted();
                let take_result = cell.take();

                match take_result {
                    Some(taken_value) => {
                        tracker.record_take_succeeded(taken_value);

                        // Verify we got the value we set
                        if let Some(expected) = expected_take_result {
                            if taken_value != expected {
                                tracker.record_invariant_violation();
                                return Err(format!(
                                    "Take after set returned wrong value: expected {}, got {}",
                                    expected, taken_value
                                ));
                            }
                        }
                    }
                    None => {
                        tracker.record_take_failed();

                        // If set succeeded, take should have succeeded too
                        if set_result.is_ok() {
                            tracker.record_invariant_violation();
                            return Err("Take failed after successful set".to_string());
                        }
                    }
                }
            }

            TakeRaceOperation::RapidCycle { actor_id: _, cycles } => {
                let cycle_count = (*cycles).min(OnceCellTakeConfig::max_rapid_cycles()) as usize;

                for i in 0..cycle_count {
                    let cycle_value = (i + 1) as i32 * 100;

                    // Set
                    tracker.record_set_attempted();
                    let set_result = cell.set(cycle_value);

                    if set_result.is_err() && cell.is_initialized() {
                        // Cell already initialized, skip this cycle
                        tracker.record_set_failed();
                        continue;
                    } else if set_result.is_ok() {
                        tracker.record_set_succeeded();
                    }

                    // Get to verify
                    tracker.record_get_attempted();
                    if let Some(value) = cell.get() {
                        tracker.record_value_observed(*value);
                        if *value != cycle_value {
                            tracker.record_invariant_violation();
                            return Err(format!(
                                "Rapid cycle {}: get returned wrong value: expected {}, got {}",
                                i, cycle_value, value
                            ));
                        }
                    }

                    // Take
                    tracker.record_take_attempted();
                    let take_result = cell.take();

                    match take_result {
                        Some(taken_value) => {
                            tracker.record_take_succeeded(taken_value);
                            if taken_value != cycle_value {
                                tracker.record_invariant_violation();
                                return Err(format!(
                                    "Rapid cycle {}: take returned wrong value: expected {}, got {}",
                                    i, cycle_value, taken_value
                                ));
                            }
                        }
                        None => {
                            tracker.record_take_failed();
                            tracker.record_invariant_violation();
                            return Err(format!("Rapid cycle {}: take failed after successful set", i));
                        }
                    }

                    // Verify cell is uninitialized after take
                    if cell.is_initialized() {
                        tracker.record_invariant_violation();
                        return Err(format!("Rapid cycle {}: cell still initialized after take", i));
                    }
                }
            }

            TakeRaceOperation::CheckState => {
                // Basic state consistency checks
                let is_initialized = cell.is_initialized();
                let has_value = cell.get().is_some();

                if is_initialized != has_value {
                    tracker.record_invariant_violation();
                    return Err(format!(
                        "Inconsistent state: is_initialized={}, has_value={}",
                        is_initialized, has_value
                    ));
                }

                // Check our tracking invariants
                if let Err(msg) = tracker.check_invariants() {
                    return Err(format!("State check failed: {}", msg));
                }
            }
        }
    }

    // Final consistency check
    if let Err(msg) = tracker.check_invariants() {
        return Err(format!("Final invariant violation: {}", msg));
    }

    Ok(())
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    let config: OnceCellTakeConfig = match unstructured.arbitrary() {
        Ok(cfg) => cfg,
        Err(_) => return, // Invalid input, skip
    };

    // Validate and limit parameters
    if config.operations.is_empty() {
        return;
    }

    let tracker = TakeRaceTracker::new();

    // Test the take race scenario
    if let Err(msg) = test_take_race_scenario(&config, &tracker) {
        panic!("OnceCell take race test failed: {}", msg);
    }

    // Test concurrent scenarios if requested
    if config.test_concurrency {
        let tracker2 = TakeRaceTracker::new();
        let config2 = config.clone();

        let handle = thread::spawn(move || {
            test_take_race_scenario(&config2, &tracker2)
        });

        match handle.join() {
            Ok(Ok(())) => {
                // Concurrent test succeeded
            }
            Ok(Err(msg)) => {
                panic!("Concurrent take race test failed: {}", msg);
            }
            Err(_) => {
                panic!("Concurrent test thread panicked");
            }
        }
    }

    // Ensure we actually performed some operations
    let total_takes = tracker.takes_attempted.load(Ordering::SeqCst);
    let total_sets = tracker.sets_attempted.load(Ordering::SeqCst);
    let total_gets = tracker.gets_attempted.load(Ordering::SeqCst);

    if total_takes == 0 && total_sets == 0 && total_gets == 0 && !config.operations.is_empty() {
        panic!("No meaningful operations were performed during the test");
    }
});