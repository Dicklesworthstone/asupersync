#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};
use std::sync::{Arc, Mutex as StdMutex};
use std::thread;
use std::time::Duration;
use std::panic::{catch_unwind, AssertUnwindSafe};

use asupersync::sync::OnceCell;

#[derive(Debug, Clone)]
struct SetAfterInitTracker {
    operations: Arc<StdMutex<Vec<String>>>,
    set_results: Arc<StdMutex<Vec<SetResult>>>,
    invariant_violations: Arc<StdMutex<Vec<InvariantViolation>>>,
}

#[derive(Debug, Clone)]
struct SetResult {
    operation_id: usize,
    value_attempted: u32,
    result: SetOutcome,
    cell_was_initialized_before: bool,
    cell_was_initialized_after: bool,
}

#[derive(Debug, Clone, PartialEq)]
enum SetOutcome {
    Success,
    Failed(u32), // Failed with returned value
    Panicked,
}

#[derive(Debug, Clone)]
struct InvariantViolation {
    violation_type: String,
    description: String,
    operation_id: usize,
}

impl SetAfterInitTracker {
    fn new() -> Self {
        Self {
            operations: Arc::new(StdMutex::new(Vec::new())),
            set_results: Arc::new(StdMutex::new(Vec::new())),
            invariant_violations: Arc::new(StdMutex::new(Vec::new())),
        }
    }

    fn record_operation(&self, op: &str) {
        if let Ok(mut ops) = self.operations.lock() {
            ops.push(op.to_string());
        }
    }

    fn record_set_result(&self, result: SetResult) {
        if let Ok(mut results) = self.set_results.lock() {
            results.push(result);
        }
    }

    fn record_violation(&self, violation: InvariantViolation) {
        if let Ok(mut violations) = self.invariant_violations.lock() {
            violations.push(violation);
        }
    }

    fn validate_set_after_init_invariants(&self) {
        if let Ok(results) = self.set_results.lock() {
            for result in results.iter() {
                // Core invariant: if cell was already initialized, set should fail with original value
                if result.cell_was_initialized_before {
                    match &result.result {
                        SetOutcome::Success => {
                            self.record_violation(InvariantViolation {
                                violation_type: "set_succeeded_on_initialized_cell".to_string(),
                                description: format!(
                                    "Operation {} succeeded on already-initialized cell",
                                    result.operation_id
                                ),
                                operation_id: result.operation_id,
                            });
                        }
                        SetOutcome::Failed(returned_value) => {
                            // This is correct behavior - verify returned value matches attempted
                            if *returned_value != result.value_attempted {
                                self.record_violation(InvariantViolation {
                                    violation_type: "incorrect_returned_value".to_string(),
                                    description: format!(
                                        "Operation {} returned {} but attempted {}",
                                        result.operation_id, returned_value, result.value_attempted
                                    ),
                                    operation_id: result.operation_id,
                                });
                            }
                        }
                        SetOutcome::Panicked => {
                            self.record_violation(InvariantViolation {
                                violation_type: "panic_on_set_after_init".to_string(),
                                description: format!(
                                    "Operation {} panicked when setting on initialized cell",
                                    result.operation_id
                                ),
                                operation_id: result.operation_id,
                            });
                        }
                    }
                }

                // Invariant: successful set should leave cell initialized
                if result.result == SetOutcome::Success && !result.cell_was_initialized_after {
                    self.record_violation(InvariantViolation {
                        violation_type: "successful_set_did_not_initialize".to_string(),
                        description: format!(
                            "Operation {} succeeded but cell not initialized after",
                            result.operation_id
                        ),
                        operation_id: result.operation_id,
                    });
                }

                // Invariant: failed set should not change initialization state
                if matches!(result.result, SetOutcome::Failed(_)) {
                    if result.cell_was_initialized_before != result.cell_was_initialized_after {
                        self.record_violation(InvariantViolation {
                            violation_type: "failed_set_changed_state".to_string(),
                            description: format!(
                                "Operation {} failed but changed initialization state from {} to {}",
                                result.operation_id, result.cell_was_initialized_before, result.cell_was_initialized_after
                            ),
                            operation_id: result.operation_id,
                        });
                    }
                }
            }
        }

        // Check for any violations and panic if found
        if let Ok(violations) = self.invariant_violations.lock() {
            if !violations.is_empty() {
                for violation in violations.iter() {
                    self.record_operation(&format!(
                        "VIOLATION: {} - {}",
                        violation.violation_type, violation.description
                    ));
                }
                panic!("OnceCell set-after-init invariant violations detected: {} violations", violations.len());
            }
        }
    }
}

#[derive(Debug, Clone, Arbitrary)]
struct SetAfterInitConfig {
    initial_value: u32,
    set_attempts: Vec<SetAttempt>,
    pattern: SetPattern,
}

#[derive(Debug, Clone, Arbitrary)]
struct SetAttempt {
    value: u32,
    delay_us: u16,
}

#[derive(Debug, Clone, Arbitrary)]
enum SetPattern {
    SequentialSets,
    ConcurrentSets { thread_count: u8 },
    RapidFire { iterations: u8 },
    DelayedSets { base_delay_us: u16 },
    MixedPattern { operations: Vec<Operation> },
}

#[derive(Debug, Clone, Arbitrary)]
enum Operation {
    Set { value: u32 },
    CheckInitialized,
    GetValue,
    ConcurrentSet { value: u32, delay_us: u16 },
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);

    let config: SetAfterInitConfig = u.arbitrary().unwrap_or(SetAfterInitConfig {
        initial_value: 42,
        set_attempts: vec![
            SetAttempt { value: 100, delay_us: 0 },
            SetAttempt { value: 200, delay_us: 10 },
        ],
        pattern: SetPattern::SequentialSets,
    });

    // Limit the number of operations to prevent excessive test time
    let set_attempts = config.set_attempts.into_iter().take(10).collect::<Vec<_>>();
    if set_attempts.is_empty() {
        return;
    }

    let tracker = SetAfterInitTracker::new();
    let cell = Arc::new(OnceCell::<u32>::new());

    // Initialize the cell first
    let init_result = cell.set(config.initial_value);
    tracker.record_operation(&format!("initial_set_{}_result_{:?}", config.initial_value, init_result.is_ok()));

    if init_result.is_err() {
        // If initial set failed, something is wrong
        tracker.record_violation(InvariantViolation {
            violation_type: "initial_set_failed".to_string(),
            description: "Initial set on empty cell failed".to_string(),
            operation_id: 0,
        });
        tracker.validate_set_after_init_invariants();
        return;
    }

    // Execute the pattern
    match config.pattern {
        SetPattern::SequentialSets => {
            test_sequential_sets(&tracker, &cell, &set_attempts);
        }

        SetPattern::ConcurrentSets { thread_count } => {
            test_concurrent_sets(&tracker, &cell, &set_attempts, thread_count.min(8));
        }

        SetPattern::RapidFire { iterations } => {
            test_rapid_fire_sets(&tracker, &cell, &set_attempts, iterations.min(20));
        }

        SetPattern::DelayedSets { base_delay_us } => {
            test_delayed_sets(&tracker, &cell, &set_attempts, base_delay_us);
        }

        SetPattern::MixedPattern { operations } => {
            test_mixed_pattern(&tracker, &cell, operations);
        }
    }

    // Validate all invariants
    tracker.validate_set_after_init_invariants();
});

fn test_sequential_sets(tracker: &SetAfterInitTracker, cell: &OnceCell<u32>, attempts: &[SetAttempt]) {
    tracker.record_operation("test_sequential_sets");

    for (i, attempt) in attempts.iter().enumerate() {
        if attempt.delay_us > 0 {
            thread::sleep(Duration::from_micros(attempt.delay_us.min(1000) as u64));
        }

        let was_initialized_before = cell.is_initialized();

        let result = catch_unwind(AssertUnwindSafe(|| {
            cell.set(attempt.value)
        }));

        let was_initialized_after = cell.is_initialized();

        let outcome = match result {
            Ok(Ok(())) => SetOutcome::Success,
            Ok(Err(returned_value)) => SetOutcome::Failed(returned_value),
            Err(_) => SetOutcome::Panicked,
        };

        tracker.record_set_result(SetResult {
            operation_id: i + 1,
            value_attempted: attempt.value,
            result: outcome,
            cell_was_initialized_before: was_initialized_before,
            cell_was_initialized_after: was_initialized_after,
        });
    }
}

fn test_concurrent_sets(tracker: &SetAfterInitTracker, cell: &OnceCell<u32>, attempts: &[SetAttempt], thread_count: u8) {
    tracker.record_operation("test_concurrent_sets");

    let mut handles = Vec::new();
    let cell = Arc::new(cell);

    for i in 0..thread_count as usize {
        let attempt_idx = i % attempts.len();
        let attempt = attempts[attempt_idx].clone();
        let cell_clone = Arc::clone(&cell);
        let tracker_clone = tracker.clone();

        let handle = thread::spawn(move || {
            if attempt.delay_us > 0 {
                thread::sleep(Duration::from_micros(attempt.delay_us.min(1000) as u64));
            }

            let was_initialized_before = cell_clone.is_initialized();

            let result = catch_unwind(AssertUnwindSafe(|| {
                cell_clone.set(attempt.value)
            }));

            let was_initialized_after = cell_clone.is_initialized();

            let outcome = match result {
                Ok(Ok(())) => SetOutcome::Success,
                Ok(Err(returned_value)) => SetOutcome::Failed(returned_value),
                Err(_) => SetOutcome::Panicked,
            };

            tracker_clone.record_set_result(SetResult {
                operation_id: i + 100, // Offset to distinguish from sequential
                value_attempted: attempt.value,
                result: outcome,
                cell_was_initialized_before: was_initialized_before,
                cell_was_initialized_after: was_initialized_after,
            });
        });

        handles.push(handle);
    }

    for handle in handles {
        let _ = handle.join();
    }
}

fn test_rapid_fire_sets(tracker: &SetAfterInitTracker, cell: &OnceCell<u32>, attempts: &[SetAttempt], iterations: u8) {
    tracker.record_operation("test_rapid_fire_sets");

    for i in 0..iterations as usize {
        let attempt_idx = i % attempts.len();
        let attempt = &attempts[attempt_idx];

        let was_initialized_before = cell.is_initialized();

        let result = catch_unwind(AssertUnwindSafe(|| {
            cell.set(attempt.value)
        }));

        let was_initialized_after = cell.is_initialized();

        let outcome = match result {
            Ok(Ok(())) => SetOutcome::Success,
            Ok(Err(returned_value)) => SetOutcome::Failed(returned_value),
            Err(_) => SetOutcome::Panicked,
        };

        tracker.record_set_result(SetResult {
            operation_id: i + 200, // Offset to distinguish from other patterns
            value_attempted: attempt.value,
            result: outcome,
            cell_was_initialized_before: was_initialized_before,
            cell_was_initialized_after: was_initialized_after,
        });
    }
}

fn test_delayed_sets(tracker: &SetAfterInitTracker, cell: &OnceCell<u32>, attempts: &[SetAttempt], base_delay_us: u16) {
    tracker.record_operation("test_delayed_sets");

    for (i, attempt) in attempts.iter().enumerate() {
        let total_delay = base_delay_us.saturating_add(attempt.delay_us).min(2000);
        if total_delay > 0 {
            thread::sleep(Duration::from_micros(total_delay as u64));
        }

        let was_initialized_before = cell.is_initialized();

        let result = catch_unwind(AssertUnwindSafe(|| {
            cell.set(attempt.value)
        }));

        let was_initialized_after = cell.is_initialized();

        let outcome = match result {
            Ok(Ok(())) => SetOutcome::Success,
            Ok(Err(returned_value)) => SetOutcome::Failed(returned_value),
            Err(_) => SetOutcome::Panicked,
        };

        tracker.record_set_result(SetResult {
            operation_id: i + 300, // Offset to distinguish from other patterns
            value_attempted: attempt.value,
            result: outcome,
            cell_was_initialized_before: was_initialized_before,
            cell_was_initialized_after: was_initialized_after,
        });
    }
}

fn test_mixed_pattern(tracker: &SetAfterInitTracker, cell: &OnceCell<u32>, operations: Vec<Operation>) {
    tracker.record_operation("test_mixed_pattern");

    for (i, operation) in operations.iter().take(15).enumerate() {
        match operation {
            Operation::Set { value } => {
                let was_initialized_before = cell.is_initialized();

                let result = catch_unwind(AssertUnwindSafe(|| {
                    cell.set(*value)
                }));

                let was_initialized_after = cell.is_initialized();

                let outcome = match result {
                    Ok(Ok(())) => SetOutcome::Success,
                    Ok(Err(returned_value)) => SetOutcome::Failed(returned_value),
                    Err(_) => SetOutcome::Panicked,
                };

                tracker.record_set_result(SetResult {
                    operation_id: i + 400, // Offset for mixed pattern
                    value_attempted: *value,
                    result: outcome,
                    cell_was_initialized_before: was_initialized_before,
                    cell_was_initialized_after: was_initialized_after,
                });
            }

            Operation::CheckInitialized => {
                let is_init = cell.is_initialized();
                tracker.record_operation(&format!("check_initialized_{}", is_init));
            }

            Operation::GetValue => {
                let value = cell.get();
                tracker.record_operation(&format!("get_value_{:?}", value));
            }

            Operation::ConcurrentSet { value, delay_us } => {
                let value = *value;
                let delay = Duration::from_micros((*delay_us).min(500) as u64);
                let cell_clone = cell;
                let tracker_clone = tracker.clone();

                let handle = thread::spawn(move || {
                    thread::sleep(delay);

                    let was_initialized_before = cell_clone.is_initialized();

                    let result = catch_unwind(AssertUnwindSafe(|| {
                        cell_clone.set(value)
                    }));

                    let was_initialized_after = cell_clone.is_initialized();

                    let outcome = match result {
                        Ok(Ok(())) => SetOutcome::Success,
                        Ok(Err(returned_value)) => SetOutcome::Failed(returned_value),
                        Err(_) => SetOutcome::Panicked,
                    };

                    tracker_clone.record_set_result(SetResult {
                        operation_id: i + 500, // Offset for concurrent mixed
                        value_attempted: value,
                        result: outcome,
                        cell_was_initialized_before: was_initialized_before,
                        cell_was_initialized_after: was_initialized_after,
                    });
                });

                let _ = handle.join();
            }
        }
    }
}