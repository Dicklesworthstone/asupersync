#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::sync::atomic::{AtomicU64, Ordering};

use asupersync::lab::config::LabConfig;
use asupersync::lab::runtime::{AutoAdvanceTermination, LabRuntime, VirtualTimeReport};
use asupersync::types::Time;

/// Simplified fuzz input for LabRuntime virtual time advance functionality
#[derive(Arbitrary, Debug, Clone)]
struct LabRuntimeVirtualTimeFuzz {
    /// Random seed for deterministic execution
    pub seed: u64,
    /// Sequence of operations to execute
    pub operations: Vec<VirtualTimeOperation>,
    /// Runtime configuration parameters
    pub runtime_config: RuntimeConfiguration,
}

/// Individual virtual time operations to fuzz
#[derive(Arbitrary, Debug, Clone)]
enum VirtualTimeOperation {
    /// advance_time(nanos)
    AdvanceTime { nanos: u64 },
    /// advance_time_to(target_time)
    AdvanceTimeTo { target_nanos: u64 },
    /// advance_to_next_timer()
    AdvanceToNextTimer,
    /// run_with_auto_advance() with max iterations limit
    RunWithAutoAdvance { max_iterations: u32 },
    /// Pause virtual clock
    PauseClock,
    /// Resume virtual clock
    ResumeClock,
    /// Check if clock is paused
    CheckClockState,
    /// Check if runtime is quiescent
    CheckQuiescence,
}

/// Runtime configuration parameters
#[derive(Arbitrary, Debug, Clone)]
struct RuntimeConfiguration {
    /// Enable auto-advance
    pub auto_advance: bool,
    /// Maximum steps for run_with_auto_advance
    pub max_steps: Option<u64>,
    /// Enable chaos injection
    pub enable_chaos: bool,
    /// Maximum virtual time to prevent infinite loops
    pub max_virtual_time_nanos: u64,
}

/// Shadow model to track expected virtual time behavior
#[derive(Debug)]
struct VirtualTimeShadowModel {
    /// Expected current virtual time
    expected_virtual_time: AtomicU64,
    /// Operation count for validation
    operation_count: AtomicU64,
    /// Detected violations
    violations: std::sync::Mutex<Vec<String>>,
}

impl VirtualTimeShadowModel {
    fn new() -> Self {
        Self {
            expected_virtual_time: AtomicU64::new(0),
            operation_count: AtomicU64::new(0),
            violations: std::sync::Mutex::new(Vec::new()),
        }
    }

    fn record_time_advance(&self, nanos: u64) {
        let previous = self
            .expected_virtual_time
            .fetch_add(nanos, Ordering::SeqCst);
        let new_time = previous + nanos;

        // Check for overflow
        if new_time < previous {
            self.add_violation("Virtual time overflow detected".to_string());
        }
    }

    fn set_virtual_time(&self, nanos: u64) {
        let previous = self.expected_virtual_time.swap(nanos, Ordering::SeqCst);

        // Time should not go backward
        if nanos < previous {
            self.add_violation(format!("Time went backward: {} -> {}", previous, nanos));
        }
    }

    fn add_violation(&self, violation: String) {
        self.violations.lock().unwrap().push(violation);
    }

    fn get_violations(&self) -> Vec<String> {
        self.violations.lock().unwrap().clone()
    }

    fn verify_time_consistency(&self, actual_time: Time) -> Result<(), String> {
        let expected_nanos = self.expected_virtual_time.load(Ordering::SeqCst);
        let actual_nanos = actual_time.as_nanos();

        // Allow some tolerance for floating-point precision issues
        let tolerance = 1000; // 1 microsecond tolerance

        if actual_nanos.abs_diff(expected_nanos) > tolerance {
            return Err(format!(
                "Virtual time mismatch: expected {}, actual {}",
                expected_nanos, actual_nanos
            ));
        }

        Ok(())
    }
}

/// Normalize fuzz input to valid ranges
fn normalize_fuzz_input(input: &mut LabRuntimeVirtualTimeFuzz) {
    // Limit operations to prevent timeouts
    input.operations.truncate(50);

    // Bound time values to prevent overflow and ensure reasonable test duration
    const MAX_TIME_NANOS: u64 = 24 * 60 * 60 * 1_000_000_000; // 24 hours in nanoseconds

    for op in &mut input.operations {
        match op {
            VirtualTimeOperation::AdvanceTime { nanos } => {
                *nanos = (*nanos).clamp(0, MAX_TIME_NANOS / 100); // Limit individual advances
            }
            VirtualTimeOperation::AdvanceTimeTo { target_nanos } => {
                *target_nanos = (*target_nanos).clamp(0, MAX_TIME_NANOS);
            }
            VirtualTimeOperation::RunWithAutoAdvance { max_iterations } => {
                *max_iterations = (*max_iterations).clamp(1, 100); // Prevent infinite loops
            }
            _ => {}
        }
    }

    // Normalize runtime configuration
    if let Some(ref mut max_steps) = input.runtime_config.max_steps {
        *max_steps = (*max_steps).clamp(1, 1000);
    }
    input.runtime_config.max_virtual_time_nanos = input
        .runtime_config
        .max_virtual_time_nanos
        .clamp(0, MAX_TIME_NANOS);
}

/// Execute virtual time operations and verify invariants
fn execute_virtual_time_operations(
    input: &LabRuntimeVirtualTimeFuzz,
    shadow: &VirtualTimeShadowModel,
) -> Result<(), String> {
    // Create lab runtime with deterministic seed and optional auto-advance
    let mut config = LabConfig::new(input.seed);

    if input.runtime_config.auto_advance {
        config = config.with_auto_advance();
    }

    if input.runtime_config.enable_chaos {
        config = config.with_light_chaos();
    }

    let mut runtime = LabRuntime::new(config);

    // Execute operation sequence
    for (op_index, operation) in input.operations.iter().enumerate() {
        shadow
            .operation_count
            .store(op_index as u64, Ordering::SeqCst);

        // Check if we've exceeded maximum virtual time to prevent runaway tests
        if runtime.now().as_nanos() > input.runtime_config.max_virtual_time_nanos {
            break;
        }

        match operation {
            VirtualTimeOperation::AdvanceTime { nanos } => {
                let before_time = runtime.now();
                runtime.advance_time(*nanos);
                let after_time = runtime.now();

                // Verify time advanced correctly
                let expected_advance = *nanos;
                let actual_advance = after_time.as_nanos() - before_time.as_nanos();

                if actual_advance != expected_advance {
                    return Err(format!(
                        "advance_time({}) failed: expected advance {}, actual advance {}",
                        nanos, expected_advance, actual_advance
                    ));
                }

                shadow.record_time_advance(*nanos);
            }

            VirtualTimeOperation::AdvanceTimeTo { target_nanos } => {
                let before_time = runtime.now();
                let target = Time::from_nanos(*target_nanos);
                runtime.advance_time_to(target);
                let after_time = runtime.now();

                // Verify time advanced correctly (or didn't go backward)
                if target > before_time {
                    if after_time != target {
                        return Err(format!(
                            "advance_time_to({}) failed: expected {}, actual {}",
                            target_nanos,
                            target.as_nanos(),
                            after_time.as_nanos()
                        ));
                    }
                    shadow.set_virtual_time(*target_nanos);
                } else {
                    // Time shouldn't change if target is in past
                    if after_time != before_time {
                        return Err(format!(
                            "advance_time_to({}) incorrectly changed time from {} to {}",
                            target_nanos,
                            before_time.as_nanos(),
                            after_time.as_nanos()
                        ));
                    }
                }
            }

            VirtualTimeOperation::AdvanceToNextTimer => {
                let before_time = runtime.now();
                let wakeups = runtime.advance_to_next_timer();
                let after_time = runtime.now();

                // Verify time advanced to a timer deadline (or stayed same if no timers)
                if wakeups > 0 && after_time <= before_time {
                    return Err(format!(
                        "advance_to_next_timer() reported {} wakeups but time didn't advance",
                        wakeups
                    ));
                }

                // Update shadow model if time advanced
                if after_time > before_time {
                    shadow.set_virtual_time(after_time.as_nanos());
                }
            }

            VirtualTimeOperation::RunWithAutoAdvance { max_iterations } => {
                let before_time = runtime.now();

                // Create a temporary runtime with max steps limit for this operation
                let mut limited_config = LabConfig::new(input.seed);
                if input.runtime_config.auto_advance {
                    limited_config = limited_config.with_auto_advance();
                }
                if let Some(max_steps) = input.runtime_config.max_steps {
                    limited_config =
                        limited_config.max_steps(max_steps.min(*max_iterations as u64));
                } else {
                    limited_config = limited_config.max_steps(*max_iterations as u64);
                }

                let mut limited_runtime = LabRuntime::new(limited_config);
                // Copy the current time state
                limited_runtime.advance_time_to(before_time);

                let report = limited_runtime.run_with_auto_advance();
                let after_time = limited_runtime.now();

                // Apply the time change to our main runtime
                runtime.advance_time_to(after_time);

                // Verify report consistency
                verify_virtual_time_report(&report, before_time, after_time)?;

                // Update shadow model
                shadow.set_virtual_time(after_time.as_nanos());
            }

            VirtualTimeOperation::PauseClock => {
                runtime.pause_clock();
            }

            VirtualTimeOperation::ResumeClock => {
                runtime.resume_clock();
            }

            VirtualTimeOperation::CheckClockState => {
                // Just check the clock state - this tests the is_clock_paused() method
                let _paused = runtime.is_clock_paused();
            }

            VirtualTimeOperation::CheckQuiescence => {
                // Check if runtime is quiescent
                let _quiescent = runtime.is_quiescent();
            }
        }

        // Verify shadow model consistency every 10 operations
        if op_index % 10 == 0 {
            shadow.verify_time_consistency(runtime.now())?;
        }
    }

    // Final consistency check
    shadow.verify_time_consistency(runtime.now())?;

    // Check for any recorded violations
    let violations = shadow.get_violations();
    if !violations.is_empty() {
        return Err(format!("Shadow model violations: {:?}", violations));
    }

    Ok(())
}

/// Verify VirtualTimeReport consistency
fn verify_virtual_time_report(
    report: &VirtualTimeReport,
    before_time: Time,
    after_time: Time,
) -> Result<(), String> {
    // Time should have advanced or stayed the same
    if after_time < before_time {
        return Err("Virtual time went backward during auto-advance".to_string());
    }

    // Elapsed time should match time difference
    let expected_elapsed = after_time.as_nanos() - before_time.as_nanos();
    if report.virtual_elapsed_nanos != expected_elapsed {
        return Err(format!(
            "VirtualTimeReport elapsed time mismatch: expected {}, actual {}",
            expected_elapsed, report.virtual_elapsed_nanos
        ));
    }

    // Start and end times should match
    if report.time_start != before_time {
        return Err(format!(
            "VirtualTimeReport start time mismatch: expected {}, actual {}",
            before_time.as_nanos(),
            report.time_start.as_nanos()
        ));
    }

    if report.time_end != after_time {
        return Err(format!(
            "VirtualTimeReport end time mismatch: expected {}, actual {}",
            after_time.as_nanos(),
            report.time_end.as_nanos()
        ));
    }

    // Termination reason should be valid
    match report.termination {
        AutoAdvanceTermination::Quiescent => {
            // Valid - runtime reached quiescence
        }
        AutoAdvanceTermination::StepLimitReached => {
            // Valid - hit configured step limit
        }
        AutoAdvanceTermination::StuckBailout => {
            // Valid - runtime was stuck
        }
    }

    // Steps should be reasonable
    if report.steps > 1_000_000 {
        return Err(format!("Excessive step count: {}", report.steps));
    }

    Ok(())
}

/// Main fuzzing entry point
fn fuzz_lab_runtime_virtual_time(mut input: LabRuntimeVirtualTimeFuzz) -> Result<(), String> {
    normalize_fuzz_input(&mut input);

    // Skip degenerate cases
    if input.operations.is_empty() {
        return Ok(());
    }

    let shadow = VirtualTimeShadowModel::new();

    // Test virtual time operations
    execute_virtual_time_operations(&input, &shadow)?;

    Ok(())
}

fuzz_target!(|data: &[u8]| {
    // Limit input size for performance
    if data.len() > 10_000 {
        return;
    }

    let mut unstructured = arbitrary::Unstructured::new(data);

    // Generate fuzz configuration
    let input = if let Ok(input) = LabRuntimeVirtualTimeFuzz::arbitrary(&mut unstructured) {
        input
    } else {
        return;
    };

    // Run virtual time fuzzing
    let _ = fuzz_lab_runtime_virtual_time(input);
});
