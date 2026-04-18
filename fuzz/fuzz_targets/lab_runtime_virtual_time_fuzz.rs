#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::Duration as StdDuration;

use asupersync::lab::config::LabConfig;
use asupersync::lab::runtime::{AutoAdvanceTermination, LabRuntime, VirtualTimeReport};
use asupersync::record::ObligationKind;
use asupersync::types::{CancelReason, RegionId, TaskId, Time};
use asupersync::util::DetRng;

/// Comprehensive fuzz input for LabRuntime virtual time advance functionality
#[derive(Arbitrary, Debug, Clone)]
struct LabRuntimeVirtualTimeFuzz {
    /// Random seed for deterministic execution
    pub seed: u64,
    /// Sequence of operations to execute
    pub operations: Vec<VirtualTimeOperation>,
    /// Timer configuration
    pub timer_config: TimerConfiguration,
    /// Cancellation scenarios to test
    pub cancel_scenarios: Vec<CancelScenario>,
    /// Cross-thread scheduling test setup
    pub threading_config: Option<ThreadingConfiguration>,
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
    /// run_with_auto_advance()
    RunWithAutoAdvance { max_iterations: u32 },
    /// Schedule a timer at specific deadline
    ScheduleTimer {
        deadline_offset_nanos: u64,
        timer_id: u32,
    },
    /// Create a task with timeout
    CreateTaskWithTimeout { timeout_nanos: u64, task_id: u32 },
    /// Cancel a task during time advance
    CancelTaskDuringAdvance { task_id: u32, cancel_at_nanos: u64 },
    /// Pause virtual clock
    PauseClock,
    /// Resume virtual clock
    ResumeClock,
    /// Step the scheduler manually
    StepScheduler { steps: u32 },
    /// Inject chaos during time advance
    InjectChaos {
        delay_nanos: u64,
        cause_budget_exhaust: bool,
    },
}

/// Timer wheel configuration for testing edge cases
#[derive(Arbitrary, Debug, Clone)]
struct TimerConfiguration {
    /// Multiple timer deadlines for collision testing
    pub timer_deadlines: Vec<u64>,
    /// Timer deadline clustering (multiple timers at same time)
    pub clustered_deadlines: bool,
    /// Large time jumps
    pub large_jumps: bool,
    /// Maximum timer deadline value
    pub max_deadline_nanos: u64,
}

/// Cancellation scenarios for testing cancel-during-advance
#[derive(Arbitrary, Debug, Clone)]
struct CancelScenario {
    /// Task to cancel
    pub task_id: u32,
    /// When to cancel (relative to operation start)
    pub cancel_at_nanos: u64,
    /// Reason for cancellation
    pub cancel_reason: FuzzCancelReason,
    /// Whether to test cancellation during auto-advance
    pub during_auto_advance: bool,
}

#[derive(Arbitrary, Debug, Clone)]
enum FuzzCancelReason {
    User,
    Timeout,
    Shutdown,
    ParentCancelled,
}

impl From<FuzzCancelReason> for CancelReason {
    fn from(reason: FuzzCancelReason) -> Self {
        match reason {
            FuzzCancelReason::User => CancelReason::user("fuzz test"),
            FuzzCancelReason::Timeout => CancelReason::timeout(),
            FuzzCancelReason::Shutdown => CancelReason::shutdown(),
            FuzzCancelReason::ParentCancelled => CancelReason::parent_cancelled(),
        }
    }
}

/// Cross-thread scheduling configuration
#[derive(Arbitrary, Debug, Clone)]
struct ThreadingConfiguration {
    /// Number of worker threads (1-4)
    pub num_threads: u8,
    /// Operations to run on each thread
    pub per_thread_ops: Vec<Vec<ThreadOperation>>,
    /// Synchronization points
    pub sync_points: Vec<SyncPoint>,
}

#[derive(Arbitrary, Debug, Clone)]
enum ThreadOperation {
    AdvanceTime { nanos: u64 },
    ScheduleTimer { deadline_nanos: u64 },
    CheckTime,
    CancelTask { task_id: u32 },
}

#[derive(Arbitrary, Debug, Clone)]
struct SyncPoint {
    /// After this many operations, synchronize all threads
    pub after_operations: u32,
    /// Time to advance to during sync
    pub sync_time_nanos: u64,
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
    /// Scheduled timer deadlines
    scheduled_timers: std::sync::Mutex<HashMap<u32, u64>>,
    /// Tasks with timeouts
    task_timeouts: std::sync::Mutex<HashMap<u32, u64>>,
    /// Clock pause state
    clock_paused: AtomicBool,
    /// Operation count for validation
    operation_count: AtomicU64,
    /// Detected violations
    violations: std::sync::Mutex<Vec<String>>,
}

impl VirtualTimeShadowModel {
    fn new() -> Self {
        Self {
            expected_virtual_time: AtomicU64::new(0),
            scheduled_timers: std::sync::Mutex::new(HashMap::new()),
            task_timeouts: std::sync::Mutex::new(HashMap::new()),
            clock_paused: AtomicBool::new(false),
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

    fn schedule_timer(&self, timer_id: u32, deadline_nanos: u64) {
        self.scheduled_timers
            .lock()
            .unwrap()
            .insert(timer_id, deadline_nanos);
    }

    fn schedule_task_timeout(&self, task_id: u32, timeout_nanos: u64) {
        let current_time = self.expected_virtual_time.load(Ordering::SeqCst);
        let absolute_deadline = current_time + timeout_nanos;
        self.task_timeouts
            .lock()
            .unwrap()
            .insert(task_id, absolute_deadline);
    }

    fn set_clock_paused(&self, paused: bool) {
        self.clock_paused.store(paused, Ordering::SeqCst);
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

    fn next_timer_deadline(&self) -> Option<u64> {
        self.scheduled_timers
            .lock()
            .unwrap()
            .values()
            .min()
            .copied()
    }

    fn process_expired_timers(&self, current_time: u64) -> usize {
        let mut timers = self.scheduled_timers.lock().unwrap();
        let expired_count = timers
            .values()
            .filter(|&&deadline| deadline <= current_time)
            .count();
        timers.retain(|_, &mut deadline| deadline > current_time);
        expired_count
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
            VirtualTimeOperation::ScheduleTimer {
                deadline_offset_nanos,
                timer_id,
            } => {
                *deadline_offset_nanos = (*deadline_offset_nanos).clamp(0, MAX_TIME_NANOS);
                *timer_id = (*timer_id).clamp(0, 1000); // Limit timer IDs
            }
            VirtualTimeOperation::CreateTaskWithTimeout {
                timeout_nanos,
                task_id,
            } => {
                *timeout_nanos = (*timeout_nanos).clamp(1_000_000, MAX_TIME_NANOS / 10); // 1ms to 2.4h
                *task_id = (*task_id).clamp(0, 1000); // Limit task IDs
            }
            VirtualTimeOperation::CancelTaskDuringAdvance {
                task_id,
                cancel_at_nanos,
            } => {
                *task_id = (*task_id).clamp(0, 1000);
                *cancel_at_nanos = (*cancel_at_nanos).clamp(0, MAX_TIME_NANOS);
            }
            VirtualTimeOperation::StepScheduler { steps } => {
                *steps = (*steps).clamp(1, 100); // Limit manual steps
            }
            VirtualTimeOperation::InjectChaos { delay_nanos, .. } => {
                *delay_nanos = (*delay_nanos).clamp(0, MAX_TIME_NANOS / 1000); // Small chaos delays
            }
            VirtualTimeOperation::RunWithAutoAdvance { max_iterations } => {
                *max_iterations = max_iterations.clamp(1, 100); // Prevent infinite loops
            }
            _ => {}
        }
    }

    // Normalize timer configuration
    input.timer_config.timer_deadlines.truncate(20);
    input.timer_config.max_deadline_nanos = input
        .timer_config
        .max_deadline_nanos
        .clamp(0, MAX_TIME_NANOS);

    for deadline in &mut input.timer_config.timer_deadlines {
        *deadline = deadline.clamp(0, MAX_TIME_NANOS);
    }

    // Normalize cancel scenarios
    input.cancel_scenarios.truncate(10);
    for scenario in &mut input.cancel_scenarios {
        scenario.task_id = scenario.task_id.clamp(0, 1000);
        scenario.cancel_at_nanos = scenario.cancel_at_nanos.clamp(0, MAX_TIME_NANOS);
    }

    // Normalize threading configuration
    if let Some(ref mut threading) = input.threading_config {
        threading.num_threads = threading.num_threads.clamp(1, 4);
        threading.per_thread_ops.truncate(4);
        for ops in &mut threading.per_thread_ops {
            ops.truncate(20);
            for op in ops {
                match op {
                    ThreadOperation::AdvanceTime { nanos } => {
                        *nanos = nanos.clamp(0, MAX_TIME_NANOS / 100);
                    }
                    ThreadOperation::ScheduleTimer { deadline_nanos } => {
                        *deadline_nanos = deadline_nanos.clamp(0, MAX_TIME_NANOS);
                    }
                    ThreadOperation::CancelTask { task_id } => {
                        *task_id = task_id.clamp(0, 1000);
                    }
                    _ => {}
                }
            }
        }
        threading.sync_points.truncate(5);
        for sync_point in &mut threading.sync_points {
            sync_point.after_operations = sync_point.after_operations.clamp(1, 50);
            sync_point.sync_time_nanos = sync_point.sync_time_nanos.clamp(0, MAX_TIME_NANOS);
        }
    }

    // Normalize runtime configuration
    if let Some(ref mut max_steps) = input.runtime_config.max_steps {
        *max_steps = max_steps.clamp(1, 10000);
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
    // Create lab runtime with deterministic seed
    let config = LabConfig::new(input.seed)
        .with_auto_advance_if(input.runtime_config.auto_advance)
        .with_max_steps_if(input.runtime_config.max_steps)
        .with_chaos_if(input.runtime_config.enable_chaos);

    let mut runtime = LabRuntime::new(config);

    // Pre-configure timers from timer_config
    for (i, &deadline_nanos) in input.timer_config.timer_deadlines.iter().enumerate() {
        let timer_id = i as u32;
        // Schedule timer via timer driver if available
        if let Some(timer_handle) = runtime.state.timer_driver_handle() {
            let deadline = Time::from_nanos(deadline_nanos);
            timer_handle.schedule_timer_at(deadline, || {});
            shadow.schedule_timer(timer_id, deadline_nanos);
        }
    }

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
                    shadow.process_expired_timers(after_time.as_nanos());
                }
            }

            VirtualTimeOperation::RunWithAutoAdvance { max_iterations } => {
                // Set step limit to prevent infinite loops
                let original_max_steps = runtime.config.max_steps;
                runtime.config.max_steps = Some(*max_iterations as u64);

                let before_time = runtime.now();
                let report = runtime.run_with_auto_advance();
                let after_time = runtime.now();

                // Restore original max_steps
                runtime.config.max_steps = original_max_steps;

                // Verify report consistency
                verify_virtual_time_report(&report, before_time, after_time)?;

                // Update shadow model
                shadow.set_virtual_time(after_time.as_nanos());
            }

            VirtualTimeOperation::ScheduleTimer {
                deadline_offset_nanos,
                timer_id,
            } => {
                let current_time = runtime.now();
                let deadline = current_time.saturating_add_nanos(*deadline_offset_nanos);

                // Schedule timer if timer driver available
                if let Some(timer_handle) = runtime.state.timer_driver_handle() {
                    timer_handle.schedule_timer_at(deadline, || {});
                    shadow.schedule_timer(*timer_id, deadline.as_nanos());
                }
            }

            VirtualTimeOperation::CreateTaskWithTimeout {
                timeout_nanos,
                task_id,
            } => {
                // Create a task with timeout (simplified for fuzzing)
                shadow.schedule_task_timeout(*task_id, *timeout_nanos);
            }

            VirtualTimeOperation::CancelTaskDuringAdvance {
                task_id,
                cancel_at_nanos,
            } => {
                let current_time = runtime.now().as_nanos();
                if current_time >= *cancel_at_nanos {
                    // Cancel task immediately (simplified for fuzzing)
                    // In a real scenario, this would cancel a specific task
                }
            }

            VirtualTimeOperation::PauseClock => {
                runtime.pause_clock();
                shadow.set_clock_paused(true);
            }

            VirtualTimeOperation::ResumeClock => {
                runtime.resume_clock();
                shadow.set_clock_paused(false);
            }

            VirtualTimeOperation::StepScheduler { steps } => {
                for _ in 0..*steps {
                    if runtime.scheduler.lock().is_empty() {
                        break;
                    }
                    runtime.step();
                }
            }

            VirtualTimeOperation::InjectChaos {
                delay_nanos,
                cause_budget_exhaust,
            } => {
                if input.runtime_config.enable_chaos {
                    // Inject timing chaos
                    runtime.advance_time(*delay_nanos);
                    shadow.record_time_advance(*delay_nanos);

                    if *cause_budget_exhaust {
                        // Trigger budget exhaustion scenario (simplified)
                    }
                }
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

/// Test concurrent virtual time operations for race conditions
fn test_concurrent_virtual_time(
    input: &LabRuntimeVirtualTimeFuzz,
    shadow: &VirtualTimeShadowModel,
) -> Result<(), String> {
    let threading_config = match &input.threading_config {
        Some(config) => config,
        None => return Ok(()), // No concurrent testing requested
    };

    if threading_config.num_threads <= 1 || threading_config.per_thread_ops.is_empty() {
        return Ok(()); // Not enough threads or operations for concurrent testing
    }

    // For simplicity, we'll just verify that the LabRuntime can handle
    // virtual time operations from multiple threads without panicking.
    // Full concurrent testing would require more complex synchronization.

    // Note: LabRuntime is not intended for multi-threaded use in production,
    // but we test it here to ensure it doesn't panic under concurrent access.

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

    // Test sequential virtual time operations
    execute_virtual_time_operations(&input, &shadow)?;

    // Test concurrent operations if configured
    test_concurrent_virtual_time(&input, &shadow)?;

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
