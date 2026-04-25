//! Comprehensive test suite for cancel protocol validator.
//!
//! This module provides extensive testing for the cancel-safe state machine validation
//! system, including bug injection, property-based testing, performance measurement,
//! and integration testing.

use super::protocol_state_machines::{
    CancelProtocolValidator, CancelStateMachine, ObligationContext, ObligationEvent,
    ObligationStateMachine, RegionContext, RegionEvent, RegionStateMachine, TaskContext, TaskEvent,
    TaskState, TaskStateMachine, TransitionResult, ValidationLevel,
};
use crate::types::{ObligationId, RegionId, TaskId, Time};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

#[cfg(test)]
use proptest::prelude::*;

// ============================================================================
// Bug Injection Testing Framework
// ============================================================================

/// Bug injection configuration for testing validator effectiveness.
#[derive(Debug, Clone)]
pub struct BugInjectionConfig {
    /// Types of protocol violations to inject.
    pub violation_types: Vec<ProtocolViolationType>,
    /// Probability of injecting a bug (0.0 to 1.0).
    pub injection_probability: f64,
    /// Random seed for reproducible bug injection.
    pub random_seed: Option<u64>,
}

/// Types of protocol violations that can be injected for testing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolViolationType {
    /// Skip drain phase in region lifecycle.
    RegionSkipDrain,
    /// Complete task after cancel request.
    TaskCompleteAfterCancel,
    /// Double commit obligation.
    ObligationDoubleCommit,
    /// Double abort obligation.
    ObligationDoubleAbort,
    /// Use channel after close.
    ChannelUseAfterClose,
    /// Invalid state transition.
    InvalidStateTransition,
    /// Resource leak (fail to clean up).
    ResourceLeak,
    /// Race condition in state update.
    StateUpdateRace,
}

/// Bug injection framework for testing cancel protocol violations.
pub struct BugInjector {
    config: BugInjectionConfig,
    injected_bugs: AtomicU64,
    detected_bugs: AtomicU64,
    random_state: AtomicU64,
}

impl BugInjector {
    /// Create a new bug injector with the given configuration.
    pub fn new(config: BugInjectionConfig) -> Self {
        Self {
            random_state: AtomicU64::new(config.random_seed.unwrap_or(42)),
            config,
            injected_bugs: AtomicU64::new(0),
            detected_bugs: AtomicU64::new(0),
        }
    }

    /// Check if a bug should be injected for the given violation type.
    pub fn should_inject(&self, violation_type: ProtocolViolationType) -> bool {
        if !self.config.violation_types.contains(&violation_type) {
            return false;
        }

        // Simple linear congruential generator for reproducible randomness
        let current = self.random_state.load(Ordering::Relaxed);
        let next = current.wrapping_mul(1103515245).wrapping_add(12345);
        self.random_state.store(next, Ordering::Relaxed);

        let probability = (next % 1000) as f64 / 1000.0;
        probability < self.config.injection_probability
    }

    /// Record that a bug was injected.
    pub fn record_injection(&self, _violation_type: ProtocolViolationType) {
        self.injected_bugs.fetch_add(1, Ordering::Relaxed);
    }

    /// Record that a bug was detected by the validator.
    pub fn record_detection(&self) {
        self.detected_bugs.fetch_add(1, Ordering::Relaxed);
    }

    /// Get bug injection statistics.
    pub fn stats(&self) -> BugInjectionStats {
        let injected = self.injected_bugs.load(Ordering::Relaxed);
        let detected = self.detected_bugs.load(Ordering::Relaxed);

        BugInjectionStats {
            bugs_injected: injected,
            bugs_detected: detected,
            detection_rate: if injected == 0 {
                1.0
            } else {
                detected as f64 / injected as f64
            },
        }
    }
}

/// Statistics for bug injection testing.
#[derive(Debug, Clone, PartialEq)]
pub struct BugInjectionStats {
    /// Number of protocol bugs intentionally injected by the harness.
    pub bugs_injected: u64,
    /// Number of injected protocol bugs detected by validation.
    pub bugs_detected: u64,
    /// Fraction of injected bugs detected; `1.0` when no bugs were injected.
    pub detection_rate: f64,
}

// ============================================================================
// Property-Based Testing Framework
// ============================================================================

#[cfg(test)]
/// Generate valid region events for property testing.
pub fn region_event_strategy() -> impl Strategy<Value = RegionEvent> {
    prop_oneof![
        Just(RegionEvent::Activate),
        Just(RegionEvent::TaskSpawned),
        Just(RegionEvent::TaskCompleted),
        Just(RegionEvent::TaskDrained),
        Just(RegionEvent::Cancel {
            reason: "property cancel".to_string(),
        }),
        Just(RegionEvent::FinalizerRegistered),
        Just(RegionEvent::FinalizerStarted),
        Just(RegionEvent::FinalizerCompleted),
        Just(RegionEvent::RequestClose),
    ]
}

#[cfg(test)]
/// Generate valid task events for property testing.
pub fn task_event_strategy() -> impl Strategy<Value = TaskEvent> {
    prop_oneof![
        Just(TaskEvent::Start),
        Just(TaskEvent::Complete),
        Just(TaskEvent::RequestCancel),
        Just(TaskEvent::DrainComplete),
        prop::string::string_regex(r"[a-zA-Z0-9 ]{1,50}")
            .unwrap()
            .prop_map(|msg| TaskEvent::Panic { message: msg }),
    ]
}

#[cfg(test)]
/// Generate valid obligation events for property testing.
pub fn obligation_event_strategy() -> impl Strategy<Value = ObligationEvent> {
    prop_oneof![
        Just(ObligationEvent::Reserve { token: 1 }),
        Just(ObligationEvent::Commit),
        Just(ObligationEvent::Abort {
            reason: "property abort".to_string(),
        }),
    ]
}

/// Property-based test harness for state machines.
pub struct PropertyTestHarness {
    validation_level: ValidationLevel,
    bug_injector: Option<BugInjector>,
}

impl PropertyTestHarness {
    /// Create a new property test harness.
    pub fn new(validation_level: ValidationLevel, bug_injector: Option<BugInjector>) -> Self {
        Self {
            validation_level,
            bug_injector,
        }
    }

    /// Test a sequence of region state transitions.
    pub fn test_region_transitions(&mut self, events: Vec<RegionEvent>) -> Result<(), String> {
        let region_id = RegionId::new_for_test(10, 0);
        let context = RegionContext {
            region_id,
            parent_region: None,
            created_at: Time::ZERO,
            validation_level: self.validation_level,
        };

        let mut state_machine = RegionStateMachine::new(region_id, self.validation_level);

        for (i, event) in events.iter().enumerate() {
            if let Some(ref injector) = self.bug_injector {
                if matches!(event, RegionEvent::TaskDrained)
                    && injector.should_inject(ProtocolViolationType::RegionSkipDrain)
                {
                    injector.record_injection(ProtocolViolationType::RegionSkipDrain);
                    let result = state_machine.transition(RegionEvent::RequestClose, &context);
                    if !result.is_valid() {
                        injector.record_detection();
                        return Err(format!(
                            "Injected skipped-drain violation detected at step {i}: {result:?}"
                        ));
                    }
                }
            }

            let result = state_machine.transition(event.clone(), &context);

            if !result.is_valid() {
                if let Some(ref injector) = self.bug_injector {
                    injector.record_detection();
                }
                return Err(format!("Invalid transition at step {i}: {result:?}"));
            }
        }

        Ok(())
    }

    /// Test a sequence of task state transitions.
    pub fn test_task_transitions(&mut self, events: Vec<TaskEvent>) -> Result<(), String> {
        let task_id = TaskId::new_for_test(20, 0);
        let region_id = RegionId::new_for_test(20, 0);
        let context = TaskContext {
            task_id,
            region_id,
            spawned_at: Time::ZERO,
            validation_level: self.validation_level,
        };

        let mut state_machine = TaskStateMachine::new(task_id, region_id, self.validation_level);

        for (i, event) in events.iter().enumerate() {
            let mut event = event.clone();
            if let Some(ref injector) = self.bug_injector {
                if matches!(state_machine.current_state(), TaskState::CancelRequested)
                    && matches!(event, TaskEvent::DrainComplete)
                    && injector.should_inject(ProtocolViolationType::TaskCompleteAfterCancel)
                {
                    injector.record_injection(ProtocolViolationType::TaskCompleteAfterCancel);
                    event = TaskEvent::Complete;
                }
            }

            let result = state_machine.transition(event, &context);

            if !result.is_valid() {
                if let Some(ref injector) = self.bug_injector {
                    injector.record_detection();
                }
                return Err(format!("Invalid transition at step {i}: {result:?}"));
            }
        }

        Ok(())
    }

    /// Test a sequence of obligation state transitions.
    pub fn test_obligation_transitions(
        &mut self,
        events: Vec<ObligationEvent>,
    ) -> Result<(), String> {
        let obligation_id = ObligationId::new_for_test(30, 0);
        let context = ObligationContext {
            obligation_id,
            region_id: RegionId::new_for_test(30, 0),
            created_at: Time::ZERO,
            validation_level: self.validation_level,
        };

        let mut state_machine = ObligationStateMachine::new(obligation_id, self.validation_level);

        for (i, event) in events.iter().enumerate() {
            let event = event.clone();
            if let Some(ref injector) = self.bug_injector {
                let inject_double_commit = matches!(event, ObligationEvent::Commit)
                    && injector.should_inject(ProtocolViolationType::ObligationDoubleCommit);
                let inject_double_abort = matches!(event, ObligationEvent::Abort { .. })
                    && injector.should_inject(ProtocolViolationType::ObligationDoubleAbort);

                if inject_double_commit || inject_double_abort {
                    let first = state_machine.transition(event.clone(), &context);
                    if !first.is_valid() {
                        injector.record_detection();
                        return Err(format!(
                            "Injected obligation setup failed at step {i}: {first:?}"
                        ));
                    }

                    let injected_kind = if inject_double_commit {
                        ProtocolViolationType::ObligationDoubleCommit
                    } else {
                        ProtocolViolationType::ObligationDoubleAbort
                    };
                    injector.record_injection(injected_kind);

                    let second = state_machine.transition(event, &context);
                    if !second.is_valid() {
                        injector.record_detection();
                        return Err(format!(
                            "Injected duplicate obligation violation detected at step {i}: {second:?}"
                        ));
                    }
                    continue;
                }
            }

            let result = state_machine.transition(event, &context);

            if !result.is_valid() {
                if let Some(ref injector) = self.bug_injector {
                    injector.record_detection();
                }
                return Err(format!("Invalid transition at step {i}: {result:?}"));
            }
        }

        Ok(())
    }
}

// ============================================================================
// Performance Testing Framework
// ============================================================================

/// Performance measurement results.
#[derive(Debug, Clone, PartialEq)]
pub struct PerformanceMeasurement {
    /// Runtime overhead of enabled validation compared with disabled validation.
    pub validation_overhead_pct: f64,
    /// Estimated additional validator memory in bytes.
    pub memory_overhead_bytes: u64,
    /// Average measured operation latency in nanoseconds.
    pub avg_latency_ns: u64,
    /// P99 measured operation latency in nanoseconds.
    pub p99_latency_ns: u64,
    /// Measured validation operations per second.
    pub throughput_ops_per_sec: f64,
}

/// Performance test configuration.
#[derive(Debug, Clone)]
pub struct PerformanceTestConfig {
    /// Number of measured operations after warmup.
    pub num_operations: usize,
    /// Number of unmeasured warmup operations.
    pub num_warmup: usize,
    /// State-machine validation level used for the enabled run.
    pub validation_level: ValidationLevel,
}

/// Performance testing framework for cancel protocol validation.
pub struct PerformanceTestHarness {
    config: PerformanceTestConfig,
}

impl PerformanceTestHarness {
    /// Create a new performance test harness.
    pub fn new(config: PerformanceTestConfig) -> Self {
        Self { config }
    }

    /// Measure validation overhead compared to no validation.
    pub fn measure_validation_overhead(&self) -> PerformanceMeasurement {
        // Measure with validation enabled
        let with_validation = self.run_validation_benchmark(true);

        // Measure with validation disabled
        let without_validation = self.run_validation_benchmark(false);

        let overhead_pct = if without_validation.total_time_ns == 0 {
            0.0
        } else {
            ((with_validation.total_time_ns as f64 - without_validation.total_time_ns as f64)
                / without_validation.total_time_ns as f64)
                * 100.0
        };

        PerformanceMeasurement {
            validation_overhead_pct: overhead_pct,
            memory_overhead_bytes: with_validation
                .memory_usage
                .saturating_sub(without_validation.memory_usage),
            avg_latency_ns: with_validation.avg_latency_ns,
            p99_latency_ns: with_validation.p99_latency_ns,
            throughput_ops_per_sec: with_validation.throughput_ops_per_sec,
        }
    }

    /// Run a validation benchmark.
    fn run_validation_benchmark(&self, enable_validation: bool) -> BenchmarkResult {
        let validation_level = if enable_validation {
            self.config.validation_level
        } else {
            ValidationLevel::None
        };

        let mut validator = CancelProtocolValidator::new(validation_level);
        let mut latencies = Vec::with_capacity(self.config.num_operations);

        // Warmup
        for _ in 0..self.config.num_warmup {
            let _ = self.simulate_cancel_protocol_operation(&mut validator);
        }

        // Actual measurement
        let memory_before = Self::estimate_memory_usage(&validator);
        let start_time = Instant::now();

        for _ in 0..self.config.num_operations {
            let op_start = Instant::now();
            let _ = self.simulate_cancel_protocol_operation(&mut validator);
            let op_duration = op_start.elapsed();
            latencies.push(op_duration.as_nanos() as u64);
        }

        let total_time = start_time.elapsed();
        let memory_after = Self::estimate_memory_usage(&validator);

        if latencies.is_empty() {
            return BenchmarkResult {
                total_time_ns: total_time.as_nanos() as u64,
                memory_usage: memory_after.saturating_sub(memory_before),
                avg_latency_ns: 0,
                p99_latency_ns: 0,
                throughput_ops_per_sec: 0.0,
            };
        }

        latencies.sort_unstable();
        let avg_latency_ns = latencies.iter().sum::<u64>() / latencies.len() as u64;
        let p99_index = (latencies.len() as f64 * 0.99) as usize;
        let p99_latency_ns = latencies[p99_index.min(latencies.len() - 1)];
        let throughput_ops_per_sec = self.config.num_operations as f64 / total_time.as_secs_f64();

        BenchmarkResult {
            total_time_ns: total_time.as_nanos() as u64,
            memory_usage: memory_after.saturating_sub(memory_before),
            avg_latency_ns,
            p99_latency_ns,
            throughput_ops_per_sec,
        }
    }

    /// Simulate a typical cancel protocol operation for benchmarking.
    fn simulate_cancel_protocol_operation(
        &self,
        validator: &mut CancelProtocolValidator,
    ) -> Result<(), String> {
        let region_id = RegionId::new_for_test(40, 0);
        let task_id = TaskId::new_for_test(40, 0);
        let obligation_id = ObligationId::new_for_test(40, 0);

        validator.register_region(region_id);
        validator.register_task(task_id, region_id);
        validator.register_obligation(obligation_id);

        let region_context = RegionContext {
            region_id,
            parent_region: None,
            created_at: Time::ZERO,
            validation_level: self.config.validation_level,
        };
        let task_context = TaskContext {
            task_id,
            region_id,
            spawned_at: Time::ZERO,
            validation_level: self.config.validation_level,
        };
        let obligation_context = ObligationContext {
            obligation_id,
            region_id,
            created_at: Time::ZERO,
            validation_level: self.config.validation_level,
        };

        Self::ensure_valid(validator.validate_region_transition(
            region_id,
            RegionEvent::Activate,
            &region_context,
        ))?;
        Self::ensure_valid(validator.validate_region_transition(
            region_id,
            RegionEvent::TaskSpawned,
            &region_context,
        ))?;
        Self::ensure_valid(validator.validate_task_transition(
            task_id,
            TaskEvent::Start,
            &task_context,
        ))?;
        Self::ensure_valid(validator.validate_obligation_transition(
            obligation_id,
            ObligationEvent::Reserve { token: 40 },
            &obligation_context,
        ))?;
        Self::ensure_valid(validator.validate_obligation_transition(
            obligation_id,
            ObligationEvent::Commit,
            &obligation_context,
        ))?;
        Self::ensure_valid(validator.validate_task_transition(
            task_id,
            TaskEvent::Complete,
            &task_context,
        ))?;
        Self::ensure_valid(validator.validate_region_transition(
            region_id,
            RegionEvent::TaskCompleted,
            &region_context,
        ))?;
        Self::ensure_valid(validator.validate_region_transition(
            region_id,
            RegionEvent::RequestClose,
            &region_context,
        ))?;

        Ok(())
    }

    fn ensure_valid(result: TransitionResult) -> Result<(), String> {
        if result.is_valid() {
            Ok(())
        } else {
            Err(format!("validator transition failed: {result:?}"))
        }
    }

    /// Deterministic lower-bound estimate based on tracked validator records.
    fn estimate_memory_usage(validator: &CancelProtocolValidator) -> u64 {
        let (regions, tasks, obligations, channels, io_ops, timers, _) = validator.stats();
        let bytes = regions * std::mem::size_of::<RegionStateMachine>()
            + tasks * std::mem::size_of::<TaskStateMachine>()
            + obligations * std::mem::size_of::<ObligationStateMachine>()
            + channels * std::mem::size_of::<super::protocol_state_machines::ChannelStateMachine>()
            + io_ops * std::mem::size_of::<super::protocol_state_machines::IoStateMachine>()
            + timers * std::mem::size_of::<super::protocol_state_machines::TimerStateMachine>();
        bytes as u64
    }
}

/// Internal benchmark result structure.
#[derive(Debug, Clone)]
struct BenchmarkResult {
    total_time_ns: u64,
    memory_usage: u64,
    avg_latency_ns: u64,
    p99_latency_ns: u64,
    throughput_ops_per_sec: f64,
}

// ============================================================================
// Integration Testing Framework
// ============================================================================

/// Integration test configuration.
#[derive(Debug, Clone)]
pub struct IntegrationTestConfig {
    /// Number of independent region lifecycles to simulate.
    pub num_concurrent_regions: usize,
    /// Number of tasks to register and complete in each region.
    pub num_tasks_per_region: usize,
    /// Number of obligations to reserve and commit per task.
    pub num_obligations_per_task: usize,
    /// State-machine validation level used by the integration harness.
    pub validation_level: ValidationLevel,
}

/// Integration test harness for cancel protocol validation.
pub struct IntegrationTestHarness {
    config: IntegrationTestConfig,
}

impl IntegrationTestHarness {
    /// Create a new integration test harness.
    pub fn new(config: IntegrationTestConfig) -> Self {
        Self { config }
    }

    /// Test concurrent region operations with validation (simplified for sync testing).
    pub fn test_concurrent_regions(&self) -> Result<(), String> {
        // Simplified synchronous version for testing without tokio dependency
        for i in 0..self.config.num_concurrent_regions {
            let config = self.config.clone();
            Self::simulate_region_lifecycle_sync(i, config)?;
        }

        Ok(())
    }

    /// Simulate a complete region lifecycle with tasks and obligations (sync version).
    fn simulate_region_lifecycle_sync(
        region_idx: usize,
        config: IntegrationTestConfig,
    ) -> Result<(), String> {
        let mut validator = CancelProtocolValidator::new(config.validation_level);
        let region_index = 100 + region_idx as u32;
        let region_id = RegionId::new_for_test(region_index, 0);
        validator.register_region(region_id);

        let region_context = RegionContext {
            region_id,
            parent_region: None,
            created_at: Time::ZERO,
            validation_level: config.validation_level,
        };

        PerformanceTestHarness::ensure_valid(validator.validate_region_transition(
            region_id,
            RegionEvent::Activate,
            &region_context,
        ))?;

        for task_idx in 0..config.num_tasks_per_region {
            let task_id = TaskId::new_for_test(region_index, task_idx as u32);
            validator.register_task(task_id, region_id);

            let task_context = TaskContext {
                task_id,
                region_id,
                spawned_at: Time::ZERO,
                validation_level: config.validation_level,
            };

            PerformanceTestHarness::ensure_valid(validator.validate_region_transition(
                region_id,
                RegionEvent::TaskSpawned,
                &region_context,
            ))?;
            PerformanceTestHarness::ensure_valid(validator.validate_task_transition(
                task_id,
                TaskEvent::Start,
                &task_context,
            ))?;

            for obligation_idx in 0..config.num_obligations_per_task {
                let obligation_id = ObligationId::new_for_test(
                    region_index,
                    (task_idx * config.num_obligations_per_task + obligation_idx) as u32,
                );
                validator.register_obligation(obligation_id);

                let obligation_context = ObligationContext {
                    obligation_id,
                    region_id,
                    created_at: Time::ZERO,
                    validation_level: config.validation_level,
                };

                PerformanceTestHarness::ensure_valid(validator.validate_obligation_transition(
                    obligation_id,
                    ObligationEvent::Reserve {
                        token: 1 + obligation_idx as u64,
                    },
                    &obligation_context,
                ))?;
                PerformanceTestHarness::ensure_valid(validator.validate_obligation_transition(
                    obligation_id,
                    ObligationEvent::Commit,
                    &obligation_context,
                ))?;
            }

            PerformanceTestHarness::ensure_valid(validator.validate_task_transition(
                task_id,
                TaskEvent::Complete,
                &task_context,
            ))?;
            PerformanceTestHarness::ensure_valid(validator.validate_region_transition(
                region_id,
                RegionEvent::TaskCompleted,
                &region_context,
            ))?;
        }

        PerformanceTestHarness::ensure_valid(validator.validate_region_transition(
            region_id,
            RegionEvent::RequestClose,
            &region_context,
        ))?;

        Ok(())
    }

    /// Test error reporting integration with logging/tracing infrastructure.
    pub fn test_error_reporting(&self) -> Result<(), String> {
        let mut validator = CancelProtocolValidator::new(self.config.validation_level);
        let region_id = RegionId::new_for_test(200, 0);
        let context = RegionContext {
            region_id,
            parent_region: None,
            created_at: Time::ZERO,
            validation_level: self.config.validation_level,
        };

        let result =
            validator.validate_region_transition(region_id, RegionEvent::RequestClose, &context);
        match result {
            TransitionResult::Invalid { reason, .. } if reason.contains("not registered") => Ok(()),
            other => Err(format!("unexpected validation result: {other:?}")),
        }
    }

    /// Test configuration handling for different assertion levels.
    pub fn test_validation_level_config(&self) -> Result<(), String> {
        let test_cases = [
            ValidationLevel::None,
            ValidationLevel::Basic,
            ValidationLevel::Full,
            ValidationLevel::Debug,
        ];

        for (idx, level) in test_cases.into_iter().enumerate() {
            Self::simulate_region_lifecycle_sync(
                idx,
                IntegrationTestConfig {
                    num_concurrent_regions: 1,
                    num_tasks_per_region: 1,
                    num_obligations_per_task: 1,
                    validation_level: level,
                },
            )?;
        }

        Ok(())
    }
}

// ============================================================================
// False Positive Detection Framework
// ============================================================================

/// False positive detection test harness.
pub struct FalsePositiveTestHarness {
    validator: CancelProtocolValidator,
}

impl FalsePositiveTestHarness {
    /// Create a new false positive test harness.
    pub fn new(validation_level: ValidationLevel) -> Self {
        Self {
            validator: CancelProtocolValidator::new(validation_level),
        }
    }

    /// Test that valid operation sequences never trigger false positive assertions.
    pub fn test_valid_sequences(&mut self) -> Result<(), String> {
        // Test a variety of valid operation sequences
        let test_sequences = vec![
            self.test_simple_region_lifecycle(),
            self.test_nested_region_lifecycle(),
            self.test_concurrent_task_completion(),
            self.test_obligation_lifecycle(),
            self.test_cancel_propagation(),
        ];

        for (i, result) in test_sequences.into_iter().enumerate() {
            result.map_err(|e| format!("Valid sequence {} failed validation: {}", i, e))?;
        }

        Ok(())
    }

    /// Test simple region create -> use -> close lifecycle.
    fn test_simple_region_lifecycle(&mut self) -> Result<(), String> {
        let region_id = RegionId::new_for_test(300, 0);
        let task_id = TaskId::new_for_test(300, 0);
        let region_context = RegionContext {
            region_id,
            parent_region: None,
            created_at: Time::ZERO,
            validation_level: ValidationLevel::Full,
        };
        let task_context = TaskContext {
            task_id,
            region_id,
            spawned_at: Time::ZERO,
            validation_level: ValidationLevel::Full,
        };

        self.validator.register_region(region_id);
        self.validator.register_task(task_id, region_id);

        PerformanceTestHarness::ensure_valid(self.validator.validate_region_transition(
            region_id,
            RegionEvent::Activate,
            &region_context,
        ))?;
        PerformanceTestHarness::ensure_valid(self.validator.validate_region_transition(
            region_id,
            RegionEvent::TaskSpawned,
            &region_context,
        ))?;
        PerformanceTestHarness::ensure_valid(self.validator.validate_task_transition(
            task_id,
            TaskEvent::Start,
            &task_context,
        ))?;
        PerformanceTestHarness::ensure_valid(self.validator.validate_task_transition(
            task_id,
            TaskEvent::Complete,
            &task_context,
        ))?;
        PerformanceTestHarness::ensure_valid(self.validator.validate_region_transition(
            region_id,
            RegionEvent::TaskCompleted,
            &region_context,
        ))?;
        PerformanceTestHarness::ensure_valid(self.validator.validate_region_transition(
            region_id,
            RegionEvent::RequestClose,
            &region_context,
        ))?;

        Ok(())
    }

    /// Test nested region lifecycle.
    fn test_nested_region_lifecycle(&mut self) -> Result<(), String> {
        let parent_region = RegionId::new_for_test(301, 0);
        let child_region = RegionId::new_for_test(301, 1);
        let parent_context = RegionContext {
            region_id: parent_region,
            parent_region: None,
            created_at: Time::ZERO,
            validation_level: ValidationLevel::Full,
        };
        let child_context = RegionContext {
            region_id: child_region,
            parent_region: Some(parent_region),
            created_at: Time::ZERO,
            validation_level: ValidationLevel::Full,
        };

        self.validator.register_region(parent_region);
        self.validator.register_region(child_region);

        for (region_id, context) in [
            (parent_region, &parent_context),
            (child_region, &child_context),
        ] {
            PerformanceTestHarness::ensure_valid(self.validator.validate_region_transition(
                region_id,
                RegionEvent::Activate,
                context,
            ))?;
        }
        for (region_id, context) in [
            (child_region, &child_context),
            (parent_region, &parent_context),
        ] {
            PerformanceTestHarness::ensure_valid(self.validator.validate_region_transition(
                region_id,
                RegionEvent::RequestClose,
                context,
            ))?;
        }

        Ok(())
    }

    /// Test concurrent task completion.
    fn test_concurrent_task_completion(&mut self) -> Result<(), String> {
        let region_id = RegionId::new_for_test(302, 0);
        let region_context = RegionContext {
            region_id,
            parent_region: None,
            created_at: Time::ZERO,
            validation_level: ValidationLevel::Full,
        };
        self.validator.register_region(region_id);
        PerformanceTestHarness::ensure_valid(self.validator.validate_region_transition(
            region_id,
            RegionEvent::Activate,
            &region_context,
        ))?;

        let task_ids: Vec<_> = (0..5).map(|idx| TaskId::new_for_test(302, idx)).collect();
        for &task_id in &task_ids {
            let task_context = TaskContext {
                task_id,
                region_id,
                spawned_at: Time::ZERO,
                validation_level: ValidationLevel::Full,
            };
            self.validator.register_task(task_id, region_id);
            PerformanceTestHarness::ensure_valid(self.validator.validate_region_transition(
                region_id,
                RegionEvent::TaskSpawned,
                &region_context,
            ))?;
            PerformanceTestHarness::ensure_valid(self.validator.validate_task_transition(
                task_id,
                TaskEvent::Start,
                &task_context,
            ))?;
        }

        for &task_id in task_ids.iter().rev() {
            let task_context = TaskContext {
                task_id,
                region_id,
                spawned_at: Time::ZERO,
                validation_level: ValidationLevel::Full,
            };
            PerformanceTestHarness::ensure_valid(self.validator.validate_task_transition(
                task_id,
                TaskEvent::Complete,
                &task_context,
            ))?;
            PerformanceTestHarness::ensure_valid(self.validator.validate_region_transition(
                region_id,
                RegionEvent::TaskCompleted,
                &region_context,
            ))?;
        }

        PerformanceTestHarness::ensure_valid(self.validator.validate_region_transition(
            region_id,
            RegionEvent::RequestClose,
            &region_context,
        ))?;
        Ok(())
    }

    /// Test obligation lifecycle.
    fn test_obligation_lifecycle(&mut self) -> Result<(), String> {
        let region_id = RegionId::new_for_test(303, 0);
        let task_id = TaskId::new_for_test(303, 0);
        let obligation_id = ObligationId::new_for_test(303, 0);
        let region_context = RegionContext {
            region_id,
            parent_region: None,
            created_at: Time::ZERO,
            validation_level: ValidationLevel::Full,
        };
        let task_context = TaskContext {
            task_id,
            region_id,
            spawned_at: Time::ZERO,
            validation_level: ValidationLevel::Full,
        };
        let obligation_context = ObligationContext {
            obligation_id,
            region_id,
            created_at: Time::ZERO,
            validation_level: ValidationLevel::Full,
        };

        self.validator.register_region(region_id);
        self.validator.register_task(task_id, region_id);
        self.validator.register_obligation(obligation_id);

        PerformanceTestHarness::ensure_valid(self.validator.validate_region_transition(
            region_id,
            RegionEvent::Activate,
            &region_context,
        ))?;
        PerformanceTestHarness::ensure_valid(self.validator.validate_region_transition(
            region_id,
            RegionEvent::TaskSpawned,
            &region_context,
        ))?;
        PerformanceTestHarness::ensure_valid(self.validator.validate_task_transition(
            task_id,
            TaskEvent::Start,
            &task_context,
        ))?;
        PerformanceTestHarness::ensure_valid(self.validator.validate_obligation_transition(
            obligation_id,
            ObligationEvent::Reserve { token: 303 },
            &obligation_context,
        ))?;
        PerformanceTestHarness::ensure_valid(self.validator.validate_obligation_transition(
            obligation_id,
            ObligationEvent::Commit,
            &obligation_context,
        ))?;
        PerformanceTestHarness::ensure_valid(self.validator.validate_task_transition(
            task_id,
            TaskEvent::Complete,
            &task_context,
        ))?;
        PerformanceTestHarness::ensure_valid(self.validator.validate_region_transition(
            region_id,
            RegionEvent::TaskCompleted,
            &region_context,
        ))?;
        PerformanceTestHarness::ensure_valid(self.validator.validate_region_transition(
            region_id,
            RegionEvent::RequestClose,
            &region_context,
        ))?;

        Ok(())
    }

    /// Test cancel signal propagation.
    fn test_cancel_propagation(&mut self) -> Result<(), String> {
        let region_id = RegionId::new_for_test(304, 0);
        let task_id = TaskId::new_for_test(304, 0);
        let region_context = RegionContext {
            region_id,
            parent_region: None,
            created_at: Time::ZERO,
            validation_level: ValidationLevel::Full,
        };
        let task_context = TaskContext {
            task_id,
            region_id,
            spawned_at: Time::ZERO,
            validation_level: ValidationLevel::Full,
        };

        self.validator.register_region(region_id);
        self.validator.register_task(task_id, region_id);

        PerformanceTestHarness::ensure_valid(self.validator.validate_region_transition(
            region_id,
            RegionEvent::Activate,
            &region_context,
        ))?;
        PerformanceTestHarness::ensure_valid(self.validator.validate_region_transition(
            region_id,
            RegionEvent::TaskSpawned,
            &region_context,
        ))?;
        PerformanceTestHarness::ensure_valid(self.validator.validate_task_transition(
            task_id,
            TaskEvent::Start,
            &task_context,
        ))?;
        PerformanceTestHarness::ensure_valid(self.validator.validate_region_transition(
            region_id,
            RegionEvent::Cancel {
                reason: "test cancel".to_string(),
            },
            &region_context,
        ))?;
        PerformanceTestHarness::ensure_valid(self.validator.validate_task_transition(
            task_id,
            TaskEvent::RequestCancel,
            &task_context,
        ))?;
        PerformanceTestHarness::ensure_valid(self.validator.validate_task_transition(
            task_id,
            TaskEvent::DrainComplete,
            &task_context,
        ))?;
        PerformanceTestHarness::ensure_valid(self.validator.validate_region_transition(
            region_id,
            RegionEvent::TaskDrained,
            &region_context,
        ))?;
        Ok(())
    }

    /// Test edge cases around state transitions.
    pub fn test_edge_cases(&mut self) -> Result<(), String> {
        for idx in 0..100 {
            let region_id = RegionId::new_for_test(400, idx);
            let context = RegionContext {
                region_id,
                parent_region: None,
                created_at: Time::ZERO,
                validation_level: ValidationLevel::Full,
            };
            self.validator.register_region(region_id);
            PerformanceTestHarness::ensure_valid(self.validator.validate_region_transition(
                region_id,
                RegionEvent::Activate,
                &context,
            ))?;
            PerformanceTestHarness::ensure_valid(self.validator.validate_region_transition(
                region_id,
                RegionEvent::RequestClose,
                &context,
            ))?;
        }

        let region_id = RegionId::new_for_test(401, 0);
        let task_id = TaskId::new_for_test(401, 0);
        let context = RegionContext {
            region_id,
            parent_region: None,
            created_at: Time::ZERO,
            validation_level: ValidationLevel::Full,
        };
        self.validator.register_region(region_id);
        self.validator.register_task(task_id, region_id);
        PerformanceTestHarness::ensure_valid(self.validator.validate_region_transition(
            region_id,
            RegionEvent::Activate,
            &context,
        ))?;
        PerformanceTestHarness::ensure_valid(self.validator.validate_region_transition(
            region_id,
            RegionEvent::RequestClose,
            &context,
        ))?;

        Ok(())
    }
}

// ============================================================================
// Test Infrastructure and Utilities
// ============================================================================

/// Test infrastructure for managing comprehensive cancel protocol validation tests.
pub struct CancelProtocolTestSuite {
    /// Aggregated bug-injection detection metrics.
    pub bug_injection: BugInjectionStats,
    /// Aggregated validation benchmark metrics.
    pub performance: PerformanceMeasurement,
    /// Number of valid sequences incorrectly rejected by the validator.
    pub false_positive_count: u64,
    /// Number of top-level harness phases executed.
    pub total_tests_run: u64,
}

impl CancelProtocolTestSuite {
    /// Run the complete test suite and return aggregated results.
    pub fn run_full_suite() -> Result<Self, String> {
        let mut total_tests = 0u64;
        let false_positives = 0u64;

        // 1. Bug Injection Testing
        let bug_injection_config = BugInjectionConfig {
            violation_types: vec![
                ProtocolViolationType::RegionSkipDrain,
                ProtocolViolationType::TaskCompleteAfterCancel,
                ProtocolViolationType::ObligationDoubleCommit,
            ],
            injection_probability: 1.0,
            random_seed: Some(42),
        };

        let bug_injector = BugInjector::new(bug_injection_config);
        let mut property_harness =
            PropertyTestHarness::new(ValidationLevel::Full, Some(bug_injector));

        // Run property-based tests with bug injection
        total_tests += 1;
        let _ = property_harness.test_task_transitions(vec![
            TaskEvent::Start,
            TaskEvent::RequestCancel,
            TaskEvent::DrainComplete,
        ]);

        let _ = property_harness.test_obligation_transitions(vec![
            ObligationEvent::Reserve { token: 1 },
            ObligationEvent::Commit,
        ]);

        let bug_injection_stats = property_harness.bug_injector.as_ref().unwrap().stats();
        if bug_injection_stats.bugs_injected != bug_injection_stats.bugs_detected {
            return Err(format!(
                "bug injection detection mismatch: injected={}, detected={}",
                bug_injection_stats.bugs_injected, bug_injection_stats.bugs_detected
            ));
        }

        // 2. Performance Testing
        let perf_config = PerformanceTestConfig {
            num_operations: 256,
            num_warmup: 32,
            validation_level: ValidationLevel::Full,
        };

        let perf_harness = PerformanceTestHarness::new(perf_config);
        let performance_results = perf_harness.measure_validation_overhead();
        total_tests += 1;

        // 3. False Positive Testing
        let mut fp_harness = FalsePositiveTestHarness::new(ValidationLevel::Full);
        match fp_harness.test_valid_sequences() {
            Ok(_) => {}
            Err(e) => {
                return Err(format!("false positive detected: {e}"));
            }
        }
        total_tests += 1;

        // 4. Integration Testing
        let integration_config = IntegrationTestConfig {
            num_concurrent_regions: 10,
            num_tasks_per_region: 5,
            num_obligations_per_task: 2,
            validation_level: ValidationLevel::Full,
        };

        let integration_harness = IntegrationTestHarness::new(integration_config);
        integration_harness.test_error_reporting()?;
        integration_harness.test_validation_level_config()?;
        total_tests += 2;

        Ok(Self {
            bug_injection: bug_injection_stats,
            performance: performance_results,
            false_positive_count: false_positives,
            total_tests_run: total_tests,
        })
    }

    /// Generate a comprehensive test report.
    pub fn generate_report(&self) -> String {
        format!(
            r"
# Cancel Protocol Validator Test Suite Results

## Summary
- Total tests run: {}
- False positives: {}
- Bug detection rate: {:.2}%

## Bug Injection Testing
- Bugs injected: {}
- Bugs detected: {}
- Detection rate: {:.2}%

## Performance Testing
- Validation overhead: {:.2}%
- Memory overhead: {} bytes
- Average latency: {} ns
- P99 latency: {} ns
- Throughput: {:.0} ops/sec

## Performance Targets
- Debug overhead target: <5% (actual: {:.2}%)
- Production overhead target: <0.1% (estimated from debug)
- Memory overhead: acceptable if <1MB per 1000 entities

## Recommendations
{}
",
            self.total_tests_run,
            self.false_positive_count,
            if self.bug_injection.bugs_injected > 0 {
                self.bug_injection.detection_rate * 100.0
            } else {
                100.0
            },
            self.bug_injection.bugs_injected,
            self.bug_injection.bugs_detected,
            self.bug_injection.detection_rate * 100.0,
            self.performance.validation_overhead_pct,
            self.performance.memory_overhead_bytes,
            self.performance.avg_latency_ns,
            self.performance.p99_latency_ns,
            self.performance.throughput_ops_per_sec,
            self.performance.validation_overhead_pct,
            self.generate_recommendations()
        )
    }

    /// Generate recommendations based on test results.
    fn generate_recommendations(&self) -> String {
        let mut recommendations = Vec::new();

        if self.bug_injection.detection_rate < 1.0 {
            recommendations
                .push("- Improve bug detection: some injected violations were not caught");
        }

        if self.performance.validation_overhead_pct > 5.0 {
            recommendations.push("- Optimize validation performance: overhead exceeds 5% target");
        }

        if self.false_positive_count > 0 {
            recommendations
                .push("- Fix false positives: valid operations should never trigger assertions");
        }

        if self.performance.memory_overhead_bytes > 1024 * 1024 {
            recommendations.push("- Optimize memory usage: overhead exceeds 1MB guidelines");
        }

        if recommendations.is_empty() {
            recommendations.push("- All tests passed within acceptable parameters");
        }

        recommendations.join("\n")
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    #[test]
    fn test_bug_injector_creation() {
        let config = BugInjectionConfig {
            violation_types: vec![ProtocolViolationType::RegionSkipDrain],
            injection_probability: 0.5,
            random_seed: Some(42),
        };

        let injector = BugInjector::new(config);
        let stats = injector.stats();

        assert_eq!(stats.bugs_injected, 0);
        assert_eq!(stats.bugs_detected, 0);
        assert_eq!(stats.detection_rate, 1.0);
    }

    #[test]
    fn test_performance_harness_creation() {
        let config = PerformanceTestConfig {
            num_operations: 100,
            num_warmup: 10,
            validation_level: ValidationLevel::Full,
        };

        let harness = PerformanceTestHarness::new(config);
        // Test that harness can be created without panicking
        assert!(harness.config.num_operations == 100);
    }

    #[test]
    fn test_property_harness_basic() {
        let mut harness = PropertyTestHarness::new(ValidationLevel::Full, None);

        // Test valid region lifecycle
        let events = vec![
            RegionEvent::Activate,
            RegionEvent::TaskSpawned,
            RegionEvent::TaskCompleted,
            RegionEvent::RequestClose,
        ];

        // Should succeed with valid event sequence
        assert!(harness.test_region_transitions(events).is_ok());
    }

    #[test]
    fn test_false_positive_harness() {
        let mut harness = FalsePositiveTestHarness::new(ValidationLevel::Full);

        // Valid sequences should never fail
        assert!(harness.test_simple_region_lifecycle().is_ok());
        assert!(harness.test_edge_cases().is_ok());
    }

    #[test]
    fn test_integration_harness_config() {
        let config = IntegrationTestConfig {
            num_concurrent_regions: 5,
            num_tasks_per_region: 3,
            num_obligations_per_task: 1,
            validation_level: ValidationLevel::Full,
        };

        let harness = IntegrationTestHarness::new(config);

        // Test configuration validation
        assert!(harness.test_validation_level_config().is_ok());
    }

    proptest! {
        #[test]
        fn property_test_region_events(events in prop::collection::vec(region_event_strategy(), 1..20)) {
            let mut harness = PropertyTestHarness::new(ValidationLevel::Full, None);

            // Property: any sequence of valid events should either succeed or fail gracefully
            let result = harness.test_region_transitions(events);

            // We don't require all sequences to succeed (some may be invalid),
            // but they should never panic or return malformed errors
            match result {
                Ok(_) => {
                    // Valid sequence succeeded
                }
                Err(error) => {
                    // Invalid sequence was properly rejected
                    assert!(!error.is_empty(), "Error messages should not be empty");
                    assert!(error.len() < 1000, "Error messages should be reasonable length");
                }
            }
        }

        #[test]
        fn property_test_task_events(events in prop::collection::vec(task_event_strategy(), 1..15)) {
            let mut harness = PropertyTestHarness::new(ValidationLevel::Full, None);

            let result = harness.test_task_transitions(events);

            match result {
                Ok(_) => {
                    // Valid sequence
                }
                Err(error) => {
                    // Invalid sequence properly caught
                    assert!(!error.is_empty());
                }
            }
        }
    }
}
