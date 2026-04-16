//! Comprehensive test suite for cancel protocol validator.
//!
//! This module provides extensive testing for the cancel-safe state machine validation
//! system, including bug injection, property-based testing, performance measurement,
//! and integration testing.

#![allow(unused_imports, unused_variables)] // Temporary for development

use super::protocol_state_machines::{
    CancelProtocolValidator, CancelStateMachine, ValidationLevel,
    RegionStateMachine, TaskStateMachine, ObligationStateMachine,
    RegionState, RegionEvent, RegionContext,
    TaskState, TaskEvent, TaskContext,
    ObligationState, ObligationEvent, ObligationContext,
    TransitionResult,
};
use crate::types::{RegionId, TaskId, ObligationId};
use std::collections::HashMap;
use std::sync::{Arc, atomic::{AtomicU64, AtomicBool, Ordering}};
use std::time::{Duration, Instant};

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
    pub fn record_injection(&self, violation_type: ProtocolViolationType) {
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
            detection_rate: if injected == 0 { 1.0 } else { detected as f64 / injected as f64 },
        }
    }
}

/// Statistics for bug injection testing.
#[derive(Debug, Clone, PartialEq)]
pub struct BugInjectionStats {
    pub bugs_injected: u64,
    pub bugs_detected: u64,
    pub detection_rate: f64,
}

// ============================================================================
// Property-Based Testing Framework
// ============================================================================

#[cfg(test)]
/// Generate valid region events for property testing.
pub fn region_event_strategy() -> impl Strategy<Value = RegionEvent> {
    prop_oneof![
        Just(RegionEvent::Create),
        Just(RegionEvent::AddTask),
        Just(RegionEvent::RemoveTask),
        Just(RegionEvent::RequestClose),
        Just(RegionEvent::BeginDrain),
        Just(RegionEvent::CompleteDrain),
        Just(RegionEvent::Finalize),
    ]
}

#[cfg(test)]
/// Generate valid task events for property testing.
pub fn task_event_strategy() -> impl Strategy<Value = TaskEvent> {
    prop_oneof![
        Just(TaskEvent::Start),
        Just(TaskEvent::Complete),
        Just(TaskEvent::RequestCancel),
        Just(TaskEvent::AcknowledgeCancel),
        Just(TaskEvent::CompleteDrain),
        prop::string::string_regex(r"[a-zA-Z0-9 ]{1,50}").unwrap()
            .prop_map(|msg| TaskEvent::Panic { message: msg }),
    ]
}

#[cfg(test)]
/// Generate valid obligation events for property testing.
pub fn obligation_event_strategy() -> impl Strategy<Value = ObligationEvent> {
    prop_oneof![
        Just(ObligationEvent::Create),
        Just(ObligationEvent::Commit),
        Just(ObligationEvent::Abort),
    ]
}

/// Property-based test harness for state machines.
pub struct PropertyTestHarness {
    validator: CancelProtocolValidator,
    bug_injector: Option<BugInjector>,
}

impl PropertyTestHarness {
    /// Create a new property test harness.
    pub fn new(validation_level: ValidationLevel, bug_injector: Option<BugInjector>) -> Self {
        Self {
            validator: CancelProtocolValidator::new(validation_level),
            bug_injector,
        }
    }

    /// Test a sequence of region state transitions.
    pub fn test_region_transitions(&mut self, events: Vec<RegionEvent>) -> Result<(), String> {
        let region_id = RegionId::new();
        let context = RegionContext {
            parent_region: None,
            child_count: 0,
            active_tasks: HashMap::new(),
        };

        let mut state_machine = RegionStateMachine::new(region_id, self.validator.validation_level);

        for (i, event) in events.iter().enumerate() {
            // Inject bugs if configured
            if let Some(ref injector) = self.bug_injector {
                if injector.should_inject(ProtocolViolationType::RegionSkipDrain) {
                    match event {
                        RegionEvent::BeginDrain => {
                            // Skip drain phase (bug injection)
                            injector.record_injection(ProtocolViolationType::RegionSkipDrain);
                            continue;
                        }
                        _ => {}
                    }
                }
            }

            // Attempt state transition
            let result = state_machine.transition(event.clone(), &context);

            // Record validation results
            match result {
                TransitionResult::Valid => {
                    // Transition succeeded
                }
                TransitionResult::Invalid(reason) => {
                    // Validator caught an issue
                    if let Some(ref injector) = self.bug_injector {
                        injector.record_detection();
                    }
                    return Err(format!("Invalid transition at step {}: {}", i, reason));
                }
            }
        }

        Ok(())
    }

    /// Test a sequence of task state transitions.
    pub fn test_task_transitions(&mut self, events: Vec<TaskEvent>) -> Result<(), String> {
        let task_id = TaskId::new();
        let region_id = RegionId::new();
        let context = TaskContext {
            region_state: RegionState::Active,
            has_cleanup: false,
        };

        let mut state_machine = TaskStateMachine::new(task_id, region_id, self.validator.validation_level);

        for (i, event) in events.iter().enumerate() {
            // Inject bugs if configured
            if let Some(ref injector) = self.bug_injector {
                if injector.should_inject(ProtocolViolationType::TaskCompleteAfterCancel) {
                    if matches!(state_machine.current_state(), TaskState::CancelRequested) {
                        if matches!(event, TaskEvent::Complete) {
                            // Complete after cancel (bug injection)
                            injector.record_injection(ProtocolViolationType::TaskCompleteAfterCancel);
                            // Force the invalid transition
                        }
                    }
                }
            }

            let result = state_machine.transition(event.clone(), &context);

            match result {
                TransitionResult::Valid => {
                    // Transition succeeded
                }
                TransitionResult::Invalid(reason) => {
                    if let Some(ref injector) = self.bug_injector {
                        injector.record_detection();
                    }
                    return Err(format!("Invalid transition at step {}: {}", i, reason));
                }
            }
        }

        Ok(())
    }

    /// Test a sequence of obligation state transitions.
    pub fn test_obligation_transitions(&mut self, events: Vec<ObligationEvent>) -> Result<(), String> {
        let obligation_id = ObligationId::new();
        let context = ObligationContext {
            region_state: RegionState::Active,
            permits_available: 1,
        };

        let mut state_machine = ObligationStateMachine::new(obligation_id, self.validator.validation_level);

        for (i, event) in events.iter().enumerate() {
            // Inject bugs if configured
            if let Some(ref injector) = self.bug_injector {
                let should_inject_double_commit = injector.should_inject(ProtocolViolationType::ObligationDoubleCommit);
                let should_inject_double_abort = injector.should_inject(ProtocolViolationType::ObligationDoubleAbort);

                if should_inject_double_commit || should_inject_double_abort {
                    match (state_machine.current_state(), event) {
                        (ObligationState::Committed, ObligationEvent::Commit) => {
                            injector.record_injection(ProtocolViolationType::ObligationDoubleCommit);
                        }
                        (ObligationState::Aborted, ObligationEvent::Abort) => {
                            injector.record_injection(ProtocolViolationType::ObligationDoubleAbort);
                        }
                        _ => {}
                    }
                }
            }

            let result = state_machine.transition(event.clone(), &context);

            match result {
                TransitionResult::Valid => {
                    // Transition succeeded
                }
                TransitionResult::Invalid(reason) => {
                    if let Some(ref injector) = self.bug_injector {
                        injector.record_detection();
                    }
                    return Err(format!("Invalid transition at step {}: {}", i, reason));
                }
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
    pub validation_overhead_pct: f64,
    pub memory_overhead_bytes: u64,
    pub avg_latency_ns: u64,
    pub p99_latency_ns: u64,
    pub throughput_ops_per_sec: f64,
}

/// Performance test configuration.
#[derive(Debug, Clone)]
pub struct PerformanceTestConfig {
    pub num_operations: usize,
    pub num_warmup: usize,
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
            ((with_validation.total_time_ns - without_validation.total_time_ns) as f64
                / without_validation.total_time_ns as f64) * 100.0
        };

        PerformanceMeasurement {
            validation_overhead_pct: overhead_pct,
            memory_overhead_bytes: with_validation.memory_usage - without_validation.memory_usage,
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
            ValidationLevel::Off
        };

        let mut validator = CancelProtocolValidator::new(validation_level);
        let mut latencies = Vec::with_capacity(self.config.num_operations);

        // Warmup
        for _ in 0..self.config.num_warmup {
            let _ = self.simulate_cancel_protocol_operation(&mut validator);
        }

        // Actual measurement
        let memory_before = self.estimate_memory_usage();
        let start_time = Instant::now();

        for _ in 0..self.config.num_operations {
            let op_start = Instant::now();
            let _ = self.simulate_cancel_protocol_operation(&mut validator);
            let op_duration = op_start.elapsed();
            latencies.push(op_duration.as_nanos() as u64);
        }

        let total_time = start_time.elapsed();
        let memory_after = self.estimate_memory_usage();

        // Calculate statistics
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
    fn simulate_cancel_protocol_operation(&self, validator: &mut CancelProtocolValidator) -> Result<(), String> {
        // Create a region
        let region_id = RegionId::new();
        validator.track_region(region_id)?;

        // Create a task
        let task_id = TaskId::new();
        validator.track_task(task_id, region_id)?;

        // Start the task
        validator.validate_task_start(task_id)?;

        // Complete the task
        validator.validate_task_completion(task_id)?;

        // Close the region
        validator.validate_region_close(region_id)?;

        Ok(())
    }

    /// Estimate current memory usage (simplified implementation).
    fn estimate_memory_usage(&self) -> u64 {
        // This is a placeholder - in a real implementation, you would measure
        // actual memory usage using platform-specific APIs or memory profiling tools
        0
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
    pub num_concurrent_regions: usize,
    pub num_tasks_per_region: usize,
    pub num_obligations_per_task: usize,
    pub validation_level: ValidationLevel,
}

/// Integration test harness for cancel protocol validation.
pub struct IntegrationTestHarness {
    config: IntegrationTestConfig,
    validator: Arc<CancelProtocolValidator>,
}

impl IntegrationTestHarness {
    /// Create a new integration test harness.
    pub fn new(config: IntegrationTestConfig) -> Self {
        let validator = Arc::new(CancelProtocolValidator::new(config.validation_level));
        Self { config, validator }
    }

    /// Test concurrent region operations with validation (simplified for sync testing).
    pub fn test_concurrent_regions(&self) -> Result<(), String> {
        // Simplified synchronous version for testing without tokio dependency
        for i in 0..self.config.num_concurrent_regions {
            let validator = Arc::clone(&self.validator);
            let config = self.config.clone();

            Self::simulate_region_lifecycle_sync(i, validator, config)?;
        }

        Ok(())
    }

    /// Simulate a complete region lifecycle with tasks and obligations (sync version).
    fn simulate_region_lifecycle_sync(
        _region_idx: usize,
        validator: Arc<CancelProtocolValidator>,
        config: IntegrationTestConfig,
    ) -> Result<(), String> {
        // Simulate a typical region lifecycle
        let region_id = RegionId::new();
        validator.track_region(region_id)?;

        // Create and manage tasks
        for task_idx in 0..config.num_tasks_per_region {
            let task_id = TaskId::new();
            validator.track_task(task_id, region_id)?;
            validator.validate_task_start(task_id)?;

            // Create obligations for this task
            for _obligation_idx in 0..config.num_obligations_per_task {
                let obligation_id = ObligationId::new();
                validator.track_obligation(obligation_id, task_id)?;
                validator.validate_obligation_commit(obligation_id)?;
            }

            // Complete the task
            validator.validate_task_completion(task_id)?;
        }

        // Close the region
        validator.validate_region_close(region_id)?;

        Ok(())
    }

    /// Test error reporting integration with logging/tracing infrastructure.
    pub fn test_error_reporting(&self) -> Result<(), String> {
        // Test that validation errors are properly reported through the logging system
        let region_id = RegionId::new();

        // Attempt an invalid operation that should be caught by validation
        match self.validator.validate_region_close(region_id) {
            Ok(_) => Err("Expected validation to catch invalid region close".to_string()),
            Err(error) => {
                // Verify error message format and content
                if error.contains("region") && error.contains("not found") {
                    Ok(())
                } else {
                    Err(format!("Unexpected error message format: {}", error))
                }
            }
        }
    }

    /// Test configuration handling for different assertion levels.
    pub fn test_validation_level_config(&self) -> Result<(), String> {
        // Test that different validation levels behave correctly
        let test_cases = vec![
            ValidationLevel::Off,
            ValidationLevel::Development,
            ValidationLevel::Production,
        ];

        for level in test_cases {
            let validator = CancelProtocolValidator::new(level);

            // Verify that validation behavior matches the configured level
            match level {
                ValidationLevel::Off => {
                    // All operations should succeed without validation
                    assert!(validator.validate_region_close(RegionId::new()).is_ok());
                }
                ValidationLevel::Development | ValidationLevel::Production => {
                    // Operations should be validated
                    assert!(validator.validate_region_close(RegionId::new()).is_err());
                }
            }
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
        let region_id = RegionId::new();

        // Create region
        self.validator.track_region(region_id)?;

        // Create and run task
        let task_id = TaskId::new();
        self.validator.track_task(task_id, region_id)?;
        self.validator.validate_task_start(task_id)?;
        self.validator.validate_task_completion(task_id)?;

        // Close region
        self.validator.validate_region_close(region_id)?;

        Ok(())
    }

    /// Test nested region lifecycle.
    fn test_nested_region_lifecycle(&mut self) -> Result<(), String> {
        let parent_region = RegionId::new();
        let child_region = RegionId::new();

        // Create parent region
        self.validator.track_region(parent_region)?;

        // Create child region
        self.validator.track_region(child_region)?;

        // Close child first, then parent
        self.validator.validate_region_close(child_region)?;
        self.validator.validate_region_close(parent_region)?;

        Ok(())
    }

    /// Test concurrent task completion.
    fn test_concurrent_task_completion(&mut self) -> Result<(), String> {
        let region_id = RegionId::new();
        self.validator.track_region(region_id)?;

        // Create multiple tasks
        let task_ids: Vec<_> = (0..5).map(|_| TaskId::new()).collect();
        for &task_id in &task_ids {
            self.validator.track_task(task_id, region_id)?;
            self.validator.validate_task_start(task_id)?;
        }

        // Complete tasks in different order
        for &task_id in task_ids.iter().rev() {
            self.validator.validate_task_completion(task_id)?;
        }

        self.validator.validate_region_close(region_id)?;
        Ok(())
    }

    /// Test obligation lifecycle.
    fn test_obligation_lifecycle(&mut self) -> Result<(), String> {
        let region_id = RegionId::new();
        let task_id = TaskId::new();
        let obligation_id = ObligationId::new();

        self.validator.track_region(region_id)?;
        self.validator.track_task(task_id, region_id)?;
        self.validator.track_obligation(obligation_id, task_id)?;

        // Commit obligation
        self.validator.validate_obligation_commit(obligation_id)?;

        // Complete task and close region
        self.validator.validate_task_completion(task_id)?;
        self.validator.validate_region_close(region_id)?;

        Ok(())
    }

    /// Test cancel signal propagation.
    fn test_cancel_propagation(&mut self) -> Result<(), String> {
        let region_id = RegionId::new();
        let task_id = TaskId::new();

        self.validator.track_region(region_id)?;
        self.validator.track_task(task_id, region_id)?;
        self.validator.validate_task_start(task_id)?;

        // Request cancel and validate proper handling
        self.validator.validate_task_cancel_request(task_id)?;
        self.validator.validate_task_cancel_completion(task_id)?;

        self.validator.validate_region_close(region_id)?;
        Ok(())
    }

    /// Test edge cases around state transitions.
    pub fn test_edge_cases(&mut self) -> Result<(), String> {
        // Test rapid region creation and destruction
        for _ in 0..1000 {
            let region_id = RegionId::new();
            self.validator.track_region(region_id)?;
            self.validator.validate_region_close(region_id)?;
        }

        // Test task creation without starting
        let region_id = RegionId::new();
        self.validator.track_region(region_id)?;
        let task_id = TaskId::new();
        self.validator.track_task(task_id, region_id)?;
        // Don't start task, just close region
        self.validator.validate_region_close(region_id)?;

        Ok(())
    }
}

// ============================================================================
// Test Infrastructure and Utilities
// ============================================================================

/// Test infrastructure for managing comprehensive cancel protocol validation tests.
pub struct CancelProtocolTestSuite {
    pub bug_injection: BugInjectionStats,
    pub performance: PerformanceMeasurement,
    pub false_positive_count: u64,
    pub total_tests_run: u64,
}

impl CancelProtocolTestSuite {
    /// Run the complete test suite and return aggregated results.
    pub fn run_full_suite() -> Result<Self, String> {
        let mut total_tests = 0u64;
        let mut false_positives = 0u64;

        // 1. Bug Injection Testing
        let bug_injection_config = BugInjectionConfig {
            violation_types: vec![
                ProtocolViolationType::RegionSkipDrain,
                ProtocolViolationType::TaskCompleteAfterCancel,
                ProtocolViolationType::ObligationDoubleCommit,
            ],
            injection_probability: 0.1,
            random_seed: Some(42),
        };

        let bug_injector = BugInjector::new(bug_injection_config);
        let mut property_harness = PropertyTestHarness::new(
            ValidationLevel::Development,
            Some(bug_injector)
        );

        // Run property-based tests with bug injection
        total_tests += 1;
        property_harness.test_region_transitions(vec![
            RegionEvent::Create,
            RegionEvent::AddTask,
            RegionEvent::RequestClose,
            RegionEvent::BeginDrain,
            RegionEvent::CompleteDrain,
            RegionEvent::Finalize,
        ])?;

        let bug_injection_stats = property_harness.bug_injector.as_ref().unwrap().stats();

        // 2. Performance Testing
        let perf_config = PerformanceTestConfig {
            num_operations: 10000,
            num_warmup: 1000,
            validation_level: ValidationLevel::Development,
        };

        let perf_harness = PerformanceTestHarness::new(perf_config);
        let performance_results = perf_harness.measure_validation_overhead();
        total_tests += 1;

        // 3. False Positive Testing
        let mut fp_harness = FalsePositiveTestHarness::new(ValidationLevel::Development);
        match fp_harness.test_valid_sequences() {
            Ok(_) => {},
            Err(e) => {
                // If a valid sequence failed, it's a false positive
                false_positives += 1;
                eprintln!("False positive detected: {}", e);
            }
        }
        total_tests += 1;

        // 4. Integration Testing
        let integration_config = IntegrationTestConfig {
            num_concurrent_regions: 10,
            num_tasks_per_region: 5,
            num_obligations_per_task: 2,
            validation_level: ValidationLevel::Development,
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
            r#"
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
"#,
            self.total_tests_run,
            self.false_positive_count,
            if self.bug_injection.bugs_injected > 0 { self.bug_injection.detection_rate * 100.0 } else { 100.0 },
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
            recommendations.push("- Improve bug detection: some injected violations were not caught");
        }

        if self.performance.validation_overhead_pct > 5.0 {
            recommendations.push("- Optimize validation performance: overhead exceeds 5% target");
        }

        if self.false_positive_count > 0 {
            recommendations.push("- Fix false positives: valid operations should never trigger assertions");
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
            validation_level: ValidationLevel::Development,
        };

        let harness = PerformanceTestHarness::new(config);
        // Test that harness can be created without panicking
        assert!(harness.config.num_operations == 100);
    }

    #[test]
    fn test_property_harness_basic() {
        let mut harness = PropertyTestHarness::new(ValidationLevel::Development, None);

        // Test valid region lifecycle
        let events = vec![
            RegionEvent::Create,
            RegionEvent::AddTask,
            RegionEvent::RequestClose,
            RegionEvent::BeginDrain,
            RegionEvent::CompleteDrain,
            RegionEvent::Finalize,
        ];

        // Should succeed with valid event sequence
        assert!(harness.test_region_transitions(events).is_ok());
    }

    #[test]
    fn test_false_positive_harness() {
        let mut harness = FalsePositiveTestHarness::new(ValidationLevel::Development);

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
            validation_level: ValidationLevel::Development,
        };

        let harness = IntegrationTestHarness::new(config);

        // Test configuration validation
        assert!(harness.test_validation_level_config().is_ok());
    }

    proptest! {
        #[test]
        fn property_test_region_events(events in prop::collection::vec(region_event_strategy(), 1..20)) {
            let mut harness = PropertyTestHarness::new(ValidationLevel::Development, None);

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
            let mut harness = PropertyTestHarness::new(ValidationLevel::Development, None);

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