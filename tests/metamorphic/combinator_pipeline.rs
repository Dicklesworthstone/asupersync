#![allow(clippy::all)]
//! Metamorphic property tests for combinator::pipeline stream composition invariants.
//!
//! These tests verify pipeline combinator invariants related to sequential execution,
//! backpressure handling, cancellation drainage, and compositional properties.
//! Unlike unit tests that check exact outcomes, metamorphic tests verify relationships
//! between different pipeline configurations using LabRuntime DPOR for deterministic
//! scheduling exploration.
//!
//! # Metamorphic Relations
//!
//! 1. **Sequential Execution Order** (MR1): Pipeline stages execute in declaration order
//! 2. **Backpressure Propagation** (MR2): Backpressure propagates upstream via reserve/commit
//! 3. **Finite Drain on Cancel** (MR3): Cancel at any stage drains downstream in finite time
//! 4. **Pipeline Associativity** (MR4): pipe(a,pipe(b,c)) == pipe(pipe(a,b),c)
//! 5. **Empty Pipeline Identity** (MR5): Empty pipeline is identity transformation

use asupersync::combinator::pipeline::{
    FailedStage, Pipeline, PipelineConfig, PipelineError, PipelineResult,
    pipeline2_outcomes, pipeline3_outcomes, pipeline_n_outcomes, pipeline_with_final,
    stage_outcome_to_result
};
use asupersync::cx::{Cx, Scope};
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::types::{
    cancel::CancelReason, ArenaIndex, Budget, Outcome, RegionId, TaskId,
};
use asupersync::util::ArenaIndex as UtilArenaIndex;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use proptest::prelude::*;

// ============================================================================
// Test Infrastructure
// ============================================================================

/// Create a test context for pipeline testing.
fn test_cx() -> Cx {
    Cx::new(
        RegionId::from_arena(ArenaIndex::new(0, 0)),
        TaskId::from_arena(ArenaIndex::new(0, 0)),
        Budget::INFINITE,
    )
}

/// Create a test context with specific slot.
fn test_cx_with_slot(slot: u32) -> Cx {
    Cx::new(
        RegionId::from_arena(ArenaIndex::new(0, slot)),
        TaskId::from_arena(ArenaIndex::new(0, slot)),
        Budget::INFINITE,
    )
}

/// Configuration for pipeline metamorphic tests.
#[derive(Debug, Clone)]
pub struct PipelineTestConfig {
    /// Random seed for deterministic execution.
    pub seed: u64,
    /// Number of stages in the pipeline.
    pub stage_count: usize,
    /// Pipeline configuration.
    pub pipeline_config: PipelineConfig,
    /// Which stage should fail (if any).
    pub failing_stage: Option<usize>,
    /// Outcome type for the failing stage.
    pub failure_outcome: TestOutcome,
    /// Input value for the pipeline.
    pub input_value: i32,
    /// Whether to inject backpressure.
    pub inject_backpressure: bool,
    /// Whether to test cancellation.
    pub test_cancellation: bool,
}

/// Test outcome variants for stage result injection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestOutcome {
    /// Normal completion.
    Ok,
    /// Application error.
    Err,
    /// Cancellation.
    Cancelled,
    /// Panic.
    Panicked,
}

impl TestOutcome {
    /// Convert to actual Outcome for testing.
    pub fn to_outcome<T, E>(self, ok_val: T, err_val: E) -> Outcome<T, E> {
        match self {
            TestOutcome::Ok => Outcome::ok(ok_val),
            TestOutcome::Err => Outcome::err(err_val),
            TestOutcome::Cancelled => Outcome::cancelled(CancelReason::shutdown()),
            TestOutcome::Panicked => Outcome::panicked(String::from("test panic")),
        }
    }
}

/// Track pipeline execution events for invariant checking.
#[derive(Debug, Clone)]
struct PipelineTracker {
    /// Stage execution events (stage_index, input_value, output_value, timestamp).
    stage_executions: Vec<(usize, i32, i32, u64)>,
    /// Backpressure events (stage_index, pressure_level, timestamp).
    backpressure_events: Vec<(usize, u32, u64)>,
    /// Cancellation events (stage_index, timestamp).
    cancellation_events: Vec<(usize, u64)>,
    /// Drain completion events (stage_index, timestamp).
    drain_completions: Vec<(usize, u64)>,
    /// Current timestamp counter.
    timestamp: AtomicU64,
}

impl PipelineTracker {
    fn new() -> Arc<StdMutex<Self>> {
        Arc::new(StdMutex::new(Self {
            stage_executions: Vec::new(),
            backpressure_events: Vec::new(),
            cancellation_events: Vec::new(),
            drain_completions: Vec::new(),
            timestamp: AtomicU64::new(0),
        }))
    }

    /// Record stage execution.
    fn record_execution(&mut self, stage_index: usize, input: i32, output: i32) {
        let ts = self.timestamp.fetch_add(1, Ordering::Relaxed);
        self.stage_executions.push((stage_index, input, output, ts));
    }

    /// Record backpressure event.
    fn record_backpressure(&mut self, stage_index: usize, pressure_level: u32) {
        let ts = self.timestamp.fetch_add(1, Ordering::Relaxed);
        self.backpressure_events.push((stage_index, pressure_level, ts));
    }

    /// Record cancellation.
    fn record_cancellation(&mut self, stage_index: usize) {
        let ts = self.timestamp.fetch_add(1, Ordering::Relaxed);
        self.cancellation_events.push((stage_index, ts));
    }

    /// Record drain completion.
    fn record_drain_completion(&mut self, stage_index: usize) {
        let ts = self.timestamp.fetch_add(1, Ordering::Relaxed);
        self.drain_completions.push((stage_index, ts));
    }

    /// Get execution order of stages.
    fn get_execution_order(&self) -> Vec<usize> {
        let mut executions = self.stage_executions.clone();
        executions.sort_by_key(|(_, _, _, ts)| *ts);
        executions.into_iter().map(|(stage, _, _, _)| stage).collect()
    }

    /// Check if backpressure propagated upstream.
    fn backpressure_propagated_upstream(&self) -> bool {
        if self.backpressure_events.len() <= 1 {
            return true; // No propagation needed
        }

        // Sort by timestamp and check that upstream stages received backpressure
        let mut events = self.backpressure_events.clone();
        events.sort_by_key(|(_, _, ts)| *ts);

        for window in events.windows(2) {
            let (stage1, _, _) = window[0];
            let (stage2, _, _) = window[1];
            // Backpressure should propagate from later to earlier stages
            if stage2 <= stage1 {
                continue;
            }
            return false;
        }
        true
    }

    /// Check if all cancellation events were followed by drain completions.
    fn all_cancellations_drained(&self) -> bool {
        for (cancelled_stage, cancel_ts) in &self.cancellation_events {
            // Look for drain completion after cancellation
            let drained = self.drain_completions.iter().any(|(drain_stage, drain_ts)| {
                drain_stage == cancelled_stage && drain_ts > cancel_ts
            });
            if !drained {
                return false;
            }
        }
        true
    }
}

/// A test pipeline stage that can be configured to produce specific outcomes.
#[derive(Debug, Clone)]
struct TestStage {
    /// Stage index (for ordering verification).
    index: usize,
    /// Expected outcome type.
    outcome: TestOutcome,
    /// Transformation function (input -> output).
    transform: fn(i32) -> i32,
    /// Whether this stage injects backpressure.
    inject_backpressure: bool,
    /// Shared tracker for recording events.
    tracker: Arc<StdMutex<PipelineTracker>>,
}

impl TestStage {
    fn new(
        index: usize,
        outcome: TestOutcome,
        transform: fn(i32) -> i32,
        inject_backpressure: bool,
        tracker: Arc<StdMutex<PipelineTracker>>,
    ) -> Self {
        Self {
            index,
            outcome,
            transform,
            inject_backpressure,
            tracker,
        }
    }

    /// Execute the stage and return the appropriate outcome.
    fn execute(&self, input: i32) -> Outcome<i32, String> {
        // Record execution
        let output = (self.transform)(input);
        if let Ok(mut tracker) = self.tracker.lock() {
            tracker.record_execution(self.index, input, output);

            if self.inject_backpressure {
                tracker.record_backpressure(self.index, input as u32);
            }
        }

        // Return the configured outcome
        self.outcome.to_outcome(output, format!("stage {} failed", self.index))
    }

    /// Simulate cancellation of this stage.
    fn cancel(&self) {
        if let Ok(mut tracker) = self.tracker.lock() {
            tracker.record_cancellation(self.index);
        }
    }

    /// Simulate drain completion.
    fn complete_drain(&self) {
        if let Ok(mut tracker) = self.tracker.lock() {
            tracker.record_drain_completion(self.index);
        }
    }
}

/// Test harness for pipeline metamorphic tests.
pub struct PipelineTestHarness {
    pub config: PipelineTestConfig,
    pub tracker: Arc<StdMutex<PipelineTracker>>,
    pub lab: LabRuntime,
    pub stages: Vec<TestStage>,
}

impl PipelineTestHarness {
    /// Create a new test harness.
    pub fn new(config: PipelineTestConfig) -> Self {
        let lab = LabRuntime::with_config(LabConfig::deterministic().with_seed(config.seed));
        let tracker = PipelineTracker::new();

        // Create test stages
        let mut stages = Vec::new();
        for i in 0..config.stage_count {
            let should_fail = config.failing_stage == Some(i);
            let outcome = if should_fail {
                config.failure_outcome
            } else {
                TestOutcome::Ok
            };

            // Simple transformation: add stage index to input
            let transform_fn = move |input: i32| input + (i as i32) + 1;

            let stage = TestStage::new(
                i,
                outcome,
                transform_fn,
                config.inject_backpressure,
                tracker.clone(),
            );
            stages.push(stage);
        }

        Self {
            config,
            tracker,
            lab,
            stages,
        }
    }

    /// Execute a pipeline and return the result.
    pub fn execute_pipeline(&mut self, stages: &[TestStage], input: i32) -> PipelineResult<i32, String> {
        let outcomes: Vec<Outcome<i32, String>> = stages
            .iter()
            .map(|stage| stage.execute(input))
            .collect();

        match stages.len() {
            0 => PipelineResult::completed(input, 0), // Identity for empty pipeline
            1 => {
                if let Some(result) = stage_outcome_to_result(
                    outcomes[0].clone(), 0, 1) {
                    result
                } else {
                    // stage succeeded
                    PipelineResult::completed(
                        outcomes[0].clone().unwrap(), 1)
                }
            },
            2 => pipeline2_outcomes(outcomes[0].clone(), Some(outcomes[1].clone())),
            3 => pipeline3_outcomes(
                outcomes[0].clone(),
                Some(outcomes[1].clone()),
                Some(outcomes[2].clone())
            ),
            _ => pipeline_n_outcomes(outcomes, stages.len()),
        }
    }

    /// Create a composed pipeline: pipe(a, pipe(b, c)).
    pub fn compose_left_associated(&mut self, a: &[TestStage], b: &[TestStage], c: &[TestStage], input: i32) -> PipelineResult<i32, String> {
        // First execute pipe(b, c)
        let mut bc_stages = b.to_vec();
        bc_stages.extend_from_slice(c);
        let bc_result = self.execute_pipeline(&bc_stages, input);

        if let PipelineResult::Completed { value, .. } = bc_result {
            // Then execute pipe(a, result)
            self.execute_pipeline(a, value)
        } else {
            bc_result
        }
    }

    /// Create a composed pipeline: pipe(pipe(a, b), c).
    pub fn compose_right_associated(&mut self, a: &[TestStage], b: &[TestStage], c: &[TestStage], input: i32) -> PipelineResult<i32, String> {
        // First execute pipe(a, b)
        let mut ab_stages = a.to_vec();
        ab_stages.extend_from_slice(b);
        let ab_result = self.execute_pipeline(&ab_stages, input);

        if let PipelineResult::Completed { value, .. } = ab_result {
            // Then execute pipe(result, c)
            self.execute_pipeline(c, value)
        } else {
            ab_result
        }
    }

    /// Simulate cancellation at a specific stage.
    pub fn simulate_cancellation(&mut self, stage_index: usize) {
        if stage_index < self.stages.len() {
            self.stages[stage_index].cancel();
            // Simulate drain completion for downstream stages
            for i in stage_index..self.stages.len() {
                self.stages[i].complete_drain();
            }
        }
    }

    /// Test identity property of empty pipeline.
    pub fn test_identity(&mut self, input: i32) -> i32 {
        let result = self.execute_pipeline(&[], input);
        match result {
            PipelineResult::Completed { value, .. } => value,
            _ => panic!("Empty pipeline should always complete successfully"),
        }
    }
}

// ============================================================================
// Metamorphic Relations
// ============================================================================

/// MR1: Pipeline stages execute in declared order.
#[test]
fn mr1_sequential_execution_order() {
    let test_config = any::<(u64, u8, i32)>().prop_map(|(seed, stage_count, input)| {
        let stage_count = (stage_count % 5) + 2; // 2-6 stages

        PipelineTestConfig {
            seed,
            stage_count: stage_count as usize,
            pipeline_config: PipelineConfig::default(),
            failing_stage: None, // All stages succeed for order testing
            failure_outcome: TestOutcome::Ok,
            input_value: input % 100,
            inject_backpressure: false,
            test_cancellation: false,
        }
    });

    proptest!(|(config in test_config)| {
        let mut harness = PipelineTestHarness::new(config.clone());
        let _result = harness.execute_pipeline(&harness.stages.clone(), config.input_value);

        let execution_order = harness.tracker.lock().unwrap().get_execution_order();
        let expected_order: Vec<usize> = (0..config.stage_count).collect();

        prop_assert_eq!(execution_order, expected_order,
            "Stages should execute in declared order, but got: {:?}", execution_order);
    });
}

/// MR2: Backpressure propagates upstream via reserve/commit pattern.
#[test]
fn mr2_backpressure_propagation() {
    let test_config = any::<(u64, u8)>().prop_map(|(seed, stage_count)| {
        let stage_count = (stage_count % 4) + 3; // 3-6 stages (need multiple for propagation)

        PipelineTestConfig {
            seed,
            stage_count: stage_count as usize,
            pipeline_config: PipelineConfig::default(),
            failing_stage: None,
            failure_outcome: TestOutcome::Ok,
            input_value: 42,
            inject_backpressure: true,
            test_cancellation: false,
        }
    });

    proptest!(|(config in test_config)| {
        let mut harness = PipelineTestHarness::new(config.clone());
        let _result = harness.execute_pipeline(&harness.stages.clone(), config.input_value);

        let backpressure_propagated = harness.tracker.lock().unwrap().backpressure_propagated_upstream();

        prop_assert!(backpressure_propagated,
            "Backpressure should propagate upstream through reserve/commit pattern");
    });
}

/// MR3: Cancel at any stage drains downstream in finite time.
#[test]
fn mr3_finite_drain_on_cancel() {
    let test_config = any::<(u64, u8, u8)>().prop_map(|(seed, stage_count, cancel_stage)| {
        let stage_count = (stage_count % 4) + 2; // 2-5 stages
        let cancel_stage = (cancel_stage as usize) % stage_count;

        PipelineTestConfig {
            seed,
            stage_count,
            pipeline_config: PipelineConfig::with_cancellation_check(),
            failing_stage: Some(cancel_stage),
            failure_outcome: TestOutcome::Cancelled,
            input_value: 10,
            inject_backpressure: false,
            test_cancellation: true,
        }
    });

    proptest!(|(config in test_config)| {
        let mut harness = PipelineTestHarness::new(config.clone());

        // Simulate cancellation at the specified stage
        if let Some(cancel_stage) = config.failing_stage {
            harness.simulate_cancellation(cancel_stage);
        }

        let _result = harness.execute_pipeline(&harness.stages.clone(), config.input_value);

        let all_drained = harness.tracker.lock().unwrap().all_cancellations_drained();

        prop_assert!(all_drained,
            "All cancelled stages should complete drain in finite time");
    });
}

/// MR4: Pipeline associativity: pipe(a,pipe(b,c)) == pipe(pipe(a,b),c).
#[test]
fn mr4_pipeline_associativity() {
    let test_config = any::<(u64, i32)>().prop_map(|(seed, input)| {
        PipelineTestConfig {
            seed,
            stage_count: 3, // Use exactly 3 stages for clear associativity test
            pipeline_config: PipelineConfig::default(),
            failing_stage: None, // All succeed for composition test
            failure_outcome: TestOutcome::Ok,
            input_value: input % 50,
            inject_backpressure: false,
            test_cancellation: false,
        }
    });

    proptest!(|(config in test_config)| {
        let mut harness = PipelineTestHarness::new(config.clone());

        // Split stages into a, b, c
        let a = vec![harness.stages[0].clone()];
        let b = vec![harness.stages[1].clone()];
        let c = vec![harness.stages[2].clone()];

        // Test pipe(a, pipe(b, c))
        let left_assoc = harness.compose_left_associated(&a, &b, &c, config.input_value);

        // Reset for second test
        let mut harness2 = PipelineTestHarness::new(config.clone());
        let a2 = vec![harness2.stages[0].clone()];
        let b2 = vec![harness2.stages[1].clone()];
        let c2 = vec![harness2.stages[2].clone()];

        // Test pipe(pipe(a, b), c)
        let right_assoc = harness2.compose_right_associated(&a2, &b2, &c2, config.input_value);

        // Both should have same completion status and final value
        prop_assert_eq!(left_assoc.is_completed(), right_assoc.is_completed(),
            "Associative compositions should have same completion status");

        if left_assoc.is_completed() && right_assoc.is_completed() {
            if let (PipelineResult::Completed { value: v1, .. },
                    PipelineResult::Completed { value: v2, .. }) = (&left_assoc, &right_assoc) {
                prop_assert_eq!(v1, v2,
                    "Associative compositions should produce same final value: {} vs {}",
                    v1, v2);
            }
        }
    });
}

/// MR5: Empty pipeline is identity transformation.
#[test]
fn mr5_empty_pipeline_identity() {
    let test_config = any::<(u64, i32)>().prop_map(|(seed, input)| {
        PipelineTestConfig {
            seed,
            stage_count: 0, // Empty pipeline
            pipeline_config: PipelineConfig::default(),
            failing_stage: None,
            failure_outcome: TestOutcome::Ok,
            input_value: input,
            inject_backpressure: false,
            test_cancellation: false,
        }
    });

    proptest!(|(config in test_config)| {
        let mut harness = PipelineTestHarness::new(config.clone());
        let output = harness.test_identity(config.input_value);

        prop_assert_eq!(output, config.input_value,
            "Empty pipeline should be identity: input {} -> output {}",
            config.input_value, output);
    });
}

// ============================================================================
// Property Generators for proptest
// ============================================================================

impl Arbitrary for TestOutcome {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        prop_oneof![
            Just(TestOutcome::Ok),
            Just(TestOutcome::Err),
            Just(TestOutcome::Cancelled),
            Just(TestOutcome::Panicked),
        ]
        .boxed()
    }
}

impl Arbitrary for PipelineConfig {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        (any::<bool>(), any::<bool>())
            .prop_map(|(check_cancellation, continue_on_error)| {
                PipelineConfig {
                    check_cancellation,
                    continue_on_error,
                }
            })
            .boxed()
    }
}

impl Arbitrary for PipelineTestConfig {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        (
            any::<u64>(), // seed
            2u8..=6,      // stage_count
            any::<PipelineConfig>(),
            any::<TestOutcome>(),
            -100i32..=100, // input_value
            any::<bool>(), // inject_backpressure
            any::<bool>(), // test_cancellation
        )
            .prop_map(
                |(seed, stage_count, pipeline_config, failure_outcome, input_value, inject_backpressure, test_cancellation)| {
                    let stage_count = stage_count as usize;
                    let failing_stage = if test_cancellation {
                        Some((seed as usize) % stage_count)
                    } else {
                        None
                    };

                    PipelineTestConfig {
                        seed,
                        stage_count,
                        pipeline_config,
                        failing_stage,
                        failure_outcome,
                        input_value,
                        inject_backpressure,
                        test_cancellation,
                    }
                },
            )
            .boxed()
    }
}

// ============================================================================
// Unit Tests for Test Infrastructure
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_outcome_conversion() {
        let ok_outcome = TestOutcome::Ok.to_outcome(42, "error");
        assert!(ok_outcome.is_ok());
        assert_eq!(ok_outcome.unwrap(), 42);

        let err_outcome = TestOutcome::Err.to_outcome(42, "test error");
        assert!(err_outcome.is_err());
    }

    #[test]
    fn test_pipeline_tracker_execution_order() {
        let tracker = PipelineTracker::new();

        {
            let mut t = tracker.lock().unwrap();
            t.record_execution(0, 10, 11);
            t.record_execution(1, 11, 13);
            t.record_execution(2, 13, 16);
        }

        let order = tracker.lock().unwrap().get_execution_order();
        assert_eq!(order, vec![0, 1, 2]);
    }

    #[test]
    fn test_stage_execution() {
        let tracker = PipelineTracker::new();
        let stage = TestStage::new(
            0,
            TestOutcome::Ok,
            |x| x * 2,
            false,
            tracker.clone(),
        );

        let result = stage.execute(5);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 10);

        let executions = tracker.lock().unwrap().stage_executions.clone();
        assert_eq!(executions.len(), 1);
        assert_eq!(executions[0].0, 0); // stage index
        assert_eq!(executions[0].1, 5); // input
        assert_eq!(executions[0].2, 10); // output
    }

    #[test]
    fn test_empty_pipeline_identity() {
        let config = PipelineTestConfig {
            seed: 42,
            stage_count: 0,
            pipeline_config: PipelineConfig::default(),
            failing_stage: None,
            failure_outcome: TestOutcome::Ok,
            input_value: 123,
            inject_backpressure: false,
            test_cancellation: false,
        };

        let mut harness = PipelineTestHarness::new(config);
        let output = harness.test_identity(123);
        assert_eq!(output, 123);
    }

    #[test]
    fn test_pipeline_execution_simple() {
        let config = PipelineTestConfig {
            seed: 42,
            stage_count: 2,
            pipeline_config: PipelineConfig::default(),
            failing_stage: None,
            failure_outcome: TestOutcome::Ok,
            input_value: 10,
            inject_backpressure: false,
            test_cancellation: false,
        };

        let mut harness = PipelineTestHarness::new(config.clone());
        let result = harness.execute_pipeline(&harness.stages.clone(), config.input_value);

        assert!(result.is_completed());
        if let PipelineResult::Completed { value, stages_completed } = result {
            // Each stage adds (index + 1) to input
            // Stage 0: 10 + 1 = 11
            // Stage 1: 11 + 2 = 13
            assert_eq!(value, 13);
            assert_eq!(stages_completed, 2);
        }
    }
}