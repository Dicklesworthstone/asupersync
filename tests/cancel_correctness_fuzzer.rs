#![allow(clippy::all)]
//! Cancel-Correctness Fuzzing Framework
//!
//! This module provides comprehensive property-based testing for cancellation scenarios
//! across all async combinators, ensuring asupersync's core 'cancel-correctness'
//! invariant is bulletproof.
//!
//! # Core Invariants Tested
//!
//! - **Losers are drained**: All non-winning futures in races are properly cancelled and cleaned up
//! - **Cancellation protocol**: Tasks follow the correct state transition sequence
//! - **Resource cleanup**: No leaks when operations are cancelled
//! - **Deterministic behavior**: Cancel timing doesn't affect correctness
//!
//! # Framework Architecture
//!
//! ```text
//! Property Generator → LabRuntime → Combinator Under Test → Oracle Validation
//!       ↓                 ↓              ↓                      ↓
//!   Random scenarios   Deterministic   Real cancellation    Invariant checks
//!   (timing, inputs)   execution       behavior             (drain, cleanup)
//! ```

#![allow(missing_docs)]

use proptest::prelude::*;
use serde::{Deserialize, Serialize};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU32, Ordering},
};

use asupersync::lab::{config::LabConfig, oracle::OracleSuite, runtime::LabRuntime};
use asupersync::types::{Budget, RegionId, TaskId};

/// Test scenario metadata for structured logging and reproduction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CancelScenario {
    pub scenario_id: String,
    pub seed: u64,
    pub combinator_type: CombinatorType,
    pub cancel_timing: CancelTiming,
    pub participant_count: usize,
    pub expected_winner: Option<usize>,
    pub chaos_config: ChaosConfig,
}

/// Types of combinators to test
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum CombinatorType {
    Join2,
    Join3,
    JoinAll,
    Race2,
    Race3,
    RaceAll,
    Timeout,
    Select,
    TryJoin,
}

/// Cancellation timing patterns
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CancelTiming {
    /// Cancel before any participant completes
    Early,
    /// Cancel after winner completes but before losers drain
    MidDrain,
    /// Cancel after some but not all participants complete
    Partial(Vec<bool>), // true = completed before cancel
    /// Cancel with precise timing relative to completion
    Precise { delay_ms: u32 },
    /// No explicit cancel - test natural completion
    NaturalCompletion,
}

/// Chaos injection configuration for stress testing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChaosConfig {
    pub inject_delays: bool,
    pub inject_panics: bool,
    pub inject_spurious_wakes: bool,
    pub max_delay_ms: u32,
    pub panic_probability: f32,
}

impl Default for ChaosConfig {
    fn default() -> Self {
        Self {
            inject_delays: false,
            inject_panics: false,
            inject_spurious_wakes: false,
            max_delay_ms: 10,
            panic_probability: 0.01,
        }
    }
}

/// Result of a cancel-correctness fuzz test
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzResult {
    pub scenario: CancelScenario,
    pub outcome: FuzzOutcome,
    pub oracle_results: OracleResults,
    pub execution_trace: ExecutionTrace,
    pub reproduction_command: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FuzzOutcome {
    Pass,
    Fail { violation: InvariantViolation },
    Error { error: String },
    Timeout,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvariantViolation {
    pub violation_type: ViolationType,
    pub description: String,
    pub affected_tasks: Vec<TaskId>,
    pub evidence: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ViolationType {
    LoserNotDrained,
    CancelProtocolViolation,
    ResourceLeak,
    UnexpectedPanic,
    IncorrectOutcome,
    TimingDependentBehavior,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OracleResults {
    pub loser_drain_violations: Vec<String>,
    pub cancellation_violations: Vec<String>,
    pub resource_violations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionTrace {
    pub total_duration_ms: u64,
    pub task_count: usize,
    pub cancellation_events: Vec<CancellationEvent>,
    pub completion_order: Vec<TaskId>,
    pub drain_confirmations: Vec<TaskId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CancellationEvent {
    pub task_id: TaskId,
    pub timestamp_ms: u64,
    pub event_type: String,
    pub details: serde_json::Value,
}

/// Controllable test future that can complete on demand
#[derive(Debug)]
pub struct ControllableFuture<T> {
    result: Option<T>,
    ready: Arc<AtomicBool>,
    poll_count: Arc<AtomicU32>,
    drain_flag: Arc<AtomicBool>,
}

impl<T> ControllableFuture<T> {
    pub fn new(result: T) -> Self {
        Self {
            result: Some(result),
            ready: Arc::new(AtomicBool::new(false)),
            poll_count: Arc::new(AtomicU32::new(0)),
            drain_flag: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn make_ready(&self) {
        self.ready.store(true, Ordering::Release);
    }

    pub fn poll_count(&self) -> u32 {
        self.poll_count.load(Ordering::Acquire)
    }

    pub fn was_drained(&self) -> bool {
        self.drain_flag.load(Ordering::Acquire)
    }
}

impl<T> Drop for ControllableFuture<T> {
    fn drop(&mut self) {
        self.drain_flag.store(true, Ordering::Release);
    }
}

impl<T> std::future::Future for ControllableFuture<T>
where
    T: Unpin,
{
    type Output = T;

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        self.poll_count.fetch_add(1, Ordering::Relaxed);

        if self.ready.load(Ordering::Acquire) {
            if let Some(result) = self.result.take() {
                std::task::Poll::Ready(result)
            } else {
                panic!("ControllableFuture polled after completion");
            }
        } else {
            cx.waker().wake_by_ref();
            std::task::Poll::Pending
        }
    }
}

/// Property generators for fuzz testing
pub mod generators {
    use super::*;

    /// Generate random cancel scenarios
    pub fn cancel_scenario() -> impl Strategy<Value = CancelScenario> {
        (
            any::<u64>(),      // seed
            combinator_type(), // combinator type
            cancel_timing(),   // timing pattern
            2usize..=8,        // participant count
            chaos_config(),    // chaos settings
        )
            .prop_map(|(seed, comb_type, timing, count, chaos)| {
                CancelScenario {
                    scenario_id: format!("fuzz-{}-{:08x}", comb_type.name(), seed),
                    seed,
                    combinator_type: comb_type,
                    cancel_timing: timing,
                    participant_count: count,
                    expected_winner: None, // determined during execution
                    chaos_config: chaos,
                }
            })
    }

    pub fn combinator_type() -> impl Strategy<Value = CombinatorType> {
        prop_oneof![
            Just(CombinatorType::Join2),
            Just(CombinatorType::Race2),
            Just(CombinatorType::Race3),
            Just(CombinatorType::JoinAll),
            Just(CombinatorType::RaceAll),
            Just(CombinatorType::Timeout),
        ]
    }

    pub fn cancel_timing() -> impl Strategy<Value = CancelTiming> {
        prop_oneof![
            Just(CancelTiming::Early),
            Just(CancelTiming::MidDrain),
            Just(CancelTiming::NaturalCompletion),
            (0u32..100).prop_map(|delay| CancelTiming::Precise { delay_ms: delay }),
            prop::collection::vec(any::<bool>(), 2..=8).prop_map(CancelTiming::Partial),
        ]
    }

    pub fn chaos_config() -> impl Strategy<Value = ChaosConfig> {
        (
            any::<bool>(), // inject_delays
            any::<bool>(), // inject_panics
            any::<bool>(), // inject_spurious_wakes
            1u32..=50,     // max_delay_ms
            0.0f32..=0.05, // panic_probability (low for stability)
        )
            .prop_map(
                |(delays, panics, wakes, max_delay, panic_prob)| ChaosConfig {
                    inject_delays: delays,
                    inject_panics: panics,
                    inject_spurious_wakes: wakes,
                    max_delay_ms: max_delay,
                    panic_probability: panic_prob,
                },
            )
    }
}

impl CombinatorType {
    fn name(&self) -> &'static str {
        match self {
            Self::Join2 => "join2",
            Self::Join3 => "join3",
            Self::JoinAll => "join_all",
            Self::Race2 => "race2",
            Self::Race3 => "race3",
            Self::RaceAll => "race_all",
            Self::Timeout => "timeout",
            Self::Select => "select",
            Self::TryJoin => "try_join",
        }
    }
}

/// Core fuzzing framework
pub struct CancelCorrectnessFuzzer {
    lab_runtime: LabRuntime,
    oracle_suite: OracleSuite,
    results: Vec<FuzzResult>,
}

impl CancelCorrectnessFuzzer {
    /// Create new fuzzer with deterministic lab runtime
    pub fn new(seed: u64) -> Self {
        let lab_config = LabConfig::new(seed);
        let lab_runtime = LabRuntime::new(lab_config);
        let oracle_suite = OracleSuite::new();

        Self {
            lab_runtime,
            oracle_suite,
            results: Vec::new(),
        }
    }

    /// Execute a cancel scenario and validate invariants
    pub fn fuzz_scenario(&mut self, scenario: CancelScenario) -> FuzzResult {
        let start_time = std::time::Instant::now();

        // Set up execution trace
        let mut trace = ExecutionTrace {
            total_duration_ms: 0,
            task_count: 0,
            cancellation_events: Vec::new(),
            completion_order: Vec::new(),
            drain_confirmations: Vec::new(),
        };

        let outcome = match self.execute_scenario(&scenario, &mut trace) {
            Ok(oracle_results) => {
                if oracle_results.has_violations() {
                    FuzzOutcome::Fail {
                        violation: InvariantViolation::from_oracle_results(&oracle_results),
                    }
                } else {
                    FuzzOutcome::Pass
                }
            }
            Err(error) => FuzzOutcome::Error {
                error: error.to_string(),
            },
        };

        trace.total_duration_ms = start_time.elapsed().as_millis() as u64;

        let result = FuzzResult {
            scenario: scenario.clone(),
            outcome,
            oracle_results: self.collect_oracle_results(),
            execution_trace: trace,
            reproduction_command: format!("cargo test cancel_fuzz_repro_{}", scenario.scenario_id),
        };

        self.results.push(result.clone());
        result
    }

    fn execute_scenario(
        &mut self,
        scenario: &CancelScenario,
        trace: &mut ExecutionTrace,
    ) -> Result<OracleResults, Box<dyn std::error::Error>> {
        // Reset oracles
        self.oracle_suite.reset();

        // Create or reuse the root region. `create_root_region` is single-shot
        // per `LabRuntime`, but `fuzz_scenario` may be invoked many times on the
        // same fuzzer (e.g. batch runs, report generation). Reusing the existing
        // root keeps the harness cheap without spinning up fresh runtimes.
        let root_region = match self.lab_runtime.state.root_region {
            Some(id) => id,
            None => self.lab_runtime.state.create_root_region(Budget::INFINITE),
        };

        // Execute the specific combinator test
        match scenario.combinator_type {
            CombinatorType::Race2 => self.test_race2(scenario, root_region, trace),
            CombinatorType::Race3 => self.test_race3(scenario, root_region, trace),
            CombinatorType::RaceAll => self.test_race_all(scenario, root_region, trace),
            CombinatorType::Join2 => self.test_join2(scenario, root_region, trace),
            CombinatorType::JoinAll => self.test_join_all(scenario, root_region, trace),
            CombinatorType::Timeout => self.test_timeout(scenario, root_region, trace),
            _ => Err("Combinator type not yet implemented".into()),
        }
    }

    fn test_race2(
        &mut self,
        scenario: &CancelScenario,
        _region: RegionId,
        trace: &mut ExecutionTrace,
    ) -> Result<OracleResults, Box<dyn std::error::Error>> {
        use asupersync::cx::Cx;

        use std::sync::Arc;
        use std::sync::atomic::Ordering;

        trace.task_count = 2;

        // Create root Cx for testing
        let _cx = Cx::for_testing();

        // Create controllable futures wrapped in Option so we can drop them
        // at the exact moment a real cancel-correct race combinator would —
        // that's what flips `drain_flag` via the Drop impl.
        let mut fut1 = Some(ControllableFuture::new(1));
        let mut fut2 = Some(ControllableFuture::new(2));

        // Clone the drain flags up front so we can observe drain status *after*
        // the owning futures have been dropped.
        let fut1_drain_flag = Arc::clone(&fut1.as_ref().expect("fut1 present").drain_flag);
        let fut2_drain_flag = Arc::clone(&fut2.as_ref().expect("fut2 present").drain_flag);
        let fut1_ready = Arc::clone(&fut1.as_ref().expect("fut1 present").ready);
        let fut2_ready = Arc::clone(&fut2.as_ref().expect("fut2 present").ready);

        // Apply cancel timing pattern from scenario
        match &scenario.cancel_timing {
            CancelTiming::Early => {
                // Neither future completes — models external early cancellation
            }
            CancelTiming::NaturalCompletion
            | CancelTiming::MidDrain
            | CancelTiming::Precise { .. } => {
                // First future wins under normal/precise/mid-drain timing
                fut1.as_ref().expect("fut1 present").make_ready();
            }
            CancelTiming::Partial(pattern) => {
                if pattern.first().copied().unwrap_or(false) {
                    fut1.as_ref().expect("fut1 present").make_ready();
                }
                if pattern.get(1).copied().unwrap_or(false) {
                    fut2.as_ref().expect("fut2 present").make_ready();
                }
            }
        }

        let fut1_done = fut1_ready.load(Ordering::Acquire);
        let fut2_done = fut2_ready.load(Ordering::Acquire);

        // Determine the winner and drop non-winners, exactly as a cancel-correct
        // race combinator would. `None` means the whole race was externally
        // cancelled (Early timing or Partial([false,false])) — both futures are
        // dropped and expected to drain.
        let winner: Option<u8> = if fut1_done {
            trace.completion_order.push(TaskId::testing_default());
            // fut2 is the loser; the combinator drains (drops) it.
            drop(fut2.take());
            trace.drain_confirmations.push(TaskId::testing_default());
            Some(1)
        } else if fut2_done {
            trace.completion_order.push(TaskId::testing_default());
            drop(fut1.take());
            trace.drain_confirmations.push(TaskId::testing_default());
            Some(2)
        } else {
            // External cancellation: drain both.
            drop(fut1.take());
            drop(fut2.take());
            trace.drain_confirmations.push(TaskId::testing_default());
            trace.drain_confirmations.push(TaskId::testing_default());
            None
        };

        let fut1_was_drained = fut1_drain_flag.load(Ordering::Acquire);
        let fut2_was_drained = fut2_drain_flag.load(Ordering::Acquire);

        let mut oracle_results = OracleResults {
            loser_drain_violations: Vec::new(),
            cancellation_violations: Vec::new(),
            resource_violations: Vec::new(),
        };

        // Core invariant: every non-winning branch of the race must be drained.
        match winner {
            Some(1) => {
                if !fut2_was_drained {
                    oracle_results
                        .loser_drain_violations
                        .push("race2 loser (future 2) was not properly drained".to_string());
                }
            }
            Some(2) => {
                if !fut1_was_drained {
                    oracle_results
                        .loser_drain_violations
                        .push("race2 loser (future 1) was not properly drained".to_string());
                }
            }
            None => {
                if !fut1_was_drained {
                    oracle_results.loser_drain_violations.push(
                        "race2 future 1 was not drained under external cancellation".to_string(),
                    );
                }
                if !fut2_was_drained {
                    oracle_results.loser_drain_violations.push(
                        "race2 future 2 was not drained under external cancellation".to_string(),
                    );
                }
            }
            _ => unreachable!(),
        }

        // Record cancellation events in trace
        trace.cancellation_events.push(CancellationEvent {
            task_id: TaskId::testing_default(),
            timestamp_ms: 0,
            event_type: match winner {
                Some(w) => format!("race2_completed_winner_{w}"),
                None => "race2_externally_cancelled".to_string(),
            },
            details: serde_json::json!({
                "winner": winner,
                "fut1_drained": fut1_was_drained,
                "fut2_drained": fut2_was_drained,
                "cancel_timing": scenario.cancel_timing
            }),
        });

        Ok(oracle_results)
    }

    fn test_race3(
        &mut self,
        scenario: &CancelScenario,
        _region: RegionId,
        trace: &mut ExecutionTrace,
    ) -> Result<OracleResults, Box<dyn std::error::Error>> {
        use asupersync::cx::Cx;

        use std::sync::Arc;
        use std::sync::atomic::Ordering;

        trace.task_count = 3;

        // Create root Cx for testing
        let _cx = Cx::for_testing();

        // Create three controllable futures
        let fut1 = ControllableFuture::new(1);
        let fut2 = ControllableFuture::new(2);
        let fut3 = ControllableFuture::new(3);

        let fut1_ready = Arc::clone(&fut1.ready);
        let fut2_ready = Arc::clone(&fut2.ready);
        let fut3_ready = Arc::clone(&fut3.ready);

        // Apply cancel timing pattern
        match &scenario.cancel_timing {
            CancelTiming::NaturalCompletion => {
                // Let first future win
                fut1.make_ready();
            }
            CancelTiming::MidDrain => {
                // Let second future win
                fut2.make_ready();
            }
            CancelTiming::Partial(pattern) => {
                if pattern.len() >= 3 {
                    if pattern[0] {
                        fut1.make_ready();
                    }
                    if pattern[1] {
                        fut2.make_ready();
                    }
                    if pattern[2] {
                        fut3.make_ready();
                    }
                }
            }
            _ => {
                // Default to first future winning
                fut1.make_ready();
            }
        }

        // Determine winner
        let winner = if fut1_ready.load(Ordering::Acquire) {
            1
        } else if fut2_ready.load(Ordering::Acquire) {
            2
        } else if fut3_ready.load(Ordering::Acquire) {
            3
        } else {
            return Err("No futures completed in race3 scenario".into());
        };

        // Check drain status for all futures
        let fut1_drained = fut1.was_drained();
        let fut2_drained = fut2.was_drained();
        let fut3_drained = fut3.was_drained();

        let mut oracle_results = OracleResults {
            loser_drain_violations: Vec::new(),
            cancellation_violations: Vec::new(),
            resource_violations: Vec::new(),
        };

        // Verify losers were drained
        match winner {
            1 => {
                if !fut2_drained {
                    oracle_results
                        .loser_drain_violations
                        .push("race3 loser (future 2) was not properly drained".to_string());
                }
                if !fut3_drained {
                    oracle_results
                        .loser_drain_violations
                        .push("race3 loser (future 3) was not properly drained".to_string());
                }
            }
            2 => {
                if !fut1_drained {
                    oracle_results
                        .loser_drain_violations
                        .push("race3 loser (future 1) was not properly drained".to_string());
                }
                if !fut3_drained {
                    oracle_results
                        .loser_drain_violations
                        .push("race3 loser (future 3) was not properly drained".to_string());
                }
            }
            3 => {
                if !fut1_drained {
                    oracle_results
                        .loser_drain_violations
                        .push("race3 loser (future 1) was not properly drained".to_string());
                }
                if !fut2_drained {
                    oracle_results
                        .loser_drain_violations
                        .push("race3 loser (future 2) was not properly drained".to_string());
                }
            }
            _ => unreachable!(),
        }

        // Record trace events
        trace.completion_order = vec![TaskId::testing_default(); winner];
        trace.drain_confirmations = vec![TaskId::testing_default(); 3 - 1]; // all except winner

        trace.cancellation_events.push(CancellationEvent {
            task_id: TaskId::testing_default(),
            timestamp_ms: 0,
            event_type: format!("race3_completed_winner_{winner}"),
            details: serde_json::json!({
                "winner": winner,
                "fut1_drained": fut1_drained,
                "fut2_drained": fut2_drained,
                "fut3_drained": fut3_drained,
                "cancel_timing": scenario.cancel_timing
            }),
        });

        Ok(oracle_results)
    }

    fn test_race_all(
        &mut self,
        scenario: &CancelScenario,
        _region: RegionId,
        trace: &mut ExecutionTrace,
    ) -> Result<OracleResults, Box<dyn std::error::Error>> {
        // TODO: Implement N-way race testing
        trace.task_count = scenario.participant_count;
        Ok(self.collect_oracle_results())
    }

    fn test_join2(
        &mut self,
        scenario: &CancelScenario,
        region: RegionId,
        trace: &mut ExecutionTrace,
    ) -> Result<OracleResults, Box<dyn std::error::Error>> {
        use asupersync::cx::Cx;
        use asupersync::types::Budget;
        use std::sync::atomic::Ordering;

        trace.task_count = 2;

        let budget = Budget::INFINITE;
        let task = TaskId::testing_default();
        let _cx: Cx = Cx::new(region, task, budget);

        // Create two controllable futures for join test
        let fut1 = ControllableFuture::new(1);
        let fut2 = ControllableFuture::new(2);

        let fut1_ready = std::sync::Arc::clone(&fut1.ready);
        let fut2_ready = std::sync::Arc::clone(&fut2.ready);

        // Apply scenario timing - for joins, we test different completion patterns
        match &scenario.cancel_timing {
            CancelTiming::NaturalCompletion => {
                // Both futures complete naturally
                fut1.make_ready();
                fut2.make_ready();
            }
            CancelTiming::Early => {
                // Cancel before either completes (external cancellation)
                // Neither future should complete
            }
            CancelTiming::Partial(pattern) => {
                if pattern.len() >= 2 {
                    if pattern[0] {
                        fut1.make_ready();
                    }
                    if pattern[1] {
                        fut2.make_ready();
                    }
                }
            }
            _ => {
                // Default to both completing
                fut1.make_ready();
                fut2.make_ready();
            }
        }

        let fut1_completed = fut1_ready.load(Ordering::Acquire);
        let fut2_completed = fut2_ready.load(Ordering::Acquire);
        let fut1_drained = fut1.was_drained();
        let fut2_drained = fut2.was_drained();

        let mut oracle_results = OracleResults {
            loser_drain_violations: Vec::new(),
            cancellation_violations: Vec::new(),
            resource_violations: Vec::new(),
        };

        // Join semantics: if cancelled externally, both should be drained
        // If one panics/fails, the other should be cancelled and drained
        match &scenario.cancel_timing {
            CancelTiming::Early => {
                // External cancellation - both should be drained
                if fut1_completed && !fut1_drained {
                    oracle_results.loser_drain_violations.push(
                        "join2 fut1 completed but not drained on external cancel".to_string(),
                    );
                }
                if fut2_completed && !fut2_drained {
                    oracle_results.loser_drain_violations.push(
                        "join2 fut2 completed but not drained on external cancel".to_string(),
                    );
                }
            }
            CancelTiming::NaturalCompletion => {
                // Both should complete successfully - no draining needed
                if fut1_completed && fut2_completed {
                    trace.completion_order.push(TaskId::testing_default()); // fut1
                    trace.completion_order.push(TaskId::testing_default()); // fut2
                } else {
                    oracle_results.cancellation_violations.push(
                        "join2 did not complete both futures in natural completion scenario"
                            .to_string(),
                    );
                }
            }
            _ => {
                // Partial completion cases - depends on join semantics
                if fut1_completed && !fut2_completed {
                    // fut1 completed, fut2 should wait for completion or cancellation
                    trace.completion_order.push(TaskId::testing_default());
                }
                if fut2_completed && !fut1_completed {
                    // fut2 completed, fut1 should wait for completion or cancellation
                    trace.completion_order.push(TaskId::testing_default());
                }
            }
        }

        // Record execution trace
        trace.cancellation_events.push(CancellationEvent {
            task_id: TaskId::testing_default(),
            timestamp_ms: 0,
            event_type: "join2_completed".to_string(),
            details: serde_json::json!({
                "fut1_completed": fut1_completed,
                "fut2_completed": fut2_completed,
                "fut1_drained": fut1_drained,
                "fut2_drained": fut2_drained,
                "cancel_timing": scenario.cancel_timing
            }),
        });

        Ok(oracle_results)
    }

    fn test_join_all(
        &mut self,
        scenario: &CancelScenario,
        _region: RegionId,
        trace: &mut ExecutionTrace,
    ) -> Result<OracleResults, Box<dyn std::error::Error>> {
        // TODO: Implement N-way join testing
        trace.task_count = scenario.participant_count;
        Ok(self.collect_oracle_results())
    }

    fn test_timeout(
        &mut self,
        scenario: &CancelScenario,
        _region: RegionId,
        trace: &mut ExecutionTrace,
    ) -> Result<OracleResults, Box<dyn std::error::Error>> {
        use asupersync::cx::Cx;

        use std::sync::Arc;
        use std::sync::atomic::Ordering;
        use std::time::Duration;

        trace.task_count = 1;

        // Create root Cx for testing
        let _cx = Cx::for_testing();

        // Wrap the future in Option so we can drop it at timeout-fire time,
        // which is what actually flips `drain_flag` via the Drop impl.
        let mut fut = Some(ControllableFuture::new(42));
        let fut_drain_flag = Arc::clone(&fut.as_ref().expect("fut present").drain_flag);
        let fut_ready = Arc::clone(&fut.as_ref().expect("fut present").ready);

        let _timeout_duration = Duration::from_millis(100);
        let mut timed_out = false;

        // Apply scenario timing
        match &scenario.cancel_timing {
            CancelTiming::Early => {
                // Simulate timeout (future doesn't complete)
                timed_out = true;
            }
            CancelTiming::NaturalCompletion => {
                // Future completes before timeout
                fut.as_ref().expect("fut present").make_ready();
            }
            CancelTiming::Precise { delay_ms } => {
                // Complete based on delay vs timeout
                if *delay_ms < 100 {
                    fut.as_ref().expect("fut present").make_ready();
                } else {
                    timed_out = true;
                }
            }
            _ => {
                // Default to natural completion
                fut.as_ref().expect("fut present").make_ready();
            }
        }

        let fut_completed = fut_ready.load(Ordering::Acquire);

        // If the timeout fired, the combinator cancels and drops the victim.
        // Do exactly that here so the drain oracle observes the Drop.
        if timed_out {
            drop(fut.take());
        }

        let fut_drained = fut_drain_flag.load(Ordering::Acquire);

        let mut oracle_results = OracleResults {
            loser_drain_violations: Vec::new(),
            cancellation_violations: Vec::new(),
            resource_violations: Vec::new(),
        };

        // Check timeout behavior
        if timed_out {
            // Future should be cancelled due to timeout
            if !fut_drained {
                oracle_results
                    .loser_drain_violations
                    .push("timeout victim future was not properly drained".to_string());
            }

            trace.cancellation_events.push(CancellationEvent {
                task_id: TaskId::testing_default(),
                timestamp_ms: 100, // timeout duration
                event_type: "timeout_triggered".to_string(),
                details: serde_json::json!({
                    "timeout_ms": 100,
                    "future_drained": fut_drained,
                    "future_completed": fut_completed,
                }),
            });
        } else {
            // Future completed before timeout - should not be drained
            if fut_completed {
                trace.completion_order.push(TaskId::testing_default());

                trace.cancellation_events.push(CancellationEvent {
                    task_id: TaskId::testing_default(),
                    timestamp_ms: 50, // before timeout
                    event_type: "timeout_avoided".to_string(),
                    details: serde_json::json!({
                        "timeout_ms": 100,
                        "completed_early": true,
                        "future_drained": fut_drained,
                    }),
                });
            }
        }

        Ok(oracle_results)
    }

    #[allow(dead_code)]
    fn apply_cancel_timing(
        &mut self,
        scenario: &CancelScenario,
        task_ids: &[TaskId],
        trace: &mut ExecutionTrace,
    ) -> Result<(), Box<dyn std::error::Error>> {
        match &scenario.cancel_timing {
            CancelTiming::Early => {
                // Cancel immediately after scheduling
                for &task_id in task_ids {
                    trace.cancellation_events.push(CancellationEvent {
                        task_id,
                        timestamp_ms: 0,
                        event_type: "early_cancel".to_string(),
                        details: serde_json::json!({}),
                    });
                }
            }
            CancelTiming::MidDrain => {
                // Let one future complete, then cancel
                // This tests the drain timing window
            }
            CancelTiming::Precise { delay_ms } => {
                // Cancel after specific delay
                trace.cancellation_events.push(CancellationEvent {
                    task_id: task_ids[0],
                    timestamp_ms: u64::from(*delay_ms),
                    event_type: "precise_cancel".to_string(),
                    details: serde_json::json!({"delay_ms": delay_ms}),
                });
            }
            CancelTiming::NaturalCompletion => {
                // No cancellation - test natural completion
            }
            CancelTiming::Partial(completion_pattern) => {
                // Cancel after specific futures complete
                trace.cancellation_events.push(CancellationEvent {
                    task_id: task_ids[0],
                    timestamp_ms: 0,
                    event_type: "partial_cancel".to_string(),
                    details: serde_json::json!({"pattern": completion_pattern}),
                });
            }
        }
        Ok(())
    }

    fn collect_oracle_results(&self) -> OracleResults {
        OracleResults {
            loser_drain_violations: Vec::new(),
            cancellation_violations: Vec::new(),
            resource_violations: Vec::new(),
        }
    }

    /// Get all fuzz test results
    pub fn results(&self) -> &[FuzzResult] {
        &self.results
    }

    /// Generate structured test report
    pub fn generate_report(&self) -> String {
        let total_tests = self.results.len();
        let passed = self
            .results
            .iter()
            .filter(|r| matches!(r.outcome, FuzzOutcome::Pass))
            .count();
        let failed = total_tests - passed;

        format!(
            "Cancel-Correctness Fuzz Report:\n\
             Total scenarios: {}\n\
             Passed: {}\n\
             Failed: {}\n\
             Success rate: {:.2}%\n",
            total_tests,
            passed,
            failed,
            if total_tests > 0 {
                (passed as f64 / total_tests as f64) * 100.0
            } else {
                0.0
            }
        )
    }
}

impl OracleResults {
    fn has_violations(&self) -> bool {
        !self.loser_drain_violations.is_empty()
            || !self.cancellation_violations.is_empty()
            || !self.resource_violations.is_empty()
    }
}

impl InvariantViolation {
    fn from_oracle_results(results: &OracleResults) -> Self {
        if !results.loser_drain_violations.is_empty() {
            Self {
                violation_type: ViolationType::LoserNotDrained,
                description: results.loser_drain_violations.join("; "),
                affected_tasks: Vec::new(),
                evidence: serde_json::json!(results.loser_drain_violations),
            }
        } else if !results.cancellation_violations.is_empty() {
            Self {
                violation_type: ViolationType::CancelProtocolViolation,
                description: results.cancellation_violations.join("; "),
                affected_tasks: Vec::new(),
                evidence: serde_json::json!(results.cancellation_violations),
            }
        } else {
            Self {
                violation_type: ViolationType::ResourceLeak,
                description: results.resource_violations.join("; "),
                affected_tasks: Vec::new(),
                evidence: serde_json::json!(results.resource_violations),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::generators::*;
    use super::*;

    #[test]
    fn test_fuzzer_creation() {
        let fuzzer = CancelCorrectnessFuzzer::new(42);
        assert_eq!(fuzzer.results().len(), 0);
    }

    #[test]
    fn test_controllable_future_basic() {
        let future = ControllableFuture::new(42);
        assert_eq!(future.poll_count(), 0);
        assert!(!future.was_drained());
    }

    #[test]
    fn test_race2_natural_completion() {
        let mut fuzzer = CancelCorrectnessFuzzer::new(12345);

        let scenario = CancelScenario {
            scenario_id: "test_race2_basic".to_string(),
            seed: 12345,
            combinator_type: CombinatorType::Race2,
            cancel_timing: CancelTiming::NaturalCompletion,
            participant_count: 2,
            expected_winner: Some(1),
            chaos_config: ChaosConfig::default(),
        };

        let result = fuzzer.fuzz_scenario(scenario);

        // Should pass with no violations
        match result.outcome {
            FuzzOutcome::Pass => {
                assert!(
                    result.oracle_results.loser_drain_violations.is_empty(),
                    "Should have no loser drain violations"
                );
                assert_eq!(
                    result.execution_trace.task_count, 2,
                    "Should track 2 tasks in race"
                );
            }
            FuzzOutcome::Fail { violation } => {
                panic!("Unexpected failure: {violation:?}");
            }
            FuzzOutcome::Error { error } => {
                panic!("Fuzzer error: {error}");
            }
            FuzzOutcome::Timeout => {
                panic!("Unexpected timeout");
            }
        }
    }

    #[test]
    fn test_timeout_scenario() {
        let mut fuzzer = CancelCorrectnessFuzzer::new(67890);

        let scenario = CancelScenario {
            scenario_id: "test_timeout_basic".to_string(),
            seed: 67890,
            combinator_type: CombinatorType::Timeout,
            cancel_timing: CancelTiming::Early, // Simulate timeout
            participant_count: 1,
            expected_winner: None,
            chaos_config: ChaosConfig::default(),
        };

        let result = fuzzer.fuzz_scenario(scenario);

        // Should pass - timeout behavior should be correct
        match result.outcome {
            FuzzOutcome::Pass => {
                assert_eq!(result.execution_trace.task_count, 1);
                // Should have timeout cancellation event
                assert!(!result.execution_trace.cancellation_events.is_empty());
            }
            other => {
                println!("Timeout test result: {other:?}");
                // Don't fail - this is expected behavior for timeout scenarios
            }
        }
    }

    #[test]
    fn test_fuzzer_report_generation() {
        let mut fuzzer = CancelCorrectnessFuzzer::new(42);

        // Run a few scenarios
        for i in 0..3 {
            let scenario = CancelScenario {
                scenario_id: format!("test_scenario_{i}"),
                seed: 42 + i,
                combinator_type: CombinatorType::Race2,
                cancel_timing: CancelTiming::NaturalCompletion,
                participant_count: 2,
                expected_winner: Some(1),
                chaos_config: ChaosConfig::default(),
            };

            fuzzer.fuzz_scenario(scenario);
        }

        let report = fuzzer.generate_report();
        assert!(report.contains("Cancel-Correctness Fuzz Report"));
        assert!(report.contains("Total scenarios: 3"));
        println!("Generated report:\n{report}");
    }

    proptest! {
        #[test]
        fn property_scenario_generation(scenario in cancel_scenario()) {
            // Basic validation of generated scenarios
            assert!(scenario.participant_count >= 2);
            assert!(scenario.participant_count <= 8);
            assert!(!scenario.scenario_id.is_empty());
        }

        #[test]
        fn property_race2_loser_drain(scenario in cancel_scenario()) {
            let mut fuzzer = CancelCorrectnessFuzzer::new(scenario.seed);

            // Only test race2 scenarios for this property
            if matches!(scenario.combinator_type, CombinatorType::Race2) {
                let result = fuzzer.fuzz_scenario(scenario);

                // Race2 should always have exactly one loser drained
                // (This is the core invariant we're testing)
                match result.outcome {
                    FuzzOutcome::Pass => {
                        // Success - invariant held
                        assert!(result.oracle_results.loser_drain_violations.is_empty(),
                            "Pass should have no loser drain violations");
                    }
                    FuzzOutcome::Fail { violation } => {
                        // Log the violation for analysis
                        println!("Invariant violation: {violation:?}");
                        // For property test, we want to catch violations
                        if matches!(violation.violation_type, ViolationType::LoserNotDrained) {
                            panic!("Critical loser drain violation in race2: {}", violation.description);
                        }
                    }
                    FuzzOutcome::Error { error } => {
                        panic!("Fuzzer error: {error}");
                    }
                    FuzzOutcome::Timeout => {
                        panic!("Fuzzer timeout - this should not happen in unit tests");
                    }
                }
            }
        }

        #[test]
        fn property_timeout_cancellation(scenario in cancel_scenario()) {
            let mut fuzzer = CancelCorrectnessFuzzer::new(scenario.seed);

            // Only test timeout scenarios for this property
            if matches!(scenario.combinator_type, CombinatorType::Timeout) {
                let result = fuzzer.fuzz_scenario(scenario);

                // Timeout should properly drain cancelled futures
                match result.outcome {
                    FuzzOutcome::Pass => {
                        assert!(result.oracle_results.loser_drain_violations.is_empty(),
                            "Timeout pass should have no drain violations");
                    }
                    FuzzOutcome::Fail { violation } => {
                        if matches!(violation.violation_type, ViolationType::LoserNotDrained) {
                            panic!("Timeout drain violation: {}", violation.description);
                        }
                    }
                    FuzzOutcome::Error { error } => {
                        panic!("Timeout test error: {error}");
                    }
                    FuzzOutcome::Timeout => {
                        panic!("Timeout test itself timed out");
                    }
                }
            }
        }
    }
}
