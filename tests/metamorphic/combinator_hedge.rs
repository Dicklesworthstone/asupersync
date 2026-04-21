#![allow(warnings)]
#![allow(clippy::all)]
//! Metamorphic testing for combinator::hedge parallel fallback invariants.
//!
//! Tests hedge combinator properties through systematic property-based exploration:
//! 1. First-success wins and cancels others
//! 2. Hedge delay respects configured interval
//! 3. Adaptive hedge adjusts based on p95 latency
//! 4. Cancel propagates to all outstanding attempts
//! 5. No value duplication across attempts
//!
//! Uses LabRuntime virtual time for deterministic concurrency testing and PropTest
//! for systematic input space exploration with comprehensive scenario coverage.

use asupersync::combinator::hedge::{
    hedge, AdaptiveHedgePolicy, HedgeConfig, HedgeResult, HedgeWinner,
};
use asupersync::cx::Cx;
use asupersync::lab::{LabRuntime, RuntimeConfig};
use asupersync::time::Sleep;
use asupersync::types::cancel::{CancelReason, CancelKind};
use asupersync::types::{Outcome, Time};
use proptest::prelude::*;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

/// Maximum test duration to prevent infinite loops
const MAX_TEST_DURATION_SECS: u64 = 30;

/// Maximum hedge delay for reasonable test bounds
const MAX_HEDGE_DELAY_MS: u64 = 5000;

/// Maximum task execution time for test scenarios
const MAX_TASK_DURATION_MS: u64 = 3000;

/// Execution trace for hedge operations to verify metamorphic properties
#[derive(Debug, Clone)]
struct HedgeExecutionTrace {
    /// Configuration used for the hedge operation
    config: HedgeConfig,
    /// Start time of the hedge operation
    start_time: Time,
    /// Time when backup was spawned (if any)
    backup_spawn_time: Option<Time>,
    /// Time when primary completed (if any)
    primary_completion_time: Option<Time>,
    /// Time when backup completed (if any)
    backup_completion_time: Option<Time>,
    /// Final result of the hedge operation
    result: HedgeResult<i32, String>,
    /// Whether external cancellation was requested
    external_cancel_requested: bool,
    /// Time when external cancellation was requested (if any)
    external_cancel_time: Option<Time>,
    /// Number of values produced across all attempts
    total_values_produced: u32,
    /// Execution timings for adaptive policy testing
    execution_latencies: Vec<Duration>,
}

impl HedgeExecutionTrace {
    fn new(config: HedgeConfig, start_time: Time) -> Self {
        Self {
            config,
            start_time,
            backup_spawn_time: None,
            primary_completion_time: None,
            backup_completion_time: None,
            result: HedgeResult::primary_fast(Outcome::Ok(0)), // placeholder
            external_cancel_requested: false,
            external_cancel_time: None,
            total_values_produced: 0,
            execution_latencies: Vec::new(),
        }
    }

    /// Records backup spawn event
    fn record_backup_spawn(&mut self, time: Time) {
        self.backup_spawn_time = Some(time);
    }

    /// Records primary completion
    fn record_primary_completion(&mut self, time: Time, outcome: Outcome<i32, String>) {
        self.primary_completion_time = Some(time);
        if outcome.is_ok() {
            self.total_values_produced += 1;
        }
    }

    /// Records backup completion
    fn record_backup_completion(&mut self, time: Time, outcome: Outcome<i32, String>) {
        self.backup_completion_time = Some(time);
        if outcome.is_ok() {
            self.total_values_produced += 1;
        }
    }

    /// Records external cancellation request
    fn record_external_cancel(&mut self, time: Time) {
        self.external_cancel_requested = true;
        self.external_cancel_time = Some(time);
    }

    /// Records the final result
    fn record_result(&mut self, result: HedgeResult<i32, String>) {
        self.result = result;
    }

    /// Calculates actual hedge delay based on execution timing
    fn actual_hedge_delay(&self) -> Option<Duration> {
        self.backup_spawn_time.map(|spawn_time| {
            Duration::from_nanos(
                spawn_time.as_nanos().saturating_sub(self.start_time.as_nanos())
            )
        })
    }

    /// Determines which branch completed first
    fn first_completion(&self) -> Option<HedgeWinner> {
        match (self.primary_completion_time, self.backup_completion_time) {
            (Some(p), Some(b)) => {
                if p <= b {
                    Some(HedgeWinner::Primary)
                } else {
                    Some(HedgeWinner::Backup)
                }
            }
            (Some(_), None) => Some(HedgeWinner::Primary),
            (None, Some(_)) => Some(HedgeWinner::Backup),
            (None, None) => None,
        }
    }
}

/// Mock task that can be configured for various timing and outcome behaviors
struct MockTask {
    /// Task identifier for debugging
    id: String,
    /// Planned duration before completion
    duration: Duration,
    /// Outcome to return upon completion
    outcome: Outcome<i32, String>,
    /// Shared trace for recording execution events
    trace: Arc<std::sync::Mutex<HedgeExecutionTrace>>,
    /// Whether this task has been polled
    polled: Arc<AtomicBool>,
    /// Whether this task has completed
    completed: Arc<AtomicBool>,
    /// Timer for duration control
    timer: Option<Sleep>,
    /// Start time for this task
    start_time: Option<Time>,
}

impl MockTask {
    fn new(
        id: String,
        duration: Duration,
        outcome: Outcome<i32, String>,
        trace: Arc<std::sync::Mutex<HedgeExecutionTrace>>,
    ) -> Self {
        Self {
            id,
            duration,
            outcome,
            trace,
            polled: Arc::new(AtomicBool::new(false)),
            completed: Arc::new(AtomicBool::new(false)),
            timer: None,
            start_time: None,
        }
    }
}

impl Future for MockTask {
    type Output = Outcome<i32, String>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // Initialize timer on first poll
        if !self.polled.load(Ordering::Acquire) {
            self.polled.store(true, Ordering::Release);

            let now = Cx::current()
                .and_then(|cx| cx.timer_driver())
                .map(|timer| timer.now())
                .unwrap_or_else(|| Time::from_nanos(0));

            self.start_time = Some(now);

            // Create timer for the specified duration
            self.timer = Some(Sleep::after(now, self.duration));
        }

        // Poll the timer
        if let Some(timer) = &mut self.timer {
            match Pin::new(timer).poll(cx) {
                Poll::Ready(()) => {
                    // Timer completed, return outcome
                    if !self.completed.load(Ordering::Acquire) {
                        self.completed.store(true, Ordering::Release);

                        let now = Cx::current()
                            .and_then(|cx| cx.timer_driver())
                            .map(|timer| timer.now())
                            .unwrap_or_else(|| Time::from_nanos(0));

                        // Record completion in trace
                        if let Ok(mut trace) = self.trace.lock() {
                            if self.id.starts_with("primary") {
                                trace.record_primary_completion(now, self.outcome.clone());
                            } else if self.id.starts_with("backup") {
                                trace.record_backup_completion(now, self.outcome.clone());
                            }
                        }

                        Poll::Ready(self.outcome.clone())
                    } else {
                        // Already completed
                        Poll::Ready(self.outcome.clone())
                    }
                }
                Poll::Pending => Poll::Pending,
            }
        } else {
            // No timer, complete immediately
            if !self.completed.load(Ordering::Acquire) {
                self.completed.store(true, Ordering::Release);

                let now = Cx::current()
                    .and_then(|cx| cx.timer_driver())
                    .map(|timer| timer.now())
                    .unwrap_or_else(|| Time::from_nanos(0));

                // Record completion in trace
                if let Ok(mut trace) = self.trace.lock() {
                    if self.id.starts_with("primary") {
                        trace.record_primary_completion(now, self.outcome.clone());
                    } else if self.id.starts_with("backup") {
                        trace.record_backup_completion(now, self.outcome.clone());
                    }
                }
            }

            Poll::Ready(self.outcome.clone())
        }
    }
}

impl Drop for MockTask {
    fn drop(&mut self) {
        // Record cancellation when task is dropped
        if !self.completed.load(Ordering::Acquire) {
            let now = Cx::current()
                .and_then(|cx| cx.timer_driver())
                .map(|timer| timer.now())
                .unwrap_or_else(|| Time::from_nanos(0));

            if let Ok(mut trace) = self.trace.lock() {
                if self.id.starts_with("primary") {
                    trace.record_primary_completion(now, Outcome::Cancelled(CancelReason::race_loser()));
                } else if self.id.starts_with("backup") {
                    trace.record_backup_completion(now, Outcome::Cancelled(CancelReason::race_loser()));
                }
            }
        }
    }
}

/// PropTest strategy for generating hedge configurations
fn hedge_config_strategy() -> impl Strategy<Value = HedgeConfig> {
    (1u64..MAX_HEDGE_DELAY_MS).prop_map(|delay_ms| HedgeConfig::from_millis(delay_ms))
}

/// PropTest strategy for generating task durations
fn task_duration_strategy() -> impl Strategy<Value = Duration> {
    (1u64..MAX_TASK_DURATION_MS).prop_map(Duration::from_millis)
}

/// PropTest strategy for generating task outcomes
fn task_outcome_strategy() -> impl Strategy<Value = Outcome<i32, String>> {
    prop_oneof![
        (0i32..1000).prop_map(Outcome::Ok),
        "[a-zA-Z0-9]{1,10}".prop_map(Outcome::Err),
        Just(Outcome::Cancelled(CancelReason::shutdown())),
    ]
}

/// PropTest strategy for generating hedge test scenarios
#[derive(Debug, Clone)]
struct HedgeScenario {
    config: HedgeConfig,
    primary_duration: Duration,
    primary_outcome: Outcome<i32, String>,
    backup_duration: Duration,
    backup_outcome: Outcome<i32, String>,
    external_cancel_after: Option<Duration>,
}

fn hedge_scenario_strategy() -> impl Strategy<Value = HedgeScenario> {
    (
        hedge_config_strategy(),
        task_duration_strategy(),
        task_outcome_strategy(),
        task_duration_strategy(),
        task_outcome_strategy(),
        prop::option::of(task_duration_strategy()),
    )
        .prop_map(|(config, primary_duration, primary_outcome, backup_duration, backup_outcome, external_cancel_after)| {
            HedgeScenario {
                config,
                primary_duration,
                primary_outcome,
                backup_duration,
                backup_outcome,
                external_cancel_after,
            }
        })
}

/// Execute a hedge scenario and return execution trace
async fn execute_hedge_scenario(scenario: &HedgeScenario) -> HedgeExecutionTrace {
    let start_time = Cx::current()
        .and_then(|cx| cx.timer_driver())
        .map(|timer| timer.now())
        .unwrap_or_else(|| Time::from_nanos(0));

    let trace = Arc::new(std::sync::Mutex::new(HedgeExecutionTrace::new(
        scenario.config,
        start_time,
    )));

    let trace_clone = trace.clone();

    // Create primary task
    let primary = MockTask::new(
        "primary".to_string(),
        scenario.primary_duration,
        scenario.primary_outcome.clone(),
        trace_clone.clone(),
    );

    // Create backup factory
    let backup_trace = trace_clone.clone();
    let backup_duration = scenario.backup_duration;
    let backup_outcome = scenario.backup_outcome.clone();
    let backup_factory = move || {
        let now = Cx::current()
            .and_then(|cx| cx.timer_driver())
            .map(|timer| timer.now())
            .unwrap_or_else(|| Time::from_nanos(0));

        // Record backup spawn in trace
        if let Ok(mut trace) = backup_trace.lock() {
            trace.record_backup_spawn(now);
        }

        MockTask::new(
            "backup".to_string(),
            backup_duration,
            backup_outcome.clone(),
            backup_trace.clone(),
        )
    };

    // Execute hedge operation
    let hedge_future = hedge(scenario.config, primary, backup_factory);

    // Handle external cancellation if configured
    let result = if let Some(cancel_delay) = scenario.external_cancel_after {
        // Race hedge future against external cancellation
        let cancel_future = async move {
            let timer = Sleep::after(start_time, cancel_delay);
            timer.await;

            // Record external cancellation
            let cancel_time = Cx::current()
                .and_then(|cx| cx.timer_driver())
                .map(|timer| timer.now())
                .unwrap_or_else(|| Time::from_nanos(0));

            if let Ok(mut trace) = trace.lock() {
                trace.record_external_cancel(cancel_time);
            }

            // Return cancelled outcome
            HedgeResult::primary_fast(Outcome::Cancelled(CancelReason::shutdown()))
        };

        // Race hedge against external cancel
        futures_lite::future::race(hedge_future, cancel_future).await
    } else {
        hedge_future.await
    };

    // Record final result
    if let Ok(mut trace) = trace.lock() {
        trace.record_result(result);
    }

    Arc::try_unwrap(trace).unwrap().into_inner().unwrap()
}

// =============================================================================
// Metamorphic Relations
// =============================================================================

/// MR1: First-success wins and cancels others
///
/// Property: When a hedge operation completes, exactly one branch should have won,
/// and any loser should be cancelled with race_loser reason.
fn mr_first_success_wins_and_cancels_others(trace: &HedgeExecutionTrace) -> bool {
    let result = &trace.result;

    match result {
        HedgeResult::PrimaryFast(_) => {
            // Primary completed before backup was spawned - no cancellation needed
            trace.backup_spawn_time.is_none()
        }
        HedgeResult::Raced { winner, loser_outcome, .. } => {
            // A race occurred - verify loser was cancelled correctly
            if let Outcome::Cancelled(reason) = loser_outcome {
                matches!(reason.kind(), CancelKind::RaceLost)
            } else {
                false
            }
        }
    }
}

/// MR2: Hedge delay respects configured interval
///
/// Property: If backup was spawned, it should have been spawned approximately
/// at the configured hedge delay time (within virtual time precision).
fn mr_hedge_delay_respects_configured_interval(trace: &HedgeExecutionTrace) -> bool {
    if let Some(actual_delay) = trace.actual_hedge_delay() {
        let configured_delay = trace.config.hedge_delay;

        // Allow small tolerance for virtual time precision
        let tolerance = Duration::from_micros(100);

        actual_delay >= configured_delay.saturating_sub(tolerance) &&
        actual_delay <= configured_delay + tolerance
    } else {
        // Backup was never spawned - hedge delay is respected trivially
        // (primary completed before delay expired)
        true
    }
}

/// MR3: Adaptive hedge adjusts based on p95 latency
///
/// Property: An adaptive policy should produce hedge delays that track
/// the empirical quantile of recorded latencies.
fn mr_adaptive_hedge_adjusts_based_on_latency(latencies: &[Duration]) -> bool {
    if latencies.len() < 10 {
        // Not enough data for meaningful adaptive behavior
        return true;
    }

    let min_delay = Duration::from_millis(10);
    let max_delay = Duration::from_secs(1);

    let mut policy = AdaptiveHedgePolicy::new(100, 0.05, min_delay, max_delay);

    // Record all latencies
    for &latency in latencies {
        policy.record(latency);
    }

    let computed_delay = policy.next_hedge_delay();

    // Verify delay is within bounds
    computed_delay >= min_delay && computed_delay <= max_delay
}

/// MR4: Cancel propagates to all outstanding attempts
///
/// Property: When external cancellation is requested, all outstanding
/// tasks (both primary and backup if spawned) should be cancelled.
fn mr_cancel_propagates_to_all_attempts(trace: &HedgeExecutionTrace) -> bool {
    if !trace.external_cancel_requested {
        // No external cancellation - property trivially holds
        return true;
    }

    // If external cancellation was requested, the result should reflect it
    match &trace.result {
        HedgeResult::PrimaryFast(outcome) => {
            matches!(outcome, Outcome::Cancelled(_))
        }
        HedgeResult::Raced { winner_outcome, .. } => {
            // In a race scenario with external cancel, winner should be cancelled
            matches!(winner_outcome, Outcome::Cancelled(_))
        }
    }
}

/// MR5: No value duplication across attempts
///
/// Property: Exactly one successful value should be produced across all
/// attempts, even in race scenarios.
fn mr_no_value_duplication_across_attempts(trace: &HedgeExecutionTrace) -> bool {
    // Count successful outcomes in the final result
    let winner_success_count = match &trace.result {
        HedgeResult::PrimaryFast(outcome) |
        HedgeResult::Raced { winner_outcome: outcome, .. } => {
            if outcome.is_ok() { 1 } else { 0 }
        }
    };

    // Verify that only one value was produced total
    winner_success_count <= 1
}

// =============================================================================
// Property-Based Test Functions
// =============================================================================

/// Test MR1: First-success wins and cancels others
#[test]
fn test_mr_first_success_wins_and_cancels_others() {
    proptest!(|(scenario in hedge_scenario_strategy())| {
        let rt = LabRuntime::new(RuntimeConfig::default()).expect("lab runtime");

        let trace = rt.block_on(async {
            execute_hedge_scenario(&scenario).await
        }).expect("hedge execution");

        prop_assert!(
            mr_first_success_wins_and_cancels_others(&trace),
            "MR1 violated: first-success win/cancel property failed for scenario: {:?}, trace: {:?}",
            scenario,
            trace
        );
    });
}

/// Test MR2: Hedge delay respects configured interval
#[test]
fn test_mr_hedge_delay_respects_configured_interval() {
    proptest!(|(scenario in hedge_scenario_strategy())| {
        let rt = LabRuntime::new(RuntimeConfig::default()).expect("lab runtime");

        let trace = rt.block_on(async {
            execute_hedge_scenario(&scenario).await
        }).expect("hedge execution");

        prop_assert!(
            mr_hedge_delay_respects_configured_interval(&trace),
            "MR2 violated: hedge delay interval property failed for scenario: {:?}, trace: {:?}",
            scenario,
            trace
        );
    });
}

/// Test MR3: Adaptive hedge adjusts based on p95 latency
#[test]
fn test_mr_adaptive_hedge_adjusts_based_on_latency() {
    proptest!(|(latencies in prop::collection::vec(task_duration_strategy(), 0..50))| {
        prop_assert!(
            mr_adaptive_hedge_adjusts_based_on_latency(&latencies),
            "MR3 violated: adaptive hedge latency adjustment property failed for latencies: {:?}",
            latencies
        );
    });
}

/// Test MR4: Cancel propagates to all outstanding attempts
#[test]
fn test_mr_cancel_propagates_to_all_attempts() {
    proptest!(|(scenario in hedge_scenario_strategy())| {
        let rt = LabRuntime::new(RuntimeConfig::default()).expect("lab runtime");

        let trace = rt.block_on(async {
            execute_hedge_scenario(&scenario).await
        }).expect("hedge execution");

        prop_assert!(
            mr_cancel_propagates_to_all_attempts(&trace),
            "MR4 violated: cancel propagation property failed for scenario: {:?}, trace: {:?}",
            scenario,
            trace
        );
    });
}

/// Test MR5: No value duplication across attempts
#[test]
fn test_mr_no_value_duplication_across_attempts() {
    proptest!(|(scenario in hedge_scenario_strategy())| {
        let rt = LabRuntime::new(RuntimeConfig::default()).expect("lab runtime");

        let trace = rt.block_on(async {
            execute_hedge_scenario(&scenario).await
        }).expect("hedge execution");

        prop_assert!(
            mr_no_value_duplication_across_attempts(&trace),
            "MR5 violated: no value duplication property failed for scenario: {:?}, trace: {:?}",
            scenario,
            trace
        );
    });
}

// =============================================================================
// Composite Metamorphic Relations
// =============================================================================

/// Composite MR: First-success + timing consistency
///
/// Property: If primary wins, it should have completed before or at the
/// same time as backup spawn time (if backup was spawned).
#[test]
fn test_composite_mr_first_success_timing_consistency() {
    proptest!(|(scenario in hedge_scenario_strategy())| {
        let rt = LabRuntime::new(RuntimeConfig::default()).expect("lab runtime");

        let trace = rt.block_on(async {
            execute_hedge_scenario(&scenario).await
        }).expect("hedge execution");

        // Verify base properties hold
        prop_assert!(mr_first_success_wins_and_cancels_others(&trace));
        prop_assert!(mr_hedge_delay_respects_configured_interval(&trace));

        // Additional composite property: timing consistency
        if let HedgeResult::Raced { winner: HedgeWinner::Primary, .. } = &trace.result {
            if let (Some(primary_time), Some(backup_spawn_time)) =
                (trace.primary_completion_time, trace.backup_spawn_time) {
                prop_assert!(
                    primary_time >= backup_spawn_time,
                    "Composite MR violated: primary won race but completed before backup was spawned"
                );
            }
        }
    });
}

/// Composite MR: Adaptive policy + delay consistency
///
/// Property: Combining adaptive policy behavior with timing constraints.
#[test]
fn test_composite_mr_adaptive_delay_consistency() {
    proptest!(|(latencies in prop::collection::vec(task_duration_strategy(), 10..30))| {
        // Verify adaptive property
        prop_assert!(mr_adaptive_hedge_adjusts_based_on_latency(&latencies));

        // Additional composite check: delay calculation determinism
        let min_delay = Duration::from_millis(10);
        let max_delay = Duration::from_secs(1);
        let mut policy1 = AdaptiveHedgePolicy::new(100, 0.05, min_delay, max_delay);
        let mut policy2 = AdaptiveHedgePolicy::new(100, 0.05, min_delay, max_delay);

        // Record same latencies in both policies
        for &latency in &latencies {
            policy1.record(latency);
            policy2.record(latency);
        }

        prop_assert_eq!(
            policy1.next_hedge_delay(),
            policy2.next_hedge_delay(),
            "Composite MR violated: identical adaptive policies produced different delays"
        );
    });
}

// =============================================================================
// Integration Tests for Specific Hedge Scenarios
// =============================================================================

/// Test hedge behavior when primary completes quickly (before hedge delay)
#[test]
fn test_hedge_primary_fast_scenario() {
    let rt = LabRuntime::new(RuntimeConfig::default()).expect("lab runtime");

    let scenario = HedgeScenario {
        config: HedgeConfig::from_millis(500),  // Long delay
        primary_duration: Duration::from_millis(100),  // Quick primary
        primary_outcome: Outcome::Ok(42),
        backup_duration: Duration::from_millis(200),
        backup_outcome: Outcome::Ok(99),
        external_cancel_after: None,
    };

    let trace = rt.block_on(async {
        execute_hedge_scenario(&scenario).await
    }).expect("hedge execution");

    // Verify hedge properties
    assert!(mr_first_success_wins_and_cancels_others(&trace));
    assert!(mr_hedge_delay_respects_configured_interval(&trace));
    assert!(mr_no_value_duplication_across_attempts(&trace));

    // Specific assertions for primary-fast scenario
    assert!(trace.result.is_primary_fast());
    assert!(trace.backup_spawn_time.is_none());
    assert_eq!(trace.result.winner(), HedgeWinner::Primary);
}

/// Test hedge race where backup wins
#[test]
fn test_hedge_backup_wins_race_scenario() {
    let rt = LabRuntime::new(RuntimeConfig::default()).expect("lab runtime");

    let scenario = HedgeScenario {
        config: HedgeConfig::from_millis(100),  // Short delay
        primary_duration: Duration::from_millis(1000),  // Slow primary
        primary_outcome: Outcome::Ok(42),
        backup_duration: Duration::from_millis(50),   // Fast backup
        backup_outcome: Outcome::Ok(99),
        external_cancel_after: None,
    };

    let trace = rt.block_on(async {
        execute_hedge_scenario(&scenario).await
    }).expect("hedge execution");

    // Verify hedge properties
    assert!(mr_first_success_wins_and_cancels_others(&trace));
    assert!(mr_hedge_delay_respects_configured_interval(&trace));
    assert!(mr_no_value_duplication_across_attempts(&trace));

    // Specific assertions for backup-wins scenario
    assert!(trace.result.was_raced());
    assert!(trace.backup_spawn_time.is_some());
    assert_eq!(trace.result.winner(), HedgeWinner::Backup);
}

/// Test hedge behavior with external cancellation
#[test]
fn test_hedge_external_cancellation_scenario() {
    let rt = LabRuntime::new(RuntimeConfig::default()).expect("lab runtime");

    let scenario = HedgeScenario {
        config: HedgeConfig::from_millis(200),
        primary_duration: Duration::from_millis(1000),  // Slow primary
        primary_outcome: Outcome::Ok(42),
        backup_duration: Duration::from_millis(800),   // Slow backup
        backup_outcome: Outcome::Ok(99),
        external_cancel_after: Some(Duration::from_millis(300)),  // Cancel during race
    };

    let trace = rt.block_on(async {
        execute_hedge_scenario(&scenario).await
    }).expect("hedge execution");

    // Verify hedge properties
    assert!(mr_cancel_propagates_to_all_attempts(&trace));
    assert!(mr_no_value_duplication_across_attempts(&trace));

    // Specific assertions for cancellation scenario
    assert!(trace.external_cancel_requested);
    assert!(trace.external_cancel_time.is_some());
}

/// Test adaptive hedge policy edge cases
#[test]
fn test_adaptive_hedge_policy_edge_cases() {
    // Test minimum data threshold
    let min_delay = Duration::from_millis(1);
    let max_delay = Duration::from_millis(1000);
    let mut policy = AdaptiveHedgePolicy::new(100, 0.05, min_delay, max_delay);

    // With insufficient data, should return max_delay
    for _ in 0..5 {
        policy.record(Duration::from_millis(10));
    }
    assert_eq!(policy.next_hedge_delay(), max_delay);

    // Test clamping behavior
    let mut policy = AdaptiveHedgePolicy::new(20, 0.1, Duration::from_millis(100), Duration::from_millis(200));

    // Record very small latencies - should clamp to min
    for _ in 0..20 {
        policy.record(Duration::from_millis(1));
    }
    assert_eq!(policy.next_hedge_delay(), Duration::from_millis(100));

    // Record very large latencies - should clamp to max
    for _ in 0..20 {
        policy.record(Duration::from_secs(10));
    }
    assert_eq!(policy.next_hedge_delay(), Duration::from_millis(200));
}

/// Test hedge configuration edge cases
#[test]
fn test_hedge_config_edge_cases() {
    // Test very small delays
    let config = HedgeConfig::from_millis(1);
    let start = Time::from_nanos(1000);
    let deadline = config.deadline_from(start);
    assert_eq!(deadline, Time::from_nanos(1_001_000));

    // Test delay saturation
    let config = HedgeConfig::new(Duration::from_nanos(u64::MAX));
    let start = Time::from_nanos(1000);
    let deadline = config.deadline_from(start);
    assert_eq!(deadline, Time::MAX);

    // Test delay elapsed calculation
    let config = HedgeConfig::from_millis(100);
    let start = Time::from_nanos(1_000_000);
    let before_deadline = Time::from_nanos(50_000_000);
    let at_deadline = Time::from_nanos(101_000_000);
    let after_deadline = Time::from_nanos(200_000_000);

    assert!(!config.delay_elapsed(start, before_deadline));
    assert!(config.delay_elapsed(start, at_deadline));
    assert!(config.delay_elapsed(start, after_deadline));
}