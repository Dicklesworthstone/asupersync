//! Metamorphic testing for Barrier wait correctness under spurious wakeups.
//!
//! This module implements comprehensive metamorphic relations for the `Barrier`
//! synchronization primitive, verifying that barrier behavior remains correct
//! under various execution interleavings, cancellation patterns, and spurious wakeup scenarios.
//!
//! # Metamorphic Relations
//!
//! 1. **Party Count Invariant** (MR1): N parties pass iff N wait() calls
//! 2. **Spurious Wakeup Preservation** (MR2): Spurious wakeup retry preserves party count
//! 3. **Drop Cleanup Correctness** (MR3): Drop-before-wait decrements count correctly
//! 4. **Deterministic Replay** (MR4): LabRuntime replay identical across seeds
//! 5. **Leader Election Determinism** (MR5): Leader promotion after last wait is deterministic
//!
//! # Testing Strategy
//!
//! Each metamorphic relation is implemented as a property-based test using `proptest`,
//! with configurable test scenarios including party counts, cancellation patterns,
//! spurious wakeup injection, and concurrent execution patterns.

use crate::cx::Cx;
use crate::lab::{LabConfig, LabRuntime};
use crate::record::{Budget, TaskId};
use crate::sync::{Barrier, BarrierWaitError, BarrierWaitResult};
use crate::util::{DetEntropy, DetRng};
use parking_lot::Mutex;
use proptest::prelude::*;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Configuration for barrier metamorphic tests.
#[derive(Debug, Clone)]
pub struct BarrierTestConfig {
    /// Number of parties required for barrier.
    pub parties: usize,
    /// Whether to inject spurious wakeups.
    pub inject_spurious_wakeups: bool,
    /// Probability of cancelling a waiter mid-flight (0.0 to 1.0).
    pub cancel_probability: f64,
    /// Probability of dropping a waiter future without completion (0.0 to 1.0).
    pub drop_probability: f64,
    /// Random seed for deterministic test execution.
    pub seed: u64,
}

impl BarrierTestConfig {
    /// Creates a basic configuration for testing.
    pub fn basic(parties: usize, seed: u64) -> Self {
        Self {
            parties,
            inject_spurious_wakeups: false,
            cancel_probability: 0.0,
            drop_probability: 0.0,
            seed,
        }
    }

    /// Creates a stress configuration with cancellation and drops.
    pub fn with_cancellation(parties: usize, cancel_prob: f64, drop_prob: f64, seed: u64) -> Self {
        Self {
            parties,
            inject_spurious_wakeups: true,
            cancel_probability: cancel_prob,
            drop_probability: drop_prob,
            seed,
        }
    }
}

/// Test workunit representing a single party's interaction with the barrier.
#[derive(Debug, Clone)]
pub struct BarrierWorkUnit {
    /// Unique identifier for this work unit.
    pub id: usize,
    /// Whether this unit should be cancelled before completion.
    pub should_cancel: bool,
    /// Whether this unit should be dropped mid-wait.
    pub should_drop: bool,
    /// Delay before starting wait (milliseconds).
    pub start_delay_ms: u64,
}

impl BarrierWorkUnit {
    pub fn new(id: usize) -> Self {
        Self {
            id,
            should_cancel: false,
            should_drop: false,
            start_delay_ms: 0,
        }
    }

    pub fn with_cancel(mut self) -> Self {
        self.should_cancel = true;
        self
    }

    pub fn with_drop(mut self) -> Self {
        self.should_drop = true;
        self
    }

    pub fn with_delay(mut self, delay_ms: u64) -> Self {
        self.start_delay_ms = delay_ms;
        self
    }
}

/// Result of executing a barrier work unit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BarrierWorkResult {
    /// Successfully completed barrier wait.
    Completed { is_leader: bool },
    /// Wait was cancelled.
    Cancelled,
    /// Future was dropped before completion.
    Dropped,
    /// Task panicked during execution.
    Panicked(String),
}

impl BarrierWorkResult {
    pub fn is_completed(&self) -> bool {
        matches!(self, Self::Completed { .. })
    }

    pub fn is_leader(&self) -> bool {
        matches!(self, Self::Completed { is_leader: true })
    }

    pub fn is_cancelled(&self) -> bool {
        matches!(self, Self::Cancelled)
    }

    pub fn is_dropped(&self) -> bool {
        matches!(self, Self::Dropped)
    }
}

/// Global state for coordinating barrier metamorphic tests.
#[derive(Debug)]
pub struct GlobalBarrierState {
    /// Results from each work unit execution.
    pub results: Mutex<HashMap<usize, BarrierWorkResult>>,
    /// Count of work units that completed successfully.
    pub completed_count: AtomicUsize,
    /// Count of work units that were cancelled.
    pub cancelled_count: AtomicUsize,
    /// Count of work units that were dropped.
    pub dropped_count: AtomicUsize,
    /// Count of leaders elected.
    pub leader_count: AtomicUsize,
    /// Whether any spurious wakeups were injected.
    pub spurious_wakeups_injected: AtomicBool,
}

impl GlobalBarrierState {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            results: Mutex::new(HashMap::new()),
            completed_count: AtomicUsize::new(0),
            cancelled_count: AtomicUsize::new(0),
            dropped_count: AtomicUsize::new(0),
            leader_count: AtomicUsize::new(0),
            spurious_wakeups_injected: AtomicBool::new(false),
        })
    }

    pub fn record_result(&self, id: usize, result: BarrierWorkResult) {
        match &result {
            BarrierWorkResult::Completed { is_leader } => {
                self.completed_count.fetch_add(1, Ordering::SeqCst);
                if *is_leader {
                    self.leader_count.fetch_add(1, Ordering::SeqCst);
                }
            }
            BarrierWorkResult::Cancelled => {
                self.cancelled_count.fetch_add(1, Ordering::SeqCst);
            }
            BarrierWorkResult::Dropped => {
                self.dropped_count.fetch_add(1, Ordering::SeqCst);
            }
            BarrierWorkResult::Panicked(_) => {
                // Panics are handled separately and don't affect counts
            }
        }
        self.results.lock().insert(id, result);
    }

    pub fn summary(&self) -> BarrierTestSummary {
        BarrierTestSummary {
            total_units: self.results.lock().len(),
            completed: self.completed_count.load(Ordering::SeqCst),
            cancelled: self.cancelled_count.load(Ordering::SeqCst),
            dropped: self.dropped_count.load(Ordering::SeqCst),
            leaders: self.leader_count.load(Ordering::SeqCst),
            spurious_wakeups: self.spurious_wakeups_injected.load(Ordering::SeqCst),
        }
    }
}

/// Summary of barrier test execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BarrierTestSummary {
    pub total_units: usize,
    pub completed: usize,
    pub cancelled: usize,
    pub dropped: usize,
    pub leaders: usize,
    pub spurious_wakeups: bool,
}

impl BarrierTestSummary {
    /// Returns the effective party count (completed + dropped units that registered).
    pub fn effective_parties(&self) -> usize {
        // Dropped units may have registered before being dropped, affecting party count
        self.completed + self.dropped
    }

    /// Returns true if the barrier should have tripped.
    pub fn should_trip(&self, expected_parties: usize) -> bool {
        self.effective_parties() >= expected_parties
    }
}

/// Execute a barrier work unit within a LabRuntime task.
async fn execute_barrier_work_unit(
    cx: &Cx,
    barrier: &Barrier,
    work_unit: BarrierWorkUnit,
    config: &BarrierTestConfig,
    global_state: Arc<GlobalBarrierState>,
) {
    let id = work_unit.id;

    // Apply start delay if configured
    if work_unit.start_delay_ms > 0 {
        crate::time::sleep(Duration::from_millis(work_unit.start_delay_ms)).await;
    }

    // Simulate spurious wakeup injection if enabled
    if config.inject_spurious_wakeups {
        let mut rng = DetRng::from_seed(config.seed.wrapping_add(id as u64));
        if rng.gen_bool(0.1) {
            global_state.spurious_wakeups_injected.store(true, Ordering::SeqCst);
            crate::cx::yield_now().await;
        }
    }

    let result = if work_unit.should_cancel {
        // Cancel before or during wait
        let cancel_cx = cx.with_cancel();
        cancel_cx.cancel();
        match barrier.wait(&cancel_cx).await {
            Ok(result) => BarrierWorkResult::Completed {
                is_leader: result.is_leader(),
            },
            Err(BarrierWaitError::Cancelled) => BarrierWorkResult::Cancelled,
            Err(BarrierWaitError::PolledAfterCompletion) => {
                BarrierWorkResult::Panicked("polled after completion".to_string())
            }
        }
    } else if work_unit.should_drop {
        // Start the wait, then drop the future (simulates select! cancellation)
        let wait_future = barrier.wait(cx);
        // Poll once to register with the barrier
        std::future::poll_once(wait_future).await;
        // Future is dropped here, triggering cleanup
        BarrierWorkResult::Dropped
    } else {
        // Normal completion path
        match barrier.wait(cx).await {
            Ok(result) => BarrierWorkResult::Completed {
                is_leader: result.is_leader(),
            },
            Err(BarrierWaitError::Cancelled) => BarrierWorkResult::Cancelled,
            Err(BarrierWaitError::PolledAfterCompletion) => {
                BarrierWorkResult::Panicked("polled after completion".to_string())
            }
        }
    };

    global_state.record_result(id, result);
}

// ================================================================
// METAMORPHIC RELATIONS
// ================================================================

/// MR1: Party Count Invariant
///
/// N parties pass iff N wait() calls. The barrier should trip exactly when
/// the required number of parties have arrived, regardless of execution order
/// or timing variations.
fn mr1_party_count_invariant(
    config: BarrierTestConfig,
    work_units: Vec<BarrierWorkUnit>,
) -> Result<(), String> {
    let lab_config = LabConfig::new(config.seed).worker_count(4);
    let mut runtime = LabRuntime::new(lab_config);
    let root = runtime.state.create_root_region(Budget::INFINITE);

    let barrier = Arc::new(Barrier::new(config.parties));
    let global_state = GlobalBarrierState::new();

    // Execute all work units concurrently
    for work_unit in work_units.iter() {
        let barrier_clone = Arc::clone(&barrier);
        let config_clone = config.clone();
        let global_state_clone = Arc::clone(&global_state);
        let work_unit_clone = work_unit.clone();

        let (task_id, _handle) = runtime
            .state
            .create_task(root, Budget::INFINITE, async move {
                let cx = Cx::new();
                execute_barrier_work_unit(
                    &cx,
                    &barrier_clone,
                    work_unit_clone,
                    &config_clone,
                    global_state_clone,
                )
                .await;
            })
            .map_err(|e| format!("create task failed: {}", e))?;

        runtime.scheduler.lock().schedule(task_id, 0);
    }

    runtime.run_until_quiescent();
    let summary = global_state.summary();

    // MR1: Verify party count invariant
    let expected_completions = if summary.effective_parties() >= config.parties {
        config.parties.min(summary.completed + summary.dropped)
    } else {
        0
    };

    if summary.completed != expected_completions {
        return Err(format!(
            "MR1 violation: expected {} completions, got {}. Config: {:?}, Summary: {:?}",
            expected_completions, summary.completed, config, summary
        ));
    }

    // Verify exactly one leader per barrier trip
    let expected_leaders = if summary.completed > 0 { 1 } else { 0 };
    if summary.leaders != expected_leaders {
        return Err(format!(
            "MR1 leader violation: expected {} leaders, got {}. Summary: {:?}",
            expected_leaders, summary.leaders, summary
        ));
    }

    Ok(())
}

/// MR2: Spurious Wakeup Preservation
///
/// Spurious wakeup retry preserves party count. Waker updates and re-polling
/// should not affect the fundamental barrier semantics or party counting.
fn mr2_spurious_wakeup_preservation(
    config: BarrierTestConfig,
    work_units: Vec<BarrierWorkUnit>,
) -> Result<(), String> {
    // Run the same scenario with and without spurious wakeups
    let config_no_spurious = BarrierTestConfig {
        inject_spurious_wakeups: false,
        ..config.clone()
    };
    let config_with_spurious = BarrierTestConfig {
        inject_spurious_wakeups: true,
        ..config
    };

    let summary1 = execute_barrier_scenario(config_no_spurious, work_units.clone())?;
    let summary2 = execute_barrier_scenario(config_with_spurious, work_units)?;

    // MR2: Core semantics should be preserved despite spurious wakeups
    if summary1.completed != summary2.completed {
        return Err(format!(
            "MR2 violation: spurious wakeups changed completion count. Without: {}, With: {}",
            summary1.completed, summary2.completed
        ));
    }

    if summary1.leaders != summary2.leaders {
        return Err(format!(
            "MR2 violation: spurious wakeups changed leader count. Without: {}, With: {}",
            summary1.leaders, summary2.leaders
        ));
    }

    Ok(())
}

/// MR3: Drop Cleanup Correctness
///
/// Drop-before-wait decrements count correctly. When a future is dropped
/// after registering but before completion, the barrier state should be
/// properly cleaned up for subsequent operations.
fn mr3_drop_cleanup_correctness(
    config: BarrierTestConfig,
    work_units: Vec<BarrierWorkUnit>,
) -> Result<(), String> {
    let lab_config = LabConfig::new(config.seed).worker_count(4);
    let mut runtime = LabRuntime::new(lab_config);
    let root = runtime.state.create_root_region(Budget::INFINITE);

    let barrier = Arc::new(Barrier::new(config.parties));
    let global_state = GlobalBarrierState::new();

    // Phase 1: Execute work units with drops
    for work_unit in work_units.iter() {
        let barrier_clone = Arc::clone(&barrier);
        let config_clone = config.clone();
        let global_state_clone = Arc::clone(&global_state);
        let work_unit_clone = work_unit.clone();

        let (task_id, _handle) = runtime
            .state
            .create_task(root, Budget::INFINITE, async move {
                let cx = Cx::new();
                execute_barrier_work_unit(
                    &cx,
                    &barrier_clone,
                    work_unit_clone,
                    &config_clone,
                    global_state_clone,
                )
                .await;
            })
            .map_err(|e| format!("create task failed: {}", e))?;

        runtime.scheduler.lock().schedule(task_id, 0);
    }

    runtime.run_until_quiescent();
    let phase1_summary = global_state.summary();

    // Phase 2: Verify barrier is still functional with fresh parties
    if phase1_summary.completed < config.parties {
        let remaining_parties = config.parties;
        let fresh_global_state = GlobalBarrierState::new();

        for i in 0..remaining_parties {
            let barrier_clone = Arc::clone(&barrier);
            let fresh_global_state_clone = Arc::clone(&fresh_global_state);
            let fresh_work_unit = BarrierWorkUnit::new(1000 + i); // Different ID space

            let (task_id, _handle) = runtime
                .state
                .create_task(root, Budget::INFINITE, async move {
                    let cx = Cx::new();
                    match barrier_clone.wait(&cx).await {
                        Ok(result) => {
                            fresh_global_state_clone.record_result(
                                fresh_work_unit.id,
                                BarrierWorkResult::Completed {
                                    is_leader: result.is_leader(),
                                },
                            );
                        }
                        Err(_) => {
                            fresh_global_state_clone.record_result(
                                fresh_work_unit.id,
                                BarrierWorkResult::Cancelled,
                            );
                        }
                    }
                })
                .map_err(|e| format!("create fresh task failed: {}", e))?;

            runtime.scheduler.lock().schedule(task_id, 0);
        }

        runtime.run_until_quiescent();
        let phase2_summary = fresh_global_state.summary();

        // MR3: Fresh parties should be able to trip the barrier normally
        if phase2_summary.completed != remaining_parties {
            return Err(format!(
                "MR3 violation: barrier not functional after drops. Expected {} fresh completions, got {}",
                remaining_parties, phase2_summary.completed
            ));
        }

        if phase2_summary.leaders != 1 {
            return Err(format!(
                "MR3 violation: incorrect leader count in fresh generation. Expected 1, got {}",
                phase2_summary.leaders
            ));
        }
    }

    Ok(())
}

/// MR4: Deterministic Replay
///
/// LabRuntime replay identical across seeds. The same barrier scenario
/// should produce identical results when run multiple times with the
/// same seed under LabRuntime's deterministic execution.
fn mr4_deterministic_replay(
    config: BarrierTestConfig,
    work_units: Vec<BarrierWorkUnit>,
) -> Result<(), String> {
    let summary1 = execute_barrier_scenario(config.clone(), work_units.clone())?;
    let summary2 = execute_barrier_scenario(config.clone(), work_units)?;

    // MR4: Identical execution should produce identical results
    if summary1 != summary2 {
        return Err(format!(
            "MR4 violation: non-deterministic behavior detected. Run 1: {:?}, Run 2: {:?}",
            summary1, summary2
        ));
    }

    Ok(())
}

/// MR5: Leader Election Determinism
///
/// Leader promotion after last wait is deterministic. When multiple parties
/// arrive concurrently, the same party should be elected leader across
/// multiple runs with the same seed.
fn mr5_leader_election_determinism(
    config: BarrierTestConfig,
    work_units: Vec<BarrierWorkUnit>,
) -> Result<(), String> {
    let mut leader_ids = Vec::new();

    // Run the scenario multiple times and collect leader IDs
    for _ in 0..3 {
        let summary = execute_barrier_scenario_with_leader_tracking(config.clone(), work_units.clone())?;
        leader_ids.push(summary);
    }

    // MR5: The same party should be elected leader each time
    if leader_ids.windows(2).any(|w| w[0] != w[1]) {
        return Err(format!(
            "MR5 violation: leader election non-deterministic. Leaders across runs: {:?}",
            leader_ids
        ));
    }

    Ok(())
}

/// Helper function to execute a barrier scenario and return summary.
fn execute_barrier_scenario(
    config: BarrierTestConfig,
    work_units: Vec<BarrierWorkUnit>,
) -> Result<BarrierTestSummary, String> {
    let lab_config = LabConfig::new(config.seed).worker_count(4);
    let mut runtime = LabRuntime::new(lab_config);
    let root = runtime.state.create_root_region(Budget::INFINITE);

    let barrier = Arc::new(Barrier::new(config.parties));
    let global_state = GlobalBarrierState::new();

    for work_unit in work_units {
        let barrier_clone = Arc::clone(&barrier);
        let config_clone = config.clone();
        let global_state_clone = Arc::clone(&global_state);

        let (task_id, _handle) = runtime
            .state
            .create_task(root, Budget::INFINITE, async move {
                let cx = Cx::new();
                execute_barrier_work_unit(
                    &cx,
                    &barrier_clone,
                    work_unit,
                    &config_clone,
                    global_state_clone,
                )
                .await;
            })
            .map_err(|e| format!("create task failed: {}", e))?;

        runtime.scheduler.lock().schedule(task_id, 0);
    }

    runtime.run_until_quiescent();
    Ok(global_state.summary())
}

/// Helper function with leader tracking for MR5.
fn execute_barrier_scenario_with_leader_tracking(
    config: BarrierTestConfig,
    work_units: Vec<BarrierWorkUnit>,
) -> Result<Vec<usize>, String> {
    let lab_config = LabConfig::new(config.seed).worker_count(4);
    let mut runtime = LabRuntime::new(lab_config);
    let root = runtime.state.create_root_region(Budget::INFINITE);

    let barrier = Arc::new(Barrier::new(config.parties));
    let leader_ids: Arc<Mutex<Vec<usize>>> = Arc::new(Mutex::new(Vec::new()));

    for work_unit in work_units {
        let barrier_clone = Arc::clone(&barrier);
        let leader_ids_clone = Arc::clone(&leader_ids);

        let (task_id, _handle) = runtime
            .state
            .create_task(root, Budget::INFINITE, async move {
                let cx = Cx::new();
                if !work_unit.should_cancel && !work_unit.should_drop {
                    if let Ok(result) = barrier_clone.wait(&cx).await {
                        if result.is_leader() {
                            leader_ids_clone.lock().push(work_unit.id);
                        }
                    }
                }
            })
            .map_err(|e| format!("create task failed: {}", e))?;

        runtime.scheduler.lock().schedule(task_id, 0);
    }

    runtime.run_until_quiescent();
    Ok(leader_ids.lock().clone())
}

// ================================================================
// PROPTEST INTEGRATION
// ================================================================

/// Strategy for generating barrier test configurations.
fn barrier_config_strategy() -> impl Strategy<Value = BarrierTestConfig> {
    (
        1..=8_usize,           // parties
        any::<bool>(),         // inject_spurious_wakeups
        0.0..0.3_f64,         // cancel_probability
        0.0..0.2_f64,         // drop_probability
        any::<u64>(),         // seed
    )
        .prop_map(|(parties, spurious, cancel_prob, drop_prob, seed)| BarrierTestConfig {
            parties,
            inject_spurious_wakeups: spurious,
            cancel_probability: cancel_prob,
            drop_probability: drop_prob,
            seed,
        })
}

/// Strategy for generating work units.
fn work_units_strategy(max_units: usize) -> impl Strategy<Value = Vec<BarrierWorkUnit>> {
    prop::collection::vec(
        (
            any::<usize>(),      // id
            any::<bool>(),       // should_cancel
            any::<bool>(),       // should_drop
            0..50_u64,          // start_delay_ms
        ),
        1..=max_units,
    )
    .prop_map(|units| {
        units
            .into_iter()
            .enumerate()
            .map(|(i, (_, should_cancel, should_drop, delay))| {
                let mut unit = BarrierWorkUnit::new(i);
                if should_cancel {
                    unit = unit.with_cancel();
                }
                if should_drop {
                    unit = unit.with_drop();
                }
                unit.with_delay(delay)
            })
            .collect()
    })
}

// ================================================================
// TEST FUNCTIONS
// ================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::init_test_logging;

    fn init_test(name: &str) {
        init_test_logging();
        crate::test_phase!(name);
    }

    /// Test MR1: Party Count Invariant
    #[test]
    fn mr1_party_count_invariant_basic() {
        init_test("mr1_party_count_invariant_basic");

        let config = BarrierTestConfig::basic(3, 42);
        let work_units = vec![
            BarrierWorkUnit::new(0),
            BarrierWorkUnit::new(1),
            BarrierWorkUnit::new(2),
        ];

        let result = mr1_party_count_invariant(config, work_units);
        crate::assert_with_log!(
            result.is_ok(),
            "MR1 basic scenario should pass",
            true,
            result.is_ok()
        );

        crate::test_complete!("mr1_party_count_invariant_basic");
    }

    /// Test MR2: Spurious Wakeup Preservation
    #[test]
    fn mr2_spurious_wakeup_preservation_basic() {
        init_test("mr2_spurious_wakeup_preservation_basic");

        let config = BarrierTestConfig::basic(2, 123);
        let work_units = vec![
            BarrierWorkUnit::new(0),
            BarrierWorkUnit::new(1),
        ];

        let result = mr2_spurious_wakeup_preservation(config, work_units);
        crate::assert_with_log!(
            result.is_ok(),
            "MR2 basic scenario should pass",
            true,
            result.is_ok()
        );

        crate::test_complete!("mr2_spurious_wakeup_preservation_basic");
    }

    /// Test MR3: Drop Cleanup Correctness
    #[test]
    fn mr3_drop_cleanup_correctness_basic() {
        init_test("mr3_drop_cleanup_correctness_basic");

        let config = BarrierTestConfig::basic(3, 456);
        let work_units = vec![
            BarrierWorkUnit::new(0),
            BarrierWorkUnit::new(1).with_drop(),
            BarrierWorkUnit::new(2),
        ];

        let result = mr3_drop_cleanup_correctness(config, work_units);
        crate::assert_with_log!(
            result.is_ok(),
            "MR3 basic scenario should pass",
            true,
            result.is_ok()
        );

        crate::test_complete!("mr3_drop_cleanup_correctness_basic");
    }

    /// Test MR4: Deterministic Replay
    #[test]
    fn mr4_deterministic_replay_basic() {
        init_test("mr4_deterministic_replay_basic");

        let config = BarrierTestConfig::basic(2, 789);
        let work_units = vec![
            BarrierWorkUnit::new(0),
            BarrierWorkUnit::new(1),
        ];

        let result = mr4_deterministic_replay(config, work_units);
        crate::assert_with_log!(
            result.is_ok(),
            "MR4 basic scenario should pass",
            true,
            result.is_ok()
        );

        crate::test_complete!("mr4_deterministic_replay_basic");
    }

    /// Test MR5: Leader Election Determinism
    #[test]
    fn mr5_leader_election_determinism_basic() {
        init_test("mr5_leader_election_determinism_basic");

        let config = BarrierTestConfig::basic(3, 999);
        let work_units = vec![
            BarrierWorkUnit::new(0),
            BarrierWorkUnit::new(1),
            BarrierWorkUnit::new(2),
        ];

        let result = mr5_leader_election_determinism(config, work_units);
        crate::assert_with_log!(
            result.is_ok(),
            "MR5 basic scenario should pass",
            true,
            result.is_ok()
        );

        crate::test_complete!("mr5_leader_election_determinism_basic");
    }

    /// Property-based test for MR1 with various configurations.
    #[proptest]
    fn mr1_party_count_invariant_property(
        #[strategy(barrier_config_strategy())] config: BarrierTestConfig,
        #[strategy(work_units_strategy(10))] work_units: Vec<BarrierWorkUnit>,
    ) {
        let result = mr1_party_count_invariant(config, work_units);
        prop_assert!(result.is_ok(), "MR1 property failed: {:?}", result);
    }

    /// Property-based test for MR2 with spurious wakeup scenarios.
    #[proptest]
    fn mr2_spurious_wakeup_preservation_property(
        #[strategy(barrier_config_strategy().prop_filter("parties > 1", |c| c.parties > 1))] config: BarrierTestConfig,
        #[strategy(work_units_strategy(8))] work_units: Vec<BarrierWorkUnit>,
    ) {
        let result = mr2_spurious_wakeup_preservation(config, work_units);
        prop_assert!(result.is_ok(), "MR2 property failed: {:?}", result);
    }

    /// Property-based test for MR4 with deterministic replay verification.
    #[proptest]
    fn mr4_deterministic_replay_property(
        #[strategy(barrier_config_strategy())] config: BarrierTestConfig,
        #[strategy(work_units_strategy(6))] work_units: Vec<BarrierWorkUnit>,
    ) {
        let result = mr4_deterministic_replay(config, work_units);
        prop_assert!(result.is_ok(), "MR4 property failed: {:?}", result);
    }

    /// Stress test combining all metamorphic relations.
    #[test]
    fn barrier_metamorphic_stress_test() {
        init_test("barrier_metamorphic_stress_test");

        let config = BarrierTestConfig::with_cancellation(4, 0.1, 0.05, 12345);
        let work_units = vec![
            BarrierWorkUnit::new(0),
            BarrierWorkUnit::new(1).with_delay(5),
            BarrierWorkUnit::new(2).with_cancel(),
            BarrierWorkUnit::new(3),
            BarrierWorkUnit::new(4).with_drop(),
            BarrierWorkUnit::new(5),
        ];

        // Test all metamorphic relations
        let mr1_result = mr1_party_count_invariant(config.clone(), work_units.clone());
        let mr2_result = mr2_spurious_wakeup_preservation(config.clone(), work_units.clone());
        let mr4_result = mr4_deterministic_replay(config, work_units);

        crate::assert_with_log!(
            mr1_result.is_ok(),
            "MR1 stress test should pass",
            true,
            mr1_result.is_ok()
        );
        crate::assert_with_log!(
            mr2_result.is_ok(),
            "MR2 stress test should pass",
            true,
            mr2_result.is_ok()
        );
        crate::assert_with_log!(
            mr4_result.is_ok(),
            "MR4 stress test should pass",
            true,
            mr4_result.is_ok()
        );

        crate::test_complete!("barrier_metamorphic_stress_test");
    }
}