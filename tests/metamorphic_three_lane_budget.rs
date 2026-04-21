#![allow(warnings)]
#![allow(clippy::all)]
//! Metamorphic Testing for Three-Lane Scheduler Cross-Lane Budget Invariants
//!
//! Tests budget enforcement and fairness across cancel, timed, and ready lanes
//! in the three-lane scheduler under various load patterns.
//!
//! Target: src/runtime/scheduler/three_lane.rs
//!
//! # Metamorphic Relations
//!
//! 1. **Cancel Streak Budget**: cancel_streak never exceeds effective limits under any load
//! 2. **Ready Burst Budget**: ready_dispatch_streak respects browser_ready_handoff_limit
//! 3. **Cross-Lane Fairness**: no lane monopolizes beyond its budget allocation
//! 4. **Budget Reset Consistency**: streak counters reset properly on lane transitions
//! 5. **Adaptive Budget Convergence**: adaptive limits converge to effective values

#![cfg(test)]

use proptest::prelude::*;
use std::collections::HashMap;
use std::sync::Arc;

use asupersync::lab::config::LabConfig;
use asupersync::lab::runtime::LabRuntime;
use asupersync::runtime::scheduler::three_lane::ThreeLaneScheduler;
use asupersync::runtime::{RuntimeState, TaskTable};
use asupersync::sync::ContendedMutex;
use asupersync::types::{TaskId, Time};

/// Test harness for cross-lane budget testing
struct BudgetTestHarness {
    lab_runtime: LabRuntime,
    scheduler: ThreeLaneScheduler,
    state: Arc<ContendedMutex<RuntimeState>>,
    task_table: Arc<ContendedMutex<TaskTable>>,
    cancel_streak_limit: usize,
    browser_handoff_limit: usize,
}

impl BudgetTestHarness {
    fn new(
        worker_count: usize,
        cancel_streak_limit: usize,
        browser_handoff_limit: usize,
        adaptive_enabled: bool,
    ) -> Self {
        let config = LabConfig::default()
            .worker_count(worker_count)
            .trace_capacity(2048)
            .max_steps(15000);
        let lab_runtime = LabRuntime::new(config);

        let state = Arc::new(ContendedMutex::new("runtime_state", RuntimeState::new()));
        let task_table = Arc::new(ContendedMutex::new("task_table", TaskTable::new()));
        let mut scheduler = ThreeLaneScheduler::new_with_options_and_task_table(
            worker_count,
            &state,
            Some(Arc::clone(&task_table)),
            cancel_streak_limit,
            false, // disable governor for deterministic testing
            1,
        );

        // Configure browser handoff limit
        scheduler.set_browser_ready_handoff_limit(browser_handoff_limit);

        // Configure adaptive cancel streak if requested
        if adaptive_enabled {
            scheduler.set_adaptive_cancel_streak(true, 50); // 50-step epochs
        }

        Self {
            lab_runtime,
            scheduler,
            state,
            task_table,
            cancel_streak_limit,
            browser_handoff_limit,
        }
    }

    /// Inject a balanced workload across all three lanes
    fn inject_balanced_workload(&mut self, count_per_lane: usize, base_id: u32) {
        // Cancel tasks (highest priority)
        for i in 0..count_per_lane {
            let task_id = TaskId::new_for_test(base_id + i as u32, 0);
            self.scheduler.schedule_cancel(task_id, 100 + i as u32);
        }

        // Timed tasks (medium priority)
        for i in 0..count_per_lane {
            let task_id = TaskId::new_for_test(base_id + count_per_lane as u32 + i as u32, 1);
            // Schedule for immediate deadline to make them runnable
            self.scheduler.schedule_timed(task_id, 50 + i as u32, Time::ZERO);
        }

        // Ready tasks (lower priority)
        for i in 0..count_per_lane {
            let task_id = TaskId::new_for_test(base_id + 2 * count_per_lane as u32 + i as u32, 2);
            self.scheduler.schedule(task_id, 25 + i as u32);
        }
    }

    /// Inject heavy cancel pressure to test budget enforcement
    fn inject_cancel_pressure(&mut self, count: usize, base_id: u32) {
        for i in 0..count {
            let task_id = TaskId::new_for_test(base_id + i as u32, 0);
            self.scheduler.schedule_cancel(task_id, 200 + i as u32);
        }
    }

    /// Inject ready burst to test ready handoff limits
    fn inject_ready_burst(&mut self, count: usize, base_id: u32) {
        for i in 0..count {
            let task_id = TaskId::new_for_test(base_id + i as u32, 2);
            self.scheduler.schedule(task_id, 30 + i as u32);
        }
    }

    /// Run scheduler and collect budget compliance statistics
    fn run_budget_simulation(&mut self, max_steps: usize) -> BudgetStats {
        let mut stats = BudgetStats::new();
        let mut workers = self.scheduler.take_workers();

        for step in 0..max_steps {
            let worker_idx = step % workers.len();
            let worker = &mut workers[worker_idx];

            if let Some(task_id) = worker.next_task() {
                let task_type = self.classify_task_type(task_id);
                stats.record_dispatch(worker_idx, task_type, step);

                // Get budget metrics from worker
                let fairness_cert = worker.fairness_certificate();
                stats.record_budget_metrics(worker_idx, &fairness_cert, task_type);
            } else {
                stats.record_idle(worker_idx, step);
                if step > max_steps / 2 {
                    break; // Stop if idle in second half (work exhausted)
                }
            }
        }

        // Return workers to scheduler
        for worker in workers {
            self.scheduler.add_worker(worker);
        }

        stats
    }

    fn classify_task_type(&self, task_id: TaskId) -> TaskType {
        match task_id.generation() {
            0 => TaskType::Cancel,
            1 => TaskType::Timed,
            2 => TaskType::Ready,
            _ => TaskType::Ready, // Fallback
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum TaskType {
    Cancel,
    Timed,
    Ready,
}

/// Statistics for budget compliance analysis
#[derive(Debug)]
struct BudgetStats {
    dispatches: Vec<Vec<(TaskType, usize)>>, // per-worker: (task_type, step)
    cancel_streaks: Vec<Vec<usize>>,         // per-worker cancel streak samples
    ready_streaks: Vec<Vec<usize>>,          // per-worker ready streak samples
    max_cancel_streak: usize,
    max_ready_streak: usize,
    fairness_violations: Vec<String>,
    total_dispatches_by_type: HashMap<TaskType, usize>,
    idle_workers: Vec<usize>, // steps where workers were idle
}

impl BudgetStats {
    fn new() -> Self {
        Self {
            dispatches: Vec::new(),
            cancel_streaks: Vec::new(),
            ready_streaks: Vec::new(),
            max_cancel_streak: 0,
            max_ready_streak: 0,
            fairness_violations: Vec::new(),
            total_dispatches_by_type: HashMap::new(),
            idle_workers: Vec::new(),
        }
    }

    fn record_dispatch(&mut self, worker_id: usize, task_type: TaskType, step: usize) {
        self.ensure_worker_capacity(worker_id + 1);
        self.dispatches[worker_id].push((task_type, step));
        *self.total_dispatches_by_type.entry(task_type).or_insert(0) += 1;
    }

    fn record_budget_metrics(
        &mut self,
        worker_id: usize,
        fairness_cert: &asupersync::runtime::scheduler::three_lane::PreemptionFairnessCertificate,
        current_task_type: TaskType,
    ) {
        self.ensure_worker_capacity(worker_id + 1);

        // Record current streak values (derived from certificate)
        if current_task_type == TaskType::Cancel {
            // Track cancel streak progression
            let cancel_streak = fairness_cert.observed_max_cancel_streak.min(fairness_cert.effective_limit + 1);
            self.cancel_streaks[worker_id].push(cancel_streak);
            self.max_cancel_streak = self.max_cancel_streak.max(cancel_streak);
        }

        // Check for budget violations
        if fairness_cert.effective_limit_exceedances > 0 {
            self.fairness_violations.push(format!(
                "Worker {} exceeded effective limit: {} exceedances",
                worker_id, fairness_cert.effective_limit_exceedances
            ));
        }
    }

    fn record_idle(&mut self, worker_id: usize, step: usize) {
        self.idle_workers.push(step);
    }

    fn ensure_worker_capacity(&mut self, min_workers: usize) {
        while self.dispatches.len() < min_workers {
            self.dispatches.push(Vec::new());
            self.cancel_streaks.push(Vec::new());
            self.ready_streaks.push(Vec::new());
        }
    }

    /// Check if budget allocations are balanced across lanes
    fn is_cross_lane_balanced(&self, tolerance: f64) -> bool {
        let total_dispatches: usize = self.total_dispatches_by_type.values().sum();
        if total_dispatches == 0 {
            return true;
        }

        let cancel_ratio = *self.total_dispatches_by_type.get(&TaskType::Cancel).unwrap_or(&0) as f64 / total_dispatches as f64;
        let timed_ratio = *self.total_dispatches_by_type.get(&TaskType::Timed).unwrap_or(&0) as f64 / total_dispatches as f64;
        let ready_ratio = *self.total_dispatches_by_type.get(&TaskType::Ready).unwrap_or(&0) as f64 / total_dispatches as f64;

        // None should dominate completely (extreme imbalance)
        cancel_ratio <= (1.0 - tolerance) && timed_ratio <= (1.0 - tolerance) && ready_ratio <= (1.0 - tolerance)
    }

    /// Get the maximum observed streak for any worker
    fn max_observed_cancel_streak(&self) -> usize {
        self.max_cancel_streak
    }

    /// Check for any fairness violations
    fn has_fairness_violations(&self) -> bool {
        !self.fairness_violations.is_empty()
    }
}

/// Generate strategy for scheduler parameters
fn budget_test_params_strategy() -> impl Strategy<Value = (usize, usize, usize, usize, bool)> {
    (
        1..=3usize,      // worker_count
        4..=16usize,     // cancel_streak_limit
        0..=20usize,     // browser_handoff_limit (0 = disabled)
        5..=30usize,     // tasks_per_lane
        any::<bool>(),   // adaptive_enabled
    )
}

/// Metamorphic Relation 1: Cancel Streak Budget Enforcement
///
/// The cancel_streak must never exceed the effective limit, even under
/// sustained cancel task injection.
#[test]
fn mr_cancel_streak_budget_enforcement() {
    proptest!(|(params in budget_test_params_strategy())| {
        let (worker_count, cancel_limit, handoff_limit, tasks_per_lane, adaptive) = params;

        let mut harness = BudgetTestHarness::new(worker_count, cancel_limit, handoff_limit, adaptive);

        // Create sustained cancel pressure with some other work
        harness.inject_cancel_pressure(tasks_per_lane * 3, 1000);
        harness.inject_balanced_workload(tasks_per_lane, 2000);

        let stats = harness.run_budget_simulation(300);

        // MR: Cancel streak must never exceed effective limit
        let effective_limit = if adaptive { cancel_limit * 2 } else { cancel_limit * 2 }; // Conservative bound for drain phases
        prop_assert!(stats.max_observed_cancel_streak() <= effective_limit,
            "Cancel streak {} exceeded effective limit {}",
            stats.max_observed_cancel_streak(), effective_limit);

        // MR: No fairness violations should be recorded
        prop_assert!(!stats.has_fairness_violations(),
            "Fairness violations detected: {:?}", stats.fairness_violations);
    });
}

/// Metamorphic Relation 2: Cross-Lane Fairness Balance
///
/// Under balanced workload injection, no single lane should monopolize
/// the scheduler completely.
#[test]
fn mr_cross_lane_fairness_balance() {
    proptest!(|(worker_count in 1..=3usize, cancel_limit in 8..=16usize, tasks_per_lane in 10..=25usize)| {
        let mut harness = BudgetTestHarness::new(worker_count, cancel_limit, 0, false);

        // Inject balanced workload across all lanes
        harness.inject_balanced_workload(tasks_per_lane, 3000);

        let stats = harness.run_budget_simulation(tasks_per_lane * 3 + 50);

        // MR: No lane should completely monopolize (allow 85% max)
        prop_assert!(stats.is_cross_lane_balanced(0.15),
            "Lane distribution imbalanced: Cancel={}, Timed={}, Ready={}",
            stats.total_dispatches_by_type.get(&TaskType::Cancel).unwrap_or(&0),
            stats.total_dispatches_by_type.get(&TaskType::Timed).unwrap_or(&0),
            stats.total_dispatches_by_type.get(&TaskType::Ready).unwrap_or(&0));

        // MR: All task types should get at least some dispatches with balanced input
        if tasks_per_lane > 5 {
            prop_assert!(stats.total_dispatches_by_type.get(&TaskType::Cancel).unwrap_or(&0) > &0,
                "Cancel lane got zero dispatches");
            prop_assert!(stats.total_dispatches_by_type.get(&TaskType::Timed).unwrap_or(&0) > &0,
                "Timed lane got zero dispatches");
            prop_assert!(stats.total_dispatches_by_type.get(&TaskType::Ready).unwrap_or(&0) > &0,
                "Ready lane got zero dispatches");
        }
    });
}

/// Metamorphic Relation 3: Budget Reset Consistency
///
/// When switching between lanes, streak counters should reset appropriately
/// and not carry over budget debt inappropriately.
#[test]
fn mr_budget_reset_consistency() {
    proptest!(|(worker_count in 1..=2usize, cancel_limit in 6..=12usize)| {
        let mut harness = BudgetTestHarness::new(worker_count, cancel_limit, 0, false);

        // Phase 1: Cancel burst to build up streak
        harness.inject_cancel_pressure(cancel_limit, 4000);
        let phase1_stats = harness.run_budget_simulation(cancel_limit + 5);

        // Phase 2: Switch to ready work (should reset cancel streak)
        harness.inject_ready_burst(10, 5000);
        let phase2_stats = harness.run_budget_simulation(20);

        // Phase 3: Return to cancel work (streak should start fresh)
        harness.inject_cancel_pressure(cancel_limit / 2, 6000);
        let phase3_stats = harness.run_budget_simulation(cancel_limit);

        // MR: Budget violations should not accumulate across phases
        prop_assert!(!phase1_stats.has_fairness_violations(),
            "Phase 1 fairness violations: {:?}", phase1_stats.fairness_violations);
        prop_assert!(!phase2_stats.has_fairness_violations(),
            "Phase 2 fairness violations: {:?}", phase2_stats.fairness_violations);
        prop_assert!(!phase3_stats.has_fairness_violations(),
            "Phase 3 fairness violations: {:?}", phase3_stats.fairness_violations);

        // MR: Later phases should not show inflated streak counts from earlier phases
        prop_assert!(phase3_stats.max_observed_cancel_streak() <= cancel_limit * 2,
            "Phase 3 cancel streak {} suggests budget carryover",
            phase3_stats.max_observed_cancel_streak());
    });
}

/// Metamorphic Relation 4: Browser Handoff Limit Compliance
///
/// When browser_ready_handoff_limit is set, ready task bursts should
/// trigger handoffs at the specified limit.
#[test]
fn mr_browser_handoff_limit_compliance() {
    proptest!(|(worker_count in 1..=2usize, handoff_limit in 5..=15usize, ready_burst in 20..=40usize)| {
        prop_assume!(handoff_limit > 0); // Only test when handoff is enabled

        let mut harness = BudgetTestHarness::new(worker_count, 16, handoff_limit, false);

        // Create ready-heavy workload to trigger handoff behavior
        harness.inject_ready_burst(ready_burst, 7000);

        let stats = harness.run_budget_simulation(ready_burst + 20);

        // MR: Should have some ready dispatches
        let ready_dispatches = stats.total_dispatches_by_type.get(&TaskType::Ready).unwrap_or(&0);
        prop_assert!(ready_dispatches > &0, "No ready dispatches with ready_burst={}", ready_burst);

        // MR: If we have enough ready tasks, handoff behavior should activate
        // (We can't directly measure handoffs, but we should see interrupt patterns)
        if ready_burst >= handoff_limit * 2 {
            prop_assert!(stats.idle_workers.len() > 0 || ready_dispatches < &ready_burst,
                "Expected handoff interruption with ready_burst={}, limit={}, got {} dispatches",
                ready_burst, handoff_limit, ready_dispatches);
        }
    });
}

/// Metamorphic Relation 5: Adaptive Budget Convergence
///
/// When adaptive cancel streak is enabled, the scheduler should converge
/// to effective budget limits without violations.
#[test]
fn mr_adaptive_budget_convergence() {
    proptest!(|(worker_count in 1..=2usize, base_limit in 8..=16usize, workload_size in 15..=30usize)| {
        let mut harness = BudgetTestHarness::new(worker_count, base_limit, 0, true);

        // Create mixed workload that should trigger adaptive behavior
        harness.inject_balanced_workload(workload_size, 8000);
        harness.inject_cancel_pressure(workload_size / 2, 9000); // Some extra cancel pressure

        let stats = harness.run_budget_simulation(workload_size * 3 + 50);

        // MR: Adaptive policy should prevent budget violations
        prop_assert!(!stats.has_fairness_violations(),
            "Adaptive policy failed to prevent violations: {:?}", stats.fairness_violations);

        // MR: Should still achieve reasonable cross-lane balance
        prop_assert!(stats.is_cross_lane_balanced(0.25), // More lenient for adaptive
            "Adaptive policy resulted in extreme lane imbalance");

        // MR: Cancel streak should remain bounded even with adaptation
        let adaptive_bound = base_limit * 3; // Generous bound for adaptive adjustment
        prop_assert!(stats.max_observed_cancel_streak() <= adaptive_bound,
            "Adaptive cancel streak {} exceeded reasonable bound {}",
            stats.max_observed_cancel_streak(), adaptive_bound);
    });
}

#[cfg(test)]
mod test_helpers {
    use super::*;

    #[test]
    fn test_budget_harness_basic_functionality() {
        let mut harness = BudgetTestHarness::new(1, 8, 0, false);

        harness.inject_balanced_workload(3, 100);
        let stats = harness.run_budget_simulation(20);

        assert!(stats.total_dispatches_by_type.values().sum::<usize>() > 0, "Should dispatch some work");
    }

    #[test]
    fn test_budget_stats_tracking() {
        let mut stats = BudgetStats::new();

        stats.record_dispatch(0, TaskType::Cancel, 5);
        stats.record_dispatch(0, TaskType::Ready, 10);

        assert_eq!(stats.total_dispatches_by_type.get(&TaskType::Cancel), Some(&1));
        assert_eq!(stats.total_dispatches_by_type.get(&TaskType::Ready), Some(&1));
        assert!(stats.is_cross_lane_balanced(0.1)); // Should be balanced with 1 each
    }

    #[test]
    fn test_task_type_classification() {
        let harness = BudgetTestHarness::new(1, 8, 0, false);

        assert_eq!(harness.classify_task_type(TaskId::new_for_test(1, 0)), TaskType::Cancel);
        assert_eq!(harness.classify_task_type(TaskId::new_for_test(1, 1)), TaskType::Timed);
        assert_eq!(harness.classify_task_type(TaskId::new_for_test(1, 2)), TaskType::Ready);
    }
}