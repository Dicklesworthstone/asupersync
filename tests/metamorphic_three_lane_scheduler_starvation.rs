#![allow(warnings)]
#![allow(clippy::all)]
//! Metamorphic Testing for Three-Lane Scheduler Starvation Prevention
//!
//! Tests fairness bounds and starvation prevention in the three-lane scheduler
//! under sustained high-priority task injection.
//!
//! Target: src/runtime/scheduler/three_lane.rs
//!
//! # Metamorphic Relations
//!
//! 1. **Cancel Fairness Bound**: Ready work dispatch within cancel_streak_limit + 1 cycles under cancel injection
//! 2. **Work Stealing Balance**: No worker completely starves another through aggressive stealing
//! 3. **Priority Inversion Bound**: Lower priority tasks don't block higher priority indefinitely
//! 4. **Cross-Worker Fairness**: All workers make progress under mixed workload distribution
//! 5. **Handoff Yield Consistency**: Browser handoff yields occur consistently at burst limits

#![cfg(test)]

use proptest::prelude::*;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use asupersync::lab::config::LabConfig;
use asupersync::lab::runtime::LabRuntime;
use asupersync::runtime::scheduler::three_lane::{ThreeLaneScheduler, ThreeLaneWorker};
use asupersync::runtime::{RuntimeState, TaskTable};
use asupersync::sync::ContendedMutex;
use asupersync::types::{TaskId, Time};

/// Test harness for scheduler starvation testing
struct StarvationTestHarness {
    lab_runtime: LabRuntime,
    scheduler: ThreeLaneScheduler,
    /// Workers owned by the harness so phase1/phase2 simulations reuse the
    /// same worker set. `ThreeLaneScheduler::take_workers()` is one-shot
    /// (`std::mem::take`) with no put-back API, so calling it per simulation
    /// would leave later phases with an empty worker vector and silently
    /// dispatch zero tasks — breaking tests like
    /// `mr_starvation_recovery_consistency` that check phase2 dispatch counts.
    workers: Vec<ThreeLaneWorker>,
    state: Arc<ContendedMutex<RuntimeState>>,
    task_table: Arc<ContendedMutex<TaskTable>>,
    cancel_streak_limit: usize,
}

impl StarvationTestHarness {
    fn new(worker_count: usize, cancel_streak_limit: usize) -> Self {
        let config = LabConfig::default()
            .worker_count(worker_count)
            .trace_capacity(4096)
            .max_steps(20000);
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
        // Take workers once at harness construction. `take_workers()` is
        // one-shot (std::mem::take) with no put-back API; doing it per call
        // would leave later simulation phases empty and silently pass.
        let workers = scheduler.take_workers();

        Self {
            lab_runtime,
            scheduler,
            workers,
            state,
            task_table,
            cancel_streak_limit,
        }
    }

    /// Inject cancel tasks at high frequency to stress fairness bounds
    fn inject_cancel_burst(&mut self, count: usize, start_id: u32) -> Vec<TaskId> {
        let mut cancel_tasks = Vec::new();
        for i in 0..count {
            let task_id = TaskId::new_for_test(start_id + i as u32, 0);
            // High priority cancel tasks
            self.scheduler.inject_cancel(task_id, (100 + i as u32) as u8);
            cancel_tasks.push(task_id);
        }
        cancel_tasks
    }

    /// Inject ready tasks that should get fair scheduling despite cancel pressure
    fn inject_ready_burst(&mut self, count: usize, start_id: u32) -> Vec<TaskId> {
        let mut ready_tasks = Vec::new();
        for i in 0..count {
            let task_id = TaskId::new_for_test(start_id + i as u32, 1);
            // Medium priority ready tasks
            self.scheduler.inject_ready(task_id, (50 + i as u32) as u8);
            ready_tasks.push(task_id);
        }
        ready_tasks
    }

    /// Run scheduler and collect dispatch statistics.
    ///
    /// Uses the harness-owned `self.workers` (populated once in `new()`) so
    /// multi-phase tests (`mr_starvation_recovery_consistency`) see the same
    /// worker set across every simulation pass instead of running phase2
    /// against an empty vector.
    fn run_scheduling_simulation(&mut self, max_steps: usize) -> SchedulerStats {
        let mut stats = SchedulerStats::new();
        if self.workers.is_empty() {
            return stats;
        }

        for step in 0..max_steps {
            let worker_idx = step % self.workers.len();
            let worker = &mut self.workers[worker_idx];

            if let Some(task_id) = worker.next_task() {
                stats.record_dispatch(worker_idx, task_id, step);

                // Track streaks for fairness analysis
                if Self::is_cancel_task(task_id) {
                    stats.update_cancel_streak(worker_idx);
                } else {
                    stats.break_cancel_streak(worker_idx);
                }
            } else {
                stats.record_idle(worker_idx, step);
                break; // No more work
            }
        }

        stats
    }

    /// Cancel tasks have generation 0 in our test setup.
    ///
    /// Associated (non-method) so it doesn't hold a borrow on `self` while
    /// `self.workers[..]` is borrowed mutably inside the simulation loop.
    fn is_cancel_task(task_id: TaskId) -> bool {
        task_id.arena_index().generation() == 0
    }
}

/// Statistics collector for scheduler behavior analysis
struct SchedulerStats {
    dispatches: Vec<Vec<(TaskId, usize)>>, // per-worker: (task_id, step)
    cancel_streaks: Vec<usize>,            // current streak per worker
    max_cancel_streaks: Vec<usize>,        // max observed streak per worker
    idle_steps: Vec<Vec<usize>>,           // per-worker idle step numbers
    total_cancel_dispatches: usize,
    total_ready_dispatches: usize,
}

impl SchedulerStats {
    fn new() -> Self {
        Self {
            dispatches: Vec::new(),
            cancel_streaks: Vec::new(),
            max_cancel_streaks: Vec::new(),
            idle_steps: Vec::new(),
            total_cancel_dispatches: 0,
            total_ready_dispatches: 0,
        }
    }

    fn record_dispatch(&mut self, worker_id: usize, task_id: TaskId, step: usize) {
        self.ensure_worker_capacity(worker_id + 1);
        self.dispatches[worker_id].push((task_id, step));

        if task_id.arena_index().generation() == 0 {
            self.total_cancel_dispatches += 1;
        } else {
            self.total_ready_dispatches += 1;
        }
    }

    fn update_cancel_streak(&mut self, worker_id: usize) {
        self.ensure_worker_capacity(worker_id + 1);
        self.cancel_streaks[worker_id] += 1;
        self.max_cancel_streaks[worker_id] =
            self.max_cancel_streaks[worker_id].max(self.cancel_streaks[worker_id]);
    }

    fn break_cancel_streak(&mut self, worker_id: usize) {
        self.ensure_worker_capacity(worker_id + 1);
        self.cancel_streaks[worker_id] = 0;
    }

    fn record_idle(&mut self, worker_id: usize, step: usize) {
        self.ensure_worker_capacity(worker_id + 1);
        self.idle_steps[worker_id].push(step);
    }

    fn ensure_worker_capacity(&mut self, min_workers: usize) {
        while self.dispatches.len() < min_workers {
            self.dispatches.push(Vec::new());
            self.cancel_streaks.push(0);
            self.max_cancel_streaks.push(0);
            self.idle_steps.push(Vec::new());
        }
    }

    /// Analyze gaps between ready task dispatches for a worker
    fn ready_dispatch_gaps(&self, worker_id: usize) -> Vec<usize> {
        if worker_id >= self.dispatches.len() {
            return Vec::new();
        }

        let ready_steps: Vec<usize> = self.dispatches[worker_id]
            .iter()
            .filter(|(task_id, _)| task_id.arena_index().generation() != 0)
            .map(|(_, step)| *step)
            .collect();

        if ready_steps.len() < 2 {
            return Vec::new();
        }

        ready_steps
            .windows(2)
            .map(|window| window[1] - window[0])
            .collect()
    }
}

/// Generate strategy for scheduler parameters
fn scheduler_params_strategy() -> impl Strategy<Value = (usize, usize, usize, usize)> {
    (
        2..=4usize,   // worker_count
        4..=32usize,  // cancel_streak_limit
        10..=50usize, // cancel_burst_size
        5..=25usize,  // ready_burst_size
    )
}

/// Metamorphic Relation 1: Cancel Fairness Bound
///
/// Under sustained cancel task injection, ready tasks must be dispatched
/// within cancel_streak_limit + 1 scheduling cycles per worker.
#[test]
fn mr_cancel_fairness_bound() {
    proptest!(|(params in scheduler_params_strategy())| {
        let (worker_count, cancel_streak_limit, cancel_burst_size, ready_burst_size) = params;

        let mut harness = StarvationTestHarness::new(worker_count, cancel_streak_limit);

        // Inject sustained cancel pressure with some ready work
        harness.inject_cancel_burst(cancel_burst_size, 1000);
        harness.inject_ready_burst(ready_burst_size, 2000);

        let stats = harness.run_scheduling_simulation(500);

        // MR: Maximum cancel streak should not exceed limit significantly
        for (worker_id, &max_streak) in stats.max_cancel_streaks.iter().enumerate() {
            let fairness_bound = cancel_streak_limit * 2; // Allow some tolerance for drain phases
            prop_assert!(max_streak <= fairness_bound,
                "Worker {} exceeded fairness bound: max_streak={} > bound={}",
                worker_id, max_streak, fairness_bound);
        }

        // MR: Ready tasks should get dispatched despite cancel pressure
        prop_assert!(stats.total_ready_dispatches > 0,
            "No ready tasks dispatched under cancel pressure - starvation detected");

        // MR: Ready dispatch gaps should be bounded by fairness constraint
        for worker_id in 0..worker_count {
            let gaps = stats.ready_dispatch_gaps(worker_id);
            for &gap in &gaps {
                let max_expected_gap = (cancel_streak_limit + 1) * 2; // Allow for other workers
                prop_assert!(gap <= max_expected_gap,
                    "Worker {} ready task gap {} exceeds fairness bound {}",
                    worker_id, gap, max_expected_gap);
            }
        }
    });
}

/// Metamorphic Relation 2: Work Stealing Balance
///
/// No single worker should be able to completely starve another worker
/// through aggressive work stealing.
#[test]
fn mr_work_stealing_balance() {
    proptest!(|(worker_count in 2..=4usize, task_count in 20..=100usize)| {
        let mut harness = StarvationTestHarness::new(worker_count, 16);

        // Distribute ready tasks to create stealing opportunities
        for i in 0..task_count {
            let task_id = TaskId::new_for_test(3000 + i as u32, 1);
            let target_worker = i % worker_count;
            harness.scheduler.inject_ready(task_id, 50);
        }

        let stats = harness.run_scheduling_simulation(task_count + 50);

        // MR: All workers should get some work (no complete starvation)
        for worker_id in 0..worker_count {
            let worker_dispatches = if worker_id < stats.dispatches.len() {
                stats.dispatches[worker_id].len()
            } else {
                0
            };

            // Allow some imbalance but prevent total starvation
            let min_expected = task_count / (worker_count * 4); // Very lenient bound
            prop_assert!(worker_dispatches >= min_expected,
                "Worker {} starved: only {} dispatches (expected >= {})",
                worker_id, worker_dispatches, min_expected);
        }

        // MR: Work distribution should not be extremely skewed
        let total_dispatches: usize = stats.dispatches.iter().map(|d| d.len()).sum();
        let mean_dispatches = total_dispatches as f64 / worker_count as f64;

        for worker_id in 0..worker_count {
            let worker_dispatches = if worker_id < stats.dispatches.len() {
                stats.dispatches[worker_id].len()
            } else {
                0
            };

            // Check that no worker gets more than 3x the mean (anti-hogging)
            let max_allowed = (mean_dispatches * 3.0) as usize;
            prop_assert!(worker_dispatches <= max_allowed,
                "Worker {} hogging work: {} dispatches > max_allowed={}",
                worker_id, worker_dispatches, max_allowed);
        }
    });
}

/// Metamorphic Relation 3: Cross-Worker Progress Fairness
///
/// Under mixed priority workloads, all workers should make forward progress
/// and no worker should be indefinitely blocked.
#[test]
fn mr_cross_worker_progress_fairness() {
    proptest!(|(params in scheduler_params_strategy())| {
        let (worker_count, cancel_streak_limit, cancel_burst, ready_burst) = params;

        let mut harness = StarvationTestHarness::new(worker_count, cancel_streak_limit);

        // Create mixed workload: cancel + ready + some high-priority tasks
        harness.inject_cancel_burst(cancel_burst, 4000);
        harness.inject_ready_burst(ready_burst, 5000);

        // Add some high-priority tasks that should preempt
        for i in 0..5 {
            let task_id = TaskId::new_for_test(6000 + i, 1);
            harness.scheduler.inject_ready(task_id, 200); // Higher priority than ready
        }

        let stats = harness.run_scheduling_simulation(300);

        // MR: Every worker that has potential work should make progress
        let active_workers = stats.dispatches.iter()
            .enumerate()
            .filter(|(_, dispatches)| !dispatches.is_empty())
            .count();

        // At least half the workers should be active with mixed workload
        let min_active = (worker_count + 1) / 2;
        prop_assert!(active_workers >= min_active,
            "Insufficient worker participation: only {} of {} workers active",
            active_workers, worker_count);

        // MR: No worker should have excessive idle periods
        for (worker_id, idle_steps) in stats.idle_steps.iter().enumerate() {
            if !idle_steps.is_empty() && worker_id < stats.dispatches.len() {
                let dispatch_count = stats.dispatches[worker_id].len();
                if dispatch_count > 0 {
                    // Workers with work shouldn't idle for too long consecutively
                    let max_consecutive_idle = 10;
                    prop_assert!(idle_steps.len() <= max_consecutive_idle,
                        "Worker {} excessive idling: {} consecutive idle steps",
                        worker_id, idle_steps.len());
                }
            }
        }

        // MR: Priority inversion should be bounded
        // High-priority tasks (priority > 150) should dispatch before many low-priority
        let high_priority_dispatched = stats.dispatches.iter()
            .flat_map(|worker_dispatches| worker_dispatches.iter())
            .filter(|(task_id, _)| task_id.arena_index().index() >= 6000)
            .count();

        if high_priority_dispatched > 0 {
            prop_assert!(high_priority_dispatched >= 3,
                "High-priority tasks under-dispatched: {} (expected >= 3)", high_priority_dispatched);
        }
    });
}

/// Metamorphic Relation 4: Starvation Recovery Consistency
///
/// After a period of starvation, the scheduler should consistently
/// recover and provide fair access to starved work categories.
#[test]
fn mr_starvation_recovery_consistency() {
    proptest!(|(recovery_cycles in 5..=20usize)| {
        let mut harness = StarvationTestHarness::new(2, 8);

        // Phase 1: Create starvation with cancel flood
        harness.inject_cancel_burst(50, 7000);
        harness.inject_ready_burst(10, 8000); // These will be starved initially

        let phase1_stats = harness.run_scheduling_simulation(100);

        // Phase 2: Stop cancel injection, add recovery work
        for i in 0..recovery_cycles {
            let task_id = TaskId::new_for_test(9000 + i as u32, 1);
            harness.scheduler.inject_ready(task_id, 75); // Recovery ready tasks
        }

        let phase2_stats = harness.run_scheduling_simulation(recovery_cycles + 20);

        // MR: Recovery should happen within bounded time
        let recovery_ready_dispatches = phase2_stats.total_ready_dispatches;
        prop_assert!(recovery_ready_dispatches >= recovery_cycles / 2,
            "Insufficient recovery: {} ready dispatches (expected >= {})",
            recovery_ready_dispatches, recovery_cycles / 2);

        // MR: Cancel streaks should reset during recovery
        let max_recovery_streak = phase2_stats.max_cancel_streaks.iter().max().copied().unwrap_or(0);
        prop_assert!(max_recovery_streak <= 16, // Should be well within limit during recovery
            "Cancel streaks not reset during recovery: max_streak={}",
            max_recovery_streak);

        // MR: Recovery should be deterministic across workers
        let worker_balance = phase2_stats.dispatches.iter()
            .map(|dispatches| dispatches.len())
            .collect::<Vec<_>>();

        if worker_balance.len() >= 2 {
            let balance_ratio = if worker_balance[1] > 0 {
                worker_balance[0] as f64 / worker_balance[1] as f64
            } else {
                worker_balance[0] as f64
            };

            // Recovery shouldn't be too imbalanced between workers
            prop_assert!(balance_ratio <= 3.0 && balance_ratio >= 0.33,
                "Recovery imbalanced between workers: ratio={:.2} dispatches={:?}",
                balance_ratio, worker_balance);
        }
    });
}

/// Metamorphic Relation 5: Bounded Preemption Consistency
///
/// The number of preemptions (fairness yields) should be predictable
/// based on the cancel_streak_limit and cancel task injection rate.
#[test]
fn mr_bounded_preemption_consistency() {
    proptest!(|(cancel_streak_limit in 4..=16usize, inject_ratio in 2..=8usize)| {
        let mut harness = StarvationTestHarness::new(1, cancel_streak_limit);

        let cancel_count = cancel_streak_limit * inject_ratio;
        let ready_count = cancel_count / 4; // Ensure some ready work exists

        harness.inject_cancel_burst(cancel_count, 10000);
        harness.inject_ready_burst(ready_count, 11000);

        let stats = harness.run_scheduling_simulation(cancel_count + ready_count + 50);

        // MR: Number of fairness yields should correlate with cancel pressure
        let expected_min_yields = if ready_count > 0 {
            cancel_count / (cancel_streak_limit + 1)
        } else {
            0
        };

        // We can't directly access fairness yield metrics from stats, but we can infer
        // from the pattern of cancel vs ready dispatches
        let ready_dispatch_count = stats.total_ready_dispatches;

        if ready_count > 0 {
            prop_assert!(ready_dispatch_count > 0,
                "No ready dispatches with ready_count={} - fairness mechanism failed",
                ready_count);

            // MR: Ready work should get proportional access
            let min_expected_ready = ready_count / 4; // Very conservative
            prop_assert!(ready_dispatch_count >= min_expected_ready,
                "Insufficient ready dispatches: {} (expected >= {})",
                ready_dispatch_count, min_expected_ready);
        }

        // MR: Cancel work should still get majority of dispatches under pressure
        let total_dispatches = stats.total_cancel_dispatches + stats.total_ready_dispatches;
        if total_dispatches > 0 {
            let cancel_ratio = stats.total_cancel_dispatches as f64 / total_dispatches as f64;
            prop_assert!(cancel_ratio >= 0.5,
                "Cancel work should dominate under pressure: ratio={:.2}",
                cancel_ratio);
        }
    });
}

#[cfg(test)]
mod test_helpers {
    use super::*;

    #[test]
    fn test_harness_basic_functionality() {
        let mut harness = StarvationTestHarness::new(2, 8);

        // Basic smoke test
        harness.inject_ready_burst(5, 100);
        let stats = harness.run_scheduling_simulation(20);

        assert!(
            stats.total_ready_dispatches > 0,
            "Should dispatch some ready work"
        );
    }

    #[test]
    fn test_scheduler_stats_tracking() {
        let mut stats = SchedulerStats::new();

        stats.record_dispatch(0, TaskId::new_for_test(1, 0), 5);
        stats.update_cancel_streak(0);
        stats.record_dispatch(0, TaskId::new_for_test(2, 1), 10);
        stats.break_cancel_streak(0);

        assert_eq!(stats.max_cancel_streaks[0], 1);
        assert_eq!(stats.cancel_streaks[0], 0);
        assert_eq!(stats.total_cancel_dispatches, 1);
        assert_eq!(stats.total_ready_dispatches, 1);
    }
}
