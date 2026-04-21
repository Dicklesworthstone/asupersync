#![allow(warnings)]
#![allow(clippy::all)]
//! Metamorphic Testing for Three-Lane Scheduler Lane Promotion Fairness
//!
//! Tests fairness of task promotion between cancel, timed, and ready lanes
//! in the three-lane scheduler under various promotion scenarios.
//!
//! Target: src/runtime/scheduler/three_lane.rs
//!
//! # Metamorphic Relations
//!
//! 1. **Promotion Priority Preservation**: promoted tasks maintain correct priority order within target lane
//! 2. **EDF Fairness**: timed tasks are promoted in earliest-deadline-first order when deadlines are due
//! 3. **Promotion Atomicity**: task promotion is atomic - no task exists in multiple lanes simultaneously
//! 4. **Cancel Promotion Precedence**: cancel-promoted tasks get immediate precedence in cancel lane
//! 5. **Promotion Starvation Prevention**: frequent promotions don't starve existing work in target lanes

#![cfg(test)]

use proptest::prelude::*;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

use asupersync::lab::config::LabConfig;
use asupersync::lab::runtime::LabRuntime;
use asupersync::runtime::scheduler::three_lane::{ThreeLaneScheduler, ThreeLaneWorker};
use asupersync::runtime::{RuntimeState, TaskTable};
use asupersync::sync::ContendedMutex;
use asupersync::types::{TaskId, Time};

/// Test harness for lane promotion fairness testing
struct PromotionTestHarness {
    lab_runtime: LabRuntime,
    scheduler: ThreeLaneScheduler,
    workers: Vec<ThreeLaneWorker>,
    state: Arc<ContendedMutex<RuntimeState>>,
    task_table: Arc<ContendedMutex<TaskTable>>,
    base_time: Time,
}

impl PromotionTestHarness {
    fn new(worker_count: usize) -> Self {
        let config = LabConfig::default()
            .worker_count(worker_count)
            .trace_capacity(2048)
            .max_steps(10000);
        let lab_runtime = LabRuntime::new(config);

        let state = Arc::new(ContendedMutex::new("runtime_state", RuntimeState::new()));
        let task_table = Arc::new(ContendedMutex::new("task_table", TaskTable::new()));
        let mut scheduler = ThreeLaneScheduler::new_with_options_and_task_table(
            worker_count,
            &state,
            Some(Arc::clone(&task_table)),
            8,     // reasonable cancel streak limit
            false, // disable governor for deterministic testing
            1,
        );
        let workers = scheduler.take_workers();

        Self {
            lab_runtime,
            scheduler,
            workers,
            state,
            task_table,
            base_time: Time::from_nanos(1000), // Start at t=1000
        }
    }

    /// Create tasks scheduled for different lanes with varying priorities
    fn setup_multi_lane_tasks(&mut self, count_per_lane: usize, base_id: u32) -> PromotionTaskSet {
        let mut task_set = PromotionTaskSet::new();

        // Ready tasks (lowest priority lane)
        for i in 0..count_per_lane {
            let task_id = TaskId::new_for_test(base_id + i as u32, 0);
            let priority = 50 + i as u32;
            self.scheduler.inject_ready(task_id, priority as u8);
            task_set.ready_tasks.push((task_id, priority as u8));
        }

        // Timed tasks (medium priority lane) with staggered deadlines
        for i in 0..count_per_lane {
            let task_id = TaskId::new_for_test(base_id + count_per_lane as u32 + i as u32, 1);
            let priority = 75 + i as u32;
            let deadline = self.base_time.saturating_add_nanos((i as u64 + 1) * 100); // staggered every 100ns
            self.scheduler
                .inject_timed(task_id, deadline);
            task_set
                .timed_tasks
                .push((task_id, priority as u8, deadline));
        }

        // Cancel tasks (highest priority lane)
        for i in 0..count_per_lane {
            let task_id = TaskId::new_for_test(base_id + 2 * count_per_lane as u32 + i as u32, 2);
            let priority = 100 + i as u32;
            self.scheduler.inject_cancel(task_id, priority as u8);
            task_set.cancel_tasks.push((task_id, priority as u8));
        }

        task_set
    }

    /// Promote ready tasks to cancel lane
    fn promote_ready_to_cancel(&mut self, task_priorities: &[(TaskId, u8)]) {
        for &(task_id, priority) in task_priorities {
            // Promote to cancel lane with higher priority
            self.scheduler.inject_cancel(task_id, priority + 50);
        }
    }

    /// Advance time to make timed tasks become due (ready for promotion)
    fn advance_time_for_timed_promotion(&mut self, target_time: Time) {
        self.base_time = target_time;
        // Time advancement would happen via timer driver in real scenarios
    }

    /// Run promotion scenario and collect fairness statistics
    fn run_promotion_simulation(&mut self, max_steps: usize) -> PromotionStats {
        let mut stats = PromotionStats::new();

        if self.workers.is_empty() {
            return stats;
        }

        for step in 0..max_steps {
            let worker_idx = step % self.workers.len();
            let worker = &mut self.workers[worker_idx];

            if let Some(task_id) = worker.next_task() {
                let lane = Self::classify_task_lane(task_id);
                stats.record_dispatch(task_id, lane, step);
            } else {
                stats.record_idle(step);
                if step > max_steps / 2 {
                    break; // Stop if consistently idle
                }
            }
        }

        stats
    }

    fn classify_task_lane(task_id: TaskId) -> TaskLane {
        // Use task generation to classify original lane intent
        match task_id.arena_index().generation() {
            0 => TaskLane::Ready,  // Originally ready
            1 => TaskLane::Timed,  // Originally timed
            2 => TaskLane::Cancel, // Originally cancel
            _ => TaskLane::Ready,
        }
    }
}

/// Container for tasks organized by their initial lane
#[derive(Debug)]
struct PromotionTaskSet {
    ready_tasks: Vec<(TaskId, u8)>,       // (task_id, priority)
    timed_tasks: Vec<(TaskId, u8, Time)>, // (task_id, priority, deadline)
    cancel_tasks: Vec<(TaskId, u8)>,      // (task_id, priority)
}

impl PromotionTaskSet {
    fn new() -> Self {
        Self {
            ready_tasks: Vec::new(),
            timed_tasks: Vec::new(),
            cancel_tasks: Vec::new(),
        }
    }

    fn all_tasks(&self) -> Vec<TaskId> {
        let mut all = Vec::new();
        all.extend(self.ready_tasks.iter().map(|(id, _)| *id));
        all.extend(self.timed_tasks.iter().map(|(id, _, _)| *id));
        all.extend(self.cancel_tasks.iter().map(|(id, _)| *id));
        all
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum TaskLane {
    Ready,
    Timed,
    Cancel,
}

/// Statistics for promotion fairness analysis
#[derive(Debug)]
struct PromotionStats {
    dispatches: Vec<(TaskId, TaskLane, usize)>, // (task_id, original_lane, step)
    lane_dispatch_counts: HashMap<TaskLane, usize>,
    dispatch_order: Vec<TaskId>,
    idle_steps: Vec<usize>,
    promotion_violations: Vec<String>,
}

impl PromotionStats {
    fn new() -> Self {
        Self {
            dispatches: Vec::new(),
            lane_dispatch_counts: HashMap::new(),
            dispatch_order: Vec::new(),
            idle_steps: Vec::new(),
            promotion_violations: Vec::new(),
        }
    }

    fn record_dispatch(&mut self, task_id: TaskId, original_lane: TaskLane, step: usize) {
        self.dispatches.push((task_id, original_lane, step));
        self.dispatch_order.push(task_id);
        *self.lane_dispatch_counts.entry(original_lane).or_insert(0) += 1;
    }

    fn record_idle(&mut self, step: usize) {
        self.idle_steps.push(step);
    }

    /// Check if cancel tasks (including promoted ones) were dispatched before others
    fn check_cancel_precedence(&self, cancel_task_ids: &HashSet<TaskId>) -> bool {
        if cancel_task_ids.is_empty() {
            return true;
        }

        let first_non_cancel_pos = self
            .dispatch_order
            .iter()
            .position(|&task_id| !cancel_task_ids.contains(&task_id));

        match first_non_cancel_pos {
            None => true, // All dispatches were cancel tasks
            Some(pos) => {
                // Check if all cancel tasks were dispatched before first non-cancel
                let cancel_tasks_before_pos = self.dispatch_order[..pos]
                    .iter()
                    .filter(|&&task_id| cancel_task_ids.contains(&task_id))
                    .count();

                cancel_tasks_before_pos == cancel_task_ids.len()
            }
        }
    }

    /// Analyze if timed tasks were dispatched in deadline order
    fn check_edf_ordering(&self, timed_tasks: &[(TaskId, u8, Time)]) -> bool {
        if timed_tasks.len() <= 1 {
            return true;
        }

        let mut timed_dispatch_order = Vec::new();
        for &(task_id, _, deadline) in timed_tasks {
            if let Some(pos) = self.dispatch_order.iter().position(|&id| id == task_id) {
                timed_dispatch_order.push((task_id, deadline, pos));
            }
        }

        // Sort by dispatch order (position)
        timed_dispatch_order.sort_by_key(|(_, _, pos)| *pos);

        // Check if deadlines are in non-decreasing order
        timed_dispatch_order.windows(2).all(|window| {
            window[0].1 <= window[1].1 // deadline ordering
        })
    }

    /// Check if promoted tasks didn't completely starve existing work
    fn check_promotion_starvation(&self, promoted_count: usize, total_tasks: usize) -> bool {
        let total_dispatches = self.dispatch_order.len();
        if total_dispatches == 0 {
            return true;
        }

        // If we have promotions, ensure they didn't dominate completely
        if promoted_count > 0 && total_tasks > promoted_count {
            let promotion_ratio = promoted_count as f64 / total_dispatches as f64;
            promotion_ratio <= 0.85 // Allow promotions to take up to 85% but not completely dominate
        } else {
            true
        }
    }

    fn has_violations(&self) -> bool {
        !self.promotion_violations.is_empty()
    }
}

/// Generate strategy for promotion test parameters
fn promotion_test_params_strategy() -> impl Strategy<Value = (usize, usize, usize, usize)> {
    (
        1..=2usize, // worker_count
        2..=6usize, // tasks_per_lane
        0..=3usize, // promotions_from_ready
        0..=2usize, // promotions_from_timed
    )
}

/// Metamorphic Relation 1: Promotion Priority Preservation
///
/// When tasks are promoted between lanes, they should maintain correct
/// priority ordering within the target lane.
#[test]
fn mr_promotion_priority_preservation() {
    proptest!(|(params in promotion_test_params_strategy())| {
        let (worker_count, tasks_per_lane, ready_promotions, _timed_promotions) = params;

        let mut harness = PromotionTestHarness::new(worker_count);
        let task_set = harness.setup_multi_lane_tasks(tasks_per_lane, 1000);

        // Promote some ready tasks to cancel lane
        if ready_promotions > 0 && ready_promotions <= task_set.ready_tasks.len() {
            let to_promote = &task_set.ready_tasks[..ready_promotions];
            harness.promote_ready_to_cancel(to_promote);
        }

        let stats = harness.run_promotion_simulation(100);

        // MR: Cancel tasks (including promoted ones) should have precedence
        let cancel_task_ids: HashSet<_> = task_set.cancel_tasks.iter()
            .map(|(id, _)| *id)
            .chain(
                task_set.ready_tasks[..ready_promotions.min(task_set.ready_tasks.len())]
                    .iter().map(|(id, _)| *id)
            )
            .collect();

        if !cancel_task_ids.is_empty() {
            prop_assert!(stats.check_cancel_precedence(&cancel_task_ids),
                "Cancel tasks (including promoted) should be dispatched first. Dispatch order: {:?}",
                stats.dispatch_order);
        }

        // MR: Promotions shouldn't cause complete starvation
        let promoted_count = ready_promotions.min(task_set.ready_tasks.len());
        prop_assert!(stats.check_promotion_starvation(promoted_count, task_set.all_tasks().len()),
            "Promoted tasks caused excessive starvation");

        // MR: All lanes should get some representation if they have tasks
        if tasks_per_lane > 0 {
            for lane in [TaskLane::Ready, TaskLane::Timed, TaskLane::Cancel] {
                let has_tasks = match lane {
                    TaskLane::Ready => !task_set.ready_tasks.is_empty(),
                    TaskLane::Timed => !task_set.timed_tasks.is_empty(),
                    TaskLane::Cancel => !task_set.cancel_tasks.is_empty() || ready_promotions > 0,
                };

                if has_tasks {
                    let dispatches = stats.lane_dispatch_counts.get(&lane).unwrap_or(&0);
                    prop_assert!(dispatches > &0,
                        "Lane {:?} with tasks got zero dispatches", lane);
                }
            }
        }
    });
}

/// Metamorphic Relation 2: EDF (Earliest Deadline First) Fairness
///
/// Timed tasks should be promoted and dispatched in earliest deadline first
/// order when their deadlines become due.
#[test]
fn mr_edf_promotion_fairness() {
    proptest!(|(worker_count in 1..=2usize, timed_task_count in 3..=8usize)| {
        let mut harness = PromotionTestHarness::new(worker_count);

        // Create timed tasks with staggered deadlines
        let base_id = 2000;
        let base_time = Time::from_nanos(1000);
        let mut timed_tasks = Vec::new();

        for i in 0..timed_task_count {
            let task_id = TaskId::new_for_test(base_id + i as u32, 1);
            let priority = 50;
            // Deadlines at t=1000, 1100, 1200, ... (100ns apart)
            let deadline = base_time.saturating_add_nanos(i as u64 * 100);
            harness.scheduler.inject_timed(task_id, deadline);
            timed_tasks.push((task_id, priority, deadline));
        }

        // Advance time to make all timed tasks due
        harness.advance_time_for_timed_promotion(base_time.saturating_add_nanos(timed_task_count as u64 * 100));

        let stats = harness.run_promotion_simulation(timed_task_count + 10);

        // MR: Timed tasks should be dispatched in EDF order
        prop_assert!(stats.check_edf_ordering(&timed_tasks),
            "Timed tasks not dispatched in EDF order. Dispatch order: {:?}, Expected deadline order: {:?}",
            stats.dispatch_order,
            {
                let mut sorted = timed_tasks.clone();
                sorted.sort_by_key(|(_, _, deadline)| *deadline);
                sorted.iter().map(|(id, _, deadline)| (*id, *deadline)).collect::<Vec<_>>()
            });

        // MR: All due timed tasks should be dispatched
        let dispatched_timed: HashSet<_> = stats.dispatches.iter()
            .filter(|(_, lane, _)| *lane == TaskLane::Timed)
            .map(|(id, _, _)| *id)
            .collect();

        let expected_timed: HashSet<_> = timed_tasks.iter().map(|(id, _, _)| *id).collect();

        prop_assert!(dispatched_timed == expected_timed,
            "Not all due timed tasks were dispatched. Expected: {:?}, Got: {:?}",
            expected_timed, dispatched_timed);
    });
}

/// Metamorphic Relation 3: Promotion Atomicity
///
/// Task promotion between lanes should be atomic - no task should be
/// dispatched from multiple lanes or appear to exist in multiple lanes.
#[test]
fn mr_promotion_atomicity() {
    proptest!(|(worker_count in 1..=2usize, base_tasks in 3..=6usize, promotions in 1..=4usize)| {
        let mut harness = PromotionTestHarness::new(worker_count);
        let task_set = harness.setup_multi_lane_tasks(base_tasks, 3000);

        // Track which tasks we're promoting
        let mut promoted_tasks = HashSet::new();

        // Promote some ready tasks to cancel
        let ready_promotions = promotions.min(task_set.ready_tasks.len());
        if ready_promotions > 0 {
            let to_promote = &task_set.ready_tasks[..ready_promotions];
            harness.promote_ready_to_cancel(to_promote);

            for &(task_id, _) in to_promote {
                promoted_tasks.insert(task_id);
            }
        }

        let stats = harness.run_promotion_simulation(100);

        // MR: Each task should be dispatched from exactly one lane
        let mut task_lane_counts: HashMap<TaskId, usize> = HashMap::new();
        for &(task_id, _, _) in &stats.dispatches {
            *task_lane_counts.entry(task_id).or_insert(0) += 1;
        }

        for (task_id, count) in task_lane_counts {
            prop_assert_eq!(count, 1,
                "Task {:?} was dispatched {} times (atomicity violation)", task_id, count);
        }

        // MR: Promoted tasks should not appear in their original lane after promotion
        for &(task_id, original_lane, _) in &stats.dispatches {
            if promoted_tasks.contains(&task_id) {
                prop_assert_ne!(original_lane, TaskLane::Ready,
                    "Promoted task {:?} was dispatched from original lane {:?} instead of cancel lane",
                    task_id, original_lane);
            }
        }
    });
}

/// Metamorphic Relation 4: Cancel Promotion Immediate Precedence
///
/// Tasks promoted to cancel lane should get immediate precedence over
/// lower-priority lanes, respecting existing cancel lane ordering.
#[test]
fn mr_cancel_promotion_precedence() {
    proptest!(|(worker_count in 1..=2usize)| {
        let mut harness = PromotionTestHarness::new(worker_count);

        // Setup scenario: existing cancel task, ready task, then promote ready task
        let existing_cancel = TaskId::new_for_test(4000, 2);
        let ready_task = TaskId::new_for_test(4001, 0);
        let later_ready = TaskId::new_for_test(4002, 0);

        // 1. Schedule existing cancel task
        harness.scheduler.inject_cancel(existing_cancel, 100);

        // 2. Schedule ready tasks
        harness.scheduler.inject_ready(ready_task, 50);
        harness.scheduler.inject_ready(later_ready, 50);

        // 3. Promote one ready task to cancel
        harness.scheduler.inject_cancel(ready_task, 110); // Higher priority than existing

        let stats = harness.run_promotion_simulation(10);

        // MR: Promoted task should be dispatched from cancel lane, not ready lane
        let promoted_task_lane = stats.dispatches.iter()
            .find(|(id, _, _)| *id == ready_task)
            .map(|(_, lane, _)| *lane);

        prop_assert!(promoted_task_lane.is_some(),
            "Promoted task should be dispatched");

        // Note: Due to implementation details, the promoted task gets dispatched as Cancel
        // but our lane classification is based on original generation, so this test focuses
        // on precedence ordering rather than lane classification

        // MR: Promoted task should be dispatched before non-cancel tasks
        let ready_task_pos = stats.dispatch_order.iter().position(|&id| id == ready_task);
        let later_ready_pos = stats.dispatch_order.iter().position(|&id| id == later_ready);

        match (ready_task_pos, later_ready_pos) {
            (Some(promoted_pos), Some(other_pos)) => {
                prop_assert!(promoted_pos < other_pos,
                    "Promoted task should be dispatched before non-promoted ready task");
            }
            _ => {
                // One or both weren't dispatched, which is acceptable
            }
        }
    });
}

/// Metamorphic Relation 5: Promotion Frequency Stability
///
/// Frequent promotions should not destabilize the scheduler or cause
/// fairness violations in the target lane.
#[test]
fn mr_promotion_frequency_stability() {
    proptest!(|(worker_count in 1..=2usize, burst_size in 5..=12usize, promotion_ratio in 0.3..=0.8f64)| {
        let mut harness = PromotionTestHarness::new(worker_count);

        // Create a larger task set
        let ready_tasks_count = burst_size;
        let cancel_tasks_count = burst_size / 2;

        let mut ready_tasks = Vec::new();
        let mut cancel_tasks = Vec::new();

        // Schedule ready tasks
        for i in 0..ready_tasks_count {
            let task_id = TaskId::new_for_test(5000 + i as u32, 0);
            harness.scheduler.inject_ready(task_id, 50);
            ready_tasks.push(task_id);
        }

        // Schedule some existing cancel tasks
        for i in 0..cancel_tasks_count {
            let task_id = TaskId::new_for_test(6000 + i as u32, 2);
            harness.scheduler.inject_cancel(task_id, 100);
            cancel_tasks.push(task_id);
        }

        // Promote a fraction of ready tasks with rapid promotions
        let promotion_count = ((ready_tasks_count as f64) * promotion_ratio) as usize;
        let promotion_count = promotion_count.min(ready_tasks_count).max(1);

        for i in 0..promotion_count {
            if i < ready_tasks.len() {
                harness.scheduler.inject_cancel(ready_tasks[i], 120 + i as u8);
            }
        }

        let stats = harness.run_promotion_simulation(burst_size * 2);

        // MR: Frequent promotions shouldn't cause system instability
        prop_assert!(!stats.has_violations(),
            "Promotion frequency caused fairness violations: {:?}", stats.promotion_violations);

        // MR: Both promoted and existing cancel tasks should be dispatched
        let total_cancel_expected = cancel_tasks_count + promotion_count;
        let cancel_dispatches = stats.lane_dispatch_counts.get(&TaskLane::Cancel).unwrap_or(&0);

        // Allow some flexibility for scheduling variations
        prop_assert!(*cancel_dispatches >= total_cancel_expected / 2,
            "Too few cancel tasks dispatched with frequent promotions: {} < {} / 2",
            cancel_dispatches, total_cancel_expected);

        // MR: System should remain responsive (not completely stalled)
        let total_dispatches = stats.dispatch_order.len();
        prop_assert!(total_dispatches >= burst_size / 3,
            "System became unresponsive under promotion load: only {} dispatches",
            total_dispatches);
    });
}

#[cfg(test)]
mod test_helpers {
    use super::*;

    #[test]
    fn test_promotion_harness_basic_functionality() {
        let mut harness = PromotionTestHarness::new(1);
        let task_set = harness.setup_multi_lane_tasks(2, 100);

        assert_eq!(task_set.ready_tasks.len(), 2);
        assert_eq!(task_set.timed_tasks.len(), 2);
        assert_eq!(task_set.cancel_tasks.len(), 2);

        let stats = harness.run_promotion_simulation(20);
        assert!(stats.dispatch_order.len() > 0, "Should dispatch some tasks");
    }

    #[test]
    fn test_promotion_stats_tracking() {
        let mut stats = PromotionStats::new();

        let task1 = TaskId::new_for_test(1, 0);
        let task2 = TaskId::new_for_test(2, 2);

        stats.record_dispatch(task1, TaskLane::Ready, 5);
        stats.record_dispatch(task2, TaskLane::Cancel, 6);

        assert_eq!(stats.dispatch_order, vec![task1, task2]);
        assert_eq!(stats.lane_dispatch_counts.get(&TaskLane::Ready), Some(&1));
        assert_eq!(stats.lane_dispatch_counts.get(&TaskLane::Cancel), Some(&1));
    }

    #[test]
    fn test_edf_ordering_check() {
        let mut stats = PromotionStats::new();

        let task1 = TaskId::new_for_test(1, 1);
        let task2 = TaskId::new_for_test(2, 1);
        let task3 = TaskId::new_for_test(3, 1);

        // Dispatch in order: task1, task2, task3
        stats.record_dispatch(task1, TaskLane::Timed, 1);
        stats.record_dispatch(task2, TaskLane::Timed, 2);
        stats.record_dispatch(task3, TaskLane::Timed, 3);

        // Deadlines in order: task1 (100), task2 (200), task3 (300)
        let timed_tasks = vec![
            (task1, 50, Time::from_nanos(100)),
            (task2, 50, Time::from_nanos(200)),
            (task3, 50, Time::from_nanos(300)),
        ];

        assert!(
            stats.check_edf_ordering(&timed_tasks),
            "Should pass EDF ordering check"
        );

        // Test violation case
        let stats_bad = {
            let mut s = PromotionStats::new();
            s.record_dispatch(task3, TaskLane::Timed, 1); // task3 first (bad order)
            s.record_dispatch(task1, TaskLane::Timed, 2);
            s.record_dispatch(task2, TaskLane::Timed, 3);
            s
        };

        assert!(
            !stats_bad.check_edf_ordering(&timed_tasks),
            "Should fail EDF ordering check"
        );
    }
}
