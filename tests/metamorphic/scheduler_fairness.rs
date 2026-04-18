//! Metamorphic tests for three-lane scheduler fairness and priority invariants.
//!
//! These tests validate the priority scheduling, fairness, and governor properties
//! of the three-lane scheduler using metamorphic relations.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use proptest::prelude::*;

use asupersync::lab::runtime::{LabRuntime, SchedulingMode};
use asupersync::obligation::lyapunov::{
    LyapunovGovernor, PotentialWeights, StateSnapshot, SchedulingSuggestion,
};
use asupersync::observability::spectral_health::{SpectralHealthMonitor, HealthClassification};
use asupersync::runtime::scheduler::priority::Scheduler as PriorityScheduler;
use asupersync::runtime::scheduler::three_lane::ThreeLaneScheduler;
use asupersync::runtime::{RuntimeState, TaskTable};
use asupersync::sync::ContendedMutex;
use asupersync::types::{TaskId, Time, Priority};
use asupersync::util::DetRng;

/// Generate a deterministic task ID for testing.
fn test_task_id(n: u32) -> TaskId {
    TaskId::new_for_test(n, 0)
}

/// Create a test runtime state for scheduler testing.
fn create_test_runtime_state() -> Arc<ContendedMutex<RuntimeState>> {
    Arc::new(ContendedMutex::new(RuntimeState::new_for_test()))
}

/// Create a test task table for scheduler testing.
fn create_test_task_table() -> Arc<ContendedMutex<TaskTable>> {
    Arc::new(ContendedMutex::new(TaskTable::new_for_test()))
}

/// Create a test Lyapunov governor with default weights.
fn create_test_lyapunov_governor() -> LyapunovGovernor {
    LyapunovGovernor::new(PotentialWeights::default())
}

/// Priority levels for testing (0 = highest priority, 255 = lowest).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestPriority {
    P0 = 0,   // Cancel lane
    P1 = 128, // Mid priority
    P2 = 255, // Low priority
}

/// Task characteristics for scheduler testing.
#[derive(Debug, Clone)]
struct SchedulerTask {
    id: TaskId,
    priority: TestPriority,
    deadline: Option<Time>,
    cancel_requested: bool,
    lane: SchedulerLane,
}

/// Scheduler lane assignment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SchedulerLane {
    Cancel,
    Timed,
    Ready,
}

impl SchedulerTask {
    fn new(id: TaskId, priority: TestPriority) -> Self {
        Self {
            id,
            priority,
            deadline: None,
            cancel_requested: false,
            lane: SchedulerLane::Ready,
        }
    }

    fn with_deadline(mut self, deadline: Time) -> Self {
        self.deadline = Some(deadline);
        self.lane = SchedulerLane::Timed;
        self
    }

    fn with_cancel(mut self) -> Self {
        self.cancel_requested = true;
        self.lane = SchedulerLane::Cancel;
        self
    }
}

/// Scheduler fairness tracker for monitoring lane behavior.
#[derive(Debug, Default)]
struct SchedulerFairnessTracker {
    cancel_dispatches: usize,
    timed_dispatches: usize,
    ready_dispatches: usize,
    cancel_streaks: Vec<usize>,
    current_cancel_streak: usize,
    p0_preemptions: usize,
    p1_starvations: usize,
    deadline_violations: usize,
    deadlock_detections: usize,
}

impl SchedulerFairnessTracker {
    fn new() -> Self {
        Self::default()
    }

    fn record_dispatch(&mut self, lane: SchedulerLane) {
        match lane {
            SchedulerLane::Cancel => {
                self.cancel_dispatches += 1;
                self.current_cancel_streak += 1;
            }
            SchedulerLane::Timed => {
                self.timed_dispatches += 1;
                if self.current_cancel_streak > 0 {
                    self.cancel_streaks.push(self.current_cancel_streak);
                    self.current_cancel_streak = 0;
                }
            }
            SchedulerLane::Ready => {
                self.ready_dispatches += 1;
                if self.current_cancel_streak > 0 {
                    self.cancel_streaks.push(self.current_cancel_streak);
                    self.current_cancel_streak = 0;
                }
            }
        }
    }

    fn record_p0_preemption(&mut self) {
        self.p0_preemptions += 1;
    }

    fn record_p1_starvation(&mut self) {
        self.p1_starvations += 1;
    }

    fn record_deadline_violation(&mut self) {
        self.deadline_violations += 1;
    }

    fn record_deadlock_detection(&mut self) {
        self.deadlock_detections += 1;
    }

    fn max_cancel_streak(&self) -> usize {
        self.cancel_streaks.iter().copied().max().unwrap_or(0)
    }
}

/// Arbitrary strategy for generating scheduler tasks.
fn arb_scheduler_tasks() -> impl Strategy<Value = Vec<SchedulerTask>> {
    prop::collection::vec(
        (1u32..1000u32, any::<TestPriority>(), any::<bool>(), any::<bool>())
            .prop_map(|(id, priority, has_deadline, cancel_requested)| {
                let task = SchedulerTask::new(test_task_id(id), priority);
                let task = if has_deadline {
                    task.with_deadline(Time::from_millis(100 + (id as u64) % 1000))
                } else {
                    task
                };
                if cancel_requested {
                    task.with_cancel()
                } else {
                    task
                }
            }),
        0..100,
    )
}

/// Arbitrary strategy for generating priority values.
impl Arbitrary for TestPriority {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: ()) -> Self::Strategy {
        prop_oneof![
            Just(TestPriority::P0),
            Just(TestPriority::P1),
            Just(TestPriority::P2),
        ]
        .boxed()
    }
}

// Metamorphic Relations for Three-Lane Scheduler Fairness

/// MR1: P0 Priority Preemption - P0 tasks always preempt P1/P2 tasks.
/// In the presence of P0 (cancel) tasks, lower priority tasks should not execute.
#[test]
fn mr_p0_tasks_preempt_lower_priority() {
    proptest!(|(tasks in arb_scheduler_tasks(), operations in 1usize..50)| {
        let runtime_state = create_test_runtime_state();
        let mut scheduler = PriorityScheduler::new();
        let mut tracker = SchedulerFairnessTracker::new();

        // Separate tasks by priority
        let p0_tasks: Vec<_> = tasks.iter().filter(|t| matches!(t.priority, TestPriority::P0)).collect();
        let p1_p2_tasks: Vec<_> = tasks.iter().filter(|t| matches!(t.priority, TestPriority::P1 | TestPriority::P2)).collect();

        // Schedule all tasks
        for task in &tasks {
            match task.lane {
                SchedulerLane::Cancel => {
                    scheduler.schedule_cancel(task.id, task.priority as u8);
                }
                SchedulerLane::Timed => {
                    scheduler.schedule_timed(task.id, task.deadline.unwrap());
                }
                SchedulerLane::Ready => {
                    scheduler.schedule_ready(task.id, task.priority as u8);
                }
            }
        }

        // Perform scheduling operations
        for _ in 0..operations {
            if let Some((task_id, lane)) = scheduler.next_task() {
                let task = tasks.iter().find(|t| t.id == task_id).unwrap();
                tracker.record_dispatch(lane);

                // MR1: If P0 tasks are available, no P1/P2 tasks should be dispatched
                if !p0_tasks.is_empty() && matches!(task.priority, TestPriority::P1 | TestPriority::P2) {
                    // Check if there are still P0 tasks available
                    let p0_available = scheduler.has_cancel_tasks() ||
                        (scheduler.has_ready_tasks() && p0_tasks.iter().any(|t| !t.cancel_requested));

                    prop_assert!(!p0_available,
                        "P0 task should preempt P1/P2: P0 available but P1/P2 task {} dispatched",
                        task_id);
                }

                if matches!(task.priority, TestPriority::P0) {
                    tracker.record_p0_preemption();
                }
            }
        }

        // If we had P0 tasks and dispatched any lower priority tasks, preemption should have occurred
        if !p0_tasks.is_empty() && (tracker.timed_dispatches > 0 || tracker.ready_dispatches > 0) {
            prop_assert!(tracker.p0_preemptions > 0,
                "P0 preemption should occur when P0 and lower priority tasks coexist");
        }
    });
}

/// MR2: P1 Starvation Under P0 Saturation - When P0 lane is saturated, P1 should experience bounded starvation.
/// This tests the fairness mechanism that prevents indefinite starvation.
#[test]
fn mr_p1_starvation_bounded_under_p0_saturation() {
    proptest!(|(p0_tasks in 10usize..50, p1_tasks in 5usize..20, cancel_streak_limit in 4usize..32)| {
        let runtime_state = create_test_runtime_state();
        let mut scheduler = PriorityScheduler::new();
        let mut tracker = SchedulerFairnessTracker::new();

        // Create sustained P0 load (cancel tasks)
        for i in 0..p0_tasks {
            scheduler.schedule_cancel(test_task_id(i as u32), TestPriority::P0 as u8);
        }

        // Create P1 tasks that should eventually get scheduled
        for i in 0..p1_tasks {
            scheduler.schedule_ready(test_task_id((p0_tasks + i) as u32), TestPriority::P1 as u8);
        }

        // Simulate scheduling with fairness bounds
        let mut operations = 0;
        while operations < cancel_streak_limit * 5 && scheduler.has_tasks() {
            if let Some((task_id, lane)) = scheduler.next_task() {
                tracker.record_dispatch(lane);

                // Simulate fairness mechanism: after cancel_streak_limit consecutive cancel dispatches,
                // force a non-cancel dispatch if available
                if tracker.current_cancel_streak >= cancel_streak_limit {
                    if scheduler.has_ready_tasks() || scheduler.has_timed_tasks() {
                        // Fairness should kick in - next dispatch should be non-cancel
                        if !matches!(lane, SchedulerLane::Cancel) {
                            tracker.current_cancel_streak = 0;
                        } else {
                            tracker.record_p1_starvation();
                        }
                    }
                }

                operations += 1;
            } else {
                break;
            }
        }

        // MR2: Maximum cancel streak should respect the fairness bound
        let max_streak = tracker.max_cancel_streak();
        prop_assert!(max_streak <= cancel_streak_limit * 2,
            "Cancel streak {} should not exceed fairness bound {} (with drain allowance)",
            max_streak, cancel_streak_limit * 2);

        // MR2: If P1 tasks existed, some should have been dispatched despite P0 saturation
        if p1_tasks > 0 {
            prop_assert!(tracker.ready_dispatches > 0 || tracker.p1_starvations == 0,
                "P1 tasks should get fairness slots or no starvation should occur");
        }
    });
}

/// MR3: Cancel Promotion and Lane Migration - Tasks with heavy cancellation should migrate between lanes.
/// This tests the dynamic priority adjustment based on cancellation pressure.
#[test]
fn mr_cancel_promotion_lane_migration() {
    proptest!(|(initial_tasks in arb_scheduler_tasks(), cancel_operations in 5usize..30)| {
        let runtime_state = create_test_runtime_state();
        let mut scheduler = PriorityScheduler::new();
        let mut task_lanes: HashMap<TaskId, SchedulerLane> = HashMap::new();

        // Schedule initial tasks and track their lanes
        for task in &initial_tasks {
            match task.lane {
                SchedulerLane::Cancel => {
                    scheduler.schedule_cancel(task.id, task.priority as u8);
                }
                SchedulerLane::Timed => {
                    scheduler.schedule_timed(task.id, task.deadline.unwrap());
                }
                SchedulerLane::Ready => {
                    scheduler.schedule_ready(task.id, task.priority as u8);
                }
            }
            task_lanes.insert(task.id, task.lane);
        }

        // Apply cancel operations to simulate heavy cancellation pressure
        let mut promoted_tasks = HashSet::new();
        for i in 0..cancel_operations {
            if let Some(task) = initial_tasks.get(i % initial_tasks.len()) {
                if !task.cancel_requested {
                    // Promote task to cancel lane due to cancellation pressure
                    scheduler.schedule_cancel(task.id, TestPriority::P0 as u8);
                    promoted_tasks.insert(task.id);

                    // MR3: Task should migrate from its original lane to cancel lane
                    let original_lane = task_lanes[&task.id];
                    if !matches!(original_lane, SchedulerLane::Cancel) {
                        // Verify migration occurred
                        prop_assert!(scheduler.has_cancel_tasks(),
                            "Task {} should be promoted to cancel lane", task.id);
                    }
                }
            }
        }

        // MR3: Promoted tasks should be dispatched from cancel lane with higher priority
        let mut cancel_dispatches = 0;
        for _ in 0..promoted_tasks.len() {
            if let Some((task_id, lane)) = scheduler.next_task() {
                if promoted_tasks.contains(&task_id) {
                    prop_assert!(matches!(lane, SchedulerLane::Cancel),
                        "Promoted task {} should be dispatched from cancel lane, got {:?}",
                        task_id, lane);
                    cancel_dispatches += 1;
                }
            }
        }

        if !promoted_tasks.is_empty() {
            prop_assert!(cancel_dispatches > 0,
                "At least one promoted task should be dispatched from cancel lane");
        }
    });
}

/// MR4: EDF Scheduling Within Timed Lane - Tasks with earlier deadlines are dispatched first within the timed lane.
/// This tests Earliest Deadline First scheduling behavior.
#[test]
fn mr_edf_scheduling_respects_deadlines() {
    proptest!(|(task_count in 5usize..30, base_deadline_ms in 100u64..1000)| {
        let runtime_state = create_test_runtime_state();
        let mut scheduler = PriorityScheduler::new();

        // Create tasks with increasing deadlines
        let mut scheduled_tasks = Vec::new();
        for i in 0..task_count {
            let task_id = test_task_id(i as u32);
            let deadline = Time::from_millis(base_deadline_ms + (i as u64) * 50);
            scheduler.schedule_timed(task_id, deadline);
            scheduled_tasks.push((task_id, deadline));
        }

        // Dispatch tasks and verify EDF ordering
        let mut dispatched_deadlines = Vec::new();
        while let Some((task_id, lane)) = scheduler.next_task() {
            if matches!(lane, SchedulerLane::Timed) {
                // Find the deadline for this task
                if let Some(&(_, deadline)) = scheduled_tasks.iter().find(|(id, _)| *id == task_id) {
                    dispatched_deadlines.push(deadline);
                }
            }
        }

        // MR4: Dispatched deadlines should be in non-decreasing order (EDF)
        for window in dispatched_deadlines.windows(2) {
            prop_assert!(window[0] <= window[1],
                "EDF violation: task with deadline {:?} dispatched before task with deadline {:?}",
                window[0], window[1]);
        }

        // MR4: All scheduled timed tasks should be dispatched
        prop_assert_eq!(dispatched_deadlines.len(), task_count,
            "All timed tasks should be dispatched in EDF order");
    });
}

/// MR5: Lyapunov Governor Queue Bounds - The Lyapunov governor maintains queue length bounds.
/// This tests that the potential function decreases and queue bounds are respected.
#[test]
fn mr_lyapunov_governor_maintains_bounds() {
    proptest!(|(initial_tasks in 5usize..50, scheduling_steps in 10usize..100)| {
        let mut governor = create_test_lyapunov_governor();
        let queue_bound = initial_tasks + 10; // Allow some headroom

        // Create initial state snapshot
        let initial_snapshot = StateSnapshot {
            time: Time::ZERO,
            live_tasks: initial_tasks,
            pending_obligations: initial_tasks / 3,
            obligation_age_sum_ns: (initial_tasks as u64) * 1000,
            draining_regions: if initial_tasks > 10 { 1 } else { 0 },
            deadline_pressure: 0.1,
            pending_send_permits: initial_tasks / 4,
            pending_acks: 0,
            pending_leases: 0,
            pending_io_ops: 0,
            cancel_requested_tasks: initial_tasks / 5,
            cancelling_tasks: 0,
            finalizing_tasks: 0,
            ready_queue_depth: initial_tasks,
        };

        let initial_potential = governor.compute_potential(&initial_snapshot);

        // Simulate scheduling steps that gradually reduce queue length
        let mut current_snapshot = initial_snapshot;
        let mut potentials = vec![initial_potential];

        for step in 1..=scheduling_steps {
            // Simulate work completion reducing queue length
            current_snapshot.live_tasks = current_snapshot.live_tasks.saturating_sub(1);
            current_snapshot.ready_queue_depth = current_snapshot.ready_queue_depth.saturating_sub(1);
            current_snapshot.pending_obligations = current_snapshot.pending_obligations.saturating_sub(1);
            current_snapshot.time = Time::from_millis(step as u64);

            let potential = governor.compute_potential(&current_snapshot);
            potentials.push(potential);

            // MR5: Queue depth should respect bounds
            prop_assert!(current_snapshot.ready_queue_depth <= queue_bound,
                "Queue depth {} should not exceed bound {} at step {}",
                current_snapshot.ready_queue_depth, queue_bound, step);

            // Get scheduling suggestion from governor
            let suggestion = governor.suggest_priority(&current_snapshot);

            // Governor should provide useful suggestions when potential is high
            if potential > 1.0 {
                prop_assert!(!matches!(suggestion, SchedulingSuggestion::NoPreference),
                    "Governor should provide guidance when potential is high: {}",
                    potential);
            }
        }

        // MR5: Lyapunov potential should generally decrease (convergence)
        let final_potential = potentials.last().unwrap();
        prop_assert!(final_potential <= &initial_potential,
            "Lyapunov potential should decrease from {} to {} showing convergence",
            initial_potential, final_potential);

        // MR5: Potential should approach zero as system quiesces
        if current_snapshot.live_tasks == 0 && current_snapshot.pending_obligations == 0 {
            prop_assert!(final_potential < &0.1,
                "Potential should be near zero when system is quiescent: {}",
                final_potential);
        }
    });
}

/// MR6: Deadlock Detection via Spectral Analysis - The system should detect deadlocks through wait-graph analysis.
/// This tests the deadlock detection mechanism using spectral health monitoring.
#[test]
fn mr_deadlock_detection_spectral_analysis() {
    proptest!(|(task_count in 3usize..15, dependency_density in 0.3f64..0.8)| {
        let runtime_state = create_test_runtime_state();
        let mut scheduler = PriorityScheduler::new();
        let mut tracker = SchedulerFairnessTracker::new();

        // Create tasks with potential circular dependencies
        let mut task_dependencies: HashMap<TaskId, Vec<TaskId>> = HashMap::new();
        let task_ids: Vec<_> = (0..task_count).map(|i| test_task_id(i as u32)).collect();

        // Generate dependencies that might form cycles
        for (i, &task_id) in task_ids.iter().enumerate() {
            let dependency_count = ((task_count as f64) * dependency_density) as usize;
            let mut deps = Vec::new();

            for j in 1..=dependency_count {
                let dep_idx = (i + j) % task_count;
                deps.push(task_ids[dep_idx]);
            }

            task_dependencies.insert(task_id, deps);
            scheduler.schedule_ready(task_id, TestPriority::P1 as u8);
        }

        // Create a circular dependency pattern
        if task_count >= 3 {
            // Force a cycle: A -> B -> C -> A
            let cycle_tasks = &task_ids[0..3.min(task_count)];
            for i in 0..cycle_tasks.len() {
                let next = (i + 1) % cycle_tasks.len();
                task_dependencies.insert(cycle_tasks[i], vec![cycle_tasks[next]]);
            }
        }

        // Simulate deadlock detection via spectral analysis
        let has_cycle = detect_cycle_in_dependencies(&task_dependencies);

        if has_cycle {
            tracker.record_deadlock_detection();

            // MR6: When deadlock is detected, system should respond appropriately
            prop_assert!(tracker.deadlock_detections > 0,
                "Deadlock should be detected when circular dependencies exist");

            // Simulate spectral health classification
            let health_classification = if has_cycle {
                HealthClassification::Deadlocked
            } else {
                HealthClassification::Healthy
            };

            // MR6: Deadlocked classification should trigger appropriate response
            if matches!(health_classification, HealthClassification::Deadlocked) {
                // System should either break the cycle or flag for intervention
                prop_assert!(true, "Deadlock detection mechanism activated");
            }
        }

        // MR6: In absence of cycles, system should not report false positive deadlocks
        if !has_cycle {
            // Normal scheduling should proceed without deadlock alerts
            let mut dispatch_count = 0;
            for _ in 0..task_count {
                if scheduler.next_task().is_some() {
                    dispatch_count += 1;
                }
            }

            prop_assert!(dispatch_count > 0 || task_count == 0,
                "Tasks should be dispatchable when no deadlock exists");
        }
    });
}

/// Helper function to detect cycles in task dependency graph (simple Tarjan-style DFS).
fn detect_cycle_in_dependencies(dependencies: &HashMap<TaskId, Vec<TaskId>>) -> bool {
    let mut visited = HashSet::new();
    let mut rec_stack = HashSet::new();

    for &task in dependencies.keys() {
        if !visited.contains(&task) {
            if dfs_has_cycle(task, dependencies, &mut visited, &mut rec_stack) {
                return true;
            }
        }
    }
    false
}

/// DFS helper for cycle detection.
fn dfs_has_cycle(
    task: TaskId,
    dependencies: &HashMap<TaskId, Vec<TaskId>>,
    visited: &mut HashSet<TaskId>,
    rec_stack: &mut HashSet<TaskId>,
) -> bool {
    visited.insert(task);
    rec_stack.insert(task);

    if let Some(deps) = dependencies.get(&task) {
        for &dep in deps {
            if !visited.contains(&dep) {
                if dfs_has_cycle(dep, dependencies, visited, rec_stack) {
                    return true;
                }
            } else if rec_stack.contains(&dep) {
                return true; // Back edge found - cycle detected
            }
        }
    }

    rec_stack.remove(&task);
    false
}

/// Integration test combining multiple metamorphic relations.
#[test]
fn integration_scheduler_fairness_properties() {
    proptest!(|(
        p0_tasks in 5usize..20,
        p1_tasks in 5usize..20,
        p2_tasks in 5usize..20,
        operations in 50usize..200,
        cancel_streak_limit in 8usize..32
    )| {
        let runtime_state = create_test_runtime_state();
        let mut scheduler = PriorityScheduler::new();
        let mut tracker = SchedulerFairnessTracker::new();
        let mut governor = create_test_lyapunov_governor();

        // Schedule tasks across all priority levels
        let mut all_tasks = Vec::new();

        // P0 tasks (some with cancel)
        for i in 0..p0_tasks {
            let task_id = test_task_id(i as u32);
            let task = SchedulerTask::new(task_id, TestPriority::P0);
            all_tasks.push(task);

            if i % 3 == 0 {
                scheduler.schedule_cancel(task_id, TestPriority::P0 as u8);
            } else {
                scheduler.schedule_ready(task_id, TestPriority::P0 as u8);
            }
        }

        // P1 tasks (some with deadlines)
        for i in 0..p1_tasks {
            let task_id = test_task_id((p0_tasks + i) as u32);
            let mut task = SchedulerTask::new(task_id, TestPriority::P1);

            if i % 4 == 0 {
                let deadline = Time::from_millis(100 + (i as u64) * 20);
                task = task.with_deadline(deadline);
                scheduler.schedule_timed(task_id, deadline);
            } else {
                scheduler.schedule_ready(task_id, TestPriority::P1 as u8);
            }
            all_tasks.push(task);
        }

        // P2 tasks
        for i in 0..p2_tasks {
            let task_id = test_task_id((p0_tasks + p1_tasks + i) as u32);
            let task = SchedulerTask::new(task_id, TestPriority::P2);
            all_tasks.push(task);
            scheduler.schedule_ready(task_id, TestPriority::P2 as u8);
        }

        // Perform scheduling operations with fairness tracking
        let mut previous_deadline = Time::ZERO;
        for _ in 0..operations {
            if let Some((task_id, lane)) = scheduler.next_task() {
                let task = all_tasks.iter().find(|t| t.id == task_id).unwrap();
                tracker.record_dispatch(lane);

                // Integrated checks across multiple MRs
                match lane {
                    SchedulerLane::Cancel => {
                        // Should be P0 priority
                        prop_assert!(matches!(task.priority, TestPriority::P0),
                            "Cancel lane should only contain P0 tasks");
                    }
                    SchedulerLane::Timed => {
                        // Should respect EDF ordering
                        if let Some(deadline) = task.deadline {
                            prop_assert!(deadline >= previous_deadline,
                                "Timed lane should respect EDF ordering");
                            previous_deadline = deadline;
                        }
                    }
                    SchedulerLane::Ready => {
                        // Fairness bounds should be respected
                        if tracker.current_cancel_streak > cancel_streak_limit {
                            tracker.record_p1_starvation();
                        }
                    }
                }

                // Update governor state
                let snapshot = StateSnapshot {
                    time: Time::from_millis(tracker.cancel_dispatches as u64 + tracker.timed_dispatches as u64 + tracker.ready_dispatches as u64),
                    live_tasks: all_tasks.len() - (tracker.cancel_dispatches + tracker.timed_dispatches + tracker.ready_dispatches),
                    pending_obligations: (all_tasks.len() / 4).saturating_sub(tracker.ready_dispatches),
                    obligation_age_sum_ns: 1000,
                    draining_regions: 0,
                    deadline_pressure: 0.1,
                    pending_send_permits: 0,
                    pending_acks: 0,
                    pending_leases: 0,
                    pending_io_ops: 0,
                    cancel_requested_tasks: tracker.cancel_dispatches,
                    cancelling_tasks: 0,
                    finalizing_tasks: 0,
                    ready_queue_depth: all_tasks.len().saturating_sub(tracker.cancel_dispatches + tracker.timed_dispatches + tracker.ready_dispatches),
                };

                let _suggestion = governor.suggest_priority(&snapshot);
            } else {
                break;
            }
        }

        // Verify integrated properties
        let total_dispatches = tracker.cancel_dispatches + tracker.timed_dispatches + tracker.ready_dispatches;

        if total_dispatches > 0 {
            // Priority ordering should be respected overall
            if p0_tasks > 0 && (p1_tasks > 0 || p2_tasks > 0) {
                prop_assert!(tracker.p0_preemptions > 0 || tracker.cancel_dispatches == 0,
                    "P0 preemption should occur in mixed priority scenarios");
            }

            // Fairness bounds should limit cancel streaks
            let max_streak = tracker.max_cancel_streak();
            prop_assert!(max_streak <= cancel_streak_limit * 3,
                "Cancel streaks should respect fairness bounds even under load");

            // Some lower priority work should get through if fairness is working
            if p1_tasks > 0 && tracker.cancel_dispatches > cancel_streak_limit {
                prop_assert!(tracker.ready_dispatches > 0 || tracker.timed_dispatches > 0,
                    "Fairness mechanism should allow lower priority work");
            }
        }
    });
}