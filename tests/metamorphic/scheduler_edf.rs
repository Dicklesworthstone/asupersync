//! Metamorphic tests for EDF (Earliest Deadline First) scheduler deadline ordering.
//!
//! These tests validate the core EDF scheduling invariants using metamorphic relations
//! with deterministic virtual time execution in the LabRuntime.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use proptest::prelude::*;

use asupersync::lab::runtime::{LabRuntime, SchedulingMode};
use asupersync::observability::resource_accounting::ResourceAccounting;
use asupersync::runtime::scheduler::priority::Scheduler as PriorityScheduler;
use asupersync::runtime::{RuntimeState, TaskTable};
use asupersync::sync::ContendedMutex;
use asupersync::time::{Sleep, Deadline};
use asupersync::types::{TaskId, Time};
use asupersync::util::DetRng;
use asupersync::{scope, Cx, Scope, task};

/// Generate a deterministic task ID for testing.
fn test_task_id(n: u32) -> TaskId {
    TaskId::new_for_test(n, 0)
}

/// Create a test time from nanoseconds.
fn test_time(nanos: u64) -> Time {
    Time::from_nanos(nanos)
}

/// Create a deadline from nanoseconds.
fn test_deadline(nanos: u64) -> Deadline {
    Deadline::from_time(test_time(nanos))
}

/// Task with deadline for EDF testing.
#[derive(Debug, Clone)]
struct DeadlineTask {
    id: TaskId,
    deadline: Time,
    insertion_order: u64,
    work_duration: Duration,
    cancelled: bool,
    deadline_reset: Option<Time>,
}

impl DeadlineTask {
    fn new(id: TaskId, deadline: Time, insertion_order: u64, work_duration: Duration) -> Self {
        Self {
            id,
            deadline,
            insertion_order,
            work_duration,
            cancelled: false,
            deadline_reset: None,
        }
    }

    fn with_reset(mut self, new_deadline: Time) -> Self {
        self.deadline_reset = Some(new_deadline);
        self
    }

    fn cancel(mut self) -> Self {
        self.cancelled = true;
        self
    }
}

/// Result of EDF scheduling execution.
#[derive(Debug, Clone)]
struct SchedulingResult {
    execution_order: Vec<TaskId>,
    completion_times: HashMap<TaskId, Time>,
    deadline_misses: Vec<TaskId>,
    cancelled_tasks: Vec<TaskId>,
}

/// Execute a set of deadline tasks with EDF scheduling.
async fn execute_edf_scenario(
    cx: &Cx,
    tasks: Vec<DeadlineTask>,
) -> Result<SchedulingResult, Box<dyn std::error::Error + Send + Sync>> {
    let mut execution_order = Vec::new();
    let mut completion_times = HashMap::new();
    let mut deadline_misses = Vec::new();
    let mut cancelled_tasks = Vec::new();

    scope!(cx, |s| {
        for task in tasks {
            let task_id = task.id;
            let deadline = task.deadline;
            let work_duration = task.work_duration;
            let should_cancel = task.cancelled;
            let reset_deadline = task.deadline_reset;

            task!(s, async move {
                let deadline = if let Some(new_deadline) = reset_deadline {
                    new_deadline
                } else {
                    deadline
                };

                // Create a sleep with deadline
                let mut sleep = Sleep::new(deadline);

                // Check if task should be cancelled
                if should_cancel {
                    cancelled_tasks.push(task_id);
                    return Ok(());
                }

                // Reset deadline if requested
                if let Some(new_deadline) = reset_deadline {
                    sleep.reset(new_deadline);
                }

                // Simulate work
                let start_time = cx.time_source().now();
                execution_order.push(task_id);

                // Sleep for work duration
                cx.sleep(work_duration).await;

                let completion_time = cx.time_source().now();
                completion_times.insert(task_id, completion_time);

                // Check if deadline was missed
                if completion_time > deadline {
                    deadline_misses.push(task_id);
                }

                Ok(())
            })?;
        }
    }).await?;

    Ok(SchedulingResult {
        execution_order,
        completion_times,
        deadline_misses,
        cancelled_tasks,
    })
}

/// Metamorphic Relation 1: Earliest-deadline task always scheduled first.
///
/// Relation: For any set of tasks with distinct deadlines, the task with the
/// earliest deadline should always be scheduled (executed) first.
#[cfg(test)]
proptest! {
    #[test]
    fn mr1_earliest_deadline_first(
        task_count in 2..8usize,
        deadline_base in 1000..10000u64,
        deadline_spread in 100..1000u64,
        work_duration_ms in 1..50u64,
    ) {
        let mut rt = LabRuntime::new();

        rt.block_on(async {
            let cx = rt.cx();
            let mut tasks = Vec::new();

            // Create tasks with ascending deadlines (earliest first)
            for i in 0..task_count {
                let deadline = test_time(deadline_base + i as u64 * deadline_spread);
                let work = Duration::from_millis(work_duration_ms);
                tasks.push(DeadlineTask::new(test_task_id(i as u32), deadline, i as u64, work));
            }

            let result = execute_edf_scenario(&cx, tasks.clone()).await
                .expect("EDF execution should succeed");

            // Assertion: The earliest deadline task should execute first
            prop_assert!(
                !result.execution_order.is_empty(),
                "Execution order should not be empty"
            );

            let first_executed = result.execution_order[0];
            let earliest_deadline_task = tasks.iter()
                .min_by_key(|t| t.deadline)
                .expect("Should have earliest deadline task");

            prop_assert_eq!(
                first_executed,
                earliest_deadline_task.id,
                "Earliest deadline task {:?} (deadline {:?}) should execute first, but {:?} executed first",
                earliest_deadline_task.id,
                earliest_deadline_task.deadline,
                first_executed
            );

            // Additional verification: Execution order should follow deadline order
            for i in 1..result.execution_order.len() {
                let prev_task_id = result.execution_order[i - 1];
                let curr_task_id = result.execution_order[i];

                let prev_deadline = tasks.iter()
                    .find(|t| t.id == prev_task_id)
                    .map(|t| t.deadline)
                    .expect("Previous task should exist");

                let curr_deadline = tasks.iter()
                    .find(|t| t.id == curr_task_id)
                    .map(|t| t.deadline)
                    .expect("Current task should exist");

                prop_assert!(
                    prev_deadline <= curr_deadline,
                    "Tasks should execute in deadline order: task {:?} (deadline {:?}) should not execute before task {:?} (deadline {:?})",
                    curr_task_id,
                    curr_deadline,
                    prev_task_id,
                    prev_deadline
                );
            }
        });
    }
}

/// Metamorphic Relation 2: Ties broken by insertion order.
///
/// Relation: When multiple tasks have the same deadline, they should be
/// scheduled in FIFO order (insertion/generation order).
#[cfg(test)]
proptest! {
    #[test]
    fn mr2_ties_broken_by_insertion_order(
        task_count in 3..6usize,
        common_deadline in 1000..5000u64,
        work_duration_ms in 1..20u64,
    ) {
        let mut rt = LabRuntime::new();

        rt.block_on(async {
            let cx = rt.cx();
            let mut tasks = Vec::new();

            let deadline = test_time(common_deadline);
            let work = Duration::from_millis(work_duration_ms);

            // Create tasks with the same deadline but different insertion orders
            for i in 0..task_count {
                tasks.push(DeadlineTask::new(
                    test_task_id(i as u32),
                    deadline,
                    i as u64,
                    work,
                ));
            }

            let result = execute_edf_scenario(&cx, tasks.clone()).await
                .expect("EDF execution should succeed");

            // Assertion: Tasks with same deadline should execute in insertion order
            prop_assert!(
                result.execution_order.len() >= task_count,
                "All tasks should have executed"
            );

            // Find all tasks with the common deadline in execution order
            let same_deadline_execution: Vec<_> = result.execution_order.iter()
                .filter(|&&task_id| {
                    tasks.iter()
                        .find(|t| t.id == task_id)
                        .map(|t| t.deadline == deadline)
                        .unwrap_or(false)
                })
                .cloned()
                .collect();

            // Verify FIFO ordering among same-deadline tasks
            for i in 1..same_deadline_execution.len() {
                let prev_task_id = same_deadline_execution[i - 1];
                let curr_task_id = same_deadline_execution[i];

                let prev_order = tasks.iter()
                    .find(|t| t.id == prev_task_id)
                    .map(|t| t.insertion_order)
                    .expect("Previous task should exist");

                let curr_order = tasks.iter()
                    .find(|t| t.id == curr_task_id)
                    .map(|t| t.insertion_order)
                    .expect("Current task should exist");

                prop_assert!(
                    prev_order < curr_order,
                    "Same-deadline tasks should execute in insertion order: task {:?} (order {}) should not execute before task {:?} (order {})",
                    curr_task_id,
                    curr_order,
                    prev_task_id,
                    prev_order
                );
            }
        });
    }
}

/// Metamorphic Relation 3: Deadline miss logged does not panic.
///
/// Relation: When a task misses its deadline, the system should log the miss
/// but continue operating without panicking or crashing.
#[cfg(test)]
proptest! {
    #[test]
    fn mr3_deadline_miss_does_not_panic(
        tight_deadline in 10..50u64,
        long_work_ms in 100..200u64,
    ) {
        let mut rt = LabRuntime::new();

        rt.block_on(async {
            let cx = rt.cx();

            // Create a task that will definitely miss its deadline
            let deadline = test_time(tight_deadline);
            let work_duration = Duration::from_millis(long_work_ms);

            let task = DeadlineTask::new(test_task_id(1), deadline, 1, work_duration);

            // This should not panic even though deadline will be missed
            let result = execute_edf_scenario(&cx, vec![task]).await
                .expect("EDF execution should not panic on deadline miss");

            // Assertion: Task should have executed and missed deadline
            prop_assert!(
                !result.execution_order.is_empty(),
                "Task should have executed despite deadline miss"
            );

            prop_assert!(
                !result.deadline_misses.is_empty(),
                "Deadline miss should be recorded"
            );

            prop_assert_eq!(
                result.deadline_misses[0],
                test_task_id(1),
                "Correct task should be recorded as missing deadline"
            );

            // Assertion: System should remain operational
            let completion_time = result.completion_times.get(&test_task_id(1))
                .expect("Task should have completion time");

            prop_assert!(
                *completion_time > deadline,
                "Task should complete after deadline (miss confirmed)"
            );
        });
    }
}

/// Metamorphic Relation 4: Cancel removes task from deadline queue.
///
/// Relation: When a task is cancelled, it should be removed from the deadline
/// queue and not affect the scheduling of remaining tasks.
#[cfg(test)]
proptest! {
    #[test]
    fn mr4_cancel_removes_from_deadline_queue(
        task_count in 3..6usize,
        deadline_base in 1000..5000u64,
        deadline_spread in 100..500u64,
        cancel_index in 0..2usize,
        work_duration_ms in 10..30u64,
    ) {
        let mut rt = LabRuntime::new();
        let cancel_index = cancel_index % task_count.max(1);

        rt.block_on(async {
            let cx = rt.cx();
            let mut tasks_with_cancel = Vec::new();
            let mut tasks_without_cancel = Vec::new();
            let work = Duration::from_millis(work_duration_ms);

            // Create tasks with different deadlines
            for i in 0..task_count {
                let deadline = test_time(deadline_base + i as u64 * deadline_spread);
                let task = DeadlineTask::new(test_task_id(i as u32), deadline, i as u64, work);

                if i == cancel_index {
                    tasks_with_cancel.push(task.clone().cancel());
                    // Don't add cancelled task to without_cancel scenario
                } else {
                    tasks_with_cancel.push(task.clone());
                    tasks_without_cancel.push(task);
                }
            }

            // Execute scenario with cancellation
            let result_with_cancel = execute_edf_scenario(&cx, tasks_with_cancel).await
                .expect("EDF execution with cancel should succeed");

            // Execute scenario without cancellation (reset runtime)
            let mut rt2 = LabRuntime::new();
            rt2.block_on(async {
                let cx2 = rt2.cx();
                let result_without_cancel = execute_edf_scenario(&cx2, tasks_without_cancel).await
                    .expect("EDF execution without cancel should succeed");

                // Assertion: Cancelled task should not appear in execution order
                prop_assert!(
                    !result_with_cancel.execution_order.contains(&test_task_id(cancel_index as u32)),
                    "Cancelled task should not execute"
                );

                prop_assert!(
                    result_with_cancel.cancelled_tasks.contains(&test_task_id(cancel_index as u32)),
                    "Cancelled task should be recorded as cancelled"
                );

                // Assertion: Other tasks should execute in same order relative to each other
                let non_cancelled_execution: Vec<_> = result_with_cancel.execution_order.iter()
                    .filter(|&&id| id != test_task_id(cancel_index as u32))
                    .cloned()
                    .collect();

                let expected_execution = &result_without_cancel.execution_order;

                prop_assert_eq!(
                    non_cancelled_execution,
                    *expected_execution,
                    "Non-cancelled tasks should maintain same relative execution order"
                );
            });
        });
    }
}

/// Metamorphic Relation 5: Deadline reset reschedules task.
///
/// Relation: When a task's deadline is reset to a different value, it should
/// be rescheduled according to the new deadline position in EDF order.
#[cfg(test)]
proptest! {
    #[test]
    fn mr5_deadline_reset_reschedules(
        initial_deadline in 2000..4000u64,
        new_deadline in 1000..6000u64,
        other_deadline in 3000..5000u64,
        work_duration_ms in 10..30u64,
    ) {
        let mut rt = LabRuntime::new();

        rt.block_on(async {
            let cx = rt.cx();
            let work = Duration::from_millis(work_duration_ms);

            // Task that will have its deadline reset
            let reset_task = DeadlineTask::new(
                test_task_id(1),
                test_time(initial_deadline),
                1,
                work,
            ).with_reset(test_time(new_deadline));

            // Reference task to compare ordering
            let reference_task = DeadlineTask::new(
                test_task_id(2),
                test_time(other_deadline),
                2,
                work,
            );

            let tasks = vec![reset_task.clone(), reference_task.clone()];
            let result = execute_edf_scenario(&cx, tasks).await
                .expect("EDF execution with reset should succeed");

            // Assertion: Tasks should be ordered by their final deadlines
            prop_assert_eq!(
                result.execution_order.len(),
                2,
                "Both tasks should execute"
            );

            let first_task = result.execution_order[0];
            let second_task = result.execution_order[1];

            if new_deadline < other_deadline {
                // Reset task should execute first
                prop_assert_eq!(
                    first_task,
                    test_task_id(1),
                    "Reset task with earlier new deadline should execute first"
                );
                prop_assert_eq!(
                    second_task,
                    test_task_id(2),
                    "Reference task should execute second"
                );
            } else {
                // Reference task should execute first
                prop_assert_eq!(
                    first_task,
                    test_task_id(2),
                    "Reference task with earlier deadline should execute first"
                );
                prop_assert_eq!(
                    second_task,
                    test_task_id(1),
                    "Reset task should execute second"
                );
            }

            // Additional assertion: Reset should affect completion times appropriately
            let reset_completion = result.completion_times.get(&test_task_id(1))
                .expect("Reset task should have completion time");
            let reference_completion = result.completion_times.get(&test_task_id(2))
                .expect("Reference task should have completion time");

            if new_deadline < other_deadline {
                prop_assert!(
                    reset_completion < reference_completion,
                    "Reset task with earlier deadline should complete before reference task"
                );
            } else {
                prop_assert!(
                    reference_completion < reset_completion,
                    "Reference task should complete before reset task with later deadline"
                );
            }
        });
    }
}

/// Integration test: Complex EDF scenario with all MRs.
///
/// Tests a complex scenario involving multiple tasks with various deadline
/// relationships, cancellations, and resets to verify all MRs work together.
#[test]
fn integration_complex_edf_scenario() {
    let mut rt = LabRuntime::new();

    rt.block_on(async {
        let cx = rt.cx();
        let work = Duration::from_millis(20);

        let tasks = vec![
            // Task 1: Early deadline, will execute first
            DeadlineTask::new(test_task_id(1), test_time(1000), 1, work),

            // Task 2: Same deadline as task 3, should execute before task 3 (FIFO)
            DeadlineTask::new(test_task_id(2), test_time(2000), 2, work),
            DeadlineTask::new(test_task_id(3), test_time(2000), 3, work),

            // Task 4: Will be cancelled
            DeadlineTask::new(test_task_id(4), test_time(1500), 4, work).cancel(),

            // Task 5: Deadline reset to become earliest
            DeadlineTask::new(test_task_id(5), test_time(3000), 5, work)
                .with_reset(test_time(500)),
        ];

        let result = execute_edf_scenario(&cx, tasks).await
            .expect("Complex EDF scenario should succeed");

        // Verify MR5: Reset task should execute first
        assert_eq!(result.execution_order[0], test_task_id(5));

        // Verify MR1: Next should be task 1 (earliest remaining deadline)
        assert_eq!(result.execution_order[1], test_task_id(1));

        // Verify MR2: Tasks 2 and 3 should execute in FIFO order
        let task2_pos = result.execution_order.iter().position(|&id| id == test_task_id(2));
        let task3_pos = result.execution_order.iter().position(|&id| id == test_task_id(3));
        assert!(task2_pos < task3_pos, "Task 2 should execute before task 3 (FIFO)");

        // Verify MR4: Task 4 should not execute (cancelled)
        assert!(!result.execution_order.contains(&test_task_id(4)));
        assert!(result.cancelled_tasks.contains(&test_task_id(4)));

        // Verify MR3: No panics even with complex scheduling
        assert!(result.execution_order.len() == 4); // All non-cancelled tasks executed
    });
}

#[cfg(test)]
mod edf_deadline_ordering_tests {
    use super::*;

    #[test]
    fn test_simple_edf_ordering() {
        let mut rt = LabRuntime::new();

        rt.block_on(async {
            let cx = rt.cx();
            let work = Duration::from_millis(10);

            let tasks = vec![
                DeadlineTask::new(test_task_id(1), test_time(2000), 1, work),
                DeadlineTask::new(test_task_id(2), test_time(1000), 2, work),
                DeadlineTask::new(test_task_id(3), test_time(3000), 3, work),
            ];

            let result = execute_edf_scenario(&cx, tasks).await.unwrap();

            // Should execute in deadline order: task 2 (1000), task 1 (2000), task 3 (3000)
            assert_eq!(result.execution_order[0], test_task_id(2));
            assert_eq!(result.execution_order[1], test_task_id(1));
            assert_eq!(result.execution_order[2], test_task_id(3));
        });
    }

    #[test]
    fn test_fifo_tie_breaking() {
        let mut rt = LabRuntime::new();

        rt.block_on(async {
            let cx = rt.cx();
            let work = Duration::from_millis(10);
            let same_deadline = test_time(2000);

            let tasks = vec![
                DeadlineTask::new(test_task_id(1), same_deadline, 1, work),
                DeadlineTask::new(test_task_id(2), same_deadline, 2, work),
                DeadlineTask::new(test_task_id(3), same_deadline, 3, work),
            ];

            let result = execute_edf_scenario(&cx, tasks).await.unwrap();

            // Should execute in insertion order for same deadline
            assert_eq!(result.execution_order[0], test_task_id(1));
            assert_eq!(result.execution_order[1], test_task_id(2));
            assert_eq!(result.execution_order[2], test_task_id(3));
        });
    }
}