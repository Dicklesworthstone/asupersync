//! Task leak oracle for verifying invariant #1: no orphan tasks.
//!
//! This oracle verifies that every task spawned within a region completes
//! before that region closes, ensuring structured concurrency.
//!
//! # Invariant
//!
//! From asupersync_plan_v4.md:
//! > Structured concurrency – every task is owned by exactly one region
//!
//! Formally: `∀r ∈ closed_regions: ∀t ∈ tasks(r): t.state = Completed`
//!
//! # Usage
//!
//! ```ignore
//! let mut oracle = TaskLeakOracle::new();
//!
//! // During execution, record events:
//! oracle.on_spawn(task_id, region_id, time);
//! oracle.on_complete(task_id, time);
//! oracle.on_region_close(region_id, time);
//!
//! // At end of test, verify:
//! oracle.check(now)?;
//! ```

use crate::types::{RegionId, TaskId, Time};
use std::collections::{HashMap, HashSet};
use std::fmt;

/// A task leak violation.
///
/// This indicates that a region closed while some of its tasks had not
/// completed, violating the structured concurrency invariant.
#[derive(Debug, Clone)]
pub struct TaskLeakViolation {
    /// The region that closed with leaked tasks.
    pub region: RegionId,
    /// The tasks that were not completed when the region closed.
    pub leaked_tasks: Vec<TaskId>,
    /// The time when the region closed.
    pub region_close_time: Time,
}

impl fmt::Display for TaskLeakViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Region {:?} closed at {:?} with {} leaked task(s): {:?}",
            self.region,
            self.region_close_time,
            self.leaked_tasks.len(),
            self.leaked_tasks
        )
    }
}

impl std::error::Error for TaskLeakViolation {}

/// Oracle for detecting task leak violations.
///
/// Tracks task spawns, completions, and region closes to verify that
/// all tasks complete before their owning region closes.
#[derive(Debug, Default)]
pub struct TaskLeakOracle {
    /// Tasks by region: region -> set of tasks spawned in that region.
    tasks_by_region: HashMap<RegionId, HashSet<TaskId>>,
    /// Completed tasks.
    completed_tasks: HashSet<TaskId>,
    /// Region close records: region -> close_time.
    region_closes: HashMap<RegionId, Time>,
}

impl TaskLeakOracle {
    /// Creates a new task leak oracle.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a task spawn event.
    pub fn on_spawn(&mut self, task: TaskId, region: RegionId, _time: Time) {
        self.tasks_by_region.entry(region).or_default().insert(task);
    }

    /// Records a task completion event.
    pub fn on_complete(&mut self, task: TaskId, _time: Time) {
        self.completed_tasks.insert(task);
    }

    /// Records a region close event.
    pub fn on_region_close(&mut self, region: RegionId, time: Time) {
        self.region_closes.insert(region, time);
    }

    /// Verifies the invariant holds.
    ///
    /// Checks that for every closed region, all its tasks have completed.
    /// Returns an error with the first violation found.
    ///
    /// # Returns
    /// * `Ok(())` if no violations are found
    /// * `Err(TaskLeakViolation)` if a violation is detected
    pub fn check(&self, _now: Time) -> Result<(), TaskLeakViolation> {
        for (&region, &close_time) in &self.region_closes {
            let Some(tasks) = self.tasks_by_region.get(&region) else {
                continue; // No tasks spawned in this region
            };

            let mut leaked = Vec::new();

            for &task in tasks {
                if !self.completed_tasks.contains(&task) {
                    leaked.push(task);
                }
            }

            if !leaked.is_empty() {
                return Err(TaskLeakViolation {
                    region,
                    leaked_tasks: leaked,
                    region_close_time: close_time,
                });
            }
        }

        Ok(())
    }

    /// Resets the oracle to its initial state.
    pub fn reset(&mut self) {
        self.tasks_by_region.clear();
        self.completed_tasks.clear();
        self.region_closes.clear();
    }

    /// Returns the number of tracked tasks.
    #[must_use]
    pub fn task_count(&self) -> usize {
        self.tasks_by_region.values().map(HashSet::len).sum()
    }

    /// Returns the number of completed tasks.
    #[must_use]
    pub fn completed_count(&self) -> usize {
        self.completed_tasks.len()
    }

    /// Returns the number of closed regions.
    #[must_use]
    pub fn closed_region_count(&self) -> usize {
        self.region_closes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::ArenaIndex;

    fn task(n: u32) -> TaskId {
        TaskId::from_arena(ArenaIndex::new(n, 0))
    }

    fn region(n: u32) -> RegionId {
        RegionId::from_arena(ArenaIndex::new(n, 0))
    }

    fn t(nanos: u64) -> Time {
        Time::from_nanos(nanos)
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn no_tasks_passes() {
        init_test("no_tasks_passes");
        let oracle = TaskLeakOracle::new();
        let ok = oracle.check(t(100)).is_ok();
        crate::assert_with_log!(ok, "ok", true, ok);
        crate::test_complete!("no_tasks_passes");
    }

    #[test]
    fn all_tasks_complete_passes() {
        init_test("all_tasks_complete_passes");
        let mut oracle = TaskLeakOracle::new();

        oracle.on_spawn(task(1), region(0), t(10));
        oracle.on_spawn(task(2), region(0), t(20));

        oracle.on_complete(task(1), t(50));
        oracle.on_complete(task(2), t(60));

        oracle.on_region_close(region(0), t(100));

        let ok = oracle.check(t(100)).is_ok();
        crate::assert_with_log!(ok, "ok", true, ok);
        crate::test_complete!("all_tasks_complete_passes");
    }

    #[test]
    fn leaked_task_fails() {
        init_test("leaked_task_fails");
        let mut oracle = TaskLeakOracle::new();

        oracle.on_spawn(task(1), region(0), t(10));
        oracle.on_spawn(task(2), region(0), t(20));

        // Only task 1 completes
        oracle.on_complete(task(1), t(50));

        oracle.on_region_close(region(0), t(100));

        let result = oracle.check(t(100));
        let err = result.is_err();
        crate::assert_with_log!(err, "err", true, err);

        let violation = result.unwrap_err();
        crate::assert_with_log!(
            violation.region == region(0),
            "region",
            region(0),
            violation.region
        );
        crate::assert_with_log!(
            violation.leaked_tasks == vec![task(2)],
            "leaked_tasks",
            vec![task(2)],
            violation.leaked_tasks
        );
        crate::assert_with_log!(
            violation.region_close_time == t(100),
            "close_time",
            t(100),
            violation.region_close_time
        );
        crate::test_complete!("leaked_task_fails");
    }

    #[test]
    fn no_tasks_complete_all_leak() {
        init_test("no_tasks_complete_all_leak");
        let mut oracle = TaskLeakOracle::new();

        oracle.on_spawn(task(1), region(0), t(10));
        oracle.on_spawn(task(2), region(0), t(20));

        // No tasks complete
        oracle.on_region_close(region(0), t(100));

        let result = oracle.check(t(100));
        let err = result.is_err();
        crate::assert_with_log!(err, "err", true, err);

        let violation = result.unwrap_err();
        let len = violation.leaked_tasks.len();
        crate::assert_with_log!(len == 2, "leaked_tasks len", 2, len);
        crate::test_complete!("no_tasks_complete_all_leak");
    }

    #[test]
    fn multiple_regions_independent() {
        init_test("multiple_regions_independent");
        let mut oracle = TaskLeakOracle::new();

        // Region 0: task completes
        oracle.on_spawn(task(1), region(0), t(10));
        oracle.on_complete(task(1), t(50));
        oracle.on_region_close(region(0), t(100));

        // Region 1: task does NOT complete
        oracle.on_spawn(task(2), region(1), t(20));
        oracle.on_region_close(region(1), t(100));

        let result = oracle.check(t(100));
        let err = result.is_err();
        crate::assert_with_log!(err, "err", true, err);

        let violation = result.unwrap_err();
        crate::assert_with_log!(
            violation.region == region(1),
            "region",
            region(1),
            violation.region
        );
        crate::assert_with_log!(
            violation.leaked_tasks == vec![task(2)],
            "leaked_tasks",
            vec![task(2)],
            violation.leaked_tasks
        );
        crate::test_complete!("multiple_regions_independent");
    }

    #[test]
    fn region_without_close_not_checked() {
        init_test("region_without_close_not_checked");
        let mut oracle = TaskLeakOracle::new();

        oracle.on_spawn(task(1), region(0), t(10));
        // task 1 never completes, but region never closes either

        let ok = oracle.check(t(100)).is_ok();
        crate::assert_with_log!(ok, "ok", true, ok);
        crate::test_complete!("region_without_close_not_checked");
    }

    #[test]
    fn reset_clears_state() {
        init_test("reset_clears_state");
        let mut oracle = TaskLeakOracle::new();

        oracle.on_spawn(task(1), region(0), t(10));
        oracle.on_region_close(region(0), t(100));

        // Would fail
        let err = oracle.check(t(100)).is_err();
        crate::assert_with_log!(err, "err", true, err);

        oracle.reset();

        // After reset, no violations
        let ok = oracle.check(t(100)).is_ok();
        crate::assert_with_log!(ok, "ok", true, ok);
        let task_count = oracle.task_count();
        crate::assert_with_log!(task_count == 0, "task_count", 0, task_count);
        let completed_count = oracle.completed_count();
        crate::assert_with_log!(completed_count == 0, "completed_count", 0, completed_count);
        let closed_count = oracle.closed_region_count();
        crate::assert_with_log!(closed_count == 0, "closed_count", 0, closed_count);
        crate::test_complete!("reset_clears_state");
    }

    #[test]
    fn violation_display() {
        init_test("violation_display");
        let violation = TaskLeakViolation {
            region: region(0),
            leaked_tasks: vec![task(1), task(2)],
            region_close_time: t(100),
        };

        let s = violation.to_string();
        let has_leaked = s.contains("leaked");
        crate::assert_with_log!(has_leaked, "leaked text", true, has_leaked);
        let has_two = s.contains('2');
        crate::assert_with_log!(has_two, "contains 2", true, has_two);
        crate::test_complete!("violation_display");
    }

    #[test]
    fn task_in_multiple_regions_ok() {
        init_test("task_in_multiple_regions_ok");
        // This tests the oracle's behavior - tasks should only be in one region
        // but if a bug causes them to be recorded in multiple, we check per-region
        let mut oracle = TaskLeakOracle::new();

        // Spawn same task in different regions (shouldn't happen in practice)
        oracle.on_spawn(task(1), region(0), t(10));
        oracle.on_spawn(task(1), region(1), t(20));

        oracle.on_complete(task(1), t(50));

        oracle.on_region_close(region(0), t(100));
        oracle.on_region_close(region(1), t(100));

        // Should pass because task 1 is marked complete
        let ok = oracle.check(t(100)).is_ok();
        crate::assert_with_log!(ok, "ok", true, ok);
        crate::test_complete!("task_in_multiple_regions_ok");
    }

    #[test]
    fn many_tasks_some_leaked() {
        init_test("many_tasks_some_leaked");
        let mut oracle = TaskLeakOracle::new();

        // Spawn 5 tasks
        for i in 1..=5 {
            oracle.on_spawn(task(i), region(0), t(u64::from(i) * 10));
        }

        // Complete only odd tasks
        oracle.on_complete(task(1), t(60));
        oracle.on_complete(task(3), t(70));
        oracle.on_complete(task(5), t(80));

        oracle.on_region_close(region(0), t(100));

        let result = oracle.check(t(100));
        let err = result.is_err();
        crate::assert_with_log!(err, "err", true, err);

        let violation = result.unwrap_err();
        // Tasks 2 and 4 should be leaked
        let len = violation.leaked_tasks.len();
        crate::assert_with_log!(len == 2, "leaked_tasks len", 2, len);
        let has_two = violation.leaked_tasks.contains(&task(2));
        crate::assert_with_log!(has_two, "contains task2", true, has_two);
        let has_four = violation.leaked_tasks.contains(&task(4));
        crate::assert_with_log!(has_four, "contains task4", true, has_four);
        crate::test_complete!("many_tasks_some_leaked");
    }
}
