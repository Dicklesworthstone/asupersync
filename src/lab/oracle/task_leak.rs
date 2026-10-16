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
    /// Violations captured at the moment a region closes.
    violations: Vec<TaskLeakViolation>,
}

impl TaskLeakOracle {
    /// Creates a new task leak oracle.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn record_leaked_tasks(
        &mut self,
        region: RegionId,
        region_close_time: Time,
        leaked_tasks: impl IntoIterator<Item = TaskId>,
    ) {
        if let Some(existing) = self
            .violations
            .iter_mut()
            .find(|violation| violation.region == region)
        {
            for task in leaked_tasks {
                if !existing.leaked_tasks.contains(&task) {
                    existing.leaked_tasks.push(task);
                }
            }
            existing.leaked_tasks.sort();
            return;
        }

        let mut leaked_tasks: Vec<TaskId> = leaked_tasks.into_iter().collect();
        leaked_tasks.sort();

        if !leaked_tasks.is_empty() {
            self.violations.push(TaskLeakViolation {
                region,
                leaked_tasks,
                region_close_time,
            });
        }
    }

    /// Records a task spawn event.
    pub fn on_spawn(&mut self, task: TaskId, region: RegionId, _time: Time) {
        self.tasks_by_region.entry(region).or_default().insert(task);

        if let Some(&region_close_time) = self.region_closes.get(&region) {
            // A post-close spawn is itself a structured-concurrency violation,
            // even if the task later completes.
            self.record_leaked_tasks(region, region_close_time, [task]);
        }
    }

    /// Records a task completion event.
    pub fn on_complete(&mut self, task: TaskId, _time: Time) {
        self.completed_tasks.insert(task);
    }

    /// Records a region close event.
    pub fn on_region_close(&mut self, region: RegionId, time: Time) {
        self.region_closes.insert(region, time);

        let Some(tasks) = self.tasks_by_region.get(&region) else {
            return;
        };

        let mut leaked: Vec<TaskId> = tasks
            .iter()
            .copied()
            .filter(|task| !self.completed_tasks.contains(task))
            .collect();
        leaked.sort();

        self.record_leaked_tasks(region, time, leaked);
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
        if let Some(violation) = self
            .violations
            .iter()
            .min_by_key(|violation| (violation.region, violation.region_close_time))
        {
            return Err(violation.clone());
        }

        Ok(())
    }

    /// Resets the oracle to its initial state.
    pub fn reset(&mut self) {
        self.tasks_by_region.clear();
        self.completed_tasks.clear();
        self.region_closes.clear();
        self.violations.clear();
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
#[path = "task_leak_inline_tests.rs"]
mod tests;
