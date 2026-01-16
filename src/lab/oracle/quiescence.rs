//! Quiescence oracle for verifying invariant #2: region close = quiescence.
//!
//! This oracle verifies that when a region closes, all its tasks have completed
//! and all its child regions have closed.
//!
//! # Invariant
//!
//! From asupersync_plan_v4.md:
//! > Region close = quiescence: no live children + all finalizers done
//!
//! Formally: `∀r ∈ closed_regions: children(r) = ∅ ∧ tasks(r) = ∅`
//!
//! # Usage
//!
//! ```ignore
//! let mut oracle = QuiescenceOracle::new();
//!
//! // During execution, record events:
//! oracle.on_region_create(region_id, parent);
//! oracle.on_spawn(task_id, region_id);
//! oracle.on_task_complete(task_id);
//! oracle.on_region_close(region_id);
//!
//! // At end of test, verify:
//! oracle.check()?;
//! ```

use crate::types::{RegionId, TaskId, Time};
use std::collections::{HashMap, HashSet};
use std::fmt;

/// A quiescence violation.
///
/// This indicates that a region closed while still having live tasks
/// or child regions, violating the quiescence invariant.
#[derive(Debug, Clone)]
pub struct QuiescenceViolation {
    /// The region that closed without quiescence.
    pub region: RegionId,
    /// Child regions that were still live.
    pub live_children: Vec<RegionId>,
    /// Tasks that were still live.
    pub live_tasks: Vec<TaskId>,
    /// The time when the region closed.
    pub close_time: Time,
}

impl fmt::Display for QuiescenceViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Region {:?} closed at {:?} without quiescence: {} live children, {} live tasks",
            self.region,
            self.close_time,
            self.live_children.len(),
            self.live_tasks.len()
        )
    }
}

impl std::error::Error for QuiescenceViolation {}

/// Oracle for detecting quiescence violations.
///
/// Tracks region hierarchy, task spawns, and completions to verify that
/// regions only close when they have no live work.
#[derive(Debug, Default)]
pub struct QuiescenceOracle {
    /// Region parent relationships: region -> parent.
    region_parents: HashMap<RegionId, Option<RegionId>>,
    /// Region child relationships: region -> children.
    region_children: HashMap<RegionId, Vec<RegionId>>,
    /// Tasks by region: region -> tasks.
    region_tasks: HashMap<RegionId, Vec<TaskId>>,
    /// Completed tasks.
    completed_tasks: HashSet<TaskId>,
    /// Closed regions with their close times.
    closed_regions: HashMap<RegionId, Time>,
    /// Detected violations.
    violations: Vec<QuiescenceViolation>,
}

impl QuiescenceOracle {
    /// Creates a new quiescence oracle.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a region creation event.
    pub fn on_region_create(&mut self, region: RegionId, parent: Option<RegionId>) {
        self.region_parents.insert(region, parent);
        self.region_children.entry(region).or_default();
        self.region_tasks.entry(region).or_default();

        if let Some(p) = parent {
            self.region_children.entry(p).or_default().push(region);
        }
    }

    /// Records a task spawn event.
    pub fn on_spawn(&mut self, task: TaskId, region: RegionId) {
        self.region_tasks.entry(region).or_default().push(task);
    }

    /// Records a task completion event.
    pub fn on_task_complete(&mut self, task: TaskId) {
        self.completed_tasks.insert(task);
    }

    /// Records a region close event.
    ///
    /// Checks quiescence at close time and records any violations.
    pub fn on_region_close(&mut self, region: RegionId, time: Time) {
        self.closed_regions.insert(region, time);

        // Check quiescence immediately
        let mut live_children = Vec::new();
        let mut live_tasks = Vec::new();

        // Check child regions
        if let Some(children) = self.region_children.get(&region) {
            for &child in children {
                if !self.closed_regions.contains_key(&child) {
                    live_children.push(child);
                }
            }
        }

        // Check tasks
        if let Some(tasks) = self.region_tasks.get(&region) {
            for &task in tasks {
                if !self.completed_tasks.contains(&task) {
                    live_tasks.push(task);
                }
            }
        }

        if !live_children.is_empty() || !live_tasks.is_empty() {
            self.violations.push(QuiescenceViolation {
                region,
                live_children,
                live_tasks,
                close_time: time,
            });
        }
    }

    /// Verifies the invariant holds.
    ///
    /// Checks that for every closed region, all its tasks have completed
    /// and all its child regions have closed. Returns an error with the
    /// first violation found.
    ///
    /// # Returns
    /// * `Ok(())` if no violations are found
    /// * `Err(QuiescenceViolation)` if a violation is detected
    pub fn check(&self) -> Result<(), QuiescenceViolation> {
        if let Some(violation) = self.violations.first() {
            return Err(violation.clone());
        }
        Ok(())
    }

    /// Resets the oracle to its initial state.
    pub fn reset(&mut self) {
        self.region_parents.clear();
        self.region_children.clear();
        self.region_tasks.clear();
        self.completed_tasks.clear();
        self.closed_regions.clear();
        self.violations.clear();
    }

    /// Returns the number of regions tracked.
    #[must_use]
    pub fn region_count(&self) -> usize {
        self.region_parents.len()
    }

    /// Returns the number of closed regions.
    #[must_use]
    pub fn closed_count(&self) -> usize {
        self.closed_regions.len()
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

    #[test]
    fn empty_region_passes() {
        let mut oracle = QuiescenceOracle::new();
        oracle.on_region_create(region(0), None);
        oracle.on_region_close(region(0), t(100));
        assert!(oracle.check().is_ok());
    }

    #[test]
    fn all_tasks_complete_passes() {
        let mut oracle = QuiescenceOracle::new();

        oracle.on_region_create(region(0), None);
        oracle.on_spawn(task(1), region(0));
        oracle.on_spawn(task(2), region(0));

        oracle.on_task_complete(task(1));
        oracle.on_task_complete(task(2));
        oracle.on_region_close(region(0), t(100));

        assert!(oracle.check().is_ok());
    }

    #[test]
    fn live_task_fails() {
        let mut oracle = QuiescenceOracle::new();

        oracle.on_region_create(region(0), None);
        oracle.on_spawn(task(1), region(0));
        // Task not completed
        oracle.on_region_close(region(0), t(100));

        let result = oracle.check();
        assert!(result.is_err());

        let violation = result.unwrap_err();
        assert_eq!(violation.region, region(0));
        assert_eq!(violation.live_tasks, vec![task(1)]);
        assert!(violation.live_children.is_empty());
    }

    #[test]
    fn live_child_region_fails() {
        let mut oracle = QuiescenceOracle::new();

        oracle.on_region_create(region(0), None);
        oracle.on_region_create(region(1), Some(region(0)));

        // Parent closes but child does not
        oracle.on_region_close(region(0), t(100));

        let result = oracle.check();
        assert!(result.is_err());

        let violation = result.unwrap_err();
        assert_eq!(violation.live_children, vec![region(1)]);
    }

    #[test]
    fn nested_regions_pass_when_properly_closed() {
        let mut oracle = QuiescenceOracle::new();

        oracle.on_region_create(region(0), None);
        oracle.on_region_create(region(1), Some(region(0)));
        oracle.on_spawn(task(1), region(1));

        oracle.on_task_complete(task(1));
        oracle.on_region_close(region(1), t(50)); // Child closes first
        oracle.on_region_close(region(0), t(100)); // Parent closes after

        assert!(oracle.check().is_ok());
    }

    #[test]
    fn multiple_children_all_must_close() {
        let mut oracle = QuiescenceOracle::new();

        oracle.on_region_create(region(0), None);
        oracle.on_region_create(region(1), Some(region(0)));
        oracle.on_region_create(region(2), Some(region(0)));

        // Only close one child
        oracle.on_region_close(region(1), t(50));
        oracle.on_region_close(region(0), t(100));

        let result = oracle.check();
        assert!(result.is_err());

        let violation = result.unwrap_err();
        assert_eq!(violation.live_children, vec![region(2)]);
    }

    #[test]
    fn reset_clears_state() {
        let mut oracle = QuiescenceOracle::new();

        oracle.on_region_create(region(0), None);
        oracle.on_spawn(task(1), region(0));
        oracle.on_region_close(region(0), t(100));

        // This would fail
        assert!(oracle.check().is_err());

        oracle.reset();

        // After reset, no violations
        assert!(oracle.check().is_ok());
        assert_eq!(oracle.region_count(), 0);
        assert_eq!(oracle.closed_count(), 0);
    }

    #[test]
    fn violation_display() {
        let violation = QuiescenceViolation {
            region: region(0),
            live_children: vec![region(1)],
            live_tasks: vec![task(1), task(2)],
            close_time: t(100),
        };

        let s = violation.to_string();
        assert!(s.contains("without quiescence"));
        assert!(s.contains("1 live children"));
        assert!(s.contains("2 live tasks"));
    }

    #[test]
    fn deeply_nested_regions() {
        let mut oracle = QuiescenceOracle::new();

        // Create a chain: r0 -> r1 -> r2
        oracle.on_region_create(region(0), None);
        oracle.on_region_create(region(1), Some(region(0)));
        oracle.on_region_create(region(2), Some(region(1)));
        oracle.on_spawn(task(1), region(2));

        // Close in correct order (innermost first)
        oracle.on_task_complete(task(1));
        oracle.on_region_close(region(2), t(30));
        oracle.on_region_close(region(1), t(50));
        oracle.on_region_close(region(0), t(100));

        assert!(oracle.check().is_ok());
    }

    #[test]
    fn both_tasks_and_children_must_complete() {
        let mut oracle = QuiescenceOracle::new();

        oracle.on_region_create(region(0), None);
        oracle.on_region_create(region(1), Some(region(0)));
        oracle.on_spawn(task(1), region(0));

        // Close child but not task
        oracle.on_region_close(region(1), t(50));
        oracle.on_region_close(region(0), t(100));

        let result = oracle.check();
        assert!(result.is_err());

        let violation = result.unwrap_err();
        assert!(violation.live_children.is_empty());
        assert_eq!(violation.live_tasks, vec![task(1)]);
    }
}
