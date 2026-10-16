//! Deadline monotone oracle for verifying INV-DEADLINE-MONOTONE.
//!
//! This oracle verifies that child regions can never have longer deadlines
//! than their parents, ensuring bounded cleanup is always achievable.
//!
//! # Invariant
//!
//! From asupersync_v4_formal_semantics.md §5:
//! ```text
//! ∀r ∈ dom(R), ∀r' ∈ R[r].subregions:
//!   deadline(R[r']) ≤ deadline(R[r])    // Tighter or equal
//! ```
//!
//! Where `None` represents unbounded (∞), and the ordering is:
//! - `Some(T₁) ≤ Some(T₂)` iff `T₁ ≤ T₂`
//! - `Some(_) ≤ None` (bounded is always ≤ unbounded)
//! - `None ≤ None` (unbounded = unbounded)
//! - `None > Some(_)` is a VIOLATION (unbounded child with bounded parent)
//!
//! # Why This Matters
//!
//! - Prevents orphan work that outlives its parent
//! - Ensures cancellation can always complete within parent's budget
//! - Critical for bounded cleanup guarantees
//!
//! # Usage
//!
//! ```ignore
//! let mut oracle = DeadlineMonotoneOracle::new();
//!
//! // During execution, record events:
//! oracle.on_region_create(region_id, parent, &budget);
//! oracle.on_budget_update(region_id, &new_budget);
//!
//! // At end of test, verify:
//! oracle.check()?;
//! ```

use crate::types::{Budget, RegionId, Time};
use std::collections::BTreeMap;
use std::fmt;

/// A deadline monotonicity violation.
///
/// This indicates that a child region has a deadline later than its parent,
/// violating the deadline monotonicity invariant.
#[derive(Debug, Clone)]
pub struct DeadlineMonotoneViolation {
    /// The child region with the violation.
    pub child: RegionId,
    /// The child's deadline (`None` = unbounded).
    pub child_deadline: Option<Time>,
    /// The parent region.
    pub parent: RegionId,
    /// The parent's deadline (`None` = unbounded).
    pub parent_deadline: Option<Time>,
    /// When the violation was detected.
    pub detected_at: Time,
}

impl fmt::Display for DeadlineMonotoneViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let child_str = self
            .child_deadline
            .map_or_else(|| "unbounded".to_string(), |d| format!("{d:?}"));
        let parent_str = self
            .parent_deadline
            .map_or_else(|| "unbounded".to_string(), |d| format!("{d:?}"));

        write!(
            f,
            "Deadline monotonicity violated: region {:?} has deadline {} but parent {:?} has deadline {} (child cannot exceed parent)",
            self.child, child_str, self.parent, parent_str
        )
    }
}

impl std::error::Error for DeadlineMonotoneViolation {}

/// Tracks deadline information for a region.
#[derive(Debug, Clone)]
struct RegionDeadlineEntry {
    /// Current deadline (`None` = unbounded).
    deadline: Option<Time>,
    /// Parent region (if any).
    parent: Option<RegionId>,
    /// Time when this entry was created/updated.
    timestamp: Time,
}

/// Oracle for detecting deadline monotonicity violations.
///
/// Tracks region deadlines and parent relationships to verify that
/// child deadlines never exceed parent deadlines.
#[derive(Debug, Default)]
pub struct DeadlineMonotoneOracle {
    /// Region deadline entries: region -> entry.
    regions: BTreeMap<RegionId, RegionDeadlineEntry>,
    /// Detected violations.
    violations: Vec<DeadlineMonotoneViolation>,
}

impl DeadlineMonotoneOracle {
    /// Creates a new deadline monotone oracle.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Compares two deadlines for monotonicity.
    ///
    /// Returns `true` if `child_deadline ≤ parent_deadline` (no violation).
    /// Returns `false` if `child_deadline > parent_deadline` (violation).
    ///
    /// Semantics:
    /// - `None` = unbounded = ∞
    /// - `Some(T)` = bounded to time T
    /// - `Some(T₁) ≤ Some(T₂)` iff `T₁ ≤ T₂`
    /// - `Some(_) ≤ None` (always true - bounded ≤ unbounded)
    /// - `None > Some(_)` (unbounded > any bounded - violation!)
    #[must_use]
    fn is_deadline_monotone(child: Option<Time>, parent: Option<Time>) -> bool {
        match (child, parent) {
            // Both bounded: check time ordering
            (Some(c), Some(p)) => c <= p,
            // Child bounded with unbounded parent, or both unbounded: always ok
            // (any bounded ≤ ∞, and ∞ ≤ ∞)
            (Some(_) | None, None) => true,
            // Child unbounded, parent bounded: VIOLATION! (∞ > any bounded)
            (None, Some(_)) => false,
        }
    }

    fn record_violation_if_needed(
        &mut self,
        child: RegionId,
        child_deadline: Option<Time>,
        parent: RegionId,
        parent_deadline: Option<Time>,
        time: Time,
    ) {
        if !Self::is_deadline_monotone(child_deadline, parent_deadline) {
            self.violations.push(DeadlineMonotoneViolation {
                child,
                child_deadline,
                parent,
                parent_deadline,
                detected_at: time,
            });
        }
    }

    fn check_existing_children(
        &mut self,
        parent: RegionId,
        parent_deadline: Option<Time>,
        time: Time,
    ) {
        let children_to_check: Vec<(RegionId, Option<Time>)> = self
            .regions
            .iter()
            .filter_map(|(region_id, entry)| {
                if entry.parent == Some(parent) {
                    Some((*region_id, entry.deadline))
                } else {
                    None
                }
            })
            .collect();

        for (child, child_deadline) in children_to_check {
            self.record_violation_if_needed(child, child_deadline, parent, parent_deadline, time);
        }
    }

    /// Records a region creation event.
    ///
    /// Checks deadline monotonicity immediately against the parent.
    /// Also re-validates any already-tracked children of this region so the
    /// oracle remains correct even if region-create events arrive out of
    /// parent-first order.
    pub fn on_region_create(
        &mut self,
        region: RegionId,
        parent: Option<RegionId>,
        budget: &Budget,
        time: Time,
    ) {
        let deadline = budget.deadline;

        // Check against parent's deadline if parent exists
        if let Some(parent_id) = parent {
            if let Some(parent_entry) = self.regions.get(&parent_id) {
                self.record_violation_if_needed(
                    region,
                    deadline,
                    parent_id,
                    parent_entry.deadline,
                    time,
                );
            }
        }

        self.regions.insert(
            region,
            RegionDeadlineEntry {
                deadline,
                parent,
                timestamp: time,
            },
        );

        self.check_existing_children(region, deadline, time);
    }

    /// Records a budget update event for a region.
    ///
    /// Re-checks deadline monotonicity against the parent and any existing
    /// children of the updated region.
    /// Note: Deadlines should only get tighter, never extended.
    pub fn on_budget_update(&mut self, region: RegionId, budget: &Budget, time: Time) {
        let new_deadline = budget.deadline;

        let Some(parent_id) = self.regions.get(&region).and_then(|entry| entry.parent) else {
            if let Some(entry) = self.regions.get_mut(&region) {
                entry.deadline = new_deadline;
                entry.timestamp = time;
            }
            self.check_existing_children(region, new_deadline, time);
            return;
        };

        if let Some(parent_entry) = self.regions.get(&parent_id).cloned() {
            self.record_violation_if_needed(
                region,
                new_deadline,
                parent_id,
                parent_entry.deadline,
                time,
            );
        }

        if let Some(entry) = self.regions.get_mut(&region) {
            entry.deadline = new_deadline;
            entry.timestamp = time;
        }

        self.check_existing_children(region, new_deadline, time);
    }

    /// Records a parent's deadline being tightened.
    ///
    /// When a parent's deadline is tightened, all children with unbounded or
    /// looser deadlines might now be in violation. This method checks all
    /// children of the given parent.
    pub fn on_parent_deadline_tightened(&mut self, parent: RegionId, budget: &Budget, time: Time) {
        let parent_deadline = budget.deadline;

        // Update parent first
        if let Some(entry) = self.regions.get_mut(&parent) {
            entry.deadline = parent_deadline;
            entry.timestamp = time;
        }

        self.check_existing_children(parent, parent_deadline, time);
    }

    /// Verifies the invariant holds.
    ///
    /// Returns an error with the first violation found.
    ///
    /// # Returns
    /// * `Ok(())` if no violations are found
    /// * `Err(DeadlineMonotoneViolation)` if a violation is detected
    pub fn check(&self) -> Result<(), DeadlineMonotoneViolation> {
        if let Some(violation) = self.violations.first() {
            return Err(violation.clone());
        }
        Ok(())
    }

    /// Returns all detected violations.
    #[must_use]
    pub fn violations(&self) -> &[DeadlineMonotoneViolation] {
        &self.violations
    }

    /// Resets the oracle to its initial state.
    pub fn reset(&mut self) {
        self.regions.clear();
        self.violations.clear();
    }

    /// Returns the number of regions tracked.
    #[must_use]
    pub fn region_count(&self) -> usize {
        self.regions.len()
    }

    /// Returns the deadline for a region, if tracked.
    #[must_use]
    pub fn get_deadline(&self, region: RegionId) -> Option<Option<Time>> {
        self.regions.get(&region).map(|e| e.deadline)
    }
}

#[cfg(test)]
#[path = "deadline_monotone_inline_tests.rs"]
mod tests;
