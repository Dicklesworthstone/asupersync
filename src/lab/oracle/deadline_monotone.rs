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
use std::collections::HashMap;
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
    regions: HashMap<RegionId, RegionDeadlineEntry>,
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

    /// Records a region creation event.
    ///
    /// Checks deadline monotonicity immediately against the parent.
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
                if !Self::is_deadline_monotone(deadline, parent_entry.deadline) {
                    self.violations.push(DeadlineMonotoneViolation {
                        child: region,
                        child_deadline: deadline,
                        parent: parent_id,
                        parent_deadline: parent_entry.deadline,
                        detected_at: time,
                    });
                }
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
    }

    /// Records a budget update event for a region.
    ///
    /// Re-checks deadline monotonicity against the parent.
    /// Note: Deadlines should only get tighter, never extended.
    pub fn on_budget_update(&mut self, region: RegionId, budget: &Budget, time: Time) {
        let new_deadline = budget.deadline;

        if let Some(entry) = self.regions.get_mut(&region) {
            // Check against parent if we have one
            if let Some(parent_id) = entry.parent {
                if let Some(parent_entry) = self.regions.get(&parent_id).cloned() {
                    if !Self::is_deadline_monotone(new_deadline, parent_entry.deadline) {
                        self.violations.push(DeadlineMonotoneViolation {
                            child: region,
                            child_deadline: new_deadline,
                            parent: parent_id,
                            parent_deadline: parent_entry.deadline,
                            detected_at: time,
                        });
                    }
                }
            }

            // Also need to re-get the entry since we had to drop the borrow
            if let Some(entry) = self.regions.get_mut(&region) {
                entry.deadline = new_deadline;
                entry.timestamp = time;
            }
        }
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

        // Collect children to check (to avoid borrow issues)
        let children_to_check: Vec<(RegionId, Option<Time>)> = self
            .regions
            .iter()
            .filter_map(|(rid, entry)| {
                if entry.parent == Some(parent) {
                    Some((*rid, entry.deadline))
                } else {
                    None
                }
            })
            .collect();

        // Check each child
        for (child_id, child_deadline) in children_to_check {
            if !Self::is_deadline_monotone(child_deadline, parent_deadline) {
                self.violations.push(DeadlineMonotoneViolation {
                    child: child_id,
                    child_deadline,
                    parent,
                    parent_deadline,
                    detected_at: time,
                });
            }
        }
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
mod tests {
    use super::*;
    use crate::util::ArenaIndex;

    fn region(n: u32) -> RegionId {
        RegionId::from_arena(ArenaIndex::new(n, 0))
    }

    fn t(nanos: u64) -> Time {
        Time::from_nanos(nanos)
    }

    fn budget_with_deadline(deadline: Time) -> Budget {
        Budget::new().with_deadline(deadline)
    }

    fn unbounded_budget() -> Budget {
        Budget::new()
    }

    // =========================================================================
    // Basic monotonicity tests
    // =========================================================================

    #[test]
    fn root_region_with_any_deadline_passes() {
        let mut oracle = DeadlineMonotoneOracle::new();

        // Root with bounded deadline
        oracle.on_region_create(region(0), None, &budget_with_deadline(t(1000)), t(0));
        assert!(oracle.check().is_ok());

        // Root with unbounded deadline
        oracle.on_region_create(region(1), None, &unbounded_budget(), t(0));
        assert!(oracle.check().is_ok());
    }

    #[test]
    fn child_with_tighter_deadline_passes() {
        let mut oracle = DeadlineMonotoneOracle::new();

        // Parent with deadline at t=1000
        oracle.on_region_create(region(0), None, &budget_with_deadline(t(1000)), t(0));
        // Child with tighter deadline at t=500
        oracle.on_region_create(
            region(1),
            Some(region(0)),
            &budget_with_deadline(t(500)),
            t(0),
        );

        assert!(oracle.check().is_ok());
    }

    #[test]
    fn child_with_equal_deadline_passes() {
        let mut oracle = DeadlineMonotoneOracle::new();

        // Parent with deadline at t=1000
        oracle.on_region_create(region(0), None, &budget_with_deadline(t(1000)), t(0));
        // Child with same deadline at t=1000
        oracle.on_region_create(
            region(1),
            Some(region(0)),
            &budget_with_deadline(t(1000)),
            t(0),
        );

        assert!(oracle.check().is_ok());
    }

    #[test]
    fn child_with_looser_deadline_fails() {
        let mut oracle = DeadlineMonotoneOracle::new();

        // Parent with deadline at t=500
        oracle.on_region_create(region(0), None, &budget_with_deadline(t(500)), t(0));
        // Child with looser deadline at t=1000 - VIOLATION!
        oracle.on_region_create(
            region(1),
            Some(region(0)),
            &budget_with_deadline(t(1000)),
            t(0),
        );

        let result = oracle.check();
        assert!(result.is_err());

        let violation = result.unwrap_err();
        assert_eq!(violation.child, region(1));
        assert_eq!(violation.child_deadline, Some(t(1000)));
        assert_eq!(violation.parent, region(0));
        assert_eq!(violation.parent_deadline, Some(t(500)));
    }

    // =========================================================================
    // Unbounded (None) deadline tests
    // =========================================================================

    #[test]
    fn bounded_child_under_unbounded_parent_passes() {
        let mut oracle = DeadlineMonotoneOracle::new();

        // Parent with unbounded deadline (None = ∞)
        oracle.on_region_create(region(0), None, &unbounded_budget(), t(0));
        // Child with bounded deadline - always ok under unbounded parent
        oracle.on_region_create(
            region(1),
            Some(region(0)),
            &budget_with_deadline(t(1000)),
            t(0),
        );

        assert!(oracle.check().is_ok());
    }

    #[test]
    fn unbounded_child_under_unbounded_parent_passes() {
        let mut oracle = DeadlineMonotoneOracle::new();

        // Parent with unbounded deadline
        oracle.on_region_create(region(0), None, &unbounded_budget(), t(0));
        // Child also unbounded - ok (∞ ≤ ∞)
        oracle.on_region_create(region(1), Some(region(0)), &unbounded_budget(), t(0));

        assert!(oracle.check().is_ok());
    }

    #[test]
    fn unbounded_child_under_bounded_parent_fails() {
        let mut oracle = DeadlineMonotoneOracle::new();

        // Parent with bounded deadline at t=1000
        oracle.on_region_create(region(0), None, &budget_with_deadline(t(1000)), t(0));
        // Child with unbounded deadline (∞) - VIOLATION! ∞ > 1000
        oracle.on_region_create(region(1), Some(region(0)), &unbounded_budget(), t(0));

        let result = oracle.check();
        assert!(result.is_err());

        let violation = result.unwrap_err();
        assert_eq!(violation.child, region(1));
        assert_eq!(violation.child_deadline, None); // Unbounded
        assert_eq!(violation.parent, region(0));
        assert_eq!(violation.parent_deadline, Some(t(1000)));
    }

    // =========================================================================
    // Nested hierarchy tests
    // =========================================================================

    #[test]
    fn deeply_nested_with_progressively_tighter_deadlines_passes() {
        let mut oracle = DeadlineMonotoneOracle::new();

        // r0: deadline 1000
        oracle.on_region_create(region(0), None, &budget_with_deadline(t(1000)), t(0));
        // r1 under r0: deadline 800
        oracle.on_region_create(
            region(1),
            Some(region(0)),
            &budget_with_deadline(t(800)),
            t(0),
        );
        // r2 under r1: deadline 500
        oracle.on_region_create(
            region(2),
            Some(region(1)),
            &budget_with_deadline(t(500)),
            t(0),
        );
        // r3 under r2: deadline 200
        oracle.on_region_create(
            region(3),
            Some(region(2)),
            &budget_with_deadline(t(200)),
            t(0),
        );

        assert!(oracle.check().is_ok());
    }

    #[test]
    fn violation_in_deep_hierarchy_detected() {
        let mut oracle = DeadlineMonotoneOracle::new();

        // r0: deadline 1000
        oracle.on_region_create(region(0), None, &budget_with_deadline(t(1000)), t(0));
        // r1 under r0: deadline 500
        oracle.on_region_create(
            region(1),
            Some(region(0)),
            &budget_with_deadline(t(500)),
            t(0),
        );
        // r2 under r1: deadline 800 - VIOLATION! 800 > 500
        oracle.on_region_create(
            region(2),
            Some(region(1)),
            &budget_with_deadline(t(800)),
            t(0),
        );

        let result = oracle.check();
        assert!(result.is_err());

        let violation = result.unwrap_err();
        assert_eq!(violation.child, region(2));
        assert_eq!(violation.parent, region(1));
    }

    #[test]
    fn multiple_children_one_violating() {
        let mut oracle = DeadlineMonotoneOracle::new();

        // Parent with deadline at t=1000
        oracle.on_region_create(region(0), None, &budget_with_deadline(t(1000)), t(0));
        // Child 1: ok (deadline 500)
        oracle.on_region_create(
            region(1),
            Some(region(0)),
            &budget_with_deadline(t(500)),
            t(0),
        );
        // Child 2: ok (deadline 900)
        oracle.on_region_create(
            region(2),
            Some(region(0)),
            &budget_with_deadline(t(900)),
            t(0),
        );
        // Child 3: VIOLATION (deadline 1500 > parent's 1000)
        oracle.on_region_create(
            region(3),
            Some(region(0)),
            &budget_with_deadline(t(1500)),
            t(0),
        );

        let result = oracle.check();
        assert!(result.is_err());
        assert_eq!(oracle.violations().len(), 1);
    }

    // =========================================================================
    // Budget update tests
    // =========================================================================

    #[test]
    fn budget_update_tightening_passes() {
        let mut oracle = DeadlineMonotoneOracle::new();

        // Parent with deadline at t=1000
        oracle.on_region_create(region(0), None, &budget_with_deadline(t(1000)), t(0));
        // Child with deadline at t=800
        oracle.on_region_create(
            region(1),
            Some(region(0)),
            &budget_with_deadline(t(800)),
            t(0),
        );

        // Tighten child's deadline to t=500 - still ok
        oracle.on_budget_update(region(1), &budget_with_deadline(t(500)), t(10));

        assert!(oracle.check().is_ok());
    }

    #[test]
    fn budget_update_loosening_fails() {
        let mut oracle = DeadlineMonotoneOracle::new();

        // Parent with deadline at t=500
        oracle.on_region_create(region(0), None, &budget_with_deadline(t(500)), t(0));
        // Child with deadline at t=400 - ok initially
        oracle.on_region_create(
            region(1),
            Some(region(0)),
            &budget_with_deadline(t(400)),
            t(0),
        );

        assert!(oracle.check().is_ok());

        // Loosen child's deadline to t=1000 - VIOLATION!
        oracle.on_budget_update(region(1), &budget_with_deadline(t(1000)), t(10));

        let result = oracle.check();
        assert!(result.is_err());
    }

    #[test]
    fn parent_deadline_tightened_causes_child_violation() {
        let mut oracle = DeadlineMonotoneOracle::new();

        // Parent with deadline at t=1000
        oracle.on_region_create(region(0), None, &budget_with_deadline(t(1000)), t(0));
        // Child with deadline at t=800 - ok initially
        oracle.on_region_create(
            region(1),
            Some(region(0)),
            &budget_with_deadline(t(800)),
            t(0),
        );

        assert!(oracle.check().is_ok());

        // Parent's deadline is tightened to t=500 - child's 800 is now a violation!
        oracle.on_parent_deadline_tightened(region(0), &budget_with_deadline(t(500)), t(10));

        let result = oracle.check();
        assert!(result.is_err());

        let violation = result.unwrap_err();
        assert_eq!(violation.child, region(1));
        assert_eq!(violation.child_deadline, Some(t(800)));
        assert_eq!(violation.parent_deadline, Some(t(500)));
    }

    // =========================================================================
    // Reset and utility tests
    // =========================================================================

    #[test]
    fn reset_clears_state() {
        let mut oracle = DeadlineMonotoneOracle::new();

        oracle.on_region_create(region(0), None, &budget_with_deadline(t(100)), t(0));
        oracle.on_region_create(
            region(1),
            Some(region(0)),
            &budget_with_deadline(t(500)),
            t(0),
        ); // Violation

        assert!(oracle.check().is_err());
        assert_eq!(oracle.region_count(), 2);

        oracle.reset();

        assert!(oracle.check().is_ok());
        assert_eq!(oracle.region_count(), 0);
        assert!(oracle.violations().is_empty());
    }

    #[test]
    fn get_deadline_returns_tracked_value() {
        let mut oracle = DeadlineMonotoneOracle::new();

        oracle.on_region_create(region(0), None, &budget_with_deadline(t(1000)), t(0));
        oracle.on_region_create(region(1), None, &unbounded_budget(), t(0));

        assert_eq!(oracle.get_deadline(region(0)), Some(Some(t(1000))));
        assert_eq!(oracle.get_deadline(region(1)), Some(None));
        assert_eq!(oracle.get_deadline(region(99)), None); // Not tracked
    }

    #[test]
    fn violation_display() {
        let violation = DeadlineMonotoneViolation {
            child: region(1),
            child_deadline: Some(t(1000)),
            parent: region(0),
            parent_deadline: Some(t(500)),
            detected_at: t(100),
        };

        let s = violation.to_string();
        assert!(s.contains("monotonicity violated"));
        assert!(s.contains("cannot exceed parent"));
    }

    #[test]
    fn violation_display_with_unbounded() {
        let violation = DeadlineMonotoneViolation {
            child: region(1),
            child_deadline: None,
            parent: region(0),
            parent_deadline: Some(t(500)),
            detected_at: t(100),
        };

        let s = violation.to_string();
        assert!(s.contains("unbounded"));
    }

    // =========================================================================
    // is_deadline_monotone unit tests
    // =========================================================================

    #[test]
    fn test_is_deadline_monotone() {
        // Both bounded - normal comparison
        assert!(DeadlineMonotoneOracle::is_deadline_monotone(
            Some(t(100)),
            Some(t(200))
        ));
        assert!(DeadlineMonotoneOracle::is_deadline_monotone(
            Some(t(200)),
            Some(t(200))
        ));
        assert!(!DeadlineMonotoneOracle::is_deadline_monotone(
            Some(t(300)),
            Some(t(200))
        ));

        // Bounded child, unbounded parent - always ok
        assert!(DeadlineMonotoneOracle::is_deadline_monotone(
            Some(t(100)),
            None
        ));
        assert!(DeadlineMonotoneOracle::is_deadline_monotone(
            Some(t(u64::MAX)),
            None
        ));

        // Both unbounded - ok
        assert!(DeadlineMonotoneOracle::is_deadline_monotone(None, None));

        // Unbounded child, bounded parent - VIOLATION
        assert!(!DeadlineMonotoneOracle::is_deadline_monotone(
            None,
            Some(t(100))
        ));
        assert!(!DeadlineMonotoneOracle::is_deadline_monotone(
            None,
            Some(t(u64::MAX))
        ));
    }
}
