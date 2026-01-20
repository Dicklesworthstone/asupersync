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

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    // =========================================================================
    // Basic monotonicity tests
    // =========================================================================

    #[test]
    fn root_region_with_any_deadline_passes() {
        init_test("root_region_with_any_deadline_passes");
        let mut oracle = DeadlineMonotoneOracle::new();

        // Root with bounded deadline
        oracle.on_region_create(region(0), None, &budget_with_deadline(t(1000)), t(0));
        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "oracle ok", true, ok);

        // Root with unbounded deadline
        oracle.on_region_create(region(1), None, &unbounded_budget(), t(0));
        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "oracle ok", true, ok);
        crate::test_complete!("root_region_with_any_deadline_passes");
    }

    #[test]
    fn child_with_tighter_deadline_passes() {
        init_test("child_with_tighter_deadline_passes");
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

        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "oracle ok", true, ok);
        crate::test_complete!("child_with_tighter_deadline_passes");
    }

    #[test]
    fn child_with_equal_deadline_passes() {
        init_test("child_with_equal_deadline_passes");
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

        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "oracle ok", true, ok);
        crate::test_complete!("child_with_equal_deadline_passes");
    }

    #[test]
    fn child_with_looser_deadline_fails() {
        init_test("child_with_looser_deadline_fails");
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
        let err = result.is_err();
        crate::assert_with_log!(err, "result err", true, err);

        let violation = result.unwrap_err();
        crate::assert_with_log!(
            violation.child == region(1),
            "violation child",
            region(1),
            violation.child
        );
        crate::assert_with_log!(
            violation.child_deadline == Some(t(1000)),
            "child deadline",
            Some(t(1000)),
            violation.child_deadline
        );
        crate::assert_with_log!(
            violation.parent == region(0),
            "parent",
            region(0),
            violation.parent
        );
        crate::assert_with_log!(
            violation.parent_deadline == Some(t(500)),
            "parent deadline",
            Some(t(500)),
            violation.parent_deadline
        );
        crate::test_complete!("child_with_looser_deadline_fails");
    }

    // =========================================================================
    // Unbounded (None) deadline tests
    // =========================================================================

    #[test]
    fn bounded_child_under_unbounded_parent_passes() {
        init_test("bounded_child_under_unbounded_parent_passes");
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

        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "oracle ok", true, ok);
        crate::test_complete!("bounded_child_under_unbounded_parent_passes");
    }

    #[test]
    fn unbounded_child_under_unbounded_parent_passes() {
        init_test("unbounded_child_under_unbounded_parent_passes");
        let mut oracle = DeadlineMonotoneOracle::new();

        // Parent with unbounded deadline
        oracle.on_region_create(region(0), None, &unbounded_budget(), t(0));
        // Child also unbounded - ok (∞ ≤ ∞)
        oracle.on_region_create(region(1), Some(region(0)), &unbounded_budget(), t(0));

        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "oracle ok", true, ok);
        crate::test_complete!("unbounded_child_under_unbounded_parent_passes");
    }

    #[test]
    fn unbounded_child_under_bounded_parent_fails() {
        init_test("unbounded_child_under_bounded_parent_fails");
        let mut oracle = DeadlineMonotoneOracle::new();

        // Parent with bounded deadline at t=1000
        oracle.on_region_create(region(0), None, &budget_with_deadline(t(1000)), t(0));
        // Child with unbounded deadline (∞) - VIOLATION! ∞ > 1000
        oracle.on_region_create(region(1), Some(region(0)), &unbounded_budget(), t(0));

        let result = oracle.check();
        let err = result.is_err();
        crate::assert_with_log!(err, "result err", true, err);

        let violation = result.unwrap_err();
        crate::assert_with_log!(
            violation.child == region(1),
            "violation child",
            region(1),
            violation.child
        );
        crate::assert_with_log!(
            violation.child_deadline.is_none(),
            "child deadline unbounded",
            true,
            violation.child_deadline.is_none()
        );
        crate::assert_with_log!(
            violation.parent == region(0),
            "parent",
            region(0),
            violation.parent
        );
        crate::assert_with_log!(
            violation.parent_deadline == Some(t(1000)),
            "parent deadline",
            Some(t(1000)),
            violation.parent_deadline
        );
        crate::test_complete!("unbounded_child_under_bounded_parent_fails");
    }

    // =========================================================================
    // Nested hierarchy tests
    // =========================================================================

    #[test]
    fn deeply_nested_with_progressively_tighter_deadlines_passes() {
        init_test("deeply_nested_with_progressively_tighter_deadlines_passes");
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

        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "oracle ok", true, ok);
        crate::test_complete!("deeply_nested_with_progressively_tighter_deadlines_passes");
    }

    #[test]
    fn violation_in_deep_hierarchy_detected() {
        init_test("violation_in_deep_hierarchy_detected");
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
        let err = result.is_err();
        crate::assert_with_log!(err, "result err", true, err);

        let violation = result.unwrap_err();
        crate::assert_with_log!(
            violation.child == region(2),
            "violation child",
            region(2),
            violation.child
        );
        crate::assert_with_log!(
            violation.parent == region(1),
            "violation parent",
            region(1),
            violation.parent
        );
        crate::test_complete!("violation_in_deep_hierarchy_detected");
    }

    #[test]
    fn multiple_children_one_violating() {
        init_test("multiple_children_one_violating");
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
        let err = result.is_err();
        crate::assert_with_log!(err, "result err", true, err);
        let violations = oracle.violations().len();
        crate::assert_with_log!(violations == 1, "violations len", 1, violations);
        crate::test_complete!("multiple_children_one_violating");
    }

    // =========================================================================
    // Budget update tests
    // =========================================================================

    #[test]
    fn budget_update_tightening_passes() {
        init_test("budget_update_tightening_passes");
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

        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "oracle ok", true, ok);
        crate::test_complete!("budget_update_tightening_passes");
    }

    #[test]
    fn budget_update_loosening_fails() {
        init_test("budget_update_loosening_fails");
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

        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "oracle ok", true, ok);

        // Loosen child's deadline to t=1000 - VIOLATION!
        oracle.on_budget_update(region(1), &budget_with_deadline(t(1000)), t(10));

        let result = oracle.check();
        let err = result.is_err();
        crate::assert_with_log!(err, "result err", true, err);
        crate::test_complete!("budget_update_loosening_fails");
    }

    #[test]
    fn parent_deadline_tightened_causes_child_violation() {
        init_test("parent_deadline_tightened_causes_child_violation");
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

        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "oracle ok", true, ok);

        // Parent's deadline is tightened to t=500 - child's 800 is now a violation!
        oracle.on_parent_deadline_tightened(region(0), &budget_with_deadline(t(500)), t(10));

        let result = oracle.check();
        let err = result.is_err();
        crate::assert_with_log!(err, "result err", true, err);

        let violation = result.unwrap_err();
        crate::assert_with_log!(
            violation.child == region(1),
            "violation child",
            region(1),
            violation.child
        );
        crate::assert_with_log!(
            violation.child_deadline == Some(t(800)),
            "child deadline",
            Some(t(800)),
            violation.child_deadline
        );
        crate::assert_with_log!(
            violation.parent_deadline == Some(t(500)),
            "parent deadline",
            Some(t(500)),
            violation.parent_deadline
        );
        crate::test_complete!("parent_deadline_tightened_causes_child_violation");
    }

    // =========================================================================
    // Reset and utility tests
    // =========================================================================

    #[test]
    fn reset_clears_state() {
        init_test("reset_clears_state");
        let mut oracle = DeadlineMonotoneOracle::new();

        oracle.on_region_create(region(0), None, &budget_with_deadline(t(100)), t(0));
        oracle.on_region_create(
            region(1),
            Some(region(0)),
            &budget_with_deadline(t(500)),
            t(0),
        ); // Violation

        let err = oracle.check().is_err();
        crate::assert_with_log!(err, "oracle err", true, err);
        let count = oracle.region_count();
        crate::assert_with_log!(count == 2, "region count", 2, count);

        oracle.reset();

        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "oracle ok", true, ok);
        let count = oracle.region_count();
        crate::assert_with_log!(count == 0, "region count", 0, count);
        let empty = oracle.violations().is_empty();
        crate::assert_with_log!(empty, "violations empty", true, empty);
        crate::test_complete!("reset_clears_state");
    }

    #[test]
    fn get_deadline_returns_tracked_value() {
        init_test("get_deadline_returns_tracked_value");
        let mut oracle = DeadlineMonotoneOracle::new();

        oracle.on_region_create(region(0), None, &budget_with_deadline(t(1000)), t(0));
        oracle.on_region_create(region(1), None, &unbounded_budget(), t(0));

        let r0 = oracle.get_deadline(region(0));
        crate::assert_with_log!(
            r0 == Some(Some(t(1000))),
            "deadline r0",
            Some(Some(t(1000))),
            r0
        );
        let r1 = oracle.get_deadline(region(1));
        let r1_unbounded = matches!(r1, Some(None));
        crate::assert_with_log!(
            r1_unbounded,
            "deadline r1 unbounded",
            true,
            r1_unbounded
        );
        let r99 = oracle.get_deadline(region(99));
        crate::assert_with_log!(r99.is_none(), "deadline r99", true, r99.is_none());
        crate::test_complete!("get_deadline_returns_tracked_value");
    }

    #[test]
    fn violation_display() {
        init_test("violation_display");
        let violation = DeadlineMonotoneViolation {
            child: region(1),
            child_deadline: Some(t(1000)),
            parent: region(0),
            parent_deadline: Some(t(500)),
            detected_at: t(100),
        };

        let s = violation.to_string();
        let has_violation = s.contains("monotonicity violated");
        crate::assert_with_log!(
            has_violation,
            "message contains violation",
            true,
            has_violation
        );
        let has_parent = s.contains("cannot exceed parent");
        crate::assert_with_log!(
            has_parent,
            "message contains parent",
            true,
            has_parent
        );
        crate::test_complete!("violation_display");
    }

    #[test]
    fn violation_display_with_unbounded() {
        init_test("violation_display_with_unbounded");
        let violation = DeadlineMonotoneViolation {
            child: region(1),
            child_deadline: None,
            parent: region(0),
            parent_deadline: Some(t(500)),
            detected_at: t(100),
        };

        let s = violation.to_string();
        let has_unbounded = s.contains("unbounded");
        crate::assert_with_log!(
            has_unbounded,
            "message contains unbounded",
            true,
            has_unbounded
        );
        crate::test_complete!("violation_display_with_unbounded");
    }

    // =========================================================================
    // is_deadline_monotone unit tests
    // =========================================================================

    #[test]
    fn test_is_deadline_monotone() {
        init_test("test_is_deadline_monotone");
        // Both bounded - normal comparison
        let bounded_ok = DeadlineMonotoneOracle::is_deadline_monotone(
            Some(t(100)),
            Some(t(200)),
        );
        crate::assert_with_log!(bounded_ok, "100 <= 200", true, bounded_ok);
        let equal_ok = DeadlineMonotoneOracle::is_deadline_monotone(
            Some(t(200)),
            Some(t(200)),
        );
        crate::assert_with_log!(equal_ok, "200 <= 200", true, equal_ok);
        let looser_bad = DeadlineMonotoneOracle::is_deadline_monotone(
            Some(t(300)),
            Some(t(200)),
        );
        crate::assert_with_log!(!looser_bad, "300 <= 200", false, looser_bad);

        // Bounded child, unbounded parent - always ok
        let bounded_unbounded = DeadlineMonotoneOracle::is_deadline_monotone(
            Some(t(100)),
            None,
        );
        crate::assert_with_log!(
            bounded_unbounded,
            "bounded under unbounded",
            true,
            bounded_unbounded
        );
        let bounded_max = DeadlineMonotoneOracle::is_deadline_monotone(
            Some(t(u64::MAX)),
            None,
        );
        crate::assert_with_log!(
            bounded_max,
            "max under unbounded",
            true,
            bounded_max
        );

        // Both unbounded - ok
        let both_unbounded = DeadlineMonotoneOracle::is_deadline_monotone(None, None);
        crate::assert_with_log!(
            both_unbounded,
            "unbounded <= unbounded",
            true,
            both_unbounded
        );

        // Unbounded child, bounded parent - VIOLATION
        let unbounded_bad = DeadlineMonotoneOracle::is_deadline_monotone(None, Some(t(100)));
        crate::assert_with_log!(!unbounded_bad, "unbounded <= 100", false, unbounded_bad);
        let unbounded_max = DeadlineMonotoneOracle::is_deadline_monotone(
            None,
            Some(t(u64::MAX)),
        );
        crate::assert_with_log!(
            !unbounded_max,
            "unbounded <= max",
            false,
            unbounded_max
        );
        crate::test_complete!("test_is_deadline_monotone");
    }
}
