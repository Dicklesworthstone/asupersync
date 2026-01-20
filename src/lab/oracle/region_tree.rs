//! Region tree oracle for verifying invariant INV-TREE: region tree structure.
//!
//! This oracle verifies that regions form a proper rooted tree structure where
//! every region (except root) has exactly one parent and is listed in its
//! parent's subregions.
//!
//! # Invariant
//!
//! From asupersync_v4_formal_semantics.md §5:
//! ```text
//! ∀r ∈ dom(R):
//!   r = root ∨ (R[r].parent ∈ dom(R) ∧ r ∈ R[R[r].parent].subregions)
//! ```
//!
//! This invariant ensures:
//! 1. Exactly one root region exists
//! 2. Every non-root region has a valid parent
//! 3. Parent-child relationships are bidirectional (parent.subregions contains child)
//! 4. No cycles exist in the parent relationship
//!
//! # Usage
//!
//! ```ignore
//! let mut oracle = RegionTreeOracle::new();
//!
//! // During execution, record events:
//! oracle.on_region_create(region_id, parent, time);
//!
//! // At end of test, verify:
//! oracle.check()?;
//! ```

use crate::types::{RegionId, Time};
use std::collections::{HashMap, HashSet};
use std::fmt;

/// A region tree violation.
///
/// This indicates that the region tree structure is malformed, violating
/// the INV-TREE invariant.
#[derive(Debug, Clone)]
pub enum RegionTreeViolation {
    /// Multiple regions claim to be the root (parent = None).
    MultipleRoots {
        /// The regions that all claim to be root.
        roots: Vec<RegionId>,
    },

    /// A region has a parent that doesn't exist in the tree.
    InvalidParent {
        /// The region with the invalid parent.
        region: RegionId,
        /// The claimed parent that doesn't exist.
        claimed_parent: RegionId,
    },

    /// A region is not in its parent's subregions set.
    ParentChildMismatch {
        /// The child region.
        region: RegionId,
        /// The parent that should contain this region.
        parent: RegionId,
    },

    /// A cycle was detected in the parent relationship.
    CycleDetected {
        /// The regions forming the cycle.
        cycle: Vec<RegionId>,
    },

    /// No root region exists (all regions have parents but none is root).
    NoRoot,
}

impl fmt::Display for RegionTreeViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MultipleRoots { roots } => {
                write!(f, "Multiple root regions detected: {roots:?}")
            }
            Self::InvalidParent {
                region,
                claimed_parent,
            } => {
                write!(
                    f,
                    "Region {region:?} claims parent {claimed_parent:?} which does not exist"
                )
            }
            Self::ParentChildMismatch { region, parent } => {
                write!(
                    f,
                    "Region {region:?} not found in parent {parent:?}'s subregions"
                )
            }
            Self::CycleDetected { cycle } => {
                write!(f, "Cycle detected in parent relationships: {cycle:?}")
            }
            Self::NoRoot => {
                write!(f, "No root region exists (all regions have parents)")
            }
        }
    }
}

impl std::error::Error for RegionTreeViolation {}

/// Entry tracking a region's tree relationships.
#[derive(Debug, Clone)]
pub struct RegionTreeEntry {
    /// Parent region, or None if this is the root.
    pub parent: Option<RegionId>,
    /// Child regions (subregions).
    pub subregions: HashSet<RegionId>,
    /// Time when the region was created.
    pub created_at: Time,
}

/// Oracle for detecting region tree structure violations.
///
/// Tracks region creation and parent-child relationships to verify that
/// regions form a proper tree structure.
#[derive(Debug, Default)]
pub struct RegionTreeOracle {
    /// All tracked regions with their tree entries.
    regions: HashMap<RegionId, RegionTreeEntry>,
}

impl RegionTreeOracle {
    /// Creates a new region tree oracle.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a region creation event.
    ///
    /// This method tracks the region and its parent relationship. It also
    /// automatically updates the parent's subregions set.
    pub fn on_region_create(&mut self, region: RegionId, parent: Option<RegionId>, time: Time) {
        // Create entry for this region
        self.regions.insert(
            region,
            RegionTreeEntry {
                parent,
                subregions: HashSet::new(),
                created_at: time,
            },
        );

        // If there's a parent, add this region to parent's subregions
        if let Some(p) = parent {
            if let Some(parent_entry) = self.regions.get_mut(&p) {
                parent_entry.subregions.insert(region);
            }
            // Note: if parent doesn't exist yet, the check() will catch this
        }
    }

    /// Records that a subregion was explicitly added to a parent.
    ///
    /// This is typically called automatically by `on_region_create`, but
    /// can be used for manual subregion tracking.
    pub fn on_subregion_add(&mut self, parent: RegionId, child: RegionId) {
        if let Some(entry) = self.regions.get_mut(&parent) {
            entry.subregions.insert(child);
        }
    }

    /// Verifies the tree structure invariant.
    ///
    /// Checks that:
    /// 1. Exactly one root region exists (parent = None)
    /// 2. Every non-root region has a parent that exists
    /// 3. Every region is in its parent's subregions set
    /// 4. No cycles exist in the parent relationship
    ///
    /// # Returns
    /// * `Ok(())` if no violations are found
    /// * `Err(RegionTreeViolation)` if a violation is detected
    pub fn check(&self) -> Result<(), RegionTreeViolation> {
        // Empty tree is valid
        if self.regions.is_empty() {
            return Ok(());
        }

        // 1. Check for exactly one root
        let roots: Vec<RegionId> = self
            .regions
            .iter()
            .filter(|(_, entry)| entry.parent.is_none())
            .map(|(&id, _)| id)
            .collect();

        if roots.is_empty() {
            return Err(RegionTreeViolation::NoRoot);
        }

        if roots.len() > 1 {
            return Err(RegionTreeViolation::MultipleRoots { roots });
        }

        // 2. Check that every non-root region has a valid parent
        for (&region, entry) in &self.regions {
            if let Some(parent) = entry.parent {
                if !self.regions.contains_key(&parent) {
                    return Err(RegionTreeViolation::InvalidParent {
                        region,
                        claimed_parent: parent,
                    });
                }
            }
        }

        // 3. Check bidirectional consistency (child in parent's subregions)
        for (&region, entry) in &self.regions {
            if let Some(parent) = entry.parent {
                if let Some(parent_entry) = self.regions.get(&parent) {
                    if !parent_entry.subregions.contains(&region) {
                        return Err(RegionTreeViolation::ParentChildMismatch { region, parent });
                    }
                }
            }
        }

        // 4. Check for cycles using DFS
        if let Some(cycle) = self.find_cycle() {
            return Err(RegionTreeViolation::CycleDetected { cycle });
        }

        Ok(())
    }

    /// Finds a cycle in the parent relationships, if one exists.
    ///
    /// Uses tortoise-and-hare algorithm for each region to detect cycles.
    fn find_cycle(&self) -> Option<Vec<RegionId>> {
        for &start in self.regions.keys() {
            let mut visited = HashSet::new();
            let mut path = Vec::new();
            let mut current = start;

            loop {
                if visited.contains(&current) {
                    // Found a cycle - extract just the cycle portion
                    if let Some(pos) = path.iter().position(|&r| r == current) {
                        let cycle: Vec<RegionId> = path[pos..].to_vec();
                        return Some(cycle);
                    }
                    break;
                }

                visited.insert(current);
                path.push(current);

                // Follow parent pointer
                if let Some(entry) = self.regions.get(&current) {
                    if let Some(parent) = entry.parent {
                        current = parent;
                    } else {
                        // Reached root, no cycle from this start
                        break;
                    }
                } else {
                    // Region not found (shouldn't happen)
                    break;
                }
            }
        }

        None
    }

    /// Resets the oracle to its initial state.
    pub fn reset(&mut self) {
        self.regions.clear();
    }

    /// Returns the number of tracked regions.
    #[must_use]
    pub fn region_count(&self) -> usize {
        self.regions.len()
    }

    /// Returns the root region, if exactly one exists.
    #[must_use]
    pub fn root(&self) -> Option<RegionId> {
        let roots: Vec<RegionId> = self
            .regions
            .iter()
            .filter(|(_, entry)| entry.parent.is_none())
            .map(|(&id, _)| id)
            .collect();

        if roots.len() == 1 {
            Some(roots[0])
        } else {
            None
        }
    }

    /// Returns the depth of a region in the tree.
    ///
    /// Returns None if the region is not found or if there's a cycle.
    #[must_use]
    pub fn depth(&self, region: RegionId) -> Option<usize> {
        let mut depth = 0;
        let mut current = region;
        let mut visited = HashSet::new();

        loop {
            if visited.contains(&current) {
                // Cycle detected
                return None;
            }
            visited.insert(current);

            if let Some(entry) = self.regions.get(&current) {
                if let Some(parent) = entry.parent {
                    depth += 1;
                    current = parent;
                } else {
                    // Reached root
                    return Some(depth);
                }
            } else {
                // Region not found
                return None;
            }
        }
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

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    // === Valid Tree Tests ===

    #[test]
    fn empty_tree_passes() {
        init_test("empty_tree_passes");
        let oracle = RegionTreeOracle::new();
        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "ok", true, ok);
        crate::test_complete!("empty_tree_passes");
    }

    #[test]
    fn single_root_passes() {
        init_test("single_root_passes");
        let mut oracle = RegionTreeOracle::new();
        oracle.on_region_create(region(0), None, t(10));
        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "ok", true, ok);
        let root = oracle.root();
        crate::assert_with_log!(root == Some(region(0)), "root", Some(region(0)), root);
        crate::test_complete!("single_root_passes");
    }

    #[test]
    fn linear_chain_passes() {
        init_test("linear_chain_passes");
        let mut oracle = RegionTreeOracle::new();

        // r0 -> r1 -> r2
        oracle.on_region_create(region(0), None, t(10));
        oracle.on_region_create(region(1), Some(region(0)), t(20));
        oracle.on_region_create(region(2), Some(region(1)), t(30));

        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "ok", true, ok);
        let count = oracle.region_count();
        crate::assert_with_log!(count == 3, "region_count", 3, count);
        crate::test_complete!("linear_chain_passes");
    }

    #[test]
    fn branching_tree_passes() {
        init_test("branching_tree_passes");
        let mut oracle = RegionTreeOracle::new();

        //       r0
        //      /  \
        //    r1    r2
        //   / \
        //  r3  r4
        oracle.on_region_create(region(0), None, t(10));
        oracle.on_region_create(region(1), Some(region(0)), t(20));
        oracle.on_region_create(region(2), Some(region(0)), t(30));
        oracle.on_region_create(region(3), Some(region(1)), t(40));
        oracle.on_region_create(region(4), Some(region(1)), t(50));

        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "ok", true, ok);
        let count = oracle.region_count();
        crate::assert_with_log!(count == 5, "region_count", 5, count);
        crate::test_complete!("branching_tree_passes");
    }

    #[test]
    fn deeply_nested_tree_passes() {
        init_test("deeply_nested_tree_passes");
        let mut oracle = RegionTreeOracle::new();

        // Create a chain of 10 nested regions
        oracle.on_region_create(region(0), None, t(0));
        for i in 1..10 {
            oracle.on_region_create(region(i), Some(region(i - 1)), t(u64::from(i) * 10));
        }

        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "ok", true, ok);
        let depth9 = oracle.depth(region(9));
        crate::assert_with_log!(depth9 == Some(9), "depth 9", Some(9), depth9);
        let depth0 = oracle.depth(region(0));
        crate::assert_with_log!(depth0 == Some(0), "depth 0", Some(0), depth0);
        crate::test_complete!("deeply_nested_tree_passes");
    }

    // === Multiple Roots Violation ===

    #[test]
    fn multiple_roots_fails() {
        init_test("multiple_roots_fails");
        let mut oracle = RegionTreeOracle::new();

        oracle.on_region_create(region(0), None, t(10));
        oracle.on_region_create(region(1), None, t(20)); // Second root!

        let result = oracle.check();
        let err = result.is_err();
        crate::assert_with_log!(err, "err", true, err);

        match result.unwrap_err() {
            RegionTreeViolation::MultipleRoots { roots } => {
                let len = roots.len();
                crate::assert_with_log!(len == 2, "roots len", 2, len);
                let has0 = roots.contains(&region(0));
                crate::assert_with_log!(has0, "contains r0", true, has0);
                let has1 = roots.contains(&region(1));
                crate::assert_with_log!(has1, "contains r1", true, has1);
            }
            other => panic!("Expected MultipleRoots, got {other:?}"),
        }
        crate::test_complete!("multiple_roots_fails");
    }

    #[test]
    fn multiple_roots_with_children_fails() {
        init_test("multiple_roots_with_children_fails");
        let mut oracle = RegionTreeOracle::new();

        // Two separate trees
        oracle.on_region_create(region(0), None, t(10));
        oracle.on_region_create(region(1), Some(region(0)), t(20));
        oracle.on_region_create(region(2), None, t(30)); // Second root!
        oracle.on_region_create(region(3), Some(region(2)), t(40));

        let result = oracle.check();
        let is_multiple = matches!(result.unwrap_err(), RegionTreeViolation::MultipleRoots { .. });
        crate::assert_with_log!(is_multiple, "multiple roots", true, is_multiple);
        crate::test_complete!("multiple_roots_with_children_fails");
    }

    // === No Root Violation ===

    #[test]
    fn no_root_fails() {
        init_test("no_root_fails");
        let mut oracle = RegionTreeOracle::new();

        // Manually create regions where all have parents (forming a cycle)
        // which results in NoRoot being detected first
        oracle.regions.insert(
            region(0),
            RegionTreeEntry {
                parent: Some(region(1)),
                subregions: HashSet::from([region(1)]),
                created_at: t(10),
            },
        );
        oracle.regions.insert(
            region(1),
            RegionTreeEntry {
                parent: Some(region(0)),
                subregions: HashSet::from([region(0)]),
                created_at: t(20),
            },
        );

        let result = oracle.check();
        let err = result.is_err();
        crate::assert_with_log!(err, "err", true, err);

        // First we'll get NoRoot since all have parents
        match result.unwrap_err() {
            RegionTreeViolation::NoRoot => {
                // Expected - there's no root when all regions have parents
            }
            other => panic!("Expected NoRoot, got {other:?}"),
        }
        crate::test_complete!("no_root_fails");
    }

    // === Invalid Parent Violation ===

    #[test]
    fn invalid_parent_fails() {
        init_test("invalid_parent_fails");
        let mut oracle = RegionTreeOracle::new();

        oracle.on_region_create(region(0), None, t(10));
        // region(1) claims region(99) as parent, but region(99) doesn't exist
        oracle.on_region_create(region(1), Some(region(99)), t(20));

        let result = oracle.check();
        let err = result.is_err();
        crate::assert_with_log!(err, "err", true, err);

        match result.unwrap_err() {
            RegionTreeViolation::InvalidParent {
                region: r,
                claimed_parent,
            } => {
                crate::assert_with_log!(r == region(1), "region", region(1), r);
                crate::assert_with_log!(claimed_parent == region(99), "parent", region(99), claimed_parent);
            }
            other => panic!("Expected InvalidParent, got {other:?}"),
        }
        crate::test_complete!("invalid_parent_fails");
    }

    // === Parent-Child Mismatch Violation ===

    #[test]
    fn parent_child_mismatch_fails() {
        init_test("parent_child_mismatch_fails");
        let mut oracle = RegionTreeOracle::new();

        // Create root
        oracle.on_region_create(region(0), None, t(10));

        // Manually insert a region that claims region(0) as parent
        // but don't add it to region(0)'s subregions
        oracle.regions.insert(
            region(1),
            RegionTreeEntry {
                parent: Some(region(0)),
                subregions: HashSet::new(),
                created_at: t(20),
            },
        );
        // Note: we did NOT add region(1) to region(0)'s subregions

        let result = oracle.check();
        let err = result.is_err();
        crate::assert_with_log!(err, "err", true, err);

        match result.unwrap_err() {
            RegionTreeViolation::ParentChildMismatch { region: r, parent } => {
                crate::assert_with_log!(r == region(1), "region", region(1), r);
                crate::assert_with_log!(parent == region(0), "parent", region(0), parent);
            }
            other => panic!("Expected ParentChildMismatch, got {other:?}"),
        }
        crate::test_complete!("parent_child_mismatch_fails");
    }

    // === Cycle Detection ===

    #[test]
    fn simple_cycle_fails() {
        init_test("simple_cycle_fails");
        let mut oracle = RegionTreeOracle::new();

        // Create a cycle: r0 -> r1 -> r2 -> r0
        // We need to manually create this since on_region_create prevents it

        oracle.regions.insert(
            region(0),
            RegionTreeEntry {
                parent: Some(region(2)),
                subregions: HashSet::from([region(1)]),
                created_at: t(10),
            },
        );
        oracle.regions.insert(
            region(1),
            RegionTreeEntry {
                parent: Some(region(0)),
                subregions: HashSet::from([region(2)]),
                created_at: t(20),
            },
        );
        oracle.regions.insert(
            region(2),
            RegionTreeEntry {
                parent: Some(region(1)),
                subregions: HashSet::from([region(0)]),
                created_at: t(30),
            },
        );

        let result = oracle.check();
        let err = result.is_err();
        crate::assert_with_log!(err, "err", true, err);

        // First we'll get NoRoot since all have parents
        match result.unwrap_err() {
            RegionTreeViolation::NoRoot => {
                // Expected - there's no root in a cycle
            }
            RegionTreeViolation::CycleDetected { cycle } => {
                let empty = cycle.is_empty();
                crate::assert_with_log!(!empty, "cycle not empty", false, empty);
            }
            other => panic!("Expected NoRoot or CycleDetected, got {other:?}"),
        }
        crate::test_complete!("simple_cycle_fails");
    }

    #[test]
    fn self_loop_fails() {
        init_test("self_loop_fails");
        let mut oracle = RegionTreeOracle::new();

        // Region is its own parent
        oracle.regions.insert(
            region(0),
            RegionTreeEntry {
                parent: Some(region(0)),
                subregions: HashSet::from([region(0)]),
                created_at: t(10),
            },
        );

        let result = oracle.check();
        let err = result.is_err();
        crate::assert_with_log!(err, "err", true, err);
        crate::test_complete!("self_loop_fails");
    }

    // === Helper Method Tests ===

    #[test]
    fn depth_calculation() {
        init_test("depth_calculation");
        let mut oracle = RegionTreeOracle::new();

        oracle.on_region_create(region(0), None, t(10));
        oracle.on_region_create(region(1), Some(region(0)), t(20));
        oracle.on_region_create(region(2), Some(region(1)), t(30));

        let depth0 = oracle.depth(region(0));
        crate::assert_with_log!(depth0 == Some(0), "depth 0", Some(0), depth0);
        let depth1 = oracle.depth(region(1));
        crate::assert_with_log!(depth1 == Some(1), "depth 1", Some(1), depth1);
        let depth2 = oracle.depth(region(2));
        crate::assert_with_log!(depth2 == Some(2), "depth 2", Some(2), depth2);
        let depth_missing = oracle.depth(region(99));
        crate::assert_with_log!(
            depth_missing == None,
            "depth missing",
            None::<usize>,
            depth_missing
        ); // Not found
        crate::test_complete!("depth_calculation");
    }

    #[test]
    fn root_returns_none_for_multiple_roots() {
        init_test("root_returns_none_for_multiple_roots");
        let mut oracle = RegionTreeOracle::new();

        oracle.on_region_create(region(0), None, t(10));
        oracle.on_region_create(region(1), None, t(20));

        let root = oracle.root();
        crate::assert_with_log!(root == None, "root none", None::<RegionId>, root);
        crate::test_complete!("root_returns_none_for_multiple_roots");
    }

    #[test]
    fn reset_clears_state() {
        init_test("reset_clears_state");
        let mut oracle = RegionTreeOracle::new();

        oracle.on_region_create(region(0), None, t(10));
        oracle.on_region_create(region(1), Some(region(0)), t(20));

        let count = oracle.region_count();
        crate::assert_with_log!(count == 2, "region_count", 2, count);

        oracle.reset();

        let count = oracle.region_count();
        crate::assert_with_log!(count == 0, "region_count", 0, count);
        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "ok", true, ok);
        crate::test_complete!("reset_clears_state");
    }

    #[test]
    fn on_subregion_add_updates_parent() {
        init_test("on_subregion_add_updates_parent");
        let mut oracle = RegionTreeOracle::new();

        oracle.on_region_create(region(0), None, t(10));
        oracle.on_region_create(region(1), None, t(20)); // Initially a second root

        // Fix by manually adding subregion relationship
        if let Some(entry) = oracle.regions.get_mut(&region(1)) {
            entry.parent = Some(region(0));
        }
        oracle.on_subregion_add(region(0), region(1));

        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "ok", true, ok);
        crate::test_complete!("on_subregion_add_updates_parent");
    }

    // === Violation Display Tests ===

    #[test]
    fn violation_display_multiple_roots() {
        init_test("violation_display_multiple_roots");
        let v = RegionTreeViolation::MultipleRoots {
            roots: vec![region(0), region(1)],
        };
        let s = v.to_string();
        let has = s.contains("Multiple root");
        crate::assert_with_log!(has, "contains", true, has);
        crate::test_complete!("violation_display_multiple_roots");
    }

    #[test]
    fn violation_display_invalid_parent() {
        init_test("violation_display_invalid_parent");
        let v = RegionTreeViolation::InvalidParent {
            region: region(1),
            claimed_parent: region(99),
        };
        let s = v.to_string();
        let has = s.contains("does not exist");
        crate::assert_with_log!(has, "contains", true, has);
        crate::test_complete!("violation_display_invalid_parent");
    }

    #[test]
    fn violation_display_mismatch() {
        init_test("violation_display_mismatch");
        let v = RegionTreeViolation::ParentChildMismatch {
            region: region(1),
            parent: region(0),
        };
        let s = v.to_string();
        let has = s.contains("subregions");
        crate::assert_with_log!(has, "contains", true, has);
        crate::test_complete!("violation_display_mismatch");
    }

    #[test]
    fn violation_display_cycle() {
        init_test("violation_display_cycle");
        let v = RegionTreeViolation::CycleDetected {
            cycle: vec![region(0), region(1), region(2)],
        };
        let s = v.to_string();
        let has = s.contains("Cycle");
        crate::assert_with_log!(has, "contains", true, has);
        crate::test_complete!("violation_display_cycle");
    }

    #[test]
    fn violation_display_no_root() {
        init_test("violation_display_no_root");
        let v = RegionTreeViolation::NoRoot;
        let s = v.to_string();
        let has = s.contains("No root");
        crate::assert_with_log!(has, "contains", true, has);
        crate::test_complete!("violation_display_no_root");
    }

    // === Edge Cases ===

    #[test]
    fn late_parent_creation_handled() {
        init_test("late_parent_creation_handled");
        let mut oracle = RegionTreeOracle::new();

        // Create child before parent (unusual but possible in some scenarios)
        // This will initially have invalid parent
        oracle.on_region_create(region(1), Some(region(0)), t(10));

        // Now create parent
        oracle.on_region_create(region(0), None, t(5));

        // Need to manually fix the subregions relationship since parent was created later
        oracle.on_subregion_add(region(0), region(1));

        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "ok", true, ok);
        crate::test_complete!("late_parent_creation_handled");
    }

    #[test]
    fn many_siblings() {
        init_test("many_siblings");
        let mut oracle = RegionTreeOracle::new();

        oracle.on_region_create(region(0), None, t(10));

        // Create 100 children of root
        for i in 1..=100 {
            oracle.on_region_create(region(i), Some(region(0)), t(u64::from(i) * 10));
        }

        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "ok", true, ok);
        let count = oracle.region_count();
        crate::assert_with_log!(count == 101, "region_count", 101, count);

        // Verify all children are at depth 1
        for i in 1..=100 {
            let depth = oracle.depth(region(i));
            crate::assert_with_log!(depth == Some(1), "depth", Some(1), depth);
        }
        crate::test_complete!("many_siblings");
    }
}
