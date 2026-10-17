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

    /// A parent's subregions set references a region that does not exist.
    PhantomSubregion {
        /// The parent with the stale reference.
        parent: RegionId,
        /// The non-existent child.
        phantom_child: RegionId,
    },
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
            Self::PhantomSubregion {
                parent,
                phantom_child,
            } => {
                write!(
                    f,
                    "Parent {parent:?} references non-existent subregion {phantom_child:?}"
                )
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
        let (previous_parent, existing_subregions) = self.regions.get(&region).map_or_else(
            || (None, HashSet::new()),
            |previous| (previous.parent, previous.subregions.clone()),
        );

        // If this region already existed with a different parent, remove the
        // stale edge from the old parent's subregion set.
        if let Some(previous_parent) = previous_parent {
            if Some(previous_parent) != parent {
                if let Some(previous_parent_entry) = self.regions.get_mut(&previous_parent) {
                    previous_parent_entry.subregions.remove(&region);
                }
            }
        }

        // Create entry for this region
        self.regions.insert(
            region,
            RegionTreeEntry {
                parent,
                // Re-registration can move a region without changing its
                // existing children; keep those edges intact.
                subregions: existing_subregions,
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
    /// 4. Every subregion reference points to an existing region
    /// 5. No cycles exist in the parent relationship
    ///
    /// # Returns
    /// * `Ok(())` if no violations are found
    /// * `Err(RegionTreeViolation)` if a violation is detected
    pub fn check(&self) -> Result<(), RegionTreeViolation> {
        let sorted_regions = self.sorted_region_ids();
        // Empty tree is valid
        if self.regions.is_empty() {
            return Ok(());
        }

        // 1. Check for exactly one root
        let mut roots: Vec<RegionId> = Vec::new();
        for region in &sorted_regions {
            let entry = self
                .regions
                .get(region)
                .expect("region missing from oracle");
            if entry.parent.is_none() {
                roots.push(*region);
            }
        }

        if roots.is_empty() {
            return Err(RegionTreeViolation::NoRoot);
        }

        if roots.len() > 1 {
            return Err(RegionTreeViolation::MultipleRoots { roots });
        }

        // 2. Check that every non-root region has a valid parent
        for region in &sorted_regions {
            let entry = self
                .regions
                .get(region)
                .expect("region missing from oracle");
            if let Some(parent) = entry.parent {
                if !self.regions.contains_key(&parent) {
                    return Err(RegionTreeViolation::InvalidParent {
                        region: *region,
                        claimed_parent: parent,
                    });
                }
            }
        }

        // 3. Check bidirectional consistency (child in parent's subregions)
        for region in &sorted_regions {
            let entry = self
                .regions
                .get(region)
                .expect("region missing from oracle");
            if let Some(parent) = entry.parent {
                if let Some(parent_entry) = self.regions.get(&parent) {
                    if !parent_entry.subregions.contains(region) {
                        return Err(RegionTreeViolation::ParentChildMismatch {
                            region: *region,
                            parent,
                        });
                    }
                }
            }
        }

        // 4. Reverse check: every subregion reference points to an existing region
        for parent in &sorted_regions {
            let entry = self
                .regions
                .get(parent)
                .expect("region missing from oracle");
            let mut children: Vec<RegionId> = entry.subregions.iter().copied().collect();
            children.sort();
            for child in children {
                let Some(child_entry) = self.regions.get(&child) else {
                    return Err(RegionTreeViolation::PhantomSubregion {
                        parent: *parent,
                        phantom_child: child,
                    });
                };

                // Reverse-edge consistency: if parent lists child, child must
                // also claim this parent.
                if child_entry.parent != Some(*parent) {
                    return Err(RegionTreeViolation::ParentChildMismatch {
                        region: child,
                        parent: *parent,
                    });
                }
            }
        }

        // 5. Check for cycles using DFS
        if let Some(cycle) = self.find_cycle() {
            return Err(RegionTreeViolation::CycleDetected { cycle });
        }

        Ok(())
    }

    /// Finds a cycle in the parent relationships, if one exists.
    ///
    /// Uses tortoise-and-hare algorithm for each region to detect cycles.
    fn find_cycle(&self) -> Option<Vec<RegionId>> {
        for start in self.sorted_region_ids() {
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
        let mut roots: Vec<RegionId> = Vec::new();
        for region in self.sorted_region_ids() {
            let entry = self
                .regions
                .get(&region)
                .expect("region missing from oracle");
            if entry.parent.is_none() {
                roots.push(region);
            }
        }

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

            let entry = self.regions.get(&current)?;
            if let Some(parent) = entry.parent {
                depth += 1;
                current = parent;
            } else {
                // Reached root
                return Some(depth);
            }
        }
    }

    fn sorted_region_ids(&self) -> Vec<RegionId> {
        let mut ids: Vec<RegionId> = self.regions.keys().copied().collect();
        ids.sort();
        ids
    }
}

#[cfg(test)]
#[path = "region_tree_inline_tests.rs"]
mod tests;
