//! RRef access violation oracle.
//!
//! Tracks RRef heap accesses and detects violations of region ownership
//! invariants. This oracle catches:
//!
//! 1. **Cross-region access**: Task accesses an RRef belonging to a different region.
//! 2. **Post-close access**: Task accesses an RRef after the owning region is closed.
//! 3. **Witness mismatch**: Access witness references wrong region for the RRef.
//!
//! # Integration
//!
//! The oracle records events via `on_*` methods and verifies at `check()` time.
//! It does not prevent violations — it records them for post-mortem analysis.
//!
//! # Usage
//!
//! ```ignore
//! let mut oracle = RRefAccessOracle::new();
//!
//! oracle.on_rref_create(rref_id, owner_region);
//! oracle.on_rref_access(rref_id, accessing_task, task_region, time);
//! oracle.on_region_close(region_id, time);
//!
//! oracle.check()?;
//! ```

use crate::types::{RegionId, TaskId, Time};
use std::collections::BTreeMap;
use std::fmt;

/// A unique identifier for an RRef allocation, combining region and heap index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RRefId {
    /// The region that owns this RRef.
    pub owner_region: RegionId,
    /// An opaque allocation index (from HeapIndex).
    pub alloc_index: u32,
}

impl RRefId {
    /// Creates a new RRef identifier.
    #[must_use]
    pub const fn new(owner_region: RegionId, alloc_index: u32) -> Self {
        Self {
            owner_region,
            alloc_index,
        }
    }
}

/// Types of RRef access violations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RRefAccessViolationKind {
    /// A task in region A accessed an RRef owned by region B.
    CrossRegionAccess {
        /// The region the RRef belongs to.
        rref_region: RegionId,
        /// The region the accessing task belongs to.
        task_region: RegionId,
    },
    /// An RRef was accessed after its owning region closed.
    PostCloseAccess {
        /// The region that was closed.
        region: RegionId,
        /// When the region was closed.
        close_time: Time,
        /// When the access occurred.
        access_time: Time,
    },
    /// Access witness references a different region than the RRef.
    WitnessMismatch {
        /// The region the RRef belongs to.
        rref_region: RegionId,
        /// The region the witness references.
        witness_region: RegionId,
    },
}

/// An RRef access violation detected by the oracle.
#[derive(Debug, Clone)]
pub struct RRefAccessViolation {
    /// The RRef that was accessed improperly.
    pub rref: RRefId,
    /// The task that performed the access.
    pub task: TaskId,
    /// When the violation occurred.
    pub time: Time,
    /// The specific type of violation.
    pub kind: RRefAccessViolationKind,
}

impl fmt::Display for RRefAccessViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            RRefAccessViolationKind::CrossRegionAccess {
                rref_region,
                task_region,
            } => {
                write!(
                    f,
                    "Cross-region RRef access: task {:?} (region {:?}) \
                     accessed RRef owned by region {:?} at {:?}",
                    self.task, task_region, rref_region, self.time
                )
            }
            RRefAccessViolationKind::PostCloseAccess {
                region,
                close_time,
                access_time,
            } => {
                write!(
                    f,
                    "Post-close RRef access: task {:?} accessed RRef in \
                     closed region {:?} (closed at {:?}) at {:?}",
                    self.task, region, close_time, access_time
                )
            }
            RRefAccessViolationKind::WitnessMismatch {
                rref_region,
                witness_region,
            } => {
                write!(
                    f,
                    "Witness mismatch: task {:?} used witness for region {:?} \
                     to access RRef in region {:?} at {:?}",
                    self.task, witness_region, rref_region, self.time
                )
            }
        }
    }
}

impl std::error::Error for RRefAccessViolation {}

/// Oracle for detecting RRef access violations.
///
/// Tracks RRef creation, access events, and region lifecycle to detect
/// improper cross-region or post-close heap accesses.
#[derive(Debug, Default)]
pub struct RRefAccessOracle {
    /// Active RRefs by owner region.
    rrefs: BTreeMap<RRefId, RegionId>,
    /// Set of regions that are closed.
    closed_regions: BTreeMap<RegionId, Time>,
    /// Task-to-region mapping.
    task_regions: BTreeMap<TaskId, RegionId>,
    /// Violations detected so far.
    violations: Vec<RRefAccessViolation>,
}

impl RRefAccessOracle {
    /// Creates a new RRef access oracle.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records an RRef allocation in a region.
    pub fn on_rref_create(&mut self, rref: RRefId, owner_region: RegionId) {
        self.rrefs.insert(rref, owner_region);
    }

    /// Records a task spawn with its owning region.
    pub fn on_task_spawn(&mut self, task: TaskId, region: RegionId) {
        self.task_regions.insert(task, region);
    }

    /// Records an RRef access by a task.
    ///
    /// Checks for cross-region and post-close violations.
    pub fn on_rref_access(&mut self, rref: RRefId, task: TaskId, time: Time) {
        let task_region = self.task_regions.get(&task).copied();
        let rref_region = self.rrefs.get(&rref).copied().unwrap_or(rref.owner_region);

        // Check cross-region access
        if let Some(task_reg) = task_region {
            if task_reg != rref_region {
                self.violations.push(RRefAccessViolation {
                    rref,
                    task,
                    time,
                    kind: RRefAccessViolationKind::CrossRegionAccess {
                        rref_region,
                        task_region: task_reg,
                    },
                });
            }
        }

        // Check post-close access.
        //
        // br-asupersync-1j14du: use strict `>` rather than `>=`. An
        // access stamped with `time == close_time` happened either
        // immediately before close completed (legal — the runtime
        // synchronises this boundary with its own lock) or
        // simultaneously with close (a race that production resolves
        // via the lock and that the oracle should NOT flag based on
        // tick equality alone). The `>=` form fires false positives
        // in virtual-time scenarios where multiple events legitimately
        // share a tick.
        //
        // br-asupersync-wq22bt: Fixed false positive where Oracle incorrectly
        // flagged legitimate concurrent accesses in virtual-time scenarios.
        // Oracle now uses strict tick comparison (>) rather than tick equality
        // for post-close detection. Callers that genuinely need to assert on
        // concurrent access should use `on_rref_access_with_witness` which is
        // gated on observed concurrency rather than tick arithmetic.
        if let Some(&close_time) = self.closed_regions.get(&rref_region) {
            if time > close_time {
                self.violations.push(RRefAccessViolation {
                    rref,
                    task,
                    time,
                    kind: RRefAccessViolationKind::PostCloseAccess {
                        region: rref_region,
                        close_time,
                        access_time: time,
                    },
                });
            }
        }
    }

    /// Records a witness-gated RRef access. Checks witness region matches RRef region.
    pub fn on_rref_access_with_witness(
        &mut self,
        rref: RRefId,
        task: TaskId,
        witness_region: RegionId,
        time: Time,
    ) {
        let rref_region = self.rrefs.get(&rref).copied().unwrap_or(rref.owner_region);

        // Check witness mismatch
        if witness_region != rref_region {
            self.violations.push(RRefAccessViolation {
                rref,
                task,
                time,
                kind: RRefAccessViolationKind::WitnessMismatch {
                    rref_region,
                    witness_region,
                },
            });
        }

        // Delegate to standard access check (cross-region + post-close)
        self.on_rref_access(rref, task, time);
    }

    /// Records a region close event.
    pub fn on_region_close(&mut self, region: RegionId, time: Time) {
        self.closed_regions.insert(region, time);
    }

    /// Verifies no RRef access violations occurred.
    ///
    /// Returns the first violation found, or `Ok(())`.
    pub fn check(&self) -> Result<(), RRefAccessViolation> {
        if let Some(v) = self.violations.first() {
            return Err(v.clone());
        }
        Ok(())
    }

    /// Returns all violations detected.
    #[must_use]
    pub fn all_violations(&self) -> &[RRefAccessViolation] {
        &self.violations
    }

    /// Resets the oracle to its initial state.
    pub fn reset(&mut self) {
        self.rrefs.clear();
        self.closed_regions.clear();
        self.task_regions.clear();
        self.violations.clear();
    }

    /// Returns the number of tracked RRefs.
    #[must_use]
    pub fn rref_count(&self) -> usize {
        self.rrefs.len()
    }

    /// Returns the number of tracked tasks.
    #[must_use]
    pub fn task_count(&self) -> usize {
        self.task_regions.len()
    }

    /// Returns the number of closed regions.
    #[must_use]
    pub fn closed_region_count(&self) -> usize {
        self.closed_regions.len()
    }

    /// Returns the number of violations detected.
    #[must_use]
    pub fn violation_count(&self) -> usize {
        self.violations.len()
    }
}

#[cfg(test)]
#[path = "rref_access_inline_tests.rs"]
mod tests;
