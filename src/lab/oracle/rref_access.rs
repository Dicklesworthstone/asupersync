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

        // Check post-close access
        if let Some(&close_time) = self.closed_regions.get(&rref_region) {
            if time >= close_time {
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
mod tests {
    use super::*;
    use crate::util::ArenaIndex;

    fn region(n: u32) -> RegionId {
        RegionId::from_arena(ArenaIndex::new(n, 0))
    }

    fn task(n: u32) -> TaskId {
        TaskId::from_arena(ArenaIndex::new(n, 0))
    }

    fn t(nanos: u64) -> Time {
        Time::from_nanos(nanos)
    }

    fn rref(region_n: u32, alloc: u32) -> RRefId {
        RRefId::new(region(region_n), alloc)
    }

    // ================================================================
    // Positive tests (no violations)
    // ================================================================

    #[test]
    fn same_region_access_no_violation() {
        let mut oracle = RRefAccessOracle::new();
        let r = region(0);
        let tid = task(1);

        oracle.on_rref_create(rref(0, 0), r);
        oracle.on_task_spawn(tid, r);
        oracle.on_rref_access(rref(0, 0), tid, t(10));

        assert!(oracle.check().is_ok());
        assert_eq!(oracle.violation_count(), 0);
    }

    #[test]
    fn access_before_close_no_violation() {
        let mut oracle = RRefAccessOracle::new();
        let r = region(0);
        let tid = task(1);

        oracle.on_rref_create(rref(0, 0), r);
        oracle.on_task_spawn(tid, r);
        oracle.on_rref_access(rref(0, 0), tid, t(10));
        oracle.on_region_close(r, t(100));

        assert!(oracle.check().is_ok());
    }

    #[test]
    fn witness_matching_no_violation() {
        let mut oracle = RRefAccessOracle::new();
        let r = region(0);
        let tid = task(1);

        oracle.on_rref_create(rref(0, 0), r);
        oracle.on_task_spawn(tid, r);
        oracle.on_rref_access_with_witness(rref(0, 0), tid, r, t(10));

        assert!(oracle.check().is_ok());
    }

    #[test]
    fn multiple_rrefs_same_region_no_violation() {
        let mut oracle = RRefAccessOracle::new();
        let r = region(0);
        let tid = task(1);

        oracle.on_rref_create(rref(0, 0), r);
        oracle.on_rref_create(rref(0, 1), r);
        oracle.on_rref_create(rref(0, 2), r);
        oracle.on_task_spawn(tid, r);

        oracle.on_rref_access(rref(0, 0), tid, t(10));
        oracle.on_rref_access(rref(0, 1), tid, t(20));
        oracle.on_rref_access(rref(0, 2), tid, t(30));

        assert!(oracle.check().is_ok());
    }

    // ================================================================
    // Cross-region violation tests
    // ================================================================

    #[test]
    fn cross_region_access_detected() {
        let mut oracle = RRefAccessOracle::new();
        let r_a = region(0);
        let r_b = region(1);
        let tid = task(1);

        oracle.on_rref_create(rref(0, 0), r_a);
        oracle.on_task_spawn(tid, r_b); // Task is in region B
        oracle.on_rref_access(rref(0, 0), tid, t(10)); // Accessing region A's RRef

        let err = oracle.check().unwrap_err();
        assert_eq!(
            err.kind,
            RRefAccessViolationKind::CrossRegionAccess {
                rref_region: r_a,
                task_region: r_b,
            }
        );
    }

    // ================================================================
    // Post-close violation tests
    // ================================================================

    #[test]
    fn post_close_access_detected() {
        let mut oracle = RRefAccessOracle::new();
        let r = region(0);
        let tid = task(1);

        oracle.on_rref_create(rref(0, 0), r);
        oracle.on_task_spawn(tid, r);
        oracle.on_region_close(r, t(50));
        oracle.on_rref_access(rref(0, 0), tid, t(100)); // After close

        let err = oracle.check().unwrap_err();
        assert_eq!(
            err.kind,
            RRefAccessViolationKind::PostCloseAccess {
                region: r,
                close_time: t(50),
                access_time: t(100),
            }
        );
    }

    #[test]
    fn access_at_close_time_detected() {
        let mut oracle = RRefAccessOracle::new();
        let r = region(0);
        let tid = task(1);

        oracle.on_rref_create(rref(0, 0), r);
        oracle.on_task_spawn(tid, r);
        oracle.on_region_close(r, t(50));
        oracle.on_rref_access(rref(0, 0), tid, t(50)); // Exactly at close time

        assert!(oracle.check().is_err());
    }

    // ================================================================
    // Witness mismatch tests
    // ================================================================

    #[test]
    fn witness_mismatch_detected() {
        let mut oracle = RRefAccessOracle::new();
        let r_a = region(0);
        let r_b = region(1);
        let tid = task(1);

        oracle.on_rref_create(rref(0, 0), r_a);
        oracle.on_task_spawn(tid, r_a);
        // Witness from region B used with region A's RRef
        oracle.on_rref_access_with_witness(rref(0, 0), tid, r_b, t(10));

        let violations = oracle.all_violations();
        assert!(violations
            .iter()
            .any(|v| matches!(v.kind, RRefAccessViolationKind::WitnessMismatch { .. })));
    }

    // ================================================================
    // Multiple violation tests
    // ================================================================

    #[test]
    fn multiple_violations_all_recorded() {
        let mut oracle = RRefAccessOracle::new();
        let r_a = region(0);
        let r_b = region(1);
        let t1 = task(1);
        let t2 = task(2);

        oracle.on_rref_create(rref(0, 0), r_a);
        oracle.on_rref_create(rref(1, 0), r_b);
        oracle.on_task_spawn(t1, r_a);
        oracle.on_task_spawn(t2, r_b);

        // Cross-region: t2 accesses region A's rref
        oracle.on_rref_access(rref(0, 0), t2, t(10));
        // Post-close: close region B, then t1 accesses it
        oracle.on_region_close(r_b, t(20));
        oracle.on_rref_access(rref(1, 0), t1, t(30));

        let violations = oracle.all_violations();
        // 3 violations: cross-region (t2→rref in r_a), cross-region (t1→rref in r_b),
        // and post-close (r_b closed before t1 access)
        assert_eq!(violations.len(), 3);
    }

    // ================================================================
    // Reset and stats tests
    // ================================================================

    #[test]
    fn reset_clears_all_state() {
        let mut oracle = RRefAccessOracle::new();
        let r = region(0);
        let tid = task(1);

        oracle.on_rref_create(rref(0, 0), r);
        oracle.on_task_spawn(tid, r);
        oracle.on_region_close(r, t(10));
        oracle.on_rref_access(rref(0, 0), tid, t(20));

        assert!(oracle.check().is_err());

        oracle.reset();
        assert!(oracle.check().is_ok());
        assert_eq!(oracle.rref_count(), 0);
        assert_eq!(oracle.task_count(), 0);
        assert_eq!(oracle.closed_region_count(), 0);
        assert_eq!(oracle.violation_count(), 0);
    }

    #[test]
    fn stats_track_entities() {
        let mut oracle = RRefAccessOracle::new();
        let r = region(0);

        oracle.on_rref_create(rref(0, 0), r);
        oracle.on_rref_create(rref(0, 1), r);
        oracle.on_task_spawn(task(1), r);
        oracle.on_task_spawn(task(2), r);
        oracle.on_task_spawn(task(3), r);
        oracle.on_region_close(r, t(100));

        assert_eq!(oracle.rref_count(), 2);
        assert_eq!(oracle.task_count(), 3);
        assert_eq!(oracle.closed_region_count(), 1);
    }

    #[test]
    fn violation_display_formats() {
        let r_a = region(0);
        let r_b = region(1);
        let tid = task(1);

        let violations = vec![
            RRefAccessViolation {
                rref: rref(0, 0),
                task: tid,
                time: t(10),
                kind: RRefAccessViolationKind::CrossRegionAccess {
                    rref_region: r_a,
                    task_region: r_b,
                },
            },
            RRefAccessViolation {
                rref: rref(0, 0),
                task: tid,
                time: t(100),
                kind: RRefAccessViolationKind::PostCloseAccess {
                    region: r_a,
                    close_time: t(50),
                    access_time: t(100),
                },
            },
            RRefAccessViolation {
                rref: rref(0, 0),
                task: tid,
                time: t(10),
                kind: RRefAccessViolationKind::WitnessMismatch {
                    rref_region: r_a,
                    witness_region: r_b,
                },
            },
        ];

        for v in &violations {
            let msg = format!("{v}");
            assert!(!msg.is_empty(), "violation display should not be empty");
        }
    }
}
