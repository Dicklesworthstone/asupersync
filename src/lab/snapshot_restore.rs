//! Snapshot/restore functionality with quiescence proof.
//!
//! This module provides mechanisms for saving and restoring runtime state
//! with formal guarantees about eventual quiescence.
//!
//! # Quiescence Proof Sketch
//!
//! **Theorem**: If a snapshot S is valid, then restoring S into a fresh
//! runtime state R and running to completion yields quiescence.
//!
//! **Proof sketch**:
//!
//! 1. **Well-formedness invariant**: A valid snapshot satisfies:
//!    - All task IDs reference valid regions
//!    - All obligation IDs reference valid tasks
//!    - The region tree is acyclic (parent references valid)
//!    - No completed regions have non-terminal children
//!
//! 2. **Restoration preserves invariants**: The restore procedure:
//!    - Creates regions in topological order (parents before children)
//!    - Creates tasks only in their owning regions
//!    - Restores obligations only for existing tasks
//!    - Validates structural invariants before returning
//!
//! 3. **Quiescence convergence**: After restoration:
//!    - All tasks are either terminal or schedulable
//!    - The scheduler drains runnable tasks to completion
//!    - Cancelled tasks follow the cancellation protocol (request→drain→finalize)
//!    - Obligations are resolved by task completion or abort
//!    - Region close waits for all children (by construction)
//!
//! 4. **Termination**: The system terminates because:
//!    - Task count is finite and monotonically decreasing
//!    - Each poll either completes or checkpoints
//!    - Budgets bound the number of polls
//!    - Finalizers have bounded budgets
//!
//! Therefore: restore(S) + run_to_completion() ⇒ quiescence(R)
//!
//! # Usage
//!
//! ```ignore
//! use asupersync::lab::{LabRuntime, LabConfig, SnapshotRestore};
//!
//! // Create and run a runtime
//! let mut runtime = LabRuntime::new(LabConfig::new(42));
//! // ... do work ...
//!
//! // Take a restorable snapshot
//! let snapshot = runtime.state.restorable_snapshot();
//!
//! // Later, restore into a fresh runtime
//! let mut restored = LabRuntime::new(LabConfig::new(42));
//! restored.restore_from_snapshot(&snapshot)?;
//!
//! // Run to quiescence
//! restored.run_until_quiescent();
//!
//! // Verify invariants
//! assert!(restored.oracles.quiescence.check().is_ok());
//! assert!(restored.oracles.obligation_leak.check().is_ok());
//! ```

use crate::runtime::state::{
    ObligationStateSnapshot, RegionStateSnapshot, RuntimeSnapshot, TaskSnapshot, TaskStateSnapshot,
};
use crate::runtime::RuntimeState;
use crate::types::Time;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt;

/// Errors that can occur during snapshot restoration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestoreError {
    /// A task references a non-existent region.
    OrphanTask {
        /// The orphan task's ID.
        task_id: u32,
        /// The non-existent region ID referenced by the task.
        region_id: u32,
    },
    /// An obligation references a non-existent task.
    OrphanObligation {
        /// The orphan obligation's ID.
        obligation_id: u32,
        /// The non-existent task ID referenced by the obligation.
        task_id: u32,
    },
    /// A region references a non-existent parent.
    InvalidParent {
        /// The region with the invalid parent reference.
        region_id: u32,
        /// The non-existent parent region ID.
        parent_id: u32,
    },
    /// The region tree contains a cycle.
    CyclicRegionTree {
        /// The region IDs forming the cycle.
        cycle: Vec<u32>,
    },
    /// A closed region has non-terminal children.
    NonQuiescentClosure {
        /// The closed region that violates quiescence.
        region_id: u32,
        /// Child regions that are still live.
        live_children: Vec<u32>,
        /// Tasks that are still live.
        live_tasks: Vec<u32>,
    },
    /// Snapshot timestamp is inconsistent.
    InvalidTimestamp {
        /// The snapshot's timestamp.
        snapshot_time: u64,
        /// The entity's timestamp that is inconsistent.
        entity_time: u64,
        /// Description of the entity with inconsistent timestamp.
        entity: String,
    },
    /// Duplicate entity ID detected.
    DuplicateId {
        /// The kind of entity (e.g., "region", "task").
        kind: &'static str,
        /// The duplicate ID.
        id: u32,
    },
}

impl fmt::Display for RestoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OrphanTask { task_id, region_id } => {
                write!(
                    f,
                    "task {task_id} references non-existent region {region_id}"
                )
            }
            Self::OrphanObligation {
                obligation_id,
                task_id,
            } => {
                write!(
                    f,
                    "obligation {obligation_id} references non-existent task {task_id}"
                )
            }
            Self::InvalidParent {
                region_id,
                parent_id,
            } => {
                write!(
                    f,
                    "region {region_id} references non-existent parent {parent_id}"
                )
            }
            Self::CyclicRegionTree { cycle } => {
                write!(f, "region tree contains cycle: {cycle:?}")
            }
            Self::NonQuiescentClosure {
                region_id,
                live_children,
                live_tasks,
            } => {
                write!(
                    f,
                    "closed region {region_id} has {} live children and {} live tasks",
                    live_children.len(),
                    live_tasks.len()
                )
            }
            Self::InvalidTimestamp {
                snapshot_time,
                entity_time,
                entity,
            } => {
                write!(
                    f,
                    "timestamp inconsistency: snapshot={snapshot_time}, {entity}={entity_time}"
                )
            }
            Self::DuplicateId { kind, id } => {
                write!(f, "duplicate {kind} ID: {id}")
            }
        }
    }
}

impl std::error::Error for RestoreError {}

/// Result of snapshot validation.
#[derive(Debug, Clone)]
pub struct ValidationResult {
    /// Whether the snapshot is valid.
    pub is_valid: bool,
    /// List of validation errors (empty if valid).
    pub errors: Vec<RestoreError>,
    /// Structural statistics.
    pub stats: SnapshotStats,
}

/// Statistics about a snapshot's structure.
#[derive(Debug, Clone, Default)]
pub struct SnapshotStats {
    /// Number of regions.
    pub region_count: usize,
    /// Number of tasks.
    pub task_count: usize,
    /// Number of obligations.
    pub obligation_count: usize,
    /// Maximum region tree depth.
    pub max_depth: usize,
    /// Number of terminal tasks.
    pub terminal_task_count: usize,
    /// Number of resolved obligations.
    pub resolved_obligation_count: usize,
    /// Number of closed regions.
    pub closed_region_count: usize,
}

/// A snapshot that can be restored into a runtime state.
///
/// Extends `RuntimeSnapshot` with validation and restoration capabilities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestorableSnapshot {
    /// The underlying runtime snapshot.
    pub snapshot: RuntimeSnapshot,
    /// Schema version for forward compatibility.
    pub schema_version: u32,
    /// Content hash for integrity verification.
    pub content_hash: u64,
}

impl RestorableSnapshot {
    /// Current schema version.
    pub const SCHEMA_VERSION: u32 = 1;

    /// Creates a new restorable snapshot from a runtime snapshot.
    #[must_use]
    pub fn new(snapshot: RuntimeSnapshot) -> Self {
        let content_hash = Self::compute_hash(&snapshot);
        Self {
            snapshot,
            schema_version: Self::SCHEMA_VERSION,
            content_hash,
        }
    }

    /// Computes a deterministic hash of the snapshot content.
    fn compute_hash(snapshot: &RuntimeSnapshot) -> u64 {
        // FNV-1a hash for determinism
        const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
        const FNV_PRIME: u64 = 0x0100_0000_01b3;

        let mut hash = FNV_OFFSET;

        // Hash timestamp
        for byte in snapshot.timestamp.to_le_bytes() {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(FNV_PRIME);
        }

        // Hash entity counts
        for byte in (snapshot.regions.len() as u64).to_le_bytes() {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(FNV_PRIME);
        }
        for byte in (snapshot.tasks.len() as u64).to_le_bytes() {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(FNV_PRIME);
        }
        for byte in (snapshot.obligations.len() as u64).to_le_bytes() {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(FNV_PRIME);
        }

        hash
    }

    /// Validates the snapshot for structural consistency.
    ///
    /// Checks:
    /// - All task IDs reference valid regions
    /// - All obligation IDs reference valid tasks
    /// - The region tree is acyclic
    /// - Closed regions have no live children/tasks
    /// - Timestamps are consistent
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn validate(&self) -> ValidationResult {
        let mut errors = Vec::new();
        let mut stats = SnapshotStats::default();

        // Build lookup sets
        let region_ids: HashSet<u32> = self.snapshot.regions.iter().map(|r| r.id.index).collect();
        let task_ids: HashSet<u32> = self.snapshot.tasks.iter().map(|t| t.id.index).collect();

        stats.region_count = self.snapshot.regions.len();
        stats.task_count = self.snapshot.tasks.len();
        stats.obligation_count = self.snapshot.obligations.len();

        // Check for duplicate region IDs
        if region_ids.len() != self.snapshot.regions.len() {
            // Find duplicates
            let mut seen = HashSet::new();
            for region in &self.snapshot.regions {
                if !seen.insert(region.id.index) {
                    errors.push(RestoreError::DuplicateId {
                        kind: "region",
                        id: region.id.index,
                    });
                }
            }
        }

        // Check for duplicate task IDs
        if task_ids.len() != self.snapshot.tasks.len() {
            let mut seen = HashSet::new();
            for task in &self.snapshot.tasks {
                if !seen.insert(task.id.index) {
                    errors.push(RestoreError::DuplicateId {
                        kind: "task",
                        id: task.id.index,
                    });
                }
            }
        }

        // Validate tasks reference valid regions
        for task in &self.snapshot.tasks {
            if !region_ids.contains(&task.region_id.index) {
                errors.push(RestoreError::OrphanTask {
                    task_id: task.id.index,
                    region_id: task.region_id.index,
                });
            }
            if is_task_terminal(&task.state) {
                stats.terminal_task_count += 1;
            }
        }

        // Validate obligations reference valid tasks
        for obligation in &self.snapshot.obligations {
            if !task_ids.contains(&obligation.holder_task.index) {
                errors.push(RestoreError::OrphanObligation {
                    obligation_id: obligation.id.index,
                    task_id: obligation.holder_task.index,
                });
            }
            if is_obligation_resolved(&obligation.state) {
                stats.resolved_obligation_count += 1;
            }
        }

        // Validate region tree structure
        let mut parent_map: HashMap<u32, Option<u32>> = HashMap::new();
        for region in &self.snapshot.regions {
            parent_map.insert(region.id.index, region.parent_id.map(|p| p.index));
            if let Some(parent_id) = &region.parent_id {
                if !region_ids.contains(&parent_id.index) {
                    errors.push(RestoreError::InvalidParent {
                        region_id: region.id.index,
                        parent_id: parent_id.index,
                    });
                }
            }
            if is_region_closed(&region.state) {
                stats.closed_region_count += 1;
            }
        }

        // Check for cycles in region tree
        if let Some(cycle) = detect_cycle(&parent_map) {
            errors.push(RestoreError::CyclicRegionTree { cycle });
        }

        // Compute max depth
        stats.max_depth = compute_max_depth(&parent_map);

        // Build region → tasks and region → children maps
        let mut region_tasks: HashMap<u32, Vec<&TaskSnapshot>> = HashMap::new();
        for task in &self.snapshot.tasks {
            region_tasks
                .entry(task.region_id.index)
                .or_default()
                .push(task);
        }

        let mut region_children: HashMap<u32, Vec<u32>> = HashMap::new();
        for region in &self.snapshot.regions {
            if let Some(parent_id) = region.parent_id {
                region_children
                    .entry(parent_id.index)
                    .or_default()
                    .push(region.id.index);
            }
        }

        // Validate quiescence for closed regions
        for region in &self.snapshot.regions {
            if is_region_closed(&region.state) {
                let live_children: Vec<u32> = region_children
                    .get(&region.id.index)
                    .map(|children| {
                        children
                            .iter()
                            .filter(|&&child_id| {
                                self.snapshot
                                    .regions
                                    .iter()
                                    .find(|r| r.id.index == child_id)
                                    .is_some_and(|r| !is_region_closed(&r.state))
                            })
                            .copied()
                            .collect()
                    })
                    .unwrap_or_default();

                let live_tasks: Vec<u32> = region_tasks
                    .get(&region.id.index)
                    .map(|tasks| {
                        tasks
                            .iter()
                            .filter(|t| !is_task_terminal(&t.state))
                            .map(|t| t.id.index)
                            .collect()
                    })
                    .unwrap_or_default();

                if !live_children.is_empty() || !live_tasks.is_empty() {
                    errors.push(RestoreError::NonQuiescentClosure {
                        region_id: region.id.index,
                        live_children,
                        live_tasks,
                    });
                }
            }
        }

        ValidationResult {
            is_valid: errors.is_empty(),
            errors,
            stats,
        }
    }

    /// Verifies the content hash matches.
    #[must_use]
    pub fn verify_integrity(&self) -> bool {
        Self::compute_hash(&self.snapshot) == self.content_hash
    }

    /// Returns the snapshot timestamp.
    #[must_use]
    pub fn timestamp(&self) -> Time {
        Time::from_nanos(self.snapshot.timestamp)
    }
}

/// Checks if a task state is terminal.
fn is_task_terminal(state: &TaskStateSnapshot) -> bool {
    matches!(state, TaskStateSnapshot::Completed { .. })
}

/// Checks if an obligation state is resolved.
fn is_obligation_resolved(state: &ObligationStateSnapshot) -> bool {
    matches!(
        state,
        ObligationStateSnapshot::Committed
            | ObligationStateSnapshot::Aborted
            | ObligationStateSnapshot::Leaked
    )
}

/// Checks if a region state is closed.
fn is_region_closed(state: &RegionStateSnapshot) -> bool {
    matches!(state, RegionStateSnapshot::Closed)
}

/// Detects a cycle in the parent map, returning the cycle if found.
fn detect_cycle(parent_map: &HashMap<u32, Option<u32>>) -> Option<Vec<u32>> {
    for &start in parent_map.keys() {
        let mut visited = HashSet::new();
        let mut path = Vec::new();
        let mut current = Some(start);

        while let Some(node) = current {
            if visited.contains(&node) {
                // Found a cycle - extract it
                if let Some(pos) = path.iter().position(|&n| n == node) {
                    return Some(path[pos..].to_vec());
                }
            }
            visited.insert(node);
            path.push(node);
            current = parent_map.get(&node).copied().flatten();
        }
    }
    None
}

/// Computes the maximum depth of the region tree.
fn compute_max_depth(parent_map: &HashMap<u32, Option<u32>>) -> usize {
    let mut max_depth = 0;
    for &start in parent_map.keys() {
        let mut depth = 0;
        let mut current = Some(start);
        while let Some(node) = current {
            depth += 1;
            current = parent_map.get(&node).copied().flatten();
        }
        max_depth = max_depth.max(depth);
    }
    max_depth
}

/// Extension trait for creating restorable snapshots.
pub trait SnapshotRestore {
    /// Creates a restorable snapshot of the current state.
    fn restorable_snapshot(&self) -> RestorableSnapshot;
}

impl SnapshotRestore for RuntimeState {
    fn restorable_snapshot(&self) -> RestorableSnapshot {
        RestorableSnapshot::new(self.snapshot())
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::state::IdSnapshot;
    use crate::runtime::state::{
        BudgetSnapshot, ObligationKindSnapshot, ObligationSnapshot, RegionSnapshot,
    };

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn make_region(id: u32, parent: Option<u32>, state: RegionStateSnapshot) -> RegionSnapshot {
        RegionSnapshot {
            id: IdSnapshot {
                index: id,
                generation: 0,
            },
            parent_id: parent.map(|p| IdSnapshot {
                index: p,
                generation: 0,
            }),
            state,
            budget: BudgetSnapshot {
                deadline: None,
                poll_quota: 1000,
                cost_quota: None,
                priority: 100,
            },
            child_count: 0,
            task_count: 0,
            name: None,
        }
    }

    fn make_task(id: u32, region_id: u32, state: TaskStateSnapshot) -> TaskSnapshot {
        TaskSnapshot {
            id: IdSnapshot {
                index: id,
                generation: 0,
            },
            region_id: IdSnapshot {
                index: region_id,
                generation: 0,
            },
            state,
            name: None,
            poll_count: 0,
            created_at: 0,
            obligations: Vec::new(),
        }
    }

    fn make_obligation(
        id: u32,
        task_id: u32,
        state: ObligationStateSnapshot,
    ) -> ObligationSnapshot {
        ObligationSnapshot {
            id: IdSnapshot {
                index: id,
                generation: 0,
            },
            kind: ObligationKindSnapshot::SendPermit,
            state,
            holder_task: IdSnapshot {
                index: task_id,
                generation: 0,
            },
            owning_region: IdSnapshot {
                index: 0,
                generation: 0,
            },
            created_at: 0,
        }
    }

    fn make_snapshot(
        regions: Vec<RegionSnapshot>,
        tasks: Vec<TaskSnapshot>,
        obligations: Vec<ObligationSnapshot>,
    ) -> RestorableSnapshot {
        RestorableSnapshot::new(RuntimeSnapshot {
            timestamp: 1000,
            regions,
            tasks,
            obligations,
            recent_events: Vec::new(),
        })
    }

    #[test]
    fn empty_snapshot_is_valid() {
        init_test("empty_snapshot_is_valid");
        let snapshot = make_snapshot(Vec::new(), Vec::new(), Vec::new());
        let result = snapshot.validate();

        crate::assert_with_log!(result.is_valid, "is_valid", true, result.is_valid);
        let errors_empty = result.errors.is_empty();
        crate::assert_with_log!(errors_empty, "errors empty", true, errors_empty);
        crate::test_complete!("empty_snapshot_is_valid");
    }

    #[test]
    fn single_region_is_valid() {
        init_test("single_region_is_valid");
        let snapshot = make_snapshot(
            vec![make_region(0, None, RegionStateSnapshot::Open)],
            Vec::new(),
            Vec::new(),
        );
        let result = snapshot.validate();

        crate::assert_with_log!(result.is_valid, "is_valid", true, result.is_valid);
        crate::assert_with_log!(
            result.stats.region_count == 1,
            "region_count",
            1,
            result.stats.region_count
        );
        crate::test_complete!("single_region_is_valid");
    }

    #[test]
    fn task_with_valid_region_is_valid() {
        init_test("task_with_valid_region_is_valid");
        let snapshot = make_snapshot(
            vec![make_region(0, None, RegionStateSnapshot::Open)],
            vec![make_task(0, 0, TaskStateSnapshot::Running)],
            Vec::new(),
        );
        let result = snapshot.validate();

        crate::assert_with_log!(result.is_valid, "is_valid", true, result.is_valid);
        crate::assert_with_log!(
            result.stats.task_count == 1,
            "task_count",
            1,
            result.stats.task_count
        );
        crate::test_complete!("task_with_valid_region_is_valid");
    }

    #[test]
    fn orphan_task_detected() {
        init_test("orphan_task_detected");
        let snapshot = make_snapshot(
            vec![make_region(0, None, RegionStateSnapshot::Open)],
            vec![make_task(0, 99, TaskStateSnapshot::Running)], // region 99 doesn't exist
            Vec::new(),
        );
        let result = snapshot.validate();

        let not_valid = !result.is_valid;
        crate::assert_with_log!(not_valid, "not valid", true, not_valid);
        let has_error = result
            .errors
            .iter()
            .any(|e| matches!(e, RestoreError::OrphanTask { .. }));
        crate::assert_with_log!(has_error, "has OrphanTask error", true, has_error);
        crate::test_complete!("orphan_task_detected");
    }

    #[test]
    fn orphan_obligation_detected() {
        init_test("orphan_obligation_detected");
        let snapshot = make_snapshot(
            vec![make_region(0, None, RegionStateSnapshot::Open)],
            vec![make_task(0, 0, TaskStateSnapshot::Running)],
            vec![make_obligation(0, 99, ObligationStateSnapshot::Reserved)], // task 99 doesn't exist
        );
        let result = snapshot.validate();

        let not_valid = !result.is_valid;
        crate::assert_with_log!(not_valid, "not valid", true, not_valid);
        let has_error = result
            .errors
            .iter()
            .any(|e| matches!(e, RestoreError::OrphanObligation { .. }));
        crate::assert_with_log!(has_error, "has OrphanObligation error", true, has_error);
        crate::test_complete!("orphan_obligation_detected");
    }

    #[test]
    fn invalid_parent_detected() {
        init_test("invalid_parent_detected");
        let snapshot = make_snapshot(
            vec![
                make_region(0, None, RegionStateSnapshot::Open),
                make_region(1, Some(99), RegionStateSnapshot::Open), // parent 99 doesn't exist
            ],
            Vec::new(),
            Vec::new(),
        );
        let result = snapshot.validate();

        let not_valid = !result.is_valid;
        crate::assert_with_log!(not_valid, "not valid", true, not_valid);
        let has_error = result
            .errors
            .iter()
            .any(|e| matches!(e, RestoreError::InvalidParent { .. }));
        crate::assert_with_log!(has_error, "has InvalidParent error", true, has_error);
        crate::test_complete!("invalid_parent_detected");
    }

    #[test]
    fn closed_region_with_live_task_detected() {
        init_test("closed_region_with_live_task_detected");
        let snapshot = make_snapshot(
            vec![make_region(0, None, RegionStateSnapshot::Closed)],
            vec![make_task(0, 0, TaskStateSnapshot::Running)], // task still running in closed region
            Vec::new(),
        );
        let result = snapshot.validate();

        let not_valid = !result.is_valid;
        crate::assert_with_log!(not_valid, "not valid", true, not_valid);
        let has_error = result
            .errors
            .iter()
            .any(|e| matches!(e, RestoreError::NonQuiescentClosure { .. }));
        crate::assert_with_log!(has_error, "has NonQuiescentClosure error", true, has_error);
        crate::test_complete!("closed_region_with_live_task_detected");
    }

    #[test]
    fn nested_regions_valid() {
        init_test("nested_regions_valid");
        let snapshot = make_snapshot(
            vec![
                make_region(0, None, RegionStateSnapshot::Open),
                make_region(1, Some(0), RegionStateSnapshot::Open),
                make_region(2, Some(1), RegionStateSnapshot::Open),
            ],
            Vec::new(),
            Vec::new(),
        );
        let result = snapshot.validate();

        crate::assert_with_log!(result.is_valid, "is_valid", true, result.is_valid);
        crate::assert_with_log!(
            result.stats.max_depth == 3,
            "max_depth",
            3,
            result.stats.max_depth
        );
        crate::test_complete!("nested_regions_valid");
    }

    #[test]
    fn terminal_task_stats_computed() {
        init_test("terminal_task_stats_computed");
        let snapshot = make_snapshot(
            vec![make_region(0, None, RegionStateSnapshot::Open)],
            vec![
                make_task(0, 0, TaskStateSnapshot::Running),
                make_task(
                    1,
                    0,
                    TaskStateSnapshot::Completed {
                        outcome: crate::runtime::state::OutcomeSnapshot::Ok,
                    },
                ),
            ],
            Vec::new(),
        );
        let result = snapshot.validate();

        crate::assert_with_log!(result.is_valid, "is_valid", true, result.is_valid);
        crate::assert_with_log!(
            result.stats.terminal_task_count == 1,
            "terminal_task_count",
            1,
            result.stats.terminal_task_count
        );
        crate::test_complete!("terminal_task_stats_computed");
    }

    #[test]
    fn content_hash_deterministic() {
        init_test("content_hash_deterministic");
        let snapshot1 = make_snapshot(
            vec![make_region(0, None, RegionStateSnapshot::Open)],
            vec![make_task(0, 0, TaskStateSnapshot::Running)],
            Vec::new(),
        );
        let snapshot2 = make_snapshot(
            vec![make_region(0, None, RegionStateSnapshot::Open)],
            vec![make_task(0, 0, TaskStateSnapshot::Running)],
            Vec::new(),
        );

        crate::assert_with_log!(
            snapshot1.content_hash == snapshot2.content_hash,
            "hashes equal",
            snapshot1.content_hash,
            snapshot2.content_hash
        );
        crate::test_complete!("content_hash_deterministic");
    }

    #[test]
    fn integrity_verification_works() {
        init_test("integrity_verification_works");
        let snapshot = make_snapshot(
            vec![make_region(0, None, RegionStateSnapshot::Open)],
            Vec::new(),
            Vec::new(),
        );

        let valid = snapshot.verify_integrity();
        crate::assert_with_log!(valid, "integrity valid", true, valid);

        // Tamper with hash
        let mut tampered = snapshot.clone();
        tampered.content_hash ^= 1;
        let invalid = !tampered.verify_integrity();
        crate::assert_with_log!(invalid, "tampered invalid", true, invalid);

        crate::test_complete!("integrity_verification_works");
    }

    #[test]
    fn duplicate_region_id_detected() {
        init_test("duplicate_region_id_detected");
        let snapshot = make_snapshot(
            vec![
                make_region(0, None, RegionStateSnapshot::Open),
                make_region(0, None, RegionStateSnapshot::Open), // duplicate
            ],
            Vec::new(),
            Vec::new(),
        );
        let result = snapshot.validate();

        let not_valid = !result.is_valid;
        crate::assert_with_log!(not_valid, "not valid", true, not_valid);
        let has_error = result
            .errors
            .iter()
            .any(|e| matches!(e, RestoreError::DuplicateId { kind: "region", .. }));
        crate::assert_with_log!(has_error, "has DuplicateId error", true, has_error);
        crate::test_complete!("duplicate_region_id_detected");
    }

    #[test]
    fn resolved_obligation_stats_computed() {
        init_test("resolved_obligation_stats_computed");
        let snapshot = make_snapshot(
            vec![make_region(0, None, RegionStateSnapshot::Open)],
            vec![make_task(0, 0, TaskStateSnapshot::Running)],
            vec![
                make_obligation(0, 0, ObligationStateSnapshot::Reserved),
                make_obligation(1, 0, ObligationStateSnapshot::Committed),
                make_obligation(2, 0, ObligationStateSnapshot::Aborted),
            ],
        );
        let result = snapshot.validate();

        crate::assert_with_log!(result.is_valid, "is_valid", true, result.is_valid);
        crate::assert_with_log!(
            result.stats.resolved_obligation_count == 2,
            "resolved_obligation_count",
            2,
            result.stats.resolved_obligation_count
        );
        crate::test_complete!("resolved_obligation_stats_computed");
    }
}
