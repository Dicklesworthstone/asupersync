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

use crate::runtime::RuntimeState;
use crate::runtime::state::{
    EventSnapshot, FinalizerHistoryEvent, IdSnapshot, LoserDrainHistoryEvent, ObligationSnapshot,
    ObligationStateSnapshot, RegionSnapshot, RegionStateSnapshot, RuntimeSnapshot, TaskSnapshot,
    TaskStateSnapshot,
};
use crate::types::Time;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;

/// Magic bytes for the owned runtime-snapshot artifact envelope.
pub const SNAPSHOT_ARTIFACT_MAGIC: [u8; 8] = *b"ASUPSNAP";

/// Current owned runtime-snapshot artifact envelope version.
pub const SNAPSHOT_ARTIFACT_VERSION: u16 = 1;

const SNAPSHOT_ARTIFACT_HEADER_LEN: usize = 52;
const SNAPSHOT_ARTIFACT_KIND_FULL: u8 = 0;
const SNAPSHOT_ARTIFACT_KIND_INCREMENTAL: u8 = 1;
const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0100_0000_01b3;

/// Errors that can occur during snapshot restoration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestoreError {
    /// The snapshot schema is outside the supported compatibility window.
    UnsupportedSchemaVersion {
        /// Version carried by the snapshot.
        actual: u32,
        /// Oldest readable schema version.
        minimum: u32,
        /// Newest readable schema version.
        maximum: u32,
    },
    /// The stored content hash does not match the snapshot state.
    ContentHashMismatch,
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
    /// An obligation references a non-existent owning region.
    OrphanObligationRegion {
        /// The orphan obligation's ID.
        obligation_id: u32,
        /// The non-existent region ID referenced by the obligation.
        region_id: u32,
    },
    /// An obligation's owning region disagrees with its holder task's region.
    ObligationRegionMismatch {
        /// The obligation with inconsistent ownership.
        obligation_id: u32,
        /// The task holding the obligation.
        task_id: u32,
        /// The holder task's actual region.
        holder_region_id: u32,
        /// The obligation's recorded owning region.
        owning_region_id: u32,
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
    /// An obligation is still unresolved (Reserved/pending) even though its
    /// context can no longer make progress: either its owning region is
    /// `Closed`, or its holder task is terminal (`Completed`). Such a snapshot
    /// can never reach quiescence because nothing remains to commit or abort it.
    UnresolvedObligation {
        /// The unresolved obligation's ID.
        obligation_id: u32,
        /// The task holding the obligation.
        holder_task_id: u32,
        /// The obligation's owning region.
        owning_region_id: u32,
        /// Why quiescence is unreachable
        /// (`"closed region"` or `"terminal holder task"`).
        reason: &'static str,
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
            Self::UnsupportedSchemaVersion {
                actual,
                minimum,
                maximum,
            } => {
                write!(
                    f,
                    "snapshot schema version {actual} is outside supported range \
                     {minimum}..={maximum}"
                )
            }
            Self::ContentHashMismatch => {
                f.write_str("snapshot content hash does not match its state")
            }
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
            Self::OrphanObligationRegion {
                obligation_id,
                region_id,
            } => {
                write!(
                    f,
                    "obligation {obligation_id} references non-existent owning region {region_id}"
                )
            }
            Self::ObligationRegionMismatch {
                obligation_id,
                task_id,
                holder_region_id,
                owning_region_id,
            } => {
                write!(
                    f,
                    "obligation {obligation_id} held by task {task_id} is in region \
                     {holder_region_id}, but records owning region {owning_region_id}"
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
            Self::UnresolvedObligation {
                obligation_id,
                holder_task_id,
                owning_region_id,
                reason,
            } => {
                write!(
                    f,
                    "obligation {obligation_id} (holder task {holder_task_id}, owning region \
                     {owning_region_id}) is unresolved but can never resolve: {reason}"
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

/// Admission limits for owned runtime-snapshot artifacts.
///
/// The byte limit is enforced before JSON decoding. Collection limits and
/// region-tree depth are checked after decoding and again after applying an
/// incremental snapshot to its base.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotLimits {
    /// Maximum complete envelope or legacy JSON size.
    pub max_artifact_bytes: usize,
    /// Maximum number of region records.
    pub max_regions: usize,
    /// Maximum number of task records.
    pub max_tasks: usize,
    /// Maximum number of obligation records.
    pub max_obligations: usize,
    /// Maximum number of recent trace events.
    pub max_recent_events: usize,
    /// Maximum number of finalizer history records.
    pub max_finalizer_history: usize,
    /// Maximum number of loser-drain history records.
    pub max_loser_drain_history: usize,
    /// Maximum admitted region-parent depth.
    pub max_region_depth: usize,
}

impl SnapshotLimits {
    /// Conservative default admission envelope for persisted runtime state.
    pub const DEFAULT: Self = Self {
        max_artifact_bytes: 64 * 1024 * 1024,
        max_regions: 1_000_000,
        max_tasks: 1_000_000,
        max_obligations: 1_000_000,
        max_recent_events: 10_000_000,
        max_finalizer_history: 1_000_000,
        max_loser_drain_history: 1_000_000,
        max_region_depth: 4_096,
    };
}

impl Default for SnapshotLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Whether an owned artifact carries complete state or a delta from a base.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotArtifactKind {
    /// Complete restorable runtime state.
    Full,
    /// Entity-level changes relative to a named base content hash.
    Incremental,
}

/// Entity-level delta between two complete runtime snapshots.
///
/// Primary state tables use sorted upsert and removal lists. Trace and oracle
/// histories are ordered logs, so an incremental artifact carries their target
/// value in full rather than attempting an order-sensitive splice.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncrementalSnapshot {
    /// Content hash of the required base snapshot.
    pub base_content_hash: u64,
    /// Schema version of the materialized target.
    pub target_schema_version: u32,
    /// Content hash of the materialized target.
    pub target_content_hash: u64,
    /// Target snapshot timestamp.
    pub timestamp: u64,
    /// Added or changed regions, sorted by identifier.
    pub region_upserts: Vec<RegionSnapshot>,
    /// Removed region identifiers, sorted by identifier.
    pub removed_regions: Vec<IdSnapshot>,
    /// Added or changed tasks, sorted by identifier.
    pub task_upserts: Vec<TaskSnapshot>,
    /// Removed task identifiers, sorted by identifier.
    pub removed_tasks: Vec<IdSnapshot>,
    /// Added or changed obligations, sorted by identifier.
    pub obligation_upserts: Vec<ObligationSnapshot>,
    /// Removed obligation identifiers, sorted by identifier.
    pub removed_obligations: Vec<IdSnapshot>,
    /// Complete target recent-event window.
    pub recent_events: Vec<EventSnapshot>,
    /// Complete target finalizer history.
    pub finalizer_history: Vec<FinalizerHistoryEvent>,
    /// Complete target loser-drain history.
    pub loser_drain_history: Vec<LoserDrainHistoryEvent>,
}

/// Versioned owned runtime-snapshot artifact.
#[derive(Debug, Clone)]
pub enum SnapshotArtifact {
    /// Complete runtime snapshot.
    Full(RestorableSnapshot),
    /// Incremental state relative to a required base snapshot.
    Incremental(IncrementalSnapshot),
}

/// Failures while encoding, decoding, or materializing a snapshot artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotCodecError {
    /// Input is shorter than the fixed envelope header.
    TruncatedHeader {
        /// Actual input length.
        actual: usize,
    },
    /// Neither the owned envelope magic nor legacy JSON was detected.
    InvalidMagic,
    /// The owned envelope version is not supported.
    UnsupportedArtifactVersion {
        /// Version found in the input.
        actual: u16,
    },
    /// The full/incremental kind tag is not defined.
    InvalidArtifactKind {
        /// Kind byte found in the input.
        actual: u8,
    },
    /// Reserved envelope flags were non-zero.
    UnsupportedFlags {
        /// Flags byte found in the input.
        actual: u8,
    },
    /// Declared or actual artifact bytes exceed the admission envelope.
    ArtifactTooLarge {
        /// Observed or declared size.
        actual: usize,
        /// Configured maximum.
        maximum: usize,
    },
    /// Declared payload length did not exactly consume the input.
    LengthMismatch {
        /// Total length implied by the header.
        declared_total: usize,
        /// Actual input length.
        actual: usize,
    },
    /// The payload checksum did not match.
    ChecksumMismatch,
    /// JSON payload decoding or encoding failed.
    Json {
        /// Owned backend diagnostic.
        message: String,
    },
    /// A decoded collection or tree exceeds its configured bound.
    LimitExceeded {
        /// Bounded resource name.
        resource: &'static str,
        /// Observed count or depth.
        actual: usize,
        /// Configured maximum.
        maximum: usize,
    },
    /// Structural validation or content integrity failed.
    InvalidSnapshot {
        /// Number of validation failures.
        error_count: usize,
    },
    /// Incremental entity lists are internally inconsistent.
    InvalidDelta {
        /// Actionable structural diagnostic.
        message: String,
    },
    /// An incremental artifact was materialized without a base.
    MissingBase,
    /// The supplied base snapshot does not match the delta's declared base.
    BaseHashMismatch {
        /// Hash required by the incremental artifact.
        expected: u64,
        /// Hash carried by the supplied base.
        actual: u64,
    },
    /// Applying a delta did not reproduce its declared target hash.
    TargetHashMismatch {
        /// Hash declared by the incremental artifact.
        expected: u64,
        /// Hash computed after materialization.
        actual: u64,
    },
}

impl fmt::Display for SnapshotCodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[ASUP-E404] snapshot artifact ")?;
        match self {
            Self::TruncatedHeader { actual } => {
                write!(
                    f,
                    "is truncated: {actual} bytes, need at least \
                     {SNAPSHOT_ARTIFACT_HEADER_LEN}"
                )
            }
            Self::InvalidMagic => f.write_str("has unknown magic"),
            Self::UnsupportedArtifactVersion { actual } => {
                write!(
                    f,
                    "version {actual} is unsupported; expected {SNAPSHOT_ARTIFACT_VERSION}"
                )
            }
            Self::InvalidArtifactKind { actual } => {
                write!(f, "kind byte {actual} is unsupported")
            }
            Self::UnsupportedFlags { actual } => {
                write!(f, "flags byte {actual:#04x} is unsupported")
            }
            Self::ArtifactTooLarge { actual, maximum } => {
                write!(f, "size {actual} exceeds limit {maximum}")
            }
            Self::LengthMismatch {
                declared_total,
                actual,
            } => {
                write!(
                    f,
                    "length mismatch: header declares {declared_total} total bytes, got {actual}"
                )
            }
            Self::ChecksumMismatch => f.write_str("payload checksum mismatch"),
            Self::Json { message } => write!(f, "JSON payload failed: {message}"),
            Self::LimitExceeded {
                resource,
                actual,
                maximum,
            } => {
                write!(f, "{resource} count/depth {actual} exceeds limit {maximum}")
            }
            Self::InvalidSnapshot { error_count } => {
                write!(
                    f,
                    "failed structural validation with {error_count} error(s)"
                )
            }
            Self::InvalidDelta { message } => {
                write!(f, "incremental payload is invalid: {message}")
            }
            Self::MissingBase => f.write_str("incremental payload requires a base snapshot"),
            Self::BaseHashMismatch { expected, actual } => {
                write!(
                    f,
                    "base hash mismatch: expected {expected:#018x}, got {actual:#018x}"
                )
            }
            Self::TargetHashMismatch { expected, actual } => {
                write!(
                    f,
                    "target hash mismatch: expected {expected:#018x}, got {actual:#018x}"
                )
            }
        }
    }
}

impl std::error::Error for SnapshotCodecError {}

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
    pub const SCHEMA_VERSION: u32 = 2;

    /// Oldest schema version accepted by the compatibility reader.
    pub const MINIMUM_SUPPORTED_SCHEMA_VERSION: u32 = 1;

    /// Creates a new restorable snapshot from a runtime snapshot.
    #[must_use]
    pub fn new(snapshot: RuntimeSnapshot) -> Self {
        let snapshot = canonicalize_runtime_snapshot(snapshot);
        let schema_version = Self::SCHEMA_VERSION;
        let content_hash = Self::compute_hash(schema_version, &snapshot);
        Self {
            snapshot,
            schema_version,
            content_hash,
        }
    }

    /// Computes a deterministic hash of the snapshot content.
    fn compute_hash(schema_version: u32, snapshot: &RuntimeSnapshot) -> u64 {
        let mut hash = FNV_OFFSET;
        for byte in schema_version.to_le_bytes() {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(FNV_PRIME);
        }

        // Schema v1 hashed the caller-provided vector order. Keep that exact
        // behavior for legacy reads. Schema v2 canonicalizes entity tables and
        // recent events before hashing so equivalent state has stable bytes.
        let canonical;
        let hash_input = if schema_version >= 2 {
            canonical = canonicalize_runtime_snapshot(snapshot.clone());
            &canonical
        } else {
            snapshot
        };
        if let Ok(encoded) = serde_json::to_vec(hash_input) {
            for byte in encoded {
                hash ^= u64::from(byte);
                hash = hash.wrapping_mul(FNV_PRIME);
            }
        } else {
            // Keep behavior deterministic even if serialization unexpectedly fails.
            for byte in b"snapshot-hash-serialization-error" {
                hash ^= u64::from(*byte);
                hash = hash.wrapping_mul(FNV_PRIME);
            }
        }

        hash
    }

    const fn schema_version_is_supported(schema_version: u32) -> bool {
        schema_version >= Self::MINIMUM_SUPPORTED_SCHEMA_VERSION
            && schema_version <= Self::SCHEMA_VERSION
    }

    /// Returns a current-schema canonical copy after validating the source.
    ///
    /// This is the explicit migration boundary for legacy schema-v1 JSON.
    /// Callers retain the original bytes or path for rollback.
    pub fn migrate_to_current(&self) -> Result<Self, SnapshotCodecError> {
        ensure_snapshot_valid(self)?;
        Ok(Self::new(self.snapshot.clone()))
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

        if !Self::schema_version_is_supported(self.schema_version) {
            errors.push(RestoreError::UnsupportedSchemaVersion {
                actual: self.schema_version,
                minimum: Self::MINIMUM_SUPPORTED_SCHEMA_VERSION,
                maximum: Self::SCHEMA_VERSION,
            });
        } else if !self.verify_integrity() {
            errors.push(RestoreError::ContentHashMismatch);
        }

        // Referential integrity must include generations to reject stale slot reuse.
        let region_ids: HashSet<SnapshotIdKey> = self
            .snapshot
            .regions
            .iter()
            .map(|region| snapshot_id_key(region.id))
            .collect();
        let task_ids: HashSet<SnapshotIdKey> = self
            .snapshot
            .tasks
            .iter()
            .map(|task| snapshot_id_key(task.id))
            .collect();
        let task_regions: HashMap<SnapshotIdKey, SnapshotIdKey> = self
            .snapshot
            .tasks
            .iter()
            .map(|task| (snapshot_id_key(task.id), snapshot_id_key(task.region_id)))
            .collect();
        let region_slots: HashSet<u32> = self
            .snapshot
            .regions
            .iter()
            .map(|region| region.id.index)
            .collect();
        let task_slots: HashSet<u32> = self
            .snapshot
            .tasks
            .iter()
            .map(|task| task.id.index)
            .collect();
        let obligation_slots: HashSet<u32> = self
            .snapshot
            .obligations
            .iter()
            .map(|obligation| obligation.id.index)
            .collect();

        stats.region_count = self.snapshot.regions.len();
        stats.task_count = self.snapshot.tasks.len();
        stats.obligation_count = self.snapshot.obligations.len();
        let snapshot_time = self.snapshot.timestamp;

        // Check for duplicate region IDs
        if region_slots.len() != self.snapshot.regions.len() {
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
        if task_slots.len() != self.snapshot.tasks.len() {
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

        // Check for duplicate obligation IDs
        if obligation_slots.len() != self.snapshot.obligations.len() {
            let mut seen = HashSet::new();
            for obligation in &self.snapshot.obligations {
                if !seen.insert(obligation.id.index) {
                    errors.push(RestoreError::DuplicateId {
                        kind: "obligation",
                        id: obligation.id.index,
                    });
                }
            }
        }

        // Validate tasks reference valid regions
        for task in &self.snapshot.tasks {
            if task.created_at > snapshot_time {
                errors.push(RestoreError::InvalidTimestamp {
                    snapshot_time,
                    entity_time: task.created_at,
                    entity: format!("task {} created_at", task.id.index),
                });
            }
            if !region_ids.contains(&snapshot_id_key(task.region_id)) {
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
            if obligation.created_at > snapshot_time {
                errors.push(RestoreError::InvalidTimestamp {
                    snapshot_time,
                    entity_time: obligation.created_at,
                    entity: format!("obligation {} created_at", obligation.id.index),
                });
            }
            if !task_ids.contains(&snapshot_id_key(obligation.holder_task)) {
                errors.push(RestoreError::OrphanObligation {
                    obligation_id: obligation.id.index,
                    task_id: obligation.holder_task.index,
                });
            }
            if !region_ids.contains(&snapshot_id_key(obligation.owning_region)) {
                errors.push(RestoreError::OrphanObligationRegion {
                    obligation_id: obligation.id.index,
                    region_id: obligation.owning_region.index,
                });
            } else if let Some(holder_region_id) =
                task_regions.get(&snapshot_id_key(obligation.holder_task))
            {
                if *holder_region_id != snapshot_id_key(obligation.owning_region) {
                    errors.push(RestoreError::ObligationRegionMismatch {
                        obligation_id: obligation.id.index,
                        task_id: obligation.holder_task.index,
                        holder_region_id: holder_region_id.0,
                        owning_region_id: obligation.owning_region.index,
                    });
                }
            }
            if is_obligation_resolved(&obligation.state) {
                stats.resolved_obligation_count += 1;
            }
        }

        // Validate region tree structure
        let mut parent_map: HashMap<SnapshotIdKey, Option<SnapshotIdKey>> = HashMap::new();
        for region in &self.snapshot.regions {
            parent_map.insert(
                snapshot_id_key(region.id),
                region.parent_id.map(snapshot_id_key),
            );
            if let Some(parent_id) = &region.parent_id {
                if !region_ids.contains(&snapshot_id_key(*parent_id)) {
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
        let mut region_tasks: HashMap<SnapshotIdKey, Vec<&TaskSnapshot>> = HashMap::new();
        for task in &self.snapshot.tasks {
            region_tasks
                .entry(snapshot_id_key(task.region_id))
                .or_default()
                .push(task);
        }

        let mut region_children: HashMap<SnapshotIdKey, Vec<SnapshotIdKey>> = HashMap::new();
        let mut closed_regions: HashSet<SnapshotIdKey> = HashSet::new();
        for region in &self.snapshot.regions {
            if is_region_closed(&region.state) {
                closed_regions.insert(snapshot_id_key(region.id));
            }
            if let Some(parent_id) = region.parent_id {
                region_children
                    .entry(snapshot_id_key(parent_id))
                    .or_default()
                    .push(snapshot_id_key(region.id));
            }
        }

        // Validate quiescence for closed regions
        for region in &self.snapshot.regions {
            if is_region_closed(&region.state) {
                let region_id = snapshot_id_key(region.id);
                let live_children: Vec<u32> = region_children
                    .get(&region_id)
                    .map(|children| {
                        children
                            .iter()
                            .filter(|&&child_id| !closed_regions.contains(&child_id))
                            .map(|&(child_index, _)| child_index)
                            .collect()
                    })
                    .unwrap_or_default();

                let live_tasks: Vec<u32> = region_tasks
                    .get(&region_id)
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

        // Obligation-resolution invariant. Quiescence requires that every
        // obligation is eventually resolved (Committed/Aborted/Leaked). An
        // obligation still Reserved/pending can only resolve while its owning
        // region is live and its holder task is live. If either has already
        // reached a terminal state, the obligation is stranded and the snapshot
        // can never quiesce — reject it. (The closed-region quiescence check
        // above only inspects live child regions and live tasks, never
        // obligations, so this closes that gap.)
        let terminal_tasks: HashSet<SnapshotIdKey> = self
            .snapshot
            .tasks
            .iter()
            .filter(|task| is_task_terminal(&task.state))
            .map(|task| snapshot_id_key(task.id))
            .collect();
        for obligation in &self.snapshot.obligations {
            if is_obligation_resolved(&obligation.state) {
                continue;
            }
            let owning_region = snapshot_id_key(obligation.owning_region);
            let holder = snapshot_id_key(obligation.holder_task);
            if closed_regions.contains(&owning_region) {
                errors.push(RestoreError::UnresolvedObligation {
                    obligation_id: obligation.id.index,
                    holder_task_id: obligation.holder_task.index,
                    owning_region_id: obligation.owning_region.index,
                    reason: "closed region",
                });
            } else if terminal_tasks.contains(&holder) {
                errors.push(RestoreError::UnresolvedObligation {
                    obligation_id: obligation.id.index,
                    holder_task_id: obligation.holder_task.index,
                    owning_region_id: obligation.owning_region.index,
                    reason: "terminal holder task",
                });
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
        Self::compute_hash(self.schema_version, &self.snapshot) == self.content_hash
    }

    /// Returns the snapshot timestamp.
    #[must_use]
    pub fn timestamp(&self) -> Time {
        Time::from_nanos(self.snapshot.timestamp)
    }
}

impl SnapshotArtifact {
    /// Builds a validated full artifact.
    pub fn full(
        snapshot: RestorableSnapshot,
        limits: SnapshotLimits,
    ) -> Result<Self, SnapshotCodecError> {
        ensure_snapshot_valid(&snapshot)?;
        validate_snapshot_limits(&snapshot.snapshot, limits)?;
        Ok(Self::Full(snapshot))
    }

    /// Builds a deterministic incremental artifact between two snapshots.
    ///
    /// The target is migrated to the current canonical schema. The base keeps
    /// its own supported schema version so existing schema-v1 content hashes
    /// remain usable as rollback anchors.
    pub fn incremental(
        base: &RestorableSnapshot,
        target: &RestorableSnapshot,
        limits: SnapshotLimits,
    ) -> Result<Self, SnapshotCodecError> {
        ensure_snapshot_valid(base)?;
        validate_snapshot_limits(&base.snapshot, limits)?;
        let target = target.migrate_to_current()?;
        validate_snapshot_limits(&target.snapshot, limits)?;

        let base_state = canonicalize_runtime_snapshot(base.snapshot.clone());
        let target_state = canonicalize_runtime_snapshot(target.snapshot.clone());
        let (region_upserts, removed_regions) =
            diff_entities(&base_state.regions, &target_state.regions, |region| {
                region.id
            })?;
        let (task_upserts, removed_tasks) =
            diff_entities(&base_state.tasks, &target_state.tasks, |task| task.id)?;
        let (obligation_upserts, removed_obligations) = diff_entities(
            &base_state.obligations,
            &target_state.obligations,
            |obligation| obligation.id,
        )?;

        let delta = IncrementalSnapshot {
            base_content_hash: base.content_hash,
            target_schema_version: target.schema_version,
            target_content_hash: target.content_hash,
            timestamp: target_state.timestamp,
            region_upserts,
            removed_regions,
            task_upserts,
            removed_tasks,
            obligation_upserts,
            removed_obligations,
            recent_events: target_state.recent_events,
            finalizer_history: target_state.finalizer_history,
            loser_drain_history: target_state.loser_drain_history,
        };
        validate_delta(&delta, limits)?;
        Ok(Self::Incremental(delta))
    }

    /// Returns the artifact's payload kind.
    #[must_use]
    pub const fn kind(&self) -> SnapshotArtifactKind {
        match self {
            Self::Full(_) => SnapshotArtifactKind::Full,
            Self::Incremental(_) => SnapshotArtifactKind::Incremental,
        }
    }

    /// Encodes this artifact with [`SnapshotLimits::DEFAULT`].
    pub fn to_bytes(&self) -> Result<Vec<u8>, SnapshotCodecError> {
        self.to_bytes_with_limits(SnapshotLimits::DEFAULT)
    }

    /// Encodes this artifact into the owned `ASUPSNAP` envelope.
    pub fn to_bytes_with_limits(
        &self,
        limits: SnapshotLimits,
    ) -> Result<Vec<u8>, SnapshotCodecError> {
        let (kind, payload) = match self {
            Self::Full(snapshot) => {
                ensure_snapshot_valid(snapshot)?;
                validate_snapshot_limits(&snapshot.snapshot, limits)?;
                let normalized = if snapshot.schema_version >= 2 {
                    RestorableSnapshot {
                        snapshot: canonicalize_runtime_snapshot(snapshot.snapshot.clone()),
                        schema_version: snapshot.schema_version,
                        content_hash: snapshot.content_hash,
                    }
                } else {
                    snapshot.clone()
                };
                (
                    SNAPSHOT_ARTIFACT_KIND_FULL,
                    serde_json::to_vec(&normalized).map_err(json_error)?,
                )
            }
            Self::Incremental(delta) => {
                validate_delta(delta, limits)?;
                (
                    SNAPSHOT_ARTIFACT_KIND_INCREMENTAL,
                    serde_json::to_vec(delta).map_err(json_error)?,
                )
            }
        };

        let total_len = SNAPSHOT_ARTIFACT_HEADER_LEN.saturating_add(payload.len());
        ensure_artifact_size(total_len, limits)?;
        let payload_len =
            u64::try_from(payload.len()).map_err(|_| SnapshotCodecError::ArtifactTooLarge {
                actual: payload.len(),
                maximum: limits.max_artifact_bytes,
            })?;
        let checksum = Sha256::digest(&payload);
        let mut encoded = Vec::with_capacity(total_len);
        encoded.extend_from_slice(&SNAPSHOT_ARTIFACT_MAGIC);
        encoded.extend_from_slice(&SNAPSHOT_ARTIFACT_VERSION.to_le_bytes());
        encoded.push(kind);
        encoded.push(0);
        encoded.extend_from_slice(&payload_len.to_le_bytes());
        encoded.extend_from_slice(&checksum);
        encoded.extend_from_slice(&payload);
        Ok(encoded)
    }

    /// Decodes an owned envelope or legacy raw JSON with default limits.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SnapshotCodecError> {
        Self::from_bytes_with_limits(bytes, SnapshotLimits::DEFAULT)
    }

    /// Decodes an owned envelope or legacy raw JSON with explicit limits.
    ///
    /// Legacy JSON is detected by the first non-whitespace `{` byte. It is
    /// validated with the schema-v1 hash rule and remains a full artifact until
    /// [`RestorableSnapshot::migrate_to_current`] is explicitly requested.
    pub fn from_bytes_with_limits(
        bytes: &[u8],
        limits: SnapshotLimits,
    ) -> Result<Self, SnapshotCodecError> {
        ensure_artifact_size(bytes.len(), limits)?;
        if bytes
            .iter()
            .copied()
            .find(|byte| !byte.is_ascii_whitespace())
            == Some(b'{')
        {
            let snapshot: RestorableSnapshot = serde_json::from_slice(bytes).map_err(json_error)?;
            return Self::full(snapshot, limits);
        }

        if bytes.len() < SNAPSHOT_ARTIFACT_HEADER_LEN {
            return Err(SnapshotCodecError::TruncatedHeader {
                actual: bytes.len(),
            });
        }
        if bytes[..SNAPSHOT_ARTIFACT_MAGIC.len()] != SNAPSHOT_ARTIFACT_MAGIC {
            return Err(SnapshotCodecError::InvalidMagic);
        }

        let version = u16::from_le_bytes(
            bytes[8..10]
                .try_into()
                .expect("fixed header version slice has two bytes"),
        );
        if version != SNAPSHOT_ARTIFACT_VERSION {
            return Err(SnapshotCodecError::UnsupportedArtifactVersion { actual: version });
        }
        let kind = bytes[10];
        if !matches!(
            kind,
            SNAPSHOT_ARTIFACT_KIND_FULL | SNAPSHOT_ARTIFACT_KIND_INCREMENTAL
        ) {
            return Err(SnapshotCodecError::InvalidArtifactKind { actual: kind });
        }
        let flags = bytes[11];
        if flags != 0 {
            return Err(SnapshotCodecError::UnsupportedFlags { actual: flags });
        }
        let payload_len_u64 = u64::from_le_bytes(
            bytes[12..20]
                .try_into()
                .expect("fixed header payload-length slice has eight bytes"),
        );
        let payload_len =
            usize::try_from(payload_len_u64).map_err(|_| SnapshotCodecError::ArtifactTooLarge {
                actual: usize::MAX,
                maximum: limits.max_artifact_bytes,
            })?;
        if payload_len > limits.max_artifact_bytes {
            return Err(SnapshotCodecError::ArtifactTooLarge {
                actual: payload_len,
                maximum: limits.max_artifact_bytes,
            });
        }
        let declared_total = SNAPSHOT_ARTIFACT_HEADER_LEN
            .checked_add(payload_len)
            .ok_or(SnapshotCodecError::ArtifactTooLarge {
                actual: usize::MAX,
                maximum: limits.max_artifact_bytes,
            })?;
        if declared_total != bytes.len() {
            return Err(SnapshotCodecError::LengthMismatch {
                declared_total,
                actual: bytes.len(),
            });
        }

        let expected_checksum = &bytes[20..52];
        let payload = &bytes[SNAPSHOT_ARTIFACT_HEADER_LEN..];
        if Sha256::digest(payload).as_slice() != expected_checksum {
            return Err(SnapshotCodecError::ChecksumMismatch);
        }

        match kind {
            SNAPSHOT_ARTIFACT_KIND_FULL => {
                let snapshot = serde_json::from_slice(payload).map_err(json_error)?;
                Self::full(snapshot, limits)
            }
            SNAPSHOT_ARTIFACT_KIND_INCREMENTAL => {
                let delta = serde_json::from_slice(payload).map_err(json_error)?;
                validate_delta(&delta, limits)?;
                Ok(Self::Incremental(delta))
            }
            _ => unreachable!("artifact kind was validated above"),
        }
    }

    /// Materializes complete runtime state, applying a delta when necessary.
    pub fn materialize(
        &self,
        base: Option<&RestorableSnapshot>,
        limits: SnapshotLimits,
    ) -> Result<RestorableSnapshot, SnapshotCodecError> {
        match self {
            Self::Full(snapshot) => {
                ensure_snapshot_valid(snapshot)?;
                validate_snapshot_limits(&snapshot.snapshot, limits)?;
                Ok(snapshot.clone())
            }
            Self::Incremental(delta) => {
                validate_delta(delta, limits)?;
                let base = base.ok_or(SnapshotCodecError::MissingBase)?;
                ensure_snapshot_valid(base)?;
                validate_snapshot_limits(&base.snapshot, limits)?;
                if base.content_hash != delta.base_content_hash {
                    return Err(SnapshotCodecError::BaseHashMismatch {
                        expected: delta.base_content_hash,
                        actual: base.content_hash,
                    });
                }

                let mut state = canonicalize_runtime_snapshot(base.snapshot.clone());
                apply_entities(
                    &mut state.regions,
                    &delta.removed_regions,
                    &delta.region_upserts,
                    |region| region.id,
                );
                apply_entities(
                    &mut state.tasks,
                    &delta.removed_tasks,
                    &delta.task_upserts,
                    |task| task.id,
                );
                apply_entities(
                    &mut state.obligations,
                    &delta.removed_obligations,
                    &delta.obligation_upserts,
                    |obligation| obligation.id,
                );
                state.timestamp = delta.timestamp;
                state.recent_events.clone_from(&delta.recent_events);
                state.finalizer_history.clone_from(&delta.finalizer_history);
                state
                    .loser_drain_history
                    .clone_from(&delta.loser_drain_history);
                state = canonicalize_runtime_snapshot(state);

                let content_hash =
                    RestorableSnapshot::compute_hash(delta.target_schema_version, &state);
                if content_hash != delta.target_content_hash {
                    return Err(SnapshotCodecError::TargetHashMismatch {
                        expected: delta.target_content_hash,
                        actual: content_hash,
                    });
                }
                let snapshot = RestorableSnapshot {
                    snapshot: state,
                    schema_version: delta.target_schema_version,
                    content_hash,
                };
                ensure_snapshot_valid(&snapshot)?;
                validate_snapshot_limits(&snapshot.snapshot, limits)?;
                Ok(snapshot)
            }
        }
    }
}

fn json_error(error: serde_json::Error) -> SnapshotCodecError {
    SnapshotCodecError::Json {
        message: error.to_string(),
    }
}

fn ensure_artifact_size(actual: usize, limits: SnapshotLimits) -> Result<(), SnapshotCodecError> {
    if actual > limits.max_artifact_bytes {
        return Err(SnapshotCodecError::ArtifactTooLarge {
            actual,
            maximum: limits.max_artifact_bytes,
        });
    }
    Ok(())
}

fn ensure_snapshot_valid(snapshot: &RestorableSnapshot) -> Result<(), SnapshotCodecError> {
    let validation = snapshot.validate();
    if validation.is_valid {
        Ok(())
    } else {
        Err(SnapshotCodecError::InvalidSnapshot {
            error_count: validation.errors.len(),
        })
    }
}

fn validate_snapshot_limits(
    snapshot: &RuntimeSnapshot,
    limits: SnapshotLimits,
) -> Result<(), SnapshotCodecError> {
    check_limit("regions", snapshot.regions.len(), limits.max_regions)?;
    check_limit("tasks", snapshot.tasks.len(), limits.max_tasks)?;
    check_limit(
        "obligations",
        snapshot.obligations.len(),
        limits.max_obligations,
    )?;
    check_limit(
        "recent events",
        snapshot.recent_events.len(),
        limits.max_recent_events,
    )?;
    check_limit(
        "finalizer history",
        snapshot.finalizer_history.len(),
        limits.max_finalizer_history,
    )?;
    check_limit(
        "loser-drain history",
        snapshot.loser_drain_history.len(),
        limits.max_loser_drain_history,
    )?;
    let parent_map: HashMap<SnapshotIdKey, Option<SnapshotIdKey>> = snapshot
        .regions
        .iter()
        .map(|region| {
            (
                snapshot_id_key(region.id),
                region.parent_id.map(snapshot_id_key),
            )
        })
        .collect();
    check_limit(
        "region depth",
        compute_max_depth(&parent_map),
        limits.max_region_depth,
    )
}

fn validate_delta(
    delta: &IncrementalSnapshot,
    limits: SnapshotLimits,
) -> Result<(), SnapshotCodecError> {
    if delta.target_schema_version != RestorableSnapshot::SCHEMA_VERSION {
        return Err(SnapshotCodecError::InvalidDelta {
            message: format!(
                "target schema {} must be current schema {}",
                delta.target_schema_version,
                RestorableSnapshot::SCHEMA_VERSION
            ),
        });
    }
    check_limit(
        "region upserts",
        delta.region_upserts.len(),
        limits.max_regions,
    )?;
    check_limit(
        "region removals",
        delta.removed_regions.len(),
        limits.max_regions,
    )?;
    check_limit("task upserts", delta.task_upserts.len(), limits.max_tasks)?;
    check_limit("task removals", delta.removed_tasks.len(), limits.max_tasks)?;
    check_limit(
        "obligation upserts",
        delta.obligation_upserts.len(),
        limits.max_obligations,
    )?;
    check_limit(
        "obligation removals",
        delta.removed_obligations.len(),
        limits.max_obligations,
    )?;
    check_limit(
        "recent events",
        delta.recent_events.len(),
        limits.max_recent_events,
    )?;
    check_limit(
        "finalizer history",
        delta.finalizer_history.len(),
        limits.max_finalizer_history,
    )?;
    check_limit(
        "loser-drain history",
        delta.loser_drain_history.len(),
        limits.max_loser_drain_history,
    )?;
    validate_delta_entity_ids(
        "region",
        delta.region_upserts.iter().map(|region| region.id),
        &delta.removed_regions,
    )?;
    validate_delta_entity_ids(
        "task",
        delta.task_upserts.iter().map(|task| task.id),
        &delta.removed_tasks,
    )?;
    validate_delta_entity_ids(
        "obligation",
        delta
            .obligation_upserts
            .iter()
            .map(|obligation| obligation.id),
        &delta.removed_obligations,
    )
}

fn validate_delta_entity_ids(
    entity: &'static str,
    upserts: impl Iterator<Item = IdSnapshot>,
    removals: &[IdSnapshot],
) -> Result<(), SnapshotCodecError> {
    let mut upsert_ids = HashSet::new();
    for id in upserts {
        if !upsert_ids.insert(snapshot_id_key(id)) {
            return Err(SnapshotCodecError::InvalidDelta {
                message: format!("duplicate {entity} upsert {}:{}", id.index, id.generation),
            });
        }
    }
    let mut removed_ids = HashSet::new();
    for id in removals {
        let key = snapshot_id_key(*id);
        if !removed_ids.insert(key) {
            return Err(SnapshotCodecError::InvalidDelta {
                message: format!("duplicate {entity} removal {}:{}", id.index, id.generation),
            });
        }
        if upsert_ids.contains(&key) {
            return Err(SnapshotCodecError::InvalidDelta {
                message: format!(
                    "{entity} {}:{} is both removed and upserted",
                    id.index, id.generation
                ),
            });
        }
    }
    Ok(())
}

fn check_limit(
    resource: &'static str,
    actual: usize,
    maximum: usize,
) -> Result<(), SnapshotCodecError> {
    if actual > maximum {
        Err(SnapshotCodecError::LimitExceeded {
            resource,
            actual,
            maximum,
        })
    } else {
        Ok(())
    }
}

fn canonicalize_runtime_snapshot(mut snapshot: RuntimeSnapshot) -> RuntimeSnapshot {
    snapshot
        .regions
        .sort_by_key(|region| snapshot_id_key(region.id));
    for task in &mut snapshot.tasks {
        task.obligations.sort_by_key(|id| snapshot_id_key(*id));
    }
    snapshot.tasks.sort_by_key(|task| snapshot_id_key(task.id));
    snapshot
        .obligations
        .sort_by_key(|obligation| snapshot_id_key(obligation.id));
    snapshot
        .recent_events
        .sort_by_key(|event| (event.seq, event.time, event.version));
    snapshot
}

fn diff_entities<T, F>(
    base: &[T],
    target: &[T],
    id: F,
) -> Result<(Vec<T>, Vec<IdSnapshot>), SnapshotCodecError>
where
    T: Clone + Serialize,
    F: Fn(&T) -> IdSnapshot + Copy,
{
    let base_by_id: BTreeMap<SnapshotIdKey, &T> = base
        .iter()
        .map(|value| (snapshot_id_key(id(value)), value))
        .collect();
    let target_by_id: BTreeMap<SnapshotIdKey, &T> = target
        .iter()
        .map(|value| (snapshot_id_key(id(value)), value))
        .collect();
    let mut upserts = Vec::new();
    for (key, target_value) in &target_by_id {
        let changed = match base_by_id.get(key) {
            Some(base_value) => {
                serde_json::to_vec(*base_value).map_err(json_error)?
                    != serde_json::to_vec(*target_value).map_err(json_error)?
            }
            None => true,
        };
        if changed {
            upserts.push((*target_value).clone());
        }
    }
    let removed = base_by_id
        .keys()
        .filter(|key| !target_by_id.contains_key(key))
        .map(|&(index, generation)| IdSnapshot { index, generation })
        .collect();
    Ok((upserts, removed))
}

fn apply_entities<T, F>(base: &mut Vec<T>, removed: &[IdSnapshot], upserts: &[T], id: F)
where
    T: Clone,
    F: Fn(&T) -> IdSnapshot,
{
    let removed: HashSet<SnapshotIdKey> = removed.iter().map(|id| snapshot_id_key(*id)).collect();
    let mut by_id: BTreeMap<SnapshotIdKey, T> = std::mem::take(base)
        .into_iter()
        .filter(|value| !removed.contains(&snapshot_id_key(id(value))))
        .map(|value| (snapshot_id_key(id(&value)), value))
        .collect();
    for value in upserts {
        by_id.insert(snapshot_id_key(id(value)), value.clone());
    }
    *base = by_id.into_values().collect();
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

type SnapshotIdKey = (u32, u32);

fn snapshot_id_key(id: IdSnapshot) -> SnapshotIdKey {
    (id.index, id.generation)
}

/// Detects a cycle in the parent map, returning the cycle if found.
fn detect_cycle(parent_map: &HashMap<SnapshotIdKey, Option<SnapshotIdKey>>) -> Option<Vec<u32>> {
    for &start in parent_map.keys() {
        let mut visited = HashSet::new();
        let mut path = Vec::new();
        let mut current = Some(start);

        while let Some(node) = current {
            if visited.contains(&node) {
                // Found a cycle - extract it
                if let Some(pos) = path.iter().position(|&key| key == node) {
                    return Some(path[pos..].iter().map(|(index, _)| *index).collect());
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
fn compute_max_depth(parent_map: &HashMap<SnapshotIdKey, Option<SnapshotIdKey>>) -> usize {
    let mut max_depth = 0;
    for &start in parent_map.keys() {
        let mut depth = 0;
        let mut current = Some(start);
        let mut visited = HashSet::new();
        while let Some(node) = current {
            if !visited.insert(node) {
                // Break on cycle to keep depth computation total.
                break;
            }
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
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::runtime::state::IdSnapshot;
    use crate::runtime::state::{
        BudgetSnapshot, ObligationKindSnapshot, ObligationSnapshot, RegionSnapshot,
    };

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn snap_id(index: u32, generation: u32) -> IdSnapshot {
        IdSnapshot { index, generation }
    }

    fn make_region(id: u32, parent: Option<u32>, state: RegionStateSnapshot) -> RegionSnapshot {
        RegionSnapshot {
            id: snap_id(id, 0),
            parent_id: parent.map(|p| snap_id(p, 0)),
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
            id: snap_id(id, 0),
            region_id: snap_id(region_id, 0),
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
        make_obligation_in_region(id, task_id, 0, state)
    }

    fn make_obligation_in_region(
        id: u32,
        task_id: u32,
        owning_region: u32,
        state: ObligationStateSnapshot,
    ) -> ObligationSnapshot {
        ObligationSnapshot {
            id: snap_id(id, 0),
            kind: ObligationKindSnapshot::SendPermit,
            state,
            holder_task: snap_id(task_id, 0),
            owning_region: snap_id(owning_region, 0),
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
            finalizer_history: Vec::new(),
            loser_drain_history: Vec::new(),
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
    fn task_with_stale_region_generation_is_orphaned() {
        init_test("task_with_stale_region_generation_is_orphaned");
        let mut snapshot = make_snapshot(
            vec![make_region(7, None, RegionStateSnapshot::Open)],
            vec![make_task(0, 7, TaskStateSnapshot::Running)],
            Vec::new(),
        );
        snapshot.snapshot.regions[0].id = snap_id(7, 1);

        let result = snapshot.validate();

        let not_valid = !result.is_valid;
        crate::assert_with_log!(not_valid, "not valid", true, not_valid);
        let has_error = result.errors.iter().any(|e| {
            matches!(
                e,
                RestoreError::OrphanTask {
                    task_id: 0,
                    region_id: 7,
                }
            )
        });
        crate::assert_with_log!(
            has_error,
            "generation mismatch yields OrphanTask",
            true,
            has_error
        );
        crate::test_complete!("task_with_stale_region_generation_is_orphaned");
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
    fn obligation_with_stale_holder_generation_is_orphaned() {
        init_test("obligation_with_stale_holder_generation_is_orphaned");
        let mut snapshot = make_snapshot(
            vec![make_region(0, None, RegionStateSnapshot::Open)],
            vec![make_task(5, 0, TaskStateSnapshot::Running)],
            vec![make_obligation(0, 5, ObligationStateSnapshot::Reserved)],
        );
        snapshot.snapshot.tasks[0].id = snap_id(5, 1);

        let result = snapshot.validate();

        let not_valid = !result.is_valid;
        crate::assert_with_log!(not_valid, "not valid", true, not_valid);
        let has_error = result.errors.iter().any(|e| {
            matches!(
                e,
                RestoreError::OrphanObligation {
                    obligation_id: 0,
                    task_id: 5,
                }
            )
        });
        crate::assert_with_log!(
            has_error,
            "generation mismatch yields OrphanObligation",
            true,
            has_error
        );
        crate::test_complete!("obligation_with_stale_holder_generation_is_orphaned");
    }

    #[test]
    fn orphan_obligation_region_detected() {
        init_test("orphan_obligation_region_detected");
        let snapshot = make_snapshot(
            vec![make_region(0, None, RegionStateSnapshot::Open)],
            vec![make_task(0, 0, TaskStateSnapshot::Running)],
            vec![make_obligation_in_region(
                0,
                0,
                99,
                ObligationStateSnapshot::Reserved,
            )],
        );
        let result = snapshot.validate();

        let not_valid = !result.is_valid;
        crate::assert_with_log!(not_valid, "not valid", true, not_valid);
        let has_error = result
            .errors
            .iter()
            .any(|e| matches!(e, RestoreError::OrphanObligationRegion { .. }));
        crate::assert_with_log!(
            has_error,
            "has OrphanObligationRegion error",
            true,
            has_error
        );
        crate::test_complete!("orphan_obligation_region_detected");
    }

    #[test]
    fn obligation_with_stale_owning_region_generation_is_orphaned() {
        init_test("obligation_with_stale_owning_region_generation_is_orphaned");
        let mut snapshot = make_snapshot(
            vec![make_region(3, None, RegionStateSnapshot::Open)],
            vec![make_task(0, 3, TaskStateSnapshot::Running)],
            vec![make_obligation_in_region(
                0,
                0,
                3,
                ObligationStateSnapshot::Reserved,
            )],
        );
        snapshot.snapshot.regions[0].id = snap_id(3, 1);
        snapshot.snapshot.tasks[0].region_id = snap_id(3, 1);

        let result = snapshot.validate();

        let not_valid = !result.is_valid;
        crate::assert_with_log!(not_valid, "not valid", true, not_valid);
        let has_error = result.errors.iter().any(|e| {
            matches!(
                e,
                RestoreError::OrphanObligationRegion {
                    obligation_id: 0,
                    region_id: 3,
                }
            )
        });
        crate::assert_with_log!(
            has_error,
            "generation mismatch yields OrphanObligationRegion",
            true,
            has_error
        );
        crate::test_complete!("obligation_with_stale_owning_region_generation_is_orphaned");
    }

    #[test]
    fn obligation_region_mismatch_detected() {
        init_test("obligation_region_mismatch_detected");
        let snapshot = make_snapshot(
            vec![
                make_region(0, None, RegionStateSnapshot::Open),
                make_region(1, None, RegionStateSnapshot::Open),
            ],
            vec![make_task(0, 0, TaskStateSnapshot::Running)],
            vec![make_obligation_in_region(
                0,
                0,
                1,
                ObligationStateSnapshot::Reserved,
            )],
        );
        let result = snapshot.validate();

        let not_valid = !result.is_valid;
        crate::assert_with_log!(not_valid, "not valid", true, not_valid);
        let has_error = result
            .errors
            .iter()
            .any(|e| matches!(e, RestoreError::ObligationRegionMismatch { .. }));
        crate::assert_with_log!(
            has_error,
            "has ObligationRegionMismatch error",
            true,
            has_error
        );
        crate::test_complete!("obligation_region_mismatch_detected");
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
    fn parent_generation_mismatch_detected() {
        init_test("parent_generation_mismatch_detected");
        let mut snapshot = make_snapshot(
            vec![
                make_region(0, None, RegionStateSnapshot::Open),
                make_region(1, Some(0), RegionStateSnapshot::Open),
            ],
            Vec::new(),
            Vec::new(),
        );
        snapshot.snapshot.regions[0].id = snap_id(0, 1);

        let result = snapshot.validate();

        let not_valid = !result.is_valid;
        crate::assert_with_log!(not_valid, "not valid", true, not_valid);
        let has_error = result.errors.iter().any(|e| {
            matches!(
                e,
                RestoreError::InvalidParent {
                    region_id: 1,
                    parent_id: 0,
                }
            )
        });
        crate::assert_with_log!(
            has_error,
            "generation mismatch yields InvalidParent",
            true,
            has_error
        );
        crate::test_complete!("parent_generation_mismatch_detected");
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
        let mut tampered = snapshot;
        tampered.content_hash ^= 1;
        let invalid = !tampered.verify_integrity();
        crate::assert_with_log!(invalid, "tampered invalid", true, invalid);

        crate::test_complete!("integrity_verification_works");
    }

    #[test]
    fn integrity_verification_detects_semantic_tampering() {
        init_test("integrity_verification_detects_semantic_tampering");
        let snapshot = make_snapshot(
            vec![make_region(0, None, RegionStateSnapshot::Open)],
            vec![make_task(0, 0, TaskStateSnapshot::Running)],
            vec![make_obligation(0, 0, ObligationStateSnapshot::Reserved)],
        );

        let mut tampered = snapshot;
        tampered.snapshot.tasks[0].state = TaskStateSnapshot::Completed {
            outcome: crate::runtime::state::OutcomeSnapshot::Ok,
        };

        let invalid = !tampered.verify_integrity();
        crate::assert_with_log!(invalid, "semantic tamper invalid", true, invalid);

        crate::test_complete!("integrity_verification_detects_semantic_tampering");
    }

    #[test]
    fn integrity_verification_detects_schema_version_tampering() {
        init_test("integrity_verification_detects_schema_version_tampering");
        let snapshot = make_snapshot(
            vec![make_region(0, None, RegionStateSnapshot::Open)],
            vec![make_task(0, 0, TaskStateSnapshot::Running)],
            Vec::new(),
        );

        let mut tampered = snapshot;
        tampered.schema_version = tampered.schema_version.saturating_add(1);

        let invalid = !tampered.verify_integrity();
        crate::assert_with_log!(invalid, "schema version tamper invalid", true, invalid);

        crate::test_complete!("integrity_verification_detects_schema_version_tampering");
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
    fn duplicate_obligation_id_detected() {
        init_test("duplicate_obligation_id_detected");
        let snapshot = make_snapshot(
            vec![make_region(0, None, RegionStateSnapshot::Open)],
            vec![make_task(0, 0, TaskStateSnapshot::Running)],
            vec![
                make_obligation(7, 0, ObligationStateSnapshot::Reserved),
                make_obligation(7, 0, ObligationStateSnapshot::Committed), // duplicate
            ],
        );
        let result = snapshot.validate();

        let not_valid = !result.is_valid;
        crate::assert_with_log!(not_valid, "not valid", true, not_valid);
        let has_error = result.errors.iter().any(|e| {
            matches!(
                e,
                RestoreError::DuplicateId {
                    kind: "obligation",
                    ..
                }
            )
        });
        crate::assert_with_log!(
            has_error,
            "has obligation DuplicateId error",
            true,
            has_error
        );
        crate::test_complete!("duplicate_obligation_id_detected");
    }

    #[test]
    fn cyclic_region_tree_detected_without_depth_hang() {
        init_test("cyclic_region_tree_detected_without_depth_hang");
        let snapshot = make_snapshot(
            vec![
                make_region(0, Some(1), RegionStateSnapshot::Open),
                make_region(1, Some(0), RegionStateSnapshot::Open),
            ],
            Vec::new(),
            Vec::new(),
        );
        let result = snapshot.validate();

        let not_valid = !result.is_valid;
        crate::assert_with_log!(not_valid, "not valid", true, not_valid);
        let has_cycle = result
            .errors
            .iter()
            .any(|e| matches!(e, RestoreError::CyclicRegionTree { .. }));
        crate::assert_with_log!(has_cycle, "has CyclicRegionTree error", true, has_cycle);
        crate::assert_with_log!(
            result.stats.max_depth == 2,
            "max_depth bounded with cycle",
            2,
            result.stats.max_depth
        );
        crate::test_complete!("cyclic_region_tree_detected_without_depth_hang");
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

    #[test]
    fn task_timestamp_after_snapshot_detected() {
        init_test("task_timestamp_after_snapshot_detected");
        let mut snapshot = make_snapshot(
            vec![make_region(0, None, RegionStateSnapshot::Open)],
            vec![make_task(0, 0, TaskStateSnapshot::Running)],
            Vec::new(),
        );
        snapshot.snapshot.tasks[0].created_at = snapshot.snapshot.timestamp + 1;

        let result = snapshot.validate();
        let has_error = result.errors.iter().any(|e| {
            matches!(
                e,
                RestoreError::InvalidTimestamp {
                    entity, ..
                } if entity.contains("task 0 created_at")
            )
        });
        crate::assert_with_log!(
            has_error,
            "task invalid timestamp detected",
            true,
            has_error
        );
        crate::test_complete!("task_timestamp_after_snapshot_detected");
    }

    #[test]
    fn obligation_timestamp_after_snapshot_detected() {
        init_test("obligation_timestamp_after_snapshot_detected");
        let mut snapshot = make_snapshot(
            vec![make_region(0, None, RegionStateSnapshot::Open)],
            vec![make_task(0, 0, TaskStateSnapshot::Running)],
            vec![make_obligation(0, 0, ObligationStateSnapshot::Reserved)],
        );
        snapshot.snapshot.obligations[0].created_at = snapshot.snapshot.timestamp + 1;

        let result = snapshot.validate();
        let has_error = result.errors.iter().any(|e| {
            matches!(
                e,
                RestoreError::InvalidTimestamp {
                    entity, ..
                } if entity.contains("obligation 0 created_at")
            )
        });
        crate::assert_with_log!(
            has_error,
            "obligation invalid timestamp detected",
            true,
            has_error
        );
        crate::test_complete!("obligation_timestamp_after_snapshot_detected");
    }

    // ── derive-trait coverage (wave 73) ──────────────────────────────────

    #[test]
    fn restore_error_debug_clone_eq() {
        let e1 = RestoreError::OrphanTask {
            task_id: 5,
            region_id: 99,
        };
        let e2 = e1.clone();
        assert_eq!(e1, e2);
        let dbg = format!("{e1:?}");
        assert!(dbg.contains("OrphanTask"));

        let e3 = RestoreError::CyclicRegionTree {
            cycle: vec![1, 2, 3],
        };
        let e4 = e3.clone();
        assert_eq!(e3, e4);
        assert_ne!(e1, e3);
    }

    #[test]
    fn snapshot_stats_debug_clone_default() {
        let s = SnapshotStats::default();
        assert_eq!(s.region_count, 0);
        assert_eq!(s.task_count, 0);
        assert_eq!(s.obligation_count, 0);
        assert_eq!(s.max_depth, 0);
        assert_eq!(s.terminal_task_count, 0);
        assert_eq!(s.resolved_obligation_count, 0);
        assert_eq!(s.closed_region_count, 0);

        let s2 = s;
        let dbg = format!("{s2:?}");
        assert!(dbg.contains("SnapshotStats"));
    }

    #[test]
    fn validation_result_debug_clone() {
        let vr = ValidationResult {
            is_valid: true,
            errors: vec![],
            stats: SnapshotStats::default(),
        };
        let vr2 = vr;
        assert!(vr2.is_valid);
        assert!(vr2.errors.is_empty());
        let dbg = format!("{vr2:?}");
        assert!(dbg.contains("ValidationResult"));
    }
}
