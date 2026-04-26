//! Bridge between local and distributed region operations.
//!
//! Provides transparent upgrade paths from local to distributed operation,
//! lifecycle synchronization between local and distributed state machines,
//! and type conversions that preserve structured concurrency guarantees.
//!
//! # Architecture
//!
//! ```text
//! RegionRecord ↔ RegionBridge ↔ DistributedRegionRecord
//! ```

#![allow(clippy::result_large_err)]

use std::time::Duration;

use super::snapshot::{BudgetSnapshot, RegionSnapshot, TaskSnapshot, TaskState};
use crate::error::{Error, ErrorKind};
use crate::record::distributed_region::{
    ConsistencyLevel, DistributedRegionConfig, DistributedRegionRecord, DistributedRegionState,
    ReplicaInfo, StateTransition, TransitionReason,
};
use crate::record::region::{RegionRecord, RegionState};
use crate::types::budget::Budget;
use crate::types::cancel::CancelReason;
use crate::types::{RegionId, TaskId, Time};

// ---------------------------------------------------------------------------
// RegionMode
// ---------------------------------------------------------------------------

/// Operating mode for a region.
///
/// Determines whether a region operates locally or with distributed
/// replication. Can be promoted (but not demoted) during the region's
/// lifetime.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum RegionMode {
    /// Local operation only — no replication.
    #[default]
    Local,
    /// Distributed operation with configurable replication.
    Distributed {
        /// Number of replicas.
        replication_factor: u32,
        /// Consistency level for operations.
        consistency: ConsistencyLevel,
    },
    /// Hybrid mode — local primary with async replication.
    Hybrid {
        /// Number of backup replicas.
        replication_factor: u32,
        /// Maximum replication lag before blocking.
        max_lag: Duration,
    },
}

impl RegionMode {
    /// Creates a local-only mode.
    #[must_use]
    pub const fn local() -> Self {
        Self::Local
    }

    /// Creates a distributed mode with quorum consistency.
    #[must_use]
    pub fn distributed(replication_factor: u32) -> Self {
        assert!(
            replication_factor > 0,
            "distributed region mode requires at least one replica"
        );
        Self::Distributed {
            replication_factor,
            consistency: ConsistencyLevel::Quorum,
        }
    }

    /// Creates a hybrid mode with async replication.
    #[must_use]
    pub fn hybrid(replication_factor: u32) -> Self {
        assert!(
            replication_factor > 0,
            "hybrid region mode requires at least one replica"
        );
        Self::Hybrid {
            replication_factor,
            max_lag: Duration::from_secs(5),
        }
    }

    fn assert_valid(self) {
        match self {
            Self::Local => {}
            Self::Distributed {
                replication_factor, ..
            } => assert!(
                replication_factor > 0,
                "distributed region mode requires at least one replica"
            ),
            Self::Hybrid {
                replication_factor, ..
            } => assert!(
                replication_factor > 0,
                "hybrid region mode requires at least one replica"
            ),
        }
    }

    const fn min_quorum(replication_factor: u32, consistency: ConsistencyLevel) -> u32 {
        match consistency {
            ConsistencyLevel::One | ConsistencyLevel::Local => 1,
            ConsistencyLevel::Quorum => replication_factor / 2 + 1,
            ConsistencyLevel::All => replication_factor,
        }
    }

    /// Returns true if this mode involves any replication.
    #[must_use]
    pub const fn is_replicated(&self) -> bool {
        !matches!(self, Self::Local)
    }

    /// Returns true if this mode is fully distributed.
    #[must_use]
    pub const fn is_distributed(&self) -> bool {
        matches!(self, Self::Distributed { .. })
    }

    /// Returns the replication factor, or 1 for local mode.
    #[must_use]
    pub const fn replication_factor(&self) -> u32 {
        match self {
            Self::Local => 1,
            Self::Distributed {
                replication_factor, ..
            }
            | Self::Hybrid {
                replication_factor, ..
            } => *replication_factor,
        }
    }
}

// ---------------------------------------------------------------------------
// BridgeConfig / SyncMode / ConflictResolution
// ---------------------------------------------------------------------------

/// How synchronization is performed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncMode {
    /// Operations block until replicated.
    Synchronous,
    /// Operations complete locally, replicate in background.
    Asynchronous,
    /// Block only for writes, reads are local.
    WriteSync,
}

/// How to resolve conflicts between local and distributed state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictResolution {
    /// Distributed state wins.
    DistributedWins,
    /// Local state wins.
    LocalWins,
    /// Use highest sequence number.
    HighestSequence,
    /// Report error on conflict.
    Error,
}

/// Configuration for bridge behavior.
#[derive(Debug, Clone)]
pub struct BridgeConfig {
    /// Whether to allow mode upgrades during lifetime.
    pub allow_upgrade: bool,
    /// Timeout for synchronization operations.
    pub sync_timeout: Duration,
    /// How synchronization is performed.
    pub sync_mode: SyncMode,
    /// Conflict resolution strategy.
    pub conflict_resolution: ConflictResolution,
}

impl Default for BridgeConfig {
    fn default() -> Self {
        Self {
            allow_upgrade: true,
            sync_timeout: Duration::from_secs(5),
            sync_mode: SyncMode::Synchronous,
            conflict_resolution: ConflictResolution::DistributedWins,
        }
    }
}

// ---------------------------------------------------------------------------
// SyncState
// ---------------------------------------------------------------------------

/// Current synchronization state between local and distributed.
#[derive(Debug, Clone, Default)]
pub struct SyncState {
    /// Last successfully synchronized sequence number.
    pub last_synced_sequence: u64,
    /// Whether synchronization is pending.
    pub sync_pending: bool,
    /// Number of pending operations to sync.
    pub pending_ops: u32,
    /// Last sync timestamp.
    pub last_sync_time: Option<Time>,
    /// Last sync error, if any.
    pub last_sync_error: Option<String>,
    /// br-asupersync-nyp2ts: separate inbound dedup gate. Tracks the
    /// highest sequence number we have applied via
    /// [`RegionBridge::apply_snapshot`] (inbound traffic from peers
    /// or recovery). Kept distinct from `last_synced_sequence`
    /// (which is updated by outbound `sync()` and so reflects the
    /// LOCAL sequence counter we last published) and from
    /// `RegionBridge::sequence` (the local outbound generation
    /// counter, bumped by `create_snapshot`). Conflating these
    /// namespaces caused valid newer inbound snapshots to be
    /// silently dropped whenever the local node had generated more
    /// outbound snapshots than the inbound carried — see
    /// br-asupersync-nyp2ts.
    pub last_applied_inbound_sequence: u64,
}

// ---------------------------------------------------------------------------
// EffectiveState
// ---------------------------------------------------------------------------

/// Effective state considering both local and distributed status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectiveState {
    /// Region is open and accepting work.
    Open,
    /// Region is active but in degraded mode (distributed only).
    Degraded,
    /// Region is recovering (distributed only).
    Recovering,
    /// Region is closing.
    Closing,
    /// Region is closed.
    Closed,
    /// States are inconsistent (error condition).
    Inconsistent {
        /// Local state.
        local: RegionState,
        /// Distributed state.
        distributed: DistributedRegionState,
    },
}

impl EffectiveState {
    /// Computes effective state from local and optional distributed state.
    #[must_use]
    pub fn compute(local: RegionState, distributed: Option<DistributedRegionState>) -> Self {
        match (local, distributed) {
            // Local-only mode.
            (local_s, None) => Self::from_local(local_s),

            // Distributed mode — both must agree.
            (
                RegionState::Open,
                Some(DistributedRegionState::Active | DistributedRegionState::Initializing),
            ) => Self::Open,
            (RegionState::Open, Some(DistributedRegionState::Degraded)) => Self::Degraded,
            (RegionState::Open, Some(DistributedRegionState::Recovering)) => Self::Recovering,

            // Closing states.
            (
                RegionState::Closing | RegionState::Draining | RegionState::Finalizing,
                Some(DistributedRegionState::Closing),
            ) => Self::Closing,

            // Closed states.
            (RegionState::Closed, Some(DistributedRegionState::Closed)) => Self::Closed,

            // Inconsistent states.
            (local_s, Some(dist_s)) => Self::Inconsistent {
                local: local_s,
                distributed: dist_s,
            },
        }
    }

    fn from_local(local: RegionState) -> Self {
        match local {
            RegionState::Open => Self::Open,
            RegionState::Closing | RegionState::Draining | RegionState::Finalizing => Self::Closing,
            RegionState::Closed => Self::Closed,
        }
    }

    /// Returns true if work can be spawned.
    #[must_use]
    pub const fn can_spawn(&self) -> bool {
        matches!(self, Self::Open)
    }

    /// Returns true if the region is in an error state.
    #[must_use]
    pub const fn is_inconsistent(&self) -> bool {
        matches!(self, Self::Inconsistent { .. })
    }

    /// Returns true if the region needs recovery.
    #[must_use]
    pub const fn needs_recovery(&self) -> bool {
        matches!(
            self,
            Self::Degraded | Self::Recovering | Self::Inconsistent { .. }
        )
    }
}

// ---------------------------------------------------------------------------
// Type Conversion Traits
// ---------------------------------------------------------------------------

/// Converts local types to their distributed equivalents.
pub trait LocalToDistributed {
    /// The distributed equivalent type.
    type Distributed;

    /// Converts to the distributed equivalent.
    fn to_distributed(&self) -> Self::Distributed;
}

/// Converts distributed types to their local equivalents.
pub trait DistributedToLocal {
    /// The local equivalent type.
    type Local;

    /// Converts to the local equivalent.
    fn to_local(&self) -> Self::Local;

    /// Returns true if lossless conversion is possible.
    fn is_lossless(&self) -> bool;
}

impl LocalToDistributed for RegionState {
    type Distributed = DistributedRegionState;

    fn to_distributed(&self) -> DistributedRegionState {
        match self {
            Self::Open => DistributedRegionState::Active,
            Self::Closing | Self::Draining | Self::Finalizing => DistributedRegionState::Closing,
            Self::Closed => DistributedRegionState::Closed,
        }
    }
}

impl DistributedToLocal for DistributedRegionState {
    type Local = RegionState;

    fn to_local(&self) -> RegionState {
        match self {
            Self::Initializing | Self::Active | Self::Degraded | Self::Recovering => {
                RegionState::Open
            }
            Self::Closing => RegionState::Closing,
            Self::Closed => RegionState::Closed,
        }
    }

    fn is_lossless(&self) -> bool {
        matches!(self, Self::Active | Self::Closing | Self::Closed)
    }
}

impl LocalToDistributed for Budget {
    type Distributed = BudgetSnapshot;

    fn to_distributed(&self) -> BudgetSnapshot {
        BudgetSnapshot {
            deadline_nanos: self.deadline.map(Time::as_nanos),
            polls_remaining: if self.poll_quota > 0 {
                Some(self.poll_quota)
            } else {
                None
            },
            cost_remaining: self.cost_quota,
        }
    }
}

impl DistributedToLocal for BudgetSnapshot {
    type Local = Budget;

    fn to_local(&self) -> Budget {
        let mut budget = Budget::default();
        if let Some(d) = self.deadline_nanos {
            budget.deadline = Some(Time::from_nanos(d));
        }
        if let Some(p) = self.polls_remaining {
            budget.poll_quota = p;
        }
        if let Some(c) = self.cost_remaining {
            budget.cost_quota = Some(c);
        }
        budget
    }

    fn is_lossless(&self) -> bool {
        false // Priority is lost
    }
}

// ---------------------------------------------------------------------------
// CloseResult / UpgradeResult / SyncResult
// ---------------------------------------------------------------------------

/// Result of a close operation.
#[derive(Debug)]
pub struct CloseResult {
    /// Whether the local state changed.
    pub local_changed: bool,
    /// Distributed transition, if any.
    pub distributed_transition: Option<StateTransition>,
    /// New effective state.
    pub effective_state: EffectiveState,
}

/// Result of a mode upgrade operation.
#[derive(Debug)]
pub struct UpgradeResult {
    /// Previous operating mode.
    pub previous_mode: RegionMode,
    /// New operating mode.
    pub new_mode: RegionMode,
    /// Sequence number of the snapshot taken during upgrade.
    pub snapshot_sequence: u64,
}

/// Result of a sync operation.
#[derive(Debug)]
pub enum SyncResult {
    /// Sync was not needed (local mode or no changes).
    NotNeeded,
    /// Sync completed successfully.
    Synced {
        /// Synced sequence number.
        sequence: u64,
    },
    /// Sync is pending (async mode).
    Pending {
        /// Pending sequence number.
        sequence: u64,
    },
}

// ---------------------------------------------------------------------------
// RegionBridge
// ---------------------------------------------------------------------------

/// Coordinates local and distributed region state.
///
/// Keeps both state machines synchronized, translates operations between
/// systems, handles mode upgrades, and manages replication lifecycle.
#[derive(Debug)]
pub struct RegionBridge {
    local: RegionRecord,
    distributed: Option<DistributedRegionRecord>,
    mode: RegionMode,
    /// Current synchronization state (accessible for tests).
    pub sync_state: SyncState,
    /// Bridge configuration (accessible for tests).
    pub config: BridgeConfig,
    /// Monotonic sequence counter for snapshots.
    sequence: u64,
}

impl RegionBridge {
    fn mark_sync_pending(&mut self) {
        self.sync_state.sync_pending = true;
        self.sync_state.pending_ops = self.sync_state.pending_ops.saturating_add(1);
    }

    /// Creates a new bridge in local-only mode.
    #[must_use]
    pub fn new_local(id: RegionId, parent: Option<RegionId>, budget: Budget) -> Self {
        Self {
            local: RegionRecord::new(id, parent, budget),
            distributed: None,
            mode: RegionMode::Local,
            sync_state: SyncState::default(),
            config: BridgeConfig::default(),
            sequence: 0,
        }
    }

    /// Creates a new bridge in distributed mode.
    #[must_use]
    pub fn new_distributed(
        id: RegionId,
        parent: Option<RegionId>,
        budget: Budget,
        config: DistributedRegionConfig,
    ) -> Self {
        let replication_factor = config.replication_factor;
        let consistency = config.write_consistency;
        let distributed = DistributedRegionRecord::new(id, config, parent, budget);
        Self {
            local: RegionRecord::new(id, parent, budget),
            distributed: Some(distributed),
            mode: RegionMode::Distributed {
                replication_factor,
                consistency,
            },
            sync_state: SyncState::default(),
            config: BridgeConfig::default(),
            sequence: 0,
        }
    }

    /// Creates a new bridge with a specified mode.
    #[must_use]
    pub fn with_mode(
        id: RegionId,
        parent: Option<RegionId>,
        budget: Budget,
        mode: RegionMode,
    ) -> Self {
        mode.assert_valid();
        match mode {
            RegionMode::Local => Self {
                local: RegionRecord::new(id, parent, budget),
                distributed: None,
                mode,
                sync_state: SyncState::default(),
                config: BridgeConfig::default(),
                sequence: 0,
            },
            RegionMode::Hybrid {
                replication_factor,
                max_lag,
            } => {
                // Hybrid = local-primary with async replication. We must keep a
                // local copy AND replicate. ConsistencyLevel::One + min_quorum=1
                // means the local write is sufficient to consider the operation
                // committed; replicas are asynchronously caught up. SyncMode is
                // Asynchronous and sync_timeout is the max replication lag.
                let dist_config = DistributedRegionConfig {
                    min_quorum: 1,
                    replication_factor,
                    write_consistency: ConsistencyLevel::One,
                    ..Default::default()
                };
                let bridge_config = BridgeConfig {
                    sync_mode: SyncMode::Asynchronous,
                    sync_timeout: max_lag,
                    ..Default::default()
                };
                let distributed =
                    DistributedRegionRecord::new(id, dist_config, parent, budget);
                Self {
                    local: RegionRecord::new(id, parent, budget),
                    distributed: Some(distributed),
                    mode,
                    sync_state: SyncState::default(),
                    config: bridge_config,
                    sequence: 0,
                }
            }
            RegionMode::Distributed {
                replication_factor,
                consistency,
            } => {
                let config = DistributedRegionConfig {
                    min_quorum: RegionMode::min_quorum(replication_factor, consistency),
                    replication_factor,
                    write_consistency: consistency,
                    ..Default::default()
                };
                Self::new_distributed(id, parent, budget, config)
            }
        }
    }

    // =========================================================================
    // Query Operations
    // =========================================================================

    /// Returns the region ID.
    #[must_use]
    pub fn id(&self) -> RegionId {
        self.local.id
    }

    /// Returns the current mode.
    #[must_use]
    pub fn mode(&self) -> RegionMode {
        self.mode
    }

    /// Returns the local region state.
    #[must_use]
    pub fn local_state(&self) -> RegionState {
        self.local.state()
    }

    /// Returns the distributed state if in distributed mode.
    #[must_use]
    pub fn distributed_state(&self) -> Option<DistributedRegionState> {
        self.distributed.as_ref().map(|d| d.state)
    }

    /// Returns the effective state (considering both local and distributed).
    #[must_use]
    pub fn effective_state(&self) -> EffectiveState {
        EffectiveState::compute(self.local_state(), self.distributed_state())
    }

    /// Returns true if the region can accept new work.
    #[must_use]
    pub fn can_spawn(&self) -> bool {
        self.effective_state().can_spawn()
    }

    /// Returns true if the region has any active work.
    #[must_use]
    pub fn has_live_work(&self) -> bool {
        self.local.has_live_work()
    }

    /// Returns the local region record (read-only).
    #[must_use]
    pub fn local(&self) -> &RegionRecord {
        &self.local
    }

    /// Returns the distributed record if in distributed mode.
    #[must_use]
    pub fn distributed(&self) -> Option<&DistributedRegionRecord> {
        self.distributed.as_ref()
    }

    // =========================================================================
    // Lifecycle Operations
    // =========================================================================

    /// Begins closing the region.
    ///
    /// Coordinates between local and distributed close sequences.
    pub fn begin_close(
        &mut self,
        reason: Option<CancelReason>,
        now: Time,
    ) -> Result<CloseResult, Error> {
        // Extract transition reason before consuming the cancel reason.
        let transition_reason = reason.as_ref().map_or(TransitionReason::LocalClose, |r| {
            TransitionReason::Cancelled {
                reason: r.kind.as_str().to_owned(),
            }
        });

        // br-asupersync-60rane: attempt the distributed transition
        // FIRST so that its `?` failure bails out before any local
        // mutation. The previous order (local first) left the bridge
        // in `local=Closing, distributed=Active` on dist failure,
        // which `effective_state()` then reports as
        // `Inconsistent` with no rollback path.
        let distributed_transition = if let Some(ref mut dist) = self.distributed {
            match dist.state {
                DistributedRegionState::Closing | DistributedRegionState::Closed => None,
                _ => Some(dist.begin_close(transition_reason, now)?),
            }
        } else {
            None
        };

        let local_changed = self.local.begin_close(reason);

        if local_changed || distributed_transition.is_some() {
            self.mark_sync_pending();
        }

        Ok(CloseResult {
            local_changed,
            distributed_transition,
            effective_state: self.effective_state(),
        })
    }

    /// Transitions to draining state.
    pub fn begin_drain(&mut self) -> Result<bool, Error> {
        let changed = self.local.begin_drain();
        if changed {
            self.mark_sync_pending();
        }
        Ok(changed)
    }

    /// Transitions to finalizing state.
    pub fn begin_finalize(&mut self) -> Result<bool, Error> {
        let changed = self.local.begin_finalize();
        if changed {
            self.mark_sync_pending();
        }
        Ok(changed)
    }

    /// Completes the close operation.
    pub fn complete_close(&mut self, now: Time) -> Result<CloseResult, Error> {
        // br-asupersync-60rane: attempt the distributed transition
        // FIRST so that its `?` failure bails out before any local
        // mutation. The previous order (local first) could leave the
        // bridge in `local=Closed, distributed=non-Closed` on dist
        // failure, which `effective_state()` then reports as
        // `Inconsistent` with no rollback path.
        let distributed_transition = if let Some(ref mut dist) = self.distributed {
            match dist.state {
                DistributedRegionState::Closed => None,
                _ => Some(dist.complete_close(now)?),
            }
        } else {
            None
        };

        let local_changed = self.local.complete_close();

        if local_changed || distributed_transition.is_some() {
            self.mark_sync_pending();
        }

        Ok(CloseResult {
            local_changed,
            distributed_transition,
            effective_state: self.effective_state(),
        })
    }

    // =========================================================================
    // Child/Task Management
    // =========================================================================

    /// Adds a child region.
    pub fn add_child(&mut self, child: RegionId) -> Result<(), Error> {
        if !self.can_spawn() {
            return Err(
                Error::new(ErrorKind::RegionClosed).with_message("region not accepting new work")
            );
        }

        let before = self.local.child_ids().len();
        self.local
            .add_child(child)
            .map_err(|e| Error::new(ErrorKind::AdmissionDenied).with_message(format!("{e:?}")))?;
        if self.local.child_ids().len() > before {
            self.mark_sync_pending();
        }
        Ok(())
    }

    /// Removes a child region.
    pub fn remove_child(&mut self, child: RegionId) {
        let before = self.local.child_ids().len();
        self.local.remove_child(child);
        if self.local.child_ids().len() < before {
            self.mark_sync_pending();
        }
    }

    /// Adds a task to the region.
    pub fn add_task(&mut self, task: TaskId) -> Result<(), Error> {
        if !self.can_spawn() {
            return Err(
                Error::new(ErrorKind::RegionClosed).with_message("region not accepting new work")
            );
        }

        let before = self.local.task_ids().len();
        self.local
            .add_task(task)
            .map_err(|e| Error::new(ErrorKind::AdmissionDenied).with_message(format!("{e:?}")))?;
        if self.local.task_ids().len() > before {
            self.mark_sync_pending();
        }
        Ok(())
    }

    /// Removes a task from the region.
    pub fn remove_task(&mut self, task: TaskId) {
        let before = self.local.task_ids().len();
        self.local.remove_task(task);
        if self.local.task_ids().len() < before {
            self.mark_sync_pending();
        }
    }

    // =========================================================================
    // Synchronization
    // =========================================================================

    /// Synchronizes local state to distributed replicas (sync test path).
    ///
    /// Returns [`SyncResult::NotNeeded`] if in local mode or no changes pending.
    pub fn sync(&mut self, now: Time) -> Result<SyncResult, Error> {
        if !self.mode.is_replicated() || !self.sync_state.sync_pending || self.distributed.is_none()
        {
            return Ok(SyncResult::NotNeeded);
        }

        let snapshot = self.create_snapshot(now);
        let seq = snapshot.sequence;
        let timestamp = snapshot.timestamp;

        self.sync_state.last_synced_sequence = seq;
        self.sync_state.last_sync_time = Some(timestamp);
        self.sync_state.sync_pending = false;
        self.sync_state.pending_ops = 0;

        Ok(SyncResult::Synced { sequence: seq })
    }

    /// Creates a snapshot of current region state.
    #[must_use]
    pub fn create_snapshot(&mut self, now: Time) -> RegionSnapshot {
        self.sequence = self
            .sequence
            .checked_add(1)
            .expect("distributed bridge snapshot sequence counter exhausted");

        let tasks: Vec<TaskSnapshot> = self
            .local
            .task_ids()
            .into_iter()
            .map(|id| TaskSnapshot {
                task_id: id,
                state: TaskState::Running,
                priority: 0,
            })
            .collect();

        RegionSnapshot {
            region_id: self.local.id,
            state: self.local.state(),
            timestamp: now,
            sequence: self.sequence,
            tasks,
            children: self.local.child_ids(),
            finalizer_count: u32::try_from(self.local.finalizer_count()).unwrap_or(u32::MAX),
            budget: self.local.budget().to_distributed(),
            cancel_reason: self
                .local
                .cancel_reason()
                .map(|r| r.kind.as_str().to_owned()),
            parent: self.local.parent,
            metadata: vec![],
        }
    }

    /// Applies a recovered snapshot to this bridge.
    pub fn apply_snapshot(&mut self, snapshot: &RegionSnapshot) -> Result<(), Error> {
        if snapshot.region_id != self.local.id {
            return Err(Error::new(ErrorKind::ObjectMismatch)
                .with_message("snapshot region ID does not match bridge"));
        }

        // br-asupersync-nyp2ts: the inbound dedup gate uses ONLY the
        // inbound counter. Cross-cluster delivery can reorder or
        // duplicate inbound snapshots, and the gate must drop those —
        // but it must NOT also drop perfectly valid inbound snapshots
        // just because the local node has generated more outbound
        // snapshots in the meantime (`self.sequence`) or already
        // pushed a higher sequence outbound via `sync()`
        // (`last_synced_sequence`). Outbound and inbound live in
        // independent namespaces. Compare against
        // `last_applied_inbound_sequence` only.
        if snapshot.sequence <= self.sync_state.last_applied_inbound_sequence {
            return Ok(());
        }

        // Reconstruct Budget
        let budget = Budget {
            deadline: snapshot.budget.deadline_nanos.map(Time::from_nanos),
            poll_quota: snapshot.budget.polls_remaining.unwrap_or(0),
            cost_quota: snapshot.budget.cost_remaining,
            priority: 128, // Default priority (not preserved in snapshot)
        };

        // Reconstruct CancelReason
        let cancel_reason = snapshot.cancel_reason.as_ref().map(|reason_str| {
            // Attempt to parse known kinds from the string
            let kind = match reason_str.as_str() {
                "Timeout" => crate::types::cancel::CancelKind::Timeout,
                "Deadline" => crate::types::cancel::CancelKind::Deadline,
                "PollQuota" => crate::types::cancel::CancelKind::PollQuota,
                "CostBudget" => crate::types::cancel::CancelKind::CostBudget,
                "FailFast" => crate::types::cancel::CancelKind::FailFast,
                "RaceLost" => crate::types::cancel::CancelKind::RaceLost,
                "ParentCancelled" => crate::types::cancel::CancelKind::ParentCancelled,
                "ResourceUnavailable" => crate::types::cancel::CancelKind::ResourceUnavailable,
                "Shutdown" => crate::types::cancel::CancelKind::Shutdown,
                "LinkedExit" => crate::types::cancel::CancelKind::LinkedExit,
                _ => crate::types::cancel::CancelKind::User, // Fallback (includes "User")
            };

            crate::types::cancel::CancelReason::with_origin(
                kind,
                snapshot.region_id,
                snapshot.timestamp,
            )
        });

        // Extract tasks IDs
        let tasks: Vec<TaskId> = snapshot.tasks.iter().map(|t| t.task_id).collect();

        // Apply state from snapshot to local record
        self.local.apply_distributed_snapshot(
            snapshot.state,
            budget,
            snapshot.children.clone(),
            tasks,
            cancel_reason,
        );

        // br-asupersync-c2m5w7: also align the distributed record's
        // state machine. Without this, applying a snapshot that
        // transitions local from Open to Closing leaves
        // self.distributed in its prior state — and
        // `effective_state()` would then report `Inconsistent` until
        // some other lifecycle op realigns. We bypass
        // `validate_transition` here because recovery is an
        // out-of-band restore, not an in-band lifecycle step;
        // RegionRecord::apply_distributed_snapshot already follows
        // the same convention. The transitions-history VecDeque is
        // intentionally NOT mutated from here — that history is for
        // in-band lifecycle events and reaching into it from the
        // bridge would bypass the private `MAX_TRANSITION_HISTORY`
        // cap enforced by `record_transition`.
        if let Some(ref mut dist) = self.distributed {
            let target = snapshot.state.to_distributed();
            if dist.state != target {
                dist.state = target;
                dist.last_replicated = Some(snapshot.timestamp);
            }
        }

        // Keep future locally created snapshots monotonic after recovery/apply.
        self.sequence = self.sequence.max(snapshot.sequence);
        self.sync_state.last_synced_sequence = snapshot.sequence;
        // br-asupersync-nyp2ts: track the inbound high-water mark
        // separately so the dedup gate above can compare against it
        // without conflating with outbound generation.
        self.sync_state.last_applied_inbound_sequence = snapshot.sequence;
        self.sync_state.last_sync_time = Some(snapshot.timestamp);
        self.sync_state.sync_pending = false;
        self.sync_state.pending_ops = 0;

        Ok(())
    }

    // =========================================================================
    // Mode Upgrade
    // =========================================================================

    /// Upgrades from local to distributed mode (sync test path).
    ///
    /// Validates preconditions and creates the distributed record.
    /// In production, this would also encode and distribute the snapshot.
    pub fn upgrade_to_distributed(
        &mut self,
        now: Time,
        config: DistributedRegionConfig,
        _replicas: &[ReplicaInfo],
    ) -> Result<UpgradeResult, Error> {
        if !self.config.allow_upgrade {
            return Err(Error::new(ErrorKind::InvalidStateTransition)
                .with_message("mode upgrade not allowed"));
        }

        if self.mode.is_replicated() {
            return Err(Error::new(ErrorKind::InvalidStateTransition)
                .with_message("already in distributed mode"));
        }

        if self.local.state() != RegionState::Open {
            return Err(Error::new(ErrorKind::InvalidStateTransition)
                .with_message("can only upgrade open regions"));
        }

        config.validate()?;

        let snapshot = self.create_snapshot(now);
        let snapshot_sequence = snapshot.sequence;

        let replication_factor = config.replication_factor;
        let consistency = config.write_consistency;

        let distributed = DistributedRegionRecord::new(
            self.local.id,
            config,
            self.local.parent,
            self.local.budget(),
        );

        let previous_mode = self.mode;
        self.distributed = Some(distributed);
        self.mode = RegionMode::Distributed {
            replication_factor,
            consistency,
        };

        Ok(UpgradeResult {
            previous_mode,
            new_mode: self.mode,
            snapshot_sequence,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::similar_names)]
mod tests {
    use super::*;
    use serde_json::json;

    // =====================================================================
    // RegionMode Tests
    // =====================================================================

    #[test]
    fn mode_local() {
        let mode = RegionMode::local();
        assert!(!mode.is_replicated());
        assert!(!mode.is_distributed());
        assert_eq!(mode.replication_factor(), 1);
    }

    #[test]
    fn mode_distributed() {
        let mode = RegionMode::distributed(3);
        assert!(mode.is_replicated());
        assert!(mode.is_distributed());
        assert_eq!(mode.replication_factor(), 3);
    }

    #[test]
    fn mode_hybrid() {
        let mode = RegionMode::hybrid(2);
        assert!(mode.is_replicated());
        assert!(!mode.is_distributed());
        assert_eq!(mode.replication_factor(), 2);
    }

    #[test]
    #[should_panic(expected = "distributed region mode requires at least one replica")]
    fn mode_distributed_rejects_zero_replication() {
        let _ = RegionMode::distributed(0);
    }

    #[test]
    #[should_panic(expected = "hybrid region mode requires at least one replica")]
    fn mode_hybrid_rejects_zero_replication() {
        let _ = RegionMode::hybrid(0);
    }

    #[test]
    fn mode_default_is_local() {
        assert_eq!(RegionMode::default(), RegionMode::Local);
    }

    // =====================================================================
    // EffectiveState Tests
    // =====================================================================

    #[test]
    fn effective_state_local_open() {
        let state = EffectiveState::compute(RegionState::Open, None);
        assert_eq!(state, EffectiveState::Open);
        assert!(state.can_spawn());
        assert!(!state.needs_recovery());
    }

    #[test]
    fn effective_state_local_closing() {
        let state = EffectiveState::compute(RegionState::Closing, None);
        assert_eq!(state, EffectiveState::Closing);
        assert!(!state.can_spawn());
    }

    #[test]
    fn effective_state_local_closed() {
        let state = EffectiveState::compute(RegionState::Closed, None);
        assert_eq!(state, EffectiveState::Closed);
    }

    #[test]
    fn effective_state_distributed_active() {
        let state =
            EffectiveState::compute(RegionState::Open, Some(DistributedRegionState::Active));
        assert_eq!(state, EffectiveState::Open);
        assert!(state.can_spawn());
    }

    #[test]
    fn effective_state_distributed_initializing() {
        let state = EffectiveState::compute(
            RegionState::Open,
            Some(DistributedRegionState::Initializing),
        );
        assert_eq!(state, EffectiveState::Open);
    }

    #[test]
    fn effective_state_degraded() {
        let state =
            EffectiveState::compute(RegionState::Open, Some(DistributedRegionState::Degraded));
        assert_eq!(state, EffectiveState::Degraded);
        assert!(!state.can_spawn());
        assert!(state.needs_recovery());
    }

    #[test]
    fn effective_state_recovering() {
        let state =
            EffectiveState::compute(RegionState::Open, Some(DistributedRegionState::Recovering));
        assert_eq!(state, EffectiveState::Recovering);
        assert!(state.needs_recovery());
    }

    #[test]
    fn effective_state_inconsistent() {
        let state =
            EffectiveState::compute(RegionState::Closed, Some(DistributedRegionState::Active));
        assert!(state.is_inconsistent());
        assert!(state.needs_recovery());
    }

    #[test]
    fn effective_state_closing_distributed() {
        let state =
            EffectiveState::compute(RegionState::Closing, Some(DistributedRegionState::Closing));
        assert_eq!(state, EffectiveState::Closing);
    }

    #[test]
    fn effective_state_closed_distributed() {
        let state =
            EffectiveState::compute(RegionState::Closed, Some(DistributedRegionState::Closed));
        assert_eq!(state, EffectiveState::Closed);
    }

    // =====================================================================
    // Type Conversion Tests
    // =====================================================================

    #[test]
    fn local_state_to_distributed() {
        assert_eq!(
            RegionState::Open.to_distributed(),
            DistributedRegionState::Active
        );
        assert_eq!(
            RegionState::Closing.to_distributed(),
            DistributedRegionState::Closing
        );
        assert_eq!(
            RegionState::Draining.to_distributed(),
            DistributedRegionState::Closing
        );
        assert_eq!(
            RegionState::Finalizing.to_distributed(),
            DistributedRegionState::Closing
        );
        assert_eq!(
            RegionState::Closed.to_distributed(),
            DistributedRegionState::Closed
        );
    }

    #[test]
    fn distributed_state_to_local() {
        assert_eq!(DistributedRegionState::Active.to_local(), RegionState::Open);
        assert_eq!(
            DistributedRegionState::Initializing.to_local(),
            RegionState::Open
        );
        assert_eq!(
            DistributedRegionState::Degraded.to_local(),
            RegionState::Open
        );
        assert_eq!(
            DistributedRegionState::Recovering.to_local(),
            RegionState::Open
        );
        assert_eq!(
            DistributedRegionState::Closing.to_local(),
            RegionState::Closing
        );
        assert_eq!(
            DistributedRegionState::Closed.to_local(),
            RegionState::Closed
        );
    }

    #[test]
    fn is_lossless_conversion() {
        assert!(DistributedRegionState::Active.is_lossless());
        assert!(DistributedRegionState::Closing.is_lossless());
        assert!(DistributedRegionState::Closed.is_lossless());
        assert!(!DistributedRegionState::Degraded.is_lossless());
        assert!(!DistributedRegionState::Recovering.is_lossless());
        assert!(!DistributedRegionState::Initializing.is_lossless());
    }

    #[test]
    fn budget_to_distributed() {
        let budget = Budget::new().with_poll_quota(100).with_cost_quota(500);
        let snapshot = budget.to_distributed();

        assert_eq!(snapshot.polls_remaining, Some(100));
        assert_eq!(snapshot.cost_remaining, Some(500));
    }

    // =====================================================================
    // Bridge Creation Tests
    // =====================================================================

    #[test]
    fn bridge_new_local() {
        let bridge = RegionBridge::new_local(RegionId::new_for_test(1, 0), None, Budget::default());

        assert_eq!(bridge.mode(), RegionMode::Local);
        assert!(bridge.distributed().is_none());
        assert!(bridge.can_spawn());
        assert_eq!(bridge.local_state(), RegionState::Open);
    }

    #[test]
    fn bridge_new_distributed() {
        let bridge = RegionBridge::new_distributed(
            RegionId::new_for_test(1, 0),
            None,
            Budget::default(),
            DistributedRegionConfig::default(),
        );

        assert!(bridge.mode().is_distributed());
        assert!(bridge.distributed().is_some());
    }

    #[test]
    fn bridge_with_mode_local() {
        let bridge = RegionBridge::with_mode(
            RegionId::new_for_test(1, 0),
            None,
            Budget::default(),
            RegionMode::Local,
        );

        assert_eq!(bridge.mode(), RegionMode::Local);
    }

    #[test]
    fn bridge_with_mode_distributed() {
        let bridge = RegionBridge::with_mode(
            RegionId::new_for_test(1, 0),
            None,
            Budget::default(),
            RegionMode::distributed(3),
        );

        assert!(bridge.mode().is_distributed());
        assert!(bridge.distributed().is_some());
    }

    #[test]
    fn bridge_with_mode_distributed_single_replica_derives_valid_quorum() {
        let bridge = RegionBridge::with_mode(
            RegionId::new_for_test(1, 0),
            None,
            Budget::default(),
            RegionMode::distributed(1),
        );

        let distributed = bridge.distributed().expect("distributed mode");
        assert_eq!(distributed.config.replication_factor, 1);
        assert_eq!(distributed.config.min_quorum, 1);
        assert_eq!(
            distributed.config.write_consistency,
            ConsistencyLevel::Quorum
        );
    }

    #[test]
    #[should_panic(expected = "distributed region mode requires at least one replica")]
    fn bridge_with_mode_distributed_rejects_zero_replication_literal() {
        let _ = RegionBridge::with_mode(
            RegionId::new_for_test(1, 0),
            None,
            Budget::default(),
            RegionMode::Distributed {
                replication_factor: 0,
                consistency: ConsistencyLevel::Quorum,
            },
        );
    }

    // =====================================================================
    // Lifecycle Coordination Tests
    // =====================================================================

    #[test]
    fn bridge_begin_close_local() {
        let mut bridge = create_local_bridge();

        let result = bridge.begin_close(None, Time::from_secs(0)).unwrap();

        assert!(result.local_changed);
        assert!(result.distributed_transition.is_none());
        assert_eq!(result.effective_state, EffectiveState::Closing);
    }

    #[test]
    fn bridge_begin_close_distributed() {
        let mut bridge = create_distributed_bridge();
        // Activate the distributed region first.
        if let Some(ref mut dist) = bridge.distributed {
            let _ = dist.activate(Time::from_secs(0));
        }

        let result = bridge.begin_close(None, Time::from_secs(1)).unwrap();

        assert!(result.local_changed);
        assert!(result.distributed_transition.is_some());
        assert_eq!(result.effective_state, EffectiveState::Closing);
    }

    #[test]
    fn bridge_full_lifecycle() {
        let mut bridge = create_local_bridge();

        // Close.
        bridge.begin_close(None, Time::from_secs(0)).unwrap();
        assert!(!bridge.can_spawn());

        // Drain.
        bridge.begin_drain().unwrap();

        // Finalize.
        bridge.begin_finalize().unwrap();

        // Complete.
        bridge.complete_close(Time::from_secs(1)).unwrap();
        assert_eq!(bridge.effective_state(), EffectiveState::Closed);
    }

    #[test]
    fn bridge_cannot_spawn_when_closed() {
        let mut bridge = create_local_bridge();
        bridge.begin_close(None, Time::from_secs(0)).unwrap();

        let result = bridge.add_task(TaskId::new_for_test(1, 0));
        assert!(result.is_err());
    }

    // =====================================================================
    // Child/Task Management Tests
    // =====================================================================

    #[test]
    fn bridge_add_remove_task() {
        let mut bridge = create_local_bridge();
        let task_id = TaskId::new_for_test(1, 0);

        bridge.add_task(task_id).unwrap();
        assert!(bridge.has_live_work());
        assert!(bridge.sync_state.sync_pending);

        bridge.remove_task(task_id);
        assert!(!bridge.has_live_work());
    }

    #[test]
    fn bridge_add_remove_child() {
        let mut bridge = create_local_bridge();
        let child_id = RegionId::new_for_test(2, 0);

        bridge.add_child(child_id).unwrap();
        assert!(bridge.has_live_work());

        bridge.remove_child(child_id);
        assert!(!bridge.has_live_work());
    }

    // =====================================================================
    // Sync Tests
    // =====================================================================

    #[test]
    fn sync_not_needed_local() {
        let mut bridge = create_local_bridge();
        let result = bridge.sync(Time::from_secs(1)).unwrap();
        assert!(matches!(result, SyncResult::NotNeeded));
    }

    #[test]
    fn sync_after_changes() {
        let mut bridge = create_distributed_bridge();
        bridge.sync_state.sync_pending = true;

        let sync_time = Time::from_secs(10);
        let result = bridge.sync(sync_time).unwrap();
        assert!(matches!(result, SyncResult::Synced { .. }));
        assert!(!bridge.sync_state.sync_pending);
        assert_eq!(bridge.sync_state.last_sync_time, Some(sync_time));
    }

    // =====================================================================
    // Snapshot Tests
    // =====================================================================

    #[test]
    fn create_snapshot_increments_sequence() {
        let mut bridge = create_local_bridge();

        let snap1 = bridge.create_snapshot(Time::from_secs(10));
        let snap2 = bridge.create_snapshot(Time::from_secs(11));

        assert_eq!(snap1.sequence, 1);
        assert_eq!(snap2.sequence, 2);
        assert_eq!(snap1.region_id, bridge.id());
        assert_eq!(snap1.timestamp, Time::from_secs(10));
        assert_eq!(snap2.timestamp, Time::from_secs(11));
    }

    #[test]
    fn snapshot_includes_tasks() {
        let mut bridge = create_local_bridge();
        bridge.add_task(TaskId::new_for_test(1, 0)).unwrap();
        bridge.add_task(TaskId::new_for_test(2, 0)).unwrap();

        let snap = bridge.create_snapshot(Time::from_secs(20));
        assert_eq!(snap.tasks.len(), 2);
    }

    #[test]
    fn apply_snapshot_updates_sync_state() {
        let mut bridge = create_local_bridge();
        bridge.sync_state.sync_pending = true;
        bridge.sync_state.pending_ops = 7;

        let snap = RegionSnapshot {
            region_id: bridge.id(),
            state: RegionState::Open,
            timestamp: Time::from_secs(100),
            sequence: 42,
            tasks: vec![],
            children: vec![],
            finalizer_count: 0,
            budget: BudgetSnapshot {
                deadline_nanos: None,
                polls_remaining: None,
                cost_remaining: None,
            },
            cancel_reason: None,
            parent: None,
            metadata: vec![],
        };

        bridge.apply_snapshot(&snap).unwrap();
        assert_eq!(bridge.sync_state.last_synced_sequence, 42);
        assert_eq!(bridge.sync_state.last_sync_time, Some(Time::from_secs(100)));
        assert!(!bridge.sync_state.sync_pending);
        assert_eq!(bridge.sync_state.pending_ops, 0);
    }

    #[test]
    fn apply_snapshot_advances_local_sequence_counter() {
        let mut bridge = create_local_bridge();

        let snap = RegionSnapshot {
            region_id: bridge.id(),
            state: RegionState::Open,
            timestamp: Time::from_secs(100),
            sequence: 42,
            tasks: vec![],
            children: vec![],
            finalizer_count: 0,
            budget: BudgetSnapshot {
                deadline_nanos: None,
                polls_remaining: None,
                cost_remaining: None,
            },
            cancel_reason: None,
            parent: None,
            metadata: vec![],
        };

        bridge.apply_snapshot(&snap).unwrap();

        let next = bridge.create_snapshot(Time::from_secs(101));
        assert_eq!(next.sequence, 43);
    }

    #[test]
    fn apply_snapshot_mismatch() {
        let mut bridge = create_local_bridge();

        let snap = RegionSnapshot {
            region_id: RegionId::new_for_test(999, 0),
            state: RegionState::Open,
            timestamp: Time::ZERO,
            sequence: 1,
            tasks: vec![],
            children: vec![],
            finalizer_count: 0,
            budget: BudgetSnapshot {
                deadline_nanos: None,
                polls_remaining: None,
                cost_remaining: None,
            },
            cancel_reason: None,
            parent: None,
            metadata: vec![],
        };

        let result = bridge.apply_snapshot(&snap);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), ErrorKind::ObjectMismatch);
    }

    // =====================================================================
    // Mode Upgrade Tests
    // =====================================================================

    #[test]
    fn upgrade_local_to_distributed() {
        let mut bridge = create_local_bridge();

        let config = DistributedRegionConfig {
            replication_factor: 3,
            ..Default::default()
        };
        let replicas = create_test_replicas(3);

        let result = bridge
            .upgrade_to_distributed(Time::from_secs(30), config, &replicas)
            .unwrap();

        assert_eq!(result.previous_mode, RegionMode::Local);
        assert!(result.new_mode.is_distributed());
        assert!(bridge.distributed().is_some());
    }

    #[test]
    fn upgrade_not_allowed() {
        let mut bridge = create_local_bridge();
        bridge.config.allow_upgrade = false;

        let result = bridge.upgrade_to_distributed(
            Time::from_secs(31),
            DistributedRegionConfig::default(),
            &create_test_replicas(3),
        );

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().kind(),
            ErrorKind::InvalidStateTransition
        );
    }

    #[test]
    fn upgrade_already_distributed() {
        let mut bridge = create_distributed_bridge();

        let result = bridge.upgrade_to_distributed(
            Time::from_secs(32),
            DistributedRegionConfig::default(),
            &create_test_replicas(3),
        );

        assert!(result.is_err());
    }

    #[test]
    fn upgrade_only_from_open() {
        let mut bridge = create_local_bridge();
        bridge.begin_close(None, Time::from_secs(0)).unwrap();

        let result = bridge.upgrade_to_distributed(
            Time::from_secs(33),
            DistributedRegionConfig::default(),
            &create_test_replicas(3),
        );

        assert!(result.is_err());
    }

    // =====================================================================
    // Helpers
    // =====================================================================

    fn create_local_bridge() -> RegionBridge {
        RegionBridge::new_local(RegionId::new_for_test(1, 0), None, Budget::default())
    }

    fn create_distributed_bridge() -> RegionBridge {
        RegionBridge::new_distributed(
            RegionId::new_for_test(1, 0),
            None,
            Budget::default(),
            DistributedRegionConfig::default(),
        )
    }

    fn create_test_replicas(count: usize) -> Vec<ReplicaInfo> {
        (0..count)
            .map(|i| ReplicaInfo::new(&format!("r{i}"), &format!("addr{i}")))
            .collect()
    }

    fn scrub_region_snapshot_for_snapshot_test(snapshot: &RegionSnapshot) -> serde_json::Value {
        json!({
            "region_id": "[region_id]",
            "state": format!("{:?}", snapshot.state),
            "timestamp_nanos": "[timestamp_nanos]",
            "sequence": snapshot.sequence,
            "tasks": snapshot.tasks.iter().map(|task| {
                json!({
                    "task_id": "[task_id]",
                    "state": format!("{:?}", task.state),
                    "priority": task.priority,
                })
            }).collect::<Vec<_>>(),
            "children": snapshot.children.iter().map(|_| "[child_region_id]").collect::<Vec<_>>(),
            "finalizer_count": snapshot.finalizer_count,
            "budget": {
                "deadline_nanos": snapshot
                    .budget
                    .deadline_nanos
                    .map(|_| "[deadline_nanos]"),
                "polls_remaining": snapshot.budget.polls_remaining,
                "cost_remaining": snapshot.budget.cost_remaining,
            },
            "cancel_reason": snapshot.cancel_reason,
            "parent": snapshot.parent.map(|_| "[parent_region_id]"),
            "metadata": snapshot.metadata,
        })
    }

    fn scrub_bridge_sequence_advancement_step(
        applied_sequence: u64,
        bridge: &RegionBridge,
    ) -> serde_json::Value {
        json!({
            "applied_sequence": applied_sequence,
            "bridge_sequence": bridge.sequence,
            "last_synced_sequence": bridge.sync_state.last_synced_sequence,
            "last_sync_time_nanos": bridge.sync_state.last_sync_time.map(|_| "[timestamp_nanos]"),
            "sync_pending": bridge.sync_state.sync_pending,
            "pending_ops": bridge.sync_state.pending_ops,
            "local_state": format!("{:?}", bridge.local.state()),
            "task_count": bridge.local.task_ids().len(),
            "child_count": bridge.local.child_ids().len(),
            "cancel_reason": bridge
                .local
                .cancel_reason()
                .map(|reason| reason.kind.as_str().to_owned()),
        })
    }

    fn run_bridge_sequence_advancement_scenario(
        snapshots: &[&RegionSnapshot],
    ) -> Vec<serde_json::Value> {
        let mut bridge = create_local_bridge();
        let mut steps = Vec::with_capacity(snapshots.len());

        for &snapshot in snapshots {
            bridge.apply_snapshot(snapshot).unwrap();
            steps.push(scrub_bridge_sequence_advancement_step(
                snapshot.sequence,
                &bridge,
            ));
        }

        steps
    }

    fn strip_applied_sequence(step: &serde_json::Value) -> serde_json::Value {
        let mut object = step
            .as_object()
            .expect("bridge sequence snapshot step should be an object")
            .clone();
        object.remove("applied_sequence");
        serde_json::Value::Object(object)
    }

    // =====================================================================
    // Lifecycle Race / Edge Case Tests (bd-fgs0)
    // =====================================================================

    #[test]
    fn upgrade_while_tasks_running() {
        // Upgrade Local→Distributed while tasks are active in the region.
        let mut bridge = create_local_bridge();
        bridge.add_task(TaskId::new_for_test(1, 0)).unwrap();
        bridge.add_task(TaskId::new_for_test(2, 0)).unwrap();
        assert!(bridge.has_live_work());

        let config = DistributedRegionConfig {
            replication_factor: 3,
            ..Default::default()
        };
        let result = bridge
            .upgrade_to_distributed(Time::from_secs(34), config, &create_test_replicas(3))
            .unwrap();

        assert!(result.new_mode.is_distributed());
        // Tasks should still be present after upgrade.
        assert!(bridge.has_live_work());
        // Snapshot taken during upgrade should include the tasks.
        assert!(result.snapshot_sequence > 0);
    }

    #[test]
    fn snapshot_monotonic_under_rapid_changes() {
        let mut bridge = create_local_bridge();

        let mut prev_seq = 0;
        for i in 0u32..20 {
            // Interleave task add/remove with snapshots.
            let tid = TaskId::new_for_test(i, 0);
            bridge.add_task(tid).unwrap();
            let snap = bridge.create_snapshot(Time::from_secs(u64::from(i) + 1));
            assert!(
                snap.sequence > prev_seq,
                "sequence must be monotonically increasing"
            );
            prev_seq = snap.sequence;
            bridge.remove_task(tid);
        }
    }

    #[test]
    fn double_close_local() {
        let mut bridge = create_local_bridge();

        let result1 = bridge.begin_close(None, Time::from_secs(0)).unwrap();
        assert!(result1.local_changed);

        // Second close — should not change state (already closing).
        let result2 = bridge.begin_close(None, Time::from_secs(1)).unwrap();
        assert!(!result2.local_changed);
        assert_eq!(result2.effective_state, EffectiveState::Closing);
    }

    #[test]
    fn double_close_distributed() {
        let mut bridge = create_distributed_bridge();

        let result1 = bridge.begin_close(None, Time::from_secs(0)).unwrap();
        assert!(result1.local_changed);
        assert!(result1.distributed_transition.is_some());
        assert_eq!(result1.effective_state, EffectiveState::Closing);

        let result2 = bridge.begin_close(None, Time::from_secs(1)).unwrap();
        assert!(!result2.local_changed);
        assert!(result2.distributed_transition.is_none());
        assert_eq!(result2.effective_state, EffectiveState::Closing);
    }

    #[test]
    fn double_complete_close_local() {
        let mut bridge = create_local_bridge();
        bridge.begin_close(None, Time::from_secs(0)).unwrap();
        bridge.begin_drain().unwrap();
        bridge.begin_finalize().unwrap();

        let result1 = bridge.complete_close(Time::from_secs(1)).unwrap();
        assert!(result1.local_changed);
        assert_eq!(result1.effective_state, EffectiveState::Closed);

        // Second complete_close — already closed, no change.
        let result2 = bridge.complete_close(Time::from_secs(2)).unwrap();
        assert!(!result2.local_changed);
    }

    #[test]
    fn double_complete_close_distributed() {
        let mut bridge = create_distributed_bridge();
        bridge.begin_close(None, Time::from_secs(0)).unwrap();
        bridge.begin_drain().unwrap();
        bridge.begin_finalize().unwrap();

        let result1 = bridge.complete_close(Time::from_secs(1)).unwrap();
        assert!(result1.local_changed);
        assert!(result1.distributed_transition.is_some());
        assert_eq!(result1.effective_state, EffectiveState::Closed);

        let result2 = bridge.complete_close(Time::from_secs(2)).unwrap();
        assert!(!result2.local_changed);
        assert!(result2.distributed_transition.is_none());
        assert_eq!(result2.effective_state, EffectiveState::Closed);
    }

    #[test]
    fn close_with_cancel_reason() {
        let mut bridge = create_local_bridge();

        let reason = CancelReason::timeout();
        let result = bridge
            .begin_close(Some(reason), Time::from_secs(0))
            .unwrap();

        assert!(result.local_changed);
        assert_eq!(result.effective_state, EffectiveState::Closing);
    }

    #[test]
    fn add_child_after_close_rejected() {
        let mut bridge = create_local_bridge();
        bridge.begin_close(None, Time::from_secs(0)).unwrap();

        let result = bridge.add_child(RegionId::new_for_test(2, 0));
        assert!(result.is_err());
    }

    #[test]
    fn sync_not_needed_when_no_changes() {
        let mut bridge = create_distributed_bridge();
        // sync_pending is false by default.
        assert!(!bridge.sync_state.sync_pending);

        let result = bridge.sync(Time::from_secs(40)).unwrap();
        assert!(matches!(result, SyncResult::NotNeeded));
    }

    #[test]
    fn sync_clears_pending_ops() {
        let mut bridge = create_distributed_bridge();
        bridge.sync_state.sync_pending = true;
        bridge.sync_state.pending_ops = 5;

        let sync_time = Time::from_secs(41);
        let result = bridge.sync(sync_time).unwrap();
        assert!(matches!(result, SyncResult::Synced { .. }));
        assert_eq!(bridge.sync_state.pending_ops, 0);
        assert!(!bridge.sync_state.sync_pending);
        assert_eq!(bridge.sync_state.last_sync_time, Some(sync_time));
    }

    #[test]
    fn pending_ops_counts_only_real_mutations() {
        let mut bridge = create_distributed_bridge();

        bridge.add_task(TaskId::new_for_test(1, 0)).unwrap();
        bridge.add_task(TaskId::new_for_test(1, 0)).unwrap(); // duplicate, no mutation
        bridge.remove_task(TaskId::new_for_test(999, 0)); // absent, no mutation
        bridge.remove_task(TaskId::new_for_test(1, 0)); // present, mutation

        bridge.add_child(RegionId::new_for_test(2, 0)).unwrap();
        bridge.add_child(RegionId::new_for_test(2, 0)).unwrap(); // duplicate, no mutation
        bridge.remove_child(RegionId::new_for_test(777, 0)); // absent, no mutation
        bridge.remove_child(RegionId::new_for_test(2, 0)); // present, mutation

        assert!(bridge.sync_state.sync_pending);
        assert_eq!(bridge.sync_state.pending_ops, 4);
    }

    #[test]
    fn close_transitions_mark_sync_pending() {
        let mut bridge = create_distributed_bridge();
        if let Some(ref mut dist) = bridge.distributed {
            let _ = dist.activate(Time::from_secs(0));
        }
        assert!(!bridge.sync_state.sync_pending);
        assert_eq!(bridge.sync_state.pending_ops, 0);

        bridge.begin_close(None, Time::from_secs(1)).unwrap();
        assert!(bridge.sync_state.sync_pending);
        assert!(bridge.sync_state.pending_ops >= 1);
    }

    #[test]
    fn upgrade_snapshot_sequence_matches() {
        let mut bridge = create_local_bridge();

        // Create two snapshots first to advance sequence.
        let _ = bridge.create_snapshot(Time::from_secs(50));
        let _ = bridge.create_snapshot(Time::from_secs(51));
        assert_eq!(bridge.sequence, 2);

        let config = DistributedRegionConfig {
            replication_factor: 3,
            ..Default::default()
        };
        let result = bridge
            .upgrade_to_distributed(Time::from_secs(52), config, &create_test_replicas(3))
            .unwrap();

        // Upgrade creates a snapshot, so sequence should be 3.
        assert_eq!(result.snapshot_sequence, 3);
    }

    #[test]
    fn bridge_with_mode_hybrid() {
        let bridge = RegionBridge::with_mode(
            RegionId::new_for_test(1, 0),
            None,
            Budget::default(),
            RegionMode::hybrid(2),
        );

        assert!(bridge.mode().is_replicated());
        assert!(!bridge.mode().is_distributed());
        // Hybrid keeps a local copy AND replicates asynchronously: the
        // distributed record must exist so replication paths fire.
        let dist = bridge
            .distributed()
            .expect("hybrid mode must create a distributed record so it actually replicates");
        assert_eq!(dist.config.replication_factor, 2);
        assert_eq!(dist.config.min_quorum, 1);
        assert_eq!(dist.config.write_consistency, ConsistencyLevel::One);
        // Bridge config should reflect async-with-lag semantics.
        assert_eq!(bridge.config.sync_mode, SyncMode::Asynchronous);
    }

    #[test]
    #[should_panic(expected = "hybrid region mode requires at least one replica")]
    fn bridge_with_mode_hybrid_rejects_zero_replication_literal() {
        let _ = RegionBridge::with_mode(
            RegionId::new_for_test(1, 0),
            None,
            Budget::default(),
            RegionMode::Hybrid {
                replication_factor: 0,
                max_lag: Duration::from_secs(1),
            },
        );
    }

    #[test]
    fn upgrade_to_distributed_rejects_zero_replication_without_panicking() {
        let mut bridge = create_local_bridge();
        let config = DistributedRegionConfig {
            min_quorum: 1,
            replication_factor: 0,
            ..Default::default()
        };

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            bridge.upgrade_to_distributed(Time::from_secs(53), config, &[])
        }))
        .expect("invalid config should return Err rather than panic");
        let err = result.expect_err("zero-replica config must be rejected");

        assert_eq!(err.kind(), ErrorKind::ConfigError);
        assert!(err.to_string().contains("replication_factor >= 1"));
        assert_eq!(bridge.mode(), RegionMode::Local);
        assert!(bridge.distributed().is_none());
    }

    #[test]
    fn upgrade_to_distributed_rejects_invalid_quorum_without_panicking() {
        let mut bridge = create_local_bridge();
        let config = DistributedRegionConfig {
            min_quorum: 3,
            replication_factor: 2,
            ..Default::default()
        };

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            bridge.upgrade_to_distributed(Time::from_secs(54), config, &[])
        }))
        .expect("invalid config should return Err rather than panic");
        let err = result.expect_err("out-of-range quorum must be rejected");

        assert_eq!(err.kind(), ErrorKind::ConfigError);
        assert!(
            err.to_string()
                .contains("min_quorum in 1..=replication_factor")
        );
        assert_eq!(bridge.mode(), RegionMode::Local);
        assert!(bridge.distributed().is_none());
    }

    #[test]
    fn effective_state_draining_with_distributed_closing() {
        let state =
            EffectiveState::compute(RegionState::Draining, Some(DistributedRegionState::Closing));
        assert_eq!(state, EffectiveState::Closing);
    }

    #[test]
    fn effective_state_finalizing_with_distributed_closing() {
        let state = EffectiveState::compute(
            RegionState::Finalizing,
            Some(DistributedRegionState::Closing),
        );
        assert_eq!(state, EffectiveState::Closing);
    }

    #[test]
    fn bridge_config_defaults() {
        let config = BridgeConfig::default();
        assert!(config.allow_upgrade);
        assert_eq!(config.sync_timeout, Duration::from_secs(5));
        assert_eq!(config.sync_mode, SyncMode::Synchronous);
        assert_eq!(
            config.conflict_resolution,
            ConflictResolution::DistributedWins
        );
    }

    #[test]
    fn sync_state_default() {
        let state = SyncState::default();
        assert_eq!(state.last_synced_sequence, 0);
        assert!(!state.sync_pending);
        assert_eq!(state.pending_ops, 0);
        assert!(state.last_sync_time.is_none());
        assert!(state.last_sync_error.is_none());
    }

    #[test]
    fn snapshot_includes_children() {
        let mut bridge = create_local_bridge();
        bridge.add_child(RegionId::new_for_test(2, 0)).unwrap();
        bridge.add_child(RegionId::new_for_test(3, 0)).unwrap();

        let snap = bridge.create_snapshot(Time::from_secs(60));
        assert_eq!(snap.children.len(), 2);
    }

    #[test]
    fn region_snapshot_json_snapshot_scrubs_ids_and_wall_clock() {
        let budget = Budget::new()
            .with_deadline(Time::from_secs(90))
            .with_poll_quota(12)
            .with_cost_quota(34);
        let mut bridge = RegionBridge::new_local(
            RegionId::new_for_test(7, 0),
            Some(RegionId::new_for_test(4, 1)),
            budget,
        );

        bridge.add_task(TaskId::new_for_test(3, 0)).unwrap();
        bridge.add_task(TaskId::new_for_test(5, 2)).unwrap();
        bridge.add_child(RegionId::new_for_test(8, 0)).unwrap();
        bridge.add_child(RegionId::new_for_test(9, 1)).unwrap();
        bridge
            .begin_close(Some(CancelReason::timeout()), Time::from_secs(55))
            .unwrap();

        let snapshot = bridge.create_snapshot(Time::from_secs(56));

        insta::assert_json_snapshot!(
            "region_snapshot_scrubbed",
            scrub_region_snapshot_for_snapshot_test(&snapshot)
        );
    }

    #[test]
    fn bridge_sequence_advancement_scrubbed() {
        let mut source = create_local_bridge();

        source.add_task(TaskId::new_for_test(11, 0)).unwrap();
        let snap1 = source.create_snapshot(Time::from_secs(10));

        source.add_child(RegionId::new_for_test(2, 0)).unwrap();
        source.add_task(TaskId::new_for_test(12, 0)).unwrap();
        let snap2 = source.create_snapshot(Time::from_secs(11));

        source
            .begin_close(Some(CancelReason::timeout()), Time::from_secs(12))
            .unwrap();
        source.remove_task(TaskId::new_for_test(11, 0));
        let snap3 = source.create_snapshot(Time::from_secs(13));

        let normal = run_bridge_sequence_advancement_scenario(&[&snap1, &snap2, &snap3]);
        let reordered = run_bridge_sequence_advancement_scenario(&[&snap2, &snap1, &snap3]);
        let duplicate =
            run_bridge_sequence_advancement_scenario(&[&snap1, &snap1, &snap2, &snap2, &snap3]);

        assert_eq!(
            normal.last(),
            reordered.last(),
            "reordered delivery should converge to the same final state"
        );
        assert_eq!(
            normal.last(),
            duplicate.last(),
            "duplicate delivery should converge to the same final state"
        );
        assert_eq!(
            strip_applied_sequence(&reordered[0]),
            strip_applied_sequence(&reordered[1]),
            "older snapshots must be ignored after a newer sequence lands"
        );
        assert_eq!(
            strip_applied_sequence(&duplicate[0]),
            strip_applied_sequence(&duplicate[1]),
            "duplicate sequence 1 delivery must be idempotent"
        );
        assert_eq!(
            strip_applied_sequence(&duplicate[2]),
            strip_applied_sequence(&duplicate[3]),
            "duplicate sequence 2 delivery must be idempotent"
        );

        insta::assert_json_snapshot!(
            "bridge_sequence_advancement_scrubbed",
            json!({
                "normal": normal,
                "reordered": reordered,
                "duplicate": duplicate,
            })
        );
    }

    #[test]
    fn region_mode_debug_clone_copy_default_eq() {
        let m = RegionMode::default();
        assert_eq!(m, RegionMode::Local);
        let dbg = format!("{m:?}");
        assert!(dbg.contains("Local"), "{dbg}");

        let dist = RegionMode::distributed(3);
        let copied: RegionMode = dist;
        let cloned = dist;
        assert_eq!(copied, cloned);
        assert_ne!(dist, RegionMode::Local);
    }

    #[test]
    fn sync_mode_debug_clone_copy_eq() {
        let s = SyncMode::Synchronous;
        let dbg = format!("{s:?}");
        assert!(dbg.contains("Synchronous"), "{dbg}");
        let copied: SyncMode = s;
        let cloned = s;
        assert_eq!(copied, cloned);
        assert_ne!(s, SyncMode::Asynchronous);
    }

    #[test]
    fn conflict_resolution_debug_clone_copy_eq() {
        let c = ConflictResolution::DistributedWins;
        let dbg = format!("{c:?}");
        assert!(dbg.contains("DistributedWins"), "{dbg}");
        let copied: ConflictResolution = c;
        let cloned = c;
        assert_eq!(copied, cloned);
    }

    #[test]
    fn bridge_config_debug_clone_default() {
        let c = BridgeConfig::default();
        let dbg = format!("{c:?}");
        assert!(dbg.contains("BridgeConfig"), "{dbg}");
        assert!(c.allow_upgrade);
        let cloned = c;
        assert_eq!(format!("{cloned:?}"), dbg);
    }

    #[test]
    fn effective_state_debug_clone_copy_eq() {
        let e = EffectiveState::Open;
        let dbg = format!("{e:?}");
        assert!(dbg.contains("Open"), "{dbg}");
        let copied: EffectiveState = e;
        let cloned = e;
        assert_eq!(copied, cloned);
        assert_ne!(e, EffectiveState::Closed);
    }

    #[test]
    fn sync_state_debug_clone_default() {
        let s = SyncState::default();
        let dbg = format!("{s:?}");
        assert!(dbg.contains("SyncState"), "{dbg}");
        assert_eq!(s.pending_ops, 0);
        let cloned = s;
        assert_eq!(format!("{cloned:?}"), dbg);
    }

    #[test]
    fn distributed_close_full_lifecycle() {
        let mut bridge = create_distributed_bridge();
        // Activate distributed record.
        if let Some(ref mut dist) = bridge.distributed {
            let _ = dist.activate(Time::from_secs(0));
        }

        // Begin close — both local and distributed should transition.
        let result = bridge.begin_close(None, Time::from_secs(1)).unwrap();
        assert!(result.local_changed);
        assert!(result.distributed_transition.is_some());

        // Drain and finalize.
        bridge.begin_drain().unwrap();
        bridge.begin_finalize().unwrap();

        // Complete close.
        let result = bridge.complete_close(Time::from_secs(2)).unwrap();
        assert_eq!(result.effective_state, EffectiveState::Closed);
    }

    // =================================================================
    // B6 Invariant Tests (asupersync-3narc.2.6)
    // =================================================================

    /// Invariant: all state pairs that do NOT match an explicit rule in
    /// `EffectiveState::compute` must produce `Inconsistent` with the
    /// correct local and distributed states preserved.
    #[test]
    fn effective_state_inconsistent_pairs_are_exhaustive() {
        // These pairs should all produce Inconsistent.
        let inconsistent_pairs: &[(RegionState, DistributedRegionState)] = &[
            (RegionState::Closed, DistributedRegionState::Active),
            (RegionState::Closed, DistributedRegionState::Initializing),
            (RegionState::Closed, DistributedRegionState::Degraded),
            (RegionState::Closed, DistributedRegionState::Recovering),
            (RegionState::Closed, DistributedRegionState::Closing),
            (RegionState::Closing, DistributedRegionState::Active),
            (RegionState::Closing, DistributedRegionState::Initializing),
            (RegionState::Closing, DistributedRegionState::Degraded),
            (RegionState::Closing, DistributedRegionState::Recovering),
            (RegionState::Closing, DistributedRegionState::Closed),
            (RegionState::Draining, DistributedRegionState::Active),
            (RegionState::Draining, DistributedRegionState::Initializing),
            (RegionState::Draining, DistributedRegionState::Degraded),
            (RegionState::Draining, DistributedRegionState::Recovering),
            (RegionState::Draining, DistributedRegionState::Closed),
            (RegionState::Finalizing, DistributedRegionState::Active),
            (
                RegionState::Finalizing,
                DistributedRegionState::Initializing,
            ),
            (RegionState::Finalizing, DistributedRegionState::Degraded),
            (RegionState::Finalizing, DistributedRegionState::Recovering),
            (RegionState::Finalizing, DistributedRegionState::Closed),
            (RegionState::Open, DistributedRegionState::Closing),
            (RegionState::Open, DistributedRegionState::Closed),
        ];

        for (local, distributed) in inconsistent_pairs {
            let state = EffectiveState::compute(*local, Some(*distributed));
            assert!(
                state.is_inconsistent(),
                "({local:?}, {distributed:?}) should be Inconsistent, got {state:?}"
            );
            if let EffectiveState::Inconsistent {
                local: l,
                distributed: d,
            } = state
            {
                assert_eq!(l, *local, "local state not preserved");
                assert_eq!(d, *distributed, "distributed state not preserved");
            }
        }
    }

    /// Invariant: Hybrid mode bridge with no distributed record reports
    /// sync as NotNeeded, even though mode.is_replicated() is true.
    #[test]
    fn hybrid_mode_sync_not_needed_without_distributed_record() {
        let mut bridge = RegionBridge::with_mode(
            RegionId::new_for_test(1, 0),
            None,
            Budget::default(),
            RegionMode::hybrid(3),
        );
        assert!(bridge.mode().is_replicated());
        let sync = bridge.sync(Time::from_secs(70)).unwrap();
        assert!(
            matches!(sync, SyncResult::NotNeeded),
            "hybrid mode without distributed record must report NotNeeded"
        );
    }

    /// Regression: Hybrid mode sync stays NotNeeded when sync_pending is
    /// set but there is no distributed record to sync to. Without the
    /// distributed record, creating a snapshot is wasteful.
    #[test]
    fn hybrid_mode_sync_not_needed_with_pending_ops() {
        let mut bridge = RegionBridge::with_mode(
            RegionId::new_for_test(1, 0),
            None,
            Budget::default(),
            RegionMode::hybrid(3),
        );
        // Simulate pending ops without going through the full close path.
        bridge.sync_state.sync_pending = true;
        bridge.sync_state.pending_ops = 3;

        let sync = bridge.sync(Time::from_secs(71)).unwrap();
        assert!(
            matches!(sync, SyncResult::NotNeeded),
            "hybrid mode without distributed record must report NotNeeded even with pending ops"
        );
    }

    // =====================================================================
    // br-asupersync-nyp2ts: inbound vs outbound dedup namespaces
    // =====================================================================

    /// Builds an `Open`-state RegionSnapshot for `bridge.id()` at the
    /// requested sequence number. Used by the nyp2ts regression
    /// tests below.
    fn nyp2ts_snapshot_at(bridge: &RegionBridge, sequence: u64) -> RegionSnapshot {
        RegionSnapshot {
            region_id: bridge.id(),
            state: RegionState::Open,
            timestamp: Time::from_secs(sequence),
            sequence,
            tasks: vec![],
            children: vec![],
            finalizer_count: 0,
            budget: BudgetSnapshot {
                deadline_nanos: None,
                polls_remaining: None,
                cost_remaining: None,
            },
            cancel_reason: None,
            parent: None,
            metadata: vec![],
        }
    }

    #[test]
    fn nyp2ts_outbound_create_does_not_gate_inbound_apply() {
        // Pre-fix the dedup gate compared snapshot.sequence against
        // self.sequence (outbound counter), so generating outbound
        // snapshots locally caused valid inbound snapshots with a
        // smaller sequence to be silently dropped. Post-fix the gate
        // is keyed only on last_applied_inbound_sequence — outbound
        // generation is irrelevant to inbound application.
        let mut bridge = create_local_bridge();

        // Generate 5 outbound snapshots: self.sequence advances to 5,
        // last_applied_inbound_sequence stays at 0.
        for _ in 0..5 {
            let _ = bridge.create_snapshot(Time::from_secs(0));
        }
        assert_eq!(bridge.sequence, 5, "outbound counter must have advanced");
        assert_eq!(
            bridge.sync_state.last_applied_inbound_sequence, 0,
            "no inbound snapshots have been applied yet"
        );

        // Inbound snapshot from a peer with its OWN sequence=3. Pre-
        // fix this would silently drop because 3 <= max(self.sequence=5,
        // last_synced_sequence=0) = 5. Post-fix it applies cleanly
        // because 3 > last_applied_inbound_sequence=0.
        let inbound = nyp2ts_snapshot_at(&bridge, 3);
        bridge.apply_snapshot(&inbound).unwrap();

        assert_eq!(
            bridge.sync_state.last_applied_inbound_sequence, 3,
            "inbound snapshot must have been applied (was silently dropped pre-fix)"
        );
    }

    #[test]
    fn nyp2ts_outbound_sync_does_not_gate_inbound_apply() {
        // Same shape as above but with the outbound counter promoted
        // by sync() (which also advances last_synced_sequence). The
        // inbound apply must still go through.
        let mut bridge = create_distributed_bridge();
        bridge.sync_state.sync_pending = true;
        let _ = bridge.sync(Time::from_secs(10)).unwrap();
        assert!(
            bridge.sync_state.last_synced_sequence > 0,
            "outbound sync must have advanced last_synced_sequence"
        );

        let inbound_seq = bridge.sync_state.last_synced_sequence - 1;
        // Edge case: if outbound sync only emitted seq=1, fall back
        // to seq=1 since 0 is not > last_applied_inbound_sequence=0.
        let inbound_seq = inbound_seq.max(1);
        let inbound = nyp2ts_snapshot_at(&bridge, inbound_seq);
        bridge.apply_snapshot(&inbound).unwrap();

        assert_eq!(
            bridge.sync_state.last_applied_inbound_sequence, inbound_seq,
            "inbound apply must succeed even when outbound sync ran first"
        );
    }

    #[test]
    fn nyp2ts_inbound_dedup_still_drops_duplicates_and_older() {
        // The dedup gate must still drop duplicate or older inbound
        // snapshots — that's the legitimate behaviour the gate
        // exists for. After applying seq=10, applying seq=10 again
        // (duplicate) and seq=5 (older) must both be silent no-ops.
        let mut bridge = create_local_bridge();

        let first = nyp2ts_snapshot_at(&bridge, 10);
        bridge.apply_snapshot(&first).unwrap();
        assert_eq!(bridge.sync_state.last_applied_inbound_sequence, 10);

        // Duplicate.
        let dup = nyp2ts_snapshot_at(&bridge, 10);
        bridge.apply_snapshot(&dup).unwrap();
        assert_eq!(
            bridge.sync_state.last_applied_inbound_sequence, 10,
            "duplicate inbound must not advance the counter"
        );

        // Older.
        let older = nyp2ts_snapshot_at(&bridge, 5);
        bridge.apply_snapshot(&older).unwrap();
        assert_eq!(
            bridge.sync_state.last_applied_inbound_sequence, 10,
            "older inbound must not rewind the counter"
        );

        // Strictly newer must apply.
        let newer = nyp2ts_snapshot_at(&bridge, 11);
        bridge.apply_snapshot(&newer).unwrap();
        assert_eq!(bridge.sync_state.last_applied_inbound_sequence, 11);
    }
}
