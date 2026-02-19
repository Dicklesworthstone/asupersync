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
        Self::Distributed {
            replication_factor,
            consistency: ConsistencyLevel::Quorum,
        }
    }

    /// Creates a hybrid mode with async replication.
    #[must_use]
    pub fn hybrid(replication_factor: u32) -> Self {
        Self::Hybrid {
            replication_factor,
            max_lag: Duration::from_secs(5),
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
        match mode {
            RegionMode::Local | RegionMode::Hybrid { .. } => Self {
                local: RegionRecord::new(id, parent, budget),
                distributed: None,
                mode,
                sync_state: SyncState::default(),
                config: BridgeConfig::default(),
                sequence: 0,
            },
            RegionMode::Distributed {
                replication_factor,
                consistency,
            } => {
                let config = DistributedRegionConfig {
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

        let local_changed = self.local.begin_close(reason);

        let distributed_transition = if let Some(ref mut dist) = self.distributed {
            Some(dist.begin_close(transition_reason, now)?)
        } else {
            None
        };

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
        let local_changed = self.local.complete_close();

        let distributed_transition = if let Some(ref mut dist) = self.distributed {
            Some(dist.complete_close(now)?)
        } else {
            None
        };

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
    pub fn sync(&mut self) -> Result<SyncResult, Error> {
        if !self.mode.is_replicated() || !self.sync_state.sync_pending {
            return Ok(SyncResult::NotNeeded);
        }

        let snapshot = self.create_snapshot();
        let seq = snapshot.sequence;

        self.sync_state.last_synced_sequence = seq;
        self.sync_state.sync_pending = false;
        self.sync_state.pending_ops = 0;

        Ok(SyncResult::Synced { sequence: seq })
    }

    /// Creates a snapshot of current region state.
    #[must_use]
    pub fn create_snapshot(&mut self) -> RegionSnapshot {
        self.sequence += 1;

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
            timestamp: Time::ZERO,
            sequence: self.sequence,
            tasks,
            children: self.local.child_ids(),
            finalizer_count: self.local.finalizer_count() as u32,
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

        self.sync_state.last_synced_sequence = snapshot.sequence;
        self.sync_state.sync_pending = false;

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

        let snapshot = self.create_snapshot();
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
        let result = bridge.sync().unwrap();
        assert!(matches!(result, SyncResult::NotNeeded));
    }

    #[test]
    fn sync_after_changes() {
        let mut bridge = create_distributed_bridge();
        bridge.sync_state.sync_pending = true;

        let result = bridge.sync().unwrap();
        assert!(matches!(result, SyncResult::Synced { .. }));
        assert!(!bridge.sync_state.sync_pending);
    }

    // =====================================================================
    // Snapshot Tests
    // =====================================================================

    #[test]
    fn create_snapshot_increments_sequence() {
        let mut bridge = create_local_bridge();

        let snap1 = bridge.create_snapshot();
        let snap2 = bridge.create_snapshot();

        assert_eq!(snap1.sequence, 1);
        assert_eq!(snap2.sequence, 2);
        assert_eq!(snap1.region_id, bridge.id());
    }

    #[test]
    fn snapshot_includes_tasks() {
        let mut bridge = create_local_bridge();
        bridge.add_task(TaskId::new_for_test(1, 0)).unwrap();
        bridge.add_task(TaskId::new_for_test(2, 0)).unwrap();

        let snap = bridge.create_snapshot();
        assert_eq!(snap.tasks.len(), 2);
    }

    #[test]
    fn apply_snapshot_updates_sync_state() {
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
        assert_eq!(bridge.sync_state.last_synced_sequence, 42);
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

        let result = bridge.upgrade_to_distributed(config, &replicas).unwrap();

        assert_eq!(result.previous_mode, RegionMode::Local);
        assert!(result.new_mode.is_distributed());
        assert!(bridge.distributed().is_some());
    }

    #[test]
    fn upgrade_not_allowed() {
        let mut bridge = create_local_bridge();
        bridge.config.allow_upgrade = false;

        let result = bridge
            .upgrade_to_distributed(DistributedRegionConfig::default(), &create_test_replicas(3));

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().kind(),
            ErrorKind::InvalidStateTransition
        );
    }

    #[test]
    fn upgrade_already_distributed() {
        let mut bridge = create_distributed_bridge();

        let result = bridge
            .upgrade_to_distributed(DistributedRegionConfig::default(), &create_test_replicas(3));

        assert!(result.is_err());
    }

    #[test]
    fn upgrade_only_from_open() {
        let mut bridge = create_local_bridge();
        bridge.begin_close(None, Time::from_secs(0)).unwrap();

        let result = bridge
            .upgrade_to_distributed(DistributedRegionConfig::default(), &create_test_replicas(3));

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
            .upgrade_to_distributed(config, &create_test_replicas(3))
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
        for i in 0..20 {
            // Interleave task add/remove with snapshots.
            let tid = TaskId::new_for_test(i, 0);
            bridge.add_task(tid).unwrap();
            let snap = bridge.create_snapshot();
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

        let result = bridge.sync().unwrap();
        assert!(matches!(result, SyncResult::NotNeeded));
    }

    #[test]
    fn sync_clears_pending_ops() {
        let mut bridge = create_distributed_bridge();
        bridge.sync_state.sync_pending = true;
        bridge.sync_state.pending_ops = 5;

        let result = bridge.sync().unwrap();
        assert!(matches!(result, SyncResult::Synced { .. }));
        assert_eq!(bridge.sync_state.pending_ops, 0);
        assert!(!bridge.sync_state.sync_pending);
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
        let _ = bridge.create_snapshot();
        let _ = bridge.create_snapshot();
        assert_eq!(bridge.sequence, 2);

        let config = DistributedRegionConfig {
            replication_factor: 3,
            ..Default::default()
        };
        let result = bridge
            .upgrade_to_distributed(config, &create_test_replicas(3))
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
        // Hybrid mode doesn't create distributed record in with_mode.
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

        let snap = bridge.create_snapshot();
        assert_eq!(snap.children.len(), 2);
    }

    #[test]
    fn region_mode_debug_clone_copy_default_eq() {
        let m = RegionMode::default();
        assert_eq!(m, RegionMode::Local);
        let dbg = format!("{m:?}");
        assert!(dbg.contains("Local"), "{dbg}");

        let dist = RegionMode::distributed(3);
        let copied: RegionMode = dist;
        let cloned = dist.clone();
        assert_eq!(copied, cloned);
        assert_ne!(dist, RegionMode::Local);
    }

    #[test]
    fn sync_mode_debug_clone_copy_eq() {
        let s = SyncMode::Synchronous;
        let dbg = format!("{s:?}");
        assert!(dbg.contains("Synchronous"), "{dbg}");
        let copied: SyncMode = s;
        let cloned = s.clone();
        assert_eq!(copied, cloned);
        assert_ne!(s, SyncMode::Asynchronous);
    }

    #[test]
    fn conflict_resolution_debug_clone_copy_eq() {
        let c = ConflictResolution::DistributedWins;
        let dbg = format!("{c:?}");
        assert!(dbg.contains("DistributedWins"), "{dbg}");
        let copied: ConflictResolution = c;
        let cloned = c.clone();
        assert_eq!(copied, cloned);
    }

    #[test]
    fn bridge_config_debug_clone_default() {
        let c = BridgeConfig::default();
        let dbg = format!("{c:?}");
        assert!(dbg.contains("BridgeConfig"), "{dbg}");
        assert!(c.allow_upgrade);
        let cloned = c.clone();
        assert_eq!(format!("{cloned:?}"), dbg);
    }

    #[test]
    fn effective_state_debug_clone_copy_eq() {
        let e = EffectiveState::Open;
        let dbg = format!("{e:?}");
        assert!(dbg.contains("Open"), "{dbg}");
        let copied: EffectiveState = e;
        let cloned = e.clone();
        assert_eq!(copied, cloned);
        assert_ne!(e, EffectiveState::Closed);
    }

    #[test]
    fn sync_state_debug_clone_default() {
        let s = SyncState::default();
        let dbg = format!("{s:?}");
        assert!(dbg.contains("SyncState"), "{dbg}");
        assert_eq!(s.pending_ops, 0);
        let cloned = s.clone();
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
}
