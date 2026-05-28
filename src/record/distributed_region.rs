//! Distributed region state machine.
//!
//! Extends the local [`RegionRecord`](super::region::RegionRecord) concept to
//! operate across multiple replicas with fault-tolerant structured concurrency.

#![allow(clippy::result_large_err)]
//!
//! # State Transitions
//!
//! ```text
//!  Initializing ──(quorum_reached)──> Active
//!  Initializing ──(init_timeout)───> Degraded
//!  Initializing ──(close)──────────> Closing
//!  Active ────────(replica_lost)───> Degraded
//!  Active ────────(close)──────────> Closing
//!  Degraded ──────(recovery)───────> Recovering
//!  Degraded ──────(close)──────────> Closing
//!  Recovering ────(success)────────> Active
//!  Recovering ────(failure/close)──> Closing
//!  Closing ───────(complete)───────> Closed
//! ```

use crate::error::{Error, ErrorKind};
use crate::remote::NodeId;
use crate::trace::distributed::vclock::{CausalOrder, VectorClock};
use crate::types::{Budget, RegionId, Time};
use std::collections::VecDeque;
use std::time::Duration;

/// Maximum number of state transitions retained in history.
const MAX_TRANSITION_HISTORY: usize = 64;

// ---------------------------------------------------------------------------
// DistributedRegionState
// ---------------------------------------------------------------------------

/// The state of a distributed region in its lifecycle.
///
/// Unlike local `RegionState`, this captures distributed-specific phases
/// including initialization quorum, degraded operation, and recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DistributedRegionState {
    /// Region is forming initial quorum with replicas.
    Initializing,
    /// Region is operating normally with quorum maintained.
    Active,
    /// Region is operating below quorum (read-only mode).
    Degraded,
    /// Region is recovering state from available replicas.
    Recovering,
    /// Region is closing across all replicas.
    Closing,
    /// Terminal state - region is fully closed on all replicas.
    Closed,
}

impl DistributedRegionState {
    /// Returns true if the region can accept new work (spawns).
    #[must_use]
    pub const fn can_spawn(&self) -> bool {
        matches!(self, Self::Active)
    }

    /// Returns true if the region is in a terminal state.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(self, Self::Closed)
    }

    /// Returns true if the region is in a degraded or recovery state.
    #[must_use]
    pub const fn is_unhealthy(&self) -> bool {
        matches!(self, Self::Degraded | Self::Recovering)
    }

    /// Returns true if the region can process read operations.
    #[must_use]
    pub const fn can_read(&self) -> bool {
        matches!(self, Self::Active | Self::Degraded | Self::Recovering)
    }

    /// Returns true if write operations are allowed.
    #[must_use]
    pub const fn can_write(&self) -> bool {
        matches!(self, Self::Active)
    }

    /// Returns true if the region is closing.
    #[must_use]
    pub const fn is_closing(&self) -> bool {
        matches!(self, Self::Closing)
    }

    /// Returns the allowed transitions from this state.
    #[must_use]
    pub const fn allowed_transitions(&self) -> &'static [Self] {
        match self {
            Self::Initializing => &[Self::Active, Self::Degraded, Self::Closing],
            Self::Active => &[Self::Degraded, Self::Closing],
            Self::Degraded => &[Self::Recovering, Self::Closing],
            Self::Recovering => &[Self::Active, Self::Closing],
            Self::Closing => &[Self::Closed],
            Self::Closed => &[],
        }
    }

    /// Returns true if transition to `target` is valid.
    #[must_use]
    pub fn can_transition_to(&self, target: Self) -> bool {
        self.allowed_transitions().contains(&target)
    }
}

impl std::fmt::Display for DistributedRegionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Initializing => "initializing",
            Self::Active => "active",
            Self::Degraded => "degraded",
            Self::Recovering => "recovering",
            Self::Closing => "closing",
            Self::Closed => "closed",
        };
        write!(f, "{s}")
    }
}

// ---------------------------------------------------------------------------
// StateTransition
// ---------------------------------------------------------------------------

/// A state transition event with metadata.
#[derive(Debug, Clone)]
pub struct StateTransition {
    /// Previous state before transition.
    pub from: DistributedRegionState,
    /// New state after transition.
    pub to: DistributedRegionState,
    /// Reason for the transition.
    pub reason: TransitionReason,
    /// Timestamp when transition occurred.
    pub timestamp: Time,
    /// Optional context (e.g., which replica triggered).
    pub context: Option<String>,
}

/// Result of vector clock-based conflict resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConflictResolutionResult {
    /// Keep the local state (local wins).
    KeepLocal,
    /// Accept the remote state (remote wins).
    AcceptRemote,
    /// Manual intervention required.
    RequiresIntervention,
}

/// Reasons that can trigger a state transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransitionReason {
    /// Initial quorum was reached during initialization.
    QuorumReached {
        /// Number of replicas that acknowledged.
        replicas: u32,
        /// Minimum required for quorum.
        required: u32,
    },
    /// Initialization timed out before quorum.
    InitTimeout {
        /// Number of replicas achieved.
        achieved: u32,
        /// Minimum required for quorum.
        required: u32,
    },
    /// A replica became unavailable.
    ReplicaLost {
        /// Identifier of the lost replica.
        replica_id: String,
        /// Remaining healthy replica count.
        remaining: u32,
    },
    /// Quorum was lost (dropped below threshold).
    QuorumLost {
        /// Remaining healthy replicas.
        remaining: u32,
        /// Minimum required for quorum.
        required: u32,
    },
    /// Recovery was explicitly triggered.
    RecoveryTriggered {
        /// Who initiated recovery.
        initiator: String,
    },
    /// Recovery completed successfully.
    RecoveryComplete {
        /// Number of symbols used for recovery.
        symbols_used: u32,
        /// Duration of recovery in milliseconds.
        duration_ms: u64,
    },
    /// Recovery failed and cannot continue.
    RecoveryFailed {
        /// Reason for failure.
        reason: String,
    },
    /// Local region requested close.
    LocalClose,
    /// User/operator requested close.
    UserClose {
        /// Optional reason from the user.
        reason: Option<String>,
    },
    /// Close completed across all replicas.
    CloseComplete,
    /// Cancellation propagated from parent.
    Cancelled {
        /// Reason for cancellation.
        reason: String,
    },
    /// Conflict was resolved during partition healing.
    ConflictResolved {
        /// How the conflict was resolved.
        resolution: ConflictResolutionResult,
        /// Causal relationship between local and remote state.
        causal_order: CausalOrder,
        /// Local sequence number at conflict time.
        local_sequence: u64,
        /// Remote sequence number at conflict time.
        remote_sequence: u64,
    },
    /// Region was prepared for merge operation.
    MergePrepared,
}

// ---------------------------------------------------------------------------
// ConsistencyLevel
// ---------------------------------------------------------------------------

/// Consistency level for distributed operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsistencyLevel {
    /// Operation completes when one replica acknowledges.
    One,
    /// Operation completes when quorum (majority) acknowledges.
    Quorum,
    /// Operation completes when all replicas acknowledge.
    All,
    /// Local only - no replication (for testing).
    Local,
}

// ---------------------------------------------------------------------------
// DistributedRegionConfig
// ---------------------------------------------------------------------------

/// Configuration for distributed region behavior.
#[derive(Debug, Clone)]
pub struct DistributedRegionConfig {
    /// Minimum replicas required for quorum (write operations).
    pub min_quorum: u32,
    /// Total number of replicas to maintain.
    pub replication_factor: u32,
    /// Timeout for initial quorum formation.
    pub init_timeout: Duration,
    /// Timeout for recovery operations.
    pub recovery_timeout: Duration,
    /// Whether to allow degraded (read-only) operation.
    pub allow_degraded: bool,
    /// Consistency level for read operations.
    pub read_consistency: ConsistencyLevel,
    /// Consistency level for write operations.
    pub write_consistency: ConsistencyLevel,
    /// Maximum time to wait for replica acknowledgement.
    pub replica_timeout: Duration,
}

impl Default for DistributedRegionConfig {
    fn default() -> Self {
        Self {
            min_quorum: 2,
            replication_factor: 3,
            init_timeout: Duration::from_secs(30),
            recovery_timeout: Duration::from_mins(1),
            allow_degraded: true,
            read_consistency: ConsistencyLevel::One,
            write_consistency: ConsistencyLevel::Quorum,
            replica_timeout: Duration::from_secs(5),
        }
    }
}

impl DistributedRegionConfig {
    pub(crate) fn validate(&self) -> Result<(), Error> {
        if self.replication_factor == 0 {
            return Err(Error::new(ErrorKind::ConfigError)
                .with_message("distributed region config requires replication_factor >= 1"));
        }
        if self.min_quorum == 0 || self.min_quorum > self.replication_factor {
            return Err(Error::new(ErrorKind::ConfigError).with_message(
                "distributed region config requires min_quorum in 1..=replication_factor",
            ));
        }
        Ok(())
    }

    fn assert_valid(&self) {
        self.validate()
            .expect("distributed region config must satisfy replication/quorum invariants");
    }
}

// ---------------------------------------------------------------------------
// ReplicaInfo
// ---------------------------------------------------------------------------

/// Status of a replica.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplicaStatus {
    /// Replica is healthy and responsive.
    Healthy,
    /// Replica is suspected (missed heartbeats).
    Suspect,
    /// Replica is confirmed unavailable.
    Unavailable,
    /// Replica is syncing (catching up).
    Syncing,
}

/// Information about a replica.
#[derive(Debug, Clone)]
pub struct ReplicaInfo {
    /// Unique identifier for this replica.
    pub id: String,
    /// Network address for the replica.
    pub address: String,
    /// Current status of the replica.
    pub status: ReplicaStatus,
    /// Last heartbeat timestamp.
    pub last_heartbeat: Time,
    /// Symbols held by this replica.
    pub symbol_count: u32,
}

impl ReplicaInfo {
    /// Creates a new replica with Healthy status.
    #[must_use]
    pub fn new(id: &str, address: &str) -> Self {
        Self {
            id: id.to_string(),
            address: address.to_string(),
            status: ReplicaStatus::Healthy,
            last_heartbeat: Time::from_nanos(1_000_000_000),
            symbol_count: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// DistributedRegionRecord
// ---------------------------------------------------------------------------

/// Internal record for a distributed region.
#[derive(Debug)]
pub struct DistributedRegionRecord {
    /// Unique identifier for this region.
    pub id: RegionId,
    /// Distributed-specific state.
    pub state: DistributedRegionState,
    /// Configuration for this region.
    pub config: DistributedRegionConfig,
    /// Active replicas (by replica ID).
    pub replicas: Vec<ReplicaInfo>,
    /// State transition history (bounded).
    pub transitions: VecDeque<StateTransition>,
    /// Last successful replication timestamp.
    pub last_replicated: Option<Time>,
    /// Parent region (if nested).
    pub parent: Option<RegionId>,
    /// Budget allocated to this region.
    pub budget: Budget,
    /// Vector clock for tracking causality in distributed operations.
    pub vector_clock: VectorClock,
    /// Node ID of the local replica.
    pub local_node_id: NodeId,
}

impl DistributedRegionRecord {
    /// Creates a new distributed region in Initializing state.
    #[must_use]
    pub fn new(
        id: RegionId,
        config: DistributedRegionConfig,
        parent: Option<RegionId>,
        budget: Budget,
        local_node_id: NodeId,
    ) -> Self {
        config.assert_valid();
        let mut vector_clock = VectorClock::new();
        // Initialize the local node in the vector clock
        vector_clock.increment(&local_node_id);

        Self {
            id,
            state: DistributedRegionState::Initializing,
            config,
            replicas: Vec::with_capacity(3),
            transitions: VecDeque::with_capacity(MAX_TRANSITION_HISTORY),
            last_replicated: None,
            parent,
            budget,
            vector_clock,
            local_node_id,
        }
    }

    // --- Split-brain detection and partition tolerance ---

    /// Detects and handles heartbeat timeouts for split-brain prevention.
    ///
    /// Checks all replicas for heartbeat timeouts and marks them as suspect
    /// or unavailable based on the configured replica timeout. This is the
    /// core split-brain detection mechanism.
    pub fn detect_partition(&mut self, now: Time) -> Result<Vec<StateTransition>, Error> {
        let mut transitions = Vec::new();
        let mut needs_reconcile = false;
        let replica_timeout_ns = self
            .config
            .replica_timeout
            .as_nanos()
            .min(u128::from(u64::MAX)) as u64;
        let double_timeout_ns = (self.config.replica_timeout * 2)
            .as_nanos()
            .min(u128::from(u64::MAX)) as u64;
        let timeout_threshold = Time::from_nanos(now.as_nanos().saturating_sub(replica_timeout_ns));

        for replica in &mut self.replicas {
            if replica.status == ReplicaStatus::Healthy
                && replica.last_heartbeat < timeout_threshold
            {
                // Mark as suspect first, then unavailable if confirmed
                replica.status = ReplicaStatus::Suspect;
            } else if replica.status == ReplicaStatus::Suspect
                && replica.last_heartbeat
                    < Time::from_nanos(now.as_nanos().saturating_sub(double_timeout_ns))
            {
                // Confirm as unavailable after 2x timeout
                replica.status = ReplicaStatus::Unavailable;
                needs_reconcile = true;
            }
        }

        if needs_reconcile {
            if let Some(transition) = self.reconcile_replica_change(now) {
                transitions.push(transition);
            }
        }

        Ok(transitions)
    }

    /// Checks if the current state represents a network partition.
    ///
    /// A partition is detected when:
    /// 1. We have lost quorum (below min_quorum healthy replicas)
    /// 2. Some replicas are suspected but not confirmed unavailable
    /// 3. The region is in Degraded state due to network issues
    #[must_use]
    pub fn is_partitioned(&self) -> bool {
        let healthy = self.healthy_replicas();
        let suspected = self
            .replicas
            .iter()
            .filter(|r| r.status == ReplicaStatus::Suspect)
            .count() as u32;

        // Partition detected if we lost quorum but have suspected (not confirmed dead) replicas
        healthy < self.config.min_quorum && suspected > 0
    }

    /// Returns true if this node is in a minority partition.
    ///
    /// A minority partition occurs when this node can see fewer than half
    /// of the total configured replicas. This is critical for preventing
    /// split-brain scenarios where multiple minorities might accept writes.
    #[must_use]
    pub fn is_minority_partition(&self) -> bool {
        let reachable = self.healthy_replicas()
            + self
                .replicas
                .iter()
                .filter(|r| r.status == ReplicaStatus::Syncing)
                .count() as u32;

        reachable < (self.config.replication_factor / 2) + 1
    }

    /// Attempts to recover from a network partition by re-establishing
    /// contact with suspected replicas.
    ///
    /// This method should be called periodically during Degraded state
    /// to detect when network connectivity is restored.
    pub fn attempt_partition_recovery(
        &mut self,
        now: Time,
    ) -> Result<Option<StateTransition>, Error> {
        if !matches!(self.state, DistributedRegionState::Degraded) {
            return Ok(None);
        }

        // Count replicas that might be reachable again
        let potentially_healthy = self
            .replicas
            .iter()
            .filter(|r| {
                matches!(
                    r.status,
                    ReplicaStatus::Healthy | ReplicaStatus::Syncing | ReplicaStatus::Suspect
                )
            })
            .count() as u32;

        // If we might have quorum, trigger recovery
        if potentially_healthy >= self.config.min_quorum {
            return Ok(Some(self.trigger_recovery("partition_recovery", now)?));
        }

        Ok(None)
    }

    /// Updates heartbeat for a replica and potentially transitions out of degraded state.
    ///
    /// This is an enhanced version of update_replica_status that specifically
    /// handles partition recovery scenarios.
    pub fn receive_heartbeat(
        &mut self,
        replica_id: &str,
        now: Time,
    ) -> Result<Option<StateTransition>, Error> {
        let replica = self
            .replicas
            .iter_mut()
            .find(|r| r.id == replica_id)
            .ok_or_else(|| {
                Error::new(ErrorKind::Internal)
                    .with_message(format!("replica {replica_id} not found"))
            })?;

        // Update heartbeat and status
        replica.last_heartbeat = now;
        let old_status = replica.status;
        replica.status = ReplicaStatus::Healthy;

        // If this heartbeat restores quorum, trigger recovery
        if matches!(
            old_status,
            ReplicaStatus::Suspect | ReplicaStatus::Unavailable
        ) && self.state == DistributedRegionState::Degraded
            && self.has_quorum()
        {
            return Ok(Some(self.trigger_recovery("heartbeat_recovery", now)?));
        }

        // Standard reconciliation for other cases
        Ok(self.reconcile_replica_change(now))
    }

    // --- Vector clock-based merge semantics ---

    /// Attempts to merge state from another region using vector clock causality.
    ///
    /// This implements the core conflict resolution for partition healing:
    /// 1. If local causally dominates remote: keep local state
    /// 2. If remote causally dominates local: accept remote state
    /// 3. If concurrent: use sequence number tie-breaking
    ///
    /// Returns the conflict resolution decision.
    pub fn resolve_conflict(
        &mut self,
        remote_vector_clock: &VectorClock,
        remote_sequence: u64,
        local_sequence: u64,
        now: Time,
    ) -> Result<ConflictResolutionResult, Error> {
        // Compare vector clocks to determine causal relationship
        let causal_order = self.vector_clock.causal_order(remote_vector_clock);

        let resolution = match causal_order {
            CausalOrder::Before => {
                // Local happened before remote, so remote has newer information
                // Accept remote state and update our vector clock
                self.vector_clock.merge_in(remote_vector_clock);
                self.vector_clock.increment(&self.local_node_id);
                ConflictResolutionResult::AcceptRemote
            }
            CausalOrder::After => {
                // Local happened after remote, so local has newer information
                // Keep local state, but still update vector clock
                self.vector_clock.merge_in(remote_vector_clock);
                self.vector_clock.increment(&self.local_node_id);
                ConflictResolutionResult::KeepLocal
            }
            CausalOrder::Equal => {
                // Same causal history, use sequence number tie-breaking
                self.vector_clock.merge_in(remote_vector_clock);
                self.vector_clock.increment(&self.local_node_id);
                if remote_sequence > local_sequence {
                    ConflictResolutionResult::AcceptRemote
                } else {
                    ConflictResolutionResult::KeepLocal
                }
            }
            CausalOrder::Concurrent => {
                // Concurrent updates - need tie-breaking
                self.vector_clock.merge_in(remote_vector_clock);
                self.vector_clock.increment(&self.local_node_id);

                // Use sequence number for tie-breaking in concurrent case
                match remote_sequence.cmp(&local_sequence) {
                    std::cmp::Ordering::Greater => ConflictResolutionResult::AcceptRemote,
                    std::cmp::Ordering::Less => ConflictResolutionResult::KeepLocal,
                    std::cmp::Ordering::Equal => {
                        // Same sequence number - use node ID lexicographic order for determinism
                        let remote_node_id = remote_vector_clock
                            .iter()
                            .max_by_key(|(_, count)| *count)
                            .map_or(&self.local_node_id, |(node_id, _)| node_id);

                        if self.local_node_id > *remote_node_id {
                            ConflictResolutionResult::KeepLocal
                        } else {
                            ConflictResolutionResult::AcceptRemote
                        }
                    }
                }
            }
        };

        // Record the merge decision in transition history
        let _transition = self.record_transition(
            self.state, // State doesn't change during conflict resolution
            TransitionReason::ConflictResolved {
                resolution: resolution.clone(),
                causal_order,
                local_sequence,
                remote_sequence,
            },
            now,
        );

        Ok(resolution)
    }

    /// Prepares this region for a merge operation during partition healing.
    ///
    /// This should be called before attempting to merge with other partitions
    /// to ensure the region is in a consistent state for conflict resolution.
    pub fn prepare_for_merge(&mut self, now: Time) -> Result<(), Error> {
        // Can only merge from Active or Degraded states
        if !matches!(
            self.state,
            DistributedRegionState::Active | DistributedRegionState::Degraded
        ) {
            return Err(Error::new(ErrorKind::InvalidStateTransition)
                .with_message(format!("cannot merge from state {}", self.state)));
        }

        // Update vector clock to reflect current state
        self.vector_clock.increment(&self.local_node_id);

        // Record the prepare transition
        self.record_transition(self.state, TransitionReason::MergePrepared, now);

        Ok(())
    }

    /// Checks if this region can safely merge with another partition.
    ///
    /// Returns false if merge would violate safety invariants or if
    /// insufficient replicas are available for the operation.
    #[must_use]
    pub fn can_merge_with_partition(&self) -> bool {
        // Can merge if:
        // 1. In Active or Degraded state
        // 2. Have at least one healthy replica for coordination
        // 3. Not already in a terminal state
        matches!(
            self.state,
            DistributedRegionState::Active | DistributedRegionState::Degraded
        ) && self.healthy_replicas() > 0
            && !self.state.is_terminal()
    }

    /// Detects potential split-brain scenarios using vector clock analysis.
    ///
    /// A split-brain is detected when:
    /// 1. Multiple partitions exist with concurrent vector clocks
    /// 2. Each partition believes it has quorum
    /// 3. There's evidence of concurrent writes
    #[must_use]
    pub fn detect_split_brain(&self, other_vector_clocks: &[VectorClock]) -> bool {
        // If we don't have quorum, we can't be in a split-brain scenario
        if !self.has_quorum() {
            return false;
        }

        // Check for concurrent vector clocks - indicates potential split-brain
        for other_clock in other_vector_clocks {
            if self.vector_clock.is_concurrent_with(other_clock) {
                // Concurrent clocks suggest independent progress in separate partitions
                return true;
            }
        }

        false
    }

    /// Returns the current vector clock for external synchronization.
    #[must_use]
    pub fn vector_clock(&self) -> &VectorClock {
        &self.vector_clock
    }

    /// Updates the vector clock based on a received clock from another replica.
    pub fn receive_vector_clock(&mut self, remote_clock: &VectorClock) {
        self.vector_clock.receive(&self.local_node_id, remote_clock);
    }

    // --- State transitions ---

    /// Attempts to transition to Active state.
    ///
    /// Returns error if quorum not reached or invalid transition.
    pub fn activate(&mut self, now: Time) -> Result<StateTransition, Error> {
        self.validate_transition(DistributedRegionState::Active)?;

        let healthy = self.healthy_replicas();
        if healthy < self.config.min_quorum {
            return Err(Error::quorum_not_reached(healthy, self.config.min_quorum));
        }

        let transition = self.record_transition(
            DistributedRegionState::Active,
            TransitionReason::QuorumReached {
                replicas: healthy,
                required: self.config.min_quorum,
            },
            now,
        );
        Ok(transition)
    }

    /// Marks a replica as lost and potentially degrades or closes the region.
    pub fn replica_lost(&mut self, replica_id: &str, now: Time) -> Result<StateTransition, Error> {
        self.ensure_replica_mutation_allowed("mark replica lost")?;

        // Mark the replica as unavailable.
        let replica = self
            .replicas
            .iter_mut()
            .find(|r| r.id == replica_id)
            .ok_or_else(|| {
                Error::new(ErrorKind::Internal)
                    .with_message(format!("replica {replica_id} not found"))
            })?;
        replica.status = ReplicaStatus::Unavailable;

        if let Some(transition) = self.reconcile_replica_change(now) {
            return Ok(transition);
        }

        let healthy = self.healthy_replicas();

        // If still above quorum, just note the loss without state change.
        Err(Error::new(ErrorKind::Internal).with_message(format!(
            "replica {replica_id} lost but quorum maintained ({healthy} healthy)"
        )))
    }

    /// Triggers recovery from degraded state.
    pub fn trigger_recovery(
        &mut self,
        initiator: &str,
        now: Time,
    ) -> Result<StateTransition, Error> {
        self.validate_transition(DistributedRegionState::Recovering)?;

        let transition = self.record_transition(
            DistributedRegionState::Recovering,
            TransitionReason::RecoveryTriggered {
                initiator: initiator.to_string(),
            },
            now,
        );
        Ok(transition)
    }

    /// Marks recovery as complete. Returns to Active.
    pub fn complete_recovery(
        &mut self,
        symbols_used: u32,
        now: Time,
    ) -> Result<StateTransition, Error> {
        self.validate_transition(DistributedRegionState::Active)?;

        let healthy = self.healthy_replicas();
        if healthy < self.config.min_quorum {
            return Err(Error::quorum_not_reached(healthy, self.config.min_quorum));
        }

        let duration_ms = self.transitions.back().map_or(0, |last| {
            now.as_nanos().saturating_sub(last.timestamp.as_nanos()) / 1_000_000
        });

        let transition = self.record_transition(
            DistributedRegionState::Active,
            TransitionReason::RecoveryComplete {
                symbols_used,
                duration_ms,
            },
            now,
        );
        Ok(transition)
    }

    /// Marks recovery as failed. Transitions to Closing.
    pub fn fail_recovery(&mut self, reason: String, now: Time) -> Result<StateTransition, Error> {
        self.validate_transition(DistributedRegionState::Closing)?;

        let transition = self.record_transition(
            DistributedRegionState::Closing,
            TransitionReason::RecoveryFailed { reason },
            now,
        );
        Ok(transition)
    }

    /// Begins the closing process.
    pub fn begin_close(
        &mut self,
        reason: TransitionReason,
        now: Time,
    ) -> Result<StateTransition, Error> {
        self.validate_transition(DistributedRegionState::Closing)?;
        let transition = self.record_transition(DistributedRegionState::Closing, reason, now);
        Ok(transition)
    }

    /// Completes the close (terminal transition).
    pub fn complete_close(&mut self, now: Time) -> Result<StateTransition, Error> {
        self.validate_transition(DistributedRegionState::Closed)?;
        let transition = self.record_transition(
            DistributedRegionState::Closed,
            TransitionReason::CloseComplete,
            now,
        );
        Ok(transition)
    }

    // --- Quorum management ---

    /// Returns the current quorum count (healthy replicas).
    #[must_use]
    pub fn current_quorum(&self) -> u32 {
        self.healthy_replicas()
    }

    /// Returns true if quorum is maintained.
    #[must_use]
    pub fn has_quorum(&self) -> bool {
        self.healthy_replicas() >= self.config.min_quorum
    }

    /// Returns healthy replica count.
    #[must_use]
    pub fn healthy_replicas(&self) -> u32 {
        self.replicas
            .iter()
            .filter(|r| r.status == ReplicaStatus::Healthy || r.status == ReplicaStatus::Syncing)
            .count() as u32
    }

    /// Adds a replica to the region.
    pub fn add_replica(&mut self, info: ReplicaInfo) -> Result<(), Error> {
        self.ensure_replica_mutation_allowed("add replica")?;
        if self.replicas.iter().any(|r| r.id == info.id) {
            return Err(Error::new(ErrorKind::Internal)
                .with_message(format!("replica {} already exists", info.id)));
        }
        self.replicas.push(info);
        Ok(())
    }

    /// Removes a replica from the region.
    pub fn remove_replica(&mut self, replica_id: &str, now: Time) -> Result<ReplicaInfo, Error> {
        self.ensure_replica_mutation_allowed("remove replica")?;
        let pos = self
            .replicas
            .iter()
            .position(|r| r.id == replica_id)
            .ok_or_else(|| {
                Error::new(ErrorKind::Internal)
                    .with_message(format!("replica {replica_id} not found"))
            })?;
        let removed = self.replicas.remove(pos);
        let _ = self.reconcile_replica_change(now);
        Ok(removed)
    }

    /// Updates replica status based on heartbeat.
    pub fn update_replica_status(
        &mut self,
        replica_id: &str,
        status: ReplicaStatus,
        now: Time,
    ) -> Result<(), Error> {
        self.ensure_replica_mutation_allowed("update replica status")?;
        let replica = self
            .replicas
            .iter_mut()
            .find(|r| r.id == replica_id)
            .ok_or_else(|| {
                Error::new(ErrorKind::Internal)
                    .with_message(format!("replica {replica_id} not found"))
            })?;
        replica.status = status;
        if status == ReplicaStatus::Healthy {
            replica.last_heartbeat = now;
        }
        let _ = self.reconcile_replica_change(now);
        Ok(())
    }

    // --- Internal helpers ---

    fn validate_transition(&self, target: DistributedRegionState) -> Result<(), Error> {
        if !self.state.can_transition_to(target) {
            return Err(
                Error::new(ErrorKind::InvalidStateTransition).with_message(format!(
                    "cannot transition from {} to {}",
                    self.state, target
                )),
            );
        }
        Ok(())
    }

    fn ensure_replica_mutation_allowed(&self, operation: &str) -> Result<(), Error> {
        if self.state.is_terminal() || self.state.is_closing() {
            return Err(Error::new(ErrorKind::InvalidStateTransition)
                .with_message(format!("cannot {operation} in {} region", self.state)));
        }
        Ok(())
    }

    fn reconcile_replica_change(&mut self, now: Time) -> Option<StateTransition> {
        let healthy = self.healthy_replicas();
        let next_state = match self.state {
            DistributedRegionState::Active if healthy < self.config.min_quorum => {
                Some(if healthy == 0 || !self.config.allow_degraded {
                    DistributedRegionState::Closing
                } else {
                    DistributedRegionState::Degraded
                })
            }
            DistributedRegionState::Degraded | DistributedRegionState::Recovering
                if healthy == 0 =>
            {
                Some(DistributedRegionState::Closing)
            }
            _ => None,
        }?;

        Some(self.record_transition(
            next_state,
            TransitionReason::QuorumLost {
                remaining: healthy,
                required: self.config.min_quorum,
            },
            now,
        ))
    }

    fn record_transition(
        &mut self,
        to: DistributedRegionState,
        reason: TransitionReason,
        timestamp: Time,
    ) -> StateTransition {
        let from = self.state;
        self.state = to;

        let transition = StateTransition {
            from,
            to,
            reason,
            timestamp,
            context: None,
        };

        self.transitions.push_back(transition.clone());
        if self.transitions.len() > MAX_TRANSITION_HISTORY {
            self.transitions.pop_front();
        }

        transition
    }
}

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

    // =========================================================================
    // State Predicate Tests
    // =========================================================================

    #[test]
    fn initializing_predicates() {
        let state = DistributedRegionState::Initializing;
        assert!(!state.can_spawn());
        assert!(!state.is_terminal());
        assert!(!state.is_unhealthy());
        assert!(!state.can_read());
        assert!(!state.can_write());
    }

    #[test]
    fn active_predicates() {
        let state = DistributedRegionState::Active;
        assert!(state.can_spawn());
        assert!(!state.is_terminal());
        assert!(!state.is_unhealthy());
        assert!(state.can_read());
        assert!(state.can_write());
    }

    #[test]
    fn degraded_predicates() {
        let state = DistributedRegionState::Degraded;
        assert!(!state.can_spawn());
    }

    // =========================================================================
    // Partition Tolerance Tests
    // =========================================================================

    #[test]
    fn test_partition_detection() {
        let node_id = NodeId::new("test-node");
        let config = DistributedRegionConfig {
            min_quorum: 2,
            replication_factor: 3,
            replica_timeout: Duration::from_secs(10),
            ..Default::default()
        };

        let mut record = DistributedRegionRecord::new(
            RegionId::new_for_test(1, 0),
            config,
            None,
            Budget::new(),
            node_id.clone(),
        );

        // Add replicas
        record
            .add_replica(ReplicaInfo::new("replica1", "addr1"))
            .unwrap();
        record
            .add_replica(ReplicaInfo::new("replica2", "addr2"))
            .unwrap();

        let now = Time::from_secs(100);

        // Simulate heartbeat timeout
        let _transitions = record.detect_partition(now).unwrap();

        // Should detect suspects
        let suspect_count = record
            .replicas
            .iter()
            .filter(|r| r.status == ReplicaStatus::Suspect)
            .count();

        assert!(suspect_count > 0);
    }

    #[test]
    fn test_split_brain_detection() {
        let node_id = NodeId::new("test-node");
        let mut record = DistributedRegionRecord::new(
            RegionId::new_for_test(1, 0),
            DistributedRegionConfig::default(),
            None,
            Budget::new(),
            node_id,
        );

        // Activate with quorum
        record
            .add_replica(ReplicaInfo::new("replica1", "addr1"))
            .unwrap();
        record
            .add_replica(ReplicaInfo::new("replica2", "addr2"))
            .unwrap();

        let now = Time::from_secs(100);
        record.activate(now).unwrap();

        // Create a concurrent vector clock (simulating another partition)
        let other_node = NodeId::new("other-node");
        let mut other_clock = VectorClock::new();
        other_clock.increment(&other_node);
        other_clock.increment(&other_node);

        let other_clocks = vec![other_clock];

        // Should detect split-brain with concurrent clocks
        assert!(record.detect_split_brain(&other_clocks));
    }

    #[test]
    fn test_vector_clock_conflict_resolution() {
        let node_id = NodeId::new("local-node");
        let mut record = DistributedRegionRecord::new(
            RegionId::new_for_test(1, 0),
            DistributedRegionConfig::default(),
            None,
            Budget::new(),
            node_id.clone(),
        );

        // Create a remote vector clock that happened after local
        let remote_node = NodeId::new("remote-node");
        let mut remote_clock = record.vector_clock().clone();
        remote_clock.increment(&remote_node);
        remote_clock.increment(&remote_node);

        let now = Time::from_secs(100);
        let result = record.resolve_conflict(&remote_clock, 10, 5, now).unwrap();

        // Remote clock happened after, so should accept remote
        assert_eq!(result, ConflictResolutionResult::AcceptRemote);
    }

    #[test]
    fn recovering_predicates() {
        let state = DistributedRegionState::Recovering;
        assert!(!state.can_spawn());
        assert!(!state.is_terminal());
        assert!(state.is_unhealthy());
        assert!(state.can_read());
        assert!(!state.can_write());
    }

    #[test]
    fn closed_is_terminal() {
        let state = DistributedRegionState::Closed;
        assert!(state.is_terminal());
        assert!(!state.can_spawn());
        assert!(!state.can_read());
        assert!(!state.can_write());
    }

    // =========================================================================
    // Transition Validity Tests
    // =========================================================================

    #[test]
    fn initializing_valid_transitions() {
        let state = DistributedRegionState::Initializing;
        assert!(state.can_transition_to(DistributedRegionState::Active));
        assert!(state.can_transition_to(DistributedRegionState::Degraded));
        assert!(state.can_transition_to(DistributedRegionState::Closing));
        assert!(!state.can_transition_to(DistributedRegionState::Recovering));
        assert!(!state.can_transition_to(DistributedRegionState::Closed));
    }

    #[test]
    fn active_valid_transitions() {
        let state = DistributedRegionState::Active;
        assert!(state.can_transition_to(DistributedRegionState::Degraded));
        assert!(state.can_transition_to(DistributedRegionState::Closing));
        assert!(!state.can_transition_to(DistributedRegionState::Initializing));
        assert!(!state.can_transition_to(DistributedRegionState::Recovering));
    }

    #[test]
    fn degraded_valid_transitions() {
        let state = DistributedRegionState::Degraded;
        assert!(state.can_transition_to(DistributedRegionState::Recovering));
        assert!(state.can_transition_to(DistributedRegionState::Closing));
        assert!(!state.can_transition_to(DistributedRegionState::Active));
    }

    #[test]
    fn recovering_valid_transitions() {
        let state = DistributedRegionState::Recovering;
        assert!(state.can_transition_to(DistributedRegionState::Active));
        assert!(state.can_transition_to(DistributedRegionState::Closing));
        assert!(!state.can_transition_to(DistributedRegionState::Degraded));
    }

    #[test]
    fn closed_no_transitions() {
        let state = DistributedRegionState::Closed;
        assert!(state.allowed_transitions().is_empty());
        assert!(!state.can_transition_to(DistributedRegionState::Initializing));
        assert!(!state.can_transition_to(DistributedRegionState::Active));
    }

    // =========================================================================
    // Region Lifecycle Tests
    // =========================================================================

    #[test]
    fn happy_path_lifecycle() {
        let config = DistributedRegionConfig::default();
        let mut region = DistributedRegionRecord::new(
            RegionId::new_ephemeral(),
            config,
            None,
            Budget::default(),
            NodeId::new("test-node"),
        );
        assert_eq!(region.state, DistributedRegionState::Initializing);

        // Add replicas to reach quorum.
        region.add_replica(ReplicaInfo::new("r1", "addr1")).unwrap();
        region.add_replica(ReplicaInfo::new("r2", "addr2")).unwrap();

        // Activate.
        let transition = region.activate(Time::from_secs(1)).unwrap();
        assert_eq!(transition.to, DistributedRegionState::Active);
        assert_eq!(region.state, DistributedRegionState::Active);

        // Close.
        let _transition = region
            .begin_close(
                TransitionReason::UserClose { reason: None },
                Time::from_secs(10),
            )
            .unwrap();
        assert_eq!(region.state, DistributedRegionState::Closing);

        // Complete close.
        let _transition = region.complete_close(Time::from_secs(11)).unwrap();
        assert_eq!(region.state, DistributedRegionState::Closed);
    }

    #[test]
    fn degraded_path() {
        let mut region = create_active_region();

        // Lose a replica below quorum.
        let transition = region.replica_lost("r2", Time::from_secs(5)).unwrap();
        assert_eq!(transition.to, DistributedRegionState::Degraded);
        assert_eq!(region.state, DistributedRegionState::Degraded);

        // Verify read-only mode.
        assert!(region.state.can_read());
        assert!(!region.state.can_write());
    }

    #[test]
    fn recovery_path() {
        let mut region = create_degraded_region();

        // Trigger recovery.
        let transition = region
            .trigger_recovery("operator", Time::from_secs(10))
            .unwrap();
        assert_eq!(transition.to, DistributedRegionState::Recovering);
        assert_eq!(region.state, DistributedRegionState::Recovering);

        region
            .update_replica_status("r2", ReplicaStatus::Healthy, Time::from_secs(14))
            .unwrap();

        // Complete recovery.
        let transition = region.complete_recovery(42, Time::from_secs(15)).unwrap();
        assert_eq!(transition.to, DistributedRegionState::Active);
        assert_eq!(region.state, DistributedRegionState::Active);
    }

    #[test]
    fn complete_recovery_requires_quorum() {
        let mut region = create_degraded_region();

        region
            .trigger_recovery("operator", Time::from_secs(10))
            .unwrap();

        let result = region.complete_recovery(42, Time::from_secs(15));
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), ErrorKind::QuorumNotReached);
        assert_eq!(region.state, DistributedRegionState::Recovering);
    }

    #[test]
    fn recovery_failure() {
        let mut region = create_degraded_region();
        region
            .trigger_recovery("operator", Time::from_secs(10))
            .unwrap();

        // Fail recovery.
        let transition = region
            .fail_recovery("insufficient symbols".to_string(), Time::from_secs(15))
            .unwrap();
        assert_eq!(transition.to, DistributedRegionState::Closing);
        assert_eq!(region.state, DistributedRegionState::Closing);
    }

    // =========================================================================
    // Error Handling Tests
    // =========================================================================

    #[test]
    fn invalid_transition_error() {
        let mut region = create_active_region();

        // Cannot go directly to Recovering from Active.
        let result = region.trigger_recovery("test", Time::from_secs(1));
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().kind(),
            ErrorKind::InvalidStateTransition
        );
    }

    #[test]
    fn activate_without_quorum_error() {
        let config = DistributedRegionConfig {
            min_quorum: 2,
            ..Default::default()
        };
        let mut region = DistributedRegionRecord::new(
            RegionId::new_ephemeral(),
            config,
            None,
            Budget::default(),
            NodeId::new("test-node"),
        );

        // Only one replica.
        region.add_replica(ReplicaInfo::new("r1", "addr1")).unwrap();

        let result = region.activate(Time::from_secs(1));
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), ErrorKind::QuorumNotReached);
    }

    #[test]
    fn close_from_any_non_terminal_state() {
        for state in [
            DistributedRegionState::Initializing,
            DistributedRegionState::Active,
            DistributedRegionState::Degraded,
            DistributedRegionState::Recovering,
        ] {
            assert!(
                state.can_transition_to(DistributedRegionState::Closing),
                "should be able to close from {state}"
            );
        }
    }

    #[test]
    fn duplicate_replica_error() {
        let mut region = create_active_region();
        let result = region.add_replica(ReplicaInfo::new("r1", "addr1"));
        assert!(result.is_err());
    }

    #[test]
    fn remove_unknown_replica_error() {
        let mut region = create_active_region();
        let result = region.remove_replica("nonexistent", Time::from_secs(7));
        assert!(result.is_err());
    }

    #[test]
    fn replica_lost_unknown_replica_error_does_not_mutate_state() {
        let mut region = create_active_region();
        let prev_state = region.state;
        let prev_healthy = region.healthy_replicas();
        let prev_transitions = region.transitions.len();

        let result = region.replica_lost("nonexistent", Time::from_secs(9));
        assert!(result.is_err());
        assert_eq!(region.state, prev_state);
        assert_eq!(region.healthy_replicas(), prev_healthy);
        assert_eq!(region.transitions.len(), prev_transitions);
    }

    // =========================================================================
    // Quorum Tests
    // =========================================================================

    #[test]
    fn quorum_calculation() {
        let config = DistributedRegionConfig {
            min_quorum: 2,
            replication_factor: 3,
            ..Default::default()
        };
        let mut region = DistributedRegionRecord::new(
            RegionId::new_ephemeral(),
            config,
            None,
            Budget::default(),
            NodeId::new("test-node"),
        );

        assert_eq!(region.current_quorum(), 0);
        assert!(!region.has_quorum());

        region.add_replica(ReplicaInfo::new("r1", "addr1")).unwrap();
        assert_eq!(region.current_quorum(), 1);
        assert!(!region.has_quorum());

        region.add_replica(ReplicaInfo::new("r2", "addr2")).unwrap();
        assert_eq!(region.current_quorum(), 2);
        assert!(region.has_quorum());
    }

    #[test]
    fn replica_status_update() {
        let mut region = create_active_region();

        region
            .update_replica_status("r1", ReplicaStatus::Suspect, Time::from_secs(3))
            .unwrap();

        let r1 = region.replicas.iter().find(|r| r.id == "r1").unwrap();
        assert_eq!(r1.status, ReplicaStatus::Suspect);
        assert_eq!(region.state, DistributedRegionState::Degraded);
    }

    #[test]
    fn quorum_loss_closes_when_degraded_mode_disabled() {
        let config = DistributedRegionConfig {
            min_quorum: 2,
            replication_factor: 3,
            allow_degraded: false,
            ..Default::default()
        };
        let mut region = DistributedRegionRecord::new(
            RegionId::new_ephemeral(),
            config,
            None,
            Budget::default(),
            NodeId::new("test-node"),
        );

        region.add_replica(ReplicaInfo::new("r1", "addr1")).unwrap();
        region.add_replica(ReplicaInfo::new("r2", "addr2")).unwrap();
        region.add_replica(ReplicaInfo::new("r3", "addr3")).unwrap();
        region.activate(Time::from_secs(0)).unwrap();

        let first_loss = region.replica_lost("r1", Time::from_secs(5));
        assert!(first_loss.is_err());
        assert_eq!(region.state, DistributedRegionState::Active);

        let transition = region.replica_lost("r2", Time::from_secs(6)).unwrap();
        assert_eq!(transition.to, DistributedRegionState::Closing);
        assert_eq!(
            transition.reason,
            TransitionReason::QuorumLost {
                remaining: 1,
                required: 2,
            }
        );
        assert_eq!(region.state, DistributedRegionState::Closing);
    }

    #[test]
    fn active_region_closes_when_last_available_replica_is_lost() {
        let config = DistributedRegionConfig {
            min_quorum: 1,
            replication_factor: 1,
            allow_degraded: true,
            ..Default::default()
        };
        let mut region = DistributedRegionRecord::new(
            RegionId::new_ephemeral(),
            config,
            None,
            Budget::default(),
            NodeId::new("test-node"),
        );
        region.add_replica(ReplicaInfo::new("r1", "addr1")).unwrap();
        region.activate(Time::from_secs(0)).unwrap();

        let transition = region.replica_lost("r1", Time::from_secs(1)).unwrap();
        assert_eq!(transition.to, DistributedRegionState::Closing);
        assert_eq!(
            transition.reason,
            TransitionReason::QuorumLost {
                remaining: 0,
                required: 1,
            }
        );
        assert_eq!(region.state, DistributedRegionState::Closing);
    }

    #[test]
    fn degraded_region_closes_when_last_available_replica_is_lost() {
        let mut region = create_degraded_region();

        let transition = region.replica_lost("r1", Time::from_secs(6)).unwrap();
        assert_eq!(transition.to, DistributedRegionState::Closing);
        assert_eq!(
            transition.reason,
            TransitionReason::QuorumLost {
                remaining: 0,
                required: 2,
            }
        );
        assert_eq!(region.state, DistributedRegionState::Closing);
    }

    #[test]
    fn recovering_region_closes_when_last_available_replica_becomes_unavailable() {
        let mut region = create_degraded_region();
        region
            .trigger_recovery("operator", Time::from_secs(10))
            .unwrap();

        region
            .update_replica_status("r1", ReplicaStatus::Unavailable, Time::from_secs(11))
            .unwrap();

        let transition = region.transitions.back().expect("closing transition");
        assert_eq!(transition.to, DistributedRegionState::Closing);
        assert_eq!(
            transition.reason,
            TransitionReason::QuorumLost {
                remaining: 0,
                required: 2,
            }
        );
        assert_eq!(region.state, DistributedRegionState::Closing);
    }

    #[test]
    fn closing_region_rejects_replica_mutations() {
        let mut region = create_active_region();
        region
            .begin_close(
                TransitionReason::UserClose { reason: None },
                Time::from_secs(10),
            )
            .unwrap();

        let add_err = region
            .add_replica(ReplicaInfo::new("r3", "addr3"))
            .unwrap_err();
        assert_eq!(add_err.kind(), ErrorKind::InvalidStateTransition);

        let update_err = region
            .update_replica_status("r1", ReplicaStatus::Suspect, Time::from_secs(12))
            .unwrap_err();
        assert_eq!(update_err.kind(), ErrorKind::InvalidStateTransition);

        let remove_err = region
            .remove_replica("r1", Time::from_secs(13))
            .unwrap_err();
        assert_eq!(remove_err.kind(), ErrorKind::InvalidStateTransition);

        let lost_err = region.replica_lost("r1", Time::from_secs(14)).unwrap_err();
        assert_eq!(lost_err.kind(), ErrorKind::InvalidStateTransition);
    }

    #[test]
    fn remove_replica() {
        let mut region = create_active_region();
        let removed = region.remove_replica("r2", Time::from_secs(6)).unwrap();
        assert_eq!(removed.id, "r2");
        assert_eq!(region.replicas.len(), 1);
        assert_eq!(region.state, DistributedRegionState::Degraded);
    }

    #[test]
    fn remove_replica_closes_when_degraded_mode_disabled() {
        let config = DistributedRegionConfig {
            min_quorum: 2,
            replication_factor: 3,
            allow_degraded: false,
            ..Default::default()
        };
        let mut region = DistributedRegionRecord::new(
            RegionId::new_ephemeral(),
            config,
            None,
            Budget::default(),
            NodeId::new("test-node"),
        );
        region.add_replica(ReplicaInfo::new("r1", "addr1")).unwrap();
        region.add_replica(ReplicaInfo::new("r2", "addr2")).unwrap();
        region.activate(Time::from_secs(0)).unwrap();

        let removed = region.remove_replica("r2", Time::from_secs(6)).unwrap();
        assert_eq!(removed.id, "r2");
        assert_eq!(region.state, DistributedRegionState::Closing);
    }

    #[test]
    fn closed_region_rejects_replica_mutations() {
        let mut region = create_active_region();
        region
            .begin_close(
                TransitionReason::UserClose { reason: None },
                Time::from_secs(10),
            )
            .unwrap();
        region.complete_close(Time::from_secs(11)).unwrap();

        let add_err = region
            .add_replica(ReplicaInfo::new("r3", "addr3"))
            .unwrap_err();
        assert_eq!(add_err.kind(), ErrorKind::InvalidStateTransition);

        let update_err = region
            .update_replica_status("r1", ReplicaStatus::Suspect, Time::from_secs(12))
            .unwrap_err();
        assert_eq!(update_err.kind(), ErrorKind::InvalidStateTransition);

        let remove_err = region
            .remove_replica("r1", Time::from_secs(13))
            .unwrap_err();
        assert_eq!(remove_err.kind(), ErrorKind::InvalidStateTransition);

        let lost_err = region.replica_lost("r1", Time::from_secs(14)).unwrap_err();
        assert_eq!(lost_err.kind(), ErrorKind::InvalidStateTransition);
    }

    // =========================================================================
    // Display/Debug Tests
    // =========================================================================

    #[test]
    fn state_display() {
        assert_eq!(
            format!("{}", DistributedRegionState::Initializing),
            "initializing"
        );
        assert_eq!(format!("{}", DistributedRegionState::Active), "active");
        assert_eq!(format!("{}", DistributedRegionState::Degraded), "degraded");
        assert_eq!(
            format!("{}", DistributedRegionState::Recovering),
            "recovering"
        );
        assert_eq!(format!("{}", DistributedRegionState::Closing), "closing");
        assert_eq!(format!("{}", DistributedRegionState::Closed), "closed");
    }

    #[test]
    fn transition_history_bounded() {
        let mut region = create_active_region();

        // Close and reopen repeatedly to build up transitions.
        // We already have 1 transition from activate. Add more via begin_close + complete_close
        // cycles. Since we can't reopen, just verify history is bounded after many closes.
        for _ in 0..MAX_TRANSITION_HISTORY + 10 {
            // Reset state to test history bounding (artificially).
            region.state = DistributedRegionState::Initializing;
            let _ = region.activate(Time::from_secs(1));
        }

        assert!(region.transitions.len() <= MAX_TRANSITION_HISTORY);
    }

    #[test]
    fn config_default() {
        let config = DistributedRegionConfig::default();
        assert_eq!(config.min_quorum, 2);
        assert_eq!(config.replication_factor, 3);
        assert!(config.allow_degraded);
        assert_eq!(config.read_consistency, ConsistencyLevel::One);
        assert_eq!(config.write_consistency, ConsistencyLevel::Quorum);
    }

    #[test]
    #[should_panic(expected = "replication_factor >= 1")]
    fn distributed_region_new_rejects_zero_replication_factor() {
        let config = DistributedRegionConfig {
            min_quorum: 1,
            replication_factor: 0,
            ..Default::default()
        };

        let _ = DistributedRegionRecord::new(
            RegionId::new_ephemeral(),
            config,
            None,
            Budget::default(),
            NodeId::new("test-node"),
        );
    }

    #[test]
    #[should_panic(expected = "min_quorum in 1..=replication_factor")]
    fn distributed_region_new_rejects_zero_quorum() {
        let config = DistributedRegionConfig {
            min_quorum: 0,
            replication_factor: 1,
            ..Default::default()
        };

        let _ = DistributedRegionRecord::new(
            RegionId::new_ephemeral(),
            config,
            None,
            Budget::default(),
            NodeId::new("test-node"),
        );
    }

    #[test]
    #[should_panic(expected = "min_quorum in 1..=replication_factor")]
    fn distributed_region_new_rejects_quorum_above_replication_factor() {
        let config = DistributedRegionConfig {
            min_quorum: 3,
            replication_factor: 2,
            ..Default::default()
        };

        let _ = DistributedRegionRecord::new(
            RegionId::new_ephemeral(),
            config,
            None,
            Budget::default(),
            NodeId::new("test-node"),
        );
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    fn create_active_region() -> DistributedRegionRecord {
        let config = DistributedRegionConfig::default();
        let mut region = DistributedRegionRecord::new(
            RegionId::new_ephemeral(),
            config,
            None,
            Budget::default(),
            NodeId::new("test-node"),
        );
        region.add_replica(ReplicaInfo::new("r1", "addr1")).unwrap();
        region.add_replica(ReplicaInfo::new("r2", "addr2")).unwrap();
        region.activate(Time::from_secs(0)).unwrap();
        region
    }

    fn create_degraded_region() -> DistributedRegionRecord {
        let mut region = create_active_region();
        region.replica_lost("r2", Time::from_secs(5)).unwrap();
        region
    }

    #[test]
    fn distributed_region_state_debug_clone_copy_hash_eq() {
        use std::collections::HashSet;
        let s = DistributedRegionState::Active;
        let dbg = format!("{s:?}");
        assert!(dbg.contains("Active"), "{dbg}");
        let copied: DistributedRegionState = s;
        let cloned = s;
        assert_eq!(copied, cloned);
        assert_ne!(s, DistributedRegionState::Closed);

        let mut set = HashSet::new();
        set.insert(DistributedRegionState::Initializing);
        set.insert(DistributedRegionState::Active);
        set.insert(DistributedRegionState::Degraded);
        assert_eq!(set.len(), 3);
    }

    #[test]
    fn consistency_level_debug_clone_copy_eq() {
        let c = ConsistencyLevel::Quorum;
        let dbg = format!("{c:?}");
        assert!(dbg.contains("Quorum"), "{dbg}");
        let copied: ConsistencyLevel = c;
        let cloned = c;
        assert_eq!(copied, cloned);
        assert_ne!(c, ConsistencyLevel::All);
    }

    #[test]
    fn distributed_region_config_debug_clone_default() {
        let c = DistributedRegionConfig::default();
        let dbg = format!("{c:?}");
        assert!(dbg.contains("DistributedRegionConfig"), "{dbg}");
        assert_eq!(c.min_quorum, 2);
        let cloned = c;
        assert_eq!(format!("{cloned:?}"), dbg);
    }

    #[test]
    fn replica_status_debug_clone_copy_eq() {
        let s = ReplicaStatus::Healthy;
        let dbg = format!("{s:?}");
        assert!(dbg.contains("Healthy"), "{dbg}");
        let copied: ReplicaStatus = s;
        let cloned = s;
        assert_eq!(copied, cloned);
        assert_ne!(s, ReplicaStatus::Unavailable);
    }
}
