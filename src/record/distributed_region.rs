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
            last_heartbeat: Time::ZERO,
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
}

impl DistributedRegionRecord {
    /// Creates a new distributed region in Initializing state.
    #[must_use]
    pub fn new(
        id: RegionId,
        config: DistributedRegionConfig,
        parent: Option<RegionId>,
        budget: Budget,
    ) -> Self {
        Self {
            id,
            state: DistributedRegionState::Initializing,
            config,
            replicas: Vec::new(),
            transitions: VecDeque::new(),
            last_replicated: None,
            parent,
            budget,
        }
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

    /// Marks a replica as lost and potentially degrades the region.
    pub fn replica_lost(&mut self, replica_id: &str, now: Time) -> Result<StateTransition, Error> {
        // Mark the replica as unavailable.
        let found = self.replicas.iter_mut().find(|r| r.id == replica_id);

        if let Some(replica) = found {
            replica.status = ReplicaStatus::Unavailable;
        }

        let healthy = self.healthy_replicas();

        // If we're Active and lost quorum, degrade.
        if self.state == DistributedRegionState::Active && healthy < self.config.min_quorum {
            let transition = self.record_transition(
                DistributedRegionState::Degraded,
                TransitionReason::ReplicaLost {
                    replica_id: replica_id.to_string(),
                    remaining: healthy,
                },
                now,
            );
            return Ok(transition);
        }

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
        if self.replicas.iter().any(|r| r.id == info.id) {
            return Err(Error::new(ErrorKind::Internal)
                .with_message(format!("replica {} already exists", info.id)));
        }
        self.replicas.push(info);
        Ok(())
    }

    /// Removes a replica from the region.
    pub fn remove_replica(&mut self, replica_id: &str) -> Result<ReplicaInfo, Error> {
        let pos = self
            .replicas
            .iter()
            .position(|r| r.id == replica_id)
            .ok_or_else(|| {
                Error::new(ErrorKind::Internal)
                    .with_message(format!("replica {replica_id} not found"))
            })?;
        Ok(self.replicas.remove(pos))
    }

    /// Updates replica status based on heartbeat.
    pub fn update_replica_status(
        &mut self,
        replica_id: &str,
        status: ReplicaStatus,
        now: Time,
    ) -> Result<(), Error> {
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
        assert!(!state.is_terminal());
        assert!(state.is_unhealthy());
        assert!(state.can_read());
        assert!(!state.can_write());
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

        // Complete recovery.
        let transition = region.complete_recovery(42, Time::from_secs(15)).unwrap();
        assert_eq!(transition.to, DistributedRegionState::Active);
        assert_eq!(region.state, DistributedRegionState::Active);
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
        let result = region.remove_replica("nonexistent");
        assert!(result.is_err());
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
    }

    #[test]
    fn remove_replica() {
        let mut region = create_active_region();
        let removed = region.remove_replica("r2").unwrap();
        assert_eq!(removed.id, "r2");
        assert_eq!(region.replicas.len(), 1);
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
}
