//! ATP-owned QUIC connection IDs, path validation, and migration hooks.

use crate::cx::Cx;
use crate::net::atp::path::{
    AtpPathCandidate, AtpPathId, AtpPathManager, PathMigrationError, PathMigrationReason,
    PathMigrationRecord, PathMigrationStatus,
};
use crate::net::atp::protocol::quic_frames::QuicFrame;
use std::collections::{BTreeMap, BTreeSet};

/// Maximum QUIC connection ID length from RFC 9000.
pub const MAX_CONNECTION_ID_LEN: usize = 20;

/// QUIC PATH_CHALLENGE/PATH_RESPONSE payload length.
pub const PATH_VALIDATION_DATA_LEN: usize = 8;

/// QUIC stateless reset token length.
pub const STATELESS_RESET_TOKEN_LEN: usize = 16;

/// ATP QUIC connection-migration configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AtpQuicConnectionConfig {
    /// Active connection ID limit advertised by the peer.
    pub active_connection_id_limit: usize,
    /// PATH_CHALLENGE validation timeout.
    pub validation_timeout_micros: u64,
    /// Whether peer transport parameters disable active migration.
    pub active_migration_disabled: bool,
    /// Deterministic secret used to derive lab-stable validation payloads.
    pub validation_secret: u64,
}

impl Default for AtpQuicConnectionConfig {
    fn default() -> Self {
        Self {
            active_connection_id_limit: 8,
            validation_timeout_micros: 3_000_000,
            active_migration_disabled: false,
            validation_secret: 0xa7c0_0a10_9000_0001,
        }
    }
}

/// A QUIC connection ID and its stateless reset token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuicConnectionId {
    sequence: u64,
    bytes: Vec<u8>,
    stateless_reset_token: [u8; STATELESS_RESET_TOKEN_LEN],
    issued_at_micros: u64,
}

impl QuicConnectionId {
    /// Construct a connection ID.
    ///
    /// # Errors
    ///
    /// Returns [`AtpQuicConnectionError::InvalidConnectionIdLength`] when the
    /// ID is empty or longer than [`MAX_CONNECTION_ID_LEN`].
    pub fn new(
        sequence: u64,
        bytes: impl Into<Vec<u8>>,
        stateless_reset_token: [u8; STATELESS_RESET_TOKEN_LEN],
        issued_at_micros: u64,
    ) -> Result<Self, AtpQuicConnectionError> {
        let bytes = bytes.into();
        if bytes.is_empty() || bytes.len() > MAX_CONNECTION_ID_LEN {
            return Err(AtpQuicConnectionError::InvalidConnectionIdLength {
                length: bytes.len(),
            });
        }

        Ok(Self {
            sequence,
            bytes,
            stateless_reset_token,
            issued_at_micros,
        })
    }

    /// Connection ID sequence number.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Wire bytes for the connection ID.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Stateless reset token.
    #[must_use]
    pub const fn stateless_reset_token(&self) -> &[u8; STATELESS_RESET_TOKEN_LEN] {
        &self.stateless_reset_token
    }

    /// Deterministic issue timestamp.
    #[must_use]
    pub const fn issued_at_micros(&self) -> u64 {
        self.issued_at_micros
    }
}

/// Registry of active and retired QUIC connection IDs.
#[derive(Debug, Clone)]
pub struct ConnectionIdRegistry {
    active: BTreeMap<u64, QuicConnectionId>,
    retired: BTreeSet<u64>,
    active_sequence: u64,
    next_sequence: u64,
    active_limit: usize,
}

impl ConnectionIdRegistry {
    /// Construct a registry with an initial active connection ID.
    pub fn new(
        initial: QuicConnectionId,
        active_limit: usize,
    ) -> Result<Self, AtpQuicConnectionError> {
        if active_limit < 2 {
            return Err(AtpQuicConnectionError::ConnectionIdLimitTooSmall {
                limit: active_limit,
            });
        }

        let active_sequence = initial.sequence();
        let next_sequence = active_sequence.saturating_add(1);
        let mut active = BTreeMap::new();
        active.insert(active_sequence, initial);

        Ok(Self {
            active,
            retired: BTreeSet::new(),
            active_sequence,
            next_sequence,
            active_limit,
        })
    }

    /// Active connection ID.
    #[must_use]
    pub fn active(&self) -> Option<&QuicConnectionId> {
        self.active.get(&self.active_sequence)
    }

    /// Active connection ID sequence.
    #[must_use]
    pub const fn active_sequence(&self) -> u64 {
        self.active_sequence
    }

    /// Active connection ID limit.
    #[must_use]
    pub const fn active_limit(&self) -> usize {
        self.active_limit
    }

    /// Active connection IDs keyed by sequence number.
    #[must_use]
    pub const fn active_ids(&self) -> &BTreeMap<u64, QuicConnectionId> {
        &self.active
    }

    /// Retired connection ID sequence numbers.
    #[must_use]
    pub const fn retired_ids(&self) -> &BTreeSet<u64> {
        &self.retired
    }

    /// Issue a new connection ID and retire the oldest inactive ID if needed.
    pub fn issue(
        &mut self,
        bytes: impl Into<Vec<u8>>,
        stateless_reset_token: [u8; STATELESS_RESET_TOKEN_LEN],
        issued_at_micros: u64,
    ) -> Result<QuicConnectionId, AtpQuicConnectionError> {
        let cid = QuicConnectionId::new(
            self.next_sequence,
            bytes,
            stateless_reset_token,
            issued_at_micros,
        )?;
        self.next_sequence = self.next_sequence.saturating_add(1);
        self.active.insert(cid.sequence(), cid.clone());
        self.enforce_active_limit()?;
        Ok(cid)
    }

    /// Activate a connection ID by sequence number.
    pub fn activate(&mut self, sequence: u64) -> Result<(), AtpQuicConnectionError> {
        if self.retired.contains(&sequence) {
            return Err(AtpQuicConnectionError::ConnectionIdRetired { sequence });
        }
        if !self.active.contains_key(&sequence) {
            return Err(AtpQuicConnectionError::UnknownConnectionId { sequence });
        }
        self.active_sequence = sequence;
        Ok(())
    }

    /// Retire an inactive connection ID.
    pub fn retire(&mut self, sequence: u64) -> Result<(), AtpQuicConnectionError> {
        if sequence == self.active_sequence {
            return Err(AtpQuicConnectionError::CannotRetireActiveConnectionId { sequence });
        }
        if self.active.remove(&sequence).is_none() {
            return Err(AtpQuicConnectionError::UnknownConnectionId { sequence });
        }
        self.retired.insert(sequence);
        Ok(())
    }

    fn enforce_active_limit(&mut self) -> Result<(), AtpQuicConnectionError> {
        while self.active.len() > self.active_limit {
            let Some(sequence) = self
                .active
                .keys()
                .copied()
                .find(|sequence| *sequence != self.active_sequence)
            else {
                return Err(AtpQuicConnectionError::NoRetirableConnectionId);
            };
            self.retire(sequence)?;
        }
        Ok(())
    }
}

/// A pending QUIC PATH_CHALLENGE.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathValidationChallenge {
    path_id: AtpPathId,
    data: [u8; PATH_VALIDATION_DATA_LEN],
    issued_at_micros: u64,
    expires_at_micros: u64,
}

impl PathValidationChallenge {
    /// Path being validated.
    #[must_use]
    pub const fn path_id(self) -> AtpPathId {
        self.path_id
    }

    /// Challenge payload.
    #[must_use]
    pub const fn data(self) -> [u8; PATH_VALIDATION_DATA_LEN] {
        self.data
    }

    /// Issue timestamp.
    #[must_use]
    pub const fn issued_at_micros(self) -> u64 {
        self.issued_at_micros
    }

    /// Expiration timestamp.
    #[must_use]
    pub const fn expires_at_micros(self) -> u64 {
        self.expires_at_micros
    }

    /// Build the QUIC PATH_CHALLENGE frame.
    #[must_use]
    pub const fn frame(self) -> QuicFrame {
        QuicFrame::PathChallenge { data: self.data }
    }

    fn is_expired(self, now_micros: u64) -> bool {
        now_micros >= self.expires_at_micros
    }
}

/// PATH_RESPONSE processing outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathValidationOutcome {
    /// The response matched and the path is validated.
    Validated,
    /// The response data did not match the outstanding challenge.
    Rejected,
    /// The response arrived after validation timeout.
    TimedOut,
}

/// Structured ATP migration trace entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationTraceEntry {
    sequence: u64,
    event: MigrationTraceEvent,
    old_path_id: AtpPathId,
    new_path_id: AtpPathId,
    key_phase: u8,
    outcome: PathMigrationStatus,
    verifier_context: String,
    replay_pointer: String,
}

impl MigrationTraceEntry {
    /// Trace sequence number.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Trace event kind.
    #[must_use]
    pub const fn event(&self) -> MigrationTraceEvent {
        self.event
    }

    /// Path active before the event.
    #[must_use]
    pub const fn old_path_id(&self) -> AtpPathId {
        self.old_path_id
    }

    /// Candidate or committed path for the event.
    #[must_use]
    pub const fn new_path_id(&self) -> AtpPathId {
        self.new_path_id
    }

    /// Packet protection key phase observed at the event.
    #[must_use]
    pub const fn key_phase(&self) -> u8 {
        self.key_phase
    }

    /// Event outcome.
    #[must_use]
    pub const fn outcome(&self) -> PathMigrationStatus {
        self.outcome
    }

    /// Verifier continuity context.
    #[must_use]
    pub fn verifier_context(&self) -> &str {
        &self.verifier_context
    }

    /// Replay pointer for qlog/ATP trace correlation.
    #[must_use]
    pub fn replay_pointer(&self) -> &str {
        &self.replay_pointer
    }
}

/// Migration trace event kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationTraceEvent {
    /// Migration request accepted and challenge emitted.
    Requested,
    /// PATH_RESPONSE validated the candidate path.
    PathValidated,
    /// Path became active.
    Committed,
    /// Path was rejected or timed out.
    Rejected,
    /// Key phase changed during migration-capable connection lifetime.
    KeyUpdate,
}

/// ATP-owned QUIC migration state.
#[derive(Debug, Clone)]
pub struct AtpQuicConnectionState {
    config: AtpQuicConnectionConfig,
    connection_ids: ConnectionIdRegistry,
    path_manager: AtpPathManager,
    pending_challenges: BTreeMap<AtpPathId, PathValidationChallenge>,
    key_phase: u8,
    key_update_pending: bool,
    traces: Vec<MigrationTraceEntry>,
    next_trace_sequence: u64,
}

impl AtpQuicConnectionState {
    /// Construct ATP QUIC connection state.
    pub fn new(
        initial_connection_id: impl Into<Vec<u8>>,
        initial_reset_token: [u8; STATELESS_RESET_TOKEN_LEN],
        initial_path: AtpPathCandidate,
        config: AtpQuicConnectionConfig,
    ) -> Result<Self, AtpQuicConnectionError> {
        let initial_cid = QuicConnectionId::new(0, initial_connection_id, initial_reset_token, 0)?;
        Ok(Self {
            config,
            connection_ids: ConnectionIdRegistry::new(
                initial_cid,
                config.active_connection_id_limit,
            )?,
            path_manager: AtpPathManager::new(initial_path),
            pending_challenges: BTreeMap::new(),
            key_phase: 0,
            key_update_pending: false,
            traces: Vec::new(),
            next_trace_sequence: 1,
        })
    }

    /// Connection ID registry.
    #[must_use]
    pub const fn connection_ids(&self) -> &ConnectionIdRegistry {
        &self.connection_ids
    }

    /// ATP path manager.
    #[must_use]
    pub const fn path_manager(&self) -> &AtpPathManager {
        &self.path_manager
    }

    /// Pending path-validation challenges.
    #[must_use]
    pub const fn pending_challenges(&self) -> &BTreeMap<AtpPathId, PathValidationChallenge> {
        &self.pending_challenges
    }

    /// Current packet protection key phase.
    #[must_use]
    pub const fn key_phase(&self) -> u8 {
        self.key_phase
    }

    /// Migration trace entries.
    #[must_use]
    pub fn migration_traces(&self) -> &[MigrationTraceEntry] {
        &self.traces
    }

    /// Issue a fresh QUIC connection ID.
    pub fn issue_connection_id(
        &mut self,
        bytes: impl Into<Vec<u8>>,
        stateless_reset_token: [u8; STATELESS_RESET_TOKEN_LEN],
        issued_at_micros: u64,
    ) -> Result<QuicConnectionId, AtpQuicConnectionError> {
        self.connection_ids
            .issue(bytes, stateless_reset_token, issued_at_micros)
    }

    /// Retire an inactive QUIC connection ID.
    pub fn retire_connection_id(&mut self, sequence: u64) -> Result<(), AtpQuicConnectionError> {
        self.connection_ids.retire(sequence)
    }

    /// Request path migration and emit a PATH_CHALLENGE.
    pub fn request_migration(
        &mut self,
        cx: &Cx,
        candidate: AtpPathCandidate,
        reason: PathMigrationReason,
        now_micros: u64,
    ) -> Result<PathValidationChallenge, AtpQuicConnectionError> {
        checkpoint(cx)?;
        if self.config.active_migration_disabled && reason != PathMigrationReason::NatRebinding {
            return Err(AtpQuicConnectionError::ActiveMigrationDisabled);
        }

        let record = self
            .path_manager
            .request_migration(candidate, reason, now_micros)?;
        let challenge = self.make_challenge(record.candidate().id(), now_micros);
        self.pending_challenges
            .insert(record.candidate().id(), challenge);
        self.trace_record(MigrationTraceEvent::Requested, &record);
        Ok(challenge)
    }

    /// Observe a NAT rebinding candidate and require validation before commit.
    pub fn observe_nat_rebinding(
        &mut self,
        cx: &Cx,
        candidate: AtpPathCandidate,
        now_micros: u64,
    ) -> Result<PathValidationChallenge, AtpQuicConnectionError> {
        // Enhanced NAT rebinding detection with timing and connection state validation
        let active_path = self.path_manager.active_path();
        let candidate_endpoints = candidate.endpoints();
        let active_endpoints = active_path.endpoints();

        // Basic endpoint check: local same, remote different (original logic)
        if !(candidate_endpoints.local() == active_endpoints.local()
            && candidate_endpoints.remote() != active_endpoints.remote())
        {
            return Err(AtpQuicConnectionError::NotNatRebinding);
        }

        // Timing validation: NAT rebinding typically happens quickly due to NAT table
        // expiration, while load balancer changes or legitimate topology updates are gradual
        const NAT_REBINDING_WINDOW_MICROS: u64 = 30_000_000; // 30 seconds
        let time_since_active_path = now_micros.saturating_sub(active_path.observed_at_micros());
        let candidate_age = now_micros.saturating_sub(candidate.observed_at_micros());

        // If the active path has been stable for too long, endpoint change is more likely
        // to be legitimate topology change (load balancer rotation, etc.) rather than NAT rebinding
        if time_since_active_path > NAT_REBINDING_WINDOW_MICROS {
            return Err(AtpQuicConnectionError::NotNatRebinding);
        }

        // Ensure candidate observation is recent - stale observations shouldn't trigger rebinding
        if candidate_age > NAT_REBINDING_WINDOW_MICROS {
            return Err(AtpQuicConnectionError::NotNatRebinding);
        }

        // Connection state validation: ensure we're in a state where NAT rebinding makes sense
        // If there are pending migrations, this might be a cascading change rather than rebinding
        if !self.pending_challenges.is_empty() {
            return Err(AtpQuicConnectionError::NotNatRebinding);
        }

        self.request_migration(cx, candidate, PathMigrationReason::NatRebinding, now_micros)
    }

    /// Process a PATH_RESPONSE frame for a pending path.
    pub fn on_path_response(
        &mut self,
        cx: &Cx,
        path_id: AtpPathId,
        response_data: [u8; PATH_VALIDATION_DATA_LEN],
        now_micros: u64,
    ) -> Result<PathValidationOutcome, AtpQuicConnectionError> {
        checkpoint(cx)?;
        let Some(challenge) = self.pending_challenges.get(&path_id).copied() else {
            return Err(AtpQuicConnectionError::NoPendingChallenge { path_id });
        };

        if challenge.is_expired(now_micros) {
            self.pending_challenges.remove(&path_id);
            let record = self.path_manager.reject_migration(
                path_id,
                PathMigrationStatus::TimedOut,
                now_micros,
            )?;
            self.trace_record(MigrationTraceEvent::Rejected, &record);
            return Ok(PathValidationOutcome::TimedOut);
        }

        if response_data != challenge.data() {
            self.pending_challenges.remove(&path_id);
            let record = self.path_manager.reject_migration(
                path_id,
                PathMigrationStatus::Rejected,
                now_micros,
            )?;
            self.trace_record(MigrationTraceEvent::Rejected, &record);
            return Ok(PathValidationOutcome::Rejected);
        }

        let record = self.path_manager.observe_validation(path_id, now_micros)?;
        self.trace_record(MigrationTraceEvent::PathValidated, &record);
        Ok(PathValidationOutcome::Validated)
    }

    /// Build a PATH_RESPONSE frame for a received challenge.
    #[must_use]
    pub const fn path_response_frame(challenge_data: [u8; PATH_VALIDATION_DATA_LEN]) -> QuicFrame {
        QuicFrame::PathResponse {
            data: challenge_data,
        }
    }

    /// Commit a validated migration.
    pub fn commit_migration(
        &mut self,
        cx: &Cx,
        path_id: AtpPathId,
        now_micros: u64,
    ) -> Result<PathMigrationRecord, AtpQuicConnectionError> {
        checkpoint(cx)?;
        let record = self.path_manager.commit_migration(path_id, now_micros)?;
        self.pending_challenges.remove(&path_id);
        self.trace_record(MigrationTraceEvent::Committed, &record);
        Ok(record)
    }

    /// Reject a pending migration attempt.
    pub fn reject_migration(
        &mut self,
        cx: &Cx,
        path_id: AtpPathId,
        now_micros: u64,
    ) -> Result<PathMigrationRecord, AtpQuicConnectionError> {
        checkpoint(cx)?;
        self.pending_challenges.remove(&path_id);
        let record = self.path_manager.reject_migration(
            path_id,
            PathMigrationStatus::Rejected,
            now_micros,
        )?;
        self.trace_record(MigrationTraceEvent::Rejected, &record);
        Ok(record)
    }

    /// Expire every outstanding validation whose deadline has passed.
    pub fn expire_validations(
        &mut self,
        cx: &Cx,
        now_micros: u64,
    ) -> Result<Vec<PathMigrationRecord>, AtpQuicConnectionError> {
        checkpoint(cx)?;
        let expired: Vec<AtpPathId> = self
            .pending_challenges
            .iter()
            .filter_map(|(path_id, challenge)| challenge.is_expired(now_micros).then_some(*path_id))
            .collect();

        let mut records = Vec::with_capacity(expired.len());
        for path_id in expired {
            self.pending_challenges.remove(&path_id);
            let record = self.path_manager.reject_migration(
                path_id,
                PathMigrationStatus::TimedOut,
                now_micros,
            )?;
            self.trace_record(MigrationTraceEvent::Rejected, &record);
            records.push(record);
        }
        Ok(records)
    }

    /// Request a QUIC key update.
    pub fn request_key_update(&mut self, cx: &Cx) -> Result<u8, AtpQuicConnectionError> {
        checkpoint(cx)?;
        if self.key_update_pending {
            return Err(AtpQuicConnectionError::KeyUpdateAlreadyPending);
        }
        self.key_update_pending = true;
        Ok(self.key_phase ^ 1)
    }

    /// Commit a pending QUIC key update and trace the new key phase.
    pub fn commit_key_update(&mut self, cx: &Cx) -> Result<u8, AtpQuicConnectionError> {
        checkpoint(cx)?;
        if !self.key_update_pending {
            return Err(AtpQuicConnectionError::NoPendingKeyUpdate);
        }
        self.key_phase ^= 1;
        self.key_update_pending = false;
        self.trace_key_update();
        Ok(self.key_phase)
    }

    fn make_challenge(&self, path_id: AtpPathId, now_micros: u64) -> PathValidationChallenge {
        let seed = self.config.validation_secret
            ^ path_id.value()
            ^ now_micros
            ^ self.connection_ids.active_sequence();
        PathValidationChallenge {
            path_id,
            data: splitmix64(seed).to_be_bytes(),
            issued_at_micros: now_micros,
            expires_at_micros: now_micros.saturating_add(self.config.validation_timeout_micros),
        }
    }

    fn trace_record(&mut self, event: MigrationTraceEvent, record: &PathMigrationRecord) {
        let trace = MigrationTraceEntry {
            sequence: self.next_trace_sequence,
            event,
            old_path_id: record.old_path_id(),
            new_path_id: record.candidate().id(),
            key_phase: self.key_phase,
            outcome: record.status(),
            verifier_context: record.candidate().verifier_context().to_owned(),
            replay_pointer: format!(
                "atp.quic.migration.{}.{}",
                record.sequence(),
                record.candidate().id().value()
            ),
        };
        self.next_trace_sequence = self.next_trace_sequence.saturating_add(1);
        self.traces.push(trace);
    }

    fn trace_key_update(&mut self) {
        let active = self.path_manager.active_path();
        let trace = MigrationTraceEntry {
            sequence: self.next_trace_sequence,
            event: MigrationTraceEvent::KeyUpdate,
            old_path_id: active.id(),
            new_path_id: active.id(),
            key_phase: self.key_phase,
            outcome: PathMigrationStatus::Committed,
            verifier_context: active.verifier_context().to_owned(),
            replay_pointer: format!(
                "atp.quic.key_update.{}.{}",
                self.next_trace_sequence, self.key_phase
            ),
        };
        self.next_trace_sequence = self.next_trace_sequence.saturating_add(1);
        self.traces.push(trace);
    }
}

/// Errors returned by ATP QUIC connection migration state.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AtpQuicConnectionError {
    /// Operation was cancelled at a `Cx` checkpoint.
    #[error("operation cancelled")]
    Cancelled,
    /// Connection ID length was invalid.
    #[error("invalid connection id length: {length}")]
    InvalidConnectionIdLength {
        /// Observed length.
        length: usize,
    },
    /// Active connection ID limit is too small for migration.
    #[error("connection id limit too small: {limit}")]
    ConnectionIdLimitTooSmall {
        /// Advertised limit.
        limit: usize,
    },
    /// Connection ID sequence is unknown.
    #[error("unknown connection id sequence: {sequence}")]
    UnknownConnectionId {
        /// Sequence number.
        sequence: u64,
    },
    /// Connection ID sequence was already retired.
    #[error("connection id sequence is retired: {sequence}")]
    ConnectionIdRetired {
        /// Sequence number.
        sequence: u64,
    },
    /// The active connection ID cannot be retired.
    #[error("cannot retire active connection id: {sequence}")]
    CannotRetireActiveConnectionId {
        /// Sequence number.
        sequence: u64,
    },
    /// No inactive connection ID can be retired to honor the active limit.
    #[error("no retirable connection id")]
    NoRetirableConnectionId,
    /// Active migration is disabled by peer transport parameters.
    #[error("active migration disabled by transport parameters")]
    ActiveMigrationDisabled,
    /// Candidate endpoints did not represent NAT rebinding.
    #[error("candidate is not a NAT rebinding of the active path")]
    NotNatRebinding,
    /// No challenge is pending for this path.
    #[error("no pending path validation challenge for path {path_id:?}")]
    NoPendingChallenge {
        /// Path identifier.
        path_id: AtpPathId,
    },
    /// Path manager rejected the operation.
    #[error(transparent)]
    Path(#[from] PathMigrationError),
    /// A key update is already pending.
    #[error("key update already pending")]
    KeyUpdateAlreadyPending,
    /// No key update is pending.
    #[error("no pending key update")]
    NoPendingKeyUpdate,
}

fn checkpoint(cx: &Cx) -> Result<(), AtpQuicConnectionError> {
    cx.checkpoint()
        .map_err(|_| AtpQuicConnectionError::Cancelled)
}

fn splitmix64(mut value: u64) -> u64 {
    value = value.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut mixed = value;
    mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    mixed ^ (mixed >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::atp::path::{AtpPathEndpoints, PathContinuity};
    use crate::net::atp::stun::{EndpointFamily, ObservedEndpoint};
    use crate::types::CancelKind;

    fn endpoint(address: &str, port: u16) -> ObservedEndpoint {
        ObservedEndpoint::new(EndpointFamily::Ipv4, address, port).expect("endpoint")
    }

    fn candidate(id: u64, remote_port: u16, rank: u8) -> AtpPathCandidate {
        AtpPathCandidate::new(
            AtpPathId::new(id),
            AtpPathEndpoints::new(
                endpoint("10.0.0.2", 40_000),
                endpoint("198.51.100.10", remote_port),
            ),
            rank,
            100 + id,
            format!("path-{id}"),
            format!("verifier-{id}"),
        )
        .expect("candidate")
    }

    fn state() -> AtpQuicConnectionState {
        AtpQuicConnectionState::new(
            vec![0xaa, 0xbb, 0xcc, 0xdd],
            [7; STATELESS_RESET_TOKEN_LEN],
            candidate(0, 50_000, 10),
            AtpQuicConnectionConfig {
                validation_secret: 0x1234_5678,
                ..AtpQuicConnectionConfig::default()
            },
        )
        .expect("state")
    }

    #[test]
    fn connection_id_issuance_and_retirement_enforce_active_limit() {
        let initial = QuicConnectionId::new(0, vec![1, 2, 3, 4], [1; 16], 0).expect("cid");
        let mut registry = ConnectionIdRegistry::new(initial, 2).expect("registry");

        let first = registry.issue(vec![5, 6, 7, 8], [2; 16], 1).expect("first");
        let second = registry
            .issue(vec![9, 10, 11, 12], [3; 16], 2)
            .expect("second");

        assert_eq!(first.sequence(), 1);
        assert_eq!(second.sequence(), 2);
        assert_eq!(registry.active().map(QuicConnectionId::sequence), Some(0));
        assert!(registry.retired_ids().contains(&1));
        assert!(registry.active_ids().contains_key(&0));
        assert!(registry.active_ids().contains_key(&2));

        let err = registry
            .retire(registry.active_sequence())
            .expect_err("active cid cannot retire");
        assert_eq!(
            err,
            AtpQuicConnectionError::CannotRetireActiveConnectionId { sequence: 0 }
        );
    }

    #[test]
    fn active_connection_id_absence_returns_none_instead_of_panicking() {
        let initial = QuicConnectionId::new(0, vec![1, 2, 3, 4], [1; 16], 0).expect("cid");
        let mut registry = ConnectionIdRegistry::new(initial, 2).expect("registry");

        registry.active_sequence = 42;

        assert_eq!(registry.active(), None);
    }

    #[test]
    fn path_challenge_response_validates_before_commit() {
        let cx = Cx::for_testing();
        let mut state = state();
        let target = candidate(1, 50_100, 1);

        let challenge = state
            .request_migration(&cx, target, PathMigrationReason::ActiveMigration, 1_000)
            .expect("challenge");
        assert_eq!(challenge.path_id(), AtpPathId::new(1));
        assert!(matches!(challenge.frame(), QuicFrame::PathChallenge { .. }));

        let err = state
            .commit_migration(&cx, AtpPathId::new(1), 1_100)
            .expect_err("commit before validation");
        assert_eq!(
            err,
            AtpQuicConnectionError::Path(PathMigrationError::NotValidated)
        );

        let outcome = state
            .on_path_response(&cx, AtpPathId::new(1), challenge.data(), 1_200)
            .expect("response");
        assert_eq!(outcome, PathValidationOutcome::Validated);

        let committed = state
            .commit_migration(&cx, AtpPathId::new(1), 1_300)
            .expect("commit");
        assert_eq!(committed.status(), PathMigrationStatus::Committed);
        assert_eq!(committed.continuity(), PathContinuity::VERIFIED);
        assert_eq!(state.path_manager().active_path_id(), AtpPathId::new(1));

        let trace = state.migration_traces().last().expect("trace");
        assert_eq!(trace.old_path_id(), AtpPathId::INITIAL);
        assert_eq!(trace.new_path_id(), AtpPathId::new(1));
        assert_eq!(trace.key_phase(), 0);
        assert!(trace.replay_pointer().contains("atp.quic.migration"));
    }

    #[test]
    fn path_response_mismatch_rejects_candidate() {
        let cx = Cx::for_testing();
        let mut state = state();
        let challenge = state
            .request_migration(
                &cx,
                candidate(2, 50_200, 1),
                PathMigrationReason::RelayFallback,
                10,
            )
            .expect("challenge");
        let mut wrong = challenge.data();
        wrong[0] ^= 0xff;

        let outcome = state
            .on_path_response(&cx, AtpPathId::new(2), wrong, 20)
            .expect("response");
        assert_eq!(outcome, PathValidationOutcome::Rejected);
        assert!(state.pending_challenges().is_empty());
        assert_eq!(
            state.path_manager().history()[0].status(),
            PathMigrationStatus::Rejected
        );
    }

    #[test]
    fn validation_timeout_rejects_pending_migration() {
        let cx = Cx::for_testing();
        let mut state = state();
        let challenge = state
            .request_migration(
                &cx,
                candidate(3, 50_300, 1),
                PathMigrationReason::MobileChurn,
                10,
            )
            .expect("challenge");

        let expired = state
            .expire_validations(&cx, challenge.expires_at_micros())
            .expect("expire");
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].status(), PathMigrationStatus::TimedOut);
        assert!(state.pending_challenges().is_empty());
    }

    #[test]
    fn nat_rebinding_preserves_verified_transfer_continuity() {
        let cx = Cx::for_testing();
        let mut state = state();
        let challenge = state
            .observe_nat_rebinding(&cx, candidate(4, 55_000, 1), 2_000)
            .expect("nat rebinding challenge");
        assert_eq!(
            state.path_manager().pending()[&AtpPathId::new(4)].reason(),
            PathMigrationReason::NatRebinding
        );

        assert_eq!(
            state
                .on_path_response(&cx, AtpPathId::new(4), challenge.data(), 2_100)
                .expect("response"),
            PathValidationOutcome::Validated
        );
        let committed = state
            .commit_migration(&cx, AtpPathId::new(4), 2_200)
            .expect("commit");
        assert!(committed.continuity().is_verified());
        assert_eq!(committed.candidate().verifier_context(), "verifier-4");
    }

    #[test]
    fn preferred_address_key_update_and_candidate_race_are_observable() {
        let cx = Cx::for_testing();
        let mut state = state();
        let best = state
            .path_manager()
            .race_candidates(vec![candidate(5, 50_500, 20), candidate(6, 50_600, 5)])
            .expect("winner");
        assert_eq!(best.id(), AtpPathId::new(6));

        let challenge = state
            .request_migration(&cx, best, PathMigrationReason::PreferredAddress, 3_000)
            .expect("challenge");
        state
            .on_path_response(&cx, AtpPathId::new(6), challenge.data(), 3_100)
            .expect("response");
        state
            .commit_migration(&cx, AtpPathId::new(6), 3_200)
            .expect("commit");

        assert_eq!(state.request_key_update(&cx).expect("request"), 1);
        assert_eq!(state.commit_key_update(&cx).expect("commit"), 1);
        let key_trace = state.migration_traces().last().expect("key trace");
        assert_eq!(key_trace.event(), MigrationTraceEvent::KeyUpdate);
        assert_eq!(key_trace.key_phase(), 1);
        assert_eq!(key_trace.new_path_id(), AtpPathId::new(6));
    }

    #[test]
    fn cancellation_checkpoint_blocks_migration_request() {
        let cx = Cx::for_testing();
        cx.cancel_with(CancelKind::User, Some("test cancel"));
        let mut state = state();
        let err = state
            .request_migration(
                &cx,
                candidate(7, 50_700, 1),
                PathMigrationReason::ActiveMigration,
                1,
            )
            .expect_err("cancelled");
        assert_eq!(err, AtpQuicConnectionError::Cancelled);
    }

    #[test]
    fn active_migration_disabled_still_allows_nat_rebinding_validation() {
        let cx = Cx::for_testing();
        let mut state = AtpQuicConnectionState::new(
            vec![0xaa, 0xbb, 0xcc, 0xdd],
            [7; STATELESS_RESET_TOKEN_LEN],
            candidate(0, 50_000, 10),
            AtpQuicConnectionConfig {
                active_migration_disabled: true,
                ..AtpQuicConnectionConfig::default()
            },
        )
        .expect("state");

        let err = state
            .request_migration(
                &cx,
                candidate(8, 50_800, 1),
                PathMigrationReason::ActiveMigration,
                1,
            )
            .expect_err("active migration disabled");
        assert_eq!(err, AtpQuicConnectionError::ActiveMigrationDisabled);

        state
            .observe_nat_rebinding(&cx, candidate(9, 50_900, 1), 2)
            .expect("nat rebinding allowed");
    }
}
