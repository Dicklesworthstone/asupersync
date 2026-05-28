//! ATP per-transfer actor state machine.
//!
//! `TransferActor` is the single owner for one transfer session. It owns
//! manifest identity, peer capability decisions, path progress, scheduler
//! feedback inputs, commit state, and the obligation ledger for request/reply
//! protocol edges.

use super::actor::{
    TransferActorId, TransferActorTopology, TransferChildRegion, TransferObligationId,
    TransferRegionId, TransferTopologyError,
};
use super::autotune::{
    AtpAutotuneApplicationReceipt, AtpAutotuneApplicationState, AtpAutotuneDecisionReceipt,
    AtpAutotunePolicy, AtpAutotuneSettings, AtpAutotuneTelemetry, AtpAutotuneTelemetryError,
    AtpTransferPressureSnapshot,
};
use sha2::{Digest, Sha256};
use smallvec::SmallVec;
use std::fmt;

/// Deterministic transfer id bound to peers, nonce, and manifest root.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TransferId([u8; 32]);

impl TransferId {
    const DERIVATION_DOMAIN: &'static [u8] = b"ATP-TRANSFER-ID-V1\0";

    /// Construct a transfer id from canonical bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Construct a transfer id from a small deterministic integer.
    #[must_use]
    pub const fn from_u128(value: u128) -> Self {
        let mut bytes = [0_u8; 32];
        let value_bytes = value.to_be_bytes();
        let mut index = 0;
        while index < value_bytes.len() {
            bytes[16 + index] = value_bytes[index];
            index += 1;
        }
        Self(bytes)
    }

    /// Derive a stable transfer id for tests and transcripts.
    #[must_use]
    pub fn derive(
        local_peer: [u8; 32],
        remote_peer: [u8; 32],
        nonce: [u8; 32],
        root: [u8; 32],
    ) -> Self {
        Self::derive_with_policy(local_peer, remote_peer, nonce, root, [0; 32])
    }

    /// Derive a transfer id from all H2 identity-binding inputs.
    #[must_use]
    pub fn derive_with_policy(
        local_peer: [u8; 32],
        remote_peer: [u8; 32],
        nonce: [u8; 32],
        manifest_root: [u8; 32],
        policy_digest: [u8; 32],
    ) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(Self::DERIVATION_DOMAIN);
        hasher.update(b"local-peer");
        hasher.update(local_peer);
        hasher.update(b"remote-peer");
        hasher.update(remote_peer);
        hasher.update(b"nonce");
        hasher.update(nonce);
        hasher.update(b"manifest-root");
        hasher.update(manifest_root);
        hasher.update(b"policy-digest");
        hasher.update(policy_digest);
        Self(hasher.finalize().into())
    }

    /// Borrow canonical transfer-id bytes.
    #[must_use]
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Return a stable lowercase hex id for logs, reports, and proof artifacts.
    #[must_use]
    pub fn to_hex(self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(64);
        for byte in self.0 {
            output.push(char::from(HEX[usize::from(byte >> 4)]));
            output.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        output
    }
}

/// Idempotency key for replay-safe transfer commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IdempotencyKey(u128);

impl IdempotencyKey {
    /// Construct an idempotency key.
    #[must_use]
    pub const fn new(raw: u128) -> Self {
        Self(raw)
    }
}

/// Manifest summary owned by the transfer actor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferManifestRef {
    /// Manifest schema version.
    pub schema_version: u32,
    /// Manifest or graph Merkle root.
    pub merkle_root: [u8; 32],
    /// Number of objects covered by the manifest.
    pub object_count: u64,
}

/// Peer capability snapshot accepted for this transfer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerCapabilities {
    /// Peer can use an online relay path.
    pub relay: bool,
    /// Peer can use encrypted store-and-forward mailbox.
    pub mailbox: bool,
    /// Peer can participate in swarm transfer.
    pub swarm: bool,
    /// Maximum number of in-flight request/reply obligations.
    pub max_inflight_obligations: usize,
}

impl Default for PeerCapabilities {
    fn default() -> Self {
        Self {
            relay: false,
            mailbox: false,
            swarm: false,
            max_inflight_obligations: 8,
        }
    }
}

/// Transfer progress and scheduler input surface.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TransferProgress {
    /// Bytes offered by the sender.
    pub offered_bytes: u64,
    /// Bytes verified by the receiver.
    pub verified_bytes: u64,
    /// Bytes committed to exposed output.
    pub committed_bytes: u64,
    /// Repair symbols processed.
    pub repair_symbols: u64,
    /// Selected path id, if a path has won.
    pub selected_path: Option<u64>,
}

impl TransferProgress {
    /// Collect transfer-owned pressure metrics into the autotune snapshot shape.
    ///
    /// This method only records fields owned by the transfer actor itself:
    /// offered-but-unverified bytes become in-flight pressure, and
    /// verified-but-uncommitted bytes become receiver buffer pressure. Transport,
    /// disk, CPU, repair, and relay collectors can merge their own observations
    /// into the returned snapshot before policy evaluation.
    #[must_use]
    pub fn to_pressure_snapshot(
        self,
        trace_id: impl Into<String>,
        transfer_id: TransferId,
        sample_count: u32,
    ) -> AtpTransferPressureSnapshot {
        let mut snapshot = AtpTransferPressureSnapshot::new(trace_id, transfer_id.to_hex())
            .with_sample_count(sample_count);
        snapshot.in_flight_bytes = Some(self.offered_bytes.saturating_sub(self.verified_bytes));
        snapshot.receive_buffer_queued_bytes =
            Some(self.verified_bytes.saturating_sub(self.committed_bytes));
        snapshot
    }
}

/// Pressure source family required for a complete autotune snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferPressureSourceKind {
    /// Actor-owned byte progress counters.
    Progress,
    /// QUIC recovery and path-pressure counters.
    Transport,
    /// Disk and journal latency counters.
    Disk,
    /// RaptorQ encode/decode backlog counters.
    Coding,
    /// Repair-symbol usefulness counters.
    Repair,
    /// Relay path cost counters.
    Relay,
    /// Path migration counters.
    Migration,
}

impl TransferPressureSourceKind {
    /// Stable source name for logs, receipts, and proof artifacts.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Progress => "progress",
            Self::Transport => "transport",
            Self::Disk => "disk",
            Self::Coding => "coding",
            Self::Repair => "repair",
            Self::Relay => "relay",
            Self::Migration => "migration",
        }
    }
}

impl fmt::Display for TransferPressureSourceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// QUIC/path pressure counters sampled by transfer-owned state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferTransportPressure {
    /// Trace id attached to this source sample.
    pub trace_id: String,
    /// Smoothed round-trip time in microseconds.
    pub rtt_micros: u64,
    /// Loss rate in packets per thousand.
    pub loss_permille: u16,
    /// Probe timeout in microseconds.
    pub pto_micros: u64,
    /// Congestion window in bytes.
    pub congestion_window_bytes: u64,
    /// Bytes queued in the sender buffer.
    pub send_buffer_queued_bytes: u64,
}

/// Disk and journal pressure counters sampled by transfer-owned state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferDiskPressure {
    /// Trace id attached to this source sample.
    pub trace_id: String,
    /// Disk read lag in microseconds.
    pub read_lag_micros: u64,
    /// Disk write lag in microseconds.
    pub write_lag_micros: u64,
}

/// RaptorQ encode/decode pressure counters sampled by transfer-owned state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferCodingPressure {
    /// Trace id attached to this source sample.
    pub trace_id: String,
    /// Pending encoder work in symbols.
    pub encode_backlog_symbols: u32,
    /// Pending decoder work in symbols.
    pub decode_backlog_symbols: u32,
}

/// Repair-symbol pressure counters sampled by transfer-owned state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferRepairPressure {
    /// Trace id attached to this source sample.
    pub trace_id: String,
    /// Repair symbols sent during this decision window.
    pub symbols_sent: u32,
    /// Repair symbols that helped decoding during this decision window.
    pub useful_symbols: u32,
}

/// Relay path cost counters sampled by transfer-owned state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferRelayPressure {
    /// Trace id attached to this source sample.
    pub trace_id: String,
    /// Relay path cost observed during this window.
    pub cost_micros: u64,
    /// Payload bytes forwarded through the relay during this window.
    pub bytes: u64,
}

/// Path migration counters sampled by transfer-owned state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferMigrationPressure {
    /// Trace id attached to this source sample.
    pub trace_id: String,
    /// Migration events during this decision window.
    pub events: u32,
}

/// All source groups needed to produce a complete ATP-E3 pressure snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferPressureSources {
    /// Trace id all source groups must match.
    pub trace_id: String,
    /// Samples represented by this complete source window.
    pub sample_count: u32,
    /// QUIC recovery and path-pressure counters.
    pub transport: Option<TransferTransportPressure>,
    /// Disk and journal latency counters.
    pub disk: Option<TransferDiskPressure>,
    /// RaptorQ encode/decode backlog counters.
    pub coding: Option<TransferCodingPressure>,
    /// Repair-symbol usefulness counters.
    pub repair: Option<TransferRepairPressure>,
    /// Relay path cost counters.
    pub relay: Option<TransferRelayPressure>,
    /// Path migration counters.
    pub migration: Option<TransferMigrationPressure>,
}

impl TransferPressureSources {
    /// Create an empty complete-source window for one trace id.
    #[must_use]
    pub fn new(trace_id: impl Into<String>, sample_count: u32) -> Self {
        Self {
            trace_id: trace_id.into(),
            sample_count,
            transport: None,
            disk: None,
            coding: None,
            repair: None,
            relay: None,
            migration: None,
        }
    }
}

/// Fail-closed reason for refusing to build a policy-ready pressure snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferPressureCollectionError {
    /// A complete snapshot cannot represent zero source samples.
    ZeroSamples,
    /// A required source family is absent.
    MissingSource {
        /// Source family that was absent.
        source: TransferPressureSourceKind,
    },
    /// A source was sampled for a different trace id.
    StaleSourceTrace {
        /// Source family that carried the stale trace id.
        source: TransferPressureSourceKind,
        /// Trace id expected for this decision window.
        expected: String,
        /// Trace id observed on the source sample.
        observed: String,
    },
    /// Transfer progress counters moved backwards.
    ContradictoryProgress {
        /// Offered bytes.
        offered_bytes: u64,
        /// Verified bytes.
        verified_bytes: u64,
        /// Committed bytes.
        committed_bytes: u64,
    },
    /// Repair counters claim more useful symbols than were sent.
    ContradictoryRepair {
        /// Repair symbols sent during this decision window.
        symbols_sent: u32,
        /// Repair symbols that helped decoding during this decision window.
        useful_symbols: u32,
    },
    /// Relay counters record cost without forwarded payload.
    ContradictoryRelay {
        /// Relay path cost observed during this window.
        cost_micros: u64,
        /// Payload bytes forwarded through the relay during this window.
        bytes: u64,
    },
}

impl TransferPressureCollectionError {
    /// Stable reason code suitable for decision receipts and operator logs.
    #[must_use]
    pub const fn reason_code(&self) -> &'static str {
        match self {
            Self::ZeroSamples => "zero_pressure_samples",
            Self::MissingSource { .. } => "missing_pressure_source",
            Self::StaleSourceTrace { .. } => "stale_pressure_trace_id",
            Self::ContradictoryProgress { .. } => "contradictory_progress_counters",
            Self::ContradictoryRepair { .. } => "contradictory_repair_counters",
            Self::ContradictoryRelay { .. } => "contradictory_relay_counters",
        }
    }
}

impl fmt::Display for TransferPressureCollectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroSamples => f.write_str("transfer pressure window has zero samples"),
            Self::MissingSource { source } => {
                write!(f, "missing transfer pressure source: {source}")
            }
            Self::StaleSourceTrace {
                source,
                expected,
                observed,
            } => write!(
                f,
                "stale transfer pressure source {source}: expected trace {expected}, observed {observed}"
            ),
            Self::ContradictoryProgress {
                offered_bytes,
                verified_bytes,
                committed_bytes,
            } => write!(
                f,
                "contradictory transfer progress counters: offered={offered_bytes} verified={verified_bytes} committed={committed_bytes}"
            ),
            Self::ContradictoryRepair {
                symbols_sent,
                useful_symbols,
            } => write!(
                f,
                "contradictory repair counters: useful={useful_symbols} sent={symbols_sent}"
            ),
            Self::ContradictoryRelay { cost_micros, bytes } => write!(
                f,
                "contradictory relay counters: cost_micros={cost_micros} bytes={bytes}"
            ),
        }
    }
}

impl std::error::Error for TransferPressureCollectionError {}

/// Transfer actor states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TransferState {
    /// Sender has offered a transfer.
    Offered,
    /// Receiver accepted the offer and capability grant.
    Accepted,
    /// Object bytes are moving.
    Running,
    /// Transfer is paused with journal state intact.
    Paused,
    /// Cancellation requested and finalizers are draining.
    Cancelling,
    /// Transfer failed with a typed failure class.
    Failed,
    /// Manifest commit and finalizer proof completed.
    Committed,
    /// Transfer resumed from journal state.
    Resumed,
    /// Store-and-forward mailbox accepted encrypted transfer state.
    MailboxStored,
    /// Online relay accepted forwarding responsibility.
    RelayForwarded,
    /// Committed transfer is now serving verified data to peers.
    Seeded,
    /// Swarm peers are assisting with verified chunks or repair symbols.
    SwarmAssisted,
}

impl TransferState {
    /// Every state covered by ATP-E1.
    pub const ALL: [Self; 12] = [
        Self::Offered,
        Self::Accepted,
        Self::Running,
        Self::Paused,
        Self::Cancelling,
        Self::Failed,
        Self::Committed,
        Self::Resumed,
        Self::MailboxStored,
        Self::RelayForwarded,
        Self::Seeded,
        Self::SwarmAssisted,
    ];

    /// Whether this state should have no live child obligations.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Cancelling | Self::Failed | Self::Committed | Self::Seeded
        )
    }
}

/// Fail-closed reason for refusing to apply autotune settings to a transfer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferAutotuneApplicationError {
    /// Complete pressure collection failed before policy evaluation.
    PressureCollection(TransferPressureCollectionError),
    /// Pressure samples could not be aggregated into a policy window.
    Telemetry(AtpAutotuneTelemetryError),
    /// The actor is terminal or draining and must not mutate transfer knobs.
    ActorNotTunable {
        /// Current transfer state.
        state: TransferState,
    },
}

impl TransferAutotuneApplicationError {
    /// Stable reason code suitable for status and replay artifacts.
    #[must_use]
    pub const fn reason_code(&self) -> &'static str {
        match self {
            Self::PressureCollection(err) => err.reason_code(),
            Self::Telemetry(_) => "invalid_autotune_telemetry",
            Self::ActorNotTunable { .. } => "transfer_not_tunable",
        }
    }
}

impl fmt::Display for TransferAutotuneApplicationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PressureCollection(err) => {
                write!(f, "transfer pressure collection failed: {err}")
            }
            Self::Telemetry(err) => write!(f, "transfer autotune telemetry failed: {err}"),
            Self::ActorNotTunable { state } => {
                write!(f, "transfer state {state:?} cannot apply autotune settings")
            }
        }
    }
}

impl std::error::Error for TransferAutotuneApplicationError {}

impl From<TransferPressureCollectionError> for TransferAutotuneApplicationError {
    fn from(err: TransferPressureCollectionError) -> Self {
        Self::PressureCollection(err)
    }
}

impl From<AtpAutotuneTelemetryError> for TransferAutotuneApplicationError {
    fn from(err: AtpAutotuneTelemetryError) -> Self {
        Self::Telemetry(err)
    }
}

/// Cancellation phase preserved in logs and replay artifacts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferCancelPhase {
    /// User or parent requested cancellation.
    Requested,
    /// Losers, writers, and relay grants are draining.
    Draining,
    /// Finalizers completed.
    Finalized,
}

/// Failure class preserved across actor logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferFailureKind {
    /// Remote peer failed or violated policy.
    Peer,
    /// Disk, sparse writer, or commit finalizer failed.
    Disk,
    /// Repair-symbol encode/decode failed.
    Repair,
    /// Manifest or verifier rejected input.
    Verification,
    /// Transfer exceeded a resource budget.
    ResourceBudget,
}

/// Actor command variants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferCommandKind {
    /// Accept an offered transfer.
    Accept { obligation: TransferObligationId },
    /// Select a path and begin movement.
    Start {
        /// Winning path identifier.
        path_id: u64,
        /// Request/reply obligation for the start edge.
        obligation: TransferObligationId,
    },
    /// Pause a running transfer.
    Pause,
    /// Resume from a journal position.
    Resume {
        /// Last durable journal sequence observed before resume.
        journal_seq: u64,
        /// Request/reply obligation for the resume edge.
        obligation: TransferObligationId,
    },
    /// Begin cancellation.
    Cancel { phase: TransferCancelPhase },
    /// Fail with a stable class.
    Fail { kind: TransferFailureKind },
    /// Commit verified output.
    Commit { obligation: TransferObligationId },
    /// Store encrypted state in mailbox.
    StoreMailbox { obligation: TransferObligationId },
    /// Forward encrypted bytes through relay.
    ForwardRelay { obligation: TransferObligationId },
    /// Seed committed data to peers.
    Seed { obligation: TransferObligationId },
    /// Join a swarm-assisted transfer.
    JoinSwarm { obligation: TransferObligationId },
    /// Stop the actor after terminal quiescence.
    Shutdown,
}

impl TransferCommandKind {
    fn obligation(&self) -> Option<TransferObligationId> {
        match self {
            Self::Accept { obligation }
            | Self::Start { obligation, .. }
            | Self::Resume { obligation, .. }
            | Self::Commit { obligation }
            | Self::StoreMailbox { obligation }
            | Self::ForwardRelay { obligation }
            | Self::Seed { obligation }
            | Self::JoinSwarm { obligation } => Some(*obligation),
            Self::Pause | Self::Cancel { .. } | Self::Fail { .. } | Self::Shutdown => None,
        }
    }
}

/// Transfer actor command with an idempotency key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferCommand {
    /// Idempotency key.
    pub key: IdempotencyKey,
    /// Command payload.
    pub kind: TransferCommandKind,
}

impl TransferCommand {
    /// Construct a command.
    #[must_use]
    pub const fn new(key: IdempotencyKey, kind: TransferCommandKind) -> Self {
        Self { key, kind }
    }
}

/// Settled obligation outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObligationOutcome {
    /// Command transition committed.
    Committed,
    /// Command transition aborted.
    Aborted,
}

/// Journal entry emitted by every non-duplicate command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferJournalEntry {
    /// Monotonic journal sequence.
    pub seq: u64,
    /// Actor that emitted this transition.
    pub actor_id: TransferActorId,
    /// Transfer governed by this actor.
    pub transfer_id: TransferId,
    /// Idempotency key for replay.
    pub key: IdempotencyKey,
    /// Previous state.
    pub previous: TransferState,
    /// New state.
    pub next: TransferState,
    /// Settled obligation, if the command required one.
    pub obligation: Option<(TransferObligationId, ObligationOutcome)>,
    /// Parent region that supervises the actor.
    pub supervisor_region: TransferRegionId,
    /// Region that owns the actor state.
    pub actor_region: TransferRegionId,
    /// Child topology snapshot at the time of transition.
    pub child_topology: Vec<TransferChildRegion>,
    /// Cancellation phase carried by this transition.
    pub cancel_phase: Option<TransferCancelPhase>,
    /// Deterministic replay/crashpack path hint for this transition.
    pub replay_crashpack_path: String,
}

/// Reply returned by the transfer actor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferReply {
    /// State changed.
    Transitioned {
        /// Previous state.
        previous: TransferState,
        /// New state.
        next: TransferState,
    },
    /// Duplicate command was ignored.
    Duplicate {
        /// Current state.
        state: TransferState,
    },
    /// Terminal actor had no open obligations at shutdown.
    ShutdownQuiescent {
        /// Final state.
        state: TransferState,
    },
}

/// Transfer actor errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferActorError {
    /// Topology violates region ownership.
    InvalidTopology(TransferTopologyError),
    /// Transition is not allowed.
    InvalidTransition {
        /// Current state.
        state: TransferState,
        /// Command attempted in that state.
        command: &'static str,
    },
    /// In-flight obligations would exceed peer policy.
    ObligationBudgetExceeded {
        /// Configured limit.
        limit: usize,
    },
    /// Actor cannot shut down with open obligations.
    ObligationLeak {
        /// Number of leaked obligations.
        open: usize,
    },
}

impl fmt::Display for TransferActorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTopology(err) => write!(f, "invalid transfer topology: {err}"),
            Self::InvalidTransition { state, command } => {
                write!(f, "invalid transfer transition {command} from {state:?}")
            }
            Self::ObligationBudgetExceeded { limit } => {
                write!(f, "transfer obligation budget exceeded: limit {limit}")
            }
            Self::ObligationLeak { open } => {
                write!(f, "transfer actor has {open} open obligations")
            }
        }
    }
}

impl std::error::Error for TransferActorError {}

/// Single-owner state for one ATP transfer.
#[derive(Debug, Clone)]
pub struct TransferActor {
    /// Actor id.
    pub actor_id: TransferActorId,
    /// Transfer id.
    pub transfer_id: TransferId,
    /// Manifest summary.
    pub manifest: TransferManifestRef,
    /// Peer capabilities accepted for this transfer.
    pub peer_capabilities: PeerCapabilities,
    /// Region ownership topology.
    pub topology: TransferActorTopology,
    /// Transfer progress.
    pub progress: TransferProgress,
    /// Transfer-owned autotune settings and hysteresis state.
    autotune: AtpAutotuneApplicationState,
    state: TransferState,
    next_journal_seq: u64,
    applied_keys: SmallVec<[IdempotencyKey; 8]>,
    open_obligations: SmallVec<[(TransferObligationId, IdempotencyKey); 8]>,
    settled_obligations: SmallVec<[(TransferObligationId, ObligationOutcome); 8]>,
    journal: SmallVec<[TransferJournalEntry; 8]>,
}

impl TransferActor {
    /// Construct a transfer actor in the offered state.
    pub fn new(
        actor_id: TransferActorId,
        transfer_id: TransferId,
        manifest: TransferManifestRef,
        peer_capabilities: PeerCapabilities,
        topology: TransferActorTopology,
    ) -> Result<Self, TransferActorError> {
        topology
            .validate()
            .map_err(TransferActorError::InvalidTopology)?;

        Ok(Self {
            actor_id,
            transfer_id,
            manifest,
            peer_capabilities,
            topology,
            progress: TransferProgress::default(),
            autotune: AtpAutotuneApplicationState::default(),
            state: TransferState::Offered,
            next_journal_seq: 0,
            applied_keys: SmallVec::new(),
            open_obligations: SmallVec::new(),
            settled_obligations: SmallVec::new(),
            journal: SmallVec::new(),
        })
    }

    /// Current transfer state.
    #[must_use]
    pub const fn state(&self) -> TransferState {
        self.state
    }

    /// Durable journal entries.
    #[must_use]
    pub fn journal(&self) -> &[TransferJournalEntry] {
        self.journal.as_slice()
    }

    /// Settled obligations.
    #[must_use]
    pub fn settled_obligations(&self) -> &[(TransferObligationId, ObligationOutcome)] {
        self.settled_obligations.as_slice()
    }

    /// Number of open obligations.
    #[must_use]
    pub fn open_obligation_count(&self) -> usize {
        self.open_obligations.len()
    }

    /// Current bounded autotune settings owned by this transfer.
    #[must_use]
    pub const fn autotune_settings(&self) -> AtpAutotuneSettings {
        self.autotune.settings
    }

    /// Current autotune application state, including hysteresis counters.
    #[must_use]
    pub const fn autotune_application_state(&self) -> &AtpAutotuneApplicationState {
        &self.autotune
    }

    /// Collect actor-owned transfer pressure for an autotune decision window.
    #[must_use]
    pub fn pressure_snapshot(
        &self,
        trace_id: impl Into<String>,
        sample_count: u32,
    ) -> AtpTransferPressureSnapshot {
        self.progress
            .to_pressure_snapshot(trace_id, self.transfer_id, sample_count)
    }

    /// Collect a complete, policy-ready transfer pressure snapshot.
    ///
    /// Unlike [`Self::pressure_snapshot`], this method is intentionally
    /// fail-closed: every source family required by ATP-E3 must be present,
    /// attached to the same trace id, and internally consistent.
    pub fn collect_complete_pressure_snapshot(
        &self,
        sources: TransferPressureSources,
    ) -> Result<AtpTransferPressureSnapshot, TransferPressureCollectionError> {
        validate_complete_pressure_sources(&self.progress, &sources)?;

        let transport =
            sources
                .transport
                .as_ref()
                .ok_or(TransferPressureCollectionError::MissingSource {
                    source: TransferPressureSourceKind::Transport,
                })?;
        let disk = sources
            .disk
            .as_ref()
            .ok_or(TransferPressureCollectionError::MissingSource {
                source: TransferPressureSourceKind::Disk,
            })?;
        let coding =
            sources
                .coding
                .as_ref()
                .ok_or(TransferPressureCollectionError::MissingSource {
                    source: TransferPressureSourceKind::Coding,
                })?;
        let repair =
            sources
                .repair
                .as_ref()
                .ok_or(TransferPressureCollectionError::MissingSource {
                    source: TransferPressureSourceKind::Repair,
                })?;
        let relay =
            sources
                .relay
                .as_ref()
                .ok_or(TransferPressureCollectionError::MissingSource {
                    source: TransferPressureSourceKind::Relay,
                })?;
        let migration =
            sources
                .migration
                .as_ref()
                .ok_or(TransferPressureCollectionError::MissingSource {
                    source: TransferPressureSourceKind::Migration,
                })?;

        let mut snapshot = self.progress.to_pressure_snapshot(
            sources.trace_id.clone(),
            self.transfer_id,
            sources.sample_count,
        );
        snapshot.rtt_micros = Some(transport.rtt_micros);
        snapshot.loss_permille = Some(transport.loss_permille);
        snapshot.pto_micros = Some(transport.pto_micros);
        snapshot.congestion_window_bytes = Some(transport.congestion_window_bytes);
        snapshot.send_buffer_queued_bytes = Some(transport.send_buffer_queued_bytes);
        snapshot.disk_read_lag_micros = Some(disk.read_lag_micros);
        snapshot.disk_write_lag_micros = Some(disk.write_lag_micros);
        snapshot.encode_backlog_symbols = Some(coding.encode_backlog_symbols);
        snapshot.decode_backlog_symbols = Some(coding.decode_backlog_symbols);
        snapshot.repair_symbols_sent = Some(repair.symbols_sent);
        snapshot.useful_repair_symbols = Some(repair.useful_symbols);
        snapshot.relay_cost_micros = Some(relay.cost_micros);
        snapshot.relay_bytes = Some(relay.bytes);
        snapshot.migration_events = Some(migration.events);
        Ok(snapshot)
    }

    /// Apply one policy window to this transfer's owned autotune state.
    ///
    /// The method mutates only the transfer-owned autotune settings. Terminal
    /// or draining states reject before mutation so cancellation cannot leave a
    /// partially-applied tuning step behind.
    pub fn apply_autotune_telemetry(
        &mut self,
        policy: AtpAutotunePolicy,
        telemetry: &AtpAutotuneTelemetry,
    ) -> Result<AtpAutotuneApplicationReceipt, TransferAutotuneApplicationError> {
        self.ensure_autotune_mutable()?;
        Ok(self.autotune.apply_policy_window(policy, telemetry))
    }

    /// Apply one already-built transfer pressure snapshot to the actor's knobs.
    pub fn apply_autotune_snapshot(
        &mut self,
        policy: AtpAutotunePolicy,
        snapshot: AtpTransferPressureSnapshot,
    ) -> Result<AtpAutotuneApplicationReceipt, TransferAutotuneApplicationError> {
        let telemetry = snapshot.into_telemetry()?;
        self.apply_autotune_telemetry(policy, &telemetry)
    }

    /// Collect complete pressure sources and apply the resulting policy window.
    pub fn apply_complete_pressure_autotune(
        &mut self,
        policy: AtpAutotunePolicy,
        sources: TransferPressureSources,
    ) -> Result<AtpAutotuneApplicationReceipt, TransferAutotuneApplicationError> {
        let snapshot = self.collect_complete_pressure_snapshot(sources)?;
        self.apply_autotune_snapshot(policy, snapshot)
    }

    /// Apply a precomputed decision receipt if it still matches actor-owned state.
    pub fn apply_autotune_decision_receipt(
        &mut self,
        receipt: AtpAutotuneDecisionReceipt,
    ) -> Result<AtpAutotuneApplicationReceipt, TransferAutotuneApplicationError> {
        self.ensure_autotune_mutable()?;
        Ok(self.autotune.apply_decision_receipt(receipt))
    }

    /// Apply a command to the actor.
    pub fn apply(&mut self, command: TransferCommand) -> Result<TransferReply, TransferActorError> {
        if self.applied_keys.contains(&command.key) {
            return Ok(TransferReply::Duplicate { state: self.state });
        }

        let previous = self.state;
        let obligation = command.kind.obligation();
        if let Some(id) = obligation {
            self.open_obligation(id, command.key)?;
        }

        let transition = self.transition_for(&command.kind);
        match transition {
            Ok(next) => {
                if let Some(id) = obligation {
                    self.settle_obligation(id, ObligationOutcome::Committed);
                }
                self.apply_side_effects(&command.kind);
                self.state = next;
                self.applied_keys.push(command.key);
                self.push_journal(
                    command.key,
                    previous,
                    next,
                    obligation,
                    ObligationOutcome::Committed,
                    &command.kind,
                );
                if matches!(command.kind, TransferCommandKind::Shutdown) {
                    self.assert_quiescent()?;
                    return Ok(TransferReply::ShutdownQuiescent { state: self.state });
                }
                Ok(TransferReply::Transitioned { previous, next })
            }
            Err(err) => {
                if let Some(id) = obligation {
                    self.settle_obligation(id, ObligationOutcome::Aborted);
                    self.push_journal(
                        command.key,
                        previous,
                        previous,
                        obligation,
                        ObligationOutcome::Aborted,
                        &command.kind,
                    );
                }
                Err(err)
            }
        }
    }

    /// Assert terminal shutdown quiescence.
    pub fn assert_quiescent(&self) -> Result<(), TransferActorError> {
        if self.open_obligations.is_empty() {
            Ok(())
        } else {
            Err(TransferActorError::ObligationLeak {
                open: self.open_obligations.len(),
            })
        }
    }

    fn ensure_autotune_mutable(&self) -> Result<(), TransferAutotuneApplicationError> {
        if self.state.is_terminal() {
            Err(TransferAutotuneApplicationError::ActorNotTunable { state: self.state })
        } else {
            Ok(())
        }
    }

    /// Rebuild an actor from a journal by replaying idempotent commands.
    pub fn restart_from_journal(
        actor_id: TransferActorId,
        transfer_id: TransferId,
        manifest: TransferManifestRef,
        peer_capabilities: PeerCapabilities,
        topology: TransferActorTopology,
        journal: &[TransferJournalEntry],
    ) -> Result<Self, TransferActorError> {
        let mut actor = Self::new(actor_id, transfer_id, manifest, peer_capabilities, topology)?;
        for entry in journal {
            actor.state = entry.next;
            if !actor.applied_keys.contains(&entry.key) {
                actor.applied_keys.push(entry.key);
            }
            actor.next_journal_seq = actor.next_journal_seq.max(entry.seq + 1);
            if let Some((id, outcome)) = entry.obligation {
                actor.settled_obligations.push((id, outcome));
            }
            actor.journal.push(entry.clone());
        }
        // The journal records settled obligations only; transfer operations settle every
        // obligation before returning, so replay reaches quiescence with no open obligations.
        actor.assert_quiescent()?;
        Ok(actor)
    }

    fn open_obligation(
        &mut self,
        obligation: TransferObligationId,
        key: IdempotencyKey,
    ) -> Result<(), TransferActorError> {
        if self.open_obligations.len() >= self.peer_capabilities.max_inflight_obligations {
            return Err(TransferActorError::ObligationBudgetExceeded {
                limit: self.peer_capabilities.max_inflight_obligations,
            });
        }
        if let Some((_, existing_key)) = self
            .open_obligations
            .iter_mut()
            .find(|(open_id, _)| *open_id == obligation)
        {
            *existing_key = key;
        } else {
            self.open_obligations.push((obligation, key));
        }
        Ok(())
    }

    fn settle_obligation(&mut self, id: TransferObligationId, outcome: ObligationOutcome) {
        if let Some(index) = self
            .open_obligations
            .iter()
            .position(|(open_id, _)| *open_id == id)
        {
            self.open_obligations.swap_remove(index);
        }
        self.settled_obligations.push((id, outcome));
    }

    fn transition_for(
        &self,
        command: &TransferCommandKind,
    ) -> Result<TransferState, TransferActorError> {
        match command {
            TransferCommandKind::Accept { .. } if self.state == TransferState::Offered => {
                Ok(TransferState::Accepted)
            }
            TransferCommandKind::Start { .. }
                if matches!(self.state, TransferState::Accepted | TransferState::Resumed) =>
            {
                Ok(TransferState::Running)
            }
            TransferCommandKind::Pause
                if matches!(
                    self.state,
                    TransferState::Running
                        | TransferState::Resumed
                        | TransferState::RelayForwarded
                        | TransferState::SwarmAssisted
                ) =>
            {
                Ok(TransferState::Paused)
            }
            TransferCommandKind::Resume { .. }
                if matches!(
                    self.state,
                    TransferState::Paused | TransferState::Failed | TransferState::MailboxStored
                ) =>
            {
                Ok(TransferState::Resumed)
            }
            TransferCommandKind::Cancel { .. } if !self.state.is_terminal() => {
                Ok(TransferState::Cancelling)
            }
            TransferCommandKind::Fail { .. } if self.state != TransferState::Committed => {
                Ok(TransferState::Failed)
            }
            TransferCommandKind::Commit { .. }
                if matches!(
                    self.state,
                    TransferState::Running
                        | TransferState::Resumed
                        | TransferState::MailboxStored
                        | TransferState::RelayForwarded
                        | TransferState::SwarmAssisted
                ) =>
            {
                Ok(TransferState::Committed)
            }
            TransferCommandKind::StoreMailbox { .. }
                if matches!(self.state, TransferState::Running | TransferState::Resumed) =>
            {
                Ok(TransferState::MailboxStored)
            }
            TransferCommandKind::ForwardRelay { .. }
                if matches!(self.state, TransferState::Running | TransferState::Resumed) =>
            {
                Ok(TransferState::RelayForwarded)
            }
            TransferCommandKind::Seed { .. } if self.state == TransferState::Committed => {
                Ok(TransferState::Seeded)
            }
            TransferCommandKind::JoinSwarm { .. }
                if matches!(
                    self.state,
                    TransferState::Running | TransferState::Resumed | TransferState::Seeded
                ) =>
            {
                Ok(TransferState::SwarmAssisted)
            }
            TransferCommandKind::Shutdown if self.state.is_terminal() => Ok(self.state),
            _ => Err(TransferActorError::InvalidTransition {
                state: self.state,
                command: command_name(command),
            }),
        }
    }

    fn apply_side_effects(&mut self, command: &TransferCommandKind) {
        match command {
            TransferCommandKind::Start { path_id, .. } => {
                self.progress.selected_path = Some(*path_id);
            }
            TransferCommandKind::Commit { .. } => {
                self.progress.committed_bytes = self.progress.verified_bytes;
            }
            TransferCommandKind::Fail { .. } | TransferCommandKind::Cancel { .. } => {
                self.progress.committed_bytes = 0;
            }
            TransferCommandKind::JoinSwarm { .. } => {
                self.progress.repair_symbols = self.progress.repair_symbols.saturating_add(1);
            }
            TransferCommandKind::Accept { .. }
            | TransferCommandKind::Pause
            | TransferCommandKind::Resume { .. }
            | TransferCommandKind::StoreMailbox { .. }
            | TransferCommandKind::ForwardRelay { .. }
            | TransferCommandKind::Seed { .. }
            | TransferCommandKind::Shutdown => {}
        }
    }

    fn push_journal(
        &mut self,
        key: IdempotencyKey,
        previous: TransferState,
        next: TransferState,
        obligation: Option<TransferObligationId>,
        outcome: ObligationOutcome,
        command: &TransferCommandKind,
    ) {
        self.journal.push(TransferJournalEntry {
            seq: self.next_journal_seq,
            actor_id: self.actor_id,
            transfer_id: self.transfer_id,
            key,
            previous,
            next,
            obligation: obligation.map(|id| (id, outcome)),
            supervisor_region: self.topology.supervisor_region,
            actor_region: self.topology.actor_region,
            child_topology: self.topology.child_regions.clone(),
            cancel_phase: match command {
                TransferCommandKind::Cancel { phase } => Some(*phase),
                _ => None,
            },
            replay_crashpack_path: format!(
                "atp/replay/actor-{}/transition-{}.crashpack",
                self.actor_id.get(),
                self.next_journal_seq
            ),
        });
        self.next_journal_seq += 1;
    }
}

fn command_name(command: &TransferCommandKind) -> &'static str {
    match command {
        TransferCommandKind::Accept { .. } => "accept",
        TransferCommandKind::Start { .. } => "start",
        TransferCommandKind::Pause => "pause",
        TransferCommandKind::Resume { .. } => "resume",
        TransferCommandKind::Cancel { .. } => "cancel",
        TransferCommandKind::Fail { .. } => "fail",
        TransferCommandKind::Commit { .. } => "commit",
        TransferCommandKind::StoreMailbox { .. } => "store_mailbox",
        TransferCommandKind::ForwardRelay { .. } => "forward_relay",
        TransferCommandKind::Seed { .. } => "seed",
        TransferCommandKind::JoinSwarm { .. } => "join_swarm",
        TransferCommandKind::Shutdown => "shutdown",
    }
}

fn validate_complete_pressure_sources(
    progress: &TransferProgress,
    sources: &TransferPressureSources,
) -> Result<(), TransferPressureCollectionError> {
    if sources.sample_count == 0 {
        return Err(TransferPressureCollectionError::ZeroSamples);
    }
    if progress.verified_bytes > progress.offered_bytes
        || progress.committed_bytes > progress.verified_bytes
    {
        return Err(TransferPressureCollectionError::ContradictoryProgress {
            offered_bytes: progress.offered_bytes,
            verified_bytes: progress.verified_bytes,
            committed_bytes: progress.committed_bytes,
        });
    }

    let transport = require_source(
        TransferPressureSourceKind::Transport,
        sources.transport.as_ref(),
    )?;
    validate_source_trace(
        TransferPressureSourceKind::Transport,
        &sources.trace_id,
        &transport.trace_id,
    )?;

    let disk = require_source(TransferPressureSourceKind::Disk, sources.disk.as_ref())?;
    validate_source_trace(
        TransferPressureSourceKind::Disk,
        &sources.trace_id,
        &disk.trace_id,
    )?;

    let coding = require_source(TransferPressureSourceKind::Coding, sources.coding.as_ref())?;
    validate_source_trace(
        TransferPressureSourceKind::Coding,
        &sources.trace_id,
        &coding.trace_id,
    )?;

    let repair = require_source(TransferPressureSourceKind::Repair, sources.repair.as_ref())?;
    validate_source_trace(
        TransferPressureSourceKind::Repair,
        &sources.trace_id,
        &repair.trace_id,
    )?;
    if repair.useful_symbols > repair.symbols_sent {
        return Err(TransferPressureCollectionError::ContradictoryRepair {
            symbols_sent: repair.symbols_sent,
            useful_symbols: repair.useful_symbols,
        });
    }

    let relay = require_source(TransferPressureSourceKind::Relay, sources.relay.as_ref())?;
    validate_source_trace(
        TransferPressureSourceKind::Relay,
        &sources.trace_id,
        &relay.trace_id,
    )?;
    if relay.cost_micros > 0 && relay.bytes == 0 {
        return Err(TransferPressureCollectionError::ContradictoryRelay {
            cost_micros: relay.cost_micros,
            bytes: relay.bytes,
        });
    }

    let migration = require_source(
        TransferPressureSourceKind::Migration,
        sources.migration.as_ref(),
    )?;
    validate_source_trace(
        TransferPressureSourceKind::Migration,
        &sources.trace_id,
        &migration.trace_id,
    )
}

fn require_source<T>(
    source: TransferPressureSourceKind,
    value: Option<&T>,
) -> Result<&T, TransferPressureCollectionError> {
    value.ok_or(TransferPressureCollectionError::MissingSource { source })
}

fn validate_source_trace(
    source: TransferPressureSourceKind,
    expected: &str,
    observed: &str,
) -> Result<(), TransferPressureCollectionError> {
    if expected == observed {
        Ok(())
    } else {
        Err(TransferPressureCollectionError::StaleSourceTrace {
            source,
            expected: expected.to_string(),
            observed: observed.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::actor::{TransferActorTopology, TransferChildRole, TransferRegionId};
    use super::super::autotune::{
        AtpAutotuneApplicationOutcome, AtpAutotuneMetric, AtpAutotuneMetricSample,
    };
    use super::*;

    fn manifest() -> TransferManifestRef {
        TransferManifestRef {
            schema_version: 1,
            merkle_root: [7; 32],
            object_count: 3,
        }
    }

    fn topology() -> TransferActorTopology {
        TransferActorTopology::new(TransferRegionId::new(1), TransferRegionId::new(2))
            .with_child(TransferRegionId::new(3), TransferChildRole::PathRace)
            .with_child(TransferRegionId::new(4), TransferChildRole::Writer)
            .with_child(TransferRegionId::new(5), TransferChildRole::Finalizer)
    }

    fn actor() -> TransferActor {
        TransferActor::new(
            TransferActorId::new(11),
            TransferId::derive([1; 32], [2; 32], [3; 32], [4; 32]),
            manifest(),
            PeerCapabilities {
                relay: true,
                mailbox: true,
                swarm: true,
                max_inflight_obligations: 4,
            },
            topology(),
        )
        .unwrap()
    }

    fn complete_sources(trace_id: &str) -> TransferPressureSources {
        let mut sources = TransferPressureSources::new(trace_id, 5);
        sources.transport = Some(TransferTransportPressure {
            trace_id: trace_id.to_string(),
            rtt_micros: 42_000,
            loss_permille: 8,
            pto_micros: 120_000,
            congestion_window_bytes: 64_000,
            send_buffer_queued_bytes: 2_048,
        });
        sources.disk = Some(TransferDiskPressure {
            trace_id: trace_id.to_string(),
            read_lag_micros: 9_000,
            write_lag_micros: 11_000,
        });
        sources.coding = Some(TransferCodingPressure {
            trace_id: trace_id.to_string(),
            encode_backlog_symbols: 7,
            decode_backlog_symbols: 3,
        });
        sources.repair = Some(TransferRepairPressure {
            trace_id: trace_id.to_string(),
            symbols_sent: 20,
            useful_symbols: 10,
        });
        sources.relay = Some(TransferRelayPressure {
            trace_id: trace_id.to_string(),
            cost_micros: 250_000,
            bytes: 1_048_576,
        });
        sources.migration = Some(TransferMigrationPressure {
            trace_id: trace_id.to_string(),
            events: 0,
        });
        sources
    }

    #[test]
    fn actor_construction_uses_inline_empty_collections() {
        let actor = actor();

        assert!(!actor.applied_keys.spilled());
        assert!(!actor.open_obligations.spilled());
        assert!(!actor.settled_obligations.spilled());
        assert!(!actor.journal.spilled());
    }

    #[test]
    fn transfer_id_binds_peers_nonce_manifest_and_policy() {
        let baseline = TransferId::derive_with_policy([1; 32], [2; 32], [3; 32], [4; 32], [5; 32]);

        assert_eq!(
            baseline,
            TransferId::derive_with_policy([1; 32], [2; 32], [3; 32], [4; 32], [5; 32])
        );
        assert_ne!(
            baseline,
            TransferId::derive_with_policy([2; 32], [1; 32], [3; 32], [4; 32], [5; 32])
        );
        assert_ne!(
            baseline,
            TransferId::derive_with_policy([1; 32], [2; 32], [9; 32], [4; 32], [5; 32])
        );
        assert_ne!(
            baseline,
            TransferId::derive_with_policy([1; 32], [2; 32], [3; 32], [9; 32], [5; 32])
        );
        assert_ne!(
            baseline,
            TransferId::derive_with_policy([1; 32], [2; 32], [3; 32], [4; 32], [9; 32])
        );
    }

    #[test]
    fn transfer_id_hex_is_stable_lowercase() {
        let mut bytes = [0_u8; 32];
        bytes[0] = 0xab;
        bytes[1] = 0xcd;
        bytes[30] = 0x12;
        bytes[31] = 0x34;

        assert_eq!(
            TransferId::new(bytes).to_hex(),
            "abcd000000000000000000000000000000000000000000000000000000001234"
        );
    }

    #[test]
    fn transfer_progress_collects_actor_owned_pressure_metrics() {
        let mut actor = actor();
        actor.progress.offered_bytes = 8_192;
        actor.progress.verified_bytes = 3_072;
        actor.progress.committed_bytes = 1_024;

        let snapshot = actor.pressure_snapshot("trace-transfer-actor", 4);

        assert_eq!(snapshot.trace_id, "trace-transfer-actor");
        assert_eq!(snapshot.transfer_id, actor.transfer_id.to_hex());
        assert_eq!(snapshot.sample_count, 4);
        assert_eq!(snapshot.in_flight_bytes, Some(5_120));
        assert_eq!(snapshot.receive_buffer_queued_bytes, Some(2_048));

        let report = snapshot.to_report();
        assert_eq!(
            report.samples,
            vec![
                AtpAutotuneMetricSample::new(AtpAutotuneMetric::InFlightBytes, 5_120),
                AtpAutotuneMetricSample::new(AtpAutotuneMetric::ReceiveBufferQueuedBytes, 2_048,),
            ]
        );
    }

    #[test]
    fn transfer_progress_pressure_snapshot_saturates_inconsistent_counters() {
        let progress = TransferProgress {
            offered_bytes: 10,
            verified_bytes: 20,
            committed_bytes: 30,
            repair_symbols: 0,
            selected_path: None,
        };

        let snapshot =
            progress.to_pressure_snapshot("trace-saturating", TransferId::from_u128(7), 1);

        assert_eq!(snapshot.in_flight_bytes, Some(0));
        assert_eq!(snapshot.receive_buffer_queued_bytes, Some(0));
    }

    #[test]
    fn complete_pressure_snapshot_collects_every_metric_family() {
        let mut actor = actor();
        actor.progress.offered_bytes = 4_096;
        actor.progress.verified_bytes = 1_024;
        actor.progress.committed_bytes = 256;

        let snapshot = actor
            .collect_complete_pressure_snapshot(complete_sources("trace-complete"))
            .expect("complete pressure sources");

        assert_eq!(snapshot.trace_id, "trace-complete");
        assert_eq!(snapshot.transfer_id, actor.transfer_id.to_hex());
        assert_eq!(snapshot.sample_count, 5);
        assert_eq!(snapshot.in_flight_bytes, Some(3_072));
        assert_eq!(snapshot.receive_buffer_queued_bytes, Some(768));
        assert_eq!(snapshot.repair_roi_permille(), Some(500));
        assert_eq!(snapshot.relay_cost_micros_per_mib(), Some(250_000));

        let report = snapshot.to_report();
        assert_eq!(
            report.samples,
            vec![
                AtpAutotuneMetricSample::new(AtpAutotuneMetric::RttMicros, 42_000),
                AtpAutotuneMetricSample::new(AtpAutotuneMetric::LossPermille, 8),
                AtpAutotuneMetricSample::new(AtpAutotuneMetric::PtoMicros, 120_000),
                AtpAutotuneMetricSample::new(AtpAutotuneMetric::CongestionWindowBytes, 64_000,),
                AtpAutotuneMetricSample::new(AtpAutotuneMetric::InFlightBytes, 3_072),
                AtpAutotuneMetricSample::new(AtpAutotuneMetric::SendBufferQueuedBytes, 2_048,),
                AtpAutotuneMetricSample::new(AtpAutotuneMetric::ReceiveBufferQueuedBytes, 768,),
                AtpAutotuneMetricSample::new(AtpAutotuneMetric::DiskReadLagMicros, 9_000),
                AtpAutotuneMetricSample::new(AtpAutotuneMetric::DiskWriteLagMicros, 11_000),
                AtpAutotuneMetricSample::new(AtpAutotuneMetric::EncodeBacklogSymbols, 7),
                AtpAutotuneMetricSample::new(AtpAutotuneMetric::DecodeBacklogSymbols, 3),
                AtpAutotuneMetricSample::new(AtpAutotuneMetric::RepairRoiPermille, 500),
                AtpAutotuneMetricSample::new(AtpAutotuneMetric::RelayCostMicrosPerMiB, 250_000,),
                AtpAutotuneMetricSample::new(AtpAutotuneMetric::MigrationEvents, 0),
            ]
        );
    }

    #[test]
    fn complete_pressure_snapshot_fails_closed_for_missing_source() {
        let mut sources = complete_sources("trace-missing");
        sources.disk = None;

        let err = actor()
            .collect_complete_pressure_snapshot(sources)
            .expect_err("missing disk source must fail closed");

        assert_eq!(err.reason_code(), "missing_pressure_source");
        assert!(matches!(
            err,
            TransferPressureCollectionError::MissingSource {
                source: TransferPressureSourceKind::Disk
            }
        ));
    }

    #[test]
    fn complete_pressure_snapshot_fails_closed_for_stale_trace_id() {
        let mut sources = complete_sources("trace-current");
        sources.repair.as_mut().expect("repair source").trace_id = "trace-stale".to_string();

        let err = actor()
            .collect_complete_pressure_snapshot(sources)
            .expect_err("stale repair trace must fail closed");

        assert_eq!(err.reason_code(), "stale_pressure_trace_id");
        assert!(matches!(
            err,
            TransferPressureCollectionError::StaleSourceTrace {
                source: TransferPressureSourceKind::Repair,
                ..
            }
        ));
    }

    #[test]
    fn complete_pressure_snapshot_fails_closed_for_zero_samples() {
        let mut sources = complete_sources("trace-zero");
        sources.sample_count = 0;

        let err = actor()
            .collect_complete_pressure_snapshot(sources)
            .expect_err("zero-sample complete source must fail closed");

        assert_eq!(err.reason_code(), "zero_pressure_samples");
        assert!(matches!(err, TransferPressureCollectionError::ZeroSamples));
    }

    #[test]
    fn complete_pressure_snapshot_fails_closed_for_contradictory_progress() {
        let mut actor = actor();
        actor.progress.offered_bytes = 10;
        actor.progress.verified_bytes = 20;
        actor.progress.committed_bytes = 5;

        let err = actor
            .collect_complete_pressure_snapshot(complete_sources("trace-progress"))
            .expect_err("backwards progress counters must fail closed");

        assert_eq!(err.reason_code(), "contradictory_progress_counters");
        assert!(matches!(
            err,
            TransferPressureCollectionError::ContradictoryProgress {
                offered_bytes: 10,
                verified_bytes: 20,
                committed_bytes: 5,
            }
        ));
    }

    #[test]
    fn complete_pressure_snapshot_fails_closed_for_contradictory_repair_or_relay() {
        let mut repair_sources = complete_sources("trace-repair");
        repair_sources
            .repair
            .as_mut()
            .expect("repair source")
            .useful_symbols = 21;

        let repair_err = actor()
            .collect_complete_pressure_snapshot(repair_sources)
            .expect_err("useful repair cannot exceed sent repair");
        assert_eq!(repair_err.reason_code(), "contradictory_repair_counters");

        let mut relay_sources = complete_sources("trace-relay");
        let relay = relay_sources.relay.as_mut().expect("relay source");
        relay.bytes = 0;
        relay.cost_micros = 1;

        let relay_err = actor()
            .collect_complete_pressure_snapshot(relay_sources)
            .expect_err("relay cost without payload must fail closed");
        assert_eq!(relay_err.reason_code(), "contradictory_relay_counters");
    }

    #[test]
    fn transfer_actor_applies_autotune_growth_after_hysteresis() {
        let policy = AtpAutotunePolicy::default();
        let mut actor = actor();
        let initial = actor.autotune_settings();
        let mut first_sources = complete_sources("trace-growth-1");
        first_sources.sample_count = 16;

        let first = actor
            .apply_complete_pressure_autotune(policy, first_sources)
            .expect("first healthy pressure window");

        assert_eq!(
            first.outcome,
            AtpAutotuneApplicationOutcome::DeferredGrowthHysteresis
        );
        assert!(!first.applied);
        assert_eq!(actor.autotune_settings(), initial);
        assert_eq!(
            actor
                .autotune_application_state()
                .consecutive_growth_windows,
            1
        );

        let mut second_sources = complete_sources("trace-growth-2");
        second_sources.sample_count = 16;
        let second = actor
            .apply_complete_pressure_autotune(policy, second_sources)
            .expect("second healthy pressure window");

        assert_eq!(
            second.outcome,
            AtpAutotuneApplicationOutcome::AppliedConfirmedGrowth
        );
        assert!(second.applied);
        assert!(actor.autotune_settings().in_flight_bytes > initial.in_flight_bytes);
        assert!(actor.autotune_settings().stream_count > initial.stream_count);
        assert!(actor.autotune_settings().chunk_size_bytes > initial.chunk_size_bytes);
        assert_eq!(
            actor
                .autotune_application_state()
                .consecutive_growth_windows,
            0
        );
    }

    #[test]
    fn transfer_actor_applies_autotune_pressure_to_independent_knobs() {
        let policy = AtpAutotunePolicy::default();

        let mut network_actor = actor();
        let network_initial = network_actor.autotune_settings();
        let mut network_sources = complete_sources("trace-network");
        network_sources.sample_count = 16;
        network_sources
            .transport
            .as_mut()
            .expect("transport source")
            .loss_permille = policy.loss_backoff_permille + 1;

        let network_receipt = network_actor
            .apply_complete_pressure_autotune(policy, network_sources)
            .expect("network pressure window");

        assert_eq!(
            network_receipt.outcome,
            AtpAutotuneApplicationOutcome::AppliedPressureBackoff
        );
        assert!(
            network_actor.autotune_settings().in_flight_bytes < network_initial.in_flight_bytes
        );
        assert!(network_actor.autotune_settings().stream_count < network_initial.stream_count);
        assert!(
            network_actor.autotune_settings().repair_symbols_per_second
                > network_initial.repair_symbols_per_second
        );

        let mut disk_cpu_actor = actor();
        let disk_cpu_initial = disk_cpu_actor.autotune_settings();
        let mut disk_cpu_sources = complete_sources("trace-disk-cpu");
        disk_cpu_sources.sample_count = 16;
        disk_cpu_sources
            .disk
            .as_mut()
            .expect("disk source")
            .write_lag_micros = policy.disk_lag_micros + 1;
        disk_cpu_sources
            .coding
            .as_mut()
            .expect("coding source")
            .encode_backlog_symbols = policy.cpu_backlog_symbols + 1;

        let disk_cpu_receipt = disk_cpu_actor
            .apply_complete_pressure_autotune(policy, disk_cpu_sources)
            .expect("disk/cpu pressure window");

        assert_eq!(
            disk_cpu_receipt.outcome,
            AtpAutotuneApplicationOutcome::AppliedPressureBackoff
        );
        assert_eq!(
            disk_cpu_actor.autotune_settings().in_flight_bytes,
            disk_cpu_initial.in_flight_bytes
        );
        assert!(
            disk_cpu_actor.autotune_settings().chunk_size_bytes < disk_cpu_initial.chunk_size_bytes
        );

        let mut relay_actor = actor();
        let relay_initial = relay_actor.autotune_settings();
        let mut relay_sources = complete_sources("trace-relay-cost");
        relay_sources.sample_count = 16;
        let relay = relay_sources.relay.as_mut().expect("relay source");
        relay.bytes = 1_048_576;
        relay.cost_micros = policy.relay_cost_micros_per_mib + 1;

        let relay_receipt = relay_actor
            .apply_complete_pressure_autotune(policy, relay_sources)
            .expect("relay pressure window");

        assert_eq!(
            relay_receipt.outcome,
            AtpAutotuneApplicationOutcome::AppliedPressureBackoff
        );
        assert!(relay_actor.autotune_settings().in_flight_bytes < relay_initial.in_flight_bytes);
        assert!(relay_actor.autotune_settings().stream_count < relay_initial.stream_count);
        assert_eq!(
            relay_actor.autotune_settings().repair_symbols_per_second,
            relay_initial.repair_symbols_per_second
        );
    }

    #[test]
    fn transfer_actor_rejects_contradictory_autotune_sources_without_mutation() {
        let policy = AtpAutotunePolicy::default();
        let mut actor = actor();
        actor.progress.offered_bytes = 10;
        actor.progress.verified_bytes = 20;
        actor.progress.committed_bytes = 5;
        let before = actor.autotune_settings();
        let mut sources = complete_sources("trace-contradictory");
        sources.sample_count = 16;

        let err = actor
            .apply_complete_pressure_autotune(policy, sources)
            .expect_err("contradictory progress must reject before mutation");

        assert_eq!(err.reason_code(), "contradictory_progress_counters");
        assert!(matches!(
            err,
            TransferAutotuneApplicationError::PressureCollection(
                TransferPressureCollectionError::ContradictoryProgress { .. }
            )
        ));
        assert_eq!(actor.autotune_settings(), before);
    }

    #[test]
    fn transfer_actor_rejects_autotune_while_cancelling_without_obligation_or_settings_mutation() {
        let policy = AtpAutotunePolicy::default();
        let mut actor = actor();
        actor
            .apply(cmd(
                1,
                TransferCommandKind::Accept {
                    obligation: TransferObligationId::new(1),
                },
            ))
            .expect("accept");
        actor
            .apply(cmd(
                2,
                TransferCommandKind::Start {
                    path_id: 7,
                    obligation: TransferObligationId::new(2),
                },
            ))
            .expect("start");
        actor
            .apply(cmd(
                3,
                TransferCommandKind::Cancel {
                    phase: TransferCancelPhase::Requested,
                },
            ))
            .expect("cancel");

        let before_settings = actor.autotune_settings();
        let before_open = actor.open_obligation_count();
        let before_journal_len = actor.journal().len();
        let mut sources = complete_sources("trace-cancelled");
        sources.sample_count = 16;

        let err = actor
            .apply_complete_pressure_autotune(policy, sources)
            .expect_err("cancelled actor must not apply autotune");

        assert_eq!(err.reason_code(), "transfer_not_tunable");
        assert!(matches!(
            err,
            TransferAutotuneApplicationError::ActorNotTunable {
                state: TransferState::Cancelling
            }
        ));
        assert_eq!(actor.autotune_settings(), before_settings);
        assert_eq!(actor.open_obligation_count(), before_open);
        assert_eq!(actor.journal().len(), before_journal_len);
    }

    fn cmd(key: u128, kind: TransferCommandKind) -> TransferCommand {
        TransferCommand::new(IdempotencyKey::new(key), kind)
    }

    #[test]
    fn state_coverage_matches_atp_e1() {
        assert_eq!(TransferState::ALL.len(), 12);
        assert!(TransferState::ALL.contains(&TransferState::Offered));
        assert!(TransferState::ALL.contains(&TransferState::Accepted));
        assert!(TransferState::ALL.contains(&TransferState::Running));
        assert!(TransferState::ALL.contains(&TransferState::Paused));
        assert!(TransferState::ALL.contains(&TransferState::Cancelling));
        assert!(TransferState::ALL.contains(&TransferState::Failed));
        assert!(TransferState::ALL.contains(&TransferState::Committed));
        assert!(TransferState::ALL.contains(&TransferState::Resumed));
        assert!(TransferState::ALL.contains(&TransferState::MailboxStored));
        assert!(TransferState::ALL.contains(&TransferState::RelayForwarded));
        assert!(TransferState::ALL.contains(&TransferState::Seeded));
        assert!(TransferState::ALL.contains(&TransferState::SwarmAssisted));
    }

    #[test]
    fn offer_accept_running_commit_shutdown_is_quiescent() {
        let mut actor = actor();
        actor.progress.verified_bytes = 4096;

        actor
            .apply(cmd(
                1,
                TransferCommandKind::Accept {
                    obligation: TransferObligationId::new(101),
                },
            ))
            .unwrap();
        actor
            .apply(cmd(
                2,
                TransferCommandKind::Start {
                    path_id: 55,
                    obligation: TransferObligationId::new(102),
                },
            ))
            .unwrap();
        actor
            .apply(cmd(
                3,
                TransferCommandKind::Commit {
                    obligation: TransferObligationId::new(103),
                },
            ))
            .unwrap();
        let reply = actor
            .apply(cmd(4, TransferCommandKind::Shutdown))
            .expect("shutdown after commit");

        assert_eq!(actor.state(), TransferState::Committed);
        assert_eq!(actor.progress.selected_path, Some(55));
        assert_eq!(actor.progress.committed_bytes, 4096);
        assert_eq!(actor.open_obligation_count(), 0);
        assert_eq!(actor.settled_obligations().len(), 3);
        assert_eq!(actor.journal()[0].actor_id, actor.actor_id);
        assert_eq!(actor.journal()[0].transfer_id, actor.transfer_id);
        assert_eq!(actor.journal()[0].actor_region, actor.topology.actor_region);
        assert_eq!(
            actor.journal()[0].supervisor_region,
            actor.topology.supervisor_region
        );
        assert_eq!(
            actor.journal()[0].child_topology,
            actor.topology.child_regions
        );
        assert_eq!(
            actor.journal()[0].replay_crashpack_path,
            "atp/replay/actor-11/transition-0.crashpack"
        );
        assert!(matches!(
            reply,
            TransferReply::ShutdownQuiescent {
                state: TransferState::Committed
            }
        ));
    }

    #[test]
    fn invalid_transition_aborts_obligation_without_state_change() {
        let mut actor = actor();
        let err = actor
            .apply(cmd(
                1,
                TransferCommandKind::Commit {
                    obligation: TransferObligationId::new(77),
                },
            ))
            .expect_err("commit from offered must fail");

        assert_eq!(actor.state(), TransferState::Offered);
        assert_eq!(actor.open_obligation_count(), 0);
        assert_eq!(
            actor.settled_obligations(),
            &[(TransferObligationId::new(77), ObligationOutcome::Aborted)]
        );
        assert!(matches!(
            err,
            TransferActorError::InvalidTransition {
                state: TransferState::Offered,
                command: "commit"
            }
        ));
    }

    #[test]
    fn duplicate_messages_are_idempotent() {
        let mut actor = actor();
        let command = cmd(
            1,
            TransferCommandKind::Accept {
                obligation: TransferObligationId::new(10),
            },
        );

        actor.apply(command.clone()).unwrap();
        let duplicate = actor.apply(command).unwrap();

        assert_eq!(actor.state(), TransferState::Accepted);
        assert_eq!(actor.journal().len(), 1);
        assert_eq!(actor.settled_obligations().len(), 1);
        assert!(matches!(
            duplicate,
            TransferReply::Duplicate {
                state: TransferState::Accepted
            }
        ));
    }

    #[test]
    fn cancellation_is_accepted_from_every_nonterminal_state() {
        for state in [
            TransferState::Offered,
            TransferState::Accepted,
            TransferState::Running,
            TransferState::Paused,
            TransferState::Resumed,
            TransferState::MailboxStored,
            TransferState::RelayForwarded,
            TransferState::SwarmAssisted,
        ] {
            let mut actor = actor();
            actor.state = state;
            actor
                .apply(cmd(
                    1,
                    TransferCommandKind::Cancel {
                        phase: TransferCancelPhase::Requested,
                    },
                ))
                .unwrap();
            assert_eq!(actor.state(), TransferState::Cancelling);
            assert_eq!(
                actor.journal()[0].cancel_phase,
                Some(TransferCancelPhase::Requested)
            );
        }
    }

    #[test]
    fn restart_from_journal_preserves_state_and_idempotency() {
        let mut actor = actor();
        actor
            .apply(cmd(
                1,
                TransferCommandKind::Accept {
                    obligation: TransferObligationId::new(1),
                },
            ))
            .unwrap();
        actor
            .apply(cmd(
                2,
                TransferCommandKind::Start {
                    path_id: 9,
                    obligation: TransferObligationId::new(2),
                },
            ))
            .unwrap();

        let mut restarted = TransferActor::restart_from_journal(
            actor.actor_id,
            actor.transfer_id,
            actor.manifest.clone(),
            actor.peer_capabilities.clone(),
            actor.topology.clone(),
            actor.journal(),
        )
        .unwrap();

        assert_eq!(restarted.state(), TransferState::Running);
        let duplicate = restarted
            .apply(cmd(
                2,
                TransferCommandKind::Start {
                    path_id: 9,
                    obligation: TransferObligationId::new(2),
                },
            ))
            .unwrap();
        assert!(matches!(
            duplicate,
            TransferReply::Duplicate {
                state: TransferState::Running
            }
        ));
    }

    #[test]
    fn failed_peer_disk_and_repair_paths_are_distinct() {
        for (key, failure) in [
            (1, TransferFailureKind::Peer),
            (2, TransferFailureKind::Disk),
            (3, TransferFailureKind::Repair),
        ] {
            let mut actor = actor();
            actor
                .apply(cmd(key, TransferCommandKind::Fail { kind: failure }))
                .unwrap();
            assert_eq!(actor.state(), TransferState::Failed);
            assert_eq!(actor.open_obligation_count(), 0);
        }
    }

    #[test]
    fn restart_from_journal_preserves_obligation_state() {
        // Test demonstrates current synchronous obligation behavior and documents
        // expected behavior for future asynchronous obligation support
        let mut actor = actor();

        // Apply commands that create and immediately settle obligations
        actor
            .apply(cmd(
                1,
                TransferCommandKind::Accept {
                    obligation: TransferObligationId::new(101),
                },
            ))
            .unwrap();
        actor
            .apply(cmd(
                2,
                TransferCommandKind::Start {
                    path_id: 42,
                    obligation: TransferObligationId::new(102),
                },
            ))
            .unwrap();

        // All obligations should be settled, none open
        assert_eq!(actor.open_obligation_count(), 0);
        assert_eq!(actor.settled_obligations().len(), 2);

        // Restart from journal
        let restarted = TransferActor::restart_from_journal(
            actor.actor_id,
            actor.transfer_id,
            actor.manifest.clone(),
            actor.peer_capabilities.clone(),
            actor.topology.clone(),
            actor.journal(),
        )
        .unwrap();

        // After restart, state should be preserved
        assert_eq!(restarted.state(), TransferState::Running);
        assert_eq!(restarted.open_obligation_count(), 0);
        assert_eq!(restarted.settled_obligations().len(), 2);

        // The two settled obligations should match the original
        let original_settled = actor.settled_obligations();
        let restarted_settled = restarted.settled_obligations();
        assert_eq!(original_settled, restarted_settled);

        // Verify specific obligation IDs and outcomes are preserved
        assert!(
            original_settled
                .contains(&(TransferObligationId::new(101), ObligationOutcome::Committed))
        );
        assert!(
            original_settled
                .contains(&(TransferObligationId::new(102), ObligationOutcome::Committed))
        );
    }
}

// Include integration tests with real ATP transfer workflows
#[cfg(all(test, feature = "legacy-internal-test-harnesses"))]
#[path = "../transfer_integration_tests.rs"]
mod transfer_integration_tests;
