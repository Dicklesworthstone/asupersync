//! MessagePort-based coordination utilities for browser main-thread / worker
//! runtime communication.
//!
//! Bead: asupersync-18tbo.3
//!
//! This module provides the typed coordination layer that sits between raw
//! `postMessage` usage and application code. It defines a structured message
//! protocol for:
//!
//! - **Bootstrap readiness**: worker reports initialization status
//! - **Work dispatch**: main thread sends work requests with region/task IDs
//! - **Cancellation**: main thread requests cancellation of in-flight work
//! - **Graceful shutdown**: coordinated worker lifecycle termination
//! - **Diagnostic events**: structured error/status reporting
//!
//! # Design
//!
//! The protocol is defined as Rust types that serialize to JSON for the
//! structured-clone boundary. All messages carry explicit region and
//! sequence metadata so the coordination path remains compatible with
//! Asupersync's structured concurrency and deterministic replay.
//!
//! # Browser Integration
//!
//! On `wasm32` targets, the coordinator and endpoint integrate with the
//! [`BrowserReactor`](crate::runtime::reactor::BrowserReactor) through its
//! `register_message_port()` API, delivering
//! events via the reactor's token-based readiness model.

use std::collections::VecDeque;
use std::fmt;

/// Protocol version for the worker coordination envelope.
pub const WORKER_PROTOCOL_VERSION: u32 = 1;

/// Maximum payload size in bytes (256 KiB, matching policy).
pub const MAX_PAYLOAD_BYTES: usize = 262_144;

/// Payload ownership mode across the non-SAB worker boundary.
///
/// The concrete v1 envelope only ships structured-clone semantics for owned
/// byte payloads. The enum exists so policy, diagnostics, and later browser
/// wiring can describe transfer rules without implying SharedArrayBuffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerPayloadTransfer {
    /// Structured-clone the payload across the `postMessage` boundary.
    StructuredClone,
    /// Transfer ownership of an `ArrayBuffer`-backed payload.
    TransferArrayBuffer,
}

#[must_use]
fn replay_hash(
    message_id: u64,
    seq_no: u64,
    decision_seq: u64,
    seed: u64,
    issued_at_turn: u64,
    worker_id: Option<&str>,
    op: &WorkerOp,
) -> u64 {
    let mut hash = message_id
        .wrapping_mul(0x9E37_79B1_85EB_CA87)
        .wrapping_add(seq_no.rotate_left(13))
        ^ decision_seq.rotate_left(23)
        ^ seed.rotate_left(29)
        ^ issued_at_turn.rotate_left(47);
    if let Some(worker_id) = worker_id {
        for byte in worker_id.as_bytes() {
            hash = hash.rotate_left(7) ^ u64::from(*byte);
            hash = hash.wrapping_mul(0x100_0000_01B3);
        }
    }
    for byte in serde_json::to_vec(op).unwrap_or_default() {
        hash = hash.rotate_left(5) ^ u64::from(byte);
        hash = hash.wrapping_mul(0x100_0000_01B3);
    }
    hash
}

fn validate_payload_size(size: usize) -> Result<(), WorkerChannelError> {
    if size > MAX_PAYLOAD_BYTES {
        return Err(WorkerChannelError::PayloadTooLarge {
            size,
            max: MAX_PAYLOAD_BYTES,
        });
    }
    Ok(())
}

// ─── Envelope ────────────────────────────────────────────────────────

/// A typed coordination message exchanged between main thread and worker.
///
/// All messages carry sequence metadata for deterministic replay and
/// region affinity for structured concurrency enforcement.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WorkerEnvelope {
    /// Protocol version for forward compatibility.
    pub version: u32,
    /// Unique message identifier within this coordination session.
    pub message_id: u64,
    /// Monotonically increasing sequence number per sender.
    pub seq_no: u64,
    /// Deterministic decision sequence used for replay parity.
    pub decision_seq: u64,
    /// Deterministic RNG seed for replay (propagated from parent Cx).
    pub seed: u64,
    /// Host turn ID at message creation (for deterministic scheduling).
    pub issued_at_turn: u64,
    /// Worker runtime instance for worker-originated messages.
    ///
    /// Main-thread coordinator messages leave this unset. Worker-originated
    /// messages must carry the runtime instance id so stale messages from a
    /// replaced worker cannot poison a fresh inbound session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_id: Option<String>,
    /// Stable replay digest for cross-runtime policy checks.
    pub replay_hash: u64,
    /// The coordination operation.
    pub op: WorkerOp,
}

impl WorkerEnvelope {
    /// Create a coordinator-originated envelope with the given operation and sequence metadata.
    ///
    /// This constructor is for main-thread/coordinator messages only. Worker-
    /// originated messages must use [`Self::from_worker`] so the runtime
    /// instance identity is carried explicitly.
    #[must_use]
    pub fn new(message_id: u64, seq_no: u64, seed: u64, issued_at_turn: u64, op: WorkerOp) -> Self {
        Self::new_with_decision_seq(message_id, seq_no, seq_no, seed, issued_at_turn, op)
    }

    /// Create a coordinator-originated envelope with explicit transport and decision sequence
    /// counters.
    ///
    /// This constructor intentionally leaves [`Self::worker_id`] unset. Use
    /// [`Self::from_worker_with_decision_seq`] for worker-originated messages.
    #[must_use]
    pub fn new_with_decision_seq(
        message_id: u64,
        seq_no: u64,
        decision_seq: u64,
        seed: u64,
        issued_at_turn: u64,
        op: WorkerOp,
    ) -> Self {
        Self {
            version: WORKER_PROTOCOL_VERSION,
            message_id,
            seq_no,
            decision_seq,
            seed,
            issued_at_turn,
            worker_id: None,
            replay_hash: replay_hash(
                message_id,
                seq_no,
                decision_seq,
                seed,
                issued_at_turn,
                None,
                &op,
            ),
            op,
        }
    }

    /// Create a worker-originated envelope tagged with the worker runtime id.
    #[must_use]
    pub fn from_worker(
        worker_id: impl Into<String>,
        message_id: u64,
        seq_no: u64,
        seed: u64,
        issued_at_turn: u64,
        op: WorkerOp,
    ) -> Self {
        Self::from_worker_with_decision_seq(
            worker_id,
            message_id,
            seq_no,
            seq_no,
            seed,
            issued_at_turn,
            op,
        )
    }

    /// Create a worker-originated envelope with explicit decision sequence metadata.
    #[must_use]
    pub fn from_worker_with_decision_seq(
        worker_id: impl Into<String>,
        message_id: u64,
        seq_no: u64,
        decision_seq: u64,
        seed: u64,
        issued_at_turn: u64,
        op: WorkerOp,
    ) -> Self {
        let worker_id = worker_id.into();
        Self {
            version: WORKER_PROTOCOL_VERSION,
            message_id,
            seq_no,
            decision_seq,
            seed,
            issued_at_turn,
            worker_id: Some(worker_id.clone()),
            replay_hash: replay_hash(
                message_id,
                seq_no,
                decision_seq,
                seed,
                issued_at_turn,
                Some(worker_id.as_str()),
                &op,
            ),
            op,
        }
    }

    /// Validate the envelope against protocol constraints.
    pub fn validate(&self) -> Result<(), WorkerChannelError> {
        if self.version != WORKER_PROTOCOL_VERSION {
            return Err(WorkerChannelError::VersionMismatch {
                expected: WORKER_PROTOCOL_VERSION,
                actual: self.version,
            });
        }
        let expected_replay_hash = replay_hash(
            self.message_id,
            self.seq_no,
            self.decision_seq,
            self.seed,
            self.issued_at_turn,
            self.worker_id.as_deref(),
            &self.op,
        );
        if self.replay_hash != expected_replay_hash {
            return Err(WorkerChannelError::ReplayHashMismatch {
                expected: expected_replay_hash,
                actual: self.replay_hash,
            });
        }
        self.validate_worker_identity()?;
        match &self.op {
            WorkerOp::SpawnJob(req) => validate_payload_size(req.payload.len())?,
            WorkerOp::JobCompleted(JobResult {
                outcome: JobOutcome::Ok { payload },
                ..
            }) => validate_payload_size(payload.len())?,
            _ => {}
        }
        Ok(())
    }

    fn validate_worker_identity(&self) -> Result<(), WorkerChannelError> {
        match &self.op {
            WorkerOp::BootstrapReady { worker_id }
            | WorkerOp::BootstrapFailed { worker_id, .. } => {
                let actual = self
                    .worker_id
                    .as_deref()
                    .ok_or(WorkerChannelError::MissingWorkerSessionIdentity)?;
                if actual != worker_id {
                    return Err(WorkerChannelError::WorkerIdentityMismatch {
                        expected: worker_id.clone(),
                        actual: actual.to_string(),
                    });
                }
            }
            WorkerOp::StatusSnapshot(_)
            | WorkerOp::JobCompleted(_)
            | WorkerOp::CancelAcknowledged { .. }
            | WorkerOp::DrainCompleted { .. }
            | WorkerOp::FinalizeCompleted { .. }
            | WorkerOp::ShutdownCompleted
            | WorkerOp::Diagnostic(_) => {
                if self.worker_id.is_none() {
                    return Err(WorkerChannelError::MissingWorkerSessionIdentity);
                }
            }
            WorkerOp::SpawnJob(_)
            | WorkerOp::PollStatus { .. }
            | WorkerOp::CancelJob { .. }
            | WorkerOp::DrainJob { .. }
            | WorkerOp::FinalizeJob { .. }
            | WorkerOp::ShutdownWorker { .. } => {
                if let Some(worker_id) = &self.worker_id {
                    return Err(WorkerChannelError::UnexpectedWorkerSessionIdentity(
                        worker_id.clone(),
                    ));
                }
            }
        }
        Ok(())
    }
}

// ─── Operations ──────────────────────────────────────────────────────

/// Worker coordination operations.
///
/// These map to the lifecycle messages described in the worker offload
/// policy: bootstrap, work dispatch, cancellation, shutdown, and
/// diagnostics.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type")]
pub enum WorkerOp {
    // ── Bootstrap ────────────────────────────────────────────────
    /// Worker → main: worker runtime has initialized successfully.
    BootstrapReady {
        /// Worker-assigned identifier for this runtime instance.
        worker_id: String,
    },
    /// Worker → main: worker runtime failed to initialize.
    BootstrapFailed {
        /// Worker-assigned identifier for this runtime instance.
        worker_id: String,
        /// Human-readable failure reason.
        reason: String,
    },

    // ── Work dispatch ────────────────────────────────────────────
    /// Main → worker: spawn a new job inside the worker runtime.
    SpawnJob(SpawnJobRequest),
    /// Main → worker: request an explicit status snapshot for an in-flight job.
    PollStatus {
        /// Job identifier whose state should be reported.
        job_id: u64,
    },
    /// Worker → main: current state for an in-flight job.
    StatusSnapshot(JobStatusSnapshot),
    /// Worker → main: job completed with a result.
    JobCompleted(JobResult),

    // ── Cancellation ─────────────────────────────────────────────
    /// Main → worker: request cancellation of a specific job.
    CancelJob {
        /// Job identifier to cancel.
        job_id: u64,
        /// Cancellation reason.
        reason: String,
    },
    /// Worker → main: cancellation acknowledged, entering drain phase.
    CancelAcknowledged {
        /// Job identifier whose cancellation request was acknowledged.
        job_id: u64,
    },
    /// Main → worker: execute bounded drain for a cancelled job.
    DrainJob {
        /// Job identifier whose drain phase should execute.
        job_id: u64,
    },
    /// Worker → main: drain phase completed.
    DrainCompleted {
        /// Job identifier whose drain phase completed.
        job_id: u64,
    },
    /// Main → worker: execute bounded finalize after drain completion.
    FinalizeJob {
        /// Job identifier whose finalize phase should execute.
        job_id: u64,
    },
    /// Worker → main: finalize phase completed.
    FinalizeCompleted {
        /// Job identifier whose finalize phase completed.
        job_id: u64,
    },

    // ── Shutdown ─────────────────────────────────────────────────
    /// Main → worker: request graceful shutdown of the worker runtime.
    ShutdownWorker {
        /// Reason for the shutdown request.
        reason: String,
    },
    /// Worker → main: shutdown completed, worker is safe to terminate.
    ShutdownCompleted,

    // ── Diagnostics ──────────────────────────────────────────────
    /// Worker → main: structured diagnostic event.
    Diagnostic(DiagnosticEvent),
}

/// A request to spawn a job inside the worker runtime.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SpawnJobRequest {
    /// Unique job identifier within this coordination session.
    pub job_id: u64,
    /// Region ID that owns this job (for structured concurrency enforcement).
    pub region_id: u64,
    /// Task ID within the owning region.
    pub task_id: u64,
    /// Obligation ID for the job's commit/abort tracking.
    pub obligation_id: u64,
    /// Serialized job payload (must respect MAX_PAYLOAD_BYTES).
    pub payload: Vec<u8>,
}

impl SpawnJobRequest {
    /// The concrete v1 non-SAB transport always uses structured-cloned owned bytes.
    #[must_use]
    pub fn payload_transfer(&self) -> WorkerPayloadTransfer {
        WorkerPayloadTransfer::StructuredClone
    }

    /// Whether the request owns the payload it is sending across the boundary.
    #[must_use]
    pub fn owned_payload(&self) -> bool {
        true
    }
}

/// Explicit non-terminal status report for `poll_status` requests.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct JobStatusSnapshot {
    /// Job identifier being reported.
    pub job_id: u64,
    /// Current worker-observed non-terminal lifecycle state.
    ///
    /// Terminal outcomes must use [`WorkerOp::JobCompleted`] or
    /// [`WorkerOp::FinalizeCompleted`] so the coordinator does not lose the
    /// completion semantics attached to those messages. Coordinator-owned
    /// phases such as `created`, `draining`, and `finalizing` must not be
    /// reported via `status_snapshot`; they are driven by explicit control
    /// messages in the cancellation protocol.
    pub state: JobState,
    /// Optional human-readable detail for diagnostics.
    pub detail: Option<String>,
}

/// The result of a completed job.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct JobResult {
    /// Job identifier.
    pub job_id: u64,
    /// Four-valued outcome matching Asupersync's Outcome semantics.
    pub outcome: JobOutcome,
}

/// Job completion outcome using the four-valued Asupersync model.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "status")]
pub enum JobOutcome {
    /// Job completed successfully.
    Ok {
        /// Serialized result payload.
        payload: Vec<u8>,
    },
    /// Job completed with an application error.
    Err {
        /// Error code.
        code: String,
        /// Human-readable error message.
        message: String,
    },
    /// Job was cancelled through the cancellation protocol.
    Cancelled {
        /// Cancellation reason.
        reason: String,
    },
    /// Job panicked (worker caught the panic).
    Panicked {
        /// Panic payload description.
        message: String,
    },
}

impl JobOutcome {
    /// The concrete v1 result path uses structured-cloned owned bytes.
    #[must_use]
    pub fn payload_transfer(&self) -> Option<WorkerPayloadTransfer> {
        match self {
            Self::Ok { .. } => Some(WorkerPayloadTransfer::StructuredClone),
            Self::Err { .. } | Self::Cancelled { .. } | Self::Panicked { .. } => None,
        }
    }
}

/// A structured diagnostic event from the worker.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DiagnosticEvent {
    /// Severity level.
    pub level: DiagnosticLevel,
    /// Diagnostic category.
    pub category: String,
    /// Human-readable message.
    pub message: String,
    /// Optional structured metadata.
    pub metadata: Option<String>,
}

/// Diagnostic severity levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum DiagnosticLevel {
    /// Informational (lifecycle transitions, metrics).
    Info,
    /// Warning (degraded state, approaching limits).
    Warn,
    /// Error (failed operation, requires attention).
    Error,
}

// ─── Job State Machine ───────────────────────────────────────────────

/// Job lifecycle state matching the worker offload policy.
///
/// Transitions:
/// ```text
/// Created → Queued → Running → Completed
///           ↓          ↓         ↘
///      CancelRequested → Draining → Finalizing → Completed
///                      ↘
///                       Completed (cancel raced with natural completion before ack)
///
/// Any non-terminal state may also transition to `Failed` if the worker
/// session dies or is replaced before the job reaches a terminal outcome.
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum JobState {
    /// Job created but not yet dispatched to the worker.
    Created,
    /// Job dispatched, waiting for worker to start.
    Queued,
    /// Job actively running in the worker.
    Running,
    /// Cancellation requested, waiting for acknowledgement.
    CancelRequested,
    /// Worker acknowledged cancellation, draining in progress.
    Draining,
    /// Drain completed, finalization in progress.
    Finalizing,
    /// Job completed (with any outcome).
    Completed,
    /// Job failed before completion.
    Failed,
}

impl fmt::Display for JobState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Created => write!(f, "created"),
            Self::Queued => write!(f, "queued"),
            Self::Running => write!(f, "running"),
            Self::CancelRequested => write!(f, "cancel_requested"),
            Self::Draining => write!(f, "draining"),
            Self::Finalizing => write!(f, "finalizing"),
            Self::Completed => write!(f, "completed"),
            Self::Failed => write!(f, "failed"),
        }
    }
}

impl JobState {
    /// Whether this state is terminal.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed)
    }

    /// Whether a worker may report this state via `status_snapshot`.
    ///
    /// Only states the worker can observe organically are allowed.
    /// `CancelRequested`, `Draining`, and `Finalizing` are driven by
    /// the coordinator's explicit cancel protocol messages.
    #[must_use]
    pub const fn allowed_in_status_snapshot(self) -> bool {
        matches!(self, Self::Queued | Self::Running)
    }

    /// Check whether the given transition is valid.
    #[must_use]
    pub fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Created, Self::Queued | Self::Failed)
                | (
                    Self::Queued,
                    Self::Running | Self::CancelRequested | Self::Completed | Self::Failed,
                )
                | (
                    Self::Running,
                    Self::Completed | Self::CancelRequested | Self::Failed,
                )
                | (
                    Self::CancelRequested,
                    Self::Completed | Self::Draining | Self::Failed,
                )
                | (Self::Draining, Self::Finalizing | Self::Failed)
                | (Self::Finalizing, Self::Completed | Self::Failed)
        )
    }
}

// ─── Tracked Job ─────────────────────────────────────────────────────

/// Main-thread tracking state for an in-flight job.
#[derive(Debug)]
pub struct TrackedJob {
    /// Job identifier.
    pub job_id: u64,
    /// Region that owns this job.
    pub region_id: u64,
    /// Current lifecycle state.
    pub state: JobState,
    /// Sequence number of the last message sent about this job.
    pub last_seq_no: u64,
}

impl TrackedJob {
    /// Create a new tracked job in the Created state.
    #[must_use]
    pub fn new(job_id: u64, region_id: u64) -> Self {
        Self {
            job_id,
            region_id,
            state: JobState::Created,
            last_seq_no: 0,
        }
    }

    /// Attempt a state transition, returning an error on invalid transitions.
    pub fn transition_to(&mut self, next: JobState) -> Result<JobState, WorkerChannelError> {
        if !self.state.can_transition_to(next) {
            return Err(WorkerChannelError::InvalidTransition {
                job_id: self.job_id,
                from: self.state,
                to: next,
            });
        }
        let prev = self.state;
        self.state = next;
        Ok(prev)
    }
}

// ─── Coordinator (main-thread side) ──────────────────────────────────

/// Main-thread coordinator for worker lifecycle management.
///
/// Manages the outbound message queue, tracks in-flight jobs, and enforces
/// the coordination protocol.
#[derive(Debug)]
pub struct WorkerCoordinator {
    /// Outbound message queue.
    outbox: VecDeque<WorkerEnvelope>,
    /// Monotonically increasing sequence number.
    next_seq: u64,
    /// Monotonically increasing deterministic decision sequence.
    next_decision_seq: u64,
    /// Monotonically increasing message ID.
    next_message_id: u64,
    /// Active tracked jobs by job_id.
    jobs: std::collections::BTreeMap<u64, TrackedJob>,
    /// Current deterministic seed.
    seed: u64,
    /// Current host turn ID.
    turn: u64,
    /// Highest inbound worker sequence accepted by this coordinator session.
    last_inbound_seq_no: u64,
    /// Worker runtime instance currently associated with the inbound session.
    active_worker_id: Option<String>,
    /// Whether the worker has reported bootstrap readiness.
    worker_ready: bool,
    /// Whether a shutdown has been requested.
    shutdown_requested: bool,
}

impl WorkerCoordinator {
    /// Create a new coordinator with the given deterministic seed.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self {
            outbox: VecDeque::new(),
            next_seq: 1,
            next_decision_seq: 1,
            next_message_id: 1,
            jobs: std::collections::BTreeMap::new(),
            seed,
            turn: 0,
            last_inbound_seq_no: 0,
            active_worker_id: None,
            worker_ready: false,
            shutdown_requested: false,
        }
    }

    /// Advance the host turn counter.
    pub fn advance_turn(&mut self) {
        self.turn += 1;
    }

    /// Whether the worker has reported bootstrap readiness.
    #[must_use]
    pub fn is_worker_ready(&self) -> bool {
        self.worker_ready
    }

    /// Whether a shutdown has been requested.
    #[must_use]
    pub fn is_shutdown_requested(&self) -> bool {
        self.shutdown_requested
    }

    /// Number of in-flight (non-completed) jobs.
    #[must_use]
    pub fn inflight_count(&self) -> usize {
        self.jobs
            .values()
            .filter(|j| j.state != JobState::Completed && j.state != JobState::Failed)
            .count()
    }

    /// Enqueue a spawn-job message. Returns the job_id.
    pub fn spawn_job(
        &mut self,
        job_id: u64,
        region_id: u64,
        task_id: u64,
        obligation_id: u64,
        payload: Vec<u8>,
    ) -> Result<u64, WorkerChannelError> {
        if !self.worker_ready {
            return Err(WorkerChannelError::WorkerNotReady);
        }
        if self.shutdown_requested {
            return Err(WorkerChannelError::ShutdownInProgress);
        }
        validate_payload_size(payload.len())?;
        if let Some(existing_state) = self.jobs.get(&job_id).map(|job| job.state) {
            if existing_state == JobState::Failed {
                self.jobs.remove(&job_id);
            } else {
                return Err(WorkerChannelError::DuplicateJobId(job_id));
            }
        }

        let mut tracked = TrackedJob::new(job_id, region_id);
        tracked.transition_to(JobState::Queued)?;

        let envelope = self.make_envelope(WorkerOp::SpawnJob(SpawnJobRequest {
            job_id,
            region_id,
            task_id,
            obligation_id,
            payload,
        }));
        tracked.last_seq_no = envelope.seq_no;
        self.jobs.insert(job_id, tracked);
        self.outbox.push_back(envelope);
        Ok(job_id)
    }

    /// Enqueue a cancel-job message.
    pub fn cancel_job(&mut self, job_id: u64, reason: String) -> Result<(), WorkerChannelError> {
        if self.shutdown_requested {
            return Err(WorkerChannelError::ShutdownInProgress);
        }
        {
            let job = self
                .jobs
                .get_mut(&job_id)
                .ok_or(WorkerChannelError::UnknownJobId(job_id))?;
            job.transition_to(JobState::CancelRequested)?;
        }

        self.enqueue_job_message(job_id, WorkerOp::CancelJob { job_id, reason })
    }

    /// Enqueue an explicit poll-status message for an in-flight job.
    pub fn poll_status(&mut self, job_id: u64) -> Result<(), WorkerChannelError> {
        if self.shutdown_requested {
            return Err(WorkerChannelError::ShutdownInProgress);
        }
        let state = self
            .jobs
            .get(&job_id)
            .ok_or(WorkerChannelError::UnknownJobId(job_id))?
            .state;
        if state.is_terminal() {
            return Err(WorkerChannelError::JobNotPollable { job_id, state });
        }
        self.enqueue_job_message(job_id, WorkerOp::PollStatus { job_id })
    }

    /// Enqueue a shutdown message.
    pub fn request_shutdown(&mut self, reason: String) -> Result<(), WorkerChannelError> {
        if self.shutdown_requested {
            return Err(WorkerChannelError::ShutdownInProgress);
        }
        self.shutdown_requested = true;
        self.discard_outbound_session_messages();
        let envelope = self.make_envelope(WorkerOp::ShutdownWorker { reason });
        self.outbox.push_back(envelope);
        Ok(())
    }

    /// Process an inbound message from the worker.
    pub fn handle_inbound(&mut self, envelope: &WorkerEnvelope) -> Result<(), WorkerChannelError> {
        self.prepare_inbound(envelope)?;
        match &envelope.op {
            WorkerOp::BootstrapReady { worker_id } => {
                self.active_worker_id = Some(worker_id.clone());
                self.worker_ready = true;
                self.shutdown_requested = false;
                Ok(())
            }
            WorkerOp::BootstrapFailed { reason, .. } => {
                self.fail_nonterminal_jobs();
                self.discard_outbound_session_messages();
                // Clear active_worker_id so the failed worker cannot send
                // follow-up messages (Diagnostic, ShutdownCompleted) that
                // would pass the session check and potentially interfere
                // with a replacement worker's bootstrap sequence.
                self.active_worker_id = None;
                self.worker_ready = false;
                self.shutdown_requested = false;
                Err(WorkerChannelError::BootstrapFailed(reason.clone()))
            }
            WorkerOp::StatusSnapshot(snapshot) => self.handle_status_snapshot(snapshot),
            WorkerOp::JobCompleted(result) => {
                let job = self
                    .jobs
                    .get_mut(&result.job_id)
                    .ok_or(WorkerChannelError::UnknownJobId(result.job_id))?;
                if !matches!(
                    job.state,
                    JobState::Queued | JobState::Running | JobState::CancelRequested
                ) {
                    return Err(WorkerChannelError::UnexpectedCompletionPhase {
                        job_id: result.job_id,
                        state: job.state,
                    });
                }
                job.transition_to(JobState::Completed)?;
                Ok(())
            }
            WorkerOp::CancelAcknowledged { job_id } => {
                if !self.jobs.contains_key(job_id) {
                    return Err(WorkerChannelError::UnknownJobId(*job_id));
                }
                // Once shutdown is in progress, do not emit new job-scoped
                // control traffic. The pending job will be failed when the
                // worker reports shutdown completion or the session is reset.
                if self.shutdown_requested {
                    return Ok(());
                }
                {
                    let job = self
                        .jobs
                        .get_mut(job_id)
                        .ok_or(WorkerChannelError::UnknownJobId(*job_id))?;
                    job.transition_to(JobState::Draining)?;
                }
                self.enqueue_job_message(*job_id, WorkerOp::DrainJob { job_id: *job_id })
            }
            WorkerOp::DrainCompleted { job_id } => {
                if !self.jobs.contains_key(job_id) {
                    return Err(WorkerChannelError::UnknownJobId(*job_id));
                }
                // Once shutdown is in progress, do not continue the explicit
                // cancel protocol with new outbound drain/finalize traffic.
                if self.shutdown_requested {
                    return Ok(());
                }
                {
                    let job = self
                        .jobs
                        .get_mut(job_id)
                        .ok_or(WorkerChannelError::UnknownJobId(*job_id))?;
                    job.transition_to(JobState::Finalizing)?;
                }
                self.enqueue_job_message(*job_id, WorkerOp::FinalizeJob { job_id: *job_id })
            }
            WorkerOp::FinalizeCompleted { job_id } => {
                let job = self
                    .jobs
                    .get_mut(job_id)
                    .ok_or(WorkerChannelError::UnknownJobId(*job_id))?;
                if job.state != JobState::Finalizing {
                    return Err(WorkerChannelError::InvalidTransition {
                        job_id: *job_id,
                        from: job.state,
                        to: JobState::Completed,
                    });
                }
                job.transition_to(JobState::Completed)?;
                Ok(())
            }
            WorkerOp::ShutdownCompleted => {
                self.fail_nonterminal_jobs();
                self.discard_outbound_session_messages();
                self.active_worker_id = None;
                self.shutdown_requested = false;
                self.worker_ready = false;
                Ok(())
            }
            WorkerOp::Diagnostic(_) => Ok(()),
            // Main-to-worker ops should not be inbound
            WorkerOp::SpawnJob(_)
            | WorkerOp::PollStatus { .. }
            | WorkerOp::CancelJob { .. }
            | WorkerOp::DrainJob { .. }
            | WorkerOp::FinalizeJob { .. }
            | WorkerOp::ShutdownWorker { .. } => Err(WorkerChannelError::UnexpectedDirection {
                op: format!("{:?}", std::mem::discriminant(&envelope.op)),
            }),
        }
    }

    /// Drain the next outbound message, if any.
    #[must_use]
    pub fn drain_outbox(&mut self) -> Option<WorkerEnvelope> {
        self.outbox.pop_front()
    }

    /// Get the current state of a tracked job.
    #[must_use]
    pub fn job_state(&self, job_id: u64) -> Option<JobState> {
        self.jobs.get(&job_id).map(|j| j.state)
    }

    /// Remove a terminal job from tracking to prevent memory leaks.
    /// Returns the last known state of the job, or None if unknown.
    pub fn remove_job(&mut self, job_id: u64) -> Option<JobState> {
        self.jobs.remove(&job_id).map(|j| j.state)
    }

    fn enqueue_job_message(&mut self, job_id: u64, op: WorkerOp) -> Result<(), WorkerChannelError> {
        if !self.jobs.contains_key(&job_id) {
            return Err(WorkerChannelError::UnknownJobId(job_id));
        }
        let envelope = self.make_envelope(op);
        if let Some(job) = self.jobs.get_mut(&job_id) {
            job.last_seq_no = envelope.seq_no;
        }
        self.outbox.push_back(envelope);
        Ok(())
    }

    fn handle_status_snapshot(
        &mut self,
        snapshot: &JobStatusSnapshot,
    ) -> Result<(), WorkerChannelError> {
        if snapshot.state.is_terminal() {
            return Err(WorkerChannelError::TerminalStatusSnapshot {
                job_id: snapshot.job_id,
                state: snapshot.state,
            });
        }
        if !snapshot.state.allowed_in_status_snapshot() {
            return Err(WorkerChannelError::InvalidStatusSnapshotState {
                job_id: snapshot.job_id,
                state: snapshot.state,
            });
        }
        let job = self
            .jobs
            .get_mut(&snapshot.job_id)
            .ok_or(WorkerChannelError::UnknownJobId(snapshot.job_id))?;

        // Ignore stale status snapshots that arrive after the job has moved
        // into cancellation phases or reached a terminal state. The worker
        // emitted these before observing our state transition.
        if !matches!(
            job.state,
            JobState::Created | JobState::Queued | JobState::Running
        ) {
            return Ok(());
        }

        if job.state != snapshot.state {
            job.transition_to(snapshot.state)?;
        }
        Ok(())
    }

    fn prepare_inbound(&mut self, envelope: &WorkerEnvelope) -> Result<(), WorkerChannelError> {
        envelope.validate()?;
        if self.should_reset_inbound_session(&envelope.op) {
            self.fail_nonterminal_jobs();
            self.reset_inbound_session();
        }
        self.validate_inbound_worker_session(envelope)?;
        self.validate_inbound_sequence(envelope.seq_no)?;
        self.record_inbound_sequence(envelope.seq_no);
        Ok(())
    }

    fn should_reset_inbound_session(&self, op: &WorkerOp) -> bool {
        match op {
            WorkerOp::BootstrapReady { worker_id }
            | WorkerOp::BootstrapFailed { worker_id, .. } => {
                self.active_worker_id.as_deref() != Some(worker_id.as_str())
            }
            _ => false,
        }
    }

    fn fail_nonterminal_jobs(&mut self) {
        for job in self.jobs.values_mut() {
            if job.state.is_terminal() {
                continue;
            }
            let _ = job.transition_to(JobState::Failed);
        }
    }

    fn discard_outbound_session_messages(&mut self) {
        self.outbox.clear();
    }

    fn reset_inbound_session(&mut self) {
        self.last_inbound_seq_no = 0;
        self.discard_outbound_session_messages();
    }

    fn validate_inbound_sequence(&self, seq_no: u64) -> Result<(), WorkerChannelError> {
        if seq_no <= self.last_inbound_seq_no {
            return Err(WorkerChannelError::InboundSequenceNotFresh {
                last_seen: self.last_inbound_seq_no,
                actual: seq_no,
            });
        }
        Ok(())
    }

    fn record_inbound_sequence(&mut self, seq_no: u64) {
        self.last_inbound_seq_no = seq_no;
    }

    fn validate_inbound_worker_session(
        &self,
        envelope: &WorkerEnvelope,
    ) -> Result<(), WorkerChannelError> {
        match &envelope.op {
            WorkerOp::BootstrapReady { .. }
            | WorkerOp::BootstrapFailed { .. }
            | WorkerOp::SpawnJob(_)
            | WorkerOp::PollStatus { .. }
            | WorkerOp::CancelJob { .. }
            | WorkerOp::DrainJob { .. }
            | WorkerOp::FinalizeJob { .. }
            | WorkerOp::ShutdownWorker { .. } => Ok(()),
            _ => {
                let actual = envelope
                    .worker_id
                    .as_deref()
                    .ok_or(WorkerChannelError::MissingWorkerSessionIdentity)?;
                if self.active_worker_id.as_deref() == Some(actual) {
                    return Ok(());
                }
                Err(WorkerChannelError::InboundWorkerSessionMismatch {
                    expected: self.active_worker_id.clone(),
                    actual: actual.to_string(),
                })
            }
        }
    }

    fn make_envelope(&mut self, op: WorkerOp) -> WorkerEnvelope {
        let msg_id = self.next_message_id;
        let seq = self.next_seq;
        let decision_seq = self.next_decision_seq;
        self.next_message_id += 1;
        self.next_seq += 1;
        self.next_decision_seq += 1;
        WorkerEnvelope::new_with_decision_seq(msg_id, seq, decision_seq, self.seed, self.turn, op)
    }
}

// ─── Errors ──────────────────────────────────────────────────────────

/// Errors from the worker coordination channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkerChannelError {
    /// Protocol version mismatch.
    VersionMismatch {
        /// Protocol version expected by the receiver.
        expected: u32,
        /// Protocol version provided by the sender.
        actual: u32,
    },
    /// Replay digest does not match the envelope metadata.
    ReplayHashMismatch {
        /// Expected replay digest for the envelope metadata.
        expected: u64,
        /// Actual replay digest carried by the envelope.
        actual: u64,
    },
    /// Inbound worker sequence repeated or regressed relative to coordinator state.
    InboundSequenceNotFresh {
        /// Highest inbound sequence previously observed by this coordinator.
        last_seen: u64,
        /// Sequence number carried by the rejected envelope.
        actual: u64,
    },
    /// Worker-originated messages must carry the worker runtime instance id.
    MissingWorkerSessionIdentity,
    /// Main-thread-originated messages must not carry a worker runtime instance id.
    UnexpectedWorkerSessionIdentity(String),
    /// Envelope worker runtime id disagrees with the operation payload.
    WorkerIdentityMismatch {
        /// Worker id implied by the operation payload.
        expected: String,
        /// Worker id carried by the envelope metadata.
        actual: String,
    },
    /// Inbound message came from a different worker runtime instance than the active session.
    InboundWorkerSessionMismatch {
        /// Active worker runtime id, if any.
        expected: Option<String>,
        /// Worker runtime id carried by the inbound envelope.
        actual: String,
    },
    /// Payload exceeds maximum size.
    PayloadTooLarge {
        /// Serialized payload size in bytes.
        size: usize,
        /// Maximum payload size in bytes permitted by the protocol.
        max: usize,
    },
    /// Invalid job state transition.
    InvalidTransition {
        /// Job identifier whose state transition was rejected.
        job_id: u64,
        /// State observed before the rejected transition.
        from: JobState,
        /// Target state requested by the rejected transition.
        to: JobState,
    },
    /// A status snapshot tried to report a terminal state.
    TerminalStatusSnapshot {
        /// Job identifier carried by the terminal snapshot.
        job_id: u64,
        /// Terminal state that must not be reported via `status_snapshot`.
        state: JobState,
    },
    /// A status snapshot tried to report a state owned by explicit coordinator control flow.
    InvalidStatusSnapshotState {
        /// Job identifier carried by the invalid snapshot.
        job_id: u64,
        /// State that must not be reported via `status_snapshot`.
        state: JobState,
    },
    /// A completion result arrived while the explicit cancellation protocol was active.
    UnexpectedCompletionPhase {
        /// Job identifier whose completion arrived out of phase.
        job_id: u64,
        /// Coordinator state when the completion arrived.
        state: JobState,
    },
    /// Worker has not reported bootstrap readiness.
    WorkerNotReady,
    /// Shutdown is already in progress.
    ShutdownInProgress,
    /// Duplicate job ID.
    DuplicateJobId(u64),
    /// Unknown job ID.
    UnknownJobId(u64),
    /// Job is terminal and can no longer accept poll requests.
    JobNotPollable {
        /// Job identifier whose poll request was rejected.
        job_id: u64,
        /// Terminal state that makes the job non-pollable.
        state: JobState,
    },
    /// Worker bootstrap failed.
    BootstrapFailed(String),
    /// Received a message in the wrong direction.
    UnexpectedDirection {
        /// Operation received from the wrong side of the channel.
        op: String,
    },
}

impl fmt::Display for WorkerChannelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::VersionMismatch { expected, actual } => {
                write!(
                    f,
                    "protocol version mismatch: expected {expected}, got {actual}"
                )
            }
            Self::ReplayHashMismatch { expected, actual } => {
                write!(f, "replay hash mismatch: expected {expected}, got {actual}")
            }
            Self::InboundSequenceNotFresh { last_seen, actual } => {
                write!(
                    f,
                    "inbound worker sequence is not fresh: saw {actual} after {last_seen}"
                )
            }
            Self::MissingWorkerSessionIdentity => {
                write!(
                    f,
                    "worker-originated envelope missing worker session identity"
                )
            }
            Self::UnexpectedWorkerSessionIdentity(worker_id) => {
                write!(
                    f,
                    "main-thread envelope unexpectedly carried worker session identity {worker_id}"
                )
            }
            Self::WorkerIdentityMismatch { expected, actual } => {
                write!(
                    f,
                    "worker identity mismatch: envelope carried {actual}, operation expects {expected}"
                )
            }
            Self::InboundWorkerSessionMismatch { expected, actual } => match expected {
                Some(expected) => write!(
                    f,
                    "inbound worker session mismatch: active session {expected}, got {actual}"
                ),
                None => write!(
                    f,
                    "inbound worker session mismatch: no active session, got {actual}"
                ),
            },
            Self::PayloadTooLarge { size, max } => {
                write!(
                    f,
                    "payload too large: {size} bytes exceeds {max} byte limit"
                )
            }
            Self::InvalidTransition { job_id, from, to } => {
                write!(f, "invalid job {job_id} transition: {from} → {to}")
            }
            Self::TerminalStatusSnapshot { job_id, state } => {
                write!(
                    f,
                    "job {job_id} reported terminal state {state} via status snapshot"
                )
            }
            Self::InvalidStatusSnapshotState { job_id, state } => {
                write!(
                    f,
                    "job {job_id} reported coordinator-owned state {state} via status snapshot"
                )
            }
            Self::UnexpectedCompletionPhase { job_id, state } => {
                write!(
                    f,
                    "job {job_id} reported completion while coordinator was in {state}"
                )
            }
            Self::WorkerNotReady => write!(f, "worker has not reported bootstrap readiness"),
            Self::ShutdownInProgress => write!(f, "shutdown already in progress"),
            Self::DuplicateJobId(id) => write!(f, "duplicate job id: {id}"),
            Self::UnknownJobId(id) => write!(f, "unknown job id: {id}"),
            Self::JobNotPollable { job_id, state } => {
                write!(f, "job {job_id} is terminal ({state}) and cannot be polled")
            }
            Self::BootstrapFailed(reason) => write!(f, "worker bootstrap failed: {reason}"),
            Self::UnexpectedDirection { op } => {
                write!(f, "received outbound-only operation as inbound: {op}")
            }
        }
    }
}

impl std::error::Error for WorkerChannelError {}

// ─── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
#[path = "worker_channel_inline_tests.rs"]
mod tests;
