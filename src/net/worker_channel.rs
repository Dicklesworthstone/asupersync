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
//! [`BrowserReactor`] through its `register_message_port()` API, delivering
//! events via the reactor's token-based readiness model.

use std::collections::VecDeque;
use std::fmt;

/// Protocol version for the worker coordination envelope.
pub const WORKER_PROTOCOL_VERSION: u32 = 1;

/// Maximum payload size in bytes (256 KiB, matching policy).
pub const MAX_PAYLOAD_BYTES: usize = 262_144;

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
    /// Deterministic RNG seed for replay (propagated from parent Cx).
    pub seed: u64,
    /// Host turn ID at message creation (for deterministic scheduling).
    pub issued_at_turn: u64,
    /// The coordination operation.
    pub op: WorkerOp,
}

impl WorkerEnvelope {
    /// Create a new envelope with the given operation and sequence metadata.
    #[must_use]
    pub fn new(message_id: u64, seq_no: u64, seed: u64, issued_at_turn: u64, op: WorkerOp) -> Self {
        Self {
            version: WORKER_PROTOCOL_VERSION,
            message_id,
            seq_no,
            seed,
            issued_at_turn,
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
        if let WorkerOp::SpawnJob(ref req) = self.op {
            if req.payload.len() > MAX_PAYLOAD_BYTES {
                return Err(WorkerChannelError::PayloadTooLarge {
                    size: req.payload.len(),
                    max: MAX_PAYLOAD_BYTES,
                });
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
        /// Human-readable failure reason.
        reason: String,
    },

    // ── Work dispatch ────────────────────────────────────────────
    /// Main → worker: spawn a new job inside the worker runtime.
    SpawnJob(SpawnJobRequest),
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
    CancelAcknowledged { job_id: u64 },
    /// Worker → main: drain phase completed.
    DrainCompleted { job_id: u64 },
    /// Worker → main: finalize phase completed.
    FinalizeCompleted { job_id: u64 },

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
///                      ↓
///                CancelRequested → Draining → Finalizing → Completed
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
    /// Check whether the given transition is valid.
    #[must_use]
    pub fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Created, Self::Queued)
                | (Self::Queued, Self::Running)
                | (Self::Queued, Self::Completed)
                | (Self::Queued, Self::Failed)
                | (Self::Running, Self::Completed)
                | (Self::Running, Self::CancelRequested)
                | (Self::Running, Self::Failed)
                | (Self::CancelRequested, Self::Draining)
                | (Self::CancelRequested, Self::Completed)
                | (Self::Draining, Self::Finalizing)
                | (Self::Draining, Self::Completed)
                | (Self::Finalizing, Self::Completed)
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
    /// Monotonically increasing message ID.
    next_message_id: u64,
    /// Active tracked jobs by job_id.
    jobs: std::collections::BTreeMap<u64, TrackedJob>,
    /// Current deterministic seed.
    seed: u64,
    /// Current host turn ID.
    turn: u64,
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
            next_message_id: 1,
            jobs: std::collections::BTreeMap::new(),
            seed,
            turn: 0,
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
        if payload.len() > MAX_PAYLOAD_BYTES {
            return Err(WorkerChannelError::PayloadTooLarge {
                size: payload.len(),
                max: MAX_PAYLOAD_BYTES,
            });
        }
        if self.jobs.contains_key(&job_id) {
            return Err(WorkerChannelError::DuplicateJobId(job_id));
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
        {
            let job = self
                .jobs
                .get_mut(&job_id)
                .ok_or(WorkerChannelError::UnknownJobId(job_id))?;
            job.transition_to(JobState::CancelRequested)?;
        }

        let envelope = self.make_envelope(WorkerOp::CancelJob { job_id, reason });
        // Safe: we validated job_id exists above and never remove during this method.
        self.jobs.get_mut(&job_id).unwrap().last_seq_no = envelope.seq_no;
        self.outbox.push_back(envelope);
        Ok(())
    }

    /// Enqueue a shutdown message.
    pub fn request_shutdown(&mut self, reason: String) -> Result<(), WorkerChannelError> {
        if self.shutdown_requested {
            return Err(WorkerChannelError::ShutdownInProgress);
        }
        self.shutdown_requested = true;
        let envelope = self.make_envelope(WorkerOp::ShutdownWorker { reason });
        self.outbox.push_back(envelope);
        Ok(())
    }

    /// Process an inbound message from the worker.
    pub fn handle_inbound(&mut self, envelope: &WorkerEnvelope) -> Result<(), WorkerChannelError> {
        envelope.validate()?;
        match &envelope.op {
            WorkerOp::BootstrapReady { .. } => {
                self.worker_ready = true;
                Ok(())
            }
            WorkerOp::BootstrapFailed { reason } => {
                Err(WorkerChannelError::BootstrapFailed(reason.clone()))
            }
            WorkerOp::JobCompleted(result) => {
                let job = self
                    .jobs
                    .get_mut(&result.job_id)
                    .ok_or(WorkerChannelError::UnknownJobId(result.job_id))?;
                job.transition_to(JobState::Completed)?;
                Ok(())
            }
            WorkerOp::CancelAcknowledged { job_id } => {
                let job = self
                    .jobs
                    .get_mut(job_id)
                    .ok_or(WorkerChannelError::UnknownJobId(*job_id))?;
                job.transition_to(JobState::Draining)?;
                Ok(())
            }
            WorkerOp::DrainCompleted { job_id } => {
                let job = self
                    .jobs
                    .get_mut(job_id)
                    .ok_or(WorkerChannelError::UnknownJobId(*job_id))?;
                job.transition_to(JobState::Finalizing)?;
                Ok(())
            }
            WorkerOp::FinalizeCompleted { job_id } => {
                let job = self
                    .jobs
                    .get_mut(job_id)
                    .ok_or(WorkerChannelError::UnknownJobId(*job_id))?;
                job.transition_to(JobState::Completed)?;
                Ok(())
            }
            WorkerOp::ShutdownCompleted => {
                self.shutdown_requested = false;
                Ok(())
            }
            WorkerOp::Diagnostic(_) => Ok(()),
            // Main-to-worker ops should not be inbound
            WorkerOp::SpawnJob(_)
            | WorkerOp::CancelJob { .. }
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

    fn make_envelope(&mut self, op: WorkerOp) -> WorkerEnvelope {
        let msg_id = self.next_message_id;
        let seq = self.next_seq;
        self.next_message_id += 1;
        self.next_seq += 1;
        WorkerEnvelope::new(msg_id, seq, self.seed, self.turn, op)
    }
}

// ─── Errors ──────────────────────────────────────────────────────────

/// Errors from the worker coordination channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkerChannelError {
    /// Protocol version mismatch.
    VersionMismatch { expected: u32, actual: u32 },
    /// Payload exceeds maximum size.
    PayloadTooLarge { size: usize, max: usize },
    /// Invalid job state transition.
    InvalidTransition {
        job_id: u64,
        from: JobState,
        to: JobState,
    },
    /// Worker has not reported bootstrap readiness.
    WorkerNotReady,
    /// Shutdown is already in progress.
    ShutdownInProgress,
    /// Duplicate job ID.
    DuplicateJobId(u64),
    /// Unknown job ID.
    UnknownJobId(u64),
    /// Worker bootstrap failed.
    BootstrapFailed(String),
    /// Received a message in the wrong direction.
    UnexpectedDirection { op: String },
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
            Self::PayloadTooLarge { size, max } => {
                write!(
                    f,
                    "payload too large: {size} bytes exceeds {max} byte limit"
                )
            }
            Self::InvalidTransition { job_id, from, to } => {
                write!(f, "invalid job {job_id} transition: {from} → {to}")
            }
            Self::WorkerNotReady => write!(f, "worker has not reported bootstrap readiness"),
            Self::ShutdownInProgress => write!(f, "shutdown already in progress"),
            Self::DuplicateJobId(id) => write!(f, "duplicate job id: {id}"),
            Self::UnknownJobId(id) => write!(f, "unknown job id: {id}"),
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
mod tests {
    use super::*;

    fn bootstrap_ready_envelope(seq: u64) -> WorkerEnvelope {
        WorkerEnvelope::new(
            seq,
            seq,
            42,
            0,
            WorkerOp::BootstrapReady {
                worker_id: "test-worker-1".into(),
            },
        )
    }

    #[test]
    fn coordinator_rejects_spawn_before_bootstrap() {
        let mut coord = WorkerCoordinator::new(42);
        let result = coord.spawn_job(1, 100, 200, 300, vec![1, 2, 3]);
        assert_eq!(result, Err(WorkerChannelError::WorkerNotReady));
    }

    #[test]
    fn coordinator_accepts_spawn_after_bootstrap() {
        let mut coord = WorkerCoordinator::new(42);
        coord.handle_inbound(&bootstrap_ready_envelope(1)).unwrap();
        assert!(coord.is_worker_ready());

        let job_id = coord.spawn_job(1, 100, 200, 300, vec![1, 2, 3]).unwrap();
        assert_eq!(job_id, 1);
        assert_eq!(coord.job_state(1), Some(JobState::Queued));
        assert_eq!(coord.inflight_count(), 1);

        let msg = coord.drain_outbox().unwrap();
        assert!(matches!(msg.op, WorkerOp::SpawnJob(_)));
        assert_eq!(msg.version, WORKER_PROTOCOL_VERSION);
        assert_eq!(msg.seed, 42);
    }

    #[test]
    fn coordinator_tracks_full_job_lifecycle() {
        let mut coord = WorkerCoordinator::new(42);
        coord.handle_inbound(&bootstrap_ready_envelope(1)).unwrap();
        coord.spawn_job(1, 100, 200, 300, vec![]).unwrap();
        let _ = coord.drain_outbox(); // consume spawn message

        // Job completed successfully (Queued → Completed is valid for
        // fast-completing jobs that skip the Running notification)
        let result_env = WorkerEnvelope::new(
            2,
            2,
            42,
            1,
            WorkerOp::JobCompleted(JobResult {
                job_id: 1,
                outcome: JobOutcome::Ok { payload: vec![42] },
            }),
        );
        coord.handle_inbound(&result_env).unwrap();
        assert_eq!(coord.job_state(1), Some(JobState::Completed));
        assert_eq!(coord.inflight_count(), 0);
    }

    #[test]
    fn coordinator_tracks_cancellation_lifecycle() {
        let mut coord = WorkerCoordinator::new(42);
        coord.handle_inbound(&bootstrap_ready_envelope(1)).unwrap();
        coord.spawn_job(1, 100, 200, 300, vec![]).unwrap();
        let _ = coord.drain_outbox();

        // Simulate: job starts running (would come from worker)
        // For tracking, we transition manually:
        coord.jobs.get_mut(&1).unwrap().state = JobState::Running;

        // Request cancellation
        coord.cancel_job(1, "test cancel".into()).unwrap();
        assert_eq!(coord.job_state(1), Some(JobState::CancelRequested));
        let cancel_msg = coord.drain_outbox().unwrap();
        assert!(matches!(cancel_msg.op, WorkerOp::CancelJob { .. }));

        // Worker acknowledges
        let ack = WorkerEnvelope::new(3, 3, 42, 2, WorkerOp::CancelAcknowledged { job_id: 1 });
        coord.handle_inbound(&ack).unwrap();
        assert_eq!(coord.job_state(1), Some(JobState::Draining));

        // Drain completed
        let drain = WorkerEnvelope::new(4, 4, 42, 3, WorkerOp::DrainCompleted { job_id: 1 });
        coord.handle_inbound(&drain).unwrap();
        assert_eq!(coord.job_state(1), Some(JobState::Finalizing));

        // Finalize completed
        let finalize = WorkerEnvelope::new(5, 5, 42, 4, WorkerOp::FinalizeCompleted { job_id: 1 });
        coord.handle_inbound(&finalize).unwrap();
        assert_eq!(coord.job_state(1), Some(JobState::Completed));
    }

    #[test]
    fn coordinator_rejects_invalid_transition() {
        let mut coord = WorkerCoordinator::new(42);
        coord.handle_inbound(&bootstrap_ready_envelope(1)).unwrap();
        coord.spawn_job(1, 100, 200, 300, vec![]).unwrap();
        let _ = coord.drain_outbox();

        // Job is Queued, cannot go directly to CancelRequested
        // (must be Running first)
        let result = coord.cancel_job(1, "bad cancel".into());
        assert!(matches!(
            result,
            Err(WorkerChannelError::InvalidTransition { .. })
        ));
    }

    #[test]
    fn coordinator_rejects_oversized_payload() {
        let mut coord = WorkerCoordinator::new(42);
        coord.handle_inbound(&bootstrap_ready_envelope(1)).unwrap();
        let big_payload = vec![0u8; MAX_PAYLOAD_BYTES + 1];
        let result = coord.spawn_job(1, 100, 200, 300, big_payload);
        assert!(matches!(
            result,
            Err(WorkerChannelError::PayloadTooLarge { .. })
        ));
    }

    #[test]
    fn coordinator_rejects_duplicate_job_id() {
        let mut coord = WorkerCoordinator::new(42);
        coord.handle_inbound(&bootstrap_ready_envelope(1)).unwrap();
        coord.spawn_job(1, 100, 200, 300, vec![]).unwrap();
        let result = coord.spawn_job(1, 100, 200, 300, vec![]);
        assert_eq!(result, Err(WorkerChannelError::DuplicateJobId(1)));
    }

    #[test]
    fn coordinator_shutdown_lifecycle() {
        let mut coord = WorkerCoordinator::new(42);
        coord.handle_inbound(&bootstrap_ready_envelope(1)).unwrap();

        coord.request_shutdown("test shutdown".into()).unwrap();
        assert!(coord.is_shutdown_requested());

        let msg = coord.drain_outbox().unwrap();
        assert!(matches!(msg.op, WorkerOp::ShutdownWorker { .. }));

        // Reject spawn during shutdown
        let result = coord.spawn_job(1, 100, 200, 300, vec![]);
        assert_eq!(result, Err(WorkerChannelError::ShutdownInProgress));

        // Worker completes shutdown
        let done = WorkerEnvelope::new(2, 2, 42, 1, WorkerOp::ShutdownCompleted);
        coord.handle_inbound(&done).unwrap();
        assert!(!coord.is_shutdown_requested());
    }

    #[test]
    fn coordinator_rejects_wrong_direction_messages() {
        let mut coord = WorkerCoordinator::new(42);
        coord.handle_inbound(&bootstrap_ready_envelope(1)).unwrap();

        // Worker should not send SpawnJob to coordinator
        let bad = WorkerEnvelope::new(
            2,
            2,
            42,
            1,
            WorkerOp::SpawnJob(SpawnJobRequest {
                job_id: 1,
                region_id: 100,
                task_id: 200,
                obligation_id: 300,
                payload: vec![],
            }),
        );
        let result = coord.handle_inbound(&bad);
        assert!(matches!(
            result,
            Err(WorkerChannelError::UnexpectedDirection { .. })
        ));
    }

    #[test]
    fn envelope_validates_version() {
        let mut env = WorkerEnvelope::new(
            1,
            1,
            42,
            0,
            WorkerOp::BootstrapReady {
                worker_id: "w".into(),
            },
        );
        assert!(env.validate().is_ok());

        env.version = 99;
        assert!(matches!(
            env.validate(),
            Err(WorkerChannelError::VersionMismatch { .. })
        ));
    }

    #[test]
    fn envelope_validates_payload_size() {
        let env = WorkerEnvelope::new(
            1,
            1,
            42,
            0,
            WorkerOp::SpawnJob(SpawnJobRequest {
                job_id: 1,
                region_id: 100,
                task_id: 200,
                obligation_id: 300,
                payload: vec![0u8; MAX_PAYLOAD_BYTES + 1],
            }),
        );
        assert!(matches!(
            env.validate(),
            Err(WorkerChannelError::PayloadTooLarge { .. })
        ));
    }

    #[test]
    fn job_state_transitions_are_correct() {
        // Valid transitions
        assert!(JobState::Created.can_transition_to(JobState::Queued));
        assert!(JobState::Queued.can_transition_to(JobState::Running));
        assert!(JobState::Running.can_transition_to(JobState::Completed));
        assert!(JobState::Running.can_transition_to(JobState::CancelRequested));
        assert!(JobState::CancelRequested.can_transition_to(JobState::Draining));
        assert!(JobState::Draining.can_transition_to(JobState::Finalizing));
        assert!(JobState::Finalizing.can_transition_to(JobState::Completed));

        assert!(JobState::Queued.can_transition_to(JobState::Completed));

        // Invalid transitions
        assert!(!JobState::Created.can_transition_to(JobState::Running));
        assert!(!JobState::Created.can_transition_to(JobState::Completed));
        assert!(!JobState::Queued.can_transition_to(JobState::CancelRequested));
        assert!(!JobState::Completed.can_transition_to(JobState::Running));
    }

    #[test]
    fn envelope_serialization_round_trip() {
        let env = WorkerEnvelope::new(
            1,
            1,
            42,
            0,
            WorkerOp::SpawnJob(SpawnJobRequest {
                job_id: 1,
                region_id: 100,
                task_id: 200,
                obligation_id: 300,
                payload: vec![1, 2, 3],
            }),
        );
        let json = serde_json::to_string(&env).unwrap();
        let deserialized: WorkerEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(env, deserialized);
    }

    #[test]
    fn coordinator_sequence_numbers_are_monotonic() {
        let mut coord = WorkerCoordinator::new(42);
        coord.handle_inbound(&bootstrap_ready_envelope(1)).unwrap();

        coord.spawn_job(1, 100, 200, 300, vec![]).unwrap();
        coord.spawn_job(2, 100, 201, 301, vec![]).unwrap();

        let msg1 = coord.drain_outbox().unwrap();
        let msg2 = coord.drain_outbox().unwrap();
        assert!(msg2.seq_no > msg1.seq_no);
        assert!(msg2.message_id > msg1.message_id);
    }

    #[test]
    fn diagnostic_events_are_accepted() {
        let mut coord = WorkerCoordinator::new(42);
        coord.handle_inbound(&bootstrap_ready_envelope(1)).unwrap();

        let diag = WorkerEnvelope::new(
            2,
            2,
            42,
            1,
            WorkerOp::Diagnostic(DiagnosticEvent {
                level: DiagnosticLevel::Info,
                category: "lifecycle".into(),
                message: "worker initialized".into(),
                metadata: None,
            }),
        );
        assert!(coord.handle_inbound(&diag).is_ok());
    }
}
