//! Lab runtime for deterministic execution.
//!
//! The lab runtime executes tasks with:
//! - Virtual time (controlled advancement)
//! - Deterministic scheduling (seed-driven)
//! - Trace capture for replay
//! - Chaos injection for stress testing

use super::config::LabConfig;
use super::oracle::OracleSuite;
use crate::lab::chaos::{ChaosRng, ChaosStats};
use crate::record::ObligationKind;
use crate::record::task::TaskState;
use crate::runtime::RuntimeState;
use crate::runtime::config::ObligationLeakResponse;
use crate::runtime::deadline_monitor::{
    DeadlineMonitor, DeadlineWarning, MonitorConfig, default_warning_handler,
};
use crate::runtime::reactor::LabReactor;
use crate::runtime::scheduler::priority::ExactDispatchError;
use crate::runtime::scheduler::{DispatchLane, ScheduleCertificate};
use crate::time::VirtualClock;
use crate::trace::TraceBufferHandle;
use crate::trace::crashpack::{
    CrashPack, CrashPackConfig, CrashPackWriteError, CrashPackWriter, FailureInfo, FailureOutcome,
    FileCrashPackWriter, ReplayCommand, artifact_filename,
};
use crate::trace::event::TraceEventKind;
use crate::trace::recorder::TraceRecorder;
use crate::trace::replay::{
    CompactTaskId, ProductionSchedule, ProjectionError, ProjectionOptions, ReplayEvent,
    ReplayTrace, TraceMetadata,
};
use crate::trace::scoring::seed_fingerprint;
use crate::trace::{TraceData, TraceEvent, check_refinement_firewall};
use crate::trace::{canonicalize::trace_fingerprint, certificate::TraceCertificate};
use crate::types::Time;
use crate::types::{ObligationId, RegionId, TaskId};
use crate::util::det_hash::{DetHashMap, DetHashSet};
use crate::util::{ArenaIndex, DetEntropy, DetRng};
use parking_lot::Mutex;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::Duration;
use std::{fmt, future::Future};

/// Fail-closed, bounded execution of a production dispatch projection.
pub mod production_strict;

use production_strict::{
    ProductionReplayMode, StrictProductionReplayError, StrictProductionReplayTermination,
};

const AUTO_ARTIFACTS_ENV: &str = "ASUPERSYNC_AUTO_ARTIFACTS";
const TEST_ARTIFACTS_DIR_ENV: &str = "ASUPERSYNC_TEST_ARTIFACTS_DIR";
const LAB_TEST_SEED_ENV: &str = "ASUPERSYNC_LAB_TEST_SEED";
const LAB_TEST_WORKERS_ENV: &str = "ASUPERSYNC_WORKERS";
const LAB_TEST_MAX_STEPS_ENV: &str = "ASUPERSYNC_MAX_STEPS";
#[cfg(test)]
const PLAIN_RUNNER_FAILURE_PROBE_ENV: &str = "ASUPERSYNC_PLAIN_RUNNER_FAILURE_PROBE";

/// Summary of a trace certificate built from the current trace buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LabTraceCertificateSummary {
    /// Incremental hash of witnessed events.
    pub event_hash: u64,
    /// Total number of events witnessed.
    pub event_count: u64,
    /// Hash of scheduling decisions (from [`ScheduleCertificate`]).
    pub schedule_hash: u64,
}

/// Schema version for the exact lab dispatch projection.
pub const FORCED_SCHEDULE_SCHEMA_VERSION: u32 = 1;

/// Fixed magic prefix for a canonical [`ForcedSchedule`] artifact.
pub const FORCED_SCHEDULE_ARTIFACT_MAGIC: [u8; 8] = *b"ASUPFSC\0";

/// Canonical artifact codec version.
pub const FORCED_SCHEDULE_ARTIFACT_VERSION: u32 = 1;

/// Schema version for a reduced exact-dispatch candidate.
pub const FORCED_SCHEDULE_CANDIDATE_SCHEMA_VERSION: u32 = 1;

const FORCED_SCHEDULE_ARTIFACT_HEADER_LEN: usize = 40;
const FORCED_SCHEDULE_ARTIFACT_DISPATCH_LEN: usize = 29;
const FORCED_SCHEDULE_ARTIFACT_TERMINAL_LEN: usize = 26;
const FORCED_SCHEDULE_ARTIFACT_CHECKSUM_LEN: usize = 32;
const FORCED_SCHEDULE_ARTIFACT_COUNT_OFFSET: usize = 32;

/// Caller-owned resource bounds for decoding one forced-schedule artifact.
///
/// The decoder checks all three limits before reserving the dispatch vector.
/// `max_decoded_dispatch_bytes` bounds the in-memory `ForcedDispatch`
/// storage independently of the more compact wire representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForcedScheduleDecodeLimits {
    /// Maximum admitted encoded artifact length.
    pub max_encoded_bytes: usize,
    /// Maximum admitted dispatch count.
    pub max_dispatches: usize,
    /// Maximum admitted decoded dispatch-vector storage.
    pub max_decoded_dispatch_bytes: usize,
}

impl ForcedScheduleDecodeLimits {
    /// Creates explicit encoded-byte, dispatch-count, and allocation bounds.
    #[must_use]
    pub const fn new(
        max_encoded_bytes: usize,
        max_dispatches: usize,
        max_decoded_dispatch_bytes: usize,
    ) -> Self {
        Self {
            max_encoded_bytes,
            max_dispatches,
            max_decoded_dispatch_bytes,
        }
    }
}

/// One scheduler choice captured before the selected task was polled.
///
/// Unlike [`ReplayEvent::TaskScheduled`], this lab-only projection retains the
/// modeled worker and authoritative lane. That distinction is load-bearing for
/// exact replay: a task chosen from the wrong lane can change cancellation and
/// fairness semantics even when the task ID happens to match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForcedDispatch {
    task: CompactTaskId,
    worker: u32,
    lane: DispatchLane,
    at_step: u64,
    at_nanos: u64,
}

impl ForcedDispatch {
    /// Full arena identity (slot plus generation) of the selected task.
    #[must_use]
    pub const fn task(&self) -> CompactTaskId {
        self.task
    }

    /// Modeled worker that performed the dispatch.
    #[must_use]
    pub const fn worker(&self) -> u32 {
        self.worker
    }

    /// Authoritative lane used for the dispatch.
    #[must_use]
    pub const fn lane(&self) -> DispatchLane {
        self.lane
    }

    /// Deterministic lab step at which the task was selected.
    #[must_use]
    pub const fn at_step(&self) -> u64 {
        self.at_step
    }

    /// Virtual time observed when the task was selected.
    #[must_use]
    pub const fn at_nanos(&self) -> u64 {
        self.at_nanos
    }
}

/// Complete, versioned exact-dispatch projection from one lab execution.
///
/// The projection is deliberately not a production scheduler-control format.
/// It can only be applied to a fresh [`LabRuntime`] with the same configuration,
/// and every task generation, worker, lane, step, and virtual-time value is
/// revalidated before polling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForcedSchedule {
    version: u32,
    seed: u64,
    config_hash: u64,
    dispatches: Vec<ForcedDispatch>,
    terminal_steps: u64,
    terminal_nanos: u64,
    terminal_schedule_hash: u64,
    terminal_quiescent: bool,
    truncated: bool,
}

/// One retained source dispatch in a reduced schedule candidate.
///
/// The fields are private so a caller can delete source choices but cannot
/// synthesize a new task identity, worker, lane, step, or timestamp. Candidate
/// execution uses the task/worker/lane tuple as the scheduler authority; the
/// source step and time remain provenance rather than terminal expectations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForcedScheduleCandidateDispatch {
    source_index: usize,
    dispatch: ForcedDispatch,
}

impl ForcedScheduleCandidateDispatch {
    /// Index of this dispatch in the complete captured source schedule.
    #[must_use]
    pub const fn source_index(&self) -> usize {
        self.source_index
    }

    /// Exact task generation retained from the source schedule.
    #[must_use]
    pub const fn task(&self) -> CompactTaskId {
        self.dispatch.task
    }

    /// Modeled worker retained from the source schedule.
    #[must_use]
    pub const fn worker(&self) -> u32 {
        self.dispatch.worker
    }

    /// Authoritative scheduler lane retained from the source schedule.
    #[must_use]
    pub const fn lane(&self) -> DispatchLane {
        self.dispatch.lane
    }

    /// Source step retained for provenance only.
    #[must_use]
    pub const fn source_step(&self) -> u64 {
        self.dispatch.at_step
    }

    /// Source virtual time retained for provenance only.
    #[must_use]
    pub const fn source_nanos(&self) -> u64 {
        self.dispatch.at_nanos
    }
}

/// A bounded, deletion-only candidate derived from one complete schedule.
///
/// This is a lab delta-debugging authority, not a weaker form of exact replay.
/// [`LabRuntime::run_forced_schedule`] continues to validate the complete
/// source terminal receipt. A candidate instead executes only its retained
/// scheduler choices and reports whether that exact subsequence quiesced or
/// was exhausted with work remaining.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForcedScheduleCandidate {
    version: u32,
    source_version: u32,
    seed: u64,
    config_hash: u64,
    source_dispatch_count: usize,
    source_terminal_schedule_hash: u64,
    dispatches: Vec<ForcedScheduleCandidateDispatch>,
}

impl ForcedScheduleCandidate {
    /// Candidate schema version.
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// Source schedule schema version.
    #[must_use]
    pub const fn source_version(&self) -> u32 {
        self.source_version
    }

    /// Source lab seed.
    #[must_use]
    pub const fn seed(&self) -> u64 {
        self.seed
    }

    /// Stable source execution-configuration hash.
    #[must_use]
    pub const fn config_hash(&self) -> u64 {
        self.config_hash
    }

    /// Number of dispatches in the complete source schedule.
    #[must_use]
    pub const fn source_dispatch_count(&self) -> usize {
        self.source_dispatch_count
    }

    /// Complete source schedule certificate hash retained as provenance.
    #[must_use]
    pub const fn source_terminal_schedule_hash(&self) -> u64 {
        self.source_terminal_schedule_hash
    }

    /// Ordered retained source choices.
    #[must_use]
    pub fn dispatches(&self) -> &[ForcedScheduleCandidateDispatch] {
        &self.dispatches
    }
}

/// Caller-owned admission and execution limits for a reduced candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForcedScheduleCandidateLimits {
    /// Maximum complete source dispatch count admitted for derivation/replay.
    pub max_source_dispatches: usize,
    /// Maximum retained candidate dispatch count.
    pub max_candidate_dispatches: usize,
    /// Maximum bounded execution actions (scheduler steps or time/event pumps).
    pub max_work_units: u64,
}

impl ForcedScheduleCandidateLimits {
    /// Creates explicit source, candidate, and execution limits.
    #[must_use]
    pub const fn new(
        max_source_dispatches: usize,
        max_candidate_dispatches: usize,
        max_work_units: u64,
    ) -> Self {
        Self {
            max_source_dispatches,
            max_candidate_dispatches,
            max_work_units,
        }
    }
}

/// Terminal classification for a reduced candidate execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForcedScheduleCandidateTermination {
    /// Every retained choice executed and the runtime reached quiescence.
    Quiescent,
    /// Every retained choice executed, but runnable or live work remained.
    Exhausted,
}

/// Observed receipt from executing a reduced schedule candidate.
#[derive(Debug, Clone)]
pub struct ForcedScheduleCandidateReport {
    /// Why candidate execution stopped.
    pub termination: ForcedScheduleCandidateTermination,
    /// Exact source indices consumed, in execution order.
    pub consumed_source_indices: Vec<usize>,
    /// Bounded scheduler-step/time-pump work consumed by the runner.
    pub work_units: u64,
    /// Canonical runtime/oracle report at the candidate boundary.
    pub lab: LabRunReport,
}

impl ForcedSchedule {
    /// Encodes this complete lab receipt into its strict canonical artifact.
    ///
    /// The format is fixed-width and little-endian. A domain-separated SHA-256
    /// checksum covers the header, every dispatch field, and the complete
    /// terminal receipt. This is an integrity binding for immutable lab
    /// evidence, not an authentication or production scheduler-control format.
    ///
    /// # Errors
    ///
    /// Returns [`ForcedScheduleArtifactError`] when the receipt is partial,
    /// malformed, too large for the artifact format, or cannot allocate its
    /// exact output.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, ForcedScheduleArtifactError> {
        validate_complete_forced_schedule_shape(self)?;
        let expected_len = forced_schedule_artifact_len(self.dispatches.len())?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(expected_len).map_err(|_| {
            ForcedScheduleArtifactError::AllocationFailed {
                requested: expected_len,
            }
        })?;

        bytes.extend_from_slice(&FORCED_SCHEDULE_ARTIFACT_MAGIC);
        bytes.extend_from_slice(&FORCED_SCHEDULE_ARTIFACT_VERSION.to_le_bytes());
        bytes.extend_from_slice(&self.version.to_le_bytes());
        bytes.extend_from_slice(&self.seed.to_le_bytes());
        bytes.extend_from_slice(&self.config_hash.to_le_bytes());
        let dispatch_count = u64::try_from(self.dispatches.len()).map_err(|_| {
            ForcedScheduleArtifactError::LengthOverflow {
                dispatch_count: u64::MAX,
            }
        })?;
        bytes.extend_from_slice(&dispatch_count.to_le_bytes());
        for dispatch in &self.dispatches {
            bytes.extend_from_slice(&dispatch.task.0.to_le_bytes());
            bytes.extend_from_slice(&dispatch.worker.to_le_bytes());
            bytes.push(forced_schedule_lane_tag(dispatch.lane));
            bytes.extend_from_slice(&dispatch.at_step.to_le_bytes());
            bytes.extend_from_slice(&dispatch.at_nanos.to_le_bytes());
        }
        bytes.extend_from_slice(&self.terminal_steps.to_le_bytes());
        bytes.extend_from_slice(&self.terminal_nanos.to_le_bytes());
        bytes.extend_from_slice(&self.terminal_schedule_hash.to_le_bytes());
        bytes.push(u8::from(self.terminal_quiescent));
        bytes.push(u8::from(self.truncated));
        let checksum = forced_schedule_artifact_checksum(&bytes);
        bytes.extend_from_slice(&checksum);
        debug_assert_eq!(bytes.len(), expected_len);
        Ok(bytes)
    }

    /// Decodes and validates one strict canonical forced-schedule artifact.
    ///
    /// Byte, count, decoded-storage, and arithmetic admission all happen before
    /// the dispatch vector is allocated. The reconstructed private authority is
    /// complete and canonical, but [`LabRuntime::run_forced_schedule`] still
    /// revalidates the source seed/config and every task generation, worker,
    /// lane, step, time, and terminal certificate before accepting replay.
    ///
    /// # Errors
    ///
    /// Returns [`ForcedScheduleArtifactError`] for an unsupported or
    /// noncanonical artifact, an incomplete source receipt, checksum mismatch,
    /// exceeded caller limit, checked-arithmetic failure, or allocation
    /// refusal.
    pub fn try_from_canonical_bytes(
        bytes: &[u8],
        limits: ForcedScheduleDecodeLimits,
    ) -> Result<Self, ForcedScheduleArtifactError> {
        if bytes.len() > limits.max_encoded_bytes {
            return Err(ForcedScheduleArtifactError::ByteLimitExceeded {
                found: bytes.len(),
                limit: limits.max_encoded_bytes,
            });
        }
        if bytes.len() < FORCED_SCHEDULE_ARTIFACT_HEADER_LEN {
            return Err(ForcedScheduleArtifactError::Truncated {
                expected: FORCED_SCHEDULE_ARTIFACT_HEADER_LEN,
                found: bytes.len(),
            });
        }
        if bytes[..FORCED_SCHEDULE_ARTIFACT_MAGIC.len()] != FORCED_SCHEDULE_ARTIFACT_MAGIC {
            return Err(ForcedScheduleArtifactError::MagicMismatch);
        }
        let artifact_version = forced_schedule_artifact_u32(bytes, 8)?;
        if artifact_version != FORCED_SCHEDULE_ARTIFACT_VERSION {
            return Err(ForcedScheduleArtifactError::VersionMismatch {
                expected: FORCED_SCHEDULE_ARTIFACT_VERSION,
                found: artifact_version,
            });
        }
        let version = forced_schedule_artifact_u32(bytes, 12)?;
        if version != FORCED_SCHEDULE_SCHEMA_VERSION {
            return Err(ForcedScheduleArtifactError::SchemaMismatch {
                expected: FORCED_SCHEDULE_SCHEMA_VERSION,
                found: version,
            });
        }
        let seed = forced_schedule_artifact_u64(bytes, 16)?;
        let config_hash = forced_schedule_artifact_u64(bytes, 24)?;
        let dispatch_count_u64 =
            forced_schedule_artifact_u64(bytes, FORCED_SCHEDULE_ARTIFACT_COUNT_OFFSET)?;
        let dispatch_count = usize::try_from(dispatch_count_u64).map_err(|_| {
            ForcedScheduleArtifactError::LengthOverflow {
                dispatch_count: dispatch_count_u64,
            }
        })?;
        if dispatch_count > limits.max_dispatches {
            return Err(ForcedScheduleArtifactError::DispatchLimitExceeded {
                found: dispatch_count,
                limit: limits.max_dispatches,
            });
        }
        let decoded_dispatch_bytes = dispatch_count
            .checked_mul(std::mem::size_of::<ForcedDispatch>())
            .ok_or(ForcedScheduleArtifactError::LengthOverflow {
                dispatch_count: dispatch_count_u64,
            })?;
        if decoded_dispatch_bytes > limits.max_decoded_dispatch_bytes {
            return Err(
                ForcedScheduleArtifactError::DecodedAllocationLimitExceeded {
                    requested: decoded_dispatch_bytes,
                    limit: limits.max_decoded_dispatch_bytes,
                },
            );
        }

        let expected_len = forced_schedule_artifact_len(dispatch_count)?;
        if bytes.len() < expected_len {
            return Err(ForcedScheduleArtifactError::Truncated {
                expected: expected_len,
                found: bytes.len(),
            });
        }
        if bytes.len() > expected_len {
            return Err(ForcedScheduleArtifactError::TrailingBytes {
                expected: expected_len,
                found: bytes.len(),
            });
        }
        let checksum_offset = expected_len - FORCED_SCHEDULE_ARTIFACT_CHECKSUM_LEN;
        let actual_checksum = forced_schedule_artifact_checksum(&bytes[..checksum_offset]);
        if bytes[checksum_offset..] != actual_checksum {
            return Err(ForcedScheduleArtifactError::ChecksumMismatch);
        }

        let mut dispatches = Vec::new();
        dispatches.try_reserve_exact(dispatch_count).map_err(|_| {
            ForcedScheduleArtifactError::AllocationFailed {
                requested: decoded_dispatch_bytes,
            }
        })?;
        for index in 0..dispatch_count {
            let offset =
                FORCED_SCHEDULE_ARTIFACT_HEADER_LEN + index * FORCED_SCHEDULE_ARTIFACT_DISPATCH_LEN;
            let task = CompactTaskId(forced_schedule_artifact_u64(bytes, offset)?);
            let worker = forced_schedule_artifact_u32(bytes, offset + 8)?;
            let lane_tag = bytes[offset + 12];
            let lane = forced_schedule_lane_from_tag(index, lane_tag)?;
            let at_step = forced_schedule_artifact_u64(bytes, offset + 13)?;
            let at_nanos = forced_schedule_artifact_u64(bytes, offset + 21)?;
            dispatches.push(ForcedDispatch {
                task,
                worker,
                lane,
                at_step,
                at_nanos,
            });
        }
        let terminal_offset = FORCED_SCHEDULE_ARTIFACT_HEADER_LEN
            + dispatch_count * FORCED_SCHEDULE_ARTIFACT_DISPATCH_LEN;
        let terminal_steps = forced_schedule_artifact_u64(bytes, terminal_offset)?;
        let terminal_nanos = forced_schedule_artifact_u64(bytes, terminal_offset + 8)?;
        let terminal_schedule_hash = forced_schedule_artifact_u64(bytes, terminal_offset + 16)?;
        let terminal_quiescent =
            forced_schedule_bool(bytes[terminal_offset + 24], "terminal_quiescent")?;
        let truncated = forced_schedule_bool(bytes[terminal_offset + 25], "truncated")?;
        let schedule = Self {
            version,
            seed,
            config_hash,
            dispatches,
            terminal_steps,
            terminal_nanos,
            terminal_schedule_hash,
            terminal_quiescent,
            truncated,
        };
        validate_complete_forced_schedule_shape(&schedule)?;
        if schedule.to_canonical_bytes()?.as_slice() != bytes {
            return Err(ForcedScheduleArtifactError::NonCanonical);
        }
        Ok(schedule)
    }

    /// Projection schema version.
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// Source lab seed.
    #[must_use]
    pub const fn seed(&self) -> u64 {
        self.seed
    }

    /// Stable source execution-configuration hash.
    #[must_use]
    pub const fn config_hash(&self) -> u64 {
        self.config_hash
    }

    /// Ordered exact dispatches.
    #[must_use]
    pub fn dispatches(&self) -> &[ForcedDispatch] {
        &self.dispatches
    }

    /// Source run terminal step.
    #[must_use]
    pub const fn terminal_steps(&self) -> u64 {
        self.terminal_steps
    }

    /// Source run terminal virtual time.
    #[must_use]
    pub const fn terminal_nanos(&self) -> u64 {
        self.terminal_nanos
    }

    /// Source run terminal schedule-certificate hash.
    #[must_use]
    pub const fn terminal_schedule_hash(&self) -> u64 {
        self.terminal_schedule_hash
    }

    /// Whether the source terminated in structured quiescence.
    #[must_use]
    pub const fn terminal_quiescent(&self) -> bool {
        self.terminal_quiescent
    }

    /// Whether bounded source capture truncated dispatch evidence.
    #[must_use]
    pub const fn truncated(&self) -> bool {
        self.truncated
    }

    /// Derives a deletion-only candidate from ordered source indices.
    ///
    /// Every retained dispatch is copied from this complete source receipt.
    /// Callers can therefore remove choices but cannot synthesize task IDs or
    /// scheduler metadata. The source itself is bounded and shape-validated
    /// before any candidate allocation.
    ///
    /// # Errors
    ///
    /// Returns [`ForcedScheduleError`] when the source is partial or malformed,
    /// a caller limit is zero/exhausted, indices are duplicated/reordered/out of
    /// range, or bounded candidate allocation fails.
    pub fn derive_candidate(
        &self,
        retained_source_indices: &[usize],
        limits: ForcedScheduleCandidateLimits,
    ) -> Result<ForcedScheduleCandidate, ForcedScheduleError> {
        validate_candidate_limits(limits)?;
        if self.version != FORCED_SCHEDULE_SCHEMA_VERSION {
            return Err(ForcedScheduleError::SchemaMismatch {
                expected: FORCED_SCHEDULE_SCHEMA_VERSION,
                found: self.version,
            });
        }
        if self.truncated || !self.terminal_quiescent {
            return Err(ForcedScheduleError::PartialSource);
        }
        if self.dispatches.len() > limits.max_source_dispatches {
            return Err(ForcedScheduleError::CandidateSourceLimitExceeded {
                found: self.dispatches.len(),
                limit: limits.max_source_dispatches,
            });
        }
        if retained_source_indices.len() > limits.max_candidate_dispatches {
            return Err(ForcedScheduleError::DispatchLimitExceeded {
                found: retained_source_indices.len(),
                limit: limits.max_candidate_dispatches,
            });
        }

        validate_dispatch_order(&self.dispatches)?;
        if self.dispatches.last().is_some_and(|dispatch| {
            dispatch.at_step > self.terminal_steps || dispatch.at_nanos > self.terminal_nanos
        }) {
            return Err(ForcedScheduleError::PartialSource);
        }

        let mut dispatches = Vec::new();
        dispatches
            .try_reserve_exact(retained_source_indices.len())
            .map_err(|_| ForcedScheduleError::CandidateAllocationFailed {
                requested: retained_source_indices.len(),
            })?;
        let mut previous = None;
        for (candidate_index, &source_index) in retained_source_indices.iter().enumerate() {
            if let Some(previous) = previous
                && source_index <= previous
            {
                return Err(ForcedScheduleError::CandidateIndexOrder {
                    candidate_index,
                    previous,
                    next: source_index,
                });
            }
            let Some(&dispatch) = self.dispatches.get(source_index) else {
                return Err(ForcedScheduleError::CandidateIndexOutOfRange {
                    candidate_index,
                    source_index,
                    source_len: self.dispatches.len(),
                });
            };
            dispatches.push(ForcedScheduleCandidateDispatch {
                source_index,
                dispatch,
            });
            previous = Some(source_index);
        }

        Ok(ForcedScheduleCandidate {
            version: FORCED_SCHEDULE_CANDIDATE_SCHEMA_VERSION,
            source_version: self.version,
            seed: self.seed,
            config_hash: self.config_hash,
            source_dispatch_count: self.dispatches.len(),
            source_terminal_schedule_hash: self.terminal_schedule_hash,
            dispatches,
        })
    }
}

/// Caller-owned admission limits for forced lab execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForcedScheduleLimits {
    /// Maximum number of dispatch records the caller will admit.
    pub max_dispatches: usize,
    /// Maximum lab steps the forced runner may execute.
    pub max_steps: u64,
}

impl ForcedScheduleLimits {
    /// Creates explicit forced-execution limits.
    #[must_use]
    pub const fn new(max_dispatches: usize, max_steps: u64) -> Self {
        Self {
            max_dispatches,
            max_steps,
        }
    }
}

/// Successful exact forced-schedule execution receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForcedScheduleReport {
    /// Number of exact dispatch records consumed.
    pub dispatches: usize,
    /// Number of lab steps executed by this call.
    pub steps: u64,
    /// Terminal virtual time.
    pub terminal_nanos: u64,
    /// Terminal schedule-certificate hash.
    pub schedule_hash: u64,
    /// Whether the runtime reached structured quiescence.
    pub quiescent: bool,
}

/// Fail-closed forced-schedule admission or execution error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ForcedScheduleError {
    /// Recording was requested with a zero event limit.
    #[error("forced schedule recording requires a nonzero dispatch limit")]
    ZeroRecordingLimit,
    /// A recorder is already active on this runtime.
    #[error("forced schedule recording is already active")]
    RecordingAlreadyActive,
    /// No recorder is active on this runtime.
    #[error("forced schedule recording is not active")]
    RecordingNotActive,
    /// The source execution exceeded its recording limit.
    #[error("forced schedule recording exceeded its limit of {max_dispatches} dispatches")]
    RecordingLimitExceeded {
        /// Configured source recording limit.
        max_dispatches: usize,
    },
    /// A candidate limit was configured as zero.
    #[error("forced schedule candidate limit {limit_name} must be nonzero")]
    ZeroCandidateLimit {
        /// Stable name of the invalid limit.
        limit_name: &'static str,
    },
    /// The complete source schedule exceeds caller admission.
    #[error("forced schedule candidate source has {found} dispatches, limit is {limit}")]
    CandidateSourceLimitExceeded {
        /// Complete source dispatch count.
        found: usize,
        /// Caller-owned source admission bound.
        limit: usize,
    },
    /// Retained source indices are not strictly increasing.
    #[error(
        "forced schedule candidate index order is invalid at {candidate_index}: previous {previous}, next {next}"
    )]
    CandidateIndexOrder {
        /// Candidate position containing the invalid source index.
        candidate_index: usize,
        /// Previous retained source index.
        previous: usize,
        /// Reordered or duplicate source index.
        next: usize,
    },
    /// A retained index does not exist in the complete source schedule.
    #[error(
        "forced schedule candidate index {candidate_index} references source {source_index}, source length is {source_len}"
    )]
    CandidateIndexOutOfRange {
        /// Candidate position containing the invalid source index.
        candidate_index: usize,
        /// Invalid source index.
        source_index: usize,
        /// Complete source schedule length.
        source_len: usize,
    },
    /// Candidate allocation failed before execution.
    #[error("forced schedule candidate could not allocate {requested} dispatches")]
    CandidateAllocationFailed {
        /// Requested retained dispatch capacity.
        requested: usize,
    },
    /// The reduced candidate uses an unsupported schema.
    #[error("forced schedule candidate schema mismatch: expected {expected}, found {found}")]
    CandidateSchemaMismatch {
        /// Supported candidate schema.
        expected: u32,
        /// Supplied candidate schema.
        found: u32,
    },
    /// Caller-owned candidate execution work was exhausted.
    #[error("forced schedule candidate work limit exhausted at {work_units} units (limit {limit})")]
    CandidateWorkLimitExceeded {
        /// Bounded execution work already consumed.
        work_units: u64,
        /// Caller-owned execution work bound.
        limit: u64,
    },
    /// The projection schema is unsupported.
    #[error("forced schedule schema mismatch: expected {expected}, found {found}")]
    SchemaMismatch {
        /// Supported schema.
        expected: u32,
        /// Supplied schema.
        found: u32,
    },
    /// The projection is from a different deterministic seed.
    #[error("forced schedule seed mismatch: expected {expected}, found {found}")]
    SeedMismatch {
        /// Runtime seed.
        expected: u64,
        /// Projection seed.
        found: u64,
    },
    /// The projection is from a different lab configuration.
    #[error("forced schedule config mismatch: expected {expected:#x}, found {found:#x}")]
    ConfigMismatch {
        /// Runtime configuration hash.
        expected: u64,
        /// Projection configuration hash.
        found: u64,
    },
    /// Forced execution only starts from a pristine runtime clock/certificate.
    #[error("forced schedule requires a pristine runtime (steps={steps}, decisions={decisions})")]
    RuntimeAlreadyStarted {
        /// Runtime steps already executed.
        steps: u64,
        /// Schedule decisions already recorded.
        decisions: u64,
    },
    /// The source projection was incomplete or did not reach quiescence.
    #[error("forced schedule source projection is partial")]
    PartialSource,
    /// Caller-owned dispatch admission was exceeded.
    #[error("forced schedule has {found} dispatches, limit is {limit}")]
    DispatchLimitExceeded {
        /// Supplied number of dispatches.
        found: usize,
        /// Caller-owned limit.
        limit: usize,
    },
    /// Caller-owned step budget was exhausted.
    #[error("forced schedule work limit exhausted at {steps} steps (limit {limit})")]
    WorkLimitExceeded {
        /// Steps consumed by this invocation.
        steps: u64,
        /// Caller-owned limit.
        limit: u64,
    },
    /// Dispatch steps are not strictly increasing.
    #[error(
        "forced schedule step order is invalid at dispatch {index}: previous {previous}, next {next}"
    )]
    StepOrder {
        /// Offending dispatch index.
        index: usize,
        /// Previous step.
        previous: u64,
        /// Next step.
        next: u64,
    },
    /// Dispatch virtual time moved backwards.
    #[error(
        "forced schedule virtual time moved backwards at dispatch {index}: previous {previous}, next {next}"
    )]
    TimeOrder {
        /// Offending dispatch index.
        index: usize,
        /// Previous virtual time.
        previous: u64,
        /// Next virtual time.
        next: u64,
    },
    /// Runnable work appeared before the next recorded dispatch step.
    #[error("runnable work appeared at step {actual} before recorded step {expected}")]
    EarlyRunnable {
        /// Recorded next dispatch step.
        expected: u64,
        /// Current step.
        actual: u64,
    },
    /// The runner passed the next recorded dispatch step.
    #[error("forced schedule missed dispatch {index}: expected step {expected}, reached {actual}")]
    StepMismatch {
        /// Dispatch index.
        index: usize,
        /// Recorded step.
        expected: u64,
        /// Current step.
        actual: u64,
    },
    /// The virtual clock did not match the recorded dispatch.
    #[error(
        "forced schedule time mismatch at dispatch {index}: expected {expected}, found {actual}"
    )]
    TimeMismatch {
        /// Dispatch index.
        index: usize,
        /// Recorded virtual time.
        expected: u64,
        /// Runtime virtual time.
        actual: u64,
    },
    /// The recorded worker is not part of this runtime.
    #[error("forced schedule worker {worker} is unavailable (worker count {worker_count})")]
    WorkerUnavailable {
        /// Recorded worker.
        worker: u32,
        /// Runtime worker count.
        worker_count: usize,
    },
    /// The exact task generation is absent or already completed.
    #[error("forced schedule task {task:?} is unavailable at dispatch {index}")]
    TaskUnavailable {
        /// Dispatch index.
        index: usize,
        /// Full compact task identity.
        task: CompactTaskId,
    },
    /// The task's authoritative worker differs from the recorded worker.
    #[error(
        "forced schedule worker mismatch at dispatch {index}: expected {expected}, found {actual}"
    )]
    WorkerMismatch {
        /// Dispatch index.
        index: usize,
        /// Recorded worker.
        expected: u32,
        /// Actual assigned worker.
        actual: u32,
    },
    /// The task's authoritative lane differs from the recorded lane.
    #[error(
        "forced schedule lane mismatch at dispatch {index}: expected {expected:?}, found {actual:?}"
    )]
    LaneMismatch {
        /// Dispatch index.
        index: usize,
        /// Recorded lane.
        expected: DispatchLane,
        /// Actual lane.
        actual: DispatchLane,
    },
    /// A timed task was selected before its deadline.
    #[error(
        "forced schedule timed task is not due at dispatch {index}: deadline {deadline}, now {now}"
    )]
    TimedNotDue {
        /// Dispatch index.
        index: usize,
        /// Recorded task deadline.
        deadline: u64,
        /// Current virtual time.
        now: u64,
    },
    /// Scheduler membership and lane queues disagree.
    #[error("forced schedule queue invariant failed at dispatch {index}")]
    QueueInvariant {
        /// Dispatch index.
        index: usize,
    },
    /// The projection ended while runnable or live work remained.
    #[error("forced schedule exhausted after {consumed} dispatches before terminal quiescence")]
    ScheduleExhausted {
        /// Dispatches consumed.
        consumed: usize,
    },
    /// Terminal schedule hash differed from the source receipt.
    #[error("forced schedule certificate mismatch: expected {expected:#x}, found {actual:#x}")]
    CertificateMismatch {
        /// Source schedule hash.
        expected: u64,
        /// Replayed schedule hash.
        actual: u64,
    },
    /// Terminal step or virtual time differed from the source receipt.
    #[error(
        "forced schedule terminal mismatch: expected step/time {expected_steps}/{expected_nanos}, found {actual_steps}/{actual_nanos}"
    )]
    TerminalMismatch {
        /// Source terminal step.
        expected_steps: u64,
        /// Source terminal virtual time.
        expected_nanos: u64,
        /// Replay terminal step.
        actual_steps: u64,
        /// Replay terminal virtual time.
        actual_nanos: u64,
    },
}

/// Fail-closed error for the canonical [`ForcedSchedule`] artifact codec.
///
/// This error is separate from [`ForcedScheduleError`] so adding the codec in
/// a `0.4.x` release does not add variants to that existing exhaustively
/// matchable public enum.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ForcedScheduleArtifactError {
    /// The complete schedule is not valid replay authority.
    #[error(transparent)]
    Schedule(#[from] ForcedScheduleError),
    /// The artifact exceeds the caller's encoded-byte admission limit.
    #[error("forced schedule artifact has {found} bytes, limit is {limit}")]
    ByteLimitExceeded {
        /// Supplied encoded byte length.
        found: usize,
        /// Caller-owned encoded byte limit.
        limit: usize,
    },
    /// The artifact magic prefix is not recognized.
    #[error("forced schedule artifact magic mismatch")]
    MagicMismatch,
    /// The artifact codec version is unsupported.
    #[error("forced schedule artifact version mismatch: expected {expected}, found {found}")]
    VersionMismatch {
        /// Supported artifact version.
        expected: u32,
        /// Supplied artifact version.
        found: u32,
    },
    /// The encoded schedule schema is unsupported.
    #[error("forced schedule schema mismatch: expected {expected}, found {found}")]
    SchemaMismatch {
        /// Supported schedule schema.
        expected: u32,
        /// Supplied schedule schema.
        found: u32,
    },
    /// Artifact size arithmetic overflowed before allocation.
    #[error("forced schedule artifact length overflow for {dispatch_count} dispatches")]
    LengthOverflow {
        /// Untrusted dispatch count that overflowed admission arithmetic.
        dispatch_count: u64,
    },
    /// The artifact ended before its declared canonical length.
    #[error("forced schedule artifact is truncated: expected {expected} bytes, found {found}")]
    Truncated {
        /// Minimum or exact required byte length.
        expected: usize,
        /// Supplied byte length.
        found: usize,
    },
    /// Bytes remain after the canonical artifact boundary.
    #[error("forced schedule artifact has trailing bytes: expected {expected}, found {found}")]
    TrailingBytes {
        /// Exact canonical byte length.
        expected: usize,
        /// Supplied byte length.
        found: usize,
    },
    /// The SHA-256 integrity binding does not match the artifact body.
    #[error("forced schedule artifact checksum mismatch")]
    ChecksumMismatch,
    /// The decoded dispatch count exceeds the caller's admission limit.
    #[error("forced schedule artifact has {found} dispatches, limit is {limit}")]
    DispatchLimitExceeded {
        /// Supplied number of dispatches.
        found: usize,
        /// Caller-owned dispatch limit.
        limit: usize,
    },
    /// Decoded dispatch storage exceeds the caller's allocation admission.
    #[error("forced schedule artifact needs {requested} decoded dispatch bytes, limit is {limit}")]
    DecodedAllocationLimitExceeded {
        /// Required decoded dispatch-vector bytes.
        requested: usize,
        /// Caller-owned decoded allocation limit.
        limit: usize,
    },
    /// Exact artifact or dispatch-vector allocation failed.
    #[error("forced schedule artifact could not allocate {requested} bytes")]
    AllocationFailed {
        /// Exact requested allocation size.
        requested: usize,
    },
    /// A dispatch encoded an unsupported scheduler-lane tag.
    #[error("forced schedule artifact lane tag {tag} is invalid at dispatch {index}")]
    LaneTag {
        /// Dispatch containing the invalid tag.
        index: usize,
        /// Unsupported lane tag.
        tag: u8,
    },
    /// A boolean field used a noncanonical tag.
    #[error("forced schedule artifact boolean {field} has invalid tag {tag}")]
    BooleanTag {
        /// Stable field name.
        field: &'static str,
        /// Unsupported boolean tag.
        tag: u8,
    },
    /// Parsed fields did not reproduce the exact input bytes.
    #[error("forced schedule artifact is not canonically encoded")]
    NonCanonical,
}

#[derive(Debug)]
struct ForcedScheduleRecorder {
    max_dispatches: usize,
    dispatches: Vec<ForcedDispatch>,
    truncated: bool,
}

/// Why a production-schedule replay stopped following the recorded order
/// (br-asupersync-bi2462.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayDivergenceReason {
    /// The recorded task is bound to a lab task that was not runnable
    /// after `waited` bounded virtual-time advances.
    ///
    /// Making it runnable would take polling a different task first, which
    /// is exactly the divergence.
    TaskNotRunnable {
        /// Virtual-time advances spent looking for the task.
        waited: usize,
    },
    /// No lab task ever entered the scheduler at the recorded spawn ordinal.
    TaskNeverSpawned,
    /// The lab scheduler's dedup set and its lane queues disagreed about
    /// the task.
    SchedulerInvariant,
}

/// The first point where the lab could not follow a recorded production
/// schedule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayDivergence {
    /// Lab step counter when the divergence was detected.
    pub step: u64,
    /// Index into the recorded schedule of the step that could not be
    /// honoured.
    pub schedule_index: usize,
    /// Recorded spawn ordinal of the expected task.
    pub expected_ordinal: usize,
    /// Recorded task id of the expected task (`None` only for a malformed
    /// schedule whose step names an ordinal outside its spawn order).
    pub expected: Option<CompactTaskId>,
    /// The lab task bound to that ordinal, if any.
    pub actual: Option<TaskId>,
    /// Why the recorded choice could not be taken.
    pub reason: ReplayDivergenceReason,
}

/// What a production-schedule replay does after its first divergence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OnReplayDivergence {
    /// Stop dispatching: the run loops return and the report names the
    /// divergence (default).
    #[default]
    Stop,
    /// Record the divergence, then continue with the lab's normal policy.
    Continue,
}

/// Options for [`LabRuntime::replay_production_schedule`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProductionReplayOptions {
    /// Divergence policy.
    pub on_divergence: OnReplayDivergence,
    /// Bounded virtual-time advances spent waiting for a recorded task that
    /// is not runnable yet.
    ///
    /// Each advance moves to the next timer or reactor deadline; when no
    /// deadline exists at all the wait is exhausted immediately and the
    /// divergence is declared.
    pub max_wait_steps: usize,
}

impl Default for ProductionReplayOptions {
    fn default() -> Self {
        Self {
            on_divergence: OnReplayDivergence::Stop,
            max_wait_steps: 64,
        }
    }
}

/// Outcome of a production-schedule replay so far
/// ([`LabRuntime::replay_report`]).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReplayReport {
    /// Recorded steps the lab dispatched exactly as recorded.
    pub steps_matched: usize,
    /// Recorded steps in the schedule.
    pub steps_total: usize,
    /// Recorded spawn ordinals that resolved to a lab task so far.
    pub spawns_bound: usize,
    /// The first divergence, if any.
    pub divergence: Option<ReplayDivergence>,
    /// Whether the replay stopped dispatching
    /// ([`OnReplayDivergence::Stop`] after a divergence).
    pub stopped: bool,
}

/// Errors from configuring or deriving a production-schedule replay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProductionReplayError {
    /// The runtime already executed steps; a replay must start from step
    /// zero so spawn ordinals line up.
    AlreadyStarted {
        /// Steps already executed.
        steps: u64,
    },
    /// The schedule has no dispatch steps to follow.
    EmptySchedule,
    /// Replay recording is disabled on this runtime, so no schedule can be
    /// derived from it.
    RecordingDisabled,
    /// The recorded events did not project into a schedule.
    Projection(ProjectionError),
}

impl std::fmt::Display for ProductionReplayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyStarted { steps } => write!(
                f,
                "production replay must be configured before the first step (already ran {steps})"
            ),
            Self::EmptySchedule => f.write_str("production schedule has no dispatch steps"),
            Self::RecordingDisabled => {
                f.write_str("replay recording is disabled; enable LabConfig::replay_recording")
            }
            Self::Projection(error) => write!(f, "recorded events did not project: {error}"),
        }
    }
}

impl std::error::Error for ProductionReplayError {}

/// The oracle state behind [`LabRuntime::replay_production_schedule`].
///
/// The recorded `(spawn ordinal, seq)` steps, how far the lab has followed
/// them, and the report. Spawn ordinals bind to lab tasks by the order in
/// which tasks first enter the lab scheduler
/// ([`LabScheduler::first_entry`]).
#[derive(Debug)]
struct ProductionReplayState {
    steps: Vec<(usize, u64)>,
    spawn_order: Vec<CompactTaskId>,
    options: ProductionReplayOptions,
    next: usize,
    waited: usize,
    following: bool,
    report: ReplayReport,
    mode: ProductionReplayMode,
    termination: Option<StrictProductionReplayTermination>,
    source_error: Option<StrictProductionReplayError>,
    selected: Option<usize>,
    cancellation: Option<production_strict::CancellationReplay>,
}

/// What the oracle decided for one lab step.
enum ReplayPick {
    /// Dispatch exactly this task from this lane on this worker.
    Take(TaskId, DispatchLane, usize),
    /// The recorded task is not runnable yet: advance virtual time once and
    /// retry on the next step.
    WaitForTime,
    /// The replay diverged under `OnReplayDivergence::Stop`: dispatch nothing.
    Stopped,
    /// Not (or no longer) following the schedule: use the normal policy.
    Normal,
}

impl ProductionReplayState {
    fn new(schedule: &ProductionSchedule, options: ProductionReplayOptions) -> Self {
        let steps: Vec<(usize, u64)> = schedule.steps().collect();
        let report = ReplayReport {
            steps_total: steps.len(),
            ..ReplayReport::default()
        };
        Self {
            steps,
            spawn_order: schedule.spawn_order().to_vec(),
            options,
            next: 0,
            waited: 0,
            following: true,
            report,
            mode: ProductionReplayMode::Prefix,
            termination: None,
            source_error: None,
            selected: None,
            cancellation: None,
        }
    }

    fn pick(&mut self, sched: &mut LabScheduler, now: Time, step: u64) -> ReplayPick {
        if self.report.stopped {
            return ReplayPick::Stopped;
        }
        if !self.following {
            return ReplayPick::Normal;
        }
        let Some(&(ordinal, _seq)) = self.steps.get(self.next) else {
            if self.mode == ProductionReplayMode::Strict {
                self.report.stopped = true;
                return ReplayPick::Stopped;
            }
            // Only explicit prefix replay permits an unrecorded continuation.
            self.following = false;
            return ReplayPick::Normal;
        };
        if self.mode == ProductionReplayMode::Strict
            && sched.first_entry_count() > self.spawn_order.len()
        {
            self.termination = Some(StrictProductionReplayTermination::SpawnCountMismatch {
                expected: self.spawn_order.len(),
                observed: sched.first_entry_count(),
            });
            self.report.stopped = true;
            return ReplayPick::Stopped;
        }
        let Some(task) = sched.first_entry(ordinal) else {
            return self.diverge(
                step,
                ordinal,
                None,
                ReplayDivergenceReason::TaskNeverSpawned,
            );
        };
        match sched.take_preferred(task, now) {
            Ok((lane, worker)) => {
                self.waited = 0;
                if self.mode == ProductionReplayMode::Strict {
                    // Selection alone is not a poll: stale wakes can enqueue a
                    // completed task whose stored future has already gone.
                    self.selected = Some(ordinal);
                } else {
                    self.next = self.next.saturating_add(1);
                    self.report.steps_matched = self.report.steps_matched.saturating_add(1);
                }
                ReplayPick::Take(task, lane, worker)
            }
            Err(PreferredDispatchError::NotRunnable | PreferredDispatchError::TimedNotDue) => {
                if self.waited < self.options.max_wait_steps {
                    self.waited = self.waited.saturating_add(1);
                    ReplayPick::WaitForTime
                } else {
                    let waited = self.waited;
                    self.diverge(
                        step,
                        ordinal,
                        Some(task),
                        ReplayDivergenceReason::TaskNotRunnable { waited },
                    )
                }
            }
            Err(PreferredDispatchError::SchedulerInvariant) => self.diverge(
                step,
                ordinal,
                Some(task),
                ReplayDivergenceReason::SchedulerInvariant,
            ),
        }
    }

    /// Nothing can make the awaited task runnable without polling another
    /// task: spend the whole wait budget so the next pick diverges.
    fn exhaust_wait(&mut self) {
        self.waited = self.options.max_wait_steps;
    }

    fn diverge(
        &mut self,
        step: u64,
        ordinal: usize,
        actual: Option<TaskId>,
        reason: ReplayDivergenceReason,
    ) -> ReplayPick {
        let expected = self.spawn_order.get(ordinal).copied();
        self.report.divergence.get_or_insert(ReplayDivergence {
            step,
            schedule_index: self.next,
            expected_ordinal: ordinal,
            expected,
            actual,
            reason,
        });
        self.following = false;
        match self.options.on_divergence {
            OnReplayDivergence::Stop => {
                self.report.stopped = true;
                ReplayPick::Stopped
            }
            OnReplayDivergence::Continue => ReplayPick::Normal,
        }
    }
}

enum LabDispatchMode<'a> {
    Normal,
    Forced {
        expected: Option<(usize, &'a ForcedDispatch)>,
    },
    Candidate {
        expected: Option<(usize, &'a ForcedDispatch)>,
    },
}

fn compact_task_id(compact: CompactTaskId) -> TaskId {
    let (index, generation) = compact.unpack();
    TaskId::from_arena(ArenaIndex::new(index, generation))
}

fn forced_schedule_config_hash(config: &LabConfig) -> u64 {
    use std::hash::{Hash, Hasher};

    let mut hasher = crate::util::DetHasher::for_lab();
    "asupersync.lab.forced-schedule.config.v1".hash(&mut hasher);
    LabConfigSummary::from_config(config)
        .config_hash()
        .hash(&mut hasher);
    config.auto_advance_time.hash(&mut hasher);
    config.enable_cancellation_oracle.hash(&mut hasher);
    config.panic_on_cancellation_violation.hash(&mut hasher);
    config.oracle_selection.hash(&mut hasher);
    hasher.finish()
}

fn validate_candidate_limits(
    limits: ForcedScheduleCandidateLimits,
) -> Result<(), ForcedScheduleError> {
    if limits.max_source_dispatches == 0 {
        return Err(ForcedScheduleError::ZeroCandidateLimit {
            limit_name: "max_source_dispatches",
        });
    }
    if limits.max_candidate_dispatches == 0 {
        return Err(ForcedScheduleError::ZeroCandidateLimit {
            limit_name: "max_candidate_dispatches",
        });
    }
    if limits.max_work_units == 0 {
        return Err(ForcedScheduleError::ZeroCandidateLimit {
            limit_name: "max_work_units",
        });
    }
    Ok(())
}

fn take_candidate_work(work_units: &mut u64, limit: u64) -> Result<(), ForcedScheduleError> {
    if *work_units >= limit {
        return Err(ForcedScheduleError::CandidateWorkLimitExceeded {
            work_units: *work_units,
            limit,
        });
    }
    *work_units += 1;
    Ok(())
}

fn validate_dispatch_order(dispatches: &[ForcedDispatch]) -> Result<(), ForcedScheduleError> {
    let mut previous_step = 0u64;
    let mut previous_nanos = 0u64;
    for (index, dispatch) in dispatches.iter().enumerate() {
        if dispatch.at_step <= previous_step {
            return Err(ForcedScheduleError::StepOrder {
                index,
                previous: previous_step,
                next: dispatch.at_step,
            });
        }
        if dispatch.at_nanos < previous_nanos {
            return Err(ForcedScheduleError::TimeOrder {
                index,
                previous: previous_nanos,
                next: dispatch.at_nanos,
            });
        }
        previous_step = dispatch.at_step;
        previous_nanos = dispatch.at_nanos;
    }
    Ok(())
}

fn forced_schedule_artifact_len(
    dispatch_count: usize,
) -> Result<usize, ForcedScheduleArtifactError> {
    let dispatch_count_u64 = u64::try_from(dispatch_count).unwrap_or(u64::MAX);
    let dispatch_bytes = dispatch_count
        .checked_mul(FORCED_SCHEDULE_ARTIFACT_DISPATCH_LEN)
        .ok_or(ForcedScheduleArtifactError::LengthOverflow {
            dispatch_count: dispatch_count_u64,
        })?;
    FORCED_SCHEDULE_ARTIFACT_HEADER_LEN
        .checked_add(dispatch_bytes)
        .and_then(|len| len.checked_add(FORCED_SCHEDULE_ARTIFACT_TERMINAL_LEN))
        .and_then(|len| len.checked_add(FORCED_SCHEDULE_ARTIFACT_CHECKSUM_LEN))
        .ok_or(ForcedScheduleArtifactError::LengthOverflow {
            dispatch_count: dispatch_count_u64,
        })
}

fn forced_schedule_artifact_checksum(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"asupersync.lab.forced-schedule.artifact.v1\0");
    hasher.update(bytes);
    hasher.finalize().into()
}

fn forced_schedule_artifact_u32(
    bytes: &[u8],
    offset: usize,
) -> Result<u32, ForcedScheduleArtifactError> {
    let end = offset
        .checked_add(4)
        .ok_or(ForcedScheduleArtifactError::LengthOverflow {
            dispatch_count: u64::MAX,
        })?;
    let Some(raw) = bytes.get(offset..end) else {
        return Err(ForcedScheduleArtifactError::Truncated {
            expected: end,
            found: bytes.len(),
        });
    };
    let mut value = [0u8; 4];
    value.copy_from_slice(raw);
    Ok(u32::from_le_bytes(value))
}

fn forced_schedule_artifact_u64(
    bytes: &[u8],
    offset: usize,
) -> Result<u64, ForcedScheduleArtifactError> {
    let end = offset
        .checked_add(8)
        .ok_or(ForcedScheduleArtifactError::LengthOverflow {
            dispatch_count: u64::MAX,
        })?;
    let Some(raw) = bytes.get(offset..end) else {
        return Err(ForcedScheduleArtifactError::Truncated {
            expected: end,
            found: bytes.len(),
        });
    };
    let mut value = [0u8; 8];
    value.copy_from_slice(raw);
    Ok(u64::from_le_bytes(value))
}

const fn forced_schedule_lane_tag(lane: DispatchLane) -> u8 {
    match lane {
        DispatchLane::Cancel => 0,
        DispatchLane::Timed => 1,
        DispatchLane::Ready => 2,
        DispatchLane::Stolen => 3,
    }
}

fn forced_schedule_lane_from_tag(
    index: usize,
    tag: u8,
) -> Result<DispatchLane, ForcedScheduleArtifactError> {
    match tag {
        0 => Ok(DispatchLane::Cancel),
        1 => Ok(DispatchLane::Timed),
        2 => Ok(DispatchLane::Ready),
        3 => Ok(DispatchLane::Stolen),
        _ => Err(ForcedScheduleArtifactError::LaneTag { index, tag }),
    }
}

fn forced_schedule_bool(tag: u8, field: &'static str) -> Result<bool, ForcedScheduleArtifactError> {
    match tag {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(ForcedScheduleArtifactError::BooleanTag { field, tag }),
    }
}

fn validate_complete_forced_schedule_shape(
    schedule: &ForcedSchedule,
) -> Result<(), ForcedScheduleError> {
    if schedule.version != FORCED_SCHEDULE_SCHEMA_VERSION {
        return Err(ForcedScheduleError::SchemaMismatch {
            expected: FORCED_SCHEDULE_SCHEMA_VERSION,
            found: schedule.version,
        });
    }
    if schedule.truncated || !schedule.terminal_quiescent {
        return Err(ForcedScheduleError::PartialSource);
    }
    validate_dispatch_order(&schedule.dispatches)?;
    if schedule.dispatches.last().is_some_and(|dispatch| {
        dispatch.at_step > schedule.terminal_steps || dispatch.at_nanos > schedule.terminal_nanos
    }) {
        return Err(ForcedScheduleError::PartialSource);
    }
    Ok(())
}

/// Why a [`LabRuntime::run_with_auto_advance`] loop terminated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AutoAdvanceTermination {
    /// The runtime reached quiescence: no runnable tasks, no pending timers,
    /// and all regions are closed.
    Quiescent,
    /// The configured `max_steps` limit was reached before quiescence.
    StepLimitReached,
    /// The runtime was stuck (scheduler empty, no pending deadlines, not
    /// quiescent) for 1 000 consecutive iterations, or replay forbade further
    /// dispatch. See [`LabRuntime::production_replay_boundary`] for the typed
    /// replay reason; a replay pause returns immediately without advancing time.
    StuckBailout,
}

impl fmt::Display for AutoAdvanceTermination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Quiescent => f.write_str("quiescent"),
            Self::StepLimitReached => f.write_str("step-limit-reached"),
            Self::StuckBailout => f.write_str("stuck-bailout"),
        }
    }
}

/// Report from a [`LabRuntime::run_with_auto_advance`] execution.
///
/// Captures statistics about automatic time advancement during the run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VirtualTimeReport {
    /// Total scheduler steps executed.
    pub steps: u64,
    /// Number of times virtual time was auto-advanced to the next pending
    /// timer or lab-reactor deadline.
    pub auto_advances: u64,
    /// Total timer wakeups triggered by auto-advances.
    pub total_wakeups: u64,
    /// Virtual time at the start of the run.
    pub time_start: Time,
    /// Virtual time at the end of the run.
    pub time_end: Time,
    /// Total virtual nanoseconds elapsed during the run.
    pub virtual_elapsed_nanos: u64,
    /// Why the auto-advance loop terminated.
    pub termination: AutoAdvanceTermination,
}

impl VirtualTimeReport {
    /// Returns the virtual elapsed time in milliseconds.
    #[must_use]
    pub const fn virtual_elapsed_ms(&self) -> u64 {
        self.virtual_elapsed_nanos / 1_000_000
    }

    /// Returns the virtual elapsed time in seconds.
    #[must_use]
    pub const fn virtual_elapsed_secs(&self) -> u64 {
        self.virtual_elapsed_nanos / 1_000_000_000
    }
}

/// Structured report for a single lab runtime run.
///
/// This is intended as a low-level building block for Spork app harnesses.
/// It contains canonical trace fingerprints and oracle outcomes, but it does
/// not write to stdout/stderr or persist artifacts.
#[derive(Debug, Clone)]
pub struct LabRunReport {
    /// Lab seed driving scheduling determinism.
    pub seed: u64,
    /// Steps executed during the `run_until_quiescent()` call that produced this report.
    pub steps_delta: u64,
    /// Total steps executed by the runtime so far.
    pub steps_total: u64,
    /// Whether the runtime is quiescent at report time.
    pub quiescent: bool,
    /// Virtual time (nanoseconds since epoch) at report time.
    pub now_nanos: u64,
    /// Number of events in the current trace buffer snapshot.
    pub trace_len: usize,
    /// Canonical fingerprint of the trace equivalence class (Foata / Mazurkiewicz).
    pub trace_fingerprint: u64,
    /// Trace certificate summary (event hash/count + schedule hash).
    pub trace_certificate: LabTraceCertificateSummary,
    /// Unified oracle report (stable ordering, serializable).
    pub oracle_report: crate::lab::oracle::OracleReport,
    /// Runtime invariant violations detected by `LabRuntime::check_invariants()`
    /// plus stable `oracle:<name>` mirrors for every failed oracle-suite row.
    ///
    /// Runtime checks remain distinct from the oracle suite; the `oracle:` rows
    /// are stable references to failed suite entries for consumers of this
    /// aggregate channel.
    pub invariant_violations: Vec<String>,
    /// Temporal-oracle invariants that failed in this report.
    pub temporal_invariant_failures: Vec<String>,
    /// Minimized divergent-prefix length for temporal failures, when available.
    pub temporal_counterexample_prefix_len: Option<usize>,
    /// First failed refinement-firewall rule id, when present.
    pub refinement_firewall_rule_id: Option<String>,
    /// Event index where refinement-firewall first failed.
    pub refinement_firewall_event_index: Option<usize>,
    /// Event sequence where refinement-firewall first failed.
    pub refinement_firewall_event_seq: Option<u64>,
    /// Deterministic minimal counterexample prefix length for refinement failures.
    pub refinement_counterexample_prefix_len: Option<usize>,
    /// Whether refinement checks were skipped due to trace-buffer truncation.
    pub refinement_firewall_skipped_due_to_trace_truncation: bool,
}

impl LabRunReport {
    /// Returns true when the report satisfies the `#[lab_test]` success contract.
    #[must_use]
    pub fn lab_test_passed(&self) -> bool {
        self.quiescent && self.oracle_report.all_passed() && self.invariant_violations.is_empty()
    }

    /// Convert to JSON for artifact storage.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        use serde_json::json;

        json!({
            "seed": self.seed,
            "steps_delta": self.steps_delta,
            "steps_total": self.steps_total,
            "quiescent": self.quiescent,
            "now_nanos": self.now_nanos,
            "trace": {
                "len": self.trace_len,
                "fingerprint": self.trace_fingerprint,
                "certificate": {
                    "event_hash": self.trace_certificate.event_hash,
                    "event_count": self.trace_certificate.event_count,
                    "schedule_hash": self.trace_certificate.schedule_hash,
                }
            },
            "oracles": self.oracle_report.to_json(),
            "invariants": self.invariant_violations,
            "temporal": {
                "failed_invariants": self.temporal_invariant_failures,
                "counterexample_prefix_len": self.temporal_counterexample_prefix_len,
            },
            "refinement_firewall": {
                "rule_id": self.refinement_firewall_rule_id,
                "event_index": self.refinement_firewall_event_index,
                "event_seq": self.refinement_firewall_event_seq,
                "counterexample_prefix_len": self.refinement_counterexample_prefix_len,
                "skipped_due_to_trace_truncation": self.refinement_firewall_skipped_due_to_trace_truncation,
            },
        })
    }

    /// Export this run's trace events to a TLA+ module for model checking.
    ///
    /// Converts the captured trace into a TLA+ behavior (concrete state
    /// sequence) with property templates for the 6 core invariants. The
    /// resulting module can be fed to TLC for bounded model checking.
    ///
    /// Returns `None` if no trace events were captured.
    #[must_use]
    pub fn export_tla(
        &self,
        trace_events: &[crate::trace::TraceEvent],
        module_name: &str,
    ) -> Option<crate::trace::tla_export::TlaModule> {
        if trace_events.is_empty() {
            return None;
        }
        let exporter = crate::trace::tla_export::TlaExporter::from_trace(trace_events);
        if exporter.snapshot_count() == 0 {
            return None;
        }
        Some(exporter.export_behavior(module_name))
    }
}

/// Crashpack artifact written by the lab auto-forensics path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabAutoCrashpack {
    /// Filesystem path of the written crashpack.
    pub path: String,
    /// One-command replay recipe embedded in the crashpack.
    pub replay: ReplayCommand,
}

/// Error returned when lab auto-forensics cannot write a crashpack.
#[derive(Debug)]
pub enum LabAutoCrashpackError {
    /// Creating the deterministic artifact directory failed.
    CreateDir {
        /// Directory that could not be created.
        path: PathBuf,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// Serializing or writing the crashpack failed.
    Write(CrashPackWriteError),
}

impl fmt::Display for LabAutoCrashpackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CreateDir { path, source } => {
                write!(
                    f,
                    "failed to create lab crashpack directory {}: {source}",
                    path.display()
                )
            }
            Self::Write(source) => write!(f, "{source}"),
        }
    }
}

impl std::error::Error for LabAutoCrashpackError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::CreateDir { source, .. } => Some(source),
            Self::Write(source) => Some(source),
        }
    }
}

impl From<CrashPackWriteError> for LabAutoCrashpackError {
    fn from(source: CrashPackWriteError) -> Self {
        Self::Write(source)
    }
}

const TEMPORAL_ORACLE_INVARIANTS: &[&str] = &[
    "task_leak",
    "obligation_leak",
    "quiescence",
    "cancellation_protocol",
    "loser_drain",
    "region_tree",
    "deadline_monotone",
    #[cfg(feature = "messaging-fabric")]
    "fabric_publish",
    #[cfg(feature = "messaging-fabric")]
    "fabric_reply",
    #[cfg(feature = "messaging-fabric")]
    "fabric_quiescence",
    #[cfg(feature = "messaging-fabric")]
    "fabric_redelivery",
];

// ---------------------------------------------------------------------------
// Spork app harness report schema (bd-11dm5)
// ---------------------------------------------------------------------------

/// Snapshot of a [`LabConfig`] captured into a stable, JSON-friendly schema.
///
/// This is intentionally a *summary* (not the raw config), so downstream tools
/// can depend on a stable field set without pulling in internal config types.
#[derive(Debug, Clone, PartialEq)]
pub struct LabConfigSummary {
    /// Random seed for deterministic scheduling.
    pub seed: u64,
    /// Seed for capability entropy sources (may be decoupled from `seed`).
    pub entropy_seed: u64,
    /// Number of modeled workers in the deterministic multi-worker simulation.
    pub worker_count: usize,
    /// Whether the runtime panics on obligation leaks in lab mode.
    pub panic_on_obligation_leak: bool,
    /// Capacity of the trace buffer.
    pub trace_capacity: usize,
    /// Maximum steps a task may remain unpolled while holding obligations before futurelock triggers.
    pub futurelock_max_idle_steps: u64,
    /// Whether the runtime panics when a futurelock is detected.
    pub panic_on_futurelock: bool,
    /// Optional maximum step limit for a run.
    pub max_steps: Option<u64>,
    /// Chaos configuration summary, when enabled.
    pub chaos: Option<ChaosConfigSummary>,
    /// Whether replay recording is enabled.
    pub replay_recording_enabled: bool,
}

impl LabConfigSummary {
    /// Build a config summary from the full [`LabConfig`].
    #[must_use]
    pub fn from_config(config: &LabConfig) -> Self {
        Self {
            seed: config.seed,
            entropy_seed: config.entropy_seed,
            worker_count: config.worker_count,
            panic_on_obligation_leak: config.panic_on_obligation_leak,
            trace_capacity: config.trace_capacity,
            futurelock_max_idle_steps: config.futurelock_max_idle_steps,
            panic_on_futurelock: config.panic_on_futurelock,
            max_steps: config.max_steps,
            chaos: config.chaos.as_ref().map(ChaosConfigSummary::from_config),
            replay_recording_enabled: config.replay_recording.is_some(),
        }
    }

    /// Compute a stable hash of the configuration for quick equivalence checking.
    ///
    /// Two configs with the same hash produced identical lab setups. Agents can
    /// compare config hashes across runs to confirm they used the same settings.
    #[must_use]
    pub fn config_hash(&self) -> u64 {
        use std::hash::{Hash, Hasher};
        // DefaultHasher is NOT stable across Rust versions; DetHasher uses a
        // fixed algorithm and seed for cross-version deterministic hashing.
        let mut h = crate::util::DetHasher::for_lab();
        self.seed.hash(&mut h);
        self.entropy_seed.hash(&mut h);
        self.worker_count.hash(&mut h);
        self.panic_on_obligation_leak.hash(&mut h);
        self.trace_capacity.hash(&mut h);
        self.futurelock_max_idle_steps.hash(&mut h);
        self.panic_on_futurelock.hash(&mut h);
        self.max_steps.hash(&mut h);
        self.replay_recording_enabled.hash(&mut h);
        if let Some(ref c) = self.chaos {
            1u8.hash(&mut h);
            c.seed.hash(&mut h);
            c.cancel_probability.to_bits().hash(&mut h);
            c.delay_probability.to_bits().hash(&mut h);
            c.io_error_probability.to_bits().hash(&mut h);
            c.wakeup_storm_probability.to_bits().hash(&mut h);
            c.budget_exhaust_probability.to_bits().hash(&mut h);
        } else {
            0u8.hash(&mut h);
        }
        h.finish()
    }

    /// Convert to JSON for artifact storage.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        use serde_json::json;

        json!({
            "seed": self.seed,
            "entropy_seed": self.entropy_seed,
            "worker_count": self.worker_count,
            "panic_on_obligation_leak": self.panic_on_obligation_leak,
            "trace_capacity": self.trace_capacity,
            "futurelock_max_idle_steps": self.futurelock_max_idle_steps,
            "panic_on_futurelock": self.panic_on_futurelock,
            "max_steps": self.max_steps,
            "chaos": self.chaos.as_ref().map(ChaosConfigSummary::to_json),
            "replay_recording_enabled": self.replay_recording_enabled,
        })
    }
}

/// JSON-friendly summary of chaos settings.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ChaosConfigSummary {
    /// Seed for deterministic chaos injection.
    pub seed: u64,
    /// Probability of injecting cancellation at each poll point.
    pub cancel_probability: f64,
    /// Probability of injecting delay at each poll point.
    pub delay_probability: f64,
    /// Probability of injecting an I/O error.
    pub io_error_probability: f64,
    /// Probability of triggering a spurious wakeup storm.
    pub wakeup_storm_probability: f64,
    /// Probability of injecting budget exhaustion.
    pub budget_exhaust_probability: f64,
}

impl ChaosConfigSummary {
    /// Build a chaos summary from the full chaos configuration.
    #[must_use]
    pub fn from_config(config: &crate::lab::chaos::ChaosConfig) -> Self {
        Self {
            seed: config.seed,
            cancel_probability: config.cancel_probability,
            delay_probability: config.delay_probability,
            io_error_probability: config.io_error_probability,
            wakeup_storm_probability: config.wakeup_storm_probability,
            budget_exhaust_probability: config.budget_exhaust_probability,
        }
    }

    /// Convert to JSON for artifact storage.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        use serde_json::json;

        json!({
            "seed": self.seed,
            "cancel_probability": self.cancel_probability,
            "delay_probability": self.delay_probability,
            "io_error_probability": self.io_error_probability,
            "wakeup_storm_probability": self.wakeup_storm_probability,
            "budget_exhaust_probability": self.budget_exhaust_probability,
        })
    }
}

/// Attachment kind for Spork harness reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum HarnessAttachmentKind {
    /// Crash pack artifact (minimal repro pack).
    CrashPack,
    /// Replay trace artifact (recorded non-determinism for replay).
    ReplayTrace,
    /// Generic trace artifact (e.g., NDJSON/JSON trace snapshot).
    Trace,
    /// Other harness-defined artifact.
    Other,
}

impl fmt::Display for HarnessAttachmentKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CrashPack => write!(f, "crashpack"),
            Self::ReplayTrace => write!(f, "replay_trace"),
            Self::Trace => write!(f, "trace"),
            Self::Other => write!(f, "other"),
        }
    }
}

/// Report attachment reference (path-only).
///
/// The lab runtime does not write artifacts; this is a schema hook that a harness
/// can fill in when it persists crash packs, replay traces, etc.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HarnessAttachmentRef {
    /// Attachment kind (used for deterministic ordering and downstream routing).
    pub kind: HarnessAttachmentKind,
    /// Artifact path (relative or absolute; interpreted by the harness).
    pub path: String,
}

impl HarnessAttachmentRef {
    /// Convenience constructor for crash pack attachments.
    #[must_use]
    pub fn crashpack(path: impl Into<String>) -> Self {
        Self {
            kind: HarnessAttachmentKind::CrashPack,
            path: path.into(),
        }
    }

    /// Convenience constructor for replay trace attachments.
    #[must_use]
    pub fn replay_trace(path: impl Into<String>) -> Self {
        Self {
            kind: HarnessAttachmentKind::ReplayTrace,
            path: path.into(),
        }
    }

    /// Convenience constructor for generic trace attachments.
    #[must_use]
    pub fn trace(path: impl Into<String>) -> Self {
        Self {
            kind: HarnessAttachmentKind::Trace,
            path: path.into(),
        }
    }

    /// Convert to JSON for artifact storage.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        use serde_json::json;

        json!({
            "kind": self.kind.to_string(),
            "path": self.path,
        })
    }
}

/// Deterministic crashpack linkage metadata exposed in harness reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrashpackLink {
    /// Artifact path for the crashpack attachment.
    pub path: String,
    /// Stable crashpack identifier (seed + fingerprint tuple).
    pub id: String,
    /// Canonical trace fingerprint associated with this crashpack.
    pub fingerprint: u64,
    /// Reproduction command generated from the run config and crashpack path.
    pub replay: ReplayCommand,
}

impl CrashpackLink {
    /// Convert to JSON for artifact storage.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        use serde_json::json;

        json!({
            "path": self.path,
            "id": self.id,
            "fingerprint": self.fingerprint,
            "replay": self.replay,
        })
    }
}

/// Stable, JSON-first report schema for Spork app harness runs.
///
/// This wraps [`LabRunReport`] and adds:
/// - config snapshot (lab-side)
/// - stable fingerprint extraction points
/// - optional artifact attachment references (crash packs, replay traces, ...)
#[derive(Debug, Clone)]
pub struct SporkHarnessReport {
    /// Schema version for stable downstream parsing.
    pub schema_version: u32,
    /// Application identifier/name for the harness run.
    pub app: String,
    /// Lab configuration snapshot used for the run.
    pub config: LabConfigSummary,
    /// Low-level lab run report (trace fingerprints + oracles + invariants).
    pub run: LabRunReport,
    /// Optional attachment references (crash packs, replay traces, etc.).
    pub attachments: Vec<HarnessAttachmentRef>,
}

impl SporkHarnessReport {
    /// Current stable schema version.
    ///
    /// Increment when the JSON contract changes in a backward-incompatible way.
    /// Backward-compatible additions (new optional fields) do NOT require a bump.
    /// Breaking changes (field renames, type changes, removals) MUST bump this
    /// and document the migration in a comment here.
    ///
    /// # Version history
    ///
    /// - **v1**: Initial schema (bd-11dm5). Top-level keys: `schema_version`,
    ///   `app`, `lab`, `fingerprints`, `run`, `attachments`.
    /// - **v2**: Agent report contract (bd-f262i). Added `lab.config_hash` for
    ///   quick equivalence checking. Added `verdict` top-level key. No
    ///   breaking changes to existing fields.
    /// - **v3**: Crashpack linking contract (bd-1wen4). Added top-level
    ///   `crashpack` object with deterministic path/id/fingerprint/replay.
    pub const SCHEMA_VERSION: u32 = 3;

    /// Create a new harness report from a low-level lab run report.
    #[must_use]
    pub fn new(
        app: impl Into<String>,
        config: &LabConfig,
        run: LabRunReport,
        attachments: Vec<HarnessAttachmentRef>,
    ) -> Self {
        Self {
            schema_version: Self::SCHEMA_VERSION,
            app: app.into(),
            config: LabConfigSummary::from_config(config),
            run,
            attachments,
        }
    }

    // -------------------------------------------------------------------------
    // Agent UX convenience methods (bd-f262i)
    // -------------------------------------------------------------------------

    /// Quick pass/fail verdict: quiescent, with all oracles passed and no
    /// invariant violations.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.run.lab_test_passed()
    }

    /// The canonical trace fingerprint for this run.
    #[must_use]
    pub fn trace_fingerprint(&self) -> u64 {
        self.run.trace_fingerprint
    }

    /// The lab seed that drove this run.
    #[must_use]
    pub fn seed(&self) -> u64 {
        self.run.seed
    }

    /// Config hash for quick equivalence checking across runs.
    #[must_use]
    pub fn config_hash(&self) -> u64 {
        self.config.config_hash()
    }

    /// Returns the path to the first crashpack attachment, if any.
    #[must_use]
    pub fn crashpack_path(&self) -> Option<&str> {
        self.attachments
            .iter()
            .find(|a| a.kind == HarnessAttachmentKind::CrashPack)
            .map(|a| a.path.as_str())
    }

    /// Deterministic crashpack linkage metadata when a crashpack is attached.
    #[must_use]
    pub fn crashpack_link(&self) -> Option<CrashpackLink> {
        let path = self.crashpack_path()?.to_string();
        let crash_config = CrashPackConfig {
            seed: self.seed(),
            config_hash: self.config_hash(),
            worker_count: self.config.worker_count,
            max_steps: self.config.max_steps,
            test_name: None,
            commit_hash: compiled_commit_hash(),
        };
        let replay = ReplayCommand::from_config_cli(&crash_config, &path);
        Some(CrashpackLink {
            id: format!(
                "crashpack-{seed:016x}-{fingerprint:016x}",
                seed = self.seed(),
                fingerprint = self.trace_fingerprint()
            ),
            fingerprint: self.trace_fingerprint(),
            path,
            replay,
        })
    }

    /// Returns oracle failure descriptions, if any.
    #[must_use]
    pub fn oracle_failures(&self) -> Vec<String> {
        self.run
            .oracle_report
            .failures()
            .iter()
            .map(|e| {
                let desc = e
                    .violation
                    .as_ref()
                    .map_or_else(String::new, |v| format!(": {v}"));
                format!("{}{desc}", e.invariant)
            })
            .collect()
    }

    /// One-line human-readable summary suitable for agent log output.
    ///
    /// Format: `[PASS|FAIL] app="name" seed=N fingerprint=N oracles=P/T`
    #[must_use]
    pub fn summary_line(&self) -> String {
        let verdict = if self.passed() { "PASS" } else { "FAIL" };
        let oracle = &self.run.oracle_report;
        format!(
            "[{verdict}] app=\"{}\" seed={} fingerprint={} oracles={}/{} invariant_violations={}",
            self.app,
            self.run.seed,
            self.run.trace_fingerprint,
            oracle.passed,
            oracle.total,
            self.run.invariant_violations.len(),
        )
    }

    /// Convert to JSON for artifact storage.
    ///
    /// # Agent Report Contract (bd-f262i)
    ///
    /// This is the **single stable JSON schema** that agents rely on across:
    /// - Lab runs (`SporkAppHarness::run_to_report`)
    /// - DPOR exploration (`ExplorationReport` wraps these)
    /// - Conformance suites (test assertions against these fields)
    ///
    /// ## Top-level fields (v2)
    ///
    /// | Key              | Type    | Stable? | Description                              |
    /// |------------------|---------|---------|------------------------------------------|
    /// | `schema_version` | u32     | yes     | Schema version (bump on breaking change) |
    /// | `verdict`        | string  | yes     | `"pass"` or `"fail"`                     |
    /// | `app.name`       | string  | yes     | Application name from `AppSpec`           |
    /// | `lab.config`     | object  | yes     | Full config snapshot                      |
    /// | `lab.config_hash`| u64     | yes     | Quick config equivalence hash             |
    /// | `fingerprints.*` | u64     | yes     | Trace/schedule fingerprints               |
    /// | `run.*`          | object  | yes     | Full `LabRunReport` (oracles, invariants) |
    /// | `crashpack`      | object? | yes     | Deterministic crashpack linkage metadata  |
    /// | `attachments`    | array   | yes     | Sorted by (kind, path)                    |
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        use serde_json::json;

        // Ensure stable ordering regardless of insertion order.
        let mut attachments = self.attachments.clone();
        attachments.sort_by(|a, b| (a.kind, &a.path).cmp(&(b.kind, &b.path)));

        json!({
            "schema_version": self.schema_version,
            "verdict": if self.passed() { "pass" } else { "fail" },
            "app": { "name": self.app },
            "lab": {
                "config": self.config.to_json(),
                "config_hash": self.config.config_hash(),
            },
            "fingerprints": {
                "trace": self.run.trace_fingerprint,
                "event_hash": self.run.trace_certificate.event_hash,
                "event_count": self.run.trace_certificate.event_count,
                "schedule_hash": self.run.trace_certificate.schedule_hash,
            },
            "run": self.run.to_json(),
            "crashpack": self.crashpack_link().map(|link| link.to_json()),
            "attachments": attachments.iter().map(HarnessAttachmentRef::to_json).collect::<Vec<_>>(),
        })
    }
}

/// Retires producer admission and queued work before the lab's state drops.
/// Kept in a private field so `LabRuntime` itself need not implement `Drop`:
/// callers may continue moving its public state and scheduler fields out.
#[derive(Debug)]
struct LabSpawnShutdown {
    liveness: Option<Arc<()>>,
    mailbox: Arc<crate::runtime::spawn_mailbox::SpawnMailbox>,
}

impl Drop for LabSpawnShutdown {
    fn drop(&mut self) {
        fn isolate(cleanup: impl FnOnce()) {
            if let Err(payload) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(cleanup)) {
                // A user panic payload can itself panic when destroyed.
                std::mem::forget(payload);
            }
        }

        if let Some(token) = self.liveness.take() {
            let publishers = Arc::downgrade(&token);
            drop(token);
            // Match native teardown: a producer already holding the token may
            // finish publishing before we perform the final mailbox drain.
            while publishers.strong_count() > 0 {
                std::thread::park_timeout(Duration::from_millis(1));
            }
        }
        self.mailbox.retire_region_commands();
        let mut cancelled = Vec::new();
        while self.mailbox.dequeue_handle_cancels_into(64, &mut cancelled) > 0 {
            for request in cancelled.drain(..) {
                isolate(|| {
                    if let Some(slot) = request.admitted_slot {
                        slot.abandon_unpublished_spawn_effects();
                    }
                });
            }
        }
        while let Some(request) = self.mailbox.dequeue() {
            let mut parts = request.into_parts();
            // Keep the region's pending credit until even the panic fallback
            // has made retirement visible to the caller.
            let pending_reservation = parts.pending_reservation.take();
            let barrier = parts
                .admitted_slot
                .as_ref()
                .and_then(|slot| slot.retirement_barrier());
            isolate(|| parts.resolve_cancelled(crate::types::CancelReason::shutdown()));
            // If a captured destructor panicked before the denial callback,
            // the sender is now dropped but its join still needs retirement.
            if let Some(barrier) = barrier {
                isolate(|| barrier.open_after_shutdown());
            }
            drop(pending_reservation);
        }
    }
}

/// The deterministic lab runtime.
///
/// This runtime is designed for testing and provides:
/// - Virtual time instead of wall-clock time
/// - Deterministic scheduling based on a seed
/// - Trace capture for debugging and replay
/// - Chaos injection for stress testing
#[derive(Debug)]
pub struct LabRuntime {
    // Field drop order is significant: reject further spawns before dropping
    // state-owned futures, whose destructors may retain and use a parent Cx.
    _spawn_shutdown: LabSpawnShutdown,
    /// Runtime state (public for tests and oracle access).
    pub state: RuntimeState,
    /// Lab reactor for deterministic I/O simulation.
    lab_reactor: Arc<LabReactor>,
    /// Deterministic spawn intake (br-asupersync-4h8lye / A2.1): requests
    /// enqueued here are admitted in FIFO order at the top of each step.
    spawn_mailbox: Arc<crate::runtime::spawn_mailbox::SpawnMailbox>,
    /// Tokens seen for I/O submissions (for trace emission).
    seen_io_tokens: DetHashSet<usize>,
    /// Scheduler.
    pub scheduler: Arc<Mutex<LabScheduler>>,
    /// Configuration.
    config: LabConfig,
    /// Deterministic RNG.
    rng: DetRng,
    /// Current virtual time.
    virtual_time: Time,
    /// Virtual clock backing the timer driver.
    virtual_clock: Arc<VirtualClock>,
    /// Number of steps executed.
    steps: u64,
    /// Number of steps that actually dispatched a task.
    ///
    /// GH#55: `steps` counts loop turns, including turns where the scheduler
    /// reported pending work but nothing was dispatchable. Progress-based
    /// bailouts must key off this counter, not `steps`, or a task stranded in
    /// `LabScheduler::scheduled` spins forever while looking busy.
    dispatches: u64,
    /// Chaos RNG for deterministic fault injection.
    chaos_rng: Option<ChaosRng>,
    /// Statistics about chaos injections.
    chaos_stats: ChaosStats,
    /// Reactor chaos statistics already folded into `chaos_stats`.
    seen_reactor_chaos_stats: ChaosStats,
    /// Replay recorder for deterministic trace capture.
    replay_recorder: TraceRecorder,
    /// Optional bounded recorder for exact lab dispatch choices.
    forced_schedule_recorder: Option<ForcedScheduleRecorder>,
    /// Optional production-schedule oracle (br-asupersync-bi2462.7).
    production_replay: Option<ProductionReplayState>,
    /// Optional deadline monitor for warning callbacks.
    deadline_monitor: Option<DeadlineMonitor>,
    /// Oracle suite for invariant verification.
    pub oracles: OracleSuite,
    /// Schedule certificate for determinism verification.
    certificate: ScheduleCertificate,
}

impl LabRuntime {
    /// Creates a new lab runtime with the given configuration.
    #[must_use]
    pub fn new(config: LabConfig) -> Self {
        let rng = config.rng();
        let chaos_rng = config.chaos.as_ref().map(ChaosRng::from_config);
        let lab_reactor = config.chaos.as_ref().map_or_else(
            || Arc::new(LabReactor::new()),
            |chaos| Arc::new(LabReactor::with_chaos(chaos.clone())),
        );
        let mut state = RuntimeState::with_reactor(lab_reactor.clone());
        state.trace = TraceBufferHandle::new(config.trace_capacity);
        state.set_logical_clock_mode(crate::trace::distributed::LogicalClockMode::Lamport);
        state.set_obligation_leak_response(if config.panic_on_obligation_leak {
            ObligationLeakResponse::Panic
        } else {
            ObligationLeakResponse::Log
        });
        let virtual_clock = Arc::new(VirtualClock::starting_at(Time::ZERO));
        state.set_timer_driver(crate::time::TimerDriverHandle::with_virtual_clock(
            virtual_clock.clone(),
        ));
        // Producer-side spawn gateway (br-asupersync-hwjqyo / A2.2): the
        // lab drains this mailbox synchronously at the top of each step, so
        // the notifier is a no-op.
        let spawn_mailbox = Arc::new(crate::runtime::spawn_mailbox::SpawnMailbox::with_trace(
            state.trace_handle(),
        ));
        let spawn_liveness = Arc::new(());
        // Managed supervisors record restart history for the supervision
        // oracle, and GenServer replies their resolution for the
        // reply-linearity oracle (br-asupersync-52hxjz).
        let supervision_history = state.supervision_history_handle();
        let reply_history = state.reply_history_handle();
        state.set_spawn_gateway(Arc::new(
            crate::runtime::spawn_mailbox::SpawnGateway::new(
                Arc::clone(&spawn_mailbox),
                Arc::new(|| {}),
                state.timer_driver_handle(),
                Arc::downgrade(&spawn_liveness),
            )
            .with_supervision_history(supervision_history)
            .with_reply_history(reply_history),
        ));
        // Obligation mailbox (br-asupersync-bi2462.13): drained at the start
        // of every step next to spawn admissions, so token reserve/commit/
        // abort/leak posts reach `RuntimeState` deterministically.
        state.set_obligation_gateway(Arc::new(
            crate::runtime::obligation_mailbox::ObligationGateway::new(
                Arc::new(crate::runtime::obligation_mailbox::ObligationMailbox::new()),
                Arc::new(|| {}),
                Arc::downgrade(&spawn_liveness),
            ),
        ));
        state.set_entropy_source(Arc::new(DetEntropy::new(config.entropy_seed)));

        // Initialize replay recorder if configured
        let mut replay_recorder = if let Some(ref rec_config) = config.replay_recording {
            TraceRecorder::with_config(TraceMetadata::new(config.seed), rec_config.clone())
        } else {
            TraceRecorder::disabled()
        };

        // Record initial RNG seed
        replay_recorder.record_rng_seed(config.seed);

        crate::tracing_compat::info!("virtual clock initialized: start_time_ms=0");

        Self {
            _spawn_shutdown: LabSpawnShutdown {
                liveness: Some(spawn_liveness),
                mailbox: Arc::clone(&spawn_mailbox),
            },
            state,
            lab_reactor,
            spawn_mailbox,
            // GH#55: derive lab hashing from the lab seed rather than
            // `Default::default()`, which is randomly seeded in builds
            // without `test-internals` and breaks lab determinism.
            seen_io_tokens: DetHashSet::with_hasher(
                crate::util::det_hash::DetBuildHasher::with_seed(config.seed),
            ),
            scheduler: Arc::new(Mutex::new(LabScheduler::new(
                config.worker_count,
                config.seed,
            ))),
            config,
            rng,
            virtual_time: Time::ZERO,
            virtual_clock,
            steps: 0,
            dispatches: 0,
            chaos_rng,
            chaos_stats: ChaosStats::new(),
            seen_reactor_chaos_stats: ChaosStats::new(),
            replay_recorder,
            forced_schedule_recorder: None,
            production_replay: None,
            deadline_monitor: None,
            oracles: OracleSuite::new(),
            certificate: ScheduleCertificate::new(),
        }
    }

    /// Creates a lab runtime with the default configuration.
    #[must_use]
    pub fn with_seed(seed: u64) -> Self {
        Self::new(LabConfig::new(seed))
    }

    /// Returns the current virtual time.
    #[must_use]
    pub const fn now(&self) -> Time {
        self.virtual_time
    }

    /// Returns the number of steps executed.
    #[must_use]
    pub const fn steps(&self) -> u64 {
        self.steps
    }

    /// Returns a reference to the configuration.
    #[must_use]
    pub const fn config(&self) -> &LabConfig {
        &self.config
    }

    /// Returns a handle to the lab reactor for deterministic I/O injection.
    #[must_use]
    pub fn lab_reactor(&self) -> &Arc<LabReactor> {
        &self.lab_reactor
    }

    /// Returns a reference to the trace buffer handle.
    #[must_use]
    pub fn trace(&self) -> &TraceBufferHandle {
        &self.state.trace
    }

    /// Returns a race report derived from the current trace buffer.
    #[must_use]
    pub fn detected_races(&self) -> crate::trace::dpor::RaceReport {
        crate::trace::dpor::detect_hb_races(&self.state.trace.snapshot())
    }

    /// Returns aggregated chaos statistics for both task-side and reactor-side injection.
    #[must_use]
    pub fn chaos_stats(&self) -> &ChaosStats {
        &self.chaos_stats
    }

    /// Returns the schedule certificate for determinism verification.
    #[must_use]
    pub fn certificate(&self) -> &ScheduleCertificate {
        &self.certificate
    }

    /// Returns true if replay recording is enabled.
    #[must_use]
    pub fn has_replay_recording(&self) -> bool {
        self.replay_recorder.is_enabled()
    }

    /// Returns a reference to the replay recorder.
    #[must_use]
    pub fn replay_recorder(&self) -> &TraceRecorder {
        &self.replay_recorder
    }

    /// Takes the replay trace, leaving an empty trace in place.
    ///
    /// Returns `None` if recording is disabled.
    pub fn take_replay_trace(&mut self) -> Option<ReplayTrace> {
        self.replay_recorder.take()
    }

    /// Finishes recording and returns the replay trace.
    ///
    /// This consumes the replay recorder. Returns `None` if recording is disabled.
    pub fn finish_replay_trace(&mut self) -> Option<ReplayTrace> {
        // Take ownership by replacing with a disabled recorder
        let recorder = std::mem::replace(&mut self.replay_recorder, TraceRecorder::disabled());
        recorder.finish()
    }

    /// Starts bounded capture of exact task/worker/lane/step/time dispatches.
    ///
    /// Capture is opt-in and lab-only. Reaching the bound does not perturb the
    /// source execution, but finishing the recorder then fails closed instead
    /// of returning a partial schedule.
    ///
    /// # Errors
    ///
    /// Returns [`ForcedScheduleError::ZeroRecordingLimit`] for a zero bound or
    /// [`ForcedScheduleError::RecordingAlreadyActive`] when capture is active.
    pub fn start_forced_schedule_recording(
        &mut self,
        max_dispatches: usize,
    ) -> Result<(), ForcedScheduleError> {
        if max_dispatches == 0 {
            return Err(ForcedScheduleError::ZeroRecordingLimit);
        }
        if self.forced_schedule_recorder.is_some() {
            return Err(ForcedScheduleError::RecordingAlreadyActive);
        }
        if self.steps != 0 || self.certificate.decisions() != 0 {
            return Err(ForcedScheduleError::RuntimeAlreadyStarted {
                steps: self.steps,
                decisions: self.certificate.decisions(),
            });
        }
        self.forced_schedule_recorder = Some(ForcedScheduleRecorder {
            max_dispatches,
            dispatches: Vec::new(),
            truncated: false,
        });
        Ok(())
    }

    /// Finishes exact dispatch capture and binds it to terminal runtime state.
    ///
    /// # Errors
    ///
    /// Returns a typed error when capture was not active or its event bound was
    /// exceeded. A non-quiescent source is represented in the returned receipt
    /// and is rejected by [`Self::run_forced_schedule`].
    pub fn finish_forced_schedule_recording(
        &mut self,
    ) -> Result<ForcedSchedule, ForcedScheduleError> {
        let recorder = self
            .forced_schedule_recorder
            .take()
            .ok_or(ForcedScheduleError::RecordingNotActive)?;
        if recorder.truncated {
            return Err(ForcedScheduleError::RecordingLimitExceeded {
                max_dispatches: recorder.max_dispatches,
            });
        }
        Ok(ForcedSchedule {
            version: FORCED_SCHEDULE_SCHEMA_VERSION,
            seed: self.config.seed,
            config_hash: forced_schedule_config_hash(&self.config),
            dispatches: recorder.dispatches,
            terminal_steps: self.steps,
            terminal_nanos: self.now().as_nanos(),
            terminal_schedule_hash: self.certificate.hash(),
            terminal_quiescent: self.is_quiescent(),
            truncated: false,
        })
    }

    /// Executes an exact recorded dispatch projection on this fresh lab runtime.
    ///
    /// The next recorded task is removed from its exact authoritative queue
    /// before it is polled. There is no RNG-scheduler fallback: missing, early,
    /// stale, wrong-worker, wrong-lane, wrong-time, or extra work returns a typed
    /// error while leaving the mismatched task unpolled.
    ///
    /// # Errors
    ///
    /// Returns [`ForcedScheduleError`] for incompatible or partial receipts,
    /// exhausted caller limits, or the first execution divergence.
    pub fn run_forced_schedule(
        &mut self,
        schedule: &ForcedSchedule,
        limits: ForcedScheduleLimits,
    ) -> Result<ForcedScheduleReport, ForcedScheduleError> {
        self.validate_forced_schedule(schedule, limits)?;

        let start_steps = self.steps;
        let mut consumed = 0usize;
        while self.steps < schedule.terminal_steps {
            let used = self.steps.saturating_sub(start_steps);
            if used >= limits.max_steps {
                return Err(ForcedScheduleError::WorkLimitExceeded {
                    steps: used,
                    limit: limits.max_steps,
                });
            }

            let next = schedule.dispatches.get(consumed);
            if let Some(dispatch) = next {
                let target = Time::from_nanos(dispatch.at_nanos);
                let can_auto_advance = self.scheduler.lock().is_empty()
                    && self.spawn_mailbox.is_empty()
                    && !self.state.has_deferred_cancel_dispatches()
                    && self.now() < target
                    && self.next_auto_advance_deadline() == Some(target);
                if can_auto_advance {
                    self.advance_time_to(target);
                    let _ = self.pump_due_system_events();
                }
            }

            if self.step_with_forced_dispatch(next.map(|dispatch| (consumed, dispatch)))? {
                consumed = consumed.saturating_add(1);
            }
        }

        // A source using auto-advance can reach its final virtual timestamp
        // after the last task dispatch (for example, while draining a reactor
        // event that does not wake another task). Reproduce that one bounded
        // terminal jump only when the runtime independently exposes the exact
        // recorded timer/reactor deadline. A caller-mutated timestamp or an
        // unrecorded manual clock jump is not self-authenticating. If the real
        // deadline makes work runnable, the missing dispatch below is still
        // rejected rather than selected by the normal scheduler.
        let terminal_target = Time::from_nanos(schedule.terminal_nanos);
        if consumed == schedule.dispatches.len()
            && self.scheduler.lock().is_empty()
            && self.spawn_mailbox.is_empty()
            && !self.state.has_deferred_cancel_dispatches()
            && self.now() < terminal_target
            && self.next_auto_advance_deadline() == Some(terminal_target)
        {
            self.advance_time_to(terminal_target);
            let _ = self.pump_due_system_events();
        }

        if consumed != schedule.dispatches.len() || !self.is_quiescent() {
            return Err(ForcedScheduleError::ScheduleExhausted { consumed });
        }
        let actual_nanos = self.now().as_nanos();
        if self.steps != schedule.terminal_steps || actual_nanos != schedule.terminal_nanos {
            return Err(ForcedScheduleError::TerminalMismatch {
                expected_steps: schedule.terminal_steps,
                expected_nanos: schedule.terminal_nanos,
                actual_steps: self.steps,
                actual_nanos,
            });
        }
        let actual_hash = self.certificate.hash();
        if actual_hash != schedule.terminal_schedule_hash {
            return Err(ForcedScheduleError::CertificateMismatch {
                expected: schedule.terminal_schedule_hash,
                actual: actual_hash,
            });
        }

        Ok(ForcedScheduleReport {
            dispatches: consumed,
            steps: self.steps.saturating_sub(start_steps),
            terminal_nanos: actual_nanos,
            schedule_hash: actual_hash,
            quiescent: true,
        })
    }

    /// Executes a deletion-only schedule candidate on this fresh runtime.
    ///
    /// Each retained task/worker/lane tuple is removed from its authoritative
    /// scheduler queue before polling. Scheduler RNG is still advanced as part
    /// of deterministic lab state, but it is never consulted to select a task.
    /// Once the retained choices are exhausted, the runner may pump only
    /// deterministic system work; it never polls an unrecorded task.
    ///
    /// # Errors
    ///
    /// Returns [`ForcedScheduleError`] for invalid provenance, incompatible
    /// runtime configuration, impossible retained choices, allocation failure,
    /// or exhausted caller-owned work.
    pub fn run_forced_schedule_candidate(
        &mut self,
        candidate: &ForcedScheduleCandidate,
        limits: ForcedScheduleCandidateLimits,
    ) -> Result<ForcedScheduleCandidateReport, ForcedScheduleError> {
        self.validate_forced_schedule_candidate(candidate, limits)?;

        let start_steps = self.steps;
        let mut work_units = 0u64;
        let mut consumed_source_indices = Vec::new();
        consumed_source_indices
            .try_reserve_exact(candidate.dispatches.len())
            .map_err(|_| ForcedScheduleError::CandidateAllocationFailed {
                requested: candidate.dispatches.len(),
            })?;

        for (candidate_index, retained) in candidate.dispatches.iter().enumerate() {
            loop {
                if self.has_pending_dispatch_commands() {
                    take_candidate_work(&mut work_units, limits.max_work_units)?;
                    let dispatched = self.step_with_candidate_dispatch(None)?;
                    debug_assert!(
                        !dispatched,
                        "candidate command pump must not poll a retained task"
                    );
                    continue;
                }
                if !self.candidate_has_runnable_work()
                    && let Some(deadline) = self.next_auto_advance_deadline()
                {
                    take_candidate_work(&mut work_units, limits.max_work_units)?;
                    if deadline > self.now() {
                        self.advance_time_to(deadline);
                    }
                    let _ = self.pump_due_system_events();
                    continue;
                }

                take_candidate_work(&mut work_units, limits.max_work_units)?;
                if self.step_with_candidate_dispatch(Some((candidate_index, &retained.dispatch)))? {
                    consumed_source_indices.push(retained.source_index);
                    break;
                }
            }
        }

        let termination = loop {
            if self.is_quiescent() {
                break ForcedScheduleCandidateTermination::Quiescent;
            }
            if self.candidate_has_runnable_work() {
                break ForcedScheduleCandidateTermination::Exhausted;
            }
            if self.has_pending_dispatch_commands() {
                take_candidate_work(&mut work_units, limits.max_work_units)?;
                let dispatched = self.step_with_candidate_dispatch(None)?;
                debug_assert!(
                    !dispatched,
                    "candidate system-work pump must not poll an unrecorded task"
                );
                continue;
            }
            if let Some(deadline) = self.next_auto_advance_deadline() {
                take_candidate_work(&mut work_units, limits.max_work_units)?;
                if deadline > self.now() {
                    self.advance_time_to(deadline);
                }
                let _ = self.pump_due_system_events();
                continue;
            }
            break ForcedScheduleCandidateTermination::Exhausted;
        };

        let steps_delta = self.steps.saturating_sub(start_steps);
        let lab = self.report_with_steps_delta(steps_delta);
        Ok(ForcedScheduleCandidateReport {
            termination,
            consumed_source_indices,
            work_units,
            lab,
        })
    }

    fn candidate_has_runnable_work(&self) -> bool {
        let now = self.now();
        self.scheduler.lock().has_runnable_work(now)
    }

    pub(crate) fn has_pending_dispatch_commands(&self) -> bool {
        !self.spawn_mailbox.is_empty() || self.state.has_deferred_cancel_dispatches()
    }

    /// True when nothing inside the lab can make progress, yet it is not quiescent:
    /// no runnable task, no pending dispatch command or obligation post, and no
    /// timer to fire. Only a wake from outside the lab (a real thread, such as a
    /// blocking pool finishing work) can move it forward.
    pub(crate) fn awaits_external_wake(&self) -> bool {
        self.scheduler.lock().is_empty()
            && !self.has_pending_dispatch_commands()
            && !self.state.has_pending_obligation_posts()
            && self.next_timer_deadline().is_none()
            && !self.is_quiescent()
    }

    fn validate_forced_schedule_candidate(
        &self,
        candidate: &ForcedScheduleCandidate,
        limits: ForcedScheduleCandidateLimits,
    ) -> Result<(), ForcedScheduleError> {
        validate_candidate_limits(limits)?;
        if candidate.version != FORCED_SCHEDULE_CANDIDATE_SCHEMA_VERSION {
            return Err(ForcedScheduleError::CandidateSchemaMismatch {
                expected: FORCED_SCHEDULE_CANDIDATE_SCHEMA_VERSION,
                found: candidate.version,
            });
        }
        if candidate.source_version != FORCED_SCHEDULE_SCHEMA_VERSION {
            return Err(ForcedScheduleError::SchemaMismatch {
                expected: FORCED_SCHEDULE_SCHEMA_VERSION,
                found: candidate.source_version,
            });
        }
        if candidate.seed != self.config.seed {
            return Err(ForcedScheduleError::SeedMismatch {
                expected: self.config.seed,
                found: candidate.seed,
            });
        }
        let config_hash = forced_schedule_config_hash(&self.config);
        if candidate.config_hash != config_hash {
            return Err(ForcedScheduleError::ConfigMismatch {
                expected: config_hash,
                found: candidate.config_hash,
            });
        }
        if self.steps != 0 || self.certificate.decisions() != 0 {
            return Err(ForcedScheduleError::RuntimeAlreadyStarted {
                steps: self.steps,
                decisions: self.certificate.decisions(),
            });
        }
        if candidate.source_dispatch_count > limits.max_source_dispatches {
            return Err(ForcedScheduleError::CandidateSourceLimitExceeded {
                found: candidate.source_dispatch_count,
                limit: limits.max_source_dispatches,
            });
        }
        if candidate.dispatches.len() > limits.max_candidate_dispatches {
            return Err(ForcedScheduleError::DispatchLimitExceeded {
                found: candidate.dispatches.len(),
                limit: limits.max_candidate_dispatches,
            });
        }
        let minimum_work = u64::try_from(candidate.dispatches.len()).unwrap_or(u64::MAX);
        if minimum_work > limits.max_work_units {
            return Err(ForcedScheduleError::CandidateWorkLimitExceeded {
                work_units: minimum_work,
                limit: limits.max_work_units,
            });
        }

        let worker_count = self.config.worker_count.max(1);
        let mut previous_source_index = None;
        let mut retained_dispatches = Vec::new();
        retained_dispatches
            .try_reserve_exact(candidate.dispatches.len())
            .map_err(|_| ForcedScheduleError::CandidateAllocationFailed {
                requested: candidate.dispatches.len(),
            })?;
        for (candidate_index, retained) in candidate.dispatches.iter().enumerate() {
            if retained.source_index >= candidate.source_dispatch_count {
                return Err(ForcedScheduleError::CandidateIndexOutOfRange {
                    candidate_index,
                    source_index: retained.source_index,
                    source_len: candidate.source_dispatch_count,
                });
            }
            if let Some(previous) = previous_source_index
                && retained.source_index <= previous
            {
                return Err(ForcedScheduleError::CandidateIndexOrder {
                    candidate_index,
                    previous,
                    next: retained.source_index,
                });
            }
            if retained.dispatch.worker as usize >= worker_count {
                return Err(ForcedScheduleError::WorkerUnavailable {
                    worker: retained.dispatch.worker,
                    worker_count,
                });
            }
            retained_dispatches.push(retained.dispatch);
            previous_source_index = Some(retained.source_index);
        }
        validate_dispatch_order(&retained_dispatches)
    }

    fn validate_forced_schedule(
        &self,
        schedule: &ForcedSchedule,
        limits: ForcedScheduleLimits,
    ) -> Result<(), ForcedScheduleError> {
        if schedule.version != FORCED_SCHEDULE_SCHEMA_VERSION {
            return Err(ForcedScheduleError::SchemaMismatch {
                expected: FORCED_SCHEDULE_SCHEMA_VERSION,
                found: schedule.version,
            });
        }
        if schedule.seed != self.config.seed {
            return Err(ForcedScheduleError::SeedMismatch {
                expected: self.config.seed,
                found: schedule.seed,
            });
        }
        let config_hash = forced_schedule_config_hash(&self.config);
        if schedule.config_hash != config_hash {
            return Err(ForcedScheduleError::ConfigMismatch {
                expected: config_hash,
                found: schedule.config_hash,
            });
        }
        if self.steps != 0 || self.certificate.decisions() != 0 {
            return Err(ForcedScheduleError::RuntimeAlreadyStarted {
                steps: self.steps,
                decisions: self.certificate.decisions(),
            });
        }
        if schedule.truncated || !schedule.terminal_quiescent {
            return Err(ForcedScheduleError::PartialSource);
        }
        if schedule.dispatches.len() > limits.max_dispatches {
            return Err(ForcedScheduleError::DispatchLimitExceeded {
                found: schedule.dispatches.len(),
                limit: limits.max_dispatches,
            });
        }
        if schedule.terminal_steps > limits.max_steps {
            return Err(ForcedScheduleError::WorkLimitExceeded {
                steps: schedule.terminal_steps,
                limit: limits.max_steps,
            });
        }

        let worker_count = self.config.worker_count.max(1);
        let mut previous_step = 0u64;
        let mut previous_nanos = 0u64;
        for (index, dispatch) in schedule.dispatches.iter().enumerate() {
            if dispatch.at_step <= previous_step {
                return Err(ForcedScheduleError::StepOrder {
                    index,
                    previous: previous_step,
                    next: dispatch.at_step,
                });
            }
            if dispatch.at_nanos < previous_nanos {
                return Err(ForcedScheduleError::TimeOrder {
                    index,
                    previous: previous_nanos,
                    next: dispatch.at_nanos,
                });
            }
            if dispatch.worker as usize >= worker_count {
                return Err(ForcedScheduleError::WorkerUnavailable {
                    worker: dispatch.worker,
                    worker_count,
                });
            }
            previous_step = dispatch.at_step;
            previous_nanos = dispatch.at_nanos;
        }
        if previous_step > schedule.terminal_steps || previous_nanos > schedule.terminal_nanos {
            return Err(ForcedScheduleError::PartialSource);
        }
        Ok(())
    }

    /// Returns true if chaos injection is enabled.
    #[must_use]
    pub fn has_chaos(&self) -> bool {
        self.chaos_rng.is_some() && self.config.has_chaos()
    }

    /// Returns true if the runtime is quiescent.
    #[must_use]
    pub fn is_quiescent(&self) -> bool {
        self.state.is_quiescent()
            && self.spawn_mailbox.is_empty()
            && !self.state.has_pending_obligation_posts()
    }

    /// Advances virtual time by the given number of nanoseconds.
    pub fn advance_time(&mut self, nanos: u64) {
        let from = self.virtual_time;
        self.virtual_time = self.virtual_time.saturating_add_nanos(nanos);
        self.state.now = self.virtual_time;
        self.virtual_clock.advance(nanos);
        self.lab_reactor.advance_time(Duration::from_nanos(nanos));
        // Record time advancement
        self.replay_recorder
            .record_time_advanced(from, self.virtual_time);

        crate::tracing_compat::debug!(
            "virtual clock advanced: delta_ms={}, new_time_ms={}",
            nanos / 1_000_000,
            self.virtual_time.as_nanos() / 1_000_000
        );
    }

    /// Advances time to the given absolute time.
    ///
    /// If the target time is before the current time, logs an error
    /// and does nothing (time cannot go backward).
    pub fn advance_time_to(&mut self, time: Time) {
        if time > self.virtual_time {
            let from = self.virtual_time;
            self.virtual_time = time;
            self.state.now = self.virtual_time;
            self.virtual_clock.advance_to(time);
            self.lab_reactor.advance_time_to(time);
            // Record time advancement
            self.replay_recorder
                .record_time_advanced(from, self.virtual_time);

            crate::tracing_compat::debug!(
                "virtual clock advanced: delta_ms={}, new_time_ms={}",
                (time.as_nanos() - from.as_nanos()) / 1_000_000,
                time.as_nanos() / 1_000_000
            );
        } else if time < self.virtual_time {
            crate::tracing_compat::error!(
                "virtual clock attempt to go backward: current_ms={}, requested_ms={}",
                self.virtual_time.as_nanos() / 1_000_000,
                time.as_nanos() / 1_000_000
            );
        }
    }

    // =========================================================================
    // Virtual time control (bd-1hu19.3)
    // =========================================================================

    /// Advances virtual time to the next timer deadline.
    ///
    /// If a timer is pending, advances time to its deadline, processes the
    /// expired timer(s), and returns the number of wakeups triggered.
    /// Returns 0 if no timers are pending.
    pub fn advance_to_next_timer(&mut self) -> usize {
        let next = self
            .state
            .timer_driver_handle()
            .and_then(|h| h.next_deadline());

        let Some(deadline) = next else {
            return 0;
        };

        if deadline <= self.virtual_time {
            // Timer already expired, just process it
            return self
                .state
                .timer_driver_handle()
                .map_or(0, |h| h.process_timers());
        }

        let delta_nanos = deadline.as_nanos() - self.virtual_time.as_nanos();
        self.advance_time(delta_nanos);

        let wakeups = self
            .state
            .timer_driver_handle()
            .map_or(0, |h| h.process_timers());

        crate::tracing_compat::debug!(
            "virtual clock auto-advance: reason=all_tasks_blocked, \
             next_wakeup_ms={}, delta_ms={}, wakeup_count={}",
            deadline.as_nanos() / 1_000_000,
            delta_nanos / 1_000_000,
            wakeups
        );

        wakeups
    }

    /// Returns the next timer deadline, if any timers are pending.
    #[must_use]
    pub fn next_timer_deadline(&self) -> Option<Time> {
        self.state
            .timer_driver_handle()
            .and_then(|h| h.next_deadline())
    }

    fn next_reactor_deadline(&self) -> Option<Time> {
        self.state
            .io_driver_handle()
            .and_then(|_| self.lab_reactor.next_event_time())
    }

    fn next_auto_advance_deadline(&self) -> Option<Time> {
        match (self.next_timer_deadline(), self.next_reactor_deadline()) {
            (Some(timer), Some(reactor)) => Some(timer.min(reactor)),
            (Some(timer), None) => Some(timer),
            (None, Some(reactor)) => Some(reactor),
            (None, None) => None,
        }
    }

    fn pump_due_system_events(&mut self) -> usize {
        let wakeups = self
            .state
            .timer_driver_handle()
            .map_or(0, |h| h.process_timers());
        self.poll_io();
        self.schedule_async_finalizers();
        self.check_deadline_monitor();
        wakeups
    }

    /// Returns the number of pending timers.
    #[must_use]
    pub fn pending_timer_count(&self) -> usize {
        self.state
            .timer_driver_handle()
            .map_or(0, |h| h.pending_count())
    }

    /// Runs until quiescent, automatically advancing virtual time to pending
    /// timer or lab-reactor deadlines whenever all tasks are idle.
    ///
    /// This enables "instant timeout testing": a scenario that would take
    /// 24 hours of wall-clock time completes in <1 second because every
    /// `sleep`/`timeout` deadline is jumped to instantly.
    ///
    /// The loop is:
    /// 1. Run until idle (no runnable tasks in scheduler).
    /// 2. If timers or lab-reactor events are pending, advance time to the
    ///    next deadline → go to 1.
    /// 3. If no pending virtual deadlines and quiescent → done.
    ///
    /// Returns a [`VirtualTimeReport`] with execution statistics.
    pub fn run_with_auto_advance(&mut self) -> VirtualTimeReport {
        let start_steps = self.steps;
        let mut auto_advances: u64 = 0;
        let mut total_wakeups: u64 = 0;
        let mut stuck_counter: u32 = 0;
        let start_time = self.virtual_time;

        let termination = loop {
            if self.replay_stopped() {
                break if self.is_quiescent() {
                    AutoAdvanceTermination::Quiescent
                } else {
                    AutoAdvanceTermination::StuckBailout
                };
            }
            // Check step limit
            if let Some(max) = self.config.max_steps {
                if self.steps >= max {
                    break AutoAdvanceTermination::StepLimitReached;
                }
            }

            // Run until the scheduler is empty
            let is_empty = self.scheduler.lock().is_empty();
            if !is_empty {
                // GH#55: reset the stall counter only when the step actually
                // dispatched something. `is_empty()` reads `scheduled`, which
                // can retain a task that is no longer queued in any worker
                // lane; resetting unconditionally made `StuckBailout`
                // unreachable, turning that strand into an unbounded spin
                // bounded only by `max_steps`.
                let before = self.dispatches;
                self.step();
                if self.dispatches != before {
                    stuck_counter = 0;
                } else {
                    stuck_counter = stuck_counter.saturating_add(1);
                    if stuck_counter > 1000 {
                        break AutoAdvanceTermination::StuckBailout;
                    }
                }
                continue;
            }

            // Scheduler is empty — check if we should auto-advance
            if self.has_pending_dispatch_commands() {
                self.step();
                continue;
            }
            if let Some(deadline) = self.next_auto_advance_deadline() {
                if deadline > self.virtual_time {
                    self.advance_time_to(deadline);
                    let wakeups = self
                        .state
                        .timer_driver_handle()
                        .map_or(0, |h| h.process_timers());
                    auto_advances = auto_advances.saturating_add(1);
                    total_wakeups = total_wakeups.saturating_add(wakeups as u64);
                    continue;
                }
                // A timer or reactor event is already due at the current time.
                total_wakeups = total_wakeups.saturating_add(self.pump_due_system_events() as u64);
                // A due deadline that wakes nothing never goes away (a paused
                // clock keeps timers from firing), and this branch takes no
                // step, so it counts as a stall like an empty step does.
                stuck_counter = stuck_counter.saturating_add(1);
                if stuck_counter > 1000 {
                    break AutoAdvanceTermination::StuckBailout;
                }
                continue;
            }

            // No runnable tasks and no pending virtual deadlines → quiescent
            if self.is_quiescent() {
                break AutoAdvanceTermination::Quiescent;
            }

            // Not quiescent but nothing to advance — try one more step
            // (there may be I/O or finalizers to process)
            stuck_counter = stuck_counter.saturating_add(1);
            if stuck_counter > 1000 {
                break AutoAdvanceTermination::StuckBailout;
            }
            self.step();
        };

        VirtualTimeReport {
            steps: self.steps - start_steps,
            auto_advances,
            total_wakeups,
            time_start: start_time,
            time_end: self.virtual_time,
            virtual_elapsed_nanos: self.virtual_time.as_nanos() - start_time.as_nanos(),
            termination,
        }
    }

    /// Pauses the virtual clock, freezing time at the current value.
    ///
    /// While paused, `advance_time()` and timer processing still work at the
    /// `LabRuntime` level (they update the runtime's own `virtual_time` field),
    /// but the underlying `VirtualClock` visible to tasks via `Cx::now()` is
    /// frozen. This is useful for testing timeout detection: tasks that call
    /// `Cx::now()` will see time standing still while the runtime can still
    /// orchestrate scheduling.
    pub fn pause_clock(&self) {
        self.virtual_clock.pause();
        crate::tracing_compat::info!(
            "virtual clock paused at time_ms={}",
            self.virtual_time.as_nanos() / 1_000_000
        );
    }

    /// Resumes a paused virtual clock.
    pub fn resume_clock(&self) {
        self.virtual_clock.resume();
        crate::tracing_compat::info!(
            "virtual clock resumed at time_ms={}",
            self.virtual_time.as_nanos() / 1_000_000
        );
    }

    /// Returns true if the virtual clock is currently paused.
    #[must_use]
    pub fn is_clock_paused(&self) -> bool {
        self.virtual_clock.is_paused()
    }

    /// Injects a clock skew by jumping time forward by `skew_nanos`.
    ///
    /// This simulates clock drift or NTP corrections. A warning is logged
    /// because large jumps may affect lease/timeout correctness.
    #[allow(clippy::no_effect_underscore_binding)]
    pub fn inject_clock_skew(&mut self, skew_nanos: u64) {
        // Capture old time *before* advance for accurate logging.
        let old_nanos = self.virtual_time.as_nanos();
        self.advance_time(skew_nanos);

        crate::tracing_compat::warn!(
            "virtual clock jump detected: old_time_ms={}, new_time_ms={}, jump_ms={} \
             -- may affect lease/timeout correctness",
            old_nanos / 1_000_000,
            self.virtual_time.as_nanos() / 1_000_000,
            skew_nanos / 1_000_000
        );
        #[cfg(not(feature = "tracing-integration"))]
        let _ = old_nanos;
    }

    /// Runs until quiescent or max steps reached.
    ///
    /// With [`LabConfig::auto_advance_time`] set, virtual time jumps to the
    /// next timer or lab-reactor deadline whenever nothing can run before it.
    ///
    /// Returns the number of steps executed.
    pub fn run_until_quiescent(&mut self) -> u64 {
        let start_steps = self.steps;

        while !self.is_quiescent() {
            if let Some(max) = self.config.max_steps {
                if self.steps >= max {
                    break;
                }
            }
            if self.replay_stopped() {
                break;
            }
            if self.config.auto_advance_time && self.advance_idle_time() {
                continue;
            }
            self.step();
        }

        self.steps - start_steps
    }

    /// Moves virtual time to the next timer or lab-reactor deadline when no
    /// task, command or obligation post can run before it, and returns whether
    /// time moved. The next step fires what is due.
    fn advance_idle_time(&mut self) -> bool {
        if !self.scheduler.lock().is_empty()
            || self.has_pending_dispatch_commands()
            || self.state.has_pending_obligation_posts()
        {
            return false;
        }
        match self.next_auto_advance_deadline() {
            Some(deadline) if deadline > self.virtual_time => {
                self.advance_time_to(deadline);
                true
            }
            _ => false,
        }
    }

    /// Runs until there are no runnable tasks in the scheduler.
    ///
    /// This is intentionally weaker than [`Self::run_until_quiescent`]:
    /// - It does **not** require all tasks to complete.
    /// - It does **not** require all obligations to be resolved.
    ///
    /// Use this when a test wants to "poll once" until the system is *idle*
    /// (e.g. a task is blocked on a channel receive) without forcing full
    /// completion and drain.
    pub fn run_until_idle(&mut self) -> u64 {
        let start_steps = self.steps;

        loop {
            if let Some(max) = self.config.max_steps {
                if self.steps >= max {
                    break;
                }
            }
            self.drain_handle_cancel_requests();
            self.drain_deferred_cancel_dispatches();
            let is_empty = self.scheduler.lock().is_empty();
            if is_empty && !self.has_pending_dispatch_commands() {
                break;
            }
            if self.replay_stopped() {
                break;
            }

            self.step();
        }

        self.steps - start_steps
    }

    /// Runs until quiescent (or `max_steps` is reached) and returns a structured report.
    #[must_use]
    pub fn run_until_quiescent_with_report(&mut self) -> LabRunReport {
        let steps_delta = self.run_until_quiescent();
        self.report_with_steps_delta(steps_delta)
    }

    /// Build a structured report for the current runtime state.
    ///
    /// This does not advance execution.
    #[must_use]
    pub fn report(&mut self) -> LabRunReport {
        self.report_with_steps_delta(0)
    }

    /// Runs until quiescent (or `max_steps` is reached) and returns a Spork harness report.
    #[must_use]
    pub fn run_until_quiescent_spork_report(
        &mut self,
        app: impl Into<String>,
        attachments: Vec<HarnessAttachmentRef>,
    ) -> SporkHarnessReport {
        let run = self.run_until_quiescent_with_report();
        self.build_spork_report(app.into(), run, attachments)
    }

    /// Build a Spork harness report for the current runtime state.
    ///
    /// This does not advance execution.
    #[must_use]
    pub fn spork_report(
        &mut self,
        app: impl Into<String>,
        attachments: Vec<HarnessAttachmentRef>,
    ) -> SporkHarnessReport {
        let run = self.report();
        self.build_spork_report(app.into(), run, attachments)
    }

    fn build_spork_report(
        &self,
        app: String,
        run: LabRunReport,
        mut attachments: Vec<HarnessAttachmentRef>,
    ) -> SporkHarnessReport {
        if let Some(auto_crashpack) = self.auto_crashpack_attachment(&run, &attachments) {
            attachments.push(auto_crashpack);
        }
        SporkHarnessReport::new(app, &self.config, run, attachments)
    }

    fn auto_crashpack_attachment(
        &self,
        run: &LabRunReport,
        attachments: &[HarnessAttachmentRef],
    ) -> Option<HarnessAttachmentRef> {
        if attachments
            .iter()
            .any(|attachment| attachment.kind == HarnessAttachmentKind::CrashPack)
        {
            return None;
        }
        let crashpack = self.build_crashpack_for_report(run)?;
        Some(HarnessAttachmentRef::crashpack(artifact_filename(
            &crashpack,
        )))
    }

    /// Build an in-memory crashpack for a failing report.
    ///
    /// Returns `None` for passing reports.
    #[must_use]
    pub fn build_crashpack_for_report(&self, run: &LabRunReport) -> Option<CrashPack> {
        self.build_crashpack_for_report_with_outcome(run, None, None, None, None)
    }

    /// Write a deterministic crashpack for a failing lab-test report.
    ///
    /// Returns `Ok(None)` when the report is passing, when auto-artifacts are
    /// disabled with `ASUPERSYNC_AUTO_ARTIFACTS=0`, or when no crashpack can be
    /// built for the report.
    pub fn write_auto_crashpack_for_report(
        &self,
        test_name: &str,
        run: &LabRunReport,
    ) -> Result<Option<LabAutoCrashpack>, LabAutoCrashpackError> {
        self.write_auto_crashpack(test_name, run, None, None, None)
    }

    /// Write a deterministic crashpack for a panic observed by a lab test body.
    ///
    /// This is used when a test panics before oracle assertions are evaluated.
    pub fn write_auto_crashpack_for_panic(
        &self,
        test_name: &str,
        run: &LabRunReport,
        panic_message: &str,
    ) -> Result<Option<LabAutoCrashpack>, LabAutoCrashpackError> {
        self.write_auto_crashpack(
            test_name,
            run,
            None,
            Some(FailureOutcome::Panicked {
                message: panic_message.to_string(),
            }),
            Some(format!("panic:{panic_message}")),
        )
    }

    fn write_auto_crashpack_for_task_failure(
        &self,
        test_name: &str,
        run: &LabRunReport,
        task: TaskId,
        region: RegionId,
        outcome: FailureOutcome,
        failure_detail: &str,
    ) -> Result<Option<LabAutoCrashpack>, LabAutoCrashpackError> {
        self.write_auto_crashpack(
            test_name,
            run,
            Some((task, region)),
            Some(outcome),
            Some(format!("task_failure:{failure_detail}")),
        )
    }

    fn write_auto_crashpack(
        &self,
        test_name: &str,
        run: &LabRunReport,
        failure_identity: Option<(TaskId, RegionId)>,
        forced_outcome: Option<FailureOutcome>,
        extra_violation: Option<String>,
    ) -> Result<Option<LabAutoCrashpack>, LabAutoCrashpackError> {
        if !auto_artifacts_enabled() {
            return Ok(None);
        }

        let Some(mut pack) = self.build_crashpack_for_report_with_outcome(
            run,
            Some(test_name),
            failure_identity,
            forced_outcome,
            extra_violation,
        ) else {
            return Ok(None);
        };

        let dir = auto_crashpack_dir(test_name, &pack);
        std::fs::create_dir_all(&dir).map_err(|source| LabAutoCrashpackError::CreateDir {
            path: dir.clone(),
            source,
        })?;

        let replay = pack.replay_command();
        pack.replay = Some(replay.clone());

        let writer = FileCrashPackWriter::new(dir);
        let artifact = writer.write(&pack)?;

        Ok(Some(LabAutoCrashpack {
            path: artifact.path().to_string(),
            replay,
        }))
    }

    fn build_crashpack_for_report_with_outcome(
        &self,
        run: &LabRunReport,
        test_name: Option<&str>,
        failure_identity: Option<(TaskId, RegionId)>,
        forced_outcome: Option<FailureOutcome>,
        extra_violation: Option<String>,
    ) -> Option<CrashPack> {
        let has_failure = !run.oracle_report.all_passed()
            || !run.invariant_violations.is_empty()
            || !run.quiescent
            || run.refinement_firewall_rule_id.is_some()
            || forced_outcome.is_some();
        if !has_failure {
            return None;
        }

        let config_summary = LabConfigSummary::from_config(&self.config);
        let crash_config = CrashPackConfig {
            seed: run.seed,
            config_hash: config_summary.config_hash(),
            worker_count: self.config.worker_count,
            max_steps: self.config.max_steps,
            test_name: test_name.map(str::to_owned),
            commit_hash: compiled_commit_hash(),
        };

        let failed_task = self.state.tasks_iter().find_map(|(_, task)| {
            let outcome = match &task.state {
                TaskState::Completed(crate::types::Outcome::Err(_)) => FailureOutcome::Err,
                TaskState::Completed(crate::types::Outcome::Cancelled(reason)) => {
                    FailureOutcome::Cancelled {
                        cancel_kind: reason.kind(),
                    }
                }
                TaskState::Completed(crate::types::Outcome::Panicked(payload)) => {
                    FailureOutcome::Panicked {
                        message: payload.message().to_owned(),
                    }
                }
                _ => return None,
            };
            Some((task.id, task.owner, outcome))
        });
        let (task, region, inferred_outcome) = failure_identity
            .map(|(task, region)| (task, region, None))
            .or_else(|| failed_task.map(|(task, region, outcome)| (task, region, Some(outcome))))
            .or_else(|| {
                self.state
                    .tasks_iter()
                    .find(|(_, task)| !task.state.is_terminal())
                    .map(|(_, task)| (task.id, task.owner, None))
            })
            .or_else(|| {
                self.state
                    .obligations_iter()
                    .find(|(_, obligation)| obligation.is_pending())
                    .map(|(_, obligation)| (obligation.holder, obligation.region, None))
            })
            .or_else(|| {
                self.state
                    .regions_iter()
                    .next()
                    .map(|(_, region)| (TaskId::testing_default(), region.id, None))
            })
            .or_else(|| {
                self.state
                    .root_region
                    .map(|root| (TaskId::testing_default(), root, None))
            })
            .unwrap_or((TaskId::testing_default(), RegionId::testing_default(), None));

        let mut oracle_violations = run.invariant_violations.clone();
        oracle_violations.extend(
            run.oracle_report
                .failures()
                .iter()
                .map(|entry| entry.invariant.clone()),
        );
        if let Some(rule_id) = &run.refinement_firewall_rule_id {
            oracle_violations.push(format!("refinement_firewall:{rule_id}"));
        }
        if let Some(prefix_len) = run.refinement_counterexample_prefix_len {
            oracle_violations.push(format!(
                "refinement_firewall:minimal_counterexample_prefix_len={prefix_len}"
            ));
        }
        if let Some(extra_violation) = extra_violation {
            oracle_violations.push(extra_violation);
        }
        oracle_violations.sort();
        oracle_violations.dedup();

        let trace_events = self.trace().snapshot();
        let mut builder = CrashPack::builder(crash_config.clone())
            .failure(FailureInfo {
                task,
                region,
                outcome: forced_outcome
                    .or(inferred_outcome)
                    .unwrap_or(FailureOutcome::Err),
                virtual_time: Time::from_nanos(run.now_nanos),
            })
            .created_at(run.now_nanos)
            .oracle_violations(oracle_violations)
            .replay(ReplayCommand::from_config(&crash_config));

        let divergent_prefix = self.auto_divergent_prefix();
        if !divergent_prefix.is_empty() {
            builder = builder.divergent_prefix(divergent_prefix);
        }

        builder = if trace_events.is_empty() {
            builder
                .fingerprint(run.trace_fingerprint)
                .event_count(run.trace_certificate.event_count)
        } else {
            builder.from_trace(&trace_events)
        };

        match builder.build() {
            Ok(pack) => Some(pack),
            Err(err) => {
                let _ = &err;
                crate::tracing_compat::error!("failed to build crash pack for lab report: {err}");
                None
            }
        }
    }

    fn auto_divergent_prefix(&self) -> Vec<ReplayEvent> {
        let Some(replay_trace) = self.replay_recorder.snapshot() else {
            return Vec::new();
        };
        if replay_trace.events.is_empty() {
            return Vec::new();
        }

        let failure_index = replay_trace
            .events
            .iter()
            .position(
                |event| matches!(event, ReplayEvent::TaskCompleted { outcome, .. } if *outcome > 0),
            )
            .unwrap_or(replay_trace.events.len().saturating_sub(1));

        crate::trace::minimal_divergent_prefix(&replay_trace, failure_index).events
    }

    fn report_with_steps_delta(&mut self, steps_delta: u64) -> LabRunReport {
        let seed = self.config.seed;
        let quiescent = self.is_quiescent();
        let now = self.now();

        let trace_events = self.trace().snapshot();
        let trace_len = trace_events.len();

        let trace_fingerprint = if trace_events.is_empty() {
            // Mirror explorer behavior: ensure the report fingerprint varies by seed
            // even if trace capture is effectively disabled / empty.
            seed_fingerprint(seed)
        } else {
            trace_fingerprint(&trace_events)
        };

        let schedule_hash = self.certificate().hash();
        let mut certificate = TraceCertificate::new();
        for e in &trace_events {
            certificate.record_event(e);
        }
        certificate.set_schedule_hash(schedule_hash);

        self.oracles.hydrate_temporal_from_state(&self.state, now);
        // Feed the anytime-valid e-process monitor once per run that advanced
        // the lab. `report()` does not advance execution, so re-reporting the
        // same state must not count as fresh evidence.
        let oracle_report = if steps_delta > 0 {
            self.oracles.report_and_observe(now)
        } else {
            self.oracles.report(now)
        };
        let oracle_invariant_failures = oracle_report
            .failures()
            .into_iter()
            .map(|entry| entry.invariant.clone())
            .collect::<Vec<_>>();
        let temporal_invariant_failures = oracle_invariant_failures
            .iter()
            .filter(|invariant| TEMPORAL_ORACLE_INVARIANTS.contains(&invariant.as_str()))
            .cloned()
            .collect::<Vec<_>>();
        let temporal_counterexample_prefix_len = if temporal_invariant_failures.is_empty() {
            None
        } else {
            let prefix_len = self.auto_divergent_prefix().len();
            (prefix_len > 0).then_some(prefix_len)
        };
        // br-asupersync-9ri7x0: capture the truncation watermark BEFORE
        // deciding whether to run the firewall. Previously, when
        // total_pushed > buffer_len the refinement-firewall oracle was
        // silently disabled and the scenario could still report
        // 'passed' — adversarial event-heavy scenarios could drown out
        // detection by deliberately exceeding the buffer. The new
        // contract: a truncated trace MUST surface as an explicit
        // violation in invariant_violations so the scenario fails
        // loudly, naming the seed and the truncation watermark.
        let trace_total_pushed = self.trace().total_pushed();
        let trace_buffered_len = trace_events.len() as u64;
        let refinement_firewall_skipped_due_to_trace_truncation =
            trace_total_pushed > trace_buffered_len;
        let refinement_violation = if refinement_firewall_skipped_due_to_trace_truncation {
            None
        } else {
            check_refinement_firewall(&trace_events).first_violation
        };
        let refinement_violation = refinement_violation.as_ref();
        let refinement_firewall_rule_id = refinement_violation.map(|v| v.rule_id.to_owned());
        let refinement_firewall_event_index = refinement_violation.map(|v| v.event_index);
        let refinement_firewall_event_seq = refinement_violation.map(|v| v.event_seq);
        let refinement_counterexample_prefix_len =
            refinement_firewall_event_index.map(|idx| idx + 1);

        let mut invariant_violations = self
            .check_invariants()
            .into_iter()
            .map(|v| v.to_string())
            .collect::<Vec<_>>();
        for invariant in &oracle_invariant_failures {
            invariant_violations.push(format!("oracle:{invariant}"));
        }
        for invariant in &temporal_invariant_failures {
            invariant_violations.push(format!("temporal:{invariant}"));
        }
        if let Some(boundary) = self.production_replay_boundary()
            && boundary.mode == ProductionReplayMode::Strict
            && boundary.termination != Some(StrictProductionReplayTermination::Matched)
        {
            // State quiescence can precede replay completion: a stale wake may
            // remain queued after every real task has finished. A still-pending
            // boundary must not let that partial source pass the Lab report.
            let termination = boundary.termination.map_or_else(
                || "Pending".to_owned(),
                |termination| format!("{termination:?}"),
            );
            invariant_violations.push(format!(
                "production_replay:incomplete:{termination}:matched={},total={},source_error={:?}",
                boundary.replay.steps_matched, boundary.replay.steps_total, boundary.source_error,
            ));
        }
        if let Some(prefix_len) = temporal_counterexample_prefix_len {
            invariant_violations.push(format!(
                "temporal:minimal_divergent_prefix_len={prefix_len}"
            ));
        }
        if let Some(rule_id) = &refinement_firewall_rule_id {
            invariant_violations.push(format!("refinement_firewall:{rule_id}"));
        }
        if let Some(prefix_len) = refinement_counterexample_prefix_len {
            invariant_violations.push(format!(
                "refinement_firewall:minimal_counterexample_prefix_len={prefix_len}"
            ));
        }
        // br-asupersync-9ri7x0: when the in-memory event buffer was
        // overrun, the refinement-firewall oracle could not run on the
        // suffix that was dropped. Report it as a hard scenario
        // failure with the seed + watermark so an operator can
        // increase trace_capacity (or split the scenario) instead of
        // silently shipping a green result.
        if refinement_firewall_skipped_due_to_trace_truncation {
            invariant_violations.push(format!(
                "refinement_firewall:scenario_failed_due_to_trace_truncation:\
                 seed={seed},total_pushed={trace_total_pushed},buffered={trace_buffered_len}"
            ));
        }
        invariant_violations.sort();
        invariant_violations.dedup();

        LabRunReport {
            seed,
            steps_delta,
            steps_total: self.steps(),
            quiescent,
            now_nanos: now.as_nanos(),
            trace_len,
            trace_fingerprint,
            trace_certificate: LabTraceCertificateSummary {
                event_hash: certificate.event_hash(),
                event_count: certificate.event_count(),
                schedule_hash: certificate.schedule_hash(),
            },
            oracle_report,
            invariant_violations,
            temporal_invariant_failures,
            temporal_counterexample_prefix_len,
            refinement_firewall_rule_id,
            refinement_firewall_event_index,
            refinement_firewall_event_seq,
            refinement_counterexample_prefix_len,
            refinement_firewall_skipped_due_to_trace_truncation,
        }
    }

    /// Enable deadline monitoring with the default warning handler.
    pub fn enable_deadline_monitoring(&mut self, config: MonitorConfig) {
        self.enable_deadline_monitoring_with_handler(config, default_warning_handler);
    }

    /// Enable deadline monitoring with a custom warning handler.
    pub fn enable_deadline_monitoring_with_handler<F>(&mut self, config: MonitorConfig, f: F)
    where
        F: Fn(DeadlineWarning) + Send + Sync + 'static,
    {
        let mut monitor = DeadlineMonitor::new(config);
        monitor.on_warning(f);
        self.deadline_monitor = Some(monitor);
    }

    /// Returns a mutable reference to the deadline monitor, if enabled.
    pub fn deadline_monitor_mut(&mut self) -> Option<&mut DeadlineMonitor> {
        self.deadline_monitor.as_mut()
    }

    /// Returns the lab's deterministic spawn mailbox.
    ///
    /// Requests enqueued here (with pending-spawn credits, per the A1.2
    /// contract) are admitted in FIFO order at the start of the next step,
    /// so `run_until_quiescent` observes them as live work end to end.
    #[must_use]
    pub fn spawn_mailbox(&self) -> Arc<crate::runtime::spawn_mailbox::SpawnMailbox> {
        Arc::clone(&self.spawn_mailbox)
    }

    /// Admits every pending spawn request in FIFO order
    /// (br-asupersync-4h8lye / A2.1). Lab is single-threaded, so denial
    /// slots run inline; admitted tasks join the lab scheduler at their
    /// budget priority. Deterministic: admission order is exactly enqueue
    /// order, and the admitted arena ids depend only on prior state.
    fn drain_spawn_admissions(&mut self) {
        // Obligation posts first (br-asupersync-bi2462.13): a reservation a
        // task posted during its last poll is applied before any new task is
        // admitted or polled this step.
        const OBLIGATION_POST_BATCH: usize = 64;
        while self.state.has_pending_obligation_posts() {
            if self.state.drain_obligation_posts(OBLIGATION_POST_BATCH) == 0 {
                break;
            }
        }
        if self.spawn_mailbox.spawn_requests_are_empty() {
            return;
        }
        while let Some(request) = self.spawn_mailbox.dequeue() {
            match self.state.admit_spawn_request(request.into_parts()) {
                crate::runtime::state::SpawnAdmission::Admitted {
                    task_id,
                    priority,
                    cancel_publication,
                    spawn_effects,
                } => {
                    let (cancel_wakes, spawn_effects) = cancel_publication
                        .publish_with_spawn_effects(spawn_effects, |cancel_priority| {
                            let mut scheduler = self.scheduler.lock();
                            if let Some(cancel_priority) = cancel_priority {
                                scheduler.schedule_cancel(task_id, cancel_priority);
                            } else {
                                scheduler.schedule(task_id, priority);
                            }
                        });
                    // The closure-local scheduler guard is gone and the task's
                    // runnable/cancel lane is visible before observer reentry.
                    if let Some(spawn_effects) = spawn_effects {
                        spawn_effects.dispatch();
                    }
                    cancel_wakes.dispatch();
                }
                crate::runtime::state::SpawnAdmission::Denied { parts, error } => {
                    // Resolving the denial releases the region's pending-spawn
                    // credit, which close gates on: re-advance the region, as
                    // the native scheduler does, or a region that began
                    // closing with this spawn in flight never closes.
                    let region = parts.region;
                    match error {
                        crate::runtime::state::SpawnError::RegionClosed(_)
                        | crate::runtime::state::SpawnError::RegionNotFound(_) => {
                            parts.resolve_cancelled(crate::types::CancelReason::new(
                                crate::types::CancelKind::ParentCancelled,
                            ));
                        }
                        other => parts.resolve_failed(other),
                    }
                    self.state.advance_region_state(region);
                }
            }
        }
    }

    /// Applies a bounded batch of callback-free TaskHandle cancellation
    /// commands. Every required cancel lane is physically published before
    /// any retained Waker is invoked.
    fn drain_handle_cancel_requests(&mut self) {
        const HANDLE_CANCEL_BATCH: usize = 16;

        if self.spawn_mailbox.handle_cancels_are_empty() {
            return;
        }
        let mut requests = Vec::with_capacity(HANDLE_CANCEL_BATCH);
        if self
            .spawn_mailbox
            .dequeue_handle_cancels_into(HANDLE_CANCEL_BATCH, &mut requests)
            == 0
        {
            return;
        }

        let requests = crate::runtime::spawn_mailbox::coalesce_handle_cancel_requests(requests);
        // Annotate explicitly: the task/priority prefix is only pinned by
        // `schedule_cancel(task_id, priority)` far below, which the current
        // nightly no longer back-infers through the `&mut tasks`/`&mut delegated`
        // shared `target` binding (E0282).
        //
        // The break is configuration-dependent, not universal: it first showed
        // up building asupersync as a *path dependency of FrankenSQLite*, whose
        // narrower downstream feature set gives inference less to work with than
        // this crate's own `cargo check`. So a green build here does NOT prove
        // the annotation is redundant — drop it and the downstream consumer is
        // what breaks, not us.
        let mut tasks: Vec<(
            TaskId,
            u8,
            Option<Arc<crate::runtime::spawn_mailbox::AdmittedTaskSlot>>,
        )> = Vec::with_capacity(requests.len());
        let mut delegated: Vec<(
            TaskId,
            u8,
            Option<Arc<crate::runtime::spawn_mailbox::AdmittedTaskSlot>>,
        )> = Vec::new();
        let mut spawn_effects_to_dispatch = Vec::with_capacity(requests.len());
        let mut wakes = crate::types::task_context::CancelWakeEffects::empty();
        for request in requests {
            let task_id = request.task_id;
            let reason = request.reason;
            let admitted_slot = request.admitted_slot;
            let task_exists = self.state.task(task_id).is_some();
            let effects = self.state.cancel_task_for_handle(task_id, &reason);
            let (route, task_wakes) = effects.into_parts();
            wakes.merge(task_wakes);

            let Some(route) = route else {
                if task_exists
                    && let Some(admitted_slot) = admitted_slot
                    && let Some(effects) = admitted_slot.take_spawn_effects_if_lane_published()
                {
                    spawn_effects_to_dispatch.push(effects);
                }
                continue;
            };
            let target = if route.delegated_initial {
                &mut delegated
            } else {
                &mut tasks
            };
            if let Some((_, queued_priority, queued_slot)) = target
                .iter_mut()
                .find(|(queued_task_id, _, _)| *queued_task_id == task_id)
            {
                *queued_priority = (*queued_priority).max(route.priority);
                if queued_slot.is_none() {
                    *queued_slot = admitted_slot;
                }
            } else {
                target.push((task_id, route.priority, admitted_slot));
            }
        }

        {
            let mut scheduler = self.scheduler.lock();
            for (task_id, priority, admitted_slot) in tasks {
                scheduler.schedule_cancel(task_id, priority);
                if let Some(admitted_slot) = admitted_slot
                    && let Some(effects) = admitted_slot.publish_spawn_lane_and_take_effects()
                {
                    spawn_effects_to_dispatch.push(effects);
                }
            }
        }

        for (task_id, requested_priority, admitted_slot) in delegated {
            let scheduler = &self.scheduler;
            let (published_priority, task_wakes) = self
                .state
                .publish_handle_cancel_lane(task_id, |priority, _, _| {
                    scheduler.lock().schedule_cancel(task_id, priority);
                    Some(priority)
                })
                .into_parts();
            if let Some(published_priority) = published_priority {
                let spawn_effects = admitted_slot
                    .as_ref()
                    .and_then(|slot| slot.publish_spawn_lane_and_take_effects());
                debug_assert!(published_priority >= requested_priority);
                if let Some(effects) = spawn_effects {
                    spawn_effects_to_dispatch.push(effects);
                }
            }
            wakes.merge(task_wakes);
        }
        for effects in spawn_effects_to_dispatch {
            effects.dispatch();
        }
        wakes.dispatch();
    }

    /// Applies region lifecycle commands (bd-asupersync-ambient-child-region-0fm8l)
    /// synchronously at the same deterministic point as handle cancels: the
    /// authoritative record transitions run against the lab state, and mint
    /// outcomes publish into caller-shared slots afterwards.
    fn drain_region_commands(&mut self) {
        const REGION_COMMAND_BATCH: usize = 8;

        if self.spawn_mailbox.region_commands_are_empty() {
            return;
        }
        let mut commands = Vec::with_capacity(REGION_COMMAND_BATCH);
        if self
            .spawn_mailbox
            .dequeue_region_commands_into(REGION_COMMAND_BATCH, &mut commands)
            == 0
        {
            return;
        }

        let mut publications: Vec<(
            std::sync::Arc<crate::runtime::spawn_mailbox::AdmittedRegionSlot>,
            Result<
                crate::runtime::spawn_mailbox::AdmittedRegion,
                crate::runtime::region_table::RegionCreateError,
            >,
        )> = Vec::with_capacity(commands.len());
        let mut finalizer_publications = Vec::new();
        let mut live_task_publications = Vec::new();
        let mut watch_wakers = Vec::new();
        let mut watch_retries = Vec::new();
        for command in commands {
            match command {
                crate::runtime::spawn_mailbox::RegionCommand::Create(request) => {
                    let (slot, outcome) = self.state.open_child_region_command(request);
                    publications.push((slot, outcome));
                }
                crate::runtime::spawn_mailbox::RegionCommand::Watch(command) => {
                    match self.state.apply_watch_command(command, None) {
                        crate::monitor::WatchApply::Done(waker) => watch_wakers.extend(waker),
                        crate::monitor::WatchApply::Retry(command) => watch_retries.push(command),
                    }
                }
                crate::runtime::spawn_mailbox::RegionCommand::RegisterFinalizer(request) => {
                    finalizer_publications.push(request.apply(&mut self.state));
                }
                crate::runtime::spawn_mailbox::RegionCommand::LiveTasks(query) => {
                    live_task_publications.push(query.apply(&self.state));
                }
                crate::runtime::spawn_mailbox::RegionCommand::Cancel { region_id, reason } => {
                    self.state.close_region_command(region_id, &reason);
                }
                crate::runtime::spawn_mailbox::RegionCommand::CancelWithBudget {
                    region_id,
                    reason,
                    shutdown_budget,
                } => {
                    self.state.close_region_command_with_budget(
                        region_id,
                        &reason,
                        shutdown_budget,
                    );
                }
                crate::runtime::spawn_mailbox::RegionCommand::Close { region_id } => {
                    // Never earlier than the reasons it races with (pz66t0).
                    let completion = owned_region_close_reason(self.now());
                    self.state.close_region_command(region_id, &completion);
                }
            }
        }
        for (slot, outcome) in publications {
            slot.publish(outcome);
        }
        for publication in finalizer_publications {
            publication.publish();
        }
        for publication in live_task_publications {
            publication.publish();
        }
        for waker in watch_wakers {
            waker.wake();
        }
        for command in watch_retries {
            self.spawn_mailbox.enqueue_region_command(
                crate::runtime::spawn_mailbox::RegionCommand::Watch(command),
            );
        }
    }

    fn drain_deferred_cancel_dispatches(&mut self) {
        let batches = self.state.take_deferred_cancel_dispatches();
        if batches.is_empty() {
            return;
        }
        let mut wakes = Vec::with_capacity(batches.len());
        {
            let mut scheduler = self.scheduler.lock();
            for batch in batches {
                let (tasks, batch_wakes) = batch.into_parts();
                for (task_id, priority) in tasks {
                    scheduler.schedule_cancel(task_id, priority);
                }
                wakes.push(batch_wakes);
            }
        }
        for batch_wakes in wakes {
            batch_wakes.dispatch();
        }
    }

    /// Drives this run's scheduling choices from a recorded production
    /// schedule (br-asupersync-bi2462.7).
    ///
    /// While the schedule is being followed, each lab step dispatches the
    /// recorded task if it is runnable; a task that is not runnable yet is
    /// waited for through bounded virtual-time advances
    /// ([`ProductionReplayOptions::max_wait_steps`]); a task that no lab task
    /// ever bound to, or one still not runnable after the bound, is a
    /// [`ReplayDivergence`] handled per [`ProductionReplayOptions::on_divergence`].
    /// The default is fail closed: no task is polled after the source ends.
    /// [`Self::production_replay_boundary`] distinguishes a complete match
    /// from source exhaustion with outstanding work or unconsumed choices.
    /// Use [`Self::replay_production_schedule_prefix`] to explicitly authorize
    /// an exploratory continuation. `OnReplayDivergence::Continue` still
    /// explicitly permits continuation after a recorded task-order divergence.
    /// Recorded spawn ordinals bind to lab tasks by the order in which tasks
    /// first enter the lab scheduler, so the replay must be configured before
    /// the first step. [`ForcedSchedule`] replay is a separate, hash-bound
    /// mechanism and is untouched.
    ///
    /// # Errors
    ///
    /// [`ProductionReplayError::AlreadyStarted`] after any step,
    /// [`ProductionReplayError::EmptySchedule`] for a schedule without steps.
    /// Additional source-admission failures install a stopped replay and are
    /// exposed by [`Self::production_replay_boundary`], preserving this method's
    /// existing error type. Prefer [`Self::run_production_schedule_strict`] for
    /// bounded admission with directly returned typed errors.
    pub fn replay_production_schedule(
        &mut self,
        schedule: &ProductionSchedule,
        options: ProductionReplayOptions,
    ) -> Result<(), ProductionReplayError> {
        if self.steps != 0 {
            return Err(ProductionReplayError::AlreadyStarted { steps: self.steps });
        }
        if schedule.summary().steps == 0 {
            return Err(ProductionReplayError::EmptySchedule);
        }
        let limits = production_strict::StrictProductionReplayLimits::new(
            usize::MAX,
            usize::MAX,
            usize::MAX,
            u64::MAX,
            options.max_wait_steps,
        );
        let admission = if self.has_chaos() {
            Err(StrictProductionReplayError::ChaosActive)
        } else if schedule.cancellation_events().is_some() {
            Err(StrictProductionReplayError::CancellationRequiresStrictDriver)
        } else {
            production_strict::prepare_source(schedule, limits)
        };
        let state = match admission {
            Ok(mut state) => {
                state.options = options;
                state
            }
            Err(error) => {
                let mut state = ProductionReplayState::new(schedule, options);
                state.mode = ProductionReplayMode::Strict;
                state.source_error = Some(error);
                state.report.stopped = true;
                state
            }
        };
        self.production_replay = Some(state);
        Ok(())
    }

    /// Replays a recorded prefix and explicitly resumes ordinary scheduling.
    ///
    /// This retains the historical continuation policy. Its boundary report
    /// always says [`ProductionReplayMode::Prefix`], so a matched prefix cannot
    /// be mistaken for a complete strict replay. Source completeness and
    /// quiescence are not admission conditions for this exploratory mode.
    /// Cancellation annexes are not injected or validated by this task-order
    /// prefix; use [`Self::run_production_schedule_strict`] to replay them.
    ///
    /// # Errors
    /// Returns the same configuration errors as [`Self::replay_production_schedule`].
    pub fn replay_production_schedule_prefix(
        &mut self,
        schedule: &ProductionSchedule,
        options: ProductionReplayOptions,
    ) -> Result<(), ProductionReplayError> {
        if self.steps != 0 {
            return Err(ProductionReplayError::AlreadyStarted { steps: self.steps });
        }
        let state = ProductionReplayState::new(schedule, options);
        if state.steps.is_empty() {
            return Err(ProductionReplayError::EmptySchedule);
        }
        self.production_replay = Some(state);
        Ok(())
    }

    /// The production-schedule replay report, or `None` when no schedule was
    /// configured with [`Self::replay_production_schedule`].
    #[must_use]
    pub fn replay_report(&self) -> Option<ReplayReport> {
        let replay = self.production_replay.as_ref()?;
        let mut report = replay.report.clone();
        report.spawns_bound = self
            .scheduler
            .lock()
            .first_entry_count()
            .min(replay.spawn_order.len());
        if replay.mode == ProductionReplayMode::Strict
            && replay.following
            && replay.next >= replay.steps.len()
            && (!self.is_quiescent() || !self.scheduler.lock().is_empty())
            && !self.has_pending_dispatch_commands()
            && !self.state.has_pending_obligation_posts()
        {
            report.stopped = true;
        }
        Some(report)
    }

    /// Whether a production-schedule replay diverged under
    /// [`OnReplayDivergence::Stop`]; the run loops stop stepping then.
    fn replay_stopped(&self) -> bool {
        self.production_replay.as_ref().is_some_and(|replay| {
            replay.report.stopped
                || (replay.mode == ProductionReplayMode::Strict
                    && replay.following
                    && replay.next >= replay.steps.len()
                    && !self.has_pending_dispatch_commands()
                    && !self.state.has_pending_obligation_posts())
        })
    }

    /// One bounded wait for a recorded task that is not runnable yet.
    ///
    /// Advances virtual time to the next timer/reactor deadline and pumps
    /// the system events that become due. Without any deadline nothing will
    /// ever make the task runnable except polling another task, so the wait
    /// is exhausted at once and the next pick reports the divergence.
    fn replay_wait_for_time(&mut self) {
        if let Some(deadline) = self.next_auto_advance_deadline() {
            if deadline > self.now() {
                self.advance_time_to(deadline);
            }
            let _ = self.pump_due_system_events();
        } else if let Some(replay) = self.production_replay.as_mut() {
            replay.exhaust_wait();
        }
        self.check_deadline_monitor();
    }

    /// The runtime trace this lab run would hand to
    /// [`ProductionSchedule::from_runtime_trace`].
    ///
    /// The `Spawn` events from the trace buffer (creation order) followed by
    /// one `Poll` event per recorded scheduling decision, in dispatch order.
    /// `None` when replay recording is disabled. A polled task without a
    /// `Spawn` event in the (bounded) trace buffer is attributed to the first
    /// spawned region so it projects as an orphan rather than vanishing.
    #[must_use]
    pub fn recorded_production_trace_events(&self) -> Option<Vec<TraceEvent>> {
        let recording = self.replay_recorder.snapshot()?;
        let mut events: Vec<TraceEvent> = self
            .trace()
            .snapshot()
            .into_iter()
            .filter(|event| event.kind == TraceEventKind::Spawn)
            .collect();
        events.sort_by_key(|event| event.seq);
        let mut region_of: Vec<(TaskId, RegionId)> = Vec::with_capacity(events.len());
        let mut fallback_region = None;
        for event in &events {
            if let TraceData::Task { task, region } = &event.data {
                region_of.push((*task, *region));
                fallback_region.get_or_insert(*region);
            }
        }
        let mut seq = events.last().map_or(0, |event| event.seq).saturating_add(1);
        for event in recording.iter() {
            if let ReplayEvent::TaskScheduled { task, at_tick } = event {
                let task_id = compact_task_id(*task);
                let region = region_of
                    .iter()
                    .find(|(candidate, _)| *candidate == task_id)
                    .map(|(_, region)| *region)
                    .or(fallback_region)?;
                events.push(TraceEvent::poll(
                    seq,
                    Time::from_nanos(*at_tick),
                    task_id,
                    region,
                ));
                seq = seq.saturating_add(1);
            }
        }
        Some(events)
    }

    /// The [`ProductionSchedule`] projected from this run's recording.
    ///
    /// See [`Self::recorded_production_trace_events`]; this is what a second
    /// lab runtime replays through [`Self::replay_production_schedule`].
    ///
    /// # Errors
    ///
    /// [`ProductionReplayError::RecordingDisabled`] without replay recording,
    /// [`ProductionReplayError::Projection`] when the events do not project.
    pub fn recorded_production_schedule(
        &self,
    ) -> Result<ProductionSchedule, ProductionReplayError> {
        let events = self
            .recorded_production_trace_events()
            .ok_or(ProductionReplayError::RecordingDisabled)?;
        ProductionSchedule::from_runtime_trace_with(
            &events,
            ProjectionOptions {
                allow_orphans: true,
            },
        )
        .map_err(ProductionReplayError::Projection)
    }

    /// Executes a single step.
    #[allow(clippy::too_many_lines)]
    fn step(&mut self) {
        self.step_inner(LabDispatchMode::Normal)
            .expect("normal lab scheduling cannot produce a forced-schedule error");
    }

    fn step_with_forced_dispatch(
        &mut self,
        expected: Option<(usize, &ForcedDispatch)>,
    ) -> Result<bool, ForcedScheduleError> {
        self.step_inner(LabDispatchMode::Forced { expected })
    }

    fn step_with_candidate_dispatch(
        &mut self,
        expected: Option<(usize, &ForcedDispatch)>,
    ) -> Result<bool, ForcedScheduleError> {
        self.step_inner(LabDispatchMode::Candidate { expected })
    }

    #[allow(clippy::too_many_lines)]
    fn step_inner(
        &mut self,
        dispatch_mode: LabDispatchMode<'_>,
    ) -> Result<bool, ForcedScheduleError> {
        self.steps += 1;
        self.drain_deferred_cancel_dispatches();
        self.drain_spawn_admissions();
        self.drain_handle_cancel_requests();
        self.drain_region_commands();
        // Consume any command it enqueued before selecting runnable work.
        self.drain_handle_cancel_requests();
        self.drain_deferred_cancel_dispatches();
        if !self.spawn_mailbox.handle_cancels_are_empty()
            || self.state.has_deferred_cancel_dispatches()
        {
            // Bound each deterministic step: reentrant cancellation gets the
            // next step, and ordinary ready work cannot overtake it.
            return Ok(false);
        }
        let rng_value = self.rng.next_u64();
        if self.steps < 50 {
            crate::tracing_compat::trace!(
                "lab runtime rng sample: rng_value={}, worker_hint={}",
                rng_value,
                (rng_value >> 32) as usize % self.config.worker_count.max(1)
            );
        }
        self.replay_recorder.record_rng_value(rng_value);
        self.check_futurelocks();
        if let Some(timer) = self.state.timer_driver_handle() {
            let _ = timer.process_timers();
        }
        self.poll_io();
        self.schedule_async_finalizers();

        // 1. Choose a worker and pop a task (deterministic multi-worker model)
        let worker_count = self.config.worker_count.max(1);
        // Use higher bits of rng_value since xorshift64 has poor low-bit entropy
        let worker_hint = ((rng_value >> 32) as usize) % worker_count;
        let now = self.now();
        let (task_id, dispatch_lane, dispatch_worker) = {
            let mut sched = self.scheduler.lock();
            match dispatch_mode {
                LabDispatchMode::Normal => {
                    // Production-schedule oracle (br-asupersync-bi2462.7):
                    // while a recorded schedule is being followed it names
                    // the exact task to dispatch; the RNG sample above is
                    // still drawn so the lab's own state evolves as usual.
                    let replay_pick = self
                        .production_replay
                        .as_mut()
                        .map(|replay| replay.pick(&mut sched, now, self.steps));
                    match replay_pick {
                        Some(ReplayPick::Take(tid, lane, worker)) => (tid, lane, worker),
                        Some(ReplayPick::WaitForTime) => {
                            drop(sched);
                            self.replay_wait_for_time();
                            return Ok(false);
                        }
                        Some(ReplayPick::Stopped) => {
                            drop(sched);
                            return Ok(false);
                        }
                        None | Some(ReplayPick::Normal) => {
                            if let Some((tid, lane)) =
                                sched.pop_for_worker(worker_hint, rng_value, now)
                            {
                                (tid, lane, worker_hint)
                            } else if let Some(tid) =
                                sched.steal_for_worker(worker_hint, rng_value.rotate_left(17))
                            {
                                (tid, DispatchLane::Stolen, worker_hint)
                            } else {
                                drop(sched);
                                self.check_deadline_monitor();
                                return Ok(false);
                            }
                        }
                    }
                }
                LabDispatchMode::Forced {
                    expected: Some((index, dispatch)),
                } => {
                    if self.steps < dispatch.at_step {
                        if sched.has_runnable_work(now) {
                            return Err(ForcedScheduleError::EarlyRunnable {
                                expected: dispatch.at_step,
                                actual: self.steps,
                            });
                        }
                        drop(sched);
                        self.check_deadline_monitor();
                        return Ok(false);
                    }
                    if self.steps > dispatch.at_step {
                        return Err(ForcedScheduleError::StepMismatch {
                            index,
                            expected: dispatch.at_step,
                            actual: self.steps,
                        });
                    }
                    if now.as_nanos() != dispatch.at_nanos {
                        return Err(ForcedScheduleError::TimeMismatch {
                            index,
                            expected: dispatch.at_nanos,
                            actual: now.as_nanos(),
                        });
                    }
                    let task_id = compact_task_id(dispatch.task);
                    sched.take_forced(
                        task_id,
                        dispatch.worker as usize,
                        dispatch.lane,
                        now,
                        index,
                    )?;
                    (task_id, dispatch.lane, dispatch.worker as usize)
                }
                LabDispatchMode::Forced { expected: None } => {
                    if !sched.is_empty() {
                        return Err(ForcedScheduleError::ScheduleExhausted {
                            consumed: self.certificate.decisions() as usize,
                        });
                    }
                    drop(sched);
                    self.check_deadline_monitor();
                    return Ok(false);
                }
                LabDispatchMode::Candidate {
                    expected: Some((index, dispatch)),
                } => {
                    let task_id = compact_task_id(dispatch.task);
                    sched.take_forced(
                        task_id,
                        dispatch.worker as usize,
                        dispatch.lane,
                        now,
                        index,
                    )?;
                    (task_id, dispatch.lane, dispatch.worker as usize)
                }
                LabDispatchMode::Candidate { expected: None } => {
                    drop(sched);
                    self.check_deadline_monitor();
                    return Ok(false);
                }
            }
        };

        self.dispatches = self.dispatches.saturating_add(1);

        // Record task scheduling in certificate and replay recorder
        self.certificate.record(task_id, dispatch_lane, self.steps);
        self.replay_recorder
            .record_task_scheduled(task_id, self.steps);
        if let Some(recorder) = &mut self.forced_schedule_recorder {
            if recorder.dispatches.len() < recorder.max_dispatches {
                recorder.dispatches.push(ForcedDispatch {
                    task: task_id.into(),
                    worker: u32::try_from(dispatch_worker)
                        .expect("lab worker index is bounded by LabConfig::worker_count"),
                    lane: dispatch_lane,
                    at_step: self.steps,
                    at_nanos: now.as_nanos(),
                });
            } else {
                recorder.truncated = true;
            }
        }

        // 2. Pre-poll chaos injection
        if self.inject_pre_poll_chaos(task_id) {
            // Chaos caused the task to be skipped (e.g., cancelled, budget exhausted)
            return Ok(true);
        }

        // 3. Prepare context, enforce budget, and take any cached wakers.
        let (priority, cached_waker, cached_cancel_waker, current_cx, cx_inner) = self
            .state
            .update_task(task_id, |record| {
                let priority = record.cx_inner.as_ref().map_or(0, |inner| {
                    let mut guard = inner.write();

                    // Enforce poll quota
                    if guard.budget.consume_poll().is_none() {
                        guard.set_cancel_requested(true);
                        if let Some(existing) = &mut guard.cancel_reason {
                            existing.strengthen(&crate::types::CancelReason::poll_quota());
                        } else {
                            guard.cancel_reason = Some(crate::types::CancelReason::poll_quota());
                        }
                    }

                    guard.budget.priority
                });

                (
                    priority,
                    record.cached_waker.take(),
                    record.cached_cancel_waker.take(),
                    record.cx.clone(),
                    record.cx_inner.clone(),
                )
            })
            .unwrap_or((0, None, None, None, None));

        let waker = match cached_waker {
            Some((waker, cached_priority)) if cached_priority == priority => waker,
            _ => Waker::from(Arc::new(TaskWaker {
                task_id,
                priority,
                scheduler: self.scheduler.clone(),
            })),
        };
        let mut cx = Context::from_waker(&waker);

        // Set cancel_waker so abort_with_reason can reschedule cancelled tasks.
        let cancel_waker_for_cache = cx_inner.as_ref().map(|_| match cached_cancel_waker {
            Some((waker, cached_priority)) if cached_priority == priority => (waker, priority),
            _ => (
                Waker::from(Arc::new(CancelTaskWaker {
                    task_id,
                    priority,
                    scheduler: self.scheduler.clone(),
                })),
                priority,
            ),
        });

        if let (Some(inner), Some((cancel_waker, _))) =
            (cx_inner.as_ref(), cancel_waker_for_cache.as_ref())
        {
            // Prepare and retire Wakers without a live CxInner guard: custom
            // callbacks may reenter the same task context.
            let mut incoming_waker = Some(Arc::new(crate::types::task_context::CancelWaker::new(
                cancel_waker.clone(),
            )));
            let retired_waker = {
                let mut guard = inner.write();
                if guard.cancel_waker_registry_closed {
                    None
                } else if !guard
                    .cancel_waker
                    .as_ref()
                    .is_some_and(|registered| registered.will_wake(cancel_waker))
                {
                    std::mem::replace(&mut guard.cancel_waker, incoming_waker.take())
                } else {
                    None
                }
            };
            drop(retired_waker);
            drop(incoming_waker);
        }

        let _cx_guard = crate::cx::Cx::set_current(current_cx);

        let started_running = self
            .state
            .update_task(task_id, |record| {
                let old_state = record.state.clone();
                if record.start_running() {
                    Some((old_state, record.state.clone()))
                } else {
                    None
                }
            })
            .flatten();

        if let Some((from_state, to_state)) = started_running.as_ref() {
            if self.config.has_cancellation_oracle() {
                self.notify_cancellation_oracle_task_transition(task_id, from_state, to_state);
            }
        }

        // 4. Poll the task
        if self.steps < 50 {
            crate::tracing_compat::trace!(
                "lab runtime executing task {:?} at step {}",
                task_id,
                self.steps
            );
        }

        // Notify oracle of task poll
        if self.config.has_cancellation_oracle() {
            self.notify_cancellation_oracle_task_poll(task_id);
        }

        let result = if let Some(stored) = self.state.get_stored_future(task_id) {
            if let Some(replay) = self.production_replay.as_mut()
                && let Some(ordinal) = replay.selected.take()
            {
                if let Some(cancellation) = replay.cancellation.as_mut() {
                    cancellation.record_poll(ordinal);
                }
                replay.next = replay.next.saturating_add(1);
                replay.report.steps_matched = replay.report.steps_matched.saturating_add(1);
            }
            let _scheduler_driven =
                crate::runtime::scheduler::three_lane::ScopedSchedulerDriven::enter();
            stored.poll(&mut cx)
        } else {
            if let Some(replay) = self.production_replay.as_mut()
                && let Some(ordinal) = replay.selected.take()
            {
                let _ = replay.diverge(
                    self.steps,
                    ordinal,
                    Some(task_id),
                    ReplayDivergenceReason::SchedulerInvariant,
                );
            }
            // A stale wake may name a retired future. It is not a matched poll.
            return Ok(true);
        };

        // Obligation posts made during this poll are applied while the task
        // record still exists: a reserve+resolve within one poll is tracked,
        // and a reservation left open is caught by the task's completion-time
        // leak check instead of being refused as a post from a retired holder
        // (br-asupersync-bi2462.13).
        if result.is_ready() {
            self.state
                .revoke_obligation_admission_before_completion(task_id, None);
        }
        while self.state.has_pending_obligation_posts() {
            if self.state.drain_obligation_posts(64) == 0 {
                break;
            }
        }

        // Record the poll so futurelock detection uses the correct idle step count.
        let _ = self.state.update_task(task_id, |record| {
            record.mark_polled(self.steps);
        });

        let (cancel_ack, cancel_wakes) = self.consume_cancel_ack(task_id).into_parts();

        // Sample only the admitted task's primary Cx. A derived fiber context
        // can share its TaskId without cancelling this task.
        let observed_cancellation = self
            .production_replay
            .as_ref()
            .and_then(|replay| replay.cancellation.as_ref())
            .and_then(|_| self.state.task(task_id))
            .and_then(|record| record.cx_inner.as_ref())
            .map(|inner| {
                let inner = inner.read();
                (inner.is_cancel_requested(), inner.cancel_reason.clone())
            });
        // Compare the actual checkpoint receipt at this poll boundary. A task
        // may acknowledge again on later cleanup polls; completion alone is
        // not evidence that the captured acknowledgement happened.
        if let Some(replay) = self.production_replay.as_mut()
            && let Some(cancellation) = replay.cancellation.as_mut()
            && let Some(termination) = cancellation.observe_ack(
                cancel_ack.as_ref(),
                replay.next,
                observed_cancellation.as_ref(),
            )
        {
            replay.termination = Some(termination);
        }

        // A checkpoint can win the race with the runtime-owned handle command.
        // Replay the logical RequestCancel -> acknowledgement ordering into the
        // oracle even though both TaskRecord mutations are already complete.
        if let Some(receipt) = cancel_ack.as_ref()
            && self.config.has_cancellation_oracle()
        {
            self.notify_cancellation_oracle_cancel_request(
                task_id,
                receipt.effective_reason.clone(),
            );
            if let Some((from_state, to_state)) = receipt.request_transition.as_ref() {
                self.notify_cancellation_oracle_task_transition(task_id, from_state, to_state);
            }
            if let Some((from_state, to_state)) = receipt.acknowledge_transition.as_ref() {
                self.notify_cancellation_oracle_task_transition(task_id, from_state, to_state);
            }
            self.notify_cancellation_oracle_cancel_ack(task_id);
        }
        let cancel_priority = cancel_ack.as_ref().map(|receipt| receipt.cleanup_priority);
        let cancel_ack = cancel_ack.is_some();

        // 5. Handle result
        match result {
            Poll::Ready(outcome) => {
                // Task completed
                self.state.remove_stored_future(task_id);
                self.scheduler.lock().forget_task(task_id);

                // Update state to Completed if not already terminal
                let mut oracle_transitions = Vec::new(); // Collect transitions for later oracle notification

                let _ = self.state.update_task(task_id, |record| {
                    if !record.state.is_terminal() {
                        let old_state = record.state.clone();
                        let record_outcome = match outcome {
                            crate::types::Outcome::Ok(()) => crate::types::Outcome::Ok(()),
                            crate::types::Outcome::Err(()) => crate::types::Outcome::Err(
                                crate::error::Error::new(crate::error::ErrorKind::Internal),
                            ),
                            crate::types::Outcome::Cancelled(r) => {
                                crate::types::Outcome::Cancelled(r)
                            }
                            crate::types::Outcome::Panicked(p) => {
                                crate::types::Outcome::Panicked(p)
                            }
                        };
                        let completed_via_cancel =
                            if matches!(record_outcome, crate::types::Outcome::Ok(())) {
                                let should_cancel = matches!(
                                    record.state,
                                    TaskState::Cancelling { .. } | TaskState::Finalizing { .. }
                                ) || (cancel_ack
                                    && matches!(record.state, TaskState::CancelRequested { .. }));
                                if should_cancel {
                                    if matches!(record.state, TaskState::CancelRequested { .. }) {
                                        let state_before = record.state.clone();
                                        let _ = record.acknowledge_cancel();
                                        oracle_transitions
                                            .push((state_before, record.state.clone()));
                                    }
                                    if matches!(record.state, TaskState::Cancelling { .. }) {
                                        let state_before = record.state.clone();
                                        record.cleanup_done();
                                        oracle_transitions
                                            .push((state_before, record.state.clone()));
                                    }
                                    if matches!(record.state, TaskState::Finalizing { .. }) {
                                        let state_before = record.state.clone();
                                        record.finalize_done();
                                        oracle_transitions
                                            .push((state_before, record.state.clone()));
                                    }
                                    matches!(
                                        record.state,
                                        TaskState::Completed(crate::types::Outcome::Cancelled(_))
                                    )
                                } else {
                                    false
                                }
                            } else {
                                false
                            };
                        if !completed_via_cancel {
                            record.complete(record_outcome);
                            oracle_transitions.push((old_state, record.state.clone()));
                        }
                    }
                });

                // Notify oracle of all state transitions after all mutations are complete
                if self.config.has_cancellation_oracle() {
                    for (from_state, to_state) in oracle_transitions {
                        self.notify_cancellation_oracle_task_transition(
                            task_id,
                            &from_state,
                            &to_state,
                        );
                    }
                }

                // Record task completion with severity from the finalized task
                // record. Must happen AFTER state finalization above because
                // create_task wraps user futures to always return Outcome::Ok(())
                // — the real severity comes from the cancel protocol state machine.
                let final_severity =
                    self.state
                        .task(task_id)
                        .map_or(crate::types::Severity::Ok, |record| match &record.state {
                            TaskState::Completed(outcome) => outcome.severity(),
                            _ => crate::types::Severity::Ok,
                        });
                self.replay_recorder
                    .record_task_completed(task_id, final_severity);

                if let Some(monitor) = &mut self.deadline_monitor {
                    if let Some(record) = self.state.task(task_id) {
                        let now = self.state.now;
                        let duration =
                            Duration::from_nanos(now.duration_since(record.created_at()));
                        let (task_type, deadline) = record
                            .cx_inner
                            .as_ref()
                            .map(|inner| inner.read())
                            .map_or_else(
                                || ("default".to_string(), None),
                                |inner| {
                                    (
                                        inner
                                            .task_type
                                            .clone()
                                            .unwrap_or_else(|| "default".to_string()),
                                        inner.budget.deadline,
                                    )
                                },
                            );
                        monitor.record_completion(task_id, &task_type, duration, deadline, now);
                    }
                }

                // Capture this task's retirement barrier BEFORE task_completed
                // recycles the record: reading it afterward (as this site used
                // to) finds the record already removed and never opens it,
                // hanging a consumer parked on gated terminal-result visibility
                // (br-asupersync-yhueis). The scheduler (A-tier) lock is not yet
                // held here, so this cx_inner (E-tier) read respects E -> A.
                let retirement_barrier = self
                    .state
                    .task(task_id)
                    .and_then(|record| record.cx_inner.as_ref())
                    .and_then(|inner| inner.read().retirement_barrier.clone());

                // Notify waiters
                let (waiters, completion_observer) =
                    self.state.task_completed(task_id).into_parts();

                // br-asupersync-iwqn3q: hoist priority lookup OUT of
                // the scheduler-locked scope. cx_inner is an
                // E(Config)-tier RwLock; the scheduler is an A(Tasks)
                // mutex. The project's lock ordering requires
                // E → D → B → A → C, so cx_inner.read() must precede
                // scheduler.lock(). Acquiring them in the loop
                // body inverted the order and could deadlock against
                // any thread holding cx_inner.write() while waiting
                // for the scheduler. Snapshot the (waiter, priority)
                // tuples first, THEN acquire the scheduler.
                //
                // The sibling pattern at schedule_for_cancel
                // (line ~2002) already gets this right; this site
                // was the asymmetric outlier.
                let scheduled: Vec<(TaskId, u8)> = waiters
                    .into_iter()
                    .map(|w| {
                        let prio = self
                            .state
                            .task(w)
                            .and_then(|t| t.cx_inner.as_ref())
                            .map_or(0, |inner| inner.read().budget.priority);
                        (w, prio)
                    })
                    .collect();
                let mut sched = self.scheduler.lock();
                for (waiter, prio) in scheduled {
                    sched.schedule(waiter, prio);
                }
                drop(sched);
                // Open this task's retirement barrier post-lock so a consumer
                // that received its terminal result early can now surface
                // completion (br-asupersync-yhueis). The record has committed
                // terminal; `open_and_wake` may run a foreign consumer waker, so
                // it must follow the scheduler unlock. The barrier was captured
                // above, before task_completed recycled the record.
                if let Some(barrier) = retirement_barrier {
                    barrier.open_and_wake();
                }
                completion_observer.dispatch();
                cancel_wakes.dispatch();
            }
            Poll::Pending => {
                // Task yielded. Waker will reschedule it when ready.
                // Note: If the task yielded via `cx.waker().wake_by_ref()`, it might already be scheduled.
                // If it yielded for I/O or other events, it won't be scheduled until that event fires.

                // Record task yielding
                self.replay_recorder.record_task_yielded(task_id);
                let _ = self.state.update_task(task_id, |record| {
                    // Inspector poll counts, as on the native schedulers
                    // (asupersync-bi2462.116).
                    record.increment_polls();
                    record.cached_waker = Some((waker, priority));
                    record.cached_cancel_waker = cancel_waker_for_cache;
                });

                if let Some(cancel_priority) = cancel_priority {
                    // The queued handle command may now coalesce against the
                    // reconciled TaskRecord, so this poll owns the replacement
                    // cancel-lane publication before any auxiliary Waker runs.
                    self.scheduler
                        .lock()
                        .schedule_cancel(task_id, cancel_priority);
                }
                cancel_wakes.dispatch();

                // 6. Post-poll chaos injection (spurious wakeups for pending tasks)
                self.inject_post_poll_chaos(task_id, priority);
            }
        }

        self.check_deadline_monitor();
        Ok(true)
    }

    fn check_deadline_monitor(&mut self) {
        if let Some(monitor) = &mut self.deadline_monitor {
            let now = self.state.now;
            monitor.check(now, self.state.tasks_iter().map(|(_, record)| record));
        }
    }

    fn poll_io(&mut self) {
        let Some(handle) = self.state.io_driver_handle() else {
            return;
        };
        let now = self.state.now;
        let (state, recorder, seen) = (
            &mut self.state,
            &mut self.replay_recorder,
            &mut self.seen_io_tokens,
        );
        if let Err(error) = handle.turn_with(Some(Duration::ZERO), |event, interest| {
            let token = event.token.0;
            let interest = interest.unwrap_or(event.ready);
            if seen.insert(token) {
                state.record_trace_event(|seq| {
                    TraceEvent::io_requested(seq, now, token as u64, interest.bits())
                });
            }
            state.record_trace_event(|seq| {
                TraceEvent::io_ready(seq, now, token as u64, event.ready.bits())
            });
            recorder.record_io_ready(
                token as u64,
                event.is_readable(),
                event.is_writable(),
                event.is_error(),
                event.is_hangup(),
            );
        }) {
            let _ = &error;
            crate::tracing_compat::warn!(
                error = ?error,
                "lab runtime io_driver poll failed"
            );
        }
        self.sync_reactor_chaos_stats();
    }

    /// Injects chaos before polling a task.
    ///
    /// Returns `true` if the task should be skipped (e.g., cancelled or budget exhausted).
    fn inject_pre_poll_chaos(&mut self, task_id: TaskId) -> bool {
        let Some(chaos_config) = self.config.chaos.clone() else {
            return false;
        };
        let Some(chaos_rng) = &mut self.chaos_rng else {
            return false;
        };

        let cancel = chaos_rng.should_inject_cancel(&chaos_config);

        // Check for delay injection
        let delay = chaos_rng
            .should_inject_delay(&chaos_config)
            .then(|| chaos_rng.next_delay(&chaos_config));

        // Check for budget exhaustion injection
        let budget_exhaust = chaos_rng.should_inject_budget_exhaust(&chaos_config);
        let skip_poll = cancel | budget_exhaust;
        self.chaos_stats
            .record_pre_poll_outcomes(cancel, delay, budget_exhaust);

        // Now apply the injections (no more borrowing chaos_rng).
        // Cancel and budget_exhaust are independent — apply both when both fire.
        let cancel_wakes = cancel.then(|| self.inject_cancel(task_id));
        if cancel {
            // Publish the cancelled task before any virtual-time advancement
            // or deferred cancellation callback can reenter the lab runtime.
            self.reschedule_after_chaos_skip(task_id);
        }

        if let Some(d) = delay {
            self.advance_time(Self::duration_nanos_saturating(d));
        }

        if budget_exhaust {
            self.inject_budget_exhaust(task_id);
        }

        if skip_poll && !cancel {
            self.reschedule_after_chaos_skip(task_id);
        }
        if let Some(cancel_wakes) = cancel_wakes {
            cancel_wakes.dispatch();
        }

        skip_poll
    }

    #[inline]
    fn duration_nanos_saturating(duration: Duration) -> u64 {
        u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
    }

    /// Injects chaos after polling a task that returned Pending.
    fn inject_post_poll_chaos(&mut self, task_id: TaskId, priority: u8) {
        let Some(chaos_config) = self.config.chaos.clone() else {
            return;
        };
        let Some(chaos_rng) = &mut self.chaos_rng else {
            return;
        };

        // br-asupersync-4so3w3: gate wakeup_storm injection on at-least-
        // one-open-region. After every region has closed, the lab is in
        // a quiescence state that production reaches via region drop;
        // injecting a spurious wakeup at that point would synthesize a
        // schedule that production cannot reproduce, defeating the
        // whole point of chaos-driven trace minimisation.
        let has_open_region = self.state.live_region_count() > 0;
        let wakeup_count = if chaos_rng.should_inject_wakeup_storm(&chaos_config, has_open_region) {
            Some(chaos_rng.next_wakeup_count(&chaos_config))
        } else {
            None
        };

        // br-asupersync-7uu7sa: even when SOME region is open, this
        // specific task may belong to a region that has already
        // transitioned to Closing/Draining/Finalizing/Closed during a different
        // chaos action in the same step. Re-polling such a task
        // violates the structured-concurrency contract the oracles
        // assume — it produces a 'cancel-aware future re-polled after
        // region close' code path that production never executes.
        // Filter post-decision so chaos budget accounting stays in
        // sync with the global gate decision.
        let target_region_open = self
            .state
            .task(task_id)
            .map(|t| t.owner)
            .and_then(|owner| self.state.region(owner))
            .is_some_and(|region| region.state().can_accept_work());

        // Apply the injection (no more borrowing chaos_rng)
        if let Some(count) = wakeup_count
            && target_region_open
        {
            self.chaos_stats.record_wakeup_storm(count as u64);
            self.inject_spurious_wakes(task_id, priority, count);
        } else {
            self.chaos_stats.record_no_injection();
        }
    }

    fn sync_reactor_chaos_stats(&mut self) {
        let current = self.lab_reactor.chaos_stats();
        let previous = &self.seen_reactor_chaos_stats;
        let delta = ChaosStats {
            cancellations: current.cancellations.saturating_sub(previous.cancellations),
            delays: current.delays.saturating_sub(previous.delays),
            total_delay: current.total_delay.saturating_sub(previous.total_delay),
            io_errors: current.io_errors.saturating_sub(previous.io_errors),
            wakeup_storms: current.wakeup_storms.saturating_sub(previous.wakeup_storms),
            spurious_wakeups: current
                .spurious_wakeups
                .saturating_sub(previous.spurious_wakeups),
            budget_exhaustions: current
                .budget_exhaustions
                .saturating_sub(previous.budget_exhaustions),
            decision_points: current
                .decision_points
                .saturating_sub(previous.decision_points),
        };
        self.chaos_stats.merge(&delta);
        self.seen_reactor_chaos_stats = current;
    }

    fn reschedule_after_chaos_skip(&self, task_id: TaskId) {
        let Some(record) = self.state.task(task_id) else {
            return;
        };
        if record.state.is_terminal() {
            return;
        }
        let priority = record
            .cx_inner
            .as_ref()
            .map_or(0, |inner| inner.read().budget.priority);
        let mut sched = self.scheduler.lock();
        sched.schedule_cancel(task_id, priority);
    }

    fn schedule_async_finalizers(&mut self) {
        let tasks = self.state.drain_ready_async_finalizers();
        if tasks.is_empty() {
            return;
        }
        let mut sched = self.scheduler.lock();
        let mut spawn_effects = Vec::with_capacity(tasks.len());
        for (task_id, priority, effects) in tasks {
            sched.schedule(task_id, priority);
            spawn_effects.push(effects);
        }
        drop(sched);
        for effects in spawn_effects {
            effects.dispatch();
        }
    }

    fn consume_cancel_ack(
        &mut self,
        task_id: TaskId,
    ) -> crate::types::task_context::CancellationEffects<
        Option<crate::record::task::CheckpointCancelAck>,
    > {
        self.state.consume_task_checkpoint_cancel_ack(task_id)
    }

    /// Injects a cancellation for a task.
    fn inject_cancel(&mut self, task_id: TaskId) -> crate::types::task_context::CancelWakeEffects {
        use crate::types::{Budget, CancelReason};

        // Record replay event
        self.replay_recorder.record_cancel_injection(task_id);

        let reason = CancelReason::user("chaos-injected");
        // Mark the task as cancel-requested with the chaos reason, preserving
        // any stronger cancellation that already won for this task.
        let transition = self
            .state
            .update_task(task_id, |record| {
                if !record.state.is_terminal() {
                    let old_state = record.state.clone();
                    let effects = record.request_cancel_with_budget(reason.clone(), Budget::ZERO);
                    let (_, cancel_wakes) = effects.into_parts();
                    let effective_reason = record
                        .cancel_reason()
                        .cloned()
                        .unwrap_or_else(|| reason.clone());
                    Some((
                        old_state,
                        record.state.clone(),
                        effective_reason,
                        cancel_wakes,
                    ))
                } else {
                    None
                }
            })
            .flatten();

        // Publish the authoritative post-strengthening reason to the oracle
        // after mutation, then record the corresponding state transition.
        let cancel_wakes =
            if let Some((old_state, new_state, effective_reason, cancel_wakes)) = transition {
                if self.config.has_cancellation_oracle() {
                    self.oracles.cancellation_protocol.on_cancel_request(
                        task_id,
                        effective_reason,
                        self.virtual_time,
                    );
                    self.oracles.cancellation_protocol.on_transition(
                        task_id,
                        &old_state,
                        &new_state,
                        self.virtual_time,
                    );
                }
                cancel_wakes
            } else {
                crate::types::task_context::CancelWakeEffects::empty()
            };

        // Emit trace event
        self.state.record_trace_event(|seq| {
            TraceEvent::new(
                seq,
                self.virtual_time,
                TraceEventKind::ChaosInjection,
                TraceData::Chaos {
                    kind: "cancel".to_string(),
                    task: Some(task_id),
                    detail: "chaos-injected cancellation".to_string(),
                },
            )
        });
        cancel_wakes
    }

    /// Notifies the cancellation protocol oracle about runtime events.
    pub fn notify_cancellation_oracle_task_create(&mut self, task_id: TaskId, region_id: RegionId) {
        self.oracles
            .cancellation_protocol
            .on_task_create(task_id, region_id);
    }

    /// Notifies the cancellation protocol oracle about region creation.
    pub fn notify_cancellation_oracle_region_create(
        &mut self,
        region_id: RegionId,
        parent: Option<RegionId>,
    ) {
        self.oracles
            .cancellation_protocol
            .on_region_create(region_id, parent);
    }

    /// Notifies the cancellation protocol oracle about task state transitions.
    pub fn notify_cancellation_oracle_task_transition(
        &mut self,
        task_id: TaskId,
        from: &crate::record::task::TaskState,
        to: &crate::record::task::TaskState,
    ) {
        self.oracles
            .cancellation_protocol
            .on_transition(task_id, from, to, self.virtual_time);
    }

    /// Notifies the cancellation protocol oracle about cancel requests.
    pub fn notify_cancellation_oracle_cancel_request(
        &mut self,
        task_id: TaskId,
        reason: crate::types::CancelReason,
    ) {
        self.oracles
            .cancellation_protocol
            .on_cancel_request(task_id, reason, self.virtual_time);
    }

    /// Notifies the cancellation protocol oracle about cancel acknowledgments.
    pub fn notify_cancellation_oracle_cancel_ack(&mut self, task_id: TaskId) {
        self.oracles
            .cancellation_protocol
            .on_cancel_ack(task_id, self.virtual_time);
    }

    /// Notifies the cancellation protocol oracle about task polling.
    pub fn notify_cancellation_oracle_task_poll(&mut self, task_id: TaskId) {
        self.oracles.cancellation_protocol.on_task_poll(task_id);
    }

    /// Notifies the cancellation protocol oracle about mask entry.
    pub fn notify_cancellation_oracle_mask_enter(&mut self, task_id: TaskId) {
        self.oracles
            .cancellation_protocol
            .on_mask_enter(task_id, self.virtual_time);
    }

    /// Notifies the cancellation protocol oracle about mask exit.
    pub fn notify_cancellation_oracle_mask_exit(&mut self, task_id: TaskId) {
        self.oracles
            .cancellation_protocol
            .on_mask_exit(task_id, self.virtual_time);
    }

    /// Notifies the cancellation protocol oracle about region cancellation.
    pub fn notify_cancellation_oracle_region_cancel(
        &mut self,
        region_id: RegionId,
        reason: crate::types::CancelReason,
    ) {
        self.oracles
            .cancellation_protocol
            .on_region_cancel(region_id, reason, self.virtual_time);
    }

    /// Checks the cancellation protocol oracle for violations and optionally enforces them.
    pub fn check_cancellation_protocol(
        &mut self,
    ) -> Result<(), crate::lab::oracle::CancellationProtocolViolation> {
        if !self.config.has_cancellation_oracle() {
            return Ok(());
        }

        let result = self.oracles.cancellation_protocol.check();

        if let Err(ref violation) = result {
            if self.config.panic_on_cancellation_violation {
                // Configurable enforcement: panic in enforce mode
                panic!("Cancellation protocol violation detected: {violation}");
            } else {
                // Warn mode: log the violation
                crate::tracing_compat::warn!(
                    violation = %violation,
                    "Cancellation protocol violation detected"
                );
            }
        }

        result
    }

    /// Injects budget exhaustion for a task.
    fn inject_budget_exhaust(&mut self, task_id: TaskId) {
        // Record replay event
        self.replay_recorder
            .record_budget_exhaust_injection(task_id);

        // Set the task's budget quotas to zero
        if let Some(record) = self.state.task(task_id) {
            if let Some(cx_inner) = &record.cx_inner {
                let mut inner = cx_inner.write();
                inner.budget.poll_quota = 0;
                inner.budget.cost_quota = Some(0);
            }
        }

        // Emit trace event
        self.state.record_trace_event(|seq| {
            TraceEvent::new(
                seq,
                self.virtual_time,
                TraceEventKind::ChaosInjection,
                TraceData::Chaos {
                    kind: "budget_exhaust".to_string(),
                    task: Some(task_id),
                    detail: "chaos-injected budget exhaustion".to_string(),
                },
            )
        });
    }

    /// Injects spurious wakeups for a task.
    fn inject_spurious_wakes(&mut self, task_id: TaskId, priority: u8, count: usize) {
        // br-asupersync-7uu7sa: defense-in-depth — even when the chaos
        // call site (inject_post_poll_chaos) gates correctly, future
        // callers may invoke this method directly. Refuse to wake a
        // task whose owning region is no longer accepting normal work
        // (Closing / Draining / Finalizing / Closed). This silently no-ops rather
        // than panicking so chaos campaigns with TaskId selection that
        // races region close don't artificially abort.
        let owner_open = self
            .state
            .task(task_id)
            .map(|t| t.owner)
            .and_then(|owner| self.state.region(owner))
            .is_some_and(|region| region.state().can_accept_work());
        if !owner_open {
            return;
        }

        // Record replay event
        self.replay_recorder
            .record_wakeup_storm_injection(task_id, u32::try_from(count).unwrap_or(u32::MAX));

        // Schedule the task multiple times (spurious wakeups)
        let mut sched = self.scheduler.lock();
        sched.inject_spurious_wakes(task_id, priority, count);
        drop(sched);

        // Emit trace event
        self.state.record_trace_event(|seq| {
            TraceEvent::new(
                seq,
                self.virtual_time,
                TraceEventKind::ChaosInjection,
                TraceData::Chaos {
                    kind: "wakeup_storm".to_string(),
                    task: Some(task_id),
                    detail: format!("chaos-injected {count} spurious wakeups"),
                },
            )
        });
    }

    /// Public wrapper for `step()` for use in tests.
    ///
    /// This is useful for testing determinism across multiple step executions.
    pub fn step_for_test(&mut self) {
        self.step();
    }

    /// Checks invariants and returns any violations.
    #[must_use]
    pub fn check_invariants(&mut self) -> Vec<InvariantViolation> {
        let mut violations = Vec::new();

        // Check cancellation protocol oracle
        if let Err(violation) = self.check_cancellation_protocol() {
            violations.push(InvariantViolation::CancellationProtocol {
                violation: violation.to_string(),
            });
        }

        // Check for obligation leaks
        let leaks = self.obligation_leaks();
        if !leaks.is_empty() {
            for leak in &leaks {
                let _ = self.state.mark_obligation_leaked(leak.obligation);
            }
            violations.push(InvariantViolation::ObligationLeak { leaks });
        }

        violations.extend(self.futurelock_violations());
        violations.extend(self.quiescence_violations());

        // Check for task leaks (non-terminal tasks)
        let task_leak_count = self.task_leaks();
        if task_leak_count > 0 {
            violations.push(InvariantViolation::TaskLeak {
                count: task_leak_count,
            });
        }

        violations
    }

    fn obligation_leaks(&self) -> Vec<ObligationLeak> {
        let mut leaks = Vec::new();

        for (_, obligation) in self.state.obligations_iter() {
            if !obligation.is_pending() {
                continue;
            }

            let holder_terminal = self
                .state
                .task(obligation.holder)
                .is_none_or(|t| t.state.is_terminal());
            let region_closed = self
                .state
                .region(obligation.region)
                .is_none_or(|r| r.state().is_terminal());

            if holder_terminal || region_closed {
                leaks.push(ObligationLeak {
                    obligation: obligation.id,
                    kind: obligation.kind,
                    holder: obligation.holder,
                    region: obligation.region,
                });
            }
        }

        leaks
    }

    fn task_leaks(&self) -> usize {
        self.state
            .tasks_iter()
            .filter(|(_, t)| !t.state.is_terminal())
            .count()
    }

    fn quiescence_violations(&self) -> Vec<InvariantViolation> {
        let mut violations = Vec::new();
        for (_, region) in self.state.regions_iter() {
            if region.state().is_terminal() {
                // Check if any children or tasks are NOT terminal
                let live_tasks = region
                    .task_ids()
                    .iter()
                    .any(|&tid| self.state.task(tid).is_some_and(|t| !t.state.is_terminal()));

                let live_children = region.child_ids().iter().any(|&rid| {
                    self.state
                        .region(rid)
                        .is_some_and(|r| !r.state().is_terminal())
                });

                if live_tasks || live_children {
                    violations.push(InvariantViolation::QuiescenceViolation);
                }
            }
        }
        violations
    }

    fn futurelock_violations(&self) -> Vec<InvariantViolation> {
        let threshold = self.config.futurelock_max_idle_steps;
        // A task's idle count is `steps - last_polled_step`, never more than
        // `steps`, so no task can pass the threshold before the run does.
        // This runs every step: it must not walk the task table
        // (br-asupersync-bzict6).
        if threshold == 0 || self.steps <= threshold {
            return Vec::new();
        }

        let current_step = self.steps;
        let mut violations = Vec::new();

        // One pass over the obligations, grouped by holder. `TaskId` orders by
        // arena slot, so holders come out in `tasks_iter` order and each
        // `held` list keeps `obligations_iter` order.
        let mut held_by_holder = std::collections::BTreeMap::<TaskId, Vec<ObligationId>>::new();
        for (_, obligation) in self.state.obligations_iter() {
            if obligation.is_pending() {
                held_by_holder
                    .entry(obligation.holder)
                    .or_default()
                    .push(obligation.id);
            }
        }

        for (holder, held) in held_by_holder {
            let Some(task) = self.state.task(holder) else {
                continue;
            };
            if task.state.is_terminal() {
                continue;
            }

            let idle_steps = current_step.saturating_sub(task.last_polled_step);
            if idle_steps > threshold {
                violations.push(InvariantViolation::Futurelock {
                    task: task.id,
                    region: task.owner,
                    idle_steps,
                    held,
                    last_checkpoint_message: self.futurelock_checkpoint_message(task.id),
                });
            }
        }

        violations
    }

    fn futurelock_checkpoint_message(&self, task_id: TaskId) -> Option<String> {
        self.state.task(task_id).and_then(|task| {
            task.cx
                .as_ref()
                .and_then(|cx| cx.checkpoint_state().last_message)
                .or_else(|| {
                    task.cx_inner
                        .as_ref()
                        .and_then(|inner| inner.read().materialised_checkpoint_state().last_message)
                })
        })
    }

    fn check_futurelocks(&self) {
        let violations = self.futurelock_violations();
        if violations.is_empty() {
            return;
        }

        for v in violations {
            let InvariantViolation::Futurelock {
                task,
                region,
                idle_steps,
                held,
                last_checkpoint_message,
            } = v
            else {
                continue;
            };

            let mut held_kinds = Vec::new();
            for oid in &held {
                for (_, obligation) in self.state.obligations_iter() {
                    if obligation.id == *oid {
                        held_kinds.push((obligation.id, obligation.kind));
                        break;
                    }
                }
            }

            self.state.record_trace_event(|seq| {
                TraceEvent::new(
                    seq,
                    self.virtual_time,
                    TraceEventKind::FuturelockDetected,
                    TraceData::Futurelock {
                        task,
                        region,
                        idle_steps,
                        held: held_kinds,
                    },
                )
            });

            assert!(
                !self.config.panic_on_futurelock,
                "[ASUP-E402] futurelock detected: seed={} {task} in {region} idle={idle_steps} held={held:?} last_checkpoint={}",
                self.config.seed,
                format_futurelock_checkpoint(last_checkpoint_message.as_deref())
            );
        }
    }
}

/// Run an async task under a fresh [`LabRuntime`] with the given seed.
///
/// This is the runtime half of the `#[lab_test]` macro. It creates a root
/// region, spawns one task under a current [`crate::cx::Cx`], drives the lab to
/// quiescence, and returns the task output together with the passing structured
/// [`LabRunReport`]. Any failed lab-test contract attempts to write an automatic
/// crashpack before panicking when auto-artifacts are enabled.
///
/// # Panics
///
/// Panics if the task cannot be spawned, does not finish after the lab run, is
/// cancelled, panics, fails an oracle or runtime invariant, or does not reach
/// quiescence. Test harness callers should treat those panics as deterministic
/// failures; a returned report always satisfies the lab-test success contract.
///
/// # Examples
///
/// ```rust
/// use asupersync::lab::run_async_under_lab;
///
/// let (value, report) = run_async_under_lab(7, |cx| async move {
///     assert_eq!(
///         cx.region_id(),
///         asupersync::cx::Cx::current().expect("current Cx").region_id()
///     );
///     42_u8
/// });
///
/// assert_eq!(value, 42);
/// assert!(report.quiescent);
/// assert!(report.oracle_report.all_passed());
/// assert!(report.invariant_violations.is_empty());
/// ```
#[must_use]
pub fn run_async_under_lab<F, Fut, T>(seed: u64, task: F) -> (T, LabRunReport)
where
    F: FnOnce(crate::cx::Cx) -> Fut + Send + 'static,
    Fut: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    run_async_under_lab_with_config(LabConfig::new(seed), task)
}

/// Run an async task under a fresh [`LabRuntime`] using an explicit config.
///
/// This variant lets test macros and harnesses enable deterministic chaos or
/// tune step limits while preserving the same strict root-task execution and
/// automatic-crashpack contract as [`run_async_under_lab`].
///
/// # Panics
///
/// Panics under the same conditions as [`run_async_under_lab`].
#[must_use]
pub fn run_async_under_lab_with_config<F, Fut, T>(config: LabConfig, task: F) -> (T, LabRunReport)
where
    F: FnOnce(crate::cx::Cx) -> Fut + Send + 'static,
    Fut: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    let test_name = std::thread::current()
        .name()
        .unwrap_or("run_async_under_lab")
        .to_owned();
    run_async_lab_test_with_config(config, &test_name, task)
}

/// Run an async `#[lab_test]` body under a fresh [`LabRuntime`].
///
/// This helper uses the same root-task model as [`run_async_under_lab_with_config`],
/// and adds lab-test failure handling: task failures, missing completion, oracle
/// failures, invariant violations, and non-quiescence all write an auto-crashpack
/// before panicking.
///
/// # Panics
///
/// Panics when the async body fails, does not finish, or when the final
/// [`LabRunReport`] violates the lab-test success contract.
///
/// Replay configuration overrides are applied from the environment before the
/// runtime is constructed. Generated test harnesses resolve the seed override
/// separately so seed-derived chaos configuration remains internally
/// consistent.
#[must_use]
pub fn run_async_lab_test_with_config<F, Fut, T>(
    config: LabConfig,
    test_name: &str,
    task: F,
) -> (T, LabRunReport)
where
    F: FnOnce(crate::cx::Cx) -> Fut + Send + 'static,
    Fut: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    let config = lab_test_config_from_env(config);
    let seed = config.seed;
    let mut runtime = LabRuntime::new(config);
    let root = runtime
        .state
        .create_root_region(crate::types::Budget::INFINITE);
    let (task_id, mut handle, spawn_effects) = runtime
        .state
        .create_task_with_deferred_spawn_effects(root, crate::types::Budget::INFINITE, async move {
            let cx = crate::cx::Cx::current()
                .unwrap_or_else(|| panic!("lab task started without current Cx for seed {seed}"));
            task(cx).await
        })
        .unwrap_or_else(|error| panic!("failed to spawn lab task for seed {seed}: {error}"));
    runtime
        .scheduler
        .lock()
        .schedule(task_id, crate::types::Budget::INFINITE.priority);
    spawn_effects.dispatch();

    let report = runtime.run_until_quiescent_with_report();
    let output = match handle.try_join() {
        Ok(Some(output)) => output,
        Ok(None) => {
            let cause = format!(
                "lab task did not finish for seed {seed}: quiescent={}, steps_total={}",
                report.quiescent, report.steps_total
            );
            let artifact = runtime.write_auto_crashpack_for_task_failure(
                test_name,
                &report,
                task_id,
                root,
                FailureOutcome::Err,
                &cause,
            );
            panic!(
                "{}",
                lab_auto_failure_message(test_name, seed, &cause, artifact)
            );
        }
        Err(error) => {
            let cause = format!("lab task failed for seed {seed}: {error}");
            let outcome = failure_outcome_from_join_error(&error);
            let artifact = runtime.write_auto_crashpack_for_task_failure(
                test_name, &report, task_id, root, outcome, &cause,
            );
            panic!(
                "{}",
                lab_auto_failure_message(test_name, seed, &cause, artifact)
            );
        }
    };

    if !report.lab_test_passed() {
        let cause = lab_report_failure_summary(&report);
        let artifact = runtime.write_auto_crashpack_for_report(test_name, &report);
        panic!(
            "{}",
            lab_auto_failure_message(test_name, seed, &cause, artifact)
        );
    }

    (output, report)
}

fn failure_outcome_from_join_error(error: &crate::runtime::JoinError) -> FailureOutcome {
    match error {
        crate::runtime::JoinError::Cancelled(reason) => FailureOutcome::Cancelled {
            cancel_kind: reason.kind(),
        },
        crate::runtime::JoinError::Panicked(payload) => FailureOutcome::Panicked {
            message: payload.message().to_owned(),
        },
        crate::runtime::JoinError::PolledAfterCompletion => FailureOutcome::Err,
    }
}

/// Read the replay seed override consumed by generated lab-test harnesses.
///
/// # Panics
///
/// Panics when the variable is present but is not a valid `u64`.
#[doc(hidden)]
#[must_use]
pub fn lab_test_seed_override() -> Option<u64> {
    let value = lab_test_env_value(LAB_TEST_SEED_ENV)?;
    Some(value.parse::<u64>().unwrap_or_else(|error| {
        panic!("{LAB_TEST_SEED_ENV} must be a u64, got {value:?}: {error}")
    }))
}

/// Apply crashpack replay overrides to a lab-test configuration.
///
/// `ASUPERSYNC_MAX_STEPS=none` restores an unlimited step budget. Generated
/// harnesses resolve the seed before configuration construction; this helper
/// also updates seed-derived entropy and chaos seeds for direct callers while
/// preserving explicitly decoupled seeds.
///
/// # Panics
///
/// Panics when an override is present but malformed.
#[doc(hidden)]
#[must_use]
pub fn lab_test_config_from_env(mut config: LabConfig) -> LabConfig {
    if let Some(seed) = lab_test_seed_override() {
        let original_seed = config.seed;
        config.seed = seed;
        if config.entropy_seed == original_seed {
            config.entropy_seed = seed;
        }
        if let Some(chaos) = config.chaos.take() {
            config.chaos = Some(if chaos.seed == original_seed {
                chaos.with_seed(seed)
            } else {
                chaos
            });
        }
    }

    if let Some(value) = lab_test_env_value(LAB_TEST_WORKERS_ENV) {
        let workers = value.parse::<usize>().unwrap_or_else(|error| {
            panic!("{LAB_TEST_WORKERS_ENV} must be a positive integer, got {value:?}: {error}")
        });
        assert!(
            workers > 0,
            "{LAB_TEST_WORKERS_ENV} must be greater than zero"
        );
        config = config.worker_count(workers);
    }

    if let Some(value) = lab_test_env_value(LAB_TEST_MAX_STEPS_ENV) {
        config = if value == "none" {
            config.no_step_limit()
        } else {
            let steps = value.parse::<u64>().unwrap_or_else(|error| {
                panic!("{LAB_TEST_MAX_STEPS_ENV} must be a u64 or 'none', got {value:?}: {error}")
            });
            config.max_steps(steps)
        };
    }

    config
}

fn lab_test_env_value(name: &str) -> Option<String> {
    match std::env::var(name) {
        Ok(value) => Some(value),
        Err(std::env::VarError::NotPresent) => None,
        Err(std::env::VarError::NotUnicode(_)) => {
            panic!("{name} must contain valid Unicode")
        }
    }
}

fn lab_auto_failure_message(
    test_name: &str,
    seed: u64,
    cause: &str,
    artifact: Result<Option<LabAutoCrashpack>, LabAutoCrashpackError>,
) -> String {
    let mut message = format!(
        "lab_test failed for {test_name} seed {seed}; rerun: \
         ASUPERSYNC_LAB_TEST_SEED={seed} cargo test {test_name} -- --exact --nocapture; \
         cause: {cause}"
    );
    match artifact {
        Ok(Some(artifact)) => {
            message.push_str(&format!(
                "\ncrashpack: {}\nreplay: {}",
                artifact.path, artifact.replay.command_line
            ));
        }
        Ok(None) => {}
        Err(error) => {
            message.push_str(&format!("\ncrashpack_error: {error}"));
        }
    }
    message
}

fn lab_report_failure_summary(report: &LabRunReport) -> String {
    format!(
        "quiescent={}; oracle_passed={}; invariant_violations={:?}; trace_fingerprint={}",
        report.quiescent,
        report.oracle_report.all_passed(),
        report.invariant_violations,
        report.trace_fingerprint
    )
}

fn auto_artifacts_enabled() -> bool {
    std::env::var(AUTO_ARTIFACTS_ENV).map_or(true, |value| value != "0")
}

fn compiled_commit_hash() -> Option<String> {
    option_env!("ASUPERSYNC_BUILD_GIT_COMMIT").map(str::to_owned)
}

fn auto_crashpack_dir(test_name: &str, pack: &CrashPack) -> PathBuf {
    let root = std::env::var_os(TEST_ARTIFACTS_DIR_ENV).map_or_else(
        || PathBuf::from("target").join("test-artifacts"),
        PathBuf::from,
    );
    root.join(sanitize_test_artifact_segment(test_name))
        .join(format!(
            "seed-{:016x}-trace-{:016x}",
            pack.seed(),
            pack.fingerprint()
        ))
}

fn sanitize_test_artifact_segment(test_name: &str) -> String {
    let mut sanitized = String::with_capacity(test_name.len());
    let mut last_was_separator = false;
    for ch in test_name.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.' {
            sanitized.push(ch);
            last_was_separator = false;
        } else if !last_was_separator {
            sanitized.push('_');
            last_was_separator = true;
        }
    }
    let sanitized = sanitized.trim_matches('_');
    if sanitized.is_empty() {
        "lab-test".to_string()
    } else {
        sanitized.to_string()
    }
}

const DEFAULT_LAB_CANCEL_STREAK_LIMIT: usize = 16;

#[derive(Debug, Clone, Copy)]
struct PendingSpuriousWake {
    priority: u8,
    remaining: usize,
}

#[derive(Debug)]
/// Deterministic lab scheduler with per-worker queues.
///
/// This is a single-threaded model of multi-worker scheduling used by the lab
/// runtime to simulate parallel execution deterministically.
pub struct LabScheduler {
    workers: Vec<crate::runtime::scheduler::PriorityScheduler>,
    scheduled: DetHashSet<TaskId>,
    pending_spurious_wakes: DetHashMap<TaskId, PendingSpuriousWake>,
    /// Task → worker assignment, indexed by arena slot.
    /// Task → worker assignment, indexed by arena slot and tagged with the
    /// generation the assignment was recorded for (GH#55). The generation tag
    /// keeps slot reuse from aliasing a live task's routing.
    assignments: Vec<Option<(u32, usize)>>,
    next_worker: usize,
    cancel_streak: Vec<usize>,
    cancel_streak_limit: usize,
    /// Tasks in the order they first entered this scheduler.
    ///
    /// The binding between recorded production spawn ordinals and lab tasks
    /// for [`LabRuntime::replay_production_schedule`]
    /// (br-asupersync-bi2462.7).
    first_entry_order: Vec<TaskId>,
    first_entry_seen: DetHashSet<TaskId>,
}

/// Why [`LabScheduler::take_preferred`] could not dispatch the requested task.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PreferredDispatchError {
    /// The task is not scheduled on any worker.
    NotRunnable,
    /// The task sits in the timed lane with a deadline in the future.
    TimedNotDue,
    /// The dedup set says scheduled but no lane holds the task.
    SchedulerInvariant,
}

impl LabScheduler {
    fn new(worker_count: usize, seed: u64) -> Self {
        let count = if worker_count == 0 { 1 } else { worker_count };
        let cancel_streak_limit = DEFAULT_LAB_CANCEL_STREAK_LIMIT.max(1);
        // GH#55: seed-derived hashing keeps `scheduled` iteration (and thus
        // every schedule-order decision that flows through it) identical for
        // identical lab seeds, regardless of the `test-internals` feature.
        let build_hasher = crate::util::det_hash::DetBuildHasher::with_seed(seed);
        Self {
            workers: (0..count)
                .map(|_| crate::runtime::scheduler::PriorityScheduler::new())
                .collect(),
            scheduled: DetHashSet::with_hasher(build_hasher.clone()),
            first_entry_seen: DetHashSet::with_hasher(build_hasher.clone()),
            first_entry_order: Vec::new(),
            pending_spurious_wakes: DetHashMap::with_hasher(build_hasher),
            assignments: Vec::new(),
            next_worker: 0,
            cancel_streak: vec![0; count],
            cancel_streak_limit,
        }
    }

    /// Returns true if no tasks are currently scheduled.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.scheduled.is_empty()
    }

    fn has_runnable_work(&mut self, now: Time) -> bool {
        self.workers
            .iter_mut()
            .any(|worker| worker.has_runnable_work(now))
    }

    /// Returns the configured cancel streak limit for lab scheduling.
    #[must_use]
    pub fn cancel_streak_limit(&self) -> usize {
        self.cancel_streak_limit
    }

    #[inline]
    fn set_assignment(&mut self, task: TaskId, worker: usize) {
        let slot = task.arena_index().index() as usize;
        if slot >= self.assignments.len() {
            self.assignments.resize(slot + 1, None);
        }
        self.assignments[slot] = Some((task.arena_index().generation(), worker));
    }

    /// Returns the worker owning `task`, but only when the recorded assignment
    /// belongs to this exact task generation.
    ///
    /// GH#55: `assignments` is indexed by arena slot, while `scheduled` and the
    /// per-worker queues are keyed by the full `TaskId` (slot + generation).
    /// Without the generation check, a task that reuses a slot aliases the
    /// previous occupant's assignment and can be routed to a worker that does
    /// not hold its queue entry.
    #[inline]
    fn assignment_for(&self, task: TaskId) -> Option<usize> {
        let slot = task.arena_index().index() as usize;
        match self.assignments.get(slot) {
            Some(&Some((generation, worker))) if generation == task.arena_index().generation() => {
                Some(worker)
            }
            _ => None,
        }
    }

    fn assign_worker(&mut self, task: TaskId) -> usize {
        if let Some(worker) = self.assignment_for(task) {
            return worker;
        }
        let worker = self.next_worker % self.workers.len();
        self.next_worker = self.next_worker.wrapping_add(1);
        self.set_assignment(task, worker);
        worker
    }

    /// Schedules a task in the ready lane on its assigned worker.
    pub fn schedule(&mut self, task: TaskId, priority: u8) {
        if !self.scheduled.insert(task) {
            return;
        }
        self.note_first_entry(task);

        let worker = self.assign_worker(task);
        self.workers[worker].schedule(task, priority);
    }

    /// Injects ready-lane wakeups that should survive normal deduplication.
    ///
    /// The first wake is scheduled immediately when needed. Remaining wakeups
    /// are re-armed one-by-one after each dequeue so wake storms trigger
    /// repeated polls instead of collapsing to a single queued wake.
    fn inject_spurious_wakes(&mut self, task: TaskId, priority: u8, count: usize) {
        if count == 0 {
            return;
        }

        let mut remaining = count;
        if self.scheduled.insert(task) {
            let worker = self.assign_worker(task);
            self.workers[worker].schedule(task, priority);
            remaining = remaining.saturating_sub(1);
        }

        if remaining == 0 {
            return;
        }

        self.pending_spurious_wakes
            .entry(task)
            .and_modify(|pending| {
                pending.priority = pending.priority.max(priority);
                pending.remaining = pending.remaining.saturating_add(remaining);
            })
            .or_insert(PendingSpuriousWake {
                priority,
                remaining,
            });
    }

    /// Schedules or promotes a task into the cancel lane.
    pub fn schedule_cancel(&mut self, task: TaskId, priority: u8) {
        if self.scheduled.insert(task) {
            self.note_first_entry(task);
            let worker = self.assign_worker(task);
            self.workers[worker].schedule_cancel(task, priority);
            return;
        }

        // GH#55: the task is already in `scheduled`, so `is_empty()` reports
        // work pending. If we cannot promote it we must still queue it
        // somewhere, or it is stranded — present in `scheduled` with no entry
        // in any worker lane — and the runtime spins forever waiting for work
        // that can never be dispatched.
        if let Some(worker) = self.assignment_for(task) {
            self.workers[worker].move_to_cancel_lane(task, priority);
        } else {
            let worker = self.assign_worker(task);
            self.workers[worker].schedule_cancel(task, priority);
        }
    }

    /// Schedules a task in the timed lane on its assigned worker.
    pub fn schedule_timed(&mut self, task: TaskId, deadline: Time) {
        if !self.scheduled.insert(task) {
            return;
        }
        self.note_first_entry(task);

        let worker = self.assign_worker(task);
        self.workers[worker].schedule_timed(task, deadline);
    }

    /// Record the first time `task` enters the scheduler (any lane).
    fn note_first_entry(&mut self, task: TaskId) {
        if self.first_entry_seen.insert(task) {
            self.first_entry_order.push(task);
        }
    }

    /// The task that entered this scheduler `ordinal`-th (zero-based), if
    /// any task has yet.
    fn first_entry(&self, ordinal: usize) -> Option<TaskId> {
        self.first_entry_order.get(ordinal).copied()
    }

    /// How many distinct tasks have entered this scheduler.
    fn first_entry_count(&self) -> usize {
        self.first_entry_order.len()
    }

    /// Dispatch exactly `task` from whichever worker and lane hold it
    /// (br-asupersync-bi2462.7).
    ///
    /// Unlike [`Self::take_forced`], no worker or lane is prescribed: a
    /// recorded production schedule names tasks, not lab workers.
    /// Bookkeeping mirrors the normal pop path.
    fn take_preferred(
        &mut self,
        task: TaskId,
        now: Time,
    ) -> Result<(DispatchLane, usize), PreferredDispatchError> {
        if !self.scheduled.contains(&task) {
            return Err(PreferredDispatchError::NotRunnable);
        }
        let worker_count = self.workers.len();
        let first = self.assignment_for(task).unwrap_or(0) % worker_count.max(1);
        for offset in 0..worker_count {
            let worker = (first + offset) % worker_count;
            let outcome = match self.workers[worker].take_exact(task, DispatchLane::Ready, now) {
                Ok(()) => Ok(DispatchLane::Ready),
                Err(ExactDispatchError::LaneMismatch { actual }) => self.workers[worker]
                    .take_exact(task, actual, now)
                    .map(|()| actual),
                Err(other) => Err(other),
            };
            match outcome {
                Ok(lane) => {
                    let removed = self.scheduled.remove(&task);
                    debug_assert!(removed, "preferred task was checked in lab scheduled set");
                    self.set_assignment(task, worker);
                    self.rearm_spurious_wake(task);
                    let limit = self.cancel_streak_limit;
                    let streak = &mut self.cancel_streak[worker];
                    *streak = if lane == DispatchLane::Cancel {
                        streak.saturating_add(1).min(limit)
                    } else {
                        0
                    };
                    return Ok((lane, worker));
                }
                Err(ExactDispatchError::NotScheduled) => {}
                Err(ExactDispatchError::TimedNotDue { .. }) => {
                    return Err(PreferredDispatchError::TimedNotDue);
                }
                Err(
                    ExactDispatchError::LaneMismatch { .. } | ExactDispatchError::QueueInvariant,
                ) => {
                    return Err(PreferredDispatchError::SchedulerInvariant);
                }
            }
        }
        Err(PreferredDispatchError::NotRunnable)
    }

    fn pop_for_worker(
        &mut self,
        worker: usize,
        rng_hint: u64,
        now: Time,
    ) -> Option<(TaskId, DispatchLane)> {
        if self.workers.is_empty() {
            return None;
        }

        let worker = worker % self.workers.len();
        let cancel_streak = &mut self.cancel_streak[worker];

        if *cancel_streak < self.cancel_streak_limit {
            if let Some((task, lane)) = self.workers[worker].pop_cancel_with_rng(rng_hint) {
                *cancel_streak += 1;
                self.scheduled.remove(&task);
                self.set_assignment(task, worker);
                self.rearm_spurious_wake(task);
                return Some((task, lane));
            }
        }

        if let Some(task) = self.workers[worker].pop_timed_only_with_hint(rng_hint, now) {
            *cancel_streak = 0;
            self.scheduled.remove(&task);
            self.set_assignment(task, worker);
            self.rearm_spurious_wake(task);
            return Some((task, DispatchLane::Timed));
        }

        if let Some(task) = self.workers[worker].pop_ready_only_with_hint(rng_hint) {
            *cancel_streak = 0;
            self.scheduled.remove(&task);
            self.set_assignment(task, worker);
            self.rearm_spurious_wake(task);
            return Some((task, DispatchLane::Ready));
        }

        if let Some((task, lane)) = self.workers[worker].pop_cancel_with_rng(rng_hint) {
            *cancel_streak = 1;
            self.scheduled.remove(&task);
            self.set_assignment(task, worker);
            self.rearm_spurious_wake(task);
            return Some((task, lane));
        }

        *cancel_streak = 0;
        None
    }

    fn steal_for_worker(&mut self, thief: usize, rng_hint: u64) -> Option<TaskId> {
        let count = self.workers.len();
        if count <= 1 {
            return None;
        }

        let thief = thief % count;
        let start = (rng_hint as usize) % count;

        for offset in 0..count {
            let victim = (start + offset) % count;
            if victim == thief {
                continue;
            }
            if let Some(task) =
                self.workers[victim].pop_ready_only_with_hint(rng_hint.wrapping_add(offset as u64))
            {
                self.scheduled.remove(&task);
                self.set_assignment(task, thief);
                self.rearm_spurious_wake(task);
                return Some(task);
            }
        }

        None
    }

    fn take_forced(
        &mut self,
        task: TaskId,
        expected_worker: usize,
        expected_lane: DispatchLane,
        now: Time,
        index: usize,
    ) -> Result<(), ForcedScheduleError> {
        if expected_worker >= self.workers.len() {
            return Err(ForcedScheduleError::WorkerUnavailable {
                worker: u32::try_from(expected_worker).unwrap_or(u32::MAX),
                worker_count: self.workers.len(),
            });
        }
        if !self.scheduled.contains(&task) {
            return Err(ForcedScheduleError::TaskUnavailable {
                index,
                task: task.into(),
            });
        }
        let actual_worker =
            self.assignment_for(task)
                .ok_or(ForcedScheduleError::TaskUnavailable {
                    index,
                    task: task.into(),
                })?;

        let queue_lane = if expected_lane == DispatchLane::Stolen {
            if expected_worker == actual_worker {
                return Err(ForcedScheduleError::LaneMismatch {
                    index,
                    expected: DispatchLane::Stolen,
                    actual: DispatchLane::Ready,
                });
            }
            DispatchLane::Ready
        } else {
            if expected_worker != actual_worker {
                return Err(ForcedScheduleError::WorkerMismatch {
                    index,
                    expected: u32::try_from(expected_worker).unwrap_or(u32::MAX),
                    actual: u32::try_from(actual_worker).unwrap_or(u32::MAX),
                });
            }
            expected_lane
        };

        match self.workers[actual_worker].take_exact(task, queue_lane, now) {
            Ok(()) => {}
            Err(ExactDispatchError::NotScheduled) => {
                return Err(ForcedScheduleError::TaskUnavailable {
                    index,
                    task: task.into(),
                });
            }
            Err(ExactDispatchError::TimedNotDue { deadline }) => {
                return Err(ForcedScheduleError::TimedNotDue {
                    index,
                    deadline: deadline.as_nanos(),
                    now: now.as_nanos(),
                });
            }
            Err(ExactDispatchError::LaneMismatch { actual }) => {
                return Err(ForcedScheduleError::LaneMismatch {
                    index,
                    expected: expected_lane,
                    actual,
                });
            }
            Err(ExactDispatchError::QueueInvariant) => {
                return Err(ForcedScheduleError::QueueInvariant { index });
            }
        }

        let removed = self.scheduled.remove(&task);
        debug_assert!(removed, "forced task was checked in lab scheduled set");
        if expected_lane == DispatchLane::Stolen {
            self.set_assignment(task, expected_worker);
            self.cancel_streak[expected_worker] = 0;
        } else if expected_lane == DispatchLane::Cancel {
            let cancel_streak = &mut self.cancel_streak[actual_worker];
            *cancel_streak = if *cancel_streak < self.cancel_streak_limit {
                (*cancel_streak).saturating_add(1)
            } else {
                1
            };
        } else {
            self.cancel_streak[actual_worker] = 0;
        }
        self.rearm_spurious_wake(task);
        Ok(())
    }

    fn forget_task(&mut self, task: TaskId) {
        self.scheduled.remove(&task);
        self.pending_spurious_wakes.remove(&task);
        // GH#55: only clear the slot when the recorded assignment belongs to
        // this generation. `scheduled` and the worker lanes are keyed by the
        // full `TaskId`, so clearing on slot alone would drop the routing of a
        // still-live task that merely reuses the arena slot.
        if self.assignment_for(task).is_some() {
            let slot = task.arena_index().index() as usize;
            self.assignments[slot] = None;
        }
        for worker in &mut self.workers {
            worker.remove(task);
        }
    }

    fn rearm_spurious_wake(&mut self, task: TaskId) {
        let Some(mut pending) = self.pending_spurious_wakes.remove(&task) else {
            return;
        };

        self.schedule(task, pending.priority);
        pending.remaining = pending.remaining.saturating_sub(1);
        if pending.remaining > 0 {
            self.pending_spurious_wakes.insert(task, pending);
        }
    }
}

struct TaskWaker {
    task_id: crate::types::TaskId,
    priority: u8,
    scheduler: Arc<Mutex<LabScheduler>>,
}

use std::task::Wake;
impl Wake for TaskWaker {
    fn wake(self: Arc<Self>) {
        self.scheduler.lock().schedule(self.task_id, self.priority);
    }
}

/// Waker that reschedules a task into the cancel lane.
///
/// Set as `cancel_waker` on each task's `CxInner` before polling so that
/// `abort_with_reason` can wake cancelled tasks.
struct CancelTaskWaker {
    task_id: crate::types::TaskId,
    priority: u8,
    scheduler: Arc<Mutex<LabScheduler>>,
}

impl Wake for CancelTaskWaker {
    fn wake(self: Arc<Self>) {
        self.scheduler
            .lock()
            .schedule_cancel(self.task_id, self.priority);
    }
}

/// An invariant violation detected by the lab runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvariantViolation {
    /// Obligations were not resolved.
    ObligationLeak {
        /// Leaked obligations and diagnostic metadata.
        leaks: Vec<ObligationLeak>,
    },
    /// Tasks were not drained.
    TaskLeak {
        /// Number of leaked tasks.
        count: usize,
    },
    /// Actors were not stopped before region close.
    ActorLeak {
        /// Number of leaked actors.
        count: usize,
    },
    /// A region closed with live children.
    QuiescenceViolation,
    /// A task held obligations but stopped being polled (futurelock).
    Futurelock {
        /// The task that futurelocked.
        task: crate::types::TaskId,
        /// The owning region.
        region: crate::types::RegionId,
        /// How many lab steps since last poll.
        idle_steps: u64,
        /// Held obligations.
        held: Vec<ObligationId>,
        /// Last checkpoint message recorded by the task, when available.
        last_checkpoint_message: Option<String>,
    },
    /// Cancellation protocol violation detected.
    CancellationProtocol {
        /// The violation description.
        violation: String,
    },
    /// br-asupersync-ipejce: a fuzz / scenario test closure panicked.
    /// Recorded so the campaign can keep searching instead of
    /// aborting on the first finding (the most interesting outcome
    /// of any fuzz campaign).
    TestPanic {
        /// Stringified panic payload (extracted via `Any::downcast`
        /// of `&str` and `String` — falls back to `<unknown panic>`).
        message: String,
    },
}

/// Diagnostic details for a leaked obligation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObligationLeak {
    /// The leaked obligation id.
    pub obligation: ObligationId,
    /// Kind of obligation (permit/ack/lease/io).
    pub kind: ObligationKind,
    /// Task that held the obligation.
    pub holder: crate::types::TaskId,
    /// Region that owned the obligation.
    pub region: crate::types::RegionId,
}

impl std::fmt::Display for ObligationLeak {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "obligation={:?} kind={:?} holder={:?} region={:?}",
            self.obligation, self.kind, self.holder, self.region
        )
    }
}

fn format_futurelock_checkpoint(message: Option<&str>) -> String {
    match message {
        Some(message) => format!("{message:?}"),
        None => "<none>".to_string(),
    }
}

impl std::fmt::Display for InvariantViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ObligationLeak { leaks } => {
                write!(f, "[ASUP-E101] obligation leak: count={}", leaks.len())?;
                if !leaks.is_empty() {
                    write!(f, " leaks=[")?;
                    for (index, leak) in leaks.iter().enumerate() {
                        if index > 0 {
                            write!(f, "; ")?;
                        }
                        write!(f, "{leak}")?;
                    }
                    write!(f, "]")?;
                }
                Ok(())
            }
            Self::TaskLeak { count } => write!(f, "{count} tasks leaked"),
            Self::ActorLeak { count } => write!(f, "{count} actors leaked"),
            Self::QuiescenceViolation => write!(f, "region closed without quiescence"),
            Self::Futurelock {
                task,
                region,
                idle_steps,
                held,
                last_checkpoint_message,
            } => write!(
                f,
                "[ASUP-E402] futurelock: {task} in {region} idle={idle_steps} held={held:?} last_checkpoint={}",
                format_futurelock_checkpoint(last_checkpoint_message.as_deref())
            ),
            Self::CancellationProtocol { violation } => {
                write!(f, "cancellation protocol violation: {violation}")
            }
            Self::TestPanic { message } => write!(f, "test panic: {message}"),
        }
    }
}

/// Convenience function for running a test with the lab runtime.
pub fn test<F, R>(seed: u64, f: F) -> R
where
    F: FnOnce(&mut LabRuntime) -> R,
{
    let mut runtime = LabRuntime::with_seed(seed);
    let result = f(&mut runtime);

    // Check invariants
    let violations = runtime.check_invariants();
    assert!(
        violations.is_empty(),
        "Lab runtime invariant violations: {violations:?}"
    );

    result
}

/// The reason a closing owned child region's remaining tasks are cancelled
/// with: the lab's virtual close time, never earlier than
/// `CancelReason::user`'s own stamp (see the native scheduler's
/// `owned_region_close_reason`; br-asupersync-pz66t0).
fn owned_region_close_reason(now: Time) -> crate::types::CancelReason {
    let reason = crate::types::CancelReason::user("owned child region body finished");
    if now > reason.timestamp {
        reason.with_timestamp(now)
    } else {
        reason
    }
}

#[cfg(test)]
#[path = "runtime_inline_tests.rs"]
mod tests;
