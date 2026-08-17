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
use crate::trace::replay::{CompactTaskId, ReplayEvent, ReplayTrace, TraceMetadata};
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
    /// quiescent) for 1 000 consecutive iterations and bailed out.
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

/// The deterministic lab runtime.
///
/// This runtime is designed for testing and provides:
/// - Virtual time instead of wall-clock time
/// - Deterministic scheduling based on a seed
/// - Trace capture for debugging and replay
/// - Chaos injection for stress testing
#[derive(Debug)]
pub struct LabRuntime {
    /// Runtime state (public for tests and oracle access).
    pub state: RuntimeState,
    /// Lab reactor for deterministic I/O simulation.
    lab_reactor: Arc<LabReactor>,
    /// Deterministic spawn intake (br-asupersync-4h8lye / A2.1): requests
    /// enqueued here are admitted in FIFO order at the top of each step.
    spawn_mailbox: Arc<crate::runtime::spawn_mailbox::SpawnMailbox>,
    /// Keeps the lab spawn gateway live while the lab runtime is alive.
    _spawn_liveness: Arc<()>,
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
        state.set_spawn_gateway(Arc::new(crate::runtime::spawn_mailbox::SpawnGateway::new(
            Arc::clone(&spawn_mailbox),
            Arc::new(|| {}),
            state.timer_driver_handle(),
            Arc::downgrade(&spawn_liveness),
        )));
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
            state,
            lab_reactor,
            spawn_mailbox,
            _spawn_liveness: spawn_liveness,
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

    fn has_pending_dispatch_commands(&self) -> bool {
        !self.spawn_mailbox.is_empty() || self.state.has_deferred_cancel_dispatches()
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
        self.state.is_quiescent() && self.spawn_mailbox.is_empty()
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
    /// Returns the number of steps executed.
    pub fn run_until_quiescent(&mut self) -> u64 {
        let start_steps = self.steps;

        while !self.is_quiescent() {
            if let Some(max) = self.config.max_steps {
                if self.steps >= max {
                    break;
                }
            }
            self.step();
        }

        self.steps - start_steps
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
        let oracle_report = self.oracles.report(now);
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
                crate::runtime::state::SpawnAdmission::Denied { parts, error } => match error {
                    crate::runtime::state::SpawnError::RegionClosed(_)
                    | crate::runtime::state::SpawnError::RegionNotFound(_) => {
                        parts.resolve_cancelled(crate::types::CancelReason::new(
                            crate::types::CancelKind::ParentCancelled,
                        ));
                    }
                    other => parts.resolve_failed(other),
                },
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
        // Admission publication can invoke a retained cancellation Waker.
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
                    if let Some((tid, lane)) = sched.pop_for_worker(worker_hint, rng_value, now) {
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
            stored.poll(&mut cx)
        } else {
            // Task lost (should not happen if consistent)
            return Ok(true);
        };

        // Record the poll so futurelock detection uses the correct idle step count.
        let _ = self.state.update_task(task_id, |record| {
            record.mark_polled(self.steps);
        });

        let (cancel_ack, cancel_wakes) = self.consume_cancel_ack(task_id).into_parts();

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
        if threshold == 0 {
            return Vec::new();
        }

        let current_step = self.steps;
        let mut violations = Vec::new();

        for (_, task) in self.state.tasks_iter() {
            if task.state.is_terminal() {
                continue;
            }

            let mut held = Vec::new();
            for (_, obligation) in self.state.obligations_iter() {
                if obligation.is_pending() && obligation.holder == task.id {
                    held.push(obligation.id);
                }
            }

            if held.is_empty() {
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

        let worker = self.assign_worker(task);
        self.workers[worker].schedule_timed(task, deadline);
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
    use crate::lab::chaos::ChaosConfig;
    use crate::record::TaskRecord;
    use crate::record::{ObligationAbortReason, ObligationKind};
    use crate::runtime::deadline_monitor::{AdaptiveDeadlineConfig, WarningReason};
    #[cfg(unix)]
    use crate::runtime::reactor::Interest;
    use crate::runtime::reactor::{Event, Token};
    use crate::types::{Budget, CancelKind, CancelReason, CxInner, Outcome, TaskId};
    use crate::util::ArenaIndex;
    use parking_lot::Mutex;
    use parking_lot::RwLock;
    use std::sync::Arc;
    use std::task::Waker;
    use std::time::Duration;

    #[cfg(unix)]
    struct TestFdSource;
    #[cfg(unix)]
    impl std::os::fd::AsRawFd for TestFdSource {
        fn as_raw_fd(&self) -> std::os::fd::RawFd {
            0
        }
    }

    #[cfg(unix)]
    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    /// Waker that sets an `AtomicBool` when woken (for virtual time tests).
    struct FlagWaker(Arc<std::sync::atomic::AtomicBool>);
    impl Wake for FlagWaker {
        fn wake(self: Arc<Self>) {
            self.0.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    /// Waker that increments an `AtomicU64` counter when woken.
    struct CountWaker(Arc<std::sync::atomic::AtomicU64>);
    impl Wake for CountWaker {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    struct HandleCancelWakeAudit {
        task_id: TaskId,
        caller_lock: Arc<Mutex<()>>,
        scheduler: Arc<Mutex<LabScheduler>>,
        wake_calls: Arc<std::sync::atomic::AtomicUsize>,
        calls_under_caller_lock: Arc<std::sync::atomic::AtomicUsize>,
        calls_under_scheduler_lock: Arc<std::sync::atomic::AtomicUsize>,
        cancel_lane_published: Arc<std::sync::atomic::AtomicBool>,
    }

    impl std::task::Wake for HandleCancelWakeAudit {
        fn wake(self: Arc<Self>) {
            use std::sync::atomic::Ordering;

            self.wake_calls.fetch_add(1, Ordering::SeqCst);
            let caller_guard = self.caller_lock.try_lock();
            if caller_guard.is_none() {
                self.calls_under_caller_lock.fetch_add(1, Ordering::SeqCst);
            }
            drop(caller_guard);

            if let Some(scheduler) = self.scheduler.try_lock() {
                let mut scheduler = scheduler;
                let observed = scheduler.pop_for_worker(0, 0, Time::ZERO);
                self.cancel_lane_published.store(
                    matches!(observed, Some((task, DispatchLane::Cancel)) if task == self.task_id),
                    Ordering::SeqCst,
                );
                if observed.is_some() {
                    scheduler.schedule_cancel(self.task_id, u8::MAX);
                }
            } else {
                self.calls_under_scheduler_lock
                    .fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    fn exercise_managed_handle_cancel_boundary(via_join_drop: bool) {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

        let mut runtime = LabRuntime::new(LabConfig::new(7));
        let root = runtime.state.create_root_region(Budget::INFINITE);
        let (task_id, mut handle) = runtime
            .state
            .create_task(root, Budget::INFINITE, async {
                std::future::poll_fn(|_| {
                    if crate::cx::Cx::with_current(|cx| cx.checkpoint().is_err()).unwrap_or(false) {
                        Poll::Ready(())
                    } else {
                        Poll::Pending
                    }
                })
                .await;
            })
            .expect("create managed task");
        let inner = runtime
            .state
            .task(task_id)
            .and_then(|task| task.cx_inner.clone())
            .expect("managed task has a Cx");

        runtime.scheduler.lock().schedule(task_id, 0);
        runtime.step_for_test();
        assert!(runtime.scheduler.lock().is_empty());

        let caller_lock = Arc::new(Mutex::new(()));
        let wake_calls = Arc::new(AtomicUsize::new(0));
        let calls_under_caller_lock = Arc::new(AtomicUsize::new(0));
        let calls_under_scheduler_lock = Arc::new(AtomicUsize::new(0));
        let cancel_lane_published = Arc::new(AtomicBool::new(false));
        let audit_waker = Waker::from(Arc::new(HandleCancelWakeAudit {
            task_id,
            caller_lock: Arc::clone(&caller_lock),
            scheduler: Arc::clone(&runtime.scheduler),
            wake_calls: Arc::clone(&wake_calls),
            calls_under_caller_lock: Arc::clone(&calls_under_caller_lock),
            calls_under_scheduler_lock: Arc::clone(&calls_under_scheduler_lock),
            cancel_lane_published: Arc::clone(&cancel_lane_published),
        }));
        let retired_waker = {
            let mut guard = inner.write();
            guard
                .cancel_waker
                .replace(Arc::new(crate::types::task_context::CancelWaker::new(
                    audit_waker,
                )))
        };
        drop(retired_waker);

        let join_cx = crate::cx::Cx::for_testing();
        if via_join_drop {
            let join = handle.join_with_drop_reason(&join_cx, CancelReason::timeout());
            let caller_guard = caller_lock.lock();
            drop(join);
            assert_eq!(
                wake_calls.load(Ordering::SeqCst),
                0,
                "JoinFuture::drop must not invoke a cancellation Waker inline"
            );
            drop(caller_guard);
        } else {
            let caller_guard = caller_lock.lock();
            handle.abort_with_reason(CancelReason::timeout());
            handle.abort_with_reason(CancelReason::timeout());
            assert_eq!(
                wake_calls.load(Ordering::SeqCst),
                0,
                "TaskHandle::abort must not invoke a cancellation Waker inline"
            );
            drop(caller_guard);
        }

        {
            let guard = inner.read();
            assert!(
                guard.cancel_requested,
                "managed handle cancellation is checkpoint-visible immediately"
            );
            assert_eq!(
                guard.cancel_reason.as_ref().map(|reason| reason.kind),
                Some(CancelKind::Timeout)
            );
        }
        assert_eq!(runtime.spawn_mailbox.len(), 1, "identical aborts coalesce");
        assert!(runtime.scheduler.lock().is_empty());

        assert_eq!(runtime.run_until_quiescent(), 1);
        assert_eq!(wake_calls.load(Ordering::SeqCst), 1);
        assert_eq!(calls_under_caller_lock.load(Ordering::SeqCst), 0);
        assert_eq!(calls_under_scheduler_lock.load(Ordering::SeqCst), 0);
        assert!(cancel_lane_published.load(Ordering::SeqCst));
        assert!(runtime.spawn_mailbox.handle_cancels_are_empty());
        assert!(handle.is_finished());
        assert!(runtime.state.task(task_id).is_none());
        assert!(matches!(
            runtime.state.region_close_outcome(root),
            Some(Outcome::Cancelled(reason)) if reason.is_kind(CancelKind::Timeout)
        ));
        assert!(runtime.is_quiescent());
    }

    #[test]
    fn managed_task_handle_abort_defers_waker_until_cancel_lane_publication() {
        init_test("managed_task_handle_abort_defers_waker_until_cancel_lane_publication");
        exercise_managed_handle_cancel_boundary(false);
        crate::test_complete!(
            "managed_task_handle_abort_defers_waker_until_cancel_lane_publication"
        );
    }

    #[test]
    fn managed_join_future_drop_defers_waker_until_cancel_lane_publication() {
        init_test("managed_join_future_drop_defers_waker_until_cancel_lane_publication");
        exercise_managed_handle_cancel_boundary(true);
        crate::test_complete!(
            "managed_join_future_drop_defers_waker_until_cancel_lane_publication"
        );
    }

    #[test]
    fn checkpoint_ack_ready_before_handle_command_reconciles_terminal_cancel() {
        use std::sync::Barrier;
        use std::sync::atomic::{AtomicU64, Ordering};

        init_test("checkpoint_ack_ready_before_handle_command_reconciles_terminal_cancel");
        let mut runtime = LabRuntime::new(LabConfig::new(19));
        let root = runtime.state.create_root_region(Budget::INFINITE);
        let entered = Arc::new(Barrier::new(2));
        let abort_done = Arc::new(Barrier::new(2));
        let auxiliary_calls = Arc::new(AtomicU64::new(0));
        let auxiliary_waker = Waker::from(Arc::new(CountWaker(Arc::clone(&auxiliary_calls))));

        let task_entered = Arc::clone(&entered);
        let task_abort_done = Arc::clone(&abort_done);
        let (task_id, handle) = runtime
            .state
            .create_task(root, Budget::INFINITE, async move {
                std::future::poll_fn(move |_| {
                    crate::cx::Cx::with_current(|cx| {
                        cx.register_cancel_waker(&auxiliary_waker);
                    })
                    .expect("task Cx is installed");
                    task_entered.wait();
                    task_abort_done.wait();
                    assert!(
                        crate::cx::Cx::with_current(|cx| cx.checkpoint().is_err()).unwrap_or(false),
                        "same-poll checkpoint observes the queued handle abort"
                    );
                    Poll::Ready(())
                })
                .await;
            })
            .expect("create managed task");
        runtime.scheduler.lock().schedule(task_id, 0);

        let canceller = std::thread::spawn(move || {
            let handle = handle;
            entered.wait();
            handle.abort_with_reason(CancelReason::race_loser());
            abort_done.wait();
            handle
        });

        runtime.step_for_test();
        let mut handle = canceller.join().expect("abort thread completes");
        assert!(
            !runtime.spawn_mailbox.handle_cancels_are_empty(),
            "command remains queued until the next runtime boundary"
        );
        assert!(runtime.state.task(task_id).is_none());
        assert!(matches!(
            runtime.state.region_close_outcome(root),
            Some(Outcome::Cancelled(reason)) if reason.is_kind(CancelKind::RaceLost)
        ));
        assert_eq!(
            auxiliary_calls.load(Ordering::SeqCst),
            1,
            "auxiliary cancellation Waker runs once after terminal publication"
        );
        assert!(handle.is_finished());
        assert!(
            !matches!(handle.try_join(), Ok(None)),
            "join result is available regardless of path-specific payload semantics"
        );

        runtime.step_for_test();
        assert!(runtime.spawn_mailbox.handle_cancels_are_empty());
        assert!(runtime.state.task(task_id).is_none());
        assert!(matches!(
            runtime.state.region_close_outcome(root),
            Some(Outcome::Cancelled(reason)) if reason.is_kind(CancelKind::RaceLost)
        ));
        assert_eq!(auxiliary_calls.load(Ordering::SeqCst), 1);
        assert!(runtime.check_invariants().is_empty());
        crate::test_complete!(
            "checkpoint_ack_ready_before_handle_command_reconciles_terminal_cancel"
        );
    }

    #[test]
    fn checkpoint_ack_pending_republishes_cancel_lane_before_waker_dispatch() {
        use std::sync::Barrier;
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

        init_test("checkpoint_ack_pending_republishes_cancel_lane_before_waker_dispatch");
        let mut runtime = LabRuntime::new(LabConfig::new(23));
        let root = runtime.state.create_root_region(Budget::INFINITE);
        let entered = Arc::new(Barrier::new(2));
        let abort_done = Arc::new(Barrier::new(2));
        let polls = Arc::new(AtomicUsize::new(0));
        let audit_target = Arc::new(Mutex::new(None));
        let caller_lock = Arc::new(Mutex::new(()));
        let wake_calls = Arc::new(AtomicUsize::new(0));
        let calls_under_caller_lock = Arc::new(AtomicUsize::new(0));
        let calls_under_scheduler_lock = Arc::new(AtomicUsize::new(0));
        let cancel_lane_published = Arc::new(AtomicBool::new(false));

        let task_entered = Arc::clone(&entered);
        let task_abort_done = Arc::clone(&abort_done);
        let task_polls = Arc::clone(&polls);
        let task_audit_target = Arc::clone(&audit_target);
        let (task_id, handle) = runtime
            .state
            .create_task(root, Budget::INFINITE, async move {
                std::future::poll_fn(move |_| {
                    let poll = task_polls.fetch_add(1, Ordering::SeqCst);
                    if poll == 0 {
                        let target = task_audit_target
                            .lock()
                            .as_ref()
                            .cloned()
                            .expect("audit Waker installed before first poll");
                        let retired = crate::cx::Cx::with_current(|cx| {
                            cx.inner.write().cancel_waker.replace(target)
                        })
                        .expect("task Cx is installed");
                        drop(retired);
                        task_entered.wait();
                        task_abort_done.wait();
                    }
                    assert!(
                        crate::cx::Cx::with_current(|cx| cx.checkpoint().is_err()).unwrap_or(false),
                        "checkpoint observes cancellation on every cleanup poll"
                    );
                    if poll == 0 {
                        Poll::Pending
                    } else {
                        Poll::Ready(())
                    }
                })
                .await;
            })
            .expect("create managed task");
        *audit_target.lock() = Some(Arc::new(crate::types::task_context::CancelWaker::new(
            Waker::from(Arc::new(HandleCancelWakeAudit {
                task_id,
                caller_lock: Arc::clone(&caller_lock),
                scheduler: Arc::clone(&runtime.scheduler),
                wake_calls: Arc::clone(&wake_calls),
                calls_under_caller_lock: Arc::clone(&calls_under_caller_lock),
                calls_under_scheduler_lock: Arc::clone(&calls_under_scheduler_lock),
                cancel_lane_published: Arc::clone(&cancel_lane_published),
            })),
        )));
        runtime.scheduler.lock().schedule(task_id, 0);

        let canceller = std::thread::spawn(move || {
            let handle = handle;
            entered.wait();
            handle.abort_with_reason(CancelReason::shutdown());
            abort_done.wait();
            handle
        });

        runtime.step_for_test();
        let handle = canceller.join().expect("abort thread completes");
        assert!(matches!(
            &runtime.state.task(task_id).expect("task record").state,
            TaskState::Cancelling { reason, .. } if reason.is_kind(CancelKind::Shutdown)
        ));
        assert!(
            !runtime.scheduler.lock().is_empty(),
            "acknowledged Pending task is republished on the cancel lane"
        );
        assert_eq!(
            wake_calls.load(Ordering::SeqCst),
            1,
            "first reconciliation dispatches the audit Waker once"
        );
        assert_eq!(calls_under_caller_lock.load(Ordering::SeqCst), 0);
        assert_eq!(calls_under_scheduler_lock.load(Ordering::SeqCst), 0);
        assert!(
            cancel_lane_published.load(Ordering::SeqCst),
            "the first Waker callback must observe an already-published cancel lane"
        );

        runtime.step_for_test();
        assert_eq!(polls.load(Ordering::SeqCst), 2);
        assert!(runtime.state.task(task_id).is_none());
        assert!(matches!(
            runtime.state.region_close_outcome(root),
            Some(Outcome::Cancelled(reason)) if reason.is_kind(CancelKind::Shutdown)
        ));
        assert_eq!(
            wake_calls.load(Ordering::SeqCst),
            1,
            "repeated acknowledged checkpoints do not duplicate Waker dispatch"
        );
        assert!(handle.is_finished());
        assert!(runtime.spawn_mailbox.handle_cancels_are_empty());
        assert!(runtime.check_invariants().is_empty());
        crate::test_complete!(
            "checkpoint_ack_pending_republishes_cancel_lane_before_waker_dispatch"
        );
    }

    #[test]
    fn handle_cancel_command_blocks_lab_quiescence_until_drained() {
        init_test("handle_cancel_command_blocks_lab_quiescence_until_drained");
        let mut runtime = LabRuntime::new(LabConfig::new(11));
        assert!(runtime.is_quiescent());

        let missing = TaskId::from_arena(ArenaIndex::new(usize::MAX as u32, 0));
        let gateway = runtime.state.spawn_gateway().expect("lab gateway");
        assert!(gateway.enqueue_handle_cancel(missing, CancelReason::shutdown()));
        assert!(
            !runtime.is_quiescent(),
            "a queued command is live runtime work even when its task is stale"
        );

        assert_eq!(runtime.run_until_quiescent(), 1);
        assert!(runtime.spawn_mailbox.handle_cancels_are_empty());
        assert!(runtime.is_quiescent());
        crate::test_complete!("handle_cancel_command_blocks_lab_quiescence_until_drained");
    }

    #[test]
    fn managed_pre_admission_abort_transitions_task_record_before_first_poll() {
        init_test("managed_pre_admission_abort_transitions_task_record_before_first_poll");
        let mut runtime = LabRuntime::new(LabConfig::new(13));
        let root = runtime.state.create_root_region(Budget::INFINITE);
        let pending = runtime
            .state
            .region(root)
            .expect("root region")
            .pending_spawn_handle();
        let parent: crate::cx::Cx = crate::cx::Cx::new(
            root,
            TaskId::from_arena(ArenaIndex::new(u32::MAX - 1, 0)),
            Budget::INFINITE,
        )
        .with_spawn_gateway(runtime.state.spawn_gateway())
        .with_pending_spawn_counter(Some(pending));

        let mut handle = parent
            .spawn(|child| async move {
                std::future::poll_fn(move |_| {
                    if child.checkpoint().is_err() {
                        Poll::Ready(())
                    } else {
                        Poll::Pending
                    }
                })
                .await;
            })
            .expect("managed spawn enqueues");
        let provisional = handle.task_id();
        handle.abort_with_reason(CancelReason::race_loser());
        assert!(
            runtime.spawn_mailbox.handle_cancels_are_empty(),
            "pre-admission abort remains cache-only until identity publication"
        );

        assert_eq!(runtime.run_until_quiescent(), 1);
        let canonical = handle.task_id();
        assert_ne!(canonical, provisional);
        assert!(
            runtime.state.task(canonical).is_none(),
            "quiescent completion retires the canonical task record"
        );
        assert!(handle.is_finished());
        assert!(runtime.spawn_mailbox.is_empty());
        assert!(runtime.is_quiescent());
        assert!(matches!(
            handle.try_join(),
            Err(crate::runtime::JoinError::Cancelled(reason))
                if reason.is_kind(CancelKind::RaceLost)
        ));
        crate::test_complete!(
            "managed_pre_admission_abort_transitions_task_record_before_first_poll"
        );
    }

    #[test]
    fn stale_handle_cancel_command_cannot_weaken_newer_cx_reason() {
        init_test("stale_handle_cancel_command_cannot_weaken_newer_cx_reason");
        let mut runtime = LabRuntime::new(LabConfig::new(17));
        let root = runtime.state.create_root_region(Budget::INFINITE);
        let (task_id, handle) = runtime
            .state
            .create_task(root, Budget::INFINITE, async {
                std::future::pending::<()>().await;
            })
            .expect("create managed task");
        let inner = runtime
            .state
            .task(task_id)
            .and_then(|task| task.cx_inner.clone())
            .expect("managed task Cx");

        handle.abort_with_reason(CancelReason::user("stale"));
        let mut stale = Vec::new();
        assert_eq!(
            runtime
                .spawn_mailbox
                .dequeue_handle_cancels_into(1, &mut stale),
            1
        );
        handle.abort_with_reason(CancelReason::shutdown());
        let stale = stale.pop().expect("saved stale command");

        let (route, wakes) = runtime
            .state
            .cancel_task_for_handle(stale.task_id, &stale.reason)
            .into_parts();
        assert_eq!(route.map(|route| route.priority), Some(u8::MAX));
        assert!(route.is_some_and(|route| !route.delegated_initial));
        assert!(wakes.is_empty());
        wakes.dispatch();
        assert!(
            runtime
                .state
                .task(task_id)
                .and_then(TaskRecord::cancel_reason)
                .is_some_and(|reason| reason.is_kind(CancelKind::Shutdown))
        );
        assert!(
            inner
                .read()
                .cancel_reason
                .as_ref()
                .is_some_and(|reason| reason.is_kind(CancelKind::Shutdown))
        );
        crate::test_complete!("stale_handle_cancel_command_cannot_weaken_newer_cx_reason");
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    struct TimerAdvanceOutcome {
        advance_points: Vec<Time>,
        total_wakeups: u64,
        final_time: Time,
        cancelled_wakeups: u64,
    }

    fn collect_timer_advances(
        deadlines_secs: &[u64],
        cancelled_indices: &[usize],
    ) -> TimerAdvanceOutcome {
        let mut runtime = LabRuntime::with_seed(42);
        let timer_handle = runtime.state.timer_driver_handle().expect("timer handle");
        let live_wakeups = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let cancelled_wakeups = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let mut handles = Vec::with_capacity(deadlines_secs.len());

        for (idx, secs) in deadlines_secs.iter().copied().enumerate() {
            let counter = if cancelled_indices.contains(&idx) {
                cancelled_wakeups.clone()
            } else {
                live_wakeups.clone()
            };
            let waker = Waker::from(Arc::new(CountWaker(counter)));
            handles.push(timer_handle.register(Time::from_secs(secs), waker));
        }

        for &idx in cancelled_indices {
            let cancelled = timer_handle.cancel(&handles[idx]);
            crate::assert_with_log!(
                cancelled,
                "cancelled timer handle remains removable before auto-advance",
                true,
                cancelled
            );
        }

        let mut advance_points = Vec::new();
        while runtime.pending_timer_count() > 0 {
            let before = runtime.now();
            let next_deadline = runtime.next_timer_deadline().expect("pending deadline");
            let wakeups = runtime.advance_to_next_timer();
            let after = runtime.now();

            crate::assert_with_log!(
                after >= before,
                "virtual time stays monotone while advancing timers",
                true,
                after >= before
            );
            crate::assert_with_log!(
                after >= next_deadline,
                "advance reaches or passes scheduled deadline",
                true,
                after >= next_deadline
            );
            crate::assert_with_log!(
                wakeups > 0,
                "each advance drains at least one live timer",
                true,
                wakeups > 0
            );

            advance_points.push(after);
        }

        TimerAdvanceOutcome {
            advance_points,
            total_wakeups: live_wakeups.load(std::sync::atomic::Ordering::SeqCst),
            final_time: runtime.now(),
            cancelled_wakeups: cancelled_wakeups.load(std::sync::atomic::Ordering::SeqCst),
        }
    }

    #[asupersync::lab_test(seeds = 42..43)]
    fn empty_runtime_is_quiescent(runtime: &mut LabRuntime) {
        let quiescent = runtime.is_quiescent();
        crate::assert_with_log!(quiescent, "quiescent", true, quiescent);
    }

    #[asupersync::lab_test(seeds = 42..43)]
    fn advance_time(runtime: &mut LabRuntime) {
        let now = runtime.now();
        crate::assert_with_log!(now == Time::ZERO, "now", Time::ZERO, now);

        runtime.advance_time(1_000_000);
        let now = runtime.now();
        crate::assert_with_log!(
            now == Time::from_millis(1),
            "now",
            Time::from_millis(1),
            now
        );
    }

    #[test]
    fn duration_nanos_saturating_clamps_large_duration() {
        init_test("duration_nanos_saturating_clamps_large_duration");
        let huge = Duration::from_secs(u64::MAX);
        let saturated = LabRuntime::duration_nanos_saturating(huge);
        crate::assert_with_log!(
            saturated == u64::MAX,
            "huge duration saturates",
            u64::MAX,
            saturated
        );

        let small = Duration::from_nanos(123);
        let exact = LabRuntime::duration_nanos_saturating(small);
        crate::assert_with_log!(exact == 123, "small duration exact", 123u64, exact);
        crate::test_complete!("duration_nanos_saturating_clamps_large_duration");
    }

    #[cfg(unix)]
    #[test]
    fn lab_runtime_records_io_ready_trace() {
        init_test("lab_runtime_records_io_ready_trace");

        let mut runtime = LabRuntime::with_seed(42);
        let handle = runtime.state.io_driver_handle().expect("io driver");
        let waker = noop_waker();
        let source = TestFdSource;

        let registration = handle
            .register(&source, Interest::READABLE, waker)
            .expect("register source");
        let token = registration.token();

        runtime
            .lab_reactor()
            .inject_event(token, Event::readable(token), Duration::from_millis(1));
        runtime.advance_time(1_000_000);
        runtime.step_for_test();

        let mut saw_requested = false;
        let mut saw_ready = false;
        for event in runtime.state.trace.snapshot() {
            if event.kind == TraceEventKind::IoRequested {
                saw_requested = true;
            }
            if event.kind == TraceEventKind::IoReady {
                saw_ready = true;
            }
        }
        crate::assert_with_log!(
            saw_requested,
            "io requested trace recorded",
            true,
            saw_requested
        );
        crate::assert_with_log!(saw_ready, "io ready trace recorded", true, saw_ready);
        crate::test_complete!("lab_runtime_records_io_ready_trace");
    }

    #[cfg(unix)]
    #[test]
    fn lab_runtime_chaos_stats_include_reactor_io_error_injections() {
        init_test("lab_runtime_chaos_stats_include_reactor_io_error_injections");

        let config = LabConfig::new(7).with_chaos(
            ChaosConfig::new(7)
                .with_io_error_probability(1.0)
                .with_io_error_kinds(vec![std::io::ErrorKind::TimedOut]),
        );
        let mut runtime = LabRuntime::new(config);
        let handle = runtime.state.io_driver_handle().expect("io driver");
        let waker = noop_waker();
        let source = TestFdSource;

        let registration = handle
            .register(&source, Interest::READABLE, waker)
            .expect("register source");
        let token = registration.token();

        runtime
            .lab_reactor()
            .inject_event(token, Event::readable(token), Duration::ZERO);
        runtime.step_for_test();

        let stats = runtime.chaos_stats();
        crate::assert_with_log!(
            stats.io_errors == 1,
            "io errors aggregated",
            1u64,
            stats.io_errors
        );
        crate::assert_with_log!(
            stats.decision_points == 1,
            "reactor decision points aggregated",
            1u64,
            stats.decision_points
        );
        crate::assert_with_log!(
            runtime.lab_reactor().last_io_error_kind() == Some(std::io::ErrorKind::TimedOut),
            "reactor last error kind surfaced",
            Some(std::io::ErrorKind::TimedOut),
            runtime.lab_reactor().last_io_error_kind()
        );

        crate::test_complete!("lab_runtime_chaos_stats_include_reactor_io_error_injections");
    }

    #[test]
    fn pending_task_without_wakeup_storm_still_counts_chaos_decision_point() {
        init_test("pending_task_without_wakeup_storm_still_counts_chaos_decision_point");

        let config =
            LabConfig::new(99).with_chaos(ChaosConfig::new(99).with_wakeup_storm_probability(0.0));
        let mut runtime = LabRuntime::new(config);
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let (task_id, _handle) = runtime
            .state
            .create_task(region, Budget::INFINITE, async {
                std::future::pending::<()>().await;
            })
            .expect("create task");
        runtime.scheduler.lock().schedule(task_id, 0);

        runtime.step_for_test();

        let stats = runtime.chaos_stats();
        crate::assert_with_log!(
            stats.decision_points == 2,
            "pending-task decision point counted",
            2u64,
            stats.decision_points
        );
        crate::assert_with_log!(
            stats.wakeup_storms == 0,
            "no wakeup storm recorded",
            0u64,
            stats.wakeup_storms
        );

        crate::test_complete!(
            "pending_task_without_wakeup_storm_still_counts_chaos_decision_point"
        );
    }

    #[test]
    fn pre_poll_multi_injection_counts_one_chaos_decision_point() {
        init_test("pre_poll_multi_injection_counts_one_chaos_decision_point");

        let config = LabConfig::new(123).with_chaos(
            ChaosConfig::new(123)
                .with_cancel_probability(1.0)
                .with_delay_probability(1.0)
                .with_delay_range(Duration::ZERO..Duration::from_nanos(2))
                .with_budget_exhaust_probability(1.0),
        );
        let mut runtime = LabRuntime::new(config);
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let (task_id, _handle) = runtime
            .state
            .create_task(region, Budget::INFINITE, async {
                std::future::pending::<()>().await;
            })
            .expect("create task");
        runtime.scheduler.lock().schedule(task_id, 0);

        runtime.step_for_test();

        let stats = runtime.chaos_stats();
        crate::assert_with_log!(
            stats.decision_points == 1,
            "multi-injection pre-poll counts once",
            1u64,
            stats.decision_points
        );
        crate::assert_with_log!(
            stats.cancellations == 1,
            "cancel recorded",
            1u64,
            stats.cancellations
        );
        crate::assert_with_log!(stats.delays == 1, "delay recorded", 1u64, stats.delays);
        crate::assert_with_log!(
            stats.budget_exhaustions == 1,
            "budget exhaust recorded",
            1u64,
            stats.budget_exhaustions
        );
        crate::assert_with_log!(
            stats.total_delay == Duration::from_nanos(1),
            "positive delay preserved",
            Duration::from_nanos(1),
            stats.total_delay
        );

        crate::test_complete!("pre_poll_multi_injection_counts_one_chaos_decision_point");
    }

    #[test]
    fn deterministic_rng() {
        init_test("deterministic_rng");
        let mut r1 = LabRuntime::with_seed(42);
        let mut r2 = LabRuntime::with_seed(42);

        let a = r1.rng.next_u64();
        let b = r2.rng.next_u64();
        crate::assert_with_log!(a == b, "rng", b, a);
        crate::test_complete!("deterministic_rng");
    }

    #[test]
    fn lab_scheduler_pop_for_worker_respects_timed_deadlines() {
        init_test("lab_scheduler_pop_for_worker_respects_timed_deadlines");
        let mut scheduler = LabScheduler::new(1, 0);
        let timed = TaskId::from_arena(ArenaIndex::new(1, 0));
        let ready = TaskId::from_arena(ArenaIndex::new(2, 0));

        scheduler.schedule_timed(timed, Time::from_nanos(100));
        scheduler.schedule(ready, 10);

        let first = scheduler.pop_for_worker(0, 0, Time::ZERO);
        crate::assert_with_log!(
            first == Some((ready, DispatchLane::Ready)),
            "ready task dispatches before not-due timed task",
            Some((ready, DispatchLane::Ready)),
            first
        );

        let second = scheduler.pop_for_worker(0, 1, Time::ZERO);
        crate::assert_with_log!(
            second.is_none(),
            "future timed task stays queued before deadline",
            true,
            second.is_none()
        );

        let third = scheduler.pop_for_worker(0, 2, Time::from_nanos(100));
        crate::assert_with_log!(
            third == Some((timed, DispatchLane::Timed)),
            "timed task dispatches at deadline",
            Some((timed, DispatchLane::Timed)),
            third
        );

        crate::test_complete!("lab_scheduler_pop_for_worker_respects_timed_deadlines");
    }

    #[test]
    fn forced_cancel_dispatch_preserves_normal_fairness_state() {
        init_test("forced_cancel_dispatch_preserves_normal_fairness_state");
        let task = TaskId::from_arena(ArenaIndex::new(3, 0));
        let mut normal = LabScheduler::new(1, 0);
        let mut forced = LabScheduler::new(1, 0);

        normal.cancel_streak[0] = normal.cancel_streak_limit;
        forced.cancel_streak[0] = forced.cancel_streak_limit;
        normal.schedule_cancel(task, 10);
        forced.schedule_cancel(task, 10);

        assert_eq!(
            normal.pop_for_worker(0, 0, Time::ZERO),
            Some((task, DispatchLane::Cancel))
        );
        forced
            .take_forced(task, 0, DispatchLane::Cancel, Time::ZERO, 0)
            .expect("forced cancel dispatch must remain available");

        assert_eq!(normal.cancel_streak[0], 1);
        assert_eq!(forced.cancel_streak[0], normal.cancel_streak[0]);
        crate::test_complete!("forced_cancel_dispatch_preserves_normal_fairness_state");
    }

    #[test]
    fn lab_scheduler_steal_for_worker_only_steals_ready_tasks() {
        init_test("lab_scheduler_steal_for_worker_only_steals_ready_tasks");
        let mut scheduler = LabScheduler::new(2, 0);
        let cancel = TaskId::from_arena(ArenaIndex::new(10, 0));
        let timed = TaskId::from_arena(ArenaIndex::new(11, 0));
        let ready = TaskId::from_arena(ArenaIndex::new(12, 0));

        // With 2 workers, assignment is round-robin: cancel->w0, timed->w1, ready->w0.
        scheduler.schedule_cancel(cancel, 100);
        scheduler.schedule_timed(timed, Time::ZERO);
        scheduler.schedule(ready, 50);

        let stolen = scheduler.steal_for_worker(1, 0);
        crate::assert_with_log!(
            stolen == Some(ready),
            "steal path takes only ready lane work",
            Some(ready),
            stolen
        );

        crate::assert_with_log!(
            scheduler.workers[0].has_cancel_work(),
            "victim cancel lane remains intact after steal",
            true,
            scheduler.workers[0].has_cancel_work()
        );

        let cancel_dispatch = scheduler.pop_for_worker(0, 0, Time::ZERO);
        crate::assert_with_log!(
            cancel_dispatch == Some((cancel, DispatchLane::Cancel)),
            "cancel lane still dispatches from victim worker",
            Some((cancel, DispatchLane::Cancel)),
            cancel_dispatch
        );

        let timed_dispatch = scheduler.pop_for_worker(1, 0, Time::ZERO);
        crate::assert_with_log!(
            timed_dispatch == Some((timed, DispatchLane::Timed)),
            "timed lane remains on owning worker",
            Some((timed, DispatchLane::Timed)),
            timed_dispatch
        );

        crate::test_complete!("lab_scheduler_steal_for_worker_only_steals_ready_tasks");
    }

    #[test]
    fn lab_scheduler_spurious_wakes_do_not_collapse_duplicates() {
        init_test("lab_scheduler_spurious_wakes_do_not_collapse_duplicates");
        let mut scheduler = LabScheduler::new(1, 0);
        let task = TaskId::from_arena(ArenaIndex::new(13, 0));

        scheduler.inject_spurious_wakes(task, 42, 3);

        let first = scheduler.pop_for_worker(0, 0, Time::ZERO);
        crate::assert_with_log!(
            first == Some((task, DispatchLane::Ready)),
            "first spurious wake dispatches",
            Some((task, DispatchLane::Ready)),
            first
        );

        let second = scheduler.pop_for_worker(0, 1, Time::ZERO);
        crate::assert_with_log!(
            second == Some((task, DispatchLane::Ready)),
            "second spurious wake remains queued",
            Some((task, DispatchLane::Ready)),
            second
        );

        let third = scheduler.pop_for_worker(0, 2, Time::ZERO);
        crate::assert_with_log!(
            third == Some((task, DispatchLane::Ready)),
            "third spurious wake remains queued",
            Some((task, DispatchLane::Ready)),
            third
        );

        let fourth = scheduler.pop_for_worker(0, 3, Time::ZERO);
        crate::assert_with_log!(
            fourth.is_none(),
            "storm drains after requested wake count",
            true,
            fourth.is_none()
        );
        crate::assert_with_log!(
            scheduler.is_empty(),
            "scheduler empty after spurious storm drains",
            true,
            scheduler.is_empty()
        );

        crate::test_complete!("lab_scheduler_spurious_wakes_do_not_collapse_duplicates");
    }

    #[test]
    fn lab_scheduler_forget_task_clears_pending_spurious_wakes() {
        init_test("lab_scheduler_forget_task_clears_pending_spurious_wakes");
        let mut scheduler = LabScheduler::new(1, 0);
        let task = TaskId::from_arena(ArenaIndex::new(14, 0));

        scheduler.inject_spurious_wakes(task, 42, 3);
        let first = scheduler.pop_for_worker(0, 0, Time::ZERO);
        crate::assert_with_log!(
            first == Some((task, DispatchLane::Ready)),
            "first spurious wake dispatches before forget",
            Some((task, DispatchLane::Ready)),
            first
        );

        scheduler.forget_task(task);

        let second = scheduler.pop_for_worker(0, 1, Time::ZERO);
        crate::assert_with_log!(
            second.is_none(),
            "forget_task drains queued spurious wakes",
            true,
            second.is_none()
        );
        crate::assert_with_log!(
            scheduler.pending_spurious_wakes.is_empty(),
            "forget_task clears pending spurious wake budget",
            true,
            scheduler.pending_spurious_wakes.is_empty()
        );
        crate::assert_with_log!(
            scheduler.is_empty(),
            "scheduler empty after forget_task",
            true,
            scheduler.is_empty()
        );

        crate::test_complete!("lab_scheduler_forget_task_clears_pending_spurious_wakes");
    }

    #[test]
    fn lab_scheduler_steal_preserves_pending_spurious_wakes() {
        init_test("lab_scheduler_steal_preserves_pending_spurious_wakes");
        let mut scheduler = LabScheduler::new(2, 0);
        let task = TaskId::from_arena(ArenaIndex::new(15, 0));

        scheduler.inject_spurious_wakes(task, 42, 3);

        let stolen = scheduler.steal_for_worker(1, 0);
        crate::assert_with_log!(
            stolen == Some(task),
            "steal dispatches first storm wake",
            Some(task),
            stolen
        );

        let second = scheduler.pop_for_worker(1, 1, Time::ZERO);
        crate::assert_with_log!(
            second == Some((task, DispatchLane::Ready)),
            "steal path re-arms second storm wake on thief worker",
            Some((task, DispatchLane::Ready)),
            second
        );

        let third = scheduler.pop_for_worker(1, 2, Time::ZERO);
        crate::assert_with_log!(
            third == Some((task, DispatchLane::Ready)),
            "steal path preserves final pending storm wake",
            Some((task, DispatchLane::Ready)),
            third
        );

        let fourth = scheduler.pop_for_worker(1, 3, Time::ZERO);
        crate::assert_with_log!(
            fourth.is_none(),
            "all stolen storm wakes drain after requested count",
            true,
            fourth.is_none()
        );
        crate::assert_with_log!(
            scheduler.is_empty(),
            "scheduler empty after stolen storm drains",
            true,
            scheduler.is_empty()
        );

        crate::test_complete!("lab_scheduler_steal_preserves_pending_spurious_wakes");
    }

    #[test]
    fn deterministic_multiworker_schedule() {
        init_test("deterministic_multiworker_schedule");
        let config = LabConfig::new(7).worker_count(4);

        crate::lab::assert_deterministic(config, |runtime| {
            let root = runtime.state.create_root_region(Budget::INFINITE);
            for _ in 0..4 {
                let (task_id, _handle) = runtime
                    .state
                    .create_task(root, Budget::INFINITE, async {
                        crate::runtime::yield_now::yield_now().await;
                    })
                    .expect("create task");
                runtime.scheduler.lock().schedule(task_id, 0);
            }
            runtime.run_until_quiescent();
        });

        crate::test_complete!("deterministic_multiworker_schedule");
    }

    #[test]
    fn run_until_quiescent_with_report_is_deterministic() {
        init_test("run_until_quiescent_with_report_is_deterministic");

        let config = LabConfig::new(123).worker_count(4).max_steps(10_000);
        let mut r1 = LabRuntime::new(config.clone());
        let mut r2 = LabRuntime::new(config);

        let setup = |runtime: &mut LabRuntime| {
            let root = runtime.state.create_root_region(Budget::INFINITE);
            for _ in 0..4 {
                let (task_id, _handle) = runtime
                    .state
                    .create_task(root, Budget::INFINITE, async {
                        crate::runtime::yield_now::yield_now().await;
                    })
                    .expect("create task");
                runtime.scheduler.lock().schedule(task_id, 0);
            }
        };

        setup(&mut r1);
        setup(&mut r2);

        let rep1 = r1.run_until_quiescent_with_report();
        let rep2 = r2.run_until_quiescent_with_report();

        crate::assert_with_log!(rep1.quiescent, "quiescent", true, rep1.quiescent);
        crate::assert_with_log!(rep2.quiescent, "quiescent", true, rep2.quiescent);

        assert_eq!(rep1.trace_fingerprint, rep2.trace_fingerprint);
        assert_eq!(rep1.trace_certificate, rep2.trace_certificate);
        assert_eq!(rep1.oracle_report.to_json(), rep2.oracle_report.to_json());
        assert_eq!(rep1.invariant_violations, rep2.invariant_violations);

        crate::assert_with_log!(
            rep1.oracle_report.all_passed(),
            "oracles passed",
            true,
            rep1.oracle_report.all_passed()
        );
        crate::assert_with_log!(
            rep2.oracle_report.all_passed(),
            "oracles passed",
            true,
            rep2.oracle_report.all_passed()
        );

        crate::test_complete!("run_until_quiescent_with_report_is_deterministic");
    }

    #[test]
    fn deadline_monitor_emits_warning() {
        init_test("deadline_monitor_emits_warning");
        let mut runtime = LabRuntime::with_seed(42);

        let warnings: Arc<Mutex<Vec<DeadlineWarning>>> = Arc::new(Mutex::new(Vec::new()));
        let warnings_clone = Arc::clone(&warnings);

        let config = MonitorConfig {
            check_interval: Duration::from_secs(0),
            warning_threshold_fraction: 1.0,
            checkpoint_timeout: Duration::from_secs(0),
            adaptive: AdaptiveDeadlineConfig::default(),
            enabled: true,
        };

        runtime.enable_deadline_monitoring_with_handler(config, move |warning| {
            warnings_clone.lock().push(warning);
        });

        let root = runtime.state.create_root_region(Budget::INFINITE);
        let budget = Budget::new().with_deadline(Time::from_millis(10));

        let task_idx = runtime.state.insert_task(TaskRecord::new_with_time(
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            root,
            budget,
            runtime.state.now,
        ));
        let task_id = TaskId::from_arena(task_idx);
        runtime.state.task_mut(task_id).unwrap().id = task_id;

        let mut inner = CxInner::new(root, task_id, budget);
        inner.checkpoint_state.last_checkpoint = None;
        runtime
            .state
            .task_mut(task_id)
            .unwrap()
            .set_cx_inner(Arc::new(RwLock::new(inner)));

        runtime.step();

        let warnings = warnings.lock();
        let warning = warnings.first().expect("expected warning");
        crate::assert_with_log!(
            warning.task_id == task_id,
            "task_id",
            task_id,
            warning.task_id
        );
        crate::assert_with_log!(
            warning.region_id == root,
            "region_id",
            root,
            warning.region_id
        );
        let ok = matches!(
            warning.reason,
            WarningReason::ApproachingDeadline | WarningReason::ApproachingDeadlineNoProgress
        );
        crate::assert_with_log!(ok, "reason", true, ok);
        drop(warnings);
        crate::test_complete!("deadline_monitor_emits_warning");
    }

    #[test]
    fn deadline_monitor_e2e_stuck_detection() {
        init_test("deadline_monitor_e2e_stuck_detection");
        let mut runtime = LabRuntime::with_seed(42);

        let warnings: Arc<Mutex<Vec<DeadlineWarning>>> = Arc::new(Mutex::new(Vec::new()));
        let warnings_clone = Arc::clone(&warnings);

        let config = MonitorConfig {
            check_interval: Duration::ZERO,
            warning_threshold_fraction: 0.0,
            checkpoint_timeout: Duration::ZERO,
            adaptive: AdaptiveDeadlineConfig::default(),
            enabled: true,
        };

        runtime.enable_deadline_monitoring_with_handler(config, move |warning| {
            warnings_clone.lock().push(warning);
        });

        let root = runtime.state.create_root_region(Budget::INFINITE);
        let budget = Budget::new().with_deadline(Time::from_secs(10));
        let (task_id, _handle) = runtime
            .state
            .create_task(root, budget, async {})
            .expect("create task");

        {
            let task = runtime.state.task_mut(task_id).unwrap();
            let cx = task.cx.as_ref().expect("task cx");
            cx.checkpoint_with("starting work").expect("checkpoint");
        }

        runtime.step();

        let warnings = warnings.lock();
        let warning = warnings.first().expect("expected warning");
        crate::assert_with_log!(
            warning.task_id == task_id,
            "task_id",
            task_id,
            warning.task_id
        );
        crate::assert_with_log!(
            warning.reason == WarningReason::NoProgress,
            "reason",
            WarningReason::NoProgress,
            warning.reason
        );
        crate::assert_with_log!(
            warning.last_checkpoint_message.as_deref() == Some("starting work"),
            "checkpoint message",
            Some("starting work"),
            warning.last_checkpoint_message.as_deref()
        );
        drop(warnings);
        crate::test_complete!("deadline_monitor_e2e_stuck_detection");
    }

    #[test]
    fn futurelock_emits_trace_event() {
        init_test("futurelock_emits_trace_event");
        let config = LabConfig::new(42)
            .futurelock_max_idle_steps(3)
            .panic_on_futurelock(false);
        let mut runtime = LabRuntime::new(config);

        let root = runtime.state.create_root_region(Budget::INFINITE);

        // Create a task.
        let task_idx = runtime.state.insert_task(TaskRecord::new(
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            root,
            Budget::INFINITE,
        ));
        let task_id = TaskId::from_arena(task_idx);
        runtime.state.task_mut(task_id).unwrap().id = task_id;

        // Create a pending obligation held by that task.
        let obl_id = runtime
            .state
            .create_obligation(ObligationKind::SendPermit, task_id, root, None)
            .expect("create obligation");

        for _ in 0..4 {
            runtime.step();
        }

        let futurelock = runtime
            .trace()
            .snapshot()
            .into_iter()
            .find(|e| e.kind == TraceEventKind::FuturelockDetected)
            .expect("expected futurelock trace event");

        match &futurelock.data {
            TraceData::Futurelock {
                task,
                region,
                idle_steps,
                held,
            } => {
                crate::assert_with_log!(*task == task_id, "task", task_id, *task);
                crate::assert_with_log!(*region == root, "region", root, *region);
                let idle_ok = *idle_steps > 3;
                crate::assert_with_log!(idle_ok, "idle_steps > 3", true, idle_ok);
                let ok = held.as_slice() == [(obl_id, ObligationKind::SendPermit)];
                crate::assert_with_log!(
                    ok,
                    "held",
                    &[(obl_id, ObligationKind::SendPermit)],
                    held.as_slice()
                );
            }
            other => panic!("unexpected trace data: {other:?}"),
        }
        crate::test_complete!("futurelock_emits_trace_event");
    }

    #[test]
    fn futurelock_display_includes_error_code() {
        init_test("futurelock_display_includes_error_code");
        let task = TaskId::from_arena(ArenaIndex::new(2, 0));
        let region = RegionId::from_arena(ArenaIndex::new(3, 0));
        let obligation = ObligationId::from_arena(ArenaIndex::new(4, 0));
        let violation = InvariantViolation::Futurelock {
            task,
            region,
            idle_steps: 8,
            held: vec![obligation],
            last_checkpoint_message: Some("waiting on permit".to_string()),
        };

        let rendered = violation.to_string();
        let has_code = rendered.starts_with("[ASUP-E402] futurelock:");
        crate::assert_with_log!(has_code, "futurelock display error code", true, has_code);
        crate::assert_with_log!(
            rendered.contains("idle=8"),
            "futurelock display idle steps",
            true,
            rendered.contains("idle=8")
        );
        crate::assert_with_log!(
            rendered.contains("last_checkpoint=\"waiting on permit\""),
            "futurelock display checkpoint message",
            true,
            rendered.contains("last_checkpoint=\"waiting on permit\"")
        );
        crate::test_complete!("futurelock_display_includes_error_code");
    }

    #[test]
    fn obligation_leak_display_includes_error_code_and_owner_facts() {
        init_test("obligation_leak_display_includes_error_code_and_owner_facts");
        let task = TaskId::from_arena(ArenaIndex::new(2, 0));
        let region = RegionId::from_arena(ArenaIndex::new(3, 0));
        let obligation = ObligationId::from_arena(ArenaIndex::new(4, 0));
        let violation = InvariantViolation::ObligationLeak {
            leaks: vec![ObligationLeak {
                obligation,
                kind: ObligationKind::SendPermit,
                holder: task,
                region,
            }],
        };

        let rendered = violation.to_string();
        let has_code = rendered.starts_with("[ASUP-E101] obligation leak:");
        crate::assert_with_log!(
            has_code,
            "obligation leak display error code",
            true,
            has_code
        );
        crate::assert_with_log!(
            rendered.contains("count=1"),
            "obligation leak display count",
            true,
            rendered.contains("count=1")
        );
        crate::assert_with_log!(
            rendered.contains("obligation="),
            "obligation leak display obligation id",
            true,
            rendered.contains("obligation=")
        );
        crate::assert_with_log!(
            rendered.contains("kind=SendPermit"),
            "obligation leak display kind",
            true,
            rendered.contains("kind=SendPermit")
        );
        crate::assert_with_log!(
            rendered.contains("holder="),
            "obligation leak display holder",
            true,
            rendered.contains("holder=")
        );
        crate::assert_with_log!(
            rendered.contains("region="),
            "obligation leak display region",
            true,
            rendered.contains("region=")
        );
        crate::test_complete!("obligation_leak_display_includes_error_code_and_owner_facts");
    }

    #[test]
    fn futurelock_panic_includes_last_checkpoint_message() {
        init_test("futurelock_panic_includes_last_checkpoint_message");
        let config = LabConfig::new(42)
            .futurelock_max_idle_steps(1)
            .panic_on_futurelock(true);
        let mut runtime = LabRuntime::new(config);

        let root = runtime.state.create_root_region(Budget::INFINITE);
        let (task_id, _handle) = runtime
            .state
            .create_task(root, Budget::INFINITE, async {})
            .expect("create task");
        runtime
            .state
            .task(task_id)
            .expect("task")
            .cx
            .as_ref()
            .expect("task cx")
            .checkpoint_with("waiting on downstream permit")
            .expect("checkpoint");

        let _ = runtime
            .state
            .create_obligation(ObligationKind::SendPermit, task_id, root, None)
            .expect("create obligation");

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            for _ in 0..3 {
                runtime.step();
            }
        }));
        let payload = result.expect_err("futurelock should panic");
        let message = if let Some(message) = payload.downcast_ref::<String>() {
            message.clone()
        } else if let Some(message) = payload.downcast_ref::<&str>() {
            (*message).to_string()
        } else {
            String::from("<non-string panic>")
        };

        crate::assert_with_log!(
            message.contains("[ASUP-E402] futurelock detected"),
            "futurelock panic error code",
            true,
            message.contains("[ASUP-E402] futurelock detected")
        );
        crate::assert_with_log!(
            message.contains("last_checkpoint=\"waiting on downstream permit\""),
            "futurelock panic checkpoint message",
            true,
            message.contains("last_checkpoint=\"waiting on downstream permit\"")
        );
        crate::assert_with_log!(
            message.contains("seed=42"),
            "futurelock panic seed",
            true,
            message.contains("seed=42")
        );
        crate::test_complete!("futurelock_panic_includes_last_checkpoint_message");
    }

    #[test]
    #[should_panic(expected = "[ASUP-E402] futurelock detected")]
    fn futurelock_can_panic() {
        init_test("futurelock_can_panic");
        let config = LabConfig::new(42).futurelock_max_idle_steps(1);
        let mut runtime = LabRuntime::new(config);

        let root = runtime.state.create_root_region(Budget::INFINITE);

        let task_idx = runtime.state.insert_task(TaskRecord::new(
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            root,
            Budget::INFINITE,
        ));
        let task_id = TaskId::from_arena(task_idx);
        runtime.state.task_mut(task_id).unwrap().id = task_id;

        let _ = runtime
            .state
            .create_obligation(ObligationKind::SendPermit, task_id, root, None)
            .expect("create obligation");

        // Run enough steps to exceed threshold and trigger panic.
        for _ in 0..3 {
            runtime.step();
        }
    }

    /// Regression test: actively polled tasks must NOT be flagged as futurelocked.
    ///
    /// Before the fix, `mark_polled()` was never called from `step()`, so
    /// `last_polled_step` stayed at 0. After threshold+1 steps, even a
    /// task polled every single step would be falsely flagged.
    #[test]
    fn polled_task_not_flagged_as_futurelocked() {
        init_test("polled_task_not_flagged_as_futurelocked");
        let config = LabConfig::new(42)
            .futurelock_max_idle_steps(5)
            .panic_on_futurelock(false);
        let mut runtime = LabRuntime::new(config);

        let root = runtime.state.create_root_region(Budget::INFINITE);

        // Create a task with a stored future that always yields (Pending).
        let (task_id, _handle) = runtime
            .state
            .create_task(root, Budget::INFINITE, async {
                loop {
                    crate::runtime::yield_now::yield_now().await;
                }
            })
            .expect("create task");

        // Give the task a pending obligation so it's eligible for futurelock.
        let _obl = runtime
            .state
            .create_obligation(ObligationKind::SendPermit, task_id, root, None)
            .expect("create obligation");

        // Schedule and run well past the threshold.
        runtime.scheduler.lock().schedule(task_id, 0);
        for _ in 0..20 {
            runtime.step();
        }

        // The task was polled every step, so no futurelock should fire.
        let violations = runtime.futurelock_violations();
        crate::assert_with_log!(
            violations.is_empty(),
            "no futurelock for actively polled task",
            true,
            violations.is_empty()
        );
        crate::test_complete!("polled_task_not_flagged_as_futurelocked");
    }

    #[test]
    fn immediate_completion_marks_running_before_completion() {
        init_test("immediate_completion_marks_running_before_completion");
        let mut runtime = LabRuntime::new(LabConfig::new(42));
        let root = runtime.state.create_root_region(Budget::INFINITE);
        let (task_id, _) = runtime
            .state
            .create_task(root, Budget::INFINITE, async {})
            .expect("create task");
        runtime.scheduler.lock().schedule(task_id, 0);

        runtime.run_until_quiescent();

        let protocol_ok = runtime.check_cancellation_protocol().is_ok();
        crate::assert_with_log!(
            runtime.is_quiescent(),
            "runtime reached quiescence after immediate completion",
            true,
            runtime.is_quiescent()
        );
        crate::assert_with_log!(
            protocol_ok,
            "cancellation oracle accepted Created -> Running -> Completed",
            true,
            protocol_ok
        );

        crate::test_complete!("immediate_completion_marks_running_before_completion");
    }

    #[test]
    fn obligation_leak_detected_when_holder_completed() {
        init_test("obligation_leak_detected_when_holder_completed");
        let mut runtime = LabRuntime::with_seed(7);
        let root = runtime.state.create_root_region(Budget::INFINITE);

        let task_idx = runtime.state.insert_task(TaskRecord::new(
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            root,
            Budget::INFINITE,
        ));
        let task_id = TaskId::from_arena(task_idx);
        runtime.state.task_mut(task_id).unwrap().id = task_id;

        let obl_id = runtime
            .state
            .create_obligation(ObligationKind::SendPermit, task_id, root, None)
            .expect("create obligation");

        runtime
            .state
            .update_task(task_id, |record| record.complete(Outcome::Ok(())))
            .unwrap();

        let violations = runtime.check_invariants();
        let mut found = false;
        for violation in violations {
            if let InvariantViolation::ObligationLeak { leaks } = violation {
                found = true;
                let len = leaks.len();
                crate::assert_with_log!(len == 1, "leaks len", 1, len);
                let leak = &leaks[0];
                crate::assert_with_log!(
                    leak.obligation == obl_id,
                    "obligation",
                    obl_id,
                    leak.obligation
                );
                crate::assert_with_log!(
                    leak.kind == ObligationKind::SendPermit,
                    "kind",
                    ObligationKind::SendPermit,
                    leak.kind
                );
                crate::assert_with_log!(leak.holder == task_id, "holder", task_id, leak.holder);
                crate::assert_with_log!(leak.region == root, "region", root, leak.region);
            }
        }
        crate::assert_with_log!(found, "found leak", true, found);
        crate::test_complete!("obligation_leak_detected_when_holder_completed");
    }

    #[test]
    fn obligation_leak_ignored_when_resolved() {
        init_test("obligation_leak_ignored_when_resolved");
        let mut runtime = LabRuntime::with_seed(11);
        let root = runtime.state.create_root_region(Budget::INFINITE);

        let task_idx = runtime.state.insert_task(TaskRecord::new(
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            root,
            Budget::INFINITE,
        ));
        let task_id = TaskId::from_arena(task_idx);
        runtime.state.task_mut(task_id).unwrap().id = task_id;

        let obl_id = runtime
            .state
            .create_obligation(ObligationKind::Ack, task_id, root, None)
            .expect("create obligation");
        runtime
            .state
            .commit_obligation(obl_id)
            .expect("commit obligation");

        runtime
            .state
            .update_task(task_id, |record| record.complete(Outcome::Ok(())))
            .unwrap();

        let violations = runtime.check_invariants();
        let has_leak = violations
            .iter()
            .any(|v| matches!(v, InvariantViolation::ObligationLeak { .. }));
        crate::assert_with_log!(!has_leak, "no leak", false, has_leak);
        crate::test_complete!("obligation_leak_ignored_when_resolved");
    }

    #[test]
    fn report_hydrates_temporal_oracles_from_state_snapshot() {
        init_test("report_hydrates_temporal_oracles_from_state_snapshot");
        let mut runtime = LabRuntime::with_seed(31);
        let root = runtime.state.create_root_region(Budget::INFINITE);
        let (_task, _handle) = runtime
            .state
            .create_task(root, Budget::INFINITE, async {})
            .expect("create task");

        // Force-close the region while a task is still live to simulate a
        // temporal invariant break that must be surfaced by report hydration.
        runtime
            .state
            .region(root)
            .expect("region exists")
            .set_state(crate::record::region::RegionState::Closed);

        let report = runtime.report();
        let task_leak = report
            .oracle_report
            .entry("task_leak")
            .expect("task_leak entry");
        let quiescence = report
            .oracle_report
            .entry("quiescence")
            .expect("quiescence entry");

        crate::assert_with_log!(
            !task_leak.passed,
            "task_leak failed",
            false,
            task_leak.passed
        );
        crate::assert_with_log!(
            !quiescence.passed,
            "quiescence failed",
            false,
            quiescence.passed
        );
        let has_temporal_tag = report
            .invariant_violations
            .iter()
            .any(|v| v == "temporal:task_leak");
        crate::assert_with_log!(
            has_temporal_tag,
            "temporal marker present",
            true,
            has_temporal_tag
        );
        let temporal_failed = report
            .temporal_invariant_failures
            .iter()
            .any(|v| v == "task_leak");
        crate::assert_with_log!(
            temporal_failed,
            "temporal failure surfaced",
            true,
            temporal_failed
        );
        crate::test_complete!("report_hydrates_temporal_oracles_from_state_snapshot");
    }

    #[test]
    fn report_hydrates_quiescence_from_finalizers_and_obligations() {
        init_test("report_hydrates_quiescence_from_finalizers_and_obligations");
        let mut runtime = LabRuntime::with_seed(32);
        let root = runtime.state.create_root_region(Budget::INFINITE);
        let (task_id, _handle) = runtime
            .state
            .create_task(root, Budget::INFINITE, async {})
            .expect("create task");

        runtime.state.now = Time::from_nanos(10);
        let registered = runtime.state.register_sync_finalizer(root, || {});
        crate::assert_with_log!(registered, "registered finalizer", true, registered);

        runtime.state.now = Time::from_nanos(20);
        let _obligation = runtime
            .state
            .create_obligation(ObligationKind::SendPermit, task_id, root, None)
            .expect("create obligation");

        runtime.state.now = Time::from_nanos(30);
        runtime
            .state
            .update_task(task_id, |record| record.complete(Outcome::Ok(())))
            .expect("complete task without auto-resolving obligation");

        runtime.state.now = Time::from_nanos(40);
        runtime.state.record_finalizer_close_for_test(root);
        runtime
            .state
            .region(root)
            .expect("region exists")
            .set_state(crate::record::region::RegionState::Closed);

        let report = runtime.report();
        let quiescence = report
            .oracle_report
            .entry("quiescence")
            .expect("quiescence entry");
        let finalizer = report
            .oracle_report
            .entry("finalizer")
            .expect("finalizer entry");
        let obligation_leak = report
            .oracle_report
            .entry("obligation_leak")
            .expect("obligation entry");

        crate::assert_with_log!(
            !quiescence.passed,
            "quiescence failed",
            false,
            quiescence.passed
        );
        let quiescence_text = quiescence
            .violation
            .as_deref()
            .expect("quiescence violation text");
        crate::assert_with_log!(
            quiescence_text.contains("1 unrun finalizers"),
            "quiescence mentions finalizers",
            true,
            quiescence_text.contains("1 unrun finalizers")
        );
        crate::assert_with_log!(
            quiescence_text.contains("1 leaked obligations"),
            "quiescence mentions obligations",
            true,
            quiescence_text.contains("1 leaked obligations")
        );
        crate::assert_with_log!(
            !finalizer.passed,
            "finalizer failed",
            false,
            finalizer.passed
        );
        crate::assert_with_log!(
            !obligation_leak.passed,
            "obligation_leak failed",
            false,
            obligation_leak.passed
        );
        for failed in report.oracle_report.failures() {
            let marker = format!("oracle:{}", failed.invariant);
            crate::assert_with_log!(
                report.invariant_violations.contains(&marker),
                "every failed oracle has aggregate marker",
                true,
                report.invariant_violations.contains(&marker)
            );
        }
        crate::test_complete!("report_hydrates_quiescence_from_finalizers_and_obligations");
    }

    #[test]
    fn report_hydrates_cancellation_propagation_from_state_snapshot() {
        init_test("report_hydrates_cancellation_propagation_from_state_snapshot");
        // This test intentionally drives a cancellation-propagation violation
        // to verify it surfaces in the temporal report. Default configs panic
        // on such violations during `report()`, so the oracle must be allowed
        // to merely *record* the violation instead of aborting the test.
        let config = LabConfig::new(32).panic_on_cancellation_violation(false);
        let mut runtime = LabRuntime::new(config);
        let root = runtime.state.create_root_region(Budget::INFINITE);
        let _child = runtime
            .state
            .create_child_region(root, Budget::INFINITE)
            .expect("create child");

        runtime
            .state
            .region(root)
            .expect("root exists")
            .cancel_request(crate::types::CancelReason::shutdown());

        let report = runtime.report();
        let cancellation = report
            .oracle_report
            .entry("cancellation_protocol")
            .expect("cancellation_protocol entry");
        crate::assert_with_log!(
            !cancellation.passed,
            "cancellation_protocol failed",
            false,
            cancellation.passed
        );
        let has_temporal_tag = report
            .invariant_violations
            .iter()
            .any(|v| v == "temporal:cancellation_protocol");
        crate::assert_with_log!(
            has_temporal_tag,
            "temporal cancellation marker present",
            true,
            has_temporal_tag
        );
        crate::test_complete!("report_hydrates_cancellation_propagation_from_state_snapshot");
    }

    #[test]
    fn report_surfaces_refinement_firewall_violation_from_trace_snapshot() {
        init_test("report_surfaces_refinement_firewall_violation_from_trace_snapshot");
        let mut runtime = LabRuntime::with_seed(33);
        let region = RegionId::new_for_test(41, 0);
        let task = TaskId::new_for_test(7, 0);

        runtime
            .state
            .trace
            .push_event(TraceEvent::spawn(1, Time::ZERO, task, region));
        runtime
            .state
            .trace
            .push_event(TraceEvent::spawn(2, Time::ZERO, task, region));

        let report = runtime.report();
        crate::assert_with_log!(
            report.refinement_firewall_rule_id.as_deref() == Some("RFW-SPAWN-001"),
            "refinement rule id surfaced",
            Some("RFW-SPAWN-001"),
            report.refinement_firewall_rule_id.as_deref()
        );
        crate::assert_with_log!(
            report.refinement_firewall_event_index == Some(1),
            "refinement event index surfaced",
            Some(1usize),
            report.refinement_firewall_event_index
        );
        crate::assert_with_log!(
            report.refinement_counterexample_prefix_len == Some(2),
            "refinement prefix len surfaced",
            Some(2usize),
            report.refinement_counterexample_prefix_len
        );
        let has_marker = report
            .invariant_violations
            .iter()
            .any(|v| v == "refinement_firewall:RFW-SPAWN-001");
        crate::assert_with_log!(
            has_marker,
            "refinement invariant marker present",
            true,
            has_marker
        );
        let json = report.to_json();
        crate::assert_with_log!(
            json["refinement_firewall"]["rule_id"] == "RFW-SPAWN-001",
            "refinement json rule id",
            "RFW-SPAWN-001",
            json["refinement_firewall"]["rule_id"]
        );
        crate::assert_with_log!(
            json["refinement_firewall"]["counterexample_prefix_len"] == 2,
            "refinement json prefix len",
            2,
            json["refinement_firewall"]["counterexample_prefix_len"]
        );
        crate::assert_with_log!(
            json["refinement_firewall"]["skipped_due_to_trace_truncation"] == false,
            "refinement json not skipped",
            false,
            json["refinement_firewall"]["skipped_due_to_trace_truncation"]
        );
        crate::test_complete!("report_surfaces_refinement_firewall_violation_from_trace_snapshot");
    }

    // br-asupersync-9ri7x0: trace truncation no longer silently
    // disables the refinement-firewall oracle. The flag remains set
    // (it is part of the report contract) and the rule_id is None
    // because the firewall did not run, but the scenario must now
    // surface a hard 'scenario_failed_due_to_trace_truncation'
    // invariant_violations entry so any caller that gates on
    // invariant_violations.is_empty() will fail loudly. The seed and
    // truncation watermark are embedded in the message so an
    // operator can immediately bump trace_capacity or split the
    // scenario.
    #[test]
    fn report_fails_loudly_when_trace_buffer_is_truncated_l9ri7x0() {
        init_test("report_fails_loudly_when_trace_buffer_is_truncated_l9ri7x0");
        let seed = 35;
        let config = LabConfig::new(seed).trace_capacity(1);
        let mut runtime = LabRuntime::new(config);
        let region = RegionId::new_for_test(43, 0);
        let task = TaskId::new_for_test(9, 0);

        runtime
            .state
            .trace
            .push_event(TraceEvent::spawn(1, Time::ZERO, task, region));
        runtime
            .state
            .trace
            .push_event(TraceEvent::complete(2, Time::ZERO, task, region));

        let report = runtime.report();
        crate::assert_with_log!(
            report.refinement_firewall_skipped_due_to_trace_truncation,
            "refinement_firewall_skipped_due_to_trace_truncation",
            true,
            report.refinement_firewall_skipped_due_to_trace_truncation
        );
        crate::assert_with_log!(
            report.refinement_firewall_rule_id.is_none(),
            "no real rule_id when firewall could not run",
            true,
            report.refinement_firewall_rule_id.is_none()
        );

        // The new contract: invariant_violations MUST contain a
        // hard-fail marker that names the truncation cause + seed +
        // watermark. The substring is checked rather than equality
        // so future format adjustments stay backward-compatible.
        let truncation_marker = report
            .invariant_violations
            .iter()
            .find(|v| v.starts_with("refinement_firewall:scenario_failed_due_to_trace_truncation"));
        let marker = truncation_marker.expect(
            "truncation must surface as a hard refinement_firewall:scenario_failed_due_to_trace_truncation marker",
        );
        assert!(
            marker.contains(&format!("seed={seed}")),
            "truncation marker must embed the seed, got: {marker}"
        );
        assert!(
            marker.contains("total_pushed=") && marker.contains("buffered="),
            "truncation marker must embed total_pushed + buffered watermark, got: {marker}"
        );
        // And of course the scenario must NOT report 'passed':
        // invariant_violations.is_empty() is the standard pass gate.
        crate::assert_with_log!(
            !report.invariant_violations.is_empty(),
            "scenario must fail loudly when trace buffer truncates",
            true,
            !report.invariant_violations.is_empty()
        );

        let json = report.to_json();
        crate::assert_with_log!(
            json["refinement_firewall"]["skipped_due_to_trace_truncation"] == true,
            "skipped flag still serialized for downstream tooling",
            true,
            json["refinement_firewall"]["skipped_due_to_trace_truncation"]
        );
        crate::test_complete!("report_fails_loudly_when_trace_buffer_is_truncated_l9ri7x0");
    }

    // br-asupersync-7uu7sa: chaos-injected wakeup_storm must be
    // suppressed when the targeted task's owning region has already
    // transitioned to Closing/Draining/Closed. Drives the inner
    // method directly, then drives it again after flipping the
    // owning region's state to Closing — the second call must NOT
    // schedule the task.
    #[test]
    fn inject_spurious_wakes_suppressed_when_owning_region_is_closing_l7uu7sa() {
        init_test("inject_spurious_wakes_suppressed_when_owning_region_is_closing_l7uu7sa");

        let mut runtime = LabRuntime::with_seed(42);
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let task_idx = runtime.state.insert_task(TaskRecord::new_with_time(
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            region,
            Budget::INFINITE,
            runtime.state.now,
        ));
        let task_id = TaskId::from_arena(task_idx);
        runtime.state.task_mut(task_id).unwrap().id = task_id;

        // Region is Open: the inner method must schedule the task.
        runtime.inject_spurious_wakes(task_id, 0, 2);
        let scheduled_open = {
            let mut sched = runtime.scheduler.lock();
            let mut count = 0u32;
            while sched.pop_for_worker(0, count.into(), Time::ZERO).is_some() {
                count += 1;
            }
            count
        };
        crate::assert_with_log!(
            scheduled_open == 2,
            "while region is Open, 2 spurious wakes are scheduled",
            2u32,
            scheduled_open
        );

        // Transition the region into a non-accepting state.
        runtime
            .state
            .region(region)
            .expect("region exists")
            .set_state(crate::record::region::RegionState::Closing);

        // Now the call must be silently suppressed — no work on the queue.
        runtime.inject_spurious_wakes(task_id, 0, 5);
        let scheduled_closing = {
            let mut sched = runtime.scheduler.lock();
            let mut count = 0u32;
            while sched.pop_for_worker(0, count.into(), Time::ZERO).is_some() {
                count += 1;
            }
            count
        };
        crate::assert_with_log!(
            scheduled_closing == 0,
            "after region.set_state(Closing), spurious wakes are suppressed",
            0u32,
            scheduled_closing
        );

        // Defense-in-depth: walk every other terminal-ish state.
        for state in [
            crate::record::region::RegionState::Draining,
            crate::record::region::RegionState::Closed,
        ] {
            runtime
                .state
                .region(region)
                .expect("region exists")
                .set_state(state);
            runtime.inject_spurious_wakes(task_id, 0, 3);
            let scheduled = {
                let mut sched = runtime.scheduler.lock();
                let mut count = 0u32;
                while sched.pop_for_worker(0, count.into(), Time::ZERO).is_some() {
                    count += 1;
                }
                count
            };
            assert_eq!(
                scheduled, 0,
                "spurious wakes must be suppressed in region state {state:?}"
            );
        }

        crate::test_complete!(
            "inject_spurious_wakes_suppressed_when_owning_region_is_closing_l7uu7sa"
        );
    }

    #[test]
    fn crashpack_includes_refinement_firewall_markers() {
        init_test("crashpack_includes_refinement_firewall_markers");
        let mut runtime = LabRuntime::with_seed(34);
        let region = RegionId::new_for_test(42, 0);
        let task = TaskId::new_for_test(8, 0);

        runtime
            .state
            .trace
            .push_event(TraceEvent::spawn(1, Time::ZERO, task, region));
        runtime
            .state
            .trace
            .push_event(TraceEvent::spawn(2, Time::ZERO, task, region));

        let run = runtime.report();
        let crashpack = runtime
            .build_crashpack_for_report(&run)
            .expect("refinement-firewall failure should build crashpack");
        let has_rule_marker = crashpack
            .oracle_violations
            .iter()
            .any(|entry| entry == "refinement_firewall:RFW-SPAWN-001");
        crate::assert_with_log!(
            has_rule_marker,
            "crashpack includes refinement rule marker",
            true,
            has_rule_marker
        );
        let has_prefix_marker = crashpack
            .oracle_violations
            .iter()
            .any(|entry| entry == "refinement_firewall:minimal_counterexample_prefix_len=2");
        crate::assert_with_log!(
            has_prefix_marker,
            "crashpack includes refinement prefix marker",
            true,
            has_prefix_marker
        );
        crate::test_complete!("crashpack_includes_refinement_firewall_markers");
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn obligation_trace_events_emitted() {
        init_test("obligation_trace_events_emitted");
        let mut runtime = LabRuntime::with_seed(21);
        let root = runtime.state.create_root_region(Budget::INFINITE);

        let task_idx = runtime.state.insert_task(TaskRecord::new(
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            root,
            Budget::INFINITE,
        ));
        let task_id = TaskId::from_arena(task_idx);
        runtime.state.task_mut(task_id).unwrap().id = task_id;

        runtime.advance_time_to(Time::from_nanos(10));
        let ob1 = runtime
            .state
            .create_obligation(ObligationKind::SendPermit, task_id, root, None)
            .unwrap();

        runtime.advance_time_to(Time::from_nanos(25));
        runtime.state.commit_obligation(ob1).unwrap();

        runtime.advance_time_to(Time::from_nanos(30));
        let ob2 = runtime
            .state
            .create_obligation(ObligationKind::Ack, task_id, root, None)
            .unwrap();

        runtime.advance_time_to(Time::from_nanos(50));
        runtime
            .state
            .abort_obligation(ob2, ObligationAbortReason::Cancel)
            .unwrap();

        let commit_event = runtime
            .trace()
            .snapshot()
            .into_iter()
            .find(|e| e.kind == TraceEventKind::ObligationCommit)
            .expect("commit event");
        match &commit_event.data {
            TraceData::Obligation {
                obligation,
                task,
                region,
                kind,
                state,
                duration_ns,
                abort_reason,
            } => {
                crate::assert_with_log!(*obligation == ob1, "obligation", ob1, *obligation);
                crate::assert_with_log!(*task == task_id, "task", task_id, *task);
                crate::assert_with_log!(*region == root, "region", root, *region);
                crate::assert_with_log!(
                    *kind == ObligationKind::SendPermit,
                    "kind",
                    ObligationKind::SendPermit,
                    *kind
                );
                crate::assert_with_log!(
                    *state == crate::record::ObligationState::Committed,
                    "state",
                    crate::record::ObligationState::Committed,
                    *state
                );
                crate::assert_with_log!(
                    duration_ns == &Some(15),
                    "duration",
                    &Some(15),
                    duration_ns
                );
                crate::assert_with_log!(
                    abort_reason.is_none(),
                    "abort_reason",
                    &None::<crate::record::ObligationAbortReason>,
                    abort_reason
                );
            }
            other => panic!("unexpected commit data: {other:?}"),
        }

        let abort_event = runtime
            .trace()
            .snapshot()
            .into_iter()
            .find(|e| e.kind == TraceEventKind::ObligationAbort)
            .expect("abort event");
        match &abort_event.data {
            TraceData::Obligation {
                obligation,
                task,
                region,
                kind,
                state,
                duration_ns,
                abort_reason,
            } => {
                crate::assert_with_log!(*obligation == ob2, "obligation", ob2, *obligation);
                crate::assert_with_log!(*task == task_id, "task", task_id, *task);
                crate::assert_with_log!(*region == root, "region", root, *region);
                crate::assert_with_log!(
                    *kind == ObligationKind::Ack,
                    "kind",
                    ObligationKind::Ack,
                    *kind
                );
                crate::assert_with_log!(
                    *state == crate::record::ObligationState::Aborted,
                    "state",
                    crate::record::ObligationState::Aborted,
                    *state
                );
                crate::assert_with_log!(
                    duration_ns == &Some(20),
                    "duration",
                    &Some(20),
                    duration_ns
                );
                crate::assert_with_log!(
                    abort_reason == &Some(ObligationAbortReason::Cancel),
                    "abort_reason",
                    &Some(ObligationAbortReason::Cancel),
                    abort_reason
                );
            }
            other => panic!("unexpected abort data: {other:?}"),
        }
        crate::test_complete!("obligation_trace_events_emitted");
    }

    #[test]
    fn obligation_leak_emits_trace_event() {
        init_test("obligation_leak_emits_trace_event");
        let mut runtime = LabRuntime::with_seed(22);
        let root = runtime.state.create_root_region(Budget::INFINITE);

        let task_idx = runtime.state.insert_task(TaskRecord::new(
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            root,
            Budget::INFINITE,
        ));
        let task_id = TaskId::from_arena(task_idx);
        runtime.state.task_mut(task_id).unwrap().id = task_id;

        runtime.advance_time_to(Time::from_nanos(100));
        let obligation = runtime
            .state
            .create_obligation(ObligationKind::Lease, task_id, root, None)
            .unwrap();

        runtime.advance_time_to(Time::from_nanos(140));
        runtime
            .state
            .update_task(task_id, |record| record.complete(Outcome::Ok(())))
            .unwrap();

        let violations = runtime.check_invariants();
        let has_leak = violations
            .iter()
            .any(|v| matches!(v, InvariantViolation::ObligationLeak { .. }));
        crate::assert_with_log!(has_leak, "has leak", true, has_leak);

        let leak_event = runtime
            .trace()
            .snapshot()
            .into_iter()
            .find(|e| e.kind == TraceEventKind::ObligationLeak)
            .expect("leak event");
        match &leak_event.data {
            TraceData::Obligation {
                obligation: leaked,
                task,
                region,
                kind,
                state,
                duration_ns,
                abort_reason,
            } => {
                crate::assert_with_log!(*leaked == obligation, "obligation", obligation, *leaked);
                crate::assert_with_log!(*task == task_id, "task", task_id, *task);
                crate::assert_with_log!(*region == root, "region", root, *region);
                crate::assert_with_log!(
                    *kind == ObligationKind::Lease,
                    "kind",
                    ObligationKind::Lease,
                    *kind
                );
                crate::assert_with_log!(
                    *state == crate::record::ObligationState::Leaked,
                    "state",
                    crate::record::ObligationState::Leaked,
                    *state
                );
                crate::assert_with_log!(
                    duration_ns == &Some(40),
                    "duration",
                    &Some(40),
                    duration_ns
                );
                crate::assert_with_log!(
                    abort_reason.is_none(),
                    "abort_reason",
                    &None::<crate::record::ObligationAbortReason>,
                    abort_reason
                );
            }
            other => panic!("unexpected leak data: {other:?}"),
        }
        crate::test_complete!("obligation_leak_emits_trace_event");
    }

    // =========================================================================
    // Agent Report Contract tests (bd-f262i)
    // =========================================================================

    /// The JSON schema must contain all required top-level keys.
    #[test]
    fn contract_json_has_required_top_level_keys() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("contract_json_has_required_top_level_keys");

        let app = crate::app::AppSpec::new("contract_test");
        let harness = crate::lab::SporkAppHarness::with_seed(42, app).unwrap();
        let report = harness.run_to_report().unwrap();
        let json = report.to_json();

        // Required top-level keys per bd-f262i contract.
        let required_keys = [
            "schema_version",
            "verdict",
            "app",
            "lab",
            "fingerprints",
            "run",
            "crashpack",
            "attachments",
        ];
        for key in &required_keys {
            assert!(
                json.get(key).is_some(),
                "missing required top-level key: {key}"
            );
        }

        // Nested required keys.
        assert!(json["app"]["name"].is_string(), "app.name must be a string");
        assert!(
            json["lab"]["config"].is_object(),
            "lab.config must be an object"
        );
        assert!(
            json["lab"]["config_hash"].is_u64(),
            "lab.config_hash must be a u64"
        );
        assert!(
            json["fingerprints"]["trace"].is_u64(),
            "fingerprints.trace must be a u64"
        );
        assert!(
            json["fingerprints"]["event_hash"].is_u64(),
            "fingerprints.event_hash must be a u64"
        );
        assert!(
            json["fingerprints"]["event_count"].is_u64(),
            "fingerprints.event_count must be a u64"
        );
        assert!(
            json["fingerprints"]["schedule_hash"].is_u64(),
            "fingerprints.schedule_hash must be a u64"
        );
        assert!(json["run"]["seed"].is_u64(), "run.seed must be a u64");
        assert!(
            json["run"]["oracles"].is_object(),
            "run.oracles must be an object"
        );
        assert!(
            json["run"]["invariants"].is_array(),
            "run.invariants must be an array"
        );
        assert!(
            json["run"]["refinement_firewall"].is_object(),
            "run.refinement_firewall must be an object"
        );
        assert!(
            json["run"]["refinement_firewall"]["skipped_due_to_trace_truncation"].is_boolean(),
            "run.refinement_firewall.skipped_due_to_trace_truncation must be a boolean"
        );
        assert!(
            json["attachments"].is_array(),
            "attachments must be an array"
        );
        assert!(
            json["crashpack"].is_null(),
            "passing runs should have null crashpack linkage"
        );

        crate::test_complete!("contract_json_has_required_top_level_keys");
    }

    /// Schema version must be the current constant.
    #[test]
    fn contract_schema_version_is_current() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("contract_schema_version_is_current");

        let app = crate::app::AppSpec::new("version_test");
        let harness = crate::lab::SporkAppHarness::with_seed(1, app).unwrap();
        let report = harness.run_to_report().unwrap();

        assert_eq!(report.schema_version, SporkHarnessReport::SCHEMA_VERSION);
        assert_eq!(
            report.to_json()["schema_version"],
            SporkHarnessReport::SCHEMA_VERSION
        );

        crate::test_complete!("contract_schema_version_is_current");
    }

    /// Config hash is deterministic: same config -> same hash.
    #[test]
    fn contract_config_hash_deterministic() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("contract_config_hash_deterministic");

        let config = LabConfig::new(42);
        let summary_a = LabConfigSummary::from_config(&config);
        let summary_b = LabConfigSummary::from_config(&config);

        assert_eq!(summary_a.config_hash(), summary_b.config_hash());

        // Different seed -> different hash.
        let config_2 = LabConfig::new(99);
        let summary_c = LabConfigSummary::from_config(&config_2);
        assert_ne!(summary_a.config_hash(), summary_c.config_hash());

        crate::test_complete!("contract_config_hash_deterministic");
    }

    /// Verdict field correctly reflects pass/fail.
    #[test]
    fn contract_verdict_reflects_oracle_state() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("contract_verdict_reflects_oracle_state");

        let app = crate::app::AppSpec::new("verdict_test");
        let harness = crate::lab::SporkAppHarness::with_seed(42, app).unwrap();
        let report = harness.run_to_report().unwrap();

        // Empty app should pass.
        assert!(report.passed());
        assert_eq!(report.to_json()["verdict"], "pass");
        assert!(report.summary_line().starts_with("[PASS]"));

        let mut truncated = report.clone();
        truncated.run.quiescent = false;
        assert!(!truncated.passed());
        assert_eq!(truncated.to_json()["verdict"], "fail");
        assert!(truncated.summary_line().starts_with("[FAIL]"));
        let runtime = LabRuntime::with_seed(42);
        assert!(runtime.build_crashpack_for_report(&truncated.run).is_some());

        crate::test_complete!("contract_verdict_reflects_oracle_state");
    }

    #[test]
    fn crashpack_prefers_failed_terminal_task_over_live_task() {
        init_test("crashpack_prefers_failed_terminal_task_over_live_task");
        let mut runtime = LabRuntime::with_seed(0x4b_78);
        let root = runtime.state.create_root_region(Budget::INFINITE);

        let live_idx = runtime.state.insert_task(TaskRecord::new(
            TaskId::testing_default(),
            root,
            Budget::INFINITE,
        ));
        let live_task = TaskId::from_arena(live_idx);
        runtime.state.task_mut(live_task).unwrap().id = live_task;

        let failed_idx = runtime.state.insert_task(TaskRecord::new(
            TaskId::testing_default(),
            root,
            Budget::INFINITE,
        ));
        let failed_task = TaskId::from_arena(failed_idx);
        runtime.state.task_mut(failed_task).unwrap().id = failed_task;
        runtime
            .state
            .update_task(failed_task, |record| {
                record.complete(Outcome::Panicked(crate::types::PanicPayload::new(
                    "intentional crashpack attribution panic",
                )))
            })
            .expect("complete failed task");

        let report = runtime.report();
        let crashpack = runtime
            .build_crashpack_for_report(&report)
            .expect("live task should make the report fail");
        assert_eq!(crashpack.failure.task, failed_task);
        assert_eq!(crashpack.failure.region, root);
        assert!(matches!(
            crashpack.failure.outcome,
            FailureOutcome::Panicked { ref message }
                if message == "intentional crashpack attribution panic"
        ));
        crate::test_complete!("crashpack_prefers_failed_terminal_task_over_live_task");
    }

    #[test]
    fn crashpack_preserves_cancelled_terminal_task_kind() {
        init_test("crashpack_preserves_cancelled_terminal_task_kind");
        let mut runtime = LabRuntime::with_seed(0x4b_79);
        let root = runtime.state.create_root_region(Budget::INFINITE);

        let live_idx = runtime.state.insert_task(TaskRecord::new(
            TaskId::testing_default(),
            root,
            Budget::INFINITE,
        ));
        let live_task = TaskId::from_arena(live_idx);
        runtime.state.task_mut(live_task).unwrap().id = live_task;

        let cancelled_idx = runtime.state.insert_task(TaskRecord::new(
            TaskId::testing_default(),
            root,
            Budget::INFINITE,
        ));
        let cancelled_task = TaskId::from_arena(cancelled_idx);
        runtime.state.task_mut(cancelled_task).unwrap().id = cancelled_task;
        runtime
            .state
            .update_task(cancelled_task, |record| {
                record.complete(Outcome::Cancelled(crate::types::CancelReason::timeout()))
            })
            .expect("complete cancelled task");

        let report = runtime.report();
        let crashpack = runtime
            .build_crashpack_for_report(&report)
            .expect("live task should make the report fail");
        assert_eq!(crashpack.failure.task, cancelled_task);
        assert_eq!(crashpack.failure.region, root);
        assert_eq!(
            crashpack.failure.outcome,
            FailureOutcome::Cancelled {
                cancel_kind: crate::types::CancelKind::Timeout,
            }
        );
        crate::test_complete!("crashpack_preserves_cancelled_terminal_task_kind");
    }

    const PLAIN_RUNNER_FAILURE_PROBE: &str = "lab::runtime::tests::plain_runner_failure_probe";
    const PLAIN_RUNNER_FAILURE_SEED: u64 = 0x4b78_0003;

    fn trigger_plain_runner_failure_probe() {
        panic!("intentional plain-runner failure probe"); // ubs:ignore — deliberate subprocess failure injection in a test-only helper
    }

    #[test]
    #[ignore = "subprocess-only probe for plain-runner crashpack emission"]
    fn plain_runner_failure_probe() {
        if std::env::var_os(PLAIN_RUNNER_FAILURE_PROBE_ENV).is_none() {
            return;
        }
        let _ = run_async_under_lab(PLAIN_RUNNER_FAILURE_SEED, |_cx| async move {
            trigger_plain_runner_failure_probe();
        });
    }

    #[test]
    fn plain_runner_failure_writes_crashpack() {
        init_test("plain_runner_failure_writes_crashpack");
        let now = std::time::SystemTime::now(); // ubs:ignore — test-directory uniqueness only, not a security token
        let nonce = now
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock after Unix epoch")
            .as_nanos();
        let artifact_root = std::env::temp_dir().join(format!(
            "asupersync-fgdb-4bxh-{}-{nonce}",
            std::process::id()
        ));
        let output = std::process::Command::new(std::env::current_exe().expect("test binary"))
            .args([
                "--ignored",
                "--exact",
                PLAIN_RUNNER_FAILURE_PROBE,
                "--nocapture",
            ])
            .env(AUTO_ARTIFACTS_ENV, "1")
            .env(TEST_ARTIFACTS_DIR_ENV, &artifact_root)
            .env(PLAIN_RUNNER_FAILURE_PROBE_ENV, "1")
            .env_remove(LAB_TEST_SEED_ENV)
            .env_remove(LAB_TEST_WORKERS_ENV)
            .env_remove(LAB_TEST_MAX_STEPS_ENV)
            .output()
            .expect("run plain-runner failure probe");
        assert!(!output.status.success(), "failure probe must fail");

        let mut transcript = String::from_utf8_lossy(&output.stdout).into_owned();
        transcript.push_str(&String::from_utf8_lossy(&output.stderr));
        assert!(
            transcript.contains(&format!("seed {PLAIN_RUNNER_FAILURE_SEED}")),
            "failure transcript must name the replay seed: {transcript}"
        );
        let crashpack_path = transcript
            .lines()
            .find_map(|line| line.trim().strip_prefix("crashpack: "))
            .expect("failure transcript must name the crashpack path");
        assert!(
            std::path::Path::new(crashpack_path).is_file(),
            "crashpack path must exist: {crashpack_path}"
        );
        let crashpack_json = std::fs::read_to_string(crashpack_path)
            .expect("plain-runner crashpack must be readable");
        let crashpack: serde_json::Value =
            serde_json::from_str(&crashpack_json).expect("plain-runner crashpack JSON");
        assert_eq!(
            crashpack["manifest"]["config"]["seed"],
            PLAIN_RUNNER_FAILURE_SEED
        );
        assert_eq!(
            crashpack["failure"]["outcome"]["Panicked"]["message"].as_str(),
            Some("intentional plain-runner failure probe")
        );
        crate::test_complete!("plain_runner_failure_writes_crashpack");
    }

    #[test]
    fn join_error_crashpack_outcome_preserves_kind_and_payload() {
        init_test("join_error_crashpack_outcome_preserves_kind_and_payload");
        let cancelled = crate::runtime::JoinError::Cancelled(crate::types::CancelReason::timeout());
        assert_eq!(
            failure_outcome_from_join_error(&cancelled),
            FailureOutcome::Cancelled {
                cancel_kind: crate::types::CancelKind::Timeout,
            }
        );

        let panicked = crate::runtime::JoinError::Panicked(crate::types::PanicPayload::new(
            "exact panic payload",
        ));
        assert_eq!(
            failure_outcome_from_join_error(&panicked),
            FailureOutcome::Panicked {
                message: "exact panic payload".to_owned(),
            }
        );
        crate::test_complete!("join_error_crashpack_outcome_preserves_kind_and_payload");
    }

    /// Agent UX convenience methods return consistent values.
    #[test]
    fn contract_convenience_methods_consistent() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("contract_convenience_methods_consistent");

        let app = crate::app::AppSpec::new("ux_test");
        let harness = crate::lab::SporkAppHarness::with_seed(42, app).unwrap();
        let report = harness.run_to_report().unwrap();
        let json = report.to_json();

        // trace_fingerprint() matches JSON.
        assert_eq!(
            report.trace_fingerprint(),
            json["fingerprints"]["trace"].as_u64().unwrap()
        );

        // seed() matches JSON.
        assert_eq!(report.seed(), json["run"]["seed"].as_u64().unwrap());

        // config_hash() matches JSON.
        assert_eq!(
            report.config_hash(),
            json["lab"]["config_hash"].as_u64().unwrap()
        );

        // No crashpack by default.
        assert!(report.crashpack_path().is_none());

        // Empty app -> no oracle failures.
        assert!(report.oracle_failures().is_empty());

        crate::test_complete!("contract_convenience_methods_consistent");
    }

    /// Failing runs auto-attach a deterministic crashpack reference.
    #[test]
    fn contract_auto_crashpack_on_failure() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("contract_auto_crashpack_on_failure");

        let config = LabConfig::new(17).panic_on_leak(false);
        let mut runtime = LabRuntime::new(config);
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let (task, _) = runtime
            .state
            .create_task(region, Budget::INFINITE, async {})
            .expect("create task");
        runtime.scheduler.lock().schedule(task, 0);
        // Create the obligation while the task is still live, then run to
        // quiescence so the task completes without resolving it (intentional leak).
        runtime
            .state
            .create_obligation(
                ObligationKind::SendPermit,
                task,
                region,
                Some("intentional leak".to_string()),
            )
            .expect("create obligation");
        runtime.run_until_quiescent();

        let report = runtime.spork_report("failing_app", Vec::new());
        assert!(!report.passed(), "failing run must not report PASS");
        let crashpack_path = report
            .crashpack_path()
            .expect("failing run should include crashpack attachment");
        assert!(
            crashpack_path.starts_with("crashpack-"),
            "unexpected crashpack path: {crashpack_path}"
        );
        assert!(
            report
                .attachments
                .iter()
                .any(|attachment| attachment.kind == HarnessAttachmentKind::CrashPack),
            "crashpack attachment kind must be present"
        );
        let crashpack_link = report
            .crashpack_link()
            .expect("failing run should expose crashpack link metadata");
        assert_eq!(crashpack_link.path, crashpack_path);
        assert_eq!(crashpack_link.fingerprint, report.trace_fingerprint());
        assert!(
            crashpack_link.id.starts_with("crashpack-"),
            "unexpected crashpack id: {}",
            crashpack_link.id
        );
        assert!(
            crashpack_link.replay.command_line.contains(crashpack_path),
            "replay command should include crashpack path"
        );

        crate::test_complete!("contract_auto_crashpack_on_failure");
    }

    /// Failing runs with replay recording enabled include a deterministic
    /// divergent prefix in the auto-built crashpack.
    #[test]
    fn contract_auto_crashpack_contains_divergent_prefix_when_replay_enabled() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("contract_auto_crashpack_contains_divergent_prefix_when_replay_enabled");

        let config = LabConfig::new(1701)
            .panic_on_leak(false)
            .with_default_replay_recording();
        let mut runtime = LabRuntime::new(config);
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let (task, _) = runtime
            .state
            .create_task(region, Budget::INFINITE, async {})
            .expect("create task");
        runtime.scheduler.lock().schedule(task, 0);
        runtime
            .state
            .create_obligation(
                ObligationKind::SendPermit,
                task,
                region,
                Some("intentional leak".to_string()),
            )
            .expect("create obligation");
        runtime.run_until_quiescent();

        let run = runtime.report();
        let crashpack = runtime
            .build_crashpack_for_report(&run)
            .expect("failing run should build crashpack");

        assert!(crashpack.has_divergent_prefix());
        assert!(
            crashpack
                .manifest
                .has_attachment(&crate::trace::crashpack::AttachmentKind::DivergentPrefix),
            "manifest must include divergent prefix attachment"
        );
        assert!(
            crashpack.replay.is_some(),
            "crashpack should carry replay command metadata"
        );

        crate::test_complete!(
            "contract_auto_crashpack_contains_divergent_prefix_when_replay_enabled"
        );
    }

    /// Manual crashpack attachments are preserved without auto-duplication.
    #[test]
    fn contract_manual_crashpack_not_duplicated_on_failure() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("contract_manual_crashpack_not_duplicated_on_failure");

        let config = LabConfig::new(18).panic_on_leak(false);
        let mut runtime = LabRuntime::new(config);
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let (task, _) = runtime
            .state
            .create_task(region, Budget::INFINITE, async {})
            .expect("create task");
        runtime.scheduler.lock().schedule(task, 0);
        runtime
            .state
            .create_obligation(
                ObligationKind::SendPermit,
                task,
                region,
                Some("intentional leak".to_string()),
            )
            .expect("create obligation");
        runtime.run_until_quiescent();

        let report = runtime.spork_report(
            "failing_app_manual",
            vec![HarnessAttachmentRef::crashpack("manual-crashpack.json")],
        );
        let crashpack_count = report
            .attachments
            .iter()
            .filter(|attachment| attachment.kind == HarnessAttachmentKind::CrashPack)
            .count();
        assert_eq!(
            crashpack_count, 1,
            "manual crashpack should not be duplicated"
        );
        assert_eq!(report.crashpack_path(), Some("manual-crashpack.json"));
        let crashpack_link = report
            .crashpack_link()
            .expect("manual crashpack should still produce metadata");
        assert_eq!(crashpack_link.path, "manual-crashpack.json");
        assert!(
            crashpack_link
                .replay
                .command_line
                .contains("manual-crashpack.json"),
            "replay command should include manual crashpack path"
        );

        crate::test_complete!("contract_manual_crashpack_not_duplicated_on_failure");
    }

    /// JSON output is deterministic across runs with same seed.
    #[test]
    fn contract_json_deterministic_same_seed() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("contract_json_deterministic_same_seed");

        let json_a = {
            let app = crate::app::AppSpec::new("det_contract");
            let harness = crate::lab::SporkAppHarness::with_seed(42, app).unwrap();
            harness.run_to_report().unwrap().to_json()
        };

        let json_b = {
            let app = crate::app::AppSpec::new("det_contract");
            let harness = crate::lab::SporkAppHarness::with_seed(42, app).unwrap();
            harness.run_to_report().unwrap().to_json()
        };

        // The canonical Foata `trace_fingerprint` is the semantic determinism
        // signal. The sequential `event_hash` additionally embeds per-event
        // data (e.g. ephemeral IDs allocated from process-global counters)
        // that benignly drifts across invocations in the same process even
        // for the same seed. Normalise it before comparing so the assertion
        // targets what the test actually contracts for ("same seed →
        // equivalent run artefact") rather than incidental monotonic counters.
        fn strip_event_hash(obj: &mut serde_json::Map<String, serde_json::Value>) {
            if obj.contains_key("event_hash") {
                obj.insert("event_hash".into(), serde_json::Value::Null);
            }
            for val in obj.values_mut() {
                if let Some(sub) = val.as_object_mut() {
                    strip_event_hash(sub);
                }
            }
        }
        let normalize = |mut v: serde_json::Value| -> serde_json::Value {
            if let Some(obj) = v.as_object_mut() {
                strip_event_hash(obj);
            }
            v
        };

        assert_eq!(
            normalize(json_a),
            normalize(json_b),
            "same seed must produce identical JSON (mod sequential event_hash)",
        );

        crate::test_complete!("contract_json_deterministic_same_seed");
    }

    /// Attachments appear in the report, sorted by (kind, path).
    #[test]
    fn contract_attachments_sorted_in_json() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("contract_attachments_sorted_in_json");

        let app = crate::app::AppSpec::new("attach_contract");
        let mut harness = crate::lab::SporkAppHarness::with_seed(7, app).unwrap();
        // Add in reverse order to verify sorting.
        harness.attach(HarnessAttachmentRef::trace("z_trace.json"));
        harness.attach(HarnessAttachmentRef::crashpack("a_crash.tar"));

        let report = harness.run_to_report().unwrap();

        // crashpack_path() returns the crashpack.
        assert_eq!(report.crashpack_path(), Some("a_crash.tar"));

        let json = report.to_json();
        let attachments = json["attachments"].as_array().unwrap();
        assert_eq!(attachments.len(), 2);

        // CrashPack sorts before Trace (enum ordering).
        assert_eq!(attachments[0]["kind"], "crashpack");
        assert_eq!(attachments[1]["kind"], "trace");

        crate::test_complete!("contract_attachments_sorted_in_json");
    }

    // =========================================================================
    // Virtual Time Control Tests (bd-1hu19.3)
    // =========================================================================

    #[asupersync::lab_test(seeds = 42..43)]
    fn advance_to_next_timer_empty(runtime: &mut LabRuntime) {
        let wakeups = runtime.advance_to_next_timer();
        crate::assert_with_log!(wakeups == 0, "no timers → 0 wakeups", 0, wakeups);

        let deadline = runtime.next_timer_deadline();
        crate::assert_with_log!(
            deadline.is_none(),
            "no pending deadline",
            true,
            deadline.is_none()
        );
    }

    #[test]
    fn advance_to_next_timer_fires_timer() {
        init_test("advance_to_next_timer_fires_timer");
        let mut runtime = LabRuntime::with_seed(42);

        // Register a timer at t=1s via the timer driver handle
        let timer_handle = runtime.state.timer_driver_handle().unwrap();
        let woken = Arc::new(std::sync::atomic::AtomicBool::new(false));

        let waker = Waker::from(Arc::new(FlagWaker(woken.clone())));
        let _ = timer_handle.register(Time::from_secs(1), waker);

        // Should have 1 pending timer
        let count = runtime.pending_timer_count();
        crate::assert_with_log!(count == 1, "1 pending timer", 1, count);

        // Advance to next timer
        let wakeups = runtime.advance_to_next_timer();
        crate::assert_with_log!(wakeups == 1, "1 wakeup", 1, wakeups);

        // Time should now be at 1 second
        let now = runtime.now();
        crate::assert_with_log!(
            now == Time::from_secs(1),
            "time at 1s",
            Time::from_secs(1),
            now
        );

        // Waker should have been called
        let was_woken = woken.load(std::sync::atomic::Ordering::SeqCst);
        crate::assert_with_log!(was_woken, "waker fired", true, was_woken);
        crate::test_complete!("advance_to_next_timer_fires_timer");
    }

    #[test]
    fn metamorphic_timer_registration_permutation_preserves_virtual_time_progression() {
        init_test("metamorphic_timer_registration_permutation_preserves_virtual_time_progression");

        let baseline = collect_timer_advances(&[5, 1, 3, 1, 8], &[]);
        let permuted = collect_timer_advances(&[1, 8, 5, 1, 3], &[]);

        crate::assert_with_log!(
            baseline.advance_points == permuted.advance_points,
            "deadline multiset permutation preserves advance points",
            &baseline.advance_points,
            &permuted.advance_points
        );
        crate::assert_with_log!(
            baseline.total_wakeups == permuted.total_wakeups,
            "deadline multiset permutation preserves wakeup count",
            baseline.total_wakeups,
            permuted.total_wakeups
        );
        crate::assert_with_log!(
            baseline.final_time == permuted.final_time,
            "deadline multiset permutation preserves final virtual time",
            baseline.final_time,
            permuted.final_time
        );
        crate::assert_with_log!(
            baseline.advance_points
                == vec![
                    Time::from_secs(1),
                    Time::from_secs(3),
                    Time::from_secs(5),
                    Time::from_secs(8)
                ],
            "advance points collapse duplicate deadlines without moving backward",
            vec![
                Time::from_secs(1),
                Time::from_secs(3),
                Time::from_secs(5),
                Time::from_secs(8)
            ],
            baseline.advance_points.clone()
        );

        crate::test_complete!(
            "metamorphic_timer_registration_permutation_preserves_virtual_time_progression"
        );
    }

    #[test]
    fn metamorphic_cancelled_timer_does_not_skew_virtual_time_progression() {
        init_test("metamorphic_cancelled_timer_does_not_skew_virtual_time_progression");

        let baseline = collect_timer_advances(&[2, 4, 9], &[]);
        let with_cancelled_timer = collect_timer_advances(&[2, 4, 6, 9], &[2]);

        crate::assert_with_log!(
            baseline.advance_points == with_cancelled_timer.advance_points,
            "cancelling an intermediate timer preserves surviving advance points",
            &baseline.advance_points,
            &with_cancelled_timer.advance_points
        );
        crate::assert_with_log!(
            baseline.total_wakeups == with_cancelled_timer.total_wakeups,
            "cancelling an intermediate timer preserves surviving wakeup count",
            baseline.total_wakeups,
            with_cancelled_timer.total_wakeups
        );
        crate::assert_with_log!(
            baseline.final_time == with_cancelled_timer.final_time,
            "cancelling an intermediate timer preserves final virtual time",
            baseline.final_time,
            with_cancelled_timer.final_time
        );
        crate::assert_with_log!(
            with_cancelled_timer.cancelled_wakeups == 0,
            "cancelled timer never wakes after auto-advance",
            0u64,
            with_cancelled_timer.cancelled_wakeups
        );

        crate::test_complete!("metamorphic_cancelled_timer_does_not_skew_virtual_time_progression");
    }

    #[cfg(unix)]
    #[test]
    fn run_with_auto_advance_delivers_delayed_reactor_events() {
        init_test("run_with_auto_advance_delivers_delayed_reactor_events");
        let config = LabConfig::new(42).with_auto_advance().max_steps(32);
        let mut runtime = LabRuntime::new(config);
        let handle = runtime.state.io_driver_handle().expect("io driver");
        let wake_count = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let waker = Waker::from(Arc::new(CountWaker(wake_count.clone())));
        let source = TestFdSource;

        let registration = handle
            .register(&source, Interest::READABLE, waker)
            .expect("register source");
        let token = registration.token();

        runtime
            .lab_reactor()
            .inject_event(token, Event::readable(token), Duration::from_secs(1));

        let report = runtime.run_with_auto_advance();

        crate::assert_with_log!(
            report.auto_advances >= 1,
            "auto-advance reaches delayed reactor deadline",
            true,
            report.auto_advances >= 1
        );
        crate::assert_with_log!(
            runtime.now() >= Time::from_secs(1),
            "virtual time advanced to delayed reactor event",
            true,
            runtime.now() >= Time::from_secs(1)
        );
        let wakeups = wake_count.load(std::sync::atomic::Ordering::SeqCst);
        crate::assert_with_log!(
            wakeups == 1,
            "reactor event woke registration",
            1u64,
            wakeups
        );
        let saw_ready = runtime
            .state
            .trace
            .snapshot()
            .iter()
            .any(|event| event.kind == TraceEventKind::IoReady);
        crate::assert_with_log!(saw_ready, "io ready trace recorded", true, saw_ready);
        let next_event = runtime.lab_reactor().next_event_time();
        crate::assert_with_log!(
            next_event.is_none(),
            "delayed reactor event drained",
            true,
            next_event.is_none()
        );

        crate::test_complete!("run_with_auto_advance_delivers_delayed_reactor_events");
    }

    #[test]
    fn run_with_auto_advance_basic() {
        init_test("run_with_auto_advance_basic");
        let config = LabConfig::new(42).with_auto_advance();
        let mut runtime = LabRuntime::new(config);

        // No tasks, no timers → immediate quiescence
        let report = runtime.run_with_auto_advance();
        crate::assert_with_log!(report.steps == 0, "0 steps", 0u64, report.steps);
        crate::assert_with_log!(
            report.auto_advances == 0,
            "0 auto-advances",
            0u64,
            report.auto_advances
        );
        crate::test_complete!("run_with_auto_advance_basic");
    }

    #[test]
    fn run_with_auto_advance_jumps_past_timer_deadlines() {
        init_test("run_with_auto_advance_jumps_past_timer_deadlines");
        let config = LabConfig::new(42).with_auto_advance().max_steps(1_000);
        let mut runtime = LabRuntime::new(config);

        // Register timers at 1s, 5s, and 10s via timer driver
        let timer_handle = runtime.state.timer_driver_handle().unwrap();
        let wake_count = Arc::new(std::sync::atomic::AtomicU64::new(0));

        for secs in [1, 5, 10] {
            let waker = Waker::from(Arc::new(CountWaker(wake_count.clone())));
            let _ = timer_handle.register(Time::from_secs(secs), waker);
        }

        let report = runtime.run_with_auto_advance();

        // All 3 timer deadlines should have been auto-advanced to
        crate::assert_with_log!(
            report.auto_advances >= 3,
            "at least 3 auto-advances",
            true,
            report.auto_advances >= 3
        );

        // Virtual time should be at or past 10 seconds
        let now = runtime.now();
        crate::assert_with_log!(
            now >= Time::from_secs(10),
            "time >= 10s",
            true,
            now >= Time::from_secs(10)
        );

        // All wakers should have been called
        let count = wake_count.load(std::sync::atomic::Ordering::SeqCst);
        crate::assert_with_log!(count == 3, "3 wakeups", 3u64, count);
        crate::test_complete!("run_with_auto_advance_jumps_past_timer_deadlines");
    }

    #[test]
    fn virtual_time_24_hour_instant_test() {
        init_test("virtual_time_24_hour_instant_test");
        // Acceptance criterion: 24 hours of virtual time in <1 second wall time.
        let config = LabConfig::new(42).with_auto_advance().max_steps(100_000);
        let mut runtime = LabRuntime::new(config);

        // Register timers spread across 24 hours (every hour)
        let timer_handle = runtime.state.timer_driver_handle().unwrap();
        let wake_count = Arc::new(std::sync::atomic::AtomicU64::new(0));

        for hour in 1..=24 {
            let waker = Waker::from(Arc::new(CountWaker(wake_count.clone())));
            let _ = timer_handle.register(Time::from_secs(hour * 3600), waker);
        }

        let wall_start = std::time::Instant::now();
        let report = runtime.run_with_auto_advance();
        let wall_elapsed = wall_start.elapsed();

        // Virtual time should span 24 hours = 86400 seconds
        crate::assert_with_log!(
            report.virtual_elapsed_secs() >= 86400,
            "24h virtual",
            true,
            report.virtual_elapsed_secs() >= 86400
        );

        // All 24 timers fired
        let count = wake_count.load(std::sync::atomic::Ordering::SeqCst);
        crate::assert_with_log!(count == 24, "24 wakeups", 24u64, count);

        // Wall time should be well under 1 second (typically <1ms)
        let wall_ms = wall_elapsed.as_millis();
        crate::assert_with_log!(wall_ms < 1000, "wall time < 1s", true, wall_ms < 1000);
        crate::test_complete!("virtual_time_24_hour_instant_test");
    }

    #[asupersync::lab_test(seeds = 42..43)]
    fn clock_pause_resume(runtime: &mut LabRuntime) {
        let not_paused = !runtime.is_clock_paused();
        crate::assert_with_log!(not_paused, "not paused initially", true, not_paused);

        runtime.pause_clock();
        let paused = runtime.is_clock_paused();
        crate::assert_with_log!(paused, "paused", true, paused);

        runtime.resume_clock();
        let resumed = !runtime.is_clock_paused();
        crate::assert_with_log!(resumed, "resumed", true, resumed);
    }

    #[asupersync::lab_test(seeds = 42..43)]
    fn inject_clock_skew(runtime: &mut LabRuntime) {
        runtime.advance_time(1_000_000_000); // 1 second
        let before = runtime.now();

        // Inject 5 second skew
        runtime.inject_clock_skew(5_000_000_000);
        let after = runtime.now();

        let delta = after.as_nanos() - before.as_nanos();
        crate::assert_with_log!(
            delta == 5_000_000_000,
            "5s skew applied",
            5_000_000_000u64,
            delta
        );

        crate::assert_with_log!(
            after == Time::from_secs(6),
            "time at 6s",
            Time::from_secs(6),
            after
        );
    }

    #[test]
    fn virtual_time_report_conversions() {
        init_test("virtual_time_report_conversions");
        let report = VirtualTimeReport {
            steps: 100,
            auto_advances: 5,
            total_wakeups: 10,
            time_start: Time::ZERO,
            time_end: Time::from_secs(3600),
            virtual_elapsed_nanos: 3_600_000_000_000,
            termination: AutoAdvanceTermination::Quiescent,
        };

        let ms = report.virtual_elapsed_ms();
        crate::assert_with_log!(ms == 3_600_000, "3600000 ms", 3_600_000u64, ms);

        let secs = report.virtual_elapsed_secs();
        crate::assert_with_log!(secs == 3600, "3600 secs", 3600u64, secs);
        crate::test_complete!("virtual_time_report_conversions");
    }

    // =========================================================================
    // Replay severity correctness (bd-beuyd)
    // =========================================================================

    fn forced_schedule_fixture(config: LabConfig, observations: Arc<Mutex<Vec<u8>>>) -> LabRuntime {
        let mut runtime = LabRuntime::new(config);
        let root = runtime.state.create_root_region(Budget::INFINITE);
        for label in 0..3u8 {
            let observations = Arc::clone(&observations);
            let (task, _handle) = runtime
                .state
                .create_task(root, Budget::INFINITE, async move {
                    observations.lock().push(label);
                    futures_lite::future::yield_now().await;
                    observations.lock().push(label + 10);
                })
                .expect("create forced-schedule fixture task");
            runtime.scheduler.lock().schedule(task, label);
        }
        runtime
    }

    #[test]
    fn forced_schedule_artifact_codec_is_canonical_bounded_and_replayable() {
        init_test("forced_schedule_artifact_codec_is_canonical_bounded_and_replayable");

        fn rewrite_checksum(bytes: &mut [u8]) {
            let checksum_offset = bytes
                .len()
                .checked_sub(FORCED_SCHEDULE_ARTIFACT_CHECKSUM_LEN)
                .expect("canonical artifact contains checksum");
            let checksum = forced_schedule_artifact_checksum(&bytes[..checksum_offset]);
            bytes[checksum_offset..].copy_from_slice(&checksum);
        }

        fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
            bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }

        fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
            bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }

        let config = LabConfig::new(0xF0CE_D5CE).worker_count(2).max_steps(128);
        let source_observations = Arc::new(Mutex::new(Vec::new()));
        let mut source = forced_schedule_fixture(config.clone(), Arc::clone(&source_observations));
        source
            .start_forced_schedule_recording(32)
            .expect("start complete dispatch capture");
        let source_report = source.run_until_quiescent_with_report();
        assert!(source_report.quiescent);
        let schedule = source
            .finish_forced_schedule_recording()
            .expect("complete source schedule");
        assert_eq!(schedule.dispatches().len(), 6);

        let canonical = schedule
            .to_canonical_bytes()
            .expect("encode complete source schedule");
        let decoded_dispatch_bytes =
            schedule.dispatches().len() * std::mem::size_of::<ForcedDispatch>();
        let decode_limits =
            ForcedScheduleDecodeLimits::new(canonical.len(), 32, decoded_dispatch_bytes);
        assert_eq!(
            canonical.len(),
            FORCED_SCHEDULE_ARTIFACT_HEADER_LEN
                + 6 * FORCED_SCHEDULE_ARTIFACT_DISPATCH_LEN
                + FORCED_SCHEDULE_ARTIFACT_TERMINAL_LEN
                + FORCED_SCHEDULE_ARTIFACT_CHECKSUM_LEN
        );
        let decoded = ForcedSchedule::try_from_canonical_bytes(&canonical, decode_limits)
            .expect("decode canonical schedule");
        assert_eq!(decoded, schedule);
        assert_eq!(
            decoded.to_canonical_bytes().expect("re-encode schedule"),
            canonical,
            "encode-decode-encode must be byte-identical"
        );
        for (decoded_dispatch, source_dispatch) in
            decoded.dispatches().iter().zip(schedule.dispatches())
        {
            assert_eq!(decoded_dispatch.task(), source_dispatch.task());
            assert_eq!(decoded_dispatch.worker(), source_dispatch.worker());
            assert_eq!(decoded_dispatch.lane(), source_dispatch.lane());
            assert_eq!(decoded_dispatch.at_step(), source_dispatch.at_step());
            assert_eq!(decoded_dispatch.at_nanos(), source_dispatch.at_nanos());
        }
        assert_eq!(decoded.seed(), schedule.seed());
        assert_eq!(decoded.config_hash(), schedule.config_hash());
        assert_eq!(decoded.terminal_steps(), schedule.terminal_steps());
        assert_eq!(decoded.terminal_nanos(), schedule.terminal_nanos());
        assert_eq!(
            decoded.terminal_schedule_hash(),
            schedule.terminal_schedule_hash()
        );
        assert!(decoded.terminal_quiescent());
        assert!(!decoded.truncated());

        let replay_observations = Arc::new(Mutex::new(Vec::new()));
        let mut replay = forced_schedule_fixture(config.clone(), Arc::clone(&replay_observations));
        let replay_report = replay
            .run_forced_schedule(&decoded, ForcedScheduleLimits::new(32, 128))
            .expect("decoded schedule replays exactly");
        assert_eq!(replay_report.dispatches, 6);
        assert_eq!(replay_report.steps, decoded.terminal_steps());
        assert_eq!(
            replay_report.schedule_hash,
            decoded.terminal_schedule_hash()
        );
        assert_eq!(*replay_observations.lock(), *source_observations.lock());

        let candidate_limits = ForcedScheduleCandidateLimits::new(32, 32, 128);
        let all_indices = (0..decoded.dispatches().len()).collect::<Vec<_>>();
        let candidate = decoded
            .derive_candidate(&all_indices, candidate_limits)
            .expect("derive candidate from decoded authority");
        assert_eq!(candidate.source_version(), decoded.version());
        assert_eq!(candidate.seed(), decoded.seed());
        assert_eq!(candidate.config_hash(), decoded.config_hash());
        assert_eq!(
            candidate.source_dispatch_count(),
            decoded.dispatches().len()
        );
        assert_eq!(
            candidate.source_terminal_schedule_hash(),
            decoded.terminal_schedule_hash()
        );
        for (index, (retained, source_dispatch)) in candidate
            .dispatches()
            .iter()
            .zip(decoded.dispatches())
            .enumerate()
        {
            assert_eq!(retained.source_index(), index);
            assert_eq!(retained.task(), source_dispatch.task());
            assert_eq!(retained.worker(), source_dispatch.worker());
            assert_eq!(retained.lane(), source_dispatch.lane());
            assert_eq!(retained.source_step(), source_dispatch.at_step());
            assert_eq!(retained.source_nanos(), source_dispatch.at_nanos());
        }
        let candidate_observations = Arc::new(Mutex::new(Vec::new()));
        let mut candidate_replay =
            forced_schedule_fixture(config.clone(), Arc::clone(&candidate_observations));
        let candidate_report = candidate_replay
            .run_forced_schedule_candidate(&candidate, candidate_limits)
            .expect("decoded candidate executes exact retained choices");
        assert_eq!(
            candidate_report.termination,
            ForcedScheduleCandidateTermination::Quiescent
        );
        assert_eq!(candidate_report.consumed_source_indices, all_indices);
        assert_eq!(*candidate_observations.lock(), *source_observations.lock());

        for prefix_len in 0..canonical.len() {
            assert!(matches!(
                ForcedSchedule::try_from_canonical_bytes(&canonical[..prefix_len], decode_limits),
                Err(ForcedScheduleArtifactError::Truncated { .. })
            ));
        }
        let mut trailing = canonical.clone();
        trailing.push(0);
        assert!(matches!(
            ForcedSchedule::try_from_canonical_bytes(
                &trailing,
                ForcedScheduleDecodeLimits::new(trailing.len(), 32, decoded_dispatch_bytes)
            ),
            Err(ForcedScheduleArtifactError::TrailingBytes { .. })
        ));

        for byte_index in 0..canonical.len() {
            let mut corrupted = canonical.clone();
            corrupted[byte_index] ^= 0x80;
            assert!(
                ForcedSchedule::try_from_canonical_bytes(&corrupted, decode_limits).is_err(),
                "byte mutation {byte_index} was accepted"
            );
        }

        assert!(matches!(
            ForcedSchedule::try_from_canonical_bytes(
                &canonical,
                ForcedScheduleDecodeLimits::new(canonical.len() - 1, 32, decoded_dispatch_bytes)
            ),
            Err(ForcedScheduleArtifactError::ByteLimitExceeded { .. })
        ));
        assert!(matches!(
            ForcedSchedule::try_from_canonical_bytes(
                &canonical,
                ForcedScheduleDecodeLimits::new(
                    canonical.len(),
                    schedule.dispatches().len() - 1,
                    decoded_dispatch_bytes
                )
            ),
            Err(ForcedScheduleArtifactError::DispatchLimitExceeded { .. })
        ));
        assert!(matches!(
            ForcedSchedule::try_from_canonical_bytes(
                &canonical,
                ForcedScheduleDecodeLimits::new(canonical.len(), 32, decoded_dispatch_bytes - 1)
            ),
            Err(ForcedScheduleArtifactError::DecodedAllocationLimitExceeded { .. })
        ));
        let mut impossible_count = canonical[..FORCED_SCHEDULE_ARTIFACT_HEADER_LEN].to_vec();
        write_u64(
            &mut impossible_count,
            FORCED_SCHEDULE_ARTIFACT_COUNT_OFFSET,
            u64::MAX,
        );
        assert!(matches!(
            ForcedSchedule::try_from_canonical_bytes(
                &impossible_count,
                ForcedScheduleDecodeLimits::new(impossible_count.len(), usize::MAX, usize::MAX)
            ),
            Err(ForcedScheduleArtifactError::LengthOverflow { .. })
        ));

        let dispatch0 = FORCED_SCHEDULE_ARTIFACT_HEADER_LEN;
        let dispatch1 = dispatch0 + FORCED_SCHEDULE_ARTIFACT_DISPATCH_LEN;
        let terminal = FORCED_SCHEDULE_ARTIFACT_HEADER_LEN
            + schedule.dispatches().len() * FORCED_SCHEDULE_ARTIFACT_DISPATCH_LEN;

        let mut wrong_magic = canonical.clone();
        wrong_magic[0] ^= 1;
        rewrite_checksum(&mut wrong_magic);
        assert_eq!(
            ForcedSchedule::try_from_canonical_bytes(&wrong_magic, decode_limits),
            Err(ForcedScheduleArtifactError::MagicMismatch)
        );
        let mut wrong_artifact_version = canonical.clone();
        write_u32(
            &mut wrong_artifact_version,
            8,
            FORCED_SCHEDULE_ARTIFACT_VERSION + 1,
        );
        rewrite_checksum(&mut wrong_artifact_version);
        assert!(matches!(
            ForcedSchedule::try_from_canonical_bytes(&wrong_artifact_version, decode_limits),
            Err(ForcedScheduleArtifactError::VersionMismatch { .. })
        ));
        let mut wrong_schema = canonical.clone();
        write_u32(&mut wrong_schema, 12, FORCED_SCHEDULE_SCHEMA_VERSION + 1);
        rewrite_checksum(&mut wrong_schema);
        assert!(matches!(
            ForcedSchedule::try_from_canonical_bytes(&wrong_schema, decode_limits),
            Err(ForcedScheduleArtifactError::SchemaMismatch { .. })
        ));
        let mut unknown_lane = canonical.clone();
        unknown_lane[dispatch0 + 12] = 0xff;
        rewrite_checksum(&mut unknown_lane);
        assert!(matches!(
            ForcedSchedule::try_from_canonical_bytes(&unknown_lane, decode_limits),
            Err(ForcedScheduleArtifactError::LaneTag {
                index: 0,
                tag: 0xff
            })
        ));
        let mut duplicate_step = canonical.clone();
        write_u64(
            &mut duplicate_step,
            dispatch1 + 13,
            schedule.dispatches()[0].at_step(),
        );
        rewrite_checksum(&mut duplicate_step);
        assert!(matches!(
            ForcedSchedule::try_from_canonical_bytes(&duplicate_step, decode_limits),
            Err(ForcedScheduleArtifactError::Schedule(ForcedScheduleError::StepOrder { index: 1, .. }))
        ));
        let mut backwards_time = canonical.clone();
        write_u64(&mut backwards_time, dispatch0 + 21, 1);
        write_u64(&mut backwards_time, dispatch1 + 21, 0);
        rewrite_checksum(&mut backwards_time);
        assert!(matches!(
            ForcedSchedule::try_from_canonical_bytes(&backwards_time, decode_limits),
            Err(ForcedScheduleArtifactError::Schedule(ForcedScheduleError::TimeOrder { index: 1, .. }))
        ));
        for (offset, field) in [
            (terminal + 24, "terminal_quiescent"),
            (terminal + 25, "truncated"),
        ] {
            let mut invalid_bool = canonical.clone();
            invalid_bool[offset] = 2;
            rewrite_checksum(&mut invalid_bool);
            assert_eq!(
                ForcedSchedule::try_from_canonical_bytes(&invalid_bool, decode_limits),
                Err(ForcedScheduleArtifactError::BooleanTag { field, tag: 2 })
            );
        }
        for (offset, value) in [(terminal + 24, 0), (terminal + 25, 1)] {
            let mut partial = canonical.clone();
            partial[offset] = value;
            rewrite_checksum(&mut partial);
            assert_eq!(
                ForcedSchedule::try_from_canonical_bytes(&partial, decode_limits),
                Err(ForcedScheduleArtifactError::Schedule(ForcedScheduleError::PartialSource))
            );
        }
        let mut impossible_terminal = canonical.clone();
        write_u64(
            &mut impossible_terminal,
            terminal,
            schedule
                .dispatches()
                .last()
                .expect("last dispatch")
                .at_step()
                - 1,
        );
        rewrite_checksum(&mut impossible_terminal);
        assert_eq!(
            ForcedSchedule::try_from_canonical_bytes(&impossible_terminal, decode_limits),
            Err(ForcedScheduleArtifactError::Schedule(ForcedScheduleError::PartialSource))
        );

        let mut wrong_seed = canonical.clone();
        write_u64(&mut wrong_seed, 16, schedule.seed() ^ 1);
        rewrite_checksum(&mut wrong_seed);
        let wrong_seed = ForcedSchedule::try_from_canonical_bytes(&wrong_seed, decode_limits)
            .expect("authenticated alternate seed decodes");
        let observations = Arc::new(Mutex::new(Vec::new()));
        let mut runtime = forced_schedule_fixture(config.clone(), Arc::clone(&observations));
        assert!(matches!(
            runtime.run_forced_schedule(&wrong_seed, ForcedScheduleLimits::new(32, 128)),
            Err(ForcedScheduleError::SeedMismatch { .. })
        ));
        assert!(observations.lock().is_empty());

        let mut wrong_config = canonical.clone();
        write_u64(&mut wrong_config, 24, schedule.config_hash() ^ 1);
        rewrite_checksum(&mut wrong_config);
        let wrong_config = ForcedSchedule::try_from_canonical_bytes(&wrong_config, decode_limits)
            .expect("authenticated alternate config decodes");
        let observations = Arc::new(Mutex::new(Vec::new()));
        let mut runtime = forced_schedule_fixture(config.clone(), Arc::clone(&observations));
        assert!(matches!(
            runtime.run_forced_schedule(&wrong_config, ForcedScheduleLimits::new(32, 128)),
            Err(ForcedScheduleError::ConfigMismatch { .. })
        ));
        assert!(observations.lock().is_empty());

        let mut wrong_task = canonical.clone();
        write_u64(
            &mut wrong_task,
            dispatch0,
            schedule.dispatches()[0].task().0 ^ 1,
        );
        rewrite_checksum(&mut wrong_task);
        let wrong_task = ForcedSchedule::try_from_canonical_bytes(&wrong_task, decode_limits)
            .expect("authenticated alternate task decodes");
        let observations = Arc::new(Mutex::new(Vec::new()));
        let mut runtime = forced_schedule_fixture(config.clone(), Arc::clone(&observations));
        assert!(matches!(
            runtime.run_forced_schedule(&wrong_task, ForcedScheduleLimits::new(32, 128)),
            Err(ForcedScheduleError::TaskUnavailable { index: 0, .. })
        ));
        assert!(observations.lock().is_empty());

        let mut wrong_worker = canonical.clone();
        write_u32(&mut wrong_worker, dispatch0 + 8, u32::MAX);
        rewrite_checksum(&mut wrong_worker);
        let wrong_worker = ForcedSchedule::try_from_canonical_bytes(&wrong_worker, decode_limits)
            .expect("authenticated alternate worker decodes");
        let observations = Arc::new(Mutex::new(Vec::new()));
        let mut runtime = forced_schedule_fixture(config.clone(), Arc::clone(&observations));
        assert!(matches!(
            runtime.run_forced_schedule(&wrong_worker, ForcedScheduleLimits::new(32, 128)),
            Err(ForcedScheduleError::WorkerUnavailable { .. })
        ));
        assert!(observations.lock().is_empty());

        let mut wrong_lane = canonical.clone();
        wrong_lane[dispatch0 + 12] = match schedule.dispatches()[0].lane() {
            DispatchLane::Cancel => forced_schedule_lane_tag(DispatchLane::Ready),
            DispatchLane::Timed | DispatchLane::Ready | DispatchLane::Stolen => {
                forced_schedule_lane_tag(DispatchLane::Cancel)
            }
        };
        rewrite_checksum(&mut wrong_lane);
        let wrong_lane = ForcedSchedule::try_from_canonical_bytes(&wrong_lane, decode_limits)
            .expect("authenticated alternate lane decodes");
        let observations = Arc::new(Mutex::new(Vec::new()));
        let mut runtime = forced_schedule_fixture(config.clone(), Arc::clone(&observations));
        assert!(matches!(
            runtime.run_forced_schedule(&wrong_lane, ForcedScheduleLimits::new(32, 128)),
            Err(ForcedScheduleError::LaneMismatch { index: 0, .. })
        ));
        assert!(observations.lock().is_empty());

        let mut wrong_terminal_hash = canonical.clone();
        write_u64(
            &mut wrong_terminal_hash,
            terminal + 16,
            schedule.terminal_schedule_hash() ^ 1,
        );
        rewrite_checksum(&mut wrong_terminal_hash);
        let wrong_terminal_hash =
            ForcedSchedule::try_from_canonical_bytes(&wrong_terminal_hash, decode_limits)
                .expect("authenticated alternate terminal hash decodes");
        let observations = Arc::new(Mutex::new(Vec::new()));
        let mut runtime = forced_schedule_fixture(config, Arc::clone(&observations));
        assert!(matches!(
            runtime.run_forced_schedule(&wrong_terminal_hash, ForcedScheduleLimits::new(32, 128)),
            Err(ForcedScheduleError::CertificateMismatch { .. })
        ));
        assert_eq!(observations.lock().len(), 6);

        crate::test_complete!("forced_schedule_artifact_codec_is_canonical_bounded_and_replayable");
    }

    fn pending_spawn_with_future_reactor_fixture(
        config: LabConfig,
        observations: Arc<Mutex<Vec<u64>>>,
    ) -> LabRuntime {
        let mut runtime = LabRuntime::new(config);
        let token = Token::new(0xCAAD);
        runtime
            .lab_reactor()
            .inject_event(token, Event::readable(token), Duration::from_secs(1));

        let root = runtime.state.create_root_region(Budget::INFINITE);
        let pending = runtime
            .state
            .region(root)
            .expect("root region")
            .pending_spawn_handle();
        let parent: crate::cx::Cx = crate::cx::Cx::new_with_drivers(
            root,
            TaskId::from_arena(ArenaIndex::new(u32::MAX - 1, 0)),
            Budget::INFINITE,
            None,
            runtime.state.io_driver_handle(),
            None,
            runtime.state.timer_driver_handle(),
            None,
        )
        .with_spawn_gateway(runtime.state.spawn_gateway())
        .with_pending_spawn_counter(Some(pending));
        let _handle = parent
            .spawn(|child| async move {
                observations.lock().push(child.now().as_nanos());
            })
            .expect("managed spawn enqueues");
        assert_eq!(runtime.spawn_mailbox.len(), 1);
        runtime
    }

    fn pending_command_before_timer_fixture(
        config: LabConfig,
        observations: Arc<Mutex<Vec<u64>>>,
    ) -> LabRuntime {
        let mut runtime = LabRuntime::new(config);
        let root = runtime.state.create_root_region(Budget::INFINITE);
        let gateway = runtime.state.spawn_gateway().expect("lab spawn gateway");
        let missing = TaskId::from_arena(ArenaIndex::new(u32::MAX - 2, 0));
        let (task, _handle) = runtime
            .state
            .create_task(root, Budget::INFINITE, async move {
                let now = crate::cx::Cx::current().map_or(Time::ZERO, |cx| cx.now());
                observations.lock().push(now.as_nanos());
                assert!(gateway.enqueue_handle_cancel(missing, CancelReason::shutdown()));
                crate::time::sleep(now, Duration::from_secs(1)).await;
                let now = crate::cx::Cx::current().map_or(Time::ZERO, |cx| cx.now());
                observations.lock().push(now.as_nanos());
            })
            .expect("create command-before-timer task");
        runtime.scheduler.lock().schedule(task, 0);
        runtime
    }

    #[test]
    fn pending_dispatch_auto_advance_before_future_deadline() {
        init_test("pending_dispatch_auto_advance_before_future_deadline");
        let observations = Arc::new(Mutex::new(Vec::new()));
        let mut runtime = pending_spawn_with_future_reactor_fixture(
            LabConfig::new(0xCAAD_A070).max_steps(32),
            Arc::clone(&observations),
        );

        let report = runtime.run_with_auto_advance();

        assert_eq!(
            *observations.lock(),
            vec![0],
            "queued spawn work must run before an unrelated future reactor deadline"
        );
        assert_eq!(report.termination, AutoAdvanceTermination::Quiescent);
        assert_eq!(runtime.now(), Time::from_secs(1));
        crate::test_complete!("pending_dispatch_auto_advance_before_future_deadline");
    }

    #[test]
    fn pending_dispatch_run_until_idle_admits_spawn() {
        init_test("pending_dispatch_run_until_idle_admits_spawn");
        let observations = Arc::new(Mutex::new(Vec::new()));
        let mut runtime = pending_spawn_with_future_reactor_fixture(
            LabConfig::new(0x1D1E_CAAD).max_steps(32),
            Arc::clone(&observations),
        );

        assert_eq!(runtime.run_until_idle(), 1);
        assert_eq!(
            *observations.lock(),
            vec![0],
            "idle detection must admit and poll queued managed spawns"
        );
        assert!(runtime.spawn_mailbox.is_empty());
        crate::test_complete!("pending_dispatch_run_until_idle_admits_spawn");
    }

    #[test]
    fn pending_dispatch_forced_candidate_before_future_deadline() {
        init_test("pending_dispatch_forced_candidate_before_future_deadline");
        let config = LabConfig::new(0xCAAD_CAAD).max_steps(32);
        let source_observations = Arc::new(Mutex::new(Vec::new()));
        let mut source = pending_spawn_with_future_reactor_fixture(
            config.clone(),
            Arc::clone(&source_observations),
        );
        source
            .start_forced_schedule_recording(4)
            .expect("start exact dispatch capture");
        source.step();
        assert!(source.is_quiescent());
        let schedule = source
            .finish_forced_schedule_recording()
            .expect("capture one pending-spawn dispatch");
        assert_eq!(schedule.dispatches().len(), 1);
        assert_eq!(schedule.dispatches()[0].at_nanos(), 0);
        assert_eq!(*source_observations.lock(), vec![0]);

        let limits = ForcedScheduleCandidateLimits::new(4, 4, 16);
        let candidate = schedule
            .derive_candidate(&[0], limits)
            .expect("derive full-retention candidate");
        let replay_observations = Arc::new(Mutex::new(Vec::new()));
        let mut replay =
            pending_spawn_with_future_reactor_fixture(config, Arc::clone(&replay_observations));
        let report = replay
            .run_forced_schedule_candidate(&candidate, limits)
            .expect("candidate must drain spawn admission before time advancement");

        assert_eq!(
            report.termination,
            ForcedScheduleCandidateTermination::Quiescent
        );
        assert_eq!(report.consumed_source_indices, vec![0]);
        assert_eq!(*replay_observations.lock(), vec![0]);
        assert_eq!(report.lab.now_nanos, 0);
        crate::test_complete!("pending_dispatch_forced_candidate_before_future_deadline");
    }

    #[test]
    fn pending_dispatch_forced_candidate_before_later_retained_dispatch() {
        init_test("pending_dispatch_forced_candidate_before_later_retained_dispatch");
        let config = LabConfig::new(0xCAAD_C0DE).max_steps(32);
        let source_observations = Arc::new(Mutex::new(Vec::new()));
        let mut source =
            pending_command_before_timer_fixture(config.clone(), Arc::clone(&source_observations));
        source
            .start_forced_schedule_recording(4)
            .expect("start exact dispatch capture");
        let source_report = source.run_with_auto_advance();
        assert_eq!(source_report.termination, AutoAdvanceTermination::Quiescent);
        let schedule = source
            .finish_forced_schedule_recording()
            .expect("capture both task dispatches");
        assert_eq!(schedule.dispatches().len(), 2);
        assert_eq!(*source_observations.lock(), vec![0, 1_000_000_000]);

        let limits = ForcedScheduleCandidateLimits::new(4, 4, 16);
        let candidate = schedule
            .derive_candidate(&[0, 1], limits)
            .expect("derive full-retention candidate");
        let replay_observations = Arc::new(Mutex::new(Vec::new()));
        let mut replay =
            pending_command_before_timer_fixture(config, Arc::clone(&replay_observations));
        let report = replay
            .run_forced_schedule_candidate(&candidate, limits)
            .expect("candidate must pump the command before advancing to the retained wake");

        assert_eq!(
            report.termination,
            ForcedScheduleCandidateTermination::Quiescent
        );
        assert_eq!(report.consumed_source_indices, vec![0, 1]);
        assert_eq!(*replay_observations.lock(), vec![0, 1_000_000_000]);
        assert_eq!(report.lab.now_nanos, 1_000_000_000);
        crate::test_complete!("pending_dispatch_forced_candidate_before_later_retained_dispatch");
    }

    #[test]
    fn forced_schedule_replay_executes_recorded_choices_before_polling() {
        init_test("forced_schedule_replay_executes_recorded_choices_before_polling");
        let config = LabConfig::new(0xF0CE_D5CE).worker_count(2).max_steps(128);
        let source_observations = Arc::new(Mutex::new(Vec::new()));
        let mut source = forced_schedule_fixture(config.clone(), Arc::clone(&source_observations));
        source
            .start_forced_schedule_recording(32)
            .expect("start exact dispatch capture");
        let source_report = source.run_until_quiescent_with_report();
        assert!(source_report.quiescent, "source fixture must quiesce");
        let schedule = source
            .finish_forced_schedule_recording()
            .expect("complete exact dispatch projection");
        assert_eq!(schedule.version(), FORCED_SCHEDULE_SCHEMA_VERSION);
        assert_eq!(schedule.seed(), config.seed);
        assert_eq!(schedule.dispatches().len(), 6);
        assert_eq!(
            schedule.terminal_schedule_hash(),
            source_report.trace_certificate.schedule_hash
        );

        let replay_observations = Arc::new(Mutex::new(Vec::new()));
        let mut replay = forced_schedule_fixture(config, Arc::clone(&replay_observations));
        let receipt = replay
            .run_forced_schedule(&schedule, ForcedScheduleLimits::new(32, 128))
            .expect("recorded dispatch projection must execute exactly");

        assert!(receipt.quiescent);
        assert_eq!(receipt.dispatches, schedule.dispatches().len());
        assert_eq!(receipt.steps, schedule.terminal_steps());
        assert_eq!(receipt.terminal_nanos, schedule.terminal_nanos());
        assert_eq!(receipt.schedule_hash, schedule.terminal_schedule_hash());
        assert_eq!(*replay_observations.lock(), *source_observations.lock());
        crate::test_complete!("forced_schedule_replay_executes_recorded_choices_before_polling");
    }

    fn recorded_forced_schedule_fixture() -> ForcedSchedule {
        let config = LabConfig::new(0xA471_FAC7).worker_count(2).max_steps(128);
        let observations = Arc::new(Mutex::new(Vec::new()));
        let mut source = forced_schedule_fixture(config, observations);
        source
            .start_forced_schedule_recording(32)
            .expect("start artifact fixture capture");
        assert!(source.run_until_quiescent_with_report().quiescent);
        source
            .finish_forced_schedule_recording()
            .expect("finish complete artifact fixture capture")
    }

    fn reseal_forced_schedule_artifact(bytes: &mut [u8]) {
        let checksum_offset = bytes.len() - FORCED_SCHEDULE_ARTIFACT_CHECKSUM_LEN;
        let checksum = forced_schedule_artifact_checksum(&bytes[..checksum_offset]);
        bytes[checksum_offset..].copy_from_slice(&checksum);
    }

    #[test]
    fn forced_schedule_artifact_roundtrip_is_exact_and_bounded() {
        init_test("forced_schedule_artifact_roundtrip_is_exact_and_bounded");
        let schedule = recorded_forced_schedule_fixture();
        let bytes = schedule
            .to_canonical_bytes()
            .expect("encode complete forced schedule");
        assert_eq!(
            schedule.to_canonical_bytes().expect("repeat encoding"),
            bytes,
            "canonical encoding must be deterministic"
        );

        let decoded_bytes = schedule.dispatches().len() * std::mem::size_of::<ForcedDispatch>();
        let limits = ForcedScheduleDecodeLimits::new(
            bytes.len(),
            schedule.dispatches().len(),
            decoded_bytes,
        );
        assert_eq!(
            ForcedSchedule::try_from_canonical_bytes(&bytes, limits)
                .expect("decode canonical artifact"),
            schedule
        );

        assert!(matches!(
            ForcedSchedule::try_from_canonical_bytes(
                &bytes,
                ForcedScheduleDecodeLimits::new(
                    bytes.len() - 1,
                    schedule.dispatches().len(),
                    decoded_bytes,
                ),
            ),
            Err(ForcedScheduleArtifactError::ByteLimitExceeded { .. })
        ));
        assert!(matches!(
            ForcedSchedule::try_from_canonical_bytes(
                &bytes,
                ForcedScheduleDecodeLimits::new(
                    bytes.len(),
                    schedule.dispatches().len() - 1,
                    decoded_bytes,
                ),
            ),
            Err(ForcedScheduleArtifactError::DispatchLimitExceeded { .. })
        ));
        assert!(matches!(
            ForcedSchedule::try_from_canonical_bytes(
                &bytes,
                ForcedScheduleDecodeLimits::new(
                    bytes.len(),
                    schedule.dispatches().len(),
                    decoded_bytes - 1,
                ),
            ),
            Err(ForcedScheduleArtifactError::DecodedAllocationLimitExceeded { .. })
        ));
        crate::test_complete!("forced_schedule_artifact_roundtrip_is_exact_and_bounded");
    }

    #[test]
    fn forced_schedule_artifact_rejects_hostile_encodings() {
        init_test("forced_schedule_artifact_rejects_hostile_encodings");
        let schedule = recorded_forced_schedule_fixture();
        let bytes = schedule
            .to_canonical_bytes()
            .expect("encode complete forced schedule");
        let limits = ForcedScheduleDecodeLimits::new(
            bytes.len() + 1,
            schedule.dispatches().len() + 1,
            (schedule.dispatches().len() + 1) * std::mem::size_of::<ForcedDispatch>(),
        );

        assert!(matches!(
            ForcedSchedule::try_from_canonical_bytes(&bytes[..12], limits),
            Err(ForcedScheduleArtifactError::Truncated { .. })
        ));

        let mut malformed = bytes.clone();
        malformed[0] ^= 0x80;
        assert_eq!(
            ForcedSchedule::try_from_canonical_bytes(&malformed, limits),
            Err(ForcedScheduleArtifactError::MagicMismatch)
        );

        let mut malformed = bytes.clone();
        malformed[8..12].copy_from_slice(&(FORCED_SCHEDULE_ARTIFACT_VERSION + 1).to_le_bytes());
        assert!(matches!(
            ForcedSchedule::try_from_canonical_bytes(&malformed, limits),
            Err(ForcedScheduleArtifactError::VersionMismatch { .. })
        ));

        let mut malformed = bytes.clone();
        malformed.push(0);
        assert!(matches!(
            ForcedSchedule::try_from_canonical_bytes(&malformed, limits),
            Err(ForcedScheduleArtifactError::TrailingBytes { .. })
        ));

        let mut malformed = bytes.clone();
        let last = malformed.len() - 1;
        malformed[last] ^= 1;
        assert_eq!(
            ForcedSchedule::try_from_canonical_bytes(&malformed, limits),
            Err(ForcedScheduleArtifactError::ChecksumMismatch)
        );

        let mut malformed = bytes.clone();
        malformed[FORCED_SCHEDULE_ARTIFACT_HEADER_LEN + 12] = u8::MAX;
        reseal_forced_schedule_artifact(&mut malformed);
        assert!(matches!(
            ForcedSchedule::try_from_canonical_bytes(&malformed, limits),
            Err(ForcedScheduleArtifactError::LaneTag { index: 0, .. })
        ));

        let mut malformed = bytes;
        let terminal_offset = FORCED_SCHEDULE_ARTIFACT_HEADER_LEN
            + schedule.dispatches().len() * FORCED_SCHEDULE_ARTIFACT_DISPATCH_LEN;
        malformed[terminal_offset + 24] = 2;
        reseal_forced_schedule_artifact(&mut malformed);
        assert!(matches!(
            ForcedSchedule::try_from_canonical_bytes(&malformed, limits),
            Err(ForcedScheduleArtifactError::BooleanTag {
                field: "terminal_quiescent",
                tag: 2,
            })
        ));
        crate::test_complete!("forced_schedule_artifact_rejects_hostile_encodings");
    }

    #[test]
    fn forced_schedule_artifact_refuses_partial_authority() {
        init_test("forced_schedule_artifact_refuses_partial_authority");
        let config = LabConfig::new(0xA471_0BAD).max_steps(128);
        let observations = Arc::new(Mutex::new(Vec::new()));
        let mut source = forced_schedule_fixture(config, observations);
        source
            .start_forced_schedule_recording(32)
            .expect("start partial artifact fixture capture");
        let partial = source
            .finish_forced_schedule_recording()
            .expect("finish represented partial capture");

        assert_eq!(
            partial.to_canonical_bytes(),
            Err(ForcedScheduleArtifactError::Schedule(
                ForcedScheduleError::PartialSource
            ))
        );
        crate::test_complete!("forced_schedule_artifact_refuses_partial_authority");
    }

    #[test]
    fn forced_schedule_candidate_executes_only_retained_source_choices() {
        init_test("forced_schedule_candidate_executes_only_retained_source_choices");
        let config = LabConfig::new(0xCAAD_1DA7).worker_count(2).max_steps(128);
        let source_observations = Arc::new(Mutex::new(Vec::new()));
        let mut source = forced_schedule_fixture(config.clone(), Arc::clone(&source_observations));
        source
            .start_forced_schedule_recording(32)
            .expect("start exact dispatch capture");
        let source_report = source.run_until_quiescent_with_report();
        assert!(source_report.quiescent);
        let schedule = source
            .finish_forced_schedule_recording()
            .expect("complete exact dispatch projection");
        let limits = ForcedScheduleCandidateLimits::new(32, 32, 128);
        let all_indices = (0..schedule.dispatches().len()).collect::<Vec<_>>();
        let full = schedule
            .derive_candidate(&all_indices, limits)
            .expect("derive full-retention candidate");
        assert_eq!(full.version(), FORCED_SCHEDULE_CANDIDATE_SCHEMA_VERSION);
        assert_eq!(full.source_version(), FORCED_SCHEDULE_SCHEMA_VERSION);
        assert_eq!(full.seed(), schedule.seed());
        assert_eq!(full.config_hash(), schedule.config_hash());
        assert_eq!(
            full.source_terminal_schedule_hash(),
            schedule.terminal_schedule_hash()
        );
        assert_eq!(full.source_dispatch_count(), schedule.dispatches().len());
        assert_eq!(
            full.dispatches()
                .iter()
                .map(ForcedScheduleCandidateDispatch::source_index)
                .collect::<Vec<_>>(),
            all_indices
        );

        let exact_observations = Arc::new(Mutex::new(Vec::new()));
        let mut exact_replay =
            forced_schedule_fixture(config.clone(), Arc::clone(&exact_observations));
        let exact_report = exact_replay
            .run_forced_schedule(&schedule, ForcedScheduleLimits::new(32, 128))
            .expect("complete source schedule must still replay exactly");

        let full_observations = Arc::new(Mutex::new(Vec::new()));
        let mut full_replay =
            forced_schedule_fixture(config.clone(), Arc::clone(&full_observations));
        let full_report = full_replay
            .run_forced_schedule_candidate(&full, limits)
            .expect("full candidate must execute without RNG fallback");
        assert_eq!(
            full_report.termination,
            ForcedScheduleCandidateTermination::Quiescent
        );
        assert_eq!(full_report.consumed_source_indices, all_indices);
        assert!(full_report.lab.quiescent);
        assert_eq!(full_report.lab.steps_total, schedule.terminal_steps());
        assert_eq!(full_report.lab.now_nanos, schedule.terminal_nanos());
        assert_eq!(
            full_report.lab.trace_certificate.schedule_hash,
            schedule.terminal_schedule_hash()
        );
        assert_eq!(full_report.lab.steps_total, exact_report.steps);
        assert_eq!(full_report.lab.now_nanos, exact_report.terminal_nanos);
        assert_eq!(
            full_report.lab.trace_certificate.schedule_hash,
            exact_report.schedule_hash
        );
        assert_eq!(full_report.lab.quiescent, exact_report.quiescent);
        assert_eq!(*full_observations.lock(), *source_observations.lock());
        assert_eq!(*full_observations.lock(), *exact_observations.lock());

        let retained = schedule
            .derive_candidate(&[1], limits)
            .expect("derive one-choice candidate");
        assert_eq!(retained.dispatches()[0].source_index(), 1);
        assert_eq!(
            retained.dispatches()[0].task(),
            schedule.dispatches()[1].task()
        );
        assert_eq!(
            retained.dispatches()[0].worker(),
            schedule.dispatches()[1].worker()
        );
        assert_eq!(
            retained.dispatches()[0].lane(),
            schedule.dispatches()[1].lane()
        );
        assert_eq!(
            retained.dispatches()[0].source_step(),
            schedule.dispatches()[1].at_step()
        );
        assert_eq!(
            retained.dispatches()[0].source_nanos(),
            schedule.dispatches()[1].at_nanos()
        );
        let retained_observations = Arc::new(Mutex::new(Vec::new()));
        let mut retained_replay =
            forced_schedule_fixture(config.clone(), Arc::clone(&retained_observations));
        let retained_report = retained_replay
            .run_forced_schedule_candidate(&retained, limits)
            .expect("retained source choice must execute directly");
        assert_eq!(
            retained_report.termination,
            ForcedScheduleCandidateTermination::Exhausted
        );
        assert_eq!(retained_report.consumed_source_indices, vec![1]);
        assert_eq!(retained_observations.lock().len(), 1);
        assert!(!retained_report.lab.quiescent);

        let empty = schedule
            .derive_candidate(&[], limits)
            .expect("derive empty deletion candidate");
        let empty_observations = Arc::new(Mutex::new(Vec::new()));
        let mut empty_replay = forced_schedule_fixture(config, Arc::clone(&empty_observations));
        let empty_report = empty_replay
            .run_forced_schedule_candidate(&empty, limits)
            .expect("empty candidate must report exhaustion without RNG polling");
        assert_eq!(
            empty_report.termination,
            ForcedScheduleCandidateTermination::Exhausted
        );
        assert!(empty_report.consumed_source_indices.is_empty());
        assert_eq!(empty_report.work_units, 0);
        assert!(empty_observations.lock().is_empty());
        crate::test_complete!("forced_schedule_candidate_executes_only_retained_source_choices");
    }

    #[test]
    fn forced_schedule_candidate_admission_is_bounded_and_source_derived() {
        init_test("forced_schedule_candidate_admission_is_bounded_and_source_derived");
        let config = LabConfig::new(0xCAAD_B0AD).worker_count(2).max_steps(128);
        let source_observations = Arc::new(Mutex::new(Vec::new()));
        let mut source = forced_schedule_fixture(config.clone(), source_observations);
        source
            .start_forced_schedule_recording(32)
            .expect("start exact dispatch capture");
        assert!(source.run_until_quiescent_with_report().quiescent);
        let schedule = source
            .finish_forced_schedule_recording()
            .expect("complete exact dispatch projection");
        let source_len = schedule.dispatches().len();
        let limits = ForcedScheduleCandidateLimits::new(32, 32, 128);

        assert!(matches!(
            schedule.derive_candidate(&[], ForcedScheduleCandidateLimits::new(0, 32, 128)),
            Err(ForcedScheduleError::ZeroCandidateLimit {
                limit_name: "max_source_dispatches"
            })
        ));
        assert!(matches!(
            schedule.derive_candidate(&[], ForcedScheduleCandidateLimits::new(32, 0, 128)),
            Err(ForcedScheduleError::ZeroCandidateLimit {
                limit_name: "max_candidate_dispatches"
            })
        ));
        assert!(matches!(
            schedule.derive_candidate(&[], ForcedScheduleCandidateLimits::new(32, 32, 0)),
            Err(ForcedScheduleError::ZeroCandidateLimit {
                limit_name: "max_work_units"
            })
        ));
        assert!(matches!(
            schedule.derive_candidate(
                &[],
                ForcedScheduleCandidateLimits::new(source_len - 1, 32, 128)
            ),
            Err(ForcedScheduleError::CandidateSourceLimitExceeded { .. })
        ));
        assert!(matches!(
            schedule.derive_candidate(&[0, 1], ForcedScheduleCandidateLimits::new(32, 1, 128)),
            Err(ForcedScheduleError::DispatchLimitExceeded { .. })
        ));
        assert!(matches!(
            schedule.derive_candidate(&[0, 0], limits),
            Err(ForcedScheduleError::CandidateIndexOrder { .. })
        ));
        assert!(matches!(
            schedule.derive_candidate(&[1, 0], limits),
            Err(ForcedScheduleError::CandidateIndexOrder { .. })
        ));
        assert!(matches!(
            schedule.derive_candidate(&[source_len], limits),
            Err(ForcedScheduleError::CandidateIndexOutOfRange { .. })
        ));

        let all_indices = (0..source_len).collect::<Vec<_>>();
        let full = schedule
            .derive_candidate(&all_indices, limits)
            .expect("derive valid full candidate");
        let work_limited_observations = Arc::new(Mutex::new(Vec::new()));
        let mut work_limited =
            forced_schedule_fixture(config.clone(), Arc::clone(&work_limited_observations));
        assert!(matches!(
            work_limited.run_forced_schedule_candidate(
                &full,
                ForcedScheduleCandidateLimits::new(32, 32, 1)
            ),
            Err(ForcedScheduleError::CandidateWorkLimitExceeded { .. })
        ));
        assert!(
            work_limited_observations.lock().is_empty(),
            "minimum work refusal polled a task"
        );

        let mut wrong_task = schedule
            .derive_candidate(&[0], limits)
            .expect("derive source-owned candidate");
        wrong_task.dispatches[0].dispatch.task.0 ^= 1;
        let wrong_task_observations = Arc::new(Mutex::new(Vec::new()));
        let mut wrong_task_replay =
            forced_schedule_fixture(config.clone(), Arc::clone(&wrong_task_observations));
        assert!(matches!(
            wrong_task_replay.run_forced_schedule_candidate(&wrong_task, limits),
            Err(ForcedScheduleError::TaskUnavailable { index: 0, .. })
        ));
        assert!(wrong_task_observations.lock().is_empty());

        let mut wrong_config = schedule
            .derive_candidate(&[0], limits)
            .expect("derive source-owned candidate");
        wrong_config.config_hash ^= 1;
        let wrong_config_observations = Arc::new(Mutex::new(Vec::new()));
        let mut wrong_config_replay =
            forced_schedule_fixture(config.clone(), Arc::clone(&wrong_config_observations));
        assert!(matches!(
            wrong_config_replay.run_forced_schedule_candidate(&wrong_config, limits),
            Err(ForcedScheduleError::ConfigMismatch { .. })
        ));
        assert!(wrong_config_observations.lock().is_empty());

        let mut wrong_candidate_version = schedule
            .derive_candidate(&[0], limits)
            .expect("derive source-owned candidate");
        wrong_candidate_version.version += 1;
        let observations = Arc::new(Mutex::new(Vec::new()));
        let mut replay = forced_schedule_fixture(config.clone(), Arc::clone(&observations));
        assert!(matches!(
            replay.run_forced_schedule_candidate(&wrong_candidate_version, limits),
            Err(ForcedScheduleError::CandidateSchemaMismatch { .. })
        ));
        assert!(observations.lock().is_empty());

        let mut wrong_source_version = schedule
            .derive_candidate(&[0], limits)
            .expect("derive source-owned candidate");
        wrong_source_version.source_version += 1;
        let observations = Arc::new(Mutex::new(Vec::new()));
        let mut replay = forced_schedule_fixture(config.clone(), Arc::clone(&observations));
        assert!(matches!(
            replay.run_forced_schedule_candidate(&wrong_source_version, limits),
            Err(ForcedScheduleError::SchemaMismatch { .. })
        ));
        assert!(observations.lock().is_empty());

        let mut wrong_seed = schedule
            .derive_candidate(&[0], limits)
            .expect("derive source-owned candidate");
        wrong_seed.seed ^= 1;
        let observations = Arc::new(Mutex::new(Vec::new()));
        let mut replay = forced_schedule_fixture(config.clone(), Arc::clone(&observations));
        assert!(matches!(
            replay.run_forced_schedule_candidate(&wrong_seed, limits),
            Err(ForcedScheduleError::SeedMismatch { .. })
        ));
        assert!(observations.lock().is_empty());

        let mut wrong_order = schedule
            .derive_candidate(&[0, 1], limits)
            .expect("derive source-owned candidate");
        wrong_order.dispatches.swap(0, 1);
        let observations = Arc::new(Mutex::new(Vec::new()));
        let mut replay = forced_schedule_fixture(config.clone(), Arc::clone(&observations));
        assert!(matches!(
            replay.run_forced_schedule_candidate(&wrong_order, limits),
            Err(ForcedScheduleError::CandidateIndexOrder { .. })
        ));
        assert!(observations.lock().is_empty());

        let mut wrong_worker = schedule
            .derive_candidate(&[0], limits)
            .expect("derive source-owned candidate");
        wrong_worker.dispatches[0].dispatch.worker ^= 1;
        let observations = Arc::new(Mutex::new(Vec::new()));
        let mut replay = forced_schedule_fixture(config.clone(), Arc::clone(&observations));
        assert!(matches!(
            replay.run_forced_schedule_candidate(&wrong_worker, limits),
            Err(ForcedScheduleError::WorkerMismatch { index: 0, .. })
                | Err(ForcedScheduleError::LaneMismatch { index: 0, .. })
        ));
        assert!(observations.lock().is_empty());

        let mut wrong_lane = schedule
            .derive_candidate(&[0], limits)
            .expect("derive source-owned candidate");
        wrong_lane.dispatches[0].dispatch.lane = match wrong_lane.dispatches[0].dispatch.lane {
            DispatchLane::Cancel => DispatchLane::Ready,
            DispatchLane::Timed | DispatchLane::Ready | DispatchLane::Stolen => {
                DispatchLane::Cancel
            }
        };
        let observations = Arc::new(Mutex::new(Vec::new()));
        let mut replay = forced_schedule_fixture(config, Arc::clone(&observations));
        assert!(matches!(
            replay.run_forced_schedule_candidate(&wrong_lane, limits),
            Err(ForcedScheduleError::LaneMismatch { index: 0, .. })
                | Err(ForcedScheduleError::WorkerMismatch { index: 0, .. })
        ));
        assert!(observations.lock().is_empty());
        crate::test_complete!("forced_schedule_candidate_admission_is_bounded_and_source_derived");
    }

    #[test]
    fn forced_schedule_mutations_refuse_before_the_wrong_poll() {
        init_test("forced_schedule_mutations_refuse_before_the_wrong_poll");
        let config = LabConfig::new(0xF0CE_D5CE).worker_count(2).max_steps(128);
        let source_observations = Arc::new(Mutex::new(Vec::new()));
        let mut source = forced_schedule_fixture(config.clone(), source_observations);
        source
            .start_forced_schedule_recording(32)
            .expect("start exact dispatch capture");
        assert!(source.run_until_quiescent_with_report().quiescent);
        let schedule = source
            .finish_forced_schedule_recording()
            .expect("complete exact dispatch projection");

        let mut wrong_tick = schedule.clone();
        for dispatch in &mut wrong_tick.dispatches {
            dispatch.at_step += 1;
        }
        wrong_tick.terminal_steps += 1;
        let observations = Arc::new(Mutex::new(Vec::new()));
        let mut replay = forced_schedule_fixture(config.clone(), Arc::clone(&observations));
        assert!(matches!(
            replay.run_forced_schedule(&wrong_tick, ForcedScheduleLimits::new(32, 128)),
            Err(ForcedScheduleError::EarlyRunnable { .. })
        ));
        assert!(
            observations.lock().is_empty(),
            "tick mismatch polled a task"
        );
        assert!(
            replay.run_until_quiescent_with_report().quiescent,
            "tick refusal corrupted runnable work"
        );
        assert_eq!(observations.lock().len(), 6);

        let mut wrong_time = schedule.clone();
        for dispatch in &mut wrong_time.dispatches {
            dispatch.at_nanos += 1;
        }
        wrong_time.terminal_nanos += 1;
        let observations = Arc::new(Mutex::new(Vec::new()));
        let mut replay = forced_schedule_fixture(config.clone(), Arc::clone(&observations));
        assert!(matches!(
            replay.run_forced_schedule(&wrong_time, ForcedScheduleLimits::new(32, 128)),
            Err(ForcedScheduleError::TimeMismatch { index: 0, .. })
        ));
        assert!(
            observations.lock().is_empty(),
            "time mismatch polled a task"
        );
        assert!(
            replay.run_until_quiescent_with_report().quiescent,
            "time refusal corrupted runnable work"
        );
        assert_eq!(observations.lock().len(), 6);

        let mut wrong_task = schedule.clone();
        wrong_task.dispatches[0].task.0 ^= 1;
        let observations = Arc::new(Mutex::new(Vec::new()));
        let mut replay = forced_schedule_fixture(config.clone(), Arc::clone(&observations));
        assert!(matches!(
            replay.run_forced_schedule(&wrong_task, ForcedScheduleLimits::new(32, 128)),
            Err(ForcedScheduleError::TaskUnavailable { index: 0, .. })
        ));
        assert!(
            observations.lock().is_empty(),
            "generation mismatch polled a task"
        );
        assert!(
            replay.run_until_quiescent_with_report().quiescent,
            "task refusal corrupted runnable work"
        );
        assert_eq!(observations.lock().len(), 6);

        let mut wrong_worker = schedule.clone();
        wrong_worker.dispatches[0].worker ^= 1;
        let observations = Arc::new(Mutex::new(Vec::new()));
        let mut replay = forced_schedule_fixture(config.clone(), Arc::clone(&observations));
        assert!(matches!(
            replay.run_forced_schedule(&wrong_worker, ForcedScheduleLimits::new(32, 128)),
            Err(ForcedScheduleError::WorkerMismatch { index: 0, .. })
                | Err(ForcedScheduleError::LaneMismatch { index: 0, .. })
        ));
        assert!(
            observations.lock().is_empty(),
            "worker mismatch polled a task"
        );
        assert!(
            replay.run_until_quiescent_with_report().quiescent,
            "worker refusal corrupted runnable work"
        );
        assert_eq!(observations.lock().len(), 6);

        let mut wrong_lane = schedule.clone();
        wrong_lane.dispatches[0].lane = match wrong_lane.dispatches[0].lane {
            DispatchLane::Cancel => DispatchLane::Ready,
            DispatchLane::Timed | DispatchLane::Ready | DispatchLane::Stolen => {
                DispatchLane::Cancel
            }
        };
        let observations = Arc::new(Mutex::new(Vec::new()));
        let mut replay = forced_schedule_fixture(config.clone(), Arc::clone(&observations));
        assert!(matches!(
            replay.run_forced_schedule(&wrong_lane, ForcedScheduleLimits::new(32, 128)),
            Err(ForcedScheduleError::LaneMismatch { index: 0, .. })
                | Err(ForcedScheduleError::WorkerMismatch { index: 0, .. })
        ));
        assert!(
            observations.lock().is_empty(),
            "lane mismatch polled a task"
        );
        assert!(
            replay.run_until_quiescent_with_report().quiescent,
            "lane refusal corrupted runnable work"
        );
        assert_eq!(observations.lock().len(), 6);

        let mut wrong_order = schedule.clone();
        wrong_order.dispatches.swap(0, 1);
        let observations = Arc::new(Mutex::new(Vec::new()));
        let mut replay = forced_schedule_fixture(config, Arc::clone(&observations));
        assert!(matches!(
            replay.run_forced_schedule(&wrong_order, ForcedScheduleLimits::new(32, 128)),
            Err(ForcedScheduleError::StepOrder { .. })
        ));
        assert!(
            observations.lock().is_empty(),
            "order mismatch polled a task"
        );
        assert!(
            replay.run_until_quiescent_with_report().quiescent,
            "order refusal corrupted runnable work"
        );
        assert_eq!(observations.lock().len(), 6);
        crate::test_complete!("forced_schedule_mutations_refuse_before_the_wrong_poll");
    }

    #[test]
    fn forced_schedule_partial_and_resource_limited_receipts_fail_closed() {
        init_test("forced_schedule_partial_and_resource_limited_receipts_fail_closed");
        let config = LabConfig::new(0xF0CE_D5CE).max_steps(128);

        let mut source = LabRuntime::new(config.clone());
        source
            .start_forced_schedule_recording(1)
            .expect("start empty terminal-time capture");
        source.advance_time_to(Time::from_nanos(17));
        let terminal_time_only = source
            .finish_forced_schedule_recording()
            .expect("finish empty terminal-time capture");
        assert!(terminal_time_only.dispatches().is_empty());
        let mut replay = LabRuntime::new(config.clone());
        assert!(matches!(
            replay.run_forced_schedule(&terminal_time_only, ForcedScheduleLimits::new(1, 1)),
            Err(ForcedScheduleError::TerminalMismatch {
                expected_nanos: 17,
                actual_nanos: 0,
                ..
            })
        ));

        let observations = Arc::new(Mutex::new(Vec::new()));
        let mut source = forced_schedule_fixture(config.clone(), observations);
        source
            .start_forced_schedule_recording(32)
            .expect("start deliberately partial capture");
        let partial = source
            .finish_forced_schedule_recording()
            .expect("partial source is represented, not silently promoted");
        let observations = Arc::new(Mutex::new(Vec::new()));
        let mut replay = forced_schedule_fixture(config.clone(), Arc::clone(&observations));
        assert_eq!(
            replay.run_forced_schedule(&partial, ForcedScheduleLimits::new(32, 128)),
            Err(ForcedScheduleError::PartialSource)
        );
        assert!(observations.lock().is_empty());

        let observations = Arc::new(Mutex::new(Vec::new()));
        let mut source = forced_schedule_fixture(config.clone(), observations);
        source
            .start_forced_schedule_recording(1)
            .expect("start deliberately bounded capture");
        assert!(source.run_until_quiescent_with_report().quiescent);
        assert!(matches!(
            source.finish_forced_schedule_recording(),
            Err(ForcedScheduleError::RecordingLimitExceeded { max_dispatches: 1 })
        ));

        let observations = Arc::new(Mutex::new(Vec::new()));
        let mut source = forced_schedule_fixture(config.clone(), observations);
        source
            .start_forced_schedule_recording(32)
            .expect("start exact dispatch capture");
        assert!(source.run_until_quiescent_with_report().quiescent);
        let schedule = source
            .finish_forced_schedule_recording()
            .expect("complete exact dispatch projection");

        let observations = Arc::new(Mutex::new(Vec::new()));
        let mut replay = forced_schedule_fixture(config.clone(), observations);
        assert!(matches!(
            replay.run_forced_schedule(&schedule, ForcedScheduleLimits::new(1, 128)),
            Err(ForcedScheduleError::DispatchLimitExceeded { .. })
        ));

        let observations = Arc::new(Mutex::new(Vec::new()));
        let mut replay = forced_schedule_fixture(config.clone(), Arc::clone(&observations));
        assert!(matches!(
            replay.run_forced_schedule(&schedule, ForcedScheduleLimits::new(32, 1)),
            Err(ForcedScheduleError::WorkLimitExceeded { .. })
        ));
        assert!(observations.lock().is_empty());

        let mut mismatched_config = config.clone();
        mismatched_config.enable_cancellation_oracle = !config.enable_cancellation_oracle;
        let observations = Arc::new(Mutex::new(Vec::new()));
        let mut replay = forced_schedule_fixture(mismatched_config, Arc::clone(&observations));
        assert!(matches!(
            replay.run_forced_schedule(&schedule, ForcedScheduleLimits::new(32, 128)),
            Err(ForcedScheduleError::ConfigMismatch { .. })
        ));
        assert!(observations.lock().is_empty());

        let mut truncated = schedule.clone();
        truncated.dispatches.pop();
        let observations = Arc::new(Mutex::new(Vec::new()));
        let mut replay = forced_schedule_fixture(config, observations);
        assert!(matches!(
            replay.run_forced_schedule(&truncated, ForcedScheduleLimits::new(32, 128)),
            Err(ForcedScheduleError::ScheduleExhausted { .. })
                | Err(ForcedScheduleError::CertificateMismatch { .. })
        ));
        crate::test_complete!("forced_schedule_partial_and_resource_limited_receipts_fail_closed");
    }

    /// Regression test: replay recorder must capture the actual completion
    /// severity from the finalized task record, not always `Severity::Ok`.
    ///
    /// `create_task` wraps futures to always return `Outcome::Ok(())` — the
    /// real severity is determined by the cancel protocol state machine. This
    /// test puts a task through the cancel protocol and verifies the replay
    /// trace records the correct `Cancelled` severity.
    #[test]
    fn replay_records_correct_severity_for_cancelled_task() {
        init_test("replay_records_correct_severity_for_cancelled_task");

        let config = LabConfig::new(42)
            .panic_on_leak(false)
            .with_default_replay_recording();
        let mut runtime = LabRuntime::new(config);
        let root = runtime
            .state
            .create_root_region(crate::types::Budget::INFINITE);

        // Create a task that yields once then completes with Ok.
        // The yield allows us to cancel the task before it finishes.
        let (task_id, _) = runtime
            .state
            .create_task(root, crate::types::Budget::INFINITE, async {
                crate::runtime::yield_now::yield_now().await;
            })
            .expect("create task");
        runtime.scheduler.lock().schedule(task_id, 0);

        // Step once: task yields (Pending)
        runtime.step();

        // Put the task through cancel protocol: CancelRequested → Cancelling
        let cancel_effects = runtime
            .state
            .update_task(task_id, |record| {
                let effects =
                    record.request_cancel(crate::types::CancelReason::user("test-cancel"));
                let _ = record.acknowledge_cancel();
                // Task is now in Cancelling state
                assert!(
                    matches!(
                        record.state,
                        crate::record::task::TaskState::Cancelling { .. }
                    ),
                    "task should be in Cancelling state"
                );
                effects
            })
            .unwrap();

        // Reschedule and run to completion: the cancel protocol will
        // complete it as Cancelled when the wrapped future returns Ok.
        runtime.scheduler.lock().schedule_cancel(task_id, 0);
        let (_, cancel_wakes) = cancel_effects.into_parts();
        cancel_wakes.dispatch();
        runtime.run_until_quiescent();

        // Verify the task completed as Cancelled
        if let Some(record) = runtime.state.task(task_id) {
            assert!(
                matches!(
                    record.state,
                    crate::record::task::TaskState::Completed(crate::types::Outcome::Cancelled(_))
                ),
                "task should be Completed(Cancelled), got {:?}",
                record.state
            );
        }

        // Check the replay trace for the TaskCompleted event
        let replay = runtime
            .replay_recorder()
            .snapshot()
            .expect("replay recording enabled");
        let completed_events: Vec<_> = replay
            .events
            .iter()
            .filter(|e| matches!(e, crate::trace::replay::ReplayEvent::TaskCompleted { .. }))
            .collect();

        assert!(
            !completed_events.is_empty(),
            "should have at least one TaskCompleted event"
        );

        // The severity should be Cancelled (2), not Ok (0)
        for event in &completed_events {
            if let crate::trace::replay::ReplayEvent::TaskCompleted { outcome, .. } = event {
                let expected = crate::types::Severity::Cancelled.as_u8();
                crate::assert_with_log!(
                    *outcome == expected,
                    "severity should be Cancelled (2)",
                    expected,
                    *outcome
                );
            }
        }

        crate::test_complete!("replay_records_correct_severity_for_cancelled_task");
    }

    #[test]
    fn replay_recording_metadata_is_stable_for_same_seed() {
        init_test("replay_recording_metadata_is_stable_for_same_seed");

        let mut first = LabRuntime::new(LabConfig::new(42).with_default_replay_recording());
        let mut second = LabRuntime::new(LabConfig::new(42).with_default_replay_recording());

        let first_trace = first
            .finish_replay_trace()
            .expect("first replay recording enabled");
        let second_trace = second
            .finish_replay_trace()
            .expect("second replay recording enabled");

        crate::assert_with_log!(
            first_trace.metadata == second_trace.metadata,
            "replay metadata should match for identical seeds",
            &first_trace.metadata,
            &second_trace.metadata
        );
        crate::assert_with_log!(
            first_trace.events == second_trace.events,
            "replay events should match for identical seeds",
            &first_trace.events,
            &second_trace.events
        );
        crate::assert_with_log!(
            first_trace.metadata.recorded_at == 0,
            "recorded_at defaults to deterministic zero stamp",
            0u64,
            first_trace.metadata.recorded_at
        );

        crate::test_complete!("replay_recording_metadata_is_stable_for_same_seed");
    }

    // =========================================================================
    // Pure data-type tests (wave 40 – CyanBarn)
    // =========================================================================

    #[test]
    fn lab_trace_certificate_summary_debug_clone_copy_eq() {
        let summary = LabTraceCertificateSummary {
            event_hash: 123,
            event_count: 456,
            schedule_hash: 789,
        };
        let copied = summary;
        let cloned = summary;
        assert_eq!(copied, cloned);
        assert_ne!(
            summary,
            LabTraceCertificateSummary {
                event_hash: 0,
                event_count: 456,
                schedule_hash: 789,
            }
        );
        let dbg = format!("{summary:?}");
        assert!(dbg.contains("LabTraceCertificateSummary"));
    }

    #[test]
    fn virtual_time_report_debug_clone_copy_eq() {
        let report = VirtualTimeReport {
            steps: 100,
            auto_advances: 5,
            total_wakeups: 10,
            time_start: Time::ZERO,
            time_end: Time::from_millis(500),
            virtual_elapsed_nanos: 500_000_000,
            termination: AutoAdvanceTermination::Quiescent,
        };
        let copied = report;
        assert_eq!(copied, report);
        assert_eq!(report.virtual_elapsed_ms(), 500);
        assert_eq!(report.virtual_elapsed_secs(), 0);
        let dbg = format!("{report:?}");
        assert!(dbg.contains("VirtualTimeReport"));
    }

    // =========================================================================
    // AutoAdvanceTermination tests (bead 56c785)
    // =========================================================================

    #[asupersync::lab_test(seeds = 42..43)]
    fn auto_advance_quiescent_termination(lab: &mut LabRuntime) {
        // No tasks enqueued → immediately quiescent
        let report = lab.run_with_auto_advance();
        assert_eq!(
            report.termination,
            AutoAdvanceTermination::Quiescent,
            "empty runtime should terminate as quiescent"
        );
    }

    #[test]
    fn auto_advance_step_limit_termination() {
        init_test("auto_advance_step_limit_termination");
        let mut lab = LabRuntime::new(LabConfig::new(42).max_steps(0));
        let report = lab.run_with_auto_advance();
        assert_eq!(
            report.termination,
            AutoAdvanceTermination::StepLimitReached,
            "zero max_steps should terminate as step-limit-reached"
        );
        crate::test_complete!("auto_advance_step_limit_termination");
    }

    #[test]
    fn auto_advance_stuck_bailout_termination() {
        init_test("auto_advance_stuck_bailout_termination");
        let config = LabConfig::new(42)
            .with_auto_advance()
            .no_step_limit()
            .futurelock_max_idle_steps(0);
        let mut lab = LabRuntime::new(config);
        let root = lab.state.create_root_region(Budget::INFINITE);
        let (task_id, _handle) = lab
            .state
            .create_task(root, Budget::INFINITE, async {
                std::future::pending::<()>().await;
            })
            .expect("create pending task");
        lab.scheduler.lock().schedule(task_id, 0);

        let report = lab.run_with_auto_advance();
        assert_eq!(
            report.termination,
            AutoAdvanceTermination::StuckBailout,
            "pending task without deadlines should terminate via stuck bailout"
        );
        assert!(
            !lab.is_quiescent(),
            "stuck bailout should preserve non-quiescent state for diagnosis"
        );
        assert_eq!(
            report.auto_advances, 0,
            "stuck bailout path should not auto-advance virtual time without deadlines"
        );
        crate::test_complete!("auto_advance_stuck_bailout_termination");
    }

    #[test]
    fn auto_advance_termination_display() {
        assert_eq!(
            format!("{}", AutoAdvanceTermination::Quiescent),
            "quiescent"
        );
        assert_eq!(
            format!("{}", AutoAdvanceTermination::StepLimitReached),
            "step-limit-reached"
        );
        assert_eq!(
            format!("{}", AutoAdvanceTermination::StuckBailout),
            "stuck-bailout"
        );
    }

    #[test]
    fn auto_advance_termination_debug_clone_copy_eq_hash() {
        use std::collections::HashSet;
        let variants = [
            AutoAdvanceTermination::Quiescent,
            AutoAdvanceTermination::StepLimitReached,
            AutoAdvanceTermination::StuckBailout,
        ];
        // Copy + Clone + Eq
        for &v in &variants {
            let copied = v;
            let cloned = v;
            assert_eq!(copied, cloned);
        }
        // Hash uniqueness
        let mut set = HashSet::new();
        for &v in &variants {
            assert!(set.insert(v));
        }
        assert_eq!(set.len(), 3);
        // Debug contains type name
        let dbg = format!("{:?}", AutoAdvanceTermination::StuckBailout);
        assert!(dbg.contains("StuckBailout"));
    }

    #[test]
    fn harness_attachment_kind_debug_clone_copy_eq_hash_ord_display() {
        use std::collections::HashSet;
        let kinds = [
            HarnessAttachmentKind::CrashPack,
            HarnessAttachmentKind::ReplayTrace,
            HarnessAttachmentKind::Trace,
            HarnessAttachmentKind::Other,
        ];
        // Display
        assert_eq!(format!("{}", kinds[0]), "crashpack");
        assert_eq!(format!("{}", kinds[1]), "replay_trace");
        assert_eq!(format!("{}", kinds[2]), "trace");
        assert_eq!(format!("{}", kinds[3]), "other");
        // Copy/Clone/Eq
        for &k in &kinds {
            let copied = k;
            let cloned = k;
            assert_eq!(copied, cloned);
        }
        // Hash
        let mut set = HashSet::new();
        for &k in &kinds {
            set.insert(k);
        }
        assert_eq!(set.len(), 4);
        // Ord (derive ordering: CrashPack < ReplayTrace < Trace < Other)
        assert!(HarnessAttachmentKind::CrashPack < HarnessAttachmentKind::ReplayTrace);
        assert!(HarnessAttachmentKind::ReplayTrace < HarnessAttachmentKind::Trace);
        assert!(HarnessAttachmentKind::Trace < HarnessAttachmentKind::Other);
        let mut sorted = [kinds[3], kinds[0], kinds[2], kinds[1]];
        sorted.sort();
        assert_eq!(sorted, kinds);
    }

    #[test]
    fn harness_attachment_ref_debug_clone_eq_hash() {
        use std::collections::HashSet;
        let ref1 = HarnessAttachmentRef::crashpack("crash.bin");
        let ref2 = HarnessAttachmentRef::replay_trace("replay.bin");
        let ref3 = HarnessAttachmentRef::trace("trace.ndjson");
        assert_eq!(ref1.kind, HarnessAttachmentKind::CrashPack);
        assert_eq!(ref2.kind, HarnessAttachmentKind::ReplayTrace);
        assert_eq!(ref3.kind, HarnessAttachmentKind::Trace);
        let cloned = ref1.clone();
        assert_eq!(cloned, ref1);
        assert_ne!(ref1, ref2);
        let dbg = format!("{ref1:?}");
        assert!(dbg.contains("HarnessAttachmentRef"));
        let mut set = HashSet::new();
        set.insert(ref1.clone());
        set.insert(ref2);
        set.insert(ref1); // duplicate
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn chaos_config_summary_debug_clone_copy_partial_eq() {
        let summary = ChaosConfigSummary {
            seed: 42,
            cancel_probability: 0.1,
            delay_probability: 0.2,
            io_error_probability: 0.05,
            wakeup_storm_probability: 0.01,
            budget_exhaust_probability: 0.03,
        };
        let copied = summary;
        let cloned = summary;
        assert_eq!(copied, cloned);
        let dbg = format!("{summary:?}");
        assert!(dbg.contains("ChaosConfigSummary"));
    }

    #[test]
    fn obligation_leak_debug_clone_eq_display() {
        let leak = ObligationLeak {
            obligation: ObligationId::new_for_test(1, 0),
            kind: ObligationKind::SendPermit,
            holder: TaskId::from_arena(crate::util::ArenaIndex::new(1, 0)),
            region: RegionId::new_for_test(0, 0),
        };
        let cloned = leak.clone();
        assert_eq!(cloned, leak);
        let dbg = format!("{leak:?}");
        assert!(dbg.contains("ObligationLeak"));
        let display = format!("{leak}");
        assert!(display.contains("obligation="));
        assert!(display.contains("kind=SendPermit"));
        assert!(display.contains("holder="));
        assert!(display.contains("region="));
    }

    // ================================================================
    // CONFORMANCE TESTS: LabRuntime Deterministic Seed Reproduction
    // ================================================================
    //
    // Golden tests verifying the non-negotiable determinism invariants:
    // (1) Same seed produces byte-identical execution trace
    // (2) Virtual-time advances in same order across replays
    // (3) Scheduler lottery with same seed picks same tasks
    // (4) Chaos injection with same seed identical
    // (5) Cross-thread panic semantics preserved
    //
    // These conformance tests ensure LabRuntime provides reproducible
    // execution for debugging, testing, and formal verification.

    /// CONFORMANCE: Same seed produces byte-identical execution trace.
    ///
    /// Verifies that identical configuration and program produce identical
    /// trace fingerprints, event counts, and schedule certificates.
    #[test]
    fn conformance_identical_seed_identical_trace() {
        init_test("conformance_identical_seed_identical_trace");

        let seed = 42_u64;
        let config = LabConfig::new(seed).worker_count(2).max_steps(1000);

        // Run same program with same seed twice
        let mut reports = Vec::new();
        for run_id in 0..2 {
            let mut runtime = LabRuntime::new(config.clone());
            let root = runtime.state.create_root_region(Budget::INFINITE);

            // Create deterministic workload with multiple tasks
            for i in 0..5 {
                let (task_id, _handle) = runtime
                    .state
                    .create_task(root, Budget::INFINITE, async move {
                        // Simulate work with deterministic operations
                        for j in 0..10 {
                            futures_lite::future::yield_now().await;
                            if (i + j) % 3 == 0 {
                                let now =
                                    crate::cx::Cx::current().map_or(Time::ZERO, |cx| cx.now());
                                crate::time::sleep(now, Duration::from_millis(1)).await;
                            }
                        }
                        i * 100 + run_id
                    })
                    .expect("create task");
                runtime.scheduler.lock().schedule(task_id, 0);
            }

            let report = runtime.run_until_quiescent_with_report();
            reports.push(report);
        }

        // Verify identical traces
        let report1 = &reports[0];
        let report2 = &reports[1];

        crate::assert_with_log!(
            report1.seed == report2.seed,
            "seeds should be identical",
            report1.seed,
            report2.seed
        );

        crate::assert_with_log!(
            report1.trace_fingerprint == report2.trace_fingerprint,
            "trace fingerprints should be identical",
            report1.trace_fingerprint,
            report2.trace_fingerprint
        );

        crate::assert_with_log!(
            report1.trace_certificate.event_hash == report2.trace_certificate.event_hash,
            "event hashes should be identical",
            report1.trace_certificate.event_hash,
            report2.trace_certificate.event_hash
        );

        crate::assert_with_log!(
            report1.trace_certificate.event_count == report2.trace_certificate.event_count,
            "event counts should be identical",
            report1.trace_certificate.event_count,
            report2.trace_certificate.event_count
        );

        crate::assert_with_log!(
            report1.trace_certificate.schedule_hash == report2.trace_certificate.schedule_hash,
            "schedule hashes should be identical",
            report1.trace_certificate.schedule_hash,
            report2.trace_certificate.schedule_hash
        );

        crate::test_complete!("conformance_identical_seed_identical_trace");
    }

    /// CONFORMANCE: Virtual-time advances in same order across replays.
    ///
    /// Verifies that virtual time progression and auto-advancement
    /// behavior is deterministic across runs with the same seed.
    #[test]
    fn conformance_virtual_time_deterministic_advancement() {
        init_test("conformance_virtual_time_deterministic_advancement");

        let config = LabConfig::new(123).worker_count(1);

        crate::lab::assert_deterministic(config, |runtime| {
            let root = runtime.state.create_root_region(Budget::INFINITE);
            let initial_time = runtime.now();

            // Create tasks that sleep for different durations to test time advancement
            let durations = [
                Duration::from_millis(10),
                Duration::from_millis(5),
                Duration::from_millis(15),
                Duration::from_millis(1),
            ];

            for (i, duration) in durations.iter().enumerate() {
                let dur = *duration;
                let (task_id, _handle) = runtime
                    .state
                    .create_task(root, Budget::INFINITE, async move {
                        let now = crate::cx::Cx::current().map_or(Time::ZERO, |cx| cx.now());
                        crate::time::sleep(now, dur).await;
                        i
                    })
                    .expect("create task");
                runtime.scheduler.lock().schedule(task_id, 0);
            }

            // Use auto-advance to let virtual time progress deterministically
            let vtime_report = runtime.run_with_auto_advance();

            // Verify time advanced
            crate::assert_with_log!(
                vtime_report.time_end > initial_time,
                "virtual time should have advanced",
                vtime_report.time_end,
                initial_time
            );

            crate::assert_with_log!(
                vtime_report.auto_advances > 0,
                "should have auto-advanced virtual time",
                vtime_report.auto_advances,
                0
            );

            crate::assert_with_log!(
                vtime_report.termination == AutoAdvanceTermination::Quiescent,
                "should reach quiescence",
                vtime_report.termination,
                AutoAdvanceTermination::Quiescent
            );
        });

        crate::test_complete!("conformance_virtual_time_deterministic_advancement");
    }

    /// CONFORMANCE: Scheduler lottery with same seed picks same tasks.
    ///
    /// Verifies that scheduler decisions (task selection, worker assignment)
    /// are deterministic given the same random seed.
    #[test]
    fn conformance_scheduler_deterministic_lottery() {
        init_test("conformance_scheduler_deterministic_lottery");

        let config = LabConfig::new(456).worker_count(4);

        let mut schedule_sequences = Vec::new();

        // Run same workload multiple times to capture scheduler decisions
        for run in 0..2 {
            let mut runtime = LabRuntime::new(config.clone());
            let root = runtime.state.create_root_region(Budget::INFINITE);
            let mut task_order = Vec::new();

            // Create many competing tasks to stress scheduler lottery
            for task_idx in 0..20 {
                let (task_id, _handle) = runtime
                    .state
                    .create_task(root, Budget::INFINITE, async move {
                        // Add some yield points to allow preemption
                        for _ in 0..3 {
                            futures_lite::future::yield_now().await;
                        }
                        task_idx
                    })
                    .expect("create task");
                runtime.scheduler.lock().schedule(task_id, 0);
            }

            // Execute and capture schedule certificate
            runtime.run_until_quiescent();
            let cert = runtime.certificate();
            task_order.push((run, cert.decisions(), cert.hash()));
            schedule_sequences.push(task_order);
        }

        // Verify scheduler made same decisions across runs
        let seq1 = &schedule_sequences[0];
        let seq2 = &schedule_sequences[1];

        crate::assert_with_log!(
            seq1.len() == seq2.len(),
            "should have same number of scheduling decision points",
            seq1.len(),
            seq2.len()
        );

        for (i, ((_run1, count1, hash1), (_run2, count2, hash2))) in
            seq1.iter().zip(seq2.iter()).enumerate()
        {
            crate::assert_with_log!(
                count1 == count2,
                &format!("decision count should be identical at point {}", i),
                count1,
                count2
            );

            crate::assert_with_log!(
                hash1 == hash2,
                &format!("schedule hash should be identical at point {}", i),
                hash1,
                hash2
            );
        }

        crate::test_complete!("conformance_scheduler_deterministic_lottery");
    }

    /// CONFORMANCE: Chaos injection with same seed produces identical outcomes.
    ///
    /// Verifies that chaos injection (cancellation, delays, errors) is
    /// deterministically reproducible with the same chaos seed.
    #[test]
    fn conformance_chaos_injection_deterministic() {
        init_test("conformance_chaos_injection_deterministic");

        let chaos_config = crate::lab::chaos::ChaosConfig::new(789)
            .with_cancel_probability(0.1)
            .with_delay_probability(0.05)
            .with_io_error_probability(0.02);
        let config = LabConfig::new(999).with_chaos(chaos_config);

        crate::lab::assert_deterministic(config, |runtime| {
            let root = runtime.state.create_root_region(Budget::INFINITE);

            // Create workload susceptible to chaos injection
            for i in 0..10 {
                let (task_id, _handle) = runtime
                    .state
                    .create_task(root, Budget::INFINITE, async move {
                        // Multiple poll points where chaos can be injected
                        for j in 0..20 {
                            futures_lite::future::yield_now().await;
                            if j % 5 == 0 {
                                let now =
                                    crate::cx::Cx::current().map_or(Time::ZERO, |cx| cx.now());
                                crate::time::sleep(now, Duration::from_millis(1)).await;
                            }
                        }
                        i
                    })
                    .expect("create task");
                runtime.scheduler.lock().schedule(task_id, 0);
            }

            runtime.run_until_quiescent();

            // Verify chaos was actually applied
            let chaos_stats = runtime.chaos_stats();
            let total_decisions = chaos_stats.decision_points;

            crate::assert_with_log!(
                total_decisions > 0,
                "chaos should have made some decisions",
                total_decisions,
                0
            );
        });

        crate::test_complete!("conformance_chaos_injection_deterministic");
    }

    /// CONFORMANCE: Cross-thread panic semantics are preserved deterministically.
    ///
    /// Verifies that panic propagation and cleanup across workers/regions
    /// follows the same deterministic pattern with identical seeds.
    #[test]
    fn conformance_panic_semantics_deterministic() {
        init_test("conformance_panic_semantics_deterministic");

        let config = LabConfig::new(333)
            .worker_count(3)
            .panic_on_leak(false)
            .max_steps(10_000); // Fail diagnostically instead of hanging if panic cleanup regresses

        crate::lab::assert_deterministic(config, |runtime| {
            let root = runtime.state.create_root_region(Budget::INFINITE);

            // Create tasks where one will panic
            for i in 0..5 {
                let (task_id, _handle) = runtime
                    .state
                    .create_task(root, Budget::INFINITE, async move {
                        // Task 2 will deterministically panic
                        assert!(i != 2, "deterministic panic in task {}", i);

                        // Other tasks continue working
                        for _j in 0..10 {
                            futures_lite::future::yield_now().await;
                        }
                        i * 10
                    })
                    .expect("create task");
                runtime.scheduler.lock().schedule(task_id, 0);
            }

            // The lab trace no longer exposes a dedicated `TaskPanicked` data
            // variant. Drive the panic-bearing run to quiescence once and
            // inspect that same run's report rather than a second already-idle
            // pass.
            let report = runtime.run_until_quiescent_with_report();
            let trace_events = runtime.trace().snapshot();
            let complete_events = trace_events
                .iter()
                .filter(|event| event.kind == TraceEventKind::Complete)
                .count();

            crate::assert_with_log!(
                complete_events > 0,
                "should have recorded task completion activity",
                complete_events,
                0
            );

            // Verify deterministic cleanup occurred
            crate::assert_with_log!(
                report.quiescent,
                "runtime should reach quiescence despite panic",
                report.quiescent,
                false
            );
        });

        crate::test_complete!("conformance_panic_semantics_deterministic");
    }

    /// CONFORMANCE: Comprehensive multi-run determinism verification.
    ///
    /// Combines all previous conformance aspects into a stress test
    /// that verifies determinism across many execution runs.
    #[test]
    fn conformance_comprehensive_determinism_stress() {
        init_test("conformance_comprehensive_determinism_stress");

        let chaos_config = crate::lab::chaos::ChaosConfig::new(555)
            .with_cancel_probability(0.05)
            .with_delay_probability(0.03);
        let config = LabConfig::new(777)
            .worker_count(4)
            .with_chaos(chaos_config)
            .max_steps(5000);

        // Use assert_deterministic_multi for extra confidence
        crate::lab::assert_deterministic_multi(&config, 3, |runtime| {
            let root = runtime.state.create_root_region(Budget::INFINITE);

            // Complex workload mixing all runtime features
            for i in 0..15 {
                let (task_id, _handle) = runtime
                    .state
                    .create_task(root, Budget::INFINITE, async move {
                        // Mix of operations: yields, sleeps, work
                        for j in 0..30 {
                            match (i + j) % 4 {
                                0 => futures_lite::future::yield_now().await,
                                1 => {
                                    let now =
                                        crate::cx::Cx::current().map_or(Time::ZERO, |cx| cx.now());
                                    crate::time::sleep(now, Duration::from_millis(j as u64 % 5))
                                        .await;
                                }
                                2 => {
                                    // Simulate CPU work
                                    let mut sum = 0_u64;
                                    for k in 0..100 {
                                        sum = sum.wrapping_add(k);
                                    }
                                    let _ = sum;
                                }
                                _ => futures_lite::future::yield_now().await,
                            }
                        }
                        i * 1000 + 42
                    })
                    .expect("create task");
                runtime.scheduler.lock().schedule(task_id, 0);
            }

            // Use auto-advance for time progression
            let vtime_report = runtime.run_with_auto_advance();

            crate::assert_with_log!(
                vtime_report.termination == AutoAdvanceTermination::Quiescent,
                "comprehensive workload should reach quiescence",
                vtime_report.termination,
                AutoAdvanceTermination::Quiescent
            );
        });

        crate::test_complete!("conformance_comprehensive_determinism_stress");
    }

    #[test]
    #[allow(clippy::literal_string_with_formatting_args)]
    fn non_test_lab_runtime_paths_do_not_use_stray_stdout_debug_prints() {
        let source =
            std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(file!()))
                .expect("lab runtime source must be readable");

        for message in [
            "LabScheduler already scheduled {task:?}",
            "LabScheduler scheduling {task:?}",
            "Executing {:?} at step {}",
            "rng_value = {}, worker_hint = {}",
        ] {
            let stdout_call = format!("print{}!(\"{message}\"", "ln");
            assert!(
                !source.contains(&stdout_call),
                "non-test LabRuntime debug print regressed: {message}"
            );
        }
    }
}
