//! Failure-preserving reduction of executable lab schedules.
//!
//! Unlike deleting trace events, this runs every candidate through the real
//! `LabRuntime` exact-choice runner. The complete source must first replay
//! strictly and reproduce one caller-defined failure identity. Only quiescent
//! candidates reproducing that same identity on fresh runtimes are retained.
//! Exhaustion, impossible choices and a different failure are not reproductions.
//!
//! All factories must reconstruct the same lab-controlled workload and retain
//! any task handles in their returned fixture. Classifiers inspect the fixture
//! and terminal report; they must not advance execution. Neither callback may
//! use ambient I/O or spawn native work. Rejected lab instances are discarded,
//! which is a test reset, not proof that a live production region drained.
//!
//! Bounds cover admitted dispatch storage, runner work and factory invocations,
//! not wall-clock duration, callback allocation or a future that never returns
//! from `poll`. Callback panics propagate; they are never counted as a match.
//! Completion means a single-deletion pass finished under a stable classifier,
//! not globally shortest reproduction, exhaustive exploration or optimal DPOR.

use super::runtime::{
    ForcedSchedule, ForcedScheduleArtifactError, ForcedScheduleCandidate,
    ForcedScheduleCandidateLimits, ForcedScheduleCandidateTermination, ForcedScheduleError,
    ForcedScheduleLimits, LabRunReport, LabRuntime,
};
use sha2::{Digest, Sha256};

/// Portable minimized schedules and fail-closed downstream replay.
pub mod reproducer;

/// Stable caller-defined failure identity, normally a domain-separated digest.
///
/// Use the violated invariant/application error, not the whole trace hash or
/// step count (which change during reduction). Do not embed secret payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FailureKey(pub [u8; 32]);

/// Explicit storage, execution and confirmation bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScheduleMinimizerLimits {
    /// Maximum dispatch count in the complete source.
    pub max_source_dispatches: usize,
    /// Maximum fresh runtime constructions, including strict source replay and baseline confirmations.
    pub max_attempts: usize,
    /// Maximum runner work units granted to one candidate.
    pub max_work_per_attempt: u64,
    /// Aggregate work budget; unsuccessful runner calls are charged their grant.
    pub max_total_work: u64,
    /// Fresh candidate confirmations, after one additional strict source replay.
    pub confirmations: usize,
}

/// Why reduction stopped. Every returned candidate has already reproduced.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScheduleMinimizerStop {
    /// Every single deletion of the final candidate was tried and refused.
    SingleDeletionPassComplete,
    /// No further factory invocation was admitted.
    AttemptLimit,
    /// No aggregate runner work remains.
    TotalWorkLimit,
    /// A candidate exhausted its individual work grant; minimality is unknown.
    ReplayWorkLimit,
    /// A candidate matched once but failed a later fresh confirmation.
    UnstableReproduction,
}

/// Bounded aggregate diagnostics; no trace or per-attempt fixture is retained.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ScheduleMinimizerStats {
    /// Fresh runtimes constructed, including source confirmation runs.
    pub attempts: usize,
    /// Runner work charged, including conservative grants for runner errors.
    pub charged_work: u64,
    /// Smaller candidates accepted after all confirmations.
    pub reductions: usize,
    /// Candidate executions rejected by the exact-choice runner.
    pub rejected: usize,
    /// Candidate executions that ended with live work remaining.
    pub incomplete: usize,
    /// Quiescent executions without the target failure identity.
    pub nonmatching: usize,
}

/// An executable, failure-confirmed subsequence of one identified source.
///
/// Private construction prevents accidental relabelling of an unexecuted
/// proposal as a minimization result. Persisted results still require fresh
/// replay; this receipt does not authenticate externally supplied artifacts.
#[derive(Debug, Clone)]
pub struct MinimizedSchedule {
    source_digest: [u8; 32],
    failure: FailureKey,
    retained: Vec<usize>,
    candidate: ForcedScheduleCandidate,
    stats: ScheduleMinimizerStats,
    stop: ScheduleMinimizerStop,
    confirmations: usize,
}

impl MinimizedSchedule {
    /// Digest of the canonical complete source, including its terminal receipt.
    #[must_use]
    pub const fn source_digest(&self) -> &[u8; 32] {
        &self.source_digest
    }

    /// Failure identity reproduced by the retained candidate.
    #[must_use]
    pub const fn failure(&self) -> FailureKey {
        self.failure
    }

    /// Ordered indices into the original source, never renumbered after deletion.
    #[must_use]
    pub fn retained_source_indices(&self) -> &[usize] {
        &self.retained
    }

    /// Executable candidate accepted by fresh confirmation runs.
    #[must_use]
    pub const fn candidate(&self) -> &ForcedScheduleCandidate {
        &self.candidate
    }

    /// Aggregate bounded campaign diagnostics.
    #[must_use]
    pub const fn stats(&self) -> ScheduleMinimizerStats {
        self.stats
    }

    /// Whether reduction completed its pass or stopped at a narrower boundary.
    #[must_use]
    pub const fn stop(&self) -> ScheduleMinimizerStop {
        self.stop
    }

    /// Required matching executions for every accepted result.
    #[must_use]
    pub const fn confirmations(&self) -> usize {
        self.confirmations
    }
}

/// Admission or baseline failures. No verified result exists on these paths.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum ScheduleMinimizerError {
    /// A required limit was zero or cannot admit the confirmation baseline.
    #[error("invalid schedule minimizer limit: {0}")]
    InvalidLimit(&'static str),
    /// The source cannot be derived into a bounded complete candidate.
    #[error("invalid minimizer source: {0}")]
    Source(ForcedScheduleError),
    /// The complete source cannot be encoded canonically.
    #[error("invalid minimizer source artifact: {0}")]
    Artifact(ForcedScheduleArtifactError),
    /// Fresh reconstruction failed strict source replay or full-candidate replay.
    #[error("baseline replay failed: {0}")]
    BaselineReplay(ForcedScheduleError),
    /// The first exact replay had no target failure.
    #[error("the exact source replay did not reproduce a classified failure")]
    NoBaselineFailure,
    /// The full candidate did not consistently reproduce the exact source failure.
    #[error("the exact source failure was not stable across confirmations")]
    UnstableBaseline,
    /// Bounded dispatch-index storage could not be allocated.
    #[error("could not allocate bounded minimizer index storage")]
    Allocation,
}

fn candidate_limits(limits: ScheduleMinimizerLimits, work: u64) -> ForcedScheduleCandidateLimits {
    ForcedScheduleCandidateLimits::new(
        limits.max_source_dispatches,
        limits.max_source_dispatches,
        work,
    )
}

fn source_digest(source: &ForcedSchedule) -> Result<[u8; 32], ScheduleMinimizerError> {
    let bytes = source
        .to_canonical_bytes()
        .map_err(ScheduleMinimizerError::Artifact)?;
    let mut hash = Sha256::new();
    hash.update(b"asupersync.lab.schedule-minimizer.source.v1\0");
    hash.update(bytes);
    Ok(hash.finalize().into())
}

fn indices_without(
    indices: &[usize],
    start: usize,
    end: usize,
) -> Result<Vec<usize>, ScheduleMinimizerError> {
    let mut kept = Vec::new();
    kept.try_reserve_exact(indices.len() - (end - start))
        .map_err(|_| ScheduleMinimizerError::Allocation)?;
    kept.extend_from_slice(&indices[..start]);
    kept.extend_from_slice(&indices[end..]);
    Ok(kept)
}

fn admit_attempt(
    limits: ScheduleMinimizerLimits,
    stats: &mut ScheduleMinimizerStats,
) -> Result<u64, ScheduleMinimizerStop> {
    if stats.attempts >= limits.max_attempts {
        return Err(ScheduleMinimizerStop::AttemptLimit);
    }
    let remaining = limits.max_total_work - stats.charged_work;
    if remaining == 0 {
        return Err(ScheduleMinimizerStop::TotalWorkLimit);
    }
    let grant = remaining.min(limits.max_work_per_attempt);
    stats.attempts += 1;
    // Reserve before foreign code. On runner error its consumed work is not
    // exposed, so conservatively keep this full charge instead of inventing 0.
    stats.charged_work += grant;
    Ok(grant)
}

/// Reduce a complete captured schedule while preserving one failure identity.
///
/// `build` returns a fresh runtime and caller-owned fixture/handles. `classify`
/// observes completed executions and returns `Some(key)` for a failure. First,
/// the original receipt must strictly replay, including its terminal hash,
/// step/time and quiescence. The full candidate must then reproduce the same
/// failure for every requested confirmation. Then contiguous
/// deletions are tried deterministically from large chunks down to singletons.
/// A smaller choice is retained only after all fresh confirmations match.
///
/// The strict baseline is conservatively charged at most one step and one
/// time/event pump per source step, plus one terminal pump. Candidate runners
/// expose actual work on success; errors retain their full reserved grant.
/// Admission is checked before constructing a runtime. Storage is O(source
/// dispatch count), independent of the attempt budget; no unbounded cache of
/// subsets or failing traces is built.
///
/// # Errors
///
/// Refuses invalid limits/source, an irreproducible or unstable baseline, and
/// allocation failure. Once a baseline exists, execution/confirmation limits
/// return the last verified candidate and a non-completion stop reason.
///
/// # Panics
///
/// Panics from factories, classifiers, runtime callbacks or fixture destruction
/// propagate. They are infrastructure failures, not candidate reproductions.
pub fn minimize_schedule<F, T, C>(
    source: &ForcedSchedule,
    limits: ScheduleMinimizerLimits,
    mut build: F,
    mut classify: C,
) -> Result<MinimizedSchedule, ScheduleMinimizerError>
where
    F: FnMut() -> (LabRuntime, T),
    C: FnMut(&LabRuntime, &T, &LabRunReport) -> Option<FailureKey>,
{
    if limits.max_source_dispatches == 0 {
        return Err(ScheduleMinimizerError::InvalidLimit("max_source_dispatches"));
    }
    if limits.confirmations == 0 || limits.max_attempts <= limits.confirmations {
        return Err(ScheduleMinimizerError::InvalidLimit("confirmations/max_attempts"));
    }
    if limits.max_work_per_attempt == 0 || limits.max_total_work == 0 {
        return Err(ScheduleMinimizerError::InvalidLimit("work budget"));
    }
    // Derive an empty proposal to validate complete source shape and count
    // before allocating index storage or invoking any workload factory.
    source
        .derive_candidate(&[], candidate_limits(limits, limits.max_work_per_attempt))
        .map_err(ScheduleMinimizerError::Source)?;
    let baseline_work = source
        .terminal_steps()
        .checked_mul(2)
        .and_then(|work| work.checked_add(1))
        .ok_or(ScheduleMinimizerError::InvalidLimit("baseline work overflow"))?;
    let confirmations = u64::try_from(limits.confirmations)
        .map_err(|_| ScheduleMinimizerError::InvalidLimit("confirmations overflow"))?;
    let baseline_total = limits.max_work_per_attempt
        .checked_mul(confirmations)
        .and_then(|work| work.checked_add(baseline_work))
        .ok_or(ScheduleMinimizerError::InvalidLimit("baseline total overflow"))?;
    if baseline_work > limits.max_work_per_attempt || baseline_total > limits.max_total_work {
        return Err(ScheduleMinimizerError::InvalidLimit("baseline work admission"));
    }
    let digest = source_digest(source)?;
    let mut retained = Vec::new();
    retained
        .try_reserve_exact(source.dispatches().len())
        .map_err(|_| ScheduleMinimizerError::Allocation)?;
    retained.extend(0..source.dispatches().len());
    let mut best = source
        .derive_candidate(&retained, candidate_limits(limits, limits.max_work_per_attempt))
        .map_err(ScheduleMinimizerError::Source)?;
    let mut stats = ScheduleMinimizerStats::default();
    stats.attempts += 1;
    stats.charged_work += baseline_work;
    let failure = {
        let (mut runtime, fixture) = build();
        runtime
            .run_forced_schedule(
                source,
                ForcedScheduleLimits::new(limits.max_source_dispatches, source.terminal_steps()),
            )
            .map_err(ScheduleMinimizerError::BaselineReplay)?;
        let lab = runtime.report();
        classify(&runtime, &fixture, &lab)
            .ok_or(ScheduleMinimizerError::NoBaselineFailure)?
    };
    // Confirm the full subsequence through the candidate engine too. Strict
    // replay and candidate replay have different time/command pumping rules;
    // a successful strict run alone must not certify a candidate never run.
    for _ in 0..limits.confirmations {
        let grant = admit_attempt(limits, &mut stats)
            .expect("aggregate baseline grants were admitted before the first factory");
        let (mut runtime, fixture) = build();
        let report = runtime
            .run_forced_schedule_candidate(&best, candidate_limits(limits, grant))
            .map_err(ScheduleMinimizerError::BaselineReplay)?;
        assert!(report.work_units <= grant, "candidate exceeded its work grant");
        stats.charged_work -= grant - report.work_units;
        if report.termination != ForcedScheduleCandidateTermination::Quiescent
            || classify(&runtime, &fixture, &report.lab) != Some(failure)
        {
            return Err(ScheduleMinimizerError::UnstableBaseline);
        }
    }
    let mut chunk = retained.len();
    let stop = 'search: loop {
        if retained.is_empty() {
            break ScheduleMinimizerStop::SingleDeletionPassComplete;
        }
        let mut start = 0;
        while start < retained.len() {
            let end = start.saturating_add(chunk).min(retained.len());
            let proposal_indices = indices_without(&retained, start, end)?;
            let proposal = source
                .derive_candidate(
                    &proposal_indices,
                    candidate_limits(limits, limits.max_work_per_attempt),
                )
                .map_err(ScheduleMinimizerError::Source)?;
            let mut matches = 0;
            for _ in 0..limits.confirmations {
                let grant = match admit_attempt(limits, &mut stats) {
                    Ok(grant) => grant,
                    Err(stop) => break 'search stop,
                };
                let (mut runtime, fixture) = build();
                let result = runtime.run_forced_schedule_candidate(
                    &proposal,
                    candidate_limits(limits, grant),
                );
                let matched = match result {
                    Ok(report) => {
                        // The runner enforces this bound before each action.
                        assert!(report.work_units <= grant, "candidate exceeded its work grant");
                        stats.charged_work -= grant - report.work_units;
                        if report.termination != ForcedScheduleCandidateTermination::Quiescent {
                            stats.incomplete += 1;
                            false
                        } else if classify(&runtime, &fixture, &report.lab) == Some(failure) {
                            true
                        } else {
                            stats.nonmatching += 1;
                            false
                        }
                    }
                    Err(ForcedScheduleError::CandidateWorkLimitExceeded { .. }) => {
                        break 'search ScheduleMinimizerStop::ReplayWorkLimit;
                    }
                    Err(_) => {
                        stats.rejected += 1;
                        false
                    }
                };
                if !matched {
                    if matches != 0 {
                        break 'search ScheduleMinimizerStop::UnstableReproduction;
                    }
                    break;
                }
                matches += 1;
            }
            if matches == limits.confirmations {
                retained = proposal_indices;
                best = proposal;
                stats.reductions += 1;
                if retained.is_empty() {
                    break 'search ScheduleMinimizerStop::SingleDeletionPassComplete;
                }
                chunk = chunk.min(retained.len());
                start = 0;
            } else {
                start = end;
            }
        }
        if chunk == 1 {
            break ScheduleMinimizerStop::SingleDeletionPassComplete;
        }
        chunk = chunk.div_ceil(2);
    };
    Ok(MinimizedSchedule {
        source_digest: digest,
        failure,
        retained,
        candidate: best,
        stats,
        stop,
        confirmations: limits.confirmations,
    })
}

#[cfg(test)]
mod tests;
