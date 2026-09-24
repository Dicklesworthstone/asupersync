//! Bounded, fail-closed driving of a production task-order projection.
//!
//! Production replay stops at the end of its projection. Only the explicit
//! [`LabRuntime::replay_production_schedule_prefix`] API resumes seeded
//! scheduling afterward. [`LabRuntime::run_production_schedule_strict`]
//! additionally bounds admission and requires consumption and quiescence. It
//! never polls a task after consuming the last recorded choice. A rejection, budget boundary,
//! or unwind leaves normal dispatch paused and retains the caller's runtime.
//! [`LabRuntime::discard_production_replay`] explicitly leaves replay mode so
//! the caller can cancel/drain that retained work under ordinary scheduling.
//!
//! This verifies task order under the existing spawn-ordinal binding, not exact
//! production identities, worker/lane choices, timing, entropy, I/O results, or
//! task outcomes. A source projection has no trustworthy terminal capture
//! watermark: matching it is not proof that the production capture was complete.
//! Effects must remain Lab-controlled for deterministic interpretation. Driver
//! step quotas cannot bound a user poll or callback that does not return.

use super::{
    LabRunReport, LabRuntime, OnReplayDivergence, ProductionReplayOptions, ProductionReplayState,
    ReplayReport,
};
use crate::trace::replay::{CompactTaskId, ProductionSchedule, ReplayEvent};

/// Authority granted to a production task-order projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum ProductionReplayMode {
    /// Stop before polling any task beyond the recorded choices.
    #[default]
    Strict,
    /// Explicitly permit exploratory execution after the recorded prefix.
    Prefix,
}

/// Typed replay boundary without extending the legacy report's public fields.
#[derive(Debug, Clone)]
pub struct ProductionReplayBoundary {
    /// Whether unrecorded continuation was explicitly authorized.
    pub mode: ProductionReplayMode,
    /// Known terminal classification; `None` means execution is still pending.
    /// A prefix never receives a strict `Matched` classification.
    pub termination: Option<StrictProductionReplayTermination>,
    /// Source rejection observed by the legacy-signature configurator.
    /// The bounded strict driver returns these errors before installation.
    pub source_error: Option<StrictProductionReplayError>,
    /// Actual number of tasks that entered the Lab scheduler.
    pub observed_spawns: usize,
    /// Recorded choices and any task-order divergence.
    pub replay: ReplayReport,
}

/// Source admission and driver work limits; no implicit unbounded defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StrictProductionReplayLimits {
    /// Maximum projected events scanned during admission, including non-polls.
    pub max_events: usize,
    /// Maximum source spawn identities retained for ordinal binding.
    pub max_spawns: usize,
    /// Maximum recorded task choices retained by the driver.
    pub max_dispatches: usize,
    /// Maximum driver steps, including waits and post-prefix command pumps.
    /// A zero budget admits the source but does not advance the runtime.
    pub max_work_units: u64,
    /// Maximum virtual-time waits for each recorded task to become runnable.
    /// Zero refuses an unavailable task without advancing time to wait for it.
    pub max_wait_steps: usize,
}

impl StrictProductionReplayLimits {
    /// Creates explicit source and execution limits.
    #[must_use]
    pub const fn new(
        max_events: usize,
        max_spawns: usize,
        max_dispatches: usize,
        max_work_units: u64,
        max_wait_steps: usize,
    ) -> Self {
        Self {
            max_events,
            max_spawns,
            max_dispatches,
            max_work_units,
            max_wait_steps,
        }
    }
}

/// Why the strict driver stopped. Incomplete work remains in the caller's runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum StrictProductionReplayTermination {
    /// Every recorded choice and spawn bound, and no live or queued work remained.
    Matched,
    /// The workload quiesced before the source's remaining choices were consumed.
    SourceRemaining,
    /// The source ended with live or queued work; no unrecorded task was polled.
    SourceExhausted,
    /// The observed and recorded spawn counts differed.
    SpawnCountMismatch {
        /// Number of identities in the source projection.
        expected: usize,
        /// Total first entries observed by the Lab scheduler, without clamping.
        observed: usize,
    },
    /// The recorded next task could not be dispatched. See the replay report.
    Diverged,
    /// The caller's driver-step quota was exhausted.
    WorkLimit,
    /// The Lab configuration's step limit was reached; it was not overridden.
    ConfiguredStepLimit,
}

/// Actual observations at the strict replay boundary, not a universal replay proof.
#[derive(Debug, Clone)]
pub struct StrictProductionReplayReport {
    /// Exact terminal classification.
    pub termination: StrictProductionReplayTermination,
    /// Driver steps consumed, including steps that did not poll any task.
    pub work_units: u64,
    /// Unclamped number of first task entries in the reconstructed runtime.
    pub observed_spawns: usize,
    /// Source choices consumed, binding counts, and the first divergence.
    /// `stopped` is true on every returned strict receipt, including a match.
    pub replay: ReplayReport,
    /// Runtime/oracle observations at the same boundary.
    pub lab: LabRunReport,
}

impl StrictProductionReplayReport {
    /// Whether source consumption and quiescence matched and Lab checks passed.
    /// Does not compare production effects or classify the original failure.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.termination == StrictProductionReplayTermination::Matched
            && self.replay.divergence.is_none()
            && self.replay.steps_matched == self.replay.steps_total
            && self.lab.lab_test_passed()
    }
}

/// Admission failed before replay state was installed or execution advanced.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum StrictProductionReplayError {
    /// A strict replay must start before the first execution step or dispatch.
    #[error(
        "strict production replay requires a fresh runtime (steps {steps}, decisions {decisions})"
    )]
    AlreadyStarted {
        /// Runtime steps already executed.
        steps: u64,
        /// Scheduling decisions already recorded.
        decisions: u64,
    },
    /// An existing replay is never silently replaced.
    #[error("production replay is already configured")]
    ReplayAlreadyConfigured,
    /// Exact-dispatch recording and this driver must be explicitly separated.
    #[error("exact-dispatch recording is active")]
    RecordingActive,
    /// Pre-poll chaos can consume a selected choice without polling its task.
    #[error("strict production replay refuses active chaos injection")]
    ChaosActive,
    /// Caller-owned source admission was exceeded before allocation/scanning.
    #[error("strict production replay {resource} limit exceeded: {found} > {limit}")]
    SourceLimit {
        /// Stable resource name: events, spawns, or dispatches.
        resource: &'static str,
        /// Source resource count.
        found: usize,
        /// Caller-owned maximum.
        limit: usize,
    },
    /// No recorded poll choices exist; a zero-test projection cannot pass.
    #[error("strict production replay requires at least one recorded poll")]
    NoDispatches,
    /// Missing birth events make ordinal reconstruction ambiguous.
    #[error("strict production replay refuses {count} orphan spawn identities")]
    OrphanSpawns {
        /// Identities admitted without a recorded spawn.
        count: usize,
    },
    /// Enqueue notifications are not evidence of actual task polls.
    #[error("strict production replay requires Poll events, not Schedule-event fallback")]
    NonPollSource,
    /// Source observations were duplicated or reordered before projection.
    #[error("production source sequence is not increasing: {previous} then {next}")]
    SourceOrder {
        /// Sequence of the earlier observation.
        previous: u64,
        /// Sequence of the following observation.
        next: u64,
    },
    /// The retained source does not satisfy its projection contract.
    #[error("invalid production schedule projection: {reason}")]
    InvalidProjection {
        /// Stable diagnostic; never includes captured effects or secrets.
        reason: &'static str,
    },
    /// A required bounded vector could not be reserved before installation.
    #[error("strict production replay could not allocate {count} {resource}")]
    Allocation {
        /// Stable storage name.
        resource: &'static str,
        /// Requested element capacity.
        count: usize,
    },
}

impl LabRuntime {
    /// Drive a production task-order projection without a seeded tail fallback.
    ///
    /// Source counts are checked before copying. Orphan identities, enqueue-
    /// only projections, and active pre-poll chaos injection are refused.
    /// Recorded tasks retain the legacy binding
    /// to the order in which Lab tasks first enter their scheduler. Legacy
    /// option and report shapes remain unchanged; prefix continuation requires
    /// an explicit call to [`Self::replay_production_schedule_prefix`].
    ///
    /// Each recorded choice is attempted through the existing production replay
    /// selector with `OnReplayDivergence::Stop`. After the last choice, only
    /// bounded command/obligation pumps may run, never another task poll. A
    /// complete receipt requires exact source consumption, exact spawn count,
    /// and no live or queued work. An incomplete receipt is not a successful
    /// replay, even if some or all recorded choices matched.
    ///
    /// Normal dispatch stays paused on every exit after admission, including an
    /// unwind. The caller retains `self`; cleanup is neither run implicitly nor
    /// certified. Call [`Self::discard_production_replay`] to explicitly leave
    /// replay mode before ordinary cancellation/drain. Keep the runtime outside
    /// a caller-owned unwind boundary when retained custody matters.
    ///
    /// # Errors
    /// Admission errors leave the existing runtime/replay state unchanged.
    /// Driver limits and observed divergence are returned in the receipt.
    ///
    /// # Panics
    /// Runtime/observer/oracle panics propagate unchanged. The pause guard is
    /// still installed during unwinding; it does not repair arbitrary damaged
    /// runtime state or contain aborts, double panics, or non-returning polls.
    pub fn run_production_schedule_strict(
        &mut self,
        schedule: &ProductionSchedule,
        limits: StrictProductionReplayLimits,
    ) -> Result<StrictProductionReplayReport, StrictProductionReplayError> {
        if self.steps != 0 || self.certificate.decisions() != 0 {
            return Err(StrictProductionReplayError::AlreadyStarted {
                steps: self.steps,
                decisions: self.certificate.decisions(),
            });
        }
        if self.production_replay.is_some() {
            return Err(StrictProductionReplayError::ReplayAlreadyConfigured);
        }
        if self.forced_schedule_recorder.is_some() {
            return Err(StrictProductionReplayError::RecordingActive);
        }
        if self.has_chaos() {
            return Err(StrictProductionReplayError::ChaosActive);
        }
        // Fully prepare off to the side. A failed admission never installs a
        // partial source, replaces another mode, or invokes user code.
        let replay = prepare_source(schedule, limits)?;
        self.production_replay = Some(replay);
        let mut pause = PauseOnExit { runtime: self };
        let start_steps = pause.runtime.steps;
        let mut work_units = 0;
        let termination = drive(&mut *pause.runtime, limits, &mut work_units);
        pause
            .runtime
            .production_replay
            .as_mut()
            .expect("strict source installed")
            .termination = Some(termination);
        // Pause before reporting too: reporting can itself invoke panic-prone
        // oracle/trace paths, and must not reopen ordinary dispatch on unwind.
        pause.freeze();
        let replay = pause
            .runtime
            .replay_report()
            .expect("strict source installed");
        let observed_spawns = pause.runtime.scheduler.lock().first_entry_count();
        let steps_delta = pause.runtime.steps.saturating_sub(start_steps);
        let lab = pause.runtime.report_with_steps_delta(steps_delta);
        Ok(StrictProductionReplayReport {
            termination,
            work_units,
            observed_spawns,
            replay,
            lab,
        })
    }

    /// Explicitly discard production replay authority and resume ordinary policy.
    ///
    /// Returns the last replay observations before removal. Subsequent task
    /// polls are cleanup or a new exploratory continuation, NOT part of that
    /// replay. This does not drain/cancel work or clear an exact recorder.
    /// Nothing changes when no production replay is configured.
    #[must_use]
    pub fn discard_production_replay(&mut self) -> Option<ReplayReport> {
        let report = self.replay_report()?;
        self.production_replay = None;
        Some(report)
    }

    /// Reports whether replay is strict, an explicit prefix, or incomplete.
    ///
    /// This does not dispatch work. Numerical gaps between source sequence
    /// numbers alone are not evidence of loss: the runtime can allocate a
    /// sequence without publishing an event. A match proves the reconstructed
    /// workload consumed the retained choices, not the capture's completeness.
    #[must_use]
    pub fn production_replay_boundary(&self) -> Option<ProductionReplayBoundary> {
        let state = self.production_replay.as_ref()?;
        let scheduler = self.scheduler.lock();
        let observed_spawns = scheduler.first_entry_count();
        let scheduler_empty = scheduler.is_empty();
        drop(scheduler);
        let termination = state.termination.or_else(|| {
            if state.source_error.is_some() || state.report.divergence.is_some() {
                return Some(StrictProductionReplayTermination::Diverged);
            }
            if state.mode == ProductionReplayMode::Prefix {
                return None;
            }
            let exhausted = state.next >= state.steps.len();
            let pending =
                self.has_pending_dispatch_commands() || self.state.has_pending_obligation_posts();
            if observed_spawns > state.spawn_order.len()
                || (exhausted
                    && !pending
                    && self.is_quiescent()
                    && observed_spawns != state.spawn_order.len())
            {
                return Some(StrictProductionReplayTermination::SpawnCountMismatch {
                    expected: state.spawn_order.len(),
                    observed: observed_spawns,
                });
            }
            if exhausted && !pending {
                return Some(if self.is_quiescent() && scheduler_empty {
                    StrictProductionReplayTermination::Matched
                } else {
                    StrictProductionReplayTermination::SourceExhausted
                });
            }
            if !exhausted && self.is_quiescent() && scheduler_empty {
                return Some(StrictProductionReplayTermination::SourceRemaining);
            }
            None
        });
        Some(ProductionReplayBoundary {
            mode: state.mode,
            termination,
            source_error: state.source_error.clone(),
            observed_spawns,
            replay: self.replay_report().expect("production replay installed"),
        })
    }
}

struct PauseOnExit<'a> {
    runtime: &'a mut LabRuntime,
}

impl PauseOnExit<'_> {
    fn freeze(&mut self) {
        if let Some(replay) = self.runtime.production_replay.as_mut() {
            replay.following = false;
            replay.report.stopped = true;
        }
    }
}

impl Drop for PauseOnExit<'_> {
    fn drop(&mut self) {
        self.freeze();
    }
}

fn admit(
    resource: &'static str,
    found: usize,
    limit: usize,
) -> Result<(), StrictProductionReplayError> {
    if found > limit {
        return Err(StrictProductionReplayError::SourceLimit {
            resource,
            found,
            limit,
        });
    }
    Ok(())
}

fn reserve<T>(resource: &'static str, count: usize) -> Result<Vec<T>, StrictProductionReplayError> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_| StrictProductionReplayError::Allocation { resource, count })?;
    Ok(values)
}

pub(super) fn prepare_source(
    schedule: &ProductionSchedule,
    limits: StrictProductionReplayLimits,
) -> Result<ProductionReplayState, StrictProductionReplayError> {
    let events = &schedule.trace().events;
    let spawns = schedule.spawn_order();
    admit("events", events.len(), limits.max_events)?;
    admit("spawns", spawns.len(), limits.max_spawns)?;
    if let Some((previous, next)) = schedule.source_sequence_disorder() {
        return Err(StrictProductionReplayError::SourceOrder { previous, next });
    }
    if !schedule.summary().orphans.is_empty() {
        return Err(StrictProductionReplayError::OrphanSpawns {
            count: schedule.summary().orphans.len(),
        });
    }
    let count = events
        .iter()
        .filter(|event| matches!(event, ReplayEvent::TaskScheduled { .. }))
        .count();
    admit("dispatches", count, limits.max_dispatches)?;
    if count == 0 {
        return Err(StrictProductionReplayError::NoDispatches);
    }
    if schedule.summary().steps_from_schedule_events {
        return Err(StrictProductionReplayError::NonPollSource);
    }
    if count != schedule.summary().steps || spawns.len() != schedule.summary().spawned {
        return Err(StrictProductionReplayError::InvalidProjection {
            reason: "source counts disagree",
        });
    }

    // Avoid ProductionSchedule::steps' per-poll linear spawn lookup. Admission
    // uses O(events + spawns log spawns + dispatches log spawns) bounded work.
    let mut lookup = reserve::<(u64, usize)>("spawn lookup entries", spawns.len())?;
    lookup.extend(
        spawns
            .iter()
            .enumerate()
            .map(|(ordinal, id)| (id.0, ordinal)),
    );
    lookup.sort_unstable_by_key(|entry| entry.0);
    if lookup.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(StrictProductionReplayError::InvalidProjection {
            reason: "duplicate spawn identity",
        });
    }
    let mut steps = reserve("dispatch entries", count)?;
    let mut previous_tick = None;
    for event in events {
        let ReplayEvent::TaskScheduled { task, at_tick } = event else {
            continue;
        };
        if previous_tick.is_some_and(|previous| *at_tick <= previous) {
            return Err(StrictProductionReplayError::InvalidProjection {
                reason: "poll sequence is not strictly increasing",
            });
        }
        let index = lookup
            .binary_search_by_key(&task.0, |entry| entry.0)
            .map_err(|_| StrictProductionReplayError::InvalidProjection {
                reason: "poll has no spawn identity",
            })?;
        steps.push((lookup[index].1, *at_tick));
        previous_tick = Some(*at_tick);
    }
    let mut spawn_order = reserve::<CompactTaskId>("spawn identities", spawns.len())?;
    spawn_order.extend_from_slice(spawns);
    Ok(ProductionReplayState {
        steps,
        spawn_order,
        options: ProductionReplayOptions {
            on_divergence: OnReplayDivergence::Stop,
            max_wait_steps: limits.max_wait_steps,
        },
        next: 0,
        waited: 0,
        following: true,
        mode: ProductionReplayMode::Strict,
        termination: None,
        source_error: None,
        selected: None,
        report: ReplayReport {
            steps_total: count,
            ..ReplayReport::default()
        },
    })
}

fn drive(
    runtime: &mut LabRuntime,
    limits: StrictProductionReplayLimits,
    work_units: &mut u64,
) -> StrictProductionReplayTermination {
    use StrictProductionReplayTermination as End;
    loop {
        let replay = runtime
            .production_replay
            .as_ref()
            .expect("strict source installed");
        if let Some(termination) = replay.termination {
            return termination;
        }
        if replay.report.divergence.is_some() || replay.report.stopped || !replay.following {
            return End::Diverged;
        }
        let exhausted = replay.next >= replay.steps.len();
        let expected_spawns = replay.spawn_order.len();
        let observed_spawns = runtime.scheduler.lock().first_entry_count();
        if observed_spawns > expected_spawns {
            return End::SpawnCountMismatch {
                expected: expected_spawns,
                observed: observed_spawns,
            };
        }
        let pending_commands =
            runtime.has_pending_dispatch_commands() || runtime.state.has_pending_obligation_posts();
        if exhausted && !pending_commands {
            if !runtime.is_quiescent() || !runtime.scheduler.lock().is_empty() {
                return End::SourceExhausted;
            }
            return if observed_spawns == expected_spawns {
                End::Matched
            } else {
                End::SpawnCountMismatch {
                    expected: expected_spawns,
                    observed: observed_spawns,
                }
            };
        }
        if !exhausted && runtime.is_quiescent() && runtime.scheduler.lock().is_empty() {
            return End::SourceRemaining;
        }
        if runtime
            .config
            .max_steps
            .is_some_and(|max| runtime.steps >= max)
        {
            return End::ConfiguredStepLimit;
        }
        if *work_units >= limits.max_work_units {
            return End::WorkLimit;
        }
        *work_units += 1;
        if exhausted {
            // A terminal command pump must have no authority to select a task,
            // independent of the production selector's current replay mode.
            let dispatched = runtime
                .step_with_candidate_dispatch(None)
                .expect("system-only pump has no candidate dispatch to reject");
            debug_assert!(!dispatched, "strict terminal pump cannot dispatch work");
        } else {
            runtime.step();
        }
    }
}

#[cfg(test)]
mod tests;
