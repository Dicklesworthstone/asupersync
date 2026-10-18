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
//! production identities, worker/lane choices, timing, entropy or I/O results.
//! Terminal task outcomes are compared only when the schedule carries outcomes
//! captured beside the production trace, as
//! [`crate::trace::ScheduleCaptureSnapshot::production_schedule`] provides; a
//! difference is [`StrictProductionReplayTermination::OutcomeMismatch`]. Values
//! a task returns are never compared. A source projection has no trustworthy
//! terminal capture watermark: matching it is not proof that the production
//! capture was complete.
//! Cancellation injection and acknowledgement matching are additionally enabled
//! by [`crate::trace::ScheduleCaptureSnapshot::production_schedule_with_cancellation`].
//! That capture rejects requests without publication evidence and requests that
//! overlap native polls. Legacy task-order projections keep their old behavior.
//! Effects must remain Lab-controlled for deterministic interpretation. Driver
//! step quotas cannot bound a user poll or callback that does not return.

use super::{
    LabRunReport, LabRuntime, OnReplayDivergence, ProductionReplayOptions, ProductionReplayState,
    ReplayReport,
};
use crate::trace::event::{TraceData, TraceEventKind};
use crate::trace::replay::{
    CompactTaskId, ProductionCancellationEvent, ProductionCancellationPhase, ProductionSchedule,
    ReplayEvent,
};
use crate::types::Severity;

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
    /// Maximum projected events plus cancellation annex observations admitted.
    pub max_events: usize,
    /// Maximum source spawn identities retained for ordinal binding.
    pub max_spawns: usize,
    /// Maximum recorded task choices retained by the driver.
    pub max_dispatches: usize,
    /// Maximum driver steps, cancellation requests, waits and command pumps.
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
    /// A captured request or actual checkpoint acknowledgement did not match.
    CancellationMismatch {
        /// Index of the next expected cancellation observation in the annex.
        event_index: usize,
        /// Typed difference, without exposing captured task data in diagnostics.
        reason: CancellationReplayDivergence,
    },
    /// Order and quiescence matched, but a task's terminal outcome differs
    /// from the outcome captured for it (br-asupersync-bi2462.8). Reported
    /// only for a schedule that [`ProductionSchedule::carries_outcomes`].
    OutcomeMismatch {
        /// Spawn ordinal of the first task whose outcome differs.
        ordinal: usize,
        /// Outcome captured in production.
        expected: Severity,
        /// Outcome the Lab recorded; `None` when its completion is no longer
        /// in the Lab's trace ring.
        observed: Option<Severity>,
    },
}

/// Cancellation observation that prevented a strict replay match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CancellationReplayDivergence {
    /// The recorded task was not admitted or was already terminal.
    TargetUnavailable,
    /// A request was not applied at its recorded dispatch boundary.
    RequestBoundary,
    /// The workload had already requested cancellation before the captured request.
    UnexpectedRequest,
    /// The acknowledging source poll did not acknowledge cancellation in the Lab.
    MissingAcknowledgement,
    /// The Lab acknowledged cancellation without a matching source observation.
    UnexpectedAcknowledgement,
    /// The acknowledgement named a different task or originating poll.
    AcknowledgementOrder,
    /// The effective cancellation reason or cleanup budget differed.
    RequestMismatch,
    /// The acknowledgement carried a different effective cancellation reason.
    ReasonMismatch,
}

#[derive(Debug)]
struct BoundCancellationEvent {
    source: ProductionCancellationEvent,
    ordinal: usize,
    // ACK bookkeeping can follow another worker's Poll. Its semantic boundary
    // is the end of its own originating poll, whose ordinal the capture proves.
    boundary: usize,
}

#[derive(Debug)]
pub(super) struct CancellationReplay {
    events: Vec<BoundCancellationEvent>,
    next: usize,
    task_polls: Vec<usize>,
    requested: Vec<Option<usize>>,
    current_poll: Option<usize>,
}

impl CancellationReplay {
    pub(super) fn record_poll(&mut self, ordinal: usize) {
        self.task_polls[ordinal] += 1;
        self.current_poll = Some(ordinal);
    }

    fn mismatch(&self, reason: CancellationReplayDivergence) -> StrictProductionReplayTermination {
        StrictProductionReplayTermination::CancellationMismatch {
            event_index: self.next,
            reason,
        }
    }

    pub(super) fn observe_ack(
        &mut self,
        receipt: Option<&crate::record::task::CheckpointCancelAck>,
        consumed_dispatches: usize,
        context: Option<&(bool, Option<crate::types::CancelReason>)>,
    ) -> Option<StrictProductionReplayTermination> {
        use CancellationReplayDivergence as Why;
        let ordinal = self.current_poll.take();
        let expected = self.events.get(self.next);
        if let Some(receipt) = receipt {
            let Some(expected) = expected else {
                return Some(self.mismatch(Why::UnexpectedAcknowledgement));
            };
            if expected.source.phase() != ProductionCancellationPhase::Acknowledgement {
                return Some(self.mismatch(Why::UnexpectedAcknowledgement));
            }
            if ordinal != Some(expected.ordinal)
                || expected.boundary != consumed_dispatches
                || self.task_polls[expected.ordinal] != expected.source.task_poll_ordinal()
            {
                return Some(self.mismatch(Why::AcknowledgementOrder));
            }
            if &receipt.effective_reason != expected.source.reason() {
                return Some(self.mismatch(Why::ReasonMismatch));
            }
            self.next += 1;
        } else if expected.is_some_and(|event| {
            event.source.phase() == ProductionCancellationPhase::Acknowledgement
                && event.boundary <= consumed_dispatches
        }) {
            return Some(self.mismatch(Why::MissingAcknowledgement));
        }

        // Reading cancellation without checkpointing is observable too. A
        // checked source must not accept a silent Cx request or reason change.
        let Some(ordinal) = ordinal else {
            return Some(self.mismatch(Why::RequestBoundary));
        };
        let Some((requested, reason)) = context else {
            return Some(self.mismatch(Why::RequestMismatch));
        };
        if let Some(index) = self.requested[ordinal] {
            let source = &self.events[index].source;
            if !requested || reason.as_ref() != Some(source.reason()) {
                return Some(self.mismatch(Why::RequestMismatch));
            }
        } else if *requested || reason.is_some() {
            return Some(self.mismatch(Why::UnexpectedRequest));
        }
        None
    }

    fn complete(&self) -> bool {
        self.next == self.events.len()
    }
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
    /// Cancellation annexes require the bounded driver that injects requests.
    #[error("captured cancellation requires run_production_schedule_strict")]
    CancellationRequiresStrictDriver,
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
    /// and no live or queued work. When the schedule carries captured terminal
    /// outcomes, every recorded task must also end with the same outcome in
    /// the Lab, or the receipt is
    /// [`StrictProductionReplayTermination::OutcomeMismatch`]. An incomplete
    /// receipt is not a successful replay, even if some or all recorded
    /// choices matched. A cancellation annex additionally authorizes requests
    /// at its recorded dispatch boundaries and requires the matching actual
    /// checkpoint receipts, including acknowledgements on later cleanup polls.
    /// Each request consumes one work unit; missing or extra acknowledgements
    /// stop replay before the next task poll.
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
        if schedule.carries_outcomes() {
            // Keep the Lab's own terminal outcomes so they can be compared.
            self.trace().enable_completion_outcomes();
        }
        self.production_replay = Some(replay);
        let mut pause = PauseOnExit { runtime: self };
        let start_steps = pause.runtime.steps;
        let mut work_units = 0;
        let mut termination = drive(&mut *pause.runtime, limits, &mut work_units);
        if termination == StrictProductionReplayTermination::Matched
            && let Some(mismatch) = outcome_mismatch(pause.runtime, schedule)
        {
            termination = mismatch;
        }
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

/// The first recorded task, in spawn order, whose Lab outcome differs from
/// its captured outcome. Lab tasks bind to recorded tasks in the order they
/// first entered the scheduler, as for task order.
fn outcome_mismatch(
    runtime: &LabRuntime,
    schedule: &ProductionSchedule,
) -> Option<StrictProductionReplayTermination> {
    if !schedule.carries_outcomes() {
        return None;
    }
    let (events, _, kept) = runtime.trace().snapshot_with_outcomes();
    let kept: std::collections::BTreeMap<u64, Severity> = kept.into_iter().collect();
    let scheduler = runtime.scheduler.lock();
    schedule
        .spawn_order()
        .iter()
        .enumerate()
        .find_map(|(ordinal, source)| {
            let expected = schedule.captured_outcome(*source)?;
            let observed = scheduler.first_entry(ordinal).and_then(|lab_task| {
                events.iter().find_map(|event| match &event.data {
                    TraceData::Task { task, .. }
                        if event.kind == TraceEventKind::Complete && *task == lab_task =>
                    {
                        kept.get(&event.seq).copied()
                    }
                    _ => None,
                })
            });
            (observed != Some(expected)).then_some(
                StrictProductionReplayTermination::OutcomeMismatch {
                    ordinal,
                    expected,
                    observed,
                },
            )
        })
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
    let event_count = events
        .len()
        .checked_add(schedule.cancellation_events().map_or(0, <[ProductionCancellationEvent]>::len))
        .ok_or(StrictProductionReplayError::InvalidProjection {
            reason: "combined source event count overflow",
        })?;
    admit("events", event_count, limits.max_events)?;
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
    // A cancellation annex also sorts its bounded dispatch-location index.
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
    let cancellation = prepare_cancellation(schedule, &lookup, &steps)?;
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
        cancellation,
        report: ReplayReport {
            steps_total: count,
            ..ReplayReport::default()
        },
    })
}

fn prepare_cancellation(
    schedule: &ProductionSchedule,
    lookup: &[(u64, usize)],
    steps: &[(usize, u64)],
) -> Result<Option<CancellationReplay>, StrictProductionReplayError> {
    let Some(source) = schedule.cancellation_events() else {
        return Ok(None);
    };
    let spawns = schedule.spawn_order().len();
    let mut task_polls = reserve("cancellation poll counters", spawns)?;
    task_polls.resize(spawns, 0_usize);
    let mut poll_locations = reserve("cancellation poll locations", steps.len())?;
    for (index, &(ordinal, _)) in steps.iter().enumerate() {
        task_polls[ordinal] += 1;
        poll_locations.push((ordinal, task_polls[ordinal], index + 1));
    }
    poll_locations.sort_unstable_by_key(|&(ordinal, poll, _)| (ordinal, poll));
    let mut events = reserve("cancellation observations", source.len())?;
    let mut previous_sequence = None;
    let mut previous_boundary = None;
    for event in source {
        if previous_sequence.is_some_and(|previous| event.source_sequence() <= previous) {
            return Err(StrictProductionReplayError::InvalidProjection {
                reason: "cancellation sequence is not strictly increasing",
            });
        }
        let index = lookup
            .binary_search_by_key(&event.task().0, |entry| entry.0)
            .map_err(|_| StrictProductionReplayError::InvalidProjection {
                reason: "cancellation has no spawn identity",
            })?;
        let ordinal = lookup[index].1;
        let (boundary, phase_order) = match event.phase() {
            ProductionCancellationPhase::Request => (event.after_dispatches(), 1_u8),
            ProductionCancellationPhase::Acknowledgement => {
                let index = poll_locations
                    .binary_search_by_key(&(ordinal, event.task_poll_ordinal()), |entry| {
                        (entry.0, entry.1)
                    })
                    .map_err(|_| StrictProductionReplayError::InvalidProjection {
                        reason: "cancellation acknowledgement has no originating poll",
                    })?;
                (poll_locations[index].2, 0_u8)
            }
        };
        if boundary > steps.len() || boundary > event.after_dispatches() {
            return Err(StrictProductionReplayError::InvalidProjection {
                reason: "cancellation observation exceeds its dispatch boundary",
            });
        }
        if previous_boundary.is_some_and(|previous| (boundary, phase_order) < previous) {
            return Err(StrictProductionReplayError::InvalidProjection {
                reason: "cancellation observations cannot be serialized between polls",
            });
        }
        events.push(BoundCancellationEvent {
            source: event.clone(),
            ordinal,
            boundary,
        });
        previous_sequence = Some(event.source_sequence());
        previous_boundary = Some((boundary, phase_order));
    }
    task_polls.fill(0);
    let mut requested = reserve("cancellation request counters", spawns)?;
    requested.resize(spawns, None);
    Ok(Some(CancellationReplay {
        events,
        next: 0,
        task_polls,
        requested,
        current_poll: None,
    }))
}

/// Apply only a source-authorized task request. The source's reason remains
/// intact, including native provenance; only the target binds by spawn ordinal.
fn inject_cancellation(
    runtime: &mut LabRuntime,
    task_id: crate::types::TaskId,
    source: &ProductionCancellationEvent,
    already_requested: bool,
) -> Result<(), CancellationReplayDivergence> {
    use CancellationReplayDivergence as Why;
    let record = runtime
        .state
        .task(task_id)
        .filter(|record| !record.state.is_terminal())
        .ok_or(Why::TargetUnavailable)?;
    if !already_requested
        && (record.cancel_reason().is_some() || record.context_cancel_requested() == Some(true))
    {
        return Err(Why::UnexpectedRequest);
    }
    let old_state = record.state.clone();
    let (publish, wakes) = runtime
        .state
        .cancel_task_with_budget(task_id, source.reason(), source.cleanup_budget())
        .into_parts();
    let observed = runtime.state.task(task_id).map(|record| {
        (
            record.state.clone(),
            record.cancel_reason().cloned(),
            record.cleanup_budget(),
        )
    });
    if publish {
        let priority = observed
            .as_ref()
            .and_then(|(_, _, budget)| *budget)
            .map_or(source.cleanup_budget().priority, |budget| budget.priority);
        runtime.scheduler.lock().schedule_cancel(task_id, priority);
    }
    // Every queue/state guard is gone. A waking callback can now observe the
    // published cancellation lane, including for an already runnable target.
    wakes.dispatch();
    let Some((new_state, Some(reason), Some(budget))) = observed else {
        return Err(Why::RequestMismatch);
    };
    if runtime.config.has_cancellation_oracle() {
        runtime.notify_cancellation_oracle_cancel_request(task_id, reason.clone());
        runtime.notify_cancellation_oracle_task_transition(task_id, &old_state, &new_state);
    }
    if &reason != source.reason() || budget != source.cleanup_budget() {
        return Err(Why::RequestMismatch);
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn drive(
    runtime: &mut LabRuntime,
    limits: StrictProductionReplayLimits,
    work_units: &mut u64,
) -> StrictProductionReplayTermination {
    use CancellationReplayDivergence as Why;
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
        let due_request = if let Some(cancellation) = replay.cancellation.as_ref()
            && let Some(event) = cancellation.events.get(cancellation.next)
            && event.boundary <= replay.next
        {
            if event.source.phase() == ProductionCancellationPhase::Acknowledgement {
                return cancellation.mismatch(Why::MissingAcknowledgement);
            }
            if event.boundary != replay.next {
                return cancellation.mismatch(Why::RequestBoundary);
            }
            Some((
                cancellation.next,
                event.ordinal,
                event.source.clone(),
                cancellation.requested[event.ordinal].is_some(),
            ))
        } else {
            None
        };
        if let Some((event_index, ordinal, source, already_requested)) = due_request {
            // Injection is driver work. Neither a request nor a preparatory
            // admission pump may escape the caller's/configured work budget.
            if let Some(end) = work_boundary(runtime, limits, *work_units) {
                return end;
            }
            let target = runtime.scheduler.lock().first_entry(ordinal);
            let Some(target) = target else {
                if pending_commands {
                    *work_units += 1;
                    let dispatched = runtime
                        .step_with_candidate_dispatch(None)
                        .expect("cancellation admission pump has no candidate dispatch");
                    debug_assert!(!dispatched, "cancellation admission cannot poll work");
                    continue;
                }
                return End::CancellationMismatch {
                    event_index,
                    reason: Why::TargetUnavailable,
                };
            };
            *work_units += 1;
            if let Err(reason) = inject_cancellation(runtime, target, &source, already_requested) {
                return End::CancellationMismatch {
                    event_index,
                    reason,
                };
            }
            let cancellation = runtime
                .production_replay
                .as_mut()
                .expect("strict source installed")
                .cancellation
                .as_mut()
                .expect("captured request installed");
            cancellation.requested[ordinal] = Some(event_index);
            cancellation.next += 1;
            continue;
        }
        if exhausted && !pending_commands {
            if let Some(cancellation) = replay.cancellation.as_ref()
                && !cancellation.complete()
            {
                return cancellation.mismatch(Why::MissingAcknowledgement);
            }
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
        if let Some(end) = work_boundary(runtime, limits, *work_units) {
            return end;
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

fn work_boundary(
    runtime: &LabRuntime,
    limits: StrictProductionReplayLimits,
    work_units: u64,
) -> Option<StrictProductionReplayTermination> {
    if runtime
        .config
        .max_steps
        .is_some_and(|max| runtime.steps >= max)
    {
        return Some(StrictProductionReplayTermination::ConfiguredStepLimit);
    }
    (work_units >= limits.max_work_units).then_some(StrictProductionReplayTermination::WorkLimit)
}

#[cfg(test)]
mod tests;
