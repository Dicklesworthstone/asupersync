//! Race-guided exploration that forces witnessed scheduler alternatives.
//!
//! This joins the task-causal race detector to the exact-prefix execution
//! engine. A candidate retains the complete enabled sets before a conflicting
//! dispatch and selects the later task only if it was eligible there. Every
//! subsequent run validates that prefix against a fresh workload.
//!
//! Guidance is deliberately incomplete: uninstrumented effects, races without
//! an attributable task dispatch, and tasks not enabled at the earlier choice
//! cannot generate a candidate. Selecting a task earlier does not guarantee
//! that it reaches the same later effect; it can have intervening polls or take
//! a different path. No sleep-set, trace hash, or equivalence-class estimate is
//! used to discard an execution. An empty guidance queue is neither exhaustive
//! schedule coverage nor an optimal-DPOR certificate. Use
//! [`super::exact_explorer::ExactScheduleExplorer`] to enumerate the admitted
//! schedule tree without race-guided pruning.
//!
//! # Instrumentation boundary
//!
//! Guidance uses the existing detector's typed resource footprints and task
//! attribution. A plain `Cx::trace` message has no resource footprint. Channel
//! or lock clock propagation alone does not describe the application's shared
//! state accesses. Timer, I/O, monitor and link events currently lack the task
//! attribution required by that detector. A cancellation event naming another
//! task also cannot stand in for an effect performed by the current dispatch.
//!
//! Checked obligations supply real built-in effects: reserve and settlement
//! mutate both the obligation and the owning region's shared quota. This
//! example explores the order of two callers using the same region quota;
//! their task clocks and obligation trace events are recorded by the runtime:
//!
//! ```
//! use asupersync::{
//!     Cx,
//!     lab::{ExactDporExplorer, ExactDporLimits, ExactScheduleLimits, LabConfig},
//!     record::ObligationKind,
//!     types::Budget,
//! };
//!
//! let limits = ExactDporLimits::new(
//!     ExactScheduleLimits::new(16, 128, 32, 64, 128),
//!     512, 131_072, 512, 2048,
//! );
//! let report = ExactDporExplorer::new(LabConfig::new(2), limits)
//!     .explore(|lab| {
//!         let region = lab.state.create_root_region(Budget::INFINITE);
//!         let record = lab.state.region(region).unwrap();
//!         let mut quota = record.limits();
//!         quota.max_obligations = Some(1);
//!         record.set_limits(quota);
//!         for _ in 0..2 {
//!             let (task, _join) = lab.state.create_task(region, Budget::INFINITE, async {
//!                 let cx = Cx::current().unwrap();
//!                 let credit = cx.try_register_obligation_checked(
//!                     ObligationKind::Lease, cx.task_id(),
//!                 ).unwrap().unwrap();
//!                 assert!(credit.commit());
//!             }).unwrap();
//!             lab.scheduler.lock().schedule(task, 0);
//!         }
//!     }).unwrap();
//! assert_eq!(report.runs.len(), 2);
//! assert!(report.runs.iter().all(|run| run.execution.schedule.is_some()));
//! ```
//!
//! Custom test models can publish their actual typed effects through
//! `Cx::trace_buffer().record_event` and stamp them with `Cx::logical_tick`.
//! Such instrumentation describes the model; it does not detect arbitrary Rust
//! memory accesses. Incomplete causal instrumentation can overapproximate
//! conflicts, so a reported conflict is guidance rather than proof of a bug.
//!
//! Supply the same instrumented workload to every factory invocation. Inspect
//! each run's analysis result and the report's unavailable/unmappable counts;
//! even an empty guidance queue makes no claim about uninstrumented effects.

use super::config::LabConfig;
use super::exact_explorer::{
    ExactScheduleConfigError, ExactScheduleLimits, ExactSchedulePrefix, ExactScheduleRun,
    ExactScheduleTermination,
};
use super::runtime::LabRuntime;
use crate::trace::distributed::{LogicalTime, vclock::NodeId};
use crate::trace::dpor::RaceDetector;
use crate::trace::event::{TraceData, TraceEvent, TraceEventKind};
use crate::types::TaskId;
use std::collections::VecDeque;
use std::ops::Range;

/// Execution, analysis and retained-frontier bounds for exact DPOR guidance.
///
/// The lab configuration still controls trace-ring capacity. A lost event is a
/// refused analysis, never permission to analyze only the retained tail.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct ExactDporLimits {
    /// Existing run, work, dispatch, prefix-count and scheduler-inventory bounds.
    pub execution: ExactScheduleLimits,
    /// Maximum complete trace events admitted to happens-before analysis.
    pub max_trace_events: usize,
    /// Maximum event pairs admitted before constructing the race detector.
    pub max_event_pairs: usize,
    /// Sum of decision counts in all queued prefixes.
    pub max_pending_decisions: usize,
    /// Sum of enabled-dispatch counts in all queued decision witnesses.
    pub max_pending_choices: usize,
}

impl ExactDporLimits {
    /// Creates explicit limits. All limits must be nonzero.
    #[must_use]
    pub const fn new(
        execution: ExactScheduleLimits,
        max_trace_events: usize,
        max_event_pairs: usize,
        max_pending_decisions: usize,
        max_pending_choices: usize,
    ) -> Self {
        Self {
            execution,
            max_trace_events,
            max_event_pairs,
            max_pending_decisions,
            max_pending_choices,
        }
    }
}

/// Configuration refused before any workload is constructed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExactDporConfigError {
    /// The underlying exact execution model cannot admit this configuration.
    Execution(ExactScheduleConfigError),
    /// An analysis or aggregate-frontier bound was zero.
    ZeroLimit,
    /// The admitted report or prefix-size counters would overflow.
    CounterOverflow,
}

/// The conflict that suggested one exact dispatch alternative.
///
/// These are source-run observations. The new run guarantees only the exact
/// requested dispatch prefix, not that either resource event will recur.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ExactDporBacktrack {
    /// Index in the report of the run that supplied these observations.
    pub source_run: usize,
    /// Sequence of the earlier conflict endpoint in the complete source trace.
    pub earlier_event_sequence: u64,
    /// Sequence of the later conflict endpoint in the complete source trace.
    pub later_event_sequence: u64,
    /// Dispatch containing the earlier endpoint and changed by the candidate.
    pub earlier_decision: usize,
    /// Source dispatch containing the later endpoint.
    pub later_decision: usize,
    /// Task actually dispatched at the earlier decision.
    pub earlier_task: TaskId,
    /// Task selected instead by the candidate.
    pub later_task: TaskId,
    /// Polls of the later task between the source conflict's two dispatches.
    /// A nonzero count makes especially clear that moving its next poll does
    /// not directly move the later resource event.
    pub intervening_later_task_polls: usize,
}

/// Why a run's trace was or was not used to generate guidance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExactDporAnalysis {
    /// A complete bounded task-causal capture was analyzed.
    Analyzed,
    /// The exact execution did not reach supported structured quiescence.
    IncompleteExecution,
    /// The factory replaced the supplied runtime, clock policy or trace buffer.
    CaptureReplaced,
    /// The trace ring evicted events, including events lost during setup.
    TraceTruncated {
        /// Lifetime insertion count.
        recorded: u64,
        /// Events still retained by the ring.
        retained: usize,
    },
    /// The complete trace exceeds the caller's analysis bound.
    TraceLimit,
    /// The trace's event-pair count exceeds the caller's analysis bound.
    PairLimit,
    /// Sequence order or causal poll/dispatch attribution was inconsistent.
    InvalidDispatchTrace,
}

/// Counts for guidance actually considered by this invocation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ExactDporStatistics {
    /// Happens-before-unordered conflicts reported by the existing detector.
    pub races: usize,
    /// Conflicts that did not map to two distinct matching task dispatches.
    pub unmappable: usize,
    /// Conflicts whose later task was not eligible at the earlier decision.
    pub unavailable: usize,
    /// Pure scheduler-lifecycle pairs excluded from effect guidance.
    pub scheduler_only: usize,
    /// Alternative prefixes admitted to the queue.
    pub queued: usize,
    /// Alternatives already queued or already executed as exact prefixes.
    pub duplicates: usize,
    /// Alternatives refused by a prefix-count or aggregate-frontier bound.
    pub omitted: usize,
}

/// A fresh execution, its source conflict if any, and its guidance disposition.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ExactDporRun {
    /// Independently inspectable exact execution and complete replay receipt.
    pub execution: ExactScheduleRun,
    /// Source witness for the requested alternative; absent on the initial run.
    pub backtrack: Option<ExactDporBacktrack>,
    /// Capture and analysis admission result.
    pub analysis: ExactDporAnalysis,
}

/// Why the race-guided invocation stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExactDporTermination {
    /// No admitted, unexecuted direct race-guided alternative remains.
    /// This never asserts exhaustive or optimal-DPOR coverage.
    GuidanceQueueEmpty,
    /// The execution bound was reached with alternatives still queued.
    RunLimit,
    /// A witnessed alternative could not fit in the bounded frontier.
    FrontierLimit,
    /// An execution or capture/analysis refusal made guidance incomplete.
    Incomplete,
    /// The caller's predicate requested a stop after the last reported run.
    Stopped,
}

/// Bounded guided executions and any unfinished exact prefixes.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ExactDporReport {
    /// Why this invocation ended.
    pub termination: ExactDporTermination,
    /// Runs in deterministic breadth-first guidance order.
    pub runs: Vec<ExactDporRun>,
    /// Remaining prefixes, usable with `ExactScheduleExplorer::replay`.
    pub pending_prefixes: Vec<ExactSchedulePrefix>,
    /// Guidance counts, including unsupported and omitted conflicts.
    pub statistics: ExactDporStatistics,
}

/// Executes real dispatch alternatives suggested by task-causal conflicts.
///
/// The factory must install the same workload, with fresh mutable state, on
/// every call and must not drive or replace the supplied runtime. Single-worker
/// exact execution, task causality, cancellation-lane policy and enabled-set
/// checks are shared with `ExactScheduleExplorer`. Arbitrary polls, callbacks
/// and destructors must return; resource bounds cannot preempt Rust code.
#[derive(Debug, Clone)]
pub struct ExactDporExplorer {
    config: LabConfig,
    limits: ExactDporLimits,
}

struct Candidate {
    prefix: ExactSchedulePrefix,
    backtrack: Option<ExactDporBacktrack>,
}

#[derive(Default)]
struct FrontierSize {
    decisions: usize,
    choices: usize,
}

impl ExactDporExplorer {
    /// Creates an explorer without executing a workload.
    #[must_use]
    pub const fn new(config: LabConfig, limits: ExactDporLimits) -> Self {
        Self { config, limits }
    }

    fn validate(&self) -> Result<(), ExactDporConfigError> {
        let execution = self.limits.execution;
        if execution.max_runs == 0
            || execution.max_work_per_run == 0
            || execution.max_dispatches_per_run == 0
            || execution.max_pending_prefixes == 0
            || execution.max_inventory_entries == 0
        {
            return Err(ExactDporConfigError::Execution(
                ExactScheduleConfigError::ZeroLimit,
            ));
        }
        if self.config.worker_count.max(1) != 1 {
            return Err(ExactDporConfigError::Execution(
                ExactScheduleConfigError::MultipleWorkers,
            ));
        }
        if self.config.has_chaos() {
            return Err(ExactDporConfigError::Execution(
                ExactScheduleConfigError::ChaosEnabled,
            ));
        }
        if self.limits.max_trace_events == 0
            || self.limits.max_event_pairs == 0
            || self.limits.max_pending_decisions == 0
            || self.limits.max_pending_choices == 0
        {
            return Err(ExactDporConfigError::ZeroLimit);
        }
        if execution
            .max_runs
            .checked_mul(self.limits.max_event_pairs)
            .is_none()
            || execution
                .max_dispatches_per_run
                .checked_mul(execution.max_inventory_entries)
                .is_none()
        {
            return Err(ExactDporConfigError::CounterOverflow);
        }
        Ok(())
    }

    /// Explores until the guidance queue or a caller-owned bound is reached.
    ///
    /// # Errors
    /// Rejects invalid limits or an unsupported model before calling `factory`.
    pub fn explore<F>(&self, factory: F) -> Result<ExactDporReport, ExactDporConfigError>
    where
        F: Fn(&mut LabRuntime),
    {
        self.explore_until(factory, |_| false)
    }

    /// Stops after the first oracle/invariant failure or incomplete execution.
    ///
    /// # Errors
    /// Uses the same pre-execution admission as [`Self::explore`].
    pub fn explore_until_failure<F>(
        &self,
        factory: F,
    ) -> Result<ExactDporReport, ExactDporConfigError>
    where
        F: Fn(&mut LabRuntime),
    {
        self.explore_until(factory, |run| {
            !run.execution.lab.lab_test_passed()
                || run.execution.termination != ExactScheduleTermination::Quiescent
        })
    }

    /// Stops when `should_stop` accepts an observed run, retaining its report.
    ///
    /// Alternatives from that run are queued before the predicate is called.
    /// Complete schedules retain the existing `ForcedSchedule` replay format.
    /// Incomplete or untrustworthy captures never generate more guidance.
    ///
    /// # Errors
    /// Uses the same pre-execution admission as [`Self::explore`].
    pub fn explore_until<F, P>(
        &self,
        factory: F,
        mut should_stop: P,
    ) -> Result<ExactDporReport, ExactDporConfigError>
    where
        F: Fn(&mut LabRuntime),
        P: FnMut(&ExactDporRun) -> bool,
    {
        self.validate()?;
        let initial = LabRuntime::new_with_task_causality(self.config.clone());
        let mut pending = VecDeque::from([Candidate {
            prefix: initial.exact_schedule_empty_prefix(),
            backtrack: None,
        }]);
        let mut first = Some(initial);
        let mut frontier = FrontierSize::default();
        let mut statistics = ExactDporStatistics::default();
        let mut runs = Vec::new();
        let mut incomplete = false;
        let mut stopped = false;

        while runs.len() < self.limits.execution.max_runs {
            let Some(candidate) = pending.pop_front() else {
                break;
            };
            frontier.decisions -= candidate.prefix.decisions.len();
            frontier.choices -= prefix_choices(&candidate.prefix);
            let mut runtime = first
                .take()
                .unwrap_or_else(|| LabRuntime::new_with_task_causality(self.config.clone()));
            let causality = runtime.state.task_causality_runtime();
            let trace = runtime.trace().clone();
            factory(&mut runtime);
            let replaced = causality.is_none()
                || runtime.state.task_causality_runtime() != causality
                || !runtime.trace().shares_storage_with(&trace);
            let (execution, ranges) = if replaced {
                let execution = ExactScheduleRun {
                    requested_prefix: candidate.prefix,
                    execution: runtime.exact_schedule_empty_prefix(),
                    termination: ExactScheduleTermination::Unsupported {
                        reason: "workload replaced the runtime, task-causality policy or trace buffer",
                    },
                    work_units: 0,
                    schedule: None,
                    lab: runtime.report(),
                };
                (execution, Vec::new())
            } else {
                runtime.run_exact_schedule_prefix_with_trace(
                    &candidate.prefix,
                    self.limits.execution,
                    true,
                )
            };
            let replaced = replaced
                || runtime.state.task_causality_runtime() != causality
                || !runtime.trace().shares_storage_with(&trace);
            let analysis = if replaced {
                ExactDporAnalysis::CaptureReplaced
            } else if execution.termination != ExactScheduleTermination::Quiescent {
                ExactDporAnalysis::IncompleteExecution
            } else {
                self.guide(
                    &runtime,
                    &execution,
                    &ranges,
                    &runs,
                    &mut pending,
                    &mut frontier,
                    &mut statistics,
                )
            };
            incomplete |= analysis != ExactDporAnalysis::Analyzed;
            let run = ExactDporRun {
                execution,
                backtrack: candidate.backtrack,
                analysis,
            };
            stopped = should_stop(&run);
            runs.push(run);
            if stopped {
                break;
            }
        }

        let termination = if stopped {
            ExactDporTermination::Stopped
        } else if incomplete {
            ExactDporTermination::Incomplete
        } else if statistics.omitted != 0 {
            ExactDporTermination::FrontierLimit
        } else if pending.is_empty() {
            ExactDporTermination::GuidanceQueueEmpty
        } else {
            ExactDporTermination::RunLimit
        };
        Ok(ExactDporReport {
            termination,
            runs,
            pending_prefixes: pending
                .into_iter()
                .map(|candidate| candidate.prefix)
                .collect(),
            statistics,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn guide(
        &self,
        runtime: &LabRuntime,
        run: &ExactScheduleRun,
        ranges: &[Range<u64>],
        previous: &[ExactDporRun],
        pending: &mut VecDeque<Candidate>,
        frontier: &mut FrontierSize,
        statistics: &mut ExactDporStatistics,
    ) -> ExactDporAnalysis {
        let (events, recorded) = runtime.trace().snapshot_with_stats();
        if u64::try_from(events.len()) != Ok(recorded) {
            return ExactDporAnalysis::TraceTruncated {
                recorded,
                retained: events.len(),
            };
        }
        if events.len() > self.limits.max_trace_events {
            return ExactDporAnalysis::TraceLimit;
        }
        if event_pairs(events.len()).is_none_or(|pairs| pairs > self.limits.max_event_pairs) {
            return ExactDporAnalysis::PairLimit;
        }
        let Some(dispatches) = attribute_events(&events, ranges, run) else {
            return ExactDporAnalysis::InvalidDispatchTrace;
        };
        // This detector compares pairs, rather than the cubic immediate-race
        // search. Both its trace/clock input and possible pair output have been
        // admitted before construction. No partial trace is analyzed.
        let detector = RaceDetector::from_trace(&events);
        for race in detector.races() {
            statistics.races += 1;
            if scheduler_event(race.earlier_kind) && scheduler_event(race.later_kind) {
                statistics.scheduler_only += 1;
                continue;
            }
            let (Some(earlier), Some(later), Some(earlier_task), Some(later_task)) = (
                dispatches[race.race.earlier],
                dispatches[race.race.later],
                race.earlier_task,
                race.later_task,
            ) else {
                statistics.unmappable += 1;
                continue;
            };
            if earlier >= later
                || earlier_task == later_task
                || run.execution.decisions[earlier].selected().task() != earlier_task.into()
                || run.execution.decisions[later].selected().task() != later_task.into()
            {
                statistics.unmappable += 1;
                continue;
            }
            let Some(alternative) = run.execution.decisions[earlier]
                .enabled()
                .iter()
                .position(|dispatch| dispatch.task() == later_task.into())
            else {
                statistics.unavailable += 1;
                continue;
            };
            let Some(prefix) = run.alternative_prefix(earlier, alternative) else {
                statistics.unmappable += 1;
                continue;
            };
            if pending.iter().any(|candidate| candidate.prefix == prefix)
                || executed_prefix(&prefix, run)
                || previous
                    .iter()
                    .any(|prior| executed_prefix(&prefix, &prior.execution))
            {
                statistics.duplicates += 1;
                continue;
            }
            let decisions = prefix.decisions.len();
            let choices = prefix_choices(&prefix);
            if pending.len() >= self.limits.execution.max_pending_prefixes
                || decisions > self.limits.max_pending_decisions - frontier.decisions
                || choices > self.limits.max_pending_choices - frontier.choices
            {
                statistics.omitted += 1;
                continue;
            }
            frontier.decisions += decisions;
            frontier.choices += choices;
            let intervening_later_task_polls = run.execution.decisions[earlier + 1..later]
                .iter()
                .filter(|decision| decision.selected().task() == later_task.into())
                .count();
            pending.push_back(Candidate {
                prefix,
                backtrack: Some(ExactDporBacktrack {
                    source_run: previous.len(),
                    earlier_event_sequence: events[race.race.earlier].seq,
                    later_event_sequence: events[race.race.later].seq,
                    earlier_decision: earlier,
                    later_decision: later,
                    earlier_task,
                    later_task,
                    intervening_later_task_polls,
                }),
            });
            statistics.queued += 1;
        }
        ExactDporAnalysis::Analyzed
    }
}

fn event_pairs(count: usize) -> Option<usize> {
    if count.is_multiple_of(2) {
        (count / 2).checked_mul(count.saturating_sub(1))
    } else {
        count.checked_mul(count / 2)
    }
}

fn prefix_choices(prefix: &ExactSchedulePrefix) -> usize {
    prefix
        .decisions
        .iter()
        .map(|decision| decision.enabled.len())
        .sum()
}

fn executed_prefix(prefix: &ExactSchedulePrefix, run: &ExactScheduleRun) -> bool {
    prefix.seed == run.execution.seed
        && prefix.config_hash == run.execution.config_hash
        && run.execution.decisions.starts_with(&prefix.decisions)
}

fn scheduler_event(kind: TraceEventKind) -> bool {
    matches!(
        kind,
        TraceEventKind::Spawn
            | TraceEventKind::Schedule
            | TraceEventKind::Yield
            | TraceEventKind::Wake
            | TraceEventKind::Poll
            | TraceEventKind::Complete
            | TraceEventKind::TaskSpawnEnqueued
            | TraceEventKind::TaskAdmitted
    )
}

fn attribute_events(
    events: &[TraceEvent],
    ranges: &[Range<u64>],
    run: &ExactScheduleRun,
) -> Option<Vec<Option<usize>>> {
    if ranges.len() != run.execution.decisions.len()
        || events.windows(2).any(|pair| pair[0].seq >= pair[1].seq)
        || ranges.iter().any(|range| range.start > range.end)
        || ranges.windows(2).any(|pair| pair[0].end > pair[1].start)
    {
        return None;
    }
    let mut attribution = Vec::with_capacity(events.len());
    let mut polls = vec![0usize; ranges.len()];
    for event in events {
        let index = ranges.partition_point(|range| range.end <= event.seq);
        let dispatch = ranges
            .get(index)
            .filter(|range| range.contains(&event.seq))
            .map(|_| index);
        if event.kind == TraceEventKind::Poll {
            let index = dispatch?;
            let selected = run.execution.decisions[index].selected();
            let TraceData::Task { task, .. } = &event.data else {
                return None;
            };
            let Some(LogicalTime::Vector(clock)) = &event.logical_time else {
                return None;
            };
            if selected.task() != (*task).into()
                || selected.at_nanos() != event.time.as_nanos()
                || clock.get(&NodeId::new(format!("lab-task:{:016x}", task.as_u64()))) == 0
            {
                return None;
            }
            polls[index] += 1;
        }
        attribution.push(dispatch);
    }
    polls.iter().all(|count| *count == 1).then_some(attribution)
}

#[cfg(test)]
#[path = "exact_dpor_inline_tests.rs"]
mod tests;
