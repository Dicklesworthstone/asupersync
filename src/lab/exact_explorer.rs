//! Bounded exploration by replaying exact scheduler prefixes.
//!
//! Each run receives a fresh workload, validates every witnessed enabled set,
//! and forces one admitted alternative before continuing deterministically.
//! Unlike seed diversification, this changes the selected dispatch directly.
//!
//! The admitted model is one virtual worker without chaos. Choices preserve
//! the scheduler's lane, priority, deadline, and cancellation-streak policy.
//! Lazy queue entries and tie groups exceeding the scheduler's selection
//! window are reported as unsupported, never silently normalized. Time pumps
//! must lead directly to a dispatch or terminal quiescence so complete receipts
//! remain representable by the existing forced-schedule replay format.
//!
//! This enumerates schedules, including equivalent schedules. It does not
//! implement source-set DPOR or certify a Mazurkiewicz quotient. Search
//! exhaustion applies only to the admitted deterministic workload and model.
//! Factories, polls, and callbacks must return; work bounds cannot preempt
//! arbitrary Rust code. External concurrency is outside this model.

use super::config::LabConfig;
use super::runtime::{ForcedDispatch, ForcedSchedule, ForcedScheduleError, LabRunReport, LabRuntime};
use std::collections::VecDeque;

mod checkpoint;
pub use checkpoint::{
    ExactScheduleCheckpoint, ExactScheduleCheckpointError, ExactScheduleCheckpointLimits,
    ExactScheduleProgress,
};
pub use super::schedule_minimizer::reproducer::WorkloadKey as ExactScheduleWorkloadKey;

/// Explicit resource bounds for exact-prefix exploration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExactScheduleLimits {
    /// Maximum executions, including the initial execution.
    pub max_runs: usize,
    /// Maximum lab steps plus virtual-time pumping operations per execution.
    pub max_work_per_run: u64,
    /// Maximum dispatched task polls per execution.
    pub max_dispatches_per_run: usize,
    /// Maximum alternative prefixes retained in the exploration queue.
    pub max_pending_prefixes: usize,
    /// Maximum scheduler entries inspected at a decision.
    pub max_inventory_entries: usize,
}

impl ExactScheduleLimits {
    /// Creates caller-owned execution, queue, and inventory limits.
    #[must_use]
    pub const fn new(
        max_runs: usize,
        max_work_per_run: u64,
        max_dispatches_per_run: usize,
        max_pending_prefixes: usize,
        max_inventory_entries: usize,
    ) -> Self {
        Self {
            max_runs,
            max_work_per_run,
            max_dispatches_per_run,
            max_pending_prefixes,
            max_inventory_entries,
        }
    }
}

/// A complete eligible tie group and the choice made from it.
///
/// Task identities include arena generations. Worker, lane, lab step, and
/// virtual time are retained in each dispatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExactScheduleDecision {
    pub(crate) enabled: Vec<ForcedDispatch>,
    pub(crate) selected: usize,
}

impl ExactScheduleDecision {
    /// Returns all choices admitted by the scheduling policy at this point.
    #[must_use]
    pub fn enabled(&self) -> &[ForcedDispatch] {
        &self.enabled
    }

    /// Returns the witnessed or requested choice.
    #[must_use]
    pub fn selected(&self) -> &ForcedDispatch {
        &self.enabled[self.selected]
    }
}

/// A replay prefix containing the complete witnessed enabled sets.
///
/// Prefixes come from an execution, its admitted alternatives, or an explicitly
/// unverified loaded [`ExactScheduleCheckpoint`]. Resumption validates the full
/// enabled sets against the fresh runtime before each poll; loading bytes alone
/// does not verify the historical execution. Complete portable execution
/// receipts use [`ForcedSchedule`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExactSchedulePrefix {
    pub(crate) seed: u64,
    pub(crate) config_hash: u64,
    pub(crate) decisions: Vec<ExactScheduleDecision>,
}

impl ExactSchedulePrefix {
    /// Returns the decisions whose full enabled sets must be reproduced.
    #[must_use]
    pub fn decisions(&self) -> &[ExactScheduleDecision] {
        &self.decisions
    }
}

/// Why one exact-prefix execution ended.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExactScheduleTermination {
    /// All live work retired and the requested prefix was consumed.
    Quiescent,
    /// The work bound or the lab configuration's step bound was reached.
    WorkLimit,
    /// Another dispatch was available beyond the caller's dispatch bound.
    DispatchLimit,
    /// Live work remained without a runnable task or virtual deadline.
    Stalled,
    /// Execution encountered a scheduler state outside the admitted model.
    Unsupported {
        /// Stable description of the unsupported condition.
        reason: &'static str,
    },
    /// The next full enabled set differed, or execution ended too early.
    PrefixDiverged {
        /// Zero-based index of the first unconsumed decision.
        decision: usize,
    },
    /// Exact-dispatch admission or execution failed.
    ReplayRejected(ForcedScheduleError),
}

/// One fresh execution and its independently replayable complete receipt.
#[derive(Debug, Clone)]
pub struct ExactScheduleRun {
    /// Prefix requested by this execution.
    pub requested_prefix: ExactSchedulePrefix,
    /// Decisions actually witnessed before termination.
    pub execution: ExactSchedulePrefix,
    /// Completion, exhaustion, or the first unsupported/divergent condition.
    pub termination: ExactScheduleTermination,
    /// Lab steps plus virtual-time pumping operations used.
    pub work_units: u64,
    /// Complete receipt, present only after structured quiescence.
    pub schedule: Option<ForcedSchedule>,
    /// Runtime invariant and oracle observations, including incomplete runs.
    pub lab: LabRunReport,
}

impl ExactScheduleRun {
    /// Requests a different admitted choice at one witnessed decision.
    ///
    /// Returns `None` for an invalid index or the already selected choice.
    /// Earlier decisions are retained exactly; later ones are discarded.
    #[must_use]
    pub fn alternative_prefix(
        &self,
        decision: usize,
        alternative: usize,
    ) -> Option<ExactSchedulePrefix> {
        let witnessed = self.execution.decisions.get(decision)?;
        if alternative >= witnessed.enabled.len() || alternative == witnessed.selected {
            return None;
        }
        let mut decisions = self.execution.decisions[..=decision].to_vec();
        decisions[decision].selected = alternative;
        Some(ExactSchedulePrefix {
            seed: self.execution.seed,
            config_hash: self.execution.config_hash,
            decisions,
        })
    }
}

/// Why the bounded schedule search ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExactScheduleSearchTermination {
    /// Every queued alternative completed in the admitted deterministic model.
    ///
    /// This is schedule-tree exhaustion, not a DPOR optimality or general
    /// program-correctness claim.
    SearchExhausted,
    /// Executions remain queued after the run bound was reached.
    RunLimit,
    /// At least one witnessed alternative could not be queued.
    PrefixQueueLimit,
    /// At least one run failed to reach supported, replayable quiescence.
    IncompleteRun,
    /// A campaign's caller requested a stop after the last reported run.
    ///
    /// The checkpoint retains every queued alternative, including alternatives
    /// discovered by that run. This says nothing about search exhaustion.
    Stopped,
}

/// Executions produced by one resumable campaign invocation.
///
/// Completed run reports are returned to the caller rather than accumulated in
/// the checkpoint. Thus another invocation does not retain old traces or
/// receipts. Progress counters and unfinished prefixes survive independently.
#[derive(Debug, Clone)]
pub struct ExactScheduleBatch {
    /// Why this invocation stopped, including sticky coverage limitations.
    pub termination: ExactScheduleSearchTermination,
    /// Fresh executions attempted by this invocation, in breadth-first order.
    pub runs: Vec<ExactScheduleRun>,
    /// Cumulative campaign progress after this invocation.
    pub progress: ExactScheduleProgress,
}

/// A campaign checkpoint incompatible with the requested execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExactScheduleResumeError {
    /// The explorer configuration is outside the admitted model.
    Configuration(ExactScheduleConfigError),
    /// The caller supplied a different workload identity.
    WorkloadMismatch,
    /// The seed or execution configuration changed.
    ExecutionMismatch,
    /// The retained queue exceeds this invocation's queue bound.
    FrontierLimit,
    /// A retained prefix exceeds this invocation's dispatch bound.
    PrefixLimit,
    /// A retained enabled set exceeds this invocation's inventory bound.
    InventoryLimit,
    /// Historical counters cannot represent this invocation's bounded work.
    CounterOverflow,
}

/// Bounded exploration results with unfinished work made explicit.
#[derive(Debug, Clone)]
pub struct ExactScheduleExplorationReport {
    /// Search completion or the reason coverage is incomplete.
    pub termination: ExactScheduleSearchTermination,
    /// Every execution attempted, in deterministic queue order.
    pub runs: Vec<ExactScheduleRun>,
    /// Alternative prefixes not yet executed.
    pub pending_prefixes: Vec<ExactSchedulePrefix>,
    /// Alternatives omitted because the pending-prefix bound was full.
    pub omitted_prefixes: usize,
}

impl ExactScheduleExplorationReport {
    /// Returns the number of completed schedules, without quotient reduction.
    #[must_use]
    pub fn completed_schedules(&self) -> usize {
        self.runs
            .iter()
            .filter(|run| run.termination == ExactScheduleTermination::Quiescent)
            .count()
    }
}

/// A configuration rejected before invoking the workload factory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExactScheduleConfigError {
    /// Every caller-owned limit must be nonzero.
    ZeroLimit,
    /// This exploration model admits exactly one virtual worker.
    MultipleWorkers,
    /// Fault choices require a separate model and are not enumerated here.
    ChaosEnabled,
}

/// Explores exact scheduling alternatives on fresh deterministic workloads.
///
/// The factory must install the same initial workload on every invocation,
/// without driving the runtime. State mutated by tasks must be fresh per run.
/// This runner automatically advances to lab timer/reactor deadlines when
/// idle, and enables task-level causality without changing the default lab
/// constructor. Ordinary seeded exploration remains available separately.
///
/// All results remain useful when a bound is reached: incomplete runs carry
/// their observed prefix and invariant report, but never a complete receipt.
#[derive(Debug, Clone)]
pub struct ExactScheduleExplorer {
    config: LabConfig,
    limits: ExactScheduleLimits,
}

impl ExactScheduleExplorer {
    /// Creates an explorer with a fixed deterministic configuration.
    #[must_use]
    pub const fn new(config: LabConfig, limits: ExactScheduleLimits) -> Self {
        Self { config, limits }
    }

    fn validate(&self) -> Result<(), ExactScheduleConfigError> {
        if self.limits.max_runs == 0
            || self.limits.max_work_per_run == 0
            || self.limits.max_dispatches_per_run == 0
            || self.limits.max_pending_prefixes == 0
            || self.limits.max_inventory_entries == 0
        {
            return Err(ExactScheduleConfigError::ZeroLimit);
        }
        if self.config.worker_count.max(1) != 1 {
            return Err(ExactScheduleConfigError::MultipleWorkers);
        }
        if self.config.has_chaos() {
            return Err(ExactScheduleConfigError::ChaosEnabled);
        }
        Ok(())
    }

    /// Starts an empty, portable exploration campaign without invoking a workload.
    ///
    /// The workload key identifies the caller's code, fixture inputs and schema.
    /// It cannot prove equivalence of arbitrary closures: callers must change it
    /// when those inputs change. Every resumed prefix also rechecks the complete
    /// enabled sets against a freshly constructed runtime before each poll.
    ///
    /// # Errors
    /// Rejects invalid resource limits, multiple workers or enabled chaos.
    pub fn new_checkpoint(
        &self,
        workload: ExactScheduleWorkloadKey,
    ) -> Result<ExactScheduleCheckpoint, ExactScheduleConfigError> {
        self.validate()?;
        let runtime = LabRuntime::new_with_task_causality(self.config.clone());
        let initial = runtime.exact_schedule_empty_prefix();
        Ok(ExactScheduleCheckpoint {
            workload,
            seed: initial.seed,
            config_hash: initial.config_hash,
            pending: VecDeque::from([initial]),
            progress: ExactScheduleProgress::default(),
        })
    }

    /// Continues a campaign for at most this explorer's `max_runs` fresh runs.
    ///
    /// The execution configuration and workload must match; exploration limits
    /// may change. A smaller queue, dispatch or inventory limit must still admit
    /// every saved prefix. Run reports belong to this batch only, while the
    /// checkpoint retains the cumulative counts and exact remaining queue.
    ///
    /// An omitted branch or incomplete run permanently prevents this campaign
    /// from claiming search exhaustion. Raising later limits cannot restore work
    /// already omitted; start a new campaign to explore that work.
    ///
    /// # Errors
    /// Rejects incompatibility before invoking the factory or changing the
    /// checkpoint. Enabled-set divergence during execution is an incomplete run.
    pub fn resume<F>(
        &self,
        checkpoint: &mut ExactScheduleCheckpoint,
        workload: ExactScheduleWorkloadKey,
        factory: F,
    ) -> Result<ExactScheduleBatch, ExactScheduleResumeError>
    where
        F: Fn(&mut LabRuntime),
    {
        self.resume_until(checkpoint, workload, factory, |_| false)
    }

    /// Continues until the first run fails the lab test contract or the budget ends.
    ///
    /// A failing oracle, invariant violation or non-quiescent run stops the
    /// batch. Its complete report is retained as the last run, and its queued
    /// alternatives remain resumable. Use [`Self::resume_until`] for an
    /// application-specific failure predicate.
    ///
    /// # Errors
    /// Uses the same pre-execution admission as [`Self::resume`].
    pub fn resume_until_failure<F>(
        &self,
        checkpoint: &mut ExactScheduleCheckpoint,
        workload: ExactScheduleWorkloadKey,
        factory: F,
    ) -> Result<ExactScheduleBatch, ExactScheduleResumeError>
    where
        F: Fn(&mut LabRuntime),
    {
        self.resume_until(checkpoint, workload, factory, |run| !run.lab.lab_test_passed())
    }

    /// Continues until a caller predicate requests a stop after an execution.
    ///
    /// Alternatives from the stopping run are queued before returning, so
    /// stopping and resuming does not change deterministic breadth-first order.
    /// The predicate and fresh-workload factory must return; budgets cannot
    /// preempt arbitrary Rust code. A factory or execution panic leaves the
    /// current prefix queued. The predicate runs after progress and alternatives
    /// are committed, so its panic preserves a coherent completed execution.
    /// Stored counters are historical claims, not independently verified evidence
    /// that earlier executions occurred.
    ///
    /// # Errors
    /// Rejects invalid configuration, identity mismatch, an over-budget saved
    /// frontier or insufficient counter headroom before calling either callback
    /// or mutating the checkpoint.
    pub fn resume_until<F, P>(
        &self,
        checkpoint: &mut ExactScheduleCheckpoint,
        workload: ExactScheduleWorkloadKey,
        factory: F,
        mut should_stop: P,
    ) -> Result<ExactScheduleBatch, ExactScheduleResumeError>
    where
        F: Fn(&mut LabRuntime),
        P: FnMut(&ExactScheduleRun) -> bool,
    {
        self.validate().map_err(ExactScheduleResumeError::Configuration)?;
        if checkpoint.workload != workload {
            return Err(ExactScheduleResumeError::WorkloadMismatch);
        }
        let first = LabRuntime::new_with_task_causality(self.config.clone());
        let identity = first.exact_schedule_empty_prefix();
        if checkpoint.seed != identity.seed || checkpoint.config_hash != identity.config_hash {
            return Err(ExactScheduleResumeError::ExecutionMismatch);
        }
        if checkpoint.pending.len() > self.limits.max_pending_prefixes {
            return Err(ExactScheduleResumeError::FrontierLimit);
        }
        for prefix in &checkpoint.pending {
            if prefix.seed != identity.seed || prefix.config_hash != identity.config_hash {
                return Err(ExactScheduleResumeError::ExecutionMismatch);
            }
            if prefix.decisions.len() > self.limits.max_dispatches_per_run {
                return Err(ExactScheduleResumeError::PrefixLimit);
            }
            if prefix.decisions.iter().any(|decision| {
                decision.enabled.len() > self.limits.max_inventory_entries
            }) {
                return Err(ExactScheduleResumeError::InventoryLimit);
            }
        }
        // Reserve counter headroom for the whole batch before any callback.
        // Each decision can omit at most (inventory - 1) alternatives. This
        // conservative admission keeps even hostile decoded historical counts
        // exact, without saturating into a false exhaustion claim.
        if !checkpoint.pending.is_empty() {
            let count = |value| {
                u64::try_from(value).map_err(|_| ExactScheduleResumeError::CounterOverflow)
            };
            let runs = count(self.limits.max_runs)?;
            let omitted = runs
                .checked_mul(count(self.limits.max_dispatches_per_run)?)
                .and_then(|n| {
                    n.checked_mul(count(self.limits.max_inventory_entries - 1).ok()?)
                })
                .ok_or(ExactScheduleResumeError::CounterOverflow)?;
            if checkpoint.progress.runs.checked_add(runs).is_none()
                || checkpoint.progress.omitted.checked_add(omitted).is_none()
            {
                return Err(ExactScheduleResumeError::CounterOverflow);
            }
        }

        let mut first_runtime = Some(first);
        let mut runs = Vec::new();
        let mut stopped = false;
        while runs.len() < self.limits.max_runs {
            let Some(prefix) = checkpoint.pending.front().cloned() else {
                break;
            };
            let mut runtime = first_runtime.take().unwrap_or_else(|| {
                LabRuntime::new_with_task_causality(self.config.clone())
            });
            factory(&mut runtime);
            let run = runtime.run_exact_schedule_prefix(&prefix, self.limits);
            checkpoint.pending.pop_front();
            checkpoint.progress.runs += 1;
            if run.termination == ExactScheduleTermination::Quiescent {
                checkpoint.progress.completed += 1;
            } else {
                checkpoint.progress.incomplete += 1;
            }
            if !run.lab.lab_test_passed() {
                checkpoint.progress.failed += 1;
            }
            for decision in prefix.decisions.len()..run.execution.decisions.len() {
                let witnessed = &run.execution.decisions[decision];
                for alternative in 0..witnessed.enabled.len() {
                    if alternative == witnessed.selected {
                        continue;
                    }
                    if checkpoint.pending.len() == self.limits.max_pending_prefixes {
                        checkpoint.progress.omitted += 1;
                    } else if let Some(branch) = run.alternative_prefix(decision, alternative) {
                        checkpoint.pending.push_back(branch);
                    }
                }
            }
            stopped = should_stop(&run);
            runs.push(run);
            if stopped {
                break;
            }
        }

        let termination = if stopped {
            ExactScheduleSearchTermination::Stopped
        } else if checkpoint.progress.incomplete != 0 {
            ExactScheduleSearchTermination::IncompleteRun
        } else if checkpoint.progress.omitted != 0 {
            ExactScheduleSearchTermination::PrefixQueueLimit
        } else if checkpoint.pending.is_empty() {
            ExactScheduleSearchTermination::SearchExhausted
        } else {
            ExactScheduleSearchTermination::RunLimit
        };
        Ok(ExactScheduleBatch {
            termination,
            runs,
            progress: checkpoint.progress,
        })
    }

    /// Replays one prefix and deterministically completes its remaining choices.
    ///
    /// Enabled-set divergence stops before polling the mismatched task.
    ///
    /// # Errors
    ///
    /// Rejects zero resource limits, multiple workers, or enabled chaos before
    /// invoking the factory. Execution failures are recorded in the run.
    pub fn replay<F>(
        &self,
        prefix: &ExactSchedulePrefix,
        factory: F,
    ) -> Result<ExactScheduleRun, ExactScheduleConfigError>
    where
        F: FnOnce(&mut LabRuntime),
    {
        self.validate()?;
        let mut runtime = LabRuntime::new_with_task_causality(self.config.clone());
        factory(&mut runtime);
        Ok(runtime.run_exact_schedule_prefix(prefix, self.limits))
    }

    /// Executes witnessed alternatives in deterministic breadth-first order.
    ///
    /// At each new decision, every other enabled choice becomes an exact
    /// prefix. Decisions already imposed by a prefix are not branched again:
    /// their alternatives were generated by an ancestor. No race estimate,
    /// fingerprint, or sleep-set heuristic is used to discard a schedule.
    ///
    /// # Errors
    ///
    /// Rejects zero resource limits, multiple workers, or enabled chaos before
    /// invoking the factory. Incomplete execution remains in the report.
    pub fn explore<F>(
        &self,
        factory: F,
    ) -> Result<ExactScheduleExplorationReport, ExactScheduleConfigError>
    where
        F: Fn(&mut LabRuntime),
    {
        self.validate()?;
        let mut first = LabRuntime::new_with_task_causality(self.config.clone());
        let initial = first.exact_schedule_empty_prefix();
        factory(&mut first);
        let mut pending = VecDeque::from([initial]);
        let mut first_runtime = Some(first);
        let mut runs = Vec::new();
        let mut omitted_prefixes = 0usize;
        let mut incomplete = false;

        while runs.len() < self.limits.max_runs {
            let Some(prefix) = pending.pop_front() else {
                break;
            };
            let mut runtime = first_runtime.take().unwrap_or_else(|| {
                let mut runtime = LabRuntime::new_with_task_causality(self.config.clone());
                factory(&mut runtime);
                runtime
            });
            let run = runtime.run_exact_schedule_prefix(&prefix, self.limits);
            incomplete |= run.termination != ExactScheduleTermination::Quiescent;
            for decision in prefix.decisions.len()..run.execution.decisions.len() {
                let witnessed = &run.execution.decisions[decision];
                for alternative in 0..witnessed.enabled.len() {
                    if alternative == witnessed.selected {
                        continue;
                    }
                    if pending.len() == self.limits.max_pending_prefixes {
                        omitted_prefixes = omitted_prefixes.saturating_add(1);
                        continue;
                    }
                    if let Some(branch) = run.alternative_prefix(decision, alternative) {
                        pending.push_back(branch);
                    }
                }
            }
            runs.push(run);
        }

        let termination = if incomplete {
            ExactScheduleSearchTermination::IncompleteRun
        } else if omitted_prefixes != 0 {
            ExactScheduleSearchTermination::PrefixQueueLimit
        } else if !pending.is_empty() {
            ExactScheduleSearchTermination::RunLimit
        } else {
            ExactScheduleSearchTermination::SearchExhausted
        };
        Ok(ExactScheduleExplorationReport {
            termination,
            runs,
            pending_prefixes: pending.into_iter().collect(),
            omitted_prefixes,
        })
    }
}

#[cfg(test)]
#[path = "exact_explorer_inline_tests.rs"]
mod tests;
