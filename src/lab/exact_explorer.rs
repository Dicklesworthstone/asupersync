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

/// An in-memory replay prefix derived from a witnessed execution.
///
/// Prefixes can only be obtained from an execution or its admitted
/// alternatives. Complete portable receipts use [`ForcedSchedule`] instead.
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
