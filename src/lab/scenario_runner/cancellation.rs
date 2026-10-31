//! Bounded cancellation campaigns over real scenario dispatches.
//!
//! A campaign records one successful baseline, selects one-based scheduler
//! poll opportunities with the scenario's cancellation strategy, then creates
//! a fresh workload for each selected point. The complete baseline prefix is
//! checked before a new cooperative request is published. These boundaries
//! are scheduler dispatches, not an enumeration of source-level await sites.

use super::{ScenarioRunResult, ScenarioRunner, ScenarioRunnerError};
use crate::lab::instrumented_future::InjectionStrategy;
use crate::lab::runtime::poll_cancellation::{PollCancellationControl, PollCancellationResult};
use crate::lab::runtime::{ForcedDispatch, ForcedSchedule, ForcedScheduleError, LabRuntime};
use crate::lab::scenario::{CancellationSection, CancellationStrategy, Scenario};
use std::sync::Arc;

/// Resource bounds for a scenario cancellation campaign.
///
/// The baseline is additional to the injection-trial limit. Every run uses
/// the smaller of the scenario's step limit and this per-run step limit.
/// Reports retain a single bounded baseline schedule and compact run reports;
/// full replay-event vectors are dropped before a run is retained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScenarioCancellationLimits {
    /// Maximum fresh injection trials after the baseline.
    pub max_runs: usize,
    /// Maximum baseline scheduler dispatches retained for target selection.
    pub max_poll_points: usize,
    /// Maximum cumulative lab steps in each baseline or injection run.
    pub max_steps_per_run: u64,
    /// Stop after the first failed or inconclusive injection trial.
    pub stop_on_failure: bool,
}

impl Default for ScenarioCancellationLimits {
    fn default() -> Self {
        Self {
            max_runs: 64,
            max_poll_points: 4096,
            max_steps_per_run: 100_000,
            stop_on_failure: true,
        }
    }
}

/// Admission or setup error before a campaign can return an execution report.
#[derive(Debug, thiserror::Error)]
pub enum ScenarioCancellationError {
    /// The scenario or one of its requested oracles is invalid.
    #[error(transparent)]
    Scenario(#[from] ScenarioRunnerError),
    /// No strategy was specified.
    #[error("cancellation campaign requires a scenario cancellation section")]
    MissingConfiguration,
    /// A resource bound was zero.
    #[error("cancellation campaign limit {limit_name} must be nonzero")]
    ZeroLimit {
        /// Stable name of the invalid bound.
        limit_name: &'static str,
    },
    /// Chaos can skip dispatches, so those recordings are not poll boundaries.
    #[error("cancellation campaign requires chaos to be disabled")]
    ChaosEnabled,
    /// The baseline recorder could not be installed or finished.
    #[error(transparent)]
    Capture(#[from] ForcedScheduleError),
    /// A selection index cannot be represented or is outside the baseline.
    #[error("cancellation campaign selected an invalid poll index")]
    InvalidPollIndex,
}

/// Why a cancellation campaign stopped.
///
/// Completion means every selected target was attempted. It is only a passing
/// campaign when the baseline and every actual injection trial also passed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ScenarioCancellationTermination {
    /// Every selected baseline boundary was attempted.
    Completed,
    /// The ordinary baseline failed, so it cannot justify injection targets.
    BaselineFailed,
    /// No task dispatch was observed.
    NoPollPoints,
    /// The strategy selected no points, including the recording-only strategy.
    NoInjectionSelected,
    /// The baseline exceeded its bounded dispatch capture.
    CaptureLimit,
    /// More selected points remain beyond the injection-trial limit.
    RunLimit,
    /// The configured fail-fast policy stopped after a nonpassing trial.
    StoppedOnFailure,
}

impl ScenarioCancellationTermination {
    /// Stable machine-readable termination name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::BaselineFailed => "baseline_failed",
            Self::NoPollPoints => "no_poll_points",
            Self::NoInjectionSelected => "no_injection_selected",
            Self::CaptureLimit => "capture_limit",
            Self::RunLimit => "run_limit",
            Self::StoppedOnFailure => "stopped_on_failure",
        }
    }
}

/// Evidence about one attempted cancellation request.
///
/// A requested transition is not a count of inner-future polls. The selected
/// dispatch is returned to the cancellation lane, and later scheduler turns
/// must drive the task through its cooperative cleanup to terminal state.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ScenarioCancellationInjection {
    /// A new request was published after the entire baseline prefix matched.
    Requested,
    /// Scheduling differed before the target; no campaign request was made.
    PrefixDiverged {
        /// One-based first mismatching dispatch.
        poll_index: u64,
        /// Dispatch recorded by the baseline.
        expected: ForcedDispatch,
        /// Dispatch actually selected by the fresh trial.
        actual: ForcedDispatch,
    },
    /// The trial ended before reaching its selected boundary.
    TargetNotReached {
        /// Number of matching dispatches observed before the run ended.
        observed_polls: u64,
    },
    /// The target already had a request or no new request could be published.
    NotApplied,
}

impl From<PollCancellationResult> for ScenarioCancellationInjection {
    fn from(result: PollCancellationResult) -> Self {
        match result {
            PollCancellationResult::Requested => Self::Requested,
            PollCancellationResult::PrefixDiverged {
                poll_index,
                expected,
                actual,
            } => Self::PrefixDiverged {
                poll_index,
                expected,
                actual,
            },
            PollCancellationResult::TargetNotReached { observed_polls } => {
                Self::TargetNotReached { observed_polls }
            }
            PollCancellationResult::NotApplied => Self::NotApplied,
        }
    }
}

/// One fresh execution targeting one baseline scheduler boundary.
#[derive(Debug, Clone)]
pub struct ScenarioCancellationTrial {
    /// One-based index into the baseline's dispatch projection.
    pub poll_index: u64,
    /// Full task generation, worker, lane, step, and time of the target.
    pub target: ForcedDispatch,
    /// Whether the checked request was actually published.
    pub injection: ScenarioCancellationInjection,
    /// Whether the exact target task reached a terminal runtime state.
    pub target_terminal: bool,
    /// Ordinary scenario report, with its replay-event vector discarded.
    pub run: ScenarioRunResult,
}

impl ScenarioCancellationTrial {
    /// Requires a real request, terminal target, and all ordinary run checks.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.injection == ScenarioCancellationInjection::Requested
            && self.target_terminal
            && self.run.passed()
    }

    fn to_json(&self) -> serde_json::Value {
        let injection = match &self.injection {
            ScenarioCancellationInjection::Requested => {
                serde_json::json!({ "status": "requested" })
            }
            ScenarioCancellationInjection::PrefixDiverged {
                poll_index,
                expected,
                actual,
            } => serde_json::json!({
                "status": "prefix_diverged",
                "poll_index": poll_index,
                "expected": dispatch_json(expected),
                "actual": dispatch_json(actual),
            }),
            ScenarioCancellationInjection::TargetNotReached { observed_polls } => {
                serde_json::json!({
                    "status": "target_not_reached",
                    "observed_polls": observed_polls,
                })
            }
            ScenarioCancellationInjection::NotApplied => {
                serde_json::json!({ "status": "not_applied" })
            }
        };
        serde_json::json!({
            "poll_index": self.poll_index,
            "target": dispatch_json(&self.target),
            "injection": injection,
            "target_terminal": self.target_terminal,
            "passed": self.passed(),
            "run": self.run.to_json(),
        })
    }
}

/// Baseline and bounded fresh cancellation executions.
///
/// An empty workload, a strategy selecting no points, capture truncation, or
/// unattempted targets cannot pass. The retained schedule is the only complete
/// event-like vector in this report; full run replay traces are not retained.
#[derive(Debug, Clone)]
pub struct ScenarioCancellationReport {
    /// Ordinary baseline report, without a retained replay-event vector.
    pub baseline: ScenarioRunResult,
    /// Complete bounded baseline projection, absent if capture was truncated.
    pub baseline_schedule: Option<ForcedSchedule>,
    /// Selected one-based baseline dispatch indices in deterministic order.
    pub selected_polls: Vec<u64>,
    /// At most the configured number of injection trials.
    pub trials: Vec<ScenarioCancellationTrial>,
    /// Why execution stopped.
    pub termination: ScenarioCancellationTermination,
}

impl ScenarioCancellationReport {
    /// Requires nonempty, complete coverage of the selected boundaries.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.termination == ScenarioCancellationTermination::Completed
            && self.baseline.passed()
            && !self.trials.is_empty()
            && self.remaining_trials() == 0
            && self.trials.iter().all(ScenarioCancellationTrial::passed)
    }

    /// Number of selected targets not attempted within this report.
    #[must_use]
    pub fn remaining_trials(&self) -> usize {
        self.selected_polls.len().saturating_sub(self.trials.len())
    }

    /// Stable JSON summary suitable for CLI output and stored evidence.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "schema": "asupersync.scenario-cancellation.v1",
            "boundary": "scheduler_poll_opportunity",
            "replay_traces_retained": false,
            "passed": self.passed(),
            "termination": self.termination.as_str(),
            "baseline": self.baseline.to_json(),
            "baseline_poll_count": self.baseline_schedule.as_ref().map(|s| s.dispatches().len()),
            "selected_polls": self.selected_polls,
            "attempted_trials": self.trials.len(),
            "remaining_trials": self.remaining_trials(),
            "trials": self.trials.iter().map(ScenarioCancellationTrial::to_json).collect::<Vec<_>>(),
        })
    }
}

fn dispatch_json(dispatch: &ForcedDispatch) -> serde_json::Value {
    let (slot, generation) = dispatch.task().unpack();
    serde_json::json!({
        "task": { "slot": slot, "generation": generation },
        "worker": dispatch.worker(),
        "lane": format!("{:?}", dispatch.lane()),
        "at_step": dispatch.at_step(),
        "at_nanos": dispatch.at_nanos(),
    })
}

fn select_strategy(
    section: &CancellationSection,
) -> Result<InjectionStrategy, ScenarioCancellationError> {
    // Scenario validation has already checked parameter presence and range.
    let count = section.count.unwrap_or(0);
    Ok(match section.strategy {
        CancellationStrategy::Never => InjectionStrategy::Never,
        CancellationStrategy::AllPoints => InjectionStrategy::AllPoints,
        CancellationStrategy::RandomSample => InjectionStrategy::RandomSample(count),
        CancellationStrategy::FirstN => InjectionStrategy::FirstN(count),
        CancellationStrategy::LastN => InjectionStrategy::LastN(count),
        CancellationStrategy::EveryNth => InjectionStrategy::EveryNth(
            u64::try_from(count).map_err(|_| ScenarioCancellationError::InvalidPollIndex)?,
        ),
        CancellationStrategy::Probabilistic => {
            InjectionStrategy::Probabilistic(section.probability.unwrap_or(0.0))
        }
    })
}

impl ScenarioRunner {
    /// Execute the scenario's cancellation strategy over bounded real tasks.
    ///
    /// First runs the ordinary workload to completion and records its scheduler
    /// dispatches. Each selected point gets a fresh runtime with the same seed
    /// and bounded configuration. Every dispatch up to the selected point must
    /// match the baseline before a new cancellation request is published.
    /// Cancellation uses the normal reason's cleanup budget and cancellation
    /// lane. The target and its peers must then satisfy the existing scenario
    /// quiescence, oracle, and workload checks.
    ///
    /// The indices refer to scheduler poll opportunities, not every source
    /// await expression. Chaos is rejected because it can skip selected polls.
    /// Timed scenario faults still run through the ordinary scenario driver.
    /// The baseline is an additional run beyond `limits.max_runs`.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid scenarios, absent cancellation strategy,
    /// zero resource limits, enabled chaos, or recorder setup failure.
    /// Ordinary run failures and bounded incomplete coverage are returned as
    /// nonpassing reports, including empty and recording-only campaigns.
    ///
    /// # Panics
    ///
    /// Honors the scenario's fatal obligation-leak and futurelock settings,
    /// like ordinary runs. Those configured panics are not converted to reports.
    /// Cancellation-protocol violations, including a request left unfinished
    /// by the step budget, are reported in the run's invariant violations
    /// instead of panicking.
    pub fn run_cancellation_campaign(
        scenario: &Scenario,
        seed_override: Option<u64>,
        limits: ScenarioCancellationLimits,
    ) -> Result<ScenarioCancellationReport, ScenarioCancellationError> {
        for (limit_name, zero) in [
            ("max_runs", limits.max_runs == 0),
            ("max_poll_points", limits.max_poll_points == 0),
            ("max_steps_per_run", limits.max_steps_per_run == 0),
        ] {
            if zero {
                return Err(ScenarioCancellationError::ZeroLimit { limit_name });
            }
        }
        let errors = scenario.validate();
        if !errors.is_empty() {
            return Err(Self::validation_error(scenario, errors).into());
        }
        Self::validate_oracle_names(scenario)?;
        let plan = Self::workload_plan(scenario)?;
        let section = scenario
            .cancellation
            .as_ref()
            .ok_or(ScenarioCancellationError::MissingConfiguration)?;
        let strategy = select_strategy(section)?;
        let mut config = Self::lab_config_for(scenario, seed_override);
        if config.has_chaos() {
            return Err(ScenarioCancellationError::ChaosEnabled);
        }
        config.max_steps = Some(
            config
                .max_steps
                .unwrap_or(limits.max_steps_per_run)
                .min(limits.max_steps_per_run),
        );
        // An unfinished cancellation is a nonpassing trial ("unfinished cleanup
        // cannot pass", f69e4cdc1), not a reason to abort the campaign. Keep
        // the cancellation oracle enabled, in warning mode, so its verdict lands
        // in invariant_violations instead of panicking from LabRuntime::report.
        config.panic_on_cancellation_violation = false;

        let mut runtime = LabRuntime::new(config.clone());
        runtime.start_forced_schedule_recording(limits.max_poll_points)?;
        let (mut baseline, _) = Self::run_prepared(scenario, seed_override, &plan, &mut runtime);
        baseline.replay_trace = None;
        let schedule = match runtime.finish_forced_schedule_recording() {
            Ok(schedule) => schedule,
            Err(ForcedScheduleError::RecordingLimitExceeded { .. }) => {
                return Ok(ScenarioCancellationReport {
                    baseline,
                    baseline_schedule: None,
                    selected_polls: Vec::new(),
                    trials: Vec::new(),
                    termination: ScenarioCancellationTermination::CaptureLimit,
                });
            }
            Err(error) => return Err(error.into()),
        };
        // Do not retain the baseline runtime (or its task/trace storage) while
        // creating any of the fresh injection runtimes.
        drop(runtime);
        let mut report = ScenarioCancellationReport {
            baseline,
            baseline_schedule: Some(schedule),
            selected_polls: Vec::new(),
            trials: Vec::new(),
            termination: ScenarioCancellationTermination::BaselineFailed,
        };
        if !report.baseline.passed() {
            return Ok(report);
        }
        let schedule = report
            .baseline_schedule
            .as_ref()
            .ok_or(ScenarioCancellationError::InvalidPollIndex)?;
        if schedule.dispatches().is_empty() {
            report.termination = ScenarioCancellationTermination::NoPollPoints;
            return Ok(report);
        }
        let poll_count = u64::try_from(schedule.dispatches().len())
            .map_err(|_| ScenarioCancellationError::InvalidPollIndex)?;
        let points: Vec<u64> = (1..=poll_count).collect();
        report.selected_polls = strategy.select_points(&points, config.seed);
        if report.selected_polls.is_empty() {
            report.termination = ScenarioCancellationTermination::NoInjectionSelected;
            return Ok(report);
        }
        let source: Arc<[ForcedDispatch]> = schedule.dispatches().to_vec().into();
        report.termination = ScenarioCancellationTermination::Completed;

        for &poll_index in report.selected_polls.iter().take(limits.max_runs) {
            let target_index = poll_index
                .checked_sub(1)
                .and_then(|index| usize::try_from(index).ok())
                .ok_or(ScenarioCancellationError::InvalidPollIndex)?;
            let target = *source
                .get(target_index)
                .ok_or(ScenarioCancellationError::InvalidPollIndex)?;
            let control = PollCancellationControl::new(Arc::clone(&source), target_index)
                .ok_or(ScenarioCancellationError::InvalidPollIndex)?;
            let mut runtime = LabRuntime::new(config.clone());
            runtime.set_poll_cancellation(control);
            let (mut run, _) = Self::run_prepared(scenario, seed_override, &plan, &mut runtime);
            run.replay_trace = None;
            let (injection, target_terminal) = runtime.finish_poll_cancellation().map_or(
                (ScenarioCancellationInjection::NotApplied, false),
                |(result, terminal)| (result.into(), terminal),
            );
            let trial = ScenarioCancellationTrial {
                poll_index,
                target,
                injection,
                target_terminal,
                run,
            };
            let failed = !trial.passed();
            report.trials.push(trial);
            if failed && limits.stop_on_failure {
                report.termination = ScenarioCancellationTermination::StoppedOnFailure;
                return Ok(report);
            }
        }
        if report.remaining_trials() != 0 {
            report.termination = ScenarioCancellationTermination::RunLimit;
        }
        Ok(report)
    }
}

#[cfg(test)]
mod tests;
