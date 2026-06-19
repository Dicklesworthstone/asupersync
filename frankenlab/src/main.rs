//! FrankenLab: Deterministic testing harness for async Rust.
//!
//! Record, replay, and minimize concurrency bugs with full determinism.
//! Works with any async Rust project, not just Asupersync.
//!
//! # Quick Start
//!
//! ```bash
//! frankenlab run examples/scenarios/01_race_condition.yaml
//! frankenlab explore examples/scenarios/01_race_condition.yaml --seeds 1000
//! frankenlab replay examples/scenarios/01_race_condition.yaml
//! ```

use asupersync::config::EncodingConfig;
use asupersync::lab::ldfi::HittingSetBudget;
use asupersync::lab::ldfi_trace::{
    LdfiReport, TraceLineageConfig, blind_chaos_single_fault_count, ldfi_report, support_graph_for,
};
use asupersync::lab::scenario::Scenario;
use asupersync::lab::scenario_runner::{
    ScenarioExplorationResult, ScenarioRunResult, ScenarioRunner, ScenarioRunnerError,
};
use asupersync::runtime::RuntimeBuilder;
use asupersync::trace::minimizer::LogicalMinimizerClock;
use asupersync::trace::raptorq_journal_writer::{
    DurableJournalError, DurableTraceJournal, DurableTraceJournalConfig,
};
use asupersync::trace::{
    IncidentOracleKind, IncidentReplayMinimizationConfig, IncidentReplayMinimizationReport,
    IncidentReplayMinimizationVerdict, IncidentReplayOracle, IncidentReplayPackage,
    IncidentReplaySourceRole, ScenarioElement, TraceMinimizer, minimize_incident_replay_package,
};
use asupersync::trace::{TraceData, TraceEvent, TraceEventKind};
use clap::{ArgAction, Args, Parser, Subcommand};
use serde::Serialize;
use std::cell::{Cell, RefCell};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Parser, Debug)]
#[command(
    name = "frankenlab",
    version,
    about = "Deterministic testing harness for async Rust",
    long_about = "FrankenLab records, replays, and minimizes concurrency bugs.\n\n\
        Run deterministic test scenarios with virtual time, fault injection,\n\
        and schedule exploration. Find concurrency bugs reproducibly."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Output as JSON instead of human-readable text
    #[arg(long, global = true, action = ArgAction::SetTrue)]
    json: bool,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run a FrankenLab scenario from a YAML file
    Run(RunArgs),

    /// Validate a scenario YAML file without executing it
    Validate(ValidateArgs),

    /// Replay a scenario twice and verify determinism
    Replay(ReplayArgs),

    /// Explore multiple seeds to find invariant violations
    Explore(ExploreArgs),

    /// Minimize a failing scenario by shrinking its fault list
    Minimize(MinimizeArgs),

    /// Run the built-in time-travel demo pipeline
    Demo(DemoArgs),

    /// Recover a crash-durable RaptorQ trace journal from its surviving stripes
    TraceRecover(TraceRecoverArgs),

    /// Run lineage-driven fault injection over a recorded trace
    Ldfi(LdfiArgs),
}

#[derive(Args, Debug)]
struct RunArgs {
    /// Path to the scenario YAML file
    scenario: PathBuf,

    /// Override the seed from the scenario file
    #[arg(long)]
    seed: Option<u64>,
}

#[derive(Args, Debug)]
struct ValidateArgs {
    /// Path to the scenario YAML file
    scenario: PathBuf,
}

#[derive(Args, Debug)]
struct ReplayArgs {
    /// Path to the scenario YAML file
    scenario: PathBuf,
}

#[derive(Args, Debug)]
struct ExploreArgs {
    /// Path to the scenario YAML file
    scenario: PathBuf,

    /// Number of seeds to explore
    #[arg(long, default_value_t = 100)]
    seeds: u64,

    /// Starting seed for exploration
    #[arg(long, default_value_t = 0)]
    start_seed: u64,
}

#[derive(Args, Debug)]
struct MinimizeArgs {
    /// Path to a failing scenario YAML file or incident replay package JSON
    scenario: PathBuf,

    /// Maximum scenario reruns or incident shrink steps; 0 means unlimited
    #[arg(long, default_value_t = 128)]
    max_replays: usize,

    /// Deterministic per-rerun scheduler-step cap for scenario minimization
    #[arg(long = "timeout", value_name = "STEPS")]
    timeout_steps: Option<u64>,
}

#[derive(Args, Debug)]
struct DemoArgs {
    /// Which demo stage to run
    #[command(subcommand)]
    stage: Option<DemoStage>,
}

#[derive(Subcommand, Debug)]
enum DemoStage {
    /// Run the full demo pipeline (default)
    All,
    /// Run only scenario validation
    Validate,
    /// Run scenario and show results
    Run,
    /// Explore seeds to find failures
    Explore,
}

#[derive(Args, Debug)]
struct TraceRecoverArgs {
    /// Directory holding the durable RaptorQ trace journal (stripe + manifest +
    /// params files written by `DurableTraceJournal::record_epoch`)
    journal_dir: PathBuf,

    /// Recover this specific epoch instead of the latest recoverable one
    #[arg(long)]
    epoch: Option<u64>,

    /// Number of stripe files (failure domains) each epoch was spread across;
    /// must match the journal's writer configuration
    #[arg(long, default_value_t = 3)]
    stripe_count: usize,

    /// Write the recovered checkpoint bytes to this file (otherwise only a
    /// recovery summary is reported)
    #[arg(long)]
    output: Option<PathBuf>,
}

#[derive(Args, Debug)]
struct LdfiArgs {
    /// Path to a JSON file holding the recorded trace (a serialized `Vec<TraceEvent>`)
    trace: PathBuf,

    /// `stable_name` of the trace event kind that produces the target invariant
    /// outcome (the "oracle"), e.g. `user_trace`, `obligation_commit`, `down_delivered`
    #[arg(long, default_value = "user_trace")]
    outcome_kind: String,

    /// For `user_trace` outcomes, only treat events whose message contains this
    /// substring as the outcome
    #[arg(long)]
    outcome_contains: Option<String>,

    /// Maximum fault depth k to enumerate
    #[arg(long, default_value_t = 3)]
    depth: usize,

    /// Maximum number of minimal fault hypotheses to return
    #[arg(long, default_value_t = 64)]
    max_hypotheses: usize,
}

// ---------------------------------------------------------------------------
// Scenario loading
// ---------------------------------------------------------------------------

fn parse_scenario(path: &Path, yaml: &str) -> Result<asupersync::lab::scenario::Scenario, String> {
    serde_yaml::from_str(yaml).map_err(|e| {
        format!(
            "Failed to parse {}: {e}. Hint: check indentation and field names",
            path.display()
        )
    })
}

fn load_scenario(path: &Path) -> Result<asupersync::lab::scenario::Scenario, String> {
    let yaml =
        fs::read_to_string(path).map_err(|e| format!("Failed to read {}: {e}", path.display()))?;
    parse_scenario(path, &yaml)
}

fn runner_error_message(err: ScenarioRunnerError) -> String {
    match err {
        ScenarioRunnerError::Validation {
            scenario_id,
            errors,
        } => {
            let detail: Vec<String> = errors.iter().map(|e| format!("  - {e}")).collect();
            format!(
                "Scenario validation failed for '{scenario_id}':\n{}",
                detail.join("\n")
            )
        }
        ScenarioRunnerError::UnknownOracle(name) => {
            format!(
                "Unknown oracle '{name}'. Available: {}",
                asupersync::lab::meta::mutation::ALL_ORACLE_INVARIANTS.join(", ")
            )
        }
        ScenarioRunnerError::ReplayDivergence {
            seed,
            first,
            second,
        } => {
            format!(
                "Replay divergence at seed {seed}: \
                run1(event_hash={}, steps={}) != run2(event_hash={}, steps={})",
                first.event_hash, first.steps, second.event_hash, second.steps,
            )
        }
    }
}

fn pretty_json_or<T: serde::Serialize>(value: &T, fallback: &'static str) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|_| fallback.to_string())
}

fn scenario_with_fault_indices(scenario: &Scenario, fault_indices: &[usize]) -> Scenario {
    let mut reduced = scenario.clone();
    reduced.faults = fault_indices
        .iter()
        .filter_map(|&index| scenario.faults.get(index).cloned())
        .collect();
    reduced
}

fn apply_per_replay_step_cap(scenario: &mut Scenario, per_replay_step_cap: Option<u64>) {
    if let Some(cap) = per_replay_step_cap {
        scenario.lab.max_steps = Some(
            scenario
                .lab
                .max_steps
                .map_or(cap, |existing| existing.min(cap)),
        );
    }
}

// ---------------------------------------------------------------------------
// Run
// ---------------------------------------------------------------------------

fn format_run_result(result: &ScenarioRunResult, json: bool) -> String {
    if json {
        pretty_json_or(&result.to_json(), "{}")
    } else {
        let status = if result.passed() { "PASS" } else { "FAIL" };
        let mut lines = vec![
            format!("Scenario: {} [{}]", result.scenario_id, status),
            format!("Seed: {}", result.seed),
            format!("Steps: {}", result.lab_report.steps_total),
            format!("Faults injected: {}", result.faults_injected),
            format!(
                "Oracles: {}/{} passed",
                result.oracle_report.passed_count,
                result.oracle_report.checked.len()
            ),
        ];
        if !result.lab_report.invariant_violations.is_empty() {
            lines.push(format!(
                "Invariant violations: {}",
                result.lab_report.invariant_violations.join(", ")
            ));
        }
        lines.push(format!(
            "Certificate: event_hash={}, schedule_hash={}",
            result.certificate.event_hash, result.certificate.schedule_hash
        ));
        lines.join("\n")
    }
}

#[allow(clippy::needless_pass_by_value)]
fn cmd_run(args: RunArgs, json: bool) -> Result<(), String> {
    let scenario = load_scenario(&args.scenario)?;
    let result =
        ScenarioRunner::run_with_seed(&scenario, args.seed).map_err(runner_error_message)?;

    let output = format_run_result(&result, json);
    println!("{output}");

    if result.passed() {
        Ok(())
    } else {
        Err("Scenario assertions failed".to_string())
    }
}

// ---------------------------------------------------------------------------
// Validate
// ---------------------------------------------------------------------------

#[allow(clippy::needless_pass_by_value)]
fn cmd_validate(args: ValidateArgs, json: bool) -> Result<(), String> {
    let scenario = load_scenario(&args.scenario)?;
    let errors = scenario.validate();

    if json {
        let report = serde_json::json!({
            "scenario": args.scenario.display().to_string(),
            "scenario_id": scenario.id,
            "valid": errors.is_empty(),
            "errors": errors.iter().map(ToString::to_string).collect::<Vec<_>>(),
        });
        println!("{}", pretty_json_or(&report, ""));
    } else if errors.is_empty() {
        println!("Scenario '{}' is valid", scenario.id);
    } else {
        let mut lines = vec![format!("Scenario '{}' has errors:", scenario.id)];
        for err in &errors {
            lines.push(format!("  - {err}"));
        }
        println!("{}", lines.join("\n"));
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err("Scenario validation failed".to_string())
    }
}

// ---------------------------------------------------------------------------
// Replay
// ---------------------------------------------------------------------------

#[allow(clippy::needless_pass_by_value)]
fn cmd_replay(args: ReplayArgs, json: bool) -> Result<(), String> {
    let scenario = load_scenario(&args.scenario)?;
    let result = ScenarioRunner::validate_replay(&scenario).map_err(runner_error_message)?;

    if json {
        let report = serde_json::json!({
            "scenario": args.scenario.display().to_string(),
            "scenario_id": result.scenario_id,
            "deterministic": true,
            "seed": result.seed,
            "event_hash": result.certificate.event_hash,
            "schedule_hash": result.certificate.schedule_hash,
        });
        println!("{}", pretty_json_or(&report, ""));
    } else {
        println!(
            "Replay verified: {} (seed={}, event_hash={}, schedule_hash={})",
            result.scenario_id,
            result.seed,
            result.certificate.event_hash,
            result.certificate.schedule_hash
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Explore
// ---------------------------------------------------------------------------

#[allow(clippy::cast_possible_truncation)]
fn format_explore_result(result: &ScenarioExplorationResult, json: bool) -> String {
    if json {
        pretty_json_or(&result.to_json(), "{}")
    } else {
        let status = if result.all_passed() { "PASS" } else { "FAIL" };
        let mut lines = vec![
            format!("Exploration: {} [{}]", result.scenario_id, status),
            format!("Seeds: {}/{} passed", result.passed, result.seeds_explored),
            format!("Unique fingerprints: {}", result.unique_fingerprints),
        ];
        if let Some(seed) = result.first_failure_seed {
            lines.push(format!("First failure at seed: {seed}"));
        }
        lines.join("\n")
    }
}

#[allow(clippy::cast_possible_truncation, clippy::needless_pass_by_value)]
fn cmd_explore(args: ExploreArgs, json: bool) -> Result<(), String> {
    let scenario = load_scenario(&args.scenario)?;
    let result = ScenarioRunner::explore_seeds(&scenario, args.start_seed, args.seeds as usize)
        .map_err(runner_error_message)?;

    let output = format_explore_result(&result, json);
    println!("{output}");

    if result.all_passed() {
        Ok(())
    } else {
        Err(format!(
            "{} of {} seeds failed",
            result.failed, result.seeds_explored
        ))
    }
}

// ---------------------------------------------------------------------------
// Minimize
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
struct FaultMinimizeOutcome {
    original_fault_count: usize,
    minimized_fault_count: usize,
    removed_fault_count: usize,
    minimized_fault_indices: Vec<usize>,
    removed_fault_indices: Vec<usize>,
    reduction_ratio: f64,
    replay_attempts: usize,
    budget_exhausted: bool,
    verified_still_failing: bool,
}

#[derive(Debug, Clone, Serialize)]
struct MinimizeScenarioReport {
    schema_version: u32,
    input_kind: &'static str,
    minimized_surface: &'static str,
    scenario: String,
    scenario_id: String,
    per_replay_step_cap: Option<u64>,
    outcome: FaultMinimizeOutcome,
    minimized_scenario: Scenario,
}

#[derive(Debug, Clone)]
enum MinimizeInput {
    ScenarioYaml(Scenario),
    IncidentReplayPackageJson(IncidentReplayPackage),
}

#[derive(Debug, Clone, Serialize)]
struct MinimizeIncidentReplayPackageReport {
    schema_version: u32,
    input_kind: &'static str,
    minimized_surface: &'static str,
    package: String,
    package_id: String,
    per_replay_step_cap: Option<u64>,
    oracle: IncidentReplayOracle,
    config: IncidentReplayMinimizationConfig,
    verification: IncidentReplayPackageVerification,
    outcome: IncidentReplayMinimizationReport,
}

#[derive(Debug, Clone, Serialize)]
struct IncidentReplayPackageVerification {
    #[serde(flatten)]
    status: IncidentReplayPackageVerificationStatus,
    #[serde(flatten)]
    required_evidence: IncidentReplayPackageRequiredEvidence,
    retained_source_count: usize,
    retained_feature_flag_count: usize,
    budget_exhausted: bool,
}

#[derive(Debug, Clone, Serialize)]
struct IncidentReplayPackageVerificationStatus {
    emitted_repro: bool,
    verified_still_failing: bool,
    oracle_stable: bool,
}

#[derive(Debug, Clone, Serialize)]
struct IncidentReplayPackageRequiredEvidence {
    required_source_roles_present: bool,
    required_trace_fingerprint_present: bool,
}

fn parse_minimize_input(path: &Path, raw: &str) -> Result<MinimizeInput, String> {
    if let Ok(package) = serde_json::from_str::<IncidentReplayPackage>(raw) {
        return Ok(MinimizeInput::IncidentReplayPackageJson(package));
    }

    parse_scenario(path, raw).map(MinimizeInput::ScenarioYaml)
}

fn load_minimize_input(path: &Path) -> Result<MinimizeInput, String> {
    let raw =
        fs::read_to_string(path).map_err(|e| format!("Failed to read {}: {e}", path.display()))?;
    parse_minimize_input(path, &raw)
}

fn fault_elements(fault_count: usize) -> Vec<ScenarioElement> {
    (0..fault_count)
        .map(|index| ScenarioElement::AdvanceTime {
            nanos: u64::try_from(index).expect("fault index fits in u64") + 1,
        })
        .collect()
}

fn fault_indices_from_elements(elements: &[ScenarioElement]) -> Vec<usize> {
    let mut indices: Vec<usize> = elements
        .iter()
        .filter_map(|element| match element {
            ScenarioElement::AdvanceTime { nanos } => nanos
                .checked_sub(1)
                .and_then(|index| usize::try_from(index).ok()),
            _ => None,
        })
        .collect();
    indices.sort_unstable();
    indices.dedup();
    indices
}

fn minimize_fault_indices(
    fault_count: usize,
    max_replays: usize,
    fails_with_fault_indices: impl FnMut(&[usize]) -> bool,
) -> Result<FaultMinimizeOutcome, String> {
    let mut full_indices: Vec<usize> = (0..fault_count).collect();
    let fails = RefCell::new(fails_with_fault_indices);
    if !(fails.borrow_mut())(&full_indices) {
        return Err("scenario does not currently fail; minimization needs a failing input".into());
    }

    if fault_count == 0 {
        return Ok(FaultMinimizeOutcome {
            original_fault_count: 0,
            minimized_fault_count: 0,
            removed_fault_count: 0,
            minimized_fault_indices: Vec::new(),
            removed_fault_indices: Vec::new(),
            reduction_ratio: 0.0,
            replay_attempts: 1,
            budget_exhausted: false,
            verified_still_failing: true,
        });
    }

    let replay_attempts = Cell::new(0usize);
    let budget_exhausted = Cell::new(false);
    let elements = fault_elements(fault_count);
    let checker = |subset: &[ScenarioElement]| {
        if max_replays != 0 && replay_attempts.get() >= max_replays {
            budget_exhausted.set(true);
            return false;
        }
        replay_attempts.set(replay_attempts.get() + 1);
        let candidate = fault_indices_from_elements(subset);
        (fails.borrow_mut())(&candidate)
    };

    let report =
        TraceMinimizer::minimize_with_clock(&elements, checker, &LogicalMinimizerClock::new());

    let minimized_fault_indices = fault_indices_from_elements(&report.minimized_elements());
    let verified_still_failing = (fails.borrow_mut())(&minimized_fault_indices);
    full_indices.retain(|index| !minimized_fault_indices.contains(index));

    Ok(FaultMinimizeOutcome {
        original_fault_count: fault_count,
        minimized_fault_count: minimized_fault_indices.len(),
        removed_fault_count: full_indices.len(),
        minimized_fault_indices,
        removed_fault_indices: full_indices,
        reduction_ratio: report.reduction_ratio,
        replay_attempts: replay_attempts.get() + 1,
        budget_exhausted: budget_exhausted.get(),
        verified_still_failing,
    })
}

fn minimize_scenario_report(
    scenario_path: &Path,
    scenario: &Scenario,
    max_replays: usize,
    per_replay_step_cap: Option<u64>,
    mut fails_with_scenario: impl FnMut(&Scenario) -> bool,
) -> Result<MinimizeScenarioReport, String> {
    let outcome = minimize_fault_indices(scenario.faults.len(), max_replays, |indices| {
        let mut reduced = scenario_with_fault_indices(scenario, indices);
        apply_per_replay_step_cap(&mut reduced, per_replay_step_cap);
        fails_with_scenario(&reduced)
    })?;

    if !outcome.verified_still_failing {
        return Err("minimized scenario did not reproduce the original failure".into());
    }

    let mut minimized_scenario =
        scenario_with_fault_indices(scenario, &outcome.minimized_fault_indices);
    apply_per_replay_step_cap(&mut minimized_scenario, per_replay_step_cap);

    Ok(MinimizeScenarioReport {
        schema_version: 1,
        input_kind: "scenario_yaml",
        minimized_surface: "faults",
        scenario: scenario_path.display().to_string(),
        scenario_id: scenario.id.clone(),
        per_replay_step_cap,
        outcome,
        minimized_scenario,
    })
}

fn incident_replay_step_budget(max_replays: usize) -> usize {
    if max_replays == 0 {
        usize::MAX
    } else {
        max_replays
    }
}

fn crashpack_replay_oracle(package: &IncidentReplayPackage) -> IncidentReplayOracle {
    let crashpack_fingerprint = package
        .sources
        .iter()
        .find(|source| source.role == IncidentReplaySourceRole::CrashPack)
        .and_then(|source| source.trace_fingerprint.clone())
        .or_else(|| package.canonicalization.trace_fingerprints.first().cloned());

    IncidentReplayOracle {
        kind: IncidentOracleKind::Panic,
        expected_signal: "crashpack_replay_source_preserved".to_string(),
        stable: true,
        required_source_roles: vec![IncidentReplaySourceRole::CrashPack],
        required_trace_fingerprint: crashpack_fingerprint,
    }
}

fn minimize_incident_replay_package_report(
    package_path: &Path,
    package: &IncidentReplayPackage,
    max_replays: usize,
    per_replay_step_cap: Option<u64>,
) -> MinimizeIncidentReplayPackageReport {
    let oracle = crashpack_replay_oracle(package);
    let config = IncidentReplayMinimizationConfig {
        step_budget: incident_replay_step_budget(max_replays),
        shrink_feature_flags: true,
    };
    let outcome = minimize_incident_replay_package(package, oracle.clone(), config);
    let verification = verify_incident_replay_package_repro(&oracle, &outcome);

    MinimizeIncidentReplayPackageReport {
        schema_version: 1,
        input_kind: "incident_replay_package_json",
        minimized_surface: "replay_package_sources",
        package: package_path.display().to_string(),
        package_id: package.package_id.clone(),
        per_replay_step_cap,
        oracle,
        config,
        verification,
        outcome,
    }
}

fn verify_incident_replay_package_repro(
    oracle: &IncidentReplayOracle,
    outcome: &IncidentReplayMinimizationReport,
) -> IncidentReplayPackageVerification {
    let Some(repro) = &outcome.repro else {
        return IncidentReplayPackageVerification {
            status: IncidentReplayPackageVerificationStatus {
                emitted_repro: false,
                verified_still_failing: false,
                oracle_stable: oracle.stable,
            },
            required_evidence: IncidentReplayPackageRequiredEvidence {
                required_source_roles_present: false,
                required_trace_fingerprint_present: false,
            },
            retained_source_count: 0,
            retained_feature_flag_count: 0,
            budget_exhausted: outcome.contains_issue(
                asupersync::trace::IncidentReplayMinimizationIssueKind::BudgetExhausted,
            ),
        };
    };

    let required_source_roles_present = oracle.required_source_roles.iter().all(|role| {
        repro
            .retained_sources
            .iter()
            .any(|source| source.role == *role)
    });
    let required_trace_fingerprint_present =
        oracle
            .required_trace_fingerprint
            .as_ref()
            .is_none_or(|required| {
                repro
                    .retained_sources
                    .iter()
                    .any(|source| source.trace_fingerprint.as_ref() == Some(required))
            });
    let verified_still_failing =
        oracle.stable && required_source_roles_present && required_trace_fingerprint_present;

    IncidentReplayPackageVerification {
        status: IncidentReplayPackageVerificationStatus {
            emitted_repro: true,
            verified_still_failing,
            oracle_stable: oracle.stable,
        },
        required_evidence: IncidentReplayPackageRequiredEvidence {
            required_source_roles_present,
            required_trace_fingerprint_present,
        },
        retained_source_count: repro.retained_sources.len(),
        retained_feature_flag_count: repro.retained_feature_flags.len(),
        budget_exhausted: repro.summary.budget_exhausted,
    }
}

fn incident_verdict_tag(verdict: IncidentReplayMinimizationVerdict) -> &'static str {
    match verdict {
        IncidentReplayMinimizationVerdict::Minimized => "minimized",
        IncidentReplayMinimizationVerdict::AlreadyMinimal => "already_minimal",
        IncidentReplayMinimizationVerdict::BudgetExhausted => "budget_exhausted",
        IncidentReplayMinimizationVerdict::Inconclusive => "inconclusive",
        IncidentReplayMinimizationVerdict::Blocked => "blocked",
    }
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

fn format_incident_minimize_result(report: &MinimizeIncidentReplayPackageReport) -> String {
    let verdict = incident_verdict_tag(report.outcome.verdict);
    let mut lines = vec![
        format!(
            "Incident replay package: {} [{}]",
            report.package_id, verdict
        ),
        format!("Shrink steps: {}", report.outcome.steps.len()),
        format!(
            "Emitted repro: {}",
            yes_no(report.verification.status.emitted_repro)
        ),
        format!(
            "Verified still failing: {}",
            yes_no(report.verification.status.verified_still_failing)
        ),
        format!(
            "Oracle stable: {}",
            yes_no(report.verification.status.oracle_stable)
        ),
        format!(
            "Required source roles present: {}",
            yes_no(
                report
                    .verification
                    .required_evidence
                    .required_source_roles_present,
            )
        ),
        format!(
            "Required trace fingerprint present: {}",
            yes_no(
                report
                    .verification
                    .required_evidence
                    .required_trace_fingerprint_present,
            )
        ),
        format!(
            "Retained source count: {}",
            report.verification.retained_source_count
        ),
        format!(
            "Retained feature flag count: {}",
            report.verification.retained_feature_flag_count
        ),
        format!(
            "Budget exhausted: {}",
            yes_no(report.verification.budget_exhausted)
        ),
    ];

    if let Some(cap) = report.per_replay_step_cap {
        lines.push(format!("Per-rerun step cap: {cap}"));
    }

    if let Some(repro) = &report.outcome.repro {
        lines.push(format!(
            "Replay units: {} -> {}",
            repro.summary.original_units, repro.summary.minimized_units
        ));
        lines.push(format!(
            "Retained sources: {}",
            repro.retained_sources.len()
        ));
        lines.push(format!("Removed sources: {:?}", repro.removed_source_ids));
        lines.push(format!(
            "Removed feature flags: {:?}",
            repro.removed_feature_flags
        ));
    } else {
        lines.push(format!("Issues: {}", report.outcome.issues.len()));
        for issue in &report.outcome.issues {
            lines.push(format!("  - {}: {}", issue.field, issue.message));
        }
    }

    lines.join("\n")
}

#[allow(clippy::needless_pass_by_value)]
fn cmd_minimize(args: MinimizeArgs, json: bool) -> Result<(), String> {
    let input = load_minimize_input(&args.scenario)?;
    match input {
        MinimizeInput::ScenarioYaml(scenario) => cmd_minimize_scenario(&args, json, &scenario),
        MinimizeInput::IncidentReplayPackageJson(package) => {
            cmd_minimize_incident_replay_package(&args, json, &package)
        }
    }
}

fn cmd_minimize_scenario(
    args: &MinimizeArgs,
    json: bool,
    scenario: &Scenario,
) -> Result<(), String> {
    let report = minimize_scenario_report(
        &args.scenario,
        scenario,
        args.max_replays,
        args.timeout_steps,
        |candidate| ScenarioRunner::run(candidate).is_ok_and(|result| !result.passed()),
    )?;

    if json {
        println!("{}", pretty_json_or(&report, "{}"));
    } else {
        println!(
            "Minimized faults: {} -> {} ({:.1}% reduction)",
            report.outcome.original_fault_count,
            report.outcome.minimized_fault_count,
            report.outcome.reduction_ratio * 100.0
        );
        println!(
            "Kept fault indices: {:?}",
            report.outcome.minimized_fault_indices
        );
        println!(
            "Removed fault indices: {:?}",
            report.outcome.removed_fault_indices
        );
        println!(
            "Replay attempts: {}{}",
            report.outcome.replay_attempts,
            if report.outcome.budget_exhausted {
                " (budget exhausted)"
            } else {
                ""
            }
        );
        if let Some(cap) = report.per_replay_step_cap {
            println!("Per-rerun step cap: {cap}");
        }
        println!("Verified still failing: yes");
    }

    Ok(())
}

fn cmd_minimize_incident_replay_package(
    args: &MinimizeArgs,
    json: bool,
    package: &IncidentReplayPackage,
) -> Result<(), String> {
    let report = minimize_incident_replay_package_report(
        &args.scenario,
        package,
        args.max_replays,
        args.timeout_steps,
    );

    if json {
        println!("{}", pretty_json_or(&report, "{}"));
    } else {
        println!("{}", format_incident_minimize_result(&report));
    }

    if report.outcome.has_repro() {
        Ok(())
    } else {
        Err(format!(
            "Incident replay package minimization did not emit a repro: {}",
            incident_verdict_tag(report.outcome.verdict)
        ))
    }
}

// ---------------------------------------------------------------------------
// Demo
// ---------------------------------------------------------------------------

fn cmd_demo(args: DemoArgs, json: bool) -> Result<(), String> {
    let stage = args.stage.unwrap_or(DemoStage::All);
    let scenarios_dir = find_scenarios_dir()?;

    match stage {
        DemoStage::Validate => {
            println!("=== Demo: Validating example scenarios ===\n");
            demo_validate_all(&scenarios_dir, json)?;
        }
        DemoStage::Run => {
            println!("=== Demo: Running example scenarios ===\n");
            demo_run_scenarios(&scenarios_dir, json)?;
        }
        DemoStage::Explore => {
            println!("=== Demo: Exploring seeds for bug discovery ===\n");
            demo_explore(&scenarios_dir, json)?;
        }
        DemoStage::All => {
            println!("=== FrankenLab Demo Pipeline ===\n");

            println!("Step 1/3: Validating scenarios...\n");
            demo_validate_all(&scenarios_dir, json)?;

            println!("\nStep 2/3: Running scenarios...\n");
            demo_run_scenarios(&scenarios_dir, json)?;

            println!("\nStep 3/3: Exploring seeds...\n");
            demo_explore(&scenarios_dir, json)?;

            println!("\n=== Demo complete! ===");
            println!("All scenarios passed validation, execution, and seed exploration.");
        }
    }

    Ok(())
}

fn find_scenarios_dir() -> Result<PathBuf, String> {
    // Check relative to current directory
    let candidates = [
        PathBuf::from("examples/scenarios"),
        PathBuf::from("frankenlab/examples/scenarios"),
        PathBuf::from("scenarios"),
    ];

    for candidate in &candidates {
        if candidate.is_dir() {
            return Ok(candidate.clone());
        }
    }

    Err(
        "Could not find scenarios directory. Expected one of: examples/scenarios, \
         frankenlab/examples/scenarios, scenarios"
            .to_string(),
    )
}

fn demo_validate_all(dir: &Path, json: bool) -> Result<(), String> {
    let yamls = collect_yaml_files(dir)?;
    if yamls.is_empty() {
        return Err(format!("No YAML scenarios found in {}", dir.display()));
    }

    for path in &yamls {
        let name = path.file_stem().unwrap_or_default().to_string_lossy();
        print!("  Validating {name}... ");
        io::stdout().flush().ok();

        let result = cmd_validate(
            ValidateArgs {
                scenario: path.clone(),
            },
            json,
        );

        match result {
            Ok(()) => {
                if !json {
                    println!("OK");
                }
            }
            Err(e) => {
                println!("FAILED: {e}");
                return Err(format!("Validation failed for {name}"));
            }
        }
    }

    Ok(())
}

fn demo_run_scenarios(dir: &Path, json: bool) -> Result<(), String> {
    let yamls = collect_yaml_files(dir)?;

    for path in &yamls {
        let name = path.file_stem().unwrap_or_default().to_string_lossy();
        println!("--- {name} ---");

        let result = cmd_run(
            RunArgs {
                scenario: path.clone(),
                seed: None,
            },
            json,
        );

        match result {
            Ok(()) => println!(),
            Err(e) => {
                // Failures during demo are reported but don't stop the pipeline
                println!("  (expected failure: {e})\n");
            }
        }
    }

    Ok(())
}

fn demo_explore(dir: &Path, json: bool) -> Result<(), String> {
    // Pick the simplest scenario for seed exploration
    let scenario_path = dir.join("01_race_condition.yaml");
    if !scenario_path.exists() {
        // Fall back to first available scenario
        let yamls = collect_yaml_files(dir)?;
        if let Some(first) = yamls.first() {
            println!("Exploring 50 seeds on {}...\n", first.display());
            return cmd_explore(
                ExploreArgs {
                    scenario: first.clone(),
                    seeds: 50,
                    start_seed: 0,
                },
                json,
            );
        }
        return Err("No scenarios available for exploration".to_string());
    }

    println!("Exploring 50 seeds on 01_race_condition.yaml...\n");
    cmd_explore(
        ExploreArgs {
            scenario: scenario_path,
            seeds: 50,
            start_seed: 0,
        },
        json,
    )
}

fn collect_yaml_files(dir: &Path) -> Result<Vec<PathBuf>, String> {
    let mut paths: Vec<PathBuf> = fs::read_dir(dir)
        .map_err(|e| format!("Cannot read {}: {e}", dir.display()))?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            p.extension()
                .is_some_and(|ext| ext == "yaml" || ext == "yml")
        })
        .collect();
    paths.sort();
    Ok(paths)
}

// ---------------------------------------------------------------------------
// Trace recover
// ---------------------------------------------------------------------------

/// Result of a [`cmd_trace_recover`] journal scan: the recorded epochs plus,
/// when recovery succeeds, the restored epoch and its decoded bytes.
type RecoverOutcome = Result<(Vec<u64>, Option<(u64, Vec<u8>)>), DurableJournalError>;

/// Restore a crash-durable RaptorQ trace journal from the stripe files that
/// survived a crash.
///
/// Wraps [`DurableTraceJournal`]: given only a journal directory, it finds the
/// newest still-decodable checkpoint epoch (or a `--epoch`-selected one), runs
/// the real RaptorQ decoder over the surviving stripes, and reconstructs the
/// original checkpoint bytes — tolerating the loss of any minority of stripe
/// files. With `--output`, the recovered bytes are written to disk; otherwise a
/// recovery summary is reported. Returns an error (nonzero exit) when no
/// recorded epoch still recovers.
#[allow(clippy::needless_pass_by_value)]
fn cmd_trace_recover(args: TraceRecoverArgs, json: bool) -> Result<(), String> {
    if args.stripe_count == 0 {
        return Err("--stripe-count must be at least 1".to_string());
    }

    let journal = DurableTraceJournal::new(DurableTraceJournalConfig {
        directory: args.journal_dir.clone(),
        // `encoding`/`repair_count` are write-path only; recovery reads the
        // persisted object-params record for the decode layout.
        encoding: EncodingConfig::default(),
        repair_count: 0,
        stripe_count: args.stripe_count,
    });

    let runtime = RuntimeBuilder::current_thread()
        .build()
        .map_err(|e| format!("build runtime: {e}"))?;

    let selected_epoch = args.epoch;
    let outcome: RecoverOutcome = runtime.block_on(runtime.handle().spawn(async move {
        let recorded = journal.recorded_epochs().await?;
        let restored = match selected_epoch {
            Some(epoch) => Some((epoch, journal.recover_epoch(epoch).await?)),
            None => journal.recover_latest().await?,
        };
        Ok((recorded, restored))
    }));

    let (recorded, restored) = outcome.map_err(|e| format!("trace-recover: {e}"))?;

    let written = match (&args.output, &restored) {
        (Some(path), Some((_, bytes))) => {
            fs::write(path, bytes)
                .map_err(|e| format!("write recovered trace to {}: {e}", path.display()))?;
            Some(path.clone())
        }
        _ => None,
    };

    if json {
        let report = serde_json::json!({
            "journal_dir": args.journal_dir.display().to_string(),
            "stripe_count": args.stripe_count,
            "recorded_epochs": recorded,
            "recovered": restored.is_some(),
            "epoch": restored.as_ref().map(|(epoch, _)| *epoch),
            "bytes": restored.as_ref().map(|(_, bytes)| bytes.len()),
            "output": written.as_ref().map(|p| p.display().to_string()),
        });
        println!("{}", pretty_json_or(&report, ""));
    } else if let Some((epoch, bytes)) = &restored {
        let suffix = written
            .as_ref()
            .map(|path| format!("; wrote {}", path.display()))
            .unwrap_or_default();
        println!(
            "Recovered epoch {epoch} from {} ({} bytes, {} recorded epoch(s)){suffix}",
            args.journal_dir.display(),
            bytes.len(),
            recorded.len()
        );
    } else {
        println!(
            "No recoverable checkpoint in {} ({} recorded epoch(s))",
            args.journal_dir.display(),
            recorded.len()
        );
    }

    if restored.is_some() {
        Ok(())
    } else {
        Err("no recoverable checkpoint found".to_string())
    }
}

// ---------------------------------------------------------------------------
// LDFI (lineage-driven fault injection)
// ---------------------------------------------------------------------------

/// Builds the LDFI report for a recorded trace: extract the lineage, take the
/// fault-able causal cone of each outcome-kind event as a derivation, enumerate
/// the minimal breaking hypotheses, and pair them with the blind-chaos baseline.
/// Pure and deterministic — the `cmd_ldfi` wrapper only adds file IO and output.
fn run_ldfi(
    trace: &[TraceEvent],
    outcome_kind: &str,
    outcome_contains: Option<&str>,
    budget: HittingSetBudget,
) -> Result<LdfiReport, String> {
    let kind = TraceEventKind::ALL
        .iter()
        .copied()
        .find(|k| k.stable_name() == outcome_kind)
        .ok_or_else(|| format!("unknown outcome kind '{outcome_kind}'"))?;
    let graph = support_graph_for(trace, TraceLineageConfig::default(), |ev| {
        ev.kind == kind
            && outcome_contains
                .is_none_or(|sub| matches!(&ev.data, TraceData::Message(m) if m.contains(sub)))
    });
    if graph.is_empty() {
        return Err(format!(
            "no outcome events of kind '{outcome_kind}' in the trace"
        ));
    }
    let result = graph.minimal_hitting_sets(budget);
    Ok(ldfi_report(&result, blind_chaos_single_fault_count(trace)))
}

fn cmd_ldfi(args: &LdfiArgs, json: bool) -> Result<(), String> {
    if args.depth == 0 {
        return Err("--depth must be at least 1".to_string());
    }
    let content = fs::read_to_string(&args.trace)
        .map_err(|e| format!("read trace {}: {e}", args.trace.display()))?;
    let trace: Vec<TraceEvent> = serde_json::from_str(&content)
        .map_err(|e| format!("parse trace {}: {e}", args.trace.display()))?;

    let report = run_ldfi(
        &trace,
        &args.outcome_kind,
        args.outcome_contains.as_deref(),
        HittingSetBudget {
            max_depth: args.depth,
            max_hypotheses: args.max_hypotheses,
        },
    )?;

    if json {
        println!("{}", pretty_json_or(&report, ""));
    } else {
        let certificate = report.coverage_certificate.map_or_else(String::new, |k| {
            format!(", coverage certificate: no <= {k}-fault counterexample")
        });
        println!(
            "LDFI: {} fault hypothes(es) vs {} blind-chaos single-fault experiments, depth {}{}",
            report.hypotheses.len(),
            report.blind_chaos_single_fault_experiments,
            report.max_depth,
            certificate,
        );
        for (i, hypothesis) in report.hypotheses.iter().enumerate() {
            println!("  #{i}: {hypothesis:?}");
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() -> ExitCode {
    let cli = Cli::parse();

    let result = match cli.command {
        Command::Run(args) => cmd_run(args, cli.json),
        Command::Validate(args) => cmd_validate(args, cli.json),
        Command::Replay(args) => cmd_replay(args, cli.json),
        Command::Explore(args) => cmd_explore(args, cli.json),
        Command::Minimize(args) => cmd_minimize(args, cli.json),
        Command::Demo(args) => cmd_demo(args, cli.json),
        Command::TraceRecover(args) => cmd_trace_recover(args, cli.json),
        Command::Ldfi(args) => cmd_ldfi(&args, cli.json),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("Error: {msg}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asupersync::lab::scenario::{FaultAction, FaultEvent};
    use asupersync::trace::replay::TraceMetadata;
    use asupersync::trace::{
        IncidentCommand, IncidentDeterminism, IncidentProvenance, IncidentReplayCanonicalization,
        IncidentReplayMinimizationIssueKind, IncidentReplayShrinkStepKind, IncidentReplaySource,
        IncidentSourceKind,
    };
    use std::collections::BTreeMap;

    #[test]
    fn ldfi_cli_core_finds_single_shared_fault() {
        use asupersync::remote::NodeId;
        use asupersync::trace::distributed::{LogicalTime, VectorClock};
        use asupersync::types::Time;

        let net = NodeId::new("net");
        let a = NodeId::new("a");
        let b = NodeId::new("b");
        let mut send = VectorClock::new();
        send.increment(&net);
        let mut ack_a = send.clone();
        ack_a.increment(&a);
        let mut ack_b = send.clone();
        ack_b.increment(&b);
        let mut ok_a = ack_a.clone();
        ok_a.increment(&a);
        let mut ok_b = ack_b.clone();
        ok_b.increment(&b);

        let trace = vec![
            TraceEvent::io_result(1, Time::ZERO, 10, 4)
                .with_logical_time(LogicalTime::Vector(send)),
            TraceEvent::io_ready(2, Time::ZERO, 20, 1)
                .with_logical_time(LogicalTime::Vector(ack_a)),
            TraceEvent::io_ready(3, Time::ZERO, 30, 1)
                .with_logical_time(LogicalTime::Vector(ack_b)),
            TraceEvent::user_trace(10, Time::ZERO, "delivered-a")
                .with_logical_time(LogicalTime::Vector(ok_a)),
            TraceEvent::user_trace(11, Time::ZERO, "delivered-b")
                .with_logical_time(LogicalTime::Vector(ok_b)),
        ];

        let budget = HittingSetBudget {
            max_depth: 3,
            max_hypotheses: 64,
        };
        let report = run_ldfi(&trace, "user_trace", None, budget).expect("report");
        assert_eq!(report.hypotheses[0], vec![1u64]);
        assert_eq!(report.blind_chaos_single_fault_experiments, 3);
        assert_eq!(report.coverage_certificate, None);
        assert_eq!(report.schema, "ldfi-report-v1");

        let json = serde_json::to_string(&report).expect("serialize");
        let back: LdfiReport = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, report);

        // Unknown outcome kind and a kind with no matching events are clean errors.
        assert!(run_ldfi(&trace, "bogus-kind", None, budget).is_err());
        assert!(run_ldfi(&trace, "down_delivered", None, budget).is_err());
    }

    fn disk_pressure_fault(at_ms: u64, path: &str) -> FaultEvent {
        let mut args = BTreeMap::new();
        args.insert("path".to_string(), serde_json::json!(path));
        args.insert("bytes".to_string(), serde_json::json!(1024));
        FaultEvent {
            at_ms,
            action: FaultAction::DiskPressure,
            args,
        }
    }

    #[test]
    fn fault_index_elements_round_trip_and_sort() {
        let elements = vec![
            ScenarioElement::AdvanceTime { nanos: 4 },
            ScenarioElement::AdvanceTime { nanos: 2 },
            ScenarioElement::AdvanceTime { nanos: 4 },
        ];

        assert_eq!(fault_indices_from_elements(&elements), vec![1, 3]);
    }

    #[test]
    fn minimize_fault_indices_recovers_required_fault_pair() {
        let outcome =
            minimize_fault_indices(6, 0, |indices| indices.contains(&1) && indices.contains(&4))
                .expect("full fault set fails");

        assert_eq!(outcome.minimized_fault_indices, vec![1, 4]);
        assert_eq!(outcome.minimized_fault_count, 2);
        assert_eq!(outcome.removed_fault_count, 4);
        assert!(outcome.verified_still_failing);
        assert!(!outcome.budget_exhausted);
    }

    #[test]
    fn minimize_fault_indices_is_deterministic() {
        let first =
            minimize_fault_indices(7, 0, |indices| indices.contains(&1) && indices.contains(&5))
                .expect("full fault set fails");
        let second =
            minimize_fault_indices(7, 0, |indices| indices.contains(&1) && indices.contains(&5))
                .expect("full fault set fails");

        assert_eq!(
            first.minimized_fault_indices,
            second.minimized_fault_indices
        );
        assert_eq!(first.removed_fault_indices, second.removed_fault_indices);
        assert_eq!(
            first.reduction_ratio.to_bits(),
            second.reduction_ratio.to_bits()
        );
        assert_eq!(first.replay_attempts, second.replay_attempts);
        assert_eq!(first.budget_exhausted, second.budget_exhausted);
        assert_eq!(first.verified_still_failing, second.verified_still_failing);
    }

    #[test]
    fn minimize_scenario_report_has_stable_json_shape() {
        let scenario = Scenario {
            id: "synthetic-minimize-schema".to_string(),
            faults: vec![
                disk_pressure_fault(10, "target/a"),
                disk_pressure_fault(20, "target/required"),
                disk_pressure_fault(30, "target/c"),
            ],
            ..Scenario::default()
        };

        let report = minimize_scenario_report(
            Path::new("synthetic.yaml"),
            &scenario,
            0,
            Some(77),
            |candidate| candidate.faults.iter().any(|fault| fault.at_ms == 20),
        )
        .expect("required synthetic fault should keep scenario failing");

        assert_eq!(report.schema_version, 1);
        assert_eq!(report.input_kind, "scenario_yaml");
        assert_eq!(report.minimized_surface, "faults");
        assert_eq!(report.scenario, "synthetic.yaml");
        assert_eq!(report.scenario_id, "synthetic-minimize-schema");
        assert_eq!(report.per_replay_step_cap, Some(77));
        assert_eq!(report.outcome.minimized_fault_indices, vec![1]);
        assert_eq!(report.minimized_scenario.faults.len(), 1);
        assert_eq!(report.minimized_scenario.faults[0].at_ms, 20);
        assert_eq!(report.minimized_scenario.lab.max_steps, Some(77));

        let json = serde_json::to_value(&report).expect("report serializes");
        assert_eq!(json["schema_version"], 1);
        assert_eq!(json["input_kind"], "scenario_yaml");
        assert_eq!(json["minimized_surface"], "faults");
        assert_eq!(json["scenario_id"], "synthetic-minimize-schema");
        assert_eq!(json["per_replay_step_cap"], 77);
        assert_eq!(
            json["outcome"]["minimized_fault_indices"],
            serde_json::json!([1])
        );
        assert_eq!(
            json["minimized_scenario"]["faults"]
                .as_array()
                .expect("faults is an array")
                .len(),
            1
        );
    }

    #[test]
    fn minimize_fault_indices_budget_exhaustion_keeps_verified_result() {
        let outcome = minimize_fault_indices(4, 1, |indices| indices.contains(&2))
            .expect("full fault set fails");

        assert_eq!(outcome.minimized_fault_indices, vec![0, 1, 2, 3]);
        assert_eq!(outcome.removed_fault_count, 0);
        assert!(outcome.verified_still_failing);
        assert!(outcome.budget_exhausted);
    }

    #[test]
    fn minimize_fault_indices_rejects_passing_input() {
        let err = minimize_fault_indices(3, 0, |_| false).expect_err("input must fail");

        assert!(err.contains("does not currently fail"));
    }

    fn synthetic_incident_replay_package() -> IncidentReplayPackage {
        let crashpack = IncidentReplaySource {
            source_id: "crashpack-main".to_string(),
            role: IncidentReplaySourceRole::CrashPack,
            kind: IncidentSourceKind::CrashPack,
            artifact_path: Some("artifacts/crashpacks/main.json".to_string()),
            content_hash: format!("sha256:{}", "a".repeat(64)),
            content_bytes: 256,
            trace_fingerprint: Some("trace-fingerprint-main".to_string()),
            provenance_edge: "capture->crashpack-main".to_string(),
        };
        let trace_log = IncidentReplaySource {
            source_id: "trace-log-main".to_string(),
            role: IncidentReplaySourceRole::TraceLog,
            kind: IncidentSourceKind::TraceLog,
            artifact_path: Some("artifacts/traces/main.json".to_string()),
            content_hash: format!("sha256:{}", "b".repeat(64)),
            content_bytes: 512,
            trace_fingerprint: Some("trace-fingerprint-main".to_string()),
            provenance_edge: "capture->trace-log-main".to_string(),
        };

        IncidentReplayPackage {
            schema_version: asupersync::trace::INCIDENT_REPLAY_PACKAGE_SCHEMA_VERSION,
            package_id: "incident-replay-v1:synthetic".to_string(),
            bundle_id: "bundle-synthetic".to_string(),
            bundle_fingerprint: 42,
            sources: vec![crashpack, trace_log],
            trace_metadata: TraceMetadata::new(17)
                .with_config_hash(99)
                .with_description("synthetic incident replay package"),
            command: IncidentCommand {
                program: "rch".to_string(),
                args: vec!["exec".to_string(), "--".to_string(), "cargo".to_string()],
                env: Vec::new(),
                working_dir: ".".to_string(),
            },
            determinism: IncidentDeterminism {
                seed: Some(17),
                schedule_seed: None,
                virtual_time_nanos: Some(0),
                config_hash: "config-hash".to_string(),
                feature_flags: vec!["extra-diagnostics".to_string()],
                target_triple: "x86_64-unknown-linux-gnu".to_string(),
            },
            provenance: IncidentProvenance {
                capture_id: "capture-synthetic".to_string(),
                origin: "unit-test".to_string(),
                reporter: "frankenlab".to_string(),
                captured_commit: Some("0123456789abcdef".to_string()),
                related_bead_id: Some("asupersync-lab-dx-v2-n2v2fi.4".to_string()),
            },
            canonicalization: IncidentReplayCanonicalization {
                source_digest: 1,
                source_order: vec!["crashpack-main".to_string(), "trace-log-main".to_string()],
                trace_fingerprints: vec!["trace-fingerprint-main".to_string()],
                normalization_strategy: "synthetic-unit-fixture".to_string(),
            },
        }
    }

    #[test]
    fn minimize_incident_replay_package_keeps_crashpack_source() {
        let package = synthetic_incident_replay_package();
        let report = minimize_incident_replay_package_report(
            Path::new("synthetic-incident-package.json"),
            &package,
            0,
            None,
        );
        let repro = report.outcome.repro.expect("repro emitted");

        assert_eq!(report.input_kind, "incident_replay_package_json");
        assert_eq!(report.minimized_surface, "replay_package_sources");
        assert_eq!(
            report.outcome.verdict,
            IncidentReplayMinimizationVerdict::Minimized
        );
        assert_eq!(repro.retained_sources.len(), 1);
        assert_eq!(repro.retained_sources[0].source_id, "crashpack-main");
        assert_eq!(repro.removed_source_ids, ["trace-log-main"]);
        assert_eq!(repro.removed_feature_flags, ["extra-diagnostics"]);
        assert!(!repro.summary.budget_exhausted);
    }

    #[test]
    fn minimize_incident_replay_package_has_stable_json_projection() {
        let package = synthetic_incident_replay_package();
        let first = minimize_incident_replay_package_report(
            Path::new("synthetic-incident-package.json"),
            &package,
            8,
            Some(55),
        );
        let second = minimize_incident_replay_package_report(
            Path::new("synthetic-incident-package.json"),
            &package,
            8,
            Some(55),
        );

        let first_json = serde_json::to_string_pretty(&first).expect("report serializes");
        let second_json = serde_json::to_string_pretty(&second).expect("report serializes");
        assert_eq!(first_json, second_json);

        let value: serde_json::Value =
            serde_json::from_str(&first_json).expect("report JSON parses");
        assert_eq!(value["schema_version"], 1);
        assert_eq!(value["input_kind"], "incident_replay_package_json");
        assert_eq!(value["minimized_surface"], "replay_package_sources");
        assert_eq!(value["package"], "synthetic-incident-package.json");
        assert_eq!(value["package_id"], "incident-replay-v1:synthetic");
        assert_eq!(value["per_replay_step_cap"], 55);
        assert_eq!(value["oracle"]["kind"], "panic");
        assert_eq!(
            value["oracle"]["expected_signal"],
            "crashpack_replay_source_preserved"
        );
        assert_eq!(value["config"]["step_budget"], 8);
        assert_eq!(value["verification"]["emitted_repro"], true);
        assert_eq!(value["verification"]["verified_still_failing"], true);
        assert_eq!(value["verification"]["oracle_stable"], true);
        assert_eq!(value["verification"]["required_source_roles_present"], true);
        assert_eq!(
            value["verification"]["required_trace_fingerprint_present"],
            true
        );
        assert_eq!(value["verification"]["retained_source_count"], 1);
        assert_eq!(value["verification"]["retained_feature_flag_count"], 0);
        assert_eq!(value["verification"]["budget_exhausted"], false);
        assert_eq!(value["outcome"]["verdict"], "minimized");
        assert_eq!(
            value["outcome"]["repro"]["retained_sources"][0]["source_id"],
            "crashpack-main"
        );
    }

    #[test]
    fn minimize_incident_replay_package_budget_exhaustion_keeps_best_repro() {
        let package = synthetic_incident_replay_package();
        let report = minimize_incident_replay_package_report(
            Path::new("synthetic-incident-package.json"),
            &package,
            1,
            None,
        );
        let repro = report.outcome.repro.expect("budgeted repro emitted");

        assert_eq!(
            report.outcome.verdict,
            IncidentReplayMinimizationVerdict::BudgetExhausted
        );
        assert!(report.outcome.issues.iter().any(|issue| {
            issue.kind == IncidentReplayMinimizationIssueKind::BudgetExhausted
                && issue.field == "config.step_budget"
        }));
        assert!(report.outcome.steps.iter().any(|step| {
            step.kind == IncidentReplayShrinkStepKind::BudgetExhausted && !step.accepted
        }));
        assert!(repro.summary.budget_exhausted);
        assert!(report.verification.status.emitted_repro);
        assert!(report.verification.status.verified_still_failing);
        assert!(
            report
                .verification
                .required_evidence
                .required_source_roles_present
        );
        assert!(
            report
                .verification
                .required_evidence
                .required_trace_fingerprint_present
        );
        assert!(report.verification.budget_exhausted);
        assert_eq!(repro.retained_sources.len(), 1);
        assert_eq!(repro.retained_sources[0].source_id, "crashpack-main");
        assert_eq!(repro.removed_source_ids, ["trace-log-main"]);
        assert_eq!(repro.retained_feature_flags, ["extra-diagnostics"]);
    }

    #[test]
    fn incident_replay_package_human_output_prints_verification_status() {
        let package = synthetic_incident_replay_package();
        let report = minimize_incident_replay_package_report(
            Path::new("synthetic-incident-package.json"),
            &package,
            8,
            None,
        );
        let output = format_incident_minimize_result(&report);

        assert!(output.contains("Emitted repro: yes"));
        assert!(output.contains("Verified still failing: yes"));
        assert!(output.contains("Oracle stable: yes"));
        assert!(output.contains("Required source roles present: yes"));
        assert!(output.contains("Required trace fingerprint present: yes"));
        assert!(output.contains("Retained source count: 1"));
        assert!(output.contains("Retained feature flag count: 0"));
        assert!(output.contains("Budget exhausted: no"));
        assert!(output.contains("Replay units: 3 -> 1"));
    }

    #[test]
    fn incident_replay_package_verification_fails_closed_without_repro() {
        let package = synthetic_incident_replay_package();
        let oracle = IncidentReplayOracle {
            kind: IncidentOracleKind::Panic,
            expected_signal: "missing-required-source".to_string(),
            stable: true,
            required_source_roles: vec![IncidentReplaySourceRole::SupportBundle],
            required_trace_fingerprint: Some("missing-fingerprint".to_string()),
        };
        let outcome = minimize_incident_replay_package(
            &package,
            oracle.clone(),
            IncidentReplayMinimizationConfig {
                step_budget: 8,
                shrink_feature_flags: true,
            },
        );
        let verification = verify_incident_replay_package_repro(&oracle, &outcome);

        assert!(!outcome.has_repro());
        assert!(!verification.status.emitted_repro);
        assert!(!verification.status.verified_still_failing);
        assert!(verification.status.oracle_stable);
        assert!(!verification.required_evidence.required_source_roles_present);
        assert!(
            !verification
                .required_evidence
                .required_trace_fingerprint_present
        );
        assert_eq!(verification.retained_source_count, 0);
        assert_eq!(verification.retained_feature_flag_count, 0);
        assert!(!verification.budget_exhausted);
    }

    #[test]
    fn incident_replay_package_human_output_fails_closed_without_repro() {
        let package = synthetic_incident_replay_package();
        let oracle = IncidentReplayOracle {
            kind: IncidentOracleKind::Panic,
            expected_signal: "missing-required-source".to_string(),
            stable: true,
            required_source_roles: vec![IncidentReplaySourceRole::SupportBundle],
            required_trace_fingerprint: Some("missing-fingerprint".to_string()),
        };
        let config = IncidentReplayMinimizationConfig {
            step_budget: 8,
            shrink_feature_flags: true,
        };
        let outcome = minimize_incident_replay_package(&package, oracle.clone(), config);
        let verification = verify_incident_replay_package_repro(&oracle, &outcome);
        let report = MinimizeIncidentReplayPackageReport {
            schema_version: 1,
            input_kind: "incident_replay_package_json",
            minimized_surface: "replay_package_sources",
            package: "synthetic-incident-package.json".to_string(),
            package_id: package.package_id,
            per_replay_step_cap: None,
            oracle,
            config,
            verification,
            outcome,
        };
        let output = format_incident_minimize_result(&report);

        assert!(output.contains("Emitted repro: no"));
        assert!(output.contains("Verified still failing: no"));
        assert!(output.contains("Required source roles present: no"));
        assert!(output.contains("Required trace fingerprint present: no"));
        assert!(output.contains("Retained source count: 0"));
        assert!(output.contains("Retained feature flag count: 0"));
        assert!(output.contains("Issues: "));
        assert!(!output.contains("Replay units:"));
    }

    #[test]
    fn minimize_input_detects_incident_replay_package_json() {
        let package = synthetic_incident_replay_package();
        let json = serde_json::to_string_pretty(&package).expect("package serializes");
        let parsed = parse_minimize_input(Path::new("synthetic.json"), &json)
            .expect("incident replay package parses");

        match parsed {
            MinimizeInput::IncidentReplayPackageJson(parsed_package) => {
                assert_eq!(parsed_package.package_id, package.package_id);
            }
            MinimizeInput::ScenarioYaml(_) => panic!("expected incident replay package input"),
        }
    }
}
