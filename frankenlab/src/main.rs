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

use asupersync::lab::scenario::Scenario;
use asupersync::lab::scenario_runner::{
    ScenarioExplorationResult, ScenarioRunResult, ScenarioRunner, ScenarioRunnerError,
};
use asupersync::trace::minimizer::LogicalMinimizerClock;
use asupersync::trace::{
    IncidentOracleKind, IncidentReplayMinimizationConfig, IncidentReplayMinimizationReport,
    IncidentReplayMinimizationVerdict, IncidentReplayOracle, IncidentReplayPackage,
    IncidentReplaySourceRole, ScenarioElement, TraceMinimizer, minimize_incident_replay_package,
};
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
    oracle: IncidentReplayOracle,
    config: IncidentReplayMinimizationConfig,
    outcome: IncidentReplayMinimizationReport,
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
    mut fails_with_scenario: impl FnMut(&Scenario) -> bool,
) -> Result<MinimizeScenarioReport, String> {
    let outcome = minimize_fault_indices(scenario.faults.len(), max_replays, |indices| {
        let reduced = scenario_with_fault_indices(scenario, indices);
        fails_with_scenario(&reduced)
    })?;

    if !outcome.verified_still_failing {
        return Err("minimized scenario did not reproduce the original failure".into());
    }

    let minimized_scenario =
        scenario_with_fault_indices(scenario, &outcome.minimized_fault_indices);

    Ok(MinimizeScenarioReport {
        schema_version: 1,
        input_kind: "scenario_yaml",
        minimized_surface: "faults",
        scenario: scenario_path.display().to_string(),
        scenario_id: scenario.id.clone(),
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
) -> MinimizeIncidentReplayPackageReport {
    let oracle = crashpack_replay_oracle(package);
    let config = IncidentReplayMinimizationConfig {
        step_budget: incident_replay_step_budget(max_replays),
        shrink_feature_flags: true,
    };
    let outcome = minimize_incident_replay_package(package, oracle.clone(), config);

    MinimizeIncidentReplayPackageReport {
        schema_version: 1,
        input_kind: "incident_replay_package_json",
        minimized_surface: "replay_package_sources",
        package: package_path.display().to_string(),
        package_id: package.package_id.clone(),
        oracle,
        config,
        outcome,
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

fn format_incident_minimize_result(report: &MinimizeIncidentReplayPackageReport) -> String {
    let verdict = incident_verdict_tag(report.outcome.verdict);
    let mut lines = vec![
        format!(
            "Incident replay package: {} [{}]",
            report.package_id, verdict
        ),
        format!("Shrink steps: {}", report.outcome.steps.len()),
    ];

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
        lines.push(format!(
            "Budget exhausted: {}",
            repro.summary.budget_exhausted
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
    let report =
        minimize_scenario_report(&args.scenario, scenario, args.max_replays, |candidate| {
            ScenarioRunner::run(candidate).is_ok_and(|result| !result.passed())
        })?;

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
        println!("Verified still failing: yes");
    }

    Ok(())
}

fn cmd_minimize_incident_replay_package(
    args: &MinimizeArgs,
    json: bool,
    package: &IncidentReplayPackage,
) -> Result<(), String> {
    let report = minimize_incident_replay_package_report(&args.scenario, package, args.max_replays);

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
        IncidentReplaySource, IncidentSourceKind,
    };
    use std::collections::BTreeMap;

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

        let report =
            minimize_scenario_report(Path::new("synthetic.yaml"), &scenario, 0, |candidate| {
                candidate.faults.iter().any(|fault| fault.at_ms == 20)
            })
            .expect("required synthetic fault should keep scenario failing");

        assert_eq!(report.schema_version, 1);
        assert_eq!(report.input_kind, "scenario_yaml");
        assert_eq!(report.minimized_surface, "faults");
        assert_eq!(report.scenario, "synthetic.yaml");
        assert_eq!(report.scenario_id, "synthetic-minimize-schema");
        assert_eq!(report.outcome.minimized_fault_indices, vec![1]);
        assert_eq!(report.minimized_scenario.faults.len(), 1);
        assert_eq!(report.minimized_scenario.faults[0].at_ms, 20);

        let json = serde_json::to_value(&report).expect("report serializes");
        assert_eq!(json["schema_version"], 1);
        assert_eq!(json["input_kind"], "scenario_yaml");
        assert_eq!(json["minimized_surface"], "faults");
        assert_eq!(json["scenario_id"], "synthetic-minimize-schema");
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
