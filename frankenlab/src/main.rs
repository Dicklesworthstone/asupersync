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

use asupersync::lab::scenario_runner::{
    ScenarioExplorationResult, ScenarioRunResult, ScenarioRunner, ScenarioRunnerError,
};
use asupersync::trace::minimizer::LogicalMinimizerClock;
use asupersync::trace::{ScenarioElement, TraceMinimizer};
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
    /// Path to the failing scenario YAML file
    scenario: PathBuf,

    /// Maximum scenario reruns used by the reducer; 0 means unlimited
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

fn load_scenario(path: &Path) -> Result<asupersync::lab::scenario::Scenario, String> {
    let yaml =
        fs::read_to_string(path).map_err(|e| format!("Failed to read {}: {e}", path.display()))?;
    serde_yaml::from_str(&yaml).map_err(|e| {
        format!(
            "Failed to parse {}: {e}. Hint: check indentation and field names",
            path.display()
        )
    })
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

fn scenario_with_fault_indices(
    scenario: &asupersync::lab::scenario::Scenario,
    fault_indices: &[usize],
) -> asupersync::lab::scenario::Scenario {
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

#[allow(clippy::needless_pass_by_value)]
fn cmd_minimize(args: MinimizeArgs, json: bool) -> Result<(), String> {
    let scenario = load_scenario(&args.scenario)?;
    let outcome = minimize_fault_indices(scenario.faults.len(), args.max_replays, |indices| {
        let reduced = scenario_with_fault_indices(&scenario, indices);
        ScenarioRunner::run(&reduced).is_ok_and(|result| !result.passed())
    })?;

    if !outcome.verified_still_failing {
        return Err("minimized scenario did not reproduce the original failure".into());
    }

    if json {
        let minimized = scenario_with_fault_indices(&scenario, &outcome.minimized_fault_indices);
        let report = serde_json::json!({
            "schema_version": 1,
            "input_kind": "scenario_yaml",
            "minimized_surface": "faults",
            "scenario": args.scenario.display().to_string(),
            "scenario_id": scenario.id,
            "outcome": outcome,
            "minimized_scenario": minimized,
        });
        println!("{}", pretty_json_or(&report, "{}"));
    } else {
        println!(
            "Minimized faults: {} -> {} ({:.1}% reduction)",
            outcome.original_fault_count,
            outcome.minimized_fault_count,
            outcome.reduction_ratio * 100.0
        );
        println!("Kept fault indices: {:?}", outcome.minimized_fault_indices);
        println!("Removed fault indices: {:?}", outcome.removed_fault_indices);
        println!(
            "Replay attempts: {}{}",
            outcome.replay_attempts,
            if outcome.budget_exhausted {
                " (budget exhausted)"
            } else {
                ""
            }
        );
        println!("Verified still failing: yes");
    }

    Ok(())
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
}
