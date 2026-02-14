//! Integration test for the FrankenLab adoption funnel.
//!
//! Validates that the full adoption workflow works end-to-end:
//! validate → run → replay → explore for all example scenarios.

use asupersync::lab::scenario::Scenario;
use asupersync::lab::scenario_runner::ScenarioRunner;
use std::fs;
use std::path::PathBuf;

fn scenarios_dir() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir.join("examples/scenarios")
}

fn load_scenario(name: &str) -> Scenario {
    let path = scenarios_dir().join(name);
    let yaml = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {e}", path.display()));
    serde_yaml::from_str(&yaml)
        .unwrap_or_else(|e| panic!("Failed to parse {}: {e}", path.display()))
}

// -----------------------------------------------------------------------
// Step 1: All scenarios validate without errors
// -----------------------------------------------------------------------

#[test]
fn validate_01_race_condition() {
    let scenario = load_scenario("01_race_condition.yaml");
    let errors = scenario.validate();
    assert!(errors.is_empty(), "Validation errors: {errors:?}");
}

#[test]
fn validate_02_obligation_leak() {
    let scenario = load_scenario("02_obligation_leak.yaml");
    let errors = scenario.validate();
    assert!(errors.is_empty(), "Validation errors: {errors:?}");
}

#[test]
fn validate_03_saga_partition() {
    let scenario = load_scenario("03_saga_partition.yaml");
    let errors = scenario.validate();
    assert!(errors.is_empty(), "Validation errors: {errors:?}");
}

// -----------------------------------------------------------------------
// Step 2: All scenarios run successfully with default seeds
// -----------------------------------------------------------------------

#[test]
fn run_01_race_condition() {
    let scenario = load_scenario("01_race_condition.yaml");
    let result = ScenarioRunner::run_with_seed(&scenario, None).expect("scenario runner error");
    assert!(
        result.passed(),
        "Scenario failed: violations={:?}",
        result.lab_report.invariant_violations
    );
}

#[test]
fn run_02_obligation_leak() {
    let scenario = load_scenario("02_obligation_leak.yaml");
    let result = ScenarioRunner::run_with_seed(&scenario, None).expect("scenario runner error");
    assert!(
        result.passed(),
        "Scenario failed: violations={:?}",
        result.lab_report.invariant_violations
    );
}

#[test]
fn run_03_saga_partition() {
    let scenario = load_scenario("03_saga_partition.yaml");
    let result = ScenarioRunner::run_with_seed(&scenario, None).expect("scenario runner error");
    assert!(
        result.passed(),
        "Scenario failed: violations={:?}",
        result.lab_report.invariant_violations
    );
    // Verify faults were actually injected
    assert!(
        result.faults_injected > 0,
        "Expected faults to be injected in saga partition scenario"
    );
}

// -----------------------------------------------------------------------
// Step 3: Replay produces identical results (determinism)
// -----------------------------------------------------------------------

#[test]
fn replay_01_race_condition() {
    let scenario = load_scenario("01_race_condition.yaml");
    let result = ScenarioRunner::validate_replay(&scenario).expect("replay divergence detected");
    assert_eq!(result.scenario_id, "example-race-condition");
}

#[test]
fn replay_02_obligation_leak() {
    let scenario = load_scenario("02_obligation_leak.yaml");
    let result = ScenarioRunner::validate_replay(&scenario).expect("replay divergence detected");
    assert_eq!(result.scenario_id, "example-obligation-leak");
}

#[test]
fn replay_03_saga_partition() {
    let scenario = load_scenario("03_saga_partition.yaml");
    let result = ScenarioRunner::validate_replay(&scenario).expect("replay divergence detected");
    assert_eq!(result.scenario_id, "example-saga-partition");
}

// -----------------------------------------------------------------------
// Step 4: Seed exploration finds no failures
// -----------------------------------------------------------------------

#[test]
fn explore_01_race_condition_50_seeds() {
    let scenario = load_scenario("01_race_condition.yaml");
    let result = ScenarioRunner::explore_seeds(&scenario, 0, 50).expect("exploration error");
    assert!(
        result.all_passed(),
        "Failed seeds: {}/{}. First failure at seed {:?}",
        result.failed,
        result.seeds_explored,
        result.first_failure_seed
    );
}

#[test]
fn explore_02_obligation_leak_30_seeds() {
    let scenario = load_scenario("02_obligation_leak.yaml");
    let result = ScenarioRunner::explore_seeds(&scenario, 0, 30).expect("exploration error");
    assert!(
        result.all_passed(),
        "Failed seeds: {}/{}. First failure at seed {:?}",
        result.failed,
        result.seeds_explored,
        result.first_failure_seed
    );
}

// -----------------------------------------------------------------------
// Step 5: JSON output is valid
// -----------------------------------------------------------------------

#[test]
fn json_output_is_valid() {
    let scenario = load_scenario("01_race_condition.yaml");
    let result = ScenarioRunner::run_with_seed(&scenario, None).expect("scenario runner error");
    let json = result.to_json();

    // Verify key fields are present
    assert!(json.get("scenario_id").is_some());
    assert!(json.get("seed").is_some());
    assert!(json.get("certificate").is_some());

    // Verify it serializes without error
    let serialized = serde_json::to_string(&json).expect("JSON serialization failed");
    assert!(!serialized.is_empty());
}

// -----------------------------------------------------------------------
// Scenario composition: seed override
// -----------------------------------------------------------------------

#[test]
fn seed_override_produces_different_fingerprint_or_same_result() {
    let scenario = load_scenario("01_race_condition.yaml");

    let result_default =
        ScenarioRunner::run_with_seed(&scenario, None).expect("run with default seed failed");
    let result_override = ScenarioRunner::run_with_seed(&scenario, Some(9999))
        .expect("run with override seed failed");

    // Both should pass (oracles hold regardless of seed)
    assert!(result_default.passed());
    assert!(result_override.passed());

    // Seeds should differ
    assert_ne!(result_default.seed, result_override.seed);
}
