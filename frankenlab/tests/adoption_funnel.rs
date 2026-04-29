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

fn assert_scenario_valid(name: &str) {
    let errors = load_scenario(name).validate();
    assert!(errors.is_empty(), "Validation errors: {errors:?}");
}

fn assert_scenario_run_passes(name: &str, require_faults: bool) {
    let scenario = load_scenario(name);
    let result = ScenarioRunner::run_with_seed(&scenario, None).expect("scenario runner error");
    assert!(
        result.passed(),
        "Scenario failed: violations={:?}",
        result.lab_report.invariant_violations
    );
    if require_faults {
        assert!(
            result.faults_injected > 0,
            "Expected faults to be injected in saga partition scenario"
        );
    }
}

fn assert_replay_matches(name: &str, expected_id: &str) {
    let scenario = load_scenario(name);
    let result = ScenarioRunner::validate_replay(&scenario).expect("replay divergence detected");
    assert_eq!(result.scenario_id, expected_id);
}

fn assert_explore_passes(name: &str, seeds: usize) {
    let scenario = load_scenario(name);
    let result = ScenarioRunner::explore_seeds(&scenario, 0, seeds).expect("exploration error");
    assert!(
        result.all_passed(),
        "Failed seeds: {}/{}. First failure at seed {:?}",
        result.failed,
        result.seeds_explored,
        result.first_failure_seed
    );
}

// -----------------------------------------------------------------------
// Step 1: All scenarios validate without errors
// -----------------------------------------------------------------------

#[test]
fn validate_01_race_condition() {
    assert_scenario_valid("01_race_condition.yaml");
}

#[test]
fn validate_02_obligation_leak() {
    assert_scenario_valid("02_obligation_leak.yaml");
}

#[test]
fn validate_03_saga_partition() {
    assert_scenario_valid("03_saga_partition.yaml");
}

// -----------------------------------------------------------------------
// Step 2: All scenarios run successfully with default seeds
// -----------------------------------------------------------------------

#[test]
fn run_01_race_condition() {
    assert_scenario_run_passes("01_race_condition.yaml", false);
}

#[test]
fn run_02_obligation_leak() {
    assert_scenario_run_passes("02_obligation_leak.yaml", false);
}

#[test]
fn run_03_saga_partition() {
    assert_scenario_run_passes("03_saga_partition.yaml", true);
}

// -----------------------------------------------------------------------
// Step 3: Replay produces identical results (determinism)
// -----------------------------------------------------------------------

#[test]
fn replay_01_race_condition() {
    assert_replay_matches("01_race_condition.yaml", "example-race-condition");
}

#[test]
fn replay_02_obligation_leak() {
    assert_replay_matches("02_obligation_leak.yaml", "example-obligation-leak");
}

#[test]
fn replay_03_saga_partition() {
    assert_replay_matches("03_saga_partition.yaml", "example-saga-partition");
}

// -----------------------------------------------------------------------
// Step 4: Seed exploration finds no failures
// -----------------------------------------------------------------------

#[test]
fn explore_01_race_condition_50_seeds() {
    assert_explore_passes("01_race_condition.yaml", 50);
}

#[test]
fn explore_02_obligation_leak_30_seeds() {
    assert_explore_passes("02_obligation_leak.yaml", 30);
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
