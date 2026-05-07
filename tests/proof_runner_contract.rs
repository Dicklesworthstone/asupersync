//! Contract tests for the agent-swarm safe proof runner.

#![allow(missing_docs)]

use serde_json::Value;
use std::collections::{BTreeSet, HashMap};
use std::process::{Command, Output};

const SCRIPT_PATH: &str = "scripts/proof_runner.py";
const MANIFEST_PATH: &str = "artifacts/proof_lane_manifest_v1.json";
const SCHEMA_PATH: &str = "artifacts/validation_frontier_ledger_schema_v1.json";

fn load_json(path: &str) -> Value {
    let raw = std::fs::read_to_string(path).unwrap_or_else(|error| panic!("read {path}: {error}"));
    serde_json::from_str(&raw).unwrap_or_else(|error| panic!("parse {path}: {error}"))
}

fn run_proof_runner(args: &[&str]) -> Result<Output, std::io::Error> {
    Command::new("python3").arg(SCRIPT_PATH).args(args).output()
}

fn proof_runner_json(args: &[&str]) -> Value {
    let output = run_proof_runner(args).expect("proof runner should execute");
    if !output.status.success() {
        panic!(
            "proof runner failed: {}\nstdout: {}\nstderr: {}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str(&stdout)
        .unwrap_or_else(|error| panic!("proof runner output not JSON: {error}\noutput: {stdout}"))
}

#[test]
fn proof_runner_script_exists_and_is_executable() {
    assert!(
        std::path::Path::new(SCRIPT_PATH).exists(),
        "proof runner script must exist at {SCRIPT_PATH}"
    );
    let output = run_proof_runner(&["--help"]).expect("proof runner must be executable");
    assert!(
        output.status.success() || output.status.code() == Some(0),
        "proof runner --help should succeed"
    );
}

#[test]
fn proof_runner_can_list_available_lanes() {
    let result = proof_runner_json(&["--list-lanes", "--output", "json"]);
    let lanes = result["available_lanes"]
        .as_array()
        .expect("list-lanes should return available_lanes array");

    // Should have the key lanes from the manifest
    let lane_set: BTreeSet<String> = lanes
        .iter()
        .map(|v| v.as_str().expect("lane should be string").to_string())
        .collect();

    for required_lane in [
        "rustfmt-check",
        "all-targets-check",
        "clippy-all-targets",
        "lib-tests",
    ] {
        assert!(
            lane_set.contains(required_lane),
            "list-lanes should include {required_lane}"
        );
    }
}

#[test]
fn proof_runner_suggests_appropriate_lanes_for_rust_files() {
    let result = proof_runner_json(&[
        "--suggest-lanes",
        "--touched-files",
        "src/runtime/state.rs",
        "src/obligation/ledger.rs",
        "--output",
        "json",
    ]);

    let suggested = result["suggested_lanes"]
        .as_array()
        .expect("suggest-lanes should return suggested_lanes array");

    let suggestions: BTreeSet<String> = suggested
        .iter()
        .map(|v| v.as_str().expect("suggestion should be string").to_string())
        .collect();

    // Should suggest format check for any file
    assert!(suggestions.contains("rustfmt-check"));

    // Should suggest compilation and linting for Rust files
    assert!(suggestions.contains("all-targets-check"));
    assert!(suggestions.contains("clippy-all-targets"));

    // Should suggest lib tests for src/ files
    assert!(suggestions.contains("lib-tests"));
}

#[test]
fn proof_runner_suggests_dependency_checks_for_cargo_toml() {
    let result = proof_runner_json(&[
        "--suggest-lanes",
        "--touched-files",
        "Cargo.toml",
        "--output",
        "json",
    ]);

    let suggested = result["suggested_lanes"]
        .as_array()
        .expect("suggest-lanes should return suggested_lanes array");

    let suggestions: BTreeSet<String> = suggested
        .iter()
        .map(|v| v.as_str().expect("suggestion should be string").to_string())
        .collect();

    // Should suggest dependency validation for Cargo.toml changes
    assert!(suggestions.contains("default-production-tokio-tree"));
    assert!(suggestions.contains("rustfmt-check"));
}

#[test]
fn proof_runner_blocks_unknown_lanes() {
    let output = run_proof_runner(&[
        "--lane",
        "nonexistent-lane-12345",
        "--touched-files",
        "src/test.rs",
        "--output",
        "json",
    ])
    .expect("proof runner should execute");

    // Should fail with exit code 1 (blocked)
    assert_eq!(output.status.code(), Some(1));

    let result: Value = serde_json::from_str(&String::from_utf8_lossy(&output.stdout))
        .expect("should return JSON on error");

    assert!(!result["preflight_passed"].as_bool().unwrap_or(true));
    let record = &result["validation_frontier_record"];
    assert_eq!(record["decision"].as_str(), Some("blocked-external"));
    assert_eq!(record["error_class"].as_str(), Some("unknown_proof_lane"));
}

#[test]
fn proof_runner_emits_validation_frontier_compatible_records() {
    // Test with a known lane to get a proper record structure
    let result = proof_runner_json(&[
        "--lane",
        "rustfmt-check",
        "--touched-files",
        "src/lib.rs",
        "--output",
        "json",
    ]);

    let record = &result["validation_frontier_record"];

    // Verify required fields from the schema exist
    assert!(record["command"].is_string(), "record must have command");
    assert!(
        record["timestamp"].is_string(),
        "record must have timestamp"
    );
    assert!(
        record["touched_files"].is_array(),
        "record must have touched_files array"
    );
    assert!(record["decision"].is_string(), "record must have decision");
    assert!(
        record["error_class"].is_string(),
        "record must have error_class"
    );

    let first_failure = &record["first_failure"];
    assert!(first_failure["crate_or_surface"].is_string());
    assert!(first_failure["target"].is_string());
    assert!(first_failure["file"].is_string());
    assert!(first_failure["line"].is_number());

    assert!(
        record["likely_owner"].is_string(),
        "record must have likely_owner"
    );
    assert!(record["supplemental_proof_command"].is_string());
    assert!(record["summary"].is_string(), "record must have summary");

    // Decision should be valid
    let decision = record["decision"]
        .as_str()
        .expect("decision should be string");
    assert!(
        matches!(decision, "pass" | "blocked-external" | "failed-local"),
        "decision should be a valid frontier decision: {decision}"
    );
}

#[test]
fn proof_runner_generates_appropriate_supplemental_proofs() {
    // Test supplemental proof for formatting
    let result = proof_runner_json(&[
        "--lane",
        "rustfmt-check",
        "--touched-files",
        "src/runtime/state.rs",
        "--output",
        "json",
    ]);

    let supplemental = result["validation_frontier_record"]["supplemental_proof_command"]
        .as_str()
        .expect("should have supplemental proof command");

    // Should generate a narrow rustfmt command
    assert!(
        supplemental.contains("rustfmt") && supplemental.contains("src/runtime/state.rs"),
        "supplemental proof should focus on touched file: {supplemental}"
    );

    // Test supplemental proof for compilation
    let result = proof_runner_json(&[
        "--lane",
        "all-targets-check",
        "--touched-files",
        "src/sync/mutex.rs",
        "src/sync/pool.rs",
        "--output",
        "json",
    ]);

    let supplemental = result["validation_frontier_record"]["supplemental_proof_command"]
        .as_str()
        .expect("should have supplemental proof command");

    // Should suggest a narrower compilation check
    assert!(
        supplemental.contains("cargo check") || supplemental.contains("rustfmt"),
        "supplemental proof should be narrower than all-targets: {supplemental}"
    );
}

#[test]
fn proof_runner_uses_manifest_commands_correctly() {
    let manifest = load_json(MANIFEST_PATH);
    let lanes = manifest["lanes"]
        .as_array()
        .expect("manifest should have lanes");

    // Pick a few representative lanes to test
    for lane in lanes.iter().take(3) {
        let lane_id = lane["lane_id"].as_str().expect("lane should have id");
        let expected_command = lane["command"].as_str().expect("lane should have command");

        let result = proof_runner_json(&[
            "--lane",
            lane_id,
            "--touched-files",
            "src/lib.rs",
            "--output",
            "json",
        ]);

        let actual_command = result["command_would_run"]
            .as_str()
            .expect("result should include command_would_run");

        assert_eq!(
            actual_command, expected_command,
            "proof runner should use manifest command for lane {lane_id}"
        );
    }
}

#[test]
fn proof_runner_record_schema_matches_validation_frontier_contract() {
    let schema = load_json(SCHEMA_PATH);
    let required_fields: BTreeSet<String> = schema["record_fields"]
        .as_array()
        .expect("schema should have record_fields")
        .iter()
        .map(|field| {
            field["name"]
                .as_str()
                .expect("field should have name")
                .to_string()
        })
        .collect();

    // Get a sample record from the proof runner
    let result = proof_runner_json(&[
        "--lane",
        "rustfmt-check",
        "--touched-files",
        "README.md",
        "--output",
        "json",
    ]);

    let record = &result["validation_frontier_record"];

    // Verify all required fields are present
    for field in &required_fields {
        if field.contains('.') {
            // Nested field like "first_failure.file"
            let parts: Vec<&str> = field.split('.').collect();
            if parts.len() == 2 {
                assert!(
                    record[parts[0]][parts[1]].is_string()
                        || record[parts[0]][parts[1]].is_number()
                        || record[parts[0]][parts[1]].is_null(),
                    "record should have nested field {field}"
                );
            }
        } else {
            // Top-level field
            assert!(
                record[field].is_string() || record[field].is_array() || record[field].is_null(),
                "record should have field {field}"
            );
        }
    }
}

#[test]
fn proof_runner_produces_deterministic_output_for_same_inputs() {
    let args = &[
        "--lane",
        "rustfmt-check",
        "--touched-files",
        "src/types/outcome.rs",
        "--output",
        "json",
    ];

    let result1 = proof_runner_json(args);
    let result2 = proof_runner_json(args);

    // Remove timestamp which is expected to differ
    let mut record1 = result1["validation_frontier_record"].clone();
    let mut record2 = result2["validation_frontier_record"].clone();

    if let Value::Object(ref mut map1) = record1 {
        map1.remove("timestamp");
    }
    if let Value::Object(ref mut map2) = record2 {
        map2.remove("timestamp");
    }

    assert_eq!(
        record1, record2,
        "proof runner should produce deterministic output for same inputs"
    );
}

#[test]
fn proof_runner_output_format_is_machine_readable() {
    let result = proof_runner_json(&[
        "--lane",
        "lib-tests",
        "--touched-files",
        "src/channel/mpsc.rs",
        "--output",
        "json",
    ]);

    // Should have required top-level fields
    assert!(result["preflight_passed"].is_boolean());
    assert!(result["lane_id"].is_string());
    assert!(result["command_would_run"].is_string());
    assert!(result["validation_frontier_record"].is_object());
    assert!(result["recommendation"].is_string());

    let recommendation = result["recommendation"]
        .as_str()
        .expect("recommendation should be string");
    assert!(
        matches!(recommendation, "proceed" | "use_supplemental"),
        "recommendation should be valid: {recommendation}"
    );
}
