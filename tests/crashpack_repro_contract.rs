//! Contract tests for the crashpack-to-repro command generator.

#![allow(missing_docs)]

use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

const SCRIPT_PATH: &str = "scripts/crashpack_to_repro.py";
const FIXTURE_ROOT: &str = "tests/fixtures/crashpack_to_repro";
const GENERATED_AT: &str = "2026-05-08T12:00:00Z";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn run_generator(fixture: &str) -> Output {
    Command::new("python3")
        .arg(repo_root().join(SCRIPT_PATH))
        .arg("--input")
        .arg(repo_root().join(FIXTURE_ROOT).join(fixture))
        .arg("--generated-at")
        .arg(GENERATED_AT)
        .arg("--output")
        .arg("json")
        .current_dir(repo_root())
        .output()
        .expect("run crashpack-to-repro helper")
}

fn generator_text(fixture: &str) -> String {
    let output = run_generator(fixture);
    assert!(
        output.status.success(),
        "generator failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("generator stdout is utf-8")
}

fn generator_json(fixture: &str) -> Value {
    serde_json::from_str(&generator_text(fixture)).expect("generator output must be JSON")
}

fn fixture_text(fixture: &str) -> String {
    fs::read_to_string(repo_root().join(FIXTURE_ROOT).join(fixture))
        .unwrap_or_else(|error| panic!("read fixture {fixture}: {error}"))
}

fn assert_output_matches_golden(input_fixture: &str, expected_fixture: &str) {
    let actual = generator_text(input_fixture);
    let expected = fixture_text(expected_fixture);
    let actual_json: Value =
        serde_json::from_str(&actual).expect("actual generator output must be JSON");
    let expected_json: Value =
        serde_json::from_str(&expected).expect("expected generator output must be JSON");

    assert_eq!(
        actual_json, expected_json,
        "parsed crashpack-to-repro JSON drifted for {input_fixture}"
    );
    assert_eq!(
        actual, expected,
        "crashpack-to-repro text drifted for {input_fixture}"
    );
}

fn command_ids(receipt: &Value) -> Vec<&str> {
    receipt["commands"]
        .as_array()
        .expect("commands")
        .iter()
        .map(|command| command["id"].as_str().expect("command id"))
        .collect()
}

#[test]
fn script_exists_and_help_is_non_mutating() {
    assert!(
        repo_root().join(SCRIPT_PATH).exists(),
        "crashpack-to-repro helper must exist at {SCRIPT_PATH}"
    );
    let output = Command::new("python3")
        .arg(repo_root().join(SCRIPT_PATH))
        .arg("--help")
        .current_dir(repo_root())
        .output()
        .expect("run helper --help");
    assert!(output.status.success(), "--help should succeed");
}

#[test]
fn cargo_test_crashpack_generates_rch_test_command() {
    let receipt = generator_json("cargo_test_crashpack.json");

    assert_eq!(
        receipt["schema_version"].as_str(),
        Some("crashpack-repro-command-v1")
    );
    assert_eq!(
        receipt["input_schema_version"].as_str(),
        Some("crashpack-to-repro-input-v1")
    );
    assert_eq!(receipt["generated_at"].as_str(), Some(GENERATED_AT));
    assert_eq!(receipt["current_date"].as_str(), Some("2026-05-08"));
    assert_eq!(command_ids(&receipt), vec!["rerun-cargo-test"]);
    assert_eq!(
        receipt["summary"]["safe_for_direct_main"].as_bool(),
        Some(true)
    );
    assert_eq!(receipt["commands"][0]["uses_rch"].as_bool(), Some(true));
    assert!(
        receipt["commands"][0]["shell_command"]
            .as_str()
            .expect("shell command")
            .contains("cargo test -p asupersync --test repro_region_lifecycle")
    );
}

#[test]
fn cargo_test_crashpack_matches_full_golden() {
    assert_output_matches_golden(
        "cargo_test_crashpack.json",
        "cargo_test_crashpack_expected.json",
    );
}

#[test]
fn fuzz_crashpack_generates_rch_fuzz_replay() {
    let receipt = generator_json("fuzz_crashpack.json");

    assert_eq!(command_ids(&receipt), vec!["rerun-fuzz-artifact"]);
    assert_eq!(receipt["commands"][0]["runs_cargo"].as_bool(), Some(true));
    assert_eq!(receipt["commands"][0]["uses_rch"].as_bool(), Some(true));
    assert!(
        receipt["commands"][0]["shell_command"]
            .as_str()
            .expect("shell command")
            .contains("cargo fuzz run fuzz_raptorq_decoder")
    );
}

#[test]
fn fuzz_crashpack_matches_full_golden() {
    assert_output_matches_golden("fuzz_crashpack.json", "fuzz_crashpack_expected.json");
}

#[test]
fn rch_wrapper_hang_keeps_remote_proof_and_retrieval_diagnostic_separate() {
    let receipt = generator_json("rch_wrapper_hang_after_remote_exit.json");

    assert_eq!(
        command_ids(&receipt),
        vec!["rerun-remote-proof", "classify-rch-retrieval"]
    );
    assert_eq!(receipt["commands"][0]["uses_rch"].as_bool(), Some(true));
    assert_eq!(receipt["commands"][1]["runs_cargo"].as_bool(), Some(false));
    assert!(
        receipt["commands"][1]["shell_command"]
            .as_str()
            .expect("shell command")
            .contains("scripts/rch_retrieval_receipt.py")
    );
}

#[test]
fn rch_wrapper_hang_matches_full_golden() {
    assert_output_matches_golden(
        "rch_wrapper_hang_after_remote_exit.json",
        "rch_wrapper_hang_after_remote_exit_expected.json",
    );
}

#[test]
fn proof_runner_blocker_generates_rch_contract_rerun() {
    let receipt = generator_json("proof_runner_blocker.json");

    assert_eq!(command_ids(&receipt), vec!["rerun-proof-runner-blocker"]);
    assert_eq!(receipt["commands"][0]["uses_rch"].as_bool(), Some(true));
    assert!(
        receipt["commands"][0]["shell_command"]
            .as_str()
            .expect("shell command")
            .contains("cargo test -p asupersync --test proof_console_report_contract")
    );
}

#[test]
fn proof_runner_blocker_matches_full_golden() {
    assert_output_matches_golden(
        "proof_runner_blocker.json",
        "proof_runner_blocker_expected.json",
    );
}

#[test]
fn existing_helpers_are_not_the_command_generator_extension_point() {
    let receipt = generator_json("cargo_test_crashpack.json");
    let considered = receipt["tool_selection"]["existing_helpers_considered"]
        .as_array()
        .expect("existing helper analysis");

    assert_eq!(
        receipt["tool_selection"]["new_tool_file_required"].as_bool(),
        Some(true)
    );
    assert!(
        considered.iter().any(|row| row["path"].as_str()
            == Some("scripts/rch_retrieval_receipt.py")
            && row["fit"].as_str() == Some("partial")),
        "analysis must record why the rch receipt helper is not enough"
    );
    assert!(
        considered
            .iter()
            .any(|row| row["path"].as_str() == Some("scripts/swarm_coordination_replay_pack.py")),
        "analysis must record the coordination replay helper decision"
    );
}
