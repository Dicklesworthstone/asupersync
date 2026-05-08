//! Contract tests for the rch artifact retrieval receipt helper.

#![allow(missing_docs)]

use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

const SCRIPT_PATH: &str = "scripts/rch_retrieval_receipt.py";
const FIXTURE_ROOT: &str = "tests/fixtures/rch_retrieval_receipt";
const GENERATED_AT: &str = "2026-05-08T05:10:00Z";
const RECEIPT_COMMAND: &str = "rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_rch_retrieval_receipt_docs cargo test --test proof_runner_contract -- --nocapture";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn run_receipt(fixture: &str, wrapper_exit_code: Option<i32>) -> Output {
    run_receipt_with_args(fixture, wrapper_exit_code, &[])
}

fn run_receipt_with_args(
    fixture: &str,
    wrapper_exit_code: Option<i32>,
    extra_args: &[&str],
) -> Output {
    let mut command = Command::new("python3");
    command
        .arg(repo_root().join(SCRIPT_PATH))
        .arg("--log")
        .arg(repo_root().join(FIXTURE_ROOT).join(fixture))
        .arg("--command")
        .arg(RECEIPT_COMMAND)
        .arg("--generated-at")
        .arg(GENERATED_AT)
        .arg("--output")
        .arg("json")
        .current_dir(repo_root());
    command.args(extra_args);
    if let Some(code) = wrapper_exit_code {
        command.arg("--wrapper-exit-code").arg(code.to_string());
    }
    command.output().expect("run rch retrieval receipt script")
}

fn receipt_json(fixture: &str, wrapper_exit_code: Option<i32>) -> Value {
    let output = run_receipt(fixture, wrapper_exit_code);
    receipt_from_output(output)
}

fn receipt_json_with_args(
    fixture: &str,
    wrapper_exit_code: Option<i32>,
    extra_args: &[&str],
) -> Value {
    let output = run_receipt_with_args(fixture, wrapper_exit_code, extra_args);
    receipt_from_output(output)
}

fn receipt_from_output(output: Output) -> Value {
    let text = receipt_text_from_output(output);
    serde_json::from_str(&text).expect("receipt output must be JSON")
}

fn receipt_text_from_output(output: Output) -> String {
    assert!(
        output.status.success(),
        "receipt helper failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("receipt output must be UTF-8")
}

fn fixture_text(fixture: &str) -> String {
    fs::read_to_string(repo_root().join(FIXTURE_ROOT).join(fixture)).expect("read fixture text")
}

fn assert_output_matches_golden(output: Output, expected_fixture: &str, drift_message: &str) {
    let actual = receipt_text_from_output(output);
    let expected = fixture_text(expected_fixture);

    assert_json_text_eq(&actual, &expected, expected_fixture, drift_message);
}

fn assert_json_text_eq(actual: &str, expected: &str, expected_fixture: &str, drift_message: &str) {
    let actual_json: Value = serde_json::from_str(actual)
        .unwrap_or_else(|err| panic!("actual receipt output JSON for {expected_fixture}: {err}"));
    let expected_json: Value = serde_json::from_str(expected).unwrap_or_else(|err| {
        panic!("expected receipt fixture {expected_fixture} must be JSON: {err}")
    });

    assert_eq!(
        actual_json, expected_json,
        "parsed rch retrieval receipt JSON drifted from {expected_fixture}; {drift_message}"
    );
    assert_eq!(actual, expected, "{drift_message}");
}

#[test]
fn receipt_command_routes_cargo_through_target_dir() {
    let stale_command = concat!(
        "rch exec -- ",
        "cargo test --test proof_runner_contract -- --nocapture"
    );

    assert!(RECEIPT_COMMAND.starts_with("rch exec -- env "));
    assert!(RECEIPT_COMMAND.contains("CARGO_TARGET_DIR="));
    assert!(!RECEIPT_COMMAND.contains(stale_command));
}

#[test]
fn script_exists_and_help_is_non_mutating() {
    assert!(
        repo_root().join(SCRIPT_PATH).exists(),
        "receipt helper must exist at {SCRIPT_PATH}"
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
fn completed_artifact_retrieval_is_clean_remote_success() {
    let receipt = receipt_json("remote_success.log", None);

    assert_eq!(
        receipt["schema_version"].as_str(),
        Some("rch-retrieval-receipt-v1")
    );
    assert_eq!(receipt["generated_at"].as_str(), Some(GENERATED_AT));
    assert_eq!(receipt["current_date"].as_str(), Some("2026-05-08"));
    assert_eq!(receipt["classification"].as_str(), Some("remote_success"));
    assert_eq!(receipt["decision"].as_str(), Some("passed"));
    assert_eq!(receipt["markers"]["remote_exit_code"].as_i64(), Some(0));
    assert_eq!(
        receipt["markers"]["retrieval_completed"].as_bool(),
        Some(true)
    );
    assert_eq!(
        receipt["markers"]["retrieval_elapsed_ms"].as_u64(),
        Some(2326)
    );
    assert_eq!(
        receipt["markers"]["artifact_file_count"].as_u64(),
        Some(1271)
    );
    assert_eq!(receipt["markers"]["artifact_bytes"].as_u64(), Some(356));
    assert_eq!(
        receipt["artifact_budget"]["status"].as_str(),
        Some("not-configured")
    );
}

#[test]
fn remote_success_matches_full_output_golden() {
    let output = run_receipt("remote_success.log", None);
    assert_output_matches_golden(
        output,
        "remote_success_expected.json",
        "rch retrieval remote-success receipt changed; update the golden only after reviewing clean remote proof semantics",
    );
}

#[test]
fn remote_pass_then_retrieval_timeout_is_split_verdict() {
    let receipt = receipt_json("passed_after_retrieval_timeout.log", Some(124));

    assert_eq!(
        receipt["classification"].as_str(),
        Some("passed_after_retrieval_timeout")
    );
    assert_eq!(
        receipt["decision"].as_str(),
        Some("pass-with-retrieval-blocker")
    );
    assert_eq!(receipt["markers"]["remote_success"].as_bool(), Some(true));
    assert_eq!(
        receipt["markers"]["retrieval_started"].as_bool(),
        Some(true)
    );
    assert_eq!(
        receipt["markers"]["retrieval_completed"].as_bool(),
        Some(false)
    );
    assert_eq!(receipt["markers"]["timeout_observed"].as_bool(), Some(true));
    assert!(
        receipt["remediation"]["operator_note"]
            .as_str()
            .expect("operator note")
            .contains("remote command as passed only when the remote success marker is present")
    );
    assert_eq!(
        receipt["artifact_budget"]["status"].as_str(),
        Some("not-configured")
    );
}

#[test]
fn remote_pass_then_retrieval_timeout_matches_full_output_golden() {
    let output = run_receipt("passed_after_retrieval_timeout.log", Some(124));
    assert_output_matches_golden(
        output,
        "passed_after_retrieval_timeout_expected.json",
        "rch retrieval timeout receipt changed; update the golden only after reviewing pass-with-retrieval-blocker semantics",
    );
}

#[test]
fn multistage_target_retrieval_timeout_is_not_clean_success() {
    let receipt = receipt_json_with_args(
        "multistage_target_timeout.log",
        Some(124),
        &[
            "--proof-lane",
            "rch-retrieval-budget",
            "--max-retrieval-ms",
            "3000",
            "--max-artifact-files",
            "2000",
        ],
    );

    assert_eq!(
        receipt["classification"].as_str(),
        Some("passed_after_retrieval_timeout")
    );
    assert_eq!(
        receipt["decision"].as_str(),
        Some("pass-with-retrieval-blocker")
    );
    assert_eq!(
        receipt["markers"]["retrieval_stage_count"].as_u64(),
        Some(2)
    );
    assert_eq!(
        receipt["markers"]["retrieval_completed_count"].as_u64(),
        Some(1)
    );
    assert_eq!(
        receipt["markers"]["retrieval_completed"].as_bool(),
        Some(false)
    );
    assert_eq!(
        receipt["markers"]["retrieval_partial"].as_bool(),
        Some(true)
    );
    assert_eq!(
        receipt["markers"]["retrieval_elapsed_ms"].as_u64(),
        Some(2826)
    );
    assert_eq!(
        receipt["markers"]["artifact_file_count"].as_u64(),
        Some(1536)
    );
    assert_eq!(
        receipt["artifact_budget"]["status"].as_str(),
        Some("retrieval-incomplete")
    );
}

#[test]
fn multistage_target_retrieval_matches_full_output_golden() {
    let output = run_receipt_with_args(
        "multistage_target_timeout.log",
        Some(124),
        &[
            "--proof-lane",
            "rch-retrieval-budget",
            "--max-retrieval-ms",
            "3000",
            "--max-artifact-files",
            "2000",
        ],
    );
    assert_output_matches_golden(
        output,
        "multistage_target_timeout_expected.json",
        "rch retrieval multi-stage timeout receipt changed; update the golden only after reviewing partial retrieval and artifact-budget semantics",
    );
}

#[test]
fn completed_retrieval_reports_artifact_budget_warnings_by_lane() {
    let receipt = receipt_json_with_args(
        "remote_success.log",
        None,
        &[
            "--proof-lane",
            "proof-runner-contract",
            "--max-retrieval-ms",
            "1000",
            "--max-artifact-files",
            "1000",
            "--max-artifact-bytes",
            "128",
        ],
    );

    assert_eq!(receipt["classification"].as_str(), Some("remote_success"));
    assert_eq!(
        receipt["decision"].as_str(),
        Some("passed-with-artifact-budget-warning")
    );
    assert_eq!(
        receipt["proof_lane"].as_str(),
        Some("proof-runner-contract")
    );
    assert_eq!(
        receipt["artifact_budget"]["proof_lane"].as_str(),
        Some("proof-runner-contract")
    );
    assert_eq!(
        receipt["artifact_budget"]["status"].as_str(),
        Some("over-budget")
    );
    assert_eq!(
        receipt["artifact_budget"]["within_budget"].as_bool(),
        Some(false)
    );
    let violation_metrics: Vec<&str> = receipt["artifact_budget"]["violations"]
        .as_array()
        .expect("violations")
        .iter()
        .filter_map(|row| row["metric"].as_str())
        .collect();
    assert!(violation_metrics.contains(&"retrieval_elapsed_ms"));
    assert!(violation_metrics.contains(&"artifact_file_count"));
    assert!(violation_metrics.contains(&"artifact_bytes"));
    assert!(
        receipt["artifact_budget"]["rchignore_remediation"]["recommended_patterns"]
            .as_array()
            .expect("patterns")
            .iter()
            .any(|value| value.as_str() == Some(".rch-*/"))
    );
}

#[test]
fn incomplete_retrieval_reports_budget_blocker_and_rchignore_guidance() {
    let receipt = receipt_json_with_args(
        "passed_after_retrieval_timeout.log",
        Some(124),
        &[
            "--proof-lane",
            "proof-runner-contract",
            "--max-retrieval-ms",
            "1000",
            "--max-artifact-files",
            "1000",
        ],
    );

    assert_eq!(
        receipt["classification"].as_str(),
        Some("passed_after_retrieval_timeout")
    );
    assert_eq!(
        receipt["artifact_budget"]["status"].as_str(),
        Some("retrieval-incomplete")
    );
    assert_eq!(
        receipt["artifact_budget"]["within_budget"].as_bool(),
        Some(false)
    );
    assert!(
        receipt["artifact_budget"]["violations"]
            .as_array()
            .expect("violations")
            .iter()
            .any(|row| row["reason"].as_str() == Some("retrieval-timeout-or-incomplete"))
    );
    assert!(
        receipt["artifact_budget"]["rchignore_remediation"]["operator_note"]
            .as_str()
            .expect("operator note")
            .contains("CARGO_TARGET_DIR")
    );
}

#[test]
fn remote_failure_is_not_treated_as_green_proof() {
    let receipt = receipt_json("remote_failure.log", Some(101));

    assert_eq!(receipt["classification"].as_str(), Some("remote_failure"));
    assert_eq!(receipt["decision"].as_str(), Some("failed"));
    assert_eq!(receipt["markers"]["remote_exit_code"].as_i64(), Some(101));
    assert_eq!(receipt["markers"]["remote_failure"].as_bool(), Some(true));
    assert!(
        receipt["remediation"]["operator_note"]
            .as_str()
            .expect("operator note")
            .contains("Do not treat this as a green proof")
    );
}

#[test]
fn remote_failure_matches_full_output_golden() {
    let output = run_receipt("remote_failure.log", Some(101));
    assert_output_matches_golden(
        output,
        "remote_failure_expected.json",
        "rch retrieval remote-failure receipt changed; update the golden only after reviewing failed proof semantics",
    );
}

#[test]
fn local_fallback_invalidates_captured_cargo_output() {
    let receipt = receipt_json("local_fallback.log", None);

    assert_eq!(receipt["classification"].as_str(), Some("local_fallback"));
    assert_eq!(receipt["decision"].as_str(), Some("invalid"));
    assert_eq!(receipt["markers"]["local_fallback"].as_bool(), Some(true));
    assert!(
        receipt["remediation"]["operator_note"]
            .as_str()
            .expect("operator note")
            .contains("Reject local cargo/test output")
    );
}

#[test]
fn local_fallback_matches_full_output_golden() {
    let output = run_receipt("local_fallback.log", None);
    assert_output_matches_golden(
        output,
        "local_fallback_expected.json",
        "rch retrieval local-fallback receipt changed; update the golden only after reviewing invalid local cargo output semantics",
    );
}

#[test]
fn helper_declares_it_does_not_run_mutating_commands() {
    let receipt = receipt_json("passed_after_retrieval_timeout.log", Some(124));

    assert_eq!(receipt["non_mutating"].as_bool(), Some(true));
    for key in [
        "runs_cargo",
        "runs_git_mutation",
        "runs_beads_mutation",
        "runs_destructive_command",
    ] {
        assert_eq!(
            receipt["forbidden_actions"][key].as_bool(),
            Some(false),
            "{key} must stay false"
        );
    }
}
