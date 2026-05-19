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

fn run_receipt_with_command(
    fixture: &str,
    wrapper_exit_code: Option<i32>,
    receipt_command: &str,
    extra_args: &[&str],
) -> Output {
    let mut command = Command::new("python3");
    command
        .arg(repo_root().join(SCRIPT_PATH))
        .arg("--log")
        .arg(repo_root().join(FIXTURE_ROOT).join(fixture))
        .arg("--command")
        .arg(receipt_command)
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

fn receipt_json_with_command(
    fixture: &str,
    wrapper_exit_code: Option<i32>,
    receipt_command: &str,
    extra_args: &[&str],
) -> Value {
    let output = run_receipt_with_command(fixture, wrapper_exit_code, receipt_command, extra_args);
    receipt_from_output(output)
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
    assert_eq!(
        receipt["target_dir"].as_str(),
        Some("${TMPDIR:-/tmp}/rch_target_rch_retrieval_receipt_docs")
    );
    assert_eq!(receipt["guarantee"].as_str(), Some("unspecified"));
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
fn target_dir_auditor_passes_unique_remote_cargo_proof() {
    let receipt = receipt_json_with_args(
        "remote_success.log",
        None,
        &[
            "--audit-target-dir",
            "--active-target-dir",
            "/tmp/rch_target_other_agent",
        ],
    );

    assert_eq!(receipt["target_dir_audit"]["status"].as_str(), Some("pass"));
    assert_eq!(
        receipt["target_dir_audit"]["summary"]["blockers"].as_u64(),
        Some(0)
    );
    assert_eq!(
        receipt["target_dir_audit"]["summary"]["warnings"].as_u64(),
        Some(0)
    );
    assert_eq!(
        receipt["target_dir_audit"]["command_classification"]["runs_cargo"].as_bool(),
        Some(true)
    );
    assert_eq!(
        receipt["target_dir_audit"]["command_classification"]["runs_rch"].as_bool(),
        Some(true)
    );
    assert_eq!(
        receipt["target_dir_audit"]["command_classification"]["target_dir"].as_str(),
        Some("${TMPDIR:-/tmp}/rch_target_rch_retrieval_receipt_docs")
    );
}

#[test]
fn target_dir_auditor_blocks_cargo_without_target_dir() {
    let receipt = receipt_json_with_command(
        "remote_success.log",
        None,
        "rch exec -- cargo test --test proof_runner_contract -- --nocapture",
        &["--audit-target-dir"],
    );

    assert_eq!(
        receipt["target_dir_audit"]["status"].as_str(),
        Some("blocker")
    );
    assert!(
        receipt["target_dir_audit"]["findings"]
            .as_array()
            .expect("findings")
            .iter()
            .any(|finding| finding["code"].as_str() == Some("missing-cargo-target-dir"))
    );
}

#[test]
fn target_dir_auditor_warns_on_reused_concurrent_target_dir() {
    let receipt = receipt_json_with_args(
        "remote_success.log",
        None,
        &[
            "--audit-target-dir",
            "--active-target-dir",
            "${TMPDIR:-/tmp}/rch_target_rch_retrieval_receipt_docs",
        ],
    );

    assert_eq!(
        receipt["target_dir_audit"]["status"].as_str(),
        Some("warning")
    );
    assert!(
        receipt["target_dir_audit"]["findings"]
            .as_array()
            .expect("findings")
            .iter()
            .any(|finding| finding["code"].as_str() == Some("reused-target-dir"))
    );
}

#[test]
fn target_dir_auditor_blocks_local_fallback_markers() {
    let receipt = receipt_json_with_args("local_fallback.log", None, &["--audit-target-dir"]);

    assert_eq!(
        receipt["target_dir_audit"]["status"].as_str(),
        Some("blocker")
    );
    assert_eq!(
        receipt["target_dir_audit"]["command_classification"]["local_fallback"].as_bool(),
        Some(true)
    );
    assert!(
        receipt["target_dir_audit"]["findings"]
            .as_array()
            .expect("findings")
            .iter()
            .any(|finding| finding["code"].as_str() == Some("local-fallback-marker"))
    );
}

#[test]
fn target_dir_auditor_does_not_fail_non_cargo_local_checks() {
    let receipt = receipt_json_with_command(
        "remote_success.log",
        None,
        "git diff --check -- scripts/rch_retrieval_receipt.py",
        &["--audit-target-dir"],
    );

    assert_eq!(receipt["target_dir_audit"]["status"].as_str(), Some("pass"));
    assert_eq!(
        receipt["target_dir_audit"]["command_classification"]["runs_cargo"].as_bool(),
        Some(false)
    );
    assert_eq!(
        receipt["target_dir_audit"]["command_classification"]["target_dir"].as_str(),
        None
    );
}

#[test]
fn receipt_schema_records_target_dir_and_lane_guarantee() {
    let receipt = receipt_json_with_args(
        "remote_success.log",
        None,
        &[
            "--proof-lane",
            "bin-scoped-fuzz-smoke",
            "--guarantee",
            "bin-scoped fuzz target compiles and one-input smoke runs without panic",
        ],
    );

    assert_eq!(
        receipt["target_dir"].as_str(),
        Some("${TMPDIR:-/tmp}/rch_target_rch_retrieval_receipt_docs")
    );
    assert_eq!(
        receipt["guarantee"].as_str(),
        Some("bin-scoped fuzz target compiles and one-input smoke runs without panic")
    );
    assert_eq!(
        receipt["proof_lane"].as_str(),
        Some("bin-scoped-fuzz-smoke")
    );
    assert_eq!(receipt["markers"]["local_fallback"].as_bool(), Some(false));
    assert_eq!(receipt["markers"]["remote_exit_code"].as_i64(), Some(0));
    assert_eq!(
        receipt["markers"]["retrieval_completed"].as_bool(),
        Some(true)
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
fn interrupted_wrapper_without_remote_verdict_is_unknown() {
    let receipt = receipt_json("wrapper_interrupted.log", Some(143));

    assert_eq!(
        receipt["classification"].as_str(),
        Some("wrapper_interrupted")
    );
    assert_eq!(receipt["decision"].as_str(), Some("unknown-interrupted"));
    assert_eq!(receipt["markers"]["remote_exit_code"].as_i64(), None);
    assert_eq!(receipt["markers"]["remote_success"].as_bool(), Some(false));
    assert_eq!(receipt["markers"]["remote_failure"].as_bool(), Some(false));
    assert_eq!(receipt["markers"]["timeout_observed"].as_bool(), Some(true));
    assert!(
        receipt["remediation"]["operator_note"]
            .as_str()
            .expect("operator note")
            .contains("Do not infer pass or fail")
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
fn artifact_free_proof_receipt_covers_success_timeout_and_failure() {
    let success = receipt_json_with_args(
        "remote_success.log",
        None,
        &["--artifact-free-proof-receipt"],
    );
    let success_receipt = &success["artifact_free_proof_receipt"];
    assert_eq!(
        success_receipt["schema_version"].as_str(),
        Some("artifact-free-rch-proof-receipt-v1")
    );
    assert_eq!(success_receipt["command"].as_str(), Some(RECEIPT_COMMAND));
    assert_eq!(
        success_receipt["log_remote_command"].as_str(),
        Some("cargo test --test proof_runner_contract -- --nocapture")
    );
    assert_eq!(success_receipt["remote_exit_status"].as_i64(), Some(0));
    assert_eq!(success_receipt["remote_elapsed_ms"].as_u64(), Some(30_721));
    assert_eq!(
        success_receipt["artifact_status"].as_str(),
        Some("retrieved")
    );
    assert_eq!(
        success_receipt["artifact_retrieval"]["completed"].as_bool(),
        Some(true)
    );
    assert_eq!(
        success_receipt["artifact_retrieval"]["file_count"].as_u64(),
        Some(1_271)
    );
    assert_eq!(
        success_receipt["operator_decision"].as_str(),
        Some("cite-remote-proof")
    );
    assert_eq!(
        success_receipt["command_class"]["class"].as_str(),
        Some("rch-cargo-proof")
    );
    assert_eq!(
        success_receipt["command_class"]["target_dir_present"].as_bool(),
        Some(true)
    );
    assert_eq!(
        success_receipt["remote_required_status"]["status"].as_str(),
        Some("not-declared")
    );
    assert_eq!(
        success_receipt["first_blocker"]["kind"].as_str(),
        Some("none")
    );

    let retrieval_timeout = receipt_json_with_args(
        "passed_after_retrieval_timeout.log",
        Some(124),
        &["--artifact-free-proof-receipt"],
    );
    let timeout_receipt = &retrieval_timeout["artifact_free_proof_receipt"];
    assert_eq!(timeout_receipt["remote_exit_status"].as_i64(), Some(0));
    assert_eq!(
        timeout_receipt["decision"].as_str(),
        Some("pass-with-retrieval-blocker")
    );
    assert_eq!(
        timeout_receipt["artifact_status"].as_str(),
        Some("retrieval_failed")
    );
    assert_eq!(timeout_receipt["wrapper_exit_code"].as_i64(), Some(124));
    assert_eq!(
        timeout_receipt["artifact_retrieval"]["partial"].as_bool(),
        Some(true)
    );
    assert_eq!(
        timeout_receipt["operator_decision"].as_str(),
        Some("cite-remote-result-and-surface-retrieval-blocker")
    );
    assert_eq!(
        timeout_receipt["retrieval_blocker"]["kind"].as_str(),
        Some("wrapper-timeout")
    );
    assert_eq!(
        timeout_receipt["first_blocker"]["source"].as_str(),
        Some("artifact-retrieval")
    );

    let failure = receipt_json_with_args(
        "remote_failure.log",
        Some(101),
        &["--artifact-free-proof-receipt"],
    );
    let failure_receipt = &failure["artifact_free_proof_receipt"];
    assert_eq!(failure_receipt["remote_exit_status"].as_i64(), Some(101));
    assert_eq!(failure_receipt["remote_elapsed_ms"].as_u64(), Some(83_012));
    assert_eq!(failure_receipt["decision"].as_str(), Some("failed"));
    assert_eq!(
        failure_receipt["artifact_status"].as_str(),
        Some("not_requested")
    );
    assert_eq!(
        failure_receipt["selected_worker"].as_str(),
        Some("vmi1152480")
    );
    assert_eq!(
        failure_receipt["operator_decision"].as_str(),
        Some("surface-remote-failure")
    );
    assert_eq!(
        failure_receipt["first_blocker"]["kind"].as_str(),
        Some("remote-error")
    );
    assert_eq!(failure_receipt["first_blocker"]["line"].as_u64(), Some(2));
}

#[test]
fn artifact_free_proof_receipt_records_selected_worker_when_reported() {
    let receipt = receipt_json_with_args(
        "multistage_target_timeout.log",
        Some(124),
        &["--artifact-free-proof-receipt"],
    );
    let proof_receipt = &receipt["artifact_free_proof_receipt"];

    assert_eq!(
        proof_receipt["selected_worker"].as_str(),
        Some("vmi1153651")
    );
    assert_eq!(proof_receipt["remote_exit_status"].as_i64(), Some(0));
    assert_eq!(
        proof_receipt["artifact_status"].as_str(),
        Some("retrieval_failed")
    );
    assert!(
        proof_receipt["closeout_fields"]
            .as_array()
            .expect("closeout fields")
            .iter()
            .any(|field| field.as_str() == Some("selected_worker"))
    );
}

#[test]
fn artifact_free_proof_receipt_rejects_remote_required_local_fallback() {
    let remote_required_command = concat!(
        "RCH_REQUIRE_REMOTE=1 rch exec -- env ",
        "CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_rch_retrieval_receipt_docs ",
        "cargo test --test proof_runner_contract -- --nocapture"
    );
    let receipt = receipt_json_with_command(
        "local_fallback.log",
        None,
        remote_required_command,
        &["--artifact-free-proof-receipt"],
    );
    let proof_receipt = &receipt["artifact_free_proof_receipt"];

    assert_eq!(
        proof_receipt["classification"].as_str(),
        Some("local_fallback")
    );
    assert_eq!(
        proof_receipt["remote_required_status"]["status"].as_str(),
        Some("failed-local-fallback")
    );
    assert_eq!(
        proof_receipt["remote_required_status"]["local_fallback_refused"].as_bool(),
        Some(true)
    );
    assert_eq!(
        proof_receipt["local_fallback_refusal"]["refused_as_remote_proof"].as_bool(),
        Some(true)
    );
    assert_eq!(
        proof_receipt["operator_decision"].as_str(),
        Some("reject-local-fallback-rerun-remote")
    );
    assert_eq!(
        proof_receipt["first_blocker"]["file"].as_str(),
        Some("rch-local-fallback")
    );
    assert_eq!(
        proof_receipt["command_class"]["remote_required"].as_bool(),
        Some(true)
    );
    assert_eq!(
        proof_receipt["command_class"]["class"].as_str(),
        Some("rch-cargo-proof")
    );
}

#[test]
fn proof_lifecycle_contract_splits_remote_enospc_and_cleanup_authorization() {
    let receipt = receipt_json_with_args(
        "passed_after_retrieval_enospc.log",
        None,
        &[
            "--proof-lifecycle-contract",
            "--proof-lane",
            "rch-retrieval-lifecycle",
            "--guarantee",
            "remote fuzz smoke result is separated from local artifact retrieval",
            "--stale-target-candidate",
            "/tmp/rch_target_maroontrout_semaphore_fuzz",
        ],
    );
    let lifecycle = &receipt["proof_lifecycle_contract"];

    assert_eq!(
        lifecycle["schema_version"].as_str(),
        Some("proof-artifact-lifecycle-contract-v1")
    );
    assert_eq!(lifecycle["remote_result"]["status"].as_str(), Some("pass"));
    assert_eq!(lifecycle["remote_result"]["exit_code"].as_i64(), Some(0));
    assert_eq!(
        lifecycle["retrieval_result"]["status"].as_str(),
        Some("blocked")
    );
    assert_eq!(
        lifecycle["retrieval_result"]["blocker_kind"].as_str(),
        Some("local-disk-full")
    );
    assert_eq!(
        lifecycle["local_pressure"]["status"].as_str(),
        Some("critical")
    );
    assert_eq!(
        lifecycle["local_pressure"]["signal"].as_str(),
        Some("enospc")
    );
    assert_eq!(
        lifecycle["cleanup_authorization"]["status"].as_str(),
        Some("required")
    );
    assert_eq!(
        lifecycle["cleanup_authorization"]["authorized"].as_bool(),
        Some(false)
    );
    assert_eq!(
        lifecycle["cleanup_authorization"]["executable_cleanup_commands"]
            .as_array()
            .expect("cleanup commands must be array")
            .len(),
        0,
        "receipt must not emit executable deletion commands"
    );
    assert!(
        lifecycle["cleanup_authorization"]["stale_target_candidates"]
            .as_array()
            .expect("stale target candidates")
            .iter()
            .any(|candidate| candidate.as_str()
                == Some("/tmp/rch_target_maroontrout_semaphore_fuzz"))
    );
    assert!(
        lifecycle["closeout_template"]
            .as_str()
            .expect("closeout template")
            .contains("cleanup_authorization.authorized=false")
    );
}

#[test]
fn proof_lifecycle_contract_covers_remote_failure_without_retrieval() {
    let receipt = receipt_json_with_args(
        "remote_failure.log",
        Some(101),
        &["--proof-lifecycle-contract"],
    );
    let lifecycle = &receipt["proof_lifecycle_contract"];

    assert_eq!(lifecycle["remote_result"]["status"].as_str(), Some("fail"));
    assert_eq!(lifecycle["remote_result"]["exit_code"].as_i64(), Some(101));
    assert_eq!(
        lifecycle["retrieval_result"]["status"].as_str(),
        Some("not_requested")
    );
    assert_eq!(
        lifecycle["local_pressure"]["status"].as_str(),
        Some("unknown")
    );
    assert_eq!(
        lifecycle["cleanup_authorization"]["status"].as_str(),
        Some("not_required")
    );
    assert_eq!(
        lifecycle["cleanup_authorization"]["executable_cleanup_commands"]
            .as_array()
            .expect("cleanup commands must be array")
            .len(),
        0
    );
}

#[test]
fn proof_lifecycle_contract_covers_local_fallback_under_red_disk() {
    let receipt = receipt_json_with_args(
        "local_fallback_red_disk.log",
        None,
        &["--proof-lifecycle-contract"],
    );
    let lifecycle = &receipt["proof_lifecycle_contract"];

    assert_eq!(lifecycle["classification"].as_str(), Some("local_fallback"));
    assert_eq!(
        lifecycle["remote_result"]["status"].as_str(),
        Some("invalid")
    );
    assert_eq!(
        lifecycle["retrieval_result"]["status"].as_str(),
        Some("not_available")
    );
    assert_eq!(
        lifecycle["local_pressure"]["status"].as_str(),
        Some("critical")
    );
    assert_eq!(
        lifecycle["local_pressure"]["signal"].as_str(),
        Some("critical_pressure")
    );
    assert_eq!(
        lifecycle["cleanup_authorization"]["status"].as_str(),
        Some("required")
    );
    assert_eq!(
        lifecycle["cleanup_authorization"]["authorized"].as_bool(),
        Some(false)
    );
    assert!(
        lifecycle["closeout_template"]
            .as_str()
            .expect("closeout template")
            .contains("remote_result.status=invalid")
    );
}

#[test]
fn proof_lifecycle_contract_enospc_matches_full_output_golden() {
    let output = run_receipt_with_args(
        "passed_after_retrieval_enospc.log",
        None,
        &[
            "--proof-lifecycle-contract",
            "--proof-lane",
            "rch-retrieval-lifecycle",
            "--guarantee",
            "remote fuzz smoke result is separated from local artifact retrieval",
            "--stale-target-candidate",
            "/tmp/rch_target_maroontrout_semaphore_fuzz",
        ],
    );
    assert_output_matches_golden(
        output,
        "passed_after_retrieval_enospc_expected.json",
        "rch retrieval ENOSPC lifecycle receipt changed; update the golden only after reviewing cleanup authorization semantics",
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
