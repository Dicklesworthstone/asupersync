//! Contract tests for the rch artifact retrieval receipt helper.

#![allow(missing_docs)]

use serde_json::Value;
use std::path::PathBuf;
use std::process::{Command, Output};

const SCRIPT_PATH: &str = "scripts/rch_retrieval_receipt.py";
const FIXTURE_ROOT: &str = "tests/fixtures/rch_retrieval_receipt";
const GENERATED_AT: &str = "2026-05-08T05:10:00Z";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn run_receipt(fixture: &str, wrapper_exit_code: Option<i32>) -> Output {
    let mut command = Command::new("python3");
    command
        .arg(repo_root().join(SCRIPT_PATH))
        .arg("--log")
        .arg(repo_root().join(FIXTURE_ROOT).join(fixture))
        .arg("--command")
        .arg("rch exec -- cargo test --test proof_runner_contract -- --nocapture")
        .arg("--generated-at")
        .arg(GENERATED_AT)
        .arg("--output")
        .arg("json")
        .current_dir(repo_root());
    if let Some(code) = wrapper_exit_code {
        command.arg("--wrapper-exit-code").arg(code.to_string());
    }
    command.output().expect("run rch retrieval receipt script")
}

fn receipt_json(fixture: &str, wrapper_exit_code: Option<i32>) -> Value {
    let output = run_receipt(fixture, wrapper_exit_code);
    assert!(
        output.status.success(),
        "receipt helper failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("receipt output must be JSON")
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
