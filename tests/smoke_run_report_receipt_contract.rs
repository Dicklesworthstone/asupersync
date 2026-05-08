//! Contract tests for the smoke run report receipt helper.

#![allow(missing_docs)]

use serde_json::Value;
use std::path::PathBuf;
use std::process::{Command, Output};

const SCRIPT_PATH: &str = "scripts/smoke_run_report_receipt.py";
const FIXTURE_ROOT: &str = "tests/fixtures/smoke_run_report_receipt";
const GENERATED_AT: &str = "2026-05-08T05:55:00Z";
const REQUIRED: &[&str] = &["AFA-SMOKE-ABUSE", "AFA-SMOKE-REVOCATION", "AFA-SMOKE-AUDIT"];

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn run_receipt(fixture: &str) -> Output {
    let mut command = Command::new("python3");
    command
        .arg(repo_root().join(SCRIPT_PATH))
        .arg("--fixture")
        .arg(repo_root().join(FIXTURE_ROOT).join(fixture))
        .arg("--agent")
        .arg("CopperSpring")
        .arg("--generated-at")
        .arg(GENERATED_AT);
    for scenario in REQUIRED {
        command.arg("--required-scenario").arg(scenario);
    }
    command
        .current_dir(repo_root())
        .output()
        .expect("run smoke report receipt")
}

fn receipt_json(fixture: &str) -> Value {
    let output = run_receipt(fixture);
    assert!(
        output.status.success(),
        "receipt helper failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("receipt output must be JSON")
}

fn fixture_text(fixture: &str) -> String {
    std::fs::read_to_string(repo_root().join(FIXTURE_ROOT).join(fixture))
        .unwrap_or_else(|error| panic!("read golden fixture {fixture}: {error}"))
}

fn assert_output_matches_golden(input_fixture: &str, expected_fixture: &str, drift_message: &str) {
    let output = run_receipt(input_fixture);
    assert!(
        output.status.success(),
        "receipt helper failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let actual = String::from_utf8(output.stdout).expect("receipt stdout is utf-8");
    let expected = fixture_text(expected_fixture);
    let actual_json: Value = serde_json::from_str(&actual).expect("actual receipt JSON");
    let expected_json: Value = serde_json::from_str(&expected).expect("golden receipt JSON");
    assert_eq!(actual_json, expected_json);
    assert_eq!(actual, expected, "{drift_message}");
}

fn cues(receipt: &Value) -> &Vec<Value> {
    receipt["review_cues"]
        .as_array()
        .expect("review_cues must be array")
}

#[test]
fn executed_success_output_matches_full_reviewed_golden() {
    assert_output_matches_golden(
        "executed_success.json",
        "executed_success_expected.json",
        "executed smoke run report receipt drifted from the reviewed golden",
    );
}

#[test]
fn dry_run_plan_output_matches_full_reviewed_golden() {
    assert_output_matches_golden(
        "dry_run_plan.json",
        "dry_run_plan_expected.json",
        "dry-run smoke report receipt drifted from the reviewed golden",
    );
}

#[test]
fn local_fallback_failure_output_matches_full_reviewed_golden() {
    assert_output_matches_golden(
        "local_fallback_failure.json",
        "local_fallback_failure_expected.json",
        "local-fallback smoke report receipt drifted from the reviewed golden",
    );
}

#[test]
fn missing_required_output_matches_full_reviewed_golden() {
    assert_output_matches_golden(
        "missing_required_scenario.json",
        "missing_required_scenario_expected.json",
        "missing-required smoke report receipt drifted from the reviewed golden",
    );
}

#[test]
fn executed_success_report_is_complete_proof() {
    let receipt = receipt_json("executed_success.json");

    assert_eq!(
        receipt["schema_version"].as_str(),
        Some("smoke-run-report-receipt-v1")
    );
    assert_eq!(receipt["generated_at"].as_str(), Some(GENERATED_AT));
    assert_eq!(receipt["agent"].as_str(), Some("CopperSpring"));
    assert_eq!(receipt["verdict"].as_str(), Some("executed-proof-complete"));
    assert_eq!(receipt["source_counts"]["scenarios"].as_u64(), Some(3));
    assert_eq!(
        receipt["source_counts"]["missing_required_scenarios"].as_u64(),
        Some(0)
    );
    assert_eq!(
        receipt["classification_counts"]["executed-pass"].as_u64(),
        Some(3)
    );
    assert!(
        cues(&receipt).is_empty(),
        "complete proof must have no cues"
    );
}

#[test]
fn dry_run_report_is_plan_only_not_execution_proof() {
    let receipt = receipt_json("dry_run_plan.json");

    assert_eq!(receipt["dry_run"].as_bool(), Some(true));
    assert_eq!(receipt["verdict"].as_str(), Some("dry-run-plan-only"));
    assert_eq!(
        receipt["classification_counts"]["dry-run-only"].as_u64(),
        Some(3)
    );
    assert!(cues(&receipt).iter().any(|cue| {
        cue["kind"].as_str() == Some("dry-run-only")
            && cue["scenario_id"].as_str() == Some("AFA-SMOKE-AUDIT")
    }));
}

#[test]
fn local_fallback_is_blocker_and_redacted() {
    let receipt = receipt_json("local_fallback_failure.json");
    let serialized = serde_json::to_string(&receipt).expect("serialize receipt");

    assert_eq!(receipt["verdict"].as_str(), Some("blocked"));
    assert_eq!(
        receipt["classification_counts"]["local-fallback-failed"].as_u64(),
        Some(1)
    );
    assert!(cues(&receipt).iter().any(|cue| {
        cue["kind"].as_str() == Some("local-fallback")
            && cue["scenario_id"].as_str() == Some("AFA-SMOKE-REVOCATION")
    }));
    assert!(!serialized.contains("token=abc123"));
    assert!(!serialized.contains("Bearer secret-token-value"));
    assert!(serialized.contains("[REDACTED_QUERY]"));
    assert!(serialized.contains("[REDACTED_TOKEN]"));
    assert!(serialized.contains("[REDACTED_SECRET]"));
}

#[test]
fn missing_required_scenario_blocks_closeout() {
    let receipt = receipt_json("missing_required_scenario.json");

    assert_eq!(receipt["verdict"].as_str(), Some("blocked"));
    assert_eq!(
        receipt["classification_counts"]["missing-required-scenario"].as_u64(),
        Some(1)
    );
    assert_eq!(
        receipt["missing_required_scenarios"][0].as_str(),
        Some("AFA-SMOKE-AUDIT")
    );
    assert!(cues(&receipt).iter().any(|cue| {
        cue["kind"].as_str() == Some("missing-required-scenario")
            && cue["severity"].as_str() == Some("blocker")
    }));
}

#[test]
fn output_is_deterministic_for_same_fixture_and_timestamp() {
    let first = run_receipt("executed_success.json");
    let second = run_receipt("executed_success.json");

    assert!(first.status.success());
    assert!(second.status.success());
    assert_eq!(first.stdout, second.stdout);
}

#[test]
fn receipt_declares_read_only_safety_contract() {
    let receipt = receipt_json("executed_success.json");

    for key in [
        "non_mutating",
        "reads_fixture_only",
        "agent_mail_mutated",
        "beads_mutated",
        "git_mutated",
        "cargo_executed",
        "branch_or_worktree_operations",
        "files_deleted",
        "live_probe_performed",
    ] {
        let expected = matches!(key, "non_mutating" | "reads_fixture_only");
        assert_eq!(
            receipt["safety"][key].as_bool(),
            Some(expected),
            "{key} safety flag mismatch"
        );
    }
}
