//! Contract tests for the landed-but-open closeout receipt helper.

#![allow(missing_docs)]

use serde_json::Value;
use std::path::PathBuf;
use std::process::{Command, Output};

const SCRIPT_PATH: &str = "scripts/landed_but_open_receipt.py";
const FIXTURE_ROOT: &str = "tests/fixtures/landed_but_open_receipt";
const GENERATED_AT: &str = "2026-05-08T05:40:00Z";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn run_receipt(fixture: &str) -> Output {
    Command::new("python3")
        .arg(repo_root().join(SCRIPT_PATH))
        .arg("--fixture")
        .arg(repo_root().join(FIXTURE_ROOT).join(fixture))
        .arg("--repo-path")
        .arg(repo_root())
        .arg("--agent")
        .arg("CopperSpring")
        .arg("--generated-at")
        .arg(GENERATED_AT)
        .arg("--output")
        .arg("json")
        .current_dir(repo_root())
        .output()
        .expect("run landed-but-open receipt")
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
        .unwrap_or_else(|err| panic!("read fixture {fixture}: {err}"))
}

fn first_row(receipt: &Value) -> &Value {
    receipt["rows"]
        .as_array()
        .expect("rows must be an array")
        .first()
        .expect("fixture should contain a row")
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
fn landed_with_tracker_conflict_waits_for_closeout_window() {
    let receipt = receipt_json("landed_tracker_conflict.json");
    let row = first_row(&receipt);

    assert_eq!(
        receipt["schema_version"].as_str(),
        Some("landed-but-open-receipt-v1")
    );
    assert_eq!(receipt["current_date"].as_str(), Some("2026-05-08"));
    assert_eq!(row["id"].as_str(), Some("asupersync-aj7lx3.11"));
    assert_eq!(
        row["classification"].as_str(),
        Some("landed-awaiting-tracker")
    );
    assert_eq!(row["decision"].as_str(), Some("wait-for-tracker"));
    assert_eq!(row["proposed_action"]["allowed_now"].as_bool(), Some(false));
    assert_eq!(
        row["evidence"]["commit_hash"].as_str(),
        Some("17896bafc123")
    );
    assert_eq!(
        row["evidence"]["tracker_conflicts"][0]["holder"].as_str(),
        Some("VioletLark")
    );
    assert!(
        row["proposed_action"]["command"]
            .as_str()
            .expect("close command")
            .contains("br close asupersync-aj7lx3.11")
    );
}

#[test]
fn tracker_conflict_matches_full_output_golden() {
    let output = run_receipt("landed_tracker_conflict.json");
    assert!(
        output.status.success(),
        "receipt helper failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let actual = String::from_utf8(output.stdout).expect("receipt stdout must be UTF-8");
    let expected = fixture_text("landed_tracker_conflict_expected.json");

    let actual_json: Value = serde_json::from_str(&actual).expect("actual receipt JSON");
    let expected_json: Value = serde_json::from_str(&expected).expect("golden receipt JSON");
    assert_eq!(actual_json, expected_json, "parsed receipt JSON must match");
    assert_eq!(
        actual, expected,
        "landed-but-open tracker-conflict receipt changed; update the golden only after reviewing wait-for-tracker semantics"
    );
}

#[test]
fn landed_without_tracker_conflict_is_ready_to_close() {
    let receipt = receipt_json("ready_to_close.json");
    let row = first_row(&receipt);

    assert_eq!(row["classification"].as_str(), Some("ready-to-close"));
    assert_eq!(row["decision"].as_str(), Some("close-with-reservation"));
    assert_eq!(row["proposed_action"]["allowed_now"].as_bool(), Some(true));
    assert_eq!(
        receipt["summary"]["ready-to-close"].as_u64(),
        Some(1),
        "summary should count ready closeouts"
    );
}

#[test]
fn ready_to_close_matches_full_output_golden() {
    let output = run_receipt("ready_to_close.json");
    assert!(
        output.status.success(),
        "receipt helper failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let actual = String::from_utf8(output.stdout).expect("receipt stdout must be UTF-8");
    let expected = fixture_text("ready_to_close_expected.json");

    let actual_json: Value = serde_json::from_str(&actual).expect("actual receipt JSON");
    let expected_json: Value = serde_json::from_str(&expected).expect("golden receipt JSON");
    assert_eq!(actual_json, expected_json, "parsed receipt JSON must match");
    assert_eq!(
        actual, expected,
        "landed-but-open ready closeout receipt changed; update the golden only after reviewing closeout command and evidence semantics"
    );
}

#[test]
fn missing_proof_matches_full_output_golden() {
    let output = run_receipt("missing_proof.json");
    assert!(
        output.status.success(),
        "receipt helper failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let actual = String::from_utf8(output.stdout).expect("receipt stdout must be UTF-8");
    let expected = fixture_text("missing_proof_expected.json");

    let actual_json: Value = serde_json::from_str(&actual).expect("actual receipt JSON");
    let expected_json: Value = serde_json::from_str(&expected).expect("golden receipt JSON");
    assert_eq!(actual_json, expected_json, "parsed receipt JSON must match");
    assert_eq!(
        actual, expected,
        "landed-but-open missing-proof receipt changed; update the golden only after reviewing verification-before-close semantics"
    );
}

#[test]
fn commit_without_proof_stays_open_for_verification() {
    let receipt = receipt_json("missing_proof.json");
    let row = first_row(&receipt);

    assert_eq!(row["classification"].as_str(), Some("landed-missing-proof"));
    assert_eq!(row["decision"].as_str(), Some("verify-before-close"));
    assert_eq!(row["evidence"]["proof_line_count"].as_u64(), Some(0));
    assert_eq!(
        row["proposed_action"]["kind"].as_str(),
        Some("collect-proof")
    );
}

#[test]
fn no_commit_reference_is_not_landed() {
    let receipt = receipt_json("no_commit_reference.json");
    let row = first_row(&receipt);

    assert_eq!(row["classification"].as_str(), Some("not-landed"));
    assert_eq!(row["decision"].as_str(), Some("keep-open"));
    assert_eq!(row["evidence"]["commit_count"].as_u64(), Some(0));
}

#[test]
fn no_commit_reference_matches_full_output_golden() {
    let output = run_receipt("no_commit_reference.json");
    assert!(
        output.status.success(),
        "receipt helper failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let actual = String::from_utf8(output.stdout).expect("receipt stdout must be UTF-8");
    let expected = fixture_text("no_commit_reference_expected.json");

    let actual_json: Value = serde_json::from_str(&actual).expect("actual receipt JSON");
    let expected_json: Value = serde_json::from_str(&expected).expect("golden receipt JSON");
    assert_eq!(actual_json, expected_json, "parsed receipt JSON must match");
    assert_eq!(
        actual, expected,
        "landed-but-open no-commit receipt changed; update the golden only after reviewing keep-open semantics"
    );
}

#[test]
fn bead_id_filter_limits_rows() {
    let output = Command::new("python3")
        .arg(repo_root().join(SCRIPT_PATH))
        .arg("--fixture")
        .arg(repo_root().join(FIXTURE_ROOT).join("multi_issue.json"))
        .arg("--repo-path")
        .arg(repo_root())
        .arg("--agent")
        .arg("CopperSpring")
        .arg("--bead-id")
        .arg("asupersync-aj7lx3.11")
        .arg("--generated-at")
        .arg(GENERATED_AT)
        .arg("--output")
        .arg("json")
        .current_dir(repo_root())
        .output()
        .expect("run filtered receipt");
    assert!(output.status.success());
    let receipt: Value = serde_json::from_slice(&output.stdout).expect("JSON receipt");
    let rows = receipt["rows"].as_array().expect("rows array");

    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["id"].as_str(), Some("asupersync-aj7lx3.11"));
}

#[test]
fn receipt_declares_non_mutating_safety_contract() {
    let receipt = receipt_json("landed_tracker_conflict.json");

    assert_eq!(receipt["safety"]["non_mutating"].as_bool(), Some(true));
    for key in [
        "beads_mutated",
        "agent_mail_mutated",
        "git_mutated",
        "cargo_executed",
        "branch_or_worktree_operations",
        "files_deleted",
    ] {
        assert_eq!(
            receipt["safety"][key].as_bool(),
            Some(false),
            "{key} must stay false"
        );
    }
}
