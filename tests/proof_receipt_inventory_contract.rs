//! Contract tests for the proof receipt inventory helper.

#![allow(missing_docs)]

use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

const SCRIPT_PATH: &str = "scripts/proof_receipt_inventory.py";
const FIXTURE_ROOT: &str = "tests/fixtures/proof_receipt_inventory";
const GENERATED_AT: &str = "2026-05-08T05:45:00Z";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn run_receipt(fixture: &str) -> Output {
    run_receipt_with_repo_path(fixture, repo_root().to_string_lossy().as_ref())
}

fn run_receipt_with_repo_path(fixture: &str, repo_path: &str) -> Output {
    Command::new("python3")
        .arg(repo_root().join(SCRIPT_PATH))
        .arg("--fixture")
        .arg(repo_root().join(FIXTURE_ROOT).join(fixture))
        .arg("--repo-path")
        .arg(repo_path)
        .arg("--agent")
        .arg("CoralGorge")
        .arg("--generated-at")
        .arg(GENERATED_AT)
        .arg("--output")
        .arg("json")
        .current_dir(repo_root())
        .output()
        .expect("run proof receipt inventory")
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
    fs::read_to_string(repo_root().join(FIXTURE_ROOT).join(fixture)).expect("read fixture text")
}

fn assert_output_matches_full_golden(
    input_fixture: &str,
    expected_fixture: &str,
    drift_message: &str,
) {
    let output = run_receipt_with_repo_path(input_fixture, "/repo");
    assert!(
        output.status.success(),
        "receipt helper failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let actual = String::from_utf8(output.stdout).expect("receipt stdout is utf-8");
    let actual_json: Value = serde_json::from_str(&actual).expect("actual receipt output JSON");
    let expected = fixture_text(expected_fixture);
    let expected_json: Value =
        serde_json::from_str(&expected).expect("expected receipt output JSON");

    assert_eq!(
        actual_json, expected_json,
        "parsed proof receipt inventory JSON drifted for {input_fixture} -> {expected_fixture}"
    );
    assert_eq!(actual, expected, "{drift_message}");
}

fn helpers(receipt: &Value) -> &Vec<Value> {
    receipt["helpers"]
        .as_array()
        .expect("helpers must be array")
}

fn helper<'a>(receipt: &'a Value, helper_id: &str) -> &'a Value {
    helpers(receipt)
        .iter()
        .find(|row| row["helper_id"].as_str() == Some(helper_id))
        .expect("helper row must exist")
}

#[test]
fn script_exists_and_help_is_non_mutating() {
    assert!(
        repo_root().join(SCRIPT_PATH).exists(),
        "helper must exist at {SCRIPT_PATH}"
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
fn inventory_marks_quarantine_helper_as_superseded_by_health_receipt() {
    let receipt = receipt_json("current_inventory.json");
    let row = helper(&receipt, "rch-worker-quarantine-receipt");

    assert_eq!(
        receipt["schema_version"].as_str(),
        Some("proof-receipt-inventory-v1")
    );
    assert_eq!(receipt["generated_at"].as_str(), Some(GENERATED_AT));
    assert_eq!(receipt["current_date"].as_str(), Some("2026-05-08"));
    assert_eq!(row["classification"].as_str(), Some("superseded"));
    assert_eq!(
        row["superseded_by"].as_str(),
        Some("rch-worker-health-receipt")
    );
    assert_eq!(receipt["source_counts"]["helpers"].as_u64(), Some(3));
    assert_eq!(
        receipt["source_counts"]["superseded_helpers"].as_u64(),
        Some(1)
    );

    let cues = receipt["review_cues"].as_array().expect("review cues");
    assert!(cues.iter().any(|cue| {
        cue["kind"].as_str() == Some("superseded-helper")
            && cue["helper_id"].as_str() == Some("rch-worker-quarantine-receipt")
    }));
}

#[test]
fn duplicate_current_helpers_emit_capability_overlap_cue() {
    let receipt = receipt_json("duplicate_current.json");

    assert_eq!(
        receipt["source_counts"]["duplicate_capabilities"].as_u64(),
        Some(1)
    );
    assert_eq!(
        receipt["classification_counts"]["duplicate-capability"].as_u64(),
        Some(1)
    );

    let cues = receipt["review_cues"].as_array().expect("review cues");
    assert!(cues.iter().any(|cue| {
        cue["kind"].as_str() == Some("capability-overlap")
            && cue["capability_id"].as_str() == Some("artifact-freshness")
    }));
}

#[test]
fn duplicate_current_matches_full_output_golden() {
    assert_output_matches_full_golden(
        "duplicate_current.json",
        "duplicate_current_expected.json",
        "proof receipt inventory duplicate-current golden changed; update only after reviewing capability-overlap semantics",
    );
}

#[test]
fn covered_draft_helpers_emit_review_cue_instead_of_canonical_status() {
    let receipt = receipt_json("covered_draft.json");
    let row = helper(&receipt, "proof-runner-execute-receipt-draft");

    assert_eq!(row["classification"].as_str(), Some("draft"));
    assert_eq!(receipt["classification_counts"]["draft"].as_u64(), Some(1));

    let cues = receipt["review_cues"].as_array().expect("review cues");
    assert!(cues.iter().any(|cue| {
        cue["kind"].as_str() == Some("draft-helper")
            && cue["helper_id"].as_str() == Some("proof-runner-execute-receipt-draft")
    }));
}

#[test]
fn covered_draft_matches_full_output_golden() {
    assert_output_matches_full_golden(
        "covered_draft.json",
        "covered_draft_expected.json",
        "proof receipt inventory covered-draft golden changed; update only after reviewing draft-helper actionability semantics",
    );
}

#[test]
fn missing_contract_and_fixture_are_actionable() {
    let receipt = receipt_json("redaction_and_missing_contract.json");
    let row = helper(&receipt, "operator-token-audit-receipt");

    assert_eq!(
        row["classification"].as_str(),
        Some("missing-contract-test")
    );
    let cues = receipt["review_cues"].as_array().expect("review cues");
    assert!(cues.iter().any(|cue| {
        cue["kind"].as_str() == Some("missing-contract-test")
            && cue["helper_id"].as_str() == Some("operator-token-audit-receipt")
    }));
}

#[test]
fn redaction_and_missing_contract_matches_full_output_golden() {
    assert_output_matches_full_golden(
        "redaction_and_missing_contract.json",
        "redaction_and_missing_contract_expected.json",
        "proof receipt inventory redaction/missing-contract golden changed; update only after reviewing redaction and actionability semantics",
    );
}

#[test]
fn secret_and_query_text_is_redacted() {
    let receipt = receipt_json("redaction_and_missing_contract.json");
    let serialized = serde_json::to_string(&receipt).expect("serialize receipt");

    assert!(!serialized.contains("sk-live-this-should-not-leak"));
    assert!(!serialized.contains("token=abc123"));
    assert!(!serialized.contains("sig=secret"));
    assert!(serialized.contains("[REDACTED_SECRET]"));
    assert!(serialized.contains("[REDACTED_QUERY]"));
    assert!(
        receipt["redaction_counts"]["secret"].as_u64().unwrap_or(0) >= 1,
        "expected at least one secret redaction"
    );
    assert!(
        receipt["redaction_counts"]["url_query"]
            .as_u64()
            .unwrap_or(0)
            >= 1,
        "expected at least one query-string redaction"
    );
}

#[test]
fn output_is_deterministic_for_same_fixture_and_timestamp() {
    let first = run_receipt("current_inventory.json");
    let second = run_receipt("current_inventory.json");

    assert!(first.status.success());
    assert!(second.status.success());
    assert_eq!(first.stdout, second.stdout);
}

#[test]
fn current_inventory_matches_full_output_golden() {
    assert_output_matches_full_golden(
        "current_inventory.json",
        "current_inventory_expected.json",
        "proof receipt inventory current-inventory golden changed; update only after reviewing superseded-helper and source-count semantics",
    );
}

#[test]
fn receipt_declares_read_only_safety_contract() {
    let receipt = receipt_json("current_inventory.json");

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
