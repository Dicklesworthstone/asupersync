//! Contract tests for the proof artifact freshness receipt helper.

#![allow(missing_docs)]

use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

const SCRIPT_PATH: &str = "scripts/proof_artifact_freshness_receipt.py";
const FIXTURE_ROOT: &str = "tests/fixtures/proof_artifact_freshness_receipt";
const GENERATED_AT: &str = "2026-05-08T05:20:00Z";

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
        .arg("TopazGoose")
        .arg("--generated-at")
        .arg(GENERATED_AT)
        .arg("--output")
        .arg("json")
        .current_dir(repo_root())
        .output()
        .expect("run proof artifact freshness receipt")
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

fn first_row(receipt: &Value) -> &Value {
    receipt["rows"]
        .as_array()
        .expect("rows must be array")
        .first()
        .expect("fixture should have at least one row")
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
fn current_clean_artifact_is_citeable() {
    let receipt = receipt_json("current_clean.json");
    let row = first_row(&receipt);

    assert_eq!(
        receipt["schema_version"].as_str(),
        Some("proof-artifact-freshness-receipt-v1")
    );
    assert_eq!(receipt["current_date"].as_str(), Some("2026-05-08"));
    assert_eq!(row["classification"].as_str(), Some("current-clean"));
    assert_eq!(row["decision"].as_str(), Some("cite-as-current"));
    assert_eq!(row["safe_to_cite"].as_bool(), Some(true));
    assert_eq!(receipt["summary"]["safe_to_cite"].as_u64(), Some(1));
}

#[test]
fn current_clean_matches_full_output_golden() {
    let output = run_receipt_with_repo_path("current_clean.json", "/repo");
    assert!(
        output.status.success(),
        "receipt helper failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let actual = String::from_utf8(output.stdout).expect("receipt stdout is utf-8");
    let actual_json: Value = serde_json::from_str(&actual).expect("actual receipt output JSON");
    let expected = fixture_text("current_clean_expected.json");
    let expected_json: Value =
        serde_json::from_str(&expected).expect("expected receipt output JSON");

    assert_eq!(actual_json, expected_json, "parsed receipt JSON must match");
    assert_eq!(actual, expected);
}

#[test]
fn superseded_head_is_suppressed_even_when_status_passed() {
    let receipt = receipt_json("superseded_head.json");
    let row = first_row(&receipt);

    assert_eq!(row["status"].as_str(), Some("pass"));
    assert_eq!(row["classification"].as_str(), Some("superseded-head"));
    assert_eq!(row["decision"].as_str(), Some("suppress-as-stale"));
    assert_eq!(row["safe_to_cite"].as_bool(), Some(false));
    assert_eq!(
        row["evidence"]["artifact_git_sha"].as_str(),
        Some("1111111111111111111111111111111111111111")
    );
    assert_eq!(
        row["evidence"]["current_head_sha"].as_str(),
        Some("2222222222222222222222222222222222222222")
    );
}

#[test]
fn non_main_artifact_branch_is_wrong_branch() {
    let receipt = receipt_json("wrong_branch.json");
    let row = first_row(&receipt);

    assert_eq!(row["classification"].as_str(), Some("wrong-branch"));
    assert_eq!(row["decision"].as_str(), Some("suppress-as-stale"));
    assert_eq!(
        row["reason"].as_str(),
        Some("artifact was produced on a non-main branch")
    );
}

#[test]
fn dirty_peer_surface_overlap_requires_rerun() {
    let receipt = receipt_json("dirty_surface_overlap.json");
    let row = first_row(&receipt);

    assert_eq!(
        row["classification"].as_str(),
        Some("dirty-surface-overlap")
    );
    assert_eq!(row["decision"].as_str(), Some("rerun-required"));
    assert_eq!(
        row["evidence"]["dirty_overlaps"][0]["owner"].as_str(),
        Some("CoralGorge")
    );
    assert_eq!(receipt["summary"]["rerun_required"].as_u64(), Some(1));
}

#[test]
fn missing_git_sha_is_unverifiable() {
    let receipt = receipt_json("missing_head.json");
    let row = first_row(&receipt);

    assert_eq!(row["classification"].as_str(), Some("unverifiable-head"));
    assert_eq!(row["decision"].as_str(), Some("suppress-as-unverifiable"));
    assert_eq!(receipt["summary"]["unverifiable"].as_u64(), Some(1));
}

#[test]
fn missing_touched_files_is_unverifiable_surface() {
    let receipt = receipt_json("missing_touched_files.json");
    let row = first_row(&receipt);

    assert_eq!(row["classification"].as_str(), Some("unverifiable-surface"));
    assert_eq!(row["decision"].as_str(), Some("suppress-as-unverifiable"));
}

#[test]
fn receipt_safety_contract_declares_read_only_behavior() {
    let receipt = receipt_json("current_clean.json");

    assert_eq!(receipt["safety"]["non_mutating"].as_bool(), Some(true));
    assert_eq!(
        receipt["safety"]["mutating_commands_executed"].as_bool(),
        Some(false)
    );
    assert_eq!(receipt["safety"]["beads_mutated"].as_bool(), Some(false));
    assert_eq!(receipt["safety"]["cargo_executed"].as_bool(), Some(false));
    assert_eq!(
        receipt["safety"]["branch_or_worktree_operations"].as_bool(),
        Some(false)
    );
    assert_eq!(
        receipt["safety"]["destructive_commands_executed"].as_bool(),
        Some(false)
    );
}

#[test]
fn receipt_has_required_top_level_shape() {
    let receipt = receipt_json("dirty_surface_overlap.json");
    for field in [
        "schema_version",
        "generated_at",
        "current_date",
        "agent",
        "repo_path",
        "current_head_sha",
        "current_branch",
        "rows",
        "summary",
        "safety",
    ] {
        assert!(receipt.get(field).is_some(), "receipt missing {field}");
    }
}
