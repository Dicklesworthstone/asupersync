//! Contract tests for the clean-overlay proof input planner helper.

#![allow(missing_docs)]

use serde_json::Value;
use std::path::PathBuf;
use std::process::{Command, Output};

const SCRIPT_PATH: &str = "scripts/clean_overlay_proof_planner.py";
const FIXTURE_ROOT: &str = "tests/fixtures/clean_overlay_proof_planner";
const GENERATED_AT: &str = "2026-06-14T23:00:00Z";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn run_planner(fixture: &str) -> Output {
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
        .expect("run clean-overlay proof planner")
}

fn planner_json(fixture: &str) -> Value {
    let output = run_planner(fixture);
    assert!(
        output.status.success(),
        "planner helper failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("planner output must be JSON")
}

fn fixture_text(fixture: &str) -> String {
    std::fs::read_to_string(repo_root().join(FIXTURE_ROOT).join(fixture))
        .unwrap_or_else(|error| panic!("read golden fixture {fixture}: {error}"))
}

fn assert_output_matches_golden(input_fixture: &str, expected_fixture: &str, label: &str) {
    let output = run_planner(input_fixture);
    assert!(
        output.status.success(),
        "planner helper failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let actual = String::from_utf8(output.stdout).expect("planner stdout is utf-8");
    let expected = fixture_text(expected_fixture);
    let actual_json: Value = serde_json::from_str(&actual).expect("actual JSON");
    let expected_json: Value = serde_json::from_str(&expected).expect("expected JSON");
    assert_eq!(
        actual_json, expected_json,
        "parsed JSON drifted for {label}"
    );
    assert_eq!(actual, expected, "reviewed golden drifted for {label}");
}

#[test]
fn script_exists_and_help_is_non_mutating() {
    assert!(
        repo_root().join(SCRIPT_PATH).exists(),
        "planner helper must exist at {SCRIPT_PATH}"
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
fn clean_tree_admits_selected_head_paths() {
    let receipt = planner_json("clean_tree.json");
    assert_eq!(
        receipt["schema_version"].as_str(),
        Some("clean-overlay-proof-planner-v1")
    );
    assert_eq!(
        receipt["decision"].as_str(),
        Some("admit-clean-overlay-proof")
    );
    assert_eq!(receipt["proof_allowed"].as_bool(), Some(true));
    assert_eq!(
        receipt["included_paths"][0]["path"].as_str(),
        Some("src/lib.rs")
    );
    assert_eq!(
        receipt["included_paths"][0]["overlay_source"].as_str(),
        Some("head")
    );
}

#[test]
fn clean_tree_output_matches_full_reviewed_golden() {
    assert_output_matches_golden(
        "clean_tree.json",
        "clean_tree_expected.json",
        "clean-tree clean-overlay manifest",
    );
}

#[test]
fn selected_dirty_file_requires_and_records_self_reservation() {
    let receipt = planner_json("selected_dirty_reserved.json");
    assert_eq!(receipt["proof_allowed"].as_bool(), Some(true));
    assert_eq!(
        receipt["included_paths"][0]["overlay_source"].as_str(),
        Some("worktree-dirty")
    );
    assert_eq!(
        receipt["included_paths"][0]["reservation_evidence"][0]["holder"].as_str(),
        Some("SapphireHill")
    );
}

#[test]
fn selected_untracked_file_is_admitted_only_with_self_reservation() {
    let receipt = planner_json("selected_untracked_reserved.json");
    assert_eq!(receipt["proof_allowed"].as_bool(), Some(true));
    assert_eq!(
        receipt["included_paths"][0]["status"].as_str(),
        Some("untracked")
    );
    assert_eq!(
        receipt["included_paths"][0]["overlay_source"].as_str(),
        Some("worktree-untracked")
    );
}

#[test]
fn selected_dirty_file_with_shared_reservation_fails_closed() {
    let receipt = planner_json("selected_dirty_shared_reservation.json");
    assert_eq!(receipt["proof_allowed"].as_bool(), Some(false));
    assert_eq!(receipt["decision"].as_str(), Some("fail-closed"));
    assert_eq!(
        receipt["blockers"][0]["kind"].as_str(),
        Some("selected-path-unreserved")
    );
    assert_eq!(receipt["included_paths"].as_array().map(Vec::len), Some(0));
}

#[test]
fn unreserved_dirty_file_fails_closed() {
    let receipt = planner_json("selected_dirty_unreserved.json");
    assert_eq!(receipt["proof_allowed"].as_bool(), Some(false));
    assert_eq!(receipt["decision"].as_str(), Some("fail-closed"));
    assert_eq!(
        receipt["blockers"][0]["kind"].as_str(),
        Some("selected-path-unreserved")
    );
}

#[test]
fn deleted_paths_are_refused_even_when_selected_and_reserved() {
    let receipt = planner_json("deleted_selected_reserved.json");
    assert_eq!(receipt["proof_allowed"].as_bool(), Some(false));
    assert_eq!(
        receipt["blockers"][0]["kind"].as_str(),
        Some("deleted-path-refused")
    );
}

#[test]
fn glob_and_dot_path_normalization_are_deterministic() {
    let receipt = planner_json("glob_normalization.json");
    assert_eq!(
        receipt["selected_paths"][0].as_str(),
        Some("tests/fixtures/clean_overlay_proof_planner/**")
    );
    assert_eq!(
        receipt["included_paths"][0]["path"].as_str(),
        Some("tests/fixtures/clean_overlay_proof_planner/new_case.json")
    );
}

#[test]
fn peer_dirty_outside_selection_is_excluded_and_blocks_default_proof() {
    let receipt = planner_json("peer_dirty_excluded.json");
    assert_eq!(receipt["proof_allowed"].as_bool(), Some(false));
    assert_eq!(
        receipt["excluded_dirty_paths"][0]["path"].as_str(),
        Some("src/grpc/client.rs")
    );
    assert_eq!(
        receipt["excluded_dirty_paths"][0]["reservation_evidence"][0]["holder"].as_str(),
        Some("SnowyFortress")
    );
    assert_eq!(
        receipt["blockers"][0]["kind"].as_str(),
        Some("unselected-dirty-path")
    );
}

#[test]
fn report_only_override_never_admits_proof() {
    let receipt = planner_json("report_only_peer_dirty.json");
    assert_eq!(receipt["decision"].as_str(), Some("report-only-dry-run"));
    assert_eq!(receipt["report_only"].as_bool(), Some(true));
    assert_eq!(receipt["proof_allowed"].as_bool(), Some(false));
    assert_eq!(receipt["summary"]["blocker_count"].as_u64(), Some(1));
}

#[test]
fn helper_declares_no_mutating_or_execution_actions() {
    let receipt = planner_json("selected_dirty_reserved.json");
    assert_eq!(receipt["non_mutating"].as_bool(), Some(true));
    for key in [
        "runs_cargo",
        "runs_rch",
        "runs_git_mutation",
        "runs_git_branch",
        "runs_git_worktree",
        "runs_destructive_command",
        "runs_agent_mail_mutation",
        "runs_beads_mutation",
    ] {
        assert_eq!(
            receipt["forbidden_actions"][key].as_bool(),
            Some(false),
            "{key} must remain false"
        );
    }
}
