//! Contract tests for the touched-surface proof selector helper.

#![allow(missing_docs)]

use serde_json::Value;
use std::path::PathBuf;
use std::process::{Command, Output};

const SCRIPT_PATH: &str = "scripts/touched_surface_proof_selector.py";
const FIXTURE_ROOT: &str = "tests/fixtures/touched_surface_proof_selector";
const GENERATED_AT: &str = "2026-05-08T06:00:00Z";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn run_selector(fixture: &str) -> Output {
    Command::new("python3")
        .arg(repo_root().join(SCRIPT_PATH))
        .arg("--input")
        .arg(PathBuf::from(FIXTURE_ROOT).join(fixture))
        .arg("--generated-at")
        .arg(GENERATED_AT)
        .arg("--output")
        .arg("json")
        .current_dir(repo_root())
        .output()
        .expect("run touched-surface proof selector")
}

fn selector_json(fixture: &str) -> Value {
    let output = run_selector(fixture);
    assert!(
        output.status.success(),
        "selector helper failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("selector output must be JSON")
}

fn fixture_text(fixture: &str) -> String {
    std::fs::read_to_string(repo_root().join(FIXTURE_ROOT).join(fixture))
        .unwrap_or_else(|error| panic!("read golden fixture {fixture}: {error}"))
}

fn assert_selector_output_matches_golden(output: Output, fixture: &str, label: &str) {
    assert!(
        output.status.success(),
        "selector helper failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let actual = String::from_utf8(output.stdout).expect("selector stdout is utf-8");
    let expected = fixture_text(fixture);
    let actual_json: Value =
        serde_json::from_str(&actual).expect("actual selector output must be JSON");
    let expected_json: Value =
        serde_json::from_str(&expected).expect("golden selector output must be JSON");
    assert_eq!(actual_json, expected_json);
    assert_eq!(
        actual, expected,
        "{label} selector receipt drifted from the reviewed golden"
    );
}

fn lane_ids(receipt: &Value, key: &str) -> Vec<String> {
    receipt[key]
        .as_array()
        .expect("lane rows")
        .iter()
        .map(|row| row["lane_id"].as_str().expect("lane id").to_string())
        .collect()
}

#[test]
fn script_exists_and_help_is_non_mutating() {
    assert!(
        repo_root().join(SCRIPT_PATH).exists(),
        "selector helper must exist at {SCRIPT_PATH}"
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
fn runtime_source_selects_lib_tests_with_broad_supplemental_frontiers() {
    let receipt = selector_json("src_change.json");

    assert_eq!(
        receipt["schema_version"].as_str(),
        Some("touched-surface-proof-selector-v1")
    );
    assert_eq!(receipt["generated_at"].as_str(), Some(GENERATED_AT));
    assert_eq!(receipt["summary"]["passes"].as_bool(), Some(true));
    assert_eq!(lane_ids(&receipt, "selected_lanes"), vec!["lib-tests"]);
    assert_eq!(
        lane_ids(&receipt, "supplemental_lanes"),
        vec!["all-targets-check", "rustfmt-frontier"]
    );
    assert_eq!(
        receipt["supplemental_lanes"][0]["broad_frontier"].as_bool(),
        Some(true)
    );
}

#[test]
fn runtime_source_output_matches_full_reviewed_golden() {
    let output = run_selector("src_change.json");
    assert_selector_output_matches_golden(output, "src_change_expected.json", "src_change");
}

#[test]
fn fuzz_changes_select_fuzz_manifest_smoke_without_dependency_graph_lane() {
    let receipt = selector_json("fuzz_change.json");

    assert_eq!(receipt["summary"]["passes"].as_bool(), Some(true));
    assert_eq!(
        lane_ids(&receipt, "selected_lanes"),
        vec!["fuzz-manifest-smoke"]
    );
    assert!(
        !lane_ids(&receipt, "selected_lanes")
            .contains(&"default-production-tokio-tree".to_string())
    );
}

#[test]
fn fuzz_change_output_matches_full_reviewed_golden() {
    let output = run_selector("fuzz_change.json");
    assert_selector_output_matches_golden(output, "fuzz_change_expected.json", "fuzz_change");
}

#[test]
fn cargo_manifest_changes_select_dependency_graph_and_compile_frontier() {
    let receipt = selector_json("manifest_change.json");

    assert_eq!(receipt["summary"]["passes"].as_bool(), Some(true));
    assert_eq!(
        lane_ids(&receipt, "selected_lanes"),
        vec!["default-production-tokio-tree"]
    );
    assert_eq!(
        lane_ids(&receipt, "supplemental_lanes"),
        vec!["all-targets-check"]
    );
}

#[test]
fn manifest_change_output_matches_full_reviewed_golden() {
    let output = run_selector("manifest_change.json");
    assert_selector_output_matches_golden(
        output,
        "manifest_change_expected.json",
        "manifest_change",
    );
}

#[test]
fn blocked_direct_lane_is_reported_instead_of_hidden_by_supplemental_green_checks() {
    let receipt = selector_json("blocked_lane.json");

    assert_eq!(receipt["summary"]["passes"].as_bool(), Some(false));
    assert_eq!(
        receipt["summary"]["blocked_selected_count"].as_u64(),
        Some(1)
    );
    assert_eq!(lane_ids(&receipt, "selected_lanes").len(), 0);
    assert_eq!(
        lane_ids(&receipt, "blocked_selected_lanes"),
        vec!["lib-tests"]
    );
    assert!(
        receipt["action_items"][0]
            .as_str()
            .expect("action item")
            .contains("peer dirty source file blocks lib frontier")
    );
}

#[test]
fn blocked_direct_lane_output_matches_full_reviewed_golden() {
    let output = run_selector("blocked_lane.json");
    assert_selector_output_matches_golden(output, "blocked_lane_expected.json", "blocked_lane");
}

#[test]
fn lane_source_paths_are_used_as_fallback_when_no_rule_matches() {
    let receipt = selector_json("source_path_fallback.json");

    assert_eq!(receipt["summary"]["passes"].as_bool(), Some(true));
    assert_eq!(
        lane_ids(&receipt, "selected_lanes"),
        vec!["proof-lane-manifest-contract"]
    );
    assert_eq!(
        receipt["selected_lanes"][0]["rule_ids"][0].as_str(),
        Some("source-path-fallback")
    );
}

#[test]
fn lane_source_fallback_output_matches_full_reviewed_golden() {
    let output = run_selector("source_path_fallback.json");
    assert_selector_output_matches_golden(
        output,
        "source_path_fallback_expected.json",
        "source_path_fallback",
    );
}

#[test]
fn unmatched_paths_fail_with_an_action_item() {
    let receipt = selector_json("unmatched_path.json");

    assert_eq!(receipt["summary"]["passes"].as_bool(), Some(false));
    assert_eq!(
        receipt["summary"]["unmatched_touched_count"].as_u64(),
        Some(1)
    );
    assert_eq!(
        receipt["unmatched_touched_files"][0].as_str(),
        Some("packages/browser/src/index.ts")
    );
    assert!(
        receipt["action_items"][0]
            .as_str()
            .expect("action item")
            .contains("packages/browser/src/index.ts")
    );
}

#[test]
fn unmatched_path_output_matches_full_reviewed_golden() {
    let output = run_selector("unmatched_path.json");
    assert_selector_output_matches_golden(output, "unmatched_path_expected.json", "unmatched_path");
}

#[test]
fn empty_touched_files_do_not_select_a_proxy_lane() {
    let receipt = selector_json("empty_touched.json");

    assert_eq!(receipt["summary"]["passes"].as_bool(), Some(false));
    assert_eq!(receipt["summary"]["selected_count"].as_u64(), Some(0));
    assert!(
        receipt["action_items"][0]
            .as_str()
            .expect("action item")
            .contains("provide at least one touched file")
    );
}

#[test]
fn empty_touched_output_matches_full_reviewed_golden() {
    let output = run_selector("empty_touched.json");
    assert_selector_output_matches_golden(output, "empty_touched_expected.json", "empty_touched");
}

#[test]
fn helper_declares_it_does_not_run_or_mutate_anything() {
    let receipt = selector_json("src_change.json");

    assert_eq!(receipt["non_mutating"].as_bool(), Some(true));
    for key in [
        "runs_cargo",
        "runs_rch",
        "runs_git_mutation",
        "runs_beads_mutation",
        "runs_agent_mail_mutation",
        "runs_destructive_command",
    ] {
        assert_eq!(
            receipt["forbidden_actions"][key].as_bool(),
            Some(false),
            "{key} must stay false"
        );
    }
}
