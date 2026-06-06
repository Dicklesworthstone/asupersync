#![allow(missing_docs)]

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const CONTRACT_PATH: &str = "artifacts/tracker_graph_drift_report_contract_v1.json";
const DOC_PATH: &str = "docs/tracker_graph_drift_report.md";
const GENERATED_AT: &str = "2026-06-06T13:40:00Z";
const SCRIPT_PATH: &str = "scripts/tracker_graph_drift_report.py";

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_repo_file(relative: &str) -> String {
    std::fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|err| panic!("read {relative}: {err}"))
}

fn json_file(relative: &str) -> Value {
    serde_json::from_str(&read_repo_file(relative))
        .unwrap_or_else(|err| panic!("parse {relative}: {err}"))
}

fn run_helper(output_format: &str) -> Output {
    Command::new("python3")
        .arg(repo_path(SCRIPT_PATH))
        .arg("--fixture")
        .arg(repo_path(CONTRACT_PATH))
        .arg("--generated-at")
        .arg(GENERATED_AT)
        .arg("--output")
        .arg(output_format)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run tracker graph drift helper")
}

fn report_json() -> Value {
    let output = run_helper("json");
    assert!(
        output.status.success(),
        "helper failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("helper JSON output")
}

fn markdown_report() -> String {
    let output = run_helper("markdown");
    assert!(
        output.status.success(),
        "helper markdown failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("markdown is utf-8")
}

fn string<'a>(value: &'a Value, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"))
}

fn array<'a>(value: &'a Value, key: &str) -> &'a Vec<Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
}

fn object<'a>(value: &'a Value, key: &str) -> &'a Value {
    value
        .get(key)
        .unwrap_or_else(|| panic!("{key} must be present"))
}

fn bool_field(value: &Value, key: &str) -> bool {
    value
        .get(key)
        .and_then(Value::as_bool)
        .unwrap_or_else(|| panic!("{key} must be a boolean"))
}

fn u64_field(value: &Value, key: &str) -> u64 {
    value
        .get(key)
        .and_then(Value::as_u64)
        .unwrap_or_else(|| panic!("{key} must be an unsigned integer"))
}

fn string_set(value: &Value, key: &str) -> BTreeSet<String> {
    array(value, key)
        .iter()
        .map(|item| {
            item.as_str()
                .unwrap_or_else(|| panic!("{key} entries must be strings"))
                .to_string()
        })
        .collect()
}

fn rows_by_scenario(report: &Value) -> BTreeMap<String, Value> {
    array(report, "rows")
        .iter()
        .map(|row| (string(row, "scenario_id").to_string(), row.clone()))
        .collect()
}

#[test]
fn script_exists_and_help_is_read_only() {
    assert!(repo_path(SCRIPT_PATH).exists(), "{SCRIPT_PATH} must exist");
    let output = Command::new("python3")
        .arg(repo_path(SCRIPT_PATH))
        .arg("--help")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run helper --help");
    assert!(output.status.success(), "--help should succeed");

    let source = read_repo_file(SCRIPT_PATH);
    for forbidden in [
        "subprocess",
        "os.system",
        "git add",
        "git commit",
        "git push",
        "cargo test",
        "cargo check",
        "br update",
        "br close",
        "send_message",
        "file_reservation_paths",
        "write_text",
        "Path.write",
        "open(\"w\"",
    ] {
        assert!(
            !source.contains(forbidden),
            "read-only helper must not contain forbidden token {forbidden}"
        );
    }
}

#[test]
fn contract_fixture_emits_expected_json_summary() {
    let contract = json_file(CONTRACT_PATH);
    let expected = object(&contract, "expected_summary");
    let report = report_json();
    let summary = object(&report, "summary");

    assert_eq!(
        string(&report, "schema_version"),
        "tracker-graph-drift-report-v1"
    );
    assert_eq!(
        string(&report, "fixture_id"),
        "tracker-graph-drift-contract-fixture"
    );
    assert_eq!(string(&report, "generated_at"), GENERATED_AT);
    for key in [
        "scenario_count",
        "safe_to_claim",
        "create_child_bead",
        "refresh_required",
        "blocked_or_unsafe",
    ] {
        assert_eq!(u64_field(summary, key), u64_field(expected, key), "{key}");
    }
    assert_eq!(
        string(summary, "highest_severity_scenario"),
        string(expected, "highest_severity_scenario")
    );
}

#[test]
fn every_required_classification_is_exercised_once() {
    let contract = json_file(CONTRACT_PATH);
    let expected = string_set(&contract, "required_classifications");
    let report = report_json();
    let classification_counts = object(object(&report, "summary"), "classification_counts");

    for classification in &expected {
        assert_eq!(
            classification_counts
                .get(classification)
                .and_then(Value::as_u64)
                .unwrap_or_default(),
            1,
            "{classification} should be exercised exactly once"
        );
        assert!(
            object(&report, "classification_catalog")
                .get(classification)
                .is_some(),
            "{classification} missing from catalog"
        );
    }
}

#[test]
fn live_parent_only_ready_shape_creates_child_bead_instead_of_source_claim() {
    let report = report_json();
    let rows = rows_by_scenario(&report);
    let row = &rows["parent-only-ready"];

    assert_eq!(string(row, "classification"), "parent-only-ready-queue");
    assert!(!bool_field(row, "safe_to_claim"));
    assert!(bool_field(row, "create_child_bead"));
    assert_eq!(
        string(row, "recommended_action"),
        "create-or-select-child-bead"
    );
    assert!(
        string_set(row, "parent_ready_issue_ids").contains("asupersync-ol11aa"),
        "ol11aa must be classified as parent-like ready work"
    );
}

#[test]
fn concrete_br_ready_with_empty_bv_fails_closed() {
    let report = report_json();
    let rows = rows_by_scenario(&report);
    let row = &rows["br-ready-bv-empty"];

    assert_eq!(
        string(row, "classification"),
        "br-ready-bv-empty-divergence"
    );
    assert!(!bool_field(row, "safe_to_claim"));
    assert!(bool_field(row, "refresh_required"));
    assert!(
        string_set(row, "concrete_ready_issue_ids").contains("asupersync-ol11aa.9.2"),
        "concrete ready task must stay visible in the report"
    );
}

#[test]
fn consistent_actionable_names_exact_claim_issue() {
    let report = report_json();
    let rows = rows_by_scenario(&report);
    let row = &rows["consistent-actionable"];

    assert_eq!(string(row, "classification"), "consistent-actionable");
    assert!(bool_field(row, "safe_to_claim"));
    assert_eq!(string(row, "claim_issue_id"), "asupersync-ol11aa.9.2");
    assert!(!bool_field(row, "refresh_required"));
}

#[test]
fn stale_hash_and_command_failures_are_not_admissible() {
    let report = report_json();
    let rows = rows_by_scenario(&report);

    let command_failure = &rows["command-failure"];
    assert_eq!(
        string(command_failure, "classification"),
        "command-provenance-failure"
    );
    assert!(!array(command_failure, "command_failures").is_empty());
    assert!(bool_field(command_failure, "refresh_required"));

    let hash_mismatch = &rows["data-hash-mismatch"];
    assert_eq!(
        string(hash_mismatch, "classification"),
        "data-hash-mismatch"
    );
    assert_eq!(array(hash_mismatch, "bv_data_hashes").len(), 2);
    assert!(bool_field(hash_mismatch, "refresh_required"));

    let stale = &rows["stale-snapshot"];
    assert_eq!(string(stale, "classification"), "stale-graph-snapshot");
    assert!(!array(stale, "stale_inputs").is_empty());
    assert!(bool_field(stale, "refresh_required"));
}

#[test]
fn report_forbids_overclaiming_and_unsafe_coordination_actions() {
    let report = report_json();
    let rows = rows_by_scenario(&report);

    for row in rows.values() {
        let forbidden = string_set(row, "forbidden_actions");
        for required in [
            "do-not-create-branches",
            "do-not-create-worktrees",
            "do-not-edit-peer-dirty-files",
            "do-not-claim-parent-only-work-as-implementation",
            "do-not-treat-empty-bv-next-as-no-work-without-br-cross-check",
            "do-not-cite-stale-graph-snapshot-as-current",
        ] {
            assert!(
                forbidden.contains(required),
                "{} must forbid {required}",
                string(row, "scenario_id")
            );
        }
        for non_claim in array(row, "evidence_does_not_prove") {
            let text = non_claim
                .as_str()
                .expect("non-claim entries must be strings");
            assert!(
                text.contains("does not prove source correctness")
                    || text.contains("do not override live br")
                    || text.contains("planning work")
                    || text.contains("requires normal claim"),
                "unexpected non-claim text: {text}"
            );
        }
    }
}

#[test]
fn markdown_and_docs_cover_operator_usage_and_validation() {
    let markdown = markdown_report();
    assert!(markdown.contains("# Tracker Graph Drift Report"));
    assert!(markdown.contains("parent-only-ready-queue"));
    assert!(markdown.contains("br-ready-bv-empty-divergence"));
    assert!(markdown.contains("do-not-create-branches"));

    let docs = read_repo_file(DOC_PATH);
    for needle in [
        "python3 scripts/tracker_graph_drift_report.py",
        "br-ready-bv-empty-divergence",
        "parent-only-ready-queue",
        "RCH_REQUIRE_REMOTE=1 rch exec --",
        "does not prove source correctness",
    ] {
        assert!(docs.contains(needle), "docs must mention {needle}");
    }
}
