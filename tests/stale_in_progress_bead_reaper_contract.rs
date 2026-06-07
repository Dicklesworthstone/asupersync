#![allow(missing_docs)]

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const CONTRACT_PATH: &str = "artifacts/stale_in_progress_bead_reaper_contract_v1.json";
const DOC_PATH: &str = "docs/stale_in_progress_bead_reaper.md";
const GENERATED_AT: &str = "2026-06-06T14:30:00Z";
const SCRIPT_PATH: &str = "scripts/stale_in_progress_bead_reaper.py";

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

fn run_helper(mode: &str, output_format: &str) -> Output {
    Command::new("python3")
        .arg(repo_path(SCRIPT_PATH))
        .arg("--fixture")
        .arg(repo_path(CONTRACT_PATH))
        .arg("--generated-at")
        .arg(GENERATED_AT)
        .arg("--mode")
        .arg(mode)
        .arg("--output")
        .arg(output_format)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run stale in-progress bead reaper helper")
}

fn report_json(mode: &str) -> Value {
    let output = run_helper(mode, "json");
    assert!(
        output.status.success(),
        "helper failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("helper JSON output")
}

fn markdown_report(mode: &str) -> String {
    let output = run_helper(mode, "markdown");
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

fn rows_by_issue(report: &Value) -> BTreeMap<String, Value> {
    array(report, "rows")
        .iter()
        .map(|row| (string(row, "issue_id").to_string(), row.clone()))
        .collect()
}

#[test]
fn script_exists_and_default_path_is_non_mutating() {
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
        "open(\"w\"",
        "open('w'",
    ] {
        assert!(
            !source.contains(forbidden),
            "helper must not contain forbidden token {forbidden}"
        );
    }
}

#[test]
fn report_mode_emits_expected_summary_without_applying() {
    let contract = json_file(CONTRACT_PATH);
    let expected = object(&contract, "expected_report_summary");
    let report = report_json("report");
    let summary = object(&report, "summary");

    assert_eq!(
        string(&report, "schema_version"),
        "stale-in-progress-bead-reaper-report-v1"
    );
    assert_eq!(
        string(&report, "fixture_id"),
        "stale-in-progress-bead-reaper-contract-fixture"
    );
    assert_eq!(string(&report, "mode"), "report");
    for key in [
        "issue_count",
        "candidate_count",
        "would_reopen",
        "applied_reopen",
        "refused_or_excluded",
        "ignored",
    ] {
        assert_eq!(u64_field(summary, key), u64_field(expected, key), "{key}");
    }
    assert_eq!(
        string(summary, "highest_severity_issue"),
        string(expected, "highest_severity_issue")
    );
}

#[test]
fn every_required_classification_is_exercised_once() {
    let contract = json_file(CONTRACT_PATH);
    let expected = string_set(&contract, "required_classifications");
    let report = report_json("report");
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
fn stale_candidate_has_exact_dry_run_mutation() {
    let report = report_json("report");
    let rows = rows_by_issue(&report);
    let row = &rows["asupersync-stale-old"];

    assert_eq!(string(row, "classification"), "stale-reopen-candidate");
    assert!(bool_field(row, "candidate"));
    assert!(bool_field(row, "apply_allowed"));
    assert!(!bool_field(row, "applied"));
    assert!(bool_field(row, "explicit_apply_required"));
    assert_eq!(u64_field(row, "age_seconds"), 1_909_800);

    let mutation = object(row, "planned_mutation");
    assert_eq!(string(mutation, "id"), "asupersync-stale-old");
    assert_eq!(string(mutation, "from_status"), "in_progress");
    assert_eq!(string(mutation, "to_status"), "open");
    assert!(bool_field(mutation, "clear_assignee"));
    assert!(row.get("resulting_issue").is_some_and(Value::is_null));
}

#[test]
fn apply_mode_only_applies_the_candidate_in_output() {
    let contract = json_file(CONTRACT_PATH);
    let expected = object(&contract, "expected_apply_summary");
    let report = report_json("apply");
    let summary = object(&report, "summary");
    let rows = rows_by_issue(&report);
    let row = &rows["asupersync-stale-old"];

    assert_eq!(string(&report, "mode"), "apply");
    assert_eq!(
        u64_field(summary, "would_reopen"),
        u64_field(expected, "would_reopen")
    );
    assert_eq!(
        u64_field(summary, "applied_reopen"),
        u64_field(expected, "applied_reopen")
    );
    assert!(bool_field(row, "applied"));

    let resulting = object(row, "resulting_issue");
    assert_eq!(string(resulting, "id"), "asupersync-stale-old");
    assert_eq!(string(resulting, "status"), "open");
    assert!(resulting.get("assignee").is_none());
    assert_eq!(string(resulting, "updated_at"), GENERATED_AT);
    assert!(bool_field(resulting, "stale_reaper_applied"));

    for id in [
        "asupersync-live-agent",
        "asupersync-recent-update",
        "asupersync-missing-timestamp",
        "asupersync-unknown-owner",
    ] {
        assert!(
            !bool_field(&rows[id], "applied"),
            "{id} must not be applied"
        );
    }
}

#[test]
fn live_recent_missing_malformed_and_ambiguous_rows_fail_closed() {
    let report = report_json("report");
    let rows = rows_by_issue(&report);

    let live = &rows["asupersync-live-agent"];
    assert_eq!(string(live, "classification"), "live-agent-excluded");
    assert!(string_set(live, "blockers").contains("assignee-active:PinkStream"));

    let recent = &rows["asupersync-recent-update"];
    assert_eq!(string(recent, "classification"), "recent-update-excluded");
    assert!(string_set(recent, "blockers").contains("threshold=604800s"));

    let missing = &rows["asupersync-missing-timestamp"];
    assert_eq!(
        string(missing, "classification"),
        "missing-timestamp-refused"
    );
    assert!(string_set(missing, "blockers").contains("missing-or-unparseable-updated-at"));

    let malformed = &rows[""];
    assert_eq!(string(malformed, "classification"), "malformed-row-refused");
    assert!(string_set(malformed, "blockers").contains("missing-id"));

    let ambiguous = &rows["asupersync-unknown-owner"];
    assert_eq!(
        string(ambiguous, "classification"),
        "ambiguous-ownership-refused"
    );
    assert!(
        string_set(ambiguous, "blockers")
            .contains("assignee-not-in-active-agent-snapshot:UnknownAgent")
    );
}

#[test]
fn closed_rows_are_ignored() {
    let report = report_json("report");
    let rows = rows_by_issue(&report);
    let row = &rows["asupersync-closed-row"];

    assert_eq!(string(row, "classification"), "non-in-progress-ignored");
    assert!(!bool_field(row, "candidate"));
    assert!(!bool_field(row, "apply_allowed"));
    assert!(!bool_field(row, "explicit_apply_required"));
}

#[test]
fn report_forbids_unsafe_tracker_reopen_actions() {
    let report = report_json("report");
    let rows = rows_by_issue(&report);

    for row in rows.values() {
        let forbidden = string_set(row, "forbidden_actions");
        for required in [
            "do-not-create-branches",
            "do-not-create-worktrees",
            "do-not-edit-peer-dirty-files",
            "do-not-apply-without-explicit-mode",
            "do-not-reopen-live-agent-work",
            "do-not-reopen-recently-updated-work",
            "do-not-reopen-ambiguous-ownership",
            "do-not-rewrite-beads-jsonl-in-place",
        ] {
            assert!(
                forbidden.contains(required),
                "{} must forbid {required}",
                string(row, "issue_id")
            );
        }
        for non_claim in array(row, "evidence_does_not_prove") {
            let text = non_claim
                .as_str()
                .expect("non-claim entries must be strings");
            assert!(
                text.contains("does not prove source correctness")
                    || text.contains("do not override live br")
                    || text.contains("advisory")
                    || text.contains("does not commit"),
                "unexpected non-claim text: {text}"
            );
        }
    }
}

#[test]
fn markdown_and_docs_cover_operator_usage_and_validation() {
    let markdown = markdown_report("apply");
    assert!(markdown.contains("# Stale In-Progress Bead Reaper Report"));
    assert!(markdown.contains("stale-reopen-candidate"));
    assert!(markdown.contains("Applied reopen: 1"));
    assert!(markdown.contains("do-not-rewrite-beads-jsonl-in-place"));

    let docs = read_repo_file(DOC_PATH);
    for needle in [
        "python3 scripts/stale_in_progress_bead_reaper.py",
        "stale-reopen-candidate",
        "missing-timestamp-refused",
        "RCH_REQUIRE_REMOTE=1 rch exec --",
        "does not prove source correctness",
        "stage only the intended tracker rows",
    ] {
        assert!(docs.contains(needle), "docs must mention {needle}");
    }
}
