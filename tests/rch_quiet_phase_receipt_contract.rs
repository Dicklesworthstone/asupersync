#![allow(missing_docs)]

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const CONTRACT_PATH: &str = "artifacts/rch_quiet_phase_receipt_contract_v1.json";
const DOC_PATH: &str = "docs/rch_quiet_phase_receipt.md";
const GENERATED_AT: &str = "2026-06-06T16:50:00Z";
const SCRIPT_PATH: &str = "scripts/rch_quiet_phase_receipt.py";

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
        .expect("run rch quiet-phase receipt helper")
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

fn i64_field(value: &Value, key: &str) -> i64 {
    value
        .get(key)
        .and_then(Value::as_i64)
        .unwrap_or_else(|| panic!("{key} must be an integer"))
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
fn script_exists_and_is_read_only_fixture_evaluator() {
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
        "cargo clippy",
        "br update",
        "br close",
        "send_message",
        "file_reservation_paths",
        "write_text",
        "Path.write",
        "open(\"w\"",
        "open('w'",
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
        "rch-quiet-phase-receipt-v1"
    );
    assert_eq!(
        string(&report, "fixture_id"),
        "rch-quiet-phase-contract-fixture"
    );
    assert_eq!(string(&report, "generated_at"), GENERATED_AT);
    for key in [
        "scenario_count",
        "proof_success_citable_count",
        "progress_evidence_count",
        "warning_count",
        "blocker_count",
        "local_fallback_count",
        "artifact_stall_count",
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
fn successful_cold_clippy_is_citeable_only_because_exit_zero_completed() {
    let rows = rows_by_scenario(&report_json());
    let row = &rows["successful-cold-clippy"];

    assert_eq!(
        string(row, "classification"),
        "remote-success-with-quiet-progress"
    );
    assert!(bool_field(row, "proof_success_citable"));
    assert!(bool_field(row, "progress_evidence"));
    let markers = object(row, "markers");
    assert_eq!(string(markers, "selected_worker"), "ts2");
    assert_eq!(i64_field(markers, "remote_exit_code"), 0);
    assert!(bool_field(markers, "retrieval_completed"));
    assert_eq!(u64_field(markers, "artifact_file_count"), 17269);
    assert_eq!(u64_field(markers, "artifact_bytes"), 2601801);

    let quiet = object(row, "quiet_phase_summary");
    let longest = object(quiet, "longest");
    assert_eq!(string(longest, "from"), "workspace-crate-phase");
    assert_eq!(string(longest, "to"), "workspace-crate-phase");
    assert_eq!(u64_field(longest, "seconds"), 745);
    assert!(
        string_set(row, "warnings").contains("quiet-phase-exceeded-warning=745"),
        "successful cold clippy should still record quiet-phase progress warning"
    );

    for non_claim in array(row, "evidence_does_not_prove") {
        let text = non_claim.as_str().expect("non-claim entries are strings");
        assert!(
            text.contains("does not prove source correctness")
                || text.contains("remote exit evidence")
                || text.contains("do not override live RCH")
                || text.contains("Local fallback is never acceptable"),
            "unexpected non-claim text: {text}"
        );
    }
}

#[test]
fn failed_test_and_retrieval_stall_are_not_citeable_success() {
    let rows = rows_by_scenario(&report_json());

    let failed = &rows["failed-cargo-test"];
    assert_eq!(string(failed, "classification"), "remote-command-failed");
    assert!(!bool_field(failed, "proof_success_citable"));
    assert!(bool_field(failed, "progress_evidence"));
    assert_eq!(
        i64_field(object(failed, "markers"), "remote_exit_code"),
        101
    );
    assert!(string_set(failed, "blockers").contains("remote-exit=101"));

    let stall = &rows["artifact-retrieval-stall"];
    assert_eq!(string(stall, "classification"), "artifact-retrieval-stall");
    assert!(!bool_field(stall, "proof_success_citable"));
    assert_eq!(i64_field(object(stall, "markers"), "remote_exit_code"), 0);
    assert!(!bool_field(object(stall, "markers"), "retrieval_completed"));
    assert!(string_set(stall, "blockers").contains("artifact-retrieval:started-not-completed"));
}

#[test]
fn timeout_forecast_and_remote_evidence_fail_closed() {
    let rows = rows_by_scenario(&report_json());

    let timeout = &rows["timeout-forecast-risk"];
    assert_eq!(string(timeout, "classification"), "envelope-timeout-risk");
    assert!(!bool_field(timeout, "proof_success_citable"));
    assert!(bool_field(timeout, "progress_evidence"));
    assert_eq!(
        u64_field(
            object(object(timeout, "quiet_phase_summary"), "longest"),
            "seconds"
        ),
        690
    );
    assert!(string_set(timeout, "blockers").contains("quiet-phase-seconds=690"));

    let missing = &rows["missing-remote-evidence"];
    assert_eq!(
        string(missing, "classification"),
        "missing-remote-required-evidence"
    );
    assert!(!bool_field(missing, "proof_success_citable"));
    for required in [
        "command_provenance:RCH_REQUIRE_REMOTE:missing",
        "rch:selected-worker:missing",
        "rch:remote-command-start:missing",
        "proof_envelope:remote_required:must-be-true",
        "proof_envelope:no_local_fallback:must-be-true",
    ] {
        assert!(
            string_set(missing, "blockers").contains(required),
            "missing remote evidence should report {required}"
        );
    }
}

#[test]
fn local_fallback_refusal_is_highest_severity_and_forbidden() {
    let report = report_json();
    let rows = rows_by_scenario(&report);
    let row = &rows["local-fallback-refusal"];

    assert_eq!(string(row, "classification"), "local-fallback-refused");
    assert_eq!(
        string(object(&report, "summary"), "highest_severity_scenario"),
        "local-fallback-refusal"
    );
    assert!(!bool_field(row, "proof_success_citable"));
    assert!(!bool_field(row, "progress_evidence"));
    assert!(
        string_set(row, "blockers")
            .iter()
            .any(|blocker| blocker.starts_with("local-fallback-line:"))
    );
}

#[test]
fn report_forbids_overclaiming_quiet_phases() {
    let rows = rows_by_scenario(&report_json());

    for row in rows.values() {
        let forbidden = string_set(row, "forbidden_actions");
        for required in [
            "do-not-treat-quiet-progress-as-success",
            "do-not-cite-local-fallback-as-rch-proof",
            "do-not-ignore-missing-remote-worker-evidence",
            "do-not-ignore-artifact-retrieval-stalls",
            "do-not-close-lane-without-remote-exit-evidence",
            "do-not-restart-a-long-lane-without-preserving-the-log",
        ] {
            assert!(
                forbidden.contains(required),
                "{} must forbid {required}",
                string(row, "scenario_id")
            );
        }
    }
}

#[test]
fn markdown_and_docs_cover_operator_usage_and_validation() {
    let markdown = markdown_report();
    for marker in [
        "# RCH Quiet-Phase Receipt",
        "successful-cold-clippy",
        "`remote-success-with-quiet-progress`",
        "`artifact-retrieval-stall`",
        "`local-fallback-refused`",
        "`do-not-treat-quiet-progress-as-success`",
    ] {
        assert!(
            markdown.contains(marker),
            "markdown missing marker: {marker}"
        );
    }

    let docs = read_repo_file(DOC_PATH);
    for marker in [
        SCRIPT_PATH,
        CONTRACT_PATH,
        "rch-quiet-phase-receipt-v1",
        "remote-success-with-quiet-progress",
        "remote-command-failed",
        "artifact-retrieval-stall",
        "local-fallback-refused",
        "envelope-timeout-risk",
        "missing-remote-required-evidence",
        "RCH_REQUIRE_REMOTE=1 rch exec --",
        "quiet progress is not success",
    ] {
        assert!(docs.contains(marker), "docs missing marker: {marker}");
    }
}
