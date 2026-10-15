#![allow(missing_docs)]

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const CONTRACT_PATH: &str = "artifacts/rch_stale_progress_receipt_contract_v1.json";
const DOC_PATH: &str = "docs/rch_stale_progress_receipt.md";
const GENERATED_AT: &str = "2026-06-10T12:40:00Z";
const SCRIPT_PATH: &str = "scripts/rch_stale_progress_receipt.py";

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
        .expect("run rch stale-progress receipt helper")
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
        "rch-stale-progress-receipt-v1"
    );
    assert_eq!(
        string(&report, "fixture_id"),
        "rch-stale-progress-contract-fixture"
    );
    assert_eq!(string(&report, "generated_at"), GENERATED_AT);
    for key in [
        "scenario_count",
        "code_evidence_claimable_count",
        "proof_success_citable_count",
        "cancel_allowed_count",
        "retry_allowed_count",
        "peer_cancel_forbidden_count",
        "local_fallback_count",
        "heartbeat_stale_count",
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
fn channel_stale_pattern_preserves_build_worker_and_non_claims() {
    let rows = rows_by_scenario(&report_json());
    let row = &rows["channel-mpsc-select-e2e-progress-stale"];

    assert_eq!(
        string(row, "classification"),
        "owned-stale-cancel-recommended"
    );
    assert!(!bool_field(row, "proof_success_citable"));
    assert!(!bool_field(row, "code_evidence_claimable"));
    assert!(bool_field(
        object(row, "cancellation_policy"),
        "cancel_allowed"
    ));
    assert_eq!(
        u64_field(object(row, "rch_status"), "build_id"),
        29880940465488021
    );
    assert_eq!(string(object(row, "rch_status"), "worker_id"), "vmi1227854");
    assert!(
        string(object(row, "rch_status"), "selected_target_dir")
            .contains(".rch-target-vmi1227854-job-29880940465488021")
    );
    assert!(
        string(object(row, "lane"), "command").contains("channel_mpsc_select_e2e"),
        "channel stale fixture must preserve the focused lane command"
    );
    assert!(
        string_set(row, "evidence_does_not_prove")
            .iter()
            .any(|claim| claim.contains("does not prove source correctness")),
        "stale progress must carry source-correctness non-claim"
    );
}

#[test]
fn peer_owned_and_live_wait_rows_never_cancel() {
    let rows = rows_by_scenario(&report_json());

    let peer = &rows["peer-owned-progress-stale"];
    assert_eq!(string(peer, "classification"), "peer-owned-do-not-cancel");
    assert!(!bool_field(
        object(peer, "cancellation_policy"),
        "cancel_allowed"
    ));
    assert!(
        bool_field(
            object(peer, "cancellation_policy"),
            "never_cancel_peer_owned_builds"
        ),
        "peer stale rows must preserve the never-cancel policy"
    );

    let wait = &rows["heartbeat-live-progress-stale-wait"];
    assert_eq!(
        string(wait, "classification"),
        "heartbeat-live-progress-stale-wait"
    );
    assert!(!bool_field(
        object(wait, "cancellation_policy"),
        "cancel_allowed"
    ));
    assert!(
        bool_field(
            object(wait, "cancellation_policy"),
            "wait_for_fresh_heartbeat"
        ),
        "heartbeat-live wait rows must preserve wait-for-heartbeat policy"
    );
}

#[test]
fn terminal_stale_receipts_allow_retry_without_becoming_proof() {
    let rows = rows_by_scenario(&report_json());

    let canceled = &rows["owned-stale-canceled-cleanly"];
    assert_eq!(
        string(canceled, "classification"),
        "stale-progress-canceled"
    );
    assert!(bool_field(
        object(canceled, "retry_policy"),
        "retry_allowed"
    ));
    assert!(!bool_field(canceled, "proof_success_citable"));
    assert_eq!(
        string(object(canceled, "cancellation_outcome"), "operation_id"),
        "cancel-29880940465488043"
    );

    let heartbeat = &rows["heartbeat-stale-worker-infra"];
    assert_eq!(string(heartbeat, "classification"), "heartbeat-stale-infra");
    assert!(bool_field(
        object(heartbeat, "retry_policy"),
        "retry_allowed"
    ));
    assert!(!bool_field(heartbeat, "code_evidence_claimable"));

    let local = &rows["local-fallback-refusal"];
    assert_eq!(string(local, "classification"), "local-fallback-refused");
    assert!(!bool_field(object(local, "retry_policy"), "retry_allowed"));
    assert!(!bool_field(local, "proof_success_citable"));
}

#[test]
fn markdown_and_docs_cover_operator_usage_and_validation() {
    let markdown = markdown_report();
    for marker in [
        "# RCH Stale-Progress Receipt",
        "channel-mpsc-select-e2e-progress-stale",
        "`owned-stale-cancel-recommended`",
        "`peer-owned-do-not-cancel`",
        "`heartbeat-stale-infra`",
        "`local-fallback-refused`",
        "`do-not-cancel-peer-owned-builds`",
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
        "rch-stale-progress-receipt-v1",
        "heartbeat-live-progress-stale-wait",
        "owned-stale-cancel-recommended",
        "stale-progress-canceled",
        "peer-owned-do-not-cancel",
        "heartbeat-stale-infra",
        "local-fallback-refused",
        "RCH_REQUIRE_REMOTE=1 rch exec --",
        "Never cancel peer-owned builds",
    ] {
        assert!(docs.contains(marker), "docs missing marker: {marker}");
    }
}
