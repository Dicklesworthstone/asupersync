#![allow(missing_docs)]

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const CONTRACT_PATH: &str = "artifacts/reservation_lease_watchdog_contract_v1.json";
const DOC_PATH: &str = "docs/reservation_lease_watchdog.md";
const GENERATED_AT: &str = "2026-06-06T16:05:00Z";
const SCRIPT_PATH: &str = "scripts/reservation_lease_watchdog.py";

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

fn run_helper(output_format: &str, mode: &str) -> Output {
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
        .expect("run reservation lease watchdog helper")
}

fn report_json() -> Value {
    let output = run_helper("json", "dry-run");
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
    let output = run_helper("markdown", "dry-run");
    assert!(
        output.status.success(),
        "helper markdown failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("markdown is utf-8")
}

fn log_report() -> String {
    let output = run_helper("log", "renew");
    assert!(
        output.status.success(),
        "helper log failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("log is utf-8")
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
        "br update",
        "br close",
        "send_message",
        "requests.",
        "socket.",
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
        "reservation-lease-watchdog-report-v1"
    );
    assert_eq!(
        string(&report, "fixture_id"),
        "reservation-lease-watchdog-contract-fixture"
    );
    assert_eq!(string(&report, "generated_at"), GENERATED_AT);
    assert_eq!(string(&report, "mode"), "dry-run");
    for key in [
        "scenario_count",
        "admissible_count",
        "non_admissible_count",
        "renew_needed_count",
        "fail_closed_count",
        "renewal_request_count",
        "missing_path_count",
        "conflict_count",
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
fn sufficient_ttl_row_covers_all_paths_and_provenance() {
    let rows = rows_by_scenario(&report_json());
    let row = &rows["sufficient-ttl"];

    assert_eq!(string(row, "classification"), "sufficient-ttl");
    assert!(bool_field(row, "coverage_admissible"));
    assert!(!bool_field(row, "fail_closed"));
    assert_eq!(
        string(object(row, "lane"), "bead_id"),
        "asupersync-ol11aa.9.3"
    );
    assert_eq!(
        string(object(row, "lane"), "command_id"),
        "focused-reservation-lease-watchdog-rch"
    );

    let reservation_summary = object(row, "reservation_summary");
    assert_eq!(u64_field(reservation_summary, "expected_path_count"), 5);
    assert_eq!(u64_field(reservation_summary, "owned_active_count"), 5);
    assert!(array(reservation_summary, "missing_paths").is_empty());
    assert!(array(reservation_summary, "expired_paths").is_empty());
    assert!(array(reservation_summary, "insufficient_ttl_paths").is_empty());
    assert_eq!(
        string(reservation_summary, "required_coverage_until"),
        "2026-06-06T16:45:00Z"
    );

    let command = object(object(row, "lane"), "command_provenance");
    assert!(
        array(command, "argv")
            .iter()
            .any(|arg| arg.as_str() == Some("rch"))
    );
    assert_eq!(string(object(command, "env"), "RCH_REQUIRE_REMOTE"), "1");
    assert_eq!(
        string(command, "source_fingerprint"),
        "git:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );
    let envelope = object(object(row, "lane"), "proof_envelope");
    assert_eq!(u64_field(envelope, "timeout_seconds"), 3600);
    assert!(bool_field(envelope, "remote_required"));
    assert!(bool_field(envelope, "no_local_fallback"));
}

#[test]
fn near_expiry_requires_explicit_renewal_plan() {
    let rows = rows_by_scenario(&report_json());
    let row = &rows["near-expiry-renew-needed"];

    assert_eq!(string(row, "classification"), "renew-needed");
    assert!(!bool_field(row, "coverage_admissible"));
    assert!(!bool_field(row, "fail_closed"));
    let plan = object(row, "renewal_plan");
    assert!(bool_field(plan, "needed"));
    assert!(bool_field(plan, "explicit_request_required"));
    assert_eq!(string(plan, "action"), "renew-reservations");
    assert_eq!(u64_field(plan, "ttl_seconds"), 7200);
    assert!(string_set(plan, "paths").contains("docs/reservation_lease_watchdog.md"));
    assert!(
        string_set(row, "blockers")
            .contains("reservation-renew-needed:docs/reservation_lease_watchdog.md")
    );
}

#[test]
fn fail_closed_cases_show_precise_blockers() {
    let rows = rows_by_scenario(&report_json());

    let expired = &rows["expired-owned-reservation"];
    assert_eq!(string(expired, "classification"), "expired-reservation");
    assert!(!bool_field(expired, "coverage_admissible"));
    assert!(bool_field(expired, "fail_closed"));
    assert!(
        string_set(expired, "blockers")
            .contains("reservation-expired:artifacts/reservation_lease_watchdog_contract_v1.json")
    );

    let missing = &rows["missing-doc-reservation"];
    assert_eq!(string(missing, "classification"), "missing-reservation");
    assert!(!bool_field(missing, "coverage_admissible"));
    assert!(
        string_set(missing, "blockers")
            .contains("reservation-missing:docs/reservation_lease_watchdog.md")
    );

    let conflict = &rows["peer-conflict-on-script"];
    assert_eq!(
        string(conflict, "classification"),
        "conflicting-reservation"
    );
    assert!(!bool_field(conflict, "coverage_admissible"));
    assert!(
        string_set(conflict, "blockers")
            .iter()
            .any(|blocker| blocker.contains("held by SapphireHill"))
    );

    let renewal = &rows["renewal-failure-after-request"];
    assert_eq!(string(renewal, "classification"), "renewal-failure");
    assert!(!bool_field(renewal, "coverage_admissible"));
    assert!(bool_field(renewal, "fail_closed"));
    assert!(string_set(renewal, "blockers").contains("renewal_attempt:failed"));
    assert_eq!(
        string(object(renewal, "renewal_attempt"), "error"),
        "FILE_RESERVATION_CONFLICT"
    );

    let provenance = &rows["missing-command-provenance"];
    assert_eq!(
        string(provenance, "classification"),
        "command-provenance-missing"
    );
    assert!(!bool_field(provenance, "coverage_admissible"));
    assert!(string_set(provenance, "blockers").contains("command_provenance:argv:missing"));
    assert!(
        string_set(provenance, "blockers").contains("proof_envelope:remote_required:must-be-true")
    );
}

#[test]
fn report_forbids_overclaiming_and_lists_non_claims() {
    let report = report_json();
    let rows = rows_by_scenario(&report);

    for row in rows.values() {
        let forbidden = string_set(row, "forbidden_actions");
        for required in [
            "do-not-create-branches",
            "do-not-create-worktrees",
            "do-not-edit-peer-reserved-paths",
            "do-not-assume-expired-reservations-cover-validation",
            "do-not-hide-renewal-failure",
            "do-not-cite-local-fallback-as-rch-proof",
            "do-not-close-lane-with-missing-command-provenance",
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
                    || text.contains("do not override live Agent Mail")
                    || text.contains("not a renewal receipt")
                    || text.contains("local fallback is never proof"),
                "unexpected non-claim text: {text}"
            );
        }
    }
}

#[test]
fn markdown_docs_and_log_cover_operator_usage() {
    let markdown = markdown_report();
    for marker in [
        "# Reservation Lease Watchdog",
        "near-expiry-renew-needed",
        "`renew-needed`",
        "`renew-reservations`",
        "`do-not-hide-renewal-failure`",
    ] {
        assert!(
            markdown.contains(marker),
            "markdown missing marker: {marker}"
        );
    }

    let log = log_report();
    for marker in [
        "[watchdog] start",
        "scenario=near-expiry-renew-needed classification=renewal-failure",
        "renewal action=blocked",
        "scenario=sufficient-ttl classification=sufficient-ttl",
        "[watchdog] end",
    ] {
        assert!(log.contains(marker), "log missing marker: {marker}");
    }

    let docs = read_repo_file(DOC_PATH);
    for marker in [
        SCRIPT_PATH,
        CONTRACT_PATH,
        "reservation-lease-watchdog-report-v1",
        "sufficient-ttl",
        "renew-needed",
        "expired-reservation",
        "missing-reservation",
        "conflicting-reservation",
        "renewal-failure",
        "command-provenance-missing",
        "RCH_REQUIRE_REMOTE=1 rch exec --",
        "python3 scripts/reservation_lease_watchdog.py",
    ] {
        assert!(docs.contains(marker), "docs missing marker: {marker}");
    }
}
