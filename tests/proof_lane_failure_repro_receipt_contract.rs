#![allow(missing_docs)]

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const CONTRACT_PATH: &str = "artifacts/proof_lane_failure_repro_receipt_contract_v1.json";
const DOC_PATH: &str = "docs/proof_lane_failure_repro_receipt.md";
const GENERATED_AT: &str = "2026-06-06T09:20:00Z";
const README_PATH: &str = "README.md";
const SCRIPT_PATH: &str = "scripts/proof_lane_failure_repro_receipt.py";
const TEST_PATH: &str = "tests/proof_lane_failure_repro_receipt_contract.rs";

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
        .expect("run proof lane failure repro helper")
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

fn rows_by_failure(report: &Value) -> BTreeMap<String, Value> {
    array(report, "rows")
        .iter()
        .map(|row| (string(row, "failure_id").to_string(), row.clone()))
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
        "proof-lane-failure-repro-receipt-v1"
    );
    assert_eq!(
        string(&report, "fixture_id"),
        "proof-lane-failure-repro-contract-fixture"
    );
    assert_eq!(string(&report, "generated_at"), GENERATED_AT);
    for key in [
        "total_failures",
        "cargo_repro_commands",
        "envelope_ok",
        "blocked_external",
        "failed_local",
        "proof_admissible",
    ] {
        assert_eq!(u64_field(summary, key), u64_field(expected, key), "{key}");
    }
    assert_eq!(
        string(&array(&report, "rows")[0], "failure_id"),
        string(expected, "highest_ranked_failure")
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
fn minimal_repro_commands_preserve_remote_required_envelopes() {
    let report = report_json();
    let rows = rows_by_failure(&report);

    for row in rows.values() {
        assert!(
            !bool_field(row, "proof_admissible"),
            "repro receipts must not be counted as fresh proof"
        );
        let repro = object(row, "minimal_repro");
        assert!(
            !bool_field(repro, "local_fallback_allowed"),
            "local fallback must remain disabled"
        );
        assert!(
            bool_field(repro, "envelope_ok"),
            "minimal command envelope should be valid for {}",
            string(row, "failure_id")
        );
        if bool_field(repro, "is_cargo") {
            let command = string(repro, "command");
            assert!(
                command.starts_with("RCH_REQUIRE_REMOTE=1 rch exec -- "),
                "cargo repro must preserve remote-required RCH prefix: {command}"
            );
            assert!(
                command.contains("CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_repro_"),
                "cargo repro must preserve lane-specific target dir: {command}"
            );
        }
    }

    let retrieval = object(&rows["retrieval-timeout-pass-lane"], "minimal_repro");
    assert!(!bool_field(retrieval, "is_cargo"));
    assert!(
        string(retrieval, "command").contains("scripts/rch_retrieval_receipt.py"),
        "retrieval timeout after pass should use the retrieval diagnostic helper"
    );
}

#[test]
fn first_hard_blockers_are_classified_without_overclaiming() {
    let rows = rows_by_failure(&report_json());

    let compile = object(&rows["compile-error-lane"], "first_blocker");
    assert_eq!(
        string(&rows["compile-error-lane"], "classification"),
        "rustc-compile-error"
    );
    assert_eq!(
        string(compile, "file"),
        "tests/proof_console_report_contract.rs"
    );
    assert_eq!(u64_field(compile, "line"), 67);
    assert_eq!(string(compile, "code"), "E0106");

    let assertion = object(&rows["test-assertion-lane"], "first_blocker");
    assert_eq!(
        string(&rows["test-assertion-lane"], "classification"),
        "test-assertion-failure"
    );
    assert_eq!(
        string(assertion, "file"),
        "tests/brownout_no_win_lab_e2e.rs"
    );
    assert_eq!(u64_field(assertion, "line"), 214);
    assert_eq!(string(assertion, "code"), "test-panicked");

    let timeout = object(&rows["timeout-after-first-failure-lane"], "first_blocker");
    assert_eq!(
        string(&rows["timeout-after-first-failure-lane"], "classification"),
        "timeout-after-first-failure"
    );
    assert_eq!(
        string(timeout, "file"),
        "tests/swarm_proof_lane_planner_contract.rs"
    );
    assert_eq!(string(timeout, "code"), "E0277");

    for (failure_id, classification, blocker_code) in [
        ("worker-enospc-lane", "worker-disk-pressure", "enospc"),
        (
            "ssh-transport-lane",
            "ssh-transport-failure",
            "ssh-transport-failure",
        ),
        (
            "retrieval-timeout-pass-lane",
            "retrieval-timeout-after-pass",
            "retrieval-timeout-after-pass",
        ),
        ("zero-test-lane", "zero-test-proof", "zero-tests"),
        (
            "local-fallback-refusal-lane",
            "local-fallback-refused",
            "local-fallback-refused",
        ),
    ] {
        let row = &rows[failure_id];
        assert_eq!(string(row, "classification"), classification);
        assert_eq!(string(object(row, "first_blocker"), "code"), blocker_code);
    }
}

#[test]
fn markdown_report_lists_non_claims_classifications_and_commands() {
    let markdown = markdown_report();
    for needle in [
        "# Proof Lane Failure Repro Receipts",
        "This receipt chooses minimal repro commands; it is not workspace health.",
        "A repro command is not a fresh proof until it is rerun through RCH.",
        "rustc-compile-error",
        "worker-disk-pressure",
        "retrieval-timeout-after-pass",
        "local-fallback-refused",
        "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_repro_compile_error",
        "scripts/rch_retrieval_receipt.py",
    ] {
        assert!(
            markdown.contains(needle),
            "markdown report missing expected text: {needle}"
        );
    }
}

#[test]
fn docs_and_readme_track_the_contract_surface() {
    for path in [README_PATH, DOC_PATH, TEST_PATH, CONTRACT_PATH, SCRIPT_PATH] {
        assert!(repo_path(path).exists(), "{path} must exist");
    }

    let docs = read_repo_file(DOC_PATH);
    let readme = read_repo_file(README_PATH);
    for needle in [
        "scripts/proof_lane_failure_repro_receipt.py",
        "artifacts/proof_lane_failure_repro_receipt_contract_v1.json",
        "tests/proof_lane_failure_repro_receipt_contract.rs",
        "rustc-compile-error",
        "worker-disk-pressure",
        "retrieval-timeout-after-pass",
        "zero-test-proof",
        "local-fallback-refused",
        "does not certify workspace health",
    ] {
        assert!(docs.contains(needle), "docs missing {needle}");
    }
    for needle in [
        "Proof Lane Failure Repro Receipts",
        "artifacts/proof_lane_failure_repro_receipt_contract_v1.json",
        "scripts/proof_lane_failure_repro_receipt.py",
    ] {
        assert!(readme.contains(needle), "README missing {needle}");
    }
}
