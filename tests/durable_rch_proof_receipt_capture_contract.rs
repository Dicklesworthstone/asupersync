//! Contract tests for durable RCH terminal receipt capture.

#![allow(missing_docs)]

use serde_json::Value;
use std::path::PathBuf;
use std::process::{Command, Output};

const SCRIPT_PATH: &str = "scripts/durable_rch_proof_receipt.py";
const CONTRACT_PATH: &str = "artifacts/durable_rch_proof_receipt_contract_v1.json";
const SNAPSHOT_PATH: &str = "artifacts/proof_status_snapshot_v1.json";
const FIXTURE_ROOT: &str = "tests/fixtures/durable_rch_proof_receipt_capture";
const GENERATED_AT: &str = "2026-06-09T10:00:00Z";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn repo_path(relative: &str) -> PathBuf {
    repo_root().join(relative)
}

fn read_json(relative: &str) -> Value {
    serde_json::from_str(
        &std::fs::read_to_string(repo_path(relative))
            .unwrap_or_else(|err| panic!("read {relative}: {err}")),
    )
    .unwrap_or_else(|err| panic!("parse {relative}: {err}"))
}

fn run_capture(fixture: &str, extra_args: &[&str]) -> Output {
    let mut command = Command::new("python3");
    command
        .arg(repo_path(SCRIPT_PATH))
        .arg("--repo-root")
        .arg(repo_root())
        .arg("--fixture")
        .arg(repo_path(&format!("{FIXTURE_ROOT}/{fixture}")))
        .arg("--generated-at")
        .arg(GENERATED_AT)
        .arg("--output")
        .arg("json")
        .current_dir(repo_root());
    command.args(extra_args);
    command.output().expect("run durable receipt helper")
}

fn capture_json(fixture: &str, extra_args: &[&str]) -> Value {
    let output = run_capture(fixture, extra_args);
    assert!(
        output.status.success(),
        "capture helper failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("capture output JSON")
}

fn array<'a>(value: &'a Value, key: &str) -> &'a Vec<Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
}

fn string<'a>(value: &'a Value, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"))
}

fn string_list(value: &Value, key: &str) -> Vec<String> {
    array(value, key)
        .iter()
        .map(|entry| entry.as_str().expect("string entry").to_string())
        .collect()
}

fn fixture_names() -> [&'static str; 8] {
    [
        "terminal_pass.json",
        "cargo_failure.json",
        "operator_canceled.json",
        "stale_progress_canceled.json",
        "heartbeat_stale_infra.json",
        "client_disconnected_partial.json",
        "local_fallback_refused.json",
        "oversized_output_redaction.json",
    ]
}

fn contract_allowed(key: &str) -> Vec<String> {
    string_list(&read_json(CONTRACT_PATH), key)
}

fn status_catalog() -> Vec<String> {
    array(&read_json(SNAPSHOT_PATH), "proof_evidence_status_catalog")
        .iter()
        .map(|status| string(status, "status").to_string())
        .collect()
}

#[test]
fn script_exists_and_help_is_non_mutating() {
    assert!(repo_path(SCRIPT_PATH).exists(), "receipt helper must exist");
    let output = Command::new("python3")
        .arg(repo_path(SCRIPT_PATH))
        .arg("--help")
        .current_dir(repo_root())
        .output()
        .expect("run helper --help");
    assert!(output.status.success(), "--help should succeed");
}

#[test]
fn golden_fixtures_cover_required_terminal_classifications() {
    let mut classifications = fixture_names()
        .iter()
        .map(|name| {
            let fixture = read_json(&format!("{FIXTURE_ROOT}/{name}"));
            string(&fixture["expected"], "terminal_classification").to_string()
        })
        .collect::<Vec<_>>();
    classifications.sort();
    classifications.dedup();

    assert_eq!(
        classifications,
        vec![
            "cargo_failure",
            "client_disconnected_partial",
            "heartbeat_stale_infra",
            "local_fallback_refused",
            "operator_canceled",
            "pass",
            "stale_progress_canceled",
        ]
    );
    assert!(
        repo_path(&format!("{FIXTURE_ROOT}/oversized_output_redaction.json")).exists(),
        "oversized redaction fixture must be present"
    );
}

#[test]
fn generated_receipts_match_golden_expectations() {
    let allowed_lifecycle = contract_allowed("allowed_lifecycle_states");
    let allowed_classifications = contract_allowed("terminal_classifications");
    let allowed_statuses = status_catalog();

    for fixture_name in fixture_names() {
        let fixture = read_json(&format!("{FIXTURE_ROOT}/{fixture_name}"));
        let expected = &fixture["expected"];
        let receipt = capture_json(fixture_name, &[]);

        assert_eq!(
            receipt["schema_version"].as_str(),
            Some("durable-rch-proof-receipt-v1")
        );
        assert_eq!(receipt["generated_at"].as_str(), Some(GENERATED_AT));
        assert_eq!(
            receipt["lifecycle_state"].as_str(),
            expected["lifecycle_state"].as_str(),
            "{fixture_name}: lifecycle_state"
        );
        assert_eq!(
            receipt["terminal_classification"].as_str(),
            expected["terminal_classification"].as_str(),
            "{fixture_name}: terminal_classification"
        );
        assert_eq!(
            receipt["proof_evidence_status"].as_str(),
            expected["proof_evidence_status"].as_str(),
            "{fixture_name}: proof_evidence_status"
        );
        assert_eq!(
            receipt["outcome"]["status"].as_str(),
            expected["outcome_status"].as_str(),
            "{fixture_name}: outcome.status"
        );
        assert_eq!(
            receipt["outcome"]["exit_code"].as_i64(),
            expected["exit_code"].as_i64(),
            "{fixture_name}: outcome.exit_code"
        );
        assert_eq!(
            receipt["claim_boundaries"]["citable"].as_bool(),
            expected["citable"].as_bool(),
            "{fixture_name}: citable"
        );
        assert_eq!(
            string_list(&receipt["claim_boundaries"], "refusal_reason_codes"),
            string_list(expected, "refusal_reason_codes"),
            "{fixture_name}: refusal reasons"
        );
        assert!(
            allowed_lifecycle.contains(&string(&receipt, "lifecycle_state").to_string()),
            "{fixture_name}: lifecycle must be in contract vocabulary"
        );
        assert!(
            allowed_classifications
                .contains(&string(&receipt, "terminal_classification").to_string()),
            "{fixture_name}: classification must be in contract vocabulary"
        );
        assert!(
            allowed_statuses.contains(&string(&receipt, "proof_evidence_status").to_string()),
            "{fixture_name}: proof status must be in snapshot catalog"
        );
        assert!(
            string(&receipt["outcome"], "output_digest").starts_with("sha256:"),
            "{fixture_name}: output digest"
        );
    }
}

#[test]
fn first_blocker_extraction_and_redaction_are_exact() {
    for fixture_name in fixture_names() {
        let fixture = read_json(&format!("{FIXTURE_ROOT}/{fixture_name}"));
        let expected = &fixture["expected"];
        let extra_args = if fixture_name == "oversized_output_redaction.json" {
            vec!["--max-blocker-lines", "3"]
        } else {
            Vec::new()
        };
        let receipt = capture_json(fixture_name, &extra_args);
        let lines = string_list(&receipt["outcome"], "first_blocker_lines");
        let joined = lines.join("\n");

        for needle in string_list(expected, "first_blocker_contains") {
            assert!(
                joined.contains(&needle),
                "{fixture_name}: first blocker must contain {needle:?}; got {joined:?}"
            );
        }
        for forbidden in string_list(expected, "first_blocker_forbidden") {
            assert!(
                !joined.contains(&forbidden),
                "{fixture_name}: first blocker leaked forbidden text {forbidden:?}"
            );
        }
        assert!(
            lines.len()
                <= expected["max_first_blocker_lines"]
                    .as_u64()
                    .expect("max lines") as usize,
            "{fixture_name}: first blocker line bound"
        );
    }
}

#[test]
fn receipt_ids_and_output_digests_are_stable() {
    let left = capture_json("cargo_failure.json", &[]);
    let right = capture_json("cargo_failure.json", &[]);

    assert_eq!(left["receipt_id"], right["receipt_id"]);
    assert_eq!(
        left["outcome"]["output_digest"],
        right["outcome"]["output_digest"]
    );
}

#[test]
fn generated_receipts_have_all_schema_required_sections() {
    let contract = read_json(CONTRACT_PATH);
    let required_sections = string_list(&contract, "required_receipt_sections");

    for fixture_name in fixture_names() {
        let receipt = capture_json(fixture_name, &[]);
        for section in &required_sections {
            assert!(
                receipt.get(section).is_some(),
                "{fixture_name}: missing required receipt section {section}"
            );
        }
    }
}
