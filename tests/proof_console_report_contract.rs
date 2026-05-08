#![allow(missing_docs)]

use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const CONTRACT_PATH: &str = "artifacts/proof_console_report_contract_v1.json";
const FRONTIER_PATH: &str = "artifacts/validation_frontier_ledger_schema_v1.json";
const MANIFEST_PATH: &str = "artifacts/proof_lane_manifest_v1.json";
const SNAPSHOT_PATH: &str = "artifacts/proof_status_snapshot_v1.json";

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

fn array<'a>(value: &'a Value, key: &str) -> &'a Vec<Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
}

fn string<'a>(value: &'a Value, key: &str) -> &'a str {
    let text = value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"));
    assert!(!text.trim().is_empty(), "{key} must be nonempty");
    text
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

fn contract() -> Value {
    json_file(CONTRACT_PATH)
}

fn allowed_set(contract: &Value, key: &str) -> BTreeSet<String> {
    string_set(contract, key)
}

fn required_report_keys(contract: &Value) -> BTreeSet<String> {
    string_set(contract, "required_report_fields")
}

fn valid_report() -> Value {
    json!({
        "schema_version": "proof-console-report-v1",
        "generated_at": "2026-05-08T12:00:00Z",
        "generator": {
            "name": "proof-console-contract-fixture",
            "mode": "contract-test"
        },
        "source_artifact_hashes": {
            "artifacts/proof_lane_manifest_v1.json": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "artifacts/proof_status_snapshot_v1.json": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "artifacts/validation_frontier_ledger_schema_v1.json": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
        },
        "summary": {
            "claim_count": 1,
            "lane_count": 1,
            "green_claim_count": 1,
            "yellow_claim_count": 0,
            "red_claim_count": 0,
            "stale_blocker_count": 0,
            "unsupported_broad_claim_count": 0,
            "unclassified_rch_outcome_count": 0
        },
        "claim_rows": [
            {
                "claim_id": "no-tokio-production-graph",
                "category": "no-Tokio production graph",
                "status": "green",
                "manifest_lane_ids": ["default-production-tokio-tree"],
                "manifest_guarantee_ids": ["default-production-tokio-free"],
                "proof_commands": ["rch exec -- cargo tree -e normal -p asupersync -i tokio"],
                "blocked_frontier": null,
                "doc_claim_markers": {
                    "README.md": ["default production graph has no normal-edge dependency on tokio"],
                    "AGENTS.md": ["default production runtime crate"]
                },
                "broad_claim": false
            }
        ],
        "lane_rows": [
            {
                "lane_id": "default-production-tokio-tree",
                "kind": "dependency_graph",
                "command": "rch exec -- cargo tree -e normal -p asupersync -i tokio",
                "guarantee_ids": ["default-production-tokio-free"],
                "expected_signal": "warning: nothing to print.",
                "status": "pass",
                "explicit_not_covered": "Workspace, dev-dependency, fuzz, conformance, and asupersync-tokio-compat graphs are outside this production proof."
            }
        ],
        "rch_outcomes": [
            {
                "command": "rch exec -- cargo tree -e normal -p asupersync -i tokio",
                "outcome_class": "pass",
                "remote_exit_status": 0,
                "first_blocker": null
            }
        ],
        "failure_reasons": [],
        "verdict": "pass"
    })
}

fn validate_report(contract: &Value, report: &Value) -> Vec<String> {
    let mut failures = Vec::new();

    for key in required_report_keys(contract) {
        if report.get(&key).is_none() {
            failures.push(format!("missing-report-field:{key}"));
        }
    }

    let allowed_lane_statuses = allowed_set(contract, "allowed_lane_statuses");
    let allowed_claim_statuses = allowed_set(contract, "allowed_claim_statuses");
    let allowed_outcomes = allowed_set(contract, "allowed_rch_outcome_classes");

    for field in string_set(contract, "summary_required_fields") {
        if report["summary"].get(&field).is_none() {
            failures.push(format!("missing-summary-field:{field}"));
        }
    }

    for path in [MANIFEST_PATH, SNAPSHOT_PATH, FRONTIER_PATH] {
        let hash = report["source_artifact_hashes"]
            .get(path)
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !hash.starts_with("sha256:") || hash.len() != "sha256:".len() + 64 {
            failures.push(format!("missing-source-artifact-hash:{path}"));
        }
    }

    for row in array(report, "claim_rows") {
        let claim_id = string(row, "claim_id");
        for field in string_set(contract, "claim_row_required_fields") {
            if row.get(&field).is_none() {
                failures.push(format!("missing-claim-field:{claim_id}:{field}"));
            }
        }

        let status = string(row, "status");
        if !allowed_claim_statuses.contains(status) {
            failures.push(format!("unknown-claim-status:{claim_id}:{status}"));
        }

        if row.get("broad_claim").and_then(Value::as_bool) == Some(true) {
            failures.push(format!("unsupported-broad-claim:{claim_id}"));
        }

        if status == "red_blocked_external" {
            let blocked = &row["blocked_frontier"];
            let generated_at = blocked
                .get("generated_at")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let first_failure = &blocked["first_failure"];
            let line = first_failure.get("line").and_then(Value::as_u64);
            let file = first_failure
                .get("file")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if generated_at < "2026-05-08T00:00:00Z" || file.is_empty() || line.is_none() {
                failures.push(format!("stale-blocker-row:{claim_id}"));
            }
        }
    }

    for row in array(report, "lane_rows") {
        let lane_id = string(row, "lane_id");
        for field in string_set(contract, "lane_row_required_fields") {
            if row.get(&field).is_none() {
                failures.push(format!("missing-lane-field:{lane_id}:{field}"));
            }
        }

        let Some(status) = row.get("status").and_then(Value::as_str) else {
            failures.push(format!("missing-lane-status:{lane_id}"));
            continue;
        };
        if !allowed_lane_statuses.contains(status) {
            failures.push(format!("unknown-lane-status:{lane_id}:{status}"));
        }
    }

    for outcome in array(report, "rch_outcomes") {
        let command = string(outcome, "command");
        let outcome_class = outcome
            .get("outcome_class")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !allowed_outcomes.contains(outcome_class) {
            failures.push(format!("unclassified-rch-outcome:{command}"));
        }
    }

    failures
}

#[test]
fn contract_declares_sources_and_report_artifact_path() {
    let contract = contract();

    assert_eq!(
        contract.get("contract_version").and_then(Value::as_str),
        Some("proof-console-report-contract-v1")
    );
    assert_eq!(
        contract.get("bead_id").and_then(Value::as_str),
        Some("asupersync-xeh8m0.1")
    );
    assert_eq!(
        contract["generated_report"]["artifact_path"].as_str(),
        Some("target/proof-console/proof_console_report_v1.json")
    );
    assert_eq!(
        contract["generated_report"]["schema_version"].as_str(),
        Some("proof-console-report-v1")
    );

    let source = contract
        .get("source_of_truth")
        .expect("source_of_truth object");
    for path in [
        "contract",
        "contract_test",
        "proof_lane_manifest",
        "proof_lane_manifest_verifier",
        "proof_status_snapshot",
        "proof_status_snapshot_verifier",
        "validation_frontier_ledger",
    ] {
        let relative = string(source, path);
        assert!(
            repo_path(relative).exists(),
            "source_of_truth.{path} must point to a live repo file: {relative}"
        );
    }
}

#[test]
fn contract_names_fail_closed_conditions_for_operator_review() {
    let contract = contract();
    let reasons = array(&contract, "fail_closed_conditions")
        .iter()
        .map(|row| string(row, "reason_id").to_string())
        .collect::<BTreeSet<_>>();

    for required in [
        "missing-lane-status",
        "stale-blocker-row",
        "unsupported-broad-claim",
        "unclassified-rch-outcome",
        "missing-source-artifact-hash",
        "raw-coordination-data",
    ] {
        assert!(reasons.contains(required), "missing reason {required}");
    }
}

#[test]
fn valid_report_shape_passes_contract_validator() {
    let contract = contract();
    let failures = validate_report(&contract, &valid_report());
    assert!(failures.is_empty(), "unexpected failures: {failures:?}");
}

#[test]
fn missing_lane_status_is_rejected() {
    let contract = contract();
    let mut report = valid_report();
    report["lane_rows"][0]
        .as_object_mut()
        .expect("lane row object")
        .remove("status");

    let failures = validate_report(&contract, &report);
    assert!(
        failures
            .iter()
            .any(|failure| failure.starts_with("missing-lane-status:")),
        "missing lane status must fail closed: {failures:?}"
    );
}

#[test]
fn stale_blocker_rows_are_rejected() {
    let contract = contract();
    let mut report = valid_report();
    report["summary"]["red_claim_count"] = json!(1);
    report["summary"]["green_claim_count"] = json!(0);
    report["summary"]["stale_blocker_count"] = json!(1);
    report["claim_rows"][0]["status"] = json!("red_blocked_external");
    report["claim_rows"][0]["blocked_frontier"] = json!({
        "generated_at": "2026-05-01T00:00:00Z",
        "command": "rch exec -- cargo test -p asupersync --lib",
        "first_failure": {
            "file": "src/runtime/scheduler/three_lane.rs",
            "line": 0
        }
    });
    report["verdict"] = json!("fail_closed");

    let failures = validate_report(&contract, &report);
    assert!(
        failures
            .iter()
            .any(|failure| failure.starts_with("stale-blocker-row:")),
        "stale blocker rows must fail closed: {failures:?}"
    );
}

#[test]
fn unsupported_broad_claims_are_rejected() {
    let contract = contract();
    let mut report = valid_report();
    report["summary"]["unsupported_broad_claim_count"] = json!(1);
    report["claim_rows"][0]["broad_claim"] = json!(true);
    report["verdict"] = json!("fail_closed");

    let failures = validate_report(&contract, &report);
    assert!(
        failures
            .iter()
            .any(|failure| failure.starts_with("unsupported-broad-claim:")),
        "unsupported broad claims must fail closed: {failures:?}"
    );
}

#[test]
fn unclassified_rch_outcomes_are_rejected() {
    let contract = contract();
    let mut report = valid_report();
    report["summary"]["unclassified_rch_outcome_count"] = json!(1);
    report["rch_outcomes"][0]["outcome_class"] = json!("mystery-wrapper-state");
    report["verdict"] = json!("fail_closed");

    let failures = validate_report(&contract, &report);
    assert!(
        failures
            .iter()
            .any(|failure| failure.starts_with("unclassified-rch-outcome:")),
        "unclassified rch outcomes must fail closed: {failures:?}"
    );
}

#[test]
fn proof_commands_are_rch_routed_and_include_existing_manifest_snapshot_gates() {
    let contract = contract();
    let commands = string_set(&contract, "proof_commands");

    for command in &commands {
        assert!(
            command.starts_with("rch exec -- "),
            "proof command must be rch-routed: {command}"
        );
    }
    assert!(
        commands
            .iter()
            .any(|command| command.contains("--test proof_console_report_contract")),
        "contract must name its own proof lane"
    );
    assert!(
        commands.iter().any(
            |command| command.contains("--test proof_lane_manifest_contract")
                && command.contains("--test proof_status_snapshot_contract")
        ),
        "contract must retain manifest and snapshot proof gates"
    );
}
