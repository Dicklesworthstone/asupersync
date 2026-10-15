#![allow(missing_docs)]

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const BEAD_ID: &str = "asupersync-idea-wizard-fifth-wave-3gaiun.3.4";
const CONTRACT_PATH: &str = "artifacts/semantic_lint_proof_lane_contract_v1.json";
const DOCS_PATH: &str = "docs/semantic_lint_proof_lane.md";
const EVENTS_PATH: &str = "artifacts/semantic_lint_proof_lane_events_v1.ndjson";
const GUARANTEE_ID: &str = "semantic-lint-proof-lane-contract";
const LANE_ID: &str = "semantic-lint-proof-lane-contract";
const MANIFEST_PATH: &str = "artifacts/proof_lane_manifest_v1.json";
const PROJECTION_PATH: &str = "tests/fixtures/proof_lane_manifest/manifest_projection.json";
const RULE_INVENTORY_PATH: &str = "artifacts/semantic_lint_rule_inventory_v1.json";
const SUMMARY_PATH: &str = "artifacts/semantic_lint_proof_lane_summary_v1.json";

const PROOF_COMMAND: &str = "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_semantic_lint_proof_lane CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -j 1 -p asupersync --test semantic_lint_proof_lane_contract --test semantic_lint_rule_inventory_contract --test semantic_lint_diagnostic_codes_contract --test error_code_registry_contract --test semantic_lint_ambient_contract --test semantic_lint_cleanup_budget_contract --test semantic_lint_core_tokio_contract --test semantic_lint_loop_checkpoint_contract --test semantic_lint_ignored_outcome_contract --test semantic_lint_await_holding_contract --test semantic_lint_drop_race_loser_contract -- --nocapture";

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_repo_file(relative: &str) -> String {
    std::fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|err| panic!("read {relative}: {err}"))
}

fn json(relative: &str) -> Value {
    serde_json::from_str(&read_repo_file(relative))
        .unwrap_or_else(|err| panic!("parse {relative}: {err}"))
}

fn array<'a>(value: &'a Value, key: &str) -> &'a Vec<Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
}

fn object<'a>(value: &'a Value, key: &str) -> &'a serde_json::Map<String, Value> {
    value
        .get(key)
        .and_then(Value::as_object)
        .unwrap_or_else(|| panic!("{key} must be an object"))
}

fn string<'a>(value: &'a Value, key: &str) -> &'a str {
    let text = value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"));
    assert!(!text.trim().is_empty(), "{key} must be nonempty");
    text
}

fn bool_field(value: &Value, key: &str) -> bool {
    value
        .get(key)
        .and_then(Value::as_bool)
        .unwrap_or_else(|| panic!("{key} must be a bool"))
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

fn find_by_id<'a>(rows: &'a [Value], key: &str, id: &str) -> &'a Value {
    rows.iter()
        .find(|row| row.get(key).and_then(Value::as_str) == Some(id))
        .unwrap_or_else(|| panic!("missing {key}={id}"))
}

fn contract() -> Value {
    json(CONTRACT_PATH)
}

fn rule_rows_by_id(value: &Value) -> BTreeMap<String, &Value> {
    array(value, "rule_contracts")
        .iter()
        .map(|row| (string(row, "rule_id").to_string(), row))
        .collect()
}

#[test]
fn contract_declares_sources_command_and_outputs() {
    let contract = contract();
    assert_eq!(
        contract["contract_version"].as_str(),
        Some("semantic-lint-proof-lane-contract-v1")
    );
    assert_eq!(contract["bead_id"].as_str(), Some(BEAD_ID));
    assert_eq!(contract["lane_id"].as_str(), Some(LANE_ID));
    assert_eq!(contract["guarantee_id"].as_str(), Some(GUARANTEE_ID));
    assert_eq!(contract["proof_command"].as_str(), Some(PROOF_COMMAND));

    let source = object(&contract, "source_of_truth");
    for key in [
        "contract",
        "summary",
        "events",
        "contract_test",
        "docs",
        "runner",
        "rule_inventory",
        "proof_lane_manifest",
        "manifest_projection",
        "diagnostic_codes_contract",
        "error_code_registry_contract",
    ] {
        let path = source
            .get(key)
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("source_of_truth.{key} must be a string"));
        assert!(
            repo_path(path).exists(),
            "source_of_truth.{key} must point to a live path: {path}"
        );
    }
    assert_eq!(
        source.get("contract").and_then(Value::as_str),
        Some(CONTRACT_PATH)
    );

    let outputs = object(&contract, "proof_outputs");
    assert_eq!(
        outputs.get("summary_artifact").and_then(Value::as_str),
        Some(SUMMARY_PATH)
    );
    assert_eq!(
        outputs.get("events_artifact").and_then(Value::as_str),
        Some(EVENTS_PATH)
    );
    assert_eq!(
        outputs.get("proof_evidence_status").and_then(Value::as_str),
        Some("rerun-required")
    );
    assert!(bool_field(
        &contract["proof_outputs"],
        "fresh_evidence_requires_exact_command"
    ));
}

#[test]
fn rule_contracts_cover_inventory_and_asup_codes() {
    let contract = contract();
    let inventory = json(RULE_INVENTORY_PATH);
    let required = string_set(&contract, "required_rule_ids");
    let inventory_required = string_set(&inventory, "required_rule_ids");
    assert_eq!(required, inventory_required);
    assert_eq!(required.len(), 7);

    let expected_codes = BTreeMap::from([
        ("ambient-time-or-entropy-in-lab-sensitive-code", "ASUP-E902"),
        ("await-while-holding-capability-resource", "ASUP-E903"),
        ("loop-without-cx-checkpoint", "ASUP-E904"),
        ("ignored-outcome-severity", "ASUP-E905"),
        ("drop-based-race-loser-handling", "ASUP-E906"),
        ("unbounded-cleanup-budget", "ASUP-E907"),
        ("core-tokio-feature-leakage", "ASUP-E908"),
    ]);
    let rows = rule_rows_by_id(&contract);
    assert_eq!(rows.keys().cloned().collect::<BTreeSet<_>>(), required);

    for (rule_id, expected_code) in expected_codes {
        let row = rows
            .get(rule_id)
            .unwrap_or_else(|| panic!("missing rule {rule_id}"));
        assert_eq!(string(row, "asup_code"), expected_code);
        for key in ["contract", "contract_test", "docs"] {
            let path = string(row, key);
            assert!(
                repo_path(path).exists(),
                "{rule_id}: {key} path missing: {path}"
            );
        }

        let fixture_classes = string_set(row, "fixture_classes");
        assert!(
            fixture_classes
                .iter()
                .any(|class| class.starts_with("positive")),
            "{rule_id}: positive fixture class required"
        );
        assert!(
            fixture_classes
                .iter()
                .any(|class| class.starts_with("negative")),
            "{rule_id}: negative fixture class required"
        );
        if rule_id != "core-tokio-feature-leakage" {
            assert!(fixture_classes.contains("valid_allow"));
            assert!(fixture_classes.contains("invalid_allow"));
        }
    }
}

#[test]
fn manifest_and_projection_map_aggregate_lane() {
    let manifest = json(MANIFEST_PATH);
    let projection = json(PROJECTION_PATH);

    assert!(
        string_set(&manifest, "required_guarantee_ids").contains(GUARANTEE_ID),
        "manifest must require the semantic lint aggregate guarantee"
    );

    for (label, value) in [("manifest", manifest), ("projection", projection)] {
        let lane = find_by_id(array(&value, "lanes"), "lane_id", LANE_ID);
        assert_eq!(lane["kind"].as_str(), Some("artifact_contract"), "{label}");
        assert_eq!(
            lane["resource_envelope_class"].as_str(),
            Some("artifact-contract-medium"),
            "{label}"
        );
        assert_eq!(lane["package"].as_str(), Some("asupersync"), "{label}");
        assert_eq!(lane["command"].as_str(), Some(PROOF_COMMAND), "{label}");
        assert!(string_set(lane, "guarantee_ids").contains(GUARANTEE_ID));
        assert!(string_set(lane, "source_paths").contains(CONTRACT_PATH));
        assert!(string_set(lane, "source_paths").contains(SUMMARY_PATH));
        assert!(string_set(lane, "source_paths").contains(EVENTS_PATH));
        assert!(string_set(lane, "source_paths").contains(DOCS_PATH));

        let guarantee = find_by_id(array(&value, "guarantees"), "guarantee_id", GUARANTEE_ID);
        assert!(string_set(guarantee, "lane_ids").contains(LANE_ID));
    }
}

#[test]
fn proof_command_runs_all_aggregate_contracts_remotely() {
    let contract = contract();
    assert!(PROOF_COMMAND.starts_with("RCH_REQUIRE_REMOTE=1 rch exec -- "));
    assert!(PROOF_COMMAND.contains("CARGO_TARGET_DIR="));
    assert!(PROOF_COMMAND.contains(" -j 1 "));

    for test_name in string_set(&contract, "aggregate_tests") {
        let marker = format!("--test {test_name}");
        assert!(
            PROOF_COMMAND.contains(&marker),
            "proof command missing aggregate test marker {marker}"
        );
    }
}

#[test]
fn summary_and_events_are_deterministic_rerun_required_artifacts() {
    let summary = json(SUMMARY_PATH);
    assert_eq!(
        summary["contract_version"].as_str(),
        Some("semantic-lint-proof-lane-summary-v1")
    );
    assert_eq!(summary["lane_id"].as_str(), Some(LANE_ID));
    assert_eq!(
        summary["proof_evidence_status"].as_str(),
        Some("rerun-required")
    );
    assert_eq!(summary["proof_command"].as_str(), Some(PROOF_COMMAND));
    assert_eq!(summary["event_artifact"].as_str(), Some(EVENTS_PATH));
    assert_eq!(summary["rule_count"].as_u64(), Some(7));
    assert_eq!(summary["aggregate_test_count"].as_u64(), Some(11));
    assert!(bool_field(
        &summary,
        "fresh_evidence_requires_exact_command"
    ));

    let events = read_repo_file(EVENTS_PATH);
    let mut expected_sequence = 1;
    for line in events.lines() {
        let event: Value = serde_json::from_str(line).expect("event line must be json");
        assert_eq!(
            event["schema_version"].as_str(),
            Some("semantic-lint-proof-lane-event-v1")
        );
        assert_eq!(event["sequence"].as_u64(), Some(expected_sequence));
        expected_sequence += 1;
    }
    assert_eq!(expected_sequence, 5, "expected four event rows");
}

#[test]
fn docs_and_contract_preserve_failure_rehearsal_and_no_claims() {
    let contract = contract();
    let docs = read_repo_file(DOCS_PATH);

    for marker in array(&contract, "docs_markers") {
        let marker = marker.as_str().expect("docs marker string");
        assert!(docs.contains(marker), "docs missing marker {marker}");
    }

    for required in [
        "Positive fixtures must fail",
        "Invalid allow-marker fixtures must fail",
        "Unsupported engines must fail closed",
        "ASUP-E908",
        "is not a formal proof of cancel-correctness",
        "does not certify broad workspace health",
        "release readiness",
        "live RCH fleet availability",
    ] {
        assert!(docs.contains(required), "docs missing {required}");
    }

    let failure_rehearsal = array(&contract, "failure_rehearsal")
        .iter()
        .map(|entry| entry.as_str().expect("failure rehearsal string"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(failure_rehearsal.contains("positive fixtures"));
    assert!(failure_rehearsal.contains("invalid allow-marker"));
    assert!(failure_rehearsal.contains("unsupported engines"));

    let no_claims = array(&contract, "no_claims")
        .iter()
        .map(|entry| entry.as_str().expect("no claim string"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(no_claims.contains("not a formal proof of cancel-correctness"));
    assert!(no_claims.contains("broad workspace health"));
    assert!(no_claims.contains("release readiness"));
    assert!(no_claims.contains("rerun-required"));
}
