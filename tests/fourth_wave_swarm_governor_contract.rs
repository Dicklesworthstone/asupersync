#![allow(missing_docs)]

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const CONTRACT_PATH: &str = "artifacts/fourth_wave_swarm_governor_contract_v1.json";
const SNAPSHOT_SCHEMA: &str = "asupersync.fourth-wave.pressure-snapshot.v1";
const RECEIPT_SCHEMA: &str = "asupersync.fourth-wave.governor-decision-receipt.v1";
const POLICY_VERSION: &str = "fourth-wave-governor-policy-v1";

#[derive(Debug, Clone, PartialEq, Eq)]
struct Decision {
    selected_action: String,
    rule_id: String,
    fail_closed: bool,
}

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_text(relative: &str) -> String {
    std::fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|error| panic!("read {relative}: {error}"))
}

fn artifact() -> Value {
    serde_json::from_str(&read_text(CONTRACT_PATH))
        .unwrap_or_else(|error| panic!("parse {CONTRACT_PATH}: {error}"))
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

fn optional_string<'a>(value: &'a Value, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"))
}

fn bool_field(value: &Value, key: &str) -> bool {
    value
        .get(key)
        .and_then(Value::as_bool)
        .unwrap_or_else(|| panic!("{key} must be a bool"))
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
        .map(|entry| {
            entry
                .as_str()
                .unwrap_or_else(|| panic!("{key} entries must be strings"))
                .to_string()
        })
        .collect()
}

fn object_string_set(value: &Value, key: &str) -> BTreeSet<String> {
    object(value, key).keys().cloned().collect()
}

fn schema<'a>(artifact: &'a Value, name: &str) -> &'a Value {
    artifact
        .get("schema_definitions")
        .and_then(|schemas| schemas.get(name))
        .unwrap_or_else(|| panic!("schema definition missing: {name}"))
}

fn pressure_snapshot(scenario: &Value) -> &Value {
    scenario
        .get("pressure_snapshot")
        .expect("scenario pressure_snapshot")
}

fn decision_receipt(scenario: &Value) -> &Value {
    scenario
        .get("decision_receipt")
        .expect("scenario decision_receipt")
}

fn source_classes(snapshot: &Value) -> BTreeSet<String> {
    array(snapshot, "evidence_rows")
        .iter()
        .map(|row| string(row, "source_class").to_string())
        .collect()
}

fn has_local_fallback(snapshot: &Value) -> bool {
    bool_field(
        snapshot
            .get("rch_admission_state")
            .expect("rch_admission_state"),
        "local_fallback_marker_detected",
    ) || array(snapshot, "evidence_rows")
        .iter()
        .any(|row| bool_field(row, "local_fallback_marker_detected"))
}

fn has_stale_evidence(snapshot: &Value, max_age: u64) -> bool {
    array(snapshot, "evidence_rows")
        .iter()
        .any(|row| u64_field(row, "evidence_age_seconds") > max_age)
}

fn is_advisory_only(snapshot: &Value) -> bool {
    let rows = array(snapshot, "evidence_rows");
    !rows.is_empty()
        && rows
            .iter()
            .all(|row| string(row, "claim_status") == "advisory_only")
        && !bool_field(
            snapshot
                .get("lab_replay_metadata")
                .expect("lab_replay_metadata"),
            "replay_backed",
        )
}

fn exceeds_brownout_threshold(snapshot: &Value) -> bool {
    u64_field(
        snapshot.get("memory_envelope").expect("memory_envelope"),
        "memory_pressure_bps",
    ) >= 9_000
        || u64_field(
            snapshot.get("core_envelope").expect("core_envelope"),
            "local_core_pressure_bps",
        ) >= 9_000
        || u64_field(
            snapshot
                .get("active_region_pressure")
                .expect("active_region_pressure"),
            "region_pressure_bps",
        ) >= 9_000
        || u64_field(
            snapshot
                .get("obligation_pressure")
                .expect("obligation_pressure"),
            "obligation_pressure_bps",
        ) >= 9_000
}

fn evaluate_scenario(
    scenario: &Value,
    required_inputs: &BTreeSet<String>,
    max_age: u64,
) -> Decision {
    let snapshot = pressure_snapshot(scenario);
    if string(snapshot, "input_status") != "complete" {
        return Decision {
            selected_action: "fail_closed_malformed_input".to_string(),
            rule_id: "malformed-input".to_string(),
            fail_closed: true,
        };
    }

    let present = source_classes(snapshot);
    if required_inputs.difference(&present).next().is_some() {
        return Decision {
            selected_action: "fail_closed_missing_evidence".to_string(),
            rule_id: "missing-required-evidence".to_string(),
            fail_closed: true,
        };
    }

    if has_local_fallback(snapshot) {
        return Decision {
            selected_action: "fail_closed_local_rch_fallback".to_string(),
            rule_id: "local-rch-fallback".to_string(),
            fail_closed: true,
        };
    }

    if has_stale_evidence(snapshot, max_age) {
        return Decision {
            selected_action: "fail_closed_stale_evidence".to_string(),
            rule_id: "stale-evidence".to_string(),
            fail_closed: true,
        };
    }

    if is_advisory_only(snapshot) {
        return Decision {
            selected_action: "fail_closed_advisory_only".to_string(),
            rule_id: "advisory-only-evidence".to_string(),
            fail_closed: true,
        };
    }

    let rch = snapshot
        .get("rch_admission_state")
        .expect("rch_admission_state");
    if bool_field(rch, "remote_required") && !bool_field(rch, "workers_admissible") {
        return Decision {
            selected_action: "defer_no_remote_worker".to_string(),
            rule_id: "remote-required-no-worker".to_string(),
            fail_closed: false,
        };
    }

    if exceeds_brownout_threshold(snapshot) {
        return Decision {
            selected_action: "brownout_optional_work".to_string(),
            rule_id: "brownout-optional-work".to_string(),
            fail_closed: false,
        };
    }

    Decision {
        selected_action: "admit_required_work".to_string(),
        rule_id: "admit-required-work".to_string(),
        fail_closed: false,
    }
}

fn expected_decision(scenario: &Value) -> Decision {
    let receipt = decision_receipt(scenario);
    Decision {
        selected_action: string(receipt, "selected_action").to_string(),
        rule_id: string(receipt, "rule_id").to_string(),
        fail_closed: bool_field(receipt, "fail_closed"),
    }
}

fn assert_hash(value: &str, field: &str) {
    assert!(
        value.starts_with("sha256:") && value.len() == "sha256:".len() + 64,
        "{field} must be sha256:<64 lowercase hex>, got {value}"
    );
    assert!(
        value["sha256:".len()..]
            .chars()
            .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase()),
        "{field} must use lowercase hex"
    );
}

#[test]
fn artifact_declares_sources_boundaries_and_schema_versions() {
    let artifact = artifact();
    assert_eq!(
        artifact.get("schema_version").and_then(Value::as_str),
        Some("fourth-wave-swarm-governor-contract-v1")
    );
    assert_eq!(
        artifact.get("bead_id").and_then(Value::as_str),
        Some("asupersync-86fe9v.1")
    );
    assert_eq!(
        artifact.get("policy_version").and_then(Value::as_str),
        Some(POLICY_VERSION)
    );
    assert_eq!(
        artifact
            .get("pressure_snapshot_schema_version")
            .and_then(Value::as_str),
        Some(SNAPSHOT_SCHEMA)
    );
    assert_eq!(
        artifact
            .get("decision_receipt_schema_version")
            .and_then(Value::as_str),
        Some(RECEIPT_SCHEMA)
    );

    for path in object(&artifact, "source_of_truth").values() {
        let path = path.as_str().expect("source path string");
        assert!(repo_path(path).exists(), "source path must exist: {path}");
    }

    let boundary = artifact
        .get("proof_boundary")
        .expect("proof_boundary object");
    assert!(bool_field(boundary, "schema_contract_only"));
    for key in [
        "proves_policy_engine",
        "proves_runtime_bridge",
        "proves_real_host_throughput",
        "proves_scheduler_regression_closed",
        "proves_rch_fleet_health",
        "adaptive_control_enabled_by_default",
        "local_cargo_fallback_allowed",
        "core_runtime_stdout_stderr_added",
    ] {
        assert!(!bool_field(boundary, key), "{key} must remain false");
    }
}

#[test]
fn schema_definitions_cover_snapshot_receipt_evidence_and_logs() {
    let artifact = artifact();
    let snapshot = schema(&artifact, "pressure_snapshot");
    assert_eq!(
        snapshot.get("schema_version").and_then(Value::as_str),
        Some(SNAPSHOT_SCHEMA)
    );
    assert_eq!(
        string_set(snapshot, "required_sections"),
        BTreeSet::from([
            "active_region_pressure".to_string(),
            "bead_mail_workload_context".to_string(),
            "core_envelope".to_string(),
            "evidence_rows".to_string(),
            "input_artifact_hashes".to_string(),
            "lab_replay_metadata".to_string(),
            "memory_envelope".to_string(),
            "normalized_host_capacity".to_string(),
            "obligation_pressure".to_string(),
            "policy_version".to_string(),
            "rch_admission_state".to_string(),
            "snapshot_id".to_string(),
            "worker_envelope".to_string(),
        ])
    );
    assert_eq!(
        object_string_set(snapshot, "field_contract"),
        BTreeSet::from([
            "active_region_pressure".to_string(),
            "bead_mail_workload_context".to_string(),
            "core_envelope".to_string(),
            "lab_replay_metadata".to_string(),
            "memory_envelope".to_string(),
            "normalized_host_capacity".to_string(),
            "obligation_pressure".to_string(),
            "rch_admission_state".to_string(),
            "worker_envelope".to_string(),
        ])
    );

    let evidence_row = schema(&artifact, "evidence_row");
    assert_eq!(
        string_set(evidence_row, "required_fields"),
        BTreeSet::from([
            "claim_status".to_string(),
            "collected_timestamp_utc".to_string(),
            "confidence_bps".to_string(),
            "evidence_age_seconds".to_string(),
            "evidence_hash".to_string(),
            "freshness_status".to_string(),
            "local_fallback_marker_detected".to_string(),
            "redacted_subject".to_string(),
            "rejected_reason".to_string(),
            "source_class".to_string(),
            "source_id".to_string(),
            "source_schema_version".to_string(),
            "source_timestamp_utc".to_string(),
        ])
    );

    let receipt = schema(&artifact, "decision_receipt");
    assert_eq!(
        receipt.get("schema_version").and_then(Value::as_str),
        Some(RECEIPT_SCHEMA)
    );
    assert_eq!(
        string_set(receipt, "required_fields"),
        BTreeSet::from([
            "confidence_bps".to_string(),
            "decision_id".to_string(),
            "evidence_rows".to_string(),
            "fail_closed".to_string(),
            "input_artifact_hashes".to_string(),
            "log_fields".to_string(),
            "non_action_reason".to_string(),
            "non_claims".to_string(),
            "policy_version".to_string(),
            "rejected_rows".to_string(),
            "rule_id".to_string(),
            "selected_action".to_string(),
            "snapshot_id".to_string(),
        ])
    );

    assert_eq!(
        string_set(&artifact, "required_log_fields"),
        BTreeSet::from([
            "bead_id".to_string(),
            "decision_id".to_string(),
            "first_rejected_row_reason".to_string(),
            "input_artifact_hashes".to_string(),
            "policy_version".to_string(),
            "rejected_row_count".to_string(),
            "scenario_id".to_string(),
            "selected_action".to_string(),
            "snapshot_id".to_string(),
        ])
    );
}

#[test]
fn scenario_matrix_covers_decisions_and_deterministic_precedence() {
    let artifact = artifact();
    let required_inputs = string_set(&artifact, "required_input_classes");
    let allowed_actions = string_set(&artifact, "allowed_decision_actions");
    let max_age = u64_field(
        artifact.get("staleness_policy").expect("staleness_policy"),
        "max_evidence_age_seconds",
    );
    let priorities = array(&artifact, "decision_priority_order")
        .iter()
        .map(|rule| {
            (
                u64_field(rule, "priority"),
                string(rule, "rule_id").to_string(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        priorities.len(),
        array(&artifact, "decision_priority_order").len(),
        "decision priorities must be unique"
    );

    let mut covered_actions = BTreeSet::new();
    for scenario in array(&artifact, "scenarios") {
        let receipt = decision_receipt(scenario);
        covered_actions.insert(string(receipt, "selected_action").to_string());
        assert_eq!(
            evaluate_scenario(scenario, &required_inputs, max_age),
            expected_decision(scenario),
            "{} must follow the deterministic fail-closed precedence ladder",
            string(scenario, "scenario_id")
        );
    }
    assert_eq!(covered_actions, allowed_actions);
}

#[test]
fn scenarios_include_required_sections_fields_hashes_and_redaction() {
    let artifact = artifact();
    let snapshot_sections = string_set(schema(&artifact, "pressure_snapshot"), "required_sections");
    let field_contract = object(schema(&artifact, "pressure_snapshot"), "field_contract");
    let evidence_fields = string_set(schema(&artifact, "evidence_row"), "required_fields");
    let receipt_fields = string_set(schema(&artifact, "decision_receipt"), "required_fields");
    let log_fields = string_set(&artifact, "required_log_fields");
    let redaction = artifact.get("redaction_policy").expect("redaction_policy");
    let forbidden_subject_markers = array(redaction, "forbidden_subject_markers")
        .iter()
        .map(|entry| entry.as_str().expect("marker string"))
        .collect::<Vec<_>>();

    for scenario in array(&artifact, "scenarios") {
        let scenario_id = string(scenario, "scenario_id");
        let snapshot = pressure_snapshot(scenario);
        for section in &snapshot_sections {
            assert!(
                snapshot.get(section).is_some(),
                "{scenario_id}: missing snapshot section {section}"
            );
        }
        for (section, fields) in field_contract {
            let section_value = snapshot
                .get(section)
                .unwrap_or_else(|| panic!("{scenario_id}: section {section}"));
            for field in fields.as_array().expect("field list") {
                let field = field.as_str().expect("field name");
                assert!(
                    section_value.get(field).is_some(),
                    "{scenario_id}: {section}.{field} missing"
                );
            }
        }
        for hash in array(snapshot, "input_artifact_hashes") {
            assert_hash(
                hash.as_str().expect("input hash string"),
                "input_artifact_hash",
            );
        }

        for row in array(snapshot, "evidence_rows") {
            for field in &evidence_fields {
                assert!(
                    row.get(field).is_some(),
                    "{scenario_id}: evidence row missing {field}"
                );
            }
            assert_hash(string(row, "evidence_hash"), "evidence_hash");
            let subject = string(row, "redacted_subject");
            for marker in &forbidden_subject_markers {
                assert!(
                    !subject.contains(marker),
                    "{scenario_id}: redacted subject leaked marker {marker}: {subject}"
                );
            }
            if string(row, "source_class") == "rch_proof_lane" {
                assert!(
                    subject.starts_with("rch-worker://redacted/"),
                    "{scenario_id}: rch subject must be redacted: {subject}"
                );
            }
        }

        let receipt = decision_receipt(scenario);
        for field in &receipt_fields {
            assert!(
                receipt.get(field).is_some(),
                "{scenario_id}: receipt missing {field}"
            );
        }
        assert_eq!(string(receipt, "schema_version"), RECEIPT_SCHEMA);
        assert_eq!(string(receipt, "policy_version"), POLICY_VERSION);
        assert_eq!(
            string(receipt, "snapshot_id"),
            string(snapshot, "snapshot_id")
        );
        assert!(
            string(receipt, "decision_id").starts_with("fw-governor-decision/"),
            "{scenario_id}: deterministic decision id namespace"
        );
        for hash in array(receipt, "input_artifact_hashes") {
            assert_hash(
                hash.as_str().expect("receipt hash string"),
                "receipt input hash",
            );
        }
        let logs = object(receipt, "log_fields");
        for field in &log_fields {
            assert!(
                logs.get(field).is_some(),
                "{scenario_id}: log field missing {field}"
            );
        }
    }
}

#[test]
fn fail_closed_cases_preserve_rejected_reasons_and_non_claims() {
    let artifact = artifact();
    let expected = BTreeMap::from([
        (
            "FW-GOVERNOR-FAIL-ADVISORY-ONLY",
            ("fail_closed_advisory_only", "advisory-only-evidence"),
        ),
        (
            "FW-GOVERNOR-FAIL-LOCAL-RCH-FALLBACK",
            ("fail_closed_local_rch_fallback", "local-rch-fallback"),
        ),
        (
            "FW-GOVERNOR-FAIL-MALFORMED-INPUT",
            ("fail_closed_malformed_input", "malformed-input"),
        ),
        (
            "FW-GOVERNOR-FAIL-MISSING-EVIDENCE",
            ("fail_closed_missing_evidence", "missing-required-evidence"),
        ),
        (
            "FW-GOVERNOR-FAIL-STALE-EVIDENCE",
            ("fail_closed_stale_evidence", "stale-evidence"),
        ),
    ]);

    for scenario in array(&artifact, "scenarios") {
        let scenario_id = string(scenario, "scenario_id");
        let Some((action, rule_id)) = expected.get(scenario_id) else {
            continue;
        };
        let receipt = decision_receipt(scenario);
        assert!(bool_field(receipt, "fail_closed"), "{scenario_id}");
        assert_eq!(string(receipt, "selected_action"), *action);
        assert_eq!(string(receipt, "rule_id"), *rule_id);
        assert!(
            !array(receipt, "rejected_rows").is_empty(),
            "{scenario_id}: fail-closed receipt must retain rejected rows"
        );
        assert!(
            !optional_string(receipt, "non_action_reason").is_empty(),
            "{scenario_id}: fail-closed receipt must name why it did not act"
        );
        assert!(
            array(receipt, "non_claims").iter().any(|claim| claim
                .as_str()
                .unwrap_or_default()
                .contains("no runtime bridge")),
            "{scenario_id}: non-claims must preserve runtime bridge boundary"
        );
    }
}

#[test]
fn rows_and_scenarios_have_stable_rendering_order() {
    let artifact = artifact();
    let scenario_ids = array(&artifact, "scenarios")
        .iter()
        .map(|scenario| string(scenario, "scenario_id").to_string())
        .collect::<Vec<_>>();
    let mut sorted_scenarios = scenario_ids.clone();
    sorted_scenarios.sort();
    assert_eq!(
        scenario_ids, sorted_scenarios,
        "scenario order must be stable"
    );

    for scenario in array(&artifact, "scenarios") {
        let scenario_id = string(scenario, "scenario_id");
        let row_keys = array(pressure_snapshot(scenario), "evidence_rows")
            .iter()
            .map(|row| {
                format!(
                    "{}::{}",
                    string(row, "source_class"),
                    string(row, "source_id")
                )
            })
            .collect::<Vec<_>>();
        let mut sorted_rows = row_keys.clone();
        sorted_rows.sort();
        assert_eq!(
            row_keys, sorted_rows,
            "{scenario_id}: evidence rows must use stable source_class/source_id order"
        );
    }
}

#[test]
fn file_is_json_with_trailing_newline_and_no_local_fallback_permission() {
    let body = read_text(CONTRACT_PATH);
    assert!(
        body.ends_with('\n'),
        "contract artifact should end in newline"
    );
    assert!(
        !body.contains("local_cargo_fallback_allowed\": true"),
        "artifact must not authorize local Cargo fallback"
    );
    assert!(
        !body.contains("adaptive_control_enabled_by_default\": true"),
        "artifact must not enable adaptive controls by default"
    );
    let artifact = artifact();
    let non_claims = array(&artifact, "non_claims")
        .iter()
        .map(|entry| entry.as_str().expect("non-claim"))
        .collect::<Vec<_>>()
        .join("\n")
        .to_ascii_lowercase();
    for required in [
        "does not enable runtime admission",
        "does not prove real-host throughput",
        "does not authorize local cargo fallback",
        "does not mutate agent mail",
    ] {
        assert!(
            non_claims.contains(required),
            "non-claims must include {required:?}"
        );
    }
}
