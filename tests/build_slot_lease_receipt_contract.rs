#![allow(missing_docs)]

use serde_json::Value as JsonValue;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const ARTIFACT_PATH: &str = "artifacts/build_slot_lease_receipt_contract_v1.json";
const CONTRACT_TEST: &str = "tests/build_slot_lease_receipt_contract.rs";
const REQUIRED_DECISIONS: [&str; 7] = [
    "accept_lease",
    "warn_expiring_soon",
    "fail_closed_expired",
    "fail_closed_exclusive_conflict",
    "fail_closed_missing_release",
    "fail_closed_stale_observation",
    "fail_closed_malformed_receipt",
];

#[derive(Debug, Clone, PartialEq, Eq)]
struct LeaseDecision {
    decision: String,
    rule_id: String,
    issue_kind: String,
}

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn artifact() -> JsonValue {
    let path = repo_path(ARTIFACT_PATH);
    let body = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    serde_json::from_str(&body).unwrap_or_else(|err| panic!("parse {}: {err}", path.display()))
}

fn array<'a>(value: &'a JsonValue, key: &str) -> &'a Vec<JsonValue> {
    value
        .get(key)
        .and_then(JsonValue::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
}

fn nested<'a>(value: &'a JsonValue, key: &str) -> &'a JsonValue {
    value
        .get(key)
        .unwrap_or_else(|| panic!("missing required object {key}"))
}

fn string<'a>(value: &'a JsonValue, key: &str) -> &'a str {
    let item = value
        .get(key)
        .and_then(JsonValue::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"));
    assert!(!item.trim().is_empty(), "{key} must be nonempty");
    item
}

fn optional_string<'a>(value: &'a JsonValue, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(JsonValue::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"))
}

fn bool_value(value: &JsonValue, key: &str) -> bool {
    value
        .get(key)
        .and_then(JsonValue::as_bool)
        .unwrap_or_else(|| panic!("{key} must be a bool"))
}

fn u64_value(value: &JsonValue, key: &str) -> u64 {
    value
        .get(key)
        .and_then(JsonValue::as_u64)
        .unwrap_or_else(|| panic!("{key} must be an unsigned integer"))
}

fn string_set(value: &JsonValue, key: &str) -> BTreeSet<String> {
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

fn timestamp_utc(value: &JsonValue, key: &str) {
    let timestamp = string(value, key);
    assert!(
        timestamp.ends_with('Z') && timestamp.contains('T'),
        "{key} must be a UTC timestamp ending in Z: {timestamp}"
    );
}

fn expected_decision(scenario: &JsonValue) -> LeaseDecision {
    let expected = nested(scenario, "expected_decision");
    LeaseDecision {
        decision: string(expected, "decision").to_string(),
        rule_id: string(expected, "rule_id").to_string(),
        issue_kind: optional_string(expected, "issue_kind").to_string(),
    }
}

fn scenario_by_id<'a>(artifact: &'a JsonValue, scenario_id: &str) -> &'a JsonValue {
    array(artifact, "scenarios")
        .iter()
        .find(|scenario| {
            scenario.get("scenario_id").and_then(JsonValue::as_str) == Some(scenario_id)
        })
        .unwrap_or_else(|| panic!("missing scenario {scenario_id}"))
}

fn evaluate_scenario(scenario: &JsonValue, artifact: &JsonValue) -> LeaseDecision {
    if string(scenario, "receipt_status") == "malformed" {
        return LeaseDecision {
            decision: "fail_closed_malformed_receipt".to_string(),
            rule_id: "malformed-receipt".to_string(),
            issue_kind: "malformed_receipt".to_string(),
        };
    }

    let max_age = u64_value(
        nested(artifact, "freshness_policy"),
        "max_observation_age_seconds",
    );
    if u64_value(scenario, "observation_age_seconds") > max_age {
        return LeaseDecision {
            decision: "fail_closed_stale_observation".to_string(),
            rule_id: "stale-observation".to_string(),
            issue_kind: "stale_observation".to_string(),
        };
    }

    if string(scenario, "lease_state") == "expired"
        || u64_value(scenario, "seconds_until_expiry") == 0
    {
        return LeaseDecision {
            decision: "fail_closed_expired".to_string(),
            rule_id: "expired-lease".to_string(),
            issue_kind: "expired_lease".to_string(),
        };
    }

    if bool_value(scenario, "exclusive") && !array(scenario, "conflicts").is_empty() {
        return LeaseDecision {
            decision: "fail_closed_exclusive_conflict".to_string(),
            rule_id: "exclusive-conflict".to_string(),
            issue_kind: "exclusive_conflict".to_string(),
        };
    }

    if bool_value(scenario, "release_required") && !bool_value(scenario, "release_observed") {
        return LeaseDecision {
            decision: "fail_closed_missing_release".to_string(),
            rule_id: "missing-release".to_string(),
            issue_kind: "missing_release".to_string(),
        };
    }

    let renew_before = u64_value(
        nested(artifact, "freshness_policy"),
        "renew_before_expiry_seconds",
    );
    if u64_value(scenario, "seconds_until_expiry") <= renew_before {
        return LeaseDecision {
            decision: "warn_expiring_soon".to_string(),
            rule_id: "expiring-soon".to_string(),
            issue_kind: "lease_expiring_soon".to_string(),
        };
    }

    LeaseDecision {
        decision: "accept_lease".to_string(),
        rule_id: "accept-lease".to_string(),
        issue_kind: String::new(),
    }
}

fn required_receipt_field_present(receipt: &JsonValue, field: &str) -> bool {
    receipt.get(field).is_some_and(|value| match value {
        JsonValue::String(s) => !s.trim().is_empty() || field == "issue_kind",
        JsonValue::Array(items) => !items.is_empty() || matches!(field, "conflicts" | "holders"),
        JsonValue::Object(items) => !items.is_empty(),
        JsonValue::Bool(_) | JsonValue::Number(_) => true,
        JsonValue::Null => false,
    })
}

#[test]
fn artifact_declares_schema_paths_and_report_only_policy() {
    let artifact = artifact();

    assert_eq!(
        artifact.get("schema_version").and_then(JsonValue::as_str),
        Some("build-slot-lease-receipt-contract-v1")
    );
    assert_eq!(
        artifact.get("bead_id").and_then(JsonValue::as_str),
        Some("asupersync-vjc3pv.7")
    );
    assert_eq!(
        artifact.get("capability_id").and_then(JsonValue::as_str),
        Some("build_slot_lease_receipts")
    );
    assert_eq!(string(&artifact, "artifact_path"), ARTIFACT_PATH);
    assert_eq!(string(&artifact, "contract_test"), CONTRACT_TEST);
    timestamp_utc(&artifact, "generated_at_utc");

    for path_key in ["artifact_path", "contract_test"] {
        let path = string(&artifact, path_key);
        assert!(
            repo_path(path).is_file(),
            "{path_key} path must exist: {path}"
        );
    }

    let policy = nested(&artifact, "side_effect_policy");
    assert_eq!(string(policy, "mode"), "report_only");
    for key in [
        "beads_mutation_allowed",
        "agent_mail_mutation_allowed",
        "filesystem_cleanup_allowed",
        "cargo_execution_allowed",
        "local_cargo_fallback_allowed",
    ] {
        assert!(!bool_value(policy, key), "{key} must be false");
    }
}

#[test]
fn receipt_schema_covers_required_fields_and_decisions() {
    let artifact = artifact();
    let fields = string_set(&artifact, "required_receipt_fields");
    let command_fields = string_set(&artifact, "required_command_context_fields");
    let decisions = string_set(&artifact, "required_decision_outputs");

    for field in [
        "slot_name",
        "requester_agent",
        "exclusive",
        "acquired_at_utc",
        "expires_at_utc",
        "observed_at_utc",
        "observation_age_seconds",
        "ttl_seconds",
        "lease_state",
        "seconds_until_expiry",
        "holders",
        "conflicts",
        "release_required",
        "release_observed",
        "command_context",
        "expected_decision",
    ] {
        assert!(fields.contains(field), "missing receipt field {field}");
    }

    for field in [
        "remote_required",
        "local_fallback_detected",
        "cargo_target_dir",
        "validation_command",
    ] {
        assert!(
            command_fields.contains(field),
            "missing command context field {field}"
        );
    }

    for decision in REQUIRED_DECISIONS {
        assert!(decisions.contains(decision), "missing decision {decision}");
    }
    assert_eq!(decisions.len(), REQUIRED_DECISIONS.len());
}

#[test]
fn every_scenario_has_complete_receipt_shape() {
    let artifact = artifact();
    let fields = string_set(&artifact, "required_receipt_fields");
    let command_fields = string_set(&artifact, "required_command_context_fields");

    for scenario in array(&artifact, "scenarios") {
        let scenario_id = string(scenario, "scenario_id");
        timestamp_utc(scenario, "acquired_at_utc");
        timestamp_utc(scenario, "expires_at_utc");
        timestamp_utc(scenario, "observed_at_utc");

        for field in &fields {
            assert!(
                required_receipt_field_present(scenario, field),
                "{scenario_id} missing required receipt field {field}"
            );
        }

        let command_context = nested(scenario, "command_context");
        for field in &command_fields {
            assert!(
                required_receipt_field_present(command_context, field),
                "{scenario_id} missing command context field {field}"
            );
        }
        assert!(
            bool_value(command_context, "remote_required"),
            "{scenario_id} must require remote validation"
        );
        assert!(
            !bool_value(command_context, "local_fallback_detected"),
            "{scenario_id} must not contain a local fallback marker"
        );

        if string(scenario, "receipt_status") == "complete"
            && matches!(string(scenario, "lease_state"), "active" | "expired")
        {
            assert!(
                !array(scenario, "holders").is_empty(),
                "{scenario_id} must name observed lease holders"
            );
        }
    }
}

#[test]
fn scenarios_cover_each_decision_output_once() {
    let artifact = artifact();
    let decisions: BTreeSet<_> = array(&artifact, "scenarios")
        .iter()
        .map(|scenario| expected_decision(scenario).decision)
        .collect();

    for decision in REQUIRED_DECISIONS {
        assert!(decisions.contains(decision), "missing scenario {decision}");
    }
    assert_eq!(
        decisions.len(),
        REQUIRED_DECISIONS.len(),
        "unexpected decision coverage drift"
    );
}

#[test]
fn decision_precedence_matches_contract_rules() {
    let artifact = artifact();
    for scenario in array(&artifact, "scenarios") {
        assert_eq!(
            evaluate_scenario(scenario, &artifact),
            expected_decision(scenario),
            "{} decision drift",
            string(scenario, "scenario_id")
        );
    }

    let stale = scenario_by_id(&artifact, "BUILD-SLOT-LEASE-STALE-OBSERVATION");
    assert_eq!(
        evaluate_scenario(stale, &artifact).decision,
        "fail_closed_stale_observation",
        "stale observation must win before interpreting a possibly conflicted lease"
    );

    let missing_release = scenario_by_id(&artifact, "BUILD-SLOT-LEASE-MISSING-RELEASE");
    assert_eq!(
        evaluate_scenario(missing_release, &artifact).decision,
        "fail_closed_missing_release",
        "missing release must win before expiring-soon warning"
    );
}

#[test]
fn validation_lane_is_remote_required_and_forbids_local_fallback() {
    let artifact = artifact();
    let validation = nested(&artifact, "validation");
    let command = string(validation, "remote_required_contract_test");
    assert!(
        command.starts_with("RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR="),
        "contract test must force remote rch execution: {command}"
    );
    assert!(
        command.contains("cargo test -p asupersync --test build_slot_lease_receipt_contract"),
        "contract test command must target this integration test: {command}"
    );
    assert!(
        string(validation, "local_fallback_policy").contains("invalidates"),
        "local fallback policy must fail closed"
    );

    for forbidden in array(&artifact, "forbidden_command_fragments") {
        let forbidden = forbidden.as_str().expect("forbidden fragment string");
        assert!(
            !command.contains(forbidden),
            "validation command must not contain forbidden fragment {forbidden}"
        );
    }
}
