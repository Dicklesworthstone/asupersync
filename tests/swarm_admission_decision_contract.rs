#![allow(missing_docs)]

use serde_json::Value as JsonValue;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const ARTIFACT_PATH: &str = "artifacts/swarm_admission_decision_contract_v1.json";
const REQUIRED_INPUT_CLASSES: [&str; 6] = [
    "capacity_snapshot",
    "proof_lane_status",
    "agent_mail_reservation_pressure",
    "beads_backlog_state",
    "host_pressure_snapshot",
    "rch_admissibility",
];
const REQUIRED_DECISION_OUTPUTS: [&str; 8] = [
    "admit_full",
    "brownout_degraded_optional",
    "no_win",
    "defer_tracker_blocked",
    "fail_closed_stale_evidence",
    "fail_closed_unsupported_host_data",
    "fail_closed_malformed_input",
    "fail_closed_local_rch_fallback",
];

#[derive(Debug, Clone, PartialEq, Eq)]
struct Decision {
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

fn nested<'a>(value: &'a JsonValue, key: &str) -> &'a JsonValue {
    value
        .get(key)
        .unwrap_or_else(|| panic!("missing required object {key}"))
}

fn max_age_seconds(artifact: &JsonValue) -> u64 {
    u64_value(
        nested(artifact, "staleness_policy"),
        "max_source_age_seconds",
    )
}

fn has_stale_evidence(scenario: &JsonValue, max_age: u64) -> bool {
    REQUIRED_INPUT_CLASSES
        .iter()
        .filter_map(|key| scenario.get(*key))
        .any(|input| {
            input
                .get("evidence_age_seconds")
                .and_then(JsonValue::as_u64)
                .is_some_and(|age| age > max_age)
        })
}

fn expected_decision(scenario: &JsonValue) -> Decision {
    let expected = nested(scenario, "expected_decision");
    Decision {
        decision: string(expected, "decision").to_string(),
        rule_id: string(expected, "rule_id").to_string(),
        issue_kind: optional_string(expected, "issue_kind").to_string(),
    }
}

fn evaluate_scenario(
    scenario: &JsonValue,
    allowed_pressure_sources: &BTreeSet<String>,
    max_age: u64,
) -> Decision {
    if string(scenario, "input_status") == "malformed" {
        return Decision {
            decision: "fail_closed_malformed_input".to_string(),
            rule_id: "malformed-input".to_string(),
            issue_kind: "malformed_input".to_string(),
        };
    }

    let host_pressure = nested(scenario, "host_pressure_snapshot");
    let pressure_source = string(host_pressure, "pressure_source");
    if !allowed_pressure_sources.contains(pressure_source) {
        return Decision {
            decision: "fail_closed_unsupported_host_data".to_string(),
            rule_id: "unsupported-pressure-source".to_string(),
            issue_kind: "unsupported_pressure_source".to_string(),
        };
    }

    let proof_lane = nested(scenario, "proof_lane_status");
    if bool_value(proof_lane, "local_fallback_marker_detected") {
        return Decision {
            decision: "fail_closed_local_rch_fallback".to_string(),
            rule_id: "local-rch-fallback".to_string(),
            issue_kind: "local_rch_fallback".to_string(),
        };
    }

    if has_stale_evidence(scenario, max_age) {
        return Decision {
            decision: "fail_closed_stale_evidence".to_string(),
            rule_id: "stale-evidence".to_string(),
            issue_kind: "stale_evidence".to_string(),
        };
    }

    let agent_mail = nested(scenario, "agent_mail_reservation_pressure");
    let beads = nested(scenario, "beads_backlog_state");
    if bool_value(agent_mail, "tracker_reserved") || !bool_value(beads, "tracker_writable") {
        return Decision {
            decision: "defer_tracker_blocked".to_string(),
            rule_id: "tracker-blocked".to_string(),
            issue_kind: "tracker_blocked".to_string(),
        };
    }

    let rch = nested(scenario, "rch_admissibility");
    if bool_value(rch, "remote_required") && !bool_value(rch, "workers_admissible") {
        return Decision {
            decision: "no_win".to_string(),
            rule_id: "remote-required-no-worker".to_string(),
            issue_kind: "remote_worker_unavailable".to_string(),
        };
    }

    if bool_value(host_pressure, "disk_critical")
        || u64_value(host_pressure, "memory_pressure_bps") >= 9_000
        || u64_value(host_pressure, "cpu_saturation_bps") >= 9_000
    {
        return Decision {
            decision: "brownout_degraded_optional".to_string(),
            rule_id: "brownout-pressure".to_string(),
            issue_kind: "brownout_pressure".to_string(),
        };
    }

    Decision {
        decision: "admit_full".to_string(),
        rule_id: "admit-full".to_string(),
        issue_kind: String::new(),
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

#[test]
fn artifact_declares_schema_sources_and_report_only_safety() {
    let artifact = artifact();
    assert_eq!(
        artifact.get("schema_version").and_then(JsonValue::as_str),
        Some("swarm-admission-decision-contract-v1")
    );
    assert_eq!(
        artifact.get("bead_id").and_then(JsonValue::as_str),
        Some("asupersync-vjc3pv.2")
    );
    assert_eq!(
        artifact.get("capability_id").and_then(JsonValue::as_str),
        Some("deterministic_swarm_admission_decision")
    );

    for path_key in ["artifact_path", "contract_test"] {
        let path = string(&artifact, path_key);
        assert!(
            repo_path(path).is_file(),
            "{path_key} path must exist: {path}"
        );
    }

    let side_effect_policy = nested(&artifact, "side_effect_policy");
    assert_eq!(string(side_effect_policy, "mode"), "report_only");
    for key in [
        "beads_mutation_allowed",
        "agent_mail_mutation_allowed",
        "filesystem_cleanup_allowed",
        "cargo_execution_allowed",
    ] {
        assert!(!bool_value(side_effect_policy, key), "{key} must be false");
    }

    for forbidden in string_set(&artifact, "forbidden_command_fragments") {
        assert!(
            !forbidden.trim().is_empty(),
            "forbidden fragment must be nonempty"
        );
    }
}

#[test]
fn scenario_matrix_covers_required_input_classes_and_decision_outputs() {
    let artifact = artifact();
    assert_eq!(
        string_set(&artifact, "required_input_classes"),
        REQUIRED_INPUT_CLASSES
            .into_iter()
            .map(String::from)
            .collect()
    );
    assert_eq!(
        string_set(&artifact, "required_decision_outputs"),
        REQUIRED_DECISION_OUTPUTS
            .into_iter()
            .map(String::from)
            .collect()
    );

    let mut covered_decisions = BTreeSet::new();
    for scenario in array(&artifact, "scenarios") {
        let scenario_id = string(scenario, "scenario_id");
        let expected = expected_decision(scenario);
        covered_decisions.insert(expected.decision.to_string());
        if string(scenario, "input_status") == "complete" {
            for key in REQUIRED_INPUT_CLASSES {
                assert!(
                    scenario.get(key).is_some(),
                    "{scenario_id} missing required input class {key}"
                );
            }
        }
    }

    assert_eq!(
        covered_decisions,
        REQUIRED_DECISION_OUTPUTS
            .into_iter()
            .map(String::from)
            .collect(),
        "scenario matrix must cover every decision output"
    );
}

#[test]
fn deterministic_precedence_maps_inputs_to_expected_decisions() {
    let artifact = artifact();
    let allowed_sources = string_set(&artifact, "allowed_pressure_sources");
    let max_age = max_age_seconds(&artifact);
    let priorities = array(&artifact, "decision_rules")
        .iter()
        .map(|rule| {
            (
                u64_value(rule, "priority"),
                string(rule, "rule_id").to_string(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        priorities.len(),
        array(&artifact, "decision_rules").len(),
        "decision rule priorities must be unique"
    );

    for scenario in array(&artifact, "scenarios") {
        assert_eq!(
            evaluate_scenario(scenario, &allowed_sources, max_age),
            expected_decision(scenario),
            "{} must follow the deterministic precedence ladder",
            string(scenario, "scenario_id")
        );
    }
}

#[test]
fn brownout_and_no_win_decisions_require_receipts() {
    let artifact = artifact();
    for scenario in array(&artifact, "scenarios") {
        let scenario_id = string(scenario, "scenario_id");
        match expected_decision(scenario).decision.as_str() {
            "brownout_degraded_optional" => {
                let receipt = nested(scenario, "brownout_receipt");
                assert!(
                    !string(receipt, "receipt_id").is_empty(),
                    "{scenario_id} brownout receipt id"
                );
                assert!(
                    !array(receipt, "degraded_optional_surfaces").is_empty(),
                    "{scenario_id} must name degraded optional surfaces"
                );
                assert!(
                    !array(receipt, "preserved_surfaces").is_empty(),
                    "{scenario_id} must name preserved surfaces"
                );
                assert!(
                    string(receipt, "recovery_condition").contains("local_fallback"),
                    "{scenario_id} recovery condition must keep local fallback fail-closed"
                );
            }
            "no_win" => {
                let receipt = nested(scenario, "no_win_receipt");
                assert!(
                    !string(receipt, "receipt_id").is_empty(),
                    "{scenario_id} no-win receipt id"
                );
                assert!(
                    bool_value(receipt, "local_fallback_refused"),
                    "{scenario_id} no-win receipt must refuse local fallback"
                );
                assert!(
                    !string(receipt, "first_blocker").is_empty(),
                    "{scenario_id} no-win receipt must preserve first blocker"
                );
            }
            _ => {}
        }
    }
}

#[test]
fn stale_unsupported_malformed_and_local_fallback_cases_fail_closed() {
    let artifact = artifact();
    let cases = [
        (
            "ASWARM-ADMISSION-FAIL-STALE-EVIDENCE",
            "fail_closed_stale_evidence",
            "stale_evidence",
        ),
        (
            "ASWARM-ADMISSION-FAIL-UNSUPPORTED-HOST-DATA",
            "fail_closed_unsupported_host_data",
            "unsupported_pressure_source",
        ),
        (
            "ASWARM-ADMISSION-FAIL-MALFORMED-INPUT",
            "fail_closed_malformed_input",
            "malformed_input",
        ),
        (
            "ASWARM-ADMISSION-FAIL-LOCAL-RCH-FALLBACK",
            "fail_closed_local_rch_fallback",
            "local_rch_fallback",
        ),
    ];

    for (scenario_id, decision, issue_kind) in cases {
        let expected = expected_decision(scenario_by_id(&artifact, scenario_id));
        assert_eq!(expected.decision, decision, "{scenario_id} decision");
        assert_eq!(expected.issue_kind, issue_kind, "{scenario_id} issue");
    }
}

#[test]
fn validation_lanes_are_remote_required_and_isolated() {
    let artifact = artifact();
    let validation = nested(&artifact, "validation");
    let remote = string(validation, "remote_required_contract_test");
    assert!(
        remote.starts_with("RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_boldtower_swarm_admission_contract"),
        "remote proof lane must require rch remote execution and a stable target dir"
    );
    assert!(
        remote.contains(
            " cargo test -p asupersync --test swarm_admission_decision_contract -- --nocapture"
        ),
        "remote proof lane must point at the contract test"
    );
    assert!(
        string(validation, "local_fallback_policy").contains("fail-closed"),
        "validation docs must state local fallback fails closed"
    );

    for forbidden in string_set(&artifact, "forbidden_command_fragments") {
        assert!(
            !remote.contains(&forbidden),
            "remote validation command must not include forbidden fragment {forbidden}"
        );
    }
}
