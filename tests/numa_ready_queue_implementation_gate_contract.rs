#![allow(missing_docs)]

use serde_json::{Map as JsonMap, Value as JsonValue, json};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const ARTIFACT_PATH: &str = "artifacts/numa_ready_queue_implementation_gate_contract_v1.json";

#[derive(Debug, Clone, PartialEq, Eq)]
struct GateDecision {
    decision: String,
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

fn object<'a>(value: &'a JsonValue, key: &str) -> &'a JsonMap<String, JsonValue> {
    value
        .get(key)
        .and_then(JsonValue::as_object)
        .unwrap_or_else(|| panic!("{key} must be an object"))
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

fn expected_decision(scenario: &JsonValue) -> GateDecision {
    let expected = nested(scenario, "expected_gate_decision");
    GateDecision {
        decision: string(expected, "decision").to_string(),
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

fn set_path(root: &mut JsonValue, dotted_path: &str, replacement: JsonValue) {
    let mut current = root;
    let mut parts = dotted_path.split('.').peekable();
    while let Some(part) = parts.next() {
        if parts.peek().is_none() {
            current
                .as_object_mut()
                .unwrap_or_else(|| panic!("{dotted_path}: parent must be an object"))
                .insert(part.to_string(), replacement);
            return;
        }
        current = current
            .get_mut(part)
            .unwrap_or_else(|| panic!("{dotted_path}: missing path segment {part}"));
    }
}

fn expanded_scenario(artifact: &JsonValue, scenario: &JsonValue) -> JsonValue {
    let Some(base_id) = scenario
        .get("mutate_from_scenario")
        .and_then(JsonValue::as_str)
    else {
        return scenario.clone();
    };
    let mut base = scenario_by_id(artifact, base_id).clone();
    let mutations = object(scenario, "mutations");
    for (path, replacement) in mutations {
        set_path(&mut base, path, replacement.clone());
    }
    base.as_object_mut()
        .expect("expanded scenario object")
        .insert(
            "scenario_id".to_string(),
            json!(string(scenario, "scenario_id")),
        );
    base.as_object_mut()
        .expect("expanded scenario object")
        .insert(
            "expected_gate_decision".to_string(),
            nested(scenario, "expected_gate_decision").clone(),
        );
    base
}

fn required_receipt_field_present(receipt: &JsonValue, field: &str) -> bool {
    receipt.get(field).is_some_and(|value| match value {
        JsonValue::String(s) => !s.trim().is_empty() || field == "first_blocker",
        JsonValue::Array(items) => !items.is_empty(),
        JsonValue::Object(items) => !items.is_empty(),
        JsonValue::Bool(_) | JsonValue::Number(_) => true,
        JsonValue::Null => false,
    })
}

fn receipt_has_required_fields(receipt: &JsonValue, required_fields: &BTreeSet<String>) -> bool {
    required_fields
        .iter()
        .all(|field| required_receipt_field_present(receipt, field))
}

fn receipt_lanes(receipt: &JsonValue) -> BTreeSet<String> {
    array(receipt, "lanes")
        .iter()
        .map(|lane| string(lane, "lane_id").to_string())
        .collect()
}

fn receipt_remote_valid(receipt: &JsonValue) -> bool {
    bool_value(receipt, "remote_required")
        && string(receipt, "command_line").starts_with("RCH_REQUIRE_REMOTE=1 rch exec --")
}

fn receipt_has_fairness(receipt: &JsonValue) -> bool {
    let fairness = nested(receipt, "fairness_counters");
    u64_value(fairness, "max_cancel_streak") > 0 && u64_value(fairness, "ready_stall_depth") > 0
}

fn receipt_has_cancel_drain(receipt: &JsonValue) -> bool {
    u64_value(nested(receipt, "cancel_drain_evidence"), "p99_drain_ns") > 0
}

fn receipts_same_host(before: &JsonValue, after: &JsonValue) -> bool {
    string(before, "host_signature") == string(after, "host_signature")
        && string(before, "rch_worker_id") == string(after, "rch_worker_id")
}

fn lock_order_proof_complete(scenario: &JsonValue, artifact: &JsonValue) -> bool {
    let notes = array(scenario, "lock_order_proof_notes")
        .iter()
        .map(|entry| entry.as_str().expect("lock order note string"))
        .collect::<Vec<_>>();
    array(
        nested(artifact, "lock_order_proof"),
        "required_note_fragments",
    )
    .iter()
    .all(|required| {
        let required = required.as_str().expect("required lock-order fragment");
        notes.iter().any(|note| note.contains(required))
    })
}

fn rollback_complete(scenario: &JsonValue, artifact: &JsonValue) -> bool {
    let Some(rollback) = scenario.get("rollback_criteria") else {
        return false;
    };
    for field in array(nested(artifact, "rollback_policy"), "required_fields") {
        let field = field.as_str().expect("rollback field string");
        if !rollback.get(field).is_some_and(|value| match value {
            JsonValue::String(s) => !s.trim().is_empty(),
            JsonValue::Array(items) => !items.is_empty(),
            _ => false,
        }) {
            return false;
        }
    }
    let triggers = string_set(rollback, "triggers");
    array(nested(artifact, "rollback_policy"), "minimum_triggers")
        .iter()
        .all(|trigger| triggers.contains(trigger.as_str().expect("trigger string")))
}

fn lane_throughput_improvement_bps(before: &JsonValue, after: &JsonValue, lane_id: &str) -> i64 {
    let before_lane = array(before, "lanes")
        .iter()
        .find(|lane| string(lane, "lane_id") == lane_id)
        .unwrap_or_else(|| panic!("missing before lane {lane_id}"));
    let after_lane = array(after, "lanes")
        .iter()
        .find(|lane| string(lane, "lane_id") == lane_id)
        .unwrap_or_else(|| panic!("missing after lane {lane_id}"));
    let before_ops = u64_value(before_lane, "throughput_ops_per_sec");
    let after_ops = u64_value(after_lane, "throughput_ops_per_sec");
    (((after_ops as i128 - before_ops as i128) * 10_000) / before_ops as i128) as i64
}

fn max_latency_regression_bps(before: &JsonValue, after: &JsonValue, percentile_key: &str) -> i64 {
    array(before, "lanes")
        .iter()
        .map(|before_lane| {
            let lane_id = string(before_lane, "lane_id");
            let after_lane = array(after, "lanes")
                .iter()
                .find(|lane| string(lane, "lane_id") == lane_id)
                .unwrap_or_else(|| panic!("missing after lane {lane_id}"));
            let before_ns = u64_value(before_lane, percentile_key);
            let after_ns = u64_value(after_lane, percentile_key);
            (((after_ns as i128 - before_ns as i128) * 10_000) / before_ns as i128) as i64
        })
        .max()
        .unwrap_or(0)
}

fn non_regression_holds(before: &JsonValue, after: &JsonValue, artifact: &JsonValue) -> bool {
    let thresholds = nested(artifact, "non_regression_thresholds");
    let p95_ok = max_latency_regression_bps(before, after, "p95_ns")
        <= u64_value(thresholds, "max_p95_regression_bps") as i64;
    let p99_ok = max_latency_regression_bps(before, after, "p99_ns")
        <= u64_value(thresholds, "max_p99_regression_bps") as i64;
    let p999_ok = max_latency_regression_bps(before, after, "p999_ns")
        <= u64_value(thresholds, "max_p999_regression_bps") as i64;
    let drain_ok = u64_value(
        nested(after, "cancel_drain_evidence"),
        "drain_regression_bps",
    ) <= u64_value(thresholds, "max_cancel_drain_regression_bps");
    let overhead_ok = u64_value(nested(after, "evidence_capture_overhead"), "overhead_bps")
        <= u64_value(thresholds, "max_evidence_capture_overhead_bps");
    p95_ok && p99_ok && p999_ok && drain_ok && overhead_ok
}

fn evaluate_gate(scenario: &JsonValue, artifact: &JsonValue) -> GateDecision {
    if scenario
        .get("gate_bypassed")
        .and_then(JsonValue::as_bool)
        .unwrap_or(false)
    {
        return GateDecision {
            decision: "reject_scheduler_semantics_change_without_gate".to_string(),
            issue_kind: "scheduler_semantics_gate_bypassed".to_string(),
        };
    }

    let Some(before) = scenario.get("before_benchmark_receipt") else {
        return GateDecision {
            decision: "reject_missing_baseline".to_string(),
            issue_kind: "missing_before_receipt".to_string(),
        };
    };
    let Some(after) = scenario.get("after_benchmark_receipt") else {
        return GateDecision {
            decision: "reject_missing_baseline".to_string(),
            issue_kind: "missing_after_receipt".to_string(),
        };
    };

    let required_fields = string_set(artifact, "required_receipt_fields");
    if !receipt_has_required_fields(before, &required_fields)
        || !receipt_has_required_fields(after, &required_fields)
    {
        return GateDecision {
            decision: "reject_missing_remote_rch_evidence".to_string(),
            issue_kind: "receipt_fields_missing".to_string(),
        };
    }
    if !receipts_same_host(before, after) {
        return GateDecision {
            decision: "reject_mixed_host_comparison".to_string(),
            issue_kind: "mixed_host_receipts".to_string(),
        };
    }
    if !receipt_remote_valid(before) || !receipt_remote_valid(after) {
        return GateDecision {
            decision: "reject_missing_remote_rch_evidence".to_string(),
            issue_kind: "remote_rch_evidence_missing".to_string(),
        };
    }
    if bool_value(before, "local_fallback_marker_detected")
        || bool_value(after, "local_fallback_marker_detected")
    {
        return GateDecision {
            decision: "reject_local_rch_fallback".to_string(),
            issue_kind: "local_rch_fallback".to_string(),
        };
    }
    if !lock_order_proof_complete(scenario, artifact) {
        return GateDecision {
            decision: "reject_missing_lock_order_proof".to_string(),
            issue_kind: "lock_order_proof_missing".to_string(),
        };
    }
    if !receipt_has_fairness(before) || !receipt_has_fairness(after) {
        return GateDecision {
            decision: "reject_missing_fairness_evidence".to_string(),
            issue_kind: "fairness_evidence_missing".to_string(),
        };
    }
    if !receipt_has_cancel_drain(before) || !receipt_has_cancel_drain(after) {
        return GateDecision {
            decision: "reject_missing_cancel_drain_evidence".to_string(),
            issue_kind: "cancel_drain_evidence_missing".to_string(),
        };
    }
    if !rollback_complete(scenario, artifact) {
        return GateDecision {
            decision: "reject_missing_rollback_criteria".to_string(),
            issue_kind: "rollback_criteria_missing".to_string(),
        };
    }

    let required_lanes = string_set(artifact, "required_benchmark_lanes");
    if !required_lanes.is_subset(&receipt_lanes(before))
        || !required_lanes.is_subset(&receipt_lanes(after))
    {
        return GateDecision {
            decision: "reject_missing_remote_rch_evidence".to_string(),
            issue_kind: "benchmark_lane_evidence_missing".to_string(),
        };
    }
    let improvement = lane_throughput_improvement_bps(
        before,
        after,
        "scheduler/three_lane_decision/global_ready_burst/64",
    );
    if improvement
        < u64_value(
            nested(artifact, "non_regression_thresholds"),
            "required_throughput_improvement_bps",
        ) as i64
        || !non_regression_holds(before, after, artifact)
    {
        return GateDecision {
            decision: "reject_scheduler_semantics_change_without_gate".to_string(),
            issue_kind: "performance_gate_not_satisfied".to_string(),
        };
    }

    GateDecision {
        decision: "pass".to_string(),
        issue_kind: String::new(),
    }
}

#[test]
fn artifact_declares_report_only_gate_and_source_evidence() {
    let artifact = artifact();
    assert_eq!(
        artifact.get("schema_version").and_then(JsonValue::as_str),
        Some("numa-ready-queue-implementation-gate-contract-v1")
    );
    assert_eq!(
        artifact.get("bead_id").and_then(JsonValue::as_str),
        Some("asupersync-vjc3pv.5")
    );
    assert_eq!(
        artifact.get("capability_id").and_then(JsonValue::as_str),
        Some("numa_ready_queue_implementation_gate")
    );

    for path_key in ["artifact_path", "contract_test"] {
        let path = string(&artifact, path_key);
        assert!(
            repo_path(path).is_file(),
            "{path_key} path must exist: {path}"
        );
    }
    for source_path in array(&artifact, "source_evidence_paths") {
        let source_path = source_path.as_str().expect("source path string");
        assert!(
            repo_path(source_path).exists(),
            "source evidence path must exist: {source_path}"
        );
    }

    let scope = nested(&artifact, "gate_scope");
    assert_eq!(
        string(scope, "mode"),
        "fail_closed_before_scheduler_semantics_change"
    );
    for key in [
        "scheduler_sharding_implementation_allowed",
        "tracker_mutation_allowed",
        "cleanup_allowed",
    ] {
        assert!(!bool_value(scope, key), "{key} must be false");
    }
}

#[test]
fn scenario_matrix_covers_required_gate_outputs() {
    let artifact = artifact();
    let covered = array(&artifact, "scenarios")
        .iter()
        .map(|scenario| expected_decision(scenario).decision)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        covered,
        string_set(&artifact, "required_gate_outputs"),
        "scenario matrix must cover every gate output"
    );
}

#[test]
fn gate_decision_precedence_matches_expected_scenarios() {
    let artifact = artifact();
    for scenario in array(&artifact, "scenarios") {
        let expanded = expanded_scenario(&artifact, scenario);
        assert_eq!(
            evaluate_gate(&expanded, &artifact),
            expected_decision(scenario),
            "{} must evaluate to its expected fail-closed gate decision",
            string(scenario, "scenario_id")
        );
    }
}

#[test]
fn pass_case_requires_same_host_lanes_lock_order_and_rollback() {
    let artifact = artifact();
    let scenario = scenario_by_id(&artifact, "ASWARM-NUMA-GATE-PASS-SAME-HOST");
    let before = nested(scenario, "before_benchmark_receipt");
    let after = nested(scenario, "after_benchmark_receipt");
    assert!(receipts_same_host(before, after));
    assert!(string_set(&artifact, "required_benchmark_lanes").is_subset(&receipt_lanes(before)));
    assert!(string_set(&artifact, "required_benchmark_lanes").is_subset(&receipt_lanes(after)));
    assert!(lock_order_proof_complete(scenario, &artifact));
    assert!(rollback_complete(scenario, &artifact));
    assert!(non_regression_holds(before, after, &artifact));
}

#[test]
fn validation_lanes_are_remote_required_and_local_fallback_rejects() {
    let artifact = artifact();
    let validation = nested(&artifact, "validation");
    for key in ["remote_required_contract_test", "benchmark_smoke"] {
        let command = string(validation, key);
        assert!(
            command.starts_with(
                "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_"
            ),
            "{key} must start with remote-required rch and stable target dir"
        );
        assert!(
            command.contains(" cargo "),
            "{key} must keep cargo behind rch exec -- env"
        );
    }
    assert!(
        string(validation, "local_fallback_policy").contains("fail-closed"),
        "local fallback policy must fail closed"
    );

    for forbidden in string_set(&artifact, "forbidden_command_fragments") {
        for key in ["remote_required_contract_test", "benchmark_smoke"] {
            assert!(
                !string(validation, key).starts_with(&forbidden),
                "{key} must not be a bare forbidden command: {forbidden}"
            );
        }
    }
}

#[test]
fn rollback_policy_names_every_non_regression_trigger() {
    let artifact = artifact();
    let rollback = nested(
        scenario_by_id(&artifact, "ASWARM-NUMA-GATE-PASS-SAME-HOST"),
        "rollback_criteria",
    );
    let triggers = string_set(rollback, "triggers");
    for trigger in array(nested(&artifact, "rollback_policy"), "minimum_triggers") {
        let trigger = trigger.as_str().expect("rollback trigger string");
        assert!(
            triggers.contains(trigger),
            "pass scenario rollback criteria missing trigger {trigger}"
        );
    }
}
