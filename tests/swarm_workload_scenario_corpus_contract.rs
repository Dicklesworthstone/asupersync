#![allow(missing_docs)]

use asupersync::lab::{
    SWARM_REPLAY_SCHEMA_VERSION, SwarmReplayAdmissionDecision, SwarmReplayScenario,
    run_swarm_replay_scenario,
};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const ARTIFACT_PATH: &str = "artifacts/swarm_workload_scenario_corpus_v1.json";

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn contract() -> Value {
    let raw = std::fs::read_to_string(repo_path(ARTIFACT_PATH))
        .unwrap_or_else(|error| panic!("read {ARTIFACT_PATH}: {error}"));
    serde_json::from_str(&raw).unwrap_or_else(|error| panic!("parse {ARTIFACT_PATH}: {error}"))
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

fn scenario_rows(contract: &Value) -> BTreeMap<String, &Value> {
    array(contract, "scenarios")
        .iter()
        .map(|row| (string(row, "scenario_id").to_string(), row))
        .collect()
}

fn parse_replay(row: &Value) -> SwarmReplayScenario {
    serde_json::from_value(
        row.get("replay_scenario")
            .unwrap_or_else(|| panic!("{} missing replay_scenario", string(row, "scenario_id")))
            .clone(),
    )
    .unwrap_or_else(|error| {
        panic!(
            "parse replay_scenario {}: {error}",
            string(row, "scenario_id")
        )
    })
}

fn scenario_dimensions(row: &Value) -> BTreeSet<String> {
    string_set(row, "semantic_dimensions")
}

fn replay_json_fields(row: &Value) -> BTreeSet<String> {
    row.get("replay_scenario")
        .and_then(Value::as_object)
        .unwrap_or_else(|| {
            panic!(
                "{} replay_scenario must be object",
                string(row, "scenario_id")
            )
        })
        .keys()
        .cloned()
        .collect()
}

#[test]
fn artifact_declares_source_schema_and_runner_boundary() {
    let contract = contract();
    assert_eq!(
        contract["contract_version"].as_str(),
        Some("swarm-workload-scenario-corpus-v1")
    );
    assert_eq!(contract["bead_id"].as_str(), Some("asupersync-vssefs.9.1"));
    assert_eq!(
        contract["runtime_schema_version"].as_str(),
        Some(SWARM_REPLAY_SCHEMA_VERSION)
    );

    let source = contract
        .get("source_of_truth")
        .expect("source_of_truth object");
    for key in ["contract", "contract_test", "runtime_scenario_source"] {
        let path = string(source, key);
        assert!(
            repo_path(path).exists(),
            "source_of_truth.{key} must point to a live repo file: {path}"
        );
    }
    assert_eq!(
        string(source, "runtime_scenario_type"),
        "asupersync::lab::SwarmReplayScenario"
    );
    assert_eq!(
        string(source, "runtime_runner"),
        "asupersync::lab::run_swarm_replay_scenario"
    );

    let runner = contract
        .get("runner_contract")
        .expect("runner_contract object");
    assert_eq!(string(runner, "lab_runtime_adapter_status"), "live");
    assert!(
        string(runner, "future_no_mock_runner_adapter").contains("same replay_scenario object")
    );
    assert!(string(runner, "same_shape_policy").contains("semantic workload knobs"));
    assert!(
        string(runner, "proof_command").contains("RCH_REQUIRE_REMOTE=1 rch exec --"),
        "published proof command must require remote RCH execution"
    );
}

#[test]
fn schema_fields_are_complete_and_source_backed() {
    let contract = contract();
    let schema = contract.get("schema").expect("schema object");
    let required = string_set(schema, "required_replay_fields");
    let pressure = string_set(schema, "pressure_knobs");
    let failure = string_set(schema, "failure_mode_knobs");

    for field in [
        "scenario_id",
        "seed",
        "worker_count",
        "cohort_count",
        "region_count",
        "tasks_per_region",
        "channel_capacity",
        "messages_per_task",
        "obligations_per_task",
        "region_task_admission_limit",
        "region_over_limit_decision",
        "region_memory_bytes_per_task",
        "cancel_after_steps",
        "max_steps",
    ] {
        assert!(
            required.contains(field),
            "schema missing required field {field}"
        );
    }

    for field in [
        "channel_capacity",
        "messages_per_task",
        "obligations_per_task",
        "region_memory_bytes_per_task",
        "region_cleanup_poll_quota_per_task",
    ] {
        assert!(pressure.contains(field), "pressure knobs missing {field}");
    }
    for field in [
        "region_task_admission_limit",
        "region_over_limit_decision",
        "cancel_after_steps",
        "max_steps",
    ] {
        assert!(
            failure.contains(field),
            "failure-mode knobs missing {field}"
        );
    }

    let source_path = string(&contract["source_of_truth"], "runtime_scenario_source");
    let source = std::fs::read_to_string(repo_path(source_path))
        .unwrap_or_else(|error| panic!("read {source_path}: {error}"));
    for field in &required {
        assert!(
            source.contains(&format!("pub {field}:")),
            "runtime source must own field {field}"
        );
    }
}

#[test]
fn corpus_covers_required_dimensions_with_unique_named_scenarios() {
    let contract = contract();
    let scenarios = array(&contract, "scenarios");
    assert!(
        scenarios.len() >= 6,
        "corpus must include at least six named scenarios"
    );
    assert_eq!(
        scenarios.len(),
        scenario_rows(&contract).len(),
        "scenario ids must be unique"
    );

    let mut covered = BTreeSet::new();
    for row in scenarios {
        let replay = row
            .get("replay_scenario")
            .unwrap_or_else(|| panic!("{} missing replay_scenario", string(row, "scenario_id")));
        assert_eq!(
            string(row, "scenario_id"),
            string(replay, "scenario_id"),
            "row id and replay scenario id must match"
        );
        covered.extend(scenario_dimensions(row));
    }

    let required = string_set(&contract, "required_semantic_dimensions");
    let missing = required.difference(&covered).cloned().collect::<Vec<_>>();
    assert!(missing.is_empty(), "missing dimensions: {missing:?}");
}

#[test]
fn replay_fixtures_deserialize_validate_and_keep_required_fields() {
    let contract = contract();
    let required = string_set(&contract["schema"], "required_replay_fields");
    for row in array(&contract, "scenarios") {
        let fields = replay_json_fields(row);
        let missing = required.difference(&fields).cloned().collect::<Vec<_>>();
        assert!(
            missing.is_empty(),
            "{} missing replay fields: {missing:?}",
            string(row, "scenario_id")
        );

        let scenario = parse_replay(row);
        scenario
            .validate()
            .unwrap_or_else(|error| panic!("{} must validate: {error}", scenario.scenario_id));
        assert_eq!(scenario.scenario_id, string(row, "scenario_id"));
        assert!(scenario.task_count() > 0);
        assert!(scenario.worker_count >= scenario.cohort_count);
        assert_ne!(
            scenario.region_over_limit_decision,
            SwarmReplayAdmissionDecision::Accept,
            "corpus should not mask over-limit scenarios with accept"
        );
    }
}

#[test]
fn minimal_and_saturated_boundary_scenarios_are_explicit() {
    let contract = contract();
    let rows = scenario_rows(&contract);
    let minimal = parse_replay(
        rows.get("swarm-minimal-healthy-run")
            .expect("minimal scenario row"),
    );
    assert_eq!(minimal.task_count(), 1);
    assert_eq!(minimal.worker_count, 1);
    assert_eq!(minimal.region_count, 1);
    assert_eq!(minimal.tasks_per_region, 1);

    let saturated = parse_replay(
        rows.get("swarm-saturated-contract-boundary")
            .expect("saturated scenario row"),
    );
    assert_eq!(saturated.worker_count, 64);
    assert_eq!(saturated.task_count(), 10_000);
    saturated.validate().expect("saturated boundary validates");
}

#[test]
fn malformed_examples_fail_closed() {
    let contract = contract();
    for row in array(&contract, "malformed_examples") {
        let scenario: SwarmReplayScenario = serde_json::from_value(
            row.get("replay_scenario")
                .unwrap_or_else(|| panic!("{} missing replay_scenario", string(row, "case_id")))
                .clone(),
        )
        .unwrap_or_else(|error| panic!("parse malformed {}: {error}", string(row, "case_id")));
        let error = scenario
            .validate()
            .expect_err("malformed example must fail validation")
            .to_string();
        let expected = string(row, "expected_error_contains");
        assert!(
            error.contains(expected),
            "{} expected error containing {expected:?}, got {error:?}",
            string(row, "case_id")
        );
    }
}

#[test]
fn fixture_records_do_not_use_placeholder_success_markers() {
    let contract = contract();
    let forbidden = string_set(&contract["schema"], "forbidden_fixture_markers");
    for row in array(&contract, "scenarios") {
        let rendered =
            serde_json::to_string(row).expect("scenario row must render to JSON for marker scan");
        let rendered_lower = rendered.to_ascii_lowercase();
        for marker in &forbidden {
            assert!(
                !rendered_lower.contains(marker),
                "{} must not contain forbidden fixture marker {marker}",
                string(row, "scenario_id")
            );
        }
    }
}

#[test]
fn smoke_scenarios_execute_through_lab_runtime_and_quiesce() {
    let contract = contract();
    for row in array(&contract, "scenarios") {
        if string(row, "execution_mode") != "run_in_contract" {
            continue;
        }
        let scenario = parse_replay(row);
        let summary = run_swarm_replay_scenario(&scenario)
            .unwrap_or_else(|error| panic!("{} must run: {error}", scenario.scenario_id));
        assert_eq!(summary.schema_version, SWARM_REPLAY_SCHEMA_VERSION);
        assert_eq!(summary.scenario_id, scenario.scenario_id);
        assert!(summary.quiescent, "{} must quiesce", summary.scenario_id);
        assert_eq!(summary.non_terminal_task_count, 0);
        assert!(
            summary.invariant_violations.is_empty(),
            "{} invariant violations: {:?}",
            summary.scenario_id,
            summary.invariant_violations
        );

        let dimensions = scenario_dimensions(row);
        if dimensions.contains("cancellation_storm") {
            assert!(
                summary.cancellation_requests > 0,
                "{} must request cancellation",
                summary.scenario_id
            );
            assert!(
                summary.obligation_aborts > 0 || summary.obligation_commits > 0,
                "{} must resolve obligations",
                summary.scenario_id
            );
        }
        if dimensions.contains("admission_rejection") {
            assert!(
                summary
                    .admission_records
                    .iter()
                    .any(|record| { record.decision == SwarmReplayAdmissionDecision::Shed }),
                "{} must include shed admission records",
                summary.scenario_id
            );
        }
        if dimensions.contains("admission_cancel_drain") {
            assert!(
                summary
                    .admission_records
                    .iter()
                    .any(|record| { record.decision == SwarmReplayAdmissionDecision::Cancel }),
                "{} must include cancel admission records",
                summary.scenario_id
            );
        }
    }
}
