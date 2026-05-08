#![allow(missing_docs)]

use asupersync::lab::scenario::{FaultAction, GoldenProjectionFormat, Scenario};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

const CONTRACT_PATH: &str = "artifacts/chaos_scenario_dsl_contract_v1.json";

fn repo_path(relative: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn contract() -> Value {
    let raw = std::fs::read_to_string(repo_path(CONTRACT_PATH))
        .unwrap_or_else(|error| panic!("read {CONTRACT_PATH}: {error}"));
    serde_json::from_str(&raw).unwrap_or_else(|error| panic!("parse {CONTRACT_PATH}: {error}"))
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

fn string_list(value: &Value, key: &str) -> Vec<String> {
    array(value, key)
        .iter()
        .map(|item| {
            item.as_str()
                .unwrap_or_else(|| panic!("{key} entries must be strings"))
                .to_string()
        })
        .collect()
}

fn rows_by_scenario(contract: &Value) -> BTreeMap<String, &Value> {
    array(contract, "scenario_rows")
        .iter()
        .map(|row| (string(row, "scenario_id").to_string(), row))
        .collect()
}

fn markdown_projection(contract: &Value) -> String {
    let mut lines = vec![
        "| scenario_id | status | fault_dimensions | expected_invariants |".to_string(),
        "| --- | --- | --- | --- |".to_string(),
    ];
    for (scenario_id, row) in rows_by_scenario(contract) {
        lines.push(format!(
            "| {scenario_id} | {} | {} | {} |",
            string(row, "report_status"),
            string_list(row, "fault_dimensions").join(", "),
            string_list(row, "expected_invariants").join(", ")
        ));
    }
    lines.join("\n") + "\n"
}

fn action_name(action: &FaultAction) -> &'static str {
    match action {
        FaultAction::Partition => "partition",
        FaultAction::Heal => "heal",
        FaultAction::HostCrash => "host_crash",
        FaultAction::HostRestart => "host_restart",
        FaultAction::ClockSkew => "clock_skew",
        FaultAction::ClockReset => "clock_reset",
    }
}

fn projection_format(format: GoldenProjectionFormat) -> &'static str {
    match format {
        GoldenProjectionFormat::Json => "json",
        GoldenProjectionFormat::Markdown => "markdown",
    }
}

fn source_backed_projection(scenario: &Scenario) -> String {
    let participants = scenario
        .participants
        .iter()
        .map(|participant| participant.name.as_str())
        .collect::<Vec<_>>()
        .join(",");
    let faults = scenario
        .faults
        .iter()
        .map(|fault| {
            let from = fault.args.get("from").and_then(Value::as_str).unwrap_or("");
            let to = fault.args.get("to").and_then(Value::as_str).unwrap_or("");
            format!(
                "{}:{}:{}->{}",
                fault.at_ms,
                action_name(&fault.action),
                from,
                to
            )
        })
        .collect::<Vec<_>>()
        .join("|");
    format!(
        "scenario_id={};seed={};participants={};faults={};invariants={};caps=max_artifact_bytes={},max_fault_events={},max_counterexample_events={};minimization=enabled={},max_evaluations={},max_counterexample_events={};golden=format={},canonicalized={},redacted={}",
        scenario.id,
        scenario.lab.seed,
        participants,
        faults,
        scenario.expected_invariants.join(","),
        scenario
            .resource_caps
            .max_artifact_bytes
            .unwrap_or_default(),
        scenario.resource_caps.max_fault_events.unwrap_or_default(),
        scenario
            .resource_caps
            .max_counterexample_events
            .unwrap_or_default(),
        scenario.minimization.enabled,
        scenario.minimization.max_evaluations.unwrap_or_default(),
        scenario
            .minimization
            .max_counterexample_events
            .unwrap_or_default(),
        projection_format(scenario.golden_projection.format),
        scenario.golden_projection.canonicalized,
        scenario.golden_projection.redacted
    )
}

#[test]
fn contract_declares_sources_and_dsl_policy() {
    let contract = contract();
    assert_eq!(
        contract["contract_version"].as_str(),
        Some("chaos-scenario-dsl-contract-v1")
    );
    assert_eq!(contract["bead_id"].as_str(), Some("asupersync-b3ecyh"));

    let source = contract
        .get("source_of_truth")
        .expect("source_of_truth object");
    for key in [
        "contract",
        "contract_test",
        "scenario_format",
        "scenario_runner",
        "chaos_config",
        "network_module",
        "swarm_replay",
    ] {
        let path = string(source, key);
        assert!(
            repo_path(path).exists(),
            "source_of_truth.{key} must point to a live repo file: {path}"
        );
    }

    let policy = contract.get("dsl_policy").expect("dsl_policy object");
    assert_eq!(
        string_set(policy, "canonical_formats"),
        ["json", "toml", "yaml"]
            .into_iter()
            .map(str::to_string)
            .collect()
    );
    for key in [
        "seed_required",
        "lab_runtime_deterministic",
        "fault_schedule_must_be_ordered",
        "resource_caps_required",
        "expected_invariants_required",
        "minimized_counterexample_required",
        "redaction_required",
        "fail_closed_when_runner_is_unwired",
    ] {
        assert_eq!(policy[key].as_bool(), Some(true), "{key} must be true");
    }
}

#[test]
fn required_dimensions_cover_the_bead_scope() {
    let contract = contract();
    let dimensions = string_set(&contract, "required_chaos_dimensions");
    for dimension in [
        "network_partition",
        "disk_pressure",
        "process_stall",
        "delayed_cleanup",
        "cancellation_storm",
        "resource_caps",
        "expected_invariants",
        "minimized_counterexample",
    ] {
        assert!(
            dimensions.contains(dimension),
            "required_chaos_dimensions must include {dimension}"
        );
    }

    let fields = string_set(&contract, "required_scenario_fields");
    for field in [
        "scenario_id",
        "seed",
        "worker_count",
        "max_steps",
        "participants",
        "fault_schedule",
        "resource_caps",
        "expected_invariants",
        "minimization",
        "golden_projection",
    ] {
        assert!(
            fields.contains(field),
            "scenario fields must include {field}"
        );
    }
}

#[test]
fn source_markers_cover_required_dsl_fields() {
    let contract = contract();
    let source = contract
        .get("source_of_truth")
        .expect("source_of_truth object");
    let scenario_format = std::fs::read_to_string(repo_path(string(source, "scenario_format")))
        .expect("read scenario source");

    for marker in string_list(&contract, "source_markers") {
        assert!(
            scenario_format.contains(&marker),
            "scenario source must contain marker {marker}"
        );
    }

    let mappings = contract
        .get("source_field_mappings")
        .and_then(Value::as_object)
        .expect("source_field_mappings object");
    for field in string_set(&contract, "required_scenario_fields") {
        assert!(
            mappings.contains_key(&field),
            "required scenario field {field} must map to a source-owned field"
        );
    }
    assert_eq!(
        mappings["resource_caps"].as_str(),
        Some("Scenario.resource_caps")
    );
    assert_eq!(
        mappings["expected_invariants"].as_str(),
        Some("Scenario.expected_invariants")
    );
    assert_eq!(
        mappings["minimization"].as_str(),
        Some("Scenario.minimization")
    );
    assert_eq!(
        mappings["golden_projection"].as_str(),
        Some("Scenario.golden_projection")
    );
}

#[test]
fn canonical_source_backed_scenario_parses_validates_and_projects_golden() {
    let contract = contract();
    let raw_scenario = serde_json::to_string(
        contract
            .get("canonical_source_backed_scenario")
            .expect("canonical_source_backed_scenario object"),
    )
    .expect("serialize canonical source-backed scenario");
    let scenario = Scenario::from_json(&raw_scenario).expect("parse canonical scenario");
    let errors = scenario.validate();
    assert!(
        errors.is_empty(),
        "canonical scenario must validate: {errors:?}"
    );

    let rows = rows_by_scenario(&contract);
    let row = rows
        .get(&scenario.id)
        .unwrap_or_else(|| panic!("scenario row for {}", scenario.id));
    assert_eq!(string(row, "scenario_id"), scenario.id);
    let row_invariants = string_set(row, "expected_invariants");
    for invariant in &scenario.expected_invariants {
        assert!(
            row_invariants.contains(invariant),
            "scenario invariant {invariant} must be represented in its row"
        );
    }
    assert_eq!(scenario.resource_caps.max_artifact_bytes, Some(65_536));
    assert_eq!(scenario.resource_caps.max_fault_events, Some(8));
    assert_eq!(scenario.resource_caps.max_counterexample_events, Some(16));
    assert!(scenario.minimization.enabled);
    assert_eq!(scenario.minimization.max_evaluations, Some(64));
    assert_eq!(scenario.minimization.max_counterexample_events, Some(16));
    assert!(scenario.golden_projection.canonicalized);
    assert!(scenario.golden_projection.redacted);

    let actual = source_backed_projection(&scenario);
    assert_eq!(actual, string(&contract, "source_backed_golden_projection"));
    for forbidden in [
        "/home/ubuntu/",
        "Authorization: Bearer ",
        "body_md",
        "created_ts",
    ] {
        assert!(
            !actual.contains(forbidden),
            "source-backed projection must not expose {forbidden}"
        );
    }
}

#[test]
fn current_fault_actions_are_explicit_and_future_dimensions_fail_closed() {
    let contract = contract();
    let existing = string_set(&contract, "existing_fault_actions");
    for action in [
        "partition",
        "heal",
        "host_crash",
        "host_restart",
        "clock_skew",
        "clock_reset",
    ] {
        assert!(existing.contains(action), "existing fault action {action}");
    }

    let rows = rows_by_scenario(&contract);
    assert!(rows["chaos-partition-cancel-storm"]["live_runner_wired"] == false);
    assert!(rows["chaos-disk-pressure-cleanup-delay"]["live_runner_wired"] == false);
    assert!(rows["chaos-process-stall-minimized-counterexample"]["live_runner_wired"] == false);
}

#[test]
fn scenario_rows_fail_closed_until_the_runner_is_wired() {
    let contract = contract();
    let allowed_statuses = string_set(&contract, "allowed_report_statuses");
    assert!(allowed_statuses.contains("XFAIL"));
    assert!(!allowed_statuses.contains("PASS"));

    let global_dimensions = string_set(&contract, "required_chaos_dimensions");
    let global_invariants = string_set(&contract, "required_invariants");

    for (scenario_id, row) in rows_by_scenario(&contract) {
        let status = string(row, "report_status");
        assert!(
            allowed_statuses.contains(status),
            "{scenario_id} status must be recognized"
        );
        if row["live_runner_wired"].as_bool() == Some(false) {
            assert_eq!(
                status, "XFAIL",
                "{scenario_id} must fail closed while unwired"
            );
            assert!(
                string(row, "status_reason").contains("not wired yet"),
                "{scenario_id} must explain why it is XFAIL"
            );
        }

        for dimension in string_set(row, "fault_dimensions") {
            assert!(
                global_dimensions.contains(&dimension),
                "{scenario_id} uses unknown dimension {dimension}"
            );
        }
        for invariant in string_set(row, "expected_invariants") {
            assert!(
                global_invariants.contains(&invariant),
                "{scenario_id} uses unknown invariant {invariant}"
            );
        }
        assert_eq!(
            string(row, "golden_strategy"),
            "exact_canonicalized",
            "{scenario_id} must use exact canonicalized golden output"
        );
    }
}

#[test]
fn golden_markdown_projection_is_stable_and_redacted() {
    let contract = contract();
    let expected = string(&contract, "golden_markdown");
    let actual = markdown_projection(&contract);
    assert_eq!(actual, expected);

    for forbidden in [
        "/home/ubuntu/",
        "body_md",
        "ack_required",
        "Authorization: Bearer ",
        "created_ts",
    ] {
        assert!(
            !actual.contains(forbidden),
            "chaos DSL projection must not expose raw coordination marker {forbidden}"
        );
    }
}

#[test]
fn proof_commands_are_rch_routed_and_target_this_contract() {
    let contract = contract();
    let commands = string_set(&contract, "proof_commands");
    assert!(
        commands
            .iter()
            .any(|command| command.contains("--test chaos_scenario_dsl_contract")),
        "contract must name its own proof command"
    );
    for command in commands {
        assert!(
            command.starts_with("rch exec -- "),
            "proof command must be rch-routed: {command}"
        );
    }
}
