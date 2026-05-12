#![allow(missing_docs)]

use asupersync::lab::scenario::{FaultAction, GoldenProjectionFormat, Scenario};
use asupersync::lab::scenario_runner::ScenarioRunner;
use asupersync::lab::swarm_replay::{
    SwarmReplayEventKind, SwarmReplayScenario, SwarmReplayTaskStatus, run_swarm_replay_scenario,
};
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
        FaultAction::DiskPressure => "disk_pressure",
        FaultAction::DiskRecovered => "disk_recovered",
        FaultAction::DelayedCleanup => "delayed_cleanup",
        FaultAction::ProcessStall => "process_stall",
        FaultAction::ProcessResume => "process_resume",
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
fn live_runner_fault_log_executes_canonical_scenario_and_projects_redacted_log() {
    let contract = contract();
    let live_probe = contract
        .get("live_runner_fault_log")
        .expect("live_runner_fault_log object");
    assert_eq!(string(live_probe, "report_status"), "LIVE");
    assert_eq!(live_probe["must_pass_replay"].as_bool(), Some(true));
    assert_eq!(
        live_probe["must_log_every_scheduled_fault"].as_bool(),
        Some(true)
    );

    let raw_scenario = serde_json::to_string(
        contract
            .get("canonical_source_backed_scenario")
            .expect("canonical_source_backed_scenario object"),
    )
    .expect("serialize canonical source-backed scenario");
    let scenario = Scenario::from_json(&raw_scenario).expect("parse canonical scenario");
    assert_eq!(string(live_probe, "scenario_id"), scenario.id);

    let result =
        ScenarioRunner::validate_replay(&scenario).expect("canonical scenario must replay");
    assert!(result.passed(), "canonical scenario must pass");
    assert!(
        result.lab_report.quiescent,
        "canonical scenario must quiesce"
    );
    assert!(
        result.lab_report.invariant_violations.is_empty(),
        "canonical scenario must not emit invariant violations: {:?}",
        result.lab_report.invariant_violations
    );
    assert_eq!(result.faults_injected, scenario.faults.len());
    assert_eq!(result.fault_log.len(), scenario.faults.len());

    let actual_fault_log = Value::Array(
        result
            .fault_log
            .iter()
            .map(|entry| entry.to_json())
            .collect(),
    );
    let expected_fault_log = Value::Array(array(live_probe, "expected_fault_log").clone());
    assert_eq!(
        actual_fault_log, expected_fault_log,
        "runner fault log must remain canonical and source backed"
    );

    let result_json = result.to_json();
    for field in string_list(live_probe, "required_result_fields") {
        assert!(
            result_json.get(&field).is_some(),
            "runner JSON result must include {field}"
        );
    }
    assert_eq!(result_json["passed"].as_bool(), Some(true));
    let expected_fault_count = u64::try_from(scenario.faults.len()).expect("fault count fits u64");
    assert_eq!(
        result_json["faults_injected"].as_u64(),
        Some(expected_fault_count)
    );
    assert_eq!(result_json["fault_log"], expected_fault_log);

    let rendered_fault_log =
        serde_json::to_string(&result_json["fault_log"]).expect("render fault log");
    for forbidden in string_list(live_probe, "forbidden_projection_markers") {
        assert!(
            !rendered_fault_log.contains(&forbidden),
            "fault log projection must not expose raw coordination marker {forbidden}"
        );
    }
}

#[test]
fn live_cancellation_storm_replay_uses_lab_runtime_state_machine() {
    let contract = contract();
    let probe = contract
        .get("live_cancellation_storm_replay")
        .expect("live_cancellation_storm_replay object");
    assert_eq!(string(probe, "report_status"), "LIVE");
    assert_eq!(probe["must_use_lab_runtime"].as_bool(), Some(true));
    assert_eq!(
        probe["must_request_cancellation_through_runtime_state"].as_bool(),
        Some(true)
    );

    let source_path = string(probe, "source_path");
    let source = std::fs::read_to_string(repo_path(source_path))
        .unwrap_or_else(|error| panic!("read {source_path}: {error}"));
    assert!(source.contains(string(probe, "live_function")));
    assert!(
        source.contains("runtime.state.cancel_request("),
        "live replay must request cancellation through RuntimeState"
    );
    assert!(
        source.contains("scheduler.schedule_cancel("),
        "live replay must route cancelled tasks through the scheduler cancel lane"
    );

    let raw_scenario = serde_json::to_string(
        contract
            .get("canonical_source_backed_scenario")
            .expect("canonical_source_backed_scenario object"),
    )
    .expect("serialize canonical source-backed scenario");
    let canonical_scenario = Scenario::from_json(&raw_scenario).expect("parse canonical scenario");
    assert_eq!(string(probe, "scenario_id"), canonical_scenario.id);

    let replay_scenario: SwarmReplayScenario = serde_json::from_value(
        probe
            .get("swarm_replay_scenario")
            .expect("swarm replay scenario object")
            .clone(),
    )
    .expect("parse swarm replay scenario");
    replay_scenario
        .validate()
        .expect("contracted swarm replay scenario must be bounded");
    assert_eq!(replay_scenario.seed, canonical_scenario.lab.seed);
    assert_eq!(
        replay_scenario.worker_count,
        canonical_scenario.lab.worker_count
    );
    assert_eq!(replay_scenario.cancel_after_steps, Some(1));

    let summary =
        run_swarm_replay_scenario(&replay_scenario).expect("swarm replay scenario must run");
    let replayed =
        run_swarm_replay_scenario(&replay_scenario).expect("swarm replay scenario must replay");
    assert_eq!(
        summary.event_log, replayed.event_log,
        "cancellation-storm event log must be deterministic"
    );
    assert_eq!(
        summary.task_outcomes, replayed.task_outcomes,
        "cancellation-storm task outcomes must be deterministic"
    );
    assert_eq!(
        summary.trace_fingerprint, replayed.trace_fingerprint,
        "live replay trace fingerprint must be deterministic"
    );

    let summary_json = serde_json::to_value(&summary).expect("serialize swarm replay summary");
    for field in string_list(probe, "required_summary_fields") {
        assert!(
            summary_json.get(&field).is_some(),
            "swarm replay summary must include {field}"
        );
    }
    assert_eq!(summary.scenario_id, replay_scenario.scenario_id);
    assert!(summary.quiescent, "swarm replay must quiesce");
    assert!(
        summary.invariant_violations.is_empty(),
        "swarm replay must not emit invariant violations: {:?}",
        summary.invariant_violations
    );
    assert_eq!(
        summary.non_terminal_task_count, 0,
        "all tracked cancellation-storm tasks must reach terminal state"
    );

    let minimums = probe
        .get("minimums")
        .and_then(Value::as_object)
        .expect("minimums object");
    let min_cancellations = minimums["cancellation_requests"]
        .as_u64()
        .expect("cancellation_requests minimum") as usize;
    assert!(
        summary.cancellation_requests >= min_cancellations,
        "live replay must schedule cancellation requests"
    );
    let min_terminal = minimums["terminal_task_count"]
        .as_u64()
        .expect("terminal_task_count minimum") as usize;
    assert!(summary.terminal_task_count >= min_terminal);
    assert_eq!(summary.terminal_task_count, replay_scenario.task_count());

    let event_kinds = summary
        .event_log
        .iter()
        .map(|event| serde_json::to_value(event.kind).expect("event kind JSON"))
        .map(|value| value.as_str().expect("event kind string").to_string())
        .collect::<BTreeSet<_>>();
    for kind in string_list(probe, "required_event_kinds") {
        assert!(
            event_kinds.contains(&kind),
            "swarm replay must emit event kind {kind}"
        );
    }

    let cancel_observed_events = summary
        .event_log
        .iter()
        .filter(|event| event.kind == SwarmReplayEventKind::CancelObserved)
        .count();
    let min_cancel_observed = minimums["cancel_observed_events"]
        .as_u64()
        .expect("cancel_observed_events minimum") as usize;
    assert!(
        cancel_observed_events >= min_cancel_observed,
        "cancel-storm replay must include observed task cancellation"
    );

    let statuses = summary
        .task_outcomes
        .iter()
        .map(|outcome| serde_json::to_value(outcome.status).expect("task status JSON"))
        .map(|value| value.as_str().expect("task status string").to_string())
        .collect::<BTreeSet<_>>();
    for status in string_list(probe, "required_task_statuses") {
        assert!(
            statuses.contains(&status),
            "swarm replay must include task status {status}"
        );
    }
    assert!(
        summary
            .task_outcomes
            .iter()
            .all(|outcome| outcome.status == SwarmReplayTaskStatus::Cancelled),
        "cancel-after-one-step scenario should cancel every tracked task"
    );
    assert!(summary.shrink_hint.first_cancelled_task.is_some());
    assert!(summary.shrink_hint.event_prefix_len <= summary.event_log.len());

    let rendered_summary = serde_json::to_string(&summary_json).expect("render summary JSON");
    for forbidden in string_list(probe, "forbidden_projection_markers") {
        assert!(
            !rendered_summary.contains(&forbidden),
            "swarm replay projection must not expose raw coordination marker {forbidden}"
        );
    }
}

#[test]
fn live_partition_cancel_storm_row_is_backed_by_runner_and_swarm_replay() {
    let contract = contract();
    let probe = contract
        .get("live_partition_cancel_storm_contract")
        .expect("live_partition_cancel_storm_contract object");
    assert_eq!(string(probe, "report_status"), "LIVE");

    let rows = rows_by_scenario(&contract);
    let row = rows
        .get(string(probe, "scenario_id"))
        .expect("partition cancel storm scenario row");
    let required_row_fields = probe
        .get("required_row_fields")
        .and_then(Value::as_object)
        .expect("required_row_fields object");
    assert_eq!(
        row["live_runner_wired"],
        required_row_fields["live_runner_wired"]
    );
    assert_eq!(
        string(row, "report_status"),
        required_row_fields["report_status"]
            .as_str()
            .expect("required row report_status")
    );
    assert_eq!(
        string(row, "status_reason"),
        required_row_fields["status_reason"]
            .as_str()
            .expect("required row status_reason")
    );

    let runner_probe_key = string(probe, "runner_probe");
    let runner_probe = contract
        .get(runner_probe_key)
        .unwrap_or_else(|| panic!("runner probe {runner_probe_key} must exist"));
    let cancellation_probe_key = string(probe, "cancellation_probe");
    let cancellation_probe = contract
        .get(cancellation_probe_key)
        .unwrap_or_else(|| panic!("cancellation probe {cancellation_probe_key} must exist"));
    assert_eq!(string(runner_probe, "report_status"), "LIVE");
    assert_eq!(string(cancellation_probe, "report_status"), "LIVE");

    let source_markers = probe.get("source_markers").expect("source_markers object");
    for source_path in ["src/lab/scenario_runner.rs", "src/lab/swarm_replay.rs"] {
        let source = std::fs::read_to_string(repo_path(source_path))
            .unwrap_or_else(|error| panic!("read {source_path}: {error}"));
        for marker in string_list(source_markers, source_path) {
            assert!(
                source.contains(&marker),
                "{source_path} must contain live marker {marker}"
            );
        }
    }

    let raw_scenario = serde_json::to_string(
        contract
            .get("canonical_source_backed_scenario")
            .expect("canonical source-backed scenario object"),
    )
    .expect("serialize canonical source-backed scenario");
    let scenario = Scenario::from_json(&raw_scenario).expect("parse canonical scenario");
    assert!(
        scenario.validate().is_empty(),
        "partition/cancel scenario must validate"
    );

    let result =
        ScenarioRunner::validate_replay(&scenario).expect("partition/cancel scenario must replay");
    assert!(result.passed(), "partition/cancel runner probe must pass");
    let result_json = result.to_json();
    for field in string_list(probe, "required_runner_fields") {
        assert!(
            result_json.get(&field).is_some(),
            "runner JSON result must include {field}"
        );
    }
    let expected_fault_log = Value::Array(array(runner_probe, "expected_fault_log").clone());
    assert_eq!(result_json["fault_log"], expected_fault_log);

    let replay_scenario: SwarmReplayScenario = serde_json::from_value(
        cancellation_probe
            .get("swarm_replay_scenario")
            .expect("swarm replay scenario object")
            .clone(),
    )
    .expect("parse swarm replay scenario");
    let summary =
        run_swarm_replay_scenario(&replay_scenario).expect("swarm replay scenario must run");
    let summary_json = serde_json::to_value(&summary).expect("serialize swarm replay summary");
    for field in string_list(probe, "required_swarm_summary_fields") {
        assert!(
            summary_json.get(&field).is_some(),
            "swarm replay summary must include {field}"
        );
    }
    assert!(summary.quiescent, "swarm replay must quiesce");
    assert_eq!(
        summary.non_terminal_task_count, 0,
        "swarm replay must drain every tracked task"
    );
    let minimums = cancellation_probe
        .get("minimums")
        .and_then(Value::as_object)
        .expect("cancellation minimums object");
    let min_cancellations = minimums["cancellation_requests"]
        .as_u64()
        .expect("cancellation_requests minimum") as usize;
    assert!(
        summary.cancellation_requests >= min_cancellations,
        "swarm replay must issue cancellation requests"
    );
    assert!(
        summary
            .event_log
            .iter()
            .any(|event| event.kind == SwarmReplayEventKind::CancelObserved),
        "swarm replay must include observed task cancellation"
    );
}

#[test]
fn current_fault_actions_are_explicit_and_future_dimensions_fail_closed() {
    let contract = contract();
    let existing = string_set(&contract, "existing_fault_actions");
    for action in [
        "partition",
        "heal",
        "disk_pressure",
        "disk_recovered",
        "delayed_cleanup",
        "process_stall",
        "process_resume",
        "host_crash",
        "host_restart",
        "clock_skew",
        "clock_reset",
    ] {
        assert!(existing.contains(action), "existing fault action {action}");
    }

    let rows = rows_by_scenario(&contract);
    assert_eq!(
        rows["chaos-partition-cancel-storm"]["live_runner_wired"],
        true,
    );
    assert_eq!(
        rows["chaos-disk-pressure-cleanup-delay"]["live_runner_wired"],
        true,
    );
    assert_eq!(
        rows["chaos-process-stall-minimized-counterexample"]["live_runner_wired"],
        true,
    );
}

#[test]
fn live_fault_action_validation_covers_disk_process_and_cleanup_dimensions() {
    let contract = contract();
    let probe = contract
        .get("live_fault_action_validation")
        .expect("live_fault_action_validation object");
    assert_eq!(string(probe, "report_status"), "LIVE");

    let source_path = string(probe, "source_path");
    let source = std::fs::read_to_string(repo_path(source_path))
        .unwrap_or_else(|error| panic!("read {source_path}: {error}"));
    for marker in string_list(probe, "source_markers") {
        assert!(
            source.contains(&marker),
            "scenario source must contain fault validation marker {marker}"
        );
    }

    let raw_scenario = serde_json::to_string(
        probe
            .get("valid_source_backed_scenario")
            .expect("valid source-backed scenario object"),
    )
    .expect("serialize valid scenario");
    let scenario = Scenario::from_json(&raw_scenario).expect("parse valid fault-action scenario");
    assert!(
        scenario.validate().is_empty(),
        "contracted disk/process/cleanup fault scenario must validate"
    );

    let actions = scenario
        .faults
        .iter()
        .map(|fault| action_name(&fault.action).to_string())
        .collect::<BTreeSet<_>>();
    for action in string_list(probe, "required_fault_actions") {
        assert!(
            actions.contains(&action),
            "valid scenario must include action {action}"
        );
    }

    let runner_result =
        ScenarioRunner::run(&scenario).expect("valid fault-action scenario must run");
    assert!(runner_result.passed());
    assert_eq!(runner_result.faults_injected, scenario.faults.len());
    let logged_actions = runner_result
        .fault_log
        .iter()
        .map(|entry| entry.action.clone())
        .collect::<BTreeSet<_>>();
    for action in string_list(probe, "required_fault_actions") {
        assert!(
            logged_actions.contains(&action),
            "runner fault log must include action {action}"
        );
    }

    let invalid = Scenario::from_json(
        &serde_json::to_string(
            probe
                .get("invalid_fail_closed_scenario")
                .expect("invalid fail-closed scenario object"),
        )
        .expect("serialize invalid scenario"),
    )
    .expect("parse invalid fault-action scenario");
    let errors = invalid.validate();
    for field in string_list(probe, "required_error_fields") {
        assert!(
            errors.iter().any(|error| error.field == field),
            "invalid scenario must fail closed on {field}: {errors:?}"
        );
    }

    let rows = rows_by_scenario(&contract);
    assert_eq!(
        rows["chaos-disk-pressure-cleanup-delay"]["report_status"].as_str(),
        Some("LIVE"),
        "disk/cleanup runner semantics are covered by the live effect-summary probe"
    );
    assert_eq!(
        rows["chaos-disk-pressure-cleanup-delay"]["live_runner_wired"].as_bool(),
        Some(true),
        "disk/cleanup row is live once the runner effect summary is source-backed"
    );
    assert_eq!(
        rows["chaos-process-stall-minimized-counterexample"]["report_status"].as_str(),
        Some("LIVE"),
        "process-stall minimization is covered by the live counterexample probe"
    );
    assert_eq!(
        rows["chaos-process-stall-minimized-counterexample"]["live_runner_wired"].as_bool(),
        Some(true),
        "process-stall row is live once minimized counterexample output is source-backed"
    );
}

#[test]
fn live_disk_pressure_cleanup_delay_uses_runner_effect_summary() {
    let contract = contract();
    let probe = contract
        .get("live_disk_pressure_cleanup_delay")
        .expect("live_disk_pressure_cleanup_delay object");
    assert_eq!(string(probe, "report_status"), "LIVE");

    let rows = rows_by_scenario(&contract);
    let row = rows
        .get(string(probe, "scenario_id"))
        .expect("disk cleanup scenario row");
    assert_eq!(string(row, "report_status"), "LIVE");
    assert_eq!(row["live_runner_wired"].as_bool(), Some(true));

    let source_path = string(probe, "source_path");
    let source = std::fs::read_to_string(repo_path(source_path))
        .unwrap_or_else(|error| panic!("read {source_path}: {error}"));
    for marker in string_list(probe, "source_markers") {
        assert!(
            source.contains(&marker),
            "scenario runner source must contain effect-summary marker {marker}"
        );
    }

    let raw_scenario = serde_json::to_string(
        probe
            .get("scenario")
            .expect("live disk cleanup scenario object"),
    )
    .expect("serialize live disk cleanup scenario");
    let scenario = Scenario::from_json(&raw_scenario).expect("parse disk cleanup scenario");
    assert!(
        scenario.validate().is_empty(),
        "disk cleanup scenario must validate"
    );

    let result =
        ScenarioRunner::validate_replay(&scenario).expect("disk cleanup scenario must replay");
    assert!(result.passed(), "disk cleanup scenario must pass");
    assert!(result.lab_report.quiescent);
    assert!(
        result.lab_report.invariant_violations.is_empty(),
        "disk cleanup scenario must not emit invariant violations: {:?}",
        result.lab_report.invariant_violations
    );
    assert_eq!(result.faults_injected, scenario.faults.len());

    let result_json = result.to_json();
    for field in string_list(probe, "required_result_fields") {
        assert!(
            result_json.get(&field).is_some(),
            "runner JSON result must include {field}"
        );
    }

    let effect_summary = result.fault_effect_summary.to_json();
    let expected_effect_summary = probe
        .get("expected_effect_summary")
        .expect("expected effect summary object");
    assert_eq!(
        &effect_summary, expected_effect_summary,
        "disk cleanup effect summary must remain exact and source-backed"
    );
    assert_eq!(result_json["fault_effect_summary"], effect_summary);

    let minimums = probe
        .get("minimums")
        .and_then(Value::as_object)
        .expect("minimums object");
    let minimum_disk_pressure = minimums["max_disk_pressure_bytes"]
        .as_u64()
        .expect("max disk pressure minimum");
    let minimum_cleanup_delay = minimums["delayed_cleanup_total_ms"]
        .as_u64()
        .expect("cleanup delay minimum");
    assert!(
        effect_summary["max_disk_pressure_bytes"]
            .as_u64()
            .expect("max disk pressure bytes")
            >= minimum_disk_pressure
    );
    assert!(
        effect_summary["delayed_cleanup_total_ms"]
            .as_u64()
            .expect("cleanup delay total")
            >= minimum_cleanup_delay
    );
    assert_eq!(
        effect_summary["resource_cap_breaches"]
            .as_array()
            .map(Vec::len),
        Some(0),
        "bounded artifact output must not breach resource caps"
    );

    let rendered_effect_summary =
        serde_json::to_string(&effect_summary).expect("render effect summary");
    for forbidden in string_list(probe, "forbidden_projection_markers") {
        assert!(
            !rendered_effect_summary.contains(&forbidden),
            "effect summary projection must not expose raw coordination marker {forbidden}"
        );
    }
}

#[test]
fn live_process_stall_minimized_counterexample_is_source_backed() {
    let contract = contract();
    let probe = contract
        .get("live_process_stall_minimized_counterexample")
        .expect("live_process_stall_minimized_counterexample object");
    assert_eq!(string(probe, "report_status"), "LIVE");

    let rows = rows_by_scenario(&contract);
    let row = rows
        .get(string(probe, "scenario_id"))
        .expect("process stall scenario row");
    assert_eq!(string(row, "report_status"), "LIVE");
    assert_eq!(row["live_runner_wired"].as_bool(), Some(true));

    let source_path = string(probe, "source_path");
    let source = std::fs::read_to_string(repo_path(source_path))
        .unwrap_or_else(|error| panic!("read {source_path}: {error}"));
    for marker in string_list(probe, "source_markers") {
        assert!(
            source.contains(&marker),
            "scenario runner source must contain counterexample marker {marker}"
        );
    }

    let raw_scenario = serde_json::to_string(
        probe
            .get("scenario")
            .expect("live process stall scenario object"),
    )
    .expect("serialize live process stall scenario");
    let scenario = Scenario::from_json(&raw_scenario).expect("parse process stall scenario");
    assert!(
        scenario.validate().is_empty(),
        "process stall scenario must validate"
    );

    let result =
        ScenarioRunner::validate_replay(&scenario).expect("process stall scenario must replay");
    assert!(result.passed(), "process stall scenario must quiesce");
    assert_eq!(result.faults_injected, scenario.faults.len());

    let result_json = result.to_json();
    for field in string_list(probe, "required_result_fields") {
        assert!(
            result_json.get(&field).is_some(),
            "runner JSON result must include {field}"
        );
    }

    let effect_summary = result.fault_effect_summary.to_json();
    let expected_effect_summary = probe
        .get("expected_effect_summary")
        .expect("expected effect summary object");
    assert_eq!(
        &effect_summary, expected_effect_summary,
        "process stall effect summary must remain exact and source-backed"
    );

    let counterexample = result
        .minimized_counterexample
        .as_ref()
        .expect("unresolved process stall must emit counterexample packet");
    let counterexample_json = counterexample.to_json();
    let expected_counterexample = probe
        .get("expected_counterexample")
        .expect("expected counterexample object");
    assert_eq!(
        &counterexample_json, expected_counterexample,
        "process stall counterexample packet must remain exact"
    );
    assert_eq!(result_json["minimized_counterexample"], counterexample_json);
    assert!(
        counterexample.prefix_len <= counterexample.max_counterexample_events,
        "minimized prefix must respect max_counterexample_events"
    );
    assert_eq!(counterexample.reason, "unresolved_process_stall");
    assert_eq!(
        counterexample
            .fault_log_prefix
            .first()
            .map(|entry| entry.action.as_str()),
        Some("process_stall")
    );

    let rendered_counterexample =
        serde_json::to_string(&counterexample_json).expect("render counterexample packet");
    for forbidden in string_list(probe, "forbidden_projection_markers") {
        assert!(
            !rendered_counterexample.contains(&forbidden),
            "counterexample projection must not expose raw coordination marker {forbidden}"
        );
    }
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
