#![allow(missing_docs)]

use asupersync::lab::{
    SWARM_AGENT_RUN_SCHEMA_VERSION, SWARM_PRESSURE_SCHEMA_VERSION, SWARM_REPLAY_SCHEMA_VERSION,
    SWARM_WHAT_IF_PLAN_SCHEMA_VERSION, SwarmAgentRunScenario, SwarmAgentRunSummary,
    SwarmPressureScenario, SwarmPressureSummary, SwarmReplayAdmissionDecision, SwarmReplayScenario,
    SwarmReplaySummary, SwarmWhatIfPlan, SwarmWhatIfRecommendation, SwarmWhatIfScenario,
    plan_swarm_admission_wave, run_swarm_agent_run_scenario, run_swarm_pressure_scenario,
    run_swarm_replay_scenario,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
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

fn row_by_id<'a>(contract: &'a Value, section: &str, scenario_id: &str) -> &'a Value {
    array(contract, section)
        .iter()
        .find(|row| string(row, "scenario_id") == scenario_id)
        .unwrap_or_else(|| panic!("{section} missing scenario {scenario_id}"))
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

fn parse_pressure(row: &Value) -> SwarmPressureScenario {
    serde_json::from_value(
        row.get("pressure_scenario")
            .unwrap_or_else(|| panic!("{} missing pressure_scenario", string(row, "scenario_id")))
            .clone(),
    )
    .unwrap_or_else(|error| {
        panic!(
            "parse pressure_scenario {}: {error}",
            string(row, "scenario_id")
        )
    })
}

fn parse_agent_run(row: &Value) -> SwarmAgentRunScenario {
    serde_json::from_value(
        row.get("agent_run_scenario")
            .unwrap_or_else(|| panic!("{} missing agent_run_scenario", string(row, "scenario_id")))
            .clone(),
    )
    .unwrap_or_else(|error| {
        panic!(
            "parse agent_run_scenario {}: {error}",
            string(row, "scenario_id")
        )
    })
}

fn parse_what_if(row: &Value) -> SwarmWhatIfScenario {
    serde_json::from_value(
        row.get("what_if_scenario")
            .unwrap_or_else(|| panic!("{} missing what_if_scenario", string(row, "scenario_id")))
            .clone(),
    )
    .unwrap_or_else(|error| {
        panic!(
            "parse what_if_scenario {}: {error}",
            string(row, "scenario_id")
        )
    })
}

fn scenario_dimensions(row: &Value) -> BTreeSet<String> {
    string_set(row, "semantic_dimensions")
}

fn workload_dimensions(row: &Value) -> BTreeSet<String> {
    string_set(row, "workload_dimensions")
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

fn stable_hash(value: &Value) -> String {
    use std::fmt::Write;

    let bytes = serde_json::to_vec(value).expect("stable JSON projection must serialize");
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest.as_slice() {
        write!(&mut out, "{byte:02x}").expect("write to String cannot fail");
    }
    out
}

fn stable_json(value: impl serde::Serialize) -> Value {
    serde_json::to_value(value).expect("runner log projection must serialize")
}

fn runner_log_projection(
    contract: &Value,
    replay: &SwarmReplaySummary,
    pressure: &SwarmPressureSummary,
    agent: &SwarmAgentRunSummary,
    plan: &SwarmWhatIfPlan,
) -> Value {
    let profile = array(contract, "large_host_profiles")
        .first()
        .expect("large_host_profiles must include fourth-wave profile");
    let region_ids = replay
        .admission_records
        .iter()
        .filter_map(|record| record.region_id)
        .collect::<Vec<_>>();
    let pressure_timeline = pressure
        .event_log
        .iter()
        .map(|event| {
            serde_json::json!({
                "step": event.step,
                "lane": stable_json(event.lane),
                "queue_depth": event.queue_depth,
                "rch_workers_available": event.rch_workers_available,
                "disk_pressure": stable_json(event.disk_pressure),
                "admission_latency_steps": event.admission_latency_steps,
            })
        })
        .collect::<Vec<_>>();
    let rch_worker_minimum = pressure
        .event_log
        .iter()
        .map(|event| event.rch_workers_available)
        .min()
        .unwrap_or(0);
    let rch_worker_maximum = pressure
        .event_log
        .iter()
        .map(|event| event.rch_workers_available)
        .max()
        .unwrap_or(0);

    serde_json::json!({
        "scenario_id": format!("{}/{}/{}", replay.scenario_id, pressure.scenario_id, agent.scenario_id),
        "seed": {
            "replay": replay.seed,
            "pressure": pressure.seed,
            "agent_run": agent.seed,
        },
        "host_envelope": {
            "profile_id": string(profile, "profile_id"),
            "cpu_cores": profile["cpu_cores"],
            "memory_gib": profile["memory_gib"],
        },
        "agent_count": agent.agent_count,
        "task_counts": {
            "replay_total": replay.task_count,
            "replay_scheduled": replay.scheduled_task_count,
            "pressure_interactive": pressure.interactive_tasks,
            "pressure_proof": pressure.proof_tasks,
            "pressure_cleanup": pressure.cleanup_requests,
            "agent_scheduled": agent.scheduled_task_count,
        },
        "region_ids": region_ids,
        "obligation_counts": {
            "commits": replay.obligation_commits,
            "aborts": replay.obligation_aborts,
            "total": replay.obligation_commits.saturating_add(replay.obligation_aborts),
        },
        "pressure_timeline": pressure_timeline,
        "rch_queue_state": {
            "worker_minimum": rch_worker_minimum,
            "worker_maximum": rch_worker_maximum,
            "loss_events": pressure.rch_worker_loss_events,
            "recovery_events": pressure.rch_worker_recovery_events,
            "remote_refusals": agent.rch_remote_refusal_count,
            "first_blocker": agent.first_blocker.clone(),
        },
        "final_governor_input_snapshot": {
            "schema_version": plan.schema_version.clone(),
            "scenario_id": plan.scenario_id.clone(),
            "agent_count": plan.agent_count,
            "weighted_demand_units": plan.weighted_demand_units,
            "weighted_capacity_units": plan.weighted_capacity_units,
            "bounded_queue_estimate": plan.bounded_queue_estimate,
            "recommendation": stable_json(plan.recommendation),
            "starvation_risk": stable_json(plan.starvation_risk),
            "input_freshness": stable_json(plan.input_freshness),
            "first_cap_to_adjust": plan.first_cap_to_adjust.clone(),
            "first_blocker": plan.first_blocker.clone(),
            "deferred_workload_ids": plan.deferred_workload_ids.clone(),
        },
    })
}

fn assert_no_forbidden_markers(row: &Value, id_key: &str, forbidden: &BTreeSet<String>) {
    let rendered =
        serde_json::to_string(row).expect("scenario row must render to JSON for marker scan");
    let rendered_lower = rendered.to_ascii_lowercase();
    for marker in forbidden {
        assert!(
            !rendered_lower.contains(marker),
            "{} must not contain forbidden fixture marker {marker}",
            string(row, id_key)
        );
    }
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
        contract["extension_bead_id"].as_str(),
        Some("asupersync-86fe9v.3")
    );
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

    let profile = array(&contract, "large_host_profiles")
        .first()
        .expect("large_host_profiles must include fourth-wave profile");
    assert_eq!(string(profile, "profile_id"), "large-host-64c-256g");
    assert_eq!(profile["cpu_cores"].as_u64(), Some(64));
    assert_eq!(profile["memory_gib"].as_u64(), Some(256));
    assert!(
        string_set(profile, "non_claims").contains("does_not_authorize_local_cargo_fallback"),
        "large-host profile must stay truthful about non-claims"
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
fn fourth_wave_workload_dimensions_are_complete_and_stably_ordered() {
    let contract = contract();
    let required = string_set(&contract, "required_fourth_wave_workload_dimensions");
    let mut covered = BTreeSet::new();

    for row in array(&contract, "pressure_scenarios") {
        assert_eq!(
            string(row, "scenario_id"),
            string(&row["pressure_scenario"], "scenario_id")
        );
        covered.extend(workload_dimensions(row));
    }
    for row in array(&contract, "agent_run_scenarios") {
        assert_eq!(
            string(row, "scenario_id"),
            string(&row["agent_run_scenario"], "scenario_id")
        );
        covered.extend(workload_dimensions(row));
    }
    for row in array(&contract, "what_if_scenarios") {
        assert_eq!(
            string(row, "scenario_id"),
            string(&row["what_if_scenario"], "scenario_id")
        );
        covered.extend(workload_dimensions(row));
    }

    let missing = required.difference(&covered).cloned().collect::<Vec<_>>();
    assert!(
        missing.is_empty(),
        "missing fourth-wave dimensions: {missing:?}"
    );

    let projection = serde_json::json!({
        "extension_bead_id": contract["extension_bead_id"],
        "required": contract["required_fourth_wave_workload_dimensions"],
        "pressure": array(&contract, "pressure_scenarios")
            .iter()
            .map(|row| string(row, "scenario_id"))
            .collect::<Vec<_>>(),
        "agent": array(&contract, "agent_run_scenarios")
            .iter()
            .map(|row| string(row, "scenario_id"))
            .collect::<Vec<_>>(),
        "what_if": array(&contract, "what_if_scenarios")
            .iter()
            .map(|row| string(row, "scenario_id"))
            .collect::<Vec<_>>(),
    });
    assert_eq!(
        stable_hash(&projection),
        "203d0606046b112add24928304c537e1c69da4c314fbf4d1b7f0c83fff0d485e"
    );
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
fn pressure_scenarios_validate_and_run_deterministically() {
    let contract = contract();
    for row in array(&contract, "pressure_scenarios") {
        let scenario = parse_pressure(row);
        scenario
            .validate()
            .unwrap_or_else(|error| panic!("{} must validate: {error}", scenario.scenario_id));
        assert_eq!(scenario.scenario_id, string(row, "scenario_id"));

        let dimensions = workload_dimensions(row);
        if dimensions.contains("large_host_64c_256g") {
            assert_eq!(scenario.worker_count, 64);
        }
        if dimensions.contains("rch_active_project_exclusion") {
            assert!(
                scenario
                    .rch_worker_events
                    .iter()
                    .any(|event| event.worker_delta == scenario.rch_workers_initial),
                "{} must model full RCH worker loss",
                scenario.scenario_id
            );
        }

        if string(row, "execution_mode") != "run_in_contract" {
            continue;
        }

        let first = run_swarm_pressure_scenario(&scenario)
            .unwrap_or_else(|error| panic!("{} first run: {error}", scenario.scenario_id));
        let second = run_swarm_pressure_scenario(&scenario)
            .unwrap_or_else(|error| panic!("{} second run: {error}", scenario.scenario_id));
        assert_eq!(
            first, second,
            "{} must replay deterministically",
            scenario.scenario_id
        );
        assert_eq!(first.schema_version, SWARM_PRESSURE_SCHEMA_VERSION);
        assert!(first.quiescent, "{} must quiesce", first.scenario_id);
        assert_eq!(first.non_terminal_task_count, 0);
        assert!(first.invariant_violations.is_empty());
        assert_eq!(
            stable_hash(&serde_json::to_value(&first).expect("summary json")),
            stable_hash(&serde_json::to_value(&second).expect("summary json"))
        );

        if dimensions.contains("release_gate_quiet_phase") {
            assert!(first.rch_worker_loss_events > 0);
            assert!(first.rch_worker_recovery_events > 0);
            assert!(first.proof_throttled_count > 0);
        }
        assert_eq!(
            first.auto_delete_command_count, 0,
            "pressure corpus must never authorize cleanup commands"
        );
    }
}

#[test]
fn agent_run_scenarios_model_tracker_rch_and_handoff_without_side_effects() {
    let contract = contract();
    for row in array(&contract, "agent_run_scenarios") {
        let scenario = parse_agent_run(row);
        scenario
            .validate()
            .unwrap_or_else(|error| panic!("{} must validate: {error}", scenario.scenario_id));
        assert_eq!(scenario.scenario_id, string(row, "scenario_id"));

        let dimensions = workload_dimensions(row);
        if dimensions.contains("large_host_64c_256g") {
            assert_eq!(scenario.agent_count, 64);
        }
        if string(row, "execution_mode") != "run_in_contract" {
            continue;
        }

        let first = run_swarm_agent_run_scenario(&scenario)
            .unwrap_or_else(|error| panic!("{} first run: {error}", scenario.scenario_id));
        let second = run_swarm_agent_run_scenario(&scenario)
            .unwrap_or_else(|error| panic!("{} second run: {error}", scenario.scenario_id));
        assert_eq!(
            first, second,
            "{} must replay deterministically",
            scenario.scenario_id
        );
        assert_eq!(first.schema_version, SWARM_AGENT_RUN_SCHEMA_VERSION);
        assert!(first.quiescent, "{} must quiesce", first.scenario_id);
        assert_eq!(first.non_terminal_task_count, 0);
        assert_eq!(first.bead_claim_count, scenario.agent_count);
        assert_eq!(first.file_reservations_acquired, scenario.agent_count);
        assert_eq!(first.file_reservations_released, scenario.agent_count);
        assert!(first.no_duplicate_ownership);
        assert!(first.no_leaked_reservations);
        assert!(first.no_false_green_proof);
        assert!(first.non_mutating);
        assert!(!first.forbidden_actions.runs_cargo);
        assert!(!first.forbidden_actions.runs_git_mutation);
        assert!(!first.forbidden_actions.runs_beads_mutation);
        assert!(!first.forbidden_actions.runs_agent_mail_mutation);
        assert!(!first.forbidden_actions.runs_destructive_command);

        if dimensions.contains("rch_active_project_exclusion") {
            assert!(first.rch_remote_refusal_count > 0);
            assert!(
                first
                    .first_blocker
                    .as_deref()
                    .is_some_and(|blocker| blocker.contains("rch remote required refused"))
            );
        }
        if dimensions.contains("stalled_worker_recovery") {
            assert!(first.recovery_handoff_count > 0);
            assert!(first.crashed_agent_count > 0);
        }
    }
}

#[test]
fn what_if_scenarios_cover_no_useful_work_and_memory_heavy_planning() {
    let contract = contract();
    for row in array(&contract, "what_if_scenarios") {
        let scenario = parse_what_if(row);
        scenario
            .validate()
            .unwrap_or_else(|error| panic!("{} must validate: {error}", scenario.scenario_id));
        assert_eq!(scenario.scenario_id, string(row, "scenario_id"));

        let first = plan_swarm_admission_wave(&scenario)
            .unwrap_or_else(|error| panic!("{} first plan: {error}", scenario.scenario_id));
        let second = plan_swarm_admission_wave(&scenario)
            .unwrap_or_else(|error| panic!("{} second plan: {error}", scenario.scenario_id));
        assert_eq!(
            first, second,
            "{} plan must be deterministic",
            scenario.scenario_id
        );
        assert_eq!(first.schema_version, SWARM_WHAT_IF_PLAN_SCHEMA_VERSION);
        assert!(!first.destructive_cleanup_required);
        assert!(!first.branch_or_worktree_required);

        let dimensions = workload_dimensions(row);
        if dimensions.contains("no_useful_work_planning_fallback") {
            assert_eq!(first.agent_count, 0);
            assert_eq!(first.recommendation, SwarmWhatIfRecommendation::AdmitNow);
            assert!(first.deferred_workload_ids.is_empty());
            assert!(first.first_blocker.is_none());
        }
        if dimensions.contains("memory_heavy_artifact_generation") {
            assert_eq!(first.recommendation, SwarmWhatIfRecommendation::SplitWave);
            assert_eq!(
                first.first_cap_to_adjust.as_deref(),
                Some("memory_tier_cap")
            );
            assert!(
                first
                    .deferred_workload_ids
                    .iter()
                    .any(|id| id == "memory-heavy-artifact-generation")
            );
        }
    }
}

#[test]
fn e2e_runner_log_projection_is_deterministic_and_complete() {
    let contract = contract();
    let required = string_set(&contract["runner_log_contract"], "required_fields");
    let replay_scenario = parse_replay(row_by_id(
        &contract,
        "scenarios",
        "swarm-fanout-healthy-baseline",
    ));
    let pressure_scenario = parse_pressure(row_by_id(
        &contract,
        "pressure_scenarios",
        "fourth-wave-large-host-release-gate-pressure",
    ));
    let agent_scenario = parse_agent_run(row_by_id(
        &contract,
        "agent_run_scenarios",
        "fourth-wave-agent-swarm-rch-refusal-handoff",
    ));
    let what_if_scenario = parse_what_if(row_by_id(
        &contract,
        "what_if_scenarios",
        "fourth-wave-memory-heavy-artifact-planning",
    ));

    let replay_first = run_swarm_replay_scenario(&replay_scenario).unwrap_or_else(|error| {
        panic!("{} replay first run: {error}", replay_scenario.scenario_id)
    });
    let replay_second = run_swarm_replay_scenario(&replay_scenario).unwrap_or_else(|error| {
        panic!("{} replay second run: {error}", replay_scenario.scenario_id)
    });
    let pressure_first = run_swarm_pressure_scenario(&pressure_scenario).unwrap_or_else(|error| {
        panic!(
            "{} pressure first run: {error}",
            pressure_scenario.scenario_id
        )
    });
    let pressure_second = run_swarm_pressure_scenario(&pressure_scenario).unwrap_or_else(|error| {
        panic!(
            "{} pressure second run: {error}",
            pressure_scenario.scenario_id
        )
    });
    let agent_first = run_swarm_agent_run_scenario(&agent_scenario)
        .unwrap_or_else(|error| panic!("{} agent first run: {error}", agent_scenario.scenario_id));
    let agent_second = run_swarm_agent_run_scenario(&agent_scenario)
        .unwrap_or_else(|error| panic!("{} agent second run: {error}", agent_scenario.scenario_id));
    let plan_first = plan_swarm_admission_wave(&what_if_scenario).unwrap_or_else(|error| {
        panic!(
            "{} what-if first plan: {error}",
            what_if_scenario.scenario_id
        )
    });
    let plan_second = plan_swarm_admission_wave(&what_if_scenario).unwrap_or_else(|error| {
        panic!(
            "{} what-if second plan: {error}",
            what_if_scenario.scenario_id
        )
    });

    let first_log = runner_log_projection(
        &contract,
        &replay_first,
        &pressure_first,
        &agent_first,
        &plan_first,
    );
    let second_log = runner_log_projection(
        &contract,
        &replay_second,
        &pressure_second,
        &agent_second,
        &plan_second,
    );
    assert_eq!(
        first_log, second_log,
        "runner log projection must be deterministic"
    );
    assert_eq!(
        stable_hash(&first_log),
        stable_hash(&second_log),
        "runner log artifact hash must be stable"
    );

    let log_object = first_log
        .as_object()
        .expect("runner log projection must be an object");
    for field in required {
        assert!(
            log_object.contains_key(&field),
            "runner log missing required field {field}"
        );
    }
    assert_eq!(first_log["host_envelope"]["cpu_cores"].as_u64(), Some(64));
    assert_eq!(first_log["host_envelope"]["memory_gib"].as_u64(), Some(256));
    assert_eq!(first_log["agent_count"].as_u64(), Some(64));
    assert!(
        first_log["region_ids"]
            .as_array()
            .is_some_and(|region_ids| !region_ids.is_empty()),
        "runner log must include runtime region ids"
    );
    assert!(
        first_log["pressure_timeline"]
            .as_array()
            .is_some_and(|timeline| !timeline.is_empty()),
        "runner log must include pressure timeline entries"
    );
    assert!(
        first_log["obligation_counts"]["total"]
            .as_u64()
            .unwrap_or(0)
            > 0,
        "runner log must include nonzero obligation accounting"
    );
    assert_eq!(
        first_log["final_governor_input_snapshot"]["recommendation"].as_str(),
        Some("split_wave")
    );
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
    for section in [
        "scenarios",
        "pressure_scenarios",
        "agent_run_scenarios",
        "what_if_scenarios",
    ] {
        for row in array(&contract, section) {
            assert_no_forbidden_markers(row, "scenario_id", &forbidden);
        }
    }
    for row in array(&contract, "malformed_examples") {
        assert_no_forbidden_markers(row, "case_id", &forbidden);
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
