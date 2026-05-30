#![allow(missing_docs)]

use asupersync::lab::{
    SWARM_REPLAY_SCHEMA_VERSION, SwarmReplayAdmissionDecision, SwarmReplayScenario,
    SwarmReplaySummary, run_swarm_replay_scenario,
};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

const CONTRACT_PATH: &str = "artifacts/no_mock_massive_agent_swarm_e2e_contract_v1.json";
const SCENARIO_CORPUS_PATH: &str = "artifacts/swarm_workload_scenario_corpus_v1.json";
const RUNNER_SCRIPT_PATH: &str = "scripts/run_no_mock_massive_agent_swarm_e2e.sh";
const EVENT_PREFIX: &str = "NO_MOCK_MASSIVE_AGENT_SWARM_E2E_EVENT ";

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_json(relative: &str) -> Value {
    let path = repo_path(relative);
    let raw =
        std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("read {relative}: {error}"));
    serde_json::from_str(&raw).unwrap_or_else(|error| panic!("parse {}: {error}", path.display()))
}

fn array<'a>(value: &'a Value, key: &str) -> &'a Vec<Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
}

fn object<'a>(value: &'a Value, key: &str) -> &'a Value {
    let item = value
        .get(key)
        .unwrap_or_else(|| panic!("{key} must be present"));
    assert!(item.is_object(), "{key} must be an object");
    item
}

fn string<'a>(value: &'a Value, key: &str) -> &'a str {
    let item = value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"));
    assert!(!item.trim().is_empty(), "{key} must be nonempty");
    item
}

fn bool_value(value: &Value, key: &str) -> bool {
    value
        .get(key)
        .and_then(Value::as_bool)
        .unwrap_or_else(|| panic!("{key} must be a bool"))
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

fn artifact() -> Value {
    read_json(CONTRACT_PATH)
}

fn scenario_corpus() -> Value {
    read_json(SCENARIO_CORPUS_PATH)
}

fn scenario_rows(corpus: &Value) -> BTreeMap<String, &Value> {
    array(corpus, "scenarios")
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

fn selected_matrix_rows<'a>(artifact: &'a Value, profile: &str) -> Vec<&'a Value> {
    array(artifact, "scenario_matrix")
        .iter()
        .filter(|row| profile == "all" || string(row, "profile") == profile)
        .collect()
}

fn env_string(key: &str, fallback: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| fallback.to_string())
}

fn overrides_json() -> Value {
    std::env::var("NO_MOCK_MASSIVE_AGENT_SWARM_E2E_OVERRIDES")
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_else(|| {
            json!({
                "worker_count": null,
                "region_count": null,
                "tasks_per_region": null,
                "channel_fanout": null,
                "cancellation_rate": null,
                "obligation_rate": null,
            })
        })
}

fn apply_overrides(mut scenario: SwarmReplayScenario, overrides: &Value) -> SwarmReplayScenario {
    if let Some(value) = overrides.get("worker_count").and_then(Value::as_u64) {
        scenario.worker_count = usize::try_from(value).expect("worker_count fits usize");
        scenario.cohort_count = scenario.cohort_count.min(scenario.worker_count);
    }
    if let Some(value) = overrides.get("region_count").and_then(Value::as_u64) {
        scenario.region_count = usize::try_from(value).expect("region_count fits usize");
    }
    if let Some(value) = overrides.get("tasks_per_region").and_then(Value::as_u64) {
        scenario.tasks_per_region = usize::try_from(value).expect("tasks_per_region fits usize");
    }
    if let Some(value) = overrides.get("channel_fanout").and_then(Value::as_u64) {
        scenario.messages_per_task = usize::try_from(value).expect("channel_fanout fits usize");
    }
    if let Some(value) = overrides.get("obligation_rate").and_then(Value::as_u64) {
        scenario.obligations_per_task = usize::try_from(value).expect("obligation_rate fits usize");
    }
    if let Some(rate) = overrides.get("cancellation_rate").and_then(Value::as_f64) {
        scenario.cancel_after_steps = if rate > 0.0 {
            Some(1_u64.min(scenario.max_steps.saturating_sub(1)))
        } else {
            None
        };
    }
    scenario
}

fn cancellation_rate_for(scenario: &SwarmReplayScenario, overrides: &Value) -> f64 {
    overrides
        .get("cancellation_rate")
        .and_then(Value::as_f64)
        .unwrap_or_else(|| {
            if scenario.cancel_after_steps.is_some() {
                1.0
            } else {
                0.0
            }
        })
}

fn modeled_memory_envelope(scenario: &SwarmReplayScenario, summary: &SwarmReplaySummary) -> u64 {
    scenario
        .region_memory_bytes_per_task
        .saturating_mul(summary.admitted_task_count as u64)
}

fn scenario_event_row(
    matrix_row: &Value,
    scenario: &SwarmReplayScenario,
    summary: Option<&SwarmReplaySummary>,
    proof_status: &str,
    first_failure: &str,
    overrides: &Value,
) -> Value {
    let profile = string(matrix_row, "profile");
    let command = env_string(
        "NO_MOCK_MASSIVE_AGENT_SWARM_E2E_COMMAND",
        "cargo test -p asupersync --test no_mock_massive_agent_swarm_e2e_contract",
    );
    let git_commit = env_string("NO_MOCK_MASSIVE_AGENT_SWARM_E2E_GIT_COMMIT", "unknown");
    let feature_set = env_string("NO_MOCK_MASSIVE_AGENT_SWARM_E2E_FEATURES", "test-internals");
    let artifact_path = env_string(
        "NO_MOCK_MASSIVE_AGENT_SWARM_E2E_OUTPUT_DIR",
        "target/no-mock-massive-agent-swarm-e2e/contract-test",
    );
    let task_count = summary.map_or_else(|| scenario.task_count(), |summary| summary.task_count);
    let quiescence_result = if proof_status == "fail_closed" {
        "blocked_cleanup"
    } else {
        summary.map_or("manifest_only", |summary| {
            if summary.quiescent && summary.non_terminal_task_count == 0 {
                "quiescent"
            } else {
                "not_quiescent"
            }
        })
    };
    let memory_envelope = summary.map_or_else(
        || {
            scenario
                .region_memory_bytes_per_task
                .saturating_mul(scenario.task_count() as u64)
        },
        |summary| modeled_memory_envelope(scenario, summary),
    );

    json!({
        "scenario_id": string(matrix_row, "scenario_id"),
        "profile": profile,
        "command": command,
        "git_commit": git_commit,
        "rch_worker": "captured-by-runner",
        "feature_set": feature_set,
        "worker_count": scenario.worker_count,
        "region_count": scenario.region_count,
        "task_count": task_count,
        "channel_fanout": scenario.messages_per_task,
        "cancellation_rate": cancellation_rate_for(scenario, overrides),
        "obligation_rate": scenario.obligations_per_task,
        "p95_latency_us": Value::Null,
        "p99_latency_us": Value::Null,
        "memory_envelope_bytes": memory_envelope,
        "quiescence_result": quiescence_result,
        "first_failure": first_failure,
        "artifact_path": artifact_path,
        "proof_status": proof_status,
    })
}

fn validate_event_row(artifact: &Value, row: &Value) -> Result<(), String> {
    let required = string_set(artifact, "required_log_fields");
    let present = row
        .as_object()
        .ok_or_else(|| "event row must be object".to_string())?
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    let missing = required.difference(&present).cloned().collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(format!("event row missing fields: {missing:?}"));
    }

    let proof_status = string(row, "proof_status");
    let first_failure = row
        .get("first_failure")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let quiescence_result = string(row, "quiescence_result");
    if proof_status == "pass" {
        if !first_failure.is_empty() {
            return Err("pass row must not carry first_failure".to_string());
        }
        if quiescence_result != "quiescent" {
            return Err("pass row must prove quiescence".to_string());
        }
    }
    if proof_status == "fail_closed" && first_failure.is_empty() {
        return Err("fail_closed row must explain first_failure".to_string());
    }

    let rendered = serde_json::to_string(row).expect("render event row");
    for marker in string_set(artifact, "forbidden_success_markers") {
        if rendered.to_ascii_lowercase().contains(&marker) {
            return Err(format!("event row contains forbidden marker {marker}"));
        }
    }
    Ok(())
}

fn emit_event(row: &Value) {
    println!(
        "{EVENT_PREFIX}{}",
        serde_json::to_string(row).expect("render event row")
    );
}

#[test]
fn artifact_declares_live_sources_rch_only_execution_and_required_fields() {
    let artifact = artifact();
    assert_eq!(
        artifact["contract_version"].as_str(),
        Some("no-mock-massive-agent-swarm-e2e-v1")
    );
    assert_eq!(artifact["bead_id"].as_str(), Some("asupersync-vssefs.6"));

    for key in ["runner_script", "contract_test", "scenario_corpus"] {
        let path = string(&artifact, key);
        assert!(repo_path(path).exists(), "{key} path must exist: {path}");
    }
    let scenario_source = object(&artifact, "scenario_source");
    assert_eq!(
        string(scenario_source, "runtime_scenario_type"),
        "asupersync::lab::SwarmReplayScenario"
    );
    assert_eq!(
        string(scenario_source, "runtime_runner"),
        "asupersync::lab::run_swarm_replay_scenario"
    );
    assert!(repo_path(string(scenario_source, "runtime_source")).exists());

    let policy = object(&artifact, "execution_policy");
    assert!(!bool_value(policy, "local_fallback_allowed"));
    assert!(string(&artifact, "proof_command").contains("RCH_REQUIRE_REMOTE=1"));
    assert!(string(&artifact, "proof_command").contains("--execute"));
    let runner_source =
        std::fs::read_to_string(repo_path(RUNNER_SCRIPT_PATH)).expect("read runner script");
    assert!(runner_source.contains("RCH_REQUIRE_REMOTE=1"));
    assert!(runner_source.contains("exec --"));
    assert!(string(&artifact, "dry_run_command").contains("--dry-run"));

    let required = string_set(&artifact, "required_log_fields");
    for field in [
        "scenario_id",
        "command",
        "git_commit",
        "rch_worker",
        "feature_set",
        "task_count",
        "memory_envelope_bytes",
        "quiescence_result",
        "first_failure",
        "proof_status",
    ] {
        assert!(required.contains(field), "missing required field {field}");
    }
}

#[test]
fn scenario_matrix_covers_knobs_profiles_failure_modes_and_source_fixtures() {
    let artifact = artifact();
    let corpus = scenario_corpus();
    let scenarios = scenario_rows(&corpus);
    let mut profiles = BTreeSet::new();
    let mut modes = BTreeSet::new();
    let mut failure_modes = BTreeSet::new();

    for row in array(&artifact, "scenario_matrix") {
        profiles.insert(string(row, "profile").to_string());
        modes.insert(string(row, "execution_mode").to_string());
        failure_modes.extend(string_set(row, "failure_modes"));

        let source_id = string(row, "source_scenario_id");
        let source = scenarios
            .get(source_id)
            .unwrap_or_else(|| panic!("missing source scenario {source_id}"));
        let scenario = parse_replay(source);
        scenario
            .validate()
            .unwrap_or_else(|error| panic!("{source_id} should validate: {error}"));

        let rendered = serde_json::to_string(row).expect("render matrix row");
        for marker in string_set(&artifact, "forbidden_success_markers") {
            assert!(
                !rendered.to_ascii_lowercase().contains(&marker),
                "{} contains forbidden success marker {marker}",
                string(row, "scenario_id")
            );
        }
    }

    assert_eq!(
        profiles,
        ["large", "medium", "small"]
            .into_iter()
            .map(String::from)
            .collect::<BTreeSet<_>>()
    );
    assert!(modes.contains("execute"));
    assert!(modes.contains("negative_contract"));
    assert!(modes.contains("manifest_only"));
    for required_mode in string_set(&artifact, "required_failure_modes") {
        assert!(
            failure_modes.contains(&required_mode),
            "missing failure mode {required_mode}"
        );
    }
}

#[test]
fn dry_run_manifest_is_deterministic_and_operator_grade() {
    let output = Command::new("bash")
        .arg(repo_path(RUNNER_SCRIPT_PATH))
        .arg("--dry-run")
        .arg("--profile")
        .arg("small")
        .arg("--run-id")
        .arg("contract-dry-run")
        .arg("--output-root")
        .arg(repo_path("target/no-mock-massive-agent-swarm-e2e-contract"))
        .output()
        .expect("run dry-run script");

    assert!(
        output.status.success(),
        "dry-run failed stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let manifest: Value =
        serde_json::from_slice(&output.stdout).expect("dry-run stdout must be JSON manifest");
    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("asupersync.no-mock-massive-agent-swarm-e2e.manifest.v1")
    );
    assert_eq!(manifest["mode"].as_str(), Some("dry-run"));
    assert_eq!(manifest["profile"].as_str(), Some("small"));
    assert_eq!(manifest["remote_required"].as_bool(), Some(true));
    assert_eq!(manifest["local_fallback_allowed"].as_bool(), Some(false));
    assert!(string(&manifest, "command").contains("RCH_REQUIRE_REMOTE=1"));
    assert!(string(&manifest, "command").contains("rch exec"));
    assert!(
        array(&manifest, "selected_scenarios")
            .iter()
            .any(|row| string(row, "execution_mode") == "negative_contract"),
        "small manifest must include blocked-cleanup negative contract row"
    );
}

#[test]
fn selected_profile_runs_real_lab_scenarios_and_emits_operator_rows() {
    let artifact = artifact();
    let corpus = scenario_corpus();
    let scenarios = scenario_rows(&corpus);
    let profile = env_string("NO_MOCK_MASSIVE_AGENT_SWARM_E2E_PROFILE", "small");
    let overrides = overrides_json();
    let selected = selected_matrix_rows(&artifact, &profile);
    assert!(!selected.is_empty(), "profile {profile} selected no rows");

    let mut emitted_rows = Vec::new();
    for matrix_row in selected {
        let source_id = string(matrix_row, "source_scenario_id");
        let source = scenarios
            .get(source_id)
            .unwrap_or_else(|| panic!("missing source scenario {source_id}"));
        let scenario = apply_overrides(parse_replay(source), &overrides);
        scenario
            .validate()
            .unwrap_or_else(|error| panic!("{} should validate: {error}", scenario.scenario_id));

        let row = match string(matrix_row, "execution_mode") {
            "execute" => {
                let summary = run_swarm_replay_scenario(&scenario)
                    .unwrap_or_else(|error| panic!("{} should run: {error}", scenario.scenario_id));
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
                if string_set(matrix_row, "failure_modes").contains("admission_rejection") {
                    assert!(
                        summary.admission_records.iter().any(|record| {
                            matches!(
                                record.decision,
                                SwarmReplayAdmissionDecision::Shed
                                    | SwarmReplayAdmissionDecision::Cancel
                            )
                        }),
                        "{} must expose admission pressure",
                        string(matrix_row, "scenario_id")
                    );
                }
                if string_set(matrix_row, "failure_modes").contains("cancellation_storm") {
                    assert!(
                        summary.cancellation_requests > 0
                            || summary.admission_cancelled_task_count > 0,
                        "{} must request cancellation or admission cancel",
                        string(matrix_row, "scenario_id")
                    );
                }
                scenario_event_row(
                    matrix_row,
                    &scenario,
                    Some(&summary),
                    "pass",
                    "",
                    &overrides,
                )
            }
            "negative_contract" => {
                let summary = run_swarm_replay_scenario(&scenario)
                    .unwrap_or_else(|error| panic!("{} should run: {error}", scenario.scenario_id));
                scenario_event_row(
                    matrix_row,
                    &scenario,
                    Some(&summary),
                    "fail_closed",
                    string(matrix_row, "expected_first_failure"),
                    &overrides,
                )
            }
            "manifest_only" => scenario_event_row(
                matrix_row,
                &scenario,
                None,
                "manifest_only",
                matrix_row
                    .get("expected_first_failure")
                    .and_then(Value::as_str)
                    .unwrap_or("expensive lane is manifest-only for this profile"),
                &overrides,
            ),
            other => panic!("unsupported execution mode {other}"),
        };

        validate_event_row(&artifact, &row).unwrap_or_else(|error| {
            panic!(
                "{} invalid event row: {error}",
                string(matrix_row, "scenario_id")
            )
        });
        emit_event(&row);
        emitted_rows.push(row);
    }

    if let Ok(output_dir) = std::env::var("NO_MOCK_MASSIVE_AGENT_SWARM_E2E_OUTPUT_DIR") {
        let path = PathBuf::from(output_dir);
        std::fs::create_dir_all(&path)
            .unwrap_or_else(|error| panic!("create {}: {error}", path.display()));
        let report_path = path.join("contract_scenario_events.json");
        std::fs::write(
            &report_path,
            serde_json::to_vec_pretty(&emitted_rows).expect("render emitted rows"),
        )
        .unwrap_or_else(|error| panic!("write {}: {error}", report_path.display()));
    }
}

#[test]
fn blocked_cleanup_negative_contract_cannot_be_reported_as_success() {
    let artifact = artifact();
    let corpus = scenario_corpus();
    let scenarios = scenario_rows(&corpus);
    let blocked = array(&artifact, "scenario_matrix")
        .iter()
        .find(|row| string(row, "scenario_id") == "swarm-blocked-cleanup-negative")
        .expect("blocked cleanup row exists");
    let source = scenarios
        .get(string(blocked, "source_scenario_id"))
        .expect("blocked cleanup source exists");
    let scenario = parse_replay(source);
    let summary =
        run_swarm_replay_scenario(&scenario).expect("blocked-cleanup source scenario should run");
    let fail_closed = scenario_event_row(
        blocked,
        &scenario,
        Some(&summary),
        "fail_closed",
        string(blocked, "expected_first_failure"),
        &overrides_json(),
    );
    validate_event_row(&artifact, &fail_closed).expect("fail-closed row should validate");

    let mut false_green = fail_closed.clone();
    false_green["proof_status"] = json!("pass");
    assert!(
        validate_event_row(&artifact, &false_green).is_err(),
        "blocked cleanup row must not be reportable as pass"
    );
}
