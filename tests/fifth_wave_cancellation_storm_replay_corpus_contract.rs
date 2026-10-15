#![allow(missing_docs)]

use asupersync::lab::{
    SWARM_REPLAY_SCHEMA_VERSION, SwarmReplayScenario, run_swarm_replay_scenario,
};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const ARTIFACT_PATH: &str = "artifacts/fifth_wave_cancellation_storm_replay_corpus_v1.json";
const ATLAS_PATH: &str = "artifacts/fifth_wave_swarm_control_plane_atlas_v1.json";
const SCENARIO_CORPUS_PATH: &str = "artifacts/swarm_workload_scenario_corpus_v1.json";
const TEST_PATH: &str = "tests/fifth_wave_cancellation_storm_replay_corpus_contract.rs";

const OWNER_BEAD: &str = "asupersync-cancellation-storm-replay-corpus-z7hfs6";
const LANE_ID: &str = "fifth-wave-cancellation-storm-replay-corpus";
const PROOF_COMMAND_ID: &str = "fifth-wave-cancellation-storm-replay-corpus-contract";
const TARGET_DIR: &str = "${TMPDIR:-/tmp}/rch_target_fifth_wave_cancellation_storm_replay_corpus";

const REQUIRED_INVARIANTS: &[&str] = &[
    "runtime-quiescent",
    "all-tracked-tasks-terminal",
    "cancellation-request-observed",
    "obligations-resolved",
    "losers-drained",
    "deterministic-replay",
];

const REQUIRED_SUMMARY_FIELDS: &[&str] = &[
    "schema_version",
    "scenario_id",
    "seed",
    "worker_count",
    "cohort_count",
    "region_count",
    "task_count",
    "scheduled_task_count",
    "terminal_task_count",
    "non_terminal_task_count",
    "cancellation_requests",
    "obligation_commits",
    "obligation_aborts",
    "timer_registrations",
    "timer_wakeups",
    "cancellation_drain_steps",
    "quiescent",
    "trace_digest",
    "trace_event_count",
    "invariant_violations",
    "shrink_hint",
    "admission_records",
];

const REQUIRED_LOG_FIELDS: &[&str] = &[
    "scenario_id",
    "source_scenario_id",
    "seed",
    "worker_count",
    "cohort_count",
    "region_count",
    "scheduled_task_count",
    "terminal_task_count",
    "non_terminal_task_count",
    "cancellation_requests",
    "obligation_commits",
    "obligation_aborts",
    "cancellation_drain_steps",
    "quiescent",
    "trace_digest",
    "trace_event_count",
    "first_invariant_violation",
    "shrink_hint",
];

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_repo_file(relative: &str) -> String {
    std::fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|error| panic!("read {relative}: {error}"))
}

fn read_json(relative: &str) -> Value {
    serde_json::from_str(&read_repo_file(relative))
        .unwrap_or_else(|error| panic!("parse {relative}: {error}"))
}

fn artifact() -> Value {
    read_json(ARTIFACT_PATH)
}

fn atlas() -> Value {
    read_json(ATLAS_PATH)
}

fn scenario_corpus() -> Value {
    read_json(SCENARIO_CORPUS_PATH)
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

fn usize_field(value: &Value, key: &str) -> usize {
    value
        .get(key)
        .and_then(Value::as_u64)
        .unwrap_or_else(|| panic!("{key} must be an unsigned integer"))
        .try_into()
        .unwrap_or_else(|_| panic!("{key} must fit usize"))
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

fn rows_by_id<'a>(value: &'a Value, key: &str, id_key: &str) -> BTreeMap<String, &'a Value> {
    array(value, key)
        .iter()
        .map(|row| (string(row, id_key).to_string(), row))
        .collect()
}

fn scenario_rows(corpus: &Value) -> BTreeMap<String, &Value> {
    rows_by_id(corpus, "scenarios", "scenario_id")
}

fn parse_replay_scenario(row: &Value) -> SwarmReplayScenario {
    serde_json::from_value(
        row.get("replay_scenario")
            .unwrap_or_else(|| panic!("{} missing replay_scenario", string(row, "scenario_id")))
            .clone(),
    )
    .unwrap_or_else(|error| {
        panic!(
            "parse {} replay_scenario: {error}",
            string(row, "scenario_id")
        )
    })
}

fn assert_remote_required_cargo(command: &str) {
    assert!(
        command.starts_with("RCH_REQUIRE_REMOTE=1 rch exec -- env "),
        "proof command must require remote RCH: {command}"
    );
    assert!(
        command.contains(" cargo test "),
        "proof command must run cargo test through RCH: {command}"
    );
    assert!(
        command.contains(TARGET_DIR),
        "proof command must use the fifth-wave target dir: {command}"
    );
    for required in [
        "CARGO_INCREMENTAL=0",
        "CARGO_PROFILE_TEST_DEBUG=0",
        "RUSTFLAGS='-D warnings -C debuginfo=0'",
        "--test fifth_wave_cancellation_storm_replay_corpus_contract",
        "-- --nocapture",
    ] {
        assert!(
            command.contains(required),
            "proof command missing {required}: {command}"
        );
    }
    for forbidden in [
        "RCH_ALLOW_LOCAL=1",
        "RCH_REQUIRE_REMOTE=0",
        "local fallback",
    ] {
        assert!(
            !command.contains(forbidden),
            "proof command contains forbidden fallback marker {forbidden}: {command}"
        );
    }
}

fn validate_contract(value: &Value) -> Vec<String> {
    let mut errors = Vec::new();

    let proof_lane = object(value, "proof_lane");
    if bool_field(
        value.get("proof_lane").expect("proof_lane"),
        "local_fallback_allowed",
    ) {
        errors.push("local fallback allowed".to_string());
    }
    let non_claims = string_set(&Value::Object(proof_lane.clone()), "does_not_cover");
    for required in [
        "does not prove broad cancellation correctness",
        "does not prove broad workspace health",
        "does not replace DPOR or formal proofs",
        "does not implement production admission policy",
    ] {
        if !non_claims.contains(required) {
            errors.push(format!("missing non-claim: {required}"));
        }
    }

    let summary_fields = string_set(value, "required_summary_fields");
    for required in REQUIRED_SUMMARY_FIELDS {
        if !summary_fields.contains(*required) {
            errors.push(format!("missing summary field: {required}"));
        }
    }
    for required in ["obligation_commits", "obligation_aborts"] {
        if !summary_fields.contains(required) {
            errors.push(format!("missing obligation resolution field: {required}"));
        }
    }

    let invariant_ids = rows_by_id(value, "invariant_catalog", "invariant_id");
    for required in REQUIRED_INVARIANTS {
        if !invariant_ids.contains_key(*required) {
            errors.push(format!("missing invariant: {required}"));
        }
    }

    let fixture_rows = rows_by_id(value, "fixture_catalog", "fixture_id");
    for (fixture_id, row) in fixture_rows {
        if !row.get("shrink").is_some_and(Value::is_object) {
            errors.push(format!("{fixture_id} missing shrink metadata"));
            continue;
        }
        let shrink = object(row, "shrink");
        if string(row, "execution_mode") == "run_in_contract" {
            let dimensions = string_set(row, "semantic_dimensions");
            if dimensions.contains("cancellation_storm")
                && usize_field(row, "minimum_cancellation_requests") == 0
            {
                errors.push(format!(
                    "{fixture_id} cancellation storm does not require cancellation"
                ));
            }
        }
        if array(&Value::Object(shrink.clone()), "preserve_fields").is_empty() {
            errors.push(format!("{fixture_id} shrink preserve_fields empty"));
        }
        if usize_field(&Value::Object(shrink.clone()), "first_region_count") == 0
            || usize_field(&Value::Object(shrink.clone()), "first_tasks_per_region") == 0
        {
            errors.push(format!("{fixture_id} shrink target must stay positive"));
        }
    }

    errors
}

#[test]
fn artifact_matches_atlas_lane_sources_and_remote_proof_command() {
    let artifact = artifact();
    assert_eq!(
        string(&artifact, "schema_version"),
        "fifth-wave-cancellation-storm-replay-corpus-v1"
    );
    assert_eq!(string(&artifact, "bead_id"), OWNER_BEAD);

    for (key, expected) in [
        ("atlas_artifact", ATLAS_PATH),
        ("scenario_corpus", SCENARIO_CORPUS_PATH),
        (
            "scenario_contract",
            "tests/swarm_workload_scenario_corpus_contract.rs",
        ),
        (
            "trace_summary_contract",
            "tests/swarm_pressure_trace_summary_contract.rs",
        ),
        ("runtime_source", "src/lab/swarm_replay.rs"),
        ("contract_test", TEST_PATH),
    ] {
        assert_eq!(string(&artifact["source_of_truth"], key), expected);
        assert!(
            repo_path(expected).exists(),
            "{key} path must exist: {expected}"
        );
    }

    let atlas = atlas();
    let atlas_rows = rows_by_id(&atlas, "child_lanes", "owner_bead");
    let atlas_lane = atlas_rows
        .get(OWNER_BEAD)
        .unwrap_or_else(|| panic!("atlas missing owner bead {OWNER_BEAD}"));
    let proof_lane = &artifact["proof_lane"];

    assert_eq!(string(proof_lane, "lane_id"), LANE_ID);
    assert_eq!(string(proof_lane, "proof_command_id"), PROOF_COMMAND_ID);
    assert_eq!(
        string(proof_lane, "proof_command"),
        string(atlas_lane, "proof_command")
    );
    assert!(!bool_field(proof_lane, "local_fallback_allowed"));
    assert_remote_required_cargo(string(proof_lane, "proof_command"));
}

#[test]
fn fixture_catalog_maps_existing_scenarios_invariants_shrink_and_logs() {
    let artifact = artifact();
    let corpus = scenario_corpus();
    let scenarios = scenario_rows(&corpus);
    let invariant_ids = rows_by_id(&artifact, "invariant_catalog", "invariant_id");

    let summary_fields = string_set(&artifact, "required_summary_fields");
    for required in REQUIRED_SUMMARY_FIELDS {
        assert!(
            summary_fields.contains(*required),
            "summary field missing {required}"
        );
    }
    let log_fields = string_set(&artifact, "required_log_fields");
    for required in REQUIRED_LOG_FIELDS {
        assert!(
            log_fields.contains(*required),
            "log field missing {required}"
        );
    }

    let fixtures = rows_by_id(&artifact, "fixture_catalog", "fixture_id");
    assert_eq!(fixtures.len(), 3);
    assert!(fixtures.contains_key("storm-small-executable"));
    assert!(fixtures.contains_key("admission-cancel-drain-validate"));
    assert!(fixtures.contains_key("healthy-baseline-contrast"));

    for (fixture_id, row) in fixtures {
        let source_id = string(row, "source_scenario_id");
        let source = scenarios
            .get(source_id)
            .unwrap_or_else(|| panic!("{fixture_id} references unknown source {source_id}"));
        let replay = parse_replay_scenario(source);
        replay
            .validate()
            .unwrap_or_else(|error| panic!("{source_id} scenario must validate: {error}"));

        assert!(!string_set(row, "semantic_dimensions").is_empty());
        assert!(
            usize_field(row, "minimum_obligation_resolutions") > 0,
            "{fixture_id} must require obligation evidence"
        );
        for invariant in string_set(row, "required_invariants") {
            assert!(
                invariant_ids.contains_key(&invariant),
                "{fixture_id} references missing invariant {invariant}"
            );
        }

        let shrink = object(row, "shrink");
        let strategy = shrink
            .get("strategy")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("{fixture_id} shrink.strategy must be a string"));
        assert!(
            !strategy.trim().is_empty(),
            "{fixture_id} shrink.strategy must be nonempty"
        );
    }
}

#[test]
fn executable_cancellation_storm_replays_deterministically_and_quiesces() {
    let artifact = artifact();
    let corpus = scenario_corpus();
    let scenarios = scenario_rows(&corpus);
    let fixtures = rows_by_id(&artifact, "fixture_catalog", "fixture_id");
    let row = fixtures
        .get("storm-small-executable")
        .expect("missing executable storm fixture");
    assert_eq!(string(row, "execution_mode"), "run_in_contract");

    let source_id = string(row, "source_scenario_id");
    let scenario_row = scenarios
        .get(source_id)
        .unwrap_or_else(|| panic!("missing source scenario {source_id}"));
    let scenario = parse_replay_scenario(scenario_row);
    assert!(
        scenario.cancel_after_steps.is_some(),
        "storm scenario must request cancellation"
    );

    let first = run_swarm_replay_scenario(&scenario)
        .unwrap_or_else(|error| panic!("{source_id} first replay: {error}"));
    let second = run_swarm_replay_scenario(&scenario)
        .unwrap_or_else(|error| panic!("{source_id} second replay: {error}"));
    assert_eq!(first, second, "swarm replay must be deterministic");

    assert_eq!(first.schema_version, SWARM_REPLAY_SCHEMA_VERSION);
    assert_eq!(first.scenario_id, source_id);
    assert!(first.quiescent, "{source_id} must quiesce");
    assert_eq!(first.non_terminal_task_count, 0);
    assert_eq!(first.terminal_task_count, first.scheduled_task_count);
    assert!(
        first.invariant_violations.is_empty(),
        "{source_id} invariant violations: {:?}",
        first.invariant_violations
    );
    assert!(
        first.cancellation_requests >= usize_field(row, "minimum_cancellation_requests"),
        "{source_id} must request cancellation"
    );
    assert!(
        first.obligation_commits + first.obligation_aborts
            >= usize_field(row, "minimum_obligation_resolutions"),
        "{source_id} must resolve obligations"
    );
    assert_eq!(
        first.obligation_commits + first.obligation_aborts,
        first.scheduled_task_count * scenario.obligations_per_task
    );
    assert!(
        first.cancellation_drain_steps > 0,
        "{source_id} must record cancellation drain steps"
    );
    assert!(!first.trace_digest.trim().is_empty());
    assert!(first.trace_event_count > 0);
}

#[test]
fn failure_fixtures_reject_missing_cancellation_obligations_shrink_claims_and_fallback() {
    let artifact = artifact();
    let base_errors = validate_contract(&artifact);
    assert!(
        base_errors.is_empty(),
        "base artifact errors: {base_errors:?}"
    );

    let failure_cases = string_set(
        &serde_json::json!({
            "cases": array(&artifact, "failure_fixtures")
                .iter()
                .map(|row| string(row, "case_id").to_string())
                .collect::<Vec<_>>()
        }),
        "cases",
    );
    for required in [
        "missing-cancellation-request",
        "missing-obligation-resolution",
        "missing-shrink-metadata",
        "broad-cancellation-claim",
        "local-fallback-authorized",
    ] {
        assert!(
            failure_cases.contains(required),
            "missing failure case {required}"
        );
    }

    let mut missing_cancel = artifact.clone();
    missing_cancel["fixture_catalog"][0]["minimum_cancellation_requests"] = serde_json::json!(0);
    assert!(
        validate_contract(&missing_cancel)
            .iter()
            .any(|error| error.contains("does not require cancellation")),
        "missing cancellation request mutation must be rejected"
    );

    let mut missing_obligations = artifact.clone();
    missing_obligations["required_summary_fields"] =
        serde_json::json!(["schema_version", "scenario_id", "quiescent"]);
    assert!(
        validate_contract(&missing_obligations)
            .iter()
            .any(|error| error.contains("obligation")),
        "missing obligation fields mutation must be rejected"
    );

    let mut missing_shrink = artifact.clone();
    missing_shrink["fixture_catalog"][0]
        .as_object_mut()
        .expect("fixture object")
        .remove("shrink");
    assert!(
        validate_contract(&missing_shrink)
            .iter()
            .any(|error| error.contains("missing shrink")),
        "missing shrink metadata mutation must be rejected"
    );

    let mut broad_claim = artifact.clone();
    broad_claim["proof_lane"]["does_not_cover"] = serde_json::json!([]);
    assert!(
        validate_contract(&broad_claim)
            .iter()
            .any(|error| error.contains("broad cancellation")),
        "broad-claim mutation must be rejected"
    );

    let mut local_fallback = artifact;
    local_fallback["proof_lane"]["local_fallback_allowed"] = serde_json::json!(true);
    assert!(
        validate_contract(&local_fallback)
            .iter()
            .any(|error| error.contains("local fallback")),
        "local fallback mutation must be rejected"
    );
}
