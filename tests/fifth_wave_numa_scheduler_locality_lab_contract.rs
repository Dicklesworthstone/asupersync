#![allow(missing_docs)]

use asupersync::lab::{
    NumaCachePressureInput, NumaCachePressureProjection, NumaPressureClass,
    project_numa_cache_pressure,
};
use asupersync::runtime::ArtifactMemoryPressureSnapshot;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const ARTIFACT_PATH: &str = "artifacts/fifth_wave_numa_scheduler_locality_lab_v1.json";
const ATLAS_PATH: &str = "artifacts/fifth_wave_swarm_control_plane_atlas_v1.json";
const BEAD_ID: &str = "asupersync-numa-scheduler-locality-lab-zhvkr9";
const LANE_ID: &str = "fifth-wave-numa-scheduler-locality-lab";
const PROOF_COMMAND_ID: &str = "fifth-wave-numa-scheduler-locality-lab-contract";
const TARGET_DIR: &str = "${TMPDIR:-/tmp}/rch_target_fifth_wave_numa_scheduler_locality_lab";
const TEST_PATH: &str = "tests/fifth_wave_numa_scheduler_locality_lab_contract.rs";

const REQUIRED_INPUT_FIELDS: &[&str] = &[
    "scenario_id",
    "cache",
    "agent_budget_bytes",
    "agent_resident_bytes",
    "local_node_bytes",
    "remote_node_bytes",
    "topology_confidence_bps",
    "replay_pointer",
];

const REQUIRED_PROJECTION_FIELDS: &[&str] = &[
    "scenario_id",
    "pressure_bps",
    "agent_budget_pressure_bps",
    "cache_pressure_bps",
    "remote_numa_penalty_bps",
    "hot_cache_discount_bps",
    "recommended_eviction_bytes",
    "spill_to_disk_bytes",
    "pressure_class",
    "numa_hint_used",
    "replay_pointer",
];

const REQUIRED_NON_CLAIMS: &[&str] = &[
    "does not prove scheduler performance improvement",
    "does not change production scheduling policy",
    "does not prove no regression",
    "does not implement the fourth-wave governor",
    "does not require real NUMA hardware",
    "does not authorize local Cargo fallback",
    "does not prove broad workspace health",
    "does not create branches, worktrees, scratch clones, or non-main refs",
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

fn u64_field(value: &Value, key: &str) -> u64 {
    value
        .get(key)
        .and_then(Value::as_u64)
        .unwrap_or_else(|| panic!("{key} must be a u64"))
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

fn serde_text<T: serde::Serialize>(value: T) -> String {
    serde_json::to_value(value)
        .expect("serialize enum")
        .as_str()
        .expect("serialized enum should be a string")
        .to_string()
}

fn assert_remote_required_cargo_command(command: &str) {
    assert!(
        command.starts_with("RCH_REQUIRE_REMOTE=1 rch exec -- env "),
        "proof command must require remote RCH: {command}"
    );
    assert!(
        command.contains(" cargo test "),
        "proof command must route Cargo through RCH: {command}"
    );
    for required in [
        TARGET_DIR,
        "CARGO_INCREMENTAL=0",
        "CARGO_PROFILE_TEST_DEBUG=0",
        "RUSTFLAGS='-D warnings -C debuginfo=0'",
        "--test fifth_wave_numa_scheduler_locality_lab_contract",
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
        "executing locally",
    ] {
        assert!(
            !command.contains(forbidden),
            "proof command contains forbidden fallback marker {forbidden}: {command}"
        );
    }
}

fn snapshot(
    resident_bytes: u64,
    max_resident_bytes: u64,
    hot_resident_bytes: u64,
    spill_eligible_bytes: u64,
    pressure_bps: u16,
) -> ArtifactMemoryPressureSnapshot {
    ArtifactMemoryPressureSnapshot {
        resident_bytes,
        max_resident_bytes,
        hot_resident_bytes,
        cold_resident_bytes: resident_bytes.saturating_sub(hot_resident_bytes),
        spill_eligible_bytes,
        remote_numa_bytes: 0,
        pressure_bps,
        high_pressure: pressure_bps >= 8_500,
        duplicate_bytes_avoided: 0,
        artifact_count: 8,
    }
}

fn input_for(fixture_id: &str) -> NumaCachePressureInput {
    match fixture_id {
        "portable-low-confidence-green" => NumaCachePressureInput {
            scenario_id: "numa-portable-low-confidence-green".to_string(),
            cache: snapshot(400, 1_000, 350, 200, 4_000),
            agent_budget_bytes: 1_000,
            agent_resident_bytes: 300,
            local_node_bytes: 900,
            remote_node_bytes: 100,
            topology_confidence_bps: 4_000,
            replay_pointer: "trace://fifth-wave/numa/portable".to_string(),
        },
        "amber-locality-spill" => NumaCachePressureInput {
            scenario_id: "numa-amber-locality-spill".to_string(),
            cache: snapshot(800, 1_000, 200, 500, 8_000),
            agent_budget_bytes: 1_000,
            agent_resident_bytes: 760,
            local_node_bytes: 700,
            remote_node_bytes: 300,
            topology_confidence_bps: 9_000,
            replay_pointer: "trace://fifth-wave/numa/amber".to_string(),
        },
        "red-budget-overage" => NumaCachePressureInput {
            scenario_id: "numa-red-budget-overage".to_string(),
            cache: snapshot(1_200, 1_000, 100, 900, 12_000),
            agent_budget_bytes: 1_000,
            agent_resident_bytes: 1_400,
            local_node_bytes: 700,
            remote_node_bytes: 300,
            topology_confidence_bps: 9_000,
            replay_pointer: "trace://fifth-wave/numa/red".to_string(),
        },
        other => panic!("unknown fixture {other}"),
    }
}

fn projection_for(fixture_id: &str) -> NumaCachePressureProjection {
    project_numa_cache_pressure(&input_for(fixture_id))
}

#[test]
fn artifact_declares_sources_atlas_alignment_and_remote_proof_lane() {
    let artifact = artifact();
    assert_eq!(
        string(&artifact, "schema_version"),
        "fifth-wave-numa-scheduler-locality-lab-v1"
    );
    assert_eq!(string(&artifact, "bead_id"), BEAD_ID);

    let source = object(&artifact, "source_of_truth");
    for (key, expected) in [
        ("atlas_artifact", ATLAS_PATH),
        (
            "runtime_workload_corpus",
            "artifacts/runtime_workload_corpus_v1.json",
        ),
        (
            "runtime_capacity_hints_contract",
            "tests/runtime_capacity_hints_contract.rs",
        ),
        ("numa_projection_source", "src/lab/numa/mod.rs"),
        ("contract_test", TEST_PATH),
        ("agent_instructions", "AGENTS.md"),
        ("readme", "README.md"),
    ] {
        assert_eq!(
            source
                .get(key)
                .and_then(Value::as_str)
                .unwrap_or_else(|| panic!("source_of_truth.{key}")),
            expected
        );
        assert!(
            repo_path(expected).exists(),
            "source_of_truth.{key} path must exist: {expected}"
        );
    }

    let lane = &artifact["proof_lane"];
    assert_eq!(string(lane, "lane_id"), LANE_ID);
    assert_eq!(string(lane, "owner_bead"), BEAD_ID);
    assert_eq!(string(lane, "proof_command_id"), PROOF_COMMAND_ID);
    assert_eq!(string(lane, "target_dir"), TARGET_DIR);
    assert!(bool_field(lane, "remote_required"));
    assert!(!bool_field(lane, "local_fallback_allowed"));
    assert_remote_required_cargo_command(string(lane, "proof_command"));

    let atlas = atlas();
    let atlas_lanes = rows_by_id(&atlas, "child_lanes", "owner_bead");
    let atlas_lane = atlas_lanes.get(BEAD_ID).expect("atlas NUMA child lane");
    assert_eq!(string(atlas_lane, "lane_id"), string(lane, "lane_id"));
    assert_eq!(
        string(atlas_lane, "proof_command_id"),
        string(lane, "proof_command_id")
    );
    assert_eq!(
        string(atlas_lane, "proof_command"),
        string(lane, "proof_command")
    );
}

#[test]
fn projection_schema_matches_live_numa_projection_fields_and_classes() {
    let artifact = artifact();
    let schema = &artifact["projection_schema"];
    assert_eq!(
        string(schema, "runtime_projection_type"),
        "NumaCachePressureProjection"
    );
    assert_eq!(
        u64_field(schema, "topology_confidence_threshold_bps"),
        7_500
    );
    assert_eq!(u64_field(schema, "amber_pressure_threshold_bps"), 7_000);
    assert_eq!(u64_field(schema, "red_pressure_threshold_bps"), 9_000);

    let input_fields = string_set(schema, "required_input_fields");
    for field in REQUIRED_INPUT_FIELDS {
        assert!(input_fields.contains(*field), "missing input field {field}");
    }

    let projection_fields = string_set(schema, "required_projection_fields");
    for field in REQUIRED_PROJECTION_FIELDS {
        assert!(
            projection_fields.contains(*field),
            "missing projection field {field}"
        );
    }

    let projection = projection_for("amber-locality-spill");
    let projection_json = serde_json::to_value(&projection).expect("serialize projection");
    let projection_object = projection_json.as_object().expect("projection object");
    for field in REQUIRED_PROJECTION_FIELDS {
        assert!(
            projection_object.contains_key(*field),
            "live projection missing artifact field {field}"
        );
    }

    let classes = string_set(schema, "pressure_classes");
    for class in [
        NumaPressureClass::Green,
        NumaPressureClass::Amber,
        NumaPressureClass::Red,
    ] {
        assert!(
            classes.contains(&serde_text(class)),
            "artifact missing pressure class {class:?}"
        );
    }

    let metrics = rows_by_id(schema, "metric_catalog", "metric");
    for metric in [
        "agent_budget_pressure_bps",
        "cache_pressure_bps",
        "remote_numa_penalty_bps",
        "recommended_eviction_bytes",
    ] {
        let row = metrics
            .get(metric)
            .unwrap_or_else(|| panic!("missing metric {metric}"));
        assert!(!string(row, "authority").trim().is_empty());
        assert!(!string(row, "interpretation").trim().is_empty());
    }
}

#[test]
fn fixture_catalog_exercises_portable_amber_and_red_projection_paths() {
    let artifact = artifact();
    let fixtures = rows_by_id(&artifact, "fixture_catalog", "fixture_id");

    for fixture_id in [
        "portable-low-confidence-green",
        "amber-locality-spill",
        "red-budget-overage",
    ] {
        let row = fixtures
            .get(fixture_id)
            .unwrap_or_else(|| panic!("missing fixture {fixture_id}"));
        assert!(
            !bool_field(row, "hardware_required"),
            "{fixture_id} must be replayable without real NUMA hardware"
        );
        assert!(
            string_set(row, "proves").len() >= 2,
            "{fixture_id} must document concrete proof dimensions"
        );

        let projection = projection_for(fixture_id);
        assert_eq!(
            serde_text(projection.pressure_class),
            string(row, "expected_pressure_class"),
            "{fixture_id} pressure class mismatch"
        );
        assert_eq!(
            projection.numa_hint_used,
            bool_field(row, "expected_numa_hint_used"),
            "{fixture_id} numa_hint_used mismatch"
        );
        assert_eq!(
            u64::from(projection.remote_numa_penalty_bps),
            u64_field(row, "expected_remote_numa_penalty_bps"),
            "{fixture_id} remote penalty mismatch"
        );
        assert_eq!(
            projection.recommended_eviction_bytes,
            u64_field(row, "expected_recommended_eviction_bytes"),
            "{fixture_id} eviction target mismatch"
        );
        if let Some(expected_spill) = row
            .get("expected_spill_to_disk_bytes")
            .and_then(Value::as_u64)
        {
            assert_eq!(
                projection.spill_to_disk_bytes, expected_spill,
                "{fixture_id} spill target mismatch"
            );
        }
        assert_eq!(projection.scenario_id, input_for(fixture_id).scenario_id);
        assert_eq!(
            projection.replay_pointer,
            input_for(fixture_id).replay_pointer
        );
    }
}

#[test]
fn hardware_benchmark_plan_and_non_claims_fail_closed() {
    let artifact = artifact();
    let plan = &artifact["hardware_benchmark_plan"];
    assert_eq!(string(plan, "status"), "no_fresh_hardware_benchmark");
    assert!(string(plan, "no_claim_when_absent").contains("deterministic lab projection behavior"));
    let benchmark_requirements = string_set(plan, "required_before_performance_claims");
    for required in [
        "large-host run with explicit core count and memory size",
        "NUMA topology capture attached to the benchmark receipt",
        "comparison against current main with identical workload corpus",
    ] {
        assert!(
            benchmark_requirements.contains(required),
            "missing hardware benchmark precondition {required}"
        );
    }

    let failure_fixtures = rows_by_id(&artifact, "failure_fixtures", "case_id");
    for case_id in [
        "local-fallback-authorized",
        "missing-no-performance-claim",
        "hardware-benchmark-claimed-without-receipt",
        "production-scheduler-policy-claim",
    ] {
        let row = failure_fixtures
            .get(case_id)
            .unwrap_or_else(|| panic!("missing failure fixture {case_id}"));
        assert_eq!(string(row, "expected_verdict"), "fail_closed");
        assert!(!string(row, "expected_reason").trim().is_empty());
    }

    let lane = &artifact["proof_lane"];
    assert!(bool_field(lane, "remote_required"));
    assert!(!bool_field(lane, "local_fallback_allowed"));
    assert_remote_required_cargo_command(string(lane, "proof_command"));

    let lane_no_claims = string_set(lane, "does_not_cover");
    let artifact_non_claims = string_set(&artifact, "non_claims");
    for required in REQUIRED_NON_CLAIMS {
        assert!(
            artifact_non_claims.contains(*required),
            "missing non-claim {required}"
        );
    }
    for required in [
        "does not prove scheduler performance improvement",
        "does not change production scheduling policy",
        "does not prove no regression",
        "does not implement the fourth-wave governor",
    ] {
        assert!(
            lane_no_claims.contains(required),
            "proof lane missing no-claim {required}"
        );
    }

    for requirement in array(&artifact, "closeout_requirements") {
        let text = requirement
            .as_str()
            .expect("closeout_requirements entries must be strings");
        assert!(!text.trim().is_empty(), "closeout requirement is empty");
    }
}
