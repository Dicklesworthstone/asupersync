#![allow(missing_docs)]

use serde_json::Value as JsonValue;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const ARTIFACT_PATH: &str = "artifacts/proof_lane_admission_input_schema_v1.json";
const FIXTURE_PATH: &str =
    "tests/fixtures/proof_lane_admission_input_schema/64c_256g_smoke_profile.json";
const REQUIRED_SECTIONS: [&str; 9] = [
    "host_profile",
    "resource_pressure",
    "disk_headroom",
    "rch_workers",
    "active_project_exclusion",
    "cargo_target_isolation",
    "agent_mail_reservations",
    "dirty_tree",
    "proof_lane",
];
const REQUIRED_COVERAGE: [&str; 5] = [
    "complete_64c_256g",
    "missing_telemetry",
    "dirty_tree_peer_reserved",
    "worker_saturation",
    "low_disk_headroom",
];
const GIB: u64 = 1024 * 1024 * 1024;

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn load_json(relative: &str) -> JsonValue {
    let path = repo_path(relative);
    let body = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    serde_json::from_str(&body).unwrap_or_else(|error| panic!("parse {}: {error}", path.display()))
}

fn artifact() -> JsonValue {
    load_json(ARTIFACT_PATH)
}

fn fixture() -> JsonValue {
    load_json(FIXTURE_PATH)
}

fn object<'a>(value: &'a JsonValue, key: &str) -> &'a serde_json::Map<String, JsonValue> {
    value
        .get(key)
        .and_then(JsonValue::as_object)
        .unwrap_or_else(|| panic!("{key} must be an object"))
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
    assert!(!item.trim().is_empty(), "{key} must not be blank");
    item
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

fn section_schema<'a>(
    artifact: &'a JsonValue,
    section: &str,
) -> &'a serde_json::Map<String, JsonValue> {
    let input_schema = object(artifact, "input_schema");
    let sections = input_schema
        .get("sections")
        .and_then(JsonValue::as_object)
        .unwrap_or_else(|| panic!("input_schema.sections must be an object"));
    sections
        .get(section)
        .and_then(JsonValue::as_object)
        .unwrap_or_else(|| panic!("missing schema section {section}"))
}

fn field_names(fields: &[JsonValue]) -> BTreeSet<String> {
    fields
        .iter()
        .map(|field| string(field, "name").to_string())
        .collect()
}

fn coverage_by_id(artifact: &JsonValue) -> BTreeMap<String, &JsonValue> {
    let mut cases = BTreeMap::new();
    for case in array(artifact, "fixture_coverage") {
        let case_id = string(case, "case_id").to_string();
        assert!(
            cases.insert(case_id.clone(), case).is_none(),
            "duplicate coverage case {case_id}"
        );
    }
    cases
}

#[test]
fn artifact_declares_non_mutating_schema_surface() {
    let artifact = artifact();
    assert_eq!(
        string(&artifact, "schema_version"),
        "proof-lane-admission-input-schema-v1"
    );
    assert_eq!(
        string(&artifact, "input_schema_version"),
        "proof-lane-admission-input-v1"
    );
    assert_eq!(string(&artifact, "bead_id"), "asupersync-l5m170.5.1");
    assert_eq!(string(&artifact, "artifact_path"), ARTIFACT_PATH);
    assert_eq!(
        string(&artifact, "contract_test"),
        "tests/proof_lane_admission_input_schema_contract.rs"
    );

    let scope = object(&artifact, "scope_boundary");
    assert!(
        bool_value(&JsonValue::Object(scope.clone()), "defines_schema_only"),
        "this bead must remain schema-only"
    );
    assert_eq!(
        string(&JsonValue::Object(scope.clone()), "decision_engine_bead"),
        "asupersync-l5m170.5.2"
    );

    let side_effects = object(&artifact, "side_effect_policy");
    for key in [
        "beads_mutation_allowed",
        "agent_mail_mutation_allowed",
        "filesystem_cleanup_allowed",
        "cargo_execution_allowed",
        "rch_execution_allowed",
        "cache_mutation_allowed",
    ] {
        assert!(
            !bool_value(&JsonValue::Object(side_effects.clone()), key),
            "{key} must remain false for the schema artifact"
        );
    }
}

#[test]
fn schema_requires_all_resource_coordination_and_cost_inputs() {
    let artifact = artifact();
    let declared_sections = string_set(&artifact, "required_input_sections");
    let expected_sections: BTreeSet<String> =
        REQUIRED_SECTIONS.iter().map(ToString::to_string).collect();
    assert_eq!(
        declared_sections, expected_sections,
        "schema must require every large-core admission input class"
    );

    for section in REQUIRED_SECTIONS {
        let schema = JsonValue::Object(section_schema(&artifact, section).clone());
        assert!(
            !string(&schema, "description").is_empty(),
            "{section} needs an operator-facing description"
        );
        let fields = array(&schema, "required_fields");
        assert!(!fields.is_empty(), "{section} must declare required fields");
        for field in fields {
            assert!(!string(field, "name").is_empty());
            assert!(!string(field, "type").is_empty());
            assert!(!string(field, "reason").is_empty());
        }
    }

    let rch_workers = JsonValue::Object(section_schema(&artifact, "rch_workers").clone());
    let worker_fields = string_set(&rch_workers, "worker_required_fields");
    for required in [
        "worker_id",
        "queue_state",
        "available_cores",
        "available_memory_bytes",
        "active_project_excluded",
        "cache_warmth",
    ] {
        assert!(
            worker_fields.contains(required),
            "worker rows must include {required}"
        );
    }

    let proof_lane = JsonValue::Object(section_schema(&artifact, "proof_lane").clone());
    let cost_fields = string_set(&proof_lane, "estimated_cost_required_fields");
    for required in [
        "cpu_core_seconds",
        "memory_bytes_peak",
        "io_bytes",
        "proof_weight",
    ] {
        assert!(
            cost_fields.contains(required),
            "proof lane cost must include {required}"
        );
    }
}

#[test]
fn smoke_profile_matches_64_core_256g_contract() {
    let artifact = artifact();
    let profile = fixture();
    let host = JsonValue::Object(object(&profile, "host_profile").clone());
    assert_eq!(u64_value(&host, "cpu_cores"), 64);
    assert_eq!(u64_value(&host, "memory_bytes"), 256 * GIB);
    assert_eq!(u64_value(&host, "numa_nodes"), 2);
    assert_eq!(string(&host, "profile_class"), "large_core_swarm");

    let smoke = object(&artifact, "64_core_256gb_smoke_profile");
    assert_eq!(
        string(&JsonValue::Object(smoke.clone()), "fixture_path"),
        FIXTURE_PATH
    );
    let expected =
        JsonValue::Object(object(&JsonValue::Object(smoke.clone()), "expected_projection").clone());
    assert_eq!(u64_value(&expected, "cpu_cores"), 64);
    assert_eq!(u64_value(&expected, "memory_bytes"), 256 * GIB);
    assert_eq!(string(&expected, "input_status"), "complete");
    assert_eq!(string(&expected, "admission_precondition"), "schema-ready");
    assert!(bool_value(&expected, "target_dir_isolated"));
    assert!(bool_value(&expected, "remote_required"));
    assert_eq!(u64_value(&expected, "peer_dirty_paths"), 0);
    assert_eq!(u64_value(&expected, "unreserved_source_paths"), 0);
}

#[test]
fn complete_fixture_satisfies_every_declared_required_field() {
    let artifact = artifact();
    let profile = fixture();

    for section in REQUIRED_SECTIONS {
        let section_value = JsonValue::Object(object(&profile, section).clone());
        let schema_value = JsonValue::Object(section_schema(&artifact, section).clone());
        let declared_fields = field_names(array(&schema_value, "required_fields"));
        let actual_fields: BTreeSet<String> = object(&profile, section)
            .keys()
            .map(ToString::to_string)
            .collect();
        assert!(
            declared_fields.is_subset(&actual_fields),
            "{section} missing required fields: {:?}",
            declared_fields
                .difference(&actual_fields)
                .collect::<Vec<&String>>()
        );
        assert!(
            !section_value
                .as_object()
                .expect("section is object")
                .is_empty(),
            "{section} must not be empty"
        );
    }

    let rch_workers = JsonValue::Object(object(&profile, "rch_workers").clone());
    assert!(bool_value(&rch_workers, "remote_required"));
    assert!(u64_value(&rch_workers, "telemetry_age_seconds") <= 900);
    assert!(
        !array(&rch_workers, "workers").is_empty(),
        "complete profile needs at least one worker row"
    );

    let target = JsonValue::Object(object(&profile, "cargo_target_isolation").clone());
    let template = string(&target, "target_dir_template");
    for token in ["{agent}", "{bead}", "{lane}"] {
        assert!(
            template.contains(token),
            "target_dir_template must include {token}"
        );
    }
    assert!(bool_value(&target, "agent_scoped"));
    assert!(bool_value(&target, "bead_scoped"));
    assert!(bool_value(&target, "lane_scoped"));
    assert!(bool_value(&target, "forbid_shared_target_dir"));
}

#[test]
fn coverage_cases_include_fail_closed_boundaries() {
    let artifact = artifact();
    let cases = coverage_by_id(&artifact);

    for required in REQUIRED_COVERAGE {
        assert!(
            cases.contains_key(required),
            "missing required coverage case {required}"
        );
    }

    let complete = cases
        .get("complete_64c_256g")
        .expect("complete case exists");
    assert_eq!(string(complete, "expected_input_status"), "complete");
    assert_eq!(
        string(complete, "expected_admission_precondition"),
        "schema-ready"
    );
    assert!(!bool_value(complete, "fail_closed"));

    for case_id in [
        "missing_telemetry",
        "dirty_tree_peer_reserved",
        "worker_saturation",
        "low_disk_headroom",
    ] {
        let case = cases.get(case_id).expect("coverage case exists");
        assert!(
            bool_value(case, "fail_closed"),
            "{case_id} must fail closed before admission"
        );
        assert_ne!(
            string(case, "expected_admission_precondition"),
            "schema-ready",
            "{case_id} cannot be schema-ready"
        );
        assert!(
            !array(case, "reason_codes").is_empty(),
            "{case_id} must include stable reason codes"
        );
    }
}

#[test]
fn operator_logging_and_validation_commands_are_complete() {
    let artifact = artifact();
    let logging = JsonValue::Object(object(&artifact, "operator_receipt_logging").clone());
    let required_logs = string_set(&logging, "required_fields");
    for field in [
        "receipt_id",
        "profile_id",
        "input_status",
        "reason_codes",
        "dirty_tree.classification",
        "dirty_tree.dirty_paths",
        "reservation_holders",
        "resource_pressure_summary",
        "worker_summary",
        "cargo_target_dir_template",
        "suggested_next_command",
        "non_coverage",
    ] {
        assert!(
            required_logs.contains(field),
            "operator receipt must log {field}"
        );
    }

    let profile = fixture();
    let proof_lane = JsonValue::Object(object(&profile, "proof_lane").clone());
    let command = string(&proof_lane, "command_template");
    for fragment in [
        "RCH_REQUIRE_REMOTE=1",
        "rch exec -- env",
        "CARGO_TARGET_DIR=",
        "cargo test -p asupersync --test proof_lane_admission_input_schema_contract",
        "-- --nocapture",
    ] {
        assert!(
            command.contains(fragment),
            "proof command must include {fragment}"
        );
    }

    let validation = JsonValue::Object(object(&artifact, "validation").clone());
    let remote_test = string(&validation, "remote_required_contract_test");
    assert!(remote_test.contains("RCH_REQUIRE_REMOTE=1"));
    assert!(remote_test.contains("CARGO_TARGET_DIR="));
    assert!(remote_test.contains("rch exec -- env"));
    assert!(remote_test.contains("-- --nocapture"));
    assert!(
        string(&validation, "dirty_tree_caveat").contains("peer-owned dirty source"),
        "validation caveat must forbid contaminated remote proof claims"
    );
}
