//! Contract-backed checks for the large-host operator signoff matrix.

#![allow(missing_docs)]

use serde_json::{Map, Value};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

const ARTIFACT_PATH: &str = "artifacts/massive_swarm_signoff_smoke_contract_v1.json";
const RUNNER_SCRIPT_PATH: &str = "scripts/run_massive_swarm_signoff_smoke.sh";
const SIGNOFF_OWNED_DIRTY_PATHS: &[&str] = &[
    ARTIFACT_PATH,
    RUNNER_SCRIPT_PATH,
    "tests/massive_swarm_signoff_contract.rs",
];

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn load_artifact() -> Value {
    let raw = std::fs::read_to_string(repo_root().join(ARTIFACT_PATH))
        .expect("failed to load massive swarm signoff contract");
    serde_json::from_str(&raw).expect("failed to parse massive swarm signoff contract")
}

fn validate_matrix_entry(entry: &Value, required_fields: &[String]) -> Result<(), String> {
    for field in required_fields {
        let value = entry
            .get(field)
            .ok_or_else(|| format!("missing matrix field {field}"))?;
        let allow_empty = field == "blocker_reason";
        let missing = value.is_null()
            || (!allow_empty && value.as_str().is_some_and(str::is_empty))
            || value.as_array().is_some_and(Vec::is_empty);
        if missing {
            return Err(format!("empty matrix field {field}"));
        }
    }

    let proof_status = entry["proof_status"]
        .as_str()
        .ok_or_else(|| "proof_status must be string".to_string())?;
    if !matches!(proof_status, "trusted" | "fail_closed") {
        return Err(format!("unsupported proof_status {proof_status}"));
    }
    let tracker_status = entry["tracker_status"]
        .as_str()
        .ok_or_else(|| "tracker_status must be string".to_string())?;
    if !matches!(tracker_status, "open" | "closed" | "in_progress") {
        return Err(format!("unsupported tracker_status {tracker_status}"));
    }
    if proof_status == "fail_closed" && entry["blocker_reason"].as_str().is_none_or(str::is_empty) {
        return Err("fail_closed entry must explain blocker_reason".to_string());
    }

    let artifact_path = entry["artifact_path"]
        .as_str()
        .ok_or_else(|| "artifact_path must be string".to_string())?;
    if !Path::new(artifact_path).exists() {
        return Err(format!("artifact path missing: {artifact_path}"));
    }
    let runner_path = entry["runner_path"]
        .as_str()
        .ok_or_else(|| "runner_path must be string".to_string())?;
    if !Path::new(runner_path).exists() {
        return Err(format!("runner path missing: {runner_path}"));
    }

    let operator_fields = entry["operator_fields"]
        .as_array()
        .ok_or_else(|| "operator_fields must be array".to_string())?;
    if operator_fields.is_empty() {
        return Err("operator_fields must not be empty".to_string());
    }

    Ok(())
}

fn validate_artifact(artifact: &Value) -> Result<(), String> {
    let top_level_required = [
        "contract_version",
        "bead_id",
        "description",
        "runner_script",
        "runner_bundle_schema_version",
        "runner_report_schema_version",
        "required_source_skills",
        "required_source_skill_phases",
        "required_objective_requirement_ids",
        "tracked_dirty_blocker_fixture_paths",
        "blocked_dependency_policy",
        "required_matrix_fields",
        "signoff_matrix",
        "smoke_scenarios",
    ];
    for field in top_level_required {
        if artifact.get(field).is_none() {
            return Err(format!("missing top-level field {field}"));
        }
    }

    let required_fields: Vec<String> = artifact["required_matrix_fields"]
        .as_array()
        .ok_or_else(|| "required_matrix_fields must be array".to_string())?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(ToOwned::to_owned)
                .ok_or_else(|| "required_matrix_fields entries must be strings".to_string())
        })
        .collect::<Result<_, _>>()?;

    let matrix = artifact["signoff_matrix"]
        .as_array()
        .ok_or_else(|| "signoff_matrix must be array".to_string())?;
    if matrix.len() < 5 {
        return Err("signoff_matrix must cover the operator chain".to_string());
    }

    let mut control_ids = BTreeSet::new();
    for entry in matrix {
        validate_matrix_entry(entry, &required_fields)?;
        let control_id = entry["control_id"]
            .as_str()
            .ok_or_else(|| "control_id must be string".to_string())?;
        if !control_ids.insert(control_id.to_string()) {
            return Err(format!("duplicate control_id {control_id}"));
        }
    }

    let blocked_policy = &artifact["blocked_dependency_policy"];
    if blocked_policy["fail_closed_conditions"]
        .as_array()
        .map_or(0, Vec::len)
        < 4
    {
        return Err("blocked dependency policy is too thin".to_string());
    }
    if blocked_policy["safe_default_verdict"].as_str() != Some("fail_closed") {
        return Err("safe_default_verdict must be fail_closed".to_string());
    }

    let scenarios = artifact["smoke_scenarios"]
        .as_array()
        .ok_or_else(|| "smoke_scenarios must be array".to_string())?;
    if scenarios.len() != 2 {
        return Err("expected exactly two smoke scenarios".to_string());
    }
    for scenario in scenarios {
        if scenario["required_log_fields"]
            .as_array()
            .map_or(0, Vec::len)
            < 10
        {
            return Err("required_log_fields must be non-trivial".to_string());
        }
    }

    Ok(())
}

fn skill_provenance_artifact(artifact: &Value) -> Value {
    let path = artifact["signoff_matrix"]
        .as_array()
        .expect("signoff_matrix must be array")
        .iter()
        .find(|entry| entry["control_id"].as_str() == Some("skill_provenance"))
        .and_then(|entry| entry["artifact_path"].as_str())
        .expect("skill provenance artifact path must exist");
    let raw = std::fs::read_to_string(repo_root().join(path))
        .expect("skill provenance artifact must load");
    serde_json::from_str(&raw).expect("skill provenance artifact must parse")
}

fn child_statuses(artifact: &Value) -> Vec<Value> {
    artifact["signoff_matrix"]
        .as_array()
        .expect("signoff_matrix must be array")
        .iter()
        .map(|entry| {
            let mut object = entry
                .as_object()
                .expect("matrix entries must be objects")
                .clone();
            let artifact_exists = entry["artifact_path"]
                .as_str()
                .is_some_and(|path| Path::new(path).exists());
            let runner_exists = entry["runner_path"]
                .as_str()
                .is_some_and(|path| Path::new(path).exists());
            object.insert("artifact_exists".to_string(), Value::Bool(artifact_exists));
            object.insert("runner_exists".to_string(), Value::Bool(runner_exists));
            Value::Object(object)
        })
        .collect()
}

fn dirty_cluster_fail_closed_count(artifact: &Value) -> usize {
    let inventory_path = artifact["signoff_matrix"]
        .as_array()
        .expect("signoff_matrix must be array")
        .iter()
        .find(|entry| entry["control_id"].as_str() == Some("generated_smoke_inventory"))
        .and_then(|entry| entry["artifact_path"].as_str())
        .expect("generated inventory path must exist");
    let raw = std::fs::read_to_string(repo_root().join(inventory_path))
        .expect("generated inventory artifact must load");
    let inventory: Value =
        serde_json::from_str(&raw).expect("generated inventory artifact must parse");
    inventory["clusters"]
        .as_array()
        .expect("clusters must be array")
        .iter()
        .filter(|cluster| {
            cluster["signoff_status"]
                .as_str()
                .is_some_and(|status| status.starts_with("fail_closed"))
        })
        .count()
}

fn tracked_dirty_paths() -> Vec<String> {
    let output = Command::new("git")
        .args(["status", "--short", "--untracked-files=no"])
        .current_dir(repo_root())
        .output();
    if let Ok(output) = output
        && output.status.success()
    {
        return String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter_map(|line| line.get(3..).map(str::trim))
            .filter(|path| !path.is_empty())
            .filter(|path| !SIGNOFF_OWNED_DIRTY_PATHS.contains(path))
            .map(ToOwned::to_owned)
            .collect();
    }

    let artifact = load_artifact();
    artifact["tracked_dirty_blocker_fixture_paths"]
        .as_array()
        .expect("tracked_dirty_blocker_fixture_paths must be array")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("tracked dirty fixture paths must be strings")
                .to_string()
        })
        .collect()
}

fn is_hex_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn strip_projection_hash(mut projection: Value) -> Value {
    projection
        .as_object_mut()
        .expect("projection must be object")
        .remove("projection_hash");
    projection
}

fn string_array(value: &Value) -> Vec<String> {
    value
        .as_array()
        .expect("value must be array")
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .expect("array entries must be strings")
                .to_string()
        })
        .collect()
}

fn unique_mapping_strings<F>(mappings: &[Value], mut mapper: F) -> Vec<String>
where
    F: FnMut(&Value) -> Option<&str>,
{
    let mut seen = BTreeSet::new();
    let mut ordered = Vec::new();
    for value in mappings.iter().filter_map(&mut mapper) {
        if seen.insert(value.to_string()) {
            ordered.push(value.to_string());
        }
    }
    ordered
}

fn difference_preserving(required: &[String], actual: &[String]) -> Vec<String> {
    let actual_set: BTreeSet<&str> = actual.iter().map(String::as_str).collect();
    required
        .iter()
        .filter(|value| !actual_set.contains(value.as_str()))
        .cloned()
        .collect()
}

fn objective_coverage_summary(artifact: &Value) -> Value {
    let provenance = skill_provenance_artifact(artifact);
    let mappings = provenance["selected_bead_mappings"]
        .as_array()
        .expect("selected_bead_mappings must be array");
    let required_source_skills = string_array(&artifact["required_source_skills"]);
    let required_source_skill_phases = string_array(&artifact["required_source_skill_phases"]);
    let required_objective_requirement_ids =
        string_array(&artifact["required_objective_requirement_ids"]);
    let actual_source_skills = string_array(&provenance["source_skills"]);
    let declared_objective_requirement_ids = provenance["objective_requirements"]
        .as_array()
        .expect("objective_requirements must be array")
        .iter()
        .map(|entry| {
            entry["id"]
                .as_str()
                .expect("objective requirement id must be string")
                .to_string()
        })
        .collect::<Vec<_>>();
    let actual_source_skill_phases =
        unique_mapping_strings(mappings, |entry| entry["source_skill_phase"].as_str());
    let mapped_objective_requirement_ids =
        unique_mapping_strings(mappings, |entry| entry["objective_requirement_id"].as_str());
    let selected_bead_mapping_bead_ids =
        unique_mapping_strings(mappings, |entry| entry["bead_id"].as_str());

    let mut object = Map::new();
    object.insert(
        "required_source_skills".to_string(),
        Value::Array(
            required_source_skills
                .iter()
                .cloned()
                .map(Value::String)
                .collect(),
        ),
    );
    object.insert(
        "actual_source_skills".to_string(),
        Value::Array(
            actual_source_skills
                .iter()
                .cloned()
                .map(Value::String)
                .collect(),
        ),
    );
    object.insert(
        "missing_required_source_skills".to_string(),
        Value::Array(
            difference_preserving(&required_source_skills, &actual_source_skills)
                .into_iter()
                .map(Value::String)
                .collect(),
        ),
    );
    object.insert(
        "required_source_skill_phases".to_string(),
        Value::Array(
            required_source_skill_phases
                .iter()
                .cloned()
                .map(Value::String)
                .collect(),
        ),
    );
    object.insert(
        "actual_source_skill_phases".to_string(),
        Value::Array(
            actual_source_skill_phases
                .iter()
                .cloned()
                .map(Value::String)
                .collect(),
        ),
    );
    object.insert(
        "missing_required_source_skill_phases".to_string(),
        Value::Array(
            difference_preserving(&required_source_skill_phases, &actual_source_skill_phases)
                .into_iter()
                .map(Value::String)
                .collect(),
        ),
    );
    object.insert(
        "required_objective_requirement_ids".to_string(),
        Value::Array(
            required_objective_requirement_ids
                .iter()
                .cloned()
                .map(Value::String)
                .collect(),
        ),
    );
    object.insert(
        "declared_objective_requirement_ids".to_string(),
        Value::Array(
            declared_objective_requirement_ids
                .iter()
                .cloned()
                .map(Value::String)
                .collect(),
        ),
    );
    object.insert(
        "missing_required_objective_requirement_ids".to_string(),
        Value::Array(
            difference_preserving(
                &required_objective_requirement_ids,
                &declared_objective_requirement_ids,
            )
            .into_iter()
            .map(Value::String)
            .collect(),
        ),
    );
    object.insert(
        "mapped_objective_requirement_ids".to_string(),
        Value::Array(
            mapped_objective_requirement_ids
                .iter()
                .cloned()
                .map(Value::String)
                .collect(),
        ),
    );
    object.insert(
        "unmapped_objective_requirement_ids".to_string(),
        Value::Array(
            difference_preserving(
                &required_objective_requirement_ids,
                &mapped_objective_requirement_ids,
            )
            .into_iter()
            .map(Value::String)
            .collect(),
        ),
    );
    object.insert(
        "selected_bead_mapping_count".to_string(),
        Value::from(mappings.len()),
    );
    object.insert(
        "selected_bead_mapping_bead_ids".to_string(),
        Value::Array(
            selected_bead_mapping_bead_ids
                .into_iter()
                .map(Value::String)
                .collect(),
        ),
    );
    Value::Object(object)
}

fn build_projection(artifact: &Value, scenario_id: &str) -> Value {
    let scenario = artifact["smoke_scenarios"]
        .as_array()
        .expect("smoke_scenarios must be array")
        .iter()
        .find(|scenario| scenario["scenario_id"].as_str() == Some(scenario_id))
        .unwrap_or_else(|| panic!("scenario {scenario_id} must exist"));
    let statuses = child_statuses(artifact);
    let child_artifact_count = statuses.len();
    let trusted_child_count = statuses
        .iter()
        .filter(|entry| entry["proof_status"].as_str() == Some("trusted"))
        .count();
    let fail_closed_child_count = statuses
        .iter()
        .filter(|entry| entry["proof_status"].as_str() == Some("fail_closed"))
        .count();
    let open_tracker_blocker_count = statuses
        .iter()
        .filter(|entry| entry["tracker_status"].as_str() != Some("closed"))
        .count();
    let missing_artifact_path_count = statuses
        .iter()
        .filter(|entry| entry["artifact_exists"].as_bool() == Some(false))
        .count();
    let missing_runner_path_count = statuses
        .iter()
        .filter(|entry| entry["runner_exists"].as_bool() == Some(false))
        .count();
    let dirty_cluster_fail_closed_count = dirty_cluster_fail_closed_count(artifact);
    let tracked_dirty_blocker_count = tracked_dirty_paths().len();
    let objective_coverage = objective_coverage_summary(artifact);
    let source_skill_count = objective_coverage["actual_source_skills"]
        .as_array()
        .expect("actual_source_skills must be array")
        .len();
    let required_source_skill_count = objective_coverage["required_source_skills"]
        .as_array()
        .expect("required_source_skills must be array")
        .len();
    let missing_required_source_skill_count = objective_coverage["missing_required_source_skills"]
        .as_array()
        .expect("missing_required_source_skills must be array")
        .len();
    let source_skill_phase_count = objective_coverage["actual_source_skill_phases"]
        .as_array()
        .expect("actual_source_skill_phases must be array")
        .len();
    let required_source_skill_phase_count = objective_coverage["required_source_skill_phases"]
        .as_array()
        .expect("required_source_skill_phases must be array")
        .len();
    let missing_required_source_skill_phase_count =
        objective_coverage["missing_required_source_skill_phases"]
            .as_array()
            .expect("missing_required_source_skill_phases must be array")
            .len();
    let objective_requirement_count = objective_coverage["declared_objective_requirement_ids"]
        .as_array()
        .expect("declared_objective_requirement_ids must be array")
        .len();
    let required_objective_requirement_count =
        objective_coverage["required_objective_requirement_ids"]
            .as_array()
            .expect("required_objective_requirement_ids must be array")
            .len();
    let covered_objective_requirement_count =
        objective_coverage["mapped_objective_requirement_ids"]
            .as_array()
            .expect("mapped_objective_requirement_ids must be array")
            .len();
    let missing_required_objective_requirement_count =
        objective_coverage["missing_required_objective_requirement_ids"]
            .as_array()
            .expect("missing_required_objective_requirement_ids must be array")
            .len();
    let unmapped_objective_requirement_count =
        objective_coverage["unmapped_objective_requirement_ids"]
            .as_array()
            .expect("unmapped_objective_requirement_ids must be array")
            .len();
    let selected_bead_mapping_count = objective_coverage["selected_bead_mapping_count"]
        .as_u64()
        .expect("selected_bead_mapping_count must be number");
    let host_template_mode = scenario["host_template_mode"]
        .as_bool()
        .expect("host_template_mode must be bool");
    let no_unexplained_artifacts = dirty_cluster_fail_closed_count == 0;
    let objective_checklist_complete = missing_required_source_skill_count == 0
        && missing_required_source_skill_phase_count == 0
        && missing_required_objective_requirement_count == 0
        && unmapped_objective_requirement_count == 0
        && selected_bead_mapping_count > 0;

    let signoff_verdict = if host_template_mode {
        "template_only"
    } else if fail_closed_child_count > 0
        || open_tracker_blocker_count > 0
        || missing_artifact_path_count > 0
        || missing_runner_path_count > 0
        || dirty_cluster_fail_closed_count > 0
        || tracked_dirty_blocker_count > 0
        || !objective_checklist_complete
    {
        "fail_closed"
    } else {
        "ready_for_signoff"
    };

    let mut object = Map::new();
    object.insert(
        "signoff_verdict".to_string(),
        Value::String(signoff_verdict.to_string()),
    );
    object.insert(
        "host_template_mode".to_string(),
        Value::Bool(host_template_mode),
    );
    object.insert(
        "child_artifact_count".to_string(),
        Value::from(child_artifact_count),
    );
    object.insert(
        "trusted_child_count".to_string(),
        Value::from(trusted_child_count),
    );
    object.insert(
        "fail_closed_child_count".to_string(),
        Value::from(fail_closed_child_count),
    );
    object.insert(
        "open_tracker_blocker_count".to_string(),
        Value::from(open_tracker_blocker_count),
    );
    object.insert(
        "dirty_cluster_fail_closed_count".to_string(),
        Value::from(dirty_cluster_fail_closed_count),
    );
    object.insert(
        "tracked_dirty_blocker_count".to_string(),
        Value::from(tracked_dirty_blocker_count),
    );
    object.insert(
        "source_skill_count".to_string(),
        Value::from(source_skill_count),
    );
    object.insert(
        "required_source_skill_count".to_string(),
        Value::from(required_source_skill_count),
    );
    object.insert(
        "missing_required_source_skill_count".to_string(),
        Value::from(missing_required_source_skill_count),
    );
    object.insert(
        "source_skill_phase_count".to_string(),
        Value::from(source_skill_phase_count),
    );
    object.insert(
        "required_source_skill_phase_count".to_string(),
        Value::from(required_source_skill_phase_count),
    );
    object.insert(
        "missing_required_source_skill_phase_count".to_string(),
        Value::from(missing_required_source_skill_phase_count),
    );
    object.insert(
        "objective_requirement_count".to_string(),
        Value::from(objective_requirement_count),
    );
    object.insert(
        "required_objective_requirement_count".to_string(),
        Value::from(required_objective_requirement_count),
    );
    object.insert(
        "covered_objective_requirement_count".to_string(),
        Value::from(covered_objective_requirement_count),
    );
    object.insert(
        "missing_required_objective_requirement_count".to_string(),
        Value::from(missing_required_objective_requirement_count),
    );
    object.insert(
        "unmapped_objective_requirement_count".to_string(),
        Value::from(unmapped_objective_requirement_count),
    );
    object.insert(
        "selected_bead_mapping_count".to_string(),
        Value::from(selected_bead_mapping_count),
    );
    object.insert(
        "missing_artifact_path_count".to_string(),
        Value::from(missing_artifact_path_count),
    );
    object.insert(
        "missing_runner_path_count".to_string(),
        Value::from(missing_runner_path_count),
    );
    object.insert(
        "objective_checklist_complete".to_string(),
        Value::Bool(objective_checklist_complete),
    );
    object.insert(
        "no_unexplained_artifacts".to_string(),
        Value::Bool(no_unexplained_artifacts),
    );

    Value::Object(object)
}

#[test]
fn artifact_and_runner_exist() {
    assert!(
        Path::new(ARTIFACT_PATH).exists(),
        "massive swarm signoff contract must exist"
    );
    assert!(
        Path::new(RUNNER_SCRIPT_PATH).exists(),
        "massive swarm signoff runner must exist"
    );
}

#[test]
fn schema_round_trip_is_stable() {
    let artifact = load_artifact();
    let serialized = serde_json::to_string_pretty(&artifact).expect("serialize artifact");
    let reparsed: Value = serde_json::from_str(&serialized).expect("reparse artifact");
    assert_eq!(artifact, reparsed, "artifact must round-trip through JSON");
}

#[test]
fn contract_contains_required_matrix_and_policy_fields() {
    let artifact = load_artifact();
    validate_artifact(&artifact).expect("artifact should satisfy required signoff contract");
}

#[test]
fn missing_matrix_field_is_rejected() {
    let mut artifact = load_artifact();
    artifact["signoff_matrix"][0]
        .as_object_mut()
        .expect("entry object")
        .remove("config_gate");
    assert!(
        validate_artifact(&artifact)
            .expect_err("missing config_gate should fail")
            .contains("config_gate")
    );
}

#[test]
fn objective_provenance_covers_required_skills_and_requirements() {
    let artifact = load_artifact();
    let coverage = objective_coverage_summary(&artifact);
    assert_eq!(
        coverage["missing_required_source_skills"],
        Value::Array(Vec::new()),
        "required source skills must all be present"
    );
    assert_eq!(
        coverage["missing_required_source_skill_phases"],
        Value::Array(Vec::new()),
        "required source skill phases must all be present"
    );
    assert_eq!(
        coverage["missing_required_objective_requirement_ids"],
        Value::Array(Vec::new()),
        "required objective requirements must all be declared"
    );
    assert_eq!(
        coverage["unmapped_objective_requirement_ids"],
        Value::Array(Vec::new()),
        "required objective requirements must all be mapped to selected beads"
    );
}

#[test]
fn small_mode_projection_matches_contract_when_pinned() {
    let artifact = load_artifact();
    let expected = artifact["smoke_scenarios"][0]["expected_report_projection"].clone();
    let actual = build_projection(
        &artifact,
        "AA-MASSIVE-SWARM-SIGNOFF-OPERATOR-CHAIN-SMALL-MODE",
    );
    if !expected.is_null() {
        let expected_hash = expected["projection_hash"]
            .as_str()
            .expect("expected projection hash must be string");
        assert!(
            is_hex_digest(expected_hash),
            "expected projection hash must be a 64-character hex digest"
        );
        assert_eq!(actual, strip_projection_hash(expected));
    }
}

#[test]
fn template_projection_matches_contract_when_pinned() {
    let artifact = load_artifact();
    let expected = artifact["smoke_scenarios"][1]["expected_report_projection"].clone();
    let actual = build_projection(&artifact, "AA-MASSIVE-SWARM-SIGNOFF-REAL-HOST-TEMPLATE");
    if !expected.is_null() {
        let expected_hash = expected["projection_hash"]
            .as_str()
            .expect("expected projection hash must be string");
        assert!(
            is_hex_digest(expected_hash),
            "expected projection hash must be a 64-character hex digest"
        );
        assert_eq!(actual, strip_projection_hash(expected));
    }
}
