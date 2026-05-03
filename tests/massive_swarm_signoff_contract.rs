//! Contract-backed checks for the large-host operator signoff matrix.

#![allow(missing_docs)]

use serde_json::{Map, Value};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const ARTIFACT_PATH: &str = "artifacts/massive_swarm_signoff_smoke_contract_v1.json";
const RUNNER_SCRIPT_PATH: &str = "scripts/run_massive_swarm_signoff_smoke.sh";

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
    let host_template_mode = scenario["host_template_mode"]
        .as_bool()
        .expect("host_template_mode must be bool");
    let no_unexplained_artifacts = dirty_cluster_fail_closed_count == 0;

    let signoff_verdict = if host_template_mode {
        "template_only"
    } else if fail_closed_child_count > 0
        || open_tracker_blocker_count > 0
        || missing_artifact_path_count > 0
        || missing_runner_path_count > 0
        || dirty_cluster_fail_closed_count > 0
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
        "missing_artifact_path_count".to_string(),
        Value::from(missing_artifact_path_count),
    );
    object.insert(
        "missing_runner_path_count".to_string(),
        Value::from(missing_runner_path_count),
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
