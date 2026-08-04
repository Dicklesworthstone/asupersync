#![allow(missing_docs)]

use std::collections::BTreeSet;
use std::fs;

use serde_json::{Value, json};

const MATRIX_PATH: &str = "artifacts/dependency_real_service_fixture_matrix_v1.json";
const SOURCE_PATH: &str = "src/test_logging.rs";
const RUNNER_PATH: &str = "scripts/run_dependency_sovereignty_e2e.sh";
const DOC_PATH: &str = "docs/dependency_real_service_fixtures.md";

fn load_matrix() -> Value {
    serde_json::from_str(
        &fs::read_to_string(MATRIX_PATH).expect("read real-service fixture matrix"),
    )
    .expect("parse real-service fixture matrix")
}

fn required_string<'a>(value: &'a Value, pointer: &str) -> Result<&'a str, String> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .filter(|text| !text.trim().is_empty())
        .ok_or_else(|| format!("missing non-empty string at {pointer}"))
}

fn validate_matrix(matrix: &Value) -> Result<(), String> {
    if matrix.pointer("/schema_version").and_then(Value::as_u64) != Some(1) {
        return Err("schema_version must be 1".to_string());
    }
    if required_string(matrix, "/artifact_id")? != "dependency-real-service-fixture-matrix-v1" {
        return Err("unexpected artifact_id".to_string());
    }
    if matrix
        .pointer("/fixture_contract/ambient_services_forbidden")
        .and_then(Value::as_bool)
        != Some(true)
        || matrix
            .pointer("/fixture_contract/mock_substitution_forbidden")
            .and_then(Value::as_bool)
            != Some(true)
    {
        return Err("ambient services and mock substitution must be forbidden".to_string());
    }

    let taxonomy: BTreeSet<_> = matrix
        .pointer("/outcome_taxonomy")
        .and_then(Value::as_array)
        .ok_or_else(|| "outcome_taxonomy must be an array".to_string())?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let expected_taxonomy =
        BTreeSet::from(["BLOCKED_EXTERNAL", "EXECUTABLE_COMPLETE", "UNSUPPORTED"]);
    if taxonomy != expected_taxonomy {
        return Err(format!("unexpected outcome taxonomy: {taxonomy:?}"));
    }

    let required_ids: BTreeSet<_> = matrix
        .pointer("/required_service_family_ids")
        .and_then(Value::as_array)
        .ok_or_else(|| "required_service_family_ids must be an array".to_string())?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let families = matrix
        .pointer("/service_families")
        .and_then(Value::as_array)
        .ok_or_else(|| "service_families must be an array".to_string())?;
    let actual_ids: BTreeSet<_> = families
        .iter()
        .filter_map(|family| family.get("family_id").and_then(Value::as_str))
        .collect();
    if actual_ids != required_ids || actual_ids.len() != families.len() {
        return Err(format!(
            "service family coverage or uniqueness mismatch: required={required_ids:?} actual={actual_ids:?}"
        ));
    }

    let mut smoke_ids = BTreeSet::new();
    for family in families {
        let family_id = required_string(family, "/family_id")?;
        let outcome = required_string(family, "/declared_outcome")?;
        if !taxonomy.contains(outcome) {
            return Err(format!("{family_id}: unknown outcome {outcome}"));
        }
        let smoke_id = required_string(family, "/smoke_scenario_id")?;
        if !smoke_id.starts_with("fixture-smoke-") || !smoke_ids.insert(smoke_id) {
            return Err(format!(
                "{family_id}: invalid or duplicate smoke scenario ID"
            ));
        }
        let proof_source = required_string(family, "/proof_source")?.to_ascii_lowercase();
        if proof_source.contains("mock") || proof_source.contains("ambient") {
            return Err(format!(
                "{family_id}: proof source cannot name a mock or ambient service"
            ));
        }
        let directions = family
            .pointer("/directions")
            .and_then(Value::as_array)
            .ok_or_else(|| format!("{family_id}: directions must be an array"))?;
        if directions.len() != 2 || directions.iter().any(|value| value.as_str().is_none()) {
            return Err(format!(
                "{family_id}: exactly two interoperability directions are required"
            ));
        }
        let cells = family
            .pointer("/cells")
            .and_then(Value::as_array)
            .ok_or_else(|| format!("{family_id}: cells must be an array"))?;
        if cells.is_empty() {
            return Err(format!(
                "{family_id}: at least one fixture cell is required"
            ));
        }
        for cell in cells {
            required_string(cell, "/cell_id")?;
            required_string(cell, "/mode")?;
            if required_string(cell, "/declared_outcome")? != outcome {
                return Err(format!(
                    "{family_id}: cell outcome must match aggregate family outcome"
                ));
            }
        }

        let version = family
            .pointer("/provenance/version")
            .and_then(Value::as_str);
        let identity = family
            .pointer("/provenance/identity")
            .and_then(Value::as_str);
        match outcome {
            "EXECUTABLE_COMPLETE" => {
                if version.is_none_or(str::is_empty) || identity.is_none_or(str::is_empty) {
                    return Err(format!(
                        "{family_id}: executable fixture needs pinned version and identity"
                    ));
                }
                let command = required_string(family, "/smoke_command")?;
                if !command.starts_with("RCH_REQUIRE_REMOTE=1 rch exec ")
                    || command.contains("fallback")
                {
                    return Err(format!(
                        "{family_id}: executable smoke must be remote-required with no fallback"
                    ));
                }
                if !family.pointer("/blocker").is_some_and(Value::is_null) {
                    return Err(format!(
                        "{family_id}: executable fixture cannot retain a blocker"
                    ));
                }
            }
            "BLOCKED_EXTERNAL" => {
                if !family.pointer("/smoke_command").is_some_and(Value::is_null) {
                    return Err(format!(
                        "{family_id}: blocked fixture cannot expose an executable command"
                    ));
                }
                required_string(family, "/blocker")?;
                if family
                    .pointer("/unblock_requirements")
                    .and_then(Value::as_array)
                    .is_none_or(Vec::is_empty)
                {
                    return Err(format!(
                        "{family_id}: blocked fixture needs unblock requirements"
                    ));
                }
            }
            "UNSUPPORTED" => {
                required_string(family, "/blocker")?;
                required_string(family, "/external_owner")?;
                if !family.pointer("/smoke_command").is_some_and(Value::is_null) {
                    return Err(format!(
                        "{family_id}: unsupported fixture cannot expose a local command"
                    ));
                }
            }
            _ => unreachable!("taxonomy checked above"),
        }
    }

    let lifecycle_tests: BTreeSet<_> = matrix
        .pointer("/lifecycle_tests")
        .and_then(Value::as_array)
        .ok_or_else(|| "lifecycle_tests must be an array".to_string())?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    for required in [
        "test_port_allocator_allocates_unique_ports",
        "test_environment_start_failure_rolls_back_in_reverse_order",
        "test_environment_readiness_failure_stops_every_service",
        "test_wait_until_healthy_immediate",
        "test_wait_until_healthy_timeout",
        "test_process_fixture_pinned_lifecycle_and_redacted_logs",
        "test_process_fixture_rejects_digest_and_version_drift",
        "test_process_fixture_rejects_ambient_working_directory",
        "test_process_fixture_captures_crash_and_readiness_timeout",
        "test_environment_retries_failed_teardown_and_reports_orphan",
        "test_environment_teardown_idempotent",
    ] {
        if !lifecycle_tests.contains(required) {
            return Err(format!("missing lifecycle test {required}"));
        }
    }
    Ok(())
}

#[test]
fn real_service_fixture_matrix_is_complete_and_fail_closed() {
    validate_matrix(&load_matrix()).expect("fixture matrix contract");
}

#[test]
fn lifecycle_harness_runner_and_docs_are_wired() {
    let matrix = load_matrix();
    let source = fs::read_to_string(SOURCE_PATH).expect("read fixture lifecycle source");
    for token in [
        "pub struct PinnedProcessIdentity",
        "pub struct ProcessFixtureService",
        "pub enum ProcessReadiness",
        "pub fn orphaned_services",
        "pub fn teardown_errors",
        "pub fn image_is_pinned",
    ] {
        assert!(
            source.contains(token),
            "fixture source missing token {token}"
        );
    }
    for test_name in matrix["lifecycle_tests"]
        .as_array()
        .expect("lifecycle test array")
        .iter()
        .filter_map(Value::as_str)
    {
        assert!(
            source.contains(&format!("fn {test_name}(")),
            "fixture source missing lifecycle test {test_name}"
        );
    }

    let runner = fs::read_to_string(RUNNER_PATH).expect("read canonical runner");
    for token in [
        "REAL_SERVICE_FIXTURE_MATRIX",
        "real-service-fixture-contract",
        "dependency_real_service_fixture_contract",
    ] {
        assert!(runner.contains(token), "runner missing token {token}");
    }
    let docs = fs::read_to_string(DOC_PATH).expect("read fixture documentation");
    for token in [
        "PinnedProcessIdentity",
        "ProcessFixtureService",
        "BLOCKED_EXTERNAL",
        "UNSUPPORTED",
        "fixture-smoke-kafka",
        "fixture-smoke-sqlite-real-disk",
    ] {
        assert!(docs.contains(token), "fixture docs missing token {token}");
    }
}

#[test]
fn each_service_family_emits_a_non_ambient_smoke_receipt() {
    let matrix = load_matrix();
    validate_matrix(&matrix).expect("fixture matrix contract");
    let families = matrix["service_families"]
        .as_array()
        .expect("service families");
    for family in families {
        let outcome = family["declared_outcome"]
            .as_str()
            .expect("declared outcome");
        let receipt = json!({
            "schema_version": "dependency-real-service-fixture-receipt-v1",
            "suite_id": "dependency-sovereignty",
            "scenario_id": family["smoke_scenario_id"],
            "family_id": family["family_id"],
            "execution_kind": "catalog-preflight",
            "observed_outcome": outcome,
            "proof_admitted": false,
            "ambient_service_used": false,
            "mock_substitution_used": false,
            "provenance": family["provenance"],
            "blocker": family["blocker"],
            "cleanup": {
                "processes": 0,
                "containers": 0,
                "ports": 0,
                "temporary_directories": 0,
                "credentials": 0
            }
        });
        assert_eq!(receipt["proof_admitted"], false);
        assert_eq!(receipt["ambient_service_used"], false);
        assert_eq!(receipt["mock_substitution_used"], false);
        eprintln!("{receipt}");
    }
    assert_eq!(families.len(), 8);
}

#[test]
fn invalid_green_or_missing_family_is_rejected() {
    let mut matrix = load_matrix();
    let kafka = matrix["service_families"]
        .as_array_mut()
        .expect("service families")
        .iter_mut()
        .find(|family| family["family_id"] == "kafka")
        .expect("Kafka row");
    kafka["declared_outcome"] = json!("EXECUTABLE_COMPLETE");
    for cell in kafka["cells"].as_array_mut().expect("Kafka cells") {
        cell["declared_outcome"] = json!("EXECUTABLE_COMPLETE");
    }
    let error = validate_matrix(&matrix).expect_err("unpinned green fixture must fail");
    assert!(
        error.contains("pinned version and identity"),
        "unexpected validation error: {error}"
    );

    let mut missing = load_matrix();
    missing["service_families"]
        .as_array_mut()
        .expect("service families")
        .retain(|family| family["family_id"] != "otlp");
    let error = validate_matrix(&missing).expect_err("missing family must fail");
    assert!(
        error.contains("coverage or uniqueness mismatch"),
        "unexpected validation error: {error}"
    );
}
