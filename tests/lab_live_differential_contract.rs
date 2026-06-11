#![allow(missing_docs)]

use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const CONTRACT_PATH: &str = "artifacts/lab_live_differential_scenario_contract_v1.json";
const DOCS_PATH: &str = "docs/lab_live_differential_scenarios.md";
const BEAD_ID: &str = "asupersync-idea-wizard-fifth-wave-3gaiun.5.1";
const FIXTURE_SCHEMA: &str = "lab-live-differential-scenario-fixture-v1";

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_repo_file(relative: &str) -> String {
    std::fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|err| panic!("read {relative}: {err}"))
}

fn parse_json(relative: &str) -> Value {
    serde_json::from_str(&read_repo_file(relative))
        .unwrap_or_else(|err| panic!("parse {relative}: {err}"))
}

fn string<'a>(value: &'a Value, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"))
}

fn array<'a>(value: &'a Value, key: &str) -> &'a Vec<Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
}

fn child<'a>(value: &'a Value, key: &str) -> &'a Value {
    value
        .get(key)
        .unwrap_or_else(|| panic!("{key} must be present"))
}

fn contract() -> Value {
    parse_json(CONTRACT_PATH)
}

fn fixture_paths(contract: &Value) -> Vec<String> {
    array(contract, "fixture_matrix")
        .iter()
        .map(|fixture| string(fixture, "fixture").to_owned())
        .collect()
}

fn validate_fixture(fixture: &Value) -> Result<(), String> {
    for field in [
        "schema_version",
        "scenario_id",
        "claim_id",
        "claim_class",
        "surface_id",
        "phase",
        "lab_fixture",
        "live_adapter",
        "admitted_differences",
        "timing_normalization",
        "platform_prerequisites",
        "expected_logs",
        "failure_bundle",
        "readme_or_support_matrix_row",
        "verification_floor",
        "expected_verdict",
        "no_claims",
    ] {
        if fixture.get(field).is_none() {
            return Err(format!("missing required field {field}"));
        }
    }

    if string(fixture, "schema_version") != FIXTURE_SCHEMA {
        return Err("unexpected fixture schema".to_owned());
    }
    if array(fixture, "no_claims").is_empty() {
        return Err("no_claims must be nonempty".to_owned());
    }
    if array(fixture, "expected_logs").is_empty() {
        return Err("expected_logs must be nonempty".to_owned());
    }
    if array(fixture, "verification_floor").is_empty() {
        return Err("verification_floor must be nonempty".to_owned());
    }

    let timing = child(fixture, "timing_normalization");
    for field in ["policy_doc", "clock_model", "wall_clock_fields"] {
        if !child(timing, field).is_string() {
            return Err(format!("timing_normalization.{field} must be a string"));
        }
    }
    if string(timing, "policy_doc") != "docs/lab_live_time_normalization_policy.md" {
        return Err("timing policy must point at the canonical doc".to_owned());
    }

    let failure_bundle = child(fixture, "failure_bundle");
    for field in [
        "bundle_path",
        "summary_record",
        "events_record",
        "repro_command",
        "first_failure_field",
    ] {
        if !child(failure_bundle, field).is_string() {
            return Err(format!("failure_bundle.{field} must be a string"));
        }
    }
    if !string(failure_bundle, "repro_command").contains("rch exec --") {
        return Err("failure bundle repro command must use rch".to_owned());
    }

    Ok(())
}

#[test]
fn contract_links_sources_and_existing_lab_live_contracts() {
    let contract = contract();
    assert_eq!(
        contract["contract_version"].as_str(),
        Some("lab-live-differential-scenario-contract-v1")
    );
    assert_eq!(contract["bead_id"].as_str(), Some(BEAD_ID));
    assert_eq!(contract["artifact_path"].as_str(), Some(CONTRACT_PATH));

    let source = child(&contract, "source_of_truth");
    for key in [
        "contract",
        "docs",
        "contract_test",
        "pass_fixture",
        "fail_fixture",
        "unsupported_fixture",
        "stale_fixture",
    ] {
        let path = string(source, key);
        assert!(
            repo_path(path).exists(),
            "source_of_truth.{key} must point at a live path: {path}"
        );
    }

    let inherited = array(&contract, "inherits")
        .iter()
        .map(|entry| string(entry, "path"))
        .collect::<BTreeSet<_>>();
    for path in [
        "docs/lab_live_differential_scope_matrix.md",
        "docs/lab_live_normalized_observable_schema.md",
        "docs/lab_live_divergence_taxonomy.md",
        "docs/lab_live_verification_taxonomy.md",
        "docs/lab_live_scenario_adapter_contract.md",
        "artifacts/lab_live_differential_v2_scenarios_v1.json",
    ] {
        assert!(
            inherited.contains(path),
            "missing inherited contract: {path}"
        );
        assert!(
            repo_path(path).exists(),
            "inherited contract must exist: {path}"
        );
    }
}

#[test]
fn scenario_schema_requires_no_claim_boundaries() {
    let contract = contract();
    let schema = child(&contract, "scenario_schema");
    let required = array(schema, "required_fields")
        .iter()
        .map(|field| field.as_str().expect("required field string"))
        .collect::<BTreeSet<_>>();
    for field in [
        "lab_fixture",
        "live_adapter",
        "admitted_differences",
        "timing_normalization",
        "failure_bundle",
        "readme_or_support_matrix_row",
        "verification_floor",
        "no_claims",
    ] {
        assert!(required.contains(field), "required field missing: {field}");
    }
    assert!(
        string(schema, "required_no_claim_boundary").contains("nonempty no_claims"),
        "schema must make no_claim boundaries mandatory"
    );
}

#[test]
fn fixtures_cover_pass_fail_unsupported_and_stale_outcomes() {
    let contract = contract();
    let verdicts = array(&contract, "fixture_matrix")
        .iter()
        .map(|fixture| string(fixture, "expected_verdict"))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        verdicts,
        BTreeSet::from(["fail", "pass", "stale", "unsupported"])
    );

    let claim_classes = array(&contract, "semantic_claim_map")
        .iter()
        .map(|claim| string(claim, "claim_class"))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        claim_classes,
        BTreeSet::from(["stale_evidence", "supported_now", "unsupported"])
    );
}

#[test]
fn fixtures_are_valid_and_match_contract_matrix() {
    let contract = contract();
    let allowed_verdicts = array(
        child(&contract, "scenario_schema"),
        "expected_verdict_values",
    )
    .iter()
    .map(|value| value.as_str().expect("verdict string"))
    .collect::<BTreeSet<_>>();

    for path in fixture_paths(&contract) {
        let fixture = parse_json(&path);
        validate_fixture(&fixture).unwrap_or_else(|err| panic!("{path}: {err}"));
        assert!(
            allowed_verdicts.contains(string(&fixture, "expected_verdict")),
            "{path} has unknown verdict"
        );
        assert!(
            string(&fixture, "readme_or_support_matrix_row").starts_with("docs/"),
            "{path} must point at a docs support row"
        );
    }
}

#[test]
fn fixture_without_no_claims_is_rejected() {
    let contract = contract();
    let path = fixture_paths(&contract)
        .into_iter()
        .find(|path| path.contains("pass_channel"))
        .expect("pass fixture path");
    let mut fixture = parse_json(&path);
    fixture
        .as_object_mut()
        .expect("fixture object")
        .remove("no_claims");

    let err = validate_fixture(&fixture).expect_err("missing no_claims must fail");
    assert!(
        err.contains("no_claims"),
        "error should name no_claims, got {err}"
    );
}

#[test]
fn docs_explain_claim_classes_and_no_claim_boundary() {
    let docs = read_repo_file(DOCS_PATH);
    for token in [
        BEAD_ID,
        "supported_now",
        "supported_later",
        "unsupported",
        "stale_evidence",
        "no_claims",
        "do not prove broad workspace health",
        "does not replace the existing `asupersync-2a6k9` lab/live program",
    ] {
        assert!(docs.contains(token), "docs missing token: {token}");
    }
}
