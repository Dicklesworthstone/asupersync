#![allow(missing_docs)]

use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const CONTRACT_PATH: &str = "artifacts/lab_live_timing_platform_policy_v1.json";
const DOCS_PATH: &str = "docs/lab_live_timing_platform_policy.md";
const BEAD_ID: &str = "asupersync-idea-wizard-fifth-wave-3gaiun.5.3";
const FIXTURE_SCHEMA: &str = "lab-live-timing-platform-policy-fixture-v1";

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
        .map(|entry| string(entry, "fixture").to_owned())
        .collect()
}

fn validate_fixture(fixture: &Value) -> Result<(), String> {
    for field in [
        "schema_version",
        "scenario_id",
        "claim_id",
        "surface_id",
        "expected_verdict",
        "policy_class",
        "time_policy_class",
        "scheduler_noise_class",
        "platform_report",
        "adapter",
        "classification_inputs",
        "failure_bundle",
        "expected_logs",
        "redaction",
        "docs_alignment",
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

    let platform_report = child(fixture, "platform_report");
    for field in [
        "surface_family",
        "host_role",
        "capability_status",
        "eligibility_verdict",
        "observability_status",
        "platform_prerequisites",
    ] {
        if platform_report.get(field).is_none() {
            return Err(format!("platform_report.{field} must be present"));
        }
    }
    if array(platform_report, "platform_prerequisites").is_empty() {
        return Err("platform prerequisites must be nonempty".to_owned());
    }

    let failure_bundle = child(fixture, "failure_bundle");
    for field in [
        "seed",
        "repro_command",
        "platform",
        "adapter",
        "logs",
        "replay_pointers",
        "redaction",
    ] {
        if failure_bundle.get(field).is_none() {
            return Err(format!("failure_bundle.{field} must be present"));
        }
    }
    if !string(failure_bundle, "repro_command").contains("rch exec --") {
        return Err("failure_bundle.repro_command must use rch".to_owned());
    }
    if array(failure_bundle, "logs").is_empty() {
        return Err("failure_bundle.logs must be nonempty".to_owned());
    }
    if array(failure_bundle, "replay_pointers").is_empty() {
        return Err("failure_bundle.replay_pointers must be nonempty".to_owned());
    }

    let redaction = child(fixture, "redaction");
    for field in ["input_samples", "redacted_samples", "forbidden_substrings"] {
        if redaction.get(field).is_none() {
            return Err(format!("redaction.{field} must be present"));
        }
    }
    let forbidden = array(redaction, "forbidden_substrings")
        .iter()
        .map(|entry| entry.as_str().expect("forbidden substring string"))
        .collect::<Vec<_>>();
    for sample in array(redaction, "redacted_samples") {
        let sample = sample.as_str().expect("redacted sample string");
        for token in &forbidden {
            if sample.contains(token) {
                return Err(format!("redacted sample leaked token {token}"));
            }
        }
    }

    let expected_verdict = string(fixture, "expected_verdict");
    let classification = child(fixture, "classification_inputs");
    if expected_verdict == "skip" {
        if child(classification, "skip_is_pass").as_bool() != Some(false) {
            return Err("skip fixtures must set skip_is_pass=false".to_owned());
        }
    }
    if expected_verdict == "stale" {
        if child(classification, "stale_is_pass").as_bool() != Some(false) {
            return Err("stale fixtures must set stale_is_pass=false".to_owned());
        }
    }

    Ok(())
}

#[test]
fn contract_links_sources_and_inherited_policy_docs() {
    let contract = contract();
    assert_eq!(
        contract["contract_version"].as_str(),
        Some("lab-live-timing-platform-policy-v1")
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
        "skip_fixture",
        "stale_fixture",
        "malformed_fixture",
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
        "artifacts/lab_live_differential_scenario_contract_v1.json",
        "docs/lab_live_time_normalization_policy.md",
        "docs/lab_live_virtualized_surface_matrix.md",
        "docs/lab_live_divergence_taxonomy.md",
        "docs/lab_live_verification_taxonomy.md",
    ] {
        assert!(inherited.contains(path), "missing inherited policy: {path}");
        assert!(
            repo_path(path).exists(),
            "inherited policy must exist: {path}"
        );
    }
}

#[test]
fn policy_schema_makes_skip_and_stale_non_passing() {
    let contract = contract();
    let schema = child(&contract, "policy_schema");
    assert_eq!(child(schema, "skip_is_pass").as_bool(), Some(false));
    assert_eq!(child(schema, "stale_is_pass").as_bool(), Some(false));
    assert!(
        string(schema, "required_no_claim_boundary").contains("Skip and stale"),
        "schema must explain skip/stale no-pass semantics"
    );

    let required = array(schema, "required_fields")
        .iter()
        .map(|field| field.as_str().expect("required field string"))
        .collect::<BTreeSet<_>>();
    for field in [
        "platform_report",
        "failure_bundle",
        "redaction",
        "classification_inputs",
        "no_claims",
    ] {
        assert!(required.contains(field), "required field missing: {field}");
    }
}

#[test]
fn fixtures_cover_pass_fail_skip_and_stale() {
    let contract = contract();
    let verdicts = array(&contract, "fixture_matrix")
        .iter()
        .map(|entry| string(entry, "expected_verdict"))
        .collect::<BTreeSet<_>>();
    assert_eq!(verdicts, BTreeSet::from(["fail", "pass", "skip", "stale"]));

    let policy_classes = array(&contract, "fixture_matrix")
        .iter()
        .map(|entry| string(entry, "policy_class"))
        .collect::<BTreeSet<_>>();
    assert!(policy_classes.contains("semantic_match"));
    assert!(policy_classes.contains("runtime_semantic_bug"));
    assert!(policy_classes.contains("unsupported_surface"));
    assert!(policy_classes.contains("stale_evidence"));
}

#[test]
fn fixtures_are_valid_and_redacted() {
    let contract = contract();
    let allowed_verdicts = array(child(&contract, "policy_schema"), "expected_verdict_values")
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
            array(&fixture, "docs_alignment")
                .iter()
                .all(|entry| entry.as_str().expect("docs path").starts_with("docs/")),
            "{path} must align only to checked docs paths"
        );
    }
}

#[test]
fn malformed_platform_report_fixture_is_rejected() {
    let contract = contract();
    let negative = array(&contract, "negative_fixtures")
        .first()
        .expect("negative fixture");
    let path = string(negative, "fixture");
    let fixture = parse_json(path);
    let err = validate_fixture(&fixture).expect_err("malformed fixture must fail");
    assert_eq!(err, string(negative, "expected_error"));
}

#[test]
fn docs_explain_classification_redaction_and_no_claims() {
    let docs = read_repo_file(DOCS_PATH);
    for token in [
        BEAD_ID,
        "pass",
        "fail",
        "skip",
        "stale",
        "A skip is not pass",
        "Stale is not pass",
        "docs/lab_live_time_normalization_policy.md",
        "docs/lab_live_virtualized_surface_matrix.md",
        "failure bundle",
        "redaction",
        "do not run live adapter scenarios",
    ] {
        assert!(docs.contains(token), "docs missing token: {token}");
    }
}
