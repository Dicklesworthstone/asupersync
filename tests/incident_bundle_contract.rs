//! Contract tests for the incident bundle schema artifact.

use asupersync::trace::{
    INCIDENT_BUNDLE_SCHEMA_VERSION, IncidentBundle, IncidentSourceKind, IncidentValidationIssueKind,
};
use serde_json::Value;
use std::collections::BTreeSet;

const CONTRACT_PATH: &str = "artifacts/incident_bundle_contract_v1.json";

fn contract() -> Value {
    let raw = std::fs::read_to_string(CONTRACT_PATH).expect("incident contract artifact exists");
    serde_json::from_str(&raw).expect("incident contract artifact parses as JSON")
}

fn issue_tags(report: &asupersync::trace::IncidentValidationReport) -> BTreeSet<String> {
    report
        .issues
        .iter()
        .map(|issue| issue.kind.as_str().to_string())
        .collect()
}

#[test]
fn artifact_source_kinds_match_rust_schema() {
    let artifact = contract();
    let artifact_tags: BTreeSet<String> = artifact["source_kinds"]
        .as_array()
        .expect("source_kinds is an array")
        .iter()
        .map(|value| value.as_str().expect("source kind is string").to_string())
        .collect();
    let rust_tags: BTreeSet<String> = IncidentSourceKind::supported_tags()
        .iter()
        .map(|tag| (*tag).to_string())
        .collect();

    assert_eq!(artifact_tags, rust_tags);
}

#[test]
fn artifact_fail_closed_triggers_match_rust_issue_tags() {
    let artifact = contract();
    let artifact_tags: BTreeSet<String> = artifact["fail_closed_triggers"]
        .as_array()
        .expect("fail_closed_triggers is an array")
        .iter()
        .map(|value| value.as_str().expect("issue kind is string").to_string())
        .collect();
    let rust_tags: BTreeSet<String> = [
        IncidentValidationIssueKind::UnsupportedSchemaVersion,
        IncidentValidationIssueKind::MissingRequiredField,
        IncidentValidationIssueKind::DuplicateSourceId,
        IncidentValidationIssueKind::UnsupportedSourceKind,
        IncidentValidationIssueKind::MissingRedactionPolicy,
        IncidentValidationIssueKind::RedactionRequiredButMissing,
        IncidentValidationIssueKind::SecretLikeMaterial,
        IncidentValidationIssueKind::OversizedField,
        IncidentValidationIssueKind::ExternalPath,
        IncidentValidationIssueKind::MalformedContentHash,
        IncidentValidationIssueKind::BinaryLikePayload,
        IncidentValidationIssueKind::DuplicateFeatureFlag,
    ]
    .into_iter()
    .map(|kind| kind.as_str().to_string())
    .collect();

    assert_eq!(artifact_tags, rust_tags);
}

#[test]
fn accepted_fixture_validates_cleanly() {
    let artifact = contract();
    let bundle: IncidentBundle = serde_json::from_value(artifact["fixtures"]["accepted"].clone())
        .expect("accepted fixture parses");
    let report = bundle.validate();

    assert!(report.is_accepted(), "{report:#?}");
    assert_eq!(report.schema_version, INCIDENT_BUNDLE_SCHEMA_VERSION);
    assert_eq!(report.bundle_id, "incident-fixture-accepted");
}

#[test]
fn rejected_fixtures_validate_as_typed_blockers() {
    let artifact = contract();
    let rejected = artifact["fixtures"]["rejected"]
        .as_array()
        .expect("rejected fixtures are an array");

    assert!(!rejected.is_empty());
    for fixture in rejected {
        let scenario = fixture["scenario_id"]
            .as_str()
            .expect("scenario id is present");
        let bundle: IncidentBundle =
            serde_json::from_value(fixture["bundle"].clone()).expect("rejected bundle parses");
        let report = bundle.validate();
        let tags = issue_tags(&report);
        let expected: BTreeSet<String> = fixture["expected_issue_kinds"]
            .as_array()
            .expect("expected issue kinds are present")
            .iter()
            .map(|value| value.as_str().expect("issue kind is string").to_string())
            .collect();

        assert!(!report.is_accepted(), "{scenario}: {report:#?}");
        assert!(
            expected.is_subset(&tags),
            "{scenario}: expected {expected:?}, got {tags:?}"
        );
    }
}

#[test]
fn artifact_lists_script_and_rch_proof_commands() {
    let artifact = contract();
    assert_eq!(
        artifact["e2e_script"].as_str(),
        Some("scripts/validate_incident_bundle_contract.sh")
    );
    let commands = artifact["proof_commands"]
        .as_array()
        .expect("proof commands are present");
    assert!(commands.iter().any(|command| {
        command
            .as_str()
            .is_some_and(|text| text.contains("rch exec"))
    }));
    assert!(commands.iter().any(|command| {
        command
            .as_str()
            .is_some_and(|text| text.contains("incident_bundle_contract"))
    }));
}
