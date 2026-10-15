//! Contract tests for incident bundle to replay-package import.

use asupersync::trace::{
    INCIDENT_REPLAY_PACKAGE_SCHEMA_VERSION, IncidentBundle, IncidentReplayBlockReasonKind,
    IncidentReplayImportVerdict, IncidentReplayPackage, IncidentReplaySourceRole,
    import_incident_bundle_json,
};
use serde_json::Value;
use std::collections::BTreeSet;

const CONTRACT_PATH: &str = "artifacts/incident_replay_import_contract_v1.json";
const SCRIPT_PATH: &str = "scripts/validate_incident_replay_import.sh";

fn contract() -> Value {
    let raw = std::fs::read_to_string(CONTRACT_PATH).expect("incident replay contract exists");
    serde_json::from_str(&raw).expect("incident replay contract parses")
}

fn role_tags() -> BTreeSet<String> {
    [
        IncidentReplaySourceRole::CrashPack,
        IncidentReplaySourceRole::TraceLog,
        IncidentReplaySourceRole::SupportBundle,
        IncidentReplaySourceRole::ReadmeClaimFailure,
        IncidentReplaySourceRole::ConformanceFailure,
        IncidentReplaySourceRole::RchProofFailure,
        IncidentReplaySourceRole::ReproNotes,
    ]
    .into_iter()
    .map(|role| role.as_str().to_string())
    .collect()
}

fn block_reason_tags() -> BTreeSet<String> {
    [
        IncidentReplayBlockReasonKind::MalformedJson,
        IncidentReplayBlockReasonKind::ValidationIssue,
        IncidentReplayBlockReasonKind::UnsupportedSourceKind,
        IncidentReplayBlockReasonKind::MissingSourcePayload,
        IncidentReplayBlockReasonKind::StaleContentHash,
        IncidentReplayBlockReasonKind::RedactionRequiredButMissing,
    ]
    .into_iter()
    .map(|kind| kind.as_str().to_string())
    .collect()
}

#[test]
fn artifact_catalog_matches_rust_importer_tags() {
    let artifact = contract();
    let artifact_roles: BTreeSet<String> = artifact["supported_replay_source_roles"]
        .as_array()
        .expect("supported roles are listed")
        .iter()
        .map(|value| value.as_str().expect("role is string").to_string())
        .collect();
    let artifact_reasons: BTreeSet<String> = artifact["block_reason_kinds"]
        .as_array()
        .expect("block reasons are listed")
        .iter()
        .map(|value| value.as_str().expect("reason is string").to_string())
        .collect();

    assert_eq!(artifact_roles, role_tags());
    assert_eq!(artifact_reasons, block_reason_tags());
    assert_eq!(
        artifact["package_schema_version"].as_u64(),
        Some(u64::from(INCIDENT_REPLAY_PACKAGE_SCHEMA_VERSION))
    );
}

#[test]
fn accepted_fixtures_import_to_stable_packages() {
    let artifact = contract();
    let accepted = artifact["fixtures"]["accepted"]
        .as_array()
        .expect("accepted fixtures are present");
    assert!(
        accepted.len() >= 2,
        "contract must keep at least two accepted golden fixtures"
    );

    let mut package_ids = BTreeSet::new();
    for fixture in accepted {
        let scenario = fixture["scenario_id"].as_str().expect("scenario id");
        let bundle: IncidentBundle =
            serde_json::from_value(fixture["bundle"].clone()).expect("accepted bundle parses");
        let report = bundle.import_replay_package();
        assert!(report.is_imported(), "{scenario}: {report:#?}");

        let package = report.package.expect("accepted import emits package");
        assert_eq!(
            package.schema_version,
            INCIDENT_REPLAY_PACKAGE_SCHEMA_VERSION
        );
        assert_eq!(package.bundle_id, bundle.bundle_id);
        assert!(package.package_id.starts_with("incident-replay-v1:"));
        assert_eq!(
            package.trace_metadata.seed,
            bundle.determinism.seed.unwrap_or(0)
        );

        let expected_roles: BTreeSet<String> = fixture["expected_roles"]
            .as_array()
            .expect("expected roles are present")
            .iter()
            .map(|value| value.as_str().expect("role is string").to_string())
            .collect();
        let actual_roles: BTreeSet<String> = package
            .sources
            .iter()
            .map(|source| source.role.as_str().to_string())
            .collect();
        assert_eq!(actual_roles, expected_roles, "{scenario}");

        let json = package.to_json().expect("package serializes");
        let parsed = IncidentReplayPackage::from_json(&json).expect("package parses");
        assert_eq!(package, parsed, "{scenario}");
        assert!(
            package_ids.insert(package.package_id.clone()),
            "package id must be unique across accepted fixtures: {}",
            package.package_id
        );
    }
}

#[test]
fn source_order_does_not_change_package_id() {
    let artifact = contract();
    let fixture = &artifact["fixtures"]["accepted"][0];
    let mut bundle: IncidentBundle =
        serde_json::from_value(fixture["bundle"].clone()).expect("accepted bundle parses");
    let first_package = bundle
        .import_replay_package()
        .package
        .expect("first package emitted");

    bundle.sources.reverse();
    let second_package = bundle
        .import_replay_package()
        .package
        .expect("second package emitted");

    assert_eq!(first_package.package_id, second_package.package_id);
    assert_eq!(
        first_package.canonicalization.source_order,
        second_package.canonicalization.source_order
    );
}

#[test]
fn rejected_fixtures_import_as_typed_blockers() {
    let artifact = contract();
    let rejected = artifact["fixtures"]["rejected"]
        .as_array()
        .expect("rejected fixtures are present");
    assert!(!rejected.is_empty());

    for fixture in rejected {
        let scenario = fixture["scenario_id"].as_str().expect("scenario id");
        let bundle: IncidentBundle =
            serde_json::from_value(fixture["bundle"].clone()).expect("rejected bundle parses");
        let report = bundle.import_replay_package();
        let actual: BTreeSet<String> = report
            .blocked_reasons
            .iter()
            .map(|reason| reason.kind.as_str().to_string())
            .collect();
        let expected: BTreeSet<String> = fixture["expected_block_reason_kinds"]
            .as_array()
            .expect("expected blocker kinds are present")
            .iter()
            .map(|value| value.as_str().expect("blocker is string").to_string())
            .collect();

        assert_eq!(report.verdict, IncidentReplayImportVerdict::Blocked);
        assert!(
            expected.is_subset(&actual),
            "{scenario}: expected {expected:?}, got {actual:?}"
        );
        assert!(report.package.is_none(), "{scenario} must not emit package");
    }
}

#[test]
fn malformed_fixture_imports_as_malformed_report() {
    let artifact = contract();
    let malformed = artifact["fixtures"]["malformed"]
        .as_str()
        .expect("malformed fixture is a string");
    let report = import_incident_bundle_json(malformed);

    assert_eq!(report.verdict, IncidentReplayImportVerdict::Malformed);
    assert!(report.contains_kind(IncidentReplayBlockReasonKind::MalformedJson));
    assert!(report.package.is_none());
}

#[test]
fn artifact_lists_script_logs_and_rch_proof_commands() {
    let artifact = contract();
    assert_eq!(artifact["e2e_script"].as_str(), Some(SCRIPT_PATH));
    assert!(
        std::path::Path::new(SCRIPT_PATH).exists(),
        "fixture runner must exist"
    );

    let log_fields: BTreeSet<String> = artifact["required_log_fields"]
        .as_array()
        .expect("required log fields are present")
        .iter()
        .map(|value| value.as_str().expect("log field is string").to_string())
        .collect();
    for field in [
        "scenario_id",
        "bead_id",
        "bundle_id",
        "verdict",
        "package_id",
        "block_reason_kinds",
        "artifact_path",
    ] {
        assert!(log_fields.contains(field), "missing log field {field}");
    }

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
            .is_some_and(|text| text.contains("incident_replay_import"))
    }));
}
