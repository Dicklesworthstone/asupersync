#![allow(missing_docs)]

use serde_json::Value;

const RUNNER: &str = include_str!("../scripts/run_doctor_e2e.sh");
const RUN_ALL_E2E: &str = include_str!("../scripts/run_all_e2e.sh");
const DOCS: &str = include_str!("../docs/doctor_e2e_harness_contract.md");
const MANIFEST: &str = include_str!("../artifacts/proof_lane_manifest_v1.json");
const STATUS: &str = include_str!("../artifacts/proof_status_snapshot_v1.json");

fn json(text: &str) -> Value {
    serde_json::from_str(text).expect("valid json")
}

fn array<'a>(value: &'a Value, key: &str) -> &'a Vec<Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
}

fn find_by_id<'a>(rows: &'a [Value], id_key: &str, id: &str) -> &'a Value {
    rows.iter()
        .find(|row| row.get(id_key).and_then(Value::as_str) == Some(id))
        .unwrap_or_else(|| panic!("missing {id_key}={id}"))
}

fn string_array_contains(value: &Value, key: &str, expected: &str) {
    let values = value
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"));
    assert!(
        values.iter().any(|entry| entry.as_str() == Some(expected)),
        "{key} must contain {expected}"
    );
}

#[test]
fn runner_emits_required_artifacts_and_fail_closed_events() {
    for required in [
        "doctor_e2e_proof_lane",
        "summary.json",
        "events.ndjson",
        "operator_report.md",
        "doctor-e2e-proof-lane-event-v1",
        "RCH_REQUIRE_REMOTE=1",
        "rch_local_fallback",
        "doctor diagnoses evidence but does not certify broad workspace health",
    ] {
        assert!(RUNNER.contains(required), "runner missing {required}");
    }

    for stage in [
        "test_doctor_workspace_scan_e2e.sh",
        "test_doctor_report_export_e2e.sh",
        "test_doctor_cli_packaging_e2e.sh",
        "doctor_analyzer_fixture_harness",
    ] {
        assert!(RUNNER.contains(stage), "runner missing stage {stage}");
    }

    for coverage in [
        "representative fixture scans",
        "malformed-input failure cases",
        "redaction checks",
        "report schema checks",
        "CLI smoke",
        "stale-evidence rehearsal",
    ] {
        assert!(
            RUNNER.contains(coverage),
            "runner missing coverage {coverage}"
        );
    }

    for fallback_marker in [
        "^\\[RCH\\] local \\(",
        "falling back to local",
        "local fallback marker",
        "no-local-fallback violation",
    ] {
        assert!(
            RUNNER.contains(fallback_marker),
            "runner must fail closed on {fallback_marker}"
        );
    }
}

#[test]
fn orchestrator_registers_doctor_proof_lane() {
    for required in [
        "[doctor-e2e-proof-lane]=\"run_doctor_e2e.sh\"",
        "[doctor-e2e-proof-lane]=\"target/e2e-results/doctor_e2e_proof_lane\"",
        "[doctor-e2e-proof-lane]=\"summary.json\"",
        "[doctor-e2e-proof-lane]=\"artifacts_*\"",
        "[doctor-e2e-proof-lane]=\"E2E-SUITE-DOCTOR-E2E-PROOF-LANE\"",
        "doctor-frankensuite-export doctor-e2e-proof-lane",
    ] {
        assert!(
            RUN_ALL_E2E.contains(required),
            "orchestrator missing {required}"
        );
    }
}

#[test]
fn docs_capture_contract_outputs_and_no_claim_boundary() {
    for required in [
        "doctor-e2e-proof-lane-v1",
        "scripts/run_doctor_e2e.sh",
        "summary.json",
        "events.ndjson",
        "operator_report.md",
        "tests/doctor_analyzer_fixture_harness.rs",
        "redaction checks",
        "malformed proof artifacts",
        "stale-evidence rehearsals",
        "doctor diagnoses evidence but does not certify broad workspace health",
    ] {
        assert!(DOCS.contains(required), "docs missing {required}");
    }
}

#[test]
fn proof_manifest_maps_doctor_e2e_contract_lane() {
    let manifest = json(MANIFEST);
    string_array_contains(
        &manifest,
        "required_guarantee_ids",
        "doctor-e2e-proof-lane-contract",
    );

    let lane = find_by_id(
        array(&manifest, "lanes"),
        "lane_id",
        "doctor-e2e-proof-lane-contract",
    );
    assert_eq!(lane["kind"].as_str(), Some("artifact_contract"));
    assert_eq!(
        lane["resource_envelope_class"].as_str(),
        Some("artifact-contract-medium")
    );
    assert!(
        lane["command"]
            .as_str()
            .expect("lane command")
            .contains("doctor_e2e_proof_lane_contract"),
        "lane command must run the focused contract test"
    );
    string_array_contains(lane, "guarantee_ids", "doctor-e2e-proof-lane-contract");
    string_array_contains(lane, "source_paths", "scripts/run_doctor_e2e.sh");
    string_array_contains(lane, "source_paths", "docs/doctor_e2e_harness_contract.md");

    let guarantee = find_by_id(
        array(&manifest, "guarantees"),
        "guarantee_id",
        "doctor-e2e-proof-lane-contract",
    );
    string_array_contains(guarantee, "lane_ids", "doctor-e2e-proof-lane-contract");
}

#[test]
fn status_snapshot_maps_doctor_e2e_without_overclaiming() {
    let status = json(STATUS);
    string_array_contains(
        &status,
        "required_claim_categories",
        "doctor e2e proof lane",
    );

    let claim = find_by_id(
        array(&status, "claim_categories"),
        "claim_id",
        "doctor-e2e-proof-lane",
    );
    assert_eq!(claim["category"].as_str(), Some("doctor e2e proof lane"));
    assert_eq!(claim["status"].as_str(), Some("green"));
    assert_eq!(
        claim["proof_evidence_status"].as_str(),
        Some("rerun-required")
    );
    string_array_contains(claim, "manifest_lane_ids", "doctor-e2e-proof-lane-contract");
    string_array_contains(
        claim,
        "manifest_guarantee_ids",
        "doctor-e2e-proof-lane-contract",
    );
    let notes = claim["notes"].as_str().expect("claim notes");
    assert!(notes.contains("run scripts/run_doctor_e2e.sh for fresh aggregate evidence"));
    assert!(notes.contains("does not prove broad workspace health"));
    assert!(claim["blocked_frontier"].is_null());
}
