#![allow(missing_docs)]

use serde_json::Value;

const ARTIFACT: &str = include_str!("../artifacts/lab_live_support_claim_report_v1.json");
const MANIFEST: &str = include_str!("../artifacts/proof_lane_manifest_v1.json");
const SNAPSHOT: &str = include_str!("../artifacts/proof_status_snapshot_v1.json");
const README: &str = include_str!("../README.md");
const DOCS: &str = include_str!("../docs/lab_live_support_claim_report.md");
const FRESH_FILESYSTEM: &str =
    include_str!("fixtures/lab_live_support_claim_report/fresh_filesystem_claim.json");
const STALE_REFUSAL: &str =
    include_str!("fixtures/lab_live_support_claim_report/stale_evidence_refusal.json");
const DRIFT_DEMOTION: &str =
    include_str!("fixtures/lab_live_support_claim_report/drift_demotion.json");

const ARTIFACT_PATH: &str = "artifacts/lab_live_support_claim_report_v1.json";
const DOCS_PATH: &str = "docs/lab_live_support_claim_report.md";
const LANE_ID: &str = "lab-live-support-claim-report-contract";
const CLAIM_ID: &str = "lab-live-support-claim-report";
const GUARANTEE_ID: &str = "lab-live-support-claim-report-contract";
const PROOF_COMMAND: &str = "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_lab_live_support_claim_report CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -p asupersync --test lab_live_support_claim_report_contract -- --nocapture";

fn json(src: &str) -> Value {
    serde_json::from_str(src).expect("JSON fixture must parse")
}

fn array<'a>(value: &'a Value, key: &str) -> &'a Vec<Value> {
    value[key]
        .as_array()
        .unwrap_or_else(|| panic!("{key} must be an array"))
}

fn string<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} must be a string"))
}

fn bool_field(value: &Value, key: &str) -> bool {
    value[key]
        .as_bool()
        .unwrap_or_else(|| panic!("{key} must be a bool"))
}

fn contains_value(value: &Value, key: &str, expected: &str) -> bool {
    array(value, key).iter().any(|entry| entry == expected)
}

fn find_by_id<'a>(rows: &'a [Value], key: &str, id: &str) -> &'a Value {
    rows.iter()
        .find(|row| row[key] == id)
        .unwrap_or_else(|| panic!("missing {key}={id}"))
}

fn fixtures() -> Vec<Value> {
    vec![
        json(FRESH_FILESYSTEM),
        json(STALE_REFUSAL),
        json(DRIFT_DEMOTION),
    ]
}

#[test]
fn report_aggregates_v1_v2_v3_and_filesystem_runner_evidence() {
    let artifact = json(ARTIFACT);
    assert_eq!(
        artifact["schema_version"],
        "lab-live-support-claim-report-v1"
    );
    assert_eq!(
        artifact["bead_id"],
        "asupersync-idea-wizard-fifth-wave-3gaiun.5.4"
    );
    assert_eq!(artifact["artifact_path"], ARTIFACT_PATH);
    assert_eq!(artifact["proof_status_claim_id"], CLAIM_ID);
    assert_eq!(artifact["manifest_lane_id"], LANE_ID);
    assert_eq!(artifact["manifest_guarantee_id"], GUARANTEE_ID);

    for input in [
        "artifacts/lab_live_differential_scenario_contract_v1.json",
        "artifacts/lab_live_differential_v2_scenarios_v1.json",
        "artifacts/lab_live_timing_platform_policy_v1.json",
        "artifacts/lab_live_v2_filesystem_runner_v1.json",
    ] {
        assert!(
            contains_value(&artifact, "input_artifacts", input),
            "missing {input}"
        );
    }

    let rows = array(&artifact, "report_rows");
    assert_eq!(rows.len(), 4);
    for row_id in [
        "captured-filesystem-current-fresh",
        "raw-host-filesystem-skip",
        "stale-evidence-refusal",
        "drift-demotion",
    ] {
        let row = find_by_id(rows, "row_id", row_id);
        assert!(
            !array(row, "no_claims").is_empty(),
            "{row_id} must preserve no-claim boundaries"
        );
    }
}

#[test]
fn fixtures_enforce_fresh_stale_and_drift_decisions() {
    for fixture in fixtures() {
        assert_eq!(
            fixture["schema_version"],
            "lab-live-support-claim-fixture-v1"
        );
        assert!(!array(&fixture, "no_claims").is_empty());
        assert_eq!(fixture["artifact_bundle"]["report"], ARTIFACT_PATH);
    }

    let fresh = json(FRESH_FILESYSTEM);
    assert_eq!(string(&fresh, "evidence_status"), "fresh");
    assert_eq!(string(&fresh, "support_action"), "allow_scoped_claim");
    assert!(bool_field(&fresh, "claim_strengthening_allowed"));
    assert_eq!(fresh["freshness"]["evidence_age_days"], 0);

    let stale = json(STALE_REFUSAL);
    assert_eq!(string(&stale, "evidence_status"), "stale");
    assert_eq!(string(&stale, "support_action"), "refuse_strengthening");
    assert!(!bool_field(&stale, "claim_strengthening_allowed"));
    assert!(
        stale["freshness"]["evidence_age_days"]
            .as_i64()
            .expect("evidence age")
            > stale["freshness"]["max_age_days"]
                .as_i64()
                .expect("max age")
    );

    let drift = json(DRIFT_DEMOTION);
    assert_eq!(string(&drift, "evidence_status"), "drift");
    assert_eq!(string(&drift, "live_verdict"), "fail");
    assert_eq!(string(&drift, "support_action"), "demote_or_block");
    assert!(!bool_field(&drift, "claim_strengthening_allowed"));
    assert_eq!(
        drift["demotion"]["support_class_after"],
        "blocked_or_unsupported"
    );
}

#[test]
fn manifest_and_status_snapshot_wire_the_focused_rch_lane() {
    let manifest = json(MANIFEST);
    assert!(contains_value(
        &manifest,
        "required_guarantee_ids",
        GUARANTEE_ID
    ));
    let lane = find_by_id(array(&manifest, "lanes"), "lane_id", LANE_ID);
    assert_eq!(string(lane, "command"), PROOF_COMMAND);
    assert_eq!(lane["resource_envelope_class"], "artifact-contract-medium");
    assert!(contains_value(lane, "guarantee_ids", GUARANTEE_ID));
    assert!(contains_value(lane, "source_paths", ARTIFACT_PATH));
    assert!(contains_value(lane, "source_paths", DOCS_PATH));
    assert!(contains_value(lane, "source_paths", "README.md"));
    assert!(
        string(lane, "explicit_not_covered").contains("broad workspace health")
            && string(lane, "explicit_not_covered").contains("raw host filesystem")
    );

    let guarantee = find_by_id(array(&manifest, "guarantees"), "guarantee_id", GUARANTEE_ID);
    assert!(contains_value(guarantee, "lane_ids", LANE_ID));

    let snapshot = json(SNAPSHOT);
    assert!(contains_value(
        &snapshot,
        "required_claim_categories",
        "lab-live support-claim report"
    ));
    let row = find_by_id(array(&snapshot, "claim_categories"), "claim_id", CLAIM_ID);
    assert_eq!(string(row, "category"), "lab-live support-claim report");
    assert_eq!(string(row, "status"), "yellow_scoped");
    assert_eq!(string(row, "proof_evidence_status"), "rerun-required");
    assert!(contains_value(row, "manifest_lane_ids", LANE_ID));
    assert!(contains_value(row, "manifest_guarantee_ids", GUARANTEE_ID));
    assert!(contains_value(row, "proof_commands", PROOF_COMMAND));
}

#[test]
fn report_refuses_to_strengthen_without_fresh_evidence() {
    let artifact = json(ARTIFACT);
    let rows = array(&artifact, "report_rows");
    let stale = find_by_id(rows, "row_id", "stale-evidence-refusal");
    assert_eq!(string(stale, "support_action"), "refuse_strengthening");
    assert_eq!(string(stale, "evidence_status"), "stale");
    assert_eq!(
        string(stale, "expected_report_verdict"),
        "stale_evidence_refused"
    );

    let skip = find_by_id(rows, "row_id", "raw-host-filesystem-skip");
    assert_eq!(string(skip, "support_action"), "refuse_promotion");
    assert_eq!(string(skip, "evidence_status"), "unsupported");
    assert!(
        array(skip, "no_claims")
            .iter()
            .any(|claim| claim == "skip is not pass evidence")
    );
}

#[test]
fn readme_and_docs_explain_the_claim_gate_and_next_family_runbook() {
    assert!(README.contains(DOCS_PATH));
    assert!(README.contains(ARTIFACT_PATH));

    for marker in [
        "skipped platform capability is never pass evidence",
        "Stale evidence cannot strengthen README or support-matrix claims",
        "Demotion Policy",
        "Adding The Next Adapter Family",
        "does not prove broad workspace health",
    ] {
        assert!(DOCS.contains(marker), "missing docs marker {marker}");
    }
}
