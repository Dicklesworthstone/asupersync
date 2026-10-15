#![allow(missing_docs)]

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const SIGNOFF_PATH: &str = "artifacts/artifact_governance_final_signoff_v1.json";
const RUNBOOK_PATH: &str = "docs/proof/artifact_governance_final_signoff.md";
const LEDGER_PATH: &str = "artifacts/artifact_governance_ledger_v1.json";
const HARNESS_PATH: &str = "artifacts/artifact_governance_validation_harness_v1.json";
const MANIFEST_PATH: &str = "artifacts/proof_lane_manifest_v1.json";
const STATUS_PATH: &str = "artifacts/proof_status_snapshot_v1.json";
const BEAD_ID: &str = "asupersync-artifact-governance-awdiwy.6";
const LANE_ID: &str = "artifact-governance-final-signoff";
const GUARANTEE_ID: &str = "artifact-governance-final-signoff";
const CLAIM_ID: &str = "artifact-governance-final-signoff";

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_repo_file(relative: &str) -> String {
    std::fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|error| panic!("read {relative}: {error}"))
}

fn repo_json(relative: &str) -> Value {
    serde_json::from_str(&read_repo_file(relative))
        .unwrap_or_else(|error| panic!("parse {relative}: {error}"))
}

fn array<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value
        .get(key)
        .and_then(Value::as_array)
        .map_or_else(|| panic!("{key} must be an array"), Vec::as_slice)
}

fn object<'a>(value: &'a Value, key: &str) -> &'a serde_json::Map<String, Value> {
    value
        .get(key)
        .and_then(Value::as_object)
        .unwrap_or_else(|| panic!("{key} must be an object"))
}

fn string<'a>(value: &'a Value, key: &str) -> &'a str {
    let text = value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"));
    assert!(!text.trim().is_empty(), "{key} must be nonempty");
    text
}

fn optional_string<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    match value.get(key) {
        Some(Value::Null) | None => None,
        Some(Value::String(text)) => {
            assert!(!text.trim().is_empty(), "{key} must be nonempty when set");
            Some(text)
        }
        Some(_) => panic!("{key} must be null or string"),
    }
}

fn bool_field(value: &Value, key: &str) -> bool {
    value
        .get(key)
        .and_then(Value::as_bool)
        .unwrap_or_else(|| panic!("{key} must be a bool"))
}

fn string_set(value: &Value, key: &str) -> BTreeSet<String> {
    array(value, key)
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .filter(|text| !text.trim().is_empty())
                .unwrap_or_else(|| panic!("{key} entries must be nonempty strings"))
                .to_owned()
        })
        .collect()
}

fn assert_repo_file_exists(path: &str) {
    assert!(repo_path(path).is_file(), "repo file must exist: {path}");
}

fn rows_by_id() -> BTreeMap<String, Value> {
    let ledger = repo_json(LEDGER_PATH);
    let mut rows = BTreeMap::new();
    for row in array(&ledger, "rows") {
        let artifact_id = string(row, "artifact_id").to_owned();
        assert!(
            rows.insert(artifact_id.clone(), row.clone()).is_none(),
            "duplicate ledger row {artifact_id}"
        );
    }
    rows
}

fn lanes_by_id() -> BTreeMap<String, Value> {
    let manifest = repo_json(MANIFEST_PATH);
    array(&manifest, "lanes")
        .iter()
        .map(|lane| (string(lane, "lane_id").to_owned(), lane.clone()))
        .collect()
}

fn guarantees_by_id() -> BTreeMap<String, Value> {
    let manifest = repo_json(MANIFEST_PATH);
    array(&manifest, "guarantees")
        .iter()
        .map(|guarantee| {
            (
                string(guarantee, "guarantee_id").to_owned(),
                guarantee.clone(),
            )
        })
        .collect()
}

fn status_rows_by_claim() -> BTreeMap<String, Value> {
    let status = repo_json(STATUS_PATH);
    array(&status, "claim_categories")
        .iter()
        .map(|row| (string(row, "claim_id").to_owned(), row.clone()))
        .collect()
}

#[test]
fn final_signoff_schema_sources_and_policy_are_bounded() {
    let signoff = repo_json(SIGNOFF_PATH);
    assert_eq!(
        signoff.get("schema_version").and_then(Value::as_str),
        Some("artifact-governance-final-signoff-v1")
    );
    assert_eq!(
        signoff.get("bead_id").and_then(Value::as_str),
        Some(BEAD_ID)
    );

    for path in object(&signoff, "source_of_truth")
        .values()
        .map(|value| value.as_str().expect("source path string"))
    {
        assert_repo_file_exists(path);
    }

    let policy = object(&signoff, "signoff_policy");
    let policy_value = Value::Object(policy.clone());
    assert!(!bool_field(&policy_value, "full_corpus_claim"));
    assert!(bool_field(
        &policy_value,
        "requires_remote_required_validation"
    ));
    assert!(bool_field(&policy_value, "no_local_fallback"));
    let non_destructive = string(&policy_value, "non_destructive_policy");
    for required in [
        "does not delete",
        "branches",
        "worktrees",
        "local Cargo fallback",
    ] {
        assert!(
            non_destructive.contains(required),
            "non_destructive_policy missing {required}"
        );
    }
    assert!(string(&policy_value, "tracker_policy").contains(".beads/issues.jsonl"));

    for boundary in string_set(&signoff, "no_claim_boundaries") {
        assert!(
            boundary.starts_with("does_not_"),
            "boundary must be a does_not token: {boundary}"
        );
    }
}

#[test]
fn child_deliverables_match_existing_artifacts_contracts_and_ledger_rows() {
    let signoff = repo_json(SIGNOFF_PATH);
    let rows = rows_by_id();
    let children = array(&signoff, "child_deliverables");
    let child_ids = children
        .iter()
        .map(|child| string(child, "child_id").to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        child_ids,
        BTreeSet::from([
            "A1".to_owned(),
            "A2".to_owned(),
            "A3".to_owned(),
            "A4".to_owned(),
            "A5".to_owned(),
            "A7".to_owned(),
            "A8".to_owned(),
        ])
    );

    for child in children {
        assert_eq!(string(child, "status"), "landed");
        assert_repo_file_exists(string(child, "primary_artifact"));
        for test_path in array(child, "contract_tests") {
            assert_repo_file_exists(test_path.as_str().expect("contract test path"));
        }
        let no_claims = string_set(child, "no_claim_boundaries");
        assert!(no_claims.len() >= 3);
        assert!(no_claims.iter().all(|claim| claim.starts_with("does_not_")));

        if let Some(row_id) = optional_string(child, "ledger_row") {
            let row = rows
                .get(row_id)
                .unwrap_or_else(|| panic!("missing ledger row {row_id}"));
            assert_eq!(string(row, "path"), string(child, "primary_artifact"));
        }
    }
}

#[test]
fn manifest_and_status_rows_point_to_the_same_remote_required_lane() {
    let signoff = repo_json(SIGNOFF_PATH);
    let proof_lane = object(&signoff, "proof_lane");
    let proof_lane_value = Value::Object(proof_lane.clone());
    let command = string(&proof_lane_value, "command");
    assert_eq!(string(&proof_lane_value, "lane_id"), LANE_ID);
    assert_eq!(string(&proof_lane_value, "guarantee_id"), GUARANTEE_ID);
    assert_eq!(string(&proof_lane_value, "status_claim_id"), CLAIM_ID);
    assert!(command.starts_with("RCH_REQUIRE_REMOTE=1 rch exec -- "));
    assert!(command.contains("artifact_governance_final_signoff_contract"));
    assert!(command.contains("proof_lane_manifest_contract"));
    assert!(command.contains("proof_status_snapshot_contract"));

    let lanes = lanes_by_id();
    let lane = lanes.get(LANE_ID).expect("manifest lane");
    assert_eq!(string(lane, "command"), command);
    assert_eq!(string(lane, "kind"), "artifact_contract");
    assert_eq!(
        string(lane, "resource_envelope_class"),
        "artifact-contract-medium"
    );
    assert_eq!(
        string_set(lane, "guarantee_ids"),
        BTreeSet::from([GUARANTEE_ID.to_owned()])
    );
    assert!(string(lane, "explicit_not_covered").contains("release readiness"));
    assert!(string(lane, "explicit_not_covered").contains("workspace health"));
    assert!(
        string_set(&lane["proof_reuse_policy"], "non_citeable_claim_scopes")
            .contains("release-readiness")
    );

    let guarantees = guarantees_by_id();
    let guarantee = guarantees.get(GUARANTEE_ID).expect("manifest guarantee");
    assert_eq!(
        string_set(guarantee, "lane_ids"),
        BTreeSet::from([LANE_ID.to_owned()])
    );

    let status_rows = status_rows_by_claim();
    let status = status_rows.get(CLAIM_ID).expect("status claim row");
    assert_eq!(string(status, "status"), "yellow_scoped");
    assert_eq!(string(status, "proof_evidence_status"), "rerun-required");
    assert_eq!(
        string_set(status, "manifest_lane_ids"),
        BTreeSet::from([LANE_ID.to_owned()])
    );
    assert_eq!(
        string_set(status, "manifest_guarantee_ids"),
        BTreeSet::from([GUARANTEE_ID.to_owned()])
    );
    assert_eq!(
        string_set(status, "proof_commands"),
        BTreeSet::from([command.to_owned()])
    );
    assert!(string(status, "notes").contains("scoped"));
    assert!(string(status, "notes").contains("does not prove release readiness"));
}

#[test]
fn ledger_and_validation_harness_include_final_signoff_without_overclaiming() {
    let rows = rows_by_id();
    let row = rows
        .get("artifact-governance-final-signoff")
        .expect("final signoff ledger row");
    assert_eq!(string(row, "path"), SIGNOFF_PATH);
    assert_eq!(string(row, "owning_bead"), BEAD_ID);
    assert_eq!(string(row, "artifact_family"), "artifact_governance");
    assert_eq!(string(row, "citeability_class"), "proof-bearing");
    assert!(
        string_set(row, "no_claim_boundaries").contains("does_not_authorize_local_cargo_fallback")
    );
    assert!(string_set(row, "no_claim_boundaries").contains("does_not_prove_release_readiness"));

    let harness = repo_json(HARNESS_PATH);
    let class_counts = object(&harness["e2e_flow_log"], "artifact_counts_by_class");
    let actual_proof_bearing = rows
        .values()
        .filter(|row| string(row, "citeability_class") == "proof-bearing")
        .count() as u64;
    assert_eq!(
        class_counts["proof-bearing"].as_u64(),
        Some(actual_proof_bearing)
    );
}

#[test]
fn runbook_and_docs_markers_preserve_no_local_fallback_boundary() {
    let runbook = read_repo_file(RUNBOOK_PATH);
    for required in [
        SIGNOFF_PATH,
        "artifact_governance_final_signoff_contract",
        "RCH_REQUIRE_REMOTE=1 rch exec --",
        "do not cite the lane as fresh proof",
        "does_not_authorize_local_cargo_fallback",
        "does_not_prove_release_readiness",
        "close A4, A7, A8, and A6",
    ] {
        assert!(runbook.contains(required), "runbook missing {required}");
    }

    let readme = read_repo_file("README.md");
    let agents = read_repo_file("AGENTS.md");
    for marker in [SIGNOFF_PATH, RUNBOOK_PATH] {
        assert!(readme.contains(marker), "README missing marker {marker}");
        assert!(agents.contains(marker), "AGENTS missing marker {marker}");
    }
}
