#![allow(missing_docs)]

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const ARTIFACT_PATH: &str = "artifacts/downstream_consumer_proof_v1.json";
const FIXTURE_MANIFEST_PATH: &str = "tests/fixtures/downstream-consumer-proof/Cargo.toml";
const MANIFEST_PATH: &str = "artifacts/proof_lane_manifest_v1.json";
const SNAPSHOT_PATH: &str = "artifacts/proof_status_snapshot_v1.json";

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_repo_file(relative: &str) -> String {
    std::fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|err| panic!("read {relative}: {err}"))
}

fn json(relative: &str) -> Value {
    serde_json::from_str(&read_repo_file(relative))
        .unwrap_or_else(|err| panic!("parse {relative}: {err}"))
}

fn array<'a>(value: &'a Value, key: &str) -> &'a Vec<Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
}

fn object<'a>(value: &'a Value, key: &str) -> &'a Value {
    value
        .get(key)
        .filter(|entry| entry.is_object())
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

fn string_set(value: &Value, key: &str) -> BTreeSet<String> {
    array(value, key)
        .iter()
        .map(|item| {
            item.as_str()
                .unwrap_or_else(|| panic!("{key} entries must be strings"))
                .to_string()
        })
        .collect()
}

fn manifest_lanes(manifest: &Value) -> BTreeMap<String, Value> {
    array(manifest, "lanes")
        .iter()
        .map(|lane| (string(lane, "lane_id").to_string(), lane.clone()))
        .collect()
}

fn manifest_guarantees(manifest: &Value) -> BTreeMap<String, Value> {
    array(manifest, "guarantees")
        .iter()
        .map(|guarantee| {
            (
                string(guarantee, "guarantee_id").to_string(),
                guarantee.clone(),
            )
        })
        .collect()
}

fn artifact_profile_entries(artifact: &Value) -> Vec<&Value> {
    let mut entries = Vec::new();
    entries.extend(array(artifact, "positive_profiles"));
    entries.extend(array(artifact, "dependency_profiles"));
    entries.extend(array(artifact, "negative_fixtures"));
    entries.push(object(artifact, "contract_profile"));
    entries
}

#[test]
fn fixture_is_external_workspace_and_does_not_enable_test_internals() {
    let artifact = json(ARTIFACT_PATH);
    let fixture_manifest = read_repo_file(FIXTURE_MANIFEST_PATH);

    assert_eq!(
        artifact["contract_version"].as_str(),
        Some("downstream-consumer-proof-v1")
    );
    assert_eq!(
        artifact["bead_id"].as_str(),
        Some("asupersync-validation-frontier-v2-b5cjsv.5")
    );
    assert_eq!(
        artifact["fixture_manifest"].as_str(),
        Some(FIXTURE_MANIFEST_PATH)
    );
    assert!(repo_path(string(&artifact, "fixture_root")).is_dir());
    assert!(fixture_manifest.contains("[workspace]"));
    assert!(fixture_manifest.contains("name = \"asupersync-downstream-consumer-proof\""));
    assert!(fixture_manifest.contains("asupersync = { path = \"../../..\" }"));
    assert!(fixture_manifest.contains("metrics-profile = [\"asupersync/metrics\"]"));
    assert!(
        fixture_manifest
            .contains("channel-mpsc-select-e2e-profile = [\"asupersync/channel-mpsc-select-e2e\"]")
    );
    assert!(
        !fixture_manifest.contains("test-internals"),
        "the downstream fixture must not opt into internal test helpers"
    );
}

#[test]
fn fixture_sources_keep_positive_and_negative_surfaces_separate() {
    let artifact = json(ARTIFACT_PATH);
    let lib_source = read_repo_file("tests/fixtures/downstream-consumer-proof/src/lib.rs");
    assert!(lib_source.contains("use asupersync::{Budget, Outcome, Time};"));
    assert!(!lib_source.contains("test_utils"));

    for profile in array(&artifact, "positive_profiles") {
        let source = read_repo_file(string(profile, "bin_path"));
        assert!(
            !source.contains("test_utils"),
            "{} must stay on public API only",
            string(profile, "profile_id")
        );
    }

    let negative = &array(&artifact, "negative_fixtures")[0];
    let negative_source = read_repo_file(string(negative, "bin_path"));
    assert!(negative_source.contains(string(negative, "forbidden_reference")));
    assert_eq!(string(negative, "expected_error_code"), "E0433");
}

#[test]
fn proof_manifest_lanes_match_downstream_profiles() {
    let artifact = json(ARTIFACT_PATH);
    let manifest = json(MANIFEST_PATH);
    let lanes = manifest_lanes(&manifest);
    let guarantees = manifest_guarantees(&manifest);

    for profile in artifact_profile_entries(&artifact) {
        let lane_id = string(profile, "lane_id");
        let guarantee_id = string(profile, "guarantee_id");
        let lane = lanes
            .get(lane_id)
            .unwrap_or_else(|| panic!("missing manifest lane {lane_id}"));
        let guarantee = guarantees
            .get(guarantee_id)
            .unwrap_or_else(|| panic!("missing manifest guarantee {guarantee_id}"));

        assert_eq!(string(lane, "command"), string(profile, "command"));
        assert_eq!(
            string_set(lane, "feature_flags"),
            string_set(profile, "root_feature_flags"),
            "{lane_id}: manifest feature flags must record root asupersync features"
        );
        assert!(
            string_set(lane, "guarantee_ids").contains(guarantee_id),
            "{lane_id}: lane must map to {guarantee_id}"
        );
        assert!(
            string_set(guarantee, "lane_ids").contains(lane_id),
            "{guarantee_id}: guarantee must map back to {lane_id}"
        );
        assert!(
            string_set(lane, "source_paths").contains(FIXTURE_MANIFEST_PATH),
            "{lane_id}: source paths must include fixture manifest"
        );
        if let Some(bin_path) = profile.get("bin_path").and_then(Value::as_str) {
            assert!(
                string_set(lane, "source_paths").contains(bin_path),
                "{lane_id}: source paths must include profile bin"
            );
        }
        assert!(
            string(lane, "explicit_not_covered").contains("release-readiness"),
            "{lane_id}: no-claim boundaries must be visible in the lane"
        );
    }
}

#[test]
fn status_snapshot_maps_the_downstream_claim_without_overclaiming() {
    let artifact = json(ARTIFACT_PATH);
    let snapshot = json(SNAPSHOT_PATH);
    let manifest = json(MANIFEST_PATH);
    let lanes = manifest_lanes(&manifest);
    let claim_id = string(&artifact, "status_claim_id");
    let claim = array(&snapshot, "claim_categories")
        .iter()
        .find(|entry| entry["claim_id"].as_str() == Some(claim_id))
        .unwrap_or_else(|| panic!("missing proof status claim {claim_id}"));

    let expected_lane_ids = artifact_profile_entries(&artifact)
        .iter()
        .map(|profile| string(profile, "lane_id").to_string())
        .collect::<BTreeSet<_>>();
    let expected_guarantee_ids = artifact_profile_entries(&artifact)
        .iter()
        .map(|profile| string(profile, "guarantee_id").to_string())
        .collect::<BTreeSet<_>>();
    let expected_commands = expected_lane_ids
        .iter()
        .map(|lane_id| string(lanes.get(lane_id).expect("lane exists"), "command").to_string())
        .collect::<BTreeSet<_>>();

    assert_eq!(string(claim, "status"), "yellow_frontier");
    assert_eq!(string(claim, "proof_evidence_status"), "rerun-required");
    assert_eq!(string_set(claim, "manifest_lane_ids"), expected_lane_ids);
    assert_eq!(
        string_set(claim, "manifest_guarantee_ids"),
        expected_guarantee_ids
    );
    assert_eq!(string_set(claim, "proof_commands"), expected_commands);
    assert!(claim.get("blocked_frontier").is_some_and(Value::is_null));

    let notes = string(claim, "notes");
    for boundary in string_set(&artifact, "no_claim_boundaries") {
        assert!(
            notes.contains(&boundary),
            "status notes must carry no-claim boundary {boundary}"
        );
    }
}
