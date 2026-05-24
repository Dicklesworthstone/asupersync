#![allow(missing_docs)]

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const AGENTS_PATH: &str = "AGENTS.md";
const FRONTIER_PATH: &str = "artifacts/validation_frontier_ledger_schema_v1.json";
const MANIFEST_PATH: &str = "artifacts/proof_lane_manifest_v1.json";
const README_PATH: &str = "README.md";
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
            assert!(!text.trim().is_empty(), "{key} must be nonempty if present");
            Some(text)
        }
        _ => panic!("{key} must be a string or null"),
    }
}

fn string_vec(value: &Value, key: &str) -> Vec<String> {
    array(value, key)
        .iter()
        .map(|item| {
            item.as_str()
                .unwrap_or_else(|| panic!("{key} entries must be strings"))
                .to_string()
        })
        .collect()
}

fn string_set(value: &Value, key: &str) -> BTreeSet<String> {
    string_vec(value, key).into_iter().collect()
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

fn frontier_fixture_map(frontier: &Value) -> BTreeMap<String, Value> {
    array(frontier, "fixtures")
        .iter()
        .map(|fixture| (string(fixture, "fixture_id").to_string(), fixture.clone()))
        .collect()
}

fn proof_commands_for_lanes(
    lane_ids: &BTreeSet<String>,
    lanes: &BTreeMap<String, Value>,
) -> BTreeSet<String> {
    lane_ids
        .iter()
        .map(|lane_id| {
            let lane = lanes
                .get(lane_id)
                .unwrap_or_else(|| panic!("snapshot references missing lane {lane_id}"));
            string(lane, "command").to_string()
        })
        .collect()
}

fn validate_claim_lane_mapping(
    entry: &Value,
    lanes: &BTreeMap<String, Value>,
    guarantees: &BTreeMap<String, Value>,
) -> Result<BTreeSet<String>, String> {
    let claim_id = string(entry, "claim_id");
    let lane_ids = string_set(entry, "manifest_lane_ids");
    let guarantee_ids = string_set(entry, "manifest_guarantee_ids");
    if lane_ids.is_empty() {
        return Err(format!("{claim_id}: missing lane ids"));
    }
    if guarantee_ids.is_empty() {
        return Err(format!("{claim_id}: missing guarantee ids"));
    }

    for lane_id in &lane_ids {
        if !lanes.contains_key(lane_id) {
            return Err(format!("{claim_id}: unknown lane {lane_id}"));
        }
    }
    for guarantee_id in &guarantee_ids {
        if !guarantees.contains_key(guarantee_id) {
            return Err(format!("{claim_id}: unknown guarantee {guarantee_id}"));
        }
    }

    for guarantee_id in &guarantee_ids {
        let guarantee = guarantees
            .get(guarantee_id)
            .expect("guarantee existence checked above");
        let mapped_lanes = string_set(guarantee, "lane_ids");
        if mapped_lanes.is_disjoint(&lane_ids) {
            return Err(format!(
                "{claim_id}: guarantee {guarantee_id} must share at least one listed lane"
            ));
        }
    }

    for lane_id in &lane_ids {
        let lane = lanes.get(lane_id).expect("lane existence checked above");
        let lane_guarantees = string_set(lane, "guarantee_ids");
        if lane_guarantees.is_disjoint(&guarantee_ids) {
            return Err(format!(
                "{claim_id}: lane {lane_id} must cover at least one listed guarantee"
            ));
        }
    }

    let expected_commands = proof_commands_for_lanes(&lane_ids, lanes);
    let snapshot_commands = string_set(entry, "proof_commands");
    if expected_commands != snapshot_commands {
        return Err(format!(
            "{claim_id}: proof commands must match the manifest lane commands"
        ));
    }

    Ok(snapshot_commands)
}

fn validate_status_support(entry: &Value, lanes: &BTreeMap<String, Value>) -> Result<(), String> {
    let claim_id = string(entry, "claim_id");
    let status = string(entry, "status");
    let lane_ids = string_set(entry, "manifest_lane_ids");
    let lane_kinds = lane_ids
        .iter()
        .map(|lane_id| {
            lanes
                .get(lane_id)
                .map(|lane| string(lane, "kind").to_string())
                .ok_or_else(|| format!("{claim_id}: unknown lane {lane_id}"))
        })
        .collect::<Result<BTreeSet<_>, _>>()?;

    match status {
        "green" => {
            let frontier_only_kinds = [
                "compile_frontier",
                "test_frontier",
                "lint_frontier",
                "format_frontier",
                "documentation_frontier",
            ];
            if lane_kinds
                .iter()
                .any(|kind| frontier_only_kinds.contains(&kind.as_str()))
            {
                return Err(format!(
                    "{claim_id}: frontier lane kinds cannot be represented as green: {lane_kinds:?}"
                ));
            }
        }
        "yellow_frontier" => {
            if !lane_kinds.iter().any(|kind| kind.ends_with("_frontier")) {
                return Err(format!(
                    "{claim_id}: yellow_frontier row must include at least one frontier lane"
                ));
            }
        }
        "yellow_scoped" => {
            let notes = string(entry, "notes").to_ascii_lowercase();
            if !(notes.contains("scoped") || notes.contains("quarantine")) {
                return Err(format!(
                    "{claim_id}: yellow_scoped row must explain its scope or quarantine"
                ));
            }
        }
        "red_blocked_external" => {}
        other => return Err(format!("{claim_id}: unknown status {other}")),
    }

    Ok(())
}

fn validate_blocked_frontier_record(
    blocked: &Value,
    fixtures: &BTreeMap<String, Value>,
) -> Result<(), String> {
    let blocked = blocked
        .as_object()
        .ok_or_else(|| "red row must have a blocked_frontier object".to_string())?;
    let fixture_id = blocked
        .get("fixture_id")
        .and_then(Value::as_str)
        .ok_or_else(|| "blocked fixture_id".to_string())?;
    let fixture = fixtures
        .get(fixture_id)
        .ok_or_else(|| format!("missing frontier fixture {fixture_id}"))?;
    let expected = fixture
        .get("expected_record")
        .ok_or_else(|| format!("{fixture_id}: missing expected_record"))?;
    let first_failure = expected
        .get("first_failure")
        .ok_or_else(|| format!("{fixture_id}: missing expected first_failure"))?;
    let blocked_failure = blocked
        .get("first_failure")
        .and_then(Value::as_object)
        .ok_or_else(|| format!("{fixture_id}: blocked first_failure must be an object"))?;

    for (blocked_key, expected_value) in [
        ("command", fixture.get("command")),
        ("decision", expected.get("decision")),
        ("error_class", expected.get("error_class")),
        ("summary", expected.get("summary")),
        (
            "supplemental_proof_command",
            fixture.get("supplemental_proof_command"),
        ),
    ] {
        if blocked.get(blocked_key) != expected_value {
            return Err(format!(
                "{fixture_id}: blocked_frontier.{blocked_key} no longer matches validation frontier fixture"
            ));
        }
    }

    for key in ["crate_or_surface", "target", "file", "line"] {
        if blocked_failure.get(key) != first_failure.get(key) {
            return Err(format!(
                "{fixture_id}: first_failure.{key} must match validation frontier fixture"
            ));
        }
    }

    Ok(())
}

#[test]
fn snapshot_declares_schema_sources_and_required_categories() {
    let snapshot = json(SNAPSHOT_PATH);
    assert_eq!(
        snapshot.get("contract_version").and_then(Value::as_str),
        Some("proof-status-snapshot-v1")
    );
    assert_eq!(
        snapshot.get("bead_id").and_then(Value::as_str),
        Some("asupersync-aj7lx3.5")
    );

    let source = snapshot
        .get("source_of_truth")
        .expect("source_of_truth object");
    assert_eq!(source["snapshot"].as_str(), Some(SNAPSHOT_PATH));
    assert_eq!(source["proof_lane_manifest"].as_str(), Some(MANIFEST_PATH));
    assert_eq!(
        source["validation_frontier_ledger"].as_str(),
        Some(FRONTIER_PATH)
    );
    assert_eq!(source["readme"].as_str(), Some(README_PATH));
    assert_eq!(source["agent_instructions"].as_str(), Some(AGENTS_PATH));

    let required = string_set(&snapshot, "required_claim_categories");
    let actual = array(&snapshot, "claim_categories")
        .iter()
        .map(|entry| string(entry, "category").to_string())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        required, actual,
        "required claim categories must exactly match snapshot entries"
    );
    assert_eq!(
        actual.len(),
        9,
        "snapshot must cover the requested claim list"
    );
}

#[test]
fn statuses_are_known_and_include_live_green_and_frontier_rows() {
    let snapshot = json(SNAPSHOT_PATH);
    let allowed = array(&snapshot, "status_catalog")
        .iter()
        .map(|entry| string(entry, "status").to_string())
        .collect::<BTreeSet<_>>();
    for expected in [
        "green",
        "yellow_scoped",
        "yellow_frontier",
        "red_blocked_external",
    ] {
        assert!(allowed.contains(expected), "missing status {expected}");
    }

    let mut seen = BTreeSet::new();
    for entry in array(&snapshot, "claim_categories") {
        let status = string(entry, "status");
        assert!(allowed.contains(status), "unknown status {status}");
        seen.insert(status.to_string());
    }
    for required in ["green", "yellow_frontier"] {
        assert!(
            seen.contains(required),
            "dashboard must contain at least one {required} row"
        );
    }
}

#[test]
fn every_claim_maps_to_manifest_lanes_guarantees_and_commands() {
    let snapshot = json(SNAPSHOT_PATH);
    let manifest = json(MANIFEST_PATH);
    let lanes = manifest_lanes(&manifest);
    let guarantees = manifest_guarantees(&manifest);

    for entry in array(&snapshot, "claim_categories") {
        let claim_id = string(entry, "claim_id");
        let snapshot_commands = validate_claim_lane_mapping(entry, &lanes, &guarantees)
            .unwrap_or_else(|error| panic!("{error}"));
        for command in &snapshot_commands {
            assert!(
                command.starts_with("RCH_REQUIRE_REMOTE=1 rch exec -- "),
                "{claim_id}: proof command must require remote rch execution: {command}"
            );
            if command.contains(" cargo ") {
                assert!(
                    command.contains("CARGO_TARGET_DIR="),
                    "{claim_id}: cargo proof command must isolate target output: {command}"
                );
                assert!(
                    !command.contains("rch exec -- cargo"),
                    "{claim_id}: cargo proof command must not use bare rch cargo routing: {command}"
                );
            }
        }
    }
}

#[test]
fn status_rows_do_not_overstate_frontier_or_scoped_claims() {
    let snapshot = json(SNAPSHOT_PATH);
    let manifest = json(MANIFEST_PATH);
    let lanes = manifest_lanes(&manifest);

    for entry in array(&snapshot, "claim_categories") {
        validate_status_support(entry, &lanes).unwrap_or_else(|error| panic!("{error}"));
    }
}

#[test]
fn doc_claim_markers_are_present_in_readme_and_agents() {
    let snapshot = json(SNAPSHOT_PATH);
    let docs = BTreeMap::from([
        (README_PATH, read_repo_file(README_PATH)),
        (AGENTS_PATH, read_repo_file(AGENTS_PATH)),
    ]);
    let required_docs = docs.keys().copied().collect::<BTreeSet<_>>();

    for entry in array(&snapshot, "claim_categories") {
        let claim_id = string(entry, "claim_id");
        let markers = entry
            .get("doc_claim_markers")
            .and_then(Value::as_object)
            .unwrap_or_else(|| panic!("{claim_id}: doc_claim_markers must be an object"));
        let marker_docs = markers.keys().map(String::as_str).collect::<BTreeSet<_>>();
        assert_eq!(
            marker_docs, required_docs,
            "{claim_id}: each proof claim must carry README and AGENTS markers"
        );
        for (path, marker_values) in markers {
            let doc = docs
                .get(path.as_str())
                .unwrap_or_else(|| panic!("{claim_id}: unexpected doc path {path}"));
            let marker_array = marker_values
                .as_array()
                .unwrap_or_else(|| panic!("{claim_id}: markers for {path} must be an array"));
            assert!(
                !marker_array.is_empty(),
                "{claim_id}: markers for {path} must be nonempty"
            );
            for marker in marker_array {
                let marker = marker
                    .as_str()
                    .unwrap_or_else(|| panic!("{claim_id}: marker must be a string"));
                assert!(
                    doc.contains(marker),
                    "{claim_id}: {path} must contain marker {marker:?}"
                );
            }
        }
    }
}

#[test]
fn red_rows_carry_exact_validation_frontier_records() {
    let snapshot = json(SNAPSHOT_PATH);
    let frontier = json(FRONTIER_PATH);
    let fixtures = frontier_fixture_map(&frontier);

    for entry in array(&snapshot, "claim_categories") {
        let status = string(entry, "status");
        let blocked = entry.get("blocked_frontier").expect("blocked_frontier");
        if status == "red_blocked_external" {
            validate_blocked_frontier_record(blocked, &fixtures)
                .unwrap_or_else(|error| panic!("{error}"));
        } else {
            assert!(
                blocked.is_null(),
                "non-red rows must not attach blocked frontier records"
            );
        }
    }
}

#[test]
fn synthetic_missing_lane_and_unsupported_green_claims_are_rejected() {
    let manifest = json(MANIFEST_PATH);
    let lanes = manifest_lanes(&manifest);
    let guarantees = manifest_guarantees(&manifest);
    let missing_lane = serde_json::json!({
        "claim_id": "synthetic-missing-lane",
        "status": "yellow_frontier",
        "manifest_guarantee_ids": ["all-target-compile-frontier"],
        "manifest_lane_ids": ["not-a-real-proof-lane"],
        "proof_commands": [],
        "blocked_frontier": null,
        "notes": "frontier fixture"
    });
    let missing_lane_error =
        validate_claim_lane_mapping(&missing_lane, &lanes, &guarantees).unwrap_err();
    assert!(
        missing_lane_error.contains("unknown lane not-a-real-proof-lane"),
        "unexpected missing-lane error: {missing_lane_error}"
    );

    let unsupported_green = serde_json::json!({
        "claim_id": "synthetic-frontier-green",
        "status": "green",
        "manifest_lane_ids": ["all-targets-check"],
        "notes": "would overstate broad compile-frontier evidence"
    });
    let status_error = validate_status_support(&unsupported_green, &lanes).unwrap_err();
    assert!(
        status_error.contains("frontier lane kinds cannot be represented as green"),
        "unexpected unsupported-green error: {status_error}"
    );
}

#[test]
fn synthetic_stale_blocker_rows_are_rejected() {
    let frontier = json(FRONTIER_PATH);
    let fixtures = frontier_fixture_map(&frontier);
    let fixture = fixtures
        .get("VF-RUSTC-COMPILE-STOP")
        .expect("fixture exists");
    let expected = fixture
        .get("expected_record")
        .expect("fixture expected_record");
    let stale_blocker = serde_json::json!({
        "fixture_id": "VF-RUSTC-COMPILE-STOP",
        "command": fixture["command"].clone(),
        "decision": expected["decision"].clone(),
        "error_class": expected["error_class"].clone(),
        "summary": "stale summary that no longer matches the validation frontier fixture",
        "supplemental_proof_command": fixture["supplemental_proof_command"].clone(),
        "first_failure": expected["first_failure"].clone()
    });

    let error = validate_blocked_frontier_record(&stale_blocker, &fixtures).unwrap_err();
    assert!(
        error.contains("blocked_frontier.summary no longer matches"),
        "unexpected stale-blocker error: {error}"
    );
}

#[test]
fn documentation_points_to_snapshot_and_verifier() {
    let snapshot = json(SNAPSHOT_PATH);
    let docs = snapshot
        .get("documentation_contract")
        .expect("documentation_contract");
    let marker = string(docs, "required_marker");
    let verifier = string(docs, "verifier_marker");

    for path in string_vec(docs, "docs_must_reference_snapshot") {
        let text = read_repo_file(&path);
        assert!(text.contains(marker), "{path} must reference {marker}");
        assert!(text.contains(verifier), "{path} must reference {verifier}");
    }
}

#[test]
fn null_and_string_field_helpers_cover_blocked_shape() {
    let snapshot = json(SNAPSHOT_PATH);
    let rows = array(&snapshot, "claim_categories");
    let non_red = rows
        .iter()
        .find(|entry| string(entry, "status") != "red_blocked_external")
        .expect("at least one non-red row");
    assert!(optional_string(non_red, "missing_optional").is_none());
}
