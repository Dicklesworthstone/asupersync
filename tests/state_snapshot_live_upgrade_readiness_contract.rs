#![allow(clippy::nursery, clippy::pedantic, missing_docs)]

use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const ARTIFACT_PATH: &str = "artifacts/state_snapshot_live_upgrade_readiness_v1.json";
const DOCS_PATH: &str = "docs/state_snapshot_live_upgrade_readiness.md";
const TEST_PATH: &str = "tests/state_snapshot_live_upgrade_readiness_contract.rs";
const BEAD_ID: &str = "asupersync-idea-wizard-fifth-wave-3gaiun.15";

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_repo_file(relative: &str) -> String {
    std::fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|err| panic!("read {relative}: {err}"))
}

fn artifact() -> Value {
    serde_json::from_str(&read_repo_file(ARTIFACT_PATH))
        .unwrap_or_else(|err| panic!("parse {ARTIFACT_PATH}: {err}"))
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
                .unwrap_or_else(|| panic!("{key} entries must be strings"))
                .to_owned()
        })
        .collect()
}

fn assert_live_path(path: &str) {
    assert!(repo_path(path).exists(), "path must exist: {path}");
}

#[test]
fn artifact_docs_and_validation_are_wired() {
    let artifact = artifact();
    assert_eq!(
        artifact.get("schema_version").and_then(Value::as_str),
        Some("state-snapshot-live-upgrade-readiness-v1")
    );
    assert_eq!(
        artifact.get("bead_id").and_then(Value::as_str),
        Some(BEAD_ID)
    );
    assert_eq!(
        artifact.get("artifact_path").and_then(Value::as_str),
        Some(ARTIFACT_PATH)
    );
    assert_eq!(
        artifact.get("docs_path").and_then(Value::as_str),
        Some(DOCS_PATH)
    );
    assert_eq!(
        artifact.get("contract_test").and_then(Value::as_str),
        Some(TEST_PATH)
    );

    for path in array(&artifact, "source_paths") {
        assert_live_path(path.as_str().expect("source path string"));
    }

    let docs = read_repo_file(DOCS_PATH);
    assert!(docs.contains(ARTIFACT_PATH), "docs must link artifact");
    assert!(docs.contains(BEAD_ID), "docs must link bead");
    for marker in array(&artifact, "docs_markers") {
        let marker = marker.as_str().expect("docs marker string");
        assert!(docs.contains(marker), "docs missing marker {marker}");
    }

    let validation = object(&artifact, "validation");
    let command = string(validation, "rch_command");
    assert!(command.starts_with("RCH_REQUIRE_REMOTE=1 rch exec -- env "));
    assert!(command.contains(
        "cargo test -p asupersync --test state_snapshot_live_upgrade_readiness_contract"
    ));
    assert!(command.contains("--no-default-features"));
    assert!(bool_field(validation, "no_local_cargo_fallback"));
}

#[test]
fn feasibility_matrix_covers_required_surfaces_with_live_anchors() {
    let artifact = artifact();
    let required = string_set(&artifact, "required_surface_ids");
    let surfaces = array(&artifact, "feasibility_matrix");
    assert_eq!(surfaces.len(), required.len());

    let mut actual = BTreeSet::new();
    for surface in surfaces {
        let surface_id = string(surface, "surface_id");
        actual.insert(surface_id.to_owned());
        assert!(
            !array(surface, "evidence").is_empty(),
            "{surface_id} must carry evidence"
        );
        assert!(
            !array(surface, "next_steps").is_empty(),
            "{surface_id} must carry next steps"
        );
        assert!(
            !array(surface, "no_claims").is_empty(),
            "{surface_id} must carry no-claim boundaries"
        );
        for path in array(surface, "source_paths") {
            assert_live_path(path.as_str().expect("surface source path"));
        }
    }

    assert_eq!(actual, required);
}

#[test]
fn versioned_schema_and_handoff_protocol_fail_closed() {
    let artifact = artifact();
    let schema = object(&artifact, "versioned_snapshot_schema");
    assert_eq!(
        schema.get("schema_id").and_then(Value::as_str),
        Some("asupersync-state-snapshot-handoff-v1")
    );
    assert_eq!(
        schema.get("version_field").and_then(Value::as_str),
        Some("RestorableSnapshot::schema_version")
    );
    assert_eq!(
        schema
            .get("content_integrity_field")
            .and_then(Value::as_str),
        Some("RestorableSnapshot::content_hash")
    );
    assert!(
        string(schema, "compatible_upgrade_policy").contains("exact schema-version matches"),
        "schema policy must reject implicit migration"
    );

    let incompatible = object(schema, "incompatible_state_policy");
    for key in [
        "unknown_schema_version",
        "hash_mismatch",
        "orphan_task",
        "orphan_obligation",
        "cyclic_region_tree",
        "closed_region_with_live_children",
        "unresolved_handoff_obligations",
    ] {
        assert_eq!(
            incompatible.get(key).and_then(Value::as_str),
            Some("reject"),
            "{key} must reject"
        );
    }

    let handoff = object(&artifact, "handoff_protocol");
    let phases = array(handoff, "phases")
        .iter()
        .map(|phase| {
            assert!(
                !array(phase, "required_evidence").is_empty(),
                "phase must require evidence"
            );
            string(phase, "phase").to_owned()
        })
        .collect::<Vec<_>>();
    assert_eq!(
        phases,
        ["prepare", "quiesce", "snapshot", "validate", "restore"]
    );
}

#[test]
fn fail_closed_fixtures_cover_incompatible_and_unsupported_states() {
    let artifact = artifact();
    let required = string_set(&artifact, "required_fail_closed_fixture_ids");
    let fixtures = array(&artifact, "fail_closed_fixtures");
    assert_eq!(fixtures.len(), required.len());

    let mut actual = BTreeSet::new();
    for fixture in fixtures {
        let fixture_id = string(fixture, "fixture_id");
        actual.insert(fixture_id.to_owned());
        assert_eq!(
            fixture.get("expected_verdict").and_then(Value::as_str),
            Some("blocked"),
            "{fixture_id} must block"
        );
        assert!(
            string(fixture, "expected_reason").contains("reject")
                || string(fixture, "expected_reason").contains("requires")
                || string(fixture, "expected_reason").contains("cannot")
                || string(fixture, "expected_reason").contains("non-goal"),
            "{fixture_id} reason must be fail-closed"
        );
    }

    assert_eq!(actual, required);
}

#[test]
fn proof_lane_and_no_claims_prevent_live_upgrade_overclaim() {
    let artifact = artifact();
    let lanes = array(&artifact, "proof_lanes");
    assert_eq!(lanes.len(), 1);
    let lane = &lanes[0];
    assert_eq!(
        lane.get("lane_id").and_then(Value::as_str),
        Some("state-snapshot-live-upgrade-readiness-contract")
    );
    let command = string(lane, "command");
    assert!(command.starts_with("RCH_REQUIRE_REMOTE=1 rch exec -- env "));
    assert!(command.contains("--no-default-features"));
    assert!(!array(lane, "covers").is_empty());
    assert!(
        array(lane, "does_not_cover")
            .iter()
            .any(|item| item.as_str() == Some("production live upgrade"))
    );

    let top_no_claims = array(&artifact, "no_claims")
        .iter()
        .map(|claim| claim.as_str().expect("no-claim string"))
        .collect::<Vec<_>>();
    assert!(
        top_no_claims
            .iter()
            .any(|claim| claim.contains("does not implement production live upgrade"))
    );
    assert!(
        top_no_claims
            .iter()
            .any(|claim| claim.contains("does not support arbitrary hot code reload"))
    );

    let rendered = serde_json::to_string(&artifact).expect("render artifact");
    for forbidden in [
        "\"readiness\":\"supported\"",
        "\"support_class\":\"implemented-production-live-upgrade\"",
        "\"no_local_cargo_fallback\":false",
    ] {
        assert!(
            !rendered.contains(forbidden),
            "artifact must not contain forbidden overclaim {forbidden}"
        );
    }
}
