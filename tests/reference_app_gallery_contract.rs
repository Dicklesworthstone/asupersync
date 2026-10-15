#![allow(clippy::nursery, clippy::pedantic, missing_docs)]

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const ARTIFACT_PATH: &str = "artifacts/reference_app_gallery_v1.json";
const DOCS_PATH: &str = "docs/reference_app_gallery.md";
const TEST_PATH: &str = "tests/reference_app_gallery_contract.rs";
const BEAD_ID: &str = "asupersync-idea-wizard-fifth-wave-3gaiun.8";
const TARGET_DIR: &str = "${TMPDIR:-/tmp}/rch_target_reference_app_gallery";

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_repo_file(relative: &str) -> String {
    std::fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|error| panic!("read {relative}: {error}"))
}

fn artifact() -> Value {
    serde_json::from_str(&read_repo_file(ARTIFACT_PATH))
        .unwrap_or_else(|error| panic!("parse {ARTIFACT_PATH}: {error}"))
}

fn array<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value
        .get(key)
        .and_then(Value::as_array)
        .map_or_else(|| panic!("{key} must be an array"), Vec::as_slice)
}

fn object<'a>(value: &'a Value, key: &str) -> &'a Value {
    value
        .get(key)
        .and_then(Value::as_object)
        .unwrap_or_else(|| panic!("{key} must be an object"));
    value.get(key).expect("object field checked above")
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

fn rows_by_id<'a>(value: &'a Value, key: &str, id_key: &str) -> BTreeMap<String, &'a Value> {
    array(value, key)
        .iter()
        .map(|row| (string(row, id_key).to_owned(), row))
        .collect()
}

fn assert_live_path(path: &str) {
    assert!(repo_path(path).exists(), "path must exist: {path}");
}

fn assert_remote_required_cargo_command(command: &str) {
    assert!(
        command.starts_with("RCH_REQUIRE_REMOTE=1 rch exec -- env "),
        "proof command must require remote RCH: {command}"
    );
    assert!(
        command.contains(" cargo test "),
        "proof command must run cargo through RCH: {command}"
    );
    for required in [
        "CARGO_INCREMENTAL=0",
        "CARGO_PROFILE_TEST_DEBUG=0",
        "RUSTFLAGS='-D warnings -C debuginfo=0'",
        "--no-default-features",
        "-- --nocapture",
    ] {
        assert!(
            command.contains(required),
            "proof command missing {required}: {command}"
        );
    }
    for forbidden in [
        "RCH_ALLOW_LOCAL=1",
        "RCH_REQUIRE_REMOTE=0",
        "local fallback",
        "executing locally",
    ] {
        assert!(
            !command.contains(forbidden),
            "proof command contains forbidden fallback marker {forbidden}: {command}"
        );
    }
}

#[test]
fn artifact_docs_and_remote_validation_are_wired() {
    let artifact = artifact();
    assert_eq!(
        artifact.get("schema_version").and_then(Value::as_str),
        Some("reference-app-gallery-v1")
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

    let docs = read_repo_file(DOCS_PATH);
    assert!(docs.contains(ARTIFACT_PATH), "docs must link artifact");
    assert!(docs.contains(BEAD_ID), "docs must link bead");
    for marker in array(&artifact, "docs_markers") {
        let marker = marker.as_str().expect("docs marker string");
        assert!(docs.contains(marker), "docs missing marker {marker}");
    }

    let validation = object(&artifact, "validation");
    let command = string(validation, "rch_command");
    assert!(command.contains(TARGET_DIR));
    assert!(command.contains("--test reference_app_gallery_contract"));
    assert_remote_required_cargo_command(command);
    assert!(bool_field(validation, "no_local_cargo_fallback"));
}

#[test]
fn every_required_journey_has_live_sources_and_remote_repros() {
    let artifact = artifact();
    let required = string_set(&artifact, "required_journey_ids");
    let journeys = rows_by_id(&artifact, "journeys", "journey_id");
    assert_eq!(journeys.keys().cloned().collect::<BTreeSet<_>>(), required);

    let supported_classes = array(&artifact, "support_class_catalog")
        .iter()
        .map(|entry| string(entry, "support_class").to_owned())
        .collect::<BTreeSet<_>>();

    for (journey_id, journey) in journeys {
        assert!(
            supported_classes.contains(string(journey, "support_class")),
            "{journey_id} must use a declared support class"
        );
        for path in array(journey, "source_paths") {
            assert_live_path(path.as_str().expect("source path string"));
        }
        for path in array(journey, "evidence_refs") {
            assert_live_path(path.as_str().expect("evidence path string"));
        }
        for command in array(journey, "repro_commands") {
            assert_remote_required_cargo_command(command.as_str().expect("command string"));
        }
        assert!(
            !array(journey, "structured_log_fields").is_empty(),
            "{journey_id} must define structured log fields"
        );
        assert!(
            !array(journey, "no_claims").is_empty(),
            "{journey_id} must define no-claim boundaries"
        );
    }
}

#[test]
fn structured_log_contract_is_deterministic_and_redacted() {
    let artifact = artifact();
    let contract = object(&artifact, "structured_log_contract");
    let required = string_set(contract, "required_fields");
    for field in [
        "journey_id",
        "scenario_id",
        "proof_command",
        "support_class",
        "outcome",
        "artifact_path",
    ] {
        assert!(required.contains(field), "missing log field {field}");
    }
    let forbidden = string_set(contract, "forbidden_fields");
    for field in [
        "secret",
        "token",
        "password",
        "raw_request_body",
        "raw_response_body",
        "absolute_host_path",
    ] {
        assert!(
            forbidden.contains(field),
            "missing forbidden log field {field}"
        );
    }
    assert_eq!(
        contract.get("redaction_policy").and_then(Value::as_str),
        Some("reference-app-gallery-redaction-v1")
    );
    assert!(
        string(contract, "failure_policy").contains("block"),
        "log failure policy must fail closed"
    );
}

#[test]
fn blocked_adapter_rows_cannot_be_rendered_as_passing() {
    let artifact = artifact();
    let journeys = rows_by_id(&artifact, "journeys", "journey_id");
    let blocked = journeys
        .values()
        .filter(|journey| {
            journey.get("support_class").and_then(Value::as_str) == Some("blocked-adapter")
        })
        .collect::<Vec<_>>();
    assert_eq!(
        blocked.len(),
        1,
        "exactly one known blocked adapter row expected"
    );
    let blocked_row = blocked[0];
    assert!(
        !array(blocked_row, "known_blockers").is_empty(),
        "blocked adapter row must name blockers"
    );
    assert!(
        array(blocked_row, "no_claims")
            .iter()
            .any(|claim| claim.as_str()
                == Some("does not turn blocked adapter status into passing reference coverage")),
        "blocked adapter row must not pass as coverage"
    );
}

#[test]
fn proof_lane_and_no_claims_prevent_gallery_overclaiming() {
    let artifact = artifact();
    let lanes = array(&artifact, "proof_lanes");
    assert_eq!(lanes.len(), 1);
    let lane = &lanes[0];
    assert_eq!(
        lane.get("lane_id").and_then(Value::as_str),
        Some("reference-app-gallery-contract")
    );
    assert_remote_required_cargo_command(string(lane, "command"));
    assert!(bool_field(lane, "no_local_cargo_fallback"));
    for boundary in [
        "running each journey",
        "production app completeness",
        "external service availability",
        "broad workspace health",
        "release readiness",
    ] {
        assert!(
            array(lane, "does_not_cover")
                .iter()
                .any(|item| item.as_str() == Some(boundary)),
            "missing lane boundary {boundary}"
        );
    }

    let no_claims = array(&artifact, "no_claims")
        .iter()
        .map(|claim| claim.as_str().expect("no-claim string"))
        .collect::<Vec<_>>();
    for required in [
        "does not create new production reference apps",
        "does not run every journey",
        "does not prove production deployment readiness",
        "does not prove broad workspace health",
        "does not prove release readiness",
        "does not authorize local Cargo fallback",
        "does not turn blocked adapter rows into passing coverage",
    ] {
        assert!(no_claims.contains(&required), "missing no-claim {required}");
    }
}
