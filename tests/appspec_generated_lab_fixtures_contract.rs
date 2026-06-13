#![allow(clippy::nursery, clippy::pedantic, missing_docs)]

use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const ARTIFACT_PATH: &str = "artifacts/appspec_generated_lab_fixtures_v1.json";
const DOCS_PATH: &str = "docs/appspec_generated_lab_fixtures.md";
const TEST_PATH: &str = "tests/appspec_generated_lab_fixtures_contract.rs";
const BEAD_ID: &str = "asupersync-idea-wizard-fifth-wave-3gaiun.2.3";
const PARENT_BEAD_ID: &str = "asupersync-idea-wizard-fifth-wave-3gaiun.2";
const BLOCKER_BEAD_ID: &str = "asupersync-idea-wizard-fifth-wave-3gaiun.2.2";
const TARGET_DIR: &str = "${TMPDIR:-/tmp}/rch_target_appspec_generated_lab_fixtures_contract";

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
    let object = value
        .get(key)
        .unwrap_or_else(|| panic!("{key} must be present"));
    assert!(object.as_object().is_some(), "{key} must be an object");
    object
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

fn assert_remote_required_cargo_command(command: &str) {
    assert!(
        command.starts_with("RCH_REQUIRE_REMOTE=1 rch exec -- env "),
        "proof command must require remote RCH: {command}"
    );
    for required in [
        TARGET_DIR,
        "CARGO_INCREMENTAL=0",
        "CARGO_PROFILE_TEST_DEBUG=0",
        "RUSTFLAGS='-D warnings -C debuginfo=0'",
        "cargo test -p asupersync --test appspec_generated_lab_fixtures_contract",
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
        "rch exec -- cargo",
        "local fallback",
        "falling back to local execution",
        "cargo test -p asupersync --test appspec_generated_lab_fixtures_contract -- --nocapture",
    ] {
        assert!(
            !command.contains(forbidden),
            "proof command contains forbidden fallback marker {forbidden}: {command}"
        );
    }
}

#[test]
fn artifact_docs_sources_and_remote_validation_are_wired() {
    let artifact = artifact();
    assert_eq!(
        artifact.get("schema_version").and_then(Value::as_str),
        Some("appspec-generated-lab-fixtures-v1")
    );
    assert_eq!(
        artifact.get("bead_id").and_then(Value::as_str),
        Some(BEAD_ID)
    );
    assert_eq!(
        artifact.get("parent_bead_id").and_then(Value::as_str),
        Some(PARENT_BEAD_ID)
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

    for path in [ARTIFACT_PATH, DOCS_PATH, TEST_PATH] {
        assert_live_path(path);
    }
    for path in object(&artifact, "source_of_truth")
        .as_object()
        .unwrap_or_else(|| panic!("source_of_truth must be an object"))
        .values()
    {
        let path = path
            .as_str()
            .unwrap_or_else(|| panic!("source_of_truth values must be paths"));
        assert_live_path(path);
    }

    let docs = read_repo_file(DOCS_PATH);
    assert!(docs.contains(ARTIFACT_PATH), "docs must link artifact");
    assert!(docs.contains(BEAD_ID), "docs must link bead");
    for marker in array(&artifact, "docs_markers") {
        let marker = marker.as_str().unwrap_or_else(|| panic!("marker string"));
        assert!(docs.contains(marker), "docs missing marker {marker}");
    }

    let validation = object(&artifact, "validation");
    assert_remote_required_cargo_command(string(validation, "rch_command"));
    assert!(bool_field(validation, "no_local_cargo_fallback"));

    let checks = string_set(validation, "local_non_cargo_checks");
    for required in [
        "jq empty artifacts/appspec_generated_lab_fixtures_v1.json",
        "rustfmt --edition 2024 --check tests/appspec_generated_lab_fixtures_contract.rs",
    ] {
        assert!(checks.contains(required), "missing check {required}");
    }
    assert!(
        checks
            .iter()
            .any(|check| check.starts_with("git diff --check -- ")),
        "local syntax checks must include diff whitespace validation"
    );
}

#[test]
fn accepted_fixture_declares_deterministic_topology_and_lab_replay() {
    let artifact = artifact();
    let fixtures = array(&artifact, "accepted_fixtures");
    assert_eq!(fixtures.len(), 1, "A3 starts with one minimal fixture");

    let fixture = &fixtures[0];
    assert_eq!(
        string(fixture, "fixture_id"),
        "minimal-http-worker-topology"
    );
    assert_eq!(string(fixture, "fixture_status"), "contracted-not-executed");

    let summary = object(fixture, "manifest_summary");
    for required in ["api", "worker", "/health"] {
        let haystack = summary.to_string();
        assert!(
            haystack.contains(required),
            "manifest summary missing {required}"
        );
    }

    let topology = object(fixture, "expected_topology_snapshot");
    let children = string_set(topology, "children");
    for required in ["service:api", "background:worker"] {
        assert!(children.contains(required), "missing child {required}");
    }

    let route_bindings = string_set(topology, "route_bindings");
    assert!(
        route_bindings.contains("/health -> service:api"),
        "missing health route binding"
    );

    let capability_declarations = string_set(topology, "capability_declarations");
    for required in [
        "service:api requires net.listen",
        "service:api requires http.server",
        "background:worker requires trace.emit",
    ] {
        assert!(
            capability_declarations.contains(required),
            "missing capability declaration {required}"
        );
    }

    let lab_replay = object(fixture, "lab_replay");
    assert_eq!(
        string(lab_replay, "execution_status"),
        "blocked-by-a2-proof"
    );
    assert_eq!(
        string(lab_replay, "expected_outcome"),
        "not-executed-until-a2-proof-is-fresh"
    );
    assert_eq!(array(lab_replay, "deterministic_seeds").len(), 3);

    let oracles = string_set(lab_replay, "oracles");
    for required in [
        "no-task-leaks",
        "region-close-quiescence",
        "no-obligation-leaks",
        "race-losers-drained",
    ] {
        assert!(oracles.contains(required), "missing oracle {required}");
    }
}

#[test]
fn negative_fixture_catalog_covers_required_validation_classes() {
    let artifact = artifact();
    let negative = array(&artifact, "negative_fixtures");
    assert_eq!(negative.len(), 4, "A3 requires four negative fixtures");

    let categories = negative
        .iter()
        .map(|row| string(row, "category").to_owned())
        .collect::<BTreeSet<_>>();
    for required in [
        "missing-capability",
        "invalid-budget-composition",
        "unsupported-db-protocol-feature",
        "supervision-cycle",
    ] {
        assert!(categories.contains(required), "missing category {required}");
    }

    for row in negative {
        string(row, "fixture_id");
        string(row, "expected_validation_phase");
        string(row, "expected_error_kind");
        assert!(
            !array(row, "no_claims").is_empty(),
            "negative fixture must carry local no-claim boundaries"
        );
    }
}

#[test]
fn proof_projection_and_status_remain_fail_closed() {
    let artifact = artifact();

    let blockers = array(&artifact, "blocked_by");
    assert!(
        blockers
            .iter()
            .any(|row| string(row, "bead_id") == BLOCKER_BEAD_ID),
        "A3 must record the A2 proof blocker"
    );

    let projection = object(&artifact, "proof_manifest_projection");
    assert_eq!(
        string(projection, "lane_id"),
        "appspec-generated-lab-fixtures-contract"
    );
    assert_eq!(string(projection, "kind"), "artifact_contract");
    assert_remote_required_cargo_command(string(projection, "command"));

    let guarantees = string_set(projection, "guarantee_ids");
    assert!(
        guarantees.contains("appspec-generated-lab-fixtures-contract"),
        "missing fixture contract guarantee"
    );

    let sources = string_set(projection, "source_paths");
    for required in [
        ARTIFACT_PATH,
        DOCS_PATH,
        TEST_PATH,
        "artifacts/appspec_v1_schema.json",
        "docs/appspec_v1.md",
        "src/app.rs",
    ] {
        assert!(sources.contains(required), "missing source {required}");
    }

    let status = object(&artifact, "proof_status_projection");
    assert_eq!(string(status, "status"), "blocked-by-a2-proof");
    assert!(!bool_field(status, "fresh_rch_pass"));
    assert_eq!(string(status, "first_blocker"), BLOCKER_BEAD_ID);

    let no_claims = string_set(&artifact, "no_claims");
    for required in [
        "broad workspace health",
        "release readiness",
        "AppSpec production readiness",
        "runtime correctness",
        "local Cargo fallback",
        "closure of asupersync-idea-wizard-fifth-wave-3gaiun.2",
        "closure of asupersync-idea-wizard-fifth-wave-3gaiun.2.3",
        "closure of asupersync-idea-wizard-fifth-wave-3gaiun.16",
    ] {
        assert!(no_claims.contains(required), "missing no-claim {required}");
    }
}
