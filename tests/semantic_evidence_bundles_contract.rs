#![allow(clippy::nursery, clippy::pedantic, missing_docs)]

use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const ARTIFACT_PATH: &str = "artifacts/semantic_evidence_bundles_v1.json";
const DOCS_PATH: &str = "docs/semantic_evidence_bundles.md";
const README_PATH: &str = "README.md";
const PROOF_MANIFEST_PATH: &str = "artifacts/proof_lane_manifest_v1.json";
const BEAD_ID: &str = "asupersync-idea-wizard-fifth-wave-3gaiun.14";

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_repo_file(relative: &str) -> String {
    std::fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|err| panic!("read {relative}: {err}"))
}

fn json_file(relative: &str) -> Value {
    serde_json::from_str(&read_repo_file(relative))
        .unwrap_or_else(|err| panic!("parse {relative}: {err}"))
}

fn array<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value
        .get(key)
        .and_then(Value::as_array)
        .map_or_else(|| panic!("{key} must be an array"), Vec::as_slice)
}

fn object<'a>(value: &'a Value, key: &str) -> &'a Value {
    let object = value.get(key).unwrap_or_else(|| panic!("{key} must exist"));
    assert!(object.is_object(), "{key} must be an object");
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

fn proof_manifest_lane_ids() -> BTreeSet<String> {
    array(&json_file(PROOF_MANIFEST_PATH), "lanes")
        .iter()
        .map(|lane| string(lane, "lane_id").to_owned())
        .collect()
}

fn assert_live_path(path: &str) {
    assert!(repo_path(path).exists(), "path must exist: {path}");
}

#[test]
fn artifact_docs_readme_and_validation_are_wired() {
    let artifact = json_file(ARTIFACT_PATH);
    assert_eq!(
        artifact.get("schema_version").and_then(Value::as_str),
        Some("semantic-evidence-bundles-v1")
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
        Some("tests/semantic_evidence_bundles_contract.rs")
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

    let readme = read_repo_file(README_PATH);
    let marker = string(&artifact, "readme_marker");
    assert!(readme.contains(marker), "README missing {marker}");
    assert!(
        readme.contains(ARTIFACT_PATH),
        "README must link semantic evidence artifact"
    );
    assert!(
        readme.contains("tests/semantic_evidence_bundles_contract.rs"),
        "README must link contract test"
    );

    let validation = object(&artifact, "validation");
    let command = string(validation, "rch_command");
    assert!(command.starts_with("RCH_REQUIRE_REMOTE=1 rch exec -- env "));
    assert!(command.contains("cargo test -p asupersync --test semantic_evidence_bundles_contract"));
    assert!(command.contains("--no-default-features"));
    assert!(bool_field(validation, "no_local_cargo_fallback"));
}

#[test]
fn bundles_cover_exactly_the_required_public_guarantees() {
    let artifact = json_file(ARTIFACT_PATH);
    let required = string_set(&artifact, "required_guarantee_ids");
    let required_fields = string_set(&artifact, "required_bundle_fields");
    let bundles = array(&artifact, "public_guarantee_bundles");
    assert_eq!(bundles.len(), required.len());

    let mut actual = BTreeSet::new();
    for bundle in bundles {
        let bundle_id = string(bundle, "bundle_id");
        let guarantee_id = string(bundle, "public_guarantee_id");
        actual.insert(guarantee_id.to_owned());

        for field in &required_fields {
            assert!(bundle.get(field).is_some(), "{bundle_id} missing {field}");
        }
        assert!(
            !array(bundle, "primary_lanes").is_empty(),
            "{bundle_id} must have a primary lane"
        );
        assert!(
            !array(bundle, "supporting_lanes").is_empty(),
            "{bundle_id} must have supporting lanes"
        );
        assert!(
            !array(bundle, "failure_mode_examples").is_empty(),
            "{bundle_id} must have failure examples"
        );
        assert!(
            !array(bundle, "stale_missing_fixtures").is_empty(),
            "{bundle_id} must have stale/missing fixtures"
        );
        assert!(
            !array(bundle, "no_claims").is_empty(),
            "{bundle_id} must have no-claim boundaries"
        );
        for path in array(bundle, "source_paths") {
            assert_live_path(path.as_str().expect("bundle source path"));
        }
    }

    assert_eq!(actual, required);
}

#[test]
fn proof_lanes_exist_in_manifest_and_require_fresh_remote_evidence() {
    let artifact = json_file(ARTIFACT_PATH);
    let lane_ids = proof_manifest_lane_ids();

    for bundle in array(&artifact, "public_guarantee_bundles") {
        let bundle_id = string(bundle, "bundle_id");
        let freshness = object(bundle, "freshness_policy");
        assert!(
            bool_field(freshness, "fresh_rch_required"),
            "{bundle_id} must require fresh RCH"
        );
        assert!(
            !bool_field(freshness, "cache_hit_allowed"),
            "{bundle_id} must not treat cache hits as fresh proof"
        );
        assert!(
            bool_field(freshness, "dirty_overlap_requires_rerun"),
            "{bundle_id} must rerun on dirty overlap"
        );
        assert!(
            !bool_field(freshness, "local_fallback_allowed"),
            "{bundle_id} must reject local fallback"
        );

        for lane_key in ["primary_lanes", "supporting_lanes"] {
            for lane in array(bundle, lane_key) {
                let lane = lane.as_str().expect("lane id string");
                assert!(
                    lane_ids.contains(lane),
                    "{bundle_id} references unknown manifest lane {lane}"
                );
            }
        }
    }
}

#[test]
fn fail_closed_fixtures_and_golden_report_are_complete() {
    let artifact = json_file(ARTIFACT_PATH);
    let fixture_ids = array(&artifact, "stale_missing_fixture_cases")
        .iter()
        .map(|fixture| {
            assert_eq!(
                fixture.get("expected_verdict").and_then(Value::as_str),
                Some("blocked")
            );
            assert!(
                string(fixture, "reason").contains("cannot")
                    || string(fixture, "reason").contains("requires")
                    || string(fixture, "reason").contains("must")
                    || string(fixture, "reason").contains("not evidence"),
                "fixture reason must be fail-closed"
            );
            string(fixture, "fixture_id").to_owned()
        })
        .collect::<BTreeSet<_>>();
    assert!(fixture_ids.contains("missing-primary-lane"));
    assert!(fixture_ids.contains("stale-rch-receipt"));
    assert!(fixture_ids.contains("local-fallback-receipt"));
    assert!(fixture_ids.contains("dirty-overlap-without-rerun"));
    assert!(fixture_ids.contains("missing-no-claim-boundary"));

    let required = string_set(&artifact, "required_guarantee_ids");
    let report = object(&artifact, "golden_report");
    assert_eq!(
        report.get("report_id").and_then(Value::as_str),
        Some("semantic-evidence-bundles-golden-report-v1")
    );
    let reported = array(report, "rows")
        .iter()
        .map(|row| {
            assert_eq!(
                row.get("status").and_then(Value::as_str),
                Some("ready-for-proof-rerun")
            );
            assert!(
                string(row, "next_action").contains("rerun"),
                "report rows must require rerun before citation"
            );
            string(row, "public_guarantee_id").to_owned()
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(reported, required);
}

#[test]
fn no_claim_boundaries_prevent_overstatement() {
    let artifact = json_file(ARTIFACT_PATH);
    let top_no_claims = array(&artifact, "no_claims")
        .iter()
        .map(|claim| claim.as_str().expect("no-claim string"))
        .collect::<Vec<_>>();
    assert!(
        top_no_claims
            .iter()
            .any(|claim| claim.contains("does not execute any proof lane"))
    );
    assert!(
        top_no_claims
            .iter()
            .any(|claim| claim.contains("does not prove broad workspace health"))
    );
    assert!(
        top_no_claims
            .iter()
            .any(|claim| claim.contains("does not turn cached"))
    );

    let rendered = serde_json::to_string(&artifact).expect("render artifact");
    for forbidden in [
        "\"local_fallback_allowed\":true",
        "\"cache_hit_allowed\":true",
        "\"fresh_rch_required\":false",
        "\"dirty_overlap_requires_rerun\":false",
    ] {
        assert!(
            !rendered.contains(forbidden),
            "artifact must not contain forbidden policy {forbidden}"
        );
    }
}
