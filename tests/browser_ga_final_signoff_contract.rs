#![allow(missing_docs)]

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const DOC_PATH: &str = "docs/browser_ga_final_signoff.md";
const FIXTURE_PATH: &str = "tests/fixtures/browser_ga_final_signoff/rollback_drill.json";
const MANIFEST_PATH: &str = "artifacts/proof_lane_manifest_v1.json";
const READINESS_PATH: &str = "artifacts/browser_edition_readiness_matrix_v1.json";
const PACKAGE_GATE_PATH: &str = "artifacts/browser_package_integrity_gate_v1.json";
const CONSUMER_MATRIX_PATH: &str = "artifacts/browser_consumer_compatibility_matrix_v1.json";
const README_PATH: &str = "README.md";
const SIGNOFF_PATH: &str = "artifacts/browser_ga_final_signoff_v1.json";
const SNAPSHOT_PATH: &str = "artifacts/proof_status_snapshot_v1.json";
const TEST_PATH: &str = "tests/browser_ga_final_signoff_contract.rs";

const BEAD_ID: &str = "asupersync-idea-wizard-fifth-wave-3gaiun.4.4";
const LANE_ID: &str = "browser-ga-final-signoff";
const PROOF_COMMAND: &str = "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_browser_ga_final_signoff CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -p asupersync --test browser_ga_final_signoff_contract -- --nocapture";

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_repo_file(relative: &str) -> String {
    std::fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|error| panic!("read {relative}: {error}"))
}

fn json(relative: &str) -> Value {
    serde_json::from_str(&read_repo_file(relative))
        .unwrap_or_else(|error| panic!("parse {relative}: {error}"))
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

fn bool_field(value: &Value, key: &str) -> bool {
    value
        .get(key)
        .and_then(Value::as_bool)
        .unwrap_or_else(|| panic!("{key} must be a boolean"))
}

fn string_set(value: &Value, key: &str) -> BTreeSet<String> {
    array(value, key)
        .iter()
        .map(|item| {
            item.as_str()
                .unwrap_or_else(|| panic!("{key} entries must be strings"))
                .to_owned()
        })
        .collect()
}

fn sha256_file(relative: &str) -> String {
    let bytes = std::fs::read(repo_path(relative))
        .unwrap_or_else(|error| panic!("hash input {relative}: {error}"));
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn signoff() -> Value {
    json(SIGNOFF_PATH)
}

fn manifest_lanes(manifest: &Value) -> BTreeMap<String, Value> {
    array(manifest, "lanes")
        .iter()
        .map(|lane| (string(lane, "lane_id").to_owned(), lane.clone()))
        .collect()
}

fn manifest_guarantees(manifest: &Value) -> BTreeMap<String, Value> {
    array(manifest, "guarantees")
        .iter()
        .map(|guarantee| {
            (
                string(guarantee, "guarantee_id").to_owned(),
                guarantee.clone(),
            )
        })
        .collect()
}

fn snapshot_claims(snapshot: &Value) -> BTreeMap<String, Value> {
    array(snapshot, "claim_categories")
        .iter()
        .map(|claim| (string(claim, "claim_id").to_owned(), claim.clone()))
        .collect()
}

fn package_manifest_version(manifest_path: &str) -> String {
    string(&json(manifest_path), "version").to_owned()
}

fn assert_remote_required_cargo(command: &str) {
    assert!(
        command.starts_with("RCH_REQUIRE_REMOTE=1 rch exec -- env "),
        "proof command must require remote RCH: {command}"
    );
    assert!(
        command.contains("CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_browser_ga_final_signoff"),
        "proof command must isolate the Browser GA target dir: {command}"
    );
    assert!(
        command.contains(" cargo test -p asupersync --test browser_ga_final_signoff_contract "),
        "proof command must run the focused Browser GA signoff contract: {command}"
    );
    for forbidden in [
        "RCH_ALLOW_LOCAL=1",
        "RCH_REQUIRE_REMOTE=0",
        "rch exec -- cargo",
        "[RCH] local",
        "local fallback accepted",
    ] {
        assert!(
            !command.contains(forbidden),
            "proof command contains forbidden local/fallback marker {forbidden}: {command}"
        );
    }
}

#[test]
fn signoff_declares_sources_decision_and_remote_required_lane() {
    let artifact = signoff();
    assert_eq!(
        artifact.get("schema_version").and_then(Value::as_str),
        Some("browser-ga-final-signoff-v1")
    );
    assert_eq!(string(&artifact, "bead_id"), BEAD_ID);
    assert_eq!(
        string(&artifact, "parent_bead"),
        "asupersync-idea-wizard-fifth-wave-3gaiun.4"
    );

    let source = &artifact["source_of_truth"];
    for (key, expected) in [
        ("signoff_artifact", SIGNOFF_PATH),
        ("human_report", DOC_PATH),
        ("rollback_drill_fixture", FIXTURE_PATH),
        ("contract_test", TEST_PATH),
        ("readiness_matrix", READINESS_PATH),
        ("package_integrity_gate", PACKAGE_GATE_PATH),
        ("consumer_compatibility_matrix", CONSUMER_MATRIX_PATH),
        ("proof_lane_manifest", MANIFEST_PATH),
        ("proof_status_snapshot", SNAPSHOT_PATH),
        ("readme", README_PATH),
    ] {
        assert_eq!(string(source, key), expected);
        assert!(
            repo_path(expected).exists(),
            "source_of_truth.{key} path {expected} must exist"
        );
    }

    let lane = &artifact["signoff_lane"];
    assert_eq!(string(lane, "lane_id"), LANE_ID);
    assert_eq!(string(lane, "guarantee_id"), LANE_ID);
    assert_eq!(string(lane, "proof_status_claim_id"), LANE_ID);
    assert_eq!(string(lane, "proof_command"), PROOF_COMMAND);
    assert_remote_required_cargo(string(lane, "proof_command"));

    let decision = &artifact["decision"];
    assert_eq!(string(decision, "final_verdict"), "pass_scoped_js_ts_ga");
    assert_eq!(string(decision, "release_channel"), "stable");
    assert!(bool_field(decision, "js_ts_package_ga_allowed"));
    assert!(!bool_field(decision, "rust_browser_api_stable_allowed"));
    assert!(!bool_field(
        decision,
        "service_worker_direct_runtime_allowed"
    ));
    assert!(!bool_field(
        decision,
        "shared_worker_direct_runtime_allowed"
    ));
    assert!(!bool_field(decision, "npm_publish_executed"));
}

#[test]
fn source_evidence_rows_bind_b1_b2_b3_artifacts_without_widening_claims() {
    let artifact = signoff();
    let rows = array(&artifact, "source_evidence_rows");
    let row_ids = rows
        .iter()
        .map(|row| string(row, "row_id").to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        row_ids,
        BTreeSet::from([
            "browser-edition-readiness-matrix".to_string(),
            "browser-package-integrity-gate".to_string(),
            "browser-consumer-compatibility-matrix".to_string(),
        ])
    );

    let evidence_ids = rows
        .iter()
        .map(|row| string(row, "evidence_id").to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        evidence_ids,
        string_set(&artifact["freshness_policy"], "required_source_evidence")
    );

    for row in rows {
        assert_eq!(
            string(row, "current_evidence_status"),
            "artifact-contract-present"
        );
        for path in array(row, "artifact_paths") {
            let path = path.as_str().expect("artifact_paths entries are strings");
            assert!(repo_path(path).exists(), "missing evidence path {path}");
        }
        assert!(
            string(row, "claim_boundary").contains("only")
                || string(row, "claim_boundary").contains("does not"),
            "{} must preserve a scoped claim boundary",
            string(row, "row_id")
        );
    }

    assert_eq!(
        json(READINESS_PATH).get("bead_id").and_then(Value::as_str),
        Some("asupersync-idea-wizard-fifth-wave-3gaiun.4.1")
    );
    assert_eq!(
        json(PACKAGE_GATE_PATH)
            .get("bead_id")
            .and_then(Value::as_str),
        Some("asupersync-idea-wizard-fifth-wave-3gaiun.4.2")
    );
    assert_eq!(
        json(CONSUMER_MATRIX_PATH)
            .get("bead_id")
            .and_then(Value::as_str),
        Some("asupersync-idea-wizard-fifth-wave-3gaiun.4.3")
    );
}

#[test]
fn package_versions_and_hashes_match_live_committed_package_files() {
    let artifact = signoff();
    let package_gate = json(PACKAGE_GATE_PATH);
    let gate_versions = array(&package_gate, "package_set")
        .iter()
        .map(|package| {
            (
                string(package, "name").to_owned(),
                string(package, "manifest_version").to_owned(),
            )
        })
        .collect::<BTreeMap<_, _>>();

    for package in array(&artifact, "package_versions") {
        let package_name = string(package, "package_name");
        let manifest_path = string(package, "manifest");
        assert_eq!(
            string(package, "version"),
            package_manifest_version(manifest_path),
            "{package_name} signoff version must match live manifest"
        );
        assert_eq!(
            Some(&string(package, "version").to_owned()),
            gate_versions.get(package_name),
            "{package_name} signoff version must match B2 package gate"
        );
        assert_eq!(
            string(package, "manifest_sha256"),
            sha256_file(manifest_path),
            "{package_name} manifest hash drifted"
        );

        let artifact_hashes = array(package, "artifact_hashes");
        assert!(
            !artifact_hashes.is_empty(),
            "{package_name} must record committed artifact hashes"
        );
        for hash in artifact_hashes {
            let path = string(hash, "path");
            assert_eq!(
                string(hash, "sha256"),
                sha256_file(path),
                "{package_name} artifact hash drifted for {path}"
            );
        }
    }
}

#[test]
fn support_classes_and_consumer_rows_preserve_preview_and_broker_boundaries() {
    let artifact = signoff();
    let readiness = json(READINESS_PATH);
    let consumer_matrix = json(CONSUMER_MATRIX_PATH);

    let readiness_classes = array(&readiness, "support_classes")
        .iter()
        .map(|class| string(class, "class_id").to_owned())
        .collect::<BTreeSet<_>>();
    let signoff_classes = array(&artifact, "support_class_table")
        .iter()
        .map(|class| string(class, "support_class").to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        signoff_classes, readiness_classes,
        "B4 support table must exactly mirror B1 support classes"
    );

    let mut green_consumers = 0usize;
    for row in array(&consumer_matrix, "consumer_matrix") {
        let support_class = string(row, "support_class");
        let green_for_ga = row["expected_outcome"]["green_for_ga"]
            .as_bool()
            .expect("green_for_ga");
        match support_class {
            "direct_runtime_supported" => {
                if green_for_ga {
                    green_consumers += 1;
                }
            }
            "preview_public_lane"
            | "broker_coordinator_only"
            | "bridge_only"
            | "impossible_unsupported" => assert!(
                !green_for_ga,
                "{} must not count as green JS/TS package GA",
                string(row, "consumer_id")
            ),
            other => panic!("unexpected support class {other}"),
        }
    }
    assert!(
        green_consumers >= 6,
        "B4 needs multiple direct-runtime JS/TS consumer rows"
    );

    let non_claims = string_set(&artifact, "non_claims");
    for required in [
        "does not promote Rust browser API from preview to stable",
        "does not promote service-worker direct runtime",
        "does not promote shared-worker direct runtime",
    ] {
        assert!(
            non_claims.contains(required),
            "missing non-claim {required}"
        );
    }
}

#[test]
fn rollback_drill_fail_closes_bad_package_abi_and_overclaim_mutations() {
    let artifact = signoff();
    let fixture = json(FIXTURE_PATH);
    assert_eq!(
        artifact["rollback_drill"]["fixture_path"].as_str(),
        Some(FIXTURE_PATH)
    );
    assert_eq!(
        fixture.get("schema_version").and_then(Value::as_str),
        Some("browser-ga-rollback-drill-v1")
    );
    assert_eq!(string(&fixture, "bead_id"), BEAD_ID);

    let required = string_set(&artifact["rollback_drill"], "required_scenarios");
    let actual = array(&fixture, "scenarios")
        .iter()
        .map(|scenario| string(scenario, "scenario_id").to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        actual, required,
        "rollback fixture must exactly cover signoff-required scenarios"
    );

    for scenario in array(&fixture, "scenarios") {
        let scenario_id = string(scenario, "scenario_id");
        assert!(
            !bool_field(scenario, "green_for_ga"),
            "{scenario_id} must fail closed for GA"
        );
        assert!(
            !string(scenario, "required_operator_note").is_empty(),
            "{scenario_id} needs an operator note"
        );
    }

    let by_id = array(&fixture, "scenarios")
        .iter()
        .map(|scenario| (string(scenario, "scenario_id").to_owned(), scenario))
        .collect::<BTreeMap<_, _>>();
    for package_blocker in ["bad_browser_core_wasm_digest", "abi_metadata_mismatch"] {
        assert_eq!(
            string(by_id[package_blocker], "expected_action"),
            "block_package_ga",
            "{package_blocker} must block package GA"
        );
    }
    assert_eq!(
        string(by_id["rust_preview_stable_overclaim"], "expected_action"),
        "reject_rust_stable_promotion"
    );
}

#[test]
fn proof_manifest_status_snapshot_and_docs_point_to_the_b4_signoff_lane() {
    let artifact = signoff();
    let manifest = json(MANIFEST_PATH);
    let snapshot = json(SNAPSHOT_PATH);
    let lanes = manifest_lanes(&manifest);
    let guarantees = manifest_guarantees(&manifest);
    let claims = snapshot_claims(&snapshot);

    let lane = lanes.get(LANE_ID).expect("manifest lane missing");
    assert_eq!(string(lane, "kind"), "artifact_contract");
    assert_eq!(string(lane, "command"), PROOF_COMMAND);
    assert_eq!(
        string_set(lane, "guarantee_ids"),
        BTreeSet::from([LANE_ID.to_owned()])
    );
    assert_remote_required_cargo(string(lane, "command"));
    for path in string_set(lane, "source_paths") {
        assert!(
            repo_path(&path).exists(),
            "manifest source path missing: {path}"
        );
    }

    let guarantee = guarantees.get(LANE_ID).expect("manifest guarantee missing");
    assert_eq!(
        string_set(guarantee, "lane_ids"),
        BTreeSet::from([LANE_ID.to_owned()])
    );

    let claim = claims.get(LANE_ID).expect("proof-status claim missing");
    assert_eq!(string(claim, "status"), "yellow_scoped");
    assert_eq!(string(claim, "proof_evidence_status"), "rerun-required");
    assert_eq!(
        string_set(claim, "manifest_lane_ids"),
        BTreeSet::from([LANE_ID.to_owned()])
    );
    assert_eq!(
        string_set(claim, "manifest_guarantee_ids"),
        BTreeSet::from([LANE_ID.to_owned()])
    );
    assert_eq!(
        string_set(claim, "proof_commands"),
        BTreeSet::from([PROOF_COMMAND.to_owned()])
    );

    assert_eq!(
        string(&artifact["signoff_lane"], "proof_command"),
        string(lane, "command")
    );

    let readme = read_repo_file(README_PATH);
    let report = read_repo_file(DOC_PATH);
    for marker in array(&artifact["docs_claim_freshness"], "required_readme_markers") {
        let marker = marker.as_str().expect("README marker");
        assert!(readme.contains(marker), "README missing marker {marker}");
    }
    for marker in array(&artifact["docs_claim_freshness"], "required_report_markers") {
        let marker = marker.as_str().expect("report marker");
        assert!(report.contains(marker), "B4 report missing marker {marker}");
    }
}

#[test]
fn deterministic_operator_report_preserves_scoped_non_claims() {
    let artifact = signoff();
    let report = &artifact["current_operator_report"];
    assert_eq!(string(report, "final_verdict"), "pass_scoped_js_ts_ga");
    assert_eq!(string(report, "release_channel"), "stable");
    assert_eq!(string(report, "first_failing_row"), "none");
    for field in [
        "owner_bead",
        "evidence_id",
        "artifact_sha256",
        "package_name",
        "package_version",
        "release_channel",
        "final_verdict",
    ] {
        assert!(
            string_set(report, "required_log_fields").contains(field),
            "operator report missing required log field {field}"
        );
    }

    let summary = string(report, "summary");
    for marker in [
        "JS/TS package GA",
        "npm publish",
        "full workspace health",
        "Rust browser stable parity",
        "service-worker direct runtime",
        "shared-worker direct runtime",
    ] {
        assert!(summary.contains(marker), "summary missing marker {marker}");
    }

    for source_row in array(&artifact, "source_evidence_rows") {
        for artifact_path in array(source_row, "artifact_paths") {
            let artifact_path = artifact_path.as_str().expect("artifact path string");
            let digest = sha256_file(artifact_path);
            assert_eq!(digest.len(), 64, "{artifact_path} sha256 must be hex");
        }
    }
}
