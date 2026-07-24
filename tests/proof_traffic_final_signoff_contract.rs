#![allow(missing_docs)]

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const SIGNOFF_PATH: &str = "artifacts/proof_traffic_final_signoff_v1.json";
const MANIFEST_PATH: &str = "artifacts/proof_lane_manifest_v1.json";
const MANIFEST_PROJECTION_PATH: &str =
    "tests/fixtures/proof_lane_manifest/manifest_projection.json";
const STATUS_PATH: &str = "artifacts/proof_status_snapshot_v1.json";
const README_PATH: &str = "README.md";
const AGENTS_PATH: &str = "AGENTS.md";
const DOC_PATH: &str = "docs/proof_traffic_control.md";
const BEAD_ID: &str = "asupersync-proof-traffic-control-kuyx64.6";
const LANE_ID: &str = "proof-traffic-final-signoff";
const GUARANTEE_ID: &str = "proof-traffic-final-signoff";
const CLAIM_ID: &str = "proof-traffic-final-signoff";
const CATEGORY: &str = "proof traffic final signoff";
const COMMAND: &str = "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_proof_traffic_final_signoff CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -p asupersync --test proof_traffic_final_signoff_contract -- --nocapture";

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

fn rows_by_id(value: &Value, array_key: &str, id_key: &str) -> BTreeMap<String, Value> {
    let mut rows = BTreeMap::new();
    for row in array(value, array_key) {
        let row_id = string(row, id_key).to_owned();
        assert!(
            rows.insert(row_id.clone(), row.clone()).is_none(),
            "duplicate {id_key} {row_id}"
        );
    }
    rows
}

fn required_no_claim_boundaries() -> BTreeSet<String> {
    BTreeSet::from([
        "does_not_prove_release_readiness".to_owned(),
        "does_not_prove_broad_workspace_health".to_owned(),
        "does_not_prove_runtime_correctness".to_owned(),
        "does_not_prove_performance_improvement".to_owned(),
        "does_not_prove_live_rch_fleet_availability".to_owned(),
        "does_not_prove_peer_dirt_exclusion_without_supported_capability_admitted_command_and_terminal_execution_evidence".to_owned(),
        "does_not_approve_local_cargo_fallback".to_owned(),
        "does_not_grant_peer_build_cancellation_authority".to_owned(),
        "does_not_grant_file_deletion_or_branch_worktree_permission".to_owned(),
    ])
}

#[test]
fn signoff_sources_child_rows_and_policy_are_bounded() {
    let signoff = repo_json(SIGNOFF_PATH);
    assert_eq!(
        signoff.get("schema_version").and_then(Value::as_str),
        Some("proof-traffic-final-signoff-v1")
    );
    assert_eq!(
        signoff.get("bead_id").and_then(Value::as_str),
        Some(BEAD_ID)
    );
    assert_eq!(
        signoff.get("status").and_then(Value::as_str),
        Some("contract_guarded")
    );
    assert_eq!(
        signoff.get("revised_at").and_then(Value::as_str),
        Some("2026-07-16T07:05:00Z")
    );

    for path in object(&signoff, "source_of_truth")
        .values()
        .map(|value| value.as_str().expect("source path string"))
    {
        assert_repo_file_exists(path);
    }

    let proof_lane = object(&signoff, "proof_lane");
    let proof_lane_value = Value::Object(proof_lane.clone());
    assert_eq!(string(&proof_lane_value, "lane_id"), LANE_ID);
    assert_eq!(string(&proof_lane_value, "guarantee_id"), GUARANTEE_ID);
    assert_eq!(string(&proof_lane_value, "status_claim_id"), CLAIM_ID);
    assert_eq!(string(&proof_lane_value, "command"), COMMAND);

    let children = array(&signoff, "child_evidence_rows");
    let child_ids = children
        .iter()
        .map(|child| string(child, "row_id").to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        child_ids,
        BTreeSet::from([
            "A1-capability-drift-gate".to_owned(),
            "A2-admission-receipts".to_owned(),
            "A3-clean-overlay-handshake".to_owned(),
            "A4-proof-parking-lot".to_owned(),
            "A5-blocked-loop-e2e".to_owned(),
        ])
    );

    for child in children {
        assert_eq!(string(child, "evidence_status"), "landed");
        assert_repo_file_exists(string(child, "primary_artifact"));
        assert_repo_file_exists(string(child, "contract_test"));
        assert!(
            !string(child, "current_interpretation").contains("release readiness"),
            "child interpretation should not widen proof scope"
        );
        let no_claims = string_set(child, "no_claim_boundaries");
        assert!(no_claims.len() >= 4);
        assert!(no_claims.iter().all(|claim| claim.starts_with("does_not_")));
        assert!(
            no_claims.contains("does_not_prove_live_rch_fleet_availability"),
            "child row must keep live RCH availability out of scope"
        );
    }

    let a3 = children
        .iter()
        .find(|child| string(child, "row_id") == "A3-clean-overlay-handshake")
        .expect("A3 child row");
    assert!(string(a3, "current_interpretation").contains("pre-execution handshake"));
    assert!(
        string_set(a3, "no_claim_boundaries")
            .contains("does_not_prove_peer_dirt_exclusion_without_terminal_execution_evidence")
    );

    let freshness = object(&signoff, "freshness_policy");
    let freshness_value = Value::Object(freshness.clone());
    assert_eq!(
        string(&freshness_value, "required_evidence_status_for_fresh_claim"),
        "fresh-rch-pass"
    );
    assert_eq!(
        string(&freshness_value, "current_signoff_evidence_status"),
        "rerun-required"
    );
    assert_eq!(
        string(&freshness_value, "fresh_claim_requires_exact_command"),
        COMMAND
    );
    assert!(!bool_field(&freshness_value, "local_fallback_allowed"));
    assert!(bool_field(
        &freshness_value,
        "live_fleet_state_is_operator_evidence_only"
    ));

    let checklist = array(&signoff, "operator_closeout_checklist")
        .iter()
        .map(|entry| entry.as_str().expect("checklist string"))
        .collect::<Vec<_>>()
        .join("\n")
        .to_ascii_lowercase();
    for required in [
        "remote-required rch",
        "br dep cycles",
        "no dependency cycles",
        "main:master",
        "do not cancel peer rch jobs",
        "local cargo fallback",
        "delete files",
        "create branches",
        "create worktrees",
        "scratch clones",
    ] {
        assert!(checklist.contains(required), "checklist missing {required}");
    }

    let rules = array(&signoff, "blocked_stale_interpretation_rules")
        .iter()
        .map(|entry| entry.as_str().expect("rule string"))
        .collect::<Vec<_>>()
        .join("\n")
        .to_ascii_lowercase();
    for required in [
        "handoff evidence",
        "capability-drift",
        "rerun-required",
        "not proof evidence",
        "dependency-cycle failure",
    ] {
        assert!(rules.contains(required), "rules missing {required}");
    }

    assert_eq!(
        string_set(&signoff, "no_claim_boundaries"),
        required_no_claim_boundaries()
    );
}

#[test]
fn manifest_projection_and_status_wire_final_signoff_lane() {
    let manifest = repo_json(MANIFEST_PATH);
    let projection = repo_json(MANIFEST_PROJECTION_PATH);
    let status = repo_json(STATUS_PATH);

    assert!(string_set(&manifest, "required_guarantee_ids").contains(GUARANTEE_ID));
    assert!(string_set(&projection, "required_guarantee_ids").contains(GUARANTEE_ID));

    let lanes = rows_by_id(&manifest, "lanes", "lane_id");
    let lane = lanes.get(LANE_ID).expect("manifest lane");
    assert_eq!(string(lane, "kind"), "artifact_contract");
    assert_eq!(
        string(lane, "resource_envelope_class"),
        "artifact-contract-medium"
    );
    assert_eq!(string(lane, "package"), "asupersync");
    assert_eq!(string(lane, "command"), COMMAND);
    assert_eq!(
        string(lane, "expected_signal"),
        "proof_traffic_final_signoff_contract tests pass"
    );
    assert_eq!(
        string_set(lane, "guarantee_ids"),
        BTreeSet::from([GUARANTEE_ID.to_owned()])
    );
    assert!(array(lane, "feature_flags").is_empty());
    assert!(string(lane, "command").starts_with("RCH_REQUIRE_REMOTE=1 rch exec -- env"));
    assert!(string(lane, "command").contains("rch_target_proof_traffic_final_signoff"));
    assert!(string(lane, "command").contains("proof_traffic_final_signoff_contract"));
    assert!(!string(lane, "command").contains("RCH_REQUIRE_REMOTE=0"));
    assert!(!string(lane, "command").contains("RCH_ALLOW_LOCAL"));
    assert!(!string(lane, "command").contains("rch exec -- cargo"));

    let source_paths = string_set(lane, "source_paths");
    for path in [
        SIGNOFF_PATH,
        "tests/proof_traffic_final_signoff_contract.rs",
        DOC_PATH,
        "artifacts/proof_traffic_rch_capabilities_v1.json",
        "tests/proof_traffic_rch_capability_contract.rs",
        "artifacts/proof_traffic_admission_receipts_v1.json",
        "tests/proof_traffic_admission_receipt_contract.rs",
        "artifacts/proof_traffic_clean_overlay_runner_handshake_v1.json",
        "tests/proof_traffic_clean_overlay_runner_handshake_contract.rs",
        "artifacts/proof_traffic_parking_lot_v1.json",
        "tests/proof_traffic_parking_lot_contract.rs",
        "artifacts/proof_traffic_blocked_loop_e2e_v1.json",
        "tests/proof_traffic_blocked_loop_e2e_contract.rs",
        MANIFEST_PATH,
        STATUS_PATH,
        MANIFEST_PROJECTION_PATH,
        README_PATH,
        AGENTS_PATH,
    ] {
        assert!(
            source_paths.contains(path),
            "lane source_paths missing {path}"
        );
        assert_repo_file_exists(path);
    }

    let explicit_not_covered = string(lane, "explicit_not_covered").to_ascii_lowercase();
    for required in [
        "release readiness",
        "broad workspace health",
        "runtime correctness",
        "performance improvement",
        "live rch fleet availability",
        "peer-dirt exclusion",
        "admitted command and terminal execution evidence",
        "local cargo fallback",
        "permission to delete files",
        "permission to cancel peer builds",
    ] {
        assert!(
            explicit_not_covered.contains(required),
            "explicit_not_covered missing {required}"
        );
    }

    let reuse_policy = object(lane, "proof_reuse_policy");
    let reuse_policy_value = Value::Object(reuse_policy.clone());
    assert!(bool_field(&reuse_policy_value, "cache_hits_allowed"));
    assert!(bool_field(
        &reuse_policy_value,
        "requires_fresh_rerun_when_dirty_overlap"
    ));
    assert!(string_set(&reuse_policy_value, "allowed_claim_scopes").contains(GUARANTEE_ID));
    assert!(
        string_set(&reuse_policy_value, "non_citeable_claim_scopes")
            .contains("local-cargo-fallback")
    );
    assert!(
        string_set(&reuse_policy_value, "non_citeable_claim_scopes")
            .contains("peer-build-cancellation")
    );
    assert!(
        string_set(&reuse_policy_value, "non_citeable_claim_scopes")
            .contains("peer-dirt-exclusion-without-supported-admitted-terminal-receipt")
    );

    let guarantees = rows_by_id(&manifest, "guarantees", "guarantee_id");
    assert_eq!(
        string_set(
            guarantees.get(GUARANTEE_ID).expect("manifest guarantee"),
            "lane_ids"
        ),
        BTreeSet::from([LANE_ID.to_owned()])
    );

    let projection_lanes = rows_by_id(&projection, "lanes", "lane_id");
    let projection_lane = projection_lanes.get(LANE_ID).expect("projection lane");
    assert_eq!(string(projection_lane, "command"), COMMAND);
    assert_eq!(string_set(projection_lane, "source_paths"), source_paths);
    let projection_guarantees = rows_by_id(&projection, "guarantees", "guarantee_id");
    assert_eq!(
        string_set(
            projection_guarantees
                .get(GUARANTEE_ID)
                .expect("projection guarantee"),
            "lane_ids",
        ),
        BTreeSet::from([LANE_ID.to_owned()])
    );

    assert!(string_set(&status, "required_claim_categories").contains(CATEGORY));
    let status_rows = rows_by_id(&status, "claim_categories", "claim_id");
    let row = status_rows.get(CLAIM_ID).expect("status row");
    assert_eq!(string(row, "category"), CATEGORY);
    assert_eq!(string(row, "status"), "yellow_scoped");
    assert_eq!(string(row, "proof_evidence_status"), "rerun-required");
    assert_eq!(
        string_set(row, "manifest_guarantee_ids"),
        BTreeSet::from([GUARANTEE_ID.to_owned()])
    );
    assert_eq!(
        string_set(row, "manifest_lane_ids"),
        BTreeSet::from([LANE_ID.to_owned()])
    );
    assert_eq!(
        string_set(row, "proof_commands"),
        BTreeSet::from([COMMAND.to_owned()])
    );
    assert!(row.get("blocked_frontier").is_some_and(Value::is_null));
    assert!(string(row, "notes").contains(
        "peer-dirt exclusion without supported capability evidence plus an admitted command and terminal execution evidence"
    ));
}

#[test]
fn docs_readme_agents_carry_exact_markers_and_boundaries() {
    let readme = read_repo_file(README_PATH);
    let agents = read_repo_file(AGENTS_PATH);
    let doc = read_repo_file(DOC_PATH);
    let status = repo_json(STATUS_PATH);
    let status_rows = rows_by_id(&status, "claim_categories", "claim_id");
    let row = status_rows.get(CLAIM_ID).expect("status row");
    let doc_markers = object(row, "doc_claim_markers");

    for (path, body) in [(README_PATH, &readme), (AGENTS_PATH, &agents)] {
        let markers = doc_markers
            .get(path)
            .and_then(Value::as_array)
            .unwrap_or_else(|| panic!("doc markers for {path}"));
        for marker in markers {
            let marker = marker.as_str().expect("marker string");
            assert!(body.contains(marker), "{path} missing marker {marker}");
        }
    }

    for body in [&readme, &agents] {
        let normalized_body = body.split_whitespace().collect::<Vec<_>>().join(" ");
        for required in [
            SIGNOFF_PATH,
            "tests/proof_traffic_final_signoff_contract.rs",
            DOC_PATH,
            LANE_ID,
            "capability-drift gate",
            "admission receipt",
            "clean-overlay handshake",
            "proof parking lot",
            "blocked-loop e2e",
            "no-local-fallback/no-peer-cancel",
            "dependency-cycle receipt/checklist",
            "peer-dirt exclusion without supported capability evidence plus an admitted command and terminal execution evidence",
            "release readiness",
            "broad workspace health",
            "runtime correctness",
            "performance improvement",
            "live RCH fleet availability",
            "local Cargo fallback approval",
            "permission to delete files",
            "permission to cancel peer builds",
        ] {
            assert!(
                normalized_body.contains(required),
                "top-level docs missing {required}"
            );
        }
    }

    let normalized_doc = doc.split_whitespace().collect::<Vec<_>>().join(" ");
    for required in [
        "Proof Traffic Control",
        "Proof-Traffic A6 Final Signoff",
        SIGNOFF_PATH,
        "tests/proof_traffic_final_signoff_contract.rs",
        LANE_ID,
        "capability-drift gate",
        "admission receipts",
        "clean-overlay handshake",
        "proof parking lot",
        "blocked-loop e2e",
        "No proof-traffic path authorizes local Cargo fallback or peer build cancellation.",
        "does not prove peer-dirt exclusion without supported capability evidence, an admitted command, and terminal execution evidence",
        "br dep cycles",
        "no dependency cycles",
        "release readiness",
        "broad workspace health",
        "runtime correctness",
        "performance improvement",
        "live RCH fleet availability",
        "local Cargo fallback approval",
        "permission to delete files",
        "cancel peer builds",
    ] {
        assert!(
            normalized_doc.contains(required),
            "{DOC_PATH} missing {required}"
        );
    }
}

#[test]
fn dependency_cycle_check_is_recorded_as_rerun_required_until_live_check() {
    let signoff = repo_json(SIGNOFF_PATH);
    let dependency_cycle_check = object(&signoff, "dependency_cycle_check");
    let dependency_cycle_check = Value::Object(dependency_cycle_check.clone());
    assert_eq!(string(&dependency_cycle_check, "command"), "br dep cycles");
    assert_eq!(
        string(&dependency_cycle_check, "expected_signal"),
        "no dependency cycles"
    );
    assert_eq!(
        string(&dependency_cycle_check, "result_status"),
        "rerun-required-before-parent-close"
    );
}
