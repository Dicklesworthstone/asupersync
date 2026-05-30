#![allow(missing_docs)]

use asupersync::lab::{
    SWARM_PROOF_LANE_PLAN_SCHEMA_VERSION, SwarmProofLaneDecision, SwarmProofLaneFallbackPolicy,
    SwarmProofLanePlan, SwarmProofLaneRequest, plan_swarm_proof_lane,
    render_swarm_proof_lane_agent_mail_summary,
};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const ARTIFACT_PATH: &str = "artifacts/swarm_proof_lane_planner_contract_v1.json";

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn contract() -> Value {
    let raw = std::fs::read_to_string(repo_path(ARTIFACT_PATH))
        .unwrap_or_else(|error| panic!("read {ARTIFACT_PATH}: {error}"));
    serde_json::from_str(&raw).unwrap_or_else(|error| panic!("parse {ARTIFACT_PATH}: {error}"))
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

fn lane_rows(contract: &Value) -> BTreeMap<String, &Value> {
    array(contract, "lanes")
        .iter()
        .map(|row| (string(row, "lane_id").to_string(), row))
        .collect()
}

fn parse_request(row: &Value) -> SwarmProofLaneRequest {
    serde_json::from_value(
        row.get("planner_request")
            .unwrap_or_else(|| panic!("{} missing planner_request", string(row, "lane_id")))
            .clone(),
    )
    .unwrap_or_else(|error| panic!("parse planner_request {}: {error}", string(row, "lane_id")))
}

fn finding_codes(plan: &SwarmProofLanePlan) -> BTreeSet<String> {
    plan.findings
        .iter()
        .map(|finding| finding.code.clone())
        .collect()
}

#[test]
fn artifact_declares_source_schema_and_planner_boundary() {
    let contract = contract();
    assert_eq!(
        contract["contract_version"].as_str(),
        Some("swarm-proof-lane-planner-v1")
    );
    assert_eq!(contract["bead_id"].as_str(), Some("asupersync-vssefs.9.2"));
    assert_eq!(
        contract["schema_version"].as_str(),
        Some(SWARM_PROOF_LANE_PLAN_SCHEMA_VERSION)
    );

    let source = contract
        .get("source_of_truth")
        .expect("source_of_truth object");
    for key in ["contract", "contract_test", "runtime_planner_source"] {
        let path = string(source, key);
        assert!(
            repo_path(path).exists(),
            "source_of_truth.{key} must point to a live repo file: {path}"
        );
    }
    assert_eq!(
        string(source, "runtime_request_type"),
        "asupersync::lab::SwarmProofLaneRequest"
    );
    assert_eq!(
        string(source, "runtime_plan_type"),
        "asupersync::lab::SwarmProofLanePlan"
    );
    assert_eq!(
        string(source, "runtime_planner"),
        "asupersync::lab::plan_swarm_proof_lane"
    );
}

#[test]
fn focused_scenario_fixture_maps_to_remote_only_proof_lane() {
    let contract = contract();
    let rows = lane_rows(&contract);
    let request = parse_request(
        rows.get("swarm-workload-corpus-focused")
            .expect("focused lane fixture"),
    );
    let plan = plan_swarm_proof_lane(&request);

    assert_eq!(plan.schema_version, SWARM_PROOF_LANE_PLAN_SCHEMA_VERSION);
    assert_eq!(plan.lane_id, "swarm-workload-corpus-focused");
    assert_eq!(plan.scenario_id, "swarm-minimal-healthy-run");
    assert_eq!(plan.decision, SwarmProofLaneDecision::Ready);
    assert_eq!(
        plan.fallback_policy,
        SwarmProofLaneFallbackPolicy::RemoteOnly
    );
    assert!(plan.findings.is_empty(), "findings: {:?}", plan.findings);
    assert!(plan.remote_required);
    assert!(plan.remote_provenance_observed);
    assert!(!plan.local_fallback_marker_detected);
    assert!(!plan.stale_head);
    assert!(!plan.missing_target_dir);
    assert_eq!(plan.features, vec!["test-internals"]);
    assert!(
        plan.command.contains("RCH_REQUIRE_REMOTE=1 rch exec --"),
        "published proof command must require remote RCH execution"
    );
    assert!(
        plan.command
            .contains("swarm_workload_scenario_corpus_contract"),
        "focused lane must prove the scenario DSL corpus contract"
    );
    assert!(
        plan.covers
            .contains(&"scenario_schema_validation".to_string()),
        "lane must declare its positive proof claim"
    );
    assert!(
        plan.does_not_cover
            .contains(&"workspace_release_health".to_string()),
        "lane must avoid broad release-health claims"
    );
    assert!(!plan.mutates_external_state);
    assert!(!plan.destructive_cleanup_required);
    assert!(!plan.branch_or_worktree_required);

    let rendered = render_swarm_proof_lane_agent_mail_summary(&plan);
    assert_eq!(rendered, plan.agent_mail_summary);
    for expected in [
        "proof_lane: swarm-workload-corpus-focused",
        "remote_required=true remote_observed=true",
        "does_not_cover: broad_conformance,workspace_release_health",
        "command: RCH_REQUIRE_REMOTE=1 rch exec --",
    ] {
        assert!(rendered.contains(expected), "summary missing {expected:?}");
    }
    assert!(
        rendered.contains("covers:") && rendered.contains("scenario_schema_validation"),
        "summary must include the scenario_schema_validation cover claim"
    );

    let roundtrip: SwarmProofLanePlan =
        serde_json::from_str(&serde_json::to_string(&plan).expect("render plan"))
            .expect("parse rendered plan");
    assert_eq!(roundtrip, plan);
}

#[test]
fn malformed_lanes_fail_closed_with_specific_findings() {
    let contract = contract();
    for row in array(&contract, "malformed_examples") {
        let request = parse_request(row);
        let plan = plan_swarm_proof_lane(&request);
        let expected = string(row, "expected_finding_code");
        assert_ne!(
            plan.decision,
            SwarmProofLaneDecision::Ready,
            "{} must not be accepted",
            string(row, "lane_id")
        );
        assert!(
            finding_codes(&plan).contains(expected),
            "{} expected finding {expected:?}, got {:?}",
            string(row, "lane_id"),
            plan.findings
        );
    }
}

#[test]
fn batching_is_stable_for_compatible_lanes_and_sensitive_to_features() {
    let contract = contract();
    let rows = lane_rows(&contract);
    let request = parse_request(
        rows.get("swarm-workload-corpus-focused")
            .expect("focused lane fixture"),
    );
    let first = plan_swarm_proof_lane(&request);

    let mut compatible = request.clone();
    compatible.lane_id = "swarm-workload-corpus-focused-replay".to_string();
    compatible
        .expected_artifacts
        .push("target/lab-replay/swarm-workload/extra-proof-copy.json".to_string());
    let second = plan_swarm_proof_lane(&compatible);
    assert_eq!(
        first.batch_key, second.batch_key,
        "lanes with the same target, features, and surfaces should batch together"
    );

    let mut incompatible = request;
    incompatible.lane_id = "swarm-workload-corpus-kafka-feature".to_string();
    incompatible.features = vec!["kafka".to_string()];
    incompatible.command = incompatible
        .command
        .replace("--features test-internals", "--features kafka");
    let third = plan_swarm_proof_lane(&incompatible);
    assert_ne!(
        first.batch_key, third.batch_key,
        "feature changes must split proof-lane batches"
    );
}

#[test]
fn schema_fields_are_source_backed_and_plan_serializes_stably() {
    let contract = contract();
    let source_path = string(&contract["source_of_truth"], "runtime_planner_source");
    let source = std::fs::read_to_string(repo_path(source_path))
        .unwrap_or_else(|error| panic!("read {source_path}: {error}"));
    for token in [
        "SWARM_PROOF_LANE_PLAN_SCHEMA_VERSION",
        "pub struct SwarmProofLaneRequest",
        "pub struct SwarmProofLanePlan",
        "pub fn plan_swarm_proof_lane",
        "pub fn render_swarm_proof_lane_agent_mail_summary",
    ] {
        assert!(source.contains(token), "planner source missing {token}");
    }

    let plan_fields = string_set(&contract["schema"], "required_plan_fields");
    let rows = lane_rows(&contract);
    let request = parse_request(
        rows.get("swarm-workload-corpus-focused")
            .expect("focused lane fixture"),
    );
    let value = serde_json::to_value(plan_swarm_proof_lane(&request)).expect("plan to JSON");
    let object = value.as_object().expect("plan JSON object");
    for field in plan_fields {
        assert!(object.contains_key(&field), "plan JSON missing {field}");
    }

    let reject_codes = string_set(&contract["schema"], "reject_finding_codes");
    for expected in [
        "missing_rch_provenance",
        "local_fallback_marker",
        "stale_head",
        "missing_target_dir",
        "missing_feature_scope",
    ] {
        assert!(
            reject_codes.contains(expected),
            "schema reject codes missing {expected}"
        );
    }
}
