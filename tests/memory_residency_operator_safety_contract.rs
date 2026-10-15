//! Contract tests for the memory-residency M5 operator safety packet.

#![allow(missing_docs)]

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const AGENTS_PATH: &str = "AGENTS.md";
const CONTRACT_PATH: &str = "artifacts/memory_residency_operator_safety_contract_v1.json";
const DOCS_PATH: &str = "docs/proof/memory_residency_operator_safety.md";
const MANIFEST_PATH: &str = "artifacts/proof_lane_manifest_v1.json";
const README_PATH: &str = "README.md";
const STATUS_PATH: &str = "artifacts/proof_status_snapshot_v1.json";

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

fn array<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value[key]
        .as_array()
        .unwrap_or_else(|| panic!("{key} array"))
        .as_slice()
}

fn string_field<'a>(value: &'a Value, key: &str) -> &'a str {
    let text = value[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} string"));
    assert!(!text.trim().is_empty(), "{key} must be nonempty");
    text
}

fn string_set(value: &Value, key: &str) -> BTreeSet<String> {
    array(value, key)
        .iter()
        .map(|entry| entry.as_str().expect("string entry").to_string())
        .collect()
}

fn row_map<'a>(rows: &'a [Value], key: &str) -> BTreeMap<&'a str, &'a Value> {
    rows.iter()
        .map(|row| (string_field(row, key), row))
        .collect()
}

fn find_by_id<'a>(rows: &'a [Value], key: &str, expected: &str) -> &'a Value {
    rows.iter()
        .find(|row| row.get(key).and_then(Value::as_str) == Some(expected))
        .unwrap_or_else(|| panic!("missing {key}={expected}"))
}

fn assert_contains_all(haystack: &str, needles: &[&str]) {
    for needle in needles {
        assert!(haystack.contains(needle), "missing {needle}");
    }
}

#[test]
fn contract_artifact_pins_sources_enablement_rollback_and_handoff() {
    let contract = json(CONTRACT_PATH);
    assert_eq!(
        string_field(&contract, "schema_version"),
        "memory-residency-operator-safety-contract-v1"
    );
    assert_eq!(
        string_field(&contract, "bead_id"),
        "asupersync-memory-residency-control-ho2itz.5"
    );
    assert_eq!(
        string_field(&contract, "parent_bead_id"),
        "asupersync-memory-residency-control-ho2itz"
    );
    assert_eq!(string_field(&contract, "status"), "contract_guarded");

    for path in [
        string_field(&contract["source_of_truth"], "contract"),
        string_field(&contract["source_of_truth"], "runbook"),
        string_field(&contract["source_of_truth"], "contract_test"),
        string_field(&contract["source_of_truth"], "readme"),
        string_field(&contract["source_of_truth"], "agent_instructions"),
        string_field(&contract["source_of_truth"], "proof_lane_manifest"),
        string_field(&contract["source_of_truth"], "proof_status_snapshot"),
        string_field(&contract["source_of_truth"], "m1_inventory"),
        string_field(&contract["source_of_truth"], "m2_policy"),
        string_field(&contract["source_of_truth"], "m3_accounting"),
        string_field(&contract["source_of_truth"], "m4_replay"),
    ] {
        assert!(repo_path(path).exists(), "{path} must exist");
    }

    assert_eq!(contract["enablement"]["default_off"].as_bool(), Some(true));
    assert_eq!(
        contract["rollback"]["restart_required"].as_bool(),
        Some(false)
    );
    assert_contains_all(
        string_field(&contract["enablement"], "operator_decision_rule"),
        &["missing", "stale", "unknown", "disabled policy"],
    );
    assert_eq!(
        string_field(&contract["agent_mail_handoff_template"], "thread_id"),
        "asupersync-memory-residency-control-ho2itz.5"
    );
    let handoff_fields = string_set(
        &contract["agent_mail_handoff_template"],
        "body_required_fields",
    );
    for field in [
        "gate_id",
        "status",
        "proof_command",
        "rch_worker_or_refusal",
        "dirty_frontier",
        "rollback_action",
        "no_claim_boundaries",
    ] {
        assert!(
            handoff_fields.contains(field),
            "missing handoff field {field}"
        );
    }
}

#[test]
fn safety_gates_fail_closed_for_m1_through_m4_and_local_fallback() {
    let contract = json(CONTRACT_PATH);
    let gates = row_map(array(&contract, "safety_gates"), "gate_id");
    let required = [
        (
            "m1_inventory_fresh",
            "artifacts/memory_residency_inventory_v1.json",
            "memory-residency-inventory-v1",
        ),
        (
            "m2_policy_known",
            "artifacts/memory_residency_policy_contract_v1.json",
            "memory-residency-policy-contract-v1",
        ),
        (
            "m3_accounting_available",
            "artifacts/memory_residency_accounting_snapshot_v1.json",
            "memory-residency-accounting-snapshot-contract-v1",
        ),
        (
            "m4_replay_artifacts_fresh",
            "artifacts/memory_residency_replay_e2e_contract_v1.json",
            "memory-residency-replay-e2e-contract-v1",
        ),
        (
            "no_local_cargo_fallback",
            "artifacts/proof_lane_manifest_v1.json",
            "proof-lane-manifest-v1",
        ),
    ];
    assert_eq!(gates.len(), required.len());

    for (gate_id, source, schema) in required {
        let gate = gates
            .get(gate_id)
            .unwrap_or_else(|| panic!("missing gate {gate_id}"));
        assert_eq!(string_field(gate, "required_source"), source);
        assert_eq!(string_field(gate, "required_schema"), schema);
        assert_eq!(gate["fail_closed"].as_bool(), Some(true));
        assert!(
            array(gate, "fail_closed_if").len() >= 3,
            "{gate_id}: fail_closed_if must name concrete inputs"
        );
        assert!(
            string_field(gate, "operator_message").contains("disabled")
                || string_field(gate, "operator_message").contains("unavailable")
                || string_field(gate, "operator_message").contains("Local Cargo"),
            "{gate_id}: operator message must guide fail-closed behavior"
        );
        assert!(
            string_field(gate, "rollback_action").contains("RCH")
                || string_field(gate, "rollback_action").contains("default")
                || string_field(gate, "rollback_action").contains("unified allocation"),
            "{gate_id}: rollback action must name a safe path"
        );
    }

    let m4 = json("artifacts/memory_residency_replay_e2e_contract_v1.json");
    assert_eq!(
        m4["benchmark_evidence"]["included"].as_bool(),
        Some(false),
        "M5 must not convert M4 replay evidence into benchmark evidence"
    );
}

#[test]
fn runbook_and_docs_preserve_no_claim_boundaries() {
    let contract = json(CONTRACT_PATH);
    let docs = read_repo_file(DOCS_PATH);
    let readme = read_repo_file(README_PATH);
    let agents = read_repo_file(AGENTS_PATH);

    assert_contains_all(
        &docs,
        &[
            CONTRACT_PATH,
            "memory-residency-operator-safety-contract",
            "RCH_REQUIRE_REMOTE=1 rch exec -- env",
            "default-off",
            "Rollback",
            "Incident Checklist",
            "Agent Mail Handoff",
            "No-Claim Boundaries",
            "no permission to delete files",
            "local Cargo fallback",
        ],
    );
    assert_contains_all(
        &readme,
        &[
            "memory-residency operator safety contract",
            CONTRACT_PATH,
            "memory-residency-operator-safety-contract",
        ],
    );
    assert_contains_all(
        &agents,
        &[
            "memory-residency operator safety contract",
            CONTRACT_PATH,
            "memory-residency-operator-safety-contract",
        ],
    );

    let no_claims = string_set(&contract, "no_claim_boundaries");
    for boundary in [
        "No permission to delete files, clean worktrees, create branches, or create worktrees.",
        "No release-readiness claim.",
        "No broad workspace-health claim.",
        "No local Cargo fallback approval.",
    ] {
        assert!(no_claims.contains(boundary), "missing boundary {boundary}");
    }
}

#[test]
fn proof_manifest_and_status_snapshot_map_operator_safety_without_overclaiming() {
    let contract = json(CONTRACT_PATH);
    let manifest = json(MANIFEST_PATH);
    let status = json(STATUS_PATH);
    let command = string_field(&contract["proof_lane"], "command");

    assert!(
        string_set(&manifest, "required_guarantee_ids")
            .contains("memory-residency-operator-safety-contract")
    );
    let lane = find_by_id(
        array(&manifest, "lanes"),
        "lane_id",
        "memory-residency-operator-safety-contract",
    );
    assert_eq!(lane["kind"].as_str(), Some("artifact_contract"));
    assert_eq!(
        lane["resource_envelope_class"].as_str(),
        Some("artifact-contract-medium")
    );
    assert_eq!(lane["command"].as_str(), Some(command));
    assert!(string_set(lane, "source_paths").contains(CONTRACT_PATH));
    assert!(string_set(lane, "source_paths").contains(DOCS_PATH));
    assert!(string_set(lane, "source_paths").contains(README_PATH));
    assert!(string_set(lane, "source_paths").contains(AGENTS_PATH));
    for forbidden in [
        "release-readiness",
        "workspace-health",
        "runtime-correctness",
        "live-rch-fleet-availability",
        "performance-improvement",
        "local-cargo-fallback",
    ] {
        assert!(
            string_set(&lane["proof_reuse_policy"], "non_citeable_claim_scopes")
                .contains(forbidden),
            "missing non-citeable scope {forbidden}"
        );
    }

    let guarantee = find_by_id(
        array(&manifest, "guarantees"),
        "guarantee_id",
        "memory-residency-operator-safety-contract",
    );
    assert!(
        string_set(guarantee, "lane_ids").contains("memory-residency-operator-safety-contract")
    );

    assert!(
        string_set(&status, "required_claim_categories")
            .contains("memory residency operator safety contract")
    );
    let claim = find_by_id(
        array(&status, "claim_categories"),
        "claim_id",
        "memory-residency-operator-safety-contract",
    );
    assert_eq!(
        claim["category"].as_str(),
        Some("memory residency operator safety contract")
    );
    assert_eq!(claim["status"].as_str(), Some("yellow_scoped"));
    assert_eq!(
        claim["proof_evidence_status"].as_str(),
        Some("rerun-required")
    );
    assert!(claim["blocked_frontier"].is_null());
    assert!(
        string_set(claim, "manifest_lane_ids")
            .contains("memory-residency-operator-safety-contract")
    );
    assert!(
        string_field(claim, "notes").contains("does not prove broad workspace health")
            && string_field(claim, "notes").contains("local Cargo fallback")
    );
}
