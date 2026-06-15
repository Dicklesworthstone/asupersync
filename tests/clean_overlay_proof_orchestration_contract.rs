//! Contract tests for the clean-overlay proof-orchestration A4 operator packet.
//!
//! This pins the operator runbook, contract artifact, canonical proof
//! manifest/status rows, and README/AGENTS markers for the shared-`main`
//! clean-overlay proof lane (PROOF-ORCH A4, `asupersync-proof-orch-clean-overlay-5ve2ao.4`).
//! It verifies the packet documents prerequisites, command examples, reservation
//! expectations, stale-progress cancellation guidance, peer-dirty blocker
//! receipts, non-destructive cleanup/rollback, Agent Mail and `br` comment
//! handoff templates, and honest no-claim boundaries — without overclaiming.

#![allow(missing_docs)]

use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const AGENTS_PATH: &str = "AGENTS.md";
const CONTRACT_PATH: &str = "artifacts/clean_overlay_proof_orchestration_v1.json";
const DOCS_PATH: &str = "docs/clean_overlay_proof_orchestration_runbook.md";
const MANIFEST_PATH: &str = "artifacts/proof_lane_manifest_v1.json";
const README_PATH: &str = "README.md";
const STATUS_PATH: &str = "artifacts/proof_status_snapshot_v1.json";
const LANE_ID: &str = "clean-overlay-proof-orchestration-contract";
const CATEGORY: &str = "clean-overlay proof orchestration contract";

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

/// The single canonical command shared by the artifact, manifest lane, status
/// claim, and the runbook. Defining it once keeps every surface byte-identical.
fn canonical_command() -> String {
    let contract = json(CONTRACT_PATH);
    string_field(&contract["proof_lane"], "command").to_string()
}

#[test]
fn contract_artifact_pins_sources_lane_templates_and_boundaries() {
    let contract = json(CONTRACT_PATH);
    assert_eq!(
        string_field(&contract, "schema_version"),
        "clean-overlay-proof-orchestration-contract-v1"
    );
    assert_eq!(
        string_field(&contract, "bead_id"),
        "asupersync-proof-orch-clean-overlay-5ve2ao.4"
    );
    assert_eq!(
        string_field(&contract, "parent_bead_id"),
        "asupersync-proof-orch-clean-overlay-5ve2ao"
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
        string_field(&contract["source_of_truth"], "a1_planner"),
        string_field(&contract["source_of_truth"], "a1_planner_contract"),
        string_field(&contract["source_of_truth"], "a2_blocker_receipt"),
        string_field(&contract["source_of_truth"], "a3_overlay_command"),
        string_field(&contract["source_of_truth"], "a3_focused_e2e"),
    ] {
        assert!(repo_path(path).exists(), "{path} must exist");
    }

    assert_eq!(string_field(&contract["proof_lane"], "lane_id"), LANE_ID);

    // Fail-closed / non-destructive posture is pinned, not aspirational.
    let stale = &contract["stale_progress_guidance"];
    assert_eq!(
        stale["never_cancel_peer_owned_builds"].as_bool(),
        Some(true)
    );
    assert_eq!(
        stale["stale_or_partial_job_is_rerun_required_not_passed"].as_bool(),
        Some(true)
    );
    let blocker = &contract["peer_dirty_blocker"];
    assert_eq!(
        blocker["blocked_manifest_is_never_admitted"].as_bool(),
        Some(true)
    );
    assert_eq!(
        blocker["blocked_emits_no_cargo_invocation"].as_bool(),
        Some(true)
    );
    let cleanup = &contract["non_destructive_cleanup"];
    assert_eq!(cleanup["performs_no_io"].as_bool(), Some(true));
    assert_eq!(
        cleanup["never_branches_clones_worktrees_or_deletes"].as_bool(),
        Some(true)
    );

    // AC4: Agent Mail + br comment handoff templates with required fields.
    assert_eq!(
        string_field(&contract["agent_mail_handoff_template"], "thread_id"),
        "asupersync-proof-orch-clean-overlay-5ve2ao.4"
    );
    let handoff = string_set(
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
        assert!(handoff.contains(field), "missing handoff field {field}");
    }
    let br_fields = string_set(
        &contract["br_comment_handoff_template"],
        "body_required_fields",
    );
    for field in ["status", "proof_command", "no_claim_boundaries"] {
        assert!(
            br_fields.contains(field),
            "missing br comment field {field}"
        );
    }

    // AC5: no-claim boundaries are explicit and honest.
    let no_claims = string_set(&contract, "no_claim_boundaries");
    for boundary in [
        "No release-readiness claim.",
        "No broad workspace-health claim.",
        "No performance-improvement claim.",
        "No live RCH fleet-availability claim.",
        "No local Cargo fallback approval.",
        "No permission to delete files, clean worktrees, create branches, or create worktrees.",
    ] {
        assert!(no_claims.contains(boundary), "missing boundary {boundary}");
    }
}

#[test]
fn runbook_documents_prereqs_commands_reservations_and_handoffs() {
    let docs = read_repo_file(DOCS_PATH);
    let command = canonical_command();
    assert_contains_all(
        &docs,
        &[
            // self-referential source-of-truth surfaces
            CONTRACT_PATH,
            DOCS_PATH,
            "tests/clean_overlay_proof_orchestration_contract.rs",
            "src/audit/clean_overlay_planner.rs",
            "src/audit/blocker_receipt.rs",
            "src/audit/overlay_proof_command.rs",
            "tests/proof_orch_clean_overlay_e2e.rs",
            // AC1: required runbook sections
            "## Prerequisites",
            "## Command examples",
            "## Reservation expectations",
            "## Stale-progress cancellation guidance",
            "## Peer-dirty blocker receipts",
            "## Non-destructive cleanup and rollback",
            // AC4: handoff templates
            "## Agent Mail handoff template",
            "## br comment handoff template",
            "file_reservation_paths",
            "renew_file_reservations",
            "release_file_reservations",
            "br comments add asupersync-proof-orch-clean-overlay-5ve2ao.4",
            // AC5: no-claim boundaries section
            "## No-claim boundaries",
            // exact command
            &command,
            // peer-dirty blocker receipt lines
            "# BLOCKED: clean-overlay refused; no RCH proof command emitted",
            "# REPORT-ONLY: clean-overlay dry run; no RCH proof command emitted",
            // AGENTS alignment + no-local-fallback language
            "Main only — no branches, no worktrees, no scratch clones, no destructive cleanup.",
            "No local Cargo fallback",
            "RCH_REQUIRE_REMOTE=1",
        ],
    );
}

#[test]
fn runbook_preserves_stale_progress_wording() {
    let docs = read_repo_file(DOCS_PATH);
    assert_contains_all(
        &docs,
        &[
            "heartbeat-fresh",
            "progress-stale",
            "never_cancel_peer_owned_builds",
            "Do **not** cancel a peer-owned build",
            "rerun-required",
        ],
    );
}

#[test]
fn readme_and_agents_carry_the_clean_overlay_markers() {
    let readme = read_repo_file(README_PATH);
    let agents = read_repo_file(AGENTS_PATH);
    for doc in [&readme, &agents] {
        assert_contains_all(doc, &[CATEGORY, LANE_ID, CONTRACT_PATH]);
    }
}

#[test]
fn proof_manifest_maps_the_lane_to_its_guarantee_without_overclaiming() {
    let contract = json(CONTRACT_PATH);
    let manifest = json(MANIFEST_PATH);
    let command = canonical_command();

    // Artifact's declared manifest row matches the canonical manifest.
    let row = &contract["proof_manifest_row"];
    assert_eq!(string_field(row, "manifest_lane_id"), LANE_ID);
    assert_eq!(string_field(row, "kind"), "artifact_contract");
    assert_eq!(
        string_field(row, "resource_envelope_class"),
        "artifact-contract-medium"
    );

    assert!(string_set(&manifest, "required_guarantee_ids").contains(LANE_ID));
    let lane = find_by_id(array(&manifest, "lanes"), "lane_id", LANE_ID);
    assert_eq!(lane["kind"].as_str(), Some("artifact_contract"));
    assert_eq!(
        lane["resource_envelope_class"].as_str(),
        Some("artifact-contract-medium")
    );
    assert_eq!(lane["command"].as_str(), Some(command.as_str()));
    let source_paths = string_set(lane, "source_paths");
    for required in [CONTRACT_PATH, DOCS_PATH, README_PATH, AGENTS_PATH] {
        assert!(source_paths.contains(required), "lane missing {required}");
    }
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

    let guarantee = find_by_id(array(&manifest, "guarantees"), "guarantee_id", LANE_ID);
    assert!(string_set(guarantee, "lane_ids").contains(LANE_ID));
}

#[test]
fn proof_status_snapshot_maps_the_claim_as_yellow_scoped() {
    let contract = json(CONTRACT_PATH);
    let status = json(STATUS_PATH);
    let command = canonical_command();

    let row = &contract["proof_status_row"];
    assert_eq!(string_field(row, "claim_id"), LANE_ID);
    assert_eq!(string_field(row, "category"), CATEGORY);
    assert_eq!(string_field(row, "status"), "yellow_scoped");
    assert_eq!(string_field(row, "proof_evidence_status"), "rerun-required");

    assert!(string_set(&status, "required_claim_categories").contains(CATEGORY));
    let claim = find_by_id(array(&status, "claim_categories"), "claim_id", LANE_ID);
    assert_eq!(claim["category"].as_str(), Some(CATEGORY));
    assert_eq!(claim["status"].as_str(), Some("yellow_scoped"));
    assert_eq!(
        claim["proof_evidence_status"].as_str(),
        Some("rerun-required")
    );
    assert!(claim["blocked_frontier"].is_null());
    assert!(string_set(claim, "manifest_lane_ids").contains(LANE_ID));
    assert!(string_set(claim, "manifest_guarantee_ids").contains(LANE_ID));
    assert!(string_set(claim, "proof_commands").contains(&command));
    let notes = string_field(claim, "notes");
    assert!(
        notes.contains("does not prove broad workspace health")
            && notes.contains("local Cargo fallback"),
        "status notes must keep the no-claim boundaries"
    );
}
