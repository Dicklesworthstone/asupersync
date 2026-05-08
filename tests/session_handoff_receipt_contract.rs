//! Contract tests for the shared-main session handoff receipt helper.

#![allow(missing_docs)]

use serde_json::Value;
use std::path::PathBuf;
use std::process::{Command, Output};

const SCRIPT_PATH: &str = "scripts/session_handoff_receipt.py";
const FIXTURE_ROOT: &str = "tests/fixtures/session_handoff_receipt";
const GENERATED_AT: &str = "2026-05-08T04:30:00Z";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn run_receipt(fixture: &str) -> Output {
    Command::new("python3")
        .arg(repo_root().join(SCRIPT_PATH))
        .arg("--fixture")
        .arg(repo_root().join(FIXTURE_ROOT).join(fixture))
        .arg("--repo-path")
        .arg(repo_root())
        .arg("--agent")
        .arg("CopperSpring")
        .arg("--generated-at")
        .arg(GENERATED_AT)
        .current_dir(repo_root())
        .output()
        .expect("run session handoff receipt script")
}

fn receipt_json(fixture: &str) -> Value {
    let output = run_receipt(fixture);
    if !output.status.success() {
        panic!(
            "receipt helper failed: {}\nstdout: {}\nstderr: {}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str(&stdout)
        .unwrap_or_else(|error| panic!("receipt output not JSON: {error}\noutput: {stdout}"))
}

fn fixture_text(fixture: &str) -> String {
    std::fs::read_to_string(repo_root().join(FIXTURE_ROOT).join(fixture))
        .unwrap_or_else(|error| panic!("read golden fixture {fixture}: {error}"))
}

fn next_action_category(receipt: &Value) -> &str {
    receipt["next_action"]["category"]
        .as_str()
        .expect("next_action.category must be a string")
}

#[test]
fn script_exists_and_help_is_non_mutating() {
    assert!(
        repo_root().join(SCRIPT_PATH).exists(),
        "receipt helper must exist at {SCRIPT_PATH}"
    );
    let output = Command::new("python3")
        .arg(repo_root().join(SCRIPT_PATH))
        .arg("--help")
        .current_dir(repo_root())
        .output()
        .expect("run helper --help");
    assert!(output.status.success(), "--help should succeed");
}

#[test]
fn clean_tree_recommends_claiming_ready_bead() {
    let receipt = receipt_json("clean_tree.json");
    assert_eq!(
        receipt["schema_version"].as_str(),
        Some("session-handoff-receipt-v1")
    );
    assert_eq!(receipt["generated_at"].as_str(), Some(GENERATED_AT));
    assert_eq!(receipt["agent"].as_str(), Some("CopperSpring"));
    assert_eq!(receipt["branch"]["current"].as_str(), Some("main"));
    assert_eq!(receipt["branch"]["is_main"].as_bool(), Some(true));
    assert_eq!(next_action_category(&receipt), "claim-ready-bead");
    assert_eq!(
        receipt["next_action"]["bead_id"].as_str(),
        Some("asupersync-ready1")
    );
}

#[test]
fn clean_tree_output_matches_full_reviewed_golden() {
    let output = run_receipt("clean_tree.json");
    assert!(
        output.status.success(),
        "receipt helper failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert_eq!(
        String::from_utf8(output.stdout).expect("receipt stdout is utf-8"),
        fixture_text("clean_tree_expected.json"),
        "clean_tree receipt drifted from the reviewed golden"
    );
}

#[test]
fn dirty_peer_owned_tree_recommends_avoiding_surface() {
    let receipt = receipt_json("dirty_peer_owned_tree.json");
    assert_eq!(next_action_category(&receipt), "avoid-peer-owned-surface");
    assert_eq!(
        receipt["next_action"]["path"].as_str(),
        Some("src/channel/mod.rs")
    );
    let clusters = receipt["dirty_clusters"]
        .as_array()
        .expect("dirty_clusters must be array");
    assert_eq!(clusters.len(), 1);
    assert_eq!(
        clusters[0]["cluster"].as_str(),
        Some("peer-owned/channel-metamorphic")
    );
    assert_eq!(
        receipt["proof_suggestions"]
            .as_array()
            .expect("proof_suggestions must be array")
            .first()
            .and_then(Value::as_str),
        Some("rustfmt-check")
    );
}

#[test]
fn dirty_peer_owned_tree_output_matches_full_reviewed_golden() {
    let output = run_receipt("dirty_peer_owned_tree.json");
    assert!(
        output.status.success(),
        "receipt helper failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert_eq!(
        String::from_utf8(output.stdout).expect("receipt stdout is utf-8"),
        fixture_text("dirty_peer_owned_tree_expected.json"),
        "dirty_peer_owned_tree receipt drifted from the reviewed golden"
    );
}

#[test]
fn tracker_reservation_conflict_waits_before_claiming() {
    let receipt = receipt_json("tracker_reservation_conflict.json");
    assert_eq!(next_action_category(&receipt), "wait-for-reservation");
    assert_eq!(
        receipt["next_action"]["path_pattern"].as_str(),
        Some(".beads/issues.jsonl")
    );
    assert_eq!(receipt["next_action"]["holder"].as_str(), Some("BlackDove"));
    let conflicts = receipt["reservation_conflicts"]
        .as_array()
        .expect("reservation_conflicts must be array");
    assert_eq!(conflicts.len(), 1);
    assert_eq!(
        conflicts[0]["classification"].as_str(),
        Some("tracker-conflict")
    );
}

#[test]
fn unavailable_agent_mail_is_explicitly_reported() {
    let receipt = receipt_json("no_agent_mail.json");
    assert_eq!(next_action_category(&receipt), "blocked");
    assert_eq!(
        receipt["reservation_snapshot"]["available"].as_bool(),
        Some(false)
    );
    assert_eq!(
        receipt["subsystems"]["agent_mail"].as_str(),
        Some("unavailable")
    );
}

#[test]
fn stale_in_progress_candidate_is_listed_without_mutation() {
    let receipt = receipt_json("stale_in_progress.json");
    assert_eq!(next_action_category(&receipt), "proof-only");
    let stale = receipt["active_bead_ids"]["stale_in_progress"]
        .as_array()
        .expect("stale_in_progress must be array");
    assert_eq!(stale.len(), 1);
    assert_eq!(stale[0]["id"].as_str(), Some("asupersync-stale1"));
    assert_eq!(stale[0]["assignee"].as_str(), Some("OlderAgent"));
    assert!(
        stale[0]["age_hours"]
            .as_f64()
            .expect("age_hours must be numeric")
            >= 24.0
    );
}

#[test]
fn receipt_has_required_top_level_shape() {
    let receipt = receipt_json("clean_tree.json");
    for field in [
        "schema_version",
        "generated_at",
        "agent",
        "repo_path",
        "branch",
        "dirty_clusters",
        "active_bead_ids",
        "reservation_conflicts",
        "proof_suggestions",
        "rch",
        "subsystems",
        "next_action",
    ] {
        assert!(receipt.get(field).is_some(), "receipt missing {field}");
    }
}
