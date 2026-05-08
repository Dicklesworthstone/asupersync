//! Contract tests for the dirty-tree ownership receipt helper.

#![allow(missing_docs)]

use serde_json::Value;
use std::path::PathBuf;
use std::process::{Command, Output};

const SCRIPT_PATH: &str = "scripts/dirty_tree_ownership_receipt.py";
const FIXTURE_ROOT: &str = "tests/fixtures/dirty_tree_ownership_receipt";
const GENERATED_AT: &str = "2026-05-08T05:10:00Z";

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
        .arg("TopazGoose")
        .arg("--generated-at")
        .arg(GENERATED_AT)
        .arg("--output")
        .arg("json")
        .current_dir(repo_root())
        .output()
        .expect("run dirty tree ownership receipt")
}

fn receipt_json(fixture: &str) -> Value {
    let output = run_receipt(fixture);
    assert!(
        output.status.success(),
        "receipt helper failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("receipt output must be JSON")
}

fn row<'a>(receipt: &'a Value, path: &str) -> &'a Value {
    receipt["rows"]
        .as_array()
        .expect("rows must be array")
        .iter()
        .find(|row| row["path"].as_str() == Some(path))
        .expect("fixture row should exist")
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
fn peer_reservation_blocks_staging() {
    let receipt = receipt_json("peer_reservation.json");
    let row = row(&receipt, "src/security/secret.rs");

    assert_eq!(
        receipt["schema_version"].as_str(),
        Some("dirty-tree-ownership-receipt-v1")
    );
    assert_eq!(receipt["current_date"].as_str(), Some("2026-05-08"));
    assert_eq!(row["classification"].as_str(), Some("peer-owned"));
    assert_eq!(row["owner"].as_str(), Some("BoldPlateau"));
    assert_eq!(
        row["staging_guidance"]["decision"].as_str(),
        Some("do-not-stage")
    );
    assert_eq!(
        row["evidence"]["reservation_expires_ts"].as_str(),
        Some("2026-05-08T05:56:00Z")
    );
}

#[test]
fn self_reservation_allows_pathspec_staging() {
    let receipt = receipt_json("self_reservation.json");
    let row = row(&receipt, "scripts/dirty_tree_ownership_receipt.py");

    assert_eq!(row["classification"].as_str(), Some("self-owned"));
    assert_eq!(
        row["staging_guidance"]["decision"].as_str(),
        Some("safe-to-stage-with-pathspec")
    );
    assert_eq!(
        row["proposed_action"]["command"].as_str(),
        Some("git add -- scripts/dirty_tree_ownership_receipt.py")
    );
    assert_eq!(row["proposed_action"]["allowed_now"].as_bool(), Some(true));
}

#[test]
fn tracker_dirty_state_is_never_mixed() {
    let receipt = receipt_json("tracker_dirty.json");
    let row = row(&receipt, ".beads/issues.jsonl");

    assert_eq!(row["classification"].as_str(), Some("tracker-state"));
    assert_eq!(
        row["staging_guidance"]["decision"].as_str(),
        Some("do-not-stage")
    );
    assert_eq!(receipt["summary"]["tracker_state"].as_u64(), Some(1));
}

#[test]
fn recent_message_can_assign_peer_owner_without_reservation() {
    let receipt = receipt_json("message_owner.json");
    let row = row(&receipt, "tests/proof_status_snapshot_contract.rs");

    assert_eq!(row["classification"].as_str(), Some("peer-owned"));
    assert_eq!(row["owner"].as_str(), Some("CoralGorge"));
    assert_eq!(
        row["evidence"]["message_created_ts"].as_str(),
        Some("2026-05-08T05:04:37Z")
    );
}

#[test]
fn unavailable_agent_mail_leaves_path_unattributed() {
    let receipt = receipt_json("no_agent_mail.json");
    let row = row(&receipt, "src/unknown.rs");

    assert_eq!(
        receipt["subsystems"]["agent_mail"].as_str(),
        Some("unavailable")
    );
    assert_eq!(row["classification"].as_str(), Some("unattributed"));
    assert_eq!(
        row["staging_guidance"]["decision"].as_str(),
        Some("needs-owner")
    );
}

#[test]
fn conflicting_owner_signals_are_explicit() {
    let receipt = receipt_json("owner_conflict.json");
    let row = row(&receipt, "src/sync/rwlock.rs");

    assert_eq!(row["classification"].as_str(), Some("owner-conflict"));
    assert_eq!(receipt["summary"]["owner_conflict"].as_u64(), Some(1));
    assert_eq!(
        row["staging_guidance"]["decision"].as_str(),
        Some("do-not-stage")
    );
}

#[test]
fn receipt_safety_contract_forbids_execution_and_destructive_commands() {
    let receipt = receipt_json("self_reservation.json");

    assert_eq!(
        receipt["safety"]["mutating_commands_executed"].as_bool(),
        Some(false)
    );
    assert_eq!(receipt["safety"]["beads_mutated"].as_bool(), Some(false));
    assert_eq!(receipt["safety"]["cargo_executed"].as_bool(), Some(false));
    assert_eq!(
        receipt["safety"]["branch_or_worktree_operations"].as_bool(),
        Some(false)
    );
    assert_eq!(
        receipt["safety"]["forbidden_command_tokens"]
            .as_array()
            .expect("forbidden tokens array")
            .len(),
        0
    );
}

#[test]
fn receipt_has_required_top_level_shape() {
    let receipt = receipt_json("peer_reservation.json");
    for field in [
        "schema_version",
        "generated_at",
        "current_date",
        "agent",
        "repo_path",
        "subsystems",
        "rows",
        "summary",
        "safety",
    ] {
        assert!(receipt.get(field).is_some(), "receipt missing {field}");
    }
}
