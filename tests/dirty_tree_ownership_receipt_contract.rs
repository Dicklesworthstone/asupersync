//! Contract tests for the dirty-tree ownership receipt helper.

#![allow(missing_docs)]

use serde_json::Value;
use std::fs;
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

fn receipt_stdout(fixture: &str) -> String {
    let output = run_receipt(fixture);
    assert!(
        output.status.success(),
        "receipt helper failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("receipt output must be UTF-8")
}

fn fixture_text(fixture: &str) -> String {
    fs::read_to_string(repo_root().join(FIXTURE_ROOT).join(fixture))
        .expect("fixture golden must be readable")
}

fn assert_receipt_output_matches_golden(fixture: &str, expected_fixture: &str) {
    let actual_text = receipt_stdout(fixture);
    let expected_text = fixture_text(expected_fixture);
    let actual_json: Value = serde_json::from_str(&actual_text).expect("actual receipt JSON");
    let expected_json: Value = serde_json::from_str(&expected_text).expect("expected receipt JSON");

    assert_eq!(
        actual_json, expected_json,
        "parsed dirty-tree ownership receipt JSON drifted for {fixture} -> {expected_fixture}"
    );
    assert_eq!(
        actual_text, expected_text,
        "dirty-tree ownership receipt {expected_fixture} changed; update the golden only after reviewing dirty ownership semantics"
    );
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
fn live_probe_preserves_porcelain_status_columns_for_unstaged_paths() {
    let script = r#"
import importlib.util
import json
import pathlib
import sys

script_path = pathlib.Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("dirty_tree_ownership_receipt", script_path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class Completed:
    stdout = " M tests/fixtures/dirty-tree/unstaged-path.log \n"

module.subprocess.run = lambda *args, **kwargs: Completed()
status, raw = module.run_text(pathlib.Path("."), ["git", "status", "--porcelain=v1"], 1.0)
entries = module.parse_status_lines(raw if status == "ok" else "")
print(json.dumps({"status": status, "raw": raw, "entries": entries}))
"#;
    let output = Command::new("python3")
        .arg("-c")
        .arg(script)
        .arg(repo_root().join(SCRIPT_PATH))
        .current_dir(repo_root())
        .output()
        .expect("run dirty-tree live probe parser smoke");
    assert!(
        output.status.success(),
        "parser smoke failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let parsed: Value = serde_json::from_slice(&output.stdout).expect("parser smoke JSON");
    assert_eq!(parsed["status"].as_str(), Some("ok"));
    assert_eq!(
        parsed["raw"].as_str(),
        Some(" M tests/fixtures/dirty-tree/unstaged-path.log ")
    );
    assert_eq!(parsed["entries"][0]["status"].as_str(), Some(" M"));
    assert_eq!(
        parsed["entries"][0]["path"].as_str(),
        Some("tests/fixtures/dirty-tree/unstaged-path.log ")
    );
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
fn peer_reservation_matches_full_output_golden() {
    assert_receipt_output_matches_golden("peer_reservation.json", "peer_reservation_expected.json");
}

#[test]
fn directory_reservation_blocks_child_path_staging() {
    let receipt = receipt_json("directory_reservation.json");
    let row = row(&receipt, "src/security/secret.rs");

    assert_eq!(row["classification"].as_str(), Some("peer-owned"));
    assert_eq!(row["owner"].as_str(), Some("BoldPlateau"));
    assert_eq!(
        row["evidence"]["reservation_path_pattern"].as_str(),
        Some("src/security")
    );
    assert_eq!(
        row["staging_guidance"]["decision"].as_str(),
        Some("do-not-stage")
    );
}

#[test]
fn directory_reservation_matches_full_output_golden() {
    assert_receipt_output_matches_golden(
        "directory_reservation.json",
        "directory_reservation_expected.json",
    );
}

#[test]
fn rename_target_reservation_blocks_destination_after_porcelain_expansion() {
    let receipt = receipt_json("rename_target_reservation.json");
    let source = row(&receipt, "docs/old-secret.rs");
    let target = row(&receipt, "src/security/secret.rs");

    assert_eq!(source["classification"].as_str(), Some("unattributed"));
    assert_eq!(target["classification"].as_str(), Some("peer-owned"));
    assert_eq!(target["owner"].as_str(), Some("BoldPlateau"));
    assert_eq!(
        target["evidence"]["reservation_path_pattern"].as_str(),
        Some("src/security")
    );
    assert_eq!(
        target["staging_guidance"]["decision"].as_str(),
        Some("do-not-stage")
    );
    assert_eq!(receipt["summary"]["total_paths"].as_u64(), Some(2));
    assert_eq!(receipt["summary"]["peer_owned"].as_u64(), Some(1));
    assert_eq!(receipt["summary"]["unattributed"].as_u64(), Some(1));
}

#[test]
fn rename_target_reservation_matches_full_output_golden() {
    assert_receipt_output_matches_golden(
        "rename_target_reservation.json",
        "rename_target_reservation_expected.json",
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
fn self_reservation_matches_full_output_golden() {
    assert_receipt_output_matches_golden("self_reservation.json", "self_reservation_expected.json");
}

#[test]
fn mixed_staged_index_requires_path_limited_commit_boundary() {
    let receipt = receipt_json("mixed_staged_index.json");
    let boundary = &receipt["commit_boundary"];

    assert_eq!(
        boundary["decision"].as_str(),
        Some("path-limited-commit-required")
    );
    assert_eq!(
        boundary["ordinary_index_commit_allowed"].as_bool(),
        Some(false)
    );
    assert_eq!(
        boundary["peer_index_preservation_required"].as_bool(),
        Some(true)
    );
    assert_eq!(
        boundary["self_owned_staged_paths"][0].as_str(),
        Some("scripts/dirty_tree_ownership_receipt.py")
    );
    assert_eq!(
        boundary["non_self_staged_paths"]
            .as_array()
            .expect("non-self staged paths")
            .len(),
        2
    );
    assert_eq!(
        boundary["path_limited_commit_command"].as_str(),
        Some("git commit --only -- scripts/dirty_tree_ownership_receipt.py")
    );
    assert!(
        !boundary["path_limited_commit_command"]
            .as_str()
            .expect("path-limited commit command")
            .contains("fuzz/Cargo.toml"),
        "path-limited commit command must not include peer staged paths"
    );

    let fuzz = row(&receipt, "fuzz/Cargo.toml");
    assert_eq!(fuzz["classification"].as_str(), Some("peer-owned"));
    assert_eq!(
        fuzz["staging_guidance"]["decision"].as_str(),
        Some("unstage-before-commit")
    );
}

#[test]
fn mixed_staged_index_matches_full_output_golden() {
    assert_receipt_output_matches_golden(
        "mixed_staged_index.json",
        "mixed_staged_index_expected.json",
    );
}

#[test]
fn upstream_drift_requires_refresh_before_commit() {
    let receipt = receipt_json("upstream_drift.json");
    let boundary = &receipt["shared_main_boundary"];

    assert_eq!(boundary["decision"].as_str(), Some("refresh-before-commit"));
    assert_eq!(boundary["upstream_drift"]["behind"].as_u64(), Some(2));
    assert_eq!(
        boundary["upstream_drift"]["requires_refresh"].as_bool(),
        Some(true)
    );
    assert_eq!(
        boundary["safe_to_stage_paths"][0].as_str(),
        Some("scripts/dirty_tree_ownership_receipt.py")
    );
    assert_eq!(
        boundary["unsafe_to_stage_paths"][0].as_str(),
        Some("tests/proof_status_snapshot_contract.rs")
    );
    assert_eq!(
        boundary["staged_without_ownership_paths"][0].as_str(),
        Some("tests/proof_status_snapshot_contract.rs")
    );
    assert_eq!(
        boundary["recommended_git_add_command"].as_str(),
        Some("git add -- scripts/dirty_tree_ownership_receipt.py")
    );
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
fn tracker_dirty_matches_full_output_golden() {
    assert_receipt_output_matches_golden("tracker_dirty.json", "tracker_dirty_expected.json");
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
fn message_owner_matches_full_output_golden() {
    assert_receipt_output_matches_golden("message_owner.json", "message_owner_expected.json");
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
fn no_agent_mail_matches_full_output_golden() {
    assert_receipt_output_matches_golden("no_agent_mail.json", "no_agent_mail_expected.json");
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
fn owner_conflict_matches_full_output_golden() {
    assert_receipt_output_matches_golden("owner_conflict.json", "owner_conflict_expected.json");
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
