//! Contract tests for the stale in-progress bead analysis receipt helper.

#![allow(missing_docs)]

use serde_json::Value;
use std::path::PathBuf;
use std::process::{Command, Output};

const SCRIPT_PATH: &str = "scripts/stale_in_progress_receipt.py";
const FIXTURE_ROOT: &str = "tests/fixtures/stale_in_progress_receipt";
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
        .arg("TopazGoose")
        .arg("--generated-at")
        .arg(GENERATED_AT)
        .arg("--output")
        .arg("json")
        .current_dir(repo_root())
        .output()
        .expect("run stale receipt script")
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

fn fixture_text(fixture: &str) -> String {
    std::fs::read_to_string(repo_root().join(FIXTURE_ROOT).join(fixture))
        .unwrap_or_else(|err| panic!("read fixture {fixture}: {err}"))
}

fn first_classification(receipt: &Value) -> &Value {
    receipt["classifications"]
        .as_array()
        .expect("classifications must be array")
        .first()
        .expect("fixture must contain one classification")
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
fn fresh_active_peer_is_wait_contact_not_stale() {
    let receipt = receipt_json("fresh_active_peer.json");
    let row = first_classification(&receipt);

    assert_eq!(
        receipt["schema_version"].as_str(),
        Some("stale-in-progress-receipt-v1")
    );
    assert_eq!(receipt["generated_at"].as_str(), Some(GENERATED_AT));
    assert_eq!(receipt["current_date"].as_str(), Some("2026-05-08"));
    assert_eq!(row["id"].as_str(), Some("asupersync-fresh1"));
    assert_eq!(row["classification"].as_str(), Some("fresh-active-peer"));
    assert_eq!(
        row["proposed_action"]["kind"].as_str(),
        Some("agent-mail-reply")
    );
    assert_ne!(row["classification"].as_str(), Some("probably-stale"));
    assert_eq!(
        row["evidence"]["message_created_ts"].as_str(),
        Some("2026-05-08T04:20:00Z")
    );
    assert_eq!(
        receipt["agent_roster"]["counts"]["active_agents"].as_u64(),
        Some(1)
    );
    assert_eq!(
        receipt["agent_roster"]["agents"][0]["name"].as_str(),
        Some("CopperSpring")
    );
    assert_eq!(
        receipt["agent_roster"]["agents"][0]["activity"].as_str(),
        Some("active")
    );
}

#[test]
fn expired_reservation_and_inactive_agent_is_probably_stale() {
    let receipt = receipt_json("expired_reservation_inactive_agent.json");
    let row = first_classification(&receipt);

    assert_eq!(row["id"].as_str(), Some("asupersync-stale1"));
    assert_eq!(row["classification"].as_str(), Some("probably-stale"));
    assert_eq!(row["evidence"]["reservation_expired"].as_bool(), Some(true));
    assert_eq!(
        row["proposed_action"]["command"].as_str(),
        Some("br update asupersync-stale1 --status open --json")
    );
    assert_eq!(row["proposed_action"]["allowed_now"].as_bool(), Some(false));
    assert_eq!(
        receipt["agent_roster"]["counts"]["inactive_agents"].as_u64(),
        Some(1)
    );
    assert_eq!(
        receipt["agent_roster"]["agents"][0]["activity"].as_str(),
        Some("inactive")
    );
}

#[test]
fn expired_reservation_matches_full_output_golden() {
    let output = run_receipt("expired_reservation_inactive_agent.json");
    assert!(
        output.status.success(),
        "receipt helper failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let actual = String::from_utf8(output.stdout).expect("receipt stdout must be UTF-8");
    let expected = fixture_text("expired_reservation_inactive_agent_expected.json");

    let actual_json: Value = serde_json::from_str(&actual).expect("actual receipt JSON");
    let expected_json: Value = serde_json::from_str(&expected).expect("golden receipt JSON");
    assert_eq!(actual_json, expected_json, "parsed receipt JSON must match");
    assert_eq!(
        actual, expected,
        "stale in-progress receipt changed; update the golden only after reviewing stale classification and proposed reopen semantics"
    );
}

#[test]
fn recent_commit_reference_recommends_verify_and_close() {
    let receipt = receipt_json("recent_commit_reference.json");
    let row = first_classification(&receipt);

    assert_eq!(
        row["classification"].as_str(),
        Some("closed-by-recent-commit")
    );
    assert_eq!(
        row["evidence"]["commit_hash"].as_str(),
        Some("29d852cf8123456789")
    );
    assert!(
        row["proposed_action"]["command"]
            .as_str()
            .expect("command string")
            .contains("br close asupersync-aj7lx3.7 --reason 'Shipped in 29d852cf8123' --json")
    );
}

#[test]
fn active_reservation_with_weak_owner_freshness_blocks_reopen() {
    let receipt = receipt_json("blocked_by_active_reservation.json");
    let row = first_classification(&receipt);

    assert_eq!(
        row["classification"].as_str(),
        Some("blocked-by-active-reservation")
    );
    assert_eq!(
        row["evidence"]["reservation_holder"].as_str(),
        Some("ReservationHolder")
    );
    assert_eq!(
        row["evidence"]["reservation_expires_ts"].as_str(),
        Some("2026-05-08T05:30:00Z")
    );
    assert_eq!(
        row["proposed_action"]["kind"].as_str(),
        Some("agent-mail-reply")
    );
    assert_eq!(
        row["proposed_action"]["target"].as_str(),
        Some("ReservationHolder")
    );
}

#[test]
fn active_reservation_blocker_matches_full_output_golden() {
    let output = run_receipt("blocked_by_active_reservation.json");
    assert!(
        output.status.success(),
        "receipt helper failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let actual = String::from_utf8(output.stdout).expect("receipt stdout must be UTF-8");
    let expected = fixture_text("blocked_by_active_reservation_expected.json");

    let actual_json: Value = serde_json::from_str(&actual).expect("actual receipt JSON");
    let expected_json: Value = serde_json::from_str(&expected).expect("golden receipt JSON");
    assert_eq!(actual_json, expected_json, "parsed receipt JSON must match");
    assert_eq!(
        actual, expected,
        "stale in-progress active-reservation receipt changed; update the golden only after reviewing stand-off and holder-message semantics"
    );
}

#[test]
fn dirty_tracker_only_state_requires_human_escalation() {
    let receipt = receipt_json("dirty_tracker_only.json");
    let row = first_classification(&receipt);

    assert_eq!(
        receipt["tracker_state"]["status"].as_str(),
        Some("dirty-tracker-only")
    );
    assert_eq!(
        row["classification"].as_str(),
        Some("needs-human-escalation")
    );
    assert_eq!(
        row["proposed_action"]["kind"].as_str(),
        Some("blocker-bead-suggestion")
    );
}

#[test]
fn unavailable_agent_mail_is_explicitly_escalated() {
    let receipt = receipt_json("unavailable_agent_mail.json");
    let row = first_classification(&receipt);

    assert_eq!(
        receipt["subsystems"]["agent_mail"].as_str(),
        Some("unavailable")
    );
    assert_eq!(
        row["classification"].as_str(),
        Some("needs-human-escalation")
    );
    assert!(
        row["rationale"]
            .as_str()
            .expect("rationale string")
            .contains("Agent Mail data is unavailable")
    );
    assert_eq!(
        receipt["agent_roster"]["counts"]["missing_assignees"].as_u64(),
        Some(1)
    );
    assert_eq!(
        receipt["agent_roster"]["missing_assignees"][0].as_str(),
        Some("UnknownAgent")
    );
}

#[test]
fn unavailable_agent_mail_matches_full_output_golden() {
    let output = run_receipt("unavailable_agent_mail.json");
    assert!(
        output.status.success(),
        "receipt helper failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let actual = String::from_utf8(output.stdout).expect("receipt stdout must be UTF-8");
    let expected = fixture_text("unavailable_agent_mail_expected.json");

    let actual_json: Value = serde_json::from_str(&actual).expect("actual receipt JSON");
    let expected_json: Value = serde_json::from_str(&expected).expect("golden receipt JSON");
    assert_eq!(actual_json, expected_json, "parsed receipt JSON must match");
    assert_eq!(
        actual, expected,
        "stale in-progress unavailable-Agent-Mail receipt changed; update the golden only after reviewing human-escalation semantics"
    );
}

#[test]
fn receipt_safety_contract_forbids_mutation_execution_and_cargo() {
    let receipt = receipt_json("expired_reservation_inactive_agent.json");

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
    let receipt = receipt_json("fresh_active_peer.json");
    for field in [
        "schema_version",
        "generated_at",
        "current_date",
        "agent",
        "repo_path",
        "thresholds",
        "subsystems",
        "agent_roster",
        "tracker_state",
        "classifications",
        "summary",
        "safety",
    ] {
        assert!(receipt.get(field).is_some(), "receipt missing {field}");
    }
}
