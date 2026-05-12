//! Contract tests for the non-mutating claim/reservation/start-message receipt helper.

#![allow(missing_docs)]

use serde_json::Value;
use std::process::{Command, Output};

const SCRIPT_PATH: &str = "scripts/claim_reservation_receipt.py";
const FIXTURE_DIR: &str = "tests/fixtures/claim_reservation_receipt";
const BEAD_ID: &str = "asupersync-aj7lx3.6";
const AGENT_NAME: &str = "TopazGoose";

fn run_receipt(reservation_fixture: &str, git_status_fixture: &str) -> Output {
    Command::new("python3")
        .arg(SCRIPT_PATH)
        .arg("--bead-id")
        .arg(BEAD_ID)
        .arg("--agent-name")
        .arg(AGENT_NAME)
        .arg("--project-key")
        .arg("/data/projects/asupersync")
        .arg("--planned-path")
        .arg("scripts/claim_reservation_receipt.py")
        .arg("--planned-path")
        .arg("tests/claim_reservation_receipt_contract.rs")
        .arg("--planned-path")
        .arg("tests/fixtures/claim_reservation_receipt/*.json")
        .arg("--reservation-snapshot")
        .arg(format!("{FIXTURE_DIR}/{reservation_fixture}"))
        .arg("--git-status-snapshot")
        .arg(format!("{FIXTURE_DIR}/{git_status_fixture}"))
        .arg("--generated-at")
        .arg("2026-05-08T04:30:00Z")
        .arg("--output")
        .arg("json")
        .output()
        .expect("receipt helper should execute")
}

fn receipt(reservation_fixture: &str, git_status_fixture: &str) -> Value {
    let output = run_receipt(reservation_fixture, git_status_fixture);
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
    std::fs::read_to_string(format!("{FIXTURE_DIR}/{fixture}"))
        .unwrap_or_else(|error| panic!("read golden fixture {fixture}: {error}"))
}

fn assert_output_matches_golden(
    reservation_fixture: &str,
    git_status_fixture: &str,
    expected_fixture: &str,
    drift_message: &str,
) {
    let output = run_receipt(reservation_fixture, git_status_fixture);
    assert!(
        output.status.success(),
        "receipt helper failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let actual = String::from_utf8(output.stdout).expect("receipt stdout is utf-8");
    let expected = fixture_text(expected_fixture);
    let actual_json: Value = serde_json::from_str(&actual).expect("actual receipt JSON");
    let expected_json: Value = serde_json::from_str(&expected).expect("golden receipt JSON");
    assert_eq!(
        actual_json, expected_json,
        "parsed claim/reservation receipt JSON drifted for {reservation_fixture} + {git_status_fixture} -> {expected_fixture}"
    );
    assert_eq!(actual, expected, "{drift_message}");
}

#[test]
fn clean_receipt_allows_atomic_claim_sequence() {
    let receipt = receipt("clear_reservations.json", "clean_git_status.json");

    assert_eq!(
        receipt["schema_version"].as_str(),
        Some("claim-reservation-start-receipt-v1")
    );
    assert_eq!(receipt["bead_id"].as_str(), Some(BEAD_ID));
    assert_eq!(receipt["agent"].as_str(), Some(AGENT_NAME));
    assert_eq!(
        receipt["recommended_next_action"].as_str(),
        Some("run-claim-sequence")
    );
    assert_eq!(receipt["tracker_mutation_status"].as_str(), Some("ready"));
    assert_eq!(receipt["message_status"].as_str(), Some("ready"));

    let commands = receipt["planned_commands"]
        .as_array()
        .expect("planned_commands must be array");
    assert!(
        commands.iter().any(
            |command| command["command"].as_str().unwrap_or("").contains(
                "br update asupersync-aj7lx3.6 --status in_progress --assignee TopazGoose --json"
            )
        ),
        "receipt must include the exact br claim command"
    );
    assert!(
        commands
            .iter()
            .all(|command| command["allowed_now"].as_bool().unwrap_or(false)),
        "all steps should be allowed for a clean preflight"
    );
}

#[test]
fn clean_receipt_output_matches_full_reviewed_golden() {
    assert_output_matches_golden(
        "clear_reservations.json",
        "clean_git_status.json",
        "clean_receipt_expected.json",
        "clean claim/reservation receipt drifted from the reviewed golden",
    );
}

#[test]
fn tracker_reservation_conflict_blocks_before_beads_mutation() {
    let receipt = receipt("tracker_conflict.json", "clean_git_status.json");

    assert_eq!(
        receipt["recommended_next_action"].as_str(),
        Some("wait-for-tracker-reservation")
    );
    assert_eq!(
        receipt["tracker_mutation_status"].as_str(),
        Some("not-attempted")
    );
    assert_eq!(receipt["message_status"].as_str(), Some("not-attempted"));
    assert_eq!(
        receipt["preflight"]["reservation"]["tracker"]["status"].as_str(),
        Some("blocked")
    );
    assert_eq!(
        receipt["preflight"]["reservation"]["tracker"]["conflicts"][0]["holder"].as_str(),
        Some("BlackDove")
    );

    let br_update = receipt["planned_commands"]
        .as_array()
        .expect("planned commands")
        .iter()
        .find(|command| {
            command["command"]
                .as_str()
                .unwrap_or("")
                .starts_with("br update ")
        })
        .expect("br update command should be present");
    assert_eq!(br_update["allowed_now"].as_bool(), Some(false));
}

#[test]
fn tracker_conflict_output_matches_full_reviewed_golden() {
    assert_output_matches_golden(
        "tracker_conflict.json",
        "clean_git_status.json",
        "tracker_conflict_expected.json",
        "claim/reservation tracker-conflict receipt changed; update the golden only after reviewing wait-for-tracker semantics",
    );
}

#[test]
fn implementation_reservation_conflict_blocks_claim_sequence() {
    let receipt = receipt("implementation_conflict.json", "clean_git_status.json");

    assert_eq!(
        receipt["recommended_next_action"].as_str(),
        Some("wait-for-implementation-reservation")
    );
    assert_eq!(
        receipt["preflight"]["reservation"]["implementation"]["status"].as_str(),
        Some("blocked")
    );
    assert_eq!(
        receipt["preflight"]["reservation"]["implementation"]["conflicts"][0]["path"].as_str(),
        Some("scripts/claim_reservation_receipt.py")
    );
    assert_eq!(
        receipt["tracker_mutation_status"].as_str(),
        Some("not-attempted")
    );
}

#[test]
fn implementation_directory_reservation_conflict_blocks_claim_sequence() {
    let receipt = receipt(
        "implementation_directory_conflict.json",
        "clean_git_status.json",
    );

    assert_eq!(
        receipt["recommended_next_action"].as_str(),
        Some("wait-for-implementation-reservation")
    );
    assert_eq!(
        receipt["preflight"]["reservation"]["implementation"]["status"].as_str(),
        Some("blocked")
    );
    assert_eq!(
        receipt["preflight"]["reservation"]["implementation"]["conflicts"][0]["path"].as_str(),
        Some("tests/fixtures/claim_reservation_receipt/*.json")
    );
    assert_eq!(
        receipt["preflight"]["reservation"]["implementation"]["conflicts"][0]["path_pattern"]
            .as_str(),
        Some("tests/fixtures/claim_reservation_receipt")
    );
}

#[test]
fn implementation_conflict_output_matches_full_reviewed_golden() {
    assert_output_matches_golden(
        "implementation_conflict.json",
        "clean_git_status.json",
        "implementation_conflict_expected.json",
        "claim/reservation implementation-conflict receipt changed; update the golden only after reviewing wait-for-implementation-reservation semantics",
    );
}

#[test]
fn implementation_directory_conflict_output_matches_full_reviewed_golden() {
    assert_output_matches_golden(
        "implementation_directory_conflict.json",
        "clean_git_status.json",
        "implementation_directory_conflict_expected.json",
        "claim/reservation directory-conflict receipt changed; update the golden only after reviewing directory-reservation semantics",
    );
}

#[test]
fn dirty_index_conflict_takes_precedence_over_reservations() {
    let receipt = receipt("clear_reservations.json", "dirty_index.json");

    assert_eq!(
        receipt["recommended_next_action"].as_str(),
        Some("clear-dirty-index-before-claim")
    );
    assert_eq!(
        receipt["preflight"]["dirty_index"]["status"].as_str(),
        Some("blocked")
    );
    assert_eq!(
        receipt["preflight"]["dirty_index"]["staged_paths"][0].as_str(),
        Some("README.md")
    );
    assert_eq!(
        receipt["tracker_mutation_status"].as_str(),
        Some("not-attempted")
    );
}

#[test]
fn dirty_index_output_matches_full_reviewed_golden() {
    assert_output_matches_golden(
        "clear_reservations.json",
        "dirty_index.json",
        "dirty_index_expected.json",
        "claim/reservation dirty-index receipt changed; update the golden only after reviewing staged-index preflight semantics",
    );
}

#[test]
fn receipt_command_sequence_stays_non_destructive_and_rch_free() {
    let receipt = receipt("clear_reservations.json", "clean_git_status.json");
    assert_eq!(
        receipt["preflight"]["forbidden_command_tokens"]
            .as_array()
            .expect("forbidden token list")
            .len(),
        0,
        "receipt should not contain branch/worktree/reset/clean/cargo commands"
    );

    let command_text = receipt["planned_commands"]
        .as_array()
        .expect("planned commands")
        .iter()
        .filter_map(|command| command["command"].as_str())
        .collect::<Vec<_>>()
        .join("\n");
    let reservation_steps = receipt["planned_commands"]
        .as_array()
        .expect("planned commands")
        .iter()
        .filter(|command| {
            command["command"]
                .as_str()
                .unwrap_or("")
                .starts_with("file_reservation_paths(")
        })
        .collect::<Vec<_>>();
    assert_eq!(
        reservation_steps.len(),
        2,
        "receipt should model tracker and implementation reservations separately"
    );
    assert!(
        reservation_steps
            .iter()
            .all(|command| command["mutates"].as_bool() == Some(true)),
        "Agent Mail file reservation steps must be marked mutating because they create reservation records"
    );
    for forbidden in [
        "git branch",
        "git checkout -b",
        "git switch -c",
        "git worktree",
        "git reset",
        "git clean",
        "cargo ",
    ] {
        assert!(
            !command_text.contains(forbidden),
            "receipt command sequence must not contain {forbidden}"
        );
    }
}
