//! Contract tests for the swarm coordination replay pack helper.

#![allow(missing_docs)]

use serde_json::Value;
use std::path::PathBuf;
use std::process::{Command, Output};

const SCRIPT_PATH: &str = "scripts/swarm_coordination_replay_pack.py";
const FIXTURE_ROOT: &str = "tests/fixtures/swarm_coordination_replay_pack";
const GENERATED_AT: &str = "2026-05-08T05:55:00Z";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn run_replay(fixture: &str) -> Output {
    Command::new("python3")
        .arg(repo_root().join(SCRIPT_PATH))
        .arg("--input")
        .arg(PathBuf::from(FIXTURE_ROOT).join(fixture))
        .arg("--generated-at")
        .arg(GENERATED_AT)
        .arg("--output")
        .arg("json")
        .current_dir(repo_root())
        .output()
        .expect("run swarm coordination replay helper")
}

fn replay_json(fixture: &str) -> Value {
    let output = run_replay(fixture);
    assert!(
        output.status.success(),
        "replay helper failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("replay output must be JSON")
}

fn fixture_text(fixture: &str) -> String {
    std::fs::read_to_string(repo_root().join(FIXTURE_ROOT).join(fixture))
        .unwrap_or_else(|error| panic!("read golden fixture {fixture}: {error}"))
}

fn assert_replay_output_matches_golden(input_fixture: &str, expected_fixture: &str, label: &str) {
    let output = run_replay(input_fixture);
    assert!(
        output.status.success(),
        "replay helper failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let actual = String::from_utf8(output.stdout).expect("replay stdout is utf-8");
    let expected = fixture_text(expected_fixture);
    let actual_json: Value =
        serde_json::from_str(&actual).expect("actual replay output must be JSON");
    let expected_json: Value =
        serde_json::from_str(&expected).expect("golden replay output must be JSON");
    assert_eq!(
        actual_json, expected_json,
        "parsed swarm replay JSON drifted for {input_fixture} -> {expected_fixture}"
    );
    assert_eq!(
        actual, expected,
        "{label} receipt drifted from the reviewed golden"
    );
}

fn violation_codes(receipt: &Value) -> Vec<&str> {
    receipt["violations"]
        .as_array()
        .expect("violations")
        .iter()
        .map(|finding| finding["code"].as_str().expect("code"))
        .collect()
}

#[test]
fn script_exists_and_help_is_non_mutating() {
    assert!(
        repo_root().join(SCRIPT_PATH).exists(),
        "replay helper must exist at {SCRIPT_PATH}"
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
fn clean_replay_passes_all_invariants() {
    let receipt = replay_json("clean_replay.json");

    assert_eq!(
        receipt["schema_version"].as_str(),
        Some("swarm-coordination-replay-pack-v1")
    );
    assert_eq!(receipt["generated_at"].as_str(), Some(GENERATED_AT));
    assert_eq!(receipt["current_date"].as_str(), Some("2026-05-08"));
    assert_eq!(receipt["summary"]["passes"].as_bool(), Some(true));
    assert_eq!(receipt["source_counts"]["events"].as_u64(), Some(8));
    for (_, value) in receipt["invariants"].as_object().expect("invariants") {
        assert_eq!(value.as_bool(), Some(true));
    }
}

#[test]
fn clean_replay_output_matches_full_reviewed_golden() {
    assert_replay_output_matches_golden(
        "clean_replay.json",
        "clean_replay_expected.json",
        "clean_replay",
    );
}

#[test]
fn duplicate_claims_are_errors() {
    let receipt = replay_json("duplicate_claims.json");

    assert_eq!(receipt["summary"]["passes"].as_bool(), Some(false));
    assert_eq!(receipt["summary"]["error_count"].as_u64(), Some(1));
    assert_eq!(violation_codes(&receipt), vec!["duplicate-active-claim"]);
    assert_eq!(
        receipt["invariants"]["no_duplicate_active_claims"].as_bool(),
        Some(false)
    );
}

#[test]
fn duplicate_claims_output_matches_full_reviewed_golden() {
    assert_replay_output_matches_golden(
        "duplicate_claims.json",
        "duplicate_claims_expected.json",
        "duplicate_claims",
    );
}

#[test]
fn overlapping_exclusive_reservations_are_errors() {
    let receipt = replay_json("reservation_contention.json");

    assert_eq!(receipt["summary"]["passes"].as_bool(), Some(false));
    assert_eq!(
        violation_codes(&receipt),
        vec!["exclusive-reservation-contention"]
    );
    assert!(
        receipt["violations"][0]["message"]
            .as_str()
            .expect("message")
            .contains("fuzz/Cargo.toml")
    );
}

#[test]
fn reservation_contention_output_matches_full_reviewed_golden() {
    assert_replay_output_matches_golden(
        "reservation_contention.json",
        "reservation_contention_expected.json",
        "reservation_contention",
    );
}

#[test]
fn partial_proof_launches_require_remote_exit_evidence() {
    let receipt = replay_json("partial_proof.json");

    assert_eq!(receipt["summary"]["passes"].as_bool(), Some(false));
    assert_eq!(violation_codes(&receipt), vec!["partial-proof-launch"]);
    assert_eq!(
        receipt["invariants"]["proofs_have_remote_exit_events"].as_bool(),
        Some(false)
    );
}

#[test]
fn partial_proof_output_matches_full_reviewed_golden() {
    assert_replay_output_matches_golden(
        "partial_proof.json",
        "partial_proof_expected.json",
        "partial_proof",
    );
}

#[test]
fn remote_success_without_artifact_and_closeout_evidence_is_warning() {
    let receipt = replay_json("artifact_warning_and_closeout_gap.json");

    assert_eq!(receipt["summary"]["passes"].as_bool(), Some(false));
    assert_eq!(receipt["summary"]["error_count"].as_u64(), Some(0));
    assert_eq!(receipt["summary"]["warning_count"].as_u64(), Some(2));
    assert_eq!(
        violation_codes(&receipt),
        vec!["proof-artifact-missing", "closeout-evidence-gap"]
    );
}

#[test]
fn artifact_warning_and_closeout_gap_output_matches_full_reviewed_golden() {
    assert_replay_output_matches_golden(
        "artifact_warning_and_closeout_gap.json",
        "artifact_warning_and_closeout_gap_expected.json",
        "artifact_warning_and_closeout_gap",
    );
}

#[test]
fn released_claims_and_reservations_do_not_trigger_false_contention() {
    let receipt = replay_json("released_claim_and_reservation.json");

    assert_eq!(receipt["summary"]["passes"].as_bool(), Some(true));
    assert_eq!(receipt["summary"]["violation_count"].as_u64(), Some(0));
}

#[test]
fn released_claim_and_reservation_output_matches_full_reviewed_golden() {
    assert_replay_output_matches_golden(
        "released_claim_and_reservation.json",
        "released_claim_and_reservation_expected.json",
        "released_claim_and_reservation",
    );
}

#[test]
fn helper_declares_it_does_not_mutate_services_or_repo() {
    let receipt = replay_json("clean_replay.json");

    assert_eq!(receipt["non_mutating"].as_bool(), Some(true));
    for key in [
        "runs_cargo",
        "runs_git_mutation",
        "runs_beads_mutation",
        "runs_agent_mail_mutation",
        "runs_destructive_command",
    ] {
        assert_eq!(
            receipt["forbidden_actions"][key].as_bool(),
            Some(false),
            "{key} must stay false"
        );
    }
}
