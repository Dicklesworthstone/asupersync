//! Contract tests for the non-mutating fuzz manifest lease queue helper.

#![allow(missing_docs)]

use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

const SCRIPT_PATH: &str = "scripts/fuzz_manifest_lease_queue.py";
const FIXTURE_ROOT: &str = "tests/fixtures/fuzz_manifest_lease_queue";
const GENERATED_AT: &str = "2026-05-08T06:10:00Z";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn run_queue(fixture: &str) -> Output {
    Command::new("python3")
        .arg(repo_root().join(SCRIPT_PATH))
        .arg("--input")
        .arg(repo_root().join(FIXTURE_ROOT).join(fixture))
        .arg("--generated-at")
        .arg(GENERATED_AT)
        .arg("--output")
        .arg("json")
        .current_dir(repo_root())
        .output()
        .expect("run fuzz manifest lease queue helper")
}

fn queue_json(fixture: &str) -> Value {
    let output = run_queue(fixture);
    assert!(
        output.status.success(),
        "queue helper failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("queue output must be JSON")
}

fn row_by_id<'a>(receipt: &'a Value, proposal_id: &str) -> &'a Value {
    receipt["queue"]
        .as_array()
        .expect("queue rows")
        .iter()
        .find(|row| row["proposal_id"].as_str() == Some(proposal_id))
        .expect("proposal id should exist")
}

fn fixture_text(fixture: &str) -> String {
    fs::read_to_string(repo_root().join(FIXTURE_ROOT).join(fixture))
        .unwrap_or_else(|error| panic!("read fixture {fixture}: {error}"))
}

fn assert_queue_matches_exact_reviewed_golden(input_fixture: &str, expected_fixture: &str) {
    let output = run_queue(input_fixture);
    assert!(
        output.status.success(),
        "queue helper failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let actual = String::from_utf8(output.stdout).expect("queue output must be UTF-8");
    let expected = fixture_text(expected_fixture);

    let actual_json: Value = serde_json::from_str(&actual).expect("actual output must be JSON");
    let expected_json: Value = serde_json::from_str(&expected).expect("golden output must be JSON");
    assert_eq!(
        actual_json, expected_json,
        "parsed fuzz manifest queue JSON drifted for {input_fixture} -> {expected_fixture}"
    );
    assert_eq!(
        actual, expected,
        "fuzz manifest queue output changed for {input_fixture}; update {expected_fixture} only after reviewing reservation ordering and queue semantics"
    );
}

#[test]
fn script_exists_and_help_is_non_mutating() {
    assert!(
        repo_root().join(SCRIPT_PATH).exists(),
        "queue helper must exist at {SCRIPT_PATH}"
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
fn clean_manifest_queue_selects_one_ready_proposal_and_queues_the_next() {
    let receipt = queue_json("clean_queue.json");

    assert_eq!(
        receipt["schema_version"].as_str(),
        Some("fuzz-manifest-lease-queue-v1")
    );
    assert_eq!(receipt["generated_at"].as_str(), Some(GENERATED_AT));
    assert_eq!(receipt["summary"]["ready_count"].as_u64(), Some(1));
    assert_eq!(receipt["summary"]["queued_count"].as_u64(), Some(1));
    assert_eq!(
        receipt["ready_now"][0].as_str(),
        Some("asupersync-fuzz-a:MaroonBear:http_header_map_invariants")
    );

    let first = row_by_id(
        &receipt,
        "asupersync-fuzz-a:MaroonBear:http_header_map_invariants",
    );
    assert_eq!(first["queue_position"].as_u64(), Some(1));
    assert_eq!(first["status"].as_str(), Some("ready-to-reserve"));
    assert_eq!(
        first["recommended_action"].as_str(),
        Some("reserve-manifest-and-target-before-editing")
    );

    let second = row_by_id(
        &receipt,
        "asupersync-fuzz-b:BlackDove:redis_resp3_map_invariants",
    );
    assert_eq!(second["queue_position"].as_u64(), Some(2));
    assert_eq!(
        second["status"].as_str(),
        Some("queued-after-earlier-proposal")
    );
}

#[test]
fn clean_manifest_queue_matches_exact_reviewed_golden() {
    assert_queue_matches_exact_reviewed_golden("clean_queue.json", "clean_queue_expected.json");
}

#[test]
fn active_manifest_reservation_blocks_all_proposals_before_manifest_edits() {
    let receipt = queue_json("manifest_reserved.json");

    assert_eq!(
        receipt["manifest_reservation"]["status"].as_str(),
        Some("blocked-by-active-reservation")
    );
    assert_eq!(
        receipt["manifest_reservation"]["holder"].as_str(),
        Some("VioletLark")
    );
    let row = row_by_id(
        &receipt,
        "asupersync-fuzz-a:MaroonBear:http_header_map_invariants",
    );
    assert_eq!(
        row["status"].as_str(),
        Some("wait-for-manifest-reservation")
    );
    assert_eq!(
        row["blockers"][0]["kind"].as_str(),
        Some("manifest-reservation")
    );
    assert_eq!(receipt["summary"]["waiting_count"].as_u64(), Some(1));
}

#[test]
fn manifest_reserved_queue_matches_exact_reviewed_golden() {
    assert_queue_matches_exact_reviewed_golden(
        "manifest_reserved.json",
        "manifest_reserved_expected.json",
    );
}

#[test]
fn active_target_reservation_blocks_only_that_target_and_next_eligible_can_run() {
    let receipt = queue_json("target_reserved.json");

    let blocked = row_by_id(
        &receipt,
        "asupersync-fuzz-a:MaroonBear:http_header_map_invariants",
    );
    assert_eq!(
        blocked["status"].as_str(),
        Some("wait-for-target-reservation")
    );
    assert_eq!(
        blocked["blockers"][0]["holder"].as_str(),
        Some("CopperSpring")
    );

    let ready = row_by_id(
        &receipt,
        "asupersync-fuzz-b:BlackDove:redis_resp3_map_invariants",
    );
    assert_eq!(ready["queue_position"].as_u64(), Some(1));
    assert_eq!(ready["status"].as_str(), Some("ready-to-reserve"));
    assert_eq!(
        receipt["ready_now"][0].as_str(),
        Some("asupersync-fuzz-b:BlackDove:redis_resp3_map_invariants")
    );
}

#[test]
fn target_reserved_queue_matches_exact_reviewed_golden() {
    assert_queue_matches_exact_reviewed_golden(
        "target_reserved.json",
        "target_reserved_expected.json",
    );
}

#[test]
fn duplicate_manifest_and_proposal_targets_are_hard_blocks() {
    let receipt = queue_json("duplicate_targets.json");

    let already_in_manifest = row_by_id(
        &receipt,
        "asupersync-fuzz-a:MaroonBear:http_header_map_invariants",
    );
    assert_eq!(
        already_in_manifest["status"].as_str(),
        Some("blocked-duplicate-manifest-target")
    );

    let duplicate_proposal = row_by_id(
        &receipt,
        "asupersync-fuzz-c:CoralGorge:postgres_row_description_state",
    );
    assert_eq!(
        duplicate_proposal["status"].as_str(),
        Some("blocked-duplicate-proposal-target")
    );
    assert_eq!(receipt["summary"]["blocked_count"].as_u64(), Some(3));
    assert_eq!(
        receipt["source_counts"]["duplicate_target_names"].as_u64(),
        Some(1)
    );
}

#[test]
fn duplicate_targets_queue_matches_exact_reviewed_golden() {
    assert_queue_matches_exact_reviewed_golden(
        "duplicate_targets.json",
        "duplicate_targets_expected.json",
    );
}

#[test]
fn owned_manifest_and_target_reservations_allow_the_holder_to_proceed() {
    let receipt = queue_json("owned_and_expired_reservations.json");

    assert_eq!(
        receipt["manifest_reservation"]["status"].as_str(),
        Some("held-by-proposal-agent")
    );
    assert_eq!(
        receipt["manifest_reservation"]["holder"].as_str(),
        Some("MaroonBear")
    );
    let holder = row_by_id(
        &receipt,
        "asupersync-fuzz-a:MaroonBear:http_header_map_invariants",
    );
    assert_eq!(holder["queue_position"].as_u64(), Some(1));
    assert_eq!(
        holder["status"].as_str(),
        Some("ready-with-owned-manifest-reservation")
    );

    let other = row_by_id(
        &receipt,
        "asupersync-fuzz-b:BlackDove:redis_resp3_map_invariants",
    );
    assert_eq!(
        other["status"].as_str(),
        Some("wait-for-manifest-reservation")
    );
    assert_eq!(
        receipt["source_counts"]["active_reservations"].as_u64(),
        Some(2)
    );
}

#[test]
fn owned_and_expired_reservations_queue_matches_exact_reviewed_golden() {
    assert_queue_matches_exact_reviewed_golden(
        "owned_and_expired_reservations.json",
        "owned_and_expired_reservations_expected.json",
    );
}

#[test]
fn helper_declares_it_does_not_mutate_or_run_proofs() {
    let receipt = queue_json("clean_queue.json");

    assert_eq!(receipt["non_mutating"].as_bool(), Some(true));
    for key in [
        "edits_fuzz_manifest",
        "creates_fuzz_target",
        "runs_cargo",
        "runs_rch",
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
