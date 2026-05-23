//! Contract tests for the reservation-aware work finder helper.

#![allow(missing_docs)]

use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

const SCRIPT_PATH: &str = "scripts/reservation_aware_work_finder.py";
const FIXTURE_ROOT: &str = "tests/fixtures/reservation_aware_work_finder";
const GENERATED_AT: &str = "2026-05-10T09:05:00Z";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn run_finder_with_output(fixture: &str, output_format: &str) -> Output {
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
        .arg("--output")
        .arg(output_format)
        .current_dir(repo_root())
        .output()
        .expect("run reservation-aware work finder")
}

fn run_finder(fixture: &str) -> Output {
    run_finder_with_output(fixture, "json")
}

fn finder_json(fixture: &str) -> Value {
    let output = run_finder(fixture);
    assert!(
        output.status.success(),
        "finder helper failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("finder output must be JSON")
}

fn finder_markdown(fixture: &str) -> String {
    let output = run_finder_with_output(fixture, "markdown");
    assert!(
        output.status.success(),
        "finder helper failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("finder markdown must be UTF-8")
}

fn candidate<'a>(receipt: &'a Value, candidate_id: &str) -> &'a Value {
    receipt["candidates"]
        .as_array()
        .expect("candidates")
        .iter()
        .find(|row| row["candidate_id"].as_str() == Some(candidate_id))
        .expect("candidate id should exist")
}

fn fixture_json(fixture: &str) -> Value {
    let text = fs::read_to_string(repo_root().join(FIXTURE_ROOT).join(fixture))
        .expect("fixture JSON should be readable");
    serde_json::from_str(&text).expect("fixture must be valid JSON")
}

fn fixture_text(fixture: &str) -> String {
    fs::read_to_string(repo_root().join(FIXTURE_ROOT).join(fixture))
        .expect("fixture text should be readable")
}

#[test]
fn script_exists_and_help_is_non_mutating() {
    assert!(
        repo_root().join(SCRIPT_PATH).exists(),
        "work finder helper must exist at {SCRIPT_PATH}"
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
fn ready_bead_blocked_by_reservation_falls_back_to_safe_lane() {
    let receipt = finder_json("ready_bead_blocked.json");
    let blocked = candidate(&receipt, "asupersync-ready-blocked");

    assert_eq!(
        receipt["schema_version"].as_str(),
        Some("reservation-aware-work-finder-v1")
    );
    assert_eq!(blocked["status"].as_str(), Some("blocked"));
    assert_eq!(
        blocked["blockers"][0]["kind"].as_str(),
        Some("active-reservation")
    );
    assert_eq!(
        receipt["recommendation"]["category"].as_str(),
        Some("run-fallback-lane")
    );
    assert_eq!(
        receipt["recommendation"]["candidate_id"].as_str(),
        Some("mock-code-finder:src-http")
    );
}

#[test]
fn empty_queue_skips_peer_dirty_fuzz_target_and_recommends_mock_scan() {
    let receipt = finder_json("empty_queue_peer_dirty_fuzz.json");
    let dirty_fuzz = candidate(&receipt, "testing-fuzzing:h2_rst_stream");
    let blockers = dirty_fuzz["blockers"].as_array().expect("blockers");
    let dirty_blocker = blockers
        .iter()
        .find(|row| row["kind"].as_str() == Some("dirty-peer-path"))
        .expect("dirty peer path blocker");

    assert_eq!(dirty_blocker["kind"].as_str(), Some("dirty-peer-path"));
    assert_eq!(dirty_blocker["holder"].as_str(), Some("GentleCitadel"));
    assert_eq!(
        receipt["recommendation"]["candidate_id"].as_str(),
        Some("mock-code-finder:tests")
    );
}

#[test]
fn dirty_rename_target_blocks_candidate_surface() {
    let receipt = finder_json("rename_dirty_target.json");
    let renamed = candidate(&receipt, "mock-code-finder:renamed-target");
    let blocker = &renamed["blockers"][0];

    assert_eq!(renamed["status"].as_str(), Some("blocked"));
    assert_eq!(blocker["kind"].as_str(), Some("dirty-unattributed-path"));
    assert_eq!(
        blocker["path"].as_str(),
        Some("tests/fixtures/reservation_aware_work_finder/new_candidate.json")
    );
    assert_eq!(
        receipt["recommendation"]["candidate_id"].as_str(),
        Some("mock-code-finder:safe-script")
    );
}

#[test]
fn dirty_tracker_blocks_tracker_mutating_ready_bead() {
    let receipt = finder_json("tracker_dirty_ready_bead.json");
    let tracker_claim = candidate(&receipt, "asupersync-ready-needs-dirty-tracker");
    let source_only = candidate(&receipt, "mock-code-finder:safe-script");
    let blockers = tracker_claim["blockers"].as_array().expect("blockers");
    let tracker_blocker = blockers
        .iter()
        .find(|row| row["kind"].as_str() == Some("tracker-dirty-peer-path"))
        .expect("tracker dirty blocker");

    assert_eq!(tracker_claim["status"].as_str(), Some("blocked"));
    assert_eq!(
        tracker_blocker["path"].as_str(),
        Some(".beads/issues.jsonl")
    );
    assert_eq!(tracker_blocker["holder"].as_str(), Some("PlumCreek"));
    assert_eq!(tracker_blocker["source"].as_str(), Some("dirty-entry"));
    assert_eq!(
        tracker_blocker["reason"].as_str(),
        Some("candidate requires a Beads tracker mutation while a tracker path is already dirty")
    );
    assert_eq!(
        tracker_claim["files_to_reserve"][0].as_str(),
        Some(".beads/issues.jsonl")
    );

    assert_eq!(source_only["status"].as_str(), Some("ready-fallback"));
    assert_eq!(
        receipt["recommendation"]["category"].as_str(),
        Some("run-fallback-lane")
    );
    assert_eq!(
        receipt["recommendation"]["candidate_id"].as_str(),
        Some("mock-code-finder:safe-script")
    );
    assert!(
        receipt["recommendation"]["safety_reason"]
            .as_str()
            .expect("safety reason")
            .contains("no tracker mutation required")
    );
}

#[test]
fn clean_workspace_selects_highest_priority_fallback_candidate() {
    let receipt = finder_json("clean_workspace_candidates.json");

    assert_eq!(receipt["summary"]["ready_count"].as_u64(), Some(2));
    assert_eq!(
        receipt["recommendation"]["category"].as_str(),
        Some("run-fallback-lane")
    );
    assert_eq!(
        receipt["recommendation"]["candidate_id"].as_str(),
        Some("testing-fuzzing:postgres_row_description")
    );
    assert_eq!(
        receipt["recommendation"]["paths"][0].as_str(),
        Some("fuzz/fuzz_targets/postgres_row_description.rs")
    );
}

#[test]
fn healthy_disk_keeps_rch_heavy_fallback_work_allowed() {
    let receipt = finder_json("disk_pressure_healthy.json");
    let rch_candidate = candidate(&receipt, "testing-fuzzing:healthy-rch-proof");

    assert_eq!(receipt["disk_pressure"]["level"].as_str(), Some("green"));
    assert_eq!(
        receipt["disk_pressure"]["rch_heavy_work_allowed"].as_bool(),
        Some(true)
    );
    assert_eq!(rch_candidate["status"].as_str(), Some("ready-fallback"));
    assert_eq!(
        receipt["recommendation"]["candidate_id"].as_str(),
        Some("testing-fuzzing:healthy-rch-proof")
    );
}

#[test]
fn low_disk_surfaces_pressure_but_does_not_block_rch_work() {
    let receipt = finder_json("disk_pressure_low.json");
    let rch_candidate = candidate(&receipt, "testing-fuzzing:low-disk-rch-proof");

    assert_eq!(receipt["disk_pressure"]["level"].as_str(), Some("low"));
    assert_eq!(
        receipt["disk_pressure"]["available_bytes"].as_u64(),
        Some(2_147_483_648)
    );
    assert_eq!(
        receipt["disk_pressure"]["rch_heavy_work_allowed"].as_bool(),
        Some(true)
    );
    assert_eq!(rch_candidate["status"].as_str(), Some("ready-fallback"));
}

#[test]
fn critical_disk_blocks_rch_heavy_and_prefers_no_build_fallback() {
    let receipt = finder_json("disk_pressure_critical_no_ballast.json");
    let rch_candidate = candidate(&receipt, "testing-fuzzing:critical-rch-proof");
    let source_only = candidate(&receipt, "mock-code-finder:source-only-scan");

    assert_eq!(receipt["disk_pressure"]["level"].as_str(), Some("critical"));
    assert_eq!(
        receipt["disk_pressure"]["rch_heavy_work_allowed"].as_bool(),
        Some(false)
    );
    assert_eq!(rch_candidate["status"].as_str(), Some("blocked"));
    assert!(
        rch_candidate["blockers"]
            .as_array()
            .expect("blockers")
            .iter()
            .any(|blocker| blocker["kind"].as_str() == Some("critical-disk-pressure-rch-heavy"))
    );
    assert_eq!(source_only["status"].as_str(), Some("ready-fallback"));
    assert_eq!(
        receipt["recommendation"]["candidate_id"].as_str(),
        Some("mock-code-finder:source-only-scan")
    );
    assert_eq!(
        receipt["disk_pressure"]["non_build_fallback_candidates"][0]["candidate_id"].as_str(),
        Some("mock-code-finder:source-only-scan")
    );
}

#[test]
fn critical_disk_without_safe_work_recommends_cleanup_authorization() {
    let receipt = finder_json("disk_pressure_critical_stale_targets.json");
    let rch_candidate = candidate(&receipt, "testing-fuzzing:critical-rch-only");

    assert_eq!(rch_candidate["status"].as_str(), Some("blocked"));
    assert_eq!(
        receipt["recommendation"]["category"].as_str(),
        Some("request-cleanup-authorization")
    );
    assert_eq!(
        receipt["recommendation"]["candidate_id"].as_str(),
        Some("stale-rch-target-large")
    );
    assert_eq!(
        receipt["disk_pressure"]["cleanup_candidates"][0]["path"].as_str(),
        Some("/tmp/rch_target_stale_large")
    );
    assert_eq!(
        receipt["disk_pressure"]["cleanup_candidates"][0]["requires_authorization"].as_bool(),
        Some(true)
    );
    assert!(
        receipt["disk_pressure"]["cleanup_candidates"][0]["delete_command"].is_null(),
        "cleanup candidates must not include deletion commands"
    );
}

#[test]
fn disk_pressure_autopilot_e2e_fixture_matches_closeout_handoff_golden() {
    let receipt = finder_json("disk_pressure_autopilot_e2e.json");
    let expected = fixture_json("disk_pressure_autopilot_e2e_expected_handoff.json");
    let rch_candidate = candidate(&receipt, "testing-fuzzing:critical-rch-only");

    assert_eq!(receipt["closeout_handoff"], expected);
    assert_eq!(receipt["disk_pressure"]["level"].as_str(), Some("critical"));
    assert_eq!(
        receipt["recommendation"]["category"].as_str(),
        Some("run-fallback-lane")
    );
    assert_eq!(
        receipt["recommendation"]["candidate_id"].as_str(),
        Some("testing-golden-artifacts:source-only-handoff")
    );
    assert!(
        rch_candidate["blockers"]
            .as_array()
            .expect("blockers")
            .iter()
            .any(|blocker| blocker["kind"].as_str() == Some("critical-disk-pressure-rch-heavy"))
    );
    assert_eq!(
        receipt["closeout_handoff"]["active_dirty_paths"][0]["path"].as_str(),
        Some("fuzz/fuzz_targets/websocket_frame_fuzzing.rs")
    );
    assert!(
        receipt["closeout_handoff"]["cleanup_candidates"][0]["delete_command"].is_null(),
        "handoff cleanup candidates must not include deletion commands"
    );
    assert_eq!(
        receipt["closeout_handoff"]["authorization"]
            ["cleanup_requires_explicit_user_authorization"]
            .as_bool(),
        Some(true)
    );
}

#[test]
fn markdown_dashboard_disk_red_fixture_matches_golden() {
    let markdown = finder_markdown("disk_pressure_autopilot_e2e.json");
    let expected = fixture_text("swarm_dashboard_disk_red_expected.md");

    assert_eq!(markdown, expected);
    assert!(markdown.contains("| disk level | `critical` |"));
    assert!(markdown.contains("testing-golden-artifacts:source-only-handoff"));
    assert!(markdown.contains("No stale in-progress issues in snapshot."));
    assert!(markdown.contains("| `rch_target_stale_large` |"));
    assert!(
        !markdown.contains("rm -rf"),
        "dashboard must not emit cleanup commands"
    );
}

#[test]
fn markdown_dashboard_reports_stale_in_progress_without_actions() {
    let markdown = finder_markdown("stale_in_progress_tracker_lock.json");
    let expected = fixture_text("stale_in_progress_tracker_lock_expected.md");

    assert_eq!(markdown, expected);
    assert!(markdown.contains("asupersync-stale-agent"));
    assert!(markdown.contains("coordinate-before-reopen-or-force-release"));
    assert!(markdown.contains("| `asupersync-stale-agent` | DormantAgent | 140 |"));
    assert!(markdown.contains("| mutating commands executed | no |"));
    assert!(markdown.contains("| beads mutated | no |"));
    assert!(
        !markdown.contains("force_release_performed=true"),
        "dashboard must report stale work without performing force-release"
    );
}

#[test]
fn pathless_epic_ready_queue_falls_through_to_fallback_candidate() {
    let receipt = finder_json("epic_queue_fallback.json");
    let epic = candidate(&receipt, "asupersync-lhx6m4");

    assert_eq!(epic["status"].as_str(), Some("blocked"));
    assert_eq!(
        epic["blockers"][0]["kind"].as_str(),
        Some("non-shippable-epic")
    );
    assert_eq!(
        receipt["recommendation"]["category"].as_str(),
        Some("run-fallback-lane")
    );
    assert_eq!(
        receipt["recommendation"]["candidate_id"].as_str(),
        Some("testing-conformance-harnesses:session-closeout")
    );
}

#[test]
fn pathless_epic_without_snapshot_uses_default_fallback_catalog() {
    let receipt = finder_json("epic_queue_default_fallback.json");
    let epic = candidate(&receipt, "asupersync-lhx6m4");
    let fallback = candidate(
        &receipt,
        "testing-conformance-harnesses:session-handoff-receipt",
    );

    assert_eq!(epic["status"].as_str(), Some("blocked"));
    assert_eq!(
        epic["blockers"][0]["kind"].as_str(),
        Some("non-shippable-epic")
    );
    assert_eq!(fallback["status"].as_str(), Some("ready-fallback"));
    assert_eq!(
        receipt["recommendation"]["candidate_id"].as_str(),
        Some("testing-conformance-harnesses:session-handoff-receipt")
    );
    assert!(
        !fallback["proof_commands"]
            .as_array()
            .expect("proof commands")
            .is_empty(),
        "default fallback candidates should carry validation expectations"
    );
    assert!(
        fallback["proof_commands"]
            .as_array()
            .expect("proof commands")
            .iter()
            .filter_map(Value::as_str)
            .any(|command| command
                .starts_with("RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=")),
        "default Cargo fallback proof commands must require remote rch"
    );
}

#[test]
fn completed_default_fallback_is_skipped_for_next_safe_candidate() {
    let receipt = finder_json("epic_queue_completed_overlap.json");
    let epic = candidate(&receipt, "asupersync-vjc3pv");
    let completed = candidate(
        &receipt,
        "testing-conformance-harnesses:session-handoff-receipt",
    );
    let blockers = completed["blockers"].as_array().expect("blockers");
    let completion_blocker = blockers
        .iter()
        .find(|row| row["kind"].as_str() == Some("fallback-already-completed"))
        .expect("completed-work blocker");

    assert_eq!(epic["status"].as_str(), Some("blocked"));
    assert_eq!(
        epic["blockers"][0]["kind"].as_str(),
        Some("non-shippable-epic")
    );
    assert_eq!(completed["status"].as_str(), Some("blocked"));
    assert_eq!(
        completion_blocker["closed_issue_id"].as_str(),
        Some("asupersync-c8thc8.11")
    );
    assert_eq!(
        completion_blocker["reason"].as_str(),
        Some("fallback candidate overlaps previously closed Beads work")
    );
    assert_eq!(
        receipt["recommendation"]["candidate_id"].as_str(),
        Some("testing-golden-artifacts:proof-receipt-inventory")
    );
    assert_eq!(
        receipt["recommendation"]["category"].as_str(),
        Some("run-fallback-lane")
    );
    assert_eq!(
        receipt["safety"]["beads_mutated"].as_bool(),
        Some(false),
        "overlap detection must remain report-only"
    );
}

#[test]
fn recent_commit_subjects_block_completed_default_fallbacks() {
    let receipt = finder_json("recent_commit_completed_fallback.json");
    let handoff = candidate(
        &receipt,
        "testing-conformance-harnesses:session-handoff-receipt",
    );
    let proof_receipt = candidate(&receipt, "testing-golden-artifacts:proof-receipt-inventory");
    let proof_runner = candidate(&receipt, "mock-code-finder:proof-runner-contracts");

    assert_eq!(receipt["summary"]["ready_count"].as_u64(), Some(0));
    assert_eq!(handoff["status"].as_str(), Some("blocked"));
    assert_eq!(proof_receipt["status"].as_str(), Some("blocked"));
    assert_eq!(proof_runner["status"].as_str(), Some("blocked"));

    let proof_receipt_blocker = proof_receipt["blockers"]
        .as_array()
        .expect("proof receipt blockers")
        .iter()
        .find(|row| row["kind"].as_str() == Some("fallback-already-completed"))
        .expect("proof receipt completion blocker");
    assert_eq!(
        proof_receipt_blocker["closed_issue_id"].as_str(),
        Some("efb254d06")
    );
    assert_eq!(
        proof_receipt_blocker["matched_alias"].as_str(),
        Some("harden proof receipt safety cues")
    );

    let proof_runner_blocker = proof_runner["blockers"]
        .as_array()
        .expect("proof runner blockers")
        .iter()
        .find(|row| row["kind"].as_str() == Some("fallback-already-completed"))
        .expect("proof runner completion blocker");
    assert_eq!(
        proof_runner_blocker["closed_issue_id"].as_str(),
        Some("9f4978b1d")
    );
    assert_eq!(
        proof_runner_blocker["matched_alias"].as_str(),
        Some("block unsafe proof runner fallback commands")
    );
    assert_eq!(
        receipt["recommendation"]["category"].as_str(),
        Some("blocked-no-safe-work")
    );
}

#[test]
fn unapproved_fallback_lane_is_blocked_by_policy() {
    let receipt = finder_json("unapproved_lane.json");
    let custom_scan = candidate(&receipt, "custom-scan:src");
    let bare_cargo = candidate(&receipt, "testing-fuzzing:bare-cargo-proof");

    assert_eq!(custom_scan["status"].as_str(), Some("blocked"));
    assert_eq!(
        custom_scan["blockers"][0]["kind"].as_str(),
        Some("unapproved-fallback-lane")
    );
    assert_eq!(bare_cargo["status"].as_str(), Some("blocked"));
    assert_eq!(
        bare_cargo["blockers"][0]["kind"].as_str(),
        Some("unsafe-proof-command")
    );
    assert_eq!(
        bare_cargo["blockers"][0]["token"].as_str(),
        Some("bare-cargo")
    );
    assert_eq!(
        receipt["recommendation"]["category"].as_str(),
        Some("blocked-no-safe-work")
    );
}

#[test]
fn stale_in_progress_is_report_only_and_tracker_lock_blocks_claim() {
    let receipt = finder_json("stale_in_progress_tracker_lock.json");
    let tracker_claim = candidate(&receipt, "asupersync-ready-needs-tracker");
    let source_only = candidate(&receipt, "mock-code-finder:source-only-finder");

    assert_eq!(receipt["tracker_lock"]["active"].as_bool(), Some(true));
    assert_eq!(
        receipt["tracker_lock"]["holder"].as_str(),
        Some("BoldTower")
    );
    assert_eq!(tracker_claim["status"].as_str(), Some("blocked"));
    assert!(
        tracker_claim["blockers"]
            .as_array()
            .expect("blockers")
            .iter()
            .any(|blocker| blocker["kind"].as_str() == Some("tracker-active-reservation"))
    );
    assert_eq!(
        tracker_claim["files_to_reserve"][0].as_str(),
        Some(".beads/issues.jsonl")
    );

    assert_eq!(source_only["status"].as_str(), Some("ready-fallback"));
    assert_eq!(
        source_only["validation_class"].as_str(),
        Some("source-only")
    );
    assert_eq!(
        source_only["files_to_reserve"][0].as_str(),
        Some("scripts/reservation_aware_work_finder.py")
    );
    assert!(
        source_only["blockers"]
            .as_array()
            .expect("blockers")
            .is_empty(),
        "expired reservations must not block a source-only fallback"
    );

    assert_eq!(
        receipt["recommendation"]["candidate_id"].as_str(),
        Some("mock-code-finder:source-only-finder")
    );
    assert_eq!(
        receipt["recommendation"]["validation_class"].as_str(),
        Some("source-only")
    );
    assert_eq!(
        receipt["recommendation"]["files_to_reserve"][0].as_str(),
        Some("scripts/reservation_aware_work_finder.py")
    );
    assert!(
        receipt["recommendation"]["safety_reason"]
            .as_str()
            .expect("safety reason")
            .contains("no tracker mutation required")
    );

    let stale = receipt["stale_in_progress"].as_array().expect("stale rows");
    assert_eq!(stale.len(), 1);
    assert_eq!(stale[0]["id"].as_str(), Some("asupersync-stale-agent"));
    assert_eq!(stale[0]["owner"].as_str(), Some("DormantAgent"));
    assert_eq!(
        stale[0]["recommended_action"].as_str(),
        Some("coordinate-before-reopen-or-force-release")
    );
    assert_eq!(stale[0]["requires_explicit_action"].as_bool(), Some(true));
    assert_eq!(stale[0]["force_release_performed"].as_bool(), Some(false));
    assert_eq!(stale[0]["reopen_performed"].as_bool(), Some(false));
    assert_eq!(
        receipt["summary"]["stale_in_progress_count"].as_u64(),
        Some(1)
    );
}

#[test]
fn coordination_churn_governor_rolls_up_mail_tracker_stale_and_dirty_state() {
    let receipt = finder_json("coordination_churn_governor.json");
    let churn = &receipt["coordination_churn"];

    assert_eq!(
        churn["schema_version"].as_str(),
        Some("coordination-churn-governor-v1")
    );
    assert_eq!(churn["active_agent_count"].as_u64(), Some(3));
    assert_eq!(churn["ack_required_backlog_count"].as_u64(), Some(2));
    assert_eq!(churn["tracker_lock_state"]["active"].as_bool(), Some(true));
    assert_eq!(
        churn["tracker_lock_state"]["holder"].as_str(),
        Some("RubyRobin")
    );
    assert_eq!(churn["stale_in_progress_count"].as_u64(), Some(1));
    assert_eq!(churn["max_stale_issue_age_minutes"].as_u64(), Some(180));
    assert_eq!(churn["peer_dirty_path_count"].as_u64(), Some(2));
    assert_eq!(churn["source_only_safe_to_proceed"].as_bool(), Some(true));
    assert_eq!(
        churn["recommended_next_action"].as_str(),
        Some("ack-required-mail-before-new-work")
    );
    assert_eq!(
        churn["stale_work_action"].as_str(),
        Some("coordinate-before-reopen-or-force-release")
    );
    assert_eq!(
        churn["required_reservations"][0].as_str(),
        Some("scripts/reservation_aware_work_finder.py")
    );
    assert_eq!(churn["mutations_performed"]["beads"].as_bool(), Some(false));
    assert_eq!(
        churn["mutations_performed"]["agent_mail"].as_bool(),
        Some(false)
    );
    assert_eq!(
        churn["mutations_performed"]["force_release"].as_bool(),
        Some(false)
    );
    assert_eq!(
        churn["mutations_performed"]["reopen"].as_bool(),
        Some(false)
    );
}

#[test]
fn stale_in_progress_owned_by_active_agent_recommends_owner_coordination_first() {
    let receipt = finder_json("stale_in_progress_active_owner.json");
    let stale = receipt["stale_in_progress"].as_array().expect("stale rows");
    let active = stale
        .iter()
        .find(|row| row["id"].as_str() == Some("asupersync-active-stale"))
        .expect("active-owner stale row");
    let dormant = stale
        .iter()
        .find(|row| row["id"].as_str() == Some("asupersync-dormant-stale"))
        .expect("dormant-owner stale row");

    assert_eq!(stale.len(), 2);
    assert_eq!(active["owner"].as_str(), Some("ActiveAgent"));
    assert_eq!(active["owner_active"].as_bool(), Some(true));
    assert_eq!(
        active["recommended_action"].as_str(),
        Some("message-active-owner-before-reopen")
    );
    assert_eq!(active["force_release_performed"].as_bool(), Some(false));
    assert_eq!(active["reopen_performed"].as_bool(), Some(false));

    assert_eq!(dormant["owner"].as_str(), Some("DormantAgent"));
    assert_eq!(dormant["owner_active"].as_bool(), Some(false));
    assert_eq!(
        dormant["recommended_action"].as_str(),
        Some("coordinate-before-reopen-or-force-release")
    );
    assert_eq!(
        receipt["coordination_churn"]["active_agent_count"].as_u64(),
        Some(1)
    );
}

#[test]
fn markdown_dashboard_reports_coordination_churn_governor() {
    let markdown = finder_markdown("coordination_churn_governor.json");
    let expected = fixture_text("coordination_churn_governor_expected.md");

    assert_eq!(markdown, expected);
    assert!(markdown.contains("## Coordination Churn"));
    assert!(markdown.contains("| ack-required backlog | 2 |"));
    assert!(markdown.contains("| next action | `ack-required-mail-before-new-work` |"));
    assert!(markdown.contains("| source-only safe | yes |"));
}

#[test]
fn proof_command_rch_routing_rejects_shell_prefix_spoofing() {
    let probe = r#"
import json
import pathlib
import sys

repo = pathlib.Path(sys.argv[1])
sys.path.insert(0, str(repo / "scripts"))
import reservation_aware_work_finder as finder

commands = {
    "safe_remote_required": "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_finder cargo test -p asupersync --test reservation_aware_work_finder_contract",
    "safe_remote_with_allowlist": "RCH_ENV_ALLOWLIST=CARGO_TARGET_DIR RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_finder cargo test -p asupersync --test reservation_aware_work_finder_contract",
    "missing_remote_required": "rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_finder cargo test -p asupersync --test reservation_aware_work_finder_contract",
    "missing_target_dir": "RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p asupersync --test reservation_aware_work_finder_contract",
    "spoofed_prefix": "echo rch exec --; cargo test -p asupersync",
    "nested_shell": "rch exec -- sh -c 'cargo test -p asupersync'",
    "bare_cargo": "cargo test -p asupersync",
    "no_cargo": "python3 -m py_compile scripts/reservation_aware_work_finder.py",
}
print(json.dumps({
    key: finder.command_routes_cargo_through_rch(command)
    for key, command in commands.items()
}, sort_keys=True))
"#;
    let output = Command::new("python3")
        .arg("-c")
        .arg(probe)
        .arg(repo_root())
        .current_dir(repo_root())
        .output()
        .expect("run proof-command routing probe");
    assert!(
        output.status.success(),
        "python routing probe failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let receipt: Value = serde_json::from_slice(&output.stdout).expect("probe output must be JSON");
    assert_eq!(receipt["safe_remote_required"].as_bool(), Some(true));
    assert_eq!(receipt["safe_remote_with_allowlist"].as_bool(), Some(true));
    assert_eq!(receipt["missing_remote_required"].as_bool(), Some(false));
    assert_eq!(receipt["missing_target_dir"].as_bool(), Some(false));
    assert_eq!(receipt["spoofed_prefix"].as_bool(), Some(false));
    assert_eq!(receipt["nested_shell"].as_bool(), Some(false));
    assert_eq!(receipt["bare_cargo"].as_bool(), Some(false));
    assert_eq!(receipt["no_cargo"].as_bool(), Some(true));
}

#[test]
fn proof_command_blockers_reject_rch_local_fallback_evidence() {
    let probe = r#"
import json
import pathlib
import sys

repo = pathlib.Path(sys.argv[1])
sys.path.insert(0, str(repo / "scripts"))
import reservation_aware_work_finder as finder

candidate = {
    "proof_commands": [
        "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_finder cargo test -p asupersync --test reservation_aware_work_finder_contract\n[RCH] local (daemon unavailable)",
        "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_finder cargo check -p asupersync\nfalling back to local execution",
        "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_finder cargo fmt --check\nlocal fallback selected",
        "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_finder cargo clippy -p asupersync --test reservation_aware_work_finder_contract\nfallback to local execution",
        "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_finder cargo test -p asupersync --test reservation_aware_work_finder_contract\nexecuting locally after remote failure",
    ],
}
print(json.dumps(finder.proof_command_blockers(candidate), sort_keys=True))
"#;
    let output = Command::new("python3")
        .arg("-c")
        .arg(probe)
        .arg(repo_root())
        .current_dir(repo_root())
        .output()
        .expect("run rch local fallback proof blocker probe");
    assert!(
        output.status.success(),
        "python fallback probe failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let blockers: Value =
        serde_json::from_slice(&output.stdout).expect("probe output must be JSON");
    let blockers = blockers.as_array().expect("blockers array");
    assert_eq!(blockers.len(), 5);
    assert!(blockers.iter().all(|blocker| {
        blocker["kind"].as_str() == Some("rch-local-fallback-proof-command")
            && blocker["token"].as_str() == Some("rch-local-fallback")
    }));
    assert_eq!(
        blockers[0]["reason"].as_str(),
        Some("proof command evidence reports rch local fallback")
    );
}

#[test]
fn helper_declares_no_mutating_side_effects() {
    let receipt = finder_json("clean_workspace_candidates.json");

    for key in [
        "mutating_commands_executed",
        "beads_mutated",
        "agent_mail_mutated",
        "cargo_executed",
        "branch_or_worktree_operations",
    ] {
        assert_eq!(
            receipt["safety"][key].as_bool(),
            Some(false),
            "{key} must stay false"
        );
    }
    assert_eq!(
        receipt["safety"]["forbidden_command_tokens"]
            .as_array()
            .expect("forbidden tokens")
            .len(),
        0
    );
}

#[test]
fn live_probe_preserves_unstaged_porcelain_leading_status_space() {
    let probe = r#"
import json
import pathlib
import sys

repo = pathlib.Path(sys.argv[1])
sys.path.insert(0, str(repo / "scripts"))
import reservation_aware_work_finder as finder

status, raw = finder.run_text(
    repo,
    [
        "python3",
        "-c",
        "import sys; sys.stdout.write(' M fuzz/Cargo.toml\\n')",
    ],
    2.0,
)
print(json.dumps({
    "entries": finder.parse_status_lines(raw),
    "raw": raw,
    "status": status,
}, sort_keys=True))
"#;
    let output = Command::new("python3")
        .arg("-c")
        .arg(probe)
        .arg(repo_root())
        .current_dir(repo_root())
        .output()
        .expect("run live probe whitespace check");
    assert!(
        output.status.success(),
        "python whitespace probe failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let receipt: Value = serde_json::from_slice(&output.stdout).expect("probe output must be JSON");
    assert_eq!(receipt["status"].as_str(), Some("ok"));
    assert_eq!(receipt["raw"].as_str(), Some(" M fuzz/Cargo.toml"));
    assert_eq!(receipt["entries"][0]["status"].as_str(), Some(" M"));
    assert_eq!(
        receipt["entries"][0]["path"].as_str(),
        Some("fuzz/Cargo.toml")
    );
}

#[test]
fn live_probe_expands_porcelain_rename_source_and_target_paths() {
    let probe = r#"
import json
import pathlib
import sys

repo = pathlib.Path(sys.argv[1])
sys.path.insert(0, str(repo / "scripts"))
import reservation_aware_work_finder as finder

entries = finder.parse_status_lines(
    "R  tests/old_fixture.json -> tests/fixtures/reservation_aware_work_finder/new_candidate.json\n"
)
print(json.dumps({"entries": entries}, sort_keys=True))
"#;
    let output = Command::new("python3")
        .arg("-c")
        .arg(probe)
        .arg(repo_root())
        .current_dir(repo_root())
        .output()
        .expect("run live probe rename expansion check");
    assert!(
        output.status.success(),
        "python rename probe failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let receipt: Value = serde_json::from_slice(&output.stdout).expect("probe output must be JSON");
    let entries = receipt["entries"].as_array().expect("entries array");
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0]["status"].as_str(), Some("R "));
    assert_eq!(entries[0]["path"].as_str(), Some("tests/old_fixture.json"));
    assert_eq!(
        entries[1]["path"].as_str(),
        Some("tests/fixtures/reservation_aware_work_finder/new_candidate.json")
    );
}
