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
    assert!(
        output.status.success(),
        "receipt helper failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str(&stdout)
        .unwrap_or_else(|error| panic!("receipt output not JSON: {error}\noutput: {stdout}"))
}

fn fixture_text(fixture: &str) -> String {
    std::fs::read_to_string(repo_root().join(FIXTURE_ROOT).join(fixture))
        .unwrap_or_else(|error| panic!("read golden fixture {fixture}: {error}"))
}

fn assert_receipt_output_matches_golden(
    input_fixture: &str,
    expected_fixture: &str,
    drift_message: &str,
) {
    let output = run_receipt(input_fixture);
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
        "parsed session handoff receipt JSON drifted for {input_fixture} -> {expected_fixture}"
    );
    assert_eq!(actual, expected, "{drift_message}");
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
    assert_receipt_output_matches_golden(
        "clean_tree.json",
        "clean_tree_expected.json",
        "clean_tree receipt drifted from the reviewed golden",
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
    assert_receipt_output_matches_golden(
        "dirty_peer_owned_tree.json",
        "dirty_peer_owned_tree_expected.json",
        "dirty_peer_owned_tree receipt drifted from the reviewed golden",
    );
}

#[test]
fn dirty_classifier_aliases_preserve_owner_and_action_fields() {
    let receipt = receipt_json("dirty_classifier_aliases.json");
    assert_eq!(next_action_category(&receipt), "avoid-peer-owned-surface");
    assert_eq!(
        receipt["next_action"]["path"].as_str(),
        Some("src/runtime/scheduler/swarm_evidence.rs")
    );

    let clusters = receipt["dirty_clusters"]
        .as_array()
        .expect("dirty_clusters must be array");
    let tracker = clusters
        .iter()
        .find(|cluster| cluster["cluster"].as_str() == Some("beads-tracker-state"))
        .expect("tracker cluster must be preserved from dirty-tree classifier aliases");
    assert_eq!(
        tracker["actions"][0].as_str(),
        Some("stage only with the matching bead work; do not mix unrelated tracker updates")
    );

    let peer = clusters
        .iter()
        .find(|cluster| cluster["cluster"].as_str() == Some("peer-owned/swarm-capacity"))
        .expect("peer source cluster must be preserved from dirty-tree classifier aliases");
    assert_eq!(
        peer["actions"][0].as_str(),
        Some("coordinate with RubyRobin before validation")
    );

    assert_eq!(
        receipt["reservation_snapshot"]["classifications"][0]["classification"].as_str(),
        Some("owned-active"),
        "current-agent tracker reservation must not be reported as a conflict"
    );
    assert_eq!(
        receipt["reservation_conflicts"][0]["path_pattern"].as_str(),
        Some("src/runtime/scheduler/swarm_evidence.rs")
    );
}

#[test]
fn dirty_classifier_aliases_output_matches_full_reviewed_golden() {
    assert_receipt_output_matches_golden(
        "dirty_classifier_aliases.json",
        "dirty_classifier_aliases_expected.json",
        "dirty classifier alias handoff receipt drifted from the reviewed golden",
    );
}

#[test]
fn dirty_rename_target_expands_source_and_target_paths() {
    let receipt = receipt_json("dirty_rename_target.json");
    assert_eq!(next_action_category(&receipt), "avoid-peer-owned-surface");
    assert_eq!(
        receipt["next_action"]["path"].as_str(),
        Some("docs/old-secret.rs")
    );

    let clusters = receipt["dirty_clusters"]
        .as_array()
        .expect("dirty_clusters must be array");
    let security_cluster = clusters
        .iter()
        .find(|cluster| cluster["cluster"].as_str() == Some("peer-owned/security-audit"))
        .expect("security rename cluster must be present");
    let paths: Vec<&str> = security_cluster["paths"]
        .as_array()
        .expect("cluster paths must be array")
        .iter()
        .map(|path| path.as_str().expect("cluster path must be string"))
        .collect();
    assert_eq!(paths, vec!["docs/old-secret.rs", "src/security/secret.rs"]);
    assert!(
        paths.iter().all(|path| !path.contains(" -> ")),
        "rename/copy rows must not leak literal arrow paths"
    );

    let literal_arrow_cluster = clusters
        .iter()
        .find(|cluster| cluster["cluster"].as_str() == Some("peer-owned/docs-arrow"))
        .expect("literal arrow cluster must be present");
    assert_eq!(
        literal_arrow_cluster["paths"][0].as_str(),
        Some("docs/name -> literal.md"),
        "ordinary non-rename paths containing arrows must be preserved"
    );
}

#[test]
fn dirty_rename_target_output_matches_full_reviewed_golden() {
    assert_receipt_output_matches_golden(
        "dirty_rename_target.json",
        "dirty_rename_target_expected.json",
        "dirty-rename-target handoff receipt drifted from the reviewed golden",
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
fn tracker_reservation_conflict_output_matches_full_reviewed_golden() {
    assert_receipt_output_matches_golden(
        "tracker_reservation_conflict.json",
        "tracker_reservation_conflict_expected.json",
        "tracker-reservation handoff receipt drifted from the reviewed golden",
    );
}

#[test]
fn tracker_directory_reservation_conflict_waits_before_claiming() {
    let receipt = receipt_json("tracker_directory_reservation_conflict.json");
    assert_eq!(next_action_category(&receipt), "wait-for-reservation");
    assert_eq!(
        receipt["next_action"]["path_pattern"].as_str(),
        Some(".beads")
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
fn tracker_directory_reservation_conflict_output_matches_full_reviewed_golden() {
    assert_receipt_output_matches_golden(
        "tracker_directory_reservation_conflict.json",
        "tracker_directory_reservation_conflict_expected.json",
        "tracker-directory-reservation handoff receipt drifted from the reviewed golden",
    );
}

#[test]
fn shared_tracker_reservation_does_not_block_ready_claim() {
    let probe = r#"
import json
import pathlib
import sys

repo = pathlib.Path(sys.argv[1])
sys.path.insert(0, str(repo / "scripts"))
import session_handoff_receipt as receipt

source = {
    "agent_mail": {
        "available": True,
        "reservations": [
            {
                "agent_name": "BlackDove",
                "exclusive": False,
                "expires_ts": "2999-01-01T00:00:00Z",
                "path_pattern": ".beads/issues.jsonl",
            }
        ],
        "status": "ok",
    },
    "beads": {
        "in_progress": [],
        "ready": [{"id": "asupersync-ready3", "title": "Ready with shared tracker observer"}],
        "status": "ok",
    },
    "dirty_tree": {"entries": []},
    "git": {"ahead": 0, "behind": 0, "branch": "main", "upstream": "origin/main"},
    "proof_runner": {"status": "ok", "suggested_lanes": []},
    "rch": {"available": True, "queue_summary": "queued=0 running=0"},
}

handoff = receipt.build_receipt(
    source=source,
    repo_path=str(repo),
    agent="CopperSpring",
    generated_at="2026-05-08T04:30:00Z",
    stale_after_hours=12,
)
print(json.dumps(handoff, sort_keys=True))
"#;
    let output = Command::new("python3")
        .arg("-c")
        .arg(probe)
        .arg(repo_root())
        .current_dir(repo_root())
        .output()
        .expect("run shared tracker reservation probe");
    assert!(
        output.status.success(),
        "python shared tracker reservation probe failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let receipt: Value = serde_json::from_slice(&output.stdout).expect("probe output must be JSON");
    assert_eq!(next_action_category(&receipt), "claim-ready-bead");
    assert_eq!(
        receipt["next_action"]["bead_id"].as_str(),
        Some("asupersync-ready3")
    );
    assert!(
        receipt["reservation_conflicts"]
            .as_array()
            .expect("reservation_conflicts must be array")
            .is_empty(),
        "shared tracker reservations are observation-only and must not block claiming"
    );
    assert_eq!(
        receipt["reservation_snapshot"]["classifications"][0]["classification"].as_str(),
        Some("shared-active")
    );
    assert_eq!(
        receipt["reservation_snapshot"]["classifications"][0]["exclusive"].as_bool(),
        Some(false)
    );
}

#[test]
fn tracker_write_lock_timeout_is_reported_without_mutation() {
    let receipt = receipt_json("write_lock_timeout.json");
    assert_eq!(next_action_category(&receipt), "blocked");
    assert_eq!(
        receipt["next_action"]["path"].as_str(),
        Some(".beads/.write.lock")
    );
    assert_eq!(receipt["next_action"]["size_bytes"].as_u64(), Some(0));
    assert_eq!(
        receipt["tracker_write_lock"]["mtime_utc"].as_str(),
        Some("2026-05-12T01:35:32Z")
    );
    assert_eq!(
        receipt["tracker_write_lock"]["exists"].as_bool(),
        Some(true)
    );
    assert_eq!(
        receipt["next_action"]["reason"].as_str(),
        Some(
            "beads write lock blocks tracker reads or writes; do not delete without explicit user approval"
        )
    );
}

#[test]
fn tracker_write_lock_timeout_output_matches_full_reviewed_golden() {
    assert_receipt_output_matches_golden(
        "write_lock_timeout.json",
        "write_lock_timeout_expected.json",
        "write-lock-timeout handoff receipt drifted from the reviewed golden",
    );
}

#[test]
fn clean_tracker_sync_preserves_ready_claim() {
    let receipt = receipt_json("tracker_sync_clean.json");
    assert_eq!(next_action_category(&receipt), "claim-ready-bead");
    assert_eq!(receipt["tracker_sync"]["blocked"].as_bool(), Some(false));
    assert_eq!(receipt["subsystems"]["tracker_sync"].as_str(), Some("ok"));
}

#[test]
fn clean_tracker_sync_output_matches_full_reviewed_golden() {
    assert_receipt_output_matches_golden(
        "tracker_sync_clean.json",
        "tracker_sync_clean_expected.json",
        "clean tracker-sync handoff receipt drifted from the reviewed golden",
    );
}

#[test]
fn tracker_sync_drift_blocks_claiming_or_creating_beads() {
    let receipt = receipt_json("tracker_sync_drift.json");
    assert_eq!(next_action_category(&receipt), "blocked");
    assert_eq!(
        receipt["next_action"]["reason"].as_str(),
        Some(
            "beads sync status is dirty or stale; repair DB/JSONL freshness before claiming or creating beads"
        )
    );
    assert_eq!(receipt["tracker_sync"]["blocked"].as_bool(), Some(true));
    assert_eq!(
        receipt["tracker_sync"]["blocking_flags"]
            .as_array()
            .expect("blocking flags must be array")
            .iter()
            .map(|value| value.as_str().expect("blocking flag must be string"))
            .collect::<Vec<_>>(),
        vec!["dirty_count", "jsonl_newer", "db_newer"]
    );
}

#[test]
fn tracker_sync_drift_output_matches_full_reviewed_golden() {
    assert_receipt_output_matches_golden(
        "tracker_sync_drift.json",
        "tracker_sync_drift_expected.json",
        "tracker-sync drift handoff receipt drifted from the reviewed golden",
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
fn no_agent_mail_output_matches_full_reviewed_golden() {
    assert_receipt_output_matches_golden(
        "no_agent_mail.json",
        "no_agent_mail_expected.json",
        "no-Agent-Mail handoff receipt drifted from the reviewed golden",
    );
}

#[test]
fn stale_in_progress_candidate_is_listed_without_mutation() {
    let receipt = receipt_json("stale_in_progress.json");
    assert_eq!(next_action_category(&receipt), "reopen-stale-bead");
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
    assert_eq!(
        receipt["next_action"]["bead_id"].as_str(),
        Some("asupersync-stale1")
    );
    assert_eq!(
        receipt["next_action"]["reason"].as_str(),
        Some("stale in-progress bead needs owner or reclaim review")
    );
}

#[test]
fn stale_in_progress_output_matches_full_reviewed_golden() {
    assert_receipt_output_matches_golden(
        "stale_in_progress.json",
        "stale_in_progress_expected.json",
        "stale-in-progress handoff receipt drifted from the reviewed golden",
    );
}

#[test]
fn stale_in_progress_without_proof_suggestions_recommends_reopen() {
    let receipt = receipt_json("stale_in_progress_no_proof.json");
    assert_eq!(next_action_category(&receipt), "reopen-stale-bead");
    assert_eq!(
        receipt["next_action"]["bead_id"].as_str(),
        Some("asupersync-stale1")
    );
    assert_eq!(
        receipt["next_action"]["assignee"].as_str(),
        Some("OlderAgent")
    );
    assert_eq!(
        receipt["next_action"]["reason"].as_str(),
        Some("stale in-progress bead needs owner or reclaim review")
    );
}

#[test]
fn stale_in_progress_no_proof_output_matches_full_reviewed_golden() {
    assert_receipt_output_matches_golden(
        "stale_in_progress_no_proof.json",
        "stale_in_progress_no_proof_expected.json",
        "stale-in-progress no-proof handoff receipt drifted from the reviewed golden",
    );
}

#[test]
fn stale_in_progress_missing_id_is_not_reopened() {
    let receipt = receipt_json("stale_in_progress_missing_id.json");
    assert_eq!(next_action_category(&receipt), "blocked");
    assert_eq!(
        receipt["next_action"]["reason"].as_str(),
        Some("no actionable ready bead or proof lane was found")
    );
    assert!(
        receipt["active_bead_ids"]["stale_in_progress"]
            .as_array()
            .expect("stale_in_progress must be array")
            .is_empty(),
        "malformed stale rows without ids must not become reclaim candidates"
    );
}

#[test]
fn stale_in_progress_missing_id_output_matches_full_reviewed_golden() {
    assert_receipt_output_matches_golden(
        "stale_in_progress_missing_id.json",
        "stale_in_progress_missing_id_expected.json",
        "stale-in-progress missing-id handoff receipt drifted from the reviewed golden",
    );
}

#[test]
fn epic_only_ready_queue_routes_to_fallback_selector() {
    let receipt = receipt_json("epic_only_ready.json");
    assert_eq!(next_action_category(&receipt), "proof-only");
    assert_eq!(
        receipt["next_action"]["reason"].as_str(),
        Some("ready queue only contains a non-claimable epic; run the fallback work selector")
    );
    assert_eq!(
        receipt["next_action"]["lane"].as_str(),
        Some("reservation-aware-work-finder")
    );
    assert_eq!(
        receipt["next_action"]["bead_id"].as_str(),
        Some("asupersync-lhx6m4")
    );
    assert_eq!(
        receipt["active_bead_ids"]["ready"][0].as_str(),
        Some("asupersync-lhx6m4")
    );
}

#[test]
fn source_peer_reservation_epic_only_routes_to_fallback_selector() {
    let receipt = receipt_json("source_peer_reservation_epic_only.json");
    assert_eq!(next_action_category(&receipt), "proof-only");
    assert_eq!(
        receipt["next_action"]["lane"].as_str(),
        Some("reservation-aware-work-finder")
    );
    assert_eq!(
        receipt["next_action"]["bead_id"].as_str(),
        Some("asupersync-lhx6m4")
    );

    let conflicts = receipt["reservation_conflicts"]
        .as_array()
        .expect("reservation_conflicts must be array");
    assert_eq!(conflicts.len(), 1);
    assert_eq!(conflicts[0]["classification"].as_str(), Some("peer-active"));
    assert_eq!(
        conflicts[0]["path_pattern"].as_str(),
        Some("src/grpc/server.rs")
    );
    assert_eq!(conflicts[0]["holder"].as_str(), Some("CalmSummit"));
}

#[test]
fn live_probe_preserves_object_shaped_ready_queue() {
    let probe = r#"
import json
import pathlib
import sys

repo = pathlib.Path(sys.argv[1])
sys.path.insert(0, str(repo / "scripts"))
import session_handoff_receipt as receipt

def fake_run_text(repo_path, command, timeout):
    if command == ["git", "branch", "--show-current"]:
        return "ok", "main"
    if command == ["git", "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"]:
        return "ok", "origin/main"
    if command == ["git", "rev-list", "--left-right", "--count", "origin/main...HEAD"]:
        return "ok", "0 0"
    if command == ["am", "file_reservations", "active", str(repo_path)]:
        return "ok", "No active reservations."
    if command == ["rch", "queue"]:
        return "ok", "queued=0 running=0"
    raise AssertionError(f"unexpected text command: {command!r}")

def fake_run_json(repo_path, command, timeout):
    if command == ["bash", "scripts/classify_dirty_tree.sh", "--json"]:
        return "ok", {"entries": [], "staged_count": 0, "unstaged_tracked_count": 0, "untracked_count": 0}
    if command == ["br", "ready", "--json"]:
        return "ok", {"issues": [
            {
                "id": "asupersync-lhx6m4",
                "issue_type": "epic",
                "title": "[idea-wizard] Swarm responsiveness and proof-lane autopilot",
            }
        ]}
    if command == ["br", "list", "--status", "in_progress", "--json"]:
        return "ok", {"issues": []}
    if command == ["br", "sync", "--status", "--json"]:
        return "ok", {"dirty_count": 0, "jsonl_newer": False, "db_newer": False, "jsonl_exists": True}
    if command[:3] == ["python3", "scripts/proof_runner.py", "--suggest-lanes"]:
        return "ok", {"suggested_lanes": []}
    raise AssertionError(f"unexpected json command: {command!r}")

receipt.run_text = fake_run_text
receipt.run_json = fake_run_json
source = receipt.live_probe(repo, 2.0)
handoff = receipt.build_receipt(
    source=source,
    repo_path=str(repo),
    agent="RubyRobin",
    generated_at="2026-05-08T04:30:00Z",
    stale_after_hours=12,
)
print(json.dumps(handoff, sort_keys=True))
"#;
    let output = Command::new("python3")
        .arg("-c")
        .arg(probe)
        .arg(repo_root())
        .current_dir(repo_root())
        .output()
        .expect("run handoff object-shaped ready probe");
    assert!(
        output.status.success(),
        "python object-shaped ready probe failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let receipt: Value = serde_json::from_slice(&output.stdout).expect("probe output must be JSON");
    assert_eq!(next_action_category(&receipt), "proof-only");
    assert_eq!(
        receipt["next_action"]["lane"].as_str(),
        Some("reservation-aware-work-finder")
    );
    assert_eq!(
        receipt["next_action"]["bead_id"].as_str(),
        Some("asupersync-lhx6m4")
    );
    assert_eq!(
        receipt["active_bead_ids"]["ready"][0].as_str(),
        Some("asupersync-lhx6m4"),
        "live br ready object output must not be collapsed to an empty ready queue"
    );
}

#[test]
fn source_peer_reservation_epic_only_output_matches_full_reviewed_golden() {
    assert_receipt_output_matches_golden(
        "source_peer_reservation_epic_only.json",
        "source_peer_reservation_epic_only_expected.json",
        "source-peer-reservation epic-only handoff receipt drifted from the reviewed golden",
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

#[test]
fn live_fallback_preserves_unstaged_porcelain_leading_status_space() {
    let probe = r#"
import json
import pathlib
import sys

repo = pathlib.Path(sys.argv[1])
sys.path.insert(0, str(repo / "scripts"))
import session_handoff_receipt as receipt

status, raw = receipt.run_text(
    repo,
    [
        "python3",
        "-c",
        "import sys; sys.stdout.write(' M fuzz/Cargo.toml\\n')",
    ],
    2.0,
)
print(json.dumps({
    "entries": receipt.parse_status_lines(raw),
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
        .expect("run handoff whitespace probe");
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
fn live_fallback_normalizes_non_rename_dirty_paths() {
    let probe = r#"
import json
import pathlib
import sys

repo = pathlib.Path(sys.argv[1])
sys.path.insert(0, str(repo / "scripts"))
import session_handoff_receipt as receipt

raw = "\n".join([
    " M ./src/channel/mod.rs",
    "?? ./tests/fixtures/session_handoff_receipt/",
])
print(json.dumps(receipt.parse_status_lines(raw), sort_keys=True))
"#;
    let output = Command::new("python3")
        .arg("-c")
        .arg(probe)
        .arg(repo_root())
        .current_dir(repo_root())
        .output()
        .expect("run handoff non-rename normalization probe");
    assert!(
        output.status.success(),
        "python non-rename normalization probe failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let entries: Value = serde_json::from_slice(&output.stdout).expect("probe output must be JSON");
    let paths: Vec<&str> = entries
        .as_array()
        .expect("probe entries must be array")
        .iter()
        .map(|entry| entry["path"].as_str().expect("entry path must be string"))
        .collect();
    assert_eq!(
        paths,
        vec![
            "src/channel/mod.rs",
            "tests/fixtures/session_handoff_receipt"
        ]
    );
}

#[test]
fn live_agent_mail_cli_reservation_rows_are_parsed_without_mutation() {
    let probe = r#"
import json
import pathlib
import sys

repo = pathlib.Path(sys.argv[1])
sys.path.insert(0, str(repo / "scripts"))
import session_handoff_receipt as receipt

raw = "\n".join([
    "  scripts/session_handoff_receipt.py [excl] by RubyRobin",
    "  docs/replay debugging.md [shared] by VioletBasin",
    "No active reservations.",
    "  malformed row without holder",
])

def fake_run_text(repo_path, command, timeout):
    return "ok", raw

receipt.run_text = fake_run_text
print(json.dumps(receipt.live_agent_mail_snapshot(repo, 2.0), sort_keys=True))
"#;
    let output = Command::new("python3")
        .arg("-c")
        .arg(probe)
        .arg(repo_root())
        .current_dir(repo_root())
        .output()
        .expect("run Agent Mail CLI reservation parser probe");
    assert!(
        output.status.success(),
        "python Agent Mail CLI parser probe failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let snapshot: Value =
        serde_json::from_slice(&output.stdout).expect("probe output must be JSON");
    assert_eq!(snapshot["available"].as_bool(), Some(true));
    assert_eq!(snapshot["status"].as_str(), Some("ok"));
    let rows = &snapshot["reservations"];
    let rows = rows.as_array().expect("reservation rows must be array");
    assert_eq!(rows.len(), 2);
    assert_eq!(
        rows[0]["path_pattern"].as_str(),
        Some("scripts/session_handoff_receipt.py")
    );
    assert_eq!(rows[0]["agent_name"].as_str(), Some("RubyRobin"));
    assert_eq!(rows[0]["exclusive"].as_bool(), Some(true));
    assert_eq!(
        rows[1]["path_pattern"].as_str(),
        Some("docs/replay debugging.md")
    );
    assert_eq!(rows[1]["agent_name"].as_str(), Some("VioletBasin"));
    assert_eq!(rows[1]["exclusive"].as_bool(), Some(false));
    assert_eq!(
        rows[1]["source"].as_str(),
        Some("am file_reservations active")
    );
}

#[test]
fn live_fallback_expands_rename_copy_rows_without_touching_literal_arrow_paths() {
    let probe = r#"
import json
import pathlib
import sys

repo = pathlib.Path(sys.argv[1])
sys.path.insert(0, str(repo / "scripts"))
import session_handoff_receipt as receipt

raw = "\n".join([
    "R  docs/old.md -> src/security/secret.rs",
    " M docs/name -> literal.md",
    "C  ./src/a.rs -> ./src/b.rs",
])
print(json.dumps(receipt.parse_status_lines(raw), sort_keys=True))
"#;
    let output = Command::new("python3")
        .arg("-c")
        .arg(probe)
        .arg(repo_root())
        .current_dir(repo_root())
        .output()
        .expect("run handoff rename/copy parser probe");
    assert!(
        output.status.success(),
        "python rename/copy probe failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let entries: Value = serde_json::from_slice(&output.stdout).expect("probe output must be JSON");
    let paths: Vec<&str> = entries
        .as_array()
        .expect("probe entries must be array")
        .iter()
        .map(|entry| entry["path"].as_str().expect("entry path must be string"))
        .collect();
    assert_eq!(
        paths,
        vec![
            "docs/old.md",
            "src/security/secret.rs",
            "docs/name -> literal.md",
            "src/a.rs",
            "src/b.rs"
        ]
    );
}
