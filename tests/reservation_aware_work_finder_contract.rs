//! Contract tests for the reservation-aware work finder helper.

#![allow(missing_docs)]

use serde_json::Value;
use std::path::PathBuf;
use std::process::{Command, Output};

const SCRIPT_PATH: &str = "scripts/reservation_aware_work_finder.py";
const FIXTURE_ROOT: &str = "tests/fixtures/reservation_aware_work_finder";
const GENERATED_AT: &str = "2026-05-10T09:05:00Z";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn run_finder(fixture: &str) -> Output {
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
        .arg("json")
        .current_dir(repo_root())
        .output()
        .expect("run reservation-aware work finder")
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

fn candidate<'a>(receipt: &'a Value, candidate_id: &str) -> &'a Value {
    receipt["candidates"]
        .as_array()
        .expect("candidates")
        .iter()
        .find(|row| row["candidate_id"].as_str() == Some(candidate_id))
        .expect("candidate id should exist")
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
}

#[test]
fn unapproved_fallback_lane_is_blocked_by_policy() {
    let receipt = finder_json("unapproved_lane.json");
    let candidate = candidate(&receipt, "custom-scan:src");

    assert_eq!(candidate["status"].as_str(), Some("blocked"));
    assert_eq!(
        candidate["blockers"][0]["kind"].as_str(),
        Some("unapproved-fallback-lane")
    );
    assert_eq!(
        receipt["recommendation"]["category"].as_str(),
        Some("blocked-no-safe-work")
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
