//! Contract tests for the shared-main swarm heatmap helper.

#![allow(missing_docs)]

use serde_json::Value;
use std::path::PathBuf;
use std::process::{Command, Output};

const SCRIPT_PATH: &str = "scripts/swarm_heatmap.py";
const FIXTURE_ROOT: &str = "tests/fixtures/swarm_heatmap";
const GENERATED_AT: &str = "2026-05-10T08:50:00Z";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn run_heatmap(fixture: &str) -> Output {
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
        .expect("run swarm heatmap helper")
}

fn heatmap_json(fixture: &str) -> Value {
    let output = run_heatmap(fixture);
    assert!(
        output.status.success(),
        "heatmap helper failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("heatmap output must be JSON")
}

#[test]
fn script_exists_and_help_is_non_mutating() {
    assert!(
        repo_root().join(SCRIPT_PATH).exists(),
        "heatmap helper must exist at {SCRIPT_PATH}"
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
fn overlapping_reservations_are_visible_and_stable() {
    let heatmap = heatmap_json("overlapping_reservations.json");
    let overlap = &heatmap["reservations"]["overlaps"][0];

    assert_eq!(heatmap["schema_version"].as_str(), Some("swarm-heatmap-v1"));
    assert_eq!(heatmap["current_date"].as_str(), Some("2026-05-10"));
    assert_eq!(heatmap["summary"]["active_reservations"].as_u64(), Some(2));
    assert_eq!(overlap["left_holder"].as_str(), Some("BlueMesa"));
    assert_eq!(overlap["right_holder"].as_str(), Some("GentleCitadel"));
    assert_eq!(overlap["severity"].as_str(), Some("warning"));
    assert_eq!(
        heatmap["suggested_stay_off_surfaces"][0]["path"].as_str(),
        Some("src/http/**")
    );
}

#[test]
fn expired_reservations_do_not_create_stay_off_surfaces() {
    let heatmap = heatmap_json("expired_reservations.json");

    assert_eq!(heatmap["summary"]["active_reservations"].as_u64(), Some(0));
    assert_eq!(
        heatmap["summary"]["expired_or_released_reservations"].as_u64(),
        Some(2)
    );
    assert_eq!(
        heatmap["suggested_stay_off_surfaces"]
            .as_array()
            .expect("stay-off surfaces")
            .len(),
        0
    );
}

#[test]
fn peer_dirty_file_reports_owner_target_dir_and_stay_off_path() {
    let heatmap = heatmap_json("peer_dirty_file.json");
    let dirty = &heatmap["dirty_paths"][0];

    assert_eq!(dirty["path"].as_str(), Some("scripts/closeout_verifier.py"));
    assert_eq!(dirty["classification"].as_str(), Some("peer-owned"));
    assert_eq!(dirty["owner"].as_str(), Some("GentleCitadel"));
    assert_eq!(dirty["stay_off"].as_bool(), Some(true));
    assert_eq!(
        heatmap["target_dirs"][0].as_str(),
        Some("/tmp/rch_target_gentlecitadel_closeout_verifier")
    );
    assert_eq!(
        heatmap["suggested_stay_off_surfaces"][0]["path"].as_str(),
        Some("scripts/closeout_verifier.py")
    );
}

#[test]
fn no_active_agents_stays_empty_without_false_conflicts() {
    let heatmap = heatmap_json("no_active_agents.json");

    assert_eq!(heatmap["summary"]["active_agents"].as_u64(), Some(0));
    assert_eq!(
        heatmap["reservations"]["active"]
            .as_array()
            .expect("active reservations")
            .len(),
        0
    );
    assert_eq!(
        heatmap["dirty_paths"]
            .as_array()
            .expect("dirty paths")
            .len(),
        0
    );
    assert_eq!(
        heatmap["suggested_open_surfaces"][0].as_str(),
        Some("fuzz/fuzz_targets")
    );
}

#[test]
fn helper_declares_no_mutating_side_effects() {
    let heatmap = heatmap_json("peer_dirty_file.json");

    for key in [
        "mutating_commands_executed",
        "beads_mutated",
        "cargo_executed",
        "agent_mail_mutated",
        "branch_or_worktree_operations",
    ] {
        assert_eq!(
            heatmap["safety"][key].as_bool(),
            Some(false),
            "{key} must stay false"
        );
    }
    assert_eq!(
        heatmap["safety"]["forbidden_command_tokens"]
            .as_array()
            .expect("forbidden tokens")
            .len(),
        0
    );
}
