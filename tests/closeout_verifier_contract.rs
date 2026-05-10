//! Contract tests for the shared-main closeout verifier.

#![allow(missing_docs)]

use serde_json::Value;
use std::path::PathBuf;
use std::process::{Command, Output};

const SCRIPT_PATH: &str = "scripts/closeout_verifier.py";
const FIXTURE_ROOT: &str = "tests/fixtures/closeout_verifier";
const GENERATED_AT: &str = "2026-05-10T08:35:00Z";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn run_verifier(fixture: &str) -> Output {
    Command::new("python3")
        .arg(repo_root().join(SCRIPT_PATH))
        .arg("--fixture")
        .arg(repo_root().join(FIXTURE_ROOT).join(fixture))
        .arg("--repo-path")
        .arg(repo_root())
        .arg("--generated-at")
        .arg(GENERATED_AT)
        .arg("--output")
        .arg("json")
        .current_dir(repo_root())
        .output()
        .expect("run closeout verifier")
}

fn report(fixture: &str) -> Value {
    let output = run_verifier(fixture);
    assert!(
        output.status.success(),
        "verifier failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("verifier output must be JSON")
}

fn row<'a>(report: &'a Value, row_id: &str) -> &'a Value {
    report["rows"]
        .as_array()
        .expect("rows array")
        .iter()
        .find(|row| row["row_id"].as_str() == Some(row_id))
        .unwrap_or_else(|| panic!("missing row {row_id}"))
}

#[test]
fn script_exists_and_help_is_non_mutating() {
    assert!(
        repo_root().join(SCRIPT_PATH).exists(),
        "verifier must exist at {SCRIPT_PATH}"
    );
    let output = Command::new("python3")
        .arg(repo_root().join(SCRIPT_PATH))
        .arg("--help")
        .current_dir(repo_root())
        .output()
        .expect("run verifier --help");
    assert!(output.status.success(), "--help should succeed");
}

#[test]
fn clean_closeout_passes_all_required_rows() {
    let report = report("clean_closeout.json");

    assert_eq!(
        report["schema_version"].as_str(),
        Some("closeout-verifier-v1")
    );
    assert_eq!(report["current_date"].as_str(), Some("2026-05-10"));
    assert_eq!(report["overall_status"].as_str(), Some("pass"));
    assert_eq!(report["summary"]["fail"].as_u64(), Some(0));
    assert_eq!(row(&report, "main_pushed")["status"].as_str(), Some("pass"));
    assert_eq!(
        row(&report, "master_synced")["status"].as_str(),
        Some("pass")
    );
    assert_eq!(row(&report, "bead_closed")["status"].as_str(), Some("pass"));
    assert_eq!(
        row(&report, "closeout_mail")["status"].as_str(),
        Some("pass")
    );
    assert_eq!(
        row(&report, "reservations_released")["status"].as_str(),
        Some("pass")
    );
    assert_eq!(
        row(&report, "validation_reported")["status"].as_str(),
        Some("pass")
    );
}

#[test]
fn active_reservation_blocks_closeout() {
    let report = report("missing_reservation_release.json");
    let reservations = row(&report, "reservations_released");

    assert_eq!(report["overall_status"].as_str(), Some("fail"));
    assert_eq!(reservations["status"].as_str(), Some("fail"));
    assert_eq!(
        reservations["evidence"]["active_reservations"][0]["path"].as_str(),
        Some("scripts/closeout_verifier.py")
    );
    assert!(
        reservations["remediation"]
            .as_str()
            .expect("remediation")
            .contains("release file reservations")
    );
}

#[test]
fn missing_master_sync_is_reported_with_git_command_evidence() {
    let report = report("missing_master_sync.json");
    let master = row(&report, "master_synced");

    assert_eq!(report["overall_status"].as_str(), Some("fail"));
    assert_eq!(master["status"].as_str(), Some("fail"));
    assert_eq!(
        master["evidence"]["origin_main"].as_str(),
        Some("fedcba987")
    );
    assert_eq!(
        master["evidence"]["origin_master"].as_str(),
        Some("old000111")
    );
    assert_eq!(
        master["evidence"]["command"].as_str(),
        Some("git rev-parse origin/main origin/master")
    );
}

#[test]
fn closed_bead_without_mail_fails_mail_row() {
    let report = report("closed_bead_without_mail.json");
    let mail = row(&report, "closeout_mail");

    assert_eq!(report["overall_status"].as_str(), Some("fail"));
    assert_eq!(row(&report, "bead_closed")["status"].as_str(), Some("pass"));
    assert_eq!(mail["status"].as_str(), Some("fail"));
    assert!(
        mail["remediation"]
            .as_str()
            .expect("remediation")
            .contains("send a closeout message")
    );
}

#[test]
fn code_only_without_bead_gets_tracker_note_instead_of_failure() {
    let report = report("code_only_without_bead.json");
    let note = row(&report, "tracker_reconciliation_note");

    assert_eq!(report["overall_status"].as_str(), Some("warn"));
    assert_eq!(report["summary"]["fail"].as_u64(), Some(0));
    assert_eq!(note["status"].as_str(), Some("warn"));
    assert!(
        note["summary"]
            .as_str()
            .expect("note summary")
            .contains("no bead to close")
    );
    assert_eq!(
        row(&report, "closeout_mail")["status"].as_str(),
        Some("pass")
    );
}

#[test]
fn verifier_declares_forbidden_actions_false() {
    let report = report("clean_closeout.json");

    assert_eq!(report["non_mutating"].as_bool(), Some(true));
    for key in [
        "runs_git_mutation",
        "runs_beads_mutation",
        "runs_agent_mail_mutation",
        "runs_destructive_command",
        "runs_cargo",
    ] {
        assert_eq!(
            report["forbidden_actions"][key].as_bool(),
            Some(false),
            "{key} must stay false"
        );
    }
}
