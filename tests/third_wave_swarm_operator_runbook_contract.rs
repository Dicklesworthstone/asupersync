#![allow(missing_docs)]

use std::path::{Path, PathBuf};

const DOC_PATH: &str = "docs/third_wave_swarm_operator_runbook.md";
const E2E_DOC_PATH: &str = "docs/third_wave_swarm_guardrail_e2e.md";
const README_PATH: &str = "README.md";
const TEST_PATH: &str = "tests/third_wave_swarm_operator_runbook_contract.rs";

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_repo_file(relative: &str) -> String {
    std::fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|err| panic!("read {relative}: {err}"))
}

fn assert_contains_all(label: &str, text: &str, markers: &[&str]) {
    for marker in markers {
        assert!(text.contains(marker), "{label} missing {marker}");
    }
}

#[test]
fn runbook_names_canonical_surfaces_and_e2e_lane() {
    let docs = read_repo_file(DOC_PATH);
    assert_contains_all(
        "runbook",
        &docs,
        &[
            "docs/third_wave_swarm_operator_runbook.md",
            "tests/third_wave_swarm_operator_runbook_contract.rs",
            "tests/third_wave_swarm_guardrail_e2e_contract.rs",
            "artifacts/third_wave_swarm_guardrail_e2e_contract_v1.json",
            "scripts/run_third_wave_swarm_guardrail_e2e.sh",
            "scripts/third_wave_swarm_guardrail_e2e.py",
            "asupersync-ol11aa.9.6",
        ],
    );
}

#[test]
fn runbook_lists_each_guardrail_command_and_fail_closed_case() {
    let docs = read_repo_file(DOC_PATH);
    assert_contains_all(
        "runbook",
        &docs,
        &[
            "python3 scripts/stale_in_progress_bead_reaper.py",
            "python3 scripts/tracker_graph_drift_report.py",
            "python3 scripts/reservation_lease_watchdog.py",
            "python3 scripts/swarm_lane_closeout_receipt.py",
            "python3 scripts/rch_quiet_phase_receipt.py",
            "bash scripts/run_third_wave_swarm_guardrail_e2e.sh",
            "fail closed",
            "stale proof evidence",
            "zero-test exact filter",
            "expired reservation",
            "unverified pushed refs",
            "peer dirt",
        ],
    );
}

#[test]
fn runbook_preserves_rch_and_validation_policy() {
    let docs = read_repo_file(DOC_PATH);
    assert_contains_all(
        "runbook",
        &docs,
        &[
            "RCH_REQUIRE_REMOTE=1 rch exec --",
            "cargo test -p asupersync --test third_wave_swarm_operator_runbook_contract",
            "cargo fmt --check",
            "cargo check --all-targets",
            "cargo clippy --all-targets -- -D warnings",
            "No local fallback",
            "Never cite local Cargo fallback as proof",
            "Never cite a zero-test exact filter as green evidence",
        ],
    );
}

#[test]
fn runbook_preserves_agent_mail_reservation_and_push_hygiene() {
    let docs = read_repo_file(DOC_PATH);
    assert_contains_all(
        "runbook",
        &docs,
        &[
            "file_reservation_paths",
            "renew_file_reservations",
            "release_file_reservations",
            "ack_required",
            "Agent Mail closeout",
            "git fetch origin main",
            "git rev-list --left-right --count HEAD...origin/main",
            "git push origin main",
            "git push origin main:master",
            "git rev-parse origin/master",
            "Leave peer dirt unstaged",
        ],
    );
}

#[test]
fn readme_and_e2e_docs_point_to_the_operator_runbook() {
    let readme = read_repo_file(README_PATH);
    let e2e_docs = read_repo_file(E2E_DOC_PATH);
    assert_contains_all(
        "README",
        &readme,
        &[
            "docs/third_wave_swarm_operator_runbook.md",
            "tests/third_wave_swarm_operator_runbook_contract.rs",
            "third-wave operator runbook",
            "fail-closed signoff checklist",
        ],
    );
    assert_contains_all(
        "e2e docs",
        &e2e_docs,
        &["docs/third_wave_swarm_operator_runbook.md"],
    );
}

#[test]
fn contract_test_names_its_own_markers() {
    let self_test = read_repo_file(TEST_PATH);
    assert_contains_all(
        "contract test",
        &self_test,
        &[
            "docs/third_wave_swarm_operator_runbook.md",
            "tests/third_wave_swarm_operator_runbook_contract.rs",
            "RCH_REQUIRE_REMOTE=1 rch exec --",
            "git push origin main:master",
            "release_file_reservations",
            "fail closed",
        ],
    );
}
