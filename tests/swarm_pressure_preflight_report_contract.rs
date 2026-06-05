#![allow(missing_docs)]

use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const SCRIPT_PATH: &str = "scripts/swarm_pressure_preflight_report.py";
const E2E_SCRIPT_PATH: &str = "scripts/run_swarm_pressure_preflight_report_e2e.sh";
const FIXTURE_DIR: &str = "tests/fixtures/swarm_pressure_preflight_report";
const GENERATED_AT: &str = "2026-06-05T08:10:00Z";

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

fn fixture_path(name: &str) -> PathBuf {
    repo_root().join(FIXTURE_DIR).join(name)
}

fn run_fixture(name: &str) -> Output {
    Command::new("python3")
        .current_dir(repo_root())
        .arg(SCRIPT_PATH)
        .arg("--fixture")
        .arg(fixture_path(name))
        .arg("--repo-path")
        .arg(repo_root())
        .arg("--generated-at")
        .arg(GENERATED_AT)
        .arg("--output")
        .arg("json")
        .output()
        .unwrap_or_else(|error| panic!("run preflight fixture {name}: {error}"))
}

fn report(name: &str) -> Value {
    let output = run_fixture(name);
    assert!(
        output.status.success(),
        "preflight fixture {name} failed\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "parse preflight fixture {name}: {error}\nstdout:\n{}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

fn source_kinds(value: &Value) -> Vec<&str> {
    value["source_artifacts"]
        .as_array()
        .expect("source_artifacts array")
        .iter()
        .map(|source| source["kind"].as_str().expect("source kind"))
        .collect()
}

fn blocker_kinds(value: &Value) -> Vec<&str> {
    value["blockers"]
        .as_array()
        .expect("blockers array")
        .iter()
        .map(|source| source["kind"].as_str().expect("blocker kind"))
        .collect()
}

fn warning_kinds(value: &Value) -> Vec<&str> {
    value["warnings"]
        .as_array()
        .expect("warnings array")
        .iter()
        .map(|source| source["kind"].as_str().expect("warning kind"))
        .collect()
}

fn assert_has_kind(kinds: &[&str], expected: &str) {
    assert!(
        kinds.contains(&expected),
        "missing {expected}; got {kinds:?}"
    );
}

fn expectation_case_id(value: &Value) -> &str {
    value["e2e_expectations"]["case_id"]
        .as_str()
        .expect("expectation case_id")
}

#[test]
fn script_exists_and_help_is_non_mutating() {
    assert!(
        repo_root().join(SCRIPT_PATH).exists(),
        "{SCRIPT_PATH} missing"
    );
    let output = Command::new("python3")
        .current_dir(repo_root())
        .arg(SCRIPT_PATH)
        .arg("--help")
        .output()
        .expect("run --help");
    assert!(output.status.success(), "--help should succeed");
}

#[test]
fn green_fixture_passes_without_blockers_or_warnings() {
    let value = report("green.json");
    assert_eq!(
        value["schema_version"].as_str(),
        Some("swarm-pressure-preflight-report-v1")
    );
    assert_eq!(value["generated_at"].as_str(), Some(GENERATED_AT));
    assert_eq!(
        value["operator_summary"]["decision"].as_str(),
        Some("preflight-pass")
    );
    assert_eq!(value["operator_summary"]["blocker_count"].as_i64(), Some(0));
    assert_eq!(value["operator_summary"]["warning_count"].as_i64(), Some(0));
    assert_eq!(
        value["proof_boundary"]["behavioral_correctness_proof"].as_bool(),
        Some(false)
    );
    assert_eq!(
        value["proof_boundary"]["fresh_rch_pass_proof"].as_bool(),
        Some(false)
    );
    for key in [
        "runs_cargo",
        "runs_rch",
        "runs_git_mutation",
        "runs_beads_mutation",
        "sends_agent_mail",
        "writes_cache",
        "deletes_files",
    ] {
        assert_eq!(
            value["forbidden_actions"][key].as_bool(),
            Some(false),
            "{key} must remain false"
        );
    }
    let kinds = source_kinds(&value);
    assert_has_kind(&kinds, "proof_lane_manifest");
    assert_has_kind(&kinds, "proof_status_snapshot");
    assert_has_kind(&kinds, "runtime_pressure_contract");
    for source in value["source_artifacts"].as_array().expect("sources") {
        assert_eq!(source["load_status"].as_str(), Some("ok"));
        assert!(
            source["digest"]
                .as_str()
                .expect("source digest")
                .starts_with("sha256:")
        );
        assert!(
            !source["version"].as_str().unwrap_or_default().is_empty(),
            "source versions must be logged"
        );
    }
}

#[test]
fn inline_empty_source_data_does_not_fall_through_to_artifact_path_loading() {
    let value = report("inline_empty_source.json");
    assert_eq!(
        value["operator_summary"]["decision"].as_str(),
        Some("preflight-pass")
    );
    assert_eq!(
        value["sections"]["proof_freshness"]["receipt_count"].as_i64(),
        Some(1)
    );
    assert_eq!(
        value["sections"]["proof_freshness"]["row_count"].as_i64(),
        Some(0)
    );
    let freshness_source = value["source_artifacts"]
        .as_array()
        .expect("sources")
        .iter()
        .find(|source| source["kind"].as_str() == Some("proof_freshness_receipt"))
        .expect("proof freshness source");
    assert_eq!(freshness_source["load_status"].as_str(), Some("ok"));
    assert_eq!(
        freshness_source["errors"].as_array().expect("errors").len(),
        0
    );
}

#[test]
fn blocked_fixture_aggregates_status_admission_and_disk_blockers() {
    let value = report("blocked.json");
    assert_eq!(
        value["operator_summary"]["decision"].as_str(),
        Some("preflight-blocked")
    );
    let blockers = blocker_kinds(&value);
    assert_has_kind(&blockers, "blocked-proof-status");
    assert_has_kind(&blockers, "proof-admission-blocked");
    assert_has_kind(&blockers, "disk-headroom-insufficient");
    assert_eq!(
        value["operator_summary"]["ready_for_release_gate"].as_bool(),
        Some(false)
    );
}

#[test]
fn stale_exact_filter_fixture_refuses_zero_test_exact_proofs() {
    let value = report("stale_exact_filter.json");
    assert_eq!(
        value["operator_summary"]["decision"].as_str(),
        Some("preflight-blocked")
    );
    let blockers = blocker_kinds(&value);
    assert_has_kind(&blockers, "stale-exact-filter-zero-tests");
    assert_eq!(
        value["sections"]["proof_freshness"]["rows"][0]["exact_filter_executed_tests"].as_i64(),
        Some(0)
    );
    assert_eq!(
        value["sections"]["proof_freshness"]["by_classification"]["exact-filter-zero-tests"]
            .as_i64(),
        Some(1)
    );
}

#[test]
fn missing_envelope_fixture_reports_lane_envelope_health() {
    let value = report("missing_envelope.json");
    assert_eq!(
        value["sections"]["proof_lane_envelope_health"]["lane_states"]["missing-envelope"].as_i64(),
        Some(1)
    );
    let blockers = blocker_kinds(&value);
    assert_has_kind(&blockers, "missing-resource-envelope");
    assert_eq!(
        value["blockers"][0]["behavioral_correctness_proof"].as_bool(),
        Some(false)
    );
}

#[test]
fn local_fallback_fixture_refuses_remote_required_policy_violations() {
    let value = report("local_fallback_attempt.json");
    assert_eq!(
        expectation_case_id(&value),
        "remote-required-lane-attempted-locally"
    );
    assert_eq!(
        value["operator_summary"]["decision"].as_str(),
        Some("preflight-blocked")
    );
    let blockers = blocker_kinds(&value);
    assert_has_kind(&blockers, "unsafe-resource-envelope-policy");
    assert_has_kind(&blockers, "unsafe-proof-command-prefix");

    let lane = &value["sections"]["proof_lane_envelope_health"]["lanes"][0];
    assert_eq!(lane["state"].as_str(), Some("bad-command-prefix"));
    assert_eq!(
        lane["command"].as_str(),
        Some(
            "cargo test -p asupersync --test swarm_pressure_preflight_report_contract -- --nocapture"
        )
    );
    assert_eq!(
        lane["resource_envelope"]["remote_required"].as_bool(),
        Some(false)
    );
    assert_eq!(
        lane["resource_envelope"]["local_fallback_allowed"].as_bool(),
        Some(true)
    );
}

#[test]
fn peer_dirty_tree_fixture_blocks_release_and_preserves_owner_context() {
    let value = report("peer_dirty_tree.json");
    let blockers = blocker_kinds(&value);
    assert_has_kind(&blockers, "dirty-tree-release-blocker");
    assert_eq!(
        value["sections"]["dirty_tree"]["decision"].as_str(),
        Some("release-blocked")
    );
    assert_eq!(
        value["sections"]["dirty_tree"]["rows"][0]["owner"].as_str(),
        Some("SageWolf")
    );
    assert_eq!(
        value["sections"]["dirty_tree"]["rows"][0]["path"].as_str(),
        Some("src/net/tcp/stream.rs")
    );
}

#[test]
fn mixed_pressure_fixture_preserves_pressure_classes_and_rerun_warning() {
    let value = report("mixed_pressure.json");
    assert_eq!(
        value["sections"]["pressure_summary"]["mixed_pressure"].as_bool(),
        Some(true)
    );
    assert_eq!(
        value["sections"]["proof_admission"]["admissible_count"].as_i64(),
        Some(1)
    );
    assert_eq!(
        value["sections"]["proof_admission"]["blocked_count"].as_i64(),
        Some(1)
    );
    assert_eq!(
        value["sections"]["proof_admission"]["rows"][0]["proof_may_run_now"].as_bool(),
        Some(false)
    );
    assert_eq!(
        value["sections"]["proof_admission"]["rows"][0]["admission_decision"].as_str(),
        Some("queue")
    );
    let blockers = blocker_kinds(&value);
    assert_has_kind(&blockers, "proof-admission-blocked");
    let warnings = warning_kinds(&value);
    assert_has_kind(&warnings, "proof-rerun-required");
    assert_has_kind(&warnings, "runtime-pressure-high");
}

#[test]
fn chaos_pressure_fixture_queues_e2e_lane_with_explicit_pressure_warning() {
    let value = report("chaos_pressure.json");
    assert_eq!(expectation_case_id(&value), "chaos-pressure-scenario");
    assert_eq!(
        value["operator_summary"]["decision"].as_str(),
        Some("preflight-blocked")
    );
    assert_eq!(
        value["sections"]["pressure_summary"]["classes"][0].as_str(),
        Some("critical")
    );
    assert_eq!(
        value["sections"]["proof_admission"]["rows"][0]["lane_id"].as_str(),
        Some("proof-lane-pressure-chaos-e2e")
    );
    assert_eq!(
        value["sections"]["proof_admission"]["rows"][0]["proof_may_run_now"].as_bool(),
        Some(false)
    );
    let blockers = blocker_kinds(&value);
    assert_has_kind(&blockers, "proof-admission-blocked");
    let warnings = warning_kinds(&value);
    assert_has_kind(&warnings, "proof-rerun-required");
    assert_has_kind(&warnings, "runtime-pressure-high");
    assert!(
        value["sections"]["proof_lane_envelope_health"]["lanes"][0]["command"]
            .as_str()
            .expect("chaos command")
            .contains("scripts/run_proof_lane_pressure_chaos_e2e.sh")
    );
}

#[test]
fn e2e_script_logs_operator_diagnostics() {
    let output_dir = std::env::temp_dir().join(format!(
        "asupersync-swarm-pressure-preflight-e2e-mixed-{}",
        std::process::id()
    ));
    let output = Command::new("bash")
        .current_dir(repo_root())
        .arg(E2E_SCRIPT_PATH)
        .arg("--fixture")
        .arg(fixture_path("mixed_pressure.json"))
        .arg("--repo-path")
        .arg(repo_root())
        .arg("--output-dir")
        .arg(&output_dir)
        .arg("--generated-at")
        .arg(GENERATED_AT)
        .output()
        .expect("run swarm pressure preflight e2e script");

    assert!(
        output.status.success(),
        "e2e failed\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    for expected in [
        "source_artifacts_begin",
        "source kind=proof_lane_manifest",
        "envelope lane_count=2",
        "proof_status claims=1",
        "freshness receipts=0",
        "admission receipts=2",
        "pressure classes=healthy,high mixed=true",
        "blocker kind=proof-admission-blocked",
        "warning kind=proof-rerun-required",
        "warning kind=runtime-pressure-high",
        "final decision=preflight-blocked",
    ] {
        assert!(
            stdout.contains(expected),
            "e2e log missing {expected:?}\nstdout:\n{stdout}"
        );
    }

    let receipt = output_dir.join("swarm_pressure_preflight_report.json");
    assert!(receipt.exists(), "e2e should write {receipt:?}");
}

#[test]
fn e2e_suite_logs_all_acceptance_cases_with_expectation_checks() {
    let output_dir = std::env::temp_dir().join(format!(
        "asupersync-swarm-pressure-preflight-e2e-suite-{}",
        std::process::id()
    ));
    let output = Command::new("bash")
        .current_dir(repo_root())
        .arg(E2E_SCRIPT_PATH)
        .arg("--suite")
        .arg("--repo-path")
        .arg(repo_root())
        .arg("--output-dir")
        .arg(&output_dir)
        .arg("--generated-at")
        .arg(GENERATED_AT)
        .output()
        .expect("run swarm pressure preflight e2e suite");

    assert!(
        output.status.success(),
        "e2e suite failed\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    for expected in [
        "case_begin id=green-workflow",
        "case_begin id=stale-exact-filter-zero-tests",
        "case_begin id=missing-resource-envelope",
        "case_begin id=remote-required-lane-attempted-locally",
        "case_begin id=peer-owned-dirty-tree",
        "case_begin id=chaos-pressure-scenario",
        "case_begin id=combined-multi-blocker",
        "command lane=proof-lane-pressure-chaos-e2e",
        "envelope_values lane=swarm-pressure-preflight-report-contract class=artifact-contract-local-fallback timeout_seconds=3600 memory_mb=16384 remote_required=false local_fallback_allowed=true",
        "parsed_tests lane=lib-tests exact_filter=default_policy_no_csp_or_permissions executed=0",
        "dirty_path path=src/net/tcp/stream.rs classification=peer-owned",
        "expected_decision=preflight-blocked actual_decision=preflight-blocked",
        "actual_blockers=[\"stale-exact-filter-zero-tests\"]",
        "final_blocker_list=",
        "suite case_count=7 pass_count=7 fail_count=0 unchecked_count=0",
    ] {
        assert!(
            stdout.contains(expected),
            "e2e suite log missing {expected:?}\nstdout:\n{stdout}"
        );
    }

    let summary_path = output_dir.join("swarm_pressure_preflight_e2e_summary.json");
    let summary: Value = serde_json::from_slice(
        &std::fs::read(&summary_path)
            .unwrap_or_else(|error| panic!("read e2e suite summary {summary_path:?}: {error}")),
    )
    .expect("parse e2e suite summary");
    assert_eq!(
        summary["schema_version"].as_str(),
        Some("swarm-pressure-preflight-e2e-summary-v1")
    );
    assert_eq!(summary["case_count"].as_i64(), Some(7));
    assert_eq!(summary["pass_count"].as_i64(), Some(7));
    assert_eq!(summary["fail_count"].as_i64(), Some(0));
}
