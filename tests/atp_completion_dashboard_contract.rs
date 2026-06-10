#![allow(missing_docs)]

use serde_json::Value;
use std::collections::BTreeSet;
use std::process::{Command, Stdio};

const CONTRACT_PATH: &str = "artifacts/atp_completion_dashboard_contract_v1.json";
const SCRIPT_PATH: &str = "scripts/atp_completion_dashboard.py";
const LIVE_GENERATED_AT: &str = "2026-05-29T15:11:00Z";
const LIVE_AS_OF_DATE: &str = "2026-05-29";
const STALE_AS_OF_DATE: &str = "2026-06-07";

fn repo_file(path: &str) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|err| panic!("read {path}: {err}"))
}

fn contract_json() -> Value {
    serde_json::from_str(&repo_file(CONTRACT_PATH)).expect("contract json parses")
}

fn run_dashboard(args: &[&str]) -> String {
    let output = Command::new("python3")
        .arg(SCRIPT_PATH)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run ATP completion dashboard");
    assert!(
        output.status.success(),
        "dashboard command failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("dashboard stdout is utf8")
}

fn dashboard_json_as_of(generated_at: &str, as_of_date: &str) -> Value {
    serde_json::from_str(&run_dashboard(&[
        "--format=json",
        "--generated-at",
        generated_at,
        "--as-of-date",
        as_of_date,
    ]))
    .expect("dashboard json parses")
}

fn dashboard_json() -> Value {
    dashboard_json_as_of(LIVE_GENERATED_AT, LIVE_AS_OF_DATE)
}

#[test]
fn dashboard_treats_missing_tracker_as_release_blocking_data() {
    let dashboard: Value = serde_json::from_str(&run_dashboard(&[
        "--format=json",
        "--generated-at",
        LIVE_GENERATED_AT,
        "--as-of-date",
        LIVE_AS_OF_DATE,
        "--issues",
        "target/atp-completion-dashboard-test/missing-issues.jsonl",
    ]))
    .expect("dashboard json parses");

    assert_eq!(
        dashboard["source_of_truth"]["tracker"].as_str(),
        Some("target/atp-completion-dashboard-test/missing-issues.jsonl")
    );
    assert_eq!(
        dashboard["summary"]["ready_to_close_top_epic"].as_bool(),
        Some(false),
        "missing tracker export must fail closed rather than crashing or going green"
    );
    assert!(
        dashboard["release_gates"]
            .as_array()
            .expect("release gate rows")
            .iter()
            .any(|row| row["dashboard_status"].as_str() == Some("red_missing_bead")),
        "missing tracker export should leave required gates visibly missing"
    );
}

#[test]
fn contract_declares_required_workstreams_questions_and_nr_gates() {
    let contract = contract_json();
    assert_eq!(
        contract["contract_version"].as_str(),
        Some("atp-completion-dashboard-contract-v1")
    );
    assert_eq!(
        contract["schema_version"].as_str(),
        Some("atp-completion-dashboard-v1")
    );
    assert_eq!(contract["bead_id"].as_str(), Some("asupersync-vk4kcf.1"));
    assert_eq!(contract["generator"].as_str(), Some(SCRIPT_PATH));
    assert_eq!(
        contract["verifier"].as_str(),
        Some("tests/atp_completion_dashboard_contract.rs")
    );
    let proof_sources = contract["proof_sources"]
        .as_array()
        .expect("proof_sources array")
        .iter()
        .map(|row| row.as_str().expect("proof source string"))
        .collect::<BTreeSet<_>>();
    assert!(
        proof_sources.contains("artifacts/atp_proof_reconciliation_v1.json"),
        "ATP-NR14 proof reconciliation must be a dashboard proof source"
    );

    let workstreams = contract["required_workstreams"]
        .as_array()
        .expect("required_workstreams array")
        .iter()
        .map(|row| row["workstream_id"].as_str().expect("workstream id"))
        .collect::<BTreeSet<_>>();
    let expected = ('A'..='N')
        .map(|letter| format!("ATP-{letter}"))
        .collect::<BTreeSet<_>>();
    let actual = workstreams
        .iter()
        .map(|item| item.to_string())
        .collect::<BTreeSet<_>>();
    assert_eq!(actual, expected, "dashboard must cover ATP-A through ATP-N");

    let gate_ids = contract["required_release_gates"]
        .as_array()
        .expect("required_release_gates array")
        .iter()
        .map(|row| row["gate_id"].as_str().expect("gate id"))
        .collect::<BTreeSet<_>>();
    for suffix in 0..=14 {
        assert!(
            gate_ids.contains(format!("ATP-NR{suffix}").as_str()),
            "missing ATP-NR{suffix}"
        );
    }

    let question_ids = contract["required_questions"]
        .as_array()
        .expect("required_questions array")
        .iter()
        .map(|row| row["question_id"].as_str().expect("question id"))
        .collect::<BTreeSet<_>>();
    for required in [
        "all_done",
        "unit_coverage_complete",
        "mock_free",
        "e2e_scripts_complete",
        "logging_failure_bundles_complete",
        "cross_platform_complete",
        "release_proof_green",
    ] {
        assert!(
            question_ids.contains(required),
            "missing question {required}"
        );
    }

    let status_catalog = contract["status_catalog"]
        .as_array()
        .expect("status_catalog array")
        .iter()
        .map(|row| row["status"].as_str().expect("status catalog id"))
        .collect::<BTreeSet<_>>();
    assert!(
        status_catalog.contains("red_blocked"),
        "dashboard must preserve blocked Beads distinctly from open Beads"
    );
}

#[test]
fn dashboard_json_answers_user_questions_and_lists_live_gates() {
    let dashboard = dashboard_json();
    assert_eq!(
        dashboard["schema_version"].as_str(),
        Some("atp-completion-dashboard-v1")
    );
    assert_eq!(
        dashboard["source_of_truth"]["tracker"].as_str(),
        Some(".beads/issues.jsonl")
    );
    assert_eq!(
        dashboard["source_of_truth"]["verifier"].as_str(),
        Some("tests/atp_completion_dashboard_contract.rs")
    );

    let answers = dashboard["answers"].as_object().expect("answers object");
    assert_eq!(
        answers.len(),
        7,
        "dashboard must answer every user question"
    );
    let all_done_gate_blockers = answers["all_done"]["blocking_gate_ids"]
        .as_array()
        .expect("all_done blocking gates");
    let all_done_artifact_blockers = answers["all_done"]["blocking_artifact_paths"]
        .as_array()
        .expect("all_done blocking artifacts");

    let gates = dashboard["release_gates"]
        .as_array()
        .expect("release gates");
    assert_eq!(
        gates.len(),
        15,
        "dashboard must list ATP-NR0 through ATP-NR14"
    );
    assert!(gates.iter().any(|row| {
        row["gate_id"].as_str() == Some("ATP-NR0")
            && row["bead_id"].as_str() == Some("asupersync-vk4kcf.1")
    }));
    let nr14_gate = gates
        .iter()
        .find(|row| row["gate_id"].as_str() == Some("ATP-NR14"))
        .expect("ATP-NR14 gate");
    assert_eq!(nr14_gate["bead_id"].as_str(), Some("asupersync-vk4kcf.15"));
    let nr14_required_artifacts = nr14_gate["required_artifacts"]
        .as_array()
        .expect("ATP-NR14 required_artifacts")
        .iter()
        .map(|row| row.as_str().expect("artifact path"))
        .collect::<BTreeSet<_>>();
    for required in [
        "artifacts/atp_proof_reconciliation_v1.json",
        "docs/atp_proof_reconciliation/README.md",
        "tests/atp_proof_reconciliation_contract.rs",
    ] {
        assert!(
            nr14_required_artifacts.contains(required),
            "ATP-NR14 dashboard gate must require {required}"
        );
    }

    let workstreams = dashboard["workstreams"].as_array().expect("workstreams");
    assert_eq!(
        workstreams.len(),
        14,
        "dashboard must list ATP-A through ATP-N"
    );
    let release_blocking_count = dashboard["summary"]["release_blocking_count"]
        .as_u64()
        .expect("release_blocking_count");
    if release_blocking_count == 0 {
        assert_eq!(
            answers["all_done"]["answer"].as_str(),
            Some("yes"),
            "ATP should be marked done only when live gates and proof artifacts are green"
        );
        assert!(
            all_done_gate_blockers.is_empty() && all_done_artifact_blockers.is_empty(),
            "green all_done must not name blocking gates or proof artifacts"
        );
        assert_eq!(
            dashboard["summary"]["ready_to_close_top_epic"].as_bool(),
            Some(true)
        );
    } else {
        assert_ne!(
            answers["all_done"]["answer"].as_str(),
            Some("yes"),
            "ATP cannot be marked done while release-blocking rows remain"
        );
        assert!(
            !all_done_gate_blockers.is_empty() || !all_done_artifact_blockers.is_empty(),
            "red all_done must name blocking gates or proof artifacts"
        );
        assert_eq!(
            dashboard["summary"]["ready_to_close_top_epic"].as_bool(),
            Some(false)
        );
    }
}

#[test]
fn dashboard_detects_missing_artifacts_and_stale_proof_snapshot() {
    let dashboard = dashboard_json_as_of("2026-06-07T00:00:00Z", STALE_AS_OF_DATE);
    let artifacts = dashboard["proof_artifacts"]
        .as_array()
        .expect("proof_artifacts array");
    let proof_status = artifacts
        .iter()
        .find(|row| row["path"].as_str() == Some("artifacts/proof_status_snapshot_v1.json"))
        .expect("proof status artifact row");
    assert_eq!(proof_status["exists"].as_bool(), Some(true));
    assert_eq!(
        proof_status["dashboard_status"].as_str(),
        Some("red_stale_proof")
    );
    assert_eq!(
        proof_status["stale"].as_bool(),
        Some(true),
        "2026-05-29 proof snapshot must be stale as of 2026-06-07 under the 7-day policy"
    );
    assert_eq!(proof_status["release_blocking"].as_bool(), Some(true));
    assert!(
        proof_status["first_blocker"]
            .as_str()
            .expect("proof artifact first_blocker")
            .contains("stale proof artifact"),
        "stale proof artifacts must explain the exact blocker"
    );

    let release_answer = &dashboard["answers"]["release_proof_green"];
    assert_eq!(
        release_answer["answer"].as_str(),
        Some("no"),
        "stale release proof artifacts must make the release-proof answer red"
    );
    let blocking_artifacts = release_answer["blocking_artifact_paths"]
        .as_array()
        .expect("release proof blocking_artifact_paths")
        .iter()
        .map(|row| row.as_str().expect("artifact path"))
        .collect::<BTreeSet<_>>();
    assert!(
        blocking_artifacts.contains("artifacts/proof_status_snapshot_v1.json"),
        "release-proof answer must name stale proof artifacts"
    );

    assert!(
        dashboard["release_gates"]
            .as_array()
            .expect("release gates")
            .iter()
            .all(|row| row["missing_artifacts"].is_array()),
        "every gate row must expose missing_artifacts explicitly, even when empty"
    );
}

#[test]
fn dashboard_summary_and_table_are_stable_human_outputs() {
    let summary = run_dashboard(&[
        "--format=summary",
        "--generated-at",
        LIVE_GENERATED_AT,
        "--as-of-date",
        LIVE_AS_OF_DATE,
    ]);
    assert!(summary.contains("ATP completion dashboard (2026-05-29)"));
    assert!(summary.contains("Ready to close top epic: "));
    assert!(summary.contains("all_done:"));
    assert!(summary.contains("mock_free:"));

    let table = run_dashboard(&[
        "--format=table",
        "--generated-at",
        LIVE_GENERATED_AT,
        "--as-of-date",
        LIVE_AS_OF_DATE,
    ]);
    assert!(table.contains("# ATP Completion Dashboard - 2026-05-29T15:11:00Z"));
    assert!(table.contains("| ATP-NR0 |"));
    assert!(table.contains("| ATP-A |"));
}

#[test]
fn script_self_tests_cover_classification_helpers() {
    let output = run_dashboard(&["--self-test"]);
    assert!(output.contains("atp completion dashboard self-test: pass"));
}
