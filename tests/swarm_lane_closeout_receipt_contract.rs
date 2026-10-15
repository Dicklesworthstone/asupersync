#![allow(missing_docs)]

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const CONTRACT_PATH: &str = "artifacts/swarm_lane_closeout_receipt_contract_v1.json";
const DOC_PATH: &str = "docs/swarm_lane_closeout_receipt.md";
const GENERATED_AT: &str = "2026-06-06T15:30:00Z";
const SCRIPT_PATH: &str = "scripts/swarm_lane_closeout_receipt.py";

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_repo_file(relative: &str) -> String {
    std::fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|err| panic!("read {relative}: {err}"))
}

fn json_file(relative: &str) -> Value {
    serde_json::from_str(&read_repo_file(relative))
        .unwrap_or_else(|err| panic!("parse {relative}: {err}"))
}

fn run_helper(output_format: &str) -> Output {
    Command::new("python3")
        .arg(repo_path(SCRIPT_PATH))
        .arg("--fixture")
        .arg(repo_path(CONTRACT_PATH))
        .arg("--generated-at")
        .arg(GENERATED_AT)
        .arg("--output")
        .arg(output_format)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run swarm lane closeout receipt helper")
}

fn report_json() -> Value {
    let output = run_helper("json");
    assert!(
        output.status.success(),
        "helper failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("helper JSON output")
}

fn markdown_report() -> String {
    let output = run_helper("markdown");
    assert!(
        output.status.success(),
        "helper markdown failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("markdown is utf-8")
}

fn string<'a>(value: &'a Value, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"))
}

fn array<'a>(value: &'a Value, key: &str) -> &'a Vec<Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
}

fn object<'a>(value: &'a Value, key: &str) -> &'a Value {
    value
        .get(key)
        .unwrap_or_else(|| panic!("{key} must be present"))
}

fn bool_field(value: &Value, key: &str) -> bool {
    value
        .get(key)
        .and_then(Value::as_bool)
        .unwrap_or_else(|| panic!("{key} must be a boolean"))
}

fn u64_field(value: &Value, key: &str) -> u64 {
    value
        .get(key)
        .and_then(Value::as_u64)
        .unwrap_or_else(|| panic!("{key} must be an unsigned integer"))
}

fn string_set(value: &Value, key: &str) -> BTreeSet<String> {
    array(value, key)
        .iter()
        .map(|item| {
            item.as_str()
                .unwrap_or_else(|| panic!("{key} entries must be strings"))
                .to_string()
        })
        .collect()
}

fn rows_by_scenario(report: &Value) -> BTreeMap<String, Value> {
    array(report, "rows")
        .iter()
        .map(|row| (string(row, "scenario_id").to_string(), row.clone()))
        .collect()
}

#[test]
fn script_exists_and_is_read_only_fixture_evaluator() {
    assert!(repo_path(SCRIPT_PATH).exists(), "{SCRIPT_PATH} must exist");
    let output = Command::new("python3")
        .arg(repo_path(SCRIPT_PATH))
        .arg("--help")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run helper --help");
    assert!(output.status.success(), "--help should succeed");

    let source = read_repo_file(SCRIPT_PATH);
    for forbidden in [
        "subprocess",
        "os.system",
        "git add",
        "git commit",
        "git push",
        "cargo check",
        "br update",
        "br close",
        "send_message",
        "file_reservation_paths",
        "write_text",
        "Path.write",
        "open(\"w\"",
        "open('w'",
    ] {
        assert!(
            !source.contains(forbidden),
            "read-only helper must not contain forbidden token {forbidden}"
        );
    }
}

#[test]
fn contract_fixture_emits_expected_json_summary() {
    let contract = json_file(CONTRACT_PATH);
    let expected = object(&contract, "expected_summary");
    let report = report_json();
    let summary = object(&report, "summary");

    assert_eq!(
        string(&report, "schema_version"),
        "swarm-lane-closeout-receipt-v1"
    );
    assert_eq!(
        string(&report, "fixture_id"),
        "swarm-lane-closeout-contract-fixture"
    );
    assert_eq!(string(&report, "generated_at"), GENERATED_AT);
    for key in [
        "scenario_count",
        "admissible_count",
        "non_admissible_count",
        "fail_closed_count",
        "peer_dirt_admissible_count",
        "proof_command_count",
    ] {
        assert_eq!(u64_field(summary, key), u64_field(expected, key), "{key}");
    }
    assert_eq!(
        string(summary, "highest_severity_scenario"),
        string(expected, "highest_severity_scenario")
    );
}

#[test]
fn every_required_classification_is_exercised_once() {
    let contract = json_file(CONTRACT_PATH);
    let expected = string_set(&contract, "required_classifications");
    let report = report_json();
    let classification_counts = object(object(&report, "summary"), "classification_counts");

    for classification in &expected {
        assert_eq!(
            classification_counts
                .get(classification)
                .and_then(Value::as_u64)
                .unwrap_or_default(),
            1,
            "{classification} should be exercised exactly once"
        );
        assert!(
            object(&report, "classification_catalog")
                .get(classification)
                .is_some(),
            "{classification} missing from catalog"
        );
    }
}

#[test]
fn successful_lane_receipt_contains_all_closeout_surfaces() {
    let report = report_json();
    let rows = rows_by_scenario(&report);
    let row = &rows["successful-lane"];

    assert_eq!(string(row, "classification"), "admissible-closeout");
    assert!(bool_field(row, "admissible"));
    assert_eq!(string(object(row, "bead"), "id"), "asupersync-ol11aa.9.4");
    assert_eq!(string(object(row, "bead"), "pre_status"), "open");
    assert_eq!(string(object(row, "bead"), "post_status"), "closed");
    assert_eq!(
        string(object(row, "agent_mail"), "agent_name"),
        "PinkStream"
    );
    assert_eq!(
        string(object(row, "agent_mail"), "thread_id"),
        "asupersync-ol11aa.9.4"
    );
    assert_eq!(
        u64_field(object(row, "reservation_summary"), "gap_count"),
        0
    );
    assert_eq!(u64_field(object(row, "proof_summary"), "command_count"), 1);
    assert_eq!(
        u64_field(object(row, "proof_summary"), "tests_run_total"),
        8
    );
    assert_eq!(
        u64_field(object(row, "dirty_tree_summary"), "remaining_count"),
        0
    );
    assert!(array(row, "blockers").is_empty());
}

#[test]
fn required_fail_closed_cases_are_non_admissible() {
    let report = report_json();
    let rows = rows_by_scenario(&report);

    let failed = &rows["failed-rch-cited-green"];
    assert_eq!(string(failed, "classification"), "failed-proof-cited-green");
    assert!(!bool_field(failed, "admissible"));
    assert!(string_set(failed, "blockers").contains("focused-contract-rch:exit=101"));

    let missing_remote = &rows["missing-remote-worker"];
    assert_eq!(
        string(missing_remote, "classification"),
        "missing-remote-worker-evidence"
    );
    assert!(!bool_field(missing_remote, "admissible"));
    assert!(
        string_set(missing_remote, "blockers")
            .contains("focused-contract-rch:missing-worker-identity")
    );

    let zero = &rows["zero-test-filter"];
    assert_eq!(string(zero, "classification"), "zero-test-exact-filter");
    assert!(!bool_field(zero, "admissible"));
    assert!(string_set(zero, "blockers").contains("focused-exact-filter-rch:tests_run=0"));

    let expired = &rows["expired-reservation-gap"];
    assert_eq!(string(expired, "classification"), "expired-reservation-gap");
    assert!(!bool_field(expired, "admissible"));
    assert!(
        string_set(expired, "blockers")
            .contains("reservation-gap:docs/swarm_lane_closeout_receipt.md")
    );

    let unverified = &rows["unverified-push-or-mirror"];
    assert_eq!(
        string(unverified, "classification"),
        "unverified-pushed-refs"
    );
    assert!(!bool_field(unverified, "admissible"));
    assert!(string_set(unverified, "blockers").contains("git:origin-main:unverified"));
    assert!(string_set(unverified, "blockers").contains("git:legacy-mirror:unverified"));
}

#[test]
fn peer_dirt_shared_main_lane_is_admissible_only_when_classified() {
    let report = report_json();
    let rows = rows_by_scenario(&report);
    let row = &rows["peer-dirt-shared-main"];

    assert_eq!(string(row, "classification"), "peer-dirt-shared-main");
    assert!(bool_field(row, "admissible"));
    assert_eq!(
        u64_field(object(row, "dirty_tree_summary"), "remaining_count"),
        3
    );
    let counts = object(object(row, "dirty_tree_summary"), "classification_counts");
    assert_eq!(u64_field(counts, "peer-owned"), 2);
    assert_eq!(u64_field(counts, "intentionally-unstaged"), 1);
    assert!(array(row, "blockers").is_empty());
}

#[test]
fn proof_rows_preserve_exact_argv_env_and_worker_evidence() {
    let report = report_json();
    let rows = rows_by_scenario(&report);
    let row = &rows["successful-lane"];
    let commands = array(object(row, "proof_summary"), "commands");
    let command = &commands[0];

    assert_eq!(string(command, "command_id"), "focused-contract-rch");
    assert!(
        array(command, "argv")
            .iter()
            .any(|arg| arg.as_str() == Some("rch"))
    );
    assert_eq!(string(object(command, "env"), "RCH_REQUIRE_REMOTE"), "1");
    assert_eq!(string(command, "worker_identity"), "rch-worker-17");
    assert_eq!(string(command, "target_dir_class"), "focused-contract");
    assert_eq!(
        string(command, "source_fingerprint"),
        "git:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );
    assert!(string(command, "artifact_digest").starts_with("sha256:"));
}

#[test]
fn report_forbids_overclaiming_and_lists_non_claims() {
    let report = report_json();
    let rows = rows_by_scenario(&report);

    for row in rows.values() {
        let forbidden = string_set(row, "forbidden_actions");
        for required in [
            "do-not-create-branches",
            "do-not-create-worktrees",
            "do-not-edit-peer-dirty-files",
            "do-not-cite-local-fallback-as-rch-proof",
            "do-not-cite-failed-proof-as-green",
            "do-not-cite-zero-test-filter-as-passing",
            "do-not-overwrite-or-rewrite-beads-jsonl",
            "do-not-claim-unverified-pushed-refs",
            "do-not-leave-owned-dirty-files-unclassified",
        ] {
            assert!(
                forbidden.contains(required),
                "{} must forbid {required}",
                string(row, "scenario_id")
            );
        }
        for non_claim in array(row, "evidence_does_not_prove") {
            let text = non_claim
                .as_str()
                .expect("non-claim entries must be strings");
            assert!(
                text.contains("does not prove source correctness")
                    || text.contains("do not override live br")
                    || text.contains("normal claim")
                    || text.contains("Peer dirty files"),
                "unexpected non-claim text: {text}"
            );
        }
    }
}

#[test]
fn markdown_and_docs_cover_operator_usage_and_validation() {
    let markdown = markdown_report();
    assert!(markdown.contains("# Swarm Lane Closeout Receipt"));
    assert!(markdown.contains("failed-proof-cited-green"));
    assert!(markdown.contains("peer-dirt-shared-main"));
    assert!(markdown.contains("do-not-claim-unverified-pushed-refs"));

    let docs = read_repo_file(DOC_PATH);
    for needle in [
        "python3 scripts/swarm_lane_closeout_receipt.py",
        "failed-proof-cited-green",
        "missing-remote-worker-evidence",
        "zero-test-exact-filter",
        "expired-reservation-gap",
        "unverified-pushed-refs",
        "peer-dirt-shared-main",
        "RCH_REQUIRE_REMOTE=1 rch exec --",
        "does not prove source correctness",
        "stage only the intended tracker rows",
    ] {
        assert!(docs.contains(needle), "docs must mention {needle}");
    }
}
