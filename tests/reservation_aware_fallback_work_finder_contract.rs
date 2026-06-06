#![allow(missing_docs)]

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const CONTRACT_PATH: &str = "artifacts/reservation_aware_fallback_work_finder_contract_v1.json";
const DOC_PATH: &str = "docs/reservation_aware_fallback_work_finder.md";
const GENERATED_AT: &str = "2026-06-06T10:20:00Z";
const README_PATH: &str = "README.md";
const SCRIPT_PATH: &str = "scripts/reservation_aware_fallback_work_finder.py";
const TEST_PATH: &str = "tests/reservation_aware_fallback_work_finder_contract.rs";

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
        .expect("run reservation-aware fallback work finder")
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
fn script_exists_and_help_is_read_only() {
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
        "cargo test",
        "cargo check",
        "br update",
        "br close",
        "bv ",
        "send_message",
        "file_reservation_paths",
        "write_text",
        "Path.write",
        "open(\"w\"",
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
        "reservation-aware-fallback-work-finder-v1"
    );
    assert_eq!(
        string(&report, "fixture_id"),
        "reservation-aware-fallback-work-finder-contract-fixture"
    );
    assert_eq!(string(&report, "generated_at"), GENERATED_AT);
    for key in [
        "scenario_count",
        "safe_to_start_work",
        "create_new_bead",
        "claimable_ready_tasks",
        "reopen_candidates",
        "blocked_actions",
    ] {
        assert_eq!(u64_field(summary, key), u64_field(expected, key), "{key}");
    }
    assert_eq!(
        string(&array(&report, "rows")[0], "scenario_id"),
        string(expected, "highest_ranked_scenario")
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
fn recommendations_never_allow_peer_edits_branches_worktrees_or_local_cargo() {
    let report = report_json();
    let rows = rows_by_scenario(&report);

    for row in rows.values() {
        let forbidden_actions = string_set(row, "forbidden_actions");
        for required in [
            "do-not-create-branches",
            "do-not-create-worktrees",
            "do-not-edit-peer-reserved-paths",
            "do-not-override-agent-mail-reservations",
            "do-not-accept-local-cargo-fallback",
        ] {
            assert!(
                forbidden_actions.contains(required),
                "{} must forbid {required}",
                string(row, "scenario_id")
            );
        }
        for non_claim in array(row, "evidence_does_not_prove") {
            let text = non_claim
                .as_str()
                .expect("non-claim entries must be strings");
            assert!(
                text.contains("does not certify source correctness")
                    || text.contains("does not override live Agent Mail reservations")
                    || text.contains("No recommendation authorizes branch/worktree")
                    || text.contains("local fallback is never proof"),
                "unexpected non-claim text: {text}"
            );
        }
    }

    let blocked = &rows["blocked-ready-by-reservation"];
    assert_eq!(
        string(blocked, "classification"),
        "blocked-by-active-reservation"
    );
    assert!(!bool_field(blocked, "safe_to_start_work"));
    assert!(
        string_set(blocked, "avoid_paths").contains("src/channel/*.rs"),
        "blocked row must carry reservation avoid paths"
    );
    assert!(
        !array(blocked, "reservation_overlaps").is_empty(),
        "blocked row must explain reservation overlap"
    );

    let source = &rows["source-peer-dirty-tree"];
    assert_eq!(string(source, "classification"), "source-peer-dirt");
    assert!(!bool_field(source, "safe_to_start_work"));
    assert!(
        string_set(source, "avoid_paths").contains("src/atp/journal/sparse_writer.rs"),
        "source peer dirt must be avoided"
    );
    assert!(
        string_set(source, "forbidden_actions").contains("do-not-stage-peer-dirty-source"),
        "source peer dirt must not be staged"
    );
}

#[test]
fn stale_in_progress_reopen_requires_inactivity_and_no_active_reservation() {
    let rows = rows_by_scenario(&report_json());

    let stale = &rows["stale-in-progress-reopen"];
    assert_eq!(
        string(stale, "classification"),
        "stale-in-progress-candidate"
    );
    assert!(bool_field(stale, "safe_to_start_work"));
    assert_eq!(
        stale.get("claim_issue_id").expect("claim_issue_id present"),
        &Value::Null
    );
    assert_eq!(
        string(stale, "reopen_issue_id"),
        "asupersync-stale-docs-lane"
    );
    assert!(
        array(stale, "reservation_overlaps").is_empty(),
        "stale reopen must not overlap active reservations"
    );

    let blocked = &rows["blocked-ready-by-reservation"];
    assert_eq!(
        blocked
            .get("reopen_issue_id")
            .expect("reopen_issue_id present"),
        &Value::Null,
        "active reservation scenario must not be treated as stale reopen"
    );
}

#[test]
fn markdown_report_lists_actions_blockers_and_forbidden_operations() {
    let markdown = markdown_report();
    for marker in [
        "# Reservation-Aware Fallback Work Finder",
        "blocked-ready-by-reservation",
        "`blocked-by-active-reservation`",
        "`coordinate-or-wait-for-reservation`",
        "ready issue asupersync-channel-telemetry overlaps an active peer reservation",
        "`do-not-create-branches`",
        "`do-not-create-worktrees`",
        "`do-not-edit-peer-reserved-paths`",
        "`do-not-accept-local-cargo-fallback`",
        "The finder recommends a next action; it does not certify source correctness.",
    ] {
        assert!(
            markdown.contains(marker),
            "markdown missing marker: {marker}"
        );
    }
}

#[test]
fn docs_and_readme_track_the_contract_surface() {
    let docs = read_repo_file(DOC_PATH);
    let readme = read_repo_file(README_PATH);
    let test = read_repo_file(TEST_PATH);
    for marker in [
        SCRIPT_PATH,
        CONTRACT_PATH,
        TEST_PATH,
        "reservation-aware-fallback-work-finder-v1",
        "blocked-by-active-reservation",
        "planning-fallback-recommended",
        "RCH_REQUIRE_REMOTE=1 rch exec --",
    ] {
        assert!(docs.contains(marker), "docs missing marker: {marker}");
        assert!(test.contains(marker), "test missing marker: {marker}");
    }
    for marker in [
        CONTRACT_PATH,
        SCRIPT_PATH,
        TEST_PATH,
        DOC_PATH,
        "Reservation-Aware Fallback Work Finder",
    ] {
        assert!(readme.contains(marker), "README missing marker: {marker}");
    }
}
