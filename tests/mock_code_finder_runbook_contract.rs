#![allow(missing_docs)]

use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const RUNBOOK: &str = include_str!("../docs/mock_code_finder_proof_runbook.md");

fn repo_path(path: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(path)
}

fn run_ok(mut command: Command, label: &str) -> std::process::Output {
    let output = command.output().unwrap_or_else(|error| {
        panic!("run {label}: {error}");
    });
    assert!(
        output.status.success(),
        "{label} failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn str_field<'a>(value: &'a Value, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("missing string field {key}"))
}

fn array<'a>(value: &'a Value, key: &str) -> &'a Vec<Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("missing array field {key}"))
}

fn extract_sample_jsonl() -> String {
    let start = "<!-- mock-code-finder-sample-jsonl:start -->";
    let end = "<!-- mock-code-finder-sample-jsonl:end -->";
    let block = RUNBOOK
        .split_once(start)
        .expect("runbook sample start marker")
        .1
        .split_once(end)
        .expect("runbook sample end marker")
        .0;
    let lines: Vec<_> = block
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with('{'))
        .collect();
    assert_eq!(
        lines.len(),
        6,
        "runbook should document one sample record for each verdict"
    );
    lines.join("\n") + "\n"
}

#[test]
fn runbook_documents_operator_commands_and_semantics() {
    for snippet in [
        "python3 scripts/run_mock_code_finder_evidence.py --list --mode rch --run-id smoke-list",
        "python3 scripts/run_mock_code_finder_evidence.py --dry-run --ci --run-id ci-smoke",
        "python3 scripts/run_mock_code_finder_evidence.py --self-test",
        "python3 scripts/run_mock_code_finder_evidence.py --mode local --artifact-root artifacts/mock-code-finder/asupersync-oelvq2 --run-id local-proof",
        "rch exec -- python3 scripts/run_mock_code_finder_evidence.py --mode rch --artifact-root artifacts/mock-code-finder/asupersync-oelvq2 --run-id rch-proof",
        "python3 scripts/run_mock_code_finder_evidence.py --child asupersync-a45 --mode local --run-id no-mock-rerun",
        "ASUPERSYNC_POSTGRES_TEST_URL=<redacted>",
        "first_failure_line",
        "mock-code-finder-aggregate.json",
        "mock-code-finder-aggregate.summary.md",
        "production_stub",
        "conformance_placeholder",
        "intentional_test_double",
        "fixture_reference_implementation",
        "stale_audit_prose",
        "Proceed to `asupersync-u7y` only after all of this is true",
    ] {
        assert!(
            RUNBOOK.contains(snippet),
            "runbook must contain `{snippet}`"
        );
    }

    for verdict in [
        "pass",
        "fail",
        "blocked",
        "unsupported",
        "expected_fail",
        "fixture_only",
    ] {
        assert!(
            RUNBOOK.contains(&format!("`{verdict}`")),
            "runbook must document verdict `{verdict}`"
        );
    }
}

#[test]
fn documented_list_dry_run_and_self_test_commands_match_runner_output() {
    let list = run_ok(
        {
            let mut command = Command::new("python3");
            command
                .arg("scripts/run_mock_code_finder_evidence.py")
                .arg("--list")
                .arg("--mode")
                .arg("rch")
                .arg("--run-id")
                .arg("smoke-list")
                .current_dir(repo_path(""));
            command
        },
        "aggregate runner documented list command",
    );
    let list_payload: Value = serde_json::from_slice(&list.stdout).expect("parse list output");
    assert_eq!(
        str_field(&list_payload, "schema_version"),
        "mock-code-finder-aggregate-plan-v1"
    );
    assert_eq!(str_field(&list_payload, "mode"), "rch");

    let child_ids: BTreeSet<_> = array(&list_payload, "children")
        .iter()
        .map(|child| str_field(child, "child_bead_id"))
        .collect();
    assert_eq!(
        child_ids,
        BTreeSet::from([
            "asupersync-a45",
            "asupersync-a5d34a",
            "asupersync-hxi1ga",
            "asupersync-kokw3m",
            "asupersync-uw9zg9",
            "asupersync-zftrj9",
        ])
    );
    for child in array(&list_payload, "children") {
        let child_id = str_field(child, "child_bead_id");
        let subsystem = str_field(child, "subsystem");
        assert!(
            RUNBOOK.contains(child_id) && RUNBOOK.contains(subsystem),
            "runbook should document child {child_id} / {subsystem}"
        );
    }

    let dry_run = run_ok(
        {
            let mut command = Command::new("python3");
            command
                .arg("scripts/run_mock_code_finder_evidence.py")
                .arg("--dry-run")
                .arg("--ci")
                .arg("--run-id")
                .arg("ci-smoke")
                .current_dir(repo_path(""));
            command
        },
        "aggregate runner documented dry-run command",
    );
    let dry_run_payload: Value =
        serde_json::from_slice(&dry_run.stdout).expect("parse dry-run output");
    assert_eq!(str_field(&dry_run_payload, "mode"), "ci");
    assert_eq!(str_field(&dry_run_payload, "run_id"), "ci-smoke");

    let self_test = run_ok(
        {
            let mut command = Command::new("python3");
            command
                .arg("scripts/run_mock_code_finder_evidence.py")
                .arg("--self-test")
                .current_dir(repo_path(""));
            command
        },
        "aggregate runner documented self-test command",
    );
    assert!(
        String::from_utf8_lossy(&self_test.stdout)
            .contains("mock-code-finder aggregate self-test: pass")
    );
}

#[test]
fn runbook_sample_jsonl_validates_against_shared_evidence_contract() {
    let root = repo_path("target/mock-code-finder/asupersync-n9laev-runbook-contract")
        .join(std::process::id().to_string());
    fs::create_dir_all(&root).expect("create runbook contract target dir");
    let jsonl = root.join("runbook-sample.jsonl");
    let summary = root.join("runbook-sample.summary.json");
    fs::write(&jsonl, extract_sample_jsonl()).expect("write runbook sample jsonl");

    run_ok(
        {
            let mut command = Command::new("python3");
            command
                .arg("scripts/validate_mock_code_finder_evidence.py")
                .arg("--contract")
                .arg("artifacts/mock_code_finder_verification_contract_v1.json")
                .arg("--jsonl")
                .arg(&jsonl)
                .arg("--summary-output")
                .arg(&summary)
                .current_dir(repo_path(""));
            command
        },
        "validate runbook sample JSONL",
    );

    let summary_json: Value =
        serde_json::from_str(&fs::read_to_string(summary).expect("read summary"))
            .expect("parse summary");
    let entry = summary_json
        .get(jsonl.to_str().expect("jsonl path is utf-8"))
        .expect("summary entry for sample JSONL");
    assert_eq!(entry["records"], Value::from(6));
    for verdict in [
        "pass",
        "fail",
        "blocked",
        "unsupported",
        "expected_fail",
        "fixture_only",
    ] {
        assert_eq!(entry["verdicts"][verdict], Value::from(1));
    }
}
