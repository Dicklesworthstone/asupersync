//! Contract tests for the fuzz oracle-debt scanner.

#![allow(missing_docs)]

use serde_json::Value;
use std::path::PathBuf;
use std::process::{Command, Output};

const SCRIPT_PATH: &str = "scripts/fuzz_oracle_debt_scanner.py";
const GENERATED_AT: &str = "2026-05-10T07:45:00Z";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn run_scanner(root: &str) -> Output {
    Command::new("python3")
        .arg(repo_root().join(SCRIPT_PATH))
        .arg("--repo-root")
        .arg(repo_root())
        .arg("--root")
        .arg(root)
        .arg("--generated-at")
        .arg(GENERATED_AT)
        .arg("--output")
        .arg("json")
        .current_dir(repo_root())
        .output()
        .expect("run fuzz oracle debt scanner")
}

fn scan_json(root: &str) -> Value {
    let output = run_scanner(root);
    assert!(
        output.status.success(),
        "scanner failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("scanner output must be JSON")
}

fn findings(report: &Value) -> &Vec<Value> {
    report["findings"].as_array().expect("findings array")
}

fn patterns(report: &Value) -> Vec<&str> {
    findings(report)
        .iter()
        .filter_map(|row| row["pattern"].as_str())
        .collect()
}

#[test]
fn script_exists_and_help_is_non_mutating() {
    assert!(
        repo_root().join(SCRIPT_PATH).exists(),
        "scanner must exist at {SCRIPT_PATH}"
    );
    let output = Command::new("python3")
        .arg(repo_root().join(SCRIPT_PATH))
        .arg("--help")
        .current_dir(repo_root())
        .output()
        .expect("run scanner --help");
    assert!(output.status.success(), "--help should succeed");
}

#[test]
fn scanner_reports_named_oracle_debt_patterns() {
    let report = scan_json("tests/fixtures/fuzz_oracle_debt_scanner/targets");

    assert_eq!(
        report["schema_version"].as_str(),
        Some("fuzz-oracle-debt-scan-v1")
    );
    assert_eq!(report["generated_at"].as_str(), Some(GENERATED_AT));
    assert_eq!(report["current_date"].as_str(), Some("2026-05-10"));
    assert_eq!(report["scope"].as_str(), Some("fuzz-targets-only"));
    assert_eq!(report["summary"]["total_findings"].as_u64(), Some(4));

    let patterns = patterns(&report);
    for required in [
        "swallowed-serialization-default",
        "thread-join-fallback",
        "ignored-result",
        "catch-unwind-return",
    ] {
        assert!(
            patterns.contains(&required),
            "missing required pattern {required}: {patterns:?}"
        );
    }
}

#[test]
fn findings_include_file_line_and_suggested_assertion() {
    let report = scan_json("tests/fixtures/fuzz_oracle_debt_scanner/targets");

    for row in findings(&report) {
        assert!(
            row["file"]
                .as_str()
                .expect("file")
                .starts_with("tests/fixtures/fuzz_oracle_debt_scanner/targets/")
        );
        assert!(row["line"].as_u64().expect("line") > 0);
        assert!(
            !row["snippet"].as_str().expect("snippet").is_empty(),
            "snippet should be actionable"
        );
        assert!(
            row["suggested_assertion"]
                .as_str()
                .expect("suggestion")
                .contains("context")
                || row["suggested_assertion"]
                    .as_str()
                    .expect("suggestion")
                    .contains("join().expect")
        );
    }
}

#[test]
fn scanner_keeps_false_positive_guards_quiet() {
    let report = scan_json("tests/fixtures/fuzz_oracle_debt_scanner/guards");

    assert_eq!(report["summary"]["total_findings"].as_u64(), Some(0));
    assert!(
        findings(&report).is_empty(),
        "guard fixtures should not produce findings"
    );
}

#[test]
fn scanner_declares_non_mutating_behavior() {
    let report = scan_json("tests/fixtures/fuzz_oracle_debt_scanner/targets");

    assert_eq!(report["non_mutating"].as_bool(), Some(true));
    for key in [
        "runs_cargo",
        "runs_git_mutation",
        "runs_beads_mutation",
        "runs_destructive_command",
    ] {
        assert_eq!(
            report["forbidden_actions"][key].as_bool(),
            Some(false),
            "{key} must stay false"
        );
    }
}
