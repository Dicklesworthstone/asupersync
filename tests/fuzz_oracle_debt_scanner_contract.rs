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

fn run_scanner_with_output(root: &str, output: &str) -> Output {
    Command::new("python3")
        .arg(repo_root().join(SCRIPT_PATH))
        .arg("--repo-root")
        .arg(repo_root())
        .arg("--root")
        .arg(root)
        .arg("--generated-at")
        .arg(GENERATED_AT)
        .arg("--output")
        .arg(output)
        .current_dir(repo_root())
        .output()
        .expect("run fuzz oracle debt scanner")
}

fn run_scanner(root: &str) -> Output {
    run_scanner_with_output(root, "json")
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

fn scan_templates(root: &str) -> Value {
    let output = run_scanner_with_output(root, "bead-template");
    assert!(
        output.status.success(),
        "template generation failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("template output must be JSON")
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

#[test]
fn bead_template_output_is_review_only_and_one_finding_per_body() {
    let report = scan_templates("tests/fixtures/fuzz_oracle_debt_scanner/targets");

    assert_eq!(
        report["schema_version"].as_str(),
        Some("fuzz-oracle-debt-bead-template-v1")
    );
    assert_eq!(
        report["source_schema_version"].as_str(),
        Some("fuzz-oracle-debt-scan-v1")
    );
    assert_eq!(report["dry_run"].as_bool(), Some(true));
    assert_eq!(report["review_required"].as_bool(), Some(true));
    assert_eq!(report["auto_create_beads"].as_bool(), Some(false));
    assert_eq!(report["template_count"].as_u64(), Some(4));
    assert_eq!(
        report["forbidden_actions"]["runs_beads_mutation"].as_bool(),
        Some(false)
    );

    let templates = report["templates"].as_array().expect("templates array");
    assert_eq!(templates.len(), 4);

    for template in templates {
        assert_eq!(template["dry_run_only"].as_bool(), Some(true));
        assert_eq!(template["auto_create_bead"].as_bool(), Some(false));
        let finding = template.get("finding").expect("template finding");
        let file = finding["file"].as_str().expect("finding file");
        let pattern = finding["pattern"].as_str().expect("finding pattern");
        let body = template["body_md"].as_str().expect("body markdown");

        assert_eq!(
            template["reservation_paths"]
                .as_array()
                .expect("reservations")
                .len(),
            1,
            "each generated bead body must reserve one finding file"
        );
        assert!(
            body.contains(file) && body.contains(pattern),
            "body must preserve exact file and pattern: {body}"
        );
        assert!(
            body.contains("Expected Oracle")
                && body.contains("CARGO_TARGET_DIR")
                && body.contains("Stale-Pattern Rescan")
                && body.contains("Dry-run template only"),
            "body must include oracle, target dir, rescan, and review boundary"
        );
        assert!(
            template["stale_pattern_rescan_command"]
                .as_str()
                .expect("stale rescan")
                .contains("--output json"),
            "rescan command should return scanner JSON"
        );
        assert!(
            template["validation_commands"]
                .as_array()
                .expect("validation commands")
                .iter()
                .all(|command| {
                    command
                        .as_str()
                        .expect("validation command")
                        .contains("rch exec -- env CARGO_TARGET_DIR=")
                }),
            "every validation command must preserve rch target-dir guidance"
        );
    }
}
