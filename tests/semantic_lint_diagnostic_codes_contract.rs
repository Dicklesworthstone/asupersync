#![allow(missing_docs)]

use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;

const REGISTRY_PATH: &str = "docs/error_codes/registry.json";
const ERROR_CODE_README_PATH: &str = "docs/error_codes/README.md";
const RUNNER_PATH: &str = "scripts/semantic_lint.py";

struct SemanticLintCase {
    rule_id: &'static str,
    asup_code: &'static str,
    fixture_path: &'static str,
    engine: &'static str,
}

const CASES: &[SemanticLintCase] = &[
    SemanticLintCase {
        rule_id: "ambient-time-or-entropy-in-lab-sensitive-code",
        asup_code: "ASUP-E902",
        fixture_path: "tests/fixtures/semantic_lint/ambient/positive_system_time.rs",
        engine: "portable-fallback",
    },
    SemanticLintCase {
        rule_id: "await-while-holding-capability-resource",
        asup_code: "ASUP-E903",
        fixture_path: "tests/fixtures/semantic_lint/await_holding/positive_mutex_guard.rs",
        engine: "auto",
    },
    SemanticLintCase {
        rule_id: "loop-without-cx-checkpoint",
        asup_code: "ASUP-E904",
        fixture_path: "tests/fixtures/semantic_lint/loop_checkpoint/positive_uncheckpointed_loop.rs",
        engine: "auto",
    },
    SemanticLintCase {
        rule_id: "ignored-outcome-severity",
        asup_code: "ASUP-E905",
        fixture_path: "tests/fixtures/semantic_lint/ignored_outcome/positive_ignored_outcome.rs",
        engine: "auto",
    },
    SemanticLintCase {
        rule_id: "drop-based-race-loser-handling",
        asup_code: "ASUP-E906",
        fixture_path: "tests/fixtures/semantic_lint/drop_race_loser/positive_drop_loser.rs",
        engine: "auto",
    },
    SemanticLintCase {
        rule_id: "unbounded-cleanup-budget",
        asup_code: "ASUP-E907",
        fixture_path: "tests/fixtures/semantic_lint/cleanup_budget/positive_unbounded.rs",
        engine: "portable-fallback",
    },
    SemanticLintCase {
        rule_id: "core-tokio-feature-leakage",
        asup_code: "ASUP-E908",
        fixture_path: "tests/fixtures/semantic_lint/core_tokio/positive_default_leak.json",
        engine: "auto",
    },
];

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_repo_file(relative: &str) -> String {
    std::fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|err| panic!("read {relative}: {err}"))
}

fn parse_json(relative: &str) -> Value {
    serde_json::from_str(&read_repo_file(relative))
        .unwrap_or_else(|err| panic!("parse {relative}: {err}"))
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

fn run_case(case: &SemanticLintCase) -> Value {
    let output = Command::new("python3")
        .arg(repo_path(RUNNER_PATH))
        .arg("--rule")
        .arg(case.rule_id)
        .arg("--engine")
        .arg(case.engine)
        .arg("--json")
        .arg("--exit-zero")
        .arg(repo_path(case.fixture_path))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .unwrap_or_else(|err| panic!("run {RUNNER_PATH} for {}: {err}", case.rule_id));

    assert!(
        output.status.success(),
        "runner failed for {}: {}\n{}",
        case.rule_id,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("runner must emit JSON")
}

#[test]
fn semantic_lint_findings_begin_with_registered_asup_codes() {
    for case in CASES {
        let result = run_case(case);
        assert_eq!(
            result["verdict"].as_str(),
            Some("fail"),
            "{} positive fixture must fail",
            case.rule_id
        );

        let findings = array(&result, "findings");
        assert!(
            !findings.is_empty(),
            "{} positive fixture must produce findings",
            case.rule_id
        );
        let expected_prefix = format!("[{}] ", case.asup_code);
        for finding in findings {
            let diagnostic = string(finding, "diagnostic");
            assert!(
                diagnostic.starts_with(&expected_prefix),
                "{} diagnostic must start with {}: {diagnostic}",
                case.rule_id,
                expected_prefix
            );
        }
    }
}

#[test]
fn semantic_lint_asup_codes_are_registered_documented_and_cataloged() {
    let registry = parse_json(REGISTRY_PATH);
    let registry_codes = array(&registry, "codes");
    let readme = read_repo_file(ERROR_CODE_README_PATH);

    for case in CASES {
        let entry = registry_codes
            .iter()
            .find(|entry| entry["code"].as_str() == Some(case.asup_code))
            .unwrap_or_else(|| panic!("{} missing from registry", case.asup_code));
        assert_eq!(
            string(entry, "status"),
            "live",
            "{} must be live because the runner emits it",
            case.asup_code
        );
        assert_eq!(
            string(entry, "area"),
            "config-build",
            "{} must stay in the build/tooling range",
            case.asup_code
        );
        assert!(
            array(entry, "source_refs")
                .iter()
                .any(|path| path.as_str() == Some(RUNNER_PATH)),
            "{} must point back to the semantic lint runner",
            case.asup_code
        );

        let doc_path = string(entry, "doc_path");
        let page = read_repo_file(doc_path);
        assert!(page.contains(case.asup_code));
        assert!(page.contains("## Symptom"));
        assert!(page.contains("## Probable Causes"));
        assert!(page.contains("## Fix"));
        assert!(page.contains("## Example"));
        assert!(page.contains("## Related"));

        assert!(
            readme.contains(case.asup_code),
            "{} must be listed in docs/error_codes/README.md",
            case.asup_code
        );
    }
}
