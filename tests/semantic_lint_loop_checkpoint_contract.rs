#![allow(missing_docs)]

use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

const CONTRACT_PATH: &str = "artifacts/semantic_lint_loop_checkpoint_rule_contract_v1.json";
const INVENTORY_PATH: &str = "artifacts/semantic_lint_rule_inventory_v1.json";
const DOCS_PATH: &str = "docs/semantic_lint_loop_checkpoint_rule.md";
const RUNNER_PATH: &str = "scripts/semantic_lint.py";
const RULE_ID: &str = "loop-without-cx-checkpoint";
const BEAD_ID: &str = "asupersync-idea-wizard-fifth-wave-3gaiun.3.2";

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

fn bool_field(value: &Value, key: &str) -> bool {
    value
        .get(key)
        .and_then(Value::as_bool)
        .unwrap_or_else(|| panic!("{key} must be a bool"))
}

fn array<'a>(value: &'a Value, key: &str) -> &'a Vec<Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
}

fn child<'a>(value: &'a Value, key: &str) -> &'a Value {
    value
        .get(key)
        .unwrap_or_else(|| panic!("{key} must be present"))
}

fn run_runner(paths: &[&str]) -> (String, Value) {
    let output = Command::new("python3")
        .arg(repo_path(RUNNER_PATH))
        .arg("--rule")
        .arg(RULE_ID)
        .arg("--engine")
        .arg("auto")
        .arg("--json")
        .arg("--exit-zero")
        .args(paths.iter().map(|path| repo_path(path)))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .unwrap_or_else(|err| panic!("run {RUNNER_PATH}: {err}"));

    assert!(
        output.status.success(),
        "runner failed: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("runner output must be utf-8");
    let parsed: Value = serde_json::from_str(&stdout).expect("runner must emit json");
    (stdout, parsed)
}

#[test]
fn contract_links_inventory_runner_docs_and_fixtures() {
    let contract = parse_json(CONTRACT_PATH);
    assert_eq!(
        contract["contract_version"].as_str(),
        Some("semantic-lint-loop-checkpoint-rule-contract-v1")
    );
    assert_eq!(contract["rule_id"].as_str(), Some(RULE_ID));
    assert_eq!(contract["bead_id"].as_str(), Some(BEAD_ID));

    let source = child(&contract, "source_of_truth");
    for key in [
        "inventory",
        "contract",
        "contract_test",
        "runner",
        "docs",
        "positive_fixture",
        "negative_checkpoint_fixture",
        "negative_bounded_fixture",
        "valid_allow_fixture",
        "invalid_allow_fixture",
    ] {
        let path = string(source, key);
        assert!(
            repo_path(path).exists(),
            "source_of_truth.{key} must point at a live path: {path}"
        );
    }

    let implementation = child(&contract, "implementation");
    assert_eq!(
        string(implementation, "selected_engine"),
        "hybrid-rustc-hir-ast-grep"
    );
    assert_eq!(string(implementation, "runner_default_engine"), "auto");
    assert!(bool_field(implementation, "candidate_scanner"));
    assert!(bool_field(
        implementation,
        "requires_future_hir_confirmation"
    ));
    assert!(bool_field(implementation, "no_source_rewrites"));
    assert!(bool_field(implementation, "no_runtime_behavior_change"));
}

#[test]
fn contract_matches_l1_inventory_decision() {
    let inventory = parse_json(INVENTORY_PATH);
    let rows = array(&inventory, "rule_rows");
    let row = rows
        .iter()
        .find(|row| row["rule_id"].as_str() == Some(RULE_ID))
        .expect("loop checkpoint rule must be in inventory");

    assert_eq!(string(row, "owner_bead"), BEAD_ID);
    assert_eq!(string(row, "selected_engine"), "hybrid-rustc-hir-ast-grep");
    assert_eq!(string(row, "status"), "requires-design");

    let contract = parse_json(CONTRACT_PATH);
    let target_paths = array(&contract, "target_paths")
        .iter()
        .map(|value| value.as_str().expect("target path string"))
        .collect::<BTreeSet<_>>();
    let inventory_paths = array(row, "target_paths")
        .iter()
        .map(|value| value.as_str().expect("target path string"))
        .collect::<BTreeSet<_>>();
    assert_eq!(target_paths, inventory_paths);
}

#[test]
fn runner_reports_uncheckpointed_async_loop_fixture() {
    let (_, result) = run_runner(&[
        "tests/fixtures/semantic_lint/loop_checkpoint/positive_uncheckpointed_loop.rs",
    ]);

    assert_eq!(
        result["schema_version"].as_str(),
        Some("semantic-lint-results-v1")
    );
    assert_eq!(result["rule_id"].as_str(), Some(RULE_ID));
    assert_eq!(result["engine"].as_str(), Some("hybrid-rustc-hir-ast-grep"));
    assert_eq!(result["verdict"].as_str(), Some("fail"));
    assert_eq!(result["summary"]["findings"].as_u64(), Some(1));

    let findings = array(&result, "findings");
    assert_eq!(string(&findings[0], "kind"), "loop_without_cx_checkpoint");
    assert_eq!(string(&findings[0], "severity"), "warning");
    assert!(
        string(&findings[0], "diagnostic").contains("checkpoint"),
        "diagnostic must name the missing checkpoint"
    );
}

#[test]
fn runner_accepts_checkpointed_and_bounded_loops() {
    let (_, result) = run_runner(&[
        "tests/fixtures/semantic_lint/loop_checkpoint/negative_checkpointed_loop.rs",
        "tests/fixtures/semantic_lint/loop_checkpoint/negative_bounded_loop.rs",
    ]);

    assert_eq!(result["verdict"].as_str(), Some("pass"));
    assert_eq!(result["summary"]["findings"].as_u64(), Some(0));
    assert_eq!(array(&result, "findings").len(), 0);
}

#[test]
fn allow_markers_require_reason_and_owner_bead() {
    let (_, allowed) = run_runner(&["tests/fixtures/semantic_lint/loop_checkpoint/valid_allow.rs"]);
    assert_eq!(allowed["verdict"].as_str(), Some("pass"));
    assert_eq!(allowed["summary"]["findings"].as_u64(), Some(0));
    assert_eq!(allowed["summary"]["suppressed"].as_u64(), Some(1));
    assert_eq!(
        allowed["suppressed"][0]["owner"].as_str(),
        Some(BEAD_ID),
        "valid allow marker must preserve owner bead"
    );

    let (_, invalid) =
        run_runner(&["tests/fixtures/semantic_lint/loop_checkpoint/invalid_allow.rs"]);
    assert_eq!(invalid["verdict"].as_str(), Some("fail"));
    assert_eq!(
        invalid["summary"]["invalid_allow_markers"].as_u64(),
        Some(1)
    );
    let findings = array(&invalid, "findings");
    assert!(
        findings
            .iter()
            .any(|finding| string(finding, "kind") == "invalid_allow_marker"),
        "invalid marker must be reported as its own diagnostic"
    );
    assert!(
        findings
            .iter()
            .any(|finding| string(finding, "kind") == "loop_without_cx_checkpoint"),
        "invalid marker must not suppress the loop finding"
    );
}

#[test]
fn runner_output_is_stable_and_docs_name_no_claim_boundary() {
    let paths = [
        "tests/fixtures/semantic_lint/loop_checkpoint/positive_uncheckpointed_loop.rs",
        "tests/fixtures/semantic_lint/loop_checkpoint/valid_allow.rs",
        "tests/fixtures/semantic_lint/loop_checkpoint/invalid_allow.rs",
    ];
    let (first, _) = run_runner(&paths);
    let (second, _) = run_runner(&paths);
    assert_eq!(first, second);

    let docs = read_repo_file(DOCS_PATH);
    assert!(docs.contains(RULE_ID));
    assert!(docs.contains("not a complete rustc-HIR implementation"));

    let contract = parse_json(CONTRACT_PATH);
    let no_claims = array(&contract, "no_claims");
    assert!(
        no_claims.iter().any(|claim| {
            claim
                .as_str()
                .is_some_and(|text| text.contains("does not close every rule"))
        }),
        "contract must keep the L2 no-claim boundary explicit"
    );
}
