#![allow(missing_docs)]

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const CONTRACT_PATH: &str = "artifacts/proof_evidence_debt_graph_contract_v1.json";
const DOC_PATH: &str = "docs/proof_evidence_debt_graph.md";
const GENERATED_AT: &str = "2026-06-06T08:20:00Z";
const README_PATH: &str = "README.md";
const SCRIPT_PATH: &str = "scripts/proof_evidence_debt_graph.py";
const TEST_PATH: &str = "tests/proof_evidence_debt_graph_contract.rs";

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
        .expect("run proof evidence debt graph helper")
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

fn rows_by_artifact(report: &Value) -> BTreeMap<String, Value> {
    array(report, "rows")
        .iter()
        .map(|row| (string(row, "artifact_id").to_string(), row.clone()))
        .collect()
}

fn reason_set(row: &Value) -> BTreeSet<String> {
    string_set(row, "reason_codes")
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
        "write_text",
        "Path.write",
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
        "proof-evidence-debt-graph-v1"
    );
    assert_eq!(
        string(&report, "fixture_id"),
        "proof-evidence-debt-contract-fixture"
    );
    assert_eq!(string(&report, "generated_at"), GENERATED_AT);
    assert_eq!(
        u64_field(summary, "total_artifacts"),
        u64_field(expected, "total_artifacts")
    );
    assert_eq!(
        u64_field(summary, "safe_to_cite"),
        u64_field(expected, "safe_to_cite")
    );
    assert_eq!(
        u64_field(summary, "proof_debt"),
        u64_field(expected, "proof_debt")
    );

    let rows = array(&report, "rows");
    assert_eq!(
        string(&rows[0], "artifact_id"),
        string(expected, "highest_ranked_artifact"),
        "rows must be ranked by severity before artifact id"
    );

    let by_artifact = rows_by_artifact(&report);
    let safe_artifact = string(expected, "only_safe_artifact");
    for (artifact_id, row) in &by_artifact {
        if artifact_id == safe_artifact {
            assert!(
                bool_field(row, "safe_to_cite"),
                "{artifact_id} should be safe"
            );
            assert_eq!(
                reason_set(row).len(),
                0,
                "{artifact_id} should have no debt"
            );
        } else {
            assert!(
                !bool_field(row, "safe_to_cite"),
                "{artifact_id} should not be citeable"
            );
        }
    }
}

#[test]
fn every_required_reason_code_is_exercised_once() {
    let contract = json_file(CONTRACT_PATH);
    let expected_reason_codes = string_set(&contract, "required_reason_codes");
    let report = report_json();
    let reason_counts = object(object(&report, "summary"), "reason_counts");

    for reason in &expected_reason_codes {
        assert_eq!(
            reason_counts
                .get(reason)
                .and_then(Value::as_u64)
                .unwrap_or_default(),
            1,
            "{reason} should be exercised exactly once"
        );
        assert!(
            object(&report, "reason_catalog").get(reason).is_some(),
            "{reason} missing from reason_catalog"
        );
    }
}

#[test]
fn row_reason_codes_preserve_fail_closed_semantics() {
    let rows = rows_by_artifact(&report_json());

    assert!(reason_set(&rows["stale-narrow-lib-proof"]).contains("stale-head"));
    assert!(reason_set(&rows["superseded-raptorq-smoke"]).contains("superseded-by-newer-artifact"));
    assert!(reason_set(&rows["zero-test-exact-filter"]).contains("zero-tests"));
    assert!(reason_set(&rows["local-fallback-proof"]).contains("local-fallback"));
    assert!(reason_set(&rows["advisory-pressure-snapshot"]).contains("advisory-only"));

    let dirty_reasons = reason_set(&rows["dirty-peer-overlap"]);
    assert!(dirty_reasons.contains("dirty-overlap"));
    assert!(dirty_reasons.contains("blocked-by-peer-reservation"));
    assert!(
        !bool_field(
            &rows["advisory-pressure-snapshot"],
            "safe_for_correctness_claim"
        ),
        "advisory-only evidence must never become correctness proof"
    );

    let failed_reasons = reason_set(&rows["failed-release-gate"]);
    assert!(failed_reasons.contains("failed-proof-status"));
    assert!(failed_reasons.contains("missing-envelope"));
}

#[test]
fn graph_edges_cover_artifacts_and_supersession() {
    let report = report_json();
    let artifact_count = array(&report, "rows").len();
    let covers_edges = array(&report, "edges")
        .iter()
        .filter(|edge| string(edge, "kind") == "covers-lane")
        .count();
    assert_eq!(
        covers_edges, artifact_count,
        "each artifact must have a covers-lane edge"
    );

    let supersession = array(&report, "edges")
        .iter()
        .find(|edge| string(edge, "kind") == "superseded-by")
        .expect("supersession edge must exist");
    assert_eq!(
        string(supersession, "from"),
        "artifact:superseded-raptorq-smoke"
    );
    assert_eq!(
        string(supersession, "to"),
        "artifact:current-focused-manifest"
    );
}

#[test]
fn markdown_report_lists_non_claims_reason_codes_and_rch_commands() {
    let markdown = markdown_report();
    for needle in [
        "# Proof Evidence Debt Graph",
        "This graph ranks proof debt and rerun needs; it is not workspace health.",
        "Advisory-only evidence is never upgraded to correctness evidence.",
        "blocked-by-peer-reservation, dirty-overlap",
        "local-fallback",
        "missing-envelope, failed-proof-status",
        "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_proof_lane_manifest",
    ] {
        assert!(
            markdown.contains(needle),
            "markdown report missing expected text: {needle}"
        );
    }
}

#[test]
fn docs_and_readme_track_the_contract_surface() {
    for path in [README_PATH, DOC_PATH, TEST_PATH, CONTRACT_PATH, SCRIPT_PATH] {
        assert!(repo_path(path).exists(), "{path} must exist");
    }

    let docs = read_repo_file(DOC_PATH);
    let readme = read_repo_file(README_PATH);
    for needle in [
        "scripts/proof_evidence_debt_graph.py",
        "artifacts/proof_evidence_debt_graph_contract_v1.json",
        "tests/proof_evidence_debt_graph_contract.rs",
        "blocked-by-peer-reservation",
        "local-fallback",
        "zero-tests",
        "advisory-only",
        "does not certify workspace health",
    ] {
        assert!(docs.contains(needle), "docs missing {needle}");
    }
    for needle in [
        "Proof Evidence Debt Graph",
        "artifacts/proof_evidence_debt_graph_contract_v1.json",
        "scripts/proof_evidence_debt_graph.py",
    ] {
        assert!(readme.contains(needle), "README missing {needle}");
    }
}
