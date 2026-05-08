//! Contract tests for the fail-closed adapter certification matrix.

#![allow(missing_docs)]

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const MATRIX_PATH: &str = "artifacts/adapter_certification_matrix_v1.json";
const TEST_PATH: &str = "tests/adapter_certification_matrix_contract.rs";

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_repo_file(relative: &str) -> String {
    std::fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|err| panic!("read {relative}: {err}"))
}

fn matrix() -> Value {
    serde_json::from_str(&read_repo_file(MATRIX_PATH))
        .unwrap_or_else(|err| panic!("parse {MATRIX_PATH}: {err}"))
}

fn array<'a>(value: &'a Value, key: &str) -> &'a Vec<Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
}

fn string<'a>(value: &'a Value, key: &str) -> &'a str {
    let text = value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"));
    assert!(!text.trim().is_empty(), "{key} must be nonempty");
    text
}

fn bool_field(value: &Value, key: &str) -> bool {
    value
        .get(key)
        .and_then(Value::as_bool)
        .unwrap_or_else(|| panic!("{key} must be a bool"))
}

fn string_set(value: &Value, key: &str) -> BTreeSet<String> {
    array(value, key)
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .unwrap_or_else(|| panic!("{key} entries must be strings"))
                .to_string()
        })
        .collect()
}

fn status_allows_pass(matrix: &Value) -> BTreeMap<String, bool> {
    array(matrix, "status_catalog")
        .iter()
        .map(|entry| {
            (
                string(entry, "status").to_string(),
                bool_field(entry, "allows_pass"),
            )
        })
        .collect()
}

fn source_bundle(row: &Value) -> String {
    array(row, "source_paths")
        .iter()
        .map(|path| {
            let path = path.as_str().expect("source path string");
            assert!(repo_path(path).exists(), "source path must exist: {path}");
            read_repo_file(path)
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn render_markdown(matrix: &Value) -> Vec<String> {
    let mut lines = vec![
        "| adapter | category | status | fail closed | proof count |".to_string(),
        "|---|---|---|---|---|".to_string(),
    ];

    for row in array(matrix, "adapters") {
        let fail_closed = if bool_field(row, "fail_closed_without_full_reference") {
            "yes"
        } else {
            "no"
        };
        lines.push(format!(
            "| {} | {} | {} | {} | {} |",
            string(row, "adapter_id"),
            string(row, "category"),
            string(row, "rendered_status"),
            fail_closed,
            array(row, "proof_commands").len()
        ));
    }

    lines
}

#[test]
fn matrix_declares_required_schema_sources_and_categories() {
    let matrix = matrix();
    assert_eq!(
        matrix.get("contract_version").and_then(Value::as_str),
        Some("adapter-certification-matrix-v1")
    );
    assert_eq!(
        matrix.get("bead_id").and_then(Value::as_str),
        Some("asupersync-y5rb4y")
    );
    assert_eq!(
        matrix["source_of_truth"]["matrix"].as_str(),
        Some(MATRIX_PATH)
    );
    assert_eq!(
        matrix["source_of_truth"]["verifier"].as_str(),
        Some(TEST_PATH)
    );

    let required = string_set(&matrix, "required_categories");
    let actual = array(&matrix, "adapters")
        .iter()
        .map(|row| string(row, "category").to_string())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        actual, required,
        "adapter matrix must cover each required category exactly once"
    );
    assert_eq!(actual.len(), 5, "matrix must cover five adapter categories");
}

#[test]
fn adapter_rows_are_source_owned_and_have_rch_proofs() {
    let matrix = matrix();
    let allowed_status = status_allows_pass(&matrix);
    let mut adapter_ids = BTreeSet::new();

    for row in array(&matrix, "adapters") {
        let adapter_id = string(row, "adapter_id");
        assert!(
            adapter_ids.insert(adapter_id.to_string()),
            "duplicate adapter id {adapter_id}"
        );
        assert!(
            allowed_status.contains_key(string(row, "certification_status")),
            "unknown certification status for {adapter_id}"
        );

        let source = source_bundle(row);
        for marker in array(row, "source_markers") {
            let marker = marker.as_str().expect("source marker string");
            assert!(
                source.contains(marker),
                "{adapter_id} source bundle must contain marker {marker:?}"
            );
        }

        for command in array(row, "proof_commands") {
            let command = command.as_str().expect("proof command string");
            assert!(
                command.starts_with("rch exec -- "),
                "{adapter_id} proof command must be rch-routed: {command}"
            );
            assert!(
                command.contains(" cargo test "),
                "{adapter_id} proof command should name a cargo test lane: {command}"
            );
            assert!(
                command.contains("CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_adapter_matrix_"),
                "{adapter_id} proof command should use an isolated rch target dir: {command}"
            );
        }
    }
}

#[test]
fn partial_and_unavailable_rows_cannot_render_green() {
    let matrix = matrix();
    let allowed_status = status_allows_pass(&matrix);

    for row in array(&matrix, "adapters") {
        let adapter_id = string(row, "adapter_id");
        let status = string(row, "certification_status");
        let allows_pass = *allowed_status
            .get(status)
            .unwrap_or_else(|| panic!("unknown status {status}"));
        let verdicts = string_set(row, "runtime_allowed_verdicts");

        if allows_pass {
            assert!(
                verdicts.contains("pass"),
                "{adapter_id} pass-capable status must list pass verdict"
            );
            assert_eq!(
                string(row, "rendered_status"),
                "PASS",
                "{adapter_id} pass-capable row must render explicitly as PASS"
            );
        } else {
            assert!(
                bool_field(row, "fail_closed_without_full_reference"),
                "{adapter_id} non-pass row must fail closed"
            );
            assert!(
                !verdicts.contains("pass"),
                "{adapter_id} fail-closed row must not allow pass verdict"
            );
            assert!(
                !array(row, "unsupported_or_out_of_scope").is_empty(),
                "{adapter_id} fail-closed row must name unsupported or out-of-scope boundaries"
            );
            assert!(
                matches!(string(row, "rendered_status"), "XFAIL" | "BLOCKED"),
                "{adapter_id} fail-closed row must render XFAIL or BLOCKED"
            );
        }
    }
}

#[test]
fn rendered_matrix_has_stable_fail_closed_projection() {
    let matrix = matrix();
    let rendered = render_markdown(&matrix);
    let golden = array(&matrix, "markdown_golden")
        .iter()
        .map(|line| line.as_str().expect("markdown line string").to_string())
        .collect::<Vec<_>>();

    assert_eq!(
        rendered, golden,
        "markdown projection must stay stable and reviewed"
    );
    assert!(
        rendered
            .iter()
            .any(|line| line.contains("| database-") && line.contains("| XFAIL |")),
        "database row must render fail-closed"
    );
    assert!(
        rendered
            .iter()
            .any(|line| line.contains("| messaging-") && line.contains("| XFAIL |")),
        "messaging row must render fail-closed"
    );
    assert!(
        rendered
            .iter()
            .any(|line| line.contains("| transport-") && line.contains("| XFAIL |")),
        "transport row must render fail-closed"
    );
}

#[test]
fn matrix_rejects_stale_green_or_drop_in_parity_claims() {
    let matrix = matrix();
    let rendered_rows = serde_json::to_string(array(&matrix, "adapters")).expect("render rows");
    let rendered_markdown = render_markdown(&matrix).join("\n");

    for forbidden in array(&matrix["fail_closed_policy"], "forbidden_rendered_claims") {
        let forbidden = forbidden.as_str().expect("forbidden claim string");
        assert!(
            !rendered_rows.contains(forbidden) && !rendered_markdown.contains(forbidden),
            "adapter rows and markdown must not contain stale unsupported claim {forbidden:?}"
        );
    }
}
