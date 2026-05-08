//! Contract tests for the fail-closed adapter certification matrix.

#![allow(missing_docs)]

use asupersync::adapter_certification::ADAPTER_CERTIFICATIONS;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const MATRIX_PATH: &str = "artifacts/adapter_certification_matrix_v1.json";
const SOURCE_DECLARATIONS_PATH: &str = "src/adapter_certification.rs";
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

fn validation_commands(matrix: &Value) -> BTreeSet<String> {
    string_set(matrix, "validation_commands")
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
        matrix["source_of_truth"]["adapter_declarations"].as_str(),
        Some(SOURCE_DECLARATIONS_PATH)
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
fn source_declarations_match_matrix_rows() {
    let matrix = matrix();
    let policy = matrix
        .get("source_declaration_policy")
        .expect("source_declaration_policy object");
    assert_eq!(
        string(policy, "declaration_table"),
        "ADAPTER_CERTIFICATIONS"
    );
    assert!(bool_field(
        policy,
        "matrix_rows_must_match_source_declarations"
    ));
    for field in [
        "adapter_id",
        "category",
        "certification_status",
        "rendered_status",
        "fail_closed_without_full_reference",
    ] {
        assert!(
            string_set(policy, "declared_fields").contains(field),
            "source declaration policy must require {field}"
        );
    }

    let rows_by_id = array(&matrix, "adapters")
        .iter()
        .map(|row| (string(row, "adapter_id").to_string(), row))
        .collect::<BTreeMap<_, _>>();
    let declared_ids = ADAPTER_CERTIFICATIONS
        .iter()
        .map(|declaration| declaration.adapter_id.to_string())
        .collect::<BTreeSet<_>>();
    let matrix_ids = rows_by_id.keys().cloned().collect::<BTreeSet<_>>();
    assert_eq!(
        matrix_ids, declared_ids,
        "matrix adapter ids must match source declarations"
    );

    for declaration in ADAPTER_CERTIFICATIONS {
        let row = rows_by_id
            .get(declaration.adapter_id)
            .unwrap_or_else(|| panic!("missing matrix row {}", declaration.adapter_id));
        assert_eq!(string(row, "category"), declaration.category.as_str());
        assert_eq!(
            string(row, "certification_status"),
            declaration.certification_status.as_str()
        );
        assert_eq!(
            string(row, "rendered_status"),
            declaration.rendered_status.as_str()
        );
        assert_eq!(
            bool_field(row, "fail_closed_without_full_reference"),
            declaration.fail_closed_without_full_reference
        );
    }

    let source = read_repo_file(SOURCE_DECLARATIONS_PATH);
    assert!(source.contains("pub const ADAPTER_CERTIFICATIONS"));
    assert!(source.contains("AdapterCertificationDeclaration"));
}

#[test]
fn validation_commands_cover_the_matrix_contract_itself() {
    let matrix = matrix();
    let policy = matrix
        .get("validation_policy")
        .expect("validation_policy object");
    assert_eq!(
        string(policy, "contract_test_target"),
        "adapter_certification_matrix_contract"
    );
    assert!(bool_field(policy, "cargo_proofs_must_be_rch_routed"));
    assert!(bool_field(
        policy,
        "cargo_proofs_must_use_isolated_target_dir"
    ));
    assert!(
        string_set(policy, "commands_must_cover").contains("json_syntax"),
        "validation policy must require JSON syntax validation"
    );
    assert!(
        string_set(policy, "commands_must_cover").contains("contract_rustfmt"),
        "validation policy must require contract rustfmt validation"
    );
    assert!(
        string_set(policy, "commands_must_cover").contains("contract_cargo_test"),
        "validation policy must require the contract cargo test"
    );

    let commands = validation_commands(&matrix);
    assert!(
        commands.contains("python3 -m json.tool artifacts/adapter_certification_matrix_v1.json"),
        "validation commands must include the matrix JSON syntax proof"
    );

    let rustfmt = commands
        .iter()
        .find(|command| command.contains("rustfmt --edition 2024 --check"))
        .expect("rustfmt validation command");
    assert!(
        rustfmt.starts_with("rch exec -- "),
        "rustfmt command must be rch-routed: {rustfmt}"
    );
    assert!(
        rustfmt.contains(SOURCE_DECLARATIONS_PATH),
        "rustfmt command must target source declarations: {rustfmt}"
    );
    assert!(
        rustfmt.contains("src/lib.rs"),
        "rustfmt command must include crate-root module wiring: {rustfmt}"
    );
    assert!(
        rustfmt.contains(TEST_PATH),
        "rustfmt command must target the contract test: {rustfmt}"
    );

    let source_declaration_test = commands
        .iter()
        .find(|command| command.contains("adapter_certifications_have_stable_ids_and_statuses"))
        .expect("source declaration cargo proof command");
    assert!(
        source_declaration_test.starts_with("rch exec -- "),
        "source declaration proof must be rch-routed: {source_declaration_test}"
    );
    assert!(
        source_declaration_test
            .contains("CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_adapter_certification_"),
        "source declaration proof must use an isolated adapter target dir: {source_declaration_test}"
    );

    let cargo = commands
        .iter()
        .find(|command| command.contains("--test adapter_certification_matrix_contract"))
        .expect("adapter certification cargo proof command");
    assert!(
        cargo.starts_with("rch exec -- "),
        "cargo proof must be rch-routed: {cargo}"
    );
    assert!(
        cargo.contains("CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_adapter_certification_matrix"),
        "cargo proof must use the isolated matrix target dir: {cargo}"
    );
    assert!(
        cargo.contains("cargo test -p asupersync --test adapter_certification_matrix_contract"),
        "cargo proof must target this integration test: {cargo}"
    );
    for feature in string_set(policy, "required_feature_flags") {
        assert!(
            cargo.contains(&feature),
            "cargo proof must include required feature flag {feature}: {cargo}"
        );
    }
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
