//! Contract tests for the validation frontier ledger schema and parser fixtures.

#![allow(missing_docs)]

use serde_json::Value;
use std::collections::BTreeSet;

const ARTIFACT_PATH: &str = "artifacts/validation_frontier_ledger_schema_v1.json";
const DOC_PATH: &str = "docs/ci_proof_gates_contract.md";

#[derive(Debug, PartialEq, Eq)]
struct FailureSite {
    crate_or_surface: String,
    target: String,
    file: String,
    line: u64,
}

#[derive(Debug, PartialEq, Eq)]
struct ValidationFrontierRecord {
    command: String,
    timestamp: String,
    touched_files: Vec<String>,
    decision: String,
    error_class: String,
    first_failure: FailureSite,
    likely_owner: String,
    likely_bead: Option<String>,
    supplemental_proof_command: String,
    summary: String,
}

fn load_json(path: &str) -> Value {
    let raw = std::fs::read_to_string(path).unwrap_or_else(|error| panic!("read {path}: {error}"));
    serde_json::from_str(&raw).unwrap_or_else(|error| panic!("parse {path}: {error}"))
}

fn artifact() -> Value {
    load_json(ARTIFACT_PATH)
}

fn doc() -> String {
    std::fs::read_to_string(DOC_PATH).expect("proof gates doc must exist")
}

fn fixtures(artifact: &Value) -> &[Value] {
    artifact["fixtures"]
        .as_array()
        .expect("fixtures must be an array")
}

fn string_field(value: &Value, key: &str) -> String {
    value[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} must be a string"))
        .to_string()
}

fn string_vec_field(value: &Value, key: &str) -> Vec<String> {
    value[key]
        .as_array()
        .unwrap_or_else(|| panic!("{key} must be an array"))
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .unwrap_or_else(|| panic!("{key} entries must be strings"))
                .to_string()
        })
        .collect()
}

fn parse_compile_target(line: &str) -> (String, String) {
    let crate_start = line
        .find('`')
        .unwrap_or_else(|| panic!("compile line missing crate start: {line}"));
    let crate_end = line[crate_start + 1..]
        .find('`')
        .map(|offset| crate_start + 1 + offset)
        .unwrap_or_else(|| panic!("compile line missing crate end: {line}"));
    let crate_name = line[crate_start + 1..crate_end].to_string();
    let target_start = line[crate_end..]
        .find('(')
        .map(|offset| crate_end + offset + 1)
        .unwrap_or_else(|| panic!("compile line missing target start: {line}"));
    let target_end = line[target_start..]
        .find(')')
        .map(|offset| target_start + offset)
        .unwrap_or_else(|| panic!("compile line missing target end: {line}"));
    (crate_name, line[target_start..target_end].to_string())
}

fn parse_code_snippet(
    fixture: &Value,
    error_class: &str,
    decision: &str,
    likely_owner: &str,
    likely_bead: Option<String>,
) -> ValidationFrontierRecord {
    let snippet = string_field(fixture, "snippet");
    let error_line = snippet
        .lines()
        .find(|line| line.starts_with("error"))
        .unwrap_or_else(|| panic!("fixture missing error line: {snippet}"));
    let summary = error_line
        .split_once(": ")
        .map(|(_, rest)| rest.to_string())
        .unwrap_or_else(|| panic!("error line missing summary: {error_line}"));
    let location_line = snippet
        .lines()
        .find(|line| line.contains("-->"))
        .unwrap_or_else(|| panic!("fixture missing location line: {snippet}"));
    let location = location_line
        .split_once("-->")
        .map(|(_, rest)| rest.trim())
        .unwrap_or_else(|| panic!("location line missing arrow: {location_line}"));
    let mut location_parts = location.split(':');
    let file = location_parts
        .next()
        .expect("location file")
        .trim()
        .to_string();
    let line = location_parts
        .next()
        .expect("location line")
        .parse::<u64>()
        .expect("location line must parse");
    let compile_line = snippet
        .lines()
        .find(|line| line.starts_with("error: could not compile"))
        .unwrap_or_else(|| panic!("fixture missing compile stop line: {snippet}"));
    let (crate_or_surface, target) = parse_compile_target(compile_line);
    ValidationFrontierRecord {
        command: string_field(fixture, "command"),
        timestamp: string_field(fixture, "timestamp"),
        touched_files: string_vec_field(fixture, "touched_files"),
        decision: decision.to_string(),
        error_class: error_class.to_string(),
        first_failure: FailureSite {
            crate_or_surface,
            target,
            file,
            line,
        },
        likely_owner: likely_owner.to_string(),
        likely_bead,
        supplemental_proof_command: string_field(fixture, "supplemental_proof_command"),
        summary,
    }
}

fn parse_reservation_conflict(fixture: &Value) -> ValidationFrontierRecord {
    let conflict = serde_json::from_str::<Value>(&string_field(fixture, "snippet"))
        .expect("reservation conflict snippet must parse as JSON");
    let first_conflict = conflict["conflicts"]
        .as_array()
        .and_then(|conflicts| conflicts.first())
        .expect("at least one conflict");
    let holder = first_conflict["holders"]
        .as_array()
        .and_then(|holders| holders.first())
        .expect("at least one holder");
    let path = first_conflict["path"]
        .as_str()
        .expect("conflict path must be a string")
        .to_string();
    let agent = holder["agent"]
        .as_str()
        .expect("holder agent must be a string")
        .to_string();
    let expires = holder["expires_ts"]
        .as_str()
        .expect("holder expiry must be a string");
    ValidationFrontierRecord {
        command: string_field(fixture, "command"),
        timestamp: string_field(fixture, "timestamp"),
        touched_files: string_vec_field(fixture, "touched_files"),
        decision: "blocked-external".to_string(),
        error_class: "file_reservation_conflict".to_string(),
        first_failure: FailureSite {
            crate_or_surface: "agent-mail".to_string(),
            target: "reservation".to_string(),
            file: path,
            line: 0,
        },
        likely_owner: agent.clone(),
        likely_bead: fixture["likely_bead_hint"].as_str().map(str::to_string),
        supplemental_proof_command: string_field(fixture, "supplemental_proof_command"),
        summary: format!("exclusive reservation held by {agent} until {expires}"),
    }
}

fn parse_peer_dirty_index(fixture: &Value) -> ValidationFrontierRecord {
    let snippet = string_field(fixture, "snippet");
    let first_path = snippet
        .lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or_else(|| panic!("peer-dirty fixture missing staged path: {snippet}"))
        .to_string();
    ValidationFrontierRecord {
        command: string_field(fixture, "command"),
        timestamp: string_field(fixture, "timestamp"),
        touched_files: string_vec_field(fixture, "touched_files"),
        decision: "blocked-external".to_string(),
        error_class: "peer_dirty_index_conflict".to_string(),
        first_failure: FailureSite {
            crate_or_surface: "git".to_string(),
            target: "staged-index".to_string(),
            file: first_path,
            line: 0,
        },
        likely_owner: "shared-main peer dirt".to_string(),
        likely_bead: None,
        supplemental_proof_command: string_field(fixture, "supplemental_proof_command"),
        summary: "unrelated staged paths present before commit".to_string(),
    }
}

fn parse_fixture(fixture: &Value) -> ValidationFrontierRecord {
    match fixture["source_kind"]
        .as_str()
        .expect("fixture source_kind")
    {
        "rustc_output" => parse_code_snippet(
            fixture,
            "rustc_compile_error",
            "failed-local",
            "local_change",
            fixture["expected_record"]["likely_bead"]
                .as_str()
                .map(str::to_string),
        ),
        "clippy_output" => parse_code_snippet(
            fixture,
            "clippy_lint_wall",
            "blocked-external",
            "shared-main external blocker",
            None,
        ),
        "file_reservation_conflict" => parse_reservation_conflict(fixture),
        "peer_dirty_index" => parse_peer_dirty_index(fixture),
        other => panic!("unexpected fixture source_kind: {other}"),
    }
}

fn expected_record(fixture: &Value) -> ValidationFrontierRecord {
    let expected = &fixture["expected_record"];
    let first_failure = &expected["first_failure"];
    ValidationFrontierRecord {
        command: string_field(fixture, "command"),
        timestamp: string_field(fixture, "timestamp"),
        touched_files: string_vec_field(fixture, "touched_files"),
        decision: string_field(expected, "decision"),
        error_class: string_field(expected, "error_class"),
        first_failure: FailureSite {
            crate_or_surface: string_field(first_failure, "crate_or_surface"),
            target: string_field(first_failure, "target"),
            file: string_field(first_failure, "file"),
            line: first_failure["line"]
                .as_u64()
                .expect("first_failure.line must be an integer"),
        },
        likely_owner: string_field(expected, "likely_owner"),
        likely_bead: expected["likely_bead"].as_str().map(str::to_string),
        supplemental_proof_command: string_field(fixture, "supplemental_proof_command"),
        summary: string_field(expected, "summary"),
    }
}

#[test]
fn artifact_declares_frontier_contract_version() {
    let artifact = artifact();
    assert_eq!(
        artifact["contract_version"].as_str(),
        Some("validation-frontier-ledger-v1")
    );
    assert_eq!(
        artifact["record_schema_version"].as_str(),
        Some("validation-frontier-record-v1")
    );
}

#[test]
fn decision_classes_cover_expected_outcomes() {
    let artifact = artifact();
    let decisions = artifact["decision_classes"]
        .as_array()
        .expect("decision_classes must be an array")
        .iter()
        .map(|entry| string_field(entry, "decision"))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        decisions,
        BTreeSet::from([
            "blocked-external".to_string(),
            "failed-local".to_string(),
            "pass".to_string(),
        ])
    );
}

#[test]
fn error_classes_cover_required_blocker_families() {
    let artifact = artifact();
    let classes = artifact["error_classes"]
        .as_array()
        .expect("error_classes must be an array")
        .iter()
        .map(|entry| string_field(entry, "error_class"))
        .collect::<BTreeSet<_>>();
    for required in [
        "rustc_compile_error",
        "clippy_lint_wall",
        "file_reservation_conflict",
        "peer_dirty_index_conflict",
    ] {
        assert!(
            classes.contains(required),
            "missing blocker class {required}"
        );
    }
}

#[test]
fn record_schema_lists_required_closeout_fields() {
    let artifact = artifact();
    let fields = artifact["record_fields"]
        .as_array()
        .expect("record_fields must be an array")
        .iter()
        .map(|entry| string_field(entry, "name"))
        .collect::<BTreeSet<_>>();
    for required in [
        "command",
        "timestamp",
        "touched_files",
        "decision",
        "error_class",
        "first_failure.crate_or_surface",
        "first_failure.target",
        "first_failure.file",
        "first_failure.line",
        "likely_owner",
        "likely_bead",
        "supplemental_proof_command",
        "summary",
    ] {
        assert!(fields.contains(required), "missing record field {required}");
    }
}

#[test]
fn fixture_parser_matches_expected_records() {
    let artifact = artifact();
    for fixture in fixtures(&artifact) {
        assert_eq!(
            parse_fixture(fixture),
            expected_record(fixture),
            "fixture {} should parse to expected record",
            string_field(fixture, "fixture_id")
        );
    }
}

#[test]
fn fixtures_are_redaction_safe_and_exact() {
    let artifact = artifact();
    for fixture in fixtures(&artifact) {
        let snippet = string_field(fixture, "snippet");
        assert!(
            !snippet.contains("/home/"),
            "fixture snippet must not contain home-directory paths"
        );
        assert!(
            !snippet.to_ascii_lowercase().contains("token"),
            "fixture snippet must not contain token-like material"
        );
        let expected = expected_record(fixture);
        if expected.first_failure.line > 0 {
            assert!(
                std::path::Path::new(&expected.first_failure.file).exists(),
                "fixture file must exist: {}",
                expected.first_failure.file
            );
        }
    }
}

#[test]
fn fixtures_capture_rch_attempts_and_narrow_supplemental_proofs() {
    let artifact = artifact();
    let fixtures = fixtures(&artifact);
    let rch_attempts = fixtures
        .iter()
        .filter(|fixture| string_field(fixture, "command").starts_with("rch exec -- "))
        .count();
    assert!(
        rch_attempts >= 2,
        "expected at least two rch-backed proof attempts"
    );
    for fixture in fixtures {
        let supplemental = string_field(fixture, "supplemental_proof_command");
        assert!(
            !supplemental.is_empty(),
            "supplemental proof command must be recorded"
        );
    }
}

#[test]
fn doc_teaches_how_to_cite_frontier_rows() {
    let doc = doc();
    for required in [
        "## Validation Frontier Ledger",
        "artifacts/validation_frontier_ledger_schema_v1.json",
        "tests/validation_frontier_ledger_contract.rs",
        "blocked-external",
        "supplemental proof",
    ] {
        assert!(
            doc.contains(required),
            "proof gates doc must contain {required}"
        );
    }
}

#[test]
fn close_reason_template_is_paste_ready() {
    let artifact = artifact();
    let template = &artifact["close_reason_template"];
    let required_fields = template["required_fields"]
        .as_array()
        .expect("close_reason_template.required_fields must be an array");
    assert!(
        required_fields.len() >= 6,
        "close_reason template must require enough context"
    );
    let example = string_field(template, "example");
    assert!(
        example.contains("blocked-external")
            && example.contains("supplemental proof")
            && example.contains("src/sync/semaphore.rs:37"),
        "close reason example must be directly reusable"
    );
}
