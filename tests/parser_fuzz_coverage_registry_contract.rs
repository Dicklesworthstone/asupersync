//! Contract tests for the parser fuzz coverage registry helper.

#![allow(missing_docs)]

use serde_json::Value;
use std::path::PathBuf;
use std::process::{Command, Output};

const SCRIPT_PATH: &str = "scripts/parser_fuzz_coverage_registry.py";
const FIXTURE_ROOT: &str = "tests/fixtures/parser_fuzz_coverage_registry";
const GENERATED_AT: &str = "2026-05-08T05:45:00Z";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn run_registry(fixture: &str) -> Output {
    Command::new("python3")
        .arg(repo_root().join(SCRIPT_PATH))
        .arg("--input")
        .arg(PathBuf::from(FIXTURE_ROOT).join(fixture))
        .arg("--generated-at")
        .arg(GENERATED_AT)
        .arg("--output")
        .arg("json")
        .current_dir(repo_root())
        .output()
        .expect("run parser fuzz coverage registry helper")
}

fn fixture_text(fixture: &str) -> String {
    std::fs::read_to_string(repo_root().join(FIXTURE_ROOT).join(fixture))
        .unwrap_or_else(|error| panic!("read fixture {fixture}: {error}"))
}

fn registry_json(fixture: &str) -> Value {
    let output = run_registry(fixture);
    assert!(
        output.status.success(),
        "registry helper failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("registry output must be JSON")
}

fn assert_registry_output_matches_golden(input_fixture: &str, expected_fixture: &str) {
    let output = run_registry(input_fixture);
    assert!(
        output.status.success(),
        "registry helper failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let actual = String::from_utf8(output.stdout).expect("registry stdout is UTF-8");
    let expected = fixture_text(expected_fixture);
    let actual_json: Value = serde_json::from_str(&actual).expect("actual registry output is JSON");
    let expected_json: Value =
        serde_json::from_str(&expected).expect("expected registry output is JSON");
    assert_eq!(actual_json, expected_json, "registry golden JSON drifted");
    assert_eq!(actual, expected, "registry golden text drifted");
}

fn coverage_record<'a>(receipt: &'a Value, id: &str) -> &'a Value {
    receipt["coverage"]
        .as_array()
        .expect("coverage records")
        .iter()
        .find(|record| record["surface"]["id"].as_str() == Some(id))
        .unwrap_or_else(|| panic!("missing coverage record for {id}"))
}

#[test]
fn script_exists_and_help_is_non_mutating() {
    assert!(
        repo_root().join(SCRIPT_PATH).exists(),
        "registry helper must exist at {SCRIPT_PATH}"
    );
    let output = Command::new("python3")
        .arg(repo_root().join(SCRIPT_PATH))
        .arg("--help")
        .current_dir(repo_root())
        .output()
        .expect("run helper --help");
    assert!(output.status.success(), "--help should succeed");
}

#[test]
fn covered_registry_matches_full_output_golden() {
    assert_registry_output_matches_golden(
        "covered_registry.json",
        "covered_registry_expected.json",
    );
}

#[test]
fn covered_public_parser_surfaces_pass_the_registry_gate() {
    let receipt = registry_json("covered_registry.json");

    assert_eq!(
        receipt["schema_version"].as_str(),
        Some("parser-fuzz-coverage-registry-v1")
    );
    assert_eq!(receipt["generated_at"].as_str(), Some(GENERATED_AT));
    assert_eq!(receipt["current_date"].as_str(), Some("2026-05-08"));
    assert_eq!(receipt["summary"]["passes"].as_bool(), Some(true));
    assert_eq!(receipt["summary"]["covered"].as_u64(), Some(2));
    assert_eq!(receipt["missing_coverage"].as_array().unwrap().len(), 0);
    assert_eq!(
        coverage_record(&receipt, "redis_resp_decode")["status"].as_str(),
        Some("covered")
    );
}

#[test]
fn missing_high_risk_parser_surface_fails_with_action_item() {
    let receipt = registry_json("missing_high_risk.json");

    assert_eq!(receipt["summary"]["passes"].as_bool(), Some(false));
    assert_eq!(receipt["summary"]["missing"].as_u64(), Some(1));
    assert_eq!(
        receipt["missing_coverage"][0].as_str(),
        Some("postgres_row_description_parse")
    );
    assert!(
        receipt["action_items"][0]
            .as_str()
            .expect("action item")
            .contains("postgres_row_description_parse")
    );
}

#[test]
fn missing_high_risk_matches_full_output_golden() {
    assert_registry_output_matches_golden(
        "missing_high_risk.json",
        "missing_high_risk_expected.json",
    );
}

#[test]
fn exemptions_need_reason_and_future_expiry() {
    let receipt = registry_json("exempt_and_expired.json");

    assert_eq!(receipt["summary"]["passes"].as_bool(), Some(false));
    assert_eq!(
        coverage_record(&receipt, "grpc_timeout_parse")["status"].as_str(),
        Some("exempt")
    );
    assert_eq!(
        coverage_record(&receipt, "internal_validated_status_parse")["status"].as_str(),
        Some("missing")
    );
    assert_eq!(receipt["summary"]["invalid_exemptions"].as_u64(), Some(1));
    assert_eq!(
        receipt["requirements"]["exemptions_have_reason_and_future_expiry"].as_bool(),
        Some(false)
    );
}

#[test]
fn exempt_and_expired_matches_full_output_golden() {
    assert_registry_output_matches_golden(
        "exempt_and_expired.json",
        "exempt_and_expired_expected.json",
    );
}

#[test]
fn partial_references_and_stale_targets_do_not_count_as_coverage() {
    let receipt = registry_json("partial_and_stale_target.json");

    assert_eq!(receipt["summary"]["passes"].as_bool(), Some(false));
    assert_eq!(
        coverage_record(&receipt, "hpack_huffman_decode")["status"].as_str(),
        Some("partial")
    );
    assert_eq!(
        coverage_record(&receipt, "mysql_handshake_parse")["status"].as_str(),
        Some("missing")
    );
    assert_eq!(
        coverage_record(&receipt, "mysql_handshake_parse")["evidence"]["stale_covering_targets"][0]
            .as_str(),
        Some("fuzz_mysql_handshake_old")
    );
}

#[test]
fn partial_and_stale_targets_match_full_output_golden() {
    assert_registry_output_matches_golden(
        "partial_and_stale_target.json",
        "partial_and_stale_target_expected.json",
    );
}

#[test]
fn duplicate_target_ids_are_coalesced_deterministically() {
    let receipt = registry_json("duplicate_targets.json");
    let covering = coverage_record(&receipt, "nats_header_parse")["evidence"]["covering_targets"]
        .as_array()
        .expect("covering targets");

    assert_eq!(receipt["summary"]["passes"].as_bool(), Some(true));
    assert_eq!(covering.len(), 2);
    assert_eq!(covering[0].as_str(), Some("fuzz_nats_headers_a"));
    assert_eq!(covering[1].as_str(), Some("fuzz_nats_headers_b"));
}

#[test]
fn duplicate_targets_matches_full_output_golden() {
    assert_registry_output_matches_golden(
        "duplicate_targets.json",
        "duplicate_targets_expected.json",
    );
}

#[test]
fn helper_declares_it_does_not_mutate_repo_or_manifest() {
    let receipt = registry_json("covered_registry.json");

    assert_eq!(receipt["non_mutating"].as_bool(), Some(true));
    for key in [
        "runs_cargo",
        "runs_git_mutation",
        "runs_beads_mutation",
        "runs_destructive_command",
        "edits_fuzz_manifest",
    ] {
        assert_eq!(
            receipt["forbidden_actions"][key].as_bool(),
            Some(false),
            "{key} must stay false"
        );
    }
}
