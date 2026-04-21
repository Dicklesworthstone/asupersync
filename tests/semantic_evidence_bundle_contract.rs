#![allow(clippy::all)]
//! SEM-09.2 evidence bundle contract tests.
//!
//! Validates deterministic schema, rule traceability, and owner-bead mapping
//! for missing evidence entries.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

const FIXTURE_DIR: &str = "tests/fixtures/semantic_evidence_bundle";
const SCRIPT_PATH: &str = "scripts/build_semantic_evidence_bundle.sh";

fn fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(FIXTURE_DIR)
        .join(name)
}

fn unique_output_path() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("semantic_evidence_bundle_{nanos}.json"))
}

fn build_bundle_from_fixtures() -> Value {
    let output_path = unique_output_path();
    let output = Command::new("bash")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .arg(SCRIPT_PATH)
        .arg("--report")
        .arg(fixture_path("verification_report_sample.json"))
        .arg("--matrix")
        .arg(fixture_path("semantic_verification_matrix_sample.md"))
        .arg("--gates")
        .arg(fixture_path("semantic_readiness_gates_sample.md"))
        .arg("--output")
        .arg(&output_path)
        .output()
        .expect("failed to execute evidence bundle script");

    assert!(
        output.status.success(),
        "bundle script failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let raw = std::fs::read_to_string(&output_path).expect("bundle output file missing");
    let parsed: Value = serde_json::from_str(&raw).expect("bundle output must be valid JSON");
    let _ = std::fs::remove_file(output_path);
    parsed
}

#[test]
fn bundle_schema_and_traceability_contract() {
    let bundle = build_bundle_from_fixtures();

    assert_eq!(
        bundle["schema_version"].as_str(),
        Some("semantic-evidence-bundle-v1"),
        "schema version must be pinned"
    );
    assert!(
        bundle["readiness_gates"]
            .as_array()
            .is_some_and(|g| !g.is_empty()),
        "bundle must include readiness gate projection"
    );
    assert_eq!(
        bundle["traceability"]["matrix_rule_count"].as_u64(),
        Some(4),
        "fixture matrix should project 4 rules"
    );
}

#[test]
fn matrix_missing_evidence_entries_include_owner_beads() {
    let bundle = build_bundle_from_fixtures();
    let missing = bundle["missing_evidence"]
        .as_array()
        .expect("missing_evidence must be array");

    let missing_pt = missing.iter().find(|entry| {
        entry["kind"] == "matrix_rule_requirement"
            && entry["details"]["rule_id"] == "inv.cancel.idempotence"
            && entry["details"]["required_class"] == "PT"
    });
    assert!(
        missing_pt.is_some(),
        "missing PT entry for inv.cancel.idempotence must exist"
    );
    assert_eq!(
        missing_pt.expect("checked above")["owner_bead"].as_str(),
        Some("asupersync-3cddg.12.5"),
        "PT gaps must map to SEM-12.5 owner bead"
    );

    let missing_doc = missing.iter().find(|entry| {
        entry["kind"] == "matrix_rule_requirement"
            && entry["details"]["rule_id"] == "rule.cancel.request"
            && entry["details"]["required_class"] == "DOC"
    });
    assert!(
        missing_doc.is_some(),
        "missing DOC entry for rule.cancel.request must exist"
    );
    assert_eq!(
        missing_doc.expect("checked above")["owner_bead"].as_str(),
        Some("asupersync-3cddg.12.2"),
        "DOC gaps must map to SEM-12.2 owner bead"
    );
}

#[test]
fn runner_gaps_and_rerun_contract_are_present() {
    let bundle = build_bundle_from_fixtures();
    let missing = bundle["missing_evidence"]
        .as_array()
        .expect("missing_evidence must be array");

    let golden_suite_gap = missing
        .iter()
        .find(|entry| entry["kind"] == "runner_suite" && entry["details"]["suite"] == "golden");
    assert!(
        golden_suite_gap.is_some(),
        "failed required golden suite must be surfaced as missing evidence"
    );
    assert_eq!(
        golden_suite_gap.expect("checked above")["owner_bead"].as_str(),
        Some("asupersync-3cddg.12.8"),
        "golden suite failures must map to SEM-12.8 owner bead"
    );

    let artifact_gap = missing.iter().find(|entry| {
        entry["kind"] == "runner_artifact" && entry["details"]["artifact"] == "docs_output.txt"
    });
    assert!(
        artifact_gap.is_some(),
        "missing profile artifact must be surfaced"
    );
    assert_eq!(
        artifact_gap.expect("checked above")["owner_bead"].as_str(),
        Some("asupersync-3cddg.12.11"),
        "artifact contract gaps must map to SEM-12.11 owner bead"
    );

    let rerun_commands = bundle["deterministic_rerun"]["commands"]
        .as_array()
        .expect("deterministic_rerun.commands must be array");
    assert!(
        rerun_commands
            .iter()
            .filter_map(Value::as_str)
            .any(|cmd| cmd.contains("run_semantic_verification.sh")),
        "bundle must include runner rerun command"
    );
    assert!(
        rerun_commands
            .iter()
            .filter_map(Value::as_str)
            .any(|cmd| cmd.contains("build_semantic_evidence_bundle.sh")),
        "bundle must include bundle rerun command"
    );
}
