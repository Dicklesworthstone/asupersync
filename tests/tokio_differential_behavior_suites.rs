//! Contract tests for differential behavior suites spec (2oh2u.10.3).
//!
//! Verifies suite schema, coverage, deterministic rules, artifact contract,
//! runner policy, and downstream gate bindings.

#![allow(missing_docs)]

use std::collections::BTreeSet;
use std::path::Path;

fn load_doc() -> String {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/tokio_differential_behavior_suites.md");
    std::fs::read_to_string(path).expect("differential behavior suites document must exist")
}

fn extract_suite_ids(doc: &str) -> BTreeSet<String> {
    let mut ids = BTreeSet::new();
    for line in doc.lines() {
        let trimmed = line.trim().trim_start_matches('|').trim();
        if let Some(id) = trimmed.split('|').next() {
            let id = id.trim().trim_matches('`');
            if id.starts_with("DS-") {
                ids.insert(id.to_string());
            }
        }
    }
    ids
}

fn extract_rule_ids(doc: &str) -> BTreeSet<String> {
    let mut ids = BTreeSet::new();
    for line in doc.lines() {
        let trimmed = line.trim().trim_start_matches('|').trim();
        if let Some(id) = trimmed.split('|').next() {
            let id = id.trim().trim_matches('`');
            if id.starts_with("DR-") {
                ids.insert(id.to_string());
            }
        }
    }
    ids
}

#[test]
fn doc_exists_and_is_substantial() {
    let doc = load_doc();
    assert!(
        doc.len() > 3000,
        "document should be substantial, got {} bytes",
        doc.len()
    );
}

#[test]
fn doc_references_correct_bead_and_track() {
    let doc = load_doc();
    assert!(
        doc.contains("asupersync-2oh2u.10.3"),
        "document must reference bead 2oh2u.10.3"
    );
    assert!(doc.contains("[T8.3]"), "document must reference T8.3");
}

#[test]
fn doc_references_required_dependencies() {
    let doc = load_doc();
    for token in [
        "asupersync-2oh2u.10.2",
        "tokio_executable_conformance_contracts.md",
        "tokio_ci_quality_gate_enforcement.md",
        "tokio_unit_quality_threshold_contract.md",
    ] {
        assert!(
            doc.contains(token),
            "document missing required dependency token: {token}"
        );
    }
}

#[test]
fn doc_defines_normative_schema_fields() {
    let doc = load_doc();
    for token in [
        "Suite ID",
        "Capability Track",
        "Reference Surface",
        "Asupersync Surface",
        "Contract IDs",
        "Scenario Classes",
        "Verdict Model",
        "Failure Classes",
        "Required Artifacts",
        "Runner Command",
        "Gate Binding",
    ] {
        assert!(doc.contains(token), "schema missing field token: {token}");
    }
}

#[test]
fn doc_has_required_suite_coverage() {
    let doc = load_doc();
    let ids = extract_suite_ids(&doc);
    assert!(
        ids.len() >= 10,
        "must define >=10 differential suite IDs, found {}",
        ids.len()
    );

    for token in [
        "DS-T2-01", "DS-T3-01", "DS-T4-01", "DS-T5-01", "DS-T6-01", "DS-T7-01", "DS-X-01",
        "DS-X-02", "DS-X-03", "DS-X-04",
    ] {
        assert!(
            ids.contains(token),
            "missing differential suite ID: {token}"
        );
    }
}

#[test]
fn doc_defines_verdict_and_deviation_rules() {
    let doc = load_doc();
    for token in ["MATCH", "JUSTIFIED_DEVIATION", "REGRESSION"] {
        assert!(doc.contains(token), "missing verdict token: {token}");
    }

    assert!(
        doc.contains("A deviation missing any required field is treated as `REGRESSION`"),
        "document must define strict deviation governance"
    );
}

#[test]
fn doc_defines_failure_taxonomy_tokens() {
    let doc = load_doc();
    for token in [
        "semantic_drift",
        "timing_drift",
        "cancel_protocol_violation",
        "loser_drain_violation",
        "obligation_leak",
        "artifact_schema_violation",
        "authority_flow_violation",
        "interop_boundary_violation",
    ] {
        assert!(
            doc.contains(token),
            "failure taxonomy missing token: {token}"
        );
    }
}

#[test]
fn doc_defines_artifact_bundle_and_entry_schema() {
    let doc = load_doc();
    for token in [
        "differential_summary.json",
        "differential_event_log.jsonl",
        "differential_failures.json",
        "differential_deviations.json",
        "differential_repro_manifest.json",
    ] {
        assert!(doc.contains(token), "missing artifact token: {token}");
    }

    for field in [
        "suite_id",
        "contract_ids",
        "reference_revision",
        "asupersync_revision",
        "verdict",
        "failure_classes",
        "artifact_paths",
        "repro_command",
        "generated_at",
    ] {
        assert!(
            doc.contains(field),
            "missing entry schema field token: {field}"
        );
    }
}

#[test]
fn doc_defines_determinism_rules() {
    let doc = load_doc();
    let ids = extract_rule_ids(&doc);
    for token in ["DR-01", "DR-02", "DR-03", "DR-04", "DR-05"] {
        assert!(ids.contains(token), "missing determinism rule ID: {token}");
    }
}

#[test]
fn doc_requires_rch_exec_for_heavy_commands() {
    let doc = load_doc();
    assert!(
        doc.contains("rch exec --"),
        "document must require rch exec for heavy validation"
    );

    for token in [
        "rch exec -- cargo fmt --check",
        "rch exec -- cargo check --all-targets",
        "rch exec -- cargo clippy --all-targets -- -D warnings",
        "rch exec -- cargo test --test tokio_executable_conformance_contracts -- --nocapture",
        "rch exec -- cargo test --test tokio_differential_behavior_suites -- --nocapture",
        "rch exec -- cargo test --test tokio_ci_quality_gate_enforcement -- --nocapture",
    ] {
        assert!(
            doc.contains(token),
            "missing required runner command: {token}"
        );
    }
}

#[test]
fn doc_binds_to_downstream_beads() {
    let doc = load_doc();
    for token in [
        "asupersync-2oh2u.10.4",
        "asupersync-2oh2u.10.5",
        "asupersync-2oh2u.10.6",
        "asupersync-2oh2u.10.7",
        "asupersync-2oh2u.10.8",
    ] {
        assert!(
            doc.contains(token),
            "missing downstream binding token: {token}"
        );
    }
}
