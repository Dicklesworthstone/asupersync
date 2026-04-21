#![allow(warnings)]
#![allow(clippy::all)]
//! Contract tests for replay artifact schema and retention policy (2oh2u.10.6).
//!
//! Verifies canonical artifact set, versioning rules, determinism fields,
//! retention lifecycle policy, provenance constraints, and downstream bindings.

#![allow(missing_docs)]

use std::collections::BTreeSet;
use std::path::Path;

fn load_doc() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("docs/tokio_replay_artifact_schema_and_retention_policy.md");
    std::fs::read_to_string(path)
        .expect("replay artifact schema and retention policy document must exist")
}

fn extract_rule_ids(doc: &str, prefix: &str) -> BTreeSet<String> {
    let mut ids = BTreeSet::new();
    for line in doc.lines() {
        let trimmed = line.trim().trim_start_matches('|').trim();
        if let Some(id) = trimmed.split('|').next() {
            let id = id.trim().trim_matches('`');
            if id.starts_with(prefix) {
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
        doc.contains("asupersync-2oh2u.10.6"),
        "document must reference bead 2oh2u.10.6"
    );
    assert!(doc.contains("[T8.6]"), "document must reference T8.6");
}

#[test]
fn doc_references_required_dependencies() {
    let doc = load_doc();
    for token in [
        "asupersync-2oh2u.10.2",
        "asupersync-2oh2u.10.5",
        "tokio_executable_conformance_contracts.md",
        "tokio_ci_quality_gate_enforcement.md",
    ] {
        assert!(
            doc.contains(token),
            "document missing required dependency token: {token}"
        );
    }
}

#[test]
fn doc_defines_canonical_artifact_set() {
    let doc = load_doc();
    for artifact in [
        "repro_manifest.json",
        "event_log.txt",
        "failed_assertions.json",
        "trace_snapshot.bin",
        "trace_index.json",
        "evidence_manifest.json",
        "retention_policy.json",
        "replay_summary.json",
    ] {
        assert!(
            doc.contains(artifact),
            "missing canonical replay artifact token: {artifact}"
        );
    }
}

#[test]
fn doc_defines_required_top_level_schema_fields() {
    let doc = load_doc();
    for token in [
        "schema_version",
        "schema_family",
        "artifact_kind",
        "trace_id",
        "run_id",
        "commit_sha",
        "generated_at",
        "producer",
        "digest",
    ] {
        assert!(
            doc.contains(token),
            "missing required schema field token: {token}"
        );
    }
}

#[test]
fn doc_defines_rs_versioning_rules() {
    let doc = load_doc();
    let rs_ids = extract_rule_ids(&doc, "RS-");
    for id in [
        "RS-01", "RS-02", "RS-03", "RS-04", "RS-05", "RS-06", "RS-07", "RS-08",
    ] {
        assert!(rs_ids.contains(id), "missing versioning rule token: {id}");
    }
}

#[test]
fn doc_defines_replay_determinism_fields() {
    let doc = load_doc();
    for token in [
        "seed",
        "schedule_profile",
        "virtual_time_mode",
        "scenario_id",
        "failure_class",
        "repro_command",
        "semantic_drift",
        "timing_drift",
    ] {
        assert!(
            doc.contains(token),
            "missing determinism/replay token: {token}"
        );
    }
}

#[test]
fn doc_defines_retention_classes_and_lifecycle_fields() {
    let doc = load_doc();
    for token in [
        "RET-HOT-14",
        "RET-WARM-90",
        "RET-COLD-365",
        "RET-AUDIT-730",
        "RET-LEGAL-HOLD",
        "retention_class",
        "retention_start",
        "retention_until",
        "legal_hold",
        "deletion_eligibility",
        "policy_reason",
    ] {
        assert!(
            doc.contains(token),
            "missing retention policy token: {token}"
        );
    }
}

#[test]
fn doc_defines_integrity_and_provenance_requirements() {
    let doc = load_doc();
    for token in [
        "manifest_digest",
        "manifest_signed",
        "path",
        "size_bytes",
        "generated_at",
        "commit_sha",
        "run_id",
        "tool version",
    ] {
        assert!(
            doc.contains(token),
            "missing integrity/provenance token: {token}"
        );
    }
}

#[test]
fn doc_requires_rch_exec_for_heavy_validation() {
    let doc = load_doc();
    assert!(
        doc.contains("rch exec --"),
        "document must require rch exec for heavy validation"
    );
    for token in [
        "rch exec -- cargo test --test tokio_executable_conformance_contracts -- --nocapture",
        "rch exec -- cargo test --test tokio_ci_quality_gate_enforcement -- --nocapture",
        "rch exec -- cargo test --test tokio_replay_artifact_schema_and_retention_policy -- --nocapture",
        "rch exec -- cargo test --test replay_e2e_suite -- --nocapture",
    ] {
        assert!(doc.contains(token), "missing runner command token: {token}");
    }
}

#[test]
fn doc_binds_to_downstream_beads() {
    let doc = load_doc();
    for token in ["asupersync-2oh2u.10.8", "asupersync-2oh2u.10.9"] {
        assert!(
            doc.contains(token),
            "missing downstream binding token: {token}"
        );
    }
}
