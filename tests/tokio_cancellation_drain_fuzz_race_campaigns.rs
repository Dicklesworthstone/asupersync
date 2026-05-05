//! Contract tests for cancellation/drain fuzz-race campaign specification (2oh2u.10.4).
//!
//! Ensures campaign coverage, deterministic replay requirements, blocking policy,
//! artifact schema, and downstream bindings are explicitly defined.

#![allow(missing_docs)]

use std::collections::BTreeSet;
use std::path::Path;

fn load_doc() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("docs/tokio_cancellation_drain_fuzz_race_campaigns.md");
    std::fs::read_to_string(path).expect("cancellation/drain fuzz-race document must exist")
}

fn extract_campaign_ids(doc: &str) -> BTreeSet<String> {
    let mut ids = BTreeSet::new();
    for line in doc.lines() {
        let trimmed = line.trim().trim_start_matches('|').trim();
        if let Some(id) = trimmed.split('|').next() {
            let id = id.trim().trim_matches('`');
            if id.starts_with("FRC-") {
                ids.insert(id.to_string());
            }
        }
    }
    ids
}

fn extract_determinism_ids(doc: &str) -> BTreeSet<String> {
    let mut ids = BTreeSet::new();
    for line in doc.lines() {
        let trimmed = line.trim().trim_start_matches('|').trim();
        if let Some(id) = trimmed.split('|').next() {
            let id = id.trim().trim_matches('`');
            if id.starts_with("FD-") {
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
        doc.contains("asupersync-2oh2u.10.4"),
        "document must reference bead 2oh2u.10.4"
    );
    assert!(doc.contains("[T8.4]"), "document must reference T8.4");
}

#[test]
fn doc_references_required_inputs() {
    let doc = load_doc();
    for token in [
        "asupersync-2oh2u.10.2",
        "tokio_executable_conformance_contracts.md",
        "tokio_deterministic_lab_model_expansion.md",
    ] {
        assert!(
            doc.contains(token),
            "document missing required dependency token: {token}"
        );
    }
}

#[test]
fn doc_includes_normative_blocking_rule() {
    let doc = load_doc();
    assert!(
        doc.contains("any reproducible violation"),
        "document must declare reproducible-violation blocking rule"
    );
    assert!(
        doc.contains("blocks closure of `asupersync-2oh2u.10.4`"),
        "document must explicitly bind blocking rule to bead closure"
    );
}

#[test]
fn doc_has_minimum_campaign_coverage() {
    let doc = load_doc();
    let campaigns = extract_campaign_ids(&doc);
    assert!(
        campaigns.len() >= 10,
        "must define >=10 campaign IDs, found {}",
        campaigns.len()
    );

    for id in [
        "FRC-01", "FRC-02", "FRC-03", "FRC-04", "FRC-05", "FRC-06", "FRC-07", "FRC-08", "FRC-09",
        "FRC-10",
    ] {
        assert!(campaigns.contains(id), "missing campaign ID token: {id}");
    }
}

#[test]
fn doc_references_required_model_families() {
    let doc = load_doc();
    for family in ["LM-S1", "LM-S2", "LM-S3", "LM-S4", "LM-S5", "LM-S6"] {
        assert!(
            doc.contains(family),
            "campaign matrix missing model family token: {family}"
        );
    }
}

#[test]
fn doc_defines_determinism_requirements() {
    let doc = load_doc();
    let ids = extract_determinism_ids(&doc);
    for id in ["FD-01", "FD-02", "FD-03", "FD-04", "FD-05"] {
        assert!(
            ids.contains(id),
            "missing determinism requirement token: {id}"
        );
    }
}

#[test]
fn doc_requires_rch_exec_for_heavy_runs() {
    let doc = load_doc();
    assert!(
        doc.contains("rch exec --"),
        "runner commands must require rch exec for heavy runs"
    );
    assert!(
        doc.contains(
            "rch exec -- cargo test --test tokio_cancellation_drain_fuzz_race_campaigns -- --nocapture"
        ),
        "document must include direct runner command for this campaign contract test"
    );
}

#[test]
fn doc_defines_failure_taxonomy_and_status_semantics() {
    let doc = load_doc();
    for token in [
        "cancel_protocol_violation",
        "loser_drain_violation",
        "obligation_leak",
        "semantic_drift",
        "timing_drift",
        "authority_flow_violation",
        "artifact_schema_violation",
    ] {
        assert!(doc.contains(token), "missing failure class token: {token}");
    }

    for status in ["PASS", "FAIL", "BLOCKED"] {
        assert!(
            doc.contains(status),
            "document must include campaign status token: {status}"
        );
    }
}

#[test]
fn doc_requires_artifact_and_corpus_outputs() {
    let doc = load_doc();
    for artifact in [
        "event_log.txt",
        "failed_assertions.json",
        "repro_manifest.json",
        "campaign_summary.json",
        "minimized_trace.json",
        "regression_corpus.jsonl",
    ] {
        assert!(
            doc.contains(artifact),
            "missing required artifact token: {artifact}"
        );
    }
}

#[test]
fn doc_binds_to_downstream_beads() {
    let doc = load_doc();
    for token in [
        "asupersync-2oh2u.10.7",
        "asupersync-2oh2u.10.5",
        "asupersync-2oh2u.10.6",
    ] {
        assert!(
            doc.contains(token),
            "document missing downstream binding token: {token}"
        );
    }
}
