//! Contract tests for executable conformance contracts (2oh2u.10.2).
//!
//! Ensures the contract specification is machine-gateable and covers
//! required tracks, taxonomy, and downstream CI bindings.

#![allow(missing_docs)]

use std::collections::BTreeSet;
use std::path::Path;

fn load_doc() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("docs/tokio_executable_conformance_contracts.md");
    std::fs::read_to_string(path).expect("executable conformance contract document must exist")
}

fn extract_contract_ids(doc: &str) -> BTreeSet<String> {
    let mut ids = BTreeSet::new();
    for line in doc.lines() {
        let trimmed = line.trim().trim_start_matches('|').trim();
        if let Some(id) = trimmed.split('|').next() {
            let id = id.trim().trim_matches('`');
            if id.starts_with("EC-") {
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
        doc.contains("asupersync-2oh2u.10.2"),
        "document must reference bead 2oh2u.10.2"
    );
    assert!(doc.contains("[T8.2]"), "document must reference T8.2");
}

#[test]
fn doc_references_required_inputs() {
    let doc = load_doc();
    for token in [
        "tokio_functional_parity_contract.md",
        "tokio_nonfunctional_closure_criteria.md",
        "tokio_evidence_checklist.md",
        "tokio_deterministic_lab_model_expansion.md",
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
        "Contract ID",
        "Capability Track",
        "Source Contract Input",
        "Runner Command",
        "Pass Criteria",
        "Failure Class",
        "Required Artifacts",
        "Gate Binding",
    ] {
        assert!(doc.contains(token), "schema missing field token: {token}");
    }
}

#[test]
fn doc_defines_pass_fail_blocked_statuses() {
    let doc = load_doc();
    for status in ["PASS", "FAIL", "BLOCKED"] {
        assert!(
            doc.contains(status),
            "document must define status token: {status}"
        );
    }
}

#[test]
fn doc_defines_failure_taxonomy() {
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
fn doc_has_contract_rows_for_all_primary_tracks_and_cross_track() {
    let doc = load_doc();
    for track in ["`T2`", "`T3`", "`T4`", "`T5`", "`T6`", "`T7`", "`Cross`"] {
        assert!(
            doc.contains(track),
            "contract rows missing capability track token: {track}"
        );
    }
}

#[test]
fn doc_has_minimum_contract_id_coverage() {
    let doc = load_doc();
    let ids = extract_contract_ids(&doc);
    assert!(
        ids.len() >= 14,
        "must define >=14 executable contract IDs, found {}",
        ids.len()
    );

    for token in [
        "EC-T2-01", "EC-T3-01", "EC-T4-01", "EC-T5-01", "EC-T6-01", "EC-T7-01", "EC-X-01",
    ] {
        assert!(ids.contains(token), "missing contract ID token: {token}");
    }
}

#[test]
fn doc_uses_rch_exec_for_heavy_runner_commands() {
    let doc = load_doc();
    assert!(
        doc.contains("rch exec --"),
        "runner command rows must use rch exec for heavy checks"
    );
}

#[test]
fn doc_defines_gate_bindings_and_policy() {
    let doc = load_doc();
    for gate in ["Gate-A", "Gate-B", "Gate-C"] {
        assert!(doc.contains(gate), "missing gate token: {gate}");
    }

    assert!(
        doc.contains("hard fail"),
        "gate section must define hard-fail policy"
    );
}

#[test]
fn doc_includes_required_replay_artifact_tokens() {
    let doc = load_doc();
    for artifact in [
        "event_log.txt",
        "failed_assertions.json",
        "repro_manifest.json",
        "summary.json",
    ] {
        assert!(
            doc.contains(artifact),
            "document missing required artifact token: {artifact}"
        );
    }
}

#[test]
fn doc_binds_to_downstream_t8_dependents() {
    let doc = load_doc();
    for token in [
        "asupersync-2oh2u.10.3",
        "asupersync-2oh2u.10.4",
        "asupersync-2oh2u.10.5",
        "asupersync-2oh2u.10.6",
    ] {
        assert!(
            doc.contains(token),
            "document missing downstream binding token: {token}"
        );
    }
}
