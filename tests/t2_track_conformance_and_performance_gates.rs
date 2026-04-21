#![allow(clippy::all)]
//! Contract tests for T2 I/O-track conformance and performance gates (2oh2u.2.8).
//!
//! Enforces deterministic gate IDs, evidence schema, artifact requirements,
//! diagnostics routing, and rch-based runner commands.

#![allow(missing_docs)]

use std::collections::BTreeSet;
use std::path::Path;

fn load_doc() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("docs/tokio_io_track_conformance_and_performance_gates.md");
    std::fs::read_to_string(path)
        .expect("T2 I/O track conformance and performance gates document must exist")
}

fn extract_ids(doc: &str, prefix: &str) -> BTreeSet<String> {
    let mut ids = BTreeSet::new();
    for line in doc.lines() {
        let trimmed = line.trim().trim_start_matches('|').trim();
        if let Some(first_cell) = trimmed.split('|').next() {
            let id = first_cell.trim().trim_matches('`');
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
        doc.contains("asupersync-2oh2u.2.8"),
        "document must reference bead 2oh2u.2.8"
    );
    assert!(doc.contains("[T2.8]"), "document must reference T2.8");
    assert!(
        doc.contains("track_id"),
        "document must define track schema"
    );
    assert!(doc.contains("`T2`"), "document must bind to T2");
}

#[test]
fn doc_references_required_dependencies() {
    let doc = load_doc();
    for token in [
        "asupersync-2oh2u.2.5",
        "asupersync-2oh2u.2.6",
        "tokio_io_parity_audit.md",
        "tokio_io_codec_cancellation_correctness.md",
    ] {
        assert!(
            doc.contains(token),
            "document missing dependency token: {token}"
        );
    }
}

#[test]
fn doc_defines_evidence_schema_fields() {
    let doc = load_doc();
    for token in [
        "run_id",
        "commit_sha",
        "track_id",
        "contract_id",
        "scenario_id",
        "backend",
        "transport_surface",
        "cancellation_path",
        "failure_class",
        "owning_bead",
        "owning_module",
        "artifact_path",
        "latency_p95_us",
        "throughput_bytes_per_sec",
        "regression_pct",
        "verdict",
        "generated_at",
        "repro_command",
    ] {
        assert!(
            doc.contains(token),
            "missing evidence schema token: {token}"
        );
    }
}

#[test]
fn doc_has_required_conformance_gate_ids() {
    let doc = load_doc();
    let ids = extract_ids(&doc, "IOCG-");
    for id in [
        "IOCG-01", "IOCG-02", "IOCG-03", "IOCG-04", "IOCG-05", "IOCG-06",
    ] {
        assert!(ids.contains(id), "missing conformance gate id: {id}");
    }
}

#[test]
fn doc_has_required_performance_gate_ids() {
    let doc = load_doc();
    let ids = extract_ids(&doc, "IOPG-");
    for id in ["IOPG-01", "IOPG-02", "IOPG-03", "IOPG-04", "IOPG-05"] {
        assert!(ids.contains(id), "missing performance gate id: {id}");
    }
}

#[test]
fn doc_defines_status_model_and_blocked_semantics() {
    let doc = load_doc();
    for token in ["PASS", "FAIL", "BLOCKED"] {
        assert!(doc.contains(token), "missing status token: {token}");
    }
    assert!(
        doc.contains("`BLOCKED` is never equivalent to `PASS`"),
        "document must define strict BLOCKED semantics"
    );
}

#[test]
fn doc_defines_required_artifact_bundle() {
    let doc = load_doc();
    for token in [
        "tokio_t2_conformance_matrix.json",
        "tokio_t2_performance_budget_report.json",
        "tokio_t2_gate_failures.json",
        "tokio_t2_gate_summary.md",
        "tokio_t2_gate_repro_commands.txt",
    ] {
        assert!(doc.contains(token), "missing artifact token: {token}");
    }
}

#[test]
fn doc_requires_failure_routing_fields() {
    let doc = load_doc();
    for token in [
        "failure_id",
        "failure_class",
        "owning_bead",
        "owning_module",
        "recommended_test",
        "repro_command",
    ] {
        assert!(
            doc.contains(token),
            "missing diagnostics routing token: {token}"
        );
    }
}

#[test]
fn doc_requires_rch_exec_for_heavy_commands() {
    let doc = load_doc();
    assert!(
        doc.contains("rch exec --"),
        "document must require rch for heavy commands"
    );
    for token in [
        "rch exec -- cargo check --all-targets",
        "rch exec -- cargo clippy --all-targets -- -D warnings",
        "rch exec -- cargo fmt --check",
        "rch exec -- cargo test --test tokio_io_codec_cancellation_correctness -- --nocapture",
        "rch exec -- cargo test --test io_cancellation -- --nocapture",
        "rch exec -- cargo test --test t2_track_conformance_and_performance_gates -- --nocapture",
    ] {
        assert!(doc.contains(token), "missing runner command token: {token}");
    }
}

#[test]
fn doc_binds_acceptance_criteria_tokens() {
    let doc = load_doc();
    for token in [
        "Contracts are executable with unambiguous pass/fail semantics tied to capability invariants.",
        "Coverage includes protocol correctness, cancellation behavior, and failure semantics.",
        "Conformance artifacts are reproducible and archived for auditability.",
        "Contract violations produce clear diagnostics mapped to owning beads/modules.",
    ] {
        assert!(
            doc.contains(token),
            "missing acceptance criteria binding token: {token}"
        );
    }
}

#[test]
fn doc_binds_downstream_beads() {
    let doc = load_doc();
    for token in [
        "asupersync-2oh2u.2.10",
        "asupersync-2oh2u.2.7",
        "asupersync-2oh2u.10.9",
    ] {
        assert!(
            doc.contains(token),
            "missing downstream bead token: {token}"
        );
    }
}
