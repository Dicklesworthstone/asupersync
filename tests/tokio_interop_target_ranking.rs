#![allow(warnings)]
#![allow(clippy::all)]
//! Contract tests for Tokio interop target ranking (2oh2u.7.1).
//!
//! Validates ranking coverage, machine-readable export presence,
//! migration-playbook content, and validation/evidence linkage.

#![allow(missing_docs)]

use std::path::Path;

fn load_doc() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/tokio_interop_target_ranking.md");
    std::fs::read_to_string(path).expect("interop ranking document must exist")
}

#[test]
fn ranking_doc_exists_and_is_substantial() {
    let doc = load_doc();
    assert!(
        doc.len() > 8_000,
        "interop ranking doc should be substantial, got {} bytes",
        doc.len()
    );
}

#[test]
fn ranking_doc_references_correct_bead_and_track() {
    let doc = load_doc();
    assert!(
        doc.contains("asupersync-2oh2u.7.1"),
        "must reference bead asupersync-2oh2u.7.1"
    );
    assert!(doc.contains("[T7.1]"), "must reference T7.1");
}

#[test]
fn ranking_doc_covers_top_tokio_locked_targets() {
    let doc = load_doc();
    for token in ["reqwest", "axum", "tonic", "sqlx", "hyper", "sea-orm"] {
        assert!(
            doc.contains(token),
            "missing expected target token: {token}"
        );
    }
}

#[test]
fn ranking_doc_has_machine_readable_export_block() {
    let doc = load_doc();
    assert!(
        doc.contains("Machine-Readable Ranking Export (JSON v1)"),
        "must include machine-readable export section"
    );
    for token in [
        "\"schema_version\": \"tokio-interop-ranking/v1\"",
        "\"crate\": \"reqwest\"",
        "\"crate\": \"axum\"",
        "\"crate\": \"tonic\"",
    ] {
        assert!(doc.contains(token), "missing JSON export token: {token}");
    }
}

#[test]
fn ranking_doc_has_before_after_patterns_and_edge_cases() {
    let doc = load_doc();
    assert!(
        doc.contains("Before/After Migration Patterns"),
        "must include before/after migration pattern section"
    );
    for token in [
        "User Journey",
        "Before (Tokio-locked)",
        "After (Asupersync path)",
        "Edge Case",
        "Validation Path",
        "cancellation requested during body upload",
    ] {
        assert!(
            doc.contains(token),
            "missing migration-pattern token: {token}"
        );
    }
}

#[test]
fn ranking_doc_has_rch_validation_command_bundle() {
    let doc = load_doc();
    for token in [
        "rch exec -- cargo test -p asupersync-tokio-compat --features hyper-bridge --lib -- --nocapture",
        "rch exec -- cargo test -p asupersync-tokio-compat --features tokio-io --lib -- --nocapture",
        "rch exec -- cargo test --test native_seam_parity -- --nocapture",
        "rch exec -- cargo test --test semantic_conformance_harness -- --nocapture",
        "rch exec -- cargo test --test tokio_executable_conformance_contracts -- --nocapture",
    ] {
        assert!(
            doc.contains(token),
            "missing validation command token: {token}"
        );
    }
}

#[test]
fn ranking_doc_includes_operational_caveats_and_rollback_guidance() {
    let doc = load_doc();
    for token in [
        "Operational Caveats, Rollback, and Troubleshooting",
        "authority_flow_violation",
        "interop_boundary_violation",
        "timing_drift",
        "Rollback Action",
        "Troubleshooting Decision Point",
    ] {
        assert!(doc.contains(token), "missing operations token: {token}");
    }
}

#[test]
fn ranking_doc_links_conformance_and_performance_evidence() {
    let doc = load_doc();
    for token in [
        "docs/tokio_executable_conformance_contracts.md",
        "docs/tokio_nonfunctional_closure_criteria.md",
        "docs/tokio_adapter_boundary_architecture.md",
        "asupersync-tokio-compat/src/hyper_bridge.rs",
        "asupersync-tokio-compat/src/io.rs",
        "asupersync-tokio-compat/src/cancel.rs",
    ] {
        assert!(doc.contains(token), "missing evidence-link token: {token}");
    }
}

#[test]
fn ranking_doc_revision_history_tracks_latest_update() {
    let doc = load_doc();
    assert!(
        doc.contains("| 2026-03-03 | WhiteDesert |"),
        "revision history should include WhiteDesert update row"
    );
    assert!(
        doc.contains("| 2026-03-03 | SapphireHill | Initial ranking (v1.0) |"),
        "revision history should retain original baseline row"
    );
}
