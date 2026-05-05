//! Contract tests for the lab-vs-live differential scope matrix (2a6k9.1.1).
//!
//! Verifies the scope buckets, rollout order, non-goals, downstream bindings,
//! and `rch`-offloaded validation policy for the differential program.

#![allow(missing_docs)]

use std::path::Path;

fn load_doc() -> String {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/lab_live_differential_scope_matrix.md");
    std::fs::read_to_string(path).expect("lab-live differential scope matrix must exist")
}

#[test]
fn doc_exists_and_is_substantial() {
    let doc = load_doc();
    assert!(
        doc.len() > 4_500,
        "document should be substantial, got {} bytes",
        doc.len()
    );
}

#[test]
fn doc_references_bead_parent_and_inputs() {
    let doc = load_doc();
    for token in [
        "asupersync-2a6k9.1.1",
        "asupersync-2a6k9.1",
        "asupersync-2a6k9",
        "docs/replay-debugging.md",
        "docs/tokio_differential_behavior_suites.md",
        "tests/semantic_witness_replay_e2e.rs",
        "tests/adversarial_witness_corpus.rs",
    ] {
        assert!(
            doc.contains(token),
            "document missing dependency token: {token}"
        );
    }
}

#[test]
fn doc_exposes_parent_contract_map() {
    let doc = load_doc();
    for token in [
        "Parent Contract Map (`asupersync-2a6k9.1`)",
        "docs/lab_live_normalized_observable_schema.md",
        "docs/lab_live_divergence_taxonomy.md",
        "docs/lab_live_verification_taxonomy.md",
        "inherit all four documents together",
        "not allowed to redefine comparator inputs, admitted surfaces, or",
    ] {
        assert!(
            doc.contains(token),
            "document missing parent-contract token: {token}"
        );
    }
}

#[test]
fn doc_defines_three_scope_buckets() {
    let doc = load_doc();
    for token in ["supported-now", "supported-later", "unsupported"] {
        assert!(
            doc.contains(token),
            "document missing scope bucket: {token}"
        );
    }
}

#[test]
fn doc_defines_rollout_phases_and_ordering() {
    let doc = load_doc();
    for token in ["Phase 1", "Phase 2", "Phase 3", "Phase 4"] {
        assert!(
            doc.contains(token),
            "document missing rollout phase: {token}"
        );
    }

    let token = "cancellation -> combinators -> channels -> obligations -> region close/quiescence -> sync primitives -> timers -> virtualized transport";
    assert!(
        doc.contains(token),
        "document missing rollout order token: {token}"
    );
}

#[test]
fn doc_covers_required_surfaces() {
    let doc = load_doc();
    for token in [
        "Cancellation protocol",
        "Combinators (`join`, `race`, loser drain, severity aggregation)",
        "Channels (`mpsc`, `oneshot`, `broadcast`, `watch`)",
        "Obligations",
        "Region close / quiescence",
        "Sync primitives (`Mutex`, `Semaphore`, `Pool`, similar bounded invariants)",
        "Timers / virtualized time",
        "Virtualized transport / loopback network",
        "HTTP / gRPC / higher-level protocol adapters on virtualized or loopback transport",
        "Browser-like environments with explicit host capture",
        "Raw sockets / reactor backends / kernel scheduling",
        "Real network behavior (`DNS`, `TLS`, packet loss on live networks, remote peers)",
    ] {
        assert!(doc.contains(token), "document missing surface row: {token}");
    }
}

#[test]
fn doc_names_explicit_non_goals() {
    let doc = load_doc();
    for token in [
        "raw event ordering parity",
        "performance parity",
        "raw OS, browser, or network fidelity",
        "whole-system equivalence",
        "automatic support claims",
    ] {
        assert!(
            doc.contains(token),
            "document missing non-goal token: {token}"
        );
    }
}

#[test]
fn doc_requires_admission_rules_for_new_surfaces() {
    let doc = load_doc();
    for token in [
        "Controllable inputs",
        "Normalized observables",
        "Externality boundary",
        "Artifact contract",
        "Failure interpretation",
    ] {
        assert!(
            doc.contains(token),
            "document missing admission rule: {token}"
        );
    }
}

#[test]
fn doc_publishes_external_surface_eligibility_gate() {
    let doc = load_doc();
    for token in [
        "Eligibility Gate for Raw-Socket, HTTP, and Browser Surfaces",
        "eligible_for_pilot",
        "blocked_missing_virtualization",
        "blocked_missing_observability",
        "blocked_missing_verification",
        "blocked_scope_red_line",
        "raw_socket",
        "http_surface",
        "browser_surface",
        "host_role",
        "support_class",
        "reason_code",
        "README.md",
        "docs/WASM.md",
    ] {
        assert!(
            doc.contains(token),
            "document missing eligibility-gate token: {token}"
        );
    }
}

#[test]
fn doc_binds_to_downstream_beads() {
    let doc = load_doc();
    for token in [
        "asupersync-2a6k9.1.2",
        "asupersync-2a6k9.1.3",
        "asupersync-2a6k9.1.4",
        "asupersync-2a6k9.2.*",
        "asupersync-2a6k9.4.*",
        "asupersync-2a6k9.6.*",
        "asupersync-2a6k9.7.*",
    ] {
        assert!(
            doc.contains(token),
            "document missing downstream binding token: {token}"
        );
    }
}

#[test]
fn doc_requires_rch_for_validation() {
    let doc = load_doc();
    for token in [
        "rch exec -- cargo fmt --check",
        "rch exec -- cargo check --all-targets",
        "rch exec -- cargo clippy --all-targets -- -D warnings",
        "rch exec -- cargo test --test lab_live_differential_scope_matrix -- --nocapture",
    ] {
        assert!(
            doc.contains(token),
            "document missing validation command: {token}"
        );
    }
}
