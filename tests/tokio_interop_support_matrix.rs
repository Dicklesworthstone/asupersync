#![allow(warnings)]
#![allow(clippy::all)]
#![allow(missing_docs)]
#![allow(clippy::items_after_statements, clippy::let_unit_value)]

//! [T7.9] Support matrix and long-term interop policy validation.
//!
//! Validates that the support matrix (`docs/tokio_interop_support_matrix.md`)
//! is complete, machine-readable requirements are met, and drift detection
//! rules are enforceable.
//!
//! Bead: `asupersync-2oh2u.7.9`

use std::collections::BTreeSet;
use std::path::Path;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn project_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn load_doc() -> String {
    let path = project_root().join("docs/tokio_interop_support_matrix.md");
    std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("Cannot read {}", path.display()))
}

fn load_source(rel: &str) -> String {
    let path = project_root().join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("Cannot read {}", path.display()))
}

// ===========================================================================
// § 1 — Document Structure
// ===========================================================================

#[test]
fn doc_exists_and_is_substantial() {
    let doc = load_doc();
    let len = doc.len();
    assert!(len > 5000, "support matrix doc too small: {len} bytes");
}

#[test]
fn doc_references_correct_bead() {
    let doc = load_doc();
    assert!(doc.contains("asupersync-2oh2u.7.9"));
    assert!(doc.contains("[T7.9]"));
}

#[test]
fn doc_has_all_required_sections() {
    let doc = load_doc();
    let sections = [
        "Support Tiers",
        "Tier Definitions",
        "Tier Assignment",
        "Feature Subset Support",
        "Invariant Preservation",
        "Maintenance Commitments",
        "Escalation Policy",
        "Gap Ranking",
        "Drift Detection",
        "Machine-Readable Output",
        "Downstream Binding",
    ];
    for s in &sections {
        assert!(doc.contains(s), "missing section: {s}");
    }
}

// ===========================================================================
// § 2 — Tier Definitions
// ===========================================================================

#[test]
fn doc_defines_five_tiers() {
    let doc = load_doc();
    for tier in ["T1", "T2", "T3", "T4", "T5"] {
        assert!(doc.contains(tier), "missing tier: {tier}");
    }
}

#[test]
fn doc_defines_tier_labels() {
    let doc = load_doc();
    for label in ["Critical", "High", "Moderate", "Low", "Minimal"] {
        assert!(doc.contains(label), "missing tier label: {label}");
    }
}

#[test]
fn doc_defines_tier_response_windows() {
    let doc = load_doc();
    assert!(doc.contains("72 hours"), "T1 must have 72h response");
    assert!(doc.contains("1 week"), "T2 must have 1 week response");
}

// ===========================================================================
// § 3 — Crate Coverage
// ===========================================================================

const ALL_CRATES: &[&str] = &[
    "reqwest",
    "axum",
    "tonic",
    "sea-orm",
    "hyper",
    "bb8",
    "sqlx",
    "rumqttc",
    "diesel-async",
    "tower",
    "rdkafka",
    "tower-http",
    "lapin",
    "deadpool",
];

#[test]
fn doc_lists_all_14_crates() {
    let doc = load_doc();
    for c in ALL_CRATES {
        assert!(doc.contains(c), "missing crate: {c}");
    }
}

#[test]
fn doc_assigns_impact_scores() {
    let doc = load_doc();
    // Critical tier crates
    assert!(doc.contains("22.5"), "reqwest impact score missing");
    assert!(doc.contains("17.5"), "axum impact score missing");
    assert!(doc.contains("14.0"), "tonic impact score missing");
}

#[test]
fn critical_tier_contains_keystone_crates() {
    let doc = load_doc();
    // reqwest, axum, tonic must be T1
    for c in &["reqwest", "axum", "tonic"] {
        // Find the line with the crate and verify T1
        let crate_line = doc
            .lines()
            .find(|l| l.contains(c) && l.contains("T1"))
            .unwrap_or("");
        assert!(
            !crate_line.is_empty(),
            "{c} must be assigned to T1 (Critical)"
        );
    }
}

// ===========================================================================
// § 4 — Feature Gates
// ===========================================================================

#[test]
fn doc_lists_all_feature_gates() {
    let doc = load_doc();
    for gate in &["hyper-bridge", "tower-bridge", "tokio-io", "full"] {
        assert!(doc.contains(gate), "missing feature gate: {gate}");
    }
}

#[test]
fn feature_gates_match_cargo_toml() {
    let toml = load_source("asupersync-tokio-compat/Cargo.toml");
    for gate in &["hyper-bridge", "tower-bridge", "tokio-io"] {
        assert!(toml.contains(gate), "feature gate {gate} not in Cargo.toml");
    }
}

// ===========================================================================
// § 5 — Invariant Preservation
// ===========================================================================

#[test]
fn doc_references_all_five_invariants() {
    let doc = load_doc();
    for inv in &["INV-1", "INV-2", "INV-3", "INV-4", "INV-5"] {
        assert!(doc.contains(inv), "missing invariant: {inv}");
    }
}

#[test]
fn doc_describes_invariant_meanings() {
    let doc = load_doc();
    let meanings = [
        "No ambient authority",
        "Structured concurrency",
        "Cancellation is a protocol",
        "No obligation leaks",
        "Outcome severity lattice",
    ];
    for m in &meanings {
        assert!(doc.contains(m), "missing invariant meaning: {m}");
    }
}

#[test]
fn doc_defines_relaxable_constraints() {
    let doc = load_doc();
    for rel in &["REL-1", "REL-2", "REL-3", "REL-4"] {
        assert!(doc.contains(rel), "missing relaxable constraint: {rel}");
    }
}

// ===========================================================================
// § 6 — Per-Crate Feature Support
// ===========================================================================

#[test]
fn doc_has_supported_and_unsupported_columns() {
    let doc = load_doc();
    assert!(doc.contains("Supported Features"));
    assert!(doc.contains("Unsupported Features"));
}

#[test]
fn doc_has_evidence_links_for_all_tiers() {
    let doc = load_doc();
    for eid in &[
        "E-01", "E-02", "E-03", "E-04", "E-05", "E-06", "E-07", "E-08", "E-09", "E-10", "E-11",
        "E-12",
    ] {
        assert!(doc.contains(eid), "missing evidence link: {eid}");
    }
}

#[test]
fn evidence_links_point_to_existing_test_files() {
    let doc = load_doc();
    let test_files = [
        "tests/tokio_interop_conformance_suites.rs",
        "tests/tokio_adapter_boundary_architecture.rs",
        "tests/tokio_adapter_boundary_correctness.rs",
    ];
    for f in &test_files {
        assert!(doc.contains(f), "evidence link not in doc: {f}");
        assert!(
            project_root().join(f).exists(),
            "evidence file missing: {f}"
        );
    }
}

// ===========================================================================
// § 7 — Maintenance Commitments
// ===========================================================================

#[test]
fn doc_specifies_compatibility_window() {
    let doc = load_doc();
    assert!(doc.contains("1.0.0"), "policy version missing");
    assert!(doc.contains("0.1.x"), "compatibility line missing");
    assert!(doc.contains("edition 2024"), "Rust edition missing");
}

#[test]
fn doc_specifies_version_pinning_policy() {
    let doc = load_doc();
    assert!(doc.contains("SemVer"), "SemVer policy missing");
    assert!(doc.contains("pinned"), "pinning policy missing");
}

// ===========================================================================
// § 8 — Escalation Policy
// ===========================================================================

#[test]
fn doc_classifies_breakage_severities() {
    let doc = load_doc();
    for sev in &["S1", "S2", "S3", "S4"] {
        assert!(doc.contains(sev), "missing severity class: {sev}");
    }
}

#[test]
fn doc_defines_escalation_flow() {
    let doc = load_doc();
    let steps = [
        "Detection",
        "Triage",
        "Assignment",
        "Fix",
        "Verification",
        "Release",
    ];
    for step in &steps {
        assert!(doc.contains(step), "escalation step missing: {step}");
    }
}

// ===========================================================================
// § 9 — Gap Ranking
// ===========================================================================

#[test]
fn doc_lists_current_gaps() {
    let doc = load_doc();
    for gid in &["G-01", "G-02", "G-03", "G-04", "G-05", "G-06"] {
        assert!(doc.contains(gid), "missing gap: {gid}");
    }
}

#[test]
fn gaps_have_severity_and_owner() {
    let doc = load_doc();
    // Every gap row should have a severity and owner column
    assert!(
        doc.contains("Severity"),
        "gap table must have Severity column"
    );
    assert!(doc.contains("Owner"), "gap table must have Owner column");
}

#[test]
fn gap_rationale_section_exists() {
    let doc = load_doc();
    assert!(
        doc.contains("Gap Rationale"),
        "gap rationale section missing"
    );
    assert!(
        doc.contains("Downstream dependency"),
        "gap ranking criterion missing"
    );
}

// ===========================================================================
// § 10 — Drift Detection
// ===========================================================================

#[test]
fn doc_defines_drift_checks() {
    let doc = load_doc();
    for dc in &["DC-01", "DC-02", "DC-03", "DC-04", "DC-05", "DC-06"] {
        assert!(doc.contains(dc), "missing drift check: {dc}");
    }
}

#[test]
fn doc_defines_drift_detection_rules() {
    let doc = load_doc();
    for dr in &["DR-01", "DR-02", "DR-03", "DR-04"] {
        assert!(doc.contains(dr), "missing drift rule: {dr}");
    }
}

#[test]
fn dc01_adapter_compile_check_is_hard_fail() {
    let doc = load_doc();
    // DC-01 should be hard-fail and every CI run
    let dc01_line = doc.lines().find(|l| l.contains("DC-01")).unwrap_or("");
    assert!(
        dc01_line.contains("Yes") || dc01_line.contains("yes"),
        "DC-01 must be hard-fail"
    );
}

#[test]
fn freshness_policy_defined() {
    let doc = load_doc();
    assert!(doc.contains("30 days"), "30-day freshness policy missing");
    assert!(doc.contains("60 days"), "60-day hard-fail missing");
}

// ===========================================================================
// § 11 — Machine-Readable Output
// ===========================================================================

#[test]
fn doc_specifies_json_schema() {
    let doc = load_doc();
    assert!(
        doc.contains("schema_version"),
        "JSON schema must have schema_version"
    );
    assert!(doc.contains("crates"), "JSON schema must have crates array");
    assert!(doc.contains("gaps"), "JSON schema must have gaps array");
    assert!(
        doc.contains("drift_checks"),
        "JSON schema must have drift_checks array"
    );
}

#[test]
fn json_schema_crate_entry_has_required_fields() {
    let doc = load_doc();
    let fields = [
        "name",
        "version_range",
        "impact_score",
        "tier",
        "adapter_modules",
        "feature_gates",
        "supported_features",
        "unsupported_features",
        "evidence_id",
        "evidence_path",
        "owner_track",
        "invariants_preserved",
    ];
    for field in &fields {
        assert!(
            doc.contains(field),
            "JSON crate entry missing field: {field}"
        );
    }
}

#[test]
fn json_schema_gap_entry_has_required_fields() {
    let doc = load_doc();
    let fields = [
        "gap_id",
        "crate",
        "feature",
        "severity",
        "downstream_impact",
        "owner_track",
    ];
    for field in &fields {
        assert!(doc.contains(field), "JSON gap entry missing field: {field}");
    }
}

// ===========================================================================
// § 12 — Downstream Binding
// ===========================================================================

#[test]
fn doc_binds_to_downstream_beads() {
    let doc = load_doc();
    assert!(
        doc.contains("asupersync-2oh2u.11.2"),
        "must bind to T9.2 migration cookbooks"
    );
    assert!(
        doc.contains("asupersync-2oh2u.10.9"),
        "must bind to T8.9 readiness gate"
    );
}

// ===========================================================================
// § 13 — Cross-Reference Validation
// ===========================================================================

#[test]
fn adapter_modules_in_doc_exist_in_source() {
    let modules = [
        "hyper_bridge",
        "body_bridge",
        "tower_bridge",
        "io",
        "cancel",
        "blocking",
    ];
    let compat_dir = project_root().join("asupersync-tokio-compat/src");
    for m in &modules {
        let path = compat_dir.join(format!("{m}.rs"));
        assert!(path.exists(), "adapter module missing: {m}.rs");
    }
}

#[test]
fn support_matrix_consistent_with_ranking_doc() {
    let _matrix = load_doc();
    let ranking = load_source("docs/tokio_interop_target_ranking.md");
    // Both should list the same crates
    for c in ALL_CRATES {
        assert!(
            ranking.contains(c),
            "crate {c} in matrix but not in ranking doc"
        );
    }
}

#[test]
fn doc_has_no_deferred_markers() {
    let doc = load_doc();
    for marker in ["[DEFERRED]", "[TBD]", "[TODO]", "[PLACEHOLDER]"] {
        assert!(!doc.contains(marker), "doc has {marker} marker");
    }
}

// ===========================================================================
// § 14 — Self-Validation
// ===========================================================================

#[test]
fn no_duplicate_test_names() {
    let src = load_source("tests/tokio_interop_support_matrix.rs");
    let fn_names: Vec<&str> = src
        .lines()
        .filter(|l| l.trim_start().starts_with("fn "))
        .filter_map(|l| l.trim_start().strip_prefix("fn ")?.split('(').next())
        .collect();
    let unique: BTreeSet<&str> = fn_names.iter().copied().collect();
    assert_eq!(
        fn_names.len(),
        unique.len(),
        "duplicate test function names"
    );
}
