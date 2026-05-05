#![allow(missing_docs)]
#![allow(
    clippy::items_after_statements,
    clippy::let_unit_value,
    clippy::cast_precision_loss
)]

//! [T9.3] Compatibility and limitation matrix enforcement tests.
//!
//! Validates that `docs/tokio_compatibility_limitation_matrix.md` covers all
//! capability domains, includes rationale for every classification, and meets
//! all acceptance criteria for a release-governance-ready matrix.
//!
//! Bead: `asupersync-2oh2u.11.3`

use std::collections::BTreeSet;
use std::path::Path;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn project_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn load_doc() -> String {
    let path = project_root().join("docs/tokio_compatibility_limitation_matrix.md");
    std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("Cannot read {}", path.display()))
}

fn load_source(rel: &str) -> String {
    let path = project_root().join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("Cannot read {}", path.display()))
}

// ===========================================================================
// S1 — Document Structure
// ===========================================================================

#[test]
fn cm01_doc_exists_and_is_substantial() {
    let doc = load_doc();
    assert!(
        doc.len() > 10000,
        "matrix doc too small: {} bytes",
        doc.len()
    );
}

#[test]
fn cm02_doc_references_correct_bead() {
    let doc = load_doc();
    assert!(doc.contains("asupersync-2oh2u.11.3"));
    assert!(doc.contains("[T9.3]"));
}

#[test]
fn cm03_doc_has_all_required_top_sections() {
    let doc = load_doc();
    let sections = [
        "Classification Definitions",
        "Capability Compatibility Matrix",
        "Limitation Register",
        "Migration Lab Evidence",
        "Invariant Preservation",
        "Machine-Readable Schema",
        "Release Governance",
        "Downstream Binding",
    ];
    for s in &sections {
        assert!(doc.contains(s), "missing section: {s}");
    }
}

// ===========================================================================
// S2 — Classification Definitions
// ===========================================================================

#[test]
fn cm04_defines_all_five_classifications() {
    let doc = load_doc();
    for class in ["Full", "Partial", "Adapter", "Unsupported", "Planned"] {
        assert!(doc.contains(class), "missing classification: {class}");
    }
}

#[test]
fn cm05_classification_symbols_defined() {
    let doc = load_doc();
    // Classification table should have single-letter symbols
    for sym in ["| F |", "| P |", "| A |", "| U |", "| Z |"] {
        assert!(doc.contains(sym), "missing classification symbol: {sym}");
    }
}

// ===========================================================================
// S3 — Capability Domain Coverage
// ===========================================================================

const CAPABILITY_DOMAINS: &[&str] = &[
    "Core Runtime",
    "Channels and Synchronization",
    "Time",
    "I/O and Codec",
    "Networking",
    "QUIC and HTTP/3",
    "HTTP/1.1 and HTTP/2",
    "Web Framework and gRPC",
    "Database and Messaging",
    "Service Layer",
    "Filesystem, Process, Signal",
    "Streams and Observability",
    "Tokio Interop",
];

#[test]
fn cm06_covers_all_13_capability_domains() {
    let doc = load_doc();
    for domain in CAPABILITY_DOMAINS {
        assert!(doc.contains(domain), "missing domain: {domain}");
    }
}

#[test]
fn cm07_each_domain_has_capability_table() {
    let doc = load_doc();
    // Each domain table has "Tokio Equivalent" column header
    let equiv_count = doc.matches("Tokio Equivalent").count();
    assert!(
        equiv_count >= 13,
        "expected >= 13 domain tables, found {equiv_count}"
    );
}

#[test]
fn cm08_tables_include_status_rationale_evidence() {
    let doc = load_doc();
    let status_count = doc.matches("| Status |").count();
    let rationale_count = doc.matches("| Rationale |").count();
    let evidence_count = doc.matches("| Evidence |").count();
    assert!(
        status_count >= 13,
        "each domain needs Status column, found {status_count}"
    );
    assert!(
        rationale_count >= 13,
        "each domain needs Rationale column, found {rationale_count}"
    );
    assert!(
        evidence_count >= 13,
        "each domain needs Evidence column, found {evidence_count}"
    );
}

// ===========================================================================
// S4 — Capability Count
// ===========================================================================

#[test]
fn cm09_has_at_least_60_capability_entries() {
    let doc = load_doc();
    // Count rows with status F, P, A, or U in capability tables
    let f_count = doc.lines().filter(|l| l.contains("| F |")).count();
    let p_count = doc.lines().filter(|l| l.contains("| P |")).count();
    let a_count = doc.lines().filter(|l| l.contains("| A |")).count();
    let u_count = doc.lines().filter(|l| l.contains("| U |")).count();
    let total = f_count + p_count + a_count + u_count;
    assert!(
        total >= 60,
        "expected >= 60 capability entries, found {total}"
    );
}

#[test]
fn cm10_majority_full_parity() {
    let doc = load_doc();
    // Exclude definition rows (contain "Full", "Partial", etc.) and limitation
    // register rows (start with "| L-") to count only capability entries.
    let is_capability_row = |l: &&str| -> bool {
        (l.contains("| F |") || l.contains("| P |") || l.contains("| A |") || l.contains("| U |"))
            && !l.contains("| Full")
            && !l.contains("| Partial")
            && !l.contains("| Adapter")
            && !l.contains("| Unsupported")
            && !l.contains("| Planned")
            && !l.contains("| L-")
    };
    let f_count = doc
        .lines()
        .filter(|l| l.contains("| F |") && is_capability_row(l))
        .count();
    let total = doc.lines().filter(is_capability_row).count();
    let ratio = f_count as f64 / total as f64;
    assert!(
        ratio > 0.70,
        "expected > 70% Full parity, got {:.1}% ({f_count}/{total})",
        ratio * 100.0
    );
}

// ===========================================================================
// S5 — Limitation Register
// ===========================================================================

#[test]
fn cm11_has_at_least_10_limitations() {
    let doc = load_doc();
    let lim_count = doc.matches("| L-").count();
    assert!(
        lim_count >= 10,
        "expected >= 10 limitations, found {lim_count}"
    );
}

#[test]
fn cm12_all_limitation_ids_unique() {
    let doc = load_doc();
    let lim_ids: Vec<&str> = doc
        .lines()
        .filter_map(|l| {
            let trimmed = l.trim();
            if trimmed.starts_with("| L-") {
                trimmed.split('|').nth(1).map(str::trim)
            } else {
                None
            }
        })
        .filter(|id| id.starts_with("L-"))
        .collect();
    let unique: BTreeSet<&str> = lim_ids.iter().copied().collect();
    assert_eq!(lim_ids.len(), unique.len(), "duplicate limitation IDs");
}

#[test]
fn cm13_limitation_table_has_required_columns() {
    let doc = load_doc();
    for col in ["User Impact", "Mitigation", "Escalation", "Owner"] {
        assert!(doc.contains(col), "limitation table missing column: {col}");
    }
}

#[test]
fn cm14_no_critical_severity_limitations() {
    let doc = load_doc();
    // Check severity classification section
    let critical_line = doc
        .lines()
        .find(|l| l.contains("Critical") && l.contains("Blocks common"));
    if let Some(line) = critical_line {
        assert!(
            line.contains("| 0"),
            "must have 0 Critical severity limitations"
        );
    }
}

// ===========================================================================
// S6 — Limitation Rationale
// ===========================================================================

#[test]
fn cm15_limitation_rationale_section_exists() {
    let doc = load_doc();
    assert!(doc.contains("Limitation Rationale"));
}

#[test]
fn cm16_rationale_has_weighted_factors() {
    let doc = load_doc();
    for factor in [
        "User workflow blockage",
        "Workaround availability",
        "Downstream dependency",
        "Implementation complexity",
    ] {
        assert!(doc.contains(factor), "missing rationale factor: {factor}");
    }
}

#[test]
fn cm17_severity_classification_defined() {
    let doc = load_doc();
    for sev in ["Critical", "High", "Medium", "Low"] {
        assert!(doc.contains(sev), "missing severity level: {sev}");
    }
}

// ===========================================================================
// S7 — Migration Lab Evidence
// ===========================================================================

#[test]
fn cm18_lab_evidence_section_exists() {
    let doc = load_doc();
    assert!(doc.contains("Migration Lab Evidence"));
}

#[test]
fn cm19_lab_covers_all_six_archetypes() {
    let doc = load_doc();
    for archetype in [
        "REST CRUD",
        "gRPC microservice",
        "Event pipeline",
        "WebSocket",
        "CLI tool",
        "Hybrid Tokio-compat",
    ] {
        assert!(
            doc.contains(archetype),
            "missing lab archetype: {archetype}"
        );
    }
}

#[test]
fn cm20_lab_reports_kpi_results() {
    let doc = load_doc();
    assert!(
        doc.contains("KPIs") || doc.contains("kpi"),
        "must report friction KPI results"
    );
    // At least 6 archetypes should have KPI pass counts
    let kpi_lines = doc
        .lines()
        .filter(|l| l.contains("pass") && l.contains("KPI"))
        .count();
    assert!(
        kpi_lines >= 6,
        "expected >= 6 KPI result rows, found {kpi_lines}"
    );
}

// ===========================================================================
// S8 — Invariant Preservation
// ===========================================================================

#[test]
fn cm21_preserves_all_five_invariants() {
    let doc = load_doc();
    for inv in ["INV-1", "INV-2", "INV-3", "INV-4", "INV-5"] {
        assert!(doc.contains(inv), "missing invariant: {inv}");
    }
}

#[test]
fn cm22_invariants_all_preserved() {
    let doc = load_doc();
    // Every invariant row should show "Preserved"
    let preserved_count = doc
        .lines()
        .filter(|l| l.contains("INV-") && l.contains("Preserved"))
        .count();
    assert_eq!(
        preserved_count, 5,
        "all 5 invariants must be Preserved, found {preserved_count}"
    );
}

// ===========================================================================
// S9 — Machine-Readable Schema
// ===========================================================================

#[test]
fn cm23_json_schema_specified() {
    let doc = load_doc();
    assert!(doc.contains("schema_version"));
    assert!(doc.contains("capabilities"));
    assert!(doc.contains("limitations"));
    assert!(doc.contains("lab_evidence"));
    assert!(doc.contains("summary"));
}

#[test]
fn cm24_schema_capability_entry_fields() {
    let doc = load_doc();
    for field in [
        "capability",
        "tokio_equivalent",
        "status",
        "rationale",
        "evidence_path",
    ] {
        assert!(
            doc.contains(field),
            "schema capability entry missing: {field}"
        );
    }
}

#[test]
fn cm25_schema_limitation_entry_fields() {
    let doc = load_doc();
    for field in [
        "lim_id",
        "user_impact",
        "mitigation",
        "escalation_path",
        "owner_track",
        "severity",
    ] {
        assert!(
            doc.contains(field),
            "schema limitation entry missing: {field}"
        );
    }
}

#[test]
fn cm26_schema_summary_counts() {
    let doc = load_doc();
    for field in [
        "total_capabilities",
        "full_count",
        "partial_count",
        "adapter_count",
        "unsupported_count",
    ] {
        assert!(doc.contains(field), "schema summary missing: {field}");
    }
}

// ===========================================================================
// S10 — Release Governance
// ===========================================================================

#[test]
fn cm27_version_policy_defined() {
    let doc = load_doc();
    assert!(doc.contains("1.0.0"), "policy version missing");
    assert!(doc.contains("0.1.x"), "compatibility line missing");
}

#[test]
fn cm28_classification_change_policy_defined() {
    let doc = load_doc();
    assert!(doc.contains("Upgrade"));
    assert!(doc.contains("Downgrade"));
    assert!(doc.contains("New limitation"));
}

#[test]
fn cm29_staleness_threshold_defined() {
    let doc = load_doc();
    assert!(
        doc.contains("30 days"),
        "staleness warning threshold missing"
    );
    assert!(
        doc.contains("60 days"),
        "staleness hard-fail threshold missing"
    );
}

// ===========================================================================
// S11 — Downstream Binding
// ===========================================================================

#[test]
fn cm30_binds_to_downstream_beads() {
    let doc = load_doc();
    assert!(
        doc.contains("asupersync-2oh2u.11.5"),
        "must bind to T9.5 release channels"
    );
}

// ===========================================================================
// S12 — Cross-Reference Validation
// ===========================================================================

#[test]
fn cm31_references_prerequisite_beads() {
    let doc = load_doc();
    assert!(
        doc.contains("asupersync-2oh2u.11.10"),
        "must reference T9.10 migration labs"
    );
    assert!(
        doc.contains("asupersync-2oh2u.11.2"),
        "must reference T9.2 cookbooks"
    );
}

#[test]
fn cm32_references_compat_crate() {
    let doc = load_doc();
    assert!(
        doc.contains("asupersync-tokio-compat"),
        "must reference compat crate for adapter entries"
    );
}

#[test]
fn cm33_references_gap_ids() {
    let doc = load_doc();
    // Should reference limitation IDs L-01 through L-10
    for lid in ["L-01", "L-05", "L-10"] {
        assert!(doc.contains(lid), "missing limitation: {lid}");
    }
}

// ===========================================================================
// S13 — No Deferred Markers
// ===========================================================================

#[test]
fn cm34_no_deferred_markers() {
    let doc = load_doc();
    for marker in ["[DEFERRED]", "[TBD]", "[TODO]", "[PLACEHOLDER]"] {
        assert!(!doc.contains(marker), "doc has {marker} marker");
    }
}

// ===========================================================================
// S14 — Self-Validation
// ===========================================================================

#[test]
fn cm35_no_duplicate_test_names() {
    let src = load_source("tests/tokio_compatibility_limitation_matrix_enforcement.rs");
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
