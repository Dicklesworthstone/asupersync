#![allow(warnings)]
#![allow(clippy::all)]
//! Contract tests for Tokio gap wave classification (2oh2u.1.3.2).

#![allow(missing_docs)]

use std::path::Path;

fn load_doc() -> String {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    let path = Path::new(&manifest_dir).join("docs/tokio_gap_wave_classification.md");
    std::fs::read_to_string(path).expect("gap wave classification document must exist")
}

#[test]
fn wave_doc_exists_and_is_substantial() {
    let doc = load_doc();
    assert!(
        doc.len() > 15_000,
        "wave classification doc should be substantial, got {} bytes",
        doc.len()
    );
}

#[test]
fn wave_doc_references_bead_and_dependencies() {
    let doc = load_doc();
    assert!(
        doc.contains("asupersync-2oh2u.1.3.2"),
        "must reference bead 2oh2u.1.3.2"
    );
    assert!(doc.contains("[T1.3.b]"), "must reference T1.3.b");
    assert!(doc.contains("T1.3.a"), "must reference T1.3.a dependency");
    assert!(doc.contains("T1.1.c"), "must reference T1.1.c dependency");
    assert!(doc.contains("T1.1.a"), "must reference T1.1.a dependency");
}

#[test]
fn wave_doc_includes_all_gap_sections() {
    let doc = load_doc();
    for gap in 1..=13 {
        let marker = format!("### G{gap}");
        assert!(
            doc.contains(&marker),
            "missing gap section marker: {marker}"
        );
    }
}

#[test]
fn wave_doc_has_composite_and_assumption_blocks_for_each_gap() {
    let doc = load_doc();
    let composite_count = doc.matches("**Composite**:").count();
    assert_eq!(
        composite_count, 13,
        "expected 13 composite score entries, found {composite_count}"
    );

    let assumption_count = doc
        .matches("**Assumptions that could change score**:")
        .count();
    assert_eq!(
        assumption_count, 13,
        "expected 13 assumptions blocks, found {assumption_count}"
    );
}

#[test]
fn wave_doc_has_confidence_model() {
    let doc = load_doc();
    for confidence in ["High (H)", "Medium (M)", "Low (L)"] {
        assert!(
            doc.contains(confidence),
            "missing confidence definition: {confidence}"
        );
    }
}

#[test]
fn wave_doc_has_three_wave_buckets() {
    let doc = load_doc();
    assert!(
        doc.contains("Wave 1 — Critical Path"),
        "missing Wave 1 critical path section"
    );
    assert!(
        doc.contains("Wave 2 — High-Impact Parallel"),
        "missing Wave 2 high-impact section"
    );
    assert!(
        doc.contains("Wave 3 — Opportunistic"),
        "missing Wave 3 opportunistic section"
    );
}

#[test]
fn wave_doc_covers_priority_distribution() {
    let doc = load_doc();
    assert!(doc.contains("| P1"), "missing P1 priority bucket");
    assert!(doc.contains("| P2"), "missing P2 priority bucket");
    assert!(doc.contains("| P3"), "missing P3 priority bucket");
    assert!(doc.contains("| 4 |"), "missing expected P1/P2 count token");
    assert!(doc.contains("| 5 |"), "missing expected P3 count token");
}

#[test]
fn wave_doc_maps_all_primary_tracks() {
    let doc = load_doc();
    for track in ["T2", "T3", "T4", "T5", "T6", "T7"] {
        assert!(
            doc.contains(&format!("**Mapped track**: {track}")),
            "missing mapped track marker for {track}"
        );
    }
}
