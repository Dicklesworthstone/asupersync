#![allow(clippy::all)]
//! Contract tests for dependency-aware Tokio replacement roadmap (2oh2u.1.3.3).

#![allow(missing_docs)]

use std::path::Path;

fn load_doc() -> String {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    let path = Path::new(&manifest_dir).join("docs/tokio_replacement_roadmap.md");
    std::fs::read_to_string(path).expect("replacement roadmap document must exist")
}

#[test]
fn roadmap_doc_exists_and_is_substantial() {
    let doc = load_doc();
    assert!(
        doc.len() > 10_000,
        "roadmap doc should be substantial, got {} bytes",
        doc.len()
    );
}

#[test]
fn roadmap_doc_references_bead_and_inputs() {
    let doc = load_doc();
    assert!(
        doc.contains("asupersync-2oh2u.1.3.3"),
        "must reference bead 2oh2u.1.3.3"
    );
    assert!(doc.contains("[T1.3.c]"), "must reference T1.3.c");
    for dep in ["T1.3.b", "T1.3.a", "T1.1.c", "T1.1.a"] {
        assert!(doc.contains(dep), "missing dependency marker: {dep}");
    }
}

#[test]
fn roadmap_doc_has_track_overview_for_t1_through_t9() {
    let doc = load_doc();
    for track in ["T1", "T2", "T3", "T4", "T5", "T6", "T7", "T8", "T9"] {
        assert!(
            doc.contains(&format!("| {track} |")),
            "missing track overview row for {track}"
        );
    }
}

#[test]
fn roadmap_doc_has_cross_track_dependency_graph_and_critical_path() {
    let doc = load_doc();
    assert!(
        doc.contains("## 2. Cross-Track Dependency Graph"),
        "missing cross-track dependency graph section"
    );
    for critical in ["T7.1", "T7.4", "T4.2", "T8.9", "T9.8", "T9.9"] {
        assert!(
            doc.contains(critical),
            "critical path token must be present: {critical}"
        );
    }
    assert!(
        doc.contains("Critical path length"),
        "critical path summary is required"
    );
}

#[test]
fn roadmap_doc_has_execution_phases_a_through_e() {
    let doc = load_doc();
    for phase in [
        "Phase A — Foundation",
        "Phase B — Architecture & Core Implementation",
        "Phase C — Hardening & Integration",
        "Phase D — Messaging, Polish & Evidence",
        "Phase E — Release Preparation & GA",
    ] {
        assert!(
            doc.contains(phase),
            "missing execution phase heading: {phase}"
        );
    }
}

#[test]
fn roadmap_doc_has_milestone_table_m0_to_m6() {
    let doc = load_doc();
    assert!(
        doc.contains("## 4. Milestone Definitions"),
        "missing milestone definitions section"
    );
    for milestone in ["M0", "M1", "M2", "M3", "M4", "M5", "M6"] {
        assert!(
            doc.contains(&format!("| {milestone} |")),
            "missing milestone row for {milestone}"
        );
    }
}

#[test]
fn roadmap_doc_has_decision_point_table() {
    let doc = load_doc();
    for milestone in ["| M2 |", "| M3 |", "| M4 |", "| M5 |"] {
        assert!(
            doc.contains(milestone),
            "missing milestone decision point row: {milestone}"
        );
    }
}

#[test]
fn roadmap_doc_declares_bv_triage_guidance() {
    let doc = load_doc();
    assert!(
        doc.contains("`bv --robot-triage`"),
        "roadmap must include bv triage guidance"
    );
    assert!(
        doc.contains("Track priorities:"),
        "roadmap must include track-priority ordering guidance"
    );
}
