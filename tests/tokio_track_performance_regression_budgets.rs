//! Contract tests for track-level performance regression budgets policy (2oh2u.10.7).
//!
//! Enforces deterministic budget schema, alarm rules, artifact requirements,
//! runner command contract, and downstream bindings.

#![allow(missing_docs)]

use std::collections::BTreeSet;
use std::path::Path;

fn load_doc() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("docs/tokio_track_performance_regression_budgets.md");
    std::fs::read_to_string(path)
        .expect("track-level performance regression budgets document must exist")
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
        doc.len() > 3500,
        "document should be substantial, got {} bytes",
        doc.len()
    );
}

#[test]
fn doc_references_correct_bead_and_track() {
    let doc = load_doc();
    assert!(
        doc.contains("asupersync-2oh2u.10.7"),
        "document must reference bead 2oh2u.10.7"
    );
    assert!(doc.contains("[T8.7]"), "document must reference T8.7");
}

#[test]
fn doc_references_required_dependencies() {
    let doc = load_doc();
    for token in [
        "asupersync-2oh2u.10.3",
        "asupersync-2oh2u.10.4",
        "asupersync-2oh2u.10.5",
        "tokio_differential_behavior_suites.md",
        "tokio_ci_quality_gate_enforcement.md",
    ] {
        assert!(
            doc.contains(token),
            "document missing required dependency token: {token}"
        );
    }
}

#[test]
fn doc_defines_metric_schema_fields() {
    let doc = load_doc();
    for token in [
        "track_id",
        "suite_id",
        "scenario_id",
        "metric_id",
        "metric_kind",
        "baseline_value",
        "candidate_value",
        "regression_pct",
        "budget_id",
        "decision",
        "alarm_ids",
        "artifact_paths",
        "repro_command",
        "generated_at",
    ] {
        assert!(doc.contains(token), "missing metric schema token: {token}");
    }
}

#[test]
fn doc_defines_decision_states() {
    let doc = load_doc();
    for token in ["PASS", "WARN", "FAIL", "BLOCKED"] {
        assert!(doc.contains(token), "missing decision-state token: {token}");
    }
    assert!(
        doc.contains("`BLOCKED` is never equivalent to `PASS`"),
        "document must define strict BLOCKED semantics"
    );
}

#[test]
fn doc_has_required_budget_ids() {
    let doc = load_doc();
    let ids = extract_ids(&doc, "PB-");
    for token in [
        "PB-01", "PB-02", "PB-03", "PB-04", "PB-05", "PB-06", "PB-07", "PB-08", "PB-09", "PB-10",
        "PB-11", "PB-12", "PB-13", "PB-14",
    ] {
        assert!(ids.contains(token), "missing budget id token: {token}");
    }
}

#[test]
fn doc_has_required_alarm_ids() {
    let doc = load_doc();
    let ids = extract_ids(&doc, "AL-");
    for token in [
        "AL-01", "AL-02", "AL-03", "AL-04", "AL-05", "AL-06", "AL-07", "AL-08",
    ] {
        assert!(ids.contains(token), "missing alarm id token: {token}");
    }
}

#[test]
fn doc_covers_tracks_t2_to_t7_and_cross() {
    let doc = load_doc();
    for token in ["`T2`", "`T3`", "`T4`", "`T5`", "`T6`", "`T7`", "`Cross`"] {
        assert!(
            doc.contains(token),
            "document missing track coverage token: {token}"
        );
    }
}

#[test]
fn doc_defines_baseline_rules() {
    let doc = load_doc();
    let ids = extract_ids(&doc, "BG-");
    for token in ["BG-01", "BG-02", "BG-03", "BG-04", "BG-05"] {
        assert!(ids.contains(token), "missing baseline rule id: {token}");
    }
    assert!(
        doc.contains("stale_baseline"),
        "document must define stale baseline failure token"
    );
}

#[test]
fn doc_defines_required_artifacts() {
    let doc = load_doc();
    for token in [
        "tokio_track_performance_regression_manifest.json",
        "tokio_track_performance_regression_report.md",
        "tokio_track_performance_regression_alarms.json",
        "tokio_track_performance_regression_repro_commands.txt",
    ] {
        assert!(
            doc.contains(token),
            "missing required artifact token: {token}"
        );
    }
}

#[test]
fn doc_requires_rch_exec_for_heavy_checks() {
    let doc = load_doc();
    assert!(
        doc.contains("rch exec --"),
        "document must require rch exec for heavy commands"
    );

    for token in [
        "rch exec -- cargo check --all-targets",
        "rch exec -- cargo clippy --all-targets -- -D warnings",
        "rch exec -- cargo fmt --check",
        "rch exec -- cargo test --test tokio_differential_behavior_suites -- --nocapture",
        "rch exec -- cargo test --test tokio_ci_quality_gate_enforcement -- --nocapture",
        "rch exec -- cargo test --test tokio_track_performance_regression_budgets -- --nocapture",
    ] {
        assert!(doc.contains(token), "missing runner command token: {token}");
    }
}

#[test]
fn doc_defines_gate_integration_tokens() {
    let doc = load_doc();
    for token in ["QG-06", "QG-07", "QG-08"] {
        assert!(
            doc.contains(token),
            "missing gate integration token: {token}"
        );
    }
}

#[test]
fn doc_binds_downstream_beads() {
    let doc = load_doc();
    for token in [
        "asupersync-2oh2u.10.9",
        "asupersync-2oh2u.10.12",
        "asupersync-2oh2u.11.9",
    ] {
        assert!(
            doc.contains(token),
            "missing downstream binding token: {token}"
        );
    }
}
