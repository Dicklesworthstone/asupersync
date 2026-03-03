//! Contract tests for the database and messaging gap baseline (2oh2u.6.1).
//!
//! Validates document structure, gap coverage, and classification consistency.

#![allow(missing_docs)]

use std::collections::BTreeSet;
use std::path::Path;

fn load_baseline_doc() -> String {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/tokio_db_messaging_gap_baseline.md");
    std::fs::read_to_string(path).expect("baseline document must exist")
}

fn extract_gap_ids(doc: &str) -> BTreeSet<String> {
    let mut ids = BTreeSet::new();
    for line in doc.lines() {
        let trimmed = line.trim().trim_start_matches('|').trim();
        if let Some(id) = trimmed.split('|').next() {
            let id = id.trim();
            let prefixes = [
                "PG-G", "MY-G", "SQ-G", "RD-G", "NT-G", "KA-G", "POOL-G", "QA-G", "OBS-G",
            ];
            if prefixes.iter().any(|p| id.starts_with(p)) && id.len() >= 4 {
                ids.insert(id.to_string());
            }
        }
    }
    ids
}

#[test]
fn baseline_document_exists_and_is_nonempty() {
    let doc = load_baseline_doc();
    assert!(
        doc.len() > 2000,
        "baseline document should be substantial, got {} bytes",
        doc.len()
    );
}

#[test]
fn baseline_references_correct_bead() {
    let doc = load_baseline_doc();
    assert!(
        doc.contains("asupersync-2oh2u.6.1"),
        "document must reference bead 2oh2u.6.1"
    );
    assert!(doc.contains("[T6.1]"), "document must reference T6.1");
}

#[test]
fn baseline_covers_all_six_integration_domains() {
    let doc = load_baseline_doc();
    let domains = ["PostgreSQL", "MySQL", "SQLite", "Redis", "NATS", "Kafka"];
    for domain in &domains {
        assert!(doc.contains(domain), "baseline must cover domain: {domain}");
    }
}

#[test]
fn baseline_covers_connection_pooling() {
    let doc = load_baseline_doc();
    assert!(
        doc.contains("Connection Pooling") || doc.contains("POOL-G"),
        "baseline must cover connection pooling gaps"
    );
    assert!(
        doc.contains("GenericPool") || doc.contains("sync/pool.rs"),
        "baseline must reference the existing pool infrastructure"
    );
}

#[test]
fn baseline_has_gap_entries_for_all_domains() {
    let doc = load_baseline_doc();
    let ids = extract_gap_ids(&doc);

    let domain_prefixes = ["PG-G", "MY-G", "SQ-G", "RD-G", "NT-G", "KA-G"];
    for prefix in &domain_prefixes {
        let count = ids.iter().filter(|id| id.starts_with(prefix)).count();
        assert!(
            count >= 3,
            "domain {prefix} must have >= 3 gap entries, found {count}"
        );
    }
}

#[test]
fn baseline_has_pool_gap_entries() {
    let doc = load_baseline_doc();
    let ids = extract_gap_ids(&doc);
    let pool_count = ids.iter().filter(|id| id.starts_with("POOL-G")).count();
    assert!(
        pool_count >= 3,
        "must have >= 3 POOL gap entries, found {pool_count}"
    );
}

#[test]
fn baseline_classifies_gap_severity() {
    let doc = load_baseline_doc();
    for level in &["Critical", "High", "Medium", "Low"] {
        assert!(
            doc.contains(level),
            "baseline must use severity level: {level}"
        );
    }
}

#[test]
fn baseline_has_migration_blocker_section() {
    let doc = load_baseline_doc();
    assert!(
        doc.contains("Migration Blocker") || doc.contains("Hard Blocker"),
        "baseline must include migration blocker classification"
    );
}

#[test]
fn baseline_has_reliability_requirements() {
    let doc = load_baseline_doc();
    assert!(
        doc.contains("Reliability Requirements") || doc.contains("DR-01"),
        "baseline must include database reliability requirements"
    );
    assert!(
        doc.contains("MR-01") || doc.contains("Messaging Reliability"),
        "baseline must include messaging reliability requirements"
    );
}

#[test]
fn baseline_has_performance_targets() {
    let doc = load_baseline_doc();
    assert!(
        doc.contains("Performance") && doc.contains("Hard Ceiling"),
        "baseline must include performance targets with hard ceilings"
    );
    assert!(
        doc.contains("us") || doc.contains("ms"),
        "performance targets must include latency units"
    );
    assert!(
        doc.contains("msg/sec") || doc.contains("ops/sec"),
        "performance targets must include throughput units"
    );
}

#[test]
fn baseline_references_tokio_interop_conditional() {
    let doc = load_baseline_doc();
    assert!(
        doc.contains("G3") && doc.contains("Interop"),
        "baseline must reference G3 Tokio interop conditional eliminations"
    );
}

#[test]
fn baseline_has_execution_order() {
    let doc = load_baseline_doc();
    assert!(
        doc.contains("Execution Order") || doc.contains("Phase A"),
        "baseline must include recommended execution order"
    );
    // Should have at least 3 phases
    let phase_count = ["Phase A", "Phase B", "Phase C"]
        .iter()
        .filter(|p| doc.contains(**p))
        .count();
    assert!(
        phase_count >= 3,
        "execution order must have >= 3 phases, found {phase_count}"
    );
}

#[test]
fn baseline_gap_summary_table_has_all_columns() {
    let doc = load_baseline_doc();
    let summary_section = doc
        .split("Gap Summary Table")
        .nth(1)
        .expect("must have gap summary table section");

    assert!(
        summary_section.contains("Domain"),
        "summary must have Domain column"
    );
    assert!(
        summary_section.contains("Severity"),
        "summary must have Severity column"
    );
    assert!(
        summary_section.contains("Phase"),
        "summary must have Phase column"
    );
}

#[test]
fn baseline_total_gap_count_is_comprehensive() {
    let doc = load_baseline_doc();
    let ids = extract_gap_ids(&doc);
    assert!(
        ids.len() >= 40,
        "baseline must identify >= 40 gaps across all domains, found {}",
        ids.len()
    );
}

#[test]
fn baseline_references_upstream_dependencies() {
    let doc = load_baseline_doc();
    assert!(
        doc.contains("T1.3.c") || doc.contains("roadmap baseline"),
        "must reference T1.3.c (roadmap baseline) dependency"
    );
    assert!(
        doc.contains("T1.2.a") || doc.contains("functional contracts"),
        "must reference T1.2.a (functional contracts) dependency"
    );
}

#[test]
fn baseline_includes_cancel_correctness_status() {
    let doc = load_baseline_doc();
    let cancel_mentions = doc.matches("Cancel-Correctness").count()
        + doc.matches("cancel-correct").count()
        + doc.matches("Outcome<").count();
    assert!(
        cancel_mentions >= 3,
        "baseline must assess cancel-correctness for each domain, found {cancel_mentions} mentions"
    );
}

#[test]
fn baseline_has_per_domain_feature_tables() {
    let doc = load_baseline_doc();
    // Each of the 6 domains should have a feature/status table
    let table_markers = [
        "PostgreSQL (F18)",
        "MySQL (F18)",
        "SQLite (F18)",
        "Redis (F19)",
        "NATS",
        "Kafka (F19)",
    ];
    let count = table_markers.iter().filter(|m| doc.contains(**m)).count();
    assert!(
        count >= 5,
        "baseline must have per-domain feature tables for >= 5 domains, found {count}"
    );
}
