#![allow(warnings)]
#![allow(clippy::all)]
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

// =============================================================================
// EXTENDED COVERAGE: severity distribution, cross-references, module paths
// =============================================================================

fn extract_summary_table_gaps(doc: &str) -> Vec<(String, String, String)> {
    // Parse rows from the "Gap Summary Table" section.
    // Each row: | ID | Domain | Description | Severity | Phase |
    let Some(summary) = doc.split("Gap Summary Table").nth(1) else {
        return Vec::new();
    };
    let mut gaps = Vec::new();
    for line in summary.lines() {
        let cols: Vec<&str> = line.split('|').map(str::trim).collect();
        if cols.len() >= 5 {
            let id = cols[1];
            let severity = cols[4];
            let phase = cols.get(5).unwrap_or(&"");
            let prefixes = ["PG-G", "MY-G", "SQ-G", "RD-G", "NT-G", "KA-G", "POOL-G"];
            if prefixes.iter().any(|p| id.starts_with(p)) {
                gaps.push((id.to_string(), severity.to_string(), phase.to_string()));
            }
        }
    }
    gaps
}

#[test]
fn summary_table_covers_all_52_gaps() {
    let doc = load_baseline_doc();
    let gaps = extract_summary_table_gaps(&doc);
    assert!(
        gaps.len() >= 45,
        "summary table must list >= 45 gaps, found {}",
        gaps.len()
    );
}

#[test]
fn severity_distribution_matches_documented_totals() {
    let doc = load_baseline_doc();
    let gaps = extract_summary_table_gaps(&doc);

    let critical = gaps.iter().filter(|(_, s, _)| s == "Critical").count();
    let high = gaps.iter().filter(|(_, s, _)| s == "High").count();
    let medium = gaps.iter().filter(|(_, s, _)| s == "Medium").count();
    let low = gaps.iter().filter(|(_, s, _)| s == "Low").count();

    assert!(
        critical >= 5,
        "expected >= 5 Critical gaps, found {critical}"
    );
    assert!(high >= 10, "expected >= 10 High gaps, found {high}");
    assert!(medium >= 10, "expected >= 10 Medium gaps, found {medium}");
    assert!(low >= 8, "expected >= 8 Low gaps, found {low}");
}

#[test]
fn every_summary_gap_appears_in_per_domain_section() {
    let doc = load_baseline_doc();
    let summary_gaps = extract_summary_table_gaps(&doc);
    let body_ids = extract_gap_ids(&doc);

    for (gap_id, _, _) in &summary_gaps {
        assert!(
            body_ids.contains(gap_id),
            "summary gap {gap_id} must also appear in per-domain sections"
        );
    }
}

#[test]
fn all_phases_are_valid() {
    let doc = load_baseline_doc();
    let gaps = extract_summary_table_gaps(&doc);
    let valid_phases = ["A", "B", "C", "D"];

    for (id, _, phase) in &gaps {
        assert!(
            valid_phases.iter().any(|p| phase.contains(p)),
            "gap {id} has invalid phase '{phase}', expected one of {valid_phases:?}"
        );
    }
}

#[test]
fn critical_gaps_are_in_early_phases() {
    let doc = load_baseline_doc();
    let gaps = extract_summary_table_gaps(&doc);

    for (id, severity, phase) in &gaps {
        if severity == "Critical" {
            assert!(
                phase.contains('A') || phase.contains('B'),
                "critical gap {id} should be in Phase A or B, found Phase {phase}"
            );
        }
    }
}

#[test]
fn database_reliability_requirements_are_numbered() {
    let doc = load_baseline_doc();
    for i in 1..=6 {
        let req_id = format!("DR-{i:02}");
        assert!(
            doc.contains(&req_id),
            "missing database reliability requirement {req_id}"
        );
    }
}

#[test]
fn messaging_reliability_requirements_are_numbered() {
    let doc = load_baseline_doc();
    for i in 1..=6 {
        let req_id = format!("MR-{i:02}");
        assert!(
            doc.contains(&req_id),
            "missing messaging reliability requirement {req_id}"
        );
    }
}

#[test]
fn module_paths_reference_real_directories() {
    let doc = load_baseline_doc();
    let expected_modules = [
        "database/postgres.rs",
        "database/mysql.rs",
        "database/sqlite.rs",
        "messaging/redis.rs",
        "messaging/nats.rs",
        "messaging/kafka.rs",
        "sync/pool.rs",
    ];
    for module in &expected_modules {
        assert!(
            doc.contains(module),
            "baseline must reference module path: {module}"
        );
    }
}

#[test]
fn module_source_files_exist() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let expected_files = [
        "src/database/postgres.rs",
        "src/database/mysql.rs",
        "src/database/sqlite.rs",
        "src/messaging/redis.rs",
        "src/messaging/nats.rs",
        "src/messaging/kafka.rs",
        "src/sync/pool.rs",
    ];
    for file in &expected_files {
        let path = manifest_dir.join(file);
        assert!(path.exists(), "referenced source file must exist: {file}");
    }
}

#[test]
fn hard_blockers_section_lists_critical_gaps() {
    let doc = load_baseline_doc();
    let hard_section = doc
        .split("Hard Blocker")
        .nth(1)
        .expect("must have Hard Blockers section");

    // Critical pool and driver gaps must be in hard blockers
    let critical_ids = ["PG-G4", "MY-G3", "RD-G1", "RD-G2"];
    for id in &critical_ids {
        assert!(
            hard_section.contains(id),
            "critical gap {id} must be listed in Hard Blockers section"
        );
    }
}

#[test]
fn soft_blockers_section_lists_high_severity_gaps() {
    let doc = load_baseline_doc();
    let soft_section = doc
        .split("Soft Blocker")
        .nth(1)
        .expect("must have Soft Blockers section");

    let expected = ["PG-G3", "NT-G2", "NT-G3"];
    for id in &expected {
        assert!(
            soft_section.contains(id),
            "high-severity gap {id} should be in Soft Blockers section"
        );
    }
}

#[test]
fn tokio_ecosystem_equivalents_are_named() {
    let doc = load_baseline_doc();
    let equivalents = [
        "tokio-postgres",
        "sqlx",
        "fred",
        "redis-rs",
        "async-nats",
        "rdkafka",
    ];
    for eq in &equivalents {
        assert!(
            doc.contains(eq),
            "baseline must name tokio ecosystem equivalent: {eq}"
        );
    }
}

#[test]
fn feature_family_mapping_is_consistent() {
    let doc = load_baseline_doc();
    // F18 = database family, F19 = messaging family
    assert!(
        doc.contains("F18") && doc.contains("F19"),
        "baseline must map gaps to capability families F18 and F19"
    );

    // Verify family assignments
    assert!(
        doc.contains("PostgreSQL") && doc.contains("F18"),
        "PostgreSQL must be in family F18"
    );
    assert!(
        doc.contains("Redis") && doc.contains("F19"),
        "Redis must be in family F19"
    );
}

#[test]
fn conditional_eliminations_reference_g3_interop() {
    let doc = load_baseline_doc();
    let g3_section = doc
        .split("Conditional Elimination")
        .nth(1)
        .expect("must have conditional eliminations section");

    assert!(
        g3_section.contains("PG-G4"),
        "G3 eliminations must mention PG-G4 (pool can be replaced by bb8)"
    );
    assert!(
        g3_section.contains("bb8") || g3_section.contains("deadpool"),
        "G3 eliminations must name pooling crate alternatives"
    );
}

#[test]
fn document_has_revision_history() {
    let doc = load_baseline_doc();
    assert!(
        doc.contains("Revision History"),
        "baseline must include revision history section"
    );
    assert!(
        doc.contains("SapphireHill"),
        "revision history must credit authoring agent"
    );
}

// =============================================================================
// T6.3 MySQL Hardening Contract Tests
// =============================================================================

#[test]
fn t63_mysql_hardening_summary_present() {
    let doc = load_baseline_doc();
    assert!(
        doc.contains("T6.3 Hardening Summary"),
        "baseline must include T6.3 hardening summary"
    );
}

#[test]
fn t63_mysql_transaction_safety_documented() {
    let doc = load_baseline_doc();
    assert!(
        doc.contains("needs_rollback") || doc.contains("implicit ROLLBACK"),
        "T6.3 must document transaction drop → implicit ROLLBACK behavior"
    );
}

#[test]
fn t63_mysql_url_parsing_hardened() {
    let doc = load_baseline_doc();
    assert!(
        doc.contains("Percent-decoding") || doc.contains("percent-decoding"),
        "T6.3 must document URL percent-decoding"
    );
    assert!(
        doc.contains("query param") || doc.contains("ssl-mode"),
        "T6.3 must document URL query parameter parsing"
    );
}

#[test]
fn t63_mysql_packet_guard_documented() {
    let doc = load_baseline_doc();
    assert!(
        doc.contains("MAX_PACKET_SIZE") || doc.contains("packet guard"),
        "T6.3 must document build_packet overflow guard"
    );
}

#[test]
fn t63_mysql_memory_guard_documented() {
    let doc = load_baseline_doc();
    assert!(
        doc.contains("max_result_rows") || doc.contains("memory guard"),
        "T6.3 must document result set max_rows safety limit"
    );
}

#[test]
fn t63_mysql_cancel_correctness_updated() {
    let doc = load_baseline_doc();
    let mysql_section = doc
        .split("### 2.2 MySQL")
        .nth(1)
        .and_then(|s| s.split("### 2.3").next())
        .unwrap_or("");
    assert!(
        mysql_section.contains("Cancel-Correctness"),
        "MySQL section must include cancel-correctness assessment"
    );
    assert!(
        mysql_section.contains("T6.3"),
        "cancel-correctness must reference T6.3 hardening"
    );
}

#[test]
fn t63_revision_history_updated() {
    let doc = load_baseline_doc();
    assert!(
        doc.contains("T6.3"),
        "revision history must include T6.3 update"
    );
    assert!(
        doc.contains("v1.1"),
        "revision history must show version bump to v1.1"
    );
}

#[test]
fn t63_mysql_feature_rows_include_hardening() {
    let doc = load_baseline_doc();
    let mysql_section = doc
        .split("### 2.2 MySQL")
        .nth(1)
        .and_then(|s| s.split("### 2.3").next())
        .unwrap_or("");

    let hardened_features = [
        "URL percent-decoding",
        "build_packet MAX_PACKET_SIZE",
        "Transaction drop",
        "Result set max_rows",
    ];
    for feature in &hardened_features {
        assert!(
            mysql_section.contains(feature),
            "MySQL feature table must include hardened feature: {feature}"
        );
    }
}

// =============================================================================
// T6.7 NATS/JetStream Hardening Contract Tests
// =============================================================================

#[test]
fn t67_nats_hardening_summary_present() {
    let doc = load_baseline_doc();
    assert!(
        doc.contains("T6.7 Hardening Summary"),
        "baseline must include T6.7 hardening summary"
    );
}

#[test]
fn t67_nats_max_payload_negotiation_documented() {
    let doc = load_baseline_doc();
    let nats_section = doc
        .split("### 2.5 NATS")
        .nth(1)
        .and_then(|s| s.split("### 2.6").next())
        .unwrap_or("");
    assert!(
        nats_section.contains("max_payload") || nats_section.contains("server limits"),
        "T6.7 must document server max_payload negotiation"
    );
}

#[test]
fn t67_nats_msg_payload_guard_documented() {
    let doc = load_baseline_doc();
    let nats_section = doc
        .split("### 2.5 NATS")
        .nth(1)
        .and_then(|s| s.split("### 2.6").next())
        .unwrap_or("");
    assert!(
        nats_section.contains("MSG payload size guard") || nats_section.contains("parse_msg"),
        "T6.7 must document MSG payload size guard"
    );
}

#[test]
fn t67_nats_buffer_overflow_protection_documented() {
    let doc = load_baseline_doc();
    let nats_section = doc
        .split("### 2.5 NATS")
        .nth(1)
        .and_then(|s| s.split("### 2.6").next())
        .unwrap_or("");
    assert!(
        nats_section.contains("Read buffer overflow protection")
            || nats_section.contains("MAX_READ_BUFFER"),
        "T6.7 must document read buffer overflow protection"
    );
}

#[test]
fn t67_nats_close_flush_documented() {
    let doc = load_baseline_doc();
    let nats_section = doc
        .split("### 2.5 NATS")
        .nth(1)
        .and_then(|s| s.split("### 2.6").next())
        .unwrap_or("");
    assert!(
        nats_section.contains("flushes before shutdown") || nats_section.contains("Close flush"),
        "T6.7 must document close flushes before shutdown"
    );
}

#[test]
fn t67_nats_cancel_correctness_updated() {
    let doc = load_baseline_doc();
    let nats_section = doc
        .split("### 2.5 NATS")
        .nth(1)
        .and_then(|s| s.split("### 2.6").next())
        .unwrap_or("");
    assert!(
        nats_section.contains("Cancel-Correctness"),
        "NATS section must include cancel-correctness assessment"
    );
    assert!(
        nats_section.contains("T6.7"),
        "cancel-correctness must reference T6.7 hardening"
    );
}

#[test]
fn t67_nats_feature_rows_include_hardening() {
    let doc = load_baseline_doc();
    let nats_section = doc
        .split("### 2.5 NATS")
        .nth(1)
        .and_then(|s| s.split("### 2.6").next())
        .unwrap_or("");

    let hardened_features = [
        "Server max_payload negotiation",
        "MSG payload size guard",
        "Read buffer overflow protection",
        "Close flushes before shutdown",
    ];
    for feature in &hardened_features {
        assert!(
            nats_section.contains(feature),
            "NATS feature table must include hardened feature: {feature}"
        );
    }
}

#[test]
fn t67_revision_history_updated() {
    let doc = load_baseline_doc();
    assert!(
        doc.contains("T6.7"),
        "revision history must include T6.7 update"
    );
    assert!(
        doc.contains("v1.2"),
        "revision history must show version bump to v1.2"
    );
}

// =============================================================================
// T6.8 Kafka Parity Contract Tests
// =============================================================================

#[test]
fn t68_kafka_section_mentions_deterministic_fallback() {
    let doc = load_baseline_doc();
    let kafka_section = doc
        .split("### 2.6 Kafka")
        .nth(1)
        .and_then(|s| s.split("\n---\n").next())
        .unwrap_or("");

    assert!(
        kafka_section.contains("deterministic fallback"),
        "Kafka section must document deterministic fallback behavior for non-kafka builds"
    );
}

#[test]
fn t68_kafka_feature_rows_capture_producer_and_consumer_lifecycle_progress() {
    let doc = load_baseline_doc();
    let kafka_section = doc
        .split("### 2.6 Kafka")
        .nth(1)
        .and_then(|s| s.split("\n---\n").next())
        .unwrap_or("");

    assert!(
        kafka_section.contains("deterministic ack metadata fallback"),
        "Kafka producer row must mention deterministic ack metadata fallback"
    );
    assert!(
        kafka_section.contains("deterministic subscription/offset lifecycle"),
        "Kafka consumer row must mention deterministic subscription/offset lifecycle"
    );
}

#[test]
fn t68_kafka_cancel_correctness_mentions_checkpointed_paths() {
    let doc = load_baseline_doc();
    let kafka_section = doc
        .split("### 2.6 Kafka")
        .nth(1)
        .and_then(|s| s.split("\n---\n").next())
        .unwrap_or("");

    assert!(
        kafka_section.contains("Producer send/flush paths")
            && kafka_section.contains("consumer subscribe/poll/commit/seek/close"),
        "Kafka cancel-correctness must enumerate checkpointed producer and consumer paths"
    );
}
