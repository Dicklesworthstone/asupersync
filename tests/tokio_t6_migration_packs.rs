//! Contract tests for T6.11 migration packs (asupersync-2oh2u.6.11).
//!
//! Validates documentation completeness, before/after pattern coverage,
//! operational caveats, rollback paths, and JSON artifact consistency.

#![allow(missing_docs)]

use serde_json::Value;
use std::collections::BTreeSet;
use std::path::Path;

fn load_doc() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/tokio_t6_migration_packs.md");
    std::fs::read_to_string(path).expect("migration packs document must exist")
}

fn load_json() -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/tokio_t6_migration_packs.json");
    let raw = std::fs::read_to_string(path).expect("migration packs JSON must exist");
    serde_json::from_str(&raw).expect("migration packs JSON must parse")
}

// ── Document infrastructure ──────────────────────────────────────────

#[test]
fn doc_exists_and_is_substantial() {
    let doc = load_doc();
    assert!(
        doc.len() > 5000,
        "migration packs document should be substantial, got {} bytes",
        doc.len()
    );
}

#[test]
fn doc_references_correct_bead() {
    let doc = load_doc();
    assert!(
        doc.contains("asupersync-2oh2u.6.11"),
        "document must reference bead asupersync-2oh2u.6.11"
    );
}

#[test]
fn doc_references_track_t6() {
    let doc = load_doc();
    assert!(
        doc.contains("[T6.11]"),
        "document must reference track T6.11"
    );
}

#[test]
fn doc_has_required_sections() {
    let doc = load_doc();
    let required_sections = [
        "Prerequisites",
        "PostgreSQL Migration",
        "MySQL Migration",
        "SQLite Migration",
        "Redis Migration",
        "NATS Migration",
        "JetStream Migration",
        "Kafka Migration",
        "Connection Pool Migration",
        "Retry Policy Migration",
        "Operational Caveats",
        "Rollback Paths",
        "Troubleshooting Decision Points",
        "Evidence and Conformance Links",
    ];
    for section in required_sections {
        assert!(
            doc.contains(section),
            "document missing required section: {section}"
        );
    }
}

// ── Before/After pattern coverage ────────────────────────────────────

#[test]
fn doc_has_before_after_patterns_for_all_backends() {
    let doc = load_doc();
    let backends = [
        ("tokio-postgres", "Before (tokio-postgres)"),
        ("sqlx", "Before (sqlx)"),
        ("mysql_async", "Before (mysql_async)"),
        ("rusqlite", "Before (rusqlite)"),
        ("redis", "Before (redis)"),
        ("async-nats", "Before (async-nats)"),
        ("rdkafka", "Before (rdkafka)"),
    ];
    for (backend, pattern) in backends {
        assert!(
            doc.contains(pattern),
            "document missing Before pattern for {backend} (expected: '{pattern}')"
        );
    }

    // Check for After patterns
    let after_count = doc.matches("**After").count() + doc.matches("**After (Asupersync)").count();
    assert!(
        after_count >= 7,
        "document should have at least 7 After patterns, found {after_count}"
    );
}

#[test]
fn doc_covers_connection_patterns() {
    let doc = load_doc();
    let connection_tokens = [
        "PgConnection::connect",
        "MySqlConnection::connect",
        "SqliteConnection::open",
        "RedisClient::connect",
        "NatsClient::connect",
        "JetStreamContext::new",
        "KafkaProducer::new",
    ];
    for token in connection_tokens {
        assert!(
            doc.contains(token),
            "document missing connection pattern: {token}"
        );
    }
}

#[test]
fn doc_covers_query_patterns() {
    let doc = load_doc();
    let query_tokens = [
        "conn.query(",
        "conn.execute(",
        "conn.query_params(",
        "conn.query_one(",
        "conn.prepare(",
    ];
    for token in query_tokens {
        assert!(
            doc.contains(token),
            "document missing query pattern: {token}"
        );
    }
}

#[test]
fn doc_covers_transaction_patterns() {
    let doc = load_doc();
    let tx_tokens = [
        "with_pg_transaction",
        "with_mysql_transaction",
        "with_sqlite_transaction",
        "with_pg_transaction_retry",
        "with_mysql_transaction_retry",
        "with_sqlite_transaction_retry",
    ];
    for token in tx_tokens {
        assert!(
            doc.contains(token),
            "document missing transaction pattern: {token}"
        );
    }
}

#[test]
fn doc_covers_error_classification() {
    let doc = load_doc();
    let error_tokens = [
        "is_transient()",
        "is_retryable()",
        "is_connection_error()",
        "is_unique_violation()",
        "is_deadlock()",
        "is_serialization_failure()",
    ];
    for token in error_tokens {
        assert!(
            doc.contains(token),
            "document missing error classification method: {token}"
        );
    }
}

#[test]
fn doc_covers_pool_config_equivalents() {
    let doc = load_doc();
    let pool_tokens = [
        "with_max_size",
        "min_idle",
        "validate_on_checkout",
        "idle_timeout",
        "max_lifetime",
        "connection_timeout",
        "ConnectionManager",
        "DbPool",
        "DbPoolConfig",
    ];
    for token in pool_tokens {
        assert!(
            doc.contains(token),
            "document missing pool config pattern: {token}"
        );
    }
}

// ── Operational caveats ──────────────────────────────────────────────

#[test]
fn doc_has_cancellation_caveat() {
    let doc = load_doc();
    assert!(
        doc.contains("Cancellation Model") || doc.contains("cancellation"),
        "document must discuss cancellation model differences"
    );
    assert!(
        doc.contains("&Cx"),
        "document must mention the Cx cancellation context"
    );
}

#[test]
fn doc_has_sync_pool_caveat() {
    let doc = load_doc();
    assert!(
        doc.contains("Synchronous Pool") || doc.contains("synchronous"),
        "document must discuss synchronous pool caveat"
    );
}

#[test]
fn doc_has_phase0_stub_caveat() {
    let doc = load_doc();
    assert!(
        doc.contains("Phase 0") || doc.contains("stub"),
        "document must discuss Phase 0 stub limitations"
    );
}

#[test]
fn doc_has_type_system_differences() {
    let doc = load_doc();
    assert!(
        doc.contains("derive(FromRow)") || doc.contains("FromRow"),
        "document must discuss lack of derive(FromRow)"
    );
    assert!(
        doc.contains("compile-time") || doc.contains("query!()"),
        "document must discuss lack of compile-time query checking"
    );
}

// ── Rollback paths ───────────────────────────────────────────────────

#[test]
fn doc_has_rollback_checklist() {
    let doc = load_doc();
    assert!(
        doc.contains("Rollback Checklist") || doc.contains("rollback"),
        "document must include rollback checklist"
    );
}

#[test]
fn doc_mentions_compat_crate() {
    let doc = load_doc();
    assert!(
        doc.contains("asupersync-tokio-compat"),
        "document must mention the compatibility crate for incremental migration"
    );
}

#[test]
fn doc_has_dual_stack_testing() {
    let doc = load_doc();
    assert!(
        doc.contains("Dual-Stack") || doc.contains("dual-stack") || doc.contains("cfg(feature"),
        "document must discuss dual-stack testing strategy"
    );
}

// ── Troubleshooting ──────────────────────────────────────────────────

#[test]
fn doc_has_troubleshooting_for_common_issues() {
    let doc = load_doc();
    let issues = [
        "Connection Failures",
        "Pool Exhaustion",
        "Transaction Deadlocks",
        "SQLite Busy",
    ];
    for issue in issues {
        assert!(
            doc.contains(issue),
            "document missing troubleshooting section: {issue}"
        );
    }
}

// ── Evidence links ───────────────────────────────────────────────────

#[test]
fn doc_links_to_evidence() {
    let doc = load_doc();
    let evidence_tokens = [
        "tests/e2e_t6_data_path.rs",
        "src/database/postgres.rs",
        "src/database/mysql.rs",
        "src/database/sqlite.rs",
        "src/database/pool.rs",
        "src/database/transaction.rs",
    ];
    for token in evidence_tokens {
        assert!(
            doc.contains(token),
            "document missing evidence link: {token}"
        );
    }
}

// ── JSON artifact validation ─────────────────────────────────────────

#[test]
fn json_artifact_valid_and_complete() {
    let json = load_json();

    assert_eq!(
        json["schema_version"].as_str().unwrap(),
        "1.0.0",
        "JSON schema_version must be 1.0.0"
    );
    assert_eq!(
        json["bead_id"].as_str().unwrap(),
        "asupersync-2oh2u.6.11",
        "JSON bead_id must match"
    );
    assert_eq!(
        json["track"].as_str().unwrap(),
        "T6",
        "JSON track must be T6"
    );
}

#[test]
fn json_has_all_migration_packs() {
    let json = load_json();
    let packs = json["migration_packs"]
        .as_array()
        .expect("migration_packs must be an array");

    assert!(
        packs.len() >= 10,
        "should have at least 10 migration packs, found {}",
        packs.len()
    );

    // Check all packs have required fields
    for pack in packs {
        assert!(
            pack["id"].as_str().is_some(),
            "each migration pack must have an id"
        );
        assert!(
            pack["source_crate"].as_str().is_some(),
            "each migration pack must have source_crate"
        );
        assert!(
            pack["target_module"].as_str().is_some(),
            "each migration pack must have target_module"
        );
        assert!(
            pack["categories"].as_array().is_some(),
            "each migration pack must have categories array"
        );
        assert!(
            pack["status"].as_str() == Some("complete"),
            "each migration pack must have status: complete"
        );
    }
}

#[test]
fn json_covers_all_source_crates() {
    let json = load_json();
    let packs = json["migration_packs"]
        .as_array()
        .expect("migration_packs must be an array");

    let source_crates: BTreeSet<String> = packs
        .iter()
        .filter_map(|p| p["source_crate"].as_str().map(String::from))
        .collect();

    let required_crates = [
        "tokio-postgres",
        "mysql_async",
        "redis",
        "async-nats",
        "rdkafka",
    ];

    for crate_name in required_crates {
        assert!(
            source_crates.iter().any(|s| s.contains(crate_name)),
            "JSON missing migration pack for source crate: {crate_name}"
        );
    }
}

#[test]
fn json_has_cross_cutting_concerns() {
    let json = load_json();
    let concerns = json["cross_cutting_concerns"]
        .as_object()
        .expect("cross_cutting_concerns must be an object");

    for key in ["cancellation", "error_classification", "connection_pooling"] {
        assert!(
            concerns.contains_key(key),
            "cross_cutting_concerns missing: {key}"
        );
    }
}

#[test]
fn json_has_operational_caveats() {
    let json = load_json();
    let caveats = json["operational_caveats"]
        .as_array()
        .expect("operational_caveats must be an array");

    assert!(
        caveats.len() >= 3,
        "should have at least 3 operational caveats, found {}",
        caveats.len()
    );

    for caveat in caveats {
        assert!(
            caveat["id"].as_str().is_some(),
            "each caveat must have an id"
        );
        assert!(
            caveat["title"].as_str().is_some(),
            "each caveat must have a title"
        );
        assert!(
            caveat["severity"].as_str().is_some(),
            "each caveat must have a severity"
        );
        assert!(
            caveat["workaround"].as_str().is_some(),
            "each caveat must have a workaround"
        );
    }
}

#[test]
fn json_has_rollback_paths() {
    let json = load_json();
    let rollback = json["rollback_paths"]
        .as_object()
        .expect("rollback_paths must be an object");

    assert!(
        rollback.contains_key("compatibility_crate"),
        "rollback_paths must include compatibility_crate"
    );
    assert!(
        rollback.contains_key("rollback_steps"),
        "rollback_paths must include rollback_steps"
    );

    let steps = rollback["rollback_steps"]
        .as_array()
        .expect("rollback_steps must be an array");
    assert!(
        steps.len() >= 3,
        "should have at least 3 rollback steps, found {}",
        steps.len()
    );
}

#[test]
fn json_has_evidence_links() {
    let json = load_json();
    let evidence = json["evidence_links"]
        .as_object()
        .expect("evidence_links must be an object");

    let required_keys = [
        "e2e_tests",
        "postgres_source",
        "mysql_source",
        "sqlite_source",
        "pool_source",
        "redis_source",
        "nats_source",
        "jetstream_source",
        "kafka_source",
    ];

    for key in required_keys {
        assert!(evidence.contains_key(key), "evidence_links missing: {key}");
    }
}

#[test]
fn json_has_dependency_tracking() {
    let json = load_json();
    let deps = json["dependencies"]
        .as_object()
        .expect("dependencies must be an object");

    assert!(
        deps.contains_key("blocked_by"),
        "dependencies must include blocked_by"
    );
    assert!(
        deps.contains_key("blocks"),
        "dependencies must include blocks"
    );

    let blocked_by = deps["blocked_by"]
        .as_array()
        .expect("blocked_by must be an array");
    assert!(
        blocked_by
            .iter()
            .any(|d| { d["bead"].as_str() == Some("asupersync-2oh2u.6.12") }),
        "blocked_by must include T6.12"
    );
    assert!(
        blocked_by
            .iter()
            .any(|d| { d["bead"].as_str() == Some("asupersync-2oh2u.6.10") }),
        "blocked_by must include T6.10"
    );
}

#[test]
fn json_summary_counts_are_consistent() {
    let json = load_json();
    let summary = &json["summary"];

    let total_packs = summary["total_migration_packs"]
        .as_u64()
        .expect("total_migration_packs must be a number");
    let packs = json["migration_packs"]
        .as_array()
        .expect("migration_packs must be an array");

    assert_eq!(
        total_packs as usize,
        packs.len(),
        "summary total_migration_packs must match actual pack count"
    );

    let total_mappings = summary["total_api_mappings"]
        .as_u64()
        .expect("total_api_mappings must be a number");
    let computed_mappings: u64 = packs
        .iter()
        .filter_map(|p| p["api_mappings"].as_u64())
        .sum();
    assert_eq!(
        total_mappings, computed_mappings,
        "summary total_api_mappings must match sum of individual packs"
    );
}

// ── Source file existence ────────────────────────────────────────────

#[test]
fn referenced_source_files_exist() {
    let sources = [
        "src/database/mod.rs",
        "src/database/pool.rs",
        "src/database/postgres.rs",
        "src/database/mysql.rs",
        "src/database/sqlite.rs",
        "src/database/transaction.rs",
        "src/messaging/mod.rs",
        "src/messaging/redis.rs",
        "src/messaging/nats.rs",
        "src/messaging/jetstream.rs",
        "src/messaging/kafka.rs",
    ];

    for source in sources {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(source);
        assert!(path.exists(), "referenced source file must exist: {source}");
    }
}

#[test]
fn e2e_test_file_exists() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/e2e_t6_data_path.rs");
    assert!(
        path.exists(),
        "e2e_t6_data_path.rs must exist (T6.13 dependency)"
    );
}

// ── Markdown/JSON consistency ────────────────────────────────────────

#[test]
fn doc_and_json_reference_same_bead() {
    let doc = load_doc();
    let json = load_json();

    let json_bead = json["bead_id"].as_str().unwrap();
    assert!(
        doc.contains(json_bead),
        "markdown document must reference the same bead as JSON: {json_bead}"
    );
}

#[test]
fn all_json_source_crates_mentioned_in_doc() {
    let doc = load_doc();
    let json = load_json();

    let crates_covered = json["summary"]["source_crates_covered"]
        .as_array()
        .expect("source_crates_covered must be an array");

    for crate_val in crates_covered {
        let crate_name = crate_val.as_str().unwrap();
        // Extract base crate name (before parenthetical)
        let base = crate_name.split(' ').next().unwrap();
        assert!(
            doc.contains(base),
            "markdown document must mention source crate: {crate_name} (looking for '{base}')"
        );
    }
}
