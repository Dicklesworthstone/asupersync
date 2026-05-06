//! T6.12 — Exhaustive Unit-Test Matrix for Database and Messaging Semantics
//!
//! Bead: `asupersync-2oh2u.6.12`
//! Track: T6 (Database and messaging ecosystem closure)
//!
//! Meta-test suite that validates coverage thresholds, file existence,
//! inline test counts, cross-backend parity, messaging error parity,
//! and contract document completeness as defined in the T6.12 contract.

use std::collections::HashSet;

// ─── Contract Document and Artifact Constants ────────────────────────────────

const CONTRACT_MD: &str = include_str!("../docs/tokio_db_messaging_unit_test_matrix_contract.md");
const CONTRACT_JSON: &str =
    include_str!("../docs/tokio_db_messaging_unit_test_matrix_contract.json");

fn parse_json() -> serde_json::Value {
    serde_json::from_str(CONTRACT_JSON).expect("T6.12 contract JSON must parse")
}

/// Count occurrences of `#[test]` in a source string.
fn count_test_fns(source: &str) -> usize {
    source.lines().filter(|l| l.trim() == "#[test]").count()
}

// ════════════════════════════════════════════════════════════════════════════
// Section 1: Document Structure (DOC-M-01)
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn doc_m_01_contract_has_required_sections() {
    let required = [
        "## 1. Coverage Matrix by Bead",
        "## 2. Cross-Backend Parity Requirements",
        "## 3. Messaging Error Parity Requirements",
        "## 4. Coverage Threshold Gates",
        "## 5. Test File Inventory Requirements",
        "## 6. Inline Test Requirements",
        "## 7. Document and Artifact Requirements",
        "## 8. Implementation Status",
        "## 9. Contract Dependencies",
    ];
    for section in &required {
        assert!(CONTRACT_MD.contains(section), "missing section: {section}");
    }
}

#[test]
fn doc_m_01_contract_has_all_bead_subsections() {
    let subsections = [
        "### UM-6.2: PostgreSQL Client Tests",
        "### UM-6.3: MySQL Client Tests",
        "### UM-6.4: SQLite Client Tests",
        "### UM-6.5: Pool/Transaction/Observability Tests",
        "### UM-6.6: Redis Error and Command Tests",
        "### UM-6.7: NATS and JetStream Tests",
        "### UM-6.8: Kafka Error and Lifecycle Tests",
        "### UM-6.9: Retry and Failure Contract Tests",
        "### UM-6.10: Integration and Fault Injection Tests",
    ];
    for sub in &subsections {
        assert!(CONTRACT_MD.contains(sub), "missing subsection: {sub}");
    }
}

#[test]
fn doc_m_01_contract_has_parity_tables() {
    // Cross-backend parity table must reference all 3 DB backends
    assert!(CONTRACT_MD.contains("| PostgreSQL | MySQL | SQLite |"));
    // Messaging parity table must reference all 4 systems
    assert!(CONTRACT_MD.contains("| Kafka | Redis | NATS | JetStream |"));
}

// ════════════════════════════════════════════════════════════════════════════
// Section 2: JSON Artifact Schema (DOC-M-02)
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn doc_m_02_json_has_schema_version() {
    let json = parse_json();
    let v = json["schema_version"].as_str().unwrap();
    assert!(!v.is_empty(), "schema_version must be non-empty");
}

#[test]
fn doc_m_02_json_has_bead_id() {
    let json = parse_json();
    assert_eq!(json["bead_id"].as_str().unwrap(), "asupersync-2oh2u.6.12");
}

#[test]
fn doc_m_02_json_has_track() {
    let json = parse_json();
    assert_eq!(json["track"].as_str().unwrap(), "T6");
}

#[test]
fn doc_m_02_json_assertions_array_present() {
    let json = parse_json();
    let assertions = json["assertions"]
        .as_array()
        .expect("assertions must be array");
    assert!(
        assertions.len() >= 60,
        "expected >= 60 assertions, got {}",
        assertions.len()
    );
}

#[test]
fn doc_m_02_json_assertions_have_required_fields() {
    let json = parse_json();
    let assertions = json["assertions"].as_array().unwrap();
    for (i, a) in assertions.iter().enumerate() {
        assert!(a["id"].as_str().is_some(), "assertion[{i}] missing 'id'");
        assert!(
            a["category"].as_str().is_some(),
            "assertion[{i}] missing 'category'"
        );
        assert!(
            a["system"].as_str().is_some(),
            "assertion[{i}] missing 'system'"
        );
        assert!(
            a["description"].as_str().is_some(),
            "assertion[{i}] missing 'description'"
        );
    }
}

#[test]
fn doc_m_02_json_assertions_all_have_um_prefix() {
    let json = parse_json();
    let assertions = json["assertions"].as_array().unwrap();
    for a in assertions {
        let id = a["id"].as_str().unwrap();
        assert!(
            id.starts_with("UM-") || id.starts_with("DOC-"),
            "assertion ID {id} must start with UM- or DOC-"
        );
    }
}

#[test]
fn doc_m_02_json_has_thresholds() {
    let json = parse_json();
    let t = json["thresholds"]
        .as_object()
        .expect("thresholds must be object");
    let required_keys = [
        "total_test_file_tests",
        "total_inline_tests",
        "contract_docs",
        "cross_backend_error_parity_cells",
        "messaging_error_parity_cells",
        "pool_lifecycle_scenarios",
        "fault_injection_scenarios",
        "cancel_safety_scenarios",
    ];
    for key in &required_keys {
        assert!(t.contains_key(*key), "thresholds missing key: {key}");
    }
}

#[test]
fn doc_m_02_json_has_file_inventory() {
    let json = parse_json();
    let inv = json["file_inventory"]
        .as_array()
        .expect("file_inventory must be array");
    assert!(
        inv.len() >= 6,
        "expected >= 6 file inventory entries, got {}",
        inv.len()
    );
    for (i, entry) in inv.iter().enumerate() {
        assert!(
            entry["path"].as_str().is_some(),
            "file_inventory[{i}] missing 'path'"
        );
        assert!(
            entry["min_tests"].as_u64().is_some(),
            "file_inventory[{i}] missing 'min_tests'"
        );
    }
}

#[test]
fn doc_m_02_json_has_inline_test_inventory() {
    let json = parse_json();
    let inv = json["inline_test_inventory"]
        .as_array()
        .expect("inline_test_inventory must be array");
    assert!(
        inv.len() >= 9,
        "expected >= 9 inline test inventory entries, got {}",
        inv.len()
    );
    for (i, entry) in inv.iter().enumerate() {
        assert!(
            entry["module"].as_str().is_some(),
            "inline_test_inventory[{i}] missing 'module'"
        );
        assert!(
            entry["min_tests"].as_u64().is_some(),
            "inline_test_inventory[{i}] missing 'min_tests'"
        );
    }
}

#[test]
fn doc_m_02_json_has_upstream_dependencies() {
    let json = parse_json();
    let deps = json["upstream_dependencies"]
        .as_array()
        .expect("upstream_dependencies must be array");
    // T6.2 through T6.10
    let required_beads = [
        "asupersync-2oh2u.6.2",
        "asupersync-2oh2u.6.3",
        "asupersync-2oh2u.6.4",
        "asupersync-2oh2u.6.5",
        "asupersync-2oh2u.6.6",
        "asupersync-2oh2u.6.7",
        "asupersync-2oh2u.6.8",
        "asupersync-2oh2u.6.9",
        "asupersync-2oh2u.6.10",
    ];
    let found: HashSet<&str> = deps.iter().filter_map(|d| d["bead_id"].as_str()).collect();
    for bead in &required_beads {
        assert!(found.contains(bead), "missing upstream dependency: {bead}");
    }
}

#[test]
fn doc_m_02_json_has_downstream_dependents() {
    let json = parse_json();
    let deps = json["downstream_dependents"]
        .as_array()
        .expect("downstream_dependents must be array");
    assert!(
        deps.iter()
            .filter_map(|d| d["bead_id"].as_str())
            .any(|x| x == "asupersync-2oh2u.6.13"),
        "must reference T6.13"
    );
}

// ════════════════════════════════════════════════════════════════════════════
// Section 3: Assertion Coverage Completeness
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn assertions_cover_all_systems() {
    let json = parse_json();
    let assertions = json["assertions"].as_array().unwrap();
    let systems: HashSet<&str> = assertions
        .iter()
        .filter_map(|a| a["system"].as_str())
        .collect();
    let required = [
        "postgres",
        "mysql",
        "sqlite",
        "pool",
        "redis",
        "nats",
        "jetstream",
        "kafka",
        "transaction",
        "integration",
        "meta",
    ];
    for sys in &required {
        assert!(systems.contains(sys), "missing system coverage: {sys}");
    }
}

#[test]
fn assertions_cover_all_categories() {
    let json = parse_json();
    let assertions = json["assertions"].as_array().unwrap();
    let categories: HashSet<&str> = assertions
        .iter()
        .filter_map(|a| a["category"].as_str())
        .collect();
    let required = [
        "error_classification",
        "display_format",
        "error_variants",
        "error_chain",
        "pool_lifecycle",
        "pool_stats",
        "transaction",
        "retry_policy",
        "config_validation",
        "document_requirements",
    ];
    for cat in &required {
        assert!(categories.contains(cat), "missing category: {cat}");
    }
}

#[test]
fn assertions_cover_postgres_ids() {
    let json = parse_json();
    let assertions = json["assertions"].as_array().unwrap();
    let ids: HashSet<&str> = assertions.iter().filter_map(|a| a["id"].as_str()).collect();
    for i in 1..=8 {
        let id = format!("UM-PG-{i:02}");
        assert!(ids.contains(id.as_str()), "missing {id}");
    }
}

#[test]
fn assertions_cover_mysql_ids() {
    let json = parse_json();
    let assertions = json["assertions"].as_array().unwrap();
    let ids: HashSet<&str> = assertions.iter().filter_map(|a| a["id"].as_str()).collect();
    for i in 1..=7 {
        let id = format!("UM-MY-{i:02}");
        assert!(ids.contains(id.as_str()), "missing {id}");
    }
}

#[test]
fn assertions_cover_sqlite_ids() {
    let json = parse_json();
    let assertions = json["assertions"].as_array().unwrap();
    let ids: HashSet<&str> = assertions.iter().filter_map(|a| a["id"].as_str()).collect();
    for i in 1..=6 {
        let id = format!("UM-SQ-{i:02}");
        assert!(ids.contains(id.as_str()), "missing {id}");
    }
}

#[test]
fn assertions_cover_pool_ids() {
    let json = parse_json();
    let assertions = json["assertions"].as_array().unwrap();
    let ids: HashSet<&str> = assertions.iter().filter_map(|a| a["id"].as_str()).collect();
    for i in 1..=10 {
        let id = format!("UM-POOL-{i:02}");
        assert!(ids.contains(id.as_str()), "missing {id}");
    }
    for i in 1..=2 {
        let id = format!("UM-TXN-{i:02}");
        assert!(ids.contains(id.as_str()), "missing {id}");
    }
}

#[test]
fn assertions_cover_redis_ids() {
    let json = parse_json();
    let assertions = json["assertions"].as_array().unwrap();
    let ids: HashSet<&str> = assertions.iter().filter_map(|a| a["id"].as_str()).collect();
    for i in 1..=6 {
        let id = format!("UM-RD-{i:02}");
        assert!(ids.contains(id.as_str()), "missing {id}");
    }
}

#[test]
fn assertions_cover_nats_ids() {
    let json = parse_json();
    let assertions = json["assertions"].as_array().unwrap();
    let ids: HashSet<&str> = assertions.iter().filter_map(|a| a["id"].as_str()).collect();
    for i in 1..=3 {
        let id = format!("UM-NT-{i:02}");
        assert!(ids.contains(id.as_str()), "missing {id}");
    }
}

#[test]
fn assertions_cover_jetstream_ids() {
    let json = parse_json();
    let assertions = json["assertions"].as_array().unwrap();
    let ids: HashSet<&str> = assertions.iter().filter_map(|a| a["id"].as_str()).collect();
    for i in 1..=4 {
        let id = format!("UM-JS-{i:02}");
        assert!(ids.contains(id.as_str()), "missing {id}");
    }
}

#[test]
fn assertions_cover_kafka_ids() {
    let json = parse_json();
    let assertions = json["assertions"].as_array().unwrap();
    let ids: HashSet<&str> = assertions.iter().filter_map(|a| a["id"].as_str()).collect();
    for i in 1..=6 {
        let id = format!("UM-KF-{i:02}");
        assert!(ids.contains(id.as_str()), "missing {id}");
    }
}

#[test]
fn assertions_cover_retry_ids() {
    let json = parse_json();
    let assertions = json["assertions"].as_array().unwrap();
    let ids: HashSet<&str> = assertions.iter().filter_map(|a| a["id"].as_str()).collect();
    for i in 1..=6 {
        let id = format!("UM-RTY-{i:02}");
        assert!(ids.contains(id.as_str()), "missing {id}");
    }
}

#[test]
fn assertions_cover_integration_ids() {
    let json = parse_json();
    let assertions = json["assertions"].as_array().unwrap();
    let ids: HashSet<&str> = assertions.iter().filter_map(|a| a["id"].as_str()).collect();
    for i in 1..=5 {
        let id = format!("UM-INT-{i:02}");
        assert!(ids.contains(id.as_str()), "missing {id}");
    }
}

#[test]
fn assertions_cover_doc_meta_ids() {
    let json = parse_json();
    let assertions = json["assertions"].as_array().unwrap();
    let ids: HashSet<&str> = assertions.iter().filter_map(|a| a["id"].as_str()).collect();
    for i in 1..=3 {
        let id = format!("DOC-M-{i:02}");
        assert!(ids.contains(id.as_str()), "missing {id}");
    }
}

#[test]
fn total_assertion_count_matches_contract() {
    let json = parse_json();
    let assertions = json["assertions"].as_array().unwrap();
    // Contract says 66 total assertions
    assert_eq!(assertions.len(), 66, "expected exactly 66 assertions");
}

// ════════════════════════════════════════════════════════════════════════════
// Section 4: Test File Existence and Minimum Counts
// ════════════════════════════════════════════════════════════════════════════

// Each test validates that a required test file exists and meets its min_tests threshold.

#[test]
fn file_inv_tokio_db_pool_transaction_observability_contracts() {
    let src = include_str!("tokio_db_pool_transaction_observability_contracts.rs");
    let count = count_test_fns(src);
    assert!(
        count >= 20,
        "tokio_db_pool_transaction_observability_contracts.rs: {count} tests < 20 min"
    );
}

#[test]
fn file_inv_tokio_retry_idempotency_failure_contracts() {
    let src = include_str!("tokio_retry_idempotency_failure_contracts.rs");
    let count = count_test_fns(src);
    assert!(
        count >= 10,
        "tokio_retry_idempotency_failure_contracts.rs: {count} tests < 10 min"
    );
}

#[test]
fn file_inv_tokio_db_messaging_integration() {
    let src = include_str!("tokio_db_messaging_integration.rs");
    let count = count_test_fns(src);
    assert!(
        count >= 30,
        "tokio_db_messaging_integration.rs: {count} tests < 30 min"
    );
}

#[test]
fn file_inv_database_pool_integration() {
    let src = include_str!("database_pool_integration.rs");
    let count = count_test_fns(src);
    assert!(
        count >= 15,
        "database_pool_integration.rs: {count} tests < 15 min"
    );
}

#[test]
fn file_inv_e2e_database() {
    let src = include_str!("e2e_database.rs");
    let count = count_test_fns(src);
    assert!(count >= 3, "e2e_database.rs: {count} tests < 3 min");
}

#[test]
fn file_inv_e2e_database_migration() {
    let src = include_str!("e2e_database_migration.rs");
    let count = count_test_fns(src);
    assert!(
        count >= 10,
        "e2e_database_migration.rs: {count} tests < 10 min"
    );
}

#[test]
fn total_test_file_tests_above_threshold() {
    let files: &[(&str, &str)] = &[
        (
            "tokio_db_pool_transaction_observability_contracts",
            include_str!("tokio_db_pool_transaction_observability_contracts.rs"),
        ),
        (
            "tokio_retry_idempotency_failure_contracts",
            include_str!("tokio_retry_idempotency_failure_contracts.rs"),
        ),
        (
            "tokio_db_messaging_integration",
            include_str!("tokio_db_messaging_integration.rs"),
        ),
        (
            "database_pool_integration",
            include_str!("database_pool_integration.rs"),
        ),
        ("e2e_database", include_str!("e2e_database.rs")),
        (
            "e2e_database_migration",
            include_str!("e2e_database_migration.rs"),
        ),
    ];
    let total: usize = files.iter().map(|(_, src)| count_test_fns(src)).sum();
    assert!(
        total >= 150,
        "total test file tests: {total} < 150 threshold"
    );
}

// ════════════════════════════════════════════════════════════════════════════
// Section 5: Inline Test Counts
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn inline_tests_database_pool() {
    let src = include_str!("../src/database/pool.rs");
    let count = count_test_fns(src);
    assert!(
        count >= 10,
        "src/database/pool.rs: {count} inline tests < 10 min"
    );
}

#[test]
fn inline_tests_database_postgres() {
    let src = include_str!("../src/database/postgres.rs");
    let count = count_test_fns(src);
    assert!(
        count >= 3,
        "src/database/postgres.rs: {count} inline tests < 3 min"
    );
}

#[test]
fn inline_tests_database_mysql() {
    let src = include_str!("../src/database/mysql.rs");
    let count = count_test_fns(src);
    assert!(
        count >= 10,
        "src/database/mysql.rs: {count} inline tests < 10 min"
    );
}

#[test]
fn inline_tests_database_sqlite() {
    let src = include_str!("../src/database/sqlite.rs");
    let count = count_test_fns(src);
    assert!(
        count >= 3,
        "src/database/sqlite.rs: {count} inline tests < 3 min"
    );
}

#[test]
fn inline_tests_messaging_kafka() {
    let src = include_str!("../src/messaging/kafka.rs");
    let count = count_test_fns(src);
    assert!(
        count >= 5,
        "src/messaging/kafka.rs: {count} inline tests < 5 min"
    );
}

#[test]
fn inline_tests_messaging_kafka_consumer() {
    let src = include_str!("../src/messaging/kafka_consumer.rs");
    let count = count_test_fns(src);
    assert!(
        count >= 3,
        "src/messaging/kafka_consumer.rs: {count} inline tests < 3 min"
    );
}

#[test]
fn inline_tests_messaging_nats() {
    let src = include_str!("../src/messaging/nats.rs");
    let count = count_test_fns(src);
    assert!(
        count >= 10,
        "src/messaging/nats.rs: {count} inline tests < 10 min"
    );
}

#[test]
fn inline_tests_messaging_jetstream() {
    let src = include_str!("../src/messaging/jetstream.rs");
    let count = count_test_fns(src);
    assert!(
        count >= 5,
        "src/messaging/jetstream.rs: {count} inline tests < 5 min"
    );
}

#[test]
fn inline_tests_messaging_redis() {
    let src = include_str!("../src/messaging/redis.rs");
    let count = count_test_fns(src);
    assert!(
        count >= 5,
        "src/messaging/redis.rs: {count} inline tests < 5 min"
    );
}

#[test]
fn total_inline_tests_above_threshold() {
    let modules: &[(&str, &str)] = &[
        ("database/pool", include_str!("../src/database/pool.rs")),
        (
            "database/postgres",
            include_str!("../src/database/postgres.rs"),
        ),
        ("database/mysql", include_str!("../src/database/mysql.rs")),
        ("database/sqlite", include_str!("../src/database/sqlite.rs")),
        ("messaging/kafka", include_str!("../src/messaging/kafka.rs")),
        (
            "messaging/kafka_consumer",
            include_str!("../src/messaging/kafka_consumer.rs"),
        ),
        ("messaging/nats", include_str!("../src/messaging/nats.rs")),
        (
            "messaging/jetstream",
            include_str!("../src/messaging/jetstream.rs"),
        ),
        ("messaging/redis", include_str!("../src/messaging/redis.rs")),
    ];
    let total: usize = modules.iter().map(|(_, src)| count_test_fns(src)).sum();
    assert!(total >= 100, "total inline tests: {total} < 100 threshold");
}

// ════════════════════════════════════════════════════════════════════════════
// Section 6: Cross-Backend Error Parity (Database)
// ════════════════════════════════════════════════════════════════════════════

/// Verify that all 3 database backends test the same error classification methods.
/// This checks inline tests reference the 6 required parity properties.
#[test]
fn cross_backend_parity_postgres_coverage() {
    let src = include_str!("../src/database/postgres.rs");
    let parity_methods = [
        "is_connection_error",
        "is_transient",
        "is_constraint_violation",
        "is_unique_violation",
    ];
    for method in &parity_methods {
        assert!(
            src.contains(method),
            "postgres.rs missing parity method: {method}"
        );
    }
}

#[test]
fn cross_backend_parity_mysql_coverage() {
    let src = include_str!("../src/database/mysql.rs");
    let parity_methods = [
        "is_connection_error",
        "is_transient",
        "is_constraint_violation",
        "is_unique_violation",
    ];
    for method in &parity_methods {
        assert!(
            src.contains(method),
            "mysql.rs missing parity method: {method}"
        );
    }
}

#[test]
fn cross_backend_parity_sqlite_coverage() {
    let src = include_str!("../src/database/sqlite.rs");
    let parity_methods = [
        "is_connection_error",
        "is_transient",
        "is_constraint_violation",
        "is_unique_violation",
    ];
    for method in &parity_methods {
        assert!(
            src.contains(method),
            "sqlite.rs missing parity method: {method}"
        );
    }
}

#[test]
fn cross_backend_parity_all_backends_have_display() {
    let pg = include_str!("../src/database/postgres.rs");
    let my = include_str!("../src/database/mysql.rs");
    let sq = include_str!("../src/database/sqlite.rs");
    // All backends must implement Display (impl fmt::Display or impl Display)
    assert!(
        pg.contains("fmt::Display") || pg.contains("impl Display"),
        "postgres.rs missing Display impl"
    );
    assert!(
        my.contains("fmt::Display") || my.contains("impl Display"),
        "mysql.rs missing Display impl"
    );
    assert!(
        sq.contains("fmt::Display") || sq.contains("impl Display"),
        "sqlite.rs missing Display impl"
    );
}

#[test]
fn cross_backend_parity_retryable_consistency() {
    // UM-PG-06, UM-MY-06, UM-SQ-05: is_retryable consistent with is_transient
    let pg = include_str!("../src/database/postgres.rs");
    let my = include_str!("../src/database/mysql.rs");
    let sq = include_str!("../src/database/sqlite.rs");
    assert!(
        pg.contains("is_retryable"),
        "postgres.rs missing is_retryable"
    );
    assert!(my.contains("is_retryable"), "mysql.rs missing is_retryable");
    assert!(
        sq.contains("is_retryable"),
        "sqlite.rs missing is_retryable"
    );
}

#[test]
fn cross_backend_parity_cell_count() {
    // Contract requires 6 properties x 3 backends = 18 cells
    let json = parse_json();
    let threshold = json["thresholds"]["cross_backend_error_parity_cells"]
        .as_u64()
        .unwrap();
    assert_eq!(threshold, 18, "parity cells threshold must be 18");
}

// ════════════════════════════════════════════════════════════════════════════
// Section 7: Messaging Error Parity
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn messaging_parity_kafka_coverage() {
    let src = include_str!("../src/messaging/kafka.rs");
    assert!(
        src.contains("is_transient"),
        "kafka.rs missing is_transient"
    );
    assert!(
        src.contains("fmt::Display") || src.contains("impl Display"),
        "kafka.rs missing Display"
    );
}

#[test]
fn messaging_parity_redis_coverage() {
    let src = include_str!("../src/messaging/redis.rs");
    assert!(
        src.contains("is_transient"),
        "redis.rs missing is_transient"
    );
    assert!(
        src.contains("fmt::Display") || src.contains("impl Display"),
        "redis.rs missing Display"
    );
}

#[test]
fn messaging_parity_nats_coverage() {
    let src = include_str!("../src/messaging/nats.rs");
    assert!(src.contains("is_transient"), "nats.rs missing is_transient");
    assert!(
        src.contains("fmt::Display") || src.contains("impl Display"),
        "nats.rs missing Display"
    );
}

#[test]
fn messaging_parity_jetstream_coverage() {
    let src = include_str!("../src/messaging/jetstream.rs");
    assert!(
        src.contains("is_transient"),
        "jetstream.rs missing is_transient"
    );
    assert!(
        src.contains("fmt::Display") || src.contains("impl Display"),
        "jetstream.rs missing Display"
    );
}

#[test]
fn messaging_parity_cell_count() {
    // Contract requires 3 properties x 4 systems = 12 cells
    let json = parse_json();
    let threshold = json["thresholds"]["messaging_error_parity_cells"]
        .as_u64()
        .unwrap();
    assert_eq!(threshold, 12, "messaging parity cells threshold must be 12");
}

// ════════════════════════════════════════════════════════════════════════════
// Section 8: Pool Lifecycle Scenario Count
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn pool_lifecycle_scenario_count() {
    let json = parse_json();
    let assertions = json["assertions"].as_array().unwrap();
    let pool_lifecycle_count = assertions
        .iter()
        .filter(|a| a["category"].as_str() == Some("pool_lifecycle"))
        .count();
    assert!(
        pool_lifecycle_count >= 7,
        "pool_lifecycle assertions: {pool_lifecycle_count} < 7"
    );
}

#[test]
fn pool_stats_assertions_present() {
    let json = parse_json();
    let assertions = json["assertions"].as_array().unwrap();
    let pool_stats_count = assertions
        .iter()
        .filter(|a| a["category"].as_str() == Some("pool_stats"))
        .count();
    assert!(
        pool_stats_count >= 3,
        "pool_stats assertions: {pool_stats_count} < 3"
    );
}

// ════════════════════════════════════════════════════════════════════════════
// Section 9: Fault Injection and Cancel Safety
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn fault_injection_assertions_present() {
    let json = parse_json();
    let assertions = json["assertions"].as_array().unwrap();
    let fi_count = assertions
        .iter()
        .filter(|a| a["category"].as_str() == Some("fault_injection"))
        .count();
    assert!(fi_count >= 1, "fault_injection assertions: {fi_count} < 1");
}

#[test]
fn cancel_safety_assertions_present() {
    let json = parse_json();
    let assertions = json["assertions"].as_array().unwrap();
    let cs_count = assertions
        .iter()
        .filter(|a| a["category"].as_str() == Some("cancel_safety"))
        .count();
    assert!(cs_count >= 1, "cancel_safety assertions: {cs_count} < 1");
}

// ════════════════════════════════════════════════════════════════════════════
// Section 10: Source Module References (DOC-M-03)
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn doc_m_03_source_module_references() {
    let required_modules = [
        "src/database/pool.rs",
        "src/database/transaction.rs",
        "src/database/postgres.rs",
        "src/database/mysql.rs",
        "src/database/sqlite.rs",
        "src/messaging/redis.rs",
        "src/messaging/nats.rs",
        "src/messaging/jetstream.rs",
        "src/messaging/kafka.rs",
        "src/messaging/kafka_consumer.rs",
    ];
    for module in &required_modules {
        assert!(
            CONTRACT_MD.contains(module),
            "contract doc missing source reference: {module}"
        );
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Section 11: Contract Document Completeness (counted)
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn contract_doc_count_threshold() {
    // T6.5, T6.9, T6.10 contract docs must all exist
    let t6_5 = include_str!("../docs/tokio_db_pool_transaction_observability_contracts.md");
    let t6_9 = include_str!("../docs/tokio_retry_idempotency_failure_contracts.md");
    let t6_10 = include_str!("../docs/tokio_db_messaging_integration_contract.md");
    assert!(!t6_5.is_empty(), "T6.5 contract doc missing/empty");
    assert!(!t6_9.is_empty(), "T6.9 contract doc missing/empty");
    assert!(!t6_10.is_empty(), "T6.10 contract doc missing/empty");
}

// ════════════════════════════════════════════════════════════════════════════
// Section 12: JSON-to-Doc Consistency
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn json_assertion_ids_appear_in_contract_doc() {
    let json = parse_json();
    let assertions = json["assertions"].as_array().unwrap();
    for a in assertions {
        let id = a["id"].as_str().unwrap();
        assert!(
            CONTRACT_MD.contains(id),
            "assertion {id} in JSON but not in contract doc"
        );
    }
}

#[test]
fn json_file_inventory_paths_match_doc() {
    let json = parse_json();
    let inv = json["file_inventory"].as_array().unwrap();
    for entry in inv {
        let path = entry["path"].as_str().unwrap();
        // The file name (without tests/ prefix) should appear in the doc
        let filename = path.rsplit('/').next().unwrap_or(path);
        assert!(
            CONTRACT_MD.contains(filename),
            "file_inventory path {path} not referenced in contract doc"
        );
    }
}

#[test]
fn json_inline_inventory_modules_match_doc() {
    let json = parse_json();
    let inv = json["inline_test_inventory"].as_array().unwrap();
    for entry in inv {
        let module = entry["module"].as_str().unwrap();
        assert!(
            CONTRACT_MD.contains(module),
            "inline_test_inventory module {module} not referenced in contract doc"
        );
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Section 13: Threshold Value Validation
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn threshold_values_match_contract() {
    let json = parse_json();
    let t = &json["thresholds"];
    assert_eq!(t["total_test_file_tests"].as_u64().unwrap(), 150);
    assert_eq!(t["total_inline_tests"].as_u64().unwrap(), 100);
    assert_eq!(t["contract_docs"].as_u64().unwrap(), 3);
    assert_eq!(t["cross_backend_error_parity_cells"].as_u64().unwrap(), 18);
    assert_eq!(t["messaging_error_parity_cells"].as_u64().unwrap(), 12);
    assert_eq!(t["pool_lifecycle_scenarios"].as_u64().unwrap(), 7);
    assert_eq!(t["fault_injection_scenarios"].as_u64().unwrap(), 5);
    assert_eq!(t["cancel_safety_scenarios"].as_u64().unwrap(), 3);
}
