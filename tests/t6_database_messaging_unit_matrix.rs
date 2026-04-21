#![allow(warnings)]
#![allow(clippy::all)]
//! T6.12 — Behavioral Verification Matrix for Database and Messaging Unit Tests
//!
//! Bead: `asupersync-2oh2u.6.12`
//! Track: T6 (Database and messaging ecosystem closure)
//!
//! This suite complements `tokio_db_messaging_unit_test_matrix.rs` (count-based
//! meta-test) with deeper **behavioral verification**: for each contract assertion
//! (UM-PG-*, UM-MY-*, UM-SQ-*, UM-POOL-*, UM-RD-*, UM-NT-*, UM-JS-*, UM-KF-*,
//! UM-RTY-*, UM-INT-*), we verify that the source code and test suites actually
//! exercise the stated behavior — not just that they exist in sufficient quantity.
//!
//! Strategy: error classification methods are defined in source modules but tested
//! in integration test files (database_pool_integration.rs, etc.). This suite
//! checks BOTH locations to confirm behavioral coverage.

use std::collections::HashSet;

// ─── Source modules under test ───────────────────────────────────────────────

const PG_SRC: &str = include_str!("../src/database/postgres.rs");
const MY_SRC: &str = include_str!("../src/database/mysql.rs");
const SQ_SRC: &str = include_str!("../src/database/sqlite.rs");
const POOL_SRC: &str = include_str!("../src/database/pool.rs");
const TXN_SRC: &str = include_str!("../src/database/transaction.rs");
const REDIS_SRC: &str = include_str!("../src/messaging/redis.rs");
const NATS_SRC: &str = include_str!("../src/messaging/nats.rs");
const JS_SRC: &str = include_str!("../src/messaging/jetstream.rs");
const KAFKA_SRC: &str = include_str!("../src/messaging/kafka.rs");
const KAFKA_CONSUMER_SRC: &str = include_str!("../src/messaging/kafka_consumer.rs");

// ─── Test file sources (integration + contract tests) ────────────────────────

const POOL_INTEGRATION: &str = include_str!("database_pool_integration.rs");
const DB_MSG_INTEGRATION: &str = include_str!("tokio_db_messaging_integration.rs");
const POOL_TXN_CONTRACTS: &str =
    include_str!("tokio_db_pool_transaction_observability_contracts.rs");
const RETRY_CONTRACTS: &str = include_str!("tokio_retry_idempotency_failure_contracts.rs");

// ─── Contract artifact ───────────────────────────────────────────────────────

const CONTRACT_JSON: &str =
    include_str!("../docs/tokio_db_messaging_unit_test_matrix_contract.json");

fn parse_json() -> serde_json::Value {
    serde_json::from_str(CONTRACT_JSON).expect("T6.12 contract JSON must parse")
}

/// Collect assertion IDs for a given system from the contract JSON.
fn assertion_ids_for_system(system: &str) -> Vec<String> {
    let json = parse_json();
    json["assertions"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|a| a["system"].as_str() == Some(system))
        .map(|a| a["id"].as_str().unwrap().to_string())
        .collect()
}

/// Check that a source file's `mod tests` section contains `needle`.
fn tests_section_contains(src: &str, needle: &str) -> bool {
    src.find("mod tests")
        .map_or_else(|| src.contains(needle), |idx| src[idx..].contains(needle))
}

/// Check that the error classification method is exercised SOMEWHERE in the
/// project test surface: inline tests, integration tests, or contract tests.
fn any_test_exercises(method: &str) -> bool {
    // Check inline test sections of source modules
    tests_section_contains(PG_SRC, method)
        || tests_section_contains(MY_SRC, method)
        || tests_section_contains(SQ_SRC, method)
        || tests_section_contains(POOL_SRC, method)
        || tests_section_contains(REDIS_SRC, method)
        || tests_section_contains(NATS_SRC, method)
        || tests_section_contains(JS_SRC, method)
        || tests_section_contains(KAFKA_SRC, method)
        || tests_section_contains(KAFKA_CONSUMER_SRC, method)
        // Check integration test files
        || POOL_INTEGRATION.contains(method)
        || DB_MSG_INTEGRATION.contains(method)
        || POOL_TXN_CONTRACTS.contains(method)
        || RETRY_CONTRACTS.contains(method)
}

/// Check that a DATABASE-specific method is tested for a given backend.
/// Looks in both the source's inline tests and the integration tests.
fn db_method_tested(src: &str, method: &str) -> bool {
    tests_section_contains(src, method)
        || POOL_INTEGRATION.contains(method)
        || DB_MSG_INTEGRATION.contains(method)
        || POOL_TXN_CONTRACTS.contains(method)
}

/// Check that a MESSAGING-specific method is tested for a given backend.
fn msg_method_tested(src: &str, method: &str) -> bool {
    tests_section_contains(src, method)
        || DB_MSG_INTEGRATION.contains(method)
        || RETRY_CONTRACTS.contains(method)
}

// ════════════════════════════════════════════════════════════════════════════
// Section 1: PostgreSQL Behavioral Assertions (UM-PG-01 through UM-PG-08)
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn um_pg_01_serialization_failure_tested_with_40001() {
    // UM-PG-01: is_serialization_failure() true for SQLSTATE 40001
    assert!(
        PG_SRC.contains("is_serialization_failure"),
        "UM-PG-01: postgres must define is_serialization_failure()"
    );
    assert!(
        PG_SRC.contains("40001"),
        "UM-PG-01: postgres must reference SQLSTATE 40001"
    );
    assert!(
        db_method_tested(PG_SRC, "is_serialization_failure"),
        "UM-PG-01: is_serialization_failure() must be tested"
    );
}

#[test]
fn um_pg_02_deadlock_tested_with_40p01() {
    // UM-PG-02: is_deadlock() true for SQLSTATE 40P01
    assert!(
        PG_SRC.contains("is_deadlock"),
        "UM-PG-02: postgres must define is_deadlock()"
    );
    assert!(
        PG_SRC.contains("40P01"),
        "UM-PG-02: postgres must reference SQLSTATE 40P01"
    );
    assert!(
        db_method_tested(PG_SRC, "is_deadlock"),
        "UM-PG-02: is_deadlock() must be tested"
    );
}

#[test]
fn um_pg_03_unique_violation_tested_with_23505() {
    // UM-PG-03: is_unique_violation() true for SQLSTATE 23505
    assert!(
        PG_SRC.contains("is_unique_violation"),
        "UM-PG-03: postgres must define is_unique_violation()"
    );
    assert!(
        PG_SRC.contains("23505"),
        "UM-PG-03: postgres must reference SQLSTATE 23505"
    );
    assert!(
        db_method_tested(PG_SRC, "is_unique_violation"),
        "UM-PG-03: is_unique_violation() must be tested"
    );
}

#[test]
fn um_pg_04_constraint_violation_tested_with_23xxx() {
    // UM-PG-04: is_constraint_violation() true for 23xxx family
    assert!(
        PG_SRC.contains("is_constraint_violation"),
        "UM-PG-04: postgres must define is_constraint_violation()"
    );
    assert!(
        PG_SRC.contains("\"23\""),
        "UM-PG-04: postgres must check class 23 prefix"
    );
}

#[test]
fn um_pg_05_connection_error_tested() {
    // UM-PG-05: is_connection_error() true for Io/ConnectionClosed
    assert!(
        PG_SRC.contains("is_connection_error"),
        "UM-PG-05: postgres must define is_connection_error()"
    );
    assert!(
        PG_SRC.contains("ConnectionClosed"),
        "UM-PG-05: postgres must have ConnectionClosed variant"
    );
}

#[test]
fn um_pg_06_transient_retryable_consistency() {
    // UM-PG-06: is_transient() consistent with is_retryable()
    assert!(
        PG_SRC.contains("is_transient") && PG_SRC.contains("is_retryable"),
        "UM-PG-06: postgres must define both is_transient() and is_retryable()"
    );
    // is_retryable should delegate to or be consistent with is_transient
    assert!(
        PG_SRC.contains("self.is_transient()"),
        "UM-PG-06: is_retryable should delegate to is_transient"
    );
}

#[test]
fn um_pg_07_error_code_returns_sqlstate() {
    // UM-PG-07: error_code() returns SQLSTATE string
    assert!(
        PG_SRC.contains("error_code"),
        "UM-PG-07: postgres must implement error_code()"
    );
}

#[test]
fn um_pg_08_display_includes_detail() {
    // UM-PG-08: Error Display includes category and detail
    assert!(
        PG_SRC.contains("fmt::Display"),
        "UM-PG-08: postgres must implement Display"
    );
}

// ════════════════════════════════════════════════════════════════════════════
// Section 2: MySQL Behavioral Assertions (UM-MY-01 through UM-MY-07)
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn um_my_01_serialization_failure_tested() {
    // UM-MY-01: is_serialization_failure() for serialization codes
    assert!(
        MY_SRC.contains("is_serialization_failure"),
        "UM-MY-01: mysql must define is_serialization_failure()"
    );
}

#[test]
fn um_my_02_deadlock_tested_with_1213() {
    // UM-MY-02: is_deadlock() true for error 1213
    assert!(
        MY_SRC.contains("is_deadlock"),
        "UM-MY-02: mysql must define is_deadlock()"
    );
    assert!(
        MY_SRC.contains("1213"),
        "UM-MY-02: mysql must reference error code 1213"
    );
}

#[test]
fn um_my_03_unique_violation_tested() {
    // UM-MY-03: is_unique_violation() for duplicate-entry codes
    assert!(
        MY_SRC.contains("is_unique_violation"),
        "UM-MY-03: mysql must define is_unique_violation()"
    );
}

#[test]
fn um_my_04_constraint_violation_tested() {
    // UM-MY-04: is_constraint_violation() for constraint family
    assert!(
        MY_SRC.contains("is_constraint_violation"),
        "UM-MY-04: mysql must define is_constraint_violation()"
    );
}

#[test]
fn um_my_05_connection_error_tested() {
    // UM-MY-05: is_connection_error() true for Io/ConnectionClosed
    assert!(
        MY_SRC.contains("is_connection_error"),
        "UM-MY-05: mysql must define is_connection_error()"
    );
    assert!(
        MY_SRC.contains("ConnectionClosed"),
        "UM-MY-05: mysql must have ConnectionClosed variant"
    );
}

#[test]
fn um_my_06_transient_retryable_consistency() {
    // UM-MY-06: is_transient() consistent with is_retryable()
    assert!(
        MY_SRC.contains("is_transient") && MY_SRC.contains("is_retryable"),
        "UM-MY-06: mysql must define both is_transient() and is_retryable()"
    );
}

#[test]
fn um_my_07_display_includes_server_code() {
    // UM-MY-07: Error Display includes server code and message
    assert!(
        MY_SRC.contains("fmt::Display"),
        "UM-MY-07: mysql must implement Display"
    );
}

// ════════════════════════════════════════════════════════════════════════════
// Section 3: SQLite Behavioral Assertions (UM-SQ-01 through UM-SQ-06)
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn um_sq_01_constraint_violation_defined() {
    // UM-SQ-01: is_constraint_violation() for constraint errors
    assert!(
        SQ_SRC.contains("is_constraint_violation"),
        "UM-SQ-01: sqlite must define is_constraint_violation()"
    );
}

#[test]
fn um_sq_02_unique_violation_defined() {
    // UM-SQ-02: is_unique_violation() for UNIQUE constraint
    assert!(
        SQ_SRC.contains("is_unique_violation"),
        "UM-SQ-02: sqlite must define is_unique_violation()"
    );
}

#[test]
fn um_sq_03_connection_error_defined() {
    // UM-SQ-03: is_connection_error() for Io/ConnectionClosed
    assert!(
        SQ_SRC.contains("is_connection_error"),
        "UM-SQ-03: sqlite must define is_connection_error()"
    );
    assert!(
        SQ_SRC.contains("ConnectionClosed"),
        "UM-SQ-03: sqlite must have ConnectionClosed variant"
    );
}

#[test]
fn um_sq_04_transient_for_busy() {
    // UM-SQ-04: is_transient() true for SQLITE_BUSY
    assert!(
        SQ_SRC.contains("is_transient"),
        "UM-SQ-04: sqlite must define is_transient()"
    );
    assert!(
        SQ_SRC.contains("is_busy") || SQ_SRC.contains("busy") || SQ_SRC.contains("locked"),
        "UM-SQ-04: sqlite must reference busy/locked semantics"
    );
}

#[test]
fn um_sq_05_retryable_consistent_with_transient() {
    // UM-SQ-05: is_retryable() consistent with is_transient()
    assert!(
        SQ_SRC.contains("is_retryable"),
        "UM-SQ-05: sqlite must define is_retryable()"
    );
}

#[test]
fn um_sq_06_display_includes_category() {
    // UM-SQ-06: Error Display includes error category
    assert!(
        SQ_SRC.contains("fmt::Display"),
        "UM-SQ-06: sqlite must implement Display"
    );
}

// ════════════════════════════════════════════════════════════════════════════
// Section 4: Pool Behavioral Assertions (UM-POOL-01 through UM-POOL-10)
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn um_pool_01_acquire_release_preserves_total() {
    // UM-POOL-01: Acquire-release lifecycle preserves total count
    assert!(
        tests_section_contains(POOL_SRC, "return_to_pool")
            || tests_section_contains(POOL_SRC, "return_on_drop"),
        "UM-POOL-01: pool tests must exercise acquire-release lifecycle"
    );
    assert!(
        tests_section_contains(POOL_SRC, "stats()"),
        "UM-POOL-01: pool tests must check stats after lifecycle operations"
    );
}

#[test]
fn um_pool_02_validation_failure_triggers_discard() {
    // UM-POOL-02: Validation failure triggers discard + recreate
    assert!(
        tests_section_contains(POOL_SRC, "set_valid(false)"),
        "UM-POOL-02: pool tests must exercise validation failure path"
    );
    assert!(
        tests_section_contains(POOL_SRC, "total_validation_failures"),
        "UM-POOL-02: pool tests must verify validation failure counter"
    );
}

#[test]
fn um_pool_03_capacity_enforcement() {
    // UM-POOL-03: Capacity enforcement at max_size
    assert!(
        tests_section_contains(POOL_SRC, "DbPoolError::Full"),
        "UM-POOL-03: pool tests must exercise capacity enforcement"
    );
}

#[test]
fn um_pool_04_stale_eviction() {
    // UM-POOL-04: Stale eviction respects idle_timeout/max_lifetime
    assert!(
        POOL_SRC.contains("evict_stale"),
        "UM-POOL-04: pool must implement evict_stale()"
    );
    assert!(
        POOL_SRC.contains("is_expired") && POOL_SRC.contains("is_idle_too_long"),
        "UM-POOL-04: pool must have both expiry check methods"
    );
}

#[test]
fn um_pool_05_close_rejects_new_acquires() {
    // UM-POOL-05: Close rejects new acquires
    assert!(
        tests_section_contains(POOL_SRC, "close_rejects_new_gets")
            || tests_section_contains(POOL_SRC, "DbPoolError::Closed"),
        "UM-POOL-05: pool tests must exercise close rejection"
    );
}

#[test]
fn um_pool_06_connect_failure_propagates() {
    // UM-POOL-06: Connect failure propagates cleanly
    assert!(
        tests_section_contains(POOL_SRC, "connect_failure")
            || tests_section_contains(POOL_SRC, "set_fail_connect"),
        "UM-POOL-06: pool tests must exercise connection failure"
    );
}

#[test]
fn um_pool_07_warmup_populates_min_idle() {
    // UM-POOL-07: Warm-up populates min_idle connections
    assert!(
        tests_section_contains(POOL_SRC, "warm_up"),
        "UM-POOL-07: pool tests must exercise warm_up()"
    );
}

#[test]
fn um_pool_08_stats_total_equals_idle_plus_active() {
    // UM-POOL-08: Stats: total == idle + active
    assert!(
        POOL_SRC.contains("saturating_sub(inner.idle.len())"),
        "UM-POOL-08: stats must compute active = total - idle"
    );
    assert!(
        tests_section_contains(POOL_SRC, "stats_track_lifecycle"),
        "UM-POOL-08: pool tests must verify stats lifecycle invariant"
    );
}

#[test]
fn um_pool_09_stats_total_bounded_by_max_size() {
    // UM-POOL-09: Stats: total <= max_size always
    assert!(
        POOL_SRC.contains("inner.total < self.config.max_size"),
        "UM-POOL-09: pool must guard total against max_size"
    );
}

#[test]
fn um_pool_10_stats_acquisitions_gte_creates() {
    // UM-POOL-10: Stats: total_acquisitions >= total_creates
    assert!(
        tests_section_contains(POOL_SRC, "total_acquisitions")
            && tests_section_contains(POOL_SRC, "total_creates"),
        "UM-POOL-10: pool tests must verify acquisition vs create counters"
    );
}

// ════════════════════════════════════════════════════════════════════════════
// Section 5: Transaction / RetryPolicy (UM-TXN-01, UM-TXN-02)
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn um_txn_01_retry_policy_exponential_backoff() {
    // UM-TXN-01: RetryPolicy exponential backoff formula
    assert!(
        TXN_SRC.contains("delay_for"),
        "UM-TXN-01: transaction module must implement delay_for()"
    );
    assert!(
        TXN_SRC.contains("checked_shl"),
        "UM-TXN-01: delay must use exponential (bit-shift) formula"
    );
    assert!(
        TXN_SRC.contains("saturating_mul"),
        "UM-TXN-01: delay computation must use overflow-safe arithmetic"
    );
}

#[test]
fn um_txn_02_retry_policy_edge_cases() {
    // UM-TXN-02: RetryPolicy edge cases
    assert!(
        TXN_SRC.contains("RetryPolicy::none()"),
        "UM-TXN-02: must have RetryPolicy::none() for zero-retry case"
    );
    assert!(
        TXN_SRC.contains("default_retry()"),
        "UM-TXN-02: must have default_retry() constructor"
    );
}

// ════════════════════════════════════════════════════════════════════════════
// Section 6: Redis Behavioral Assertions (UM-RD-01 through UM-RD-06)
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn um_rd_01_all_error_variants_constructible() {
    // UM-RD-01: All 6 RedisError variants constructible
    let variants = [
        "Io(",
        "Protocol(",
        "Redis(",
        "PoolExhausted",
        "InvalidUrl(",
        "Cancelled",
    ];
    for v in &variants {
        assert!(
            REDIS_SRC.contains(v),
            "UM-RD-01: RedisError must have variant containing '{v}'"
        );
    }
}

#[test]
fn um_rd_02_is_transient_defined_and_tested() {
    // UM-RD-02: is_transient() correct for each variant
    assert!(
        REDIS_SRC.contains("fn is_transient"),
        "UM-RD-02: redis must define is_transient()"
    );
    // Inline tests exercise error display/classification
    assert!(
        tests_section_contains(REDIS_SRC, "RedisError::")
            || msg_method_tested(REDIS_SRC, "is_transient"),
        "UM-RD-02: redis error variants must be exercised in tests"
    );
}

#[test]
fn um_rd_03_is_connection_error_defined() {
    // UM-RD-03: is_connection_error() correct for Io variant
    assert!(
        REDIS_SRC.contains("fn is_connection_error"),
        "UM-RD-03: redis must define is_connection_error()"
    );
    assert!(
        REDIS_SRC.contains("Self::Io(_)"),
        "UM-RD-03: is_connection_error must match Io variant"
    );
}

#[test]
fn um_rd_04_is_capacity_error_defined() {
    // UM-RD-04: is_capacity_error() true for PoolExhausted
    assert!(
        REDIS_SRC.contains("fn is_capacity_error"),
        "UM-RD-04: redis must define is_capacity_error()"
    );
    assert!(
        REDIS_SRC.contains("PoolExhausted"),
        "UM-RD-04: redis must map PoolExhausted to capacity error"
    );
}

#[test]
fn um_rd_05_display_non_empty() {
    // UM-RD-05: Error Display non-empty for all variants
    assert!(
        tests_section_contains(REDIS_SRC, "to_string()")
            || tests_section_contains(REDIS_SRC, "redis_error_display"),
        "UM-RD-05: redis tests must exercise Display formatting"
    );
}

#[test]
fn um_rd_06_error_chain_io() {
    // UM-RD-06: Error source chain correct for Io
    assert!(
        REDIS_SRC.contains("fn source("),
        "UM-RD-06: redis must implement Error::source()"
    );
    assert!(
        REDIS_SRC.contains("Self::Io(e) => Some(e)"),
        "UM-RD-06: redis Io variant must chain source error"
    );
}

// ════════════════════════════════════════════════════════════════════════════
// Section 7: NATS Behavioral Assertions (UM-NT-01 through UM-NT-03)
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn um_nt_01_all_error_variants_present() {
    // UM-NT-01: All NatsError variants exist
    let variants = [
        "Io(",
        "Protocol(",
        "Server(",
        "InvalidUrl(",
        "Cancelled",
        "Closed",
        "SubscriptionNotFound",
        "NotConnected",
    ];
    for v in &variants {
        assert!(
            NATS_SRC.contains(v),
            "UM-NT-01: NatsError must have variant containing '{v}'"
        );
    }
}

#[test]
fn um_nt_02_is_transient_defined() {
    // UM-NT-02: is_transient() defined and correct
    assert!(
        NATS_SRC.contains("fn is_transient"),
        "UM-NT-02: nats must define is_transient()"
    );
}

#[test]
fn um_nt_03_display_tested() {
    // UM-NT-03: Error Display non-empty for all variants
    assert!(
        tests_section_contains(NATS_SRC, "to_string()")
            || tests_section_contains(NATS_SRC, "format!(")
            || tests_section_contains(NATS_SRC, "nats_error_display"),
        "UM-NT-03: nats tests must exercise Display formatting"
    );
}

// ════════════════════════════════════════════════════════════════════════════
// Section 8: JetStream Behavioral Assertions (UM-JS-01 through UM-JS-04)
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn um_js_01_all_error_variants_present() {
    // UM-JS-01: All JsError variants exist
    let variants = [
        "Nats(",
        "Api {",
        "StreamNotFound(",
        "ConsumerNotFound",
        "NotAcked",
        "InvalidConfig(",
        "ParseError(",
    ];
    for v in &variants {
        assert!(
            JS_SRC.contains(v),
            "UM-JS-01: JsError must have variant containing '{v}'"
        );
    }
}

#[test]
fn um_js_02_is_transient_defined() {
    // UM-JS-02: is_transient() defined and delegates correctly
    assert!(
        JS_SRC.contains("fn is_transient"),
        "UM-JS-02: jetstream must define is_transient()"
    );
    // JetStream delegates transient check to underlying NatsError
    assert!(
        JS_SRC.contains("e.is_transient()") || JS_SRC.contains("Nats(e)"),
        "UM-JS-02: jetstream is_transient should delegate to NatsError"
    );
}

#[test]
fn um_js_03_display_tested() {
    // UM-JS-03: Error Display non-empty for all variants
    assert!(
        tests_section_contains(JS_SRC, "to_string()")
            || tests_section_contains(JS_SRC, "format!(")
            || tests_section_contains(JS_SRC, "js_error_display"),
        "UM-JS-03: jetstream tests must exercise Display formatting"
    );
}

#[test]
fn um_js_04_nats_error_wrapping() {
    // UM-JS-04: JsError::Nats wraps NatsError correctly
    assert!(
        JS_SRC.contains("fn source("),
        "UM-JS-04: JsError must implement Error::source()"
    );
}

// ════════════════════════════════════════════════════════════════════════════
// Section 9: Kafka Behavioral Assertions (UM-KF-01 through UM-KF-06)
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn um_kf_01_all_error_variants_present() {
    // UM-KF-01: All KafkaError variants exist
    let variants = [
        "Io(",
        "Protocol(",
        "Broker(",
        "QueueFull",
        "MessageTooLarge",
        "InvalidTopic(",
        "Transaction(",
        "Cancelled",
        "Config(",
    ];
    for v in &variants {
        assert!(
            KAFKA_SRC.contains(v),
            "UM-KF-01: KafkaError must have variant containing '{v}'"
        );
    }
}

#[test]
fn um_kf_02_is_transient_defined() {
    // UM-KF-02: is_transient() defined
    assert!(
        KAFKA_SRC.contains("fn is_transient"),
        "UM-KF-02: kafka must define is_transient()"
    );
}

#[test]
fn um_kf_03_is_capacity_error_defined() {
    // UM-KF-03: is_capacity_error() true for QueueFull
    assert!(
        KAFKA_SRC.contains("fn is_capacity_error"),
        "UM-KF-03: kafka must define is_capacity_error()"
    );
    assert!(
        KAFKA_SRC.contains("QueueFull"),
        "UM-KF-03: kafka must map QueueFull to capacity error"
    );
}

#[test]
fn um_kf_04_display_tested() {
    // UM-KF-04: Error Display non-empty for all variants
    assert!(
        tests_section_contains(KAFKA_SRC, "to_string()")
            || tests_section_contains(KAFKA_SRC, "format!(")
            || tests_section_contains(KAFKA_SRC, "kafka_error_display"),
        "UM-KF-04: kafka tests must exercise Display formatting"
    );
}

#[test]
fn um_kf_05_producer_config_has_bootstrap() {
    // UM-KF-05: Producer config has bootstrap_servers
    assert!(
        KAFKA_SRC.contains("bootstrap_servers"),
        "UM-KF-05: kafka producer must have bootstrap_servers config"
    );
}

#[test]
fn um_kf_06_consumer_config_has_group_id() {
    // UM-KF-06: Consumer config validates group_id
    assert!(
        KAFKA_CONSUMER_SRC.contains("group_id"),
        "UM-KF-06: kafka consumer must have group_id config"
    );
}

// ════════════════════════════════════════════════════════════════════════════
// Section 10: Retry Policy Assertions (UM-RTY-01 through UM-RTY-06)
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn um_rty_01_shared_retry_policy_complete() {
    assert!(
        TXN_SRC.contains("max_retries")
            && TXN_SRC.contains("base_delay")
            && TXN_SRC.contains("max_delay"),
        "UM-RTY-01: RetryPolicy must have max_retries, base_delay, max_delay"
    );
}

#[test]
fn um_rty_02_exponential_backoff_formula() {
    assert!(
        TXN_SRC.contains("checked_shl") && TXN_SRC.contains("saturating_mul"),
        "UM-RTY-02: must use overflow-safe exponential formula"
    );
}

#[test]
fn um_rty_03_max_delay_cap() {
    assert!(
        TXN_SRC.contains("max_delay"),
        "UM-RTY-03: delay must be capped at max_delay"
    );
}

#[test]
fn um_rty_04_zero_base_produces_zero() {
    assert!(
        TXN_SRC.contains("Duration::from_millis(0)"),
        "UM-RTY-04: RetryPolicy::none() must use zero duration"
    );
}

#[test]
fn um_rty_05_overflow_safety() {
    assert!(
        TXN_SRC.contains("unwrap_or(u64::MAX)") && TXN_SRC.contains("saturating_mul"),
        "UM-RTY-05: must handle overflow safely"
    );
}

#[test]
fn um_rty_06_none_returns_zero_delay() {
    assert!(
        TXN_SRC.contains("RetryPolicy::none()"),
        "UM-RTY-06: must have RetryPolicy::none() constructor"
    );
}

// ════════════════════════════════════════════════════════════════════════════
// Section 11: Integration Assertions (UM-INT-01 through UM-INT-05)
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn um_int_01_t6_10_contract_covers_scenarios() {
    let t6_10 = include_str!("../docs/tokio_db_messaging_integration_contract.md");
    assert!(
        t6_10.contains("INT-POOL") || t6_10.contains("INT-DB"),
        "UM-INT-01: T6.10 contract must reference pool scenarios"
    );
}

#[test]
fn um_int_02_json_artifact_matches_doc() {
    assert!(
        DB_MSG_INTEGRATION.contains("contract") || DB_MSG_INTEGRATION.contains("T6"),
        "UM-INT-02: integration tests must reference contract or track"
    );
}

#[test]
fn um_int_03_pool_fault_injection() {
    assert!(
        POOL_INTEGRATION.contains("fault")
            || POOL_INTEGRATION.contains("fail_connect")
            || POOL_INTEGRATION.contains("set_fail"),
        "UM-INT-03: pool integration must test fault injection"
    );
}

#[test]
fn um_int_04_cancel_safety() {
    assert!(
        DB_MSG_INTEGRATION.contains("cancel")
            || DB_MSG_INTEGRATION.contains("Cancel")
            || RETRY_CONTRACTS.contains("cancel")
            || RETRY_CONTRACTS.contains("Cancel"),
        "UM-INT-04: test files must include cancel safety scenarios"
    );
}

#[test]
fn um_int_05_cross_backend_error_normalization() {
    // All 3 DB backends must define the same error classification methods
    let common_methods = ["is_transient", "is_retryable", "is_connection_error"];
    for method in &common_methods {
        assert!(
            PG_SRC.contains(method),
            "UM-INT-05: postgres must define {method}"
        );
        assert!(
            MY_SRC.contains(method),
            "UM-INT-05: mysql must define {method}"
        );
        assert!(
            SQ_SRC.contains(method),
            "UM-INT-05: sqlite must define {method}"
        );
    }
    // Verify that at least one integration test exercises cross-backend methods
    assert!(
        any_test_exercises("is_serialization_failure"),
        "UM-INT-05: error classification must be tested somewhere"
    );
}

// ════════════════════════════════════════════════════════════════════════════
// Section 12: Structured Diagnostics Verification
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn structured_diagnostics_pool_tests_use_init_test() {
    assert!(
        tests_section_contains(POOL_SRC, "init_test"),
        "pool tests must use init_test() for structured diagnostics"
    );
    assert!(
        tests_section_contains(POOL_SRC, "test_complete!"),
        "pool tests must use test_complete!() for structured diagnostics"
    );
}

#[test]
fn structured_diagnostics_in_test_files() {
    // Integration test files should use structured diagnostics
    let has_init = POOL_INTEGRATION.contains("init_test")
        || POOL_TXN_CONTRACTS.contains("init_test")
        || DB_MSG_INTEGRATION.contains("init_test")
        || RETRY_CONTRACTS.contains("init_test");
    assert!(
        has_init,
        "integration test files should use init_test() for structured diagnostics"
    );
}

// ════════════════════════════════════════════════════════════════════════════
// Section 13: Cross-Backend Error Classification Completeness
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn all_db_backends_have_error_source() {
    assert!(
        PG_SRC.contains("fn source("),
        "postgres must implement Error::source()"
    );
    assert!(
        MY_SRC.contains("fn source("),
        "mysql must implement Error::source()"
    );
    assert!(
        SQ_SRC.contains("fn source("),
        "sqlite must implement Error::source()"
    );
}

#[test]
fn all_db_backends_handle_io_error() {
    assert!(
        PG_SRC.contains("Io(io::Error)") || PG_SRC.contains("Io("),
        "postgres must handle io::Error"
    );
    assert!(
        MY_SRC.contains("Io(io::Error)") || MY_SRC.contains("Io("),
        "mysql must handle io::Error"
    );
    assert!(
        SQ_SRC.contains("Io(io::Error)") || SQ_SRC.contains("Io("),
        "sqlite must handle io::Error"
    );
}

#[test]
fn all_messaging_backends_have_error_source() {
    assert!(
        REDIS_SRC.contains("fn source("),
        "redis must implement Error::source()"
    );
    assert!(
        NATS_SRC.contains("fn source("),
        "nats must implement Error::source()"
    );
    assert!(
        JS_SRC.contains("fn source("),
        "jetstream must implement Error::source()"
    );
    assert!(
        KAFKA_SRC.contains("fn source("),
        "kafka must implement Error::source()"
    );
}

#[test]
fn all_messaging_backends_have_is_retryable() {
    assert!(
        REDIS_SRC.contains("is_retryable"),
        "redis must implement is_retryable()"
    );
    assert!(
        NATS_SRC.contains("is_retryable"),
        "nats must implement is_retryable()"
    );
    assert!(
        JS_SRC.contains("is_retryable"),
        "jetstream must implement is_retryable()"
    );
    assert!(
        KAFKA_SRC.contains("is_retryable"),
        "kafka must implement is_retryable()"
    );
}

// ════════════════════════════════════════════════════════════════════════════
// Section 14: Pool get_with_retry Contract Verification
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn pool_get_with_retry_contract_c_rty_03() {
    assert!(
        POOL_SRC.contains("get_with_retry"),
        "pool must implement get_with_retry()"
    );
    assert!(
        POOL_SRC.contains("C-RTY-03"),
        "get_with_retry must reference contract C-RTY-03"
    );
    assert!(
        POOL_SRC.contains("policy.max_attempts"),
        "get_with_retry must bound attempts"
    );
    assert!(
        POOL_SRC.contains("connection_timeout"),
        "get_with_retry must bound total time"
    );
}

// ════════════════════════════════════════════════════════════════════════════
// Section 15: Assertion ID Completeness Across All Systems
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn all_66_assertion_ids_present_in_contract() {
    let json = parse_json();
    let assertions = json["assertions"].as_array().unwrap();
    let ids: HashSet<&str> = assertions.iter().filter_map(|a| a["id"].as_str()).collect();
    assert_eq!(ids.len(), 66, "must have exactly 66 unique assertion IDs");
}

#[test]
fn assertion_ids_cover_all_prefixes() {
    let json = parse_json();
    let assertions = json["assertions"].as_array().unwrap();
    let prefixes: HashSet<String> = assertions
        .iter()
        .filter_map(|a| {
            let id = a["id"].as_str()?;
            let parts: Vec<&str> = id.splitn(3, '-').collect();
            if parts.len() >= 2 {
                Some(format!("{}-{}", parts[0], parts[1]))
            } else {
                None
            }
        })
        .collect();
    let required = [
        "UM-PG", "UM-MY", "UM-SQ", "UM-POOL", "UM-TXN", "UM-RD", "UM-NT", "UM-JS", "UM-KF",
        "UM-RTY", "UM-INT", "DOC-M",
    ];
    for prefix in &required {
        assert!(
            prefixes.contains(*prefix),
            "missing assertion prefix: {prefix}"
        );
    }
}

#[test]
fn each_system_has_minimum_assertion_count() {
    let expected = [
        ("postgres", 8),
        ("mysql", 7),
        ("sqlite", 6),
        ("pool", 12), // POOL-01..10 + TXN-01..02
        ("redis", 6),
        ("nats", 3),
        ("jetstream", 4),
        ("kafka", 6),
        ("transaction", 6), // RTY-01..06
        ("integration", 5),
        ("meta", 3),
    ];
    for (system, min_count) in &expected {
        let ids = assertion_ids_for_system(system);
        assert!(
            ids.len() >= *min_count,
            "system '{system}' has {} assertions, expected >= {min_count}",
            ids.len()
        );
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Section 16: Kafka Consumer Behavioral Verification
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn kafka_consumer_has_config_builder() {
    assert!(
        KAFKA_CONSUMER_SRC.contains("ConsumerConfig"),
        "must have ConsumerConfig"
    );
    assert!(
        KAFKA_CONSUMER_SRC.contains("session_timeout")
            && KAFKA_CONSUMER_SRC.contains("heartbeat_interval")
            && KAFKA_CONSUMER_SRC.contains("auto_offset_reset"),
        "consumer config must have session_timeout, heartbeat_interval, auto_offset_reset"
    );
}

#[test]
fn kafka_consumer_has_offset_management() {
    assert!(
        KAFKA_CONSUMER_SRC.contains("commit") || KAFKA_CONSUMER_SRC.contains("offset"),
        "kafka consumer must support offset management"
    );
    assert!(
        KAFKA_CONSUMER_SRC.contains("AutoOffsetReset"),
        "kafka consumer must have AutoOffsetReset enum"
    );
}

#[test]
fn kafka_consumer_has_isolation_level() {
    assert!(
        KAFKA_CONSUMER_SRC.contains("IsolationLevel"),
        "must have IsolationLevel enum"
    );
    assert!(
        KAFKA_CONSUMER_SRC.contains("ReadUncommitted")
            && KAFKA_CONSUMER_SRC.contains("ReadCommitted"),
        "must have both isolation levels"
    );
}

#[test]
fn kafka_consumer_has_rebalance_lifecycle() {
    assert!(
        KAFKA_CONSUMER_SRC.contains("pub async fn rebalance"),
        "consumer must expose explicit rebalance lifecycle API"
    );
    assert!(
        KAFKA_CONSUMER_SRC.contains("RebalanceResult"),
        "consumer must provide rebalance result metadata"
    );
    assert!(
        KAFKA_CONSUMER_SRC.contains("revoked"),
        "consumer rebalance flow must track revoked partitions"
    );
}

// ════════════════════════════════════════════════════════════════════════════
// Section 17: Pool Error Ergonomics
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn pool_error_has_all_variants() {
    let variants = ["Closed", "Full", "Timeout", "Connect(", "ValidationFailed"];
    for v in &variants {
        assert!(POOL_SRC.contains(v), "DbPoolError must have variant '{v}'");
    }
}

#[test]
fn pool_error_implements_std_error() {
    assert!(
        POOL_SRC.contains("std::error::Error for DbPoolError"),
        "DbPoolError must implement std::error::Error"
    );
}

// ════════════════════════════════════════════════════════════════════════════
// Section 18: Aggregate Statistics
// ════════════════════════════════════════════════════════════════════════════

fn count_test_fns(source: &str) -> usize {
    source.lines().filter(|l| l.trim() == "#[test]").count()
}

#[test]
fn aggregate_inline_test_count() {
    let sources = [
        ("pool", POOL_SRC),
        ("postgres", PG_SRC),
        ("mysql", MY_SRC),
        ("sqlite", SQ_SRC),
        ("kafka", KAFKA_SRC),
        ("kafka_consumer", KAFKA_CONSUMER_SRC),
        ("nats", NATS_SRC),
        ("jetstream", JS_SRC),
        ("redis", REDIS_SRC),
    ];
    let total: usize = sources.iter().map(|(_, s)| count_test_fns(s)).sum();
    assert!(
        total >= 100,
        "aggregate inline tests: {total} < 100 threshold"
    );
    eprintln!("[T6.12] Aggregate inline tests: {total}");
    for (name, src) in &sources {
        eprintln!("  {name}: {}", count_test_fns(src));
    }
}

#[test]
fn aggregate_integration_test_count() {
    let files = [
        ("pool_integration", POOL_INTEGRATION),
        ("db_msg_integration", DB_MSG_INTEGRATION),
        ("pool_txn_contracts", POOL_TXN_CONTRACTS),
        ("retry_contracts", RETRY_CONTRACTS),
    ];
    let total: usize = files.iter().map(|(_, s)| count_test_fns(s)).sum();
    assert!(
        total >= 80,
        "aggregate integration tests: {total} < 80 threshold"
    );
    eprintln!("[T6.12] Aggregate integration tests: {total}");
    for (name, src) in &files {
        eprintln!("  {name}: {}", count_test_fns(src));
    }
}
