//! Integration tests for database pool + transaction management helpers.
//!
//! These tests exercise the public API surface of `database::pool`,
//! `database::transaction`, and the PgError helper methods, verifying
//! that all pieces compose correctly.
//!
//! Requires: `--features postgres` (for Pg-specific tests) or
//! `--features sqlite` (for SQLite-specific tests).

mod common;

use asupersync::database::pool::{ConnectionManager, DbPool, DbPoolConfig, DbPoolError};
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

// ─── Test infrastructure ─────────────────────────────────────────────────────

fn init_test(name: &str) {
    common::init_test_logging();
    asupersync::test_phase!(name);
}

/// Minimal in-memory connection for pool integration tests.
#[derive(Debug)]
struct MockConnection {
    id: usize,
    valid: Arc<AtomicBool>,
    operations: Arc<AtomicUsize>,
}

impl MockConnection {
    fn do_work(&self) {
        self.operations.fetch_add(1, Ordering::SeqCst);
    }

    fn operations(&self) -> usize {
        self.operations.load(Ordering::SeqCst)
    }
}

#[derive(Debug)]
struct MockError(String);

impl fmt::Display for MockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MockError: {}", self.0)
    }
}

impl std::error::Error for MockError {}

struct MockManager {
    next_id: AtomicUsize,
    valid: Arc<AtomicBool>,
    operations: Arc<AtomicUsize>,
    creates: AtomicUsize,
    disconnects: AtomicUsize,
    fail_connect: AtomicBool,
}

impl MockManager {
    fn new() -> Self {
        Self {
            next_id: AtomicUsize::new(1),
            valid: Arc::new(AtomicBool::new(true)),
            operations: Arc::new(AtomicUsize::new(0)),
            creates: AtomicUsize::new(0),
            disconnects: AtomicUsize::new(0),
            fail_connect: AtomicBool::new(false),
        }
    }

    fn creates(&self) -> usize {
        self.creates.load(Ordering::SeqCst)
    }

    fn disconnects(&self) -> usize {
        self.disconnects.load(Ordering::SeqCst)
    }

    fn total_operations(&self) -> usize {
        self.operations.load(Ordering::SeqCst)
    }
}

impl ConnectionManager for MockManager {
    type Connection = MockConnection;
    type Error = MockError;

    fn connect(&self) -> Result<Self::Connection, Self::Error> {
        if self.fail_connect.load(Ordering::SeqCst) {
            return Err(MockError("connection refused".to_string()));
        }
        self.creates.fetch_add(1, Ordering::SeqCst);
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        Ok(MockConnection {
            id,
            valid: self.valid.clone(),
            operations: self.operations.clone(),
        })
    }

    fn is_valid(&self, conn: &Self::Connection) -> bool {
        conn.valid.load(Ordering::SeqCst)
    }

    fn disconnect(&self, _conn: Self::Connection) {
        self.disconnects.fetch_add(1, Ordering::SeqCst);
    }
}

// ─── Pool lifecycle integration ──────────────────────────────────────────────

#[test]
fn pool_checkout_work_return_cycle() {
    init_test("pool_checkout_work_return_cycle");
    let pool = DbPool::new(MockManager::new(), DbPoolConfig::with_max_size(3));

    // Checkout, do work, return.
    let conn = pool.get().unwrap();
    conn.do_work();
    conn.do_work();
    assert_eq!(pool.manager.total_operations(), 2);
    conn.return_to_pool();

    // Second checkout reuses the same connection.
    let conn2 = pool.get().unwrap();
    assert_eq!(conn2.id, 1);
    conn2.do_work();
    assert_eq!(pool.manager.total_operations(), 3);
    drop(conn2);

    assert_eq!(pool.stats().idle, 1);
    assert_eq!(pool.manager.creates(), 1);
    asupersync::test_complete!("pool_checkout_work_return_cycle");
}

#[test]
fn pool_concurrent_checkouts_respect_max() {
    init_test("pool_concurrent_checkouts_respect_max");
    let pool = DbPool::new(MockManager::new(), DbPoolConfig::with_max_size(3));

    let c1 = pool.get().unwrap();
    let c2 = pool.get().unwrap();
    let c3 = pool.get().unwrap();

    // All three active.
    assert_eq!(pool.stats().active, 3);
    assert_eq!(pool.stats().total, 3);

    // Fourth fails.
    assert!(matches!(pool.get(), Err(DbPoolError::Full)));

    // Return one → can get again.
    drop(c1);
    let c4 = pool.get().unwrap();
    assert_eq!(c4.id, 1); // reused
    drop(c2);
    drop(c3);
    drop(c4);

    assert_eq!(pool.stats().idle, 3);
    assert_eq!(pool.stats().active, 0);
    asupersync::test_complete!("pool_concurrent_checkouts_respect_max");
}

#[test]
fn pool_discard_and_recreate() {
    init_test("pool_discard_and_recreate");
    let pool = DbPool::new(MockManager::new(), DbPoolConfig::with_max_size(2));

    let conn = pool.get().unwrap();
    assert_eq!(conn.id, 1);
    conn.discard();

    assert_eq!(pool.stats().total, 0);
    assert_eq!(pool.stats().total_discards, 1);
    assert_eq!(pool.manager.disconnects(), 1);

    // New connection gets a new ID.
    let conn2 = pool.get().unwrap();
    assert_eq!(conn2.id, 2);
    assert_eq!(pool.manager.creates(), 2);
    asupersync::test_complete!("pool_discard_and_recreate");
}

#[test]
fn pool_warmup_and_drain() {
    init_test("pool_warmup_and_drain");
    let pool = DbPool::new(
        MockManager::new(),
        DbPoolConfig::with_max_size(5).min_idle(3),
    );

    let created = pool.warm_up();
    assert_eq!(created, 3);
    assert_eq!(pool.stats().idle, 3);

    // Use one connection.
    let conn = pool.get().unwrap();
    assert_eq!(pool.stats().active, 1);
    assert_eq!(pool.stats().idle, 2);
    conn.do_work();
    drop(conn);

    // Close drains everything.
    pool.close();
    assert!(pool.is_closed());
    assert_eq!(pool.stats().idle, 0);
    assert_eq!(pool.manager.disconnects(), 3);

    // No more checkouts.
    assert!(matches!(pool.get(), Err(DbPoolError::Closed)));
    asupersync::test_complete!("pool_warmup_and_drain");
}

#[test]
fn pool_close_while_checked_out() {
    init_test("pool_close_while_checked_out");
    let pool = DbPool::new(MockManager::new(), DbPoolConfig::default());

    let conn = pool.get().unwrap();
    pool.close();

    // Returning after close → disconnected.
    conn.return_to_pool();
    assert_eq!(pool.stats().total, 0);
    assert_eq!(pool.manager.disconnects(), 1);
    asupersync::test_complete!("pool_close_while_checked_out");
}

#[test]
fn pool_connect_failure_recovery() {
    init_test("pool_connect_failure_recovery");
    let pool = DbPool::new(MockManager::new(), DbPoolConfig::with_max_size(2));

    // Fail first.
    pool.manager.fail_connect.store(true, Ordering::SeqCst);
    assert!(pool.get().is_err());
    assert_eq!(pool.stats().total, 0);

    // Recover.
    pool.manager.fail_connect.store(false, Ordering::SeqCst);
    let conn = pool.get().unwrap();
    conn.do_work();
    assert_eq!(pool.manager.total_operations(), 1);
    asupersync::test_complete!("pool_connect_failure_recovery");
}

#[test]
fn pool_try_get_nonblocking() {
    init_test("pool_try_get_nonblocking");
    let pool = DbPool::new(MockManager::new(), DbPoolConfig::with_max_size(1));

    let held = pool.get().unwrap();
    assert!(pool.try_get().is_none());

    drop(held);
    let got = pool.try_get();
    assert!(got.is_some());
    asupersync::test_complete!("pool_try_get_nonblocking");
}

#[test]
fn pool_stats_cumulative() {
    init_test("pool_stats_cumulative");
    let pool = DbPool::new(MockManager::new(), DbPoolConfig::with_max_size(2));

    let c1 = pool.get().unwrap();
    let c2 = pool.get().unwrap();
    c1.return_to_pool();
    c2.discard();

    let c3 = pool.get().unwrap(); // reuses c1
    drop(c3);

    let stats = pool.stats();
    assert_eq!(stats.total_creates, 2);
    assert_eq!(stats.total_acquisitions, 3);
    assert_eq!(stats.total_discards, 1);
    assert_eq!(stats.idle, 1);
    assert_eq!(stats.total, 1);
    asupersync::test_complete!("pool_stats_cumulative");
}

#[test]
fn pooled_connection_deref_access() {
    init_test("pooled_connection_deref_access");
    let pool = DbPool::new(MockManager::new(), DbPoolConfig::default());
    let mut conn = pool.get().unwrap();

    // Deref to MockConnection.
    assert_eq!(conn.id, 1);
    // DerefMut.
    conn.do_work();
    assert_eq!(conn.operations(), 1);
    asupersync::test_complete!("pooled_connection_deref_access");
}

// ─── RetryPolicy integration ─────────────────────────────────────────────────

use asupersync::database::transaction::RetryPolicy;

#[test]
fn retry_policy_backoff_progression() {
    init_test("retry_policy_backoff_progression");
    let policy = RetryPolicy {
        max_retries: 5,
        base_delay: Duration::from_millis(10),
        max_delay: Duration::from_millis(500),
    };

    // Verify delays increase monotonically until cap.
    let d0 = policy.delay_for(0);
    let d1 = policy.delay_for(1);
    let d2 = policy.delay_for(2);
    let d3 = policy.delay_for(3);
    assert!(d1 > d0, "delay should increase: {d1:?} > {d0:?}");
    assert!(d2 > d1, "delay should increase: {d2:?} > {d1:?}");
    assert!(d3 >= d2, "delay should increase or cap: {d3:?} >= {d2:?}");

    // All capped at max.
    for attempt in 0..10 {
        assert!(policy.delay_for(attempt) <= Duration::from_millis(500));
    }
    asupersync::test_complete!("retry_policy_backoff_progression");
}

#[test]
fn retry_policy_zero_base_delay() {
    init_test("retry_policy_zero_base_delay");
    let policy = RetryPolicy {
        max_retries: 3,
        base_delay: Duration::ZERO,
        max_delay: Duration::from_secs(1),
    };

    // Zero base delay → always zero.
    assert_eq!(policy.delay_for(0), Duration::ZERO);
    assert_eq!(policy.delay_for(5), Duration::ZERO);
    asupersync::test_complete!("retry_policy_zero_base_delay");
}

// ─── PgError helper methods ──────────────────────────────────────────────────

#[cfg(feature = "postgres")]
mod pg_error_tests {
    use super::*;
    use asupersync::database::PgError;

    fn init_test(name: &str) {
        common::init_test_logging();
        asupersync::test_phase!(name);
    }

    fn server_error(code: &str, message: &str) -> PgError {
        PgError::Server {
            code: code.to_string(),
            message: message.to_string(),
            detail: None,
            hint: None,
        }
    }

    #[test]
    fn pg_error_serialization_failure() {
        init_test("pg_error_serialization_failure");
        let err = server_error("40001", "could not serialize access");
        assert!(err.is_serialization_failure());
        assert!(!err.is_deadlock());
        assert!(!err.is_unique_violation());
        assert_eq!(err.code(), Some("40001"));
        asupersync::test_complete!("pg_error_serialization_failure");
    }

    #[test]
    fn pg_error_deadlock() {
        init_test("pg_error_deadlock");
        let err = server_error("40P01", "deadlock detected");
        assert!(err.is_deadlock());
        assert!(!err.is_serialization_failure());
        assert_eq!(err.code(), Some("40P01"));
        asupersync::test_complete!("pg_error_deadlock");
    }

    #[test]
    fn pg_error_unique_violation() {
        init_test("pg_error_unique_violation");
        let err = server_error("23505", "duplicate key value violates unique constraint");
        assert!(err.is_unique_violation());
        assert!(!err.is_serialization_failure());
        assert_eq!(err.code(), Some("23505"));
        asupersync::test_complete!("pg_error_unique_violation");
    }

    #[test]
    fn pg_error_no_code_for_non_server() {
        init_test("pg_error_no_code_for_non_server");
        let err = PgError::ConnectionClosed;
        assert!(err.code().is_none());
        assert!(!err.is_serialization_failure());
        assert!(!err.is_deadlock());
        assert!(!err.is_unique_violation());
        asupersync::test_complete!("pg_error_no_code_for_non_server");
    }

    #[test]
    fn pg_error_transaction_finished() {
        init_test("pg_error_transaction_finished");
        let err = PgError::TransactionFinished;
        assert!(err.code().is_none());
        let display = format!("{err}");
        assert!(display.contains("finished"));
        asupersync::test_complete!("pg_error_transaction_finished");
    }

    #[test]
    fn pg_error_with_detail_and_hint() {
        init_test("pg_error_with_detail_and_hint");
        let err = PgError::Server {
            code: "42P01".to_string(),
            message: "relation does not exist".to_string(),
            detail: Some("table \"missing\" not found".to_string()),
            hint: Some("Create the table first.".to_string()),
        };
        assert_eq!(err.code(), Some("42P01"));
        let display = format!("{err}");
        assert!(display.contains("42P01"));
        assert!(display.contains("detail"));
        assert!(display.contains("hint"));
        asupersync::test_complete!("pg_error_with_detail_and_hint");
    }

    #[test]
    fn pg_error_other_codes_not_retryable() {
        init_test("pg_error_other_codes_not_retryable");
        // Syntax error is not a serialization failure.
        let err = server_error("42601", "syntax error at or near");
        assert!(!err.is_serialization_failure());
        assert!(!err.is_deadlock());
        assert_eq!(err.code(), Some("42601"));
        asupersync::test_complete!("pg_error_other_codes_not_retryable");
    }
}

// ─── Pool + operations composition ──────────────────────────────────────────

#[test]
fn pool_multiple_operations_per_checkout() {
    init_test("pool_multiple_operations_per_checkout");
    let pool = DbPool::new(MockManager::new(), DbPoolConfig::default());

    // Simulate: checkout → multiple operations → return.
    let conn = pool.get().unwrap();
    for _ in 0..10 {
        conn.do_work();
    }
    assert_eq!(conn.operations(), 10);
    conn.return_to_pool();

    // Reuse same connection.
    let conn2 = pool.get().unwrap();
    conn2.do_work();
    assert_eq!(pool.manager.total_operations(), 11);
    asupersync::test_complete!("pool_multiple_operations_per_checkout");
}

#[test]
fn pool_interleaved_checkout_return() {
    init_test("pool_interleaved_checkout_return");
    let pool = DbPool::new(MockManager::new(), DbPoolConfig::with_max_size(2));

    // c1 checkout → c2 checkout → c1 return → c3 checkout (reuses c1).
    let c1 = pool.get().unwrap();
    let c2 = pool.get().unwrap();
    let id1 = c1.id;
    c1.return_to_pool();

    let c3 = pool.get().unwrap();
    assert_eq!(c3.id, id1);
    assert_eq!(pool.stats().total_creates, 2);

    drop(c2);
    drop(c3);
    assert_eq!(pool.stats().idle, 2);
    asupersync::test_complete!("pool_interleaved_checkout_return");
}

#[test]
fn pool_discard_doesnt_block_new_gets() {
    init_test("pool_discard_doesnt_block_new_gets");
    let pool = DbPool::new(MockManager::new(), DbPoolConfig::with_max_size(1));

    let conn = pool.get().unwrap();
    conn.discard(); // capacity freed

    let conn2 = pool.get().unwrap();
    assert_ne!(conn2.id, 0); // got a valid new connection
    asupersync::test_complete!("pool_discard_doesnt_block_new_gets");
}

// ─── Config edge cases ───────────────────────────────────────────────────────

#[test]
fn pool_config_min_idle_zero() {
    init_test("pool_config_min_idle_zero");
    let pool = DbPool::new(
        MockManager::new(),
        DbPoolConfig::with_max_size(5).min_idle(0),
    );
    let created = pool.warm_up();
    assert_eq!(created, 0);
    assert_eq!(pool.stats().idle, 0);
    asupersync::test_complete!("pool_config_min_idle_zero");
}

#[test]
fn pool_config_max_size_one() {
    init_test("pool_config_max_size_one");
    let pool = DbPool::new(MockManager::new(), DbPoolConfig::with_max_size(1));

    let c = pool.get().unwrap();
    assert!(matches!(pool.get(), Err(DbPoolError::Full)));
    c.return_to_pool();
    let _ = pool.get().unwrap();
    asupersync::test_complete!("pool_config_max_size_one");
}

// ─── Validation integration ──────────────────────────────────────────────────

#[test]
fn pool_validation_skip_when_disabled() {
    init_test("pool_validation_skip_when_disabled");
    let pool = DbPool::new(
        MockManager::new(),
        DbPoolConfig::default().validate_on_checkout(false),
    );

    let conn = pool.get().unwrap();
    conn.return_to_pool();

    pool.manager.valid.store(false, Ordering::SeqCst);
    // Still succeeds — no validation.
    let conn2 = pool.get().unwrap();
    assert_eq!(pool.stats().total_validation_failures, 0);
    drop(conn2);
    asupersync::test_complete!("pool_validation_skip_when_disabled");
}

// ─── Pool error variants ─────────────────────────────────────────────────────

#[test]
fn pool_error_variants() {
    init_test("pool_error_variants");

    let closed: DbPoolError<MockError> = DbPoolError::Closed;
    assert!(format!("{closed}").contains("closed"));
    assert!(format!("{closed:?}").contains("Closed"));

    let full: DbPoolError<MockError> = DbPoolError::Full;
    assert!(format!("{full}").contains("capacity"));

    let timeout: DbPoolError<MockError> = DbPoolError::Timeout;
    assert!(format!("{timeout}").contains("timed out"));

    let connect_err: DbPoolError<MockError> =
        DbPoolError::Connect(MockError("refused".into()));
    assert!(format!("{connect_err}").contains("refused"));

    let validation: DbPoolError<MockError> = DbPoolError::ValidationFailed;
    assert!(format!("{validation}").contains("validation"));

    // Error trait source
    use std::error::Error;
    assert!(closed.source().is_none());
    assert!(connect_err.source().is_some());
    asupersync::test_complete!("pool_error_variants");
}

// ─── RetryPolicy edge cases ─────────────────────────────────────────────────

#[test]
fn retry_policy_large_attempt_numbers() {
    init_test("retry_policy_large_attempt_numbers");
    let policy = RetryPolicy::default_retry();

    // Should not panic on any attempt number.
    for attempt in [0, 1, 10, 31, 32, 63, 64, 100, 255, u32::MAX] {
        let delay = policy.delay_for(attempt);
        assert!(delay <= policy.max_delay);
    }
    asupersync::test_complete!("retry_policy_large_attempt_numbers");
}

#[test]
fn retry_policy_very_large_base_delay() {
    init_test("retry_policy_very_large_base_delay");
    let policy = RetryPolicy {
        max_retries: 5,
        base_delay: Duration::from_secs(u64::MAX / 2),
        max_delay: Duration::from_secs(60),
    };

    // Should cap at max_delay, not overflow.
    let delay = policy.delay_for(0);
    assert!(delay <= Duration::from_secs(60));
    let delay = policy.delay_for(5);
    assert!(delay <= Duration::from_secs(60));
    asupersync::test_complete!("retry_policy_very_large_base_delay");
}
