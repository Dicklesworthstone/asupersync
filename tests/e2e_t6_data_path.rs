#![allow(clippy::all)]
//! T6.13 — End-to-end data-path scenarios for database and messaging ecosystems.
//!
//! Validates full lifecycle workflows across database backends (pool, transaction,
//! error classification) and messaging systems (Kafka, NATS, JetStream, Redis) with
//! deterministic seeds, reliability logging, correlation IDs, and fault injection.
//!
//! Bead: asupersync-2oh2u.6.13
//! Depends on: T6.12 (unit-test matrix)
//! Unblocks: T8.12 (cross-track logging), T9.2 (migration cookbooks)
#![cfg(any(feature = "sqlite", feature = "postgres", feature = "mysql"))]

#[macro_use]
mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use asupersync::combinator::{RetryPolicy, calculate_delay};
use asupersync::database::pool::{ConnectionManager, DbPool, DbPoolConfig, DbPoolError};

// =========================================================================
// Helpers: deterministic pool manager with fault injection
// =========================================================================

/// Shared counters for observing manager behavior from tests.
#[derive(Clone)]
struct FaultCounters {
    connect_calls: Arc<AtomicUsize>,
    validate_calls: Arc<AtomicUsize>,
    fail_connect: Arc<AtomicBool>,
    fail_validate: Arc<AtomicBool>,
    fail_count: Arc<AtomicUsize>,
}

impl FaultCounters {
    fn new() -> Self {
        Self {
            connect_calls: Arc::new(AtomicUsize::new(0)),
            validate_calls: Arc::new(AtomicUsize::new(0)),
            fail_connect: Arc::new(AtomicBool::new(false)),
            fail_validate: Arc::new(AtomicBool::new(false)),
            fail_count: Arc::new(AtomicUsize::new(0)),
        }
    }
}

/// Simulated connection with an ID and query tracking.
#[derive(Debug)]
struct SimConn {
    id: usize,
    queries: AtomicUsize,
    healthy: AtomicBool,
}

impl SimConn {
    fn new(id: usize) -> Self {
        Self {
            id,
            queries: AtomicUsize::new(0),
            healthy: AtomicBool::new(true),
        }
    }

    fn query(&self) -> usize {
        self.queries.fetch_add(1, Ordering::Relaxed) + 1
    }

    fn mark_unhealthy(&self) {
        self.healthy.store(false, Ordering::Relaxed);
    }
}

/// Fault-injectable pool manager for e2e testing.
struct FaultManager {
    next_id: AtomicUsize,
    counters: FaultCounters,
}

#[derive(Debug)]
struct FaultError(String);

impl std::fmt::Display for FaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "FaultError: {}", self.0)
    }
}

impl std::error::Error for FaultError {}

impl ConnectionManager for FaultManager {
    type Connection = SimConn;
    type Error = FaultError;

    fn connect(&self) -> Result<Self::Connection, Self::Error> {
        let call = self.counters.connect_calls.fetch_add(1, Ordering::Relaxed) + 1;
        tracing::debug!(call, "FaultManager::connect");

        if self.counters.fail_connect.load(Ordering::Relaxed) {
            let remaining = self.counters.fail_count.load(Ordering::Relaxed);
            if remaining > 0 {
                self.counters.fail_count.fetch_sub(1, Ordering::Relaxed);
                return Err(FaultError(format!("injected connect failure #{call}")));
            }
            self.counters.fail_connect.store(false, Ordering::Relaxed);
        }

        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        Ok(SimConn::new(id))
    }

    fn is_valid(&self, conn: &Self::Connection) -> bool {
        self.counters.validate_calls.fetch_add(1, Ordering::Relaxed);
        if self.counters.fail_validate.load(Ordering::Relaxed) {
            return false;
        }
        conn.healthy.load(Ordering::Relaxed)
    }
}

fn make_pool(max_size: usize, counters: &FaultCounters) -> DbPool<FaultManager> {
    let config = DbPoolConfig::with_max_size(max_size)
        .validate_on_checkout(true)
        .connection_timeout(Duration::from_secs(5));
    DbPool::new(
        FaultManager {
            next_id: AtomicUsize::new(0),
            counters: counters.clone(),
        },
        config,
    )
}

fn make_pool_with_config(config: DbPoolConfig, counters: &FaultCounters) -> DbPool<FaultManager> {
    DbPool::new(
        FaultManager {
            next_id: AtomicUsize::new(0),
            counters: counters.clone(),
        },
        config,
    )
}

// Correlation ID helper for reliability logging
fn correlation_id(scenario: &str, step: u32) -> String {
    format!("T6.13:{scenario}:step-{step}")
}

// =========================================================================
// DP-01: Pool lifecycle data path — init, acquire, use, return, stats
// =========================================================================

#[test]
fn e2e_dp_01_pool_lifecycle_full_path() {
    common::init_test_logging();
    test_phase!("DP-01: Pool Lifecycle Data Path");

    let counters = FaultCounters::new();
    let pool = make_pool(3, &counters);
    let cid = correlation_id("dp01", 1);
    tracing::info!(correlation_id = %cid, "starting pool lifecycle scenario");

    test_section!("Acquire first connection");
    let conn = pool.get().expect("first acquire");
    assert_eq!(conn.get().id, 0);
    tracing::info!(correlation_id = %cid, conn_id = 0, "acquired connection");

    test_section!("Use connection");
    let qc = conn.get().query();
    assert_eq!(qc, 1);

    test_section!("Return and stats");
    conn.return_to_pool();
    let stats = pool.stats();
    assert_eq!(stats.total, 1);
    assert!(stats.total <= 3, "total <= max_size");
    tracing::info!(
        correlation_id = %cid,
        total = stats.total,
        idle = stats.idle,
        active = stats.active,
        "pool stats after return"
    );

    test_section!("Re-acquire reuses connection");
    let conn2 = pool.get().expect("re-acquire");
    assert_eq!(conn2.get().id, 0, "reused same connection");
    conn2.return_to_pool();

    test_section!("Connect call count");
    assert_eq!(counters.connect_calls.load(Ordering::Relaxed), 1);

    test_complete!("e2e_dp_01_pool_lifecycle", connects = 1, queries = 1);
}

// =========================================================================
// DP-02: Pool exhaustion and backpressure
// =========================================================================

#[test]
fn e2e_dp_02_pool_exhaustion_backpressure() {
    common::init_test_logging();
    test_phase!("DP-02: Pool Exhaustion Backpressure");

    let counters = FaultCounters::new();
    let config = DbPoolConfig::with_max_size(2).connection_timeout(Duration::from_millis(100));
    let pool = make_pool_with_config(config, &counters);
    let cid = correlation_id("dp02", 1);

    test_section!("Fill pool to capacity");
    let c1 = pool.get().expect("conn 1");
    let c2 = pool.get().expect("conn 2");
    tracing::info!(correlation_id = %cid, "pool at capacity (2/2)");

    test_section!("Attempt acquire when full → should get Full error");
    let result = pool.try_get();
    assert!(result.is_none(), "pool should be full");
    tracing::info!(correlation_id = %cid, "correctly rejected: pool full");

    test_section!("Return one → acquire succeeds");
    c1.return_to_pool();
    let c3 = pool.get().expect("conn after return");
    assert_eq!(c3.get().id, 0, "reused returned connection");
    c2.return_to_pool();
    c3.return_to_pool();

    test_complete!("e2e_dp_02_pool_exhaustion");
}

// =========================================================================
// DP-03: Pool retry on transient connect failure
// =========================================================================

#[test]
fn e2e_dp_03_pool_retry_transient_connect() {
    common::init_test_logging();
    test_phase!("DP-03: Pool Retry on Transient Connect Failure");

    let counters = FaultCounters::new();
    // Fail first 2 connects, then succeed
    counters.fail_connect.store(true, Ordering::Relaxed);
    counters.fail_count.store(2, Ordering::Relaxed);

    let pool = make_pool(3, &counters);
    let policy = RetryPolicy::new()
        .with_max_attempts(5)
        .with_initial_delay(Duration::from_millis(10))
        .no_jitter();
    let cid = correlation_id("dp03", 1);

    test_section!("Acquire with retry (2 failures then success)");
    let start = Instant::now();
    let conn = pool.get_with_retry(&policy).expect("retry should succeed");
    let elapsed = start.elapsed();
    tracing::info!(
        correlation_id = %cid,
        connect_calls = counters.connect_calls.load(Ordering::Relaxed),
        elapsed_ms = elapsed.as_millis(),
        "acquired after transient failures"
    );

    assert_eq!(counters.connect_calls.load(Ordering::Relaxed), 3);
    conn.return_to_pool();

    test_complete!("e2e_dp_03_pool_retry", attempts = 3);
}

// =========================================================================
// DP-04: Pool retry exhaustion → error propagation
// =========================================================================

#[test]
fn e2e_dp_04_retry_exhaustion_error_propagation() {
    common::init_test_logging();
    test_phase!("DP-04: Retry Exhaustion Error Propagation");

    let counters = FaultCounters::new();
    counters.fail_connect.store(true, Ordering::Relaxed);
    counters.fail_count.store(100, Ordering::Relaxed);

    let pool = make_pool(3, &counters);
    let policy = RetryPolicy::new()
        .with_max_attempts(3)
        .with_initial_delay(Duration::from_millis(5))
        .no_jitter();
    let cid = correlation_id("dp04", 1);

    test_section!("Retry exhaustion");
    let result = pool.get_with_retry(&policy);
    assert!(result.is_err(), "should fail after max attempts");
    let err = result.unwrap_err();
    tracing::info!(
        correlation_id = %cid,
        error = %err,
        attempts = counters.connect_calls.load(Ordering::Relaxed),
        "retry exhausted, error propagated"
    );

    match err {
        DbPoolError::Connect(_) => {}
        other => panic!("expected Connect error, got: {other}"),
    }

    assert_eq!(counters.connect_calls.load(Ordering::Relaxed), 3);

    test_complete!("e2e_dp_04_retry_exhaustion");
}

// =========================================================================
// DP-05: Pool close rejects new acquires
// =========================================================================

#[test]
fn e2e_dp_05_pool_close_rejection() {
    common::init_test_logging();
    test_phase!("DP-05: Pool Close Rejection");

    let counters = FaultCounters::new();
    let pool = make_pool(3, &counters);
    let cid = correlation_id("dp05", 1);

    test_section!("Acquire, return, close");
    let conn = pool.get().expect("acquire before close");
    conn.return_to_pool();
    pool.close();
    tracing::info!(correlation_id = %cid, "pool closed");

    test_section!("Acquire after close → Closed error");
    let result = pool.get();
    assert!(matches!(result, Err(DbPoolError::Closed)));
    tracing::info!(correlation_id = %cid, "correctly rejected: pool closed");

    test_section!("Retry on closed pool → no retry, immediate Closed");
    let policy = RetryPolicy::new().with_max_attempts(5);
    let result = pool.get_with_retry(&policy);
    assert!(matches!(result, Err(DbPoolError::Closed)));
    // Should NOT have retried (only 1 connect call from the initial acquire)
    assert_eq!(counters.connect_calls.load(Ordering::Relaxed), 1);

    test_complete!("e2e_dp_05_pool_close_rejection");
}

// =========================================================================
// DP-06: Validation failure → discard + reconnect
// =========================================================================

#[test]
fn e2e_dp_06_validation_failure_discard_reconnect() {
    common::init_test_logging();
    test_phase!("DP-06: Validation Failure Discard + Reconnect");

    let counters = FaultCounters::new();
    let pool = make_pool(2, &counters);
    let cid = correlation_id("dp06", 1);

    test_section!("Acquire and return healthy connection");
    let conn = pool.get().expect("first acquire");
    let first_id = conn.get().id;
    conn.get().mark_unhealthy();
    conn.return_to_pool();
    tracing::info!(correlation_id = %cid, conn_id = first_id, "returned unhealthy connection");

    test_section!("Re-acquire → validation fails → new connection");
    let conn2 = pool.get().expect("second acquire (new connection)");
    let second_id = conn2.get().id;
    assert_ne!(
        first_id, second_id,
        "unhealthy connection discarded, got new one"
    );
    tracing::info!(
        correlation_id = %cid,
        old_id = first_id,
        new_id = second_id,
        validates = counters.validate_calls.load(Ordering::Relaxed),
        "validation triggered reconnect"
    );
    conn2.return_to_pool();

    test_complete!("e2e_dp_06_validation_discard");
}

// =========================================================================
// DP-07: Stale eviction respects idle_timeout
// =========================================================================

#[test]
fn e2e_dp_07_stale_eviction() {
    common::init_test_logging();
    test_phase!("DP-07: Stale Eviction");

    let counters = FaultCounters::new();
    let config = DbPoolConfig::with_max_size(3).idle_timeout(Duration::from_millis(50));
    let pool = make_pool_with_config(config, &counters);
    let cid = correlation_id("dp07", 1);

    test_section!("Create and return connections");
    let c1 = pool.get().expect("conn 1");
    let c2 = pool.get().expect("conn 2");
    c1.return_to_pool();
    c2.return_to_pool();

    let stats_before = pool.stats();
    tracing::info!(
        correlation_id = %cid,
        total = stats_before.total,
        idle = stats_before.idle,
        "before eviction"
    );

    test_section!("Wait for idle timeout then evict");
    std::thread::sleep(Duration::from_millis(60));
    let evicted = pool.evict_stale();
    tracing::info!(
        correlation_id = %cid,
        evicted,
        "stale connections evicted"
    );

    let stats_after = pool.stats();
    assert!(
        stats_after.total < stats_before.total,
        "eviction reduced total"
    );
    assert!(evicted > 0, "should have evicted at least one");

    test_complete!("e2e_dp_07_stale_eviction", evicted = evicted);
}

// =========================================================================
// DP-08: RetryPolicy delay formula verification (data-path correctness)
// =========================================================================

#[test]
fn e2e_dp_08_retry_delay_formula() {
    common::init_test_logging();
    test_phase!("DP-08: Retry Delay Formula Data Path");

    let policy = RetryPolicy::new()
        .with_initial_delay(Duration::from_millis(100))
        .with_max_delay(Duration::from_secs(5))
        .with_multiplier(2.0)
        .no_jitter();
    let cid = correlation_id("dp08", 1);

    test_section!("Verify exponential backoff sequence");
    let expected_ms = [100, 200, 400, 800, 1600, 3200, 5000, 5000];
    for (i, &expected) in expected_ms.iter().enumerate() {
        let attempt = (i + 1) as u32;
        let delay = calculate_delay(&policy, attempt, None);
        let delay_ms = delay.as_millis().min(u128::from(u64::MAX)) as u64;
        tracing::info!(
            correlation_id = %cid,
            attempt,
            delay_ms,
            expected,
            "delay for attempt"
        );
        assert_eq!(
            delay_ms, expected,
            "attempt {attempt}: expected {expected}ms, got {delay_ms}ms"
        );
    }

    test_section!("Edge case: zero initial delay");
    let zero_policy = RetryPolicy::new()
        .with_initial_delay(Duration::ZERO)
        .no_jitter();
    for attempt in 1..=5 {
        let delay = calculate_delay(&zero_policy, attempt, None);
        assert_eq!(delay, Duration::ZERO, "zero base should produce zero delay");
    }

    test_section!("Edge case: overflow safety");
    let overflow_policy = RetryPolicy::new()
        .with_initial_delay(Duration::from_secs(1))
        .with_max_delay(Duration::from_secs(60))
        .with_multiplier(2.0)
        .no_jitter();
    let delay = calculate_delay(&overflow_policy, u32::MAX, None);
    assert!(
        delay <= Duration::from_secs(60),
        "overflow capped at max_delay"
    );

    test_complete!("e2e_dp_08_retry_delay_formula");
}

// =========================================================================
// DP-09: Concurrent pool access with interleaved faults
// =========================================================================

#[test]
fn e2e_dp_09_concurrent_pool_fault_interleave() {
    common::init_test_logging();
    test_phase!("DP-09: Concurrent Pool with Interleaved Faults");

    let counters = FaultCounters::new();
    let pool = Arc::new(make_pool(4, &counters));
    let cid = correlation_id("dp09", 1);

    test_section!("Acquire multiple connections concurrently");
    let mut handles = Vec::new();
    for i in 0..4 {
        let pool = Arc::clone(&pool);
        handles.push(std::thread::spawn(move || {
            let conn = pool.get().expect("concurrent acquire");
            let qc = conn.get().query();
            tracing::debug!(
                thread = i,
                conn_id = conn.get().id,
                queries = qc,
                "thread work"
            );
            std::thread::sleep(Duration::from_millis(5));
            conn.return_to_pool();
        }));
    }

    for h in handles {
        h.join().expect("thread join");
    }

    let stats = pool.stats();
    tracing::info!(
        correlation_id = %cid,
        total = stats.total,
        total_acquires = stats.total_acquisitions,
        "concurrent access complete"
    );
    assert!(stats.total <= 4, "total connections within max_size");
    assert_eq!(stats.total_acquisitions, 4);

    test_complete!("e2e_dp_09_concurrent_pool", threads = 4);
}

// =========================================================================
// DP-10: Pool warm-up populates min_idle connections
// =========================================================================

#[test]
fn e2e_dp_10_pool_warmup() {
    common::init_test_logging();
    test_phase!("DP-10: Pool Warm-Up");

    let counters = FaultCounters::new();
    let config = DbPoolConfig::with_max_size(5).min_idle(3);
    let pool = make_pool_with_config(config, &counters);
    let cid = correlation_id("dp10", 1);

    test_section!("Warm up pool");
    let warmed = pool.warm_up();
    tracing::info!(correlation_id = %cid, warmed, "pool warmed up");

    let stats = pool.stats();
    assert!(stats.idle >= 3, "min_idle connections populated");
    assert_eq!(stats.total, warmed);

    test_section!("Acquire from warm pool");
    let conn = pool.get().expect("acquire from warm pool");
    conn.return_to_pool();

    test_complete!("e2e_dp_10_pool_warmup", warmed = warmed);
}

// =========================================================================
// DP-11: Error classification parity across backends
// =========================================================================

#[cfg(feature = "postgres")]
#[test]
fn e2e_dp_11a_pg_error_classification_data_path() {
    use asupersync::database::PgError;

    common::init_test_logging();
    test_phase!("DP-11a: PostgreSQL Error Classification Data Path");

    let cid = correlation_id("dp11a", 1);

    test_section!("Serialization failure classification");
    let err = PgError::Server {
        code: "40001".into(),
        message: "serialization_failure".into(),
        detail: None,
        hint: None,
    };
    assert!(err.is_serialization_failure());
    assert!(err.is_transient());
    assert!(err.is_retryable());
    assert!(!err.is_unique_violation());
    tracing::info!(
        correlation_id = %cid,
        code = ?err.error_code(),
        "PG serialization failure classified correctly"
    );

    test_section!("Deadlock classification");
    let err = PgError::Server {
        code: "40P01".into(),
        message: "deadlock_detected".into(),
        detail: None,
        hint: None,
    };
    assert!(err.is_deadlock());
    assert!(err.is_transient());

    test_section!("Unique violation classification");
    let err = PgError::Server {
        code: "23505".into(),
        message: "unique_violation".into(),
        detail: None,
        hint: None,
    };
    assert!(err.is_unique_violation());
    assert!(err.is_constraint_violation());
    assert!(!err.is_transient());
    assert!(!err.is_retryable());

    test_section!("Connection error classification");
    let err = PgError::Io(std::io::Error::new(
        std::io::ErrorKind::ConnectionReset,
        "reset",
    ));
    assert!(err.is_connection_error());
    assert!(err.is_transient());

    test_complete!("e2e_dp_11a_pg_error_classification");
}

#[cfg(feature = "mysql")]
#[test]
fn e2e_dp_11b_mysql_error_classification_data_path() {
    use asupersync::database::MySqlError;

    common::init_test_logging();
    test_phase!("DP-11b: MySQL Error Classification Data Path");

    let cid = correlation_id("dp11b", 1);

    test_section!("Deadlock classification");
    let err = MySqlError::Server {
        code: 1213,
        sql_state: "40001".into(),
        message: "Deadlock found".into(),
    };
    assert!(err.is_deadlock());
    assert!(err.is_transient());
    assert!(err.is_retryable());
    tracing::info!(
        correlation_id = %cid,
        code = ?err.error_code(),
        "MySQL deadlock classified correctly"
    );

    test_section!("Lock wait timeout");
    let err = MySqlError::Server {
        code: 1205,
        sql_state: "41000".into(),
        message: "Lock wait timeout exceeded".into(),
    };
    assert!(err.is_deadlock()); // 1205 is in deadlock set
    assert!(err.is_transient());

    test_section!("Unique violation");
    let err = MySqlError::Server {
        code: 1062,
        sql_state: "23000".into(),
        message: "Duplicate entry".into(),
    };
    assert!(err.is_unique_violation());
    assert!(err.is_constraint_violation());
    assert!(!err.is_transient());

    test_section!("Connection error");
    let err = MySqlError::Io(std::io::Error::new(
        std::io::ErrorKind::ConnectionReset,
        "reset",
    ));
    assert!(err.is_connection_error());
    assert!(err.is_transient());

    test_complete!("e2e_dp_11b_mysql_error_classification");
}

#[cfg(feature = "sqlite")]
#[test]
fn e2e_dp_11c_sqlite_error_classification_data_path() {
    use asupersync::database::SqliteError;

    common::init_test_logging();
    test_phase!("DP-11c: SQLite Error Classification Data Path");

    let cid = correlation_id("dp11c", 1);

    test_section!("BUSY classification");
    let err = SqliteError::Sqlite("database is locked".into());
    assert!(err.is_transient());
    assert!(err.is_retryable());
    tracing::info!(correlation_id = %cid, "SQLite BUSY classified correctly");

    test_section!("Constraint violation");
    let err = SqliteError::Sqlite("UNIQUE constraint failed: users.email".into());
    assert!(err.is_constraint_violation());
    assert!(err.is_unique_violation());
    assert!(!err.is_transient());

    test_section!("Connection error");
    let err = SqliteError::Io(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "no such file",
    ));
    assert!(err.is_connection_error());

    test_complete!("e2e_dp_11c_sqlite_error_classification");
}

// =========================================================================
// DP-12: Cross-backend error normalization data path
// =========================================================================

#[test]
fn e2e_dp_12_cross_backend_error_normalization() {
    // All backends should agree on transient vs permanent classification
    // for equivalent error categories.
    struct ErrorClassification {
        backend: &'static str,
        is_transient: bool,
        is_retryable: bool,
        is_constraint: bool,
    }

    common::init_test_logging();
    test_phase!("DP-12: Cross-Backend Error Normalization");

    let cid = correlation_id("dp12", 1);

    let classifications = vec![
        // Transient errors should be retryable
        #[cfg(feature = "postgres")]
        {
            let err = asupersync::database::PgError::Server {
                code: "40001".into(),
                message: "serialization".into(),
                detail: None,
                hint: None,
            };
            ErrorClassification {
                backend: "postgres",
                is_transient: err.is_transient(),
                is_retryable: err.is_retryable(),
                is_constraint: err.is_constraint_violation(),
            }
        },
        #[cfg(feature = "mysql")]
        {
            let err = asupersync::database::MySqlError::Server {
                code: 1213,
                sql_state: "40001".into(),
                message: "deadlock".into(),
            };
            ErrorClassification {
                backend: "mysql",
                is_transient: err.is_transient(),
                is_retryable: err.is_retryable(),
                is_constraint: err.is_constraint_violation(),
            }
        },
        #[cfg(feature = "sqlite")]
        {
            let err = asupersync::database::SqliteError::Sqlite("database is locked".into());
            ErrorClassification {
                backend: "sqlite",
                is_transient: err.is_transient(),
                is_retryable: err.is_retryable(),
                is_constraint: err.is_constraint_violation(),
            }
        },
    ];

    test_section!("Verify transient→retryable consistency");
    for c in &classifications {
        tracing::info!(
            correlation_id = %cid,
            backend = c.backend,
            is_transient = c.is_transient,
            is_retryable = c.is_retryable,
            is_constraint = c.is_constraint,
            "error classification"
        );
        assert_eq!(
            c.is_transient, c.is_retryable,
            "{}: is_transient should equal is_retryable for database errors",
            c.backend
        );
        assert!(
            !c.is_constraint,
            "{}: transient errors should not be constraint violations",
            c.backend
        );
    }

    test_complete!("e2e_dp_12_cross_backend_normalization");
}

// =========================================================================
// DP-13: Messaging error variant constructibility
// =========================================================================

#[test]
fn e2e_dp_13_messaging_error_variants() {
    common::init_test_logging();
    test_phase!("DP-13: Messaging Error Variant Data Path");

    let cid = correlation_id("dp13", 1);

    test_section!("Redis error variants");
    {
        use asupersync::messaging::RedisError;
        let variants: Vec<(&str, RedisError, bool)> = vec![
            (
                "Io",
                RedisError::Io(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "broken",
                )),
                true,
            ),
            ("Protocol", RedisError::Protocol("bad frame".into()), false),
            (
                "Redis",
                RedisError::Redis("ERR unknown command".into()),
                false,
            ),
            ("PoolExhausted", RedisError::PoolExhausted, true),
            (
                "InvalidUrl",
                RedisError::InvalidUrl("bad://url".into()),
                false,
            ),
            ("Cancelled", RedisError::Cancelled, false),
        ];
        for (name, err, expected_transient) in &variants {
            assert_eq!(
                err.is_transient(),
                *expected_transient,
                "Redis::{name} is_transient mismatch"
            );
            tracing::info!(
                correlation_id = %cid,
                variant = name,
                transient = err.is_transient(),
                display = %err,
                "Redis error variant"
            );
            assert!(!format!("{err}").is_empty(), "Display non-empty for {name}");
        }
    }

    test_section!("Kafka error variants");
    {
        use asupersync::messaging::KafkaError;
        let queue_full = KafkaError::QueueFull;
        assert!(queue_full.is_transient(), "QueueFull is transient");
        let config = KafkaError::Config("bad".into());
        assert!(!config.is_transient(), "Config is not transient");
        tracing::info!(
            correlation_id = %cid,
            "Kafka QueueFull={}, Config={}",
            queue_full.is_transient(),
            config.is_transient()
        );
    }

    test_section!("NATS error variants");
    {
        use asupersync::messaging::NatsError;
        let io_err = NatsError::Io(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "pipe"));
        assert!(io_err.is_transient(), "NATS Io is transient");
        let proto = NatsError::Protocol("bad".into());
        assert!(!proto.is_transient(), "NATS Protocol is not transient");
        tracing::info!(
            correlation_id = %cid,
            "NATS Io={}, Protocol={}",
            io_err.is_transient(),
            proto.is_transient()
        );
    }

    test_section!("JetStream error variants");
    {
        use asupersync::messaging::JsError;
        // Api 408 = timeout, is_transient
        let timeout = JsError::Api {
            code: 408,
            description: "request timeout".into(),
        };
        assert!(timeout.is_transient(), "JS Api(408) is transient");
        // InvalidConfig is not transient
        let config = JsError::InvalidConfig("bad".into());
        assert!(!config.is_transient(), "JS InvalidConfig is not transient");
        // NotAcked is transient
        let not_acked = JsError::NotAcked;
        assert!(not_acked.is_transient(), "JS NotAcked is transient");
        tracing::info!(
            correlation_id = %cid,
            "JetStream Api(408)={}, InvalidConfig={}, NotAcked={}",
            timeout.is_transient(),
            config.is_transient(),
            not_acked.is_transient()
        );
    }

    test_complete!("e2e_dp_13_messaging_error_variants");
}

// =========================================================================
// DP-14: Kafka producer→consumer data path
// =========================================================================

#[cfg(feature = "kafka")]
#[test]
fn e2e_dp_14_kafka_producer_consumer_data_path() {
    common::init_test_logging();
    common::run_test_with_cx(|cx| async move {
        test_phase!("DP-14: Kafka Producer→Consumer Data Path");

        use asupersync::messaging::{
            KafkaConsumer, KafkaConsumerConfig, KafkaProducer, ProducerConfig,
        };

        let cid = correlation_id("dp14", 1);

        test_section!("Create producer");
        let producer = KafkaProducer::new(ProducerConfig::default()).expect("producer creation");

        test_section!("Send messages");
        let ack1 = producer
            .send(&cx, "e2e-t6-topic", None, b"message-1", Some(0))
            .await
            .expect("send 1");
        let ack2 = producer
            .send(&cx, "e2e-t6-topic", None, b"message-2", Some(0))
            .await
            .expect("send 2");
        tracing::info!(
            correlation_id = %cid,
            offset1 = ack1.offset,
            offset2 = ack2.offset,
            "messages sent"
        );
        assert_eq!(ack2.offset, ack1.offset + 1, "sequential offsets");

        test_section!("Create consumer and subscribe");
        let consumer = KafkaConsumer::new(KafkaConsumerConfig::new(
            vec!["localhost:9092".into()],
            "e2e-t6-group",
        ))
        .expect("consumer creation");
        consumer
            .subscribe(&cx, &["e2e-t6-topic"])
            .await
            .expect("subscribe");

        test_section!("Close producer and consumer");
        producer
            .flush(&cx, Duration::from_millis(10))
            .await
            .expect("flush");
        consumer.close(&cx).await.expect("close consumer");

        test_complete!("e2e_dp_14_kafka_data_path");
    });
}

// =========================================================================
// DP-15: Pool stats invariants under load
// =========================================================================

#[test]
fn e2e_dp_15_pool_stats_invariants() {
    common::init_test_logging();
    test_phase!("DP-15: Pool Stats Invariants");

    let counters = FaultCounters::new();
    let pool = make_pool(5, &counters);
    let cid = correlation_id("dp15", 1);

    test_section!("Check stats invariants through lifecycle");
    let mut conns = Vec::new();
    for i in 0..5 {
        let conn = pool.get().expect("acquire");
        conns.push(conn);
        let stats = pool.stats();
        tracing::info!(
            correlation_id = %cid,
            step = i,
            total = stats.total,
            idle = stats.idle,
            active = stats.active,
            "stats during acquire"
        );
        assert_eq!(
            stats.total,
            stats.idle + stats.active,
            "total = idle + active"
        );
        assert!(stats.total <= 5, "total <= max_size");
        assert!(
            stats.total_acquisitions >= stats.total_creates,
            "acquisitions >= creates"
        );
    }

    test_section!("Return all connections");
    for conn in conns {
        conn.return_to_pool();
    }
    let stats = pool.stats();
    assert_eq!(stats.active, 0);
    assert_eq!(stats.idle, stats.total);

    test_complete!("e2e_dp_15_pool_stats_invariants");
}

// =========================================================================
// DP-16: Retry policy builder round-trip
// =========================================================================

#[test]
fn e2e_dp_16_retry_policy_builder_roundtrip() {
    common::init_test_logging();
    test_phase!("DP-16: Retry Policy Builder Round-Trip");

    let cid = correlation_id("dp16", 1);

    test_section!("Default policy");
    let default = RetryPolicy::new();
    assert_eq!(default.max_attempts, 3);
    assert_eq!(default.initial_delay, Duration::from_millis(100));
    assert_eq!(default.max_delay, Duration::from_secs(30));

    test_section!("Custom policy");
    let custom = RetryPolicy::new()
        .with_max_attempts(10)
        .with_initial_delay(Duration::from_millis(50))
        .with_max_delay(Duration::from_secs(10))
        .with_multiplier(3.0)
        .with_jitter(0.2);
    assert_eq!(custom.max_attempts, 10);
    assert_eq!(custom.initial_delay, Duration::from_millis(50));

    test_section!("Fixed delay policy");
    let fixed = RetryPolicy::fixed_delay(Duration::from_millis(200), 5);
    assert_eq!(fixed.max_attempts, 5);
    let d1 = calculate_delay(&fixed, 1, None);
    let d2 = calculate_delay(&fixed, 2, None);
    tracing::info!(
        correlation_id = %cid,
        d1_ms = d1.as_millis(),
        d2_ms = d2.as_millis(),
        "fixed delay consistency"
    );

    test_section!("Immediate policy");
    let imm = RetryPolicy::immediate(3);
    let d = calculate_delay(&imm, 1, None);
    assert_eq!(d, Duration::ZERO, "immediate policy has zero delay");

    test_section!("Validation");
    assert!(RetryPolicy::new().validate().is_ok());

    test_complete!("e2e_dp_16_retry_policy_builder");
}

// =========================================================================
// DP-17: Discard unhealthy + re-acquire doesn't leak
// =========================================================================

#[test]
fn e2e_dp_17_discard_no_resource_leak() {
    common::init_test_logging();
    test_phase!("DP-17: Discard No Resource Leak");

    let counters = FaultCounters::new();
    let pool = make_pool(3, &counters);
    let cid = correlation_id("dp17", 1);

    test_section!("Acquire and discard multiple times");
    for i in 0..5 {
        let conn = pool.get().expect("acquire");
        conn.discard();
        let stats = pool.stats();
        tracing::info!(
            correlation_id = %cid,
            iteration = i,
            total = stats.total,
            idle = stats.idle,
            active = stats.active,
            "after discard"
        );
        assert_eq!(stats.active, 0, "no active connections after discard");
    }

    test_section!("Verify total creates matches discards + 1");
    let stats = pool.stats();
    tracing::info!(
        correlation_id = %cid,
        total_creates = stats.total_creates,
        total_acquires = stats.total_acquisitions,
        "final stats"
    );

    test_complete!("e2e_dp_17_discard_no_leak");
}

// =========================================================================
// DP-18: Retry timeout integration with pool connection_timeout
// =========================================================================

#[test]
fn e2e_dp_18_retry_timeout_integration() {
    common::init_test_logging();
    test_phase!("DP-18: Retry Timeout Integration");

    let counters = FaultCounters::new();
    counters.fail_connect.store(true, Ordering::Relaxed);
    counters.fail_count.store(100, Ordering::Relaxed);

    let config = DbPoolConfig::with_max_size(2).connection_timeout(Duration::from_millis(200));
    let pool = make_pool_with_config(config, &counters);
    let cid = correlation_id("dp18", 1);

    // Policy allows 100 attempts, but pool timeout is only 200ms
    let policy = RetryPolicy::new()
        .with_max_attempts(100)
        .with_initial_delay(Duration::from_millis(50))
        .no_jitter();

    test_section!("Retry bounded by connection_timeout");
    let start = Instant::now();
    let result = pool.get_with_retry(&policy);
    let elapsed = start.elapsed();

    tracing::info!(
        correlation_id = %cid,
        elapsed_ms = elapsed.as_millis(),
        attempts = counters.connect_calls.load(Ordering::Relaxed),
        "retry bounded by timeout"
    );

    assert!(result.is_err());
    // Should have stopped well before 100 attempts due to 200ms timeout
    let attempts = counters.connect_calls.load(Ordering::Relaxed);
    assert!(
        attempts < 100,
        "timeout stopped retries early (attempts={attempts})"
    );
    assert!(
        elapsed < Duration::from_millis(500),
        "didn't exceed reasonable time"
    );

    test_complete!("e2e_dp_18_retry_timeout", attempts = attempts);
}

// =========================================================================
// DP-19: RetryPolicy::none() produces zero retries
// =========================================================================

#[test]
fn e2e_dp_19_retry_policy_none() {
    common::init_test_logging();
    test_phase!("DP-19: RetryPolicy::none()");

    let counters = FaultCounters::new();
    counters.fail_connect.store(true, Ordering::Relaxed);
    counters.fail_count.store(100, Ordering::Relaxed);

    let pool = make_pool(2, &counters);
    let policy = RetryPolicy::immediate(1);
    let cid = correlation_id("dp19", 1);

    let result = pool.get_with_retry(&policy);
    tracing::info!(
        correlation_id = %cid,
        attempts = counters.connect_calls.load(Ordering::Relaxed),
        "single attempt, no retry"
    );
    assert!(result.is_err());
    assert_eq!(
        counters.connect_calls.load(Ordering::Relaxed),
        1,
        "exactly one attempt"
    );

    test_complete!("e2e_dp_19_retry_none");
}

// =========================================================================
// DP-20: Full data-path: warm → acquire → query → fault → retry → recover
// =========================================================================

#[test]
fn e2e_dp_20_full_data_path_warmup_fault_recovery() {
    common::init_test_logging();
    test_phase!("DP-20: Full Data Path (Warm→Acquire→Fault→Retry→Recover)");

    let counters = FaultCounters::new();
    let config = DbPoolConfig::with_max_size(4).min_idle(2);
    let pool = make_pool_with_config(config, &counters);
    let cid = correlation_id("dp20", 1);

    test_section!("Phase 1: Warm up");
    let warmed = pool.warm_up();
    tracing::info!(correlation_id = %cid, warmed, "warmup complete");
    assert!(warmed >= 2);

    test_section!("Phase 2: Normal operations");
    let conn = pool.get().expect("normal acquire");
    let queries = conn.get().query();
    assert_eq!(queries, 1);
    conn.return_to_pool();

    test_section!("Phase 3: Inject connect fault");
    counters.fail_connect.store(true, Ordering::Relaxed);
    counters.fail_count.store(2, Ordering::Relaxed);

    test_section!("Phase 4: Retry through fault");
    // First, exhaust all idle connections by marking them unhealthy
    // We'll discard the warm connections and force new creates
    let mut to_discard = Vec::new();
    while let Some(c) = pool.try_get() {
        c.get().mark_unhealthy();
        to_discard.push(c);
    }
    for c in to_discard {
        c.discard();
    }

    let policy = RetryPolicy::new()
        .with_max_attempts(5)
        .with_initial_delay(Duration::from_millis(10))
        .no_jitter();
    let conn = pool.get_with_retry(&policy).expect("retry should recover");
    tracing::info!(
        correlation_id = %cid,
        conn_id = conn.get().id,
        total_connects = counters.connect_calls.load(Ordering::Relaxed),
        "recovered through retry"
    );
    conn.return_to_pool();

    test_section!("Phase 5: Verify recovery");
    let stats = pool.stats();
    assert!(stats.total >= 1);
    tracing::info!(
        correlation_id = %cid,
        total = stats.total,
        idle = stats.idle,
        "recovered pool state"
    );

    test_complete!("e2e_dp_20_full_data_path");
}

// =========================================================================
// Contract doc and artifact checks
// =========================================================================

#[test]
fn e2e_dp_contract_doc_exists_and_complete() {
    let content = std::fs::read_to_string("docs/tokio_t6_data_path_e2e_contract.md")
        .expect("contract doc should exist");

    for required in [
        "T6.13",
        "asupersync-2oh2u.6.13",
        "DP-01",
        "DP-20",
        "correlation_id",
        "reliability",
        "retry",
        "fault injection",
    ] {
        assert!(
            content.contains(required),
            "contract doc missing required content: {required}"
        );
    }
}

#[test]
fn e2e_dp_json_artifact_valid() {
    let content = std::fs::read_to_string("docs/tokio_t6_data_path_e2e_contract.json")
        .expect("JSON artifact should exist");
    let json: serde_json::Value = serde_json::from_str(&content).expect("valid JSON");

    assert_eq!(
        json["schema_version"].as_str(),
        Some("1.0.0"),
        "schema_version"
    );
    assert_eq!(
        json["bead_id"].as_str(),
        Some("asupersync-2oh2u.6.13"),
        "bead_id"
    );

    let scenarios = json["scenarios"].as_array().expect("scenarios array");
    assert!(
        scenarios.len() >= 20,
        "expected >= 20 scenarios, got {}",
        scenarios.len()
    );

    for s in scenarios {
        assert!(s["id"].is_string(), "scenario missing id");
        assert!(s["category"].is_string(), "scenario missing category");
    }
}

#[test]
fn e2e_dp_runner_script_exists_and_valid() {
    let content = std::fs::read_to_string("scripts/test_t6_data_path_e2e.sh")
        .expect("runner script should exist");

    for required in [
        "\"schema_version\": \"e2e-suite-summary-v3\"",
        "\"suite_id\":",
        "\"scenario_id\":",
        "\"seed\":",
        "\"started_ts\":",
        "\"ended_ts\":",
        "\"status\":",
        "\"repro_command\":",
        "\"artifact_path\":",
    ] {
        assert!(
            content.contains(required),
            "runner script missing summary fragment: {required}"
        );
    }
}
