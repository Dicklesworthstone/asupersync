//! Conformance proof for `database.pool.lifecycle` structured trace events
//! emitted by [`AsyncDbPool`] (eeexl1.5 AC7 — pool-event logging).
//!
//! AC7 calls for structured logging on transaction lifecycle *and* pool events.
//! The transaction side already has an inline unit test
//! (`trace_database_transaction_records_structured_fields` in
//! `src/database/transaction.rs`). The async pool emits a far richer matrix —
//! `acquire/start`, `create/start`, `acquire/ok_created`, `acquire/ok_idle`,
//! `wait/queued`, `wait/timeout`, and more — all through the private
//! `trace_async_pool_event` helper, yet nothing asserts that those events ever
//! reach a collector. This crate pins the three deterministic anonymous-`get`
//! paths end to end against a `LogCollector` attached to the caller's `Cx`:
//!
//! * `database_async_pool_cold_acquire_emits_create_then_ok_created_trace` — a
//!   fresh, empty pool walks `acquire/start -> create/start ->
//!   acquire/ok_created` (the slot is constructed on demand).
//! * `database_async_pool_warm_reuse_emits_ok_idle_trace` — once a connection
//!   is returned, the next acquire reuses it: `acquire/start ->
//!   acquire/ok_idle`, with no `create` event.
//! * `database_async_pool_saturated_acquirer_emits_queued_then_timeout_trace` —
//!   a parked acquirer on a saturated pool walks `acquire/start ->
//!   wait/queued -> wait/timeout` and the call surfaces `AcquireTimeout`
//!   carrying the stable `[ASUP-E601]` token.
//!
//! Every captured lifecycle entry is checked to carry the shared schema
//! (`component=database`, `resource=pool`, `pool_kind=async`,
//! `client_scope=anonymous`). The collector is filtered to the
//! `database.pool.lifecycle` message so unrelated trace traffic on the same
//! `Cx` cannot perturb the assertions.
//!
//! Gated on `test-internals` (for `Cx::for_testing` + the log collector) plus a
//! database feature (the `database` module only compiles with one enabled).
//! Run e.g. with `--features sqlite,test-internals`.
#![cfg(all(
    feature = "test-internals",
    any(feature = "sqlite", feature = "postgres", feature = "mysql")
))]

use std::sync::Arc;
use std::time::Duration;

use asupersync::cx::Cx;
use asupersync::database::pool::{AsyncConnectionManager, AsyncDbPool, DbPoolConfig, DbPoolError};
use asupersync::observability::{LogCollector, LogLevel};
use asupersync::types::Outcome;
use futures_lite::future::block_on;

// ─── Mock async connection manager ──────────────────────────────────────────

/// Opaque in-memory connection: the lifecycle trace under test is independent
/// of the backend, so the connection carries no state of its own.
#[derive(Debug)]
struct MockConn;

/// Always-successful manager: every `connect` succeeds and every connection
/// validates, isolating the lifecycle-trace emission under test. The error type
/// is `std::io::Error` because `connect` never fails here, so a bespoke
/// never-constructed error type would be dead code.
struct MockManager;

impl AsyncConnectionManager for MockManager {
    type Connection = MockConn;
    type Error = std::io::Error;

    // These bodies have nothing to await, so they return ready futures directly
    // rather than `async fn` (which would trip `clippy::unused_async`).
    fn connect(
        &self,
        _cx: &Cx,
    ) -> impl std::future::Future<Output = Outcome<Self::Connection, Self::Error>> + Send {
        std::future::ready(Outcome::Ok(MockConn))
    }

    fn is_valid(
        &self,
        _cx: &Cx,
        _conn: &mut Self::Connection,
    ) -> impl std::future::Future<Output = bool> + Send {
        std::future::ready(true)
    }
}

// ─── Harness helpers ─────────────────────────────────────────────────────────

const POOL_LIFECYCLE_MESSAGE: &str = "database.pool.lifecycle";

fn build_pool(max_size: usize, connection_timeout: Duration) -> Arc<AsyncDbPool<MockManager>> {
    Arc::new(AsyncDbPool::new(
        MockManager,
        DbPoolConfig::with_max_size(max_size)
            .validate_on_checkout(false)
            .connection_timeout(connection_timeout),
    ))
}

/// A `Cx` with a fresh trace collector attached at `Trace` level (pool events
/// are emitted at `Trace`, below the collector's default `Info` floor).
fn cx_with_collector() -> (Cx, LogCollector) {
    let cx = Cx::for_testing();
    let collector = LogCollector::new(32).with_min_level(LogLevel::Trace);
    cx.set_log_collector(collector.clone());
    (cx, collector)
}

/// The ordered `(operation, outcome)` pairs of every `database.pool.lifecycle`
/// event the collector saw, with the shared schema fields asserted on each.
/// Filtering by message keeps unrelated trace traffic on the same `Cx` from
/// leaking into the sequence under test.
fn pool_lifecycle_steps(collector: &LogCollector) -> Vec<(String, String)> {
    collector
        .peek()
        .into_iter()
        .filter(|entry| entry.message() == POOL_LIFECYCLE_MESSAGE)
        .map(|entry| {
            assert_eq!(
                entry.get_field("component"),
                Some("database"),
                "pool lifecycle event carries component=database"
            );
            assert_eq!(
                entry.get_field("resource"),
                Some("pool"),
                "pool lifecycle event carries resource=pool"
            );
            assert_eq!(
                entry.get_field("pool_kind"),
                Some("async"),
                "the async pool tags its events pool_kind=async"
            );
            assert_eq!(
                entry.get_field("client_scope"),
                Some("anonymous"),
                "plain get() acquires under the anonymous client scope"
            );
            (
                entry
                    .get_field("operation")
                    .expect("lifecycle event carries an operation field")
                    .to_owned(),
                entry
                    .get_field("outcome")
                    .expect("lifecycle event carries an outcome field")
                    .to_owned(),
            )
        })
        .collect()
}

fn steps_as_refs(steps: &[(String, String)]) -> Vec<(&str, &str)> {
    steps
        .iter()
        .map(|(operation, outcome)| (operation.as_str(), outcome.as_str()))
        .collect()
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[test]
fn database_async_pool_cold_acquire_emits_create_then_ok_created_trace() {
    // A fresh pool has no idle connections, so the first acquire must construct
    // a slot on demand: acquire/start -> create/start -> acquire/ok_created.
    let pool = build_pool(4, Duration::from_secs(30));
    let (cx, collector) = cx_with_collector();

    let lease = block_on(pool.get(&cx)).expect("cold acquire on an empty pool succeeds");

    let steps = pool_lifecycle_steps(&collector);
    assert_eq!(
        steps_as_refs(&steps),
        vec![
            ("acquire", "start"),
            ("create", "start"),
            ("acquire", "ok_created"),
        ],
        "a cold acquire walks start -> create -> ok_created"
    );

    lease.return_to_pool();
    assert_eq!(
        pool.stats().total_creates,
        1,
        "exactly one connection was constructed"
    );
}

#[test]
fn database_async_pool_warm_reuse_emits_ok_idle_trace() {
    let pool = build_pool(4, Duration::from_secs(30));

    // Prime the pool with one idle connection on a collector-free Cx, then
    // return it so the next acquire reuses it instead of constructing a new one.
    let warmup_cx = Cx::for_testing();
    block_on(pool.get(&warmup_cx))
        .expect("warm-up acquire succeeds")
        .return_to_pool();
    assert_eq!(
        pool.stats().idle,
        1,
        "the returned connection is parked idle for reuse"
    );

    // The reuse acquire is observed on a clean collector: acquire/start ->
    // acquire/ok_idle, with no create event.
    let (cx, collector) = cx_with_collector();
    let lease = block_on(pool.get(&cx)).expect("warm acquire reuses the idle connection");

    let steps = pool_lifecycle_steps(&collector);
    assert_eq!(
        steps_as_refs(&steps),
        vec![("acquire", "start"), ("acquire", "ok_idle")],
        "a warm acquire reuses the idle slot (no create event)"
    );

    lease.return_to_pool();
    assert_eq!(
        pool.stats().total_creates,
        1,
        "reuse constructed no additional connection beyond the warm-up"
    );
}

#[test]
fn database_async_pool_saturated_acquirer_emits_queued_then_timeout_trace() {
    // One slot, a tight acquire budget: the parked second acquirer queues and
    // then times out promptly rather than waiting the default budget.
    let pool = build_pool(1, Duration::from_millis(120));

    // Hold the only slot on a collector-free Cx so the saturation is real.
    let holder_cx = Cx::for_testing();
    let holder = block_on(pool.get(&holder_cx)).expect("holder takes the only slot");

    // The parked acquirer walks acquire/start -> wait/queued -> wait/timeout.
    let (cx, collector) = cx_with_collector();
    let outcome = block_on(pool.get(&cx));

    let err = outcome.expect_err("a saturated single-slot pool must not hand out a second lease");
    assert!(
        matches!(err, DbPoolError::AcquireTimeout),
        "budget exhaustion while parked must yield AcquireTimeout, got {err:?}"
    );
    assert!(
        err.to_string().starts_with("[ASUP-E601]"),
        "AcquireTimeout must lead with the stable ASUP-E601 token, got: {err}"
    );

    let steps = pool_lifecycle_steps(&collector);
    assert_eq!(
        steps_as_refs(&steps),
        vec![
            ("acquire", "start"),
            ("wait", "queued"),
            ("wait", "timeout"),
        ],
        "a saturated acquirer walks start -> queued -> timeout"
    );

    assert_eq!(
        pool.stats().total_timeouts,
        1,
        "budget exhaustion records exactly one timeout"
    );
    assert_eq!(
        pool.stats().pending_waiters,
        0,
        "a timed-out acquirer removes itself from the FIFO queue"
    );

    holder.return_to_pool();
}
