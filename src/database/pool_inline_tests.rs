    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::conformance::{ConformanceTarget, LabRuntimeTarget, TestConfig};
    use crate::observability::{LogCollector, LogEntry, LogLevel};
    use crate::runtime::yield_now;
    use crate::types::Budget;
    use futures_lite::future::block_on;
    use serde_json::json;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Instant;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn db_pool_stats_snapshot(stats: &DbPoolStats) -> serde_json::Value {
        json!({
            "idle": stats.idle,
            "active": stats.active,
            "total": stats.total,
            "max_size": stats.max_size,
            "total_acquisitions": stats.total_acquisitions,
            "total_creates": stats.total_creates,
            "total_discards": stats.total_discards,
            "total_timeouts": stats.total_timeouts,
            "total_validation_failures": stats.total_validation_failures,
        })
    }

    fn db_pool_inventory_snapshot(stats: &DbPoolStats) -> serde_json::Value {
        json!({
            "idle": stats.idle,
            "active": stats.active,
            "total": stats.total,
            "max_size": stats.max_size,
        })
    }

    // ================================================================
    // Test connection manager
    // ================================================================

    /// A simple in-memory connection for testing.
    #[derive(Debug)]
    struct TestConnection {
        id: usize,
        valid: Arc<AtomicBool>,
    }

    #[derive(Clone)]
    struct TestManager {
        next_id: Arc<AtomicUsize>,
        valid: Arc<AtomicBool>,
        creates: Arc<AtomicUsize>,
        disconnects: Arc<AtomicUsize>,
        fail_connect: Arc<AtomicBool>,
    }

    impl TestManager {
        fn new() -> Self {
            Self {
                next_id: Arc::new(AtomicUsize::new(1)),
                valid: Arc::new(AtomicBool::new(true)),
                creates: Arc::new(AtomicUsize::new(0)),
                disconnects: Arc::new(AtomicUsize::new(0)),
                fail_connect: Arc::new(AtomicBool::new(false)),
            }
        }

        fn disconnects(&self) -> usize {
            self.disconnects.load(Ordering::SeqCst)
        }

        fn set_fail_connect(&self, fail: bool) {
            self.fail_connect.store(fail, Ordering::SeqCst);
        }

        fn set_valid(&self, valid: bool) {
            self.valid.store(valid, Ordering::SeqCst);
        }
    }

    #[derive(Debug)]
    struct TestError(String);

    impl fmt::Display for TestError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    impl std::error::Error for TestError {}

    impl ConnectionManager for TestManager {
        type Connection = TestConnection;
        type Error = TestError;

        fn connect(&self) -> Result<Self::Connection, Self::Error> {
            if self.fail_connect.load(Ordering::SeqCst) {
                return Err(TestError("connection refused".to_string()));
            }
            self.creates.fetch_add(1, Ordering::SeqCst);
            let id = self.next_id.fetch_add(1, Ordering::SeqCst);
            Ok(TestConnection {
                id,
                valid: self.valid.clone(),
            })
        }

        fn is_valid(&self, conn: &Self::Connection) -> bool {
            conn.valid.load(Ordering::SeqCst)
        }

        fn disconnect(&self, _conn: Self::Connection) {
            self.disconnects.fetch_add(1, Ordering::SeqCst);
        }
    }

    // br-asupersync-c5d0q: a connection manager whose reported authentication
    // state can be driven to drift between return-time and the next checkout,
    // with a toggle for clear_authentication_state success. This exercises the
    // two auth-validation failure arms of the sync `get_for_client` that
    // previously leaked a pool capacity slot (the connection is taken out of the
    // ValidationGuard, so the guard's Drop rollback no longer applies).
    struct AuthDriftManager {
        next_id: Arc<AtomicUsize>,
        auth_state: Arc<Mutex<Option<String>>>,
        clear_ok: Arc<AtomicBool>,
        disconnects: Arc<AtomicUsize>,
    }

    impl AuthDriftManager {
        fn new() -> Self {
            Self {
                next_id: Arc::new(AtomicUsize::new(1)),
                auth_state: Arc::new(Mutex::new(None)),
                clear_ok: Arc::new(AtomicBool::new(true)),
                disconnects: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn set_auth_state(&self, state: Option<&str>) {
            *self.auth_state.lock() = state.map(str::to_string);
        }

        fn set_clear_ok(&self, ok: bool) {
            self.clear_ok.store(ok, Ordering::SeqCst);
        }
    }

    impl ConnectionManager for AuthDriftManager {
        type Connection = TestConnection;
        type Error = TestError;

        fn connect(&self) -> Result<Self::Connection, Self::Error> {
            let id = self.next_id.fetch_add(1, Ordering::SeqCst);
            Ok(TestConnection {
                id,
                valid: Arc::new(AtomicBool::new(true)),
            })
        }

        fn is_valid(&self, _conn: &Self::Connection) -> bool {
            true
        }

        fn disconnect(&self, _conn: Self::Connection) {
            self.disconnects.fetch_add(1, Ordering::SeqCst);
        }

        fn authentication_state(&self, _conn: &Self::Connection) -> Option<String> {
            self.auth_state.lock().clone()
        }

        fn clear_authentication_state(&self, _conn: &mut Self::Connection) -> bool {
            self.clear_ok.load(Ordering::SeqCst)
        }
    }

    #[test]
    fn db_pool_stats_reports_pending_async_waiter_depth() {
        // br-asupersync-eeexl1.5 AC3: DbPoolStats surfaces the async FIFO
        // waiter-queue depth so saturation / no-thundering-herd is observable.
        init_test("db_pool_stats_reports_pending_async_waiter_depth");
        let pool = DbPool::new(TestManager::new(), DbPoolConfig::default());

        // Fresh pool: nothing parked in the FIFO waiter queue.
        assert_eq!(pool.stats().pending_waiters, 0);
        let baseline = pool.stats();

        // Park three acquirers (white-box mirror of the saturated acquire path,
        // which pushes one Arc<AsyncPoolWaiter> per blocked caller).
        {
            let mut inner = pool.inner.lock();
            for _ in 0..3 {
                inner.waiters.push_back(Arc::new(AsyncPoolWaiter::new()));
            }
        }
        let saturated = pool.stats();
        assert_eq!(
            saturated.pending_waiters, 3,
            "stats().pending_waiters must reflect the live waiter-queue length"
        );
        // Waiter accounting is independent of connection inventory.
        assert_eq!(saturated.idle, baseline.idle, "idle unaffected by waiters");
        assert_eq!(
            saturated.active, baseline.active,
            "active unaffected by waiters"
        );
        assert_eq!(
            saturated.total, baseline.total,
            "total unaffected by waiters"
        );

        // Waking the FIFO head (pop_front) decrements the reported depth — the
        // field tracks the live queue, not a monotonic counter.
        {
            let mut inner = pool.inner.lock();
            inner.waiters.pop_front();
        }
        assert_eq!(pool.stats().pending_waiters, 2);
    }

    #[test]
    fn get_for_client_auth_mismatch_does_not_leak_capacity_slot() {
        init_test("get_for_client_auth_mismatch_does_not_leak_capacity_slot");
        let pool = DbPool::new(
            AuthDriftManager::new(),
            DbPoolConfig::with_max_size(1)
                .validate_on_checkout(true)
                .validate_authentication_state(true),
        );

        // Seed the idle list with a connection authenticated for "c1" (return
        // records manager.authentication_state()).
        pool.manager.set_auth_state(Some("c1"));
        {
            let _conn = pool
                .get_for_client("c1")
                .expect("first acquire creates a connection");
        }
        assert_eq!(pool.stats().idle, 1, "connection should return to idle");
        assert_eq!(pool.stats().total, 1);

        // Auth state drifts to a different client between return and checkout.
        pool.manager.set_auth_state(Some("c2"));
        let err = pool
            .get_for_client("c1")
            .expect_err("auth-state mismatch must be rejected");
        assert!(
            matches!(err, DbPoolError::AuthenticationMismatch { .. }),
            "expected AuthenticationMismatch, got {err:?}"
        );

        // Regression: the rejected connection must free its capacity slot. With
        // the leak, total stays pinned at max_size with zero live connections,
        // so every later acquire fails with Full forever.
        assert_eq!(
            pool.stats().total,
            0,
            "auth-mismatch rejection must not leak a pool capacity slot"
        );
        pool.manager.set_auth_state(Some("c1"));
        assert!(
            pool.get_for_client("c1").is_ok(),
            "pool must be usable again after an auth-mismatch rejection"
        );
        crate::test_complete!("get_for_client_auth_mismatch_does_not_leak_capacity_slot");
    }

    #[test]
    fn get_for_client_clear_auth_failure_does_not_leak_capacity_slot() {
        init_test("get_for_client_clear_auth_failure_does_not_leak_capacity_slot");
        let pool = DbPool::new(
            AuthDriftManager::new(),
            DbPoolConfig::with_max_size(1)
                .validate_on_checkout(true)
                .validate_authentication_state(true),
        );

        // Seed the idle list with a connection that has no recorded auth client
        // (authenticated_for = None).
        pool.manager.set_auth_state(None);
        {
            let _conn = pool
                .get_for_client("c1")
                .expect("first acquire creates a connection");
        }
        assert_eq!(pool.stats().total, 1);

        // On checkout the connection now reports an unexpected client and the
        // manager cannot scrub it, driving the clear-auth-failure discard arm.
        // (The auth state is read at validation time; the idle conn's recorded
        // authenticated_for is None, so the (Some, None) clear arm fires.)
        pool.manager.set_auth_state(Some("intruder"));
        pool.manager.set_clear_ok(false);

        // With the slot leaked, the retry inside get_for_client observes a full
        // pool (total == max_size) and returns Full forever. With the slot
        // freed, the retry takes the create path (which does not re-validate
        // auth) and succeeds.
        let result = pool.get_for_client("c1");
        assert!(
            result.is_ok(),
            "clear-auth-failure discard must free the slot so the pool stays usable, got {:?}",
            result.err()
        );
        crate::test_complete!("get_for_client_clear_auth_failure_does_not_leak_capacity_slot");
    }

    #[test]
    fn explicit_return_to_pool_and_discard_release_client_quota_slot() {
        init_test("explicit_return_to_pool_and_discard_release_client_quota_slot");
        let pool = DbPool::new(
            TestManager::new(),
            DbPoolConfig::with_max_size(4)
                .max_connections_per_client(Some(1))
                .enforce_client_quotas(true),
        );

        // Acquire under client "c1" and explicitly return it. The per-client
        // quota slot must be released. The prior code took the connection out
        // of the guard and called `return_connection` directly, so the guard's
        // Drop (which owns the quota decrement) saw `None` and the slot leaked —
        // the second acquire then failed with ClientQuotaExceeded forever.
        {
            let conn = pool.get_for_client("c1").expect("first acquire");
            conn.return_to_pool();
        }
        pool.get_for_client("c1")
            .expect("return_to_pool must free the client quota slot")
            .return_to_pool();

        // Same for discard(): the sync path previously called
        // `discard_connection` with no client id, so the per-client slot leaked.
        {
            let conn = pool.get_for_client("c1").expect("acquire before discard");
            conn.discard();
        }
        pool.get_for_client("c1")
            .expect("discard must free the client quota slot")
            .return_to_pool();

        crate::test_complete!("explicit_return_to_pool_and_discard_release_client_quota_slot");
    }

    struct AsyncTestManager {
        next_id: AtomicUsize,
        valid: Arc<AtomicBool>,
        creates: AtomicUsize,
        disconnects: AtomicUsize,
        fail_connect: AtomicBool,
    }

    impl AsyncTestManager {
        fn new() -> Self {
            Self {
                next_id: AtomicUsize::new(1),
                valid: Arc::new(AtomicBool::new(true)),
                creates: AtomicUsize::new(0),
                disconnects: AtomicUsize::new(0),
                fail_connect: AtomicBool::new(false),
            }
        }

        fn always_failing() -> Self {
            let manager = Self::new();
            manager.fail_connect.store(true, Ordering::SeqCst);
            manager
        }
    }

    impl AsyncConnectionManager for AsyncTestManager {
        type Connection = TestConnection;
        type Error = TestError;

        async fn connect(&self, _cx: &Cx) -> Outcome<Self::Connection, Self::Error> {
            if self.fail_connect.load(Ordering::SeqCst) {
                return Outcome::Err(TestError("connection refused".to_string()));
            }

            self.creates.fetch_add(1, Ordering::SeqCst);
            let id = self.next_id.fetch_add(1, Ordering::SeqCst);
            Outcome::Ok(TestConnection {
                id,
                valid: self.valid.clone(),
            })
        }

        async fn is_valid(&self, _cx: &Cx, conn: &mut Self::Connection) -> bool {
            conn.valid.load(Ordering::SeqCst)
        }

        fn disconnect(&self, _conn: Self::Connection) {
            self.disconnects.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn has_pool_lifecycle_entry(
        entries: &[LogEntry],
        operation: &str,
        outcome: &str,
        client_scope: &str,
    ) -> bool {
        entries.iter().any(|entry| {
            entry.message() == "database.pool.lifecycle"
                && entry.get_field("component") == Some("database")
                && entry.get_field("resource") == Some("pool")
                && entry.get_field("pool_kind") == Some("async")
                && entry.get_field("operation") == Some(operation)
                && entry.get_field("outcome") == Some(outcome)
                && entry.get_field("client_scope") == Some(client_scope)
        })
    }

    struct ControlledAsyncPoolManager {
        connect_outcome: Outcome<(), &'static str>,
        pause_connect: AtomicBool,
        pause_validation: AtomicBool,
        connect_calls: AtomicUsize,
        validation_calls: AtomicUsize,
        disconnects: AtomicUsize,
    }

    impl ControlledAsyncPoolManager {
        fn new(connect_outcome: Outcome<(), &'static str>) -> Self {
            Self {
                connect_outcome,
                pause_connect: AtomicBool::new(false),
                pause_validation: AtomicBool::new(false),
                connect_calls: AtomicUsize::new(0),
                validation_calls: AtomicUsize::new(0),
                disconnects: AtomicUsize::new(0),
            }
        }
    }

    impl AsyncConnectionManager for ControlledAsyncPoolManager {
        type Connection = TestConnection;
        type Error = TestError;

        async fn connect(&self, _cx: &Cx) -> Outcome<Self::Connection, Self::Error> {
            let id = self.connect_calls.fetch_add(1, Ordering::SeqCst) + 1;
            std::future::poll_fn(|_| {
                if self.pause_connect.load(Ordering::SeqCst) {
                    std::task::Poll::Pending
                } else {
                    std::task::Poll::Ready(())
                }
            })
            .await;
            self.connect_outcome
                .clone()
                .map(|()| TestConnection {
                    id,
                    valid: Arc::new(AtomicBool::new(true)),
                })
                .map_err(|message| TestError(message.to_string()))
        }

        async fn is_valid(&self, _cx: &Cx, conn: &mut Self::Connection) -> bool {
            self.validation_calls.fetch_add(1, Ordering::SeqCst);
            std::future::poll_fn(|_| {
                if self.pause_validation.load(Ordering::SeqCst) {
                    std::task::Poll::Pending
                } else {
                    std::task::Poll::Ready(conn.valid.load(Ordering::SeqCst))
                }
            })
            .await
        }

        fn disconnect(&self, _conn: Self::Connection) {
            self.disconnects.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn attributed_pool_cancel_reason() -> crate::types::CancelReason {
        use crate::types::{CancelKind, CancelReason, RegionId, TaskId};

        CancelReason::with_origin(
            CancelKind::ParentCancelled,
            RegionId::new_for_test(17, 2),
            Time::from_nanos(123_456),
        )
        .with_task(TaskId::new_for_test(23, 3))
        .with_message("pool caller stopped")
        .with_cause(CancelReason::shutdown().with_message("service shutdown"))
    }

    /// Counts the release-time hooks; its reset can fail or never finish.
    struct ResettingAsyncManager {
        keep_on_check: bool,
        reset_succeeds: bool,
        reset_parks: bool,
        release_checks: AtomicUsize,
        resets: AtomicUsize,
        disconnects: AtomicUsize,
    }

    impl ResettingAsyncManager {
        fn new(keep_on_check: bool, reset_succeeds: bool, reset_parks: bool) -> Self {
            Self {
                keep_on_check,
                reset_succeeds,
                reset_parks,
                release_checks: AtomicUsize::new(0),
                resets: AtomicUsize::new(0),
                disconnects: AtomicUsize::new(0),
            }
        }
    }

    impl AsyncConnectionManager for ResettingAsyncManager {
        type Connection = TestConnection;
        type Error = TestError;

        async fn connect(&self, _cx: &Cx) -> Outcome<Self::Connection, Self::Error> {
            Outcome::Ok(TestConnection {
                id: 1,
                valid: Arc::new(AtomicBool::new(true)),
            })
        }

        async fn is_valid(&self, _cx: &Cx, _conn: &mut Self::Connection) -> bool {
            true
        }

        fn release_check(&self, _conn: &mut Self::Connection) -> bool {
            self.release_checks.fetch_add(1, Ordering::SeqCst);
            self.keep_on_check
        }

        fn reset_on_return(
            &self,
            _cx: &Cx,
            _conn: &mut Self::Connection,
        ) -> impl std::future::Future<Output = bool> + Send {
            self.resets.fetch_add(1, Ordering::SeqCst);
            let (parks, succeeds) = (self.reset_parks, self.reset_succeeds);
            std::future::poll_fn(move |_| {
                if parks {
                    std::task::Poll::Pending
                } else {
                    std::task::Poll::Ready(succeeds)
                }
            })
        }

        fn disconnect(&self, _conn: Self::Connection) {
            self.disconnects.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// br-asupersync-qml5yb MEDIUM 4: reset_and_return awaits the manager's
    /// reset before the connection is idle. A refused release check, a
    /// failed reset and a cancelled reset discard it instead, and the
    /// release check runs once. Dropping the guard still defers the reset.
    #[test]
    fn reset_and_return_resets_before_the_connection_goes_idle() {
        init_test("reset_and_return_resets_before_the_connection_goes_idle");
        let cx = Cx::for_testing();
        for (keep_on_check, reset_succeeds) in [(true, true), (true, false), (false, true)] {
            let pool = AsyncDbPool::new(
                ResettingAsyncManager::new(keep_on_check, reset_succeeds, false),
                DbPoolConfig::with_max_size(1),
            );
            let conn = block_on(pool.get(&cx)).expect("checkout");
            block_on(conn.reset_and_return(&cx));
            let pooled = keep_on_check && reset_succeeds;
            let case = format!("check={keep_on_check} reset={reset_succeeds}");
            let manager = &pool.manager;
            assert_eq!(manager.release_checks.load(Ordering::SeqCst), 1, "{case}");
            assert_eq!(
                manager.resets.load(Ordering::SeqCst),
                usize::from(keep_on_check),
                "{case}: only a connection the check keeps is reset"
            );
            assert_eq!(pool.stats().idle, usize::from(pooled), "{case}");
            assert_eq!(pool.stats().total, usize::from(pooled), "{case}");
            assert_eq!(
                manager.disconnects.load(Ordering::SeqCst),
                usize::from(!pooled),
                "{case}"
            );
            assert_eq!(
                pool.stats().total_discards,
                u64::from(!pooled),
                "{case}: a discarded connection is counted"
            );
        }

        // Dropping the guard keeps the deferred behavior: no reset runs.
        let pool = AsyncDbPool::new(
            ResettingAsyncManager::new(true, true, false),
            DbPoolConfig::with_max_size(1),
        );
        drop(block_on(pool.get(&cx)).expect("checkout"));
        assert_eq!(pool.manager.resets.load(Ordering::SeqCst), 0);
        assert_eq!(pool.manager.release_checks.load(Ordering::SeqCst), 1);
        assert_eq!(pool.stats().idle, 1);
        crate::test_complete!("reset_and_return_resets_before_the_connection_goes_idle");
    }

    /// A reset dropped before it completes leaves the session state
    /// unknown: the connection is discarded, never pooled.
    #[test]
    fn a_cancelled_reset_and_return_discards_the_connection() {
        use std::future::Future;
        init_test("a_cancelled_reset_and_return_discards_the_connection");
        let cx = Cx::for_testing();
        let pool = AsyncDbPool::new(
            ResettingAsyncManager::new(true, true, true),
            DbPoolConfig::with_max_size(1),
        );
        let conn = block_on(pool.get(&cx)).expect("checkout");
        {
            let mut returning = std::pin::pin!(conn.reset_and_return(&cx));
            let mut task_cx = std::task::Context::from_waker(std::task::Waker::noop());
            assert!(returning.as_mut().poll(&mut task_cx).is_pending());
            assert_eq!(
                pool.manager.resets.load(Ordering::SeqCst),
                1,
                "reset in flight"
            );
            assert_eq!(pool.stats().active, 1, "still borrowed while it resets");
        }
        assert_eq!(pool.stats().idle, 0, "a cancelled reset never pools it");
        assert_eq!(pool.stats().total, 0);
        assert_eq!(pool.stats().total_discards, 1, "and counts it discarded");
        assert_eq!(pool.manager.disconnects.load(Ordering::SeqCst), 1);
        assert_eq!(pool.manager.release_checks.load(Ordering::SeqCst), 1);
        crate::test_complete!("a_cancelled_reset_and_return_discards_the_connection");
    }

    #[test]
    fn async_pool_outcome_preserves_manager_terminals_without_retry() {
        init_test("async_pool_outcome_preserves_manager_terminals_without_retry");
        let expected = [
            Outcome::Cancelled(attributed_pool_cancel_reason()),
            Outcome::Panicked(crate::types::PanicPayload::new("connect panic sentinel")),
        ];

        for terminal in expected {
            for entry in ["anonymous", "client", "retry"] {
                let pool = AsyncDbPool::new(
                    ControlledAsyncPoolManager::new(terminal.clone()),
                    DbPoolConfig::with_max_size(1).max_connections_per_client(Some(1)),
                );
                let cx = Cx::for_testing();
                let policy = RetryPolicy::immediate(4);
                let actual = match entry {
                    "anonymous" => block_on(pool.get_outcome(&cx)),
                    "client" => block_on(pool.get_for_client_outcome(&cx, "client")),
                    "retry" => block_on(pool.get_with_retry_outcome(&cx, &policy)),
                    _ => unreachable!(),
                };
                match (actual, &terminal) {
                    (Outcome::Cancelled(actual), Outcome::Cancelled(expected)) => {
                        assert_eq!(&actual, expected, "{entry} must retain all attribution");
                    }
                    (Outcome::Panicked(actual), Outcome::Panicked(expected)) => {
                        assert_eq!(&actual, expected, "{entry} must retain the panic payload");
                    }
                    (actual, expected) => {
                        panic!("{entry} returned {actual:?}, expected {expected:?}");
                    }
                }
                assert_eq!(
                    pool.manager.connect_calls.load(Ordering::SeqCst),
                    1,
                    "{entry} must not retry cancellation or panic"
                );
                assert_eq!(pool.stats().total, 0, "{entry} leaked pool capacity");
                assert_eq!(pool.stats().active, 0, "{entry} leaked an active lease");
                assert!(pool.inner.lock().client_connections.is_empty());
            }
        }
        crate::test_complete!("async_pool_outcome_preserves_manager_terminals_without_retry");
    }

    #[test]
    fn async_pool_legacy_acquisition_retains_terminal_timeout_mapping() {
        init_test("async_pool_legacy_acquisition_retains_terminal_timeout_mapping");
        for terminal in [
            Outcome::Cancelled(attributed_pool_cancel_reason()),
            Outcome::Panicked(crate::types::PanicPayload::new("legacy connect panic")),
        ] {
            for entry in ["anonymous", "client", "retry"] {
                let pool = AsyncDbPool::new(
                    ControlledAsyncPoolManager::new(terminal.clone()),
                    DbPoolConfig::with_max_size(1),
                );
                let cx = Cx::for_testing();
                let policy = RetryPolicy::immediate(4);
                let actual = match entry {
                    "anonymous" => block_on(pool.get(&cx)),
                    "client" => block_on(pool.get_for_client(&cx, "client")),
                    "retry" => block_on(pool.get_with_retry(&cx, &policy)),
                    _ => unreachable!(),
                };
                assert!(matches!(actual, Err(DbPoolError::Timeout)), "{entry}");
                assert_eq!(pool.manager.connect_calls.load(Ordering::SeqCst), 1);
                assert_eq!(pool.stats().total, 0);
                assert!(pool.inner.lock().client_connections.is_empty());
            }
        }
        crate::test_complete!("async_pool_legacy_acquisition_retains_terminal_timeout_mapping");
    }

    #[test]
    fn async_client_dropped_acquire_releases_only_its_own_quota() {
        use std::future::Future;

        init_test("async_client_dropped_acquire_releases_only_its_own_quota");
        for validating in [false, true] {
            for legacy in [false, true] {
                let pool = AsyncDbPool::new(
                    ControlledAsyncPoolManager::new(Outcome::Ok(())),
                    DbPoolConfig::with_max_size(2).max_connections_per_client(Some(2)),
                );
                let cx = Cx::for_testing();
                let sibling = block_on(pool.get_for_client(&cx, "client"))
                    .expect("first client lease must be available");
                if validating {
                    block_on(pool.get_for_client(&cx, "client"))
                        .expect("seed a second connection for validation")
                        .return_to_pool();
                    pool.manager.pause_validation.store(true, Ordering::SeqCst);
                } else {
                    pool.manager.pause_connect.store(true, Ordering::SeqCst);
                }

                let waker = std::task::Waker::noop();
                let mut task_cx = std::task::Context::from_waker(waker);
                let mut acquisition = Box::pin(async {
                    if legacy {
                        Outcome::from(pool.get_for_client(&cx, "client").await)
                    } else {
                        pool.get_for_client_outcome(&cx, "client").await
                    }
                });
                assert!(acquisition.as_mut().poll(&mut task_cx).is_pending());
                assert_eq!(pool.stats().total, 2);
                assert_eq!(pool.stats().active, 2);
                assert_eq!(
                    pool.inner.lock().client_connections.get("client"),
                    Some(&2),
                    "the pending attempt and sibling must each own a quota slot"
                );
                assert_eq!(pool.manager.connect_calls.load(Ordering::SeqCst), 2);
                assert_eq!(
                    pool.manager.validation_calls.load(Ordering::SeqCst),
                    usize::from(validating),
                    "the future must reach the intended manager await"
                );

                drop(acquisition);
                assert_eq!(pool.stats().total, 1);
                assert_eq!(pool.stats().active, 1);
                assert_eq!(pool.stats().idle, 0);
                assert_eq!(
                    pool.inner.lock().client_connections.get("client"),
                    Some(&1),
                    "hard drop must free one quota slot and retain the sibling's slot"
                );
                assert_eq!(
                    pool.manager.disconnects.load(Ordering::SeqCst),
                    usize::from(validating)
                );

                pool.manager.pause_connect.store(false, Ordering::SeqCst);
                pool.manager.pause_validation.store(false, Ordering::SeqCst);
                let recovered = match block_on(pool.get_for_client_outcome(&cx, "client")) {
                    Outcome::Ok(conn) => conn,
                    other => panic!("the released client quota must be reusable: {other:?}"),
                };
                assert!(matches!(
                    block_on(pool.get_for_client_outcome(&cx, "client")),
                    Outcome::Err(DbPoolError::ClientQuotaExceeded(client)) if client == "client"
                ));
                drop(recovered);
                assert_eq!(pool.inner.lock().client_connections.get("client"), Some(&1));
                drop(sibling);
                assert!(pool.inner.lock().client_connections.is_empty());
                assert_eq!(pool.stats().active, 0);
            }
        }
        crate::test_complete!("async_client_dropped_acquire_releases_only_its_own_quota");
    }

    #[test]
    fn async_client_close_during_acquire_prevents_checkout_and_releases_quota() {
        use std::future::Future;

        init_test("async_client_close_during_acquire_prevents_checkout_and_releases_quota");
        for validating in [false, true] {
            for legacy in [false, true] {
                let pool = AsyncDbPool::new(
                    ControlledAsyncPoolManager::new(Outcome::Ok(())),
                    DbPoolConfig::with_max_size(1).max_connections_per_client(Some(1)),
                );
                let cx = Cx::for_testing();
                if validating {
                    block_on(pool.get_for_client(&cx, "client"))
                        .expect("seed the idle connection")
                        .return_to_pool();
                    pool.manager.pause_validation.store(true, Ordering::SeqCst);
                } else {
                    pool.manager.pause_connect.store(true, Ordering::SeqCst);
                }

                let waker = std::task::Waker::noop();
                let mut task_cx = std::task::Context::from_waker(waker);
                let mut acquisition = Box::pin(async {
                    if legacy {
                        Outcome::from(pool.get_for_client(&cx, "client").await)
                    } else {
                        pool.get_for_client_outcome(&cx, "client").await
                    }
                });
                assert!(acquisition.as_mut().poll(&mut task_cx).is_pending());
                assert_eq!(pool.stats().active, 1);
                assert_eq!(pool.inner.lock().client_connections.get("client"), Some(&1));
                assert_eq!(
                    pool.manager.validation_calls.load(Ordering::SeqCst),
                    usize::from(validating)
                );

                pool.close();
                pool.manager.pause_connect.store(false, Ordering::SeqCst);
                pool.manager.pause_validation.store(false, Ordering::SeqCst);
                assert!(matches!(
                    acquisition.as_mut().poll(&mut task_cx),
                    std::task::Poll::Ready(Outcome::Err(DbPoolError::Closed))
                ));
                drop(acquisition);
                assert_eq!(pool.stats().total, 0);
                assert_eq!(pool.stats().active, 0);
                assert_eq!(pool.stats().idle, 0);
                assert_eq!(pool.stats().total_acquisitions, u64::from(validating));
                assert!(pool.inner.lock().client_connections.is_empty());
                assert_eq!(pool.manager.disconnects.load(Ordering::SeqCst), 1);
            }
        }
        crate::test_complete!(
            "async_client_close_during_acquire_prevents_checkout_and_releases_quota"
        );
    }

    #[test]
    fn async_pool_outcome_preserves_caller_cancellation_before_and_while_queued() {
        use std::future::Future;

        init_test("async_pool_outcome_preserves_caller_cancellation_before_and_while_queued");
        for queued in [false, true] {
            for client in [false, true] {
                let pool = AsyncDbPool::new(
                    ControlledAsyncPoolManager::new(Outcome::Ok(())),
                    DbPoolConfig::with_max_size(1).max_connections_per_client(Some(1)),
                );
                let holder_cx = Cx::for_testing();
                let mut holder = if queued {
                    Some(block_on(pool.get(&holder_cx)).expect("hold the only pool slot"))
                } else {
                    None
                };
                let cx = Cx::for_testing();
                let expected = attributed_pool_cancel_reason();
                if !queued {
                    cx.set_cancel_reason(expected.clone());
                }

                let waker = std::task::Waker::noop();
                let mut task_cx = std::task::Context::from_waker(waker);
                let mut acquisition = Box::pin(async {
                    if client {
                        pool.get_for_client_outcome(&cx, "client").await
                    } else {
                        pool.get_outcome(&cx).await
                    }
                });
                if queued {
                    assert!(acquisition.as_mut().poll(&mut task_cx).is_pending());
                    assert_eq!(pool.stats().pending_waiters, 1);
                    assert_eq!(pool.stats().active, 1);
                    cx.set_cancel_reason(expected.clone());
                    holder
                        .take()
                        .expect("holder remains checked out")
                        .return_to_pool();
                }

                match acquisition.as_mut().poll(&mut task_cx) {
                    std::task::Poll::Ready(Outcome::Cancelled(actual)) => {
                        assert_eq!(actual, expected);
                    }
                    other => panic!("caller cancellation must retain its exact reason: {other:?}"),
                }
                drop(acquisition);
                let stats = pool.stats();
                assert_eq!(stats.pending_waiters, 0);
                assert_eq!(stats.active, 0);
                assert_eq!(stats.idle, usize::from(queued));
                assert_eq!(stats.total, usize::from(queued));
                assert_eq!(stats.total_acquisitions, u64::from(queued));
                assert_eq!(stats.total_timeouts, 0);
                assert_eq!(
                    pool.manager.connect_calls.load(Ordering::SeqCst),
                    usize::from(queued),
                    "the cancelled caller must not create or acquire a connection"
                );
                assert!(pool.inner.lock().client_connections.is_empty());
            }
        }
        crate::test_complete!(
            "async_pool_outcome_preserves_caller_cancellation_before_and_while_queued"
        );
    }

    #[test]
    fn async_pool_outcome_preserves_caller_cancellation_after_manager_success() {
        use std::future::Future;

        init_test("async_pool_outcome_preserves_caller_cancellation_after_manager_success");
        for validating in [false, true] {
            for client in [false, true] {
                let pool = AsyncDbPool::new(
                    ControlledAsyncPoolManager::new(Outcome::Ok(())),
                    DbPoolConfig::with_max_size(1).max_connections_per_client(Some(1)),
                );
                if validating {
                    let warm_cx = Cx::for_testing();
                    block_on(pool.get(&warm_cx))
                        .expect("seed the connection to validate")
                        .return_to_pool();
                    pool.manager.pause_validation.store(true, Ordering::SeqCst);
                } else {
                    pool.manager.pause_connect.store(true, Ordering::SeqCst);
                }

                let cx = Cx::for_testing();
                let waker = std::task::Waker::noop();
                let mut task_cx = std::task::Context::from_waker(waker);
                let mut acquisition = Box::pin(async {
                    if client {
                        pool.get_for_client_outcome(&cx, "client").await
                    } else {
                        pool.get_outcome(&cx).await
                    }
                });
                assert!(acquisition.as_mut().poll(&mut task_cx).is_pending());
                assert_eq!(pool.stats().total, 1);
                assert_eq!(pool.stats().active, 1);
                assert_eq!(pool.manager.connect_calls.load(Ordering::SeqCst), 1);
                assert_eq!(
                    pool.manager.validation_calls.load(Ordering::SeqCst),
                    usize::from(validating),
                    "the future must be parked in the intended manager operation"
                );
                assert_eq!(
                    pool.inner
                        .lock()
                        .client_connections
                        .get("client")
                        .copied()
                        .unwrap_or(0),
                    usize::from(client)
                );

                let expected = attributed_pool_cancel_reason();
                cx.set_cancel_reason(expected.clone());
                pool.manager.pause_connect.store(false, Ordering::SeqCst);
                pool.manager.pause_validation.store(false, Ordering::SeqCst);
                match acquisition.as_mut().poll(&mut task_cx) {
                    std::task::Poll::Ready(Outcome::Cancelled(actual)) => {
                        assert_eq!(actual, expected);
                    }
                    other => panic!("late manager success must not erase cancellation: {other:?}"),
                }
                drop(acquisition);
                let stats = pool.stats();
                assert_eq!(stats.total, 0);
                assert_eq!(stats.active, 0);
                assert_eq!(stats.idle, 0);
                assert_eq!(stats.pending_waiters, 0);
                assert_eq!(stats.total_acquisitions, u64::from(validating));
                assert_eq!(stats.total_discards, 1);
                assert_eq!(stats.total_timeouts, 0);
                assert!(pool.inner.lock().client_connections.is_empty());
                assert_eq!(pool.manager.disconnects.load(Ordering::SeqCst), 1);
            }
        }
        crate::test_complete!(
            "async_pool_outcome_preserves_caller_cancellation_after_manager_success"
        );
    }

    #[test]
    fn async_pool_outcome_zero_acquire_budget_returns_domain_timeout() {
        init_test("async_pool_outcome_zero_acquire_budget_returns_domain_timeout");
        for client in [false, true] {
            let pool = AsyncDbPool::new(
                ControlledAsyncPoolManager::new(Outcome::Ok(())),
                DbPoolConfig::with_max_size(1).connection_timeout(Duration::ZERO),
            );
            let holder_cx = Cx::for_testing();
            let holder = block_on(pool.get(&holder_cx)).expect("hold the only pool slot");
            let cx = Cx::for_testing();
            let actual = if client {
                block_on(pool.get_for_client_outcome(&cx, "client"))
            } else {
                block_on(pool.get_outcome(&cx))
            };
            assert!(matches!(actual, Outcome::Err(DbPoolError::AcquireTimeout)));
            let stats = pool.stats();
            assert_eq!(stats.pending_waiters, 0);
            assert_eq!(stats.total, 1);
            assert_eq!(stats.active, 1);
            assert_eq!(stats.idle, 0);
            assert_eq!(stats.total_timeouts, 1);
            assert_eq!(stats.total_acquisitions, 1);
            assert_eq!(pool.manager.connect_calls.load(Ordering::SeqCst), 1);
            assert!(pool.inner.lock().client_connections.is_empty());
            holder.return_to_pool();
            assert_eq!(pool.stats().active, 0);
            assert_eq!(pool.stats().idle, 1);
        }
        crate::test_complete!("async_pool_outcome_zero_acquire_budget_returns_domain_timeout");
    }

    #[test]
    fn async_pool_advisory_sizing_stays_observe_only() {
        init_test("async_pool_advisory_sizing_stays_observe_only");
        let pool = AsyncDbPool::new(
            AsyncTestManager::new(),
            DbPoolConfig::with_max_size(6).min_idle(2),
        );
        let estimate = PoolWorkloadEstimate::new(6_000_000, 1_000_000, 0);
        let target = PoolSizingTarget::MaxWaitProbabilityPpm(50_000);

        let decision = pool.advisory_pool_sizing_decision(estimate, target);
        assert_eq!(decision.action, PoolSizingAction::ObserveOnly);
        assert_eq!(decision.recommendation.bounds, PoolSizingBounds::new(2, 6));
        assert_eq!(decision.recommendation.target, target);
        assert_eq!(
            pool.pool_sizing_controller_state(),
            PoolSizingControllerState {
                current_size: 0,
                last_resize_epoch: 0,
            }
        );
        assert_eq!(pool.manager.creates.load(Ordering::SeqCst), 0);
        crate::test_complete!("async_pool_advisory_sizing_stays_observe_only");
    }

    #[test]
    fn async_get_records_structured_pool_lifecycle_traces() {
        init_test("async_get_records_structured_pool_lifecycle_traces");
        let cx = Cx::for_testing();
        let collector = LogCollector::new(32).with_min_level(LogLevel::Trace);
        cx.set_log_collector(collector.clone());
        let pool = AsyncDbPool::new(AsyncTestManager::new(), DbPoolConfig::with_max_size(1));

        {
            let first = block_on(pool.get(&cx)).expect("first checkout creates");
            assert_eq!(first.id, 1);
        }
        {
            let second = block_on(pool.get(&cx)).expect("second checkout reuses idle");
            assert_eq!(second.id, 1);
        }

        let entries = collector.peek();
        assert!(
            has_pool_lifecycle_entry(&entries, "acquire", "start", "anonymous"),
            "acquire start trace missing from {entries:?}"
        );
        assert!(
            has_pool_lifecycle_entry(&entries, "create", "start", "anonymous"),
            "create start trace missing from {entries:?}"
        );
        assert!(
            has_pool_lifecycle_entry(&entries, "acquire", "ok_created", "anonymous"),
            "created checkout trace missing from {entries:?}"
        );
        assert!(
            has_pool_lifecycle_entry(&entries, "acquire", "ok_idle", "anonymous"),
            "idle checkout trace missing from {entries:?}"
        );
        crate::test_complete!("async_get_records_structured_pool_lifecycle_traces");
    }

    struct SlowAsyncTestManager {
        next_id: AtomicUsize,
        valid: Arc<AtomicBool>,
        disconnects: AtomicUsize,
        connect_delay: Duration,
        validate_delay: Duration,
    }

    impl SlowAsyncTestManager {
        fn with_delays(connect_delay: Duration, validate_delay: Duration) -> Self {
            Self {
                next_id: AtomicUsize::new(1),
                valid: Arc::new(AtomicBool::new(true)),
                disconnects: AtomicUsize::new(0),
                connect_delay,
                validate_delay,
            }
        }

        fn disconnects(&self) -> usize {
            self.disconnects.load(Ordering::SeqCst)
        }
    }

    impl AsyncConnectionManager for SlowAsyncTestManager {
        type Connection = TestConnection;
        type Error = TestError;

        async fn connect(&self, _cx: &Cx) -> Outcome<Self::Connection, Self::Error> {
            crate::time::sleep(crate::time::wall_now(), self.connect_delay).await;
            let id = self.next_id.fetch_add(1, Ordering::SeqCst);
            Outcome::Ok(TestConnection {
                id,
                valid: self.valid.clone(),
            })
        }

        async fn is_valid(&self, _cx: &Cx, conn: &mut Self::Connection) -> bool {
            crate::time::sleep(crate::time::wall_now(), self.validate_delay).await;
            conn.valid.load(Ordering::SeqCst)
        }

        fn disconnect(&self, _conn: Self::Connection) {
            self.disconnects.fetch_add(1, Ordering::SeqCst);
        }
    }

    // ================================================================
    // DbPoolConfig
    // ================================================================

    #[test]
    fn config_defaults() {
        init_test("config_defaults");
        let config = DbPoolConfig::default();
        assert_eq!(config.min_idle, 1);
        assert_eq!(config.max_size, 10);
        assert!(config.validate_on_checkout);
        assert_eq!(config.idle_timeout, Duration::from_secs(600));
        assert_eq!(config.max_lifetime, Duration::from_secs(3600));
        assert_eq!(config.connection_timeout, Duration::from_secs(30));
        crate::test_complete!("config_defaults");
    }

    #[test]
    fn config_builder() {
        init_test("config_builder");
        let config = DbPoolConfig::with_max_size(20)
            .min_idle(5)
            .validate_on_checkout(false)
            .idle_timeout(Duration::from_secs(120))
            .max_lifetime(Duration::from_secs(600))
            .connection_timeout(Duration::from_secs(10));

        assert_eq!(config.max_size, 20);
        assert_eq!(config.min_idle, 5);
        assert!(!config.validate_on_checkout);
        assert_eq!(config.idle_timeout, Duration::from_secs(120));
        assert_eq!(config.max_lifetime, Duration::from_secs(600));
        assert_eq!(config.connection_timeout, Duration::from_secs(10));
        crate::test_complete!("config_builder");
    }

    #[test]
    fn config_pool_sizing_bounds_follow_min_idle_and_max_size() {
        init_test("config_pool_sizing_bounds_follow_min_idle_and_max_size");
        let config = DbPoolConfig::with_max_size(8).min_idle(3);

        assert_eq!(config.pool_sizing_bounds(), PoolSizingBounds::new(3, 8));
        crate::test_complete!("config_pool_sizing_bounds_follow_min_idle_and_max_size");
    }

    #[test]
    fn config_debug_clone() {
        let config = DbPoolConfig::default();
        let dbg = format!("{config:?}");
        assert!(dbg.contains("DbPoolConfig"));
        let cloned = config;
        assert_eq!(cloned.max_size, 10);
    }

    // ================================================================
    // DbPool basics
    // ================================================================

    #[test]
    fn pool_new() {
        init_test("pool_new");
        let pool = DbPool::new(TestManager::new(), DbPoolConfig::default());
        let stats = pool.stats();
        assert_eq!(stats.idle, 0);
        assert_eq!(stats.active, 0);
        assert_eq!(stats.total, 0);
        assert_eq!(stats.max_size, 10);
        assert!(!pool.is_closed());
        crate::test_complete!("pool_new");
    }

    #[test]
    fn pool_advisory_sizing_uses_live_total_without_mutating_capacity() {
        init_test("pool_advisory_sizing_uses_live_total_without_mutating_capacity");
        let manager = TestManager::new();
        let pool = DbPool::new(
            manager.clone(),
            DbPoolConfig::with_max_size(4)
                .min_idle(1)
                .validate_on_checkout(false),
        );
        let _first = pool.get().expect("first checkout creates a connection");
        let _second = pool.get().expect("second checkout creates a connection");
        let estimate = PoolWorkloadEstimate::new(5_000_000, 1_000_000, 0);
        let target = PoolSizingTarget::MaxWaitProbabilityPpm(100_000);

        assert_eq!(pool.pool_sizing_bounds(), PoolSizingBounds::new(1, 4));
        assert_eq!(
            pool.pool_sizing_controller_state(),
            PoolSizingControllerState {
                current_size: 2,
                last_resize_epoch: 0,
            }
        );

        let decision = pool.advisory_pool_sizing_decision(estimate, target);
        assert_eq!(decision.action, PoolSizingAction::ObserveOnly);
        assert_eq!(decision.recommendation.bounds, PoolSizingBounds::new(1, 4));
        assert_eq!(decision.recommendation.target, target);
        assert_eq!(manager.creates.load(Ordering::SeqCst), 2);
        assert_eq!(pool.stats().total, 2);
        crate::test_complete!("pool_advisory_sizing_uses_live_total_without_mutating_capacity");
    }

    #[test]
    fn get_with_retry_observes_close_during_backoff() {
        init_test("get_with_retry_observes_close_during_backoff");
        let pool = Arc::new(DbPool::new(
            TestManager::new(),
            DbPoolConfig::with_max_size(1)
                .validate_on_checkout(false)
                .connection_timeout(Duration::from_secs(1)),
        ));
        let held = pool.get().expect("holder acquires the only slot");
        let policy = RetryPolicy::fixed_delay(Duration::from_millis(250), 3);
        let close_pool = Arc::clone(&pool);
        let closer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            close_pool.close();
        });

        let started = Instant::now();
        let result = pool.get_with_retry(&policy);
        let elapsed = started.elapsed();

        closer.join().expect("close thread should finish cleanly");

        assert!(matches!(result, Err(DbPoolError::Closed)));
        assert!(
            elapsed < Duration::from_millis(200),
            "close during retry backoff should stop promptly, observed {elapsed:?}"
        );

        drop(held);

        let stats = pool.stats();
        assert_eq!(stats.total, 0, "closed pool should not retain capacity");
        assert_eq!(
            stats.active, 0,
            "closed pool should not retain active leases"
        );
        assert_eq!(
            stats.total_discards, 1,
            "return after close should discard the held connection"
        );
        assert_eq!(pool.manager.disconnects(), 1);
        crate::test_complete!("get_with_retry_observes_close_during_backoff");
    }

    #[test]
    fn async_get_with_retry_observes_close_during_backoff() {
        init_test("async_get_with_retry_observes_close_during_backoff");
        let pool = Arc::new(AsyncDbPool::new(
            AsyncTestManager::always_failing(),
            DbPoolConfig::with_max_size(1)
                .validate_on_checkout(false)
                .connection_timeout(Duration::from_secs(1)),
        ));
        let policy = RetryPolicy::fixed_delay(Duration::from_millis(250), 3);
        let cx = Cx::for_testing();
        let close_pool = Arc::clone(&pool);
        let closer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            close_pool.close();
        });

        let started = Instant::now();
        let result = block_on(pool.get_with_retry(&cx, &policy));
        let elapsed = started.elapsed();

        closer.join().expect("close thread should finish cleanly");

        assert!(matches!(result, Err(DbPoolError::Closed)));
        assert!(
            elapsed < Duration::from_millis(200),
            "close during retry backoff should stop promptly, observed {elapsed:?}"
        );
        let stats = pool.stats();
        assert_eq!(
            stats.total, 0,
            "closed async pool should not retain capacity"
        );
        assert_eq!(
            stats.active, 0,
            "closed async pool should not retain active leases"
        );
        crate::test_complete!("async_get_with_retry_observes_close_during_backoff");
    }

    #[test]
    fn async_get_with_retry_observes_cancellation_during_backoff() {
        init_test("async_get_with_retry_observes_cancellation_during_backoff");
        let pool = AsyncDbPool::new(
            AsyncTestManager::always_failing(),
            DbPoolConfig::with_max_size(1)
                .validate_on_checkout(false)
                .connection_timeout(Duration::from_secs(1)),
        );
        let policy = RetryPolicy::fixed_delay(Duration::from_millis(250), 3);
        let cx = Cx::for_testing();
        let cancel_cx = cx.clone();
        let canceller = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(25));
            cancel_cx.set_cancel_requested(true);
        });

        let started = Instant::now();
        let result = block_on(pool.get_with_retry(&cx, &policy));
        let elapsed = started.elapsed();

        canceller
            .join()
            .expect("cancel thread should finish cleanly");

        assert!(matches!(result, Err(DbPoolError::Timeout)));
        assert!(
            elapsed < Duration::from_millis(200),
            "cancellation during backoff should stop promptly, observed {elapsed:?}"
        );
        let stats = pool.stats();
        assert_eq!(
            stats.total, 0,
            "cancelled retries must not leak connections"
        );
        assert_eq!(
            stats.active, 0,
            "cancelled retries must not hold active leases"
        );
        crate::test_complete!("async_get_with_retry_observes_cancellation_during_backoff");
    }

    /// A waiter woken for capacity that a shrink then took was still marked
    /// ready: its wait returned at once and the acquire loop spun without
    /// yielding, so it never timed out.
    #[test]
    fn async_waiter_whose_capacity_was_shrunk_away_parks_until_timeout() {
        init_test("async_waiter_whose_capacity_was_shrunk_away_parks_until_timeout");
        let pool = Arc::new(AsyncDbPool::new(
            AsyncTestManager::new(),
            DbPoolConfig::with_max_size(2)
                .validate_on_checkout(false)
                .connection_timeout(Duration::from_millis(200)),
        ));
        let cx = Cx::for_testing();
        let first = block_on(pool.get(&cx)).expect("first connection");
        let second = block_on(pool.get(&cx)).expect("second connection");

        let (tx, rx) = std::sync::mpsc::channel();
        let waiter_pool = Arc::clone(&pool);
        let waiter = std::thread::spawn(move || {
            let cx = Cx::for_testing();
            let result = block_on(waiter_pool.get(&cx)).map(drop);
            let _ = tx.send(matches!(result, Err(DbPoolError::AcquireTimeout)));
        });
        while pool.stats().pending_waiters == 0 {
            std::thread::sleep(Duration::from_millis(1));
        }
        // What a wake followed by a shrink leaves behind: the front waiter
        // is ready and the pool has no capacity for it.
        {
            let inner = pool.inner.lock();
            let front = inner.waiters.front().expect("queued waiter");
            front.ready.store(true, Ordering::Release);
            front.notify.notify_one();
        }

        let timed_out = rx
            .recv_timeout(Duration::from_secs(10))
            .expect("the acquire must return instead of spinning");
        assert!(timed_out, "no capacity came back, so the acquire times out");
        waiter.join().expect("waiter thread");
        drop((first, second));
        crate::test_complete!("async_waiter_whose_capacity_was_shrunk_away_parks_until_timeout");
    }

    /// Raising the cap did not wake anyone, so a parked waiter kept waiting
    /// for a release while the pool had room for it.
    #[test]
    fn raising_the_async_pool_cap_wakes_a_parked_waiter() {
        init_test("raising_the_async_pool_cap_wakes_a_parked_waiter");
        let pool = Arc::new(AsyncDbPool::new(
            AsyncTestManager::new(),
            DbPoolConfig::with_max_size(2)
                .validate_on_checkout(false)
                .connection_timeout(Duration::from_secs(5)),
        ));
        assert_eq!(pool.set_max_size(1), 1);
        let cx = Cx::for_testing();
        let held = block_on(pool.get(&cx)).expect("held connection");

        let (tx, rx) = std::sync::mpsc::channel();
        let waiter_pool = Arc::clone(&pool);
        let waiter = std::thread::spawn(move || {
            let cx = Cx::for_testing();
            let result = block_on(waiter_pool.get(&cx)).map(drop);
            let _ = tx.send(result.is_ok());
        });
        while pool.stats().pending_waiters == 0 {
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(pool.set_max_size(2), 2);

        let acquired = rx
            .recv_timeout(Duration::from_secs(2))
            .expect("the raised cap must wake the waiter");
        assert!(acquired, "the waiter gets a new connection");
        waiter.join().expect("waiter thread");
        drop(held);
        crate::test_complete!("raising_the_async_pool_cap_wakes_a_parked_waiter");
    }

    #[test]
    fn async_get_cancellation_after_connect_does_not_hand_out_connection() {
        init_test("async_get_cancellation_after_connect_does_not_hand_out_connection");
        let pool = AsyncDbPool::new(
            SlowAsyncTestManager::with_delays(Duration::from_millis(40), Duration::ZERO),
            DbPoolConfig::with_max_size(1).validate_on_checkout(false),
        );
        let cx = Cx::for_testing();
        let cancel_cx = cx.clone();
        let canceller = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(10));
            cancel_cx.set_cancel_requested(true);
        });

        let result = block_on(pool.get(&cx));

        canceller
            .join()
            .expect("cancel thread should finish cleanly");

        assert!(matches!(result, Err(DbPoolError::Timeout)));
        let stats = pool.stats();
        assert_eq!(stats.total, 0, "cancelled connect must not retain capacity");
        assert_eq!(
            stats.active, 0,
            "cancelled connect must not hand out a lease"
        );
        assert_eq!(
            stats.total_discards, 1,
            "late connect success should be disconnected"
        );
        assert_eq!(pool.manager.disconnects(), 1);
        crate::test_complete!("async_get_cancellation_after_connect_does_not_hand_out_connection");
    }

    #[test]
    fn async_get_cancellation_during_validation_discards_connection() {
        init_test("async_get_cancellation_during_validation_discards_connection");
        let pool = AsyncDbPool::new(
            SlowAsyncTestManager::with_delays(Duration::ZERO, Duration::from_millis(40)),
            DbPoolConfig::with_max_size(1),
        );

        let warm_cx = Cx::for_testing();
        let conn = block_on(pool.get(&warm_cx)).expect("warmup acquire should succeed");
        conn.return_to_pool();
        assert_eq!(
            pool.stats().idle,
            1,
            "warmup should leave one idle connection"
        );

        let cx = Cx::for_testing();
        let cancel_cx = cx.clone();
        let canceller = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(10));
            cancel_cx.set_cancel_requested(true);
        });

        let result = block_on(pool.get(&cx));

        canceller
            .join()
            .expect("cancel thread should finish cleanly");

        assert!(matches!(result, Err(DbPoolError::Timeout)));
        let stats = pool.stats();
        assert_eq!(
            stats.total, 0,
            "cancelled validation must discard the in-flight connection"
        );
        assert_eq!(
            stats.active, 0,
            "cancelled validation must not leak a checked-out lease"
        );
        assert_eq!(
            stats.idle, 0,
            "cancelled validation must not return the stale connection"
        );
        assert_eq!(
            stats.total_discards, 1,
            "validated connection cancelled mid-flight should be disconnected"
        );
        assert_eq!(pool.manager.disconnects(), 1);
        crate::test_complete!("async_get_cancellation_during_validation_discards_connection");
    }

    #[test]
    fn mr_cancelled_async_acquire_releases_slot_across_cancellation_points() {
        init_test("mr_cancelled_async_acquire_releases_slot_across_cancellation_points");
        let mut recovered_inventory = Vec::new();

        for (name, connect_delay, validate_delay, needs_warm_idle) in [
            (
                "after_connect",
                Duration::from_millis(40),
                Duration::ZERO,
                false,
            ),
            (
                "during_validation",
                Duration::ZERO,
                Duration::from_millis(40),
                true,
            ),
        ] {
            let pool = AsyncDbPool::new(
                SlowAsyncTestManager::with_delays(connect_delay, validate_delay),
                DbPoolConfig::with_max_size(1).validate_on_checkout(!validate_delay.is_zero()),
            );

            if needs_warm_idle {
                let warm_cx = Cx::for_testing();
                let lease = block_on(pool.get(&warm_cx)).expect("warmup acquire should succeed");
                lease.return_to_pool();
                assert_eq!(
                    pool.stats().idle,
                    1,
                    "{name} should start from an idle lease"
                );
            }

            let cx = Cx::for_testing();
            let cancel_cx = cx.clone();
            let canceller = std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(10));
                cancel_cx.set_cancel_requested(true);
            });

            let result = block_on(pool.get(&cx));

            canceller
                .join()
                .expect("cancel thread should finish cleanly");

            assert!(
                matches!(result, Err(DbPoolError::Timeout)),
                "{name} cancellation point should time out the acquire"
            );

            let post_cancel = pool.stats();
            assert_eq!(post_cancel.total, 0, "{name} must release total capacity");
            assert_eq!(post_cancel.active, 0, "{name} must release active capacity");
            assert_eq!(post_cancel.idle, 0, "{name} must leave no stale idle lease");

            let recovery_cx = Cx::for_testing();
            let recovery = block_on(pool.get(&recovery_cx))
                .expect("fresh acquire should succeed after cancelled attempt");
            recovery.return_to_pool();
            let final_stats = pool.stats();
            assert_eq!(
                final_stats.idle, 1,
                "{name} should recover one reusable idle lease"
            );
            assert_eq!(
                final_stats.active, 0,
                "{name} should not retain active leases"
            );
            assert_eq!(
                final_stats.total, 1,
                "{name} should recover exactly one slot"
            );
            recovered_inventory.push(db_pool_inventory_snapshot(&final_stats));
        }

        assert!(
            recovered_inventory
                .windows(2)
                .all(|pair| pair[0] == pair[1]),
            "cancellation point should not change recovered pool inventory"
        );
        crate::test_complete!(
            "mr_cancelled_async_acquire_releases_slot_across_cancellation_points"
        );
    }

    #[test]
    fn async_pool_contention_retries_under_lab_runtime() {
        init_test("async_pool_contention_retries_under_lab_runtime");
        let config = TestConfig::new()
            .with_seed(0xD8A5_E001)
            .with_tracing(true)
            .with_max_steps(20_000);
        let mut runtime = LabRuntimeTarget::create_runtime(config);
        let pool = Arc::new(AsyncDbPool::new(
            AsyncTestManager::new(),
            DbPoolConfig::with_max_size(1)
                .validate_on_checkout(false)
                .connection_timeout(Duration::from_millis(200)),
        ));
        let retry_policy = RetryPolicy::fixed_delay(Duration::from_millis(5), 32);
        let checkpoints = Arc::new(Mutex::new(Vec::new()));
        let result_checkpoints = Arc::clone(&checkpoints);

        let (holder_id, waiter_id, final_stats) =
            LabRuntimeTarget::block_on(&mut runtime, async move {
                let cx = Cx::current().expect("lab runtime should install a current Cx");
                let holder_spawn_cx = cx.clone();
                let waiter_spawn_cx = cx.clone();

                let holder_pool = Arc::clone(&pool);
                let holder_checkpoints = Arc::clone(&checkpoints);
                let holder_task_cx = holder_spawn_cx.clone();
                let holder =
                    LabRuntimeTarget::spawn(&holder_spawn_cx, Budget::INFINITE, async move {
                        let lease = holder_pool
                            .get(&holder_task_cx)
                            .await
                            .expect("holder acquires pool lease");
                        let holder_id = lease.id;
                        let acquired = serde_json::json!({
                            "phase": "holder_acquired",
                            "connection_id": holder_id,
                        });
                        tracing::info!(event = %acquired, "pool_contention_lab_checkpoint");
                        holder_checkpoints.lock().push(acquired);

                        crate::time::sleep(holder_task_cx.now(), Duration::from_millis(25)).await;
                        yield_now().await;
                        lease.return_to_pool();

                        let returned = serde_json::json!({
                            "phase": "holder_returned",
                            "connection_id": holder_id,
                        });
                        tracing::info!(event = %returned, "pool_contention_lab_checkpoint");
                        holder_checkpoints.lock().push(returned);
                        holder_id
                    });

                let waiter_pool = Arc::clone(&pool);
                let waiter_checkpoints = Arc::clone(&checkpoints);
                let waiter_task_cx = waiter_spawn_cx.clone();
                let waiter =
                    LabRuntimeTarget::spawn(&waiter_spawn_cx, Budget::INFINITE, async move {
                        let started = serde_json::json!({
                            "phase": "waiter_started",
                            "max_attempts": retry_policy.max_attempts,
                        });
                        tracing::info!(event = %started, "pool_contention_lab_checkpoint");
                        waiter_checkpoints.lock().push(started);

                        let lease = waiter_pool
                            .get_with_retry(&waiter_task_cx, &retry_policy)
                            .await
                            .expect("waiter retries until the pool returns capacity");
                        let waiter_id = lease.id;
                        let acquired = serde_json::json!({
                            "phase": "waiter_acquired",
                            "connection_id": waiter_id,
                        });
                        tracing::info!(event = %acquired, "pool_contention_lab_checkpoint");
                        waiter_checkpoints.lock().push(acquired);
                        lease.return_to_pool();
                        waiter_id
                    });

                yield_now().await;

                let holder_outcome = holder.await;
                crate::assert_with_log!(
                    matches!(holder_outcome, crate::types::Outcome::Ok(_)),
                    "holder task completes successfully",
                    true,
                    matches!(holder_outcome, crate::types::Outcome::Ok(_))
                );
                let crate::types::Outcome::Ok(holder_id) = holder_outcome else {
                    unreachable!("validated successful holder outcome");
                };

                let waiter_outcome = waiter.await;
                crate::assert_with_log!(
                    matches!(waiter_outcome, crate::types::Outcome::Ok(_)),
                    "waiter task completes successfully",
                    true,
                    matches!(waiter_outcome, crate::types::Outcome::Ok(_))
                );
                let crate::types::Outcome::Ok(waiter_id) = waiter_outcome else {
                    unreachable!("validated successful waiter outcome");
                };

                (holder_id, waiter_id, pool.stats())
            });

        crate::assert_with_log!(
            holder_id == waiter_id,
            "waiter reuses returned connection",
            holder_id,
            waiter_id
        );
        crate::assert_with_log!(
            final_stats.total_creates == 1,
            "contention path creates only one connection",
            1,
            final_stats.total_creates
        );
        crate::assert_with_log!(
            final_stats.idle == 1,
            "connection returns to idle pool after both tasks",
            1,
            final_stats.idle
        );
        crate::assert_with_log!(
            final_stats.active == 0,
            "contention path leaves no active leases",
            0,
            final_stats.active
        );
        crate::assert_with_log!(
            result_checkpoints.lock().len() == 4,
            "lab runtime emits contention checkpoints",
            4,
            result_checkpoints.lock().len()
        );
        crate::assert_with_log!(
            runtime.is_quiescent(),
            "lab runtime reaches quiescence after pool contention",
            true,
            runtime.is_quiescent()
        );

        crate::test_complete!("async_pool_contention_retries_under_lab_runtime");
    }

    #[test]
    fn async_get_waits_for_returned_capacity_without_retry() {
        init_test("async_get_waits_for_returned_capacity_without_retry");
        let pool = Arc::new(AsyncDbPool::new(
            AsyncTestManager::new(),
            DbPoolConfig::with_max_size(1).validate_on_checkout(false),
        ));
        let cx = Cx::for_testing();
        let holder = block_on(pool.get(&cx)).expect("holder acquires the only slot");
        let holder_id = holder.id;
        let waiter_started = Arc::new(AtomicBool::new(false));
        let waiter_finished = Arc::new(AtomicBool::new(false));

        let waiter_pool = Arc::clone(&pool);
        let waiter_started_thread = Arc::clone(&waiter_started);
        let waiter_finished_thread = Arc::clone(&waiter_finished);
        let waiter = std::thread::spawn(move || {
            let cx = Cx::for_testing();
            waiter_started_thread.store(true, Ordering::SeqCst);
            let lease = block_on(waiter_pool.get(&cx))
                .expect("direct async get should wait for returned capacity");
            let waiter_id = lease.id;
            lease.return_to_pool();
            waiter_finished_thread.store(true, Ordering::SeqCst);
            waiter_id
        });

        while !waiter_started.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(1));
        }
        std::thread::sleep(Duration::from_millis(25));
        assert!(
            !waiter_finished.load(Ordering::SeqCst),
            "direct async get should not fail fast or acquire while the only slot is held"
        );

        holder.return_to_pool();
        let waiter_id = waiter.join().expect("waiter thread should not panic");
        assert_eq!(
            holder_id, waiter_id,
            "direct waiter should reuse the returned connection"
        );

        let stats = pool.stats();
        assert_eq!(stats.total_creates, 1);
        assert_eq!(stats.idle, 1);
        assert_eq!(stats.active, 0);
        crate::test_complete!("async_get_waits_for_returned_capacity_without_retry");
    }

    #[test]
    fn async_get_waiter_queue_admits_direct_waiters_fifo() {
        init_test("async_get_waiter_queue_admits_direct_waiters_fifo");

        #[derive(Debug, PartialEq, Eq)]
        enum Event {
            Started(u8),
            Acquired(u8),
        }

        let pool = Arc::new(AsyncDbPool::new(
            AsyncTestManager::new(),
            DbPoolConfig::with_max_size(1).validate_on_checkout(false),
        ));
        let holder_cx = Cx::for_testing();
        let holder = block_on(pool.get(&holder_cx)).expect("holder acquires the only slot");
        let (events_tx, events_rx) = std::sync::mpsc::channel();
        let (release_first_tx, release_first_rx) = std::sync::mpsc::channel();

        let first_pool = Arc::clone(&pool);
        let first_events = events_tx.clone();
        let first = std::thread::spawn(move || {
            let cx = Cx::for_testing();
            first_events.send(Event::Started(1)).expect("send start");
            let lease = block_on(first_pool.get(&cx)).expect("first waiter acquires");
            first_events
                .send(Event::Acquired(1))
                .expect("send acquisition");
            release_first_rx.recv().expect("first release signal");
            lease.return_to_pool();
        });

        assert_eq!(
            events_rx
                .recv_timeout(Duration::from_millis(500))
                .expect("first waiter starts"),
            Event::Started(1)
        );
        std::thread::sleep(Duration::from_millis(20));

        let second_pool = Arc::clone(&pool);
        let second_events = events_tx.clone();
        let second = std::thread::spawn(move || {
            let cx = Cx::for_testing();
            second_events.send(Event::Started(2)).expect("send start");
            let lease = block_on(second_pool.get(&cx)).expect("second waiter acquires");
            second_events
                .send(Event::Acquired(2))
                .expect("send acquisition");
            lease.return_to_pool();
        });

        assert_eq!(
            events_rx
                .recv_timeout(Duration::from_millis(500))
                .expect("second waiter starts"),
            Event::Started(2)
        );

        holder.return_to_pool();
        assert_eq!(
            events_rx
                .recv_timeout(Duration::from_millis(500))
                .expect("first waiter acquires after holder returns"),
            Event::Acquired(1)
        );
        assert!(
            events_rx.recv_timeout(Duration::from_millis(50)).is_err(),
            "second waiter must not acquire while the first waiter still holds the slot"
        );

        release_first_tx.send(()).expect("release first waiter");
        assert_eq!(
            events_rx
                .recv_timeout(Duration::from_millis(500))
                .expect("second waiter acquires after first returns"),
            Event::Acquired(2)
        );

        first.join().expect("first waiter thread should finish");
        second.join().expect("second waiter thread should finish");
        let stats = pool.stats();
        assert_eq!(stats.total_creates, 1);
        assert_eq!(stats.idle, 1);
        assert_eq!(stats.active, 0);
        crate::test_complete!("async_get_waiter_queue_admits_direct_waiters_fifo");
    }

    #[test]
    fn async_get_waiter_budget_exhaustion_returns_acquire_timeout() {
        init_test("async_get_waiter_budget_exhaustion_returns_acquire_timeout");
        let pool = AsyncDbPool::new(
            AsyncTestManager::new(),
            DbPoolConfig::with_max_size(1)
                .validate_on_checkout(false)
                .connection_timeout(Duration::from_millis(120)),
        );
        let holder_cx = Cx::for_testing();
        let holder = block_on(pool.get(&holder_cx)).expect("holder acquires the only slot");

        let waiter_cx = Cx::for_testing();
        let started = Instant::now();
        let outcome = block_on(pool.get(&waiter_cx));
        let elapsed = started.elapsed();

        let err = match outcome {
            Err(err) => err,
            Ok(_) => panic!("waiter must not acquire while the only slot is held"),
        };
        assert!(
            matches!(err, DbPoolError::AcquireTimeout),
            "exhausting the FIFO acquire budget must yield AcquireTimeout"
        );
        assert!(
            err.to_string().starts_with("[ASUP-E601]"),
            "AcquireTimeout Display must lead with the ASUP-E601 token, got: {err}"
        );
        assert!(
            elapsed >= Duration::from_millis(90),
            "acquire should wait close to the full budget before timing out, observed {elapsed:?}"
        );
        assert_eq!(
            pool.stats().total_timeouts,
            1,
            "budget exhaustion records exactly one acquire timeout"
        );

        holder.return_to_pool();
        crate::test_complete!("async_get_waiter_budget_exhaustion_returns_acquire_timeout");
    }

    #[test]
    fn async_pool_dropped_parked_waiter_does_not_wedge_queue() {
        use std::future::Future;

        init_test("async_pool_dropped_parked_waiter_does_not_wedge_queue");
        let pool = AsyncDbPool::new(
            AsyncTestManager::new(),
            DbPoolConfig::with_max_size(1)
                .validate_on_checkout(false)
                .connection_timeout(Duration::from_millis(200)),
        );
        let holder_cx = Cx::for_testing();
        let holder = block_on(pool.get(&holder_cx)).expect("holder acquires the only slot");

        // Park a waiter, then hard-drop its future — no cooperative cleanup arm
        // (checkpoint / closed / timeout) ever runs, so only the RAII guard's
        // Drop can reap the queue entry.
        let waker = std::task::Waker::noop();
        let mut ctx = std::task::Context::from_waker(waker);
        let parked_cx = Cx::for_testing();
        {
            let mut parked = std::pin::pin!(pool.get(&parked_cx));
            assert!(
                parked.as_mut().poll(&mut ctx).is_pending(),
                "waiter parks while the only slot is held"
            );
            assert_eq!(
                pool.inner.lock().waiters.len(),
                1,
                "the parked waiter is registered in the FIFO queue"
            );
            // `parked` is dropped here without being polled again.
        }

        // Regression: before the guard, the dropped future left an uncancelled
        // waiter pinned at the FIFO front, wedging every later async acquire
        // pool-wide. The guard must remove it.
        assert_eq!(
            pool.inner.lock().waiters.len(),
            0,
            "dropping a parked waiter future must not orphan its queue entry",
        );

        // The pool is still usable: release the holder and a fresh acquire wins.
        holder.return_to_pool();
        let next_cx = Cx::for_testing();
        let next = block_on(pool.get(&next_cx))
            .expect("async acquisition must not be wedged by the dropped waiter");
        next.return_to_pool();
        crate::test_complete!("async_pool_dropped_parked_waiter_does_not_wedge_queue");
    }

    #[test]
    fn pool_with_manager() {
        init_test("pool_with_manager");
        let pool = DbPool::with_manager(TestManager::new());
        assert_eq!(pool.config().max_size, 10);
        crate::test_complete!("pool_with_manager");
    }

    #[test]
    fn pool_debug() {
        let pool = DbPool::new(TestManager::new(), DbPoolConfig::default());
        let dbg = format!("{pool:?}");
        assert!(dbg.contains("DbPool"));
        assert!(dbg.contains("max_size"));
        assert!(dbg.contains("stats"));
        assert!(dbg.contains("total_acquisitions: 0"));
    }

    #[test]
    fn async_pool_debug() {
        let pool = AsyncDbPool::new(AsyncTestManager::new(), DbPoolConfig::default());
        let dbg = format!("{pool:?}");
        assert!(dbg.contains("AsyncDbPool"));
        assert!(dbg.contains("stats"));
        assert!(dbg.contains("total_acquisitions: 0"));
    }

    #[test]
    fn async_pool_debug_reports_live_counter_values() {
        init_test("async_pool_debug_reports_live_counter_values");
        let pool = AsyncDbPool::new(AsyncTestManager::new(), DbPoolConfig::default());
        let cx = Cx::for_testing();
        let _conn = block_on(pool.get(&cx)).expect("async pool get should succeed");

        let dbg = format!("{pool:?}");
        assert!(dbg.contains("total_acquisitions: 1"));
        assert!(dbg.contains("total_creates: 1"));
        assert!(dbg.contains("total_discards: 0"));
        crate::test_complete!("async_pool_debug_reports_live_counter_values");
    }

    // ================================================================
    // Get / return
    // ================================================================

    #[test]
    fn get_creates_connection() {
        init_test("get_creates_connection");
        let pool = DbPool::new(TestManager::new(), DbPoolConfig::default());
        let conn = pool.get().unwrap();
        assert_eq!(conn.id, 1);

        let stats = pool.stats();
        assert_eq!(stats.active, 1);
        assert_eq!(stats.total, 1);
        assert_eq!(stats.total_creates, 1);
        crate::test_complete!("get_creates_connection");
    }

    #[test]
    fn return_on_drop() {
        init_test("return_on_drop");
        let pool = DbPool::new(TestManager::new(), DbPoolConfig::default());

        {
            let _conn = pool.get().unwrap();
            assert_eq!(pool.stats().active, 1);
        }
        // Connection returned on drop.
        assert_eq!(pool.stats().idle, 1);
        assert_eq!(pool.stats().active, 0);
        crate::test_complete!("return_on_drop");
    }

    #[test]
    fn explicit_return() {
        init_test("explicit_return");
        let pool = DbPool::new(TestManager::new(), DbPoolConfig::default());

        let conn = pool.get().unwrap();
        conn.return_to_pool();
        assert_eq!(pool.stats().idle, 1);
        assert_eq!(pool.stats().active, 0);
        crate::test_complete!("explicit_return");
    }

    #[test]
    fn reuse_idle_connection() {
        init_test("reuse_idle_connection");
        let pool = DbPool::new(TestManager::new(), DbPoolConfig::default());

        // First checkout creates.
        let conn1 = pool.get().unwrap();
        let id1 = conn1.id;
        conn1.return_to_pool();

        // Second checkout reuses.
        let conn2 = pool.get().unwrap();
        assert_eq!(conn2.id, id1);
        assert_eq!(pool.stats().total_creates, 1);
        crate::test_complete!("reuse_idle_connection");
    }

    #[test]
    fn mr_idle_return_order_preserves_capacity_bounds() {
        init_test("mr_idle_return_order_preserves_capacity_bounds");
        const MAX_SIZE: usize = 3;
        let config = DbPoolConfig::with_max_size(MAX_SIZE).validate_on_checkout(false);
        let return_orders = [
            [0usize, 1usize, 2usize],
            [2usize, 1usize, 0usize],
            [1usize, 2usize, 0usize],
        ];
        let mut final_snapshots = Vec::new();

        for order in return_orders {
            let pool = DbPool::new(TestManager::new(), config.clone());
            let mut leases = (0..MAX_SIZE)
                .map(|_| Some(pool.get().expect("acquire within pool capacity")))
                .collect::<Vec<_>>();

            for (step, index) in order.into_iter().enumerate() {
                leases[index]
                    .take()
                    .expect("lease should still be checked out")
                    .return_to_pool();

                let stats = pool.stats();
                assert_eq!(stats.idle, step + 1);
                assert_eq!(stats.total, MAX_SIZE);
                assert_eq!(stats.active + stats.idle, stats.total);
                assert!(
                    stats.idle <= stats.max_size,
                    "idle connections must remain bounded by capacity"
                );
            }

            final_snapshots.push(db_pool_inventory_snapshot(&pool.stats()));
        }

        assert!(
            final_snapshots.windows(2).all(|pair| pair[0] == pair[1]),
            "return order should not change the final idle inventory snapshot"
        );
        crate::test_complete!("mr_idle_return_order_preserves_capacity_bounds");
    }

    // ================================================================
    // Capacity limits
    // ================================================================

    #[test]
    fn max_size_enforced() {
        init_test("max_size_enforced");
        let pool = DbPool::new(TestManager::new(), DbPoolConfig::with_max_size(2));

        let _c1 = pool.get().unwrap();
        let _c2 = pool.get().unwrap();

        let result = pool.get();
        assert!(matches!(result, Err(DbPoolError::Full)));
        crate::test_complete!("max_size_enforced");
    }

    #[test]
    fn capacity_frees_on_return() {
        init_test("capacity_frees_on_return");
        let pool = DbPool::new(TestManager::new(), DbPoolConfig::with_max_size(1));

        let conn = pool.get().unwrap();
        conn.return_to_pool();

        // Can get another one now.
        let _conn2 = pool.get().unwrap();
        crate::test_complete!("capacity_frees_on_return");
    }

    // ================================================================
    // Discard
    // ================================================================

    #[test]
    fn discard_removes_from_pool() {
        init_test("discard_removes_from_pool");
        let pool = DbPool::new(TestManager::new(), DbPoolConfig::with_max_size(2));

        let conn = pool.get().unwrap();
        conn.discard();

        // Total should decrease.
        assert_eq!(pool.stats().total, 0);
        assert_eq!(pool.stats().total_discards, 1);
        assert_eq!(pool.manager.disconnects(), 1);
        crate::test_complete!("discard_removes_from_pool");
    }

    /// br-asupersync-5bv5sr: PooledConnection::Drop must consult
    /// `ConnectionManager::release_check` and route the connection to
    /// `disconnect()` (NOT the idle pool) when release_check returns
    /// false. This is the cross-user transaction-state-leak defense:
    /// a backend that detects an open transaction or poisoned protocol
    /// state at release time signals "discard" so the next acquire
    /// gets a fresh connection rather than inheriting the prior
    /// caller's half-state.
    #[test]
    fn drop_routes_unhealthy_to_discard_via_release_check() {
        init_test("drop_routes_unhealthy_to_discard_via_release_check");

        struct UnhealthyOnReleaseManager {
            inner: TestManager,
            // Set to true to make every release_check return false.
            unhealthy: Arc<AtomicBool>,
        }

        impl ConnectionManager for UnhealthyOnReleaseManager {
            type Connection = TestConnection;
            type Error = TestError;

            fn connect(&self) -> Result<Self::Connection, Self::Error> {
                self.inner.connect()
            }

            fn is_valid(&self, conn: &Self::Connection) -> bool {
                self.inner.is_valid(conn)
            }

            fn release_check(&self, _conn: &mut Self::Connection) -> bool {
                // Inverted: false means "don't reuse — discard".
                !self.unhealthy.load(Ordering::SeqCst)
            }

            fn disconnect(&self, conn: Self::Connection) {
                self.inner.disconnect(conn);
            }
        }

        let unhealthy = Arc::new(AtomicBool::new(false));
        let manager = UnhealthyOnReleaseManager {
            inner: TestManager::new(),
            unhealthy: unhealthy.clone(),
        };
        let pool = DbPool::new(manager, DbPoolConfig::with_max_size(2));

        // Healthy path: release_check returns true, conn returns to pool.
        {
            let _conn = pool.get().unwrap();
        }
        assert_eq!(
            pool.stats().idle,
            1,
            "healthy connection must return to idle pool"
        );
        assert_eq!(
            pool.stats().total_discards,
            0,
            "healthy drop must NOT discard"
        );

        // Mark all subsequent releases as unhealthy. Acquire the idle
        // connection and drop it — it should be discarded, not returned.
        unhealthy.store(true, Ordering::SeqCst);
        {
            let _conn = pool.get().unwrap();
        }
        assert_eq!(
            pool.stats().idle,
            0,
            "unhealthy drop must remove from idle pool"
        );
        assert_eq!(
            pool.stats().total_discards,
            1,
            "unhealthy drop must increment discards"
        );
        assert_eq!(
            pool.stats().total,
            0,
            "unhealthy drop must decrement total connection count"
        );

        crate::test_complete!("drop_routes_unhealthy_to_discard_via_release_check");
    }

    /// br-asupersync-db-pool-drop-unhealthy-double-decrement-b18gr5: dropping an
    /// unhealthy connection (release_check=false → safe_discard) must decrement
    /// the per-client quota EXACTLY ONCE. The buggy code decremented inline AND
    /// again inside safe_discard_connection, so a client holding 2 connections
    /// dropped to 0 after releasing one (over-count → premature entry removal /
    /// quota corruption).
    #[test]
    fn drop_unhealthy_decrements_client_quota_exactly_once() {
        init_test("drop_unhealthy_decrements_client_quota_exactly_once");

        struct UnhealthyOnReleaseManager {
            inner: TestManager,
            unhealthy: Arc<AtomicBool>,
        }

        impl ConnectionManager for UnhealthyOnReleaseManager {
            type Connection = TestConnection;
            type Error = TestError;

            fn connect(&self) -> Result<Self::Connection, Self::Error> {
                self.inner.connect()
            }

            fn is_valid(&self, conn: &Self::Connection) -> bool {
                self.inner.is_valid(conn)
            }

            fn release_check(&self, _conn: &mut Self::Connection) -> bool {
                !self.unhealthy.load(Ordering::SeqCst)
            }

            fn disconnect(&self, conn: Self::Connection) {
                self.inner.disconnect(conn);
            }
        }

        let unhealthy = Arc::new(AtomicBool::new(false));
        let manager = UnhealthyOnReleaseManager {
            inner: TestManager::new(),
            unhealthy: unhealthy.clone(),
        };
        // Default max_connections_per_client = 3, so one client may hold 2.
        let pool = DbPool::new(manager, DbPoolConfig::with_max_size(4));
        let client = "client-a";
        let client_count = || {
            pool.inner
                .lock()
                .client_connections
                .get(client)
                .copied()
                .unwrap_or(0)
        };

        // Hold TWO connections for the same client at once.
        let c1 = pool.get_for_client(client).expect("acquire 1");
        let c2 = pool.get_for_client(client).expect("acquire 2");
        assert_eq!(client_count(), 2, "client should hold 2 connections");

        // Unhealthy release routes the drop through safe_discard_connection
        // (disconnect succeeds). Releasing ONE must drop the quota 2 -> 1.
        unhealthy.store(true, Ordering::SeqCst);
        drop(c2);
        assert_eq!(
            client_count(),
            1,
            "unhealthy drop must decrement the client quota exactly once \
             (regression: the double-decrement bug dropped it to 0)"
        );

        // Releasing the survivor drops 1 -> 0 and removes the entry.
        drop(c1);
        assert_eq!(client_count(), 0, "last connection released");

        crate::test_complete!("drop_unhealthy_decrements_client_quota_exactly_once");
    }

    /// br-asupersync-5bv5sr: default release_check returns true, so
    /// existing ConnectionManager implementations that DO NOT override
    /// release_check observe the legacy return-to-pool behavior. This
    /// is the non-breaking-change guarantee.
    #[test]
    fn drop_default_release_check_preserves_legacy_return_to_pool() {
        init_test("drop_default_release_check_preserves_legacy_return_to_pool");
        // Plain TestManager — does NOT override release_check.
        let pool = DbPool::new(TestManager::new(), DbPoolConfig::with_max_size(2));
        {
            let _conn = pool.get().unwrap();
        }
        assert_eq!(
            pool.stats().idle,
            1,
            "default release_check=true must return-to-pool as before"
        );
        assert_eq!(pool.stats().total_discards, 0);
        crate::test_complete!("drop_default_release_check_preserves_legacy_return_to_pool");
    }

    // ================================================================
    // Health check / validation
    // ================================================================

    #[test]
    fn validation_on_checkout_rejects_invalid() {
        init_test("validation_on_checkout_rejects_invalid");
        let manager = TestManager::new();
        let pool = DbPool::new(manager, DbPoolConfig::default());

        // Get and return a connection.
        let conn = pool.get().unwrap();
        conn.return_to_pool();
        assert_eq!(pool.stats().idle, 1);

        // Invalidate all connections.
        pool.manager.set_valid(false);

        // Next get should discard the invalid one and create a new one.
        // But creation also creates an invalid conn — is_valid is checked on checkout,
        // new connections are not checked.
        pool.manager.set_valid(true); // New connections are valid again.
        pool.manager.set_valid(false); // But the idle one is still invalid.

        // Actually: set_valid affects all conns since they share the Arc<AtomicBool>.
        // Let's test differently: make the idle conn invalid, then make new ones valid.
        // Since they all share the same Arc, we need a different approach.
        // Instead: just verify the validation failure counter increases.
        pool.manager.set_valid(false);
        let _result = pool.get();
        // The idle one gets rejected (validation failure), then a new one is created.
        assert_eq!(pool.stats().total_validation_failures, 1);
        crate::test_complete!("validation_on_checkout_rejects_invalid");
    }

    #[test]
    fn no_validation_when_disabled() {
        init_test("no_validation_when_disabled");
        let manager = TestManager::new();
        let config = DbPoolConfig::default().validate_on_checkout(false);
        let pool = DbPool::new(manager, config);

        let conn = pool.get().unwrap();
        conn.return_to_pool();

        pool.manager.set_valid(false);

        // Should still succeed (no validation).
        let conn2 = pool.get().unwrap();
        assert_eq!(pool.stats().total_validation_failures, 0);
        drop(conn2);
        crate::test_complete!("no_validation_when_disabled");
    }

    // ================================================================
    // Connection failure
    // ================================================================

    #[test]
    fn connect_failure_returns_error() {
        init_test("connect_failure_returns_error");
        let manager = TestManager::new();
        manager.set_fail_connect(true);
        let pool = DbPool::new(manager, DbPoolConfig::default());

        let result = pool.get();
        assert!(matches!(result, Err(DbPoolError::Connect(_))));
        assert_eq!(pool.stats().total, 0);
        crate::test_complete!("connect_failure_returns_error");
    }

    #[test]
    fn connect_failure_doesnt_leak_capacity() {
        init_test("connect_failure_doesnt_leak_capacity");
        let manager = TestManager::new();
        let pool = DbPool::new(manager, DbPoolConfig::with_max_size(2));

        pool.manager.set_fail_connect(true);
        let _ = pool.get(); // Fails
        let _ = pool.get(); // Fails

        pool.manager.set_fail_connect(false);
        // Should still be able to get — capacity wasn't leaked.
        let _c1 = pool.get().unwrap();
        let _c2 = pool.get().unwrap();
        crate::test_complete!("connect_failure_doesnt_leak_capacity");
    }

    // ================================================================
    // Close
    // ================================================================

    #[test]
    fn close_rejects_new_gets() {
        init_test("close_rejects_new_gets");
        let pool = DbPool::new(TestManager::new(), DbPoolConfig::default());
        pool.close();
        assert!(pool.is_closed());

        let result = pool.get();
        assert!(matches!(result, Err(DbPoolError::Closed)));
        crate::test_complete!("close_rejects_new_gets");
    }

    #[test]
    fn close_drains_idle() {
        init_test("close_drains_idle");
        let pool = DbPool::new(TestManager::new(), DbPoolConfig::default());

        let conn = pool.get().unwrap();
        conn.return_to_pool();
        assert_eq!(pool.stats().idle, 1);

        pool.close();
        assert_eq!(pool.stats().idle, 0);
        assert_eq!(pool.manager.disconnects(), 1);
        assert_eq!(pool.stats().total_discards, 1);
        crate::test_complete!("close_drains_idle");
    }

    #[test]
    fn mr_drop_matches_close_for_idle_cleanup() {
        init_test("mr_drop_matches_close_for_idle_cleanup");
        let config = DbPoolConfig::with_max_size(2).validate_on_checkout(false);

        let close_manager = TestManager::new();
        let close_observer = close_manager.clone();
        let close_snapshot = {
            let pool = DbPool::new(close_manager, config.clone());
            let first = pool.get().expect("first checkout should succeed");
            let second = pool.get().expect("second checkout should succeed");
            first.return_to_pool();
            second.return_to_pool();
            assert_eq!(pool.stats().idle, 2, "two returned connections go idle");
            pool.close();
            db_pool_inventory_snapshot(&pool.stats())
        };

        let drop_manager = TestManager::new();
        let drop_observer = drop_manager.clone();
        {
            let pool = DbPool::new(drop_manager, config.clone());
            let first = pool.get().expect("first checkout should succeed");
            let second = pool.get().expect("second checkout should succeed");
            first.return_to_pool();
            second.return_to_pool();
            assert_eq!(pool.stats().idle, 2, "two returned connections go idle");
        }

        assert_eq!(
            close_snapshot,
            json!({
                "idle": 0,
                "active": 0,
                "total": 0,
                "max_size": 2,
            }),
            "close must synchronously drain idle inventory"
        );
        assert_eq!(close_observer.disconnects(), 2);
        assert_eq!(
            drop_observer.disconnects(),
            close_observer.disconnects(),
            "dropping a pool with only idle connections should match explicit close cleanup"
        );
        crate::test_complete!("mr_drop_matches_close_for_idle_cleanup");
    }

    #[test]
    fn close_discards_returned_connections() {
        init_test("close_discards_returned_connections");
        let pool = DbPool::new(TestManager::new(), DbPoolConfig::default());

        let conn = pool.get().unwrap();
        pool.close();

        // Return after close → disconnected.
        conn.return_to_pool();
        assert_eq!(pool.stats().total, 0);
        assert_eq!(pool.manager.disconnects(), 1);
        assert_eq!(pool.stats().total_discards, 1);
        crate::test_complete!("close_discards_returned_connections");
    }

    // ================================================================
    // try_get
    // ================================================================

    #[test]
    fn try_get_success() {
        init_test("try_get_success");
        let pool = DbPool::new(TestManager::new(), DbPoolConfig::default());
        let conn = pool.try_get();
        assert!(conn.is_some());
        crate::test_complete!("try_get_success");
    }

    #[test]
    fn try_get_when_full() {
        init_test("try_get_when_full");
        let pool = DbPool::new(TestManager::new(), DbPoolConfig::with_max_size(1));
        let _held = pool.get().unwrap();
        assert!(pool.try_get().is_none());
        crate::test_complete!("try_get_when_full");
    }

    // ================================================================
    // Warm-up
    // ================================================================

    #[test]
    fn warm_up_creates_connections() {
        init_test("warm_up_creates_connections");
        let pool = DbPool::new(TestManager::new(), DbPoolConfig::default().min_idle(3));
        let created = pool.warm_up();
        assert_eq!(created, 3);
        assert_eq!(pool.stats().idle, 3);
        assert_eq!(pool.stats().total, 3);
        crate::test_complete!("warm_up_creates_connections");
    }

    #[test]
    fn warm_up_respects_max_size() {
        init_test("warm_up_respects_max_size");
        let pool = DbPool::new(
            TestManager::new(),
            DbPoolConfig::with_max_size(2).min_idle(5),
        );
        let created = pool.warm_up();
        assert_eq!(created, 2);
        assert_eq!(pool.stats().total, 2);
        crate::test_complete!("warm_up_respects_max_size");
    }

    // ================================================================
    // PooledConnection
    // ================================================================

    #[test]
    fn pooled_connection_deref() {
        init_test("pooled_connection_deref");
        let pool = DbPool::new(TestManager::new(), DbPoolConfig::default());
        let conn = pool.get().unwrap();
        // Deref to TestConnection.
        assert_eq!(conn.id, 1);
        crate::test_complete!("pooled_connection_deref");
    }

    #[test]
    fn pooled_connection_debug() {
        let pool = DbPool::new(TestManager::new(), DbPoolConfig::default());
        let conn = pool.get().unwrap();
        let dbg = format!("{conn:?}");
        assert!(dbg.contains("PooledConnection"));
        assert!(dbg.contains("active"));
    }

    // ================================================================
    // DbPoolError
    // ================================================================

    #[test]
    fn pool_error_display() {
        init_test("pool_error_display");
        let closed: DbPoolError<TestError> = DbPoolError::Closed;
        assert!(format!("{closed}").contains("closed"));

        let full: DbPoolError<TestError> = DbPoolError::Full;
        assert!(format!("{full}").contains("capacity"));

        let timeout: DbPoolError<TestError> = DbPoolError::Timeout;
        assert!(format!("{timeout}").contains("timed out"));

        let connect: DbPoolError<TestError> =
            DbPoolError::Connect(TestError("refused".to_string()));
        assert!(format!("{connect}").contains("refused"));

        let validation: DbPoolError<TestError> = DbPoolError::ValidationFailed;
        assert!(format!("{validation}").contains("validation"));
        crate::test_complete!("pool_error_display");
    }

    #[test]
    fn pool_error_debug() {
        let err: DbPoolError<TestError> = DbPoolError::Full;
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Full"));
    }

    #[test]
    fn pool_error_source() {
        use std::error::Error;
        let closed: DbPoolError<TestError> = DbPoolError::Closed;
        assert!(closed.source().is_none());

        let connect = DbPoolError::Connect(TestError("fail".to_string()));
        assert!(connect.source().is_some());
    }

    // ================================================================
    // Stats
    // ================================================================

    #[test]
    fn stats_track_lifecycle() {
        init_test("stats_track_lifecycle");
        let pool = DbPool::new(TestManager::new(), DbPoolConfig::with_max_size(2));

        let c1 = pool.get().unwrap();
        let c2 = pool.get().unwrap();
        assert_eq!(pool.stats().total_creates, 2);
        assert_eq!(pool.stats().total_acquisitions, 2);
        assert_eq!(pool.stats().active, 2);

        c1.return_to_pool();
        assert_eq!(pool.stats().idle, 1);
        assert_eq!(pool.stats().active, 1);

        c2.discard();
        assert_eq!(pool.stats().total_discards, 1);
        assert_eq!(pool.stats().total, 1);
        crate::test_complete!("stats_track_lifecycle");
    }

    #[test]
    fn stats_default() {
        let stats = DbPoolStats::default();
        assert_eq!(stats.idle, 0);
        assert_eq!(stats.active, 0);
        assert_eq!(stats.total, 0);
    }

    #[test]
    fn stats_debug_clone() {
        let stats = DbPoolStats::default();
        let dbg = format!("{stats:?}");
        assert!(dbg.contains("DbPoolStats"));
        let cloned = stats.clone();
        assert_eq!(stats.total, 0);
        assert_eq!(cloned.total, 0);
    }

    #[test]
    fn pool_debug_reports_live_counter_values() {
        init_test("pool_debug_reports_live_counter_values");
        let pool = DbPool::new(TestManager::new(), DbPoolConfig::default());
        let _conn = pool.get().unwrap();

        let dbg = format!("{pool:?}");
        assert!(dbg.contains("total_acquisitions: 1"));
        assert!(dbg.contains("total_creates: 1"));
        assert!(dbg.contains("total_discards: 0"));
        crate::test_complete!("pool_debug_reports_live_counter_values");
    }

    #[test]
    fn pool_telemetry_snapshot() {
        let pool = DbPool::new(TestManager::new(), DbPoolConfig::with_max_size(2));

        let initial = pool.stats();

        let conn = pool.get().expect("first checkout should succeed");
        let checked_out = pool.stats();

        conn.return_to_pool();
        let returned = pool.stats();

        let recycled = pool.get().expect("recycled checkout should succeed");
        recycled.discard();
        let discarded = pool.stats();

        // sort_maps keeps the snapshot stable whether or not some feature
        // combination unifies serde_json's preserve_order feature into the
        // test build (br-asupersync-uvqpga).
        insta::with_settings!({sort_maps => true}, {
            insta::assert_json_snapshot!(
                "pool_telemetry_snapshot",
                json!({
                    "initial": db_pool_stats_snapshot(&initial),
                    "checked_out": db_pool_stats_snapshot(&checked_out),
                    "returned": db_pool_stats_snapshot(&returned),
                    "discarded": db_pool_stats_snapshot(&discarded),
                })
            );
        });
    }

    /// br-asupersync-sqlite-pool-audit-r10-dj4uhx L2 (91hka0 item 12): a
    /// client with no recorded call had its last retry defaulted to `now`,
    /// so every first call slept the whole per-client minimum delay before
    /// even trying. A 5 s minimum delay makes the old sleep unmistakable.
    #[test]
    fn get_with_retry_for_client_first_attempt_is_immediate() {
        let pool = DbPool::new(
            TestManager::new(),
            DbPoolConfig::default().min_retry_delay_per_client_ms(5_000),
        );
        let policy = RetryPolicy::fixed_delay(Duration::from_millis(10), 3);
        for call in 0..2 {
            let started = crate::time::wall_now();
            let conn = pool
                .get_with_retry_for_client("c1", &policy)
                .expect("an idle pool hands out a connection");
            let waited = Duration::from_nanos(crate::time::wall_now().duration_since(started));
            assert!(
                waited < Duration::from_secs(2),
                "call {call} waited {waited:?} before its first attempt"
            );
            drop(conn);
        }
    }

    /// br-asupersync-sqlite-pool-audit-r10-dj4uhx L3: an async waiter whose
    /// turn handed it an idle connection that failed validation went back to
    /// the end of the queue, behind the callers that queued after it, and the
    /// slot the discard freed went to the next of them. It keeps its place
    /// now: in the same poll it opens a connection in the freed slot, and the
    /// second waiter is still queued. Both acquire paths are checked.
    #[test]
    fn async_waiter_handed_an_invalid_idle_connection_keeps_its_fifo_place() {
        use std::future::Future;
        use std::pin::Pin;
        use std::task::Poll;

        type Acquire<'a> = Pin<
            Box<
                dyn Future<
                        Output = Result<
                            AsyncPooledConnection<'a, AsyncTestManager>,
                            DbPoolError<TestError>,
                        >,
                    > + 'a,
            >,
        >;

        fn acquire<'a>(
            pool: &'a AsyncDbPool<AsyncTestManager>,
            cx: &'a Cx,
            client: Option<&'a str>,
        ) -> Acquire<'a> {
            match client {
                Some(client) => Box::pin(pool.get_for_client(cx, client)),
                None => Box::pin(pool.get(cx)),
            }
        }

        init_test("async_waiter_handed_an_invalid_idle_connection_keeps_its_fifo_place");
        for (first_client, second_client) in [(None, None), (Some("first"), Some("second"))] {
            let pool = AsyncDbPool::new(
                AsyncTestManager::new(),
                DbPoolConfig::with_max_size(1).validate_on_checkout(true),
            );
            let waker = std::task::Waker::noop();
            let mut ctx = std::task::Context::from_waker(waker);
            let holder_cx = Cx::for_testing();
            let first_cx = Cx::for_testing();
            let second_cx = Cx::for_testing();
            let holder = block_on(pool.get(&holder_cx)).expect("the holder takes the only slot");
            let mut first = acquire(&pool, &first_cx, first_client);
            let mut second = acquire(&pool, &second_cx, second_client);
            assert!(
                first.as_mut().poll(&mut ctx).is_pending(),
                "the first waiter queues"
            );
            assert!(
                second.as_mut().poll(&mut ctx).is_pending(),
                "the second waiter queues behind it"
            );
            assert_eq!(pool.stats().pending_waiters, 2);

            // The connection the holder returns fails the first waiter's
            // validation (new connections are not validated).
            pool.manager.valid.store(false, Ordering::SeqCst);
            holder.return_to_pool();
            let first_lease = match first.as_mut().poll(&mut ctx) {
                Poll::Ready(Ok(lease)) => lease,
                Poll::Ready(Err(err)) => panic!("{first_client:?}: the first waiter failed: {err}"),
                Poll::Pending => panic!(
                    "{first_client:?}: the first waiter, handed an invalid connection, lost its \
                     place to the second"
                ),
            };
            assert!(
                second.as_mut().poll(&mut ctx).is_pending(),
                "{second_client:?}: the second waiter still waits for its turn"
            );
            let stats = pool.stats();
            assert_eq!(stats.pending_waiters, 1, "only the second waiter is queued");
            assert_eq!(stats.total_validation_failures, 1);
            assert_eq!(stats.total_discards, 1);
            assert_eq!(
                stats.total_creates, 2,
                "the first waiter opened the freed slot"
            );

            pool.manager.valid.store(true, Ordering::SeqCst);
            first_lease.return_to_pool();
            match second.as_mut().poll(&mut ctx) {
                Poll::Ready(Ok(lease)) => lease.return_to_pool(),
                Poll::Ready(Err(err)) => {
                    panic!("{second_client:?}: the second waiter failed: {err}")
                }
                Poll::Pending => panic!(
                    "{second_client:?}: the second waiter gets the connection the first returned"
                ),
            }
            assert_eq!(pool.stats().pending_waiters, 0);
        }
    }

    /// br-asupersync-sqlite-pool-audit-r10-dj4uhx L3: an async acquire that
    /// waited again (here its turn came, but a shrink took the capacity back
    /// before it ran) restarted its `connection_timeout` budget, so it could
    /// wait far longer than the budget. One deadline covers the whole acquire
    /// now. The second wait starts 450 ms into a 600 ms budget, so with the
    /// restart the acquire could not fail before 1050 ms.
    #[test]
    fn async_acquire_that_waits_again_keeps_its_deadline() {
        use std::future::Future;

        init_test("async_acquire_that_waits_again_keeps_its_deadline");
        let pool = AsyncDbPool::new(
            AsyncTestManager::new(),
            DbPoolConfig::with_max_size(2)
                .validate_on_checkout(false)
                .connection_timeout(Duration::from_millis(600)),
        );
        let holder_cx = Cx::for_testing();
        let first_holder = block_on(pool.get(&holder_cx)).expect("the first slot");
        let second_holder = block_on(pool.get(&holder_cx)).expect("the second slot");

        let waker = std::task::Waker::noop();
        let mut ctx = std::task::Context::from_waker(waker);
        let waiter_cx = Cx::for_testing();
        let started = Instant::now();
        let mut waiter = std::pin::pin!(pool.get(&waiter_cx));
        assert!(
            waiter.as_mut().poll(&mut ctx).is_pending(),
            "the waiter queues on a full pool"
        );

        std::thread::sleep(Duration::from_millis(450));
        // The discard frees a slot and readies the waiter; the shrink takes
        // the capacity back before it runs, so it gives its turn back and
        // waits again.
        first_holder.discard();
        assert_eq!(pool.set_max_size(1), 1);

        let outcome = block_on(waiter.as_mut());
        let elapsed = started.elapsed();
        assert!(
            matches!(outcome, Err(DbPoolError::AcquireTimeout)),
            "the acquire runs out of its budget"
        );
        assert!(
            elapsed >= Duration::from_millis(550),
            "the acquire gave up after {elapsed:?}, before its 600 ms budget"
        );
        assert!(
            elapsed < Duration::from_millis(900),
            "the acquire waited {elapsed:?}: its second wait restarted the 600 ms budget"
        );
        assert_eq!(pool.stats().total_timeouts, 1);
        second_holder.return_to_pool();
    }
