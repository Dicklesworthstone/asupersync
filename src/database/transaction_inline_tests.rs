    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    #[cfg(feature = "sqlite")]
    use crate::conformance::{ConformanceTarget, LabRuntimeTarget, TestConfig};
    #[cfg(feature = "sqlite")]
    use crate::cx::Cx;
    #[cfg(feature = "sqlite")]
    use crate::database::sqlite::{SqliteConnection, SqliteError, SqliteValue};
    use crate::observability::{LogCollector, LogLevel};
    use std::task::{Context, Poll, Waker};

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct RetryProbeError(&'static str);

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn trace_database_transaction_records_structured_fields() {
        init_test("trace_database_transaction_records_structured_fields");
        let cx = Cx::for_testing();
        let collector = LogCollector::new(8).with_min_level(LogLevel::Trace);
        cx.set_log_collector(collector.clone());

        trace_database_transaction(&cx, "postgres", "commit", "ok");

        let entries = collector.peek();
        let entry = entries.first().expect("transaction trace entry");
        assert_eq!(entry.message(), "database.transaction.lifecycle");
        assert_eq!(entry.get_field("component"), Some("database"));
        assert_eq!(entry.get_field("resource"), Some("transaction"));
        assert_eq!(entry.get_field("backend"), Some("postgres"));
        assert_eq!(entry.get_field("operation"), Some("commit"));
        assert_eq!(entry.get_field("outcome"), Some("ok"));
        crate::test_complete!("trace_database_transaction_records_structured_fields");
    }

    #[test]
    fn retry_policy_none() {
        init_test("retry_policy_none");
        let policy = RetryPolicy::none();
        assert_eq!(policy.max_retries, 0);
        assert_eq!(policy.base_delay, Duration::ZERO);
        crate::test_complete!("retry_policy_none");
    }

    #[test]
    fn retry_policy_default() {
        init_test("retry_policy_default");
        let policy = RetryPolicy::default_retry();
        assert_eq!(policy.max_retries, 3);
        assert_eq!(policy.base_delay, Duration::from_millis(50));
        assert_eq!(policy.max_delay, Duration::from_secs(2));
        crate::test_complete!("retry_policy_default");
    }

    #[test]
    fn retry_policy_exponential_backoff() {
        init_test("retry_policy_exponential_backoff");
        let policy = RetryPolicy {
            max_retries: 5,
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(10),
        };

        // attempt 0: 100ms * 2^0 = 100ms
        assert_eq!(policy.delay_for(0), Duration::from_millis(100));
        // attempt 1: 100ms * 2^1 = 200ms
        assert_eq!(policy.delay_for(1), Duration::from_millis(200));
        // attempt 2: 100ms * 2^2 = 400ms
        assert_eq!(policy.delay_for(2), Duration::from_millis(400));
        // attempt 3: 100ms * 2^3 = 800ms
        assert_eq!(policy.delay_for(3), Duration::from_millis(800));
        crate::test_complete!("retry_policy_exponential_backoff");
    }

    #[test]
    fn retry_policy_capped_at_max() {
        init_test("retry_policy_capped_at_max");
        let policy = RetryPolicy {
            max_retries: 10,
            base_delay: Duration::from_millis(500),
            max_delay: Duration::from_secs(2),
        };

        // attempt 3: 500ms * 8 = 4000ms → capped to 2000ms
        assert_eq!(policy.delay_for(3), Duration::from_secs(2));
        // attempt 10: still capped
        assert_eq!(policy.delay_for(10), Duration::from_secs(2));
        crate::test_complete!("retry_policy_capped_at_max");
    }

    #[test]
    fn retry_policy_delay_is_monotonic_and_cap_stable() {
        init_test("retry_policy_delay_is_monotonic_and_cap_stable");
        let policy = RetryPolicy {
            max_retries: 12,
            base_delay: Duration::from_millis(125),
            max_delay: Duration::from_secs(2),
        };

        let mut previous = Duration::ZERO;
        let mut capped_attempts = 0usize;
        for attempt in 0..12 {
            let delay = policy.delay_for(attempt);
            assert!(
                delay >= previous,
                "retry delay decreased at attempt {attempt}: {delay:?} < {previous:?}"
            );
            assert!(
                delay <= policy.max_delay,
                "retry delay exceeded max at attempt {attempt}: {delay:?}"
            );
            if delay == policy.max_delay {
                capped_attempts += 1;
            }
            previous = delay;
        }

        assert_eq!(
            policy.delay_for(4),
            policy.max_delay,
            "125ms * 2^4 should reach the configured 2s cap"
        );
        assert!(
            capped_attempts >= 8,
            "once capped, all later attempts should remain at max_delay"
        );
        crate::test_complete!("retry_policy_delay_is_monotonic_and_cap_stable");
    }

    #[test]
    fn retry_policy_overflow_safe() {
        init_test("retry_policy_overflow_safe");
        let policy = RetryPolicy {
            max_retries: 100,
            base_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(60),
        };

        // Very large attempt numbers should not panic.
        let delay = policy.delay_for(63);
        assert!(delay <= Duration::from_secs(60));
        let delay = policy.delay_for(100);
        assert!(delay <= Duration::from_secs(60));
        crate::test_complete!("retry_policy_overflow_safe");
    }

    #[test]
    fn retry_policy_default_trait() {
        init_test("retry_policy_default_trait");
        let policy = RetryPolicy::default();
        // Default trait impl is `none()`
        assert_eq!(policy.max_retries, 0);
        crate::test_complete!("retry_policy_default_trait");
    }

    #[test]
    fn retry_policy_debug() {
        let policy = RetryPolicy::default_retry();
        let dbg = format!("{policy:?}");
        assert!(dbg.contains("RetryPolicy"));
        assert!(dbg.contains("max_retries"));
    }

    #[test]
    fn retry_policy_clone() {
        let policy = RetryPolicy::default_retry();
        let cloned = policy.clone();
        assert_eq!(cloned.max_retries, policy.max_retries);
        assert_eq!(cloned.base_delay, policy.base_delay);
        assert_eq!(cloned.max_delay, policy.max_delay);
    }

    #[test]
    fn wait_retry_delay_returns_cancelled_while_sleeping() {
        init_test("wait_retry_delay_returns_cancelled_while_sleeping");
        let cx = Cx::for_testing();
        let waker = noop_waker();
        let mut task_cx = Context::from_waker(&waker);
        let expected = CancelReason::user("stop");
        let mut fut = Box::pin(wait_retry_delay(&cx, Duration::from_secs(60)));

        assert!(matches!(fut.as_mut().poll(&mut task_cx), Poll::Pending));
        cx.set_cancel_reason(expected.clone());

        match fut.as_mut().poll(&mut task_cx) {
            Poll::Ready(Err(reason)) => assert_eq!(reason, expected),
            other => panic!("expected cancelled retry wait, got {other:?}"),
        }
        crate::test_complete!("wait_retry_delay_returns_cancelled_while_sleeping");
    }

    #[test]
    fn wait_retry_delay_zero_delay_returns_cancelled_after_yield() {
        init_test("wait_retry_delay_zero_delay_returns_cancelled_after_yield");
        let cx = Cx::for_testing();
        let waker = noop_waker();
        let mut task_cx = Context::from_waker(&waker);
        let expected = CancelReason::user("stop");
        let mut fut = Box::pin(wait_retry_delay(&cx, Duration::ZERO));

        assert!(matches!(fut.as_mut().poll(&mut task_cx), Poll::Pending));
        cx.set_cancel_reason(expected.clone());

        match fut.as_mut().poll(&mut task_cx) {
            Poll::Ready(Err(reason)) => assert_eq!(reason, expected),
            other => panic!("expected cancelled zero-delay retry wait, got {other:?}"),
        }
        crate::test_complete!("wait_retry_delay_zero_delay_returns_cancelled_after_yield");
    }

    #[test]
    fn retry_with_policy_stops_after_max_retries_on_persistent_error() {
        init_test("retry_with_policy_stops_after_max_retries_on_persistent_error");
        let cx = Cx::for_testing();
        let policy = RetryPolicy {
            max_retries: 3,
            base_delay: Duration::ZERO,
            max_delay: Duration::ZERO,
        };
        let mut attempts = 0u32;

        let outcome = futures_lite::future::block_on(retry_with_policy(
            &cx,
            &policy,
            || {
                attempts += 1;
                std::future::ready(Outcome::<(), RetryProbeError>::Err(RetryProbeError(
                    "retryable",
                )))
            },
            |_| true,
        ));

        match outcome {
            Outcome::Err(err) => assert_eq!(err, RetryProbeError("retryable")),
            other => panic!("expected persistent retryable error, got {other:?}"),
        }
        assert_eq!(
            attempts, 4,
            "max_retries=3 must stop after 4 total attempts"
        );
        crate::test_complete!("retry_with_policy_stops_after_max_retries_on_persistent_error");
    }

    #[test]
    fn retry_with_policy_replay_unsafe_still_retries_before_body_starts() {
        init_test("retry_with_policy_replay_unsafe_still_retries_before_body_starts");
        let cx = Cx::for_testing();
        let policy = RetryPolicy {
            max_retries: 3,
            base_delay: Duration::ZERO,
            max_delay: Duration::ZERO,
        };
        let replay_safety = TransactionReplaySafety::ReplayUnsafe;
        let body_started = std::cell::Cell::new(false);
        let mut attempts = 0u32;

        let outcome = futures_lite::future::block_on(retry_with_policy(
            &cx,
            &policy,
            || {
                body_started.set(false);
                attempts += 1;
                std::future::ready(Outcome::<(), RetryProbeError>::Err(RetryProbeError(
                    "retryable",
                )))
            },
            |_| replay_safety == TransactionReplaySafety::ReplaySafe || !body_started.get(),
        ));

        match outcome {
            Outcome::Err(err) => assert_eq!(err, RetryProbeError("retryable")),
            other => panic!("expected persistent retryable error, got {other:?}"),
        }
        assert_eq!(attempts, 4, "begin-time retryables should remain retryable");
        crate::test_complete!("retry_with_policy_replay_unsafe_still_retries_before_body_starts");
    }

    #[test]
    fn retry_with_policy_replay_unsafe_fails_closed_after_body_starts() {
        init_test("retry_with_policy_replay_unsafe_fails_closed_after_body_starts");
        let cx = Cx::for_testing();
        let policy = RetryPolicy {
            max_retries: 3,
            base_delay: Duration::ZERO,
            max_delay: Duration::ZERO,
        };
        let replay_safety = TransactionReplaySafety::ReplayUnsafe;
        let body_started = std::cell::Cell::new(false);
        let mut attempts = 0u32;

        let outcome = futures_lite::future::block_on(retry_with_policy(
            &cx,
            &policy,
            || {
                body_started.set(false);
                attempts += 1;
                body_started.set(true);
                std::future::ready(Outcome::<(), RetryProbeError>::Err(RetryProbeError(
                    "retryable",
                )))
            },
            |_| replay_safety == TransactionReplaySafety::ReplaySafe || !body_started.get(),
        ));

        match outcome {
            Outcome::Err(err) => assert_eq!(err, RetryProbeError("retryable")),
            other => panic!("expected persistent retryable error, got {other:?}"),
        }
        assert_eq!(attempts, 1, "replay-unsafe closures must not be rerun");
        crate::test_complete!("retry_with_policy_replay_unsafe_fails_closed_after_body_starts");
    }

    #[test]
    fn retry_with_policy_returns_non_retryable_error_immediately() {
        init_test("retry_with_policy_returns_non_retryable_error_immediately");
        let cx = Cx::for_testing();
        let policy = RetryPolicy {
            max_retries: 10,
            base_delay: Duration::ZERO,
            max_delay: Duration::ZERO,
        };
        let mut attempts = 0u32;

        let outcome = futures_lite::future::block_on(retry_with_policy(
            &cx,
            &policy,
            || {
                attempts += 1;
                std::future::ready(Outcome::<(), RetryProbeError>::Err(RetryProbeError(
                    "fatal",
                )))
            },
            |_| false,
        ));

        match outcome {
            Outcome::Err(err) => assert_eq!(err, RetryProbeError("fatal")),
            other => panic!("expected non-retryable error, got {other:?}"),
        }
        assert_eq!(attempts, 1, "non-retryable errors must not loop");
        crate::test_complete!("retry_with_policy_returns_non_retryable_error_immediately");
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn with_sqlite_transaction_commit_persists_under_lab_runtime() {
        init_test("with_sqlite_transaction_commit_persists_under_lab_runtime");
        let config = TestConfig::new()
            .with_seed(0x7A11_7E01)
            .with_tracing(true)
            .with_max_steps(20_000);
        let mut runtime = LabRuntimeTarget::create_runtime(config);

        let (count_inside_tx, count_after_commit, committed_name) =
            LabRuntimeTarget::block_on(&mut runtime, async move {
                let cx = Cx::current().expect("lab runtime should install a current Cx");

                let conn = match SqliteConnection::open_in_memory(&cx).await {
                    Outcome::Ok(conn) => conn,
                    other => panic!("open_in_memory failed: {other:?}"),
                };
                match conn
                    .execute_batch(
                        &cx,
                        "CREATE TABLE tx_items (id INTEGER PRIMARY KEY, name TEXT);",
                    )
                    .await
                {
                    Outcome::Ok(()) => {}
                    other => panic!("schema setup failed: {other:?}"),
                }

                let count_inside_tx = match with_sqlite_transaction(&conn, &cx, |tx, cx| {
                    Box::pin(async move {
                        match tx
                            .execute(
                                cx,
                                "INSERT INTO tx_items(name) VALUES (?1)",
                                &[SqliteValue::Text("helper_committed".to_string())],
                            )
                            .await
                        {
                            Outcome::Ok(1) => {}
                            other => panic!("insert in helper transaction failed: {other:?}"),
                        }

                        let rows_inside = match tx
                            .query(cx, "SELECT COUNT(*) AS count FROM tx_items", &[])
                            .await
                        {
                            Outcome::Ok(rows) => rows,
                            other => {
                                panic!("count query inside helper transaction failed: {other:?}")
                            }
                        };
                        let count_inside_tx = rows_inside[0]
                            .get_i64("count")
                            .expect("count column should be present");
                        tracing::info!(
                            event = %serde_json::json!({
                                "phase": "helper_inserted",
                                "count_inside_tx": count_inside_tx,
                            }),
                            "sqlite_transaction_lab_checkpoint"
                        );

                        Outcome::Ok(count_inside_tx)
                    })
                })
                .await
                {
                    Outcome::Ok(count) => count,
                    other => panic!("with_sqlite_transaction failed: {other:?}"),
                };

                let rows_after = match conn
                    .query(
                        &cx,
                        "SELECT COUNT(*) AS count, MIN(name) AS name FROM tx_items",
                        &[],
                    )
                    .await
                {
                    Outcome::Ok(rows) => rows,
                    other => panic!("query after helper commit failed: {other:?}"),
                };
                let count_after_commit = rows_after[0]
                    .get_i64("count")
                    .expect("count column should be present");
                let committed_name = rows_after[0]
                    .get_str("name")
                    .expect("name column should be present")
                    .to_string();
                tracing::info!(
                    event = %serde_json::json!({
                        "phase": "helper_committed",
                        "count_after_commit": count_after_commit,
                        "name": committed_name,
                    }),
                    "sqlite_transaction_lab_checkpoint"
                );
                conn.close().unwrap();

                (count_inside_tx, count_after_commit, committed_name)
            });

        assert_eq!(count_inside_tx, 1);
        assert_eq!(count_after_commit, 1);
        assert_eq!(committed_name, "helper_committed");
        let violations = runtime.oracles.check_all(runtime.now());
        assert!(
            violations.is_empty(),
            "transaction helper lab-runtime test should leave runtime invariants clean: {violations:?}"
        );
    }

    #[cfg(feature = "sqlite")]
    fn run_sqlite_commit_abort_isolation_permutation(abort_first: bool) -> Vec<String> {
        let config = TestConfig::new()
            .with_seed(0x7A11_7E02)
            .with_tracing(true)
            .with_max_steps(20_000);
        let mut runtime = LabRuntimeTarget::create_runtime(config);

        let rows = LabRuntimeTarget::block_on(&mut runtime, async move {
            let cx = Cx::current().expect("lab runtime should install a current Cx");

            let conn = match SqliteConnection::open_in_memory(&cx).await {
                Outcome::Ok(conn) => conn,
                other => panic!("open_in_memory failed: {other:?}"),
            };
            match conn
                .execute_batch(
                    &cx,
                    "CREATE TABLE tx_isolation_items (id INTEGER PRIMARY KEY, name TEXT);",
                )
                .await
            {
                Outcome::Ok(()) => {}
                other => panic!("schema setup failed: {other:?}"),
            }

            let run_commit = || {
                with_sqlite_transaction(&conn, &cx, |tx, cx| {
                    Box::pin(async move {
                        match tx
                            .execute(
                                cx,
                                "INSERT INTO tx_isolation_items(name) VALUES (?1)",
                                &[SqliteValue::Text("committed".to_string())],
                            )
                            .await
                        {
                            Outcome::Ok(1) => Outcome::Ok(()),
                            other => {
                                panic!("commit branch insert failed: {other:?}")
                            }
                        }
                    })
                })
            };

            let run_abort = || {
                with_sqlite_transaction(&conn, &cx, |tx, cx| {
                    Box::pin(async move {
                        match tx
                            .execute(
                                cx,
                                "INSERT INTO tx_isolation_items(name) VALUES (?1)",
                                &[SqliteValue::Text("rolled_back".to_string())],
                            )
                            .await
                        {
                            Outcome::Ok(1) => {}
                            other => panic!("abort branch insert failed: {other:?}"),
                        }
                        Outcome::<(), SqliteError>::Err(SqliteError::Sqlite(
                            "metamorphic rollback branch".to_string(),
                        ))
                    })
                })
            };

            if abort_first {
                match run_abort().await {
                    Outcome::Err(SqliteError::Sqlite(message))
                        if message == "metamorphic rollback branch" => {}
                    other => panic!("abort-first branch should roll back: {other:?}"),
                }
                match run_commit().await {
                    Outcome::Ok(()) => {}
                    other => panic!("commit-after-abort branch failed: {other:?}"),
                }
            } else {
                match run_commit().await {
                    Outcome::Ok(()) => {}
                    other => panic!("commit-first branch failed: {other:?}"),
                }
                match run_abort().await {
                    Outcome::Err(SqliteError::Sqlite(message))
                        if message == "metamorphic rollback branch" => {}
                    other => panic!("abort-after-commit branch should roll back: {other:?}"),
                }
            }

            let rows = match conn
                .query(&cx, "SELECT name FROM tx_isolation_items ORDER BY id", &[])
                .await
            {
                Outcome::Ok(rows) => rows,
                other => panic!("final query failed: {other:?}"),
            };

            let names = rows
                .iter()
                .map(|row| {
                    row.get_str("name")
                        .expect("name column should be present")
                        .to_string()
                })
                .collect::<Vec<_>>();
            conn.close().unwrap();
            names
        });

        let violations = runtime.oracles.check_all(runtime.now());
        assert!(
            violations.is_empty(),
            "sqlite transaction permutation should leave runtime invariants clean: {violations:?}"
        );

        rows
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn metamorphic_sqlite_commit_abort_isolation() {
        init_test("metamorphic_sqlite_commit_abort_isolation");

        let abort_then_commit = run_sqlite_commit_abort_isolation_permutation(true);
        let commit_then_abort = run_sqlite_commit_abort_isolation_permutation(false);

        assert_eq!(abort_then_commit, vec!["committed".to_string()]);
        assert_eq!(commit_then_abort, vec!["committed".to_string()]);
        assert_eq!(abort_then_commit, commit_then_abort);

        crate::test_complete!("metamorphic_sqlite_commit_abort_isolation");
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn with_sqlite_transaction_dropped_savepoint_refuses_commit() {
        init_test("with_sqlite_transaction_dropped_savepoint_refuses_commit");

        let mut runtime = LabRuntimeTarget::create_runtime(TestConfig::default());
        LabRuntimeTarget::block_on(&mut runtime, async move {
            let cx = Cx::current().expect("lab runtime should install a current Cx");
            let logs = LogCollector::new(128).with_min_level(LogLevel::Trace);
            cx.set_log_collector(logs.clone());
            let conn = match SqliteConnection::open_in_memory(&cx).await {
                Outcome::Ok(conn) => conn,
                other => panic!("open_in_memory failed: {other:?}"),
            };

            match conn
                .execute(
                    &cx,
                    "CREATE TABLE savepoint_guard_items (id INTEGER PRIMARY KEY, name TEXT)",
                    &[],
                )
                .await
            {
                Outcome::Ok(_) => {}
                other => panic!("schema setup failed: {other:?}"),
            }

            let tx_outcome = with_sqlite_transaction(&conn, &cx, |tx, cx| {
                Box::pin(async move {
                    match tx
                        .execute(
                            cx,
                            "INSERT INTO savepoint_guard_items(name) VALUES (?1)",
                            &[SqliteValue::Text("outer".to_string())],
                        )
                        .await
                    {
                        Outcome::Ok(_) => {}
                        other => panic!("outer insert failed: {other:?}"),
                    }

                    let savepoint = match SqliteSavepoint::new(tx, cx, "sp1").await {
                        Outcome::Ok(savepoint) => savepoint,
                        other => panic!("savepoint create failed: {other:?}"),
                    };

                    match savepoint
                        .transaction()
                        .execute(
                            cx,
                            "INSERT INTO savepoint_guard_items(name) VALUES (?1)",
                            &[SqliteValue::Text("inner".to_string())],
                        )
                        .await
                    {
                        Outcome::Ok(_) => {}
                        other => panic!("inner insert failed: {other:?}"),
                    }

                    drop(savepoint);
                    Outcome::Ok(())
                })
            })
            .await;

            match tx_outcome {
                Outcome::Err(SqliteError::Sqlite(msg)) => {
                    assert!(msg.contains("must roll back before commit"), "got: {msg}");
                }
                other => panic!("expected rollback-required error, got {other:?}"),
            }

            let rollback_completed = logs.peek().iter().any(|entry| {
                entry.message() == "database.transaction.lifecycle"
                    && entry.get_field("backend") == Some("sqlite")
                    && entry.get_field("operation") == Some("rollback")
                    && matches!(entry.get_field("outcome"), Some("ok" | "err"))
            });
            assert!(
                rollback_completed,
                "rollback-required helper exit must synchronously drive rollback to a terminal result before any follow-up operation"
            );

            let rows = match conn
                .query(
                    &cx,
                    "SELECT COUNT(*) AS count FROM savepoint_guard_items",
                    &[],
                )
                .await
            {
                Outcome::Ok(rows) => rows,
                other => panic!("count query after dropped savepoint failed: {other:?}"),
            };

            let count = rows[0].get_i64("count").expect("count column");
            assert_eq!(count, 0, "dropped savepoint must prevent commit");
        });

        crate::test_complete!("with_sqlite_transaction_dropped_savepoint_refuses_commit");
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn with_sqlite_transaction_savepoint_rollback_discards_inner_changes() {
        init_test("with_sqlite_transaction_savepoint_rollback_discards_inner_changes");

        let mut runtime = LabRuntimeTarget::create_runtime(TestConfig::default());
        LabRuntimeTarget::block_on(&mut runtime, async move {
            let cx = Cx::current().expect("lab runtime should install a current Cx");
            let conn = match SqliteConnection::open_in_memory(&cx).await {
                Outcome::Ok(conn) => conn,
                other => panic!("open_in_memory failed: {other:?}"),
            };

            match conn
                .execute(
                    &cx,
                    "CREATE TABLE savepoint_rollback_items (id INTEGER PRIMARY KEY, name TEXT)",
                    &[],
                )
                .await
            {
                Outcome::Ok(_) => {}
                other => panic!("schema setup failed: {other:?}"),
            }

            let tx_outcome = with_sqlite_transaction(&conn, &cx, |tx, cx| {
                Box::pin(async move {
                    match tx
                        .execute(
                            cx,
                            "INSERT INTO savepoint_rollback_items(name) VALUES (?1)",
                            &[SqliteValue::Text("outer_before".to_string())],
                        )
                        .await
                    {
                        Outcome::Ok(_) => {}
                        other => panic!("outer_before insert failed: {other:?}"),
                    }

                    let savepoint = match SqliteSavepoint::new(tx, cx, "sp1").await {
                        Outcome::Ok(savepoint) => savepoint,
                        other => panic!("savepoint create failed: {other:?}"),
                    };

                    match savepoint
                        .transaction()
                        .execute(
                            cx,
                            "INSERT INTO savepoint_rollback_items(name) VALUES (?1)",
                            &[SqliteValue::Text("inner".to_string())],
                        )
                        .await
                    {
                        Outcome::Ok(_) => {}
                        other => panic!("inner insert failed: {other:?}"),
                    }

                    match savepoint.rollback(cx).await {
                        Outcome::Ok(()) => {}
                        other => panic!("savepoint rollback failed: {other:?}"),
                    }

                    match tx
                        .execute(
                            cx,
                            "INSERT INTO savepoint_rollback_items(name) VALUES (?1)",
                            &[SqliteValue::Text("outer_after".to_string())],
                        )
                        .await
                    {
                        Outcome::Ok(_) => {}
                        other => panic!("outer_after insert failed: {other:?}"),
                    }

                    Outcome::Ok(())
                })
            })
            .await;

            match tx_outcome {
                Outcome::Ok(()) => {}
                other => panic!("expected outer transaction commit, got {other:?}"),
            }

            let rows = match conn
                .query(
                    &cx,
                    "SELECT name FROM savepoint_rollback_items ORDER BY id",
                    &[],
                )
                .await
            {
                Outcome::Ok(rows) => rows,
                other => panic!("query after rollback failed: {other:?}"),
            };

            let names = rows
                .iter()
                .map(|row| row.get_str("name").expect("name column").to_string())
                .collect::<Vec<_>>();
            assert_eq!(
                names,
                vec!["outer_before".to_string(), "outer_after".to_string()]
            );
        });

        crate::test_complete!("with_sqlite_transaction_savepoint_rollback_discards_inner_changes");
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn with_sqlite_transaction_savepoint_rollback_removes_marker() {
        init_test("with_sqlite_transaction_savepoint_rollback_removes_marker");

        let mut runtime = LabRuntimeTarget::create_runtime(TestConfig::default());
        LabRuntimeTarget::block_on(&mut runtime, async move {
            let cx = Cx::current().expect("lab runtime should install a current Cx");
            let conn = match SqliteConnection::open_in_memory(&cx).await {
                Outcome::Ok(conn) => conn,
                other => panic!("open_in_memory failed: {other:?}"),
            };

            match conn
                .execute(
                    &cx,
                    "CREATE TABLE savepoint_marker_items (id INTEGER PRIMARY KEY, name TEXT)",
                    &[],
                )
                .await
            {
                Outcome::Ok(_) => {}
                other => panic!("schema setup failed: {other:?}"),
            }

            let tx_outcome = with_sqlite_transaction(&conn, &cx, |tx, cx| {
                Box::pin(async move {
                    let savepoint = match SqliteSavepoint::new(tx, cx, "sp1").await {
                        Outcome::Ok(savepoint) => savepoint,
                        other => panic!("savepoint create failed: {other:?}"),
                    };

                    match savepoint
                        .transaction()
                        .execute(
                            cx,
                            "INSERT INTO savepoint_marker_items(name) VALUES (?1)",
                            &[SqliteValue::Text("inner".to_string())],
                        )
                        .await
                    {
                        Outcome::Ok(_) => {}
                        other => panic!("inner insert failed: {other:?}"),
                    }

                    match savepoint.rollback(cx).await {
                        Outcome::Ok(()) => {}
                        other => panic!("savepoint rollback failed: {other:?}"),
                    }

                    match tx.execute_unchecked(cx, "RELEASE SAVEPOINT sp1", &[]).await {
                        Outcome::Err(SqliteError::Sqlite(msg)) => {
                            assert!(
                                msg.contains("no such savepoint")
                                    || msg.contains("no such savepoint: sp1"),
                                "expected missing-savepoint error, got: {msg}"
                            );
                        }
                        other => {
                            panic!("helper rollback must remove savepoint marker, got {other:?}")
                        }
                    }

                    match tx
                        .execute(
                            cx,
                            "INSERT INTO savepoint_marker_items(name) VALUES (?1)",
                            &[SqliteValue::Text("outer".to_string())],
                        )
                        .await
                    {
                        Outcome::Ok(_) => {}
                        other => panic!("outer insert failed: {other:?}"),
                    }

                    Outcome::Ok(())
                })
            })
            .await;

            match tx_outcome {
                Outcome::Ok(()) => {}
                other => panic!("expected outer transaction commit, got {other:?}"),
            }

            let rows = match conn
                .query(
                    &cx,
                    "SELECT name FROM savepoint_marker_items ORDER BY id",
                    &[],
                )
                .await
            {
                Outcome::Ok(rows) => rows,
                other => panic!("query after rollback-marker check failed: {other:?}"),
            };

            let names = rows
                .iter()
                .map(|row| row.get_str("name").expect("name column").to_string())
                .collect::<Vec<_>>();
            assert_eq!(names, vec!["outer".to_string()]);
        });

        crate::test_complete!("with_sqlite_transaction_savepoint_rollback_removes_marker");
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn with_sqlite_transaction_raw_outer_release_cascades_inner_savepoint() {
        init_test("with_sqlite_transaction_raw_outer_release_cascades_inner_savepoint");

        let mut runtime = LabRuntimeTarget::create_runtime(TestConfig::default());
        LabRuntimeTarget::block_on(&mut runtime, async move {
            let cx = Cx::current().expect("lab runtime should install a current Cx");
            let conn = match SqliteConnection::open_in_memory(&cx).await {
                Outcome::Ok(conn) => conn,
                other => panic!("open_in_memory failed: {other:?}"),
            };

            match conn
                .execute(
                    &cx,
                    "CREATE TABLE savepoint_cascade_items (id INTEGER PRIMARY KEY, name TEXT)",
                    &[],
                )
                .await
            {
                Outcome::Ok(_) => {}
                other => panic!("schema setup failed: {other:?}"),
            }

            let tx_outcome = with_sqlite_transaction(&conn, &cx, |tx, cx| {
                Box::pin(async move {
                    match tx.execute_unchecked(cx, "SAVEPOINT outer_sp", &[]).await {
                        Outcome::Ok(_) => {}
                        other => panic!("outer savepoint create failed: {other:?}"),
                    }
                    match tx.execute_unchecked(cx, "SAVEPOINT inner_sp", &[]).await {
                        Outcome::Ok(_) => {}
                        other => panic!("inner savepoint create failed: {other:?}"),
                    }

                    match tx
                        .execute(
                            cx,
                            "INSERT INTO savepoint_cascade_items(name) VALUES (?1)",
                            &[SqliteValue::Text("nested".to_string())],
                        )
                        .await
                    {
                        Outcome::Ok(_) => {}
                        other => panic!("nested insert failed: {other:?}"),
                    }

                    match tx
                        .execute_unchecked(cx, "RELEASE SAVEPOINT outer_sp", &[])
                        .await
                    {
                        Outcome::Ok(_) => {}
                        other => panic!("outer release failed: {other:?}"),
                    }

                    match tx
                        .execute_unchecked(cx, "ROLLBACK TO SAVEPOINT inner_sp", &[])
                        .await
                    {
                        Outcome::Err(SqliteError::Sqlite(msg)) => {
                            assert!(
                                msg.contains("no such savepoint")
                                    || msg.contains("no such savepoint: inner_sp"),
                                "expected cascaded inner savepoint removal, got: {msg}"
                            );
                        }
                        other => panic!(
                            "releasing outer savepoint must cascade inner savepoint, got {other:?}"
                        ),
                    }

                    match tx
                        .execute(
                            cx,
                            "INSERT INTO savepoint_cascade_items(name) VALUES (?1)",
                            &[SqliteValue::Text("after".to_string())],
                        )
                        .await
                    {
                        Outcome::Ok(_) => {}
                        other => panic!("post-cascade insert failed: {other:?}"),
                    }

                    Outcome::Ok(())
                })
            })
            .await;

            match tx_outcome {
                Outcome::Ok(()) => {}
                other => panic!("expected outer transaction commit, got {other:?}"),
            }

            let rows = match conn
                .query(
                    &cx,
                    "SELECT name FROM savepoint_cascade_items ORDER BY id",
                    &[],
                )
                .await
            {
                Outcome::Ok(rows) => rows,
                other => panic!("query after cascade failed: {other:?}"),
            };

            let names = rows
                .iter()
                .map(|row| row.get_str("name").expect("name column").to_string())
                .collect::<Vec<_>>();
            assert_eq!(names, vec!["nested".to_string(), "after".to_string()]);
        });

        crate::test_complete!("with_sqlite_transaction_raw_outer_release_cascades_inner_savepoint");
    }

    /// AC2 (br-asupersync-server-stack-hardening-eeexl1.5): a 3-deep nest of
    /// typed `SqliteSavepoint`s with a partial `rollback_to` at the innermost.
    /// The innermost savepoint's work is discarded while the two outer
    /// savepoints (and the base row) survive to commit. Resolved LIFO
    /// (innermost first) so no Rust savepoint object outlives its server-side
    /// savepoint.
    #[cfg(feature = "sqlite")]
    #[test]
    fn with_sqlite_transaction_three_deep_savepoint_partial_rollback() {
        init_test("with_sqlite_transaction_three_deep_savepoint_partial_rollback");

        let mut runtime = LabRuntimeTarget::create_runtime(TestConfig::default());
        LabRuntimeTarget::block_on(&mut runtime, async move {
            let cx = Cx::current().expect("lab runtime should install a current Cx");
            let conn = match SqliteConnection::open_in_memory(&cx).await {
                Outcome::Ok(conn) => conn,
                other => panic!("open_in_memory failed: {other:?}"),
            };

            match conn
                .execute(
                    &cx,
                    "CREATE TABLE sp_nest_items (id INTEGER PRIMARY KEY, name TEXT)",
                    &[],
                )
                .await
            {
                Outcome::Ok(_) => {}
                other => panic!("schema setup failed: {other:?}"),
            }

            let tx_outcome = with_sqlite_transaction(&conn, &cx, |tx, cx| {
                Box::pin(async move {
                    async fn insert(
                        tx: &crate::database::sqlite::SqliteTransaction<'_>,
                        cx: &Cx,
                        name: &str,
                    ) -> Outcome<(), SqliteError> {
                        match tx
                            .execute(
                                cx,
                                "INSERT INTO sp_nest_items(name) VALUES (?1)",
                                &[SqliteValue::Text(name.to_string())],
                            )
                            .await
                        {
                            Outcome::Ok(_) => Outcome::Ok(()),
                            other => panic!("insert {name} failed: {other:?}"),
                        }
                    }

                    // Base row, outside any savepoint.
                    let _ = insert(tx, cx, "a").await;

                    let sp1 = match SqliteSavepoint::new(tx, cx, "sp1").await {
                        Outcome::Ok(sp) => sp,
                        other => panic!("sp1 create failed: {other:?}"),
                    };
                    let _ = insert(tx, cx, "b").await;

                    let sp2 = match SqliteSavepoint::new(tx, cx, "sp2").await {
                        Outcome::Ok(sp) => sp,
                        other => panic!("sp2 create failed: {other:?}"),
                    };
                    let _ = insert(tx, cx, "c").await;

                    let sp3 = match SqliteSavepoint::new(tx, cx, "sp3").await {
                        Outcome::Ok(sp) => sp,
                        other => panic!("sp3 create failed: {other:?}"),
                    };
                    let _ = insert(tx, cx, "d").await;

                    // Partial rollback at the innermost: "d" is discarded.
                    match sp3.rollback(cx).await {
                        Outcome::Ok(()) => {}
                        other => panic!("sp3 rollback failed: {other:?}"),
                    }
                    // Release the two outer savepoints: "b" and "c" survive.
                    match sp2.release(cx).await {
                        Outcome::Ok(()) => {}
                        other => panic!("sp2 release failed: {other:?}"),
                    }
                    match sp1.release(cx).await {
                        Outcome::Ok(()) => {}
                        other => panic!("sp1 release failed: {other:?}"),
                    }

                    Outcome::Ok(())
                })
            })
            .await;

            match tx_outcome {
                Outcome::Ok(()) => {}
                other => panic!("expected transaction commit, got {other:?}"),
            }

            let rows = match conn
                .query(&cx, "SELECT name FROM sp_nest_items ORDER BY id", &[])
                .await
            {
                Outcome::Ok(rows) => rows,
                other => panic!("query after nested savepoints failed: {other:?}"),
            };
            let names = rows
                .iter()
                .map(|row| row.get_str("name").expect("name column").to_string())
                .collect::<Vec<_>>();
            assert_eq!(
                names,
                vec!["a".to_string(), "b".to_string(), "c".to_string()],
                "3-deep partial rollback must keep the base + two outer savepoints and discard the innermost"
            );
        });

        crate::test_complete!("with_sqlite_transaction_three_deep_savepoint_partial_rollback");
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn with_sqlite_transaction_cancelled_savepoint_release_poison_commit() {
        init_test("with_sqlite_transaction_cancelled_savepoint_release_poison_commit");

        let mut runtime = LabRuntimeTarget::create_runtime(TestConfig::default());
        LabRuntimeTarget::block_on(&mut runtime, async move {
            let cx = Cx::current().expect("lab runtime should install a current Cx");
            let conn = match SqliteConnection::open_in_memory(&cx).await {
                Outcome::Ok(conn) => conn,
                other => panic!("open_in_memory failed: {other:?}"),
            };

            match conn
                    .execute(
                        &cx,
                        "CREATE TABLE savepoint_release_cancel_items (id INTEGER PRIMARY KEY, name TEXT)",
                        &[],
                    )
                    .await
                {
                    Outcome::Ok(_) => {}
                    other => panic!("schema setup failed: {other:?}"),
                }

            let tx_outcome = with_sqlite_transaction(&conn, &cx, |tx, cx| {
                Box::pin(async move {
                    match tx
                        .execute(
                            cx,
                            "INSERT INTO savepoint_release_cancel_items(name) VALUES (?1)",
                            &[SqliteValue::Text("outer".to_string())],
                        )
                        .await
                    {
                        Outcome::Ok(_) => {}
                        other => panic!("outer insert failed: {other:?}"),
                    }

                    let savepoint = match SqliteSavepoint::new(tx, cx, "sp1").await {
                        Outcome::Ok(savepoint) => savepoint,
                        other => panic!("savepoint create failed: {other:?}"),
                    };

                    let cancelled = Cx::for_testing();
                    let expected = CancelReason::user("cancel savepoint release");
                    cancelled.set_cancel_reason(expected.clone());
                    match savepoint.release(&cancelled).await {
                        Outcome::Cancelled(reason) => assert_eq!(reason, expected),
                        other => panic!("expected cancelled savepoint release, got {other:?}"),
                    }

                    Outcome::Ok(())
                })
            })
            .await;

            match tx_outcome {
                Outcome::Err(SqliteError::Sqlite(msg)) => {
                    assert!(msg.contains("must roll back before commit"), "got: {msg}");
                }
                other => panic!("expected rollback-required error, got {other:?}"),
            }

            let rows = match conn
                .query(
                    &cx,
                    "SELECT COUNT(*) AS count FROM savepoint_release_cancel_items",
                    &[],
                )
                .await
            {
                Outcome::Ok(rows) => rows,
                other => panic!("count query after cancelled release failed: {other:?}"),
            };

            let count = rows[0].get_i64("count").expect("count column");
            assert_eq!(count, 0, "cancelled savepoint release must prevent commit");
        });

        crate::test_complete!("with_sqlite_transaction_cancelled_savepoint_release_poison_commit");
    }
