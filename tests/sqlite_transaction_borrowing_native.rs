//! Native SQLite regressions for caller-borrowed transaction state.
//!
//! These exercise the real SQLite engine on one- and two-worker runtimes.
//! The first test holds an external writer lock until the borrowed write
//! actually returns Pending. Other cases cover physical rollback, retries,
//! and dropping a helper while its body owns an uncommitted write.
#![cfg(all(feature = "sqlite", not(target_arch = "wasm32")))]
#![recursion_limit = "256"]

use asupersync::Cx;
use asupersync::database::transaction::{
    RetryPolicy, ScopedTransactionFuture, SqliteSavepoint, TransactionReplaySafety,
    with_sqlite_transaction_immediate_with_state, with_sqlite_transaction_retry,
    with_sqlite_transaction_retry_with_state, with_sqlite_transaction_with_state,
};
use asupersync::database::{SqliteConnection, SqliteError, SqliteTransaction, SqliteValue};
use asupersync::runtime::{RootDrainOutcome, RuntimeBuilder};
use asupersync::types::{Budget, CancelReason, Outcome, PanicPayload};
use std::cell::Cell;
use std::future::{Future, pending, poll_fn};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

const WAIT_LIMIT: Duration = Duration::from_secs(10);
const INSERT: &str = "INSERT INTO t (id) VALUES (?1)";

struct CompletionSignal(mpsc::Sender<()>);

impl Drop for CompletionSignal {
    fn drop(&mut self) {
        // Unwinding or dropping the scenario must also release the host wait.
        let _ = self.0.send(());
    }
}

fn native<F, Fut>(workers: usize, scenario: F)
where
    F: FnOnce(Cx) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let runtime = RuntimeBuilder::multi_thread()
        .worker_threads(workers)
        .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
        .build()
        .unwrap();
    let cx = runtime.request_cx_with_budget(Budget::INFINITE);
    let (completed_tx, completed_rx) = mpsc::channel();
    let completion = CompletionSignal(completed_tx);
    let task = runtime.handle().spawn(async move {
        // Move the guard into the future so even drop-before-first-poll signals.
        let _completion = completion;
        assert!(
            Cx::current().is_some(),
            "scenario must run on a native worker"
        );
        scenario(cx).await;
    });

    // The host deadline does not depend on a worker, timer, or lost task wake.
    // Keep the original timeout result even if shutdown subsequently unblocks
    // the scenario: teardown is recovery, not successful test completion.
    let completed = completed_rx.recv_timeout(WAIT_LIMIT);
    let drain = runtime.shutdown_drained(WAIT_LIMIT);
    let stopped = runtime.shutdown_timeout(WAIT_LIMIT);
    assert!(
        completed.is_ok(),
        "native scenario did not finish within {WAIT_LIMIT:?}: {completed:?}; drain: {drain:?}"
    );
    assert_eq!(drain.outcome, RootDrainOutcome::Quiescent, "{drain:?}");
    assert_eq!(drain.live_tasks, 0, "{drain:?}");
    assert_eq!(drain.pending_obligations, 0, "{drain:?}");
    assert_eq!(drain.queued_finalizers, 0, "{drain:?}");
    assert!(stopped, "native workers must retire");

    // The guard signals just before the runtime publishes the join outcome.
    // Drain and teardown let that publication finish. Poll only once here so
    // no unbounded join can bypass the watchdog; stored body panics resume
    // after both cleanup phases have run.
    let mut task = std::pin::pin!(task);
    assert!(
        task.as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_ready(),
        "scenario join must be ready after native workers retire"
    );
}

async fn prepare(cx: &Cx, path: &std::path::Path) -> SqliteConnection {
    let connection = SqliteConnection::open(cx, path).await.unwrap();
    connection
        .execute_batch(cx, "CREATE TABLE t (id INTEGER PRIMARY KEY)")
        .await
        .unwrap();
    connection
}

async fn count(connection: &SqliteConnection, cx: &Cx) -> i64 {
    connection
        .query(cx, "SELECT COUNT(*) AS n FROM t", &[])
        .await
        .unwrap()[0]
        .get_i64("n")
        .unwrap()
}

async fn witnessed_yield(pending_count: &mut Cell<usize>) {
    let mut first_poll = true;
    poll_fn(move |task| {
        if std::mem::take(&mut first_poll) {
            pending_count.set(pending_count.get() + 1);
            task.waker().wake_by_ref();
            Poll::Pending
        } else {
            Poll::Ready(())
        }
    })
    .await;
}

// Intentionally neither Clone nor Sync. Its mutable references remain owned
// by the caller; the callback must only reborrow them for this invocation.
struct BorrowedWrite<'env> {
    sql: &'env str,
    parameters: &'env [SqliteValue],
    blocker: &'env mut rusqlite::Connection,
    pending_count: &'env mut Cell<usize>,
    completed: &'env mut usize,
}

async fn write_with_lock_witness<'env>(
    tx: &SqliteTransaction<'_>,
    cx: &Cx,
    state: &mut BorrowedWrite<'env>,
) -> Outcome<&'env str, SqliteError> {
    let sql = state.sql;
    let parameters = state.parameters;
    let blocker = &mut *state.blocker;
    let pending_count = &mut *state.pending_count;
    let mut write = std::pin::pin!(tx.execute(cx, sql, parameters));
    let mut first_poll = true;
    let result = poll_fn(move |task| {
        let result = write.as_mut().poll(task);
        if std::mem::take(&mut first_poll) {
            assert!(
                result.is_pending(),
                "the external writer lock must prevent write completion: {result:?}"
            );
            pending_count.set(pending_count.get() + 1);
            blocker.execute_batch("ROLLBACK").unwrap();
        }
        result
    })
    .await;
    match result {
        Outcome::Ok(affected) => {
            assert_eq!(affected, 1);
            *state.completed += 1;
            // This result borrows the caller's allocation, not the transaction.
            Outcome::Ok(sql)
        }
        Outcome::Err(error) => Outcome::Err(error),
        Outcome::Cancelled(reason) => Outcome::Cancelled(reason),
        Outcome::Panicked(payload) => Outcome::Panicked(payload),
    }
}

#[test]
fn sqlite_lends_nonstatic_sql_parameters_mutable_state_and_borrowed_result() {
    for workers in [1, 2] {
        native(workers, |cx| async move {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("borrowed.db");
            let connection = prepare(&cx, &path).await;
            connection.set_busy_timeout(&cx, WAIT_LIMIT).await.unwrap();
            let mut blocker = rusqlite::Connection::open(&path).unwrap();
            blocker.busy_timeout(Duration::ZERO).unwrap();
            blocker.execute_batch("BEGIN IMMEDIATE").unwrap();
            let sql = INSERT.to_owned();
            let parameters = vec![SqliteValue::Integer(7)];
            let mut pending_count = Cell::new(0);
            let mut completed = 0;
            let mut state = BorrowedWrite {
                sql: &sql,
                parameters: &parameters,
                blocker: &mut blocker,
                pending_count: &mut pending_count,
                completed: &mut completed,
            };
            let result = with_sqlite_transaction_with_state(
                &connection,
                &cx,
                &mut state,
                |tx, cx, state| {
                    ScopedTransactionFuture::new(write_with_lock_witness(tx, cx, state))
                },
            )
            .await
            .unwrap();
            assert_eq!(result, sql);
            assert!(std::ptr::eq(result.as_ptr(), sql.as_ptr()));
            assert_eq!(pending_count.get(), 1);
            assert_eq!(completed, 1);
            assert!(blocker.is_autocommit());
            assert_eq!(count(&connection, &cx).await, 1);

            // The state parameter also accepts unsized caller-owned data.
            let mut label = String::from("pending");
            with_sqlite_transaction_with_state(
                &connection,
                &cx,
                label.as_mut_str(),
                |tx, cx, label| {
                    ScopedTransactionFuture::new(async move {
                        tx.query(cx, "SELECT id FROM t", &[]).await.unwrap();
                        asupersync::runtime::yield_now().await;
                        label.make_ascii_uppercase();
                        Outcome::Ok(())
                    })
                },
            )
            .await
            .unwrap();
            assert_eq!(label, "PENDING");

            // The preserved boxed callback also promises a Send helper for
            // T: Send. A shared borrow of its outcome across backoff would
            // incorrectly require this Cell result to implement Sync.
            let result = with_sqlite_transaction_retry(
                &connection,
                &cx,
                &RetryPolicy::none(),
                TransactionReplaySafety::ReplayUnsafe,
                |tx, cx| {
                    Box::pin(async move {
                        let rows = tx.query(cx, "SELECT id FROM t", &[]).await.unwrap();
                        Outcome::Ok(Cell::new(rows.len()))
                    })
                },
            )
            .await
            .unwrap();
            assert_eq!(result.get(), 1);
            connection.close_async(&cx).await.unwrap();
        });
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Exit {
    Commit,
    Error,
    Cancelled,
    CancelBeforeCommit,
    Panicked,
    AbandonedSavepoint,
}

struct BodyState<'env> {
    sql: &'env str,
    parameters: &'env [SqliteValue],
    calls: &'env mut usize,
    pending_count: &'env mut Cell<usize>,
}

fn cancellation() -> CancelReason {
    CancelReason::user("sqlite borrowed transaction cancelled")
}

async fn body(
    tx: &SqliteTransaction<'_>,
    cx: &Cx,
    state: &mut BodyState<'_>,
    exit: Exit,
) -> Outcome<u64, SqliteError> {
    let affected = tx.execute(cx, state.sql, state.parameters).await.unwrap();
    witnessed_yield(state.pending_count).await;
    *state.calls += 1;
    match exit {
        Exit::Commit => Outcome::Ok(affected),
        Exit::Error => Outcome::Err(SqliteError::Sqlite("body rejected".into())),
        Exit::Cancelled => {
            cx.cancel_with_reason(cancellation());
            Outcome::Cancelled(cancellation())
        }
        Exit::CancelBeforeCommit => {
            cx.cancel_with_reason(cancellation());
            Outcome::Ok(affected)
        }
        Exit::Panicked => Outcome::Panicked(PanicPayload::new("body panic")),
        Exit::AbandonedSavepoint => {
            let savepoint = SqliteSavepoint::new(tx, cx, "abandoned").await.unwrap();
            drop(savepoint);
            Outcome::Ok(affected)
        }
    }
}

#[test]
fn sqlite_state_helpers_finish_rollback_before_returning_and_release_writer_locks() {
    for workers in [1, 2] {
        for immediate in [false, true] {
            for exit in [
                Exit::Commit,
                Exit::Error,
                Exit::Cancelled,
                Exit::CancelBeforeCommit,
                Exit::Panicked,
                Exit::AbandonedSavepoint,
            ] {
                native(workers, move |cx| async move {
                    let active = Cx::current().unwrap();
                    let directory = tempfile::tempdir().unwrap();
                    let path = directory.path().join("lifecycle.db");
                    let connection = prepare(&cx, &path).await;
                    let probe = rusqlite::Connection::open(&path).unwrap();
                    probe.busy_timeout(Duration::ZERO).unwrap();
                    let sql = INSERT.to_owned();
                    let parameters = vec![SqliteValue::Integer(7)];
                    let mut calls = 0;
                    let mut pending_count = Cell::new(0);
                    let mut state = BodyState {
                        sql: &sql,
                        parameters: &parameters,
                        calls: &mut calls,
                        pending_count: &mut pending_count,
                    };
                    let outcome = if immediate {
                        with_sqlite_transaction_immediate_with_state(
                            &connection,
                            &cx,
                            &mut state,
                            |tx, cx, state| ScopedTransactionFuture::new(body(tx, cx, state, exit)),
                        )
                        .await
                    } else {
                        with_sqlite_transaction_with_state(
                            &connection,
                            &cx,
                            &mut state,
                            |tx, cx, state| ScopedTransactionFuture::new(body(tx, cx, state, exit)),
                        )
                        .await
                    };
                    assert_eq!(calls, 1);
                    assert_eq!(pending_count.get(), 1);
                    match exit {
                        Exit::Commit => assert_eq!(outcome.unwrap(), 1),
                        Exit::Error => assert!(matches!(outcome,
                            Outcome::Err(SqliteError::Sqlite(message)) if message == "body rejected")),
                        Exit::Cancelled | Exit::CancelBeforeCommit => assert!(matches!(outcome,
                            Outcome::Cancelled(reason) if reason == cancellation())),
                        Exit::Panicked => assert!(matches!(outcome,
                            Outcome::Panicked(payload) if payload.message() == "body panic")),
                        Exit::AbandonedSavepoint => assert!(matches!(outcome,
                            Outcome::Err(SqliteError::Sqlite(message))
                            if message == "transaction must roll back before commit")),
                    }
                    // Probe before ANY operation on the original connection:
                    // lazy recovery on reuse must not conceal unfinished rollback.
                    probe.execute_batch("BEGIN IMMEDIATE").unwrap();
                    let rows: i64 = probe
                        .query_row("SELECT COUNT(*) FROM t", [], |r| r.get(0))
                        .unwrap();
                    let expected = i64::from(exit == Exit::Commit);
                    assert_eq!(rows, expected);
                    probe.execute_batch("ROLLBACK").unwrap();
                    assert_eq!(count(&connection, &active).await, expected);
                    assert!(!active.is_cancel_requested());
                    connection.close_async(&active).await.unwrap();
                });
            }
        }
    }
}

struct RetryState<'env> {
    sql: &'env str,
    parameters: &'env [SqliteValue],
    attempts: &'env mut usize,
    pending_count: &'env mut Cell<usize>,
    reader: &'env mut rusqlite::Connection,
    release_on_attempt: Option<usize>,
}

async fn retry_body(
    tx: &SqliteTransaction<'_>,
    cx: &Cx,
    state: &mut RetryState<'_>,
) -> Outcome<u64, SqliteError> {
    *state.attempts += 1;
    if state.release_on_attempt == Some(*state.attempts) {
        state.reader.execute_batch("ROLLBACK").unwrap();
    }
    let rows = tx
        .query(cx, "SELECT COUNT(*) AS n FROM t", &[])
        .await
        .unwrap();
    assert_eq!(
        rows[0].get_i64("n").unwrap(),
        0,
        "failed attempt must be rolled back before replay"
    );
    let affected = tx.execute(cx, state.sql, state.parameters).await.unwrap();
    witnessed_yield(state.pending_count).await;
    Outcome::Ok(affected)
}

#[test]
fn sqlite_retries_real_commit_busy_only_with_replay_permission_and_within_limit() {
    for workers in [1, 2] {
        for (replay, release_on_attempt, max_retries, expected_attempts, committed) in [
            (TransactionReplaySafety::ReplaySafe, Some(2), 2, 2, true),
            (TransactionReplaySafety::ReplayUnsafe, None, 2, 1, false),
            (TransactionReplaySafety::ReplaySafe, None, 2, 3, false),
        ] {
            native(workers, move |cx| async move {
                let directory = tempfile::tempdir().unwrap();
                let path = directory.path().join("retry.db");
                let connection = prepare(&cx, &path).await;
                connection
                    .execute_batch_unchecked(&cx, "PRAGMA journal_mode=DELETE")
                    .await
                    .unwrap();
                connection
                    .set_busy_timeout(&cx, Duration::ZERO)
                    .await
                    .unwrap();
                let mut reader = rusqlite::Connection::open(&path).unwrap();
                reader.busy_timeout(Duration::ZERO).unwrap();
                reader.execute_batch("BEGIN").unwrap();
                let initial: i64 = reader
                    .query_row("SELECT COUNT(*) FROM t", [], |r| r.get(0))
                    .unwrap();
                assert_eq!(initial, 0); // A real shared reader lock now prevents COMMIT.
                let sql = INSERT.to_owned();
                let parameters = vec![SqliteValue::Integer(7)];
                let mut attempts = 0;
                let mut pending_count = Cell::new(0);
                let mut state = RetryState {
                    sql: &sql,
                    parameters: &parameters,
                    attempts: &mut attempts,
                    pending_count: &mut pending_count,
                    reader: &mut reader,
                    release_on_attempt,
                };
                let policy = RetryPolicy {
                    max_retries,
                    base_delay: Duration::ZERO,
                    max_delay: Duration::ZERO,
                };
                let outcome = with_sqlite_transaction_retry_with_state(
                    &connection,
                    &cx,
                    &policy,
                    replay,
                    &mut state,
                    |tx, cx, state| ScopedTransactionFuture::new(retry_body(tx, cx, state)),
                )
                .await;
                assert_eq!(attempts, expected_attempts);
                assert_eq!(pending_count.get(), expected_attempts);
                if committed {
                    assert_eq!(outcome.unwrap(), 1);
                } else {
                    assert!(matches!(outcome, Outcome::Err(error) if error.is_busy()));
                }
                if !reader.is_autocommit() {
                    reader.execute_batch("ROLLBACK").unwrap();
                }
                // Failed COMMIT consumes the low-level handle. This public
                // operation also exercises its documented drop/recovery path.
                assert_eq!(count(&connection, &cx).await, i64::from(committed));
                reader.execute_batch("BEGIN IMMEDIATE; ROLLBACK").unwrap();
                connection.close_async(&cx).await.unwrap();
            });
        }
    }
}

#[test]
fn dropping_parked_sqlite_state_helper_releases_borrows_and_recovers_transaction() {
    for workers in [1, 2] {
        native(workers, |cx| async move {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("dropped.db");
            let connection = prepare(&cx, &path).await;
            let entered = AtomicBool::new(false);
            let sql = INSERT.to_owned();
            let parameters = vec![SqliteValue::Integer(7)];
            let mut calls = 0;
            let mut state = (sql.as_str(), parameters.as_slice(), &mut calls, &entered);
            let mut helper = Box::pin(with_sqlite_transaction_with_state(
                &connection,
                &cx,
                &mut state,
                |tx, cx, state| {
                    ScopedTransactionFuture::new(async move {
                        assert_eq!(tx.execute(cx, state.0, state.1).await.unwrap(), 1);
                        *state.2 += 1;
                        state.3.store(true, Ordering::Release);
                        pending::<Outcome<(), SqliteError>>().await
                    })
                },
            ));
            poll_fn(|task| {
                assert!(helper.as_mut().poll(task).is_pending());
                if entered.load(Ordering::Acquire) {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            })
            .await;
            // The body owns a completed write and has actually parked.
            drop(helper);
            assert_eq!(calls, 1);
            // Drop schedules best-effort rollback; reuse must finish recovery.
            assert_eq!(count(&connection, &cx).await, 0);
            assert_eq!(connection.execute(&cx, &sql, &parameters).await.unwrap(), 1);
            assert_eq!(count(&connection, &cx).await, 1);
            connection.close_async(&cx).await.unwrap();
        });
    }
}

#[test]
fn sqlite_refused_immediate_begin_leaves_caller_state_untouched() {
    for workers in [1, 2] {
        native(workers, |cx| async move {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("refused_begin.db");
            let connection = prepare(&cx, &path).await;
            connection
                .set_busy_timeout(&cx, Duration::ZERO)
                .await
                .unwrap();
            let blocker = rusqlite::Connection::open(&path).unwrap();
            blocker.busy_timeout(Duration::ZERO).unwrap();
            blocker.execute_batch("BEGIN IMMEDIATE").unwrap();
            let sql = INSERT.to_owned();
            let parameters = vec![SqliteValue::Integer(7)];
            let mut calls = 0;
            let mut state = (sql.as_str(), parameters.as_slice(), &mut calls);

            let refused = with_sqlite_transaction_immediate_with_state(
                &connection,
                &cx,
                &mut state,
                |tx, cx, state| {
                    ScopedTransactionFuture::new(async move {
                        *state.2 += 1;
                        tx.execute(cx, state.0, state.1).await
                    })
                },
            )
            .await;
            assert!(matches!(refused, Outcome::Err(error) if error.is_busy()));
            assert_eq!(*state.2, 0, "a refused BEGIN must not invoke the body");

            blocker.execute_batch("ROLLBACK").unwrap();
            let committed = with_sqlite_transaction_immediate_with_state(
                &connection,
                &cx,
                &mut state,
                |tx, cx, state| {
                    ScopedTransactionFuture::new(async move {
                        *state.2 += 1;
                        tx.execute(cx, state.0, state.1).await
                    })
                },
            )
            .await;
            assert_eq!(committed.unwrap(), 1);
            assert_eq!(calls, 1);
            assert_eq!(count(&connection, &cx).await, 1);
            connection.close_async(&cx).await.unwrap();
        });
    }
}
