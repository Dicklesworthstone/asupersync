//! Native SQLite operation handoff regressions for
//! asupersync-sqlite-pool-audit-r10-dj4uhx M2.
//!
//! Channel witnesses hold the real worker before its first SQLite instruction.
//! A finite query makes the old lost interrupt fail on its actual result rather
//! than relying on a watchdog to manufacture an interruption. Each scenario
//! retires its dedicated worker pool and the native runtime's root resources.
//!
//! asupersync-pj1q40: final async-close cleanup must also use the blocking
//! pool. Its regressions witness the real connection mutex and require the
//! closing future to yield before that mutex's owner can be released.

use super::*;
use crate::runtime::{RootDrainOutcome, RuntimeBuilder};
use std::future::Future;
use std::pin::Pin;
use std::sync::mpsc as std_mpsc;
use std::task::{Context, Waker};

const WAIT_LIMIT: Duration = Duration::from_secs(10);
const FINITE_QUERY: &str = "WITH RECURSIVE c(x) AS \
    (SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < 4000000) SELECT count(*) FROM c";
const PROBE_QUERY: &str = "WITH RECURSIVE c(x) AS \
    (SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < 4096) SELECT count(*) FROM c";

fn native<F, Fut>(scenario: F)
where
    F: FnOnce(Cx) -> Fut,
    Fut: Future<Output = ()>,
{
    let runtime = RuntimeBuilder::current_thread().build().unwrap();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        runtime.block_on(async {
            let cx = Cx::current().expect("native root context");
            scenario(cx).await;
        });
    }));
    let drain = runtime.shutdown_drained(WAIT_LIMIT);
    let stopped = runtime.shutdown_timeout(WAIT_LIMIT);
    assert_eq!(drain.outcome, RootDrainOutcome::Quiescent, "{drain:?}");
    assert_eq!(drain.live_tasks, 0, "{drain:?}");
    assert_eq!(drain.live_regions, 0, "{drain:?}");
    assert_eq!(drain.pending_spawns, 0, "{drain:?}");
    assert_eq!(drain.pending_obligations, 0, "{drain:?}");
    assert_eq!(drain.queued_finalizers, 0, "{drain:?}");
    assert!(!drain.has_pending_obligation_posts, "{drain:?}");
    assert!(stopped, "native runtime workers must retire");
    if let Err(payload) = result {
        std::panic::resume_unwind(payload);
    }
}

struct Fixture {
    connection: SqliteConnection,
    pool: BlockingPool,
}

impl Fixture {
    fn new() -> Self {
        let pool = BlockingPool::new(1, 1);
        let raw = rusqlite::Connection::open_in_memory().unwrap();
        configure_connection_defaults(&raw, false).unwrap();
        let interrupt = Arc::new(raw.get_interrupt_handle());
        Self {
            connection: SqliteConnection {
                inner: Arc::new(Mutex::new(SqliteConnectionInner::new(raw))),
                pool: pool.handle(),
                stream_pool: Some(pool.handle()),
                stream_pool_owner: None,
                transaction_state: Arc::new(Mutex::new(TransactionState::Autocommit)),
                transaction_generation: Arc::new(AtomicU64::new(0)),
                interrupt,
                statement_timeout_override: None,
            },
            pool,
        }
    }

    fn fence(&self) {
        let fence = self.pool.handle().spawn(|| {});
        let completed = fence.wait_timeout(WAIT_LIMIT);
        if !completed {
            // Cleanup only: an emergency interrupt must never make the failed
            // liveness assertion look successful.
            self.connection.interrupt();
            let _ = fence.wait_timeout(WAIT_LIMIT);
        }
        assert!(
            completed,
            "earlier SQLite work must retire before the worker fence"
        );
        assert_eq!(self.pool.pending_count(), 0);
        assert_eq!(self.pool.busy_threads(), 0);
    }

    fn assert_handler_retired(&self) {
        self.fence();
        let inner = self.connection.inner.lock();
        let raw = inner.get().expect("connection remains open");
        // Bypass run_connection_op deliberately: a new operation would install
        // its own handler and could conceal a leaked cancelled/expired callback.
        let count: i64 = raw
            .query_row(PROBE_QUERY, [], |row| row.get(0))
            .expect("a retired operation must leave no stale progress handler");
        assert_eq!(count, 4096);
    }

    async fn finish(&self, cx: &Cx) {
        match self.connection.query(cx, "SELECT 1 AS one", &[]).await {
            Outcome::Ok(rows) => assert_eq!(rows[0].get_i64("one").unwrap(), 1),
            other => panic!("public follow-up query must wake and succeed: {other:?}"),
        }
        match self.connection.close_async(cx).await {
            Outcome::Ok(()) => {}
            other => panic!("close must retire the real connection: {other:?}"),
        }
        self.fence();
        assert!(self.pool.shutdown_and_wait(WAIT_LIMIT));
        assert_eq!(self.pool.pending_count(), 0);
        assert_eq!(self.pool.busy_threads(), 0);
        assert_eq!(self.pool.active_threads(), 0);
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.connection.interrupt();
        let _ = self.pool.shutdown_and_wait(WAIT_LIMIT);
    }
}

struct Release(Option<std_mpsc::Sender<()>>);

impl Release {
    fn open(mut self) {
        self.0
            .take()
            .unwrap()
            .send(())
            .expect("worker awaits release");
    }
}

impl Drop for Release {
    fn drop(&mut self) {
        if let Some(sender) = self.0.take() {
            let _ = sender.send(());
        }
    }
}

struct WorkerGate {
    entered: std_mpsc::Sender<()>,
    release: std_mpsc::Receiver<()>,
}

impl WorkerGate {
    fn wait(self) -> Result<(), SqliteError> {
        self.entered
            .send(())
            .map_err(|error| SqliteError::Sqlite(format!("entry witness: {error}")))?;
        self.release
            .recv_timeout(WAIT_LIMIT)
            .map_err(|error| SqliteError::Sqlite(format!("release witness: {error}")))
    }
}

fn gate() -> (WorkerGate, std_mpsc::Receiver<()>, Release) {
    let (entered, observed) = std_mpsc::channel();
    let (release, received) = std_mpsc::channel();
    (
        WorkerGate {
            entered,
            release: received,
        },
        observed,
        Release(Some(release)),
    )
}

fn poll_pending<F: Future>(future: Pin<&mut F>) {
    let mut context = Context::from_waker(Waker::noop());
    assert!(
        future.poll(&mut context).is_pending(),
        "operation must be pending at its worker gate"
    );
}

/// A host deadline, independent of the executor under test, bounds the close
/// tail regressions. Teardown always precedes timeout or task-panic propagation.
fn native_close<F, Fut>(workers: usize, scenario: F)
where
    F: FnOnce(Cx) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    struct CompletionSignal(std_mpsc::Sender<()>);

    impl Drop for CompletionSignal {
        fn drop(&mut self) {
            let _ = self.0.send(());
        }
    }

    let runtime = RuntimeBuilder::multi_thread()
        .worker_threads(workers)
        .build()
        .expect("native close runtime");
    let request_cx = runtime.request_cx_with_budget(crate::types::Budget::INFINITE);
    let timeout_cx = request_cx.clone();
    let (completed_tx, completed_rx) = std_mpsc::channel();
    let completion = CompletionSignal(completed_tx);
    let task = runtime.handle().spawn(async move {
        let _completion = completion;
        assert!(Cx::current().is_some(), "close must run on a native worker");
        scenario(request_cx).await;
    });
    let completed = completed_rx.recv_timeout(WAIT_LIMIT);
    if completed.is_err() {
        timeout_cx.cancel_with_reason(CancelReason::user("SQLite close test deadline"));
    }
    drop(timeout_cx);
    let drain = runtime.shutdown_drained(WAIT_LIMIT);
    let stopped = runtime.shutdown_timeout(WAIT_LIMIT);
    let mut task = std::pin::pin!(task);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        task.as_mut().poll(&mut Context::from_waker(Waker::noop()))
    }));
    assert!(
        completed.is_ok(),
        "{workers} workers: close timed out: {completed:?}; drain: {drain:?}"
    );
    assert_eq!(drain.outcome, RootDrainOutcome::Quiescent, "{drain:?}");
    assert_eq!(drain.live_tasks, 0, "{drain:?}");
    assert_eq!(drain.live_regions, 0, "{drain:?}");
    assert_eq!(drain.pending_spawns, 0, "{drain:?}");
    assert_eq!(drain.pending_obligations, 0, "{drain:?}");
    assert_eq!(drain.queued_finalizers, 0, "{drain:?}");
    assert!(!drain.has_pending_obligation_posts, "{drain:?}");
    assert!(stopped, "native close workers must retire");
    match result {
        Ok(std::task::Poll::Ready(())) => {}
        Ok(std::task::Poll::Pending) => panic!("close task must be terminal after teardown"),
        Err(payload) => std::panic::resume_unwind(payload),
    }
}

/// Occupy the fixture's sole blocking worker, optionally while holding the
/// actual connection mutex. The release guard also opens during unwinding.
struct CloseGate {
    release: Release,
    handle: crate::runtime::blocking_pool::BlockingTaskHandle,
    result: std_mpsc::Receiver<Result<(), SqliteError>>,
}

impl CloseGate {
    fn new(fixture: &Fixture, hold_connection: bool) -> Self {
        let (worker_gate, entered, release) = gate();
        let inner = hold_connection.then(|| Arc::clone(&fixture.connection.inner));
        let (completed, result) = std_mpsc::channel();
        let handle = fixture.pool.handle().spawn(move || {
            let _connection = inner.as_ref().map(|inner| inner.lock());
            let outcome = worker_gate.wait();
            let _ = completed.send(outcome);
        });
        entered
            .recv_timeout(WAIT_LIMIT)
            .expect("blocking worker must own the close gate");
        Self {
            release,
            handle,
            result,
        }
    }

    fn open(self) {
        self.release.open();
        assert!(
            self.handle.wait_timeout(WAIT_LIMIT),
            "released blocking worker must finish"
        );
        self.result
            .recv_timeout(WAIT_LIMIT)
            .expect("blocking worker must publish its gate result")
            .expect("gate release must precede its independent deadline");
    }
}

/// A successful checkpoint has two independently gated jobs: RESTART and
/// verification. Leave the verification result ready without polling close
/// again, so the next poll reaches precisely the final cleanup boundary.
fn finish_close_checkpoints<F: Future>(fixture: &Fixture, mut closing: Pin<&mut F>) {
    for _ in 0..2 {
        let gate = CloseGate::new(fixture, false);
        poll_pending(closing.as_mut());
        assert_eq!(
            fixture.pool.pending_count(),
            1,
            "each checkpoint phase must be queued behind its worker gate"
        );
        gate.open();
        fixture.fence();
    }
}

async fn public_close(
    connection: &SqliteConnection,
    cx: &Cx,
    diagnosed: bool,
) -> Outcome<(), SqliteError> {
    if diagnosed {
        connection
            .close_async_diagnosed(cx)
            .await
            .map_err(|error| SqliteError::Sqlite(error.to_string()))
    } else {
        connection.close_async(cx).await
    }
}

#[derive(Clone, Copy, Debug)]
enum CloseDisposition {
    Complete,
    DropQueued,
    CancelQueued,
    CancelAfterCompletion,
    ConcurrentClose,
}

async fn run_close_case(cx: Cx, diagnosed: bool, disposition: CloseDisposition) {
    let active_cx = Cx::current().expect("native close worker context");
    let fixture = Fixture::new();
    let mut closing = Box::pin(public_close(&fixture.connection, &cx, diagnosed));
    finish_close_checkpoints(&fixture, closing.as_mut());

    // Both callers finish their checkpoints before either final close runs.
    // The second tail must tolerate the first caller removing the engine.
    let mut contender = if matches!(disposition, CloseDisposition::ConcurrentClose) {
        let mut contender = Box::pin(public_close(&fixture.connection, &cx, diagnosed));
        finish_close_checkpoints(&fixture, contender.as_mut());
        Some(contender)
    } else {
        None
    };

    let gate = CloseGate::new(&fixture, true);
    // This is an actual mutex ownership witness, not a manufactured yield.
    // A synchronous final-close tail blocks this poll until the gate deadline.
    poll_pending(closing.as_mut());
    assert_eq!(
        fixture.pool.pending_count(),
        1,
        "final close must be queued on the blocking pool"
    );
    if let Some(contender) = contender.as_mut() {
        poll_pending(contender.as_mut());
        assert_eq!(fixture.pool.pending_count(), 2);
    }

    match disposition {
        CloseDisposition::DropQueued => {
            drop(closing);
            gate.open();
            fixture.fence();
        }
        CloseDisposition::CancelQueued => {
            let reason = CancelReason::user("cancel queued final close");
            cx.cancel_with_reason(reason.clone());
            let first = closing
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()));
            gate.open();
            let outcome = match first {
                std::task::Poll::Ready(outcome) => {
                    drop(closing);
                    outcome
                }
                std::task::Poll::Pending => closing.await,
            };
            assert!(
                matches!(outcome, Outcome::Cancelled(observed) if observed == reason),
                "queued close must preserve the caller's cancellation reason"
            );
            fixture.fence();
        }
        CloseDisposition::Complete
        | CloseDisposition::CancelAfterCompletion
        | CloseDisposition::ConcurrentClose => {
            gate.open();
            if matches!(disposition, CloseDisposition::CancelAfterCompletion) {
                fixture.fence();
                assert!(!fixture.connection.is_open(), "worker already closed the engine");
                cx.cancel_with_reason(CancelReason::user("cancel after final close completed"));
            }
            let outcome = closing.await;
            assert!(
                matches!(outcome, Outcome::Ok(())),
                "{disposition:?}, diagnosed={diagnosed}: close must succeed: {outcome:?}"
            );
            if let Some(contender) = contender.take() {
                let outcome = contender.await;
                assert!(
                    matches!(outcome, Outcome::Ok(())),
                    "the competing final close must remain idempotent: {outcome:?}"
                );
            }
            fixture.fence();
        }
    }

    if matches!(
        disposition,
        CloseDisposition::DropQueued | CloseDisposition::CancelQueued
    ) {
        assert!(fixture.connection.is_open(), "queued abandonment cannot close later");
        fixture.assert_handler_retired();
        fixture.finish(&active_cx).await;
    } else {
        assert!(!fixture.connection.is_open(), "successful close removes the engine");
        assert!(matches!(
            fixture.connection.query(&active_cx, "SELECT 1 AS one", &[]).await,
            Outcome::Err(SqliteError::ConnectionClosed)
        ));
        fixture.fence();
        assert!(fixture.pool.shutdown_and_wait(WAIT_LIMIT));
        assert_eq!(fixture.pool.pending_count(), 0);
        assert_eq!(fixture.pool.busy_threads(), 0);
        assert_eq!(fixture.pool.active_threads(), 0);
    }
}

fn close_matrix(dispositions: &[CloseDisposition]) {
    for workers in [1, 2] {
        for diagnosed in [false, true] {
            for &disposition in dispositions {
                native_close(workers, move |cx| run_close_case(cx, diagnosed, disposition));
            }
        }
    }
}

#[test]
fn sqlite_async_close_final_cleanup_runs_on_the_blocking_pool() {
    close_matrix(&[CloseDisposition::Complete]);
}

#[test]
fn sqlite_async_close_queued_abandonment_preserves_connection_reuse() {
    close_matrix(&[CloseDisposition::DropQueued, CloseDisposition::CancelQueued]);
}

#[test]
fn sqlite_async_close_completed_result_wins_late_cancellation() {
    close_matrix(&[CloseDisposition::CancelAfterCompletion]);
}

#[test]
fn sqlite_async_close_concurrent_finalizers_are_idempotent() {
    close_matrix(&[CloseDisposition::ConcurrentClose]);
}

#[derive(Debug)]
struct StatementObservation {
    value: Option<i64>,
    interrupted: bool,
    error: Option<String>,
}

impl StatementObservation {
    fn new(result: &Result<i64, SqliteError>) -> Self {
        Self {
            value: result.as_ref().ok().copied(),
            interrupted: result.as_ref().is_err_and(sqlite_error_is_interrupt),
            error: result.as_ref().err().map(ToString::to_string),
        }
    }
}

fn receive_observation(
    fixture: &Fixture,
    receiver: &std_mpsc::Receiver<StatementObservation>,
) -> StatementObservation {
    match receiver.recv_timeout(WAIT_LIMIT) {
        Ok(observation) => observation,
        Err(error) => {
            fixture.connection.interrupt();
            let cleanup = receiver.recv_timeout(WAIT_LIMIT);
            panic!("statement did not finish in time: {error}; emergency cleanup={cleanup:?}");
        }
    }
}

#[test]
fn sqlite_dropped_before_first_vm_instruction_latches_cancellation_and_reuses_connection() {
    native(|cx| async move {
        for diagnosed in [false, true] {
            let fixture = Fixture::new();
            let (worker_gate, entered, release) = gate();
            let (completed, completion) = std_mpsc::channel();
            let operation = move |raw: &mut rusqlite::Connection| {
                worker_gate.wait()?;
                let result = raw
                    .query_row(FINITE_QUERY, [], |row| row.get::<_, i64>(0))
                    .map_err(|error| SqliteError::Sqlite(error.to_string()));
                let _ = completed.send(StatementObservation::new(&result));
                result
            };
            let mut pending = Box::pin(async {
                if diagnosed {
                    fixture
                        .connection
                        .run_connection_op_diagnosed(
                            &cx,
                            "diagnosed_pre_vm_drop",
                            SqliteOperation::Step,
                            move |raw| {
                                operation(raw).map_err(|error| {
                                    SqliteOperationError::from_legacy(SqliteOperation::Step, error)
                                })
                            },
                        )
                        .await
                        .map_err(|error| SqliteError::Sqlite(error.to_string()))
                } else {
                    fixture
                        .connection
                        .run_connection_op(&cx, "pre_vm_drop", operation)
                        .await
                }
            });
            poll_pending(pending.as_mut());
            entered
                .recv_timeout(WAIT_LIMIT)
                .expect("worker entered before the first SQLite step");
            drop(pending);
            release.open();

            let observed = receive_observation(&fixture, &completion);
            assert!(
                observed.interrupted,
                "diagnosed={diagnosed}: lost pre-VM drop: {observed:?}"
            );
            assert_eq!(
                observed.value, None,
                "abandoned query must not complete its finite count"
            );
            fixture.assert_handler_retired();
            fixture.finish(&cx).await;
        }
    });
}

#[test]
fn sqlite_dropped_running_transaction_keeps_its_finite_insert_and_open_transaction() {
    native(|cx| async move {
        let fixture = Fixture::new();
        match fixture
            .connection
            .execute_batch_unchecked(&cx, "CREATE TABLE t(v); BEGIN")
            .await
        {
            Outcome::Ok(()) => {}
            other => panic!("prepare existing transaction: {other:?}"),
        }
        let (worker_gate, entered, release) = gate();
        let (completed, completion) = std_mpsc::channel();
        let mut pending = Box::pin(fixture.connection.run_connection_op(
            &cx,
            "transaction_pre_vm_drop",
            move |raw| {
                worker_gate.wait()?;
                let result = raw
                    .execute(
                        "INSERT INTO t WITH RECURSIVE c(x) AS \
                     (SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < 20000) SELECT x FROM c",
                        [],
                    )
                    .map(|count| i64::try_from(count).unwrap())
                    .map_err(|error| SqliteError::Sqlite(error.to_string()));
                let _ = completed.send(StatementObservation::new(&result));
                result
            },
        ));
        poll_pending(pending.as_mut());
        entered
            .recv_timeout(WAIT_LIMIT)
            .expect("operation owns the already open transaction");
        drop(pending);
        release.open();
        let observed = receive_observation(&fixture, &completion);
        assert_eq!(observed.value, Some(20_000), "{observed:?}");
        assert!(
            !observed.interrupted,
            "running transaction must not be interrupted: {observed:?}"
        );
        assert!(observed.error.is_none(), "{observed:?}");
        fixture.assert_handler_retired();
        {
            let inner = fixture.connection.inner.lock();
            let raw = inner.get().unwrap();
            assert!(
                !raw.is_autocommit(),
                "the caller still owns its transaction"
            );
            let count: i64 = raw
                .query_row("SELECT count(*) FROM t", [], |row| row.get(0))
                .unwrap();
            assert_eq!(count, 20_000);
        }
        match fixture
            .connection
            .execute_unchecked(&cx, "ROLLBACK", &[])
            .await
        {
            Outcome::Ok(_) => {}
            other => panic!("explicit fixture rollback: {other:?}"),
        }
        fixture.finish(&cx).await;
    });
}

#[test]
fn sqlite_panicking_operation_retires_handler_and_cannot_interrupt_its_successor() {
    native(|cx| async move {
        for expired_deadline in [false, true] {
            let mut fixture = Fixture::new();
            if expired_deadline {
                fixture
                    .connection
                    .set_statement_timeout_override(Some(Duration::ZERO));
            }
            let (worker_gate, entered, release) = gate();
            let mut abandoned = Box::pin(fixture.connection.run_connection_op::<(), _>(
                &cx,
                "panic_before_sql",
                move |_| {
                    worker_gate.wait()?;
                    panic!("injected SQLite operation panic");
                },
            ));
            poll_pending(abandoned.as_mut());
            entered
                .recv_timeout(WAIT_LIMIT)
                .expect("panicking operation entered its worker");
            release.open();
            fixture.fence();
            // Keep the original awaiting future alive after its worker unwound.
            // Its later drop must observe Completed, not interrupt a successor.
            fixture.assert_handler_retired();

            let (running, observed_running) = std_mpsc::channel();
            let (release_vm, vm_gate) = std_mpsc::channel();
            let release_vm = Release(Some(release_vm));
            let (completed, completion) = std_mpsc::channel();
            let inner = Arc::clone(&fixture.connection.inner);
            let successor = fixture.pool.handle().spawn(move || {
                let mut guard = inner.lock();
                let raw = guard.get_mut().unwrap();
                let mut first = Some((running, vm_gate));
                // This is a direct raw successor after the tested operation
                // retired, not a replacement for its cancellation callback.
                raw.progress_handler(
                    1,
                    Some(move || {
                        if let Some((running, release)) = first.take() {
                            let _ = running.send(());
                            return release.recv_timeout(WAIT_LIMIT).is_err();
                        }
                        false
                    }),
                )
                .unwrap();
                let result = raw
                    .query_row(PROBE_QUERY, [], |row| row.get::<_, i64>(0))
                    .map_err(|error| SqliteError::Sqlite(error.to_string()));
                raw.progress_handler(0, None::<fn() -> bool>).unwrap();
                let _ = completed.send(StatementObservation::new(&result));
            });
            observed_running
                .recv_timeout(WAIT_LIMIT)
                .expect("successor is inside a real SQLite VM callback");
            drop(abandoned);
            release_vm.open();
            let observed = receive_observation(&fixture, &completion);
            assert_eq!(
                observed.value,
                Some(4096),
                "expired_deadline={expired_deadline}: {observed:?}"
            );
            assert!(
                !observed.interrupted,
                "late drop interrupted the next operation: {observed:?}"
            );
            assert!(successor.wait_timeout(WAIT_LIMIT));
            fixture.connection.set_statement_timeout_override(None);
            fixture.assert_handler_retired();
            fixture.finish(&cx).await;
        }
    });
}
