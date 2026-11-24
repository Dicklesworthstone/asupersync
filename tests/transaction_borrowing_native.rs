//! Lending transaction callbacks over actual PostgreSQL/MySQL wire exchanges.
//! The peers below script protocol replies; backend behavior remains covered by
//! the real-server targets. Every body query must return Pending before its
//! peer replies, and each case checks the complete transaction command order.
#![cfg(all(feature = "postgres", feature = "mysql", not(target_arch = "wasm32")))]
#![recursion_limit = "256"]

use asupersync::Cx;
use asupersync::database::mysql::{MySqlConnection, MySqlError, MySqlTransaction};
use asupersync::database::postgres::{PgConnection, PgError, PgTransaction};
use asupersync::database::transaction::{
    RetryPolicy, ScopedTransactionFuture, TransactionFuture, TransactionReplaySafety,
    with_mysql_transaction_borrowed, with_mysql_transaction_retry_borrowed,
    with_mysql_transaction_retry_with_state, with_mysql_transaction_with_state,
    with_pg_transaction_borrowed, with_pg_transaction_retry_borrowed,
    with_pg_transaction_retry_with_state, with_pg_transaction_with_state,
};
use asupersync::runtime::{JoinHandle, RootDrainOutcome, RootDrainReport, Runtime, RuntimeBuilder};
use asupersync::time::{TimerDriverHandle, VirtualClock};
use asupersync::types::{Budget, CancelReason, Outcome, PanicPayload, Time};
use std::future::{Future, poll_fn};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::task::{Context, Poll, Waker};
use std::thread;
use std::time::{Duration, Instant};

const SQL: &str = "UPDATE accounts SET balance = balance + 1";
const REUSE_SQL: &str = "UPDATE accounts SET balance = balance + 0";
const DEADLINE: Duration = Duration::from_secs(10);

struct CompletionSignal(mpsc::Sender<()>);

impl Drop for CompletionSignal {
    fn drop(&mut self) {
        // A panic or drop-before-first-poll must also release the host wait.
        let _ = self.0.send(());
    }
}

struct NativeTask {
    join: JoinHandle<()>,
    completed: mpsc::Receiver<()>,
}

fn spawn_native(
    runtime: &Runtime,
    future: impl Future<Output = ()> + Send + 'static,
) -> NativeTask {
    let (completed_tx, completed) = mpsc::channel();
    let completion = CompletionSignal(completed_tx);
    let join = runtime.handle().spawn(async move {
        let _completion = completion;
        future.await;
    });
    NativeTask { join, completed }
}

struct NativeResult {
    completed: Result<(), mpsc::RecvTimeoutError>,
    outcome: thread::Result<Poll<()>>,
    drain: RootDrainReport,
    stopped: bool,
}

fn finish_native(runtime: Runtime, task: NativeTask, on_timeout: impl FnOnce()) -> NativeResult {
    // This deadline is independent of reactor wakes and the virtual clock.
    let completed = task.completed.recv_timeout(DEADLINE);
    if completed.is_err() {
        on_timeout();
    }
    // Keep the timeout result even if recovery or shutdown unblocks the task.
    // Both bounded cleanup phases run before any assertion or panic resumes.
    let drain = runtime.shutdown_drained(DEADLINE);
    let stopped = runtime.shutdown_timeout(DEADLINE);
    let mut join = std::pin::pin!(task.join);
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        join.as_mut().poll(&mut Context::from_waker(Waker::noop()))
    }));
    NativeResult {
        completed,
        outcome,
        drain,
        stopped,
    }
}

impl NativeResult {
    fn assert_success(self) {
        assert!(
            self.completed.is_ok(),
            "native scenario did not finish within {DEADLINE:?}: {:?}; drain: {:?}",
            self.completed,
            self.drain
        );
        assert_eq!(
            self.drain.outcome,
            RootDrainOutcome::Quiescent,
            "{:?}",
            self.drain
        );
        assert_eq!(self.drain.live_tasks, 0, "{:?}", self.drain);
        assert_eq!(self.drain.pending_spawns, 0, "{:?}", self.drain);
        assert_eq!(self.drain.pending_obligations, 0, "{:?}", self.drain);
        assert_eq!(self.drain.queued_finalizers, 0, "{:?}", self.drain);
        assert!(self.stopped, "native workers must retire");
        match self.outcome {
            Ok(Poll::Ready(())) => {}
            Ok(Poll::Pending) => panic!("scenario join must be ready after native workers retire"),
            Err(payload) => std::panic::resume_unwind(payload),
        }
    }
}

struct HostThread<T> {
    label: &'static str,
    completed: mpsc::Receiver<thread::Result<T>>,
}

struct HostResult<T> {
    label: &'static str,
    outcome: Result<thread::Result<T>, mpsc::RecvTimeoutError>,
}

fn spawn_host<T: Send + 'static>(
    label: &'static str,
    job: impl FnOnce() -> T + Send + 'static,
) -> HostThread<T> {
    let (completed_tx, completed) = mpsc::channel();
    // The result channel is the bounded completion handle. Protocol resources
    // are released when job returns or unwinds, before its result is sent.
    let _thread = thread::spawn(move || {
        let result = catch_unwind(AssertUnwindSafe(job));
        let _ = completed_tx.send(result);
    });
    HostThread { label, completed }
}

impl<T> HostThread<T> {
    fn wait(self) -> HostResult<T> {
        HostResult {
            label: self.label,
            outcome: self.completed.recv_timeout(DEADLINE),
        }
    }
}

impl<T> HostResult<T> {
    fn assert_success(self) -> T {
        match self.outcome {
            Ok(Ok(value)) => value,
            Ok(Err(payload)) => std::panic::resume_unwind(payload),
            Err(error) => panic!("{} did not finish within {DEADLINE:?}: {error}", self.label),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Case {
    Commit,
    BodyError,
    BodyCancelled,
    BodyPanicked,
    CancelBeforeCommit,
    ReplaySafe,
    ReplayUnsafe,
    BeginRetryUnsafe,
    CommitRetrySafe,
    CommitRetryUnsafe,
    ReplayExhausted,
}

const CASES: [Case; 11] = [
    Case::Commit,
    Case::BodyError,
    Case::BodyCancelled,
    Case::BodyPanicked,
    Case::CancelBeforeCommit,
    Case::ReplaySafe,
    Case::ReplayUnsafe,
    Case::BeginRetryUnsafe,
    Case::CommitRetrySafe,
    Case::CommitRetryUnsafe,
    Case::ReplayExhausted,
];

impl Case {
    fn retries(self) -> bool {
        matches!(
            self,
            Self::ReplaySafe
                | Self::ReplayUnsafe
                | Self::BeginRetryUnsafe
                | Self::CommitRetrySafe
                | Self::CommitRetryUnsafe
                | Self::ReplayExhausted
        )
    }

    fn replay_safety(self) -> TransactionReplaySafety {
        if matches!(
            self,
            Self::ReplaySafe | Self::CommitRetrySafe | Self::ReplayExhausted
        ) {
            TransactionReplaySafety::ReplaySafe
        } else {
            TransactionReplaySafety::ReplayUnsafe
        }
    }

    fn body_attempts(self) -> usize {
        if matches!(
            self,
            Self::ReplaySafe | Self::CommitRetrySafe | Self::ReplayExhausted
        ) {
            2
        } else {
            1
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Backend {
    Postgres,
    MySql,
}

fn script(backend: Backend, case: Case) -> Vec<(&'static str, bool)> {
    let (begin, commit, rollback) = match backend {
        Backend::Postgres => ("BEGIN", "COMMIT", "ROLLBACK"),
        Backend::MySql => (
            "START TRANSACTION",
            "COMMIT AND NO CHAIN NO RELEASE",
            "ROLLBACK AND NO CHAIN NO RELEASE",
        ),
    };
    let mut commands = match case {
        Case::BeginRetryUnsafe => vec![
            (begin, true),
            (begin, false),
            (SQL, false),
            (commit, false),
        ],
        Case::CommitRetrySafe | Case::CommitRetryUnsafe => {
            let mut commands = vec![(begin, false), (SQL, false), (commit, true)];
            // PostgreSQL reports ReadyForQuery(I) after a commit-time
            // serialization failure. MySQL's ERR has no status flags, so
            // its consumed transaction is conservatively rolled back by
            // the next connection operation before any further command.
            if matches!(backend, Backend::MySql) {
                commands.push((rollback, false));
            }
            if case == Case::CommitRetrySafe {
                commands.extend([(begin, false), (SQL, false), (commit, false)]);
            }
            commands
        }
        _ => {
            let body_fails = matches!(
                case,
                Case::ReplaySafe | Case::ReplayUnsafe | Case::ReplayExhausted
            );
            let mut commands = vec![(begin, false), (SQL, body_fails)];
            commands.push((
                if case == Case::Commit {
                    commit
                } else {
                    rollback
                },
                false,
            ));
            if case == Case::ReplaySafe {
                commands.extend([(begin, false), (SQL, false), (commit, false)]);
            } else if case == Case::ReplayExhausted {
                commands.extend([(begin, false), (SQL, true), (rollback, false)]);
            }
            commands
        }
    };
    if case != Case::CancelBeforeCommit {
        commands.push((REUSE_SQL, false));
    }
    commands
}

async fn witnessed<F: Future>(future: F, pending: &mpsc::Sender<()>) -> F::Output {
    let mut future = std::pin::pin!(future);
    let mut reported = false;
    poll_fn(|task| {
        let result = future.as_mut().poll(task);
        if result.is_pending() && !reported {
            pending.send(()).expect("body query Pending witness");
            reported = true;
        }
        result
    })
    .await
}

fn accept(listener: &TcpListener) -> TcpStream {
    let deadline = Instant::now() + DEADLINE;
    loop {
        match listener.accept() {
            Ok((socket, _)) => {
                socket.set_read_timeout(Some(DEADLINE)).unwrap();
                socket.set_write_timeout(Some(DEADLINE)).unwrap();
                return socket;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    Instant::now() < deadline,
                    "transaction client never connected"
                );
                thread::sleep(Duration::from_millis(1));
            }
            Err(error) => panic!("accept transaction client: {error}"),
        }
    }
}

fn pg_write(socket: &mut TcpStream, tag: u8, payload: &[u8]) {
    socket.write_all(&[tag]).unwrap();
    socket
        .write_all(&(u32::try_from(payload.len()).unwrap() + 4).to_be_bytes())
        .unwrap();
    socket.write_all(payload).unwrap();
    socket.flush().unwrap();
}

fn pg_read(socket: &mut TcpStream) -> (u8, Vec<u8>) {
    let mut header = [0; 5];
    socket.read_exact(&mut header).unwrap();
    let length = u32::from_be_bytes(header[1..].try_into().unwrap()) as usize;
    assert!((4..=4096).contains(&length));
    let mut payload = vec![0; length - 4];
    socket.read_exact(&mut payload).unwrap();
    (header[0], payload)
}

fn pg_authenticate(socket: &mut TcpStream) {
    let mut length = [0; 4];
    socket.read_exact(&mut length).unwrap();
    let length = u32::from_be_bytes(length) as usize;
    assert!((8..=4096).contains(&length));
    let mut startup = vec![0; length - 4];
    socket.read_exact(&mut startup).unwrap();
    assert_eq!(&startup[..4], &[0, 3, 0, 0]);
    pg_write(socket, b'R', &0_u32.to_be_bytes());
    pg_write(socket, b'K', &[0, 0, 0, 42, 0, 0, 0, 7]);
    pg_write(socket, b'Z', b"I");
}

fn mysql_write(socket: &mut TcpStream, sequence: u8, payload: &[u8]) {
    let length = u32::try_from(payload.len()).unwrap().to_le_bytes();
    socket
        .write_all(&[length[0], length[1], length[2], sequence])
        .unwrap();
    socket.write_all(payload).unwrap();
    socket.flush().unwrap();
}

fn mysql_read(socket: &mut TcpStream) -> (u8, Vec<u8>) {
    let mut header = [0; 4];
    socket.read_exact(&mut header).unwrap();
    let length =
        usize::from(header[0]) | (usize::from(header[1]) << 8) | (usize::from(header[2]) << 16);
    assert!(length <= 4096);
    let mut payload = vec![0; length];
    socket.read_exact(&mut payload).unwrap();
    (header[3], payload)
}

fn mysql_authenticate(socket: &mut TcpStream) {
    // Protocol 4.1, transactions, secure auth, database selection and plugin
    // auth. No TLS or multi-statement capability is needed by this fixture.
    let capabilities: u32 = 1 | (1 << 3) | (1 << 9) | (1 << 13) | (1 << 15) | (1 << 17) | (1 << 19);
    let mut greeting = vec![10];
    greeting.extend_from_slice(b"8.0.0-transaction-test\0");
    greeting.extend_from_slice(&42_u32.to_le_bytes());
    greeting.extend_from_slice(b"12345678\0");
    greeting.extend_from_slice(&(capabilities as u16).to_le_bytes());
    greeting.push(33);
    greeting.extend_from_slice(&2_u16.to_le_bytes());
    greeting.extend_from_slice(&((capabilities >> 16) as u16).to_le_bytes());
    greeting.push(21);
    greeting.extend_from_slice(&[0; 10]);
    greeting.extend_from_slice(b"abcdefghijkl\0caching_sha2_password\0");
    mysql_write(socket, 0, &greeting);
    let (sequence, response) = mysql_read(socket);
    assert_eq!(sequence, 1);
    assert!(response.len() > 32);
    mysql_write(socket, 2, &[0, 0, 0, 2, 0, 0, 0]);
}

#[derive(Default)]
struct RollbackGate {
    received: AtomicBool,
    released: AtomicBool,
    task_waker: Mutex<Option<Waker>>,
}

async fn witnessed_rollback<F: Future>(
    future: F,
    gate: &RollbackGate,
    parked: mpsc::Sender<()>,
) -> F::Output {
    let mut future = std::pin::pin!(future);
    let mut parked = Some(parked);
    poll_fn(|task| {
        *gate.task_waker.lock().unwrap() = Some(task.waker().clone());
        let result = future.as_mut().poll(task);
        if gate.received.load(Ordering::Acquire) && !gate.released.load(Ordering::Acquire) {
            assert!(
                result.is_pending(),
                "the helper returned before its ROLLBACK reply was released"
            );
            if let Some(parked) = parked.take() {
                parked.send(()).unwrap();
            }
        }
        result
    })
    .await
}

fn peer(backend: Backend, case: Case) -> (SocketAddr, mpsc::Sender<()>, HostThread<()>) {
    peer_with_gate(backend, case, None)
}

fn peer_with_gate(
    backend: Backend,
    case: Case,
    mut rollback_gate: Option<(Arc<RollbackGate>, mpsc::Receiver<()>)>,
) -> (SocketAddr, mpsc::Sender<()>, HostThread<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let (pending, observed) = mpsc::channel();
    let server = spawn_host("transaction peer", move || {
        let mut socket = accept(&listener);
        match backend {
            Backend::Postgres => pg_authenticate(&mut socket),
            Backend::MySql => mysql_authenticate(&mut socket),
        }
        let mut in_transaction = false;
        for (sql, fail) in script(backend, case) {
            match backend {
                Backend::Postgres => {
                    assert_eq!(
                        pg_read(&mut socket),
                        (b'Q', format!("{sql}\0").into_bytes())
                    );
                }
                Backend::MySql => {
                    assert_eq!(
                        mysql_read(&mut socket),
                        (0, [b"\x03", sql.as_bytes()].concat())
                    );
                }
            }
            if sql == SQL {
                observed
                    .recv_timeout(DEADLINE)
                    .expect("query must park before reply");
            }
            if matches!(sql, "ROLLBACK" | "ROLLBACK AND NO CHAIN NO RELEASE")
                && let Some((gate, parked)) = rollback_gate.take()
            {
                // Wake the wrapper after the server has received ROLLBACK.
                // The server cannot acknowledge it until the wrapper proves
                // the public helper is Pending with that reply withheld.
                gate.received.store(true, Ordering::Release);
                if let Some(waker) = gate.task_waker.lock().unwrap().take() {
                    waker.wake();
                }
                parked
                    .recv_timeout(DEADLINE)
                    .expect("helper must await the withheld ROLLBACK reply");
                gate.released.store(true, Ordering::Release);
            }
            match sql {
                "BEGIN" | "START TRANSACTION" => in_transaction = true,
                "COMMIT"
                | "ROLLBACK"
                | "COMMIT AND NO CHAIN NO RELEASE"
                | "ROLLBACK AND NO CHAIN NO RELEASE" => in_transaction = false,
                _ => {}
            }
            match backend {
                Backend::Postgres => {
                    if fail {
                        pg_write(&mut socket, b'E', b"SERROR\0C40001\0Mretry transaction\0\0");
                        // A failed statement leaves a failed block; a
                        // rejected BEGIN or failed COMMIT leaves no block.
                        pg_write(&mut socket, b'Z', if sql == SQL { b"E" } else { b"I" });
                    } else {
                        let tag = if matches!(sql, SQL | REUSE_SQL) {
                            "UPDATE 1"
                        } else {
                            sql
                        };
                        pg_write(&mut socket, b'C', format!("{tag}\0").as_bytes());
                        pg_write(&mut socket, b'Z', if in_transaction { b"T" } else { b"I" });
                    }
                }
                Backend::MySql => {
                    if fail {
                        mysql_write(&mut socket, 1, b"\xff\xbd\x04#40001retry transaction");
                    } else {
                        let affected = u8::from(matches!(sql, SQL | REUSE_SQL));
                        let status = if in_transaction { 3 } else { 2 };
                        mysql_write(&mut socket, 1, &[0, affected, 0, status, 0, 0, 0]);
                    }
                }
            }
        }
        match backend {
            Backend::Postgres => assert_eq!(pg_read(&mut socket), (b'X', vec![])),
            Backend::MySql => assert_eq!(mysql_read(&mut socket), (0, vec![1])),
        }
        assert!(rollback_gate.is_none(), "script did not reach ROLLBACK");
        assert_eq!(socket.read(&mut [0]).unwrap(), 0, "connection must close");
    });
    (address, pending, server)
}

fn runtime(workers: usize) -> Runtime {
    RuntimeBuilder::multi_thread()
        .worker_threads(workers)
        .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
        .build()
        .unwrap()
}

fn retry_policy() -> RetryPolicy {
    RetryPolicy {
        max_retries: 1,
        base_delay: Duration::ZERO,
        max_delay: Duration::ZERO,
    }
}

struct BorrowedState<'a> {
    sql: &'a str,
    pending: &'a mpsc::Sender<()>,
    attempts: &'a mut usize,
}

async fn pg_body(
    tx: &mut PgTransaction<'_>,
    cx: &Cx,
    sql: &str,
    pending: &mpsc::Sender<()>,
    case: Case,
) -> Outcome<u64, PgError> {
    asupersync::runtime::yield_now().await;
    let affected = match witnessed(tx.execute_unchecked(cx, sql), pending).await {
        Outcome::Ok(affected) => affected,
        other => return other,
    };
    match case {
        Case::BodyError => Outcome::Err(PgError::Protocol("body rejected".into())),
        Case::BodyCancelled => Outcome::Cancelled(CancelReason::user("body cancelled")),
        Case::BodyPanicked => Outcome::Panicked(PanicPayload::new("body panicked")),
        Case::CancelBeforeCommit => {
            cx.set_cancel_reason(CancelReason::user("cancel before commit"));
            Outcome::Ok(affected + u64::try_from(sql.len()).unwrap())
        }
        _ => Outcome::Ok(affected + u64::try_from(sql.len()).unwrap()),
    }
}

async fn mysql_body(
    tx: &mut MySqlTransaction<'_>,
    cx: &Cx,
    sql: &str,
    pending: &mpsc::Sender<()>,
    case: Case,
) -> Outcome<u64, MySqlError> {
    asupersync::runtime::yield_now().await;
    let affected = match witnessed(tx.execute_static_sql(cx, sql), pending).await {
        Outcome::Ok(affected) => affected,
        other => return other,
    };
    match case {
        Case::BodyError => Outcome::Err(MySqlError::Protocol("body rejected".into())),
        Case::BodyCancelled => Outcome::Cancelled(CancelReason::user("body cancelled")),
        Case::BodyPanicked => Outcome::Panicked(PanicPayload::new("body panicked")),
        Case::CancelBeforeCommit => {
            cx.set_cancel_reason(CancelReason::user("cancel before commit"));
            Outcome::Ok(affected + u64::try_from(sql.len()).unwrap())
        }
        _ => Outcome::Ok(affected + u64::try_from(sql.len()).unwrap()),
    }
}

async fn pg_state_body(
    tx: &mut PgTransaction<'_>,
    cx: &Cx,
    state: &mut BorrowedState<'_>,
    case: Case,
) -> Outcome<u64, PgError> {
    let result = pg_body(tx, cx, state.sql, state.pending, case).await;
    // Mutate caller-owned state after the witnessed suspension. This borrow
    // must remain usable across await and across rollback/retry attempts.
    *state.attempts += 1;
    result
}

async fn mysql_state_body(
    tx: &mut MySqlTransaction<'_>,
    cx: &Cx,
    state: &mut BorrowedState<'_>,
    case: Case,
) -> Outcome<u64, MySqlError> {
    let result = mysql_body(tx, cx, state.sql, state.pending, case).await;
    *state.attempts += 1;
    result
}

#[test]
fn postgres_lending_callbacks_preserve_transaction_lifecycle() {
    for workers in [1, 2] {
        for case in CASES {
            let (address, pending, server) = peer(Backend::Postgres, case);
            let runtime = runtime(workers);
            let cx = runtime.request_cx_with_budget(Budget::INFINITE);
            let task = spawn_native(&runtime, async move {
                assert!(Cx::current().is_some(), "native worker owns the task");
                let mut connection = PgConnection::connect(
                    &cx,
                    &format!("postgres://test@{address}/test?sslmode=disable"),
                )
                .await
                .unwrap();
                let sql = SQL.to_owned();
                let mut attempts = 0;
                // SQL, the Pending witness, and the mutable attempt counter
                // remain caller-owned. Each invocation lends their state
                // alongside its transaction; nothing is cloned or leaked.
                let outcome = {
                    let mut state = BorrowedState {
                        sql: sql.as_str(),
                        pending: &pending,
                        attempts: &mut attempts,
                    };
                    if case.retries() {
                        with_pg_transaction_retry_with_state(
                            &mut connection,
                            &cx,
                            &retry_policy(),
                            case.replay_safety(),
                            &mut state,
                            |tx, tx_cx, state| {
                                TransactionFuture::new(pg_state_body(tx, tx_cx, state, case))
                            },
                        )
                        .await
                    } else {
                        with_pg_transaction_with_state(
                            &mut connection,
                            &cx,
                            &mut state,
                            |tx, tx_cx, state| {
                                TransactionFuture::new(pg_state_body(tx, tx_cx, state, case))
                            },
                        )
                        .await
                    }
                };
                assert_eq!(attempts, case.body_attempts());
                match case {
                    Case::Commit
                    | Case::ReplaySafe
                    | Case::BeginRetryUnsafe
                    | Case::CommitRetrySafe => {
                        assert_eq!(outcome.unwrap(), 1 + u64::try_from(sql.len()).unwrap());
                    }
                    Case::BodyError => assert!(matches!(
                        outcome, Outcome::Err(PgError::Protocol(message)) if message == "body rejected"
                    )),
                    Case::BodyCancelled => assert!(matches!(
                        outcome, Outcome::Cancelled(reason)
                            if reason == CancelReason::user("body cancelled")
                    )),
                    Case::BodyPanicked => assert!(matches!(
                        outcome, Outcome::Panicked(payload) if payload.message() == "body panicked"
                    )),
                    Case::CancelBeforeCommit => assert!(matches!(
                        outcome, Outcome::Cancelled(reason)
                            if reason == CancelReason::user("cancel before commit")
                    )),
                    Case::ReplayUnsafe | Case::CommitRetryUnsafe | Case::ReplayExhausted => {
                        assert!(matches!(
                            outcome, Outcome::Err(error) if error.is_serialization_failure()
                        ))
                    }
                }
                if case != Case::CancelBeforeCommit {
                    assert_eq!(
                        connection.execute_unchecked(&cx, REUSE_SQL).await.unwrap(),
                        1
                    );
                }
                connection.close().await.unwrap();
            });
            let native = finish_native(runtime, task, || {});
            let peer = server.wait();
            native.assert_success();
            peer.assert_success();
        }
    }
}

#[test]
fn mysql_lending_callbacks_preserve_transaction_lifecycle() {
    for workers in [1, 2] {
        for case in CASES {
            let (address, pending, server) = peer(Backend::MySql, case);
            let runtime = runtime(workers);
            let cx = runtime.request_cx_with_budget(Budget::INFINITE);
            let task = spawn_native(&runtime, async move {
                assert!(Cx::current().is_some(), "native worker owns the task");
                let mut connection = MySqlConnection::connect(
                    &cx,
                    &format!("mysql://test:test@{address}/test?sslmode=disabled"),
                )
                .await
                .unwrap();
                let sql = SQL.to_owned();
                let mut attempts = 0;
                let outcome = {
                    let mut state = BorrowedState {
                        sql: sql.as_str(),
                        pending: &pending,
                        attempts: &mut attempts,
                    };
                    if case.retries() {
                        with_mysql_transaction_retry_with_state(
                            &mut connection,
                            &cx,
                            &retry_policy(),
                            case.replay_safety(),
                            &mut state,
                            |tx, tx_cx, state| {
                                TransactionFuture::new(mysql_state_body(tx, tx_cx, state, case))
                            },
                        )
                        .await
                    } else {
                        with_mysql_transaction_with_state(
                            &mut connection,
                            &cx,
                            &mut state,
                            |tx, tx_cx, state| {
                                TransactionFuture::new(mysql_state_body(tx, tx_cx, state, case))
                            },
                        )
                        .await
                    }
                };
                assert_eq!(attempts, case.body_attempts());
                match case {
                    Case::Commit
                    | Case::ReplaySafe
                    | Case::BeginRetryUnsafe
                    | Case::CommitRetrySafe => {
                        assert_eq!(outcome.unwrap(), 1 + u64::try_from(sql.len()).unwrap());
                    }
                    Case::BodyError => assert!(matches!(
                        outcome, Outcome::Err(MySqlError::Protocol(message)) if message == "body rejected"
                    )),
                    Case::BodyCancelled => assert!(matches!(
                        outcome, Outcome::Cancelled(reason)
                            if reason == CancelReason::user("body cancelled")
                    )),
                    Case::BodyPanicked => assert!(matches!(
                        outcome, Outcome::Panicked(payload) if payload.message() == "body panicked"
                    )),
                    Case::CancelBeforeCommit => assert!(matches!(
                        outcome, Outcome::Cancelled(reason)
                            if reason == CancelReason::user("cancel before commit")
                    )),
                    Case::ReplayUnsafe | Case::CommitRetryUnsafe | Case::ReplayExhausted => {
                        assert!(matches!(
                            outcome, Outcome::Err(error) if error.is_deadlock()
                        ))
                    }
                }
                if case != Case::CancelBeforeCommit {
                    assert_eq!(
                        connection.execute_static_sql(&cx, REUSE_SQL).await.unwrap(),
                        1
                    );
                }
                connection.close().await.unwrap();
            });
            let native = finish_native(runtime, task, || {});
            let peer = server.wait();
            native.assert_success();
            peer.assert_success();
        }
    }
}

#[test]
fn state_helpers_await_rollback_before_returning_or_replaying() {
    for workers in [1, 2] {
        for backend in [Backend::Postgres, Backend::MySql] {
            for case in [Case::CancelBeforeCommit, Case::ReplaySafe] {
                let gate = Arc::new(RollbackGate::default());
                let (parked, parked_rx) = mpsc::channel();
                let (address, pending, server) =
                    peer_with_gate(backend, case, Some((Arc::clone(&gate), parked_rx)));
                let runtime = runtime(workers);
                let cx = runtime.request_cx_with_budget(Budget::INFINITE);
                let task = spawn_native(&runtime, async move {
                    let sql = SQL.to_owned();
                    let mut attempts = 0;
                    let mut state = BorrowedState {
                        sql: sql.as_str(),
                        pending: &pending,
                        attempts: &mut attempts,
                    };
                    match backend {
                        Backend::Postgres => {
                            let mut connection = PgConnection::connect(
                                &cx,
                                &format!("postgres://test@{address}/test?sslmode=disable"),
                            )
                            .await
                            .unwrap();
                            let policy = retry_policy();
                            let helper = with_pg_transaction_retry_with_state(
                                &mut connection,
                                &cx,
                                &policy,
                                case.replay_safety(),
                                &mut state,
                                |tx, cx, state| {
                                    if *state.attempts > 0 {
                                        assert!(gate.released.load(Ordering::Acquire));
                                    }
                                    ScopedTransactionFuture::new(pg_state_body(tx, cx, state, case))
                                },
                            );
                            let outcome = witnessed_rollback(helper, &gate, parked).await;
                            if case == Case::ReplaySafe {
                                assert_eq!(outcome.unwrap(), 1 + u64::try_from(sql.len()).unwrap());
                            } else {
                                assert!(matches!(outcome, Outcome::Cancelled(reason)
                                    if reason == CancelReason::user("cancel before commit")));
                            }
                            assert!(
                                !connection.in_transaction(),
                                "ROLLBACK must be acknowledged"
                            );
                            assert!(!connection.needs_discard(), "cleanup left no orphan");
                            if case == Case::ReplaySafe {
                                assert_eq!(
                                    connection.execute_unchecked(&cx, REUSE_SQL).await.unwrap(),
                                    1
                                );
                            }
                            connection.close().await.unwrap();
                        }
                        Backend::MySql => {
                            let mut connection = MySqlConnection::connect(
                                &cx,
                                &format!("mysql://test:test@{address}/test?sslmode=disabled"),
                            )
                            .await
                            .unwrap();
                            let policy = retry_policy();
                            let helper = with_mysql_transaction_retry_with_state(
                                &mut connection,
                                &cx,
                                &policy,
                                case.replay_safety(),
                                &mut state,
                                |tx, cx, state| {
                                    if *state.attempts > 0 {
                                        assert!(gate.released.load(Ordering::Acquire));
                                    }
                                    ScopedTransactionFuture::new(mysql_state_body(
                                        tx, cx, state, case,
                                    ))
                                },
                            );
                            let outcome = witnessed_rollback(helper, &gate, parked).await;
                            if case == Case::ReplaySafe {
                                assert_eq!(outcome.unwrap(), 1 + u64::try_from(sql.len()).unwrap());
                            } else {
                                assert!(matches!(outcome, Outcome::Cancelled(reason)
                                    if reason == CancelReason::user("cancel before commit")));
                            }
                            assert!(
                                !connection.in_transaction(),
                                "ROLLBACK must be acknowledged"
                            );
                            if case == Case::ReplaySafe {
                                assert_eq!(
                                    connection.execute_static_sql(&cx, REUSE_SQL).await.unwrap(),
                                    1
                                );
                            }
                            connection.close().await.unwrap();
                        }
                    }
                    assert!(gate.received.load(Ordering::Acquire));
                    assert!(gate.released.load(Ordering::Acquire));
                    assert_eq!(attempts, case.body_attempts());
                });
                let native = finish_native(runtime, task, || {});
                let peer = server.wait();
                native.assert_success();
                peer.assert_success();
            }
        }
    }
}

// Intentionally neither Clone nor Copy: callback disposal must release the
// original caller-owned state rather than an owned replacement.
#[derive(Default)]
struct CallbackCounter {
    drops: usize,
    reuses: usize,
}

struct CallbackDropGuard<'a>(&'a mut CallbackCounter);

impl Drop for CallbackDropGuard<'_> {
    fn drop(&mut self) {
        self.0.drops += 1;
    }
}

struct DroppedBodyState<'a> {
    sql: &'a str,
    pending: &'a mpsc::Sender<()>,
    parked: &'a AtomicBool,
    counter: &'a mut CallbackCounter,
}

async fn witness_suspended_body<F: Future>(mut helper: std::pin::Pin<&mut F>, parked: &AtomicBool) {
    poll_fn(|task| {
        assert!(
            helper.as_mut().poll(task).is_pending(),
            "the helper must remain Pending after the callback parks"
        );
        if parked.load(Ordering::Acquire) {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    })
    .await;
}

#[test]
fn dropping_a_state_helper_releases_borrows_and_rolls_back_before_reuse() {
    for workers in [1, 2] {
        for backend in [Backend::Postgres, Backend::MySql] {
            // The callback is abandoned after SQL succeeds. The connection
            // must drain its orphaned transaction before the reuse command,
            // which has the same wire order as the ordinary body-error case.
            let (address, pending, server) = peer(backend, Case::BodyError);
            let runtime = runtime(workers);
            let cx = runtime.request_cx_with_budget(Budget::INFINITE);
            let task = spawn_native(&runtime, async move {
                let sql = SQL.to_owned();
                let parked = AtomicBool::new(false);
                let mut counter = CallbackCounter::default();
                let mut state = DroppedBodyState {
                    sql: sql.as_str(),
                    pending: &pending,
                    parked: &parked,
                    counter: &mut counter,
                };
                match backend {
                    Backend::Postgres => {
                        let mut connection = PgConnection::connect(
                            &cx,
                            &format!("postgres://test@{address}/test?sslmode=disable"),
                        )
                        .await
                        .unwrap();
                        let mut helper = Box::pin(with_pg_transaction_with_state(
                            &mut connection,
                            &cx,
                            &mut state,
                            |tx, cx, state| {
                                ScopedTransactionFuture::new(async move {
                                    let guard = CallbackDropGuard(&mut *state.counter);
                                    assert_eq!(
                                        witnessed(
                                            tx.execute_unchecked(cx, state.sql),
                                            state.pending
                                        )
                                        .await
                                        .unwrap(),
                                        1
                                    );
                                    state.parked.store(true, Ordering::Release);
                                    let result =
                                        std::future::pending::<Outcome<(), PgError>>().await;
                                    drop(guard);
                                    result
                                })
                            },
                        ));
                        witness_suspended_body(helper.as_mut(), &parked).await;
                        drop(helper);
                        assert_eq!(state.counter.drops, 1, "callback dropped exactly once");
                        state.counter.reuses += 1;
                        assert!(connection.in_transaction(), "cleanup is still owed");
                        assert!(
                            connection.needs_discard(),
                            "an orphan must not reach the pool"
                        );
                        assert_eq!(
                            connection.execute_unchecked(&cx, REUSE_SQL).await.unwrap(),
                            1
                        );
                        assert!(!connection.in_transaction());
                        assert!(!connection.needs_discard());
                        connection.close().await.unwrap();
                    }
                    Backend::MySql => {
                        let mut connection = MySqlConnection::connect(
                            &cx,
                            &format!("mysql://test:test@{address}/test?sslmode=disabled"),
                        )
                        .await
                        .unwrap();
                        let mut helper = Box::pin(with_mysql_transaction_with_state(
                            &mut connection,
                            &cx,
                            &mut state,
                            |tx, cx, state| {
                                ScopedTransactionFuture::new(async move {
                                    let guard = CallbackDropGuard(&mut *state.counter);
                                    assert_eq!(
                                        witnessed(
                                            tx.execute_static_sql(cx, state.sql),
                                            state.pending
                                        )
                                        .await
                                        .unwrap(),
                                        1
                                    );
                                    state.parked.store(true, Ordering::Release);
                                    let result =
                                        std::future::pending::<Outcome<(), MySqlError>>().await;
                                    drop(guard);
                                    result
                                })
                            },
                        ));
                        witness_suspended_body(helper.as_mut(), &parked).await;
                        drop(helper);
                        assert_eq!(state.counter.drops, 1, "callback dropped exactly once");
                        state.counter.reuses += 1;
                        assert!(connection.in_transaction(), "cleanup is still owed");
                        assert_eq!(
                            connection.execute_static_sql(&cx, REUSE_SQL).await.unwrap(),
                            1
                        );
                        assert!(!connection.in_transaction());
                        connection.close().await.unwrap();
                    }
                }
                // These accesses also verify that the exclusive borrow has
                // ended; no clone, 'static allocation, or leaked state exists.
                assert_eq!(counter.drops, 1);
                assert_eq!(counter.reuses, 1);
                assert_eq!(sql, SQL);
            });
            let native = finish_native(runtime, task, || {});
            let peer = server.wait();
            native.assert_success();
            peer.assert_success();
        }
    }
}

fn pg_owned_body<'a>(
    tx: &'a mut PgTransaction<'_>,
    cx: &'a Cx,
    pending: mpsc::Sender<()>,
    case: Case,
) -> TransactionFuture<'static, 'a, u64, PgError> {
    TransactionFuture::new(async move { pg_body(tx, cx, SQL, &pending, case).await })
}

fn mysql_owned_body<'a>(
    tx: &'a mut MySqlTransaction<'_>,
    cx: &'a Cx,
    pending: mpsc::Sender<()>,
    case: Case,
) -> TransactionFuture<'static, 'a, u64, MySqlError> {
    TransactionFuture::new(async move { mysql_body(tx, cx, SQL, &pending, case).await })
}

#[test]
fn existing_lending_apis_preserve_owned_callback_captures() {
    for workers in [1, 2] {
        for backend in [Backend::Postgres, Backend::MySql] {
            for case in [Case::Commit, Case::ReplayUnsafe] {
                let (address, pending, server) = peer(backend, case);
                let runtime = runtime(workers);
                let cx = runtime.request_cx_with_budget(Budget::INFINITE);
                let task = spawn_native(&runtime, async move {
                    // Existing callbacks can own their captured witness and
                    // borrow the transaction/context. The state-taking tests
                    // above additionally borrow the caller's stack data.
                    match backend {
                        Backend::Postgres => {
                            let mut connection = PgConnection::connect(
                                &cx,
                                &format!("postgres://test@{address}/test?sslmode=disable"),
                            )
                            .await
                            .unwrap();
                            let outcome = if case.retries() {
                                let mut pending = Some(pending);
                                with_pg_transaction_retry_borrowed(
                                    &mut connection,
                                    &cx,
                                    &retry_policy(),
                                    TransactionReplaySafety::ReplayUnsafe,
                                    move |tx, tx_cx| {
                                        pg_owned_body(
                                            tx,
                                            tx_cx,
                                            pending.take().expect("ReplayUnsafe cannot replay"),
                                            case,
                                        )
                                    },
                                )
                                .await
                            } else {
                                with_pg_transaction_borrowed(
                                    &mut connection,
                                    &cx,
                                    move |tx, tx_cx| pg_owned_body(tx, tx_cx, pending, case),
                                )
                                .await
                            };
                            if case == Case::Commit {
                                assert_eq!(outcome.unwrap(), 1 + u64::try_from(SQL.len()).unwrap());
                            } else {
                                assert!(matches!(outcome,
                                    Outcome::Err(error) if error.is_serialization_failure()));
                            }
                            assert_eq!(
                                connection.execute_unchecked(&cx, REUSE_SQL).await.unwrap(),
                                1
                            );
                            connection.close().await.unwrap();
                        }
                        Backend::MySql => {
                            let mut connection = MySqlConnection::connect(
                                &cx,
                                &format!("mysql://test:test@{address}/test?sslmode=disabled"),
                            )
                            .await
                            .unwrap();
                            let outcome = if case.retries() {
                                let mut pending = Some(pending);
                                with_mysql_transaction_retry_borrowed(
                                    &mut connection,
                                    &cx,
                                    &retry_policy(),
                                    TransactionReplaySafety::ReplayUnsafe,
                                    move |tx, tx_cx| {
                                        mysql_owned_body(
                                            tx,
                                            tx_cx,
                                            pending.take().expect("ReplayUnsafe cannot replay"),
                                            case,
                                        )
                                    },
                                )
                                .await
                            } else {
                                with_mysql_transaction_borrowed(
                                    &mut connection,
                                    &cx,
                                    move |tx, tx_cx| mysql_owned_body(tx, tx_cx, pending, case),
                                )
                                .await
                            };
                            if case == Case::Commit {
                                assert_eq!(outcome.unwrap(), 1 + u64::try_from(SQL.len()).unwrap());
                            } else {
                                assert!(matches!(outcome,
                                    Outcome::Err(error) if error.is_deadlock()));
                            }
                            assert_eq!(
                                connection.execute_static_sql(&cx, REUSE_SQL).await.unwrap(),
                                1
                            );
                            connection.close().await.unwrap();
                        }
                    }
                });
                let native = finish_native(runtime, task, || {});
                let peer = server.wait();
                native.assert_success();
                peer.assert_success();
            }
        }
    }
}

const RETRY_BACKOFF: Duration = Duration::from_secs(3600);

fn backoff_cancellation() -> CancelReason {
    CancelReason::user("cancel parked transaction retry")
}

struct BackoffRecovery {
    request_cx: Cx,
    clock: Arc<VirtualClock>,
    timer: TimerDriverHandle,
}

impl BackoffRecovery {
    fn release(&self) {
        // Failure recovery also covers a controller that exits before seeing
        // the parked witness. Cancellation prevents a late new attempt;
        // advancing the deadline releases an already parked, unfixed wait.
        self.request_cx.cancel_with_reason(backoff_cancellation());
        self.clock.advance_to(Time::from_secs(3600));
        let _ = self.timer.process_timers();
    }
}

struct RecoverBackoffOnDrop {
    recovery: Arc<BackoffRecovery>,
    armed: bool,
}

impl Drop for RecoverBackoffOnDrop {
    fn drop(&mut self) {
        if self.armed {
            self.recovery.release();
        }
    }
}

async fn witnessed_backoff<F: Future>(
    future: F,
    timer: &TimerDriverHandle,
    parked: mpsc::Sender<()>,
) -> F::Output {
    let mut future = std::pin::pin!(future);
    let mut parked = Some(parked);
    poll_fn(|task| {
        let result = future.as_mut().poll(task);
        if result.is_pending()
            && timer.pending_count() == 1
            && timer.next_deadline() == Some(Time::from_secs(3600))
            && let Some(parked) = parked.take()
        {
            // The callback has finished, the peer has acknowledged ROLLBACK,
            // and the public retry helper has actually parked on its backoff.
            // A callback-entry or server-write signal alone cannot prove that.
            parked.send(()).unwrap();
        }
        result
    })
    .await
}

#[test]
fn separate_request_cancellation_wakes_parked_transaction_backoff() {
    for workers in [1, 2] {
        for backend in [Backend::Postgres, Backend::MySql] {
            // Cancellation during a replay-safe backoff must produce the same
            // wire sequence as refused replay: one failed query, its rollback,
            // then the independent reuse probe, with no second BEGIN.
            let (address, pending, server) = peer(backend, Case::ReplayUnsafe);
            let clock = Arc::new(VirtualClock::new());
            let timer = TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
            let runtime = RuntimeBuilder::multi_thread()
                .worker_threads(workers)
                .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
                .with_timer_driver(timer.clone())
                .build()
                .unwrap();
            let request_cx = runtime.request_cx_with_budget(Budget::INFINITE);
            let recovery = Arc::new(BackoffRecovery {
                request_cx: request_cx.clone(),
                clock: Arc::clone(&clock),
                timer: timer.clone(),
            });
            let (parked, parked_rx) = mpsc::channel();
            let (completed, completed_rx) = mpsc::channel();
            let controller_recovery = Arc::clone(&recovery);
            let controller = spawn_host("backoff controller", move || {
                let mut rescue = RecoverBackoffOnDrop {
                    recovery: controller_recovery,
                    armed: true,
                };
                parked_rx
                    .recv_timeout(DEADLINE)
                    .expect("parked retry backoff");
                assert_eq!(rescue.recovery.timer.now(), Time::ZERO);
                rescue
                    .recovery
                    .request_cx
                    .cancel_with_reason(backoff_cancellation());
                let woke_without_timer = completed_rx.recv_timeout(Duration::from_secs(5)).is_ok();
                if !woke_without_timer {
                    // Release an unfixed implementation so the regression fails
                    // with a wake assertion instead of leaving a parked task.
                    // This recovery never counts as a successful cancellation.
                    rescue.recovery.release();
                    let _ = completed_rx.recv_timeout(Duration::from_secs(5));
                } else {
                    // Only the observed cancellation wake disarms recovery.
                    rescue.armed = false;
                }
                woke_without_timer
            });
            let task_timer = timer.clone();
            let task = spawn_native(&runtime, async move {
                let active_cx = Cx::current().expect("native transaction worker");
                assert_ne!(active_cx.task_id(), request_cx.task_id());
                let policy = RetryPolicy {
                    max_retries: 1,
                    base_delay: RETRY_BACKOFF,
                    max_delay: RETRY_BACKOFF,
                };
                let sql = SQL.to_owned();
                let mut attempts = 0;
                let mut state = BorrowedState {
                    sql: sql.as_str(),
                    pending: &pending,
                    attempts: &mut attempts,
                };
                match backend {
                    Backend::Postgres => {
                        let mut connection = PgConnection::connect(
                            &request_cx,
                            &format!("postgres://test@{address}/test?sslmode=disable"),
                        )
                        .await
                        .unwrap();
                        let retry = with_pg_transaction_retry_with_state(
                            &mut connection,
                            &request_cx,
                            &policy,
                            TransactionReplaySafety::ReplaySafe,
                            &mut state,
                            |tx, cx, state| {
                                TransactionFuture::new(pg_state_body(
                                    tx,
                                    cx,
                                    state,
                                    Case::ReplaySafe,
                                ))
                            },
                        );
                        let outcome = witnessed_backoff(retry, &task_timer, parked).await;
                        assert!(matches!(outcome, Outcome::Cancelled(reason)
                            if reason == backoff_cancellation()));
                        assert_eq!(
                            connection
                                .execute_unchecked(&active_cx, REUSE_SQL)
                                .await
                                .unwrap(),
                            1
                        );
                        connection.close().await.unwrap();
                    }
                    Backend::MySql => {
                        let mut connection = MySqlConnection::connect(
                            &request_cx,
                            &format!("mysql://test:test@{address}/test?sslmode=disabled"),
                        )
                        .await
                        .unwrap();
                        let retry = with_mysql_transaction_retry_with_state(
                            &mut connection,
                            &request_cx,
                            &policy,
                            TransactionReplaySafety::ReplaySafe,
                            &mut state,
                            |tx, cx, state| {
                                TransactionFuture::new(mysql_state_body(
                                    tx,
                                    cx,
                                    state,
                                    Case::ReplaySafe,
                                ))
                            },
                        );
                        let outcome = witnessed_backoff(retry, &task_timer, parked).await;
                        assert!(matches!(outcome, Outcome::Cancelled(reason)
                            if reason == backoff_cancellation()));
                        assert_eq!(
                            connection
                                .execute_static_sql(&active_cx, REUSE_SQL)
                                .await
                                .unwrap(),
                            1
                        );
                        connection.close().await.unwrap();
                    }
                }
                assert_eq!(attempts, 1, "cancelled backoff must not replay the body");
                assert!(!active_cx.is_cancel_requested());
                assert_eq!(task_timer.pending_count(), 0, "backoff timer must retire");
                completed.send(()).unwrap();
            });
            let native = finish_native(runtime, task, || recovery.release());
            let controller = controller.wait();
            let peer = server.wait();
            native.assert_success();
            let woke_without_timer = controller.assert_success();
            peer.assert_success();
            assert!(
                woke_without_timer,
                "{backend:?} {workers} workers: caller cancellation did not wake backoff"
            );
            assert_eq!(
                timer.now(),
                Time::ZERO,
                "cancellation needs no clock advance"
            );
            assert_eq!(timer.pending_count(), 0);
        }
    }
}
