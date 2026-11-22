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
    RetryPolicy, TransactionFuture, TransactionReplaySafety, with_mysql_transaction_borrowed,
    with_mysql_transaction_retry_borrowed, with_pg_transaction_borrowed,
    with_pg_transaction_retry_borrowed,
};
use asupersync::runtime::{RootDrainOutcome, RuntimeBuilder};
use asupersync::types::{Budget, CancelReason, Outcome};
use std::future::{Future, poll_fn};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

const SQL: &str = "UPDATE accounts SET balance = balance + 1";
const REUSE_SQL: &str = "UPDATE accounts SET balance = balance + 0";
const DEADLINE: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Case {
    Commit,
    BodyError,
    CancelBeforeCommit,
    ReplaySafe,
    ReplayUnsafe,
}

const CASES: [Case; 5] = [
    Case::Commit,
    Case::BodyError,
    Case::CancelBeforeCommit,
    Case::ReplaySafe,
    Case::ReplayUnsafe,
];

impl Case {
    fn retries(self) -> bool {
        matches!(self, Self::ReplaySafe | Self::ReplayUnsafe)
    }

    fn replay_safety(self) -> TransactionReplaySafety {
        if self == Self::ReplaySafe {
            TransactionReplaySafety::ReplaySafe
        } else {
            TransactionReplaySafety::ReplayUnsafe
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Backend {
    Postgres,
    MySql,
}

fn script(backend: Backend, case: Case) -> Vec<(&'static str, bool)> {
    let begin = match backend {
        Backend::Postgres => "BEGIN",
        Backend::MySql => "START TRANSACTION",
    };
    let mut commands = vec![(begin, false), (SQL, case.retries())];
    commands.push((
        if case == Case::Commit {
            "COMMIT"
        } else {
            "ROLLBACK"
        },
        false,
    ));
    if case == Case::ReplaySafe {
        commands.extend([(begin, false), (SQL, false), ("COMMIT", false)]);
    }
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

fn peer(backend: Backend, case: Case) -> (SocketAddr, mpsc::Sender<()>, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let (pending, observed) = mpsc::channel();
    let server = thread::spawn(move || {
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
            match sql {
                "BEGIN" | "START TRANSACTION" => in_transaction = true,
                "COMMIT" | "ROLLBACK" => in_transaction = false,
                _ => {}
            }
            match backend {
                Backend::Postgres => {
                    if fail {
                        pg_write(&mut socket, b'E', b"SERROR\0C40001\0Mretry transaction\0\0");
                        pg_write(&mut socket, b'Z', b"E");
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
        assert_eq!(socket.read(&mut [0]).unwrap(), 0, "connection must close");
    });
    (address, pending, server)
}

fn runtime(workers: usize) -> asupersync::runtime::Runtime {
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
        Case::CancelBeforeCommit => {
            cx.set_cancel_reason(CancelReason::user("cancel before commit"));
            Outcome::Ok(affected + u64::try_from(sql.len()).unwrap())
        }
        _ => Outcome::Ok(affected + u64::try_from(sql.len()).unwrap()),
    }
}

#[test]
fn postgres_lending_callbacks_preserve_transaction_lifecycle() {
    for workers in [1, 2] {
        for case in CASES {
            let (address, pending, server) = peer(Backend::Postgres, case);
            let runtime = runtime(workers);
            let cx = runtime.request_cx_with_budget(Budget::INFINITE);
            let task = runtime.handle().spawn(async move {
                assert!(Cx::current().is_some(), "native worker owns the task");
                let mut connection = PgConnection::connect(
                    &cx,
                    &format!("postgres://test@{address}/test?sslmode=disable"),
                )
                .await
                .unwrap();
                let sql = SQL.to_owned();
                let mut attempts = 0;
                // The callback lends both its arguments and independently
                // captured stack data to its future. Neither the SQL nor the
                // Pending sender is moved into the callback's async operation.
                let borrowed_sql = sql.as_str();
                let borrowed_pending = &pending;
                let outcome = if case.retries() {
                    with_pg_transaction_retry_borrowed(
                        &mut connection,
                        &cx,
                        &retry_policy(),
                        case.replay_safety(),
                        |tx, tx_cx| {
                            attempts += 1;
                            TransactionFuture::new(pg_body(
                                tx,
                                tx_cx,
                                borrowed_sql,
                                borrowed_pending,
                                case,
                            ))
                        },
                    )
                    .await
                } else {
                    with_pg_transaction_borrowed(&mut connection, &cx, |tx, tx_cx| {
                        attempts += 1;
                        TransactionFuture::new(pg_body(
                            tx,
                            tx_cx,
                            borrowed_sql,
                            borrowed_pending,
                            case,
                        ))
                    })
                    .await
                };
                assert_eq!(attempts, if case == Case::ReplaySafe { 2 } else { 1 });
                match case {
                    Case::Commit | Case::ReplaySafe => {
                        assert_eq!(outcome.unwrap(), 1 + u64::try_from(sql.len()).unwrap());
                    }
                    Case::BodyError => assert!(matches!(
                        outcome, Outcome::Err(PgError::Protocol(message)) if message == "body rejected"
                    )),
                    Case::CancelBeforeCommit => assert!(matches!(
                        outcome, Outcome::Cancelled(reason)
                            if reason == CancelReason::user("cancel before commit")
                    )),
                    Case::ReplayUnsafe => assert!(matches!(
                        outcome, Outcome::Err(error) if error.is_serialization_failure()
                    )),
                }
                if case != Case::CancelBeforeCommit {
                    assert_eq!(connection.execute_unchecked(&cx, REUSE_SQL).await.unwrap(), 1);
                }
                connection.close().await.unwrap();
            });
            runtime.block_on(task);
            server.join().unwrap();
            assert_eq!(
                runtime.shutdown_drained(DEADLINE).outcome,
                RootDrainOutcome::Quiescent
            );
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
            let task = runtime.handle().spawn(async move {
                assert!(Cx::current().is_some(), "native worker owns the task");
                let mut connection = MySqlConnection::connect(
                    &cx,
                    &format!("mysql://test:test@{address}/test?sslmode=disabled"),
                )
                .await
                .unwrap();
                let sql = SQL.to_owned();
                let mut attempts = 0;
                let borrowed_sql = sql.as_str();
                let borrowed_pending = &pending;
                let outcome = if case.retries() {
                    with_mysql_transaction_retry_borrowed(
                        &mut connection,
                        &cx,
                        &retry_policy(),
                        case.replay_safety(),
                        |tx, tx_cx| {
                            attempts += 1;
                            TransactionFuture::new(mysql_body(
                                tx,
                                tx_cx,
                                borrowed_sql,
                                borrowed_pending,
                                case,
                            ))
                        },
                    )
                    .await
                } else {
                    with_mysql_transaction_borrowed(&mut connection, &cx, |tx, tx_cx| {
                        attempts += 1;
                        TransactionFuture::new(mysql_body(
                            tx,
                            tx_cx,
                            borrowed_sql,
                            borrowed_pending,
                            case,
                        ))
                    })
                    .await
                };
                assert_eq!(attempts, if case == Case::ReplaySafe { 2 } else { 1 });
                match case {
                    Case::Commit | Case::ReplaySafe => {
                        assert_eq!(outcome.unwrap(), 1 + u64::try_from(sql.len()).unwrap());
                    }
                    Case::BodyError => assert!(matches!(
                        outcome, Outcome::Err(MySqlError::Protocol(message)) if message == "body rejected"
                    )),
                    Case::CancelBeforeCommit => assert!(matches!(
                        outcome, Outcome::Cancelled(reason)
                            if reason == CancelReason::user("cancel before commit")
                    )),
                    Case::ReplayUnsafe => assert!(matches!(
                        outcome, Outcome::Err(error) if error.is_deadlock()
                    )),
                }
                if case != Case::CancelBeforeCommit {
                    assert_eq!(connection.execute_static_sql(&cx, REUSE_SQL).await.unwrap(), 1);
                }
                connection.close().await.unwrap();
            });
            runtime.block_on(task);
            server.join().unwrap();
            assert_eq!(
                runtime.shutdown_drained(DEADLINE).outcome,
                RootDrainOutcome::Quiescent
            );
        }
    }
}
