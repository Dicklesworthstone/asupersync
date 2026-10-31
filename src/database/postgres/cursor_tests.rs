#![cfg(not(target_arch = "wasm32"))]

use super::*;
use super::super::{
    BackendFrame, CancelTarget, DEFAULT_MAX_PREPARED_STATEMENTS, DEFAULT_MAX_RESULT_ROWS,
    NotificationBuffer, PgConnectOptions, PgConnectionInner, PgStream, PreparedStatementCache,
    SslMode, oid,
};
use crate::runtime::RuntimeBuilder;
use crate::types::CancelKind;
use std::collections::{BTreeSet, VecDeque};
use std::future::{Future, poll_fn};
use std::io::{Read, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Poll;
use std::time::{Duration, Instant};

fn native<F, Fut>(workers: usize, scenario: F)
where F: FnOnce(Cx) -> Fut + Send + 'static, Fut: Future<Output = ()> + Send + 'static,
{
    let (done_tx, done_rx) = std::sync::mpsc::sync_channel(1);
    let runner = std::thread::spawn(move || {
        let builder = if workers == 1 { RuntimeBuilder::current_thread() }
            else { RuntimeBuilder::new().worker_threads(workers) };
        let runtime = builder.with_reactor(crate::runtime::reactor::create_reactor().unwrap())
            .build().unwrap();
        let complete = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let observed = Arc::clone(&complete);
        runtime.block_on(runtime.handle().spawn(async move {
            let cx = Cx::current().unwrap();
            crate::time::timeout(cx.now(), Duration::from_secs(10), scenario(cx)).await
                .expect("bounded cursor scenario");
            observed.store(true, Ordering::Release);
        }));
        assert!(complete.load(Ordering::Acquire));
        assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
        assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
        done_tx.send(()).unwrap();
    });
    match done_rx.recv_timeout(Duration::from_secs(20)) {
        Ok(()) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => runner.join().unwrap(),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => panic!("cursor native watchdog"),
    }
}

fn pair() -> (PgConnection, std::net::TcpStream) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let socket = std::net::TcpStream::connect(addr).unwrap();
    let (peer, _) = listener.accept().unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    peer.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
    let options = PgConnectOptions {
        host: "127.0.0.1".to_string(), port: addr.port(), database: "test".to_string(),
        user: "cursor".to_string(), password: None, application_name: None,
        connect_timeout: Some(Duration::from_secs(2)), ssl_mode: SslMode::Disable,
    };
    (PgConnection { inner: PgConnectionInner {
        stream: PgStream::Plain(crate::net::TcpStream::from_std(socket).unwrap()),
        options, tls_options: super::super::PgTlsOptions::default(), process_id: 0, secret_key: 0,
        cancel_target: CancelTarget { host: "127.0.0.1".to_string(), port: addr.port(), connect_timeout: Duration::from_millis(500) },
        parameters: BTreeMap::new(), transaction_status: b'I', closed: false,
        explicitly_closed: false, needs_rollback: false, needs_discard: false,
        next_stmt_id: 0, session_generation: 0, max_result_rows: DEFAULT_MAX_RESULT_ROWS,
        prepared_cache: PreparedStatementCache::new(DEFAULT_MAX_PREPARED_STATEMENTS),
        deallocate_retry_queue: VecDeque::new(), consecutive_deallocate_failures: 0,
        unhealthy: false, subscribed_channels: BTreeSet::new(), notifications: NotificationBuffer::default(),
        // Every wire timeout is floored at 1 ms (`statement_timeout_millis`: the server reads 0 as
        // "disabled"), so this session is already reconciled whatever deadline a test's Cx has.
        backend_frame: BackendFrame::default(), statement_timeout_override: Some(Duration::from_millis(1)),
        applied_statement_timeout_ms: Some(1), statement_timeout_uncertain: false,
        statement_timeout_set_in_block: false, pending_session_reset: false,
    } }, peer)
}

fn cached(conn: &mut PgConnection, name: &str, sql: &str, oids: &[u32]) -> PgStatement {
    let statement = PgStatement { name: name.to_string(), sql: sql.to_string(),
        param_oids: oids.to_vec(), columns: Vec::new(), session_generation: conn.inner.session_generation };
    assert!(conn.inner.prepared_cache.insert_returning_evicted_name(sql.to_string(), statement.clone()).is_none());
    statement
}

fn frame(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut frame = vec![kind];
    frame.extend_from_slice(&i32::try_from(body.len() + 4).unwrap().to_be_bytes());
    frame.extend_from_slice(body); frame
}
fn send(peer: &mut std::net::TcpStream, kind: u8, body: &[u8]) {
    peer.write_all(&frame(kind, body)).unwrap();
}
fn read(peer: &mut std::net::TcpStream) -> (u8, Vec<u8>) {
    let mut header = [0; 5]; peer.read_exact(&mut header).unwrap();
    let length = i32::from_be_bytes(header[1..].try_into().unwrap());
    assert!((4..=65536).contains(&length), "unexpected frontend length {length}");
    let mut body = vec![0; usize::try_from(length - 4).unwrap()]; peer.read_exact(&mut body).unwrap();
    (header[0], body)
}
fn no_request(peer: &mut std::net::TcpStream) {
    peer.set_nonblocking(true).unwrap();
    assert!(matches!(peer.read(&mut [0; 1]), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock));
    peer.set_nonblocking(false).unwrap();
}
fn eof(peer: &mut std::net::TcpStream) {
    match peer.read(&mut [0; 1]) {
        Ok(0) => {}
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
        other => panic!("unsynchronized cursor must physically close: {other:?}"),
    }
}
fn description() -> Vec<u8> {
    let mut body = Vec::new(); body.extend_from_slice(&1i16.to_be_bytes());
    body.extend_from_slice(b"value\0"); body.extend_from_slice(&0u32.to_be_bytes());
    body.extend_from_slice(&0i16.to_be_bytes()); body.extend_from_slice(&oid::TEXT.to_be_bytes());
    body.extend_from_slice(&(-1i16).to_be_bytes()); body.extend_from_slice(&(-1i32).to_be_bytes());
    body.extend_from_slice(&0i16.to_be_bytes()); body
}
fn row(value: &str) -> Vec<u8> {
    let mut body = Vec::new(); body.extend_from_slice(&1i16.to_be_bytes());
    body.extend_from_slice(&i32::try_from(value.len()).unwrap().to_be_bytes());
    body.extend_from_slice(value.as_bytes()); body
}
fn start_response(peer: &mut std::net::TcpStream) { send(peer, b'2', b""); send(peer, b'T', &description()); }
fn start_request(peer: &mut std::net::TcpStream, name: &str, batch: i32) {
    let (kind, body) = read(peer); assert_eq!(kind, b'B');
    assert!(body.starts_with(format!("\0{name}\0").as_bytes()));
    assert_eq!(read(peer), (b'D', b"P\0".to_vec()));
    fetch_request(peer, batch);
}
fn fetch_request(peer: &mut std::net::TcpStream, batch: i32) {
    let mut execute = vec![0]; execute.extend_from_slice(&batch.to_be_bytes());
    assert_eq!(read(peer), (b'E', execute)); assert_eq!(read(peer), (b'H', vec![]));
}
fn close_request(peer: &mut std::net::TcpStream) {
    assert_eq!(read(peer), (b'C', b"P\0".to_vec())); assert_eq!(read(peer), (b'S', vec![]));
}
fn close_response(peer: &mut std::net::TcpStream, status: u8) { send(peer, b'3', b""); send(peer, b'Z', &[status]); }
fn assert_row(outcome: Outcome<Option<PgRow>, PgError>, value: &str) {
    match outcome { Outcome::Ok(Some(row)) => assert_eq!(row.get_str("value").unwrap(), value),
        other => panic!("expected row {value}: {other:?}") }
}

#[test]
fn cursor_config_requires_finite_positive_wire_bounds() {
    for (rows, bytes) in [(0, 64), (u32::MAX, 64), (1, 0), (1, MAX_BACKEND_MESSAGE_LEN as usize)] {
        assert!(matches!(PgCursorConfig::new(rows, bytes), Err(PgError::Protocol(_))));
    }
    let config = PgCursorConfig::new(i32::MAX as u32, MAX_BACKEND_MESSAGE_LEN as usize - 4).unwrap();
    assert_eq!(config.batch_rows(), i32::MAX as u32);
    assert_eq!(config.max_message_bytes(), MAX_BACKEND_MESSAGE_LEN as usize - 4);
}

#[test]
fn native_cursor_requests_batches_only_when_consumed_then_reuses_connection() {
    for workers in [1, 2] { native(workers, |cx| async move {
        let (mut conn, mut peer) = pair();
        let statement = cached(&mut conn, "known", "SELECT value FROM large_table", &[]);
        start_response(&mut peer); send(&mut peer, b'D', &row("one")); send(&mut peer, b'D', &row("two"));
        send(&mut peer, b's', b"");
        let mut cursor = match conn.query_cursor_prepared(&cx, &statement, &[], PgCursorConfig::new(2, 128).unwrap()).await {
            Outcome::Ok(cursor) => cursor, other => panic!("{other:?}"),
        };
        start_request(&mut peer, "known", 2);
        assert_row(cursor.next(&cx).await, "one"); assert_row(cursor.next(&cx).await, "two");
        no_request(&mut peer);
        send(&mut peer, b'S', b"application_name\0cursor-test\0");
        send(&mut peer, b'D', &row("three")); send(&mut peer, b'C', b"SELECT 3\0");
        close_response(&mut peer, b'I');
        assert_row(cursor.next(&cx).await, "three"); fetch_request(&mut peer, 2);
        no_request(&mut peer); assert!(cursor.completion().is_none());
        assert!(matches!(cursor.next(&cx).await, Outcome::Ok(None)));
        close_request(&mut peer);
        let receipt = cursor.completion().unwrap();
        assert_eq!((receipt.rows_received(), receipt.rows_yielded()), (3, 3));
        assert!(receipt.exhausted()); assert_eq!(receipt.command_tag(), Some("SELECT 3"));
        assert!(matches!(cursor.next(&cx).await, Outcome::Ok(None)));
        assert!(matches!(cursor.close(&cx).await, Outcome::Ok(ref same) if same == &receipt));
        assert!(!conn.inner.closed); assert_eq!(conn.parameter("application_name"), Some("cursor-test"));
        send(&mut peer, b'T', &description()); send(&mut peer, b'D', &row("reused"));
        send(&mut peer, b'C', b"SELECT 1\0"); send(&mut peer, b'Z', b"I");
        match conn.query_unchecked(&cx, "SELECT 'reused'").await {
            Outcome::Ok(rows) => assert_eq!(rows[0].get_str("value").unwrap(), "reused"),
            other => panic!("synchronized connection reuse: {other:?}"),
        }
        assert_eq!(read(&mut peer), (b'Q', b"SELECT 'reused'\0".to_vec()));
    }); }
}

#[test]
fn native_early_cursor_close_drains_only_the_current_batch_and_preserves_transaction() {
    for workers in [1, 2] { native(workers, |cx| async move {
        let (mut conn, mut peer) = pair(); conn.inner.transaction_status = b'T';
        cached(&mut conn, "known", "SELECT value FROM large_table", &[]);
        start_response(&mut peer); send(&mut peer, b'D', &row("one")); send(&mut peer, b'D', &row("two"));
        send(&mut peer, b's', b""); close_response(&mut peer, b'T');
        let mut transaction = PgTransaction { conn: &mut conn, finished: false, isolation_level: None, read_only: false, obligation: None };
        let mut cursor = match transaction.query_cursor_params(&cx, "SELECT value FROM large_table", &[], PgCursorConfig::new(2, 128).unwrap()).await {
            Outcome::Ok(cursor) => cursor, other => panic!("{other:?}"),
        };
        start_request(&mut peer, "known", 2); assert_row(cursor.next(&cx).await, "one");
        let receipt = match cursor.close(&cx).await { Outcome::Ok(receipt) => receipt, other => panic!("{other:?}") };
        assert_eq!((receipt.rows_received(), receipt.rows_yielded()), (2, 1));
        assert!(!receipt.exhausted()); assert_eq!(receipt.command_tag(), None);
        close_request(&mut peer); no_request(&mut peer);
        assert_eq!(transaction.conn.inner.transaction_status, b'T'); assert!(!transaction.conn.inner.closed);
        send(&mut peer, b'C', b"ROLLBACK\0"); send(&mut peer, b'Z', b"I");
        assert!(matches!(transaction.rollback(&cx).await, Outcome::Ok(())));
        assert_eq!(read(&mut peer), (b'Q', b"ROLLBACK\0".to_vec()));
        assert!(!conn.inner.closed); assert!(!conn.in_transaction());
    }); }
}

#[test]
fn native_cursor_resolves_prepared_sql_on_current_connection_and_checks_types() {
    native(1, |cx| async move {
        let (mut conn, mut peer) = pair();
        let mut foreign = cached(&mut conn, "local-name", "SELECT $1::integer", &[oid::INT4]);
        foreign.name = "unrelated-foreign-name".to_string(); foreign.session_generation = 99;
        let wrong: f32 = 1.0;
        assert!(matches!(conn.query_cursor_prepared(&cx, &foreign, &[&wrong], PgCursorConfig::new(1, 128).unwrap()).await, Outcome::Err(PgError::Protocol(_))));
        assert!(matches!(conn.query_cursor_prepared(&cx, &foreign, &[], PgCursorConfig::new(1, 128).unwrap()).await, Outcome::Err(PgError::Protocol(_))));
        no_request(&mut peer); assert!(!conn.inner.closed);
        start_response(&mut peer); send(&mut peer, b'D', &row("7")); send(&mut peer, b'C', b"SELECT 1\0"); close_response(&mut peer, b'I');
        let value: i32 = 7;
        let mut cursor = match conn.query_cursor_prepared(&cx, &foreign, &[&value], PgCursorConfig::new(1, 128).unwrap()).await {
            Outcome::Ok(cursor) => cursor, other => panic!("{other:?}"),
        };
        start_request(&mut peer, "local-name", 1); assert_row(cursor.next(&cx).await, "7");
        assert!(matches!(cursor.next(&cx).await, Outcome::Ok(None))); close_request(&mut peer);
    });
}

#[test]
fn native_cursor_prepares_uncached_sql_and_caps_prepare_and_recovery_frames() {
    native(1, |cx| async move {
        for recovery in [false, true] {
            let (mut conn, mut peer) = pair();
            if recovery { send(&mut peer, b'E', b"SERROR\0C42601\0Msyntax\0\0"); }
            else { send(&mut peer, b'1', b""); }
            // Body deliberately never arrives. The bound must reject its header.
            peer.write_all(&[b'T', 0, 0, 0, 69]).unwrap();
            assert!(matches!(conn.query_cursor_params(&cx, "SELECT new_query", &[], PgCursorConfig::new(1, 64).unwrap()).await,
                Outcome::Err(PgError::Protocol(ref error)) if error.contains("maximum is 64")));
            assert!(conn.inner.closed); assert!(conn.inner.backend_frame.body.is_empty());
            assert_eq!(read(&mut peer).0, b'P'); assert_eq!(read(&mut peer).0, b'D'); assert_eq!(read(&mut peer).0, b'S'); eof(&mut peer);
        }
        let (mut conn, mut peer) = pair();
        send(&mut peer, b'1', b""); send(&mut peer, b't', &0i16.to_be_bytes());
        send(&mut peer, b'T', &description()); send(&mut peer, b'Z', b"I");
        start_response(&mut peer); send(&mut peer, b'C', b"SELECT 0\0"); close_response(&mut peer, b'I');
        let mut cursor = match conn.query_cursor_params(&cx, "SELECT value WHERE false", &[], PgCursorConfig::new(2, 128).unwrap()).await {
            Outcome::Ok(cursor) => cursor, other => panic!("{other:?}"),
        };
        let (kind, body) = read(&mut peer); assert_eq!(kind, b'P');
        let sql = b"SELECT value WHERE false";
        assert!(body.windows(sql.len()).any(|window| window == sql));
        assert_eq!(read(&mut peer).0, b'D'); assert_eq!(read(&mut peer).0, b'S');
        start_request(&mut peer, "__asupersync_s0", 2);
        assert!(matches!(cursor.next(&cx).await, Outcome::Ok(None))); close_request(&mut peer);
        assert_eq!(cursor.completion().unwrap().rows_received(), 0);
    });
}

#[test]
fn native_cursor_server_error_sends_missing_sync_and_invalidates_stale_plan() {
    native(1, |cx| async move {
        let (mut conn, mut peer) = pair(); cached(&mut conn, "known", "SELECT value", &[]);
        start_response(&mut peer); send(&mut peer, b'D', &row("one"));
        send(&mut peer, b'E', b"SERROR\0C26000\0Mmissing statement\0\0"); send(&mut peer, b'Z', b"I");
        let mut cursor = match conn.query_cursor_params(&cx, "SELECT value", &[], PgCursorConfig::new(2, 128).unwrap()).await {
            Outcome::Ok(cursor) => cursor, other => panic!("{other:?}"),
        };
        start_request(&mut peer, "known", 2); assert_row(cursor.next(&cx).await, "one");
        assert!(matches!(cursor.next(&cx).await, Outcome::Err(PgError::Server { code, .. }) if code == "26000"));
        assert_eq!(read(&mut peer), (b'S', vec![])); no_request(&mut peer); assert!(cursor.completion().is_none());
        drop(cursor); assert!(!conn.inner.closed); assert_eq!(conn.inner.prepared_cache.len(), 0);
        assert_eq!(conn.inner.deallocate_retry_queue.front().map(String::as_str), Some("known"));
    });
}

#[test]
fn native_cursor_refuses_hostile_sequence_batch_and_frame_bounds() {
    native(1, |cx| async move {
        let cases = [
            vec![frame(b'D', &row("before-bind"))],
            vec![frame(b'2', b"extra")],
            vec![frame(b'2', b""), frame(b'n', b""), frame(b'D', &row("no-columns"))],
            vec![frame(b'2', b""), frame(b'T', &description()), frame(b's', b"")],
            vec![frame(b'2', b""), frame(b'T', &description()), frame(b'D', &row("one")), frame(b'D', &row("excess"))],
            vec![frame(b'2', b""), frame(b'T', &description()), frame(b'Z', b"I")],
            vec![frame(b'2', b""), frame(b'T', &description()), frame(b'C', b"SELECT 0")],
            vec![frame(b'2', b""), frame(b'T', &description()), frame(b'C', b"SELECT 0\0extra")],
            vec![frame(b'2', b""), frame(b'T', &description()), vec![b'D', 0, 0, 0, 133]],
        ];
        for (case, frames) in cases.into_iter().enumerate() {
            let (mut conn, mut peer) = pair(); cached(&mut conn, "known", "SELECT value", &[]);
            for frame in frames { peer.write_all(&frame).unwrap(); }
            let mut cursor = match conn.query_cursor_params(&cx, "SELECT value", &[], PgCursorConfig::new(1, 128).unwrap()).await {
                Outcome::Ok(cursor) => cursor, other => panic!("{case}: {other:?}"),
            };
            start_request(&mut peer, "known", 1);
            let mut result = cursor.next(&cx).await;
            if matches!(result, Outcome::Ok(Some(_))) { result = cursor.next(&cx).await; }
            assert!(matches!(result, Outcome::Err(PgError::Protocol(_))), "case={case}: {result:?}");
            assert!(cursor.completion().is_none()); drop(cursor); assert!(conn.inner.closed); eof(&mut peer);
        }
    });
}

#[test]
fn native_cursor_terminal_responses_require_a_single_complete_sync_exchange() {
    native(1, |cx| async move {
        let (mut conn, mut peer) = pair(); cached(&mut conn, "empty", "", &[]);
        send(&mut peer, b'2', b""); send(&mut peer, b'n', b""); send(&mut peer, b'I', b"");
        close_response(&mut peer, b'I');
        let mut cursor = match conn.query_cursor_params(&cx, "", &[], PgCursorConfig::new(1, 128).unwrap()).await {
            Outcome::Ok(cursor) => cursor, other => panic!("{other:?}"),
        };
        start_request(&mut peer, "empty", 1); assert!(matches!(cursor.next(&cx).await, Outcome::Ok(None)));
        close_request(&mut peer); no_request(&mut peer);
        let receipt = cursor.completion().unwrap();
        assert!(receipt.exhausted()); assert_eq!(receipt.rows_received(), 0); assert_eq!(receipt.command_tag(), None);
        drop(cursor); assert!(!conn.inner.closed);

        let endings = [
            vec![frame(b'E', b"SERROR\0C34000\0Mmissing portal\0\0"), frame(b'Z', b"I")],
            vec![frame(b'Z', b"I")],
            vec![frame(b'3', b"extra")],
            vec![frame(b'3', b""), frame(b'Z', b"X")],
            vec![frame(b'3', b""), frame(b'3', b"")],
        ];
        for (case, frames) in endings.into_iter().enumerate() {
            let (mut conn, mut peer) = pair(); cached(&mut conn, "known", "SELECT value", &[]);
            start_response(&mut peer); send(&mut peer, b'C', b"SELECT 0\0");
            for frame in frames { peer.write_all(&frame).unwrap(); }
            let mut cursor = match conn.query_cursor_params(&cx, "SELECT value", &[], PgCursorConfig::new(1, 128).unwrap()).await {
                Outcome::Ok(cursor) => cursor, other => panic!("{other:?}"),
            };
            start_request(&mut peer, "known", 1);
            let result = cursor.next(&cx).await; assert!(cursor.completion().is_none());
            close_request(&mut peer); drop(cursor);
            if case == 0 {
                assert!(matches!(result, Outcome::Err(PgError::Server { code, .. }) if code == "34000"));
                assert!(!conn.inner.closed); no_request(&mut peer); // No second Sync after Close's Sync.
            } else {
                assert!(matches!(result, Outcome::Err(PgError::Protocol(_))), "{case}: {result:?}");
                assert!(conn.inner.closed); eof(&mut peer);
            }
        }
    });
}

#[test]
fn native_abandoned_partial_cursor_reads_and_close_never_reuse_the_socket() {
    for workers in [1, 2] { native(workers, |cx| async move {
        for prefix in [&[b'D', 0, 0][..], &[b'D', 0, 0, 0, 11, 0][..]] {
            let (mut conn, mut peer) = pair(); cached(&mut conn, "known", "SELECT value", &[]);
            let progress = Arc::new(AtomicUsize::new(usize::MAX));
            conn.inner.backend_frame.pending_progress = Some(Arc::clone(&progress));
            start_response(&mut peer); peer.write_all(prefix).unwrap();
            let mut cursor = match conn.query_cursor_params(&cx, "SELECT value", &[], PgCursorConfig::new(1, 128).unwrap()).await {
                Outcome::Ok(cursor) => cursor, other => panic!("{other:?}"),
            };
            start_request(&mut peer, "known", 1);
            let mut next = Box::pin(cursor.next(&cx));
            poll_fn(|task| {
                assert!(next.as_mut().poll(task).is_pending());
                if progress.load(Ordering::Acquire) == prefix.len() { Poll::Ready(()) } else { Poll::Pending }
            }).await;
            drop(next); assert_eq!(cursor.phase, Phase::Failed);
            assert!(matches!(cursor.next(&cx).await, Outcome::Err(PgError::ConnectionClosed)));
            drop(cursor); assert!(conn.inner.closed); eof(&mut peer);
        }
        let (mut conn, mut peer) = pair(); cached(&mut conn, "known", "SELECT value", &[]);
        let progress = Arc::new(AtomicUsize::new(usize::MAX)); conn.inner.backend_frame.pending_progress = Some(Arc::clone(&progress));
        start_response(&mut peer); send(&mut peer, b'D', &row("one")); send(&mut peer, b's', b"");
        send(&mut peer, b'3', b""); peer.write_all(&[b'Z', 0, 0, 0, 5]).unwrap();
        let mut cursor = match conn.query_cursor_params(&cx, "SELECT value", &[], PgCursorConfig::new(1, 128).unwrap()).await {
            Outcome::Ok(cursor) => cursor, other => panic!("{other:?}"),
        };
        start_request(&mut peer, "known", 1); assert_row(cursor.next(&cx).await, "one");
        let mut close = Box::pin(cursor.close(&cx));
        poll_fn(|task| {
            assert!(close.as_mut().poll(task).is_pending());
            if progress.load(Ordering::Acquire) == 5 { Poll::Ready(()) } else { Poll::Pending }
        }).await;
        drop(close); close_request(&mut peer); assert!(conn.inner.closed); eof(&mut peer);
    }); }
}

#[test]
fn native_abandoned_cursor_open_closes_partial_preparation_frames() {
    for workers in [1, 2] { native(workers, |cx| async move {
        for prefix in [&[b'T', 0, 0][..], &[b'T', 0, 0, 0, 8, 0][..]] {
            let (mut conn, mut peer) = pair();
            let progress = Arc::new(AtomicUsize::new(usize::MAX));
            conn.inner.backend_frame.pending_progress = Some(Arc::clone(&progress));
            send(&mut peer, b'1', b""); send(&mut peer, b't', &0i16.to_be_bytes());
            peer.write_all(prefix).unwrap();
            let mut opening = Box::pin(conn.query_cursor_params(
                &cx, "SELECT uncached", &[], PgCursorConfig::new(1, 128).unwrap(),
            ));
            poll_fn(|task| {
                assert!(opening.as_mut().poll(task).is_pending());
                if progress.load(Ordering::Acquire) == prefix.len() { Poll::Ready(()) } else { Poll::Pending }
            }).await;
            // No PgCursor exists yet: the opening future owns this obligation.
            drop(opening); assert!(conn.inner.closed);
            assert_eq!(read(&mut peer).0, b'P'); assert_eq!(read(&mut peer).0, b'D');
            assert_eq!(read(&mut peer), (b'S', vec![])); eof(&mut peer);
        }
    }); }
}

#[test]
fn native_parked_cursor_cancel_reaches_backend_before_socket_close() {
    for workers in [1, 2] { native(workers, |_native_cx| async move {
        for prefix in [&[][..], &[b'D', 0, 0][..], &[b'D', 0, 0, 0, 11, 0][..]] {
            let cx = Cx::for_testing(); let canceller = cx.clone();
            let (mut conn, mut peer) = pair(); cached(&mut conn, "known", "SELECT value", &[]);
            conn.inner.process_id = 42; conn.inner.secret_key = 1337;
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap(); listener.set_nonblocking(true).unwrap();
            conn.inner.cancel_target = CancelTarget { host: "127.0.0.1".to_string(), port: addr.port(), connect_timeout: Duration::from_millis(500) };
            let progress = Arc::new(AtomicUsize::new(usize::MAX)); conn.inner.backend_frame.pending_progress = Some(Arc::clone(&progress));
            start_response(&mut peer); peer.write_all(prefix).unwrap();
            let mut cursor = match conn.query_cursor_params(&cx, "SELECT value", &[], PgCursorConfig::new(1, 128).unwrap()).await {
                Outcome::Ok(cursor) => cursor, other => panic!("{other:?}"),
            };
            start_request(&mut peer, "known", 1);
            let (parked_tx, parked_rx) = std::sync::mpsc::sync_channel(1);
            let backend = std::thread::spawn(move || {
                parked_rx.recv_timeout(Duration::from_secs(2)).expect("actual partial-frame Pending witness");
                canceller.cancel_with(CancelKind::User, Some("cancel bounded cursor"));
                let deadline = Instant::now() + Duration::from_secs(2);
                let mut cancel = loop {
                    match listener.accept() {
                        Ok((socket, _)) => break socket,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(Instant::now() < deadline, "CancelRequest must reach backend");
                            std::thread::sleep(Duration::from_millis(1));
                        }
                        Err(error) => panic!("cancel accept: {error}"),
                    }
                };
                cancel.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                let mut message = [0; 16]; cancel.read_exact(&mut message).unwrap();
                let expected = [16i32, 80_877_102, 42, 1337].into_iter().flat_map(i32::to_be_bytes).collect::<Vec<_>>();
                assert_eq!(message.as_slice(), expected); eof(&mut peer);
            });
            let mut next = Box::pin(cursor.next(&cx)); let mut witness = Some(parked_tx);
            let result = poll_fn(|task| {
                let result = next.as_mut().poll(task);
                if result.is_pending() && progress.load(Ordering::Acquire) == prefix.len()
                    && let Some(witness) = witness.take() { witness.send(()).unwrap(); }
                result
            }).await;
            assert!(matches!(result, Outcome::Cancelled(ref reason) if reason.kind == CancelKind::User
                && reason.message.as_deref() == Some("cancel bounded cursor")));
            drop(next); drop(cursor); backend.join().unwrap(); assert!(conn.inner.closed);
        }
    }); }
}
