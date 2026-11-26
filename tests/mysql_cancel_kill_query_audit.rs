//! Native MySQL cancellation: actual parked COM_QUERY, separately authenticated
//! KILL QUERY, bounded silent cleanup peers, and streaming ownership retirement.
#![cfg(all(
    feature = "mysql",
    feature = "test-internals",
    not(target_arch = "wasm32")
))]
// An integration test is its own crate and does not inherit `src/lib.rs`'s
// `recursion_limit`. Proving `Send` for its async chains exceeds rustc's default
// depth, which the future-incompatible `recursion_depth_exceeding_limit` lint
// (rust-lang #159228) will turn into a hard error.
#![recursion_limit = "256"]

use asupersync::cx::Cx;
use asupersync::database::mysql::{MySqlConnection, MySqlError, test_active_mysql_drop_kills};
use asupersync::runtime::{RootDrainOutcome, RuntimeBuilder};
use asupersync::types::{Budget, CancelReason, Outcome};
use std::future::{Future, poll_fn};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::task::Poll;
use std::thread;
use std::time::{Duration, Instant};

static SERIAL: Mutex<()> = Mutex::new(());
const OK: &[u8] = &[0, 0, 0, 2, 0, 0, 0];

#[derive(Clone, Copy, Debug)]
enum Operation {
    Collect,
    Execute,
    StreamHeader,
    StreamRows,
    Prepare,
    PrepareMetadata,
    PreparedCollect,
    PreparedExecute,
    PreparedRows,
    PreparedStreamHeader,
    PreparedStreamRows,
    Ping,
}

#[derive(Clone, Copy, Debug)]
enum CancelSource {
    SameContext,
    Caller,
    Owner,
}
#[derive(Clone, Copy, Debug)]
enum KillPeer {
    Replies,
    SilentGreeting,
    SilentAuthentication,
    SilentReply,
}

#[derive(Clone, Copy, Debug)]
enum ExplicitCancellation {
    Acknowledged,
    Rejected,
    Cancelled,
    Abandoned,
}

#[test]
fn mysql_explicit_cancel_retires_only_acknowledged_kill_ownership() {
    let _serial = SERIAL.lock().unwrap();
    for workers in [0, 2] {
        for completion in [
            ExplicitCancellation::Acknowledged,
            ExplicitCancellation::Rejected,
            ExplicitCancellation::Cancelled,
            ExplicitCancellation::Abandoned,
        ] {
            explicit_cancellation_case(workers, completion);
        }
    }
}

#[test]
fn mysql_cancel_sends_kill_query_audit() {
    let _serial = SERIAL.lock().unwrap();
    for workers in [1, 2] {
        for cancel in [false, true] {
            for peer in [
                KillPeer::Replies,
                KillPeer::SilentGreeting,
                KillPeer::SilentAuthentication,
                KillPeer::SilentReply,
            ] {
                cancellation_case(workers, cancel, Operation::Collect, peer);
            }
        }
    }
}

#[test]
fn mysql_streaming_drop_and_cancel_retain_kill_ownership() {
    let _serial = SERIAL.lock().unwrap();
    for workers in [1, 2] {
        for cancel in [false, true] {
            for operation in [Operation::StreamHeader, Operation::StreamRows] {
                cancellation_case(workers, cancel, operation, KillPeer::Replies);
            }
        }
    }
}

#[test]
fn mysql_prepared_streaming_drop_and_cancel_retain_kill_ownership() {
    let _serial = SERIAL.lock().unwrap();
    for workers in [0, 2] {
        for cancel in [false, true] {
            for operation in [
                Operation::PreparedStreamHeader,
                Operation::PreparedStreamRows,
            ] {
                cancellation_case(workers, cancel, operation, KillPeer::Replies);
            }
        }
    }
}

#[test]
fn mysql_distinct_caller_and_owner_cancel_parked_protocol_exchanges() {
    let _serial = SERIAL.lock().unwrap();
    // Zero denotes the actual current-thread runtime, driven by block_on.
    // A controller thread observes the parked witness before requesting cancel.
    for workers in [0, 2] {
        for source in [CancelSource::Caller, CancelSource::Owner] {
            for operation in [
                Operation::Collect,
                Operation::Execute,
                Operation::StreamHeader,
                Operation::StreamRows,
                Operation::Prepare,
                Operation::PrepareMetadata,
                Operation::PreparedCollect,
                Operation::PreparedExecute,
                Operation::PreparedRows,
                Operation::PreparedStreamHeader,
                Operation::PreparedStreamRows,
                Operation::Ping,
            ] {
                cancellation_case_with_source(workers, true, operation, KillPeer::Replies, source);
            }
        }
    }
}

#[test]
fn mysql_streaming_terminator_restores_reuse_without_spurious_kill() {
    let _serial = SERIAL.lock().unwrap();
    for workers in [1, 2] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let (dropped_tx, dropped_rx) = mpsc::channel();
        let server = thread::spawn(move || {
            let mut socket = accept(&listener);
            authenticate(&mut socket, 42, true);
            assert_eq!(read_packet(&mut socket), (0, b"\x03SELECT 7".to_vec()));
            stream_header(&mut socket);
            write_packet(&mut socket, 4, b"\x017");
            write_packet(&mut socket, 5, &[0xfe, 0, 0, 2, 0]);
            assert_eq!(read_packet(&mut socket), (0, vec![0x0e]));
            write_packet(&mut socket, 1, OK);
            assert_eq!(read_packet(&mut socket), (0, vec![1]));
            assert_eof(&mut socket);
            dropped_rx.recv_timeout(Duration::from_secs(3)).unwrap();
            let deadline = Instant::now() + Duration::from_secs(2);
            while test_active_mysql_drop_kills() != 0 {
                assert!(
                    Instant::now() < deadline,
                    "cleanup thread permit retained after completed stream"
                );
                thread::sleep(Duration::from_millis(1));
            }
            assert!(
                matches!(listener.accept(), Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock)
            );
        });
        let runtime = RuntimeBuilder::new()
            .worker_threads(workers)
            .build()
            .unwrap();
        let join = runtime.handle().spawn(async move {
            let cx = Cx::current().unwrap();
            let mut connection =
                match MySqlConnection::connect(&cx, &format!("mysql://test:test@{address}/test"))
                    .await
                {
                    Outcome::Ok(connection) => connection,
                    other => panic!("connect: {other:?}"),
                };
            {
                let mut stream = match connection.query_stream(&cx, "SELECT 7").await {
                    Outcome::Ok(stream) => stream,
                    Outcome::Err(error) => panic!("stream: {error:?}"),
                    Outcome::Cancelled(reason) => panic!("stream cancelled: {reason:?}"),
                    Outcome::Panicked(_) => panic!("stream panicked"),
                };
                let row = match stream.next(&cx).await {
                    Outcome::Ok(Some(row)) => row,
                    other => panic!("row: {other:?}"),
                };
                assert_eq!(row.get_i32("value").unwrap(), 7);
                assert!(matches!(stream.next(&cx).await, Outcome::Ok(None)));
                assert!(matches!(stream.next(&cx).await, Outcome::Ok(None)));
            }
            assert!(matches!(connection.ping(&cx).await, Outcome::Ok(())));
            connection.close().await.unwrap();
            drop(connection);
            dropped_tx.send(()).unwrap();
        });
        runtime.block_on(join);
        server.join().unwrap();
        assert_eq!(
            runtime.shutdown_drained(Duration::from_secs(2)).outcome,
            RootDrainOutcome::Quiescent
        );
        assert_eq!(test_active_mysql_drop_kills(), 0);
        eprintln!("event=mysql_stream_finished workers={workers} row=7 reused=true kill_threads=0");
    }
}

#[derive(Clone, Copy, Debug)]
enum RowStreamCompletion {
    Drain,
    Deadline,
    AbortAfterMalformed,
    FinishAfterMalformed,
}

#[test]
fn mysql_row_stream_finish_drains_text_and_prepared_replies() {
    let _serial = SERIAL.lock().unwrap();
    for workers in [0, 2] {
        for prepared in [false, true] {
            row_stream_completion_case(workers, prepared, RowStreamCompletion::Drain);
        }
    }
}

#[test]
fn mysql_row_stream_finish_deadline_drains_kill_ownership() {
    let _serial = SERIAL.lock().unwrap();
    for workers in [0, 2] {
        for prepared in [false, true] {
            row_stream_completion_case(workers, prepared, RowStreamCompletion::Deadline);
        }
    }
}

#[test]
fn mysql_row_stream_explicit_cleanup_retires_failed_streams() {
    let _serial = SERIAL.lock().unwrap();
    for workers in [0, 2] {
        for prepared in [false, true] {
            for completion in [
                RowStreamCompletion::AbortAfterMalformed,
                RowStreamCompletion::FinishAfterMalformed,
            ] {
                row_stream_completion_case(workers, prepared, completion);
            }
        }
    }
}

fn row_stream_completion_case(workers: usize, prepared: bool, completion: RowStreamCompletion) {
    assert_eq!(test_active_mysql_drop_kills(), 0);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let closed = Arc::new(asupersync::sync::Notify::new());
    let peer_closed = Arc::clone(&closed);
    let (dropped_tx, dropped_rx) = mpsc::channel();
    let server = thread::spawn(move || {
        let mut main = accept(&listener);
        authenticate(&mut main, 42, true);
        if prepared {
            assert_eq!(
                read_packet(&mut main),
                (0, b"\x16SELECT 7 UNION ALL SELECT 8".to_vec())
            );
            write_packet(&mut main, 1, &[0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            assert_eq!(
                read_packet(&mut main),
                (0, vec![0x17, 7, 0, 0, 0, 0, 1, 0, 0, 0])
            );
        } else {
            assert_eq!(
                read_packet(&mut main),
                (0, b"\x03SELECT 7 UNION ALL SELECT 8".to_vec())
            );
        }
        stream_header(&mut main);
        let first_row: &[u8] = if prepared {
            &[0, 0, 7, 0, 0, 0]
        } else {
            b"\x017"
        };
        write_packet(&mut main, 4, first_row);
        match completion {
            RowStreamCompletion::Drain => {
                let second_row: &[u8] = if prepared {
                    &[0, 0, 8, 0, 0, 0]
                } else {
                    b"\x018"
                };
                write_packet(&mut main, 5, second_row);
                write_packet(&mut main, 6, &[0xfe, 0, 0, 2, 0]);
                // Only finish consumes the second row and terminal packet.
                // A reused connection must read this fresh ping response.
                assert_eq!(read_packet(&mut main), (0, vec![0x0e]));
                write_packet(&mut main, 1, OK);
                assert_eq!(read_packet(&mut main), (0, vec![1]));
            }
            RowStreamCompletion::Deadline
            | RowStreamCompletion::AbortAfterMalformed
            | RowStreamCompletion::FinishAfterMalformed => {
                if !matches!(completion, RowStreamCompletion::Deadline) {
                    // Truncated text length prefix, or invalid binary header.
                    // No terminal packet follows this malformed row.
                    write_packet(&mut main, 5, &[0xfc, 1]);
                }
                // The deadline case deliberately stalls after the first row.
                // Explicit completion must finish this KILL before returning;
                // the original connection is retained until both peers close.
                let mut killer = accept(&listener);
                authenticate(&mut killer, 43, true);
                assert_eq!(
                    read_packet(&mut killer),
                    (0, b"\x03KILL QUERY 42".to_vec())
                );
                write_packet(&mut killer, 1, OK);
                assert_eof(&mut killer);
            }
        }
        assert_eof(&mut main);
        peer_closed.notify_one();
        dropped_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        // Drop acquires its permit synchronously. Drain every acquired permit
        // before asserting that explicit cleanup did not schedule another KILL.
        let deadline = Instant::now() + Duration::from_secs(2);
        while test_active_mysql_drop_kills() != 0 {
            assert!(
                Instant::now() < deadline,
                "completion={completion:?}: cleanup thread permit retained"
            );
            thread::park_timeout(Duration::from_millis(1));
        }
        assert!(
            matches!(listener.accept(), Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock),
            "completion={completion:?}: unexpected extra KILL connection"
        );
    });
    let builder = if workers == 0 {
        RuntimeBuilder::current_thread()
    } else {
        RuntimeBuilder::multi_thread().worker_threads(workers)
    };
    let runtime = builder.build().unwrap();
    let join = runtime.handle().spawn(async move {
        let cx = Cx::current().unwrap();
        asupersync::time::timeout(cx.now(), Duration::from_secs(10), async {
            let mut connection = match MySqlConnection::connect(
                &cx,
                &format!("mysql://test:test@{address}/test"),
            )
            .await
            {
                Outcome::Ok(connection) => connection,
                other => panic!("main connect: {other:?}"),
            };
            let started = if prepared {
                connection
                    .query_stream_params(&cx, "SELECT 7 UNION ALL SELECT 8", &[])
                    .await
            } else {
                connection
                    .query_stream(&cx, "SELECT 7 UNION ALL SELECT 8")
                    .await
            };
            let mut stream = match started {
                Outcome::Ok(stream) => stream,
                Outcome::Err(error) => panic!("stream: {error:?}"),
                Outcome::Cancelled(reason) => panic!("stream cancelled: {reason:?}"),
                Outcome::Panicked(_) => panic!("stream panicked"),
            };
            let row = match stream.next(&cx).await {
                Outcome::Ok(Some(row)) => row,
                other => panic!("first row: {other:?}"),
            };
            assert_eq!(row.get_i32("value").unwrap(), 7);
            assert_eq!(stream.row_count(), 1);
            if matches!(
                completion,
                RowStreamCompletion::AbortAfterMalformed | RowStreamCompletion::FinishAfterMalformed
            ) {
                let result = stream.next(&cx).await;
                assert!(
                    matches!(
                        &result,
                        Outcome::Err(MySqlError::InvalidPacket(_) | MySqlError::Protocol(_))
                    ),
                    "malformed row: {result:?}"
                );
                // A failed stream stops yielding rows, but its outstanding
                // query still needs explicit cleanup rather than a no-op.
                assert!(matches!(stream.next(&cx).await, Outcome::Ok(None)));
            }
            match completion {
                RowStreamCompletion::Drain => {
                    let result = stream.finish(&cx, Duration::from_secs(2)).await;
                    assert!(matches!(&result, Outcome::Ok(())), "finish: {result:?}");
                }
                RowStreamCompletion::Deadline => {
                    let mut finish = Box::pin(stream.finish(&cx, Duration::from_millis(100)));
                    // Observe an actually pending drain before its deadline.
                    // No wall-clock sleep guesses when a read has parked.
                    poll_fn(|task_cx| {
                        let state = finish.as_mut().poll(task_cx);
                        assert!(state.is_pending(), "drain did not park: {state:?}");
                        Poll::Ready(())
                    })
                    .await;
                    let result = finish.await;
                    assert!(
                        matches!(
                            &result,
                            Outcome::Err(MySqlError::Io(error))
                                if error.kind() == std::io::ErrorKind::TimedOut
                        ),
                        "finish deadline: {result:?}"
                    );
                }
                RowStreamCompletion::AbortAfterMalformed => stream.abort(&cx).await,
                RowStreamCompletion::FinishAfterMalformed => {
                    let result = stream.finish(&cx, Duration::from_secs(2)).await;
                    assert!(
                        matches!(&result, Outcome::Err(MySqlError::ConnectionClosed)),
                        "finish after malformed row: {result:?}"
                    );
                }
            }
            if matches!(completion, RowStreamCompletion::Drain) {
                assert!(matches!(connection.ping(&cx).await, Outcome::Ok(())));
                connection.close().await.unwrap();
            } else {
                assert!(matches!(
                    connection.ping(&cx).await,
                    Outcome::Err(MySqlError::ConnectionClosed)
                ));
            }
            // Observe transport closure before Drop can perform fallback
            // cleanup, proving that finish/abort completed it themselves.
            closed.notified().await;
            assert_eq!(test_active_mysql_drop_kills(), 0);
            drop(connection);
            dropped_tx.send(()).unwrap();
        })
        .await
        .expect("bounded MySQL row-stream completion journey");
    });
    runtime.block_on(join);
    server.join().unwrap();
    let report = runtime.shutdown_drained(Duration::from_secs(2));
    assert_eq!(report.outcome, RootDrainOutcome::Quiescent, "{report:?}");
    assert_eq!(test_active_mysql_drop_kills(), 0);
    eprintln!(
        "event=mysql_row_stream_completion workers={workers} prepared={prepared} \
         completion={completion:?} transport_closed=true cleanup_threads=0"
    );
}

fn write_packet(stream: &mut impl Write, sequence: u8, payload: &[u8]) {
    let length = u32::try_from(payload.len()).unwrap().to_le_bytes();
    stream
        .write_all(&[length[0], length[1], length[2], sequence])
        .unwrap();
    stream.write_all(payload).unwrap();
    stream.flush().unwrap();
}

fn read_packet(stream: &mut impl Read) -> (u8, Vec<u8>) {
    let mut header = [0; 4];
    stream.read_exact(&mut header).unwrap();
    let length =
        usize::from(header[0]) | (usize::from(header[1]) << 8) | (usize::from(header[2]) << 16);
    assert!(length < 65536);
    let mut payload = vec![0; length];
    stream.read_exact(&mut payload).unwrap();
    (header[3], payload)
}

fn accept(listener: &TcpListener) -> std::net::TcpStream {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        match listener.accept() {
            Ok((socket, _)) => {
                socket
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                socket
                    .set_write_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                return socket;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    Instant::now() < deadline,
                    "expected a separate KILL connection"
                );
                thread::sleep(Duration::from_millis(1));
            }
            Err(error) => panic!("accept: {error}"),
        }
    }
}

fn authenticate(socket: &mut std::net::TcpStream, id: u32, finish: bool) {
    socket.write_all(&create_handshake_v10_packet(id)).unwrap();
    let (sequence, response) = read_packet(socket);
    assert_eq!(sequence, 1);
    assert!(response.len() > 32);
    if finish {
        write_packet(socket, 2, OK);
    }
}

fn assert_eof(socket: &mut std::net::TcpStream) {
    let mut byte = [0];
    match socket.read(&mut byte) {
        Ok(0) => {}
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
        other => panic!("cleanup must close the socket: {other:?}"),
    }
}

fn stream_header(socket: &mut std::net::TcpStream) {
    write_packet(socket, 1, &[1]);
    let mut column = Vec::new();
    for part in ["def", "", "", "", "value", ""] {
        column.push(u8::try_from(part.len()).unwrap());
        column.extend_from_slice(part.as_bytes());
    }
    column.extend_from_slice(&[12, 33, 0, 11, 0, 0, 0, 3, 0, 0, 0, 0, 0]);
    write_packet(socket, 2, &column);
    write_packet(socket, 3, &[0xfe, 0, 0, 2, 0]);
}

fn explicit_cancellation_case(workers: usize, completion: ExplicitCancellation) {
    assert_eq!(test_active_mysql_drop_kills(), 0);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let query_seen = Arc::new(asupersync::sync::Notify::new());
    let peer_query_seen = Arc::clone(&query_seen);
    let kill_seen = Arc::new(asupersync::sync::Notify::new());
    let peer_kill_seen = Arc::clone(&kill_seen);
    let (dropped_tx, dropped_rx) = mpsc::channel();
    let server = thread::spawn(move || {
        let mut main = accept(&listener);
        authenticate(&mut main, 42, true);
        assert_eq!(
            read_packet(&mut main),
            (0, b"\x03SELECT SLEEP(30)".to_vec())
        );
        peer_query_seen.notify_one();

        let mut explicit = accept(&listener);
        authenticate(&mut explicit, 43, true);
        assert_eq!(
            read_packet(&mut explicit),
            (0, b"\x03KILL QUERY 42".to_vec())
        );
        peer_kill_seen.notify_one();
        match completion {
            ExplicitCancellation::Acknowledged => write_packet(&mut explicit, 1, OK),
            ExplicitCancellation::Rejected => {
                // ER_KILL_DENIED_ERROR (1095), with a protocol-4.1 SQLSTATE.
                write_packet(
                    &mut explicit,
                    1,
                    b"\xff\x47\x04#HY000KILL denied by audit peer",
                );
            }
            ExplicitCancellation::Cancelled | ExplicitCancellation::Abandoned => {
                // Withhold the final reply until the client cancels or drops
                // this actually pending, already transmitted KILL exchange.
            }
        }
        assert_eof(&mut explicit);
        if !matches!(completion, ExplicitCancellation::Acknowledged) {
            let mut fallback = accept(&listener);
            authenticate(&mut fallback, 44, true);
            assert_eq!(
                read_packet(&mut fallback),
                (0, b"\x03KILL QUERY 42".to_vec())
            );
            write_packet(&mut fallback, 1, OK);
            assert_eof(&mut fallback);
        }
        assert_eof(&mut main);
        // Drop acquires any cleanup permit synchronously. Waiting for its
        // completion marker and then every permit prevents a delayed duplicate
        // connection from escaping the negative wire assertion.
        dropped_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while test_active_mysql_drop_kills() != 0 {
            assert!(
                Instant::now() < deadline,
                "explicit cancellation retained a cleanup thread"
            );
            thread::park_timeout(Duration::from_millis(1));
        }
        assert!(
            matches!(listener.accept(), Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock),
            "completion={completion:?}: unexpected extra KILL connection"
        );
    });
    let builder = if workers == 0 {
        RuntimeBuilder::current_thread()
    } else {
        RuntimeBuilder::multi_thread().worker_threads(workers)
    };
    let runtime = builder.build().unwrap();
    let cleanup_cx = runtime.request_cx_with_budget(Budget::INFINITE);
    let join = runtime.handle().spawn(async move {
        let cx = Cx::current().unwrap();
        asupersync::time::timeout(cx.now(), Duration::from_secs(10), async {
            let mut connection = match MySqlConnection::connect(
                &cx,
                &format!("mysql://test:test@{address}/test"),
            )
            .await
            {
                Outcome::Ok(connection) => connection,
                other => panic!("main connect: {other:?}"),
            };
            let mut query = Box::pin(connection.query_static_sql(&cx, "SELECT SLEEP(30)"));
            let observed = query_seen.notified();
            let mut observed = std::pin::pin!(observed);
            poll_fn(|task_cx| {
                assert!(query.as_mut().poll(task_cx).is_pending());
                observed.as_mut().poll(task_cx)
            })
            .await;
            drop(query);

            let mut cancellation = Box::pin(connection.cancel_in_flight_query(&cleanup_cx));
            match completion {
                ExplicitCancellation::Acknowledged => cancellation.await.unwrap(),
                ExplicitCancellation::Rejected => assert!(matches!(
                    cancellation.await,
                    Err(MySqlError::Server { code: 1095, .. })
                )),
                ExplicitCancellation::Cancelled | ExplicitCancellation::Abandoned => {
                    let observed = kill_seen.notified();
                    let mut observed = std::pin::pin!(observed);
                    poll_fn(|task_cx| {
                        assert!(cancellation.as_mut().poll(task_cx).is_pending());
                        observed.as_mut().poll(task_cx)
                    })
                    .await;
                    if matches!(completion, ExplicitCancellation::Cancelled) {
                        let reason = CancelReason::user("explicit KILL cancellation");
                        cleanup_cx.cancel_with_reason(reason.clone());
                        assert!(
                            matches!(cancellation.await, Err(MySqlError::Cancelled(actual)) if actual == reason)
                        );
                        assert!(cx.checkpoint().is_ok());
                    } else {
                        drop(cancellation);
                    }
                }
            }
            // Successful KILL acknowledgement retires cleanup ownership, not
            // the abandoned original exchange's poison. A failed reuse must
            // also preserve the fallback for every unacknowledged case.
            assert!(matches!(
                connection.query_static_sql(&cx, "SELECT 1").await,
                Outcome::Err(MySqlError::ConnectionClosed)
            ));
            drop(connection);
            dropped_tx.send(()).unwrap();
        })
        .await
        .expect("bounded explicit MySQL cancellation journey");
    });
    runtime.block_on(join);
    server.join().unwrap();
    let report = runtime.shutdown_drained(Duration::from_secs(2));
    assert_eq!(report.outcome, RootDrainOutcome::Quiescent, "{report:?}");
    assert_eq!(test_active_mysql_drop_kills(), 0);
    eprintln!(
        "event=mysql_explicit_cancel workers={workers} completion={completion:?} \
         parked=true original_reuse=false cleanup_threads=0"
    );
}

fn cancellation_case(workers: usize, cancel: bool, operation: Operation, peer: KillPeer) {
    cancellation_case_with_source(workers, cancel, operation, peer, CancelSource::SameContext);
}

fn cancellation_case_with_source(
    workers: usize,
    cancel: bool,
    operation: Operation,
    peer: KillPeer,
    source: CancelSource,
) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let (query_tx, query_rx) = mpsc::channel();
    let (closed_tx, closed_rx) = mpsc::channel();
    let server = thread::spawn(move || {
        let mut main = accept(&listener);
        authenticate(&mut main, 42, true);
        if matches!(
            operation,
            Operation::PreparedCollect
                | Operation::PreparedExecute
                | Operation::PreparedRows
                | Operation::PreparedStreamHeader
                | Operation::PreparedStreamRows
        ) {
            assert_eq!(
                read_packet(&mut main),
                (0, b"\x16SELECT SLEEP(30)".to_vec())
            );
            write_packet(&mut main, 1, &[0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            assert_eq!(
                read_packet(&mut main),
                (0, vec![0x17, 7, 0, 0, 0, 0, 1, 0, 0, 0])
            );
        } else {
            let expected = match operation {
                Operation::Prepare | Operation::PrepareMetadata => b"\x16SELECT SLEEP(30)".to_vec(),
                Operation::Ping => vec![0x0e],
                _ => b"\x03SELECT SLEEP(30)".to_vec(),
            };
            assert_eq!(read_packet(&mut main), (0, expected));
        }
        if matches!(
            operation,
            Operation::StreamRows | Operation::PreparedRows | Operation::PreparedStreamRows
        ) {
            stream_header(&mut main);
        } else if matches!(operation, Operation::PrepareMetadata) {
            // One promised column, then silence while the client reads metadata.
            write_packet(&mut main, 1, &[0, 7, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        }
        query_tx.send(()).unwrap();
        if !matches!(operation, Operation::Ping) {
            let mut killer = accept(&listener);
            if !matches!(peer, KillPeer::SilentGreeting) {
                authenticate(
                    &mut killer,
                    43,
                    !matches!(peer, KillPeer::SilentAuthentication),
                );
                if !matches!(peer, KillPeer::SilentAuthentication) {
                    assert_eq!(read_packet(&mut killer), (0, b"\x03KILL QUERY 42".to_vec()));
                    if matches!(peer, KillPeer::Replies) {
                        write_packet(&mut killer, 1, OK);
                    }
                }
            }
            assert_eof(&mut killer);
        }
        assert_eof(&mut main);
        closed_tx.send(()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while test_active_mysql_drop_kills() != 0 {
            assert!(
                Instant::now() < deadline,
                "cleanup thread permit retained after loopback teardown"
            );
            thread::sleep(Duration::from_millis(1));
        }
        assert!(
            matches!(listener.accept(), Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock),
            "timed-out killer recursively spawned another killer"
        );
    });
    let builder = if workers == 0 {
        RuntimeBuilder::current_thread()
    } else {
        RuntimeBuilder::multi_thread().worker_threads(workers)
    };
    let builder = if matches!(
        operation,
        Operation::PreparedStreamHeader | Operation::PreparedStreamRows
    ) {
        builder.with_sharded_state(workers > 1)
    } else {
        builder
    };
    let runtime = builder.build().unwrap();
    let caller_cx = runtime.request_cx_with_budget(Budget::INFINITE);
    let expected_reason = match source {
        CancelSource::SameContext => CancelReason::user("mysql audit cancellation"),
        CancelSource::Caller => CancelReason::deadline()
            .with_message("explicit MySQL caller deadline")
            .with_cause(CancelReason::user("request ingress stopped")),
        CancelSource::Owner => CancelReason::shutdown()
            .with_message("MySQL owner stopped")
            .with_cause(CancelReason::user("runtime shutdown request")),
    };
    let task_expected_reason = expected_reason.clone();
    let (control_tx, control_rx) = mpsc::channel();
    let (parked_tx, parked_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let probe = Arc::new(AtomicBool::new(false));
    let release = Arc::new(AtomicBool::new(false));
    let retire = Arc::new(AtomicBool::new(false));
    let retirement = Arc::new(asupersync::sync::Notify::new());
    let task_probe = Arc::clone(&probe);
    let task_release = Arc::clone(&release);
    let task_retire = Arc::clone(&retire);
    let task_retirement = Arc::clone(&retirement);
    let join = runtime.handle().spawn(async move {
        let owner_cx = Cx::current().unwrap();
        let cx = if matches!(source, CancelSource::SameContext) {
            owner_cx.clone()
        } else {
            assert_ne!(caller_cx.task_id(), owner_cx.task_id());
            caller_cx
        };
        let url = format!("mysql://test:test@{address}/test");
        let mut connection = match MySqlConnection::connect(&cx, &url).await {
            Outcome::Ok(connection) => connection,
            other => panic!("main connect: {other:?}"),
        };
        let result = {
            let prepared_rows_started = AtomicBool::new(false);
            let mut execute = Box::pin(async {
                match operation {
                    Operation::Collect => connection
                        .query_static_sql(&cx, "SELECT SLEEP(30)")
                        .await
                        .map(|_| ()),
                    Operation::Execute => connection
                        .execute_static_sql(&cx, "SELECT SLEEP(30)")
                        .await
                        .map(|_| ()),
                    Operation::StreamHeader => connection
                        .query_stream(&cx, "SELECT SLEEP(30)")
                        .await
                        .map(|_| ()),
                    Operation::StreamRows => {
                        match connection.query_stream(&cx, "SELECT SLEEP(30)").await {
                            Outcome::Ok(mut stream) => stream.next(&cx).await.map(|_| ()),
                            Outcome::Err(error) => Outcome::Err(error),
                            Outcome::Cancelled(reason) => Outcome::Cancelled(reason),
                            Outcome::Panicked(payload) => Outcome::Panicked(payload),
                        }
                    }
                    Operation::Prepare | Operation::PrepareMetadata => connection
                        .prepare(&cx, "SELECT SLEEP(30)")
                        .await
                        .map(|_| ()),
                    Operation::PreparedCollect
                    | Operation::PreparedExecute
                    | Operation::PreparedRows
                    | Operation::PreparedStreamHeader
                    | Operation::PreparedStreamRows => {
                        let statement = match connection.prepare(&cx, "SELECT SLEEP(30)").await {
                            Outcome::Ok(statement) => statement,
                            other => panic!("initial prepare: {other:?}"),
                        };
                        if matches!(operation, Operation::PreparedExecute) {
                            connection.execute_prepared(&cx, &statement, &[]).await.map(|_| ())
                        } else if matches!(operation, Operation::PreparedStreamHeader) {
                            connection
                                .query_stream_prepared(&cx, &statement, &[])
                                .await
                                .map(|_| ())
                        } else if matches!(operation, Operation::PreparedStreamRows) {
                            match connection.query_stream_prepared(&cx, &statement, &[]).await {
                                Outcome::Ok(mut stream) => {
                                    prepared_rows_started.store(true, Ordering::Release);
                                    stream.next(&cx).await.map(|_| ())
                                }
                                Outcome::Err(error) => Outcome::Err(error),
                                Outcome::Cancelled(reason) => Outcome::Cancelled(reason),
                                Outcome::Panicked(payload) => Outcome::Panicked(payload),
                            }
                        } else {
                            connection.query_prepared(&cx, &statement, &[]).await.map(|_| ())
                        }
                    }
                    Operation::Ping => connection.ping(&cx).await,
                }
            });
            let mut control_tx = Some(control_tx);
            poll_fn(|task_cx| {
                if let Some(sender) = control_tx.take() {
                    sender
                        .send((cx.clone(), owner_cx.clone(), task_cx.waker().clone()))
                        .unwrap();
                }
                if !cancel && task_release.load(Ordering::Acquire) {
                    return Poll::Ready(None);
                }
                let result = execute.as_mut().poll(task_cx);
                if result.is_pending()
                    && (!matches!(operation, Operation::PreparedStreamRows)
                        || prepared_rows_started.load(Ordering::Acquire))
                    && task_probe.swap(false, Ordering::AcqRel)
                {
                    parked_tx.send(()).unwrap();
                }
                result.map(Some)
            })
            .await
        };
        if cancel {
            assert!(
                matches!(result, Some(Outcome::Cancelled(ref reason)) if reason == &task_expected_reason),
                "source={source:?} operation={operation:?} expected={task_expected_reason:?} actual={result:?}"
            );
            match source {
                CancelSource::Caller => assert!(owner_cx.checkpoint().is_ok()),
                CancelSource::Owner => assert!(cx.checkpoint().is_ok()),
                CancelSource::SameContext => {}
            }
            let live_cx = match source {
                CancelSource::Caller => Some(&owner_cx),
                CancelSource::Owner => Some(&cx),
                CancelSource::SameContext => None,
            };
            if let Some(live_cx) = live_cx {
                assert!(matches!(
                    connection.query_static_sql(live_cx, "SELECT 1").await,
                    Outcome::Err(MySqlError::ConnectionClosed)
                ));
            }
            done_tx.send(()).unwrap();
            // Retain the original connection until the server observes EOF:
            // cancellation's fallback must close it before eventual Drop.
            task_retirement
                .wait_until(|| task_retire.load(Ordering::Acquire))
                .await;
        } else {
            assert!(result.is_none());
            // Attempted dirty reuse must not clear the abandoned query's flag.
            assert!(matches!(
                connection.query_static_sql(&cx, "SELECT 1").await,
                Outcome::Err(MySqlError::ConnectionClosed)
            ));
            drop(connection);
            done_tx.send(()).unwrap();
        }
    });
    let controller = thread::spawn(move || {
        let (cx, owner_cx, waker) = control_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        // A failed old-source cancellation witness must fail the test rather
        // than leave block_on waiting forever for the deliberately silent peer.
        struct FailureCleanup {
            owner: Cx,
            retire: Arc<AtomicBool>,
            retirement: Arc<asupersync::sync::Notify>,
        }
        impl Drop for FailureCleanup {
            fn drop(&mut self) {
                if thread::panicking() {
                    self.owner.cancel_with_reason(CancelReason::shutdown());
                    self.retire.store(true, Ordering::Release);
                    self.retirement.notify_waiters();
                }
            }
        }
        let _failure_cleanup = FailureCleanup {
            owner: owner_cx.clone(),
            retire: Arc::clone(&retire),
            retirement: Arc::clone(&retirement),
        };
        query_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        probe.store(true, Ordering::Release);
        waker.wake_by_ref();
        parked_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        let started = Instant::now();
        if cancel {
            let target = if matches!(source, CancelSource::Owner) {
                &owner_cx
            } else {
                &cx
            };
            target.cancel_with_reason(expected_reason);
        } else {
            release.store(true, Ordering::Release);
            waker.wake_by_ref();
        }
        // After the parked witness, cancellation itself must supply the wake.
        done_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        closed_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        retire.store(true, Ordering::Release);
        retirement.notify_waiters();
        started.elapsed()
    });
    runtime.block_on(join);
    let elapsed = controller.join().unwrap();
    server.join().unwrap();
    let report = runtime.shutdown_drained(Duration::from_secs(2));
    assert_eq!(report.outcome, RootDrainOutcome::Quiescent, "{report:?}");
    assert_eq!(test_active_mysql_drop_kills(), 0);
    eprintln!(
        "event=mysql_cancel workers={workers} cancel={cancel} source={source:?} operation={operation:?} peer={peer:?} elapsed_ms={} parked=true primary_closed=true cleanup_closed=true cleanup_threads=0",
        elapsed.as_millis()
    );
}

/// Create a minimal MySQL HandshakeV10 packet for testing
fn create_handshake_v10_packet(connection_id: u32) -> Vec<u8> {
    let mut packet = Vec::new();

    // Packet length for the fixed HandshakeV10 fixture
    packet.extend_from_slice(&[0x4a, 0x00, 0x00, 0x00]);

    // Protocol version
    packet.push(0x0a);

    // Server version (null-terminated)
    packet.extend_from_slice(b"8.0.0-scripted\0");

    // Connection ID (4 bytes, little-endian)
    packet.extend_from_slice(&connection_id.to_le_bytes());

    // Auth data part 1 (8 bytes)
    packet.extend_from_slice(b"12345678");

    // Filler (1 byte)
    packet.push(0x00);

    // Capabilities lower (2 bytes)
    packet.extend_from_slice(&[0xff, 0xf7]);

    // Charset (1 byte)
    packet.push(0x08);

    // Status flags (2 bytes)
    packet.extend_from_slice(&[0x02, 0x00]);

    // Capabilities upper (2 bytes)
    packet.extend_from_slice(&[0xff, 0x81]);

    // Auth data length (1 byte)
    packet.push(0x15);

    // Reserved (10 bytes)
    packet.extend_from_slice(&[0x00; 10]);

    // Auth data part 2 (12 bytes + null)
    packet.extend_from_slice(b"abcdefghijkl\0");

    // Auth plugin name
    packet.extend_from_slice(b"caching_sha2_password\0");

    // Update packet length
    let payload_len = packet.len() - 4;
    packet[0] = (payload_len & 0xff) as u8;
    packet[1] = ((payload_len >> 8) & 0xff) as u8;
    packet[2] = ((payload_len >> 16) & 0xff) as u8;

    packet
}
