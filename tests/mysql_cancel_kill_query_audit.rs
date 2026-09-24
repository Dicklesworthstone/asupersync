//! Native MySQL cancellation: actual parked COM_QUERY, separately authenticated
//! KILL QUERY, bounded silent cleanup peers, and streaming ownership retirement.
#![cfg(all(
    feature = "mysql",
    feature = "test-internals",
    not(target_arch = "wasm32")
))]

use asupersync::cx::Cx;
use asupersync::database::mysql::{MySqlConnection, MySqlError, test_active_mysql_drop_kills};
use asupersync::runtime::{RootDrainOutcome, RuntimeBuilder};
use asupersync::types::{CancelKind, Outcome};
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
    StreamHeader,
    StreamRows,
}
#[derive(Clone, Copy, Debug)]
enum KillPeer {
    Replies,
    SilentGreeting,
    SilentAuthentication,
    SilentReply,
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

fn cancellation_case(workers: usize, cancel: bool, operation: Operation, peer: KillPeer) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let (query_tx, query_rx) = mpsc::channel();
    let (closed_tx, closed_rx) = mpsc::channel();
    let server = thread::spawn(move || {
        let mut main = accept(&listener);
        authenticate(&mut main, 42, true);
        assert_eq!(
            read_packet(&mut main),
            (0, b"\x03SELECT SLEEP(30)".to_vec())
        );
        if matches!(operation, Operation::StreamRows) {
            stream_header(&mut main);
        }
        query_tx.send(()).unwrap();
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
    let runtime = RuntimeBuilder::new()
        .worker_threads(workers)
        .build()
        .unwrap();
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
        let cx = Cx::current().unwrap();
        let url = format!("mysql://test:test@{address}/test");
        let mut connection = match MySqlConnection::connect(&cx, &url).await {
            Outcome::Ok(connection) => connection,
            other => panic!("main connect: {other:?}"),
        };
        let result = {
            let mut execute = Box::pin(async {
                match operation {
                    Operation::Collect => connection
                        .query_static_sql(&cx, "SELECT SLEEP(30)")
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
                }
            });
            let mut control_tx = Some(control_tx);
            poll_fn(|task_cx| {
                if let Some(sender) = control_tx.take() {
                    sender.send((cx.clone(), task_cx.waker().clone())).unwrap();
                }
                if !cancel && task_release.load(Ordering::Acquire) {
                    return Poll::Ready(None);
                }
                let result = execute.as_mut().poll(task_cx);
                if result.is_pending() && task_probe.swap(false, Ordering::AcqRel) {
                    parked_tx.send(()).unwrap();
                }
                result.map(Some)
            })
            .await
        };
        if cancel {
            assert!(matches!(result, Some(Outcome::Cancelled(_))), "{result:?}");
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
    let (cx, waker) = control_rx.recv_timeout(Duration::from_secs(3)).unwrap();
    query_rx.recv_timeout(Duration::from_secs(3)).unwrap();
    probe.store(true, Ordering::Release);
    waker.wake_by_ref();
    parked_rx.recv_timeout(Duration::from_secs(3)).unwrap();
    let started = Instant::now();
    if cancel {
        cx.cancel_fast(CancelKind::User);
    } else {
        release.store(true, Ordering::Release);
        waker.wake_by_ref();
    }
    done_rx.recv_timeout(Duration::from_secs(3)).unwrap();
    closed_rx.recv_timeout(Duration::from_secs(3)).unwrap();
    retire.store(true, Ordering::Release);
    retirement.notify_waiters();
    runtime.block_on(join);
    server.join().unwrap();
    let report = runtime.shutdown_drained(Duration::from_secs(2));
    assert_eq!(report.outcome, RootDrainOutcome::Quiescent, "{report:?}");
    assert_eq!(test_active_mysql_drop_kills(), 0);
    eprintln!(
        "event=mysql_cancel workers={workers} cancel={cancel} operation={operation:?} peer={peer:?} elapsed_ms={} primary_closed=true cleanup_closed=true cleanup_threads=0",
        started.elapsed().as_millis()
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
