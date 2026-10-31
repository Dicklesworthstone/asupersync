use super::*;
use super::super::pgoutput::PgOutputMessage;
use super::super::parse_startup_message;
use crate::runtime::{Runtime, RuntimeBuilder};
use crate::types::{Budget, RegionId, TaskId};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::task::Waker;
use std::time::Instant;

fn runtime(workers: usize) -> Runtime {
    let builder = if workers == 1 {
        RuntimeBuilder::current_thread()
    } else {
        RuntimeBuilder::multi_thread().worker_threads(workers)
    };
    builder.with_reactor(crate::runtime::reactor::create_reactor().unwrap()).build().unwrap()
}

/// The owned cancellation-Waker registrations on `cx`, by token.
///
/// `Runtime::block_on` registers its caller's cancellation wake on the root
/// it drives for exactly the length of the drive. Inside a drive, a stream
/// that leaks nothing therefore leaves that one entry, not an empty registry.
fn cancel_waker_tokens(cx: &Cx) -> Vec<u64> {
    let mut tokens: Vec<u64> = cx
        .inner
        .read()
        .cancel_waker_registrations
        .iter()
        .map(|registration| registration.token)
        .collect();
    tokens.sort_unstable();
    tokens
}

fn listener() -> (TcpListener, String) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("postgres://replica@{}/application?sslmode=disable", listener.local_addr().unwrap());
    (listener, url)
}

fn accept(listener: &TcpListener) -> TcpStream {
    let until = Instant::now() + Duration::from_secs(5);
    loop {
        match listener.accept() {
            Ok((socket, _)) => {
                socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                socket.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
                return socket;
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < until => {
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(error) => panic!("native replication peer did not connect: {error}"),
        }
    }
}

fn frame(tag: u8, data: &[u8]) -> Vec<u8> {
    let mut frame = vec![tag];
    frame.extend_from_slice(&(i32::try_from(data.len()).unwrap() + 4).to_be_bytes());
    frame.extend_from_slice(data);
    frame
}

fn receive(socket: &mut TcpStream) -> (u8, Vec<u8>) {
    let mut header = [0u8; 5];
    socket.read_exact(&mut header).unwrap();
    let len = i32::from_be_bytes(header[1..].try_into().unwrap());
    assert!((4..=65_540).contains(&len));
    let mut data = vec![0; len as usize - 4];
    socket.read_exact(&mut data).unwrap();
    (header[0], data)
}

fn startup(socket: &mut TcpStream) {
    let mut length = [0; 4];
    socket.read_exact(&mut length).unwrap();
    let len = i32::from_be_bytes(length);
    assert!((8..4096).contains(&len));
    let mut bytes = length.to_vec();
    bytes.resize(len as usize, 0);
    socket.read_exact(&mut bytes[4..]).unwrap();
    let startup = parse_startup_message(&bytes).unwrap();
    assert_eq!(startup.parameters.get("replication").map(String::as_str), Some("database"));
    assert_eq!(startup.parameters.get("database").map(String::as_str), Some("application"));
    assert_eq!(startup.parameters.get("user").map(String::as_str), Some("replica"));
}

fn authenticate(socket: &mut TcpStream) {
    let mut bytes = frame(b'R', &0i32.to_be_bytes());
    let mut key = 1234i32.to_be_bytes().to_vec();
    key.extend_from_slice(&5678i32.to_be_bytes());
    bytes.extend(frame(b'K', &key));
    bytes.extend(frame(b'S', b"client_encoding\0UTF8\0"));
    bytes.extend(frame(b'Z', b"I"));
    socket.write_all(&bytes).unwrap();
}

fn start(socket: &mut TcpStream) {
    startup(socket);
    authenticate(socket);
    let (tag, data) = receive(socket);
    assert_eq!(tag, b'Q', "replication uses only simple query framing");
    assert_eq!(data, b"START_REPLICATION SLOT \"slot_1\" LOGICAL 0/10 (proto_version '1', publication_names '\"pub\"')\0");
    socket.write_all(&frame(b'W', &[0, 0, 0])).unwrap();
}

fn config() -> PgReplicationConfig {
    PgReplicationConfig::new("slot_1", ["pub"], PgLsn::new(0x10)).unwrap()
}

fn keepalive(wal_end: u64, requested: bool) -> Vec<u8> {
    let mut data = vec![b'k'];
    data.extend_from_slice(&wal_end.to_be_bytes());
    data.extend_from_slice(&(-5i64).to_be_bytes());
    data.push(u8::from(requested));
    frame(b'd', &data)
}

fn begin() -> Vec<u8> {
    let mut data = vec![b'B'];
    data.extend_from_slice(&0x30u64.to_be_bytes());
    data.extend_from_slice(&(-7i64).to_be_bytes());
    data.extend_from_slice(&42u32.to_be_bytes());
    data
}

fn wal(payload: &[u8]) -> Vec<u8> {
    let mut data = vec![b'w'];
    data.extend_from_slice(&0x10u64.to_be_bytes());
    data.extend_from_slice(&0x200u64.to_be_bytes());
    data.extend_from_slice(&(-5i64).to_be_bytes());
    data.extend_from_slice(payload);
    frame(b'd', &data)
}

fn assert_feedback(socket: &mut TcpStream, positions: [u64; 3]) {
    let (tag, data) = receive(socket);
    assert_eq!(tag, b'd');
    assert_eq!(data.len(), 34);
    assert_eq!(data[0], b'r');
    for (index, expected) in positions.into_iter().enumerate() {
        let begin = 1 + 8 * index;
        assert_eq!(u64::from_be_bytes(data[begin..begin + 8].try_into().unwrap()), expected);
    }
    assert_eq!(data[33], 0);
}

fn finish_peer(socket: &mut TcpStream) {
    assert_eq!(receive(socket), (b'c', Vec::new()));
    let mut end = frame(b'c', &[]);
    end.extend(frame(b'C', b"COPY 0\0"));
    end.extend(frame(b'C', b"START_REPLICATION\0"));
    end.extend(frame(b'Z', b"I"));
    socket.write_all(&end).unwrap();
    closed(socket);
}

fn closed(socket: &mut TcpStream) {
    let mut byte = [0];
    match socket.read(&mut byte) {
        Ok(0) => {}
        Err(error) if error.kind() == io::ErrorKind::ConnectionReset => {}
        other => panic!("replication socket remained live or emitted unexpected bytes: {other:?}"),
    }
}

fn ok<T: fmt::Debug>(outcome: Outcome<T, PgError>) -> T {
    match outcome {
        Outcome::Ok(value) => value,
        other => panic!("unexpected replication result: {other:?}"),
    }
}

#[test]
fn lsn_configuration_and_feedback_validate_without_sql_injection() {
    for (text, value) in [("0/0", 0), ("1/0", 1u64 << 32), ("FFFFFFFF/FFFFFFFF", u64::MAX)] {
        assert_eq!(text.parse::<PgLsn>().unwrap().as_u64(), value);
        assert_eq!(PgLsn::new(value).to_string(), text);
    }
    for invalid in ["", "/", "+1/0", "0/100000000", "0/0/0", " 0/1", "0/1\0", "G/0"] {
        assert!(invalid.parse::<PgLsn>().is_err(), "{invalid:?}");
    }
    for invalid in ["", "UPPER", "slot;DROP", "slot\0name"] {
        assert!(PgReplicationConfig::new(invalid, ["pub"], PgLsn::new(0)).is_err());
    }
    let command = PgReplicationConfig::new("safe", ["pub,one", "a\"b's\\c"], PgLsn::new(0))
        .unwrap().binary(true).messages(true).start_command().unwrap();
    assert_eq!(command, "START_REPLICATION SLOT \"safe\" LOGICAL 0/0 (proto_version '1', publication_names '\"pub,one\",\"a\"\"b''s\\c\"', binary 'true', messages 'true')");
    assert!(config().with_max_message_bytes(24).is_err());
    assert!(config().with_max_message_bytes(MAX_BACKEND_MESSAGE_LEN as usize).is_err());
    assert!(PgReplicationFeedback::new(PgLsn::new(1), PgLsn::new(2), PgLsn::new(0)).is_err());
    assert!(PgReplicationFeedback::new(PgLsn::new(2), PgLsn::new(1), PgLsn::new(2)).is_err());
}

#[test]
fn replication_envelopes_are_strict_and_retain_signed_timestamps() {
    let wal = wal(&begin());
    let data = wal[5..].to_vec();
    for length in 0..25 {
        assert!(parse_event(data[..length].to_vec()).is_err());
    }
    let event = parse_event(data).unwrap();
    assert!(matches!(&event, PgReplicationEvent::XLogData {
        wal_start, wal_end, server_time_micros: -5, ..
    } if *wal_start == PgLsn::new(0x10) && *wal_end == PgLsn::new(0x200)));
    assert!(matches!(event.pgoutput().unwrap(), Some(PgOutputMessage::Begin {
        xid: 42, commit_time_micros: -7, ..
    })));
    let keepalive = keepalive(0x300, true);
    let data = &keepalive[5..];
    for length in 0..data.len() { assert!(parse_event(data[..length].to_vec()).is_err()); }
    let event = parse_event(data.to_vec()).unwrap();
    assert!(matches!(event, PgReplicationEvent::PrimaryKeepAlive {
        reply_requested: true, server_time_micros: -5, ..
    }));
    let mut bad = data.to_vec();
    bad[17] = 2;
    assert!(parse_event(bad).is_err());
    let mut trailing = data.to_vec();
    trailing.push(0);
    assert!(parse_event(trailing).is_err());
}

struct ShortWriter {
    output: Vec<u8>,
    calls: usize,
    park_write: bool,
    park_flush: bool,
}

impl AsyncWrite for ShortWriter {
    fn poll_write(mut self: Pin<&mut Self>, _: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        self.calls += 1;
        if self.calls == 2 && self.park_write { return Poll::Pending; }
        let count = bytes.len().min(3);
        self.output.extend_from_slice(&bytes[..count]);
        Poll::Ready(Ok(count))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.park_flush { Poll::Pending } else { Poll::Ready(Ok(())) }
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[test]
fn pending_feedback_resumes_short_writes_and_flush_without_replaying_bytes() {
    let expected = frame(b'd', b"r0123456789");
    let mut pending = PendingWrite::new(expected.clone(), WriteKind::Feedback(PgReplicationFeedback::default()));
    let mut writer = ShortWriter { output: Vec::new(), calls: 0, park_write: true, park_flush: true };
    let mut task = Context::from_waker(Waker::noop());
    {
        let mut first = Box::pin(poll_fn(|cx| poll_pending_write(&mut pending, &mut writer, cx)));
        assert!(first.as_mut().poll(&mut task).is_pending());
    }
    assert_eq!(pending.offset, 3);
    writer.park_write = false;
    {
        let mut second = Box::pin(poll_fn(|cx| poll_pending_write(&mut pending, &mut writer, cx)));
        assert!(second.as_mut().poll(&mut task).is_pending());
    }
    assert_eq!(pending.offset, expected.len());
    assert_eq!(writer.output, expected);
    writer.park_flush = false;
    assert!(matches!(poll_pending_write(&mut pending, &mut writer, &mut task), Poll::Ready(Ok(()))));
    assert_eq!(writer.output, expected, "resuming a pending flush cannot resend its frame");
}

#[test]
fn native_replication_negotiates_mode_decodes_changes_and_acknowledges_only_confirmed_progress() {
    for workers in [1, 2] {
        let (listener, url) = listener();
        let peer = std::thread::spawn(move || {
            let mut socket = accept(&listener);
            start(&mut socket);
            let mut data = frame(b'S', b"application_name\0replica\0");
            data.extend(wal(&begin()));
            data.extend(keepalive(0x200, true));
            socket.write_all(&data).unwrap();
            assert_feedback(&mut socket, [0, 0, 0]);
            assert_feedback(&mut socket, [0x30, 0x30, 0x20]);
            finish_peer(&mut socket);
        });
        let runtime = runtime(workers);
        let cx = runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let driver_wake = cancel_waker_tokens(&cx);
            assert_eq!(driver_wake.len(), 1, "the drive registers only its caller wake");
            let connection = ok(PgReplicationConnection::connect(&cx, &url).await);
            let mut stream = ok(connection.start(&cx, config()).await);
            let event = ok(stream.next(&cx).await).unwrap();
            assert!(matches!(event.pgoutput().unwrap(), Some(PgOutputMessage::Begin { xid: 42, .. })));
            assert_eq!(stream.feedback(), PgReplicationFeedback::default());
            assert!(matches!(ok(stream.next(&cx).await), Some(PgReplicationEvent::PrimaryKeepAlive { reply_requested: true, .. })));
            assert_eq!(stream.feedback().flushed(), PgLsn::new(0));
            let feedback = PgReplicationFeedback::new(PgLsn::new(0x30), PgLsn::new(0x30), PgLsn::new(0x20)).unwrap();
            ok(stream.send_feedback(&cx, feedback).await);
            assert_eq!(stream.feedback(), feedback);
            assert!(matches!(stream.send_feedback(&cx, PgReplicationFeedback::default()).await, Outcome::Err(PgError::Protocol(_))));
            ok(stream.finish(&cx).await);
            assert_eq!(cancel_waker_tokens(&cx), driver_wake);
            cx
        });
        assert!(cx.inner.read().cancel_waker_registrations.is_empty());
        drop(cx);
        peer.join().unwrap();
        assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
    }
}

#[test]
fn native_partial_wal_wait_can_be_dropped_to_send_feedback_then_resumed() {
    for workers in [1, 2] {
        let (listener, url) = listener();
        let peer = std::thread::spawn(move || {
            let mut socket = accept(&listener);
            start(&mut socket);
            let data = wal(&begin());
            socket.write_all(&data[..7]).unwrap();
            assert_feedback(&mut socket, [0, 0, 0]);
            socket.write_all(&data[7..]).unwrap();
            finish_peer(&mut socket);
        });
        let runtime = runtime(workers);
        let cx = runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let driver_wake = cancel_waker_tokens(&cx);
            assert_eq!(driver_wake.len(), 1, "the drive registers only its caller wake");
            let connection = ok(PgReplicationConnection::connect(&cx, &url).await);
            let mut stream = ok(connection.start(&cx, config()).await);
            let progress = Arc::new(AtomicUsize::new(0));
            stream.connection.inner.backend_frame.pending_progress = Some(progress.clone());
            {
                let mut waiting = Box::pin(stream.next(&cx));
                poll_fn(|task| {
                    assert!(waiting.as_mut().poll(task).is_pending());
                    if progress.load(Ordering::Acquire) == 7 { Poll::Ready(()) } else { Poll::Pending }
                }).await;
            }
            assert_eq!(cancel_waker_tokens(&cx), driver_wake);
            ok(stream.send_feedback(&cx, PgReplicationFeedback::default()).await);
            let event = ok(stream.next(&cx).await).unwrap();
            assert!(matches!(event.pgoutput().unwrap(), Some(PgOutputMessage::Begin { xid: 42, .. })));
            ok(stream.finish(&cx).await);
            assert_eq!(cancel_waker_tokens(&cx), driver_wake);
            cx
        });
        assert!(cx.inner.read().cancel_waker_registrations.is_empty());
        drop(cx);
        peer.join().unwrap();
        assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
    }
}

#[test]
fn native_parked_replication_retains_original_owner_cancellation_and_delivers_cancel_request() {
    for workers in [1, 2] {
        let (listener, url) = listener();
        let peer = std::thread::spawn(move || {
            let mut socket = accept(&listener);
            start(&mut socket);
            let mut cancel = accept(&listener);
            let mut bytes = [0; 16];
            cancel.read_exact(&mut bytes).unwrap();
            assert_eq!(&bytes[0..4], &16i32.to_be_bytes());
            assert_eq!(&bytes[4..8], &80_877_102i32.to_be_bytes());
            assert_eq!(&bytes[8..12], &1234i32.to_be_bytes());
            assert_eq!(&bytes[12..16], &5678i32.to_be_bytes());
            closed(&mut socket);
        });
        let runtime = runtime(workers);
        let owner = runtime.request_cx_with_budget(Budget::INFINITE);
        let (parked_tx, parked_rx) = mpsc::channel();
        let reason = CancelReason::user("replication consumer stopped");
        let controller = {
            let owner = owner.clone();
            let reason = reason.clone();
            std::thread::spawn(move || {
                parked_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                owner.cancel_with_reason(reason);
            })
        };
        let poller = runtime.block_on(async {
            let poller = Cx::current().unwrap();
            let driver_wake = cancel_waker_tokens(&poller);
            assert_eq!(driver_wake.len(), 1, "the drive registers only its caller wake");
            let connection = ok(PgReplicationConnection::connect(&owner, &url).await);
            let mut stream = ok(connection.start(&owner, config()).await);
            let mut witnessed = false;
            let outcome = {
                let mut waiting = Box::pin(stream.next(&poller));
                poll_fn(|task| {
                    let result = waiting.as_mut().poll(task);
                    if result.is_pending() && !witnessed {
                        witnessed = true;
                        parked_tx.send(()).unwrap();
                    }
                    result
                }).await
            };
            assert!(witnessed);
            match outcome {
                Outcome::Cancelled(actual) => assert_eq!(actual, reason),
                other => panic!("original owner cancellation was lost: {other:?}"),
            }
            assert!(poller.checkpoint().is_ok());
            assert!(matches!(stream.next(&poller).await, Outcome::Err(PgError::Protocol(_))));
            drop(stream);
            assert!(owner.inner.read().cancel_waker_registrations.is_empty());
            assert_eq!(cancel_waker_tokens(&poller), driver_wake);
            poller
        });
        assert!(poller.inner.read().cancel_waker_registrations.is_empty());
        drop(poller);
        controller.join().unwrap();
        peer.join().unwrap();
        assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
    }
}

#[test]
fn native_replication_connect_retains_original_poller_cancellation_during_parked_startup() {
    for workers in [1, 2] {
        let (listener, url) = listener();
        let authenticated = Arc::new(AtomicBool::new(false));
        let peer = {
            let authenticated = authenticated.clone();
            std::thread::spawn(move || {
                let mut socket = accept(&listener);
                startup(&mut socket);
                authenticated.store(true, Ordering::Release);
                socket.write_all(&frame(b'R', &0i32.to_be_bytes())).unwrap();
                // No BackendKeyData or ReadyForQuery: completion must come
                // from cancellation of the original polling context.
                let mut tag = [0];
                match socket.read(&mut tag) {
                    Ok(0) => {}
                    Ok(1) if tag[0] == b'X' => {
                        // The existing connection destructor may send its
                        // best-effort Terminate before closing startup.
                        let mut length = [0; 4];
                        socket.read_exact(&mut length).unwrap();
                        assert_eq!(length, 4i32.to_be_bytes());
                        closed(&mut socket);
                    }
                    Err(error) if error.kind() == io::ErrorKind::ConnectionReset => {}
                    other => panic!("cancelled startup left unexpected wire state: {other:?}"),
                }
            })
        };
        let runtime = runtime(workers);
        let owner = runtime.request_cx_with_budget(Budget::INFINITE);
        let initial_poller = runtime.request_cx_with_budget(Budget::INFINITE);
        let reason = CancelReason::user("connect polling task stopped");
        let (parked_tx, parked_rx) = mpsc::channel();
        let controller = {
            let initial_poller = initial_poller.clone();
            let reason = reason.clone();
            std::thread::spawn(move || {
                parked_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                initial_poller.cancel_with_reason(reason);
            })
        };
        runtime.block_on(async {
            let mut future = Box::pin(PgReplicationConnection::connect(&owner, &url));
            let mut witnessed = false;
            let result = poll_fn(|task| {
                let _ambient = Cx::set_current(Some(initial_poller.clone()));
                let result = future.as_mut().poll(task);
                if result.is_pending() && authenticated.load(Ordering::Acquire) && !witnessed {
                    witnessed = true;
                    parked_tx.send(()).unwrap();
                }
                result
            }).await;
            assert!(witnessed);
            assert!(matches!(result, Outcome::Cancelled(actual) if actual == reason));
            drop(future);
            assert!(owner.checkpoint().is_ok());
            assert!(owner.inner.read().cancel_waker_registrations.is_empty());
            assert!(initial_poller.inner.read().cancel_waker_registrations.is_empty());
        });
        controller.join().unwrap();
        peer.join().unwrap();
        assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
    }
}

#[test]
fn native_replication_bounds_protocol_errors_and_unconsumed_drop_close_the_socket() {
    for workers in [1, 2] {
        for case in 0..4 {
            let (listener, url) = listener();
            let peer = std::thread::spawn(move || {
                let mut socket = accept(&listener);
                start(&mut socket);
                match case {
                    0 => socket.write_all(&[b'd', 0, 0, 4, 4]).unwrap(),
                    1 => socket.write_all(&frame(b'd', b"kbad")).unwrap(),
                    2 => socket.write_all(&frame(b'E', b"SERROR\0C55000\0Mreplication slot unavailable\0\0")).unwrap(),
                    _ => {}
                }
                closed(&mut socket);
            });
            let runtime = runtime(workers);
            let cx = runtime.block_on(async {
                let cx = Cx::current().unwrap();
                let driver_wake = cancel_waker_tokens(&cx);
                assert_eq!(driver_wake.len(), 1, "the drive registers only its caller wake");
                let connection = ok(PgReplicationConnection::connect(&cx, &url).await);
                let mut stream = ok(connection.start(&cx, config().with_max_message_bytes(128).unwrap()).await);
                if case < 3 {
                    let outcome = stream.next(&cx).await;
                    if case == 2 {
                        assert!(matches!(outcome, Outcome::Err(PgError::Server { code, .. }) if code == "55000"));
                    } else {
                        assert!(matches!(outcome, Outcome::Err(PgError::Protocol(_))));
                    }
                    if case == 0 {
                        assert!(stream.connection.inner.backend_frame.body.is_empty(), "oversized frame is rejected before payload allocation");
                    }
                }
                drop(stream);
                assert_eq!(cancel_waker_tokens(&cx), driver_wake);
                cx
            });
            assert!(cx.inner.read().cancel_waker_registrations.is_empty());
            drop(cx);
            peer.join().unwrap();
            assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
        }
    }
}

#[test]
fn control_observes_a_different_poller_after_the_same_future_has_parked() {
    let owner = Cx::for_testing();
    let first = Cx::for_testing();
    let next = Cx::for_testing();
    let mut control = {
        let _ambient = Cx::set_current(Some(first.clone()));
        ReplicationControl::new(&owner)
    };
    let mut future = Box::pin(control.drive(&owner, std::future::pending::<Result<(), PgError>>()));
    let mut task = Context::from_waker(Waker::noop());
    {
        let _ambient = Cx::set_current(Some(first.clone()));
        assert!(future.as_mut().poll(&mut task).is_pending());
    }
    let reason = CancelReason::user("new polling task cancelled");
    next.cancel_with_reason(reason.clone());
    {
        let _ambient = Cx::set_current(Some(next.clone()));
        assert!(matches!(future.as_mut().poll(&mut task), Poll::Ready(Err(PgError::Cancelled(actual))) if actual == reason));
    }
    drop(future);
    for cx in [owner, first, next] { assert!(cx.inner.read().cancel_waker_registrations.is_empty()); }
}

#[test]
fn control_translates_poller_deadlines_to_the_original_clock() {
    let owner_clock = Arc::new(crate::time::VirtualClock::starting_at(Time::from_nanos(1_000)));
    let owner = Cx::new_with_drivers(
        RegionId::new_for_test(0, 1), TaskId::new_for_test(88, 0), Budget::INFINITE,
        None, None, None, Some(TimerDriverHandle::with_virtual_clock(owner_clock.clone())), None,
    );
    let poller_clock = Arc::new(crate::time::VirtualClock::starting_at(Time::from_nanos(10)));
    let poller = Cx::new_with_drivers(
        RegionId::new_for_test(0, 1), TaskId::new_for_test(89, 0),
        Budget::INFINITE.with_deadline(Time::from_nanos(17)),
        None, None, None, Some(TimerDriverHandle::with_virtual_clock(poller_clock)), None,
    );
    let mut control = {
        let _ambient = Cx::set_current(Some(owner.clone()));
        ReplicationControl::new(&owner)
    };
    let mut future = Box::pin(control.drive(&owner, std::future::pending::<Result<(), PgError>>()));
    let _ambient = Cx::set_current(Some(poller.clone()));
    let mut task = Context::from_waker(Waker::noop());
    assert!(future.as_mut().poll(&mut task).is_pending());
    owner_clock.advance(7);
    assert!(matches!(future.as_mut().poll(&mut task), Poll::Ready(Err(PgError::Cancelled(_)))));
    drop(future);
    assert_eq!(control.deadline, Some(Time::from_nanos(1_007)));
    assert!(owner.inner.read().cancel_waker_registrations.is_empty());
    assert!(poller.inner.read().cancel_waker_registrations.is_empty());
}
