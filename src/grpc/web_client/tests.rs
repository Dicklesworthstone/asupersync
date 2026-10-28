//! Native socket tests for the gRPC-Web client. The peer writes independent
//! wire fixtures and withholds EOF until the client has consumed a message.

use super::*;
use crate::bytes::Bytes;
use crate::grpc::IdentityCodec;
use crate::runtime::RuntimeBuilder;
use crate::time::{TimerDriverHandle, VirtualClock};
use crate::types::{Budget, RegionId, TaskId};
use base64::Engine as _;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::task::{Wake, Waker};
use std::time::Instant;

fn listener() -> (TcpListener, String) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!(
        "http://{}/test.Service/Watch",
        listener.local_addr().unwrap()
    );
    (listener, url)
}

fn accept(listener: &TcpListener) -> TcpStream {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                return stream;
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                assert!(Instant::now() < deadline, "client never connected");
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(error) => panic!("accept: {error}"),
        }
    }
}

fn request(socket: &mut TcpStream) -> (String, Vec<u8>) {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        assert!(bytes.len() < 16 * 1024, "unbounded request head");
        let mut byte = [0];
        socket.read_exact(&mut byte).unwrap();
        bytes.push(byte[0]);
    }
    let head = String::from_utf8(bytes).unwrap();
    assert!(head.starts_with("POST /test.Service/Watch HTTP/1.1\r\n"));
    let length = head
        .split("\r\n")
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .unwrap()
        .1
        .trim()
        .parse::<usize>()
        .unwrap();
    assert!(length < 16 * 1024);
    let mut body = vec![0; length];
    socket.read_exact(&mut body).unwrap();
    (head, body)
}

fn envelope(flag: u8, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![flag];
    bytes.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

fn message(payload: &[u8]) -> Vec<u8> {
    envelope(0, payload)
}

fn trailers(fields: &[u8]) -> Vec<u8> {
    envelope(0x80, fields)
}

fn success(payload: &[u8]) -> Vec<u8> {
    let mut bytes = message(payload);
    bytes.extend(trailers(b"grpc-status: 0\r\nx-final: yes\r\n"));
    bytes
}

fn chunk(socket: &mut TcpStream, bytes: &[u8]) {
    write!(socket, "{:x}\r\n", bytes.len()).unwrap();
    socket.write_all(bytes).unwrap();
    socket.write_all(b"\r\n").unwrap();
    socket.flush().unwrap();
}

fn fixed(socket: &mut TcpStream, status: u16, content_type: &str, headers: &str, body: &[u8]) {
    write!(socket,
        "HTTP/1.1 {status} Response\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n{headers}\r\n",
        body.len(),
    ).unwrap();
    socket.write_all(body).unwrap();
    socket.flush().unwrap();
}

fn expect_closed(socket: &mut TcpStream) {
    let mut byte = [0];
    match socket.read(&mut byte) {
        Ok(0) => {}
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe
            ) => {}
        result => panic!("unfinished response must close its socket: {result:?}"),
    }
}

fn runtime(multithread: bool) -> crate::runtime::Runtime {
    if multithread {
        RuntimeBuilder::new()
            .worker_threads(2)
            .with_sharded_state(true)
            .build()
            .unwrap()
    } else {
        RuntimeBuilder::current_thread().build().unwrap()
    }
}

fn config(content_type: ContentType) -> GrpcWebClientConfig {
    GrpcWebClientConfig {
        content_type,
        timeout: Duration::from_secs(4),
        ..GrpcWebClientConfig::default()
    }
}

fn metadata_text(metadata: &Metadata, key: &str) -> Option<String> {
    match metadata.get(key) {
        Some(MetadataValue::Ascii(value)) => Some(value.clone()),
        _ => None,
    }
}

#[test]
fn binary_and_padded_text_stream_incrementally_and_reuse_the_connection() {
    for multithread in [false, true] {
        for content_type in [ContentType::GrpcWeb, ContentType::GrpcWebText] {
            let (listener, url) = listener();
            let (continue_tx, continue_rx) = mpsc::channel();
            let eof_sent = Arc::new(AtomicBool::new(false));
            let peer_eof = Arc::clone(&eof_sent);
            let peer = std::thread::spawn(move || {
                let mut socket = accept(&listener);
                let (head, body) = request(&mut socket);
                assert!(
                    head.to_ascii_lowercase()
                        .contains("grpc-accept-encoding: identity\r\n")
                );
                assert!(
                    head.to_ascii_lowercase()
                        .contains("authorization: bearer test\r\n")
                );
                assert!(
                    head.to_ascii_lowercase()
                        .contains("x-request-bin: aqid\r\n")
                );
                let expected = message(b"request");
                assert_eq!(
                    body,
                    if content_type.is_text_mode() {
                        base64::engine::general_purpose::STANDARD
                            .encode(expected)
                            .into_bytes()
                    } else {
                        expected
                    }
                );
                write!(socket,
                    "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nTransfer-Encoding: chunked\r\nx-initial: hello\r\n\r\n",
                    content_type.as_header_value(),
                ).unwrap();
                let first = message(b"first");
                if content_type.is_text_mode() {
                    // Independently padded chunks split both a frame header
                    // and payload. HTTP chunks further split base64 quartets.
                    for part in first.chunks(2) {
                        let encoded = base64::engine::general_purpose::STANDARD.encode(part);
                        chunk(&mut socket, &encoded.as_bytes()[..1]);
                        chunk(&mut socket, &encoded.as_bytes()[1..]);
                    }
                } else {
                    for part in first.chunks(2) {
                        chunk(&mut socket, part);
                    }
                }
                continue_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                let mut rest = message(b"second");
                rest.extend(trailers(b"grpc-status: 0\r\nx-final: yes\r\n"));
                if content_type.is_text_mode() {
                    for part in rest.chunks(7) {
                        chunk(
                            &mut socket,
                            base64::engine::general_purpose::STANDARD
                                .encode(part)
                                .as_bytes(),
                        );
                    }
                } else {
                    chunk(&mut socket, &rest);
                }
                socket
                    .write_all(b"0\r\nx-http-checksum: transport-only\r\n\r\n")
                    .unwrap();
                socket.flush().unwrap();
                peer_eof.store(true, Ordering::SeqCst);

                // The same socket must carry a later unary call. A binary
                // response is valid even if the request preferred text.
                request(&mut socket);
                fixed(
                    &mut socket,
                    200,
                    "application/grpc-web+proto",
                    "",
                    &success(b"unary"),
                );
                assert!(
                    matches!(listener.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock)
                );
            });
            let runtime = runtime(multithread);
            let cx = runtime.request_cx_with_budget(Budget::INFINITE);
            let mut http = HttpClientConfig::default();
            http.pool_config.max_connections_per_host = 1;
            http.pool_config.max_total_connections = 1;
            let client = GrpcWebClient::with_http_config(http, config(content_type)).unwrap();
            runtime.block_on_with_cx(cx.clone(), async {
                let mut metadata = Metadata::new();
                assert!(metadata.insert("authorization", "Bearer test"));
                assert!(metadata.insert_bin("x-request-bin", Bytes::from_static(&[1, 2, 3])));
                let mut stream = client
                    .server_streaming(
                        &cx,
                        &url,
                        Request::with_metadata(Bytes::from_static(b"request"), metadata),
                        IdentityCodec,
                    )
                    .await
                    .unwrap();
                assert_eq!(
                    metadata_text(stream.initial_metadata(), "x-initial").as_deref(),
                    Some("hello")
                );
                assert_eq!(stream.message().await.unwrap().unwrap().as_ref(), b"first");
                assert!(
                    !eof_sent.load(Ordering::SeqCst),
                    "first message requires no source EOF"
                );
                assert!(stream.trailing_metadata().is_none());
                assert!(stream.terminal_status().is_none());
                assert_eq!(client.http.pool_stats().idle_connections, 0);
                let mut waiting = Box::pin(stream.message());
                poll_fn(|task| {
                    assert!(waiting.as_mut().poll(task).is_pending());
                    Poll::Ready(())
                })
                .await;
                drop(waiting); // Resume the same partially progressed stream.
                continue_tx.send(()).unwrap();
                assert_eq!(stream.message().await.unwrap().unwrap().as_ref(), b"second");
                assert!(stream.message().await.unwrap().is_none());
                assert!(stream.terminal_status().unwrap().is_ok());
                assert_eq!(
                    metadata_text(stream.trailing_metadata().unwrap(), "x-final").as_deref(),
                    Some("yes")
                );
                assert_eq!(client.http.pool_stats().idle_connections, 1);
                let unary = client
                    .unary(&cx, &url, Request::new(Bytes::new()), IdentityCodec)
                    .await
                    .unwrap();
                assert_eq!(unary.get_ref().as_ref(), b"unary");
                assert_eq!(
                    metadata_text(unary.trailing_metadata(), "x-final").as_deref(),
                    Some("yes")
                );
                assert_eq!(client.http.pool_stats().connections_created, 1);
            });
            drop(client);
            peer.join().unwrap();
            assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
        }
    }
}

#[test]
fn terminal_wire_errors_follow_messages_and_never_become_successful_eof() {
    let mut remote_error = message(b"first");
    remote_error.extend(trailers(
        b"grpc-status: 7\r\ngrpc-message: denied%20here\r\n",
    ));
    let mut after_trailers = trailers(b"grpc-status: 0\r\n");
    after_trailers.extend(message(b"late"));
    let mut truncated = envelope(0, b"unfinished");
    truncated.pop();
    let cases: Vec<(&str, Vec<u8>, Option<&[u8]>, Code)> = vec![
        (
            "missing status",
            message(b"first"),
            Some(b"first"),
            Code::Unknown,
        ),
        ("truncated message", truncated, None, Code::Internal),
        (
            "truncated frame header",
            vec![0, 0, 0],
            None,
            Code::Internal,
        ),
        (
            "remote error",
            remote_error,
            Some(b"first"),
            Code::PermissionDenied,
        ),
        ("data after trailers", after_trailers, None, Code::Internal),
        (
            "missing trailer status",
            trailers(b"x-only: metadata\r\n"),
            None,
            Code::Internal,
        ),
        (
            "duplicate status",
            trailers(b"grpc-status: 7\r\ngrpc-status: 0\r\n"),
            None,
            Code::Internal,
        ),
        (
            "compressed data",
            envelope(1, b"compressed"),
            None,
            Code::Unimplemented,
        ),
        (
            "compressed trailer",
            envelope(0x81, b"grpc-status: 0\r\n"),
            None,
            Code::Unimplemented,
        ),
        (
            "reserved flag",
            envelope(0x40, b"message"),
            None,
            Code::Internal,
        ),
    ];
    for (name, body, first, code) in cases {
        let (listener, url) = listener();
        let peer = std::thread::spawn(move || {
            let mut socket = accept(&listener);
            request(&mut socket);
            fixed(
                &mut socket,
                200,
                "application/grpc-web",
                "Connection: close\r\n",
                &body,
            );
        });
        let runtime = runtime(false);
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);
        let client = GrpcWebClient::with_config(config(ContentType::GrpcWeb)).unwrap();
        runtime.block_on_with_cx(cx.clone(), async {
            let mut stream = client
                .server_streaming(&cx, &url, Request::new(Bytes::new()), IdentityCodec)
                .await
                .unwrap();
            if let Some(first) = first {
                assert_eq!(
                    stream.message().await.unwrap().unwrap().as_ref(),
                    first,
                    "{name}"
                );
            }
            let error = stream.message().await.unwrap_err();
            assert_eq!(error.code(), code, "{name}: {error}");
            if name == "remote error" {
                assert_eq!(error.message(), "denied here");
            }
            assert_eq!(stream.terminal_status().unwrap().code(), code, "{name}");
            assert!(
                stream.message().await.unwrap().is_none(),
                "terminal error must fuse: {name}"
            );
            assert_eq!(client.http.pool_stats().total_connections, 0, "{name}");
        });
        peer.join().unwrap();
        assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
    }
}

#[test]
fn trailers_only_and_http_status_mapping_obey_wire_status_precedence() {
    for (http_status, content_type, headers, body, expected) in [
        (503, "text/plain", "", Vec::new(), Code::Unavailable),
        (404, "text/plain", "", Vec::new(), Code::Unimplemented),
        (200, "application/grpc-web", "", Vec::new(), Code::Unknown),
        (
            200,
            "application/grpc-web",
            "grpc-status: 7\r\ngrpc-message: rejected\r\nx-final: head\r\n",
            Vec::new(),
            Code::PermissionDenied,
        ),
        (
            503,
            "application/grpc-web",
            "grpc-status: 7\r\n",
            Vec::new(),
            Code::PermissionDenied,
        ),
        (
            503,
            "application/grpc-web",
            "",
            trailers(b"grpc-status: 7\r\n"),
            Code::PermissionDenied,
        ),
        (
            200,
            "application/grpc-web",
            "grpc-status: 0\r\n",
            message(b"forbidden body"),
            Code::Internal,
        ),
        (
            200,
            "application/grpc-web+json",
            "",
            success(b"wrong type"),
            Code::Internal,
        ),
        (
            200,
            "application/grpc-web",
            "grpc-encoding: gzip\r\n",
            success(b"wrong encoding"),
            Code::Unimplemented,
        ),
        (
            200,
            "application/grpc-web",
            "content-encoding: gzip\r\n",
            success(b"wrong encoding"),
            Code::Unimplemented,
        ),
    ] {
        let (listener, url) = listener();
        let peer = std::thread::spawn(move || {
            let mut socket = accept(&listener);
            request(&mut socket);
            fixed(
                &mut socket,
                http_status,
                content_type,
                &format!("{headers}Connection: close\r\n"),
                &body,
            );
        });
        let runtime = runtime(false);
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);
        let client = GrpcWebClient::with_config(config(ContentType::GrpcWeb)).unwrap();
        runtime.block_on_with_cx(cx.clone(), async {
            let error = client
                .unary(&cx, &url, Request::new(Bytes::new()), IdentityCodec)
                .await
                .unwrap_err();
            assert_eq!(
                error.code(),
                expected,
                "HTTP {http_status}, {content_type}, {headers:?}: {error}"
            );
            assert_eq!(client.http.pool_stats().total_connections, 0);
        });
        peer.join().unwrap();
        assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
    }
}

#[test]
fn unary_rejects_extra_messages_and_late_error_status() {
    let mut two = message(b"one");
    two.extend(success(b"two"));
    let mut late_error = message(b"one");
    late_error.extend(trailers(
        b"grpc-status: 14\r\ngrpc-message: retry%20later\r\n",
    ));
    for (body, expected) in [(two, Code::Internal), (late_error, Code::Unavailable)] {
        let (listener, url) = listener();
        let peer = std::thread::spawn(move || {
            let mut socket = accept(&listener);
            request(&mut socket);
            fixed(
                &mut socket,
                200,
                "application/grpc-web",
                "Connection: close\r\n",
                &body,
            );
        });
        let runtime = runtime(false);
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);
        let client = GrpcWebClient::with_config(config(ContentType::GrpcWeb)).unwrap();
        runtime.block_on_with_cx(cx.clone(), async {
            let error = client
                .unary(&cx, &url, Request::new(Bytes::new()), IdentityCodec)
                .await
                .unwrap_err();
            assert_eq!(error.code(), expected);
        });
        peer.join().unwrap();
        assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
    }
}

#[derive(Default)]
struct WakeCount(AtomicUsize);
impl Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn cancellation_and_drop_close_the_real_socket_and_release_pool_admission() {
    for mode in ["caller", "consumer", "drop"] {
        let (listener, url) = listener();
        let peer = std::thread::spawn(move || {
            let mut socket = accept(&listener);
            request(&mut socket);
            socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/grpc-web\r\nTransfer-Encoding: chunked\r\n\r\n").unwrap();
            chunk(&mut socket, &message(b"first"));
            expect_closed(&mut socket);
            let mut replacement = accept(&listener);
            request(&mut replacement);
            fixed(
                &mut replacement,
                200,
                "application/grpc-web",
                "Connection: close\r\n",
                &success(b"healthy"),
            );
        });
        let runtime = runtime(false);
        let driver = runtime.request_cx_with_budget(Budget::INFINITE);
        let owner = runtime.request_cx_with_budget(Budget::INFINITE);
        let mut http = HttpClientConfig::default();
        http.pool_config.max_connections_per_host = 1;
        http.pool_config.max_total_connections = 1;
        let client = GrpcWebClient::with_http_config(http, config(ContentType::GrpcWeb)).unwrap();
        runtime.block_on_with_cx(driver.clone(), async {
            let mut stream = client
                .server_streaming(&owner, &url, Request::new(Bytes::new()), IdentityCodec)
                .await
                .unwrap();
            assert_eq!(stream.message().await.unwrap().unwrap().as_ref(), b"first");
            let wakes = Arc::new(WakeCount::default());
            let waker = Waker::from(Arc::clone(&wakes));
            let mut task = Context::from_waker(&waker);
            assert!(stream.poll_message(&mut task).is_pending());
            match mode {
                "caller" => {
                    let before = wakes.0.load(Ordering::SeqCst);
                    owner.cancel_with(CancelKind::User, Some("test owner cancellation"));
                    assert!(
                        wakes.0.load(Ordering::SeqCst) > before,
                        "owner cancellation must wake the parked read"
                    );
                    assert_eq!(stream.message().await.unwrap_err().code(), Code::Cancelled);
                    assert!(stream.message().await.unwrap().is_none());
                }
                "consumer" => {
                    stream.cancel();
                    assert_eq!(stream.terminal_status().unwrap().code(), Code::Cancelled);
                    assert!(stream.message().await.unwrap().is_none());
                    assert!(
                        owner.checkpoint().is_ok(),
                        "consumer cancellation cannot cancel its parent"
                    );
                }
                "drop" => {}
                _ => unreachable!(),
            }
            drop(stream);
            assert_eq!(client.http.pool_stats().total_connections, 0);
            assert!(owner.inner.read().cancel_waker_registrations.is_empty());
            assert!(driver.checkpoint().is_ok());
            let healthy = client
                .unary(&driver, &url, Request::new(Bytes::new()), IdentityCodec)
                .await
                .unwrap();
            assert_eq!(healthy.into_inner().as_ref(), b"healthy");
        });
        peer.join().unwrap();
        assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
    }
}

#[test]
fn original_deadline_wakes_and_closes_a_parked_native_stream() {
    let (listener, url) = listener();
    let peer = std::thread::spawn(move || {
        let mut socket = accept(&listener);
        request(&mut socket);
        socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/grpc-web\r\nTransfer-Encoding: chunked\r\n\r\n").unwrap();
        chunk(&mut socket, &message(b"first"));
        expect_closed(&mut socket);
    });
    let runtime = runtime(false);
    let driver = runtime.request_cx_with_budget(Budget::INFINITE);
    let clock = Arc::new(VirtualClock::starting_at(Time::from_nanos(100)));
    let timer = TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
    let owner = Cx::new_with_drivers(
        RegionId::new_for_test(0, 1),
        TaskId::new_for_test(4, 0),
        Budget::INFINITE.with_deadline(Time::from_nanos(110)),
        None,
        driver.io_driver_handle(),
        None,
        Some(timer.clone()),
        None,
    );
    let client = GrpcWebClient::with_config(config(ContentType::GrpcWeb)).unwrap();
    runtime.block_on_with_cx(driver.clone(), async {
        let mut stream = client.server_streaming(&owner, &url, Request::new(Bytes::new()), IdentityCodec).await.unwrap();
        assert_eq!(stream.message().await.unwrap().unwrap().as_ref(), b"first");
        let wakes = Arc::new(WakeCount::default());
        let waker = Waker::from(Arc::clone(&wakes));
        let mut task = Context::from_waker(&waker);
        clock.advance(9);
        assert!(stream.poll_message(&mut task).is_pending());
        let before = wakes.0.load(Ordering::SeqCst);
        clock.advance(1);
        assert!(timer.process_timers() > 0);
        assert!(wakes.0.load(Ordering::SeqCst) > before);
        assert!(matches!(stream.poll_message(&mut task), Poll::Ready(Err(status)) if status.code() == Code::DeadlineExceeded));
        assert!(stream.message().await.unwrap().is_none());
        assert_eq!(client.http.pool_stats().total_connections, 0);
        assert!(owner.inner.read().cancel_waker_registrations.is_empty());
    });
    peer.join().unwrap();
    assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
}

#[test]
fn message_and_trailer_limits_reject_the_prefix_before_waiting_for_payload() {
    for (prefix, limit) in [(vec![0, 0, 0, 0, 9], 8), (vec![0x80, 0, 0, 0x08, 0], 4096)] {
        let (listener, url) = listener();
        let peer = std::thread::spawn(move || {
            let mut socket = accept(&listener);
            request(&mut socket);
            socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/grpc-web\r\nTransfer-Encoding: chunked\r\n\r\n").unwrap();
            chunk(&mut socket, &prefix);
            // No payload or HTTP EOF is ever sent.
            expect_closed(&mut socket);
        });
        let runtime = runtime(false);
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);
        let client = GrpcWebClient::with_config(GrpcWebClientConfig {
            max_recv_message_size: limit,
            max_metadata_size: 1024,
            ..config(ContentType::GrpcWeb)
        })
        .unwrap();
        runtime.block_on_with_cx(cx.clone(), async {
            let mut stream = client
                .server_streaming(&cx, &url, Request::new(Bytes::new()), IdentityCodec)
                .await
                .unwrap();
            assert_eq!(
                stream.message().await.unwrap_err().code(),
                Code::ResourceExhausted
            );
            assert_eq!(client.http.pool_stats().total_connections, 0);
        });
        peer.join().unwrap();
        assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
    }
}

#[test]
fn text_truncation_and_aggregate_wire_body_limit_fail_closed() {
    let valid = base64::engine::general_purpose::STANDARD.encode(success(b"first"));
    for (body, body_limit, expected) in [
        (format!("{valid}A").into_bytes(), 1024, Code::Internal),
        (b"!invalid!".to_vec(), 1024, Code::Internal),
        (valid.into_bytes(), 16, Code::ResourceExhausted),
    ] {
        let (listener, url) = listener();
        let peer = std::thread::spawn(move || {
            let mut socket = accept(&listener);
            request(&mut socket);
            fixed(
                &mut socket,
                200,
                "application/grpc-web-text",
                "Connection: close\r\n",
                &body,
            );
        });
        let runtime = runtime(false);
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);
        let client = GrpcWebClient::with_config(GrpcWebClientConfig {
            max_body_size: body_limit,
            ..config(ContentType::GrpcWebText)
        })
        .unwrap();
        runtime.block_on_with_cx(cx.clone(), async {
            let error = client
                .unary(&cx, &url, Request::new(Bytes::new()), IdentityCodec)
                .await
                .unwrap_err();
            assert_eq!(error.code(), expected);
        });
        peer.join().unwrap();
        assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
    }
}

#[test]
fn request_bounds_reserved_metadata_and_expired_calls_fail_before_connect() {
    let (listener, url) = listener();
    let runtime = runtime(false);
    let cx = runtime.request_cx_with_budget(Budget::INFINITE);
    let client = GrpcWebClient::with_config(GrpcWebClientConfig {
        max_send_message_size: 2,
        ..config(ContentType::GrpcWeb)
    })
    .unwrap();
    runtime.block_on_with_cx(cx.clone(), async {
        assert_eq!(
            client
                .unary(
                    &cx,
                    &url,
                    Request::new(Bytes::from_static(b"large")),
                    IdentityCodec
                )
                .await
                .unwrap_err()
                .code(),
            Code::ResourceExhausted
        );
        for (key, value) in [
            ("content-length", "0"),
            ("grpc-timeout", "invalid"),
            ("grpc-encoding", "gzip"),
        ] {
            let mut metadata = Metadata::new();
            assert!(metadata.insert(key, value));
            let error = client
                .unary(
                    &cx,
                    &url,
                    Request::with_metadata(Bytes::new(), metadata),
                    IdentityCodec,
                )
                .await
                .unwrap_err();
            assert_eq!(error.code(), Code::InvalidArgument);
        }
        let mut metadata = Metadata::new();
        assert!(metadata.insert("grpc-timeout", "0n"));
        let error = client
            .unary(
                &cx,
                &url,
                Request::with_metadata(Bytes::new(), metadata),
                IdentityCodec,
            )
            .await
            .unwrap_err();
        assert_eq!(error.code(), Code::DeadlineExceeded);
        assert!(
            matches!(listener.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock)
        );
    });
    assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
}
