//! Opt-in malformed HTTP fields must not cancel sibling requests or poison
//! their shared HPACK state. These tests include a real native listener.

#![cfg(not(target_arch = "wasm32"))]
#![recursion_limit = "256"]

use std::future::Future;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use asupersync::Cx;
use asupersync::bytes::{Bytes, BytesMut};
use asupersync::codec::Decoder as _;
use asupersync::http::h1::server::HostPolicy;
use asupersync::http::h1::types::{Request, Response};
use asupersync::http::h2::connection::{CLIENT_PREFACE, ReceivedFrame, RstStreamRateLimit};
use asupersync::http::h2::frame::{
    ContinuationFrame, Frame, HeadersFrame, PushPromiseFrame, SettingsFrame,
};
use asupersync::http::h2::listener::{Http2Listener, Http2ListenerConfig};
use asupersync::http::h2::{Connection, ErrorCode, FrameCodec, Header, HpackDecoder, Settings};
use asupersync::runtime::RuntimeBuilder;
use asupersync::sync::Notify;

fn plain_string(bytes: &mut Vec<u8>, value: &[u8]) {
    assert!(value.len() < 127, "test strings use one-octet lengths");
    bytes.push(u8::try_from(value.len()).unwrap());
    bytes.extend_from_slice(value);
}

fn literal(bytes: &mut Vec<u8>, name: &[u8], value: &[u8]) {
    bytes.push(0x40); // Literal with incremental indexing and a literal name.
    plain_string(bytes, name);
    plain_string(bytes, value);
}

fn request_block(path: &str) -> Vec<u8> {
    let mut bytes = vec![0x82, 0x86, 0x04]; // GET, http, literal :path.
    plain_string(&mut bytes, path.as_bytes());
    bytes.push(0x01); // Literal :authority, without indexing.
    plain_string(&mut bytes, b"localhost");
    bytes
}

fn rejected_block() -> Vec<u8> {
    let mut bytes = request_block("/rejected");
    literal(&mut bytes, b"X-invalid", b"bad");
    // Index 62 must refer to this later insertion after the rejected request.
    literal(&mut bytes, b"x-after-error", b"synchronized");
    bytes
}

fn survivor_block() -> Vec<u8> {
    let mut bytes = request_block("/survivor");
    bytes.push(0xbe); // Dynamic table index 62.
    bytes
}

#[test]
fn decoder_rejects_stream_zero_before_changing_compression_state() {
    let mut decoder = HpackDecoder::new();
    let mut encoded = Vec::new();
    literal(&mut encoded, b"x-valid", b"value");
    let mut input = Bytes::from(encoded);
    let original_len = input.len();
    let error = decoder.decode_for_stream(&mut input, 0).unwrap_err();
    assert_eq!(error.code, ErrorCode::ProtocolError);
    assert!(error.is_connection_error());
    assert_eq!(input.len(), original_len);
    assert_eq!(decoder.dynamic_table_size(), 0);
}

#[test]
fn decoder_finishes_rejected_blocks_and_revalidates_indexed_entries() {
    for (name, value) in [
        (b"X-invalid".as_slice(), b"bad".as_slice()),
        (b"x invalid".as_slice(), b"bad".as_slice()),
        (b"".as_slice(), b"bad".as_slice()),
        (b"x-invalid".as_slice(), b"bad\0value".as_slice()),
        (b"x-invalid".as_slice(), b"bad\rvalue".as_slice()),
        (b"x-invalid".as_slice(), b"bad\nvalue".as_slice()),
    ] {
        let mut decoder = HpackDecoder::new();
        let mut encoded = Vec::new();
        literal(&mut encoded, name, value);
        literal(&mut encoded, b"x-after-error", b"synchronized");
        let mut input = Bytes::from(encoded);
        let error = decoder.decode_for_stream(&mut input, 3).unwrap_err();
        assert_eq!(error.code, ErrorCode::ProtocolError);
        assert_eq!(error.stream_id, Some(3));
        assert!(input.is_empty(), "the entire HPACK block must be consumed");
        let headers = decoder
            .decode_for_stream(&mut Bytes::from_static(&[0xbe]), 5)
            .unwrap();
        assert_eq!(headers, vec![Header::new("x-after-error", "synchronized")]);

        let error = decoder
            .decode_for_stream(&mut Bytes::from_static(&[0xbf]), 7)
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::ProtocolError);
        assert_eq!(error.stream_id, Some(7));
        // Disabling isolation must not expose an invalid cached entry.
        let error = decoder
            .decode(&mut Bytes::from_static(&[0xbf]))
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::CompressionError);
        assert!(error.is_connection_error());
    }
}

#[test]
fn compression_and_resource_errors_override_deferred_field_errors() {
    for tail in [
        vec![0x80],             // Invalid indexed field zero.
        vec![0x20],             // Table update after a field.
        vec![0x40, 0x04, b'x'], // Truncated literal name.
    ] {
        let mut bytes = Vec::new();
        literal(&mut bytes, b"X-invalid", b"bad");
        bytes.extend_from_slice(&tail);
        let error = HpackDecoder::new()
            .decode_for_stream(&mut Bytes::from(bytes), 3)
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::CompressionError);
        assert!(error.is_connection_error());
    }

    let mut decoder = HpackDecoder::new();
    decoder.set_max_header_list_size(64);
    let mut bytes = Vec::new();
    literal(&mut bytes, b"X-invalid", b"bad");
    literal(&mut bytes, b"x-after-error", b"synchronized");
    let error = decoder
        .decode_for_stream(&mut Bytes::from(bytes), 3)
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::CompressionError);
    assert!(error.is_connection_error());
}

#[test]
fn raw_non_utf8_names_and_pseudo_values_remain_connection_fatal() {
    for bytes in [
        vec![0x40, 0x01, 0xff, 0x00], // Literal name is not UTF-8.
        vec![0x41, 0x01, 0xff],       // :authority value is not UTF-8.
    ] {
        let error = HpackDecoder::new()
            .decode_for_stream(&mut Bytes::from(bytes), 3)
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::CompressionError);
        assert!(error.is_connection_error());
    }
}

#[test]
fn malformed_reset_race_blocks_still_update_the_shared_table() {
    let mut connection = Connection::server(Settings::default());
    connection.set_malformed_header_isolation(true);
    connection
        .process_frame(Frame::Settings(SettingsFrame::new(Vec::new())))
        .unwrap();
    connection
        .process_frame(Frame::Headers(HeadersFrame::new(
            1,
            request_block("/upload").into(),
            false,
            true,
        )))
        .unwrap();
    connection.reset_stream(1, ErrorCode::Cancel);
    while connection.next_frame().is_some() {}

    assert!(
        connection
            .process_frame(Frame::Headers(HeadersFrame::new(
                1,
                rejected_block().into(),
                true,
                true,
            )))
            .unwrap()
            .is_none()
    );
    match connection
        .process_frame(Frame::Headers(HeadersFrame::new(
            3,
            survivor_block().into(),
            true,
            true,
        )))
        .unwrap()
    {
        Some(ReceivedFrame::Headers {
            headers, stream_id, ..
        }) => {
            assert_eq!(stream_id, 3);
            assert!(headers.contains(&Header::new("x-after-error", "synchronized")));
        }
        other => panic!("expected a usable sibling stream, got {other:?}"),
    }
}

#[test]
fn malformed_push_blocks_preserve_the_associated_response() {
    for refuse in [false, true] {
        let mut settings = Settings::client();
        settings.enable_push = true;
        let mut connection = Connection::client(settings);
        connection.set_malformed_header_isolation(true);
        connection
            .process_frame(Frame::Settings(SettingsFrame::new(Vec::new())))
            .unwrap();
        let associated = connection
            .open_stream(
                vec![
                    Header::new(":method", "GET"),
                    Header::new(":scheme", "http"),
                    Header::new(":path", "/"),
                    Header::new(":authority", "localhost"),
                ],
                true,
            )
            .unwrap();
        if refuse {
            connection.goaway(ErrorCode::NoError, Bytes::new());
        }
        let result = connection.process_frame(Frame::PushPromise(PushPromiseFrame {
            stream_id: associated,
            promised_stream_id: 2,
            header_block: rejected_block().into(),
            end_headers: true,
        }));
        if refuse {
            assert!(result.unwrap().is_none());
        } else {
            let error = result.unwrap_err();
            assert_eq!(error.code, ErrorCode::ProtocolError);
            assert_eq!(error.stream_id, Some(2));
            connection.reset_stream(2, ErrorCode::ProtocolError);
        }
        match connection
            .process_frame(Frame::Headers(HeadersFrame::new(
                associated,
                Bytes::from_static(&[0x88, 0xbe]), // :status 200 + index 62.
                true,
                true,
            )))
            .unwrap()
        {
            Some(ReceivedFrame::Headers {
                stream_id, headers, ..
            }) => {
                assert_eq!(stream_id, associated);
                assert!(headers.contains(&Header::new("x-after-error", "synchronized")));
            }
            other => panic!("associated response lost after rejected push: {other:?}"),
        }
    }
}

#[test]
fn isolated_field_errors_still_consume_the_peer_reset_budget() {
    let mut connection =
        Connection::server(Settings::default()).rst_stream_rate_limit(RstStreamRateLimit {
            max_rst_streams: 1,
            rst_window_ms: 30_000,
        });
    connection.set_malformed_header_isolation(true);
    connection
        .process_frame(Frame::Settings(SettingsFrame::new(Vec::new())))
        .unwrap();
    for stream_id in [1, 3] {
        let error = connection
            .process_frame(Frame::Headers(HeadersFrame::new(
                stream_id,
                rejected_block().into(),
                true,
                true,
            )))
            .unwrap_err();
        if stream_id == 1 {
            assert_eq!(error.code, ErrorCode::ProtocolError);
            assert_eq!(error.stream_id, Some(stream_id));
            connection.reset_stream(stream_id, ErrorCode::ProtocolError);
        } else {
            assert_eq!(error.code, ErrorCode::EnhanceYourCalm);
            assert!(error.is_connection_error());
        }
    }
}

struct Peer {
    socket: TcpStream,
    codec: FrameCodec,
    input: BytesMut,
}

impl Peer {
    fn connect(address: SocketAddr) -> Self {
        let mut socket = TcpStream::connect(address).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        socket.write_all(CLIENT_PREFACE).unwrap();
        let mut peer = Self {
            socket,
            codec: FrameCodec::new(),
            input: BytesMut::new(),
        };
        peer.send(Frame::Settings(SettingsFrame::new(Vec::new())));
        peer
    }

    fn send(&mut self, frame: Frame) {
        let mut bytes = BytesMut::new();
        frame.encode(&mut bytes).unwrap();
        self.socket.write_all(&bytes).unwrap();
    }

    fn headers(&mut self, stream_id: u32, block: Vec<u8>, fragmented: bool) {
        let block = Bytes::from(block);
        if fragmented {
            let split = block.len() - 3;
            self.send(Frame::Headers(HeadersFrame::new(
                stream_id,
                block.slice(..split),
                true,
                false,
            )));
            self.send(Frame::Continuation(ContinuationFrame {
                stream_id,
                header_block: block.slice(split..),
                end_headers: true,
            }));
        } else {
            self.send(Frame::Headers(HeadersFrame::new(
                stream_id, block, true, true,
            )));
        }
    }

    fn receive(&mut self) -> Frame {
        loop {
            if let Some(frame) = self.codec.decode(&mut self.input).unwrap() {
                if let Frame::Settings(settings) = &frame
                    && !settings.ack
                {
                    self.send(Frame::Settings(SettingsFrame::ack()));
                }
                return frame;
            }
            let mut bytes = [0; 16_384];
            let count = self
                .socket
                .read(&mut bytes)
                .expect("native response watchdog");
            assert_ne!(count, 0, "expected a terminal HTTP/2 frame before EOF");
            self.input.extend_from_slice(&bytes[..count]);
        }
    }

    fn empty_response(&mut self, stream_id: u32) {
        loop {
            match self.receive() {
                Frame::Headers(headers) if headers.stream_id == stream_id => {
                    assert!(headers.end_stream);
                    return;
                }
                Frame::RstStream(reset) => panic!("healthy request reset: {reset:?}"),
                Frame::GoAway(goaway) => panic!("healthy connection closed: {goaway:?}"),
                _ => {}
            }
        }
    }
}

struct Gate {
    released: AtomicBool,
    notify: Notify,
}

// An assertion failure must not leave the native handler permanently parked.
struct ReleaseOnDrop(Arc<Gate>);

impl Drop for ReleaseOnDrop {
    fn drop(&mut self) {
        self.0.released.store(true, Ordering::Release);
        self.0.notify.notify_waiters();
    }
}

fn config() -> Http2ListenerConfig {
    Http2ListenerConfig::default()
        .host_policy(HostPolicy::allow_list(vec!["localhost".to_owned()]))
        .drain_timeout(Duration::from_secs(2))
        .hard_drain_timeout(Duration::from_secs(5))
}

fn native_isolation(workers: usize, fragmented: bool) {
    let runtime = RuntimeBuilder::new()
        .worker_threads(workers)
        .with_sharded_state(workers == 2)
        .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
        .build()
        .unwrap();
    let gate = Arc::new(Gate {
        released: AtomicBool::new(false),
        notify: Notify::new(),
    });
    let release = ReleaseOnDrop(Arc::clone(&gate));
    let (entered, pending) = std::sync::mpsc::channel();
    let calls = Arc::new(AtomicUsize::new(0));
    let handler_calls = Arc::clone(&calls);
    let listener = runtime
        .block_on(Http2Listener::bind_with_config(
            "127.0.0.1:0",
            move |request: Request| {
                let gate = Arc::clone(&gate);
                let entered = entered.clone();
                let calls = Arc::clone(&handler_calls);
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    if request.uri == "/held" {
                        let cx = Cx::current().expect("owned native request");
                        entered.send(cx.clone()).unwrap();
                        gate.notify
                            .wait_until(|| gate.released.load(Ordering::Acquire))
                            .await;
                        assert!(!cx.is_cancel_requested(), "sibling cancellation leaked");
                    } else {
                        assert_eq!(request.uri, "/survivor");
                        assert!(request.headers.iter().any(|(name, value)| {
                            name == "x-after-error" && value == "synchronized"
                        }));
                    }
                    Response::new(200, "OK", Vec::new())
                }
            },
            config(),
        ))
        .unwrap()
        .with_malformed_header_isolation(true);
    let address = listener.local_addr().unwrap();
    let manager = listener.connection_manager().clone();
    let in_flight = listener.in_flight_requests();
    let handle = runtime.handle();
    let serving: Pin<Box<dyn Future<Output = _> + Send>> =
        Box::pin(async move { listener.run(&handle).await });
    let run = runtime.handle().spawn(serving);
    let mut peer = Peer::connect(address);
    peer.headers(1, request_block("/held"), false);
    let held = pending.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(in_flight.load(Ordering::SeqCst), 1);

    peer.headers(3, rejected_block(), fragmented);
    loop {
        match peer.receive() {
            Frame::RstStream(reset) => {
                assert_eq!(reset.stream_id, 3);
                assert_eq!(reset.error_code, ErrorCode::ProtocolError);
                break;
            }
            Frame::GoAway(goaway) => panic!("malformed sibling killed connection: {goaway:?}"),
            _ => {}
        }
    }
    assert!(!held.is_cancel_requested());
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "bad request must not dispatch"
    );
    peer.headers(5, survivor_block(), false);
    peer.empty_response(5);
    assert!(!held.is_cancel_requested());
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    drop(release);
    peer.empty_response(1);
    drop(peer);

    assert!(manager.begin_drain(Duration::from_secs(2)));
    let stats = runtime.block_on(run).unwrap();
    assert!(stats.drain_report.unwrap().reached_quiescence);
    let started = Instant::now();
    while !runtime.is_quiescent() {
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "owned tasks did not retire"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(manager.active_count(), 0);
    assert_eq!(in_flight.load(Ordering::SeqCst), 0);
    assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
    assert_eq!(runtime.draining_region_count(), 0);
}

#[test]
fn native_listener_isolates_malformed_headers_and_preserves_live_siblings() {
    for workers in [1, 2] {
        for fragmented in [false, true] {
            native_isolation(workers, fragmented);
        }
    }
}

#[test]
fn native_legacy_and_compression_failures_still_close_the_connection() {
    for isolate in [false, true] {
        let runtime = RuntimeBuilder::new()
            .worker_threads(1)
            .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
            .build()
            .unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let handler_calls = Arc::clone(&calls);
        let listener = runtime
            .block_on(Http2Listener::bind_with_config(
                "127.0.0.1:0",
                move |_: Request| {
                    handler_calls.fetch_add(1, Ordering::SeqCst);
                    async { Response::new(200, "OK", Vec::new()) }
                },
                config(),
            ))
            .unwrap()
            .with_malformed_header_isolation(isolate);
        let address = listener.local_addr().unwrap();
        let manager = listener.connection_manager().clone();
        let handle = runtime.handle();
        let serving: Pin<Box<dyn Future<Output = _> + Send>> =
            Box::pin(async move { listener.run(&handle).await });
        let run = runtime.handle().spawn(serving);
        let mut peer = Peer::connect(address);
        let mut block = rejected_block();
        if isolate {
            // An actual compression error AFTER the semantic failure wins.
            block.push(0x80);
        }
        peer.headers(1, block, false);
        loop {
            match peer.receive() {
                Frame::GoAway(goaway) => {
                    assert_eq!(goaway.error_code, ErrorCode::CompressionError);
                    break;
                }
                Frame::RstStream(reset) => panic!("connection error was downgraded: {reset:?}"),
                _ => {}
            }
        }
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        drop(peer);
        assert!(manager.begin_drain(Duration::from_secs(2)));
        let stats = runtime.block_on(run).unwrap();
        assert!(stats.drain_report.unwrap().reached_quiescence);
        assert_eq!(manager.active_count(), 0);
    }
}
