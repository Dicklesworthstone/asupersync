//! RFC 7692 over real sockets, including the public upgrade and split paths.
//! The raw peer constructs frames independently and uses published RFC/zlib
//! vectors, so a matching encoder/decoder bug cannot satisfy these assertions.

#![cfg(all(not(target_arch = "wasm32"), feature = "test-internals", feature = "compression"))]
#![recursion_limit = "256"]

use asupersync::Cx;
use asupersync::io::{AsyncRead, AsyncWrite, ReadBuf};
use asupersync::net::TcpStream;
use asupersync::net::websocket::{CloseReason, Message, WebSocket, WebSocketAcceptor, WebSocketConfig, WsError};
use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::util::entropy::{DetEntropy, EntropySource};
use std::future::{Future, poll_fn};
use std::io::{Read, Write};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

/// Client masking entropy. `Cx::entropy_handle` is crate-private, so the test
/// passes a public deterministic source.
fn client_entropy() -> Arc<dyn EntropySource> {
    Arc::new(DetEntropy::new(0x5753_636f_6d70))
}

const WATCHDOG: Duration = Duration::from_secs(5);
const PROFILE: &str = "permessage-deflate; server_no_context_takeover; client_no_context_takeover";
const HELLO: &[u8] = &[0xf2, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00];
const UPGRADE: &[u8] = b"GET /ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n\r\n";

fn native_runtime(workers: usize) -> Runtime {
    let builder = if workers == 0 { RuntimeBuilder::current_thread() }
        else { RuntimeBuilder::multi_thread().worker_threads(workers) };
    builder.with_reactor(asupersync::runtime::reactor::create_reactor().unwrap()).build().unwrap()
}

fn assert_retired(runtime: &Runtime) {
    let started = Instant::now();
    while !runtime.is_quiescent() {
        assert!(started.elapsed() < WATCHDOG, "WebSocket owner did not retire");
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(runtime.task_inspector(Default::default()).list_tasks().is_empty());
    assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
    assert_eq!(runtime.draining_region_count(), 0);
}

fn pair() -> (std::net::TcpStream, std::net::TcpStream) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let peer = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (socket, _) = listener.accept().unwrap();
    socket.set_nonblocking(true).unwrap();
    peer.set_read_timeout(Some(WATCHDOG)).unwrap();
    peer.set_write_timeout(Some(WATCHDOG)).unwrap();
    (socket, peer)
}

fn http_head(peer: &mut std::net::TcpStream) -> Vec<u8> {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        peer.read_exact(&mut byte).expect("HTTP upgrade head");
        head.push(byte[0]);
        assert!(head.len() <= 16 * 1024);
    }
    head
}

fn frame(first: u8, payload: &[u8], masked: bool) -> Vec<u8> {
    assert!(payload.len() <= 125);
    let mut wire = vec![first, payload.len() as u8 | if masked { 0x80 } else { 0 }];
    let mask = [0x31, 0x47, 0x53, 0x61];
    if masked { wire.extend_from_slice(&mask); }
    wire.extend(payload.iter().enumerate().map(|(index, byte)| {
        if masked { byte ^ mask[index % 4] } else { *byte }
    }));
    wire
}

fn control(peer: &mut std::net::TcpStream, masked: bool) -> (u8, Vec<u8>) {
    let mut header = [0; 2];
    peer.read_exact(&mut header).expect("control frame");
    assert_eq!(header[0] & 0xf0, 0x80, "control frames must never be compressed");
    assert_eq!(header[1] & 0x80 != 0, masked);
    let length = usize::from(header[1] & 0x7f);
    assert!(length <= 125);
    let mut mask = [0; 4];
    if masked { peer.read_exact(&mut mask).unwrap(); }
    let mut payload = vec![0; length];
    peer.read_exact(&mut payload).unwrap();
    if masked { for (index, byte) in payload.iter_mut().enumerate() { *byte ^= mask[index % 4]; } }
    (header[0] & 0x0f, payload)
}

#[derive(Clone, Copy, Debug)]
enum Role { Client, Server, Split }

#[derive(Clone, Copy, Debug)]
enum Input { Valid, Expansion, InvalidText, InvalidDeflate, RsvContinuation, RsvControl, EncodedLimit, Legacy }

fn incoming_wire(input: Input, masked: bool) -> Vec<u8> {
    match input {
        Input::Valid => {
            let mut wire = frame(0x41, &HELLO[..3], masked);
            wire.extend(frame(0x89, b"probe", masked));
            wire.extend(frame(0x80, &HELLO[3..], masked));
            wire.extend(frame(0xc1, HELLO, masked));
            wire.extend(frame(0x81, b"clear", masked));
            wire.extend(frame(0xc1, &[0], masked));
            wire.extend(frame(0xc2, &[0], masked));
            wire.extend(frame(0x88, &[0x03, 0xe8], masked));
            wire
        }
        // Python zlib.compressobj(wbits=-15), Z_SYNC_FLUSH, last four bytes removed.
        Input::Expansion => frame(0xc2, &[74, 76, 28, 5, 163, 96, 20, 140, 84, 0, 0], masked), // 1024 'a's
        Input::InvalidText => frame(0xc1, &[250, 15, 0], masked), // one byte 0xff
        Input::InvalidDeflate => frame(0xc2, &[0xff], masked),
        Input::RsvContinuation => {
            let mut wire = frame(0x41, &HELLO[..3], masked);
            wire.extend(frame(0xc0, &HELLO[3..], masked));
            wire
        }
        Input::RsvControl => frame(0xc9, b"probe", masked),
        Input::EncodedLimit => {
            let mut wire = frame(0x42, &[0; 4], masked);
            wire.extend(frame(0x80, &[0; 5], masked));
            wire
        }
        Input::Legacy => frame(0xc1, HELLO, masked),
    }
}

// The same expected user-visible behavior is exercised through all three
// public receivers; the protocol bytes and error expectations are independent.
macro_rules! exercise_receiver {
    ($ws:ident, $cx:ident, $input:ident) => {{
        if matches!($input, Input::Valid) {
            for expected in ["Hello", "Hello", "clear", ""] {
                let message = $ws.recv(&$cx).await.unwrap().unwrap();
                assert!(matches!(message, Message::Text(ref text) if text == expected), "{message:?}");
            }
            assert!(matches!($ws.recv(&$cx).await.unwrap(), Some(Message::Binary(bytes)) if bytes.is_empty()));
            assert!(matches!($ws.recv(&$cx).await.unwrap(), Some(Message::Close(_))));
        } else {
            let error = $ws.recv(&$cx).await.expect_err("invalid compressed input must fail");
            match $input {
                Input::Expansion | Input::EncodedLimit => assert!(matches!(error, WsError::PayloadTooLarge { .. }), "{error:?}"),
                Input::InvalidText => assert!(matches!(error, WsError::InvalidUtf8), "{error:?}"),
                Input::InvalidDeflate => assert!(matches!(error, WsError::ProtocolViolation(_)), "{error:?}"),
                Input::RsvContinuation | Input::RsvControl | Input::Legacy => assert!(matches!(error, WsError::ReservedBitsSet), "{error:?}"),
                Input::Valid => unreachable!(),
            }
        }
        assert!($ws.is_closed(), "terminal input retires the connection");
    }};
}

fn raw_scenario(workers: usize, role: Role, input: Input) {
    let (socket, mut peer) = pair();
    let server = matches!(role, Role::Server);
    let peer = std::thread::spawn(move || {
        if server {
            let response = String::from_utf8(http_head(&mut peer)).unwrap();
            assert!(response.starts_with("HTTP/1.1 101 "));
            assert!(response.contains(PROFILE));
        }
        peer.write_all(&incoming_wire(input, server)).unwrap();
        if matches!(input, Input::Valid) {
            assert_eq!(control(&mut peer, !server), (10, b"probe".to_vec()));
            assert_eq!(control(&mut peer, !server), (8, vec![0x03, 0xe8]));
        }
        let mut byte = [0];
        assert_eq!(peer.read(&mut byte).expect("transport EOF"), 0);
    });
    let runtime = native_runtime(workers);
    runtime.block_on(async {
        let mut task = runtime.handle().try_spawn(async move {
            let cx = Cx::current().unwrap();
            let socket = TcpStream::from_std(socket).unwrap();
            let max = if matches!(input, Input::EncodedLimit) { 8 } else { 32 };
            match role {
                Role::Server => {
                    let mut ws = WebSocketAcceptor::new().permessage_deflate()
                        .max_message_size(max).ping_interval(None).accept(&cx, UPGRADE, socket).await.unwrap();
                    assert!(ws.compression_enabled());
                    exercise_receiver!(ws, cx, input);
                }
                Role::Client | Role::Split => {
                    let config = WebSocketConfig::new().max_message_size(max).ping_interval(None);
                    let mut ws = if matches!(input, Input::Legacy) { WebSocket::from_upgraded(socket, config) }
                        else { WebSocket::from_upgraded_with_extensions(socket, config, &[PROFILE.to_owned()], client_entropy()).unwrap() };
                    if matches!(role, Role::Split) {
                        let (mut read, write) = ws.split();
                        exercise_receiver!(read, cx, input);
                        drop(write);
                    } else { exercise_receiver!(ws, cx, input); }
                }
            }
        }).unwrap();
        asupersync::time::timeout(asupersync::time::wall_now(), WATCHDOG, &mut task).await.expect("compressed receiver must complete");
    });
    peer.join().expect("independent RFC peer completed");
    assert_retired(&runtime);
}

#[test]
fn native_rfc_vectors_fragmentation_control_and_fail_closed_limits() {
    for workers in [0, 2] {
        for role in [Role::Client, Role::Server, Role::Split] {
            for input in [Input::Valid, Input::Expansion, Input::InvalidText, Input::InvalidDeflate,
                Input::RsvContinuation, Input::RsvControl, Input::EncodedLimit] {
                raw_scenario(workers, role, input);
            }
        }
        raw_scenario(workers, Role::Client, Input::Legacy);
        raw_scenario(workers, Role::Split, Input::Legacy);
    }
}

#[test]
fn native_client_and_acceptor_negotiate_compressed_split_roundtrips() {
    for workers in [0, 2] {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let text = "α hello, compressed WebSocket! ".repeat(4096);
        let server_text = text.clone();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket.set_read_timeout(Some(WATCHDOG)).unwrap();
            let request = http_head(&mut socket);
            assert!(String::from_utf8_lossy(&request).contains("permessage-deflate"));
            socket.set_nonblocking(true).unwrap();
            let runtime = native_runtime(workers);
            runtime.block_on(async {
                let mut task = runtime.handle().try_spawn(async move {
                    let cx = Cx::current().unwrap();
                    let mut ws = WebSocketAcceptor::new().permessage_deflate().ping_interval(None)
                        .accept(&cx, &request, TcpStream::from_std(socket).unwrap()).await.unwrap();
                    assert!(ws.compression_enabled());
                    for _ in 0..2 {
                        assert!(matches!(ws.recv(&cx).await.unwrap(), Some(Message::Text(value)) if value == server_text));
                        ws.send(&cx, Message::Binary(server_text.as_bytes().to_vec().into())).await.unwrap();
                    }
                    assert!(matches!(ws.recv(&cx).await.unwrap(), Some(Message::Close(_))));
                }).unwrap();
                asupersync::time::timeout(asupersync::time::wall_now(), WATCHDOG, &mut task).await.unwrap();
            });
            assert_retired(&runtime);
        });
        let runtime = native_runtime(workers);
        runtime.block_on(async {
            let mut task = runtime.handle().try_spawn(async move {
                let cx = Cx::current().unwrap();
                let ws = WebSocket::connect_with_compression(&cx, &format!("ws://{address}/ws"),
                    WebSocketConfig::new().ping_interval(None)).await.unwrap();
                assert!(ws.compression_enabled());
                let (mut read, mut write) = ws.split();
                write.send(&cx, Message::Text(text.clone())).await.unwrap();
                assert!(matches!(read.recv(&cx).await.unwrap(), Some(Message::Binary(bytes)) if bytes.as_ref() == text.as_bytes()));
                let mut ws = read.reunite(write).expect("compressed state survives split/reunite");
                assert!(ws.compression_enabled());
                ws.send(&cx, Message::Text(text.clone())).await.unwrap();
                assert!(matches!(ws.recv(&cx).await.unwrap(), Some(Message::Binary(bytes)) if bytes.as_ref() == text.as_bytes()));
                ws.close(&cx, CloseReason::normal()).await.unwrap();
            }).unwrap();
            asupersync::time::timeout(asupersync::time::wall_now(), WATCHDOG, &mut task).await.unwrap();
        });
        server.join().unwrap();
        assert_retired(&runtime);
    }
}

#[test]
fn native_unsupported_offer_is_rejected_before_switching_protocols() {
    let (socket, mut peer) = pair();
    let request = String::from_utf8(UPGRADE.to_vec()).unwrap()
        .replace("permessage-deflate; client_max_window_bits", "permessage-deflate; server_max_window_bits=14");
    let peer = std::thread::spawn(move || {
        let mut response = Vec::new();
        peer.read_to_end(&mut response).unwrap();
        assert!(response.is_empty(), "unsupported compression must never publish HTTP 101");
    });
    let runtime = native_runtime(2);
    runtime.block_on(async {
        let mut task = runtime.handle().try_spawn(async move {
            let cx = Cx::current().unwrap();
            let result = WebSocketAcceptor::new().permessage_deflate()
                .accept(&cx, request.as_bytes(), TcpStream::from_std(socket).unwrap()).await;
            assert!(matches!(result, Err(asupersync::net::websocket::WsAcceptError::Handshake(_))));
        }).unwrap();
        asupersync::time::timeout(asupersync::time::wall_now(), WATCHDOG, &mut task).await.unwrap();
    });
    peer.join().unwrap();
    assert_retired(&runtime);
}

#[test]
fn native_client_validates_actual_response_parameters_and_allows_safe_omission() {
    use asupersync::net::websocket::{HttpRequest, WsConnectError, compute_accept_key};
    for (extension, accepted) in [
        ("permessage-deflate; server_no_context_takeover; server_max_window_bits=\"15\"", true),
        ("permessage-deflate", false),
        ("permessage-deflate; server_no_context_takeover=1", false),
    ] {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let peer = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket.set_read_timeout(Some(WATCHDOG)).unwrap();
            socket.set_write_timeout(Some(WATCHDOG)).unwrap();
            let request = HttpRequest::parse(&http_head(&mut socket)).unwrap();
            let key = compute_accept_key(request.header("sec-websocket-key").unwrap());
            let response = format!("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {key}\r\nSec-WebSocket-Extensions: {extension}\r\n\r\n");
            socket.write_all(response.as_bytes()).unwrap();
            let mut byte = [0];
            assert_eq!(socket.read(&mut byte).unwrap(), 0);
        });
        let runtime = native_runtime(2);
        runtime.block_on(async {
            let mut task = runtime.handle().try_spawn(async move {
                let cx = Cx::current().unwrap();
                let result = WebSocket::connect_with_compression(&cx, &format!("ws://{address}/ws"), WebSocketConfig::new()).await;
                if accepted { assert!(result.unwrap().compression_enabled()); }
                else { assert!(matches!(result, Err(WsConnectError::Handshake(_)))); }
            }).unwrap();
            asupersync::time::timeout(asupersync::time::wall_now(), WATCHDOG, &mut task).await.unwrap();
        });
        peer.join().unwrap();
        assert_retired(&runtime);
    }
}

struct ReadWitness {
    socket: TcpStream,
    bytes: Arc<AtomicUsize>,
}

impl AsyncRead for ReadWitness {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buffer: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let before = buffer.filled().len();
        let result = Pin::new(&mut self.socket).poll_read(cx, buffer);
        if matches!(result, Poll::Ready(Ok(()))) {
            self.bytes.fetch_add(buffer.filled().len() - before, Ordering::AcqRel);
        }
        result
    }
}

impl AsyncWrite for ReadWitness {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buffer: &[u8]) -> Poll<std::io::Result<usize>> { Pin::new(&mut self.socket).poll_write(cx, buffer) }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> { Pin::new(&mut self.socket).poll_flush(cx) }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> { Pin::new(&mut self.socket).poll_shutdown(cx) }
}

#[test]
fn native_abandoned_receive_preserves_partial_compressed_message_across_split() {
    for workers in [0, 2] {
        let (socket, mut peer) = pair();
        let (resume, wait) = std::sync::mpsc::channel();
        let first = frame(0x41, &HELLO[..3], false);
        let first_len = first.len();
        let peer = std::thread::spawn(move || {
            peer.write_all(&first).unwrap();
            wait.recv_timeout(WATCHDOG).expect("fragment was assembled before dropping recv");
            peer.write_all(&frame(0x80, &HELLO[3..], false)).unwrap();
            let mut byte = [0];
            assert_eq!(peer.read(&mut byte).unwrap(), 0);
        });
        let runtime = native_runtime(workers);
        runtime.block_on(async {
            let mut task = runtime.handle().try_spawn(async move {
                let cx = Cx::current().unwrap();
                let bytes = Arc::new(AtomicUsize::new(0));
                let socket = ReadWitness { socket: TcpStream::from_std(socket).unwrap(), bytes: Arc::clone(&bytes) };
                let mut ws = WebSocket::from_upgraded_with_extensions(socket, WebSocketConfig::new().ping_interval(None),
                    &[PROFILE.to_owned()], client_entropy()).unwrap();
                {
                    let mut future = std::pin::pin!(ws.recv(&cx));
                    poll_fn(|task| {
                        assert!(future.as_mut().poll(task).is_pending());
                        if bytes.load(Ordering::Acquire) >= first_len { Poll::Ready(()) } else { Poll::Pending }
                    }).await;
                }
                let (read, write) = ws.split();
                let mut ws = read.reunite(write).unwrap();
                resume.send(()).unwrap();
                assert!(matches!(ws.recv(&cx).await.unwrap(), Some(Message::Text(text)) if text == "Hello"));
            }).unwrap();
            asupersync::time::timeout(asupersync::time::wall_now(), WATCHDOG, &mut task).await.unwrap();
        });
        peer.join().unwrap();
        assert_retired(&runtime);
    }
}

/// Raw DEFLATE bits, least significant first; Huffman codes go most
/// significant bit first (RFC 1951 section 3.1.1).
#[derive(Default)]
struct Bits {
    out: Vec<u8>,
    used: usize,
}

impl Bits {
    fn put(&mut self, value: u32, count: u32) {
        for bit in 0..count {
            if self.used % 8 == 0 {
                self.out.push(0);
            }
            *self.out.last_mut().unwrap() |= (((value >> bit) & 1) as u8) << (self.used % 8);
            self.used += 1;
        }
    }

    fn code(&mut self, code: u32, count: u32) {
        for bit in (0..count).rev() {
            self.put((code >> bit) & 1, 1);
        }
    }
}

/// One fixed-Huffman block: a NUL literal, then `runs` matches of length 258
/// at distance 1, then an optional final literal of 144..=255 (a 9-bit code),
/// then the flush header whose tail RFC 7692 removes. Python zlib decodes
/// `zero_runs(32_514, None)` (52,838 bytes) to 8,388,613 NULs, and
/// `zero_runs(32_514, Some(0xff))` (52,839 bytes) to those NULs plus 0xFF.
fn zero_runs(runs: usize, last: Option<u8>) -> Vec<u8> {
    let mut bits = Bits::default();
    bits.put(0, 1);
    bits.put(1, 2);
    bits.code(0x30, 8);
    for _ in 0..runs {
        bits.code(0xc5, 8);
        bits.code(0, 5);
    }
    if let Some(byte) = last {
        assert!(byte >= 144, "only 9-bit literals are encoded here");
        bits.code(0x190 + u32::from(byte - 144), 9);
    }
    bits.code(0, 7);
    bits.put(0, 3);
    bits.out
}

/// One frame with the 16-bit extended payload length (length code 126).
fn extended_frame(first: u8, payload: &[u8], masked: bool) -> Vec<u8> {
    let mut wire = vec![first, 0x7e | if masked { 0x80 } else { 0 }];
    wire.extend_from_slice(&u16::try_from(payload.len()).unwrap().to_be_bytes());
    let mask = [0x31, 0x47, 0x53, 0x61];
    if masked {
        wire.extend_from_slice(&mask);
    }
    wire.extend(payload.iter().enumerate().map(|(index, byte)| {
        if masked {
            byte ^ mask[index % 4]
        } else {
            *byte
        }
    }));
    wire
}

/// br-asupersync-ydis91: an 8 MiB message from 52 KB of DEFLATE decodes in
/// bounded steps with a yield between them, through every public receiver.
/// The receive that reads it is still Pending one poll later, and the decode
/// survives that receive being abandoned (and, for Split, the split itself).
fn large_compressed_scenario(workers: usize, role: Role) {
    const RUNS: usize = 32_514;
    let server = matches!(role, Role::Server);
    let wire = extended_frame(0xc2, &zero_runs(RUNS, None), server);
    let wire_len = wire.len();
    let (socket, mut peer) = pair();
    let peer = std::thread::spawn(move || {
        if server {
            assert!(
                String::from_utf8(http_head(&mut peer))
                    .unwrap()
                    .starts_with("HTTP/1.1 101 ")
            );
        }
        peer.write_all(&wire).unwrap();
        let mut byte = [0];
        assert_eq!(peer.read(&mut byte).expect("transport EOF"), 0);
    });
    let runtime = native_runtime(workers);
    runtime.block_on(async {
        let mut task = runtime
            .handle()
            .try_spawn(async move {
                let cx = Cx::current().unwrap();
                let bytes = Arc::new(AtomicUsize::new(0));
                let socket = ReadWitness {
                    socket: TcpStream::from_std(socket).unwrap(),
                    bytes: Arc::clone(&bytes),
                };
                // Every poll is Pending until the frame is read and one poll after.
                // Before the fix the poll that read it returned the whole message.
                macro_rules! abandon_mid_decode {
                    ($ws:ident) => {{
                        let mut future = std::pin::pin!($ws.recv(&cx));
                        let mut polls_after_read = 0;
                        poll_fn(|task| {
                            assert!(
                                future.as_mut().poll(task).is_pending(),
                                "decode finished inside one poll ({role:?}, {workers} workers)"
                            );
                            if bytes.load(Ordering::Acquire) == wire_len {
                                polls_after_read += 1;
                            }
                            if polls_after_read == 2 {
                                Poll::Ready(())
                            } else {
                                Poll::Pending
                            }
                        })
                        .await;
                    }};
                }
                macro_rules! finish_counting_yields {
                    ($ws:ident) => {{
                        let mut future = std::pin::pin!($ws.recv(&cx));
                        let mut pending = 0;
                        let received = poll_fn(|task| match future.as_mut().poll(task) {
                            Poll::Pending => {
                                pending += 1;
                                Poll::Pending
                            }
                            ready => ready,
                        })
                        .await;
                        (received, pending)
                    }};
                }
                let (received, pending) = match role {
                    Role::Server => {
                        let mut ws = WebSocketAcceptor::new()
                            .permessage_deflate()
                            .ping_interval(None)
                            .accept(&cx, UPGRADE, socket)
                            .await
                            .unwrap();
                        abandon_mid_decode!(ws);
                        finish_counting_yields!(ws)
                    }
                    Role::Client | Role::Split => {
                        let mut ws = WebSocket::from_upgraded_with_extensions(
                            socket,
                            WebSocketConfig::new().ping_interval(None),
                            &[PROFILE.to_owned()],
                            client_entropy(),
                        )
                        .unwrap();
                        abandon_mid_decode!(ws);
                        if matches!(role, Role::Split) {
                            let (mut read, _write) = ws.split();
                            finish_counting_yields!(read)
                        } else {
                            finish_counting_yields!(ws)
                        }
                    }
                };
                let Some(Message::Binary(data)) = received.unwrap() else {
                    panic!("one binary message ({role:?})")
                };
                assert_eq!(data.len(), 1 + 258 * RUNS);
                assert!(data.iter().all(|byte| *byte == 0));
                // 8 MiB at 256 KiB per step, about 2 MiB of it before abandoning.
                assert!(
                    pending >= 8,
                    "{pending} yields after resuming ({role:?}, {workers} workers)"
                );
            })
            .unwrap();
        asupersync::time::timeout(asupersync::time::wall_now(), WATCHDOG, &mut task)
            .await
            .expect("large compressed receive completes");
    });
    peer.join().expect("independent RFC peer completed");
    assert_retired(&runtime);
}

#[test]
fn native_large_compressed_message_decodes_across_polls_and_survives_abandoned_receive() {
    for workers in [0, 2] {
        for role in [Role::Client, Role::Server, Role::Split] {
            large_compressed_scenario(workers, role);
        }
    }
}

/// RFC 6455 §7.1.7 for a decode that spans polls: an 8 MiB compressed text
/// message whose last byte is not UTF-8 fails only after its final step. The
/// connection is then failed, so a later receive does not process the frame
/// sent behind it; the codec reports that it is poisoned.
fn large_invalid_text_scenario(workers: usize, role: Role) {
    const RUNS: usize = 32_514;
    let server = matches!(role, Role::Server);
    let mut wire = extended_frame(0xc1, &zero_runs(RUNS, Some(0xff)), server);
    wire.extend(frame(0x81, b"after", server));
    let (socket, mut peer) = pair();
    let peer = std::thread::spawn(move || {
        if server {
            assert!(
                String::from_utf8(http_head(&mut peer))
                    .unwrap()
                    .starts_with("HTTP/1.1 101 ")
            );
        }
        peer.write_all(&wire).unwrap();
        let mut byte = [0];
        assert_eq!(peer.read(&mut byte).expect("transport EOF"), 0);
    });
    let runtime = native_runtime(workers);
    runtime.block_on(async {
        let mut task = runtime
            .handle()
            .try_spawn(async move {
                let cx = Cx::current().unwrap();
                let socket = TcpStream::from_std(socket).unwrap();
                macro_rules! fail_then_refuse {
                    ($ws:ident) => {{
                        let first = $ws.recv(&cx).await;
                        assert!(
                            matches!(first, Err(WsError::InvalidUtf8)),
                            "{first:?} ({role:?}, {workers} workers)"
                        );
                        let second = $ws.recv(&cx).await;
                        assert!(
                            matches!(&second, Err(WsError::ProtocolViolation(reason)) if reason.contains("poisoned")),
                            "a failed connection processes no further data: {second:?} ({role:?}, {workers} workers)"
                        );
                    }};
                }
                match role {
                    Role::Server => {
                        let mut ws = WebSocketAcceptor::new()
                            .permessage_deflate()
                            .ping_interval(None)
                            .accept(&cx, UPGRADE, socket)
                            .await
                            .unwrap();
                        fail_then_refuse!(ws);
                    }
                    Role::Client | Role::Split => {
                        let mut ws = WebSocket::from_upgraded_with_extensions(
                            socket,
                            WebSocketConfig::new().ping_interval(None),
                            &[PROFILE.to_owned()],
                            client_entropy(),
                        )
                        .unwrap();
                        if matches!(role, Role::Split) {
                            let (mut read, _write) = ws.split();
                            fail_then_refuse!(read);
                        } else {
                            fail_then_refuse!(ws);
                        }
                    }
                }
            })
            .unwrap();
        asupersync::time::timeout(asupersync::time::wall_now(), WATCHDOG, &mut task)
            .await
            .expect("the failed receive completes");
    });
    peer.join().expect("independent RFC peer completed");
    assert_retired(&runtime);
}

#[test]
fn native_large_compressed_invalid_text_fails_the_connection() {
    for workers in [0, 2] {
        for role in [Role::Client, Role::Server, Role::Split] {
            large_invalid_text_scenario(workers, role);
        }
    }
}

#[test]
fn native_http1_router_handoff_negotiates_and_runs_compressed_session() {
    use asupersync::http::h1::listener::{Http1Listener, Http1ListenerConfig};
    use asupersync::http::h1::server::{HostPolicy, Http1Config};
    use asupersync::web::handler::FnHandler1;
    use asupersync::web::router::{Router, get};
    use asupersync::web::websocket::WebSocketUpgrade;

    for workers in [0, 2] {
        let runtime = native_runtime(workers);
        let handle = runtime.handle();
        runtime.block_on(async {
            let callbacks = Arc::new(AtomicUsize::new(0));
            let handler_callbacks = Arc::clone(&callbacks);
            let router = Router::new().route("/ws", get(FnHandler1::<_, WebSocketUpgrade>::new(move |upgrade: WebSocketUpgrade| {
                let callbacks = Arc::clone(&handler_callbacks);
                upgrade.skip_origin_check().extensions(["permessage-deflate"])
                    .on_upgrade(move |cx, mut ws| async move {
                        assert!(ws.compression_enabled());
                        callbacks.fetch_add(1, Ordering::AcqRel);
                        let message = ws.recv(&cx).await.unwrap().unwrap();
                        assert!(matches!(&message, Message::Text(text) if text == "live compressed upgrade"));
                        ws.send(&cx, message).await.unwrap();
                    })
            })));
            let listener = Http1Listener::bind_upgradeable_with_config("127.0.0.1:0", router.into_http1_handler(),
                Http1ListenerConfig::default().http_config(Http1Config {
                    allowed_hosts: HostPolicy::allow_list(vec!["127.0.0.1".to_owned()]), ..Http1Config::default()
                }).drain_timeout(WATCHDOG).hard_drain_timeout(WATCHDOG)).await.unwrap();
            let address = listener.local_addr().unwrap();
            let manager = listener.connection_manager().clone();
            let run_handle = handle.clone();
            let mut listener_task = handle.try_spawn(async move { listener.run(&run_handle).await }).unwrap();
            let mut client_task = handle.try_spawn(async move {
                let cx = Cx::current().unwrap();
                let mut ws = WebSocket::connect_with_compression(&cx, &format!("ws://{address}/ws"),
                    WebSocketConfig::new().ping_interval(None)).await.unwrap();
                assert!(ws.compression_enabled());
                ws.send(&cx, Message::text("live compressed upgrade")).await.unwrap();
                assert!(matches!(ws.recv(&cx).await.unwrap(), Some(Message::Text(text)) if text == "live compressed upgrade"));
            }).unwrap();
            asupersync::time::timeout(asupersync::time::wall_now(), WATCHDOG, &mut client_task).await.unwrap();
            assert_eq!(callbacks.load(Ordering::Acquire), 1);
            assert!(manager.begin_drain(WATCHDOG));
            let stats = asupersync::time::timeout(asupersync::time::wall_now(), WATCHDOG, &mut listener_task).await.unwrap().unwrap();
            assert_eq!(stats.force_closed, 0);
        });
        assert_retired(&runtime);
    }
}

/// A few compressed bytes may inflate to the whole decoded-message limit, so
/// a Router upgrade must be able to lower it (br-asupersync-ydis91).
#[test]
fn native_http1_router_handoff_bounds_inflated_messages_by_the_configured_limit() {
    use asupersync::http::h1::listener::{Http1Listener, Http1ListenerConfig};
    use asupersync::http::h1::server::{HostPolicy, Http1Config};
    use asupersync::web::handler::FnHandler1;
    use asupersync::web::router::{Router, get};
    use asupersync::web::websocket::WebSocketUpgrade;

    for workers in [0, 2] {
        let runtime = native_runtime(workers);
        let handle = runtime.handle();
        runtime.block_on(async {
            let outcome = Arc::new(std::sync::Mutex::new(None));
            let handler_outcome = Arc::clone(&outcome);
            let router = Router::new().route(
                "/ws",
                get(FnHandler1::<_, WebSocketUpgrade>::new(
                    move |upgrade: WebSocketUpgrade| {
                        let outcome = Arc::clone(&handler_outcome);
                        upgrade
                            .skip_origin_check()
                            .extensions(["permessage-deflate"])
                            .max_message_size(1024)
                            .on_upgrade(move |cx, mut ws| async move {
                                let received = ws.recv(&cx).await;
                                *outcome.lock().unwrap() = Some(format!("{received:?}"));
                            })
                    },
                )),
            );
            let listener = Http1Listener::bind_upgradeable_with_config(
                "127.0.0.1:0",
                router.into_http1_handler(),
                Http1ListenerConfig::default()
                    .http_config(Http1Config {
                        allowed_hosts: HostPolicy::allow_list(vec!["127.0.0.1".to_owned()]),
                        ..Http1Config::default()
                    })
                    .drain_timeout(WATCHDOG)
                    .hard_drain_timeout(WATCHDOG),
            )
            .await
            .unwrap();
            let address = listener.local_addr().unwrap();
            let manager = listener.connection_manager().clone();
            let run_handle = handle.clone();
            let mut listener_task = handle
                .try_spawn(async move { listener.run(&run_handle).await })
                .unwrap();
            let mut client_task = handle
                .try_spawn(async move {
                    let cx = Cx::current().unwrap();
                    let mut ws = WebSocket::connect_with_compression(
                        &cx,
                        &format!("ws://{address}/ws"),
                        WebSocketConfig::new().ping_interval(None),
                    )
                    .await
                    .unwrap();
                    assert!(ws.compression_enabled());
                    // 4 KiB of one byte compresses to a few bytes on the wire.
                    ws.send(&cx, Message::text("a".repeat(4096))).await.unwrap();
                    let _ = ws.recv(&cx).await;
                })
                .unwrap();
            asupersync::time::timeout(asupersync::time::wall_now(), WATCHDOG, &mut client_task)
                .await
                .unwrap();
            let received = outcome
                .lock()
                .unwrap()
                .clone()
                .expect("upgrade callback ran");
            assert!(
                received.contains("PayloadTooLarge"),
                "server accepted an over-limit inflated message: {received}"
            );
            assert!(manager.begin_drain(WATCHDOG));
            let stats = asupersync::time::timeout(
                asupersync::time::wall_now(),
                WATCHDOG,
                &mut listener_task,
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(stats.force_closed, 0);
        });
        assert_retired(&runtime);
    }
}
