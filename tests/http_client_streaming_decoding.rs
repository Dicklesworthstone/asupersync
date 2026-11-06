//! Native decoded-download ownership through codec completion and pool reuse.
//! Governing owner: asupersync-server-stack-hardening-eeexl1.
//!
//! Loopback peers speak HTTP independently of the server implementation. Gates
//! and real Pending polls establish ordering; timeouts are failure watchdogs.

#![cfg(not(target_arch = "wasm32"))]
#![recursion_limit = "256"]

use asupersync::Cx;
use asupersync::bytes::{Buf, Bytes, BytesCursor};
use asupersync::http::body::{Body, ContentDecodeError, ContentDecodeLimits, Frame, Full, HeaderMap};
use asupersync::http::h1::{ClientError, DecodedClientIncomingBody, HttpClient, HttpError, Method};
use asupersync::runtime::{RootDrainOutcome, RuntimeBuilder, RuntimeHandle};
use asupersync::types::Budget;
#[cfg(feature = "compression")]
use asupersync::types::CancelReason;
use std::future::{Future, poll_fn};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
#[cfg(feature = "compression")]
use std::sync::mpsc;
#[cfg(feature = "compression")]
use std::task::Poll;
use std::time::Duration;

const WATCHDOG: Duration = Duration::from_secs(10);
const GZIP_HELLO: &[u8] = &[
    0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03,
    0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00, 0x86, 0xa6, 0x10,
    0x36, 0x05, 0x00, 0x00, 0x00,
];

type Sockets = Arc<Mutex<Vec<TcpStream>>>;
type DecodeError = ContentDecodeError<ClientError>;

struct Peer {
    address: SocketAddr,
    sockets: Sockets,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Peer {
    fn start(handler: impl FnOnce(&TcpListener, &Sockets) + Send + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let sockets = Arc::new(Mutex::new(Vec::new()));
        let owned = Arc::clone(&sockets);
        let thread = std::thread::spawn(move || handler(&listener, &owned));
        Self { address, sockets, thread: Some(thread) }
    }

    fn url(&self, path: &str) -> String { format!("http://{}{path}", self.address) }

    fn finish(mut self) {
        self.thread.take().unwrap().join().expect("wire peer assertions");
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        let Some(thread) = self.thread.take() else { return; };
        for socket in self.sockets.lock().unwrap().iter() {
            let _ = socket.shutdown(std::net::Shutdown::Both);
        }
        // Wake an accept after an earlier assertion failed. The returned
        // socket closes immediately, so the peer cannot wait on its bytes.
        let _ = TcpStream::connect_timeout(&self.address, Duration::from_secs(1));
        let _ = thread.join();
    }
}

fn accept(listener: &TcpListener, owned: &Sockets) -> TcpStream {
    let (socket, _) = listener.accept().unwrap();
    socket.set_read_timeout(Some(WATCHDOG)).unwrap();
    socket.set_write_timeout(Some(WATCHDOG)).unwrap();
    socket.set_nodelay(true).unwrap();
    owned.lock().unwrap().push(socket.try_clone().unwrap());
    socket
}

fn request(socket: &mut TcpStream) -> String {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        assert!(head.len() < 16 * 1024, "bounded fixture request head");
        let mut byte = [0];
        socket.read_exact(&mut byte).expect("request head before EOF");
        head.push(byte[0]);
    }
    String::from_utf8(head).unwrap()
}

fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().skip(1).filter_map(|line| line.split_once(':'))
        .find_map(|(field, value)| field.eq_ignore_ascii_case(name).then_some(value.trim()))
}

fn field<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers.iter().find_map(|(field, value)| field.eq_ignore_ascii_case(name).then_some(value.as_str()))
}

fn eof(socket: &mut TcpStream) {
    let mut byte = [0];
    match socket.read(&mut byte) {
        Ok(0) => {}
        Err(error) if matches!(error.kind(), io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted) => {}
        other => panic!("retired response socket received another request: {other:?}"),
    }
}

fn fixed(socket: &mut TcpStream, fields: &str, body: &[u8]) {
    let mut response = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n{fields}\r\n", body.len()).into_bytes();
    response.extend_from_slice(body);
    socket.write_all(&response).unwrap();
    socket.flush().unwrap();
}

#[cfg(feature = "compression")]
fn chunk(socket: &mut TcpStream, bytes: &[u8]) {
    let mut frame = format!("{:x}\r\n", bytes.len()).into_bytes();
    frame.extend_from_slice(bytes);
    frame.extend_from_slice(b"\r\n");
    socket.write_all(&frame).unwrap();
    socket.flush().unwrap();
}

fn client() -> HttpClient {
    HttpClient::builder().max_connections_per_host(1).max_total_connections(1)
        .pool_wait_timeout(WATCHDOG).request_timeout(WATCHDOG).build()
}

#[cfg(feature = "compression")]
fn held(client: &HttpClient) {
    let stats = client.pool_stats();
    assert_eq!((stats.total_connections, stats.in_use_connections, stats.idle_connections), (1, 1, 0));
}

fn retired(client: &HttpClient) {
    let stats = client.pool_stats();
    assert_eq!((stats.total_connections, stats.in_use_connections, stats.idle_connections), (0, 0, 0));
}

fn native<F, Fut>(workers: usize, scenario: F)
where
    F: FnOnce(Cx, RuntimeHandle) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let builder = if workers == 1 { RuntimeBuilder::current_thread() }
        else { RuntimeBuilder::new().worker_threads(workers) };
    let runtime = builder.build().unwrap();
    let caller = runtime.request_cx_with_budget(Budget::INFINITE);
    let handle = runtime.handle();
    let child_handle = handle.clone();
    let task = handle.spawn_checked(async move {
        asupersync::time::timeout(caller.now(), Duration::from_secs(30), scenario(caller, child_handle))
            .await.expect("bounded native decoded-download journey");
    });
    runtime.block_on(task).expect("native decoded-download task");
    let report = runtime.shutdown_drained(Duration::from_secs(5));
    assert_eq!(report.outcome, RootDrainOutcome::Quiescent, "{report:?}");
    assert_eq!(report.live_tasks, 0);
    assert_eq!(report.pending_spawns, 0);
    assert_eq!(report.pending_obligations, 0);
}

fn limits(encoded: usize, decoded: usize, quantum: usize) -> ContentDecodeLimits {
    ContentDecodeLimits::new(encoded, decoded).with_chunk_size(NonZeroUsize::new(quantum).unwrap())
}

async fn next(body: &mut DecodedClientIncomingBody) -> Option<Result<Frame<BytesCursor>, DecodeError>> {
    poll_fn(|task| Pin::new(&mut *body).poll_frame(task)).await
}

#[cfg(feature = "compression")]
fn data(frame: Option<Result<Frame<BytesCursor>, DecodeError>>) -> Vec<u8> {
    let Some(Ok(Frame::Data(mut bytes))) = frame else { panic!("expected decoded DATA: {frame:?}"); };
    let remaining = bytes.remaining();
    bytes.copy_to_bytes(remaining).to_vec()
}

async fn collect(body: &mut DecodedClientIncomingBody) -> Result<(Vec<u8>, Option<HeaderMap>), DecodeError> {
    let mut output = Vec::new();
    let mut trailers = None;
    while let Some(frame) = next(body).await {
        match frame? {
            Frame::Data(mut bytes) => {
                assert!(trailers.is_none(), "decoded data follows terminal trailers");
                let remaining = bytes.remaining();
                output.extend_from_slice(&bytes.copy_to_bytes(remaining));
            }
            Frame::Trailers(fields) => assert!(trailers.replace(fields).is_none()),
        }
    }
    Ok((output, trailers))
}

#[cfg(feature = "compression")]
async fn pending<F: Future>(future: Pin<&mut F>) {
    let mut future = future;
    poll_fn(|task| {
        assert!(future.as_mut().poll(task).is_pending(), "operation must remain Pending at the owned boundary");
        Poll::Ready(())
    }).await;
}

#[cfg(feature = "compression")]
#[test]
fn gzip_plaintext_precedes_footer_and_pool_reuse_requires_successful_validation() {
    for workers in [1, 2] {
        for corrupt in [false, true] {
            let (release, footer) = mpsc::channel();
            let peer = Peer::start(move |listener, owned| {
                let mut first = accept(listener, owned);
                assert!(request(&mut first).starts_with("GET /first "));
                first.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Encoding: gzip\r\nDigest: obsolete\r\nETag: \"origin\"\r\nTrailer: Digest, X-Trace\r\n\r\n").unwrap();
                chunk(&mut first, &GZIP_HELLO[..17]);
                footer.recv_timeout(WATCHDOG).expect("plaintext and both Pending witnesses precede footer");
                let mut suffix = GZIP_HELLO[17..].to_vec();
                if corrupt { suffix[0] ^= 1; }
                let mut terminal = format!("{:x}\r\n", suffix.len()).into_bytes();
                terminal.extend_from_slice(&suffix);
                terminal.extend_from_slice(b"\r\n0\r\nDigest: obsolete\r\nX-Trace: kept\r\n\r\n");
                first.write_all(&terminal).unwrap();
                first.flush().unwrap();
                if corrupt {
                    eof(&mut first);
                    let mut replacement = accept(listener, owned);
                    assert!(request(&mut replacement).starts_with("GET /next "));
                    fixed(&mut replacement, "", b"ok");
                    eof(&mut replacement);
                } else {
                    assert!(request(&mut first).starts_with("GET /next "), "same physical socket reused");
                    fixed(&mut first, "", b"ok");
                    eof(&mut first);
                }
            });
            let first_url = peer.url("/first");
            let next_url = peer.url("/next");
            native(workers, move |cx, _| async move {
                let client = client();
                let response = client.get(first_url).send_streaming_decoded(&cx, limits(25, 5, 2)).await.unwrap();
                assert_eq!(field(&response.head.headers, "Content-Encoding"), None);
                assert_eq!(field(&response.head.headers, "Digest"), None);
                assert_eq!(field(&response.head.headers, "ETag"), Some("\"origin\""));
                let mut body = response.body;
                let mut plaintext = Vec::new();
                while plaintext.len() < 5 { plaintext.extend(data(next(&mut body).await)); }
                assert_eq!(plaintext, b"hello", "not merely a codec header before the footer");
                held(&client);
                let mut blocked_body = Box::pin(next(&mut body));
                pending(blocked_body.as_mut()).await;
                drop(blocked_body);
                let mut contender = Box::pin(client.send_get(&cx, &next_url));
                pending(contender.as_mut()).await;
                held(&client);
                release.send(()).unwrap();
                if corrupt {
                    assert!(matches!(collect(&mut body).await, Err(ContentDecodeError::Decode(_))));
                    retired(&client);
                } else {
                    let Some(Ok(Frame::Trailers(trailers))) = next(&mut body).await else { panic!("validated terminal trailers"); };
                    assert!(trailers.iter().all(|(name, _)| !name.as_str().eq_ignore_ascii_case("digest")));
                    assert!(trailers.iter().any(|(name, value)| name.as_str() == "x-trace" && value.as_bytes() == b"kept"));
                    assert!(body.is_end_stream(), "terminal trailer releases admission without another EOF poll");
                    assert_eq!(client.pool_stats().idle_connections, 1);
                }
                assert!(next(&mut body).await.is_none());
                let followed = contender.await.unwrap();
                assert_eq!(followed.body, b"ok");
                assert_eq!(client.pool_stats().connections_created, if corrupt { 2 } else { 1 });
                drop(body);
                drop(client);
            });
            peer.finish();
        }
    }
}

#[cfg(feature = "compression")]
#[derive(Clone, Copy, Debug)]
enum QueuedEnd { Truncated, Drop, Cancel }

#[cfg(feature = "compression")]
#[test]
fn complete_wire_body_holds_admission_through_queued_decode_failure_drop_and_cancel() {
    for workers in [1, 2] {
        for end in [QueuedEnd::Truncated, QueuedEnd::Drop, QueuedEnd::Cancel] {
            let peer = Peer::start(move |listener, owned| {
                let mut first = accept(listener, owned);
                assert!(request(&mut first).starts_with("GET /queued "));
                // A complete Content-Length message, not a truncated HTTP
                // transport: codec finalization still owes the gzip footer.
                fixed(&mut first, "Content-Encoding: gzip\r\n", &GZIP_HELLO[..17]);
                eof(&mut first);
                let mut replacement = accept(listener, owned);
                assert!(request(&mut replacement).starts_with("GET /replacement "));
                fixed(&mut replacement, "", b"ok");
                eof(&mut replacement);
            });
            let url = peer.url("/queued");
            let replacement_url = peer.url("/replacement");
            native(workers, move |cx, handle| async move {
                let caller = handle.request_cx_with_budget(Budget::INFINITE);
                let client = client();
                let response = client.get(url).send_streaming_decoded(&caller, limits(17, 5, 1)).await.unwrap();
                let mut body = response.body;
                assert_eq!(data(next(&mut body).await), b"h");
                held(&client);
                let mut contender = Box::pin(client.send_get(&cx, &replacement_url));
                pending(contender.as_mut()).await;
                match end {
                    QueuedEnd::Truncated => {
                        let mut remaining = Vec::new();
                        loop {
                            match next(&mut body).await {
                                Some(Ok(Frame::Data(bytes))) => remaining.extend_from_slice(bytes.chunk()),
                                Some(Err(ContentDecodeError::Decode(_))) => break,
                                other => panic!("gzip footer must fail after provisional data: {other:?}"),
                            }
                        }
                        assert_eq!(remaining, b"ello");
                        assert!(next(&mut body).await.is_none());
                        drop(body);
                    }
                    QueuedEnd::Drop => drop(body),
                    QueuedEnd::Cancel => {
                        caller.cancel_with_reason(CancelReason::user("stop queued decoded download"));
                        assert!(matches!(next(&mut body).await, Some(Err(ContentDecodeError::Body(ClientError::Cancelled)))));
                        assert!(next(&mut body).await.is_none());
                        drop(body);
                    }
                }
                retired(&client);
                assert_eq!(contender.await.unwrap().body, b"ok");
                assert_eq!(client.pool_stats().connections_created, 2);
                drop(client);
            });
            peer.finish();
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum LimitCase { Exact, Encoded, Decoded, Source }

#[test]
fn wire_decoded_and_source_limits_are_independent_and_exact_bounds_succeed() {
    for workers in [1, 2] {
        for gzip in [false, true] {
            if gzip && !cfg!(feature = "compression") { continue; }
            for case in [LimitCase::Exact, LimitCase::Encoded, LimitCase::Decoded, LimitCase::Source] {
                let wire = if gzip { GZIP_HELLO } else { &b"hello"[..] };
                let peer = Peer::start(move |listener, owned| {
                    let mut socket = accept(listener, owned);
                    request(&mut socket);
                    let coding = if gzip { "Content-Encoding: gzip\r\n" } else { "" };
                    let mut response = format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n{coding}\r\n{:x}\r\n", wire.len()).into_bytes();
                    response.extend_from_slice(wire);
                    response.extend_from_slice(b"\r\n0\r\n\r\n");
                    socket.write_all(&response).unwrap();
                    socket.flush().unwrap();
                    eof(&mut socket);
                });
                let url = peer.url("/limits");
                native(workers, move |cx, _| async move {
                    let source_limit = if matches!(case, LimitCase::Source) { wire.len() - 1 } else { wire.len() };
                    let client = HttpClient::builder().max_connections_per_host(1)
                        .request_timeout(WATCHDOG).max_body_size(source_limit).build();
                    let encoded = wire.len() - usize::from(matches!(case, LimitCase::Encoded));
                    let decoded = if matches!(case, LimitCase::Decoded) { 4 } else { 5 };
                    let response = client.get(url).send_streaming_decoded(&cx, limits(encoded, decoded, 2)).await.unwrap();
                    let mut body = response.body;
                    let outcome = collect(&mut body).await;
                    match case {
                        LimitCase::Exact => {
                            assert_eq!(outcome.unwrap().0, b"hello");
                            assert_eq!(client.pool_stats().idle_connections, 1);
                        }
                        LimitCase::Encoded => {
                            assert!(matches!(outcome, Err(ContentDecodeError::EncodedLimit { limit, .. }) if limit == encoded));
                            retired(&client);
                        }
                        LimitCase::Decoded => {
                            let error = outcome.unwrap_err();
                            assert!(matches!(&error, ContentDecodeError::Decode(_)));
                            assert!(error.is_limit_exceeded(), "typed decoded resource refusal");
                            retired(&client);
                        }
                        LimitCase::Source => {
                            assert!(matches!(outcome, Err(ContentDecodeError::Body(ClientError::HttpError(HttpError::BodyTooLarge)))));
                            retired(&client);
                        }
                    }
                    assert!(body.is_end_stream());
                    assert!(next(&mut body).await.is_none());
                    drop(body);
                    drop(client);
                });
                peer.finish();
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Negotiation { Automatic, Request, Default, RangeRequest, RangeDefault }

fn automatic_encodings() -> &'static str {
    match (cfg!(feature = "compression"), cfg!(feature = "zstd")) {
        (true, true) => "gzip, deflate, br, zstd",
        (true, false) => "gzip, deflate, br",
        (false, true) => "zstd",
        (false, false) => "identity",
    }
}

#[test]
fn identity_downloads_preserve_explicit_negotiation_and_range_suppresses_advertising() {
    for workers in [1, 2] {
        for policy in [Negotiation::Automatic, Negotiation::Request, Negotiation::Default,
            Negotiation::RangeRequest, Negotiation::RangeDefault]
        {
            let peer = Peer::start(move |listener, owned| {
                let mut socket = accept(listener, owned);
                let head = request(&mut socket);
                let expected = match policy {
                    Negotiation::Automatic => Some(automatic_encodings()),
                    Negotiation::Request => Some("identity"),
                    Negotiation::Default => Some("identity;q=1"),
                    Negotiation::RangeRequest | Negotiation::RangeDefault => None,
                };
                assert_eq!(header(&head, "Accept-Encoding"), expected, "{policy:?}");
                if matches!(policy, Negotiation::RangeRequest | Negotiation::RangeDefault) {
                    assert_eq!(header(&head, "Range"), Some("bytes=0-4"));
                }
                fixed(&mut socket, "ETag: \"origin\"\r\n", b"hello");
                eof(&mut socket);
            });
            let url = peer.url("/identity");
            native(workers, move |cx, _| async move {
                let mut builder = HttpClient::builder().request_timeout(WATCHDOG);
                match policy {
                    Negotiation::Request => builder = builder.default_header("Accept-Encoding", "gzip"),
                    Negotiation::Default => builder = builder.default_header("Accept-Encoding", "identity;q=1"),
                    Negotiation::RangeDefault => builder = builder.default_header("Range", "bytes=0-4"),
                    _ => {}
                }
                let client = builder.build();
                let mut request = client.get(url);
                match policy {
                    Negotiation::Request => request = request.header("Accept-Encoding", "identity"),
                    Negotiation::RangeRequest => request = request.header("Range", "bytes=0-4"),
                    _ => {}
                }
                let response = request.send_streaming_decoded(&cx, limits(5, 5, 2)).await.unwrap();
                assert_eq!(field(&response.head.headers, "Content-Length"), Some("5"));
                assert_eq!(field(&response.head.headers, "ETag"), Some("\"origin\""));
                let mut body = response.body;
                assert_eq!(collect(&mut body).await.unwrap().0, b"hello");
                assert_eq!(client.pool_stats().idle_connections, 1);
                drop(body);
                drop(client);
            });
            peer.finish();
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum EmptyResponse { Head, NotModified, DeclaredEmpty }

#[test]
fn bodyless_metadata_is_preserved_and_declared_empty_coding_is_normalized() {
    for workers in [1, 2] {
        for case in [EmptyResponse::Head, EmptyResponse::NotModified, EmptyResponse::DeclaredEmpty] {
            let peer = Peer::start(move |listener, owned| {
                let mut socket = accept(listener, owned);
                let head = request(&mut socket);
                assert!(head.starts_with(if matches!(case, EmptyResponse::Head) { "HEAD " } else { "GET " }));
                let (status, length, coding) = match case {
                    EmptyResponse::Head => ("200 OK", 123, "unknown-bodyless-coding"),
                    EmptyResponse::NotModified => ("304 Not Modified", 123, "unknown-bodyless-coding"),
                    EmptyResponse::DeclaredEmpty => ("200 OK", 0, "gzip"),
                };
                write!(socket, "HTTP/1.1 {status}\r\nContent-Length: {length}\r\nContent-Encoding: {coding}\r\nDigest: encoded\r\nETag: \"origin\"\r\n\r\n").unwrap();
                socket.flush().unwrap();
                eof(&mut socket);
            });
            let url = peer.url("/empty");
            native(workers, move |cx, _| async move {
                let client = client();
                let method = if matches!(case, EmptyResponse::Head) { Method::Head } else { Method::Get };
                let response = client.request_streaming_decoded(
                    &cx, method, &url, Vec::new(), Vec::new(), limits(0, 0, 1),
                ).await.unwrap();
                if matches!(case, EmptyResponse::DeclaredEmpty) {
                    for name in ["Content-Length", "Content-Encoding", "Digest"] {
                        assert_eq!(field(&response.head.headers, name), None);
                    }
                } else {
                    assert_eq!(field(&response.head.headers, "Content-Length"), Some("123"));
                    assert_eq!(field(&response.head.headers, "Content-Encoding"), Some("unknown-bodyless-coding"));
                    assert_eq!(field(&response.head.headers, "Digest"), Some("encoded"));
                }
                assert_eq!(field(&response.head.headers, "ETag"), Some("\"origin\""));
                let mut body = response.body;
                assert!(collect(&mut body).await.unwrap().0.is_empty());
                assert_eq!(client.pool_stats().idle_connections, 1);
                drop(body);
                drop(client);
            });
            peer.finish();
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Refusal { Unknown, PartialStatus, PartialField, KnownLength, Unavailable }

#[test]
fn head_policy_refusals_close_without_reading_the_response_body() {
    for case in [Refusal::Unknown, Refusal::PartialStatus, Refusal::PartialField,
        Refusal::KnownLength, Refusal::Unavailable]
    {
        if matches!(case, Refusal::Unavailable) && cfg!(feature = "compression") { continue; }
        let peer = Peer::start(move |listener, owned| {
            let mut socket = accept(listener, owned);
            request(&mut socket);
            let (status, coding, extra) = match case {
                Refusal::Unknown => ("200 OK", "Content-Encoding: snappy\r\n", ""),
                Refusal::PartialStatus => ("206 Partial Content", "Content-Encoding: gzip\r\n", ""),
                Refusal::PartialField => ("200 OK", "Content-Encoding: gzip\r\n", "Content-Range: bytes 0-9/20\r\n"),
                Refusal::KnownLength => ("200 OK", "", ""),
                Refusal::Unavailable => ("200 OK", "Content-Encoding: gzip\r\n", ""),
            };
            write!(socket, "HTTP/1.1 {status}\r\nContent-Length: 10\r\n{coding}{extra}\r\n").unwrap();
            socket.flush().unwrap();
            // No payload is ever supplied. Refusal must return from the head
            // and close this socket, rather than waiting for a body/drain.
            eof(&mut socket);
        });
        let url = peer.url("/refused");
        native(1, move |cx, _| async move {
            let client = client();
            let bound = if matches!(case, Refusal::KnownLength) { 9 } else { 100 };
            let result = client.get(url).send_streaming_decoded(&cx, limits(bound, 100, 2)).await;
            match (case, result) {
                (Refusal::Unknown | Refusal::Unavailable, Err(ClientError::HttpError(HttpError::Io(error)))) => {
                    assert_eq!(error.kind(), io::ErrorKind::Unsupported);
                }
                (Refusal::PartialStatus | Refusal::PartialField, Err(ClientError::HttpError(HttpError::Io(error)))) => {
                    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
                }
                (Refusal::KnownLength, Err(ClientError::HttpError(HttpError::BodyTooLarge))) => {}
                (case, other) => panic!("{case:?}: expected typed preflight refusal, got {other:?}"),
            }
            retired(&client);
            drop(client);
        });
        peer.finish();
    }
}

#[test]
fn one_shot_full_upload_decodes_the_response_and_keeps_builder_headers() {
    for workers in [1, 2] {
        let peer = Peer::start(move |listener, owned| {
            let mut socket = accept(listener, owned);
            let head = request(&mut socket);
            assert!(head.starts_with("POST /upload "));
            assert_eq!(header(&head, "Content-Length"), Some("7"));
            assert_eq!(header(&head, "X-Upload"), Some("owned"));
            assert_eq!(header(&head, "Accept-Encoding"), Some(automatic_encodings()));
            let mut upload = [0; 7];
            socket.read_exact(&mut upload).unwrap();
            assert_eq!(&upload, b"payload");
            if cfg!(feature = "compression") {
                fixed(&mut socket, "Content-Encoding: gzip\r\n", GZIP_HELLO);
            } else {
                fixed(&mut socket, "", b"hello");
            }
            eof(&mut socket);
        });
        let url = peer.url("/upload");
        native(workers, move |cx, _| async move {
            let client = client();
            let response = client.post(url).header("X-Upload", "owned")
                .send_with_body_decoded(&cx, Full::new(BytesCursor::new(Bytes::from_static(b"payload"))), limits(25, 5, 2))
                .await.unwrap();
            assert!(!response.body_withheld);
            let mut body = response.body;
            assert_eq!(collect(&mut body).await.unwrap().0, b"hello");
            assert_eq!(client.pool_stats().idle_connections, 1);
            drop(body);
            drop(client);
        });
        peer.finish();
    }
}

#[cfg(feature = "compression")]
#[test]
fn redirect_final_method_decodes_connect_to_get_and_preserves_head_metadata() {
    for workers in [1, 2] {
        for head in [false, true] {
            let peer = Peer::start(move |listener, owned| {
                let mut socket = accept(listener, owned);
                let first = request(&mut socket);
                assert!(first.starts_with(if head { "HEAD " } else { "CONNECT " }));
                socket.write_all(b"HTTP/1.1 303 See Other\r\nLocation: /final\r\nContent-Length: 0\r\n\r\n").unwrap();
                socket.flush().unwrap();
                let redirected = request(&mut socket);
                assert!(redirected.starts_with(if head { "HEAD /final " } else { "GET /final " }));
                if head {
                    socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 25\r\nContent-Encoding: gzip\r\n\r\n").unwrap();
                    socket.flush().unwrap();
                } else {
                    fixed(&mut socket, "Content-Encoding: gzip\r\n", GZIP_HELLO);
                }
                eof(&mut socket);
            });
            let url = peer.url("/start");
            native(workers, move |cx, _| async move {
                let client = HttpClient::builder().max_redirects(2).max_connections_per_host(1)
                    .pool_wait_timeout(WATCHDOG).request_timeout(WATCHDOG).build();
                let method = if head { Method::Head } else { Method::Connect };
                let response = client.request_streaming_decoded(
                    &cx, method, &url, Vec::new(), Vec::new(), limits(25, 5, 2),
                ).await.unwrap();
                assert_eq!(field(&response.head.headers, "Content-Encoding"), if head { Some("gzip") } else { None });
                let mut body = response.body;
                let output = collect(&mut body).await.unwrap().0;
                assert_eq!(output.as_slice(), if head { &b""[..] } else { &b"hello"[..] });
                assert_eq!(client.pool_stats().connections_created, 1);
                drop(body);
                drop(client);
            });
            peer.finish();
        }
    }
}
