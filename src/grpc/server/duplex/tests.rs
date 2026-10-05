//! Native registered services and framing refusals; no loopback RPC shortcut.

use super::*;
use crate::grpc::native_stream::{NativeDuplexEvent, NativeDuplexStream, NativeStreamConfig};
use crate::grpc::service::{
    MethodDescriptor, NamedService, ServiceHandlerFuture, ServiceStreamingFuture,
};
use crate::grpc::status::Code;
use crate::http::body::{HeaderName, HeaderValue};
use crate::http::h1::stream::RequestHead;
use crate::http::h1::types::Version;
use crate::net::TcpStream;
use crate::runtime::RuntimeBuilder;
use crate::server::shutdown::ShutdownSignal;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::task::Waker;

const LIMIT: Duration = Duration::from_secs(10);
const PAYLOAD: usize = 128 * 1024;
const METHODS: &[MethodDescriptor] = &[
    MethodDescriptor::bidi_streaming("Echo", "/native.Duplex/Echo"),
    MethodDescriptor::bidi_streaming("Park", "/native.Duplex/Park"),
    MethodDescriptor::client_streaming("Aggregate", "/native.Duplex/Aggregate"),
    MethodDescriptor::client_streaming("Ignore", "/native.Duplex/Ignore"),
    MethodDescriptor::unary("Unary", "/native.Duplex/Unary"),
    MethodDescriptor::server_streaming("Watch", "/native.Duplex/Watch"),
];
static DESCRIPTOR: ServiceDescriptor = ServiceDescriptor::new("Duplex", "native", METHODS);

struct Probe {
    calls: AtomicUsize,
    messages: AtomicUsize,
    drops: AtomicUsize,
    started: mpsc::Sender<Cx>,
    retired: mpsc::Sender<()>,
    child_cancelled: AtomicBool,
    child_retired: AtomicBool,
    release: AtomicBool,
    cleanup_waker: parking_lot::Mutex<Option<Waker>>,
}

struct Guard(Arc<Probe>);
impl Drop for Guard {
    fn drop(&mut self) {
        self.0.drops.fetch_add(1, Ordering::SeqCst);
        let _ = self.0.retired.send(());
    }
}

struct Service(Arc<Probe>);
impl NamedService for Service {
    const NAME: &'static str = "native.Duplex";
}

impl ServiceHandler for Service {
    fn descriptor(&self) -> &ServiceDescriptor {
        &DESCRIPTOR
    }

    fn method_names(&self) -> Vec<&str> {
        METHODS.iter().map(|method| method.name).collect()
    }

    fn call_unary<'a>(
        &'a self,
        _cx: &'a Cx,
        _path: &'a str,
        request: Request<Bytes>,
        _trailers: Metadata,
    ) -> ServiceHandlerFuture<'a> {
        Box::pin(async move { Ok(Response::new(request.into_inner())) })
    }

    fn call_server_streaming<'a>(
        &'a self,
        _cx: &'a Cx,
        _path: &'a str,
        request: Request<Bytes>,
        _trailers: Metadata,
    ) -> ServiceStreamingFuture<'a> {
        Box::pin(async move { single_response(Response::new(request.into_inner())) })
    }

    fn call_client_streaming<'a>(
        &'a self,
        cx: &'a Cx,
        path: &'a str,
        request: Request<RegisteredRequestStream>,
    ) -> ServiceHandlerFuture<'a> {
        let probe = Arc::clone(&self.0);
        probe.calls.fetch_add(1, Ordering::SeqCst);
        let _ = probe.started.send(cx.clone());
        Box::pin(async move {
            let _guard = Guard(Arc::clone(&probe));
            let mut stream = request.into_inner();
            let mut total = 0_u64;
            loop {
                match stream.message().await {
                    Ok(Some(message)) => {
                        total += message.len() as u64;
                        probe.messages.fetch_add(1, Ordering::SeqCst);
                    }
                    Ok(None) => break,
                    Err(_) if path == "/native.Duplex/Ignore" => break,
                    Err(status) => return Err(status),
                }
            }
            let mut trailers = Metadata::new();
            assert!(trailers.insert("x-terminal", "aggregate"));
            if let Some(input) = stream.trailers() {
                if let Some(crate::grpc::MetadataValue::Ascii(value)) = input.get("x-proof") {
                    assert!(trailers.insert("x-request-proof", value));
                }
            }
            Ok(Response::with_metadata(
                Bytes::from(total.to_be_bytes().to_vec()),
                trailers,
            ))
        })
    }

    fn call_bidirectional_streaming<'a>(
        &'a self,
        cx: &'a Cx,
        path: &'a str,
        request: Request<RegisteredRequestStream>,
    ) -> ServiceStreamingFuture<'a> {
        self.0.calls.fetch_add(1, Ordering::SeqCst);
        let stream = Echo {
            input: request.into_inner(),
            guard: Guard(Arc::clone(&self.0)),
            cx: cx.clone(),
            park: path == "/native.Duplex/Park",
            witnessed: false,
        };
        Box::pin(async move {
            if stream.park {
                let (started, mut ready) = crate::channel::oneshot::channel();
                let probe = Arc::clone(&stream.guard.0);
                let expected_region = cx.region_id();
                let expected_deadline = cx.budget().deadline;
                let _child = cx
                    .spawn(move |child_cx| async move {
                        assert_eq!(
                            child_cx.region_id(),
                            expected_region,
                            "service descendant must belong to actual request region"
                        );
                        assert_eq!(child_cx.budget().deadline, expected_deadline);
                        let mut cancelled = std::pin::pin!(child_cx.cancelled());
                        let mut started = Some(started);
                        poll_fn(|task| {
                            let result = cancelled.as_mut().poll(task);
                            if result.is_pending()
                                && let Some(started) = started.take()
                            {
                                started.send_blocking(()).unwrap();
                            }
                            result
                        })
                        .await;
                        assert!(
                            child_cx.checkpoint().is_err(),
                            "service descendant acknowledges cancellation before cleanup"
                        );
                        probe.child_cancelled.store(true, Ordering::Release);
                        poll_fn(|task| {
                            let mut waker = probe.cleanup_waker.lock();
                            if probe.release.load(Ordering::Acquire) {
                                Poll::Ready(())
                            } else {
                                *waker = Some(task.waker().clone());
                                Poll::Pending
                            }
                        })
                        .await;
                        probe.child_retired.store(true, Ordering::Release);
                    })
                    .map_err(|error| {
                        Status::internal(format!("owned descendant spawn: {error}"))
                    })?;
                ready
                    .recv(cx)
                    .await
                    .map_err(|_| Status::cancelled("descendant startup cancelled"))?;
            }
            let mut trailers = Metadata::new();
            assert!(trailers.insert("x-terminal", "echo"));
            Ok(RegisteredServerStream::new(stream).with_trailers(trailers))
        })
    }
}

struct Echo {
    input: RegisteredRequestStream,
    guard: Guard,
    cx: Cx,
    park: bool,
    witnessed: bool,
}

impl Streaming for Echo {
    type Message = Bytes;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Bytes, Status>>> {
        if !self.witnessed {
            self.witnessed = true;
            let _ = self.guard.0.started.send(self.cx.clone());
        }
        if self.park {
            return Poll::Pending; // Never self-wakes; cancellation must wake the owner.
        }
        match Pin::new(&mut self.input).poll_next(cx) {
            Poll::Ready(Some(Ok(message))) => {
                self.guard.0.messages.fetch_add(1, Ordering::SeqCst);
                Poll::Ready(Some(Ok(message)))
            }
            other => other,
        }
    }
}

struct Stop(ShutdownSignal);
impl Drop for Stop {
    fn drop(&mut self) {
        // Force-close is only reachable from Draining. From Running it is
        // refused, and the listener would keep serving until the watchdog.
        let _ = self.0.begin_drain(Duration::ZERO);
        let _ = self.0.begin_force_close();
    }
}

fn service() -> (
    Arc<Server>,
    Arc<Probe>,
    mpsc::Receiver<Cx>,
    mpsc::Receiver<()>,
) {
    let (started, starts) = mpsc::channel();
    let (retired, retirements) = mpsc::channel();
    let probe = Arc::new(Probe {
        calls: AtomicUsize::new(0),
        messages: AtomicUsize::new(0),
        drops: AtomicUsize::new(0),
        started,
        retired,
        child_cancelled: AtomicBool::new(false),
        child_retired: AtomicBool::new(false),
        release: AtomicBool::new(false),
        cleanup_waker: parking_lot::Mutex::new(None),
    });
    let mut server = Server::builder()
        .add_service(Service(Arc::clone(&probe)))
        .build();
    server.config.max_recv_message_size = PAYLOAD;
    server.config.max_send_message_size = PAYLOAD;
    (Arc::new(server), probe, starts, retirements)
}

fn bounded_case(case: impl FnOnce() + Send + 'static) {
    let (completed, done) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        case();
        completed.send(()).unwrap();
    });
    done.recv_timeout(Duration::from_secs(25))
        .expect("native gRPC duplex watchdog");
    worker.join().expect("native gRPC duplex assertions");
}

fn shutdown_native(runtime: crate::runtime::Runtime) {
    // The strong handle was moved into the completed entry task. Check actual
    // root accounting before requesting bounded worker/thread teardown.
    let report = runtime.shutdown_drained(LIMIT);
    assert_eq!(report.outcome, crate::runtime::RootDrainOutcome::Quiescent);
    assert_eq!(report.live_tasks, 0);
    assert_eq!(report.pending_obligations, 0);
    assert_eq!(report.live_regions, 0);
    assert_eq!(report.queued_finalizers, 0);
    assert_eq!(report.pending_spawns, 0);
    assert!(!report.has_pending_obligation_posts);
    assert!(runtime.shutdown_timeout(LIMIT));
}

fn paired(workers: usize, bidi: bool) {
    let runtime = if workers == 1 {
        RuntimeBuilder::current_thread()
    } else {
        RuntimeBuilder::new().worker_threads(workers)
    }
    .build()
    .unwrap();
    let handle = runtime.handle().clone();
    let (server, probe, _starts, retirements) = service();
    let inspected = Arc::clone(&probe);
    runtime.block_on(runtime.handle().spawn(async move {
        let listener = server
            .bind_registered_duplex_http2(
                "127.0.0.1:0",
                HostPolicy::allow_all(),
                ServerDuplexConfig::default(),
            )
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let stop = Stop(listener.shutdown_signal());
        let client = async move {
            let _stop = stop;
            let cx = Cx::current().unwrap();
            let socket = TcpStream::connect(addr).await.unwrap();
            let config = NativeStreamConfig {
                timeout: Some(LIMIT),
                max_send_message_size: PAYLOAD,
                max_recv_message_size: PAYLOAD,
                ..NativeStreamConfig::default()
            };
            let mut call = NativeDuplexStream::new(
                &cx,
                socket,
                "localhost",
                if bidi {
                    "/native.Duplex/Echo"
                } else {
                    "/native.Duplex/Aggregate"
                },
                Request::new(()),
                IdentityCodec,
                config,
            )
            .unwrap();
            let mut queued = 0_usize;
            let mut received = 0_usize;
            let mut closed = false;
            while let Some(event) = call.next_event().await.unwrap() {
                if let NativeDuplexEvent::Message(message) = event {
                    if bidi {
                        assert!(!closed, "each echo arrives before request half-close");
                        assert_eq!(message.len(), PAYLOAD);
                        assert!(message.iter().all(|byte| usize::from(*byte) == received));
                    } else {
                        assert!(closed, "aggregate requires request EOF");
                        assert_eq!(message.as_ref(), (3_u64 * PAYLOAD as u64).to_be_bytes());
                    }
                    received += 1;
                }
                if !closed && call.request_ready() && (!bidi || queued == received) {
                    if queued < 3 {
                        call.queue_message(&Bytes::from(vec![queued as u8; PAYLOAD]))
                            .unwrap();
                        queued += 1;
                    } else {
                        call.close_requests().unwrap();
                        closed = true;
                    }
                }
            }
            assert_eq!(queued, 3);
            assert_eq!(received, if bidi { 3 } else { 1 });
            assert!(closed);
            assert_eq!(call.status().unwrap().code(), Code::Ok);
            assert!(call.trailers().unwrap().get("x-terminal").is_some());
            assert_eq!(inspected.messages.load(Ordering::SeqCst), 3);
            assert_eq!(
                inspected.drops.load(Ordering::SeqCst),
                1,
                "source/future retired before terminal response"
            );
        };
        let (served, ()) =
            futures_lite::future::zip(listener.run_streaming_produced(&handle), client).await;
        served.unwrap();
    }));
    retirements.recv_timeout(LIMIT).unwrap();
    assert_eq!(probe.calls.load(Ordering::SeqCst), 1);
    assert_eq!(probe.drops.load(Ordering::SeqCst), 1);
    shutdown_native(runtime);
    eprintln!(
        "grpc_duplex_native workers={workers} bidi={bidi} messages=3 bytes={} retired=1",
        3 * PAYLOAD
    );
}

#[test]
fn native_registered_client_streaming_and_bidi_cross_windows_on_one_and_two_workers() {
    for workers in [1, 2] {
        for bidi in [false, true] {
            bounded_case(move || paired(workers, bidi));
        }
    }
}

fn decoder(
    encoding: Option<&str>,
    max_message: usize,
    total: Option<usize>,
) -> (
    crate::http::h1::stream::FramedIncomingRequestBodyWriter,
    RegisteredRequestStream,
    Cx,
) {
    let cx = Cx::for_testing();
    let mut server = Server::builder().build();
    server.config.max_recv_message_size = max_message;
    server.config.max_request_body_bytes = total;
    // A server accepts only identity-encoded requests unless configured to
    // accept an encoding (decode_live_request refuses others as Unimplemented).
    if let Some(encoding) = encoding {
        server
            .config
            .accept_compression
            .extend(CompressionEncoding::from_header_value(encoding));
    }
    let mut head = RequestHead {
        method: Method::Post,
        uri: "/native.Duplex/Echo".to_owned(),
        version: Version::Http11,
        headers: vec![("content-type".to_owned(), "application/grpc".to_owned())],
    };
    if let Some(encoding) = encoding {
        head.headers
            .push(("grpc-encoding".to_owned(), encoding.to_owned()));
    }
    let (writer, body) = IncomingRequestBody::framed_channel_with_limits(&cx, None, 8, 65535);
    let (_, request) = server
        .decode_live_request(StreamingServerRequest::new(head, body), 65535)
        .unwrap();
    (writer, request.into_inner(), cx)
}

/// Repeated metadata keys (grpc-go's metadata.Pairs("k", "a", "k", "b"),
/// split cookie headers) are legal. The duplex lane refused them, although
/// the unary lane accepts the same request; only single-valued fields such
/// as content-type are refused when repeated.
#[test]
fn decode_live_request_accepts_repeated_metadata_but_not_a_repeated_content_type() {
    let cx = Cx::for_testing();
    let server = Server::builder().build();
    let decode = |headers: &[(&str, &str)]| {
        let head = RequestHead {
            method: Method::Post,
            uri: "/native.Duplex/Echo".to_owned(),
            version: Version::Http11,
            headers: headers
                .iter()
                .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
                .collect(),
        };
        let (_writer, body) = IncomingRequestBody::framed_channel_with_limits(&cx, None, 8, 65535);
        server
            .decode_live_request(StreamingServerRequest::new(head, body), 65535)
            .map(|(_, request)| request)
    };

    let request = decode(&[
        ("content-type", "application/grpc"),
        ("x-tag", "a"),
        ("x-tag", "b"),
    ])
    .expect("repeated metadata is accepted");
    let tags = request
        .metadata()
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("x-tag"))
        .count();
    assert_eq!(tags, 2, "both values are kept");

    match decode(&[
        ("content-type", "application/grpc"),
        ("content-type", "application/grpc"),
    ]) {
        Err(status) => assert_eq!(status.code(), Code::InvalidArgument),
        Ok(_) => panic!("a repeated content-type is refused"),
    }
}

fn put(
    writer: &mut crate::http::h1::stream::FramedIncomingRequestBodyWriter,
    cx: &Cx,
    bytes: &[u8],
) {
    let mut frame = Some(Frame::Data(BytesCursor::new(Bytes::copy_from_slice(bytes))));
    let mut task = Context::from_waker(Waker::noop());
    assert!(matches!(
        writer.poll_send_frame(cx, &mut task, &mut frame),
        Poll::Ready(Ok(()))
    ));
}

fn message(bytes: &[u8]) -> Vec<u8> {
    let mut frame = vec![0];
    frame.extend_from_slice(&u32::try_from(bytes.len()).unwrap().to_be_bytes());
    frame.extend_from_slice(bytes);
    frame
}

#[test]
fn live_request_decoder_retains_partial_waits_and_exposes_trailers_only_after_eof() {
    let (mut writer, mut input, cx) = decoder(None, 64, None);
    let frame = message(b"abc");
    put(&mut writer, &cx, &frame[..3]);
    let mut task = Context::from_waker(Waker::noop());
    {
        let mut wait = std::pin::pin!(input.message());
        assert!(wait.as_mut().poll(&mut task).is_pending());
    }
    put(&mut writer, &cx, &frame[3..]);
    assert!(
        matches!(Pin::new(&mut input).poll_next(&mut task), Poll::Ready(Some(Ok(bytes))) if bytes.as_ref() == b"abc")
    );
    let mut fields = HeaderMap::new();
    fields.append(
        HeaderName::from_string("x-proof"),
        HeaderValue::from_bytes(b"exact"),
    );
    let mut trailer = Some(Frame::Trailers(fields));
    assert!(matches!(
        writer.poll_send_frame(&cx, &mut task, &mut trailer),
        Poll::Ready(Ok(()))
    ));
    assert!(Pin::new(&mut input).poll_next(&mut task).is_pending());
    assert!(input.trailers().is_none());
    writer.finish(&cx).unwrap();
    assert!(matches!(
        Pin::new(&mut input).poll_next(&mut task),
        Poll::Ready(None)
    ));
    assert!(input.trailers().unwrap().get("x-proof").is_some());
    assert!(matches!(
        Pin::new(&mut input).poll_next(&mut task),
        Poll::Ready(None)
    ));
}

#[test]
fn live_request_decoder_refuses_oversize_truncation_compression_and_aggregate_overrun() {
    for (wire, maximum, total, expected) in [
        (vec![0, 0, 1, 0, 0], 8, None, Code::ResourceExhausted),
        (vec![0, 0, 0], 8, None, Code::InvalidArgument),
        (vec![0, 0, 0, 0, 4, 1], 8, None, Code::InvalidArgument),
        (vec![1, 0, 0, 0, 0], 8, None, Code::InvalidArgument),
        (vec![2, 0, 0, 0, 0], 8, None, Code::InvalidArgument),
        (
            [message(b"abc"), message(b"def")].concat(),
            8,
            Some(5),
            Code::ResourceExhausted,
        ),
    ] {
        let (mut writer, mut input, cx) = decoder(None, maximum, total);
        put(&mut writer, &cx, &wire);
        writer.finish(&cx).unwrap();
        let error = futures_lite::future::block_on(async {
            loop {
                match input.message().await {
                    Ok(Some(_)) => {}
                    Ok(None) => panic!("malformed stream became successful EOF"),
                    Err(status) => break status,
                }
            }
        });
        assert_eq!(error.code(), expected, "wire={wire:?}");
        assert!(input.terminal.lock().failure.is_some());
        assert!(
            futures_lite::future::block_on(input.message())
                .unwrap()
                .is_none()
        );
        assert!(input.trailers().is_none());
    }
}

#[cfg(feature = "compression")]
#[test]
fn live_request_gzip_accepts_mixed_flags_and_bounds_decompressed_payloads() {
    for limit in [128, 4096] {
        let (mut writer, mut input, cx) = decoder(Some("gzip"), limit, None);
        let inflated = Bytes::from(vec![b'a'; 2048]);
        let compressed = crate::grpc::codec::gzip_frame_compress(inflated.clone()).unwrap();
        assert!(
            compressed.len() <= 128 && inflated.len() > 128,
            "oversize refusal must exercise decoded size"
        );
        let mut frame = vec![1];
        frame.extend_from_slice(&u32::try_from(compressed.len()).unwrap().to_be_bytes());
        frame.extend_from_slice(&compressed);
        put(&mut writer, &cx, &frame);
        if limit == 4096 {
            put(&mut writer, &cx, &message(b"plain"));
        }
        writer.finish(&cx).unwrap();
        if limit == 128 {
            assert_eq!(
                futures_lite::future::block_on(input.message())
                    .unwrap_err()
                    .code(),
                Code::ResourceExhausted
            );
        } else {
            assert_eq!(
                futures_lite::future::block_on(input.message())
                    .unwrap()
                    .unwrap(),
                inflated
            );
            assert_eq!(
                futures_lite::future::block_on(input.message())
                    .unwrap()
                    .unwrap()
                    .as_ref(),
                b"plain"
            );
            assert!(
                futures_lite::future::block_on(input.message())
                    .unwrap()
                    .is_none()
            );
        }
    }
}

struct RawPeer {
    socket: std::net::TcpStream,
    decoder: crate::http::h2::HpackDecoder,
    stream: u32,
    body: Vec<u8>,
    fields: Vec<crate::http::h2::Header>,
    reset: Option<u32>,
}

impl RawPeer {
    fn new(address: std::net::SocketAddr, window: u32) -> Self {
        use std::io::Write as _;
        let socket = std::net::TcpStream::connect_timeout(&address, LIMIT).unwrap();
        socket.set_read_timeout(Some(LIMIT)).unwrap();
        socket.set_write_timeout(Some(LIMIT)).unwrap();
        let mut peer = Self {
            socket,
            decoder: crate::http::h2::HpackDecoder::new(),
            stream: 0,
            body: Vec::new(),
            fields: Vec::new(),
            reset: None,
        };
        peer.socket
            .write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
            .unwrap();
        let mut settings = vec![0, 4];
        settings.extend_from_slice(&window.to_be_bytes());
        peer.send(4, 0, 0, &settings);
        peer
    }

    fn send(&mut self, kind: u8, flags: u8, stream: u32, payload: &[u8]) {
        use std::io::Write as _;
        let length = u32::try_from(payload.len()).unwrap();
        let mut header = [0; 9];
        header[..3].copy_from_slice(&length.to_be_bytes()[1..]);
        header[3] = kind;
        header[4] = flags;
        header[5..].copy_from_slice(&stream.to_be_bytes());
        self.socket.write_all(&header).unwrap();
        self.socket.write_all(payload).unwrap();
    }

    fn request(&mut self, stream: u32, path: &str, timeout: Option<&str>) {
        self.stream = stream;
        self.body.clear();
        self.fields.clear();
        self.reset = None;
        let mut headers = Vec::new();
        for (name, value) in [
            (":method", "POST"),
            (":scheme", "http"),
            (":authority", "localhost"),
            (":path", path),
            ("content-type", "application/grpc"),
            ("te", "trailers"),
        ] {
            literal(&mut headers, name, value);
        }
        if let Some(timeout) = timeout {
            literal(&mut headers, "grpc-timeout", timeout);
        }
        self.send(1, 4, stream, &headers);
    }

    fn frame(&mut self) -> (u8, u8, u32, Vec<u8>) {
        use std::io::Read as _;
        let mut header = [0; 9];
        self.socket
            .read_exact(&mut header)
            .expect("native duplex server frame");
        let length =
            (usize::from(header[0]) << 16) | (usize::from(header[1]) << 8) | usize::from(header[2]);
        assert!(length <= 1024 * 1024, "bounded raw test peer frame");
        let mut payload = vec![0; length];
        self.socket.read_exact(&mut payload).unwrap();
        (
            header[3],
            header[4],
            u32::from_be_bytes(header[5..].try_into().unwrap()) & 0x7fff_ffff,
            payload,
        )
    }

    fn step(&mut self) -> bool {
        let (kind, flags, stream, mut payload) = self.frame();
        match kind {
            4 if flags & 1 == 0 => self.send(4, 1, 0, &[]),
            6 if flags & 1 == 0 => self.send(6, 1, 0, &payload),
            0 if stream == self.stream => {
                self.body.extend_from_slice(&payload);
                return flags & 1 != 0;
            }
            1 => {
                let mut ending = flags;
                while ending & 4 == 0 {
                    let (kind, flags, next_stream, next) = self.frame();
                    assert_eq!((kind, next_stream), (9, stream));
                    payload.extend_from_slice(&next);
                    ending = flags;
                }
                // HPACK state belongs to the connection, including closed/reset streams.
                let fields = self.decoder.decode(&mut Bytes::from(payload)).unwrap();
                if stream == self.stream {
                    self.fields.extend(fields);
                    return flags & 1 != 0;
                }
            }
            3 if stream == self.stream => {
                self.reset = Some(u32::from_be_bytes(payload.try_into().unwrap()));
                return true;
            }
            7 => panic!("unexpected GOAWAY: {payload:?}"),
            _ => {}
        }
        false
    }

    fn finish(&mut self) {
        for _ in 0..1024 {
            if self.step() {
                return;
            }
        }
        panic!("native response exceeded frame budget");
    }

    fn field(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|field| field.name == name)
            .map(|field| field.value.as_str())
    }
}

fn literal(headers: &mut Vec<u8>, name: &str, value: &str) {
    assert!(name.len() < 128 && value.len() < 128);
    headers.extend_from_slice(&[0, u8::try_from(name.len()).unwrap()]);
    headers.extend_from_slice(name.as_bytes());
    headers.push(u8::try_from(value.len()).unwrap());
    headers.extend_from_slice(value.as_bytes());
}

fn until(predicate: impl Fn() -> bool) {
    let deadline = std::time::Instant::now() + LIMIT;
    while !predicate() {
        assert!(
            std::time::Instant::now() < deadline,
            "native ownership witness watchdog"
        );
        std::thread::park_timeout(Duration::from_millis(1));
    }
}

fn release(probe: &Probe) {
    probe.release.store(true, Ordering::Release);
    let waker = probe.cleanup_waker.lock().take();
    if let Some(waker) = waker {
        waker.wake();
    }
}

struct Release(Arc<Probe>);
impl Drop for Release {
    fn drop(&mut self) {
        release(&self.0);
    }
}

fn raw_case(
    workers: usize,
    configure: impl FnOnce(&mut Server) + Send + 'static,
    test: impl FnOnce(std::net::SocketAddr, mpsc::Receiver<Cx>, Arc<Probe>, Arc<AtomicUsize>)
    + Send
    + 'static,
) {
    let runtime = if workers == 1 {
        RuntimeBuilder::current_thread()
    } else {
        RuntimeBuilder::new().worker_threads(workers)
    }
    .build()
    .unwrap();
    let handle = runtime.handle().clone();
    let (mut server, probe, starts, _retirements) = service();
    configure(Arc::get_mut(&mut server).unwrap());
    runtime.block_on(runtime.handle().spawn(async move {
        let listener = server
            .bind_registered_duplex_http2(
                "127.0.0.1:0",
                HostPolicy::allow_all(),
                ServerDuplexConfig::default(),
            )
            .await
            .unwrap()
            .max_in_flight_requests(NonZeroUsize::new(1).unwrap())
            .max_connection_in_flight_requests(NonZeroUsize::new(1).unwrap());
        let address = listener.local_addr().unwrap();
        let count = listener.in_flight_requests();
        let stop = Stop(listener.shutdown_signal());
        let observed = Arc::clone(&count);
        let peer = std::thread::spawn(move || {
            let _stop = stop;
            let _release = Release(Arc::clone(&probe));
            test(address, starts, probe, count);
        });
        let served = listener.run_streaming_produced(&handle).await;
        peer.join().expect("native duplex raw peer assertions");
        served.unwrap();
        assert_eq!(
            observed.load(Ordering::SeqCst),
            0,
            "shutdown joins request owners"
        );
    }));
    shutdown_native(runtime);
}

#[derive(Clone, Copy, Debug)]
enum Interrupt {
    Reset,
    Cancel,
    Disconnect,
    Deadline,
    InterceptorDeadline,
}

struct ShortDeadline;
impl super::super::Interceptor for ShortDeadline {
    fn intercept_request(&self, request: &mut Request<Bytes>) -> Result<(), Status> {
        assert!(request.metadata_mut().insert("grpc-timeout", "500m"));
        Ok(())
    }
    fn intercept_response(&self, _response: &mut Response<Bytes>) -> Result<(), Status> {
        Ok(())
    }
}

#[test]
fn native_registered_duplex_interruptions_join_actual_service_descendants_before_reusing_admission()
{
    for workers in [1, 2] {
        for mode in [
            Interrupt::Reset,
            Interrupt::Cancel,
            Interrupt::Disconnect,
            Interrupt::Deadline,
            Interrupt::InterceptorDeadline,
        ] {
            bounded_case(move || {
                raw_case(
                    workers,
                    move |server| {
                        if matches!(mode, Interrupt::InterceptorDeadline) {
                            server.interceptors.push(Arc::new(ShortDeadline));
                        }
                    },
                    move |address, starts, probe, count| {
                        let mut peer = RawPeer::new(address, 65535);
                        peer.request(
                            1,
                            "/native.Duplex/Park",
                            matches!(mode, Interrupt::Deadline).then_some("500m"),
                        );
                        let owner = starts
                            .recv_timeout(LIMIT)
                            .expect("actual never-waking response poll");
                        assert_eq!(count.load(Ordering::SeqCst), 1);
                        assert!(!probe.child_cancelled.load(Ordering::Acquire));
                        if matches!(mode, Interrupt::Deadline | Interrupt::InterceptorDeadline) {
                            assert!(
                                owner.budget().deadline.is_some(),
                                "actual service Cx inherits deadline"
                            );
                        }
                        match mode {
                            Interrupt::Reset => peer.send(3, 0, 1, &8_u32.to_be_bytes()),
                            Interrupt::Cancel => owner.cancel_with(
                                CancelKind::User,
                                Some("observed service cancellation"),
                            ),
                            Interrupt::Disconnect => {
                                peer.socket.shutdown(std::net::Shutdown::Both).unwrap()
                            }
                            Interrupt::Deadline | Interrupt::InterceptorDeadline => {}
                        }
                        until(|| probe.child_cancelled.load(Ordering::Acquire));
                        assert!(!probe.child_retired.load(Ordering::Acquire));
                        assert_eq!(
                            count.load(Ordering::SeqCst),
                            1,
                            "request admission remains charged while actual child cleanup is parked"
                        );
                        release(&probe);
                        until(|| probe.child_retired.load(Ordering::Acquire));
                        if !matches!(mode, Interrupt::Reset | Interrupt::Disconnect) {
                            peer.finish();
                            assert_eq!(
                                peer.reset, None,
                                "complete framing permits terminal status"
                            );
                            assert_eq!(
                                peer.field("grpc-status"),
                                Some(if matches!(mode, Interrupt::Cancel) {
                                    "1"
                                } else {
                                    "4"
                                })
                            );
                        }
                        until(|| count.load(Ordering::SeqCst) == 0);
                        assert_eq!(probe.drops.load(Ordering::SeqCst), 1);
                        if matches!(mode, Interrupt::Disconnect) {
                            peer = RawPeer::new(address, 65535);
                            peer.request(1, "/native.Duplex/Aggregate", None);
                        } else {
                            peer.request(3, "/native.Duplex/Aggregate", None);
                        }
                        peer.send(0, 1, peer.stream, &message(b"reuse"));
                        peer.finish();
                        assert_eq!(peer.field("grpc-status"), Some("0"));
                        assert_eq!(probe.calls.load(Ordering::SeqCst), 2);
                        eprintln!(
                            "grpc_duplex_owned workers={workers} mode={mode:?} child_cleanup=joined admission=reused"
                        );
                    },
                )
            });
        }
    }
}

/// A service parked reading its next request message when the call deadline
/// fires reports DEADLINE_EXCEEDED in its trailers, and the connection stays
/// usable. The deadline drops the parked read without polling it again.
#[test]
fn native_registered_duplex_deadline_while_reading_input_reports_deadline_exceeded() {
    for workers in [1, 2] {
        for path in ["/native.Duplex/Aggregate", "/native.Duplex/Echo"] {
            bounded_case(move || {
                raw_case(
                    workers,
                    |_| {},
                    move |address, _starts, probe, count| {
                        let mut peer = RawPeer::new(address, 65535);
                        peer.request(1, path, Some("500m"));
                        let first = message(b"first");
                        peer.send(0, 0, 1, &first);
                        // The service took the first message and is reading
                        // the next one; the upload stays open.
                        until(|| probe.messages.load(Ordering::SeqCst) == 1);
                        peer.finish();
                        assert_eq!(peer.reset, None, "the status trailers end the stream");
                        assert_eq!(peer.field("grpc-status"), Some("4"));
                        if path.ends_with("Echo") {
                            assert_eq!(peer.body, first);
                        }
                        until(|| count.load(Ordering::SeqCst) == 0);
                        // The connection and its HPACK state stay usable.
                        peer.request(3, "/native.Duplex/Aggregate", None);
                        peer.send(0, 1, 3, &message(b"reuse"));
                        peer.finish();
                        assert_eq!(peer.field("grpc-status"), Some("0"));
                    },
                )
            });
        }
    }
}

/// The deadline fires while request input is still in the listener: a full
/// window of DATA the service has not read fills the body queue, so the
/// request trailers wait in the writer. The call still ends with its
/// DEADLINE_EXCEEDED trailers and no reset, and the connection stays usable.
#[test]
fn native_registered_duplex_deadline_with_input_in_flight_reports_deadline_exceeded() {
    for workers in [1, 2] {
        bounded_case(move || {
            raw_case(
                workers,
                |_| {},
                move |address, starts, probe, count| {
                    let mut peer = RawPeer::new(address, 65535);
                    peer.request(1, "/native.Duplex/Park", Some("500m"));
                    let _owner = starts
                        .recv_timeout(LIMIT)
                        .expect("actual never-waking response poll");
                    // One gRPC message spends the whole 65,535-byte window,
                    // which is also the body queue's size.
                    let wire = message(&vec![7_u8; 65_535 - 5]);
                    for chunk in wire.chunks(16 * 1024) {
                        peer.send(0, 0, 1, chunk);
                    }
                    let mut block = Vec::new();
                    literal(&mut block, "x-proof", "in-flight");
                    peer.send(1, 5, 1, &block);
                    until(|| probe.child_cancelled.load(Ordering::Acquire));
                    assert!(!probe.child_retired.load(Ordering::Acquire));
                    release(&probe);
                    until(|| probe.child_retired.load(Ordering::Acquire));
                    peer.finish();
                    assert_eq!(peer.reset, None, "the status trailers end the stream");
                    assert_eq!(peer.field("grpc-status"), Some("4"));
                    until(|| count.load(Ordering::SeqCst) == 0);
                    peer.request(3, "/native.Duplex/Aggregate", None);
                    peer.send(0, 1, 3, &message(b"reuse"));
                    peer.finish();
                    assert_eq!(peer.field("grpc-status"), Some("0"));
                },
            )
        });
    }
}

#[test]
fn native_registered_duplex_validates_request_trailers_and_refuses_swallowed_input_errors() {
    for (wire, trailer, expected) in [
        (message(b"proof"), Some(("x-proof", "exact")), "0"),
        (message(b"proof"), Some(("grpc-timeout", "1H")), "3"),
        (vec![0, 0, 0], None, "3"),
        (vec![1, 0, 0, 0, 0], None, "3"),
        (vec![0, 0, 8, 0, 0], None, "8"),
    ] {
        bounded_case(move || {
            raw_case(
                1,
                |_| {},
                move |address, _starts, _probe, _count| {
                    let mut peer = RawPeer::new(address, 65535);
                    peer.request(1, "/native.Duplex/Ignore", None);
                    peer.send(0, u8::from(trailer.is_none()), 1, &wire);
                    if let Some((name, value)) = trailer {
                        let mut block = Vec::new();
                        literal(&mut block, name, value);
                        peer.send(1, 5, 1, &block);
                    }
                    peer.finish();
                    assert_eq!(peer.reset, None);
                    assert_eq!(peer.field("grpc-status"), Some(expected));
                    if expected == "0" {
                        assert_eq!(peer.field("x-request-proof"), Some("exact"));
                    } else {
                        assert!(
                            peer.body.is_empty(),
                            "observed invalid ingress cannot yield a success message"
                        );
                    }
                },
            )
        });
    }
}

#[test]
fn native_duplex_listener_preserves_unary_server_streaming_and_auth_refusal() {
    struct Deny;
    impl super::super::Interceptor for Deny {
        fn intercept_request(&self, _request: &mut Request<Bytes>) -> Result<(), Status> {
            Err(Status::unauthenticated("native auth refusal"))
        }
        fn intercept_response(&self, _response: &mut Response<Bytes>) -> Result<(), Status> {
            Ok(())
        }
    }
    for path in ["/native.Duplex/Unary", "/native.Duplex/Watch"] {
        bounded_case(move || {
            raw_case(
                1,
                |_| {},
                move |address, _, _, _| {
                    let mut peer = RawPeer::new(address, 65535);
                    peer.request(1, path, None);
                    let wire = message(b"mixed listener");
                    peer.send(0, 1, 1, &wire);
                    peer.finish();
                    assert_eq!(peer.field("grpc-status"), Some("0"));
                    assert_eq!(peer.body, wire);
                },
            )
        });
    }
    bounded_case(|| {
        raw_case(
            1,
            |server| {
                server.interceptors.push(Arc::new(Deny));
            },
            |address, _, probe, _| {
                let mut peer = RawPeer::new(address, 65535);
                peer.request(1, "/native.Duplex/Echo", None);
                // No upload or half-close: authentication must run before waiting for
                // the first message and may reject without collecting attacker input.
                peer.finish();
                assert_eq!(peer.field("grpc-status"), Some("16"));
                assert_eq!(probe.calls.load(Ordering::SeqCst), 0);
                assert!(peer.body.is_empty());
            },
        )
    });
}
