//! Real CONNECT peers for native unary and streaming channel routing.

use super::*;
use crate::bytes::{Bytes, BytesMut};
use crate::codec::Decoder as _;
use crate::grpc::client::{Channel, ClientInterceptor, GrpcClient, ResponseStream};
use crate::grpc::{Code, NativeDuplexEvent, Request, Response, Streaming};
use crate::http::h2::connection::{CLIENT_PREFACE, ReceivedFrame};
use crate::http::h2::{Connection, FrameCodec, Header, Settings};
use crate::runtime::RuntimeBuilder;
use crate::time::{TimerDriverHandle, VirtualClock};
use crate::types::{Budget, CancelKind, Time};
use std::future::{Future, poll_fn};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::task::{Poll, Waker};
use std::time::{Duration, Instant};

const WATCHDOG: Duration = Duration::from_secs(10);
const ORIGIN: &str = "http://origin.invalid:50051";
const PROXY_AUTH: &str = "Basic cHJveHk6c2VjcmV0";

#[derive(Default)]
struct WatchdogSignal {
    expired: AtomicBool,
    waiter: Mutex<Option<Waker>>,
}

struct WallWatchdog {
    signal: Arc<WatchdogSignal>,
    stop: mpsc::Sender<()>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl WallWatchdog {
    fn new() -> Self {
        let signal = Arc::new(WatchdogSignal::default());
        let expired = Arc::clone(&signal);
        let (stop, stopping) = mpsc::channel();
        let thread = std::thread::spawn(move || {
            if matches!(
                stopping.recv_timeout(WATCHDOG),
                Err(mpsc::RecvTimeoutError::Timeout)
            ) {
                expired.expired.store(true, Ordering::Release);
                if let Some(waker) = expired.waiter.lock().unwrap().take() {
                    waker.wake();
                }
            }
        });
        Self {
            signal,
            stop,
            thread: Some(thread),
        }
    }
}

impl Drop for WallWatchdog {
    fn drop(&mut self) {
        let _ = self.stop.send(());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn listener() -> (TcpListener, SocketAddr) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    (listener, address)
}

fn accept(listener: &TcpListener) -> TcpStream {
    let until = Instant::now() + WATCHDOG;
    loop {
        match listener.accept() {
            Ok((socket, _)) => {
                socket.set_nonblocking(false).unwrap();
                socket.set_read_timeout(Some(WATCHDOG)).unwrap();
                socket.set_write_timeout(Some(WATCHDOG)).unwrap();
                return socket;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(Instant::now() < until, "proxy was never contacted");
                std::thread::park_timeout(Duration::from_millis(1));
            }
            Err(error) => panic!("proxy accept failed: {error}"),
        }
    }
}

fn run_native<F, Fut>(test: F)
where
    F: FnOnce(Cx) -> Fut,
    Fut: Future<Output = ()>,
{
    run_native_with_timer(None, test);
}

fn run_native_with_timer<F, Fut>(timer: Option<TimerDriverHandle>, test: F)
where
    F: FnOnce(Cx) -> Fut,
    Fut: Future<Output = ()>,
{
    let mut builder = RuntimeBuilder::current_thread();
    if let Some(timer) = timer {
        builder = builder.with_timer_driver(timer);
    }
    let runtime = builder.build().unwrap();
    let owner = runtime.request_cx_with_budget(Budget::INFINITE);
    let driver = runtime.request_cx_with_budget(Budget::INFINITE);
    // This deadline is independent of the injected virtual protocol clock.
    // Even failure before a peer publishes its witness wakes and ends the test.
    let watchdog = WallWatchdog::new();
    runtime.block_on_with_cx(
        driver,
        Box::pin(async {
            let mut future = Box::pin(test(owner));
            poll_fn(|task| {
                *watchdog.signal.waiter.lock().unwrap() = Some(task.waker().clone());
                assert!(
                    !watchdog.signal.expired.load(Ordering::Acquire),
                    "gRPC proxy wall watchdog elapsed"
                );
                future.as_mut().poll(task)
            })
            .await;
        }),
    );
    drop(watchdog);
    assert!(runtime.shutdown_timeout(WATCHDOG));
}

fn connect_head(io: &mut impl Read, authority: &str) -> String {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        assert!(bytes.len() < 32 * 1024, "bounded CONNECT request");
        let mut byte = [0];
        io.read_exact(&mut byte).expect("CONNECT request");
        bytes.push(byte[0]);
    }
    let head = String::from_utf8(bytes).unwrap();
    assert!(head.starts_with(&format!("CONNECT {authority} HTTP/1.1\r\n")));
    assert_eq!(header_values(&head, "proxy-authorization"), [PROXY_AUTH]);
    assert!(header_values(&head, "authorization").is_empty());
    assert!(!head.contains("origin-secret"));
    assert!(!head.contains("private-call"));
    head
}

fn header_values<'a>(head: &'a str, name: &str) -> Vec<&'a str> {
    head.lines()
        .filter_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case(name).then(|| value.trim())
        })
        .collect()
}

fn framed(payload: &[u8]) -> Bytes {
    let mut bytes = Vec::with_capacity(payload.len() + 5);
    bytes.push(0);
    bytes.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
    bytes.extend_from_slice(payload);
    Bytes::from(bytes)
}

fn output(connection: &mut Connection) -> BytesMut {
    let mut encoded = BytesMut::new();
    while let Some(frame) = connection.next_frame() {
        frame.encode(&mut encoded).unwrap();
    }
    encoded
}

fn flush(io: &mut impl Write, connection: &mut Connection) {
    io.write_all(&output(connection)).unwrap();
    io.flush().unwrap();
}

fn start_tunnel(io: &mut (impl Read + Write), authority: &str) -> Connection {
    connect_head(io, authority);
    let mut connection = Connection::server(Settings::server());
    connection.queue_initial_settings();
    // A peer can send its H2 SETTINGS in the same read as CONNECT success.
    // Losing the tunnel's prefetched bytes would strand streaming setup.
    let mut response = b"HTTP/1.1 200 Connection Established\r\n\r\n".to_vec();
    response.extend_from_slice(&output(&mut connection));
    io.write_all(&response).unwrap();
    io.flush().unwrap();
    connection
}

struct Rpc {
    path: &'static str,
    request: Vec<u8>,
    replies: Vec<&'static [u8]>,
}

fn rpc(path: &'static str, uploads: &[&[u8]], replies: &[&'static [u8]]) -> Rpc {
    Rpc {
        path,
        request: uploads
            .iter()
            .flat_map(|message| framed(message).to_vec())
            .collect(),
        replies: replies.to_vec(),
    }
}

fn serve_h2(
    io: &mut (impl Read + Write),
    mut connection: Connection,
    calls: &[Rpc],
    authority: &str,
    scheme: &str,
) {
    let mut preface = [0; 24];
    io.read_exact(&mut preface).unwrap();
    assert_eq!(&preface, CLIENT_PREFACE);
    let mut decoder = FrameCodec::new();
    let mut inbound = BytesMut::new();
    for call in calls {
        let mut request = Vec::new();
        let mut active = None;
        let stream = loop {
            if let Some(frame) = decoder.decode(&mut inbound).unwrap() {
                let ended = match connection.process_frame(frame).unwrap() {
                    Some(ReceivedFrame::Headers {
                        stream_id,
                        headers,
                        end_stream,
                    }) => {
                        assert!(active.is_none(), "one initial header block");
                        active = Some(stream_id);
                        let value = |name: &str| {
                            headers
                                .iter()
                                .find(|header| header.name == name)
                                .map(|header| header.value.as_str())
                        };
                        assert_eq!(value(":authority"), Some(authority));
                        assert_eq!(value(":scheme"), Some(scheme));
                        assert_eq!(value(":path"), Some(call.path));
                        assert_eq!(value("authorization"), Some("Bearer origin-secret"));
                        assert_eq!(value("x-call"), Some("private-call"));
                        assert_eq!(value("proxy-authorization"), None);
                        end_stream
                    }
                    Some(ReceivedFrame::Data {
                        stream_id,
                        data,
                        end_stream,
                    }) => {
                        assert_eq!(Some(stream_id), active);
                        request.extend_from_slice(&data);
                        end_stream
                    }
                    _ => false,
                };
                flush(io, &mut connection);
                if ended {
                    break active.expect("request headers");
                }
            } else {
                let mut bytes = [0; 4096];
                let received = io.read(&mut bytes).expect("HTTP/2 request");
                assert_ne!(received, 0, "request ended before half-close");
                inbound.extend_from_slice(&bytes[..received]);
            }
        };
        assert_eq!(request, call.request);
        connection
            .send_headers(
                stream,
                vec![
                    Header::new(":status", "200"),
                    Header::new("content-type", "application/grpc"),
                    Header::new("x-origin", "verified"),
                ],
                false,
            )
            .unwrap();
        for reply in &call.replies {
            connection.send_data(stream, framed(reply), false).unwrap();
        }
        connection
            .send_headers(
                stream,
                vec![
                    Header::new("grpc-status", "0"),
                    Header::new("x-finished", "yes"),
                ],
                true,
            )
            .unwrap();
        flush(io, &mut connection);
    }
}

fn request<T>(body: T) -> Request<T> {
    let mut request = Request::new(body);
    assert!(
        request
            .metadata_mut()
            .insert("authorization", "Bearer origin-secret")
    );
    assert!(request.metadata_mut().insert("x-call", "private-call"));
    request
}

fn proxy(address: SocketAddr) -> HttpConnectProxy {
    HttpConnectProxy::new(format!("http://{address}"))
        .unwrap()
        .with_authorization(PROXY_AUTH)
        .unwrap()
        .with_http_client(
            HttpClient::builder()
                .default_header("Authorization", "http-client-default-secret")
                .default_header("Proxy-Authorization", "wrong-default-proxy-secret")
                .build(),
        )
}

async fn channel(address: SocketAddr) -> Channel {
    Channel::builder(ORIGIN)
        .http_connect_proxy(proxy(address))
        .connect_timeout(WATCHDOG)
        .timeout(WATCHDOG)
        .connect()
        .await
        .unwrap()
}

#[test]
fn proxy_configuration_is_explicit_validated_and_redacted() {
    for url in [
        "socks5://proxy:1080",
        "http://user:secret@proxy:3128",
        "http://proxy:0",
        "http://proxy:3128/path",
        "http://proxy?query",
        "http://proxy/#fragment",
        "http://proxy\r\nX-Injected: yes",
    ] {
        assert!(HttpConnectProxy::new(url).is_err(), "accepted {url:?}");
    }
    for auth in ["", "secret\r\nX-Injected: yes", "secret\0"] {
        assert!(
            HttpConnectProxy::new("http://proxy:3128")
                .unwrap()
                .with_authorization(auth)
                .is_err()
        );
    }
    let configured = HttpConnectProxy::new("http://[::1]:3128")
        .unwrap()
        .with_authorization("Bearer sensitive-proxy-token")
        .unwrap();
    assert_eq!(configured.url, "http://[::1]:3128");
    assert!(!format!("{configured:?}").contains("sensitive-proxy-token"));
    for target in ["http://loopback", "unix:/tmp/grpc-proxy-fixture.sock"] {
        assert!(
            futures_lite::future::block_on(
                Channel::builder(target)
                    .http_connect_proxy(configured.clone())
                    .connect(),
            )
            .is_err()
        );
    }
}

#[test]
fn native_unary_connect_tunnel_preserves_prefetched_frames_credentials_and_pool_reuse() {
    let (listener, address) = listener();
    let peer = std::thread::spawn(move || {
        let mut socket = accept(&listener);
        let connection = start_tunnel(&mut socket, "origin.invalid:50051");
        serve_h2(
            &mut socket,
            connection,
            &[
                rpc("/proxy.Service/Echo", &[b"first"], &[b"reply-one"]),
                rpc("/proxy.Service/Echo", &[b"second"], &[b"reply-two"]),
            ],
            "origin.invalid:50051",
            "http",
        );
        assert!(
            matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
            "completed unary calls must reuse their fixed proxy route"
        );
    });
    run_native(move |_| async move {
        let channel = Channel::builder(ORIGIN)
            .http_connect_proxy(proxy(address))
            .connect_timeout(WATCHDOG)
            .timeout(WATCHDOG)
            .reuse_connections(1)
            .connect()
            .await
            .unwrap();
        let mut client = GrpcClient::new(channel.clone());
        for (body, expected) in [
            (b"first".as_slice(), b"reply-one".as_slice()),
            (b"second", b"reply-two"),
        ] {
            let response: Response<Bytes> = Box::pin(
                client.unary("/proxy.Service/Echo", request(Bytes::copy_from_slice(body))),
            )
            .await
            .unwrap();
            assert_eq!(response.get_ref().as_ref(), expected);
        }
        assert_eq!(
            channel
                .unary_pool
                .as_ref()
                .unwrap()
                .idle
                .lock()
                .unwrap()
                .len(),
            1
        );
    });
    peer.join().unwrap();
}

async fn next(stream: &mut ResponseStream<Bytes>) -> Option<Result<Bytes, Status>> {
    poll_fn(|task| Pin::new(&mut *stream).poll_next(task)).await
}

#[test]
fn native_and_legacy_streaming_facades_use_connect_and_preserve_terminal_metadata() {
    for shape in [
        "native-server",
        "native-bidi",
        "legacy-server",
        "legacy-bidi",
        "legacy-upload",
    ] {
        let (listener, address) = listener();
        let peer = std::thread::spawn(move || {
            let mut socket = accept(&listener);
            let connection = start_tunnel(&mut socket, "origin.invalid:50051");
            let uploads: &[&[u8]] = if shape.ends_with("server") {
                &[b"request"]
            } else {
                &[b"a", b"b"]
            };
            let replies: &[&[u8]] = if shape == "legacy-upload" {
                &[b"one"]
            } else {
                &[b"one", b"two"]
            };
            serve_h2(
                &mut socket,
                connection,
                &[rpc("/proxy.Service/Stream", uploads, replies)],
                "origin.invalid:50051",
                "http",
            );
        });
        run_native(move |cx| async move {
            let channel = channel(address).await;
            let mut client = GrpcClient::new(channel).with_interceptor(
                crate::grpc::MetadataInterceptor::new()
                    .with_metadata("authorization", "Bearer origin-secret")
                    .with_metadata("x-call", "private-call"),
            );
            let messages = match shape {
                "native-server" => {
                    let mut stream = Box::pin(client.into_native_server_streaming(
                        &cx,
                        "/proxy.Service/Stream",
                        Request::new(Bytes::from_static(b"request")),
                    ))
                    .await
                    .unwrap();
                    let mut messages = Vec::new();
                    while let Some(message) = stream.message().await.unwrap() {
                        messages.push(message);
                    }
                    assert!(stream.trailers().unwrap().get("x-finished").is_some());
                    messages
                }
                "native-bidi" => {
                    let mut stream = Box::pin(client.into_native_duplex(
                        &cx,
                        "/proxy.Service/Stream",
                        Request::new(()),
                    ))
                    .await
                    .unwrap();
                    let mut uploads = [b"a".as_slice(), b"b".as_slice()].into_iter();
                    let mut closed = false;
                    let mut messages = Vec::new();
                    while let Some(event) = stream.next_event().await.unwrap() {
                        match event {
                            NativeDuplexEvent::RequestFlushed if !closed => {
                                if let Some(body) = uploads.next() {
                                    stream.queue_message(&Bytes::copy_from_slice(body)).unwrap();
                                } else {
                                    stream.close_requests().unwrap();
                                    closed = true;
                                }
                            }
                            NativeDuplexEvent::Message(message) => messages.push(message),
                            NativeDuplexEvent::RequestFlushed => {}
                        }
                    }
                    assert!(closed);
                    assert!(stream.trailers().unwrap().get("x-finished").is_some());
                    messages
                }
                "legacy-server" => {
                    let response = Box::pin(client.server_streaming::<Bytes, Bytes>(
                        "/proxy.Service/Stream",
                        Request::new(Bytes::from_static(b"request")),
                    ))
                    .await
                    .unwrap();
                    let mut stream = response.into_inner();
                    let mut messages = Vec::new();
                    while let Some(message) = next(&mut stream).await {
                        messages.push(message.unwrap());
                    }
                    assert!(stream.terminal_metadata().get("x-finished").is_some());
                    messages
                }
                "legacy-bidi" => {
                    let (mut sink, mut stream) =
                        Box::pin(client.bidi_streaming::<Bytes, Bytes>("/proxy.Service/Stream"))
                            .await
                            .unwrap();
                    sink.send(Bytes::from_static(b"a")).await.unwrap();
                    sink.send(Bytes::from_static(b"b")).await.unwrap();
                    sink.close().await.unwrap();
                    let mut messages = Vec::new();
                    while let Some(message) = next(&mut stream).await {
                        messages.push(message.unwrap());
                    }
                    assert!(stream.terminal_metadata().get("x-finished").is_some());
                    messages
                }
                _ => {
                    let (mut sink, response) =
                        Box::pin(client.client_streaming::<Bytes, Bytes>("/proxy.Service/Stream"))
                            .await
                            .unwrap();
                    sink.send(Bytes::from_static(b"a")).await.unwrap();
                    sink.send(Bytes::from_static(b"b")).await.unwrap();
                    sink.close().await.unwrap();
                    vec![response.await.unwrap().into_inner()]
                }
            };
            let expected = if shape == "legacy-upload" {
                vec![Bytes::from_static(b"one")]
            } else {
                vec![Bytes::from_static(b"one"), Bytes::from_static(b"two")]
            };
            assert_eq!(messages, expected, "{shape}");
        });
        peer.join().unwrap();
    }
}

#[test]
fn interceptor_proxy_credentials_are_refused_before_any_transport_is_opened() {
    struct InjectProxyAuth;
    impl ClientInterceptor for InjectProxyAuth {
        fn intercept(&self, request: &mut Request<Bytes>) -> Result<(), Status> {
            assert!(
                request
                    .metadata_mut()
                    .insert("proxy-authorization", "Bearer misplaced-secret")
            );
            Ok(())
        }
    }
    let (listener, address) = listener();
    run_native(move |cx| async move {
        let channel = channel(address).await;
        let mut unary = GrpcClient::new(channel.clone()).with_interceptor(InjectProxyAuth);
        let result: Result<Response<Bytes>, _> =
            Box::pin(unary.unary("/proxy.Service/Echo", Request::new(Bytes::new()))).await;
        assert_eq!(result.unwrap_err().code(), Code::InvalidArgument);
        let client = GrpcClient::new(channel.clone()).with_interceptor(InjectProxyAuth);
        let result =
            Box::pin(client.into_native_duplex(&cx, "/proxy.Service/Stream", Request::new(())))
                .await;
        assert_eq!(result.err().unwrap().code(), Code::InvalidArgument);
        let mut legacy = GrpcClient::new(channel).with_interceptor(InjectProxyAuth);
        assert_eq!(
            Box::pin(legacy.server_streaming::<Bytes, Bytes>(
                "/proxy.Service/Stream",
                Request::new(Bytes::new()),
            ))
            .await
            .err()
            .unwrap()
            .code(),
            Code::InvalidArgument
        );
    });
    assert!(
        matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
    );
}

#[test]
fn connect_refusal_and_redirect_never_replay_rpc_credentials_or_fall_back_directly() {
    for status in [302, 407] {
        let (listener, address) = listener();
        let (origin, target) = self::listener();
        let peer = std::thread::spawn(move || {
            let mut socket = accept(&listener);
            connect_head(&mut socket, &target.to_string());
            write!(socket, "HTTP/1.1 {status} proxy-secret\r\nLocation: http://{target}/redirect\r\nContent-Length: 0\r\n\r\n").unwrap();
            let mut byte = [0];
            assert_eq!(
                socket.read(&mut byte).unwrap(),
                0,
                "refusal must close before sending RPC bytes"
            );
            assert!(
                matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
                "CONNECT must not retry after a refusal"
            );
        });
        run_native(move |_| async move {
            let channel = Channel::builder(format!("http://{target}"))
                .http_connect_proxy(proxy(address))
                .timeout(WATCHDOG)
                .connect()
                .await
                .unwrap();
            let mut client = GrpcClient::new(channel);
            let result: Result<Response<Bytes>, _> = Box::pin(client.unary(
                "/proxy.Service/Echo",
                request(Bytes::from_static(b"private-body")),
            ))
            .await;
            let error = result.unwrap_err();
            assert_eq!(error.code(), Code::Unavailable);
            assert!(error.message().contains(&status.to_string()));
            assert!(!error.message().contains("proxy-secret"));
        });
        peer.join().unwrap();
        assert!(
            matches!(origin.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
            "neither proxy redirects nor direct fallback may open the origin"
        );
    }
}

#[derive(Default)]
struct ConnectWitness {
    received: AtomicBool,
    waiter: Mutex<Option<Waker>>,
}

impl ConnectWitness {
    fn publish(&self) {
        self.received.store(true, Ordering::Release);
        if let Some(waker) = self.waiter.lock().unwrap().take() {
            waker.wake();
        }
    }
}

#[test]
fn parked_connect_observes_original_owner_cancellation_call_deadline_and_drop() {
    for streaming in [false, true] {
        for mode in ["cancel", "deadline", "drop"] {
            let (listener, address) = listener();
            let witness = Arc::new(ConnectWitness::default());
            let observed = Arc::clone(&witness);
            let peer = std::thread::spawn(move || {
                let mut socket = accept(&listener);
                connect_head(&mut socket, "origin.invalid:50051");
                observed.publish();
                let mut byte = [0];
                assert_eq!(
                    socket.read(&mut byte).unwrap(),
                    0,
                    "a parked CONNECT must retire its socket without RPC output"
                );
            });
            let clock = Arc::new(VirtualClock::starting_at(Time::from_secs(10)));
            let timer = TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
            run_native_with_timer(Some(timer), move |owner| async move {
                let driver = Cx::current().unwrap();
                assert_ne!(driver.task_id(), owner.task_id());
                let channel = Channel::builder(ORIGIN)
                    .http_connect_proxy(proxy(address))
                    .connect_timeout(WATCHDOG)
                    .timeout(Duration::from_secs(1))
                    .connect()
                    .await
                    .unwrap();
                let mut client = GrpcClient::new(channel);
                let explicit = owner.clone();
                let mut call = Box::pin(async move {
                    if streaming {
                        Box::pin(client.into_native_duplex(
                            &explicit,
                            "/proxy.Service/Stream",
                            request(()),
                        ))
                        .await
                        .map(|_| ())
                    } else {
                        let response: Result<Response<Bytes>, _> =
                            Box::pin(client.unary("/proxy.Service/Echo", request(Bytes::new())))
                                .await;
                        response.map(|_| ())
                    }
                });
                let mut interrupted = false;
                let result = poll_fn(|task| {
                    *witness.waiter.lock().unwrap() = Some(task.waker().clone());
                    // Unary uses its documented ambient owner; explicit
                    // streaming retains the same owner inside Setup::run.
                    // The surrounding driver is deliberately a different Cx.
                    let polled = if streaming {
                        call.as_mut().poll(task)
                    } else {
                        let _owner = Cx::set_current(Some(owner.clone()));
                        call.as_mut().poll(task)
                    };
                    if let Poll::Ready(result) = polled {
                        return Poll::Ready(Some(result));
                    }
                    if witness.received.load(Ordering::Acquire) && !interrupted {
                        interrupted = true;
                        match mode {
                            "cancel" => {
                                owner.cancel_with(CancelKind::User, Some("proxy setup stopped"))
                            }
                            "deadline" => {
                                clock.advance_to(Time::from_secs(12));
                                task.waker().wake_by_ref();
                            }
                            _ => return Poll::Ready(None),
                        }
                    }
                    Poll::Pending
                })
                .await;
                drop(call);
                assert!(interrupted, "CONNECT never parked: {streaming}/{mode}");
                match mode {
                    "cancel" => assert_eq!(result.unwrap().unwrap_err().code(), Code::Cancelled),
                    "deadline" => {
                        assert_eq!(result.unwrap().unwrap_err().code(), Code::DeadlineExceeded)
                    }
                    _ => assert!(result.is_none()),
                }
                assert!(owner.inner.read().cancel_waker_registrations.is_empty());
                assert!(
                    !driver.is_cancel_requested(),
                    "cancelling a call must not cancel its poller"
                );
            });
            peer.join().unwrap();
        }
    }
}

#[cfg(feature = "tls")]
const CERT: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/tls/server.crt"
));

#[cfg(feature = "tls")]
fn tls_server<T: Read + Write>(
    io: T,
    protocol: &[u8],
) -> rustls::StreamOwned<rustls::ServerConnection, T> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
    let key = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/tls/server.key"
    ));
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![CertificateDer::from_pem_slice(CERT).unwrap()],
        PrivateKeyDer::from_pem_slice(key).unwrap(),
    )
    .unwrap();
    if !protocol.is_empty() {
        config.alpn_protocols = vec![protocol.to_vec()];
    }
    rustls::StreamOwned::new(rustls::ServerConnection::new(Arc::new(config)).unwrap(), io)
}

#[cfg(feature = "tls")]
fn origin_connector(trust: bool) -> crate::tls::TlsConnector {
    use rustls::pki_types::{CertificateDer, pem::PemObject};
    let mut roots = rustls::RootCertStore::empty();
    if trust {
        roots
            .add(CertificateDer::from_pem_slice(CERT).unwrap())
            .unwrap();
    }
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];
    crate::tls::TlsConnector::new(config)
}

#[cfg(feature = "tls")]
fn tls_proxy(address: SocketAddr, https: bool, trust: bool) -> HttpConnectProxy {
    let scheme = if https { "https" } else { "http" };
    let roots = if trust {
        crate::tls::Certificate::from_pem(CERT).unwrap()
    } else {
        Vec::new()
    };
    HttpConnectProxy::new(format!("{scheme}://localhost:{}", address.port()))
        .unwrap()
        .with_authorization(PROXY_AUTH)
        .unwrap()
        .with_http_client(HttpClient::with_config(crate::http::h1::HttpClientConfig {
            tls_root_certificates: roots,
            ..Default::default()
        }))
}

#[cfg(feature = "tls")]
fn serve_tls_route<T: Read + Write>(mut io: T, origin_tls: bool, destination: SocketAddr) {
    if origin_tls {
        connect_head(&mut io, &destination.to_string());
        io.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .unwrap();
        io.flush().unwrap();
        let mut tls = tls_server(io, b"h2");
        let mut connection = Connection::server(Settings::server());
        connection.queue_initial_settings();
        flush(&mut tls, &mut connection);
        assert_eq!(
            tls.conn.server_name(),
            Some("localhost"),
            "origin SNI is independent of CONNECT destination"
        );
        serve_h2(
            &mut tls,
            connection,
            &[rpc(
                "/proxy.Service/Echo",
                &[b"request"],
                &[b"authenticated"],
            )],
            "service.invalid",
            "https",
        );
    } else {
        let connection = start_tunnel(&mut io, "origin.invalid:50051");
        serve_h2(
            &mut io,
            connection,
            &[rpc(
                "/proxy.Service/Echo",
                &[b"request"],
                &[b"authenticated"],
            )],
            "origin.invalid:50051",
            "http",
        );
    }
}

#[cfg(feature = "tls")]
#[test]
fn native_connect_routes_authenticate_tls_origins_and_https_proxies_independently() {
    for (https_proxy, origin_tls) in [(false, true), (true, false), (true, true)] {
        let (listener, address) = listener();
        let destination: SocketAddr = "127.0.0.1:50123".parse().unwrap();
        let peer = std::thread::spawn(move || {
            let socket = accept(&listener);
            if https_proxy {
                serve_tls_route(tls_server(socket, b"http/1.1"), origin_tls, destination);
            } else {
                serve_tls_route(socket, origin_tls, destination);
            }
        });
        run_native(move |_| async move {
            let uri = if origin_tls {
                "https://service.invalid"
            } else {
                ORIGIN
            };
            let mut builder = Channel::builder(uri)
                .http_connect_proxy(tls_proxy(address, https_proxy, true))
                .connect_timeout(WATCHDOG)
                .timeout(WATCHDOG);
            if origin_tls {
                builder = builder
                    .tls_connector(origin_connector(true))
                    .tls_server_name("localhost")
                    .dial_addr(destination);
            }
            let channel = builder.connect().await.unwrap();
            let mut client = GrpcClient::new(channel);
            let response: Response<Bytes> = Box::pin(client.unary(
                "/proxy.Service/Echo",
                request(Bytes::from_static(b"request")),
            ))
            .await
            .unwrap();
            assert_eq!(response.get_ref().as_ref(), b"authenticated");
        });
        peer.join().unwrap();
    }
}

#[cfg(feature = "tls")]
fn assert_no_tls_application_bytes(result: std::io::Result<usize>) {
    match result {
        Ok(0) => {}
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::UnexpectedEof
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::InvalidData
            ) => {}
        other => panic!("TLS refusal must retire transport before RPC bytes, got {other:?}"),
    }
}

#[cfg(feature = "tls")]
fn refuse_origin_tls<T: Read + Write>(mut io: T, destination: SocketAddr, mode: &str) {
    connect_head(&mut io, &destination.to_string());
    io.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .unwrap();
    io.flush().unwrap();
    // No ALPN overlap completes TLS without negotiating h2 only when the
    // server offers no protocol, so clear the offer in that negative case.
    let mut tls = tls_server(io, if mode == "missing-h2" { b"" } else { b"h2" });
    assert_no_tls_application_bytes(tls.read(&mut [0]));
}

#[cfg(feature = "tls")]
#[test]
fn connect_tunnels_preserve_origin_identity_trust_and_required_h2_alpn() {
    for mode in [
        "wrong-name",
        "untrusted-origin",
        "missing-h2",
        "untrusted-proxy",
    ] {
        let (listener, address) = listener();
        let destination: SocketAddr = "127.0.0.1:50123".parse().unwrap();
        let https_proxy = matches!(mode, "untrusted-origin" | "untrusted-proxy");
        let peer = std::thread::spawn(move || {
            let socket = accept(&listener);
            if https_proxy {
                let mut tls = tls_server(socket, b"http/1.1");
                if mode == "untrusted-proxy" {
                    assert_no_tls_application_bytes(tls.read(&mut [0]));
                } else {
                    refuse_origin_tls(tls, destination, mode);
                }
            } else {
                refuse_origin_tls(socket, destination, mode);
            }
        });
        run_native(move |_| async move {
            let channel = Channel::builder("https://service.invalid")
                .http_connect_proxy(tls_proxy(address, https_proxy, mode != "untrusted-proxy"))
                .tls_connector(origin_connector(mode != "untrusted-origin"))
                .tls_server_name(if mode == "wrong-name" {
                    "wrong.invalid"
                } else {
                    "localhost"
                })
                .dial_addr(destination)
                .connect_timeout(WATCHDOG)
                .timeout(WATCHDOG)
                .connect()
                .await
                .unwrap();
            let mut client = GrpcClient::new(channel);
            let result: Result<Response<Bytes>, _> = Box::pin(client.unary(
                "/proxy.Service/Echo",
                request(Bytes::from_static(b"must-not-send")),
            ))
            .await;
            let error = result.unwrap_err();
            assert_eq!(error.code(), Code::Unavailable, "{mode}");
            if mode == "missing-h2" {
                assert!(error.message().contains("required h2 ALPN"));
            }
        });
        peer.join().unwrap();
    }
}
