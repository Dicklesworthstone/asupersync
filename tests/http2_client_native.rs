//! General HTTP/2 client against the production listener and scripted TCP peers.
#![cfg(all(not(target_arch = "wasm32"), feature = "test-internals"))]
#![recursion_limit = "256"]

use std::future::{Future, poll_fn};
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

use asupersync::bytes::{Bytes, BytesMut};
use asupersync::codec::Decoder;
use asupersync::cx::Cx;
use asupersync::http::h1::server::HostPolicy;
use asupersync::http::h2::connection::{CLIENT_PREFACE, ReceivedFrame};
use asupersync::http::h2::frame::{GoAwayFrame, HeadersFrame, Setting, SettingsFrame};
use asupersync::http::h2::listener::{Http2Listener, Http2ListenerConfig};
use asupersync::http::h2::{
    Connection, ErrorCode, Frame, FrameCodec, Header, Http2Client, Http2ClientError, Settings,
};
use asupersync::http::{Method, Request, Response};
use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::types::{Budget, CancelReason};

const LARGE_BODY: usize = 4 * 65_535 + 123;

fn runtime(workers: usize) -> Runtime {
    let builder = if workers == 1 {
        RuntimeBuilder::current_thread()
    } else {
        RuntimeBuilder::multi_thread().worker_threads(workers)
    };
    builder
        .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
        .build()
        .unwrap()
}

fn quiescent(runtime: &Runtime) {
    let start = Instant::now();
    while !runtime.is_quiescent() {
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "HTTP/2 owner failed to retire"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
    assert_eq!(runtime.draining_region_count(), 0);
}

fn config() -> Http2ListenerConfig {
    Http2ListenerConfig::default()
        .host_policy(HostPolicy::allow_all())
        .max_body_size(2 * LARGE_BODY)
        .drain_timeout(Duration::from_secs(2))
        .hard_drain_timeout(Duration::from_secs(5))
}

#[test]
fn public_http2_client_uploads_and_downloads_beyond_both_initial_windows() {
    for workers in [1, 2] {
        let runtime = runtime(workers);
        let handle = runtime.handle();
        runtime.block_on(async move {
            let listener = Http2Listener::bind_with_config(
                "127.0.0.1:0",
                |request: Request| async move {
                    assert_eq!(request.method, Method::Post);
                    assert_eq!(request.uri, "/echo?probe=flow");
                    assert_eq!(request.body.len(), LARGE_BODY);
                    Response::new(200, "OK", request.body)
                },
                config(),
            )
            .await
            .unwrap();
            let address = listener.local_addr().unwrap();
            let shutdown = listener.shutdown_signal();
            let server = handle
                .clone()
                .try_spawn(async move { listener.run(&handle).await })
                .unwrap();
            let cx = Cx::current().unwrap();
            let body: Vec<u8> = (0..LARGE_BODY).map(|index| (index % 251) as u8).collect();
            let response = Http2Client::new()
                .timeout(Duration::from_secs(5))
                .post(format!("http://{address}/echo?probe=flow#not-on-wire"))
                .header("Content-Type", "application/octet-stream")
                .body(body.clone())
                .send(&cx)
                .await
                .unwrap();
            assert_eq!(response.status, 200);
            assert_eq!(response.body.as_ref(), body);
            assert!(shutdown.begin_drain(Duration::from_secs(2)));
            server.await.unwrap();
        });
        quiescent(&runtime);
    }
}

/// The client advertises receive windows that track max_response_body,
/// capped at 16 MiB. Only a response larger than that cap makes the server
/// wait for the client's WINDOW_UPDATE frames, so this download crosses it.
/// Without the client's receive-side refill the server stalls at 16 MiB and
/// the request times out.
#[test]
fn public_http2_client_downloads_beyond_its_largest_receive_window() {
    const DOWNLOAD: usize = 16 * 1024 * 1024 + 1024 * 1024 + 7;
    let runtime = runtime(2);
    let handle = runtime.handle();
    runtime.block_on(async move {
        let listener = Http2Listener::bind_with_config(
            "127.0.0.1:0",
            |request: Request| async move {
                assert_eq!(request.method, Method::Get);
                let body: Vec<u8> = (0..DOWNLOAD).map(|index| (index % 253) as u8).collect();
                Response::new(200, "OK", body)
            },
            config(),
        )
        .await
        .unwrap();
        let address = listener.local_addr().unwrap();
        let shutdown = listener.shutdown_signal();
        let server = handle
            .clone()
            .try_spawn(async move { listener.run(&handle).await })
            .unwrap();
        let cx = Cx::current().unwrap();
        let response = Http2Client::new()
            .timeout(Duration::from_secs(60))
            .max_response_body(2 * DOWNLOAD)
            .get(format!("http://{address}/download"))
            .send(&cx)
            .await
            .expect("the download completes once the client refills its windows");
        assert_eq!(response.status, 200);
        assert_eq!(response.body.len(), DOWNLOAD);
        assert!(
            response
                .body
                .iter()
                .enumerate()
                .all(|(index, byte)| usize::from(*byte) == index % 253),
            "the downloaded body is byte-identical"
        );
        assert!(shutdown.begin_drain(Duration::from_secs(2)));
        server.await.unwrap();
    });
    quiescent(&runtime);
}

struct Peer {
    io: std::net::TcpStream,
    codec: FrameCodec,
    input: BytesMut,
    connection: Connection,
}

impl Peer {
    fn accept(listener: std::net::TcpListener, window: u32) -> Self {
        let (mut io, _) = listener.accept().unwrap();
        io.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        io.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut preface = [0u8; 24];
        io.read_exact(&mut preface).unwrap();
        assert_eq!(&preface, CLIENT_PREFACE);
        let mut peer = Self {
            io,
            codec: FrameCodec::new(),
            input: BytesMut::new(),
            connection: Connection::server(Settings {
                initial_window_size: window,
                ..Settings::server()
            }),
        };
        peer.connection.queue_initial_settings();
        peer.flush();
        peer
    }

    fn frame(&mut self, frame: Frame) {
        let mut bytes = BytesMut::new();
        frame.encode(&mut bytes).unwrap();
        self.io.write_all(&bytes).unwrap();
    }

    fn flush(&mut self) {
        while let Some(frame) = self.connection.next_frame() {
            self.frame(frame);
        }
        self.io.flush().unwrap();
    }

    fn receive(&mut self) -> Option<ReceivedFrame> {
        loop {
            if let Some(frame) = self.codec.decode(&mut self.input).unwrap() {
                let received = self.connection.process_frame(frame).unwrap();
                self.flush();
                return received;
            }
            let mut bytes = [0u8; 8192];
            let read = self.io.read(&mut bytes).unwrap();
            assert_ne!(read, 0, "client unexpectedly closed before request");
            self.input.extend_from_slice(&bytes[..read]);
        }
    }

    fn request(&mut self) -> u32 {
        loop {
            if let Some(ReceivedFrame::Headers {
                stream_id, headers, ..
            }) = self.receive()
            {
                assert_eq!(headers[0].value, "POST");
                return stream_id;
            }
        }
    }

    fn eof(&mut self) {
        let mut bytes = [0u8; 8192];
        loop {
            match self.io.read(&mut bytes) {
                Ok(0) => return,
                Ok(_) => {}
                // Some platforms report reset when a connection is dropped
                // with unread peer frames. Both results release the socket.
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => return,
                Err(error) => panic!("owned client socket did not close: {error}"),
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Reply {
    Early,
    Metadata,
    Reset,
    GoAwayRefused,
    GoAwayAccepted,
    Truncated,
    OverLimit,
}

#[test]
fn early_responses_metadata_resets_and_goaway_have_real_wire_semantics() {
    for workers in [1, 2] {
        for reply in [
            Reply::Early,
            Reply::Metadata,
            Reply::Reset,
            Reply::GoAwayRefused,
            Reply::GoAwayAccepted,
            Reply::Truncated,
            Reply::OverLimit,
        ] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let peer = std::thread::spawn(move || {
                // No request DATA can be sent until the server grants credit.
                // All replies exercise reads while the upload is blocked.
                let mut peer = Peer::accept(listener, 0);
                let id = peer.request();
                match reply {
                    Reply::Early => peer
                        .connection
                        .send_headers(id, vec![Header::new(":status", "413")], true)
                        .unwrap(),
                    Reply::Reset => peer.connection.reset_stream(id, ErrorCode::Cancel),
                    Reply::GoAwayRefused => {
                        peer.frame(Frame::GoAway(GoAwayFrame::new(0, ErrorCode::NoError)))
                    }
                    Reply::Metadata | Reply::GoAwayAccepted => {
                        if matches!(reply, Reply::GoAwayAccepted) {
                            peer.frame(Frame::GoAway(GoAwayFrame::new(id, ErrorCode::NoError)));
                        }
                        peer.connection
                            .send_headers(
                                id,
                                vec![
                                    Header::new(":status", "103"),
                                    Header::new("link", "</hint>"),
                                ],
                                false,
                            )
                            .unwrap();
                        peer.connection
                            .send_headers(
                                id,
                                vec![
                                    Header::new(":status", "200"),
                                    Header::new("content-length", "3"),
                                ],
                                false,
                            )
                            .unwrap();
                        peer.connection
                            .send_data(id, Bytes::from_static(b"abc"), false)
                            .unwrap();
                        peer.connection
                            .send_headers(id, vec![Header::new("x-checksum", "yes")], true)
                            .unwrap();
                    }
                    Reply::Truncated => {
                        peer.connection
                            .send_headers(
                                id,
                                vec![
                                    Header::new(":status", "200"),
                                    Header::new("content-length", "3"),
                                ],
                                false,
                            )
                            .unwrap();
                        peer.connection
                            .send_data(id, Bytes::from_static(b"ab"), true)
                            .unwrap();
                    }
                    Reply::OverLimit => peer
                        .connection
                        .send_headers(
                            id,
                            vec![
                                Header::new(":status", "200"),
                                Header::new("content-length", "99"),
                            ],
                            false,
                        )
                        .unwrap(),
                }
                peer.flush();
                peer.eof();
            });
            let runtime = runtime(workers);
            runtime.block_on(async move {
                let cx = Cx::current().unwrap();
                let result = Http2Client::new()
                    .timeout(Duration::from_secs(3))
                    .max_response_body(16)
                    .post(format!("http://{address}/early"))
                    .body(vec![1; LARGE_BODY])
                    .send(&cx)
                    .await;
                match reply {
                    Reply::Early => {
                        assert_eq!(result.unwrap().status, 413);
                    }
                    Reply::Metadata | Reply::GoAwayAccepted => {
                        let response = result.unwrap();
                        assert_eq!(response.status, 200);
                        assert_eq!(response.text().unwrap(), "abc");
                        assert!(response.header("link").is_none());
                        assert_eq!(response.trailers[0].name, "x-checksum");
                    }
                    Reply::Reset => assert!(matches!(
                        result,
                        Err(Http2ClientError::Reset(ErrorCode::Cancel))
                    )),
                    Reply::GoAwayRefused => assert!(matches!(
                        result,
                        Err(Http2ClientError::GoAway {
                            last_stream_id: 0,
                            ..
                        })
                    )),
                    Reply::Truncated => {
                        assert!(matches!(result, Err(Http2ClientError::Protocol(_))))
                    }
                    Reply::OverLimit => assert!(matches!(
                        result,
                        Err(Http2ClientError::BodyTooLarge {
                            request: false,
                            limit: 16
                        })
                    )),
                }
            });
            peer.join().unwrap();
            quiescent(&runtime);
        }
    }
}

#[test]
fn cancelled_explicit_caller_wakes_silent_peer_wait_and_releases_socket() {
    for workers in [1, 2] {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (headers_tx, headers_rx) = mpsc::channel();
        let peer = std::thread::spawn(move || {
            let mut peer = Peer::accept(listener, 0);
            peer.request();
            headers_tx.send(()).unwrap();
            peer.eof();
        });
        let runtime = runtime(workers);
        let caller = runtime.request_cx_with_budget(Budget::INFINITE);
        let reason = CancelReason::deadline()
            .with_message("HTTP request owner expired")
            .with_cause(CancelReason::user("upstream request cancelled"));
        let controller_caller = caller.clone();
        let controller_reason = reason.clone();
        let (waker_tx, waker_rx) = mpsc::channel::<std::task::Waker>();
        let (parked_tx, parked_rx) = mpsc::channel();
        let probe = Arc::new(AtomicBool::new(false));
        let controller_probe = Arc::clone(&probe);
        let controller = std::thread::spawn(move || {
            headers_rx.recv_timeout(Duration::from_secs(3)).unwrap();
            controller_probe.store(true, Ordering::Release);
            waker_rx
                .recv_timeout(Duration::from_secs(3))
                .unwrap()
                .wake();
            parked_rx.recv_timeout(Duration::from_secs(3)).unwrap();
            controller_caller.cancel_with_reason(controller_reason);
        });
        runtime.block_on(async move {
            assert_ne!(caller.task_id(), Cx::current().unwrap().task_id());
            let mut request = Box::pin(
                Http2Client::new()
                    .timeout(Duration::from_secs(4))
                    .post(format!("http://{address}/silent"))
                    .body("pending")
                    .send(&caller),
            );
            let mut waker_sent = false;
            let mut parked_sent = false;
            let result = poll_fn(|task| {
                if !waker_sent {
                    waker_tx.send(task.waker().clone()).unwrap();
                    waker_sent = true;
                }
                let result = request.as_mut().poll(task);
                if result.is_pending() && probe.load(Ordering::Acquire) && !parked_sent {
                    parked_tx.send(()).unwrap();
                    parked_sent = true;
                }
                result
            })
            .await;
            assert!(
                parked_sent,
                "cancellation must follow a silent parked transport witness"
            );
            match result {
                Err(Http2ClientError::Cancelled(actual)) => assert_eq!(actual, reason),
                other => panic!("explicit cancellation failed: {other:?}"),
            }
            assert!(Cx::current().unwrap().checkpoint().is_ok());
        });
        controller.join().unwrap();
        peer.join().unwrap();
        quiescent(&runtime);
    }
}

#[test]
fn total_deadline_closes_silent_handshake_and_denied_io_never_dials() {
    for workers in [1, 2] {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let peer = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut bytes = [0; 4096];
            let mut read = 0;
            loop {
                let count = socket.read(&mut bytes).unwrap();
                if count == 0 {
                    break;
                }
                read += count;
            }
            assert!(read >= CLIENT_PREFACE.len());
        });
        let runtime = runtime(workers);
        runtime.block_on(async move {
            let cx = Cx::current().unwrap();
            let result = Http2Client::new()
                .timeout(Duration::from_millis(100))
                .get(format!("http://{address}/silent"))
                .send(&cx)
                .await;
            assert!(matches!(result, Err(Http2ClientError::DeadlineExceeded)));
            let denied = Cx::for_testing();
            let result = Http2Client::new()
                .get("http://127.0.0.1:1/")
                .send(&denied)
                .await;
            assert!(matches!(result, Err(Http2ClientError::MissingIoCapability)));
        });
        peer.join().unwrap();
        quiescent(&runtime);
    }
}

#[cfg(feature = "tls")]
#[test]
fn https_client_uses_trusted_h2_and_rejects_wrong_alpn_or_roots() {
    use asupersync::tls::{
        Certificate, CertificateChain, PrivateKey, TlsAcceptorBuilder, TlsConnectorBuilder,
    };
    const CERT: &[u8] = include_bytes!("fixtures/tls/server.crt");
    const KEY: &[u8] = include_bytes!("fixtures/tls/server.key");
    const WRONG_ROOT: &[u8] = include_bytes!("fixtures/x509_adversarial/ca.crt");
    for workers in [1, 2] {
        let runtime = runtime(workers);
        let handle = runtime.handle();
        runtime.block_on(async move {
            let acceptor = TlsAcceptorBuilder::new(
                CertificateChain::from_pem(CERT).unwrap(),
                PrivateKey::from_pem(KEY).unwrap(),
            )
            .alpn_grpc()
            .build()
            .unwrap();
            let listener = Http2Listener::bind_with_config(
                "127.0.0.1:0",
                |request: Request| async move { Response::new(200, "OK", request.body) },
                config(),
            )
            .await
            .unwrap()
            .with_tls(acceptor);
            let address = listener.local_addr().unwrap();
            let shutdown = listener.shutdown_signal();
            let server = handle
                .clone()
                .try_spawn(async move { listener.run(&handle).await })
                .unwrap();
            let cx = Cx::current().unwrap();
            for (root, alpn, succeeds) in [
                (CERT, true, true),
                (CERT, false, false),
                (WRONG_ROOT, true, false),
            ] {
                let certificate = Certificate::from_pem(root).unwrap().remove(0);
                let connector = TlsConnectorBuilder::new().add_root_certificate(&certificate);
                let connector = if alpn {
                    connector.alpn_grpc()
                } else {
                    connector
                };
                let response = Http2Client::new()
                    .timeout(Duration::from_secs(3))
                    .tls_connector(connector.build().unwrap())
                    .post(format!("https://{address}/secure"))
                    .body(vec![7; LARGE_BODY])
                    .send(&cx)
                    .await;
                if succeeds {
                    let response = response.unwrap();
                    assert_eq!(response.status, 200);
                    assert_eq!(response.body.as_ref(), vec![7; LARGE_BODY]);
                } else {
                    assert!(matches!(response, Err(Http2ClientError::Tls(_))));
                }
            }
            assert!(shutdown.begin_drain(Duration::from_secs(2)));
            server.await.unwrap();
        });
        quiescent(&runtime);
    }
}

#[test]
fn a_server_declaring_enable_push_zero_is_served() {
    for workers in [1, 2] {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let peer = std::thread::spawn(move || {
            let mut peer = Peer::accept(listener, 65_535);
            // RFC 9113 §6.5.2: a server may include SETTINGS_ENABLE_PUSH with
            // the value 0. The peer's own state machine ignores the extra ACK.
            peer.frame(Frame::Settings(SettingsFrame::new(vec![
                Setting::EnablePush(false),
            ])));
            peer.io.flush().unwrap();
            let id = peer.request();
            peer.connection
                .send_headers(
                    id,
                    vec![
                        Header::new(":status", "200"),
                        Header::new("content-length", "2"),
                    ],
                    false,
                )
                .unwrap();
            peer.connection
                .send_data(id, Bytes::from_static(b"ok"), true)
                .unwrap();
            peer.flush();
            peer.eof();
        });
        let runtime = runtime(workers);
        runtime.block_on(async move {
            let cx = Cx::current().unwrap();
            let response = Http2Client::new()
                .timeout(Duration::from_secs(3))
                .post(format!("http://{address}/push-disabled"))
                .body(vec![1; 16])
                .send(&cx)
                .await
                .expect("a server may send SETTINGS_ENABLE_PUSH=0");
            assert_eq!(response.status, 200);
            assert_eq!(response.text().unwrap(), "ok");
        });
        peer.join().unwrap();
        quiescent(&runtime);
    }
}

/// A scripted peer without an HTTP/2 state machine, so it can declare settings
/// that its own side would then enforce against the client.
struct RawPeer {
    io: std::net::TcpStream,
    codec: FrameCodec,
    input: BytesMut,
}

impl RawPeer {
    fn accept(listener: std::net::TcpListener) -> Self {
        let (mut io, _) = listener.accept().unwrap();
        io.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        io.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut preface = [0u8; 24];
        io.read_exact(&mut preface).unwrap();
        assert_eq!(&preface, CLIENT_PREFACE);
        Self {
            io,
            codec: FrameCodec::new(),
            input: BytesMut::new(),
        }
    }

    fn frame(&mut self, frame: Frame) {
        let mut bytes = BytesMut::new();
        frame.encode(&mut bytes).unwrap();
        self.io.write_all(&bytes).unwrap();
        self.io.flush().unwrap();
    }

    /// The frames the client sends until one matches `stop` or `deadline`
    /// passes, and whether it closed the connection by then.
    fn frames_until(
        &mut self,
        deadline: Instant,
        stop: impl Fn(&Frame) -> bool,
    ) -> (Vec<Frame>, bool) {
        let mut frames = Vec::new();
        loop {
            while let Some(frame) = self.codec.decode(&mut self.input).unwrap() {
                let stopped = stop(&frame);
                frames.push(frame);
                if stopped {
                    return (frames, false);
                }
            }
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return (frames, false);
            };
            if remaining.is_zero() {
                return (frames, false);
            }
            self.io.set_read_timeout(Some(remaining)).unwrap();
            let mut bytes = [0u8; 8192];
            match self.io.read(&mut bytes) {
                Ok(0) => return (frames, true),
                Ok(read) => self.input.extend_from_slice(&bytes[..read]),
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => {}
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {
                    return (frames, true);
                }
                Err(error) => panic!("reading the client's frames failed: {error}"),
            }
        }
    }
}

#[test]
fn a_server_declaring_max_concurrent_streams_zero_is_waited_for_until_it_admits_a_stream() {
    for workers in [1, 2] {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let peer = std::thread::spawn(move || {
            let mut peer = RawPeer::accept(listener);
            // RFC 9113 §6.5.2: zero is a legal SETTINGS_MAX_CONCURRENT_STREAMS
            // that a peer is expected to raise again shortly.
            peer.frame(Frame::Settings(SettingsFrame::new(vec![
                Setting::MaxConcurrentStreams(0),
            ])));
            let (held, closed) =
                peer.frames_until(Instant::now() + Duration::from_millis(300), |_| false);
            assert!(
                !closed,
                "the client gave up on a legal zero stream limit: {held:?}"
            );
            assert!(
                held.iter()
                    .any(|frame| matches!(frame, Frame::Settings(settings) if settings.ack)),
                "the client never acknowledged the zero stream limit: {held:?}"
            );
            assert!(
                !held.iter().any(|frame| matches!(frame, Frame::Headers(_))),
                "the client opened a stream while the limit was zero: {held:?}"
            );
            peer.frame(Frame::Settings(SettingsFrame::ack()));
            peer.frame(Frame::Settings(SettingsFrame::new(vec![
                Setting::MaxConcurrentStreams(1),
            ])));
            let (frames, closed) = peer
                .frames_until(Instant::now() + Duration::from_secs(5), |frame| {
                    matches!(frame, Frame::Headers(_))
                });
            let id = frames
                .iter()
                .find_map(|frame| match frame {
                    Frame::Headers(headers) => Some(headers.stream_id),
                    _ => None,
                })
                .unwrap_or_else(|| {
                    panic!("no request once the limit was raised (closed: {closed}): {frames:?}")
                });
            // HPACK static table entry 8 is ":status: 200".
            peer.frame(Frame::Headers(HeadersFrame::new(
                id,
                Bytes::from_static(&[0x88]),
                true,
                true,
            )));
            let (_, closed) = peer.frames_until(Instant::now() + Duration::from_secs(5), |_| false);
            assert!(closed, "the client kept its connection after the response");
        });
        let runtime = runtime(workers);
        runtime.block_on(async move {
            let cx = Cx::current().unwrap();
            let response = Http2Client::new()
                .timeout(Duration::from_secs(10))
                .get(format!("http://{address}/zero-streams"))
                .send(&cx)
                .await
                .expect("the client waits until the server admits a stream");
            assert_eq!(response.status, 200);
        });
        peer.join().unwrap();
        quiescent(&runtime);
    }
}

#[test]
fn client_receive_windows_track_the_response_body_limit() {
    const LIMIT: usize = 4 * 1024 * 1024;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let peer = std::thread::spawn(move || {
        let mut peer = Peer::accept(listener, 65_535);
        let id = peer.request();
        // The client's SETTINGS and connection WINDOW_UPDATE precede HEADERS,
        // so the peer's view of its send credit is final here.
        let credit = (
            peer.connection.remote_settings().initial_window_size,
            peer.connection.send_window(),
            peer.connection
                .stream(id)
                .map(|stream| stream.send_window()),
        );
        peer.connection
            .send_headers(id, vec![Header::new(":status", "204")], true)
            .unwrap();
        peer.flush();
        peer.eof();
        credit
    });
    let runtime = runtime(1);
    runtime.block_on(async move {
        let cx = Cx::current().unwrap();
        let response = Http2Client::new()
            .timeout(Duration::from_secs(3))
            .max_response_body(LIMIT)
            .post(format!("http://{address}/windows"))
            .body(vec![1; 16])
            .send(&cx)
            .await
            .unwrap();
        assert_eq!(response.status, 204);
    });
    let (initial, connection, stream) = peer.join().unwrap();
    let limit = u32::try_from(LIMIT).unwrap();
    let credit = i32::try_from(LIMIT).unwrap();
    assert_eq!(
        initial, limit,
        "SETTINGS_INITIAL_WINDOW_SIZE must track max_response_body"
    );
    assert_eq!(
        connection, credit,
        "connection window must track max_response_body"
    );
    assert_eq!(
        stream,
        Some(credit),
        "stream window must track max_response_body"
    );
    quiescent(&runtime);
}

/// What the accept-counting peer does after answering a connection's first
/// request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AfterFirst {
    Serve,
    GoAway,
    Refuse,
    /// Lower SETTINGS_MAX_CONCURRENT_STREAMS to 0 right after the answer.
    ZeroStreams,
}

/// A raw HTTP/2 server that echoes each request body with status 200 and
/// counts the TCP connections it accepts. Each answer is signalled after it
/// (and any GOAWAY following it) has been written.
fn counting_peer(
    after: AfterFirst,
) -> (std::net::SocketAddr, Arc<AtomicUsize>, mpsc::Receiver<()>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let (answered, answers) = mpsc::channel();
    let count = Arc::clone(&accepted);
    std::thread::spawn(move || {
        for io in listener.incoming() {
            let Ok(mut io) = io else { break };
            count.fetch_add(1, Ordering::SeqCst);
            let answered = answered.clone();
            std::thread::spawn(move || {
                io.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
                let mut preface = [0u8; 24];
                if io.read_exact(&mut preface).is_err() {
                    return;
                }
                let mut connection = Connection::server(Settings::server());
                connection.queue_initial_settings();
                let mut codec = FrameCodec::new();
                let mut input = BytesMut::new();
                let mut bodies = std::collections::HashMap::<u32, Vec<u8>>::new();
                let mut served = 0;
                loop {
                    while let Some(frame) = codec.decode(&mut input).unwrap() {
                        let (id, end) = match connection.process_frame(frame).unwrap() {
                            Some(ReceivedFrame::Headers {
                                stream_id,
                                end_stream,
                                ..
                            }) => {
                                bodies.entry(stream_id).or_default();
                                (stream_id, end_stream)
                            }
                            Some(ReceivedFrame::Data {
                                stream_id,
                                data,
                                end_stream,
                            }) => {
                                bodies
                                    .entry(stream_id)
                                    .or_default()
                                    .extend_from_slice(&data);
                                (stream_id, end_stream)
                            }
                            _ => continue,
                        };
                        if !end {
                            continue;
                        }
                        if after == AfterFirst::Refuse && served > 0 {
                            connection.reset_stream(id, ErrorCode::RefusedStream);
                        } else {
                            let body = bodies.remove(&id).unwrap_or_default();
                            connection
                                .send_headers(
                                    id,
                                    vec![
                                        Header::new(":status", "200"),
                                        Header::new("content-length", body.len().to_string()),
                                    ],
                                    body.is_empty(),
                                )
                                .unwrap();
                            if !body.is_empty() {
                                connection.send_data(id, Bytes::from(body), true).unwrap();
                            }
                            served += 1;
                            if after == AfterFirst::GoAway {
                                connection.goaway(ErrorCode::NoError, Bytes::new());
                            }
                        }
                        let mut bytes = BytesMut::new();
                        while let Some(frame) = connection.next_frame() {
                            frame.encode(&mut bytes).unwrap();
                        }
                        if after == AfterFirst::ZeroStreams {
                            // RFC 9113 §6.5.2: a legal limit that admits no
                            // stream until the server raises it again.
                            let zero = vec![Setting::MaxConcurrentStreams(0)];
                            Frame::Settings(SettingsFrame::new(zero))
                                .encode(&mut bytes)
                                .unwrap();
                        }
                        let _ = io.write_all(&bytes);
                        if after == AfterFirst::GoAway && served > 0 {
                            let _ = io.shutdown(std::net::Shutdown::Both);
                            answered.send(()).unwrap();
                            return;
                        }
                        answered.send(()).unwrap();
                    }
                    let mut bytes = BytesMut::new();
                    while let Some(frame) = connection.next_frame() {
                        frame.encode(&mut bytes).unwrap();
                    }
                    if !bytes.is_empty() && io.write_all(&bytes).is_err() {
                        return;
                    }
                    let mut chunk = [0u8; 8192];
                    match io.read(&mut chunk) {
                        Ok(0) | Err(_) => return,
                        Ok(read) => input.extend_from_slice(&chunk[..read]),
                    }
                }
            });
        }
    });
    (address, accepted, answers)
}

/// Send `requests` sequential POSTs; return the connections the peer accepted.
fn pooled_requests(after: AfterFirst, reuse: usize, requests: usize) -> usize {
    let (address, accepted, answers) = counting_peer(after);
    let runtime = runtime(1);
    runtime.block_on(async move {
        let cx = Cx::current().unwrap();
        let client = Http2Client::new()
            .timeout(Duration::from_secs(10))
            .reuse_connections(reuse);
        for request in 0..requests {
            let body = format!("request {request}").into_bytes();
            let response = client
                .post(format!("http://{address}/echo"))
                .body(body.clone())
                .send(&cx)
                .await
                .unwrap_or_else(|error| panic!("{after:?} reuse={reuse} #{request}: {error}"));
            assert_eq!(response.status, 200);
            assert_eq!(response.body.as_ref(), body);
            // Loopback delivers the answer's trailing GOAWAY or close before
            // the next request looks at the idle connection.
            while answers.recv_timeout(Duration::from_millis(200)).is_ok() {}
        }
    });
    accepted.load(Ordering::SeqCst)
}

#[test]
fn requests_dial_per_request_by_default_and_share_a_pooled_connection_when_enabled() {
    assert_eq!(pooled_requests(AfterFirst::Serve, 0, 3), 3);
    assert_eq!(pooled_requests(AfterFirst::Serve, 2, 3), 1);
}

#[test]
fn a_pooled_connection_the_server_ended_or_refused_is_replaced() {
    // GOAWAY and close while idle: dropped before use, the next request dials.
    assert_eq!(pooled_requests(AfterFirst::GoAway, 2, 2), 2);
    // REFUSED_STREAM on the reused connection: the server did not process
    // the request, which is retried once on a fresh connection.
    assert_eq!(pooled_requests(AfterFirst::Refuse, 2, 2), 2);
}

/// asupersync-mu5yhv (d0's LOW 2): a pooled connection whose server has
/// lowered SETTINGS_MAX_CONCURRENT_STREAMS to 0 admits no request now. It was
/// taken from the pool anyway, and the next request waited out its whole
/// timeout (10 s here) for a stream; it now dials a fresh connection.
#[test]
fn a_pooled_connection_whose_server_admits_no_stream_is_not_reused() {
    let started = Instant::now();
    assert_eq!(pooled_requests(AfterFirst::ZeroStreams, 2, 2), 2);
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the second request waited on the zero-stream connection: {:?}",
        started.elapsed()
    );
}
