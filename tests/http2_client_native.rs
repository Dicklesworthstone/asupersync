//! General HTTP/2 client against the production listener and scripted TCP peers.
#![cfg(all(not(target_arch = "wasm32"), feature = "test-internals"))]
#![recursion_limit = "256"]

use std::future::{Future, poll_fn};
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

use asupersync::bytes::{Bytes, BytesMut};
use asupersync::codec::Decoder;
use asupersync::cx::Cx;
use asupersync::http::h1::server::HostPolicy;
use asupersync::http::h2::connection::{CLIENT_PREFACE, ReceivedFrame};
use asupersync::http::h2::frame::GoAwayFrame;
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
