//! Native peers require custom upgrade metadata and witness socket retirement.

use super::*;
use crate::channel::oneshot;
use crate::runtime::{Runtime, RuntimeBuilder};
use crate::types::{Budget, CancelKind};
use std::future::{Future, poll_fn};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream as StdTcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Wake, Waker};
use std::time::{Duration, Instant};

const WATCHDOG: Duration = Duration::from_secs(10);
const SECRET: &str = "Bearer private-upgrade-credential";
const COOKIE: &str = "session=private-upgrade-cookie";
const TRACE: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

fn runtime(workers: usize) -> Runtime {
    if workers == 1 {
        RuntimeBuilder::current_thread()
    } else {
        RuntimeBuilder::new().worker_threads(workers)
    }
    .build()
    .unwrap()
}

async fn within<T>(cx: &Cx, future: impl Future<Output = T>) -> T {
    crate::time::timeout(cx.now(), WATCHDOG, future)
        .await
        .expect("WebSocket options watchdog")
}

fn require_send<F: Future + Send>(future: F) -> F {
    future
}

fn listener() -> TcpListener {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    listener
}

fn accept(listener: &TcpListener) -> StdTcpStream {
    let until = Instant::now() + WATCHDOG;
    loop {
        match listener.accept() {
            Ok((socket, _)) => {
                socket.set_nonblocking(false).unwrap();
                socket.set_read_timeout(Some(WATCHDOG)).unwrap();
                socket.set_write_timeout(Some(WATCHDOG)).unwrap();
                return socket;
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                assert!(Instant::now() < until, "native upgrade accept watchdog");
                std::thread::park_timeout(Duration::from_millis(1));
            }
            Err(error) => panic!("native upgrade accept: {error}"),
        }
    }
}

#[derive(Debug)]
struct RequestHead {
    target: String,
    headers: Vec<(String, String)>,
}

impl RequestHead {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find_map(|(key, value)| key.eq_ignore_ascii_case(name).then_some(value.as_str()))
    }

    fn assert_authenticated(&self) {
        for (name, value) in [
            ("authorization", SECRET),
            ("cookie", COOKIE),
            ("origin", "https://app.example"),
            ("traceparent", TRACE),
        ] {
            assert_eq!(self.header(name), Some(value));
            assert_eq!(
                self.headers.iter().filter(|(key, _)| key == name).count(),
                1,
                "exactly one custom field"
            );
        }
        assert_eq!(self.header("upgrade"), Some("websocket"));
        assert_eq!(self.header("connection"), Some("Upgrade"));
        assert_eq!(self.header("sec-websocket-version"), Some("13"));
    }
}

// Parse the actual request independently of the production handshake parser.
fn read_head(io: &mut impl Read) -> RequestHead {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        io.read_exact(&mut byte).expect("native upgrade request");
        bytes.push(byte[0]);
        assert!(bytes.len() <= 16 * 1024, "bounded request fixture");
    }
    let text = String::from_utf8(bytes).unwrap();
    let mut lines = text.split("\r\n");
    let request = lines.next().unwrap().split(' ').collect::<Vec<_>>();
    assert_eq!(request.len(), 3);
    assert_eq!(request[0], "GET");
    assert_eq!(request[2], "HTTP/1.1");
    let headers = lines
        .take_while(|line| !line.is_empty())
        .map(|line| {
            let (name, value) = line.split_once(':').unwrap();
            (name.to_ascii_lowercase(), value.trim().to_owned())
        })
        .collect();
    RequestHead {
        target: request[1].to_owned(),
        headers,
    }
}

fn upgrade(head: &RequestHead, extra: &str) -> Vec<u8> {
    let accept = crate::net::websocket::compute_accept_key(
        head.header("sec-websocket-key")
            .expect("generated client key"),
    );
    format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n{extra}\r\n"
    )
    .into_bytes()
}

fn append_text(bytes: &mut Vec<u8>, text: &[u8]) {
    assert!(text.len() <= 125);
    bytes.extend_from_slice(&[0x81, u8::try_from(text.len()).unwrap()]);
    bytes.extend_from_slice(text);
}

fn read_client_text(io: &mut impl Read) -> Vec<u8> {
    let mut header = [0; 2];
    io.read_exact(&mut header).unwrap();
    assert_eq!(header[0], 0x81);
    assert_ne!(header[1] & 0x80, 0, "client frames remain masked");
    let length = usize::from(header[1] & 0x7f);
    assert!(length <= 125);
    let mut mask = [0; 4];
    io.read_exact(&mut mask).unwrap();
    let mut payload = vec![0; length];
    io.read_exact(&mut payload).unwrap();
    for (index, byte) in payload.iter_mut().enumerate() {
        *byte ^= mask[index % 4];
    }
    payload
}

fn retired(socket: &mut StdTcpStream) {
    let mut allowance = 32 * 1024_usize;
    let mut bytes = [0; 1024];
    loop {
        match socket.read(&mut bytes) {
            Ok(0) => return,
            Ok(count) => {
                allowance = allowance
                    .checked_sub(count)
                    .expect("bounded residual output");
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
                ) =>
            {
                return;
            }
            Err(error) => panic!("native upgrade socket did not retire: {error}"),
        }
    }
}

fn options(config: WebSocketConfig) -> WebSocketConnectOptions {
    WebSocketConnectOptions::new(config)
        .try_header("Authorization", SECRET)
        .unwrap()
        .try_header("Cookie", COOKIE)
        .unwrap()
        .try_header("Origin", "https://app.example")
        .unwrap()
        .try_header("traceparent", TRACE)
        .unwrap()
}

#[test]
fn custom_upgrade_options_enforce_count_byte_and_name_boundaries() {
    type Options = WebSocketConnectOptions;
    let first = "a".repeat(Options::MAX_HEADER_VALUE_BYTES);
    let second_len = Options::MAX_HEADER_BYTES - (3 + first.len() + 4) - (3 + 4);
    let exact = Options::default()
        .try_header("One", &first)
        .unwrap()
        .try_header("Two", "b".repeat(second_len))
        .unwrap();
    assert_eq!(
        exact.clone().try_header("three", "").unwrap_err(),
        WebSocketConnectOptionsError::HeaderBytesExceeded
    );
    let (_, headers, compression) = exact.into_parts();
    assert_eq!(headers[0].0, "one");
    assert_eq!(headers[1].0, "two");
    assert!(!compression);
    assert_eq!(
        headers
            .iter()
            .map(|(key, value)| key.len() + value.len() + 4)
            .sum::<usize>(),
        Options::MAX_HEADER_BYTES
    );

    let mut count = Options::default();
    for index in 0..Options::MAX_HEADERS {
        count = count.try_header(format!("x-{index}"), "").unwrap();
    }
    assert_eq!(
        count.try_header("extra", "").unwrap_err(),
        WebSocketConnectOptionsError::TooManyHeaders
    );
    assert!(
        Options::default()
            .try_header("x".repeat(Options::MAX_HEADER_NAME_BYTES), "\t")
            .is_ok()
    );
    assert_eq!(
        Options::default()
            .try_header("x".repeat(Options::MAX_HEADER_NAME_BYTES + 1), "")
            .unwrap_err(),
        WebSocketConnectOptionsError::InvalidHeaderName
    );
    assert_eq!(
        Options::default()
            .try_header("x", "a".repeat(Options::MAX_HEADER_VALUE_BYTES + 1))
            .unwrap_err(),
        WebSocketConnectOptionsError::HeaderBytesExceeded
    );
}

#[test]
fn invalid_custom_upgrade_headers_fail_before_any_native_dial_and_redact_values() {
    use WebSocketConnectOptionsError as Error;
    let runtime = runtime(1);
    let listener = listener();
    let url = format!("ws://{}/validate", listener.local_addr().unwrap());
    let mut refused = vec![
        ("", SECRET, Error::InvalidHeaderName),
        ("bad name", SECRET, Error::InvalidHeaderName),
        ("bad:name", SECRET, Error::InvalidHeaderName),
        ("bad\r\nname", SECRET, Error::InvalidHeaderName),
        ("métadata", SECRET, Error::InvalidHeaderName),
        (
            "x-metadata",
            "secret\r\nInjected: credential",
            Error::InvalidHeaderValue,
        ),
        (
            "x-metadata",
            "secret\0credential",
            Error::InvalidHeaderValue,
        ),
        (
            "x-metadata",
            "secret\u{7f}credential",
            Error::InvalidHeaderValue,
        ),
        ("x-metadata", "secretécredential", Error::InvalidHeaderValue),
        ("AUTHORIZATION", SECRET, Error::DuplicateHeader),
    ];
    for name in [
        "Host",
        "cOnNeCtIoN",
        "Upgrade",
        "Sec-WebSocket-Key",
        "sec-websocket-accept",
        "SEC-WEBSOCKET-Protocol",
        "sec-websocket-extensions",
        "sec-websocket-future",
        "Content-Length",
        "Transfer-Encoding",
        "TE",
        "Trailer",
        "Expect",
        "Keep-Alive",
        "Proxy-Connection",
        "Proxy-Authorization",
    ] {
        refused.push((name, SECRET, Error::ReservedHeader));
    }
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        for (name, value, expected) in refused {
            let result: Result<(), Box<dyn std::error::Error>> = async {
                let options = WebSocketConnectOptions::default()
                    .try_header("authorization", SECRET)?
                    .try_header(name, value)?;
                let socket = WebSocket::connect_with_options(&cx, &url, options).await?;
                drop(socket);
                Ok(())
            }
            .await;
            let error = result.unwrap_err();
            assert_eq!(error.downcast_ref::<Error>(), Some(&expected));
            assert!(!format!("{error:?} {error}").contains(SECRET));
            assert!(
                matches!(listener.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock)
            );
        }
    });
    let options = options(WebSocketConfig::default().protocol("private-protocol"));
    let debug = format!("{options:?}");
    for private in [SECRET, COOKIE, TRACE, "authorization", "private-protocol"] {
        assert!(!debug.contains(private));
    }
    assert!(runtime.shutdown_timeout(WATCHDOG));
}

#[test]
fn native_authenticated_upgrade_preserves_protocol_masking_and_coalesced_first_frame() {
    for workers in [1, 2] {
        let runtime = runtime(workers);
        let listener = listener();
        let address = listener.local_addr().unwrap();
        let peer = std::thread::spawn(move || {
            // The same endpoint first refuses the unchanged headerless API.
            let mut denied = accept(&listener);
            assert!(read_head(&mut denied).header("authorization").is_none());
            denied
                .write_all(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n")
                .unwrap();
            drop(denied);

            let mut socket = accept(&listener);
            let head = read_head(&mut socket);
            assert_eq!(head.target, "/events?room=1");
            head.assert_authenticated();
            assert_eq!(head.header("host"), Some(address.to_string().as_str()));
            assert_eq!(head.header("sec-websocket-protocol"), Some("chat"));
            let mut response = upgrade(&head, "Sec-WebSocket-Protocol: chat\r\n");
            append_text(&mut response, b"welcome");
            socket.write_all(&response).unwrap();
            assert_eq!(read_client_text(&mut socket), b"ready");
            retired(&mut socket);
        });
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let url = format!("ws://{address}/events?room=1");
            let config = WebSocketConfig::default().ping_interval(None).connect_timeout(Some(WATCHDOG)).protocol("chat");
            let error = within(&cx, WebSocket::connect_with_config(&cx, &url, config.clone()))
                .await.err().expect("the peer requires authentication");
            assert!(matches!(error, WsConnectError::Handshake(HandshakeError::NotSwitchingProtocols(401))));
            let mut socket = within(&cx, require_send(WebSocket::connect_with_options(&cx, &url, options(config))))
                .await.unwrap();
            assert_eq!(socket.protocol(), Some("chat"));
            assert!(matches!(within(&cx, socket.recv(&cx)).await.unwrap(), Some(Message::Text(text)) if text == "welcome"));
            within(&cx, socket.send(&cx, Message::text("ready"))).await.unwrap();
            drop(socket);
        });
        peer.join().expect("native authenticated peer");
        assert!(runtime.shutdown_timeout(WATCHDOG));
    }
}

struct ForwardWake {
    count: Arc<AtomicUsize>,
    parent: Waker,
}

impl Wake for ForwardWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.count.fetch_add(1, Ordering::SeqCst);
        self.parent.wake_by_ref();
    }
}

#[test]
fn cancelling_or_dropping_a_parked_authenticated_upgrade_retires_its_socket() {
    for workers in [1, 2] {
        for cancel in [false, true] {
            let runtime = runtime(workers);
            let owner = runtime.request_cx_with_budget(Budget::INFINITE);
            let listener = listener();
            let address = listener.local_addr().unwrap();
            let (seen, mut observed) = oneshot::channel();
            let (closed, mut retired_receipt) = oneshot::channel();
            let peer = std::thread::spawn(move || {
                let mut socket = accept(&listener);
                let head = read_head(&mut socket);
                head.assert_authenticated();
                seen.send_blocking(()).unwrap();
                // No response and no artificial wake: the actual read parks.
                retired(&mut socket);
                closed.send_blocking(()).unwrap();
            });
            runtime.block_on(async {
                let controller = Cx::current().unwrap();
                assert_ne!(owner.task_id(), controller.task_id());
                let url = format!("ws://{address}/parked");
                let mut call = Box::pin(WebSocket::connect_with_options(
                    &owner,
                    &url,
                    options(WebSocketConfig::default().connect_timeout(Some(WATCHDOG))),
                ));
                let count = Arc::new(AtomicUsize::new(0));
                let mut witness = std::pin::pin!(observed.recv(&controller));
                within(
                    &controller,
                    poll_fn(|task| {
                        let waker = Waker::from(Arc::new(ForwardWake {
                            count: Arc::clone(&count),
                            parent: task.waker().clone(),
                        }));
                        let mut tracked = Context::from_waker(&waker);
                        assert!(
                            call.as_mut().poll(&mut tracked).is_pending(),
                            "peer withheld its upgrade response"
                        );
                        witness.as_mut().poll(task)
                    }),
                )
                .await
                .unwrap();
                if cancel {
                    let before = count.load(Ordering::SeqCst);
                    owner.cancel_with(CancelKind::User, Some("authenticated upgrade cancelled"));
                    assert!(
                        count.load(Ordering::SeqCst) > before,
                        "explicit cancellation woke the parked call"
                    );
                    let error = within(&controller, call.as_mut())
                        .await
                        .err()
                        .expect("cancelled upgrade");
                    assert!(matches!(error, WsConnectError::Cancelled));
                }
                drop(call);
                within(&controller, retired_receipt.recv(&controller))
                    .await
                    .unwrap();
                assert!(!controller.is_cancel_requested());
            });
            peer.join().expect("parked upgrade peer observed EOF");
            assert!(runtime.shutdown_timeout(WATCHDOG));
        }
    }
}

#[test]
fn authenticated_upgrade_keeps_the_configured_response_timeout() {
    let runtime = runtime(1);
    let listener = listener();
    let address = listener.local_addr().unwrap();
    let peer = std::thread::spawn(move || {
        let mut socket = accept(&listener);
        read_head(&mut socket).assert_authenticated();
        retired(&mut socket);
    });
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        let options =
            options(WebSocketConfig::default().connect_timeout(Some(Duration::from_millis(200))));
        let error = within(
            &cx,
            WebSocket::connect_with_options(&cx, &format!("ws://{address}/timeout"), options),
        )
        .await
        .err()
        .expect("withheld upgrade response must time out");
        assert!(
            matches!(error, WsConnectError::Io(error) if error.kind() == io::ErrorKind::TimedOut)
        );
    });
    peer.join().expect("timeout retired the native socket");
    assert!(runtime.shutdown_timeout(WATCHDOG));
}

#[test]
fn peer_echoed_credentials_are_redacted_from_native_upgrade_errors() {
    for field in ["Sec-WebSocket-Accept", "Upgrade", "Sec-WebSocket-Protocol"] {
        let runtime = runtime(1);
        let listener = listener();
        let address = listener.local_addr().unwrap();
        let peer = std::thread::spawn(move || {
            let mut socket = accept(&listener);
            let head = read_head(&mut socket);
            head.assert_authenticated();
            let accept = crate::net::websocket::compute_accept_key(
                head.header("sec-websocket-key").unwrap(),
            );
            let response = format!(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: {}\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n{}\r\n",
                if field == "Upgrade" {
                    SECRET
                } else {
                    "websocket"
                },
                if field == "Sec-WebSocket-Accept" {
                    SECRET
                } else {
                    &accept
                },
                if field == "Sec-WebSocket-Protocol" {
                    format!("{field}: {SECRET}\r\n")
                } else {
                    String::new()
                },
            );
            socket.write_all(response.as_bytes()).unwrap();
            retired(&mut socket);
        });
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let error = within(
                &cx,
                WebSocket::connect_with_options(
                    &cx,
                    &format!("ws://{address}/redacted"),
                    options(WebSocketConfig::default()),
                ),
            )
            .await
            .err()
            .expect("invalid server negotiation");
            assert!(matches!(error, WsConnectError::Handshake(_)));
            let mut current: Option<&dyn std::error::Error> = Some(&error);
            while let Some(error) = current {
                assert!(!format!("{error:?} {error}").contains(SECRET));
                current = error.source();
            }
        });
        peer.join().unwrap();
        assert!(runtime.shutdown_timeout(WATCHDOG));
    }
}

#[cfg(feature = "compression")]
#[test]
fn authenticated_options_offer_existing_compression_and_allow_peer_decline() {
    for accepted in [false, true] {
        let runtime = runtime(1);
        let listener = listener();
        let address = listener.local_addr().unwrap();
        let peer = std::thread::spawn(move || {
            let mut socket = accept(&listener);
            let head = read_head(&mut socket);
            head.assert_authenticated();
            let offer = head.header("sec-websocket-extensions").unwrap();
            assert!(offer.starts_with("permessage-deflate;"));
            assert!(offer.contains("server_no_context_takeover"));
            assert!(offer.contains("client_no_context_takeover"));
            let extension = if accepted {
                "Sec-WebSocket-Extensions: permessage-deflate; server_no_context_takeover; client_no_context_takeover\r\n"
            } else {
                ""
            };
            let mut response = upgrade(&head, extension);
            append_text(&mut response, b"compression-ready");
            socket.write_all(&response).unwrap();
            retired(&mut socket);
        });
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let mut socket = within(&cx, WebSocket::connect_with_options(
                &cx, &format!("ws://{address}/compression"), options(WebSocketConfig::default()).with_compression(),
            )).await.unwrap();
            assert_eq!(socket.compression_enabled(), accepted);
            assert!(matches!(within(&cx, socket.recv(&cx)).await.unwrap(), Some(Message::Text(text)) if text == "compression-ready"));
            drop(socket);
        });
        peer.join().unwrap();
        assert!(runtime.shutdown_timeout(WATCHDOG));
    }
}

#[cfg(feature = "tls")]
#[test]
fn authenticated_tls_upgrade_preserves_explicit_trust_identity_and_first_frame() {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
    const CERT: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/tls/server.crt"
    ));
    const KEY: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/tls/server.key"
    ));
    for workers in [1, 2] {
        let runtime = runtime(workers);
        let listener = listener();
        let address = listener.local_addr().unwrap();
        let peer = std::thread::spawn(move || {
            let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from_pem_slice(CERT).unwrap()],
                PrivateKeyDer::from_pem_slice(KEY).unwrap(),
            )
            .unwrap();
            config.alpn_protocols = vec![b"http/1.1".to_vec()];
            let connection = rustls::ServerConnection::new(Arc::new(config)).unwrap();
            let mut socket = rustls::StreamOwned::new(connection, accept(&listener));
            let head = read_head(&mut socket);
            head.assert_authenticated();
            assert_eq!(head.target, "/secure");
            assert_eq!(socket.conn.server_name(), Some("localhost"));
            assert_eq!(socket.conn.alpn_protocol(), Some(b"http/1.1".as_slice()));
            let mut response = upgrade(&head, "");
            append_text(&mut response, b"secure-welcome");
            socket.write_all(&response).unwrap();
            socket.flush().unwrap();
            assert_eq!(read_client_text(&mut socket), b"secure-ready");
            retired(&mut socket.sock);
        });
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let mut roots = rustls::RootCertStore::empty();
            roots.add(CertificateDer::from_pem_slice(CERT).unwrap()).unwrap();
            let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions().unwrap().with_root_certificates(roots).with_no_client_auth();
            config.alpn_protocols = vec![b"http/1.1".to_vec()];
            let connector = TlsConnector::new(config);
            let url = format!("wss://localhost:{}/secure", address.port());
            let options = options(WebSocketConfig::default().ping_interval(None).connect_timeout(Some(WATCHDOG)));
            let mut socket = within(&cx, require_send(WebSocket::connect_tls_with_options(&cx, &url, options, &connector)))
                .await.unwrap();
            assert!(matches!(within(&cx, socket.recv(&cx)).await.unwrap(), Some(Message::Text(text)) if text == "secure-welcome"));
            within(&cx, socket.send(&cx, Message::text("secure-ready"))).await.unwrap();
            drop(socket);
        });
        peer.join()
            .expect("TLS peer observed authenticated metadata");
        assert!(runtime.shutdown_timeout(WATCHDOG));
    }
}
