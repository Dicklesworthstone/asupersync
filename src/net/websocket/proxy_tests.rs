//! Native CONNECT peers exercise routing, credential boundaries, and ownership.

use super::WebSocketHttpProxy;
use crate::Cx;
use crate::http::h1::HttpClient;
use crate::net::websocket::{
    HandshakeError, Message, WebSocket, WebSocketConfig, WebSocketConnectOptions, WsConnectError,
};
use crate::runtime::RuntimeBuilder;
use crate::time::{TimerDriverHandle, VirtualClock};
use crate::types::{Budget, CancelKind, Time};
use std::future::{Future, poll_fn};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::task::{Context, Poll, Wake, Waker};
use std::time::{Duration, Instant};

const WATCHDOG: Duration = Duration::from_secs(10);
const PROXY_AUTH: &str = "Basic cHJveHk6cHJpdmF0ZS1zZWNyZXQ=";
const ORIGIN_AUTH: &str = "Bearer private-origin-credential";
const COOKIE: &str = "session=private-origin-cookie";
const DEFAULT_SECRET: &str = "http-client-default-secret";

#[derive(Default)]
struct WallSignal {
    expired: AtomicBool,
    waiter: Mutex<Option<Waker>>,
}

struct WallWatchdog {
    signal: Arc<WallSignal>,
    stop: mpsc::Sender<()>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl WallWatchdog {
    fn new() -> Self {
        let signal = Arc::new(WallSignal::default());
        let expired = Arc::clone(&signal);
        let (stop, stopping) = mpsc::channel();
        let thread = std::thread::spawn(move || {
            if matches!(
                stopping.recv_timeout(WATCHDOG),
                Err(mpsc::RecvTimeoutError::Timeout)
            ) {
                expired.expired.store(true, Ordering::Release);
                let waiter = expired.waiter.lock().unwrap().take();
                if let Some(waiter) = waiter {
                    waiter.wake();
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

fn run_native<F, Fut>(workers: usize, timer: Option<TimerDriverHandle>, test: F)
where
    F: FnOnce(Cx) -> Fut,
    Fut: Future<Output = ()>,
{
    let mut builder = if workers == 1 {
        RuntimeBuilder::current_thread()
    } else {
        RuntimeBuilder::new().worker_threads(workers)
    };
    if let Some(timer) = timer {
        builder = builder.with_timer_driver(timer);
    }
    let runtime = builder.build().unwrap();
    let owner = runtime.request_cx_with_budget(Budget::INFINITE);
    let driver = runtime.request_cx_with_budget(Budget::INFINITE);
    let watchdog = WallWatchdog::new();
    runtime.block_on_with_cx(
        driver,
        Box::pin(async {
            let mut future = Box::pin(test(owner));
            poll_fn(|task| {
                *watchdog.signal.waiter.lock().unwrap() = Some(task.waker().clone());
                assert!(
                    !watchdog.signal.expired.load(Ordering::Acquire),
                    "WebSocket proxy watchdog"
                );
                future.as_mut().poll(task)
            })
            .await;
        }),
    );
    drop(watchdog);
    assert!(runtime.shutdown_timeout(WATCHDOG));
}

fn require_send<F: Future + Send>(future: F) -> F {
    future
}

fn bind_listener() -> (TcpListener, SocketAddr) {
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
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                assert!(Instant::now() < until, "proxy was never contacted");
                std::thread::park_timeout(Duration::from_millis(1));
            }
            Err(error) => panic!("proxy accept: {error}"),
        }
    }
}

fn no_connection(listener: &TcpListener) {
    match listener.accept() {
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
        _ => panic!("unexpected connection bypassed the explicit proxy route"),
    }
}

struct Head {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
}

impl Head {
    fn values(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter_map(|(key, value)| key.eq_ignore_ascii_case(name).then_some(value.as_str()))
            .collect()
    }

    fn one(&self, name: &str) -> &str {
        let values = self.values(name);
        assert_eq!(values.len(), 1, "expected one {name}");
        values[0]
    }

    fn assert_connect(&self, authority: &str) {
        assert_eq!(self.method, "CONNECT");
        assert_eq!(self.target, authority);
        assert_eq!(self.one("host"), authority);
        assert_eq!(self.one("proxy-authorization"), PROXY_AUTH);
        for name in [
            "authorization",
            "cookie",
            "origin",
            "sec-websocket-key",
            "x-default",
        ] {
            assert!(
                self.values(name).is_empty(),
                "origin metadata leaked into CONNECT"
            );
        }
        assert!(
            !self
                .headers
                .iter()
                .any(|(_, value)| value.contains(DEFAULT_SECRET))
        );
    }

    fn assert_upgrade(&self, host: &str, path: &str) {
        assert_eq!(self.method, "GET");
        assert_eq!(self.target, path);
        assert_eq!(self.one("host"), host);
        assert_eq!(self.one("authorization"), ORIGIN_AUTH);
        assert_eq!(self.one("cookie"), COOKIE);
        assert_eq!(self.one("origin"), "https://application.example");
        assert_eq!(self.one("upgrade"), "websocket");
        assert!(self.one("connection").eq_ignore_ascii_case("upgrade"));
        assert_eq!(self.one("sec-websocket-version"), "13");
        assert_eq!(self.one("sec-websocket-protocol"), "chat");
        assert!(self.values("proxy-authorization").is_empty());
        assert!(self.values("x-default").is_empty());
        assert!(
            !self
                .headers
                .iter()
                .any(|(_, value)| value.contains(PROXY_AUTH))
        );
    }
}

// The peer parses actual bytes independently of the production HTTP parser.
fn read_head(io: &mut impl Read) -> Head {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        assert!(bytes.len() < 32 * 1024, "bounded CONNECT/upgrade fixture");
        let mut byte = [0];
        io.read_exact(&mut byte)
            .expect("CONNECT or upgrade request");
        bytes.push(byte[0]);
    }
    let text = String::from_utf8(bytes).unwrap();
    let mut lines = text.split("\r\n");
    let request = lines.next().unwrap().split(' ').collect::<Vec<_>>();
    assert_eq!(request.len(), 3);
    assert_eq!(request[2], "HTTP/1.1");
    let headers = lines
        .take_while(|line| !line.is_empty())
        .map(|line| {
            let (name, value) = line.split_once(':').unwrap();
            (name.to_ascii_lowercase(), value.trim().to_owned())
        })
        .collect();
    Head {
        method: request[0].to_owned(),
        target: request[1].to_owned(),
        headers,
    }
}

fn tunnel(io: &mut impl Write) {
    io.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .unwrap();
    io.flush().unwrap();
}

fn upgrade_and_first_message(io: &mut impl Write, head: &Head) {
    let accept = crate::net::websocket::compute_accept_key(head.one("sec-websocket-key"));
    let mut response = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\nSec-WebSocket-Protocol: chat\r\n\r\n"
    ).into_bytes();
    response.extend_from_slice(b"\x81\x07welcome");
    io.write_all(&response).unwrap();
    io.flush().unwrap();
}

fn read_client_text(io: &mut impl Read) -> Vec<u8> {
    let mut header = [0; 2];
    io.read_exact(&mut header).unwrap();
    assert_eq!(header[0], 0x81);
    assert_ne!(header[1] & 0x80, 0, "tunneled client frames remain masked");
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

fn retired(socket: &mut TcpStream) {
    let mut budget = 32 * 1024_usize;
    let mut buffer = [0; 1024];
    loop {
        match socket.read(&mut buffer) {
            Ok(0) => return,
            Ok(count) => budget = budget.checked_sub(count).expect("bounded residual output"),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
                ) =>
            {
                return;
            }
            Err(error) => panic!("proxy socket was not retired: {error}"),
        }
    }
}

fn options(timeout: Duration) -> WebSocketConnectOptions {
    WebSocketConnectOptions::new(
        WebSocketConfig::default()
            .connect_timeout(Some(timeout))
            .ping_interval(None)
            .protocol("chat"),
    )
    .try_header("Authorization", ORIGIN_AUTH)
    .unwrap()
    .try_header("Cookie", COOKIE)
    .unwrap()
    .try_header("Origin", "https://application.example")
    .unwrap()
}

fn http_proxy(address: SocketAddr) -> WebSocketHttpProxy {
    WebSocketHttpProxy::new(format!("http://{address}"))
        .unwrap()
        .with_authorization(PROXY_AUTH)
        .unwrap()
        .with_http_client(
            HttpClient::builder()
                .default_header("Authorization", DEFAULT_SECRET)
                .default_header("Proxy-Authorization", DEFAULT_SECRET)
                .default_header("X-Default", DEFAULT_SECRET)
                .request_timeout(WATCHDOG)
                .build(),
        )
}

fn assert_redacted(error: &WsConnectError) {
    let display = format!("{error} {error:?}");
    for secret in [PROXY_AUTH, ORIGIN_AUTH, COOKIE, DEFAULT_SECRET] {
        assert!(!display.contains(secret), "credential appeared in an error");
    }
}

#[test]
fn proxy_configuration_and_invalid_targets_fail_before_dial_without_secrets() {
    for url in [
        "socks5://proxy:1080",
        "http://user:secret@proxy:3128",
        "http://proxy:0",
        "http://proxy/path",
        "http://proxy?secret",
        "http://proxy/#secret",
        "http://proxy\r\nX: secret",
        "http://[::1",
        "http://[not-an-ip]:3128",
        "http://[::1]suffix:3128",
    ] {
        let error = WebSocketHttpProxy::new(url).unwrap_err();
        assert!(!format!("{error} {error:?}").contains("secret"));
    }
    assert!(
        WebSocketHttpProxy::new(format!(
            "http://{}",
            "a".repeat(WebSocketHttpProxy::MAX_URL_BYTES)
        ))
        .is_err()
    );
    for value in [
        "",
        "secret\r\nX-Injected: yes",
        "secret\0",
        "secret\u{7f}",
        "秘密",
    ] {
        let error = WebSocketHttpProxy::new("http://proxy:3128")
            .unwrap()
            .with_authorization(value)
            .unwrap_err();
        if !value.is_empty() {
            assert!(
                !format!("{error} {error:?}").contains(value),
                "invalid credential was echoed"
            );
        }
    }
    let exact = "a".repeat(WebSocketHttpProxy::MAX_AUTHORIZATION_BYTES);
    assert!(
        WebSocketHttpProxy::new("http://proxy:3128")
            .unwrap()
            .with_authorization(&exact)
            .is_ok()
    );
    assert!(
        WebSocketHttpProxy::new("http://proxy:3128")
            .unwrap()
            .with_authorization(format!("{exact}a"))
            .is_err()
    );
    let (listener, address) = bind_listener();
    let proxy = http_proxy(address);
    let debug = format!("{proxy:?}");
    assert!(!debug.contains(PROXY_AUTH));
    assert!(!debug.contains(&address.to_string()));
    run_native(1, None, |owner| async move {
        for target in [
            "ws://",
            "http://origin.invalid",
            "ws://user:secret@origin.invalid/",
            "ws://origin.invalid/path\r\nX: secret",
            "wss://origin.invalid/",
        ] {
            let error = WebSocket::connect_via_proxy(&owner, target, options(WATCHDOG), &proxy)
                .await
                .err()
                .expect("invalid route must not dial");
            assert_redacted(&error);
        }
        let error = WebSocket::connect_via_proxy(
            &owner,
            "ws://origin.invalid/",
            options(Duration::ZERO),
            &proxy,
        )
        .await
        .err()
        .expect("zero setup budget");
        assert!(
            matches!(error, WsConnectError::Io(error) if error.kind() == io::ErrorKind::TimedOut)
        );
    });
    no_connection(&listener);
}

#[cfg(not(feature = "tls"))]
#[test]
fn https_proxy_is_refused_without_tls_before_native_setup() {
    assert!(WebSocketHttpProxy::new("https://localhost:3128").is_err());
}

#[test]
fn native_proxy_routes_credentials_and_preserves_coalesced_frames_and_masking() {
    for workers in [1, 2] {
        let (listener, address) = bind_listener();
        let (unused_proxy, unused_address) = bind_listener();
        let peer = std::thread::spawn(move || {
            let mut socket = accept(&listener);
            read_head(&mut socket).assert_connect("origin.invalid:8080");
            tunnel(&mut socket);
            let head = read_head(&mut socket);
            head.assert_upgrade("origin.invalid:8080", "/events?room=1");
            upgrade_and_first_message(&mut socket, &head);
            assert_eq!(read_client_text(&mut socket), b"ready");
            retired(&mut socket);
        });
        let clock = Arc::new(VirtualClock::starting_at(Time::from_secs(20)));
        let timer = TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
        run_native(workers, Some(timer.clone()), move |owner| async move {
            let proxy = http_proxy(address).with_http_client(
                HttpClient::builder()
                    .default_header("Authorization", DEFAULT_SECRET)
                    .default_header("Proxy-Authorization", DEFAULT_SECRET)
                    .default_header("X-Default", DEFAULT_SECRET)
                    .proxy(format!("http://{unused_address}"))
                    .request_timeout(WATCHDOG)
                    .build(),
            );
            let mut socket = require_send(WebSocket::connect_via_proxy(
                &owner,
                "ws://origin.invalid:8080/events?room=1",
                options(WATCHDOG),
                &proxy,
            ))
            .await
            .unwrap();
            assert_eq!(socket.protocol(), Some("chat"));
            assert_eq!(
                timer.next_deadline(),
                None,
                "completed setup retires its timers"
            );
            clock.advance_to(Time::from_secs(40));
            assert!(
                matches!(socket.recv(&owner).await.unwrap(), Some(Message::Text(text)) if text == "welcome")
            );
            socket.send(&owner, Message::text("ready")).await.unwrap();
            drop(socket);
            assert!(owner.inner.read().cancel_waker_registrations.is_empty());
        });
        peer.join().unwrap();
        no_connection(&unused_proxy);
    }
}

#[test]
fn connect_refusals_and_redirects_never_contact_origin_or_forward_credentials() {
    for status in [407, 302] {
        let (proxy_listener, proxy_address) = bind_listener();
        let (origin, origin_address) = bind_listener();
        let (redirect, redirect_address) = bind_listener();
        let peer = std::thread::spawn(move || {
            let mut socket = accept(&proxy_listener);
            read_head(&mut socket).assert_connect(&origin_address.to_string());
            write!(socket, "HTTP/1.1 {status} {PROXY_AUTH}\r\nLocation: http://{redirect_address}/\r\nContent-Length: 0\r\n\r\n").unwrap();
            let mut byte = [0];
            assert_eq!(
                socket.read(&mut byte).unwrap(),
                0,
                "refusal must not send origin upgrade bytes"
            );
            no_connection(&proxy_listener);
        });
        run_native(1, None, |owner| async move {
            let proxy = http_proxy(proxy_address);
            let error = WebSocket::connect_via_proxy(
                &owner,
                &format!("ws://{origin_address}/private"),
                options(WATCHDOG),
                &proxy,
            )
            .await
            .err()
            .expect("proxy refusal");
            assert_redacted(&error);
            assert!(
                matches!(error, WsConnectError::Handshake(HandshakeError::Rejected { status: actual, .. }) if actual == status)
            );
        });
        peer.join().unwrap();
        no_connection(&origin);
        no_connection(&redirect);
    }
}

#[test]
fn connect_authorities_include_default_ports_and_bracket_ipv6() {
    for (url, authority, host) in [
        (
            "ws://origin.invalid/events",
            "origin.invalid:80",
            "origin.invalid",
        ),
        ("ws://[::1]/events", "[::1]:80", "[::1]"),
    ] {
        let (listener, address) = bind_listener();
        let peer = std::thread::spawn(move || {
            let mut socket = accept(&listener);
            read_head(&mut socket).assert_connect(authority);
            tunnel(&mut socket);
            let head = read_head(&mut socket);
            head.assert_upgrade(host, "/events");
            upgrade_and_first_message(&mut socket, &head);
            retired(&mut socket);
        });
        run_native(1, None, |owner| async move {
            let proxy = http_proxy(address);
            let mut socket = WebSocket::connect_via_proxy(&owner, url, options(WATCHDOG), &proxy)
                .await
                .unwrap();
            assert!(
                matches!(socket.recv(&owner).await.unwrap(), Some(Message::Text(text)) if text == "welcome")
            );
            drop(socket);
        });
        peer.join().unwrap();
    }
}

#[derive(Default)]
struct Witness {
    stage: AtomicUsize,
    waiter: Mutex<Option<Waker>>,
}

impl Witness {
    fn publish(&self, stage: usize) {
        self.stage.store(stage, Ordering::Release);
        let waiter = self.waiter.lock().unwrap().take();
        if let Some(waiter) = waiter {
            waiter.wake();
        }
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
fn explicit_owner_cancel_or_dropped_setup_retires_parked_connect_and_upgrade() {
    for workers in [1, 2] {
        for after_connect in [false, true] {
            for cancel in [false, true] {
                let (listener, address) = bind_listener();
                let witness = Arc::new(Witness::default());
                let observed = Arc::clone(&witness);
                let peer = std::thread::spawn(move || {
                    let mut socket = accept(&listener);
                    read_head(&mut socket).assert_connect("origin.invalid:8080");
                    if after_connect {
                        tunnel(&mut socket);
                        read_head(&mut socket).assert_upgrade("origin.invalid:8080", "/parked");
                    }
                    observed.publish(1);
                    let mut byte = [0];
                    assert_eq!(
                        socket.read(&mut byte).unwrap(),
                        0,
                        "parked setup closed without sending more protocol bytes"
                    );
                });
                run_native(workers, None, |owner| async move {
                    let driver = Cx::current().unwrap();
                    assert_ne!(driver.task_id(), owner.task_id());
                    let proxy = http_proxy(address);
                    let mut call = Box::pin(require_send(WebSocket::connect_via_proxy(
                        &owner,
                        "ws://origin.invalid:8080/parked",
                        options(WATCHDOG),
                        &proxy,
                    )));
                    let wakes = Arc::new(AtomicUsize::new(0));
                    poll_fn(|task| {
                        *witness.waiter.lock().unwrap() = Some(task.waker().clone());
                        let waker = Waker::from(Arc::new(ForwardWake {
                            count: Arc::clone(&wakes),
                            parent: task.waker().clone(),
                        }));
                        assert!(
                            call.as_mut()
                                .poll(&mut Context::from_waker(&waker))
                                .is_pending()
                        );
                        if witness.stage.load(Ordering::Acquire) != 0 {
                            Poll::Ready(())
                        } else {
                            Poll::Pending
                        }
                    })
                    .await;
                    if cancel {
                        let before = wakes.load(Ordering::SeqCst);
                        owner.cancel_with(CancelKind::User, Some("stop proxy setup"));
                        assert!(
                            wakes.load(Ordering::SeqCst) > before,
                            "explicit owner woke parked setup"
                        );
                        let error = call.as_mut().await.err().expect("cancelled setup");
                        assert!(matches!(error, WsConnectError::Cancelled));
                    }
                    drop(call);
                    assert!(owner.inner.read().cancel_waker_registrations.is_empty());
                    assert!(driver.inner.read().cancel_waker_registrations.is_empty());
                    assert!(!driver.is_cancel_requested());
                });
                peer.join().unwrap();
            }
        }
    }
}

#[test]
fn connect_and_upgrade_share_one_original_virtual_setup_deadline() {
    let (listener, address) = bind_listener();
    let witness = Arc::new(Witness::default());
    let observed = Arc::clone(&witness);
    let (release, released) = mpsc::channel();
    let peer = std::thread::spawn(move || {
        let mut socket = accept(&listener);
        read_head(&mut socket).assert_connect("origin.invalid:8080");
        observed.publish(1);
        released.recv_timeout(WATCHDOG).unwrap();
        tunnel(&mut socket);
        read_head(&mut socket).assert_upgrade("origin.invalid:8080", "/budget");
        observed.publish(2);
        retired(&mut socket);
    });
    let clock = Arc::new(VirtualClock::starting_at(Time::from_secs(100)));
    let timer = TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
    run_native(1, Some(timer.clone()), |owner| async move {
        let proxy = http_proxy(address).with_http_client(
            HttpClient::builder()
                .request_timeout(Duration::from_secs(30))
                .build(),
        );
        let mut call = Box::pin(WebSocket::connect_via_proxy(
            &owner,
            "ws://origin.invalid:8080/budget",
            options(Duration::from_secs(10)),
            &proxy,
        ));
        let mut advanced = 0;
        let error = poll_fn(|task| {
            *witness.waiter.lock().unwrap() = Some(task.waker().clone());
            if let Poll::Ready(result) = call.as_mut().poll(task) {
                return Poll::Ready(result.err().expect("silent upgrade must time out"));
            }
            match witness.stage.load(Ordering::Acquire) {
                1 if advanced == 0 => {
                    advanced = 1;
                    clock.advance_to(Time::from_secs(106));
                    release.send(()).unwrap();
                    task.waker().wake_by_ref();
                }
                2 if advanced == 1 => {
                    advanced = 2;
                    assert_eq!(
                        timer.next_deadline(),
                        Some(Time::from_secs(110)),
                        "upgrade cannot reset setup timeout"
                    );
                    clock.advance_to(Time::from_secs(111));
                    task.waker().wake_by_ref();
                }
                _ => {}
            }
            Poll::Pending
        })
        .await;
        assert_eq!(advanced, 2, "both native setup phases were exercised");
        assert!(
            matches!(error, WsConnectError::Io(error) if error.kind() == io::ErrorKind::TimedOut)
        );
        drop(call);
        assert!(owner.inner.read().cancel_waker_registrations.is_empty());
        assert_eq!(timer.next_deadline(), None);
    });
    peer.join().unwrap();
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
    config.alpn_protocols = vec![protocol.to_vec()];
    rustls::StreamOwned::new(rustls::ServerConnection::new(Arc::new(config)).unwrap(), io)
}

#[cfg(feature = "tls")]
fn origin_connector(trust: bool, protocol: &[u8]) -> crate::tls::TlsConnector {
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
    config.alpn_protocols = vec![protocol.to_vec()];
    crate::tls::TlsConnector::new(config)
}

#[cfg(feature = "tls")]
fn tls_proxy(address: SocketAddr, secure: bool, trust: bool) -> WebSocketHttpProxy {
    let mut client = HttpClient::builder()
        .request_timeout(WATCHDOG)
        .default_header("Authorization", DEFAULT_SECRET)
        .default_header("X-Default", DEFAULT_SECRET);
    if trust {
        for certificate in crate::tls::Certificate::from_pem(CERT).unwrap() {
            client = client.add_root_certificate(certificate);
        }
    }
    WebSocketHttpProxy::new(format!(
        "{}://localhost:{}",
        if secure { "https" } else { "http" },
        address.port()
    ))
    .unwrap()
    .with_authorization(PROXY_AUTH)
    .unwrap()
    .with_http_client(client.build())
}

#[cfg(feature = "tls")]
fn serve_route<T: Read + Write>(mut io: T, origin_tls: bool) {
    let authority = if origin_tls {
        "localhost:443"
    } else {
        "origin.invalid:8080"
    };
    read_head(&mut io).assert_connect(authority);
    tunnel(&mut io);
    if origin_tls {
        let mut tls = tls_server(io, b"http/1.1");
        let head = read_head(&mut tls);
        head.assert_upgrade("localhost", "/secure");
        assert_eq!(tls.conn.server_name(), Some("localhost"));
        assert_eq!(tls.conn.alpn_protocol(), Some(b"http/1.1".as_slice()));
        upgrade_and_first_message(&mut tls, &head);
        assert_eq!(read_client_text(&mut tls), b"ready");
    } else {
        let head = read_head(&mut io);
        head.assert_upgrade(authority, "/secure");
        upgrade_and_first_message(&mut io, &head);
        assert_eq!(read_client_text(&mut io), b"ready");
    }
}

#[cfg(feature = "tls")]
#[test]
fn native_tls_proxy_and_origin_authenticate_separately_and_preserve_websocket_bytes() {
    for (secure_proxy, secure_origin) in [(false, true), (true, false), (true, true)] {
        let (listener, address) = bind_listener();
        let peer = std::thread::spawn(move || {
            let socket = accept(&listener);
            if secure_proxy {
                serve_route(tls_server(socket, b"http/1.1"), secure_origin);
            } else {
                serve_route(socket, secure_origin);
            }
        });
        run_native(1, None, |owner| async move {
            let proxy = tls_proxy(address, secure_proxy, true);
            if secure_origin {
                let connector = origin_connector(true, b"http/1.1");
                let mut socket = require_send(WebSocket::connect_tls_via_proxy(
                    &owner,
                    "wss://localhost/secure",
                    options(WATCHDOG),
                    &proxy,
                    &connector,
                ))
                .await
                .unwrap();
                assert_eq!(socket.protocol(), Some("chat"));
                assert!(
                    matches!(socket.recv(&owner).await.unwrap(), Some(Message::Text(text)) if text == "welcome")
                );
                socket.send(&owner, Message::text("ready")).await.unwrap();
            } else {
                let mut socket = require_send(WebSocket::connect_via_proxy(
                    &owner,
                    "ws://origin.invalid:8080/secure",
                    options(WATCHDOG),
                    &proxy,
                ))
                .await
                .unwrap();
                assert!(
                    matches!(socket.recv(&owner).await.unwrap(), Some(Message::Text(text)) if text == "welcome")
                );
                socket.send(&owner, Message::text("ready")).await.unwrap();
            }
        });
        peer.join().unwrap();
    }
}

#[cfg(feature = "tls")]
fn no_tls_application_bytes(result: io::Result<usize>) {
    match result {
        Ok(0) => {}
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::UnexpectedEof
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::BrokenPipe
                    | io::ErrorKind::InvalidData
            ) => {}
        other => panic!("TLS refusal exposed application bytes: {other:?}"),
    }
}

#[cfg(feature = "tls")]
#[test]
fn proxy_route_rejects_bad_origin_identity_trust_and_alpn_before_upgrade_secrets() {
    for mode in ["wrong-name", "untrusted-origin", "wrong-alpn"] {
        let (listener, address) = bind_listener();
        let origin = if mode == "wrong-name" {
            "wrong.invalid"
        } else {
            "localhost"
        };
        let protocol: &[u8] = if mode == "wrong-alpn" {
            b"h2"
        } else {
            b"http/1.1"
        };
        let peer = std::thread::spawn(move || {
            let mut socket = accept(&listener);
            read_head(&mut socket).assert_connect(&format!("{origin}:9443"));
            tunnel(&mut socket);
            let mut tls = tls_server(socket, protocol);
            no_tls_application_bytes(tls.read(&mut [0]));
        });
        run_native(1, None, |owner| async move {
            let proxy = http_proxy(address);
            let connector = origin_connector(mode != "untrusted-origin", protocol);
            let error = WebSocket::connect_tls_via_proxy(
                &owner,
                &format!("wss://{origin}:9443/private"),
                options(WATCHDOG),
                &proxy,
                &connector,
            )
            .await
            .err()
            .expect("origin TLS policy must be enforced");
            assert_redacted(&error);
            assert!(matches!(error, WsConnectError::Io(_)));
        });
        peer.join().unwrap();
    }
}

#[cfg(feature = "tls")]
#[test]
fn untrusted_https_proxy_receives_no_connect_or_origin_credentials() {
    let (listener, address) = bind_listener();
    let peer = std::thread::spawn(move || {
        let mut tls = tls_server(accept(&listener), b"http/1.1");
        no_tls_application_bytes(tls.read(&mut [0]));
    });
    run_native(1, None, |owner| async move {
        // An explicit unrelated root forces a real TLS authentication attempt,
        // even when builds without public roots reject an empty store pre-dial.
        let foreign = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/tls/postgres_ca.crt"
        ));
        let mut client = HttpClient::builder().request_timeout(WATCHDOG);
        for certificate in crate::tls::Certificate::from_pem(foreign).unwrap() {
            client = client.add_root_certificate(certificate);
        }
        let proxy = WebSocketHttpProxy::new(format!("https://localhost:{}", address.port()))
            .unwrap()
            .with_authorization(PROXY_AUTH)
            .unwrap()
            .with_http_client(client.build());
        let connector = origin_connector(true, b"http/1.1");
        let error = WebSocket::connect_tls_via_proxy(
            &owner,
            "wss://localhost:9443/private",
            options(WATCHDOG),
            &proxy,
            &connector,
        )
        .await
        .err()
        .expect("untrusted proxy");
        assert_redacted(&error);
        assert!(matches!(error, WsConnectError::Io(_)));
        assert!(owner.inner.read().cancel_waker_registrations.is_empty());
    });
    peer.join().unwrap();
}
