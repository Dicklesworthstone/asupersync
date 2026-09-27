//! Native WSS establishment through the public client API and a rustls peer.
//! The peer witnesses ClientHello or an incomplete HTTP response before any
//! interruption, then observes retirement of the actual acquired TCP socket.

#![cfg(all(
    not(target_arch = "wasm32"),
    feature = "tls",
    feature = "test-internals"
))]

use asupersync::net::TcpStream;
use asupersync::cx::cap::{CapSet, CapSetRuntimeMask};
use asupersync::net::websocket::{
    HttpRequest, Message, WebSocket, WebSocketConfig, WsConnectError, compute_accept_key,
};
use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::tls::{TlsConnector, TlsStream};
use asupersync::types::{Budget, CancelKind};
use asupersync::Cx;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use std::future::{Future, poll_fn};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream as StdTcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::sync_channel;
use std::sync::{Arc, Mutex};
use std::task::{Poll, Waker};
use std::time::{Duration, Instant};

type SecureWebSocket = WebSocket<TlsStream<TcpStream>>;
type Peer = rustls::StreamOwned<rustls::ServerConnection, StdTcpStream>;

const WATCHDOG: Duration = Duration::from_secs(6);
const SETUP_TIMEOUT: Duration = Duration::from_secs(2);
const CERT: &[u8] = include_bytes!("fixtures/tls/server.crt");
const KEY: &[u8] = include_bytes!("fixtures/tls/server.key");

fn listener(ip: &str) -> (TcpListener, SocketAddr) {
    let listener = TcpListener::bind((ip, 0)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    (listener, address)
}

fn accept(listener: &TcpListener) -> StdTcpStream {
    let until = Instant::now() + WATCHDOG;
    loop {
        match listener.accept() {
            Ok((socket, _)) => {
                socket.set_read_timeout(Some(WATCHDOG)).unwrap();
                socket.set_write_timeout(Some(WATCHDOG)).unwrap();
                return socket;
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                assert!(Instant::now() < until, "WSS client never connected");
                std::thread::park_timeout(Duration::from_millis(1));
            }
            Err(error) => panic!("WSS accept failed: {error}"),
        }
    }
}

fn runtime(workers: usize) -> Runtime {
    let builder = if workers == 0 {
        RuntimeBuilder::current_thread()
    } else {
        RuntimeBuilder::multi_thread().worker_threads(workers)
    };
    builder
        .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
        .build()
        .unwrap()
}

fn assert_retired(runtime: &Runtime) {
    let started = Instant::now();
    while !runtime.is_quiescent() {
        assert!(started.elapsed() < WATCHDOG, "WSS setup owner did not retire");
        std::thread::park_timeout(Duration::from_millis(1));
    }
    assert!(runtime.task_inspector(Default::default()).list_tasks().is_empty());
    assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
    assert_eq!(runtime.draining_region_count(), 0);
}

// Return a completion flag so the caller joins the independent peer before
// asserting task completion. A cancelled or panicking task cannot skip checks.
fn native<F, Fut>(workers: usize, caller_timeout: Option<Duration>, work: F) -> bool
where
    F: FnOnce(Cx, Cx) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let runtime = runtime(workers);
    let clock = runtime.request_cx_with_budget(Budget::INFINITE).timer_driver().unwrap();
    let budget = caller_timeout.map_or(Budget::INFINITE, |duration| {
        Budget::INFINITE.with_timeout(clock.now(), duration)
    });
    let caller = runtime.request_cx_with_budget(budget);
    let completed = Arc::new(AtomicBool::new(false));
    let done = Arc::clone(&completed);
    let mut task = runtime.handle().try_spawn(async move {
        let ambient = Cx::current().expect("native WSS task context");
        assert_ne!(ambient.task_id(), caller.task_id());
        work(ambient, caller).await;
        done.store(true, Ordering::Release);
    }).unwrap();
    runtime.block_on(async {
        asupersync::time::timeout(
            asupersync::time::wall_now(), WATCHDOG, &mut task,
        ).await.expect("WSS task exceeded watchdog");
    });
    assert_retired(&runtime);
    completed.load(Ordering::Acquire)
}

fn connector(trusted: bool, protocols: &[&[u8]]) -> TlsConnector {
    let mut roots = rustls::RootCertStore::empty();
    if trusted {
        roots.add(CertificateDer::from_pem_slice(CERT).unwrap()).unwrap();
    }
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.alpn_protocols = protocols.iter().map(|protocol| protocol.to_vec()).collect();
    TlsConnector::new(config)
}

fn server(socket: StdTcpStream, protocol: Option<&[u8]>) -> Peer {
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
    if let Some(protocol) = protocol {
        config.alpn_protocols = vec![protocol.to_vec()];
    }
    let connection = rustls::ServerConnection::new(Arc::new(config)).unwrap();
    rustls::StreamOwned::new(connection, socket)
}

fn request(peer: &mut impl Read) -> HttpRequest {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        peer.read_exact(&mut byte).expect("decrypted HTTP upgrade request");
        head.push(byte[0]);
        assert!(head.len() <= 16 * 1024, "bounded HTTP request fixture");
    }
    HttpRequest::parse(&head).unwrap()
}

fn response(request: &HttpRequest, extra: &str) -> Vec<u8> {
    let accept = compute_accept_key(request.header("sec-websocket-key").unwrap());
    format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n{extra}\r\n"
    ).into_bytes()
}

fn frame(first: u8, payload: &[u8]) -> Vec<u8> {
    let length = u8::try_from(payload.len()).unwrap();
    assert!(length <= 125);
    let mut bytes = vec![first, length];
    bytes.extend_from_slice(payload);
    bytes
}

fn client_frame(peer: &mut impl Read) -> (u8, Vec<u8>) {
    let mut header = [0; 2];
    peer.read_exact(&mut header).unwrap();
    assert_ne!(header[1] & 0x80, 0, "TLS does not remove client masking");
    let length = usize::from(header[1] & 0x7f);
    assert!(length <= 125);
    let mut mask = [0; 4];
    peer.read_exact(&mut mask).unwrap();
    let mut payload = vec![0; length];
    peer.read_exact(&mut payload).unwrap();
    for (index, byte) in payload.iter_mut().enumerate() {
        *byte ^= mask[index % 4];
    }
    (header[0], payload)
}

fn transport_retired(socket: &mut StdTcpStream) {
    let mut buffer = [0; 4096];
    let mut allowance = 128 * 1024_usize;
    loop {
        match socket.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => {
                allowance = allowance.checked_sub(count).expect("bounded residual TLS output");
            }
            Err(error) if matches!(error.kind(), io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted) => break,
            Err(error) => panic!("acquired WSS transport did not retire: {error:?}"),
        }
    }
}

fn no_http_then_retired(peer: &mut Peer) {
    let mut byte = [0];
    match peer.read(&mut byte) {
        Ok(0) => {}
        Ok(count) => panic!("TLS policy refusal leaked {count} HTTP bytes"),
        Err(error) => assert!(matches!(error.kind(),
            io::ErrorKind::InvalidData | io::ErrorKind::UnexpectedEof
            | io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
        ), "unexpected TLS refusal: {error:?}"),
    }
    transport_retired(&mut peer.sock);
}

#[test]
fn native_wss_authenticates_dns_and_ip_preserves_tail_and_split_state() {
    for workers in [0, 2] {
        for alpn in [Some(b"http/1.1".as_slice()), None] {
            let (listener, address) = listener("127.0.0.1");
            let host = if alpn.is_some() { "localhost" } else { "127.0.0.1" };
            let peer = std::thread::spawn(move || {
                let mut peer = server(accept(&listener), alpn);
                let request = request(&mut peer);
                assert_eq!(request.method, "GET");
                assert_eq!(request.path, "/secure?tail=1");
                assert_eq!(request.header("host"), Some(format!("{host}:{}", address.port()).as_str()));
                assert_eq!(request.header("sec-websocket-protocol"), Some("chat"));
                assert_eq!(peer.conn.alpn_protocol(), alpn);
                assert_eq!(peer.conn.server_name(), if alpn.is_some() { Some("localhost") } else { None });
                let mut head_and_tail = response(&request, "Sec-WebSocket-Protocol: chat\r\n");
                head_and_tail.extend(frame(0x81, b"tail"));
                peer.write_all(&head_and_tail).unwrap();
                peer.flush().unwrap();
                assert_eq!(client_frame(&mut peer), (0x81, b"client".to_vec()));
                let mut frames = frame(0x82, b"reply");
                frames.extend(frame(0x88, &[0x03, 0xe8]));
                peer.write_all(&frames).unwrap();
                peer.flush().unwrap();
                assert_eq!(client_frame(&mut peer), (0x88, vec![0x03, 0xe8]));
                transport_retired(&mut peer.sock);
            });
            let done = native(workers, None, move |ambient, caller| async move {
                let connector = connector(true, &[b"http/1.1"]);
                let url = format!("wss://{host}:{}/secure?tail=1", address.port());
                let config = WebSocketConfig::new().protocol("chat").ping_interval(None);
                let ws = SecureWebSocket::connect_tls(&caller, &url, config, &connector).await.unwrap();
                assert_eq!(ws.protocol(), Some("chat"));
                assert!(!ws.compression_enabled());
                let (mut read, mut write) = ws.split();
                assert!(matches!(read.recv(&caller).await.unwrap(), Some(Message::Text(text)) if text == "tail"));
                write.send(&caller, Message::Text("client".to_owned())).await.unwrap();
                assert!(matches!(read.recv(&caller).await.unwrap(), Some(Message::Binary(bytes)) if bytes.as_ref() == b"reply"));
                let mut ws = read.reunite(write).expect("TLS state and read tail survive reunite");
                assert_eq!(ws.protocol(), Some("chat"));
                assert!(matches!(ws.recv(&caller).await.unwrap(), Some(Message::Close(_))));
                assert!(ws.is_closed());
                assert!(!ambient.is_cancel_requested());
                assert!(!caller.is_cancel_requested());
            });
            peer.join().expect("authenticated independent WSS peer");
            assert!(done, "workers={workers}, ALPN={alpn:?}");
        }
    }
}

#[test]
fn native_wss_refuses_untrusted_identity_wrong_ip_and_h2_before_http() {
    for workers in [0, 2] {
        // The fixture certificate has localhost and 127.0.0.1 SANs. A second
        // loopback address reaches the server but cannot match either identity.
        for (ip, trusted, protocol) in [
            ("127.0.0.1", false, b"http/1.1".as_slice()),
            ("127.0.0.2", true, b"http/1.1".as_slice()),
            ("127.0.0.1", true, b"h2".as_slice()),
        ] {
            let (listener, address) = listener(ip);
            let peer = std::thread::spawn(move || {
                let mut peer = server(accept(&listener), Some(protocol));
                no_http_then_retired(&mut peer);
            });
            let done = native(workers, None, move |ambient, caller| async move {
                let connector = connector(trusted, &[protocol]);
                let result = SecureWebSocket::connect_tls(
                    &caller, &format!("wss://{address}/forbidden"),
                    WebSocketConfig::new(), &connector,
                ).await;
                match result {
                    Err(WsConnectError::Io(error)) => assert_eq!(error.kind(), io::ErrorKind::InvalidData),
                    Err(other) => panic!("wrong TLS policy error: {other:?}"),
                    Ok(_) => panic!("unauthenticated or non-HTTP/1.1 WSS accepted"),
                }
                assert!(!caller.is_cancel_requested());
                assert!(!ambient.is_cancel_requested());
            });
            peer.join().expect("TLS policy refusal and transport retirement");
            assert!(done, "workers={workers}, ip={ip}, trusted={trusted}, ALPN={protocol:?}");
        }
    }
}

#[derive(Default)]
struct Witness {
    received: AtomicBool,
    waiter: Mutex<Option<Waker>>,
}

impl Witness {
    fn publish(&self) {
        self.received.store(true, Ordering::Release);
        let wake = self.waiter.lock().unwrap().take();
        if let Some(wake) = wake {
            wake.wake();
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Stage { Tls, Http }

#[derive(Clone, Copy, Debug)]
enum Interrupt {
    CallerCancel, AmbientCancel, Drop, ConfigDeadline, CallerDeadline,
    RevokeIo, RevokeTimer,
}

fn interruption(workers: usize, stage: Stage, mode: Interrupt) {
    let (listener, address) = listener("127.0.0.1");
    let witness = Arc::new(Witness::default());
    let observed = Arc::clone(&witness);
    let (parked, parks) = sync_channel::<(Cx, Cx)>(1);
    let peer = std::thread::spawn(move || {
        let mut socket = accept(&listener);
        match stage {
            Stage::Tls => {
                let mut record = [0; 5];
                socket.read_exact(&mut record).unwrap();
                assert_eq!(record[0], 22, "WSS must begin with a TLS handshake");
                let length = usize::from(u16::from_be_bytes([record[3], record[4]]));
                assert!((4..=18_432).contains(&length));
                let mut hello = vec![0; length];
                socket.read_exact(&mut hello).unwrap();
                assert_eq!(hello[0], 1, "ClientHello is the parked setup witness");
            }
            Stage::Http => {
                let mut peer = server(socket, Some(b"http/1.1"));
                let request = request(&mut peer);
                assert_eq!(request.path, "/parked");
                // There is no header terminator or complete response yet.
                peer.write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade:").unwrap();
                peer.flush().unwrap();
                // Both branches below retire the exact original socket; no
                // duplicate handle can accidentally keep the transport alive.
                observed.publish();
                let (ambient, caller) = parks.recv_timeout(WATCHDOG).expect("HTTP setup polled Pending after response prefix");
                interrupt_contexts(mode, &ambient, &caller);
                transport_retired(&mut peer.sock);
                return;
            }
        }
        observed.publish();
        let (ambient, caller) = parks.recv_timeout(WATCHDOG).expect("TLS setup polled Pending after ClientHello");
        interrupt_contexts(mode, &ambient, &caller);
        transport_retired(&mut socket);
    });
    let caller_timeout = matches!(mode, Interrupt::CallerDeadline).then_some(SETUP_TIMEOUT);
    let done = native(workers, caller_timeout, move |ambient, caller| async move {
        let connector = connector(true, &[b"http/1.1"]);
        let timeout = if matches!(mode, Interrupt::ConfigDeadline) { Some(SETUP_TIMEOUT) } else { None };
        let config = WebSocketConfig::new().connect_timeout(timeout);
        let url = format!("wss://{address}/parked");
        let mut setup = Box::pin(SecureWebSocket::connect_tls(&caller, &url, config, &connector));
        let mut notified = false;
        let mut restrict_next_poll = false;
        let result = poll_fn(|task| {
            let _restriction = if restrict_next_poll {
                let mask = if matches!(mode, Interrupt::RevokeIo) {
                    <CapSet<true, true, true, false, true> as CapSetRuntimeMask>::MASK
                } else {
                    <CapSet<true, false, true, true, true> as CapSetRuntimeMask>::MASK
                };
                Some(Cx::push_restriction(mask))
            } else {
                None
            };
            *witness.waiter.lock().unwrap() = Some(task.waker().clone());
            match setup.as_mut().poll(task) {
                Poll::Ready(result) => Poll::Ready(Some(result)),
                Poll::Pending => {
                    if witness.received.load(Ordering::Acquire) && !notified {
                        notified = true;
                        parked.try_send((ambient.clone(), caller.clone())).unwrap();
                        if matches!(mode, Interrupt::Drop) {
                            return Poll::Ready(None);
                        }
                        if matches!(mode, Interrupt::RevokeIo | Interrupt::RevokeTimer) {
                            // Setup captured an unrestricted ambient context
                            // before parking. Its next poll must still respect
                            // a caller that has since attenuated authority.
                            restrict_next_poll = true;
                            task.waker().wake_by_ref();
                        }
                    }
                    Poll::Pending
                }
            }
        }).await;
        drop(setup);
        assert!(notified, "missing actual Pending witness: {stage:?}, {mode:?}");
        match mode {
            Interrupt::Drop => assert!(result.is_none()),
            Interrupt::CallerCancel | Interrupt::AmbientCancel => {
                assert!(matches!(result, Some(Err(WsConnectError::Cancelled))));
                let cancelled = if matches!(mode, Interrupt::CallerCancel) { &caller } else { &ambient };
                let independent = if matches!(mode, Interrupt::CallerCancel) { &ambient } else { &caller };
                assert_eq!(cancelled.cancel_reason().unwrap().kind, CancelKind::User);
                assert!(!independent.is_cancel_requested(), "setup must not cancel the other owner");
            }
            Interrupt::ConfigDeadline => {
                assert!(matches!(result, Some(Err(WsConnectError::Io(error))) if error.kind() == io::ErrorKind::TimedOut));
                assert!(!caller.is_cancel_requested());
                assert!(!ambient.is_cancel_requested());
            }
            Interrupt::CallerDeadline => {
                // A Cx checkpoint can classify its expired budget before the
                // setup timer. Both paths must preserve the caller's bound.
                match result {
                    Some(Err(WsConnectError::Cancelled)) => assert_eq!(caller.cancel_reason().unwrap().kind, CancelKind::Deadline),
                    Some(Err(WsConnectError::Io(error))) => assert_eq!(error.kind(), io::ErrorKind::TimedOut),
                    _ => panic!("caller deadline did not stop WSS setup"),
                }
                assert!(caller.timer_driver().unwrap().now() >= caller.budget().deadline.unwrap());
                assert!(!ambient.is_cancel_requested());
            }
            Interrupt::RevokeIo | Interrupt::RevokeTimer => {
                assert!(restrict_next_poll);
                assert!(matches!(result, Some(Err(WsConnectError::Io(error))) if error.kind() == io::ErrorKind::PermissionDenied));
                assert!(!ambient.is_cancel_requested());
                assert!(!caller.is_cancel_requested());
            }
        }
    });
    peer.join().expect("parked WSS transport retired");
    assert!(done, "workers={workers}, stage={stage:?}, mode={mode:?}");
}

fn interrupt_contexts(mode: Interrupt, ambient: &Cx, caller: &Cx) {
    match mode {
        Interrupt::CallerCancel => caller.cancel_with(CancelKind::User, Some("explicit WSS owner cancelled")),
        Interrupt::AmbientCancel => ambient.cancel_with(CancelKind::User, Some("ambient WSS task cancelled")),
        Interrupt::Drop | Interrupt::ConfigDeadline | Interrupt::CallerDeadline
        | Interrupt::RevokeIo | Interrupt::RevokeTimer => {}
    }
}

#[test]
fn native_wss_parked_tls_and_partial_http_cancel_drop_and_expire() {
    for workers in [0, 2] {
        for stage in [Stage::Tls, Stage::Http] {
            for mode in [Interrupt::CallerCancel, Interrupt::AmbientCancel, Interrupt::Drop,
                Interrupt::ConfigDeadline, Interrupt::CallerDeadline,
                Interrupt::RevokeIo, Interrupt::RevokeTimer] {
                interruption(workers, stage, mode);
            }
        }
    }
}

#[test]
fn native_wss_keeps_one_setup_deadline_across_tls_and_http() {
    const TOTAL: Duration = Duration::from_secs(3);
    const TLS_HOLD: Duration = Duration::from_secs(2);
    for workers in [0, 2] {
        let (listener, address) = listener("127.0.0.1");
        let hello = Arc::new(Witness::default());
        let hello_seen = Arc::clone(&hello);
        let prefix = Arc::new(Witness::default());
        let prefix_seen = Arc::clone(&prefix);
        let (parked, parks) = sync_channel(1);
        let peer = std::thread::spawn(move || {
            let mut peer = server(accept(&listener), Some(b"http/1.1"));
            // Consume ClientHello into rustls without sending the server's
            // handshake flight. The client therefore cannot reach HTTP yet.
            while peer.conn.server_name().is_none() {
                assert_ne!(peer.conn.read_tls(&mut peer.sock).unwrap(), 0);
                peer.conn.process_new_packets().unwrap();
            }
            assert_eq!(peer.conn.server_name(), Some("localhost"));
            assert!(peer.conn.is_handshaking());
            assert!(peer.conn.wants_write());
            hello_seen.publish();
            parks.recv_timeout(WATCHDOG).expect("TLS handshake actually parked");
            // This intentionally consumes setup time AFTER a native Pending
            // witness; the delay is not used to infer that setup has parked.
            std::thread::sleep(TLS_HOLD);
            let request = request(&mut peer);
            assert_eq!(request.path, "/one-budget");
            peer.write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade:").unwrap();
            peer.flush().unwrap();
            prefix_seen.publish();
            transport_retired(&mut peer.sock);
        });
        let done = native(workers, None, move |ambient, caller| async move {
            let connector = connector(true, &[b"http/1.1"]);
            let url = format!("wss://localhost:{}/one-budget", address.port());
            let config = WebSocketConfig::new().connect_timeout(Some(TOTAL));
            let started = Instant::now();
            let mut setup = Box::pin(SecureWebSocket::connect_tls(
                &caller, &url, config, &connector,
            ));
            let mut tls_parked = false;
            let mut http_parked = false;
            let result = poll_fn(|task| {
                *hello.waiter.lock().unwrap() = Some(task.waker().clone());
                *prefix.waiter.lock().unwrap() = Some(task.waker().clone());
                match setup.as_mut().poll(task) {
                    Poll::Ready(result) => Poll::Ready(result),
                    Poll::Pending => {
                        if hello.received.load(Ordering::Acquire) && !tls_parked {
                            tls_parked = true;
                            parked.try_send(()).unwrap();
                        }
                        if prefix.received.load(Ordering::Acquire) {
                            http_parked = true;
                        }
                        Poll::Pending
                    }
                }
            }).await;
            let elapsed = started.elapsed();
            drop(setup);
            assert!(tls_parked && http_parked, "both real setup phases must be reached");
            assert!(matches!(result, Err(WsConnectError::Io(error)) if error.kind() == io::ErrorKind::TimedOut));
            assert!(elapsed >= TOTAL, "setup expired before its configured budget");
            // A fresh three-second HTTP budget after the two-second TLS hold
            // would finish at five seconds or later. Allow 1.5 seconds of
            // scheduling slack while still rejecting that reset behavior.
            assert!(elapsed < Duration::from_millis(4500), "setup reset its budget at the TLS/HTTP boundary: {elapsed:?}");
            assert!(!caller.is_cancel_requested());
            assert!(!ambient.is_cancel_requested());
        });
        peer.join().expect("single-budget WSS transport retired");
        assert!(done, "single WSS setup budget workers={workers}");
    }
}

#[test]
fn native_wss_rejects_plaintext_and_missing_explicit_authority_without_dialing() {
    for workers in [0, 2] {
        let (listener, address) = listener("127.0.0.1");
        let done = native(workers, None, move |ambient, caller| async move {
            let connector = connector(true, &[b"http/1.1"]);
            let plaintext = SecureWebSocket::connect_tls(
                &caller, &format!("ws://{address}/downgrade"),
                WebSocketConfig::new(), &connector,
            ).await;
            assert!(matches!(plaintext, Err(WsConnectError::InvalidUrl(_))));
            let mut without_sni = connector.config().as_ref().clone();
            without_sni.enable_sni = false;
            let without_sni = TlsConnector::new(without_sni);
            let refused_sni = SecureWebSocket::connect_tls(
                &caller, &format!("wss://localhost:{}/no-sni", address.port()),
                WebSocketConfig::new(), &without_sni,
            ).await;
            assert!(matches!(refused_sni, Err(WsConnectError::Io(error)) if error.kind() == io::ErrorKind::InvalidInput));
            let detached = Cx::for_testing();
            let denied = SecureWebSocket::connect_tls(
                &detached, &format!("wss://{address}/ambient-authority"),
                WebSocketConfig::new(), &connector,
            ).await;
            assert!(matches!(denied, Err(WsConnectError::Io(error)) if error.kind() == io::ErrorKind::PermissionDenied));
            for mask in [
                <CapSet<true, true, true, false, true> as CapSetRuntimeMask>::MASK,
                <CapSet<true, false, true, true, true> as CapSetRuntimeMask>::MASK,
            ] {
                let url = format!("wss://{address}/attenuated-ambient");
                let mut setup = Box::pin(SecureWebSocket::connect_tls(
                    &caller, &url, WebSocketConfig::new(), &connector,
                ));
                let denied = poll_fn(|task| {
                    let _restriction = Cx::push_restriction(mask);
                    setup.as_mut().poll(task)
                }).await;
                assert!(matches!(denied, Err(WsConnectError::Io(error)) if error.kind() == io::ErrorKind::PermissionDenied));
            }
            assert!(matches!(listener.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
            assert!(!ambient.is_cancel_requested());
            assert!(!caller.is_cancel_requested());
        });
        assert!(done, "WSS authority admission workers={workers}");
    }
}

#[cfg(feature = "compression")]
#[test]
fn native_wss_negotiates_compression_over_tls_with_independent_wire_vector() {
    const PROFILE: &str = "permessage-deflate; server_no_context_takeover; client_no_context_takeover";
    // RFC 7692 section 7.2.3.1: "Hello", with the sync-flush tail removed.
    const HELLO: &[u8] = &[0xf2, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00];
    for workers in [0, 2] {
        let (listener, address) = listener("127.0.0.1");
        let peer = std::thread::spawn(move || {
            let mut peer = server(accept(&listener), Some(b"http/1.1"));
            let request = request(&mut peer);
            assert!(request.header("sec-websocket-extensions").unwrap().contains("permessage-deflate"));
            let mut head_and_frame = response(&request, &format!("Sec-WebSocket-Extensions: {PROFILE}\r\n"));
            head_and_frame.extend(frame(0xc1, HELLO));
            peer.write_all(&head_and_frame).unwrap();
            peer.flush().unwrap();
            let (flags, mut payload) = client_frame(&mut peer);
            assert_eq!(flags, 0xc1, "encrypted client messages remain compressed and masked");
            payload.extend_from_slice(&[0, 0, 0xff, 0xff, 3, 0]);
            let mut decoder = flate2::read::DeflateDecoder::new(payload.as_slice());
            let mut decoded = Vec::new();
            decoder.read_to_end(&mut decoded).unwrap();
            assert_eq!(decoded, b"Hello");
            peer.write_all(&frame(0x88, &[0x03, 0xe8])).unwrap();
            peer.flush().unwrap();
            assert_eq!(client_frame(&mut peer), (0x88, vec![0x03, 0xe8]));
            transport_retired(&mut peer.sock);
        });
        let done = native(workers, None, move |_, caller| async move {
            let connector = connector(true, &[b"http/1.1"]);
            let ws = SecureWebSocket::connect_tls_with_compression(
                &caller, &format!("wss://{address}/compressed"),
                WebSocketConfig::new().ping_interval(None), &connector,
            ).await.unwrap();
            assert!(ws.compression_enabled());
            let (mut read, mut write) = ws.split();
            assert!(matches!(read.recv(&caller).await.unwrap(), Some(Message::Text(text)) if text == "Hello"));
            write.send(&caller, Message::Text("Hello".to_owned())).await.unwrap();
            let mut ws = read.reunite(write).expect("WSS compressed split reunites");
            assert!(ws.compression_enabled());
            assert!(matches!(ws.recv(&caller).await.unwrap(), Some(Message::Close(_))));
        });
        peer.join().expect("compressed WSS independent peer");
        assert!(done, "compressed WSS workers={workers}");
    }
}
