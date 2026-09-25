//! Native TLS setup, strict identity/ALPN refusal, and owned interruption.
//! br-asupersync-server-stack-hardening-eeexl1.10; existing localhost identity.

use super::*;
use crate::bytes::Bytes;
use crate::grpc::codec::IdentityCodec;
use crate::grpc::status::Code;
use crate::http::h2::{Header, HpackDecoder};
use crate::runtime::RuntimeBuilder;
use crate::types::CancelKind;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream as StdTcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::sync::{Arc, Mutex};
use std::task::Waker;
use std::time::Instant;

const PATH: &str = "/test.Setup/Watch";
const WATCHDOG: Duration = Duration::from_secs(5);
const CERT: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/tls/server.crt"
));
const KEY: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/tls/server.key"
));

fn listener() -> (TcpListener, SocketAddr) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
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
                assert!(Instant::now() < until, "endpoint never connected");
                std::thread::park_timeout(Duration::from_millis(1));
            }
            Err(error) => panic!("accept TLS setup peer: {error}"),
        }
    }
}

// The peer is joined before callers assert this independent completion flag.
// Task-level cancellation or panic must never silently skip wire assertions.
fn native<F, Fut>(multithread: bool, work: F) -> bool
where
    F: FnOnce(Cx) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let runtime = if multithread {
        RuntimeBuilder::new().worker_threads(2).build().unwrap()
    } else {
        RuntimeBuilder::current_thread().build().unwrap()
    };
    let completed = Arc::new(AtomicBool::new(false));
    let done = Arc::clone(&completed);
    let _result = runtime.block_on(runtime.handle().spawn(async move {
        let cx = Cx::current().expect("native task context");
        work(cx).await;
        done.store(true, Ordering::Release);
    }));
    completed.load(Ordering::Acquire)
}

fn connector(trust_fixture: bool) -> TlsConnector {
    let mut roots = rustls::RootCertStore::empty();
    if trust_fixture {
        // Trust this test identity only. Hostname, signature and chain checks
        // remain enabled; there is no accept-any certificate verifier.
        roots
            .add(CertificateDer::from_pem_slice(CERT).unwrap())
            .unwrap();
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];
    TlsConnector::new(config)
}

fn server(
    socket: StdTcpStream,
    h2: bool,
) -> rustls::StreamOwned<rustls::ServerConnection, StdTcpStream> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from_pem_slice(CERT).unwrap()],
            PrivateKeyDer::from_pem_slice(KEY).unwrap(),
        )
        .unwrap();
    if h2 {
        config.alpn_protocols = vec![b"h2".to_vec()];
    }
    let connection = rustls::ServerConnection::new(Arc::new(config)).unwrap();
    rustls::StreamOwned::new(connection, socket)
}

fn config() -> NativeStreamConfig {
    NativeStreamConfig {
        scheme: "https",
        ..Default::default()
    }
}

fn endpoint(address: SocketAddr, timeout: Duration) -> NativeStreamEndpoint {
    NativeStreamEndpoint::new(address, "logical.service", timeout).unwrap()
}

fn rpc_request() -> Request<Bytes> {
    let mut request = Request::new(Bytes::from_static(b"request"));
    assert!(
        request
            .metadata_mut()
            .insert("authorization", "Bearer fixture-token")
    );
    request
}

fn frame(io: &mut impl Write, kind: u8, flags: u8, stream: u32, payload: &[u8]) {
    let length = u32::try_from(payload.len()).unwrap();
    assert!(length <= 16 * 1024);
    let mut head = [0_u8; 9];
    head[..3].copy_from_slice(&length.to_be_bytes()[1..]);
    head[3] = kind;
    head[4] = flags;
    head[5..].copy_from_slice(&stream.to_be_bytes());
    io.write_all(&head).unwrap();
    io.write_all(payload).unwrap();
    io.flush().unwrap();
}

fn headers(io: &mut impl Write, fields: &[(&str, &str)], end: bool) {
    let mut payload = Vec::new();
    for (name, value) in fields {
        assert!(name.len() < 128 && value.len() < 128);
        payload.extend_from_slice(&[0, u8::try_from(name.len()).unwrap()]);
        payload.extend_from_slice(name.as_bytes());
        payload.push(u8::try_from(value.len()).unwrap());
        payload.extend_from_slice(value.as_bytes());
    }
    frame(io, 1, 4 | u8::from(end), 1, &payload);
}

fn response_head(io: &mut impl Write) {
    headers(
        io,
        &[
            (":status", "200"),
            ("content-type", "application/grpc"),
            ("x-setup", "accepted"),
        ],
        false,
    );
}

fn response_body(io: &mut impl Write) {
    // Two independent golden envelopes, not the production encoder.
    frame(
        io,
        0,
        0,
        1,
        &[0, 0, 0, 0, 3, b'o', b'n', b'e', 0, 0, 0, 0, 0],
    );
    headers(io, &[("grpc-status", "0"), ("x-end", "complete")], true);
}

fn request(io: &mut (impl Read + Write)) -> Vec<Header> {
    frame(io, 4, 0, 0, &[]);
    let mut preface = [0; 24];
    io.read_exact(&mut preface).unwrap();
    assert_eq!(&preface, crate::http::h2::connection::CLIENT_PREFACE);
    let mut head = Vec::new();
    let mut body = Vec::new();
    let mut first = true;
    for _ in 0..64 {
        let mut bytes = [0; 9];
        io.read_exact(&mut bytes).unwrap();
        let length =
            (usize::from(bytes[0]) << 16) | (usize::from(bytes[1]) << 8) | usize::from(bytes[2]);
        assert!(length <= 16 * 1024);
        let mut payload = vec![0; length];
        io.read_exact(&mut payload).unwrap();
        let id = u32::from_be_bytes(bytes[5..].try_into().unwrap()) & 0x7fff_ffff;
        if first {
            assert_eq!((bytes[3], id), (4, 0));
            first = false;
        }
        match (bytes[3], id) {
            (1 | 9, 1) => {
                assert!(head.len() + length <= 16 * 1024);
                head.extend_from_slice(&payload);
            }
            (0, 1) => {
                assert!(body.len() + length <= 1024);
                body.extend_from_slice(&payload);
                if bytes[4] & 1 != 0 {
                    assert_eq!(body, b"\x00\x00\x00\x00\x07request");
                    return HpackDecoder::new().decode(&mut Bytes::from(head)).unwrap();
                }
            }
            _ => {}
        }
    }
    panic!("request exceeded fixture frame budget");
}

fn assert_request(fields: &[Header]) {
    for (name, value) in [
        (":scheme", "https"),
        (":authority", "logical.service"),
        (":path", PATH),
        ("authorization", "Bearer fixture-token"),
    ] {
        assert_eq!(
            fields
                .iter()
                .find(|field| field.name == name)
                .map(|field| field.value.as_str()),
            Some(value)
        );
    }
}

#[test]
fn native_tls_endpoint_authenticates_streams_and_retains_metadata() {
    for multithread in [false, true] {
        let (listener, address) = listener();
        let (consumed, consumed_rx) = sync_channel(1);
        let peer = std::thread::spawn(move || {
            let mut socket = server(accept(&listener), true);
            assert_request(&request(&mut socket));
            assert_eq!(socket.conn.alpn_protocol(), Some(b"h2".as_slice()));
            assert_eq!(socket.conn.server_name(), Some("localhost"));
            response_head(&mut socket);
            response_body(&mut socket);
            // Keep unread client control frames from turning teardown into a reset.
            consumed_rx
                .recv_timeout(WATCHDOG)
                .expect("client consumed terminal trailers");
        });
        let done = native(multithread, move |cx| async move {
            let endpoint = endpoint(address, Duration::from_secs(3));
            let connector = connector(true);
            let mut stream = endpoint
                .connect_tls(
                    &cx,
                    "localhost",
                    &connector,
                    PATH,
                    rpc_request(),
                    IdentityCodec,
                    config(),
                )
                .await
                .unwrap();
            assert!(stream.initial_metadata().unwrap().get("x-setup").is_some());
            assert!(stream.status().is_none());
            assert_eq!(stream.message().await.unwrap().unwrap().as_ref(), b"one");
            assert!(stream.message().await.unwrap().unwrap().is_empty());
            assert!(stream.message().await.unwrap().is_none());
            assert_eq!(stream.status().unwrap().code(), Code::Ok);
            assert!(stream.trailers().unwrap().get("x-end").is_some());
            assert!(!cx.is_cancel_requested());
            consumed.send(()).unwrap();
        });
        peer.join().expect("native TLS assertions");
        assert!(done);
    }
}

#[test]
fn native_tls_duplex_hostname_uploads_before_any_response_headers() {
    use super::super::NativeDuplexEvent;
    for multithread in [false, true] {
        let (listener, address) = listener();
        let (consumed, consumed_rx) = sync_channel(1);
        let peer = std::thread::spawn(move || {
            let mut socket = server(accept(&listener), true);
            // request() withholds all response headers until request END_STREAM.
            assert_request(&request(&mut socket));
            assert_eq!(socket.conn.alpn_protocol(), Some(b"h2".as_slice()));
            assert_eq!(socket.conn.server_name(), Some("localhost"));
            response_head(&mut socket);
            response_body(&mut socket);
            consumed_rx
                .recv_timeout(WATCHDOG)
                .expect("duplex consumed terminal trailers");
        });
        let done = native(multithread, move |cx| async move {
            let endpoint = NativeStreamEndpoint::from_host(
                "localhost",
                address.port(),
                "logical.service",
                Duration::from_secs(3),
            )
            .unwrap();
            let connector = connector(true);
            let mut stream = endpoint
                .connect_duplex_tls(
                    &cx,
                    "localhost",
                    &connector,
                    PATH,
                    rpc_request().map(|_| ()),
                    IdentityCodec,
                    config(),
                )
                .await
                .unwrap();
            assert!(
                stream.initial_metadata().is_none(),
                "setup does not consume peer responses"
            );
            assert!(matches!(
                stream.next_event().await.unwrap(),
                Some(NativeDuplexEvent::RequestFlushed)
            ));
            stream
                .queue_message(&Bytes::from_static(b"request"))
                .unwrap();
            assert!(matches!(
                stream.next_event().await.unwrap(),
                Some(NativeDuplexEvent::RequestFlushed)
            ));
            stream.close_requests().unwrap();
            let mut messages = Vec::new();
            while let Some(event) = stream.next_event().await.unwrap() {
                if let NativeDuplexEvent::Message(message) = event {
                    messages.push(message.to_vec());
                }
            }
            assert_eq!(messages, vec![b"one".to_vec(), Vec::new()]);
            assert!(stream.initial_metadata().unwrap().get("x-setup").is_some());
            assert!(stream.trailers().unwrap().get("x-end").is_some());
            assert_eq!(stream.status().unwrap().code(), Code::Ok);
            assert!(!cx.is_cancel_requested());
            consumed.send(()).unwrap();
        });
        peer.join().expect("native TLS duplex assertions");
        assert!(done);
    }
}

#[test]
fn wrong_identity_untrusted_certificate_and_absent_h2_send_no_grpc_bytes() {
    for (name, trusted, h2) in [
        ("wrong.invalid", true, true),
        ("localhost", false, true),
        ("localhost", true, false),
    ] {
        let (listener, address) = listener();
        let peer = std::thread::spawn(move || {
            let mut socket = server(accept(&listener), h2);
            let mut application = [0_u8; 24];
            match socket.read(&mut application) {
                Ok(0) => {}
                Err(error) => assert!(
                    matches!(
                        error.kind(),
                        io::ErrorKind::InvalidData
                            | io::ErrorKind::UnexpectedEof
                            | io::ErrorKind::ConnectionReset
                            | io::ErrorKind::ConnectionAborted
                            | io::ErrorKind::BrokenPipe
                    ),
                    "{error:?}"
                ),
                Ok(n) => panic!("TLS refusal leaked {n} gRPC bytes"),
            }
        });
        let done = native(false, move |cx| async move {
            let endpoint = endpoint(address, Duration::from_secs(3));
            let connector = connector(trusted);
            let result = endpoint
                .connect_tls(
                    &cx,
                    name,
                    &connector,
                    PATH,
                    rpc_request(),
                    IdentityCodec,
                    config(),
                )
                .await;
            assert_eq!(result.unwrap_err().code(), Code::Unavailable);
            assert!(!cx.is_cancel_requested());
        });
        peer.join().unwrap();
        assert!(done, "TLS policy case: {name}, trusted={trusted}, h2={h2}");
    }
}

#[test]
fn duplex_tls_refuses_wrong_identity_untrusted_certificate_and_missing_h2() {
    for (name, trusted, h2) in [
        ("wrong.invalid", true, true),
        ("localhost", false, true),
        ("localhost", true, false),
    ] {
        let (listener, address) = listener();
        let peer = std::thread::spawn(move || {
            let mut socket = server(accept(&listener), h2);
            let mut application = [0_u8; 24];
            match socket.read(&mut application) {
                Ok(0) => {}
                Err(error) => assert!(
                    matches!(
                        error.kind(),
                        io::ErrorKind::InvalidData
                            | io::ErrorKind::UnexpectedEof
                            | io::ErrorKind::ConnectionReset
                            | io::ErrorKind::ConnectionAborted
                            | io::ErrorKind::BrokenPipe
                    ),
                    "{error:?}"
                ),
                Ok(n) => panic!("duplex TLS refusal leaked {n} gRPC bytes"),
            }
        });
        let done = native(false, move |cx| async move {
            let endpoint = endpoint(address, Duration::from_secs(3));
            let connector = connector(trusted);
            let result = endpoint
                .connect_duplex_tls(
                    &cx,
                    name,
                    &connector,
                    PATH,
                    rpc_request().map(|_| ()),
                    IdentityCodec,
                    config(),
                )
                .await;
            assert_eq!(result.unwrap_err().code(), Code::Unavailable);
            assert!(!cx.is_cancel_requested());
        });
        peer.join().unwrap();
        assert!(
            done,
            "duplex TLS policy case: {name}, trusted={trusted}, h2={h2}"
        );
    }
}

#[test]
fn tls_setup_rejects_invalid_inputs_without_dialing_or_borrowing_ambient_authority() {
    let (listener, address) = listener();
    let done = native(false, move |cx| async move {
        let endpoint = endpoint(address, Duration::from_secs(1));
        let connector = connector(true);
        let wrong_scheme = endpoint
            .connect_tls(
                &cx,
                "localhost",
                &connector,
                PATH,
                rpc_request(),
                IdentityCodec,
                NativeStreamConfig::default(),
            )
            .await;
        assert_eq!(wrong_scheme.unwrap_err().code(), Code::InvalidArgument);
        let bad_name = endpoint
            .connect_tls(
                &cx,
                "not a domain",
                &connector,
                PATH,
                rpc_request(),
                IdentityCodec,
                config(),
            )
            .await;
        assert_eq!(bad_name.unwrap_err().code(), Code::InvalidArgument);
        let mut forged = rpc_request();
        assert!(forged.metadata_mut().insert("content-type", "text/plain"));
        let bad_metadata = endpoint
            .connect_tls(
                &cx,
                "localhost",
                &connector,
                PATH,
                forged,
                IdentityCodec,
                config(),
            )
            .await;
        assert_eq!(bad_metadata.unwrap_err().code(), Code::InvalidArgument);
        let detached = Cx::for_testing();
        let no_authority = endpoint
            .connect_tls(
                &detached,
                "localhost",
                &connector,
                PATH,
                rpc_request(),
                IdentityCodec,
                config(),
            )
            .await;
        assert_eq!(no_authority.unwrap_err().code(), Code::FailedPrecondition);
        assert!(
            matches!(listener.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock)
        );
        assert!(!cx.is_cancel_requested());
    });
    assert!(done);
}

#[test]
fn successful_tls_setup_does_not_limit_the_lifetime_of_an_unbounded_stream() {
    let (listener, address) = listener();
    let (release, released) = sync_channel(1);
    let (consumed, consumed_rx) = sync_channel(1);
    let peer = std::thread::spawn(move || {
        let mut socket = server(accept(&listener), true);
        assert_request(&request(&mut socket));
        response_head(&mut socket);
        released.recv_timeout(WATCHDOG).unwrap();
        response_body(&mut socket);
        // Keep unread client control frames from turning teardown into a reset.
        consumed_rx
            .recv_timeout(WATCHDOG)
            .expect("client consumed terminal trailers");
    });
    let done = native(false, move |cx| async move {
        let clock = cx.timer_driver().unwrap();
        let started = clock.now();
        let endpoint = endpoint(address, Duration::from_secs(2));
        let connector = connector(true);
        let mut stream = endpoint
            .connect_tls(
                &cx,
                "localhost",
                &connector,
                PATH,
                rpc_request(),
                IdentityCodec,
                config(),
            )
            .await
            .unwrap();
        assert!(stream.deadline.is_none());
        // Wait for the exact observed setup interval, not to infer parking.
        Sleep::with_timer_driver(started + Duration::from_millis(2100), clock).await;
        release.send(()).unwrap();
        assert_eq!(stream.message().await.unwrap().unwrap().as_ref(), b"one");
        assert!(stream.message().await.unwrap().unwrap().is_empty());
        assert!(stream.message().await.unwrap().is_none());
        assert_eq!(stream.status().unwrap().code(), Code::Ok);
        consumed.send(()).unwrap();
    });
    peer.join().unwrap();
    assert!(done);
}

#[derive(Default)]
struct HandshakeWitness {
    received: AtomicBool,
    waiter: Mutex<Option<Waker>>,
}

impl HandshakeWitness {
    fn publish(&self) {
        self.received.store(true, Ordering::Release);
        let wake = self.waiter.lock().unwrap().take();
        if let Some(wake) = wake {
            wake.wake();
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Interrupt {
    Cancel,
    Drop,
    Deadline,
}

#[test]
fn parked_native_tls_handshake_cancel_drop_and_deadline_close_the_socket() {
    for multithread in [false, true] {
        for mode in [Interrupt::Cancel, Interrupt::Drop, Interrupt::Deadline] {
            let (listener, address) = listener();
            let witness = Arc::new(HandshakeWitness::default());
            let observed = Arc::clone(&witness);
            let (parked, parks): (SyncSender<Cx>, Receiver<Cx>) = sync_channel(1);
            let peer = std::thread::spawn(move || {
                let mut socket = accept(&listener);
                let mut record = [0; 5];
                socket.read_exact(&mut record).unwrap();
                assert_eq!(record[0], 22, "TLS handshake record, not plaintext gRPC");
                let length = usize::from(u16::from_be_bytes([record[3], record[4]]));
                assert!((4..=18_432).contains(&length));
                let mut hello = vec![0; length];
                socket.read_exact(&mut hello).unwrap();
                assert_eq!(hello[0], 1, "ClientHello handshake type");
                observed.publish();
                let cx = parks
                    .recv_timeout(WATCHDOG)
                    .expect("public setup returned Pending after ClientHello");
                if matches!(mode, Interrupt::Cancel) {
                    cx.cancel_with(CancelKind::User, Some("native TLS setup cancellation"));
                }
                let mut bytes = [0; 1024];
                let mut remaining: usize = 64 * 1024;
                loop {
                    let read = socket
                        .read(&mut bytes)
                        .expect("TLS setup should close its acquired socket");
                    if read == 0 {
                        break;
                    }
                    remaining = remaining
                        .checked_sub(read)
                        .expect("unexpected retained TLS output");
                }
            });
            let done = native(multithread, move |cx| async move {
                let endpoint = endpoint(address, Duration::from_secs(2));
                let connector = connector(true);
                let mut setup = Box::pin(endpoint.connect_tls(
                    &cx,
                    "localhost",
                    &connector,
                    PATH,
                    rpc_request(),
                    IdentityCodec,
                    config(),
                ));
                let mut notified = false;
                let result = poll_fn(|task| {
                    *witness.waiter.lock().unwrap() = Some(task.waker().clone());
                    match setup.as_mut().poll(task) {
                        Poll::Ready(result) => Poll::Ready(Some(result)),
                        Poll::Pending => {
                            if witness.received.load(Ordering::Acquire) && !notified {
                                notified = true;
                                parked.try_send(cx.clone()).unwrap();
                                if matches!(mode, Interrupt::Drop) {
                                    return Poll::Ready(None);
                                }
                            }
                            Poll::Pending
                        }
                    }
                })
                .await;
                drop(setup);
                assert!(notified, "never witnessed handshake Pending: {mode:?}");
                match mode {
                    Interrupt::Drop => assert!(result.is_none()),
                    Interrupt::Cancel => {
                        assert_eq!(result.unwrap().unwrap_err().code(), Code::Cancelled);
                        assert_eq!(cx.cancel_reason().unwrap().kind, CancelKind::User);
                    }
                    Interrupt::Deadline => {
                        assert_eq!(result.unwrap().unwrap_err().code(), Code::DeadlineExceeded)
                    }
                }
                if !matches!(mode, Interrupt::Cancel) {
                    assert!(!cx.is_cancel_requested());
                }
            });
            peer.join().expect("handshake transport retirement");
            assert!(done, "native TLS interruption failed: {mode:?}");
        }
    }
}
