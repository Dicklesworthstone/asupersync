//! Explicit-context handshake cancellation at public client/server boundaries.

#![allow(clippy::pedantic, clippy::nursery)]

use super::*;
use crate::net::tcp::VirtualTcpStream;
use crate::tls::{Certificate, CertificateChain, CertificatePin, CertificatePinSet, PrivateKey};
use crate::types::CancelKind;
use rustls::{ClientConfig, ServerConfig};
use std::future::{Future, poll_fn};
use std::pin::{Pin, pin};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Wake, Waker};

const CERT: &[u8] = include_bytes!("../../tests/fixtures/tls/server.crt");
const KEY: &[u8] = include_bytes!("../../tests/fixtures/tls/server.key");

fn endpoints(version: &'static rustls::SupportedProtocolVersion) -> (TlsConnector, TlsAcceptor) {
    let chain = CertificateChain::from_pem(CERT).unwrap().into_inner();
    let key = PrivateKey::from_pem(KEY).unwrap().clone_inner();
    let mut roots = rustls::RootCertStore::empty();
    for cert in &chain {
        roots.add(cert.clone()).unwrap();
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut client = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[version])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let mut server = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[version])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap();
    client.alpn_protocols = vec![b"xmpp-client".to_vec()];
    server.alpn_protocols = client.alpn_protocols.clone();
    (TlsConnector::new(client), TlsAcceptor::new(server))
}

#[derive(Default, Debug)]
struct Probe {
    calls: AtomicUsize,
    written: AtomicUsize,
    parked: AtomicBool,
    dropped: AtomicUsize,
    release: AtomicBool,
    waker: std::sync::Mutex<Option<Waker>>,
}

impl Probe {
    fn park(&self, task: &Context<'_>) -> Poll<io::Result<()>> {
        if self.release.load(Ordering::Acquire) {
            return Poll::Ready(Err(io::ErrorKind::ConnectionAborted.into()));
        }
        *self.waker.lock().unwrap() = Some(task.waker().clone());
        self.parked.store(true, Ordering::Release);
        Poll::Pending
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn rescue(&self) {
        self.release.store(true, Ordering::Release);
        let waker = self.waker.lock().unwrap().take();
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

// This explicit transport double accepts real rustls handshake output but
// never supplies input or unsolicited wakeups. Its parked state is witnessed.
#[derive(Debug)]
struct ParkedIo {
    probe: Arc<Probe>,
    block_flush: bool,
}

impl AsyncRead for ParkedIo {
    fn poll_read(
        self: Pin<&mut Self>,
        task: &mut Context<'_>,
        _: &mut crate::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.probe.calls.fetch_add(1, Ordering::SeqCst);
        self.probe.park(task)
    }
}

impl AsyncWrite for ParkedIo {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.probe.calls.fetch_add(1, Ordering::SeqCst);
        self.probe.written.fetch_add(bytes.len(), Ordering::SeqCst);
        Poll::Ready(Ok(bytes.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.probe.calls.fetch_add(1, Ordering::SeqCst);
        if self.block_flush {
            self.probe.park(task)
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        panic!("a cancelled handshake must drop, not gracefully flush, its transport")
    }
}

impl Drop for ParkedIo {
    fn drop(&mut self) {
        self.probe.dropped.fetch_add(1, Ordering::SeqCst);
        self.probe.waker.lock().unwrap().take();
    }
}

type ParkedHandshake<'a> =
    Pin<Box<dyn Future<Output = Result<TlsStream<ParkedIo>, TlsError>> + Send + 'a>>;

fn begin<'a>(
    client: bool,
    cx: &'a Cx,
    connector: &'a TlsConnector,
    acceptor: &'a TlsAcceptor,
    probe: &Arc<Probe>,
    block_flush: bool,
) -> ParkedHandshake<'a> {
    let io = ParkedIo {
        probe: Arc::clone(probe),
        block_flush,
    };
    if client {
        Box::pin(connector.connect_with_cx(cx, "localhost", io))
    } else {
        Box::pin(acceptor.accept_with_cx(cx, io))
    }
}

fn assert_cancelled<T>(result: Poll<Result<T, TlsError>>) {
    match result {
        Poll::Ready(Err(TlsError::Io(error))) => {
            assert_eq!(error.kind(), io::ErrorKind::Interrupted);
            assert_eq!(error.to_string(), "TLS handshake cancelled");
        }
        _ => panic!("handshake must return its typed cancellation error"),
    }
}

#[derive(Default)]
struct WakeCount(AtomicUsize);

impl Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn pre_cancelled_handshakes_never_poll_the_transport() {
    let (connector, acceptor) = endpoints(&rustls::version::TLS13);
    for client in [true, false] {
        let cx = Cx::for_testing();
        let probe = Arc::new(Probe::default());
        let mut wait = begin(client, &cx, &connector, &acceptor, &probe, false);
        assert_eq!(probe.calls.load(Ordering::SeqCst), 0);
        cx.cancel_fast(CancelKind::User);
        assert_cancelled(wait.as_mut().poll(&mut Context::from_waker(Waker::noop())));
        assert_eq!(probe.calls.load(Ordering::SeqCst), 0);
        assert_eq!(probe.dropped.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn parked_handshakes_wake_on_cancellation_without_an_io_event() {
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        let (connector, acceptor) = endpoints(version);
        for client in [true, false] {
            for block_flush in [true, false] {
                let cx = Cx::for_testing();
                let probe = Arc::new(Probe::default());
                let mut wait = begin(client, &cx, &connector, &acceptor, &probe, block_flush);
                let old = Arc::new(WakeCount::default());
                let new = Arc::new(WakeCount::default());
                let old_waker = Waker::from(Arc::clone(&old));
                let new_waker = Waker::from(Arc::clone(&new));
                assert!(wait.as_mut().poll(&mut Context::from_waker(&old_waker)).is_pending());
                assert!(probe.parked.load(Ordering::Acquire));
                if client {
                    assert!(probe.written.load(Ordering::SeqCst) > 0);
                }
                assert!(wait.as_mut().poll(&mut Context::from_waker(&new_waker)).is_pending());
                let calls = probe.calls.load(Ordering::SeqCst);
                cx.cancel_fast(CancelKind::User);
                // Witness notification before repolling; the transport did not
                // supply any data, timer or readiness wake to make this happen.
                assert_eq!(old.0.load(Ordering::SeqCst), 0);
                assert!(new.0.load(Ordering::SeqCst) > 0);
                assert_cancelled(wait.as_mut().poll(&mut Context::from_waker(&new_waker)));
                assert_eq!(probe.calls.load(Ordering::SeqCst), calls);
                assert_eq!(probe.dropped.load(Ordering::SeqCst), 1);
            }
        }
    }
}

#[test]
fn abandoning_a_handshake_retires_its_cancellation_observer() {
    let (connector, acceptor) = endpoints(&rustls::version::TLS13);
    for client in [true, false] {
        let cx = Cx::for_testing();
        let probe = Arc::new(Probe::default());
        let count = Arc::new(WakeCount::default());
        let waker = Waker::from(Arc::clone(&count));
        let mut wait = begin(client, &cx, &connector, &acceptor, &probe, false);
        assert!(wait.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());
        drop(wait);
        assert_eq!(probe.dropped.load(Ordering::SeqCst), 1);
        assert!(probe.waker.lock().unwrap().is_none());
        cx.cancel_fast(CancelKind::User);
        assert_eq!(count.0.load(Ordering::SeqCst), 0, "dropped wait kept a registration");
    }
}

#[test]
fn masked_requests_do_not_spin_or_bypass_the_checkpoint() {
    let (connector, acceptor) = endpoints(&rustls::version::TLS13);
    for client in [true, false] {
        let cx = Cx::for_testing();
        cx.cancel_fast(CancelKind::User);
        let probe = Arc::new(Probe::default());
        let count = Arc::new(WakeCount::default());
        let waker = Waker::from(Arc::clone(&count));
        let mut wait = begin(client, &cx, &connector, &acceptor, &probe, false);
        cx.masked(|| {
            for _ in 0..3 {
                assert!(wait.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());
            }
        });
        assert!(probe.parked.load(Ordering::Acquire));
        assert_eq!(count.0.load(Ordering::SeqCst), 0);
        assert_eq!(probe.dropped.load(Ordering::SeqCst), 0);
        assert_cancelled(wait.as_mut().poll(&mut Context::from_waker(&waker)));
        assert_eq!(probe.dropped.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn restricted_resume_cannot_borrow_the_handshake_owners_authority() {
    let (connector, acceptor) = endpoints(&rustls::version::TLS13);
    for client in [true, false] {
        let owner = Cx::for_testing();
        let probe = Arc::new(Probe::default());
        let mut wait = begin(client, &owner, &connector, &acceptor, &probe, false);
        assert!(wait.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
        let calls = probe.calls.load(Ordering::SeqCst);
        let restricted = Cx::detached_cancel_context();
        let result = futures_lite::future::block_on(
            restricted.with_ambient(poll_fn(|task| wait.as_mut().poll(task))),
        );
        assert!(matches!(result, Err(TlsError::Io(error))
            if error.kind() == io::ErrorKind::PermissionDenied));
        assert_eq!(probe.calls.load(Ordering::SeqCst), calls);
        assert_eq!(probe.dropped.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn cancellation_during_completion_discards_success_but_preserves_tls_errors() {
    struct Value(Arc<AtomicUsize>);
    impl Drop for Value {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    let cx = Cx::for_testing();
    let drops = Arc::new(AtomicUsize::new(0));
    let value = Value(Arc::clone(&drops));
    let result = futures_lite::future::block_on(with_cancellation(&cx, async {
        cx.cancel_fast(CancelKind::User);
        Ok(value)
    }));
    assert_cancelled(Poll::Ready(result));
    assert_eq!(drops.load(Ordering::SeqCst), 1);

    let cx = Cx::for_testing();
    let result = futures_lite::future::block_on(with_cancellation::<()>(&cx, async {
        cx.cancel_fast(CancelKind::User);
        Err(TlsError::Certificate("original verification failure".into()))
    }));
    assert!(matches!(result, Err(TlsError::Certificate(message))
        if message == "original verification failure"));
}

#[test]
fn context_handshakes_keep_protocol_alpn_pinning_and_exporter_checks() {
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        for pin_matches in [true, false] {
            let (connector, acceptor) = endpoints(version);
            let certificates = Certificate::from_pem(CERT).unwrap();
            let pin = CertificatePin::compute_cert_sha256(&certificates[0]).unwrap();
            let pin = if pin_matches {
                pin
            } else {
                let mut hash = pin.hash_bytes().to_vec();
                hash[0] ^= 1;
                CertificatePin::CertSha256(hash)
            };
            let connector = connector.with_pin_set(CertificatePinSet::new().with_pin(pin));
            let (client_io, server_io) = VirtualTcpStream::pair(
                "127.0.0.1:5300".parse().unwrap(),
                "127.0.0.1:5301".parse().unwrap(),
            );
            let client_cx = Cx::for_testing();
            let server_cx = Cx::for_testing();
            let mut client = pin!(connector.connect_with_cx(&client_cx, "localhost", client_io));
            let mut server = pin!(acceptor.accept_with_cx(&server_cx, server_io));
            let mut c = None;
            let mut s = None;
            let mut task = Context::from_waker(Waker::noop());
            // Keep completed streams alive while the other endpoint finishes.
            // A failed pin can close TCP before the server sends its tickets.
            for _ in 0..128 {
                if c.is_none() && let Poll::Ready(result) = client.as_mut().poll(&mut task) {
                    c = Some(result);
                }
                if s.is_none() && let Poll::Ready(result) = server.as_mut().poll(&mut task) {
                    s = Some(result);
                }
                if c.is_some() && s.is_some() {
                    break;
                }
            }
            let c = c.expect("client handshake must finish");
            let s = s.expect("server handshake must finish or observe rejection");
            if !pin_matches {
                assert!(matches!(c, Err(TlsError::PinMismatch { .. })));
                continue;
            }
            let c = c.expect("correctly pinned client handshake");
            let s = s.expect("server handshake");
            for stream in [&c, &s] {
                assert!(stream.is_ready());
                assert_eq!(stream.protocol_version(), Some(version.version));
                assert_eq!(stream.alpn_protocol(), Some(b"xmpp-client".as_slice()));
            }
            if version.version == rustls::ProtocolVersion::TLSv1_3 {
                assert_eq!(
                    c.tls_exporter_channel_binding().unwrap(),
                    s.tls_exporter_channel_binding().unwrap()
                );
            } else {
                for stream in [&c, &s] {
                    assert!(matches!(
                        stream.tls_exporter_channel_binding(),
                        Err(TlsError::Configuration(_))
                    ));
                }
            }
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn native_abort_joins_a_parked_handshake_with_its_typed_error() {
    use crate::runtime::{RuntimeBuilder, reactor::create_reactor, yield_now};
    use std::time::Duration;

    let runtime = RuntimeBuilder::current_thread()
        .with_reactor(create_reactor().unwrap())
        .build()
        .unwrap();
    runtime.block_on(runtime.handle().spawn(async {
        let parent = Cx::current().expect("native task context");
        for client in [true, false] {
            let (connector, acceptor) = endpoints(&rustls::version::TLS13);
            let probe = Arc::new(Probe::default());
            let child_probe = Arc::clone(&probe);
            let mut child = parent
                .spawn(move |child_cx| async move {
                    begin(client, &child_cx, &connector, &acceptor, &child_probe, false)
                        .await
                        .map(|_| ())
                })
                .unwrap();
            for _ in 0..1024 {
                if probe.parked.load(Ordering::Acquire) {
                    break;
                }
                yield_now().await;
            }
            assert!(probe.parked.load(Ordering::Acquire), "must witness actual Pending");
            let calls = probe.calls.load(Ordering::SeqCst);
            child.abort();
            let result = crate::time::timeout(
                parent.now(),
                Duration::from_secs(2),
                child.join(&parent),
            )
            .await;
            if result.is_err() {
                // A regressed wrapper must not strand the native test forever.
                probe.rescue();
                let _ = crate::time::timeout(
                    parent.now(),
                    Duration::from_secs(2),
                    child.join(&parent),
                )
                .await;
                panic!("abort did not finish without a transport readiness event");
            }
            assert!(matches!(result, Ok(Ok(Err(TlsError::Io(error))))
                if error.kind() == io::ErrorKind::Interrupted));
            assert_eq!(probe.calls.load(Ordering::SeqCst), calls);
            assert_eq!(probe.dropped.load(Ordering::SeqCst), 1);
        }
    }));
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn context_connector_preserves_its_configured_handshake_timeout() {
    use crate::runtime::{RuntimeBuilder, reactor::create_reactor};
    use std::time::Duration;

    let runtime = RuntimeBuilder::current_thread()
        .with_reactor(create_reactor().unwrap())
        .build()
        .unwrap();
    runtime.block_on(runtime.handle().spawn(async {
        let cx = Cx::current().expect("native task context");
        let (connector, _) = endpoints(&rustls::version::TLS13);
        let duration = Duration::from_millis(10);
        let connector = connector.with_handshake_timeout(duration);
        let probe = Arc::new(Probe::default());
        let result = crate::time::timeout(
            cx.now(),
            Duration::from_secs(2),
            connector.connect_with_cx(
                &cx,
                "localhost",
                ParkedIo {
                    probe: Arc::clone(&probe),
                    block_flush: false,
                },
            ),
        )
        .await;
        assert!(matches!(result, Ok(Err(TlsError::Timeout(actual))) if actual == duration));
        assert!(probe.parked.load(Ordering::Acquire));
        assert_eq!(probe.dropped.load(Ordering::SeqCst), 1);
    }));
}
