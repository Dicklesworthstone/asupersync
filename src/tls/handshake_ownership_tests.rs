//! Transport destruction must use the handshake owner even without a first poll.
//!
//! The transport is an explicit test double. These tests exercise ownership and
//! ambient authority, not successful TLS negotiation or certificate validation.

#![allow(clippy::pedantic, clippy::nursery)]

use super::*;
use crate::io::ReadBuf;
use crate::tls::{CertificateChain, PrivateKey};
use crate::types::CancelKind;
use rustls::{ClientConfig, ServerConfig};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Waker};

const CERT: &[u8] = include_bytes!("../../tests/fixtures/tls/server.crt");
const KEY: &[u8] = include_bytes!("../../tests/fixtures/tls/server.key");

fn endpoints(version: &'static rustls::SupportedProtocolVersion) -> (TlsConnector, TlsAcceptor) {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let client = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[version])
        .unwrap()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    let chain = CertificateChain::from_pem(CERT).unwrap().into_inner();
    let key = PrivateKey::from_pem(KEY).unwrap().clone_inner();
    let server = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[version])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap();
    (TlsConnector::new(client), TlsAcceptor::new(server))
}

fn context(allow_io: bool) -> Cx {
    if allow_io {
        Cx::for_testing()
    } else {
        // current() returns the erased context while preserving its effective
        // runtime capability mask. Do not reach into private Cx fields.
        let restricted = Cx::detached_cancel_context();
        futures_lite::future::block_on(restricted.with_ambient(async {
            Cx::current().expect("restricted ambient context")
        }))
    }
}

#[derive(Default)]
struct Probe {
    polls: AtomicUsize,
    parked: AtomicBool,
    drops: AtomicUsize,
    drop_has_context: AtomicBool,
    drop_allows_io: AtomicBool,
    drop_observed_cancel: AtomicBool,
}

struct OwnershipIo(Arc<Probe>);

impl AsyncRead for OwnershipIo {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.0.polls.fetch_add(1, Ordering::SeqCst);
        self.0.parked.store(true, Ordering::SeqCst);
        // Deliberately never produces input or unsolicited readiness events.
        Poll::Pending
    }
}

impl AsyncWrite for OwnershipIo {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.0.polls.fetch_add(1, Ordering::SeqCst);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.0.polls.fetch_add(1, Ordering::SeqCst);
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        panic!("abandoning a handshake must drop rather than flush its transport")
    }
}

impl Drop for OwnershipIo {
    fn drop(&mut self) {
        self.0.drop_has_context.store(Cx::current().is_some(), Ordering::SeqCst);
        self.0.drop_allows_io.store(
            require_ambient_io("tls::ownership-test").is_ok(),
            Ordering::SeqCst,
        );
        self.0.drop_observed_cancel.store(
            Cx::with_current(|cx| cx.is_cancel_requested()).unwrap_or(false),
            Ordering::SeqCst,
        );
        self.0.drops.fetch_add(1, Ordering::SeqCst);
    }
}

type Wait<'a> =
    Pin<Box<dyn Future<Output = Result<TlsStream<OwnershipIo>, TlsError>> + Send + 'a>>;

fn begin<'a>(
    client: bool,
    owner: &'a Cx,
    connector: &'a TlsConnector,
    acceptor: &'a TlsAcceptor,
    probe: &Arc<Probe>,
) -> Wait<'a> {
    let io = OwnershipIo(Arc::clone(probe));
    if client {
        Box::pin(connector.connect_with_cx(owner, "localhost", io))
    } else {
        Box::pin(acceptor.accept_with_cx(owner, io))
    }
}

fn assert_cleanup(probe: &Probe, allow_io: bool, cancelled: bool) {
    assert_eq!(probe.drops.load(Ordering::SeqCst), 1);
    assert!(probe.drop_has_context.load(Ordering::SeqCst));
    assert_eq!(probe.drop_allows_io.load(Ordering::SeqCst), allow_io);
    assert_eq!(probe.drop_observed_cancel.load(Ordering::SeqCst), cancelled);
}

#[test]
fn unpolled_public_handshakes_drop_under_the_supplied_context() {
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        let (connector, acceptor) = endpoints(version);
        for client in [true, false] {
            for owner_allows_io in [true, false] {
                let owner = context(owner_allows_io);
                let caller = context(!owner_allows_io);
                owner.cancel_fast(CancelKind::User);
                let probe = Arc::new(Probe::default());
                futures_lite::future::block_on(caller.with_ambient(async {
                    let before = require_ambient_io("tls::caller").is_ok();
                    assert_eq!(before, !owner_allows_io);
                    let wait = begin(client, &owner, &connector, &acceptor, &probe);
                    // Construction may capture ownership, but must not perform
                    // TLS IO, acknowledge cancellation, or install an ambient guard.
                    assert_eq!(probe.polls.load(Ordering::SeqCst), 0);
                    assert_eq!(probe.drops.load(Ordering::SeqCst), 0);
                    assert_eq!(require_ambient_io("tls::caller").is_ok(), before);
                    assert!(!Cx::with_current(|cx| cx.is_cancel_requested()).unwrap());
                    drop(wait); // Intentionally no Future::poll call.
                    assert_cleanup(&probe, owner_allows_io, true);
                    assert_eq!(require_ambient_io("tls::caller").is_ok(), before);
                    assert!(!Cx::with_current(|cx| cx.is_cancel_requested()).unwrap());
                }));
                assert_eq!(probe.polls.load(Ordering::SeqCst), 0);
            }
        }
    }
}

#[test]
fn first_poll_refusal_drops_before_return_without_transport_io() {
    let (connector, acceptor) = endpoints(&rustls::version::TLS13);
    for client in [true, false] {
        for pre_cancelled in [true, false] {
            let owner = context(pre_cancelled);
            if pre_cancelled {
                owner.cancel_fast(CancelKind::User);
            }
            let caller = context(true);
            let probe = Arc::new(Probe::default());
            let mut wait = begin(client, &owner, &connector, &acceptor, &probe);
            let result = futures_lite::future::block_on(caller.with_ambient(poll_fn(|task| {
                wait.as_mut().poll(task)
            })));
            let expected = if pre_cancelled {
                io::ErrorKind::Interrupted
            } else {
                io::ErrorKind::PermissionDenied
            };
            assert!(matches!(result, Err(TlsError::Io(error)) if error.kind() == expected));
            // Keep the completed wrapper alive: transport cleanup must already
            // have happened, not depend on the caller dropping that wrapper.
            assert_cleanup(&probe, pre_cancelled, pre_cancelled);
            assert_eq!(probe.polls.load(Ordering::SeqCst), 0);
            drop(wait);
            assert_cleanup(&probe, pre_cancelled, pre_cancelled);
        }
    }
}

#[test]
fn dropping_a_parked_handshake_uses_owner_not_restricted_dropper() {
    let (connector, acceptor) = endpoints(&rustls::version::TLS13);
    for client in [true, false] {
        let owner = context(true);
        let probe = Arc::new(Probe::default());
        let mut wait = begin(client, &owner, &connector, &acceptor, &probe);
        assert!(wait.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
        assert!(probe.parked.load(Ordering::SeqCst));
        let polls = probe.polls.load(Ordering::SeqCst);
        owner.cancel_fast(CancelKind::User);
        let caller = context(false);
        futures_lite::future::block_on(caller.with_ambient(async {
            drop(wait);
            assert_cleanup(&probe, true, true);
            assert!(require_ambient_io("tls::caller").is_err());
            assert!(!Cx::with_current(|cx| cx.is_cancel_requested()).unwrap());
        }));
        assert_eq!(probe.polls.load(Ordering::SeqCst), polls);
    }
}

#[test]
fn unwinding_an_unpolled_handshake_keeps_owner_and_restores_caller() {
    let (connector, acceptor) = endpoints(&rustls::version::TLS13);
    for client in [true, false] {
        for owner_allows_io in [true, false] {
            let owner = context(owner_allows_io);
            owner.cancel_fast(CancelKind::User);
            let caller = context(!owner_allows_io);
            let probe = Arc::new(Probe::default());
            futures_lite::future::block_on(caller.with_ambient(async {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let _wait = begin(client, &owner, &connector, &acceptor, &probe);
                    panic!("exercise drop during caller unwind");
                }));
                assert!(result.is_err());
                assert_cleanup(&probe, owner_allows_io, true);
                assert_eq!(require_ambient_io("tls::caller").is_ok(), !owner_allows_io);
                assert!(!Cx::with_current(|cx| cx.is_cancel_requested()).unwrap());
            }));
            assert_eq!(probe.polls.load(Ordering::SeqCst), 0);
        }
    }
}
