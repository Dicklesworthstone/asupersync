//! Real rustls handshakes over an in-memory transport with bounded polling.

#![allow(clippy::pedantic, clippy::nursery)]

use super::TlsError;
use super::super::{TlsConnection, TlsStream};
use crate::io::{AsyncRead, AsyncWrite, ReadBuf};
use crate::tls::{CertificateChain, PrivateKey};
use rustls::pki_types::ServerName;
use rustls::{CipherSuite, ClientConfig, ClientConnection, ServerConfig, ServerConnection};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

const CERT_PEM: &[u8] = include_bytes!("../../../tests/fixtures/tls/server.crt");
const KEY_PEM: &[u8] = include_bytes!("../../../tests/fixtures/tls/server.key");

#[derive(Default)]
struct MemoryIo {
    incoming: Rc<RefCell<VecDeque<u8>>>,
    outgoing: Rc<RefCell<VecDeque<u8>>>,
    block_flush: bool,
}

impl AsyncRead for MemoryIo {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let mut incoming = self.incoming.borrow_mut();
        if incoming.is_empty() {
            // The test driver polls both endpoints explicitly with a step
            // limit; this transport is not used with an executor.
            return Poll::Pending;
        }
        let len = incoming.len().min(buf.remaining());
        for byte in incoming.drain(..len) {
            buf.put_slice(&[byte]);
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for MemoryIo {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.outgoing.borrow_mut().extend(buf.iter().copied());
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.block_flush {
            Poll::Pending
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn configs(
    versions: &[&'static rustls::SupportedProtocolVersion],
    suite: Option<CipherSuite>,
    trust_server: bool,
) -> (Arc<ClientConfig>, Arc<ServerConfig>) {
    let chain = CertificateChain::from_pem(CERT_PEM).unwrap().into_inner();
    let key = PrivateKey::from_pem(KEY_PEM).unwrap().clone_inner();
    let mut roots = rustls::RootCertStore::empty();
    if trust_server {
        for cert in &chain {
            roots.add(cert.clone()).unwrap();
        }
    }
    // Explicit providers avoid process-global installation and test races.
    let mut provider = rustls::crypto::ring::default_provider();
    if let Some(suite) = suite {
        provider.cipher_suites.retain(|s| s.suite() == suite);
        assert!(!provider.cipher_suites.is_empty());
    }
    let provider = Arc::new(provider);
    let client = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(versions)
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap();
    (Arc::new(client), Arc::new(server))
}

fn streams(
    client_config: &Arc<ClientConfig>,
    server_config: &Arc<ServerConfig>,
) -> (TlsStream<MemoryIo>, TlsStream<MemoryIo>) {
    let client_io = MemoryIo::default();
    let server_io = MemoryIo {
        incoming: Rc::clone(&client_io.outgoing),
        outgoing: Rc::clone(&client_io.incoming),
        block_flush: false,
    };
    let client = ClientConnection::new(
        Arc::clone(client_config),
        ServerName::try_from("localhost").unwrap(),
    )
    .unwrap();
    let server = ServerConnection::new(Arc::clone(server_config)).unwrap();
    (
        TlsStream::new_client(client_io, client),
        TlsStream::new_server(server_io, server),
    )
}

fn handshake(
    client: &mut TlsStream<MemoryIo>,
    server: &mut TlsStream<MemoryIo>,
) -> (Result<(), TlsError>, Result<(), TlsError>) {
    let mut cx = Context::from_waker(Waker::noop());
    let mut client_result = None;
    let mut server_result = None;
    for _ in 0..128 {
        if client_result.is_none()
            && let Poll::Ready(result) = client.poll_handshake(&mut cx)
        {
            client_result = Some(result);
        }
        if server_result.is_none()
            && let Poll::Ready(result) = server.poll_handshake(&mut cx)
        {
            server_result = Some(result);
        }
        if client_result.is_some() && server_result.is_some() {
            return (client_result.unwrap(), server_result.unwrap());
        }
    }
    panic!("TLS handshake exceeded the in-memory transport's step limit");
}

fn establish(client: &mut TlsStream<MemoryIo>, server: &mut TlsStream<MemoryIo>) {
    let (client_result, server_result) = handshake(client, server);
    client_result.expect("client handshake");
    server_result.expect("server handshake");
    assert!(client.is_ready() && server.is_ready());
}

fn assert_incomplete(stream: &TlsStream<MemoryIo>) {
    assert!(matches!(
        stream.tls_exporter_channel_binding(),
        Err(TlsError::Rustls(rustls::Error::HandshakeNotComplete))
    ));
}

fn assert_disconnected(stream: &TlsStream<MemoryIo>) {
    assert!(matches!(
        stream.tls_exporter_channel_binding(),
        Err(TlsError::Io(err)) if err.kind() == io::ErrorKind::NotConnected
    ));
}

/// Independent calls to the rustls public exporter, with RFC inputs spelled
/// out rather than shared with the wrapper. Agreement alone would not catch
/// both wrappers using the same wrong label, context, or output length.
fn reference_binding(stream: &TlsStream<MemoryIo>) -> [u8; 32] {
    match &stream.conn {
        TlsConnection::Client(conn) => conn
            .export_keying_material([0; 32], b"EXPORTER-Channel-Binding", Some(&[]))
            .unwrap(),
        TlsConnection::Server(conn) => conn
            .export_keying_material([0; 32], b"EXPORTER-Channel-Binding", Some(&[]))
            .unwrap(),
    }
}

fn send_and_read(sender: &mut TlsStream<MemoryIo>, receiver: &mut TlsStream<MemoryIo>) {
    let mut cx = Context::from_waker(Waker::noop());
    let message = b"application data after exporter";
    assert!(matches!(
        Pin::new(&mut *sender).poll_write(&mut cx, message),
        Poll::Ready(Ok(len)) if len == message.len()
    ));
    assert!(matches!(
        Pin::new(sender).poll_flush(&mut cx),
        Poll::Ready(Ok(()))
    ));
    let mut bytes = [0; 64];
    let mut buf = ReadBuf::new(&mut bytes);
    assert!(matches!(
        Pin::new(receiver).poll_read(&mut cx, &mut buf),
        Poll::Ready(Ok(()))
    ));
    assert_eq!(buf.filled(), message);
}

#[test]
fn tls13_exporter_agrees_with_both_endpoints_and_rustls_for_each_ring_suite() {
    for suite in [
        CipherSuite::TLS13_AES_128_GCM_SHA256,
        CipherSuite::TLS13_AES_256_GCM_SHA384,
        CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
    ] {
        let (cc, sc) = configs(&[&rustls::version::TLS13], Some(suite), true);
        let (mut client, mut server) = streams(&cc, &sc);
        assert_incomplete(&client);
        assert_incomplete(&server);
        establish(&mut client, &mut server);
        assert_eq!(client.negotiated_cipher_suite(), Some(suite));
        assert_eq!(server.negotiated_cipher_suite(), Some(suite));
        let binding: [u8; 32] = client.tls_exporter_channel_binding().unwrap();
        assert_eq!(binding, server.tls_exporter_channel_binding().unwrap());
        assert_eq!(binding, reference_binding(&client));
        assert_eq!(binding, reference_binding(&server));
        assert_ne!(binding, [0; 32]);
        send_and_read(&mut client, &mut server);
        send_and_read(&mut server, &mut client);
        assert_eq!(binding, client.tls_exporter_channel_binding().unwrap());
        assert_eq!(binding, server.tls_exporter_channel_binding().unwrap());
    }
}

#[test]
fn tls12_exporter_is_rejected_without_disabling_tls12_io() {
    let (cc, sc) = configs(&[&rustls::version::TLS12], None, true);
    let (mut client, mut server) = streams(&cc, &sc);
    assert_incomplete(&client);
    assert_incomplete(&server);
    establish(&mut client, &mut server);
    for stream in [&client, &server] {
        assert_eq!(
            stream.protocol_version(),
            Some(rustls::ProtocolVersion::TLSv1_2)
        );
        assert!(matches!(
            stream.tls_exporter_channel_binding(),
            Err(TlsError::Configuration(_))
        ));
    }
    send_and_read(&mut client, &mut server);
    send_and_read(&mut server, &mut client);
}

#[test]
fn tls13_exporter_waits_for_the_streams_final_handshake_flush() {
    let (cc, sc) = configs(&[&rustls::version::TLS13], None, true);
    let (mut client, mut server) = streams(&cc, &sc);
    let mut cx = Context::from_waker(Waker::noop());
    assert!(client.poll_handshake(&mut cx).is_pending()); // ClientHello
    assert!(server.poll_handshake(&mut cx).is_pending()); // server flight
    assert_eq!(
        server.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3)
    );
    assert_incomplete(&server); // negotiated version is not a finished handshake
    client.io.block_flush = true;
    assert!(client.poll_handshake(&mut cx).is_pending());
    assert!(!client.conn.is_handshaking()); // rustls has derived exporter secrets
    assert!(!client.is_ready()); // but the wrapper is still flushing Finished
    assert_incomplete(&client);
    let _ = reference_binding(&client); // raw rustls already permits export
    client.io.block_flush = false;
    establish(&mut client, &mut server);
    assert_eq!(
        client.tls_exporter_channel_binding().unwrap(),
        server.tls_exporter_channel_binding().unwrap()
    );
}

#[test]
fn tls13_exporter_is_unique_across_full_connections() {
    let (cc, sc) = configs(&[&rustls::version::TLS13], None, true);
    let mut cc = (*cc).clone();
    cc.resumption = rustls::client::Resumption::disabled();
    let cc = Arc::new(cc);
    let (mut first, mut first_peer) = streams(&cc, &sc);
    establish(&mut first, &mut first_peer);
    let (mut second, mut second_peer) = streams(&cc, &sc);
    establish(&mut second, &mut second_peer);
    assert_ne!(
        first.tls_exporter_channel_binding().unwrap(),
        second.tls_exporter_channel_binding().unwrap()
    );
}

#[test]
fn failed_certificate_verification_does_not_expose_a_binding() {
    let (cc, sc) = configs(&[&rustls::version::TLS13], None, false);
    let (mut client, mut server) = streams(&cc, &sc);
    let (client_result, server_result) = handshake(&mut client, &mut server);
    assert!(client_result.is_err());
    assert!(server_result.is_err());
    assert!(client.is_closed() && server.is_closed());
    assert_disconnected(&client);
    assert_disconnected(&server);
}

#[test]
fn shutdown_and_peer_close_notify_prevent_export() {
    let (cc, sc) = configs(&[&rustls::version::TLS13], None, true);
    let (mut client, mut server) = streams(&cc, &sc);
    establish(&mut client, &mut server);
    let mut cx = Context::from_waker(Waker::noop());
    assert!(matches!(
        Pin::new(&mut client).poll_shutdown(&mut cx),
        Poll::Ready(Ok(()))
    ));
    assert_disconnected(&client);
    let mut bytes = [0; 1];
    let mut buf = ReadBuf::new(&mut bytes);
    assert!(matches!(
        Pin::new(&mut server).poll_read(&mut cx, &mut buf),
        Poll::Ready(Ok(()))
    ));
    assert!(buf.filled().is_empty());
    assert_disconnected(&server);
}

#[test]
fn resumed_tls13_connections_get_fresh_bindings_and_reject_early_export() {
    let (mut cc, mut sc) = configs(&[&rustls::version::TLS13], None, true);
    Arc::get_mut(&mut cc).unwrap().enable_early_data = true;
    Arc::get_mut(&mut sc).unwrap().max_early_data_size = 1024;
    let (mut first, mut first_peer) = streams(&cc, &sc);
    establish(&mut first, &mut first_peer);
    let first_binding = first.tls_exporter_channel_binding().unwrap();

    // Consume the real post-handshake NewSessionTickets into rustls's cache.
    // There is no application data, so reading stops at Pending.
    let mut cx = Context::from_waker(Waker::noop());
    let mut bytes = [0; 1];
    let mut buf = ReadBuf::new(&mut bytes);
    assert!(Pin::new(&mut first).poll_read(&mut cx, &mut buf).is_pending());
    assert!(buf.filled().is_empty());

    let (mut resumed, mut resumed_peer) = streams(&cc, &sc);
    let TlsConnection::Client(conn) = &mut resumed.conn else {
        unreachable!();
    };
    assert!(conn.early_data().is_some(), "a ticket must permit 0-RTT");
    assert_incomplete(&resumed);
    assert_incomplete(&resumed_peer);
    establish(&mut resumed, &mut resumed_peer);
    for stream in [&resumed, &resumed_peer] {
        let kind = match &stream.conn {
            TlsConnection::Client(conn) => conn.handshake_kind(),
            TlsConnection::Server(conn) => conn.handshake_kind(),
        };
        assert_eq!(kind, Some(rustls::HandshakeKind::Resumed));
    }
    let binding = resumed.tls_exporter_channel_binding().unwrap();
    assert_ne!(binding, first_binding);
    assert_eq!(binding, resumed_peer.tls_exporter_channel_binding().unwrap());
    assert_eq!(binding, reference_binding(&resumed));
    assert_eq!(binding, reference_binding(&resumed_peer));
    send_and_read(&mut resumed, &mut resumed_peer);
    send_and_read(&mut resumed_peer, &mut resumed);
}
