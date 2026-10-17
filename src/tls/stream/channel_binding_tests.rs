//! Real rustls handshakes over an in-memory transport with bounded polling.

#![allow(clippy::pedantic, clippy::nursery)]

use super::super::{TlsConnection, TlsStream};
use super::TlsError;
use crate::io::{AsyncRead, AsyncWrite, ReadBuf};
use crate::tls::{
    Certificate, CertificateChain, CertificatePin, CertificatePinSet, PrivateKey, TlsAcceptor,
    TlsConnector,
};
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
    flush_error: Option<io::ErrorKind>,
    io_calls: usize,
    block_write: bool,
    write_limit: Option<usize>,
    buffer_writes: bool,
    buffered: Vec<u8>,
    shutdown_calls: usize,
    transport_eof: bool,
    read_errors: VecDeque<io::ErrorKind>,
    write_errors: VecDeque<io::ErrorKind>,
}

impl AsyncRead for MemoryIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.io_calls += 1;
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if let Some(kind) = self.read_errors.pop_front() {
            return Poll::Ready(Err(kind.into()));
        }
        let mut incoming = self.incoming.borrow_mut();
        if incoming.is_empty() {
            if self.transport_eof {
                return Poll::Ready(Ok(()));
            }
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
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.io_calls += 1;
        if let Some(kind) = self.write_errors.pop_front() {
            return Poll::Ready(Err(kind.into()));
        }
        if self.block_write {
            return Poll::Pending;
        }
        let len = self.write_limit.unwrap_or(buf.len()).min(buf.len());
        if self.buffer_writes {
            self.buffered.extend_from_slice(&buf[..len]);
        } else {
            self.outgoing.borrow_mut().extend(buf[..len].iter().copied());
        }
        Poll::Ready(Ok(len))
    }

    fn poll_flush(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.io_calls += 1;
        if let Some(kind) = self.flush_error {
            return Poll::Ready(Err(kind.into()));
        }
        if self.block_flush {
            return Poll::Pending;
        }
        let this = &mut *self;
        this.outgoing.borrow_mut().extend(this.buffered.drain(..));
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.io_calls += 1;
        self.shutdown_calls += 1;
        // Deliberately does not flush: the TLS wrapper must do that before
        // shutting down a transport that can hold accepted writes.
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

fn memory_pair() -> (MemoryIo, MemoryIo) {
    let client_io = MemoryIo::default();
    let server_io = MemoryIo {
        incoming: Rc::clone(&client_io.outgoing),
        outgoing: Rc::clone(&client_io.incoming),
        ..MemoryIo::default()
    };
    (client_io, server_io)
}

fn streams(
    client_config: &Arc<ClientConfig>,
    server_config: &Arc<ServerConfig>,
) -> (TlsStream<MemoryIo>, TlsStream<MemoryIo>) {
    let (client_io, server_io) = memory_pair();
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
            break;
        }
    }
    match (client_result, server_result) {
        (Some(client), Some(server)) => (client, server),
        _ => panic!("TLS handshake exceeded the in-memory transport's step limit"),
    }
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
    assert_terminal_handshake(&mut client);
    assert_terminal_handshake(&mut server);
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

#[test]
fn tls13_traffic_key_updates_preserve_the_channel_binding() {
    let (cc, sc) = configs(&[&rustls::version::TLS13], None, true);
    let (mut client, mut server) = streams(&cc, &sc);
    establish(&mut client, &mut server);
    let binding = client.tls_exporter_channel_binding().unwrap();
    let TlsConnection::Client(conn) = &mut client.conn else {
        unreachable!();
    };
    conn.refresh_traffic_keys().unwrap();

    // Carry the KeyUpdate and its response on real encrypted records. Traffic
    // keys rotate, but the connection's normal exporter secret stays fixed.
    send_and_read(&mut client, &mut server);
    send_and_read(&mut server, &mut client);
    assert_eq!(binding, client.tls_exporter_channel_binding().unwrap());
    assert_eq!(binding, server.tls_exporter_channel_binding().unwrap());
    assert_eq!(binding, reference_binding(&client));
    assert_eq!(binding, reference_binding(&server));
}

/// Exercise the public retry and write paths, not an assignment to TlsState.
/// Terminal handshake polls must neither reopen the stream nor touch its IO.
fn assert_terminal_handshake(stream: &mut TlsStream<MemoryIo>) {
    let mut cx = Context::from_waker(Waker::noop());
    let state = stream.state;
    let io_calls = stream.io.io_calls;
    for _ in 0..3 {
        assert!(matches!(
            stream.poll_handshake(&mut cx),
            Poll::Ready(Err(TlsError::Io(err))) if err.kind() == io::ErrorKind::NotConnected
        ));
        assert_eq!(stream.state, state);
        assert!(!stream.is_ready());
        assert_disconnected(stream);
        assert!(matches!(
            Pin::new(&mut *stream).poll_write(&mut cx, b"must not send"),
            Poll::Ready(Err(err)) if err.kind() == io::ErrorKind::BrokenPipe
        ));
        assert_eq!(stream.io.io_calls, io_calls, "terminal polls performed IO");
    }
}

#[test]
fn completed_handshake_repoll_is_io_free_on_both_endpoints() {
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        let (cc, sc) = configs(&[version], None, true);
        let (mut client, mut server) = streams(&cc, &sc);
        establish(&mut client, &mut server);
        let mut cx = Context::from_waker(Waker::noop());
        for stream in [&mut client, &mut server] {
            let binding = stream.tls_exporter_channel_binding().ok();
            let io_calls = stream.io.io_calls;
            // This would fail and close the already-established stream if a
            // redundant handshake poll tried to flush the transport again.
            stream.io.flush_error = Some(io::ErrorKind::ConnectionReset);
            for _ in 0..3 {
                assert!(matches!(
                    stream.poll_handshake(&mut cx),
                    Poll::Ready(Ok(()))
                ));
                assert!(stream.is_ready());
                assert_eq!(stream.io.io_calls, io_calls);
                assert_eq!(stream.tls_exporter_channel_binding().ok(), binding);
            }
            stream.io.flush_error = None;
        }
        send_and_read(&mut client, &mut server);
        send_and_read(&mut server, &mut client);
    }
}

/// Drive real handshake records until the chosen endpoint's rustls handshake
/// is done but the stream still owes its final flush. No sleeps or guessed
/// flight counts: the test observes both sides of that boundary explicitly.
fn hold_final_flush(
    client: &mut TlsStream<MemoryIo>,
    server: &mut TlsStream<MemoryIo>,
    client_side: bool,
) {
    if client_side {
        client.io.block_flush = true;
    } else {
        server.io.block_flush = true;
    }
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..128 {
        for stream in [&mut *client, &mut *server] {
            if !stream.is_ready()
                && let Poll::Ready(result) = stream.poll_handshake(&mut cx)
            {
                result.expect("handshake before the injected flush failure");
            }
        }
        let stream = if client_side { &*client } else { &*server };
        if !stream.conn.is_handshaking() {
            assert!(!stream.is_ready(), "the final flush must still be pending");
            assert!(stream.state.requires_handshake());
            assert_incomplete(stream);
            // Prove the underlying exporter is already usable: a later
            // erroneous transition back to Ready would expose these bytes.
            let _ = reference_binding(stream);
            return;
        }
    }
    panic!("did not reach the final-flush boundary");
}

#[test]
fn failed_final_flush_cannot_be_retried_into_a_successful_handshake() {
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        for client_side in [true, false] {
            let (cc, sc) = configs(&[version], None, true);
            let (mut client, mut server) = streams(&cc, &sc);
            hold_final_flush(&mut client, &mut server, client_side);
            let stream = if client_side { &mut client } else { &mut server };
            stream.io.block_flush = false;
            stream.io.flush_error = Some(io::ErrorKind::BrokenPipe);
            let mut cx = Context::from_waker(Waker::noop());
            assert!(matches!(
                stream.poll_handshake(&mut cx),
                Poll::Ready(Err(TlsError::Io(err))) if err.kind() == io::ErrorKind::BrokenPipe
            ));
            assert!(stream.is_closed());
            assert_disconnected(stream);
            // A recovered transport must not revive a failed TLS stream.
            stream.io.flush_error = None;
            assert_terminal_handshake(stream);
        }
    }
}

#[test]
fn handshake_repoll_cannot_undo_either_shutdown_api() {
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        for client_side in [true, false] {
            for async_shutdown in [true, false] {
                let (cc, sc) = configs(&[version], None, true);
                let (mut client, mut server) = streams(&cc, &sc);
                establish(&mut client, &mut server);
                let (stream, peer) = if client_side {
                    (&mut client, &mut server)
                } else {
                    (&mut server, &mut client)
                };
                let mut cx = Context::from_waker(Waker::noop());
                if async_shutdown {
                    assert!(matches!(
                        Pin::new(&mut *stream).poll_shutdown(&mut cx),
                        Poll::Ready(Ok(()))
                    ));
                } else {
                    assert!(matches!(
                        stream.poll_shutdown_tls(&mut cx),
                        Poll::Ready(Ok(()))
                    ));
                }
                assert!(stream.state.shutdown_pending());
                assert_terminal_handshake(stream);
                // Refusing a new handshake must not break the documented
                // half-close: the peer can still send application data.
                send_and_read(peer, stream);
                assert!(matches!(
                    peer.poll_shutdown_tls(&mut cx),
                    Poll::Ready(Ok(()))
                ));
                let mut bytes = [0; 1];
                let mut buf = ReadBuf::new(&mut bytes);
                assert!(matches!(
                    Pin::new(&mut *stream).poll_read(&mut cx, &mut buf),
                    Poll::Ready(Ok(()))
                ));
                assert!(buf.filled().is_empty());
                assert!(stream.is_closed());
                assert_terminal_handshake(stream);
            }
        }
    }
}

#[test]
fn shutdown_before_handshake_cannot_restart_negotiation() {
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        let (cc, sc) = configs(&[version], None, true);
        let (mut client, mut server) = streams(&cc, &sc);
        let mut cx = Context::from_waker(Waker::noop());
        for stream in [&mut client, &mut server] {
            assert!(stream.conn.is_handshaking());
            assert!(matches!(
                stream.poll_shutdown_tls(&mut cx),
                Poll::Ready(Ok(()))
            ));
            assert!(stream.state.shutdown_pending());
            assert_terminal_handshake(stream);
        }
    }
}

fn poll_shutdown_api(
    stream: &mut TlsStream<MemoryIo>,
    cx: &mut Context<'_>,
    async_shutdown: bool,
) -> Poll<io::Result<()>> {
    if async_shutdown {
        Pin::new(stream).poll_shutdown(cx)
    } else {
        stream.poll_shutdown_tls(cx).map(|result| {
            result.map_err(|error| match error {
                TlsError::Io(error) => error,
                other => io::Error::other(other),
            })
        })
    }
}

fn assert_plaintext_read(stream: &mut TlsStream<MemoryIo>, expected: &[u8]) {
    let mut cx = Context::from_waker(Waker::noop());
    let mut bytes = [0; 64];
    let mut buf = ReadBuf::new(&mut bytes);
    assert!(matches!(
        Pin::new(stream).poll_read(&mut cx, &mut buf),
        Poll::Ready(Ok(()))
    ));
    assert_eq!(buf.filled(), expected);
}

#[test]
fn both_shutdown_apis_flush_buffered_records_before_closing_transport() {
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        for client_side in [true, false] {
            for async_shutdown in [true, false] {
                let (cc, sc) = configs(&[version], None, true);
                let (mut client, mut server) = streams(&cc, &sc);
                establish(&mut client, &mut server);
                let (stream, peer) = if client_side {
                    (&mut client, &mut server)
                } else {
                    (&mut server, &mut client)
                };
                stream.io.buffer_writes = true;
                stream.io.write_limit = Some(3); // real partial TLS-record writes
                stream.io.block_flush = true;
                let mut cx = Context::from_waker(Waker::noop());
                let message = b"payload queued before shutdown";
                assert!(matches!(
                    Pin::new(&mut *stream).poll_write(&mut cx, message),
                    Poll::Ready(Ok(len)) if len == message.len()
                ));

                for _ in 0..2 {
                    assert!(poll_shutdown_api(stream, &mut cx, async_shutdown).is_pending());
                    assert!(stream.state.shutdown_pending());
                    assert!(!stream.shutdown_flushed);
                    assert!(!stream.conn.wants_write());
                    assert!(!stream.io.buffered.is_empty());
                    assert_eq!(stream.io.shutdown_calls, 0);
                    assert_terminal_handshake(stream);
                }
                let mut bytes = [0; 64];
                let mut buf = ReadBuf::new(&mut bytes);
                assert!(Pin::new(&mut *peer).poll_read(&mut cx, &mut buf).is_pending());
                assert!(buf.filled().is_empty(), "the transport has not flushed");
                // A pending local shutdown must still permit inbound traffic.
                send_and_read(peer, stream);

                stream.io.block_flush = false;
                assert!(matches!(
                    poll_shutdown_api(stream, &mut cx, async_shutdown),
                    Poll::Ready(Ok(()))
                ));
                assert!(stream.shutdown_flushed);
                assert!(stream.io.buffered.is_empty());
                assert!(!stream.conn.wants_write());
                assert_eq!(stream.io.shutdown_calls, usize::from(async_shutdown));
                assert_plaintext_read(peer, message);
                // This EOF comes from a real authenticated close_notify;
                // This transport has no simulated EOF configured.
                assert_plaintext_read(peer, b"");
                assert_disconnected(stream);
                assert_disconnected(peer);
            }
        }
    }
}

#[test]
fn peer_eof_does_not_drop_a_pending_local_close_notify() {
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        for client_side in [true, false] {
            for async_shutdown in [true, false] {
                for stall_write in [true, false] {
                    let (cc, sc) = configs(&[version], None, true);
                    let (mut client, mut server) = streams(&cc, &sc);
                    establish(&mut client, &mut server);
                    let (stream, peer) = if client_side {
                        (&mut client, &mut server)
                    } else {
                        (&mut server, &mut client)
                    };
                    stream.io.buffer_writes = true;
                    stream.io.block_write = stall_write;
                    stream.io.block_flush = !stall_write;
                    let mut cx = Context::from_waker(Waker::noop());
                    assert!(poll_shutdown_api(stream, &mut cx, async_shutdown).is_pending());
                    assert!(!stream.shutdown_flushed);
                    assert!(stream.conn.wants_write() || !stream.io.buffered.is_empty());
                    assert!(matches!(
                        peer.poll_shutdown_tls(&mut cx),
                        Poll::Ready(Ok(()))
                    ));
                    assert_plaintext_read(stream, b"");
                    assert!(stream.read_closed);
                    assert!(stream.state.shutdown_pending());
                    assert!(!stream.is_closed(), "local close_notify is still pending");
                    assert_eq!(stream.io.shutdown_calls, 0);
                    assert_terminal_handshake(stream);

                    stream.io.block_write = false;
                    stream.io.block_flush = false;
                    assert!(matches!(
                        poll_shutdown_api(stream, &mut cx, async_shutdown),
                        Poll::Ready(Ok(()))
                    ));
                    assert!(stream.shutdown_flushed && stream.is_closed());
                    assert!(stream.io.buffered.is_empty());
                    assert!(!stream.conn.wants_write());
                    assert_eq!(stream.io.shutdown_calls, usize::from(async_shutdown));
                    assert_plaintext_read(peer, b"");
                    assert!(peer.is_closed());
                    assert_terminal_handshake(stream);
                    assert_terminal_handshake(peer);
                }
            }
        }
    }
}

#[test]
fn shutdown_reports_write_zero_and_preserves_transport_flush_errors() {
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        for client_side in [true, false] {
            for async_shutdown in [true, false] {
                for zero_write in [true, false] {
                    let (cc, sc) = configs(&[version], None, true);
                    let (mut client, mut server) = streams(&cc, &sc);
                    establish(&mut client, &mut server);
                    let (stream, peer) = if client_side {
                        (&mut client, &mut server)
                    } else {
                        (&mut server, &mut client)
                    };
                    stream.io.buffer_writes = true;
                    let expected = if zero_write {
                        stream.io.write_limit = Some(0);
                        io::ErrorKind::WriteZero
                    } else {
                        stream.io.flush_error = Some(io::ErrorKind::ConnectionReset);
                        io::ErrorKind::ConnectionReset
                    };
                    let mut cx = Context::from_waker(Waker::noop());
                    for _ in 0..2 {
                        assert!(matches!(
                            poll_shutdown_api(stream, &mut cx, async_shutdown),
                            Poll::Ready(Err(error)) if error.kind() == expected
                        ));
                        assert!(!stream.shutdown_flushed);
                        assert_eq!(stream.io.shutdown_calls, 0);
                        assert!(stream.conn.wants_write() || !stream.io.buffered.is_empty());
                        assert_terminal_handshake(stream);
                    }
                    // Retrying the shutdown may drain retained records, but
                    // must never reopen application writes or channel binding.
                    stream.io.write_limit = Some(3);
                    stream.io.flush_error = None;
                    assert!(matches!(
                        poll_shutdown_api(stream, &mut cx, async_shutdown),
                        Poll::Ready(Ok(()))
                    ));
                    assert!(stream.shutdown_flushed);
                    assert_eq!(stream.io.shutdown_calls, usize::from(async_shutdown));
                    assert_plaintext_read(peer, b"");
                    assert_terminal_handshake(stream);
                }
            }
        }
    }
}

#[test]
fn tls_flush_does_not_report_success_with_unsent_application_records() {
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        for client_side in [true, false] {
            let (cc, sc) = configs(&[version], None, true);
            let (mut client, mut server) = streams(&cc, &sc);
            establish(&mut client, &mut server);
            let (stream, peer) = if client_side {
                (&mut client, &mut server)
            } else {
                (&mut server, &mut client)
            };
            let mut cx = Context::from_waker(Waker::noop());
            let message = b"accepted but not yet flushed";
            stream.io.block_write = true;
            assert!(matches!(
                Pin::new(&mut *stream).poll_write(&mut cx, message),
                Poll::Ready(Ok(len)) if len == message.len()
            ));
            assert!(stream.conn.wants_write());
            stream.io.block_write = false;
            stream.io.write_limit = Some(0);
            assert!(matches!(
                Pin::new(&mut *stream).poll_flush(&mut cx),
                Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::WriteZero
            ));
            assert!(stream.conn.wants_write());
            stream.io.write_limit = Some(3);
            stream.io.buffer_writes = true;
            stream.io.block_flush = true;
            assert!(Pin::new(&mut *stream).poll_flush(&mut cx).is_pending());
            assert!(!stream.conn.wants_write());
            assert!(!stream.io.buffered.is_empty());
            stream.io.block_flush = false;
            assert!(matches!(
                Pin::new(&mut *stream).poll_flush(&mut cx),
                Poll::Ready(Ok(()))
            ));
            assert!(stream.io.buffered.is_empty());
            assert_plaintext_read(peer, message);
            send_and_read(peer, stream);
        }
    }
}

/// Poll both public handshake futures without an executor, timer, or sleeps.
/// Keep successful streams alive until both sides finish so a server can
/// still deliver its post-handshake tickets. The transport has no waker;
/// this bounded driver deliberately polls both futures on every step.
fn public_handshakes(
    client: impl std::future::Future<Output = Result<TlsStream<MemoryIo>, TlsError>>,
    server: impl std::future::Future<Output = Result<TlsStream<MemoryIo>, TlsError>>,
) -> (
    Result<TlsStream<MemoryIo>, TlsError>,
    Result<TlsStream<MemoryIo>, TlsError>,
) {
    let mut client = std::pin::pin!(client);
    let mut server = std::pin::pin!(server);
    let mut cx = Context::from_waker(Waker::noop());
    let mut client_result = None;
    let mut server_result = None;
    for _ in 0..128 {
        if client_result.is_none()
            && let Poll::Ready(result) = client.as_mut().poll(&mut cx)
        {
            client_result = Some(result);
        }
        if server_result.is_none()
            && let Poll::Ready(result) = server.as_mut().poll(&mut cx)
        {
            server_result = Some(result);
        }
        if client_result.is_some() && server_result.is_some() {
            break;
        }
    }
    match (client_result, server_result) {
        (Some(client), Some(server)) => (client, server),
        _ => panic!("public TLS handshakes exceeded the bounded poll limit"),
    }
}

#[test]
fn public_connect_accept_export_according_to_the_negotiated_version() {
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        // The client offers both versions. Restrict only the server so the
        // assertion tests the negotiated version, not the configured maximum.
        let (mut cc, _) = configs(&[&rustls::version::TLS13, &rustls::version::TLS12], None, true);
        let (_, mut sc) = configs(&[version], None, true);
        Arc::get_mut(&mut cc).unwrap().alpn_protocols = vec![b"xmpp-client".to_vec()];
        Arc::get_mut(&mut sc).unwrap().alpn_protocols = vec![b"xmpp-client".to_vec()];
        let connector = TlsConnector::new((*cc).clone());
        let acceptor = TlsAcceptor::new((*sc).clone());
        let (client_io, server_io) = memory_pair();
        let (client, server) = public_handshakes(
            connector.connect("localhost", client_io),
            acceptor.accept(server_io),
        );
        let mut client = client.expect("public client handshake");
        let mut server = server.expect("public server handshake");
        let expected_version = version.version;
        for stream in [&client, &server] {
            assert!(stream.is_ready());
            assert_eq!(stream.protocol_version(), Some(expected_version));
            assert_eq!(stream.alpn_protocol(), Some(b"xmpp-client".as_slice()));
            if expected_version == rustls::ProtocolVersion::TLSv1_3 {
                assert_eq!(
                    stream.tls_exporter_channel_binding().unwrap(),
                    reference_binding(stream)
                );
            } else {
                assert!(matches!(
                    stream.tls_exporter_channel_binding(),
                    Err(TlsError::Configuration(_))
                ));
            }
        }
        if expected_version == rustls::ProtocolVersion::TLSv1_3 {
            assert_eq!(
                client.tls_exporter_channel_binding().unwrap(),
                server.tls_exporter_channel_binding().unwrap()
            );
        }
        send_and_read(&mut client, &mut server);
        send_and_read(&mut server, &mut client);
    }
}

#[test]
fn public_connector_enforces_pins_before_returning_an_exporter_capable_stream() {
    let certificates = Certificate::from_pem(CERT_PEM).unwrap();
    let correct_pin = CertificatePin::compute_cert_sha256(&certificates[0]).unwrap();
    let mut incorrect_hash = correct_pin.hash_bytes().to_vec();
    incorrect_hash[0] ^= 1;
    let incorrect_pin = CertificatePin::CertSha256(incorrect_hash);

    for pin_matches in [true, false] {
        let (cc, sc) = configs(&[&rustls::version::TLS13], None, true);
        let pin = if pin_matches {
            correct_pin.clone()
        } else {
            incorrect_pin.clone()
        };
        let pins = CertificatePinSet::new().with_pin(pin);
        assert!(pins.is_enforcing());
        let connector = TlsConnector::new((*cc).clone()).with_pin_set(pins);
        let acceptor = TlsAcceptor::new((*sc).clone());
        let (client_io, server_io) = memory_pair();
        let (client, server) = public_handshakes(
            connector.connect("localhost", client_io),
            acceptor.accept(server_io),
        );
        let server = server.expect("the peer must have received the client's Finished");
        assert!(server.is_ready());
        if pin_matches {
            let client = client.expect("a trusted and correctly pinned server is accepted");
            assert_eq!(
                client.tls_exporter_channel_binding().unwrap(),
                server.tls_exporter_channel_binding().unwrap()
            );
        } else {
            // Certificate-chain verification and TLS have succeeded. The
            // higher-level pin gate must still return an error, not a stream
            // whose newly exposed exporter a caller could use for binding.
            assert!(matches!(client, Err(TlsError::PinMismatch { .. })));
        }
    }
}

#[test]
fn public_acceptor_rejects_actual_early_data_but_exports_after_resumption() {
    use std::io::Write;

    let (mut cc, mut sc) = configs(&[&rustls::version::TLS13], None, true);
    Arc::get_mut(&mut cc).unwrap().enable_early_data = true;
    Arc::get_mut(&mut sc).unwrap().max_early_data_size = 1024;
    let connector = TlsConnector::new((*cc).clone());
    let acceptor = TlsAcceptor::new((*sc).clone());
    let (client_io, server_io) = memory_pair();
    let (first, first_peer) = public_handshakes(
        connector.connect("localhost", client_io),
        acceptor.accept(server_io),
    );
    let mut first = first.expect("initial public client handshake");
    let first_peer = first_peer.expect("initial public server handshake");
    let first_binding = first.tls_exporter_channel_binding().unwrap();
    assert_eq!(
        first_binding,
        first_peer.tls_exporter_channel_binding().unwrap()
    );

    // Store genuine NewSessionTickets, not fabricated resumption state.
    let mut cx = Context::from_waker(Waker::noop());
    let mut bytes = [0; 64];
    let mut buf = ReadBuf::new(&mut bytes);
    assert!(Pin::new(&mut first).poll_read(&mut cx, &mut buf).is_pending());
    assert!(buf.filled().is_empty());

    let (client_io, server_io) = memory_pair();
    let mut conn = ClientConnection::new(
        Arc::clone(connector.config()),
        ServerName::try_from("localhost").unwrap(),
    )
    .unwrap();
    // The public connector has no early-write surface; use raw rustls only
    // to create a peer that actually sends 0-RTT to the public acceptor.
    conn.early_data()
        .expect("the cached ticket must advertise early data")
        .write_all(b"must not be delivered as application data")
        .unwrap();
    let mut resumed = TlsStream::new_client(client_io, conn);
    assert_incomplete(&resumed);
    let client = async move {
        std::future::poll_fn(|cx| resumed.poll_handshake(cx)).await?;
        Ok(resumed)
    };
    let (resumed, resumed_peer) = public_handshakes(client, acceptor.accept(server_io));
    let mut resumed = resumed.expect("resumed client handshake");
    let mut resumed_peer = resumed_peer.expect("resumed public server handshake");
    let TlsConnection::Client(conn) = &resumed.conn else {
        unreachable!();
    };
    assert_eq!(conn.handshake_kind(), Some(rustls::HandshakeKind::Resumed));
    assert!(
        !conn.is_early_data_accepted(),
        "public accept must reject 0-RTT"
    );
    let TlsConnection::Server(conn) = &resumed_peer.conn else {
        unreachable!();
    };
    assert_eq!(conn.handshake_kind(), Some(rustls::HandshakeKind::Resumed));
    let binding = resumed.tls_exporter_channel_binding().unwrap();
    assert_ne!(binding, first_binding);
    assert_eq!(binding, resumed_peer.tls_exporter_channel_binding().unwrap());
    assert_eq!(binding, reference_binding(&resumed));
    assert_eq!(binding, reference_binding(&resumed_peer));
    let mut buf = ReadBuf::new(&mut bytes);
    assert!(Pin::new(&mut resumed_peer).poll_read(&mut cx, &mut buf).is_pending());
    assert!(
        buf.filled().is_empty(),
        "rejected early bytes reached the application"
    );
    send_and_read(&mut resumed, &mut resumed_peer);
    send_and_read(&mut resumed_peer, &mut resumed);
}

#[test]
fn corrupt_or_truncated_records_permanently_revoke_exporter_access() {
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        for client_receives in [true, false] {
            for truncate in [true, false] {
                let (cc, sc) = configs(&[version], None, true);
                let (mut client, mut server) = streams(&cc, &sc);
                establish(&mut client, &mut server);
                let (receiver, sender) = if client_receives {
                    (&mut client, &mut server)
                } else {
                    (&mut server, &mut client)
                };
                if version.version == rustls::ProtocolVersion::TLSv1_3 {
                    // Prove the exporter was usable before the read failure.
                    assert_eq!(
                        receiver.tls_exporter_channel_binding().unwrap(),
                        sender.tls_exporter_channel_binding().unwrap()
                    );
                }
                let mut cx = Context::from_waker(Waker::noop());
                let message = b"authenticated record to corrupt or truncate";
                assert!(matches!(
                    Pin::new(&mut *sender).poll_write(&mut cx, message),
                    Poll::Ready(Ok(len)) if len == message.len()
                ));
                assert!(matches!(
                    Pin::new(&mut *sender).poll_flush(&mut cx),
                    Poll::Ready(Ok(()))
                ));
                // Mutate the last byte of a real encrypted application record,
                // never rustls state or an already-decrypted plaintext buffer.
                let expected = {
                    let mut wire = sender.io.outgoing.borrow_mut();
                    assert!(wire.len() > message.len());
                    if truncate {
                        assert!(wire.pop_back().is_some());
                        receiver.io.transport_eof = true;
                        io::ErrorKind::UnexpectedEof
                    } else {
                        *wire.back_mut().unwrap() ^= 1;
                        io::ErrorKind::InvalidData
                    }
                };
                let mut bytes = [0; 64];
                let mut buf = ReadBuf::new(&mut bytes);
                assert!(matches!(
                    Pin::new(&mut *receiver).poll_read(&mut cx, &mut buf),
                    Poll::Ready(Err(error)) if error.kind() == expected
                ));
                assert!(
                    buf.filled().is_empty(),
                    "unauthenticated plaintext escaped"
                );
                assert!(receiver.is_closed());
                assert_disconnected(receiver);
                let io_calls = receiver.io.io_calls;
                // Even a transport that subsequently recovers must not turn a
                // truncated/authentication-failed TLS session into clean EOF.
                receiver.io.transport_eof = false;
                for _ in 0..3 {
                    let mut buf = ReadBuf::new(&mut bytes);
                    assert!(matches!(
                        Pin::new(&mut *receiver).poll_read(&mut cx, &mut buf),
                        Poll::Ready(Err(error)) if error.kind() == expected
                    ));
                    assert!(buf.filled().is_empty());
                    assert_eq!(receiver.io.io_calls, io_calls);
                    assert_terminal_handshake(receiver);
                }
            }
        }
    }
}

#[test]
fn fatal_transport_read_errors_revoke_exporter_access_and_remain_sticky() {
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        for client_receives in [true, false] {
            for kind in [io::ErrorKind::ConnectionReset, io::ErrorKind::BrokenPipe] {
                let (cc, sc) = configs(&[version], None, true);
                let (mut client, mut server) = streams(&cc, &sc);
                establish(&mut client, &mut server);
                let (receiver, sender) = if client_receives {
                    (&mut client, &mut server)
                } else {
                    (&mut server, &mut client)
                };
                if version.version == rustls::ProtocolVersion::TLSv1_3 {
                    assert_eq!(
                        receiver.tls_exporter_channel_binding().unwrap(),
                        sender.tls_exporter_channel_binding().unwrap()
                    );
                }
                receiver.io.read_errors.push_back(kind);
                let mut cx = Context::from_waker(Waker::noop());
                let mut bytes = [0; 64];
                let mut buf = ReadBuf::new(&mut bytes);
                assert!(matches!(
                    Pin::new(&mut *receiver).poll_read(&mut cx, &mut buf),
                    Poll::Ready(Err(error)) if error.kind() == kind
                ));
                assert!(buf.filled().is_empty());
                assert!(receiver.is_closed());
                assert_disconnected(receiver);

                // Recovering the underlying transport cannot make this TLS
                // session usable or turn the original failure into clean EOF.
                let io_calls = receiver.io.io_calls;
                for _ in 0..3 {
                    let mut buf = ReadBuf::new(&mut bytes);
                    assert!(matches!(
                        Pin::new(&mut *receiver).poll_read(&mut cx, &mut buf),
                        Poll::Ready(Err(error)) if error.kind() == kind
                    ));
                    assert!(buf.filled().is_empty());
                    assert_eq!(receiver.io.io_calls, io_calls);
                    assert_terminal_handshake(receiver);
                }
            }
        }
    }
}

#[test]
fn interrupted_transport_reads_preserve_live_tls_and_exporter() {
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        for client_receives in [true, false] {
            let (cc, sc) = configs(&[version], None, true);
            let (mut client, mut server) = streams(&cc, &sc);
            establish(&mut client, &mut server);
            let (receiver, sender) = if client_receives {
                (&mut client, &mut server)
            } else {
                (&mut server, &mut client)
            };
            let binding = receiver.tls_exporter_channel_binding().ok();
            receiver.io.read_errors.push_back(io::ErrorKind::Interrupted);
            let mut cx = Context::from_waker(Waker::noop());
            let mut bytes = [0; 64];
            let mut buf = ReadBuf::new(&mut bytes);
            assert!(Pin::new(&mut *receiver).poll_read(&mut cx, &mut buf).is_pending());
            assert!(buf.filled().is_empty());
            assert!(receiver.is_ready());
            assert_eq!(receiver.tls_exporter_channel_binding().ok(), binding);
            send_and_read(sender, receiver);
            assert!(receiver.is_ready());
            assert_eq!(receiver.tls_exporter_channel_binding().ok(), binding);
        }
    }
}

#[test]
fn accepted_plaintext_is_counted_once_on_fatal_transport_write_error() {
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        for client_sends in [true, false] {
            for kind in [io::ErrorKind::ConnectionReset, io::ErrorKind::BrokenPipe] {
                let (cc, sc) = configs(&[version], None, true);
                let (mut client, mut server) = streams(&cc, &sc);
                establish(&mut client, &mut server);
                let (sender, receiver) = if client_sends {
                    (&mut client, &mut server)
                } else {
                    (&mut server, &mut client)
                };
                if version.version == rustls::ProtocolVersion::TLSv1_3 {
                    assert_eq!(
                        sender.tls_exporter_channel_binding().unwrap(),
                        receiver.tls_exporter_channel_binding().unwrap()
                    );
                }
                sender.io.write_errors.push_back(kind);
                let mut cx = Context::from_waker(Waker::noop());
                let message = b"plaintext accepted before broken transport";
                // The first public write has already committed the plaintext
                // to rustls. Returning Err here would make write_all retry it.
                assert!(matches!(
                    Pin::new(&mut *sender).poll_write(&mut cx, message),
                    Poll::Ready(Ok(n)) if n == message.len()
                ));
                assert!(sender.is_closed());
                assert_disconnected(sender);
                assert!(sender.write_error.is_some());
                let calls = sender.io.io_calls;
                for _ in 0..3 {
                    assert!(matches!(
                        Pin::new(&mut *sender).poll_write(&mut cx, message),
                        Poll::Ready(Err(error)) if error.kind() == kind
                    ));
                    assert!(matches!(
                        Pin::new(&mut *sender).poll_flush(&mut cx),
                        Poll::Ready(Err(error)) if error.kind() == kind
                    ));
                    assert!(matches!(
                        Pin::new(&mut *sender).poll_shutdown(&mut cx),
                        Poll::Ready(Err(error)) if error.kind() == kind
                    ));
                    assert!(matches!(
                        sender.poll_shutdown_tls(&mut cx),
                        Poll::Ready(Err(TlsError::Io(error))) if error.kind() == kind
                    ));
                    let mut bytes = [0; 64];
                    let mut buf = ReadBuf::new(&mut bytes);
                    assert!(matches!(
                        Pin::new(&mut *sender).poll_read(&mut cx, &mut buf),
                        Poll::Ready(Err(error)) if error.kind() == kind
                    ));
                    assert!(buf.filled().is_empty());
                    assert_eq!(sender.io.io_calls, calls);
                    assert!(matches!(
                        sender.poll_handshake(&mut cx),
                        Poll::Ready(Err(TlsError::Io(error)))
                            if error.kind() == io::ErrorKind::NotConnected
                    ));
                }
                let mut bytes = [0; 64];
                let mut buf = ReadBuf::new(&mut bytes);
                assert!(Pin::new(&mut *receiver).poll_read(&mut cx, &mut buf).is_pending());
                assert!(buf.filled().is_empty(), "failed write leaked plaintext");
            }
        }
    }
}

#[test]
fn interrupted_transport_writes_allow_subsequent_flush_and_export() {
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        for client_sends in [true, false] {
            let (cc, sc) = configs(&[version], None, true);
            let (mut client, mut server) = streams(&cc, &sc);
            establish(&mut client, &mut server);
            let (sender, receiver) = if client_sends {
                (&mut client, &mut server)
            } else {
                (&mut server, &mut client)
            };
            let binding = sender.tls_exporter_channel_binding().ok();
            sender.io.write_errors.push_back(io::ErrorKind::Interrupted);
            let mut cx = Context::from_waker(Waker::noop());
            let message = b"write interrupted once, then delivered";
            assert!(matches!(
                Pin::new(&mut *sender).poll_write(&mut cx, message),
                Poll::Ready(Ok(n)) if n == message.len()
            ));
            assert!(sender.is_ready());
            assert!(sender.conn.wants_write());
            assert!(matches!(
                Pin::new(&mut *sender).poll_flush(&mut cx),
                Poll::Ready(Ok(()))
            ));
            let mut bytes = [0; 64];
            let mut buf = ReadBuf::new(&mut bytes);
            assert!(matches!(
                Pin::new(&mut *receiver).poll_read(&mut cx, &mut buf),
                Poll::Ready(Ok(()))
            ));
            assert_eq!(buf.filled(), message);
            assert!(sender.is_ready() && receiver.is_ready());
            assert_eq!(sender.tls_exporter_channel_binding().ok(), binding);
            assert_eq!(receiver.tls_exporter_channel_binding().ok(), binding);
        }
    }
}
