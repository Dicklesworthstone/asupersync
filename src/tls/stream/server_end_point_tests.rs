//! Real TLS handshakes, explicitly polled over bounded in-memory transports.

#![allow(clippy::pedantic, clippy::nursery)]

use super::super::{TlsConnection, TlsStream};
use super::TlsError;
use crate::io::{AsyncRead, AsyncWrite, ReadBuf};
use crate::tls::{Certificate, CertificateChain, PrivateKey};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, ServerConfig, ServerConnection};
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
        let mut incoming = self.incoming.borrow_mut();
        if incoming.is_empty() {
            return Poll::Pending;
        }
        let count = incoming.len().min(buf.remaining());
        for byte in incoming.drain(..count) {
            buf.put_slice(&[byte]);
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for MemoryIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.io_calls += 1;
        self.outgoing.borrow_mut().extend(bytes.iter().copied());
        Poll::Ready(Ok(bytes.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.io_calls += 1;
        if let Some(error) = self.flush_error {
            return Poll::Ready(Err(error.into()));
        }
        if self.block_flush {
            Poll::Pending
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.io_calls += 1;
        Poll::Ready(Ok(()))
    }
}

fn configs(
    version: &'static rustls::SupportedProtocolVersion,
    trust_server: bool,
    mutual: bool,
) -> (Arc<ClientConfig>, Arc<ServerConfig>) {
    let chain = CertificateChain::from_pem(CERT_PEM).unwrap().into_inner();
    let mut roots = rustls::RootCertStore::empty();
    for cert in &chain {
        roots.add(cert.clone()).unwrap();
    }
    let client_roots = if trust_server { roots.clone() } else { rustls::RootCertStore::empty() };
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[version])
        .unwrap()
        .with_root_certificates(client_roots);
    let client = if mutual {
        builder
            .with_client_auth_cert(chain.clone(), PrivateKey::from_pem(KEY_PEM).unwrap().clone_inner())
            .unwrap()
    } else {
        builder.with_no_client_auth()
    };
    let builder = ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[version])
        .unwrap();
    let builder = if mutual {
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots), provider,
        ).build().unwrap();
        builder.with_client_cert_verifier(verifier)
    } else {
        builder.with_no_client_auth()
    };
    let server = builder
        .with_single_cert(chain, PrivateKey::from_pem(KEY_PEM).unwrap().clone_inner())
        .unwrap();
    (Arc::new(client), Arc::new(server))
}

fn streams(
    client: &Arc<ClientConfig>,
    server: &Arc<ServerConfig>,
) -> (TlsStream<MemoryIo>, TlsStream<MemoryIo>) {
    let client_io = MemoryIo::default();
    let server_io = MemoryIo {
        incoming: Rc::clone(&client_io.outgoing),
        outgoing: Rc::clone(&client_io.incoming),
        ..MemoryIo::default()
    };
    let client = ClientConnection::new(
        Arc::clone(client), ServerName::try_from("localhost").unwrap(),
    ).unwrap();
    let server = ServerConnection::new(Arc::clone(server)).unwrap();
    (TlsStream::new_client(client_io, client), TlsStream::new_server(server_io, server))
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
    (client_result.expect("bounded client handshake"), server_result.expect("bounded server handshake"))
}

fn establish(client: &mut TlsStream<MemoryIo>, server: &mut TlsStream<MemoryIo>) {
    let (client, server) = handshake(client, server);
    client.expect("client handshake");
    server.expect("server handshake");
}

fn expected_binding() -> Vec<u8> {
    Certificate::from_pem(CERT_PEM).unwrap()[0]
        .tls_server_end_point_channel_binding().unwrap()
}

fn assert_incomplete(stream: &TlsStream<MemoryIo>) {
    assert!(matches!(
        stream.tls_server_end_point_channel_binding(),
        Err(TlsError::Rustls(rustls::Error::HandshakeNotComplete))
    ));
}

fn assert_disconnected(stream: &TlsStream<MemoryIo>) {
    assert!(matches!(
        stream.tls_server_end_point_channel_binding(),
        Err(TlsError::Io(error)) if error.kind() == io::ErrorKind::NotConnected
    ));
}

#[test]
fn tls12_and_tls13_clients_bind_the_server_leaf_without_io() {
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        let (cc, sc) = configs(version, true, false);
        let (mut client, mut server) = streams(&cc, &sc);
        assert_incomplete(&client);
        establish(&mut client, &mut server);
        let calls = client.io.io_calls;
        let expected = expected_binding();
        assert_eq!(client.tls_server_end_point_channel_binding().unwrap(), expected);
        assert_eq!(client.tls_server_end_point_channel_binding().unwrap(), expected);
        assert_eq!(client.io.io_calls, calls, "channel binding must perform no I/O");
        if client.protocol_version() == Some(rustls::ProtocolVersion::TLSv1_2) {
            assert!(matches!(client.tls_exporter_channel_binding(), Err(TlsError::Configuration(_))));
        } else {
            assert_eq!(client.tls_exporter_channel_binding().unwrap(), server.tls_exporter_channel_binding().unwrap());
        }
    }
}

#[test]
fn server_end_point_waits_for_the_final_handshake_flush() {
    let (cc, sc) = configs(&rustls::version::TLS13, true, false);
    let (mut client, mut server) = streams(&cc, &sc);
    let mut cx = Context::from_waker(Waker::noop());
    assert!(client.poll_handshake(&mut cx).is_pending());
    assert!(server.poll_handshake(&mut cx).is_pending());
    client.io.block_flush = true;
    assert!(client.poll_handshake(&mut cx).is_pending());
    assert!(!client.conn.is_handshaking());
    assert!(!client.is_ready());
    assert_incomplete(&client);
    client.io.block_flush = false;
    establish(&mut client, &mut server);
    assert_eq!(client.tls_server_end_point_channel_binding().unwrap(), expected_binding());
}

#[test]
fn server_role_never_binds_a_mutual_tls_client_certificate() {
    let (cc, sc) = configs(&rustls::version::TLS13, true, true);
    let (mut client, mut server) = streams(&cc, &sc);
    establish(&mut client, &mut server);
    assert!(server.peer_leaf_certificate_der().is_some(), "mutual TLS presented a client leaf");
    assert!(matches!(
        server.tls_server_end_point_channel_binding(),
        Err(TlsError::Configuration(_))
    ));
    assert_eq!(client.tls_server_end_point_channel_binding().unwrap(), expected_binding());
}

#[test]
fn untrusted_server_and_failed_final_flush_expose_no_binding() {
    let (cc, sc) = configs(&rustls::version::TLS13, false, false);
    let (mut client, mut server) = streams(&cc, &sc);
    let (client_result, _) = handshake(&mut client, &mut server);
    assert!(client_result.is_err());
    assert_disconnected(&client);

    let (cc, sc) = configs(&rustls::version::TLS13, true, false);
    let (mut client, mut server) = streams(&cc, &sc);
    let mut cx = Context::from_waker(Waker::noop());
    assert!(client.poll_handshake(&mut cx).is_pending());
    assert!(server.poll_handshake(&mut cx).is_pending());
    client.io.flush_error = Some(io::ErrorKind::BrokenPipe);
    assert!(matches!(client.poll_handshake(&mut cx), Poll::Ready(Err(_))));
    assert_disconnected(&client);
}

#[test]
fn local_shutdown_and_peer_close_notify_revoke_stream_bindings() {
    let (cc, sc) = configs(&rustls::version::TLS13, true, false);
    let (mut client, mut server) = streams(&cc, &sc);
    establish(&mut client, &mut server);
    let mut cx = Context::from_waker(Waker::noop());
    client.io.block_flush = true;
    assert!(Pin::new(&mut client).poll_shutdown(&mut cx).is_pending());
    assert_disconnected(&client);

    let (mut client, mut server) = streams(&cc, &sc);
    establish(&mut client, &mut server);
    assert!(matches!(Pin::new(&mut server).poll_shutdown(&mut cx), Poll::Ready(Ok(()))));
    let mut bytes = [0; 1];
    let mut buf = ReadBuf::new(&mut bytes);
    assert!(matches!(Pin::new(&mut client).poll_read(&mut cx, &mut buf), Poll::Ready(Ok(()))));
    assert!(buf.filled().is_empty());
    assert_disconnected(&client);
}

#[test]
fn resumed_tls13_keeps_certificate_binding_but_rejects_early_access() {
    let (mut cc, mut sc) = configs(&rustls::version::TLS13, true, false);
    Arc::get_mut(&mut cc).unwrap().enable_early_data = true;
    Arc::get_mut(&mut sc).unwrap().max_early_data_size = 1024;
    let (mut first, mut first_peer) = streams(&cc, &sc);
    establish(&mut first, &mut first_peer);
    let binding = first.tls_server_end_point_channel_binding().unwrap();
    let exporter = first.tls_exporter_channel_binding().unwrap();
    let mut cx = Context::from_waker(Waker::noop());
    let mut bytes = [0; 1];
    let mut buf = ReadBuf::new(&mut bytes);
    assert!(Pin::new(&mut first).poll_read(&mut cx, &mut buf).is_pending());
    let (mut resumed, mut peer) = streams(&cc, &sc);
    let TlsConnection::Client(conn) = &mut resumed.conn else { unreachable!() };
    assert!(conn.early_data().is_some(), "session ticket enabled 0-RTT");
    assert_incomplete(&resumed);
    establish(&mut resumed, &mut peer);
    let TlsConnection::Client(conn) = &resumed.conn else { unreachable!() };
    assert_eq!(conn.handshake_kind(), Some(rustls::HandshakeKind::Resumed));
    assert_eq!(resumed.tls_server_end_point_channel_binding().unwrap(), binding);
    assert_ne!(resumed.tls_exporter_channel_binding().unwrap(), exporter);
}
