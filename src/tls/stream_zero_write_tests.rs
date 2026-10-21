//! Zero-progress transport writes must not spin or re-admit accepted plaintext.

#![allow(clippy::pedantic, clippy::nursery)]

use super::{TlsConnection, TlsError, TlsStream};
use crate::conformance::{ConformanceTarget, LabRuntimeTarget, TestConfig};
use crate::io::{AsyncRead, AsyncWrite, ReadBuf};
use crate::net::tcp::VirtualTcpStream;
use crate::tls::{CertificateChain, PrivateKey};
use futures_lite::future::{poll_fn, zip};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, ServerConfig, ServerConnection};
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Wake, Waker};

type Stream = TlsStream<ZeroIo>;

struct ZeroIo {
    inner: VirtualTcpStream,
    block: bool,
    before_zero: Option<usize>,
    calls: usize,
    written: usize,
    zeros: usize,
    waiter: Option<Waker>,
}

impl ZeroIo {
    fn new(inner: VirtualTcpStream) -> Self {
        Self {
            inner,
            block: false,
            before_zero: None,
            calls: 0,
            written: 0,
            zeros: 0,
            waiter: None,
        }
    }
}

impl AsyncRead for ZeroIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.calls += 1;
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for ZeroIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.calls += 1;
        if self.block {
            self.waiter = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let len = self.before_zero.unwrap_or(buf.len()).min(buf.len());
        if len == 0 && !buf.is_empty() {
            self.zeros += 1;
            // An exhausted writer reports zero without registering readiness
            // or arranging a wake. This is not an asynchronous Pending.
            return Poll::Ready(Ok(0));
        }
        let n = std::task::ready!(Pin::new(&mut self.inner).poll_write(cx, &buf[..len]))?;
        self.written += n;
        if let Some(remaining) = &mut self.before_zero {
            *remaining -= n;
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.calls += 1;
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.calls += 1;
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[derive(Default)]
struct WakeCount(AtomicUsize);

impl Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

fn run_pair(
    version: &'static rustls::SupportedProtocolVersion,
    test: impl FnOnce(Stream, Stream) + Send + 'static,
) {
    let config = TestConfig::new()
        .with_seed(0x0BAD_2000)
        .with_max_steps(20_000);
    let mut runtime = LabRuntimeTarget::create_runtime(config);
    LabRuntimeTarget::block_on(&mut runtime, async move {
        let chain = CertificateChain::from_pem(include_bytes!("../../tests/fixtures/tls/server.crt"))
            .unwrap()
            .into_inner();
        let key = PrivateKey::from_pem(include_bytes!("../../tests/fixtures/tls/server.key"))
            .unwrap()
            .clone_inner();
        let mut roots = rustls::RootCertStore::empty();
        for cert in &chain {
            roots.add(cert.clone()).unwrap();
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let client_config = ClientConfig::builder_with_provider(Arc::clone(&provider))
            .with_protocol_versions(&[version])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let server_config = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[version])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .unwrap();
        let (client_io, server_io) = VirtualTcpStream::pair(
            "127.0.0.1:5260".parse().unwrap(),
            "127.0.0.1:5261".parse().unwrap(),
        );
        let mut client = TlsStream::new_client(
            ZeroIo::new(client_io),
            ClientConnection::new(
                Arc::new(client_config),
                ServerName::try_from("localhost").unwrap(),
            )
            .unwrap(),
        );
        let mut server = TlsStream::new_server(
            ZeroIo::new(server_io),
            ServerConnection::new(Arc::new(server_config)).unwrap(),
        );
        let (client_result, server_result) = zip(
            poll_fn(|cx| client.poll_handshake(cx)),
            poll_fn(|cx| server.poll_handshake(cx)),
        )
        .await;
        client_result.expect("client handshake");
        server_result.expect("server handshake");
        assert_eq!(client.protocol_version(), Some(version.version));
        assert_eq!(server.protocol_version(), Some(version.version));
        test(client, server);
    });
    assert!(runtime.is_quiescent());
}

fn assert_zero_is_terminal(stream: &mut Stream) {
    assert!(stream.is_closed());
    // Restore a writable transport. The TLS failure must remain terminal.
    stream.io.before_zero = None;
    stream.io.block = false;
    let calls = stream.io.calls;
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..3 {
        assert!(matches!(
            Pin::new(&mut *stream).poll_write(&mut cx, b"must not be re-admitted"),
            Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::WriteZero
        ));
        assert!(matches!(
            Pin::new(&mut *stream).poll_flush(&mut cx),
            Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::WriteZero
        ));
        assert!(matches!(
            Pin::new(&mut *stream).poll_shutdown(&mut cx),
            Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::WriteZero
        ));
        assert!(matches!(
            stream.poll_shutdown_tls(&mut cx),
            Poll::Ready(Err(TlsError::Io(error))) if error.kind() == io::ErrorKind::WriteZero
        ));
        let mut bytes = [0; 1];
        let mut buf = ReadBuf::new(&mut bytes);
        assert!(matches!(
            Pin::new(&mut *stream).poll_read(&mut cx, &mut buf),
            Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::WriteZero
        ));
        assert!(buf.filled().is_empty());
        assert!(matches!(
            stream.poll_handshake(&mut cx),
            Poll::Ready(Err(TlsError::Io(error))) if error.kind() == io::ErrorKind::NotConnected
        ));
        assert!(matches!(
            stream.tls_exporter_channel_binding(),
            Err(TlsError::Io(error)) if error.kind() == io::ErrorKind::NotConnected
        ));
        assert!(matches!(
            stream.tls_server_end_point_channel_binding(),
            Err(TlsError::Io(error)) if error.kind() == io::ErrorKind::NotConnected
        ));
        assert_eq!(stream.io.calls, calls, "terminal stream performed more IO");
    }
}

#[test]
fn zero_transport_write_after_acceptance_counts_plaintext_once() {
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        for client_side in [true, false] {
            for partial in [0, 7] {
                run_pair(version, move |mut client, mut server| {
                    let (stream, peer) = if client_side {
                        (&mut client, &mut server)
                    } else {
                        (&mut server, &mut client)
                    };
                    let written = stream.io.written;
                    stream.io.before_zero = Some(partial);
                    let counter = Arc::new(WakeCount::default());
                    let waker = Waker::from(Arc::clone(&counter));
                    let mut cx = Context::from_waker(&waker);
                    let message = [0xA5; 128];
                    assert!(matches!(
                        Pin::new(&mut *stream).poll_write(&mut cx, &message),
                        Poll::Ready(Ok(n)) if n == message.len()
                    ));
                    assert_eq!(stream.io.written - written, partial);
                    assert_eq!(stream.io.zeros, 1);
                    assert_eq!(counter.0.load(Ordering::Relaxed), 0);
                    assert!(stream.conn.wants_write(), "record must still be incomplete");
                    assert_zero_is_terminal(stream);
                    let mut bytes = [0; 256];
                    let mut buf = ReadBuf::new(&mut bytes);
                    assert!(Pin::new(&mut *peer).poll_read(&mut cx, &mut buf).is_pending());
                    assert!(buf.filled().is_empty(), "incomplete record released plaintext");
                });
            }
        }
    }
}

#[test]
fn zero_transport_write_with_full_tls_buffer_returns_error_without_spinning() {
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        for client_side in [true, false] {
            run_pair(version, move |mut client, mut server| {
                let stream = if client_side { &mut client } else { &mut server };
                match &mut stream.conn {
                    TlsConnection::Client(conn) => conn.set_buffer_limit(Some(64)),
                    TlsConnection::Server(conn) => conn.set_buffer_limit(Some(64)),
                }
                let counter = Arc::new(WakeCount::default());
                let waker = Waker::from(Arc::clone(&counter));
                let mut cx = Context::from_waker(&waker);
                stream.io.block = true;
                let prefix = [0x5A; 64];
                assert!(matches!(
                    Pin::new(&mut *stream).poll_write(&mut cx, &prefix),
                    Poll::Ready(Ok(n)) if n == prefix.len()
                ));
                // Witness real rustls backpressure; the probe accepts no bytes.
                assert_eq!(io::Write::write(&mut stream.conn.writer(), b"probe").unwrap(), 0);
                assert!(Pin::new(&mut *stream).poll_write(&mut cx, b"suffix").is_pending());
                assert!(stream.is_ready());
                assert_eq!(stream.io.zeros, 0);
                assert_eq!(counter.0.load(Ordering::Relaxed), 0);
                stream.io.block = false;
                stream.io.before_zero = Some(0);
                stream.io.waiter.take().expect("pending write registered readiness").wake();
                let wakes = counter.0.load(Ordering::Relaxed);
                let calls = stream.io.calls;
                assert!(matches!(
                    Pin::new(&mut *stream).poll_write(&mut cx, b"suffix"),
                    Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::WriteZero
                ));
                assert_eq!(stream.io.zeros, 1);
                assert_eq!(stream.io.calls, calls + 1);
                assert_eq!(counter.0.load(Ordering::Relaxed), wakes, "zero write self-woke");
                assert_zero_is_terminal(stream);
            });
        }
    }
}

#[test]
fn explicit_flush_keeps_its_existing_retryable_write_zero_contract() {
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        for client_side in [true, false] {
            run_pair(version, move |mut client, mut server| {
                let (stream, peer) = if client_side {
                    (&mut client, &mut server)
                } else {
                    (&mut server, &mut client)
                };
                let binding = stream.tls_exporter_channel_binding().ok();
                let mut cx = Context::from_waker(Waker::noop());
                stream.io.block = true;
                let message = b"explicit flush can retry a retained record";
                assert!(matches!(
                    Pin::new(&mut *stream).poll_write(&mut cx, message),
                    Poll::Ready(Ok(n)) if n == message.len()
                ));
                stream.io.block = false;
                stream.io.before_zero = Some(0);
                assert!(matches!(
                    Pin::new(&mut *stream).poll_flush(&mut cx),
                    Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::WriteZero
                ));
                assert!(stream.is_ready() && stream.conn.wants_write());
                assert!(stream.write_error.is_none());
                assert_eq!(stream.tls_exporter_channel_binding().ok(), binding);
                stream.io.before_zero = None;
                assert!(matches!(
                    Pin::new(&mut *stream).poll_flush(&mut cx),
                    Poll::Ready(Ok(()))
                ));
                let mut bytes = [0; 64];
                let mut buf = ReadBuf::new(&mut bytes);
                assert!(matches!(
                    Pin::new(&mut *peer).poll_read(&mut cx, &mut buf),
                    Poll::Ready(Ok(()))
                ));
                assert_eq!(buf.filled(), message);
                let mut buf = ReadBuf::new(&mut bytes);
                assert!(Pin::new(&mut *peer).poll_read(&mut cx, &mut buf).is_pending());
                assert!(buf.filled().is_empty(), "plaintext delivered more than once");
                assert_eq!(stream.tls_exporter_channel_binding().ok(), binding);
                assert_eq!(peer.tls_exporter_channel_binding().ok(), binding);
            });
        }
    }
}
