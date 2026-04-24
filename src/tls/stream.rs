//! TLS stream implementation.
//!
//! This module provides `TlsStream` that wraps an underlying transport stream
//! and implements `AsyncRead` + `AsyncWrite` with TLS encryption.

use super::error::TlsError;
use crate::io::{AsyncRead, AsyncWrite, ReadBuf};

// When tracing integration is enabled, the `debug!/trace!/error!` macros come from `tracing`.
// Import them explicitly so unqualified macro calls in this module compile under all feature sets.
#[cfg(all(feature = "tracing-integration", feature = "tls"))]
use crate::tracing_compat::{debug, error, trace};

#[cfg(feature = "tls")]
use rustls::{ClientConnection, ServerConnection};

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Internal state of the TLS stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TlsState {
    /// Handshake in progress.
    Handshaking,
    /// TLS session is established.
    Ready,
    /// Local write-side shutdown initiated; reads may continue until peer close.
    ShuttingDown,
    /// Connection is closed.
    Closed,
}

/// A TLS stream wrapping an underlying async transport.
///
/// This implements `AsyncRead` and `AsyncWrite`, transparently encrypting
/// and decrypting data over the underlying connection.
///
/// # Cancel-Safety
///
/// - `poll_read` is cancel-safe (partial reads don't lose data)
/// - `poll_write` is NOT cancel-safe during handshake
/// - `poll_shutdown` is NOT cancel-safe
#[cfg(feature = "tls")]
pub struct TlsStream<IO> {
    io: IO,
    conn: TlsConnection,
    state: TlsState,
    read_closed: bool,
}

/// Fallback `TlsStream` when TLS is disabled.
#[cfg(not(feature = "tls"))]
pub struct TlsStream<IO> {
    io: IO,
    _state: TlsState,
}

/// Wrapper to handle both client and server connections.
#[cfg(feature = "tls")]
enum TlsConnection {
    Client(ClientConnection),
    Server(ServerConnection),
}

#[cfg(feature = "tls")]
impl TlsConnection {
    fn is_handshaking(&self) -> bool {
        match self {
            Self::Client(c) => c.is_handshaking(),
            Self::Server(s) => s.is_handshaking(),
        }
    }

    fn wants_read(&self) -> bool {
        match self {
            Self::Client(c) => c.wants_read(),
            Self::Server(s) => s.wants_read(),
        }
    }

    fn wants_write(&self) -> bool {
        match self {
            Self::Client(c) => c.wants_write(),
            Self::Server(s) => s.wants_write(),
        }
    }

    fn reader(&mut self) -> rustls::Reader<'_> {
        match self {
            Self::Client(c) => c.reader(),
            Self::Server(s) => s.reader(),
        }
    }

    fn writer(&mut self) -> rustls::Writer<'_> {
        match self {
            Self::Client(c) => c.writer(),
            Self::Server(s) => s.writer(),
        }
    }

    fn read_tls(&mut self, rd: &mut dyn io::Read) -> io::Result<usize> {
        match self {
            Self::Client(c) => c.read_tls(rd),
            Self::Server(s) => s.read_tls(rd),
        }
    }

    fn write_tls(&mut self, wr: &mut dyn io::Write) -> io::Result<usize> {
        match self {
            Self::Client(c) => c.write_tls(wr),
            Self::Server(s) => s.write_tls(wr),
        }
    }

    fn process_new_packets(&mut self) -> Result<rustls::IoState, rustls::Error> {
        match self {
            Self::Client(c) => c.process_new_packets(),
            Self::Server(s) => s.process_new_packets(),
        }
    }

    fn send_close_notify(&mut self) {
        match self {
            Self::Client(c) => c.send_close_notify(),
            Self::Server(s) => s.send_close_notify(),
        }
    }

    fn protocol_version(&self) -> Option<rustls::ProtocolVersion> {
        match self {
            Self::Client(c) => c.protocol_version(),
            Self::Server(s) => s.protocol_version(),
        }
    }

    fn alpn_protocol(&self) -> Option<&[u8]> {
        match self {
            Self::Client(c) => c.alpn_protocol(),
            Self::Server(s) => s.alpn_protocol(),
        }
    }

    fn sni_hostname(&self) -> Option<&str> {
        match self {
            Self::Client(_) => None,
            Self::Server(s) => s.server_name(),
        }
    }
}

#[cfg(feature = "tls")]
impl<IO> TlsStream<IO> {
    /// Create a new client TLS stream.
    pub(crate) fn new_client(io: IO, conn: ClientConnection) -> Self {
        Self {
            io,
            conn: TlsConnection::Client(conn),
            state: TlsState::Handshaking,
            read_closed: false,
        }
    }

    /// Create a new server TLS stream.
    pub(crate) fn new_server(io: IO, conn: ServerConnection) -> Self {
        Self {
            io,
            conn: TlsConnection::Server(conn),
            state: TlsState::Handshaking,
            read_closed: false,
        }
    }

    /// Get the negotiated ALPN protocol.
    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        self.conn.alpn_protocol()
    }

    /// Get the TLS protocol version.
    pub fn protocol_version(&self) -> Option<rustls::ProtocolVersion> {
        self.conn.protocol_version()
    }

    /// Get the SNI hostname (server-side only).
    pub fn sni_hostname(&self) -> Option<&str> {
        self.conn.sni_hostname()
    }

    /// Get a reference to the underlying IO.
    pub fn get_ref(&self) -> &IO {
        &self.io
    }

    /// Get a mutable reference to the underlying IO.
    pub fn get_mut(&mut self) -> &mut IO {
        &mut self.io
    }

    /// Destructure into underlying IO (discards TLS state).
    pub fn into_inner(self) -> IO {
        self.io
    }

    /// Check if the TLS session is established.
    pub fn is_ready(&self) -> bool {
        self.state == TlsState::Ready
    }

    /// Check if the connection is closed.
    pub fn is_closed(&self) -> bool {
        self.state == TlsState::Closed
    }

    fn note_read_eof(&mut self) {
        self.read_closed = true;
        if self.state == TlsState::ShuttingDown {
            self.state = TlsState::Closed;
        }
    }
}

#[cfg(not(feature = "tls"))]
impl<IO> TlsStream<IO> {
    /// Get a reference to the underlying IO.
    pub fn get_ref(&self) -> &IO {
        &self.io
    }

    /// Get a mutable reference to the underlying IO.
    pub fn get_mut(&mut self) -> &mut IO {
        &mut self.io
    }

    /// Destructure into underlying IO.
    pub fn into_inner(self) -> IO {
        self.io
    }
}

#[cfg(feature = "tls")]
impl<IO: AsyncRead + AsyncWrite + Unpin> TlsStream<IO> {
    /// Poll the TLS handshake to completion.
    ///
    /// Returns `Poll::Ready(Ok(()))` when handshake is complete.
    pub fn poll_handshake(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), TlsError>> {
        loop {
            // Process any pending TLS data
            if let Err(e) = self.conn.process_new_packets() {
                #[cfg(feature = "tracing-integration")]
                error!(error = %e, "TLS error during handshake");
                self.state = TlsState::Closed;
                return Poll::Ready(Err(TlsError::Handshake(e.to_string())));
            }

            let mut write_would_block = false;
            while self.conn.wants_write() {
                match self.poll_write_tls(cx) {
                    Poll::Ready(Ok(0)) => {
                        self.state = TlsState::Closed;
                        return Poll::Ready(Err(TlsError::Handshake(
                            "connection closed during handshake".into(),
                        )));
                    }
                    Poll::Ready(Ok(_)) => {}
                    Poll::Ready(Err(e)) => {
                        self.state = TlsState::Closed;
                        return Poll::Ready(Err(TlsError::Io(e)));
                    }
                    Poll::Pending => {
                        write_would_block = true;
                        break;
                    }
                }
            }

            // Check if handshake is complete (after flushing writes)
            if !self.conn.is_handshaking() {
                self.state = TlsState::Ready;
                #[cfg(feature = "tracing-integration")]
                debug!("TLS handshake complete");
                return Poll::Ready(Ok(()));
            }

            // Read TLS data if expected
            if self.conn.wants_read() {
                match self.poll_read_tls(cx) {
                    Poll::Ready(Ok(0)) => {
                        self.state = TlsState::Closed;
                        return Poll::Ready(Err(TlsError::Handshake(
                            "connection closed during handshake".into(),
                        )));
                    }
                    Poll::Ready(Ok(_)) => {}
                    Poll::Ready(Err(e)) => {
                        self.state = TlsState::Closed;
                        return Poll::Ready(Err(TlsError::Io(e)));
                    }
                    Poll::Pending => return Poll::Pending,
                }
            } else if write_would_block {
                // Can't write and nothing to read - we're blocked on write
                return Poll::Pending;
            }
        }
    }

    fn poll_read_tls(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        struct AsyncReadAdapter<'a, 'b, IO> {
            io: &'a mut IO,
            cx: &'a mut Context<'b>,
        }

        impl<IO: AsyncRead + Unpin> io::Read for AsyncReadAdapter<'_, '_, IO> {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                let mut read_buf = ReadBuf::new(buf);
                match Pin::new(&mut *self.io).poll_read(self.cx, &mut read_buf) {
                    Poll::Ready(Ok(())) => Ok(read_buf.filled().len()),
                    Poll::Ready(Err(e)) => Err(e),
                    Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
                }
            }
        }

        let mut adapter = AsyncReadAdapter {
            io: &mut self.io,
            cx,
        };

        match self.conn.read_tls(&mut adapter) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    fn poll_write_tls(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        struct AsyncWriteAdapter<'a, 'b, IO> {
            io: &'a mut IO,
            cx: &'a mut Context<'b>,
        }

        impl<IO: AsyncWrite + Unpin> io::Write for AsyncWriteAdapter<'_, '_, IO> {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                match Pin::new(&mut *self.io).poll_write(self.cx, buf) {
                    Poll::Ready(Ok(n)) => Ok(n),
                    Poll::Ready(Err(e)) => Err(e),
                    Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
                }
            }

            fn flush(&mut self) -> io::Result<()> {
                match Pin::new(&mut *self.io).poll_flush(self.cx) {
                    Poll::Ready(Ok(())) => Ok(()),
                    Poll::Ready(Err(e)) => Err(e),
                    Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
                }
            }
        }

        let mut adapter = AsyncWriteAdapter {
            io: &mut self.io,
            cx,
        };

        match self.conn.write_tls(&mut adapter) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    /// Poll for graceful TLS shutdown.
    pub fn poll_shutdown_tls(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), TlsError>> {
        if self.state == TlsState::Closed {
            return Poll::Ready(Ok(()));
        }

        // Send close_notify if not already done
        if self.state != TlsState::ShuttingDown {
            #[cfg(feature = "tracing-integration")]
            debug!("Initiating TLS shutdown");
            self.state = TlsState::ShuttingDown;
            self.conn.send_close_notify();
        }

        // Flush the close_notify
        while self.conn.wants_write() {
            match self.poll_write_tls(cx) {
                Poll::Ready(Ok(0)) => break,
                Poll::Ready(Ok(_)) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(TlsError::Io(e))),
                Poll::Pending => return Poll::Pending,
            }
        }

        if self.read_closed {
            self.state = TlsState::Closed;
            #[cfg(feature = "tracing-integration")]
            debug!("TLS shutdown complete");
        } else {
            #[cfg(feature = "tracing-integration")]
            debug!("TLS close_notify flushed; awaiting peer EOF");
        }
        Poll::Ready(Ok(()))
    }
}

#[cfg(feature = "tls")]
impl<IO: AsyncRead + AsyncWrite + Unpin> AsyncRead for TlsStream<IO> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        if self.read_closed || self.state == TlsState::Closed {
            return Poll::Ready(Ok(()));
        }

        // If still handshaking, complete handshake first
        if self.state == TlsState::Handshaking {
            match self.poll_handshake(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => {
                    // poll_handshake already updates state to Closed on failure
                    return Poll::Ready(Err(io::Error::other(e)));
                }
                Poll::Pending => return Poll::Pending,
            }
        }

        loop {
            // Try to read from the decrypted buffer
            match io::Read::read(&mut self.conn.reader(), buf.unfilled()) {
                Ok(n) => {
                    buf.advance(n);
                    if n > 0 {
                        #[cfg(feature = "tracing-integration")]
                        trace!(bytes = n, "TLS read");
                        return Poll::Ready(Ok(()));
                    }
                    // Reader EOF: no more plaintext can arrive.
                    self.note_read_eof();
                    return Poll::Ready(Ok(()));
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Poll::Ready(Err(e)),
            }

            // Need more data - read from underlying IO
            match self.poll_read_tls(cx) {
                Poll::Ready(Ok(0)) => {
                    // Transport EOF without close_notify (since Reader::read didn't return Ok(0))
                    self.state = TlsState::Closed;
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "tls connection closed without close_notify",
                    )));
                }
                Poll::Ready(Ok(_)) => {
                    // Process the new TLS data
                    if let Err(e) = self.conn.process_new_packets() {
                        self.state = TlsState::Closed;
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            e.to_string(),
                        )));
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

#[cfg(feature = "tls")]
impl<IO: AsyncRead + AsyncWrite + Unpin> AsyncWrite for TlsStream<IO> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.state == TlsState::ShuttingDown || self.state == TlsState::Closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "TLS write side closed",
            )));
        }

        // If still handshaking, complete handshake first
        if self.state == TlsState::Handshaking {
            match self.poll_handshake(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => {
                    return Poll::Ready(Err(io::Error::other(e)));
                }
                Poll::Pending => return Poll::Pending,
            }
        }

        // Write to the TLS session
        let n = io::Write::write(&mut self.conn.writer(), buf)?;
        #[cfg(feature = "tracing-integration")]
        trace!(bytes = n, "TLS write");

        // When rustls returns Ok(0) with a non-empty buffer, the internal
        // plaintext buffer is full. Flush pending TLS records to make room,
        // then retry. Returning Ok(0) would cause write_all() to raise
        // WriteZero, which is not a real error in this situation.
        if n == 0 && !buf.is_empty() {
            while self.conn.wants_write() {
                match self.poll_write_tls(cx) {
                    Poll::Ready(Ok(0)) => break,
                    Poll::Ready(Ok(_)) => {}
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }
            let retry = io::Write::write(&mut self.conn.writer(), buf)?;
            #[cfg(feature = "tracing-integration")]
            trace!(bytes = retry, "TLS write retry after flush");
            if retry == 0 {
                // Buffer still full after flushing.  Schedule an immediate
                // re-poll so we don't hang — the flush loop above may have
                // completed entirely via Ready, leaving no waker registered.
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            return Poll::Ready(Ok(retry));
        }

        // Flush encrypted data to underlying IO
        while self.conn.wants_write() {
            match self.poll_write_tls(cx) {
                Poll::Ready(Ok(0)) => break,
                Poll::Ready(Ok(_)) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {
                    // If we wrote some data to the TLS session, report success
                    if n > 0 {
                        return Poll::Ready(Ok(n));
                    }
                    return Poll::Pending;
                }
            }
        }

        Poll::Ready(Ok(n))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Flush any pending TLS data
        while self.conn.wants_write() {
            match self.poll_write_tls(cx) {
                Poll::Ready(Ok(0)) => break,
                Poll::Ready(Ok(_)) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        // Flush underlying IO
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.state == TlsState::Closed {
            return Pin::new(&mut self.io).poll_shutdown(cx);
        }

        // Send close_notify if not already done
        if self.state != TlsState::ShuttingDown {
            self.state = TlsState::ShuttingDown;
            self.conn.send_close_notify();
        }

        // Flush the close_notify
        while self.conn.wants_write() {
            match self.poll_write_tls(cx) {
                Poll::Ready(Ok(0)) => break,
                Poll::Ready(Ok(_)) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        // Shutdown underlying IO. Reads may continue until the peer closes.
        match Pin::new(&mut self.io).poll_shutdown(cx) {
            Poll::Ready(Ok(())) => {
                if self.read_closed {
                    self.state = TlsState::Closed;
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<IO: std::fmt::Debug> std::fmt::Debug for TlsStream<IO> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        #[cfg(feature = "tls")]
        {
            f.debug_struct("TlsStream")
                .field("io", &self.io)
                .field("state", &self.state)
                .finish_non_exhaustive()
        }
        #[cfg(not(feature = "tls"))]
        {
            f.debug_struct("TlsStream")
                .field("io", &self.io)
                .finish_non_exhaustive()
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    #[cfg(feature = "tls")]
    use crate::conformance::{ConformanceTarget, LabRuntimeTarget, TestConfig};
    #[cfg(feature = "tls")]
    use crate::net::tcp::VirtualTcpStream;
    #[cfg(feature = "tls")]
    use crate::test_utils::init_test_logging;
    #[cfg(feature = "tls")]
    use crate::tls::{
        Certificate, CertificateChain, PrivateKey, TlsAcceptorBuilder, TlsConnectorBuilder,
    };
    #[cfg(feature = "tls")]
    use futures_lite::future::{poll_fn, zip};
    #[cfg(feature = "tls")]
    use rustls::ClientConnection;
    #[cfg(feature = "tls")]
    use rustls::ServerConnection;
    #[cfg(feature = "tls")]
    use rustls::pki_types::ServerName;
    #[cfg(feature = "tls")]
    use std::sync::Arc;

    #[cfg(feature = "tls")]
    const TEST_CERT_PEM: &[u8] = include_bytes!("../../tests/fixtures/tls/server.crt");
    #[cfg(feature = "tls")]
    const TEST_KEY_PEM: &[u8] = include_bytes!("../../tests/fixtures/tls/server.key");

    #[test]
    fn test_tls_state_transitions() {
        assert_ne!(TlsState::Handshaking, TlsState::Ready);
        assert_ne!(TlsState::Ready, TlsState::ShuttingDown);
        assert_ne!(TlsState::ShuttingDown, TlsState::Closed);
    }

    #[test]
    fn tls_state_self_equality() {
        assert_eq!(TlsState::Handshaking, TlsState::Handshaking);
        assert_eq!(TlsState::Ready, TlsState::Ready);
        assert_eq!(TlsState::ShuttingDown, TlsState::ShuttingDown);
        assert_eq!(TlsState::Closed, TlsState::Closed);
    }

    #[test]
    fn tls_state_exhaustive_inequality() {
        let states = [
            TlsState::Handshaking,
            TlsState::Ready,
            TlsState::ShuttingDown,
            TlsState::Closed,
        ];
        for (i, a) in states.iter().enumerate() {
            for (j, b) in states.iter().enumerate() {
                if i == j {
                    assert_eq!(a, b);
                } else {
                    assert_ne!(a, b);
                }
            }
        }
    }

    #[test]
    fn tls_state_debug() {
        assert_eq!(format!("{:?}", TlsState::Handshaking), "Handshaking");
        assert_eq!(format!("{:?}", TlsState::Ready), "Ready");
        assert_eq!(format!("{:?}", TlsState::ShuttingDown), "ShuttingDown");
        assert_eq!(format!("{:?}", TlsState::Closed), "Closed");
    }

    #[test]
    fn tls_state_clone_and_copy() {
        let state = TlsState::Ready;
        let copied = state; // Copy
        let cloned = state; // Clone
        assert_eq!(state, copied);
        assert_eq!(state, cloned);
    }

    #[cfg(feature = "tls")]
    #[test]
    fn tls_stream_handshake_completes_under_lab_runtime() {
        init_test_logging();
        let config = TestConfig::new()
            .with_seed(0x715A_CCE8)
            .with_tracing(true)
            .with_max_steps(20_000);
        let mut runtime = LabRuntimeTarget::create_runtime(config);

        let (
            client_state_ready,
            server_state_ready,
            client_protocol,
            server_protocol,
            client_alpn,
            server_alpn,
            checkpoints,
        ) = LabRuntimeTarget::block_on(&mut runtime, async move {
            let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
            let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
            let acceptor = TlsAcceptorBuilder::new(chain, key)
                .alpn_http()
                .build()
                .unwrap();

            let certs = Certificate::from_pem(TEST_CERT_PEM).unwrap();
            let connector = TlsConnectorBuilder::new()
                .add_root_certificates(certs)
                .alpn_http()
                .build()
                .unwrap();

            let server_name = ServerName::try_from("localhost".to_string()).unwrap();
            let client_conn =
                ClientConnection::new(Arc::clone(connector.config()), server_name).unwrap();
            let server_conn = ServerConnection::new(Arc::clone(acceptor.config())).unwrap();

            let (client_io, server_io) = VirtualTcpStream::pair(
                "127.0.0.1:5200".parse().unwrap(),
                "127.0.0.1:5201".parse().unwrap(),
            );

            let mut client_stream = TlsStream::new_client(client_io, client_conn);
            let mut server_stream = TlsStream::new_server(server_io, server_conn);

            let checkpoints = vec![serde_json::json!({
                "phase": "tls_stream_handshake_started",
                "client_state": format!("{:?}", client_stream.state),
                "server_state": format!("{:?}", server_stream.state),
                "client_addr": "127.0.0.1:5200",
                "server_addr": "127.0.0.1:5201",
            })];
            for checkpoint in &checkpoints {
                tracing::info!(event = %checkpoint, "tls_stream_lab_checkpoint");
            }

            let (client_result, server_result) = zip(
                poll_fn(|cx| client_stream.poll_handshake(cx)),
                poll_fn(|cx| server_stream.poll_handshake(cx)),
            )
            .await;
            client_result.expect("client handshake should succeed");
            server_result.expect("server handshake should succeed");

            let client_state_ready =
                client_stream.state == TlsState::Ready && client_stream.is_ready();
            let server_state_ready =
                server_stream.state == TlsState::Ready && server_stream.is_ready();
            let client_protocol = client_stream.protocol_version().is_some();
            let server_protocol = server_stream.protocol_version().is_some();
            let client_alpn = client_stream
                .alpn_protocol()
                .map(|protocol| protocol.to_vec());
            let server_alpn = server_stream
                .alpn_protocol()
                .map(|protocol| protocol.to_vec());

            let mut checkpoints = checkpoints;
            checkpoints.push(serde_json::json!({
                "phase": "tls_stream_handshake_completed",
                "client_state": format!("{:?}", client_stream.state),
                "server_state": format!("{:?}", server_stream.state),
                "client_protocol_present": client_protocol,
                "server_protocol_present": server_protocol,
                "client_alpn": client_alpn.as_ref().map(|protocol| String::from_utf8_lossy(protocol).to_string()),
                "server_alpn": server_alpn.as_ref().map(|protocol| String::from_utf8_lossy(protocol).to_string()),
            }));
            tracing::info!(event = %checkpoints[1], "tls_stream_lab_checkpoint");

            (
                client_state_ready,
                server_state_ready,
                client_protocol,
                server_protocol,
                client_alpn,
                server_alpn,
                checkpoints,
            )
        });

        assert!(client_state_ready);
        assert!(server_state_ready);
        assert!(client_protocol);
        assert!(server_protocol);
        assert_eq!(client_alpn.as_deref(), Some(b"h2".as_slice()));
        assert_eq!(server_alpn.as_deref(), Some(b"h2".as_slice()));
        assert_eq!(checkpoints.len(), 2);
        assert!(runtime.is_quiescent());
    }
}
