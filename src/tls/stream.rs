//! TLS stream implementation.
//!
//! This module provides `TlsStream` that wraps an underlying transport stream
//! and implements `AsyncRead` + `AsyncWrite` with TLS encryption.

#[cfg(feature = "tls")]
use super::error::TlsError;
#[cfg(feature = "tls")]
use crate::io::{AsyncRead, AsyncWrite, ReadBuf};

// When tracing integration is enabled, the `debug!/trace!/error!` macros come from `tracing`.
// Import them explicitly so unqualified macro calls in this module compile under all feature sets.
#[cfg(all(feature = "tracing-integration", feature = "tls"))]
use crate::tracing_compat::{debug, error, trace};

#[cfg(feature = "tls")]
use rustls::{ClientConnection, ServerConnection};

#[cfg(feature = "tls")]
use std::io;
#[cfg(feature = "tls")]
use std::pin::Pin;
#[cfg(feature = "tls")]
use std::task::{Context, Poll};

/// Internal state of the TLS stream.
#[cfg(any(feature = "tls", test))]
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

#[cfg(any(feature = "tls", test))]
impl TlsState {
    const fn requires_handshake(self) -> bool {
        matches!(self, Self::Handshaking)
    }

    const fn allows_application_io(self) -> bool {
        matches!(self, Self::Ready)
    }

    const fn shutdown_pending(self) -> bool {
        matches!(self, Self::ShuttingDown)
    }

    const fn is_terminal(self) -> bool {
        matches!(self, Self::Closed)
    }
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
    _marker: std::marker::PhantomData<()>,
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

    /// Leaf peer certificate (DER bytes), if the handshake produced one.
    /// Used by PostgreSQL SCRAM-SHA-256-PLUS channel binding
    /// (br-asupersync-7n2xsi).
    fn peer_leaf_certificate_der(&self) -> Option<Vec<u8>> {
        let certs = match self {
            Self::Client(c) => c.peer_certificates(),
            Self::Server(s) => s.peer_certificates(),
        }?;
        let leaf = certs.first()?;
        Some(leaf.as_ref().to_vec())
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

    /// Returns the DER-encoded leaf peer certificate, if the handshake
    /// produced one. Required by PostgreSQL SCRAM-SHA-256-PLUS channel
    /// binding (RFC 5929 `tls-server-end-point`). Returns `None` before
    /// the handshake is complete or when the peer presented no
    /// certificate. (br-asupersync-7n2xsi)
    pub fn peer_leaf_certificate_der(&self) -> Option<Vec<u8>> {
        self.conn.peer_leaf_certificate_der()
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
        self.state.allows_application_io()
    }

    /// Check if the connection is closed.
    pub fn is_closed(&self) -> bool {
        self.state.is_terminal()
    }

    fn note_read_eof(&mut self) {
        self.read_closed = true;
        if self.state.shutdown_pending() {
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
        let mut steps = 0;
        loop {
            steps += 1;
            if steps >= 64 {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }

            // Process any pending TLS data
            if let Err(e) = self.conn.process_new_packets() {
                #[cfg(feature = "tracing-integration")]
                error!(error = %e, "TLS error during handshake");
                self.flush_alert_best_effort(cx);
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
            // A transport may hold written bytes until flushed (a buffered
            // writer, a tunnel that frames on flush), and the peer cannot
            // answer a flight it never received.
            if !write_would_block {
                match Pin::new(&mut self.io).poll_flush(cx) {
                    Poll::Ready(Ok(())) => {}
                    Poll::Ready(Err(e)) => {
                        self.state = TlsState::Closed;
                        return Poll::Ready(Err(TlsError::Io(e)));
                    }
                    Poll::Pending => write_would_block = true,
                }
            }

            // Check if handshake is complete (after flushing writes)
            if !self.conn.is_handshaking() {
                // The final flight (a TLS 1.3 client's Finished, a TLS 1.2
                // server's ChangeCipherSpec and Finished) must reach the
                // transport first: a caller that then only reads would wait
                // for a peer that is waiting for these bytes.
                if write_would_block {
                    return Poll::Pending;
                }
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

    /// Best-effort send of the records rustls queued before failing: the
    /// fatal alert that names the reason (RFC 8446 §6.2), for example a
    /// refused client certificate. Without it the peer sees a bare EOF and
    /// cannot tell a refusal from a dropped connection, so it retries
    /// (br-asupersync-bi2462.86.3). Never waits: a write that would block
    /// abandons the alert.
    fn flush_alert_best_effort(&mut self, cx: &mut Context<'_>) {
        while self.conn.wants_write() {
            match self.poll_write_tls(cx) {
                Poll::Ready(Ok(written)) if written > 0 => {}
                _ => break,
            }
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
        if self.state.is_terminal() {
            return Poll::Ready(Ok(()));
        }

        // Send close_notify if not already done
        if !self.state.shutdown_pending() {
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

        if self.read_closed || self.state.is_terminal() {
            return Poll::Ready(Ok(()));
        }

        // If still handshaking, complete handshake first
        if self.state.requires_handshake() {
            match self.poll_handshake(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => {
                    // poll_handshake already updates state to Closed on failure
                    return Poll::Ready(Err(io::Error::other(e)));
                }
                Poll::Pending => return Poll::Pending,
            }
        }

        let mut steps = 0;
        loop {
            steps += 1;
            if steps >= 64 {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }

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
                        self.flush_alert_best_effort(cx);
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
        if self.state.shutdown_pending() || self.state.is_terminal() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "TLS write side closed",
            )));
        }

        // If still handshaking, complete handshake first
        if self.state.requires_handshake() {
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
        if self.state.is_terminal() {
            return Pin::new(&mut self.io).poll_shutdown(cx);
        }

        // Send close_notify if not already done
        if !self.state.shutdown_pending() {
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
    fn tls_state_lifecycle_classifiers_are_exclusive() {
        let cases = [
            (TlsState::Handshaking, true, false, false, false),
            (TlsState::Ready, false, true, false, false),
            (TlsState::ShuttingDown, false, false, true, false),
            (TlsState::Closed, false, false, false, true),
        ];

        for (state, requires_handshake, allows_io, shutdown_pending, terminal) in cases {
            assert_eq!(state.requires_handshake(), requires_handshake);
            assert_eq!(state.allows_application_io(), allows_io);
            assert_eq!(state.shutdown_pending(), shutdown_pending);
            assert_eq!(state.is_terminal(), terminal);
        }
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

    #[cfg(feature = "tls")]
    #[test]
    fn handshake_failure_sends_its_alert_instead_of_a_bare_close() {
        init_test_logging();
        let config = TestConfig::new()
            .with_seed(0xA1E7_0001)
            .with_max_steps(20_000);
        let mut runtime = LabRuntimeTarget::create_runtime(config);

        let (client_error, server_error) = LabRuntimeTarget::block_on(&mut runtime, async move {
            let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
            let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
            // The server speaks only h2 and the client offers only an unknown
            // protocol, so rustls refuses the ClientHello with a
            // no_application_protocol alert while the server is handshaking.
            let acceptor = TlsAcceptorBuilder::new(chain, key)
                .alpn_protocols(vec![b"h2".to_vec()])
                .build()
                .unwrap();
            let certs = Certificate::from_pem(TEST_CERT_PEM).unwrap();
            let connector = TlsConnectorBuilder::new()
                .add_root_certificates(certs)
                .alpn_protocols(vec![b"x-unknown".to_vec()])
                .build()
                .unwrap();

            let server_name = ServerName::try_from("localhost".to_string()).unwrap();
            let client_conn =
                ClientConnection::new(Arc::clone(connector.config()), server_name).unwrap();
            let server_conn = ServerConnection::new(Arc::clone(acceptor.config())).unwrap();
            let (client_io, server_io) = VirtualTcpStream::pair(
                "127.0.0.1:5210".parse().unwrap(),
                "127.0.0.1:5211".parse().unwrap(),
            );
            let mut client_stream = TlsStream::new_client(client_io, client_conn);
            let mut server_stream = TlsStream::new_server(server_io, server_conn);
            let server = async move {
                let result = poll_fn(|cx| server_stream.poll_handshake(cx)).await;
                // An acceptor closes right after a failed handshake, so only
                // bytes already written can reach the client.
                drop(server_stream);
                result
            };
            let (client_result, server_result) =
                zip(poll_fn(|cx| client_stream.poll_handshake(cx)), server).await;
            (
                client_result.expect_err("the client handshake must fail"),
                server_result.expect_err("the server refuses the ALPN offer"),
            )
        });

        let client_error = client_error.to_string();
        tracing::info!(%client_error, server_error = %server_error, "tls_alert_delivery");
        assert!(
            client_error.contains("received fatal alert"),
            "the client must learn why the server refused, not see a bare close: {client_error}"
        );
        assert!(runtime.is_quiescent());
    }

    /// Public parser fixture from rustls-pemfile 2.2.0 tests/data/crl.pem
    /// (Apache-2.0 / ISC / MIT), issued by "ponytown RSA CA", which did not
    /// issue the test certificate.
    #[cfg(feature = "tls")]
    const OTHER_ISSUER_CRL_PEM: &[u8] = b"-----BEGIN X509 CRL-----\n\
MIICiTBzAgEBMA0GCSqGSIb3DQEBCwUAMBoxGDAWBgNVBAMMD3Bvbnl0b3duIFJT\n\
QSBDQRcNMjMwNjI3MDgyODEyWhcNMjMwNzI3MDgyODEyWjAVMBMCAgHIFw0yMzA2\n\
MjcwODI3NTlaoA4wDDAKBgNVHRQEAwIBAjANBgkqhkiG9w0BAQsFAAOCAgEAP6EX\n\
9+hxjx/AqdBpynZXjGkEqigBcLcJ2PADOXngdQI1jC0WuYnZymUimemeULtt8X+1\n\
ai2KxAuF1m4NEKZsrGKvO+/9s/X1xbGroyHSAMKtZafFopFpoB2aNbYlx7yIyLtD\n\
BBIZIF50g20U+3izqpHutTD10itdk9TLsSceJHpwTkNJtaWMkOfBV28nKzEzVutV\n\
f6WzRpURGzui6nQy7aIqImeanpoBoz323psMfC32U0uMBCZltyHNqsX58/2Uhucx\n\
0IPnitNuhv4scCPf/jeRfGIWDrTf1/25LDzRxyg1S4z9aa+3GM4O3dqy4igZEhgT\n\
q3pjlJ2hUL5E0oqbZDIQD1SN8UUUv5N2AjwZcxVBNnYeGyuO7YpTBYiu62o73iL2\n\
CjgElfaMq/9hEr9GR9kJozh7VTxtQPbnr4DiucQvhv8o/A1z+zkC0gj8iCLFtDbO\n\
8bvDowcdle9LKkrLaBe6sO+fSH/I9Wj8vrEJKsuwaEraIdEaq2VrIMUPEWN0/MH9\n\
vTwHyadGSMK4CWtrn9fCAgSLw6NX74D7Cx1IaS8vstMjpeUqOS0dk5ThiW47HceB\n\
DTko7rV5N+RGH2nW1ynLoZKCJQqqZcLilFMyKPui3jifJnQlMFi54jGVgg/D6UQn\n\
7dA7wb2ux/1hSiaarp+mi7ncVOyByz6/WQP8mfc=\n\
-----END X509 CRL-----\n";

    /// A CRL from the self-signed test certificate's own key that revokes
    /// that certificate (serial 319CCC27...6C4B), next update 2126. Made with
    /// `openssl ca -gencrl -keyfile server.key -cert server.crt` from an
    /// index.txt holding one revoked entry for that serial.
    #[cfg(feature = "tls")]
    const TEST_CERT_REVOKED_CRL_PEM: &[u8] = b"-----BEGIN X509 CRL-----\n\
MIIB3TCBxgIBATANBgkqhkiG9w0BAQsFADBZMQswCQYDVQQGEwJVUzENMAsGA1UE\n\
CAwEVGVzdDENMAsGA1UEBwwEVGVzdDEYMBYGA1UECgwPQXN1cGVyU3luYyBUZXN0\n\
MRIwEAYDVQQDDAlsb2NhbGhvc3QXDTI2MTAwMzA0MTUwM1oYDzIxMjYwOTA5MDQx\n\
NTAzWjAnMCUCFDGczCdzSv8IrxFdAMI2QzZLLGxLFw0yNjEwMDMwMDAwMDBaoA4w\n\
DDAKBgNVHRQEAwIBATANBgkqhkiG9w0BAQsFAAOCAQEAczvy8Gclb2L+egBA3XVH\n\
iEb9PUNXFIm0BdsaN0dEpaQ+x1TTzIqrjcIuPWJjum0v5mmgeWXJyVHtJUrWB5B1\n\
bXyCqElzV/hKSqJLhGKUwhWOIZLd5kWOPGmSoO291xbsOcaDEG4DsOhobduBjP/z\n\
mj+NAAVGjaJKuGdbrzT1NVH6qkW4G0n+ZOuZf5CH3E90H0Bu+6lcJpYPpNGSFY0f\n\
4ZR9OkSx0eA+5EF7ThORH1LUGGbGpz5mLM6PSLN0571E3/pO7djtbceRr0rASxGG\n\
A4sj3J3HjUEnUUo0RKuVI+krlZN2dhvYvdazj/6Bcp05YiMVCJpGuoNADgg6KxKY\n\
jg==\n\
-----END X509 CRL-----\n";

    /// Handshakes against the test certificate with `crl_pem` configured on
    /// the client, and returns the client's and the server's results.
    #[cfg(feature = "tls")]
    fn handshake_with_client_crl(
        seed: u64,
        crl_pem: &'static [u8],
    ) -> (Result<(), TlsError>, Result<(), TlsError>) {
        let config = TestConfig::new().with_seed(seed).with_max_steps(20_000);
        let mut runtime = LabRuntimeTarget::create_runtime(config);
        let results = LabRuntimeTarget::block_on(&mut runtime, async move {
            let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
            let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
            let acceptor = TlsAcceptorBuilder::new(chain, key).build().unwrap();
            let certs = Certificate::from_pem(TEST_CERT_PEM).unwrap();
            let connector = TlsConnectorBuilder::new()
                .add_root_certificates(certs)
                .with_crl_pem(crl_pem)
                .build()
                .unwrap();

            let server_name = ServerName::try_from("localhost".to_string()).unwrap();
            let client_conn =
                ClientConnection::new(Arc::clone(connector.config()), server_name).unwrap();
            let server_conn = ServerConnection::new(Arc::clone(acceptor.config())).unwrap();
            let (client_io, server_io) = VirtualTcpStream::pair(
                "127.0.0.1:5220".parse().unwrap(),
                "127.0.0.1:5221".parse().unwrap(),
            );
            let mut client_stream = TlsStream::new_client(client_io, client_conn);
            let mut server_stream = TlsStream::new_server(server_io, server_conn);
            // Both streams stay open until both handshakes return: a TLS 1.3
            // server writes its session tickets after the client's Finished,
            // and a client that had already closed would fail that write.
            let client = async move {
                let result = poll_fn(|cx| client_stream.poll_handshake(cx)).await;
                (result, client_stream)
            };
            let server = async move {
                let result = poll_fn(|cx| server_stream.poll_handshake(cx)).await;
                (result, server_stream)
            };
            let ((client_result, client_stream), (server_result, server_stream)) =
                zip(client, server).await;
            drop((client_stream, server_stream));
            (client_result, server_result)
        });
        assert!(runtime.is_quiescent());
        results
    }

    #[cfg(feature = "tls")]
    #[test]
    fn a_crl_for_another_issuer_does_not_refuse_the_handshake() {
        init_test_logging();
        // A CRL covers only the certificates its issuer signed. Configuring
        // one CA's CRL must not refuse servers whose CA has none, or a CRL
        // for a private CA would break every public host.
        let (client, server) = handshake_with_client_crl(0xC41_0001, OTHER_ISSUER_CRL_PEM);
        tracing::info!(client = ?client, server = ?server, "tls_crl_other_issuer");
        client.expect("a certificate whose issuer has no CRL is accepted");
        server.expect("the server handshake completes");
    }

    #[cfg(feature = "tls")]
    #[test]
    fn a_certificate_revoked_by_its_issuers_crl_is_refused() {
        init_test_logging();
        let (client, _server) = handshake_with_client_crl(0xC41_0002, TEST_CERT_REVOKED_CRL_PEM);
        let error = client
            .expect_err("a revoked certificate must be refused")
            .to_string();
        tracing::info!(%error, "tls_crl_revoked");
        assert!(
            error.contains("Revoked"),
            "the refusal must name the revocation: {error}"
        );
    }

    /// Reports `Pending` on its second write call, as a bounded transport
    /// does while its buffer is full, and wakes the task at once.
    #[cfg(feature = "tls")]
    struct StallsSecondWrite<IO> {
        inner: IO,
        writes: usize,
    }

    /// Holds written bytes until flushed, like a buffered writer.
    #[cfg(feature = "tls")]
    struct SendsOnFlush<IO> {
        inner: IO,
        held: Vec<u8>,
    }

    #[cfg(feature = "tls")]
    impl<IO: AsyncRead + Unpin> AsyncRead for StallsSecondWrite<IO> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    #[cfg(feature = "tls")]
    impl<IO: AsyncWrite + Unpin> AsyncWrite for StallsSecondWrite<IO> {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.writes += 1;
            if self.writes == 2 {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            Pin::new(&mut self.inner).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    #[cfg(feature = "tls")]
    impl<IO: AsyncRead + Unpin> AsyncRead for SendsOnFlush<IO> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    #[cfg(feature = "tls")]
    impl<IO: AsyncWrite + Unpin> AsyncWrite for SendsOnFlush<IO> {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.held.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            let this = &mut *self;
            while !this.held.is_empty() {
                match Pin::new(&mut this.inner).poll_write(cx, &this.held) {
                    Poll::Ready(Ok(0)) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                    Poll::Ready(Ok(n)) => {
                        this.held.drain(..n);
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }
            Pin::new(&mut this.inner).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    /// Runs a client handshake over `wrap(client transport)` against a plain
    /// server, drops the client as soon as its handshake returns, and
    /// reports the client's result, whether TLS bytes were still unsent at
    /// that point, and the server's result.
    #[cfg(feature = "tls")]
    fn handshake_through<W>(
        seed: u64,
        wrap: impl FnOnce(VirtualTcpStream) -> W + Send + 'static,
    ) -> (Result<(), TlsError>, bool, Result<(), TlsError>)
    where
        W: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let config = TestConfig::new().with_seed(seed).with_max_steps(20_000);
        let mut runtime = LabRuntimeTarget::create_runtime(config);
        let (client, server) = LabRuntimeTarget::block_on(&mut runtime, async move {
            let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
            let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
            let acceptor = TlsAcceptorBuilder::new(chain, key).build().unwrap();
            let certs = Certificate::from_pem(TEST_CERT_PEM).unwrap();
            let connector = TlsConnectorBuilder::new()
                .add_root_certificates(certs)
                .build()
                .unwrap();

            let server_name = ServerName::try_from("localhost".to_string()).unwrap();
            let client_conn =
                ClientConnection::new(Arc::clone(connector.config()), server_name).unwrap();
            let server_conn = ServerConnection::new(Arc::clone(acceptor.config())).unwrap();
            let (client_io, server_io) = VirtualTcpStream::pair(
                "127.0.0.1:5230".parse().unwrap(),
                "127.0.0.1:5231".parse().unwrap(),
            );
            let mut client_stream = TlsStream::new_client(wrap(client_io), client_conn);
            let mut server_stream = TlsStream::new_server(server_io, server_conn);
            let client = async move {
                let result = poll_fn(|cx| client_stream.poll_handshake(cx)).await;
                // A caller that only reads next would not send anything
                // more, so the server must get the whole flight on its own.
                let unsent = client_stream.conn.wants_write();
                (result, unsent, client_stream)
            };
            let server = async move {
                let result = poll_fn(|cx| server_stream.poll_handshake(cx)).await;
                (result, server_stream)
            };
            // The client stays open, writing nothing more, until the server
            // finishes: a flight left unsent leaves the server waiting, and
            // the lab then ends with "task did not complete".
            let ((client_result, unsent, client_stream), (server_result, server_stream)) =
                zip(client, server).await;
            drop((client_stream, server_stream));
            ((client_result, unsent), server_result)
        });
        assert!(runtime.is_quiescent());
        (client.0, client.1, server)
    }

    #[cfg(feature = "tls")]
    #[test]
    fn handshake_completes_only_after_its_final_flight_is_written() {
        init_test_logging();
        // The second write is the client's last flight (after the
        // ClientHello); the transport refuses it once.
        let (client, unsent, server) = handshake_through(0xF117_0001, |io| StallsSecondWrite {
            inner: io,
            writes: 0,
        });
        tracing::info!(client = ?client, unsent, server = ?server, "tls_final_flight");
        client.expect("the client handshake completes");
        assert!(
            !unsent,
            "the handshake reported done with its final flight unsent"
        );
        server.expect("the server receives the client's Finished");
    }

    #[cfg(feature = "tls")]
    #[test]
    fn handshake_flushes_a_transport_that_holds_writes() {
        init_test_logging();
        let (client, unsent, server) = handshake_through(0xF117_0002, |io| SendsOnFlush {
            inner: io,
            held: Vec::new(),
        });
        tracing::info!(client = ?client, unsent, server = ?server, "tls_flush_transport");
        client.expect("the client handshake completes");
        assert!(!unsent);
        server.expect("the server handshake completes");
    }
}
