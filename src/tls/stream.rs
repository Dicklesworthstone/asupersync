//! TLS stream implementation.
//!
//! This module provides `TlsStream` that wraps an underlying transport stream
//! and implements `AsyncRead` + `AsyncWrite` with TLS encryption.

#[cfg(feature = "tls")]
mod channel_binding;

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
    /// Our close_notify and preceding records reached the flushed transport.
    shutdown_flushed: bool,
    /// The error that ended reading, reported again by every later read.
    read_error: Option<(io::ErrorKind, String)>,
    /// A fatal transport write error must not let callers retry accepted
    /// plaintext or receive a spurious successful flush/shutdown.
    write_error: Option<(io::ErrorKind, String)>,
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

    fn negotiated_cipher_suite(&self) -> Option<rustls::CipherSuite> {
        match self {
            Self::Client(c) => c.negotiated_cipher_suite(),
            Self::Server(s) => s.negotiated_cipher_suite(),
        }
        .map(|suite| suite.suite())
    }

    fn negotiated_key_exchange_group(&self) -> Option<rustls::NamedGroup> {
        match self {
            Self::Client(c) => c.negotiated_key_exchange_group(),
            Self::Server(s) => s.negotiated_key_exchange_group(),
        }
        .map(|group| group.name())
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

    fn peer_certificate_chain_der(&self) -> Option<Vec<Vec<u8>>> {
        let certs = match self {
            Self::Client(c) => c.peer_certificates(),
            Self::Server(s) => s.peer_certificates(),
        }?;
        Some(certs.iter().map(|cert| cert.as_ref().to_vec()).collect())
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
            shutdown_flushed: false,
            read_error: None,
            write_error: None,
        }
    }

    /// Create a new server TLS stream.
    pub(crate) fn new_server(io: IO, conn: ServerConnection) -> Self {
        Self {
            io,
            conn: TlsConnection::Server(conn),
            state: TlsState::Handshaking,
            read_closed: false,
            shutdown_flushed: false,
            read_error: None,
            write_error: None,
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

    /// Get the negotiated cipher suite, once the handshake has chosen one.
    pub fn negotiated_cipher_suite(&self) -> Option<rustls::CipherSuite> {
        self.conn.negotiated_cipher_suite()
    }

    /// Get the negotiated key-exchange group, once the handshake has chosen
    /// one. rustls reports `None` for a handshake without a key exchange.
    pub fn negotiated_key_exchange_group(&self) -> Option<rustls::NamedGroup> {
        self.conn.negotiated_key_exchange_group()
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

    /// Returns the DER-encoded certificates the peer presented, leaf first,
    /// in the order it sent them. `None` before the handshake is complete or
    /// when the peer presented no certificate.
    pub fn peer_certificate_chain_der(&self) -> Option<Vec<Vec<u8>>> {
        self.conn.peer_certificate_chain_der()
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
        // Peer EOF must not discard our own pending close_notify. A read can
        // run between shutdown polls while a write or transport flush stalls.
        if self.state.shutdown_pending() && self.shutdown_flushed {
            self.state = TlsState::Closed;
        }
    }

    /// Closes the stream on a read error and keeps the error for later
    /// reads. Reading again must not turn a truncated or corrupt stream
    /// into a clean end of file; rustls's own reader repeats such an
    /// error as well (br-asupersync-2dxusr item 4).
    fn fail_read(&mut self, kind: io::ErrorKind, message: String) -> io::Error {
        self.state = TlsState::Closed;
        let err = io::Error::new(kind, message.clone());
        self.read_error = Some((kind, message));
        err
    }

    fn fail_write(&mut self, error: io::Error) -> io::Error {
        self.state = TlsState::Closed;
        let kind = error.kind();
        let message = error.to_string();
        self.write_error = Some((kind, message.clone()));
        io::Error::new(kind, message)
    }

    fn retained_write_error(&self) -> Option<io::Error> {
        self.write_error
            .as_ref()
            .map(|(kind, message)| io::Error::new(*kind, message.clone()))
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
    /// Returns `Poll::Ready(Ok(()))` when the handshake is complete. Polling
    /// again after success performs no I/O and does not start a new handshake.
    ///
    /// # Errors
    ///
    /// A failed handshake or a stream whose local shutdown has started cannot
    /// be restarted. Subsequent polls return [`TlsError::Io`] with
    /// [`io::ErrorKind::NotConnected`]; create a new connection instead.
    pub fn poll_handshake(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), TlsError>> {
        // rustls may have completed its part before our final transport flush
        // fails. Its is_handshaking() flag alone cannot authorize a retry: that
        // would resurrect a Closed stream, or undo ShuttingDown, and make
        // application writes and tls-exporter bindings available again.
        match self.state {
            TlsState::Ready => return Poll::Ready(Ok(())),
            TlsState::ShuttingDown | TlsState::Closed => {
                return Poll::Ready(Err(TlsError::Io(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "cannot handshake a closed or shutting-down TLS stream",
                ))));
            }
            TlsState::Handshaking => {}
        }

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
            // EINTR is not evidence of a failed TLS session. Re-poll rather
            // than closing the stream or stranding an unregistered waker.
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
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
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    /// Drain rustls's records and flush transports that buffer accepted writes.
    fn poll_flush_tls(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.conn.wants_write() {
            match self.poll_write_tls(cx) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "failed to flush pending TLS records",
                    )));
                }
                Poll::Ready(Ok(_)) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        Pin::new(&mut self.io).poll_flush(cx)
    }

    /// Shared by both shutdown APIs so neither can skip buffered TLS bytes.
    fn poll_flush_close_notify(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.state.shutdown_pending() {
            #[cfg(feature = "tracing-integration")]
            debug!("Initiating TLS shutdown");
            self.state = TlsState::ShuttingDown;
            self.conn.send_close_notify();
        }

        if !self.shutdown_flushed {
            std::task::ready!(self.poll_flush_tls(cx))?;
            self.shutdown_flushed = true;
        }
        Poll::Ready(Ok(()))
    }

    /// Poll for graceful TLS write-side shutdown without shutting down the transport.
    ///
    /// Flushes all queued records and `close_notify`, including any transport
    /// buffering. Reads may continue until the peer closes its write side.
    ///
    /// # Errors
    ///
    /// Transport write and flush errors are preserved as [`TlsError::Io`]. A
    /// zero-byte write with TLS records still pending returns
    /// [`io::ErrorKind::WriteZero`], not a successful shutdown.
    pub fn poll_shutdown_tls(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), TlsError>> {
        if let Some(error) = self.retained_write_error() {
            return Poll::Ready(Err(TlsError::Io(error)));
        }
        if self.state.is_terminal() {
            return Poll::Ready(Ok(()));
        }

        std::task::ready!(self.poll_flush_close_notify(cx)).map_err(TlsError::Io)?;

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

        if let Some(error) = self.retained_write_error() {
            return Poll::Ready(Err(error));
        }

        if let Some((kind, message)) = &self.read_error {
            return Poll::Ready(Err(io::Error::new(*kind, message.clone())));
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
                    self.read_error = Some((io::ErrorKind::Other, e.to_string()));
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
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    return Poll::Ready(Err(self.fail_read(e.kind(), e.to_string())));
                }
            }

            // Need more data - read from underlying IO
            match self.poll_read_tls(cx) {
                Poll::Ready(Ok(0)) => {
                    // Transport EOF without close_notify (since Reader::read didn't return Ok(0))
                    return Poll::Ready(Err(self.fail_read(
                        io::ErrorKind::UnexpectedEof,
                        "tls connection closed without close_notify".to_owned(),
                    )));
                }
                Poll::Ready(Ok(_)) => {
                    // Process the new TLS data
                    if let Err(e) = self.conn.process_new_packets() {
                        self.flush_alert_best_effort(cx);
                        return Poll::Ready(Err(
                            self.fail_read(io::ErrorKind::InvalidData, e.to_string())
                        ));
                    }
                }
                // A transport read failure means the authenticated session
                // is unusable. Do not leave Ready/exporter access enabled,
                // and repeat the exact failure on subsequent reads instead
                // of turning it into clean EOF after a transport recovery.
                Poll::Ready(Err(e)) => {
                    return Poll::Ready(Err(self.fail_read(e.kind(), e.to_string())));
                }
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
        if let Some(error) = self.retained_write_error() {
            return Poll::Ready(Err(error));
        }
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
        let mut n = io::Write::write(&mut self.conn.writer(), buf)?;
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
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(self.fail_write(e))),
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
            // The retry created new records after the old queue drained.
            // Give them the same write progress as a first-attempt success:
            // returning here can strand a request when the caller next reads.
            n = retry;
        }

        // Flush encrypted data to underlying IO
        while self.conn.wants_write() {
            match self.poll_write_tls(cx) {
                Poll::Ready(Ok(0)) => break,
                Poll::Ready(Ok(_)) => {}
                Poll::Ready(Err(e)) => {
                    let error = self.fail_write(e);
                    // rustls already accepted n bytes. Returning Err would
                    // make write_all retry them and could duplicate the data.
                    // Report acceptance once; expose the sticky transport
                    // failure to the next write, read, flush, or shutdown.
                    if n > 0 {
                        return Poll::Ready(Ok(n));
                    }
                    return Poll::Ready(Err(error));
                }
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
        if let Some(error) = self.retained_write_error() {
            return Poll::Ready(Err(error));
        }
        self.poll_flush_tls(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(error) = self.retained_write_error() {
            return Poll::Ready(Err(error));
        }
        if self.state.is_terminal() {
            return Pin::new(&mut self.io).poll_shutdown(cx);
        }

        // Never shut down the transport before its buffered close_notify has
        // been flushed, even if the peer already sent its own close_notify.
        std::task::ready!(self.poll_flush_close_notify(cx))?;

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
#[path = "stream_inline_tests.rs"]
mod tests;
