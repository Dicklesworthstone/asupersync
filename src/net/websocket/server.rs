//! WebSocket server/acceptor implementation with Cx integration.
//!
//! Provides cancel-correct WebSocket connection acceptance for server applications.
//!
//! # Example
//!
//! ```ignore
//! use asupersync::net::websocket::{WebSocketAcceptor, WebSocket, Message};
//!
//! // Create acceptor with configuration
//! let acceptor = WebSocketAcceptor::new()
//!     .protocol("chat")
//!     .max_frame_size(1024 * 1024);
//!
//! // Accept upgrade from HTTP request
//! let ws = acceptor.accept(&cx, request_bytes, tcp_stream).await?;
//!
//! // Handle messages
//! while let Some(msg) = ws.recv(&cx).await? {
//!     match msg {
//!         Message::Text(text) => ws.send(&cx, Message::text(format!("Echo: {text}"))).await?,
//!         Message::Close(_) => break,
//!         _ => {}
//!     }
//! }
//! ```

use super::client::{Message, MessageAssembler, WebSocketConfig};
use super::close::{CloseHandshake, CloseReason};
use super::frame::{Frame, FrameCodec, Opcode, WsError};
use super::handshake::{AcceptResponse, HandshakeError, HttpRequest, ServerHandshake};
use crate::bytes::BytesMut;
use crate::codec::{Decoder, Encoder};
use crate::cx::Cx;
use crate::io::{AsyncRead, AsyncWrite, ReadBuf};
use std::io;
use std::pin::Pin;
use std::task::Poll;
use std::time::Duration;

/// WebSocket server acceptor.
///
/// Validates and accepts WebSocket upgrade requests, producing connected
/// WebSocket instances that are owned by the accepting region.
#[derive(Debug, Clone)]
pub struct WebSocketAcceptor {
    /// Server handshake configuration.
    handshake: ServerHandshake,
    /// Connection configuration.
    config: WebSocketConfig,
}

impl Default for WebSocketAcceptor {
    fn default() -> Self {
        Self::new()
    }
}

impl WebSocketAcceptor {
    /// Create a new acceptor with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            handshake: ServerHandshake::new(),
            config: WebSocketConfig::default(),
        }
    }

    /// Add a supported subprotocol.
    #[must_use]
    pub fn protocol(mut self, protocol: impl Into<String>) -> Self {
        let protocol = protocol.into();
        self.handshake = self.handshake.protocol(protocol.clone());
        self.config.protocols.push(protocol);
        self
    }

    /// Add a supported extension.
    #[must_use]
    pub fn extension(mut self, extension: impl Into<String>) -> Self {
        self.handshake = self.handshake.extension(extension);
        self
    }

    /// Set maximum frame size.
    #[must_use]
    pub fn max_frame_size(mut self, size: usize) -> Self {
        self.config.max_frame_size = size;
        self
    }

    /// Set maximum message size.
    #[must_use]
    pub fn max_message_size(mut self, size: usize) -> Self {
        self.config.max_message_size = size;
        self
    }

    /// Set ping interval for keepalive.
    #[must_use]
    pub fn ping_interval(mut self, interval: Option<Duration>) -> Self {
        self.config.ping_interval = interval;
        self
    }

    /// Set close handshake timeout.
    #[must_use]
    pub fn close_timeout(mut self, timeout: Duration) -> Self {
        self.config.close_config.close_timeout = timeout;
        self
    }

    /// Accept a WebSocket upgrade from raw HTTP request bytes.
    ///
    /// # Arguments
    ///
    /// * `cx` - Capability context for cancellation
    /// * `request_bytes` - Raw HTTP request bytes
    /// * `stream` - TCP stream to upgrade
    ///
    /// # Cancel-Safety
    ///
    /// If cancelled during handshake, the stream is dropped. No partial
    /// handshake state is leaked.
    pub async fn accept<IO>(
        &self,
        cx: &Cx,
        request_bytes: &[u8],
        mut stream: IO,
    ) -> Result<ServerWebSocket<IO>, WsAcceptError>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        // Check cancellation
        if cx.is_cancel_requested() {
            return Err(WsAcceptError::Cancelled);
        }

        // Parse HTTP request
        let request = HttpRequest::parse(request_bytes)?;

        // Validate and generate accept response
        let accept_response = self.handshake.accept(&request)?;

        // Check cancellation before sending response
        if cx.is_cancel_requested() {
            return Err(WsAcceptError::Cancelled);
        }

        // Send HTTP 101 response
        let response_bytes = accept_response.response_bytes();
        write_all_io(&mut stream, &response_bytes).await?;

        // Create server WebSocket
        let ws = ServerWebSocket::from_upgraded(stream, self.config.clone(), accept_response);

        Ok(ws)
    }

    /// Accept from a pre-parsed HTTP request.
    ///
    /// Use this when you've already parsed the HTTP request in an HTTP server.
    pub async fn accept_parsed<IO>(
        &self,
        cx: &Cx,
        request: &HttpRequest,
        mut stream: IO,
    ) -> Result<ServerWebSocket<IO>, WsAcceptError>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        // Check cancellation
        if cx.is_cancel_requested() {
            return Err(WsAcceptError::Cancelled);
        }

        // Validate and generate accept response
        let accept_response = self.handshake.accept(request)?;

        // Check cancellation before sending response
        if cx.is_cancel_requested() {
            return Err(WsAcceptError::Cancelled);
        }

        // Send HTTP 101 response
        let response_bytes = accept_response.response_bytes();
        write_all_io(&mut stream, &response_bytes).await?;

        // Create server WebSocket
        let ws = ServerWebSocket::from_upgraded(stream, self.config.clone(), accept_response);

        Ok(ws)
    }

    /// Reject an upgrade request with the given HTTP status code.
    ///
    /// # Arguments
    ///
    /// * `stream` - TCP stream to send rejection on
    /// * `status` - HTTP status code (e.g., 400, 403, 404)
    /// * `reason` - Status reason phrase
    pub async fn reject<IO>(stream: &mut IO, status: u16, reason: &str) -> Result<(), io::Error>
    where
        IO: AsyncWrite + Unpin,
    {
        let response = ServerHandshake::reject(status, reason);
        write_all_io(stream, &response).await.map_err(|e| match e {
            WsError::Io(e) => e,
            _ => io::Error::other("unexpected error"),
        })
    }
}

/// Server-side WebSocket connection.
///
/// Similar to the client `WebSocket` but with server-specific features:
/// - Tracks negotiated protocol and extensions
/// - Uses server role (no masking on outbound frames)
/// - Provides access to original request path
pub struct ServerWebSocket<IO> {
    /// Underlying I/O stream.
    io: IO,
    /// Frame codec for encoding/decoding.
    codec: FrameCodec,
    /// Read buffer.
    read_buf: BytesMut,
    /// Write buffer.
    write_buf: BytesMut,
    /// Close handshake state.
    close_handshake: CloseHandshake,
    /// Configuration.
    config: WebSocketConfig,
    /// Message assembler for fragmented frames.
    assembler: MessageAssembler,
    /// Negotiated subprotocol (if any).
    protocol: Option<String>,
    /// Negotiated extensions.
    extensions: Vec<String>,
    /// Pending pong payloads to send.
    pending_pongs: Vec<crate::bytes::Bytes>,
}

impl<IO> ServerWebSocket<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    /// Create a WebSocket from an already-upgraded I/O stream.
    fn from_upgraded(io: IO, config: WebSocketConfig, accept: AcceptResponse) -> Self {
        let max_message_size = config.max_message_size;
        let codec = FrameCodec::server().max_payload_size(config.max_frame_size);
        Self {
            io,
            codec,
            read_buf: BytesMut::with_capacity(8192),
            write_buf: BytesMut::with_capacity(8192),
            close_handshake: CloseHandshake::with_config(config.close_config.clone()),
            config,
            assembler: MessageAssembler::new(max_message_size),
            protocol: accept.protocol,
            extensions: accept.extensions,
            pending_pongs: Vec::new(),
        }
    }

    /// Get the negotiated subprotocol (if any).
    #[must_use]
    pub fn protocol(&self) -> Option<&str> {
        self.protocol.as_deref()
    }

    /// Get the negotiated extensions.
    #[must_use]
    pub fn extensions(&self) -> &[String] {
        &self.extensions
    }

    /// Check if the connection is open.
    #[must_use]
    pub fn is_open(&self) -> bool {
        self.close_handshake.is_open()
    }

    /// Check if the close handshake is complete.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.close_handshake.is_closed()
    }

    /// Send a message.
    ///
    /// # Cancel-Safety
    ///
    /// If cancelled, the message may be partially sent. The connection should
    /// be closed if cancellation occurs mid-send.
    pub async fn send(&mut self, cx: &Cx, msg: Message) -> Result<(), WsError> {
        // Check cancellation
        if cx.is_cancel_requested() {
            self.initiate_close(CloseReason::going_away()).await?;
            return Err(WsError::Io(io::Error::new(
                io::ErrorKind::Interrupted,
                "cancelled",
            )));
        }

        // Don't send data messages if we're closing
        if !msg.is_control() && !self.close_handshake.is_open() {
            return Err(WsError::Io(io::Error::new(
                io::ErrorKind::NotConnected,
                "connection is closing",
            )));
        }

        let frame = Frame::from(msg);
        self.send_frame(frame).await
    }

    /// Receive a message.
    ///
    /// Returns `None` when the connection is closed.
    ///
    /// # Cancel-Safety
    ///
    /// This method is cancel-safe. If cancelled, no data is lost.
    pub async fn recv(&mut self, cx: &Cx) -> Result<Option<Message>, WsError> {
        loop {
            // Check cancellation
            if cx.is_cancel_requested() {
                self.initiate_close(CloseReason::going_away()).await?;
                return Err(WsError::Io(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "cancelled",
                )));
            }

            // Send any pending pongs
            while let Some(payload) = self.pending_pongs.pop() {
                let pong = Frame::pong(payload);
                self.send_frame(pong).await?;
            }

            if let Some(frame) = self.codec.decode(&mut self.read_buf)? {
                // Handle control frames
                match frame.opcode {
                    Opcode::Ping => {
                        // Queue pong for next send
                        self.pending_pongs.push(frame.payload);
                    }
                    Opcode::Pong => {
                        // Pong received - keepalive confirmed
                    }
                    Opcode::Close => {
                        // Handle close handshake
                        if let Some(response) = self.close_handshake.receive_close(&frame)? {
                            self.send_frame(response).await?;
                        }
                        let reason = CloseReason::parse(&frame.payload).ok();
                        return Ok(Some(Message::Close(reason)));
                    }
                    _ => match self.assembler.push_frame(frame) {
                        Ok(Some(msg)) => return Ok(Some(msg)),
                        Ok(None) => {}
                        Err(err) => {
                            self.close_handshake.force_close(CloseReason::new(
                                super::CloseCode::ProtocolError,
                                None,
                            ));
                            return Err(err);
                        }
                    },
                }
            } else {
                // Need more data - read from socket
                if self.close_handshake.is_closed() {
                    return Ok(None);
                }

                let n = self.read_more().await?;
                if n == 0 {
                    // EOF - connection closed
                    self.close_handshake
                        .force_close(CloseReason::new(super::CloseCode::Abnormal, None));
                    return Ok(None);
                }
            }
        }
    }

    /// Initiate a close handshake.
    ///
    /// Sends a close frame and waits for the peer's response.
    pub async fn close(&mut self, reason: CloseReason) -> Result<(), WsError> {
        self.initiate_close(reason).await?;

        // Wait for close response (with timeout)
        let timeout = self.close_handshake.close_timeout();
        let deadline = std::time::Instant::now() + timeout;

        while !self.close_handshake.is_closed() {
            if std::time::Instant::now() >= deadline {
                self.close_handshake.force_close(CloseReason::going_away());
                break;
            }

            // Try to receive close response
            match self.codec.decode(&mut self.read_buf)? {
                Some(frame) if frame.opcode == Opcode::Close => {
                    self.close_handshake.receive_close(&frame)?;
                }
                Some(_) => {
                    // Ignore non-close frames during close
                }
                None => {
                    let n = self.read_more().await?;
                    if n == 0 {
                        self.close_handshake.force_close(CloseReason::going_away());
                        break;
                    }
                }
            }
        }

        Ok(())
    }

    /// Send a ping frame.
    pub async fn ping(&mut self, payload: impl Into<crate::bytes::Bytes>) -> Result<(), WsError> {
        let frame = Frame::ping(payload);
        self.send_frame(frame).await
    }

    /// Internal: initiate close without waiting.
    async fn initiate_close(&mut self, reason: CloseReason) -> Result<(), WsError> {
        if let Some(frame) = self.close_handshake.initiate(reason) {
            self.send_frame(frame).await?;
        }
        Ok(())
    }

    /// Internal: send a single frame.
    async fn send_frame(&mut self, frame: Frame) -> Result<(), WsError> {
        self.write_buf.clear();
        self.codec.encode(frame, &mut self.write_buf)?;

        // Copy data to avoid borrow issues
        let data = self.write_buf.to_vec();
        write_all_io(&mut self.io, &data).await
    }

    /// Internal: read more data into buffer.
    async fn read_more(&mut self) -> Result<usize, WsError> {
        // Ensure we have space
        if self.read_buf.capacity() - self.read_buf.len() < 4096 {
            self.read_buf.reserve(8192);
        }

        // Create a temporary buffer for reading
        let mut temp = [0u8; 4096];
        let n = read_some_io(&mut self.io, &mut temp).await?;

        if n > 0 {
            self.read_buf.extend_from_slice(&temp[..n]);
        }

        Ok(n)
    }
}

/// Write all bytes to an I/O stream.
async fn write_all_io<IO: AsyncWrite + Unpin>(io: &mut IO, buf: &[u8]) -> Result<(), WsError> {
    use std::future::poll_fn;

    let mut written = 0;
    while written < buf.len() {
        let n = poll_fn(|cx| Pin::new(&mut *io).poll_write(cx, &buf[written..])).await?;
        if n == 0 {
            return Err(WsError::Io(io::Error::new(
                io::ErrorKind::WriteZero,
                "write returned 0",
            )));
        }
        written += n;
    }
    Ok(())
}

/// Read some bytes from an I/O stream.
async fn read_some_io<IO: AsyncRead + Unpin>(
    io: &mut IO,
    buf: &mut [u8],
) -> Result<usize, WsError> {
    use std::future::poll_fn;

    poll_fn(|cx| {
        let mut read_buf = ReadBuf::new(buf);
        match Pin::new(&mut *io).poll_read(cx, &mut read_buf) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(read_buf.filled().len())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(WsError::Io(e))),
            Poll::Pending => Poll::Pending,
        }
    })
    .await
}

/// WebSocket accept errors.
#[derive(Debug)]
pub enum WsAcceptError {
    /// Invalid HTTP request.
    InvalidRequest(String),
    /// Handshake validation failed.
    Handshake(HandshakeError),
    /// I/O error.
    Io(io::Error),
    /// Accept cancelled.
    Cancelled,
    /// WebSocket protocol error.
    Protocol(WsError),
}

impl std::fmt::Display for WsAcceptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidRequest(msg) => write!(f, "invalid request: {msg}"),
            Self::Handshake(e) => write!(f, "handshake failed: {e}"),
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::Cancelled => write!(f, "accept cancelled"),
            Self::Protocol(e) => write!(f, "protocol error: {e}"),
        }
    }
}

impl std::error::Error for WsAcceptError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Handshake(e) => Some(e),
            Self::Io(e) => Some(e),
            Self::Protocol(e) => Some(e),
            _ => None,
        }
    }
}

impl From<HandshakeError> for WsAcceptError {
    fn from(err: HandshakeError) -> Self {
        Self::Handshake(err)
    }
}

impl From<io::Error> for WsAcceptError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<WsError> for WsAcceptError {
    fn from(err: WsError) -> Self {
        Self::Protocol(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_acceptor_builder() {
        let acceptor = WebSocketAcceptor::new()
            .protocol("chat")
            .protocol("superchat")
            .max_frame_size(1024 * 1024)
            .ping_interval(Some(Duration::from_secs(30)))
            .close_timeout(Duration::from_secs(10));

        assert_eq!(acceptor.config.max_frame_size, 1024 * 1024);
        assert_eq!(acceptor.config.ping_interval, Some(Duration::from_secs(30)));
        assert_eq!(
            acceptor.config.close_config.close_timeout,
            Duration::from_secs(10)
        );
    }

    #[test]
    fn test_ws_accept_error_display() {
        let err = WsAcceptError::Cancelled;
        assert_eq!(err.to_string(), "accept cancelled");

        let err = WsAcceptError::InvalidRequest("bad header".into());
        assert!(err.to_string().contains("invalid request"));
    }

    #[test]
    fn acceptor_protocol_and_extension_builder() {
        let acceptor = WebSocketAcceptor::new()
            .protocol("graphql-ws")
            .protocol("graphql-transport-ws")
            .extension("permessage-deflate");

        // Protocols should be tracked in config.
        assert_eq!(acceptor.config.protocols.len(), 2);
        assert_eq!(acceptor.config.protocols[0], "graphql-ws");
        assert_eq!(acceptor.config.protocols[1], "graphql-transport-ws");
    }

    #[test]
    fn acceptor_default() {
        let acceptor = WebSocketAcceptor::default();
        assert_eq!(acceptor.config.max_frame_size, 16 * 1024 * 1024);
        assert!(acceptor.config.protocols.is_empty());
    }

    #[test]
    fn acceptor_max_message_size_builder() {
        let acceptor = WebSocketAcceptor::new().max_message_size(1024);
        assert_eq!(acceptor.config.max_message_size, 1024);
    }

    #[test]
    fn ws_accept_error_source() {
        use std::error::Error;

        let err = WsAcceptError::Cancelled;
        assert!(err.source().is_none());

        let io_err = WsAcceptError::Io(io::Error::new(io::ErrorKind::BrokenPipe, "broken"));
        assert!(io_err.source().is_some());
    }

    #[test]
    fn ws_accept_error_from_io() {
        let io_err = io::Error::new(io::ErrorKind::ConnectionReset, "reset");
        let ws_err = WsAcceptError::from(io_err);
        assert!(matches!(ws_err, WsAcceptError::Io(_)));
        assert!(ws_err.to_string().contains("I/O error"));
    }
}
