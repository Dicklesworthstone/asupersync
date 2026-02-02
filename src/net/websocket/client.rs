//! WebSocket client implementation with Cx integration.
//!
//! Provides cancel-correct WebSocket connections with structured concurrency support.
//!
//! # Example
//!
//! ```ignore
//! use asupersync::net::websocket::WebSocket;
//!
//! let ws = WebSocket::connect(&cx, "ws://example.com/chat").await?;
//!
//! // Send a message
//! ws.send(&cx, Message::Text("Hello!".into())).await?;
//!
//! // Receive messages
//! while let Some(msg) = ws.recv(&cx).await? {
//!     match msg {
//!         Message::Text(text) => println!("Received: {text}"),
//!         Message::Binary(data) => println!("Binary: {} bytes", data.len()),
//!         Message::Close(reason) => break,
//!     }
//! }
//! ```

use super::close::{CloseConfig, CloseHandshake, CloseReason, CloseState};
use super::frame::{Frame, FrameCodec, Opcode, WsError};
use super::handshake::{ClientHandshake, HandshakeError, HttpResponse, WsUrl};
use crate::bytes::{Bytes, BytesMut};
use crate::codec::{Decoder, Encoder};
use crate::cx::Cx;
use crate::io::{AsyncRead, AsyncWrite, ReadBuf};
use crate::net::TcpStream;
use std::io;
use std::pin::Pin;
use std::task::Poll;
use std::time::Duration;

#[cfg(feature = "tls")]
use crate::tls::{TlsConnector, TlsStream};

/// WebSocket message types.
#[derive(Debug, Clone)]
pub enum Message {
    /// Text message (UTF-8).
    Text(String),
    /// Binary message.
    Binary(Bytes),
    /// Close message with optional reason.
    Close(Option<CloseReason>),
    /// Ping message.
    Ping(Bytes),
    /// Pong message.
    Pong(Bytes),
}

impl Message {
    /// Create a text message.
    #[must_use]
    pub fn text(s: impl Into<String>) -> Self {
        Self::Text(s.into())
    }

    /// Create a binary message.
    #[must_use]
    pub fn binary(data: impl Into<Bytes>) -> Self {
        Self::Binary(data.into())
    }

    /// Create a ping message.
    #[must_use]
    pub fn ping(data: impl Into<Bytes>) -> Self {
        Self::Ping(data.into())
    }

    /// Create a pong message.
    #[must_use]
    pub fn pong(data: impl Into<Bytes>) -> Self {
        Self::Pong(data.into())
    }

    /// Create a close message with reason.
    #[must_use]
    pub fn close(reason: CloseReason) -> Self {
        Self::Close(Some(reason))
    }

    /// Check if this is a control message (ping, pong, close).
    #[must_use]
    pub fn is_control(&self) -> bool {
        matches!(self, Self::Ping(_) | Self::Pong(_) | Self::Close(_))
    }
}

#[derive(Debug)]
struct PartialMessage {
    opcode: Opcode,
    data: BytesMut,
}

#[derive(Debug)]
pub(super) struct MessageAssembler {
    max_message_size: usize,
    partial: Option<PartialMessage>,
}

impl MessageAssembler {
    pub(super) fn new(max_message_size: usize) -> Self {
        Self {
            max_message_size,
            partial: None,
        }
    }

    pub(super) fn push_frame(&mut self, frame: Frame) -> Result<Option<Message>, WsError> {
        match frame.opcode {
            Opcode::Text | Opcode::Binary => self.push_data_frame(frame),
            Opcode::Continuation => self.push_continuation_frame(&frame),
            _ => Err(WsError::InvalidOpcode(frame.opcode as u8)),
        }
    }

    fn push_data_frame(&mut self, frame: Frame) -> Result<Option<Message>, WsError> {
        if self.partial.is_some() {
            return Err(WsError::ProtocolViolation(
                "received new data frame while continuation expected",
            ));
        }

        let payload_len = frame.payload.len();
        if payload_len > self.max_message_size {
            return Err(WsError::PayloadTooLarge {
                size: payload_len as u64,
                max: self.max_message_size,
            });
        }

        if frame.fin {
            return Ok(Some(message_from_payload(frame.opcode, frame.payload)?));
        }

        let mut data = BytesMut::with_capacity(payload_len);
        data.extend_from_slice(frame.payload.as_ref());
        self.partial = Some(PartialMessage {
            opcode: frame.opcode,
            data,
        });
        Ok(None)
    }

    fn push_continuation_frame(&mut self, frame: &Frame) -> Result<Option<Message>, WsError> {
        let Some(partial) = self.partial.as_mut() else {
            return Err(WsError::ProtocolViolation(
                "received continuation without a started message",
            ));
        };

        partial.data.extend_from_slice(frame.payload.as_ref());
        let total_len = partial.data.len();
        if total_len > self.max_message_size {
            return Err(WsError::PayloadTooLarge {
                size: total_len as u64,
                max: self.max_message_size,
            });
        }

        if !frame.fin {
            return Ok(None);
        }

        let opcode = partial.opcode;
        let data = std::mem::take(&mut partial.data).freeze();
        self.partial = None;
        Ok(Some(message_from_payload(opcode, data)?))
    }
}

fn message_from_payload(opcode: Opcode, payload: Bytes) -> Result<Message, WsError> {
    match opcode {
        Opcode::Text => {
            let text = std::str::from_utf8(payload.as_ref()).map_err(|_| WsError::InvalidUtf8)?;
            Ok(Message::Text(text.to_owned()))
        }
        Opcode::Binary => Ok(Message::Binary(payload)),
        Opcode::Continuation => Err(WsError::ProtocolViolation(
            "unexpected continuation payload",
        )),
        Opcode::Ping => Ok(Message::Ping(payload)),
        Opcode::Pong => Ok(Message::Pong(payload)),
        Opcode::Close => {
            let reason = CloseReason::parse(payload.as_ref()).ok();
            Ok(Message::Close(reason))
        }
    }
}

impl From<Frame> for Message {
    fn from(frame: Frame) -> Self {
        match frame.opcode {
            Opcode::Text => {
                let text = String::from_utf8_lossy(&frame.payload).into_owned();
                Self::Text(text)
            }
            Opcode::Binary | Opcode::Continuation => Self::Binary(frame.payload), // Simplified
            Opcode::Ping => Self::Ping(frame.payload),
            Opcode::Pong => Self::Pong(frame.payload),
            Opcode::Close => {
                let reason = CloseReason::parse(&frame.payload).ok();
                Self::Close(reason)
            }
        }
    }
}

impl From<Message> for Frame {
    fn from(msg: Message) -> Self {
        match msg {
            Message::Text(text) => Self::text(text),
            Message::Binary(data) => Self::binary(data),
            Message::Ping(data) => Self::ping(data),
            Message::Pong(data) => Self::pong(data),
            Message::Close(reason) => {
                let reason = reason.unwrap_or_else(CloseReason::normal);
                reason.to_frame()
            }
        }
    }
}

/// WebSocket client configuration.
#[derive(Debug, Clone)]
pub struct WebSocketConfig {
    /// Maximum frame payload size.
    pub max_frame_size: usize,
    /// Maximum message size (for fragmented messages).
    pub max_message_size: usize,
    /// Ping interval for keepalive.
    pub ping_interval: Option<Duration>,
    /// Close handshake configuration.
    pub close_config: CloseConfig,
    /// Requested subprotocols.
    pub protocols: Vec<String>,
    /// Connection timeout.
    pub connect_timeout: Option<Duration>,
    /// Enable TCP_NODELAY.
    pub nodelay: bool,
}

impl Default for WebSocketConfig {
    fn default() -> Self {
        Self {
            max_frame_size: 16 * 1024 * 1024,   // 16 MB
            max_message_size: 64 * 1024 * 1024, // 64 MB
            ping_interval: Some(Duration::from_secs(30)),
            close_config: CloseConfig::default(),
            protocols: Vec::new(),
            connect_timeout: Some(Duration::from_secs(30)),
            nodelay: true,
        }
    }
}

impl WebSocketConfig {
    /// Create a new configuration with defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set maximum frame size.
    #[must_use]
    pub fn max_frame_size(mut self, size: usize) -> Self {
        self.max_frame_size = size;
        self
    }

    /// Set maximum message size.
    #[must_use]
    pub fn max_message_size(mut self, size: usize) -> Self {
        self.max_message_size = size;
        self
    }

    /// Set ping interval for keepalive.
    #[must_use]
    pub fn ping_interval(mut self, interval: Option<Duration>) -> Self {
        self.ping_interval = interval;
        self
    }

    /// Add a requested subprotocol.
    #[must_use]
    pub fn protocol(mut self, protocol: impl Into<String>) -> Self {
        self.protocols.push(protocol.into());
        self
    }

    /// Set connection timeout.
    #[must_use]
    pub fn connect_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Enable or disable TCP_NODELAY.
    #[must_use]
    pub fn nodelay(mut self, enabled: bool) -> Self {
        self.nodelay = enabled;
        self
    }
}

/// WebSocket client connection.
///
/// Provides cancel-correct WebSocket communication with automatic ping/pong
/// handling and clean close on cancellation.
pub struct WebSocket<IO> {
    /// Underlying I/O stream.
    pub(super) io: IO,
    /// Frame codec for encoding/decoding.
    pub(super) codec: FrameCodec,
    /// Read buffer.
    pub(super) read_buf: BytesMut,
    /// Write buffer.
    pub(super) write_buf: BytesMut,
    /// Close handshake state.
    pub(super) close_handshake: CloseHandshake,
    /// Configuration.
    pub(super) config: WebSocketConfig,
    /// Message assembler for fragmented frames.
    pub(super) assembler: MessageAssembler,
    /// Negotiated subprotocol (if any).
    pub(super) protocol: Option<String>,
    /// Pending pong payloads to send.
    pub(super) pending_pongs: Vec<Bytes>,
}

impl<IO> WebSocket<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    /// Create a WebSocket from an already-upgraded I/O stream.
    ///
    /// Use this when you've already performed the HTTP upgrade handshake.
    #[must_use]
    pub fn from_upgraded(io: IO, config: WebSocketConfig) -> Self {
        let max_message_size = config.max_message_size;
        let codec = FrameCodec::client().max_payload_size(config.max_frame_size);
        Self {
            io,
            codec,
            read_buf: BytesMut::with_capacity(8192),
            write_buf: BytesMut::with_capacity(8192),
            close_handshake: CloseHandshake::with_config(config.close_config.clone()),
            config,
            assembler: MessageAssembler::new(max_message_size),
            protocol: None,
            pending_pongs: Vec::new(),
        }
    }

    /// Get the negotiated subprotocol (if any).
    #[must_use]
    pub fn protocol(&self) -> Option<&str> {
        self.protocol.as_deref()
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

    /// Get the close state.
    #[must_use]
    pub fn close_state(&self) -> CloseState {
        self.close_handshake.state()
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
    pub async fn ping(&mut self, payload: impl Into<Bytes>) -> Result<(), WsError> {
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
        write_all_io(&mut self.io, &data).await?;

        Ok(())
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

impl WebSocket<TcpStream> {
    /// Connect to a WebSocket server (ws://).
    ///
    /// # Cancel-Safety
    ///
    /// If cancelled during connection or handshake, the connection is dropped.
    pub async fn connect(cx: &Cx, url: &str) -> Result<Self, WsConnectError> {
        Self::connect_with_config(cx, url, WebSocketConfig::default()).await
    }

    /// Connect with custom configuration.
    pub async fn connect_with_config(
        cx: &Cx,
        url: &str,
        config: WebSocketConfig,
    ) -> Result<Self, WsConnectError> {
        // Parse URL
        let parsed = WsUrl::parse(url)?;

        // Check if TLS is required
        if parsed.tls {
            return Err(WsConnectError::TlsRequired);
        }

        // Check cancellation before connecting
        if cx.is_cancel_requested() {
            return Err(WsConnectError::Cancelled);
        }

        // Connect TCP
        let addr = format!("{}:{}", parsed.host, parsed.port);
        let tcp = TcpStream::connect(addr).await?;

        if config.nodelay {
            let _ = tcp.set_nodelay(true);
        }

        // Perform handshake
        Self::perform_handshake(cx, tcp, &parsed, &config).await
    }

    /// Internal: perform HTTP upgrade handshake.
    async fn perform_handshake(
        cx: &Cx,
        mut tcp: TcpStream,
        url: &WsUrl,
        config: &WebSocketConfig,
    ) -> Result<Self, WsConnectError> {
        // Build handshake request
        let mut handshake =
            ClientHandshake::new(&format!("ws://{}:{}{}", url.host, url.port, url.path))?;

        for protocol in &config.protocols {
            handshake = handshake.protocol(protocol);
        }

        // Check cancellation
        if cx.is_cancel_requested() {
            return Err(WsConnectError::Cancelled);
        }

        // Send request
        let request = handshake.request_bytes();
        write_all(&mut tcp, &request).await?;

        // Read response — trailing bytes after \r\n\r\n belong to the
        // first WebSocket frame and must be seeded into the read buffer.
        let (response_bytes, trailing) = read_http_response(&mut tcp).await?;
        let response = HttpResponse::parse(&response_bytes)?;

        // Validate response
        handshake.validate_response(&response)?;

        // Create WebSocket
        let mut ws = Self::from_upgraded(tcp, config.clone());
        ws.protocol = response.header("sec-websocket-protocol").map(String::from);
        if !trailing.is_empty() {
            ws.read_buf.extend_from_slice(&trailing);
        }

        Ok(ws)
    }
}

/// Write all bytes to a stream.
async fn write_all<IO: AsyncWrite + Unpin>(io: &mut IO, buf: &[u8]) -> io::Result<()> {
    use std::future::poll_fn;

    let mut written = 0;
    while written < buf.len() {
        let n = poll_fn(|cx| Pin::new(&mut *io).poll_write(cx, &buf[written..])).await?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "write returned 0"));
        }
        written += n;
    }
    Ok(())
}

/// Read HTTP response (until \r\n\r\n).
///
/// Returns `(headers, trailing)` where `trailing` contains any bytes read
/// past the `\r\n\r\n` boundary (these belong to the first WebSocket frame
/// and must be fed into the WebSocket codec's read buffer).
async fn read_http_response<IO: AsyncRead + Unpin>(io: &mut IO) -> io::Result<(Vec<u8>, Vec<u8>)> {
    use std::future::poll_fn;

    let mut buf = Vec::with_capacity(1024);
    let mut temp = [0u8; 256];

    loop {
        let n = poll_fn(|cx| {
            let mut read_buf = ReadBuf::new(&mut temp);
            match Pin::new(&mut *io).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => Poll::Ready(Ok(read_buf.filled().len())),
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending,
            }
        })
        .await?;

        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "EOF before HTTP response complete",
            ));
        }

        buf.extend_from_slice(&temp[..n]);

        // Split at the header boundary so trailing bytes (part of the first
        // WebSocket frame) are not lost.
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let split_at = pos + 4;
            let trailing = buf[split_at..].to_vec();
            buf.truncate(split_at);
            return Ok((buf, trailing));
        }

        if buf.len() > 16384 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP response too large",
            ));
        }
    }
}

/// WebSocket connection errors.
#[derive(Debug)]
pub enum WsConnectError {
    /// URL parsing failed.
    InvalidUrl(HandshakeError),
    /// Handshake failed.
    Handshake(HandshakeError),
    /// I/O error.
    Io(io::Error),
    /// TLS required but not supported.
    TlsRequired,
    /// Connection cancelled.
    Cancelled,
    /// WebSocket protocol error.
    Protocol(WsError),
}

impl std::fmt::Display for WsConnectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidUrl(e) => write!(f, "invalid URL: {e}"),
            Self::Handshake(e) => write!(f, "handshake failed: {e}"),
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::TlsRequired => write!(f, "TLS required (wss://) but TLS feature not enabled"),
            Self::Cancelled => write!(f, "connection cancelled"),
            Self::Protocol(e) => write!(f, "protocol error: {e}"),
        }
    }
}

impl std::error::Error for WsConnectError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidUrl(e) | Self::Handshake(e) => Some(e),
            Self::Io(e) => Some(e),
            Self::Protocol(e) => Some(e),
            _ => None,
        }
    }
}

impl From<HandshakeError> for WsConnectError {
    fn from(err: HandshakeError) -> Self {
        Self::Handshake(err)
    }
}

impl From<io::Error> for WsConnectError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<WsError> for WsConnectError {
    fn from(err: WsError) -> Self {
        Self::Protocol(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_from_frame() {
        let frame = Frame::text("Hello");
        let msg = Message::from(frame);
        assert!(matches!(msg, Message::Text(s) if s == "Hello"));

        let frame = Frame::binary(vec![1, 2, 3]);
        let msg = Message::from(frame);
        assert!(matches!(msg, Message::Binary(b) if b.as_ref() == [1, 2, 3]));

        let frame = Frame::ping("ping");
        let msg = Message::from(frame);
        assert!(matches!(msg, Message::Ping(_)));

        let frame = Frame::pong("pong");
        let msg = Message::from(frame);
        assert!(matches!(msg, Message::Pong(_)));
    }

    #[test]
    fn test_frame_from_message() {
        let msg = Message::text("Hello");
        let frame = Frame::from(msg);
        assert_eq!(frame.opcode, Opcode::Text);
        assert_eq!(frame.payload.as_ref(), b"Hello");

        let msg = Message::binary(vec![1, 2, 3]);
        let frame = Frame::from(msg);
        assert_eq!(frame.opcode, Opcode::Binary);
        assert_eq!(frame.payload.as_ref(), &[1, 2, 3]);
    }

    #[test]
    fn test_config_builder() {
        let config = WebSocketConfig::new()
            .max_frame_size(1024)
            .max_message_size(4096)
            .ping_interval(Some(Duration::from_secs(60)))
            .protocol("chat")
            .nodelay(false);

        assert_eq!(config.max_frame_size, 1024);
        assert_eq!(config.max_message_size, 4096);
        assert_eq!(config.ping_interval, Some(Duration::from_secs(60)));
        assert_eq!(config.protocols, vec!["chat".to_string()]);
        assert!(!config.nodelay);
    }

    #[test]
    fn test_message_is_control() {
        assert!(!Message::text("test").is_control());
        assert!(!Message::binary(vec![]).is_control());
        assert!(Message::ping(vec![]).is_control());
        assert!(Message::pong(vec![]).is_control());
        assert!(Message::Close(None).is_control());
    }

    #[test]
    fn message_assembler_rejects_invalid_utf8() {
        let mut assembler = MessageAssembler::new(1024);
        let frame = Frame {
            fin: true,
            rsv1: false,
            rsv2: false,
            rsv3: false,
            opcode: Opcode::Text,
            masked: false,
            mask_key: None,
            payload: Bytes::from_static(&[0xFF]),
        };

        let result = assembler.push_frame(frame);
        assert!(matches!(result, Err(WsError::InvalidUtf8)));
    }

    #[test]
    fn message_assembler_reassembles_fragmented_text() {
        let mut assembler = MessageAssembler::new(1024);
        let frame1 = Frame {
            fin: false,
            rsv1: false,
            rsv2: false,
            rsv3: false,
            opcode: Opcode::Text,
            masked: false,
            mask_key: None,
            payload: Bytes::from_static(b"hel"),
        };
        let frame2 = Frame {
            fin: true,
            rsv1: false,
            rsv2: false,
            rsv3: false,
            opcode: Opcode::Continuation,
            masked: false,
            mask_key: None,
            payload: Bytes::from_static(b"lo"),
        };

        let result1 = assembler.push_frame(frame1).unwrap();
        assert!(result1.is_none());
        let result2 = assembler.push_frame(frame2).unwrap();
        assert!(matches!(result2, Some(Message::Text(s)) if s == "hello"));
    }

    #[test]
    fn message_assembler_rejects_unexpected_continuation() {
        let mut assembler = MessageAssembler::new(1024);
        let frame = Frame {
            fin: true,
            rsv1: false,
            rsv2: false,
            rsv3: false,
            opcode: Opcode::Continuation,
            masked: false,
            mask_key: None,
            payload: Bytes::from_static(b"oops"),
        };

        let result = assembler.push_frame(frame);
        assert!(matches!(result, Err(WsError::ProtocolViolation(_))));
    }

    #[test]
    fn message_assembler_enforces_max_message_size() {
        let mut assembler = MessageAssembler::new(4);
        let frame = Frame {
            fin: true,
            rsv1: false,
            rsv2: false,
            rsv3: false,
            opcode: Opcode::Binary,
            masked: false,
            mask_key: None,
            payload: Bytes::from_static(b"012345"),
        };

        let result = assembler.push_frame(frame);
        assert!(matches!(
            result,
            Err(WsError::PayloadTooLarge { max: 4, .. })
        ));
    }
}
