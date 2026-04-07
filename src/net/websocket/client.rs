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
use crate::codec::Decoder;
use crate::cx::Cx;
use crate::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use crate::net::TcpStream;
use crate::util::{EntropySource, OsEntropy};
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

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

        let total_len = partial.data.len().saturating_add(frame.payload.len());
        if total_len > self.max_message_size {
            // Clear partial state to prevent corrupt follow-up continuations
            self.partial = None;
            return Err(WsError::PayloadTooLarge {
                size: total_len as u64,
                max: self.max_message_size,
            });
        }

        partial.data.extend_from_slice(frame.payload.as_ref());

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

impl TryFrom<Frame> for Message {
    type Error = WsError;

    fn try_from(frame: Frame) -> Result<Self, WsError> {
        match frame.opcode {
            Opcode::Text => {
                let text = std::str::from_utf8(frame.payload.as_ref())
                    .map_err(|_| WsError::InvalidUtf8)?;
                Ok(Self::Text(text.to_owned()))
            }
            Opcode::Binary => Ok(Self::Binary(frame.payload)),
            Opcode::Continuation => Err(WsError::ProtocolViolation(
                "continuation frame requires message assembler context",
            )),
            Opcode::Ping => Ok(Self::Ping(frame.payload)),
            Opcode::Pong => Ok(Self::Pong(frame.payload)),
            Opcode::Close => {
                let reason = CloseReason::parse(&frame.payload).ok();
                Ok(Self::Close(reason))
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
    pub(super) pending_pongs: std::collections::VecDeque<Bytes>,
    /// Entropy used for client masking when no per-call Cx is available.
    pub(super) entropy: Arc<dyn EntropySource>,
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
        Self::from_upgraded_with_entropy(io, config, Arc::new(OsEntropy))
    }

    /// Create a WebSocket from an upgraded I/O stream with an explicit
    /// entropy capability for client masking.
    #[must_use]
    pub fn from_upgraded_with_entropy(
        io: IO,
        config: WebSocketConfig,
        entropy: Arc<dyn EntropySource>,
    ) -> Self {
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
            pending_pongs: std::collections::VecDeque::new(),
            entropy,
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
            let timeout_duration = self.close_handshake.close_timeout();
            let current_time = || {
                cx.timer_driver()
                    .map_or_else(crate::time::wall_now, |driver| driver.now())
            };
            let _ = crate::time::timeout(
                current_time(),
                timeout_duration,
                self.initiate_close(CloseReason::going_away()),
            )
            .await;
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

        if let Message::Close(reason) = msg {
            return self
                .initiate_close(reason.unwrap_or_else(CloseReason::normal))
                .await;
        }

        let frame = Frame::from(msg);
        self.send_frame_with_entropy(&frame, cx.entropy()).await
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
                let timeout_duration = self.close_handshake.close_timeout();
                let current_time = || {
                    cx.timer_driver()
                        .map_or_else(crate::time::wall_now, |driver| driver.now())
                };
                let _ = crate::time::timeout(
                    current_time(),
                    timeout_duration,
                    self.initiate_close(CloseReason::going_away()),
                )
                .await;
                return Err(WsError::Io(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "cancelled",
                )));
            }

            // Send any pending pongs in FIFO order (cancel-safe: pop_front() takes
            // one at a time from the front without reversing the whole queue).
            while let Some(payload) = self.pending_pongs.pop_front() {
                let pong = Frame::pong(payload);
                self.encode_frame_with_entropy(&pong, cx.entropy())?;
            }

            if !self.write_buf.is_empty() {
                self.flush_write_buf().await?;
            }

            if let Some(frame) = self.codec.decode(&mut self.read_buf)? {
                // Handle control frames
                match frame.opcode {
                    Opcode::Ping => {
                        // Cap pending pongs to prevent memory DoS via ping
                        // flooding while preserving FIFO order of newest items.
                        if self.pending_pongs.len() >= 16 {
                            let _ = self.pending_pongs.pop_front();
                        }
                        self.pending_pongs.push_back(frame.payload);
                    }
                    Opcode::Pong => {
                        // Pong received - keepalive confirmed
                    }
                    Opcode::Close => {
                        // Handle close handshake
                        if let Some(response) = self.close_handshake.receive_close(&frame)? {
                            let send_result = async {
                                self.encode_frame_with_entropy(&response, cx.entropy())?;
                                self.flush_write_buf().await
                            }
                            .await;
                            send_result?;
                            self.close_handshake.mark_response_sent();
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
    pub async fn close(&mut self, cx: &Cx, reason: CloseReason) -> Result<(), WsError> {
        self.initiate_close(reason).await?;

        // Wait for close response (with timeout)
        let timeout_duration = self.close_handshake.close_timeout();
        let current_time = || {
            cx.timer_driver()
                .map_or_else(crate::time::wall_now, |driver| driver.now())
        };
        let initial_time = current_time();
        let deadline = initial_time + timeout_duration;

        while !self.close_handshake.is_closed() {
            let time_now = current_time();

            if time_now >= deadline {
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
                    let time_now = current_time();

                    if time_now >= deadline {
                        self.close_handshake.force_close(CloseReason::going_away());
                        break;
                    }
                    let remaining =
                        std::time::Duration::from_nanos(deadline.duration_since(time_now));

                    match crate::time::timeout(time_now, remaining, self.read_more()).await {
                        Ok(Ok(n)) => {
                            if n == 0 {
                                self.close_handshake.force_close(CloseReason::going_away());
                                break;
                            }
                        }
                        Ok(Err(e)) => return Err(e),
                        Err(_) => {
                            // Timeout elapsed
                            self.close_handshake.force_close(CloseReason::going_away());
                            break;
                        }
                    }
                }
            }
        }

        self.io.shutdown().await.map_err(WsError::Io)?;
        Ok(())
    }

    /// Send a ping frame.
    pub async fn ping(&mut self, payload: impl Into<Bytes>) -> Result<(), WsError> {
        let frame = Frame::ping(payload);
        self.send_frame(&frame).await
    }

    /// Internal: initiate close without waiting.
    async fn initiate_close(&mut self, reason: CloseReason) -> Result<(), WsError> {
        if self.close_handshake.state() == CloseState::CloseReceived {
            self.flush_write_buf().await?;
            self.close_handshake.mark_response_sent();
            return Ok(());
        }

        if self.close_handshake.state() == CloseState::CloseSent {
            self.flush_write_buf().await?;
            return Ok(());
        }

        if let Some(frame) = self.close_handshake.initiate(reason) {
            self.send_frame(&frame).await?;
        }
        Ok(())
    }

    fn encode_frame_with_entropy(
        &mut self,
        frame: &Frame,
        entropy: &dyn EntropySource,
    ) -> Result<(), WsError> {
        self.codec
            .encode_with_entropy(frame, &mut self.write_buf, entropy)
    }

    fn encode_frame_bytes_with_entropy(
        &self,
        frame: &Frame,
        entropy: &dyn EntropySource,
    ) -> Result<BytesMut, WsError> {
        let mut encoded = BytesMut::new();
        self.codec
            .encode_with_entropy(frame, &mut encoded, entropy)?;
        Ok(encoded)
    }

    async fn flush_write_buf(&mut self) -> Result<(), WsError> {
        use std::future::poll_fn;

        while !self.write_buf.is_empty() {
            let n =
                poll_fn(|cx| Pin::new(&mut self.io).poll_write(cx, &self.write_buf[..])).await?;
            if n == 0 {
                return Err(WsError::Io(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "write returned 0",
                )));
            }
            let _ = self.write_buf.split_to(n);
        }

        poll_fn(|cx| Pin::new(&mut self.io).poll_flush(cx)).await?;

        Ok(())
    }

    async fn write_frame_bytes_to_io(&mut self, buf: &mut BytesMut) -> Result<(), WsError> {
        use std::future::poll_fn;

        if buf.is_empty() {
            return Ok(());
        }

        let n = poll_fn(|cx| Pin::new(&mut self.io).poll_write(cx, &buf[..])).await?;
        if n == 0 {
            return Err(WsError::Io(io::Error::new(
                io::ErrorKind::WriteZero,
                "write returned 0",
            )));
        }
        let _ = buf.split_to(n);

        if !buf.is_empty() {
            self.write_buf.extend_from_slice(&buf[..]);
            buf.clear();
            return self.flush_write_buf().await;
        }

        poll_fn(|cx| Pin::new(&mut self.io).poll_flush(cx)).await?;

        Ok(())
    }

    async fn send_frame_with_entropy(
        &mut self,
        frame: &Frame,
        entropy: &dyn EntropySource,
    ) -> Result<(), WsError> {
        if !self.write_buf.is_empty() {
            self.flush_write_buf().await?;
        }
        let mut encoded = self.encode_frame_bytes_with_entropy(frame, entropy)?;
        self.write_frame_bytes_to_io(&mut encoded).await
    }

    /// Internal: send a single frame.
    async fn send_frame(&mut self, frame: &Frame) -> Result<(), WsError> {
        let entropy = Arc::clone(&self.entropy);
        self.send_frame_with_entropy(frame, entropy.as_ref()).await
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
        let addr = if parsed.host.contains(':') {
            format!("[{}]:{}", parsed.host, parsed.port)
        } else {
            format!("{}:{}", parsed.host, parsed.port)
        };
        let tcp = if let Some(timeout) = config.connect_timeout {
            TcpStream::connect_timeout(addr, timeout).await?
        } else {
            TcpStream::connect(addr).await?
        };

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
        let mut handshake = ClientHandshake::new(
            &format!("ws://{}:{}{}", url.host, url.port, url.path),
            cx.entropy(),
        )?;

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
        let mut ws = Self::from_upgraded_with_entropy(tcp, config.clone(), cx.entropy_handle());
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

/// Read HTTP response (until the blank line ending the headers).
///
/// Returns `(headers, trailing)` where `trailing` contains any bytes read
/// past the header boundary (these belong to the first WebSocket frame
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
        // WebSocket frame) are not lost. We must find the *earliest* terminator.
        let crlf_pos = buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4);
        let lf_pos = buf.windows(2).position(|w| w == b"\n\n").map(|p| p + 2);

        let split_at = match (crlf_pos, lf_pos) {
            (Some(c), Some(l)) => Some(std::cmp::min(c, l)),
            (Some(c), None) => Some(c),
            (None, Some(l)) => Some(l),
            (None, None) => None,
        };

        if let Some(split_at) = split_at {
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
    use crate::codec::Encoder;
    use crate::io::{AsyncRead, AsyncWrite, ReadBuf};
    use crate::types::{Budget, RegionId, TaskId};
    use crate::util::EntropySource;
    use futures_lite::future;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::Poll;

    struct TestIo {
        read_data: Vec<u8>,
        read_pos: usize,
        written: Vec<u8>,
        fail_writes: bool,
        pending_first_write: bool,
        partial_first_write_len: Option<usize>,
        pending_after_partial_write: bool,
    }

    impl TestIo {
        fn new() -> Self {
            Self::with_read_data(Vec::new())
        }

        fn with_read_data(read_data: Vec<u8>) -> Self {
            Self {
                read_data,
                read_pos: 0,
                written: Vec::new(),
                fail_writes: false,
                pending_first_write: false,
                partial_first_write_len: None,
                pending_after_partial_write: false,
            }
        }

        fn with_write_failure(mut self) -> Self {
            self.fail_writes = true;
            self
        }

        fn with_pending_first_write(mut self) -> Self {
            self.pending_first_write = true;
            self
        }

        fn with_partial_first_write(mut self, len: usize) -> Self {
            self.partial_first_write_len = Some(len);
            self.pending_after_partial_write = true;
            self
        }
    }

    fn encode_server_frame(frame: Frame) -> Vec<u8> {
        let mut codec = FrameCodec::server();
        let mut out = BytesMut::new();
        codec
            .encode(frame, &mut out)
            .expect("frame encoding should succeed");
        out.to_vec()
    }

    impl AsyncRead for TestIo {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let remaining = &self.read_data[self.read_pos..];
            let to_read = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..to_read]);
            self.read_pos += to_read;
            Poll::Ready(Ok(()))
        }
    }

    fn encode_client_frame_with_entropy(frame: &Frame, entropy: &dyn EntropySource) -> Vec<u8> {
        let codec = FrameCodec::client();
        let mut out = BytesMut::new();
        codec
            .encode_with_entropy(frame, &mut out, entropy)
            .expect("frame encoding should succeed");
        out.to_vec()
    }

    impl AsyncWrite for TestIo {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            if self.fail_writes {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "synthetic write failure",
                )));
            }
            if self.pending_first_write {
                self.pending_first_write = false;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            if let Some(len) = self.partial_first_write_len.take() {
                let to_write = len.min(buf.len());
                self.written.extend_from_slice(&buf[..to_write]);
                return Poll::Ready(Ok(to_write));
            }
            if self.pending_after_partial_write {
                self.pending_after_partial_write = false;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            self.written.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn read_http_response_accepts_lf_only_headers_and_preserves_trailing_bytes() {
        future::block_on(async {
            let mut io = TestIo::with_read_data(
                b"HTTP/1.1 101 Switching Protocols\n\
                  Upgrade: websocket\n\
                  Connection: Upgrade\n\
                  Sec-WebSocket-Accept: xyz\n\
                  \n\
                  \x81\x00"
                    .to_vec(),
            );

            let (headers, trailing) = read_http_response(&mut io)
                .await
                .expect("LF-only response should still parse");

            assert_eq!(
                headers,
                b"HTTP/1.1 101 Switching Protocols\n\
                  Upgrade: websocket\n\
                  Connection: Upgrade\n\
                  Sec-WebSocket-Accept: xyz\n\
                  \n"
            );
            assert_eq!(trailing, vec![0x81, 0x00]);

            let parsed = HttpResponse::parse(&headers).expect("parsed response");
            assert_eq!(parsed.status, 101);
            assert_eq!(parsed.header("upgrade"), Some("websocket"));
        });
    }

    #[test]
    fn test_message_from_frame() {
        let frame = Frame::text("Hello");
        let msg = Message::try_from(frame).unwrap();
        assert!(matches!(msg, Message::Text(s) if s == "Hello"));

        let frame = Frame::binary(vec![1, 2, 3]);
        let msg = Message::try_from(frame).unwrap();
        assert!(matches!(msg, Message::Binary(b) if b.as_ref() == [1, 2, 3]));

        let frame = Frame::ping("ping");
        let msg = Message::try_from(frame).unwrap();
        assert!(matches!(msg, Message::Ping(_)));

        let frame = Frame::pong("pong");
        let msg = Message::try_from(frame).unwrap();
        assert!(matches!(msg, Message::Pong(_)));

        let frame = Frame {
            fin: true,
            rsv1: false,
            rsv2: false,
            rsv3: false,
            opcode: Opcode::Continuation,
            masked: false,
            mask_key: None,
            payload: Bytes::from_static(b"tail"),
        };
        let err = Message::try_from(frame).unwrap_err();
        assert!(matches!(err, WsError::ProtocolViolation(_)));
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

    #[test]
    fn message_assembler_rejects_double_data_frame() {
        // Starting a new data frame while a fragmented message is in progress
        // is a protocol violation (must send continuation).
        let mut assembler = MessageAssembler::new(1024);

        // Start a fragmented message (fin=false).
        let frame1 = Frame {
            fin: false,
            rsv1: false,
            rsv2: false,
            rsv3: false,
            opcode: Opcode::Text,
            masked: false,
            mask_key: None,
            payload: Bytes::from_static(b"part1"),
        };
        assert!(assembler.push_frame(frame1).unwrap().is_none());

        // Send another data frame (not continuation) — protocol violation.
        let frame2 = Frame {
            fin: true,
            rsv1: false,
            rsv2: false,
            rsv3: false,
            opcode: Opcode::Binary,
            masked: false,
            mask_key: None,
            payload: Bytes::from_static(b"wrong"),
        };
        let result = assembler.push_frame(frame2);
        assert!(matches!(result, Err(WsError::ProtocolViolation(_))));
    }

    #[test]
    fn message_assembler_continuation_exceeds_max_size() {
        // Individual fragments are small, but total exceeds limit.
        let mut assembler = MessageAssembler::new(8);

        let frame1 = Frame {
            fin: false,
            rsv1: false,
            rsv2: false,
            rsv3: false,
            opcode: Opcode::Binary,
            masked: false,
            mask_key: None,
            payload: Bytes::from_static(b"12345"), // 5 bytes
        };
        assert!(assembler.push_frame(frame1).unwrap().is_none());

        let frame2 = Frame {
            fin: true,
            rsv1: false,
            rsv2: false,
            rsv3: false,
            opcode: Opcode::Continuation,
            masked: false,
            mask_key: None,
            payload: Bytes::from_static(b"6789A"), // 5 more = 10 > 8
        };
        let result = assembler.push_frame(frame2);
        assert!(matches!(
            result,
            Err(WsError::PayloadTooLarge { max: 8, .. })
        ));
    }

    #[test]
    fn config_defaults() {
        let config = WebSocketConfig::default();
        assert_eq!(config.max_frame_size, 16 * 1024 * 1024);
        assert_eq!(config.max_message_size, 64 * 1024 * 1024);
        assert_eq!(config.ping_interval, Some(Duration::from_secs(30)));
        assert!(config.protocols.is_empty());
        assert_eq!(config.connect_timeout, Some(Duration::from_secs(30)));
        assert!(config.nodelay);
    }

    #[test]
    fn config_connect_timeout_builder() {
        let config = WebSocketConfig::new().connect_timeout(None);
        assert_eq!(config.connect_timeout, None);

        let config = WebSocketConfig::new().connect_timeout(Some(Duration::from_secs(5)));
        assert_eq!(config.connect_timeout, Some(Duration::from_secs(5)));
    }

    #[test]
    fn ws_connect_error_display() {
        let err = WsConnectError::TlsRequired;
        assert!(err.to_string().contains("TLS"));

        let err = WsConnectError::Cancelled;
        assert!(err.to_string().contains("cancelled"));

        let err = WsConnectError::Io(io::Error::new(io::ErrorKind::TimedOut, "timeout"));
        assert!(err.to_string().contains("I/O error"));
    }

    #[test]
    fn message_constructors() {
        let msg = Message::text("hello");
        assert!(matches!(msg, Message::Text(s) if s == "hello"));

        let msg = Message::binary(vec![1, 2]);
        assert!(matches!(msg, Message::Binary(_)));

        let msg = Message::ping(vec![3]);
        assert!(matches!(msg, Message::Ping(_)));

        let msg = Message::pong(vec![4]);
        assert!(matches!(msg, Message::Pong(_)));

        let reason = CloseReason::normal();
        let msg = Message::close(reason);
        assert!(matches!(msg, Message::Close(Some(_))));
    }

    #[test]
    fn message_assembler_binary_single_frame() {
        let mut assembler = MessageAssembler::new(1024);
        let frame = Frame {
            fin: true,
            rsv1: false,
            rsv2: false,
            rsv3: false,
            opcode: Opcode::Binary,
            masked: false,
            mask_key: None,
            payload: Bytes::from_static(&[0xDE, 0xAD, 0xBE, 0xEF]),
        };
        let msg = assembler.push_frame(frame).unwrap().unwrap();
        assert!(matches!(msg, Message::Binary(b) if b.as_ref() == [0xDE, 0xAD, 0xBE, 0xEF]));
    }

    #[test]
    fn send_close_message_initiates_close_handshake() {
        future::block_on(async {
            let mut ws = WebSocket::from_upgraded(TestIo::new(), WebSocketConfig::default());
            let cx = Cx::for_testing();

            assert!(ws.is_open(), "connection should start open");
            ws.send(&cx, Message::Close(None))
                .await
                .expect("sending close should succeed");
            assert!(
                !ws.is_open(),
                "sending Message::Close must transition handshake out of open state"
            );

            let err = ws
                .send(&cx, Message::text("late payload"))
                .await
                .expect_err("data frames must be rejected after close initiation");
            assert!(
                matches!(err, WsError::Io(ref e) if e.kind() == io::ErrorKind::NotConnected),
                "expected NotConnected after close initiation, got {err:?}"
            );
        });
    }

    #[test]
    fn close_uses_explicit_cx_and_closes_on_peer_eof() {
        future::block_on(async {
            let mut ws = WebSocket::from_upgraded(TestIo::new(), WebSocketConfig::default());
            let cx = Cx::for_testing();

            ws.close(&cx, CloseReason::normal())
                .await
                .expect("close should complete cleanly on EOF");

            assert!(ws.is_closed(), "close handshake should finish closed");
            assert!(
                !ws.io.written.is_empty(),
                "close should emit a close frame before waiting for peer shutdown"
            );
        });
    }

    #[test]
    fn recv_keeps_close_received_state_if_response_send_fails() {
        future::block_on(async {
            let io = TestIo::with_read_data(encode_server_frame(Frame::close(Some(1000), None)))
                .with_write_failure();
            let mut ws = WebSocket::from_upgraded(io, WebSocketConfig::default());
            let cx = Cx::for_testing();

            let err = ws
                .recv(&cx)
                .await
                .expect_err("close response write should fail");
            assert!(
                matches!(err, WsError::Io(ref e) if e.kind() == io::ErrorKind::BrokenPipe),
                "expected synthetic broken-pipe write failure, got {err:?}"
            );
            assert!(
                !ws.is_closed(),
                "failed close response writes must not incorrectly finish the handshake"
            );
            assert_eq!(
                ws.close_state(),
                CloseState::CloseReceived,
                "failed close response writes must leave the handshake waiting for a retry"
            );
        });
    }

    #[derive(Debug)]
    struct NoopWake;

    impl std::task::Wake for NoopWake {
        fn wake(self: Arc<Self>) {}

        fn wake_by_ref(self: &Arc<Self>) {}
    }

    #[test]
    fn cancelled_send_does_not_flush_frame_later() {
        future::block_on(async {
            let entropy: Arc<dyn EntropySource> = Arc::new(FixedEntropy([0x12, 0x34, 0x56, 0x78]));
            let cx = test_cx_with_entropy(Arc::clone(&entropy));
            let mut ws = WebSocket::from_upgraded(
                TestIo::new().with_pending_first_write(),
                WebSocketConfig::default(),
            );

            let cancelled = Message::text("cancelled");
            let delivered = Message::text("delivered");
            let mut cancelled_send = Box::pin(ws.send(&cx, cancelled));
            let waker = std::task::Waker::from(Arc::new(NoopWake));
            let mut poll_cx = std::task::Context::from_waker(&waker);

            assert!(
                matches!(cancelled_send.as_mut().poll(&mut poll_cx), Poll::Pending),
                "first send should park before any bytes are written"
            );
            drop(cancelled_send);

            assert!(
                ws.write_buf.is_empty(),
                "dropping a parked send must not leave its frame in the shared write buffer"
            );

            ws.send(&cx, delivered.clone())
                .await
                .expect("second send should succeed");

            let expected =
                encode_client_frame_with_entropy(&Frame::from(delivered), entropy.as_ref());
            assert_eq!(
                ws.io.written, expected,
                "later flushes must not emit bytes from a cancelled send"
            );
        });
    }

    #[test]
    fn cancelled_send_after_partial_write_preserves_tail_for_later_flush() {
        future::block_on(async {
            let entropy: Arc<dyn EntropySource> = Arc::new(FixedEntropy([0x12, 0x34, 0x56, 0x78]));
            let cx = test_cx_with_entropy(Arc::clone(&entropy));
            let mut ws = WebSocket::from_upgraded(
                TestIo::new().with_partial_first_write(1),
                WebSocketConfig::default(),
            );

            let cancelled = Message::text("cancelled");
            let delivered = Message::text("delivered");
            let expected_cancelled =
                encode_client_frame_with_entropy(&Frame::from(cancelled.clone()), entropy.as_ref());
            let expected_delivered =
                encode_client_frame_with_entropy(&Frame::from(delivered.clone()), entropy.as_ref());
            let mut cancelled_send = Box::pin(ws.send(&cx, cancelled));
            let waker = std::task::Waker::from(Arc::new(NoopWake));
            let mut poll_cx = std::task::Context::from_waker(&waker);

            assert!(
                matches!(cancelled_send.as_mut().poll(&mut poll_cx), Poll::Pending),
                "send should park after the first byte is written and the remainder is buffered"
            );
            drop(cancelled_send);

            assert!(
                !ws.write_buf.is_empty(),
                "after any byte hits the wire, the unwritten tail must stay durable"
            );
            assert_eq!(
                ws.io.written,
                expected_cancelled[..1].to_vec(),
                "the transport should contain only the committed prefix before retry"
            );

            ws.send(&cx, delivered)
                .await
                .expect("second send should flush the durable tail before the next frame");

            let mut expected = expected_cancelled;
            expected.extend_from_slice(&expected_delivered);
            assert_eq!(
                ws.io.written, expected,
                "later flushes must preserve the partially written frame before the next send"
            );
        });
    }

    #[test]
    fn close_after_cancelled_recv_flushes_pending_echo_without_second_close() {
        future::block_on(async {
            let entropy: Arc<dyn EntropySource> = Arc::new(FixedEntropy([0x21, 0x43, 0x65, 0x87]));
            let cx = test_cx_with_entropy(Arc::clone(&entropy));
            let peer_close = encode_server_frame(Frame::close(Some(1000), None));
            let mut ws = WebSocket::from_upgraded(
                TestIo::with_read_data(peer_close).with_pending_first_write(),
                WebSocketConfig::default(),
            );
            let mut cancelled_recv = Box::pin(ws.recv(&cx));
            let waker = std::task::Waker::from(Arc::new(NoopWake));
            let mut poll_cx = std::task::Context::from_waker(&waker);

            assert!(
                matches!(cancelled_recv.as_mut().poll(&mut poll_cx), Poll::Pending),
                "recv should park while flushing the echoed close response"
            );
            drop(cancelled_recv);

            assert_eq!(
                ws.close_state(),
                CloseState::CloseReceived,
                "cancelling recv mid-flush must leave the echoed response pending"
            );
            assert!(
                !ws.write_buf.is_empty(),
                "the echoed close response should stay buffered for a later retry"
            );

            ws.close(&cx, CloseReason::going_away())
                .await
                .expect("close should finish the pending echoed response");

            assert!(
                ws.is_closed(),
                "finishing the pending echoed response must close the handshake"
            );

            let expected =
                encode_client_frame_with_entropy(&Frame::close(Some(1000), None), entropy.as_ref());
            assert_eq!(
                ws.io.written, expected,
                "retrying close after a cancelled recv must not append a second close frame"
            );
        });
    }

    #[test]
    fn close_after_partially_flushed_echo_preserves_tail_without_second_close() {
        future::block_on(async {
            let entropy: Arc<dyn EntropySource> = Arc::new(FixedEntropy([0x21, 0x43, 0x65, 0x87]));
            let cx = test_cx_with_entropy(Arc::clone(&entropy));
            let peer_close = encode_server_frame(Frame::close(Some(1000), None));
            let mut ws = WebSocket::from_upgraded(
                TestIo::with_read_data(peer_close).with_partial_first_write(1),
                WebSocketConfig::default(),
            );
            let expected =
                encode_client_frame_with_entropy(&Frame::close(Some(1000), None), entropy.as_ref());
            let mut cancelled_recv = Box::pin(ws.recv(&cx));
            let waker = std::task::Waker::from(Arc::new(NoopWake));
            let mut poll_cx = std::task::Context::from_waker(&waker);

            assert!(
                matches!(cancelled_recv.as_mut().poll(&mut poll_cx), Poll::Pending),
                "recv should park after partially flushing the echoed close response"
            );
            drop(cancelled_recv);

            assert_eq!(
                ws.close_state(),
                CloseState::CloseReceived,
                "partial close-response flush must leave the handshake awaiting completion"
            );
            assert!(
                !ws.write_buf.is_empty(),
                "the echoed close tail must remain buffered after partial I/O"
            );
            assert_eq!(
                ws.io.written,
                expected[..1].to_vec(),
                "only the committed close-frame prefix should hit the transport before retry"
            );

            ws.close(&cx, CloseReason::going_away())
                .await
                .expect("close should flush the durable close tail");

            assert!(
                ws.is_closed(),
                "completing the echoed close tail must close the handshake"
            );
            assert_eq!(
                ws.io.written, expected,
                "retrying close must finish the original close frame without appending a second one"
            );
        });
    }

    #[test]
    fn close_retry_flushes_partially_sent_close_without_second_close() {
        future::block_on(async {
            let entropy: Arc<dyn EntropySource> = Arc::new(FixedEntropy([0x23, 0x45, 0x67, 0x89]));
            let cx = test_cx_with_entropy(Arc::clone(&entropy));
            let peer_close = encode_server_frame(Frame::close(Some(1000), None));
            let mut ws = WebSocket::from_upgraded_with_entropy(
                TestIo::with_read_data(peer_close).with_partial_first_write(1),
                WebSocketConfig::default(),
                Arc::clone(&entropy),
            );
            let expected =
                encode_client_frame_with_entropy(&Frame::close(Some(1001), None), entropy.as_ref());
            let mut cancelled_close = Box::pin(ws.close(&cx, CloseReason::going_away()));
            let waker = std::task::Waker::from(Arc::new(NoopWake));
            let mut poll_cx = std::task::Context::from_waker(&waker);

            assert!(
                matches!(cancelled_close.as_mut().poll(&mut poll_cx), Poll::Pending),
                "close should park after partially writing the initiated close frame"
            );
            drop(cancelled_close);

            assert_eq!(
                ws.close_state(),
                CloseState::CloseSent,
                "cancelling close after a partial write must keep the handshake in CloseSent"
            );
            assert!(
                !ws.write_buf.is_empty(),
                "the initiated close tail must remain buffered after partial I/O"
            );
            assert_eq!(
                ws.io.written,
                expected[..1].to_vec(),
                "only the committed close-frame prefix should hit the transport before retry"
            );

            ws.close(&cx, CloseReason::going_away())
                .await
                .expect("retrying close should flush the durable close tail and finish");

            assert!(
                ws.is_closed(),
                "the peer close should complete the handshake"
            );
            assert_eq!(
                ws.io.written, expected,
                "retrying close must finish the original close frame without appending another"
            );
        });
    }

    #[derive(Debug, Clone, Copy)]
    struct FixedEntropy([u8; 4]);

    impl EntropySource for FixedEntropy {
        fn fill_bytes(&self, dest: &mut [u8]) {
            for (idx, byte) in dest.iter_mut().enumerate() {
                *byte = self.0[idx % self.0.len()];
            }
        }

        fn next_u64(&self) -> u64 {
            u64::from_le_bytes([
                self.0[0], self.0[1], self.0[2], self.0[3], self.0[0], self.0[1], self.0[2],
                self.0[3],
            ])
        }

        fn fork(&self, _task_id: TaskId) -> Arc<dyn EntropySource> {
            Arc::new(*self)
        }

        fn source_id(&self) -> &'static str {
            "fixed"
        }
    }

    fn test_cx_with_entropy(entropy: Arc<dyn EntropySource>) -> Cx {
        Cx::new_with_observability(
            RegionId::new_for_test(0, 0),
            TaskId::new_for_test(0, 0),
            Budget::INFINITE,
            None,
            None,
            Some(entropy),
        )
    }

    #[test]
    fn send_uses_cx_entropy_for_client_masking() {
        future::block_on(async {
            let mut ws = WebSocket::from_upgraded(TestIo::new(), WebSocketConfig::default());
            let entropy: Arc<dyn EntropySource> = Arc::new(FixedEntropy([0xAA, 0xBB, 0xCC, 0xDD]));
            let cx = test_cx_with_entropy(entropy);

            ws.send(&cx, Message::text("hi"))
                .await
                .expect("send should succeed");

            assert_eq!(&ws.io.written[2..6], &[0xAA, 0xBB, 0xCC, 0xDD]);
        });
    }
}
