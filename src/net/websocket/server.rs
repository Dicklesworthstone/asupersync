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

use super::client::{Message, MessageAssembler, SlowConsumerPolicy, WebSocketConfig};
use super::close::{CloseHandshake, CloseReason, CloseState};
use super::frame::{Frame, FrameCodec, Opcode, WsError};
use super::handshake::{AcceptResponse, HandshakeError, HttpRequest, ServerHandshake};
use crate::bytes::BytesMut;
use crate::codec::{Decoder, Encoder};
use crate::cx::{CancelWakerToken, Cx};
use crate::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use std::io;
use std::pin::Pin;
use std::task::Poll;
use std::time::Duration;

const MAX_PENDING_PONGS: usize = 16;

fn enqueue_pending_pong(
    pending_pongs: &mut std::collections::VecDeque<crate::bytes::Bytes>,
    payload: crate::bytes::Bytes,
) {
    if pending_pongs.len() >= MAX_PENDING_PONGS {
        let _ = pending_pongs.pop_front();
    }
    pending_pongs.push_back(payload);
}

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

    /// Enable RFC 7692 compression with 15-bit windows and no context takeover.
    /// Live negotiation validates every selected parameter before writing 101.
    #[cfg(feature = "compression")]
    #[must_use]
    pub fn permessage_deflate(self) -> Self {
        self.extension("permessage-deflate")
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

    /// Set maximum encoded bytes retained for a pending outbound frame.
    #[must_use]
    pub fn max_pending_write_bytes(mut self, bytes: usize) -> Self {
        self.config.max_pending_write_bytes = bytes;
        self
    }

    /// Set the slow-consumer policy for outbound write-buffer overflow.
    #[must_use]
    pub fn slow_consumer_policy(mut self, policy: SlowConsumerPolicy) -> Self {
        self.config.slow_consumer_policy = policy;
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
        if cx.checkpoint().is_err() {
            return Err(WsAcceptError::Cancelled);
        }

        // Parse HTTP request and extract any trailing bytes (pipelined frames)
        let (request, trailing) = HttpRequest::parse_with_trailing(request_bytes)?;

        // Validate and generate accept response
        let mut accept_response = self.handshake.accept(&request)?;
        accept_response.extensions = super::compression::negotiate_server(&accept_response.extensions, request.header("sec-websocket-extensions"))?;

        // Check cancellation before sending response
        if cx.checkpoint().is_err() {
            return Err(WsAcceptError::Cancelled);
        }

        // Send HTTP 101 response
        let response_bytes = accept_response.response_bytes();
        stream.write_all(&response_bytes).await?;

        // Create server WebSocket, seeding any trailing bytes into the read buffer
        let ws =
            ServerWebSocket::from_upgraded(stream, self.config.clone(), accept_response, trailing);

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
        if cx.checkpoint().is_err() {
            return Err(WsAcceptError::Cancelled);
        }

        // Validate and generate accept response
        let mut accept_response = self.handshake.accept(request)?;
        accept_response.extensions = super::compression::negotiate_server(&accept_response.extensions, request.header("sec-websocket-extensions"))?;

        // Check cancellation before sending response
        if cx.checkpoint().is_err() {
            return Err(WsAcceptError::Cancelled);
        }

        // Send HTTP 101 response
        let response_bytes = accept_response.response_bytes();
        stream.write_all(&response_bytes).await?;

        // Create server WebSocket with no trailing bytes (already parsed externally)
        let ws = ServerWebSocket::from_upgraded(stream, self.config.clone(), accept_response, &[]);

        Ok(ws)
    }

    /// Finish an upgrade whose HTTP `101 Switching Protocols` response has
    /// already been flushed by an outer HTTP/1 server.
    ///
    /// This is the second half of a two-phase upgrade. The caller owns the
    /// commit point: it must validate the request, build `accept_response`, and
    /// completely flush that response before calling this method. No HTTP bytes
    /// are written here. Any bytes the HTTP codec read beyond the request head
    /// must be supplied in `read_ahead`; they are seeded into the WebSocket
    /// decoder before the transport is polled again.
    #[must_use]
    pub fn finish_upgrade<IO>(
        &self,
        io: IO,
        accept_response: AcceptResponse,
        read_ahead: &[u8],
    ) -> ServerWebSocket<IO>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        ServerWebSocket::from_upgraded(io, self.config.clone(), accept_response, read_ahead)
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
        stream.write_all(&response).await
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
    #[allow(dead_code)] // retained for potential config inspection
    config: WebSocketConfig,
    /// Message assembler for fragmented frames.
    assembler: MessageAssembler,
    /// Negotiated subprotocol (if any).
    protocol: Option<String>,
    /// Negotiated extensions.
    extensions: Vec<String>,
    /// Pending pong payloads to send.
    pending_pongs: std::collections::VecDeque<crate::bytes::Bytes>,
    /// Retained heartbeat deadlines and the one outstanding Ping payload.
    heartbeat: super::heartbeat::Heartbeat,
}

impl<IO> ServerWebSocket<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    /// Create a WebSocket from an already-upgraded I/O stream.
    fn from_upgraded(
        io: IO,
        config: WebSocketConfig,
        accept: AcceptResponse,
        trailing: &[u8],
    ) -> Self {
        let max_message_size = config.max_message_size;
        let mut codec = FrameCodec::server().max_payload_size(config.max_frame_size);
        let compression = super::compression::negotiated(&accept.extensions);
        if matches!(compression, Ok(true)) { codec.enable_permessage_deflate(); }
        let mut close_handshake = CloseHandshake::with_config(config.close_config.clone());
        if compression.is_err() {
            // finish_upgrade's caller owns negotiation. A fabricated/unsupported
            // completed negotiation must not produce an open live connection.
            close_handshake.force_close(CloseReason::new(super::CloseCode::ProtocolError, None));
        }
        let mut read_buf = BytesMut::with_capacity(8192);
        if !trailing.is_empty() {
            read_buf.extend_from_slice(trailing);
        }
        Self {
            io,
            codec,
            read_buf,
            write_buf: BytesMut::with_capacity(8192),
            close_handshake,
            config,
            assembler: MessageAssembler::new(max_message_size),
            protocol: accept.protocol,
            extensions: accept.extensions,
            pending_pongs: std::collections::VecDeque::new(),
            heartbeat: super::heartbeat::Heartbeat::default(),
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

    /// Whether permessage-deflate is active for this connection.
    #[must_use]
    pub fn compression_enabled(&self) -> bool { self.codec.permessage_deflate_enabled() }

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
        if cx.checkpoint().is_err() {
            self.close_after_cancelled_send(cx, true).await;
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
                .initiate_close_with_cx(Some(cx), reason.unwrap_or_else(CloseReason::normal))
                .await;
        }
        if let Message::Ping(payload) | Message::Pong(payload) = &msg {
            super::frame::check_control_payload_len(payload.len())?;
        }

        let frame = super::compression::outgoing(
            Frame::from(msg), self.codec.permessage_deflate_enabled(),
            self.config.max_message_size,
            self.config.max_frame_size,
        )?;
        match self.send_frame_with_cx(Some(cx), frame).await {
            Err(WsError::Io(e))
                if e.kind() == io::ErrorKind::Interrupted && cx.checkpoint().is_err() =>
            {
                self.close_after_cancelled_send(cx, false).await;
                Err(WsError::Io(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "cancelled",
                )))
            }
            res => res,
        }
    }

    /// Receive a message.
    ///
    /// Returns `None` when the connection is closed.
    ///
    /// # Cancel-Safety
    ///
    /// This method is cancel-safe. If cancelled, no data is lost.
    pub async fn recv(&mut self, cx: &Cx) -> Result<Option<Message>, WsError> {
        let mut steps = 0;
        loop {
            steps += 1;
            if steps >= 64 {
                crate::runtime::yield_now().await;
                steps = 0;
            }

            // Check cancellation
            if cx.checkpoint().is_err() {
                let timeout_duration = self.close_handshake.close_timeout();
                let current_time = || {
                    cx.timer_driver()
                        .map_or_else(crate::time::wall_now, |driver| driver.now())
                };
                let _ = crate::time::timeout(
                    current_time(),
                    timeout_duration,
                    self.initiate_close(self.close_handshake.cancellation_reason()),
                )
                .await;
                return Err(WsError::Io(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "cancelled",
                )));
            }

            if self.heartbeat.failed() {
                return Ok(None);
            }
            match self.heartbeat.update(
                cx,
                self.config.ping_interval,
                self.close_handshake.is_open(),
                !self.read_buf.is_empty(),
            ) {
                Ok(Some(payload)) => {
                    let mut encoded = BytesMut::new();
                    self.codec.encode(Frame::ping(payload), &mut encoded)?;
                    self.config
                        .check_outbound_write_budget(self.write_buf.len(), encoded.len())?;
                    self.write_buf.extend_from_slice(&encoded);
                    self.heartbeat.ping_queued();
                }
                Ok(None) => {}
                Err(error) => {
                    self.close_handshake
                        .force_close(CloseReason::new(super::CloseCode::Abnormal, None));
                    return Err(error);
                }
            }

            // Send any pending pongs in FIFO order (cancel-safe: pop_front() takes
            // one at a time from the front without reversing the whole queue).
            while let Some(payload) = self.pending_pongs.pop_front() {
                let pong = Frame::pong(payload);
                self.encode_frame(pong)?;
            }

            if !self.write_buf.is_empty() {
                let deadline = self.heartbeat.write_deadline();
                match super::heartbeat::wait_until(
                    cx,
                    deadline,
                    self.flush_write_buf_with_cx(Some(cx)),
                )
                .await
                {
                    Ok(Some(())) => {}
                    Ok(None) => {
                        self.heartbeat.fail();
                        self.close_handshake
                            .force_close(CloseReason::new(super::CloseCode::Abnormal, None));
                        return Err(super::heartbeat::timeout_error());
                    }
                    Err(WsError::Io(e))
                        if e.kind() == std::io::ErrorKind::Interrupted
                            && cx.checkpoint().is_err() =>
                    {
                        continue;
                    }
                    Err(e) => return Err(e),
                }
            }

            // A compressed message decodes in bounded steps with a yield
            // between them, so one large message cannot hold this worker
            // for its whole decode (br-asupersync-ydis91).
            if self.assembler.is_inflating() {
                match self.assembler.resume() {
                    Ok(Some(msg)) => return Ok(Some(msg)),
                    Ok(None) => {
                        crate::runtime::yield_now().await;
                        continue;
                    }
                    Err(err) => {
                        // RFC 6455 §7.1.7, as for push_frame below.
                        self.codec.poison();
                        self.close_handshake
                            .force_close(CloseReason::new(err.as_close_code(), None));
                        return Err(err);
                    }
                }
            }

            let decoded = self.codec.decode(&mut self.read_buf).inspect_err(|error| {
                self.close_handshake
                    .force_close(CloseReason::new(error.as_close_code(), None));
            })?;
            if let Some(frame) = decoded {
                // Handle control frames
                match frame.opcode {
                    Opcode::Ping => {
                        // Cap pending pongs to prevent memory DoS via ping
                        // flooding while preserving FIFO order of newest items.
                        enqueue_pending_pong(&mut self.pending_pongs, frame.payload);
                    }
                    Opcode::Pong => {
                        self.heartbeat.received_pong(&frame.payload);
                    }
                    Opcode::Close => {
                        // Handle close handshake
                        if let Some(response) = self.close_handshake.receive_close(&frame)? {
                            let deadline = self.heartbeat.write_deadline();
                            let send_result = super::heartbeat::wait_until(cx, deadline, async {
                                self.encode_frame(response)?;
                                self.flush_write_buf_with_cx(Some(cx)).await
                            })
                            .await;
                            if send_result?.is_none() {
                                self.heartbeat.fail();
                                self.close_handshake.force_close(CloseReason::new(
                                    super::CloseCode::Abnormal,
                                    None,
                                ));
                                return Err(super::heartbeat::timeout_error());
                            }
                            self.close_handshake.mark_response_sent();
                            // RFC 6455 section 5.5.1: once both Close frames
                            // have been exchanged the server MUST close the
                            // TCP connection at once. The handshake is
                            // complete, so a failed shutdown changes nothing
                            // the caller could act on.
                            let _ = self.io.shutdown().await;
                        }
                        let reason = CloseReason::parse(&frame.payload).ok();
                        return Ok(Some(Message::Close(reason)));
                    }
                    _ => match self.assembler.push_frame(frame) {
                        Ok(Some(msg)) => return Ok(Some(msg)),
                        Ok(None) => {}
                        Err(err) => {
                            // RFC 6455 §7.1.7: a failed connection processes
                            // no further peer data, including frames already
                            // buffered behind the violation.
                            self.codec.poison();
                            self.close_handshake
                                .force_close(CloseReason::new(err.as_close_code(), None));
                            return Err(err);
                        }
                    },
                }
            } else {
                // Need more data - read from socket
                self.heartbeat.note_drained();
                if self.close_handshake.is_closed() {
                    return Ok(None);
                }

                let deadline = self.heartbeat.deadline();
                let n = match super::heartbeat::wait_until(cx, deadline, self.read_more(cx)).await {
                    Ok(Some(n)) => n,
                    Ok(None) => continue,
                    Err(WsError::Io(e))
                        if e.kind() == io::ErrorKind::Interrupted && cx.checkpoint().is_err() =>
                    {
                        continue;
                    }
                    Err(e) => return Err(e),
                };
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
    /// Sends a close frame, waits for the peer's response, then shuts down the
    /// transport.
    pub async fn close(&mut self, cx: &crate::cx::Cx, reason: CloseReason) -> Result<(), WsError> {
        // The close timeout bounds the whole handshake, including writing
        // our Close and Pong replies to a peer that stopped reading, which
        // otherwise held close() until cancellation (br-asupersync-fmw87f).
        // On expiry the connection is closed as when the peer does not
        // answer.
        let now = cx
            .timer_driver()
            .map_or_else(crate::time::wall_now, |driver| driver.now());
        let timeout_duration = self.close_handshake.close_timeout();
        if let Ok(result) =
            crate::time::timeout(now, timeout_duration, self.close_exchange(cx, reason)).await
        {
            return result;
        }
        self.close_handshake.force_close(CloseReason::going_away());
        Ok(())
    }

    async fn close_exchange(
        &mut self,
        cx: &crate::cx::Cx,
        reason: CloseReason,
    ) -> Result<(), WsError> {
        self.initiate_close_with_cx(Some(cx), reason).await?;

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
                Some(frame) => match frame.opcode {
                    Opcode::Ping => {
                        self.send_frame(Frame::pong(frame.payload)).await?;
                    }
                    Opcode::Pong => {
                        // Keepalive confirmation; nothing else to do while closing.
                    }
                    _ => {
                        // Ignore data frames during close.
                    }
                },
                None => {
                    let time_now = current_time();

                    if time_now >= deadline {
                        self.close_handshake.force_close(CloseReason::going_away());
                        break;
                    }
                    let remaining =
                        std::time::Duration::from_nanos(deadline.duration_since(time_now));

                    match crate::time::timeout(time_now, remaining, self.read_more(cx)).await {
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

        // RFC 6455 section 5.5.1: the server closes the TCP connection once
        // the close handshake ends (the client waits for it to).
        self.io.shutdown().await.map_err(WsError::Io)?;
        Ok(())
    }

    /// Send a ping frame.
    pub async fn ping(
        &mut self,
        cx: &Cx,
        payload: impl Into<crate::bytes::Bytes>,
    ) -> Result<(), WsError> {
        if cx.checkpoint().is_err() {
            let timeout_duration = self.close_handshake.close_timeout();
            let current_time = || {
                cx.timer_driver()
                    .map_or_else(crate::time::wall_now, |driver| driver.now())
            };
            let _ = crate::time::timeout(
                current_time(),
                timeout_duration,
                self.initiate_close(self.close_handshake.cancellation_reason()),
            )
            .await;
            return Err(WsError::Io(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "cancelled",
            )));
        }

        let payload: crate::bytes::Bytes = payload.into();
        super::frame::check_control_payload_len(payload.len())?;
        let frame = Frame::ping(payload);
        match self.send_frame_with_cx(Some(cx), frame).await {
            Err(WsError::Io(e))
                if e.kind() == std::io::ErrorKind::Interrupted && cx.checkpoint().is_err() =>
            {
                let timeout_duration = self.close_handshake.close_timeout();
                let current_time = || {
                    cx.timer_driver()
                        .map_or_else(crate::time::wall_now, |driver| driver.now())
                };
                let _ = crate::time::timeout(
                    current_time(),
                    timeout_duration,
                    self.initiate_close(self.close_handshake.cancellation_reason()),
                )
                .await;
                Err(WsError::Io(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "cancelled",
                )))
            }
            res => res,
        }
    }

    /// Internal: initiate close without waiting.
    async fn initiate_close(&mut self, reason: CloseReason) -> Result<(), WsError> {
        self.initiate_close_with_cx(None, reason).await
    }

    async fn close_after_cancelled_send(&mut self, cx: &Cx, close_when_uncommitted: bool) {
        if self.write_buf.is_empty() && !close_when_uncommitted {
            let reason = self.close_handshake.cancellation_reason();
            self.close_handshake.force_close(reason);
            return;
        }

        let timeout_duration = self.close_handshake.close_timeout();
        let current_time = || {
            cx.timer_driver()
                .map_or_else(crate::time::wall_now, |driver| driver.now())
        };
        let _ = crate::time::timeout(
            current_time(),
            timeout_duration,
            self.initiate_close(self.close_handshake.cancellation_reason()),
        )
        .await;
    }

    async fn initiate_close_with_cx(
        &mut self,
        op_cx: Option<&Cx>,
        reason: CloseReason,
    ) -> Result<(), WsError> {
        if self.close_handshake.state() == CloseState::CloseReceived {
            self.flush_write_buf_with_cx(op_cx).await?;
            self.close_handshake.mark_response_sent();
            return Ok(());
        }

        if self.close_handshake.state() == CloseState::CloseSent {
            self.flush_write_buf_with_cx(op_cx).await?;
            return Ok(());
        }

        if let Some(frame) = self.close_handshake.initiate(reason) {
            // The Close goes into the retained write buffer before the first
            // await. The handshake is CloseSent from here on, so a close
            // dropped before writing would otherwise lose the frame: a retry
            // only flushes the buffer (br-asupersync-fmw87f M2).
            self.encode_frame(frame)?;
            self.flush_write_buf_with_cx(op_cx).await?;
        }
        Ok(())
    }

    /// Internal: encode a frame into the write buffer.
    fn encode_frame(&mut self, frame: Frame) -> Result<(), WsError> {
        self.codec.encode(frame, &mut self.write_buf)?;
        Ok(())
    }

    fn write_path_cancelled(op_cx: Option<&Cx>, is_open: bool) -> bool {
        match op_cx {
            // An explicitly supplied operation context stays authoritative after
            // a Close frame moves the handshake to CloseSent, as on the split
            // halves. Otherwise close() writing its Close frame to a peer that
            // stopped reading could no longer observe cancellation and hung
            // forever (br-asupersync-fmw87f).
            Some(cx) => cx.checkpoint().is_err(),
            // Callers without an explicit context keep the established
            // behaviour: ambient cancellation counts only while the connection
            // is open.
            None => {
                is_open
                    && crate::cx::Cx::with_current(|cx| cx.checkpoint().is_err()).unwrap_or(false)
            }
        }
    }

    async fn flush_write_buf_with_cx(&mut self, op_cx: Option<&Cx>) -> Result<(), WsError> {
        use std::future::poll_fn;

        if self.heartbeat.failed() {
            return Err(super::heartbeat::timeout_error());
        }

        // br-asupersync-2k3o9x: wake a write parked on a stalled peer on cancel.
        let ambient = op_cx.is_none().then(crate::cx::Cx::current).flatten();
        let cx_for_wake: Option<&Cx> = op_cx.or(ambient.as_ref());
        let mut cancel_wake = cx_for_wake.map(WsCancelWakerGuard::new);

        while !self.write_buf.is_empty() {
            let is_open = self.close_handshake.is_open();
            let n = poll_fn(|task_cx| {
                if Self::write_path_cancelled(op_cx, is_open) {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "cancelled",
                    )));
                }
                if is_open || op_cx.is_some() {
                    if let Some(guard) = cancel_wake.as_mut() {
                        guard.refresh(task_cx.waker());
                    }
                }
                Pin::new(&mut self.io).poll_write(task_cx, &self.write_buf[..])
            })
            .await?;
            if n == 0 {
                return Err(WsError::Io(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "write returned 0",
                )));
            }
            let _ = self.write_buf.split_to(n);
        }

        let is_open = self.close_handshake.is_open();
        poll_fn(|task_cx| {
            if Self::write_path_cancelled(op_cx, is_open) {
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled")));
            }
            if is_open || op_cx.is_some() {
                if let Some(guard) = cancel_wake.as_mut() {
                    guard.refresh(task_cx.waker());
                }
            }
            Pin::new(&mut self.io).poll_flush(task_cx)
        })
        .await?;

        Ok(())
    }

    async fn write_buf_to_io_with_cx(
        &mut self,
        op_cx: Option<&Cx>,
        buf: &mut BytesMut,
    ) -> Result<(), WsError> {
        use std::future::poll_fn;

        if self.heartbeat.failed() {
            return Err(super::heartbeat::timeout_error());
        }

        if buf.is_empty() {
            return Ok(());
        }

        // br-asupersync-2k3o9x: wake a write parked on a stalled peer on cancel.
        let ambient = op_cx.is_none().then(crate::cx::Cx::current).flatten();
        let cx_for_wake: Option<&Cx> = op_cx.or(ambient.as_ref());
        let mut cancel_wake = cx_for_wake.map(WsCancelWakerGuard::new);

        let is_open = self.close_handshake.is_open();
        let n = poll_fn(|task_cx| {
            if Self::write_path_cancelled(op_cx, is_open) {
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled")));
            }
            if is_open || op_cx.is_some() {
                if let Some(guard) = cancel_wake.as_mut() {
                    guard.refresh(task_cx.waker());
                }
            }
            Pin::new(&mut self.io).poll_write(task_cx, &buf[..])
        })
        .await?;
        if n == 0 {
            return Err(WsError::Io(io::Error::new(
                io::ErrorKind::WriteZero,
                "write returned 0",
            )));
        }

        let _ = buf.split_to(n);
        if !buf.is_empty() {
            if let Err(err) = self
                .config
                .check_outbound_write_budget(self.write_buf.len(), buf.len())
            {
                self.close_after_outbound_backpressure();
                return Err(err);
            }
            self.write_buf.extend_from_slice(&buf[..]);
            buf.clear();
            return self.flush_write_buf_with_cx(op_cx).await;
        }

        let is_open = self.close_handshake.is_open();
        poll_fn(|task_cx| {
            if Self::write_path_cancelled(op_cx, is_open) {
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled")));
            }
            if is_open || op_cx.is_some() {
                if let Some(guard) = cancel_wake.as_mut() {
                    guard.refresh(task_cx.waker());
                }
            }
            Pin::new(&mut self.io).poll_flush(task_cx)
        })
        .await?;

        Ok(())
    }

    /// Internal: send a single frame.
    async fn send_frame(&mut self, frame: Frame) -> Result<(), WsError> {
        self.send_frame_with_cx(None, frame).await
    }

    async fn send_frame_with_cx(
        &mut self,
        op_cx: Option<&Cx>,
        frame: Frame,
    ) -> Result<(), WsError> {
        if !self.write_buf.is_empty() {
            self.flush_write_buf_with_cx(op_cx).await?;
        }
        let mut encoded = BytesMut::new();
        self.codec.encode(frame, &mut encoded)?;
        if let Err(err) = self
            .config
            .check_outbound_write_budget(self.write_buf.len(), encoded.len())
        {
            self.close_after_outbound_backpressure();
            return Err(err);
        }
        self.write_buf_to_io_with_cx(op_cx, &mut encoded).await
    }

    fn close_after_outbound_backpressure(&mut self) {
        if let Some(reason) = self.config.slow_consumer_close_reason() {
            self.close_handshake.force_close(reason);
        }
    }

    /// Internal: read more data into buffer.
    async fn read_more(&mut self, cx: &Cx) -> Result<usize, WsError> {
        // Ensure we have space
        if self.read_buf.capacity() - self.read_buf.len() < 4096 {
            self.read_buf.reserve(8192);
        }

        // Create a temporary buffer for reading
        let mut temp = [0u8; 4096];
        let n = read_some_io(cx, &mut self.io, &mut temp, self.close_handshake.is_open()).await?;

        if n > 0 {
            self.read_buf.extend_from_slice(&temp[..n]);
            self.heartbeat.note_read();
        }

        Ok(n)
    }
}

/// Read some bytes from an I/O stream.
/// Registers one cancellation-Waker on the read's `Cx` for the lifetime of a
/// parked socket read (br-asupersync-r8n4qx). A websocket read parked waiting
/// for the next frame from a silent peer is never re-polled on its own, so
/// without this an external `cancel_with` went unnoticed until a frame finally
/// arrived (or the OS TCP timeout). Mirrors the mysql/redis/nats guard.
struct WsCancelWakerGuard<'a> {
    cx: &'a Cx,
    token: Option<CancelWakerToken>,
}

impl<'a> WsCancelWakerGuard<'a> {
    fn new(cx: &'a Cx) -> Self {
        Self { cx, token: None }
    }

    fn refresh(&mut self, waker: &std::task::Waker) {
        self.token = Some(self.cx.refresh_cancel_waker(self.token, waker));
    }
}

impl Drop for WsCancelWakerGuard<'_> {
    fn drop(&mut self) {
        if let Some(token) = self.token.take() {
            self.cx.clear_cancel_waker(token);
        }
    }
}

async fn read_some_io<IO: AsyncRead + Unpin>(
    cx: &Cx,
    io: &mut IO,
    buf: &mut [u8],
    is_open: bool,
) -> Result<usize, WsError> {
    use std::future::poll_fn;

    // br-asupersync-r8n4qx: wake a read parked on a silent peer when an external
    // cancel fires, instead of only noticing it on the next self-poll.
    let mut cancel_wake = WsCancelWakerGuard::new(cx);
    poll_fn(|poll_cx| {
        if is_open && cx.checkpoint().is_err() {
            return Poll::Ready(Err(WsError::Io(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "cancelled",
            ))));
        }
        if is_open {
            cancel_wake.refresh(poll_cx.waker());
        }
        let mut read_buf = ReadBuf::new(buf);
        match Pin::new(&mut *io).poll_read(poll_cx, &mut read_buf) {
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
#[path = "server_inline_tests.rs"]
mod tests;
