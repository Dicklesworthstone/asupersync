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
use super::close::{CloseHandshake, CloseReason, CloseState};
use super::frame::{Frame, FrameCodec, Opcode, WsError};
use super::handshake::{AcceptResponse, HandshakeError, HttpRequest, ServerHandshake};
use crate::bytes::BytesMut;
use crate::codec::{Decoder, Encoder};
use crate::cx::Cx;
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

        // Parse HTTP request and extract any trailing bytes (pipelined frames)
        let (request, trailing) = HttpRequest::parse_with_trailing(request_bytes)?;

        // Validate and generate accept response
        let accept_response = self.handshake.accept(&request)?;

        // Check cancellation before sending response
        if cx.is_cancel_requested() {
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
        stream.write_all(&response_bytes).await?;

        // Create server WebSocket with no trailing bytes (already parsed externally)
        let ws = ServerWebSocket::from_upgraded(stream, self.config.clone(), accept_response, &[]);

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
        let codec = FrameCodec::server().max_payload_size(config.max_frame_size);
        let mut read_buf = BytesMut::with_capacity(8192);
        if !trailing.is_empty() {
            read_buf.extend_from_slice(trailing);
        }
        Self {
            io,
            codec,
            read_buf,
            write_buf: BytesMut::with_capacity(8192),
            close_handshake: CloseHandshake::with_config(config.close_config.clone()),
            config,
            assembler: MessageAssembler::new(max_message_size),
            protocol: accept.protocol,
            extensions: accept.extensions,
            pending_pongs: std::collections::VecDeque::new(),
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
                self.encode_frame(pong)?;
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
                        enqueue_pending_pong(&mut self.pending_pongs, frame.payload);
                    }
                    Opcode::Pong => {
                        // Pong received - keepalive confirmed
                    }
                    Opcode::Close => {
                        // Handle close handshake
                        if let Some(response) = self.close_handshake.receive_close(&frame)? {
                            let send_result = async {
                                self.encode_frame(response)?;
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
    pub async fn close(&mut self, cx: &crate::cx::Cx, reason: CloseReason) -> Result<(), WsError> {
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

        Ok(())
    }

    /// Send a ping frame.
    pub async fn ping(&mut self, payload: impl Into<crate::bytes::Bytes>) -> Result<(), WsError> {
        let frame = Frame::ping(payload);
        self.send_frame(frame).await
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
            self.send_frame(frame).await?;
        }
        Ok(())
    }

    /// Internal: encode a frame into the write buffer.
    fn encode_frame(&mut self, frame: Frame) -> Result<(), WsError> {
        self.codec.encode(frame, &mut self.write_buf)?;
        Ok(())
    }

    /// Internal: flush the write buffer to the underlying I/O stream.
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

    async fn write_buf_to_io(&mut self, buf: &mut BytesMut) -> Result<(), WsError> {
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

    /// Internal: send a single frame.
    async fn send_frame(&mut self, frame: Frame) -> Result<(), WsError> {
        if !self.write_buf.is_empty() {
            self.flush_write_buf().await?;
        }
        let mut encoded = BytesMut::new();
        self.codec.encode(frame, &mut encoded)?;
        self.write_buf_to_io(&mut encoded).await
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
    use crate::io::{AsyncRead, AsyncWrite, ReadBuf};
    use futures_lite::future;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::Poll;

    enum WriteBehavior {
        Immediate,
        PendingFirst,
        PartialThenPending(PartialWriteStage),
    }

    enum PartialWriteStage {
        WritePrefix(usize),
        PendingTail,
    }

    struct TestIo {
        read_data: Vec<u8>,
        read_pos: usize,
        written: Vec<u8>,
        fail_writes: bool,
        write_behavior: WriteBehavior,
        pending_first_flush: bool,
        flush_calls: usize,
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
                write_behavior: WriteBehavior::Immediate,
                pending_first_flush: false,
                flush_calls: 0,
            }
        }

        fn with_write_failure(mut self) -> Self {
            self.fail_writes = true;
            self
        }

        fn with_pending_first_write(mut self) -> Self {
            self.write_behavior = WriteBehavior::PendingFirst;
            self
        }

        fn with_partial_first_write(mut self, len: usize) -> Self {
            self.write_behavior =
                WriteBehavior::PartialThenPending(PartialWriteStage::WritePrefix(len));
            self
        }

        fn with_pending_first_flush(mut self) -> Self {
            self.pending_first_flush = true;
            self
        }
    }

    fn encode_client_frame(frame: Frame) -> Vec<u8> {
        let mut codec = FrameCodec::client();
        let mut out = BytesMut::new();
        codec
            .encode(frame, &mut out)
            .expect("frame encoding should succeed");
        out.to_vec()
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
            match std::mem::replace(&mut self.write_behavior, WriteBehavior::Immediate) {
                WriteBehavior::Immediate => {}
                WriteBehavior::PendingFirst
                | WriteBehavior::PartialThenPending(PartialWriteStage::PendingTail) => {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                WriteBehavior::PartialThenPending(PartialWriteStage::WritePrefix(len)) => {
                    let to_write = len.min(buf.len());
                    self.written.extend_from_slice(&buf[..to_write]);
                    self.write_behavior =
                        WriteBehavior::PartialThenPending(PartialWriteStage::PendingTail);
                    return Poll::Ready(Ok(to_write));
                }
            }
            self.written.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> Poll<io::Result<()>> {
            self.flush_calls += 1;
            if self.pending_first_flush {
                self.pending_first_flush = false;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
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

    // Pure data-type tests (wave 15 – CyanBarn)

    #[test]
    fn acceptor_debug() {
        let acceptor = WebSocketAcceptor::new();
        let dbg = format!("{acceptor:?}");
        assert!(dbg.contains("WebSocketAcceptor"));
    }

    #[test]
    fn acceptor_clone() {
        let acceptor = WebSocketAcceptor::new()
            .protocol("chat")
            .max_frame_size(4096);
        let cloned = acceptor;
        assert_eq!(cloned.config.max_frame_size, 4096);
        assert_eq!(cloned.config.protocols.len(), 1);
    }

    #[test]
    fn acceptor_close_timeout_default() {
        let acceptor = WebSocketAcceptor::default();
        // Default close timeout should be reasonable (non-zero).
        assert!(acceptor.config.close_config.close_timeout > Duration::ZERO);
    }

    #[test]
    fn acceptor_builder_chain_all() {
        let acceptor = WebSocketAcceptor::new()
            .protocol("mqtt")
            .extension("permessage-deflate")
            .max_frame_size(512)
            .max_message_size(2048)
            .ping_interval(Some(Duration::from_secs(15)))
            .close_timeout(Duration::from_secs(5));

        assert_eq!(acceptor.config.max_frame_size, 512);
        assert_eq!(acceptor.config.max_message_size, 2048);
        assert_eq!(acceptor.config.ping_interval, Some(Duration::from_secs(15)));
        assert_eq!(
            acceptor.config.close_config.close_timeout,
            Duration::from_secs(5)
        );
    }

    #[test]
    fn acceptor_ping_interval_none() {
        let acceptor = WebSocketAcceptor::new().ping_interval(None);
        assert_eq!(acceptor.config.ping_interval, None);
    }

    #[test]
    fn ws_accept_error_display_invalid_request() {
        let err = WsAcceptError::InvalidRequest("missing Upgrade header".into());
        let s = err.to_string();
        assert!(s.contains("invalid request"));
        assert!(s.contains("missing Upgrade header"));
    }

    #[test]
    fn ws_accept_error_display_cancelled() {
        let err = WsAcceptError::Cancelled;
        assert_eq!(err.to_string(), "accept cancelled");
    }

    #[test]
    fn ws_accept_error_debug() {
        let err = WsAcceptError::Cancelled;
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Cancelled"));
    }

    #[test]
    fn ws_accept_error_from_ws_error() {
        let ws_err = WsError::ProtocolViolation("bad frame");
        let accept_err = WsAcceptError::from(ws_err);
        assert!(matches!(accept_err, WsAcceptError::Protocol(_)));
    }

    #[test]
    fn pending_pong_queue_keeps_most_recent_payloads() {
        let mut pending = std::collections::VecDeque::new();
        for n in 0u8..20 {
            enqueue_pending_pong(&mut pending, crate::bytes::Bytes::from(vec![n]));
        }

        assert_eq!(pending.len(), MAX_PENDING_PONGS);
        let kept: Vec<u8> = pending
            .into_iter()
            .map(|payload| *payload.first().expect("single-byte payload"))
            .collect();
        assert_eq!(kept, (4u8..20).collect::<Vec<_>>());
    }

    #[test]
    fn send_close_message_initiates_close_handshake() {
        future::block_on(async {
            let accept = AcceptResponse {
                accept_key: String::new(),
                protocol: None,
                extensions: Vec::new(),
            };
            let mut ws = ServerWebSocket::from_upgraded(
                TestIo::new(),
                WebSocketConfig::default(),
                accept,
                &[],
            );
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
    fn recv_keeps_close_received_state_if_response_send_fails() {
        future::block_on(async {
            let accept = AcceptResponse {
                accept_key: String::new(),
                protocol: None,
                extensions: Vec::new(),
            };
            let io = TestIo::with_read_data(encode_client_frame(Frame::close(Some(1000), None)))
                .with_write_failure();
            let mut ws =
                ServerWebSocket::from_upgraded(io, WebSocketConfig::default(), accept, &[]);
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
                ws.close_handshake.state(),
                crate::net::websocket::CloseState::CloseReceived,
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
            let accept = AcceptResponse {
                accept_key: String::new(),
                protocol: None,
                extensions: Vec::new(),
            };
            let mut ws = ServerWebSocket::from_upgraded(
                TestIo::new().with_pending_first_write(),
                WebSocketConfig::default(),
                accept,
                &[],
            );
            let cx = Cx::for_testing();
            let cancelled = Message::text("cancelled");
            let delivered = Message::text("delivered");
            let mut cancelled_send = Box::pin(ws.send(&cx, cancelled));
            let waker = std::task::Waker::from(std::sync::Arc::new(NoopWake));
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

            let expected = vec![129, 9, 100, 101, 108, 105, 118, 101, 114, 101, 100];
            assert_eq!(
                ws.io.written, expected,
                "later flushes must not emit bytes from a cancelled send"
            );
        });
    }

    #[test]
    fn cancelled_send_after_partial_write_preserves_tail_for_later_flush() {
        future::block_on(async {
            let accept = AcceptResponse {
                accept_key: String::new(),
                protocol: None,
                extensions: Vec::new(),
            };
            let mut ws = ServerWebSocket::from_upgraded(
                TestIo::new().with_partial_first_write(1),
                WebSocketConfig::default(),
                accept,
                &[],
            );
            let cx = Cx::for_testing();
            let cancelled = Message::text("cancelled");
            let delivered = Message::text("delivered");
            let expected_cancelled = encode_server_frame(Frame::from(cancelled.clone()));
            let expected_delivered = encode_server_frame(Frame::from(delivered.clone()));
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
                .expect("later sends should flush the durable tail first");

            assert_eq!(
                ws.io.written,
                [expected_cancelled, expected_delivered].concat(),
                "retrying send must finish the first server frame before appending the second"
            );
        });
    }

    #[test]
    fn close_after_cancelled_recv_flushes_pending_echo_without_second_close() {
        future::block_on(async {
            let accept = AcceptResponse {
                accept_key: String::new(),
                protocol: None,
                extensions: Vec::new(),
            };
            let read_data = encode_client_frame(Frame::close(Some(1000), None));
            let mut ws = ServerWebSocket::from_upgraded(
                TestIo::with_read_data(read_data).with_pending_first_write(),
                WebSocketConfig::default(),
                accept,
                &[],
            );
            let cx = Cx::for_testing();
            let mut cancelled_recv = Box::pin(ws.recv(&cx));
            let waker = std::task::Waker::from(std::sync::Arc::new(NoopWake));
            let mut poll_cx = std::task::Context::from_waker(&waker);

            assert!(
                matches!(cancelled_recv.as_mut().poll(&mut poll_cx), Poll::Pending),
                "recv should park while flushing the echoed close response"
            );
            drop(cancelled_recv);

            assert_eq!(
                ws.close_handshake.state(),
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
            assert_eq!(
                ws.io.written,
                encode_server_frame(Frame::close(Some(1000), None)),
                "retrying close after a cancelled recv must not append a second close frame"
            );
        });
    }

    #[test]
    fn close_after_cancelled_recv_retries_pending_transport_flush_without_second_close() {
        future::block_on(async {
            let accept = AcceptResponse {
                accept_key: String::new(),
                protocol: None,
                extensions: Vec::new(),
            };
            let read_data = encode_client_frame(Frame::close(Some(1000), None));
            let mut ws = ServerWebSocket::from_upgraded(
                TestIo::with_read_data(read_data).with_pending_first_flush(),
                WebSocketConfig::default(),
                accept,
                &[],
            );
            let cx = Cx::for_testing();
            let mut cancelled_recv = Box::pin(ws.recv(&cx));
            let waker = std::task::Waker::from(std::sync::Arc::new(NoopWake));
            let mut poll_cx = std::task::Context::from_waker(&waker);

            assert!(
                matches!(cancelled_recv.as_mut().poll(&mut poll_cx), Poll::Pending),
                "recv should park while the echoed close response is waiting on poll_flush"
            );
            drop(cancelled_recv);

            assert_eq!(
                ws.close_handshake.state(),
                CloseState::CloseReceived,
                "cancelling recv during poll_flush must leave the echoed response pending"
            );
            assert!(
                ws.write_buf.is_empty(),
                "all close-response bytes should already be written before the deferred flush"
            );
            assert_eq!(
                ws.io.flush_calls, 1,
                "the cancelled recv should have attempted exactly one transport flush"
            );

            ws.close(&cx, CloseReason::going_away())
                .await
                .expect("close should retry the deferred transport flush");

            assert!(
                ws.is_closed(),
                "retrying the deferred flush must close the handshake"
            );
            assert_eq!(
                ws.io.written,
                encode_server_frame(Frame::close(Some(1000), None)),
                "retrying close after a cancelled recv must not append a second close frame"
            );
            assert_eq!(
                ws.io.flush_calls, 2,
                "close should retry the deferred transport flush once"
            );
        });
    }

    #[test]
    fn close_retry_flushes_partially_sent_close_without_second_close() {
        future::block_on(async {
            let accept = AcceptResponse {
                accept_key: String::new(),
                protocol: None,
                extensions: Vec::new(),
            };
            let peer_close = encode_client_frame(Frame::close(Some(1000), None));
            let mut ws = ServerWebSocket::from_upgraded(
                TestIo::with_read_data(peer_close).with_partial_first_write(1),
                WebSocketConfig::default(),
                accept,
                &[],
            );
            let cx = Cx::for_testing();
            let expected = encode_server_frame(Frame::close(Some(1001), None));
            let mut cancelled_close = Box::pin(ws.close(&cx, CloseReason::going_away()));
            let waker = std::task::Waker::from(Arc::new(NoopWake));
            let mut poll_cx = std::task::Context::from_waker(&waker);

            assert!(
                matches!(cancelled_close.as_mut().poll(&mut poll_cx), Poll::Pending),
                "close should park after partially writing the initiated close frame"
            );
            drop(cancelled_close);

            assert_eq!(
                ws.close_handshake.state(),
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
                "retrying close must finish the original server close frame without appending another"
            );
        });
    }
}
