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
use super::frame::{CloseCode, Frame, FrameCodec, Opcode, WsError};
use super::handshake::{ClientHandshake, HandshakeError, HttpResponse, WsUrl};
use crate::bytes::{Bytes, BytesMut};
use crate::codec::Decoder;
use crate::cx::{CancelWakerToken, Cx};
use crate::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use crate::net::TcpStream;
#[cfg(feature = "tls")]
use crate::time::{Sleep, TimerDriverHandle};
#[cfg(feature = "tls")]
use crate::tls::{TlsConnector, TlsError, TlsStream};
#[cfg(feature = "tls")]
use crate::types::Time;
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
    compressed: bool,
}

#[derive(Debug)]
pub(super) struct MessageAssembler {
    max_message_size: usize,
    partial: Option<PartialMessage>,
    /// A complete compressed message whose decode spans polls. Its frames are
    /// consumed, so it lives here and survives an abandoned receive.
    inflating: Option<(Opcode, super::compression::Inflation)>,
}

impl MessageAssembler {
    pub(super) fn new(max_message_size: usize) -> Self {
        Self {
            max_message_size,
            partial: None,
            inflating: None,
        }
    }

    /// Whether a compressed message is still decoding. The receiver resumes
    /// it, yielding between steps, before it decodes another frame.
    pub(super) fn is_inflating(&self) -> bool {
        self.inflating.is_some()
    }

    /// Decode the pending compressed message one bounded step further
    /// (br-asupersync-ydis91). `Ok(None)` means it is not complete yet.
    pub(super) fn resume(&mut self) -> Result<Option<Message>, WsError> {
        let Some((opcode, inflation)) = self.inflating.as_mut() else {
            return Ok(None);
        };
        let opcode = *opcode;
        let step = inflation.step(super::compression::INFLATE_STEP_CHUNKS);
        if !matches!(step, Ok(None)) {
            self.inflating = None;
        }
        match step? {
            Some(payload) => Ok(Some(message_from_payload(opcode, payload)?)),
            None => Ok(None),
        }
    }

    fn complete(
        &mut self,
        opcode: Opcode,
        payload: Bytes,
        compressed: bool,
    ) -> Result<Option<Message>, WsError> {
        match super::compression::incoming(payload, compressed, self.max_message_size)? {
            super::compression::Incoming::Ready(payload) => {
                Ok(Some(message_from_payload(opcode, payload)?))
            }
            super::compression::Incoming::Inflating(inflation) => {
                self.inflating = Some((opcode, inflation));
                self.resume()
            }
        }
    }

    pub(super) fn push_frame(&mut self, frame: Frame) -> Result<Option<Message>, WsError> {
        debug_assert!(
            self.inflating.is_none(),
            "a frame arrived before the pending message finished decoding"
        );
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
            return self.complete(frame.opcode, frame.payload, frame.rsv1);
        }

        let mut data = BytesMut::with_capacity(payload_len);
        data.extend_from_slice(frame.payload.as_ref());
        self.partial = Some(PartialMessage {
            opcode: frame.opcode,
            data,
            compressed: frame.rsv1,
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
        let compressed = partial.compressed;
        let data = std::mem::take(&mut partial.data).freeze();
        self.partial = None;
        self.complete(opcode, data, compressed)
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
    /// Automatic Ping cadence while `recv` is being polled. A matching Pong
    /// must arrive within one more interval, including any blocked Ping write.
    /// `None` disables heartbeat; zero is rounded up to one millisecond.
    /// The timer and outstanding payload survive dropped/recreated `recv`
    /// waits and split/reunite. No background task is spawned: callers must
    /// keep receiving to drive heartbeats.
    pub ping_interval: Option<Duration>,
    /// Close handshake configuration.
    pub close_config: CloseConfig,
    /// Maximum encoded bytes that may be retained in the outbound write buffer.
    pub max_pending_write_bytes: usize,
    /// Policy used when an outbound frame cannot fit in the bounded write buffer.
    pub slow_consumer_policy: SlowConsumerPolicy,
    /// Requested subprotocols.
    pub protocols: Vec<String>,
    /// Connection timeout. Plaintext `connect` bounds TCP and HTTP upgrade
    /// separately. `connect_tls` uses one budget for DNS, TCP, TLS, and upgrade.
    /// `None` removes this limit; caller deadlines still apply to `connect_tls`.
    pub connect_timeout: Option<Duration>,
    /// Enable TCP_NODELAY.
    pub nodelay: bool,
}

/// Default cap for the retained outbound write buffer.
///
/// The cap admits one default maximum-payload frame plus the largest RFC 6455
/// header (64-bit length + client mask). Larger application frames must opt in.
pub const DEFAULT_MAX_PENDING_WRITE_BYTES: usize = FrameCodec::DEFAULT_MAX_PAYLOAD_SIZE + 14;

/// Policy applied when an outbound frame would exceed the retained write-buffer cap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlowConsumerPolicy {
    /// Keep the connection open and report a typed error to the caller.
    Wait,
    /// Fail the connection with 1013 (Try Again Later) and report a typed error.
    CloseWithTryAgainLater,
}

impl SlowConsumerPolicy {
    const fn action(self) -> &'static str {
        match self {
            Self::Wait => "wait",
            Self::CloseWithTryAgainLater => "close-with-1013",
        }
    }
}

impl Default for WebSocketConfig {
    fn default() -> Self {
        Self {
            max_frame_size: 16 * 1024 * 1024,   // 16 MB
            max_message_size: 64 * 1024 * 1024, // 64 MB
            ping_interval: Some(Duration::from_secs(30)),
            close_config: CloseConfig::default(),
            max_pending_write_bytes: DEFAULT_MAX_PENDING_WRITE_BYTES,
            slow_consumer_policy: SlowConsumerPolicy::Wait,
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

    /// Set the maximum encoded bytes retained for a pending outbound frame.
    ///
    /// This is a cancellation-safety bound: if a write partially commits a
    /// frame, the remaining bytes must stay owned by the connection so a retry
    /// cannot interleave a second frame or silently drop bytes.
    #[must_use]
    pub fn max_pending_write_bytes(mut self, bytes: usize) -> Self {
        self.max_pending_write_bytes = bytes;
        self
    }

    /// Set the policy used when the outbound write-buffer bound is exceeded.
    #[must_use]
    pub fn slow_consumer_policy(mut self, policy: SlowConsumerPolicy) -> Self {
        self.slow_consumer_policy = policy;
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

    pub(crate) fn check_outbound_write_budget(
        &self,
        pending: usize,
        attempted: usize,
    ) -> Result<(), WsError> {
        let total = pending.saturating_add(attempted);
        if total <= self.max_pending_write_bytes {
            return Ok(());
        }

        Err(WsError::OutboundBufferFull {
            pending,
            attempted,
            max: self.max_pending_write_bytes,
            action: self.slow_consumer_policy.action(),
        })
    }

    pub(crate) fn slow_consumer_close_reason(&self) -> Option<CloseReason> {
        match self.slow_consumer_policy {
            SlowConsumerPolicy::Wait => None,
            SlowConsumerPolicy::CloseWithTryAgainLater => Some(CloseReason::with_text(
                CloseCode::TryAgainLater,
                "outbound write buffer full",
            )),
        }
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
    /// A retained Close still needs a successful transport flush. This stays
    /// set after its last byte is written, survives split/reunite, and is
    /// cleared by a successful flush or an abortive close.
    pub(super) close_flush_pending: bool,
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
    /// Retained heartbeat deadlines and the one outstanding Ping payload.
    pub(super) heartbeat: super::heartbeat::Heartbeat,
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
            close_flush_pending: false,
            close_handshake: CloseHandshake::with_config(config.close_config.clone()),
            config,
            assembler: MessageAssembler::new(max_message_size),
            protocol: None,
            pending_pongs: std::collections::VecDeque::new(),
            entropy,
            heartbeat: super::heartbeat::Heartbeat::default(),
        }
    }

    /// Create a client connection after an independently performed upgrade.
    ///
    /// The caller must validate the HTTP response, offered extensions, and TLS
    /// identity before transferring the transport. This method validates the
    /// agreed RFC 7692 profile: a 15-bit window and no server context takeover.
    /// An empty list preserves ordinary uncompressed behavior. Compression uses
    /// the existing `compression` Cargo feature. Encoded fragments and decoded
    /// messages are independently bounded by `max_message_size`. At most 256
    /// final DEFLATE sections (including a synthetic terminator) are admitted
    /// per message, bounding dictionary restoration work below 8 MiB.
    ///
    /// # Errors
    /// Returns an extension mismatch if the negotiated parameters are unsupported.
    pub fn from_upgraded_with_extensions(
        io: IO,
        config: WebSocketConfig,
        extensions: &[String],
        entropy: Arc<dyn EntropySource>,
    ) -> Result<Self, HandshakeError> {
        let compressed = super::compression::negotiated_client(extensions)?;
        let mut ws = Self::from_upgraded_with_entropy(io, config, entropy);
        if compressed { ws.codec.enable_permessage_deflate(); }
        Ok(ws)
    }

    /// Whether this connection negotiated permessage-deflate.
    #[must_use]
    pub fn compression_enabled(&self) -> bool {
        self.codec.permessage_deflate_enabled()
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
        match self
            .send_frame_with_entropy_with_cx(Some(cx), &frame, cx.entropy())
            .await
        {
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
                    let frame = Frame::ping(payload);
                    let encoded = self.encode_frame_bytes_with_entropy(&frame, cx.entropy())?;
                    self.config
                        .check_outbound_write_budget(self.write_buf.len(), encoded.len())?;
                    self.write_buf.extend_from_slice(&encoded);
                    self.heartbeat.ping_queued();
                }
                Ok(None) => {}
                Err(error) => {
                    self.force_close(CloseReason::new(super::CloseCode::Abnormal, None));
                    return Err(error);
                }
            }

            // Send any pending pongs in FIFO order (cancel-safe: pop_front() takes
            // one at a time from the front without reversing the whole queue).
            while let Some(payload) = self.pending_pongs.pop_front() {
                let pong = Frame::pong(payload);
                self.encode_frame_with_entropy(&pong, cx.entropy())?;
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
                        self.force_close(CloseReason::new(super::CloseCode::Abnormal, None));
                        return Err(super::heartbeat::timeout_error());
                    }
                    Err(WsError::Io(e))
                        if e.kind() == io::ErrorKind::Interrupted && cx.checkpoint().is_err() =>
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
                        self.force_close(CloseReason::new(err.as_close_code(), None));
                        return Err(err);
                    }
                }
            }

            let decoded = self.codec.decode(&mut self.read_buf).inspect_err(|error| {
                self.force_close(CloseReason::new(error.as_close_code(), None));
            })?;
            if let Some(frame) = decoded {
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
                        self.heartbeat.received_pong(&frame.payload);
                    }
                    Opcode::Close => {
                        // Handle close handshake
                        if let Some(response) = self.close_handshake.receive_close(&frame)? {
                            let deadline = self.heartbeat.write_deadline();
                            let send_result = super::heartbeat::wait_until(cx, deadline, async {
                                self.encode_frame_with_entropy(&response, cx.entropy())?;
                                self.flush_write_buf_with_cx(Some(cx)).await
                            })
                            .await;
                            if send_result?.is_none() {
                                self.heartbeat.fail();
                                self.force_close(CloseReason::new(
                                    super::CloseCode::Abnormal,
                                    None,
                                ));
                                return Err(super::heartbeat::timeout_error());
                            }
                            self.close_handshake.mark_response_sent();
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
                            self.force_close(CloseReason::new(err.as_close_code(), None));
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
                    self.force_close(CloseReason::new(super::CloseCode::Abnormal, None));
                    return Ok(None);
                }
            }
        }
    }

    /// Initiate a close handshake.
    ///
    /// Sends a close frame and waits for the peer's response.
    pub async fn close(&mut self, cx: &Cx, reason: CloseReason) -> Result<(), WsError> {
        // The close timeout bounds the whole handshake, including writing
        // our Close to a peer that stopped reading, which otherwise held
        // close() until cancellation (br-asupersync-fmw87f). On expiry the
        // connection is closed as when the peer does not answer.
        let now = cx
            .timer_driver()
            .map_or_else(crate::time::wall_now, |driver| driver.now());
        let timeout_duration = self.close_handshake.close_timeout();
        if let Ok(result) =
            crate::time::timeout(now, timeout_duration, self.close_exchange(cx, reason)).await
        {
            return result;
        }
        self.force_close(CloseReason::going_away());
        Ok(())
    }

    async fn close_exchange(&mut self, cx: &Cx, reason: CloseReason) -> Result<(), WsError> {
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
                self.force_close(CloseReason::going_away());
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
                        self.force_close(CloseReason::going_away());
                        break;
                    }
                    let remaining =
                        std::time::Duration::from_nanos(deadline.duration_since(time_now));

                    match crate::time::timeout(time_now, remaining, self.read_more(cx)).await {
                        Ok(Ok(n)) => {
                            if n == 0 {
                                self.force_close(CloseReason::going_away());
                                break;
                            }
                        }
                        Ok(Err(e)) => return Err(e),
                        Err(_) => {
                            // Timeout elapsed
                            self.force_close(CloseReason::going_away());
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
    pub async fn ping(&mut self, cx: &Cx, payload: impl Into<Bytes>) -> Result<(), WsError> {
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

        let payload: Bytes = payload.into();
        super::frame::check_control_payload_len(payload.len())?;
        let frame = Frame::ping(payload);
        match self
            .send_frame_with_entropy_with_cx(Some(cx), &frame, cx.entropy())
            .await
        {
            Err(WsError::Io(e))
                if e.kind() == io::ErrorKind::Interrupted && cx.checkpoint().is_err() =>
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
                Err(WsError::Io(io::Error::new(
                    io::ErrorKind::Interrupted,
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
            self.force_close(reason);
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

        if self.close_handshake.state() == CloseState::Closed && self.close_flush_pending {
            // A split receive can observe the peer's crossing Close and then
            // be dropped while flushing our previously queued local Close.
            // Reunite preserves those bytes, so a retry must flush them even
            // though the handshake has already reached Closed. The flag also
            // retains an unfinished final poll_flush with an empty buffer,
            // without flushing again after success or an abortive close.
            self.flush_write_buf_with_cx(op_cx).await?;
            return Ok(());
        }

        if let Some(frame) = self.close_handshake.initiate(reason) {
            // The Close goes into the retained write buffer before the first
            // await. The handshake is CloseSent from here on, so a close
            // dropped before writing would otherwise lose the frame: a retry
            // only flushes the buffer (br-asupersync-fmw87f M2).
            let entropy = Arc::clone(&self.entropy);
            self.encode_frame_with_entropy(&frame, entropy.as_ref())?;
            self.flush_write_buf_with_cx(op_cx).await?;
        }
        Ok(())
    }

    fn encode_frame_with_entropy(
        &mut self,
        frame: &Frame,
        entropy: &dyn EntropySource,
    ) -> Result<(), WsError> {
        self.codec
            .encode_with_entropy(frame, &mut self.write_buf, entropy)?;
        if frame.opcode == Opcode::Close {
            self.close_flush_pending = true;
        }
        Ok(())
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

        // br-asupersync-2k3o9x: wake a write parked on a stalled (non-reading)
        // peer when an external cancel fires, instead of only noticing it on the
        // next self-poll. Effective cx = the explicit op_cx, else the ambient Cx.
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
        self.close_flush_pending = false;

        Ok(())
    }

    async fn write_frame_bytes_to_io_with_cx(
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
        self.close_flush_pending = false;

        Ok(())
    }

    async fn send_frame_with_entropy_with_cx(
        &mut self,
        op_cx: Option<&Cx>,
        frame: &Frame,
        entropy: &dyn EntropySource,
    ) -> Result<(), WsError> {
        if !self.write_buf.is_empty() {
            self.flush_write_buf_with_cx(op_cx).await?;
        }
        let mut encoded = self.encode_frame_bytes_with_entropy(frame, entropy)?;
        if let Err(err) = self
            .config
            .check_outbound_write_budget(self.write_buf.len(), encoded.len())
        {
            self.close_after_outbound_backpressure();
            return Err(err);
        }
        self.write_frame_bytes_to_io_with_cx(op_cx, &mut encoded)
            .await
    }

    fn close_after_outbound_backpressure(&mut self) {
        if let Some(reason) = self.config.slow_consumer_close_reason() {
            self.force_close(reason);
        }
    }

    fn force_close(&mut self, reason: CloseReason) {
        // CloseHandshake preserves peer_reason on force_close; that reason
        // alone must never authorize retrying a failed connection's writes.
        self.close_flush_pending = false;
        self.close_handshake.force_close(reason);
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
pub(super) struct WsCancelWakerGuard<'a> {
    cx: &'a Cx,
    token: Option<CancelWakerToken>,
}

impl<'a> WsCancelWakerGuard<'a> {
    pub(super) fn new(cx: &'a Cx) -> Self {
        Self { cx, token: None }
    }

    pub(super) fn refresh(&mut self, waker: &std::task::Waker) {
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
        Self::connect_configured(cx, url, config, false).await
    }

    /// Offer bounded permessage-deflate with a fresh dictionary per message.
    ///
    /// The peer may decline compression. If it accepts, its response must
    /// disable server context takeover and use 15-bit windows. The client never
    /// reuses its outgoing dictionary. Existing deadlines, cancellation and
    /// encoded-write limits apply to the same owned connection.
    #[cfg(feature = "compression")]
    pub async fn connect_with_compression(
        cx: &Cx, url: &str, config: WebSocketConfig,
    ) -> Result<Self, WsConnectError> {
        Self::connect_configured(cx, url, config, true).await
    }

    async fn connect_configured(
        cx: &Cx, url: &str, config: WebSocketConfig, compression: bool,
    ) -> Result<Self, WsConnectError> {
        // Parse URL
        let parsed = WsUrl::parse(url)?;

        // Check if TLS is required
        if parsed.tls {
            return Err(WsConnectError::TlsRequired);
        }

        // Check cancellation before connecting
        if cx.checkpoint().is_err() {
            return Err(WsConnectError::Cancelled);
        }

        // Connect TCP
        let addr = if parsed.host.contains(':') {
            format!("[{}]:{}", parsed.host, parsed.port)
        } else {
            format!("{}:{}", parsed.host, parsed.port)
        };
        let tcp = crate::net::happy_eyeballs::connect_resolved(addr, config.connect_timeout)
            .await
            .map_err(|err| map_tcp_connect_error(cx, err))?;

        if config.nodelay {
            let _ = tcp.set_nodelay(true);
        }

        // Perform handshake
        perform_client_handshake(cx, tcp, &parsed, &config, compression, config.connect_timeout).await
    }
}

#[cfg(feature = "tls")]
impl WebSocket<TlsStream<TcpStream>> {
    /// Connect to a secure WebSocket (`wss://`) with explicit TLS policy.
    ///
    /// The URL's hostname or IP is the certificate identity. DNS names also
    /// supply SNI. Configure roots, certificate pins, or client certificates on
    /// `connector`; this method never installs implicit trust or falls back to
    /// plaintext. Offer `http/1.1` ALPN (or no ALPN): a negotiated protocol other
    /// than `http/1.1` is rejected before any HTTP request is sent.
    ///
    /// One `connect_timeout` budget covers DNS, TCP, TLS, and the HTTP upgrade,
    /// tightened by both the explicit caller's and the ambient task's deadlines.
    /// The connector's own TLS timeout may tighten its handshake phase further.
    /// `None` removes only the configured setup limit. Successful setup does not
    /// impose this deadline on subsequent messages.
    ///
    /// The explicit context and current native task must both hold I/O and timer
    /// authority on the same runtime clock. Cancellation wakes a parked setup;
    /// dropping setup closes any acquired socket. No background WebSocket driver
    /// is spawned. Hostnames use the native offloaded system resolver: a lookup
    /// already executing may finish after its cancelled wait. Literal addresses
    /// avoid that resolver. TLS errors are returned
    /// as [`WsConnectError::Io`] with the underlying [`TlsError`] as their source.
    /// Existing plaintext [`WebSocket::connect`] remains a separate entry point.
    ///
    /// ```no_run
    /// # #[cfg(feature = "tls")]
    /// # async fn example(cx: &asupersync::Cx, connector: &asupersync::tls::TlsConnector)
    /// # -> Result<(), asupersync::net::websocket::WsConnectError> {
    /// use asupersync::net::websocket::{Message, WebSocket, WebSocketConfig};
    /// let mut socket = WebSocket::connect_tls(
    ///     cx, "wss://example.com/events", WebSocketConfig::default(), connector,
    /// ).await?;
    /// socket.send(cx, Message::text("subscribe")).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn connect_tls(
        cx: &Cx,
        url: &str,
        config: WebSocketConfig,
        connector: &TlsConnector,
    ) -> Result<Self, WsConnectError> {
        Self::connect_tls_configured(cx, url, config, connector, false).await
    }

    /// Connect with TLS and offer bounded permessage-deflate.
    ///
    /// TLS policy, ownership, and setup limits match [`Self::connect_tls`]. The
    /// compression profile matches [`WebSocket::connect_with_compression`]; the
    /// peer may decline it without preventing the secure connection.
    #[cfg(feature = "compression")]
    pub async fn connect_tls_with_compression(
        cx: &Cx,
        url: &str,
        config: WebSocketConfig,
        connector: &TlsConnector,
    ) -> Result<Self, WsConnectError> {
        Self::connect_tls_configured(cx, url, config, connector, true).await
    }

    async fn connect_tls_configured(
        cx: &Cx,
        url: &str,
        config: WebSocketConfig,
        connector: &TlsConnector,
        compression: bool,
    ) -> Result<Self, WsConnectError> {
        let parsed = WsUrl::parse(url).map_err(WsConnectError::InvalidUrl)?;
        if !parsed.tls {
            return Err(WsConnectError::InvalidUrl(HandshakeError::InvalidUrl(
                "connect_tls requires a wss:// URL".into(),
            )));
        }
        TlsConnector::validate_domain(&parsed.host).map_err(map_tls_connect_error)?;
        if parsed.host.parse::<std::net::IpAddr>().is_err() && !connector.config().enable_sni {
            return Err(WsConnectError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "secure WebSocket DNS connections require TLS SNI",
            )));
        }
        let ambient = Cx::current().ok_or_else(missing_tls_setup_authority)?;
        let mut setup = WsTlsSetup::new(cx, &ambient, config.connect_timeout)?;
        let tcp = setup.run(async {
            let result = if let Ok(ip) = parsed.host.parse::<std::net::IpAddr>() {
                TcpStream::connect(std::net::SocketAddr::new(ip, parsed.port)).await
            } else {
                crate::net::happy_eyeballs::connect_resolved(
                    (parsed.host.clone(), parsed.port),
                    None,
                )
                .await
            };
            result.map_err(|error| map_tcp_connect_error(cx, error))
        }).await?;
        if config.nodelay {
            let _ = tcp.set_nodelay(true);
        }
        let tls = setup.run(async {
            connector.connect(&parsed.host, tcp).await.map_err(map_tls_connect_error)
        }).await?;
        if tls.alpn_protocol().is_some_and(|protocol| protocol != b"http/1.1") {
            return Err(WsConnectError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "secure WebSocket peer negotiated a protocol other than HTTP/1.1",
            )));
        }
        // The outer setup retains the original timer. Starting HTTP must not
        // restore a full timeout after a slow DNS/TCP/TLS phase.
        setup.run(perform_client_handshake(cx, tls, &parsed, &config, compression, None)).await
    }
}

#[cfg(feature = "tls")]
fn missing_tls_setup_authority() -> WsConnectError {
    WsConnectError::Io(io::Error::new(
        io::ErrorKind::PermissionDenied,
        "secure WebSocket setup requires explicit and current native I/O and timer authority",
    ))
}

#[cfg(feature = "tls")]
fn map_tls_connect_error(error: TlsError) -> WsConnectError {
    let kind = match &error {
        TlsError::Io(error) => error.kind(),
        TlsError::Timeout(_) => io::ErrorKind::TimedOut,
        TlsError::InvalidDnsName(_) => io::ErrorKind::InvalidInput,
        _ => io::ErrorKind::InvalidData,
    };
    WsConnectError::Io(io::Error::new(kind, error))
}

/// A single retained deadline and cancellation registration across setup phases.
#[cfg(feature = "tls")]
struct WsTlsSetup<'a> {
    cx: &'a Cx,
    ambient: &'a Cx,
    clock: TimerDriverHandle,
    deadline: Option<Time>,
    timer: Option<Sleep>,
    caller_cancel: WsCancelWakerGuard<'a>,
    ambient_cancel: WsCancelWakerGuard<'a>,
}

#[cfg(feature = "tls")]
impl<'a> WsTlsSetup<'a> {
    fn new(cx: &'a Cx, ambient: &'a Cx, timeout: Option<Duration>) -> Result<Self, WsConnectError> {
        for context in [cx, ambient] {
            if !context.runtime_mask.has(crate::cx::cap::CapMask::IO)
                || context.io_driver_handle().is_none()
                || context.timer_driver().is_none()
            {
                return Err(missing_tls_setup_authority());
            }
        }
        let clock = cx.timer_driver().ok_or_else(missing_tls_setup_authority)?;
        if !ambient.timer_driver().is_some_and(|ambient_clock| clock.ptr_eq(&ambient_clock)) {
            return Err(missing_tls_setup_authority());
        }
        let mut deadline = timeout.map(|timeout| clock.now().saturating_add_nanos(
            u64::try_from(timeout.as_nanos()).unwrap_or(u64::MAX),
        ));
        for context in [cx, ambient] {
            if let Some(bound) = context.budget().deadline {
                deadline = Some(deadline.map_or(bound, |until| until.min(bound)));
            }
        }
        let setup = Self {
            cx,
            ambient,
            timer: deadline.map(|at| Sleep::with_timer_driver(at, clock.clone())),
            clock,
            deadline,
            caller_cancel: WsCancelWakerGuard::new(cx),
            ambient_cancel: WsCancelWakerGuard::new(ambient),
        };
        setup.check()?;
        Ok(setup)
    }

    fn check(&self) -> Result<(), WsConnectError> {
        if self.cx.checkpoint().is_err() || self.ambient.checkpoint().is_err() {
            return Err(WsConnectError::Cancelled);
        }
        if self.deadline.is_some_and(|until| self.clock.now() >= until) {
            return Err(WsConnectError::Io(io::Error::new(
                io::ErrorKind::TimedOut,
                "secure WebSocket connection setup deadline exceeded",
            )));
        }
        Ok(())
    }

    async fn run<T>(
        &mut self,
        future: impl std::future::Future<Output = Result<T, WsConnectError>>,
    ) -> Result<T, WsConnectError> {
        let mut future = std::pin::pin!(future);
        std::future::poll_fn(|task| {
            // TCP/DNS/TLS adapters consult the current context. Poll under the
            // supplied context without restoring any authority attenuated by
            // the task that created this setup or the current polling task.
            let current = Cx::current().ok_or_else(missing_tls_setup_authority)?;
            let mut io_cx = self.cx.clone();
            io_cx.runtime_mask = io_cx.runtime_mask
                .intersect(self.ambient.runtime_mask)
                .intersect(current.runtime_mask);
            if !io_cx.runtime_mask.has(crate::cx::cap::CapMask::IO)
                || io_cx.timer_driver().is_none()
                || !current.timer_driver().is_some_and(|clock| self.clock.ptr_eq(&clock))
            {
                return Poll::Ready(Err(missing_tls_setup_authority()));
            }
            let _current = Cx::set_current(Some(io_cx));
            self.caller_cancel.refresh(task.waker());
            self.ambient_cancel.refresh(task.waker());
            self.check()?;
            let timer_ready = self.timer.as_mut()
                .is_some_and(|timer| Pin::new(timer).poll_deadline(task).is_ready());
            if timer_ready {
                self.check()?;
                // A timer backend may wake early; retain the absolute bound.
                if let (Some(timer), Some(deadline)) = (&mut self.timer, self.deadline) {
                    timer.reset(deadline);
                    task.waker().wake_by_ref();
                }
            }
            match future.as_mut().poll(task) {
                Poll::Ready(result) => Poll::Ready(self.check().and(result)),
                Poll::Pending => Poll::Pending,
            }
        }).await
    }
}

/// Shared HTTP/1 upgrade over an already owned plaintext or TLS transport.
async fn perform_client_handshake<IO: AsyncRead + AsyncWrite + Unpin>(
    cx: &Cx,
    mut io: IO,
    url: &WsUrl,
    config: &WebSocketConfig,
    compression: bool,
    upgrade_timeout: Option<Duration>,
) -> Result<WebSocket<IO>, WsConnectError> {
    let scheme = if url.tls { "wss" } else { "ws" };
    let mut handshake = ClientHandshake::new(
        &format!("{scheme}://{}{}", url.host_header(), url.path),
        cx.entropy(),
    )?;
    for protocol in &config.protocols {
        handshake = handshake.protocol(protocol);
    }
    if compression { handshake = handshake.extension(super::compression::OFFER); }
    if cx.checkpoint().is_err() {
        return Err(WsConnectError::Cancelled);
    }
    let request = handshake.request_bytes();
    let (response_bytes, trailing) =
        bounded_upgrade_exchange(cx, &mut io, &request, upgrade_timeout).await?;
    let response = HttpResponse::parse(&response_bytes)?;
    handshake.validate_response(&response)?;
    let extensions: Vec<String> = response.header("sec-websocket-extensions")
        .map(|value| value.split(',').map(|field| field.trim().to_owned()).collect())
        .unwrap_or_default();
    let mut ws = WebSocket::from_upgraded_with_extensions(io, config.clone(), &extensions, cx.entropy_handle())?;
    ws.protocol = response.header("sec-websocket-protocol").map(String::from);
    ws.read_buf.extend_from_slice(&trailing);
    Ok(ws)
}

fn map_tcp_connect_error(cx: &Cx, err: io::Error) -> WsConnectError {
    if err.kind() == io::ErrorKind::Interrupted && cx.checkpoint().is_err() {
        WsConnectError::Cancelled
    } else {
        WsConnectError::Io(err)
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

/// Run the client upgrade exchange (write the request, read the response
/// head) under `limit` and the caller's cancellation.
///
/// `connect_timeout` used to cover only the TCP connect, and nothing re-polled
/// the response read, so a server that accepted TCP and never answered parked
/// `connect` forever (br-asupersync-bi2462.120).
async fn bounded_upgrade_exchange<IO: AsyncRead + AsyncWrite + Unpin>(
    cx: &Cx,
    io: &mut IO,
    request: &[u8],
    limit: Option<Duration>,
) -> Result<(Vec<u8>, Vec<u8>), WsConnectError> {
    use std::future::poll_fn;

    let mut exchange = std::pin::pin!(async {
        write_all(&mut *io, request).await?;
        read_http_response(&mut *io).await
    });
    let mut deadline = limit.map(|limit| crate::time::sleep(cx.now(), limit));
    let mut cancel_wake = WsCancelWakerGuard::new(cx);
    poll_fn(|poll_cx| {
        if cx.checkpoint().is_err() {
            return Poll::Ready(Err(WsConnectError::Cancelled));
        }
        cancel_wake.refresh(poll_cx.waker());
        if let Poll::Ready(result) = exchange.as_mut().poll(poll_cx) {
            return Poll::Ready(result.map_err(WsConnectError::Io));
        }
        if let Some(sleep) = deadline.as_mut()
            && Pin::new(sleep).poll_deadline(poll_cx).is_ready()
        {
            return Poll::Ready(Err(WsConnectError::Io(io::Error::new(
                io::ErrorKind::TimedOut,
                "websocket upgrade response not received within connect_timeout",
            ))));
        }
        Poll::Pending
    })
    .await
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
            (pos @ Some(_), None) | (None, pos @ Some(_)) => pos,
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
#[path = "client_inline_tests.rs"]
mod tests;
