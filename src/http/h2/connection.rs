//! HTTP/2 connection management.
//!
//! Manages HTTP/2 connection state, settings negotiation, and frame processing.

use std::collections::VecDeque;

use crate::types::Time;

use crate::bytes::{Bytes, BytesMut};
use crate::codec::{Decoder, Encoder};

use super::error::{ErrorCode, H2Error};
use super::frame::{
    ContinuationFrame, DataFrame, FRAME_HEADER_SIZE, Frame, FrameHeader, FrameType, GoAwayFrame,
    HeadersFrame, PingFrame, PushPromiseFrame, RstStreamFrame, Setting, SettingsFrame,
    WindowUpdateFrame, parse_frame,
};
use super::hpack::{self, Header};
use super::settings::{DEFAULT_INITIAL_WINDOW_SIZE, Settings};
use super::stream::{Stream, StreamState, StreamStore};

/// Connection preface that clients must send.
pub const CLIENT_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Default connection-level window size.
pub const DEFAULT_CONNECTION_WINDOW_SIZE: i32 = 65535;

/// Default RST_STREAM rate limit: max frames within the window before GOAWAY.
///
/// Protects against CVE-2023-44487 (Rapid Reset) class attacks where a peer
/// opens and immediately resets streams in a tight loop, exhausting server
/// resources while each individual stream appears short-lived.
const DEFAULT_RST_STREAM_RATE_LIMIT: u32 = 100;

/// Default window duration for RST_STREAM rate limiting (in milliseconds).
const DEFAULT_RST_STREAM_RATE_WINDOW_MS: u128 = 30_000;

/// Last-stream-id advertised by the stage-1 graceful-shutdown GOAWAY.
///
/// RFC 9113 §6.8: a graceful shutdown starts with a GOAWAY carrying the
/// maximum stream identifier (2^31 - 1) and NO_ERROR, which warns the peer
/// that shutdown is imminent without refusing any in-flight stream.
const GRACEFUL_SHUTDOWN_LAST_STREAM_ID: u32 = 0x7fff_ffff;

/// Configurable peer reset rate limit for Rapid Reset and MadeYouReset protection.
///
/// Peer RST_STREAM frames and peer-induced stream errors share this budget.
/// Normal application cancellations through [`Connection::reset_stream`] do
/// not consume it.
///
/// **Security warning**: Increasing these limits or disabling rate limiting
/// exposes the server to Rapid Reset attacks. Only relax these values if your
/// deployment has external DoS protection (e.g., a reverse proxy or load
/// balancer that performs its own RST_STREAM rate limiting).
///
/// # Defaults
///
/// | Parameter | Default | Meaning |
/// |-----------|---------|---------|
/// | `max_rst_streams` | 100 | Max peer resets and stream errors per window |
/// | `rst_window_ms` | 30,000 | Window duration in milliseconds |
#[derive(Debug, Clone, Copy)]
pub struct RstStreamRateLimit {
    /// Maximum peer RST_STREAM frames and reset-inducing stream errors allowed
    /// within the window, combined.
    pub max_rst_streams: u32,
    /// Window duration in milliseconds.
    pub rst_window_ms: u128,
}

impl Default for RstStreamRateLimit {
    fn default() -> Self {
        Self {
            max_rst_streams: DEFAULT_RST_STREAM_RATE_LIMIT,
            rst_window_ms: DEFAULT_RST_STREAM_RATE_WINDOW_MS,
        }
    }
}

fn wall_clock_now() -> Time {
    crate::time::wall_now()
}

/// Connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Waiting for preface (client) or initial settings.
    Handshaking,
    /// Connection is open and operational.
    Open,
    /// GOAWAY sent or received, draining.
    Closing,
    /// Connection is closed.
    Closed,
}

/// HTTP/2 frame codec for encoding/decoding frames from a byte stream.
#[derive(Debug)]
pub struct FrameCodec {
    /// Maximum frame size for decoding.
    max_frame_size: u32,
    /// Partial header being decoded.
    partial_header: Option<FrameHeader>,
    /// Unknown extensions cannot interrupt a field block, even though the
    /// public codec otherwise skips them.
    awaiting_continuation: bool,
}

impl FrameCodec {
    /// Create a new frame codec.
    #[must_use]
    pub fn new() -> Self {
        Self {
            max_frame_size: super::frame::DEFAULT_MAX_FRAME_SIZE,
            partial_header: None,
            awaiting_continuation: false,
        }
    }

    /// Set the maximum frame size.
    pub fn set_max_frame_size(&mut self, size: u32) {
        self.max_frame_size = size;
    }
}

impl Default for FrameCodec {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder for FrameCodec {
    type Item = Frame;
    type Error = H2Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match self.decode_item(src)? {
            Some(DecodedFrame::Frame(frame)) => Ok(Some(frame)),
            Some(DecodedFrame::PriorityError(error)) => Err(error),
            None => Ok(None),
        }
    }
}

/// Listener-only decoding outcome. A consumed PRIORITY error does not poison
/// the framed transport; connection sequencing still decides its final scope.
#[derive(Debug)]
pub(super) enum DecodedFrame {
    Frame(Frame),
    PriorityError(H2Error),
}

// The listener that uses this codec is native-only (`h2::listener` is
// `cfg(not(target_arch = "wasm32"))`).
#[cfg_attr(target_arch = "wasm32", allow(dead_code))]
#[derive(Debug)]
pub(super) struct ListenerFrameCodec(FrameCodec);

#[cfg_attr(target_arch = "wasm32", allow(dead_code))]
impl ListenerFrameCodec {
    pub(super) fn new() -> Self {
        Self(FrameCodec::new())
    }

    pub(super) fn set_max_frame_size(&mut self, size: u32) {
        self.0.set_max_frame_size(size);
    }
}

impl Decoder for ListenerFrameCodec {
    type Item = DecodedFrame;
    type Error = H2Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        self.0.decode_item(src)
    }
}

impl<T: AsRef<Frame>> Encoder<T> for ListenerFrameCodec {
    type Error = H2Error;

    fn encode(&mut self, item: T, dst: &mut BytesMut) -> Result<(), Self::Error> {
        self.0.encode(item, dst)
    }
}

impl FrameCodec {
    fn decode_item(&mut self, src: &mut BytesMut) -> Result<Option<DecodedFrame>, H2Error> {
        loop {
            // First, try to parse the header if we don't have one.
            let header = if let Some(header) = self.partial_header.take() {
                header
            } else {
                if src.len() < FRAME_HEADER_SIZE {
                    return Ok(None);
                }
                FrameHeader::parse(src)?
            };

            // Validate frame size.
            if header.length > self.max_frame_size {
                return Err(H2Error::frame_size(format!(
                    "frame too large: {} > {}",
                    header.length, self.max_frame_size
                )));
            }

            // Check if we have the full payload.
            let payload_len = header.length as usize;
            if src.len() < payload_len {
                self.partial_header = Some(header);
                return Ok(None);
            }

            // Extract payload first. For unknown extension frame types, HTTP/2 requires
            // endpoints to ignore them while preserving connection state.
            let payload = src.split_to(payload_len).freeze();
            if FrameType::from_u8(header.frame_type).is_none() {
                if self.awaiting_continuation {
                    return Err(H2Error::protocol(
                        "extension frame interrupted header block",
                    ));
                }
                continue;
            }

            let frame = match parse_frame(&header, payload) {
                Ok(frame) => frame,
                Err(error)
                    if header.frame_type == FrameType::Priority as u8
                        && header.stream_id != 0
                        && error.stream_id == Some(header.stream_id) =>
                {
                    return Ok(Some(DecodedFrame::PriorityError(error)));
                }
                Err(error) => return Err(error),
            };
            match &frame {
                Frame::Headers(frame) => self.awaiting_continuation = !frame.end_headers,
                Frame::PushPromise(frame) => self.awaiting_continuation = !frame.end_headers,
                Frame::Continuation(frame) => self.awaiting_continuation = !frame.end_headers,
                _ => {}
            }
            return Ok(Some(DecodedFrame::Frame(frame)));
        }
    }
}

impl<T: AsRef<Frame>> Encoder<T> for FrameCodec {
    type Error = H2Error;

    fn encode(&mut self, item: T, dst: &mut BytesMut) -> Result<(), Self::Error> {
        // br-asupersync-pt23uf: Frame::encode now returns Result; propagate
        // FRAME_SIZE_ERROR to the connection codec layer instead of the
        // previous panic on >16M payloads.
        item.as_ref().encode(dst)?;
        Ok(())
    }
}

impl AsRef<Self> for Frame {
    fn as_ref(&self) -> &Self {
        self
    }
}

/// Pending operation to send.
#[derive(Debug)]
#[allow(missing_docs)]
pub enum PendingOp {
    /// Settings frame to send.
    Settings(SettingsFrame),
    /// Settings ACK to send.
    SettingsAck,
    /// Ping ACK to send.
    PingAck([u8; 8]),
    /// Window update to send.
    WindowUpdate { stream_id: u32, increment: u32 },
    /// Headers to send.
    Headers {
        stream_id: u32,
        headers: Vec<Header>,
        end_stream: bool,
    },
    /// Push promise to send.
    PushPromise {
        stream_id: u32,
        promised_stream_id: u32,
        headers: Vec<Header>,
    },
    /// Continuation of header block.
    Continuation {
        stream_id: u32,
        header_block: Bytes,
        end_headers: bool,
    },
    /// Data to send.
    Data {
        stream_id: u32,
        data: Bytes,
        end_stream: bool,
    },
    /// RST_STREAM to send.
    RstStream {
        stream_id: u32,
        error_code: ErrorCode,
    },
    /// GOAWAY to send.
    GoAway {
        last_stream_id: u32,
        error_code: ErrorCode,
        debug_data: Bytes,
    },
}

impl PendingOp {
    fn references_stream(&self, stream_id: u32) -> bool {
        match self {
            Self::Settings(_) | Self::SettingsAck | Self::PingAck(_) | Self::GoAway { .. } => false,
            Self::WindowUpdate {
                stream_id: op_stream,
                ..
            }
            | Self::Headers {
                stream_id: op_stream,
                ..
            }
            | Self::Continuation {
                stream_id: op_stream,
                ..
            }
            | Self::Data {
                stream_id: op_stream,
                ..
            }
            | Self::RstStream {
                stream_id: op_stream,
                ..
            } => *op_stream == stream_id,
            Self::PushPromise {
                stream_id: associated_stream,
                promised_stream_id,
                ..
            } => *associated_stream == stream_id || *promised_stream_id == stream_id,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct PushPromiseAccumulator {
    associated_stream_id: u32,
    promised_stream_id: u32,
    refusal: Option<PushRefusal>,
}

/// Why a PUSH_PROMISE is refused. Its field block is still decoded first
/// (RFC 9113 §4.3); then the promised stream is reset with `reset`.
#[derive(Debug, Clone, Copy)]
struct PushRefusal {
    reset: ErrorCode,
    /// The stream error reported to the caller (stream, code, reason), if
    /// any. `None` refuses silently: the promise raced our GOAWAY or our
    /// reset of the associated stream, which is no error by the peer.
    error: Option<(u32, ErrorCode, &'static str)>,
}

/// HTTP/2 connection.
#[derive(Debug)]
#[allow(clippy::struct_excessive_bools)]
pub struct Connection {
    /// Connection state.
    state: ConnectionState,
    /// Whether this is a client or server connection.
    is_client: bool,
    /// Local settings.
    local_settings: Settings,
    /// Remote settings (peer's settings).
    remote_settings: Settings,
    /// Whether we've received the peer's settings.
    received_settings: bool,
    /// Stream store.
    streams: StreamStore,
    /// HPACK encoder.
    hpack_encoder: hpack::Encoder,
    /// HPACK decoder.
    hpack_decoder: hpack::Decoder,
    /// Connection-level send window.
    send_window: i32,
    /// Connection-level receive window.
    recv_window: i32,
    /// Configured connection-level receive-window target.
    ///
    /// Unlike the per-stream initial window, HTTP/2 has no SETTINGS field for
    /// this value. A server enlarges it by sending a connection-level
    /// WINDOW_UPDATE immediately after its initial SETTINGS. Keeping the
    /// target here makes automatic replenishment return to the advertised
    /// capacity instead of silently falling back to 65,535 bytes.
    initial_recv_window: i32,
    /// Last stream ID processed.
    last_stream_id: u32,
    /// Smallest last-stream-id advertised by received GOAWAY frames.
    received_goaway_last_stream_id: Option<u32>,
    /// Last-stream-id advertised in the GOAWAY we sent, if any.
    ///
    /// This value is frozen at GOAWAY send time. Using the mutable
    /// `last_stream_id` after that would let later bookkeeping widen the
    /// refusal boundary for new peer streams, which violates RFC 9113 §6.8.
    sent_goaway_last_stream_id: Option<u32>,
    /// GOAWAY received.
    goaway_received: bool,
    /// GOAWAY sent.
    goaway_sent: bool,
    /// A stage-1 graceful-shutdown GOAWAY (last_stream_id = 2^31 - 1) was
    /// sent and the definitive stage-2 GOAWAY has not been sent yet.
    graceful_shutdown_pending: bool,
    /// Pending operations to process.
    pending_ops: VecDeque<PendingOp>,
    /// Clock source used by timeout and rate-limit bookkeeping. Carries the
    /// runtime [`Time`] so a virtual-time driver (lab runtime) drives h2
    /// deadlines deterministically instead of always reading the wall clock.
    time_getter: fn() -> Time,
    /// Stream ID being continued (for CONTINUATION frames).
    continuation_stream_id: Option<u32>,
    /// When the current continuation sequence started.
    ///
    /// Set when a HEADERS or PUSH_PROMISE frame is received without END_HEADERS.
    /// Used to enforce timeout on incomplete CONTINUATION sequences.
    continuation_started_at: Option<Time>,
    /// Pending PUSH_PROMISE header block, if any.
    pending_push_promise: Option<PushPromiseAccumulator>,
    /// RST_STREAM rate limit configuration.
    rst_rate_limit: RstStreamRateLimit,
    /// Peer RST_STREAM frames and peer-induced stream errors in this window.
    rst_stream_count: u32,
    /// Start of the current RST_STREAM rate-limit window.
    rst_stream_window_start: Time,
}

impl Connection {
    /// Create a new client connection.
    #[must_use]
    pub fn client(settings: Settings) -> Self {
        Self::client_with_time_getter(settings, wall_clock_now)
    }

    /// Create a new client connection with a custom time source.
    #[must_use]
    pub fn client_with_time_getter(settings: Settings, time_getter: fn() -> Time) -> Self {
        let max_header_list_size = settings.max_header_list_size;
        let initial_send_window = DEFAULT_INITIAL_WINDOW_SIZE;
        let initial_recv_window = settings.initial_window_size;
        let mut decoder = hpack::Decoder::new();
        decoder.set_max_header_list_size(max_header_list_size as usize);
        // The decoder rejects any peer dynamic-table-size update above
        // `allowed_table_size`, which MUST equal the SETTINGS_HEADER_TABLE_SIZE
        // we advertise to the peer (RFC 7541 §6.3). Without this it stays at the
        // 4096 default, so advertising a larger table would make us kill a
        // spec-conforming peer with a COMPRESSION_ERROR.
        decoder.set_allowed_table_size(settings.header_table_size as usize);
        let mut streams = StreamStore::new_with_local_recv_window(
            true,
            initial_send_window,
            initial_recv_window,
            max_header_list_size,
        );
        streams.set_local_max_concurrent_streams(settings.max_concurrent_streams);
        Self {
            state: ConnectionState::Handshaking,
            is_client: true,
            local_settings: settings,
            remote_settings: Settings::default(),
            received_settings: false,
            streams,
            hpack_encoder: hpack::Encoder::new(),
            hpack_decoder: decoder,
            send_window: DEFAULT_CONNECTION_WINDOW_SIZE,
            recv_window: DEFAULT_CONNECTION_WINDOW_SIZE,
            initial_recv_window: DEFAULT_CONNECTION_WINDOW_SIZE,
            last_stream_id: 0,
            received_goaway_last_stream_id: None,
            sent_goaway_last_stream_id: None,
            goaway_received: false,
            goaway_sent: false,
            graceful_shutdown_pending: false,
            pending_ops: VecDeque::new(),
            time_getter,
            continuation_stream_id: None,
            continuation_started_at: None,
            pending_push_promise: None,
            rst_rate_limit: RstStreamRateLimit::default(),
            rst_stream_count: 0,
            rst_stream_window_start: time_getter(),
        }
    }

    /// Create a new server connection.
    #[must_use]
    pub fn server(settings: Settings) -> Self {
        Self::server_with_time_getter(settings, wall_clock_now)
    }

    /// Create a new server connection with a custom time source.
    #[must_use]
    pub fn server_with_time_getter(settings: Settings, time_getter: fn() -> Time) -> Self {
        let max_header_list_size = settings.max_header_list_size;
        let initial_send_window = DEFAULT_INITIAL_WINDOW_SIZE;
        let initial_recv_window = settings.initial_window_size;
        let mut decoder = hpack::Decoder::new();
        decoder.set_max_header_list_size(max_header_list_size as usize);
        // The decoder rejects any peer dynamic-table-size update above
        // `allowed_table_size`, which MUST equal the SETTINGS_HEADER_TABLE_SIZE
        // we advertise to the peer (RFC 7541 §6.3). Without this it stays at the
        // 4096 default, so advertising a larger table would make us kill a
        // spec-conforming peer with a COMPRESSION_ERROR.
        decoder.set_allowed_table_size(settings.header_table_size as usize);
        let mut streams = StreamStore::new_with_local_recv_window(
            false,
            initial_send_window,
            initial_recv_window,
            max_header_list_size,
        );
        streams.set_local_max_concurrent_streams(settings.max_concurrent_streams);
        Self {
            state: ConnectionState::Handshaking,
            is_client: false,
            local_settings: settings,
            remote_settings: Settings::default(),
            received_settings: false,
            streams,
            hpack_encoder: hpack::Encoder::new(),
            hpack_decoder: decoder,
            send_window: DEFAULT_CONNECTION_WINDOW_SIZE,
            recv_window: DEFAULT_CONNECTION_WINDOW_SIZE,
            initial_recv_window: DEFAULT_CONNECTION_WINDOW_SIZE,
            last_stream_id: 0,
            received_goaway_last_stream_id: None,
            sent_goaway_last_stream_id: None,
            goaway_received: false,
            goaway_sent: false,
            graceful_shutdown_pending: false,
            pending_ops: VecDeque::new(),
            time_getter,
            continuation_stream_id: None,
            continuation_started_at: None,
            pending_push_promise: None,
            rst_rate_limit: RstStreamRateLimit::default(),
            rst_stream_count: 0,
            rst_stream_window_start: time_getter(),
        }
    }

    /// Configure the RST_STREAM rate limit for CVE-2023-44487 protection.
    ///
    /// **Security warning**: Relaxing these limits exposes the server to Rapid
    /// Reset attacks. Only increase if external DoS protection is in place.
    #[must_use]
    pub fn rst_stream_rate_limit(mut self, limit: RstStreamRateLimit) -> Self {
        self.rst_rate_limit = limit;
        self
    }

    /// Get the connection state.
    #[must_use]
    pub fn state(&self) -> ConnectionState {
        self.state
    }

    /// Check if this is a client connection.
    #[must_use]
    pub fn is_client(&self) -> bool {
        self.is_client
    }

    /// Get local settings.
    #[must_use]
    pub fn local_settings(&self) -> &Settings {
        &self.local_settings
    }

    /// Get remote settings.
    #[must_use]
    pub fn remote_settings(&self) -> &Settings {
        &self.remote_settings
    }

    /// Get the connection-level send window.
    #[must_use]
    pub fn send_window(&self) -> i32 {
        self.send_window
    }

    /// Return DATA bytes that can be emitted immediately for `stream_id`.
    ///
    /// The value is the minimum of the connection send window, the stream send
    /// window, and the peer's maximum frame size. It is zero for a missing,
    /// reset, or non-sendable stream. Response-body drivers use this before
    /// polling a producer, so no new DATA is pulled into transport ownership
    /// while flow control is exhausted.
    #[must_use]
    pub fn available_send_capacity(&self, stream_id: u32) -> usize {
        let Some(stream) = self.streams.get(stream_id) else {
            return 0;
        };
        if stream.error_code().is_some() || !stream.state().can_send() {
            return 0;
        }
        let connection = self.send_window.max(0).cast_unsigned();
        let stream = stream.send_window().max(0).cast_unsigned();
        connection
            .min(stream)
            .min(self.remote_settings.max_frame_size) as usize
    }

    /// Get the connection-level receive window.
    #[must_use]
    pub fn recv_window(&self) -> i32 {
        self.recv_window
    }

    /// Enlarge the connection-level receive window used for newly accepted
    /// traffic and automatic WINDOW_UPDATE replenishment.
    ///
    /// HTTP/2 fixes the initial connection window at 65,535 bytes and does
    /// not define a SETTINGS parameter for changing it. Values above that
    /// baseline are therefore advertised with a stream-0 WINDOW_UPDATE. A
    /// smaller value cannot be advertised to the peer and is rejected rather
    /// than creating asymmetric flow-control state.
    ///
    /// This must be called while the connection is still handshaking, before
    /// any peer DATA can have consumed receive credit.
    ///
    /// # Errors
    ///
    /// Returns a flow-control error when `size` is below the protocol baseline,
    /// exceeds the 31-bit window limit, or when traffic has already advanced
    /// the connection beyond its handshake state.
    pub fn set_initial_connection_recv_window(&mut self, size: u32) -> Result<(), H2Error> {
        if !matches!(self.state, ConnectionState::Handshaking)
            || self.recv_window != DEFAULT_CONNECTION_WINDOW_SIZE
        {
            return Err(H2Error::flow_control(
                "initial connection receive window must be configured before peer traffic",
            ));
        }
        if size < DEFAULT_INITIAL_WINDOW_SIZE {
            return Err(H2Error::flow_control(
                "initial connection receive window cannot be below 65535",
            ));
        }
        let target = i32::try_from(size).map_err(|_| {
            H2Error::flow_control("initial connection receive window exceeds 31-bit maximum")
        })?;
        self.initial_recv_window = target;
        let increment = size - DEFAULT_INITIAL_WINDOW_SIZE;
        if increment != 0 {
            self.send_connection_window_update(increment)?;
        }
        Ok(())
    }

    /// Get a stream by ID.
    #[must_use]
    pub fn stream(&self, id: u32) -> Option<&Stream> {
        self.streams.get(id)
    }

    /// Get a mutable stream by ID.
    #[must_use]
    pub fn stream_mut(&mut self, id: u32) -> Option<&mut Stream> {
        self.streams.get_mut(id)
    }

    /// Replenish one stream's receive window only as its consumer releases DATA.
    ///
    /// Call after the initial [`ReceivedFrame::Headers`] event and before any
    /// DATA for this stream is processed. Repeating the call is harmless.
    /// Other streams retain automatic receive-window updates. Connection-level
    /// credit is still replenished on receipt so a slow stream cannot prevent
    /// its siblings from making progress.
    ///
    /// The caller must bound retained DATA across its admitted streams, continue
    /// processing connection frames, and call
    /// [`Self::release_stream_receive_capacity`] as application bytes are
    /// consumed. Padding is discarded and credited internally; do not include it
    /// in the released byte count. The initial receive window is unchanged, so
    /// the caller must be able to retain that much DATA before issuing updates.
    ///
    /// # Errors
    ///
    /// Returns a stream error when the stream is absent or reset, its initial
    /// header block is incomplete, or DATA arrived before deferral was enabled.
    #[cfg(feature = "http2-streaming")]
    pub fn defer_stream_receive_window(&mut self, stream_id: u32) -> Result<(), H2Error> {
        self.streams
            .get_mut(stream_id)
            .ok_or_else(|| {
                H2Error::stream(
                    stream_id,
                    ErrorCode::StreamClosed,
                    "cannot defer receive credit on an absent stream",
                )
            })?
            .defer_recv_window_updates()
    }

    /// Release application DATA consumed from a stream with deferred credit.
    ///
    /// `consumed_bytes` counts only bytes surfaced in [`ReceivedFrame::Data`],
    /// once each. Queuing those bytes for later application consumption does
    /// not release capacity. A zero count is a no-op. An accepted release queues
    /// a stream WINDOW_UPDATE while input remains open; after END_STREAM it
    /// retires accounting without advertising unusable credit. A release that
    /// races with reset or pruning of a closed stream is harmless.
    ///
    /// # Errors
    ///
    /// Returns a stream error if receive credit was not deferred, the stream is
    /// idle, more bytes are released than received and not yet consumed, or the
    /// receive window would overflow. A rejected release leaves accounting and
    /// queued WINDOW_UPDATE frames unchanged.
    #[cfg(feature = "http2-streaming")]
    pub fn release_stream_receive_capacity(
        &mut self,
        stream_id: u32,
        consumed_bytes: u32,
    ) -> Result<(), H2Error> {
        if consumed_bytes == 0 {
            return Ok(());
        }
        if stream_id == 0 || stream_id > 0x7fff_ffff || self.streams.is_idle_stream_id(stream_id) {
            return Err(H2Error::stream(
                stream_id,
                ErrorCode::ProtocolError,
                "cannot release receive capacity for an invalid or idle stream",
            ));
        }
        let Some(stream) = self.streams.get_mut(stream_id) else {
            return Ok(());
        };
        let increment = stream.release_deferred_recv_capacity(consumed_bytes)?;
        if increment != 0 {
            self.pending_ops.push_back(PendingOp::WindowUpdate {
                stream_id,
                increment,
            });
        }
        Ok(())
    }

    /// Check if GOAWAY has been received.
    #[must_use]
    pub fn goaway_received(&self) -> bool {
        self.goaway_received
    }

    /// Check if a GOAWAY has been sent (immediate or graceful, either stage).
    #[must_use]
    pub fn goaway_sent(&self) -> bool {
        self.goaway_sent
    }

    /// Check if a stage-1 graceful-shutdown warning has been sent but the
    /// definitive stage-2 GOAWAY has not yet been sent.
    ///
    /// While pending, peer-initiated streams are still accepted; drain
    /// supervisors must call [`Connection::finalize_graceful_shutdown`]
    /// before treating the connection as refusing new work.
    #[must_use]
    pub fn graceful_shutdown_pending(&self) -> bool {
        self.graceful_shutdown_pending
    }

    /// Last-stream-id advertised by the GOAWAY we sent, if any.
    ///
    /// During a pending graceful shutdown this is 2^31 - 1 (the stage-1
    /// warning value); after [`Connection::finalize_graceful_shutdown`] or
    /// [`Connection::goaway`] it is the definitive refusal boundary.
    #[must_use]
    pub fn sent_goaway_last_stream_id(&self) -> Option<u32> {
        self.sent_goaway_last_stream_id
    }

    /// Number of streams that currently count as active (RFC 9113 §5.1.2:
    /// open, half-closed, or reserved).
    ///
    /// This is the in-flight figure a graceful-drain supervisor (for
    /// example `server::shutdown::GracefulDrainSupervisor`) observes while
    /// draining an HTTP/2 connection.
    #[must_use]
    pub fn active_stream_count(&self) -> usize {
        self.streams.active_count()
    }

    /// Check whether graceful shutdown has fully drained this connection.
    ///
    /// True once a definitive GOAWAY has been sent (immediate
    /// [`Connection::goaway`] or stage-2
    /// [`Connection::finalize_graceful_shutdown`]) and no active streams
    /// remain. The transport can then be closed without stranding work.
    #[must_use]
    pub fn graceful_shutdown_complete(&self) -> bool {
        self.goaway_sent && !self.graceful_shutdown_pending && self.streams.active_count() == 0
    }

    /// Check if we're expecting CONTINUATION frames.
    #[must_use]
    pub fn is_awaiting_continuation(&self) -> bool {
        self.continuation_stream_id.is_some()
    }

    /// Get the stream ID we're expecting CONTINUATION for, if any.
    #[must_use]
    pub fn continuation_stream_id(&self) -> Option<u32> {
        self.continuation_stream_id
    }

    /// Check if the current CONTINUATION sequence has timed out.
    ///
    /// Returns `Ok(())` if no timeout has occurred, or an error if the
    /// CONTINUATION sequence has been pending for longer than the configured
    /// timeout.
    ///
    /// The caller should invoke this method periodically (e.g., each time
    /// the connection is polled) to detect and handle timeout conditions.
    ///
    /// When a timeout is detected, this method:
    /// 1. Clears the continuation state
    /// 2. Returns a protocol error
    ///
    /// The caller should then send GOAWAY and close the connection.
    pub fn check_continuation_timeout(&mut self) -> Result<(), H2Error> {
        if let Some(started_at) = self.continuation_started_at {
            let timeout_ms = self.local_settings.continuation_timeout_ms;
            let elapsed =
                std::time::Duration::from_nanos((self.time_getter)().duration_since(started_at));

            if elapsed.as_millis() >= u128::from(timeout_ms) {
                // Clear continuation state
                let stream_id = self.continuation_stream_id.take();
                self.continuation_started_at = None;
                self.pending_push_promise = None;

                return Err(H2Error::protocol(format!(
                    "CONTINUATION timeout: no END_HEADERS within {timeout_ms}ms for stream {stream_id:?}",
                )));
            }
        }
        Ok(())
    }

    /// Time remaining before the in-flight CONTINUATION sequence times out, or
    /// `None` when no header-block continuation is pending.
    ///
    /// Unlike [`Connection::check_continuation_timeout`] (which only runs when
    /// a frame arrives), this lets the connection driver arm a
    /// frame-arrival-independent deadline so a peer that opens a header block
    /// and then stalls is reclaimed instead of hanging forever
    /// (br-asupersync-mfqfst L4). Returns `Some(Duration::ZERO)` once the
    /// budget is already spent.
    #[must_use]
    pub fn continuation_timeout_remaining(&self) -> Option<std::time::Duration> {
        let started_at = self.continuation_started_at?;
        let budget = std::time::Duration::from_millis(self.local_settings.continuation_timeout_ms);
        let elapsed =
            std::time::Duration::from_nanos((self.time_getter)().duration_since(started_at));
        Some(budget.saturating_sub(elapsed))
    }

    /// Queue initial settings frame.
    pub fn queue_initial_settings(&mut self) {
        let settings = SettingsFrame::new(
            self.local_settings
                .to_settings_minimal_for_role(self.is_client),
        );
        self.pending_ops.push_back(PendingOp::Settings(settings));
    }

    /// Open a new stream and send headers.
    pub fn open_stream(&mut self, headers: Vec<Header>, end_stream: bool) -> Result<u32, H2Error> {
        if self.goaway_received || self.goaway_sent {
            return Err(H2Error::protocol("cannot open new streams after GOAWAY"));
        }

        let stream_id = self.streams.allocate_stream_id()?;
        let stream = self.streams.get_mut(stream_id).ok_or_else(|| {
            H2Error::connection(
                ErrorCode::InternalError,
                "allocated stream missing from store",
            )
        })?;
        stream.send_headers(end_stream)?;
        stream.queue_end_stream(end_stream);

        self.pending_ops.push_back(PendingOp::Headers {
            stream_id,
            headers,
            end_stream,
        });

        Ok(stream_id)
    }

    /// Send data on a stream.
    pub fn send_data(
        &mut self,
        stream_id: u32,
        data: Bytes,
        end_stream: bool,
    ) -> Result<(), H2Error> {
        let stream = self.streams.get_mut(stream_id).ok_or_else(|| {
            H2Error::stream(stream_id, ErrorCode::StreamClosed, "stream not found")
        })?;

        stream.send_data(end_stream)?;
        stream.queue_end_stream(end_stream);

        self.pending_ops.push_back(PendingOp::Data {
            stream_id,
            data,
            end_stream,
        });

        Ok(())
    }

    /// Send headers on a stream (for responses or trailers).
    pub fn send_headers(
        &mut self,
        stream_id: u32,
        headers: Vec<Header>,
        end_stream: bool,
    ) -> Result<(), H2Error> {
        let stream = self.streams.get_mut(stream_id).ok_or_else(|| {
            H2Error::stream(stream_id, ErrorCode::StreamClosed, "stream not found")
        })?;

        stream.send_headers(end_stream)?;
        stream.queue_end_stream(end_stream);

        self.pending_ops.push_back(PendingOp::Headers {
            stream_id,
            headers,
            end_stream,
        });

        Ok(())
    }

    /// Send a server push promise on an existing peer-initiated stream.
    pub fn send_push_promise(
        &mut self,
        stream_id: u32,
        headers: Vec<Header>,
    ) -> Result<u32, H2Error> {
        if self.is_client {
            return Err(H2Error::protocol("clients cannot send PUSH_PROMISE"));
        }
        if self.goaway_received || self.goaway_sent {
            return Err(H2Error::protocol("cannot send PUSH_PROMISE after GOAWAY"));
        }
        if !self.remote_settings.enable_push {
            return Err(H2Error::stream(
                stream_id,
                ErrorCode::RefusedStream,
                "peer disabled server push",
            ));
        }
        if stream_id == 0 || stream_id.is_multiple_of(2) {
            return Err(H2Error::protocol(
                "PUSH_PROMISE requires a client-initiated associated stream",
            ));
        }
        if let Err(why) = validate_h2_pseudo_headers(
            &headers, /* is_request = */ true, /* is_trailers = */ false,
        ) {
            return Err(H2Error::stream(stream_id, ErrorCode::ProtocolError, why));
        }

        let assoc_state = match self.streams.get(stream_id) {
            Some(stream) => stream.state(),
            None => {
                return Err(H2Error::stream(
                    stream_id,
                    ErrorCode::StreamClosed,
                    "PUSH_PROMISE on unknown associated stream",
                ));
            }
        };
        if !matches!(
            assoc_state,
            StreamState::Open | StreamState::HalfClosedRemote
        ) {
            let code = if assoc_state.is_closed() {
                ErrorCode::StreamClosed
            } else {
                ErrorCode::ProtocolError
            };
            return Err(H2Error::stream(
                stream_id,
                code,
                "PUSH_PROMISE on stream not in open or half-closed (remote) state",
            ));
        }

        let promised_stream_id = self.streams.reserve_local_stream()?;
        self.pending_ops.push_back(PendingOp::PushPromise {
            stream_id,
            promised_stream_id,
            headers,
        });

        Ok(promised_stream_id)
    }

    /// Reset a stream.
    ///
    /// A stream is reset at most once: after our RST_STREAM the peer treats
    /// any further frame on the stream as a STREAM_CLOSED error, so a second
    /// local reset keeps the first error code and queues nothing.
    pub fn reset_stream(&mut self, stream_id: u32, error_code: ErrorCode) {
        if let Some(stream) = self.streams.get_mut(stream_id) {
            if stream.reset_sent() {
                return;
            }
            // A field block still arriving keeps its fragments: they reach
            // the HPACK decoder when the block ends (RFC 9113 §4.3).
            let arriving_block = (self.continuation_stream_id == Some(stream_id))
                .then(|| stream.take_header_fragments());
            stream.reset(error_code);
            stream.mark_reset_sent();
            for fragment in arriving_block.into_iter().flatten() {
                // These fragments already passed the caps they are checked
                // against again here.
                let _ = stream.add_header_fragment(fragment);
            }
        }
        self.pending_ops.push_back(PendingOp::RstStream {
            stream_id,
            error_code,
        });
    }

    /// Send GOAWAY and start an immediate shutdown.
    ///
    /// The advertised last-stream-id is frozen at the highest stream
    /// processed so far; peer streams above it are refused from this point
    /// on. For the RFC 9113 §6.8 two-stage graceful variant that keeps
    /// accepting racing in-flight streams first, use
    /// [`Connection::begin_graceful_shutdown`] /
    /// [`Connection::finalize_graceful_shutdown`].
    pub fn goaway(&mut self, error_code: ErrorCode, debug_data: Bytes) {
        if !self.goaway_sent {
            self.goaway_sent = true;
            self.state = ConnectionState::Closing;
            let last_stream_id = self.last_stream_id;
            self.sent_goaway_last_stream_id = Some(last_stream_id);
            self.pending_ops.push_back(PendingOp::GoAway {
                last_stream_id,
                error_code,
                debug_data,
            });
        }
    }

    /// Begin an RFC 9113 §6.8 graceful shutdown (stage 1 of 2).
    ///
    /// Queues a GOAWAY with last-stream-id 2^31 - 1 and NO_ERROR: the peer
    /// learns shutdown is imminent and should stop creating streams, but no
    /// in-flight or racing stream is refused yet. The local side stops
    /// opening new streams immediately ([`Connection::open_stream`] fails
    /// once a GOAWAY is sent).
    ///
    /// After allowing in-flight stream creation to settle (at least one
    /// round trip; a drain supervisor tick works), call
    /// [`Connection::finalize_graceful_shutdown`] to advertise the
    /// definitive boundary. A connection that is already idle
    /// ([`Connection::active_stream_count`] == 0) can be finalized
    /// immediately — that is the drain-start fast path for idle keep-alive
    /// connections.
    ///
    /// No-op if a GOAWAY (graceful or immediate) was already sent.
    pub fn begin_graceful_shutdown(&mut self, debug_data: Bytes) {
        if self.goaway_sent {
            return;
        }
        self.goaway_sent = true;
        self.graceful_shutdown_pending = true;
        self.state = ConnectionState::Closing;
        self.sent_goaway_last_stream_id = Some(GRACEFUL_SHUTDOWN_LAST_STREAM_ID);
        self.pending_ops.push_back(PendingOp::GoAway {
            last_stream_id: GRACEFUL_SHUTDOWN_LAST_STREAM_ID,
            error_code: ErrorCode::NoError,
            debug_data,
        });
    }

    /// Finalize an RFC 9113 §6.8 graceful shutdown (stage 2 of 2).
    ///
    /// Queues a GOAWAY with NO_ERROR and the highest stream identifier
    /// actually processed, ratcheting the advertised boundary down from the
    /// stage-1 value (RFC 9113 §6.8 forbids raising it). Peer streams above
    /// the boundary are refused with `RST_STREAM(REFUSED_STREAM)` from this
    /// point on; once the remaining active streams complete,
    /// [`Connection::graceful_shutdown_complete`] reports true.
    ///
    /// Calling this without [`Connection::begin_graceful_shutdown`] behaves
    /// like an immediate `goaway(ErrorCode::NoError, ..)`. No-op if a
    /// definitive GOAWAY was already sent.
    pub fn finalize_graceful_shutdown(&mut self, debug_data: Bytes) {
        if self.goaway_sent && !self.graceful_shutdown_pending {
            // A definitive boundary is already on the wire; never widen or
            // re-advertise it.
            return;
        }
        let last_stream_id = self
            .sent_goaway_last_stream_id
            .map_or(self.last_stream_id, |prev| self.last_stream_id.min(prev));
        self.goaway_sent = true;
        self.graceful_shutdown_pending = false;
        self.state = ConnectionState::Closing;
        self.sent_goaway_last_stream_id = Some(last_stream_id);
        self.pending_ops.push_back(PendingOp::GoAway {
            last_stream_id,
            error_code: ErrorCode::NoError,
            debug_data,
        });
    }

    fn check_incoming_frame(
        &mut self,
        is_settings: bool,
        continuation_stream: Option<u32>,
    ) -> Result<(), H2Error> {
        // Check continuation timeout before processing
        self.check_continuation_timeout()?;

        // Prevent memory exhaustion from PING/SETTINGS floods (CVE-2019-9512 / CVE-2019-9515).
        if self.pending_ops.len() > 10_000 {
            return Err(H2Error::connection(
                ErrorCode::EnhanceYourCalm,
                "too many pending operations, possible flood attack",
            ));
        }

        // RFC 9113 §6.10: CONTINUATION frame sequencing. Either side of the
        // boundary is a connection-level PROTOCOL_ERROR.
        match (continuation_stream, self.continuation_stream_id) {
            // Mid-sequence: only CONTINUATION on the expected stream is
            // valid; anything else (including CONTINUATION on a different
            // stream) terminates the connection.
            (Some(actual), Some(expected)) if actual == expected => {}
            (_, Some(_)) => {
                return Err(H2Error::protocol("expected CONTINUATION frame"));
            }
            // br-asupersync-pxb77u: outside a sequence, CONTINUATION is
            // forbidden. Pre-fix paths returned a stream-level
            // PROTOCOL_ERROR via stream.recv_continuation when the stream
            // existed but headers were complete — non-conformant with
            // §6.10's connection-error mandate.
            (Some(_), None) => {
                return Err(H2Error::protocol(
                    "CONTINUATION without preceding HEADERS/PUSH_PROMISE (RFC 9113 §6.10)",
                ));
            }
            (_, None) => {}
        }

        // br-asupersync-lcvdj0: RFC 9113 §3.4 / §3.5 — the first frame
        // sent and received on an HTTP/2 connection MUST be a SETTINGS
        // frame. Any other frame received in the Handshaking state is
        // a connection-level PROTOCOL_ERROR. Pre-fix `process_frame`
        // dispatched on frame type without checking the connection
        // state; a peer could send DATA / RST_STREAM / PING /
        // WINDOW_UPDATE / HEADERS / PUSH_PROMISE on a fresh connection
        // and (for the frame types that do not also fail their own
        // stream-id-zero / flag validation) have it processed
        // normally. After this guard, only SETTINGS advances out of
        // Handshaking; everything else triggers a GOAWAY-bound
        // PROTOCOL_ERROR.
        if matches!(self.state, ConnectionState::Handshaking) && !is_settings {
            return Err(H2Error::protocol(
                "first frame on the connection must be SETTINGS (RFC 9113 §3.4)",
            ));
        }

        Ok(())
    }

    #[cfg_attr(target_arch = "wasm32", allow(dead_code))] // native-only listener caller
    pub(super) fn process_decoded_frame(
        &mut self,
        frame: DecodedFrame,
    ) -> Result<Option<ReceivedFrame>, H2Error> {
        match frame {
            DecodedFrame::Frame(frame) => self.process_frame(frame),
            DecodedFrame::PriorityError(error) => {
                self.check_incoming_frame(false, None)?;
                if error.stream_id.is_some() {
                    self.record_peer_reset()?;
                }
                Err(error)
            }
        }
    }

    /// Process an incoming frame.
    pub fn process_frame(&mut self, frame: Frame) -> Result<Option<ReceivedFrame>, H2Error> {
        self.check_incoming_frame(
            matches!(frame, Frame::Settings(_)),
            match &frame {
                Frame::Continuation(frame) => Some(frame.stream_id),
                _ => None,
            },
        )?;

        let result = match frame {
            Frame::Data(f) => self.process_data(f),
            Frame::Headers(f) => self.process_headers(f),
            Frame::Priority(f) => {
                if let Some(stream) = self.streams.get_mut(f.stream_id) {
                    stream.set_priority(f.priority);
                }
                Ok(None)
            }
            Frame::RstStream(f) => self.process_rst_stream(f).map(Some),
            Frame::Settings(f) => self.process_settings(&f),
            Frame::PushPromise(f) => self.process_push_promise(&f),
            Frame::Ping(f) => Ok(self.process_ping(f)),
            Frame::GoAway(f) => Ok(Some(self.process_goaway(f))),
            Frame::WindowUpdate(f) => self.process_window_update(f),
            Frame::Continuation(f) => self.process_continuation(f),
            Frame::Unknown { .. } => Ok(None), // RFC 7540 §4.1: ignore unknown types
        };

        // Prune closed streams when the map grows large relative to the
        // configured maximum. This prevents unbounded memory growth on
        // long-lived connections where many streams are opened and closed.
        // We cap the threshold to ensure that a default unlimited (u32::MAX)
        // max_concurrent_streams doesn't completely disable pruning.
        let max = self.local_settings.max_concurrent_streams as usize;
        let threshold = std::cmp::min(max, 16_384).saturating_mul(2);
        if self.streams.len() > threshold {
            self.prune_closed_streams_without_pending_frames();
        }

        // Malformed WINDOW_UPDATE, request headers, flow-control violations,
        // and other peer-induced stream errors release protocol stream slots
        // just as a peer RST does. Charging only explicit RST_STREAM lets the
        // peer trigger the same reset amplification through these errors.
        if let Err(error) = &result
            && error.stream_id.is_some()
        {
            self.record_peer_reset()?;
        }
        result
    }

    /// Update last_stream_id to track the highest processed stream.
    fn track_stream_id(&mut self, stream_id: u32) {
        if stream_id > self.last_stream_id {
            self.last_stream_id = stream_id;
        }
    }

    /// RFC 9113 §6.8: the last-stream identifier in our GOAWAY covers the
    /// streams our peer initiated. Streams we opened (odd for a client, even
    /// for a server) keep receiving their frames after our GOAWAY: a client
    /// that sends GOAWAY still takes the responses to its requests in flight.
    fn stream_exceeds_sent_goaway(&self, stream_id: u32) -> bool {
        let peer_initiated = stream_id.is_multiple_of(2) == self.is_client;
        peer_initiated
            && self
                .sent_goaway_last_stream_id
                .is_some_and(|last_stream_id| stream_id > last_stream_id)
    }

    fn stream_can_emit_queued_frames(&self, stream_id: u32) -> bool {
        self.streams
            .get(stream_id)
            .is_some_and(|stream| stream.error_code().is_none())
    }

    /// Process DATA frame.
    fn process_data(&mut self, frame: DataFrame) -> Result<Option<ReceivedFrame>, H2Error> {
        // RFC 7540 §5.1: receiving DATA on an idle stream MUST be treated as a
        // connection error of type PROTOCOL_ERROR. Check before get_or_create
        // to avoid polluting last_stream_id and leaking idle Stream entries.
        if self.streams.is_idle_stream_id(frame.stream_id) {
            return Err(H2Error::protocol("DATA received on idle stream"));
        }

        let refused = self.stream_exceeds_sent_goaway(frame.stream_id);
        if !refused {
            // Track stream ID only after the idle check passes, and only if not refused.
            self.track_stream_id(frame.stream_id);
        }

        // RFC 9113 §6.9.1: the entire DATA frame payload is flow-controlled,
        // including the Pad Length octet and Padding. Charge the windows by the
        // on-the-wire payload length, NOT the (smaller) unpadded application
        // data length — otherwise padded frames under-debit the windows, the
        // peer's send window is never replenished, and the connection deadlocks.
        let payload_len = frame.flow_controlled_len;
        let window_delta = i32::try_from(payload_len)
            .map_err(|_| H2Error::flow_control("data too large for window"))?;
        if window_delta > self.recv_window {
            return Err(H2Error::flow_control(
                "data exceeds connection flow control window",
            ));
        }

        // Decrement the connection-level receive window BEFORE the stream-level
        // check. The peer counted these bytes against their send window when
        // they transmitted the DATA frame, so we must count them here even if
        // the stream rejects the data (e.g. StreamClosed). Failing to do so
        // desynchronizes the connection flow-control windows.
        self.recv_window -= window_delta;

        // Perform connection-level WINDOW_UPDATE check immediately after decrementing,
        // BEFORE any stream-level operations that might return early with a stream error.
        // If we don't do this, DATA frames on closed streams will permanently leak
        // connection window capacity, leading to connection deadlocks.
        let low_watermark = self.initial_recv_window / 2;
        if self.recv_window < low_watermark {
            let increment = i64::from(self.initial_recv_window) - i64::from(self.recv_window);
            let increment = u32::try_from(increment)
                .map_err(|_| H2Error::flow_control("window increment too large"))?;
            self.send_connection_window_update(increment)?;
        }

        // Look up the stream. If the stream was closed and pruned, treat
        // it as a stream error (RFC 7540 §5.1).
        let stream = self.streams.get_mut(frame.stream_id).ok_or_else(|| {
            H2Error::stream(
                frame.stream_id,
                ErrorCode::StreamClosed,
                "DATA received on closed stream",
            )
        })?;
        // RFC 9113 §5.1: DATA the peer sent before our RST_STREAM reached it
        // is discarded. Its connection credit was counted above.
        if stream.reset_sent() {
            return Ok(None);
        }
        stream.recv_data(payload_len, frame.end_stream)?;

        #[cfg(feature = "http2-streaming")]
        if stream.deferred_recv_bytes().is_some() {
            // Padding occupies wire credit but is never handed to the body
            // consumer. Reclaim it here so padding-only DATA cannot deadlock
            // a deferred stream, and the public release API counts DATA only.
            let data_len = u32::try_from(frame.data.len())
                .map_err(|_| H2Error::protocol("DATA length exceeds wire payload"))?;
            let padding_len = payload_len
                .checked_sub(data_len)
                .ok_or_else(|| H2Error::protocol("DATA length exceeds wire payload"))?;
            let increment = stream.release_deferred_recv_capacity(padding_len)?;
            if increment != 0 {
                self.pending_ops.push_back(PendingOp::WindowUpdate {
                    stream_id: frame.stream_id,
                    increment,
                });
            }
        }

        // Auto stream-level WINDOW_UPDATE when recv window drops below 25%.
        if stream.state().can_recv() {
            if let Some(increment) = stream.auto_window_update_increment() {
                // Cannot call send_stream_window_update while stream is borrowed,
                // so we update the stream's recv_window and queue the op directly.
                stream
                    .update_recv_window(i32::try_from(increment).map_err(|_| {
                        H2Error::flow_control("stream window increment too large")
                    })?)?;
                self.pending_ops.push_back(PendingOp::WindowUpdate {
                    stream_id: frame.stream_id,
                    increment,
                });
            }
        }

        if refused {
            Ok(None)
        } else {
            Ok(Some(ReceivedFrame::Data {
                stream_id: frame.stream_id,
                data: frame.data,
                end_stream: frame.end_stream,
            }))
        }
    }

    /// Process HEADERS frame.
    fn process_headers(&mut self, frame: HeadersFrame) -> Result<Option<ReceivedFrame>, H2Error> {
        if self
            .streams
            .get(frame.stream_id)
            .is_some_and(|stream| stream.wire_closed() && stream.error_code().is_none())
        {
            return Err(H2Error::connection(
                ErrorCode::StreamClosed,
                "HEADERS received after both directions ended",
            ));
        }
        if self
            .streams
            .get(frame.stream_id)
            .is_some_and(Stream::reset_sent)
        {
            return self.discard_header_fragment(
                frame.stream_id,
                frame.header_block,
                frame.end_headers,
            );
        }
        // RFC 9113 §6.8: After sending GOAWAY, refuse new streams with IDs
        // above the advertised last_stream_id. Without this, a misbehaving
        // peer could open unbounded streams during the drain phase.
        // We MUST still process the headers through HPACK to keep compression state
        // synchronized, but we will discard the result and send a RST_STREAM.
        let mut refused = self.stream_exceeds_sent_goaway(frame.stream_id);

        // Validate stream creation before tracking last_stream_id.
        // If get_or_create fails (e.g., invalid stream parity or monotonicity
        // violation), we must not pollute last_stream_id — GOAWAY must only
        // report the highest actually-processed stream (RFC 7540 §6.8).
        let created = self
            .streams
            .get_or_create_for_headers(frame.stream_id)
            .map(|stream| stream.headers_refused());
        match created {
            Ok(headers_refused) => refused |= headers_refused,
            Err(error) => {
                return Err(self.decode_unkept_field_block(
                    frame.header_block,
                    frame.end_headers,
                    error,
                ));
            }
        }

        if !refused {
            self.track_stream_id(frame.stream_id);
        }

        // Re-borrow the stream (guaranteed to exist after get_or_create).
        let stream = self.streams.get_mut(frame.stream_id).ok_or_else(|| {
            H2Error::connection(
                ErrorCode::InternalError,
                "stream disappeared after get_or_create",
            )
        })?;
        // br-asupersync-pyhaov: thread direction so Stream can apply
        // the server-side trailers-MUST-have-END_STREAM rule.
        if let Err(error) = stream.recv_headers(frame.end_stream, frame.end_headers, self.is_client)
        {
            if error.stream_id.is_none() {
                return Err(error);
            }
            // RFC 9113 §4.3: the refused block's dynamic-table updates still
            // apply. It takes the path of a block for a reset stream; the
            // caller resets the stream on this error, so the block's
            // CONTINUATION frames take that path too.
            self.discard_header_fragment(frame.stream_id, frame.header_block, frame.end_headers)?;
            return Err(error);
        }

        if let Some(priority) = frame.priority {
            stream.set_priority(priority);
        }

        stream
            .add_header_fragment(frame.header_block)
            .map_err(Self::unkept_field_block_error)?;

        if frame.end_headers {
            self.continuation_stream_id = None;
            self.continuation_started_at = None;
            let result = self.decode_headers(frame.stream_id, frame.end_stream);
            if refused {
                self.pending_ops.push_back(PendingOp::RstStream {
                    stream_id: frame.stream_id,
                    error_code: ErrorCode::RefusedStream,
                });
                // Close the local record too: a refused stream is one we
                // will take no action on, and leaving it active would block
                // graceful-drain quiescence (active_stream_count) forever.
                if let Some(stream) = self.streams.get_mut(frame.stream_id) {
                    stream.reset(ErrorCode::RefusedStream);
                    stream.mark_reset_sent();
                }
                result?; // bubble up compression errors
                Ok(None)
            } else {
                result
            }
        } else {
            self.continuation_stream_id = Some(frame.stream_id);
            self.continuation_started_at = Some((self.time_getter)());
            Ok(None)
        }
    }

    /// Process CONTINUATION frame.
    fn process_continuation(
        &mut self,
        frame: ContinuationFrame,
    ) -> Result<Option<ReceivedFrame>, H2Error> {
        if let Some(pending) = self.pending_push_promise {
            if pending.associated_stream_id == frame.stream_id {
                let promised_stream_id = pending.promised_stream_id;
                let promised = self.streams.get_mut(promised_stream_id).ok_or_else(|| {
                    H2Error::stream(
                        promised_stream_id,
                        ErrorCode::StreamClosed,
                        "promised stream not found",
                    )
                })?;
                promised
                    .add_header_fragment(frame.header_block)
                    .map_err(Self::unkept_field_block_error)?;

                if frame.end_headers {
                    self.pending_push_promise = None;
                    self.continuation_stream_id = None;
                    self.continuation_started_at = None;
                    return self.finish_push_promise(
                        frame.stream_id,
                        promised_stream_id,
                        pending.refusal,
                    );
                }

                return Ok(None);
            }
        }

        if self
            .streams
            .get(frame.stream_id)
            .is_some_and(Stream::reset_sent)
        {
            return self.discard_header_fragment(
                frame.stream_id,
                frame.header_block,
                frame.end_headers,
            );
        }
        let stream = self
            .streams
            .get_mut(frame.stream_id)
            .ok_or_else(|| H2Error::protocol("CONTINUATION for unknown stream"))?;

        stream
            .recv_continuation(frame.header_block, frame.end_headers)
            .map_err(Self::unkept_field_block_error)?;

        if frame.end_headers {
            self.continuation_stream_id = None;
            self.continuation_started_at = None;
            // Get end_stream from stream state
            let end_stream = matches!(
                stream.state(),
                StreamState::HalfClosedRemote | StreamState::Closed
            );
            let headers_refused = stream.headers_refused();
            let refused = headers_refused || self.stream_exceeds_sent_goaway(frame.stream_id);
            let result = self.decode_headers(frame.stream_id, end_stream);
            if refused {
                self.pending_ops.push_back(PendingOp::RstStream {
                    stream_id: frame.stream_id,
                    error_code: ErrorCode::RefusedStream,
                });
                // Mirror process_headers: close the local record so a
                // refused stream cannot pin active_stream_count above zero
                // during graceful drain.
                if let Some(stream) = self.streams.get_mut(frame.stream_id) {
                    stream.reset(ErrorCode::RefusedStream);
                    stream.mark_reset_sent();
                }
                result?; // bubble up compression errors
                Ok(None)
            } else {
                result
            }
        } else {
            Ok(None)
        }
    }

    /// A field block the stream's record cannot hold (past the fragment
    /// count or size cap) cannot be decoded, and a stream error would leave
    /// the HPACK tables behind the peer's (RFC 9113 §4.3), so it ends the
    /// connection.
    fn unkept_field_block_error(error: H2Error) -> H2Error {
        if error.stream_id.is_some() {
            H2Error::connection(error.code, "field block too large to keep for decoding")
        } else {
            error
        }
    }

    /// A HEADERS frame refused before any stream record exists (a stream id
    /// past the implementation's gap ceiling) still carries dynamic-table
    /// updates (RFC 9113 §4.3). A complete block is decoded and dropped
    /// before the stream error; a block that continues in CONTINUATION
    /// frames has no record to collect it, so the connection ends.
    fn decode_unkept_field_block(
        &mut self,
        mut fragment: Bytes,
        end_headers: bool,
        error: H2Error,
    ) -> H2Error {
        if error.stream_id.is_none() {
            return error;
        }
        if !end_headers {
            return H2Error::connection(
                ErrorCode::EnhanceYourCalm,
                "refused stream's field block continues in CONTINUATION frames",
            );
        }
        match self.hpack_decoder.decode(&mut fragment) {
            Ok(_) => error,
            Err(decode_error) => decode_error,
        }
    }

    /// Take a field block fragment the peer sent before our RST_STREAM
    /// reached it. RFC 9113 §5.1 ignores the frame, but §4.3 still requires
    /// the block to pass through the HPACK decoder: the peer's encoder has
    /// already applied its dynamic-table insertions, and skipping them
    /// misdecodes every later field block on the connection.
    fn discard_header_fragment(
        &mut self,
        stream_id: u32,
        fragment: Bytes,
        end_headers: bool,
    ) -> Result<Option<ReceivedFrame>, H2Error> {
        let stream = self
            .streams
            .get_mut(stream_id)
            .ok_or_else(|| H2Error::connection(ErrorCode::InternalError, "reset stream missing"))?;
        // A block too large to keep cannot be decoded, and a stream error
        // would leave the tables out of step, so it ends the connection.
        stream.add_header_fragment(fragment).map_err(|error| {
            H2Error::connection(error.code, "oversized field block on a reset stream")
        })?;
        if !end_headers {
            self.continuation_stream_id = Some(stream_id);
            self.continuation_started_at = Some((self.time_getter)());
            return Ok(None);
        }
        self.continuation_stream_id = None;
        self.continuation_started_at = None;
        let mut block = BytesMut::new();
        for fragment in stream.take_header_fragments() {
            block.extend_from_slice(&fragment);
        }
        self.hpack_decoder.decode(&mut block.freeze())?;
        Ok(None)
    }

    /// Decode accumulated headers for a stream.
    ///
    /// br-asupersync-vqpx88: applies RFC 9113 §8.3 / §8.3.1 / §8.3.2
    /// pseudo-header structural validation to the HPACK-decoded
    /// header block. Direction is inferred from `self.is_client`:
    /// when we are a server, incoming HEADERS frames carry requests
    /// (validated against §8.3.1); when we are a client, incoming
    /// HEADERS frames carry responses (validated against §8.3.2).
    /// Per RFC 9113 §8.1.1 a malformed message is a stream error of
    /// type `PROTOCOL_ERROR` — *not* a connection error — so the
    /// rejection is scoped to the offending stream and the
    /// connection survives to serve other peers.
    fn decode_headers(
        &mut self,
        stream_id: u32,
        end_stream: bool,
    ) -> Result<Option<ReceivedFrame>, H2Error> {
        let stream = self.streams.get_mut(stream_id).ok_or_else(|| {
            H2Error::connection(ErrorCode::InternalError, "decode_headers missing stream")
        })?;
        // br-asupersync-0eyf7t — RFC 9113 §8.1: trailers MUST NOT
        // contain pseudo-header fields. A second HEADERS-with-
        // END_HEADERS for the same stream is either trailers
        // (server-side: always; client-side: when END_STREAM is
        // set) or 1xx informational (client-side: when END_STREAM
        // is not set). Capture the discrimination here, before any
        // mutation, so the validator can reject pseudo-headers in
        // the trailers section. is_request is unchanged from
        // br-asupersync-vqpx88: server sees requests, client sees
        // responses.
        let is_subsequent_headers = stream.initial_headers_decoded();
        let is_request = !self.is_client;
        // br-asupersync-k4jj9p: a client may receive 1xx informational
        // HEADERS (e.g. 100 Continue, 103 Early Hints) followed by the
        // final 2xx/3xx/4xx/5xx HEADERS even when the final response is
        // bodyless. Per RFC 9113 §8.1 + §8.3.2, only the FINAL response
        // promotes the stream to "initial headers decoded"; subsequent
        // HEADERS before a final response are still informational, NOT
        // trailers. Compute a tentative is_trailers and refine it after
        // header decoding using the just-observed :status pseudo-header.
        let tentative_is_trailers = is_subsequent_headers && (is_request || end_stream);

        let fragments = stream.take_header_fragments();

        // Concatenate all fragments
        let total_len: usize = fragments.iter().map(Bytes::len).sum();
        let max_fragment_size =
            Stream::max_header_fragment_size_for(self.local_settings.max_header_list_size);
        if total_len > max_fragment_size {
            // Not decoded, so not a stream error (RFC 9113 §4.3).
            return Err(Self::unkept_field_block_error(H2Error::stream(
                stream_id,
                ErrorCode::EnhanceYourCalm,
                "accumulated header fragments too large",
            )));
        }
        let mut combined = BytesMut::with_capacity(total_len);
        for fragment in fragments {
            combined.extend_from_slice(&fragment);
        }

        // Decode headers
        let mut src = combined.freeze();
        let headers = self.hpack_decoder.decode(&mut src)?;

        // br-asupersync-k4jj9p: refine is_trailers using the just-observed
        // :status pseudo-header. CLIENT side: a subsequent HEADERS is
        // trailers ONLY if there is NO :status pseudo-header (since 1xx
        // informational AND final responses both carry :status). SERVER
        // side keeps the original semantics — any subsequent HEADERS is
        // trailers (1xx informational is impossible request-side).
        let observed_status = headers
            .iter()
            .find(|h| h.name.as_bytes() == b":status")
            .and_then(|h| std::str::from_utf8(h.value.as_bytes()).ok())
            .and_then(|s| s.parse::<u16>().ok());
        let is_informational_response =
            !is_request && observed_status.is_some_and(|s| (100..200).contains(&s));
        let is_trailers = if is_request {
            tentative_is_trailers
        } else {
            // Client side: trailers iff subsequent-headers AND no :status.
            // end_stream alone is NOT sufficient — a bodyless final
            // response after 1xx has end_stream=true but is NOT trailers.
            is_subsequent_headers && observed_status.is_none() && end_stream
        };

        // br-asupersync-vqpx88 + br-asupersync-0eyf7t: RFC 9113
        // §8.3.1/§8.3.2 pseudo-header structural validation, plus
        // the §8.1 trailers-have-no-pseudo-headers rule. The
        // is_trailers flag short-circuits to a stricter
        // no-pseudo-headers path inside the validator while still
        // applying the regular-header validations
        // (lowercase names, connection-specific header ban).
        if let Err(why) = validate_h2_pseudo_headers(&headers, is_request, is_trailers) {
            return Err(H2Error::stream(stream_id, ErrorCode::ProtocolError, why));
        }

        // br-asupersync-0eyf7t + br-asupersync-k4jj9p — mark the
        // initial-headers gate ONLY when we've observed the FINAL
        // response (not a 1xx informational). Marking on 1xx would
        // mis-classify the subsequent final-response HEADERS as
        // trailers, rejecting its valid :status pseudo-header.
        let should_mark_initial = !is_trailers && !is_informational_response;
        if should_mark_initial {
            if let Some(stream) = self.streams.get_mut(stream_id) {
                stream.mark_initial_headers_decoded();
            }
        }

        Ok(Some(ReceivedFrame::Headers {
            stream_id,
            headers,
            end_stream,
        }))
    }

    /// Completes a PUSH_PROMISE field block: an accepted promise is decoded
    /// into a [`ReceivedFrame::PushPromise`]; a refused one is decoded and
    /// dropped, its promised stream reset, and its stream error, if any,
    /// returned. The reset is sent here, so a caller that resets the error's
    /// stream again sends nothing more (`reset_stream` skips a reset stream).
    fn finish_push_promise(
        &mut self,
        associated_stream_id: u32,
        promised_stream_id: u32,
        refusal: Option<PushRefusal>,
    ) -> Result<Option<ReceivedFrame>, H2Error> {
        let Some(refusal) = refusal else {
            return self.decode_push_promise(associated_stream_id, promised_stream_id);
        };
        let promised = self.streams.get_mut(promised_stream_id).ok_or_else(|| {
            H2Error::connection(ErrorCode::InternalError, "refused promised stream missing")
        })?;
        let mut block = BytesMut::new();
        for fragment in promised.take_header_fragments() {
            block.extend_from_slice(&fragment);
        }
        promised.reset(refusal.reset);
        promised.mark_reset_sent();
        self.pending_ops.push_back(PendingOp::RstStream {
            stream_id: promised_stream_id,
            error_code: refusal.reset,
        });
        self.hpack_decoder.decode(&mut block.freeze())?;
        match refusal.error {
            Some((stream_id, code, reason)) => Err(H2Error::stream(stream_id, code, reason)),
            None => Ok(None),
        }
    }

    /// Decode accumulated PUSH_PROMISE headers for a promised stream.
    fn decode_push_promise(
        &mut self,
        associated_stream_id: u32,
        promised_stream_id: u32,
    ) -> Result<Option<ReceivedFrame>, H2Error> {
        let promised = self.streams.get_mut(promised_stream_id).ok_or_else(|| {
            H2Error::stream(
                promised_stream_id,
                ErrorCode::StreamClosed,
                "promised stream not found",
            )
        })?;
        let fragments = promised.take_header_fragments();

        let total_len: usize = fragments.iter().map(Bytes::len).sum();
        let max_fragment_size =
            Stream::max_header_fragment_size_for(self.local_settings.max_header_list_size);
        if total_len > max_fragment_size {
            // Undecoded, the block would leave the HPACK tables behind the
            // peer's (RFC 9113 §4.3), so it ends the connection.
            return Err(H2Error::connection(
                ErrorCode::EnhanceYourCalm,
                "accumulated header fragments too large",
            ));
        }
        let mut combined = BytesMut::with_capacity(total_len);
        for fragment in fragments {
            combined.extend_from_slice(&fragment);
        }

        let mut src = combined.freeze();
        let headers = self.hpack_decoder.decode(&mut src)?;

        // br-asupersync-vqpx88: PUSH_PROMISE carries request semantics
        // (RFC 9113 §8.4 — server-pushed request that the server
        // promises to fulfil). The pseudo-header set is validated as
        // a request regardless of our local role; per §8.4 a client
        // receiving an invalid PUSH_PROMISE MUST treat it as a
        // stream error of type PROTOCOL_ERROR scoped to the
        // promised stream (not the associated stream).
        // PUSH_PROMISE always carries a request header block (no
        // trailers form); is_trailers=false.
        if let Err(why) = validate_h2_pseudo_headers(
            &headers, /* is_request = */ true, /* is_trailers = */ false,
        ) {
            return Err(H2Error::stream(
                promised_stream_id,
                ErrorCode::ProtocolError,
                why,
            ));
        }

        Ok(Some(ReceivedFrame::PushPromise {
            stream_id: associated_stream_id,
            promised_stream_id,
            headers,
        }))
    }

    /// Process RST_STREAM frame.
    ///
    /// RFC 7540 §5.1: RST_STREAM received on a stream in the idle state MUST
    /// be treated as a connection error of type PROTOCOL_ERROR.
    ///
    /// Includes rate limiting to protect against CVE-2023-44487 (HTTP/2 Rapid
    /// Reset) class attacks. If the peer sends more than `DEFAULT_RST_STREAM_RATE_LIMIT`
    /// RST_STREAM frames within `DEFAULT_RST_STREAM_RATE_WINDOW_MS`, the connection is
    /// terminated with ENHANCE_YOUR_CALM.
    fn process_rst_stream(&mut self, frame: RstStreamFrame) -> Result<ReceivedFrame, H2Error> {
        // RFC 7540 §6.4: RST_STREAM frames MUST NOT be sent for stream 0.
        if frame.stream_id == 0 {
            return Err(H2Error::protocol("RST_STREAM with stream ID 0"));
        }

        // RFC 7540 §5.1: receiving RST_STREAM on an idle stream MUST be
        // treated as a connection error of type PROTOCOL_ERROR.
        if self.streams.is_idle_stream_id(frame.stream_id) {
            return Err(H2Error::protocol("RST_STREAM received on idle stream"));
        }

        // Track stream ID so GOAWAY last_stream_id is correct (RFC 9113 §6.8).
        self.track_stream_id(frame.stream_id);

        self.record_peer_reset()?;

        if let Some(stream) = self.streams.get_mut(frame.stream_id) {
            stream.reset(frame.error_code);
        }

        Ok(ReceivedFrame::Reset {
            stream_id: frame.stream_id,
            error_code: frame.error_code,
        })
    }

    /// One budget covers both peer resets and errors requiring a local reset.
    fn record_peer_reset(&mut self) -> Result<(), H2Error> {
        let now = (self.time_getter)();
        let elapsed =
            std::time::Duration::from_nanos(now.duration_since(self.rst_stream_window_start))
                .as_millis();
        if elapsed >= self.rst_rate_limit.rst_window_ms {
            // Reset the window.
            self.rst_stream_count = 0;
            self.rst_stream_window_start = now;
        }

        // Fail closed at the configured limit instead of incrementing first.
        // This preserves the "N allowed, N+1 rejected" contract even when the
        // configured ceiling is `u32::MAX`, where a direct increment would wrap.
        if self.rst_stream_count >= self.rst_rate_limit.max_rst_streams {
            return Err(H2Error::connection(
                ErrorCode::EnhanceYourCalm,
                "peer reset or stream-error flood detected",
            ));
        }
        self.rst_stream_count += 1;

        Ok(())
    }

    /// Process SETTINGS frame.
    fn process_settings(
        &mut self,
        frame: &SettingsFrame,
    ) -> Result<Option<ReceivedFrame>, H2Error> {
        if frame.ack {
            // ACK received for our settings
            return Ok(None);
        }

        // br-asupersync-wk370q: validate ALL settings BEFORE applying
        // any side-effect. Pre-fix this loop applied each setting in
        // turn (mutating self.remote_settings, self.streams,
        // self.hpack_encoder) and returned early on the first
        // failure — leaving partial state behind. With the SETTINGS
        // frame as a whole rejected, the connection would proceed to
        // GOAWAY but the per-stream initial_window_size, the HPACK
        // encoder table size, and the connection-level
        // remote_settings would have absorbed every setting before
        // the failing one. That partial state is observable during
        // the GOAWAY drain and contradicts what the peer thinks the
        // connection state is — flow-control desync, HPACK encoder
        // table-size leak, etc.
        //
        // The fix: stage every setting onto a clone of
        // remote_settings, fail-stop on first error, and only apply
        // side-effects after every setting in the frame validates
        // successfully.
        let mut staged = self.remote_settings.clone();
        for setting in &frame.settings {
            // RFC 9113 §6.5.2: a server MAY include SETTINGS_ENABLE_PUSH, but
            // only with the value 0. A client MUST treat the value 1 as a
            // connection error of type PROTOCOL_ERROR.
            if self.is_client && matches!(setting, Setting::EnablePush(true)) {
                return Err(H2Error::protocol(
                    "server MUST NOT send SETTINGS_ENABLE_PUSH=1",
                ));
            }
            if let Setting::InitialWindowSize(size) = setting {
                self.streams.check_initial_window_size(*size)?;
            }
            staged.apply(*setting)?;
        }

        // Validation passed — commit the staged settings atomically
        // and apply derived side-effects in a second pass that cannot
        // fail (set_initial_window_size is the only fallible call,
        // and it only fails when the new value would overflow a
        // u31; staged already accepted the value so this is safe).
        self.remote_settings = staged;
        for setting in &frame.settings {
            match setting {
                Setting::InitialWindowSize(size) => {
                    self.streams.set_initial_window_size(*size)?;
                }
                Setting::HeaderTableSize(size) => {
                    // Cap to 1 MiB (same limit as the decoder) to prevent
                    // unbounded encoder table growth from a peer's SETTINGS.
                    let capped = (*size as usize).min(1024 * 1024);
                    self.hpack_encoder.set_max_table_size(capped);
                }
                Setting::MaxConcurrentStreams(max) => {
                    self.streams.set_remote_max_concurrent_streams(*max);
                }
                Setting::MaxFrameSize(size) => {
                    // Update frame codec when we have one
                    let _ = size;
                }
                _ => {}
            }
        }

        // Send ACK
        self.pending_ops.push_back(PendingOp::SettingsAck);

        if !self.received_settings {
            self.received_settings = true;
            self.state = ConnectionState::Open;
        }

        Ok(None)
    }

    /// Process PUSH_PROMISE frame.
    fn process_push_promise(
        &mut self,
        frame: &PushPromiseFrame,
    ) -> Result<Option<ReceivedFrame>, H2Error> {
        if !self.is_client {
            return Err(H2Error::protocol("server received PUSH_PROMISE"));
        }
        if !self.local_settings.enable_push {
            return Err(H2Error::protocol("push not enabled"));
        }
        if frame.stream_id.is_multiple_of(2) {
            return Err(H2Error::protocol("PUSH_PROMISE on server-initiated stream"));
        }

        // A promise refused below still carries dynamic-table updates (RFC
        // 9113 §4.3): its field block is collected and decoded like an
        // accepted one, and the refusal is applied when the block is complete
        // (finish_push_promise). Returning before decoding left this side's
        // HPACK tables behind the peer's, so later field blocks decoded to
        // the wrong header values.
        let refusal = if self.stream_exceeds_sent_goaway(frame.promised_stream_id) {
            // RFC 9113 §6.8: after sending GOAWAY, refuse new streams with
            // IDs above the advertised last_stream_id.
            Some(PushRefusal {
                reset: ErrorCode::RefusedStream,
                error: None,
            })
        } else {
            let Some(associated) = self.streams.get(frame.stream_id) else {
                return Err(H2Error::protocol("PUSH_PROMISE on unknown stream"));
            };
            let assoc_state = associated.state();
            if associated.reset_sent() {
                // RFC 9113 §6.6: a promise the peer sent before our RST_STREAM
                // on the associated stream reached it is handled, not an
                // error: the promised stream is cancelled.
                Some(PushRefusal {
                    reset: ErrorCode::Cancel,
                    error: None,
                })
            } else if !matches!(
                assoc_state,
                StreamState::Open | StreamState::HalfClosedLocal
            ) {
                // RFC 7540 §5.1: PUSH_PROMISE is only valid on a stream that
                // is open or half-closed (local).
                let code = if assoc_state.is_closed() {
                    ErrorCode::StreamClosed
                } else {
                    ErrorCode::ProtocolError
                };
                Some(PushRefusal {
                    reset: ErrorCode::RefusedStream,
                    error: Some((
                        frame.stream_id,
                        code,
                        "PUSH_PROMISE on stream not in open or half-closed (local) state",
                    )),
                })
            } else if self.streams.active_count() as u32
                >= self.local_settings.max_concurrent_streams
            {
                // RST_STREAM must target the promised stream (RFC 7540
                // §8.2.2), not the parent request stream.
                Some(PushRefusal {
                    reset: ErrorCode::RefusedStream,
                    error: Some((
                        frame.promised_stream_id,
                        ErrorCode::RefusedStream,
                        "max concurrent streams exceeded",
                    )),
                })
            } else {
                None
            }
        };

        let promised_stream_id = frame.promised_stream_id;
        // A promised id the stream table refuses (past its gap ceiling) is a
        // stream error with no record to collect the block in: a complete
        // block is decoded first, a continued one ends the connection.
        if let Err(error) = self
            .streams
            .reserve_remote_stream(promised_stream_id)
            .map(|_| ())
        {
            return Err(self.decode_unkept_field_block(
                frame.header_block.clone(),
                frame.end_headers,
                error,
            ));
        }
        let promised_stream = self.streams.get_mut(promised_stream_id).ok_or_else(|| {
            H2Error::connection(ErrorCode::InternalError, "promised stream missing")
        })?;
        promised_stream
            .add_header_fragment(frame.header_block.clone())
            .map_err(Self::unkept_field_block_error)?;

        if frame.end_headers {
            self.continuation_stream_id = None;
            self.continuation_started_at = None;
            self.finish_push_promise(frame.stream_id, promised_stream_id, refusal)
        } else {
            self.pending_push_promise = Some(PushPromiseAccumulator {
                associated_stream_id: frame.stream_id,
                promised_stream_id,
                refusal,
            });
            self.continuation_stream_id = Some(frame.stream_id);
            self.continuation_started_at = Some((self.time_getter)());
            Ok(None)
        }
    }

    /// Process PING frame.
    fn process_ping(&mut self, frame: PingFrame) -> Option<ReceivedFrame> {
        if !frame.ack {
            // Send PING ACK
            self.pending_ops
                .push_back(PendingOp::PingAck(frame.opaque_data));
        }
        None
    }

    /// Process GOAWAY frame.
    fn process_goaway(&mut self, frame: GoAwayFrame) -> ReceivedFrame {
        self.goaway_received = true;
        self.state = ConnectionState::Closing;
        let effective_last_stream_id = self
            .received_goaway_last_stream_id
            .map_or(frame.last_stream_id, |previous| {
                previous.min(frame.last_stream_id)
            });
        self.received_goaway_last_stream_id = Some(effective_last_stream_id);

        // Reset locally-initiated streams that weren't processed by the peer.
        // The last_stream_id only restricts streams initiated by the receiver of the GOAWAY.
        for stream_id in self.streams.active_stream_ids() {
            let is_local = (stream_id % 2 == 1) == self.is_client;
            if is_local && stream_id > effective_last_stream_id {
                if let Some(stream) = self.streams.get_mut(stream_id) {
                    stream.reset(ErrorCode::RefusedStream);
                }
            }
        }

        ReceivedFrame::GoAway {
            last_stream_id: effective_last_stream_id,
            error_code: frame.error_code,
            debug_data: frame.debug_data,
        }
    }

    /// Process WINDOW_UPDATE frame.
    fn process_window_update(
        &mut self,
        frame: WindowUpdateFrame,
    ) -> Result<Option<ReceivedFrame>, H2Error> {
        let increment = i32::try_from(frame.increment)
            .map_err(|_| H2Error::flow_control("window increment too large"))?;
        // RFC 9113 §5.1 forbids WINDOW_UPDATE on an idle stream regardless
        // of its increment. Validate state before choosing the error scope.
        if frame.stream_id != 0 && self.streams.is_idle_stream_id(frame.stream_id) {
            return Err(H2Error::protocol("WINDOW_UPDATE received on idle stream"));
        }
        // RFC 9113 §6.9.1: increment of 0 on the connection flow-control
        // window (stream 0) MUST be treated as a connection error of type
        // PROTOCOL_ERROR. On an existing stream it is a stream error.
        if increment == 0 {
            if frame.stream_id == 0 {
                return Err(H2Error::protocol("WINDOW_UPDATE with zero increment"));
            }
            return Err(H2Error::stream(
                frame.stream_id,
                ErrorCode::ProtocolError,
                "WINDOW_UPDATE with zero increment",
            ));
        }
        if frame.stream_id == 0 {
            // Connection-level window update
            // Check for overflow using wider arithmetic before adding
            let new_window = i64::from(self.send_window) + i64::from(increment);
            if new_window > i64::from(i32::MAX) {
                return Err(H2Error::flow_control("connection window overflow"));
            }
            self.send_window = new_window as i32;
        } else {
            // Stream-level window update
            if let Some(stream) = self.streams.get_mut(frame.stream_id) {
                stream.update_send_window(increment)?;
            }
        }

        Ok(None)
    }

    /// Get next pending frame to send.
    #[allow(clippy::too_many_lines)]
    pub fn next_frame(&mut self) -> Option<Frame> {
        let mut blocked_data = false;
        let pending_len = self.pending_ops.len();
        let mut skipped_ops = std::collections::VecDeque::new();
        let mut newly_queued_ops = std::collections::VecDeque::new();
        let mut returned_frame = None;
        // Streams whose DATA was set aside for lack of send credit. Their later
        // HEADERS (trailers), DATA and PUSH_PROMISE stay queued behind it: a
        // trailer or an empty final DATA sent first would carry END_STREAM
        // ahead of the body (br-asupersync-dx72q4).
        let mut held_streams: Vec<u32> = Vec::new();

        for _ in 0..pending_len {
            let op = self.pending_ops.pop_front()?;

            match op {
                PendingOp::Settings(frame) => {
                    returned_frame = Some(Frame::Settings(frame));
                    break;
                }
                PendingOp::SettingsAck => {
                    returned_frame = Some(Frame::Settings(SettingsFrame::ack()));
                    break;
                }
                PendingOp::PingAck(data) => {
                    returned_frame = Some(Frame::Ping(PingFrame::ack(data)));
                    break;
                }
                PendingOp::WindowUpdate {
                    stream_id,
                    increment,
                } => {
                    if stream_id != 0 && !self.stream_can_emit_queued_frames(stream_id) {
                        continue;
                    }
                    returned_frame = Some(Frame::WindowUpdate(WindowUpdateFrame::new(
                        stream_id, increment,
                    )));
                    break;
                }
                PendingOp::Headers {
                    stream_id,
                    headers,
                    end_stream,
                } => {
                    if !self.stream_can_emit_queued_frames(stream_id) {
                        continue;
                    }
                    if held_streams.contains(&stream_id) {
                        skipped_ops.push_back(PendingOp::Headers {
                            stream_id,
                            headers,
                            end_stream,
                        });
                        continue;
                    }
                    if end_stream {
                        self.streams.get_mut(stream_id)?.emit_end_stream();
                    }
                    // Encode headers
                    let mut encoded = BytesMut::new();
                    self.hpack_encoder.encode(&headers, &mut encoded);
                    let encoded = encoded.freeze();

                    let max_frame_size = self.remote_settings.max_frame_size as usize;

                    if encoded.len() <= max_frame_size {
                        // Fits in a single HEADERS frame
                        returned_frame = Some(Frame::Headers(HeadersFrame::new(
                            stream_id, encoded, end_stream, true, // end_headers
                        )));
                        break;
                    }

                    // Need CONTINUATION frames - split the header block
                    let first_chunk = encoded.slice(..max_frame_size);
                    let remaining = encoded.slice(max_frame_size..);

                    // Queue CONTINUATION frames for remaining data.
                    // Push to newly_queued_ops so they are emitted immediately after
                    // this HEADERS frame, before any other pending ops
                    // (RFC 9113 §6.10 requires CONTINUATION to follow HEADERS
                    // without interleaving other frame types).
                    let mut offset = 0;
                    while offset < remaining.len() {
                        let chunk_end = (offset + max_frame_size).min(remaining.len());
                        let chunk = remaining.slice(offset..chunk_end);
                        let is_last = chunk_end == remaining.len();
                        newly_queued_ops.push_back(PendingOp::Continuation {
                            stream_id,
                            header_block: chunk,
                            end_headers: is_last,
                        });
                        offset = chunk_end;
                    }

                    returned_frame = Some(Frame::Headers(HeadersFrame::new(
                        stream_id,
                        first_chunk,
                        end_stream,
                        false, // end_headers = false, CONTINUATION follows
                    )));
                    break;
                }
                PendingOp::PushPromise {
                    stream_id,
                    promised_stream_id,
                    headers,
                } => {
                    if !self.stream_can_emit_queued_frames(stream_id)
                        || !self.stream_can_emit_queued_frames(promised_stream_id)
                    {
                        continue;
                    }
                    if held_streams.contains(&stream_id) {
                        skipped_ops.push_back(PendingOp::PushPromise {
                            stream_id,
                            promised_stream_id,
                            headers,
                        });
                        continue;
                    }

                    let mut encoded = BytesMut::new();
                    self.hpack_encoder.encode(&headers, &mut encoded);
                    let encoded = encoded.freeze();

                    let max_frame_size = self.remote_settings.max_frame_size as usize;
                    debug_assert!(max_frame_size > 4);
                    let first_chunk_limit = max_frame_size - 4;

                    if encoded.len() <= first_chunk_limit {
                        returned_frame = Some(Frame::PushPromise(PushPromiseFrame {
                            stream_id,
                            promised_stream_id,
                            header_block: encoded,
                            end_headers: true,
                        }));
                        break;
                    }

                    let first_chunk = encoded.slice(..first_chunk_limit);
                    let remaining = encoded.slice(first_chunk_limit..);

                    let mut offset = 0;
                    while offset < remaining.len() {
                        let chunk_end = (offset + max_frame_size).min(remaining.len());
                        let chunk = remaining.slice(offset..chunk_end);
                        let is_last = chunk_end == remaining.len();
                        newly_queued_ops.push_back(PendingOp::Continuation {
                            stream_id,
                            header_block: chunk,
                            end_headers: is_last,
                        });
                        offset = chunk_end;
                    }

                    returned_frame = Some(Frame::PushPromise(PushPromiseFrame {
                        stream_id,
                        promised_stream_id,
                        header_block: first_chunk,
                        end_headers: false,
                    }));
                    break;
                }
                PendingOp::Continuation {
                    stream_id,
                    header_block,
                    end_headers,
                } => {
                    // A CONTINUATION is queued only once its HEADERS or
                    // PUSH_PROMISE has gone out without END_HEADERS, so it goes
                    // out even if the stream was reset since: the peer must see
                    // the block completed before any other frame (RFC 9113
                    // §6.10, else a connection error), and its HPACK decoder
                    // needs the rest of the block.
                    returned_frame = Some(Frame::Continuation(ContinuationFrame {
                        stream_id,
                        header_block,
                        end_headers,
                    }));
                    break;
                }
                PendingOp::Data {
                    stream_id,
                    data,
                    end_stream,
                } => {
                    let stream_avail = match self.streams.get(stream_id) {
                        // A reset stream cannot send any queued frames, but a
                        // normally-closed stream may still need to flush the
                        // final chunk that closed it.
                        Some(stream) if stream.error_code().is_none() => {
                            stream.send_window().max(0).cast_unsigned()
                        }
                        _ => continue,
                    };
                    if held_streams.contains(&stream_id) {
                        skipped_ops.push_back(PendingOp::Data {
                            stream_id,
                            data,
                            end_stream,
                        });
                        continue;
                    }

                    // Determine the maximum sendable bytes from flow control windows and max_frame_size.
                    let conn_avail = self.send_window.max(0).cast_unsigned();
                    let frame_size_limit = self.remote_settings.max_frame_size;
                    let max_send = conn_avail.min(stream_avail).min(frame_size_limit) as usize;

                    if max_send == 0 && !data.is_empty() {
                        // No send window available; re-queue for later.
                        skipped_ops.push_back(PendingOp::Data {
                            stream_id,
                            data,
                            end_stream,
                        });
                        held_streams.push(stream_id);
                        blocked_data = true;
                        continue;
                    }

                    let send_len = data.len().min(max_send);
                    let (to_send, remainder) = if send_len < data.len() {
                        (data.slice(..send_len), Some(data.slice(send_len..)))
                    } else {
                        (data, None)
                    };

                    // Re-queue leftover data (end_stream only on the final piece).
                    let actually_end = end_stream && remainder.is_none();
                    if let Some(rest) = remainder {
                        skipped_ops.push_back(PendingOp::Data {
                            stream_id,
                            data: rest,
                            end_stream,
                        });
                    }

                    // Consume send windows.
                    let consumed = u32::try_from(to_send.len())
                        .expect("send_len already clamped to u32 range");
                    self.send_window -= consumed.cast_signed();
                    if let Some(stream) = self.streams.get_mut(stream_id) {
                        stream.consume_send_window(consumed);
                        if actually_end {
                            stream.emit_end_stream();
                        }
                    }

                    returned_frame = Some(Frame::Data(DataFrame::new(
                        stream_id,
                        to_send,
                        actually_end,
                    )));
                    break;
                }
                PendingOp::RstStream {
                    stream_id,
                    error_code,
                } => {
                    returned_frame =
                        Some(Frame::RstStream(RstStreamFrame::new(stream_id, error_code)));
                    break;
                }
                PendingOp::GoAway {
                    last_stream_id,
                    error_code,
                    debug_data,
                } => {
                    let mut frame = GoAwayFrame::new(last_stream_id, error_code);
                    frame.debug_data = debug_data;
                    returned_frame = Some(Frame::GoAway(frame));
                    break;
                }
            }
        }

        // Rebuild self.pending_ops while preserving precise ordering.
        // 1. newly_queued_ops (e.g. CONTINUATION) must go first so they are emitted next.
        // 2. skipped_ops (e.g. blocked DATA) go next so they maintain their original relative order.
        // 3. The remainder of self.pending_ops stays at the back.
        for op in skipped_ops.into_iter().rev() {
            self.pending_ops.push_front(op);
        }
        for op in newly_queued_ops.into_iter().rev() {
            self.pending_ops.push_front(op);
        }

        if returned_frame.is_some() {
            return returned_frame;
        }

        if blocked_data {
            return None;
        }

        None
    }

    /// Check if there are pending frames to send.
    #[must_use]
    pub fn has_pending_frames(&self) -> bool {
        !self.pending_ops.is_empty()
    }

    /// Check whether any queued outbound frame still belongs to `stream_id`.
    ///
    /// This lets the HTTP/2 listener keep request in-flight accounting alive
    /// until response frames have actually left the connection queue rather
    /// than only until the handler has produced a response. That distinction
    /// matters when DATA is flow-control-blocked and remains in `pending_ops`
    /// across drain-supervisor observations.
    #[must_use]
    pub fn has_pending_frames_for_stream(&self, stream_id: u32) -> bool {
        self.pending_ops
            .iter()
            .any(|op| op.references_stream(stream_id))
    }

    /// Streams whose queued nonempty DATA is held by peer credit, even when the
    /// application's final DATA has already marked its stream locally closed.
    #[cfg(not(target_arch = "wasm32"))]
    pub(super) fn flow_control_blocked_data_streams(&self) -> impl Iterator<Item = u32> + '_ {
        self.pending_ops.iter().filter_map(|op| {
            let PendingOp::Data {
                stream_id, data, ..
            } = op
            else {
                return None;
            };
            (!data.is_empty()
                && self.streams.get(*stream_id).is_some_and(|stream| {
                    stream.error_code().is_none()
                        && (self.send_window <= 0 || stream.send_window() <= 0)
                }))
            .then_some(*stream_id)
        })
    }

    fn prune_closed_streams_without_pending_frames(&mut self) {
        let pending_ops = &self.pending_ops;
        // A closed stream whose field block is still arriving keeps its
        // record until the block's last CONTINUATION frame.
        let continuation_stream_id = self.continuation_stream_id;
        self.streams.prune_closed_except(|stream_id| {
            continuation_stream_id == Some(stream_id)
                || pending_ops.iter().any(|op| op.references_stream(stream_id))
        });
    }

    /// Send a WINDOW_UPDATE for connection-level flow control.
    ///
    /// # Errors
    ///
    /// Returns `H2Error` if `increment` is zero (RFC 7540 §6.9) or exceeds `i32::MAX`.
    pub fn send_connection_window_update(&mut self, increment: u32) -> Result<(), H2Error> {
        if increment == 0 {
            return Err(H2Error::flow_control(
                "WINDOW_UPDATE increment must be non-zero (RFC 7540 §6.9)",
            ));
        }
        let delta = i32::try_from(increment)
            .map_err(|_| H2Error::flow_control("window increment too large"))?;
        let new_window = i64::from(self.recv_window) + i64::from(delta);
        if new_window > i64::from(i32::MAX) {
            return Err(H2Error::flow_control("connection window overflow"));
        }
        self.recv_window = new_window as i32;
        self.pending_ops.push_back(PendingOp::WindowUpdate {
            stream_id: 0,
            increment,
        });
        Ok(())
    }

    /// Send a WINDOW_UPDATE for stream-level flow control.
    ///
    /// # Errors
    ///
    /// Returns `H2Error` if `increment` is zero (RFC 7540 §6.9) or exceeds `i32::MAX`.
    pub fn send_stream_window_update(
        &mut self,
        stream_id: u32,
        increment: u32,
    ) -> Result<(), H2Error> {
        if increment == 0 {
            return Err(H2Error::flow_control(
                "WINDOW_UPDATE increment must be non-zero (RFC 7540 §6.9)",
            ));
        }
        let delta = i32::try_from(increment)
            .map_err(|_| H2Error::flow_control("window increment too large"))?;
        if let Some(stream) = self.streams.get_mut(stream_id) {
            #[cfg(feature = "http2-streaming")]
            if stream.deferred_recv_bytes().is_some() {
                return Err(H2Error::stream(
                    stream_id,
                    ErrorCode::ProtocolError,
                    "use release_stream_receive_capacity for deferred receive credit",
                ));
            }
            stream.update_recv_window(delta)?;
        } else {
            // Stream already closed/pruned — skip the WINDOW_UPDATE to avoid
            // sending it for a stream the peer may consider idle (protocol error).
            return Ok(());
        }
        self.pending_ops.push_back(PendingOp::WindowUpdate {
            stream_id,
            increment,
        });
        Ok(())
    }

    /// Prune closed streams.
    pub fn prune_closed_streams(&mut self) {
        self.prune_closed_streams_without_pending_frames();
    }
}

/// Received frame event.
#[derive(Debug)]
#[allow(missing_docs)]
pub enum ReceivedFrame {
    /// Received headers.
    Headers {
        stream_id: u32,
        headers: Vec<Header>,
        end_stream: bool,
    },
    /// Received PUSH_PROMISE.
    PushPromise {
        stream_id: u32,
        promised_stream_id: u32,
        headers: Vec<Header>,
    },
    /// Received data.
    Data {
        stream_id: u32,
        data: Bytes,
        end_stream: bool,
    },
    /// Stream was reset.
    Reset {
        stream_id: u32,
        error_code: ErrorCode,
    },
    /// Connection is closing.
    GoAway {
        last_stream_id: u32,
        error_code: ErrorCode,
        debug_data: Bytes,
    },
}

/// RFC 9113 §8.3 / §8.3.1 / §8.3.2 pseudo-header structural validation
/// for an HPACK-decoded header block.
///
/// Returns `Err(reason)` on any malformed shape so the caller can map it
/// to `ErrorCode::ProtocolError`. The first failure short-circuits.
///
/// **What this validates** (the §8.3 structural rules):
///
/// 1. **Sequencing**: every pseudo-header (a header whose name starts
///    with `:`) MUST appear *before* any regular header. Once a
///    regular header is seen, encountering a pseudo-header is malformed
///    (RFC 9113 §8.3, last paragraph).
/// 2. **No duplicates**: any given pseudo-header MUST appear at most
///    once (RFC 9113 §8.3.1, §8.3.2). HPACK can compress repeats but
///    the validation runs on the decoded list, so duplicates are
///    rejected.
/// 3. **No unknown pseudo-headers**: only `:method`, `:scheme`,
///    `:path`, `:authority`, `:status`, `:protocol` (the last for
///    extended CONNECT, RFC 8441) are defined. Anything else with a
///    leading `:` is malformed (RFC 9113 §8.3).
/// 4. **Direction-specific required/forbidden sets**:
///    - **request** (`is_request == true`, server receiving HEADERS):
///      MUST have `:method`. Non-CONNECT requests MUST also have
///      `:scheme` and `:path`. CONNECT requests MUST have `:authority`
///      and MUST NOT have `:scheme` or `:path` (RFC 9113 §8.5). Must
///      NOT have `:status`.
///    - **response** (`is_request == false`, client receiving HEADERS):
///      MUST have `:status` and MUST NOT have `:method`/`:scheme`/
///      `:path`/`:authority`/`:protocol` (RFC 9113 §8.3.2).
/// 5. **Regular header name lower-case**: regular header names MUST
///    NOT contain uppercase ASCII (RFC 9113 §8.2.1). Pseudo-headers
///    are exempt.
///
/// **What this does NOT validate** (deeper §8.3.1 value-syntax checks
/// — path-form, scheme syntax, authority form, status range, method
/// token, header-value byte set): those are the depth implemented in
/// `crate::http::h3_native::validate_request_pseudo_headers_with_settings`
/// and represent a follow-up. The structural rules above are the ones
/// flagged by the bead and are the highest-value subset because they
/// catch the entire class of confusion attacks where a peer smuggles
/// a `:method`/`:authority`/`:status` *after* a regular header to bypass
/// upstream filters that only inspect the first header pair.
fn validate_h2_pseudo_headers(
    headers: &[Header],
    is_request: bool,
    is_trailers: bool,
) -> Result<(), &'static str> {
    // br-asupersync-0eyf7t — RFC 9113 §8.1: "Trailer fields MUST NOT
    // include pseudo-header fields (Section 8.3)". Reject any
    // pseudo-header in a trailers block before the rest of the
    // structural validation runs. Regular-header validations
    // (lowercase names per §8.2.1, connection-specific header ban
    // per §8.2.2) still apply and are run below.
    if is_trailers {
        for h in headers {
            let name: &[u8] = h.name.as_bytes();
            if name.is_empty() {
                return Err("empty header name");
            }
            if name.first().copied() == Some(b':') {
                return Err("trailers section MUST NOT contain pseudo-header fields \
                     (RFC 9113 §8.1)");
            }
            if name.iter().any(|b| b.is_ascii_uppercase()) {
                return Err(
                    "regular header field name in trailers contains uppercase ASCII \
                     (RFC 9113 §8.2.1 violation)",
                );
            }
            // RFC 9113 §8.2.1: field values MUST NOT start or end with SP or HTAB.
            if h.value.starts_with([' ', '\t']) || h.value.ends_with([' ', '\t']) {
                return Err("trailer field value has leading or trailing whitespace \
                     (RFC 9113 §8.2.1 violation)");
            }
            match name {
                b"connection" | b"keep-alive" | b"proxy-connection" | b"transfer-encoding"
                | b"upgrade" => {
                    return Err(
                        "connection-specific header field forbidden in HTTP/2 trailers \
                         (RFC 9113 §8.2.2)",
                    );
                }
                b"te" if h.value.as_bytes() != b"trailers" => {
                    return Err("te header field MUST have value \"trailers\" in HTTP/2 \
                         (RFC 9113 §8.2.2)");
                }
                _ => {}
            }
        }
        return Ok(());
    }

    let mut seen_regular = false;
    let mut seen_method = false;
    let mut seen_scheme = false;
    let mut seen_path = false;
    let mut seen_authority = false;
    let mut seen_status = false;
    let mut seen_protocol = false;
    let mut method_value: Option<&[u8]> = None;

    for h in headers {
        let name: &[u8] = h.name.as_bytes();
        if name.is_empty() {
            return Err("empty header name");
        }
        // RFC 9113 §8.2.1: field values MUST NOT start or end with SP or HTAB.
        if h.value.starts_with([' ', '\t']) || h.value.ends_with([' ', '\t']) {
            return Err(
                "header field value has leading or trailing whitespace \
                 (RFC 9113 §8.2.1 violation)",
            );
        }
        if name.first().copied() == Some(b':') {
            // Pseudo-header.
            if seen_regular {
                return Err("pseudo-header field appears after a regular header field \
                     (RFC 9113 §8.3 — header-block ordering violation)");
            }
            match name {
                b":method" => {
                    if seen_method {
                        return Err("duplicate :method pseudo-header");
                    }
                    seen_method = true;
                    method_value = Some(h.value.as_bytes());
                }
                b":scheme" => {
                    if seen_scheme {
                        return Err("duplicate :scheme pseudo-header");
                    }
                    seen_scheme = true;
                }
                b":path" => {
                    if seen_path {
                        return Err("duplicate :path pseudo-header");
                    }
                    seen_path = true;
                    if h.value.is_empty() {
                        return Err("empty :path pseudo-header");
                    }
                }
                b":authority" => {
                    if seen_authority {
                        return Err("duplicate :authority pseudo-header");
                    }
                    seen_authority = true;
                }
                b":status" => {
                    if seen_status {
                        return Err("duplicate :status pseudo-header");
                    }
                    seen_status = true;
                }
                b":protocol" => {
                    if seen_protocol {
                        return Err("duplicate :protocol pseudo-header");
                    }
                    seen_protocol = true;
                }
                _ => {
                    return Err("unknown pseudo-header field \
                         (RFC 9113 §8.3 — only :method/:scheme/:path/:authority/:status \
                         and :protocol for extended CONNECT are defined)");
                }
            }
        } else {
            // Regular header. Once we've seen one, no further pseudo-
            // headers may appear.
            seen_regular = true;
            // RFC 9113 §8.2.1: regular header names MUST NOT contain
            // uppercase ASCII characters.
            if name.iter().any(|b| b.is_ascii_uppercase()) {
                return Err("regular header field name contains uppercase ASCII \
                     (RFC 9113 §8.2.1 violation)");
            }
            // br-asupersync-rmfjui — RFC 9113 §8.2.2: connection-
            // specific header fields MUST NOT be transmitted in
            // HTTP/2; any message containing them is malformed and
            // MUST be treated as a stream error of PROTOCOL_ERROR.
            // The exception is `te`, whose name is permitted but
            // whose value MUST be exactly the token "trailers".
            match name {
                b"connection" | b"keep-alive" | b"proxy-connection" | b"transfer-encoding"
                | b"upgrade" => {
                    return Err("connection-specific header field forbidden in HTTP/2 \
                         (RFC 9113 §8.2.2)");
                }
                b"te" if h.value.as_bytes() != b"trailers" => {
                    return Err("te header field MUST have value \"trailers\" in HTTP/2 \
                         (RFC 9113 §8.2.2)");
                }
                _ => {}
            }
        }
    }

    // Direction-specific required/forbidden checks.
    if is_request {
        if seen_status {
            return Err("request must not include :status pseudo-header");
        }
        if !seen_method {
            return Err("request missing required :method pseudo-header");
        }
        let is_connect = method_value == Some(b"CONNECT");
        if is_connect {
            if !seen_authority {
                return Err("CONNECT request missing required :authority pseudo-header");
            }
            // RFC 9113 §8.5: CONNECT requests MUST NOT include :scheme
            // or :path. Extended CONNECT (RFC 8441 / :protocol) is
            // the documented exception, allowed only when negotiated
            // via SETTINGS_ENABLE_CONNECT_PROTOCOL — that negotiation
            // is not represented in the structural validation here,
            // so we follow the conservative §8.5 rule. A future
            // pass that wires SETTINGS_ENABLE_CONNECT_PROTOCOL
            // through to this validator should relax this branch
            // (and align with h3_native's
            // `validate_request_pseudo_headers_with_settings`).
            if seen_protocol && (seen_scheme || seen_path) {
                // Tolerate :protocol presence for the extended-CONNECT
                // case (the deeper :protocol value validation lives
                // in the follow-up). Fall through.
            } else if seen_scheme || seen_path {
                return Err("CONNECT request must not include :scheme or :path \
                     (RFC 9113 §8.5)");
            }
        } else {
            if !seen_scheme {
                return Err("non-CONNECT request missing required :scheme pseudo-header");
            }
            if !seen_path {
                return Err("non-CONNECT request missing required :path pseudo-header");
            }
            if seen_protocol {
                return Err(
                    ":protocol pseudo-header is only valid for extended CONNECT \
                     (RFC 8441) and was sent on a non-CONNECT request",
                );
            }
        }
    } else {
        // Response.
        if !seen_status {
            return Err("response missing required :status pseudo-header");
        }
        if seen_method || seen_scheme || seen_path || seen_authority || seen_protocol {
            return Err("response must not include request pseudo-headers \
                 (:method/:scheme/:path/:authority/:protocol — RFC 9113 §8.3.2)");
        }
    }

    Ok(())
}

#[cfg(test)]
#[path = "connection_inline_tests.rs"]
mod tests;
