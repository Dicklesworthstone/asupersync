//! HTTP/2 connection management.
//!
//! Manages HTTP/2 connection state, settings negotiation, and frame processing.

use std::collections::VecDeque;
use std::time::Instant;

use crate::bytes::{Bytes, BytesMut};
use crate::codec::{Decoder, Encoder};

use super::error::{ErrorCode, H2Error};
use super::frame::{
    parse_frame, ContinuationFrame, DataFrame, Frame, FrameHeader, GoAwayFrame, HeadersFrame,
    PingFrame, PushPromiseFrame, RstStreamFrame, Setting, SettingsFrame, WindowUpdateFrame,
    FRAME_HEADER_SIZE,
};
use super::hpack::{self, Header};
use super::settings::Settings;
use super::stream::{Stream, StreamState, StreamStore};

/// Connection preface that clients must send.
pub const CLIENT_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Default connection-level window size.
pub const DEFAULT_CONNECTION_WINDOW_SIZE: i32 = 65535;

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
}

impl FrameCodec {
    /// Create a new frame codec.
    #[must_use]
    pub fn new() -> Self {
        Self {
            max_frame_size: super::frame::DEFAULT_MAX_FRAME_SIZE,
            partial_header: None,
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
        // First, try to parse the header if we don't have one
        let header = if let Some(header) = self.partial_header.take() {
            header
        } else {
            if src.len() < FRAME_HEADER_SIZE {
                return Ok(None);
            }
            FrameHeader::parse(src)?
        };

        // Validate frame size
        if header.length > self.max_frame_size {
            return Err(H2Error::frame_size(format!(
                "frame too large: {} > {}",
                header.length, self.max_frame_size
            )));
        }

        // Check if we have the full payload
        let payload_len = header.length as usize;
        if src.len() < payload_len {
            self.partial_header = Some(header);
            return Ok(None);
        }

        // Extract payload and parse frame
        let payload = src.split_to(payload_len).freeze();
        let frame = parse_frame(&header, payload)?;
        Ok(Some(frame))
    }
}

impl<T: AsRef<Frame>> Encoder<T> for FrameCodec {
    type Error = H2Error;

    fn encode(&mut self, item: T, dst: &mut BytesMut) -> Result<(), Self::Error> {
        item.as_ref().encode(dst);
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

#[derive(Debug, Clone, Copy)]
struct PushPromiseAccumulator {
    associated_stream_id: u32,
    promised_stream_id: u32,
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
    /// Last stream ID processed.
    last_stream_id: u32,
    /// GOAWAY received.
    goaway_received: bool,
    /// GOAWAY sent.
    goaway_sent: bool,
    /// Pending operations to process.
    pending_ops: VecDeque<PendingOp>,
    /// Stream ID being continued (for CONTINUATION frames).
    continuation_stream_id: Option<u32>,
    /// When the current continuation sequence started.
    ///
    /// Set when a HEADERS or PUSH_PROMISE frame is received without END_HEADERS.
    /// Used to enforce timeout on incomplete CONTINUATION sequences.
    continuation_started_at: Option<Instant>,
    /// Pending PUSH_PROMISE header block, if any.
    pending_push_promise: Option<PushPromiseAccumulator>,
}

impl Connection {
    /// Create a new client connection.
    #[must_use]
    pub fn client(settings: Settings) -> Self {
        let max_header_list_size = settings.max_header_list_size;
        let initial_window = settings.initial_window_size;
        let mut decoder = hpack::Decoder::new();
        decoder.set_max_header_list_size(max_header_list_size as usize);
        Self {
            state: ConnectionState::Handshaking,
            is_client: true,
            local_settings: settings,
            remote_settings: Settings::default(),
            received_settings: false,
            streams: StreamStore::new(true, initial_window, max_header_list_size),
            hpack_encoder: hpack::Encoder::new(),
            hpack_decoder: decoder,
            send_window: DEFAULT_CONNECTION_WINDOW_SIZE,
            recv_window: DEFAULT_CONNECTION_WINDOW_SIZE,
            last_stream_id: 0,
            goaway_received: false,
            goaway_sent: false,
            pending_ops: VecDeque::new(),
            continuation_stream_id: None,
            continuation_started_at: None,
            pending_push_promise: None,
        }
    }

    /// Create a new server connection.
    #[must_use]
    pub fn server(settings: Settings) -> Self {
        let max_header_list_size = settings.max_header_list_size;
        let initial_window = settings.initial_window_size;
        let mut decoder = hpack::Decoder::new();
        decoder.set_max_header_list_size(max_header_list_size as usize);
        Self {
            state: ConnectionState::Handshaking,
            is_client: false,
            local_settings: settings,
            remote_settings: Settings::default(),
            received_settings: false,
            streams: StreamStore::new(false, initial_window, max_header_list_size),
            hpack_encoder: hpack::Encoder::new(),
            hpack_decoder: decoder,
            send_window: DEFAULT_CONNECTION_WINDOW_SIZE,
            recv_window: DEFAULT_CONNECTION_WINDOW_SIZE,
            last_stream_id: 0,
            goaway_received: false,
            goaway_sent: false,
            pending_ops: VecDeque::new(),
            continuation_stream_id: None,
            continuation_started_at: None,
            pending_push_promise: None,
        }
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

    /// Get the connection-level receive window.
    #[must_use]
    pub fn recv_window(&self) -> i32 {
        self.recv_window
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

    /// Check if GOAWAY has been received.
    #[must_use]
    pub fn goaway_received(&self) -> bool {
        self.goaway_received
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
            let elapsed = started_at.elapsed();

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

    /// Queue initial settings frame.
    pub fn queue_initial_settings(&mut self) {
        let settings = SettingsFrame::new(self.local_settings.to_settings_minimal());
        self.pending_ops.push_back(PendingOp::Settings(settings));
    }

    /// Open a new stream and send headers.
    pub fn open_stream(&mut self, headers: Vec<Header>, end_stream: bool) -> Result<u32, H2Error> {
        if self.goaway_received {
            return Err(H2Error::protocol("cannot open new streams after GOAWAY"));
        }

        let stream_id = self.streams.allocate_stream_id()?;
        let stream = self.streams.get_mut(stream_id).unwrap();
        stream.send_headers(end_stream)?;

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

        self.pending_ops.push_back(PendingOp::Headers {
            stream_id,
            headers,
            end_stream,
        });

        Ok(())
    }

    /// Reset a stream.
    pub fn reset_stream(&mut self, stream_id: u32, error_code: ErrorCode) {
        if let Some(stream) = self.streams.get_mut(stream_id) {
            stream.reset(error_code);
        }
        self.pending_ops.push_back(PendingOp::RstStream {
            stream_id,
            error_code,
        });
    }

    /// Send GOAWAY and start graceful shutdown.
    pub fn goaway(&mut self, error_code: ErrorCode, debug_data: Bytes) {
        if !self.goaway_sent {
            self.goaway_sent = true;
            self.state = ConnectionState::Closing;
            self.pending_ops.push_back(PendingOp::GoAway {
                last_stream_id: self.last_stream_id,
                error_code,
                debug_data,
            });
        }
    }

    /// Process an incoming frame.
    pub fn process_frame(&mut self, frame: Frame) -> Result<Option<ReceivedFrame>, H2Error> {
        // Check continuation timeout before processing
        self.check_continuation_timeout()?;

        // Check for CONTINUATION requirement
        if let Some(expected_stream) = self.continuation_stream_id {
            match &frame {
                Frame::Continuation(cont) if cont.stream_id == expected_stream => {
                    // Valid continuation, process below
                }
                _ => {
                    return Err(H2Error::protocol("expected CONTINUATION frame"));
                }
            }
        }

        match frame {
            Frame::Data(f) => self.process_data(f),
            Frame::Headers(f) => self.process_headers(f),
            Frame::Priority(f) => {
                if let Some(stream) = self.streams.get_mut(f.stream_id) {
                    stream.set_priority(f.priority);
                }
                Ok(None)
            }
            Frame::RstStream(f) => Ok(Some(self.process_rst_stream(f))),
            Frame::Settings(f) => self.process_settings(&f),
            Frame::PushPromise(f) => self.process_push_promise(&f),
            Frame::Ping(f) => Ok(self.process_ping(f)),
            Frame::GoAway(f) => Ok(Some(self.process_goaway(f))),
            Frame::WindowUpdate(f) => self.process_window_update(f),
            Frame::Continuation(f) => self.process_continuation(f),
        }
    }

    /// Process DATA frame.
    fn process_data(&mut self, frame: DataFrame) -> Result<Option<ReceivedFrame>, H2Error> {
        let stream = self.streams.get_or_create(frame.stream_id)?;
        let payload_len =
            u32::try_from(frame.data.len()).map_err(|_| H2Error::frame_size("data too large"))?;
        stream.recv_data(payload_len, frame.end_stream)?;

        // Auto stream-level WINDOW_UPDATE when recv window drops below 50%.
        if let Some(increment) = stream.auto_window_update_increment() {
            // Cannot call send_stream_window_update while stream is borrowed,
            // so we update the stream's recv_window and queue the op directly.
            stream.update_recv_window(
                i32::try_from(increment)
                    .map_err(|_| H2Error::flow_control("stream window increment too large"))?,
            )?;
            self.pending_ops.push_back(PendingOp::WindowUpdate {
                stream_id: frame.stream_id,
                increment,
            });
        }

        // Update connection-level window
        let window_delta = i32::try_from(payload_len)
            .map_err(|_| H2Error::flow_control("data too large for window"))?;
        self.recv_window -= window_delta;

        let low_watermark = DEFAULT_CONNECTION_WINDOW_SIZE / 2;
        if self.recv_window < low_watermark {
            let increment = i64::from(DEFAULT_CONNECTION_WINDOW_SIZE) - i64::from(self.recv_window);
            let increment = u32::try_from(increment)
                .map_err(|_| H2Error::flow_control("window increment too large"))?;
            self.send_connection_window_update(increment)?;
        }

        Ok(Some(ReceivedFrame::Data {
            stream_id: frame.stream_id,
            data: frame.data,
            end_stream: frame.end_stream,
        }))
    }

    /// Process HEADERS frame.
    fn process_headers(&mut self, frame: HeadersFrame) -> Result<Option<ReceivedFrame>, H2Error> {
        let stream = self.streams.get_or_create(frame.stream_id)?;
        stream.recv_headers(frame.end_stream, frame.end_headers)?;

        if let Some(priority) = frame.priority {
            stream.set_priority(priority);
        }

        stream.add_header_fragment(frame.header_block)?;

        if frame.end_headers {
            self.continuation_stream_id = None;
            self.continuation_started_at = None;
            self.decode_headers(frame.stream_id, frame.end_stream)
        } else {
            self.continuation_stream_id = Some(frame.stream_id);
            self.continuation_started_at = Some(Instant::now());
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
                promised.add_header_fragment(frame.header_block)?;

                if frame.end_headers {
                    self.pending_push_promise = None;
                    self.continuation_stream_id = None;
                    self.continuation_started_at = None;
                    return self.decode_push_promise(frame.stream_id, promised_stream_id);
                }

                return Ok(None);
            }
        }

        let stream = self
            .streams
            .get_mut(frame.stream_id)
            .ok_or_else(|| H2Error::protocol("CONTINUATION for unknown stream"))?;

        stream.recv_continuation(frame.header_block, frame.end_headers)?;

        if frame.end_headers {
            self.continuation_stream_id = None;
            self.continuation_started_at = None;
            // Get end_stream from stream state
            let end_stream = matches!(
                stream.state(),
                StreamState::HalfClosedRemote | StreamState::Closed
            );
            self.decode_headers(frame.stream_id, end_stream)
        } else {
            Ok(None)
        }
    }

    /// Decode accumulated headers for a stream.
    fn decode_headers(
        &mut self,
        stream_id: u32,
        end_stream: bool,
    ) -> Result<Option<ReceivedFrame>, H2Error> {
        let stream = self.streams.get_mut(stream_id).unwrap();
        let fragments = stream.take_header_fragments();

        // Concatenate all fragments
        let total_len: usize = fragments.iter().map(Bytes::len).sum();
        let max_fragment_size =
            Stream::max_header_fragment_size_for(self.local_settings.max_header_list_size);
        if total_len > max_fragment_size {
            return Err(H2Error::stream(
                stream_id,
                ErrorCode::EnhanceYourCalm,
                "accumulated header fragments too large",
            ));
        }
        let mut combined = BytesMut::with_capacity(total_len);
        for fragment in fragments {
            combined.extend_from_slice(&fragment);
        }

        // Decode headers
        let mut src = combined.freeze();
        let headers = self.hpack_decoder.decode(&mut src)?;

        Ok(Some(ReceivedFrame::Headers {
            stream_id,
            headers,
            end_stream,
        }))
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
            return Err(H2Error::stream(
                promised_stream_id,
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

        Ok(Some(ReceivedFrame::PushPromise {
            stream_id: associated_stream_id,
            promised_stream_id,
            headers,
        }))
    }

    /// Process RST_STREAM frame.
    fn process_rst_stream(&mut self, frame: RstStreamFrame) -> ReceivedFrame {
        if let Some(stream) = self.streams.get_mut(frame.stream_id) {
            stream.reset(frame.error_code);
        }

        ReceivedFrame::Reset {
            stream_id: frame.stream_id,
            error_code: frame.error_code,
        }
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

        // Apply settings
        for setting in &frame.settings {
            self.remote_settings.apply(*setting)?;

            // Handle specific settings
            match setting {
                Setting::InitialWindowSize(size) => {
                    self.streams.set_initial_window_size(*size)?;
                }
                Setting::HeaderTableSize(size) => {
                    self.hpack_encoder.set_max_table_size(*size as usize);
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

        let assoc_state = match self.streams.get(frame.stream_id) {
            Some(stream) => stream.state(),
            None => {
                return Err(H2Error::stream(
                    frame.stream_id,
                    ErrorCode::ProtocolError,
                    "PUSH_PROMISE on unknown stream",
                ));
            }
        };
        if assoc_state.is_closed() {
            return Err(H2Error::stream(
                frame.stream_id,
                ErrorCode::StreamClosed,
                "PUSH_PROMISE on closed stream",
            ));
        }

        let max_concurrent = self.local_settings.max_concurrent_streams;
        if self.streams.active_count() as u32 >= max_concurrent {
            return Err(H2Error::stream(
                frame.stream_id,
                ErrorCode::RefusedStream,
                "max concurrent streams exceeded",
            ));
        }

        let promised_stream_id = frame.promised_stream_id;
        let promised_stream = self.streams.reserve_remote_stream(promised_stream_id)?;
        promised_stream.add_header_fragment(frame.header_block.clone())?;

        if frame.end_headers {
            self.continuation_stream_id = None;
            self.continuation_started_at = None;
            self.decode_push_promise(frame.stream_id, promised_stream_id)
        } else {
            self.pending_push_promise = Some(PushPromiseAccumulator {
                associated_stream_id: frame.stream_id,
                promised_stream_id,
            });
            self.continuation_stream_id = Some(frame.stream_id);
            self.continuation_started_at = Some(Instant::now());
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

        // Reset streams that weren't processed
        for stream_id in self.streams.active_stream_ids() {
            if stream_id > frame.last_stream_id {
                if let Some(stream) = self.streams.get_mut(stream_id) {
                    stream.reset(ErrorCode::RefusedStream);
                }
            }
        }

        ReceivedFrame::GoAway {
            last_stream_id: frame.last_stream_id,
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
        // RFC 9113 §6.9.1: increment of 0 MUST be treated as a connection
        // error (stream 0) or stream error of type PROTOCOL_ERROR.
        if increment == 0 {
            return Err(H2Error::protocol("WINDOW_UPDATE with zero increment"));
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

        for _ in 0..pending_len {
            let op = self.pending_ops.pop_front()?;

            match op {
                PendingOp::Settings(frame) => return Some(Frame::Settings(frame)),
                PendingOp::SettingsAck => return Some(Frame::Settings(SettingsFrame::ack())),
                PendingOp::PingAck(data) => return Some(Frame::Ping(PingFrame::ack(data))),
                PendingOp::WindowUpdate {
                    stream_id,
                    increment,
                } => {
                    return Some(Frame::WindowUpdate(WindowUpdateFrame::new(
                        stream_id, increment,
                    )));
                }
                PendingOp::Headers {
                    stream_id,
                    headers,
                    end_stream,
                } => {
                    // Encode headers
                    let mut encoded = BytesMut::new();
                    self.hpack_encoder.encode(&headers, &mut encoded);
                    let encoded = encoded.freeze();

                    let max_frame_size = self.remote_settings.max_frame_size as usize;

                    if encoded.len() <= max_frame_size {
                        // Fits in a single HEADERS frame
                        return Some(Frame::Headers(HeadersFrame::new(
                            stream_id, encoded, end_stream, true, // end_headers
                        )));
                    }

                    // Need CONTINUATION frames - split the header block
                    let first_chunk = encoded.slice(..max_frame_size);
                    let remaining = encoded.slice(max_frame_size..);

                    // Queue CONTINUATION frames for remaining data.
                    // Use push_back to preserve chunk ordering (push_front
                    // would reverse them, corrupting HPACK state).
                    let mut offset = 0;
                    while offset < remaining.len() {
                        let chunk_end = (offset + max_frame_size).min(remaining.len());
                        let chunk = remaining.slice(offset..chunk_end);
                        let is_last = chunk_end == remaining.len();
                        self.pending_ops.push_back(PendingOp::Continuation {
                            stream_id,
                            header_block: chunk,
                            end_headers: is_last,
                        });
                        offset = chunk_end;
                    }

                    return Some(Frame::Headers(HeadersFrame::new(
                        stream_id,
                        first_chunk,
                        end_stream,
                        false, // end_headers = false, CONTINUATION follows
                    )));
                }
                PendingOp::Continuation {
                    stream_id,
                    header_block,
                    end_headers,
                } => {
                    return Some(Frame::Continuation(ContinuationFrame {
                        stream_id,
                        header_block,
                        end_headers,
                    }));
                }
                PendingOp::Data {
                    stream_id,
                    data,
                    end_stream,
                } => {
                    // Determine the maximum sendable bytes from flow control windows and max_frame_size.
                    let conn_avail = self.send_window.max(0).cast_unsigned();
                    let stream_avail = self
                        .streams
                        .get(stream_id)
                        .map_or(0, |s| s.send_window().max(0).cast_unsigned());
                    let frame_size_limit = self.remote_settings.max_frame_size;
                    let max_send = conn_avail.min(stream_avail).min(frame_size_limit) as usize;

                    if max_send == 0 && !data.is_empty() {
                        // No send window available; re-queue for later.
                        self.pending_ops.push_back(PendingOp::Data {
                            stream_id,
                            data,
                            end_stream,
                        });
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
                        self.pending_ops.push_front(PendingOp::Data {
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
                    }

                    return Some(Frame::Data(DataFrame::new(
                        stream_id,
                        to_send,
                        actually_end,
                    )));
                }
                PendingOp::RstStream {
                    stream_id,
                    error_code,
                } => return Some(Frame::RstStream(RstStreamFrame::new(stream_id, error_code))),
                PendingOp::GoAway {
                    last_stream_id,
                    error_code,
                    debug_data,
                } => {
                    let mut frame = GoAwayFrame::new(last_stream_id, error_code);
                    frame.debug_data = debug_data;
                    return Some(Frame::GoAway(frame));
                }
            }
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

    /// Send a WINDOW_UPDATE for connection-level flow control.
    pub fn send_connection_window_update(&mut self, increment: u32) -> Result<(), H2Error> {
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
    pub fn send_stream_window_update(
        &mut self,
        stream_id: u32,
        increment: u32,
    ) -> Result<(), H2Error> {
        let delta = i32::try_from(increment)
            .map_err(|_| H2Error::flow_control("window increment too large"))?;
        if let Some(stream) = self.streams.get_mut(stream_id) {
            stream.update_recv_window(delta)?;
        }
        self.pending_ops.push_back(PendingOp::WindowUpdate {
            stream_id,
            increment,
        });
        Ok(())
    }

    /// Prune closed streams.
    pub fn prune_closed_streams(&mut self) {
        self.streams.prune_closed();
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytes::Bytes;
    use crate::http::h2::settings;

    #[test]
    fn data_frame_triggers_connection_window_update_on_low_watermark() {
        let mut conn = Connection::server(Settings::default());
        let payload_len = (DEFAULT_CONNECTION_WINDOW_SIZE / 2) + 2;
        let payload_len_usize = usize::try_from(payload_len).expect("payload_len non-negative");
        let payload_len_u32 = u32::try_from(payload_len).expect("payload_len fits u32");
        let data = Bytes::from(vec![0_u8; payload_len_usize]);
        let headers = Frame::Headers(HeadersFrame::new(1, Bytes::new(), false, true));
        let frame = Frame::Data(DataFrame::new(1, data, false));

        conn.process_frame(headers).expect("process headers frame");
        conn.process_frame(frame).expect("process data frame");

        assert!(conn.has_pending_frames(), "expected WINDOW_UPDATE(s)");
        // Both stream-level and connection-level WINDOW_UPDATEs may be queued.
        let mut found_connection_update = false;
        while let Some(pending) = conn.next_frame() {
            if let Frame::WindowUpdate(update) = pending {
                if update.stream_id == 0 {
                    assert_eq!(update.increment, payload_len_u32);
                    found_connection_update = true;
                }
            }
        }
        assert!(
            found_connection_update,
            "expected connection-level WINDOW_UPDATE"
        );
    }

    #[test]
    fn test_frame_codec_decode() {
        let mut codec = FrameCodec::new();

        // Create a PING frame
        let frame = PingFrame::new([1, 2, 3, 4, 5, 6, 7, 8]);
        let mut buf = BytesMut::new();
        Frame::Ping(frame).encode(&mut buf);

        // Decode it
        let decoded = codec.decode(&mut buf).unwrap().unwrap();
        match decoded {
            Frame::Ping(ping) => {
                assert_eq!(ping.opaque_data, [1, 2, 3, 4, 5, 6, 7, 8]);
                assert!(!ping.ack);
            }
            _ => panic!("expected PING frame"),
        }
    }

    #[test]
    fn test_connection_client_settings() {
        let mut conn = Connection::client(Settings::client());
        conn.queue_initial_settings();

        assert!(conn.has_pending_frames());
        let frame = conn.next_frame().unwrap();
        match frame {
            Frame::Settings(settings) => {
                assert!(!settings.ack);
            }
            _ => panic!("expected SETTINGS frame"),
        }
    }

    #[test]
    fn test_connection_process_settings() {
        let mut conn = Connection::client(Settings::client());

        // Process server settings
        let settings = SettingsFrame::new(vec![
            Setting::MaxConcurrentStreams(100),
            Setting::InitialWindowSize(32768),
        ]);
        conn.process_frame(Frame::Settings(settings)).unwrap();

        // Should have queued ACK
        assert!(conn.has_pending_frames());
        let frame = conn.next_frame().unwrap();
        match frame {
            Frame::Settings(settings) => {
                assert!(settings.ack);
            }
            _ => panic!("expected SETTINGS ACK"),
        }

        // Remote settings should be updated
        assert_eq!(conn.remote_settings().max_concurrent_streams, 100);
        assert_eq!(conn.remote_settings().initial_window_size, 32768);
    }

    #[test]
    fn test_connection_process_ping() {
        let mut conn = Connection::client(Settings::client());

        let ping = PingFrame::new([1, 2, 3, 4, 5, 6, 7, 8]);
        conn.process_frame(Frame::Ping(ping)).unwrap();

        // Should have queued PING ACK
        let frame = conn.next_frame().unwrap();
        match frame {
            Frame::Ping(ping) => {
                assert!(ping.ack);
                assert_eq!(ping.opaque_data, [1, 2, 3, 4, 5, 6, 7, 8]);
            }
            _ => panic!("expected PING ACK"),
        }
    }

    #[test]
    fn test_connection_open_stream() {
        let mut conn = Connection::client(Settings::client());
        conn.state = ConnectionState::Open;

        let headers = vec![
            Header::new(":method", "GET"),
            Header::new(":path", "/"),
            Header::new(":scheme", "https"),
            Header::new(":authority", "example.com"),
        ];

        let stream_id = conn.open_stream(headers, false).unwrap();
        assert_eq!(stream_id, 1);

        // Should have queued HEADERS frame
        let frame = conn.next_frame().unwrap();
        match frame {
            Frame::Headers(h) => {
                assert_eq!(h.stream_id, 1);
                assert!(!h.end_stream);
                assert!(h.end_headers);
            }
            _ => panic!("expected HEADERS frame"),
        }
    }

    #[test]
    fn data_frame_triggers_stream_window_update_on_low_watermark() {
        let mut conn = Connection::server(Settings::default());
        // Open a stream via headers.
        let headers = Frame::Headers(HeadersFrame::new(1, Bytes::new(), false, true));
        conn.process_frame(headers).expect("process headers");

        let initial_window = settings::DEFAULT_INITIAL_WINDOW_SIZE;
        // Send data that crosses the 50% threshold for the *stream*.
        let payload_len = initial_window / 2 + 2;
        let data = Bytes::from(vec![0_u8; payload_len as usize]);
        let frame = Frame::Data(DataFrame::new(1, data, false));
        conn.process_frame(frame).expect("process data");

        // Drain pending frames; look for a stream-level WINDOW_UPDATE (stream_id != 0).
        let mut found_stream_update = false;
        while let Some(f) = conn.next_frame() {
            if let Frame::WindowUpdate(wu) = f {
                if wu.stream_id == 1 {
                    found_stream_update = true;
                    assert_eq!(wu.increment, payload_len);
                }
            }
        }
        assert!(
            found_stream_update,
            "expected stream-level WINDOW_UPDATE for stream 1"
        );
    }

    #[test]
    fn data_frame_no_stream_window_update_when_above_watermark() {
        let mut conn = Connection::server(Settings::default());
        let headers = Frame::Headers(HeadersFrame::new(1, Bytes::new(), false, true));
        conn.process_frame(headers).expect("process headers");

        // Small payload: stays above the watermark.
        let data = Bytes::from(vec![0_u8; 100]);
        let frame = Frame::Data(DataFrame::new(1, data, false));
        conn.process_frame(frame).expect("process data");

        // No stream-level WINDOW_UPDATE should be queued.
        while let Some(f) = conn.next_frame() {
            if let Frame::WindowUpdate(wu) = f {
                assert_ne!(wu.stream_id, 1, "unexpected stream-level WINDOW_UPDATE");
            }
        }
    }

    #[test]
    fn send_data_respects_send_window() {
        let mut conn = Connection::client(Settings::client());
        conn.state = ConnectionState::Open;

        let headers = vec![
            Header::new(":method", "POST"),
            Header::new(":path", "/upload"),
            Header::new(":scheme", "https"),
            Header::new(":authority", "example.com"),
        ];
        let stream_id = conn.open_stream(headers, false).unwrap();
        // Drain the HEADERS frame.
        let _ = conn.next_frame().unwrap();

        // Shrink the connection send window to a small value.
        // Default is 65535; reduce it so only 100 bytes can be sent.
        conn.send_window = 100;

        // Queue 300 bytes of data.
        let data = Bytes::from(vec![0xAB_u8; 300]);
        conn.send_data(stream_id, data, true).unwrap();

        // First frame: should be clamped to 100 bytes (connection window limit).
        let frame1 = conn.next_frame().expect("expected first DATA frame");
        match frame1 {
            Frame::Data(d) => {
                assert_eq!(d.data.len(), 100, "should be clamped to send window");
                assert!(!d.end_stream, "not the final chunk");
            }
            other => panic!("expected DATA frame, got {other:?}"),
        }

        // Connection window is now 0; next call should re-queue and return None
        // (since there's no other frame type pending, it recurses but data is re-queued).
        // Replenish the window so remaining data can flow.
        conn.send_window = 300;
        let frame2 = conn.next_frame().expect("expected second DATA frame");
        match frame2 {
            Frame::Data(d) => {
                assert_eq!(d.data.len(), 200, "remaining 200 bytes");
                assert!(d.end_stream, "final chunk should carry end_stream");
            }
            other => panic!("expected DATA frame, got {other:?}"),
        }

        assert!(!conn.has_pending_frames(), "all data should be sent");
    }

    #[test]
    fn send_data_respects_stream_send_window() {
        let mut conn = Connection::client(Settings::client());
        conn.state = ConnectionState::Open;

        let headers = vec![
            Header::new(":method", "POST"),
            Header::new(":path", "/"),
            Header::new(":scheme", "https"),
            Header::new(":authority", "example.com"),
        ];
        let stream_id = conn.open_stream(headers, false).unwrap();
        let _ = conn.next_frame().unwrap(); // drain HEADERS

        // Shrink the *stream* send window to 50 bytes (connection window stays large).
        conn.stream_mut(stream_id)
            .unwrap()
            .consume_send_window(65535 - 50);

        let data = Bytes::from(vec![0xCD_u8; 200]);
        conn.send_data(stream_id, data, true).unwrap();

        let frame1 = conn.next_frame().expect("expected first DATA frame");
        match frame1 {
            Frame::Data(d) => {
                assert_eq!(d.data.len(), 50, "clamped to stream send window");
                assert!(!d.end_stream);
            }
            other => panic!("expected DATA frame, got {other:?}"),
        }

        // Restore stream window and send remaining.
        conn.stream_mut(stream_id)
            .unwrap()
            .update_send_window(200)
            .unwrap();
        let frame2 = conn.next_frame().expect("expected second DATA frame");
        match frame2 {
            Frame::Data(d) => {
                assert_eq!(d.data.len(), 150);
                assert!(d.end_stream);
            }
            other => panic!("expected DATA frame, got {other:?}"),
        }
    }

    #[test]
    fn send_data_respects_max_frame_size() {
        let mut conn = Connection::client(Settings::client());
        conn.state = ConnectionState::Open;
        // Set a small max_frame_size for testing
        conn.remote_settings.max_frame_size = 100;

        let headers = vec![
            Header::new(":method", "POST"),
            Header::new(":path", "/"),
            Header::new(":scheme", "https"),
            Header::new(":authority", "example.com"),
        ];
        let stream_id = conn.open_stream(headers, false).unwrap();
        let _ = conn.next_frame().unwrap(); // drain HEADERS

        // Queue 300 bytes of data
        let data = Bytes::from(vec![0xEE_u8; 300]);
        conn.send_data(stream_id, data, true).unwrap();

        // First frame should be clamped to max_frame_size (100 bytes)
        let frame1 = conn.next_frame().expect("expected first DATA frame");
        match frame1 {
            Frame::Data(d) => {
                assert_eq!(d.data.len(), 100, "clamped to max_frame_size");
                assert!(!d.end_stream);
            }
            other => panic!("expected DATA frame, got {other:?}"),
        }

        // Second frame
        let frame2 = conn.next_frame().expect("expected second DATA frame");
        match frame2 {
            Frame::Data(d) => {
                assert_eq!(d.data.len(), 100);
                assert!(!d.end_stream);
            }
            other => panic!("expected DATA frame, got {other:?}"),
        }

        // Third frame (final)
        let frame3 = conn.next_frame().expect("expected third DATA frame");
        match frame3 {
            Frame::Data(d) => {
                assert_eq!(d.data.len(), 100);
                assert!(d.end_stream);
            }
            other => panic!("expected DATA frame, got {other:?}"),
        }

        assert!(!conn.has_pending_frames());
    }

    #[test]
    fn large_headers_use_continuation_frames() {
        let mut conn = Connection::client(Settings::client());
        conn.state = ConnectionState::Open;
        // Set a very small max_frame_size to force CONTINUATION
        conn.remote_settings.max_frame_size = 50;

        // Create headers that will encode to more than 50 bytes
        let mut headers = vec![
            Header::new(":method", "GET"),
            Header::new(":path", "/some/very/long/path/that/exceeds/frame/size"),
            Header::new(":scheme", "https"),
            Header::new(":authority", "example.com"),
        ];
        // Add more headers to ensure we exceed the limit
        for i in 0..10 {
            headers.push(Header::new(
                format!("x-custom-header-{i}"),
                format!("value-{i}"),
            ));
        }

        let stream_id = conn.open_stream(headers, true).unwrap();

        // First frame should be HEADERS with end_headers=false
        let frame1 = conn.next_frame().expect("expected HEADERS frame");
        match &frame1 {
            Frame::Headers(h) => {
                assert_eq!(h.stream_id, stream_id);
                assert!(h.end_stream);
                assert!(!h.end_headers, "should have CONTINUATION following");
                assert_eq!(h.header_block.len(), 50);
            }
            other => panic!("expected HEADERS frame, got {other:?}"),
        }

        // Subsequent frames should be CONTINUATION
        let mut continuation_count = 0;
        let mut last_end_headers = false;
        while let Some(frame) = conn.next_frame() {
            match frame {
                Frame::Continuation(c) => {
                    assert_eq!(c.stream_id, stream_id);
                    continuation_count += 1;
                    last_end_headers = c.end_headers;
                    if c.end_headers {
                        break;
                    }
                }
                other => panic!("expected CONTINUATION frame, got {other:?}"),
            }
        }

        assert!(
            continuation_count >= 1,
            "should have at least one CONTINUATION"
        );
        assert!(last_end_headers, "last frame should have end_headers=true");
    }

    #[test]
    fn push_promise_rejected_when_disabled() {
        let mut conn = Connection::client(Settings::client());
        conn.state = ConnectionState::Open;

        let headers = vec![
            Header::new(":method", "GET"),
            Header::new(":path", "/"),
            Header::new(":scheme", "https"),
            Header::new(":authority", "example.com"),
        ];
        let stream_id = conn.open_stream(headers, false).unwrap();

        let frame = Frame::PushPromise(PushPromiseFrame {
            stream_id,
            promised_stream_id: 2,
            header_block: Bytes::new(),
            end_headers: true,
        });

        let err = conn.process_frame(frame).unwrap_err();
        assert_eq!(err.code, ErrorCode::ProtocolError);
    }

    #[test]
    fn push_promise_creates_reserved_stream() {
        let mut settings = Settings::client();
        settings.enable_push = true;
        let mut conn = Connection::client(settings);
        conn.state = ConnectionState::Open;

        let headers = vec![
            Header::new(":method", "GET"),
            Header::new(":path", "/"),
            Header::new(":scheme", "https"),
            Header::new(":authority", "example.com"),
        ];
        let stream_id = conn.open_stream(headers, false).unwrap();

        let frame = Frame::PushPromise(PushPromiseFrame {
            stream_id,
            promised_stream_id: 2,
            header_block: Bytes::new(),
            end_headers: true,
        });

        let received = conn.process_frame(frame).unwrap().unwrap();
        match received {
            ReceivedFrame::PushPromise {
                promised_stream_id, ..
            } => assert_eq!(promised_stream_id, 2),
            other => panic!("expected PushPromise frame, got {other:?}"),
        }

        let promised = conn.stream(2).expect("promised stream exists");
        assert_eq!(promised.state(), StreamState::ReservedRemote);
    }

    #[test]
    fn push_promise_continuation_accumulates() {
        let mut settings = Settings::client();
        settings.enable_push = true;
        let mut conn = Connection::client(settings);
        conn.state = ConnectionState::Open;

        let headers = vec![
            Header::new(":method", "GET"),
            Header::new(":path", "/"),
            Header::new(":scheme", "https"),
            Header::new(":authority", "example.com"),
        ];
        let stream_id = conn.open_stream(headers, false).unwrap();

        let mut promise_headers = vec![
            Header::new(":method", "GET"),
            Header::new(":path", "/pushed"),
            Header::new(":scheme", "https"),
            Header::new(":authority", "example.com"),
        ];

        let mut encoded = BytesMut::new();
        conn.hpack_encoder.encode(&promise_headers, &mut encoded);
        if encoded.len() < 2 {
            promise_headers.push(Header::new("x-extra", "1"));
            encoded.clear();
            conn.hpack_encoder.encode(&promise_headers, &mut encoded);
        }
        assert!(encoded.len() >= 2);

        let encoded = encoded.freeze();
        let split = encoded.len() / 2;
        let first = encoded.slice(..split);
        let second = encoded.slice(split..);

        let push = Frame::PushPromise(PushPromiseFrame {
            stream_id,
            promised_stream_id: 2,
            header_block: first,
            end_headers: false,
        });
        assert!(conn.process_frame(push).unwrap().is_none());

        let continuation = Frame::Continuation(ContinuationFrame {
            stream_id,
            header_block: second,
            end_headers: true,
        });

        let received = conn.process_frame(continuation).unwrap().unwrap();
        match received {
            ReceivedFrame::PushPromise {
                promised_stream_id,
                headers: decoded,
                ..
            } => {
                assert_eq!(promised_stream_id, 2);
                assert_eq!(decoded, promise_headers);
            }
            other => panic!("expected PushPromise frame, got {other:?}"),
        }
    }

    #[test]
    fn push_promise_rejected_on_server_connection() {
        let mut conn = Connection::server(Settings::server());
        conn.state = ConnectionState::Open;

        let frame = Frame::PushPromise(PushPromiseFrame {
            stream_id: 1,
            promised_stream_id: 2,
            header_block: Bytes::new(),
            end_headers: true,
        });

        let err = conn.process_frame(frame).unwrap_err();
        assert_eq!(err.code, ErrorCode::ProtocolError);
    }

    #[test]
    fn push_promise_rejected_for_invalid_promised_id() {
        let mut settings = Settings::client();
        settings.enable_push = true;
        let mut conn = Connection::client(settings);
        conn.state = ConnectionState::Open;

        let headers = vec![
            Header::new(":method", "GET"),
            Header::new(":path", "/"),
            Header::new(":scheme", "https"),
            Header::new(":authority", "example.com"),
        ];
        let stream_id = conn.open_stream(headers, false).unwrap();

        let frame = Frame::PushPromise(PushPromiseFrame {
            stream_id,
            promised_stream_id: 3,
            header_block: Bytes::new(),
            end_headers: true,
        });

        let err = conn.process_frame(frame).unwrap_err();
        assert_eq!(err.code, ErrorCode::ProtocolError);
    }

    #[test]
    fn push_promise_rejected_for_unknown_associated_stream() {
        let mut settings = Settings::client();
        settings.enable_push = true;
        let mut conn = Connection::client(settings);
        conn.state = ConnectionState::Open;

        let frame = Frame::PushPromise(PushPromiseFrame {
            stream_id: 1,
            promised_stream_id: 2,
            header_block: Bytes::new(),
            end_headers: true,
        });

        let err = conn.process_frame(frame).unwrap_err();
        assert_eq!(err.code, ErrorCode::ProtocolError);
        assert_eq!(err.stream_id, Some(1));
    }

    #[test]
    fn continuation_timeout_not_triggered_when_no_continuation() {
        let mut conn = Connection::server(Settings::default());
        conn.state = ConnectionState::Open;

        // No continuation in progress - timeout check should succeed
        assert!(conn.check_continuation_timeout().is_ok());
        assert!(!conn.is_awaiting_continuation());
    }

    #[test]
    fn continuation_timeout_not_triggered_when_within_limit() {
        let settings = Settings {
            continuation_timeout_ms: 5000, // 5 seconds
            ..Default::default()
        };
        let mut conn = Connection::server(settings);
        conn.state = ConnectionState::Open;

        // Receive HEADERS without END_HEADERS
        let headers = Frame::Headers(HeadersFrame::new(1, Bytes::new(), false, false));
        let result = conn.process_frame(headers);
        assert!(result.is_ok());
        assert!(conn.is_awaiting_continuation());

        // Immediately check timeout - should not trigger
        assert!(conn.check_continuation_timeout().is_ok());
        assert!(conn.is_awaiting_continuation());
    }

    #[test]
    fn continuation_clears_timeout_on_completion() {
        let mut conn = Connection::server(Settings::default());
        conn.state = ConnectionState::Open;

        // Receive HEADERS without END_HEADERS
        let headers = Frame::Headers(HeadersFrame::new(1, Bytes::new(), false, false));
        conn.process_frame(headers).unwrap();
        assert!(conn.is_awaiting_continuation());
        assert!(conn.continuation_started_at.is_some());

        // Receive CONTINUATION with END_HEADERS
        let continuation = Frame::Continuation(ContinuationFrame {
            stream_id: 1,
            header_block: Bytes::new(),
            end_headers: true,
        });
        conn.process_frame(continuation).unwrap();

        // Continuation state should be cleared
        assert!(!conn.is_awaiting_continuation());
        assert!(conn.continuation_started_at.is_none());
    }

    #[test]
    fn continuation_timeout_triggers_after_expiry() {
        use std::time::Duration;

        let settings = Settings {
            continuation_timeout_ms: 50, // 50ms for fast test
            ..Default::default()
        };
        let mut conn = Connection::server(settings);
        conn.state = ConnectionState::Open;

        // Receive HEADERS without END_HEADERS
        let headers = Frame::Headers(HeadersFrame::new(1, Bytes::new(), false, false));
        conn.process_frame(headers).unwrap();
        assert!(conn.is_awaiting_continuation());

        // Simulate a timeout without sleeping.
        conn.continuation_started_at = Some(
            Instant::now()
                .checked_sub(Duration::from_millis(60))
                .unwrap_or_else(Instant::now),
        );

        // Timeout should trigger
        let err = conn.check_continuation_timeout().unwrap_err();
        assert_eq!(err.code, ErrorCode::ProtocolError);
        assert!(err.message.contains("CONTINUATION timeout"));

        // Continuation state should be cleared
        assert!(!conn.is_awaiting_continuation());
        assert!(conn.continuation_started_at.is_none());
    }

    #[test]
    fn continuation_timeout_on_next_frame() {
        use std::time::Duration;

        let settings = Settings {
            continuation_timeout_ms: 50, // 50ms for fast test
            ..Default::default()
        };
        let mut conn = Connection::server(settings);
        conn.state = ConnectionState::Open;

        // Receive HEADERS without END_HEADERS
        let headers = Frame::Headers(HeadersFrame::new(1, Bytes::new(), false, false));
        conn.process_frame(headers).unwrap();

        // Simulate a timeout without sleeping.
        conn.continuation_started_at = Some(
            Instant::now()
                .checked_sub(Duration::from_millis(60))
                .unwrap_or_else(Instant::now),
        );

        // Try to process another CONTINUATION - should fail with timeout
        let continuation = Frame::Continuation(ContinuationFrame {
            stream_id: 1,
            header_block: Bytes::new(),
            end_headers: true,
        });
        let err = conn.process_frame(continuation).unwrap_err();
        assert_eq!(err.code, ErrorCode::ProtocolError);
        assert!(err.message.contains("CONTINUATION timeout"));
    }

    #[test]
    fn push_promise_continuation_timeout() {
        use std::time::Duration;

        let mut settings = Settings::client();
        settings.enable_push = true;
        settings.continuation_timeout_ms = 50;
        let mut conn = Connection::client(settings);
        conn.state = ConnectionState::Open;

        // First open a stream
        let headers = vec![
            Header::new(":method", "GET"),
            Header::new(":path", "/"),
            Header::new(":scheme", "https"),
            Header::new(":authority", "example.com"),
        ];
        let stream_id = conn.open_stream(headers, false).unwrap();
        let _ = conn.next_frame(); // drain HEADERS

        // Receive PUSH_PROMISE without END_HEADERS
        let push = Frame::PushPromise(PushPromiseFrame {
            stream_id,
            promised_stream_id: 2,
            header_block: Bytes::new(),
            end_headers: false,
        });
        conn.process_frame(push).unwrap();
        assert!(conn.is_awaiting_continuation());

        // Simulate a timeout without sleeping.
        conn.continuation_started_at = Some(
            Instant::now()
                .checked_sub(Duration::from_millis(60))
                .unwrap_or_else(Instant::now),
        );

        // Timeout should trigger
        let err = conn.check_continuation_timeout().unwrap_err();
        assert_eq!(err.code, ErrorCode::ProtocolError);
        assert!(err.message.contains("CONTINUATION timeout"));
    }

    // =========================================================================
    // Additional PUSH_PROMISE Security Tests (bd-1ckh)
    // =========================================================================

    #[test]
    fn push_promise_rejected_on_closed_stream() {
        let mut settings = Settings::client();
        settings.enable_push = true;
        let mut conn = Connection::client(settings);
        conn.state = ConnectionState::Open;

        // Open and then close a stream
        let headers = vec![
            Header::new(":method", "GET"),
            Header::new(":path", "/"),
            Header::new(":scheme", "https"),
            Header::new(":authority", "example.com"),
        ];
        let stream_id = conn.open_stream(headers, true).unwrap(); // end_stream=true
        let _ = conn.next_frame(); // drain HEADERS

        // Simulate receiving response headers with END_STREAM to fully close
        let response = Frame::Headers(HeadersFrame::new(stream_id, Bytes::new(), true, true));
        conn.process_frame(response).unwrap();

        // Stream should now be closed
        assert_eq!(conn.stream(stream_id).unwrap().state(), StreamState::Closed);

        // PUSH_PROMISE on closed stream should fail
        let frame = Frame::PushPromise(PushPromiseFrame {
            stream_id,
            promised_stream_id: 2,
            header_block: Bytes::new(),
            end_headers: true,
        });

        let err = conn.process_frame(frame).unwrap_err();
        assert_eq!(err.code, ErrorCode::StreamClosed);
    }

    #[test]
    fn push_promise_enforces_max_concurrent_streams() {
        let mut settings = Settings::client();
        settings.enable_push = true;
        settings.max_concurrent_streams = 3; // Very low limit for testing
        let mut conn = Connection::client(settings);
        conn.state = ConnectionState::Open;

        // Open client stream
        let headers = vec![
            Header::new(":method", "GET"),
            Header::new(":path", "/"),
            Header::new(":scheme", "https"),
            Header::new(":authority", "example.com"),
        ];
        let stream_id = conn.open_stream(headers, false).unwrap();
        let _ = conn.next_frame();

        // First push should succeed (now 2 active: stream 1 + pushed 2)
        let push1 = Frame::PushPromise(PushPromiseFrame {
            stream_id,
            promised_stream_id: 2,
            header_block: Bytes::new(),
            end_headers: true,
        });
        assert!(conn.process_frame(push1).is_ok());

        // Second push should succeed (now 3 active: stream 1 + pushed 2 + pushed 4)
        let push2 = Frame::PushPromise(PushPromiseFrame {
            stream_id,
            promised_stream_id: 4,
            header_block: Bytes::new(),
            end_headers: true,
        });
        assert!(conn.process_frame(push2).is_ok());

        // Third push should fail - max concurrent streams exceeded
        let push3 = Frame::PushPromise(PushPromiseFrame {
            stream_id,
            promised_stream_id: 6,
            header_block: Bytes::new(),
            end_headers: true,
        });
        let err = conn.process_frame(push3).unwrap_err();
        assert_eq!(err.code, ErrorCode::RefusedStream);
    }

    #[test]
    fn push_promise_rejected_for_duplicate_stream_id() {
        let mut settings = Settings::client();
        settings.enable_push = true;
        let mut conn = Connection::client(settings);
        conn.state = ConnectionState::Open;

        let headers = vec![
            Header::new(":method", "GET"),
            Header::new(":path", "/"),
            Header::new(":scheme", "https"),
            Header::new(":authority", "example.com"),
        ];
        let stream_id = conn.open_stream(headers, false).unwrap();
        let _ = conn.next_frame();

        // First push with stream ID 2
        let push1 = Frame::PushPromise(PushPromiseFrame {
            stream_id,
            promised_stream_id: 2,
            header_block: Bytes::new(),
            end_headers: true,
        });
        assert!(conn.process_frame(push1).is_ok());

        // Trying to push with same stream ID 2 again should fail
        let push2 = Frame::PushPromise(PushPromiseFrame {
            stream_id,
            promised_stream_id: 2,
            header_block: Bytes::new(),
            end_headers: true,
        });
        let err = conn.process_frame(push2).unwrap_err();
        assert_eq!(err.code, ErrorCode::ProtocolError);
    }

    #[test]
    fn push_promise_monotonic_stream_id() {
        let mut settings = Settings::client();
        settings.enable_push = true;
        let mut conn = Connection::client(settings);
        conn.state = ConnectionState::Open;

        let headers = vec![
            Header::new(":method", "GET"),
            Header::new(":path", "/"),
            Header::new(":scheme", "https"),
            Header::new(":authority", "example.com"),
        ];
        let stream_id = conn.open_stream(headers, false).unwrap();
        let _ = conn.next_frame();

        // Push with stream ID 4 first
        let push1 = Frame::PushPromise(PushPromiseFrame {
            stream_id,
            promised_stream_id: 4,
            header_block: Bytes::new(),
            end_headers: true,
        });
        assert!(conn.process_frame(push1).is_ok());

        // Push with stream ID 2 (lower) should fail - IDs must be monotonically increasing
        let push2 = Frame::PushPromise(PushPromiseFrame {
            stream_id,
            promised_stream_id: 2,
            header_block: Bytes::new(),
            end_headers: true,
        });
        let err = conn.process_frame(push2).unwrap_err();
        assert_eq!(err.code, ErrorCode::ProtocolError);
    }

    #[test]
    fn push_promise_attack_flood_bounded() {
        // Simulates a malicious server sending many PUSH_PROMISE frames.
        // The implementation must bound resource usage via max_concurrent_streams.
        let mut settings = Settings::client();
        settings.enable_push = true;
        settings.max_concurrent_streams = 10;
        let mut conn = Connection::client(settings);
        conn.state = ConnectionState::Open;

        let headers = vec![
            Header::new(":method", "GET"),
            Header::new(":path", "/"),
            Header::new(":scheme", "https"),
            Header::new(":authority", "example.com"),
        ];
        let stream_id = conn.open_stream(headers, false).unwrap();
        let _ = conn.next_frame();

        let mut accepted = 0;
        let mut rejected = 0;

        // Try to push 100 streams
        for i in 0..100 {
            let promised_id = (i + 1) * 2; // Even IDs: 2, 4, 6, ...
            let push = Frame::PushPromise(PushPromiseFrame {
                stream_id,
                promised_stream_id: promised_id,
                header_block: Bytes::new(),
                end_headers: true,
            });

            match conn.process_frame(push) {
                Ok(_) => accepted += 1,
                Err(e) if e.code == ErrorCode::RefusedStream => rejected += 1,
                Err(e) => panic!("unexpected error: {e:?}"),
            }
        }

        // Should accept up to max_concurrent_streams - 1 (minus the original request stream)
        assert_eq!(
            accepted, 9,
            "should accept max_concurrent_streams - 1 pushes"
        );
        assert_eq!(rejected, 91, "should reject the rest");
    }

    #[test]
    fn push_promise_on_server_initiated_stream_rejected() {
        // PUSH_PROMISE must be sent on client-initiated (odd) stream
        let mut settings = Settings::client();
        settings.enable_push = true;
        let mut conn = Connection::client(settings);
        conn.state = ConnectionState::Open;

        // Open a client stream first
        let headers = vec![
            Header::new(":method", "GET"),
            Header::new(":path", "/"),
            Header::new(":scheme", "https"),
            Header::new(":authority", "example.com"),
        ];
        let _ = conn.open_stream(headers, false).unwrap();
        let _ = conn.next_frame();

        // Try to send PUSH_PROMISE on an even (server-initiated) stream ID
        let frame = Frame::PushPromise(PushPromiseFrame {
            stream_id: 2, // Even = server-initiated = invalid for PUSH_PROMISE
            promised_stream_id: 4,
            header_block: Bytes::new(),
            end_headers: true,
        });

        let err = conn.process_frame(frame).unwrap_err();
        assert_eq!(err.code, ErrorCode::ProtocolError);
    }

    // =========================================================================
    // SETTINGS ACK Flow Tests (bd-1oo7)
    // =========================================================================

    #[test]
    fn test_settings_ack_is_no_op() {
        // SETTINGS ACK should be silently accepted
        let mut conn = Connection::client(Settings::client());
        conn.state = ConnectionState::Open;

        let ack_frame = Frame::Settings(SettingsFrame::ack());
        let result = conn.process_frame(ack_frame);

        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_settings_updates_remote_settings() {
        let mut conn = Connection::server(Settings::default());
        conn.state = ConnectionState::Open;

        // Initial values (DEFAULT_MAX_CONCURRENT_STREAMS = 256)
        assert_eq!(conn.remote_settings().max_concurrent_streams, 256);
        assert_eq!(
            conn.remote_settings().initial_window_size,
            settings::DEFAULT_INITIAL_WINDOW_SIZE
        );

        // Apply new settings
        let settings = SettingsFrame::new(vec![
            Setting::MaxConcurrentStreams(50),
            Setting::InitialWindowSize(32768),
            Setting::MaxFrameSize(32768),
        ]);
        conn.process_frame(Frame::Settings(settings)).unwrap();

        // Verify updates
        assert_eq!(conn.remote_settings().max_concurrent_streams, 50);
        assert_eq!(conn.remote_settings().initial_window_size, 32768);
        assert_eq!(conn.remote_settings().max_frame_size, 32768);
    }

    #[test]
    fn test_settings_invalid_initial_window_size() {
        let mut conn = Connection::server(Settings::default());
        conn.state = ConnectionState::Open;

        // Initial window size > 2^31 - 1 is invalid per RFC 7540 Section 6.5.2:
        // "Values above the maximum flow-control window size of 2^31-1 MUST be
        // treated as a connection error of type FLOW_CONTROL_ERROR"
        let settings = SettingsFrame::new(vec![Setting::InitialWindowSize(0x8000_0000)]);
        let err = conn.process_frame(Frame::Settings(settings)).unwrap_err();

        assert_eq!(err.code, ErrorCode::FlowControlError);
    }

    #[test]
    fn test_settings_invalid_max_frame_size() {
        let mut conn = Connection::server(Settings::default());
        conn.state = ConnectionState::Open;

        // Max frame size must be between 16384 and 16777215
        let settings = SettingsFrame::new(vec![Setting::MaxFrameSize(100)]); // Too small
        let err = conn.process_frame(Frame::Settings(settings)).unwrap_err();

        assert_eq!(err.code, ErrorCode::ProtocolError);
    }

    #[test]
    fn test_settings_transitions_to_open() {
        let mut conn = Connection::server(Settings::default());
        assert_eq!(conn.state, ConnectionState::Handshaking);

        // First SETTINGS from peer transitions to Open
        let settings = SettingsFrame::new(vec![]);
        conn.process_frame(Frame::Settings(settings)).unwrap();

        assert_eq!(conn.state, ConnectionState::Open);
    }

    // =========================================================================
    // GOAWAY Edge Case Tests (bd-1oo7)
    // =========================================================================

    #[test]
    fn test_goaway_rejects_new_streams() {
        let mut conn = Connection::client(Settings::client());
        conn.state = ConnectionState::Open;

        // Open a stream
        let headers = vec![
            Header::new(":method", "GET"),
            Header::new(":path", "/"),
            Header::new(":scheme", "https"),
            Header::new(":authority", "example.com"),
        ];
        conn.open_stream(headers.clone(), false).unwrap();

        // Receive GOAWAY
        let goaway = Frame::GoAway(GoAwayFrame::new(1, ErrorCode::NoError));
        conn.process_frame(goaway).unwrap();

        assert!(conn.goaway_received());
        assert_eq!(conn.state, ConnectionState::Closing);

        // Trying to open new streams should fail
        let err = conn.open_stream(headers, false).unwrap_err();
        assert_eq!(err.code, ErrorCode::ProtocolError);
    }

    #[test]
    fn test_goaway_resets_streams_above_last_id() {
        let mut conn = Connection::client(Settings::client());
        conn.state = ConnectionState::Open;

        // Open multiple streams
        let headers = vec![
            Header::new(":method", "GET"),
            Header::new(":path", "/"),
            Header::new(":scheme", "https"),
            Header::new(":authority", "example.com"),
        ];
        let stream1 = conn.open_stream(headers.clone(), false).unwrap(); // Stream 1
        let _ = conn.next_frame(); // Drain HEADERS
        let stream3 = conn.open_stream(headers.clone(), false).unwrap(); // Stream 3
        let _ = conn.next_frame(); // Drain HEADERS
        let stream5 = conn.open_stream(headers, false).unwrap(); // Stream 5
        let _ = conn.next_frame(); // Drain HEADERS

        assert_eq!(stream1, 1);
        assert_eq!(stream3, 3);
        assert_eq!(stream5, 5);

        // GOAWAY with last_stream_id = 1 means streams 3 and 5 were not processed
        let goaway = Frame::GoAway(GoAwayFrame::new(1, ErrorCode::NoError));
        let result = conn.process_frame(goaway).unwrap().unwrap();

        match result {
            ReceivedFrame::GoAway {
                last_stream_id,
                error_code,
                ..
            } => {
                assert_eq!(last_stream_id, 1);
                assert_eq!(error_code, ErrorCode::NoError);
            }
            _ => panic!("expected GoAway"),
        }

        // Stream 1 should still be in its original state
        assert!(!conn.stream(1).unwrap().state().is_closed());

        // Streams 3 and 5 should be reset
        assert_eq!(conn.stream(3).unwrap().state(), StreamState::Closed);
        assert_eq!(conn.stream(5).unwrap().state(), StreamState::Closed);
    }

    #[test]
    fn test_goaway_sent_once() {
        let mut conn = Connection::server(Settings::default());
        conn.state = ConnectionState::Open;

        // First GOAWAY
        conn.goaway(ErrorCode::NoError, Bytes::new());
        assert!(conn.has_pending_frames());

        // Second GOAWAY should be ignored
        conn.goaway(ErrorCode::InternalError, Bytes::new());

        // Should only have one GOAWAY frame
        let frame1 = conn.next_frame().unwrap();
        assert!(matches!(frame1, Frame::GoAway(_)));

        // No second GOAWAY
        assert!(!conn.has_pending_frames());
    }

    #[test]
    fn test_goaway_with_debug_data() {
        let mut conn = Connection::server(Settings::default());
        conn.state = ConnectionState::Open;

        let debug_data = Bytes::from("server shutting down for maintenance");
        conn.goaway(ErrorCode::NoError, debug_data.clone());

        let frame = conn.next_frame().unwrap();
        match frame {
            Frame::GoAway(g) => {
                assert_eq!(g.error_code, ErrorCode::NoError);
                assert_eq!(g.debug_data, debug_data);
            }
            _ => panic!("expected GoAway"),
        }
    }

    #[test]
    fn test_goaway_received_with_error() {
        let mut conn = Connection::client(Settings::client());
        conn.state = ConnectionState::Open;

        let goaway = Frame::GoAway(GoAwayFrame::new(0, ErrorCode::InternalError));
        let result = conn.process_frame(goaway).unwrap().unwrap();

        match result {
            ReceivedFrame::GoAway {
                error_code,
                last_stream_id,
                ..
            } => {
                assert_eq!(error_code, ErrorCode::InternalError);
                assert_eq!(last_stream_id, 0);
            }
            _ => panic!("expected GoAway"),
        }

        assert!(conn.goaway_received());
        assert_eq!(conn.state, ConnectionState::Closing);
    }

    // =========================================================================
    // Shutdown Semantics Tests (bd-1oo7)
    // =========================================================================

    #[test]
    fn test_graceful_shutdown_flow() {
        let mut conn = Connection::server(Settings::default());
        conn.state = ConnectionState::Open;

        // Initiate graceful shutdown
        conn.goaway(ErrorCode::NoError, Bytes::new());

        // Connection should transition to Closing
        assert_eq!(conn.state, ConnectionState::Closing);

        // Should have GOAWAY frame pending
        let frame = conn.next_frame().unwrap();
        match frame {
            Frame::GoAway(g) => {
                assert_eq!(g.error_code, ErrorCode::NoError);
            }
            _ => panic!("expected GoAway"),
        }
    }

    // =========================================================================
    // PING Keepalive Tests (bd-1oo7)
    // =========================================================================

    #[test]
    fn test_ping_ack_response() {
        let mut conn = Connection::server(Settings::default());
        conn.state = ConnectionState::Open;

        let opaque_data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let ping = PingFrame::new(opaque_data);
        conn.process_frame(Frame::Ping(ping)).unwrap();

        // Should have PING ACK pending
        let frame = conn.next_frame().unwrap();
        match frame {
            Frame::Ping(p) => {
                assert!(p.ack);
                assert_eq!(p.opaque_data, opaque_data);
            }
            _ => panic!("expected Ping ACK"),
        }
    }

    #[test]
    fn test_ping_ack_not_echoed() {
        let mut conn = Connection::server(Settings::default());
        conn.state = ConnectionState::Open;

        // Receive PING ACK (should not trigger another ACK)
        let ping_ack = PingFrame::ack([1, 2, 3, 4, 5, 6, 7, 8]);
        conn.process_frame(Frame::Ping(ping_ack)).unwrap();

        // No response should be queued
        assert!(!conn.has_pending_frames());
    }

    // =========================================================================
    // Cancellation Race Tests (bd-1oo7)
    // =========================================================================

    #[test]
    fn test_rst_stream_on_idle_stream() {
        let mut conn = Connection::server(Settings::default());
        conn.state = ConnectionState::Open;

        // RST_STREAM on stream that doesn't exist should be handled gracefully
        let rst = Frame::RstStream(RstStreamFrame::new(999, ErrorCode::Cancel));
        let result = conn.process_frame(rst).unwrap().unwrap();

        match result {
            ReceivedFrame::Reset {
                stream_id,
                error_code,
            } => {
                assert_eq!(stream_id, 999);
                assert_eq!(error_code, ErrorCode::Cancel);
            }
            _ => panic!("expected Reset"),
        }
    }

    #[test]
    fn test_data_after_rst_ignored() {
        let mut conn = Connection::server(Settings::default());
        conn.state = ConnectionState::Open;

        // Open stream via HEADERS
        let headers = Frame::Headers(HeadersFrame::new(1, Bytes::new(), false, true));
        conn.process_frame(headers).unwrap();

        // Reset the stream
        let rst = Frame::RstStream(RstStreamFrame::new(1, ErrorCode::Cancel));
        conn.process_frame(rst).unwrap();

        // Stream should be closed
        assert_eq!(conn.stream(1).unwrap().state(), StreamState::Closed);

        // DATA on closed stream should return error
        let data = Frame::Data(DataFrame::new(1, Bytes::from("test"), false));
        let err = conn.process_frame(data).unwrap_err();
        assert_eq!(err.code, ErrorCode::StreamClosed);
    }

    #[test]
    fn test_window_update_after_goaway() {
        let mut conn = Connection::client(Settings::client());
        conn.state = ConnectionState::Open;

        // Receive GOAWAY
        let goaway = Frame::GoAway(GoAwayFrame::new(0, ErrorCode::NoError));
        conn.process_frame(goaway).unwrap();

        // Connection-level WINDOW_UPDATE should still work
        let window_update = Frame::WindowUpdate(WindowUpdateFrame::new(0, 1024));
        let result = conn.process_frame(window_update);
        assert!(result.is_ok());
    }

    #[test]
    fn test_settings_during_continuation() {
        let mut conn = Connection::server(Settings::default());
        conn.state = ConnectionState::Open;

        // Start a HEADERS sequence without END_HEADERS
        let headers = Frame::Headers(HeadersFrame::new(1, Bytes::new(), false, false));
        conn.process_frame(headers).unwrap();

        // Connection is now expecting CONTINUATION
        assert!(conn.is_awaiting_continuation());

        // SETTINGS frame should cause protocol error (must get CONTINUATION)
        let settings = Frame::Settings(SettingsFrame::new(vec![]));
        let err = conn.process_frame(settings).unwrap_err();
        assert_eq!(err.code, ErrorCode::ProtocolError);
    }

    #[test]
    fn test_ping_during_continuation() {
        let mut conn = Connection::server(Settings::default());
        conn.state = ConnectionState::Open;

        // Start a HEADERS sequence without END_HEADERS
        let headers = Frame::Headers(HeadersFrame::new(1, Bytes::new(), false, false));
        conn.process_frame(headers).unwrap();

        // Connection is now expecting CONTINUATION
        assert!(conn.is_awaiting_continuation());

        // PING frame should cause protocol error (must get CONTINUATION)
        let ping = Frame::Ping(PingFrame::new([0; 8]));
        let err = conn.process_frame(ping).unwrap_err();
        assert_eq!(err.code, ErrorCode::ProtocolError);
    }
}
