//! HTTP/2 connection management.
//!
//! Manages HTTP/2 connection state, settings negotiation, and frame processing.

use std::collections::VecDeque;

use crate::bytes::{Bytes, BytesMut};
use crate::codec::{Decoder, Encoder};

use super::error::{ErrorCode, H2Error};
use super::frame::{
    parse_frame, ContinuationFrame, DataFrame, Frame, FrameHeader, GoAwayFrame, HeadersFrame,
    PingFrame, RstStreamFrame, Setting, SettingsFrame, WindowUpdateFrame, FRAME_HEADER_SIZE,
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
}

impl Connection {
    /// Create a new client connection.
    #[must_use]
    pub fn client(settings: Settings) -> Self {
        let initial_window = settings.initial_window_size;
        Self {
            state: ConnectionState::Handshaking,
            is_client: true,
            local_settings: settings,
            remote_settings: Settings::default(),
            received_settings: false,
            streams: StreamStore::new(true, initial_window),
            hpack_encoder: hpack::Encoder::new(),
            hpack_decoder: hpack::Decoder::new(),
            send_window: DEFAULT_CONNECTION_WINDOW_SIZE,
            recv_window: DEFAULT_CONNECTION_WINDOW_SIZE,
            last_stream_id: 0,
            goaway_received: false,
            goaway_sent: false,
            pending_ops: VecDeque::new(),
            continuation_stream_id: None,
        }
    }

    /// Create a new server connection.
    #[must_use]
    pub fn server(settings: Settings) -> Self {
        let initial_window = settings.initial_window_size;
        Self {
            state: ConnectionState::Handshaking,
            is_client: false,
            local_settings: settings,
            remote_settings: Settings::default(),
            received_settings: false,
            streams: StreamStore::new(false, initial_window),
            hpack_encoder: hpack::Encoder::new(),
            hpack_decoder: hpack::Decoder::new(),
            send_window: DEFAULT_CONNECTION_WINDOW_SIZE,
            recv_window: DEFAULT_CONNECTION_WINDOW_SIZE,
            last_stream_id: 0,
            goaway_received: false,
            goaway_sent: false,
            pending_ops: VecDeque::new(),
            continuation_stream_id: None,
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

        stream.add_header_fragment(frame.header_block);

        if frame.end_headers {
            self.continuation_stream_id = None;
            self.decode_headers(frame.stream_id, frame.end_stream)
        } else {
            self.continuation_stream_id = Some(frame.stream_id);
            Ok(None)
        }
    }

    /// Process CONTINUATION frame.
    fn process_continuation(
        &mut self,
        frame: ContinuationFrame,
    ) -> Result<Option<ReceivedFrame>, H2Error> {
        let stream = self
            .streams
            .get_mut(frame.stream_id)
            .ok_or_else(|| H2Error::protocol("CONTINUATION for unknown stream"))?;

        stream.recv_continuation(frame.header_block, frame.end_headers)?;

        if frame.end_headers {
            self.continuation_stream_id = None;
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
        &self,
        frame: &super::frame::PushPromiseFrame,
    ) -> Result<Option<ReceivedFrame>, H2Error> {
        if self.is_client && !self.local_settings.enable_push {
            return Err(H2Error::protocol("push not enabled"));
        }

        // TODO: Handle push promise properly
        let _ = frame;
        Ok(None)
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
    pub fn next_frame(&mut self) -> Option<Frame> {
        let op = self.pending_ops.pop_front()?;

        match op {
            PendingOp::Settings(frame) => Some(Frame::Settings(frame)),
            PendingOp::SettingsAck => Some(Frame::Settings(SettingsFrame::ack())),
            PendingOp::PingAck(data) => Some(Frame::Ping(PingFrame::ack(data))),
            PendingOp::WindowUpdate {
                stream_id,
                increment,
            } => Some(Frame::WindowUpdate(WindowUpdateFrame::new(
                stream_id, increment,
            ))),
            PendingOp::Headers {
                stream_id,
                headers,
                end_stream,
            } => {
                // Encode headers
                let mut encoded = BytesMut::new();
                self.hpack_encoder.encode(&headers, &mut encoded);

                Some(Frame::Headers(HeadersFrame::new(
                    stream_id,
                    encoded.freeze(),
                    end_stream,
                    true, // end_headers (no continuation for now)
                )))
            }
            PendingOp::Data {
                stream_id,
                data,
                end_stream,
            } => {
                // TODO: Handle flow control properly
                Some(Frame::Data(DataFrame::new(stream_id, data, end_stream)))
            }
            PendingOp::RstStream {
                stream_id,
                error_code,
            } => Some(Frame::RstStream(RstStreamFrame::new(stream_id, error_code))),
            PendingOp::GoAway {
                last_stream_id,
                error_code,
                debug_data,
            } => {
                let mut frame = GoAwayFrame::new(last_stream_id, error_code);
                frame.debug_data = debug_data;
                Some(Frame::GoAway(frame))
            }
        }
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
}
