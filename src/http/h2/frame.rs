//! HTTP/2 frame types and parsing.
//!
//! Implements the frame format defined in RFC 7540 Section 4.

use crate::bytes::{BufMut, Bytes, BytesMut};

use super::error::{ErrorCode, H2Error};

/// Frame header size in bytes.
pub const FRAME_HEADER_SIZE: usize = 9;

/// Default maximum frame size (16 KB).
pub const DEFAULT_MAX_FRAME_SIZE: u32 = 16_384;

/// Maximum allowed frame size (16 MB - 1).
pub const MAX_FRAME_SIZE: u32 = 16_777_215;

/// Minimum allowed max frame size setting.
pub const MIN_MAX_FRAME_SIZE: u32 = 16_384;

/// Maximum allowed initial window size setting (2^31 - 1).
const MAX_INITIAL_WINDOW_SIZE: u32 = 0x7fff_ffff;

/// Maximum WINDOW_UPDATE increment (2^31 - 1).
const MAX_WINDOW_UPDATE_INCREMENT: u32 = 0x7fff_ffff;

/// HTTP/2 frame types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum FrameType {
    /// DATA frame (type 0x0).
    Data = 0x0,
    /// HEADERS frame (type 0x1).
    Headers = 0x1,
    /// PRIORITY frame (type 0x2).
    Priority = 0x2,
    /// RST_STREAM frame (type 0x3).
    RstStream = 0x3,
    /// SETTINGS frame (type 0x4).
    Settings = 0x4,
    /// PUSH_PROMISE frame (type 0x5).
    PushPromise = 0x5,
    /// PING frame (type 0x6).
    Ping = 0x6,
    /// GOAWAY frame (type 0x7).
    GoAway = 0x7,
    /// WINDOW_UPDATE frame (type 0x8).
    WindowUpdate = 0x8,
    /// CONTINUATION frame (type 0x9).
    Continuation = 0x9,
}

impl FrameType {
    /// Parse a frame type from a byte.
    #[must_use]
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x0 => Some(Self::Data),
            0x1 => Some(Self::Headers),
            0x2 => Some(Self::Priority),
            0x3 => Some(Self::RstStream),
            0x4 => Some(Self::Settings),
            0x5 => Some(Self::PushPromise),
            0x6 => Some(Self::Ping),
            0x7 => Some(Self::GoAway),
            0x8 => Some(Self::WindowUpdate),
            0x9 => Some(Self::Continuation),
            _ => None,
        }
    }
}

/// Frame flags for DATA frames.
pub mod data_flags {
    /// END_STREAM flag (0x1).
    pub const END_STREAM: u8 = 0x1;
    /// PADDED flag (0x8).
    pub const PADDED: u8 = 0x8;
}

/// Frame flags for HEADERS frames.
pub mod headers_flags {
    /// END_STREAM flag (0x1).
    pub const END_STREAM: u8 = 0x1;
    /// END_HEADERS flag (0x4).
    pub const END_HEADERS: u8 = 0x4;
    /// PADDED flag (0x8).
    pub const PADDED: u8 = 0x8;
    /// PRIORITY flag (0x20).
    pub const PRIORITY: u8 = 0x20;
}

/// Frame flags for SETTINGS frames.
pub mod settings_flags {
    /// ACK flag (0x1).
    pub const ACK: u8 = 0x1;
}

/// Frame flags for PING frames.
pub mod ping_flags {
    /// ACK flag (0x1).
    pub const ACK: u8 = 0x1;
}

/// Frame flags for CONTINUATION frames.
pub mod continuation_flags {
    /// END_HEADERS flag (0x4).
    pub const END_HEADERS: u8 = 0x4;
}

/// Frame header information.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    /// Payload length (0-16777215).
    pub length: u32,
    /// Frame type.
    pub frame_type: u8,
    /// Frame flags.
    pub flags: u8,
    /// Stream identifier (31 bits).
    pub stream_id: u32,
}

impl FrameHeader {
    /// Parse a frame header from bytes.
    ///
    /// Returns the header and consumes 9 bytes from the buffer.
    pub fn parse(src: &mut BytesMut) -> Result<Self, H2Error> {
        if src.len() < FRAME_HEADER_SIZE {
            return Err(H2Error::protocol("insufficient bytes for frame header"));
        }

        let length = ((u32::from(src[0])) << 16) | ((u32::from(src[1])) << 8) | u32::from(src[2]);
        let frame_type = src[3];
        let flags = src[4];
        let stream_id = ((u32::from(src[5]) & 0x7f) << 24)
            | ((u32::from(src[6])) << 16)
            | ((u32::from(src[7])) << 8)
            | u32::from(src[8]);

        src.advance(FRAME_HEADER_SIZE);

        Ok(Self {
            length,
            frame_type,
            flags,
            stream_id,
        })
    }

    /// Write this frame header to a buffer.
    ///
    /// # Panics
    ///
    /// Panics if `length` exceeds `MAX_FRAME_SIZE` (24-bit limit).
    #[inline]
    pub fn write(&self, dst: &mut BytesMut) {
        assert!(
            self.length <= MAX_FRAME_SIZE,
            "frame length {0} exceeds 24-bit max {1}",
            self.length,
            MAX_FRAME_SIZE,
        );
        let buf: [u8; FRAME_HEADER_SIZE] = [
            (self.length >> 16) as u8,
            (self.length >> 8) as u8,
            self.length as u8,
            self.frame_type,
            self.flags,
            ((self.stream_id >> 24) & 0x7f) as u8,
            (self.stream_id >> 16) as u8,
            (self.stream_id >> 8) as u8,
            self.stream_id as u8,
        ];
        dst.extend_from_slice(&buf);
    }

    /// Check if the frame has a specific flag set.
    #[must_use]
    pub fn has_flag(&self, flag: u8) -> bool {
        self.flags & flag != 0
    }
}

/// Cast a payload length to the 24-bit H2 frame length field.
///
/// br-asupersync-pt23uf: returns Err(H2Error::frame_size) instead of
/// panicking when `len` exceeds `MAX_FRAME_SIZE` (16 777 215 bytes per
/// RFC 9113 §4.2). Previously this was an `assert!` that crashed the
/// connection task on any caller bug or attacker-influenced echoed
/// payload that exceeded the 24-bit length-field cap.
#[inline]
fn try_frame_length(len: usize) -> Result<u32, H2Error> {
    if len > MAX_FRAME_SIZE as usize {
        return Err(H2Error::frame_size(format!(
            "payload length {len} exceeds 24-bit max {MAX_FRAME_SIZE} (br-asupersync-pt23uf)"
        )));
    }
    #[allow(clippy::cast_possible_truncation)]
    let len = len as u32;
    Ok(len)
}

#[inline]
fn checked_frame_length_sum(lhs: usize, rhs: usize) -> Result<u32, H2Error> {
    let len = lhs.checked_add(rhs).ok_or_else(|| {
        H2Error::frame_size(format!(
            "payload length overflow while adding {lhs} and {rhs} (br-asupersync-pt23uf)"
        ))
    })?;
    try_frame_length(len)
}

#[inline]
fn checked_frame_length_product(lhs: usize, rhs: usize) -> Result<u32, H2Error> {
    let len = lhs.checked_mul(rhs).ok_or_else(|| {
        H2Error::frame_size(format!(
            "payload length overflow while multiplying {lhs} by {rhs} (br-asupersync-pt23uf)"
        ))
    })?;
    try_frame_length(len)
}

/// HTTP/2 frame.
#[derive(Debug, Clone)]
pub enum Frame {
    /// DATA frame carrying stream data.
    Data(DataFrame),
    /// HEADERS frame carrying header block fragment.
    Headers(HeadersFrame),
    /// PRIORITY frame for stream prioritization.
    Priority(PriorityFrame),
    /// RST_STREAM frame for stream termination.
    RstStream(RstStreamFrame),
    /// SETTINGS frame for connection configuration.
    Settings(SettingsFrame),
    /// PUSH_PROMISE frame for server push.
    PushPromise(PushPromiseFrame),
    /// PING frame for connection liveness.
    Ping(PingFrame),
    /// GOAWAY frame for graceful shutdown.
    GoAway(GoAwayFrame),
    /// WINDOW_UPDATE frame for flow control.
    WindowUpdate(WindowUpdateFrame),
    /// CONTINUATION frame for header block continuation.
    Continuation(ContinuationFrame),
    /// Unknown/extension frame type — MUST be ignored per RFC 7540 §4.1.
    Unknown {
        /// The raw frame type byte.
        frame_type: u8,
        /// The stream ID from the frame header.
        stream_id: u32,
        /// The opaque payload.
        payload: Bytes,
    },
}

impl Frame {
    /// Get the stream ID this frame belongs to.
    #[must_use]
    pub fn stream_id(&self) -> u32 {
        match self {
            Self::Data(f) => f.stream_id,
            Self::Headers(f) => f.stream_id,
            Self::Priority(f) => f.stream_id,
            Self::RstStream(f) => f.stream_id,
            Self::Settings(_) | Self::Ping(_) | Self::GoAway(_) => 0,
            Self::PushPromise(f) => f.stream_id,
            Self::WindowUpdate(f) => f.stream_id,
            Self::Continuation(f) => f.stream_id,
            Self::Unknown { stream_id, .. } => *stream_id,
        }
    }

    /// Encode this frame to bytes.
    #[inline]
    pub fn encode(&self, dst: &mut BytesMut) -> Result<(), H2Error> {
        match self {
            Self::Data(f) => f.encode(dst),
            Self::Headers(f) => f.encode(dst),
            Self::Priority(f) => f.encode(dst),
            Self::RstStream(f) => f.encode(dst),
            Self::Settings(f) => f.encode(dst),
            Self::PushPromise(f) => f.encode(dst),
            Self::Ping(f) => f.encode(dst),
            Self::GoAway(f) => f.encode(dst),
            Self::WindowUpdate(f) => f.encode(dst),
            Self::Continuation(f) => f.encode(dst),
            Self::Unknown {
                frame_type,
                stream_id,
                payload,
            } => {
                let header = FrameHeader {
                    length: try_frame_length(payload.len())?,
                    frame_type: *frame_type,
                    flags: 0,
                    stream_id: *stream_id,
                };
                header.write(dst);
                dst.extend_from_slice(payload);
                Ok(())
            }
        }
    }
}

/// DATA frame (type 0x0).
#[derive(Debug, Clone)]
pub struct DataFrame {
    /// Stream identifier.
    pub stream_id: u32,
    /// Application payload data (padding already stripped).
    pub data: Bytes,
    /// True if this is the last frame for this stream.
    pub end_stream: bool,
    /// RFC 9113 §6.9.1 flow-controlled length: the size of the *entire* DATA
    /// frame payload as it appeared on the wire, including the Pad Length octet
    /// and Padding when present. This is what must be charged against the
    /// connection- and stream-level flow-control windows, and it can be larger
    /// than `data.len()` for padded frames. For frames constructed locally
    /// (no padding) it equals `data.len()`.
    pub flow_controlled_len: u32,
}

impl DataFrame {
    /// Create a new DATA frame.
    #[must_use]
    pub fn new(stream_id: u32, data: Bytes, end_stream: bool) -> Self {
        // Locally constructed frames are never padded, so the flow-controlled
        // length equals the application data length.
        let flow_controlled_len = u32::try_from(data.len()).unwrap_or(u32::MAX);
        Self {
            stream_id,
            data,
            end_stream,
            flow_controlled_len,
        }
    }

    /// Parse a DATA frame from payload.
    pub fn parse(header: &FrameHeader, payload: Bytes) -> Result<Self, H2Error> {
        if header.stream_id == 0 {
            return Err(H2Error::protocol("DATA frame with stream ID 0"));
        }

        // The whole on-the-wire payload (Pad Length + data + Padding) is
        // flow-controlled, regardless of how much is application data.
        let flow_controlled_len = header.length;

        let mut data = payload;
        let end_stream = header.has_flag(data_flags::END_STREAM);

        // Handle padding
        if header.has_flag(data_flags::PADDED) {
            if data.is_empty() {
                return Err(H2Error::protocol(
                    "PADDED DATA frame with no padding length",
                ));
            }
            let pad_length = data[0] as usize;
            data = data.slice(1..);

            if pad_length > data.len() {
                return Err(H2Error::protocol("DATA frame padding exceeds data length"));
            }
            data = data.slice(..data.len() - pad_length);
        }

        Ok(Self {
            stream_id: header.stream_id,
            data,
            end_stream,
            flow_controlled_len,
        })
    }

    /// Encode this frame.
    #[inline]
    pub fn encode(&self, dst: &mut BytesMut) -> Result<(), H2Error> {
        if self.stream_id == 0 {
            return Err(H2Error::protocol("DATA frame with stream ID 0"));
        }

        let mut flags = 0u8;
        if self.end_stream {
            flags |= data_flags::END_STREAM;
        }

        let header = FrameHeader {
            length: try_frame_length(self.data.len())?,
            frame_type: FrameType::Data as u8,
            flags,
            stream_id: self.stream_id,
        };
        header.write(dst);
        dst.extend_from_slice(&self.data);
        Ok(())
    }
}

/// HEADERS frame (type 0x1).
#[derive(Debug, Clone)]
pub struct HeadersFrame {
    /// Stream identifier.
    pub stream_id: u32,
    /// Header block fragment.
    pub header_block: Bytes,
    /// True if this is the last frame for this stream.
    pub end_stream: bool,
    /// True if this ends the header block.
    pub end_headers: bool,
    /// Optional priority information.
    pub priority: Option<PrioritySpec>,
}

impl HeadersFrame {
    /// Create a new HEADERS frame.
    #[must_use]
    pub fn new(stream_id: u32, header_block: Bytes, end_stream: bool, end_headers: bool) -> Self {
        Self {
            stream_id,
            header_block,
            end_stream,
            end_headers,
            priority: None,
        }
    }

    /// Parse a HEADERS frame from payload.
    pub fn parse(header: &FrameHeader, mut payload: Bytes) -> Result<Self, H2Error> {
        if header.stream_id == 0 {
            return Err(H2Error::protocol("HEADERS frame with stream ID 0"));
        }

        let end_stream = header.has_flag(headers_flags::END_STREAM);
        let end_headers = header.has_flag(headers_flags::END_HEADERS);
        let padded = header.has_flag(headers_flags::PADDED);
        let has_priority = header.has_flag(headers_flags::PRIORITY);

        // Handle padding
        let mut pad_length = 0;
        if padded {
            if payload.is_empty() {
                return Err(H2Error::protocol(
                    "PADDED HEADERS frame with no padding length",
                ));
            }
            pad_length = payload[0] as usize;
            payload = payload.slice(1..);

            // br-asupersync-ujytci: validate pad_length BEFORE entering the
            // priority block so the connection-level PROTOCOL_ERROR for
            // padding-exceeds-payload (RFC 9113 §6.2) takes precedence over
            // the stream-level PROTOCOL_ERROR for self-dependency. If both
            // defects are present in one attacker-crafted frame, the prior
            // ordering returned the stream error first and the malformed
            // peer survived the connection. The check here accounts for
            // the 5 priority bytes that will be consumed next, so the
            // residual payload must hold both the priority block and the
            // padding tail simultaneously.
            let priority_bytes = if has_priority { 5usize } else { 0 };
            // saturating_add is defense-in-depth — pad_length is u8-sourced
            // so it cannot exceed 255 + 5 < usize::MAX.
            if pad_length.saturating_add(priority_bytes) > payload.len() {
                return Err(H2Error::protocol(
                    "HEADERS frame padding exceeds data length",
                ));
            }
        }

        // Parse priority if present
        let priority = if has_priority {
            if payload.len() < 5 {
                return Err(H2Error::protocol("HEADERS frame too short for priority"));
            }
            let exclusive = payload[0] & 0x80 != 0;
            let dependency = ((u32::from(payload[0]) & 0x7f) << 24)
                | ((u32::from(payload[1])) << 16)
                | ((u32::from(payload[2])) << 8)
                | u32::from(payload[3]);

            if dependency == header.stream_id {
                return Err(H2Error::stream(
                    header.stream_id,
                    ErrorCode::ProtocolError,
                    "stream cannot depend on itself",
                ));
            }

            let weight = payload[4];
            payload = payload.slice(5..);
            Some(PrioritySpec {
                exclusive,
                dependency,
                weight,
            })
        } else {
            None
        };

        // Strip padding tail. The pad_length-vs-payload-length check above
        // already validated this fits, so the slice is safe.
        if padded {
            payload = payload.slice(..payload.len() - pad_length);
        }

        Ok(Self {
            stream_id: header.stream_id,
            header_block: payload,
            end_stream,
            end_headers,
            priority,
        })
    }

    /// Encode this frame.
    #[inline]
    pub fn encode(&self, dst: &mut BytesMut) -> Result<(), H2Error> {
        if self.stream_id == 0 {
            return Err(H2Error::protocol("HEADERS frame with stream ID 0"));
        }
        if self
            .priority
            .is_some_and(|priority| priority.dependency & 0x7fff_ffff == self.stream_id)
        {
            return Err(H2Error::stream(
                self.stream_id,
                ErrorCode::ProtocolError,
                "stream cannot depend on itself",
            ));
        }

        let mut flags = 0u8;
        if self.end_stream {
            flags |= headers_flags::END_STREAM;
        }
        if self.end_headers {
            flags |= headers_flags::END_HEADERS;
        }

        let length = if self.priority.is_some() {
            flags |= headers_flags::PRIORITY;
            checked_frame_length_sum(self.header_block.len(), 5)?
        } else {
            try_frame_length(self.header_block.len())?
        };

        let header = FrameHeader {
            length,
            frame_type: FrameType::Headers as u8,
            flags,
            stream_id: self.stream_id,
        };
        header.write(dst);

        if let Some(ref priority) = self.priority {
            let mut dep = priority.dependency;
            if priority.exclusive {
                dep |= 0x8000_0000;
            }
            dst.put_u32(dep);
            dst.put_u8(priority.weight);
        }

        dst.extend_from_slice(&self.header_block);
        Ok(())
    }
}

/// Stream priority specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrioritySpec {
    /// Exclusive dependency flag.
    pub exclusive: bool,
    /// Stream dependency.
    pub dependency: u32,
    /// Priority weight (1-256, stored as 0-255).
    pub weight: u8,
}

/// PRIORITY frame (type 0x2).
#[derive(Debug, Clone, Copy)]
pub struct PriorityFrame {
    /// Stream identifier.
    pub stream_id: u32,
    /// Priority specification.
    pub priority: PrioritySpec,
}

impl PriorityFrame {
    /// Parse a PRIORITY frame from payload.
    pub fn parse(header: &FrameHeader, payload: &Bytes) -> Result<Self, H2Error> {
        if header.stream_id == 0 {
            return Err(H2Error::protocol("PRIORITY frame with stream ID 0"));
        }
        if payload.len() != 5 {
            // RFC 7540 §6.3: PRIORITY size error is a stream error, not connection.
            return Err(H2Error::stream(
                header.stream_id,
                ErrorCode::FrameSizeError,
                "PRIORITY frame must be 5 bytes",
            ));
        }

        let exclusive = payload[0] & 0x80 != 0;
        let dependency = ((u32::from(payload[0]) & 0x7f) << 24)
            | ((u32::from(payload[1])) << 16)
            | ((u32::from(payload[2])) << 8)
            | u32::from(payload[3]);

        if dependency == header.stream_id {
            return Err(H2Error::stream(
                header.stream_id,
                ErrorCode::ProtocolError,
                "stream cannot depend on itself",
            ));
        }

        let weight = payload[4];

        Ok(Self {
            stream_id: header.stream_id,
            priority: PrioritySpec {
                exclusive,
                dependency,
                weight,
            },
        })
    }

    /// Encode this frame.
    #[inline]
    pub fn encode(&self, dst: &mut BytesMut) -> Result<(), H2Error> {
        if self.stream_id == 0 {
            return Err(H2Error::protocol("PRIORITY frame with stream ID 0"));
        }
        if self.priority.dependency & 0x7fff_ffff == self.stream_id {
            return Err(H2Error::stream(
                self.stream_id,
                ErrorCode::ProtocolError,
                "stream cannot depend on itself",
            ));
        }

        let header = FrameHeader {
            length: 5,
            frame_type: FrameType::Priority as u8,
            flags: 0,
            stream_id: self.stream_id,
        };
        header.write(dst);

        let mut dep = self.priority.dependency;
        if self.priority.exclusive {
            dep |= 0x8000_0000;
        }
        dst.put_u32(dep);
        dst.put_u8(self.priority.weight);
        Ok(())
    }
}

/// RST_STREAM frame (type 0x3).
#[derive(Debug, Clone, Copy)]
pub struct RstStreamFrame {
    /// Stream identifier.
    pub stream_id: u32,
    /// Error code.
    pub error_code: ErrorCode,
}

impl RstStreamFrame {
    /// Create a new RST_STREAM frame.
    #[must_use]
    pub fn new(stream_id: u32, error_code: ErrorCode) -> Self {
        Self {
            stream_id,
            error_code,
        }
    }

    /// Parse a RST_STREAM frame from payload.
    pub fn parse(header: &FrameHeader, payload: &Bytes) -> Result<Self, H2Error> {
        if header.stream_id == 0 {
            return Err(H2Error::protocol("RST_STREAM frame with stream ID 0"));
        }
        if payload.len() != 4 {
            return Err(H2Error::frame_size("RST_STREAM frame must be 4 bytes"));
        }

        let error_code = ErrorCode::from_u32(
            ((u32::from(payload[0])) << 24)
                | ((u32::from(payload[1])) << 16)
                | ((u32::from(payload[2])) << 8)
                | u32::from(payload[3]),
        );

        Ok(Self {
            stream_id: header.stream_id,
            error_code,
        })
    }

    /// Encode this frame.
    #[inline]
    pub fn encode(&self, dst: &mut BytesMut) -> Result<(), H2Error> {
        if self.stream_id == 0 {
            return Err(H2Error::protocol("RST_STREAM frame with stream ID 0"));
        }

        let header = FrameHeader {
            length: 4,
            frame_type: FrameType::RstStream as u8,
            flags: 0,
            stream_id: self.stream_id,
        };
        header.write(dst);
        dst.put_u32(self.error_code.into());
        Ok(())
    }
}

/// SETTINGS frame (type 0x4).
#[derive(Debug, Clone, Default)]
pub struct SettingsFrame {
    /// Settings values.
    pub settings: Vec<Setting>,
    /// True if this is an ACK.
    pub ack: bool,
}

impl SettingsFrame {
    /// Create a new SETTINGS frame.
    #[must_use]
    pub fn new(settings: Vec<Setting>) -> Self {
        Self {
            settings,
            ack: false,
        }
    }

    /// Create a SETTINGS ACK frame.
    #[must_use]
    pub fn ack() -> Self {
        Self {
            settings: Vec::new(),
            ack: true,
        }
    }

    /// Parse a SETTINGS frame from payload.
    pub fn parse(header: &FrameHeader, payload: &Bytes) -> Result<Self, H2Error> {
        if header.stream_id != 0 {
            return Err(H2Error::protocol("SETTINGS frame with non-zero stream ID"));
        }

        let ack = header.has_flag(settings_flags::ACK);
        if ack && !payload.is_empty() {
            return Err(H2Error::frame_size("SETTINGS ACK with non-zero length"));
        }

        if !payload.len().is_multiple_of(6) {
            return Err(H2Error::frame_size(
                "SETTINGS frame length not multiple of 6",
            ));
        }

        let mut settings = Vec::new();
        let mut cursor: usize = 0;
        while cursor.saturating_add(6) <= payload.len() {
            let id =
                ((u16::from(payload[cursor])) << 8) | u16::from(payload[cursor.saturating_add(1)]);
            let value = ((u32::from(payload[cursor.saturating_add(2)])) << 24)
                | ((u32::from(payload[cursor.saturating_add(3)])) << 16)
                | ((u32::from(payload[cursor.saturating_add(4)])) << 8)
                | u32::from(payload[cursor.saturating_add(5)]);

            // RFC 7540 Section 6.5.2: SETTINGS_ENABLE_PUSH MUST be 0 or 1.
            if id == 0x2 && value > 1 {
                return Err(H2Error::protocol("SETTINGS_ENABLE_PUSH must be 0 or 1"));
            }

            // RFC 7540 Section 6.5.2: SETTINGS_INITIAL_WINDOW_SIZE MUST be <= 2^31-1
            if id == 0x4 && value > MAX_INITIAL_WINDOW_SIZE {
                return Err(H2Error::flow_control(
                    "SETTINGS_INITIAL_WINDOW_SIZE exceeds maximum",
                ));
            }

            // RFC 7540 Section 6.5.2: SETTINGS_MAX_FRAME_SIZE MUST be within bounds
            if id == 0x5 && !(MIN_MAX_FRAME_SIZE..=MAX_FRAME_SIZE).contains(&value) {
                return Err(H2Error::protocol("SETTINGS_MAX_FRAME_SIZE out of bounds"));
            }

            if let Some(setting) = Setting::from_id_value(id, value) {
                settings.push(setting);
            }
            cursor = cursor.saturating_add(6);
        }

        Ok(Self { settings, ack })
    }

    /// Encode this frame.
    #[inline]
    pub fn encode(&self, dst: &mut BytesMut) -> Result<(), H2Error> {
        let mut flags = 0u8;
        if self.ack {
            flags |= settings_flags::ACK;
        }

        // RFC 9113 §6.5.3: a SETTINGS ACK frame MUST have zero-length payload.
        let encoded_settings: &[Setting] = if self.ack { &[] } else { &self.settings };

        for setting in encoded_settings {
            validate_setting_for_encode(*setting)?;
        }

        let header = FrameHeader {
            length: checked_frame_length_product(encoded_settings.len(), 6)?,
            frame_type: FrameType::Settings as u8,
            flags,
            stream_id: 0,
        };
        header.write(dst);

        for setting in encoded_settings {
            dst.put_u16(setting.id());
            dst.put_u32(setting.value());
        }
        Ok(())
    }
}

fn validate_setting_for_encode(setting: Setting) -> Result<(), H2Error> {
    match setting {
        Setting::InitialWindowSize(value) if value > MAX_INITIAL_WINDOW_SIZE => Err(
            H2Error::flow_control("SETTINGS_INITIAL_WINDOW_SIZE exceeds maximum"),
        ),
        Setting::MaxFrameSize(value) if !(MIN_MAX_FRAME_SIZE..=MAX_FRAME_SIZE).contains(&value) => {
            Err(H2Error::protocol("SETTINGS_MAX_FRAME_SIZE out of bounds"))
        }
        _ => Ok(()),
    }
}

/// HTTP/2 setting parameter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Setting {
    /// SETTINGS_HEADER_TABLE_SIZE (0x1).
    HeaderTableSize(u32),
    /// SETTINGS_ENABLE_PUSH (0x2).
    EnablePush(bool),
    /// SETTINGS_MAX_CONCURRENT_STREAMS (0x3).
    MaxConcurrentStreams(u32),
    /// SETTINGS_INITIAL_WINDOW_SIZE (0x4).
    InitialWindowSize(u32),
    /// SETTINGS_MAX_FRAME_SIZE (0x5).
    MaxFrameSize(u32),
    /// SETTINGS_MAX_HEADER_LIST_SIZE (0x6).
    MaxHeaderListSize(u32),
}

impl Setting {
    /// Parse a setting from ID and value.
    #[must_use]
    pub fn from_id_value(id: u16, value: u32) -> Option<Self> {
        match id {
            0x1 => Some(Self::HeaderTableSize(value)),
            0x2 => Some(Self::EnablePush(value != 0)),
            0x3 => Some(Self::MaxConcurrentStreams(value)),
            0x4 => Some(Self::InitialWindowSize(value)),
            0x5 => Some(Self::MaxFrameSize(value)),
            0x6 => Some(Self::MaxHeaderListSize(value)),
            _ => None, // Unknown settings are ignored per RFC 7540
        }
    }

    /// Get the setting identifier.
    #[must_use]
    pub fn id(&self) -> u16 {
        match self {
            Self::HeaderTableSize(_) => 0x1,
            Self::EnablePush(_) => 0x2,
            Self::MaxConcurrentStreams(_) => 0x3,
            Self::InitialWindowSize(_) => 0x4,
            Self::MaxFrameSize(_) => 0x5,
            Self::MaxHeaderListSize(_) => 0x6,
        }
    }

    /// Get the setting value.
    #[must_use]
    pub fn value(&self) -> u32 {
        match self {
            Self::HeaderTableSize(v)
            | Self::MaxConcurrentStreams(v)
            | Self::InitialWindowSize(v)
            | Self::MaxFrameSize(v)
            | Self::MaxHeaderListSize(v) => *v,
            Self::EnablePush(v) => u32::from(*v),
        }
    }
}

/// PUSH_PROMISE frame (type 0x5).
#[derive(Debug, Clone)]
pub struct PushPromiseFrame {
    /// Stream identifier.
    pub stream_id: u32,
    /// Promised stream identifier.
    pub promised_stream_id: u32,
    /// Header block fragment.
    pub header_block: Bytes,
    /// True if this ends the header block.
    pub end_headers: bool,
}

impl PushPromiseFrame {
    /// Parse a PUSH_PROMISE frame from payload.
    pub fn parse(header: &FrameHeader, mut payload: Bytes) -> Result<Self, H2Error> {
        if header.stream_id == 0 {
            return Err(H2Error::protocol("PUSH_PROMISE frame with stream ID 0"));
        }

        let end_headers = header.has_flag(headers_flags::END_HEADERS);
        let padded = header.has_flag(headers_flags::PADDED);

        // Handle padding
        let mut pad_length = 0;
        if padded {
            if payload.is_empty() {
                return Err(H2Error::protocol(
                    "PADDED PUSH_PROMISE frame with no padding length",
                ));
            }
            pad_length = payload[0] as usize;
            payload = payload.slice(1..);
        }

        if payload.len() < 4 {
            return Err(H2Error::protocol("PUSH_PROMISE frame too short"));
        }

        let promised_stream_id = ((u32::from(payload[0]) & 0x7f) << 24)
            | ((u32::from(payload[1])) << 16)
            | ((u32::from(payload[2])) << 8)
            | u32::from(payload[3]);
        if promised_stream_id == 0 {
            return Err(H2Error::protocol(
                "PUSH_PROMISE frame with promised stream ID 0",
            ));
        }
        payload = payload.slice(4..);

        // Remove padding
        if padded {
            if pad_length > payload.len() {
                return Err(H2Error::protocol(
                    "PUSH_PROMISE frame padding exceeds data length",
                ));
            }
            payload = payload.slice(..payload.len() - pad_length);
        }

        Ok(Self {
            stream_id: header.stream_id,
            promised_stream_id,
            header_block: payload,
            end_headers,
        })
    }

    /// Encode this frame.
    #[inline]
    pub fn encode(&self, dst: &mut BytesMut) -> Result<(), H2Error> {
        if self.stream_id == 0 {
            return Err(H2Error::protocol("PUSH_PROMISE frame with stream ID 0"));
        }
        if self.promised_stream_id.trailing_zeros() >= 31 {
            return Err(H2Error::protocol(
                "PUSH_PROMISE frame with promised stream ID 0",
            ));
        }

        let mut flags = 0u8;
        if self.end_headers {
            flags |= headers_flags::END_HEADERS;
        }

        let header = FrameHeader {
            length: checked_frame_length_sum(self.header_block.len(), 4)?,
            frame_type: FrameType::PushPromise as u8,
            flags,
            stream_id: self.stream_id,
        };
        header.write(dst);

        dst.put_u32(self.promised_stream_id & 0x7fff_ffff);
        dst.extend_from_slice(&self.header_block);
        Ok(())
    }
}

/// PING frame (type 0x6).
#[derive(Debug, Clone, Copy)]
pub struct PingFrame {
    /// Opaque 8-byte payload.
    pub opaque_data: [u8; 8],
    /// True if this is an ACK.
    pub ack: bool,
}

impl PingFrame {
    /// Create a new PING frame.
    #[must_use]
    pub fn new(opaque_data: [u8; 8]) -> Self {
        Self {
            opaque_data,
            ack: false,
        }
    }

    /// Create a PING ACK frame.
    #[must_use]
    pub fn ack(opaque_data: [u8; 8]) -> Self {
        Self {
            opaque_data,
            ack: true,
        }
    }

    /// Parse a PING frame from payload.
    pub fn parse(header: &FrameHeader, payload: &Bytes) -> Result<Self, H2Error> {
        if header.stream_id != 0 {
            return Err(H2Error::protocol("PING frame with non-zero stream ID"));
        }
        if payload.len() != 8 {
            return Err(H2Error::frame_size("PING frame must be 8 bytes"));
        }

        let mut opaque_data = [0u8; 8];
        opaque_data.copy_from_slice(&payload[..8]);

        Ok(Self {
            opaque_data,
            ack: header.has_flag(ping_flags::ACK),
        })
    }

    /// Encode this frame.
    #[inline]
    pub fn encode(&self, dst: &mut BytesMut) -> Result<(), H2Error> {
        let mut flags = 0u8;
        if self.ack {
            flags |= ping_flags::ACK;
        }

        let header = FrameHeader {
            length: 8,
            frame_type: FrameType::Ping as u8,
            flags,
            stream_id: 0,
        };
        header.write(dst);
        dst.extend_from_slice(&self.opaque_data);
        Ok(())
    }
}

/// GOAWAY frame (type 0x7).
#[derive(Debug, Clone)]
pub struct GoAwayFrame {
    /// Last stream ID that was or might be processed.
    pub last_stream_id: u32,
    /// Error code indicating why the connection is closing.
    pub error_code: ErrorCode,
    /// Optional debug data.
    pub debug_data: Bytes,
}

impl GoAwayFrame {
    /// Create a new GOAWAY frame.
    #[must_use]
    pub fn new(last_stream_id: u32, error_code: ErrorCode) -> Self {
        Self {
            last_stream_id,
            error_code,
            debug_data: Bytes::new(),
        }
    }

    /// Parse a GOAWAY frame from payload.
    pub fn parse(header: &FrameHeader, payload: &Bytes) -> Result<Self, H2Error> {
        if header.stream_id != 0 {
            return Err(H2Error::protocol("GOAWAY frame with non-zero stream ID"));
        }
        if payload.len() < 8 {
            return Err(H2Error::frame_size("GOAWAY frame must be at least 8 bytes"));
        }

        let last_stream_id = ((u32::from(payload[0]) & 0x7f) << 24)
            | ((u32::from(payload[1])) << 16)
            | ((u32::from(payload[2])) << 8)
            | u32::from(payload[3]);
        let error_code = ErrorCode::from_u32(
            ((u32::from(payload[4])) << 24)
                | ((u32::from(payload[5])) << 16)
                | ((u32::from(payload[6])) << 8)
                | u32::from(payload[7]),
        );
        let debug_data = payload.slice(8..);

        Ok(Self {
            last_stream_id,
            error_code,
            debug_data,
        })
    }

    /// Encode this frame.
    #[inline]
    pub fn encode(&self, dst: &mut BytesMut) -> Result<(), H2Error> {
        let header = FrameHeader {
            length: checked_frame_length_sum(self.debug_data.len(), 8)?,
            frame_type: FrameType::GoAway as u8,
            flags: 0,
            stream_id: 0,
        };
        header.write(dst);

        dst.put_u32(self.last_stream_id & 0x7fff_ffff);
        dst.put_u32(self.error_code.into());
        dst.extend_from_slice(&self.debug_data);
        Ok(())
    }
}

/// WINDOW_UPDATE frame (type 0x8).
#[derive(Debug, Clone, Copy)]
pub struct WindowUpdateFrame {
    /// Stream identifier (0 for connection-level).
    pub stream_id: u32,
    /// Window size increment (1-2^31-1).
    pub increment: u32,
}

impl WindowUpdateFrame {
    /// Create a new WINDOW_UPDATE frame.
    #[must_use]
    pub fn new(stream_id: u32, increment: u32) -> Self {
        Self {
            stream_id,
            increment,
        }
    }

    /// Parse a WINDOW_UPDATE frame from payload.
    pub fn parse(header: &FrameHeader, payload: &Bytes) -> Result<Self, H2Error> {
        if payload.len() != 4 {
            return Err(H2Error::frame_size("WINDOW_UPDATE frame must be 4 bytes"));
        }

        let increment = ((u32::from(payload[0]) & 0x7f) << 24)
            | ((u32::from(payload[1])) << 16)
            | ((u32::from(payload[2])) << 8)
            | u32::from(payload[3]);

        // br-asupersync-x8re31: a zero increment is NOT rejected here. Framing
        // only extracts the value; rejection (with the correct connection-vs-
        // stream scoping per RFC 9113 §6.9.1) belongs to
        // Connection::process_window_update, which sees the connection state.
        // Rejecting at frame-decode time forced every zero increment — even a
        // stream-scoped one — through the decode-error path, which the listener
        // escalates to a whole-connection GOAWAY, tearing down every sibling
        // stream on a multiplexed connection instead of resetting just the one.
        Ok(Self {
            stream_id: header.stream_id,
            increment,
        })
    }

    /// Encode this frame.
    #[inline]
    pub fn encode(&self, dst: &mut BytesMut) -> Result<(), H2Error> {
        if self.increment == 0 {
            return Err(invalid_window_update_increment_error(
                self.stream_id,
                "WINDOW_UPDATE with zero increment",
            ));
        }
        if self.increment > MAX_WINDOW_UPDATE_INCREMENT {
            return Err(invalid_window_update_increment_error(
                self.stream_id,
                format!(
                    "WINDOW_UPDATE increment {} exceeds 31-bit maximum",
                    self.increment
                ),
            ));
        }

        let header = FrameHeader {
            length: 4,
            frame_type: FrameType::WindowUpdate as u8,
            flags: 0,
            stream_id: self.stream_id,
        };
        header.write(dst);
        dst.put_u32(self.increment);
        Ok(())
    }
}

fn invalid_window_update_increment_error(stream_id: u32, message: impl Into<String>) -> H2Error {
    if stream_id == 0 {
        H2Error::protocol(message)
    } else {
        H2Error::stream(stream_id, ErrorCode::ProtocolError, message)
    }
}

/// CONTINUATION frame (type 0x9).
#[derive(Debug, Clone)]
pub struct ContinuationFrame {
    /// Stream identifier.
    pub stream_id: u32,
    /// Header block fragment.
    pub header_block: Bytes,
    /// True if this ends the header block.
    pub end_headers: bool,
}

impl ContinuationFrame {
    /// Parse a CONTINUATION frame from payload.
    pub fn parse(header: &FrameHeader, payload: Bytes) -> Result<Self, H2Error> {
        if header.stream_id == 0 {
            return Err(H2Error::protocol("CONTINUATION frame with stream ID 0"));
        }

        Ok(Self {
            stream_id: header.stream_id,
            header_block: payload,
            end_headers: header.has_flag(continuation_flags::END_HEADERS),
        })
    }

    /// Encode this frame.
    #[inline]
    pub fn encode(&self, dst: &mut BytesMut) -> Result<(), H2Error> {
        if self.stream_id == 0 {
            return Err(H2Error::protocol("CONTINUATION frame with stream ID 0"));
        }

        let mut flags = 0u8;
        if self.end_headers {
            flags |= continuation_flags::END_HEADERS;
        }

        let header = FrameHeader {
            length: try_frame_length(self.header_block.len())?,
            frame_type: FrameType::Continuation as u8,
            flags,
            stream_id: self.stream_id,
        };
        header.write(dst);
        dst.extend_from_slice(&self.header_block);
        Ok(())
    }
}

/// Parse a complete frame from a buffer.
pub fn parse_frame(header: &FrameHeader, payload: Bytes) -> Result<Frame, H2Error> {
    let frame_type = FrameType::from_u8(header.frame_type);

    match frame_type {
        Some(FrameType::Data) => Ok(Frame::Data(DataFrame::parse(header, payload)?)),
        Some(FrameType::Headers) => Ok(Frame::Headers(HeadersFrame::parse(header, payload)?)),
        Some(FrameType::Priority) => Ok(Frame::Priority(PriorityFrame::parse(header, &payload)?)),
        Some(FrameType::RstStream) => {
            Ok(Frame::RstStream(RstStreamFrame::parse(header, &payload)?))
        }
        Some(FrameType::Settings) => Ok(Frame::Settings(SettingsFrame::parse(header, &payload)?)),
        Some(FrameType::PushPromise) => Ok(Frame::PushPromise(PushPromiseFrame::parse(
            header, payload,
        )?)),
        Some(FrameType::Ping) => Ok(Frame::Ping(PingFrame::parse(header, &payload)?)),
        Some(FrameType::GoAway) => Ok(Frame::GoAway(GoAwayFrame::parse(header, &payload)?)),
        Some(FrameType::WindowUpdate) => Ok(Frame::WindowUpdate(WindowUpdateFrame::parse(
            header, &payload,
        )?)),
        Some(FrameType::Continuation) => Ok(Frame::Continuation(ContinuationFrame::parse(
            header, payload,
        )?)),
        None => Ok(Frame::Unknown {
            frame_type: header.frame_type,
            stream_id: header.stream_id,
            payload,
        }),
    }
}

#[cfg(test)]
#[path = "frame_inline_tests.rs"]
mod tests;
