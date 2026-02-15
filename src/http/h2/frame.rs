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

        let _ = src.split_to(FRAME_HEADER_SIZE);

        Ok(Self {
            length,
            frame_type,
            flags,
            stream_id,
        })
    }

    /// Write this frame header to a buffer.
    pub fn write(&self, dst: &mut BytesMut) {
        dst.reserve(FRAME_HEADER_SIZE);
        dst.put_u8((self.length >> 16) as u8);
        dst.put_u8((self.length >> 8) as u8);
        dst.put_u8(self.length as u8);
        dst.put_u8(self.frame_type);
        dst.put_u8(self.flags);
        dst.put_u8(((self.stream_id >> 24) & 0x7f) as u8);
        dst.put_u8((self.stream_id >> 16) as u8);
        dst.put_u8((self.stream_id >> 8) as u8);
        dst.put_u8(self.stream_id as u8);
    }

    /// Check if the frame has a specific flag set.
    #[must_use]
    pub fn has_flag(&self, flag: u8) -> bool {
        self.flags & flag != 0
    }
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
        }
    }

    /// Encode this frame to bytes.
    pub fn encode(&self, dst: &mut BytesMut) {
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
        }
    }
}

/// DATA frame (type 0x0).
#[derive(Debug, Clone)]
pub struct DataFrame {
    /// Stream identifier.
    pub stream_id: u32,
    /// Payload data.
    pub data: Bytes,
    /// True if this is the last frame for this stream.
    pub end_stream: bool,
}

impl DataFrame {
    /// Create a new DATA frame.
    #[must_use]
    pub fn new(stream_id: u32, data: Bytes, end_stream: bool) -> Self {
        Self {
            stream_id,
            data,
            end_stream,
        }
    }

    /// Parse a DATA frame from payload.
    pub fn parse(header: &FrameHeader, payload: Bytes) -> Result<Self, H2Error> {
        if header.stream_id == 0 {
            return Err(H2Error::protocol("DATA frame with stream ID 0"));
        }

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
        })
    }

    /// Encode this frame.
    pub fn encode(&self, dst: &mut BytesMut) {
        let mut flags = 0u8;
        if self.end_stream {
            flags |= data_flags::END_STREAM;
        }

        let header = FrameHeader {
            length: self.data.len() as u32,
            frame_type: FrameType::Data as u8,
            flags,
            stream_id: self.stream_id,
        };
        header.write(dst);
        dst.extend_from_slice(&self.data);
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

        // Remove padding
        if padded {
            if pad_length > payload.len() {
                return Err(H2Error::protocol(
                    "HEADERS frame padding exceeds data length",
                ));
            }
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
    pub fn encode(&self, dst: &mut BytesMut) {
        let mut flags = 0u8;
        if self.end_stream {
            flags |= headers_flags::END_STREAM;
        }
        if self.end_headers {
            flags |= headers_flags::END_HEADERS;
        }

        let mut payload_len = self.header_block.len();
        if self.priority.is_some() {
            flags |= headers_flags::PRIORITY;
            payload_len += 5;
        }

        let header = FrameHeader {
            length: payload_len as u32,
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
    pub fn encode(&self, dst: &mut BytesMut) {
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
    pub fn encode(&self, dst: &mut BytesMut) {
        let header = FrameHeader {
            length: 4,
            frame_type: FrameType::RstStream as u8,
            flags: 0,
            stream_id: self.stream_id,
        };
        header.write(dst);
        dst.put_u32(self.error_code.into());
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
        let mut cursor = 0;
        while cursor + 6 <= payload.len() {
            let id = ((u16::from(payload[cursor])) << 8) | u16::from(payload[cursor + 1]);
            let value = ((u32::from(payload[cursor + 2])) << 24)
                | ((u32::from(payload[cursor + 3])) << 16)
                | ((u32::from(payload[cursor + 4])) << 8)
                | u32::from(payload[cursor + 5]);

            // RFC 7540 Section 6.5.2: SETTINGS_ENABLE_PUSH MUST be 0 or 1.
            if id == 0x2 && value > 1 {
                return Err(H2Error::protocol("SETTINGS_ENABLE_PUSH must be 0 or 1"));
            }

            if let Some(setting) = Setting::from_id_value(id, value) {
                settings.push(setting);
            }
            cursor += 6;
        }

        Ok(Self { settings, ack })
    }

    /// Encode this frame.
    pub fn encode(&self, dst: &mut BytesMut) {
        let mut flags = 0u8;
        if self.ack {
            flags |= settings_flags::ACK;
        }

        let header = FrameHeader {
            length: (self.settings.len() * 6) as u32,
            frame_type: FrameType::Settings as u8,
            flags,
            stream_id: 0,
        };
        header.write(dst);

        for setting in &self.settings {
            dst.put_u16(setting.id());
            dst.put_u32(setting.value());
        }
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
    pub fn encode(&self, dst: &mut BytesMut) {
        let mut flags = 0u8;
        if self.end_headers {
            flags |= headers_flags::END_HEADERS;
        }

        let header = FrameHeader {
            length: (4 + self.header_block.len()) as u32,
            frame_type: FrameType::PushPromise as u8,
            flags,
            stream_id: self.stream_id,
        };
        header.write(dst);

        dst.put_u32(self.promised_stream_id & 0x7fff_ffff);
        dst.extend_from_slice(&self.header_block);
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
    pub fn encode(&self, dst: &mut BytesMut) {
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
    pub fn encode(&self, dst: &mut BytesMut) {
        let header = FrameHeader {
            length: (8 + self.debug_data.len()) as u32,
            frame_type: FrameType::GoAway as u8,
            flags: 0,
            stream_id: 0,
        };
        header.write(dst);

        dst.put_u32(self.last_stream_id & 0x7fff_ffff);
        dst.put_u32(self.error_code.into());
        dst.extend_from_slice(&self.debug_data);
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

        if increment == 0 {
            // RFC 7540 §6.9: zero increment on a stream is a stream error;
            // on the connection (stream 0) it is a connection error.
            return if header.stream_id == 0 {
                Err(H2Error::protocol("WINDOW_UPDATE with zero increment"))
            } else {
                Err(H2Error::stream(
                    header.stream_id,
                    ErrorCode::ProtocolError,
                    "WINDOW_UPDATE with zero increment",
                ))
            };
        }

        Ok(Self {
            stream_id: header.stream_id,
            increment,
        })
    }

    /// Encode this frame.
    pub fn encode(&self, dst: &mut BytesMut) {
        let header = FrameHeader {
            length: 4,
            frame_type: FrameType::WindowUpdate as u8,
            flags: 0,
            stream_id: self.stream_id,
        };
        header.write(dst);
        dst.put_u32(self.increment & 0x7fff_ffff);
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
    pub fn encode(&self, dst: &mut BytesMut) {
        let mut flags = 0u8;
        if self.end_headers {
            flags |= continuation_flags::END_HEADERS;
        }

        let header = FrameHeader {
            length: self.header_block.len() as u32,
            frame_type: FrameType::Continuation as u8,
            flags,
            stream_id: self.stream_id,
        };
        header.write(dst);
        dst.extend_from_slice(&self.header_block);
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
        None => Err(H2Error::protocol(format!(
            "unknown frame type: {}",
            header.frame_type
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_header_roundtrip() {
        let original = FrameHeader {
            length: 0x0012_3456,
            frame_type: FrameType::Data as u8,
            flags: 0x05,
            stream_id: 0x7654_3210,
        };

        let mut buf = BytesMut::new();
        original.write(&mut buf);
        assert_eq!(buf.len(), FRAME_HEADER_SIZE);

        let parsed = FrameHeader::parse(&mut buf).unwrap();
        // Note: stream_id has 31 bits, so the top bit is masked
        assert_eq!(parsed.length, original.length);
        assert_eq!(parsed.frame_type, original.frame_type);
        assert_eq!(parsed.flags, original.flags);
        assert_eq!(parsed.stream_id, original.stream_id & 0x7fff_ffff);
    }

    #[test]
    fn test_frame_header_parse_insufficient_bytes() {
        let mut buf = BytesMut::from(&b"\x00\x00\x00\x00\x00\x00\x00\x00"[..]);
        let err = FrameHeader::parse(&mut buf).unwrap_err();
        assert_eq!(err.code, ErrorCode::ProtocolError);
    }

    #[test]
    fn test_data_frame_roundtrip() {
        let original = DataFrame::new(1, Bytes::from_static(b"hello"), true);

        let mut buf = BytesMut::new();
        original.encode(&mut buf);

        let header = FrameHeader::parse(&mut buf).unwrap();
        let payload = buf.split_to(header.length as usize).freeze();
        let parsed = DataFrame::parse(&header, payload).unwrap();

        assert_eq!(parsed.stream_id, original.stream_id);
        assert_eq!(parsed.data, original.data);
        assert_eq!(parsed.end_stream, original.end_stream);
    }

    #[test]
    fn test_settings_frame_roundtrip() {
        let original = SettingsFrame::new(vec![
            Setting::HeaderTableSize(4096),
            Setting::MaxConcurrentStreams(100),
            Setting::InitialWindowSize(65535),
        ]);

        let mut buf = BytesMut::new();
        original.encode(&mut buf);

        let header = FrameHeader::parse(&mut buf).unwrap();
        let payload = buf.split_to(header.length as usize).freeze();
        let parsed = SettingsFrame::parse(&header, &payload).unwrap();

        assert!(!parsed.ack);
        assert_eq!(parsed.settings.len(), 3);
    }

    #[test]
    fn test_settings_ack() {
        let original = SettingsFrame::ack();

        let mut buf = BytesMut::new();
        original.encode(&mut buf);

        let header = FrameHeader::parse(&mut buf).unwrap();
        assert_eq!(header.length, 0);
        assert!(header.has_flag(settings_flags::ACK));
    }

    #[test]
    fn test_ping_roundtrip() {
        let original = PingFrame::new([1, 2, 3, 4, 5, 6, 7, 8]);

        let mut buf = BytesMut::new();
        original.encode(&mut buf);

        let header = FrameHeader::parse(&mut buf).unwrap();
        let payload = buf.split_to(header.length as usize).freeze();
        let parsed = PingFrame::parse(&header, &payload).unwrap();

        assert_eq!(parsed.opaque_data, original.opaque_data);
        assert!(!parsed.ack);
    }

    #[test]
    fn test_goaway_roundtrip() {
        let original = GoAwayFrame::new(100, ErrorCode::NoError);

        let mut buf = BytesMut::new();
        original.encode(&mut buf);

        let header = FrameHeader::parse(&mut buf).unwrap();
        let payload = buf.split_to(header.length as usize).freeze();
        let parsed = GoAwayFrame::parse(&header, &payload).unwrap();

        assert_eq!(parsed.last_stream_id, 100);
        assert_eq!(parsed.error_code, ErrorCode::NoError);
    }

    #[test]
    fn test_window_update_roundtrip() {
        let original = WindowUpdateFrame::new(1, 65535);

        let mut buf = BytesMut::new();
        original.encode(&mut buf);

        let header = FrameHeader::parse(&mut buf).unwrap();
        let payload = buf.split_to(header.length as usize).freeze();
        let parsed = WindowUpdateFrame::parse(&header, &payload).unwrap();

        assert_eq!(parsed.stream_id, 1);
        assert_eq!(parsed.increment, 65535);
    }

    // ========================================================================
    // Frame roundtrip tests for all frame types (bd-7lg3)
    // ========================================================================

    #[test]
    fn test_headers_frame_roundtrip() {
        let original = HeadersFrame::new(3, Bytes::from_static(b"header-block"), false, true);

        let mut buf = BytesMut::new();
        original.encode(&mut buf);

        let header = FrameHeader::parse(&mut buf).unwrap();
        let payload = buf.split_to(header.length as usize).freeze();
        let parsed = HeadersFrame::parse(&header, payload).unwrap();

        assert_eq!(parsed.stream_id, original.stream_id);
        assert_eq!(parsed.header_block, original.header_block);
        assert_eq!(parsed.end_stream, original.end_stream);
        assert_eq!(parsed.end_headers, original.end_headers);
    }

    #[test]
    fn test_headers_frame_with_priority_roundtrip() {
        let mut original = HeadersFrame::new(5, Bytes::from_static(b"hdr"), true, true);
        original.priority = Some(PrioritySpec {
            exclusive: true,
            dependency: 1,
            weight: 128,
        });

        let mut buf = BytesMut::new();
        original.encode(&mut buf);

        let header = FrameHeader::parse(&mut buf).unwrap();
        let payload = buf.split_to(header.length as usize).freeze();
        let parsed = HeadersFrame::parse(&header, payload).unwrap();

        assert_eq!(parsed.stream_id, 5);
        assert!(parsed.end_stream);
        assert!(parsed.priority.is_some());
        let p = parsed.priority.unwrap();
        assert!(p.exclusive);
        assert_eq!(p.dependency, 1);
        assert_eq!(p.weight, 128);
    }

    #[test]
    fn test_priority_frame_roundtrip() {
        let original = PriorityFrame {
            stream_id: 7,
            priority: PrioritySpec {
                exclusive: false,
                dependency: 3,
                weight: 64,
            },
        };

        let mut buf = BytesMut::new();
        original.encode(&mut buf);

        let header = FrameHeader::parse(&mut buf).unwrap();
        let payload = buf.split_to(header.length as usize).freeze();
        let parsed = PriorityFrame::parse(&header, &payload).unwrap();

        assert_eq!(parsed.stream_id, original.stream_id);
        assert_eq!(parsed.priority.exclusive, original.priority.exclusive);
        assert_eq!(parsed.priority.dependency, original.priority.dependency);
        assert_eq!(parsed.priority.weight, original.priority.weight);
    }

    #[test]
    fn test_rst_stream_roundtrip() {
        let original = RstStreamFrame::new(11, ErrorCode::Cancel);

        let mut buf = BytesMut::new();
        original.encode(&mut buf);

        let header = FrameHeader::parse(&mut buf).unwrap();
        let payload = buf.split_to(header.length as usize).freeze();
        let parsed = RstStreamFrame::parse(&header, &payload).unwrap();

        assert_eq!(parsed.stream_id, original.stream_id);
        assert_eq!(parsed.error_code, original.error_code);
    }

    #[test]
    fn test_push_promise_roundtrip() {
        let original = PushPromiseFrame {
            stream_id: 1,
            promised_stream_id: 2,
            header_block: Bytes::from_static(b"pushed-headers"),
            end_headers: true,
        };

        let mut buf = BytesMut::new();
        original.encode(&mut buf);

        let header = FrameHeader::parse(&mut buf).unwrap();
        let payload = buf.split_to(header.length as usize).freeze();
        let parsed = PushPromiseFrame::parse(&header, payload).unwrap();

        assert_eq!(parsed.stream_id, original.stream_id);
        assert_eq!(parsed.promised_stream_id, original.promised_stream_id);
        assert_eq!(parsed.header_block, original.header_block);
        assert_eq!(parsed.end_headers, original.end_headers);
    }

    #[test]
    fn test_continuation_roundtrip() {
        let original = ContinuationFrame {
            stream_id: 9,
            header_block: Bytes::from_static(b"continued-headers"),
            end_headers: false,
        };

        let mut buf = BytesMut::new();
        original.encode(&mut buf);

        let header = FrameHeader::parse(&mut buf).unwrap();
        let payload = buf.split_to(header.length as usize).freeze();
        let parsed = ContinuationFrame::parse(&header, payload).unwrap();

        assert_eq!(parsed.stream_id, original.stream_id);
        assert_eq!(parsed.header_block, original.header_block);
        assert_eq!(parsed.end_headers, original.end_headers);
    }

    // ========================================================================
    // Invalid input tests (bd-7lg3)
    // ========================================================================

    #[test]
    fn test_data_frame_stream_id_zero_rejected() {
        let header = FrameHeader {
            length: 5,
            frame_type: FrameType::Data as u8,
            flags: 0,
            stream_id: 0,
        };
        let payload = Bytes::from_static(b"hello");

        let err = DataFrame::parse(&header, payload).unwrap_err();
        assert_eq!(err.code, ErrorCode::ProtocolError);
    }

    #[test]
    fn test_data_frame_invalid_padding() {
        let header = FrameHeader {
            length: 5,
            frame_type: FrameType::Data as u8,
            flags: data_flags::PADDED,
            stream_id: 1,
        };
        // Pad length (10) exceeds remaining data (4 bytes)
        let payload = Bytes::from_static(&[10, b'a', b'b', b'c', b'd']);

        let err = DataFrame::parse(&header, payload).unwrap_err();
        assert_eq!(err.code, ErrorCode::ProtocolError);
    }

    #[test]
    fn test_data_frame_padded_empty_payload_rejected() {
        let header = FrameHeader {
            length: 0,
            frame_type: FrameType::Data as u8,
            flags: data_flags::PADDED,
            stream_id: 1,
        };
        let payload = Bytes::new();

        let err = DataFrame::parse(&header, payload).unwrap_err();
        assert_eq!(err.code, ErrorCode::ProtocolError);
    }

    #[test]
    fn test_data_frame_padding_exact_length_accepted() {
        let header = FrameHeader {
            length: 2,
            frame_type: FrameType::Data as u8,
            flags: data_flags::PADDED,
            stream_id: 1,
        };
        // Pad length equals remaining bytes (1): zero data bytes, all padding.
        // Valid per RFC 7540 §6.1 (pad_length < frame_payload_length).
        let payload = Bytes::from_static(&[1, 0xff]);

        let parsed = DataFrame::parse(&header, payload).unwrap();
        assert_eq!(parsed.stream_id, 1);
        assert!(parsed.data.is_empty());
    }

    #[test]
    fn test_headers_frame_stream_id_zero_rejected() {
        let header = FrameHeader {
            length: 5,
            frame_type: FrameType::Headers as u8,
            flags: headers_flags::END_HEADERS,
            stream_id: 0,
        };
        let payload = Bytes::from_static(b"hdr");

        let err = HeadersFrame::parse(&header, payload).unwrap_err();
        assert_eq!(err.code, ErrorCode::ProtocolError);
    }

    #[test]
    fn test_headers_frame_priority_too_short() {
        let header = FrameHeader {
            length: 3,
            frame_type: FrameType::Headers as u8,
            flags: headers_flags::PRIORITY | headers_flags::END_HEADERS,
            stream_id: 1,
        };
        // Too short for priority (needs 5 bytes)
        let payload = Bytes::from_static(&[0, 0, 0]);

        let err = HeadersFrame::parse(&header, payload).unwrap_err();
        assert_eq!(err.code, ErrorCode::ProtocolError);
    }

    #[test]
    fn test_headers_frame_padded_empty_payload_rejected() {
        let header = FrameHeader {
            length: 0,
            frame_type: FrameType::Headers as u8,
            flags: headers_flags::PADDED | headers_flags::END_HEADERS,
            stream_id: 1,
        };
        let payload = Bytes::new();

        let err = HeadersFrame::parse(&header, payload).unwrap_err();
        assert_eq!(err.code, ErrorCode::ProtocolError);
    }

    #[test]
    fn test_headers_frame_padding_exact_length_accepted() {
        let header = FrameHeader {
            length: 3,
            frame_type: FrameType::Headers as u8,
            flags: headers_flags::PADDED | headers_flags::END_HEADERS,
            stream_id: 1,
        };
        // Pad length (2) equals remaining payload length (2): empty header block, all padding.
        // Valid per RFC 7540 §6.2 (pad_length < frame_payload_length).
        let payload = Bytes::from_static(&[2, b'a', b'b']);

        let parsed = HeadersFrame::parse(&header, payload).unwrap();
        assert_eq!(parsed.stream_id, 1);
        assert!(parsed.header_block.is_empty());
    }

    #[test]
    fn test_priority_frame_stream_id_zero_rejected() {
        let header = FrameHeader {
            length: 5,
            frame_type: FrameType::Priority as u8,
            flags: 0,
            stream_id: 0,
        };
        let payload = Bytes::from_static(&[0, 0, 0, 1, 16]);

        let err = PriorityFrame::parse(&header, &payload).unwrap_err();
        assert_eq!(err.code, ErrorCode::ProtocolError);
    }

    #[test]
    fn test_priority_frame_wrong_size() {
        let header = FrameHeader {
            length: 4,
            frame_type: FrameType::Priority as u8,
            flags: 0,
            stream_id: 1,
        };
        let payload = Bytes::from_static(&[0, 0, 0, 1]);

        let err = PriorityFrame::parse(&header, &payload).unwrap_err();
        assert_eq!(err.code, ErrorCode::FrameSizeError);
        // RFC 7540 §6.3: PRIORITY size error is a stream error, not connection.
        assert_eq!(err.stream_id, Some(1));
    }

    #[test]
    fn test_rst_stream_stream_id_zero_rejected() {
        let header = FrameHeader {
            length: 4,
            frame_type: FrameType::RstStream as u8,
            flags: 0,
            stream_id: 0,
        };
        let payload = Bytes::from_static(&[0, 0, 0, 0]);

        let err = RstStreamFrame::parse(&header, &payload).unwrap_err();
        assert_eq!(err.code, ErrorCode::ProtocolError);
    }

    #[test]
    fn test_rst_stream_wrong_size() {
        let header = FrameHeader {
            length: 3,
            frame_type: FrameType::RstStream as u8,
            flags: 0,
            stream_id: 1,
        };
        let payload = Bytes::from_static(&[0, 0, 0]);

        let err = RstStreamFrame::parse(&header, &payload).unwrap_err();
        assert_eq!(err.code, ErrorCode::FrameSizeError);
    }

    #[test]
    fn test_settings_frame_non_zero_stream_id_rejected() {
        let header = FrameHeader {
            length: 0,
            frame_type: FrameType::Settings as u8,
            flags: 0,
            stream_id: 1,
        };
        let payload = Bytes::new();

        let err = SettingsFrame::parse(&header, &payload).unwrap_err();
        assert_eq!(err.code, ErrorCode::ProtocolError);
    }

    #[test]
    fn test_settings_ack_with_payload_rejected() {
        let header = FrameHeader {
            length: 6,
            frame_type: FrameType::Settings as u8,
            flags: settings_flags::ACK,
            stream_id: 0,
        };
        let payload = Bytes::from_static(&[0, 1, 0, 0, 0, 1]);

        let err = SettingsFrame::parse(&header, &payload).unwrap_err();
        assert_eq!(err.code, ErrorCode::FrameSizeError);
    }

    #[test]
    fn test_settings_wrong_length() {
        let header = FrameHeader {
            length: 5, // Not multiple of 6
            frame_type: FrameType::Settings as u8,
            flags: 0,
            stream_id: 0,
        };
        let payload = Bytes::from_static(&[0, 1, 0, 0, 0]);

        let err = SettingsFrame::parse(&header, &payload).unwrap_err();
        assert_eq!(err.code, ErrorCode::FrameSizeError);
    }

    #[test]
    fn test_push_promise_stream_id_zero_rejected() {
        let header = FrameHeader {
            length: 5,
            frame_type: FrameType::PushPromise as u8,
            flags: headers_flags::END_HEADERS,
            stream_id: 0,
        };
        let payload = Bytes::from_static(&[0, 0, 0, 2, 0]);

        let err = PushPromiseFrame::parse(&header, payload).unwrap_err();
        assert_eq!(err.code, ErrorCode::ProtocolError);
    }

    #[test]
    fn test_push_promise_too_short() {
        let header = FrameHeader {
            length: 3,
            frame_type: FrameType::PushPromise as u8,
            flags: headers_flags::END_HEADERS,
            stream_id: 1,
        };
        let payload = Bytes::from_static(&[0, 0, 2]);

        let err = PushPromiseFrame::parse(&header, payload).unwrap_err();
        assert_eq!(err.code, ErrorCode::ProtocolError);
    }

    #[test]
    fn test_push_promise_padded_empty_payload_rejected() {
        let header = FrameHeader {
            length: 0,
            frame_type: FrameType::PushPromise as u8,
            flags: headers_flags::PADDED | headers_flags::END_HEADERS,
            stream_id: 1,
        };
        let payload = Bytes::new();

        let err = PushPromiseFrame::parse(&header, payload).unwrap_err();
        assert_eq!(err.code, ErrorCode::ProtocolError);
    }

    #[test]
    fn test_push_promise_padding_exceeds_length() {
        let header = FrameHeader {
            length: 5,
            frame_type: FrameType::PushPromise as u8,
            flags: headers_flags::PADDED | headers_flags::END_HEADERS,
            stream_id: 1,
        };
        // Pad length (1) >= remaining header block length (0) after promised stream ID.
        let payload = Bytes::from_static(&[1, 0, 0, 0, 1]);

        let err = PushPromiseFrame::parse(&header, payload).unwrap_err();
        assert_eq!(err.code, ErrorCode::ProtocolError);
    }

    #[test]
    fn test_ping_non_zero_stream_id_rejected() {
        let header = FrameHeader {
            length: 8,
            frame_type: FrameType::Ping as u8,
            flags: 0,
            stream_id: 1,
        };
        let payload = Bytes::from_static(&[0, 0, 0, 0, 0, 0, 0, 0]);

        let err = PingFrame::parse(&header, &payload).unwrap_err();
        assert_eq!(err.code, ErrorCode::ProtocolError);
    }

    #[test]
    fn test_ping_wrong_size() {
        let header = FrameHeader {
            length: 7,
            frame_type: FrameType::Ping as u8,
            flags: 0,
            stream_id: 0,
        };
        let payload = Bytes::from_static(&[0, 0, 0, 0, 0, 0, 0]);

        let err = PingFrame::parse(&header, &payload).unwrap_err();
        assert_eq!(err.code, ErrorCode::FrameSizeError);
    }

    #[test]
    fn test_goaway_non_zero_stream_id_rejected() {
        let header = FrameHeader {
            length: 8,
            frame_type: FrameType::GoAway as u8,
            flags: 0,
            stream_id: 1,
        };
        let payload = Bytes::from_static(&[0, 0, 0, 0, 0, 0, 0, 0]);

        let err = GoAwayFrame::parse(&header, &payload).unwrap_err();
        assert_eq!(err.code, ErrorCode::ProtocolError);
    }

    #[test]
    fn test_goaway_too_short() {
        let header = FrameHeader {
            length: 7,
            frame_type: FrameType::GoAway as u8,
            flags: 0,
            stream_id: 0,
        };
        let payload = Bytes::from_static(&[0, 0, 0, 0, 0, 0, 0]);

        let err = GoAwayFrame::parse(&header, &payload).unwrap_err();
        assert_eq!(err.code, ErrorCode::FrameSizeError);
    }

    #[test]
    fn test_goaway_with_debug_data() {
        let mut original = GoAwayFrame::new(100, ErrorCode::EnhanceYourCalm);
        original.debug_data = Bytes::from_static(b"too many requests");

        let mut buf = BytesMut::new();
        original.encode(&mut buf);

        let header = FrameHeader::parse(&mut buf).unwrap();
        let payload = buf.split_to(header.length as usize).freeze();
        let parsed = GoAwayFrame::parse(&header, &payload).unwrap();

        assert_eq!(parsed.last_stream_id, 100);
        assert_eq!(parsed.error_code, ErrorCode::EnhanceYourCalm);
        assert_eq!(&parsed.debug_data[..], b"too many requests");
    }

    #[test]
    fn test_window_update_wrong_size() {
        let header = FrameHeader {
            length: 3,
            frame_type: FrameType::WindowUpdate as u8,
            flags: 0,
            stream_id: 0,
        };
        let payload = Bytes::from_static(&[0, 0, 0]);

        let err = WindowUpdateFrame::parse(&header, &payload).unwrap_err();
        assert_eq!(err.code, ErrorCode::FrameSizeError);
    }

    #[test]
    fn test_window_update_zero_increment_rejected() {
        // Connection-level (stream 0): connection error per RFC 7540 §6.9
        let header = FrameHeader {
            length: 4,
            frame_type: FrameType::WindowUpdate as u8,
            flags: 0,
            stream_id: 0,
        };
        let payload = Bytes::from_static(&[0, 0, 0, 0]);

        let err = WindowUpdateFrame::parse(&header, &payload).unwrap_err();
        assert_eq!(err.code, ErrorCode::ProtocolError);
        assert_eq!(err.stream_id, None); // connection error
    }

    #[test]
    fn test_window_update_zero_increment_stream_level_is_stream_error() {
        // Stream-level (stream != 0): stream error per RFC 7540 §6.9
        let header = FrameHeader {
            length: 4,
            frame_type: FrameType::WindowUpdate as u8,
            flags: 0,
            stream_id: 3,
        };
        let payload = Bytes::from_static(&[0, 0, 0, 0]);

        let err = WindowUpdateFrame::parse(&header, &payload).unwrap_err();
        assert_eq!(err.code, ErrorCode::ProtocolError);
        assert_eq!(err.stream_id, Some(3)); // stream error, not connection
    }

    #[test]
    fn test_continuation_stream_id_zero_rejected() {
        let header = FrameHeader {
            length: 5,
            frame_type: FrameType::Continuation as u8,
            flags: continuation_flags::END_HEADERS,
            stream_id: 0,
        };
        let payload = Bytes::from_static(b"hdr");

        let err = ContinuationFrame::parse(&header, payload).unwrap_err();
        assert_eq!(err.code, ErrorCode::ProtocolError);
    }

    #[test]
    fn test_unknown_frame_type_rejected() {
        let header = FrameHeader {
            length: 0,
            frame_type: 0xFF,
            flags: 0,
            stream_id: 0,
        };
        let payload = Bytes::new();

        let err = parse_frame(&header, payload).unwrap_err();
        assert_eq!(err.code, ErrorCode::ProtocolError);
    }

    // ========================================================================
    // Size limit tests (bd-7lg3)
    // ========================================================================

    #[test]
    fn test_max_frame_size_constants() {
        assert_eq!(DEFAULT_MAX_FRAME_SIZE, 16_384);
        assert_eq!(MAX_FRAME_SIZE, 16_777_215);
        assert_eq!(MIN_MAX_FRAME_SIZE, 16_384);
        const {
            assert!(DEFAULT_MAX_FRAME_SIZE >= MIN_MAX_FRAME_SIZE);
            assert!(DEFAULT_MAX_FRAME_SIZE <= MAX_FRAME_SIZE);
        }
    }

    #[test]
    fn test_frame_header_length_max() {
        // Test that maximum length (24-bit) is properly encoded/decoded
        let header = FrameHeader {
            length: MAX_FRAME_SIZE,
            frame_type: FrameType::Data as u8,
            flags: 0,
            stream_id: 1,
        };

        let mut buf = BytesMut::new();
        header.write(&mut buf);

        let parsed = FrameHeader::parse(&mut buf).unwrap();
        assert_eq!(parsed.length, MAX_FRAME_SIZE);
    }

    #[test]
    fn test_stream_id_31_bits() {
        // Stream ID is 31 bits, high bit is reserved
        let header = FrameHeader {
            length: 0,
            frame_type: FrameType::Data as u8,
            flags: 0,
            stream_id: 0x7FFF_FFFF, // Max valid stream ID
        };

        let mut buf = BytesMut::new();
        header.write(&mut buf);

        let parsed = FrameHeader::parse(&mut buf).unwrap();
        assert_eq!(parsed.stream_id, 0x7FFF_FFFF);
    }

    #[test]
    fn test_stream_id_reserved_bit_masked() {
        // High bit should be masked off
        let header = FrameHeader {
            length: 0,
            frame_type: FrameType::Data as u8,
            flags: 0,
            stream_id: 0xFFFF_FFFF,
        };

        let mut buf = BytesMut::new();
        header.write(&mut buf);

        let parsed = FrameHeader::parse(&mut buf).unwrap();
        // Reserved bit is masked, so only 31 bits are preserved
        assert_eq!(parsed.stream_id, 0x7FFF_FFFF);
    }

    #[test]
    fn test_frame_type_all_variants() {
        // Ensure all frame types can be parsed from their u8 values
        assert_eq!(FrameType::from_u8(0x0), Some(FrameType::Data));
        assert_eq!(FrameType::from_u8(0x1), Some(FrameType::Headers));
        assert_eq!(FrameType::from_u8(0x2), Some(FrameType::Priority));
        assert_eq!(FrameType::from_u8(0x3), Some(FrameType::RstStream));
        assert_eq!(FrameType::from_u8(0x4), Some(FrameType::Settings));
        assert_eq!(FrameType::from_u8(0x5), Some(FrameType::PushPromise));
        assert_eq!(FrameType::from_u8(0x6), Some(FrameType::Ping));
        assert_eq!(FrameType::from_u8(0x7), Some(FrameType::GoAway));
        assert_eq!(FrameType::from_u8(0x8), Some(FrameType::WindowUpdate));
        assert_eq!(FrameType::from_u8(0x9), Some(FrameType::Continuation));
        assert_eq!(FrameType::from_u8(0xA), None);
        assert_eq!(FrameType::from_u8(0xFF), None);
    }

    #[test]
    fn test_setting_all_variants() {
        // Test all setting types
        assert_eq!(
            Setting::from_id_value(0x1, 4096),
            Some(Setting::HeaderTableSize(4096))
        );
        assert_eq!(
            Setting::from_id_value(0x2, 1),
            Some(Setting::EnablePush(true))
        );
        assert_eq!(
            Setting::from_id_value(0x2, 0),
            Some(Setting::EnablePush(false))
        );
        assert_eq!(
            Setting::from_id_value(0x3, 100),
            Some(Setting::MaxConcurrentStreams(100))
        );
        assert_eq!(
            Setting::from_id_value(0x4, 65535),
            Some(Setting::InitialWindowSize(65535))
        );
        assert_eq!(
            Setting::from_id_value(0x5, 16384),
            Some(Setting::MaxFrameSize(16384))
        );
        assert_eq!(
            Setting::from_id_value(0x6, 8192),
            Some(Setting::MaxHeaderListSize(8192))
        );
        // Unknown settings are ignored per RFC 7540
        assert_eq!(Setting::from_id_value(0x7, 123), None);
        assert_eq!(Setting::from_id_value(0xFF, 456), None);
    }

    #[test]
    fn test_settings_frame_rejects_invalid_enable_push_value() {
        let header = FrameHeader {
            length: 6,
            frame_type: FrameType::Settings as u8,
            flags: 0,
            stream_id: 0,
        };
        let payload = Bytes::from_static(&[0x00, 0x02, 0x00, 0x00, 0x00, 0x02]);

        let err = SettingsFrame::parse(&header, &payload).unwrap_err();
        assert_eq!(err.code, ErrorCode::ProtocolError);
    }

    #[test]
    fn test_setting_id_and_value() {
        let settings = vec![
            Setting::HeaderTableSize(4096),
            Setting::EnablePush(true),
            Setting::MaxConcurrentStreams(100),
            Setting::InitialWindowSize(65535),
            Setting::MaxFrameSize(16384),
            Setting::MaxHeaderListSize(8192),
        ];

        for setting in settings {
            assert_eq!(
                Setting::from_id_value(setting.id(), setting.value()),
                Some(setting)
            );
        }
    }

    #[test]
    fn test_window_update_max_increment() {
        // Maximum valid increment is 2^31 - 1
        let original = WindowUpdateFrame::new(0, 0x7FFF_FFFF);

        let mut buf = BytesMut::new();
        original.encode(&mut buf);

        let header = FrameHeader::parse(&mut buf).unwrap();
        let payload = buf.split_to(header.length as usize).freeze();
        let parsed = WindowUpdateFrame::parse(&header, &payload).unwrap();

        assert_eq!(parsed.increment, 0x7FFF_FFFF);
    }

    #[test]
    fn test_error_code_all_variants() {
        // Test all error codes can be parsed and converted
        let codes = [
            (0x0, ErrorCode::NoError),
            (0x1, ErrorCode::ProtocolError),
            (0x3, ErrorCode::FlowControlError),
            (0x4, ErrorCode::SettingsTimeout),
            (0x5, ErrorCode::StreamClosed),
            (0x6, ErrorCode::FrameSizeError),
            (0x7, ErrorCode::RefusedStream),
            (0x8, ErrorCode::Cancel),
            (0x9, ErrorCode::CompressionError),
            (0xa, ErrorCode::ConnectError),
            (0xb, ErrorCode::EnhanceYourCalm),
            (0xc, ErrorCode::InadequateSecurity),
            (0xd, ErrorCode::Http11Required),
        ];

        for (value, expected) in codes {
            let code = ErrorCode::from_u32(value);
            assert_eq!(code, expected);
            assert_eq!(u32::from(code), value);
        }

        // Unknown codes map to InternalError
        assert_eq!(ErrorCode::from_u32(0xFFFF), ErrorCode::InternalError);
    }

    #[test]
    fn test_partial_header_parse_insufficient_bytes() {
        let mut buf = BytesMut::from(&[0, 0, 5, 0, 0, 0, 0][..]); // Only 7 bytes, need 9

        let result = FrameHeader::parse(&mut buf);
        assert!(result.is_err());
    }
}
