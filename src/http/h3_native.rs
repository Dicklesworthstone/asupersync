//! Native HTTP/3 protocol primitives over QUIC streams.
//!
//! This module implements:
//! - HTTP/3 frame encode/decode
//! - SETTINGS payload handling
//! - control-stream ordering checks
//! - pseudo-header validation helpers

use crate::bytes::{Bytes, BytesMut};
use crate::net::quic_core::{decode_varint, encode_varint};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::Ipv6Addr;

use super::h2::hpack::{
    decode_huffman as hpack_decode_huffman, encode_huffman_to_buffer as hpack_encode_huffman,
    huffman_encoded_size as hpack_huffman_encoded_size,
};

const H3_FRAME_DATA: u64 = 0x0;
const H3_FRAME_HEADERS: u64 = 0x1;
const H3_FRAME_CANCEL_PUSH: u64 = 0x3;
const H3_FRAME_SETTINGS: u64 = 0x4;
const H3_FRAME_PUSH_PROMISE: u64 = 0x5;
const H3_FRAME_GOAWAY: u64 = 0x7;
const H3_FRAME_MAX_PUSH_ID: u64 = 0xD;
/// HTTP/3 DATAGRAM frame type (RFC 9297).
const H3_FRAME_DATAGRAM: u64 = 0x30;
const H3_STREAM_TYPE_CONTROL: u64 = 0x00;
const H3_STREAM_TYPE_PUSH: u64 = 0x01;
const H3_STREAM_TYPE_QPACK_ENCODER: u64 = 0x02;
const H3_STREAM_TYPE_QPACK_DECODER: u64 = 0x03;

/// HTTP/3 SETTINGS identifier: QPACK max table capacity.
pub const H3_SETTING_QPACK_MAX_TABLE_CAPACITY: u64 = 0x01;
/// HTTP/3 SETTINGS identifier: max field section size.
pub const H3_SETTING_MAX_FIELD_SECTION_SIZE: u64 = 0x06;
/// HTTP/3 SETTINGS identifier: QPACK blocked streams.
pub const H3_SETTING_QPACK_BLOCKED_STREAMS: u64 = 0x07;
/// HTTP/3 SETTINGS identifier: enable CONNECT protocol.
pub const H3_SETTING_ENABLE_CONNECT_PROTOCOL: u64 = 0x08;
/// HTTP/3 SETTINGS identifier: H3 datagrams.
pub const H3_SETTING_H3_DATAGRAM: u64 = 0x33;

/// Maximum number of decoded headers per QPACK field section (DoS protection).
const QPACK_MAX_DECODED_HEADERS: usize = 1000;

/// HTTP/3 errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum H3NativeError {
    /// Input buffer ended unexpectedly.
    UnexpectedEof,
    /// Malformed frame.
    InvalidFrame(&'static str),
    /// Frame payload exceeds maximum allowed size.
    FrameTooLarge {
        /// Actual decoded payload size.
        payload_size: usize,
        /// Configured maximum payload size.
        max_size: usize,
    },
    /// Duplicate setting key.
    DuplicateSetting(u64),
    /// Invalid setting value.
    InvalidSettingValue(u64),
    /// Control stream protocol violation.
    ControlProtocol(&'static str),
    /// Unidirectional stream protocol violation.
    StreamProtocol(&'static str),
    /// QPACK policy mismatch for this connection.
    QpackPolicy(&'static str),
    /// Invalid request pseudo headers.
    InvalidRequestPseudoHeader(&'static str),
    /// Invalid response pseudo headers.
    InvalidResponsePseudoHeader(&'static str),
    /// New request stream rejected because peer-advertised concurrency cap is full.
    ///
    /// Per RFC 9114 §5.1.2, an HTTP/3 endpoint MUST respect the QUIC
    /// `initial_max_streams_bidi` / MAX_STREAMS limits. The local state machine
    /// returns this error when a frame arrives for a previously-unseen
    /// request-stream id while `active_request_stream_count >= max`.
    ConcurrentStreamLimitExceeded {
        /// The number of currently active streams.
        active: u64,
        /// The maximum allowed streams.
        limit: u64,
    },
}

impl fmt::Display for H3NativeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEof => write!(f, "unexpected EOF"),
            Self::InvalidFrame(msg) => write!(f, "invalid frame: {msg}"),
            Self::FrameTooLarge {
                payload_size,
                max_size,
            } => write!(
                f,
                "frame payload too large: {payload_size} bytes exceeds limit of {max_size} bytes"
            ),
            Self::DuplicateSetting(id) => write!(f, "duplicate setting: 0x{id:x}"),
            Self::InvalidSettingValue(id) => write!(f, "invalid setting value: 0x{id:x}"),
            Self::ControlProtocol(msg) => write!(f, "control stream protocol violation: {msg}"),
            Self::StreamProtocol(msg) => write!(f, "stream protocol violation: {msg}"),
            Self::QpackPolicy(msg) => write!(f, "qpack policy violation: {msg}"),
            Self::InvalidRequestPseudoHeader(msg) => {
                write!(f, "invalid request pseudo-header set: {msg}")
            }
            Self::InvalidResponsePseudoHeader(msg) => {
                write!(f, "invalid response pseudo-header set: {msg}")
            }
            Self::ConcurrentStreamLimitExceeded { active, limit } => write!(
                f,
                "concurrent request stream limit exceeded: {active} active, limit {limit}"
            ),
        }
    }
}

impl std::error::Error for H3NativeError {}

/// QPACK operating mode for this HTTP/3 mapping.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum H3QpackMode {
    /// Only static-table / literal paths are allowed.
    #[default]
    StaticOnly,
    /// Dynamic table is permitted.
    DynamicTableAllowed,
}

/// Local endpoint role for role-sensitive HTTP/3 validation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum H3EndpointRole {
    /// The local endpoint is an HTTP/3 client receiving server control frames.
    #[default]
    Client,
    /// The local endpoint is an HTTP/3 server receiving client control frames.
    Server,
}

/// Connection-level configuration for native HTTP/3 mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct H3ConnectionConfig {
    /// QPACK policy.
    pub qpack_mode: H3QpackMode,
    /// Endpoint role for GOAWAY validation.
    pub endpoint_role: H3EndpointRole,
    /// Maximum frame payload size in bytes (RFC 9114 §4.2).
    pub max_frame_payload_size: usize,
    /// Peer-advertised limit on concurrent client-initiated bidirectional
    /// request streams (QUIC `initial_max_streams_bidi` / MAX_STREAMS).
    ///
    /// `None` disables enforcement at the HTTP/3 layer. Per RFC 9114 §5.1.2,
    /// endpoints MUST respect QUIC concurrency limits; set this from the
    /// transport parameter negotiated at connection start, and update it as
    /// MAX_STREAMS frames arrive.
    pub max_concurrent_request_streams: Option<u64>,
}

impl Default for H3ConnectionConfig {
    fn default() -> Self {
        Self {
            qpack_mode: H3QpackMode::StaticOnly,
            endpoint_role: H3EndpointRole::Client,
            // 1MB default limit aligns with common HTTP/3 implementations
            max_frame_payload_size: 1024 * 1024,
            max_concurrent_request_streams: None,
        }
    }
}

impl H3ConnectionConfig {
    /// Enable dynamic QPACK table support.
    ///
    /// This allows the use of dynamic table operations for more efficient
    /// header compression, but requires state synchronization between endpoints.
    #[must_use]
    pub fn with_dynamic_qpack(mut self) -> Self {
        self.qpack_mode = H3QpackMode::DynamicTableAllowed;
        self
    }
}

/// Remote unidirectional stream type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H3UniStreamType {
    /// HTTP/3 control stream.
    Control,
    /// Push stream.
    Push,
    /// QPACK encoder stream.
    QpackEncoder,
    /// QPACK decoder stream.
    QpackDecoder,
    /// Unknown stream type — RFC 9114 §6.2 requires ignoring unknown types.
    Unknown(u64),
}

impl H3UniStreamType {
    /// Decode a raw HTTP/3 unidirectional stream type.
    #[must_use]
    pub fn decode(stream_type: u64) -> Self {
        match stream_type {
            H3_STREAM_TYPE_CONTROL => Self::Control,
            H3_STREAM_TYPE_PUSH => Self::Push,
            H3_STREAM_TYPE_QPACK_ENCODER => Self::QpackEncoder,
            H3_STREAM_TYPE_QPACK_DECODER => Self::QpackDecoder,
            other => Self::Unknown(other),
        }
    }
}

/// Unknown HTTP/3 setting preserved as-is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownSetting {
    /// Setting identifier.
    pub id: u64,
    /// Setting value.
    pub value: u64,
}

/// Decoded HTTP/3 SETTINGS payload.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct H3Settings {
    /// SETTINGS_QPACK_MAX_TABLE_CAPACITY.
    pub qpack_max_table_capacity: Option<u64>,
    /// SETTINGS_MAX_FIELD_SECTION_SIZE.
    pub max_field_section_size: Option<u64>,
    /// SETTINGS_QPACK_BLOCKED_STREAMS.
    pub qpack_blocked_streams: Option<u64>,
    /// SETTINGS_ENABLE_CONNECT_PROTOCOL (boolean as 0/1).
    pub enable_connect_protocol: Option<bool>,
    /// SETTINGS_H3_DATAGRAM (boolean as 0/1).
    pub h3_datagram: Option<bool>,
    /// Unknown settings.
    pub unknown: Vec<UnknownSetting>,
}

impl H3Settings {
    /// Encode SETTINGS payload bytes.
    pub fn encode_payload(&self, out: &mut Vec<u8>) -> Result<(), H3NativeError> {
        if let Some(v) = self.qpack_max_table_capacity {
            encode_setting(out, H3_SETTING_QPACK_MAX_TABLE_CAPACITY, v)?;
        }
        if let Some(v) = self.max_field_section_size {
            encode_setting(out, H3_SETTING_MAX_FIELD_SECTION_SIZE, v)?;
        }
        if let Some(v) = self.qpack_blocked_streams {
            encode_setting(out, H3_SETTING_QPACK_BLOCKED_STREAMS, v)?;
        }
        if let Some(v) = self.enable_connect_protocol {
            encode_setting(out, H3_SETTING_ENABLE_CONNECT_PROTOCOL, u64::from(v))?;
        }
        if let Some(v) = self.h3_datagram {
            encode_setting(out, H3_SETTING_H3_DATAGRAM, u64::from(v))?;
        }
        for s in &self.unknown {
            if is_http2_reserved_settings_id(s.id) {
                return Err(H3NativeError::InvalidSettingValue(s.id));
            }
            encode_setting(out, s.id, s.value)?;
        }
        Ok(())
    }

    /// Decode SETTINGS payload bytes.
    pub fn decode_payload(input: &[u8]) -> Result<Self, H3NativeError> {
        let mut settings = Self::default();
        let mut seen_ids = BTreeSet::new();
        let mut pos = 0usize;
        while pos < input.len() {
            let (id, id_len) = decode_varint(input.get(pos..).ok_or(H3NativeError::UnexpectedEof)?)
                .map_err(|_| H3NativeError::InvalidFrame("invalid setting id varint"))?;
            pos += id_len;
            let (value, val_len) =
                decode_varint(input.get(pos..).ok_or(H3NativeError::UnexpectedEof)?)
                    .map_err(|_| H3NativeError::InvalidFrame("invalid setting value varint"))?;
            pos += val_len;

            if !seen_ids.insert(id) {
                return Err(H3NativeError::DuplicateSetting(id));
            }

            match id {
                // RFC 9114 §7.2.4.1: HTTP/2 reserved setting identifiers
                // MUST NOT be sent; receipt is a connection error.
                id if is_http2_reserved_settings_id(id) => {
                    return Err(H3NativeError::InvalidSettingValue(id));
                }
                H3_SETTING_QPACK_MAX_TABLE_CAPACITY => {
                    settings.qpack_max_table_capacity = Some(value);
                }
                H3_SETTING_MAX_FIELD_SECTION_SIZE => {
                    settings.max_field_section_size = Some(value);
                }
                H3_SETTING_QPACK_BLOCKED_STREAMS => {
                    settings.qpack_blocked_streams = Some(value);
                }
                H3_SETTING_ENABLE_CONNECT_PROTOCOL => {
                    settings.enable_connect_protocol = Some(parse_bool_setting(id, value)?);
                }
                H3_SETTING_H3_DATAGRAM => {
                    settings.h3_datagram = Some(parse_bool_setting(id, value)?);
                }
                _ => settings.unknown.push(UnknownSetting { id, value }),
            }
        }
        Ok(settings)
    }
}

const fn is_http2_reserved_settings_id(id: u64) -> bool {
    matches!(id, 0x00 | 0x02 | 0x03 | 0x04 | 0x05)
}

fn parse_bool_setting(id: u64, value: u64) -> Result<bool, H3NativeError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(H3NativeError::InvalidSettingValue(id)),
    }
}

fn encode_setting(out: &mut Vec<u8>, id: u64, value: u64) -> Result<(), H3NativeError> {
    encode_varint(id, out).map_err(|_| H3NativeError::InvalidFrame("setting id out of range"))?;
    encode_varint(value, out)
        .map_err(|_| H3NativeError::InvalidFrame("setting value out of range"))?;
    Ok(())
}

/// HTTP/3 frame representation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum H3Frame {
    /// DATA frame.
    Data(Vec<u8>),
    /// HEADERS frame (QPACK-encoded header block).
    Headers(Vec<u8>),
    /// CANCEL_PUSH frame.
    CancelPush(u64),
    /// SETTINGS frame.
    Settings(H3Settings),
    /// PUSH_PROMISE frame.
    PushPromise {
        /// Push identifier.
        push_id: u64,
        /// QPACK field section payload.
        field_block: Vec<u8>,
    },
    /// GOAWAY frame.
    Goaway(u64),
    /// MAX_PUSH_ID frame.
    MaxPushId(u64),
    /// DATAGRAM frame (RFC 9297) with quarter-stream-id and payload.
    Datagram {
        /// Quarter-stream ID for context identification.
        quarter_stream_id: u64,
        /// Application payload data.
        payload: Vec<u8>,
    },
    /// Unknown frame preserved as raw payload.
    Unknown {
        /// Frame type identifier.
        frame_type: u64,
        /// Raw frame payload.
        payload: Vec<u8>,
    },
}

impl H3Frame {
    /// Encode a single frame.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), H3NativeError> {
        let mut payload = Vec::new();
        let frame_type = match self {
            Self::Data(bytes) => {
                payload.extend_from_slice(bytes);
                H3_FRAME_DATA
            }
            Self::Headers(bytes) => {
                payload.extend_from_slice(bytes);
                H3_FRAME_HEADERS
            }
            Self::CancelPush(id) => {
                encode_varint(*id, &mut payload)
                    .map_err(|_| H3NativeError::InvalidFrame("cancel_push id out of range"))?;
                H3_FRAME_CANCEL_PUSH
            }
            Self::Settings(settings) => {
                settings.encode_payload(&mut payload)?;
                H3_FRAME_SETTINGS
            }
            Self::PushPromise {
                push_id,
                field_block,
            } => {
                encode_varint(*push_id, &mut payload)
                    .map_err(|_| H3NativeError::InvalidFrame("push_id out of range"))?;
                payload.extend_from_slice(field_block);
                H3_FRAME_PUSH_PROMISE
            }
            Self::Goaway(id) => {
                encode_varint(*id, &mut payload)
                    .map_err(|_| H3NativeError::InvalidFrame("goaway id out of range"))?;
                H3_FRAME_GOAWAY
            }
            Self::MaxPushId(id) => {
                encode_varint(*id, &mut payload)
                    .map_err(|_| H3NativeError::InvalidFrame("max_push_id out of range"))?;
                H3_FRAME_MAX_PUSH_ID
            }
            Self::Datagram {
                quarter_stream_id,
                payload: data,
            } => {
                encode_varint(*quarter_stream_id, &mut payload)
                    .map_err(|_| H3NativeError::InvalidFrame("quarter_stream_id out of range"))?;
                payload.extend_from_slice(data);
                H3_FRAME_DATAGRAM
            }
            Self::Unknown {
                frame_type,
                payload: body,
            } => {
                payload.extend_from_slice(body);
                *frame_type
            }
        };

        encode_varint(frame_type, out)
            .map_err(|_| H3NativeError::InvalidFrame("frame type out of range"))?;
        encode_varint(payload.len() as u64, out)
            .map_err(|_| H3NativeError::InvalidFrame("frame length out of range"))?;
        out.extend_from_slice(&payload);
        Ok(())
    }

    /// Decode one frame, returning `(frame, consumed)`.
    pub fn decode(
        input: &[u8],
        config: &H3ConnectionConfig,
    ) -> Result<(Self, usize), H3NativeError> {
        let (frame_type, type_len) =
            decode_varint(input).map_err(|_| H3NativeError::InvalidFrame("frame type varint"))?;
        let (len, len_len) = decode_varint(&input[type_len..])
            .map_err(|_| H3NativeError::InvalidFrame("frame length varint"))?;
        let len: usize = len
            .try_into()
            .map_err(|_| H3NativeError::InvalidFrame("frame length exceeds addressable range"))?;

        // RFC 9114 §4.2: Enforce maximum frame payload size limit
        if len > config.max_frame_payload_size {
            return Err(H3NativeError::FrameTooLarge {
                payload_size: len,
                max_size: config.max_frame_payload_size,
            });
        }

        let payload_start = type_len + len_len;

        // DATAGRAM frames (RFC 9297) are bounded: their declared length
        // fully describes the payload. A truncated input is a malformed
        // frame from the peer rather than a streaming short read. We also
        // need to distinguish "quarter_stream_id varint truncated inside
        // the payload window" from "declared length exceeds what arrived".
        if frame_type == H3_FRAME_DATAGRAM {
            let available = input.len().saturating_sub(payload_start);
            let bounded_payload = &input[payload_start..payload_start + available.min(len)];
            let (quarter_stream_id, n) = decode_varint(bounded_payload)
                .map_err(|_| H3NativeError::InvalidFrame("quarter stream id varint"))?;
            if available < len {
                return Err(H3NativeError::InvalidFrame("insufficient frame payload"));
            }
            let payload = &input[payload_start..payload_start + len];
            let consumed = payload_start + len;
            return Ok((
                Self::Datagram {
                    quarter_stream_id,
                    payload: payload[n..].to_vec(),
                },
                consumed,
            ));
        }

        if input.len().saturating_sub(payload_start) < len {
            return Err(H3NativeError::UnexpectedEof);
        }
        let payload = &input[payload_start..payload_start + len];
        let consumed = payload_start + len;

        let frame = match frame_type {
            H3_FRAME_DATA => Self::Data(payload.to_vec()),
            H3_FRAME_HEADERS => Self::Headers(payload.to_vec()),
            H3_FRAME_CANCEL_PUSH => {
                let (id, n) = decode_varint(payload)
                    .map_err(|_| H3NativeError::InvalidFrame("cancel_push payload"))?;
                if n != payload.len() {
                    return Err(H3NativeError::InvalidFrame("cancel_push trailing bytes"));
                }
                Self::CancelPush(id)
            }
            H3_FRAME_SETTINGS => Self::Settings(H3Settings::decode_payload(payload)?),
            H3_FRAME_PUSH_PROMISE => {
                let (push_id, n) = decode_varint(payload)
                    .map_err(|_| H3NativeError::InvalidFrame("push_promise push_id"))?;
                let field_block = &payload[n..];
                // br-asupersync-2gzkbh — RFC 9114 §7.2.5: a PUSH_PROMISE
                // frame's "Encoded Field Section" is mandatory and
                // non-empty. An empty field_block carries no headers and
                // therefore cannot represent a valid promised request;
                // reject as H3_FRAME_ERROR. The wire format leaves room
                // for an empty payload after the push_id varint
                // (n == payload.len()), so we must check explicitly.
                if field_block.is_empty() {
                    return Err(H3NativeError::InvalidFrame(
                        "push_promise empty field_block (RFC 9114 §7.2.5)",
                    ));
                }
                Self::PushPromise {
                    push_id,
                    field_block: field_block.to_vec(),
                }
            }
            H3_FRAME_GOAWAY => {
                let (id, n) = decode_varint(payload)
                    .map_err(|_| H3NativeError::InvalidFrame("goaway payload"))?;
                if n != payload.len() {
                    return Err(H3NativeError::InvalidFrame("goaway trailing bytes"));
                }
                Self::Goaway(id)
            }
            H3_FRAME_MAX_PUSH_ID => {
                let (id, n) = decode_varint(payload)
                    .map_err(|_| H3NativeError::InvalidFrame("max_push_id payload"))?;
                if n != payload.len() {
                    return Err(H3NativeError::InvalidFrame("max_push_id trailing bytes"));
                }
                Self::MaxPushId(id)
            }
            _ => Self::Unknown {
                frame_type,
                payload: payload.to_vec(),
            },
        };
        Ok((frame, consumed))
    }
}

/// Control stream state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct H3ControlState {
    local_settings_sent: bool,
    remote_settings_received: bool,
}

impl H3ControlState {
    /// Construct default state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Build and mark the local SETTINGS frame.
    pub fn build_local_settings(&mut self, settings: H3Settings) -> Result<H3Frame, H3NativeError> {
        if self.local_settings_sent {
            return Err(H3NativeError::ControlProtocol(
                "SETTINGS already sent on local control stream",
            ));
        }
        self.local_settings_sent = true;
        Ok(H3Frame::Settings(settings))
    }

    /// Apply a received control-stream frame with protocol checks.
    pub fn on_remote_control_frame(&mut self, frame: &H3Frame) -> Result<(), H3NativeError> {
        if self.remote_settings_received {
            match frame {
                H3Frame::Settings(_) => {
                    return Err(H3NativeError::ControlProtocol(
                        "duplicate SETTINGS on remote control stream",
                    ));
                }
                H3Frame::Data(_)
                | H3Frame::Headers(_)
                | H3Frame::PushPromise { .. }
                | H3Frame::Datagram { .. } => {
                    return Err(H3NativeError::ControlProtocol(
                        "frame type not allowed on control stream",
                    ));
                }
                H3Frame::CancelPush(_)
                | H3Frame::Goaway(_)
                | H3Frame::MaxPushId(_)
                | H3Frame::Unknown { .. } => {}
            }
            Ok(())
        } else {
            match frame {
                H3Frame::Settings(_) => {
                    self.remote_settings_received = true;
                    Ok(())
                }
                _ => Err(H3NativeError::ControlProtocol(
                    "first remote control frame must be SETTINGS",
                )),
            }
        }
    }
}

/// Validate that a frame is allowed on bidirectional request/response streams.
///
/// Per RFC 9114 §6.1, bidirectional streams are used for request/response
/// exchanges and should only carry DATA, HEADERS, PUSH_PROMISE, and DATAGRAM frames.
/// Control frames like SETTINGS, GOAWAY, CANCEL_PUSH, and MAX_PUSH_ID belong
/// on unidirectional control streams.
pub fn validate_bidirectional_frame(frame: &H3Frame) -> Result<(), H3NativeError> {
    match frame {
        // Allowed on bidirectional streams per RFC 9114 §6.1
        H3Frame::Data(_) | H3Frame::Headers(_) => Ok(()),

        // PUSH_PROMISE can be sent by servers on request streams per RFC 9114 §4.6
        H3Frame::PushPromise { .. } => Ok(()),

        // DATAGRAM frames are sent on bidirectional streams per RFC 9297
        H3Frame::Datagram { .. } => Ok(()),

        // Control frames not allowed on bidirectional streams
        H3Frame::Settings(_) => Err(H3NativeError::StreamProtocol(
            "SETTINGS frame not allowed on bidirectional stream",
        )),
        H3Frame::CancelPush(_) => Err(H3NativeError::StreamProtocol(
            "CANCEL_PUSH frame not allowed on bidirectional stream",
        )),
        H3Frame::Goaway(_) => Err(H3NativeError::StreamProtocol(
            "GOAWAY frame not allowed on bidirectional stream",
        )),
        H3Frame::MaxPushId(_) => Err(H3NativeError::StreamProtocol(
            "MAX_PUSH_ID frame not allowed on bidirectional stream",
        )),

        // Unknown frame types MUST be ignored on request streams per
        // RFC 9114 §7.2.8 ("Reserved Frame Types"):
        //
        //   "Endpoints MUST NOT consider these frames to have any meaning
        //    upon receipt. The payload and length of the frame are otherwise
        //    unconstrained."
        //
        // The same section requires that GREASE/forward-compatibility frames
        // (frame types of the form 0x1f * N + 0x21) be silently skipped so
        // that future protocol extensions can roll out without coordinated
        // upgrades. Returning an error here previously broke that guarantee
        // and made the implementation incompatible with any peer that GREASEd
        // its frame stream (br-asupersync-94bp7i).
        H3Frame::Unknown { .. } => Ok(()),
    }
}

/// HTTP/3 pseudo-header block (decoded representation).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct H3PseudoHeaders {
    /// `:method`.
    pub method: Option<String>,
    /// `:scheme`.
    pub scheme: Option<String>,
    /// `:authority`.
    pub authority: Option<String>,
    /// `:path`.
    pub path: Option<String>,
    /// `:status`.
    pub status: Option<u16>,
    /// `:protocol` (RFC 8441 extended CONNECT protocol).
    pub protocol: Option<String>,
}

/// HTTP/3 request-head representation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct H3RequestHead {
    /// Validated request pseudo headers.
    pub pseudo: H3PseudoHeaders,
    /// Non-pseudo headers.
    pub headers: Vec<(String, String)>,
}

impl H3RequestHead {
    /// Construct and validate request head.
    pub fn new(
        pseudo: H3PseudoHeaders,
        headers: Vec<(String, String)>,
    ) -> Result<Self, H3NativeError> {
        validate_request_pseudo_headers(&pseudo)?;
        for (name, value) in &headers {
            validate_header_name(name)?;
            if name.starts_with(':') {
                return Err(H3NativeError::InvalidRequestPseudoHeader(
                    "pseudo headers must not appear in regular header list",
                ));
            }
            validate_header_value(value)?;
        }
        Ok(Self { pseudo, headers })
    }

    /// Construct and validate request head with extended CONNECT protocol support.
    ///
    /// When `enable_connect_protocol` is true, CONNECT requests are allowed to
    /// include :scheme and :path pseudo-headers per RFC 8441.
    pub fn new_with_settings(
        pseudo: H3PseudoHeaders,
        headers: Vec<(String, String)>,
        enable_connect_protocol: bool,
    ) -> Result<Self, H3NativeError> {
        validate_request_pseudo_headers_with_settings(&pseudo, enable_connect_protocol)?;
        for (name, value) in &headers {
            validate_header_name(name)?;
            if name.starts_with(':') {
                return Err(H3NativeError::InvalidRequestPseudoHeader(
                    "pseudo headers must not appear in regular header list",
                ));
            }
            validate_header_value(value)?;
        }
        Ok(Self { pseudo, headers })
    }

    /// Validate CONNECT method according to RFC 8441 extended CONNECT protocol.
    ///
    /// This method should be called for CONNECT requests to ensure proper
    /// validation based on whether extended CONNECT protocol is enabled.
    pub fn validate_connect_method(
        &self,
        enable_connect_protocol: bool,
    ) -> Result<(), H3NativeError> {
        if self.pseudo.method.as_deref() != Some("CONNECT") {
            return Err(H3NativeError::InvalidRequestPseudoHeader(
                "validate_connect_method called on non-CONNECT request",
            ));
        }
        validate_request_pseudo_headers_with_settings(&self.pseudo, enable_connect_protocol)
    }
}

/// HTTP/3 response-head representation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct H3ResponseHead {
    /// HTTP status code.
    pub status: u16,
    /// Non-pseudo headers.
    pub headers: Vec<(String, String)>,
}

impl H3ResponseHead {
    /// Construct and validate response head.
    pub fn new(status: u16, headers: Vec<(String, String)>) -> Result<Self, H3NativeError> {
        let pseudo = H3PseudoHeaders {
            status: Some(status),
            ..H3PseudoHeaders::default()
        };
        validate_response_pseudo_headers(&pseudo)?;
        for (name, value) in &headers {
            validate_header_name(name)?;
            if name.starts_with(':') {
                return Err(H3NativeError::InvalidResponsePseudoHeader(
                    "response must not include request pseudo headers",
                ));
            }
            validate_header_value(value)?;
        }
        Ok(Self { status, headers })
    }
}

/// Static-only QPACK planning item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QpackFieldPlan {
    /// Indexed static-table entry.
    StaticIndex(u64),
    /// Indexed dynamic-table entry.
    DynamicIndex(u64),
    /// Literal header field (name/value).
    Literal {
        /// Header name.
        name: String,
        /// Header value.
        value: String,
    },
    /// Literal with dynamic table name reference.
    DynamicNameLiteral {
        /// Dynamic table index for name.
        name_index: u64,
        /// Header value.
        value: String,
    },
}

/// Name-reference source for QPACK encoder-stream instructions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QpackInstructionNameRef {
    /// Name reference into the QPACK static table.
    Static(u64),
    /// Name reference into the QPACK dynamic table.
    Dynamic(u64),
}

/// Side-effect-free RFC 9204 encoder-stream instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QpackEncoderInstruction {
    /// Set the dynamic table capacity.
    SetDynamicTableCapacity {
        /// New dynamic table capacity.
        capacity: u64,
    },
    /// Insert a field line using a static or dynamic name reference.
    InsertWithNameReference {
        /// Static or dynamic name reference.
        name: QpackInstructionNameRef,
        /// Header value to insert.
        value: String,
    },
    /// Insert a field line with a literal name.
    InsertWithoutNameReference {
        /// Header name to insert.
        name: String,
        /// Header value to insert.
        value: String,
    },
    /// Duplicate an existing dynamic table entry.
    Duplicate {
        /// Dynamic table index carried by the instruction.
        index: u64,
    },
}

/// Side-effect-free RFC 9204 decoder-stream instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QpackDecoderInstruction {
    /// Acknowledge successful processing of a stream field section.
    HeaderAcknowledgement {
        /// Stream identifier being acknowledged.
        stream_id: u64,
    },
    /// Notify that a stream has been cancelled.
    StreamCancellation {
        /// Stream identifier being cancelled.
        stream_id: u64,
    },
    /// Increment the peer-known insert count.
    InsertCountIncrement {
        /// Non-zero insert count increment.
        increment: u64,
    },
}

/// Build a static-only QPACK plan for a validated request head.
#[must_use]
pub fn qpack_static_plan_for_request(head: &H3RequestHead) -> Vec<QpackFieldPlan> {
    let mut out = Vec::new();
    if let Some(method) = &head.pseudo.method {
        if let Some(idx) = qpack_static_method_index(method) {
            out.push(QpackFieldPlan::StaticIndex(idx));
        } else {
            out.push(QpackFieldPlan::Literal {
                name: ":method".to_string(),
                value: method.clone(),
            });
        }
    }
    if let Some(scheme) = &head.pseudo.scheme {
        if let Some(idx) = qpack_static_scheme_index(scheme) {
            out.push(QpackFieldPlan::StaticIndex(idx));
        } else {
            out.push(QpackFieldPlan::Literal {
                name: ":scheme".to_string(),
                value: scheme.clone(),
            });
        }
    }
    if let Some(path) = &head.pseudo.path {
        if path == "/" {
            out.push(QpackFieldPlan::StaticIndex(1));
        } else {
            out.push(QpackFieldPlan::Literal {
                name: ":path".to_string(),
                value: path.clone(),
            });
        }
    }
    if let Some(authority) = &head.pseudo.authority {
        out.push(QpackFieldPlan::Literal {
            name: ":authority".to_string(),
            value: authority.clone(),
        });
    }
    for (name, value) in &head.headers {
        out.push(QpackFieldPlan::Literal {
            name: name.clone(),
            value: value.clone(),
        });
    }
    out
}

/// Build a static-only QPACK plan for a validated response head.
#[must_use]
pub fn qpack_static_plan_for_response(head: &H3ResponseHead) -> Vec<QpackFieldPlan> {
    let mut out = Vec::new();
    if let Some(idx) = qpack_static_status_index(head.status) {
        out.push(QpackFieldPlan::StaticIndex(idx));
    } else {
        out.push(QpackFieldPlan::Literal {
            name: ":status".to_string(),
            value: head.status.to_string(),
        });
    }
    for (name, value) in &head.headers {
        out.push(QpackFieldPlan::Literal {
            name: name.clone(),
            value: value.clone(),
        });
    }
    out
}

/// Encode a wire-level QPACK field section from a static/literal plan.
pub fn qpack_encode_field_section(plan: &[QpackFieldPlan]) -> Result<Vec<u8>, H3NativeError> {
    qpack_encode_field_section_with_context(plan, None)
}

/// Encode a wire-level QPACK field section with optional dynamic-table context.
///
/// Dynamic references require a `QpackContext` so the encoder can derive the
/// correct Required Insert Count / Base and map absolute insertion IDs to the
/// wire-level relative indices defined by RFC 9204.
pub fn qpack_encode_field_section_with_context(
    plan: &[QpackFieldPlan],
    qpack_context: Option<&QpackContext>,
) -> Result<Vec<u8>, H3NativeError> {
    let mut out = Vec::new();
    let required_insert_count = qpack_plan_required_insert_count(plan, qpack_context)?;
    let encoded_insert_count = qpack_encode_required_insert_count(
        required_insert_count,
        qpack_context.map_or(0, |context| context.max_table_capacity),
    )?;
    qpack_encode_prefixed_int(&mut out, 0, 8, encoded_insert_count)?;
    // Emit Base = Required Insert Count (S=0, Delta Base=0) so all currently
    // known dynamic references can be encoded as pre-base relative indices.
    qpack_encode_prefixed_int(&mut out, 0, 7, 0)?;
    let base = required_insert_count;

    for field in plan {
        match field {
            QpackFieldPlan::StaticIndex(index) => {
                if qpack_static_entry(*index).is_none() {
                    return Err(H3NativeError::InvalidFrame("unknown static qpack index"));
                }
                // Indexed field line: 1 T Index(6+), T=1 for static table.
                qpack_encode_prefixed_int(&mut out, 0b1100_0000, 6, *index)?;
            }
            QpackFieldPlan::DynamicIndex(index) => {
                let context = qpack_context.ok_or(H3NativeError::InvalidFrame(
                    "dynamic table context required",
                ))?;
                if qpack_dynamic_entry(context.dynamic_table(), *index).is_none() {
                    return Err(H3NativeError::InvalidFrame("unknown dynamic qpack index"));
                }
                let relative = qpack_absolute_to_relative(base, *index)?;
                // Indexed field line: 1 T Index(6+), T=0 for dynamic table.
                qpack_encode_prefixed_int(&mut out, 0b1000_0000, 6, relative)?;
            }
            QpackFieldPlan::Literal { name, value } => {
                // Literal field line with literal name: 001 N H NameLen(3+)
                // N=0, H set opportunistically when Huffman is smaller.
                qpack_encode_string(&mut out, 0b0010_0000, 3, name)?;
                // Value string literal: H=0 + ValueLen(7+)
                qpack_encode_string(&mut out, 0, 7, value)?;
            }
            QpackFieldPlan::DynamicNameLiteral { name_index, value } => {
                let context = qpack_context.ok_or(H3NativeError::InvalidFrame(
                    "dynamic table context required",
                ))?;
                if qpack_dynamic_name(context.dynamic_table(), *name_index).is_none() {
                    return Err(H3NativeError::InvalidFrame(
                        "unknown dynamic qpack name index",
                    ));
                }
                let relative = qpack_absolute_to_relative(base, *name_index)?;
                // Literal field line with name reference: 01 N T NameIndex(4+),
                // T=0 for dynamic table references.
                qpack_encode_prefixed_int(&mut out, 0b0100_0000, 4, relative)?;
                qpack_encode_string(&mut out, 0, 7, value)?;
            }
        }
    }
    Ok(out)
}

/// Decode a wire-level QPACK field section into static/literal planning items.
///
/// In `StaticOnly` mode, all dynamic references are rejected with
/// `H3NativeError::QpackPolicy`.
pub fn qpack_decode_field_section(
    input: &[u8],
    mode: H3QpackMode,
) -> Result<Vec<QpackFieldPlan>, H3NativeError> {
    qpack_decode_field_section_with_context(input, mode, None)
}

fn qpack_decode_required_insert_count(
    encoded_insert_count: u64,
    total_inserts: u64,
    max_table_capacity: usize,
) -> Result<u64, H3NativeError> {
    if encoded_insert_count == 0 {
        return Ok(0);
    }

    let max_entries = (max_table_capacity / 32) as u64;
    if max_entries == 0 {
        return Err(H3NativeError::QpackPolicy(
            "required insert count requires dynamic table capacity",
        ));
    }

    let full_range = max_entries
        .checked_mul(2)
        .ok_or(H3NativeError::InvalidFrame(
            "required insert count range overflow",
        ))?;
    if encoded_insert_count > full_range {
        return Err(H3NativeError::InvalidFrame(
            "required insert count exceeds qpack full range",
        ));
    }

    let max_value = total_inserts
        .checked_add(max_entries)
        .ok_or(H3NativeError::InvalidFrame(
            "required insert count exceeds addressable range",
        ))?;
    let max_wrapped = (max_value / full_range) * full_range;
    // Calculate required insert count with overflow protection
    let mut required_insert_count = max_wrapped
        .saturating_add(encoded_insert_count)
        .saturating_sub(1);

    if required_insert_count > max_value {
        if required_insert_count <= full_range {
            return Err(H3NativeError::InvalidFrame(
                "required insert count decodes below zero",
            ));
        }
        required_insert_count -= full_range;
    }

    if required_insert_count == 0 {
        return Err(H3NativeError::InvalidFrame(
            "required insert count must decode to non-zero",
        ));
    }

    Ok(required_insert_count)
}

fn qpack_decode_base(
    required_insert_count: u64,
    sign: bool,
    delta_base: u64,
) -> Result<u64, H3NativeError> {
    if sign {
        let signed_delta = delta_base
            .checked_add(1)
            .ok_or(H3NativeError::InvalidFrame(
                "delta base exceeds required insert count",
            ))?;
        required_insert_count
            .checked_sub(signed_delta)
            .ok_or(H3NativeError::InvalidFrame(
                "delta base exceeds required insert count",
            ))
    } else {
        required_insert_count
            .checked_add(delta_base)
            .ok_or(H3NativeError::InvalidFrame(
                "base exceeds addressable range",
            ))
    }
}

fn qpack_encode_required_insert_count(
    required_insert_count: u64,
    max_table_capacity: usize,
) -> Result<u64, H3NativeError> {
    if required_insert_count == 0 {
        return Ok(0);
    }

    let max_entries = (max_table_capacity / 32) as u64;
    if max_entries == 0 {
        return Err(H3NativeError::QpackPolicy(
            "required insert count requires dynamic table capacity",
        ));
    }

    let full_range = max_entries
        .checked_mul(2)
        .ok_or(H3NativeError::InvalidFrame(
            "required insert count range overflow",
        ))?;
    Ok((required_insert_count % full_range) + 1)
}

fn qpack_plan_required_insert_count(
    plan: &[QpackFieldPlan],
    qpack_context: Option<&QpackContext>,
) -> Result<u64, H3NativeError> {
    let needs_dynamic = plan.iter().any(|field| {
        matches!(
            field,
            QpackFieldPlan::DynamicIndex(_) | QpackFieldPlan::DynamicNameLiteral { .. }
        )
    });
    if !needs_dynamic {
        return Ok(0);
    }

    let context = qpack_context.ok_or(H3NativeError::InvalidFrame(
        "dynamic table context required",
    ))?;
    Ok(context.dynamic_table().insertion_counter())
}

/// Encode one RFC 9204 encoder-stream instruction.
pub fn qpack_encode_encoder_instruction(
    out: &mut Vec<u8>,
    instruction: &QpackEncoderInstruction,
) -> Result<(), H3NativeError> {
    match instruction {
        QpackEncoderInstruction::SetDynamicTableCapacity { capacity } => {
            qpack_encode_prefixed_int(out, 0b0010_0000, 5, *capacity)?;
        }
        QpackEncoderInstruction::InsertWithNameReference { name, value } => {
            match name {
                QpackInstructionNameRef::Static(index) => {
                    qpack_encode_prefixed_int(out, 0b1100_0000, 6, *index)?;
                }
                QpackInstructionNameRef::Dynamic(index) => {
                    qpack_encode_prefixed_int(out, 0b1000_0000, 6, *index)?;
                }
            }
            qpack_encode_string(out, 0, 7, value)?;
        }
        QpackEncoderInstruction::InsertWithoutNameReference { name, value } => {
            qpack_encode_string(out, 0b0100_0000, 5, name)?;
            qpack_encode_string(out, 0, 7, value)?;
        }
        QpackEncoderInstruction::Duplicate { index } => {
            qpack_encode_prefixed_int(out, 0, 5, *index)?;
        }
    }
    Ok(())
}

/// Decode one RFC 9204 encoder-stream instruction.
pub fn qpack_decode_encoder_instruction(
    input: &[u8],
) -> Result<(QpackEncoderInstruction, usize), H3NativeError> {
    let first = *input.first().ok_or(H3NativeError::UnexpectedEof)?;
    if (first & 0b1000_0000) != 0 {
        let (index, index_extra) = qpack_decode_prefixed_int(first, 6, &input[1..])?;
        let pos = 1 + index_extra;
        let value_first = *input.get(pos).ok_or(H3NativeError::UnexpectedEof)?;
        let (value, value_extra) = qpack_decode_string(value_first, 7, &input[pos + 1..])?;
        let name = if (first & 0b0100_0000) != 0 {
            QpackInstructionNameRef::Static(index)
        } else {
            QpackInstructionNameRef::Dynamic(index)
        };
        return Ok((
            QpackEncoderInstruction::InsertWithNameReference { name, value },
            // Calculate position with overflow protection
            pos.saturating_add(1).saturating_add(value_extra),
        ));
    }

    if (first & 0b0100_0000) != 0 {
        let (name, name_extra) = qpack_decode_string(first, 5, &input[1..])?;
        let pos = 1 + name_extra;
        let value_first = *input.get(pos).ok_or(H3NativeError::UnexpectedEof)?;
        let (value, value_extra) = qpack_decode_string(value_first, 7, &input[pos + 1..])?;
        return Ok((
            QpackEncoderInstruction::InsertWithoutNameReference { name, value },
            // Calculate position with overflow protection
            pos.saturating_add(1).saturating_add(value_extra),
        ));
    }

    if (first & 0b0010_0000) != 0 {
        let (capacity, extra) = qpack_decode_prefixed_int(first, 5, &input[1..])?;
        return Ok((
            QpackEncoderInstruction::SetDynamicTableCapacity { capacity },
            1 + extra,
        ));
    }

    let (index, extra) = qpack_decode_prefixed_int(first, 5, &input[1..])?;
    Ok((QpackEncoderInstruction::Duplicate { index }, 1 + extra))
}

/// Encode one RFC 9204 decoder-stream instruction.
pub fn qpack_encode_decoder_instruction(
    out: &mut Vec<u8>,
    instruction: &QpackDecoderInstruction,
) -> Result<(), H3NativeError> {
    match instruction {
        QpackDecoderInstruction::HeaderAcknowledgement { stream_id } => {
            qpack_encode_prefixed_int(out, 0b1000_0000, 7, *stream_id)?;
        }
        QpackDecoderInstruction::StreamCancellation { stream_id } => {
            qpack_encode_prefixed_int(out, 0b0100_0000, 6, *stream_id)?;
        }
        QpackDecoderInstruction::InsertCountIncrement { increment } => {
            if *increment == 0 {
                return Err(H3NativeError::InvalidFrame(
                    "qpack insert count increment must be non-zero",
                ));
            }
            qpack_encode_prefixed_int(out, 0, 6, *increment)?;
        }
    }
    Ok(())
}

/// Decode one RFC 9204 decoder-stream instruction.
pub fn qpack_decode_decoder_instruction(
    input: &[u8],
) -> Result<(QpackDecoderInstruction, usize), H3NativeError> {
    let first = *input.first().ok_or(H3NativeError::UnexpectedEof)?;
    if (first & 0b1000_0000) != 0 {
        let (stream_id, extra) = qpack_decode_prefixed_int(first, 7, &input[1..])?;
        return Ok((
            QpackDecoderInstruction::HeaderAcknowledgement { stream_id },
            1 + extra,
        ));
    }

    if (first & 0b0100_0000) != 0 {
        let (stream_id, extra) = qpack_decode_prefixed_int(first, 6, &input[1..])?;
        return Ok((
            QpackDecoderInstruction::StreamCancellation { stream_id },
            1 + extra,
        ));
    }

    let (increment, extra) = qpack_decode_prefixed_int(first, 6, &input[1..])?;
    if increment == 0 {
        return Err(H3NativeError::InvalidFrame(
            "qpack insert count increment must be non-zero",
        ));
    }
    Ok((
        QpackDecoderInstruction::InsertCountIncrement { increment },
        1 + extra,
    ))
}

/// Deterministic state for RFC 9204 decoder-stream feedback.
///
/// This is the accounting an encoder needs after receiving peer decoder-stream
/// instructions: acknowledged/cancelled stream IDs, released dynamic-table
/// references, and the peer's Known Received Count.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QpackDecoderFeedbackState {
    known_received_count: u64,
    acknowledged_streams: BTreeSet<u64>,
    cancelled_streams: BTreeSet<u64>,
    outstanding_references: BTreeMap<u64, Vec<u64>>,
    first_error: Option<H3NativeError>,
}

impl QpackDecoderFeedbackState {
    /// Construct empty decoder-feedback state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Peer Known Received Count after Insert Count Increment instructions.
    #[must_use]
    pub fn known_received_count(&self) -> u64 {
        self.known_received_count
    }

    /// Streams acknowledged by Header Acknowledgement instructions.
    #[must_use]
    pub fn acknowledged_stream_ids(&self) -> &BTreeSet<u64> {
        &self.acknowledged_streams
    }

    /// Streams cancelled by Stream Cancellation instructions.
    #[must_use]
    pub fn cancelled_stream_ids(&self) -> &BTreeSet<u64> {
        &self.cancelled_streams
    }

    /// Total dynamic references still protected by live field sections.
    #[must_use]
    pub fn outstanding_reference_count(&self) -> usize {
        self.outstanding_references.values().map(Vec::len).sum()
    }

    /// Dynamic references still protected by one stream.
    #[must_use]
    pub fn stream_outstanding_reference_count(&self, stream_id: u64) -> usize {
        self.outstanding_references
            .get(&stream_id)
            .map_or(0, Vec::len)
    }

    /// First decoder-feedback error observed by this state machine.
    #[must_use]
    pub fn first_error(&self) -> Option<&H3NativeError> {
        self.first_error.as_ref()
    }

    /// Track the dynamic-table references protected by a stream field section.
    ///
    /// The caller supplies absolute insertion IDs referenced by the encoded
    /// field section. Entries are reference-protected until the stream is
    /// acknowledged or cancelled.
    pub fn track_stream_references(
        &mut self,
        context: &mut QpackContext,
        stream_id: u64,
        references: &[u64],
    ) -> Result<(), H3NativeError> {
        if self.acknowledged_streams.contains(&stream_id) {
            return self.fail(H3NativeError::InvalidFrame(
                "qpack stream already acknowledged",
            ));
        }
        if self.cancelled_streams.contains(&stream_id) {
            return self.fail(H3NativeError::InvalidFrame(
                "qpack stream already cancelled",
            ));
        }
        if self.outstanding_references.contains_key(&stream_id) {
            return self.fail(H3NativeError::InvalidFrame("qpack stream already tracked"));
        }
        for insertion_id in references {
            if context
                .dynamic_table()
                .get_by_insertion_id(*insertion_id)
                .is_none()
            {
                return self.fail(H3NativeError::InvalidFrame(
                    "unknown dynamic qpack reference for stream",
                ));
            }
        }
        for insertion_id in references {
            let referenced = context.dynamic_table_mut().reference_entry(*insertion_id);
            debug_assert!(referenced, "prechecked qpack reference must exist");
        }
        self.outstanding_references
            .insert(stream_id, references.to_vec());
        Ok(())
    }

    fn apply_header_acknowledgement(
        &mut self,
        context: &mut QpackContext,
        stream_id: u64,
    ) -> Result<(), H3NativeError> {
        if self.acknowledged_streams.contains(&stream_id) {
            return self.fail(H3NativeError::InvalidFrame(
                "duplicate qpack header acknowledgement",
            ));
        }
        if self.cancelled_streams.contains(&stream_id) {
            return self.fail(H3NativeError::InvalidFrame(
                "qpack acknowledgement after stream cancellation",
            ));
        }
        self.release_stream_references(context, stream_id)?;
        self.acknowledged_streams.insert(stream_id);
        Ok(())
    }

    fn apply_stream_cancellation(
        &mut self,
        context: &mut QpackContext,
        stream_id: u64,
    ) -> Result<(), H3NativeError> {
        if self.cancelled_streams.contains(&stream_id) {
            return self.fail(H3NativeError::InvalidFrame(
                "duplicate qpack stream cancellation",
            ));
        }
        if self.acknowledged_streams.contains(&stream_id) {
            return self.fail(H3NativeError::InvalidFrame(
                "qpack stream cancellation after acknowledgement",
            ));
        }
        self.release_stream_references(context, stream_id)?;
        self.cancelled_streams.insert(stream_id);
        Ok(())
    }

    fn release_stream_references(
        &mut self,
        context: &mut QpackContext,
        stream_id: u64,
    ) -> Result<(), H3NativeError> {
        let Some(references) = self.outstanding_references.get(&stream_id) else {
            return self.fail(H3NativeError::InvalidFrame(
                "unknown qpack decoder feedback stream",
            ));
        };
        let references = references.clone();
        for insertion_id in &references {
            if context
                .dynamic_table()
                .get_by_insertion_id(*insertion_id)
                .is_none()
            {
                return self.fail(H3NativeError::InvalidFrame(
                    "tracked dynamic qpack reference missing",
                ));
            }
        }
        self.outstanding_references.remove(&stream_id);
        for insertion_id in references {
            let released = context.dynamic_table_mut().unreference_entry(insertion_id);
            debug_assert!(released, "prechecked qpack reference must still exist");
        }
        Ok(())
    }

    fn apply_insert_count_increment(
        &mut self,
        increment: u64,
        insertion_counter: u64,
    ) -> Result<(), H3NativeError> {
        if increment == 0 {
            return self.fail(H3NativeError::InvalidFrame(
                "qpack decoder feedback increment must be non-zero",
            ));
        }
        let Some(next) = self.known_received_count.checked_add(increment) else {
            return self.fail(H3NativeError::InvalidFrame(
                "qpack known received count overflow",
            ));
        };
        // RFC 9204 §4.4.3: the Known Received Count must never exceed the number
        // of entries the encoder has actually inserted. A peer that drives it past
        // the insertion counter could prematurely flip blocked streams to Ready
        // (unblock gates on required_insert_count <= known_received_count), so this
        // is a decoder-stream error, not a silently-accepted advance.
        if next > insertion_counter {
            return self.fail(H3NativeError::InvalidFrame(
                "qpack known received count exceeds encoder insert count",
            ));
        }
        self.known_received_count = next;
        Ok(())
    }

    fn fail<T>(&mut self, error: H3NativeError) -> Result<T, H3NativeError> {
        self.record_error(&error);
        Err(error)
    }

    fn record_error(&mut self, error: &H3NativeError) {
        if self.first_error.is_none() {
            self.first_error = Some(error.clone());
        }
    }
}

/// Apply one RFC 9204 decoder-stream instruction to decoder-feedback state.
///
/// This updates feedback accounting only; dynamic table mutations remain owned
/// by encoder-stream instruction application.
pub fn qpack_apply_decoder_instruction(
    feedback: &mut QpackDecoderFeedbackState,
    context: &mut QpackContext,
    mode: H3QpackMode,
    instruction: &QpackDecoderInstruction,
) -> Result<(), H3NativeError> {
    if mode != H3QpackMode::DynamicTableAllowed {
        let error = H3NativeError::QpackPolicy("decoder feedback requires dynamic qpack mode");
        feedback.record_error(&error);
        return Err(error);
    }

    match instruction {
        QpackDecoderInstruction::HeaderAcknowledgement { stream_id } => {
            feedback.apply_header_acknowledgement(context, *stream_id)
        }
        QpackDecoderInstruction::StreamCancellation { stream_id } => {
            feedback.apply_stream_cancellation(context, *stream_id)
        }
        QpackDecoderInstruction::InsertCountIncrement { increment } => feedback
            .apply_insert_count_increment(*increment, context.dynamic_table().insertion_counter()),
    }
}

/// Decoded QPACK field-section prefix metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QpackFieldSectionMetadata {
    encoded_insert_count: u64,
    required_insert_count: u64,
    base: u64,
    prefix_len: usize,
}

impl QpackFieldSectionMetadata {
    /// Encoded Required Insert Count carried on the wire.
    #[must_use]
    pub fn encoded_insert_count(&self) -> u64 {
        self.encoded_insert_count
    }

    /// Decoded Required Insert Count.
    #[must_use]
    pub fn required_insert_count(&self) -> u64 {
        self.required_insert_count
    }

    /// Decoded QPACK Base value.
    #[must_use]
    pub fn base(&self) -> u64 {
        self.base
    }

    /// Number of bytes consumed by the field-section prefix.
    #[must_use]
    pub fn prefix_len(&self) -> usize {
        self.prefix_len
    }
}

/// Inspect only the QPACK field-section prefix.
pub fn qpack_field_section_metadata(
    input: &[u8],
    mode: H3QpackMode,
    qpack_context: Option<&QpackContext>,
) -> Result<QpackFieldSectionMetadata, H3NativeError> {
    let mut pos = 0usize;
    let first = *input.get(pos).ok_or(H3NativeError::UnexpectedEof)?;
    pos += 1;
    let (encoded_insert_count, ric_extra) = qpack_decode_prefixed_int(first, 8, &input[pos..])?;
    pos += ric_extra;

    let second = *input.get(pos).ok_or(H3NativeError::UnexpectedEof)?;
    pos += 1;
    let sign = (second & 0x80) != 0;
    let (delta_base, db_extra) = qpack_decode_prefixed_int(second, 7, &input[pos..])?;
    pos += db_extra;

    match mode {
        H3QpackMode::StaticOnly => {
            if encoded_insert_count != 0 {
                return Err(H3NativeError::QpackPolicy(
                    "required insert count must be zero in static-only mode",
                ));
            }
            if sign || delta_base != 0 {
                return Err(H3NativeError::QpackPolicy(
                    "base must be zero in static-only mode",
                ));
            }
            Ok(QpackFieldSectionMetadata {
                encoded_insert_count,
                required_insert_count: 0,
                base: 0,
                prefix_len: pos,
            })
        }
        H3QpackMode::DynamicTableAllowed => {
            if encoded_insert_count > 65536 {
                return Err(H3NativeError::QpackPolicy(
                    "required insert count exceeds reasonable limit",
                ));
            }
            if encoded_insert_count == 0 {
                if sign || delta_base != 0 {
                    return Err(H3NativeError::InvalidFrame(
                        "base must be zero without required insert count",
                    ));
                }
                return Ok(QpackFieldSectionMetadata {
                    encoded_insert_count,
                    required_insert_count: 0,
                    base: 0,
                    prefix_len: pos,
                });
            }

            let context = qpack_context.ok_or(H3NativeError::InvalidFrame(
                "dynamic table context required",
            ))?;
            let required_insert_count = qpack_decode_required_insert_count(
                encoded_insert_count,
                context.dynamic_table().insertion_counter(),
                context.max_table_capacity,
            )?;
            let base = qpack_decode_base(required_insert_count, sign, delta_base)?;
            Ok(QpackFieldSectionMetadata {
                encoded_insert_count,
                required_insert_count,
                base,
                prefix_len: pos,
            })
        }
    }
}

/// Scheduler status for a QPACK field section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QpackBlockedStreamStatus {
    /// The peer can process the field section with its Known Received Count.
    Ready,
    /// The field section is blocked on Required Insert Count.
    Blocked,
    /// The stream was cancelled and any protected references were released.
    Cancelled,
    /// The field section failed scheduling or feedback processing.
    Failed,
}

/// Inspectable record for a QPACK-blocked stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QpackBlockedStreamRecord {
    stream_id: u64,
    required_insert_count: u64,
    base: u64,
    status: QpackBlockedStreamStatus,
    blocked_reason: Option<&'static str>,
    protected_references: Vec<u64>,
    blocked_field_section: Option<Vec<u8>>,
    first_failure: Option<H3NativeError>,
}

impl QpackBlockedStreamRecord {
    fn new(
        stream_id: u64,
        metadata: &QpackFieldSectionMetadata,
        status: QpackBlockedStreamStatus,
        blocked_reason: Option<&'static str>,
        protected_references: Vec<u64>,
    ) -> Self {
        Self {
            stream_id,
            required_insert_count: metadata.required_insert_count(),
            base: metadata.base(),
            status,
            blocked_reason,
            protected_references,
            blocked_field_section: None,
            first_failure: None,
        }
    }

    fn failed(
        stream_id: u64,
        metadata: Option<&QpackFieldSectionMetadata>,
        error: H3NativeError,
    ) -> Self {
        Self {
            stream_id,
            required_insert_count: metadata
                .map_or(0, QpackFieldSectionMetadata::required_insert_count),
            base: metadata.map_or(0, QpackFieldSectionMetadata::base),
            status: QpackBlockedStreamStatus::Failed,
            blocked_reason: None,
            protected_references: Vec::new(),
            blocked_field_section: None,
            first_failure: Some(error),
        }
    }

    fn record_failure(&mut self, error: &H3NativeError) {
        if self.first_failure.is_none() {
            self.first_failure = Some(error.clone());
        }
        if self.status != QpackBlockedStreamStatus::Cancelled {
            self.status = QpackBlockedStreamStatus::Failed;
            self.blocked_reason = None;
        }
    }

    fn is_reapable_terminal(&self) -> bool {
        self.status != QpackBlockedStreamStatus::Blocked
            && self.protected_references.is_empty()
            && self.blocked_field_section.is_none()
    }

    /// Stream ID associated with this field section.
    #[must_use]
    pub fn stream_id(&self) -> u64 {
        self.stream_id
    }

    /// Decoded Required Insert Count for this field section.
    #[must_use]
    pub fn required_insert_count(&self) -> u64 {
        self.required_insert_count
    }

    /// Decoded Base for this field section.
    #[must_use]
    pub fn base(&self) -> u64 {
        self.base
    }

    /// Current scheduler status.
    #[must_use]
    pub fn status(&self) -> QpackBlockedStreamStatus {
        self.status
    }

    /// Reason the stream is currently blocked, if any.
    #[must_use]
    pub fn blocked_reason(&self) -> Option<&'static str> {
        self.blocked_reason
    }

    /// Dynamic-table insertion IDs protected until ack/cancel.
    #[must_use]
    pub fn protected_references(&self) -> &[u64] {
        &self.protected_references
    }

    /// First scheduler or feedback failure observed for this stream.
    #[must_use]
    pub fn first_failure(&self) -> Option<&H3NativeError> {
        self.first_failure.as_ref()
    }
}

/// Cap on retained terminal records in the scheduler's `streams` map. `Blocked`
/// records and `Ready` records with protected references are still active and
/// are never reaped by this cap.
///
/// Without a cap the map is insert-only — every `submit_*` adds a per-stream
/// record (success, Ready, Cancelled, or failure) and nothing removes them — so
/// over a long-lived connection serving many short requests (monotonically
/// increasing stream IDs) it grows without bound. We reap the OLDEST unreferenced
/// terminal records (lowest stream_id) first. This bounds retained terminal
/// history while preserving records that still protect dynamic-table entries.
const MAX_RETAINED_TERMINAL_RECORDS: usize = 1024;

/// QPACK blocked-stream scheduler for outbound field sections.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QpackBlockedStreamScheduler {
    settings_blocked_streams: u64,
    streams: BTreeMap<u64, QpackBlockedStreamRecord>,
    first_failure: Option<H3NativeError>,
}

impl QpackBlockedStreamScheduler {
    /// Create a scheduler with the peer SETTINGS_QPACK_BLOCKED_STREAMS limit.
    #[must_use]
    pub fn new(settings_blocked_streams: u64) -> Self {
        Self {
            settings_blocked_streams,
            streams: BTreeMap::new(),
            first_failure: None,
        }
    }

    /// Create a scheduler from decoded HTTP/3 settings.
    #[must_use]
    pub fn from_settings(settings: &H3Settings) -> Self {
        Self::new(settings.qpack_blocked_streams.unwrap_or(0))
    }

    /// Peer SETTINGS_QPACK_BLOCKED_STREAMS limit.
    #[must_use]
    pub fn settings_blocked_streams(&self) -> u64 {
        self.settings_blocked_streams
    }

    /// Number of streams currently blocked on Required Insert Count.
    #[must_use]
    pub fn blocked_stream_count(&self) -> u64 {
        self.streams
            .values()
            .filter(|record| record.status == QpackBlockedStreamStatus::Blocked)
            .count() as u64
    }

    /// Total per-stream records currently retained; exposed so callers/tests can
    /// observe the scheduler's bounded terminal memory.
    #[must_use]
    pub fn tracked_record_count(&self) -> usize {
        self.streams.len()
    }

    /// Reap the oldest unreferenced terminal records once they exceed
    /// [`MAX_RETAINED_TERMINAL_RECORDS`], bounding the `streams` map for
    /// long-lived connections. Never removes `Blocked` records or `Ready`
    /// records that still protect dynamic-table entries.
    /// BTreeMap iteration is ascending by stream_id, so the oldest streams (whose
    /// acknowledgement/cancellation has already been processed) are reaped first.
    fn reap_excess_records(&mut self) {
        let terminal = self
            .streams
            .values()
            .filter(|record| record.is_reapable_terminal())
            .count();
        if terminal <= MAX_RETAINED_TERMINAL_RECORDS {
            return;
        }
        let excess = terminal - MAX_RETAINED_TERMINAL_RECORDS;
        let victims: Vec<u64> = self
            .streams
            .iter()
            .filter(|(_, record)| record.is_reapable_terminal())
            .take(excess)
            .map(|(stream_id, _)| *stream_id)
            .collect();
        for stream_id in victims {
            self.streams.remove(&stream_id);
        }
    }

    /// Lookup a stream record.
    #[must_use]
    pub fn record(&self, stream_id: u64) -> Option<&QpackBlockedStreamRecord> {
        self.streams.get(&stream_id)
    }

    /// First scheduler-level failure observed.
    #[must_use]
    pub fn first_failure(&self) -> Option<&H3NativeError> {
        self.first_failure.as_ref()
    }

    /// Schedule one outbound QPACK field section.
    pub fn submit_field_section(
        &mut self,
        context: &mut QpackContext,
        feedback: &mut QpackDecoderFeedbackState,
        mode: H3QpackMode,
        stream_id: u64,
        field_section: &[u8],
    ) -> Result<QpackBlockedStreamStatus, H3NativeError> {
        // Bound the streams map before adding another per-stream record.
        self.reap_excess_records();
        if self.streams.contains_key(&stream_id) {
            return self.fail(H3NativeError::StreamProtocol(
                "qpack stream already scheduled",
            ));
        }

        let metadata = match qpack_field_section_metadata(field_section, mode, Some(context)) {
            Ok(metadata) => metadata,
            Err(error) => {
                self.streams.insert(
                    stream_id,
                    QpackBlockedStreamRecord::failed(stream_id, None, error.clone()),
                );
                return self.fail(error);
            }
        };
        let context_opt = (mode == H3QpackMode::DynamicTableAllowed).then_some(&*context);
        let plan = match qpack_decode_field_section_with_context(field_section, mode, context_opt) {
            Ok(plan) => plan,
            Err(error) => {
                self.streams.insert(
                    stream_id,
                    QpackBlockedStreamRecord::failed(stream_id, Some(&metadata), error.clone()),
                );
                return self.fail(error);
            }
        };
        let references = qpack_plan_dynamic_references(&plan);
        let will_block = metadata.required_insert_count() > feedback.known_received_count();
        if will_block && self.settings_blocked_streams == 0 {
            let error = H3NativeError::QpackPolicy("qpack blocked stream capacity is zero");
            self.streams.insert(
                stream_id,
                QpackBlockedStreamRecord::failed(stream_id, Some(&metadata), error.clone()),
            );
            return self.fail(error);
        }
        if will_block && self.blocked_stream_count() >= self.settings_blocked_streams {
            let error = H3NativeError::QpackPolicy("qpack blocked stream capacity exceeded");
            self.streams.insert(
                stream_id,
                QpackBlockedStreamRecord::failed(stream_id, Some(&metadata), error.clone()),
            );
            return self.fail(error);
        }

        if mode == H3QpackMode::DynamicTableAllowed {
            if let Err(error) = feedback.track_stream_references(context, stream_id, &references) {
                self.streams.insert(
                    stream_id,
                    QpackBlockedStreamRecord::failed(stream_id, Some(&metadata), error.clone()),
                );
                return self.fail(error);
            }
        }

        let status = if will_block {
            QpackBlockedStreamStatus::Blocked
        } else {
            QpackBlockedStreamStatus::Ready
        };
        let blocked_reason =
            will_block.then_some("required insert count exceeds known received count");
        self.streams.insert(
            stream_id,
            QpackBlockedStreamRecord::new(stream_id, &metadata, status, blocked_reason, references),
        );
        Ok(status)
    }

    /// Schedule one received field section, blocking until local inserts arrive.
    pub fn submit_received_field_section(
        &mut self,
        context: &mut QpackContext,
        feedback: &mut QpackDecoderFeedbackState,
        mode: H3QpackMode,
        stream_id: u64,
        field_section: &[u8],
    ) -> Result<QpackBlockedStreamStatus, H3NativeError> {
        // Bound the streams map before adding another per-stream record.
        self.reap_excess_records();
        if self.streams.contains_key(&stream_id) {
            return self.fail(H3NativeError::StreamProtocol(
                "qpack stream already scheduled",
            ));
        }

        let metadata = match qpack_field_section_metadata(field_section, mode, Some(context)) {
            Ok(metadata) => metadata,
            Err(error) => {
                self.streams.insert(
                    stream_id,
                    QpackBlockedStreamRecord::failed(stream_id, None, error.clone()),
                );
                return self.fail(error);
            }
        };

        if mode == H3QpackMode::DynamicTableAllowed
            && metadata.required_insert_count() > context.dynamic_table().insertion_counter()
        {
            if self.settings_blocked_streams == 0 {
                let error = H3NativeError::QpackPolicy("qpack blocked stream capacity is zero");
                self.streams.insert(
                    stream_id,
                    QpackBlockedStreamRecord::failed(stream_id, Some(&metadata), error.clone()),
                );
                return self.fail(error);
            }
            if self.blocked_stream_count() >= self.settings_blocked_streams {
                let error = H3NativeError::QpackPolicy("qpack blocked stream capacity exceeded");
                self.streams.insert(
                    stream_id,
                    QpackBlockedStreamRecord::failed(stream_id, Some(&metadata), error.clone()),
                );
                return self.fail(error);
            }

            let mut record = QpackBlockedStreamRecord::new(
                stream_id,
                &metadata,
                QpackBlockedStreamStatus::Blocked,
                Some("required insert count exceeds dynamic table state"),
                Vec::new(),
            );
            record.blocked_field_section = Some(field_section.to_vec());
            self.streams.insert(stream_id, record);
            return Ok(QpackBlockedStreamStatus::Blocked);
        }

        let context_opt = (mode == H3QpackMode::DynamicTableAllowed).then_some(&*context);
        let plan = match qpack_decode_field_section_with_context(field_section, mode, context_opt) {
            Ok(plan) => plan,
            Err(error) => {
                self.streams.insert(
                    stream_id,
                    QpackBlockedStreamRecord::failed(stream_id, Some(&metadata), error.clone()),
                );
                return self.fail(error);
            }
        };
        let references = qpack_plan_dynamic_references(&plan);
        if mode == H3QpackMode::DynamicTableAllowed {
            if let Err(error) = feedback.track_stream_references(context, stream_id, &references) {
                self.streams.insert(
                    stream_id,
                    QpackBlockedStreamRecord::failed(stream_id, Some(&metadata), error.clone()),
                );
                return self.fail(error);
            }
        }

        self.streams.insert(
            stream_id,
            QpackBlockedStreamRecord::new(
                stream_id,
                &metadata,
                QpackBlockedStreamStatus::Ready,
                None,
                references,
            ),
        );
        Ok(QpackBlockedStreamStatus::Ready)
    }

    /// Apply one decoder-stream instruction and update blocked-stream state.
    pub fn apply_decoder_instruction(
        &mut self,
        feedback: &mut QpackDecoderFeedbackState,
        context: &mut QpackContext,
        mode: H3QpackMode,
        instruction: &QpackDecoderInstruction,
    ) -> Result<Vec<u64>, H3NativeError> {
        match instruction {
            QpackDecoderInstruction::InsertCountIncrement { .. } => {
                qpack_apply_decoder_instruction(feedback, context, mode, instruction)
                    .map_err(|error| self.record_global_error(error))?;
                Ok(self.unblock_ready(feedback.known_received_count()))
            }
            QpackDecoderInstruction::HeaderAcknowledgement { stream_id } => {
                let had_record = self.streams.contains_key(stream_id);
                if let Err(error) =
                    qpack_apply_decoder_instruction(feedback, context, mode, instruction)
                {
                    if had_record {
                        self.record_stream_error(*stream_id, &error);
                    } else {
                        self.record_error(&error);
                    }
                    return Err(error);
                }
                self.streams.remove(stream_id);
                Ok(Vec::new())
            }
            QpackDecoderInstruction::StreamCancellation { stream_id } => {
                let had_record = self.streams.contains_key(stream_id);
                if let Err(error) =
                    qpack_apply_decoder_instruction(feedback, context, mode, instruction)
                {
                    if had_record {
                        self.record_stream_error(*stream_id, &error);
                    } else {
                        self.record_error(&error);
                    }
                    return Err(error);
                }
                self.streams.remove(stream_id);
                Ok(Vec::new())
            }
        }
    }

    /// Apply one encoder-stream instruction, then reevaluate blocked streams.
    pub fn apply_encoder_instruction(
        &mut self,
        context: &mut QpackContext,
        feedback: &mut QpackDecoderFeedbackState,
        mode: H3QpackMode,
        instruction: &QpackEncoderInstruction,
    ) -> Result<(Option<u64>, Vec<u64>), H3NativeError> {
        let inserted = qpack_apply_encoder_instruction(context, mode, instruction)
            .map_err(|error| self.record_global_error(error))?;
        let mut unblocked = self.unblock_decodable(context, feedback, mode)?;
        unblocked.extend(self.unblock_ready(feedback.known_received_count()));
        Ok((inserted, unblocked))
    }

    /// Cancel a scheduled stream and release any protected references.
    pub fn cancel_stream(
        &mut self,
        feedback: &mut QpackDecoderFeedbackState,
        context: &mut QpackContext,
        mode: H3QpackMode,
        stream_id: u64,
    ) -> Result<(), H3NativeError> {
        self.apply_decoder_instruction(
            feedback,
            context,
            mode,
            &QpackDecoderInstruction::StreamCancellation { stream_id },
        )
        .map(|_| ())
    }

    fn unblock_ready(&mut self, known_received_count: u64) -> Vec<u64> {
        let mut unblocked = Vec::new();
        for record in self.streams.values_mut() {
            if record.status == QpackBlockedStreamStatus::Blocked
                && record.required_insert_count <= known_received_count
            {
                record.status = QpackBlockedStreamStatus::Ready;
                record.blocked_reason = None;
                unblocked.push(record.stream_id);
            }
        }
        unblocked
    }

    fn unblock_decodable(
        &mut self,
        context: &mut QpackContext,
        feedback: &mut QpackDecoderFeedbackState,
        mode: H3QpackMode,
    ) -> Result<Vec<u64>, H3NativeError> {
        let ready_ids: Vec<u64> = self
            .streams
            .iter()
            .filter(|(_, record)| {
                record.status == QpackBlockedStreamStatus::Blocked
                    && record.blocked_field_section.is_some()
                    && record.required_insert_count <= context.dynamic_table().insertion_counter()
            })
            .map(|(stream_id, _)| *stream_id)
            .collect();

        let mut unblocked = Vec::new();
        for stream_id in ready_ids {
            let field_section = self
                .streams
                .get(&stream_id)
                .and_then(|record| record.blocked_field_section.clone())
                .ok_or(H3NativeError::InvalidFrame(
                    "qpack blocked field section missing",
                ))?;
            let context_opt = (mode == H3QpackMode::DynamicTableAllowed).then_some(&*context);
            let plan =
                match qpack_decode_field_section_with_context(&field_section, mode, context_opt) {
                    Ok(plan) => plan,
                    Err(error) => {
                        self.record_stream_error(stream_id, &error);
                        return Err(error);
                    }
                };
            let references = qpack_plan_dynamic_references(&plan);
            if mode == H3QpackMode::DynamicTableAllowed {
                if let Err(error) =
                    feedback.track_stream_references(context, stream_id, &references)
                {
                    self.record_stream_error(stream_id, &error);
                    return Err(error);
                }
            }
            if let Some(record) = self.streams.get_mut(&stream_id) {
                record.status = QpackBlockedStreamStatus::Ready;
                record.blocked_reason = None;
                record.protected_references = references;
                record.blocked_field_section = None;
            }
            unblocked.push(stream_id);
        }
        Ok(unblocked)
    }

    fn record_stream_error(&mut self, stream_id: u64, error: &H3NativeError) {
        self.record_error(error);
        if let Some(record) = self.streams.get_mut(&stream_id) {
            record.record_failure(error);
        }
    }

    fn record_global_error(&mut self, error: H3NativeError) -> H3NativeError {
        self.record_error(&error);
        error
    }

    fn fail<T>(&mut self, error: H3NativeError) -> Result<T, H3NativeError> {
        self.record_error(&error);
        Err(error)
    }

    fn record_error(&mut self, error: &H3NativeError) {
        if self.first_failure.is_none() {
            self.first_failure = Some(error.clone());
        }
    }
}

/// Summary of QPACK instruction bytes processed from one stream read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QpackInstructionStreamOutcome {
    instructions_processed: usize,
    inserted_entry_ids: Vec<u64>,
    unblocked_stream_ids: Vec<u64>,
}

impl QpackInstructionStreamOutcome {
    fn record_encoder_result(&mut self, inserted: Option<u64>, mut unblocked: Vec<u64>) {
        self.instructions_processed += 1;
        if let Some(insertion_id) = inserted {
            self.inserted_entry_ids.push(insertion_id);
        }
        self.unblocked_stream_ids.append(&mut unblocked);
    }

    fn record_decoder_result(&mut self, mut unblocked: Vec<u64>) {
        self.instructions_processed += 1;
        self.unblocked_stream_ids.append(&mut unblocked);
    }

    /// Number of complete QPACK instructions processed from the byte slice.
    #[must_use]
    pub fn instructions_processed(&self) -> usize {
        self.instructions_processed
    }

    /// Dynamic-table insertion IDs created by encoder-stream instructions.
    #[must_use]
    pub fn inserted_entry_ids(&self) -> &[u64] {
        &self.inserted_entry_ids
    }

    /// Request/response stream IDs unblocked by encoder or decoder instructions.
    #[must_use]
    pub fn unblocked_stream_ids(&self) -> &[u64] {
        &self.unblocked_stream_ids
    }
}

/// Deterministic QPACK instruction-stream state for an HTTP/3 connection.
///
/// This owns the peer-facing QPACK dynamic table, peer decoder-feedback
/// accounting, and blocked-stream scheduler. It intentionally processes raw
/// QPACK instruction bytes only; HTTP/3 DATA/HEADERS frame mapping remains the
/// job of `H3ConnectionState`.
#[derive(Debug)]
pub struct QpackInstructionStreamState {
    mode: H3QpackMode,
    context: QpackContext,
    decoder_feedback: QpackDecoderFeedbackState,
    blocked_scheduler: QpackBlockedStreamScheduler,
    encoder_stream_id: Option<u64>,
    decoder_stream_id: Option<u64>,
    first_failure: Option<H3NativeError>,
}

impl QpackInstructionStreamState {
    /// Construct QPACK instruction-stream state from explicit negotiated limits.
    pub fn new(
        mode: H3QpackMode,
        max_table_capacity: u64,
        settings_blocked_streams: u64,
    ) -> Result<Self, H3NativeError> {
        if mode == H3QpackMode::StaticOnly {
            if max_table_capacity > 0 {
                return Err(H3NativeError::QpackPolicy(
                    "dynamic qpack table disabled by policy",
                ));
            }
            if settings_blocked_streams > 0 {
                return Err(H3NativeError::QpackPolicy(
                    "qpack blocked streams must be zero in static-only mode",
                ));
            }
        }
        let max_table_capacity: usize = max_table_capacity.try_into().map_err(|_| {
            H3NativeError::InvalidFrame("qpack dynamic table capacity exceeds addressable range")
        })?;
        Ok(Self {
            mode,
            context: QpackContext::new(max_table_capacity),
            decoder_feedback: QpackDecoderFeedbackState::new(),
            blocked_scheduler: QpackBlockedStreamScheduler::new(settings_blocked_streams),
            encoder_stream_id: None,
            decoder_stream_id: None,
            first_failure: None,
        })
    }

    /// Construct QPACK instruction-stream state from peer HTTP/3 SETTINGS.
    pub fn from_settings(mode: H3QpackMode, settings: &H3Settings) -> Result<Self, H3NativeError> {
        if mode == H3QpackMode::StaticOnly {
            // Peer capacity is permission, not a requirement. A static-only
            // encoder remains interoperable by declining to use the dynamic
            // table even when the peer advertises non-zero capacity.
            return Self::new(mode, 0, 0);
        }
        Self::new(
            mode,
            settings.qpack_max_table_capacity.unwrap_or(0),
            settings.qpack_blocked_streams.unwrap_or(0),
        )
    }

    /// QPACK mode used by this instruction-stream state.
    #[must_use]
    pub fn mode(&self) -> H3QpackMode {
        self.mode
    }

    /// Dynamic QPACK context.
    #[must_use]
    pub fn context(&self) -> &QpackContext {
        &self.context
    }

    /// Decoder-feedback state.
    #[must_use]
    pub fn decoder_feedback(&self) -> &QpackDecoderFeedbackState {
        &self.decoder_feedback
    }

    /// Blocked-stream scheduler.
    #[must_use]
    pub fn blocked_scheduler(&self) -> &QpackBlockedStreamScheduler {
        &self.blocked_scheduler
    }

    /// Registered peer QPACK encoder-stream id.
    #[must_use]
    pub fn encoder_stream_id(&self) -> Option<u64> {
        self.encoder_stream_id
    }

    /// Registered peer QPACK decoder-stream id.
    #[must_use]
    pub fn decoder_stream_id(&self) -> Option<u64> {
        self.decoder_stream_id
    }

    /// Peer Known Received Count.
    #[must_use]
    pub fn known_received_count(&self) -> u64 {
        self.decoder_feedback.known_received_count()
    }

    /// Number of streams currently blocked by Required Insert Count gates.
    #[must_use]
    pub fn blocked_stream_count(&self) -> u64 {
        self.blocked_scheduler.blocked_stream_count()
    }

    /// SETTINGS_QPACK_BLOCKED_STREAMS limit used by the scheduler.
    #[must_use]
    pub fn settings_blocked_streams(&self) -> u64 {
        self.blocked_scheduler.settings_blocked_streams()
    }

    /// First instruction-stream failure observed.
    #[must_use]
    pub fn first_failure(&self) -> Option<&H3NativeError> {
        self.first_failure
            .as_ref()
            .or_else(|| self.blocked_scheduler.first_failure())
            .or_else(|| self.decoder_feedback.first_error())
    }

    /// Register a peer QPACK stream directly.
    pub fn register_stream(
        &mut self,
        stream_id: u64,
        kind: H3UniStreamType,
    ) -> Result<(), H3NativeError> {
        if self.registered_stream_kind(stream_id).is_some() {
            return self.fail(H3NativeError::StreamProtocol(
                "qpack instruction stream id already registered",
            ));
        }
        match kind {
            H3UniStreamType::QpackEncoder => {
                if self.encoder_stream_id.is_some() {
                    return self.fail(H3NativeError::StreamProtocol(
                        "duplicate remote qpack encoder stream",
                    ));
                }
                self.encoder_stream_id = Some(stream_id);
                Ok(())
            }
            H3UniStreamType::QpackDecoder => {
                if self.decoder_stream_id.is_some() {
                    return self.fail(H3NativeError::StreamProtocol(
                        "duplicate remote qpack decoder stream",
                    ));
                }
                self.decoder_stream_id = Some(stream_id);
                Ok(())
            }
            H3UniStreamType::Control | H3UniStreamType::Push | H3UniStreamType::Unknown(_) => self
                .fail(H3NativeError::StreamProtocol(
                    "qpack instruction stream requires qpack stream type",
                )),
        }
    }

    /// Register a peer QPACK stream from `H3ConnectionState` stream typing.
    pub fn register_from_connection(
        &mut self,
        connection: &H3ConnectionState,
        stream_id: u64,
    ) -> Result<H3UniStreamType, H3NativeError> {
        let kind =
            connection
                .remote_uni_stream_type(stream_id)
                .ok_or(H3NativeError::StreamProtocol(
                    "unknown unidirectional stream",
                ))?;
        self.register_stream(stream_id, kind)?;
        Ok(kind)
    }

    /// Ensure the stream is registered with the same QPACK stream kind.
    pub fn ensure_stream_registered(
        &mut self,
        stream_id: u64,
        kind: H3UniStreamType,
    ) -> Result<(), H3NativeError> {
        match self.registered_stream_kind(stream_id) {
            Some(actual) if actual == kind => Ok(()),
            Some(_) => self.fail(H3NativeError::StreamProtocol(
                "qpack instruction type does not match registered stream",
            )),
            None => self.register_stream(stream_id, kind),
        }
    }

    /// Feed encoder-stream instruction bytes.
    pub fn feed_encoder_stream_bytes(
        &mut self,
        stream_id: u64,
        bytes: &[u8],
    ) -> Result<QpackInstructionStreamOutcome, H3NativeError> {
        self.ensure_stream_kind(stream_id, H3UniStreamType::QpackEncoder)?;
        let mut pos = 0usize;
        let mut outcome = QpackInstructionStreamOutcome::default();
        while pos < bytes.len() {
            let (instruction, consumed) = match qpack_decode_encoder_instruction(&bytes[pos..]) {
                Ok(decoded) => decoded,
                Err(error) => return self.fail(error),
            };
            let (inserted, unblocked) = match self.blocked_scheduler.apply_encoder_instruction(
                &mut self.context,
                &mut self.decoder_feedback,
                self.mode,
                &instruction,
            ) {
                Ok(result) => result,
                Err(error) => {
                    self.record_error(&error);
                    return Err(error);
                }
            };
            outcome.record_encoder_result(inserted, unblocked);
            pos += consumed;
        }
        Ok(outcome)
    }

    /// Feed decoder-stream instruction bytes.
    pub fn feed_decoder_stream_bytes(
        &mut self,
        stream_id: u64,
        bytes: &[u8],
    ) -> Result<QpackInstructionStreamOutcome, H3NativeError> {
        self.ensure_stream_kind(stream_id, H3UniStreamType::QpackDecoder)?;
        let mut pos = 0usize;
        let mut outcome = QpackInstructionStreamOutcome::default();
        while pos < bytes.len() {
            let (instruction, consumed) = match qpack_decode_decoder_instruction(&bytes[pos..]) {
                Ok(decoded) => decoded,
                Err(error) => return self.fail(error),
            };
            let unblocked = match self.blocked_scheduler.apply_decoder_instruction(
                &mut self.decoder_feedback,
                &mut self.context,
                self.mode,
                &instruction,
            ) {
                Ok(result) => result,
                Err(error) => {
                    self.record_error(&error);
                    return Err(error);
                }
            };
            outcome.record_decoder_result(unblocked);
            pos += consumed;
        }
        Ok(outcome)
    }

    /// Feed bytes from a typed QPACK instruction stream.
    pub fn feed_instruction_stream_bytes(
        &mut self,
        stream_id: u64,
        kind: H3UniStreamType,
        bytes: &[u8],
    ) -> Result<QpackInstructionStreamOutcome, H3NativeError> {
        match kind {
            H3UniStreamType::QpackEncoder => self.feed_encoder_stream_bytes(stream_id, bytes),
            H3UniStreamType::QpackDecoder => self.feed_decoder_stream_bytes(stream_id, bytes),
            H3UniStreamType::Control | H3UniStreamType::Push | H3UniStreamType::Unknown(_) => self
                .fail(H3NativeError::StreamProtocol(
                    "qpack instruction stream requires qpack stream type",
                )),
        }
    }

    /// Schedule one outbound field section against peer Known Received Count.
    pub fn submit_field_section(
        &mut self,
        stream_id: u64,
        field_section: &[u8],
    ) -> Result<QpackBlockedStreamStatus, H3NativeError> {
        self.blocked_scheduler.submit_field_section(
            &mut self.context,
            &mut self.decoder_feedback,
            self.mode,
            stream_id,
            field_section,
        )
    }

    /// Schedule one received field section that may wait for encoder instructions.
    pub fn submit_received_field_section(
        &mut self,
        stream_id: u64,
        field_section: &[u8],
    ) -> Result<QpackBlockedStreamStatus, H3NativeError> {
        self.blocked_scheduler.submit_received_field_section(
            &mut self.context,
            &mut self.decoder_feedback,
            self.mode,
            stream_id,
            field_section,
        )
    }

    /// Cancel a scheduled field section and release dynamic-table references.
    pub fn cancel_stream(&mut self, stream_id: u64) -> Result<(), H3NativeError> {
        self.blocked_scheduler.cancel_stream(
            &mut self.decoder_feedback,
            &mut self.context,
            self.mode,
            stream_id,
        )
    }

    fn ensure_stream_kind(
        &mut self,
        stream_id: u64,
        expected: H3UniStreamType,
    ) -> Result<(), H3NativeError> {
        match self.registered_stream_kind(stream_id) {
            Some(actual) if actual == expected => Ok(()),
            Some(_) => self.fail(H3NativeError::StreamProtocol(
                "qpack instruction type does not match registered stream",
            )),
            None => self.fail(H3NativeError::StreamProtocol(
                "unknown qpack instruction stream",
            )),
        }
    }

    fn registered_stream_kind(&self, stream_id: u64) -> Option<H3UniStreamType> {
        if self.encoder_stream_id == Some(stream_id) {
            return Some(H3UniStreamType::QpackEncoder);
        }
        if self.decoder_stream_id == Some(stream_id) {
            return Some(H3UniStreamType::QpackDecoder);
        }
        None
    }

    fn fail<T>(&mut self, error: H3NativeError) -> Result<T, H3NativeError> {
        self.record_error(&error);
        Err(error)
    }

    fn record_error(&mut self, error: &H3NativeError) {
        if self.first_failure.is_none() {
            self.first_failure = Some(error.clone());
        }
    }
}

fn qpack_plan_dynamic_references(plan: &[QpackFieldPlan]) -> Vec<u64> {
    let mut references = BTreeSet::new();
    for field in plan {
        match field {
            QpackFieldPlan::DynamicIndex(index) => {
                references.insert(*index);
            }
            QpackFieldPlan::DynamicNameLiteral { name_index, .. } => {
                references.insert(*name_index);
            }
            QpackFieldPlan::StaticIndex(_) | QpackFieldPlan::Literal { .. } => {}
        }
    }
    references.into_iter().collect()
}

/// Apply one RFC 9204 encoder-stream instruction to an existing QPACK context.
///
/// This mutates only the dynamic table carried by `context`; it does not process
/// HTTP/3 frames or alter request-stream state.
pub fn qpack_apply_encoder_instruction(
    context: &mut QpackContext,
    mode: H3QpackMode,
    instruction: &QpackEncoderInstruction,
) -> Result<Option<u64>, H3NativeError> {
    if mode != H3QpackMode::DynamicTableAllowed {
        return Err(H3NativeError::QpackPolicy(
            "encoder instructions require dynamic qpack mode",
        ));
    }

    match instruction {
        QpackEncoderInstruction::SetDynamicTableCapacity { capacity } => {
            let capacity: usize = (*capacity).try_into().map_err(|_| {
                H3NativeError::InvalidFrame(
                    "qpack dynamic table capacity exceeds addressable range",
                )
            })?;
            context
                .set_dynamic_table_capacity(capacity)
                .map_err(qpack_capacity_error)?;
            Ok(None)
        }
        QpackEncoderInstruction::InsertWithNameReference { name, value } => {
            let name = match name {
                QpackInstructionNameRef::Static(index) => qpack_static_name(*index)
                    .ok_or(H3NativeError::InvalidFrame(
                        "unknown static qpack name index",
                    ))?
                    .to_string(),
                QpackInstructionNameRef::Dynamic(index) => context
                    .dynamic_table()
                    .get_by_relative_index(*index)
                    .ok_or(H3NativeError::InvalidFrame(
                        "unknown dynamic qpack name index",
                    ))?
                    .name()
                    .to_string(),
            };
            context
                .insert_dynamic_entry(name, value.clone())
                .map(Some)
                .map_err(qpack_insert_error)
        }
        QpackEncoderInstruction::InsertWithoutNameReference { name, value } => context
            .insert_dynamic_entry(name.clone(), value.clone())
            .map(Some)
            .map_err(qpack_insert_error),
        QpackEncoderInstruction::Duplicate { index } => {
            let entry = context
                .dynamic_table()
                .get_by_relative_index(*index)
                .ok_or(H3NativeError::InvalidFrame(
                    "unknown dynamic qpack duplicate index",
                ))?;
            let name = entry.name().to_string();
            let value = entry.value().to_string();
            context
                .insert_dynamic_entry(name, value)
                .map(Some)
                .map_err(qpack_insert_error)
        }
    }
}

fn qpack_capacity_error(err: &'static str) -> H3NativeError {
    match err {
        "capacity exceeds peer limit" => {
            H3NativeError::QpackPolicy("qpack dynamic table capacity exceeds peer limit")
        }
        "cannot reduce table capacity while entries are referenced" => H3NativeError::InvalidFrame(
            "qpack dynamic table capacity shrink blocked by referenced entries",
        ),
        _ => H3NativeError::InvalidFrame("qpack dynamic table capacity update failed"),
    }
}

fn qpack_insert_error(err: &'static str) -> H3NativeError {
    match err {
        "entry larger than table capacity" => {
            H3NativeError::InvalidFrame("qpack dynamic table entry exceeds capacity")
        }
        "cannot evict enough space (all entries referenced)" => {
            H3NativeError::InvalidFrame("qpack dynamic table insert blocked by referenced entries")
        }
        _ => H3NativeError::InvalidFrame("qpack dynamic table insert failed"),
    }
}

/// br-asupersync-mbn0uo — Fuzz-target re-exporter for the H3
/// status-code parser. `#[doc(hidden)]`; only exists for direct
/// fuzz harness access.
#[doc(hidden)]
pub fn fuzz_parse_status_code(value: &str) -> Result<u16, H3NativeError> {
    parse_status_code(value)
}

/// br-asupersync-zv7n9x — Fuzz-target re-exporter for the QPACK
/// required-insert-count decoder.
#[doc(hidden)]
pub fn fuzz_qpack_decode_required_insert_count(
    encoded_insert_count: u64,
    total_inserts: u64,
    max_table_capacity: usize,
) -> Result<u64, H3NativeError> {
    qpack_decode_required_insert_count(encoded_insert_count, total_inserts, max_table_capacity)
}

/// br-asupersync-czy6d8 — Fuzz-target re-exporter for the QPACK
/// base decoder.
#[doc(hidden)]
pub fn fuzz_qpack_decode_base(
    required_insert_count: u64,
    sign: bool,
    delta_base: u64,
) -> Result<u64, H3NativeError> {
    qpack_decode_base(required_insert_count, sign, delta_base)
}

fn qpack_relative_to_absolute(
    base: u64,
    relative_index: u64,
    is_post_base: bool,
) -> Result<u64, H3NativeError> {
    if is_post_base {
        // Post-base reference: absolute = base + index
        base.checked_add(relative_index)
            .ok_or(H3NativeError::InvalidFrame(
                "dynamic qpack post-base index overflow",
            ))
    } else {
        // br-asupersync-6ws34s — Pre-base reference: absolute = base - index - 1.
        // Both subtractions must be checked. The previous shape was
        // `base.checked_sub(relative_index + 1)` which evaluates the
        // `relative_index + 1` *first*, unchecked. When
        // `relative_index == u64::MAX`, the inner add wraps to 0 and
        // `checked_sub(0)` returns `Some(base)` — yielding an absolute
        // index that bypasses the under-base bounds check, mapping a
        // crafted relative_index to whatever entry is currently at
        // `base`. The fix routes both arithmetic steps through
        // `checked_add` / `checked_sub`. RFC 9204 / 9114 treat any
        // qpack reference exceeding the base as a stream-level
        // decoding error (H3_QPACK_DECODER_STREAM_ERROR).
        let plus_one = relative_index
            .checked_add(1)
            .ok_or(H3NativeError::InvalidFrame(
                "dynamic qpack relative index +1 overflow (H3_QPACK_DECODER_STREAM_ERROR)",
            ))?;
        base.checked_sub(plus_one)
            .ok_or(H3NativeError::InvalidFrame(
                "dynamic qpack relative index exceeds base (H3_QPACK_DECODER_STREAM_ERROR)",
            ))
    }
}

fn qpack_absolute_to_relative(base: u64, absolute_index: u64) -> Result<u64, H3NativeError> {
    let next = absolute_index
        .checked_add(1)
        .ok_or(H3NativeError::InvalidFrame(
            "dynamic qpack absolute index overflow",
        ))?;
    base.checked_sub(next).ok_or(H3NativeError::InvalidFrame(
        "dynamic qpack absolute index exceeds base",
    ))
}

fn qpack_decode_field_section_with_context(
    input: &[u8],
    mode: H3QpackMode,
    qpack_context: Option<&QpackContext>,
) -> Result<Vec<QpackFieldPlan>, H3NativeError> {
    let mut pos = 0usize;

    // Field section prefix part 1: Required Insert Count (8-bit prefix int).
    let first = *input.get(pos).ok_or(H3NativeError::UnexpectedEof)?;
    pos += 1;
    let (encoded_insert_count, ric_extra) = qpack_decode_prefixed_int(first, 8, &input[pos..])?;
    pos += ric_extra;

    // Field section prefix part 2: S + Delta Base (7-bit prefix int).
    let second = *input.get(pos).ok_or(H3NativeError::UnexpectedEof)?;
    pos += 1;
    let sign = (second & 0x80) != 0;
    let (delta_base, db_extra) = qpack_decode_prefixed_int(second, 7, &input[pos..])?;
    pos += db_extra;

    let dynamic_base = match mode {
        H3QpackMode::StaticOnly => {
            if encoded_insert_count != 0 {
                return Err(H3NativeError::QpackPolicy(
                    "required insert count must be zero in static-only mode",
                ));
            }
            if sign || delta_base != 0 {
                return Err(H3NativeError::QpackPolicy(
                    "base must be zero in static-only mode",
                ));
            }
            None
        }
        H3QpackMode::DynamicTableAllowed => {
            // Dynamic table operations are permitted - validate reasonable bounds
            if encoded_insert_count > 65536 {
                return Err(H3NativeError::QpackPolicy(
                    "required insert count exceeds reasonable limit",
                ));
            }

            if let Some(context) = qpack_context {
                let total_inserts = context.dynamic_table().insertion_counter();
                let required_insert_count = qpack_decode_required_insert_count(
                    encoded_insert_count,
                    total_inserts,
                    context.max_table_capacity,
                )?;
                if required_insert_count > total_inserts {
                    return Err(H3NativeError::QpackPolicy(
                        "required insert count exceeds dynamic table state",
                    ));
                }

                let base = qpack_decode_base(required_insert_count, sign, delta_base)?;
                if base > total_inserts {
                    return Err(H3NativeError::InvalidFrame(
                        "dynamic qpack base exceeds dynamic table state",
                    ));
                }
                Some(base)
            } else {
                if encoded_insert_count != 0 || sign || delta_base != 0 {
                    return Err(H3NativeError::InvalidFrame(
                        "dynamic table context required",
                    ));
                }
                None
            }
        }
    };

    let mut out = Vec::new();
    while pos < input.len() {
        let b = input[pos];

        if (b & 0x80) != 0 {
            // Indexed field line: 1 T Index(6+)
            let is_static = (b & 0x40) != 0;
            let (index, extra) = qpack_decode_prefixed_int(b, 6, &input[pos + 1..])?;
            pos += 1 + extra;
            if !is_static && mode == H3QpackMode::StaticOnly {
                return Err(H3NativeError::QpackPolicy(
                    "dynamic qpack index references not allowed in static-only mode",
                ));
            }

            if is_static {
                if qpack_static_entry(index).is_none() {
                    return Err(H3NativeError::InvalidFrame("unknown static qpack index"));
                }
                out.push(QpackFieldPlan::StaticIndex(index));
                if out.len() > QPACK_MAX_DECODED_HEADERS {
                    return Err(H3NativeError::QpackPolicy(
                        "decoded header count exceeds safety limit",
                    ));
                }
            } else {
                let base = dynamic_base.ok_or(H3NativeError::InvalidFrame(
                    "dynamic table context required",
                ))?;
                let absolute_index = qpack_relative_to_absolute(base, index, false)?;
                out.push(QpackFieldPlan::DynamicIndex(absolute_index));
                if out.len() > QPACK_MAX_DECODED_HEADERS {
                    return Err(H3NativeError::QpackPolicy(
                        "decoded header count exceeds safety limit",
                    ));
                }
            }
            continue;
        }

        if (b & 0x40) != 0 {
            // Literal field line with name reference: 01 N T NameIndex(4+)
            let is_static = (b & 0x10) != 0;
            let (name_index, extra) = qpack_decode_prefixed_int(b, 4, &input[pos + 1..])?;
            pos += 1 + extra;
            if !is_static && mode == H3QpackMode::StaticOnly {
                return Err(H3NativeError::QpackPolicy(
                    "dynamic qpack name references not allowed in static-only mode",
                ));
            }

            let value_first = *input.get(pos).ok_or(H3NativeError::UnexpectedEof)?;
            let (value, value_extra) = qpack_decode_string(value_first, 7, &input[pos + 1..])?;
            pos += 1 + value_extra;

            if is_static {
                let name = qpack_static_name(name_index).ok_or(H3NativeError::InvalidFrame(
                    "unknown static qpack name index",
                ))?;
                out.push(QpackFieldPlan::Literal {
                    name: name.to_string(),
                    value,
                });
                if out.len() > QPACK_MAX_DECODED_HEADERS {
                    return Err(H3NativeError::QpackPolicy(
                        "decoded header count exceeds safety limit",
                    ));
                }
            } else {
                let base = dynamic_base.ok_or(H3NativeError::InvalidFrame(
                    "dynamic table context required",
                ))?;
                let absolute_name_index = qpack_relative_to_absolute(base, name_index, false)?;
                out.push(QpackFieldPlan::DynamicNameLiteral {
                    name_index: absolute_name_index,
                    value,
                });
                if out.len() > QPACK_MAX_DECODED_HEADERS {
                    return Err(H3NativeError::QpackPolicy(
                        "decoded header count exceeds safety limit",
                    ));
                }
            }
            continue;
        }

        if (b & 0x20) != 0 {
            // Literal field line with literal name: 001 N H NameLen(3+)
            let (name, name_extra) = qpack_decode_string(b, 3, &input[pos + 1..])?;
            pos += 1 + name_extra;

            let value_first = *input.get(pos).ok_or(H3NativeError::UnexpectedEof)?;
            let (value, value_extra) = qpack_decode_string(value_first, 7, &input[pos + 1..])?;
            pos += 1 + value_extra;

            out.push(QpackFieldPlan::Literal { name, value });
            if out.len() > QPACK_MAX_DECODED_HEADERS {
                return Err(H3NativeError::QpackPolicy(
                    "decoded header count exceeds safety limit",
                ));
            }
            continue;
        }

        // Remaining line representations are post-base / dynamic variants:
        // 0001.... indexed post-base, 0000.... literal post-base name ref.
        if mode == H3QpackMode::StaticOnly {
            return Err(H3NativeError::QpackPolicy(
                "post-base/dynamic qpack line representations not allowed in static-only mode",
            ));
        }

        let base = dynamic_base.ok_or(H3NativeError::InvalidFrame(
            "dynamic table context required",
        ))?;
        if (b & 0x10) != 0 {
            // Indexed field line with post-base index: 0001 Index(4+)
            let (index, extra) = qpack_decode_prefixed_int(b, 4, &input[pos + 1..])?;
            pos += 1 + extra;
            let absolute_index = qpack_relative_to_absolute(base, index, true)?;
            out.push(QpackFieldPlan::DynamicIndex(absolute_index));
            if out.len() > QPACK_MAX_DECODED_HEADERS {
                return Err(H3NativeError::QpackPolicy(
                    "decoded header count exceeds safety limit",
                ));
            }
            continue;
        }

        // Literal field line with post-base name reference: 0000 N NameIndex(3+)
        let (name_index, extra) = qpack_decode_prefixed_int(b, 3, &input[pos + 1..])?;
        pos += 1 + extra;
        let value_first = *input.get(pos).ok_or(H3NativeError::UnexpectedEof)?;
        let (value, value_extra) = qpack_decode_string(value_first, 7, &input[pos + 1..])?;
        pos += 1 + value_extra;
        let absolute_name_index = qpack_relative_to_absolute(base, name_index, true)?;
        out.push(QpackFieldPlan::DynamicNameLiteral {
            name_index: absolute_name_index,
            value,
        });
        if out.len() > QPACK_MAX_DECODED_HEADERS {
            return Err(H3NativeError::QpackPolicy(
                "decoded header count exceeds safety limit",
            ));
        }
    }

    Ok(out)
}

/// Encode a validated request head into a wire-level QPACK field section.
pub fn qpack_encode_request_field_section(head: &H3RequestHead) -> Result<Vec<u8>, H3NativeError> {
    let plan = qpack_static_plan_for_request(head);
    qpack_encode_field_section(&plan)
}

/// Encode a validated response head into a wire-level QPACK field section.
pub fn qpack_encode_response_field_section(
    head: &H3ResponseHead,
) -> Result<Vec<u8>, H3NativeError> {
    let plan = qpack_static_plan_for_response(head);
    qpack_encode_field_section(&plan)
}

/// Encode validated ordinary trailer fields into a QPACK field section.
///
/// Trailers never carry pseudo-headers. This helper deliberately emits only
/// literals so it remains valid in the static-only profile and cannot acquire
/// dynamic-table blocking dependencies.
pub fn qpack_encode_trailer_field_section(
    fields: &[(String, String)],
) -> Result<Vec<u8>, H3NativeError> {
    let mut plan = Vec::with_capacity(fields.len());
    for (name, value) in fields {
        validate_header_name(name)?;
        validate_header_value(value)?;
        if name.starts_with(':') {
            return Err(H3NativeError::InvalidFrame(
                "pseudo header forbidden in HTTP/3 trailers",
            ));
        }
        plan.push(QpackFieldPlan::Literal {
            name: name.clone(),
            value: value.clone(),
        });
    }
    qpack_encode_field_section(&plan)
}

/// Expand a QPACK plan into concrete `(name, value)` header fields.
///
/// Static-table references are resolved using the subset needed by the native
/// H3 mapping. Unknown static indices are rejected.
pub fn qpack_plan_to_header_fields(
    plan: &[QpackFieldPlan],
    qpack_context: Option<&QpackContext>,
) -> Result<Vec<(String, String)>, H3NativeError> {
    let mut out = Vec::with_capacity(plan.len());
    for field in plan {
        match field {
            QpackFieldPlan::StaticIndex(index) => {
                let (name, value) = qpack_static_entry(*index)
                    .ok_or(H3NativeError::InvalidFrame("unknown static qpack index"))?;
                out.push((name.to_string(), value.to_string()));
            }
            QpackFieldPlan::DynamicIndex(index) => {
                if let Some(context) = qpack_context {
                    let (name, value) = qpack_dynamic_entry(context.dynamic_table(), *index)
                        .ok_or(H3NativeError::InvalidFrame("unknown dynamic qpack index"))?;
                    out.push((name.to_string(), value.to_string()));
                } else {
                    return Err(H3NativeError::InvalidFrame(
                        "dynamic table context required",
                    ));
                }
            }
            QpackFieldPlan::DynamicNameLiteral { name_index, value } => {
                if let Some(context) = qpack_context {
                    let name = qpack_dynamic_name(context.dynamic_table(), *name_index).ok_or(
                        H3NativeError::InvalidFrame("unknown dynamic qpack name index"),
                    )?;
                    out.push((name.to_string(), value.clone()));
                } else {
                    return Err(H3NativeError::InvalidFrame(
                        "dynamic table context required",
                    ));
                }
            }
            QpackFieldPlan::Literal { name, value } => {
                out.push((name.clone(), value.clone()));
            }
        }
    }
    Ok(out)
}

fn decoded_field_section_size(fields: &[(String, String)]) -> Result<u64, H3NativeError> {
    fields.iter().try_fold(0u64, |acc, (name, value)| {
        let field_size = name
            .len()
            .checked_add(value.len())
            .and_then(|size| size.checked_add(32))
            .ok_or(H3NativeError::QpackPolicy(
                "decoded field section exceeds addressable range",
            ))?;
        let field_size = u64::try_from(field_size).map_err(|_| {
            H3NativeError::QpackPolicy("decoded field section exceeds addressable range")
        })?;
        acc.checked_add(field_size)
            .ok_or(H3NativeError::QpackPolicy(
                "decoded field section exceeds addressable range",
            ))
    })
}

/// Decode a wire-level request field section into a validated request head.
///
/// This applies QPACK decode rules for the configured mode and then enforces
/// HTTP/3 pseudo-header semantics:
/// - pseudo-headers must appear before regular headers
/// - duplicate pseudo-headers are rejected
/// - request-only pseudo-header set is validated
pub fn qpack_decode_request_field_section(
    input: &[u8],
    mode: H3QpackMode,
    qpack_context: Option<&QpackContext>,
) -> Result<H3RequestHead, H3NativeError> {
    qpack_decode_request_field_section_with_limit(input, mode, qpack_context, None)
}

/// Decode a wire-level request field section with optional size limit enforcement.
///
/// This applies QPACK decode rules for the configured mode and then enforces
/// HTTP/3 pseudo-header semantics. If `max_field_section_size` is Some, the total
/// size of all decoded headers (names + values) is checked against the limit.
pub fn qpack_decode_request_field_section_with_limit(
    input: &[u8],
    mode: H3QpackMode,
    qpack_context: Option<&QpackContext>,
    max_field_section_size: Option<u64>,
) -> Result<H3RequestHead, H3NativeError> {
    let plan = qpack_decode_field_section_with_context(input, mode, qpack_context)?;
    let fields = qpack_plan_to_header_fields(&plan, qpack_context)?;

    if let Some(max_size) = max_field_section_size {
        if decoded_field_section_size(&fields)? > max_size {
            return Err(H3NativeError::QpackPolicy(
                "decoded field section exceeds maximum size limit",
            ));
        }
    }

    header_fields_to_request_head(&fields)
}

/// Decode a wire-level response field section into a validated response head.
///
/// This applies QPACK decode rules for the configured mode and then enforces
/// HTTP/3 pseudo-header semantics:
/// - pseudo-headers must appear before regular headers
/// - only `:status` is allowed
/// - duplicate or malformed `:status` is rejected
pub fn qpack_decode_response_field_section(
    input: &[u8],
    mode: H3QpackMode,
    qpack_context: Option<&QpackContext>,
) -> Result<H3ResponseHead, H3NativeError> {
    qpack_decode_response_field_section_with_limit(input, mode, qpack_context, None)
}

/// Decode and validate an HTTP/3 trailer field section.
///
/// Trailers use ordinary HTTP fields only: every pseudo-header is forbidden,
/// while the normal lowercase-name, connection-specific-field, and value
/// safety rules remain enforced.
pub fn qpack_decode_trailer_field_section(
    input: &[u8],
    mode: H3QpackMode,
    qpack_context: Option<&QpackContext>,
) -> Result<Vec<(String, String)>, H3NativeError> {
    let plan = qpack_decode_field_section_with_context(input, mode, qpack_context)?;
    let fields = qpack_plan_to_header_fields(&plan, qpack_context)?;
    for (name, value) in &fields {
        validate_header_name(name)?;
        validate_header_value(value)?;
        if name.starts_with(':') {
            return Err(H3NativeError::InvalidFrame(
                "pseudo header forbidden in HTTP/3 trailers",
            ));
        }
    }
    Ok(fields)
}

/// Decode a wire-level response field section with optional size limit enforcement.
///
/// This applies QPACK decode rules for the configured mode and then enforces
/// HTTP/3 pseudo-header semantics. If `max_field_section_size` is Some, the total
/// size of all decoded headers (names + values) is checked against the limit.
pub fn qpack_decode_response_field_section_with_limit(
    input: &[u8],
    mode: H3QpackMode,
    qpack_context: Option<&QpackContext>,
    max_field_section_size: Option<u64>,
) -> Result<H3ResponseHead, H3NativeError> {
    let plan = qpack_decode_field_section_with_context(input, mode, qpack_context)?;
    let fields = qpack_plan_to_header_fields(&plan, qpack_context)?;

    if let Some(max_size) = max_field_section_size {
        if decoded_field_section_size(&fields)? > max_size {
            return Err(H3NativeError::QpackPolicy(
                "decoded field section exceeds maximum size limit",
            ));
        }
    }

    header_fields_to_response_head(&fields)
}

/// br-asupersync-5vj2xy — Header field names forbidden in HTTP/3 per
/// RFC 9114 §4.2 ("HTTP Fields"). These are connection-specific
/// fields whose semantics map to HTTP/1.1 wire framing and are
/// meaningless or actively harmful when carried over a multiplexed
/// HTTP/3 stream. RFC 9114 §4.2 says any such field on the wire
/// MUST be treated as malformed; the spec gives the exact list.
///
/// `te` is NOT forbidden as a name (it's allowed when the value is
/// exactly the token `trailers`); per-value validation for `te` is
/// handled separately via `validate_te_value` and is out of scope
/// for this name-level check.
const H3_FORBIDDEN_HEADER_NAMES: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
    "upgrade",
];

/// Validate that a header field name contains only valid characters per
/// RFC 9110 §5.1, is lowercase per HTTP/3 requirements (RFC 9114 §4.2),
/// and is not on the RFC 9114 §4.2 forbidden list (br-asupersync-5vj2xy).
fn validate_header_name(name: &str) -> Result<(), H3NativeError> {
    if name.is_empty() {
        return Err(H3NativeError::InvalidFrame("empty header field name"));
    }
    let bytes = name.as_bytes();
    let start = if bytes[0] == b':' {
        if bytes.len() == 1 {
            return Err(H3NativeError::InvalidFrame("empty header field name"));
        }
        1
    } else {
        0
    };
    for &b in &bytes[start..] {
        match b {
            // RFC 9110 token characters (subset: ALPHA / DIGIT / specials)
            b'a'..=b'z'
            | b'0'..=b'9'
            | b'!'
            | b'#'
            | b'$'
            | b'%'
            | b'&'
            | b'\''
            | b'*'
            | b'+'
            | b'-'
            | b'.'
            | b'^'
            | b'_'
            | b'`'
            | b'|'
            | b'~' => {}
            b'A'..=b'Z' => {
                return Err(H3NativeError::InvalidFrame(
                    "header field name must be lowercase in HTTP/3",
                ));
            }
            _ => {
                return Err(H3NativeError::InvalidFrame(
                    "header field name contains invalid character",
                ));
            }
        }
    }
    // br-asupersync-5vj2xy — RFC 9114 §4.2 forbidden-header check.
    // The name has already passed the lowercase enforcement above, so
    // an exact match against the lowercase forbidden list is correct.
    if H3_FORBIDDEN_HEADER_NAMES.contains(&name) {
        return Err(H3NativeError::InvalidFrame(
            "header field name forbidden in HTTP/3 (RFC 9114 §4.2)",
        ));
    }
    Ok(())
}

/// Validate that a header field value does not contain null bytes, CR, or LF.
fn validate_header_value(value: &str) -> Result<(), H3NativeError> {
    for &b in value.as_bytes() {
        if b == 0 || b == b'\r' || b == b'\n' {
            return Err(H3NativeError::InvalidFrame(
                "header field value contains forbidden character (NUL, CR, or LF)",
            ));
        }
    }
    Ok(())
}

fn validate_method_token(method: &str) -> Result<(), H3NativeError> {
    if method.is_empty() {
        return Err(H3NativeError::InvalidRequestPseudoHeader("empty :method"));
    }
    for &b in method.as_bytes() {
        match b {
            b'a'..=b'z'
            | b'A'..=b'Z'
            | b'0'..=b'9'
            | b'!'
            | b'#'
            | b'$'
            | b'%'
            | b'&'
            | b'\''
            | b'*'
            | b'+'
            | b'-'
            | b'.'
            | b'^'
            | b'_'
            | b'`'
            | b'|'
            | b'~' => {}
            _ => {
                return Err(H3NativeError::InvalidRequestPseudoHeader(
                    ":method must be a valid HTTP token",
                ));
            }
        }
    }
    Ok(())
}

fn validate_scheme_syntax(scheme: &str) -> Result<(), H3NativeError> {
    let Some((&first, rest)) = scheme.as_bytes().split_first() else {
        return Err(H3NativeError::InvalidRequestPseudoHeader("empty :scheme"));
    };
    if !first.is_ascii_alphabetic() {
        return Err(H3NativeError::InvalidRequestPseudoHeader(
            ":scheme must be a valid URI scheme",
        ));
    }
    for &b in rest {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'+' | b'-' | b'.' => {}
            _ => {
                return Err(H3NativeError::InvalidRequestPseudoHeader(
                    ":scheme must be a valid URI scheme",
                ));
            }
        }
    }
    Ok(())
}

fn validate_authority_form(authority: &str) -> Result<(), H3NativeError> {
    if authority.as_bytes().iter().any(u8::is_ascii_whitespace) {
        return Err(H3NativeError::InvalidRequestPseudoHeader(
            ":authority must be RFC authority-form without whitespace",
        ));
    }
    if authority.contains('@') {
        return Err(H3NativeError::InvalidRequestPseudoHeader(
            ":authority must not include userinfo",
        ));
    }
    if authority.contains(['/', '?', '#']) {
        return Err(H3NativeError::InvalidRequestPseudoHeader(
            ":authority must not contain path, query, or fragment",
        ));
    }
    if authority.starts_with('[') {
        let bracket_end = authority
            .find(']')
            .ok_or(H3NativeError::InvalidRequestPseudoHeader(
                ":authority has invalid IPv6 literal",
            ))?;
        let literal = &authority[1..bracket_end];
        if literal.parse::<Ipv6Addr>().is_err() {
            return Err(H3NativeError::InvalidRequestPseudoHeader(
                ":authority has invalid IPv6 literal",
            ));
        }
        let rest = &authority[bracket_end + 1..];
        if rest.is_empty() {
            return Ok(());
        }
        let Some(port_str) = rest.strip_prefix(':') else {
            return Err(H3NativeError::InvalidRequestPseudoHeader(
                ":authority has invalid IPv6 literal",
            ));
        };
        if port_str.is_empty() || port_str.parse::<u16>().is_err() {
            return Err(H3NativeError::InvalidRequestPseudoHeader(
                ":authority has invalid port",
            ));
        }
        return Ok(());
    }
    if authority.matches(':').count() > 1 {
        return Err(H3NativeError::InvalidRequestPseudoHeader(
            ":authority IPv6 literals must use [addr] form",
        ));
    }
    if let Some((host, port_str)) = authority.rsplit_once(':') {
        if host.is_empty() || port_str.is_empty() || port_str.parse::<u16>().is_err() {
            return Err(H3NativeError::InvalidRequestPseudoHeader(
                ":authority has invalid port",
            ));
        }
    }
    Ok(())
}

fn validate_request_path(method: &str, path: &str) -> Result<(), H3NativeError> {
    if path == "*" {
        if method != "OPTIONS" {
            return Err(H3NativeError::InvalidRequestPseudoHeader(
                "asterisk-form :path requires OPTIONS",
            ));
        }
        return Ok(());
    }
    if !path.starts_with('/') {
        return Err(H3NativeError::InvalidRequestPseudoHeader(
            ":path must start with /",
        ));
    }
    Ok(())
}

fn parse_status_code(value: &str) -> Result<u16, H3NativeError> {
    let bytes = value.as_bytes();
    if bytes.len() != 3 || !bytes.iter().all(u8::is_ascii_digit) {
        return Err(H3NativeError::InvalidResponsePseudoHeader(
            "invalid :status value",
        ));
    }
    value
        .parse::<u16>()
        .map_err(|_| H3NativeError::InvalidResponsePseudoHeader("invalid :status value"))
}

fn header_fields_to_request_head(
    fields: &[(String, String)],
) -> Result<H3RequestHead, H3NativeError> {
    let mut pseudo = H3PseudoHeaders::default();
    let mut headers = Vec::new();
    let mut saw_regular_headers = false;

    for (name, value) in fields {
        validate_header_name(name)?;
        validate_header_value(value)?;
        if name.starts_with(':') {
            if saw_regular_headers {
                return Err(H3NativeError::InvalidRequestPseudoHeader(
                    "request pseudo headers must precede regular headers",
                ));
            }
            match name.as_str() {
                ":method" => {
                    if pseudo.method.is_some() {
                        return Err(H3NativeError::InvalidRequestPseudoHeader(
                            "duplicate :method",
                        ));
                    }
                    pseudo.method = Some(value.clone());
                }
                ":scheme" => {
                    if pseudo.scheme.is_some() {
                        return Err(H3NativeError::InvalidRequestPseudoHeader(
                            "duplicate :scheme",
                        ));
                    }
                    pseudo.scheme = Some(value.clone());
                }
                ":authority" => {
                    if pseudo.authority.is_some() {
                        return Err(H3NativeError::InvalidRequestPseudoHeader(
                            "duplicate :authority",
                        ));
                    }
                    pseudo.authority = Some(value.clone());
                }
                ":path" => {
                    if pseudo.path.is_some() {
                        return Err(H3NativeError::InvalidRequestPseudoHeader("duplicate :path"));
                    }
                    pseudo.path = Some(value.clone());
                }
                ":status" => {
                    return Err(H3NativeError::InvalidRequestPseudoHeader(
                        "request must not include :status",
                    ));
                }
                _ => {
                    return Err(H3NativeError::InvalidRequestPseudoHeader(
                        "unknown request pseudo header",
                    ));
                }
            }
        } else {
            saw_regular_headers = true;
            headers.push((name.clone(), value.clone()));
        }
    }

    H3RequestHead::new(pseudo, headers)
}

fn header_fields_to_response_head(
    fields: &[(String, String)],
) -> Result<H3ResponseHead, H3NativeError> {
    let mut status: Option<u16> = None;
    let mut headers = Vec::new();
    let mut saw_regular_headers = false;

    for (name, value) in fields {
        validate_header_name(name)?;
        validate_header_value(value)?;
        if name.starts_with(':') {
            if saw_regular_headers {
                return Err(H3NativeError::InvalidResponsePseudoHeader(
                    "response pseudo headers must precede regular headers",
                ));
            }
            match name.as_str() {
                ":status" => {
                    if status.is_some() {
                        return Err(H3NativeError::InvalidResponsePseudoHeader(
                            "duplicate :status",
                        ));
                    }
                    let parsed = parse_status_code(value)?;
                    status = Some(parsed);
                }
                _ => {
                    return Err(H3NativeError::InvalidResponsePseudoHeader(
                        "response must not include request pseudo headers",
                    ));
                }
            }
        } else {
            saw_regular_headers = true;
            headers.push((name.clone(), value.clone()));
        }
    }

    let status = status.ok_or(H3NativeError::InvalidResponsePseudoHeader(
        "missing :status",
    ))?;
    H3ResponseHead::new(status, headers)
}

fn qpack_encode_prefixed_int(
    out: &mut Vec<u8>,
    prefix_bits: u8,
    prefix_len: u8,
    mut value: u64,
) -> Result<(), H3NativeError> {
    if !(1..=8).contains(&prefix_len) {
        return Err(H3NativeError::InvalidFrame(
            "invalid qpack integer prefix length",
        ));
    }
    let max_in_prefix = (1u64 << prefix_len) - 1;
    if value < max_in_prefix {
        out.push(prefix_bits | (value as u8));
        return Ok(());
    }
    out.push(prefix_bits | (max_in_prefix as u8));
    value -= max_in_prefix;
    while value >= 128 {
        out.push(((value as u8) & 0x7F) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
    Ok(())
}

fn qpack_decode_prefixed_int(
    first: u8,
    prefix_len: u8,
    input: &[u8],
) -> Result<(u64, usize), H3NativeError> {
    if !(1..=8).contains(&prefix_len) {
        return Err(H3NativeError::InvalidFrame(
            "invalid qpack integer prefix length",
        ));
    }
    let mask = ((1u16 << prefix_len) - 1) as u8;
    let mut value = u64::from(first & mask);
    let max_in_prefix = u64::from(mask);
    if value < max_in_prefix {
        return Ok((value, 0));
    }

    let mut shift = 0u32;
    let mut consumed = 0usize;
    loop {
        let byte = *input.get(consumed).ok_or(H3NativeError::UnexpectedEof)?;
        consumed += 1;
        let part = u64::from(byte & 0x7F);
        let shifted = part
            .checked_shl(shift)
            .ok_or(H3NativeError::InvalidFrame("qpack integer overflow"))?;
        value = value
            .checked_add(shifted)
            .ok_or(H3NativeError::InvalidFrame("qpack integer overflow"))?;
        if (byte & 0x80) == 0 {
            return Ok((value, consumed));
        }
        shift = shift.saturating_add(7);
        // Cap at shift 56 to prevent silent truncation: checked_shl(63)
        // succeeds but silently drops high bits (e.g. 2u64 << 63 = 0).
        // Any legitimate u64 value fits within 9 continuation bytes
        // (prefix bits + 9×7 = prefix + 63 bits).
        if shift > 56 {
            return Err(H3NativeError::InvalidFrame("qpack integer overflow"));
        }
    }
}

fn qpack_encode_string(
    out: &mut Vec<u8>,
    prefix_bits: u8,
    prefix_len: u8,
    value: &str,
) -> Result<(), H3NativeError> {
    let bytes = value.as_bytes();
    let huffman_len = hpack_huffman_encoded_size(bytes);
    if huffman_len < bytes.len() {
        qpack_encode_prefixed_int(
            out,
            prefix_bits | (1u8 << prefix_len),
            prefix_len,
            huffman_len as u64,
        )?;
        let mut encoded = BytesMut::with_capacity(huffman_len);
        hpack_encode_huffman(&mut encoded, bytes);
        out.extend_from_slice(&encoded);
    } else {
        qpack_encode_prefixed_int(out, prefix_bits, prefix_len, bytes.len() as u64)?;
        out.extend_from_slice(bytes);
    }
    Ok(())
}

fn qpack_decode_string(
    first: u8,
    prefix_len: u8,
    input: &[u8],
) -> Result<(String, usize), H3NativeError> {
    if prefix_len >= 8 {
        return Err(H3NativeError::InvalidFrame(
            "qpack string prefix length must be less than 8",
        ));
    }
    let huffman_bit = 1u8 << prefix_len;
    let (len, extra) = qpack_decode_prefixed_int(first, prefix_len, input)?;
    let len: usize = len.try_into().map_err(|_| {
        H3NativeError::InvalidFrame("qpack string length exceeds addressable range")
    })?;
    if input.len().saturating_sub(extra) < len {
        return Err(H3NativeError::UnexpectedEof);
    }
    let bytes = &input[extra..extra + len];
    let value = if (first & huffman_bit) != 0 {
        let encoded = Bytes::copy_from_slice(bytes);
        hpack_decode_huffman(&encoded)
            .map_err(|_| H3NativeError::InvalidFrame("invalid qpack huffman string"))?
    } else {
        std::str::from_utf8(bytes)
            .map_err(|_| H3NativeError::InvalidFrame("qpack string is not valid utf-8"))?
            .to_string()
    };
    Ok((value, extra + len))
}

fn qpack_static_name(index: u64) -> Option<&'static str> {
    qpack_static_entry(index).map(|(name, _)| name)
}

fn qpack_static_entry(index: u64) -> Option<(&'static str, &'static str)> {
    // RFC 9204 Appendix A — complete QPACK static table (indices 0–98).
    match index {
        0 => Some((":authority", "")),
        1 => Some((":path", "/")),
        2 => Some(("age", "0")),
        3 => Some(("content-disposition", "")),
        4 => Some(("content-length", "0")),
        5 => Some(("cookie", "")),
        6 => Some(("date", "")),
        7 => Some(("etag", "")),
        8 => Some(("if-modified-since", "")),
        9 => Some(("if-none-match", "")),
        10 => Some(("last-modified", "")),
        11 => Some(("link", "")),
        12 => Some(("location", "")),
        13 => Some(("referer", "")),
        14 => Some(("set-cookie", "")),
        15 => Some((":method", "CONNECT")),
        16 => Some((":method", "DELETE")),
        17 => Some((":method", "GET")),
        18 => Some((":method", "HEAD")),
        19 => Some((":method", "OPTIONS")),
        20 => Some((":method", "POST")),
        21 => Some((":method", "PUT")),
        22 => Some((":scheme", "http")),
        23 => Some((":scheme", "https")),
        24 => Some((":status", "103")),
        25 => Some((":status", "200")),
        26 => Some((":status", "304")),
        27 => Some((":status", "404")),
        28 => Some((":status", "503")),
        29 => Some(("accept", "*/*")),
        30 => Some(("accept", "application/dns-message")),
        31 => Some(("accept-encoding", "gzip, deflate, br")),
        32 => Some(("accept-ranges", "bytes")),
        33 => Some(("access-control-allow-headers", "cache-control")),
        34 => Some(("access-control-allow-headers", "content-type")),
        35 => Some(("access-control-allow-origin", "*")),
        36 => Some(("cache-control", "max-age=0")),
        37 => Some(("cache-control", "max-age=2592000")),
        38 => Some(("cache-control", "max-age=604800")),
        39 => Some(("cache-control", "no-cache")),
        40 => Some(("cache-control", "no-store")),
        41 => Some(("cache-control", "public, max-age=31536000")),
        42 => Some(("content-encoding", "br")),
        43 => Some(("content-encoding", "gzip")),
        44 => Some(("content-type", "application/dns-message")),
        45 => Some(("content-type", "application/javascript")),
        46 => Some(("content-type", "application/json")),
        47 => Some(("content-type", "application/x-www-form-urlencoded")),
        48 => Some(("content-type", "image/gif")),
        49 => Some(("content-type", "image/jpeg")),
        50 => Some(("content-type", "image/png")),
        51 => Some(("content-type", "text/css")),
        52 => Some(("content-type", "text/html; charset=utf-8")),
        53 => Some(("content-type", "text/plain")),
        54 => Some(("content-type", "text/plain;charset=utf-8")),
        55 => Some(("range", "bytes=0-")),
        56 => Some(("strict-transport-security", "max-age=31536000")),
        57 => Some((
            "strict-transport-security",
            "max-age=31536000; includesubdomains",
        )),
        58 => Some((
            "strict-transport-security",
            "max-age=31536000; includesubdomains; preload",
        )),
        59 => Some(("vary", "accept-encoding")),
        60 => Some(("vary", "origin")),
        61 => Some(("x-content-type-options", "nosniff")),
        62 => Some(("x-xss-protection", "1; mode=block")),
        63 => Some((":status", "100")),
        64 => Some((":status", "204")),
        65 => Some((":status", "206")),
        66 => Some((":status", "302")),
        67 => Some((":status", "400")),
        68 => Some((":status", "403")),
        69 => Some((":status", "421")),
        70 => Some((":status", "425")),
        71 => Some((":status", "500")),
        72 => Some(("accept-language", "")),
        73 => Some(("access-control-allow-credentials", "FALSE")),
        74 => Some(("access-control-allow-credentials", "TRUE")),
        75 => Some(("access-control-allow-headers", "*")),
        76 => Some(("access-control-allow-methods", "get")),
        77 => Some(("access-control-allow-methods", "get, post, options")),
        78 => Some(("access-control-allow-methods", "options")),
        79 => Some(("access-control-expose-headers", "content-length")),
        80 => Some(("access-control-request-headers", "content-type")),
        81 => Some(("access-control-request-method", "get")),
        82 => Some(("access-control-request-method", "post")),
        83 => Some(("alt-svc", "clear")),
        84 => Some(("authorization", "")),
        85 => Some((
            "content-security-policy",
            "script-src 'none'; object-src 'none'; base-uri 'none'",
        )),
        86 => Some(("early-data", "1")),
        87 => Some(("expect-ct", "")),
        88 => Some(("forwarded", "")),
        89 => Some(("if-range", "")),
        90 => Some(("origin", "")),
        91 => Some(("purpose", "prefetch")),
        92 => Some(("server", "")),
        93 => Some(("timing-allow-origin", "*")),
        94 => Some(("upgrade-insecure-requests", "1")),
        95 => Some(("user-agent", "")),
        96 => Some(("x-forwarded-for", "")),
        97 => Some(("x-frame-options", "deny")),
        98 => Some(("x-frame-options", "sameorigin")),
        _ => None,
    }
}

fn qpack_static_method_index(method: &str) -> Option<u64> {
    match method {
        "CONNECT" => Some(15),
        "DELETE" => Some(16),
        "GET" => Some(17),
        "HEAD" => Some(18),
        "OPTIONS" => Some(19),
        "POST" => Some(20),
        "PUT" => Some(21),
        _ => None,
    }
}

fn qpack_static_scheme_index(scheme: &str) -> Option<u64> {
    match scheme {
        "http" => Some(22),
        "https" => Some(23),
        _ => None,
    }
}

fn qpack_static_status_index(status: u16) -> Option<u64> {
    match status {
        103 => Some(24),
        200 => Some(25),
        304 => Some(26),
        404 => Some(27),
        503 => Some(28),
        100 => Some(63),
        204 => Some(64),
        206 => Some(65),
        302 => Some(66),
        400 => Some(67),
        403 => Some(68),
        421 => Some(69),
        425 => Some(70),
        500 => Some(71),
        _ => None,
    }
}

/// Request-stream frame progression state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct H3RequestStreamState {
    header_blocks_seen: u8,
    saw_data: bool,
    end_stream: bool,
}

impl H3RequestStreamState {
    /// Construct default request-stream state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply one request-stream frame with ordering checks.
    pub fn on_frame(&mut self, frame: &H3Frame) -> Result<(), H3NativeError> {
        if self.end_stream {
            return Err(H3NativeError::ControlProtocol(
                "request stream already finished",
            ));
        }
        match frame {
            H3Frame::Headers(_) => {
                if self.header_blocks_seen == 0 {
                    self.header_blocks_seen = 1;
                    return Ok(());
                }
                // A second HEADERS block is interpreted as trailers.
                // RFC 9114 §4.1: message format is HEADERS + DATA* + HEADERS?
                // where DATA* means zero or more DATA frames, so trailers are
                // valid immediately after the initial HEADERS with no DATA.
                if self.header_blocks_seen == 1 {
                    self.header_blocks_seen = 2;
                    return Ok(());
                }
                Err(H3NativeError::ControlProtocol(
                    "invalid HEADERS ordering on request stream",
                ))
            }
            H3Frame::Data(_) => {
                if self.header_blocks_seen == 0 {
                    return Err(H3NativeError::ControlProtocol(
                        "DATA before initial HEADERS on request stream",
                    ));
                }
                if self.header_blocks_seen > 1 {
                    return Err(H3NativeError::ControlProtocol(
                        "DATA not allowed after trailing HEADERS",
                    ));
                }
                self.saw_data = true;
                Ok(())
            }
            H3Frame::Datagram { .. } => {
                // br-asupersync-8w9naj: per RFC 9297 §2, DATAGRAM
                // frames are allowed on bidirectional request streams
                // as an alternative framing for streamed payloads —
                // notably CONNECT-UDP (RFC 9298 §3) and CONNECT-IP
                // (RFC 9484) which carry their tunnelled UDP/IP
                // datagrams via H3 DATAGRAM frames keyed by the
                // quarter-stream-id derived from the stream's ID.
                //
                // The project's own allow-list at
                // `validate_bidirectional_frame` (this file, line ~618)
                // and the bidi dispatch at line ~578 both correctly
                // permit `H3Frame::Datagram { .. }` on bidi streams.
                // The previous implementation of on_frame's catch-all
                // contradicted them by rejecting all non-HEADERS/DATA
                // frames — silently breaking RFC 9297/9298 interop
                // for any client that opened an Extended-CONNECT
                // session.
                //
                // DATAGRAM frames do NOT participate in the HEADERS +
                // DATA* + TRAILERS sequence — they're an out-of-band
                // sidecar for the same stream. We therefore neither
                // advance `header_blocks_seen` nor set `saw_data`;
                // we only require that the initial HEADERS frame
                // arrived first, which establishes the stream's
                // semantic identity (request method, protocol target,
                // capsule protocol negotiation per RFC 9297 §2.2).
                if self.header_blocks_seen == 0 {
                    return Err(H3NativeError::ControlProtocol(
                        "DATAGRAM before initial HEADERS on request stream",
                    ));
                }
                Ok(())
            }
            H3Frame::PushPromise { .. } | H3Frame::Unknown { .. } => Ok(()),
            H3Frame::Settings(_)
            | H3Frame::CancelPush(_)
            | H3Frame::Goaway(_)
            | H3Frame::MaxPushId(_) => Err(H3NativeError::ControlProtocol(
                "control frames are not valid on request streams",
            )),
        }
    }

    fn on_informational_response_headers(&mut self) -> Result<(), H3NativeError> {
        if self.end_stream {
            return Err(H3NativeError::ControlProtocol(
                "request stream already finished",
            ));
        }
        if self.header_blocks_seen != 0 || self.saw_data {
            return Err(H3NativeError::ControlProtocol(
                "informational response HEADERS must precede final response HEADERS",
            ));
        }
        Ok(())
    }

    /// Mark end-of-stream.
    pub fn mark_end_stream(&mut self) -> Result<(), H3NativeError> {
        if self.header_blocks_seen == 0 {
            return Err(H3NativeError::ControlProtocol(
                "request stream ended before initial HEADERS",
            ));
        }
        self.end_stream = true;
        Ok(())
    }
}

/// Push-stream state: push ID header plus response frame progression.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct H3PushStreamState {
    push_id: Option<u64>,
    response: H3RequestStreamState,
}

/// Lightweight HTTP/3 connection mapping state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct H3ConnectionState {
    config: H3ConnectionConfig,
    control: H3ControlState,
    request_streams: BTreeMap<u64, H3RequestStreamState>,
    finished_request_streams: BTreeSet<u64>,
    max_contiguous_finished_request_stream_id: Option<u64>,
    push_streams: BTreeMap<u64, H3PushStreamState>,
    used_push_ids: BTreeSet<u64>,
    uni_stream_types: BTreeMap<u64, H3UniStreamType>,
    control_stream_id: Option<u64>,
    qpack_encoder_stream_id: Option<u64>,
    qpack_decoder_stream_id: Option<u64>,
    goaway_id: Option<u64>,
}

impl H3ConnectionState {
    /// Construct default state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct state for a local HTTP/3 client.
    #[must_use]
    pub fn new_client() -> Self {
        Self::new()
    }

    /// Construct state for a local HTTP/3 server.
    #[must_use]
    pub fn new_server() -> Self {
        Self::with_config(H3ConnectionConfig {
            endpoint_role: H3EndpointRole::Server,
            ..H3ConnectionConfig::default()
        })
    }

    /// Construct state from explicit config.
    #[must_use]
    pub fn with_config(config: H3ConnectionConfig) -> Self {
        Self {
            config,
            control: H3ControlState::default(),
            request_streams: BTreeMap::new(),
            finished_request_streams: BTreeSet::new(),
            max_contiguous_finished_request_stream_id: None,
            push_streams: BTreeMap::new(),
            used_push_ids: BTreeSet::new(),
            uni_stream_types: BTreeMap::new(),
            control_stream_id: None,
            qpack_encoder_stream_id: None,
            qpack_decoder_stream_id: None,
            goaway_id: None,
        }
    }

    fn is_request_stream_finished(&self, stream_id: u64) -> bool {
        if let Some(max_contig) = self.max_contiguous_finished_request_stream_id {
            if stream_id <= max_contig {
                return true;
            }
        }
        self.finished_request_streams.contains(&stream_id)
    }

    /// Process a control-stream frame.
    pub fn on_control_frame(&mut self, frame: &H3Frame) -> Result<(), H3NativeError> {
        self.control.on_remote_control_frame(frame)?;
        if self.config.endpoint_role == H3EndpointRole::Client
            && matches!(frame, H3Frame::MaxPushId(_))
        {
            return Err(H3NativeError::ControlProtocol(
                "client must not receive MAX_PUSH_ID",
            ));
        }
        if let H3Frame::Goaway(id) = frame {
            if self.config.endpoint_role == H3EndpointRole::Client
                && !is_client_initiated_bidirectional_stream_id(*id)
            {
                return Err(H3NativeError::ControlProtocol(
                    "GOAWAY id must be a client-initiated bidirectional stream id",
                ));
            }
            if self.goaway_id.is_some_and(|prev| *id > prev) {
                return Err(H3NativeError::ControlProtocol(
                    "GOAWAY id must not increase",
                ));
            }
            self.goaway_id = Some(*id);
        }
        Ok(())
    }

    /// Process a request-stream frame.
    pub fn on_request_stream_frame(
        &mut self,
        stream_id: u64,
        frame: &H3Frame,
    ) -> Result<(), H3NativeError> {
        if !is_client_initiated_bidirectional_stream_id(stream_id) {
            return Err(H3NativeError::StreamProtocol(
                "request stream id must be client-initiated bidirectional",
            ));
        }
        if self.uni_stream_types.contains_key(&stream_id) {
            return Err(H3NativeError::StreamProtocol(
                "request stream id is registered as unidirectional",
            ));
        }
        if self.is_request_stream_finished(stream_id) {
            return Err(H3NativeError::ControlProtocol(
                "request stream already finished",
            ));
        }
        if self.config.endpoint_role == H3EndpointRole::Client
            && let Some(goaway_id) = self.goaway_id
            && stream_id >= goaway_id
        {
            return Err(H3NativeError::ControlProtocol(
                "request stream id rejected after GOAWAY",
            ));
        }
        // RFC 9114 §5.1.2: reject new streams that would exceed the
        // peer-negotiated QUIC bidi-stream cap. Previously-seen streams
        // (still live, or already finished) pass through unchanged so that
        // in-flight frames and trailers can complete normally.
        let request_stream_exists = self.request_streams.contains_key(&stream_id);
        if matches!(frame, H3Frame::Unknown { .. }) && !request_stream_exists {
            return Ok(());
        }
        if let Some(limit) = self.config.max_concurrent_request_streams
            && !request_stream_exists
            && self.request_streams.len() as u64 >= limit
        {
            return Err(H3NativeError::ConcurrentStreamLimitExceeded {
                active: self.request_streams.len() as u64,
                limit,
            });
        }
        if let Some(state) = self.request_streams.get_mut(&stream_id) {
            return state.on_frame(frame);
        }
        let mut state = H3RequestStreamState::new();
        state.on_frame(frame)?;
        self.request_streams.insert(stream_id, state);
        Ok(())
    }

    /// Register one 1xx response HEADERS block without advancing the final
    /// response/trailers state machine.
    ///
    /// HTTP/3 clients may receive zero or more informational responses before
    /// the final response. The decoded status is supplied by the mapping layer;
    /// raw request-stream framing alone cannot distinguish that sequence from
    /// request trailers.
    pub fn on_informational_response_headers(
        &mut self,
        stream_id: u64,
    ) -> Result<(), H3NativeError> {
        if self.config.endpoint_role != H3EndpointRole::Client {
            return Err(H3NativeError::ControlProtocol(
                "informational response HEADERS are client-side only",
            ));
        }
        if !is_client_initiated_bidirectional_stream_id(stream_id) {
            return Err(H3NativeError::StreamProtocol(
                "request stream id must be client-initiated bidirectional",
            ));
        }
        if self.uni_stream_types.contains_key(&stream_id) {
            return Err(H3NativeError::StreamProtocol(
                "request stream id is registered as unidirectional",
            ));
        }
        if self.is_request_stream_finished(stream_id) {
            return Err(H3NativeError::ControlProtocol(
                "request stream already finished",
            ));
        }
        if let Some(goaway_id) = self.goaway_id
            && stream_id >= goaway_id
        {
            return Err(H3NativeError::ControlProtocol(
                "request stream id rejected after GOAWAY",
            ));
        }
        let request_stream_exists = self.request_streams.contains_key(&stream_id);
        if let Some(limit) = self.config.max_concurrent_request_streams
            && !request_stream_exists
            && self.request_streams.len() as u64 >= limit
        {
            return Err(H3NativeError::ConcurrentStreamLimitExceeded {
                active: self.request_streams.len() as u64,
                limit,
            });
        }
        if let Some(state) = self.request_streams.get_mut(&stream_id) {
            return state.on_informational_response_headers();
        }
        let mut state = H3RequestStreamState::new();
        state.on_informational_response_headers()?;
        self.request_streams.insert(stream_id, state);
        Ok(())
    }

    /// Number of currently live (non-finished) request streams. Use this with
    /// `H3ConnectionConfig::max_concurrent_request_streams` to surface "near
    /// limit" observability to the transport layer.
    #[must_use]
    pub fn active_request_stream_count(&self) -> u64 {
        self.request_streams.len() as u64
    }

    /// Update the peer-advertised concurrent-stream cap mid-connection.
    ///
    /// QUIC MAX_STREAMS frames can raise the limit; the peer MUST NOT reduce
    /// it, but we accept any value here and leave policy to the caller. The
    /// new limit applies only to future new-stream requests — already-live
    /// streams are never retroactively rejected.
    pub fn set_max_concurrent_request_streams(&mut self, limit: Option<u64>) {
        self.config.max_concurrent_request_streams = limit;
    }

    /// Mark request-stream end and remove it from tracking.
    pub fn finish_request_stream(&mut self, stream_id: u64) -> Result<(), H3NativeError> {
        if self.is_request_stream_finished(stream_id) {
            return Err(H3NativeError::ControlProtocol(
                "request stream already finished",
            ));
        }
        let state =
            self.request_streams
                .get_mut(&stream_id)
                .ok_or(H3NativeError::ControlProtocol(
                    "unknown request stream on finish",
                ))?;
        state.mark_end_stream()?;
        // Drop detailed state but retain the finished stream id so late frames
        // on the same QUIC stream are still rejected as protocol violations.
        self.request_streams.remove(&stream_id);
        self.record_terminal_request_stream(stream_id);

        Ok(())
    }

    /// Abort a request stream after transport RESET_STREAM.
    ///
    /// A reset can race ahead of buffered HEADERS, so an otherwise unknown
    /// request stream is still recorded terminally. The return value reports
    /// whether a live HTTP/3 request state was retired.
    pub fn abort_request_stream(&mut self, stream_id: u64) -> Result<bool, H3NativeError> {
        if !is_client_initiated_bidirectional_stream_id(stream_id) {
            return Err(H3NativeError::StreamProtocol(
                "request stream id must be client-initiated bidirectional",
            ));
        }
        if self.uni_stream_types.contains_key(&stream_id) {
            return Err(H3NativeError::StreamProtocol(
                "request stream id is registered as unidirectional",
            ));
        }
        if self.is_request_stream_finished(stream_id) {
            return Ok(false);
        }
        let retired_live_state = self.request_streams.remove(&stream_id).is_some();
        self.record_terminal_request_stream(stream_id);
        Ok(retired_live_state)
    }

    fn record_terminal_request_stream(&mut self, stream_id: u64) {
        self.finished_request_streams.insert(stream_id);

        // Compact finished streams to avoid unbounded memory growth.
        // Client bidi streams start at 0 and increment by 4.
        let mut next_expected = self
            .max_contiguous_finished_request_stream_id
            .map_or(0, |id| id + 4);
        while self.finished_request_streams.remove(&next_expected) {
            self.max_contiguous_finished_request_stream_id = Some(next_expected);
            next_expected += 4;
        }
    }

    /// Process the required push-stream header carrying the promised push ID.
    pub fn on_push_stream_header(
        &mut self,
        stream_id: u64,
        push_id: u64,
    ) -> Result<(), H3NativeError> {
        match self.uni_stream_types.get(&stream_id) {
            Some(H3UniStreamType::Push) => {}
            Some(_) => {
                return Err(H3NativeError::StreamProtocol(
                    "push stream header requires a push stream",
                ));
            }
            None => {
                return Err(H3NativeError::StreamProtocol(
                    "unknown unidirectional stream",
                ));
            }
        }

        let state = self
            .push_streams
            .get_mut(&stream_id)
            .ok_or(H3NativeError::StreamProtocol("unknown push stream"))?;

        if state.push_id.is_some() {
            return Err(H3NativeError::StreamProtocol(
                "push stream header already received",
            ));
        }
        if !self.used_push_ids.insert(push_id) {
            return Err(H3NativeError::StreamProtocol(
                "duplicate push id in push stream header",
            ));
        }

        state.push_id = Some(push_id);
        Ok(())
    }

    /// Register and validate the type of a newly opened remote unidirectional stream.
    pub fn on_remote_uni_stream_type(
        &mut self,
        stream_id: u64,
        stream_type: u64,
    ) -> Result<H3UniStreamType, H3NativeError> {
        if !is_unidirectional_stream_id(stream_id) {
            return Err(H3NativeError::StreamProtocol(
                "unidirectional stream type requires unidirectional stream id",
            ));
        }
        if !is_peer_initiated_unidirectional_stream_id(stream_id, self.config.endpoint_role) {
            return Err(H3NativeError::StreamProtocol(
                "unidirectional stream type requires peer-initiated unidirectional stream id",
            ));
        }
        let kind = H3UniStreamType::decode(stream_type);
        if self.uni_stream_types.contains_key(&stream_id) {
            return Err(H3NativeError::StreamProtocol(
                "unidirectional stream type already set",
            ));
        }
        match kind {
            H3UniStreamType::Control => {
                if self.control_stream_id.is_some() {
                    return Err(H3NativeError::ControlProtocol(
                        "duplicate remote control stream",
                    ));
                }
                self.control_stream_id = Some(stream_id);
            }
            H3UniStreamType::QpackEncoder => {
                if self.qpack_encoder_stream_id.is_some() {
                    return Err(H3NativeError::StreamProtocol(
                        "duplicate remote qpack encoder stream",
                    ));
                }
                self.qpack_encoder_stream_id = Some(stream_id);
            }
            H3UniStreamType::QpackDecoder => {
                if self.qpack_decoder_stream_id.is_some() {
                    return Err(H3NativeError::StreamProtocol(
                        "duplicate remote qpack decoder stream",
                    ));
                }
                self.qpack_decoder_stream_id = Some(stream_id);
            }
            H3UniStreamType::Push => {
                if self.config.endpoint_role != H3EndpointRole::Client {
                    return Err(H3NativeError::StreamProtocol(
                        "server endpoint must not receive push streams",
                    ));
                }
                self.push_streams.entry(stream_id).or_default();
            }
            H3UniStreamType::Unknown(_) => {
                // RFC 9114 §6.2: unknown stream types are accepted and
                // their data is discarded by the caller.
            }
        }
        self.uni_stream_types.insert(stream_id, kind);
        Ok(kind)
    }

    /// Process a frame on a previously typed unidirectional stream.
    pub fn on_uni_stream_frame(
        &mut self,
        stream_id: u64,
        frame: &H3Frame,
    ) -> Result<(), H3NativeError> {
        let kind =
            self.uni_stream_types
                .get(&stream_id)
                .copied()
                .ok_or(H3NativeError::StreamProtocol(
                    "unknown unidirectional stream",
                ))?;
        match kind {
            H3UniStreamType::Control => self.on_control_frame(frame),
            H3UniStreamType::Push => {
                let state = self.push_streams.entry(stream_id).or_default();
                if state.push_id.is_none() {
                    return Err(H3NativeError::StreamProtocol("push stream missing push id"));
                }
                state.response.on_frame(frame)
            }
            H3UniStreamType::QpackEncoder | H3UniStreamType::QpackDecoder => Err(
                H3NativeError::StreamProtocol("qpack streams carry instructions, not h3 frames"),
            ),
            H3UniStreamType::Unknown(_) => {
                // RFC 9114 §6.2: data on unknown stream types is discarded.
                Ok(())
            }
        }
    }

    /// Registered remote unidirectional stream type for `stream_id`.
    #[must_use]
    pub fn remote_uni_stream_type(&self, stream_id: u64) -> Option<H3UniStreamType> {
        self.uni_stream_types.get(&stream_id).copied()
    }

    /// Remote QPACK encoder-stream id, if the peer opened one.
    #[must_use]
    pub fn qpack_encoder_stream_id(&self) -> Option<u64> {
        self.qpack_encoder_stream_id
    }

    /// Remote QPACK decoder-stream id, if the peer opened one.
    #[must_use]
    pub fn qpack_decoder_stream_id(&self) -> Option<u64> {
        self.qpack_decoder_stream_id
    }

    /// Register a previously typed remote QPACK stream with instruction state.
    pub fn register_qpack_instruction_stream(
        &self,
        qpack: &mut QpackInstructionStreamState,
        stream_id: u64,
    ) -> Result<H3UniStreamType, H3NativeError> {
        qpack.register_from_connection(self, stream_id)
    }

    /// Feed raw QPACK instruction bytes from a typed remote unidirectional stream.
    ///
    /// QPACK encoder/decoder streams remain separate from HTTP/3 frame parsing:
    /// `on_uni_stream_frame` still rejects them as frame streams, while this API
    /// processes their RFC 9204 instruction bytes.
    pub fn feed_qpack_instruction_stream_bytes(
        &self,
        qpack: &mut QpackInstructionStreamState,
        stream_id: u64,
        bytes: &[u8],
    ) -> Result<QpackInstructionStreamOutcome, H3NativeError> {
        let kind = self
            .remote_uni_stream_type(stream_id)
            .ok_or(H3NativeError::StreamProtocol(
                "unknown unidirectional stream",
            ))?;
        qpack.ensure_stream_registered(stream_id, kind)?;
        qpack.feed_instruction_stream_bytes(stream_id, kind, bytes)
    }

    /// Current GOAWAY stream identifier, if any.
    #[must_use]
    pub fn goaway_id(&self) -> Option<u64> {
        self.goaway_id
    }

    /// QPACK mode configured for this connection.
    #[must_use]
    pub fn qpack_mode(&self) -> H3QpackMode {
        self.config.qpack_mode
    }

    /// Endpoint role configured for this connection mapping.
    #[must_use]
    pub fn endpoint_role(&self) -> H3EndpointRole {
        self.config.endpoint_role
    }
}

fn is_unidirectional_stream_id(stream_id: u64) -> bool {
    (stream_id & 0x2) != 0
}

fn is_client_initiated_bidirectional_stream_id(stream_id: u64) -> bool {
    stream_id.trailing_zeros() >= 2
}

fn is_client_initiated_unidirectional_stream_id(stream_id: u64) -> bool {
    (stream_id & 0x3) == 0x2
}

fn is_server_initiated_unidirectional_stream_id(stream_id: u64) -> bool {
    (stream_id & 0x3) == 0x3
}

fn is_peer_initiated_unidirectional_stream_id(
    stream_id: u64,
    endpoint_role: H3EndpointRole,
) -> bool {
    match endpoint_role {
        H3EndpointRole::Client => is_server_initiated_unidirectional_stream_id(stream_id),
        H3EndpointRole::Server => is_client_initiated_unidirectional_stream_id(stream_id),
    }
}

/// Validate request pseudo headers.
pub fn validate_request_pseudo_headers(headers: &H3PseudoHeaders) -> Result<(), H3NativeError> {
    validate_request_pseudo_headers_with_settings(headers, false)
}

/// Validate request pseudo headers with extended CONNECT protocol support.
///
/// When `enable_connect_protocol` is true, CONNECT requests are allowed to
/// include :scheme and :path pseudo-headers per RFC 8441.
pub fn validate_request_pseudo_headers_with_settings(
    headers: &H3PseudoHeaders,
    enable_connect_protocol: bool,
) -> Result<(), H3NativeError> {
    let method = headers
        .method
        .as_deref()
        .ok_or(H3NativeError::InvalidRequestPseudoHeader("missing :method"))?;
    validate_header_value(method)?;
    validate_method_token(method)?;
    if headers.status.is_some() {
        return Err(H3NativeError::InvalidRequestPseudoHeader(
            "request must not include :status",
        ));
    }
    if method == "CONNECT" {
        let authority =
            headers
                .authority
                .as_deref()
                .ok_or(H3NativeError::InvalidRequestPseudoHeader(
                    "CONNECT request missing :authority",
                ))?;
        validate_header_value(authority)?;
        if authority.is_empty() {
            return Err(H3NativeError::InvalidRequestPseudoHeader(
                "CONNECT request missing :authority",
            ));
        }
        validate_authority_form(authority)?;

        // RFC 8441 Extended CONNECT Protocol support
        if enable_connect_protocol {
            // Extended CONNECT: allow :scheme/:path, require :protocol
            if let Some(protocol) = &headers.protocol {
                validate_header_value(protocol)?;
                if protocol.is_empty() {
                    return Err(H3NativeError::InvalidRequestPseudoHeader(
                        "extended CONNECT request :protocol must not be empty",
                    ));
                }
            } else {
                return Err(H3NativeError::InvalidRequestPseudoHeader(
                    "extended CONNECT request missing :protocol",
                ));
            }

            // Validate :scheme and :path if present (optional for extended CONNECT)
            if let Some(scheme) = &headers.scheme {
                validate_header_value(scheme)?;
                validate_scheme_syntax(scheme)?;
            }
            if let Some(path) = &headers.path {
                validate_header_value(path)?;
                validate_request_path("CONNECT", path)?;
            }
        } else {
            // Standard CONNECT: reject :scheme/:path/:protocol
            if headers.scheme.is_some() || headers.path.is_some() {
                return Err(H3NativeError::InvalidRequestPseudoHeader(
                    "CONNECT request must not include :scheme or :path",
                ));
            }
            if headers.protocol.is_some() {
                return Err(H3NativeError::InvalidRequestPseudoHeader(
                    "CONNECT request must not include :protocol (extended CONNECT not enabled)",
                ));
            }
        }
        return Ok(());
    }
    let scheme = headers
        .scheme
        .as_deref()
        .ok_or(H3NativeError::InvalidRequestPseudoHeader("missing :scheme"))?;
    validate_header_value(scheme)?;
    if scheme.is_empty() {
        return Err(H3NativeError::InvalidRequestPseudoHeader("empty :scheme"));
    }
    validate_scheme_syntax(scheme)?;
    let path = headers
        .path
        .as_deref()
        .ok_or(H3NativeError::InvalidRequestPseudoHeader("missing :path"))?;
    validate_header_value(path)?;
    if path.is_empty() {
        return Err(H3NativeError::InvalidRequestPseudoHeader("empty :path"));
    }
    validate_request_path(method, path)?;
    if let Some(authority) = headers.authority.as_deref() {
        validate_header_value(authority)?;
        if authority.is_empty() {
            return Err(H3NativeError::InvalidRequestPseudoHeader(
                "empty :authority",
            ));
        }
        validate_authority_form(authority)?;
    }
    Ok(())
}

/// Validate response pseudo headers.
pub fn validate_response_pseudo_headers(headers: &H3PseudoHeaders) -> Result<(), H3NativeError> {
    let status = headers
        .status
        .ok_or(H3NativeError::InvalidResponsePseudoHeader(
            "missing :status",
        ))?;
    if !(100..=999).contains(&status) {
        return Err(H3NativeError::InvalidResponsePseudoHeader(
            "status must be in 100..=999",
        ));
    }
    if status == 101 {
        return Err(H3NativeError::InvalidResponsePseudoHeader(
            "HTTP/3 does not support 101 Switching Protocols",
        ));
    }
    if headers.method.is_some()
        || headers.scheme.is_some()
        || headers.authority.is_some()
        || headers.path.is_some()
    {
        return Err(H3NativeError::InvalidResponsePseudoHeader(
            "response must not include request pseudo headers",
        ));
    }
    Ok(())
}

/// Dynamic table entry for QPACK compression.
#[derive(Debug, Clone)]
pub struct QpackDynamicEntry {
    name: String,
    value: String,
    size: usize,
    reference_count: usize,
    insertion_order: u64,
}

impl QpackDynamicEntry {
    fn new(name: String, value: String, insertion_order: u64) -> Self {
        // RFC 9204 size calculation with overflow protection
        let size = name.len().saturating_add(value.len()).saturating_add(32);
        Self {
            name,
            value,
            size,
            reference_count: 0,
            insertion_order,
        }
    }

    fn add_reference(&mut self) {
        self.reference_count = self.reference_count.saturating_add(1);
    }

    fn remove_reference(&mut self) {
        self.reference_count = self.reference_count.saturating_sub(1);
    }

    fn is_referenced(&self) -> bool {
        self.reference_count > 0
    }

    /// Get the header name for this entry.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the header value for this entry.
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Get the insertion order ID for this entry.
    pub fn insertion_id(&self) -> u64 {
        self.insertion_order
    }
}

/// Dynamic table for QPACK header compression.
///
/// Implements RFC 9204 QPACK dynamic table with LRU eviction and reference protection.
#[derive(Debug)]
pub struct QpackDynamicTable {
    entries: Vec<QpackDynamicEntry>,
    max_capacity: usize,
    current_size: usize,
    insertion_counter: u64,
    evicted_count: usize,
}

impl QpackDynamicTable {
    /// Create a new dynamic table with the specified capacity.
    pub fn new(max_capacity: usize) -> Self {
        Self {
            entries: Vec::new(),
            max_capacity,
            current_size: 0,
            insertion_counter: 0,
            evicted_count: 0,
        }
    }

    /// Insert a new header entry into the dynamic table.
    ///
    /// Returns the insertion ID on success, or an error if the entry cannot be inserted.
    pub fn insert(&mut self, name: String, value: String) -> Result<u64, &'static str> {
        let entry = QpackDynamicEntry::new(name, value, self.insertion_counter);
        let entry_size = entry.size;

        if entry_size > self.max_capacity {
            return Err("entry larger than table capacity");
        }

        // Evict entries to make space (LRU with reference checking)
        // Use saturating arithmetic to prevent overflow in capacity check
        while self.current_size.saturating_add(entry_size) > self.max_capacity {
            if !self.evict_lru_unreferenced() {
                return Err("cannot evict enough space (all entries referenced)");
            }
        }

        let insertion_id = self.insertion_counter;
        self.entries.push(entry);
        // Use saturating arithmetic to prevent overflow in size tracking
        self.current_size = self.current_size.saturating_add(entry_size);
        self.insertion_counter += 1;

        Ok(insertion_id)
    }

    /// Set the table capacity and evict least-recently-inserted unreferenced entries as needed.
    pub fn set_capacity(&mut self, max_capacity: usize) -> Result<(), &'static str> {
        if self.current_size <= max_capacity {
            self.max_capacity = max_capacity;
            return Ok(());
        }

        let mut candidates = Vec::new();
        let mut freed = 0usize;
        for (index, entry) in self.entries.iter().enumerate() {
            if entry.is_referenced() {
                continue;
            }
            candidates.push(index);
            freed += entry.size;
            if self.current_size - freed <= max_capacity {
                break;
            }
        }

        if self.current_size - freed > max_capacity {
            return Err("cannot reduce table capacity while entries are referenced");
        }

        self.max_capacity = max_capacity;
        for index in candidates.into_iter().rev() {
            let evicted = self.entries.remove(index);
            self.current_size -= evicted.size;
            self.evicted_count += 1;
        }
        Ok(())
    }

    /// Evict the least recently inserted unreferenced entry.
    fn evict_lru_unreferenced(&mut self) -> bool {
        // Find the least recently used unreferenced entry
        let mut lru_index = None;
        let mut lru_insertion_order = u64::MAX;

        for (i, entry) in self.entries.iter().enumerate() {
            if !entry.is_referenced() && entry.insertion_order < lru_insertion_order {
                lru_insertion_order = entry.insertion_order;
                lru_index = Some(i);
            }
        }

        if let Some(index) = lru_index {
            let evicted = self.entries.remove(index);
            self.current_size -= evicted.size;
            self.evicted_count += 1;
            true
        } else {
            false
        }
    }

    /// Add a reference to an entry by insertion ID.
    pub fn reference_entry(&mut self, insertion_id: u64) -> bool {
        if let Some(entry) = self
            .entries
            .iter_mut()
            .find(|e| e.insertion_order == insertion_id)
        {
            entry.add_reference();
            true
        } else {
            false
        }
    }

    /// Remove a reference from an entry by insertion ID.
    pub fn unreference_entry(&mut self, insertion_id: u64) -> bool {
        if let Some(entry) = self
            .entries
            .iter_mut()
            .find(|e| e.insertion_order == insertion_id)
        {
            entry.remove_reference();
            true
        } else {
            false
        }
    }

    /// Get an entry by absolute index / insertion ID.
    pub fn get_by_absolute_index(&self, absolute_index: u64) -> Option<&QpackDynamicEntry> {
        self.get_by_insertion_id(absolute_index)
    }

    /// Get an entry by insertion id.
    pub fn get_by_insertion_id(&self, insertion_id: u64) -> Option<&QpackDynamicEntry> {
        if insertion_id >= self.insertion_counter {
            return None;
        }
        self.entries
            .iter()
            .find(|entry| entry.insertion_order == insertion_id)
    }

    /// Get an entry by encoder-stream relative index.
    pub fn get_by_relative_index(&self, relative_index: u64) -> Option<&QpackDynamicEntry> {
        let insertion_id = self
            .insertion_counter
            .checked_sub(1)?
            .checked_sub(relative_index)?;
        self.get_by_insertion_id(insertion_id)
    }

    /// Get the number of entries in the table.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the table is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get the current size of the table in bytes.
    pub fn size(&self) -> usize {
        self.current_size
    }

    /// Get the maximum capacity of the table in bytes.
    pub fn capacity(&self) -> usize {
        self.max_capacity
    }

    /// Get the current insertion counter value.
    pub fn insertion_counter(&self) -> u64 {
        self.insertion_counter
    }

    /// Get the number of entries evicted from this table.
    pub fn evicted_count(&self) -> usize {
        self.evicted_count
    }
}

impl Default for QpackDynamicTable {
    fn default() -> Self {
        Self::new(4096) // Default 4KB capacity
    }
}

/// Look up a dynamic table entry by absolute index.
///
/// Returns None if the index is out of bounds or the entry doesn't exist.
pub fn qpack_dynamic_entry(table: &QpackDynamicTable, absolute_index: u64) -> Option<(&str, &str)> {
    table
        .get_by_absolute_index(absolute_index)
        .map(|entry| (entry.name(), entry.value()))
}

/// Look up a dynamic table entry name by absolute index.
///
/// Returns None if the index is out of bounds or the entry doesn't exist.
pub fn qpack_dynamic_name(table: &QpackDynamicTable, absolute_index: u64) -> Option<&str> {
    table
        .get_by_absolute_index(absolute_index)
        .map(|entry| entry.name())
}

/// QPACK encoding/decoding context with dynamic table support.
#[derive(Debug)]
pub struct QpackContext {
    /// Dynamic table for encoder and decoder
    dynamic_table: QpackDynamicTable,
    /// Maximum table capacity from peer settings
    max_table_capacity: usize,
}

impl QpackContext {
    /// Create a new QPACK context with the specified table capacity.
    pub fn new(max_table_capacity: usize) -> Self {
        Self {
            dynamic_table: QpackDynamicTable::new(max_table_capacity),
            max_table_capacity,
        }
    }

    /// Get a reference to the dynamic table.
    pub fn dynamic_table(&self) -> &QpackDynamicTable {
        &self.dynamic_table
    }

    /// Get a mutable reference to the dynamic table.
    pub fn dynamic_table_mut(&mut self) -> &mut QpackDynamicTable {
        &mut self.dynamic_table
    }

    /// Get the peer-advertised maximum dynamic table capacity.
    pub fn max_table_capacity(&self) -> usize {
        self.max_table_capacity
    }

    /// Set the active dynamic table capacity.
    pub fn set_dynamic_table_capacity(&mut self, capacity: usize) -> Result<(), &'static str> {
        if capacity > self.max_table_capacity {
            return Err("capacity exceeds peer limit");
        }
        self.dynamic_table.set_capacity(capacity)
    }

    /// Insert a new entry into the dynamic table.
    pub fn insert_dynamic_entry(
        &mut self,
        name: String,
        value: String,
    ) -> Result<u64, &'static str> {
        self.dynamic_table.insert(name, value)
    }
}

impl Default for QpackContext {
    fn default() -> Self {
        Self::new(4096)
    }
}

#[cfg(test)]
include!("h3_native_tests.rs");
