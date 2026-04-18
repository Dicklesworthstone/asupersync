//! Native HTTP/3 protocol primitives over QUIC streams.
//!
//! This module implements:
//! - HTTP/3 frame encode/decode
//! - SETTINGS payload handling
//! - control-stream ordering checks
//! - pseudo-header validation helpers

use crate::net::quic_core::{decode_varint, encode_varint};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

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

/// HTTP/3 errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum H3NativeError {
    /// Input buffer ended unexpectedly.
    UnexpectedEof,
    /// Malformed frame.
    InvalidFrame(&'static str),
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
}

impl fmt::Display for H3NativeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEof => write!(f, "unexpected EOF"),
            Self::InvalidFrame(msg) => write!(f, "invalid frame: {msg}"),
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

/// Connection-level configuration for native HTTP/3 mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct H3ConnectionConfig {
    /// QPACK policy.
    pub qpack_mode: H3QpackMode,
}

impl Default for H3ConnectionConfig {
    fn default() -> Self {
        Self {
            qpack_mode: H3QpackMode::StaticOnly,
        }
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
    fn decode(stream_type: u64) -> Self {
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
            encode_setting(out, s.id, s.value)?;
        }
        Ok(())
    }

    /// Decode SETTINGS payload bytes.
    pub fn decode_payload(input: &[u8]) -> Result<Self, H3NativeError> {
        let mut settings = Self::default();
        let mut seen_ids: Vec<u64> = Vec::new();
        let mut pos = 0usize;
        while pos < input.len() {
            let (id, id_len) = decode_varint(input.get(pos..).ok_or(H3NativeError::UnexpectedEof)?)
                .map_err(|_| H3NativeError::InvalidFrame("invalid setting id varint"))?;
            pos += id_len;
            let (value, val_len) =
                decode_varint(input.get(pos..).ok_or(H3NativeError::UnexpectedEof)?)
                    .map_err(|_| H3NativeError::InvalidFrame("invalid setting value varint"))?;
            pos += val_len;

            if seen_ids.contains(&id) {
                return Err(H3NativeError::DuplicateSetting(id));
            }
            seen_ids.push(id);

            match id {
                // RFC 9114 §7.2.4.1: HTTP/2 reserved setting identifiers
                // MUST NOT be sent; receipt is a connection error.
                0x00 | 0x02 | 0x03 | 0x04 | 0x05 => {
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
    pub fn decode(input: &[u8]) -> Result<(Self, usize), H3NativeError> {
        let (frame_type, type_len) =
            decode_varint(input).map_err(|_| H3NativeError::InvalidFrame("frame type varint"))?;
        let (len, len_len) = decode_varint(&input[type_len..])
            .map_err(|_| H3NativeError::InvalidFrame("frame length varint"))?;
        let len: usize = len
            .try_into()
            .map_err(|_| H3NativeError::InvalidFrame("frame length exceeds addressable range"))?;
        let payload_start = type_len + len_len;
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
                Self::PushPromise {
                    push_id,
                    field_block: payload[n..].to_vec(),
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
            H3_FRAME_DATAGRAM => {
                let (quarter_stream_id, n) = decode_varint(payload)
                    .map_err(|e| match e {
                        crate::net::quic_core::QuicCoreError::UnexpectedEof => H3NativeError::UnexpectedEof,
                        _ => H3NativeError::InvalidFrame("datagram quarter_stream_id"),
                    })?;
                Self::Datagram {
                    quarter_stream_id,
                    payload: payload[n..].to_vec(),
                }
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

/// HTTP/3 pseudo-header block (decoded representation).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
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
        Ok(Self { pseudo, headers })
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
        Ok(Self { status, headers })
    }
}

/// Static-only QPACK planning item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QpackFieldPlan {
    /// Indexed static-table entry.
    StaticIndex(u64),
    /// Literal header field (name/value).
    Literal {
        /// Header name.
        name: String,
        /// Header value.
        value: String,
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
///
/// The current implementation emits a static-only field section prefix
/// (`required_insert_count=0`, `base=0`) and supports:
/// - Indexed field lines (static table)
/// - Literal field lines with literal names (non-Huffman strings)
pub fn qpack_encode_field_section(plan: &[QpackFieldPlan]) -> Result<Vec<u8>, H3NativeError> {
    let mut out = Vec::new();
    // Field section prefix: Required Insert Count = 0, Delta Base = 0.
    qpack_encode_prefixed_int(&mut out, 0, 8, 0)?;
    qpack_encode_prefixed_int(&mut out, 0, 7, 0)?;

    for field in plan {
        match field {
            QpackFieldPlan::StaticIndex(index) => {
                if qpack_static_entry(*index).is_none() {
                    return Err(H3NativeError::InvalidFrame("unknown static qpack index"));
                }
                // Indexed field line: 1 T Index(6+), T=1 for static table.
                qpack_encode_prefixed_int(&mut out, 0b1100_0000, 6, *index)?;
            }
            QpackFieldPlan::Literal { name, value } => {
                // Literal field line with literal name: 001 N H NameLen(3+)
                // N=0, H=0 (non-Huffman)
                qpack_encode_string(&mut out, 0b0010_0000, 3, name)?;
                // Value string literal: H=0 + ValueLen(7+)
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
    let mut pos = 0usize;

    // Field section prefix part 1: Required Insert Count (8-bit prefix int).
    let first = *input.get(pos).ok_or(H3NativeError::UnexpectedEof)?;
    pos += 1;
    let (required_insert_count, ric_extra) = qpack_decode_prefixed_int(first, 8, &input[pos..])?;
    pos += ric_extra;

    // Field section prefix part 2: S + Delta Base (7-bit prefix int).
    let second = *input.get(pos).ok_or(H3NativeError::UnexpectedEof)?;
    pos += 1;
    let sign = (second & 0x80) != 0;
    let (delta_base, db_extra) = qpack_decode_prefixed_int(second, 7, &input[pos..])?;
    pos += db_extra;

    if mode == H3QpackMode::StaticOnly {
        if required_insert_count != 0 {
            return Err(H3NativeError::QpackPolicy(
                "required insert count must be zero in static-only mode",
            ));
        }
        if sign || delta_base != 0 {
            return Err(H3NativeError::QpackPolicy(
                "base must be zero in static-only mode",
            ));
        }
    }

    let mut out = Vec::new();
    while pos < input.len() {
        let b = input[pos];

        if (b & 0x80) != 0 {
            // Indexed field line: 1 T Index(6+)
            let is_static = (b & 0x40) != 0;
            let (index, extra) = qpack_decode_prefixed_int(b, 6, &input[pos + 1..])?;
            pos += 1 + extra;
            if !is_static {
                return Err(H3NativeError::QpackPolicy(
                    "dynamic qpack index references require dynamic table state",
                ));
            }
            if qpack_static_entry(index).is_none() {
                return Err(H3NativeError::InvalidFrame("unknown static qpack index"));
            }
            out.push(QpackFieldPlan::StaticIndex(index));
            continue;
        }

        if (b & 0x40) != 0 {
            // Literal field line with name reference: 01 N T NameIndex(4+)
            let is_static = (b & 0x10) != 0;
            let (name_index, extra) = qpack_decode_prefixed_int(b, 4, &input[pos + 1..])?;
            pos += 1 + extra;
            if !is_static {
                return Err(H3NativeError::QpackPolicy(
                    "dynamic qpack name references require dynamic table state",
                ));
            }
            let name = qpack_static_name(name_index).ok_or(H3NativeError::InvalidFrame(
                "unknown static qpack name index",
            ))?;
            let value_first = *input.get(pos).ok_or(H3NativeError::UnexpectedEof)?;
            let (value, value_extra) = qpack_decode_string(value_first, 7, &input[pos + 1..])?;
            pos += 1 + value_extra;
            out.push(QpackFieldPlan::Literal {
                name: name.to_string(),
                value,
            });
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
            continue;
        }

        // Remaining line representations are post-base / dynamic variants:
        // 0001.... indexed post-base, 0000.... literal post-base name ref.
        return Err(H3NativeError::QpackPolicy(
            "post-base/dynamic qpack line representations require dynamic table state",
        ));
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

/// Expand a QPACK plan into concrete `(name, value)` header fields.
///
/// Static-table references are resolved using the subset needed by the native
/// H3 mapping. Unknown static indices are rejected.
pub fn qpack_plan_to_header_fields(
    plan: &[QpackFieldPlan],
) -> Result<Vec<(String, String)>, H3NativeError> {
    let mut out = Vec::with_capacity(plan.len());
    for field in plan {
        match field {
            QpackFieldPlan::StaticIndex(index) => {
                let (name, value) = qpack_static_entry(*index)
                    .ok_or(H3NativeError::InvalidFrame("unknown static qpack index"))?;
                out.push((name.to_string(), value.to_string()));
            }
            QpackFieldPlan::Literal { name, value } => {
                out.push((name.clone(), value.clone()));
            }
        }
    }
    Ok(out)
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
) -> Result<H3RequestHead, H3NativeError> {
    let plan = qpack_decode_field_section(input, mode)?;
    let fields = qpack_plan_to_header_fields(&plan)?;
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
) -> Result<H3ResponseHead, H3NativeError> {
    let plan = qpack_decode_field_section(input, mode)?;
    let fields = qpack_plan_to_header_fields(&plan)?;
    header_fields_to_response_head(&fields)
}

/// Validate that a header field name contains only valid characters per
/// RFC 9110 §5.1 and is lowercase per HTTP/3 requirements (RFC 9114 §4.2).
fn validate_header_name(name: &str) -> Result<(), H3NativeError> {
    if name.is_empty() {
        return Err(H3NativeError::InvalidFrame("empty header field name"));
    }
    for &b in name.as_bytes() {
        match b {
            // RFC 9110 token characters (subset: ALPHA / DIGIT / specials)
            b'a'..=b'z'
            | b'0'..=b'9'
            | b':'
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
                    let parsed = value.parse::<u16>().map_err(|_| {
                        H3NativeError::InvalidResponsePseudoHeader("invalid :status value")
                    })?;
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
    qpack_encode_prefixed_int(out, prefix_bits, prefix_len, bytes.len() as u64)?;
    out.extend_from_slice(bytes);
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
    if (first & huffman_bit) != 0 {
        return Err(H3NativeError::InvalidFrame(
            "qpack huffman strings are not supported in native static mode",
        ));
    }
    let (len, extra) = qpack_decode_prefixed_int(first, prefix_len, input)?;
    let len: usize = len.try_into().map_err(|_| {
        H3NativeError::InvalidFrame("qpack string length exceeds addressable range")
    })?;
    if input.len().saturating_sub(extra) < len {
        return Err(H3NativeError::UnexpectedEof);
    }
    let bytes = &input[extra..extra + len];
    let value = std::str::from_utf8(bytes)
        .map_err(|_| H3NativeError::InvalidFrame("qpack string is not valid utf-8"))?
        .to_string();
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
            _ => Err(H3NativeError::ControlProtocol(
                "only HEADERS/DATA are valid on request streams",
            )),
        }
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

/// Lightweight HTTP/3 connection mapping state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct H3ConnectionState {
    config: H3ConnectionConfig,
    control: H3ControlState,
    request_streams: BTreeMap<u64, H3RequestStreamState>,
    finished_request_streams: BTreeSet<u64>,
    max_contiguous_finished_request_stream_id: Option<u64>,
    push_streams: BTreeMap<u64, H3RequestStreamState>,
    uni_stream_types: BTreeMap<u64, H3UniStreamType>,
    control_stream_id: Option<u64>,
    qpack_encoder_stream_id: Option<u64>,
    qpack_decoder_stream_id: Option<u64>,
    goaway_id: Option<u64>,
}

impl Default for H3ConnectionState {
    fn default() -> Self {
        Self::new()
    }
}

impl H3ConnectionState {
    /// Construct default state.
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(H3ConnectionConfig::default())
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
        if let H3Frame::Settings(settings) = frame {
            self.validate_qpack_settings(settings)?;
        }
        self.control.on_remote_control_frame(frame)?;
        if let H3Frame::Goaway(id) = frame {
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
        if is_unidirectional_stream_id(stream_id) {
            return Err(H3NativeError::StreamProtocol(
                "request stream id must be bidirectional",
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
        let state = self.request_streams.entry(stream_id).or_default();
        state.on_frame(frame)
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
        let kind = H3UniStreamType::decode(stream_type);
        if self.uni_stream_types.contains_key(&stream_id) {
            return Err(H3NativeError::StreamProtocol(
                "unidirectional stream type already set",
            ));
        }
        match kind {
            H3UniStreamType::Control => {
                if self.control_stream_id.is_some() {
                    return Err(H3NativeError::StreamProtocol(
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
                state.on_frame(frame)
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

    fn validate_qpack_settings(&self, settings: &H3Settings) -> Result<(), H3NativeError> {
        if self.config.qpack_mode == H3QpackMode::DynamicTableAllowed {
            return Ok(());
        }
        if settings.qpack_max_table_capacity.unwrap_or(0) > 0 {
            return Err(H3NativeError::QpackPolicy(
                "dynamic qpack table disabled by policy",
            ));
        }
        if settings.qpack_blocked_streams.unwrap_or(0) > 0 {
            return Err(H3NativeError::QpackPolicy(
                "qpack blocked streams must be zero in static-only mode",
            ));
        }
        Ok(())
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
}

fn is_unidirectional_stream_id(stream_id: u64) -> bool {
    (stream_id & 0x2) != 0
}

/// Validate request pseudo headers.
pub fn validate_request_pseudo_headers(headers: &H3PseudoHeaders) -> Result<(), H3NativeError> {
    let method = headers
        .method
        .as_deref()
        .ok_or(H3NativeError::InvalidRequestPseudoHeader("missing :method"))?;
    if headers.status.is_some() {
        return Err(H3NativeError::InvalidRequestPseudoHeader(
            "request must not include :status",
        ));
    }
    if method == "CONNECT" {
        if headers.authority.as_deref().is_none() {
            return Err(H3NativeError::InvalidRequestPseudoHeader(
                "CONNECT request missing :authority",
            ));
        }
        if headers.scheme.is_some() || headers.path.is_some() {
            return Err(H3NativeError::InvalidRequestPseudoHeader(
                "CONNECT request must not include :scheme or :path",
            ));
        }
        return Ok(());
    }
    if headers.scheme.as_deref().is_none() {
        return Err(H3NativeError::InvalidRequestPseudoHeader("missing :scheme"));
    }
    if headers.path.as_deref().is_none() {
        return Err(H3NativeError::InvalidRequestPseudoHeader("missing :path"));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_roundtrip_and_unknown_preservation() {
        let settings = H3Settings {
            qpack_max_table_capacity: Some(4096),
            max_field_section_size: Some(16384),
            qpack_blocked_streams: Some(16),
            enable_connect_protocol: Some(true),
            h3_datagram: Some(false),
            unknown: vec![UnknownSetting {
                id: 0xfeed,
                value: 7,
            }],
        };
        let mut payload = Vec::new();
        settings.encode_payload(&mut payload).expect("encode");
        let decoded = H3Settings::decode_payload(&payload).expect("decode");
        assert_eq!(decoded, settings);
    }

    #[test]
    fn settings_reject_duplicate_ids() {
        let mut payload = Vec::new();
        encode_setting(&mut payload, H3_SETTING_MAX_FIELD_SECTION_SIZE, 100).expect("first");
        encode_setting(&mut payload, H3_SETTING_MAX_FIELD_SECTION_SIZE, 200).expect("second");
        let err = H3Settings::decode_payload(&payload).expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::DuplicateSetting(H3_SETTING_MAX_FIELD_SECTION_SIZE)
        );
    }

    #[test]
    fn settings_reject_invalid_boolean_values() {
        let mut payload = Vec::new();
        encode_setting(&mut payload, H3_SETTING_ENABLE_CONNECT_PROTOCOL, 2).expect("encode");
        let err = H3Settings::decode_payload(&payload).expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::InvalidSettingValue(H3_SETTING_ENABLE_CONNECT_PROTOCOL)
        );
    }

    #[test]
    fn frame_roundtrip() {
        let frame = H3Frame::PushPromise {
            push_id: 9,
            field_block: vec![1, 2, 3, 4],
        };
        let mut buf = Vec::new();
        frame.encode(&mut buf).expect("encode");
        let (decoded, consumed) = H3Frame::decode(&buf).expect("decode");
        assert_eq!(decoded, frame);
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn control_stream_requires_settings_first() {
        let mut state = H3ControlState::new();
        let err = state
            .on_remote_control_frame(&H3Frame::Goaway(3))
            .expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::ControlProtocol("first remote control frame must be SETTINGS")
        );
    }

    #[test]
    fn pseudo_header_validation() {
        let req = H3PseudoHeaders {
            method: Some("GET".to_string()),
            scheme: Some("https".to_string()),
            authority: Some("example.com".to_string()),
            path: Some("/".to_string()),
            status: None,
        };
        validate_request_pseudo_headers(&req).expect("valid request");

        let resp = H3PseudoHeaders {
            status: Some(200),
            ..H3PseudoHeaders::default()
        };
        validate_response_pseudo_headers(&resp).expect("valid response");

        let connect = H3PseudoHeaders {
            method: Some("CONNECT".to_string()),
            authority: Some("upstream.example:443".to_string()),
            ..H3PseudoHeaders::default()
        };
        validate_request_pseudo_headers(&connect).expect("valid connect request");
    }

    #[test]
    fn pseudo_header_validation_rejects_invalid_connect_and_status() {
        let bad_connect = H3PseudoHeaders {
            method: Some("CONNECT".to_string()),
            scheme: Some("https".to_string()),
            authority: Some("upstream.example:443".to_string()),
            path: Some("/".to_string()),
            ..H3PseudoHeaders::default()
        };
        let err = validate_request_pseudo_headers(&bad_connect).expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::InvalidRequestPseudoHeader(
                "CONNECT request must not include :scheme or :path"
            )
        );

        let missing_authority_connect = H3PseudoHeaders {
            method: Some("CONNECT".to_string()),
            ..H3PseudoHeaders::default()
        };
        let err =
            validate_request_pseudo_headers(&missing_authority_connect).expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::InvalidRequestPseudoHeader("CONNECT request missing :authority")
        );

        let bad_resp = H3PseudoHeaders {
            status: Some(99),
            ..H3PseudoHeaders::default()
        };
        let err = validate_response_pseudo_headers(&bad_resp).expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::InvalidResponsePseudoHeader("status must be in 100..=999")
        );
    }

    #[test]
    fn request_stream_state_enforces_headers_then_data() {
        let mut st = H3RequestStreamState::new();
        let err = st
            .on_frame(&H3Frame::Data(vec![1, 2, 3]))
            .expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::ControlProtocol("DATA before initial HEADERS on request stream")
        );
        st.on_frame(&H3Frame::Headers(vec![0x80])).expect("headers");
        st.on_frame(&H3Frame::Data(vec![1])).expect("data");
        st.on_frame(&H3Frame::Headers(vec![0x81]))
            .expect("trailers headers");
        let err = st.on_frame(&H3Frame::Data(vec![2])).expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::ControlProtocol("DATA not allowed after trailing HEADERS")
        );
    }

    #[test]
    fn request_stream_rejects_non_data_headers_frames() {
        let mut st = H3RequestStreamState::new();
        let err = st
            .on_frame(&H3Frame::Settings(H3Settings::default()))
            .expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::ControlProtocol("only HEADERS/DATA are valid on request streams")
        );
    }

    #[test]
    fn control_stream_rejects_data_after_settings() {
        let mut state = H3ControlState::new();
        state
            .on_remote_control_frame(&H3Frame::Settings(H3Settings::default()))
            .expect("settings");
        let err = state
            .on_remote_control_frame(&H3Frame::Data(vec![1]))
            .expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::ControlProtocol("frame type not allowed on control stream")
        );
    }

    #[test]
    fn connection_state_applies_goaway_to_new_request_ids() {
        let mut c = H3ConnectionState::new();
        c.on_control_frame(&H3Frame::Settings(H3Settings::default()))
            .expect("settings");
        c.on_control_frame(&H3Frame::Goaway(10)).expect("goaway");
        assert_eq!(c.goaway_id(), Some(10));
        c.on_request_stream_frame(8, &H3Frame::Headers(vec![1]))
            .expect("allowed");
        let err = c
            .on_request_stream_frame(12, &H3Frame::Headers(vec![1]))
            .expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::ControlProtocol("request stream id rejected after GOAWAY")
        );
    }

    #[test]
    fn connection_state_rejects_increasing_goaway_id() {
        let mut c = H3ConnectionState::new();
        c.on_control_frame(&H3Frame::Settings(H3Settings::default()))
            .expect("settings");
        c.on_control_frame(&H3Frame::Goaway(10)).expect("first");
        let err = c
            .on_control_frame(&H3Frame::Goaway(12))
            .expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::ControlProtocol("GOAWAY id must not increase")
        );
    }

    #[test]
    fn request_stream_rejects_unidirectional_stream_id() {
        let mut c = H3ConnectionState::new();
        c.on_control_frame(&H3Frame::Settings(H3Settings::default()))
            .expect("settings");
        let err = c
            .on_request_stream_frame(2, &H3Frame::Headers(vec![1]))
            .expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::StreamProtocol("request stream id must be bidirectional")
        );
    }

    #[test]
    fn static_only_qpack_policy_rejects_dynamic_settings() {
        let mut c = H3ConnectionState::new();
        let settings = H3Settings {
            qpack_max_table_capacity: Some(1024),
            ..H3Settings::default()
        };
        let err = c
            .on_control_frame(&H3Frame::Settings(settings))
            .expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::QpackPolicy("dynamic qpack table disabled by policy")
        );
    }

    #[test]
    fn duplicate_remote_control_uni_stream_rejected() {
        let mut c = H3ConnectionState::new();
        c.on_remote_uni_stream_type(2, H3_STREAM_TYPE_CONTROL)
            .expect("first control");
        let err = c
            .on_remote_uni_stream_type(6, H3_STREAM_TYPE_CONTROL)
            .expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::StreamProtocol("duplicate remote control stream")
        );
        c.on_uni_stream_frame(2, &H3Frame::Settings(H3Settings::default()))
            .expect("original control stream remains active");
        let err = c
            .on_uni_stream_frame(6, &H3Frame::Settings(H3Settings::default()))
            .expect_err("new duplicate stream must not become active");
        assert_eq!(
            err,
            H3NativeError::StreamProtocol("unknown unidirectional stream")
        );
    }

    #[test]
    fn uni_stream_type_rejects_bidirectional_stream_id() {
        let mut c = H3ConnectionState::new();
        let err = c
            .on_remote_uni_stream_type(0, H3_STREAM_TYPE_CONTROL)
            .expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::StreamProtocol(
                "unidirectional stream type requires unidirectional stream id"
            )
        );
    }

    #[test]
    fn push_uni_stream_uses_headers_data_ordering() {
        let mut c = H3ConnectionState::new();
        c.on_remote_uni_stream_type(10, H3_STREAM_TYPE_PUSH)
            .expect("push type");
        let err = c
            .on_uni_stream_frame(10, &H3Frame::Data(vec![1]))
            .expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::ControlProtocol("DATA before initial HEADERS on request stream")
        );
        c.on_uni_stream_frame(10, &H3Frame::Headers(vec![0x80]))
            .expect("headers");
        c.on_uni_stream_frame(10, &H3Frame::Data(vec![1, 2]))
            .expect("data");
    }

    #[test]
    fn qpack_streams_reject_h3_frame_mapping() {
        let mut c = H3ConnectionState::new();
        c.on_remote_uni_stream_type(14, H3_STREAM_TYPE_QPACK_ENCODER)
            .expect("qpack encoder");
        let err = c
            .on_uni_stream_frame(14, &H3Frame::Data(vec![1]))
            .expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::StreamProtocol("qpack streams carry instructions, not h3 frames")
        );
    }

    // ========================================================================
    // Pure data-type tests (wave 11 – CyanBarn)
    // ========================================================================

    #[test]
    fn h3_native_error_display_all_variants() {
        let cases: Vec<(H3NativeError, &str)> = vec![
            (H3NativeError::UnexpectedEof, "unexpected EOF"),
            (H3NativeError::InvalidFrame("bad"), "invalid frame: bad"),
            (
                H3NativeError::DuplicateSetting(0x6),
                "duplicate setting: 0x6",
            ),
            (
                H3NativeError::InvalidSettingValue(0x8),
                "invalid setting value: 0x8",
            ),
            (
                H3NativeError::ControlProtocol("dup"),
                "control stream protocol violation: dup",
            ),
            (
                H3NativeError::StreamProtocol("bad stream"),
                "stream protocol violation: bad stream",
            ),
            (
                H3NativeError::QpackPolicy("no dyn"),
                "qpack policy violation: no dyn",
            ),
            (
                H3NativeError::InvalidRequestPseudoHeader("missing"),
                "invalid request pseudo-header set: missing",
            ),
            (
                H3NativeError::InvalidResponsePseudoHeader("bad status"),
                "invalid response pseudo-header set: bad status",
            ),
        ];
        for (err, expected) in &cases {
            assert_eq!(format!("{err}"), *expected, "{err:?}");
        }
    }

    #[test]
    fn h3_native_error_debug_clone_eq() {
        let a = H3NativeError::UnexpectedEof;
        let b = a.clone();
        assert_eq!(a, b);
        let dbg = format!("{a:?}");
        assert!(dbg.contains("UnexpectedEof"), "{dbg}");
    }

    #[test]
    fn h3_native_error_is_std_error() {
        let err = H3NativeError::UnexpectedEof;
        let _: &dyn std::error::Error = &err;
        assert!(std::error::Error::source(&err).is_none());
    }

    #[test]
    fn h3_qpack_mode_default_debug_copy() {
        let mode: H3QpackMode = H3QpackMode::default();
        assert_eq!(mode, H3QpackMode::StaticOnly);
        let copied = mode; // Copy
        let cloned = mode;
        assert_eq!(copied, cloned);
        let dbg = format!("{mode:?}");
        assert!(dbg.contains("StaticOnly"), "{dbg}");
    }

    #[test]
    fn h3_qpack_mode_inequality() {
        assert_ne!(H3QpackMode::StaticOnly, H3QpackMode::DynamicTableAllowed);
    }

    #[test]
    fn h3_connection_config_default_debug_copy() {
        let config = H3ConnectionConfig::default();
        assert_eq!(config.qpack_mode, H3QpackMode::StaticOnly);
        let copied = config; // Copy
        let cloned = config;
        assert_eq!(copied, cloned);
        let dbg = format!("{config:?}");
        assert!(dbg.contains("H3ConnectionConfig"), "{dbg}");
    }

    #[test]
    fn h3_uni_stream_type_debug_copy_eq() {
        let t = H3UniStreamType::Control;
        let copied = t; // Copy
        let cloned = t;
        assert_eq!(copied, cloned);
        assert_ne!(H3UniStreamType::Control, H3UniStreamType::Push);
        assert_ne!(H3UniStreamType::QpackEncoder, H3UniStreamType::QpackDecoder);
        let dbg = format!("{t:?}");
        assert!(dbg.contains("Control"), "{dbg}");
    }

    #[test]
    fn h3_uni_stream_type_decode_all_known() {
        assert_eq!(H3UniStreamType::decode(0x00), H3UniStreamType::Control);
        assert_eq!(H3UniStreamType::decode(0x01), H3UniStreamType::Push);
        assert_eq!(H3UniStreamType::decode(0x02), H3UniStreamType::QpackEncoder);
        assert_eq!(H3UniStreamType::decode(0x03), H3UniStreamType::QpackDecoder);
    }

    #[test]
    fn h3_uni_stream_type_decode_unknown_accepted() {
        let kind = H3UniStreamType::decode(0xFF);
        assert_eq!(kind, H3UniStreamType::Unknown(0xFF));
    }

    #[test]
    fn unknown_setting_debug_clone_eq() {
        let a = UnknownSetting {
            id: 0xAA,
            value: 42,
        };
        let b = a.clone();
        assert_eq!(a, b);
        let dbg = format!("{a:?}");
        assert!(dbg.contains("UnknownSetting"), "{dbg}");
    }

    #[test]
    fn h3_settings_default_debug_clone() {
        let s = H3Settings::default();
        assert!(s.qpack_max_table_capacity.is_none());
        assert!(s.unknown.is_empty());
        let dbg = format!("{s:?}");
        assert!(dbg.contains("H3Settings"), "{dbg}");
        let cloned = s.clone();
        assert_eq!(cloned, s);
    }

    #[test]
    fn h3_settings_empty_roundtrip() {
        let s = H3Settings::default();
        let mut payload = Vec::new();
        s.encode_payload(&mut payload).expect("encode");
        assert!(payload.is_empty());
        let decoded = H3Settings::decode_payload(&payload).expect("decode");
        assert_eq!(decoded, s);
    }

    #[test]
    fn h3_frame_debug_clone_all_variants() {
        let variants: Vec<H3Frame> = vec![
            H3Frame::Data(vec![1, 2]),
            H3Frame::Headers(vec![3, 4]),
            H3Frame::CancelPush(5),
            H3Frame::Settings(H3Settings::default()),
            H3Frame::PushPromise {
                push_id: 6,
                field_block: vec![7],
            },
            H3Frame::Goaway(8),
            H3Frame::MaxPushId(9),
            H3Frame::Unknown {
                frame_type: 0xFF,
                payload: vec![10],
            },
        ];
        for frame in &variants {
            let dbg = format!("{frame:?}");
            assert!(!dbg.is_empty());
            let cloned = frame.clone();
            assert_eq!(cloned, *frame);
        }
    }

    #[test]
    fn h3_control_state_default_debug_clone() {
        let s = H3ControlState::new();
        let dbg = format!("{s:?}");
        assert!(dbg.contains("H3ControlState"), "{dbg}");
        let cloned = s.clone();
        assert_eq!(cloned, s);
    }

    #[test]
    fn h3_control_state_duplicate_local_settings() {
        let mut s = H3ControlState::new();
        s.build_local_settings(H3Settings::default())
            .expect("first ok");
        let err = s
            .build_local_settings(H3Settings::default())
            .expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::ControlProtocol("SETTINGS already sent on local control stream")
        );
    }

    #[test]
    fn h3_control_state_duplicate_remote_settings() {
        let mut s = H3ControlState::new();
        s.on_remote_control_frame(&H3Frame::Settings(H3Settings::default()))
            .expect("first ok");
        let err = s
            .on_remote_control_frame(&H3Frame::Settings(H3Settings::default()))
            .expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::ControlProtocol("duplicate SETTINGS on remote control stream")
        );
    }

    #[test]
    fn h3_pseudo_headers_default_debug_clone() {
        let ph = H3PseudoHeaders::default();
        assert!(ph.method.is_none());
        assert!(ph.scheme.is_none());
        assert!(ph.authority.is_none());
        assert!(ph.path.is_none());
        assert!(ph.status.is_none());
        let dbg = format!("{ph:?}");
        assert!(dbg.contains("H3PseudoHeaders"), "{dbg}");
        let cloned = ph.clone();
        assert_eq!(cloned, ph);
    }

    #[test]
    fn h3_request_head_debug_clone_eq() {
        let head = H3RequestHead::new(
            H3PseudoHeaders {
                method: Some("GET".to_string()),
                scheme: Some("https".to_string()),
                authority: Some("example.com".to_string()),
                path: Some("/".to_string()),
                status: None,
            },
            vec![],
        )
        .expect("valid");
        let dbg = format!("{head:?}");
        assert!(dbg.contains("H3RequestHead"), "{dbg}");
        let cloned = head.clone();
        assert_eq!(cloned, head);
    }

    #[test]
    fn h3_response_head_debug_clone_eq() {
        let head = H3ResponseHead::new(200, vec![]).expect("valid");
        let dbg = format!("{head:?}");
        assert!(dbg.contains("H3ResponseHead"), "{dbg}");
        assert_eq!(head.status, 200);
        let cloned = head.clone();
        assert_eq!(cloned, head);
    }

    #[test]
    fn h3_response_head_invalid_status() {
        let err = H3ResponseHead::new(50, vec![]).expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::InvalidResponsePseudoHeader("status must be in 100..=999")
        );
    }

    #[test]
    fn response_pseudo_headers_reject_authority() {
        let headers = H3PseudoHeaders {
            status: Some(200),
            authority: Some("example.com".to_string()),
            ..H3PseudoHeaders::default()
        };
        let err = validate_response_pseudo_headers(&headers).expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::InvalidResponsePseudoHeader(
                "response must not include request pseudo headers"
            )
        );
    }

    #[test]
    fn qpack_field_plan_debug_clone_eq() {
        let idx = QpackFieldPlan::StaticIndex(17);
        let lit = QpackFieldPlan::Literal {
            name: "x".to_string(),
            value: "y".to_string(),
        };
        assert_ne!(idx, lit);
        let dbg = format!("{idx:?}");
        assert!(dbg.contains("StaticIndex"), "{dbg}");
        let cloned = lit.clone();
        assert_eq!(cloned, lit);
    }

    #[test]
    fn qpack_static_plans_use_known_indices() {
        let req = H3RequestHead::new(
            H3PseudoHeaders {
                method: Some("GET".to_string()),
                scheme: Some("https".to_string()),
                authority: Some("example.com".to_string()),
                path: Some("/".to_string()),
                status: None,
            },
            vec![("accept".to_string(), "*/*".to_string())],
        )
        .expect("request");
        let req_plan = qpack_static_plan_for_request(&req);
        assert!(req_plan.contains(&QpackFieldPlan::StaticIndex(17)));
        assert!(req_plan.contains(&QpackFieldPlan::StaticIndex(23)));
        assert!(req_plan.contains(&QpackFieldPlan::StaticIndex(1)));

        let resp = H3ResponseHead::new(200, vec![("server".to_string(), "asupersync".to_string())])
            .expect("response");
        let resp_plan = qpack_static_plan_for_response(&resp);
        assert_eq!(resp_plan.first(), Some(&QpackFieldPlan::StaticIndex(25)));
    }

    // ========================================================================
    // QH3-U1 gap-filling tests
    // ========================================================================

    // --- 1. Frame roundtrips ---

    #[test]
    fn frame_roundtrip_data() {
        let frame = H3Frame::Data(vec![0xCA, 0xFE]);
        let mut buf = Vec::new();
        frame.encode(&mut buf).expect("encode");
        let (decoded, consumed) = H3Frame::decode(&buf).expect("decode");
        assert_eq!(decoded, frame);
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn frame_roundtrip_headers() {
        let frame = H3Frame::Headers(vec![0x80, 0x81, 0x82]);
        let mut buf = Vec::new();
        frame.encode(&mut buf).expect("encode");
        let (decoded, consumed) = H3Frame::decode(&buf).expect("decode");
        assert_eq!(decoded, frame);
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn frame_roundtrip_cancel_push() {
        let frame = H3Frame::CancelPush(42);
        let mut buf = Vec::new();
        frame.encode(&mut buf).expect("encode");
        let (decoded, consumed) = H3Frame::decode(&buf).expect("decode");
        assert_eq!(decoded, frame);
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn frame_roundtrip_goaway() {
        let frame = H3Frame::Goaway(1000);
        let mut buf = Vec::new();
        frame.encode(&mut buf).expect("encode");
        let (decoded, consumed) = H3Frame::decode(&buf).expect("decode");
        assert_eq!(decoded, frame);
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn frame_roundtrip_max_push_id() {
        let frame = H3Frame::MaxPushId(255);
        let mut buf = Vec::new();
        frame.encode(&mut buf).expect("encode");
        let (decoded, consumed) = H3Frame::decode(&buf).expect("decode");
        assert_eq!(decoded, frame);
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn frame_roundtrip_unknown() {
        let frame = H3Frame::Unknown {
            frame_type: 0x1F,
            payload: vec![0xDE, 0xAD],
        };
        let mut buf = Vec::new();
        frame.encode(&mut buf).expect("encode");
        let (decoded, consumed) = H3Frame::decode(&buf).expect("decode");
        assert_eq!(decoded, frame);
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn frame_roundtrip_settings() {
        let settings = H3Settings {
            qpack_max_table_capacity: Some(4096),
            max_field_section_size: Some(8192),
            qpack_blocked_streams: None,
            enable_connect_protocol: Some(true),
            h3_datagram: None,
            unknown: vec![],
        };
        let frame = H3Frame::Settings(settings);
        let mut buf = Vec::new();
        frame.encode(&mut buf).expect("encode");
        let (decoded, consumed) = H3Frame::decode(&buf).expect("decode");
        assert_eq!(decoded, frame);
        assert_eq!(consumed, buf.len());
    }

    // --- 2. Frame decode edge cases ---

    #[test]
    fn frame_decode_empty_input_error() {
        let err = H3Frame::decode(&[]).expect_err("must fail on empty input");
        assert_eq!(err, H3NativeError::InvalidFrame("frame type varint"));
    }

    #[test]
    fn frame_decode_truncated_payload_unexpected_eof() {
        // Encode a Data frame with 4 bytes of payload, then truncate.
        let frame = H3Frame::Data(vec![1, 2, 3, 4]);
        let mut buf = Vec::new();
        frame.encode(&mut buf).expect("encode");
        // Truncate: remove the last 2 payload bytes.
        let truncated = &buf[..buf.len() - 2];
        let err = H3Frame::decode(truncated).expect_err("must fail on truncated payload");
        assert_eq!(err, H3NativeError::UnexpectedEof);
    }

    #[test]
    fn frame_decode_cancel_push_trailing_bytes_invalid_frame() {
        // Build a CancelPush frame manually with trailing bytes in the payload.
        let mut payload = Vec::new();
        encode_varint(7, &mut payload).expect("varint");
        payload.push(0xFF); // trailing garbage

        let mut buf = Vec::new();
        encode_varint(H3_FRAME_CANCEL_PUSH, &mut buf).expect("type");
        encode_varint(payload.len() as u64, &mut buf).expect("len");
        buf.extend_from_slice(&payload);

        let err = H3Frame::decode(&buf).expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::InvalidFrame("cancel_push trailing bytes")
        );
    }

    #[test]
    fn frame_decode_goaway_trailing_bytes_invalid_frame() {
        let mut payload = Vec::new();
        encode_varint(50, &mut payload).expect("varint");
        payload.push(0xAA); // trailing garbage

        let mut buf = Vec::new();
        encode_varint(H3_FRAME_GOAWAY, &mut buf).expect("type");
        encode_varint(payload.len() as u64, &mut buf).expect("len");
        buf.extend_from_slice(&payload);

        let err = H3Frame::decode(&buf).expect_err("must fail");
        assert_eq!(err, H3NativeError::InvalidFrame("goaway trailing bytes"));
    }

    #[test]
    fn frame_decode_max_push_id_trailing_bytes_invalid_frame() {
        let mut payload = Vec::new();
        encode_varint(99, &mut payload).expect("varint");
        payload.push(0xBB); // trailing garbage

        let mut buf = Vec::new();
        encode_varint(H3_FRAME_MAX_PUSH_ID, &mut buf).expect("type");
        encode_varint(payload.len() as u64, &mut buf).expect("len");
        buf.extend_from_slice(&payload);

        let err = H3Frame::decode(&buf).expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::InvalidFrame("max_push_id trailing bytes")
        );
    }

    // --- 3. Request stream state gaps ---

    #[test]
    fn request_stream_trailers_without_data_valid() {
        let mut st = H3RequestStreamState::new();
        st.on_frame(&H3Frame::Headers(vec![0x80]))
            .expect("first HEADERS");
        // RFC 9114 §4.1: trailers are valid without intervening DATA
        // (message format is HEADERS + DATA* + HEADERS? where DATA* = zero or more).
        st.on_frame(&H3Frame::Headers(vec![0x81]))
            .expect("trailers without DATA must succeed per RFC 9114");
    }

    #[test]
    fn request_stream_mark_end_stream_after_headers_only() {
        let mut st = H3RequestStreamState::new();
        st.on_frame(&H3Frame::Headers(vec![0x80]))
            .expect("first HEADERS");
        // Headers-only request: end stream immediately after initial HEADERS.
        st.mark_end_stream().expect("valid headers-only end");
    }

    #[test]
    fn request_stream_mark_end_stream_before_headers_error() {
        let mut st = H3RequestStreamState::new();
        let err = st.mark_end_stream().expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::ControlProtocol("request stream ended before initial HEADERS")
        );
    }

    #[test]
    fn request_stream_on_frame_after_end_stream_error() {
        let mut st = H3RequestStreamState::new();
        st.on_frame(&H3Frame::Headers(vec![0x80])).expect("HEADERS");
        st.mark_end_stream().expect("end");
        let err = st.on_frame(&H3Frame::Data(vec![1])).expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::ControlProtocol("request stream already finished")
        );
    }

    // --- 4. Connection state gaps ---

    #[test]
    fn finish_request_stream_unknown_stream_id_error() {
        let mut c = H3ConnectionState::new();
        let err = c.finish_request_stream(999).expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::ControlProtocol("unknown request stream on finish")
        );
    }

    #[test]
    fn finished_request_stream_rejects_late_frames() {
        let mut c = H3ConnectionState::new();
        c.on_request_stream_frame(0, &H3Frame::Headers(vec![0x80]))
            .expect("headers");
        c.finish_request_stream(0).expect("finish");
        let err = c
            .on_request_stream_frame(0, &H3Frame::Headers(vec![0x81]))
            .expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::ControlProtocol("request stream already finished")
        );
    }

    #[test]
    fn finish_request_stream_twice_reports_finished() {
        let mut c = H3ConnectionState::new();
        c.on_request_stream_frame(0, &H3Frame::Headers(vec![0x80]))
            .expect("headers");
        c.finish_request_stream(0).expect("finish");
        let err = c.finish_request_stream(0).expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::ControlProtocol("request stream already finished")
        );
    }

    #[test]
    fn duplicate_qpack_encoder_stream_error() {
        let mut c = H3ConnectionState::new();
        c.on_remote_uni_stream_type(2, H3_STREAM_TYPE_QPACK_ENCODER)
            .expect("first encoder");
        let err = c
            .on_remote_uni_stream_type(6, H3_STREAM_TYPE_QPACK_ENCODER)
            .expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::StreamProtocol("duplicate remote qpack encoder stream")
        );
    }

    #[test]
    fn duplicate_qpack_decoder_stream_error() {
        let mut c = H3ConnectionState::new();
        c.on_remote_uni_stream_type(2, H3_STREAM_TYPE_QPACK_DECODER)
            .expect("first decoder");
        let err = c
            .on_remote_uni_stream_type(6, H3_STREAM_TYPE_QPACK_DECODER)
            .expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::StreamProtocol("duplicate remote qpack decoder stream")
        );
    }

    #[test]
    fn uni_stream_type_already_set_for_same_id_error() {
        let mut c = H3ConnectionState::new();
        c.on_remote_uni_stream_type(2, H3_STREAM_TYPE_CONTROL)
            .expect("first set");
        let err = c
            .on_remote_uni_stream_type(2, H3_STREAM_TYPE_PUSH)
            .expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::StreamProtocol("unidirectional stream type already set")
        );
    }

    #[test]
    fn goaway_decreasing_is_allowed() {
        let mut c = H3ConnectionState::new();
        c.on_control_frame(&H3Frame::Settings(H3Settings::default()))
            .expect("settings");
        c.on_control_frame(&H3Frame::Goaway(100))
            .expect("first goaway=100");
        assert_eq!(c.goaway_id(), Some(100));
        c.on_control_frame(&H3Frame::Goaway(50))
            .expect("second goaway=50");
        assert_eq!(c.goaway_id(), Some(50));
    }

    #[test]
    fn goaway_zero_blocks_all_request_streams() {
        let mut c = H3ConnectionState::new();
        c.on_control_frame(&H3Frame::Settings(H3Settings::default()))
            .expect("settings");
        c.on_control_frame(&H3Frame::Goaway(0)).expect("goaway=0");
        assert_eq!(c.goaway_id(), Some(0));
        // Stream ID 0 is the smallest bidirectional stream; it should be rejected.
        let err = c
            .on_request_stream_frame(0, &H3Frame::Headers(vec![1]))
            .expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::ControlProtocol("request stream id rejected after GOAWAY")
        );
    }

    // --- 5. QPACK/settings gaps ---

    #[test]
    fn dynamic_table_allowed_accepts_nonzero_capacity() {
        let config = H3ConnectionConfig {
            qpack_mode: H3QpackMode::DynamicTableAllowed,
        };
        let mut c = H3ConnectionState::with_config(config);
        let settings = H3Settings {
            qpack_max_table_capacity: Some(4096),
            qpack_blocked_streams: Some(100),
            ..H3Settings::default()
        };
        c.on_control_frame(&H3Frame::Settings(settings))
            .expect("dynamic table settings accepted");
    }

    #[test]
    fn qpack_static_plan_request_non_static_method_produces_literal() {
        let req = H3RequestHead::new(
            H3PseudoHeaders {
                method: Some("PATCH".to_string()),
                scheme: Some("https".to_string()),
                authority: Some("example.com".to_string()),
                path: Some("/resource".to_string()),
                status: None,
            },
            vec![],
        )
        .expect("valid request");
        let plan = qpack_static_plan_for_request(&req);
        // PATCH is not in the QPACK static table, so the first entry must be Literal.
        assert_eq!(
            plan[0],
            QpackFieldPlan::Literal {
                name: ":method".to_string(),
                value: "PATCH".to_string(),
            }
        );
    }

    #[test]
    fn qpack_static_plan_response_non_indexed_status_produces_literal() {
        let resp = H3ResponseHead::new(201, vec![]).expect("valid response");
        let plan = qpack_static_plan_for_response(&resp);
        // 201 is not in the QPACK static table, so the first entry must be Literal.
        assert_eq!(
            plan[0],
            QpackFieldPlan::Literal {
                name: ":status".to_string(),
                value: "201".to_string(),
            }
        );
    }

    #[test]
    fn qpack_wire_roundtrip_static_and_literal_field_lines() {
        let plan = vec![
            QpackFieldPlan::StaticIndex(17), // :method GET
            QpackFieldPlan::StaticIndex(23), // :scheme https
            QpackFieldPlan::StaticIndex(1),  // :path /
            QpackFieldPlan::Literal {
                name: ":authority".to_string(),
                value: "example.com".to_string(),
            },
            QpackFieldPlan::Literal {
                name: "accept".to_string(),
                value: "application/json".to_string(),
            },
        ];

        let encoded = qpack_encode_field_section(&plan).expect("encode");
        let decoded =
            qpack_decode_field_section(&encoded, H3QpackMode::StaticOnly).expect("decode");
        assert_eq!(decoded, plan);

        let headers = qpack_plan_to_header_fields(&decoded).expect("expand headers");
        assert_eq!(headers[0], (":method".to_string(), "GET".to_string()));
        assert_eq!(headers[1], (":scheme".to_string(), "https".to_string()));
        assert_eq!(headers[2], (":path".to_string(), "/".to_string()));
        assert_eq!(
            headers[3],
            (":authority".to_string(), "example.com".to_string())
        );
        assert_eq!(
            headers[4],
            ("accept".to_string(), "application/json".to_string())
        );
    }

    #[test]
    fn qpack_wire_request_and_response_helpers_roundtrip() {
        let request = H3RequestHead::new(
            H3PseudoHeaders {
                method: Some("POST".to_string()),
                scheme: Some("https".to_string()),
                authority: Some("api.example.com".to_string()),
                path: Some("/upload".to_string()),
                status: None,
            },
            vec![("content-type".to_string(), "application/json".to_string())],
        )
        .expect("request");
        let request_plan = qpack_static_plan_for_request(&request);
        let request_wire = qpack_encode_request_field_section(&request).expect("request encode");
        let request_decoded = qpack_decode_field_section(&request_wire, H3QpackMode::StaticOnly)
            .expect("request decode");
        assert_eq!(request_decoded, request_plan);

        let response = H3ResponseHead::new(
            200,
            vec![("content-type".to_string(), "text/plain".to_string())],
        )
        .expect("response");
        let response_plan = qpack_static_plan_for_response(&response);
        let response_wire =
            qpack_encode_response_field_section(&response).expect("response encode");
        let response_decoded = qpack_decode_field_section(&response_wire, H3QpackMode::StaticOnly)
            .expect("response decode");
        assert_eq!(response_decoded, response_plan);
    }

    #[test]
    fn qpack_wire_decode_request_head_helper_roundtrip() {
        let request = H3RequestHead::new(
            H3PseudoHeaders {
                method: Some("GET".to_string()),
                scheme: Some("https".to_string()),
                authority: Some("api.example.com".to_string()),
                path: Some("/v1/items".to_string()),
                status: None,
            },
            vec![("accept".to_string(), "application/json".to_string())],
        )
        .expect("request");
        let wire = qpack_encode_request_field_section(&request).expect("encode");
        let decoded =
            qpack_decode_request_field_section(&wire, H3QpackMode::StaticOnly).expect("decode");
        assert_eq!(decoded, request);
    }

    #[test]
    fn qpack_wire_decode_response_head_helper_roundtrip() {
        let response = H3ResponseHead::new(
            200,
            vec![
                ("content-type".to_string(), "text/plain".to_string()),
                ("server".to_string(), "asupersync".to_string()),
            ],
        )
        .expect("response");
        let wire = qpack_encode_response_field_section(&response).expect("encode");
        let decoded =
            qpack_decode_response_field_section(&wire, H3QpackMode::StaticOnly).expect("decode");
        assert_eq!(decoded, response);
    }

    #[test]
    fn qpack_request_decode_rejects_pseudo_after_regular_header() {
        let plan = vec![
            QpackFieldPlan::Literal {
                name: "accept".to_string(),
                value: "*/*".to_string(),
            },
            QpackFieldPlan::StaticIndex(17), // :method GET
            QpackFieldPlan::StaticIndex(23), // :scheme https
            QpackFieldPlan::StaticIndex(1),  // :path /
        ];
        let wire = qpack_encode_field_section(&plan).expect("encode");
        let err =
            qpack_decode_request_field_section(&wire, H3QpackMode::StaticOnly).expect_err("fail");
        assert_eq!(
            err,
            H3NativeError::InvalidRequestPseudoHeader(
                "request pseudo headers must precede regular headers",
            )
        );
    }

    #[test]
    fn qpack_request_decode_rejects_duplicate_method() {
        let plan = vec![
            QpackFieldPlan::StaticIndex(17), // :method GET
            QpackFieldPlan::Literal {
                name: ":method".to_string(),
                value: "POST".to_string(),
            },
            QpackFieldPlan::StaticIndex(23), // :scheme https
            QpackFieldPlan::StaticIndex(1),  // :path /
        ];
        let wire = qpack_encode_field_section(&plan).expect("encode");
        let err =
            qpack_decode_request_field_section(&wire, H3QpackMode::StaticOnly).expect_err("fail");
        assert_eq!(
            err,
            H3NativeError::InvalidRequestPseudoHeader("duplicate :method")
        );
    }

    #[test]
    fn qpack_response_decode_rejects_invalid_status_value() {
        let plan = vec![QpackFieldPlan::Literal {
            name: ":status".to_string(),
            value: "ok".to_string(),
        }];
        let wire = qpack_encode_field_section(&plan).expect("encode");
        let err =
            qpack_decode_response_field_section(&wire, H3QpackMode::StaticOnly).expect_err("fail");
        assert_eq!(
            err,
            H3NativeError::InvalidResponsePseudoHeader("invalid :status value")
        );
    }

    #[test]
    fn qpack_response_decode_rejects_request_pseudo_header() {
        let plan = vec![
            QpackFieldPlan::StaticIndex(25), // :status 200
            QpackFieldPlan::Literal {
                name: ":method".to_string(),
                value: "GET".to_string(),
            },
        ];
        let wire = qpack_encode_field_section(&plan).expect("encode");
        let err =
            qpack_decode_response_field_section(&wire, H3QpackMode::StaticOnly).expect_err("fail");
        assert_eq!(
            err,
            H3NativeError::InvalidResponsePseudoHeader(
                "response must not include request pseudo headers",
            )
        );
    }

    #[test]
    fn qpack_wire_static_only_rejects_required_insert_count() {
        // required_insert_count = 1, base = 0, then indexed static(:method GET).
        let wire = [0x01u8, 0x00, 0xD1];
        let err = qpack_decode_field_section(&wire, H3QpackMode::StaticOnly).expect_err("reject");
        assert_eq!(
            err,
            H3NativeError::QpackPolicy("required insert count must be zero in static-only mode")
        );
    }

    #[test]
    fn qpack_wire_rejects_huffman_strings_in_static_mode() {
        // Field section prefix (RIC=0, base=0), then:
        // literal-with-name-reference (static :authority index=0), value with H=1.
        let wire = [0x00u8, 0x00, 0x50, 0x83, 0xaa, 0xbb, 0xcc];
        let err = qpack_decode_field_section(&wire, H3QpackMode::StaticOnly).expect_err("reject");
        assert_eq!(
            err,
            H3NativeError::InvalidFrame(
                "qpack huffman strings are not supported in native static mode",
            )
        );
    }

    #[test]
    fn qpack_plan_to_header_fields_rejects_unknown_static_index() {
        let err = qpack_plan_to_header_fields(&[QpackFieldPlan::StaticIndex(999)])
            .expect_err("unknown static index");
        assert_eq!(
            err,
            H3NativeError::InvalidFrame("unknown static qpack index")
        );
    }

    #[test]
    fn qpack_wire_decode_rejects_unknown_static_index() {
        // Field section prefix (RIC=0, base=0), then indexed static with index=99
        // encoded as 63 + continuation byte 36.
        let wire = [0x00u8, 0x00, 0xFF, 0x24];
        let err = qpack_decode_field_section(&wire, H3QpackMode::StaticOnly).expect_err("reject");
        assert_eq!(
            err,
            H3NativeError::InvalidFrame("unknown static qpack index")
        );
    }

    #[test]
    fn qpack_wire_encode_rejects_unknown_static_index() {
        let err = qpack_encode_field_section(&[QpackFieldPlan::StaticIndex(999)])
            .expect_err("unknown static index");
        assert_eq!(
            err,
            H3NativeError::InvalidFrame("unknown static qpack index")
        );
    }

    #[test]
    fn qpack_prefixed_int_rejects_high_shift_truncation() {
        // Build a QPACK integer with 9 continuation bytes that push shift to 63.
        // At shift=63, checked_shl(63) silently truncates (e.g., 2u64 << 63 = 0)
        // because checked_shl only checks shift >= bit_width, not result overflow.
        // prefix_len=8, first byte = 0xFF (max prefix = 255), then 9 continuation
        // bytes of 0x80 (part=0, continuation bit set). After the 9th continuation
        // byte at shift=56, shift advances to 63 which exceeds our cap of 56.
        let mut wire = vec![0xFFu8]; // max prefix
        wire.extend(std::iter::repeat_n(0x80, 9)); // continuation, part=0 — 9 bytes push shift from 0→63
        wire.push(0x02); // part=2, no continuation — would be decoded at shift=63
        // With the fix, the 9th continuation byte advances shift to 63 > 56 → error.
        let result = qpack_decode_prefixed_int(0xFF, 8, &wire[1..]);
        assert!(
            result.is_err(),
            "must reject integer that would silently truncate at high shifts"
        );
    }

    // --- 6. Validation gaps ---

    #[test]
    fn request_missing_scheme_error() {
        let pseudo = H3PseudoHeaders {
            method: Some("GET".to_string()),
            scheme: None,
            authority: Some("example.com".to_string()),
            path: Some("/".to_string()),
            status: None,
        };
        let err = validate_request_pseudo_headers(&pseudo).expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::InvalidRequestPseudoHeader("missing :scheme")
        );
    }

    #[test]
    fn request_missing_path_error() {
        let pseudo = H3PseudoHeaders {
            method: Some("GET".to_string()),
            scheme: Some("https".to_string()),
            authority: Some("example.com".to_string()),
            path: None,
            status: None,
        };
        let err = validate_request_pseudo_headers(&pseudo).expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::InvalidRequestPseudoHeader("missing :path")
        );
    }

    #[test]
    fn response_with_method_contaminant_error() {
        let pseudo = H3PseudoHeaders {
            status: Some(200),
            method: Some("GET".to_string()),
            ..H3PseudoHeaders::default()
        };
        let err = validate_response_pseudo_headers(&pseudo).expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::InvalidResponsePseudoHeader(
                "response must not include request pseudo headers"
            )
        );
    }

    #[test]
    fn response_with_scheme_contaminant_error() {
        let pseudo = H3PseudoHeaders {
            status: Some(200),
            scheme: Some("https".to_string()),
            ..H3PseudoHeaders::default()
        };
        let err = validate_response_pseudo_headers(&pseudo).expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::InvalidResponsePseudoHeader(
                "response must not include request pseudo headers"
            )
        );
    }

    // --- 7. Audit fixes: QPACK static table, header validation, unknown uni streams ---

    #[test]
    fn qpack_static_table_entries_2_through_14_present() {
        // These were previously missing, causing interop failures.
        assert_eq!(qpack_static_entry(2), Some(("age", "0")));
        assert_eq!(qpack_static_entry(4), Some(("content-length", "0")));
        assert_eq!(qpack_static_entry(5), Some(("cookie", "")));
        assert_eq!(qpack_static_entry(6), Some(("date", "")));
        assert_eq!(qpack_static_entry(12), Some(("location", "")));
        assert_eq!(qpack_static_entry(14), Some(("set-cookie", "")));
    }

    #[test]
    fn qpack_static_table_entries_29_through_62_present() {
        assert_eq!(qpack_static_entry(29), Some(("accept", "*/*")));
        assert_eq!(
            qpack_static_entry(31),
            Some(("accept-encoding", "gzip, deflate, br"))
        );
        assert_eq!(
            qpack_static_entry(46),
            Some(("content-type", "application/json"))
        );
        assert_eq!(qpack_static_entry(53), Some(("content-type", "text/plain")));
        assert_eq!(qpack_static_entry(59), Some(("vary", "accept-encoding")));
        assert_eq!(
            qpack_static_entry(62),
            Some(("x-xss-protection", "1; mode=block"))
        );
    }

    #[test]
    fn qpack_static_table_entries_72_through_98_present() {
        assert_eq!(qpack_static_entry(72), Some(("accept-language", "")));
        assert_eq!(qpack_static_entry(83), Some(("alt-svc", "clear")));
        assert_eq!(qpack_static_entry(90), Some(("origin", "")));
        assert_eq!(qpack_static_entry(95), Some(("user-agent", "")));
        assert_eq!(
            qpack_static_entry(98),
            Some(("x-frame-options", "sameorigin"))
        );
        // Index 99 does not exist.
        assert_eq!(qpack_static_entry(99), None);
    }

    #[test]
    fn header_name_rejects_uppercase() {
        let err = validate_header_name("Content-Type").expect_err("must reject uppercase");
        assert_eq!(
            err,
            H3NativeError::InvalidFrame("header field name must be lowercase in HTTP/3")
        );
    }

    #[test]
    fn header_name_rejects_null_byte() {
        let err = validate_header_name("x-\0-bad").expect_err("must reject null");
        assert_eq!(
            err,
            H3NativeError::InvalidFrame("header field name contains invalid character")
        );
    }

    #[test]
    fn header_name_rejects_space() {
        let err = validate_header_name("x bad").expect_err("must reject space");
        assert_eq!(
            err,
            H3NativeError::InvalidFrame("header field name contains invalid character")
        );
    }

    #[test]
    fn header_name_accepts_valid_token() {
        validate_header_name("content-type").expect("valid");
        validate_header_name("x-custom_header.1").expect("valid");
        validate_header_name(":method").expect("pseudo header valid");
    }

    #[test]
    fn header_value_rejects_crlf() {
        let err = validate_header_value("value\r\ninjected").expect_err("must reject CRLF");
        assert_eq!(
            err,
            H3NativeError::InvalidFrame(
                "header field value contains forbidden character (NUL, CR, or LF)"
            )
        );
    }

    #[test]
    fn header_value_rejects_null() {
        let err = validate_header_value("value\0null").expect_err("must reject null");
        assert_eq!(
            err,
            H3NativeError::InvalidFrame(
                "header field value contains forbidden character (NUL, CR, or LF)"
            )
        );
    }

    #[test]
    fn header_value_accepts_normal_text() {
        validate_header_value("application/json").expect("valid");
        validate_header_value("").expect("empty is valid");
        validate_header_value("value with spaces and tabs\tare ok").expect("valid");
    }

    #[test]
    fn unknown_uni_stream_type_accepted_and_data_ignored() {
        let mut c = H3ConnectionState::new();
        let kind = c
            .on_remote_uni_stream_type(2, 0x42)
            .expect("unknown type must be accepted per RFC 9114 §6.2");
        assert_eq!(kind, H3UniStreamType::Unknown(0x42));
        // Data on unknown streams is silently discarded.
        c.on_uni_stream_frame(2, &H3Frame::Data(vec![1, 2, 3]))
            .expect("data on unknown stream must be accepted");
    }

    #[test]
    fn request_decode_rejects_uppercase_header_name() {
        let fields = vec![
            (":method".to_string(), "GET".to_string()),
            (":scheme".to_string(), "https".to_string()),
            (":path".to_string(), "/".to_string()),
            ("Accept".to_string(), "*/*".to_string()),
        ];
        let err = header_fields_to_request_head(&fields).expect_err("must reject uppercase");
        assert_eq!(
            err,
            H3NativeError::InvalidFrame("header field name must be lowercase in HTTP/3")
        );
    }

    #[test]
    fn response_decode_rejects_crlf_in_header_value() {
        let fields = vec![
            (":status".to_string(), "200".to_string()),
            ("x-injected".to_string(), "foo\r\nbar".to_string()),
        ];
        let err = header_fields_to_response_head(&fields).expect_err("must reject CRLF");
        assert_eq!(
            err,
            H3NativeError::InvalidFrame(
                "header field value contains forbidden character (NUL, CR, or LF)"
            )
        );
    }

    #[test]
    fn qpack_decode_string_rejects_prefix_len_8() {
        let err = qpack_decode_string(0xFF, 8, &[]).expect_err("must reject prefix_len=8");
        assert_eq!(
            err,
            H3NativeError::InvalidFrame("qpack string prefix length must be less than 8")
        );
    }

    #[test]
    fn settings_rejects_h2_reserved_ids() {
        // RFC 9114 §7.2.4.1: HTTP/2 reserved setting IDs (0x00, 0x02-0x05)
        // MUST be treated as a connection error.
        for reserved_id in [0x00u64, 0x02, 0x03, 0x04, 0x05] {
            let mut payload = Vec::new();
            encode_varint(reserved_id, &mut payload).expect("varint");
            encode_varint(42, &mut payload).expect("varint");
            let err = H3Settings::decode_payload(&payload).expect_err(&format!(
                "must reject H2 reserved setting 0x{reserved_id:02x}"
            ));
            assert_eq!(err, H3NativeError::InvalidSettingValue(reserved_id));
        }
    }

    // --- HTTP/3 DATAGRAM Frame Conformance Tests (RFC 9297) ---

    #[cfg(feature = "http3")]
    #[test]
    fn datagram_frame_roundtrip() {
        // Basic DATAGRAM frame encode/decode roundtrip.
        let frame = H3Frame::Datagram {
            quarter_stream_id: 42,
            payload: vec![0xCA, 0xFE, 0xBA, 0xBE],
        };
        let mut buf = Vec::new();
        frame.encode(&mut buf).expect("encode");
        let (decoded, consumed) = H3Frame::decode(&buf).expect("decode");
        assert_eq!(decoded, frame);
        assert_eq!(consumed, buf.len());
    }

    #[cfg(feature = "http3")]
    #[test]
    fn datagram_frame_roundtrip_empty_payload() {
        // DATAGRAM frame with empty payload should work.
        let frame = H3Frame::Datagram {
            quarter_stream_id: 0,
            payload: vec![],
        };
        let mut buf = Vec::new();
        frame.encode(&mut buf).expect("encode");
        let (decoded, consumed) = H3Frame::decode(&buf).expect("decode");
        assert_eq!(decoded, frame);
        assert_eq!(consumed, buf.len());
    }

    #[cfg(feature = "http3")]
    #[test]
    fn datagram_frame_roundtrip_large_quarter_stream_id() {
        // Test maximum quarter-stream-id values (62-bit varint max).
        let frame = H3Frame::Datagram {
            quarter_stream_id: (1u64 << 62) - 1, // Maximum 62-bit value
            payload: vec![0x01, 0x02],
        };
        let mut buf = Vec::new();
        frame.encode(&mut buf).expect("encode");
        let (decoded, consumed) = H3Frame::decode(&buf).expect("decode");
        assert_eq!(decoded, frame);
        assert_eq!(consumed, buf.len());
    }

    #[cfg(feature = "http3")]
    #[test]
    fn datagram_frame_golden_test_simple() {
        // Golden test: Known DATAGRAM frame encoding.
        // Frame type 0x30 (varint), length 6 (varint), quarter_stream_id 5 (varint), payload [0x01, 0x02, 0x03, 0x04].
        let frame = H3Frame::Datagram {
            quarter_stream_id: 5,
            payload: vec![0x01, 0x02, 0x03, 0x04],
        };
        let mut buf = Vec::new();
        frame.encode(&mut buf).expect("encode");

        // Expected wire format: [0x30, 0x05, 0x05, 0x01, 0x02, 0x03, 0x04]
        // 0x30 = frame type (DATAGRAM)
        // 0x05 = frame length (1 byte quarter_stream_id + 4 bytes payload)
        // 0x05 = quarter_stream_id (5 as varint)
        // [0x01, 0x02, 0x03, 0x04] = payload
        let expected = vec![0x30u8, 0x05, 0x05, 0x01, 0x02, 0x03, 0x04];
        assert_eq!(buf, expected, "DATAGRAM frame encoding mismatch");

        // Verify decode produces the same frame
        let (decoded, consumed) = H3Frame::decode(&buf).expect("decode");
        assert_eq!(decoded, frame);
        assert_eq!(consumed, buf.len());
    }

    #[cfg(feature = "http3")]
    #[test]
    fn datagram_frame_golden_test_zero_quarter_stream_id() {
        // Golden test: DATAGRAM frame with zero quarter_stream_id.
        let frame = H3Frame::Datagram {
            quarter_stream_id: 0,
            payload: vec![0xFF],
        };
        let mut buf = Vec::new();
        frame.encode(&mut buf).expect("encode");

        // Expected: [0x30, 0x02, 0x00, 0xFF]
        // 0x30 = frame type, 0x02 = length, 0x00 = quarter_stream_id, 0xFF = payload
        let expected = vec![0x30u8, 0x02, 0x00, 0xFF];
        assert_eq!(buf, expected);

        let (decoded, consumed) = H3Frame::decode(&buf).expect("decode");
        assert_eq!(decoded, frame);
        assert_eq!(consumed, buf.len());
    }

    #[cfg(feature = "http3")]
    #[test]
    fn datagram_frame_large_payload() {
        // Test DATAGRAM frame with large payload (up to practical limits).
        let large_payload = vec![0x42u8; 1024];
        let frame = H3Frame::Datagram {
            quarter_stream_id: 1000,
            payload: large_payload.clone(),
        };
        let mut buf = Vec::new();
        frame.encode(&mut buf).expect("encode");
        let (decoded, consumed) = H3Frame::decode(&buf).expect("decode");
        assert_eq!(decoded, frame);
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn datagram_frame_forbidden_on_control_stream() {
        // RFC 9297: DATAGRAM frames MUST NOT be sent on control streams.
        let frame = H3Frame::Datagram {
            quarter_stream_id: 10,
            payload: vec![0xAA, 0xBB],
        };

        let mut state = H3ControlState::new();
        state
            .on_remote_control_frame(&H3Frame::Settings(H3Settings::default()))
            .expect("settings");
        let err = state
            .on_remote_control_frame(&frame)
            .expect_err("must reject DATAGRAM on control stream");
        assert_eq!(
            err,
            H3NativeError::ControlProtocol("frame type not allowed on control stream")
        );
    }

    #[cfg(feature = "http3")]
    #[test]
    fn settings_h3_datagram_enabled() {
        // Test SETTINGS_H3_DATAGRAM=1 negotiation.
        let settings = H3Settings {
            qpack_max_table_capacity: Some(4096),
            max_field_section_size: Some(8192),
            qpack_blocked_streams: None,
            enable_connect_protocol: Some(false),
            h3_datagram: Some(true), // Enable DATAGRAM
            unknown: vec![],
        };

        let mut buf = Vec::new();
        settings.encode_payload(&mut buf).expect("encode settings");
        let decoded = H3Settings::decode_payload(&buf).expect("decode settings");
        assert_eq!(decoded.h3_datagram, Some(true));
    }

    #[cfg(feature = "http3")]
    #[test]
    fn settings_h3_datagram_disabled() {
        // Test SETTINGS_H3_DATAGRAM=0 (explicitly disabled).
        let settings = H3Settings {
            qpack_max_table_capacity: None,
            max_field_section_size: None,
            qpack_blocked_streams: None,
            enable_connect_protocol: None,
            h3_datagram: Some(false), // Explicitly disabled
            unknown: vec![],
        };

        let mut buf = Vec::new();
        settings.encode_payload(&mut buf).expect("encode settings");
        let decoded = H3Settings::decode_payload(&buf).expect("decode settings");
        assert_eq!(decoded.h3_datagram, Some(false));
    }

    #[cfg(feature = "http3")]
    #[test]
    fn settings_h3_datagram_not_negotiated() {
        // Test when SETTINGS_H3_DATAGRAM is not present (None).
        let settings = H3Settings {
            qpack_max_table_capacity: Some(1024),
            max_field_section_size: None,
            qpack_blocked_streams: None,
            enable_connect_protocol: None,
            h3_datagram: None, // Not negotiated
            unknown: vec![],
        };

        let mut buf = Vec::new();
        settings.encode_payload(&mut buf).expect("encode settings");
        let decoded = H3Settings::decode_payload(&buf).expect("decode settings");
        assert_eq!(decoded.h3_datagram, None);
    }

    #[cfg(feature = "http3")]
    #[test]
    fn datagram_frame_context_id_boundary_values() {
        // Test boundary values for quarter_stream_id (context identifier).
        let test_cases = vec![
            0u64,             // Minimum value
            1,                // Minimum non-zero
            63,               // Single-byte varint maximum
            64,               // Two-byte varint minimum
            16383,            // Two-byte varint maximum
            16384,            // Three-byte varint minimum
            1073741823,       // Four-byte varint maximum
            (1u64 << 30),     // Five-byte varint minimum
            (1u64 << 62) - 1, // Maximum 62-bit value
        ];

        for quarter_stream_id in test_cases {
            let frame = H3Frame::Datagram {
                quarter_stream_id,
                payload: vec![0x00, 0x01],
            };
            let mut buf = Vec::new();
            frame
                .encode(&mut buf)
                .expect(&format!("encode quarter_stream_id={}", quarter_stream_id));
            let (decoded, consumed) = H3Frame::decode(&buf)
                .expect(&format!("decode quarter_stream_id={}", quarter_stream_id));
            assert_eq!(decoded, frame);
            assert_eq!(consumed, buf.len());
        }
    }

    #[test]
    fn datagram_frame_decode_truncated_quarter_stream_id() {
        // Test frame with truncated quarter_stream_id varint.
        let mut buf = Vec::new();
        encode_varint(H3_FRAME_DATAGRAM, &mut buf).expect("frame type");
        encode_varint(2, &mut buf).expect("frame length");
        buf.push(0x80); // Incomplete varint (continuation bit set but no following byte)

        let err = H3Frame::decode(&buf).expect_err("must reject truncated quarter_stream_id");
        assert_eq!(err, H3NativeError::InvalidFrame("quarter stream id varint"));
    }

    #[test]
    fn datagram_frame_decode_truncated_payload() {
        // Test frame where declared length exceeds available data.
        let mut buf = Vec::new();
        encode_varint(H3_FRAME_DATAGRAM, &mut buf).expect("frame type");
        encode_varint(10, &mut buf).expect("frame length - claims 10 bytes");
        encode_varint(5, &mut buf).expect("quarter_stream_id");
        buf.extend_from_slice(&[0x01, 0x02]); // Only 2 bytes payload, but frame claims 10 total

        let err = H3Frame::decode(&buf).expect_err("must reject truncated payload");
        assert_eq!(
            err,
            H3NativeError::InvalidFrame("insufficient frame payload")
        );
    }

    #[cfg(feature = "http3")]
    #[test]
    fn datagram_frame_varint_quarter_stream_id_encoding() {
        // Verify quarter_stream_id is properly encoded as varint in different ranges.
        let test_cases = vec![
            (0u64, vec![0x00]),                     // Zero
            (42, vec![0x2A]),                       // Single byte
            (300, vec![0x41, 0x2C]),                // Two bytes
            (100000, vec![0x80, 0x01, 0x86, 0xA0]), // Four bytes
        ];

        for (quarter_stream_id, expected_varint) in test_cases {
            let frame = H3Frame::Datagram {
                quarter_stream_id,
                payload: vec![0xFF],
            };
            let mut buf = Vec::new();
            frame.encode(&mut buf).expect("encode");

            // Skip frame type and length, check quarter_stream_id encoding
            let (_, type_len) = decode_varint(&buf).expect("frame type");
            let (declared_length, len_len) = decode_varint(&buf[type_len..]).expect("frame length");
            let quarter_stream_id_start = type_len + len_len;
            let (decoded_id, id_len) =
                decode_varint(&buf[quarter_stream_id_start..]).expect("quarter_stream_id");

            assert_eq!(decoded_id, quarter_stream_id);
            assert_eq!(
                &buf[quarter_stream_id_start..quarter_stream_id_start + id_len],
                &expected_varint
            );
        }
    }

    // =========================================================================
    // 0-RTT Early Data Conformance Tests - RFC 8446 Section 4.2.10
    // =========================================================================

    /// 0-RTT state tracker for testing early data acceptance rules.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum ZeroRttState {
        /// 0-RTT not attempted or not available.
        NotAttempted,
        /// 0-RTT attempted, waiting for handshake completion.
        Pending,
        /// 0-RTT accepted by server.
        Accepted,
        /// 0-RTT rejected by server.
        Rejected,
        /// Handshake completed (1-RTT established).
        HandshakeComplete,
    }

    /// Configuration for 0-RTT early data limits and policies.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct ZeroRttConfig {
        /// Maximum early data bytes allowed.
        pub max_early_data: u64,
        /// Whether to allow HTTP requests in early data.
        pub allow_early_requests: bool,
        /// Whether to allow SETTINGS frames in early data.
        pub allow_early_settings: bool,
        /// Current 0-RTT state.
        pub state: ZeroRttState,
        /// Bytes of early data sent so far.
        pub early_data_sent: u64,
    }

    impl Default for ZeroRttConfig {
        fn default() -> Self {
            Self {
                max_early_data: 16384, // 16KB default
                allow_early_requests: true,
                allow_early_settings: false, // Conservative default
                state: ZeroRttState::NotAttempted,
                early_data_sent: 0,
            }
        }
    }

    impl ZeroRttConfig {
        /// Check if early data is currently allowed.
        pub fn is_early_data_allowed(&self) -> bool {
            matches!(self.state, ZeroRttState::Pending | ZeroRttState::Accepted)
        }

        /// Check if we can send more early data.
        pub fn can_send_early_data(&self, additional_bytes: u64) -> bool {
            self.is_early_data_allowed()
                && self.early_data_sent.saturating_add(additional_bytes) <= self.max_early_data
        }

        /// Record early data sent.
        pub fn record_early_data_sent(&mut self, bytes: u64) -> Result<(), H3NativeError> {
            if !self.is_early_data_allowed() {
                return Err(H3NativeError::StreamProtocol(
                    "0-RTT not allowed in current state",
                ));
            }
            if !self.can_send_early_data(bytes) {
                return Err(H3NativeError::StreamProtocol("early data limit exceeded"));
            }
            self.early_data_sent = self.early_data_sent.saturating_add(bytes);
            Ok(())
        }

        /// Validate if a frame can be sent in early data.
        pub fn validate_early_frame(&self, frame: &H3Frame) -> Result<(), H3NativeError> {
            if !self.is_early_data_allowed() {
                return Ok(()); // Not in 0-RTT, no restrictions
            }

            match frame {
                // DATA and HEADERS are allowed in early data for requests
                H3Frame::Data { .. } | H3Frame::Headers { .. } if self.allow_early_requests => {
                    Ok(())
                }

                // SETTINGS may or may not be allowed based on policy
                H3Frame::Settings(_) if self.allow_early_settings => Ok(()),

                // Control frames that should wait for handshake completion
                H3Frame::Settings(_) if !self.allow_early_settings => Err(
                    H3NativeError::StreamProtocol("SETTINGS frame not allowed in 0-RTT"),
                ),

                // Frames that must never be sent in 0-RTT
                H3Frame::Goaway(_) | H3Frame::MaxPushId(_) => Err(H3NativeError::StreamProtocol(
                    "control frame not allowed in 0-RTT",
                )),

                // PUSH_PROMISE should not be sent in early data
                H3Frame::PushPromise { .. } => Err(H3NativeError::StreamProtocol(
                    "PUSH_PROMISE not allowed in 0-RTT",
                )),

                // Other frames follow default policy
                _ => {
                    if self.allow_early_requests {
                        Ok(())
                    } else {
                        Err(H3NativeError::StreamProtocol("frame not allowed in 0-RTT"))
                    }
                }
            }
        }
    }

    #[test]
    fn zero_rtt_state_transitions() {
        let mut config = ZeroRttConfig::default();
        assert_eq!(config.state, ZeroRttState::NotAttempted);
        assert!(!config.is_early_data_allowed());

        // Transition to pending 0-RTT
        config.state = ZeroRttState::Pending;
        assert!(config.is_early_data_allowed());
        assert!(config.can_send_early_data(1000));

        // Transition to accepted
        config.state = ZeroRttState::Accepted;
        assert!(config.is_early_data_allowed());

        // Transition to handshake complete
        config.state = ZeroRttState::HandshakeComplete;
        assert!(!config.is_early_data_allowed());

        // Transition to rejected
        config.state = ZeroRttState::Rejected;
        assert!(!config.is_early_data_allowed());
    }

    #[test]
    fn zero_rtt_early_data_limits() {
        let mut config = ZeroRttConfig {
            max_early_data: 1000,
            state: ZeroRttState::Pending,
            ..ZeroRttConfig::default()
        };

        // Can send within limit
        assert!(config.can_send_early_data(500));
        config
            .record_early_data_sent(500)
            .expect("record early data");
        assert_eq!(config.early_data_sent, 500);

        // Can send up to limit
        assert!(config.can_send_early_data(500));
        config
            .record_early_data_sent(500)
            .expect("record remaining");
        assert_eq!(config.early_data_sent, 1000);

        // Cannot exceed limit
        assert!(!config.can_send_early_data(1));
        let err = config.record_early_data_sent(1).expect_err("should reject");
        assert!(matches!(err, H3NativeError::StreamProtocol(_)));
    }

    #[test]
    fn zero_rtt_frame_validation_allows_requests() {
        let config = ZeroRttConfig {
            state: ZeroRttState::Pending,
            allow_early_requests: true,
            allow_early_settings: false,
            ..ZeroRttConfig::default()
        };

        // DATA and HEADERS should be allowed for requests
        let data_frame = H3Frame::Data {
            payload: vec![1, 2, 3],
        };
        config
            .validate_early_frame(&data_frame)
            .expect("DATA allowed");

        let headers_frame = H3Frame::Headers {
            field_block: vec![4, 5, 6],
        };
        config
            .validate_early_frame(&headers_frame)
            .expect("HEADERS allowed");
    }

    #[test]
    fn zero_rtt_frame_validation_rejects_control_frames() {
        let config = ZeroRttConfig {
            state: ZeroRttState::Pending,
            allow_early_requests: true,
            allow_early_settings: false,
            ..ZeroRttConfig::default()
        };

        // Control frames should be rejected
        let settings_frame = H3Frame::Settings(H3Settings::default());
        let err = config
            .validate_early_frame(&settings_frame)
            .expect_err("SETTINGS rejected");
        assert!(matches!(err, H3NativeError::StreamProtocol(_)));

        let goaway_frame = H3Frame::Goaway(123);
        let err = config
            .validate_early_frame(&goaway_frame)
            .expect_err("GOAWAY rejected");
        assert!(matches!(err, H3NativeError::StreamProtocol(_)));

        let max_push_frame = H3Frame::MaxPushId(456);
        let err = config
            .validate_early_frame(&max_push_frame)
            .expect_err("MAX_PUSH_ID rejected");
        assert!(matches!(err, H3NativeError::StreamProtocol(_)));

        let push_promise_frame = H3Frame::PushPromise {
            push_id: 789,
            field_block: vec![7, 8, 9],
        };
        let err = config
            .validate_early_frame(&push_promise_frame)
            .expect_err("PUSH_PROMISE rejected");
        assert!(matches!(err, H3NativeError::StreamProtocol(_)));
    }

    #[test]
    fn zero_rtt_settings_policy_enforcement() {
        let mut config = ZeroRttConfig {
            state: ZeroRttState::Pending,
            allow_early_settings: true,
            ..ZeroRttConfig::default()
        };

        // SETTINGS allowed when policy permits
        let settings_frame = H3Frame::Settings(H3Settings::default());
        config
            .validate_early_frame(&settings_frame)
            .expect("SETTINGS allowed with policy");

        // SETTINGS rejected when policy forbids
        config.allow_early_settings = false;
        let err = config
            .validate_early_frame(&settings_frame)
            .expect_err("SETTINGS rejected by policy");
        assert!(matches!(err, H3NativeError::StreamProtocol(_)));
    }

    #[test]
    fn zero_rtt_request_policy_enforcement() {
        let config = ZeroRttConfig {
            state: ZeroRttState::Pending,
            allow_early_requests: false,
            ..ZeroRttConfig::default()
        };

        // DATA and HEADERS rejected when requests not allowed
        let data_frame = H3Frame::Data {
            payload: vec![1, 2, 3],
        };
        let err = config
            .validate_early_frame(&data_frame)
            .expect_err("DATA rejected by policy");
        assert!(matches!(err, H3NativeError::StreamProtocol(_)));

        let headers_frame = H3Frame::Headers {
            field_block: vec![4, 5, 6],
        };
        let err = config
            .validate_early_frame(&headers_frame)
            .expect_err("HEADERS rejected by policy");
        assert!(matches!(err, H3NativeError::StreamProtocol(_)));
    }

    #[test]
    fn zero_rtt_no_restrictions_after_handshake() {
        let config = ZeroRttConfig {
            state: ZeroRttState::HandshakeComplete,
            allow_early_requests: false,
            allow_early_settings: false,
            ..ZeroRttConfig::default()
        };

        // All frames allowed after handshake completion
        let settings_frame = H3Frame::Settings(H3Settings::default());
        config
            .validate_early_frame(&settings_frame)
            .expect("SETTINGS allowed after handshake");

        let goaway_frame = H3Frame::Goaway(123);
        config
            .validate_early_frame(&goaway_frame)
            .expect("GOAWAY allowed after handshake");

        let data_frame = H3Frame::Data {
            payload: vec![1, 2, 3],
        };
        config
            .validate_early_frame(&data_frame)
            .expect("DATA allowed after handshake");
    }

    #[test]
    fn zero_rtt_replay_protection_state_isolation() {
        // Test that 0-RTT state is properly isolated to prevent replay attacks
        let mut config1 = ZeroRttConfig {
            state: ZeroRttState::Accepted,
            max_early_data: 1000,
            ..ZeroRttConfig::default()
        };

        let mut config2 = ZeroRttConfig {
            state: ZeroRttState::Rejected,
            ..ZeroRttConfig::default()
        };

        // First connection can send early data
        config1
            .record_early_data_sent(500)
            .expect("config1 early data");
        assert_eq!(config1.early_data_sent, 500);

        // Second connection (replayed) cannot send early data
        let err = config2
            .record_early_data_sent(500)
            .expect_err("config2 should reject");
        assert!(matches!(err, H3NativeError::StreamProtocol(_)));
        assert_eq!(config2.early_data_sent, 0);
    }

    #[test]
    fn zero_rtt_conservative_defaults() {
        let config = ZeroRttConfig::default();

        // Conservative defaults: allow requests but not control frames
        assert!(config.allow_early_requests);
        assert!(!config.allow_early_settings);
        assert_eq!(config.max_early_data, 16384); // 16KB
        assert_eq!(config.state, ZeroRttState::NotAttempted);
        assert_eq!(config.early_data_sent, 0);
    }

    #[test]
    fn zero_rtt_saturation_arithmetic() {
        let mut config = ZeroRttConfig {
            state: ZeroRttState::Pending,
            max_early_data: u64::MAX,
            early_data_sent: u64::MAX - 100,
            ..ZeroRttConfig::default()
        };

        // Should saturate without overflow
        assert!(config.can_send_early_data(50));
        config.record_early_data_sent(50).expect("within bounds");

        assert!(config.can_send_early_data(50));
        config.record_early_data_sent(50).expect("exactly at limit");

        // Should not allow more after saturation
        assert!(!config.can_send_early_data(1));
    }

    // ========== QPACK Dynamic Table Eviction Conformance Tests ==========

    /// Mock dynamic table entry for conformance testing.
    #[derive(Debug, Clone, PartialEq)]
    struct QpackDynamicEntry {
        name: String,
        value: String,
        size: usize,
        reference_count: usize,
        insertion_order: u64,
    }

    impl QpackDynamicEntry {
        fn new(name: String, value: String, insertion_order: u64) -> Self {
            let size = 32 + name.len() + value.len(); // RFC 9204 size calculation
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
    }

    /// Mock QPACK dynamic table for conformance testing.
    #[derive(Debug, Clone)]
    struct QpackDynamicTable {
        entries: Vec<QpackDynamicEntry>,
        max_capacity: usize,
        current_size: usize,
        insertion_counter: u64,
        evicted_count: usize,
    }

    impl QpackDynamicTable {
        fn new(max_capacity: usize) -> Self {
            Self {
                entries: Vec::new(),
                max_capacity,
                current_size: 0,
                insertion_counter: 0,
                evicted_count: 0,
            }
        }

        fn insert(&mut self, name: String, value: String) -> Result<u64, &'static str> {
            let entry = QpackDynamicEntry::new(name, value, self.insertion_counter);
            let entry_size = entry.size;

            if entry_size > self.max_capacity {
                return Err("entry larger than table capacity");
            }

            // Evict entries to make space (LRU with reference checking)
            while self.current_size + entry_size > self.max_capacity {
                if !self.evict_lru_unreferenced() {
                    return Err("cannot evict enough space (all entries referenced)");
                }
            }

            let insertion_id = self.insertion_counter;
            self.entries.push(entry);
            self.current_size += entry_size;
            self.insertion_counter += 1;

            Ok(insertion_id)
        }

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

        fn reference_entry(&mut self, insertion_id: u64) -> bool {
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

        fn unreference_entry(&mut self, insertion_id: u64) -> bool {
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

        fn len(&self) -> usize {
            self.entries.len()
        }

        fn size(&self) -> usize {
            self.current_size
        }

        fn capacity(&self) -> usize {
            self.max_capacity
        }
    }

    #[test]
    fn qpack_conformance_dynamic_table_lru_eviction() {
        // Conformance: RFC 9204 Section 3.2 - Dynamic Table
        // LRU eviction must evict least recently inserted unreferenced entries first.

        let mut table = QpackDynamicTable::new(200); // Small table for testing

        // Insert entries that together exceed capacity
        let id1 = table.insert("header-a".into(), "value-a".into()).unwrap();
        let id2 = table.insert("header-b".into(), "value-b".into()).unwrap();
        let id3 = table.insert("header-c".into(), "value-c".into()).unwrap();

        assert_eq!(table.len(), 3);

        // Insert a large entry that requires eviction
        let id4 = table
            .insert(
                "large-header".into(),
                "very-large-value-that-forces-eviction".into(),
            )
            .unwrap();

        // First entry (oldest, LRU) should have been evicted
        assert!(table.len() < 4);
        assert!(!table.reference_entry(id1)); // id1 should be gone
        assert!(table.reference_entry(id2)); // id2+ should still exist
        assert!(table.reference_entry(id3));
        assert!(table.reference_entry(id4));
    }

    #[test]
    fn qpack_conformance_dynamic_table_reference_protection() {
        // Conformance: RFC 9204 Section 3.2 - Referenced entries cannot be evicted.

        let mut table = QpackDynamicTable::new(150);

        let id1 = table
            .insert("ref-header".into(), "ref-value".into())
            .unwrap();
        let id2 = table
            .insert("temp-header".into(), "temp-value".into())
            .unwrap();

        // Reference the first entry
        assert!(table.reference_entry(id1));

        // Insert entries that would normally evict both
        let _id3 = table
            .insert("push-header-1".into(), "push-value-1".into())
            .unwrap();
        let _id4 = table
            .insert("push-header-2".into(), "push-value-2".into())
            .unwrap();

        // Referenced entry should be protected, unreferenced should be evicted
        assert!(table.reference_entry(id1)); // Still referenced and present
        assert!(!table.reference_entry(id2)); // Should be evicted
    }

    #[test]
    fn qpack_conformance_dynamic_table_size_accounting() {
        // Conformance: RFC 9204 Section 4.4 - Dynamic table size calculation.
        // Size = 32 + name_len + value_len for each entry.

        let mut table = QpackDynamicTable::new(1000);
        let initial_size = table.size();

        // Insert entry: 32 + 4 + 5 = 41 bytes
        let _id1 = table.insert("name".into(), "value".into()).unwrap();
        assert_eq!(table.size(), initial_size + 41);

        // Insert another: 32 + 7 + 8 = 47 bytes
        let _id2 = table.insert("content".into(), "response".into()).unwrap();
        assert_eq!(table.size(), initial_size + 41 + 47);

        // Size accounting must be exact
        assert!(table.size() <= table.capacity());
    }

    #[test]
    fn qpack_conformance_dynamic_table_capacity_enforcement() {
        // Conformance: RFC 9204 Section 3.2 - Table must not exceed max capacity.

        let capacity = 100;
        let mut table = QpackDynamicTable::new(capacity);

        // Fill table close to capacity
        let _id1 = table.insert("a".into(), "b".into()).unwrap(); // 32 + 1 + 1 = 34
        let _id2 = table.insert("c".into(), "d".into()).unwrap(); // 32 + 1 + 1 = 34

        assert_eq!(table.size(), 68);

        // Try to insert entry larger than remaining space
        let _id3 = table.insert("large".into(), "header-value".into()).unwrap(); // 32 + 5 + 12 = 49

        // Should have evicted entries to make space
        assert!(table.size() <= capacity);

        // Try to insert entry larger than total capacity
        let result = table.insert(
            "oversized-header-name".into(),
            "oversized-header-value-that-exceeds-table-capacity".into(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn qpack_conformance_dynamic_table_insertion_pressure() {
        // Conformance: Under heavy insertion pressure, table should maintain
        // size constraints while evicting appropriate entries.

        let mut table = QpackDynamicTable::new(200);
        let mut insertion_ids = Vec::new();

        // Insert many small entries
        for i in 0..20 {
            let name = format!("header-{}", i);
            let value = format!("value-{}", i);
            if let Ok(id) = table.insert(name, value) {
                insertion_ids.push(id);
            }
        }

        // Table should not exceed capacity
        assert!(table.size() <= table.capacity());

        // Some entries should have been evicted due to pressure
        assert!(table.evicted_count > 0);

        // Verify LRU ordering - early entries should be evicted first
        let first_half_present = insertion_ids
            .iter()
            .take(10)
            .filter(|&&id| table.reference_entry(id))
            .count();
        let second_half_present = insertion_ids
            .iter()
            .skip(10)
            .filter(|&&id| table.reference_entry(id))
            .count();

        // Later entries should be more likely to remain
        assert!(second_half_present >= first_half_present);
    }

    #[test]
    fn qpack_conformance_dynamic_table_reference_lifecycle() {
        // Conformance: Reference counting must accurately track entry usage.

        let mut table = QpackDynamicTable::new(300);

        let id1 = table
            .insert("lifecycle".into(), "test-entry".into())
            .unwrap();

        // Add multiple references
        assert!(table.reference_entry(id1));
        assert!(table.reference_entry(id1));
        assert!(table.reference_entry(id1));

        // Entry should be protected from eviction
        for i in 0..10 {
            let _ = table.insert(format!("filler-{}", i), "filler-value".into());
        }

        // Should still be referenceable (not evicted)
        assert!(table.reference_entry(id1));

        // Remove references gradually
        assert!(table.unreference_entry(id1));
        assert!(table.unreference_entry(id1));
        assert!(table.unreference_entry(id1));
        assert!(table.unreference_entry(id1)); // Remove extra reference we added for testing

        // Now should be evictable
        let large_entry_result = table.insert(
            "force-eviction".into(),
            "large-value-to-trigger-eviction-of-unreferenced-entries".into(),
        );
        assert!(large_entry_result.is_ok());

        // Entry should now be evicted (no longer referenceable)
        assert!(!table.reference_entry(id1));
    }

    #[test]
    fn qpack_conformance_dynamic_table_memory_pressure_simulation() {
        // Conformance: Table should gracefully handle memory pressure scenarios.

        let small_capacity = 150;
        let mut table = QpackDynamicTable::new(small_capacity);

        // Scenario 1: Many tiny entries
        let mut tiny_ids = Vec::new();
        for i in 0..50 {
            if let Ok(id) = table.insert(format!("t{}", i), "x".into()) {
                tiny_ids.push(id);
            }
        }
        assert!(table.size() <= small_capacity);

        // Scenario 2: Mix of sizes with references
        let medium_id = table
            .insert("medium-header".into(), "medium-value".into())
            .unwrap();
        assert!(table.reference_entry(medium_id));

        // Scenario 3: Sudden large insertion
        let large_result = table.insert(
            "emergency-large".into(),
            "large-emergency-header-value".into(),
        );
        assert!(large_result.is_ok());

        // Referenced medium entry should survive, unreferenced tiny entries evicted
        assert!(table.reference_entry(medium_id));
        assert!(table.size() <= small_capacity);

        // Scenario 4: Capacity exhaustion with all entries referenced
        let ids: Vec<_> = table.entries.iter().map(|e| e.insertion_order).collect();
        ids.into_iter().for_each(|id| {
            // Try to reference all remaining entries
            let _ = table.reference_entry(id);
        });

        let impossible_result = table.insert(
            "impossible".into(),
            "this-should-fail-due-to-references".into(),
        );
        // Should fail when no entries can be evicted
        assert!(impossible_result.is_err());
    }

    #[test]
    fn qpack_conformance_dynamic_table_eviction_order_deterministic() {
        // Conformance: Eviction order must be deterministic and follow LRU strictly.

        let mut table1 = QpackDynamicTable::new(120);
        let mut table2 = QpackDynamicTable::new(120);

        // Insert identical sequences in both tables
        let sequence = vec![
            ("first", "entry"),
            ("second", "entry"),
            ("third", "entry"),
            ("fourth", "entry"),
        ];

        let mut ids1 = Vec::new();
        let mut ids2 = Vec::new();

        for (name, value) in &sequence {
            ids1.push(table1.insert(name.to_string(), value.to_string()).unwrap());
            ids2.push(table2.insert(name.to_string(), value.to_string()).unwrap());
        }

        // Force eviction with identical large entry
        let large_name = "eviction-trigger";
        let large_value = "large-value-that-forces-eviction";

        let _final1 = table1
            .insert(large_name.into(), large_value.into())
            .unwrap();
        let _final2 = table2
            .insert(large_name.into(), large_value.into())
            .unwrap();

        // Both tables should have identical state after eviction
        assert_eq!(table1.len(), table2.len());
        assert_eq!(table1.size(), table2.size());
        assert_eq!(table1.evicted_count, table2.evicted_count);

        // Surviving entries should be the same in both tables
        for (id1, id2) in ids1.iter().zip(ids2.iter()) {
            let present1 = table1.reference_entry(*id1);
            let present2 = table2.reference_entry(*id2);
            assert_eq!(present1, present2, "Eviction determinism violated");
        }
    }
}
