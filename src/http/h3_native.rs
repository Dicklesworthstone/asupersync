//! Native HTTP/3 protocol primitives over QUIC streams.
//!
//! This module implements:
//! - HTTP/3 frame encode/decode
//! - SETTINGS payload handling
//! - control-stream ordering checks
//! - pseudo-header validation helpers

use crate::net::quic_core::{decode_varint, encode_varint};
use std::collections::BTreeMap;
use std::fmt;

const H3_FRAME_DATA: u64 = 0x0;
const H3_FRAME_HEADERS: u64 = 0x1;
const H3_FRAME_CANCEL_PUSH: u64 = 0x3;
const H3_FRAME_SETTINGS: u64 = 0x4;
const H3_FRAME_PUSH_PROMISE: u64 = 0x5;
const H3_FRAME_GOAWAY: u64 = 0x7;
const H3_FRAME_MAX_PUSH_ID: u64 = 0xD;
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
}

impl H3UniStreamType {
    fn decode(stream_type: u64) -> Result<Self, H3NativeError> {
        match stream_type {
            H3_STREAM_TYPE_CONTROL => Ok(Self::Control),
            H3_STREAM_TYPE_PUSH => Ok(Self::Push),
            H3_STREAM_TYPE_QPACK_ENCODER => Ok(Self::QpackEncoder),
            H3_STREAM_TYPE_QPACK_DECODER => Ok(Self::QpackDecoder),
            _ => Err(H3NativeError::StreamProtocol(
                "unknown unidirectional stream type",
            )),
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
        let len = len as usize;
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
                H3Frame::Data(_) | H3Frame::Headers(_) | H3Frame::PushPromise { .. } => {
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
                // A second HEADERS block is interpreted as trailers and must follow DATA.
                if self.header_blocks_seen == 1 && self.saw_data {
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
            push_streams: BTreeMap::new(),
            uni_stream_types: BTreeMap::new(),
            control_stream_id: None,
            qpack_encoder_stream_id: None,
            qpack_decoder_stream_id: None,
            goaway_id: None,
        }
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

    /// Mark request-stream end.
    pub fn finish_request_stream(&mut self, stream_id: u64) -> Result<(), H3NativeError> {
        let state =
            self.request_streams
                .get_mut(&stream_id)
                .ok_or(H3NativeError::ControlProtocol(
                    "unknown request stream on finish",
                ))?;
        state.mark_end_stream()
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
        let kind = H3UniStreamType::decode(stream_type)?;
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
        assert_eq!(
            H3UniStreamType::decode(0x00).unwrap(),
            H3UniStreamType::Control
        );
        assert_eq!(
            H3UniStreamType::decode(0x01).unwrap(),
            H3UniStreamType::Push
        );
        assert_eq!(
            H3UniStreamType::decode(0x02).unwrap(),
            H3UniStreamType::QpackEncoder
        );
        assert_eq!(
            H3UniStreamType::decode(0x03).unwrap(),
            H3UniStreamType::QpackDecoder
        );
    }

    #[test]
    fn h3_uni_stream_type_decode_unknown_rejects() {
        let err = H3UniStreamType::decode(0xFF).expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::StreamProtocol("unknown unidirectional stream type")
        );
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
    fn request_stream_second_headers_without_data_error() {
        let mut st = H3RequestStreamState::new();
        st.on_frame(&H3Frame::Headers(vec![0x80]))
            .expect("first HEADERS");
        // Second HEADERS without any intervening DATA.
        let err = st
            .on_frame(&H3Frame::Headers(vec![0x81]))
            .expect_err("must fail");
        assert_eq!(
            err,
            H3NativeError::ControlProtocol("invalid HEADERS ordering on request stream")
        );
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
}
