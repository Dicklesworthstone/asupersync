//! WebSocket frame codec according to RFC 6455.
//!
//! Implements the WebSocket wire format for framing messages:
//! - Binary frame encoding/decoding
//! - Masking (client-to-server)
//! - Fragmentation support
//! - Control frame validation
//!
//! # Frame Format (RFC 6455 Section 5.2)
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-------+-+-------------+-------------------------------+
//! |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
//! |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
//! |N|V|V|V|       |S|             |   (if payload len==126/127)   |
//! | |1|2|3|       |K|             |                               |
//! +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
//! |     Extended payload length continued, if payload len == 127  |
//! + - - - - - - - - - - - - - - - +-------------------------------+
//! |                               |Masking-key, if MASK set to 1  |
//! +-------------------------------+-------------------------------+
//! | Masking-key (continued)       |          Payload Data         |
//! +-------------------------------- - - - - - - - - - - - - - - - +
//! :                     Payload Data continued ...                :
//! + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
//! |                     Payload Data (continued)                  |
//! +---------------------------------------------------------------+
//! ```

use crate::bytes::{BufMut, Bytes, BytesMut};
use crate::codec::{Decoder, Encoder};
use crate::util::{EntropySource, OsEntropy};
use std::io;

const CONTROL_FRAME_MAX_PAYLOAD_LEN: usize = 125;

/// WebSocket frame opcode (4 bits).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Opcode {
    /// Continuation frame (fragmented message).
    Continuation = 0x0,
    /// Text data frame.
    Text = 0x1,
    /// Binary data frame.
    Binary = 0x2,
    // 0x3-0x7 reserved for non-control frames
    /// Connection close control frame.
    Close = 0x8,
    /// Ping control frame.
    Ping = 0x9,
    /// Pong control frame.
    Pong = 0xA,
    // 0xB-0xF reserved for control frames
}

impl Opcode {
    /// Returns true if this is a control frame (Close, Ping, Pong).
    #[must_use]
    pub const fn is_control(self) -> bool {
        matches!(self, Self::Close | Self::Ping | Self::Pong)
    }

    /// Returns true if this is a data frame (Continuation, Text, Binary).
    #[must_use]
    pub const fn is_data(self) -> bool {
        matches!(self, Self::Continuation | Self::Text | Self::Binary)
    }

    /// Try to parse an opcode from a byte value.
    pub fn from_u8(value: u8) -> Result<Self, WsError> {
        match value {
            0x0 => Ok(Self::Continuation),
            0x1 => Ok(Self::Text),
            0x2 => Ok(Self::Binary),
            0x8 => Ok(Self::Close),
            0x9 => Ok(Self::Ping),
            0xA => Ok(Self::Pong),
            _ => Err(WsError::InvalidOpcode(value)),
        }
    }
}

/// WebSocket frame.
#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)] // RFC 6455 exposes these as independent header bits.
pub struct Frame {
    /// Final fragment flag (FIN bit).
    pub fin: bool,
    /// Reserved bit 1 (must be 0 unless extension defines meaning).
    pub rsv1: bool,
    /// Reserved bit 2 (must be 0 unless extension defines meaning).
    pub rsv2: bool,
    /// Reserved bit 3 (must be 0 unless extension defines meaning).
    pub rsv3: bool,
    /// Frame opcode.
    pub opcode: Opcode,
    /// Mask flag (client-to-server frames must be masked).
    pub masked: bool,
    /// Masking key (4 bytes, only present if masked).
    pub mask_key: Option<[u8; 4]>,
    /// Payload data.
    pub payload: Bytes,
}

impl Frame {
    /// Create a new text frame with the given payload.
    #[must_use]
    pub fn text(payload: impl Into<Bytes>) -> Self {
        Self {
            fin: true,
            rsv1: false,
            rsv2: false,
            rsv3: false,
            opcode: Opcode::Text,
            masked: false,
            mask_key: None,
            payload: payload.into(),
        }
    }

    /// Create a new binary frame with the given payload.
    #[must_use]
    pub fn binary(payload: impl Into<Bytes>) -> Self {
        Self {
            fin: true,
            rsv1: false,
            rsv2: false,
            rsv3: false,
            opcode: Opcode::Binary,
            masked: false,
            mask_key: None,
            payload: payload.into(),
        }
    }

    /// Create a ping frame with optional payload.
    ///
    /// # Panics
    ///
    /// Panics if the payload exceeds the 125-byte control frame limit
    /// (RFC 6455 section 5.5).
    #[must_use]
    pub fn ping(payload: impl Into<Bytes>) -> Self {
        let payload = payload.into();
        assert_control_payload_len("ping", payload.len());

        Self {
            fin: true,
            rsv1: false,
            rsv2: false,
            rsv3: false,
            opcode: Opcode::Ping,
            masked: false,
            mask_key: None,
            payload,
        }
    }

    /// Create a pong frame with optional payload.
    ///
    /// # Panics
    ///
    /// Panics if the payload exceeds the 125-byte control frame limit
    /// (RFC 6455 section 5.5).
    #[must_use]
    pub fn pong(payload: impl Into<Bytes>) -> Self {
        let payload = payload.into();
        assert_control_payload_len("pong", payload.len());

        Self {
            fin: true,
            rsv1: false,
            rsv2: false,
            rsv3: false,
            opcode: Opcode::Pong,
            masked: false,
            mask_key: None,
            payload,
        }
    }

    /// Create a close frame with optional status code and reason.
    ///
    /// # Panics
    ///
    /// Panics if `code` is not valid for wire transmission per RFC 6455 §7.4,
    /// or if the total close payload (2-byte code + reason) exceeds the
    /// 125-byte control frame limit (RFC 6455 §5.5).
    #[must_use]
    pub fn close(code: Option<u16>, reason: Option<&str>) -> Self {
        if let Some(c) = code {
            assert!(
                CloseCode::is_valid_code(c),
                "close code {c} is not valid for use in a Close frame (RFC 6455 §7.4)"
            );
        }
        if code.is_none() && reason.is_some() {
            // RFC 6455 §5.5.1: a Close frame body starts with a 2-byte status
            // code. Fail closed instead of silently inventing Normal (1000).
            return Self {
                fin: true,
                rsv1: false,
                rsv2: false,
                rsv3: false,
                opcode: Opcode::Close,
                masked: false,
                mask_key: None,
                payload: Bytes::new(),
            };
        }
        if let Some(r) = reason {
            let total = 2 + r.len();
            assert_control_payload_len("close", total);
        }
        let payload = match (code, reason) {
            (Some(c), Some(r)) => {
                let mut buf = BytesMut::with_capacity(2 + r.len());
                buf.put_u16(c);
                buf.put_slice(r.as_bytes());
                buf.freeze()
            }
            (Some(c), None) => {
                let mut buf = BytesMut::with_capacity(2);
                buf.put_u16(c);
                buf.freeze()
            }
            (None, Some(_r)) => Bytes::new(),
            (None, None) => Bytes::new(),
        };

        Self {
            fin: true,
            rsv1: false,
            rsv2: false,
            rsv3: false,
            opcode: Opcode::Close,
            masked: false,
            mask_key: None,
            payload,
        }
    }
}

fn assert_control_payload_len(frame_kind: &str, payload_len: usize) {
    assert!(
        payload_len <= CONTROL_FRAME_MAX_PAYLOAD_LEN,
        "{frame_kind} frame payload ({payload_len} bytes) exceeds 125-byte control frame limit (RFC 6455 section 5.5)"
    );
}

/// Refuses a Ping or Pong payload over the 125-byte control frame limit, so
/// `send` and `ping` report [`WsError::ControlFrameTooLarge`] instead of
/// panicking in [`Frame::ping`] or [`Frame::pong`].
pub(super) fn check_control_payload_len(payload_len: usize) -> Result<(), WsError> {
    if payload_len > CONTROL_FRAME_MAX_PAYLOAD_LEN {
        return Err(WsError::ControlFrameTooLarge(payload_len));
    }
    Ok(())
}

/// WebSocket codec errors.
#[derive(Debug)]
pub enum WsError {
    /// I/O error.
    Io(io::Error),
    /// Invalid opcode value.
    InvalidOpcode(u8),
    /// Protocol violation (e.g. unexpected continuation frame).
    ProtocolViolation(&'static str),
    /// Reserved bits set without extension support.
    ReservedBitsSet,
    /// Payload exceeds maximum allowed size.
    PayloadTooLarge {
        /// Actual payload size in bytes.
        size: u64,
        /// Maximum allowed size in bytes.
        max: usize,
    },
    /// Control frame payload exceeds 125 bytes.
    ControlFrameTooLarge(usize),
    /// Control frame is fragmented (FIN not set).
    FragmentedControlFrame,
    /// Client frame is not masked (protocol violation).
    UnmaskedClientFrame,
    /// Server frame is masked (optional error, some servers accept).
    MaskedServerFrame,
    /// Invalid UTF-8 in text frame.
    InvalidUtf8,
    /// Invalid close frame payload.
    InvalidClosePayload,
    /// Outbound frame cannot fit within the bounded retained write buffer.
    OutboundBufferFull {
        /// Bytes already pending in the retained write buffer.
        pending: usize,
        /// Additional encoded bytes attempted.
        attempted: usize,
        /// Configured maximum retained bytes.
        max: usize,
        /// Stable policy action string.
        action: &'static str,
    },
}

impl WsError {
    /// Maps the error to the corresponding WebSocket close code.
    #[must_use]
    pub fn as_close_code(&self) -> CloseCode {
        match self {
            Self::PayloadTooLarge { .. } | Self::ControlFrameTooLarge(_) => {
                CloseCode::MessageTooBig
            }
            Self::InvalidUtf8 => CloseCode::InvalidPayload,
            Self::Io(_) => CloseCode::Abnormal,
            Self::OutboundBufferFull { .. } => CloseCode::TryAgainLater,
            _ => CloseCode::ProtocolError,
        }
    }
}

impl std::fmt::Display for WsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::InvalidOpcode(op) => write!(f, "invalid opcode: 0x{op:X}"),
            Self::ProtocolViolation(msg) => write!(f, "protocol violation: {msg}"),
            Self::ReservedBitsSet => write!(f, "reserved bits set without extension"),
            Self::PayloadTooLarge { size, max } => {
                write!(f, "payload too large: {size} bytes (max: {max})")
            }
            Self::ControlFrameTooLarge(size) => {
                write!(
                    f,
                    "control frame payload too large: {size} bytes (max: 125)"
                )
            }
            Self::FragmentedControlFrame => write!(f, "control frame cannot be fragmented"),
            Self::UnmaskedClientFrame => write!(f, "client frame must be masked"),
            Self::MaskedServerFrame => write!(f, "server frame should not be masked"),
            Self::InvalidUtf8 => write!(f, "invalid UTF-8 in text frame"),
            Self::InvalidClosePayload => write!(f, "invalid close frame payload"),
            Self::OutboundBufferFull {
                pending,
                attempted,
                max,
                action,
            } => write!(
                f,
                "outbound WebSocket write buffer full: pending {pending} bytes + attempted {attempted} bytes exceeds max {max}; action={action}"
            ),
        }
    }
}

impl std::error::Error for WsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for WsError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

/// Role in the WebSocket connection (affects masking requirements).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Client role: must mask frames sent to server.
    Client,
    /// Server role: must not mask frames sent to client.
    Server,
}

/// Decode state machine for the frame codec.
#[derive(Debug)]
enum DecodeState {
    /// Waiting for the first 2 header bytes.
    Header,
    /// Reading extended payload length.
    ExtendedLength {
        fin: bool,
        rsv1: bool,
        rsv2: bool,
        rsv3: bool,
        opcode: Opcode,
        masked: bool,
        bytes_needed: usize,
    },
    /// Reading mask key (4 bytes).
    MaskKey {
        fin: bool,
        rsv1: bool,
        rsv2: bool,
        rsv3: bool,
        opcode: Opcode,
        payload_len: u64,
    },
    /// Reading payload data.
    Payload {
        fin: bool,
        rsv1: bool,
        rsv2: bool,
        rsv3: bool,
        opcode: Opcode,
        mask_key: Option<[u8; 4]>,
        payload_len: u64,
    },
    /// Codec encountered a fatal error and is permanently poisoned.
    Poisoned,
}

/// WebSocket frame codec.
///
/// Implements encoding and decoding of WebSocket frames according to RFC 6455.
#[derive(Debug)]
pub struct FrameCodec {
    /// Maximum frame payload size (default: 16MB).
    max_payload_size: usize,
    /// Role (client or server) affects masking requirements.
    role: Role,
    /// Current decode state.
    state: DecodeState,
    /// Whether to validate reserved bits.
    validate_reserved_bits: bool,
    /// Negotiated RFC 7692 profile; never enabled by relaxing generic RSV checks.
    permessage_deflate: bool,
}

impl FrameCodec {
    /// Default maximum payload size (16 MB).
    pub const DEFAULT_MAX_PAYLOAD_SIZE: usize = 16 * 1024 * 1024;

    /// Creates a new frame codec for the given role.
    #[must_use]
    pub fn new(role: Role) -> Self {
        Self {
            max_payload_size: Self::DEFAULT_MAX_PAYLOAD_SIZE,
            role,
            state: DecodeState::Header,
            validate_reserved_bits: true,
            permessage_deflate: false,
        }
    }

    /// Creates a client-role frame codec.
    #[must_use]
    pub fn client() -> Self {
        Self::new(Role::Client)
    }

    /// Creates a server-role frame codec.
    #[must_use]
    pub fn server() -> Self {
        Self::new(Role::Server)
    }

    /// Sets the maximum payload size.
    #[must_use]
    pub fn max_payload_size(mut self, size: usize) -> Self {
        self.max_payload_size = size;
        self
    }

    /// Sets whether to validate reserved bits.
    #[must_use]
    pub fn validate_reserved_bits(mut self, validate: bool) -> Self {
        self.validate_reserved_bits = validate;
        self
    }

    pub(super) fn enable_permessage_deflate(&mut self) {
        self.permessage_deflate = true;
    }

    pub(super) const fn permessage_deflate_enabled(&self) -> bool {
        self.permessage_deflate
    }

    /// Encode a frame using the provided entropy source for client masking.
    pub(crate) fn encode_with_entropy(
        &self,
        frame: &Frame,
        dst: &mut BytesMut,
        entropy: &dyn EntropySource,
    ) -> Result<(), WsError> {
        let payload_len = frame.payload.len();

        // Control frame validation
        if frame.opcode.is_control() {
            if !frame.fin {
                return Err(WsError::FragmentedControlFrame);
            }
            if payload_len > CONTROL_FRAME_MAX_PAYLOAD_LEN {
                return Err(WsError::ControlFrameTooLarge(payload_len));
            }
        }
        if frame.opcode == Opcode::Close {
            validate_close_payload_for_send(&frame.payload)?;
        }

        // Determine if we need to mask (based on role)
        let should_mask = self.role == Role::Client;

        // First byte: FIN, RSV1-3, opcode
        let mut first_byte = frame.opcode as u8;
        if frame.fin {
            first_byte |= 0x80;
        }
        if frame.rsv1 {
            first_byte |= 0x40;
        }
        if frame.rsv2 {
            first_byte |= 0x20;
        }
        if frame.rsv3 {
            first_byte |= 0x10;
        }

        // Second byte: MASK bit + payload length (7-bit or indicator)
        let mask_bit = if should_mask { 0x80 } else { 0 };

        // Calculate header size
        let header_size =
            2 + if payload_len > 65535 {
                8
            } else if payload_len > 125 {
                2
            } else {
                0
            } + if should_mask { 4 } else { 0 };

        // Reserve space
        dst.reserve(header_size + payload_len);

        // Write header
        dst.put_u8(first_byte);

        if payload_len <= CONTROL_FRAME_MAX_PAYLOAD_LEN {
            dst.put_u8(mask_bit | (payload_len as u8));
        } else if payload_len <= 65535 {
            dst.put_u8(mask_bit | 0x7E);
            dst.put_u16(payload_len as u16);
        } else {
            dst.put_u8(mask_bit | 0x7F);
            dst.put_u64(payload_len as u64);
        }

        // Write mask key and payload
        if should_mask {
            let mask_key = generate_mask_key(entropy);
            dst.put_slice(&mask_key);

            // Apply mask directly in the destination buffer to avoid double copy
            let start = dst.len();
            dst.put_slice(&frame.payload);
            apply_mask(&mut dst[start..], mask_key);
        } else {
            dst.put_slice(&frame.payload);
        }

        Ok(())
    }
}

impl Decoder for FrameCodec {
    type Item = Frame;
    type Error = WsError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match self.decode_inner(src) {
            Err(e) => {
                self.state = DecodeState::Poisoned;
                Err(e)
            }
            Ok(v) => Ok(v),
        }
    }
}

impl FrameCodec {
    /// Refuses all further decoding, as a decode error does. Called when a
    /// connection is failed above the codec (message assembly), because
    /// RFC 6455 §7.1.7 forbids processing more peer data after that.
    pub(crate) fn poison(&mut self) {
        self.state = DecodeState::Poisoned;
    }

    #[allow(clippy::too_many_lines)] // Single, explicit RFC 6455 decode state machine.
    fn decode_inner(&mut self, src: &mut BytesMut) -> Result<Option<Frame>, WsError> {
        loop {
            match &self.state {
                DecodeState::Poisoned => {
                    return Err(WsError::ProtocolViolation(
                        "codec is poisoned after a fatal error",
                    ));
                }
                DecodeState::Header => {
                    if src.len() < 2 {
                        return Ok(None);
                    }

                    let first_byte = src[0];
                    let second_byte = src[1];

                    let fin = (first_byte & 0x80) != 0;
                    let rsv1 = (first_byte & 0x40) != 0;
                    let rsv2 = (first_byte & 0x20) != 0;
                    let rsv3 = (first_byte & 0x10) != 0;
                    let opcode_raw = first_byte & 0x0F;
                    let masked = (second_byte & 0x80) != 0;
                    let payload_len_7 = second_byte & 0x7F;

                    // Validate reserved bits
                    let compressed_data = self.permessage_deflate
                        && matches!(opcode_raw, 1 | 2);
                    if self.validate_reserved_bits && ((rsv1 && !compressed_data) || rsv2 || rsv3) {
                        return Err(WsError::ReservedBitsSet);
                    }

                    let opcode = Opcode::from_u8(opcode_raw)?;

                    // Masking rules (RFC 6455):
                    // - Client->Server frames MUST be masked
                    // - Server->Client frames MUST NOT be masked
                    match self.role {
                        Role::Server if !masked => return Err(WsError::UnmaskedClientFrame),
                        Role::Client if masked => return Err(WsError::MaskedServerFrame),
                        _ => {}
                    }

                    // Control frame validation
                    if opcode.is_control() {
                        if !fin {
                            return Err(WsError::FragmentedControlFrame);
                        }
                        if usize::from(payload_len_7) > CONTROL_FRAME_MAX_PAYLOAD_LEN {
                            return Err(WsError::ControlFrameTooLarge(payload_len_7 as usize));
                        }
                    }

                    // Consume the 2-byte header
                    let _ = src.split_to(2);

                    // Determine next state based on payload length encoding
                    match payload_len_7 {
                        0..=125 => {
                            let payload_len = u64::from(payload_len_7);
                            if payload_len > self.max_payload_size as u64 {
                                return Err(WsError::PayloadTooLarge {
                                    size: payload_len,
                                    max: self.max_payload_size,
                                });
                            }
                            if masked {
                                self.state = DecodeState::MaskKey {
                                    fin,
                                    rsv1,
                                    rsv2,
                                    rsv3,
                                    opcode,
                                    payload_len,
                                };
                            } else {
                                self.state = DecodeState::Payload {
                                    fin,
                                    rsv1,
                                    rsv2,
                                    rsv3,
                                    opcode,
                                    mask_key: None,
                                    payload_len,
                                };
                            }
                        }
                        126 => {
                            self.state = DecodeState::ExtendedLength {
                                fin,
                                rsv1,
                                rsv2,
                                rsv3,
                                opcode,
                                masked,
                                bytes_needed: 2,
                            };
                        }
                        127 => {
                            self.state = DecodeState::ExtendedLength {
                                fin,
                                rsv1,
                                rsv2,
                                rsv3,
                                opcode,
                                masked,
                                bytes_needed: 8,
                            };
                        }
                        _ => unreachable!(),
                    }
                }

                DecodeState::ExtendedLength {
                    fin,
                    rsv1,
                    rsv2,
                    rsv3,
                    opcode,
                    masked,
                    bytes_needed,
                } => {
                    if src.len() < *bytes_needed {
                        return Ok(None);
                    }

                    let payload_len = if *bytes_needed == 2 {
                        let bytes = src.split_to(2);
                        let len = u64::from(u16::from_be_bytes([bytes[0], bytes[1]]));
                        // RFC 6455 §5.2: minimal encoding — 2-byte form for 126..65535
                        if len < 126 {
                            self.state = DecodeState::Header;
                            return Err(WsError::ProtocolViolation(
                                "non-minimal payload length encoding",
                            ));
                        }
                        len
                    } else {
                        let bytes = src.split_to(8);
                        let raw = u64::from_be_bytes([
                            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6],
                            bytes[7],
                        ]);
                        // RFC 6455 §5.2: most significant bit MUST be 0
                        if raw & (1u64 << 63) != 0 {
                            self.state = DecodeState::Header;
                            return Err(WsError::ProtocolViolation(
                                "most significant bit of 64-bit payload length must be 0",
                            ));
                        }
                        // RFC 6455 §5.2: minimal encoding — 8-byte form for 65536+
                        if raw < 65536 {
                            self.state = DecodeState::Header;
                            return Err(WsError::ProtocolViolation(
                                "non-minimal payload length encoding",
                            ));
                        }
                        raw
                    };

                    if payload_len > self.max_payload_size as u64 {
                        // Reset state since we already consumed length bytes from src
                        self.state = DecodeState::Header;
                        return Err(WsError::PayloadTooLarge {
                            size: payload_len,
                            max: self.max_payload_size,
                        });
                    }

                    let fin = *fin;
                    let rsv1 = *rsv1;
                    let rsv2 = *rsv2;
                    let rsv3 = *rsv3;
                    let opcode = *opcode;
                    let masked = *masked;

                    if masked {
                        self.state = DecodeState::MaskKey {
                            fin,
                            rsv1,
                            rsv2,
                            rsv3,
                            opcode,
                            payload_len,
                        };
                    } else {
                        self.state = DecodeState::Payload {
                            fin,
                            rsv1,
                            rsv2,
                            rsv3,
                            opcode,
                            mask_key: None,
                            payload_len,
                        };
                    }
                }

                DecodeState::MaskKey {
                    fin,
                    rsv1,
                    rsv2,
                    rsv3,
                    opcode,
                    payload_len,
                } => {
                    if src.len() < 4 {
                        return Ok(None);
                    }

                    let mask_bytes = src.split_to(4);
                    let mut mask_key = [0u8; 4];
                    mask_key.copy_from_slice(&mask_bytes);

                    let fin = *fin;
                    let rsv1 = *rsv1;
                    let rsv2 = *rsv2;
                    let rsv3 = *rsv3;
                    let opcode = *opcode;
                    let payload_len = *payload_len;

                    self.state = DecodeState::Payload {
                        fin,
                        rsv1,
                        rsv2,
                        rsv3,
                        opcode,
                        mask_key: Some(mask_key),
                        payload_len,
                    };
                }

                DecodeState::Payload {
                    fin,
                    rsv1,
                    rsv2,
                    rsv3,
                    opcode,
                    mask_key,
                    payload_len,
                } => {
                    let payload_len_usize =
                        usize::try_from(*payload_len).map_err(|_| WsError::PayloadTooLarge {
                            size: *payload_len,
                            max: usize::MAX,
                        })?;
                    if src.len() < payload_len_usize {
                        return Ok(None);
                    }

                    let mut payload = src.split_to(payload_len_usize);

                    // Apply masking if present
                    if let Some(key) = mask_key {
                        apply_mask(&mut payload, *key);
                    }

                    if *opcode == Opcode::Close {
                        validate_close_payload_for_receive(&payload)?;
                    }

                    let frame = Frame {
                        fin: *fin,
                        rsv1: *rsv1,
                        rsv2: *rsv2,
                        rsv3: *rsv3,
                        opcode: *opcode,
                        masked: mask_key.is_some(),
                        mask_key: *mask_key,
                        payload: payload.freeze(),
                    };

                    // Reset state for next frame
                    self.state = DecodeState::Header;

                    return Ok(Some(frame));
                }
            }
        }
    }
}

impl Encoder<Frame> for FrameCodec {
    type Error = WsError;

    fn encode(&mut self, frame: Frame, dst: &mut BytesMut) -> Result<(), Self::Error> {
        self.encode_with_entropy(&frame, dst, &OsEntropy)
    }
}

/// Apply XOR masking to payload data.
///
/// This is used for both masking (encoding) and unmasking (decoding).
/// The mask is applied in-place.
pub fn apply_mask(payload: &mut [u8], mask_key: [u8; 4]) {
    for (i, byte) in payload.iter_mut().enumerate() {
        *byte ^= mask_key[i % 4];
    }
}

/// Generate a mask key for client-to-server frames.
///
/// RFC 6455 §5.3 requires masking keys to be derived from a strong source of
/// entropy to prevent cross-protocol attacks via intermediary cache poisoning.
fn generate_mask_key(entropy: &dyn EntropySource) -> [u8; 4] {
    let mut key = [0u8; 4];
    entropy.fill_bytes(&mut key);
    key
}

fn validate_close_payload(
    payload: &[u8],
    is_valid_code: impl FnOnce(u16) -> bool,
) -> Result<(), WsError> {
    match payload.len() {
        0 => Ok(()),
        1 => Err(WsError::InvalidClosePayload),
        _ => {
            let code = u16::from_be_bytes([payload[0], payload[1]]);
            if !is_valid_code(code) {
                return Err(WsError::InvalidClosePayload);
            }
            if payload.len() > 2 {
                std::str::from_utf8(&payload[2..]).map_err(|_| WsError::InvalidClosePayload)?;
            }
            Ok(())
        }
    }
}

fn validate_close_payload_for_send(payload: &[u8]) -> Result<(), WsError> {
    validate_close_payload(payload, CloseCode::is_valid_code)
}

fn validate_close_payload_for_receive(payload: &[u8]) -> Result<(), WsError> {
    validate_close_payload(payload, CloseCode::is_valid_received_code)
}

/// Close codes defined by RFC 6455.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum CloseCode {
    /// Normal closure (1000).
    Normal = 1000,
    /// Going away (1001).
    GoingAway = 1001,
    /// Protocol error (1002).
    ProtocolError = 1002,
    /// Unsupported data type (1003).
    Unsupported = 1003,
    /// Reserved (1004).
    Reserved = 1004,
    /// No status received (1005) - must not be sent in a frame.
    NoStatusReceived = 1005,
    /// Abnormal closure (1006) - must not be sent in a frame.
    Abnormal = 1006,
    /// Invalid payload data (1007).
    InvalidPayload = 1007,
    /// Policy violation (1008).
    PolicyViolation = 1008,
    /// Message too big (1009).
    MessageTooBig = 1009,
    /// Mandatory extension missing (1010).
    MandatoryExtension = 1010,
    /// Internal server error (1011).
    InternalError = 1011,
    /// Service restart (1012) — IANA registered.
    ServiceRestart = 1012,
    /// Try again later (1013) — IANA registered.
    TryAgainLater = 1013,
    /// Bad gateway (1014) — IANA registered.
    BadGateway = 1014,
    /// TLS handshake failure (1015) - must not be sent in a frame.
    TlsHandshake = 1015,
}

impl CloseCode {
    /// Returns true if this code can be sent in a close frame.
    #[must_use]
    pub const fn is_sendable(self) -> bool {
        !matches!(
            self,
            Self::Reserved | Self::NoStatusReceived | Self::Abnormal | Self::TlsHandshake
        )
    }

    /// Parse a close code from a u16 value.
    ///
    /// Returns `None` for unknown codes in valid ranges (1000-4999).
    /// Custom codes (3000-3999, 4000-4999) are accepted.
    #[must_use]
    pub fn from_u16(code: u16) -> Option<Self> {
        match code {
            1000 => Some(Self::Normal),
            1001 => Some(Self::GoingAway),
            1002 => Some(Self::ProtocolError),
            1003 => Some(Self::Unsupported),
            1004 => Some(Self::Reserved),
            1005 => Some(Self::NoStatusReceived),
            1006 => Some(Self::Abnormal),
            1007 => Some(Self::InvalidPayload),
            1008 => Some(Self::PolicyViolation),
            1009 => Some(Self::MessageTooBig),
            1010 => Some(Self::MandatoryExtension),
            1011 => Some(Self::InternalError),
            1012 => Some(Self::ServiceRestart),
            1013 => Some(Self::TryAgainLater),
            1014 => Some(Self::BadGateway),
            1015 => Some(Self::TlsHandshake),
            _ => None,
        }
    }

    /// Check if a raw code value is valid for sending.
    ///
    /// Valid ranges per RFC 6455 + IANA registry:
    /// - 1000-1003, 1007-1014: Standard and IANA-registered codes
    /// - 3000-3999: Registered (IANA)
    /// - 4000-4999: Private use
    #[must_use]
    pub fn is_valid_code(code: u16) -> bool {
        matches!(code, 1000..=1003 | 1007..=1014 | 3000..=4999)
    }

    /// Check if a raw code value is valid when received from a peer.
    ///
    /// The receive side is more permissive than the send side per RFC 6455
    /// §7.4.2: codes 1016-2999 are reserved for future revisions and
    /// extensions, and a conforming endpoint must accept them even if it
    /// does not recognise the specific value.
    ///
    /// Codes that must never appear on the wire (1004-1006, 1015) and
    /// out-of-range values (0-999, 5000+) are still rejected.
    #[must_use]
    pub fn is_valid_received_code(code: u16) -> bool {
        matches!(code, 1000..=1003 | 1007..=1014 | 1016..=4999)
    }
}

impl From<CloseCode> for u16 {
    fn from(code: CloseCode) -> Self {
        code as Self
    }
}

#[cfg(test)]
#[path = "frame_inline_tests.rs"]
mod tests;
