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
use crate::util::check_ambient_entropy;
use std::io;

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
    #[must_use]
    pub fn ping(payload: impl Into<Bytes>) -> Self {
        Self {
            fin: true,
            rsv1: false,
            rsv2: false,
            rsv3: false,
            opcode: Opcode::Ping,
            masked: false,
            mask_key: None,
            payload: payload.into(),
        }
    }

    /// Create a pong frame with optional payload.
    #[must_use]
    pub fn pong(payload: impl Into<Bytes>) -> Self {
        Self {
            fin: true,
            rsv1: false,
            rsv2: false,
            rsv3: false,
            opcode: Opcode::Pong,
            masked: false,
            mask_key: None,
            payload: payload.into(),
        }
    }

    /// Create a close frame with optional status code and reason.
    #[must_use]
    pub fn close(code: Option<u16>, reason: Option<&str>) -> Self {
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
            _ => Bytes::new(),
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
}

impl Decoder for FrameCodec {
    type Item = Frame;
    type Error = WsError;

    #[allow(clippy::too_many_lines)] // Single, explicit RFC 6455 decode state machine.
    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        loop {
            match &self.state {
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
                    if self.validate_reserved_bits && (rsv1 || rsv2 || rsv3) {
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
                        if payload_len_7 > 125 {
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
                        u64::from(u16::from_be_bytes([bytes[0], bytes[1]]))
                    } else {
                        let bytes = src.split_to(8);
                        u64::from_be_bytes([
                            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6],
                            bytes[7],
                        ])
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
                    let payload_len_usize = *payload_len as usize;
                    if src.len() < payload_len_usize {
                        return Ok(None);
                    }

                    let mut payload = src.split_to(payload_len_usize);

                    // Apply masking if present
                    if let Some(key) = mask_key {
                        apply_mask(&mut payload, *key);
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
        let payload_len = frame.payload.len();

        // Control frame validation
        if frame.opcode.is_control() {
            if !frame.fin {
                return Err(WsError::FragmentedControlFrame);
            }
            if payload_len > 125 {
                return Err(WsError::ControlFrameTooLarge(payload_len));
            }
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

        if payload_len <= 125 {
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
            // Generate a mask key (for simplicity, use a simple pattern)
            // In production, this should use a cryptographic RNG
            let mask_key = generate_mask_key();
            dst.put_slice(&mask_key);

            // Apply mask to payload and write
            let mut masked_payload = BytesMut::from(frame.payload.as_ref());
            apply_mask(&mut masked_payload, mask_key);
            dst.put_slice(&masked_payload);
        } else {
            dst.put_slice(&frame.payload);
        }

        Ok(())
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
fn generate_mask_key() -> [u8; 4] {
    let mut key = [0u8; 4];
    check_ambient_entropy("websocket_mask");
    getrandom::fill(&mut key).expect("OS RNG unavailable");
    key
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
    /// TLS handshake failure (1015) - must not be sent in a frame.
    TlsHandshake = 1015,
}

impl CloseCode {
    /// Returns true if this code can be sent in a close frame.
    #[must_use]
    pub const fn is_sendable(self) -> bool {
        !matches!(
            self,
            Self::NoStatusReceived | Self::Abnormal | Self::TlsHandshake
        )
    }
}

impl From<CloseCode> for u16 {
    fn from(code: CloseCode) -> Self {
        code as Self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opcode_is_control() {
        assert!(!Opcode::Continuation.is_control());
        assert!(!Opcode::Text.is_control());
        assert!(!Opcode::Binary.is_control());
        assert!(Opcode::Close.is_control());
        assert!(Opcode::Ping.is_control());
        assert!(Opcode::Pong.is_control());
    }

    #[test]
    fn test_opcode_from_u8() {
        assert_eq!(Opcode::from_u8(0x0).unwrap(), Opcode::Continuation);
        assert_eq!(Opcode::from_u8(0x1).unwrap(), Opcode::Text);
        assert_eq!(Opcode::from_u8(0x2).unwrap(), Opcode::Binary);
        assert_eq!(Opcode::from_u8(0x8).unwrap(), Opcode::Close);
        assert_eq!(Opcode::from_u8(0x9).unwrap(), Opcode::Ping);
        assert_eq!(Opcode::from_u8(0xA).unwrap(), Opcode::Pong);
        assert!(Opcode::from_u8(0x3).is_err());
        assert!(Opcode::from_u8(0xF).is_err());
    }

    #[test]
    fn test_apply_mask() {
        let mask_key = [0x37, 0xfa, 0x21, 0x3d];
        let mut payload = b"Hello".to_vec();
        let original = payload.clone();

        apply_mask(&mut payload, mask_key);
        assert_ne!(payload, original);

        // Apply mask again to unmask
        apply_mask(&mut payload, mask_key);
        assert_eq!(payload, original);
    }

    #[test]
    fn test_encode_decode_text_frame() {
        let mut encoder = FrameCodec::client();
        let mut decoder = FrameCodec::server();
        let frame = Frame::text("Hello, WebSocket!");

        let mut buf = BytesMut::new();
        encoder.encode(frame, &mut buf).unwrap();

        // Decode the frame (server decodes client-masked frames)
        let parsed = decoder.decode(&mut buf).unwrap().unwrap();
        assert!(parsed.fin);
        assert_eq!(parsed.opcode, Opcode::Text);
        assert_eq!(parsed.payload.as_ref(), b"Hello, WebSocket!");
    }

    #[test]
    fn test_encode_decode_binary_frame() {
        let mut encoder = FrameCodec::client();
        let mut decoder = FrameCodec::server();
        let payload: Bytes = vec![0x00, 0x01, 0x02, 0xFF].into();
        let frame = Frame::binary(payload.clone());

        let mut buf = BytesMut::new();
        encoder.encode(frame, &mut buf).unwrap();

        let parsed = decoder.decode(&mut buf).unwrap().unwrap();
        assert!(parsed.fin);
        assert_eq!(parsed.opcode, Opcode::Binary);
        assert_eq!(parsed.payload, payload);
    }

    #[test]
    fn test_encode_decode_ping_pong() {
        let mut encoder = FrameCodec::client();
        let mut decoder = FrameCodec::server();

        // Ping
        let ping_request = Frame::ping("ping-data");
        let mut buf = BytesMut::new();
        encoder.encode(ping_request, &mut buf).unwrap();

        let ping_received = decoder.decode(&mut buf).unwrap().unwrap();
        assert!(ping_received.fin);
        assert_eq!(ping_received.opcode, Opcode::Ping);
        assert_eq!(ping_received.payload.as_ref(), b"ping-data");

        // Pong
        let pong_response = Frame::pong("pong-data");
        let mut buf = BytesMut::new();
        encoder.encode(pong_response, &mut buf).unwrap();

        let pong_response = decoder.decode(&mut buf).unwrap().unwrap();
        assert!(pong_response.fin);
        assert_eq!(pong_response.opcode, Opcode::Pong);
        assert_eq!(pong_response.payload.as_ref(), b"pong-data");
    }

    #[test]
    fn test_encode_decode_close_frame() {
        let mut encoder = FrameCodec::client();
        let mut decoder = FrameCodec::server();
        let close = Frame::close(Some(1000), Some("goodbye"));

        let mut buf = BytesMut::new();
        encoder.encode(close, &mut buf).unwrap();

        let close_frame = decoder.decode(&mut buf).unwrap().unwrap();
        assert!(close_frame.fin);
        assert_eq!(close_frame.opcode, Opcode::Close);

        // Parse close payload
        let payload = close_frame.payload;
        assert!(payload.len() >= 2);
        let code = u16::from_be_bytes([payload[0], payload[1]]);
        assert_eq!(code, 1000);
        let reason = std::str::from_utf8(&payload[2..]).unwrap();
        assert_eq!(reason, "goodbye");
    }

    #[test]
    fn test_payload_length_126() {
        let mut encoder = FrameCodec::client();
        let mut decoder = FrameCodec::server();
        let frame = Frame::binary(Bytes::from(vec![0u8; 200])); // > 125, uses 2-byte length

        let mut buf = BytesMut::new();
        encoder.encode(frame, &mut buf).unwrap();

        let parsed = decoder.decode(&mut buf).unwrap().unwrap();
        assert_eq!(parsed.payload.len(), 200);
    }

    #[test]
    fn test_payload_length_127() {
        let mut encoder = FrameCodec::client();
        let mut decoder = FrameCodec::server();
        let frame = Frame::binary(Bytes::from(vec![0u8; 70_000])); // > 65535, uses 8-byte length

        let mut buf = BytesMut::new();
        encoder.encode(frame, &mut buf).unwrap();

        let parsed = decoder.decode(&mut buf).unwrap().unwrap();
        assert_eq!(parsed.payload.len(), 70_000);
    }

    #[test]
    fn test_client_masking() {
        let mut client_codec = FrameCodec::client();
        let mut server_codec = FrameCodec::server();

        let frame = Frame::text("masked message");

        // Client encodes (with masking)
        let mut buf = BytesMut::new();
        client_codec.encode(frame, &mut buf).unwrap();

        // Check that the mask bit is set (second byte, high bit)
        assert!(buf[1] & 0x80 != 0);

        // Server decodes (unmasks)
        let parsed = server_codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(parsed.payload.as_ref(), b"masked message");
    }

    #[test]
    fn test_control_frame_too_large() {
        let mut codec = FrameCodec::server();
        let payload = Bytes::from(vec![0u8; 130]); // > 125 bytes
        let mut frame = Frame::ping(Bytes::new());
        frame.payload = payload;

        let mut buf = BytesMut::new();
        let result = codec.encode(frame, &mut buf);
        assert!(matches!(result, Err(WsError::ControlFrameTooLarge(_))));
    }

    #[test]
    fn test_fragmented_control_frame_rejected() {
        let mut codec = FrameCodec::server();
        let mut frame = Frame::ping("data");
        frame.fin = false; // Fragmented - invalid for control frames

        let mut buf = BytesMut::new();
        let result = codec.encode(frame, &mut buf);
        assert!(matches!(result, Err(WsError::FragmentedControlFrame)));
    }

    #[test]
    fn test_partial_frame_returns_none() {
        let mut encoder = FrameCodec::client();
        let mut decoder = FrameCodec::server();
        let frame = Frame::text("Hello");

        let mut buf = BytesMut::new();
        encoder.encode(frame, &mut buf).unwrap();

        // Only provide partial data
        let partial = buf.split_to(3);
        let mut partial = BytesMut::from(partial.as_ref());

        // Should return None (need more data)
        assert!(decoder.decode(&mut partial).unwrap().is_none());
    }

    #[test]
    fn test_empty_payload() {
        let mut encoder = FrameCodec::client();
        let mut decoder = FrameCodec::server();
        let frame = Frame::binary(Bytes::new());

        let mut buf = BytesMut::new();
        encoder.encode(frame, &mut buf).unwrap();

        let parsed = decoder.decode(&mut buf).unwrap().unwrap();
        assert!(parsed.payload.is_empty());
    }

    #[test]
    fn test_close_code_is_sendable() {
        assert!(CloseCode::Normal.is_sendable());
        assert!(CloseCode::GoingAway.is_sendable());
        assert!(CloseCode::ProtocolError.is_sendable());
        assert!(!CloseCode::NoStatusReceived.is_sendable());
        assert!(!CloseCode::Abnormal.is_sendable());
        assert!(!CloseCode::TlsHandshake.is_sendable());
    }

    #[test]
    fn test_invalid_opcode_from_u8() {
        // Reserved non-control opcodes.
        for &op in &[0x03, 0x04, 0x05, 0x06, 0x07] {
            let result = Opcode::from_u8(op);
            assert!(matches!(result, Err(WsError::InvalidOpcode(v)) if v == op));
        }
        // Reserved control opcodes.
        for &op in &[0x0B, 0x0C, 0x0D, 0x0E, 0x0F] {
            let result = Opcode::from_u8(op);
            assert!(matches!(result, Err(WsError::InvalidOpcode(v)) if v == op));
        }
    }

    #[test]
    fn test_opcode_is_data() {
        assert!(Opcode::Text.is_data());
        assert!(Opcode::Binary.is_data());
        assert!(Opcode::Continuation.is_data());
        assert!(!Opcode::Close.is_data());
        assert!(!Opcode::Ping.is_data());
        assert!(!Opcode::Pong.is_data());
    }

    #[test]
    fn test_close_frame_with_code_and_reason() {
        let frame = Frame::close(Some(1000), Some("goodbye"));
        assert_eq!(frame.opcode, Opcode::Close);
        assert!(frame.fin);
        // Payload: 2 bytes (u16 code) + "goodbye" (7 bytes) = 9
        assert_eq!(frame.payload.len(), 9);
        assert_eq!(&frame.payload[..2], &1000u16.to_be_bytes());
        assert_eq!(&frame.payload[2..], b"goodbye");
    }

    #[test]
    fn test_close_frame_code_only() {
        let frame = Frame::close(Some(1001), None);
        assert_eq!(frame.payload.len(), 2);
        assert_eq!(&frame.payload[..], &1001u16.to_be_bytes());
    }

    #[test]
    fn test_close_frame_no_payload() {
        let frame = Frame::close(None, None);
        assert!(frame.payload.is_empty());
    }

    #[test]
    fn test_ws_error_display_variants() {
        let err = WsError::InvalidOpcode(0x0F);
        assert!(err.to_string().contains("0xF"));

        let err = WsError::ReservedBitsSet;
        assert!(err.to_string().contains("reserved bits"));

        let err = WsError::PayloadTooLarge {
            size: 10_000,
            max: 1024,
        };
        assert!(err.to_string().contains("10000"));
        assert!(err.to_string().contains("1024"));

        let err = WsError::ControlFrameTooLarge(200);
        assert!(err.to_string().contains("200"));

        let err = WsError::FragmentedControlFrame;
        assert!(err.to_string().contains("fragmented"));

        let err = WsError::UnmaskedClientFrame;
        assert!(err.to_string().contains("masked"));

        let err = WsError::InvalidUtf8;
        assert!(err.to_string().contains("UTF-8"));

        let err = WsError::InvalidClosePayload;
        assert!(err.to_string().contains("close"));
    }

    #[test]
    fn test_roundtrip_server_to_client() {
        // Server sends unmasked; client decodes unmasked frames.
        let mut encoder = FrameCodec::server();
        let mut decoder = FrameCodec::client();
        let frame = Frame::text("server says hi");

        let mut buf = BytesMut::new();
        encoder.encode(frame, &mut buf).unwrap();

        let parsed = decoder.decode(&mut buf).unwrap().unwrap();
        assert_eq!(parsed.opcode, Opcode::Text);
        assert!(!parsed.masked);
        assert_eq!(parsed.payload.as_ref(), b"server says hi");
    }
}
