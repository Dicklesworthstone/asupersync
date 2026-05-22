//! ATP Binary Frame Definitions
//!
//! Defines the ATP frame format and frame types for the protocol.
//! All frames are length-bounded, versioned, and designed for deterministic replay.

use crate::bytes::BytesMut;
use crate::codec::Encoder;
use crate::net::atp::protocol::codec::AtpFrameCodec;
use crate::net::atp::protocol::varint::{VarInt, VarIntError};
use crate::types::outcome::Outcome;
use std::collections::HashMap;
use std::fmt;

/// ATP Protocol Version
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProtocolVersion(pub u32);

impl ProtocolVersion {
    /// ATP Protocol Version 0 (initial implementation)
    pub const V0: Self = ProtocolVersion(0);

    /// Current protocol version
    pub const CURRENT: Self = Self::V0;
}

impl fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ATP/{}", self.0)
    }
}

/// Unique frame type identifiers for ATP v0 frames
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum FrameType {
    // Session establishment
    /// Client-side session hello.
    Handshake = 0x0001,
    /// Server-side session hello acknowledgement.
    HandshakeAck = 0x0002,
    /// Capability and feature advertisement.
    Capabilities = 0x0003,
    /// Capability and feature acknowledgement.
    CapabilitiesAck = 0x0004,

    // Object transfer
    /// Object manifest payload.
    ObjectManifest = 0x0100,
    /// Object chunk/range request.
    ObjectRequest = 0x0101,
    /// Object data payload.
    ObjectData = 0x0102,
    /// Object completion marker.
    ObjectComplete = 0x0103,
    /// Object transfer error.
    ObjectError = 0x0104,

    // Path and connection management
    /// Path graph update payload.
    PathUpdate = 0x0200,
    /// Path validation challenge.
    PathChallenge = 0x0201,
    /// Path validation response.
    PathResponse = 0x0202,
    /// Keep-alive frame.
    KeepAlive = 0x0203,

    // Control frames
    /// Cancel an in-flight operation.
    Cancel = 0x0300,
    /// Protocol error frame.
    Error = 0x0301,
    /// Graceful close frame.
    Close = 0x0302,

    // H3/WebTransport adapter categories.
    /// Generic control category for adapter-level mapping.
    Control = 0x0400,
    /// Generic data category for adapter-level mapping.
    Data = 0x0401,
    /// Generic proof category for adapter-level mapping.
    Proof = 0x0402,
    /// Generic repair category for adapter-level mapping.
    Repair = 0x0403,
    /// Generic session category for adapter-level mapping.
    Session = 0x0404,
    /// Generic manifest category for adapter-level mapping.
    Manifest = 0x0405,
}

impl FrameType {
    /// Convert to wire format (varint)
    pub fn to_varint(self) -> VarInt {
        match VarInt::new(self as u64) {
            Outcome::Ok(varint) => varint,
            _ => panic!("frame type fits in varint"),
        }
    }

    /// Parse from wire format
    pub fn from_varint(varint: VarInt) -> Result<Self, FrameError> {
        match varint.value() {
            0x0001 => Ok(FrameType::Handshake),
            0x0002 => Ok(FrameType::HandshakeAck),
            0x0003 => Ok(FrameType::Capabilities),
            0x0004 => Ok(FrameType::CapabilitiesAck),
            0x0100 => Ok(FrameType::ObjectManifest),
            0x0101 => Ok(FrameType::ObjectRequest),
            0x0102 => Ok(FrameType::ObjectData),
            0x0103 => Ok(FrameType::ObjectComplete),
            0x0104 => Ok(FrameType::ObjectError),
            0x0200 => Ok(FrameType::PathUpdate),
            0x0201 => Ok(FrameType::PathChallenge),
            0x0202 => Ok(FrameType::PathResponse),
            0x0203 => Ok(FrameType::KeepAlive),
            0x0300 => Ok(FrameType::Cancel),
            0x0301 => Ok(FrameType::Error),
            0x0302 => Ok(FrameType::Close),
            0x0400 => Ok(FrameType::Control),
            0x0401 => Ok(FrameType::Data),
            0x0402 => Ok(FrameType::Proof),
            0x0403 => Ok(FrameType::Repair),
            0x0404 => Ok(FrameType::Session),
            0x0405 => Ok(FrameType::Manifest),
            other => Err(FrameError::UnknownFrameType(other)),
        }
    }
}

/// ATP Frame header with version, type, and length
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameHeader {
    /// Protocol version
    pub version: ProtocolVersion,
    /// Frame type
    pub frame_type: FrameType,
    /// Payload length in bytes
    pub payload_length: VarInt,
    /// Optional extension fields (for future use)
    pub extensions: HashMap<u16, Vec<u8>>,
}

impl FrameHeader {
    /// Create a new frame header
    pub fn new(
        version: ProtocolVersion,
        frame_type: FrameType,
        payload_length: u64,
    ) -> Result<Self, FrameError> {
        let payload_varint = match VarInt::new(payload_length) {
            Outcome::Ok(varint) => varint,
            _ => {
                return Err(FrameError::InvalidFormat(
                    "Invalid payload length".to_string(),
                ));
            }
        };

        Ok(FrameHeader {
            version,
            frame_type,
            payload_length: payload_varint,
            extensions: HashMap::new(),
        })
    }

    /// Add an extension field
    pub fn with_extension(mut self, extension_id: u16, data: Vec<u8>) -> Self {
        self.extensions.insert(extension_id, data);
        self
    }

    /// Calculate the encoded size of this header
    pub fn encoded_len(&self) -> usize {
        let mut len = 0;

        // Version (varint)
        len += match VarInt::new(self.version.0 as u64) {
            Outcome::Ok(varint) => varint.encoded_len(),
            _ => panic!("version fits in varint"),
        };

        // Frame type (varint)
        len += self.frame_type.to_varint().encoded_len();

        // Payload length (varint)
        len += self.payload_length.encoded_len();

        // Extension count (varint)
        len += VarInt::new(self.extensions.len() as u64)
            .unwrap()
            .encoded_len();

        // Extensions (extension_id:varint + length:varint + data)
        for (extension_id, data) in &self.extensions {
            len += match VarInt::new(*extension_id as u64) {
                Outcome::Ok(varint) => varint.encoded_len(),
                _ => panic!("u16 extension id fits in varint"),
            };
            len += match VarInt::new(data.len() as u64) {
                Outcome::Ok(varint) => varint.encoded_len(),
                _ => panic!("data length fits in varint"),
            };
            len += data.len(); // data
        }

        len
    }
}

/// Complete ATP Frame (header + payload)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// Frame header
    pub header: FrameHeader,
    /// Frame payload
    pub payload: Vec<u8>,
}

impl Frame {
    /// Create a new frame
    pub fn new(
        version: ProtocolVersion,
        frame_type: FrameType,
        payload: Vec<u8>,
    ) -> Result<Self, FrameError> {
        let header = FrameHeader::new(version, frame_type, payload.len() as u64)?;
        Ok(Frame { header, payload })
    }

    /// Total encoded size of frame (header + payload)
    pub fn encoded_len(&self) -> usize {
        self.header.encoded_len() + self.payload.len()
    }

    /// Get frame type
    pub fn frame_type(&self) -> FrameType {
        self.header.frame_type
    }

    /// Get protocol version
    pub fn version(&self) -> ProtocolVersion {
        self.header.version
    }

    /// Get payload as slice
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Create an empty frame for adapter-level control paths.
    pub fn empty(frame_type: FrameType) -> Result<Self, FrameError> {
        Self::new(ProtocolVersion::CURRENT, frame_type, Vec::new())
    }

    /// Encode this frame with the canonical ATP binary frame codec.
    pub fn to_wire_bytes(&self) -> Result<Vec<u8>, FrameError> {
        let mut codec = AtpFrameCodec::new();
        let mut encoded = BytesMut::with_capacity(self.encoded_len());
        codec.encode(self.clone(), &mut encoded)?;
        Ok(encoded.to_vec())
    }
}

/// Frame encoding and decoding errors
#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    /// Varint encoding or decoding error.
    #[error("varint encoding error: {0}")]
    VarInt(#[from] VarIntError),

    /// Frame type is unknown to this protocol version.
    #[error("unknown frame type: {0}")]
    UnknownFrameType(u64),

    /// Protocol version is unsupported.
    #[error("unsupported protocol version: {0}")]
    UnsupportedVersion(u32),

    /// Frame exceeds the configured maximum.
    #[error("frame too large: {size} bytes (max: {max})")]
    FrameTooLarge {
        /// Observed frame size.
        size: u64,
        /// Configured frame-size limit.
        max: u64,
    },

    /// Frame payload or header had invalid structure.
    #[error("invalid frame format: {0}")]
    InvalidFormat(String),

    /// Frame data ended before the expected boundary.
    #[error("unexpected end of frame data")]
    UnexpectedEof,

    /// Extension payload exceeds the extension-size limit.
    #[error("extension too large: {size} bytes")]
    ExtensionTooLarge {
        /// Observed extension payload size.
        size: u64,
    },
}

/// Maximum frame size (1MB to prevent memory exhaustion)
pub const MAX_FRAME_SIZE: u64 = 1024 * 1024;

/// Maximum extension data size
pub const MAX_EXTENSION_SIZE: u64 = 4096;

/// Maximum number of frame header extensions (prevent DoS)
pub const MAX_EXTENSION_COUNT: u64 = 64;

/// Maximum total header size including all extensions (prevent DoS)
pub const MAX_HEADER_SIZE: u64 = 32 * 1024;

impl From<std::io::Error> for FrameError {
    fn from(err: std::io::Error) -> Self {
        FrameError::InvalidFormat(format!("I/O error: {err}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_type_roundtrip() {
        let frame_types = [
            FrameType::Handshake,
            FrameType::HandshakeAck,
            FrameType::Capabilities,
            FrameType::ObjectManifest,
            FrameType::ObjectData,
            FrameType::PathUpdate,
            FrameType::Cancel,
            FrameType::Error,
            FrameType::Close,
        ];

        for frame_type in frame_types {
            let varint = frame_type.to_varint();
            let parsed = FrameType::from_varint(varint).unwrap();
            assert_eq!(parsed, frame_type);
        }
    }

    #[test]
    fn test_frame_creation() {
        let payload = b"Hello, ATP!".to_vec();
        let frame = Frame::new(ProtocolVersion::V0, FrameType::Handshake, payload.clone()).unwrap();

        assert_eq!(frame.version(), ProtocolVersion::V0);
        assert_eq!(frame.frame_type(), FrameType::Handshake);
        assert_eq!(frame.payload(), payload);
    }

    #[test]
    fn test_frame_header_with_extensions() {
        let header = FrameHeader::new(ProtocolVersion::V0, FrameType::Capabilities, 100)
            .unwrap()
            .with_extension(1, b"ext1".to_vec())
            .with_extension(2, b"extension2".to_vec());

        assert_eq!(header.extensions.len(), 2);
        assert_eq!(header.extensions[&1], b"ext1");
        assert_eq!(header.extensions[&2], b"extension2");
    }

    #[test]
    fn frame_empty_uses_protocol_wire_bytes_not_marker_payloads() {
        let frame = Frame::empty(FrameType::Control).unwrap();

        assert_eq!(frame.payload(), b"");

        assert_eq!(
            frame.to_wire_bytes().unwrap(),
            vec![0x00, 0x44, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn test_protocol_version_display() {
        assert_eq!(ProtocolVersion::V0.to_string(), "ATP/0");
        assert_eq!(ProtocolVersion(42).to_string(), "ATP/42");
    }
}
