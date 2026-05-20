//! ATP Binary Frame Definitions
//!
//! Defines the ATP frame format and frame types for the protocol.
//! All frames are length-bounded, versioned, and designed for deterministic replay.

use crate::net::atp::protocol::varint::{VarInt, VarIntError};
use std::collections::HashMap;
use std::fmt;

/// ATP Protocol Version
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
    Handshake = 0x0001,
    HandshakeAck = 0x0002,
    Capabilities = 0x0003,
    CapabilitiesAck = 0x0004,

    // Object transfer
    ObjectManifest = 0x0100,
    ObjectRequest = 0x0101,
    ObjectData = 0x0102,
    ObjectComplete = 0x0103,
    ObjectError = 0x0104,

    // Path and connection management
    PathUpdate = 0x0200,
    PathChallenge = 0x0201,
    PathResponse = 0x0202,
    KeepAlive = 0x0203,

    // Control frames
    Cancel = 0x0300,
    Error = 0x0301,
    Close = 0x0302,
}

impl FrameType {
    /// Convert to wire format (varint)
    pub fn to_varint(self) -> VarInt {
        VarInt::new(self as u64).expect("frame type fits in varint")
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
        Ok(FrameHeader {
            version,
            frame_type,
            payload_length: VarInt::new(payload_length)?,
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
        len += VarInt::new(self.version.0 as u64).unwrap().encoded_len();

        // Frame type (varint)
        len += self.frame_type.to_varint().encoded_len();

        // Payload length (varint)
        len += self.payload_length.encoded_len();

        // Extension count (varint)
        len += VarInt::new(self.extensions.len() as u64)
            .unwrap()
            .encoded_len();

        // Extensions (extension_id:varint + length:varint + data)
        for (_, data) in &self.extensions {
            len += VarInt::new(0).unwrap().encoded_len(); // extension_id as varint
            len += VarInt::new(data.len() as u64).unwrap().encoded_len(); // data length
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
}

/// Frame encoding and decoding errors
#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("varint encoding error: {0}")]
    VarInt(#[from] VarIntError),

    #[error("unknown frame type: {0}")]
    UnknownFrameType(u64),

    #[error("unsupported protocol version: {0}")]
    UnsupportedVersion(u32),

    #[error("frame too large: {size} bytes (max: {max})")]
    FrameTooLarge { size: u64, max: u64 },

    #[error("invalid frame format: {0}")]
    InvalidFormat(String),

    #[error("unexpected end of frame data")]
    UnexpectedEof,

    #[error("extension too large: {size} bytes")]
    ExtensionTooLarge { size: u64 },
}

/// Maximum frame size (1MB to prevent memory exhaustion)
pub const MAX_FRAME_SIZE: u64 = 1024 * 1024;

/// Maximum extension data size
pub const MAX_EXTENSION_SIZE: u64 = 4096;

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
    fn test_protocol_version_display() {
        assert_eq!(ProtocolVersion::V0.to_string(), "ATP/0");
        assert_eq!(ProtocolVersion(42).to_string(), "ATP/42");
    }
}
