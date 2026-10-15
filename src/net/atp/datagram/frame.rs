//! QUIC DATAGRAM Frame Implementation (RFC 9221)

use crate::bytes::{Bytes, BytesMut};
use crate::net::atp::protocol::varint::{VARINT_MAX, VarInt};
use crate::types::outcome::Outcome;
use std::fmt;

/// DATAGRAM frame type constants (RFC 9221)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum DatagramFrameType {
    /// DATAGRAM frame without length field
    Datagram = 0x30,
    /// DATAGRAM frame with length field
    DatagramWithLength = 0x31,
}

impl DatagramFrameType {
    /// Convert to varint for wire encoding
    pub fn to_varint(self) -> VarInt {
        VarInt::from_u64_unchecked(self as u64)
    }

    /// Parse from varint
    pub fn from_varint(varint: VarInt) -> Option<Self> {
        match varint.value() {
            0x30 => Some(Self::Datagram),
            0x31 => Some(Self::DatagramWithLength),
            _ => None,
        }
    }
}

/// DATAGRAM frame payload
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatagramFrame {
    /// Frame type (with or without length)
    pub frame_type: DatagramFrameType,
    /// Datagram data payload
    pub data: Bytes,
}

impl DatagramFrame {
    /// Create a new DATAGRAM frame
    pub fn new(data: Bytes, include_length: bool) -> Self {
        let frame_type = if include_length {
            DatagramFrameType::DatagramWithLength
        } else {
            DatagramFrameType::Datagram
        };

        Self { frame_type, data }
    }

    /// Create DATAGRAM frame without length field (use when frame fills packet)
    pub fn without_length(data: Bytes) -> Self {
        Self::new(data, false)
    }

    /// Create DATAGRAM frame with length field (use when multiple frames in packet)
    pub fn with_length(data: Bytes) -> Self {
        Self::new(data, true)
    }

    /// Get payload data
    pub fn payload(&self) -> &Bytes {
        &self.data
    }

    /// Get payload length
    pub fn payload_len(&self) -> usize {
        self.data.len()
    }

    /// Check if frame includes length field
    pub fn has_length_field(&self) -> bool {
        matches!(self.frame_type, DatagramFrameType::DatagramWithLength)
    }

    /// Encode frame to wire format
    pub fn encode(&self, buf: &mut BytesMut) -> Outcome<(), DatagramError> {
        // Frame type
        match self.frame_type.to_varint().encode(buf) {
            Outcome::Ok(()) => {}
            Outcome::Err(_) => {
                return Outcome::err(DatagramError::EncodingFailed("frame type".to_string()));
            }
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        }

        // Length field (only for DatagramWithLength)
        if self.has_length_field() {
            let length = match VarInt::new(self.data.len() as u64) {
                Outcome::Ok(len) => len,
                Outcome::Err(_) => {
                    return Outcome::err(DatagramError::PayloadTooLarge {
                        size: self.data.len(),
                        max: VARINT_MAX as usize,
                    });
                }
                Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
                Outcome::Panicked(payload) => return Outcome::Panicked(payload),
            };
            match length.encode(buf) {
                Outcome::Ok(()) => {}
                Outcome::Err(_) => {
                    return Outcome::err(DatagramError::EncodingFailed("length".to_string()));
                }
                Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
                Outcome::Panicked(payload) => return Outcome::Panicked(payload),
            }
        }

        // Payload data
        buf.put_slice(&self.data);

        Outcome::ok(())
    }

    /// Decode frame from wire format
    pub fn decode(buf: &mut BytesMut, max_size: usize) -> Outcome<Self, DatagramError> {
        if buf.is_empty() {
            return Outcome::err(DatagramError::InvalidFrame("empty buffer".to_string()));
        }

        // Parse frame type
        let frame_type_varint = match VarInt::decode(buf) {
            Outcome::Ok(Some(varint)) => varint,
            Outcome::Ok(None) => {
                return Outcome::err(DatagramError::InvalidFrame(
                    "truncated frame type".to_string(),
                ));
            }
            Outcome::Err(_) => {
                return Outcome::err(DatagramError::InvalidFrame("frame type".to_string()));
            }
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        };

        let frame_type = match DatagramFrameType::from_varint(frame_type_varint) {
            Some(ft) => ft,
            None => {
                return Outcome::err(DatagramError::InvalidFrame(
                    "unknown frame type".to_string(),
                ));
            }
        };

        let data = match frame_type {
            DatagramFrameType::Datagram => {
                // No length field - consume rest of buffer
                let payload = buf.split_to(buf.len()).freeze();
                if payload.len() > max_size {
                    return Outcome::err(DatagramError::PayloadTooLarge {
                        size: payload.len(),
                        max: max_size,
                    });
                }
                payload
            }
            DatagramFrameType::DatagramWithLength => {
                // Parse length field
                let length_varint = match VarInt::decode(buf) {
                    Outcome::Ok(Some(varint)) => varint,
                    Outcome::Ok(None) => {
                        return Outcome::err(DatagramError::InvalidFrame(
                            "truncated length".to_string(),
                        ));
                    }
                    Outcome::Err(_) => {
                        return Outcome::err(DatagramError::InvalidFrame(
                            "length field".to_string(),
                        ));
                    }
                    Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
                    Outcome::Panicked(payload) => return Outcome::Panicked(payload),
                };

                let length = length_varint.value() as usize;
                if length > max_size {
                    return Outcome::err(DatagramError::PayloadTooLarge {
                        size: length,
                        max: max_size,
                    });
                }

                if buf.len() < length {
                    return Outcome::err(DatagramError::InvalidFrame(
                        "truncated payload".to_string(),
                    ));
                }

                buf.split_to(length).freeze()
            }
        };

        Outcome::ok(Self { frame_type, data })
    }

    /// Calculate encoded frame size
    pub fn encoded_size(&self) -> usize {
        let mut size = 0;

        // Frame type (always 1 byte for DATAGRAM types)
        size += 1;

        // Length field (if present)
        if self.has_length_field() {
            let length_varint = VarInt::from_u64_unchecked(self.data.len() as u64);
            size += length_varint.encoded_len();
        }

        // Payload
        size += self.data.len();

        size
    }
}

/// DATAGRAM frame errors
#[derive(Debug, Clone, thiserror::Error)]
pub enum DatagramError {
    /// Payload exceeds maximum allowed size
    #[error("datagram payload too large: {size} bytes (max: {max})")]
    PayloadTooLarge { size: usize, max: usize },

    /// Frame encoding failed
    #[error("datagram encoding failed: {0}")]
    EncodingFailed(String),

    /// Invalid frame format
    #[error("invalid datagram frame: {0}")]
    InvalidFrame(String),

    /// DATAGRAM not supported by peer
    #[error("datagram not supported by peer")]
    NotSupported,

    /// Congestion control dropped datagram
    #[error("datagram dropped due to congestion")]
    CongestionDrop,

    /// Datagram expired before transmission
    #[error("datagram expired before transmission")]
    Expired,

    /// Path not available for datagram
    #[error("path not available for datagram transmission")]
    PathUnavailable,
}

/// Datagram priority for congestion control
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DatagramPriority {
    /// High priority - path probes, critical beacons
    High = 3,
    /// Normal priority - regular beacons, telemetry
    #[default]
    Normal = 2,
    /// Low priority - optional diagnostics
    Low = 1,
    /// Background priority - best effort only
    Background = 0,
}

impl fmt::Display for DatagramPriority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::High => write!(f, "high"),
            Self::Normal => write!(f, "normal"),
            Self::Low => write!(f, "low"),
            Self::Background => write!(f, "background"),
        }
    }
}

/// Datagram metadata for tracking and congestion control
#[derive(Debug, Clone)]
pub struct DatagramMetadata {
    /// Priority for congestion control decisions
    pub priority: DatagramPriority,
    /// Optional correlation ID for probe/beacon tracking
    pub correlation_id: Option<u64>,
    /// Path ID for multi-path scenarios
    pub path_id: Option<u64>,
    /// Expiration time for time-sensitive data
    pub expires_at: Option<std::time::Instant>,
    /// Payload classification for logging (redacted)
    pub payload_class: String,
}

impl DatagramMetadata {
    /// Create new metadata with default values
    pub fn new(payload_class: impl Into<String>) -> Self {
        Self {
            priority: DatagramPriority::default(),
            correlation_id: None,
            path_id: None,
            expires_at: None,
            payload_class: payload_class.into(),
        }
    }

    /// Set priority
    pub fn with_priority(mut self, priority: DatagramPriority) -> Self {
        self.priority = priority;
        self
    }

    /// Set correlation ID
    pub fn with_correlation_id(mut self, id: u64) -> Self {
        self.correlation_id = Some(id);
        self
    }

    /// Set path ID
    pub fn with_path_id(mut self, id: u64) -> Self {
        self.path_id = Some(id);
        self
    }

    /// Set expiration time
    pub fn with_expiration(mut self, expires_at: std::time::Instant) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// Check if datagram has expired
    pub fn is_expired(&self) -> bool {
        self.expires_at
            .is_some_and(|expires| std::time::Instant::now() > expires)
    }
}

impl Default for DatagramMetadata {
    fn default() -> Self {
        Self::new("unknown")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_datagram_frame_without_length() {
        let payload = Bytes::from_static(b"hello datagram");
        let frame = DatagramFrame::without_length(payload.clone());

        assert_eq!(frame.frame_type, DatagramFrameType::Datagram);
        assert_eq!(frame.payload(), &payload);
        assert!(!frame.has_length_field());

        let mut buf = BytesMut::new();
        frame.encode(&mut buf).unwrap();

        let mut decode_buf = buf.clone();
        let decoded = DatagramFrame::decode(&mut decode_buf, 1024).unwrap();

        assert_eq!(decoded.frame_type, DatagramFrameType::Datagram);
        assert_eq!(decoded.payload(), &payload);
    }

    #[test]
    fn test_datagram_frame_with_length() {
        let payload = Bytes::from_static(b"hello datagram with length");
        let frame = DatagramFrame::with_length(payload.clone());

        assert_eq!(frame.frame_type, DatagramFrameType::DatagramWithLength);
        assert_eq!(frame.payload(), &payload);
        assert!(frame.has_length_field());

        let mut buf = BytesMut::new();
        frame.encode(&mut buf).unwrap();

        let mut decode_buf = buf.clone();
        let decoded = DatagramFrame::decode(&mut decode_buf, 1024).unwrap();

        assert_eq!(decoded.frame_type, DatagramFrameType::DatagramWithLength);
        assert_eq!(decoded.payload(), &payload);
    }

    #[test]
    fn test_datagram_size_limits() {
        let large_payload = Bytes::from(vec![0u8; 2048]);
        let frame = DatagramFrame::with_length(large_payload);

        let mut buf = BytesMut::new();
        frame.encode(&mut buf).unwrap();

        let mut decode_buf = buf;
        let result = DatagramFrame::decode(&mut decode_buf, 1024);

        assert!(matches!(
            result,
            Outcome::Err(DatagramError::PayloadTooLarge { .. })
        ));
    }

    #[test]
    fn test_datagram_metadata() {
        let mut metadata = DatagramMetadata::new("path_probe")
            .with_priority(DatagramPriority::High)
            .with_correlation_id(42)
            .with_path_id(1);

        assert_eq!(metadata.priority, DatagramPriority::High);
        assert_eq!(metadata.correlation_id, Some(42));
        assert_eq!(metadata.path_id, Some(1));
        assert_eq!(metadata.payload_class, "path_probe");

        // Test expiration
        assert!(!metadata.is_expired());

        metadata = metadata.with_expiration(
            std::time::Instant::now()
                .checked_sub(std::time::Duration::from_secs(1))
                .expect("test instant should support one-second subtraction"),
        );
        assert!(metadata.is_expired());
    }

    #[test]
    fn test_frame_type_conversion() {
        let datagram = DatagramFrameType::Datagram;
        let datagram_with_length = DatagramFrameType::DatagramWithLength;

        assert_eq!(
            DatagramFrameType::from_varint(datagram.to_varint()),
            Some(datagram)
        );
        assert_eq!(
            DatagramFrameType::from_varint(datagram_with_length.to_varint()),
            Some(datagram_with_length)
        );
        assert_eq!(
            DatagramFrameType::from_varint(VarInt::new(0x99).unwrap()),
            None
        );
    }

    #[test]
    fn test_invalid_frame_decode() {
        // Empty buffer
        let mut empty_buf = BytesMut::new();
        let result = DatagramFrame::decode(&mut empty_buf, 1024);
        assert!(matches!(
            result,
            Outcome::Err(DatagramError::InvalidFrame(_))
        ));

        // Unknown frame type
        let mut bad_type_buf = BytesMut::new();
        VarInt::new(0x99)
            .unwrap()
            .encode(&mut bad_type_buf)
            .unwrap();
        let result = DatagramFrame::decode(&mut bad_type_buf, 1024);
        assert!(matches!(
            result,
            Outcome::Err(DatagramError::InvalidFrame(_))
        ));

        // Truncated length field
        let mut truncated_buf = BytesMut::new();
        VarInt::new(0x31)
            .unwrap()
            .encode(&mut truncated_buf)
            .unwrap(); // DatagramWithLength
        let result = DatagramFrame::decode(&mut truncated_buf, 1024);
        assert!(matches!(
            result,
            Outcome::Err(DatagramError::InvalidFrame(_))
        ));
    }

    #[test]
    fn test_priority_ordering() {
        assert!(DatagramPriority::High > DatagramPriority::Normal);
        assert!(DatagramPriority::Normal > DatagramPriority::Low);
        assert!(DatagramPriority::Low > DatagramPriority::Background);
    }
}
