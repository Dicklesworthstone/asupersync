//! H3 frame codec for ATP-over-WebTransport.

use super::{AtpH3Error, AtpH3Result};
use crate::bytes::BytesMut;
use crate::codec::{Decoder, Encoder};
use crate::net::atp::protocol::{AtpFrame, AtpFrameCodec, FrameType};

/// WebTransport frame type identifiers for ATP frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebTransportFrameType {
    /// ATP Control frame (0x01).
    Control = 0x01,
    /// ATP Data frame (0x02).
    Data = 0x02,
    /// ATP Proof frame (0x03).
    Proof = 0x03,
    /// ATP Repair frame (0x04).
    Repair = 0x04,
    /// ATP Session frame (0x05).
    Session = 0x05,
    /// ATP Manifest frame (0x06).
    Manifest = 0x06,
}

impl WebTransportFrameType {
    /// Convert from ATP FrameType to WebTransport frame type.
    pub fn from_atp_frame_type(frame_type: FrameType) -> AtpH3Result<Self> {
        match frame_type {
            FrameType::Control => Ok(Self::Control),
            FrameType::Data => Ok(Self::Data),
            FrameType::Proof => Ok(Self::Proof),
            FrameType::Repair => Ok(Self::Repair),
            FrameType::Session => Ok(Self::Session),
            FrameType::Manifest => Ok(Self::Manifest),
            _ => Err(AtpH3Error::UnsupportedFeature(format!(
                "ATP frame type {:?} cannot be mapped to WebTransport",
                frame_type
            ))),
        }
    }

    /// Convert to ATP FrameType.
    pub fn to_atp_frame_type(self) -> FrameType {
        match self {
            Self::Control => FrameType::Control,
            Self::Data => FrameType::Data,
            Self::Proof => FrameType::Proof,
            Self::Repair => FrameType::Repair,
            Self::Session => FrameType::Session,
            Self::Manifest => FrameType::Manifest,
        }
    }
}

/// H3 frame codec for ATP-over-WebTransport.
#[derive(Debug)]
pub struct H3FrameCodec {
    /// Maximum frame size for encoding.
    max_frame_size: usize,
}

impl H3FrameCodec {
    /// Create a new H3 frame codec.
    pub fn new() -> Self {
        Self {
            max_frame_size: 64 * 1024, // 64KB default limit
        }
    }

    /// Create a new H3 frame codec with custom max frame size.
    pub fn with_max_frame_size(max_frame_size: usize) -> Self {
        Self { max_frame_size }
    }

    /// Encode an ATP frame for WebTransport transmission.
    ///
    /// Frame format:
    /// ```text
    /// +---+---+---+---+---+---+---+---+
    /// | Frame Type (1) | Length (4)    |
    /// +---+---+---+---+---+---+---+---+
    /// | ATP Frame Payload (Length)    |
    /// +---+---+---+---+---+---+---+---+
    /// ```
    pub fn encode_atp_frame(&self, frame: &AtpFrame) -> AtpH3Result<Vec<u8>> {
        let wt_frame_type = WebTransportFrameType::from_atp_frame_type(frame.frame_type())?;

        // Serialize the ATP frame to bytes
        let atp_payload = self.serialize_atp_frame(frame)?;

        if atp_payload.len() > self.max_frame_size {
            return Err(AtpH3Error::Codec(format!(
                "Frame size {} exceeds maximum {}",
                atp_payload.len(),
                self.max_frame_size
            )));
        }

        let mut encoded = Vec::with_capacity(5 + atp_payload.len());

        // Write frame type (1 byte)
        encoded.push(wt_frame_type as u8);

        // Write length (4 bytes, big-endian)
        let len_bytes = (atp_payload.len() as u32).to_be_bytes();
        encoded.extend_from_slice(&len_bytes);

        // Write ATP frame payload
        encoded.extend_from_slice(&atp_payload);

        Ok(encoded)
    }

    /// Decode WebTransport data to an ATP frame.
    pub fn decode_atp_frame(&self, data: &[u8]) -> AtpH3Result<AtpFrame> {
        if data.len() < 5 {
            return Err(AtpH3Error::Codec(
                "Frame too short: missing header".to_string(),
            ));
        }

        // Read frame type
        let wt_frame_type = data[0];
        let wt_frame_type = match wt_frame_type {
            0x01 => WebTransportFrameType::Control,
            0x02 => WebTransportFrameType::Data,
            0x03 => WebTransportFrameType::Proof,
            0x04 => WebTransportFrameType::Repair,
            0x05 => WebTransportFrameType::Session,
            0x06 => WebTransportFrameType::Manifest,
            _ => {
                return Err(AtpH3Error::Codec(format!(
                    "Unknown WebTransport frame type: 0x{:02x}",
                    wt_frame_type
                )));
            }
        };

        // Read length
        let length_bytes = &data[1..5];
        let length = u32::from_be_bytes([
            length_bytes[0],
            length_bytes[1],
            length_bytes[2],
            length_bytes[3],
        ]) as usize;

        if data.len() < 5 + length {
            return Err(AtpH3Error::Codec(format!(
                "Frame truncated: expected {} bytes, got {}",
                5 + length,
                data.len()
            )));
        }

        if length > self.max_frame_size {
            return Err(AtpH3Error::Codec(format!(
                "Frame too large: {} bytes exceeds maximum {}",
                length, self.max_frame_size
            )));
        }

        // Extract ATP frame payload
        let atp_payload = &data[5..5 + length];

        // Deserialize ATP frame
        self.deserialize_atp_frame(atp_payload, wt_frame_type.to_atp_frame_type())
    }

    /// Serialize an ATP frame to canonical ATP binary bytes.
    fn serialize_atp_frame(&self, frame: &AtpFrame) -> AtpH3Result<Vec<u8>> {
        let mut codec = AtpFrameCodec::new();
        let mut encoded = BytesMut::with_capacity(frame.encoded_len());
        codec
            .encode(frame.clone(), &mut encoded)
            .map_err(|err| AtpH3Error::Codec(format!("ATP frame encode failed: {err}")))?;
        Ok(encoded.to_vec())
    }

    /// Deserialize canonical ATP binary bytes to an ATP frame.
    fn deserialize_atp_frame(
        &self,
        payload: &[u8],
        frame_type: FrameType,
    ) -> AtpH3Result<AtpFrame> {
        let mut codec = AtpFrameCodec::new();
        let mut bytes = BytesMut::from(payload);
        let frame = codec
            .decode(&mut bytes)
            .map_err(|err| AtpH3Error::Codec(format!("ATP frame decode failed: {err}")))?
            .ok_or_else(|| AtpH3Error::Codec("ATP frame payload is incomplete".to_string()))?;

        if !bytes.is_empty() {
            return Err(AtpH3Error::Codec(format!(
                "ATP frame payload has {} trailing bytes",
                bytes.len()
            )));
        }

        if frame.frame_type() != frame_type {
            return Err(AtpH3Error::Codec(format!(
                "WebTransport frame type {:?} does not match ATP frame type {:?}",
                frame_type,
                frame.frame_type()
            )));
        }

        Ok(frame)
    }

    /// Get the maximum frame size.
    pub fn max_frame_size(&self) -> usize {
        self.max_frame_size
    }

    /// Set the maximum frame size.
    pub fn set_max_frame_size(&mut self, max_size: usize) {
        self.max_frame_size = max_size;
    }
}

impl Default for H3FrameCodec {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::atp::protocol::ProtocolVersion;

    #[test]
    fn test_webtransport_frame_type_conversion() {
        assert_eq!(
            WebTransportFrameType::from_atp_frame_type(FrameType::Control).unwrap(),
            WebTransportFrameType::Control
        );

        assert_eq!(
            WebTransportFrameType::Data.to_atp_frame_type(),
            FrameType::Data
        );
    }

    #[test]
    fn test_codec_creation() {
        let codec = H3FrameCodec::new();
        assert_eq!(codec.max_frame_size(), 64 * 1024);

        let codec = H3FrameCodec::with_max_frame_size(1024);
        assert_eq!(codec.max_frame_size(), 1024);
    }

    #[test]
    fn test_frame_encode_decode_roundtrip() {
        let codec = H3FrameCodec::new();

        let frame = AtpFrame::new(
            ProtocolVersion::CURRENT,
            FrameType::Control,
            b"control payload".to_vec(),
        )
        .unwrap();
        let encoded = codec.encode_atp_frame(&frame).unwrap();

        // Verify frame structure: type + length + payload
        assert!(encoded.len() >= 5);
        assert_eq!(encoded[0], WebTransportFrameType::Control as u8);

        // Test decoding
        let decoded = codec.decode_atp_frame(&encoded).unwrap();
        assert_eq!(decoded.frame_type(), FrameType::Control);
        assert_eq!(decoded.payload(), b"control payload");
    }

    #[test]
    fn test_frame_size_limits() {
        let mut codec = H3FrameCodec::with_max_frame_size(100);

        // Frame that would exceed limit should fail
        codec.set_max_frame_size(5); // Very small limit

        let frame = AtpFrame::new(
            ProtocolVersion::CURRENT,
            FrameType::Data,
            b"payload-too-large-for-limit".to_vec(),
        )
        .unwrap();
        let result = codec.encode_atp_frame(&frame);
        assert!(result.is_err());

        if let Err(AtpH3Error::Codec(msg)) = result {
            assert!(msg.contains("exceeds maximum"));
        }
    }

    #[test]
    fn test_invalid_frame_decode() {
        let codec = H3FrameCodec::new();

        // Too short
        assert!(codec.decode_atp_frame(&[0x01]).is_err());

        // Invalid frame type
        let invalid_frame = vec![0xFF, 0x00, 0x00, 0x00, 0x01, 0x42];
        assert!(codec.decode_atp_frame(&invalid_frame).is_err());

        // Truncated frame
        let truncated_frame = vec![0x01, 0x00, 0x00, 0x00, 0x10]; // Claims 16 bytes but only has header
        assert!(codec.decode_atp_frame(&truncated_frame).is_err());
    }

    #[test]
    fn test_mismatched_outer_and_inner_frame_type_rejected() {
        let codec = H3FrameCodec::new();
        let frame =
            AtpFrame::new(ProtocolVersion::CURRENT, FrameType::Data, b"data".to_vec()).unwrap();
        let mut encoded = codec.encode_atp_frame(&frame).unwrap();
        encoded[0] = WebTransportFrameType::Control as u8;

        let err = codec.decode_atp_frame(&encoded).unwrap_err();
        assert!(matches!(err, AtpH3Error::Codec(message) if message.contains("does not match")));
    }
}
