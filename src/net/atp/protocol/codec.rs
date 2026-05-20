//! ATP Frame Codec
//!
//! Implements encoding and decoding of ATP binary frames using the standard
//! asupersync codec traits. Handles frame boundaries, validation, and error recovery.

use crate::bytes::BytesMut;
use crate::codec::{Decoder, Encoder};
use crate::net::atp::protocol::frames::{
    Frame, FrameError, FrameHeader, FrameType, MAX_EXTENSION_COUNT, MAX_EXTENSION_SIZE,
    MAX_FRAME_SIZE, MAX_HEADER_SIZE, ProtocolVersion,
};
use crate::net::atp::protocol::varint::VarInt;
use std::collections::HashMap;
use std::io;

/// ATP Frame Codec for encoding/decoding binary frames
#[derive(Debug, Clone)]
pub struct AtpFrameCodec {
    /// Maximum allowed frame size
    max_frame_size: u64,
    /// Decoder state for handling partial frames
    decode_state: DecodeState,
}

/// Internal decoder state for managing partial frame reads
#[derive(Debug, Clone)]
enum DecodeState {
    /// Reading frame header
    Header,
    /// Reading frame payload (remaining bytes needed)
    Payload { header: FrameHeader, remaining: u64 },
}

impl AtpFrameCodec {
    /// Create a new ATP frame codec with default settings
    pub fn new() -> Self {
        Self {
            max_frame_size: MAX_FRAME_SIZE,
            decode_state: DecodeState::Header,
        }
    }

    /// Create codec with custom maximum frame size
    pub fn with_max_frame_size(max_frame_size: u64) -> Self {
        Self {
            max_frame_size,
            decode_state: DecodeState::Header,
        }
    }

    /// Reset decoder state (useful after errors)
    pub fn reset_decoder(&mut self) {
        self.decode_state = DecodeState::Header;
    }

    /// Decode frame header from buffer (zero-copy optimization)
    fn decode_header(buf: &mut BytesMut) -> Result<Option<FrameHeader>, FrameError> {
        // First pass: check if we have enough bytes for complete header without consuming
        let original_len = buf.len();
        let mut cursor = 0;

        // Helper to try parsing varint at cursor position
        let try_parse_varint = |buf: &[u8], pos: &mut usize| -> Option<VarInt> {
            if *pos >= buf.len() {
                return None;
            }

            let mut temp = BytesMut::from(&buf[*pos..]);
            if let Ok(Some(varint)) = VarInt::decode(&mut temp) {
                *pos += (buf.len() - *pos) - temp.len();
                Some(varint)
            } else {
                None
            }
        };

        // Parse version
        let Some(version_varint) = try_parse_varint(buf, &mut cursor) else {
            return Ok(None); // Need more data
        };
        let version = ProtocolVersion(version_varint.value() as u32);
        if version != ProtocolVersion::V0 {
            return Err(FrameError::UnsupportedVersion(version.0));
        }

        // Parse frame type
        let Some(frame_type_varint) = try_parse_varint(buf, &mut cursor) else {
            return Ok(None); // Need more data
        };
        let frame_type = FrameType::from_varint(frame_type_varint)?;

        // Parse payload length
        let Some(payload_length) = try_parse_varint(buf, &mut cursor) else {
            return Ok(None); // Need more data
        };
        if payload_length.value() > MAX_FRAME_SIZE {
            return Err(FrameError::FrameTooLarge {
                size: payload_length.value(),
                max: MAX_FRAME_SIZE,
            });
        }

        // Parse extension count
        let Some(extension_count) = try_parse_varint(buf, &mut cursor) else {
            return Ok(None); // Need more data
        };
        if extension_count.value() > MAX_EXTENSION_COUNT {
            return Err(FrameError::ExtensionTooLarge {
                size: extension_count.value(),
            });
        }

        // Parse extensions
        let mut extensions = HashMap::new();
        for _ in 0..extension_count.value() {
            let Some(ext_id_varint) = try_parse_varint(buf, &mut cursor) else {
                return Ok(None); // Need more data
            };
            let ext_id = ext_id_varint.value() as u16;

            let Some(ext_len) = try_parse_varint(buf, &mut cursor) else {
                return Ok(None); // Need more data
            };

            if ext_len.value() > MAX_EXTENSION_SIZE {
                return Err(FrameError::ExtensionTooLarge {
                    size: ext_len.value(),
                });
            }

            // Check extension data availability
            if cursor + ext_len.value() as usize > buf.len() {
                return Ok(None); // Need more data
            }

            let ext_data = buf[cursor..cursor + ext_len.value() as usize].to_vec();
            extensions.insert(ext_id, ext_data);
            cursor += ext_len.value() as usize;

            // Check total header size
            if cursor > MAX_HEADER_SIZE as usize {
                return Err(FrameError::FrameTooLarge {
                    size: cursor as u64,
                    max: MAX_HEADER_SIZE,
                });
            }
        }

        // Success - advance original buffer by consumed bytes
        let _ = buf.split_to(cursor);

        Ok(Some(FrameHeader {
            version,
            frame_type,
            payload_length,
            extensions,
        }))
    }
}

impl Default for AtpFrameCodec {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder for AtpFrameCodec {
    type Item = Frame;
    type Error = FrameError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        loop {
            match &mut self.decode_state {
                DecodeState::Header => {
                    // Try to decode header
                    match Self::decode_header(src)? {
                        Some(header) => {
                            let payload_len = header.payload_length.value();
                            if payload_len == 0 {
                                // Empty payload frame
                                let frame = Frame {
                                    header,
                                    payload: Vec::new(),
                                };
                                self.decode_state = DecodeState::Header;
                                return Ok(Some(frame));
                            } else {
                                // Need to read payload
                                self.decode_state = DecodeState::Payload {
                                    header,
                                    remaining: payload_len,
                                };
                            }
                        }
                        None => {
                            // Need more data for header
                            return Ok(None);
                        }
                    }
                }
                DecodeState::Payload { header, remaining } => {
                    let payload_len = *remaining;

                    if src.len() < payload_len as usize {
                        // Need more data for payload
                        return Ok(None);
                    }

                    // Read payload
                    let payload = src.split_to(payload_len as usize).to_vec();

                    let frame = Frame {
                        header: header.clone(),
                        payload,
                    };

                    // Reset state for next frame
                    self.decode_state = DecodeState::Header;
                    return Ok(Some(frame));
                }
            }
        }
    }
}

impl Encoder<Frame> for AtpFrameCodec {
    type Error = FrameError;

    fn encode(&mut self, frame: Frame, dst: &mut BytesMut) -> Result<(), Self::Error> {
        // Validate frame size
        let total_size = frame.encoded_len();
        if total_size as u64 > self.max_frame_size {
            return Err(FrameError::FrameTooLarge {
                size: total_size as u64,
                max: self.max_frame_size,
            });
        }

        // Ensure we have enough capacity
        dst.reserve(total_size);

        // Encode header

        // Version
        VarInt::new(frame.header.version.0 as u64)?.encode(dst)?;

        // Frame type
        frame.header.frame_type.to_varint().encode(dst)?;

        // Payload length
        frame.header.payload_length.encode(dst)?;

        // Extension count
        VarInt::new(frame.header.extensions.len() as u64)?.encode(dst)?;

        // Extensions
        for (ext_id, ext_data) in &frame.header.extensions {
            VarInt::new(*ext_id as u64)?.encode(dst)?;
            VarInt::new(ext_data.len() as u64)?.encode(dst)?;
            dst.put_slice(ext_data);
        }

        // Payload
        dst.put_slice(&frame.payload);

        Ok(())
    }
}

impl From<FrameError> for io::Error {
    fn from(err: FrameError) -> Self {
        match err {
            FrameError::VarInt(varint_err) => varint_err.into(),
            FrameError::UnknownFrameType(_) => io::Error::new(io::ErrorKind::InvalidData, err),
            FrameError::UnsupportedVersion(_) => io::Error::new(io::ErrorKind::Unsupported, err),
            FrameError::FrameTooLarge { .. } => io::Error::new(io::ErrorKind::InvalidData, err),
            FrameError::InvalidFormat(_) => io::Error::new(io::ErrorKind::InvalidData, err),
            FrameError::UnexpectedEof => io::Error::new(io::ErrorKind::UnexpectedEof, err),
            FrameError::ExtensionTooLarge { .. } => io::Error::new(io::ErrorKind::InvalidData, err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_roundtrip() {
        let mut codec = AtpFrameCodec::new();

        // Create a test frame
        let payload = b"Hello, ATP!".to_vec();
        let frame = Frame::new(ProtocolVersion::V0, FrameType::Handshake, payload.clone()).unwrap();

        // Encode
        let mut buf = BytesMut::new();
        codec.encode(frame.clone(), &mut buf).unwrap();

        // Decode
        let decoded = codec.decode(&mut buf).unwrap().unwrap();

        assert_eq!(decoded.version(), frame.version());
        assert_eq!(decoded.frame_type(), frame.frame_type());
        assert_eq!(decoded.payload(), frame.payload());
    }

    #[test]
    fn test_partial_frame_decode() {
        let mut codec = AtpFrameCodec::new();

        // Create and encode a frame
        let payload = vec![0u8; 1000]; // Large payload
        let frame = Frame::new(ProtocolVersion::V0, FrameType::ObjectData, payload).unwrap();

        let mut encoded = BytesMut::new();
        codec.encode(frame.clone(), &mut encoded).unwrap();

        // Split encoded data into chunks to simulate partial reads
        let total_len = encoded.len();
        let chunk_size = 100;

        let mut decoder = AtpFrameCodec::new();
        let mut decode_buf = BytesMut::new();

        for chunk_start in (0..total_len).step_by(chunk_size) {
            let chunk_end = (chunk_start + chunk_size).min(total_len);
            let chunk = encoded.slice(chunk_start..chunk_end);
            decode_buf.extend_from_slice(&chunk);

            // Try to decode
            match decoder.decode(&mut decode_buf).unwrap() {
                Some(decoded_frame) => {
                    // Should only succeed on the final chunk
                    assert!(chunk_end >= total_len);
                    assert_eq!(decoded_frame.payload(), frame.payload());
                    break;
                }
                None => {
                    // Should need more data
                    assert!(chunk_end < total_len);
                    continue;
                }
            }
        }
    }

    #[test]
    fn test_frame_with_extensions() {
        let mut codec = AtpFrameCodec::new();

        let mut frame = Frame::new(
            ProtocolVersion::V0,
            FrameType::Capabilities,
            b"capability_data".to_vec(),
        )
        .unwrap();

        // Add some extensions
        frame.header.extensions.insert(1, b"ext1".to_vec());
        frame.header.extensions.insert(2, b"extension2".to_vec());

        // Roundtrip
        let mut buf = BytesMut::new();
        codec.encode(frame.clone(), &mut buf).unwrap();

        let decoded = codec.decode(&mut buf).unwrap().unwrap();

        assert_eq!(decoded.header.extensions, frame.header.extensions);
    }

    #[test]
    fn test_frame_size_limits() {
        let mut codec = AtpFrameCodec::with_max_frame_size(100);

        // Frame that's too large
        let large_payload = vec![0u8; 200];
        let large_frame =
            Frame::new(ProtocolVersion::V0, FrameType::ObjectData, large_payload).unwrap();

        let mut buf = BytesMut::new();
        let result = codec.encode(large_frame, &mut buf);

        assert!(matches!(result, Err(FrameError::FrameTooLarge { .. })));
    }

    #[test]
    fn test_invalid_version() {
        let mut buf = BytesMut::new();

        // Manually encode frame with invalid version
        VarInt::new(999).unwrap().encode(&mut buf).unwrap(); // Invalid version
        VarInt::new(FrameType::Handshake as u64)
            .unwrap()
            .encode(&mut buf)
            .unwrap();
        VarInt::new(0).unwrap().encode(&mut buf).unwrap(); // payload length
        VarInt::new(0).unwrap().encode(&mut buf).unwrap(); // extension count

        let mut codec = AtpFrameCodec::new();
        let result = codec.decode(&mut buf);

        assert!(matches!(result, Err(FrameError::UnsupportedVersion(999))));
    }

    #[test]
    fn test_unknown_frame_type() {
        let mut buf = BytesMut::new();

        // Manually encode frame with unknown frame type
        VarInt::new(0).unwrap().encode(&mut buf).unwrap(); // Valid version
        VarInt::new(9999).unwrap().encode(&mut buf).unwrap(); // Invalid frame type
        VarInt::new(0).unwrap().encode(&mut buf).unwrap(); // payload length
        VarInt::new(0).unwrap().encode(&mut buf).unwrap(); // extension count

        let mut codec = AtpFrameCodec::new();
        let result = codec.decode(&mut buf);

        assert!(matches!(result, Err(FrameError::UnknownFrameType(9999))));
    }
}
