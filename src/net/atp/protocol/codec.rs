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
use crate::net::atp::protocol::outcome::AtpOutcome;
use crate::net::atp::protocol::varint::{VarInt, VarIntError};
use crate::types::outcome::Outcome;
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

    /// Helper to convert AtpOutcome to FrameError for codec compatibility
    fn atp_to_frame_error<T>(outcome: AtpOutcome<T>) -> Result<T, FrameError> {
        match outcome {
            Outcome::Ok(value) => Ok(value),
            Outcome::Err(_) => Err(FrameError::InvalidFormat("ATP protocol error".to_string())),
            Outcome::Cancelled(_) => Err(FrameError::UnexpectedEof),
            Outcome::Panicked(_) => Err(FrameError::UnexpectedEof),
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

    fn checked_frame_size(header: &FrameHeader, payload_len: u64) -> Result<u64, FrameError> {
        let payload_len = usize::try_from(payload_len)
            .map_err(|_| FrameError::InvalidFormat("Payload length too large".to_string()))?;
        let total_size = header
            .encoded_len()
            .checked_add(payload_len)
            .ok_or_else(|| FrameError::InvalidFormat("Frame size overflow".to_string()))?;
        u64::try_from(total_size)
            .map_err(|_| FrameError::InvalidFormat("Frame size too large".to_string()))
    }

    fn validate_frame_for_encoding(&self, frame: &Frame) -> Result<u64, FrameError> {
        let declared_payload_len = frame.header.payload_length.value();
        let actual_payload_len = u64::try_from(frame.payload.len())
            .map_err(|_| FrameError::InvalidFormat("Payload length too large".to_string()))?;
        if declared_payload_len != actual_payload_len {
            return Err(FrameError::InvalidFormat(format!(
                "Payload length mismatch: header declares {declared_payload_len}, payload has {actual_payload_len}",
            )));
        }

        let extension_count = u64::try_from(frame.header.extensions.len())
            .map_err(|_| FrameError::InvalidFormat("Extension count too large".to_string()))?;
        if extension_count > MAX_EXTENSION_COUNT {
            return Err(FrameError::InvalidFormat(format!(
                "Extension count {extension_count} exceeds maximum {MAX_EXTENSION_COUNT}",
            )));
        }

        for ext_data in frame.header.extensions.values() {
            let ext_len = u64::try_from(ext_data.len())
                .map_err(|_| FrameError::InvalidFormat("Extension length too large".to_string()))?;
            if ext_len > MAX_EXTENSION_SIZE {
                return Err(FrameError::ExtensionTooLarge { size: ext_len });
            }
        }

        let header_size = u64::try_from(frame.header.encoded_len())
            .map_err(|_| FrameError::InvalidFormat("Header size too large".to_string()))?;
        if header_size > MAX_HEADER_SIZE {
            return Err(FrameError::FrameTooLarge {
                size: header_size,
                max: MAX_HEADER_SIZE,
            });
        }

        let total_size = Self::checked_frame_size(&frame.header, declared_payload_len)?;
        if total_size > self.max_frame_size {
            return Err(FrameError::FrameTooLarge {
                size: total_size,
                max: self.max_frame_size,
            });
        }

        Ok(total_size)
    }

    /// Decode and validate a complete frame header before consuming it.
    ///
    /// `max_frame_size` is the codec's configured frame-size limit; the payload
    /// length is bounded against it (not a hardcoded constant) so a codec built
    /// with a non-default `with_max_frame_size` accepts exactly the frames it is
    /// willing to encode, with no encode/decode asymmetry.
    fn decode_header(
        buf: &mut BytesMut,
        max_frame_size: u64,
    ) -> Result<Option<FrameHeader>, FrameError> {
        // First pass: check if we have enough bytes for complete header without consuming
        let mut cursor = 0;

        // Helper to try parsing varint at cursor position
        let try_parse_varint =
            |buf: &[u8], pos: &mut usize| -> Result<Option<VarInt>, FrameError> {
                if *pos >= buf.len() {
                    return Ok(None);
                }

                match VarInt::decode_prefix(&buf[*pos..]) {
                    Outcome::Ok(Some((varint, length))) => {
                        *pos += length;
                        Ok(Some(varint))
                    }
                    Outcome::Ok(None) => Ok(None),
                    Outcome::Err(_) => Err(FrameError::VarInt(VarIntError::InvalidEncoding)),
                    Outcome::Cancelled(_) | Outcome::Panicked(_) => Err(FrameError::UnexpectedEof),
                }
            };

        // Parse version
        let Some(version_varint) = try_parse_varint(buf, &mut cursor)? else {
            return Ok(None); // Need more data
        };
        let version_value = u32::try_from(version_varint.value())
            .map_err(|_| FrameError::UnsupportedVersion(version_varint.value() as u32))?;
        let version = ProtocolVersion(version_value);
        if version != ProtocolVersion::V0 {
            return Err(FrameError::UnsupportedVersion(version.0));
        }

        // Parse frame type
        let Some(frame_type_varint) = try_parse_varint(buf, &mut cursor)? else {
            return Ok(None); // Need more data
        };
        let frame_type = FrameType::from_varint(frame_type_varint)?;

        // Parse payload length
        let Some(payload_length) = try_parse_varint(buf, &mut cursor)? else {
            return Ok(None); // Need more data
        };
        if payload_length.value() > max_frame_size {
            return Err(FrameError::FrameTooLarge {
                size: payload_length.value(),
                max: max_frame_size,
            });
        }

        // Parse extension count
        let Some(extension_count) = try_parse_varint(buf, &mut cursor)? else {
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
            let Some(ext_id_varint) = try_parse_varint(buf, &mut cursor)? else {
                return Ok(None); // Need more data
            };
            let ext_id = u16::try_from(ext_id_varint.value()).map_err(|_| {
                FrameError::InvalidFormat("Extension ID too large for u16".to_string())
            })?;
            if extensions.contains_key(&ext_id) {
                return Err(FrameError::InvalidFormat(format!(
                    "Duplicate extension ID {ext_id}",
                )));
            }

            let Some(ext_len) = try_parse_varint(buf, &mut cursor)? else {
                return Ok(None); // Need more data
            };

            if ext_len.value() > MAX_EXTENSION_SIZE {
                return Err(FrameError::ExtensionTooLarge {
                    size: ext_len.value(),
                });
            }

            // Check extension data availability with safe arithmetic
            let ext_len_usize = usize::try_from(ext_len.value())
                .map_err(|_| FrameError::InvalidFormat("Extension length too large".to_string()))?;
            let end_pos = cursor.checked_add(ext_len_usize).ok_or_else(|| {
                FrameError::InvalidFormat("Extension bounds overflow".to_string())
            })?;

            if end_pos > MAX_HEADER_SIZE as usize {
                return Err(FrameError::FrameTooLarge {
                    size: end_pos as u64,
                    max: MAX_HEADER_SIZE,
                });
            }

            if end_pos > buf.len() {
                return Ok(None); // Need more data
            }

            let ext_data = buf[cursor..end_pos].to_vec();
            extensions.insert(ext_id, ext_data);
            cursor = end_pos;

            // Check total header size
            if cursor > MAX_HEADER_SIZE as usize {
                return Err(FrameError::FrameTooLarge {
                    size: cursor as u64,
                    max: MAX_HEADER_SIZE,
                });
            }
        }

        let header = FrameHeader {
            version,
            frame_type,
            payload_length,
            extensions,
        };
        let total_size = Self::checked_frame_size(&header, payload_length.value())?;
        if total_size > max_frame_size {
            return Err(FrameError::FrameTooLarge {
                size: total_size,
                max: max_frame_size,
            });
        }

        // All header and total-size checks passed; errors above preserve input.
        let _ = buf.split_to(cursor);
        Ok(Some(header))
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
        let max_frame_size = self.max_frame_size;
        loop {
            match &mut self.decode_state {
                DecodeState::Header => {
                    // Try to decode header
                    match Self::decode_header(src, max_frame_size)? {
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
                    let payload_len_usize = usize::try_from(payload_len).map_err(|_| {
                        FrameError::InvalidFormat(
                            "Payload length too large for platform".to_string(),
                        )
                    })?;

                    if src.len() < payload_len_usize {
                        // Need more data for payload
                        return Ok(None);
                    }

                    // Read payload
                    let payload = src.split_to(payload_len_usize).to_vec();

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

    fn decode_eof(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match self.decode(src)? {
            Some(frame) => Ok(Some(frame)),
            None if src.is_empty() && matches!(self.decode_state, DecodeState::Header) => Ok(None),
            // A consumed header can leave an empty buffer while its declared
            // payload is still missing. The default Decoder implementation
            // inspects only that buffer and would silently accept truncation.
            None => Err(FrameError::UnexpectedEof),
        }
    }
}

impl Encoder<Frame> for AtpFrameCodec {
    type Error = FrameError;

    fn encode(&mut self, frame: Frame, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let total_size = usize::try_from(self.validate_frame_for_encoding(&frame)?)
            .map_err(|_| FrameError::InvalidFormat("Frame size too large".to_string()))?;

        // Ensure we have enough capacity
        dst.reserve(total_size);

        // Encode header

        // Version
        let version_varint = Self::atp_to_frame_error(VarInt::new(frame.header.version.0 as u64))?;
        Self::atp_to_frame_error(version_varint.encode(dst))?;

        // Frame type
        Self::atp_to_frame_error(frame.header.frame_type.to_varint().encode(dst))?;

        // Payload length
        Self::atp_to_frame_error(frame.header.payload_length.encode(dst))?;

        // Extension count
        let ext_count_varint =
            Self::atp_to_frame_error(VarInt::new(frame.header.extensions.len() as u64))?;
        Self::atp_to_frame_error(ext_count_varint.encode(dst))?;

        // Match the transcript's numeric ID order without changing the public
        // map type or copying extension payloads. Decoding still accepts the
        // unique, unsorted extension order emitted by older peers.
        let mut extensions: Vec<_> = frame.header.extensions.iter().collect();
        extensions.sort_unstable_by_key(|(id, _)| **id);
        for (ext_id, ext_data) in extensions {
            let ext_id_varint = Self::atp_to_frame_error(VarInt::new(*ext_id as u64))?;
            Self::atp_to_frame_error(ext_id_varint.encode(dst))?;

            let ext_len_varint = Self::atp_to_frame_error(VarInt::new(ext_data.len() as u64))?;
            Self::atp_to_frame_error(ext_len_varint.encode(dst))?;

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
#[path = "codec_inline_tests.rs"]
mod tests;
