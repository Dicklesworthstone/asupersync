//! Variable-length integer encoding for ATP frames.
//!
//! Uses QUIC-style varints for compact and canonical encoding:
//! - 1 byte: values 0-63 (0b00xxxxxx)
//! - 2 bytes: values 64-16383 (0b01xxxxxx xxxxxxxx)
//! - 4 bytes: values 16384-1073741823 (0b10xxxxxx xxxxxxxx xxxxxxxx xxxxxxxx)
//! - 8 bytes: values 1073741824+ (0b11xxxxxx ... 8 total bytes)

use crate::bytes::{BufMut, BytesMut};
use crate::net::atp::protocol::outcome::{AtpOutcome, ProtocolError};
use crate::types::outcome::Outcome;
use std::io;

/// Maximum value that can be encoded in a varint.
pub const VARINT_MAX: u64 = (1u64 << 62) - 1;

/// Variable-length integer encoder/decoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VarInt(pub u64);

impl VarInt {
    /// Create a new varint, ensuring the value is within range.
    pub fn new(value: u64) -> AtpOutcome<Self> {
        if value > VARINT_MAX {
            return AtpOutcome::protocol_error(ProtocolError::InvalidVarInt);
        }
        Outcome::Ok(VarInt(value))
    }

    /// Get the raw value.
    #[inline]
    pub fn value(self) -> u64 {
        self.0
    }

    /// Create a new varint from a value known to be valid (for literals and known-safe values).
    ///
    /// # Safety
    /// This panics if the value is too large. Only use with compile-time constants
    /// or values you are certain are within the varint range.
    #[inline]
    pub fn from_u64_unchecked(value: u64) -> Self {
        match VarInt::new(value) {
            Outcome::Ok(varint) => varint,
            _ => panic!("varint value exceeds maximum allowed value"),
        }
    }

    /// Calculate the encoded length without actually encoding.
    #[inline]
    pub fn encoded_len(self) -> usize {
        let value = self.0;
        if value < 64 {
            1
        } else if value < 16_384 {
            2
        } else if value < 1_073_741_824 {
            4
        } else {
            8
        }
    }

    /// Encode the varint to a buffer.
    pub fn encode(self, buf: &mut BytesMut) -> AtpOutcome<()> {
        let value = self.0;

        if value < 64 {
            // 1 byte encoding: 0b00xxxxxx
            buf.put_u8(value as u8);
        } else if value < 16_384 {
            // 2 byte encoding: 0b01xxxxxx xxxxxxxx
            buf.put_u16((0x4000 | value) as u16);
        } else if value < 1_073_741_824 {
            // 4 byte encoding: 0b10xxxxxx xxxxxxxx xxxxxxxx xxxxxxxx
            buf.put_u32((0x80000000 | value) as u32);
        } else if value <= VARINT_MAX {
            // 8 byte encoding: 0b11xxxxxx ... (8 bytes total)
            buf.put_u64(0xC000000000000000 | value);
        } else {
            return AtpOutcome::protocol_error(ProtocolError::InvalidVarInt);
        }

        Outcome::Ok(())
    }

    /// Decode a varint from a buffer.
    pub fn decode(buf: &mut BytesMut) -> AtpOutcome<Option<Self>> {
        if buf.is_empty() {
            return Outcome::Ok(None);
        }

        let first_byte = buf[0];
        let (length, prefix) = match first_byte >> 6 {
            0b00 => (1, 0x3F), // 1 byte
            0b01 => (2, 0x3F), // 2 bytes
            0b10 => (4, 0x3F), // 4 bytes
            0b11 => (8, 0x3F), // 8 bytes
            _ => unreachable!(),
        };

        if buf.len() < length {
            return Outcome::Ok(None); // Need more data
        }

        let value = match length {
            1 => {
                let _ = buf.split_to(1); // Consume the byte
                (first_byte & prefix) as u64
            }
            2 => {
                let bytes = buf.split_to(2);
                let val = u16::from_be_bytes([bytes[0], bytes[1]]) & 0x3FFF;
                val as u64
            }
            4 => {
                let bytes = buf.split_to(4);
                let val = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) & 0x3FFFFFFF;
                val as u64
            }
            8 => {
                let bytes = buf.split_to(8);
                u64::from_be_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                ]) & 0x3FFFFFFFFFFFFFFF
            }
            _ => unreachable!(),
        };

        if value > VARINT_MAX {
            return AtpOutcome::protocol_error(ProtocolError::InvalidVarInt);
        }

        Outcome::Ok(Some(VarInt(value)))
    }

    /// Peek at the length of the next varint without consuming it.
    pub fn peek_len(buf: &BytesMut) -> Option<usize> {
        if buf.is_empty() {
            return None;
        }

        let first_byte = buf[0];
        Some(match first_byte >> 6 {
            0b00 => 1,
            0b01 => 2,
            0b10 => 4,
            0b11 => 8,
            _ => unreachable!(),
        })
    }
}

impl TryFrom<u64> for VarInt {
    type Error = VarIntError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match VarInt::new(value) {
            Outcome::Ok(varint) => Ok(varint),
            _ => Err(VarIntError::ValueTooLarge(value)),
        }
    }
}

impl From<VarInt> for u64 {
    fn from(varint: VarInt) -> Self {
        varint.0
    }
}

/// Varint encoding/decoding errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VarIntError {
    /// Value cannot fit in ATP's QUIC-style 62-bit varint space.
    #[error("varint value too large: {value} > {max}", value = .0, max = VARINT_MAX)]
    ValueTooLarge(u64),

    /// Input ended before a complete varint was available.
    #[error("unexpected end of input while reading varint")]
    UnexpectedEof,

    /// Varint used a non-canonical or otherwise invalid encoding.
    #[error("invalid varint encoding")]
    InvalidEncoding,
}

impl From<VarIntError> for io::Error {
    fn from(err: VarIntError) -> Self {
        match err {
            VarIntError::ValueTooLarge(_) => io::Error::new(io::ErrorKind::InvalidData, err),
            VarIntError::UnexpectedEof => io::Error::new(io::ErrorKind::UnexpectedEof, err),
            VarIntError::InvalidEncoding => io::Error::new(io::ErrorKind::InvalidData, err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_varint_encoding_lengths() {
        let cases = [
            (0, 1),
            (63, 1),
            (64, 2),
            (16383, 2),
            (16384, 4),
            (1073741823, 4),
            (1073741824, 8),
            (VARINT_MAX, 8),
        ];

        for (value, expected_len) in cases {
            let varint = VarInt::new(value).expect("test value should be valid");
            assert_eq!(varint.encoded_len(), expected_len, "value={value}");
        }
    }

    #[test]
    fn test_varint_roundtrip() {
        let values = [
            0, 1, 63, 64, 127, 128, 16383, 16384, 65535, 65536, 1073741823, 1073741824, VARINT_MAX,
        ];

        for &value in &values {
            let mut buf = BytesMut::new();
            let varint = VarInt::new(value).expect("test value should be valid");
            varint.encode(&mut buf).expect("encoding should succeed");

            let decoded = VarInt::decode(&mut buf)
                .expect("decoding should succeed")
                .expect("should have decoded a varint");
            assert_eq!(decoded.value(), value, "value={value}");
        }
    }

    #[test]
    fn test_varint_partial_decode() {
        let varint = VarInt::new(16384).expect("test value should be valid"); // 4-byte encoding
        let mut buf = BytesMut::new();
        varint.encode(&mut buf).expect("encoding should succeed");

        // Try decoding with partial data
        let mut partial = buf.split_to(2); // Only first 2 bytes
        assert!(
            VarInt::decode(&mut partial)
                .expect("partial decode should not error")
                .is_none()
        );

        // Complete with remaining bytes
        partial.put_slice(&buf);
        let decoded = VarInt::decode(&mut partial)
            .expect("decoding should succeed")
            .expect("should have decoded a varint");
        assert_eq!(decoded.value(), 16384);
    }

    #[test]
    fn test_varint_too_large() {
        assert!(VarInt::new(VARINT_MAX + 1).is_err());
        assert!(VarInt::new(u64::MAX).is_err());
    }

    #[test]
    fn test_varint_peek_len() {
        let test_cases = [
            (VarInt::new(0).expect("test value should be valid"), 1),
            (VarInt::new(64).expect("test value should be valid"), 2),
            (VarInt::new(16384).expect("test value should be valid"), 4),
            (
                VarInt::new(1073741824).expect("test value should be valid"),
                8,
            ),
        ];

        for (varint, expected_len) in test_cases {
            let mut buf = BytesMut::new();
            varint.encode(&mut buf).expect("encoding should succeed");

            assert_eq!(
                VarInt::peek_len(&buf).expect("buffer should have varint"),
                expected_len
            );
        }
    }
}
