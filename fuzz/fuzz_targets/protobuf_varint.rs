#![no_main]

//! Fuzz target for QUIC varint decoding from src/net/quic_core/mod.rs
//!
//! This fuzzer validates the security properties of the QUIC varint decoder:
//! 1. Varints terminate within 8 bytes (QUIC varint max, not 10 like protobuf)
//! 2. Truncated varints return Incomplete not panic
//! 3. Varint overflow rejected (exceeds QUIC_VARINT_MAX)
//! 4. Continuation bit pattern respected (length prefix encoding)
//! 5. Boundary values handled correctly (since QUIC varints are unsigned, no zigzag)

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};
use asupersync::net::quic_core::{decode_varint, encode_varint, QuicCoreError, QUIC_VARINT_MAX};

/// Structured input for controlled varint fuzzing scenarios.
#[derive(Arbitrary, Debug)]
enum VarintFuzzInput {
    /// Raw bytes to decode (tests malformed inputs, truncation, overflow)
    RawBytes(Vec<u8>),

    /// Valid value to round-trip (tests encoding then decoding)
    ValidValue(u64),

    /// Specifically crafted edge case scenarios
    EdgeCase(EdgeCaseVarint),
}

#[derive(Arbitrary, Debug)]
enum EdgeCaseVarint {
    /// Empty input (should return UnexpectedEof)
    Empty,

    /// Maximum valid value (QUIC_VARINT_MAX)
    MaxValid,

    /// Value exceeding maximum (QUIC_VARINT_MAX + 1)
    Overflow,

    /// Truncated 2-byte varint (first byte indicates 2-byte but only 1 byte provided)
    Truncated2Byte,

    /// Truncated 4-byte varint (first byte indicates 4-byte but only partial bytes provided)
    Truncated4Byte(u8), // 0-2 additional bytes

    /// Truncated 8-byte varint (first byte indicates 8-byte but only partial bytes provided)
    Truncated8Byte(u8), // 0-6 additional bytes

    /// Boundary values: powers of 2 near encoding thresholds
    Boundary(BoundaryValue),
}

#[derive(Arbitrary, Debug)]
enum BoundaryValue {
    /// 6-bit boundary (63 = max 1-byte value)
    SixBit(bool), // true = 63, false = 64

    /// 14-bit boundary (16383 = max 2-byte value)
    FourteenBit(bool), // true = 16383, false = 16384

    /// 30-bit boundary (1073741823 = max 4-byte value)
    ThirtyBit(bool), // true = 1073741823, false = 1073741824

    /// 62-bit boundary (QUIC_VARINT_MAX)
    SixtyTwoBit,
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    if let Ok(input) = VarintFuzzInput::arbitrary(&mut u) {
        fuzz_varint_decode(input);
    }

    // Also fuzz raw bytes directly for maximum coverage
    if data.len() <= 10 {
        fuzz_raw_bytes(data);
    }
});

fn fuzz_varint_decode(input: VarintFuzzInput) {
    match input {
        VarintFuzzInput::RawBytes(bytes) => {
            fuzz_raw_bytes(&bytes);
        }

        VarintFuzzInput::ValidValue(value) => {
            fuzz_roundtrip(value);
        }

        VarintFuzzInput::EdgeCase(edge) => {
            fuzz_edge_case(edge);
        }
    }
}

fn fuzz_raw_bytes(bytes: &[u8]) {
    // ASSERTION 1: Varints terminate within 8 bytes (QUIC max, not 10)
    if bytes.len() > 8 {
        // For inputs > 8 bytes, decoder should only consume up to 8 bytes
        let result = decode_varint(bytes);
        if let Ok((_, consumed)) = result {
            assert!(consumed <= 8, "Varint consumed {} bytes, max is 8", consumed);
        }
        return;
    }

    // ASSERTION 2: Truncated varints return Incomplete (UnexpectedEof) not panic
    let result = std::panic::catch_unwind(|| decode_varint(bytes));
    assert!(result.is_ok(), "decode_varint panicked on input: {:?}", bytes);

    let decode_result = decode_varint(bytes);

    // Check specific error conditions
    match decode_result {
        Ok((value, consumed)) => {
            // ASSERTION 3: Varint overflow rejected (value should be <= QUIC_VARINT_MAX)
            assert!(value <= QUIC_VARINT_MAX,
                "Decoded value {} exceeds QUIC_VARINT_MAX {}", value, QUIC_VARINT_MAX);

            // ASSERTION 4: Continuation bit pattern respected
            // Consumed bytes should match the length indicated by first byte
            if !bytes.is_empty() {
                let expected_len = 1usize << (bytes[0] >> 6);
                assert_eq!(consumed, expected_len.min(bytes.len()),
                    "Consumed {} bytes but first byte indicates {} bytes", consumed, expected_len);
            }

            // Additional invariant: consumed should not exceed input length
            assert!(consumed <= bytes.len(),
                "Consumed {} bytes from {}-byte input", consumed, bytes.len());
        }

        Err(QuicCoreError::UnexpectedEof) => {
            // This is expected for truncated inputs - verify it's actually truncated
            if !bytes.is_empty() {
                let expected_len = 1usize << (bytes[0] >> 6);
                assert!(bytes.len() < expected_len,
                    "Got UnexpectedEof but input length {} >= expected length {}",
                    bytes.len(), expected_len);
            }
        }

        Err(other) => {
            // Other errors are unexpected for raw byte fuzzing
            panic!("Unexpected error for input {:?}: {:?}", bytes, other);
        }
    }
}

fn fuzz_roundtrip(value: u64) {
    if value > QUIC_VARINT_MAX {
        // ASSERTION 3: Encoding should reject overflow
        let mut buf = Vec::new();
        let encode_result = encode_varint(value, &mut buf);
        assert!(matches!(encode_result, Err(QuicCoreError::VarIntOutOfRange(_))),
            "encode_varint should reject value {} > QUIC_VARINT_MAX", value);
        return;
    }

    // ASSERTION 5: Valid values roundtrip correctly (no zigzag since QUIC varints are unsigned)
    let mut encoded = Vec::new();
    encode_varint(value, &mut encoded).expect("encode should succeed for valid value");

    let (decoded, consumed) = decode_varint(&encoded).expect("decode should succeed");
    assert_eq!(decoded, value, "Roundtrip mismatch: {} -> {:?} -> {}", value, encoded, decoded);
    assert_eq!(consumed, encoded.len(), "Decode should consume entire encoded buffer");

    // ASSERTION 1: Encoded length should be reasonable
    assert!(encoded.len() <= 8, "Encoded varint length {} exceeds 8 bytes", encoded.len());
}

fn fuzz_edge_case(edge: EdgeCaseVarint) {
    match edge {
        EdgeCaseVarint::Empty => {
            let result = decode_varint(&[]);
            assert!(matches!(result, Err(QuicCoreError::UnexpectedEof)),
                "Empty input should return UnexpectedEof");
        }

        EdgeCaseVarint::MaxValid => {
            fuzz_roundtrip(QUIC_VARINT_MAX);
        }

        EdgeCaseVarint::Overflow => {
            fuzz_roundtrip(QUIC_VARINT_MAX.saturating_add(1));
        }

        EdgeCaseVarint::Truncated2Byte => {
            // First byte indicates 2-byte varint (01xxxxxx) but only 1 byte provided
            let truncated = vec![0x40]; // 01000000 = 2-byte varint prefix
            let result = decode_varint(&truncated);
            assert!(matches!(result, Err(QuicCoreError::UnexpectedEof)),
                "Truncated 2-byte varint should return UnexpectedEof");
        }

        EdgeCaseVarint::Truncated4Byte(extra_bytes) => {
            // First byte indicates 4-byte varint (10xxxxxx) but only partial bytes provided
            let mut truncated = vec![0x80]; // 10000000 = 4-byte varint prefix
            let extra_count = (extra_bytes % 3) as usize; // 0-2 additional bytes
            for _ in 0..extra_count {
                truncated.push(0x00);
            }
            if truncated.len() < 4 {
                let result = decode_varint(&truncated);
                assert!(matches!(result, Err(QuicCoreError::UnexpectedEof)),
                    "Truncated 4-byte varint should return UnexpectedEof");
            }
        }

        EdgeCaseVarint::Truncated8Byte(extra_bytes) => {
            // First byte indicates 8-byte varint (11xxxxxx) but only partial bytes provided
            let mut truncated = vec![0xC0]; // 11000000 = 8-byte varint prefix
            let extra_count = (extra_bytes % 7) as usize; // 0-6 additional bytes
            for _ in 0..extra_count {
                truncated.push(0x00);
            }
            if truncated.len() < 8 {
                let result = decode_varint(&truncated);
                assert!(matches!(result, Err(QuicCoreError::UnexpectedEof)),
                    "Truncated 8-byte varint should return UnexpectedEof");
            }
        }

        EdgeCaseVarint::Boundary(boundary) => {
            let value = match boundary {
                BoundaryValue::SixBit(is_max) => if is_max { 63 } else { 64 },
                BoundaryValue::FourteenBit(is_max) => if is_max { 16383 } else { 16384 },
                BoundaryValue::ThirtyBit(is_max) => if is_max { 1073741823 } else { 1073741824 },
                BoundaryValue::SixtyTwoBit => QUIC_VARINT_MAX,
            };
            fuzz_roundtrip(value);
        }
    }
}

/// Stress test with maximum-length input
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_max_length_input() {
        // 8-byte varint with maximum value
        let max_input = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        fuzz_raw_bytes(&max_input);
    }

    #[test]
    fn test_all_length_prefixes() {
        // Test all 4 possible length prefixes
        for prefix in 0..4u8 {
            let first_byte = prefix << 6;
            let input = vec![first_byte];
            fuzz_raw_bytes(&input);
        }
    }

    #[test]
    fn test_boundary_values() {
        let boundaries = [0u64, 63, 64, 16383, 16384, 1073741823, 1073741824, QUIC_VARINT_MAX];
        for &value in &boundaries {
            fuzz_roundtrip(value);
        }
    }
}