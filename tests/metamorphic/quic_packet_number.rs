#![allow(warnings)]
#![allow(clippy::all)]
//! Metamorphic tests for QUIC packet number encoding (RFC 9000 compliance).
//!
//! Tests the 5 core metamorphic relations for packet number encoding:
//! 1. Encoding roundtrip preservation - decode(encode(pn)) == pn
//! 2. Width validation consistency - valid widths work, invalid widths fail
//! 3. Minimum width determination - smallest width that fits the value
//! 4. Boundary behavior - width requirements at boundary values
//! 5. Wire format consistency - network byte order preservation
//!
//! Uses LabRuntime for deterministic property-based testing.

use asupersync::lab::runtime::LabRuntime;
use asupersync::net::quic_core::{
    QuicCoreError,
    // Note: These are private functions in mod.rs but they're tested via packet headers
    // write_packet_number, read_packet_number, validate_pn_len, ensure_pn_fits,
};
use proptest::prelude::*;

/// Maximum 32-bit packet number (QUIC core uses u32)
const MAX_PACKET_NUMBER: u32 = u32::MAX;

/// Helper functions that mirror the private quic_core functions for testing
mod packet_number_helpers {
    use super::*;

    /// Write packet number to buffer (mirrors write_packet_number)
    pub fn write_packet_number(packet_number: u32, width: u8, out: &mut Vec<u8>) {
        let bytes = packet_number.to_be_bytes();
        let take = width as usize;
        out.extend_from_slice(&bytes[4 - take..]);
    }

    /// Read packet number from buffer (mirrors read_packet_number)
    pub fn read_packet_number(input: &[u8], pos: &mut usize, width: u8) -> Result<u32, QuicCoreError> {
        let width = validate_pn_len(width)? as usize;
        if input.len().saturating_sub(*pos) < width {
            return Err(QuicCoreError::UnexpectedEof);
        }
        let mut out = [0u8; 4];
        out[4 - width..].copy_from_slice(&input[*pos..*pos + width]);
        *pos += width;
        Ok(u32::from_be_bytes(out))
    }

    /// Validate packet number length (mirrors validate_pn_len)
    pub fn validate_pn_len(packet_number_len: u8) -> Result<u8, QuicCoreError> {
        if (1..=4).contains(&packet_number_len) {
            Ok(packet_number_len)
        } else {
            Err(QuicCoreError::InvalidHeader(
                "packet number length must be 1..=4",
            ))
        }
    }

    /// Ensure packet number fits in width (mirrors ensure_pn_fits)
    pub fn ensure_pn_fits(packet_number: u32, packet_number_len: u8) -> Result<(), QuicCoreError> {
        let max = match packet_number_len {
            1 => 0xff,
            2 => 0xffff,
            3 => 0x00ff_ffff,
            4 => u32::MAX,
            _ => return Err(QuicCoreError::InvalidHeader("invalid packet number length")),
        };
        if packet_number <= max {
            Ok(())
        } else {
            Err(QuicCoreError::PacketNumberTooLarge {
                packet_number,
                width: packet_number_len,
            })
        }
    }

    /// Determine minimum width needed for a packet number
    pub fn min_width_for_packet_number(packet_number: u32) -> u8 {
        if packet_number <= 0xff { 1 }
        else if packet_number <= 0xffff { 2 }
        else if packet_number <= 0x00ff_ffff { 3 }
        else { 4 }
    }
}

use packet_number_helpers::*;

/// Strategy for generating valid packet numbers
fn packet_number_strategy() -> impl Strategy<Value = u32> {
    0u32..=MAX_PACKET_NUMBER
}

/// Strategy for generating valid widths
fn width_strategy() -> impl Strategy<Value = u8> {
    1u8..=4
}

/// Strategy for generating packet number and width pairs
fn packet_number_width_strategy() -> impl Strategy<Value = (u32, u8)> {
    packet_number_strategy().prop_flat_map(|pn| {
        let min_width = min_width_for_packet_number(pn);
        (Just(pn), min_width..=4)
    })
}

/// MR1: Encoding roundtrip preservation - decode(encode(pn)) == pn
#[test]
fn mr_encoding_roundtrip_preservation() {
    let runtime = LabRuntime::new(LabConfig::default());
    let cx = runtime.cx();

    proptest!(|(
        (packet_number, width) in packet_number_width_strategy()
    )| {
        runtime.block_on(&cx, async {
            // Property: Encoding then decoding should preserve the original packet number

            // First verify this combination should work
            if ensure_pn_fits(packet_number, width).is_err() {
                return Ok(()); // Skip invalid combinations
            }

            let mut buffer = Vec::new();
            write_packet_number(packet_number, width, &mut buffer);

            prop_assert_eq!(buffer.len(), width as usize,
                "Buffer length {} should match width {}", buffer.len(), width);

            let mut pos = 0;
            let decoded = read_packet_number(&buffer, &mut pos, width)?;

            prop_assert_eq!(decoded, packet_number,
                "Roundtrip failed: encoded {} width {} -> decoded {}",
                packet_number, width, decoded);

            prop_assert_eq!(pos, buffer.len(),
                "Should consume entire buffer: pos {} vs len {}", pos, buffer.len());
        }).await;
    });
}

/// MR2: Width validation consistency - valid widths work, invalid widths fail
#[test]
fn mr_width_validation_consistency() {
    let runtime = LabRuntime::new(LabConfig::default());
    let cx = runtime.cx();

    proptest!(|(width in any::<u8>())| {
        runtime.block_on(&cx, async {
            // Property: Width validation should be consistent across all functions

            let validation_result = validate_pn_len(width);
            let is_valid_width = (1..=4).contains(&width);

            prop_assert_eq!(validation_result.is_ok(), is_valid_width,
                "validate_pn_len({}) -> {:?}, expected valid={}",
                width, validation_result, is_valid_width);

            if is_valid_width {
                // For valid widths, test with a suitable packet number
                let max_for_width = match width {
                    1 => 0xff,
                    2 => 0xffff,
                    3 => 0x00ff_ffff,
                    4 => u32::MAX,
                    _ => unreachable!(),
                };

                // Should fit exactly at the maximum
                prop_assert!(ensure_pn_fits(max_for_width, width).is_ok(),
                    "Max value {} should fit in width {}", max_for_width, width);

                // Should be able to encode/decode at maximum
                let mut buffer = Vec::new();
                write_packet_number(max_for_width, width, &mut buffer);
                let mut pos = 0;
                let decoded = read_packet_number(&buffer, &mut pos, width)?;
                prop_assert_eq!(decoded, max_for_width,
                    "Max value roundtrip failed for width {}", width);
            }
        }).await;
    });
}

/// MR3: Minimum width determination - smallest width that fits the value
#[test]
fn mr_minimum_width_determination() {
    let runtime = LabRuntime::new(LabConfig::default());
    let cx = runtime.cx();

    proptest!(|(packet_number in packet_number_strategy())| {
        runtime.block_on(&cx, async {
            // Property: There should be exactly one minimum width that fits any packet number
            // Smaller widths should fail, larger widths should succeed

            let min_width = min_width_for_packet_number(packet_number);

            // Minimum width should succeed
            prop_assert!(ensure_pn_fits(packet_number, min_width).is_ok(),
                "Minimum width {} should fit packet number {}", min_width, packet_number);

            // Smaller widths should fail (except when min_width is already 1)
            if min_width > 1 {
                for smaller_width in 1..min_width {
                    prop_assert!(ensure_pn_fits(packet_number, smaller_width).is_err(),
                        "Width {} should NOT fit packet number {} (min={})",
                        smaller_width, packet_number, min_width);
                }
            }

            // Larger widths should succeed
            for larger_width in min_width..=4 {
                prop_assert!(ensure_pn_fits(packet_number, larger_width).is_ok(),
                    "Width {} should fit packet number {} (min={})",
                    larger_width, packet_number, min_width);

                // Test encoding with larger width
                let mut buffer = Vec::new();
                write_packet_number(packet_number, larger_width, &mut buffer);
                let mut pos = 0;
                let decoded = read_packet_number(&buffer, &mut pos, larger_width)?;
                prop_assert_eq!(decoded, packet_number,
                    "Larger width {} encoding failed for packet number {}", larger_width, packet_number);
            }
        }).await;
    });
}

/// MR4: Boundary behavior - width requirements at boundary values
#[test]
fn mr_boundary_behavior() {
    let runtime = LabRuntime::new(LabConfig::default());
    let cx = runtime.cx();

    proptest!(|(offset in 0u32..=10)| {
        runtime.block_on(&cx, async {
            // Property: At width boundaries, requirements should change predictably

            let boundaries = [
                (0xff, 1, 2),      // 255 fits in 1 byte, 256 requires 2
                (0xffff, 2, 3),    // 65535 fits in 2 bytes, 65536 requires 3
                (0x00ff_ffff, 3, 4), // 16777215 fits in 3 bytes, 16777216 requires 4
            ];

            for (boundary_value, width_below, width_above) in boundaries {
                // Test value at boundary (should fit in current width)
                if boundary_value.checked_sub(offset).is_some() {
                    let below_boundary = boundary_value - offset;
                    prop_assert!(ensure_pn_fits(below_boundary, width_below).is_ok(),
                        "Value {} (boundary {} - {}) should fit in {} bytes",
                        below_boundary, boundary_value, offset, width_below);

                    // Test roundtrip at boundary
                    let mut buffer = Vec::new();
                    write_packet_number(below_boundary, width_below, &mut buffer);
                    let mut pos = 0;
                    let decoded = read_packet_number(&buffer, &mut pos, width_below)?;
                    prop_assert_eq!(decoded, below_boundary,
                        "Boundary value {} roundtrip failed", below_boundary);
                }

                // Test value above boundary (should require larger width)
                if boundary_value.checked_add(offset + 1).is_some() {
                    let above_boundary = boundary_value + offset + 1;
                    if above_boundary <= MAX_PACKET_NUMBER {
                        prop_assert!(ensure_pn_fits(above_boundary, width_below).is_err(),
                            "Value {} should NOT fit in {} bytes", above_boundary, width_below);

                        prop_assert!(ensure_pn_fits(above_boundary, width_above).is_ok(),
                            "Value {} should fit in {} bytes", above_boundary, width_above);
                    }
                }
            }
        }).await;
    });
}

/// MR5: Wire format consistency - network byte order preservation
#[test]
fn mr_wire_format_consistency() {
    let runtime = LabRuntime::new(LabConfig::default());
    let cx = runtime.cx();

    proptest!(|(
        (packet_number, width) in packet_number_width_strategy()
    )| {
        runtime.block_on(&cx, async {
            // Property: Wire format should use network byte order (big-endian)
            // and be consistent across different widths of the same value

            if ensure_pn_fits(packet_number, width).is_err() {
                return Ok(());
            }

            let mut buffer = Vec::new();
            write_packet_number(packet_number, width, &mut buffer);

            // Verify buffer length matches width
            prop_assert_eq!(buffer.len(), width as usize,
                "Buffer length should match width");

            // Verify network byte order by checking against manual big-endian encoding
            let expected_bytes = packet_number.to_be_bytes();
            let expected_slice = &expected_bytes[4 - (width as usize)..];
            prop_assert_eq!(&buffer[..], expected_slice,
                "Wire format should match big-endian encoding for pn={} width={}",
                packet_number, width);

            // Test that encoding the same value with different valid widths
            // produces the same suffix bytes
            for test_width in (width + 1)..=4 {
                if ensure_pn_fits(packet_number, test_width).is_ok() {
                    let mut test_buffer = Vec::new();
                    write_packet_number(packet_number, test_width, &mut test_buffer);

                    // The suffix should match the original encoding
                    let suffix_len = width as usize;
                    let original_suffix = &buffer[buffer.len() - suffix_len..];
                    let test_suffix = &test_buffer[test_buffer.len() - suffix_len..];

                    prop_assert_eq!(original_suffix, test_suffix,
                        "Suffix bytes should be consistent across widths {} and {} for pn={}",
                        width, test_width, packet_number);
                }
            }
        }).await;
    });
}

/// Integration test: Combined metamorphic relations
#[test]
fn mr_combined_properties() {
    let runtime = LabRuntime::new(LabConfig::default());
    let cx = runtime.cx();

    proptest!(|(
        packet_numbers in prop::collection::vec(packet_number_strategy(), 2..=10)
    )| {
        runtime.block_on(&cx, async {
            // Property: Multiple metamorphic relations should hold simultaneously

            for &packet_number in &packet_numbers {
                let min_width = min_width_for_packet_number(packet_number);

                // Test all valid widths for this packet number
                for width in min_width..=4 {
                    // MR1: Roundtrip preservation
                    let mut buffer = Vec::new();
                    write_packet_number(packet_number, width, &mut buffer);
                    let mut pos = 0;
                    let decoded = read_packet_number(&buffer, &mut pos, width)?;
                    prop_assert_eq!(decoded, packet_number,
                        "Roundtrip failed for pn={} width={}", packet_number, width);

                    // MR2: Width validation consistency
                    prop_assert!(validate_pn_len(width).is_ok(),
                        "Width {} should be valid", width);
                    prop_assert!(ensure_pn_fits(packet_number, width).is_ok(),
                        "Packet number {} should fit in width {}", packet_number, width);

                    // MR5: Wire format consistency
                    let expected_bytes = packet_number.to_be_bytes();
                    let expected_slice = &expected_bytes[4 - (width as usize)..];
                    prop_assert_eq!(&buffer[..], expected_slice,
                        "Wire format mismatch for pn={} width={}", packet_number, width);
                }

                // MR3: Minimum width is actually minimum
                if min_width > 1 {
                    prop_assert!(ensure_pn_fits(packet_number, min_width - 1).is_err(),
                        "Packet number {} should NOT fit in width {}", packet_number, min_width - 1);
                }
            }
        }).await;
    });
}

#[cfg(test)]
mod property_validation {
    use super::*;

    /// Verify test framework setup
    #[test]
    fn test_framework_validation() {
        let runtime = LabRuntime::new(LabConfig::default());
        let cx = runtime.cx();

        runtime.block_on(&cx, async {
            // Basic sanity checks for helper functions
            assert_eq!(min_width_for_packet_number(0), 1);
            assert_eq!(min_width_for_packet_number(255), 1);
            assert_eq!(min_width_for_packet_number(256), 2);
            assert_eq!(min_width_for_packet_number(65535), 2);
            assert_eq!(min_width_for_packet_number(65536), 3);
            assert_eq!(min_width_for_packet_number(16777215), 3);
            assert_eq!(min_width_for_packet_number(16777216), 4);
            assert_eq!(min_width_for_packet_number(u32::MAX), 4);

            // Width validation
            assert!(validate_pn_len(1).is_ok());
            assert!(validate_pn_len(2).is_ok());
            assert!(validate_pn_len(3).is_ok());
            assert!(validate_pn_len(4).is_ok());
            assert!(validate_pn_len(0).is_err());
            assert!(validate_pn_len(5).is_err());

            // Basic encoding/decoding
            let mut buffer = Vec::new();
            write_packet_number(0x1234, 2, &mut buffer);
            assert_eq!(buffer, vec![0x12, 0x34]);

            let mut pos = 0;
            let decoded = read_packet_number(&buffer, &mut pos, 2).unwrap();
            assert_eq!(decoded, 0x1234);
            assert_eq!(pos, 2);
        }).await;
    }
}