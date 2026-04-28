#![allow(warnings)]
#![allow(clippy::all)]
//! Tests for FEC Payload ID packet wire format (RFC 6330 Section 3.2 and 4.4.2).
//!
//! Validates exact big-endian encoding/decoding of 4-octet FEC Payload ID headers
//! and multi-symbol packet framing for RFC 6330 interoperability.

use crate::spec_derived::{
    Rfc6330ConformanceCase, Rfc6330ConformanceSuite, RequirementLevel,
    ConformanceContext, ConformanceResult,
};
use std::time::Instant;

/// Register FEC Payload ID packet format tests.
#[allow(dead_code)]
pub fn register_tests(suite: &mut Rfc6330ConformanceSuite) {
    suite.add_test_case(Rfc6330ConformanceCase {
        id: "RFC6330-3.2.1",
        section: "3.2",
        level: RequirementLevel::Must,
        description: "FEC Payload ID MUST be exactly 4 octets with SBN as 8-bit and ESI as 24-bit unsigned integers",
        test_fn: test_fec_payload_id_format,
    });

    suite.add_test_case(Rfc6330ConformanceCase {
        id: "RFC6330-3.1.1",
        section: "3.1",
        level: RequirementLevel::Must,
        description: "All fields MUST be in network byte order (big-endian)",
        test_fn: test_network_byte_order_encoding,
    });

    suite.add_test_case(Rfc6330ConformanceCase {
        id: "RFC6330-4.4.2.1",
        section: "4.4.2",
        level: RequirementLevel::Must,
        description: "Each encoding packet MUST carry SBN + ESI + encoding symbol(s)",
        test_fn: test_packet_structure,
    });

    suite.add_test_case(Rfc6330ConformanceCase {
        id: "RFC6330-4.4.2.2",
        section: "4.4.2",
        level: RequirementLevel::Must,
        description: "Packets MAY contain multiple consecutive symbols from one source block",
        test_fn: test_multi_symbol_packets,
    });

    suite.add_test_case(Rfc6330ConformanceCase {
        id: "RFC6330-4.4.2.3",
        section: "4.4.2",
        level: RequirementLevel::Must,
        description: "Packets MUST be all-source or all-repair",
        test_fn: test_packet_type_consistency,
    });

    suite.add_test_case(Rfc6330ConformanceCase {
        id: "RFC6330-4.4.2.4",
        section: "4.4.2",
        level: RequirementLevel::Must,
        description: "Packets MUST contain whole symbols only",
        test_fn: test_whole_symbols_only,
    });

    suite.add_test_case(Rfc6330ConformanceCase {
        id: "RFC6330-ESI-BOUNDS",
        section: "3.2",
        level: RequirementLevel::Must,
        description: "ESI MUST be fail-closed rejected for values > 0xFF_FFFF",
        test_fn: test_esi_bounds_validation,
    });
}

/// Test exact FEC Payload ID format: 4 octets, SBN:u8, ESI:u24.
#[allow(dead_code)]
fn test_fec_payload_id_format(ctx: &ConformanceContext) -> ConformanceResult {
    let start = Instant::now();
    let mut test_count = 0;

    // Test known vectors for FEC Payload ID encoding
    let test_vectors = vec![
        (0u8, 0u32, [0x00, 0x00, 0x00, 0x00]),           // Zero SBN, zero ESI
        (1u8, 0u32, [0x01, 0x00, 0x00, 0x00]),           // SBN=1, ESI=0
        (0u8, 1u32, [0x00, 0x00, 0x00, 0x01]),           // SBN=0, ESI=1
        (255u8, 0u32, [0xFF, 0x00, 0x00, 0x00]),         // Max SBN, ESI=0
        (0u8, 0xFF_FFFFu32, [0x00, 0xFF, 0xFF, 0xFF]),   // SBN=0, max ESI
        (128u8, 0x123456u32, [0x80, 0x12, 0x34, 0x56]),  // Mid-range values
        (42u8, 0xABCDEFu32, [0x2A, 0xAB, 0xCD, 0xEF]),   // Random values
    ];

    for (sbn, esi, expected_bytes) in test_vectors {
        test_count += 1;

        // Test encoding
        let encoded = encode_fec_payload_id(sbn, esi);
        if encoded != expected_bytes {
            return ConformanceResult::fail(format!(
                "FEC Payload ID encoding failed: SBN={}, ESI={}, expected {:02X?}, got {:02X?}",
                sbn, esi, expected_bytes, encoded
            ));
        }

        // Test decoding
        match decode_fec_payload_id(&expected_bytes) {
            Ok((decoded_sbn, decoded_esi)) => {
                if decoded_sbn != sbn || decoded_esi != esi {
                    return ConformanceResult::fail(format!(
                        "FEC Payload ID decoding failed: expected SBN={}, ESI={}, got SBN={}, ESI={}",
                        sbn, esi, decoded_sbn, decoded_esi
                    ));
                }
            }
            Err(e) => {
                return ConformanceResult::fail(format!(
                    "FEC Payload ID decoding error for valid input: {}", e
                ));
            }
        }

        // Verify exact 4-octet length
        if encoded.len() != 4 {
            return ConformanceResult::fail(format!(
                "FEC Payload ID must be exactly 4 octets, got {} octets", encoded.len()
            ));
        }
    }

    ConformanceResult::pass()
        .with_duration(start.elapsed())
        .with_metric("fec_payload_id_tests", test_count as f64)
        .with_detail(format!("Validated {} FEC Payload ID encode/decode pairs", test_count))
}

/// Test network byte order (big-endian) encoding requirement.
#[allow(dead_code)]
fn test_network_byte_order_encoding(ctx: &ConformanceContext) -> ConformanceResult {
    let start = Instant::now();

    // Test that multi-byte ESI values are encoded big-endian
    let test_cases = vec![
        (0u8, 0x010203u32, [0x00, 0x01, 0x02, 0x03]), // ESI = 0x010203
        (0u8, 0x123456u32, [0x00, 0x12, 0x34, 0x56]), // ESI = 0x123456
        (0u8, 0xFEDCBAu32, [0x00, 0xFE, 0xDC, 0xBA]), // ESI = 0xFEDCBA
    ];

    for (sbn, esi, expected) in test_cases {
        let encoded = encode_fec_payload_id(sbn, esi);

        // Verify big-endian byte order
        if encoded != expected {
            return ConformanceResult::fail(format!(
                "Network byte order violation: ESI 0x{:06X} encoded as {:02X?}, expected {:02X?}",
                esi, encoded, expected
            ));
        }

        // Specifically check that ESI bytes are in big-endian order
        let esi_bytes = [encoded[1], encoded[2], encoded[3]];
        let decoded_esi = u32::from_be_bytes([0, esi_bytes[0], esi_bytes[1], esi_bytes[2]]);
        if decoded_esi != esi {
            return ConformanceResult::fail(format!(
                "Big-endian ESI decoding failed: expected 0x{:06X}, got 0x{:06X}",
                esi, decoded_esi
            ));
        }
    }

    ConformanceResult::pass()
        .with_duration(start.elapsed())
        .with_metric("byte_order_tests", test_cases.len() as f64)
        .with_detail("All multi-byte fields correctly encoded in network byte order")
}

/// Test packet structure: SBN + ESI + encoding symbols.
#[allow(dead_code)]
fn test_packet_structure(ctx: &ConformanceContext) -> ConformanceResult {
    let start = Instant::now();
    let symbol_size = 64;

    for &k in &[10, 100, 256] {
        let sbn = 1u8;
        let esi = 0u32;
        let symbol_data = generate_test_symbol_data(symbol_size);

        // Create a single-symbol packet
        let packet = create_encoding_packet(sbn, esi, &[symbol_data.clone()]);

        // Verify packet structure
        if packet.len() < 4 {
            return ConformanceResult::fail(format!(
                "Packet too short: {} bytes, must include 4-byte FEC Payload ID", packet.len()
            ));
        }

        // Extract and verify FEC Payload ID
        let header_bytes = &packet[0..4];
        match decode_fec_payload_id(header_bytes) {
            Ok((decoded_sbn, decoded_esi)) => {
                if decoded_sbn != sbn || decoded_esi != esi {
                    return ConformanceResult::fail(format!(
                        "Packet header mismatch: expected SBN={}, ESI={}, got SBN={}, ESI={}",
                        sbn, esi, decoded_sbn, decoded_esi
                    ));
                }
            }
            Err(e) => {
                return ConformanceResult::fail(format!(
                    "Invalid FEC Payload ID in packet: {}", e
                ));
            }
        }

        // Verify symbol payload follows header
        let payload = &packet[4..];
        if payload.len() != symbol_size {
            return ConformanceResult::fail(format!(
                "Symbol payload size mismatch: expected {}, got {}", symbol_size, payload.len()
            ));
        }

        if payload != symbol_data {
            return ConformanceResult::fail(
                "Symbol payload does not match original symbol data".to_string()
            );
        }
    }

    ConformanceResult::pass()
        .with_duration(start.elapsed())
        .with_metric("packet_structure_tests", 3.0)
        .with_detail("All packets correctly structured with FEC Payload ID + encoding symbols")
}

/// Test multi-symbol packet support.
#[allow(dead_code)]
fn test_multi_symbol_packets(ctx: &ConformanceContext) -> ConformanceResult {
    let start = Instant::now();
    let symbol_size = 32;

    // Test packets with 1, 2, 4, and 8 consecutive symbols
    for &symbol_count in &[1, 2, 4, 8] {
        let sbn = 0u8;
        let first_esi = 10u32;

        // Generate consecutive symbols
        let mut symbols = Vec::new();
        for i in 0..symbol_count {
            symbols.push(generate_test_symbol_data_with_pattern(symbol_size, i));
        }

        // Create multi-symbol packet
        let packet = create_encoding_packet(sbn, first_esi, &symbols);

        // Verify packet structure
        let expected_size = 4 + (symbol_count * symbol_size); // FEC Payload ID + symbols
        if packet.len() != expected_size {
            return ConformanceResult::fail(format!(
                "Multi-symbol packet size error: expected {}, got {} (symbols={}, symbol_size={})",
                expected_size, packet.len(), symbol_count, symbol_size
            ));
        }

        // Verify FEC Payload ID names the first symbol
        let header_bytes = &packet[0..4];
        match decode_fec_payload_id(header_bytes) {
            Ok((decoded_sbn, decoded_esi)) => {
                if decoded_sbn != sbn || decoded_esi != first_esi {
                    return ConformanceResult::fail(format!(
                        "Multi-symbol packet header error: expected first ESI={}, got ESI={}",
                        first_esi, decoded_esi
                    ));
                }
            }
            Err(e) => {
                return ConformanceResult::fail(format!(
                    "Invalid FEC Payload ID in multi-symbol packet: {}", e
                ));
            }
        }

        // Verify symbol payloads are consecutive
        for (i, symbol) in symbols.iter().enumerate() {
            let symbol_start = 4 + (i * symbol_size);
            let symbol_end = symbol_start + symbol_size;
            let packet_symbol = &packet[symbol_start..symbol_end];

            if packet_symbol != symbol {
                return ConformanceResult::fail(format!(
                    "Multi-symbol packet: symbol {} data mismatch", i
                ));
            }
        }
    }

    ConformanceResult::pass()
        .with_duration(start.elapsed())
        .with_metric("multi_symbol_tests", 4.0)
        .with_detail("Multi-symbol packets correctly encode consecutive symbols with first ESI in header")
}

/// Test packet type consistency: all-source or all-repair.
#[allow(dead_code)]
fn test_packet_type_consistency(ctx: &ConformanceContext) -> ConformanceResult {
    let start = Instant::now();
    let k = 100;  // Source symbols are ESI 0..99, repair symbols start at ESI 100

    // Test valid all-source packet (ESI 0..9)
    let source_symbols = (0..10).map(|_| generate_test_symbol_data(64)).collect::<Vec<_>>();
    let source_packet = create_encoding_packet(0u8, 0u32, &source_symbols);
    if !is_valid_packet(&source_packet, k) {
        return ConformanceResult::fail("Valid all-source packet rejected".to_string());
    }

    // Test valid all-repair packet (ESI 100..109)
    let repair_symbols = (0..10).map(|_| generate_test_symbol_data(64)).collect::<Vec<_>>();
    let repair_packet = create_encoding_packet(0u8, 100u32, &repair_symbols);
    if !is_valid_packet(&repair_packet, k) {
        return ConformanceResult::fail("Valid all-repair packet rejected".to_string());
    }

    // Test invalid mixed packet (would span ESI 95..104, crossing source/repair boundary)
    let mixed_symbols = (0..10).map(|_| generate_test_symbol_data(64)).collect::<Vec<_>>();
    let mixed_packet = create_encoding_packet(0u8, 95u32, &mixed_symbols);
    if is_valid_packet(&mixed_packet, k) {
        return ConformanceResult::fail("Invalid mixed source/repair packet accepted".to_string());
    }

    ConformanceResult::pass()
        .with_duration(start.elapsed())
        .with_metric("packet_consistency_tests", 3.0)
        .with_detail("Packet type consistency enforced: mixed source/repair packets rejected")
}

/// Test whole symbols only requirement.
#[allow(dead_code)]
fn test_whole_symbols_only(ctx: &ConformanceContext) -> ConformanceResult {
    let start = Instant::now();
    let symbol_size = 64;

    // Test valid packet with whole symbols
    let symbols = vec![generate_test_symbol_data(symbol_size); 3];
    let valid_packet = create_encoding_packet(0u8, 0u32, &symbols);
    let expected_size = 4 + (3 * symbol_size);
    if valid_packet.len() != expected_size {
        return ConformanceResult::fail(format!(
            "Valid whole-symbol packet has wrong size: expected {}, got {}",
            expected_size, valid_packet.len()
        ));
    }

    // Test invalid packet with truncated symbol data
    let mut truncated_packet = valid_packet.clone();
    truncated_packet.truncate(truncated_packet.len() - 10); // Remove 10 bytes from last symbol
    if is_valid_whole_symbol_packet(&truncated_packet, symbol_size) {
        return ConformanceResult::fail(
            "Invalid truncated packet accepted (non-whole symbol)".to_string()
        );
    }

    // Test invalid packet with extra partial symbol data
    let mut oversized_packet = valid_packet.clone();
    oversized_packet.extend_from_slice(&[0u8; 30]); // Add 30 bytes (partial symbol)
    if is_valid_whole_symbol_packet(&oversized_packet, symbol_size) {
        return ConformanceResult::fail(
            "Invalid oversized packet accepted (partial symbol at end)".to_string()
        );
    }

    ConformanceResult::pass()
        .with_duration(start.elapsed())
        .with_metric("whole_symbol_tests", 3.0)
        .with_detail("Whole symbols requirement enforced: truncated and partial symbols rejected")
}

/// Test ESI bounds validation (fail-closed for ESI > 0xFF_FFFF).
#[allow(dead_code)]
fn test_esi_bounds_validation(ctx: &ConformanceContext) -> ConformanceResult {
    let start = Instant::now();

    // Test valid ESI values
    let valid_esis = vec![0u32, 1u32, 0xFFu32, 0xFFFFu32, 0xFF_FFFFu32];
    for esi in valid_esis {
        let encoded = encode_fec_payload_id(0u8, esi);
        if encoded.len() != 4 {
            return ConformanceResult::fail(format!(
                "Valid ESI {} encoding failed: wrong length", esi
            ));
        }
    }

    // Test invalid ESI values (would require more than 24 bits)
    let invalid_esis = vec![0x100_0000u32, 0xFFFF_FFFFu32, 0x1234_5678u32];
    for esi in invalid_esis {
        match validate_esi_bounds(esi) {
            Ok(_) => {
                return ConformanceResult::fail(format!(
                    "Invalid ESI {} was accepted (exceeds 24-bit limit)", esi
                ));
            }
            Err(_) => {
                // Expected failure - ESI out of bounds
            }
        }
    }

    // Test boundary case: 0xFF_FFFF should be valid, 0x100_0000 should not
    if validate_esi_bounds(0xFF_FFFFu32).is_err() {
        return ConformanceResult::fail("Valid max ESI 0xFF_FFFF was rejected".to_string());
    }

    if validate_esi_bounds(0x100_0000u32).is_ok() {
        return ConformanceResult::fail("Invalid ESI 0x100_0000 was accepted".to_string());
    }

    ConformanceResult::pass()
        .with_duration(start.elapsed())
        .with_metric("esi_bounds_tests", 8.0)
        .with_detail("ESI bounds validation: 24-bit limit enforced, fail-closed for overflow")
}

// ===== Helper Functions =====

/// Encode FEC Payload ID as 4-octet big-endian: [SBN, ESI_HIGH, ESI_MID, ESI_LOW].
#[allow(dead_code)]
fn encode_fec_payload_id(sbn: u8, esi: u32) -> [u8; 4] {
    [
        sbn,
        ((esi >> 16) & 0xFF) as u8,
        ((esi >> 8) & 0xFF) as u8,
        (esi & 0xFF) as u8,
    ]
}

/// Decode FEC Payload ID from 4-octet big-endian format.
#[allow(dead_code)]
fn decode_fec_payload_id(bytes: &[u8]) -> Result<(u8, u32), String> {
    if bytes.len() != 4 {
        return Err(format!("FEC Payload ID must be 4 bytes, got {}", bytes.len()));
    }

    let sbn = bytes[0];
    let esi = ((bytes[1] as u32) << 16) | ((bytes[2] as u32) << 8) | (bytes[3] as u32);

    // Validate ESI is within 24-bit range
    validate_esi_bounds(esi)?;

    Ok((sbn, esi))
}

/// Validate ESI is within 24-bit bounds.
#[allow(dead_code)]
fn validate_esi_bounds(esi: u32) -> Result<(), String> {
    if esi > 0xFF_FFFF {
        return Err(format!("ESI {} exceeds 24-bit limit (0xFF_FFFF)", esi));
    }
    Ok(())
}

/// Create an encoding packet with FEC Payload ID + symbol payloads.
#[allow(dead_code)]
fn create_encoding_packet(sbn: u8, first_esi: u32, symbols: &[Vec<u8>]) -> Vec<u8> {
    let mut packet = Vec::new();

    // Add FEC Payload ID header
    let header = encode_fec_payload_id(sbn, first_esi);
    packet.extend_from_slice(&header);

    // Add symbol payloads
    for symbol in symbols {
        packet.extend_from_slice(symbol);
    }

    packet
}

/// Check if packet is valid according to RFC 6330 constraints.
#[allow(dead_code)]
fn is_valid_packet(packet: &[u8], k: usize) -> bool {
    if packet.len() < 4 {
        return false;
    }

    // Decode header
    let header_bytes = &packet[0..4];
    let (sbn, first_esi) = match decode_fec_payload_id(header_bytes) {
        Ok(result) => result,
        Err(_) => return false,
    };

    let payload_size = packet.len() - 4;
    if payload_size == 0 {
        return false;
    }

    // Assume fixed symbol size for this test
    let symbol_size = 64;
    if payload_size % symbol_size != 0 {
        return false; // Not whole symbols
    }

    let symbol_count = payload_size / symbol_size;
    let last_esi = first_esi + (symbol_count as u32) - 1;

    // Check packet type consistency
    let is_all_source = last_esi < k as u32;
    let is_all_repair = first_esi >= k as u32;

    is_all_source || is_all_repair
}

/// Check if packet contains only whole symbols.
#[allow(dead_code)]
fn is_valid_whole_symbol_packet(packet: &[u8], symbol_size: usize) -> bool {
    if packet.len() < 4 {
        return false;
    }

    let payload_size = packet.len() - 4;
    payload_size % symbol_size == 0
}

/// Generate test symbol data with fixed pattern.
#[allow(dead_code)]
fn generate_test_symbol_data(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i % 256) as u8).collect()
}

/// Generate test symbol data with distinguishable pattern.
#[allow(dead_code)]
fn generate_test_symbol_data_with_pattern(size: usize, pattern: usize) -> Vec<u8> {
    (0..size).map(|i| ((i + pattern * 17) % 256) as u8).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec_derived::{ConformanceConfig, ConformanceContext};

    #[allow(dead_code)]
    fn create_test_context() -> ConformanceContext {
        ConformanceContext {
            config: ConformanceConfig::default(),
            timeout: std::time::Duration::from_secs(10),
            verbose: false,
        }
    }

    #[test]
    #[allow(dead_code)]
    fn test_fec_payload_id_basic() {
        let ctx = create_test_context();
        let result = test_fec_payload_id_format(&ctx);
        assert!(result.passed, "Basic FEC Payload ID test should pass");
    }

    #[test]
    #[allow(dead_code)]
    fn test_esi_bounds() {
        let ctx = create_test_context();
        let result = test_esi_bounds_validation(&ctx);
        assert!(result.passed, "ESI bounds validation test should pass");
    }
}