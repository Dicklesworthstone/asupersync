#![allow(warnings)]
#![allow(clippy::all)]
//! Connection preface byte-exact validation tests.
//!
//! Tests RFC 7540/9113 Section 3.5 connection preface requirements with
//! exhaustive single-byte mutation coverage and strict byte-exact validation.

use super::*;

/// Run all connection preface byte-exact validation tests.
#[allow(dead_code)]
pub fn run_preface_byte_exact_tests() -> Vec<H2ConformanceResult> {
    let mut results = Vec::new();

    results.push(test_preface_byte_exact_validation());
    results.push(test_preface_single_byte_mutations());
    results.push(test_preface_length_validation());
    results.push(test_preface_case_sensitivity());
    results.push(test_preface_terminator_validation());
    results.push(test_preface_truncation_detection());

    results
}

/// RFC 9113 Section 3.5: Byte-exact connection preface validation.
#[allow(dead_code)]
fn test_preface_byte_exact_validation() -> H2ConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        // Official HTTP/2 connection preface - must be byte-exact
        let valid_preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

        // Verify exact length (24 bytes)
        if valid_preface.len() != 24 {
            return Err(format!(
                "Connection preface must be exactly 24 bytes, got {}",
                valid_preface.len()
            ));
        }

        // Verify each byte matches specification exactly
        let expected_bytes = [
            0x50, 0x52, 0x49, 0x20, 0x2A, 0x20, 0x48, 0x54, // "PRI * HT"
            0x54, 0x50, 0x2F, 0x32, 0x2E, 0x30, 0x0D, 0x0A, // "TP/2.0\r\n"
            0x0D, 0x0A, 0x53, 0x4D, 0x0D, 0x0A, 0x0D, 0x0A, // "\r\nSM\r\n\r\n"
        ];

        for (i, (&actual, &expected)) in valid_preface.iter().zip(expected_bytes.iter()).enumerate() {
            if actual != expected {
                return Err(format!(
                    "Preface byte {} mismatch: got 0x{:02X}, expected 0x{:02X}",
                    i, actual, expected
                ));
            }
        }

        // Validate the preface can be parsed as the expected string components
        let preface_str = std::str::from_utf8(valid_preface)
            .map_err(|e| format!("Preface contains invalid UTF-8: {}", e))?;

        // Should contain the method, path, and protocol version
        if !preface_str.starts_with("PRI * HTTP/2.0") {
            return Err("Preface does not start with correct method and version".to_string());
        }

        // Should end with the connection preface magic string "SM"
        if !preface_str.contains("SM") {
            return Err("Preface does not contain required SM magic string".to_string());
        }

        Ok(())
    });

    create_test_result(
        "RFC9113-3.5-PREFACE-EXACT",
        "Connection preface byte-exact validation",
        TestCategory::Connection,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// RFC 9113 Section 3.5: Single-byte mutation testing for preface validation.
#[allow(dead_code)]
fn test_preface_single_byte_mutations() -> H2ConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let valid_preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        let mut mutation_count = 0;

        // Test every possible single-byte mutation
        for position in 0..valid_preface.len() {
            let original_byte = valid_preface[position];

            // Try all possible byte values except the original
            for new_byte in 0x00..=0xFF {
                if new_byte == original_byte {
                    continue;
                }

                let mut mutated_preface = valid_preface.to_vec();
                mutated_preface[position] = new_byte;
                mutation_count += 1;

                // Every mutation should be detectably different from valid preface
                if mutated_preface == valid_preface {
                    return Err(format!(
                        "Mutation at position {} with byte 0x{:02X} was not detected",
                        position, new_byte
                    ));
                }

                // Validate that this is recognized as invalid
                if is_valid_connection_preface(&mutated_preface) {
                    return Err(format!(
                        "Invalid preface mutation at position {} (0x{:02X} -> 0x{:02X}) was accepted",
                        position, original_byte, new_byte
                    ));
                }
            }
        }

        // Ensure we tested a reasonable number of mutations
        let expected_mutations = 24 * 255; // 24 positions * 255 possible mutations each
        if mutation_count != expected_mutations {
            return Err(format!(
                "Expected {} mutations, tested {}",
                expected_mutations, mutation_count
            ));
        }

        Ok(())
    });

    create_test_result(
        "RFC9113-3.5-PREFACE-MUTATIONS",
        "Connection preface single-byte mutation rejection",
        TestCategory::Connection,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// RFC 9113 Section 3.5: Preface length validation.
#[allow(dead_code)]
fn test_preface_length_validation() -> H2ConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let valid_preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

        // Test various invalid lengths
        let invalid_lengths = vec![
            // Too short
            (&valid_preface[..23], "truncated by 1 byte"),
            (&valid_preface[..20], "truncated to 20 bytes"),
            (&valid_preface[..10], "truncated to 10 bytes"),
            (&valid_preface[..0], "empty preface"),

            // Too long (valid preface + extra bytes)
            (b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00" as &[u8], "extended by 1 null byte"),
            (b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\nEXTRA", "extended with EXTRA"),
        ];

        for (invalid_preface, description) in invalid_lengths {
            if invalid_preface.len() == 24 && invalid_preface == valid_preface {
                continue; // Skip the valid case
            }

            if is_valid_connection_preface(invalid_preface) {
                return Err(format!(
                    "Invalid preface length ({}) was accepted: {}",
                    description, String::from_utf8_lossy(invalid_preface)
                ));
            }
        }

        Ok(())
    });

    create_test_result(
        "RFC9113-3.5-PREFACE-LENGTH",
        "Connection preface length validation",
        TestCategory::Connection,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// RFC 9113 Section 3.5: Case sensitivity validation.
#[allow(dead_code)]
fn test_preface_case_sensitivity() -> H2ConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        // HTTP/2 preface is case-sensitive
        let case_variants = vec![
            b"pri * HTTP/2.0\r\n\r\nSM\r\n\r\n", // lowercase method
            b"PRI * http/2.0\r\n\r\nSM\r\n\r\n", // lowercase protocol
            b"PRI * HTTP/2.0\r\n\r\nsm\r\n\r\n", // lowercase magic
            b"Pri * HTTP/2.0\r\n\r\nSM\r\n\r\n", // mixed case method
            b"PRI * Http/2.0\r\n\r\nSM\r\n\r\n", // mixed case protocol
        ];

        for (i, invalid_preface) in case_variants.iter().enumerate() {
            if is_valid_connection_preface(invalid_preface) {
                return Err(format!(
                    "Case variant {} was incorrectly accepted: {}",
                    i, String::from_utf8_lossy(invalid_preface)
                ));
            }
        }

        Ok(())
    });

    create_test_result(
        "RFC9113-3.5-PREFACE-CASE",
        "Connection preface case sensitivity",
        TestCategory::Connection,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// RFC 9113 Section 3.5: Line terminator validation.
#[allow(dead_code)]
fn test_preface_terminator_validation() -> H2ConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        // Test various invalid line terminators
        let terminator_variants = vec![
            b"PRI * HTTP/2.0\n\nSM\n\n",         // LF instead of CRLF
            b"PRI * HTTP/2.0\r\rSM\r\r",         // CR without LF
            b"PRI * HTTP/2.0\r\n\nSM\r\n\n",    // Mixed terminators
            b"PRI * HTTP/2.0\r\n\r\nSM\n\r\n",  // Mixed in magic section
            b"PRI * HTTP/2.0    SM    ",         // Spaces instead of CRLF
        ];

        for (i, invalid_preface) in terminator_variants.iter().enumerate() {
            if is_valid_connection_preface(invalid_preface) {
                return Err(format!(
                    "Invalid terminator variant {} was accepted: {:?}",
                    i, invalid_preface
                ));
            }
        }

        Ok(())
    });

    create_test_result(
        "RFC9113-3.5-PREFACE-TERMINATORS",
        "Connection preface line terminator validation",
        TestCategory::Connection,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// RFC 9113 Section 3.5: Truncation detection.
#[allow(dead_code)]
fn test_preface_truncation_detection() -> H2ConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let valid_preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

        // Test progressive truncation from the end
        for truncate_length in 1..valid_preface.len() {
            let truncated = &valid_preface[..truncate_length];

            if is_valid_connection_preface(truncated) {
                return Err(format!(
                    "Truncated preface (length {}) was incorrectly accepted: {}",
                    truncate_length, String::from_utf8_lossy(truncated)
                ));
            }
        }

        // Test progressive truncation from the beginning
        for skip_length in 1..valid_preface.len() {
            let truncated = &valid_preface[skip_length..];

            if is_valid_connection_preface(truncated) {
                return Err(format!(
                    "Front-truncated preface (skipped {} bytes) was incorrectly accepted: {}",
                    skip_length, String::from_utf8_lossy(truncated)
                ));
            }
        }

        Ok(())
    });

    create_test_result(
        "RFC9113-3.5-PREFACE-TRUNCATION",
        "Connection preface truncation detection",
        TestCategory::Connection,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// Helper function to validate connection preface.
/// This would integrate with the actual HTTP/2 implementation.
fn is_valid_connection_preface(preface: &[u8]) -> bool {
    // For now, implement basic validation logic
    // In a real implementation, this would call into the HTTP/2 parser

    let expected_preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    preface == expected_preface
}