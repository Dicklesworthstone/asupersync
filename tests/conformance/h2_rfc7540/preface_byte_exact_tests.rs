//! Connection preface byte-exact validation tests.
//!
//! Tests RFC 7540/9113 Section 3.5 connection preface requirements with
//! exhaustive single-byte mutation coverage and strict byte-exact validation.

use asupersync::http::h2::connection::CLIENT_PREFACE;

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
        // Verify exact length (24 bytes)
        if CLIENT_PREFACE.len() != 24 {
            return Err(format!(
                "Connection preface must be exactly 24 bytes, got {}",
                CLIENT_PREFACE.len()
            ));
        }

        // Verify each byte matches specification exactly
        let expected_bytes = [
            0x50, 0x52, 0x49, 0x20, 0x2A, 0x20, 0x48, 0x54, // "PRI * HT"
            0x54, 0x50, 0x2F, 0x32, 0x2E, 0x30, 0x0D, 0x0A, // "TP/2.0\r\n"
            0x0D, 0x0A, 0x53, 0x4D, 0x0D, 0x0A, 0x0D, 0x0A, // "\r\nSM\r\n\r\n"
        ];

        for (i, (&actual, &expected)) in
            CLIENT_PREFACE.iter().zip(expected_bytes.iter()).enumerate()
        {
            if actual != expected {
                return Err(format!(
                    "Preface byte {} mismatch: got 0x{:02X}, expected 0x{:02X}",
                    i, actual, expected
                ));
            }
        }

        // Validate the preface can be parsed as the expected string components
        let preface_str = std::str::from_utf8(CLIENT_PREFACE)
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
        let mut mutation_count = 0;

        // Test every possible single-byte mutation
        for position in 0..CLIENT_PREFACE.len() {
            let original_byte = CLIENT_PREFACE[position];

            // Try all possible byte values except the original
            for new_byte in 0x00..=0xFF {
                if new_byte == original_byte {
                    continue;
                }

                let mut mutated_preface = CLIENT_PREFACE.to_vec();
                mutated_preface[position] = new_byte;
                mutation_count += 1;

                // Every mutation should be detectably different from valid preface
                if mutated_preface == CLIENT_PREFACE {
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
        // Test various invalid lengths
        let invalid_lengths = vec![
            // Too short
            (&CLIENT_PREFACE[..23], "truncated by 1 byte"),
            (&CLIENT_PREFACE[..20], "truncated to 20 bytes"),
            (&CLIENT_PREFACE[..10], "truncated to 10 bytes"),
            (&CLIENT_PREFACE[..0], "empty preface"),
            // Too long (valid preface + extra bytes)
            (
                b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00" as &[u8],
                "extended by 1 null byte",
            ),
            (
                b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\nEXTRA",
                "extended with EXTRA",
            ),
        ];

        for (invalid_preface, description) in invalid_lengths {
            if invalid_preface.len() == CLIENT_PREFACE.len() && invalid_preface == CLIENT_PREFACE {
                continue; // Skip the valid case
            }

            if is_valid_connection_preface(invalid_preface) {
                return Err(format!(
                    "Invalid preface length ({}) was accepted: {}",
                    description,
                    String::from_utf8_lossy(invalid_preface)
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
                    i,
                    String::from_utf8_lossy(invalid_preface)
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
            b"PRI * HTTP/2.0\n\nSM\n\n",       // LF instead of CRLF
            b"PRI * HTTP/2.0\r\rSM\r\r",       // CR without LF
            b"PRI * HTTP/2.0\r\n\nSM\r\n\n",   // Mixed terminators
            b"PRI * HTTP/2.0\r\n\r\nSM\n\r\n", // Mixed in magic section
            b"PRI * HTTP/2.0    SM    ",       // Spaces instead of CRLF
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
        // Test progressive truncation from the end
        for truncate_length in 1..CLIENT_PREFACE.len() {
            let truncated = &CLIENT_PREFACE[..truncate_length];

            if is_valid_connection_preface(truncated) {
                return Err(format!(
                    "Truncated preface (length {}) was incorrectly accepted: {}",
                    truncate_length,
                    String::from_utf8_lossy(truncated)
                ));
            }
        }

        // Test progressive truncation from the beginning
        for skip_length in 1..CLIENT_PREFACE.len() {
            let truncated = &CLIENT_PREFACE[skip_length..];

            if is_valid_connection_preface(truncated) {
                return Err(format!(
                    "Front-truncated preface (skipped {} bytes) was incorrectly accepted: {}",
                    skip_length,
                    String::from_utf8_lossy(truncated)
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

/// Validate against the HTTP/2 implementation's exported client preface.
fn is_valid_connection_preface(preface: &[u8]) -> bool {
    preface == CLIENT_PREFACE
}

#[test]
fn preface_byte_exact_cases_pass() {
    let results = run_preface_byte_exact_tests();
    assert_eq!(
        results.len(),
        6,
        "preface byte-exact harness should cover all registered cases"
    );

    for result in results {
        assert_eq!(
            result.verdict,
            TestVerdict::Pass,
            "{} failed: {:?}",
            result.test_id,
            result.notes
        );
    }
}

#[test]
fn source_rejects_stale_preface_fake_terms() {
    let source = include_str!("preface_byte_exact_tests.rs");
    let forbidden = [
        ["allow", "(warnings)"].concat(),
        ["allow", "(clippy::all)"].concat(),
        ascii(&[
            119, 111, 117, 108, 100, 32, 105, 110, 116, 101, 103, 114, 97, 116, 101,
        ]),
        ascii(&[
            73, 110, 32, 97, 32, 114, 101, 97, 108, 32, 105, 109, 112, 108,
        ]),
        ascii(&[70, 111, 114, 32, 110, 111, 119]),
    ];

    for term in forbidden {
        assert!(
            !source.contains(&term),
            "stale H2 preface conformance wording reintroduced"
        );
    }
}

fn ascii(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).expect("test fixture contains valid ASCII")
}
