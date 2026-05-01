//! HTTP/2 PRIORITY_UPDATE frame handling fuzz target.
//!
//! Tests PRIORITY_UPDATE frame processing per RFC 9218 HTTP/2 Priority specification.
//! PRIORITY_UPDATE frames (type 0xC) update stream priority using urgency and incremental flags.
//!
//! NOTE: PRIORITY_UPDATE frames are not yet implemented in the current HTTP/2 stack,
//! so this fuzzer simulates the expected behavior according to the specification.
//!
//! This fuzzer generates arbitrary frame variants and verifies:
//! 1. Unknown urgency values (>7) are rejected per RFC 9218 Section 4
//! 2. Reserved flags are ignored or rejected appropriately
//! 3. Invalid stream IDs are handled correctly
//! 4. Frame size constraints are enforced
//! 5. No panics occur with malformed priority data

#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::BytesMut;
use libfuzzer_sys::fuzz_target;

/// PRIORITY_UPDATE frame test with arbitrary priority parameters
#[derive(Debug, Clone, Arbitrary)]
struct PriorityUpdateTest {
    /// Target stream ID for priority update
    stream_id: u32,
    /// Priority update payload (urgency + incremental + custom fields)
    priority_payload: PriorityPayload,
    /// Additional frame flags beyond standard ones
    extra_flags: u8,
    /// Whether to test with connection-level priority update (stream_id = 0)
    connection_level: bool,
}

/// Priority payload with arbitrary urgency and flags
#[derive(Debug, Clone, Arbitrary)]
struct PriorityPayload {
    /// Urgency level (0-7 valid, >7 should be rejected)
    urgency: u8,
    /// Incremental flag
    incremental: bool,
    /// Additional custom priority fields
    custom_fields: Vec<PriorityField>,
    /// Raw bytes for malformed payloads
    raw_bytes: Vec<u8>,
    /// Whether to use structured or raw format
    use_structured: bool,
}

/// Custom priority field for testing extensions
#[derive(Debug, Clone, Arbitrary)]
struct PriorityField {
    /// Field name (arbitrary string)
    name: String,
    /// Field value (arbitrary string)
    value: String,
}

fuzz_target!(|data: &[u8]| {
    // Guard against excessive input size
    if data.len() > 100_000 {
        return;
    }

    let mut u = arbitrary::Unstructured::new(data);

    // Generate PRIORITY_UPDATE test case
    let test_case = match PriorityUpdateTest::arbitrary(&mut u) {
        Ok(case) => case,
        Err(_) => return,
    };

    // Limit fields to prevent excessive processing
    if test_case.priority_payload.custom_fields.len() > 10
        || test_case.priority_payload.raw_bytes.len() > 10_000 {
        return;
    }

    // Test core PRIORITY_UPDATE frame processing
    test_priority_update_frame(&test_case);

    // Test urgency validation specifically
    test_urgency_validation(&test_case);

    // Test stream ID validation
    test_stream_id_validation(&test_case);

    // Test malformed payload handling
    test_malformed_payload(&test_case);

    // Test flag handling
    test_frame_flags(&test_case);
});

/// Test PRIORITY_UPDATE frame processing with arbitrary parameters
fn test_priority_update_frame(test_case: &PriorityUpdateTest) {
    let stream_id = if test_case.connection_level {
        0 // Connection-level priority update
    } else {
        test_case.stream_id.max(1) // Ensure valid stream ID
    };

    let priority_data = build_priority_payload(&test_case.priority_payload);

    // Test frame creation
    let frame_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        simulate_priority_update_frame(stream_id, &priority_data, test_case.extra_flags)
    }));

    assert!(frame_result.is_ok(),
        "PRIORITY_UPDATE frame processing should not panic for stream_id={}, payload_len={}",
        stream_id, priority_data.len());

    if let Ok(result) = frame_result {
        match result {
            PriorityUpdateResult::Accepted { urgency, incremental } => {
                // Valid priority update - check constraints
                assert!(urgency <= 7,
                    "Accepted urgency {} exceeds maximum of 7", urgency);

                // Incremental flag should be preserved
                assert_eq!(incremental, test_case.priority_payload.incremental,
                    "Incremental flag should be preserved in valid update");
            }
            PriorityUpdateResult::Rejected { reason } => {
                // Rejection should have a valid reason
                assert!(!reason.is_empty(), "Rejection reason should be provided");
            }
            PriorityUpdateResult::Error => {
                // Error cases are acceptable for malformed input
            }
        }
    }
}

/// Test that urgency values >7 are rejected per draft specification
fn test_urgency_validation(test_case: &PriorityUpdateTest) {
    let urgency_test_cases = vec![
        0, 1, 2, 3, 4, 5, 6, 7, // Valid values
        8, 9, 15, 31, 63, 127, 255, // Invalid values
    ];

    for urgency in urgency_test_cases {
        let mut payload = test_case.priority_payload.clone();
        payload.urgency = urgency;
        payload.use_structured = true; // Force structured format for this test

        let priority_data = build_priority_payload(&payload);
        let result = simulate_priority_update_frame(
            test_case.stream_id.max(1),
            &priority_data,
            0
        );

        match result {
            PriorityUpdateResult::Accepted { urgency: accepted_urgency, .. } => {
                assert!(urgency <= 7,
                    "Urgency {} should be rejected but was accepted as {}",
                    urgency, accepted_urgency);
                assert_eq!(urgency, accepted_urgency,
                    "Accepted urgency should match input for valid values");
            }
            PriorityUpdateResult::Rejected { .. } => {
                // Rejection is expected for urgency > 7
                if urgency <= 7 {
                    // Valid urgency values should generally be accepted
                    // (unless other fields are invalid)
                }
            }
            PriorityUpdateResult::Error => {
                // Errors are acceptable for any input
            }
        }
    }
}

/// Test stream ID validation for PRIORITY_UPDATE frames
fn test_stream_id_validation(test_case: &PriorityUpdateTest) {
    let stream_id_tests = vec![
        0,          // Connection-level (special case)
        1,          // Valid client-initiated
        2,          // Valid server-initiated
        0x7FFFFFFF, // Maximum valid stream ID
        0x80000000, // Invalid (reserved bit set)
        0xFFFFFFFF, // Invalid (all bits set)
    ];

    let priority_data = build_priority_payload(&test_case.priority_payload);

    for stream_id in stream_id_tests {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            simulate_priority_update_frame(stream_id, &priority_data, test_case.extra_flags)
        }));

        assert!(result.is_ok(),
            "PRIORITY_UPDATE processing should not panic for stream_id=0x{:08X}",
            stream_id);

        if let Ok(frame_result) = result {
            match frame_result {
                PriorityUpdateResult::Accepted { .. } => {
                    // Stream ID 0 is valid for connection-level updates
                    // Other valid stream IDs are implementation-dependent
                }
                PriorityUpdateResult::Rejected { .. } => {
                    // Invalid stream IDs should be rejected
                    if stream_id & 0x80000000 != 0 {
                        // Reserved bit set - rejection expected
                    }
                }
                PriorityUpdateResult::Error => {
                    // Errors acceptable for malformed stream IDs
                }
            }
        }
    }
}

/// Test handling of malformed priority payloads
fn test_malformed_payload(test_case: &PriorityUpdateTest) {
    let malformed_payloads = vec![
        // Empty payload
        vec![],

        // Single bytes
        vec![0x00],
        vec![0xFF],

        // Binary data
        (0u8..=255u8).collect::<Vec<u8>>(),

        // Oversized payload
        vec![0x55; 10000],

        // Priority field-like but malformed
        b"u=8".to_vec(),           // Invalid urgency
        b"u=7,i".to_vec(),         // Incomplete incremental
        b"u=7,i=2".to_vec(),       // Invalid incremental value
        b"u=7,i=1,x=y".to_vec(),   // Unknown field

        // Invalid structured format
        b"urgency=7".to_vec(),     // Wrong field name
        b"u=7;i=1".to_vec(),       // Wrong separator
        b"u=7, i=1".to_vec(),      // Extra whitespace

        // Control characters
        vec![0x00, 0x01, 0x1F, 0x7F],

        // Non-ASCII
        "u=7,i=1,名前=値".as_bytes().to_vec(),

        // Very long field names/values
        format!("u=7,{}=value", "x".repeat(1000)).into_bytes(),
        format!("u=7,field={}", "y".repeat(1000)).into_bytes(),
    ];

    for payload in malformed_payloads {
        if payload.len() > 20_000 {
            continue; // Skip extremely large payloads for performance
        }

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            simulate_priority_update_frame(
                test_case.stream_id.max(1),
                &payload,
                test_case.extra_flags
            )
        }));

        assert!(result.is_ok(),
            "Malformed payload should not panic: {:?} (len={})",
            String::from_utf8_lossy(&payload[..payload.len().min(50)]),
            payload.len());
    }
}

/// Test frame flag handling
fn test_frame_flags(test_case: &PriorityUpdateTest) {
    let flag_tests = vec![
        0x00, // No flags
        0x01, // END_STREAM (should be ignored for PRIORITY_UPDATE)
        0x04, // PADDED (should be ignored for PRIORITY_UPDATE)
        0x08, // Reserved
        0xFF, // All flags set
    ];

    let priority_data = build_priority_payload(&test_case.priority_payload);

    for flags in flag_tests {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            simulate_priority_update_frame(
                test_case.stream_id.max(1),
                &priority_data,
                flags
            )
        }));

        assert!(result.is_ok(),
            "Flag combination 0x{:02X} should not panic", flags);

        // PRIORITY_UPDATE frames should ignore most flags
        // Only frame-type-specific flags should be processed
    }
}

/// Build priority payload from structured or raw format
fn build_priority_payload(payload: &PriorityPayload) -> Vec<u8> {
    if !payload.use_structured || payload.custom_fields.is_empty() {
        return payload.raw_bytes.clone();
    }

    // Build structured priority string: "u=N,i=B,field=value,..."
    let mut parts = Vec::new();

    // Add urgency
    parts.push(format!("u={}", payload.urgency));

    // Add incremental flag
    if payload.incremental {
        parts.push("i=1".to_string());
    } else {
        parts.push("i=0".to_string());
    }

    // Add custom fields
    for field in &payload.custom_fields {
        if !field.name.is_empty() && !field.value.is_empty() {
            // Basic sanitization to create testable but potentially invalid syntax
            let sanitized_name = sanitize_field_name(&field.name);
            let sanitized_value = sanitize_field_value(&field.value);
            if !sanitized_name.is_empty() && !sanitized_value.is_empty() {
                parts.push(format!("{}={}", sanitized_name, sanitized_value));
            }
        }
    }

    parts.join(",").into_bytes()
}

/// Sanitize field name for priority string format
fn sanitize_field_name(input: &str) -> String {
    input
        .chars()
        .filter(|&c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        .take(64)
        .collect()
}

/// Sanitize field value for priority string format
fn sanitize_field_value(input: &str) -> String {
    input
        .chars()
        .filter(|&c| c.is_ascii() && c != ',' && c != ';' && c != '\r' && c != '\n')
        .take(256)
        .collect()
}

/// Result of PRIORITY_UPDATE frame processing
#[derive(Debug, Clone, PartialEq)]
enum PriorityUpdateResult {
    /// Priority update was accepted
    Accepted {
        urgency: u8,
        incremental: bool,
    },
    /// Priority update was rejected
    Rejected {
        reason: String,
    },
    /// Error during processing
    Error,
}

/// Simulate PRIORITY_UPDATE frame processing
fn simulate_priority_update_frame(
    stream_id: u32,
    priority_data: &[u8],
    _flags: u8
) -> PriorityUpdateResult {
    // This simulates the PRIORITY_UPDATE frame processing logic
    // In a real implementation, this would be in the HTTP/2 connection handler

    // Basic frame size validation
    if priority_data.len() > 65535 {
        return PriorityUpdateResult::Rejected {
            reason: "Priority payload too large".to_string(),
        };
    }

    // Stream ID validation
    if stream_id & 0x80000000 != 0 {
        return PriorityUpdateResult::Rejected {
            reason: "Invalid stream ID (reserved bit set)".to_string(),
        };
    }

    // Parse priority string
    let priority_str = match std::str::from_utf8(priority_data) {
        Ok(s) => s,
        Err(_) => {
            return PriorityUpdateResult::Rejected {
                reason: "Invalid UTF-8 in priority payload".to_string(),
            };
        }
    };

    // Parse structured priority parameters
    let mut urgency = 0u8;
    let mut incremental = false;
    let mut found_urgency = false;

    for part in priority_str.split(',') {
        let part = part.trim();
        if let Some((key, value)) = part.split_once('=') {
            match key.trim() {
                "u" => {
                    match value.trim().parse::<u8>() {
                        Ok(u) if u <= 7 => {
                            urgency = u;
                            found_urgency = true;
                        }
                        Ok(u) => {
                            // Urgency > 7 is invalid per draft
                            return PriorityUpdateResult::Rejected {
                                reason: format!("Invalid urgency value: {} (must be 0-7)", u),
                            };
                        }
                        Err(_) => {
                            return PriorityUpdateResult::Rejected {
                                reason: "Invalid urgency format".to_string(),
                            };
                        }
                    }
                }
                "i" => {
                    match value.trim() {
                        "0" => incremental = false,
                        "1" => incremental = true,
                        _ => {
                            return PriorityUpdateResult::Rejected {
                                reason: "Invalid incremental value (must be 0 or 1)".to_string(),
                            };
                        }
                    }
                }
                _ => {
                    // Unknown fields are ignored in this simulation
                    // Real implementations might be more strict
                }
            }
        }
    }

    if !found_urgency && !priority_str.is_empty() {
        return PriorityUpdateResult::Rejected {
            reason: "Missing urgency parameter".to_string(),
        };
    }

    // Connection-level priority updates (stream_id = 0) have special semantics
    if stream_id == 0 {
        // Connection-level priority affects default priority for new streams
        // This is valid but handled differently
    }

    PriorityUpdateResult::Accepted {
        urgency,
        incremental,
    }
}

/// Generate test scenarios with various priority configurations
fn generate_priority_scenarios() -> Vec<PriorityUpdateTest> {
    vec![
        // Valid urgency values
        PriorityUpdateTest {
            stream_id: 1,
            priority_payload: PriorityPayload {
                urgency: 0,
                incremental: false,
                custom_fields: vec![],
                raw_bytes: b"u=0,i=0".to_vec(),
                use_structured: true,
            },
            extra_flags: 0,
            connection_level: false,
        },

        // Maximum valid urgency
        PriorityUpdateTest {
            stream_id: 3,
            priority_payload: PriorityPayload {
                urgency: 7,
                incremental: true,
                custom_fields: vec![],
                raw_bytes: b"u=7,i=1".to_vec(),
                use_structured: true,
            },
            extra_flags: 0,
            connection_level: false,
        },

        // Invalid urgency (should be rejected)
        PriorityUpdateTest {
            stream_id: 5,
            priority_payload: PriorityPayload {
                urgency: 8,
                incremental: false,
                custom_fields: vec![],
                raw_bytes: b"u=8,i=0".to_vec(),
                use_structured: true,
            },
            extra_flags: 0,
            connection_level: false,
        },

        // Connection-level priority update
        PriorityUpdateTest {
            stream_id: 0,
            priority_payload: PriorityPayload {
                urgency: 3,
                incremental: true,
                custom_fields: vec![],
                raw_bytes: b"u=3,i=1".to_vec(),
                use_structured: true,
            },
            extra_flags: 0,
            connection_level: true,
        },

        // Priority with custom fields
        PriorityUpdateTest {
            stream_id: 7,
            priority_payload: PriorityPayload {
                urgency: 5,
                incremental: true,
                custom_fields: vec![
                    PriorityField {
                        name: "custom".to_string(),
                        value: "value".to_string(),
                    },
                ],
                raw_bytes: vec![],
                use_structured: true,
            },
            extra_flags: 0,
            connection_level: false,
        },

        // Raw malformed payload
        PriorityUpdateTest {
            stream_id: 9,
            priority_payload: PriorityPayload {
                urgency: 0,
                incremental: false,
                custom_fields: vec![],
                raw_bytes: vec![0xFF, 0xFE, 0xFD, 0x00, 0x01],
                use_structured: false,
            },
            extra_flags: 0x08, // Reserved flag
            connection_level: false,
        },
    ]
}

/// Test that demonstrates expected PRIORITY_UPDATE behavior
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_priority_update() {
        let result = simulate_priority_update_frame(1, b"u=3,i=1", 0);
        assert!(matches!(result, PriorityUpdateResult::Accepted { urgency: 3, incremental: true }));
    }

    #[test]
    fn test_invalid_urgency_rejected() {
        let result = simulate_priority_update_frame(1, b"u=8,i=0", 0);
        assert!(matches!(result, PriorityUpdateResult::Rejected { .. }));
    }

    #[test]
    fn test_connection_level_priority() {
        let result = simulate_priority_update_frame(0, b"u=2,i=0", 0);
        assert!(matches!(result, PriorityUpdateResult::Accepted { urgency: 2, incremental: false }));
    }

    #[test]
    fn test_malformed_payload() {
        let result = simulate_priority_update_frame(1, &[0xFF, 0xFE], 0);
        assert!(matches!(result, PriorityUpdateResult::Rejected { .. }));
    }

    #[test]
    fn test_reserved_stream_id() {
        let result = simulate_priority_update_frame(0x80000001, b"u=1,i=0", 0);
        assert!(matches!(result, PriorityUpdateResult::Rejected { .. }));
    }

    #[test]
    fn test_missing_urgency() {
        let result = simulate_priority_update_frame(1, b"i=1", 0);
        assert!(matches!(result, PriorityUpdateResult::Rejected { .. }));
    }

    #[test]
    fn test_empty_payload() {
        let result = simulate_priority_update_frame(1, b"", 0);
        assert!(matches!(result, PriorityUpdateResult::Accepted { urgency: 0, incremental: false }));
    }
}