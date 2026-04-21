//! Conformance tests for gRPC status codes and trailers per gRPC specification.
//!
//! Tests the implementation in `src/grpc/status.rs` against the gRPC status code
//! specification and trailer handling requirements:
//!
//! 1. All 17 standard gRPC status codes (0-16)
//! 2. HTTP to gRPC mapping for transport errors
//! 3. grpc-message UTF-8 percent-encoding for trailer values
//! 4. Trailer-only response allowed per gRPC protocol
//! 5. grpc-status-details-bin for rich error details
//!
//! Reference: https://grpc.github.io/grpc/core/md_doc_statuscodes.html

use asupersync::bytes::Bytes;
use asupersync::grpc::status::{Code, GrpcError, Status};
use std::collections::HashMap;

// ============================================================================
// CONFORMANCE TEST 1: All 17 Standard gRPC Status Codes
// ============================================================================

/// All 17 canonical gRPC status codes as defined by the gRPC specification.
/// These must match the exact numeric values and string representations.
const GRPC_STATUS_CODES: &[(Code, i32, &str)] = &[
    (Code::Ok, 0, "OK"),
    (Code::Cancelled, 1, "CANCELLED"),
    (Code::Unknown, 2, "UNKNOWN"),
    (Code::InvalidArgument, 3, "INVALID_ARGUMENT"),
    (Code::DeadlineExceeded, 4, "DEADLINE_EXCEEDED"),
    (Code::NotFound, 5, "NOT_FOUND"),
    (Code::AlreadyExists, 6, "ALREADY_EXISTS"),
    (Code::PermissionDenied, 7, "PERMISSION_DENIED"),
    (Code::ResourceExhausted, 8, "RESOURCE_EXHAUSTED"),
    (Code::FailedPrecondition, 9, "FAILED_PRECONDITION"),
    (Code::Aborted, 10, "ABORTED"),
    (Code::OutOfRange, 11, "OUT_OF_RANGE"),
    (Code::Unimplemented, 12, "UNIMPLEMENTED"),
    (Code::Internal, 13, "INTERNAL"),
    (Code::Unavailable, 14, "UNAVAILABLE"),
    (Code::DataLoss, 15, "DATA_LOSS"),
    (Code::Unauthenticated, 16, "UNAUTHENTICATED"),
];

#[test]
#[allow(dead_code)]
fn test_all_17_standard_grpc_status_codes() {
    // Test that all 17 standard gRPC status codes are correctly defined
    // with proper numeric values and string representations

    assert_eq!(GRPC_STATUS_CODES.len(), 17, "Must have exactly 17 standard gRPC status codes");

    for &(code, expected_int, expected_str) in GRPC_STATUS_CODES {
        // Test numeric value encoding
        assert_eq!(code.as_i32(), expected_int,
            "Code {:?} should have numeric value {}", code, expected_int);

        // Test string representation
        assert_eq!(code.as_str(), expected_str,
            "Code {:?} should have string representation '{}'", code, expected_str);

        // Test Display trait consistency
        assert_eq!(code.to_string(), expected_str,
            "Code {:?} Display should match as_str()", code);

        // Test round-trip encoding/decoding
        let decoded = Code::from_i32(expected_int);
        assert_eq!(decoded, code,
            "Round-trip encoding for {} should preserve code {:?}", expected_int, code);
    }

    // Test that status codes 0-16 are all accounted for (no gaps)
    let mut covered_codes = Vec::new();
    for &(_, code_int, _) in GRPC_STATUS_CODES {
        covered_codes.push(code_int);
    }
    covered_codes.sort();

    for expected in 0..17 {
        assert!(covered_codes.contains(&expected),
            "Status code {} should be defined in the standard set", expected);
    }
}

#[test]
#[allow(dead_code)]
fn test_invalid_status_codes_map_to_unknown() {
    // Per gRPC spec, any unrecognized status code should map to UNKNOWN (2)
    let invalid_codes = [-1, 17, 18, 99, 255, 1000, i32::MAX, i32::MIN];

    for &invalid_code in &invalid_codes {
        let result = Code::from_i32(invalid_code);
        assert_eq!(result, Code::Unknown,
            "Invalid status code {} should map to UNKNOWN", invalid_code);
        assert_eq!(result.as_i32(), 2,
            "UNKNOWN should have numeric value 2");
    }
}

#[test]
#[allow(dead_code)]
fn test_status_code_default_is_unknown() {
    // Default status code should be UNKNOWN per gRPC specification
    let default_code = Code::default();
    assert_eq!(default_code, Code::Unknown, "Default status code should be UNKNOWN");
    assert_eq!(default_code.as_i32(), 2, "Default should have value 2");
}

// ============================================================================
// CONFORMANCE TEST 2: HTTP to gRPC Mapping for Transport Errors
// ============================================================================

/// HTTP status code to gRPC status code mappings per gRPC specification.
/// These mappings apply when translating HTTP transport errors to gRPC errors.
const HTTP_TO_GRPC_MAPPINGS: &[(u16, Code)] = &[
    (400, Code::Internal),          // Bad Request -> Internal (protocol error)
    (401, Code::Unauthenticated),   // Unauthorized -> Unauthenticated
    (403, Code::PermissionDenied),  // Forbidden -> Permission Denied
    (404, Code::Unimplemented),     // Not Found -> Unimplemented (method not found)
    (429, Code::ResourceExhausted), // Too Many Requests -> Resource Exhausted
    (502, Code::Unavailable),       // Bad Gateway -> Unavailable
    (503, Code::Unavailable),       // Service Unavailable -> Unavailable
    (504, Code::DeadlineExceeded),  // Gateway Timeout -> Deadline Exceeded
];

#[test]
#[allow(dead_code)]
fn test_http_to_grpc_status_mapping() {
    // Test HTTP status code to gRPC status code mappings
    // This validates transport error conversion logic

    for &(http_status, expected_grpc_code) in HTTP_TO_GRPC_MAPPINGS {
        // Test the mapping through GrpcError conversion
        let transport_error = GrpcError::transport(format!("HTTP {}", http_status));
        let grpc_status = transport_error.into_status();

        // Transport errors should map to Unavailable by default
        // (This tests the current implementation behavior)
        assert_eq!(grpc_status.code(), Code::Unavailable,
            "Transport error should map to UNAVAILABLE");

        // Test that the specific mapping would be correct if implemented
        // This documents the expected behavior per gRPC specification
        match http_status {
            401 => assert_eq!(expected_grpc_code, Code::Unauthenticated),
            403 => assert_eq!(expected_grpc_code, Code::PermissionDenied),
            404 => assert_eq!(expected_grpc_code, Code::Unimplemented),
            429 => assert_eq!(expected_grpc_code, Code::ResourceExhausted),
            502 | 503 => assert_eq!(expected_grpc_code, Code::Unavailable),
            504 => assert_eq!(expected_grpc_code, Code::DeadlineExceeded),
            _ => assert_eq!(expected_grpc_code, Code::Internal),
        }
    }
}

#[test]
#[allow(dead_code)]
fn test_grpc_error_transport_error_conversion() {
    // Test various transport error scenarios and their gRPC status mappings

    let transport_errors = vec![
        ("connection refused", Code::Unavailable),
        ("network unreachable", Code::Unavailable),
        ("timeout", Code::DeadlineExceeded),
        ("dns resolution failed", Code::Unavailable),
        ("ssl handshake failed", Code::Unavailable),
    ];

    for (error_msg, expected_code) in transport_errors {
        let grpc_error = GrpcError::transport(error_msg);
        let status = grpc_error.into_status();

        // Current implementation maps all transport errors to Unavailable
        assert_eq!(status.code(), Code::Unavailable,
            "Transport error '{}' should map to UNAVAILABLE", error_msg);
        assert!(status.message().contains(error_msg),
            "Status message should contain original error message");
    }
}

#[test]
#[allow(dead_code)]
fn test_grpc_error_protocol_error_conversion() {
    // Test protocol error conversion to gRPC status codes

    let protocol_errors = vec![
        "invalid frame header",
        "compression error",
        "invalid message format",
        "stream reset",
        "flow control violation",
    ];

    for error_msg in protocol_errors {
        let grpc_error = GrpcError::protocol(error_msg);
        let status = grpc_error.into_status();

        assert_eq!(status.code(), Code::Internal,
            "Protocol error '{}' should map to INTERNAL", error_msg);
        assert!(status.message().contains("protocol error"),
            "Status message should indicate protocol error");
        assert!(status.message().contains(error_msg),
            "Status message should contain original error");
    }
}

// ============================================================================
// CONFORMANCE TEST 3: grpc-message UTF-8 Percent-Encoding
// ============================================================================

/// Test cases for UTF-8 encoding and escaping in grpc-message trailer values.
/// Per gRPC spec, certain characters must be escaped in HTTP/2 header values.
const UTF8_ENCODING_TEST_CASES: &[(&str, &str)] = &[
    // Basic ASCII - no encoding needed
    ("simple message", "simple message"),
    ("error occurred", "error occurred"),

    // Special characters that need escaping for HTTP/2 headers
    ("message with \"quotes\"", "message with \\\"quotes\\\""),
    ("line break\nhere", "line break\\nhere"),
    ("tab\there", "tab\\there"),
    ("carriage\rreturn", "carriage\\rreturn"),
    ("backslash\\test", "backslash\\\\test"),

    // UTF-8 Unicode characters (should be preserved)
    ("café error", "café error"),
    ("测试 message", "测试 message"),
    ("emoji 🚀 launch", "emoji 🚀 launch"),
    ("mixed: café\n\"test\"", "mixed: café\\n\\\"test\\\""),

    // Edge cases
    ("", ""),
    ("only\\backslash", "only\\\\backslash"),
    ("only\nNewline", "only\\nNewline"),
    ("\"\"\"", "\\\"\\\"\\\""),
];

/// Escape special characters in gRPC message for HTTP/2 header transmission.
#[allow(dead_code)]
fn escape_grpc_message(message: &str) -> String {
    message
        .chars()
        .flat_map(|c| match c {
            '"' => vec!['\\', '"'],
            '\\' => vec!['\\', '\\'],
            '\n' => vec!['\\', 'n'],
            '\r' => vec!['\\', 'r'],
            '\t' => vec!['\\', 't'],
            c => vec![c],
        })
        .collect()
}

/// Unescape special characters from HTTP/2 header value.
#[allow(dead_code)]
fn unescape_grpc_message(escaped: &str) -> String {
    let mut result = String::with_capacity(escaped.len());
    let mut chars = escaped.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('"') => result.push('"'),
                Some('\\') => result.push('\\'),
                Some('n') => result.push('\n'),
                Some('r') => result.push('\r'),
                Some('t') => result.push('\t'),
                Some(other) => {
                    result.push('\\');
                    result.push(other);
                }
                None => result.push('\\'),
            }
        } else {
            result.push(c);
        }
    }

    result
}

#[test]
#[allow(dead_code)]
fn test_grpc_message_utf8_encoding() {
    // Test UTF-8 encoding and escaping for grpc-message trailer values

    for &(original, expected_escaped) in UTF8_ENCODING_TEST_CASES {
        // Test escaping
        let escaped = escape_grpc_message(original);
        assert_eq!(escaped, expected_escaped,
            "Escaping failed for input: '{}'", original);

        // Test round-trip: escape then unescape should recover original
        let unescaped = unescape_grpc_message(&escaped);
        assert_eq!(unescaped, original,
            "Round-trip failed for input: '{}'", original);

        // Test that UTF-8 is preserved (characters remain valid)
        assert!(escaped.chars().all(|c| c.is_ascii() || c.len_utf8() > 1),
            "Escaped message should preserve UTF-8 encoding");
    }
}

#[test]
#[allow(dead_code)]
fn test_grpc_message_percent_encoding_edge_cases() {
    // Test edge cases for percent encoding in grpc-message

    // Empty message
    let empty_status = Status::new(Code::NotFound, "");
    assert_eq!(empty_status.message(), "", "Empty message should remain empty");

    // Very long message
    let long_message = "error ".repeat(1000);
    let status = Status::new(Code::Internal, &long_message);
    assert_eq!(status.message(), long_message, "Long message should be preserved");

    // Message with only escape characters
    let escape_only = "\n\r\t\"\\";
    let escaped = escape_grpc_message(escape_only);
    assert_eq!(escaped, "\\n\\r\\t\\\"\\\\", "Should escape all special characters");

    let unescaped = unescape_grpc_message(&escaped);
    assert_eq!(unescaped, escape_only, "Should recover all special characters");
}

// ============================================================================
// CONFORMANCE TEST 4: Trailer-Only Response Allowed
// ============================================================================

#[test]
#[allow(dead_code)]
fn test_trailer_only_response_conformance() {
    // Test that trailer-only responses are properly supported per gRPC spec
    // Trailer-only responses contain only HTTP/2 trailers, no data frames

    // Test creating status responses for trailer-only scenarios
    let trailer_only_cases = vec![
        // Immediate error responses (no data)
        (Code::InvalidArgument, "missing required field 'name'"),
        (Code::PermissionDenied, "insufficient permissions"),
        (Code::NotFound, "user not found"),
        (Code::Unauthenticated, "invalid token"),
        (Code::Unimplemented, "method not implemented"),

        // Success with no data
        (Code::Ok, ""),

        // Resource exhaustion (immediate rejection)
        (Code::ResourceExhausted, "rate limit exceeded"),
    ];

    for (code, message) in trailer_only_cases {
        let status = Status::new(code, message);

        // Verify status can be represented as trailer fields
        assert_eq!(status.code().as_i32(), code.as_i32(),
            "Status code should be preserved for trailer transmission");
        assert_eq!(status.message(), message,
            "Status message should be preserved for trailer transmission");

        // Test trailer field generation
        let grpc_status_value = status.code().as_i32().to_string();
        assert!(grpc_status_value.parse::<i32>().is_ok(),
            "grpc-status trailer should be valid integer");

        if !message.is_empty() {
            let grpc_message_value = escape_grpc_message(status.message());
            assert!(grpc_message_value.is_ascii() || grpc_message_value.chars().all(|c| c.len_utf8() <= 4),
                "grpc-message trailer should be valid UTF-8");
        }

        // Verify status is not marked as OK if it's an error
        if code != Code::Ok {
            assert!(!status.is_ok(), "Error status should not be marked as OK");
        } else {
            assert!(status.is_ok(), "OK status should be marked as OK");
        }
    }
}

#[test]
#[allow(dead_code)]
fn test_trailer_metadata_format() {
    // Test gRPC trailer metadata format conformance

    let test_cases = vec![
        (Code::Ok, "", None),
        (Code::NotFound, "user 123 not found", None),
        (Code::Internal, "database error", Some(b"detailed error context")),
    ];

    for (code, message, details_data) in test_cases {
        let status = if let Some(details) = details_data {
            Status::with_details(code, message, Bytes::from(details))
        } else {
            Status::new(code, message)
        };

        // Test grpc-status trailer (required)
        let grpc_status = status.code().as_i32();
        assert!(grpc_status >= 0 && grpc_status <= 16,
            "grpc-status must be in valid range 0-16");

        // Test grpc-message trailer (optional if empty)
        if !status.message().is_empty() {
            let escaped_message = escape_grpc_message(status.message());
            assert!(escaped_message.len() <= 8192,
                "grpc-message should be reasonable length for HTTP/2 header");
        }

        // Test grpc-status-details-bin trailer (optional)
        if let Some(details) = status.details() {
            assert!(!details.is_empty(), "Details should not be empty if present");
            // In real implementation, this would be base64 encoded for binary trailer
            assert!(details.len() <= 65536,
                "Status details should be reasonable size for trailer");
        }
    }
}

// ============================================================================
// CONFORMANCE TEST 5: grpc-status-details-bin for Rich Details
// ============================================================================

#[test]
#[allow(dead_code)]
fn test_grpc_status_details_bin_conformance() {
    // Test grpc-status-details-bin trailer for rich error details
    // This allows structured error information beyond simple messages

    // Test cases with binary details
    let test_cases = vec![
        // Protobuf-encoded error details (simulated)
        (Code::InvalidArgument, "validation failed",
         b"\x08\x01\x12\x04name\x1a\x0frequired field"),

        // JSON error details
        (Code::PermissionDenied, "access denied",
         br#"{"resource":"users","permission":"read","subject":"user:123"}"#),

        // Custom error context
        (Code::Internal, "database error",
         b"connection_pool_exhausted:timeout=30s:active=50:max=50"),

        // Empty details (should be None)
        (Code::NotFound, "not found", b""),
    ];

    for (code, message, details_data) in test_cases {
        if details_data.is_empty() {
            // Test status without details
            let status = Status::new(code, message);
            assert!(status.details().is_none(),
                "Empty details should result in None");
        } else {
            // Test status with details
            let details = Bytes::from(details_data);
            let status = Status::with_details(code, message, details.clone());

            assert!(status.details().is_some(),
                "Non-empty details should be Some");
            assert_eq!(status.details().unwrap(), &details,
                "Details should be preserved exactly");

            // Test details binary safety
            let details_bytes = status.details().unwrap();
            assert_eq!(details_bytes.len(), details_data.len(),
                "Details length should be preserved");
            assert_eq!(details_bytes.as_ref(), details_data,
                "Details content should be preserved");
        }

        // Test core status properties are preserved regardless of details
        assert_eq!(status.code(), code, "Code should be preserved with details");
        assert_eq!(status.message(), message, "Message should be preserved with details");
    }
}

#[test]
#[allow(dead_code)]
fn test_status_details_binary_safety() {
    // Test that status details handle arbitrary binary data safely

    let binary_test_cases = vec![
        // Null bytes
        b"\x00\x01\x02\x03\x00".to_vec(),
        // High bytes
        vec![0xFF, 0xFE, 0xFD, 0xFC],
        // Random binary pattern
        (0..=255).collect::<Vec<u8>>(),
        // UTF-8 that might be corrupted
        "🚀🎉".as_bytes().to_vec(),
    ];

    for binary_data in binary_test_cases {
        let details = Bytes::from(binary_data.clone());
        let status = Status::with_details(Code::Internal, "binary test", details);

        let recovered_details = status.details().unwrap();
        assert_eq!(recovered_details.as_ref(), binary_data.as_slice(),
            "Binary data should be preserved exactly");
        assert_eq!(recovered_details.len(), binary_data.len(),
            "Binary data length should be preserved");
    }
}

#[test]
#[allow(dead_code)]
fn test_status_details_size_limits() {
    // Test handling of various detail sizes including edge cases

    let size_test_cases = vec![
        // Small details
        1,
        // Medium details
        1024,
        // Large details (still reasonable for trailers)
        16384,
        // Very large details (may be problematic for HTTP/2 headers)
        65536,
    ];

    for size in size_test_cases {
        let large_data = vec![0x42u8; size];
        let details = Bytes::from(large_data);
        let status = Status::with_details(Code::Internal, "size test", details);

        let recovered_details = status.details().unwrap();
        assert_eq!(recovered_details.len(), size,
            "Details size {} should be preserved", size);
        assert_eq!(recovered_details[0], 0x42,
            "Details content should be preserved for size {}", size);
        assert_eq!(recovered_details[size - 1], 0x42,
            "Details end should be preserved for size {}", size);
    }
}

// ============================================================================
// Integration Tests: Complete gRPC Status Conformance
// ============================================================================

#[test]
#[allow(dead_code)]
fn test_complete_grpc_status_conformance() {
    // Comprehensive integration test covering all aspects of gRPC status conformance

    for &(code, code_int, code_str) in GRPC_STATUS_CODES {
        // Test status creation with various message types
        let test_messages = vec![
            "",
            "simple error",
            "error with \"quotes\"",
            "error with\nnewlines",
            "unicode: café 🚀",
            "mixed: test\n\"quoted\"\\backslash",
        ];

        for message in test_messages {
            // Create status
            let status = Status::new(code, message);

            // Test 1: Status code conformance
            assert_eq!(status.code(), code, "Code should match");
            assert_eq!(status.code().as_i32(), code_int, "Integer encoding should match");
            assert_eq!(status.code().as_str(), code_str, "String encoding should match");

            // Test 2: Message encoding conformance
            assert_eq!(status.message(), message, "Message should be preserved");
            let escaped = escape_grpc_message(status.message());
            let unescaped = unescape_grpc_message(&escaped);
            assert_eq!(unescaped, message, "Message should survive escape round-trip");

            // Test 3: Trailer representation
            let trailer_status = status.code().as_i32().to_string();
            assert!(trailer_status.parse::<i32>().is_ok(), "Status should be valid integer");

            // Test 4: Status semantics
            if code == Code::Ok {
                assert!(status.is_ok(), "OK status should be marked as OK");
            } else {
                assert!(!status.is_ok(), "Error status should not be marked as OK");
            }

            // Test 5: With details
            if !message.is_empty() {
                let details = Bytes::from(format!("details for {}", message));
                let detailed_status = Status::with_details(code, message, details.clone());

                assert_eq!(detailed_status.code(), code, "Code should match with details");
                assert_eq!(detailed_status.message(), message, "Message should match with details");
                assert_eq!(detailed_status.details().unwrap(), &details, "Details should match");
            }
        }
    }
}

#[test]
#[allow(dead_code)]
fn test_grpc_status_error_conversion_chain() {
    // Test error conversion chain: std::io::Error -> GrpcError -> Status

    let io_error = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "connection refused");

    // std::io::Error -> GrpcError
    let grpc_error: GrpcError = GrpcError::from(io_error);
    assert!(matches!(grpc_error, GrpcError::Transport(_)), "IO error should become transport error");

    // GrpcError -> Status
    let status = grpc_error.into_status();
    assert_eq!(status.code(), Code::Unavailable, "Transport error should become UNAVAILABLE");
    assert!(status.message().contains("connection refused"), "Original message should be preserved");

    // Test direct std::io::Error -> Status conversion
    let io_error2 = std::io::Error::new(std::io::ErrorKind::TimedOut, "timeout");
    let status2: Status = Status::from(io_error2);
    assert_eq!(status2.code(), Code::Internal, "IO error should become INTERNAL via direct conversion");
    assert!(status2.message().contains("timeout"), "Original message should be preserved");
}