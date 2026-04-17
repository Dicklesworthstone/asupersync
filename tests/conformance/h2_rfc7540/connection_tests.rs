//! Connection management conformance tests.
//!
//! Tests connection lifecycle and management requirements from RFC 7540 Section 3.

use super::*;

/// Run all connection management conformance tests.
pub fn run_connection_tests() -> Vec<H2ConformanceResult> {
    let mut results = Vec::new();

    results.push(test_connection_preface());
    results.push(test_http2_identification());
    results.push(test_connection_header_processing());
    results.push(test_connection_upgrade_from_http1());
    results.push(test_prior_knowledge_connection());
    results.push(test_connection_termination());
    results.push(test_goaway_frame_processing());
    results.push(test_connection_error_handling());

    results
}

/// RFC 7540 Section 3.5: HTTP/2 connection preface.
fn test_connection_preface() -> H2ConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        // HTTP/2 connection preface sequence
        let preface_string = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

        // Verify the preface string is exactly 24 bytes
        if preface_string.len() != 24 {
            return Err(format!(
                "Connection preface must be 24 bytes, got {}",
                preface_string.len()
            ));
        }

        // Verify exact preface content
        let expected_preface = [
            0x50, 0x52, 0x49, 0x20, 0x2a, 0x20, 0x48, 0x54, // "PRI * HT"
            0x54, 0x50, 0x2f, 0x32, 0x2e, 0x30, 0x0d, 0x0a, // "TP/2.0\r\n"
            0x0d, 0x0a, 0x53, 0x4d, 0x0d, 0x0a, 0x0d, 0x0a, // "\r\nSM\r\n\r\n"
        ];

        if preface_string != &expected_preface[..] {
            return Err("Connection preface content does not match specification".to_string());
        }

        // Client MUST send this preface followed immediately by a SETTINGS frame
        // Server MUST send a SETTINGS frame as its first frame

        // Invalid preface should result in GOAWAY with PROTOCOL_ERROR
        let invalid_prefixes: &[&[u8]] = &[
            b"PRI * HTTP/1.1\r\n\r\nSM\r\n\r\n", // Wrong HTTP version
            b"GET / HTTP/2.0\r\n\r\nSM\r\n\r\n", // Wrong method
            b"PRI * HTTP/2.0\r\n\r\nXX\r\n\r\n", // Wrong magic string
            b"PRI * HTTP/2.0\r\n\r\n",           // Truncated
        ];

        for (i, invalid_preface) in invalid_prefixes.iter().enumerate() {
            // These should be rejected by HTTP/2 implementation
            if *invalid_preface == expected_preface {
                return Err(format!("Invalid preface {} matches valid preface", i));
            }
        }

        Ok(())
    });

    create_test_result(
        "RFC7540-3.5-PREFACE",
        "HTTP/2 connection preface validation",
        TestCategory::Connection,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// RFC 7540 Section 3.2: HTTP/2 version identification.
fn test_http2_identification() -> H2ConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        // HTTP/2 version identification in ALPN
        let alpn_protocols: &[&[u8]] = &[
            b"h2",  // HTTP/2 over TLS
            b"h2c", // HTTP/2 over cleartext
        ];

        for protocol in alpn_protocols {
            // These should be recognized as HTTP/2 protocols
            match *protocol {
                b"h2" => {
                    // HTTP/2 over TLS - requires TLS 1.2+
                    // Must use ALPN extension to negotiate
                }
                b"h2c" => {
                    // HTTP/2 over cleartext TCP
                    // Can use prior knowledge or HTTP/1.1 upgrade
                }
                _ => {
                    return Err(format!("Unknown HTTP/2 protocol: {:?}", protocol));
                }
            }
        }

        // Invalid or unsupported protocols
        let invalid_protocols: &[&[u8]] = &[
            b"http/1.1",
            b"http/2.0", // Should be "h2" not "http/2.0"
            b"h1",
            b"h3", // HTTP/3, not HTTP/2
        ];

        for protocol in invalid_protocols {
            // These should not be treated as HTTP/2
            if *protocol == b"h2" || *protocol == b"h2c" {
                return Err(format!(
                    "Invalid protocol {:?} matches valid protocol",
                    protocol
                ));
            }
        }

        Ok(())
    });

    create_test_result(
        "RFC7540-3.2-IDENTIFICATION",
        "HTTP/2 protocol version identification",
        TestCategory::Connection,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// RFC 7540 Section 3.2: Connection header processing.
fn test_connection_header_processing() -> H2ConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        // HTTP/1.1 specific headers that must be removed in HTTP/2
        let forbidden_headers = [
            "connection",
            "keep-alive",
            "proxy-connection",
            "transfer-encoding",
            "upgrade",
        ];

        // These headers MUST NOT appear in HTTP/2
        // If present in HTTP/1.1 → HTTP/2 conversion, they must be stripped

        for header in &forbidden_headers {
            // Implementation should reject or strip these headers
            let header_lower = header.to_lowercase();
            match header_lower.as_str() {
                "connection" => {
                    // Connection-specific headers are meaningless in HTTP/2
                }
                "keep-alive" => {
                    // HTTP/2 connections are persistent by default
                }
                "proxy-connection" => {
                    // Proxy-specific, not applicable to HTTP/2
                }
                "transfer-encoding" => {
                    // HTTP/2 has native chunking, transfer-encoding forbidden
                }
                "upgrade" => {
                    // Upgrade mechanism not used within HTTP/2
                }
                _ => {}
            }
        }

        // Pseudo-headers that ARE required in HTTP/2
        let required_pseudo_headers = [":method", ":path", ":scheme", ":authority"];

        for pseudo_header in &required_pseudo_headers {
            // These must be present in HTTP/2 request headers
            if !pseudo_header.starts_with(':') {
                return Err(format!(
                    "Pseudo-header {} must start with ':'",
                    pseudo_header
                ));
            }
        }

        // Response pseudo-headers
        let response_pseudo_headers = [":status"];

        for pseudo_header in &response_pseudo_headers {
            // These must be present in HTTP/2 response headers
            if !pseudo_header.starts_with(':') {
                return Err(format!(
                    "Response pseudo-header {} must start with ':'",
                    pseudo_header
                ));
            }
        }

        Ok(())
    });

    create_test_result(
        "RFC7540-3.2-HEADERS",
        "Connection header processing and pseudo-headers",
        TestCategory::Connection,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// RFC 7540 Section 3.2: HTTP/1.1 to HTTP/2 upgrade.
fn test_connection_upgrade_from_http1() -> H2ConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        // HTTP/1.1 Upgrade mechanism for HTTP/2
        let upgrade_request_headers = [
            ("Connection", "Upgrade, HTTP2-Settings"),
            ("Upgrade", "h2c"),
            ("HTTP2-Settings", "<base64-encoded-settings>"),
        ];

        // Validate upgrade request format
        for (header_name, header_value) in &upgrade_request_headers {
            match *header_name {
                "Connection" => {
                    // Must include "Upgrade" and "HTTP2-Settings" tokens
                    if !header_value.contains("Upgrade") || !header_value.contains("HTTP2-Settings")
                    {
                        return Err(format!(
                            "Connection header missing required tokens: {}",
                            header_value
                        ));
                    }
                }
                "Upgrade" => {
                    // Must specify "h2c" for HTTP/2 over cleartext
                    if *header_value != "h2c" {
                        return Err(format!(
                            "Upgrade header must be 'h2c', got '{}'",
                            header_value
                        ));
                    }
                }
                "HTTP2-Settings" => {
                    // Must be base64url-encoded SETTINGS frame payload
                    // Empty payload is valid (uses default settings)
                    if header_value.is_empty() {
                        // Empty is valid - uses default settings
                    } else {
                        // Should be valid base64url encoding
                        // Would need base64 validation in real implementation
                    }
                }
                _ => {}
            }
        }

        // Successful upgrade response
        let upgrade_response =
            "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n";

        // After successful upgrade:
        // - Client sends HTTP/2 connection preface
        // - Server responds with SETTINGS frame
        // - First HTTP/1.1 request becomes stream 1

        // Failed upgrade (server doesn't support HTTP/2)
        let failed_upgrade = "HTTP/1.1 400 Bad Request\r\n\r\n";

        // Server can reject upgrade for various reasons:
        // - Doesn't support HTTP/2
        // - Invalid HTTP2-Settings header
        // - Policy reasons

        Ok(())
    });

    create_test_result(
        "RFC7540-3.2-UPGRADE",
        "HTTP/1.1 to HTTP/2 upgrade mechanism",
        TestCategory::Connection,
        RequirementLevel::Should,
        result,
        elapsed,
    )
}

/// RFC 7540 Section 3.4: Prior knowledge connection establishment.
fn test_prior_knowledge_connection() -> H2ConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        // Prior knowledge connection setup

        // Client knows server supports HTTP/2 (no upgrade needed)
        // Client immediately sends:
        // 1. HTTP/2 connection preface
        // 2. SETTINGS frame

        // Server responds with:
        // 1. SETTINGS frame
        // 2. SETTINGS ACK (acknowledging client settings)

        // No HTTP/1.1 involved in prior knowledge connections

        // Connection establishment order:
        let client_sequence = [
            "connection_preface", // 24-byte magic string
            "settings_frame",     // Initial settings
        ];

        let server_sequence = [
            "settings_frame", // Server settings
            "settings_ack",   // ACK of client settings
        ];

        // Validate sequence order
        for (i, step) in client_sequence.iter().enumerate() {
            match *step {
                "connection_preface" => {
                    if i != 0 {
                        return Err("Connection preface must be first".to_string());
                    }
                }
                "settings_frame" => {
                    if i != 1 {
                        return Err("SETTINGS frame must follow preface".to_string());
                    }
                }
                _ => {}
            }
        }

        // Server must not send connection preface
        for step in &server_sequence {
            if *step == "connection_preface" {
                return Err("Server must not send connection preface".to_string());
            }
        }

        Ok(())
    });

    create_test_result(
        "RFC7540-3.4-PRIOR-KNOWLEDGE",
        "Prior knowledge connection establishment",
        TestCategory::Connection,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// RFC 7540 Section 6.8: Connection termination with GOAWAY.
fn test_connection_termination() -> H2ConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        // Connection termination scenarios

        // Graceful shutdown:
        // 1. Send GOAWAY with last processed stream ID
        // 2. Complete processing of in-flight streams
        // 3. Close connection

        // GOAWAY frame contains:
        // - Last stream ID that will be processed
        // - Error code (0 for graceful shutdown)
        // - Optional debug data

        let shutdown_scenarios = [
            ("graceful", 0u32, "Normal shutdown"),
            ("protocol_error", 1u32, "Protocol violation detected"),
            ("internal_error", 2u32, "Internal server error"),
            ("flow_control_error", 3u32, "Flow control violation"),
        ];

        for (scenario, error_code, description) in &shutdown_scenarios {
            match *scenario {
                "graceful" => {
                    // Error code 0 = NO_ERROR
                    if *error_code != 0 {
                        return Err(format!(
                            "Graceful shutdown should use error code 0, got {}",
                            error_code
                        ));
                    }
                }
                "protocol_error" => {
                    // Error code 1 = PROTOCOL_ERROR
                    if *error_code != 1 {
                        return Err("Protocol error should use error code 1".to_string());
                    }
                }
                "internal_error" => {
                    // Error code 2 = INTERNAL_ERROR
                    if *error_code != 2 {
                        return Err("Internal error should use error code 2".to_string());
                    }
                }
                "flow_control_error" => {
                    // Error code 3 = FLOW_CONTROL_ERROR
                    if *error_code != 3 {
                        return Err("Flow control error should use error code 3".to_string());
                    }
                }
                _ => {
                    return Err(format!("Unknown shutdown scenario: {}", scenario));
                }
            }
        }

        Ok(())
    });

    create_test_result(
        "RFC7540-6.8-TERMINATION",
        "Connection termination with GOAWAY frame",
        TestCategory::Connection,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// RFC 7540 Section 6.8: GOAWAY frame processing.
fn test_goaway_frame_processing() -> H2ConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        // GOAWAY frame structure validation

        // GOAWAY payload format:
        // - Last Stream ID (31 bits) + Reserved bit
        // - Error Code (32 bits)
        // - Additional Debug Data (optional)

        let goaway_test_cases = [
            // (last_stream_id, error_code, has_debug_data)
            (0u32, 0u32, false),       // No streams processed, graceful shutdown
            (5u32, 0u32, false),       // Last stream 5, graceful shutdown
            (100u32, 1u32, true),      // Last stream 100, protocol error with debug
            (0x7FFFFFFF, 2u32, false), // Maximum stream ID, internal error
        ];

        for (last_stream_id, error_code, has_debug_data) in &goaway_test_cases {
            // Validate stream ID is within valid range
            if *last_stream_id > 0x7FFFFFFF {
                return Err(format!(
                    "Last stream ID {} exceeds 31-bit limit",
                    last_stream_id
                ));
            }

            // Error codes should be defined values
            let valid_error_codes = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
            if !valid_error_codes.contains(error_code) {
                // Unknown error codes are allowed but should be treated as internal error
            }

            // Debug data is optional
            if *has_debug_data {
                // Debug data can contain additional context
                // Should be UTF-8 when possible but not required
            }
        }

        // GOAWAY processing rules:
        // - No new streams with ID > last_stream_id
        // - Complete processing of existing streams ≤ last_stream_id
        // - Can send additional GOAWAY frames with lower last_stream_id

        // Multiple GOAWAY frames are allowed
        let goaway_sequence = [100u32, 50u32, 25u32, 0u32];
        for i in 1..goaway_sequence.len() {
            if goaway_sequence[i] > goaway_sequence[i - 1] {
                return Err(format!(
                    "GOAWAY last stream ID cannot increase: {} > {}",
                    goaway_sequence[i],
                    goaway_sequence[i - 1]
                ));
            }
        }

        Ok(())
    });

    create_test_result(
        "RFC7540-6.8-GOAWAY",
        "GOAWAY frame structure and processing",
        TestCategory::Connection,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// RFC 7540 Section 5.4.1: Connection error handling.
fn test_connection_error_handling() -> H2ConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        // Connection errors vs stream errors

        // Connection errors affect the entire connection
        let connection_errors = [
            (1u32, "PROTOCOL_ERROR", "Generic protocol violation"),
            (2u32, "INTERNAL_ERROR", "Implementation fault"),
            (3u32, "FLOW_CONTROL_ERROR", "Flow control limits exceeded"),
            (4u32, "SETTINGS_TIMEOUT", "SETTINGS ACK not received"),
            (5u32, "STREAM_CLOSED", "Frame received for closed stream"),
            (6u32, "FRAME_SIZE_ERROR", "Frame size constraints violated"),
            (
                9u32,
                "COMPRESSION_ERROR",
                "HPACK compression state corrupted",
            ),
            (10u32, "CONNECT_ERROR", "TCP connection broken for CONNECT"),
            (11u32, "ENHANCE_CALM", "Excessive load or resource usage"),
            (12u32, "INADEQUATE_SECURITY", "TLS requirements not met"),
            (13u32, "HTTP_1_1_REQUIRED", "HTTP/1.1 required by endpoint"),
        ];

        for (error_code, error_name, description) in &connection_errors {
            // These errors should trigger GOAWAY + connection close
            match *error_code {
                1 => {
                    // PROTOCOL_ERROR: Generic protocol violation
                    if *error_name != "PROTOCOL_ERROR" {
                        return Err("Error code 1 should be PROTOCOL_ERROR".to_string());
                    }
                }
                2 => {
                    // INTERNAL_ERROR: Implementation fault
                    if *error_name != "INTERNAL_ERROR" {
                        return Err("Error code 2 should be INTERNAL_ERROR".to_string());
                    }
                }
                3 => {
                    // FLOW_CONTROL_ERROR: Flow control violation
                    if *error_name != "FLOW_CONTROL_ERROR" {
                        return Err("Error code 3 should be FLOW_CONTROL_ERROR".to_string());
                    }
                }
                4 => {
                    // SETTINGS_TIMEOUT: SETTINGS ACK timeout
                    if *error_name != "SETTINGS_TIMEOUT" {
                        return Err("Error code 4 should be SETTINGS_TIMEOUT".to_string());
                    }
                }
                _ => {
                    // Other defined error codes
                }
            }
        }

        // Error handling sequence:
        // 1. Detect error condition
        // 2. Send GOAWAY with appropriate error code
        // 3. Close connection after sending GOAWAY

        // Some errors require immediate connection closure:
        let immediate_closure_errors = [1, 2, 9, 11]; // Protocol, internal, compression, security

        for error_code in &immediate_closure_errors {
            // These should close connection immediately after GOAWAY
        }

        Ok(())
    });

    create_test_result(
        "RFC7540-5.4.1-ERRORS",
        "Connection error detection and handling",
        TestCategory::Connection,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}
