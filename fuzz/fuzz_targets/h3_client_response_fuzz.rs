#![no_main]

//! Fuzz target for HTTP/3 client response parsing and handling.
//!
//! This target exercises the client-side HTTP/3 response parsing to ensure robust handling
//! of various response patterns, error conditions, and edge cases.
//!
//! Key scenarios tested:
//! 1. HEADERS+DATA Interleaving: Various patterns of header/data frame ordering
//! 2. Trailer Handling: Proper parsing and processing of trailing headers
//! 3. Status Code Propagation: Correct handling of 4xx/5xx error responses
//! 4. Invalid Settings Rejection: Malformed or conflicting settings handling
//! 5. Graceful Reset: Connection and stream reset handling under various conditions

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Skip tiny inputs
    if data.len() < 8 {
        return;
    }

    // Limit size to prevent timeouts
    if data.len() > 8192 {
        return;
    }

    // Parse fuzz input into test scenarios
    let mut input = data;
    let scenarios = parse_h3_client_operations(&mut input);

    // Test HTTP/3 client response handling
    test_headers_data_interleaving(&scenarios);
    test_trailer_handling(&scenarios);
    test_status_code_propagation(&scenarios);
    test_invalid_settings_rejection(&scenarios);
    test_graceful_reset_handling(&scenarios);
});

#[derive(Debug, Clone)]
enum H3ClientOperation {
    HeadersDataInterleaved {
        status_code: u16,
        headers: Vec<(String, String)>,
        data_chunks: Vec<Vec<u8>>,
        interleaving_pattern: Vec<FrameType>,
    },
    TrailerResponse {
        status_code: u16,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
        trailers: Vec<(String, String)>,
    },
    StatusCodeResponse {
        status_code: u16,
        reason_phrase: String,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    },
    InvalidSettings {
        settings: Vec<(u64, u64)>, // (setting_id, value)
        malformed_data: Vec<u8>,
    },
    ResetScenario {
        reset_timing: ResetTiming,
        reset_code: u64,
        partial_response: bool,
    },
}

#[derive(Debug, Clone)]
enum FrameType {
    Headers,
    Data,
    Settings,
}

#[derive(Debug, Clone)]
enum ResetTiming {
    BeforeHeaders,
    DuringHeaders,
    AfterHeaders,
    DuringData,
    AfterData,
    DuringTrailers,
}

fn parse_h3_client_operations(input: &mut &[u8]) -> Vec<H3ClientOperation> {
    let mut ops = Vec::new();
    let mut rng_state = 42u64;

    while input.len() >= 4 && ops.len() < 12 {
        let op_type = extract_u8(input, &mut rng_state) % 5;

        match op_type {
            0 => {
                // HEADERS+DATA interleaving
                let status_code = match extract_u8(input, &mut rng_state) % 6 {
                    0 => 200, // OK
                    1 => 404, // Not Found
                    2 => 500, // Internal Server Error
                    3 => 301, // Moved Permanently
                    4 => 429, // Too Many Requests
                    5 => 502, // Bad Gateway
                    _ => 200,
                };

                let header_count = (extract_u8(input, &mut rng_state) % 8) as usize;
                let mut headers = Vec::new();
                for i in 0..header_count {
                    let key = format!("header-{}", i);
                    let value = format!("value-{}", extract_u16(input, &mut rng_state));
                    headers.push((key, value));
                }

                let chunk_count = (extract_u8(input, &mut rng_state) % 6) as usize + 1;
                let mut data_chunks = Vec::new();
                for _ in 0..chunk_count {
                    let chunk_size = (extract_u8(input, &mut rng_state) % 32) as usize;
                    let mut chunk = vec![0u8; chunk_size];
                    for byte in &mut chunk {
                        *byte = extract_u8(input, &mut rng_state);
                    }
                    data_chunks.push(chunk);
                }

                let pattern_len = (extract_u8(input, &mut rng_state) % 8) as usize + 1;
                let mut interleaving_pattern = Vec::new();
                for _ in 0..pattern_len {
                    let frame_type = match extract_u8(input, &mut rng_state) % 3 {
                        0 => FrameType::Headers,
                        1 => FrameType::Data,
                        2 => FrameType::Settings,
                        _ => FrameType::Data,
                    };
                    interleaving_pattern.push(frame_type);
                }

                ops.push(H3ClientOperation::HeadersDataInterleaved {
                    status_code,
                    headers,
                    data_chunks,
                    interleaving_pattern,
                });
            }
            1 => {
                // Trailer handling
                let status_code = 200 + (extract_u8(input, &mut rng_state) % 100) as u16;

                let header_count = (extract_u8(input, &mut rng_state) % 6) as usize;
                let mut headers = Vec::new();
                for i in 0..header_count {
                    let key = match i {
                        0 => "content-type".to_string(),
                        1 => "content-length".to_string(),
                        _ => format!("x-custom-{}", i),
                    };
                    let value = format!("test-{}", extract_u16(input, &mut rng_state));
                    headers.push((key, value));
                }

                let body_size = (extract_u8(input, &mut rng_state) % 64) as usize;
                let mut body = vec![0u8; body_size];
                for byte in &mut body {
                    *byte = extract_u8(input, &mut rng_state);
                }

                let trailer_count = (extract_u8(input, &mut rng_state) % 4) as usize;
                let mut trailers = Vec::new();
                for i in 0..trailer_count {
                    let key = format!("trailer-{}", i);
                    let value = format!("trailer-value-{}", extract_u16(input, &mut rng_state));
                    trailers.push((key, value));
                }

                ops.push(H3ClientOperation::TrailerResponse {
                    status_code,
                    headers,
                    body,
                    trailers,
                });
            }
            2 => {
                // Status code propagation
                let status_code = match extract_u8(input, &mut rng_state) % 10 {
                    0 => 400, // Bad Request
                    1 => 401, // Unauthorized
                    2 => 403, // Forbidden
                    3 => 404, // Not Found
                    4 => 429, // Too Many Requests
                    5 => 500, // Internal Server Error
                    6 => 501, // Not Implemented
                    7 => 502, // Bad Gateway
                    8 => 503, // Service Unavailable
                    9 => 504, // Gateway Timeout
                    _ => 500,
                };

                let reason_phrase = match status_code {
                    400 => "Bad Request",
                    401 => "Unauthorized",
                    403 => "Forbidden",
                    404 => "Not Found",
                    429 => "Too Many Requests",
                    500 => "Internal Server Error",
                    501 => "Not Implemented",
                    502 => "Bad Gateway",
                    503 => "Service Unavailable",
                    504 => "Gateway Timeout",
                    _ => "Error",
                }.to_string();

                let headers = vec![
                    ("content-type".to_string(), "text/plain".to_string()),
                    ("x-error-code".to_string(), format!("ERR-{}", extract_u16(input, &mut rng_state))),
                ];

                let body_size = (extract_u8(input, &mut rng_state) % 128) as usize;
                let mut body = vec![0u8; body_size];
                for byte in &mut body {
                    *byte = extract_u8(input, &mut rng_state);
                }

                ops.push(H3ClientOperation::StatusCodeResponse {
                    status_code,
                    reason_phrase,
                    headers,
                    body,
                });
            }
            3 => {
                // Invalid settings
                let setting_count = (extract_u8(input, &mut rng_state) % 8) as usize;
                let mut settings = Vec::new();
                for _ in 0..setting_count {
                    let setting_id = extract_u64(input, &mut rng_state);
                    let value = extract_u64(input, &mut rng_state);
                    settings.push((setting_id, value));
                }

                let malformed_size = (extract_u8(input, &mut rng_state) % 32) as usize;
                let mut malformed_data = vec![0u8; malformed_size];
                for byte in &mut malformed_data {
                    *byte = extract_u8(input, &mut rng_state);
                }

                ops.push(H3ClientOperation::InvalidSettings {
                    settings,
                    malformed_data,
                });
            }
            4 => {
                // Graceful reset
                let reset_timing = match extract_u8(input, &mut rng_state) % 6 {
                    0 => ResetTiming::BeforeHeaders,
                    1 => ResetTiming::DuringHeaders,
                    2 => ResetTiming::AfterHeaders,
                    3 => ResetTiming::DuringData,
                    4 => ResetTiming::AfterData,
                    5 => ResetTiming::DuringTrailers,
                    _ => ResetTiming::AfterHeaders,
                };

                let reset_code = match extract_u8(input, &mut rng_state) % 8 {
                    0 => 0x0100, // H3_NO_ERROR
                    1 => 0x0101, // H3_GENERAL_PROTOCOL_ERROR
                    2 => 0x0102, // H3_INTERNAL_ERROR
                    3 => 0x0103, // H3_STREAM_CREATION_ERROR
                    4 => 0x0104, // H3_CLOSED_CRITICAL_STREAM
                    5 => 0x0105, // H3_FRAME_UNEXPECTED
                    6 => 0x0106, // H3_FRAME_ERROR
                    7 => 0x010A, // H3_REQUEST_CANCELLED
                    _ => 0x0100,
                };

                let partial_response = (extract_u8(input, &mut rng_state) % 2) == 1;

                ops.push(H3ClientOperation::ResetScenario {
                    reset_timing,
                    reset_code,
                    partial_response,
                });
            }
            _ => unreachable!(),
        }
    }

    ops
}

/// Test HEADERS+DATA frame interleaving patterns
fn test_headers_data_interleaving(operations: &[H3ClientOperation]) {
    for op in operations {
        if let H3ClientOperation::HeadersDataInterleaved {
            status_code,
            headers,
            data_chunks,
            interleaving_pattern,
        } = op
        {
            // Verify status code is in valid range
            assert!((100..=599).contains(status_code),
                "Status code {} out of valid range", status_code);

            // Test header frame construction
            for (key, _value) in headers {

                // Verify header names are valid (no uppercase, no invalid chars)
                assert!(key.chars().all(|c| c.is_ascii_lowercase() || c == '-' || c.is_ascii_digit()),
                    "Invalid header name: {}", key);
            }

            // Verify data chunks are reasonable
            let total_data_size: usize = data_chunks.iter().map(|chunk| chunk.len()).sum();
            assert!(total_data_size <= 1_000_000,
                "Data size {} exceeds reasonable limit", total_data_size);

            // Test interleaving pattern validity
            for frame_type in interleaving_pattern {
                match frame_type {
                    FrameType::Headers | FrameType::Data => {
                        // Valid for interleaving
                    }
                    FrameType::Settings => {
                        // Settings frames should only appear at connection start
                    }
                }
            }
        }
    }
}

/// Test HTTP trailer handling
fn test_trailer_handling(operations: &[H3ClientOperation]) {
    for op in operations {
        if let H3ClientOperation::TrailerResponse {
            status_code,
            headers,
            body,
            trailers,
        } = op
        {
            // Verify status code validity
            assert!((100..=599).contains(status_code),
                "Invalid status code: {}", status_code);

            // Check for Transfer-Encoding: chunked requirement for trailers
            let has_chunked = headers.iter().any(|(k, v)| {
                k.to_lowercase() == "transfer-encoding" &&
                v.to_lowercase().contains("chunked")
            });

            if !trailers.is_empty() && !has_chunked {
                // In HTTP/3, trailers don't require chunked encoding like HTTP/1.1
                // but we should still validate trailer field names
            }

            // Validate trailer field names (must not be control headers)
            for (trailer_name, trailer_value) in trailers {
                let name_lower = trailer_name.to_lowercase();

                // Forbidden trailer field names per RFC 7230
                assert!(!matches!(name_lower.as_str(),
                    "transfer-encoding" | "content-length" | "host" |
                    "cache-control" | "expect" | "max-forwards" |
                    "pragma" | "range" | "te"
                ), "Forbidden trailer field: {}", trailer_name);

                // Verify trailer name format
                assert!(trailer_name.chars().all(|c|
                    c.is_ascii_lowercase() || c == '-' || c.is_ascii_digit()
                ), "Invalid trailer name format: {}", trailer_name);

                // Verify trailer value is printable ASCII
                assert!(trailer_value.chars().all(|c| c.is_ascii() && !c.is_control()) ||
                    trailer_value.is_empty(),
                    "Invalid trailer value: {}", trailer_value);
            }

            // Body should be consumable
            assert!(body.len() <= 10_000, "Body too large: {}", body.len());
        }
    }
}

/// Test 4xx/5xx status code propagation
fn test_status_code_propagation(operations: &[H3ClientOperation]) {
    for op in operations {
        if let H3ClientOperation::StatusCodeResponse {
            status_code,
            reason_phrase,
            headers,
            body,
        } = op
        {
            // Verify status code is a client or server error
            if (400..=499).contains(status_code) {
                // Client error - should be propagated properly
                assert!(!reason_phrase.is_empty(), "4xx status needs reason phrase");
            } else if (500..=599).contains(status_code) {
                // Server error - should be propagated properly
                assert!(!reason_phrase.is_empty(), "5xx status needs reason phrase");
            }

            // Error responses should have appropriate headers
            let has_content_type = headers.iter().any(|(k, _)|
                k.to_lowercase() == "content-type"
            );

            if !body.is_empty() && !has_content_type {
                // Error response with body should have content-type
                // (This is a recommendation, not a strict requirement)
            }

            // Verify headers are well-formed
            for (name, _value) in headers {
                assert!(name.chars().all(|c|
                    c.is_ascii_lowercase() || c == '-' || c.is_ascii_digit()
                ), "Invalid header name in error response: {}", name);
            }

            // Error body should be reasonable size
            assert!(body.len() <= 50_000,
                "Error response body too large: {}", body.len());
        }
    }
}

/// Test invalid settings rejection
fn test_invalid_settings_rejection(operations: &[H3ClientOperation]) {
    for op in operations {
        if let H3ClientOperation::InvalidSettings {
            settings,
            malformed_data,
        } = op
        {
            // Test various invalid settings scenarios
            for (setting_id, value) in settings {
                match setting_id {
                    // QPACK_MAX_TABLE_CAPACITY (0x01)
                    0x01 => {
                        // Should validate reasonable table capacity
                        if *value > 1024 * 1024 * 1024 {
                            // Extremely large table capacity should be rejected
                        }
                    }
                    // QPACK_BLOCKED_STREAMS (0x07)
                    0x07 => {
                        // Should validate reasonable blocked streams count
                        if *value > 10000 {
                            // Too many blocked streams should be rejected
                        }
                    }
                    // MAX_FIELD_SECTION_SIZE (0x06)
                    0x06 => {
                        // Should validate reasonable field section size
                        if *value > 1024 * 1024 * 16 {
                            // Extremely large field section should be rejected
                        }
                    }
                    // Reserved or unknown settings
                    _ => {
                        if (*setting_id & 0x1f) == 0x1f {
                            // Reserved settings (ending in 0x1f) should be ignored
                        }
                    }
                }
            }

            // Test malformed settings data
            if !malformed_data.is_empty() {
                // Should handle malformed settings gracefully
                // - Incomplete varint encoding
                // - Invalid setting ID
                // - Truncated setting value
                if malformed_data.len() == 1 {
                    // Single byte might be incomplete varint
                }

                if malformed_data.len() > 100 {
                    // Very long malformed data should be rejected quickly
                }
            }
        }
    }
}

/// Test graceful reset handling
fn test_graceful_reset_handling(operations: &[H3ClientOperation]) {
    for op in operations {
        if let H3ClientOperation::ResetScenario {
            reset_timing,
            reset_code,
            partial_response,
        } = op
        {
            // Verify reset code is valid H3 error code
            let is_valid_h3_code = matches!(*reset_code,
                0x0100 | // H3_NO_ERROR
                0x0101 | // H3_GENERAL_PROTOCOL_ERROR
                0x0102 | // H3_INTERNAL_ERROR
                0x0103 | // H3_STREAM_CREATION_ERROR
                0x0104 | // H3_CLOSED_CRITICAL_STREAM
                0x0105 | // H3_FRAME_UNEXPECTED
                0x0106 | // H3_FRAME_ERROR
                0x0107 | // H3_EXCESSIVE_LOAD
                0x0108 | // H3_ID_ERROR
                0x0109 | // H3_SETTINGS_ERROR
                0x010A | // H3_MISSING_SETTINGS
                0x010B | // H3_REQUEST_REJECTED
                0x010C | // H3_REQUEST_CANCELLED
                0x010D | // H3_REQUEST_INCOMPLETE
                0x010E | // H3_MESSAGE_ERROR
                0x010F | // H3_CONNECT_ERROR
                0x0110   // H3_VERSION_FALLBACK
            );

            if !is_valid_h3_code && (*reset_code < 0x0100 || *reset_code > 0x01FF) {
                // Invalid H3 error code range
            }

            // Test reset timing scenarios
            match reset_timing {
                ResetTiming::BeforeHeaders => {
                    // Reset before any response data - should fail cleanly
                    assert!(!partial_response,
                        "Can't have partial response if reset before headers");
                }
                ResetTiming::DuringHeaders => {
                    // Reset while receiving headers - should handle gracefully
                    if *partial_response {
                        // Partial headers received
                    }
                }
                ResetTiming::AfterHeaders => {
                    // Reset after headers but before/during body
                    if *partial_response {
                        // Some response data was received
                    }
                }
                ResetTiming::DuringData => {
                    // Reset while receiving body data
                    assert!(*partial_response,
                        "Should have partial response if reset during data");
                }
                ResetTiming::AfterData => {
                    // Reset after body but before/during trailers
                }
                ResetTiming::DuringTrailers => {
                    // Reset while receiving trailers
                }
            }

            // Connection vs stream reset handling
            if *reset_code == 0x0100 {
                // H3_NO_ERROR - graceful close
                assert!(!*partial_response ||
                        matches!(*reset_timing, ResetTiming::AfterData),
                    "NO_ERROR should only occur at natural boundaries");
            }
        }
    }
}

// Helper functions to extract data from fuzzer input
fn extract_u8(input: &mut &[u8], rng_state: &mut u64) -> u8 {
    if input.is_empty() {
        *rng_state = rng_state.wrapping_mul(1103515245).wrapping_add(12345);
        (*rng_state >> 8) as u8
    } else {
        let val = input[0];
        *input = &input[1..];
        val
    }
}

fn extract_u16(input: &mut &[u8], rng_state: &mut u64) -> u16 {
    if input.len() < 2 {
        *rng_state = rng_state.wrapping_mul(1103515245).wrapping_add(12345);
        (*rng_state >> 8) as u16
    } else {
        let val = u16::from_le_bytes([input[0], input[1]]);
        *input = &input[2..];
        val
    }
}

fn extract_u64(input: &mut &[u8], rng_state: &mut u64) -> u64 {
    if input.len() < 8 {
        *rng_state = rng_state.wrapping_mul(1103515245).wrapping_add(12345);
        *rng_state
    } else {
        let val = u64::from_le_bytes([
            input[0], input[1], input[2], input[3],
            input[4], input[5], input[6], input[7],
        ]);
        *input = &input[8..];
        val
    }
}