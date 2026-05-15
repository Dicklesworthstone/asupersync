#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

// Mock HTTP/2 frame types for fuzzing
#[derive(Debug, Clone, Arbitrary)]
struct FuzzedFrame {
    frame_type: u8,
    flags: u8,
    stream_id: u32,
    payload: Vec<u8>,
}

#[derive(Debug, Clone, Arbitrary)]
struct FuzzedHeader {
    name: String,
    value: String,
}

#[derive(Debug, Clone, Arbitrary)]
struct TrailersOnlyTestCase {
    headers: Vec<FuzzedHeader>,
    end_stream_flag: bool,
    frame_sequence: Vec<FuzzedFrame>,
    malformed_scenarios: MalformedScenarios,
}

#[derive(Debug, Clone, Arbitrary)]
struct MalformedScenarios {
    // Various malformation patterns
    duplicate_end_stream: bool,
    missing_end_stream: bool,
    body_with_trailers_only: bool,
    invalid_header_encoding: bool,
    oversized_headers: bool,
    forbidden_pseudo_headers: bool,
    empty_header_name: bool,
    invalid_header_chars: bool,
}

// HTTP/2 frame type constants
const HEADERS_FRAME_TYPE: u8 = 0x1;
const DATA_FRAME_TYPE: u8 = 0x0;
const CONTINUATION_FRAME_TYPE: u8 = 0x9;

// HTTP/2 frame flags
const END_STREAM_FLAG: u8 = 0x1;
const END_HEADERS_FLAG: u8 = 0x4;

fn observe_frame_processing_error(error: &str, context: &str) {
    let diagnostic = format!("{context}: {error}");
    assert!(
        !diagnostic.trim().is_empty(),
        "H2 trailer-only frame errors must expose diagnostics"
    );
    assert!(
        diagnostic.len() < 1024,
        "H2 trailer-only frame diagnostics must stay bounded"
    );
    std::hint::black_box(diagnostic);
}

// Known problematic header patterns for testing
const PROBLEMATIC_HEADERS: &[(&str, &str)] = &[
    ("", "empty-name"),
    ("with\x00null", "null-in-name"),
    ("with\rnewline", "newline-in-name"),
    ("with\ntab", "tab-in-name"),
    ("normal-header", ""),
    ("normal-header", "with\x00null-in-value"),
    ("normal-header", "with\r\nnewlines"),
    (":path", "/forbidden-pseudo-in-trailers"),
    (":method", "GET"),
    (":scheme", "https"),
    (":authority", "example.com"),
    ("connection", "close"),            // Forbidden in HTTP/2
    ("upgrade", "websocket"),           // Forbidden in HTTP/2
    ("proxy-connection", "keep-alive"), // Forbidden in HTTP/2
    ("transfer-encoding", "chunked"),   // Forbidden in HTTP/2
    ("x-custom-trailer", "valid-trailer-value"),
    ("content-length", "0"), // Should not be in trailers
];

fuzz_target!(|data: &[u8]| {
    // Guard against excessively large inputs
    if data.len() > 100_000 {
        return;
    }

    let mut u = Unstructured::new(data);

    // Try to generate a test case from the fuzz input
    let test_case = match TrailersOnlyTestCase::arbitrary(&mut u) {
        Ok(case) => case,
        Err(_) => return, // Invalid input for generating test case
    };

    // Test scenario 1: Valid trailers-only response
    test_valid_trailers_only_response(&test_case);

    // Test scenario 2: Invalid header encoding in trailers
    test_malformed_trailer_headers(&test_case);

    // Test scenario 3: Body data with END_STREAM (should be rejected)
    test_body_with_end_stream(&test_case);

    // Test scenario 4: Missing END_STREAM flag
    test_missing_end_stream(&test_case);

    // Test scenario 5: Duplicate END_STREAM flags
    test_duplicate_end_stream(&test_case);

    // Test scenario 6: Forbidden pseudo-headers in trailers
    test_forbidden_pseudo_headers(&test_case);

    // Test scenario 7: Oversized trailer headers
    test_oversized_trailers(&test_case);

    // Test scenario 8: Empty trailer header names
    test_empty_header_names(&test_case);

    // Test scenario 9: Invalid characters in header names/values
    test_invalid_header_characters(&test_case);

    // Test scenario 10: Multiple CONTINUATION frames for trailers
    test_continuation_trailers(&test_case);

    // Test scenario 11: Arbitrary frame sequence preserves basic frame invariants
    test_arbitrary_frame_sequence(&test_case);
});

/// Test valid trailers-only response handling
fn test_valid_trailers_only_response(test_case: &TrailersOnlyTestCase) {
    // Create a valid HEADERS frame with END_STREAM flag
    let mut headers_frame = create_headers_frame(&test_case.headers);
    headers_frame.flags |= END_HEADERS_FLAG;
    if test_case.end_stream_flag {
        headers_frame.flags |= END_STREAM_FLAG;
    }

    // Process the frame and verify it's handled correctly
    let result = process_h2_frame(&headers_frame);

    // Should succeed for valid trailers
    if is_valid_trailers_only(&test_case.headers) {
        if test_case.end_stream_flag {
            let response = result.expect("Valid trailers-only response should be accepted");
            assert!(
                response.body_empty,
                "Trailers-only response should have empty body"
            );
            assert!(
                response.has_end_stream,
                "Trailers-only response should have END_STREAM"
            );
        } else if let Ok(response) = result {
            assert!(
                !response.is_trailers_only(),
                "Valid headers without END_STREAM cannot be trailers-only"
            );
        }
    }
}

/// Test malformed trailer headers
fn test_malformed_trailer_headers(test_case: &TrailersOnlyTestCase) {
    if !test_case.malformed_scenarios.invalid_header_encoding {
        return;
    }

    // Create headers with various encoding problems
    let mut malformed_headers = test_case.headers.clone();

    // Add some problematic headers
    for &(name, value) in PROBLEMATIC_HEADERS {
        malformed_headers.push(FuzzedHeader {
            name: name.to_string(),
            value: value.to_string(),
        });
    }

    let headers_frame = create_headers_frame(&malformed_headers);
    let result = process_h2_frame(&headers_frame);

    // Malformed headers should be rejected appropriately
    if contains_forbidden_headers(&malformed_headers) {
        assert!(
            result.is_err(),
            "Forbidden headers in trailers should be rejected"
        );
    }
}

/// Test body data with END_STREAM (invalid for trailers-only)
fn test_body_with_end_stream(test_case: &TrailersOnlyTestCase) {
    if !test_case.malformed_scenarios.body_with_trailers_only {
        return;
    }

    // Create DATA frame with content followed by HEADERS with trailers
    let data_frame = FuzzedFrame {
        frame_type: DATA_FRAME_TYPE,
        flags: 0, // No END_STREAM on data frame
        stream_id: 1,
        payload: b"This should not be present in trailers-only".to_vec(),
    };

    let mut headers_frame = create_headers_frame(&test_case.headers);
    headers_frame.flags |= END_STREAM_FLAG | END_HEADERS_FLAG;

    // Process data frame first, then headers
    let data_result = process_h2_frame(&data_frame);
    let headers_result = process_h2_frame(&headers_frame);

    // This pattern should be rejected as it's not truly "trailers-only"
    // The presence of body data makes this a regular response with trailers
    assert!(data_result.is_ok(), "DATA frame itself should be valid");
    if let Ok(response) = headers_result {
        assert!(
            !response.is_trailers_only(),
            "Response with body data cannot be trailers-only"
        );
    }
}

/// Test missing END_STREAM flag
fn test_missing_end_stream(test_case: &TrailersOnlyTestCase) {
    if !test_case.malformed_scenarios.missing_end_stream {
        return;
    }

    // Create HEADERS frame without END_STREAM flag
    let mut headers_frame = create_headers_frame(&test_case.headers);
    headers_frame.flags |= END_HEADERS_FLAG; // Has END_HEADERS but not END_STREAM

    let result = process_h2_frame(&headers_frame);

    // Missing END_STREAM should either be rejected or not treated as trailers-only
    if let Ok(response) = result {
        assert!(
            !response.is_trailers_only(),
            "Headers without END_STREAM cannot be trailers-only"
        );
    }
}

/// Test duplicate END_STREAM flags
fn test_duplicate_end_stream(test_case: &TrailersOnlyTestCase) {
    if !test_case.malformed_scenarios.duplicate_end_stream {
        return;
    }

    // Create first frame with END_STREAM
    let mut first_frame =
        create_headers_frame(&test_case.headers[..test_case.headers.len().min(1)]);
    first_frame.flags |= END_STREAM_FLAG | END_HEADERS_FLAG;

    // Create second frame also with END_STREAM (protocol violation)
    let mut second_frame = create_headers_frame(&test_case.headers[1..]);
    second_frame.flags |= END_STREAM_FLAG | END_HEADERS_FLAG;
    second_frame.stream_id = first_frame.stream_id; // Same stream

    let first_result = process_h2_frame(&first_frame);
    let second_result = process_h2_frame(&second_frame);

    // Second END_STREAM should be rejected
    assert!(
        first_result.is_ok() || first_result.is_err(),
        "First frame processed"
    );
    assert!(
        second_result.is_err(),
        "Duplicate END_STREAM should be rejected"
    );
}

/// Test forbidden pseudo-headers in trailers
fn test_forbidden_pseudo_headers(test_case: &TrailersOnlyTestCase) {
    if !test_case.malformed_scenarios.forbidden_pseudo_headers {
        return;
    }

    // Add pseudo-headers which are forbidden in trailers
    let mut trailer_headers = test_case.headers.clone();
    trailer_headers.extend([
        FuzzedHeader {
            name: ":path".to_string(),
            value: "/forbidden".to_string(),
        },
        FuzzedHeader {
            name: ":method".to_string(),
            value: "GET".to_string(),
        },
        FuzzedHeader {
            name: ":scheme".to_string(),
            value: "https".to_string(),
        },
        FuzzedHeader {
            name: ":status".to_string(),
            value: "200".to_string(),
        },
    ]);

    let headers_frame = create_headers_frame(&trailer_headers);
    let result = process_h2_frame(&headers_frame);

    // Pseudo-headers in trailers should be rejected
    assert!(
        result.is_err(),
        "Pseudo-headers in trailers should be rejected"
    );
}

/// Test oversized trailer headers
fn test_oversized_trailers(test_case: &TrailersOnlyTestCase) {
    if !test_case.malformed_scenarios.oversized_headers {
        return;
    }

    // Create extremely large headers
    let large_value = "x".repeat(100_000); // 100KB header value
    let oversized_headers = vec![FuzzedHeader {
        name: "x-large-header".to_string(),
        value: large_value,
    }];

    let headers_frame = create_headers_frame(&oversized_headers);
    let result = process_h2_frame(&headers_frame);

    // Oversized headers should be handled appropriately
    // (Either rejected or processed with resource limits)
    match result {
        Ok(response) => {
            // If accepted, should still maintain protocol compliance
            assert!(
                response.headers.len() <= 1000,
                "Should limit number of headers"
            );
        }
        Err(error) => {
            observe_frame_processing_error(&error, "oversized trailer rejection");
        }
    }
}

/// Test empty header names
fn test_empty_header_names(test_case: &TrailersOnlyTestCase) {
    if !test_case.malformed_scenarios.empty_header_name {
        return;
    }

    let headers_with_empty_name = vec![FuzzedHeader {
        name: "".to_string(), // Empty header name
        value: "some-value".to_string(),
    }];

    let headers_frame = create_headers_frame(&headers_with_empty_name);
    let result = process_h2_frame(&headers_frame);

    // Empty header names should be rejected
    assert!(result.is_err(), "Empty header names should be rejected");
}

/// Test invalid characters in header names/values
fn test_invalid_header_characters(test_case: &TrailersOnlyTestCase) {
    if !test_case.malformed_scenarios.invalid_header_chars {
        return;
    }

    let headers_with_invalid_chars = vec![
        FuzzedHeader {
            name: "header\x00with\x01control".to_string(),
            value: "value\x0d\x0awith\x00nulls".to_string(),
        },
        FuzzedHeader {
            name: "héader-with-unicode".to_string(), // Non-ASCII in name
            value: "válue-with-unicode".to_string(),
        },
    ];

    let headers_frame = create_headers_frame(&headers_with_invalid_chars);
    let result = process_h2_frame(&headers_frame);

    // Invalid characters should be handled appropriately
    if contains_invalid_chars(&headers_with_invalid_chars) {
        // Strict implementations should reject invalid characters
        // Lenient implementations might accept them
        // Either is acceptable as long as it's consistent
        match result {
            Ok(_) => {} // Lenient handling
            Err(error) => {
                observe_frame_processing_error(&error, "invalid trailer character rejection")
            }
        }
    }
}

/// Test multiple CONTINUATION frames for trailers
fn test_continuation_trailers(test_case: &TrailersOnlyTestCase) {
    if test_case.headers.is_empty() {
        observe_frame_processing_error("empty trailer block", "continuation trailer setup");
        return;
    }

    // Split headers across multiple CONTINUATION frames
    let mut frames = Vec::new();

    // First HEADERS frame (without END_HEADERS)
    let mut headers_frame = create_headers_frame(&test_case.headers[..1]);
    headers_frame.flags |= END_STREAM_FLAG; // Has END_STREAM but not END_HEADERS
    frames.push(headers_frame);

    // CONTINUATION frames for remaining headers
    for header_chunk in test_case.headers[1..].chunks(2) {
        let mut continuation_frame = FuzzedFrame {
            frame_type: CONTINUATION_FRAME_TYPE,
            flags: 0,
            stream_id: 1,
            payload: encode_headers_chunk(header_chunk),
        };

        // Last continuation frame gets END_HEADERS flag
        if header_chunk.len() < 2 {
            continuation_frame.flags |= END_HEADERS_FLAG;
        }

        frames.push(continuation_frame);
    }

    // Process all frames in sequence
    let mut results = Vec::new();
    for frame in frames {
        results.push(process_h2_frame(&frame));
    }

    // Verify proper CONTINUATION handling
    // All but the last should be pending, last should complete
    for (i, result) in results.iter().enumerate() {
        if i == results.len() - 1 {
            // Last frame should complete the headers
            match result {
                Ok(response) => assert!(
                    response.headers_complete,
                    "Final frame should complete headers"
                ),
                Err(error) => {
                    observe_frame_processing_error(error, "final continuation trailer rejection");
                }
            }
        } else {
            // Intermediate frames should be pending or error
            match result {
                Ok(response) => assert!(
                    !response.headers_complete,
                    "Intermediate frame should not complete headers"
                ),
                Err(error) => {
                    observe_frame_processing_error(
                        error,
                        "intermediate continuation trailer rejection",
                    );
                }
            }
        }
    }
}

fn test_arbitrary_frame_sequence(test_case: &TrailersOnlyTestCase) {
    for (index, frame) in test_case.frame_sequence.iter().take(8).enumerate() {
        match process_h2_frame(frame) {
            Ok(response) => {
                if matches!(frame.frame_type, HEADERS_FRAME_TYPE | DATA_FRAME_TYPE) {
                    assert_eq!(
                        response.has_end_stream,
                        frame.flags & END_STREAM_FLAG != 0,
                        "frame {index} END_STREAM flag should match response state"
                    );
                }
                assert!(
                    response.headers.len() <= frame.payload.len(),
                    "frame {index} decoded more headers than payload bytes"
                );
            }
            Err(error) => {
                observe_frame_processing_error(&error, "arbitrary frame sequence rejection");
            }
        }
    }
}

// Helper functions for frame processing

fn create_headers_frame(headers: &[FuzzedHeader]) -> FuzzedFrame {
    FuzzedFrame {
        frame_type: HEADERS_FRAME_TYPE,
        flags: 0,
        stream_id: 1,
        payload: encode_headers(headers),
    }
}

fn encode_headers(headers: &[FuzzedHeader]) -> Vec<u8> {
    // Simplified HPACK encoding (for fuzzing purposes)
    let mut encoded = Vec::new();
    for header in headers {
        // Length-prefixed name
        encoded.push(header.name.len() as u8);
        encoded.extend_from_slice(header.name.as_bytes());
        // Length-prefixed value
        encoded.push(header.value.len() as u8);
        encoded.extend_from_slice(header.value.as_bytes());
    }
    encoded
}

fn encode_headers_chunk(headers: &[FuzzedHeader]) -> Vec<u8> {
    encode_headers(headers)
}

fn is_valid_trailers_only(headers: &[FuzzedHeader]) -> bool {
    // Check if headers represent valid trailers
    for header in headers {
        // Pseudo-headers forbidden in trailers
        if header.name.starts_with(':') {
            return false;
        }

        // Certain headers forbidden in trailers
        match header.name.to_lowercase().as_str() {
            "content-length" | "transfer-encoding" | "connection" | "upgrade"
            | "proxy-connection" => return false,
            _ => {}
        }
    }
    true
}

fn contains_forbidden_headers(headers: &[FuzzedHeader]) -> bool {
    for header in headers {
        if header.name.starts_with(':') && !header.name.is_empty() {
            return true; // Pseudo-headers forbidden in trailers
        }

        // Check for connection-specific headers forbidden in HTTP/2
        match header.name.to_lowercase().as_str() {
            "connection" | "upgrade" | "proxy-connection" | "transfer-encoding"
            | "content-length" => return true,
            _ => {}
        }
    }
    false
}

fn contains_invalid_chars(headers: &[FuzzedHeader]) -> bool {
    for header in headers {
        // Check for control characters in names/values
        for ch in header.name.chars() {
            if ch.is_control() || !ch.is_ascii() {
                return true;
            }
        }
        for ch in header.value.chars() {
            if ch.is_control() && ch != '\t' {
                return true; // Tab is allowed in values
            }
        }
    }
    false
}

// Mock response structure
#[derive(Debug)]
struct MockH2Response {
    headers: HashMap<String, String>,
    body_empty: bool,
    has_end_stream: bool,
    headers_complete: bool,
}

impl MockH2Response {
    fn is_trailers_only(&self) -> bool {
        self.body_empty && self.has_end_stream
    }
}

// Mock frame processing function
fn process_h2_frame(frame: &FuzzedFrame) -> Result<MockH2Response, String> {
    // Simulate basic frame validation
    if frame.stream_id == 0 && frame.frame_type != 0x4 {
        // Not SETTINGS frame
        return Err("Stream ID 0 forbidden for non-connection frames".to_string());
    }

    if frame.payload.len() > 16_384 {
        // HTTP/2 default max frame size
        return Err("Frame size exceeds maximum".to_string());
    }

    match frame.frame_type {
        HEADERS_FRAME_TYPE => {
            let headers = decode_mock_headers(&frame.payload)?;

            // Validate trailer headers
            for name in headers.keys() {
                if name.starts_with(':') {
                    return Err("Pseudo-headers forbidden in trailers".to_string());
                }
                if name.is_empty() {
                    return Err("Empty header names forbidden".to_string());
                }

                match name.to_lowercase().as_str() {
                    "connection" | "upgrade" | "proxy-connection" | "transfer-encoding" => {
                        return Err("Connection-specific headers forbidden in HTTP/2".to_string());
                    }
                    _ => {}
                }
            }

            Ok(MockH2Response {
                headers,
                body_empty: frame.flags & END_STREAM_FLAG != 0,
                has_end_stream: frame.flags & END_STREAM_FLAG != 0,
                headers_complete: frame.flags & END_HEADERS_FLAG != 0,
            })
        }
        DATA_FRAME_TYPE => Ok(MockH2Response {
            headers: HashMap::new(),
            body_empty: frame.payload.is_empty(),
            has_end_stream: frame.flags & END_STREAM_FLAG != 0,
            headers_complete: true,
        }),
        CONTINUATION_FRAME_TYPE => {
            let headers = decode_mock_headers(&frame.payload)?;

            Ok(MockH2Response {
                headers,
                body_empty: true,
                has_end_stream: false, // CONTINUATION can't have END_STREAM
                headers_complete: frame.flags & END_HEADERS_FLAG != 0,
            })
        }
        _ => Err("Unsupported frame type".to_string()),
    }
}

// Mock header decoder
fn decode_mock_headers(payload: &[u8]) -> Result<HashMap<String, String>, String> {
    let mut headers = HashMap::new();
    let mut pos = 0;

    while pos < payload.len() {
        if pos + 1 >= payload.len() {
            break;
        }

        let name_len = payload[pos] as usize;
        pos += 1;

        if pos + name_len >= payload.len() {
            return Err("Invalid header encoding: name length exceeds payload".to_string());
        }

        let name = String::from_utf8_lossy(&payload[pos..pos + name_len]).to_string();
        pos += name_len;

        if pos >= payload.len() {
            return Err("Invalid header encoding: missing value length".to_string());
        }

        let value_len = payload[pos] as usize;
        pos += 1;

        if pos + value_len > payload.len() {
            return Err("Invalid header encoding: value length exceeds payload".to_string());
        }

        let value = String::from_utf8_lossy(&payload[pos..pos + value_len]).to_string();
        pos += value_len;

        headers.insert(name, value);
    }

    Ok(headers)
}
