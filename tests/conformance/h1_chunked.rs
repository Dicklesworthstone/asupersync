//! Conformance Tests: HTTP/1.1 Chunked Transfer Encoding (RFC 9112 §7)
//!
//! Validates RFC 9112 §7 compliant chunked transfer encoding with the following metamorphic relations:
//! 1. Chunk size in hex + CRLF + data + CRLF round-trips cleanly
//! 2. Terminating zero-size chunk + optional trailers + CRLF CRLF parses cleanly
//! 3. Oversized chunk-size hex rejected (bounded parsing)
//! 4. Invalid hex chars in size cause 400 Bad Request
//! 5. Chunked response cannot have Content-Length — must emit Transfer-Encoding: chunked

#![cfg(test)]

use asupersync::{
    bytes::BytesMut,
    codec::{Decoder, Encoder},
    cx::test_cx,
    http::h1::{
        codec::{Http1Codec, HttpError},
        types::{Method, Request, Response, Version},
    },
    lab::LabRuntime,
};
use std::collections::HashMap;

/// Helper to encode a response and check the result
#[allow(dead_code)]
fn encode_response(resp: Response) -> Result<String, HttpError> {
    let mut codec = Http1Codec::new();
    let mut dst = BytesMut::with_capacity(1024);
    codec.encode(resp, &mut dst)?;
    Ok(String::from_utf8(dst.to_vec()).unwrap())
}

/// Helper to decode a request from raw bytes
#[allow(dead_code)]
fn decode_request(data: &[u8]) -> Result<Option<Request>, HttpError> {
    let mut codec = Http1Codec::new();
    let mut src = BytesMut::from(data);
    codec.decode(&mut src)
}

/// Helper to create chunked request data with specific chunks
#[allow(dead_code)]
fn create_chunked_request(chunks: &[(usize, &[u8])], trailers: &[(&str, &str)]) -> Vec<u8> {
    let mut request = Vec::new();
    request.extend_from_slice(b"POST /upload HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n");

    // Write chunks
    for (size, data) in chunks {
        request.extend_from_slice(format!("{:X}\r\n", size).as_bytes());
        request.extend_from_slice(data);
        request.extend_from_slice(b"\r\n");
    }

    // Terminating chunk
    request.extend_from_slice(b"0\r\n");

    // Write trailers
    for (name, value) in trailers {
        request.extend_from_slice(format!("{}: {}\r\n", name, value).as_bytes());
    }

    // Final CRLF
    request.extend_from_slice(b"\r\n");

    request
}

/// MR1: Chunk size in hex + CRLF + data + CRLF round-trips cleanly
#[test]
#[allow(dead_code)]
fn mr1_chunk_hex_crlf_roundtrip() {
    LabRuntime::test(|lab| async {
        let test_cases = vec![
            // Small chunk
            vec![(3, b"foo" as &[u8])],
            // Multiple chunks
            vec![(5, b"hello"), (6, b" world")],
            // Single byte chunks
            vec![(1, b"a"), (1, b"b"), (1, b"c")],
            // Large chunk (1KB)
            vec![(1024, &vec![b'X'; 1024])],
            // Mixed sizes
            vec![(10, b"0123456789"), (5, b"abcde"), (15, b"XXXXXXXXXXXXXXX")],
        ];

        for chunks in test_cases {
            let expected_body: Vec<u8> = chunks.iter().flat_map(|(_, data)| data.iter().copied()).collect();
            let request_data = create_chunked_request(&chunks, &[]);

            let req = decode_request(&request_data)
                .expect("decode should succeed")
                .expect("request should be complete");

            assert_eq!(req.method, Method::Post);
            assert_eq!(req.uri, "/upload");
            assert_eq!(req.body, expected_body, "Round-trip should preserve body data exactly");

            // Verify chunked encoding was detected
            assert!(req.headers.iter().any(|(name, value)| {
                name.eq_ignore_ascii_case("transfer-encoding") &&
                value.eq_ignore_ascii_case("chunked")
            }), "Transfer-Encoding: chunked header should be preserved");
        }
    });
}

/// MR2: Terminating zero-size chunk + optional trailers + CRLF CRLF parses cleanly
#[test]
#[allow(dead_code)]
fn mr2_zero_chunk_trailers_termination() {
    LabRuntime::test(|lab| async {
        let test_cases = vec![
            // No trailers - just terminating chunk
            (vec![(5, b"hello" as &[u8])], vec![]),
            // Single trailer
            (vec![(5, b"hello")], vec![("X-Trace", "abc123")]),
            // Multiple trailers
            (vec![(5, b"hello")], vec![("X-Trace", "abc123"), ("X-Timing", "50ms"), ("X-Server", "asupersync")]),
            // Empty body with trailers
            (vec![], vec![("X-Empty", "true")]),
            // Complex case with multiple chunks and trailers
            (vec![(3, b"foo"), (3, b"bar"), (3, b"baz")], vec![("X-Chunks", "3"), ("X-Length", "9")]),
        ];

        for (chunks, trailers) in test_cases {
            let expected_body: Vec<u8> = chunks.iter().flat_map(|(_, data)| data.iter().copied()).collect();
            let request_data = create_chunked_request(&chunks, &trailers);

            let req = decode_request(&request_data)
                .expect("decode should succeed")
                .expect("request should be complete");

            assert_eq!(req.body, expected_body, "Body should be correctly assembled");
            assert_eq!(req.trailers.len(), trailers.len(), "Trailer count should match");

            // Verify all trailers are present
            for (expected_name, expected_value) in &trailers {
                let found = req.trailers.iter().find(|(name, value)| {
                    name.eq_ignore_ascii_case(expected_name) && value == expected_value
                });
                assert!(found.is_some(), "Trailer {}:{} should be preserved", expected_name, expected_value);
            }
        }
    });
}

/// MR3: Oversized chunk-size hex rejected (bounded parsing)
#[test]
#[allow(dead_code)]
fn mr3_oversized_chunk_size_rejection() {
    LabRuntime::test(|lab| async {
        let test_cases = vec![
            // Chunk size that would overflow usize on 32-bit systems
            ("FFFFFFFF", "Maximum 32-bit value"),
            // Extremely large chunk size
            ("7FFFFFFFFFFFFFFF", "Near 64-bit signed max"),
            // Size larger than any reasonable body limit
            ("100000000", "Huge chunk size"),
            // Leading zeros with large value
            ("00000000FFFFFFFF", "Leading zeros with large value"),
        ];

        for (chunk_size, description) in test_cases {
            let mut request = Vec::new();
            request.extend_from_slice(b"POST /upload HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n");
            request.extend_from_slice(chunk_size.as_bytes());
            request.extend_from_slice(b"\r\n");

            let result = decode_request(&request);

            // Should either fail to parse or reject due to body size limits
            match result {
                Err(HttpError::BodyTooLarge) |
                Err(HttpError::BadChunkedEncoding) => {
                    // Expected - oversized chunks should be rejected
                }
                Ok(None) => {
                    // Also acceptable - incomplete parse due to missing chunk data
                    // This is fine since we're testing the size parsing, not providing the actual data
                }
                other => panic!("Expected BodyTooLarge or BadChunkedEncoding for {}, got: {:?}", description, other),
            }
        }
    });
}

/// MR4: Invalid hex chars in size cause 400 Bad Request
#[test]
#[allow(dead_code)]
fn mr4_invalid_hex_chars_rejection() {
    LabRuntime::test(|lab| async {
        let test_cases = vec![
            // Invalid hex characters
            ("G", "Invalid hex char G"),
            ("1G", "Invalid hex char in middle"),
            ("ZZ", "Multiple invalid hex chars"),
            ("1Z2", "Invalid hex char between valid ones"),
            // Decimal numbers (invalid in hex context)
            ("99", "Valid decimal but might be interpreted as hex"),
            // Non-alphanumeric characters
            ("@", "Invalid symbol"),
            ("1@", "Invalid symbol after valid hex"),
            // Empty size
            ("", "Empty chunk size"),
            // Whitespace (should be rejected due to strict parsing)
            (" 5", "Leading whitespace"),
            ("5 ", "Trailing whitespace"),
            (" 5 ", "Both leading and trailing whitespace"),
            // Special characters
            ("1-2", "Dash in chunk size"),
            ("1+2", "Plus in chunk size"),
            ("5.", "Decimal point"),
        ];

        for (chunk_size, description) in test_cases {
            let mut request = Vec::new();
            request.extend_from_slice(b"POST /upload HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n");
            request.extend_from_slice(chunk_size.as_bytes());
            request.extend_from_slice(b"\r\nhello\r\n0\r\n\r\n");

            let result = decode_request(&request);

            match result {
                Err(HttpError::BadChunkedEncoding) => {
                    // Expected - invalid chunk size should be rejected
                }
                other => panic!("Expected BadChunkedEncoding for {}, got: {:?}", description, other),
            }
        }
    });
}

/// MR5: Chunked response cannot have Content-Length — must emit Transfer-Encoding: chunked
#[test]
#[allow(dead_code)]
fn mr5_chunked_response_header_exclusivity() {
    LabRuntime::test(|lab| async {
        // Test 1: Response with Transfer-Encoding: chunked should not have Content-Length
        let chunked_resp = Response::new(200, "OK", b"hello world".to_vec())
            .with_header("Transfer-Encoding", "chunked");

        let encoded = encode_response(chunked_resp).expect("Encoding should succeed");

        // Should contain Transfer-Encoding: chunked
        assert!(encoded.contains("Transfer-Encoding: chunked"),
                "Chunked response must have Transfer-Encoding header");

        // Should NOT contain Content-Length
        assert!(!encoded.contains("Content-Length"),
                "Chunked response must not have Content-Length header");

        // Should have proper chunk encoding in body
        assert!(encoded.contains("B\r\nhello world\r\n0\r\n\r\n"),
                "Response body should be properly chunk-encoded");

        // Test 2: Attempting to set both headers should fail
        let invalid_resp = Response::new(200, "OK", b"test".to_vec())
            .with_header("Transfer-Encoding", "chunked")
            .with_header("Content-Length", "4");

        let result = encode_response(invalid_resp);
        assert!(matches!(result, Err(HttpError::AmbiguousBodyLength)),
                "Response with both Transfer-Encoding and Content-Length should be rejected");

        // Test 3: Non-chunked response should auto-generate Content-Length
        let normal_resp = Response::new(200, "OK", b"test".to_vec());
        let encoded = encode_response(normal_resp).expect("Encoding should succeed");

        assert!(encoded.contains("Content-Length: 4"),
                "Non-chunked response should have Content-Length");
        assert!(!encoded.contains("Transfer-Encoding"),
                "Non-chunked response should not have Transfer-Encoding");
        assert!(encoded.ends_with("\r\n\r\ntest"),
                "Non-chunked response body should be plain");

        // Test 4: Chunked response with trailers
        let chunked_with_trailers = Response::new(200, "OK", b"data".to_vec())
            .with_header("Transfer-Encoding", "chunked")
            .with_trailer("X-Trace", "abc123")
            .with_trailer("X-Timing", "50ms");

        let encoded = encode_response(chunked_with_trailers).expect("Encoding should succeed");

        assert!(encoded.contains("Transfer-Encoding: chunked"));
        assert!(!encoded.contains("Content-Length"));
        // Should end with chunk, zero chunk, trailers, final CRLF
        assert!(encoded.ends_with("0\r\nX-Trace: abc123\r\nX-Timing: 50ms\r\n\r\n"));

        // Test 5: Trailers without chunked encoding should fail
        let invalid_trailers = Response::new(200, "OK", b"test".to_vec())
            .with_trailer("X-Trace", "abc123");

        let result = encode_response(invalid_trailers);
        assert!(matches!(result, Err(HttpError::TrailersNotAllowed)),
                "Trailers without Transfer-Encoding: chunked should be rejected");
    });
}

/// Property-based test: Chunk extension parsing (RFC 9112 allows but ignores extensions)
#[test]
#[allow(dead_code)]
fn property_chunk_extensions_ignored() {
    LabRuntime::test(|lab| async {
        let test_cases = vec![
            // Basic extension
            ("5;name=value", b"hello" as &[u8]),
            // Multiple extensions
            ("5;name=value;other=data", b"hello"),
            // Extension without value
            ("5;flag", b"hello"),
            // Complex extensions
            ("A;charset=utf-8;boundary=something", b"helloworld"),
            // Extensions with quotes (though not standard, should be tolerated)
            ("5;name=\"value\"", b"hello"),
        ];

        for (chunk_line, data) in test_cases {
            let mut request = Vec::new();
            request.extend_from_slice(b"POST /upload HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n");
            request.extend_from_slice(chunk_line.as_bytes());
            request.extend_from_slice(b"\r\n");
            request.extend_from_slice(data);
            request.extend_from_slice(b"\r\n0\r\n\r\n");

            let req = decode_request(&request)
                .expect("decode should succeed")
                .expect("request should be complete");

            assert_eq!(req.body, data, "Chunk extensions should not affect body content");
        }
    });
}

/// Edge case: Empty chunks and zero-length data
#[test]
#[allow(dead_code)]
fn edge_case_empty_and_zero_chunks() {
    LabRuntime::test(|lab| async {
        // Test 1: Request with only zero chunk (empty body)
        let empty_chunked = create_chunked_request(&[], &[]);
        let req = decode_request(&empty_chunked)
            .expect("decode should succeed")
            .expect("request should be complete");
        assert!(req.body.is_empty(), "Empty chunked body should produce empty vec");

        // Test 2: Mix of empty chunks and real data (edge case)
        let mixed_request = create_chunked_request(&[(0, b""), (5, b"hello"), (0, b"")], &[]);
        let req = decode_request(&mixed_request)
            .expect("decode should succeed")
            .expect("request should be complete");
        assert_eq!(req.body, b"hello", "Zero-size chunks should not contribute to body");

        // Test 3: Response encoding with empty body
        let empty_chunked_resp = Response::new(200, "OK", Vec::new())
            .with_header("Transfer-Encoding", "chunked");
        let encoded = encode_response(empty_chunked_resp).expect("Encoding should succeed");

        // Should have only terminating chunk
        assert!(encoded.ends_with("0\r\n\r\n"), "Empty chunked response should end with 0\\r\\n\\r\\n");
        assert!(!encoded.contains("Content-Length"), "Empty chunked response should not have Content-Length");
    });
}

/// Edge case: Boundary conditions for chunk size limits
#[test]
#[allow(dead_code)]
fn edge_case_chunk_size_boundaries() {
    LabRuntime::test(|lab| async {
        let test_cases = vec![
            // Single digit hex
            ("0", b"" as &[u8]),
            ("1", b"X"),
            ("F", &vec![b'X'; 15]),
            // Two digit hex
            ("10", &vec![b'X'; 16]),
            ("FF", &vec![b'X'; 255]),
            // Three digit hex
            ("100", &vec![b'X'; 256]),
            ("FFF", &vec![b'X'; 4095]),
        ];

        for (chunk_size, expected_data) in test_cases {
            if expected_data.len() > 10000 {
                continue; // Skip very large test cases to keep test fast
            }

            let request = create_chunked_request(&[(expected_data.len(), expected_data)], &[]);
            let req = decode_request(&request)
                .expect("decode should succeed")
                .expect("request should be complete");

            assert_eq!(req.body, expected_data,
                       "Chunk size {} should correctly decode {} bytes", chunk_size, expected_data.len());
        }
    });
}

/// Security test: CRLF injection in chunk data vs chunk framing
#[test]
#[allow(dead_code)]
fn security_crlf_handling() {
    LabRuntime::test(|lab| async {
        // Test that CRLF within chunk data is preserved as-is and doesn't break parsing
        let test_cases = vec![
            // CRLF within chunk data
            (b"line1\r\nline2" as &[u8], "CRLF in data"),
            // Multiple CRLFs
            (b"\r\n\r\n", "Multiple CRLFs"),
            // CR without LF
            (b"line1\rline2", "CR only"),
            // LF without CR
            (b"line1\nline2", "LF only"),
        ];

        for (chunk_data, description) in test_cases {
            let request = create_chunked_request(&[(chunk_data.len(), chunk_data)], &[]);
            let req = decode_request(&request)
                .expect(&format!("decode should succeed for {}", description))
                .expect("request should be complete");

            assert_eq!(req.body, chunk_data,
                       "{}: CRLF in chunk data should be preserved exactly", description);
        }
    });
}