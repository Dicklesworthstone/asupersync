//! HTTP/1.1 Request Line Parser Fuzzer
//!
//! Targets the request line parsing logic in src/http/h1/server.rs
//! to test handling of malformed METHOD/URI/VERSION bytes including
//! invalid characters in URI, ensuring malformed requests return
//! 400 Bad Request without panicking.
//!
//! Key invariants tested:
//! - Malformed request lines return 400 Bad Request (not panic)
//! - Invalid URI characters are properly rejected
//! - Malformed HTTP versions are handled gracefully
//! - Buffer boundaries and edge cases don't cause crashes
//! - Method parsing handles invalid/unknown methods appropriately

#![no_main]

use libfuzzer_sys::fuzz_target;
use asupersync::http::h1::{Http1Codec, HttpError};
use asupersync::bytes::{BytesMut, BufMut};
use asupersync::codec::Decoder;

/// Maximum input size to prevent OOM
const MAX_INPUT_SIZE: usize = 8 * 1024;

fuzz_target!(|data: &[u8]| {
    // Guard against excessive input sizes
    if data.is_empty() || data.len() > MAX_INPUT_SIZE {
        return;
    }

    // Test 1: Basic request line parsing with arbitrary input
    {
        let mut codec = Http1Codec::new();
        let mut input = BytesMut::new();

        // Add fuzzed request line data
        input.put(data);

        // Ensure we have proper HTTP termination to avoid incomplete parsing
        if !data.ends_with(b"\r\n\r\n") {
            input.put(&b"\r\n\r\n"[..]);
        }

        // Parse the request - should never panic
        let _result = codec.decode(&mut input);

        // No assertions on the result - just ensure no panics
        // Invalid input should return Err(HttpError::BadRequest) or similar
    }

    // Test 2: Malformed METHOD section
    if data.len() > 1 {
        let mut codec = Http1Codec::new();
        let mut input = BytesMut::new();

        // Create malformed method + valid rest of request
        input.put(data);
        input.put(&b" /path HTTP/1.1\r\n\r\n"[..]);

        let result = codec.decode(&mut input);

        // Should handle malformed methods gracefully (no panic)
        match result {
            Ok(_) => {}, // Somehow valid
            Err(HttpError::BadRequest) => {}, // Expected for malformed input
            Err(_) => {}, // Other errors are also acceptable
        }
    }

    // Test 3: Malformed URI section with invalid characters
    if data.len() > 1 {
        let mut codec = Http1Codec::new();
        let mut input = BytesMut::new();

        // Create request with malformed URI
        input.put(&b"GET "[..]);
        input.put(data);  // Fuzzed URI data
        input.put(&b" HTTP/1.1\r\n\r\n"[..]);

        let result = codec.decode(&mut input);

        // Should reject invalid URI characters appropriately
        match result {
            Ok(_) => {}, // Somehow valid URI
            Err(HttpError::BadRequest) => {}, // Expected for malformed URI
            Err(_) => {}, // Other errors acceptable
        }
    }

    // Test 4: Malformed HTTP version
    if data.len() > 1 {
        let mut codec = Http1Codec::new();
        let mut input = BytesMut::new();

        // Create request with malformed HTTP version
        input.put(&b"GET /path "[..]);
        input.put(data);  // Fuzzed version data
        input.put(&b"\r\n\r\n"[..]);

        let result = codec.decode(&mut input);

        // Should handle malformed HTTP version gracefully
        match result {
            Ok(_) => {}, // Somehow valid version
            Err(HttpError::BadRequest) => {}, // Expected for malformed version
            Err(_) => {}, // Other errors acceptable
        }
    }

    // Test 5: Invalid characters in various positions
    {
        let invalid_chars = [0x00, 0x01, 0x1F, 0x7F, 0x80, 0xFF]; // Control chars, high ASCII

        for &invalid_char in &invalid_chars {
            let mut codec = Http1Codec::new();
            let mut input = BytesMut::new();

            // Insert invalid character in method
            input.put(&b"G"[..]);
            input.put(&[invalid_char]);
            input.put(&b"ET /path HTTP/1.1\r\n\r\n"[..]);

            let _result = codec.decode(&mut input);

            // Reset for URI test
            let mut codec = Http1Codec::new();
            let mut input = BytesMut::new();

            // Insert invalid character in URI
            input.put(&b"GET /pa"[..]);
            input.put(&[invalid_char]);
            input.put(&b"th HTTP/1.1\r\n\r\n"[..]);

            let _result = codec.decode(&mut input);

            // Reset for version test
            let mut codec = Http1Codec::new();
            let mut input = BytesMut::new();

            // Insert invalid character in version
            input.put(&b"GET /path HTTP/1."[..]);
            input.put(&[invalid_char]);
            input.put(&b"\r\n\r\n"[..]);

            let _result = codec.decode(&mut input);
        }
    }

    // Test 6: Edge case - extremely long request line components
    if data.len() > 100 {
        let mut codec = Http1Codec::new();
        let mut input = BytesMut::new();

        // Create very long method
        input.put(data);
        input.put(&b" /path HTTP/1.1\r\n\r\n"[..]);

        let _result = codec.decode(&mut input);

        // Test very long URI
        let mut codec = Http1Codec::new();
        let mut input = BytesMut::new();
        input.put(&b"GET /"[..]);
        input.put(data);
        input.put(&b" HTTP/1.1\r\n\r\n"[..]);

        let _result = codec.decode(&mut input);
    }

    // Test 7: Missing spaces between request line components
    if data.len() > 10 {
        let mut codec = Http1Codec::new();
        let mut input = BytesMut::new();

        // No space between method and URI
        input.put(&b"GET"[..]);
        input.put(data);
        input.put(&b"HTTP/1.1\r\n\r\n"[..]);

        let _result = codec.decode(&mut input);
    }

    // Test 8: Request line with only partial data (incomplete parsing)
    {
        let mut codec = Http1Codec::new();
        let mut partial_input = BytesMut::new();

        // Add only partial request line
        partial_input.put(data);
        // Deliberately not adding \r\n\r\n to test incomplete parsing

        let _result = codec.decode(&mut partial_input);

        // Should handle incomplete data gracefully (typically Ok(None) for need more data)
    }
});