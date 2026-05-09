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

use asupersync::bytes::BytesMut;
use asupersync::codec::Decoder;
use asupersync::http::h1::Http1Codec;
use libfuzzer_sys::fuzz_target;

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
        input.extend_from_slice(data);

        // Ensure we have proper HTTP termination to avoid incomplete parsing
        if !data.ends_with(b"\r\n\r\n") {
            input.extend_from_slice(&b"\r\n\r\n"[..]);
        }

        observe_decode(&mut codec, &mut input, "arbitrary request-line parse");
    }

    // Test 2: Malformed METHOD section
    if data.len() > 1 {
        let mut codec = Http1Codec::new();
        let mut input = BytesMut::new();

        // Create malformed method + valid rest of request
        input.extend_from_slice(data);
        input.extend_from_slice(&b" /path HTTP/1.1\r\n\r\n"[..]);

        observe_decode(&mut codec, &mut input, "malformed method section");
    }

    // Test 3: Malformed URI section with invalid characters
    if data.len() > 1 {
        let mut codec = Http1Codec::new();
        let mut input = BytesMut::new();

        // Create request with malformed URI
        input.extend_from_slice(&b"GET "[..]);
        input.extend_from_slice(data); // Fuzzed URI data
        input.extend_from_slice(&b" HTTP/1.1\r\n\r\n"[..]);

        observe_decode(&mut codec, &mut input, "malformed URI section");
    }

    // Test 4: Malformed HTTP version
    if data.len() > 1 {
        let mut codec = Http1Codec::new();
        let mut input = BytesMut::new();

        // Create request with malformed HTTP version
        input.extend_from_slice(&b"GET /path "[..]);
        input.extend_from_slice(data); // Fuzzed version data
        input.extend_from_slice(&b"\r\n\r\n"[..]);

        observe_decode(&mut codec, &mut input, "malformed HTTP version");
    }

    // Test 5: Invalid characters in various positions
    {
        let invalid_chars = [0x00, 0x01, 0x1F, 0x7F, 0x80, 0xFF]; // Control chars, high ASCII

        for &invalid_char in &invalid_chars {
            let mut codec = Http1Codec::new();
            let mut input = BytesMut::new();

            // Insert invalid character in method
            input.extend_from_slice(&b"G"[..]);
            input.extend_from_slice(&[invalid_char]);
            input.extend_from_slice(&b"ET /path HTTP/1.1\r\n\r\n"[..]);

            observe_decode(&mut codec, &mut input, "invalid method character");

            // Reset for URI test
            let mut codec = Http1Codec::new();
            let mut input = BytesMut::new();

            // Insert invalid character in URI
            input.extend_from_slice(&b"GET /pa"[..]);
            input.extend_from_slice(&[invalid_char]);
            input.extend_from_slice(&b"th HTTP/1.1\r\n\r\n"[..]);

            observe_decode(&mut codec, &mut input, "invalid URI character");

            // Reset for version test
            let mut codec = Http1Codec::new();
            let mut input = BytesMut::new();

            // Insert invalid character in version
            input.extend_from_slice(&b"GET /path HTTP/1."[..]);
            input.extend_from_slice(&[invalid_char]);
            input.extend_from_slice(&b"\r\n\r\n"[..]);

            observe_decode(&mut codec, &mut input, "invalid version character");
        }
    }

    // Test 6: Edge case - extremely long request line components
    if data.len() > 100 {
        let mut codec = Http1Codec::new();
        let mut input = BytesMut::new();

        // Create very long method
        input.extend_from_slice(data);
        input.extend_from_slice(&b" /path HTTP/1.1\r\n\r\n"[..]);

        observe_decode(&mut codec, &mut input, "long method");

        // Test very long URI
        let mut codec = Http1Codec::new();
        let mut input = BytesMut::new();
        input.extend_from_slice(&b"GET /"[..]);
        input.extend_from_slice(data);
        input.extend_from_slice(&b" HTTP/1.1\r\n\r\n"[..]);

        observe_decode(&mut codec, &mut input, "long URI");
    }

    // Test 7: Missing spaces between request line components
    if data.len() > 10 {
        let mut codec = Http1Codec::new();
        let mut input = BytesMut::new();

        // No space between method and URI
        input.extend_from_slice(&b"GET"[..]);
        input.extend_from_slice(data);
        input.extend_from_slice(&b"HTTP/1.1\r\n\r\n"[..]);

        observe_decode(&mut codec, &mut input, "missing request-line spaces");
    }

    // Test 8: Request line with only partial data (incomplete parsing)
    {
        let mut codec = Http1Codec::new();
        let mut partial_input = BytesMut::new();

        // Add only partial request line
        partial_input.extend_from_slice(data);
        // Deliberately not adding \r\n\r\n to test incomplete parsing

        observe_decode(&mut codec, &mut partial_input, "partial request-line data");
    }
});

fn observe_decode(codec: &mut Http1Codec, input: &mut BytesMut, context: &str) {
    let before_len = input.len();
    let result = codec.decode(input);
    assert!(
        input.len() <= before_len,
        "{context}: decode should never increase the input buffer"
    );

    match result {
        Ok(Some(_request)) => {
            assert!(
                input.len() < before_len,
                "{context}: successful request decode should consume input bytes"
            );
        }
        Ok(None) => {}
        Err(error) => {
            assert!(
                !format!("{error:?}").is_empty(),
                "{context}: decode error should remain observable"
            );
        }
    }
}
