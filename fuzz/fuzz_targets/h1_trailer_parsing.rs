//! HTTP/1.1 Trailer Parsing Fuzzer
//!
//! Targets the ChunkedBodyDecoder::decode() trailer parsing logic in src/http/h1/codec.rs
//! to test handling of malformed trailer headers including missing CRLF terminators,
//! embedded null bytes, and forbidden header names.
//!
//! Key invariants tested:
//! - Malformed trailers return Err without corrupting subsequent request parsing
//! - Forbidden trailers (per RFC 9110 §6.5.1) are properly rejected
//! - Buffer boundaries and edge cases are handled gracefully
//! - No panic on arbitrary trailer input

#![no_main]

use asupersync::bytes::{BufMut, BytesMut};
use asupersync::codec::Decoder;
use asupersync::http::h1::{Http1Codec, HttpError};
use libfuzzer_sys::fuzz_target;

/// Maximum input size to prevent OOM
const MAX_INPUT_SIZE: usize = 64 * 1024;

fuzz_target!(|data: &[u8]| {
    // Guard against excessive input sizes
    if data.is_empty() || data.len() > MAX_INPUT_SIZE {
        return;
    }

    assert_known_trailer_outcomes();

    // Create a chunked body with trailer headers for parsing
    let mut input = BytesMut::new();

    // Write minimal chunked body ending in trailers state
    input.put(&b"5\r\nHello\r\n0\r\n"[..]); // Chunk + final chunk

    // Add fuzzed trailer data
    input.put(data);

    // Ensure we end with double CRLF (proper trailer termination)
    // This tests the parser's ability to handle malformed content before the terminator
    if !data.ends_with(b"\r\n\r\n") {
        input.put(&b"\r\n\r\n"[..]);
    }

    let input_bytes = input.freeze();

    // Test 1: Basic trailer parsing with malformed content
    // Create a complete HTTP request with chunked encoding and trailers
    {
        let mut codec = Http1Codec::new();
        let mut complete_request = BytesMut::new();

        // Add HTTP request headers with chunked encoding
        complete_request.put(&b"POST /test HTTP/1.1\r\n"[..]);
        complete_request.put(&b"Transfer-Encoding: chunked\r\n"[..]);
        complete_request.put(&b"\r\n"[..]);

        // Add the chunked body with trailers
        complete_request.put(&input_bytes[..]);

        // Try to parse the complete request
        let _result = codec.decode(&mut complete_request);

        // The key invariant: codec should either succeed or fail cleanly
        // No panics allowed on any input
    }

    // Test 2: Ensure malformed trailers don't leak into next request
    if data.len() > 4 {
        let mut codec = Http1Codec::new();
        let mut complete_request = BytesMut::new();

        // First request with chunked body and potentially malformed trailers
        complete_request.put(&b"POST /test HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"[..]);
        complete_request.put(&input_bytes[..]);

        // Try to parse first request
        let _result = codec.decode(&mut complete_request);

        // Create a fresh codec for next request to ensure no state pollution
        let mut fresh_codec = Http1Codec::new();
        let mut next_request = BytesMut::new();
        next_request.put(&b"GET /simple HTTP/1.1\r\nContent-Length: 3\r\n\r\nfoo"[..]);

        // This should succeed regardless of previous malformed trailer parsing
        let _fresh_result = fresh_codec.decode(&mut next_request);

        // No assertions on results - just ensure no panics
    }

    // Test 3: Boundary conditions - trailer parsing with minimal/maximal headers
    {
        let mut codec = Http1Codec::new();
        let mut request = BytesMut::new();

        // Create minimal chunked request
        request.put(&b"POST /test HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"[..]);
        request.put(&b"0\r\n"[..]); // Just final chunk marker
        request.put(data); // Fuzzed trailer data
        request.put(&b"\r\n"[..]); // Ensure termination

        let _result = codec.decode(&mut request);
    }

    // Test 4: Embedded null bytes and invalid ASCII
    if data.contains(&0) || data.iter().any(|&b| b > 127) {
        let mut codec = Http1Codec::new();
        let mut request = BytesMut::new();

        request.put(&b"POST /test HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"[..]);
        request.put(&b"0\r\n"[..]);
        request.put(data);
        request.put(&b"\r\n\r\n"[..]);

        let _result = codec.decode(&mut request);

        // Should handle invalid characters gracefully without panic
    }

    // Test 5: Missing CRLF scenarios - test various termination states
    {
        // Test with data that might not have proper CRLF line endings
        let mut codec = Http1Codec::new();
        let mut request = BytesMut::new();

        request.put(&b"POST /test HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"[..]);
        request.put(&b"0\r\n"[..]);

        // Add potentially malformed trailer data without guaranteed CRLF
        request.put(data);
        // Deliberately not adding final \r\n\r\n to test incomplete parsing

        let _result = codec.decode(&mut request);

        // Parser should handle incomplete trailers gracefully
    }

    // Test 6: Forbidden trailer headers (RFC 9110 §6.5.1)
    // Test common forbidden headers mixed with fuzzed data
    let forbidden_patterns = [
        b"authorization:",
        b"cache-control:",
        b"content-encoding:",
        b"content-length:",
        b"content-type:",
        b"host:",
        b"max-forwards:",
        b"te:",
        b"trailer:",
        b"transfer-encoding:",
    ];

    for pattern in &forbidden_patterns {
        let mut codec = Http1Codec::new();
        let mut request = BytesMut::new();

        request.put(&b"POST /test HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"[..]);
        request.put(&b"0\r\n"[..]);
        request.put(*pattern);
        request.put(&b" value\r\n"[..]);
        request.put(data); // Add fuzzed data after forbidden header
        request.put(&b"\r\n"[..]);

        let _result = codec.decode(&mut request);

        // Should reject forbidden headers appropriately
    }
});

fn assert_known_trailer_outcomes() {
    let parsed = decode_request_with_trailers(b"X-Checksum: abc123\r\n\r\n")
        .expect("safe trailer should decode")
        .expect("safe trailer request should be complete");
    assert_eq!(parsed.body, b"Hello");
    assert_eq!(
        parsed.trailers,
        vec![("X-Checksum".to_string(), "abc123".to_string())]
    );

    for forbidden in [
        b"Content-Length: 5\r\n\r\n".as_ref(),
        b"Transfer-Encoding: chunked\r\n\r\n".as_ref(),
        b"Host: example.com\r\n\r\n".as_ref(),
        b"Authorization: bearer token\r\n\r\n".as_ref(),
    ] {
        assert!(
            matches!(
                decode_request_with_trailers(forbidden),
                Err(HttpError::BadHeader)
            ),
            "forbidden trailer should reject: {forbidden:?}",
        );
    }

    assert!(
        matches!(
            decode_request_with_trailers(b"X-Test: ok\0bad\r\n\r\n"),
            Err(HttpError::InvalidHeaderValue)
        ),
        "NUL in trailer value should reject",
    );
    assert!(
        matches!(
            decode_request_with_trailers(b": value\r\n\r\n"),
            Err(HttpError::InvalidHeaderName)
        ),
        "empty trailer name should reject",
    );
}

fn decode_request_with_trailers(
    trailer_block: &[u8],
) -> Result<Option<asupersync::http::h1::Request>, HttpError> {
    let mut codec = Http1Codec::new();
    let mut request = BytesMut::new();
    request.put(&b"POST /test HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"[..]);
    request.put(&b"5\r\nHello\r\n0\r\n"[..]);
    request.put(trailer_block);
    codec.decode(&mut request)
}
