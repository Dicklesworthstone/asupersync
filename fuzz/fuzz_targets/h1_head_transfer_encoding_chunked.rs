//! HTTP/1.1 HEAD response with Transfer-Encoding chunked fuzzing target.
//!
//! Tests RFC 9110 compliance: HEAD responses MUST NOT include a message body,
//! regardless of headers (including Transfer-Encoding: chunked).
//!
//! This fuzzer generates arbitrary chunked body data and verifies:
//! 1. HEAD responses with Transfer-Encoding chunked are encoded successfully
//! 2. Body bytes are silently discarded (HEAD has no body per RFC 9110)
//! 3. Transfer-Encoding header is preserved in response line
//! 4. No panics occur with arbitrary chunked body data

#![no_main]

use arbitrary::Arbitrary;
use asupersync::http::h1::{codec::Http1Codec, types::Response};
use asupersync::bytes::BytesMut;
use asupersync::codec::Encoder;
use libfuzzer_sys::fuzz_target;

/// HEAD response test with arbitrary chunked body data
#[derive(Debug, Clone, Arbitrary)]
struct HeadChunkedResponse {
    /// Status code for the response
    status_code: u16,
    /// Additional headers beyond Transfer-Encoding
    additional_headers: Vec<AdditionalHeader>,
    /// Arbitrary body data that should be discarded
    body_data: Vec<u8>,
    /// Trailer headers (should also be discarded for HEAD)
    trailers: Vec<TrailerHeader>,
}

/// Additional header for the response
#[derive(Debug, Clone, Arbitrary)]
struct AdditionalHeader {
    /// Header name (will be validated for HTTP compliance)
    name: HeaderName,
    /// Header value
    value: String,
}

/// Trailer header (for chunked responses)
#[derive(Debug, Clone, Arbitrary)]
struct TrailerHeader {
    /// Trailer name
    name: HeaderName,
    /// Trailer value
    value: String,
}

/// Common HTTP header names for testing
#[derive(Debug, Clone, Arbitrary)]
enum HeaderName {
    ContentType,
    ContentLength,
    CacheControl,
    ETag,
    LastModified,
    Server,
    Date,
    Custom(String),
}

impl HeaderName {
    fn as_str(&self) -> String {
        match self {
            Self::ContentType => "Content-Type".to_string(),
            Self::ContentLength => "Content-Length".to_string(),
            Self::CacheControl => "Cache-Control".to_string(),
            Self::ETag => "ETag".to_string(),
            Self::LastModified => "Last-Modified".to_string(),
            Self::Server => "Server".to_string(),
            Self::Date => "Date".to_string(),
            Self::Custom(name) => {
                // Sanitize custom header name for HTTP compliance
                sanitize_header_name(name)
            }
        }
    }
}

/// Sanitize a string to be a valid HTTP header name
fn sanitize_header_name(input: &str) -> String {
    input
        .chars()
        .filter(|&c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        .take(64) // Reasonable header name length limit
        .collect::<String>()
        .trim_matches('-')
        .trim_matches('_')
        .to_string()
}

/// Sanitize a string to be a valid HTTP header value
fn sanitize_header_value(input: &str) -> String {
    input
        .chars()
        .filter(|&c| c.is_ascii() && c != '\r' && c != '\n' && c != '\0')
        .take(1024) // Reasonable header value length limit
        .collect()
}

fuzz_target!(|data: &[u8]| {
    // Guard against excessive input size to prevent timeouts
    if data.len() > 100_000 {
        return;
    }

    let mut u = arbitrary::Unstructured::new(data);

    // Generate HEAD response test case
    let test_case = match HeadChunkedResponse::arbitrary(&mut u) {
        Ok(case) => case,
        Err(_) => return, // Not enough input data
    };

    // Limit the number of headers and body size for performance
    if test_case.additional_headers.len() > 20
        || test_case.trailers.len() > 10
        || test_case.body_data.len() > 50_000 {
        return;
    }

    // Test HEAD response encoding with Transfer-Encoding chunked
    test_head_chunked_encoding(&test_case);

    // Test various status codes with HEAD responses
    test_head_status_codes(&test_case);

    // Test malformed header handling
    test_malformed_headers(&test_case);

    // Test edge cases in chunked body data
    test_chunked_body_edge_cases(&test_case);
});

/// Test HEAD response with Transfer-Encoding chunked
fn test_head_chunked_encoding(test_case: &HeadChunkedResponse) {
    let mut response = Response::new(
        test_case.status_code.max(100).min(599), // Valid HTTP status range
        "Test Response",
        test_case.body_data.clone()
    );

    // Add Transfer-Encoding: chunked header
    response.headers.push(("Transfer-Encoding".to_string(), "chunked".to_string()));

    // Add additional headers
    for header in &test_case.additional_headers {
        let name = header.name.as_str();
        if !name.is_empty() && name != "Transfer-Encoding" {
            let value = sanitize_header_value(&header.value);
            if !value.is_empty() {
                response.headers.push((name, value));
            }
        }
    }

    // Add trailers
    for trailer in &test_case.trailers {
        let name = trailer.name.as_str();
        if !name.is_empty() {
            let value = sanitize_header_value(&trailer.value);
            if !value.is_empty() {
                response.trailers.push((name, value));
            }
        }
    }

    // Test encoding - should succeed and discard body for HEAD
    let encoding_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut codec = Http1Codec::new();
        let mut dst = BytesMut::new();
        let result = codec.encode(response, &mut dst);
        (result, dst)
    }));

    assert!(encoding_result.is_ok(), "HEAD response encoding should not panic");

    if let Ok((Ok(()), dst)) = encoding_result {
        let response_bytes = dst.freeze();
        let response_str = String::from_utf8_lossy(&response_bytes);

        // Verify Transfer-Encoding header is present
        assert!(response_str.contains("Transfer-Encoding: chunked"),
            "Transfer-Encoding header should be preserved in HEAD response");

        // Critical assertion: HEAD responses must not have a body
        // Look for the end of headers (CRLFCRLF) and verify no body follows
        if let Some(headers_end) = response_str.find("\r\n\r\n") {
            let body_section = &response_str[headers_end + 4..];

            // RFC 9110 Section 9.3.2: HEAD responses MUST NOT include message body
            assert!(body_section.is_empty() || body_section.trim().is_empty(),
                "HEAD response must not include message body, found: {:?}",
                body_section.chars().take(100).collect::<String>());
        }

        // Verify response starts with valid status line
        assert!(response_str.starts_with("HTTP/1.1"),
            "Response should start with HTTP/1.1 status line");
    }
}

/// Test HEAD responses with various status codes
fn test_head_status_codes(test_case: &HeadChunkedResponse) {
    let status_codes = [
        200, 201, 204, 301, 302, 304, 400, 401, 403, 404, 500, 502, 503
    ];

    for &status in &status_codes {
        let response = Response::new(status, "Test", test_case.body_data.clone())
            .with_header("Transfer-Encoding", "chunked");

        let encoding_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut codec = Http1Codec::new();
            let mut dst = BytesMut::new();
            let result = codec.encode(response, &mut dst);
            (result, dst)
        }));

        assert!(encoding_result.is_ok(),
            "HEAD response with status {} should encode without panic", status);
    }
}

/// Test malformed header handling in HEAD responses
fn test_malformed_headers(_test_case: &HeadChunkedResponse) {
    let long_header_name = "X-".repeat(100);
    let long_header_value = "value".repeat(200);

    let malformed_headers = vec![
        // Empty header name - should be filtered out by sanitization
        ("", "value"),
        // Header with control characters
        ("X-Test\r\nInjected", "value"),
        ("X-Test", "value\r\nInjected: header"),
        // Very long header names and values
        (long_header_name.as_str(), long_header_value.as_str()),
    ];

    for (name, value) in malformed_headers {
        let response = Response::new(200, "OK", b"test body".to_vec())
            .with_header("Transfer-Encoding", "chunked")
            .with_header(name, value);

        let encoding_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut codec = Http1Codec::new();
            let mut dst = BytesMut::new();
            let result = codec.encode(response, &mut dst);
            (result, dst)
        }));

        // Should either succeed (if header is properly sanitized) or fail gracefully
        if let Err(_) = encoding_result {
            // Panic is not expected - malformed headers should be rejected cleanly
            panic!("Malformed header should be rejected cleanly, not panic: {}={}", name, value);
        }
    }
}

/// Test edge cases in chunked body data that should be discarded
fn test_chunked_body_edge_cases(test_case: &HeadChunkedResponse) {
    let edge_case_bodies = vec![
        // Empty body
        vec![],
        // Binary data
        (0u8..=255u8).collect::<Vec<u8>>(),
        // Large body (should be discarded anyway)
        vec![b'x'; 10_000],
        // Body with chunked encoding markers (should be ignored since raw body)
        b"5\r\nhello\r\n0\r\n\r\n".to_vec(),
        // Body with null bytes
        vec![0u8; 100],
        // Body with high bytes
        vec![0xFFu8; 100],
        // Original fuzzer body data
        test_case.body_data.clone(),
    ];

    for body_data in edge_case_bodies {
        if body_data.len() > 50_000 {
            continue; // Skip overly large bodies for performance
        }

        let response = Response::new(200, "OK", body_data.clone())
            .with_header("Transfer-Encoding", "chunked");

        let encoding_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut codec = Http1Codec::new();
            let mut dst = BytesMut::new();
            let result = codec.encode(response, &mut dst);
            (result, dst)
        }));

        assert!(encoding_result.is_ok(),
            "HEAD response with edge case body should not panic (body len={})",
            body_data.len());

        // Verify the body is discarded regardless of content
        if let Ok((Ok(()), dst)) = encoding_result {
            let response_bytes = dst.freeze();
            let response_str = String::from_utf8_lossy(&response_bytes);
            if let Some(headers_end) = response_str.find("\r\n\r\n") {
                let body_section = &response_str[headers_end + 4..];
                assert!(body_section.is_empty() || body_section.trim().is_empty(),
                    "HEAD response body should be empty regardless of input body content");
            }
        }
    }
}

/// Test that demonstrates what HEAD response behavior should be
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_head_response_no_body() {
        let response = Response::new(200, "OK", b"This body should be discarded".to_vec())
            .with_header("Transfer-Encoding", "chunked")
            .with_header("Content-Type", "text/plain");

        let mut codec = Http1Codec::new();
        let mut dst = BytesMut::new();
        let result = codec.encode(response, &mut dst);

        assert!(result.is_ok(), "HEAD response encoding should succeed");

        let encoded = dst.freeze();
        let response_text = String::from_utf8_lossy(&encoded);

        // Should have headers but no body
        assert!(response_text.contains("HTTP/1.1 200 OK"));
        assert!(response_text.contains("Transfer-Encoding: chunked"));
        assert!(response_text.contains("Content-Type: text/plain"));

        // Body should be empty after headers end
        if let Some(headers_end) = response_text.find("\r\n\r\n") {
            let body = &response_text[headers_end + 4..];
            assert!(body.is_empty(), "HEAD response should have no body content");
        }
    }

    #[test]
    fn test_head_response_with_trailers() {
        let mut response = Response::new(200, "OK", b"body content".to_vec())
            .with_header("Transfer-Encoding", "chunked");

        response.trailers.push(("X-Trailer".to_string(), "trailer-value".to_string()));

        let mut codec = Http1Codec::new();
        let mut dst = BytesMut::new();
        let result = codec.encode(response, &mut dst);

        // Should succeed - trailers should be handled appropriately for HEAD
        assert!(result.is_ok(), "HEAD response with trailers should encode successfully");
    }
}

/// Generate various test scenarios for comprehensive coverage
fn generate_test_scenarios() -> Vec<HeadChunkedResponse> {
    vec![
        // Basic HEAD response with chunked encoding
        HeadChunkedResponse {
            status_code: 200,
            additional_headers: vec![
                AdditionalHeader {
                    name: HeaderName::ContentType,
                    value: "text/html".to_string(),
                }
            ],
            body_data: b"<html><body>This should be discarded</body></html>".to_vec(),
            trailers: vec![],
        },

        // HEAD response with multiple headers
        HeadChunkedResponse {
            status_code: 304,
            additional_headers: vec![
                AdditionalHeader {
                    name: HeaderName::ETag,
                    value: "\"abc123\"".to_string(),
                },
                AdditionalHeader {
                    name: HeaderName::CacheControl,
                    value: "max-age=3600".to_string(),
                },
            ],
            body_data: vec![0u8; 1000], // Binary data that should be discarded
            trailers: vec![],
        },

        // HEAD response with trailers
        HeadChunkedResponse {
            status_code: 200,
            additional_headers: vec![],
            body_data: b"Large response body content that should be discarded".to_vec(),
            trailers: vec![
                TrailerHeader {
                    name: HeaderName::Custom("X-Processing-Time".to_string()),
                    value: "150ms".to_string(),
                },
            ],
        },
    ]
}