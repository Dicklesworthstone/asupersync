//! HTTP/1.1 Transfer-Encoding identity handling fuzz target.
//!
//! Tests RFC 7230 compliance for Transfer-Encoding: identity.
//! Identity transfer encoding means "no transformation" - data should be
//! passed through exactly as received without any encoding/decoding.
//!
//! This fuzzer generates arbitrary HTTP/1.1 requests claiming identity
//! transfer encoding and verifies:
//! 1. Pass-through is bit-for-bit correct
//! 2. No double-decode occurs
//! 3. No panics on malformed identity claims

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

/// HTTP/1.1 request with Transfer-Encoding: identity and arbitrary body content
#[derive(Debug, Clone, Arbitrary)]
struct IdentityTransferRequest {
    /// HTTP method
    method: HttpMethod,
    /// Request URI
    uri: String,
    /// HTTP version
    version: HttpVersion,
    /// Additional headers before Transfer-Encoding
    prefix_headers: Vec<HttpHeader>,
    /// Transfer-Encoding header value variations
    transfer_encoding: TransferEncodingVariant,
    /// Additional headers after Transfer-Encoding
    suffix_headers: Vec<HttpHeader>,
    /// Raw body content that claims to be identity-encoded
    body: Vec<u8>,
    /// Whether to include Content-Length (creates ambiguity test case)
    include_content_length: bool,
}

/// Supported HTTP methods for fuzzing
#[derive(Debug, Clone, Arbitrary)]
enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Head,
    Options,
    Patch,
    Trace,
}

impl HttpMethod {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
            Self::Head => "HEAD",
            Self::Options => "OPTIONS",
            Self::Patch => "PATCH",
            Self::Trace => "TRACE",
        }
    }
}

/// HTTP version variations
#[derive(Debug, Clone, Arbitrary)]
enum HttpVersion {
    Http10,
    Http11,
}

impl HttpVersion {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Http10 => "HTTP/1.0",
            Self::Http11 => "HTTP/1.1",
        }
    }
}

/// HTTP header for fuzzing
#[derive(Debug, Clone, Arbitrary)]
struct HttpHeader {
    name: String,
    value: String,
}

/// Transfer-Encoding header value variations to test
#[derive(Debug, Clone, Arbitrary)]
enum TransferEncodingVariant {
    /// Standard identity
    Identity,
    /// Case variations
    IdentityMixedCase,
    /// With whitespace
    IdentityWithWhitespace,
    /// Multiple values with identity
    IdentityWithOthers,
    /// Malformed identity claims
    MalformedIdentity(String),
}

impl TransferEncodingVariant {
    fn as_str(&self) -> String {
        match self {
            Self::Identity => "identity".to_string(),
            Self::IdentityMixedCase => "Identity".to_string(),
            Self::IdentityWithWhitespace => " identity ".to_string(),
            Self::IdentityWithOthers => "identity, gzip".to_string(),
            Self::MalformedIdentity(value) => value.clone(),
        }
    }
}

fuzz_target!(|input: IdentityTransferRequest| {
    // Guard against excessive input size
    if input.body.len() > 1_000_000 || input.prefix_headers.len() + input.suffix_headers.len() > 50
    {
        return;
    }

    // Current H1 codec support is intentionally strict: only chunked
    // Transfer-Encoding is accepted, so normalized identity variants must
    // reject deterministically instead of being treated as generic noise.
    test_identity_rejected_as_unsupported();

    // Test identity transfer encoding handling
    test_identity_pass_through(&input);

    // Test that no double-decode occurs
    test_no_double_decode(&input);

    // Test edge cases and malformed identity claims
    test_identity_edge_cases(&input);
});

/// Test that the current HTTP/1 codec rejects identity transfer coding exactly.
fn test_identity_rejected_as_unsupported() {
    use asupersync::bytes::BytesMut;
    use asupersync::codec::Decoder;
    use asupersync::http::h1::codec::{Http1Codec, HttpError};

    for transfer_encoding in [
        TransferEncodingVariant::Identity,
        TransferEncodingVariant::IdentityMixedCase,
        TransferEncodingVariant::IdentityWithWhitespace,
        TransferEncodingVariant::IdentityWithOthers,
    ] {
        let variant_label = transfer_encoding.as_str();
        let request = IdentityTransferRequest {
            method: HttpMethod::Post,
            uri: "/identity".to_string(),
            version: HttpVersion::Http11,
            prefix_headers: Vec::new(),
            transfer_encoding,
            suffix_headers: Vec::new(),
            body: b"identity body".to_vec(),
            include_content_length: false,
        };
        let request_bytes = build_identity_request(&request);
        let mut buffer = BytesMut::from(&request_bytes[..]);
        let mut codec = Http1Codec::new();

        match codec.decode(&mut buffer) {
            Err(HttpError::BadTransferEncoding) => {}
            other => {
                panic!(
                    "Transfer-Encoding {variant_label:?} must reject as BadTransferEncoding, \
                     got {other:?}"
                );
            }
        }
    }
}

/// Test that identity transfer encoding passes data through unchanged
fn test_identity_pass_through(request: &IdentityTransferRequest) {
    use asupersync::bytes::BytesMut;
    use asupersync::codec::Decoder;
    use asupersync::http::h1::codec::Http1Codec;

    let mut codec = Http1Codec::new();

    // Build request with Transfer-Encoding: identity
    let request_bytes = build_identity_request(request);
    let original_body = request.body.clone();

    let mut buffer = BytesMut::from(&request_bytes[..]);

    match codec.decode(&mut buffer) {
        Ok(Some(parsed_request)) => {
            // If parsing succeeded, body should be bit-for-bit identical to input
            assert_eq!(
                parsed_request.body,
                original_body,
                "Identity transfer encoding must preserve body exactly: \
                 expected {} bytes, got {} bytes",
                original_body.len(),
                parsed_request.body.len()
            );

            // Verify no transformation occurred
            if !original_body.is_empty() {
                for (i, (&expected, &actual)) in original_body
                    .iter()
                    .zip(parsed_request.body.iter())
                    .enumerate()
                {
                    assert_eq!(
                        expected, actual,
                        "Identity transfer encoding altered byte at position {}: \
                         expected 0x{:02x}, got 0x{:02x}",
                        i, expected, actual
                    );
                }
            }
        }
        Ok(None) => {
            // Incomplete - acceptable for fuzzing
        }
        Err(_) => {
            // Error is acceptable - current implementation may not support identity
            // This fuzz target documents the expected behavior for when/if identity is implemented
        }
    }
}

/// Test that identity transfer encoding doesn't cause double-decoding
fn test_no_double_decode(request: &IdentityTransferRequest) {
    use asupersync::bytes::BytesMut;
    use asupersync::codec::Decoder;
    use asupersync::http::h1::codec::Http1Codec;

    // Create a body that looks like it might be encoded (but should be treated as raw with identity)
    let mut test_body = request.body.clone();

    // Add patterns that might trigger double-decode bugs
    test_body.extend_from_slice(b"Content-Length: 100\r\n");
    test_body.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
    test_body.extend_from_slice(b"5\r\nhello\r\n0\r\n\r\n");

    let test_request = IdentityTransferRequest {
        body: test_body.clone(),
        ..request.clone()
    };

    let request_bytes = build_identity_request(&test_request);
    let mut buffer = BytesMut::from(&request_bytes[..]);
    let mut codec = Http1Codec::new();

    match codec.decode(&mut buffer) {
        Ok(Some(parsed_request)) => {
            // With identity encoding, the body should be exactly as sent
            // No chunked decoding or other transformations should occur
            assert_eq!(
                parsed_request.body, test_body,
                "Identity transfer encoding must not double-decode body content"
            );
        }
        Ok(None) => {
            // Incomplete - acceptable
        }
        Err(_) => {
            // Error handling - acceptable for current implementation
        }
    }
}

/// Test edge cases and malformed identity claims
fn test_identity_edge_cases(request: &IdentityTransferRequest) {
    use asupersync::bytes::BytesMut;
    use asupersync::codec::Decoder;
    use asupersync::http::h1::codec::Http1Codec;

    // Test case 1: Empty body with identity
    let empty_body_request = IdentityTransferRequest {
        body: Vec::new(),
        ..request.clone()
    };
    let empty_request_bytes = build_identity_request(&empty_body_request);
    let mut empty_buffer = BytesMut::from(&empty_request_bytes[..]);
    let mut empty_codec = Http1Codec::new();

    let empty_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        empty_codec.decode(&mut empty_buffer)
    }));
    assert!(
        empty_result.is_ok(),
        "Empty body with identity encoding should not panic"
    );

    // Test case 2: Very large body with identity (up to limit)
    let large_body = vec![b'X'; 10000]; // 10KB test
    let large_body_request = IdentityTransferRequest {
        body: large_body.clone(),
        ..request.clone()
    };
    let large_request_bytes = build_identity_request(&large_body_request);
    let mut large_buffer = BytesMut::from(&large_request_bytes[..]);
    let mut large_codec = Http1Codec::new();

    let large_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        large_codec.decode(&mut large_buffer)
    }));
    assert!(
        large_result.is_ok(),
        "Large body with identity encoding should not panic"
    );

    // Test case 3: Binary data with identity
    let binary_body = (0u8..=255u8).cycle().take(1000).collect::<Vec<u8>>();
    let binary_request = IdentityTransferRequest {
        body: binary_body.clone(),
        ..request.clone()
    };
    let binary_request_bytes = build_identity_request(&binary_request);
    let mut binary_buffer = BytesMut::from(&binary_request_bytes[..]);
    let mut binary_codec = Http1Codec::new();

    let binary_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        binary_codec.decode(&mut binary_buffer)
    }));
    assert!(
        binary_result.is_ok(),
        "Binary data with identity encoding should not panic"
    );
}

/// Build HTTP/1.1 request with Transfer-Encoding: identity
fn build_identity_request(request: &IdentityTransferRequest) -> Vec<u8> {
    let mut output = Vec::new();

    // Request line
    let request_line = format!(
        "{} {} {}",
        request.method.as_str(),
        sanitize_uri(&request.uri),
        request.version.as_str()
    );
    output.extend_from_slice(request_line.as_bytes());
    output.extend_from_slice(b"\r\n");

    // Prefix headers
    for header in &request.prefix_headers {
        let header_line = format!(
            "{}: {}",
            sanitize_header_name(&header.name),
            sanitize_header_value(&header.value)
        );
        output.extend_from_slice(header_line.as_bytes());
        output.extend_from_slice(b"\r\n");
    }

    // Transfer-Encoding header
    let te_value = request.transfer_encoding.as_str();
    output.extend_from_slice(b"Transfer-Encoding: ");
    output.extend_from_slice(te_value.as_bytes());
    output.extend_from_slice(b"\r\n");

    // Add Content-Length if requested (creates RFC 7230 violation test case)
    if request.include_content_length {
        let cl_header = format!("Content-Length: {}", request.body.len());
        output.extend_from_slice(cl_header.as_bytes());
        output.extend_from_slice(b"\r\n");
    }

    // Suffix headers
    for header in &request.suffix_headers {
        let header_line = format!(
            "{}: {}",
            sanitize_header_name(&header.name),
            sanitize_header_value(&header.value)
        );
        output.extend_from_slice(header_line.as_bytes());
        output.extend_from_slice(b"\r\n");
    }

    // End of headers
    output.extend_from_slice(b"\r\n");

    // Body (should be passed through unchanged with identity encoding)
    if !request.body.is_empty() {
        output.extend_from_slice(&request.body);
    }

    output
}

/// Sanitize URI to prevent fuzzer from generating invalid characters
fn sanitize_uri(uri: &str) -> String {
    if uri.is_empty() {
        return "/".to_string();
    }

    let mut result = String::new();
    for c in uri.chars() {
        if c.is_ascii() && !c.is_control() && c != ' ' {
            result.push(c);
        }
    }

    if result.is_empty() || !result.starts_with('/') {
        format!("/{}", result)
    } else {
        result
    }
}

/// Sanitize header name to valid HTTP token characters
fn sanitize_header_name(name: &str) -> String {
    if name.is_empty() {
        return "X-Test".to_string();
    }

    let mut result = String::new();
    for c in name.chars() {
        if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
            result.push(c);
        }
    }

    if result.is_empty() {
        "X-Test".to_string()
    } else {
        result
    }
}

/// Sanitize header value to remove control characters
fn sanitize_header_value(value: &str) -> String {
    let mut result = String::new();
    for c in value.chars() {
        if c.is_ascii() && !c.is_control() || c == ' ' || c == '\t' {
            result.push(c);
        }
    }

    if result.is_empty() {
        "test-value".to_string()
    } else {
        result
    }
}
