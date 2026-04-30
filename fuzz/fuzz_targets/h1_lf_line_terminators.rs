//! HTTP/1.1 LF-only line terminator handling fuzz target.
//!
//! Tests RFC 9112 compliance: HTTP/1.1 line terminators MUST be CRLF (\r\n).
//! Many real-world implementations accept bare LF (\n) as a compatibility measure,
//! but this creates request smuggling opportunities when intermediaries disagree.
//!
//! This fuzzer generates HTTP/1.1 requests with mixed CRLF/LF line terminators
//! and verifies that our strict implementation correctly rejects LF-only requests
//! per RFC 9112 §2.2.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

/// HTTP/1.1 request with mixed line terminators for fuzzing
#[derive(Debug, Clone, Arbitrary)]
struct MixedLineTerminatorRequest {
    /// HTTP method
    method: HttpMethod,
    /// Request URI
    uri: String,
    /// HTTP version
    version: HttpVersion,
    /// Headers with potential line terminator variations
    headers: Vec<HttpHeader>,
    /// Body content (if any)
    body: Vec<u8>,
    /// Line terminator strategy for each line
    terminator_pattern: Vec<LineTerminator>,
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
    Http09, // Edge case
}

impl HttpVersion {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Http10 => "HTTP/1.0",
            Self::Http11 => "HTTP/1.1",
            Self::Http09 => "HTTP/0.9",
        }
    }
}

/// HTTP header for fuzzing
#[derive(Debug, Clone, Arbitrary)]
struct HttpHeader {
    name: String,
    value: String,
}

/// Line terminator options
#[derive(Debug, Clone, Arbitrary)]
enum LineTerminator {
    /// Standard RFC-compliant CRLF
    Crlf,
    /// Non-compliant bare LF (should be rejected)
    Lf,
    /// Non-compliant bare CR (should be rejected)
    Cr,
    /// No terminator (incomplete line)
    None,
}

impl LineTerminator {
    fn as_bytes(&self) -> &'static [u8] {
        match self {
            Self::Crlf => b"\r\n",
            Self::Lf => b"\n",
            Self::Cr => b"\r",
            Self::None => b"",
        }
    }
}

fuzz_target!(|input: MixedLineTerminatorRequest| {
    // Guard against excessive input size
    if input.headers.len() > 50 || input.body.len() > 10_000 {
        return;
    }

    // Test strict CRLF enforcement (current behavior)
    test_strict_crlf_enforcement(&input);

    // Test various line terminator combinations
    test_line_terminator_combinations(&input);
});

/// Test that the strict HTTP/1.1 codec rejects non-CRLF line terminators
fn test_strict_crlf_enforcement(request: &MixedLineTerminatorRequest) {
    use asupersync::bytes::BytesMut;
    use asupersync::codec::Decoder;
    use asupersync::http::h1::Http1Codec;

    let mut codec = Http1Codec::new();

    // Generate request with mixed line terminators
    let request_bytes = build_http_request_with_terminators(request);
    let mut buffer = BytesMut::from(&request_bytes[..]);

    match codec.decode(&mut buffer) {
        Ok(Some(_)) => {
            // Request was accepted - verify it only used CRLF terminators
            let request_str = String::from_utf8_lossy(&request_bytes);
            assert!(!request_str.contains("\n\r"), "Request with CR-LF should be rejected");
            assert!(!contains_bare_lf_or_cr(&request_bytes),
                "Request with bare LF or CR was incorrectly accepted");
        }
        Ok(None) => {
            // Incomplete - this is fine, we might need more data
        }
        Err(_) => {
            // Error - expected for non-CRLF requests
            // This is the correct behavior per RFC 9112
        }
    }
}

/// Test various combinations of line terminators for edge case discovery
fn test_line_terminator_combinations(request: &MixedLineTerminatorRequest) {
    use asupersync::bytes::BytesMut;
    use asupersync::codec::Decoder;
    use asupersync::http::h1::Http1Codec;

    // Test 1: All CRLF (should work)
    let crlf_request = build_http_request_all_crlf(request);
    let mut crlf_buffer = BytesMut::from(&crlf_request[..]);
    let mut crlf_codec = Http1Codec::new();

    match crlf_codec.decode(&mut crlf_buffer) {
        Ok(Some(parsed)) => {
            // Valid CRLF request should parse correctly
            assert_eq!(parsed.method.as_str(), request.method.as_str());
        }
        Ok(None) => {
            // May need more data - acceptable
        }
        Err(_) => {
            // May fail due to other validation (bad method, headers, etc.)
            // This is acceptable for fuzz testing
        }
    }

    // Test 2: All LF (should be rejected)
    let lf_request = build_http_request_all_lf(request);
    let mut lf_buffer = BytesMut::from(&lf_request[..]);
    let mut lf_codec = Http1Codec::new();

    match lf_codec.decode(&mut lf_buffer) {
        Ok(Some(_)) => {
            // LF-only should not be accepted in strict mode
            assert!(false, "LF-only request should be rejected by strict codec");
        }
        Ok(None) => {
            // Incomplete - expected, since LF parsing should fail
        }
        Err(_) => {
            // Expected - LF-only should be rejected per RFC 9112
        }
    }

    // Test 3: Mixed CRLF and LF in headers (should be rejected)
    let mixed_request = build_http_request_mixed_terminators(request);
    let mut mixed_buffer = BytesMut::from(&mixed_request[..]);
    let mut mixed_codec = Http1Codec::new();

    match mixed_codec.decode(&mut mixed_buffer) {
        Ok(Some(_)) => {
            // Mixed terminators create smuggling opportunities
            panic!("Mixed line terminators should be rejected for security");
        }
        Ok(None) => {
            // Incomplete parsing expected
        }
        Err(_) => {
            // Expected - mixed terminators should fail
        }
    }
}

/// Build HTTP request with mixed line terminators per fuzz input
fn build_http_request_with_terminators(request: &MixedLineTerminatorRequest) -> Vec<u8> {
    let mut output = Vec::new();

    // Request line
    let request_line = format!("{} {} {}",
        request.method.as_str(),
        sanitize_uri(&request.uri),
        request.version.as_str()
    );
    output.extend_from_slice(request_line.as_bytes());

    // Use first terminator pattern for request line
    let request_line_term = request.terminator_pattern.get(0)
        .unwrap_or(&LineTerminator::Crlf);
    output.extend_from_slice(request_line_term.as_bytes());

    // Headers with different terminators
    for (i, header) in request.headers.iter().enumerate() {
        let header_line = format!("{}: {}",
            sanitize_header_name(&header.name),
            sanitize_header_value(&header.value)
        );
        output.extend_from_slice(header_line.as_bytes());

        let header_term = request.terminator_pattern.get(i + 1)
            .unwrap_or(&LineTerminator::Crlf);
        output.extend_from_slice(header_term.as_bytes());
    }

    // Empty line before body (use pattern or default CRLF)
    let empty_line_term = request.terminator_pattern.get(request.headers.len() + 1)
        .unwrap_or(&LineTerminator::Crlf);
    output.extend_from_slice(empty_line_term.as_bytes());

    // Body (if present)
    if !request.body.is_empty() {
        output.extend_from_slice(&request.body);
    }

    output
}

/// Build HTTP request with all CRLF line terminators (RFC compliant)
fn build_http_request_all_crlf(request: &MixedLineTerminatorRequest) -> Vec<u8> {
    let mut output = Vec::new();

    // Request line
    let request_line = format!("{} {} {}",
        request.method.as_str(),
        sanitize_uri(&request.uri),
        request.version.as_str()
    );
    output.extend_from_slice(request_line.as_bytes());
    output.extend_from_slice(b"\r\n");

    // Headers
    for header in &request.headers {
        let header_line = format!("{}: {}",
            sanitize_header_name(&header.name),
            sanitize_header_value(&header.value)
        );
        output.extend_from_slice(header_line.as_bytes());
        output.extend_from_slice(b"\r\n");
    }

    // Empty line before body
    output.extend_from_slice(b"\r\n");

    // Body
    if !request.body.is_empty() {
        output.extend_from_slice(&request.body);
    }

    output
}

/// Build HTTP request with all LF line terminators (non-compliant)
fn build_http_request_all_lf(request: &MixedLineTerminatorRequest) -> Vec<u8> {
    let mut output = Vec::new();

    // Request line
    let request_line = format!("{} {} {}",
        request.method.as_str(),
        sanitize_uri(&request.uri),
        request.version.as_str()
    );
    output.extend_from_slice(request_line.as_bytes());
    output.extend_from_slice(b"\n");

    // Headers
    for header in &request.headers {
        let header_line = format!("{}: {}",
            sanitize_header_name(&header.name),
            sanitize_header_value(&header.value)
        );
        output.extend_from_slice(header_line.as_bytes());
        output.extend_from_slice(b"\n");
    }

    // Empty line before body
    output.extend_from_slice(b"\n");

    // Body
    if !request.body.is_empty() {
        output.extend_from_slice(&request.body);
    }

    output
}

/// Build HTTP request with mixed CRLF and LF terminators
fn build_http_request_mixed_terminators(request: &MixedLineTerminatorRequest) -> Vec<u8> {
    let mut output = Vec::new();

    // Request line with CRLF
    let request_line = format!("{} {} {}",
        request.method.as_str(),
        sanitize_uri(&request.uri),
        request.version.as_str()
    );
    output.extend_from_slice(request_line.as_bytes());
    output.extend_from_slice(b"\r\n");

    // Alternate headers between CRLF and LF
    for (i, header) in request.headers.iter().enumerate() {
        let header_line = format!("{}: {}",
            sanitize_header_name(&header.name),
            sanitize_header_value(&header.value)
        );
        output.extend_from_slice(header_line.as_bytes());

        if i % 2 == 0 {
            output.extend_from_slice(b"\r\n");  // Even: CRLF
        } else {
            output.extend_from_slice(b"\n");    // Odd: LF only
        }
    }

    // Empty line with LF
    output.extend_from_slice(b"\n");

    // Body
    if !request.body.is_empty() {
        output.extend_from_slice(&request.body);
    }

    output
}

/// Check if byte sequence contains bare LF or CR
fn contains_bare_lf_or_cr(data: &[u8]) -> bool {
    for window in data.windows(2) {
        if window[1] == b'\n' && window[0] != b'\r' {
            return true; // Bare LF
        }
        if window[0] == b'\r' && window[1] != b'\n' {
            return true; // Bare CR
        }
    }

    // Check for trailing CR
    if data.ends_with(&[b'\r']) {
        return true;
    }

    // Check for leading LF
    if data.starts_with(&[b'\n']) {
        return true;
    }

    false
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