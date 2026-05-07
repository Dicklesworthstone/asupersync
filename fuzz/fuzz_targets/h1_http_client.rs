//! HTTP/1.1 client response parsing fuzz target.
//!
//! Fuzzes malformed HTTP/1.1 responses to test critical client parsing invariants:
//! 1. Status code validation (three-digit 100-999 range per RFC 9110)
//! 2. Reason-phrase CRLF termination requirements
//! 3. Header name token grammar compliance per RFC 7230
//! 4. Header value field-byte validation
//! 5. Content-Length overflow protection and bounds checking
//!
//! # Attack Vectors Tested
//! - Malformed status lines (invalid codes, missing reason phrases)
//! - CRLF injection in reason phrases
//! - Invalid header name characters (non-token grammar)
//! - Non-visible ASCII in header values (control chars, extended ASCII)
//! - Oversized Content-Length headers causing integer overflow
//! - Header injection attacks
//! - Response splitting patterns
//! - Malformed chunked encoding
//!
//! # Running
//! ```bash
//! cargo +nightly fuzz run h1_http_client
//! ```

#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::BytesMut;
use asupersync::codec::Decoder;
use asupersync::http::h1::{Http1ClientCodec, HttpError, Response};
use libfuzzer_sys::fuzz_target;

/// Maximum input size to prevent memory exhaustion during fuzzing.
const MAX_FUZZ_SIZE: usize = 64_000;
const MAX_BODY_SIZE: u64 = 16 * 1024 * 1024;

/// HTTP/1.1 client response fuzzing scenarios covering critical parsing paths.
#[derive(Arbitrary, Debug, Clone)]
enum HttpClientFuzzScenario {
    /// Test status line parsing
    StatusLineParsing {
        /// HTTP version string
        version: HttpVersion,
        /// Status code (may be invalid)
        status_code: u16,
        /// Reason phrase with potential malformation
        reason_phrase: Vec<u8>,
        /// Whether to include CRLF termination
        include_crlf: bool,
        /// Additional malformed components
        malformed_suffix: Vec<u8>,
    },
    /// Test header parsing
    HeaderParsing {
        /// Valid status line prefix
        status_line: String,
        /// Header name (may be invalid token)
        header_name: Vec<u8>,
        /// Header value (may contain invalid chars)
        header_value: Vec<u8>,
        /// Whether to include proper CRLF
        proper_crlf: bool,
        /// Additional malformed headers
        extra_headers: Vec<(String, String)>,
    },
    /// Test Content-Length parsing
    ContentLengthParsing {
        /// Base valid response
        base_response: String,
        /// Content-Length value string
        content_length: String,
        /// Whether to include multiple Content-Length headers
        duplicate_headers: bool,
        /// Additional body content
        body_data: Vec<u8>,
    },
    /// Test response body parsing
    BodyParsing {
        /// Headers defining body type
        headers: Vec<(String, String)>,
        /// Raw body data
        body_data: Vec<u8>,
        /// Whether to use chunked encoding
        use_chunked: bool,
        /// Chunk size declarations (may be malformed)
        chunk_sizes: Vec<String>,
    },
    /// Test header injection attacks
    HeaderInjection {
        /// Base header name
        base_name: String,
        /// Base header value
        base_value: String,
        /// Injection payload
        injection_payload: Vec<u8>,
        /// Injection position (0=name, 1=value, 2=both)
        injection_position: u8,
    },
}

/// HTTP version variants for testing
#[derive(Arbitrary, Debug, Clone, Copy)]
enum HttpVersion {
    Http10,
    Http11,
    Http2,
    Invalid,
    Empty,
}

impl HttpVersion {
    fn to_string(self) -> &'static str {
        match self {
            HttpVersion::Http10 => "HTTP/1.0",
            HttpVersion::Http11 => "HTTP/1.1",
            HttpVersion::Http2 => "HTTP/2.0",
            HttpVersion::Invalid => "HTTP/X.Y",
            HttpVersion::Empty => "",
        }
    }
}

fuzz_target!(|data: &[u8]| {
    // Guard against excessively large inputs
    if data.len() > MAX_FUZZ_SIZE {
        return;
    }

    assert_known_client_response_outputs();

    // Try to parse as structured scenario
    if let Ok(scenario) = arbitrary::Unstructured::new(data).arbitrary::<HttpClientFuzzScenario>() {
        test_http_client_scenario(scenario);
    }

    // Also test raw data as HTTP response
    test_raw_response_parsing(data);
});

/// Test a specific HTTP client fuzzing scenario
fn test_http_client_scenario(scenario: HttpClientFuzzScenario) {
    match scenario {
        HttpClientFuzzScenario::StatusLineParsing {
            version,
            status_code,
            reason_phrase,
            include_crlf,
            malformed_suffix,
        } => {
            test_status_line_parsing(
                version,
                status_code,
                reason_phrase,
                include_crlf,
                malformed_suffix,
            );
        }
        HttpClientFuzzScenario::HeaderParsing {
            status_line,
            header_name,
            header_value,
            proper_crlf,
            extra_headers,
        } => {
            test_header_parsing(
                status_line,
                header_name,
                header_value,
                proper_crlf,
                extra_headers,
            );
        }
        HttpClientFuzzScenario::ContentLengthParsing {
            base_response,
            content_length,
            duplicate_headers,
            body_data,
        } => {
            test_content_length_parsing(
                base_response,
                content_length,
                duplicate_headers,
                body_data,
            );
        }
        HttpClientFuzzScenario::BodyParsing {
            headers,
            body_data,
            use_chunked,
            chunk_sizes,
        } => {
            test_body_parsing(headers, body_data, use_chunked, chunk_sizes);
        }
        HttpClientFuzzScenario::HeaderInjection {
            base_name,
            base_value,
            injection_payload,
            injection_position,
        } => {
            test_header_injection(base_name, base_value, injection_payload, injection_position);
        }
    }
}

/// Test status line parsing (Assertion 1: status code range 100-599)
fn test_status_line_parsing(
    version: HttpVersion,
    status_code: u16,
    reason_phrase: Vec<u8>,
    include_crlf: bool,
    malformed_suffix: Vec<u8>,
) {
    let reason_str = String::from_utf8_lossy(&reason_phrase);
    let crlf = if include_crlf { "\r\n" } else { "" };
    let suffix = String::from_utf8_lossy(&malformed_suffix);

    let status_line = format!(
        "{} {} {}{}{}",
        version.to_string(),
        status_code,
        reason_str,
        crlf,
        suffix
    );

    match decode_response_bytes(status_line.as_bytes()) {
        Ok(Some(response)) => {
            // Assertion 1: Status code must be a three-digit RFC 9110 value.
            let status = response.status;
            assert!(
                (100..=999).contains(&status),
                "Invalid status code {} outside range 100-999",
                status
            );

            // Assertion 2: Reason phrase must be CRLF-terminated if present
            validate_reason_phrase_termination(&reason_phrase);
        }
        Ok(None) => {
            // Incomplete response - acceptable
        }
        Err(_) => {
            // Parse error - acceptable for malformed input.
        }
    }
}

/// Test header parsing (Assertions 3 & 4: header name token grammar, header value visible-ASCII)
fn test_header_parsing(
    status_line: String,
    header_name: Vec<u8>,
    header_value: Vec<u8>,
    proper_crlf: bool,
    extra_headers: Vec<(String, String)>,
) {
    let name_str = String::from_utf8_lossy(&header_name);
    let value_str = String::from_utf8_lossy(&header_value);

    let mut response = "HTTP/1.1 200 OK\r\n".to_string();
    if !status_line.is_empty() {
        response = format!("{}\r\n", status_line);
    }

    response.push_str(&format!("{}: {}", name_str, value_str));
    if proper_crlf {
        response.push_str("\r\n");
    }

    for (extra_name, extra_value) in extra_headers {
        response.push_str(&format!("{}: {}\r\n", extra_name, extra_value));
    }
    response.push_str("\r\n"); // End headers

    match decode_response_bytes(response.as_bytes()) {
        Ok(Some(parsed_response)) => {
            // Assertion 3: Header names must follow token grammar
            for (name, _value) in &parsed_response.headers {
                validate_header_name_token_grammar(name);
            }

            // Assertion 4: Header values must follow HTTP field-value byte rules.
            for (_name, value) in &parsed_response.headers {
                validate_header_value_visible_ascii(value.as_bytes());
            }
        }
        Ok(None) => {
            // Incomplete response
        }
        Err(_) => {
            // Parse error - acceptable for malformed fuzz input.
        }
    }
}

/// Test Content-Length parsing (Assertion 5: oversized Content-Length rejected)
fn test_content_length_parsing(
    base_response: String,
    content_length: String,
    duplicate_headers: bool,
    body_data: Vec<u8>,
) {
    let mut response = if base_response.is_empty() {
        "HTTP/1.1 200 OK\r\n".to_string()
    } else {
        format!("{}\r\n", base_response)
    };

    response.push_str(&format!("Content-Length: {}\r\n", content_length));

    if duplicate_headers {
        response.push_str(&format!("Content-Length: {}\r\n", content_length));
    }

    response.push_str("\r\n");
    response.extend(String::from_utf8_lossy(&body_data).chars());

    match decode_response_bytes(response.as_bytes()) {
        Ok(Some(parsed_response)) => {
            // Assertion 5: Oversized Content-Length must be rejected
            if !status_has_no_body(parsed_response.status)
                && let Some(cl_header) = header_value(&parsed_response.headers, "content-length")
            {
                validate_content_length_bounds(cl_header);
            }
        }
        Ok(None) => {
            // Incomplete response
        }
        Err(_) => {
            // Parse error - acceptable for malformed fuzz input.
        }
    }
}

/// Test body parsing with various encoding schemes
fn test_body_parsing(
    headers: Vec<(String, String)>,
    body_data: Vec<u8>,
    use_chunked: bool,
    chunk_sizes: Vec<String>,
) {
    let mut response = "HTTP/1.1 200 OK\r\n".to_string();

    if use_chunked {
        response.push_str("Transfer-Encoding: chunked\r\n");
    }

    for (name, value) in headers {
        response.push_str(&format!("{}: {}\r\n", name, value));
    }
    response.push_str("\r\n");

    if use_chunked {
        // Add chunked body with potentially malformed chunk sizes
        for (i, chunk_size) in chunk_sizes.iter().enumerate() {
            response.push_str(&format!("{}\r\n", chunk_size));
            let chunk_start = i * 10;
            let chunk_end = std::cmp::min(chunk_start + 10, body_data.len());
            if chunk_start < body_data.len() {
                response
                    .extend(String::from_utf8_lossy(&body_data[chunk_start..chunk_end]).chars());
            }
            response.push_str("\r\n");
        }
        response.push_str("0\r\n\r\n"); // End chunked
    } else {
        response.extend(String::from_utf8_lossy(&body_data).chars());
    }

    // Test that parsing doesn't panic or cause undefined behavior
    let _ = decode_response_bytes(response.as_bytes());
}

/// Test header injection attacks
fn test_header_injection(
    base_name: String,
    base_value: String,
    injection_payload: Vec<u8>,
    injection_position: u8,
) {
    let injection_str = String::from_utf8_lossy(&injection_payload);

    let (final_name, final_value) = match injection_position % 3 {
        0 => (format!("{}{}", base_name, injection_str), base_value),
        1 => (base_name, format!("{}{}", base_value, injection_str)),
        _ => (
            format!("{}{}", base_name, injection_str),
            format!("{}{}", base_value, injection_str),
        ),
    };

    let response = format!("HTTP/1.1 200 OK\r\n{}: {}\r\n\r\n", final_name, final_value);

    match decode_response_bytes(response.as_bytes()) {
        Ok(Some(parsed_response)) => {
            // Verify no header injection succeeded
            validate_no_header_injection(&parsed_response.headers, &injection_payload);
        }
        Ok(None) => {
            // Incomplete response
        }
        Err(_) => {
            // Parse error - acceptable for injection attempts
        }
    }
}

fn decode_response_bytes(input: &[u8]) -> Result<Option<Response>, HttpError> {
    let mut codec = Http1ClientCodec::new();
    let mut buf = BytesMut::from(input);
    codec.decode(&mut buf)
}

fn assert_known_client_response_outputs() {
    let response = decode_response_bytes(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
        .expect("valid response should decode")
        .expect("complete response should be returned");
    assert_eq!(response.status, 200);
    assert_eq!(response.reason, "OK");
    assert_eq!(response.body, b"hello");

    assert!(matches!(
        decode_response_bytes(b"HTTP/1.1 99 Nope\r\n\r\n"),
        Err(HttpError::BadRequestLine)
    ));
    assert!(matches!(
        decode_response_bytes(b"HTTP/1.1 1000 Nope\r\n\r\n"),
        Err(HttpError::BadRequestLine)
    ));
    assert!(matches!(
        decode_response_bytes(b"HTTP/1.1 200 OK\r\nBad Name: x\r\n\r\n"),
        Err(HttpError::InvalidHeaderName)
    ));
    assert!(matches!(
        decode_response_bytes(b"HTTP/1.1 200 OK\r\nX-Test: bad\0value\r\n\r\n"),
        Err(HttpError::InvalidHeaderValue)
    ));
    assert!(matches!(
        decode_response_bytes(b"HTTP/1.1 200 OK\r\nContent-Length: 16777217\r\n\r\n"),
        Err(HttpError::BodyTooLarge)
    ));
}

/// Helper: Validate reason phrase CRLF termination
fn validate_reason_phrase_termination(reason_phrase: &[u8]) {
    // Reason phrase should not contain unescaped CRLF
    for window in reason_phrase.windows(2) {
        if window == b"\r\n" {
            panic!("Unescaped CRLF found in reason phrase");
        }
    }
}

/// Helper: Validate header name follows token grammar per RFC 7230
fn validate_header_name_token_grammar(name: &str) {
    for ch in name.chars() {
        assert!(
            is_token_char(ch),
            "Invalid token character '{}' (U+{:04X}) in header name",
            ch,
            ch as u32
        );
    }
}

/// Helper: Validate header value follows HTTP field-value byte rules.
fn validate_header_value_visible_ascii(value: &[u8]) {
    for &byte in value {
        assert!(
            is_valid_header_value_byte(byte),
            "Invalid HTTP header field-value byte 0x{:02X}",
            byte
        );
    }
}

/// Helper: Validate Content-Length bounds
fn validate_content_length_bounds(cl_str: &str) {
    if let Ok(cl_value) = cl_str.parse::<u64>() {
        // Ensure no overflow and reasonable bounds
        assert!(
            cl_value <= MAX_BODY_SIZE,
            "Content-Length {} exceeds maximum safe size",
            cl_value
        );
    }
}

/// Helper: Check if character is valid in HTTP token
fn is_token_char(ch: char) -> bool {
    matches!(
        ch,
        'A'..='Z'
            | 'a'..='z'
            | '0'..='9'
            | '!'
            | '#'
            | '$'
            | '%'
            | '&'
            | '\''
            | '*'
            | '+'
            | '-'
            | '.'
            | '^'
            | '_'
            | '`'
            | '|'
            | '~'
    )
}

/// Helper: Check if byte is valid in an HTTP field value.
fn is_valid_header_value_byte(byte: u8) -> bool {
    byte == b'\t' || byte == b' ' || (0x21..=0x7E).contains(&byte) || byte >= 0x80
}

fn status_has_no_body(status: u16) -> bool {
    (100..=199).contains(&status) || matches!(status, 204 | 304)
}

fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(header_name, _)| header_name.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

/// Helper: Validate no header injection occurred
fn validate_no_header_injection(headers: &[(String, String)], injection_payload: &[u8]) {
    let injection_str = String::from_utf8_lossy(injection_payload);

    // Check that injection patterns didn't create additional headers
    if injection_str.contains("\r\n") {
        // CRLF injection attempt - verify it didn't succeed
        for (_name, value) in headers.iter() {
            assert!(
                !value.contains("\r\n"),
                "CRLF injection succeeded in header value"
            );
        }
    }
}

/// Test raw data as HTTP response parsing
fn test_raw_response_parsing(input: &[u8]) {
    // Test that parsing arbitrary input doesn't cause crashes
    let _ = decode_response_bytes(input);

    // Test with common HTTP prefixes
    if input.len() > 4 {
        let prefixes = [b"HTTP/1.1 ", b"HTTP/1.0 ", b"HTTP/2.0 "];

        for prefix in &prefixes {
            let mut test_input = prefix.to_vec();
            test_input.extend_from_slice(input);
            let _ = decode_response_bytes(&test_input);
        }
    }
}
