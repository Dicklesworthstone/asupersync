#![no_main]

//! Fuzz target for HTTP/0.9 simple-request rejection in HTTP/1.1 codec.
//!
//! This target validates that HTTP/0.9 style simple requests (which lack HTTP
//! version specifiers) are properly rejected by modern HTTP/1.1 parsers.
//!
//! HTTP/0.9 simple requests have the format:
//! ```text
//! GET /path\r\n
//! ```
//!
//! Modern HTTP/1.1 requires:
//! ```text
//! GET /path HTTP/1.1\r\n
//! ```
//!
//! This target generates various HTTP/0.9 style requests and verifies they
//! are rejected with appropriate error codes, typically `BadRequestLine` or
//! `UnsupportedVersion`.

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

/// Simplified HTTP method for HTTP/0.9 requests
#[derive(Debug, Clone, Arbitrary)]
enum SimpleMethod {
    Get,
    Post,  // Though not in original HTTP/0.9, test edge cases
    Head,
    Put,
    Delete,
}

impl SimpleMethod {
    fn as_str(&self) -> &'static str {
        match self {
            SimpleMethod::Get => "GET",
            SimpleMethod::Post => "POST",
            SimpleMethod::Head => "HEAD",
            SimpleMethod::Put => "PUT",
            SimpleMethod::Delete => "DELETE",
        }
    }
}

/// Path component for HTTP/0.9 requests
#[derive(Debug, Clone, Arbitrary)]
struct SimplePath {
    /// Whether to include leading slash
    has_leading_slash: bool,
    /// Path segments (empty for root)
    segments: Vec<String>,
    /// Whether to include query parameters (not in original HTTP/0.9 but test parsing)
    has_query: bool,
    /// Query string if present
    query: String,
}

impl SimplePath {
    fn to_string(&self) -> String {
        let mut path = if self.has_leading_slash || self.segments.is_empty() {
            "/".to_string()
        } else {
            String::new()
        };

        if !self.segments.is_empty() {
            if !path.ends_with('/') && self.has_leading_slash {
                path.push_str(&self.segments.join("/"));
            } else {
                path.push_str(&self.segments.join("/"));
            }
        }

        if self.has_query && !self.query.is_empty() {
            path.push('?');
            path.push_str(&self.query);
        }

        // Ensure we have at least "/" for empty paths
        if path.is_empty() {
            path = "/".to_string();
        }

        path
    }
}

/// Line ending styles for HTTP/0.9 requests
#[derive(Debug, Clone, Arbitrary)]
enum LineEnding {
    /// Standard CRLF
    Crlf,
    /// Unix LF only (should be rejected)
    Lf,
    /// Old Mac CR only (should be rejected)
    Cr,
    /// Double CRLF (simulating end of headers)
    DoubleCrlf,
    /// No ending (incomplete request)
    None,
}

impl LineEnding {
    fn as_bytes(&self) -> &'static [u8] {
        match self {
            LineEnding::Crlf => b"\r\n",
            LineEnding::Lf => b"\n",
            LineEnding::Cr => b"\r",
            LineEnding::DoubleCrlf => b"\r\n\r\n",
            LineEnding::None => b"",
        }
    }
}

/// Whitespace handling variations
#[derive(Debug, Clone, Arbitrary)]
enum WhitespaceStyle {
    /// Single space (standard)
    Single,
    /// Multiple spaces
    Multiple(u8), // 2-10 spaces
    /// Tab character
    Tab,
    /// Mixed whitespace
    Mixed,
    /// No whitespace (invalid)
    None,
}

impl WhitespaceStyle {
    fn as_bytes(&self) -> Vec<u8> {
        match self {
            WhitespaceStyle::Single => vec![b' '],
            WhitespaceStyle::Multiple(count) => vec![b' '; (*count % 10 + 2) as usize],
            WhitespaceStyle::Tab => vec![b'\t'],
            WhitespaceStyle::Mixed => vec![b' ', b'\t', b' '],
            WhitespaceStyle::None => vec![],
        }
    }
}

/// HTTP/0.9 simple request structure
#[derive(Debug, Clone, Arbitrary)]
struct Http09Request {
    /// HTTP method
    method: SimpleMethod,
    /// Whitespace between method and path
    whitespace: WhitespaceStyle,
    /// Request path
    path: SimplePath,
    /// Line ending style
    ending: LineEnding,
    /// Optional trailing data (should be ignored/rejected)
    trailing_data: Option<Vec<u8>>,
}

impl Http09Request {
    fn to_bytes(&self) -> Vec<u8> {
        let mut request = Vec::new();

        // Method
        request.extend_from_slice(self.method.as_str().as_bytes());

        // Whitespace
        request.extend(&self.whitespace.as_bytes());

        // Path
        request.extend_from_slice(self.path.to_string().as_bytes());

        // Line ending
        request.extend_from_slice(self.ending.as_bytes());

        // Optional trailing data
        if let Some(ref trailing) = self.trailing_data {
            request.extend(trailing);
        }

        request
    }
}

/// Mock HTTP/1.1 codec for testing HTTP/0.9 rejection
struct MockHttp11Codec {
    buffer: Vec<u8>,
    error_count: usize,
    rejection_reasons: HashMap<String, usize>,
}

impl MockHttp11Codec {
    fn new() -> Self {
        Self {
            buffer: Vec::new(),
            error_count: 0,
            rejection_reasons: HashMap::new(),
        }
    }

    fn feed_bytes(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    /// Attempt to parse as HTTP/1.1 request
    /// Returns Ok(()) for valid HTTP/1.1, Err(reason) for rejection
    fn try_parse_request(&mut self) -> Result<(), String> {
        // Look for end of request line
        let request_line = if let Some(pos) = self.find_line_end() {
            let line = &self.buffer[..pos];
            std::str::from_utf8(line)
                .map_err(|_| "Non-UTF8 in request line".to_string())?
        } else {
            return Err("Incomplete request line".to_string());
        };

        // Parse request line - should be "METHOD PATH HTTP/VERSION"
        let parts: Vec<&str> = request_line.split_whitespace().collect();

        match parts.len() {
            0 => {
                self.record_rejection("Empty request line");
                Err("Empty request line".to_string())
            }
            1 => {
                self.record_rejection("Only method provided (HTTP/0.9 style)");
                Err("Only method provided (HTTP/0.9 style)".to_string())
            }
            2 => {
                // This is the classic HTTP/0.9 case: "GET /path"
                self.record_rejection("HTTP/0.9 simple request (missing version)");
                Err("HTTP/0.9 simple request (missing version)".to_string())
            }
            3 => {
                // Standard HTTP/1.x format: "METHOD PATH VERSION"
                let (method, path, version) = (parts[0], parts[1], parts[2]);

                // Validate method
                if !self.is_valid_method(method) {
                    self.record_rejection("Invalid HTTP method");
                    return Err("Invalid HTTP method".to_string());
                }

                // Validate version
                if !self.is_supported_version(version) {
                    self.record_rejection("Unsupported HTTP version");
                    return Err("Unsupported HTTP version".to_string());
                }

                // Validate path
                if path.is_empty() {
                    self.record_rejection("Empty path");
                    return Err("Empty path".to_string());
                }

                // For HTTP/1.1, we'd also need to validate headers
                // but for this test we're focused on request line parsing
                Ok(())
            }
            _ => {
                // Too many parts
                self.record_rejection("Malformed request line (too many parts)");
                Err("Malformed request line (too many parts)".to_string())
            }
        }
    }

    fn find_line_end(&self) -> Option<usize> {
        // Look for CRLF first, then LF
        if let Some(pos) = self.buffer.windows(2).position(|w| w == b"\r\n") {
            Some(pos)
        } else if let Some(pos) = self.buffer.iter().position(|&b| b == b'\n') {
            Some(pos)
        } else {
            None
        }
    }

    fn is_valid_method(&self, method: &str) -> bool {
        matches!(method, "GET" | "POST" | "PUT" | "DELETE" | "HEAD" |
                        "OPTIONS" | "TRACE" | "CONNECT" | "PATCH")
    }

    fn is_supported_version(&self, version: &str) -> bool {
        matches!(version, "HTTP/1.0" | "HTTP/1.1")
    }

    fn record_rejection(&mut self, reason: &str) {
        self.error_count += 1;
        *self.rejection_reasons.entry(reason.to_string()).or_insert(0) += 1;
    }

    fn get_stats(&self) -> (usize, &HashMap<String, usize>) {
        (self.error_count, &self.rejection_reasons)
    }

    fn clear(&mut self) {
        self.buffer.clear();
    }
}

/// Test scenario for HTTP/0.9 rejection
#[derive(Debug, Clone, Arbitrary)]
struct Http09RejectionScenario {
    /// The HTTP/0.9 request to test
    request: Http09Request,
    /// Whether to test incomplete requests
    send_incomplete: bool,
    /// Additional malformed data to append
    additional_data: Option<Vec<u8>>,
}

fuzz_target!(|scenario: Http09RejectionScenario| {
    let mut codec = MockHttp11Codec::new();

    // Generate the HTTP/0.9 request bytes
    let request_bytes = scenario.request.to_bytes();

    // Feed bytes to codec
    if scenario.send_incomplete {
        // Send partial request to test incomplete parsing
        let partial_len = request_bytes.len() / 2;
        if partial_len > 0 {
            codec.feed_bytes(&request_bytes[..partial_len]);

            // Should fail due to incomplete request
            let result = codec.try_parse_request();
            assert!(result.is_err(), "Incomplete HTTP/0.9 request should be rejected");

            // Feed the rest
            codec.feed_bytes(&request_bytes[partial_len..]);
        }
    } else {
        codec.feed_bytes(&request_bytes);
    }

    // Add any additional malformed data
    if let Some(ref extra_data) = scenario.additional_data {
        codec.feed_bytes(extra_data);
    }

    // Try to parse - should fail for HTTP/0.9 requests
    let parse_result = codec.try_parse_request();

    // Validate rejection behavior
    match parse_result {
        Ok(()) => {
            // This should only happen if we accidentally generated a valid HTTP/1.x request
            // Let's check if this is actually a valid HTTP/1.1 format
            let request_str = String::from_utf8_lossy(&request_bytes);
            let parts: Vec<&str> = request_str.trim().split_whitespace().collect();

            if parts.len() == 3 && parts[2].starts_with("HTTP/") {
                // This is actually a valid HTTP/1.x request, not HTTP/0.9
                // This can happen due to fuzzing edge cases
                return;
            }

            panic!("HTTP/0.9 request was incorrectly accepted: {:?}",
                   String::from_utf8_lossy(&request_bytes));
        }
        Err(reason) => {
            // Good - the request was rejected as expected
            // Verify the rejection reason makes sense for HTTP/0.9
            assert!(
                reason.contains("HTTP/0.9") ||
                reason.contains("missing version") ||
                reason.contains("Incomplete") ||
                reason.contains("Unsupported") ||
                reason.contains("Malformed") ||
                reason.contains("Invalid") ||
                reason.contains("Empty"),
                "Unexpected rejection reason for HTTP/0.9 request: {}", reason
            );
        }
    }

    // Verify error tracking
    let (error_count, rejection_reasons) = codec.get_stats();
    assert!(error_count > 0, "Error count should be incremented");
    assert!(!rejection_reasons.is_empty(), "Rejection reasons should be recorded");

    // Test that the codec can still parse valid HTTP/1.1 after rejecting HTTP/0.9
    codec.clear();
    let valid_http11 = b"GET /test HTTP/1.1\r\n\r\n";
    codec.feed_bytes(valid_http11);

    let result = codec.try_parse_request();
    assert!(result.is_ok(), "Valid HTTP/1.1 request should be accepted after HTTP/0.9 rejection");

    // Verify specific HTTP/0.9 patterns are consistently rejected
    test_known_http09_patterns(&mut codec);
});

/// Test specific HTTP/0.9 patterns that should always be rejected
fn test_known_http09_patterns(codec: &mut MockHttp11Codec) {
    let http09_patterns = [
        b"GET /\r\n",
        b"GET /index.html\r\n",
        b"GET /path/to/file\r\n",
        b"POST /form\r\n",
        b"HEAD /\r\n",
        // With different line endings
        b"GET /\n",
        b"GET /test\r",
        // With trailing data (simulating body that HTTP/0.9 doesn't officially support)
        b"GET /\r\nSome body data",
    ];

    for (i, pattern) in http09_patterns.iter().enumerate() {
        codec.clear();
        codec.feed_bytes(pattern);

        let result = codec.try_parse_request();
        assert!(result.is_err(),
               "HTTP/0.9 pattern {} should be rejected: {}",
               i, String::from_utf8_lossy(pattern));
    }
}