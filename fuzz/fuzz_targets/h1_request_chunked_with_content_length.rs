#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::fmt;

/// HTTP/1.1 request parsing result
#[derive(Debug, PartialEq)]
enum RequestParseResult {
    /// Successfully parsed request
    Valid {
        method: String,
        uri: String,
        version: String,
        headers: Vec<(String, String)>,
        has_transfer_encoding_chunked: bool,
        has_content_length: bool,
        content_length_value: Option<u64>,
        effective_transfer_mechanism: TransferMechanism,
    },
    /// Protocol error - request smuggling or invalid combination
    ProtocolError(String),
    /// Malformed request
    MalformedRequest,
    /// Incomplete request
    IncompleteRequest,
}

/// Transfer mechanism determined after header processing
#[derive(Debug, PartialEq, Clone)]
enum TransferMechanism {
    /// Transfer-Encoding: chunked takes precedence per RFC 9112 §6.1
    Chunked,
    /// Content-Length based transfer
    ContentLength(u64),
    /// No body expected
    NoBody,
    /// Ambiguous or invalid - potential smuggling vector
    Ambiguous,
}

/// Mock HTTP/1.1 request parser focused on Transfer-Encoding vs Content-Length handling
struct MockH1RequestParser {
    /// Whether to apply RFC 9112 §6.1 strictly (remove Content-Length when Transfer-Encoding present)
    strict_rfc_mode: bool,
}

impl MockH1RequestParser {
    fn with_strict_mode(strict: bool) -> Self {
        Self {
            strict_rfc_mode: strict,
        }
    }

    /// Parse HTTP/1.1 request with strict RFC 9112 §6.1 validation
    ///
    /// Key rule being tested: RFC 9112 §6.1
    /// "If a Transfer-Encoding header field is present in a request and the chunked
    /// transfer coding is not the final encoding, the message body length cannot be
    /// determined reliably; the server MUST respond with the 400 (Bad Request) status
    /// code and then close the connection."
    ///
    /// "If a message is received with both a Transfer-Encoding and a Content-Length
    /// header field, the Transfer-Encoding overrides the Content-Length. Such a
    /// message might indicate an attempt to perform request smuggling (Section 9.5)
    /// or response splitting (Section 9.4) and ought to be handled as an error.
    /// A sender MUST remove the received Content-Length field prior to forwarding
    /// such a message downstream."
    fn parse_request(&self, request_bytes: &[u8]) -> RequestParseResult {
        let request_str = match std::str::from_utf8(request_bytes) {
            Ok(s) => s,
            Err(_) => return RequestParseResult::MalformedRequest,
        };

        // Find end of headers (double CRLF)
        let header_end = if let Some(pos) = request_str.find("\r\n\r\n") {
            pos + 4
        } else if let Some(pos) = request_str.find("\n\n") {
            pos + 2
        } else {
            return RequestParseResult::IncompleteRequest;
        };

        let header_section = &request_str[..header_end];
        let lines: Vec<&str> = header_section.lines().collect();

        if lines.is_empty() {
            return RequestParseResult::MalformedRequest;
        }

        // Parse request line
        let request_line_parts: Vec<&str> = lines[0].split_whitespace().collect();
        if request_line_parts.len() != 3 {
            return RequestParseResult::MalformedRequest;
        }

        let method = request_line_parts[0].to_string();
        let uri = request_line_parts[1].to_string();
        let version = request_line_parts[2].to_string();

        // Parse headers
        let mut headers = Vec::new();
        let mut transfer_encoding_headers = Vec::new();
        let mut content_length_headers = Vec::new();

        for line in &lines[1..] {
            if line.trim().is_empty() {
                continue;
            }

            if let Some(colon_pos) = line.find(':') {
                let name = line[..colon_pos].trim().to_lowercase();
                let value = line[colon_pos + 1..].trim().to_string();

                headers.push((name.clone(), value.clone()));

                if name == "transfer-encoding" {
                    transfer_encoding_headers.push(value);
                } else if name == "content-length" {
                    content_length_headers.push(value);
                }
            }
        }

        // Analyze Transfer-Encoding headers
        let has_chunked_encoding = transfer_encoding_headers
            .iter()
            .any(|te| te.to_lowercase().contains("chunked"));

        // Analyze Content-Length headers
        let mut content_length_value = None;
        if !content_length_headers.is_empty() {
            // RFC 9112 §6.1: Multiple Content-Length headers with same value is valid
            // Different values is a protocol error
            let first_value = content_length_headers[0].trim();

            if let Ok(length) = first_value.parse::<u64>() {
                // Check if all Content-Length headers have the same value
                let all_same = content_length_headers
                    .iter()
                    .all(|cl| cl.trim().parse::<u64>() == Ok(length));

                if !all_same {
                    return RequestParseResult::ProtocolError(
                        "Multiple Content-Length headers with different values".to_string(),
                    );
                }

                content_length_value = Some(length);
            } else {
                return RequestParseResult::ProtocolError(
                    "Invalid Content-Length value".to_string(),
                );
            }
        }

        // RFC 9112 §6.1 compliance check: Transfer-Encoding + Content-Length
        if has_chunked_encoding && !content_length_headers.is_empty() {
            if self.strict_rfc_mode {
                return RequestParseResult::ProtocolError(
                    "Request has both Transfer-Encoding: chunked AND Content-Length headers. \
                     Per RFC 9112 §6.1, this indicates potential request smuggling - \
                     Transfer-Encoding overrides Content-Length and Content-Length MUST be removed."
                        .to_string(),
                );
            } else {
                // Non-strict mode: allow but prefer Transfer-Encoding
                // This is the dangerous path that enables request smuggling!
            }
        }

        // Determine effective transfer mechanism per RFC 9112 §6.1
        let effective_transfer_mechanism = if has_chunked_encoding {
            if !content_length_headers.is_empty() && !self.strict_rfc_mode {
                // DANGEROUS: Both headers present in non-strict mode
                TransferMechanism::Ambiguous
            } else {
                TransferMechanism::Chunked
            }
        } else if let Some(length) = content_length_value {
            TransferMechanism::ContentLength(length)
        } else {
            // No body length specified
            TransferMechanism::NoBody
        };

        RequestParseResult::Valid {
            method,
            uri,
            version,
            headers,
            has_transfer_encoding_chunked: has_chunked_encoding,
            has_content_length: !content_length_headers.is_empty(),
            content_length_value,
            effective_transfer_mechanism,
        }
    }

    /// Validate that Content-Length is properly removed when Transfer-Encoding is present
    /// This simulates the RFC requirement to remove Content-Length before forwarding
    fn normalize_headers(&self, headers: &[(String, String)]) -> Vec<(String, String)> {
        let has_transfer_encoding = headers.iter().any(|(name, value)| {
            name.to_lowercase() == "transfer-encoding" && value.to_lowercase().contains("chunked")
        });

        if has_transfer_encoding && self.strict_rfc_mode {
            // Remove all Content-Length headers per RFC 9112 §6.1
            headers
                .iter()
                .filter(|(name, _)| name.to_lowercase() != "content-length")
                .cloned()
                .collect()
        } else {
            headers.to_vec()
        }
    }
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    /// HTTP method
    method: HttpMethod,
    /// Request URI
    uri: String,
    /// HTTP version
    version: HttpVersion,
    /// Whether to include Transfer-Encoding: chunked header
    include_transfer_encoding_chunked: bool,
    /// Whether to include Content-Length header
    include_content_length: bool,
    /// Content-Length value if included
    content_length_value: u64,
    /// Additional Transfer-Encoding values (for testing complex cases)
    extra_transfer_encodings: Vec<String>,
    /// Multiple Content-Length headers (for testing conflicts)
    multiple_content_lengths: Vec<u64>,
    /// Whether to test in non-strict mode (dangerous for smuggling)
    use_non_strict_mode: bool,
    /// Extra headers to add
    extra_headers: Vec<(String, String)>,
    /// Whether to use malformed line endings
    use_malformed_endings: bool,
}

#[derive(Arbitrary, Debug, Clone)]
enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Head,
    Options,
    Patch,
    Trace,
    Connect,
    Custom(String),
}

impl fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HttpMethod::Get => f.write_str("GET"),
            HttpMethod::Post => f.write_str("POST"),
            HttpMethod::Put => f.write_str("PUT"),
            HttpMethod::Delete => f.write_str("DELETE"),
            HttpMethod::Head => f.write_str("HEAD"),
            HttpMethod::Options => f.write_str("OPTIONS"),
            HttpMethod::Patch => f.write_str("PATCH"),
            HttpMethod::Trace => f.write_str("TRACE"),
            HttpMethod::Connect => f.write_str("CONNECT"),
            HttpMethod::Custom(s) => f.write_str(s),
        }
    }
}

#[derive(Arbitrary, Debug, Clone)]
enum HttpVersion {
    Http10,
    Http11,
    Http2,
    Custom(String),
}

impl fmt::Display for HttpVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HttpVersion::Http10 => f.write_str("HTTP/1.0"),
            HttpVersion::Http11 => f.write_str("HTTP/1.1"),
            HttpVersion::Http2 => f.write_str("HTTP/2.0"),
            HttpVersion::Custom(s) => f.write_str(s),
        }
    }
}

fuzz_target!(|input: FuzzInput| {
    // Build HTTP request
    let mut request = format!(
        "{} {} {}\r\n",
        input.method,
        if input.uri.is_empty() {
            "/"
        } else {
            &input.uri
        },
        input.version
    );

    // Add Transfer-Encoding headers
    if input.include_transfer_encoding_chunked {
        request.push_str("Transfer-Encoding: chunked\r\n");
    }

    for extra_te in &input.extra_transfer_encodings {
        request.push_str(&format!("Transfer-Encoding: {}\r\n", extra_te));
    }

    // Add Content-Length headers
    if input.include_content_length {
        request.push_str(&format!(
            "Content-Length: {}\r\n",
            input.content_length_value
        ));
    }

    for extra_cl in &input.multiple_content_lengths {
        request.push_str(&format!("Content-Length: {}\r\n", extra_cl));
    }

    // Add extra headers
    for (name, value) in &input.extra_headers {
        request.push_str(&format!("{}: {}\r\n", name, value));
    }

    // End headers
    request.push_str("\r\n");

    // Optionally corrupt line endings to test parser robustness
    if input.use_malformed_endings {
        request = request.replace("\r\n", "\n");
    }

    // Create parser in appropriate mode
    let parser = MockH1RequestParser::with_strict_mode(!input.use_non_strict_mode);

    // Parse the request
    let result = parser.parse_request(request.as_bytes());

    // Validate behavior based on RFC 9112 §6.1
    match &result {
        RequestParseResult::Valid {
            has_transfer_encoding_chunked,
            has_content_length,
            effective_transfer_mechanism,
            headers,
            ..
        } => {
            // Request parsed successfully - validate RFC compliance
            let has_transfer_encoding_chunked = *has_transfer_encoding_chunked;
            let has_content_length = *has_content_length;

            if has_transfer_encoding_chunked && has_content_length {
                if !input.use_non_strict_mode {
                    panic!(
                        "CRITICAL RFC VIOLATION: Request with both Transfer-Encoding: chunked \
                         and Content-Length parsed as valid in strict mode! This enables \
                         request smuggling attacks per RFC 9112 §6.1"
                    );
                } else {
                    // Non-strict mode: should mark as ambiguous
                    assert!(
                        matches!(effective_transfer_mechanism, TransferMechanism::Ambiguous),
                        "Non-strict mode with both headers should be marked as ambiguous"
                    );
                }
            }

            if has_transfer_encoding_chunked && !has_content_length {
                assert_eq!(
                    effective_transfer_mechanism,
                    &TransferMechanism::Chunked,
                    "Transfer-Encoding: chunked should result in chunked transfer mechanism"
                );
            }

            if !has_transfer_encoding_chunked && has_content_length {
                if let TransferMechanism::ContentLength(length) = effective_transfer_mechanism {
                    assert_eq!(
                        *length, input.content_length_value,
                        "Content-Length transfer should use specified length"
                    );
                } else {
                    panic!("Content-Length only should result in ContentLength mechanism");
                }
            }

            // Test header normalization (RFC requirement to remove Content-Length)
            if has_transfer_encoding_chunked && !input.use_non_strict_mode {
                let normalized_headers = parser.normalize_headers(headers);
                let has_cl_after_normalization = normalized_headers
                    .iter()
                    .any(|(name, _)| name.to_lowercase() == "content-length");

                assert!(
                    !has_cl_after_normalization,
                    "Content-Length headers MUST be removed when Transfer-Encoding is present (RFC 9112 §6.1)"
                );
            }
        }

        RequestParseResult::ProtocolError(msg) => {
            // Expected for problematic combinations

            if input.include_transfer_encoding_chunked
                && input.include_content_length
                && !input.use_non_strict_mode
            {
                // This is the exact case we're testing - should always be a protocol error
                assert!(
                    msg.contains("Transfer-Encoding")
                        && msg.contains("Content-Length")
                        && (msg.contains("request smuggling") || msg.contains("overrides")),
                    "Expected specific protocol error for TE+CL combination, got: {}",
                    msg
                );
            }

            if input.multiple_content_lengths.len() > 1 {
                // Multiple different Content-Length values should be rejected
                let all_same = input
                    .multiple_content_lengths
                    .iter()
                    .all(|&cl| cl == input.content_length_value);
                if !all_same {
                    assert!(
                        msg.contains("Multiple Content-Length") || msg.contains("different values"),
                        "Multiple different Content-Length values should be rejected, got: {}",
                        msg
                    );
                }
            }
        }

        RequestParseResult::MalformedRequest => {
            // Expected for invalid request format
        }

        RequestParseResult::IncompleteRequest => {
            // Expected for partial requests
        }
    }

    // CORE ASSERTION: Simultaneous Transfer-Encoding: chunked + Content-Length in strict mode
    // must be rejected to prevent request smuggling
    if input.include_transfer_encoding_chunked
        && input.include_content_length
        && !input.use_non_strict_mode
    {
        match &result {
            RequestParseResult::ProtocolError(msg) => {
                // Expected - verify it's the right kind of protocol error
                assert!(
                    msg.contains("Transfer-Encoding") && msg.contains("Content-Length"),
                    "Wrong protocol error message for TE+CL combination: {}",
                    msg
                );
            }
            RequestParseResult::Valid {
                effective_transfer_mechanism: TransferMechanism::Ambiguous,
                ..
            } => {
                panic!(
                    "CRITICAL: Ambiguous transfer mechanism in strict mode! Should be protocol error."
                );
            }
            RequestParseResult::Valid { .. } => {
                panic!(
                    "CRITICAL RFC VIOLATION: Request with both Transfer-Encoding: chunked \
                     and Content-Length parsed as valid in strict mode! This violates RFC 9112 §6.1 \
                     and enables HTTP request smuggling attacks."
                );
            }
            _ => {
                // Other errors (malformed, incomplete) are acceptable as long as
                // it doesn't parse as valid
            }
        }
    }

    // Test specific request smuggling scenario patterns
    if input.include_transfer_encoding_chunked && input.include_content_length {
        // This is a classic CL.TE request smuggling setup
        // Frontend (Content-Length) vs Backend (Transfer-Encoding) disagreement

        // Test both strict and non-strict modes to ensure strict mode blocks this
        let strict_parser = MockH1RequestParser::with_strict_mode(true);
        let non_strict_parser = MockH1RequestParser::with_strict_mode(false);

        let strict_result = strict_parser.parse_request(request.as_bytes());
        let non_strict_result = non_strict_parser.parse_request(request.as_bytes());

        // Strict mode must reject
        match strict_result {
            RequestParseResult::ProtocolError(_) => {
                // Expected - good!
            }
            _ => {
                panic!("Strict mode must reject CL.TE request smuggling pattern");
            }
        }

        // Non-strict mode should at least mark as ambiguous (still dangerous but detectable)
        match non_strict_result {
            RequestParseResult::Valid {
                effective_transfer_mechanism: TransferMechanism::Ambiguous,
                ..
            } => {
                // Minimally acceptable - at least it's flagged as problematic
            }
            RequestParseResult::ProtocolError(_) => {
                // Even better - rejected entirely
            }
            RequestParseResult::Valid { .. } => {
                panic!("non-strict mode silently accepted CL.TE smuggling pattern");
            }
            _ => {}
        }
    }

    // Additional edge case: Empty Transfer-Encoding value
    if input
        .extra_transfer_encodings
        .iter()
        .any(|te| te.trim().is_empty())
    {
        // Empty Transfer-Encoding values should be handled gracefully
        match result {
            RequestParseResult::Valid {
                effective_transfer_mechanism: TransferMechanism::NoBody,
                ..
            } => {
                // Acceptable - treat as no Transfer-Encoding
            }
            RequestParseResult::ProtocolError(_) => {
                // Also acceptable - reject malformed header
            }
            _ => {}
        }
    }
});
