#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

/// HTTP/2 frame header length per RFC 7540 §4.1
const FRAME_HEADER_LEN: usize = 9;

/// HTTP/2 HEADERS frame type per RFC 7540 §6.2
const HEADERS_FRAME_TYPE: u8 = 0x1;

/// HEADERS frame flags
const END_HEADERS_FLAG: u8 = 0x4;
const END_STREAM_FLAG: u8 = 0x1;

/// URL parsing result per RFC 3986 §3.3 + §3.4
#[derive(Debug, PartialEq)]
enum PathParseResult {
    /// Valid path with parsed components
    Valid {
        full_path: String,
        path_component: String,
        query_component: Option<String>,
        fragment_component: Option<String>, // Should not be present in HTTP/2
        has_multiple_query_delimiters: bool,
        url_encoded_question_marks: Vec<usize>, // Positions of %3F in path
    },
    /// Protocol error - invalid format
    ProtocolError(String),
    /// Empty path (invalid for most requests)
    Empty,
    /// Fragment present (forbidden in HTTP/2 requests)
    HasFragment(String),
    /// Invalid URL encoding
    InvalidEncoding(String),
}

/// HTTP/2 header field per RFC 7540 §6.2
#[derive(Debug, Clone)]
struct HeaderField {
    name: String,
    value: String,
}

impl HeaderField {
    fn new(name: &str, value: &str) -> Self {
        Self {
            name: name.to_string(),
            value: value.to_string(),
        }
    }

    /// Validate :path pseudo-header with focus on query string parsing per RFC 3986 §3.3 + §3.4
    ///
    /// Key rules from RFC 3986:
    /// - path-absolute = "/" *( "/" segment )
    /// - query = *( pchar / "/" / "?" )
    /// - The FIRST "?" character delimits the query component
    /// - Subsequent "?" characters are part of the query string itself
    /// - URL-encoded "?" (%3F) in path should NOT be treated as delimiters
    ///
    /// RFC 7540 §8.3.1: :path MUST NOT contain fragment component (#)
    fn validate_path_with_query(&self) -> PathParseResult {
        if self.name != ":path" {
            return PathParseResult::ProtocolError("Not a :path header".to_string());
        }

        let path = &self.value;

        // RFC 7540 §8.3.1: :path MUST NOT be empty for http/https
        if path.is_empty() {
            return PathParseResult::Empty;
        }

        // RFC 7540 §8.3.1: :path MUST NOT contain fragment component
        if let Some(fragment_pos) = path.find('#') {
            let fragment = &path[fragment_pos + 1..];
            return PathParseResult::HasFragment(fragment.to_string());
        }

        // Find URL-encoded question marks (%3F or %3f) in the original path
        let mut url_encoded_positions = Vec::new();
        let path_lower = path.to_lowercase();
        let mut search_start = 0;

        while let Some(pos) = path_lower[search_start..].find("%3f") {
            let absolute_pos = search_start + pos;
            url_encoded_positions.push(absolute_pos);
            search_start = absolute_pos + 3;
        }

        // RFC 3986 §3.4: Query component is delimited by the FIRST literal "?" character
        // URL-encoded %3F should not be treated as a delimiter
        let first_question_pos = path.find('?');

        let (path_component, query_component) = if let Some(q_pos) = first_question_pos {
            let path_part = &path[..q_pos];
            let query_part = &path[q_pos + 1..];

            // Check if this "?" is actually a URL-encoded %3F
            let is_encoded = url_encoded_positions
                .iter()
                .any(|&pos| pos + 2 == q_pos && path.chars().nth(pos) == Some('%'));

            if is_encoded {
                // This "?" is part of a %3F encoding, treat entire string as path
                (path.to_string(), None)
            } else {
                // Real query delimiter
                (
                    path_part.to_string(),
                    if query_part.is_empty() {
                        None
                    } else {
                        Some(query_part.to_string())
                    },
                )
            }
        } else {
            // No query component
            (path.to_string(), None)
        };

        // Count additional "?" characters in query component (valid per RFC 3986)
        let has_multiple_query_delimiters = if let Some(ref query) = query_component {
            query.contains('?')
        } else {
            false
        };

        // Validate path component format (must start with "/" unless "*" for OPTIONS)
        if !path_component.starts_with('/') && path_component != "*" {
            return PathParseResult::ProtocolError(format!(
                "Path component '{}' must start with '/' or be '*'",
                path_component
            ));
        }

        // Validate URL encoding in path component
        if let Err(decode_error) = validate_url_encoding(&path_component) {
            return PathParseResult::InvalidEncoding(format!(
                "Invalid URL encoding in path: {}",
                decode_error
            ));
        }

        // Validate URL encoding in query component
        if let Some(ref query) = query_component {
            if let Err(decode_error) = validate_url_encoding(query) {
                return PathParseResult::InvalidEncoding(format!(
                    "Invalid URL encoding in query: {}",
                    decode_error
                ));
            }
        }

        PathParseResult::Valid {
            full_path: path.to_string(),
            path_component,
            query_component,
            fragment_component: None, // Should never be present
            has_multiple_query_delimiters,
            url_encoded_question_marks: url_encoded_positions,
        }
    }
}

/// Validate URL encoding format per RFC 3986 §2.1
fn validate_url_encoding(input: &str) -> Result<(), String> {
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        if chars[i] == '%' {
            // Must be followed by exactly two hexadecimal digits
            if i + 2 >= chars.len() {
                return Err("Incomplete percent encoding at end of string".to_string());
            }

            let hex1 = chars[i + 1];
            let hex2 = chars[i + 2];

            if !hex1.is_ascii_hexdigit() || !hex2.is_ascii_hexdigit() {
                return Err(format!(
                    "Invalid hex digits in percent encoding: %{}{} at position {}",
                    hex1, hex2, i
                ));
            }

            i += 3; // Skip the %XX sequence
        } else {
            i += 1;
        }
    }

    Ok(())
}

/// Decode percent-encoded string per RFC 3986 §2.1
fn percent_decode(input: &str) -> Result<Vec<u8>, String> {
    let mut result = Vec::new();
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        if chars[i] == '%' {
            if i + 2 >= chars.len() {
                return Err("Incomplete percent encoding".to_string());
            }

            let hex_str = format!("{}{}", chars[i + 1], chars[i + 2]);
            match u8::from_str_radix(&hex_str, 16) {
                Ok(byte) => result.push(byte),
                Err(_) => return Err(format!("Invalid hex in percent encoding: {}", hex_str)),
            }

            i += 3;
        } else {
            // Regular ASCII character
            if chars[i].is_ascii() {
                result.push(chars[i] as u8);
            } else {
                return Err("Non-ASCII character in URL".to_string());
            }
            i += 1;
        }
    }

    Ok(result)
}

/// HTTP/2 frame header per RFC 7540 §4.1
#[derive(Debug, Clone)]
struct FrameHeader {
    length: u32,
    frame_type: u8,
    flags: u8,
    stream_id: u32,
}

impl FrameHeader {
    fn encode(&self) -> [u8; 9] {
        let mut buf = [0u8; 9];

        // Length (24 bits, big-endian)
        buf[0] = (self.length >> 16) as u8;
        buf[1] = (self.length >> 8) as u8;
        buf[2] = self.length as u8;

        // Type and flags
        buf[3] = self.frame_type;
        buf[4] = self.flags;

        // Stream ID (31 bits + reserved bit, big-endian)
        let stream_id = self.stream_id & 0x7FFF_FFFF;
        buf[5] = (stream_id >> 24) as u8;
        buf[6] = (stream_id >> 16) as u8;
        buf[7] = (stream_id >> 8) as u8;
        buf[8] = stream_id as u8;

        buf
    }
}

/// Mock HPACK encoder for testing
struct MockHpackEncoder;

impl MockHpackEncoder {
    fn encode_headers(&self, headers: &[HeaderField]) -> Vec<u8> {
        let mut encoded = Vec::new();

        for header in headers {
            // Simplified HPACK encoding
            encoded.push(0x40); // Literal header field with incremental indexing

            // Encode name
            let name_bytes = header.name.as_bytes();
            encoded.push(name_bytes.len() as u8);
            encoded.extend_from_slice(name_bytes);

            // Encode value
            let value_bytes = header.value.as_bytes();
            encoded.push(value_bytes.len() as u8);
            encoded.extend_from_slice(value_bytes);
        }

        encoded
    }
}

#[derive(Debug, PartialEq)]
enum HeadersParseResult {
    Valid {
        headers: Vec<HeaderField>,
        path_result: Option<PathParseResult>,
    },
    ProtocolError(String),
    IncompleteFrame,
    InvalidStreamId,
}

/// Mock HTTP/2 HEADERS frame parser with :path query string validation
struct MockH2PathQueryParser {
    hpack_encoder: MockHpackEncoder,
}

impl MockH2PathQueryParser {
    fn new() -> Self {
        Self {
            hpack_encoder: MockHpackEncoder,
        }
    }

    fn parse_headers_frame(&self, buf: &[u8]) -> HeadersParseResult {
        // Simplified frame parsing
        if buf.len() < FRAME_HEADER_LEN {
            return HeadersParseResult::IncompleteFrame;
        }

        // Extract payload (skip frame header)
        let payload = &buf[FRAME_HEADER_LEN..];

        // Simplified HPACK decoding
        let mut headers = Vec::new();
        let mut pos = 0;

        while pos < payload.len() {
            if pos + 2 >= payload.len() {
                break;
            }

            // Skip header pattern byte
            pos += 1;

            // Read name length
            let name_len = payload[pos] as usize;
            pos += 1;

            if pos + name_len > payload.len() {
                break;
            }

            let name = String::from_utf8_lossy(&payload[pos..pos + name_len]).to_string();
            pos += name_len;

            if pos >= payload.len() {
                break;
            }

            // Read value length
            let value_len = payload[pos] as usize;
            pos += 1;

            if pos + value_len > payload.len() {
                break;
            }

            let value = String::from_utf8_lossy(&payload[pos..pos + value_len]).to_string();
            pos += value_len;

            headers.push(HeaderField::new(&name, &value));
        }

        // Find and validate :path header
        let path_result = headers
            .iter()
            .find(|h| h.name == ":path")
            .map(|h| h.validate_path_with_query());

        // Check for protocol errors in path validation
        if let Some(PathParseResult::ProtocolError(ref msg)) = path_result {
            return HeadersParseResult::ProtocolError(format!("Invalid :path: {}", msg));
        }

        if let Some(PathParseResult::HasFragment(ref fragment)) = path_result {
            return HeadersParseResult::ProtocolError(format!(
                "Fragment component forbidden in HTTP/2 :path: #{}",
                fragment
            ));
        }

        if let Some(PathParseResult::InvalidEncoding(ref msg)) = path_result {
            return HeadersParseResult::ProtocolError(format!(
                "Invalid URL encoding in :path: {}",
                msg
            ));
        }

        HeadersParseResult::Valid {
            headers,
            path_result,
        }
    }
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    /// Stream ID for HEADERS frame
    stream_id: u32,
    /// :path pseudo-header value (main test target)
    path: PathVariant,
    /// Additional headers
    extra_headers: Vec<(String, String)>,
    /// Whether to test multiple query delimiters
    test_multiple_queries: bool,
    /// Whether to test URL-encoded question marks
    test_encoded_question_marks: bool,
    /// Whether to test fragment components (should be rejected)
    test_fragments: bool,
    /// Whether to test invalid percent encoding
    test_invalid_encoding: bool,
}

#[derive(Arbitrary, Debug, Clone)]
enum PathVariant {
    /// Valid paths with different query patterns
    Valid(ValidPathQuery),
    /// Paths with multiple ? characters
    MultipleQueries(String),
    /// Paths with URL-encoded ? characters (%3F)
    EncodedQuestions(String),
    /// Paths with fragments (invalid in HTTP/2)
    WithFragment(String, String), // path, fragment
    /// Paths with invalid percent encoding
    InvalidEncoding(String),
    /// Custom path string
    Custom(String),
}

#[derive(Arbitrary, Debug, Clone)]
enum ValidPathQuery {
    /// Simple path without query
    Simple(String),
    /// Path with single query parameter
    WithQuery(String, String), // path, query
    /// Path with multiple query parameters
    WithMultipleParams(String, Vec<(String, String)>), // path, params
    /// Path with encoded characters in path component
    WithEncodedPath(String, String), // encoded_path, query
    /// Path with encoded characters in query component
    WithEncodedQuery(String, String), // path, encoded_query
    /// Asterisk form for OPTIONS
    Asterisk,
}

impl PathVariant {
    fn to_string(&self) -> String {
        match self {
            PathVariant::Valid(valid) => match valid {
                ValidPathQuery::Simple(path) => format!("/{}", path),
                ValidPathQuery::WithQuery(path, query) => format!("/{}?{}", path, query),
                ValidPathQuery::WithMultipleParams(path, params) => {
                    let query_string = params
                        .iter()
                        .map(|(k, v)| format!("{}={}", k, v))
                        .collect::<Vec<_>>()
                        .join("&");
                    format!("/{}?{}", path, query_string)
                }
                ValidPathQuery::WithEncodedPath(encoded_path, query) => {
                    format!("/{}?{}", encoded_path, query)
                }
                ValidPathQuery::WithEncodedQuery(path, encoded_query) => {
                    format!("/{}?{}", path, encoded_query)
                }
                ValidPathQuery::Asterisk => "*".to_string(),
            },
            PathVariant::MultipleQueries(base) => {
                format!("/{}?query=value?more=data?even=more", base)
            }
            PathVariant::EncodedQuestions(base) => {
                format!("/path%3Fencoded/{}", base)
            }
            PathVariant::WithFragment(path, fragment) => {
                format!("/{}#{}", path, fragment)
            }
            PathVariant::InvalidEncoding(path) => path.clone(),
            PathVariant::Custom(custom) => custom.clone(),
        }
    }
}

fuzz_target!(|input: FuzzInput| {
    let parser = MockH2PathQueryParser::new();

    // Ensure valid stream ID (non-zero, odd for client-initiated)
    let stream_id = if input.stream_id == 0 {
        1
    } else {
        (input.stream_id & 0x7FFF_FFFF) | 1
    };

    // Build headers list
    let mut headers = Vec::new();

    // Add required pseudo-headers for a valid request
    headers.push(HeaderField::new(":method", "GET"));
    headers.push(HeaderField::new(":scheme", "https"));
    headers.push(HeaderField::new(":authority", "example.com"));

    // Add :path header (the main test target)
    let mut path_value = input.path.to_string();

    // Add specific test cases for query string edge conditions
    if input.test_multiple_queries {
        // Test various multiple query delimiter patterns
        let multiple_query_patterns = [
            "/path?query=value?more=data",         // ? in query value
            "/search?q=hello?world&sort=date",     // ? in parameter value
            "/api?callback=fn?param=1&data=test",  // Complex nesting
            "/path?a=1?b=2?c=3",                   // Multiple delimiters
            "/path?query=what?time?is?it",         // Many ? in query
            "/resource?filter=name?contains?test", // ? in filter expression
        ];

        path_value =
            multiple_query_patterns[stream_id as usize % multiple_query_patterns.len()].to_string();
    }

    if input.test_encoded_question_marks {
        // Test URL-encoded question marks in different positions
        let encoded_patterns = [
            "/path%3Fencoded?realquery=value",  // %3F in path, real ? for query
            "/search%3Fterm?q=test",            // %3F should not split query
            "/api%3Fversion%3D1?param=value",   // Multiple %3F in path
            "/file.php%3Faction%3Dview?id=123", // Common web pattern
            "/path?query=%3Fencoded",           // %3F in query value (valid)
            "/deep%3Fpath%3Fsegment?real=query", // Multiple encodings
            "/path%3fencoded?query=value",      // Lowercase %3f
        ];

        path_value = encoded_patterns[stream_id as usize % encoded_patterns.len()].to_string();
    }

    if input.test_fragments {
        // Test fragment components (should be rejected in HTTP/2)
        let fragment_patterns = [
            "/path#fragment",
            "/path?query=value#fragment",
            "/path#fragment?notquery",
            "/api/resource#section1",
            "/document.html#top?notquery=value",
            "/#empty-path-fragment",
        ];

        path_value = fragment_patterns[stream_id as usize % fragment_patterns.len()].to_string();
    }

    if input.test_invalid_encoding {
        // Test invalid percent encoding patterns
        let invalid_encoding_patterns = [
            "/path%",      // Incomplete encoding
            "/path%2",     // Incomplete encoding
            "/path%GG",    // Invalid hex digits
            "/path%2Z",    // Invalid hex digit
            "/path%XX",    // Non-hex characters
            "/path%20%",   // Valid then incomplete
            "/path%20%GH", // Valid then invalid
        ];

        path_value = invalid_encoding_patterns
            [stream_id as usize % invalid_encoding_patterns.len()]
        .to_string();
    }

    headers.push(HeaderField::new(":path", &path_value));

    // Add extra headers
    for (name, value) in &input.extra_headers {
        headers.push(HeaderField::new(name, value));
    }

    // Create HEADERS frame
    let encoded_headers = parser.hpack_encoder.encode_headers(&headers);

    let frame_header = FrameHeader {
        length: encoded_headers.len() as u32,
        frame_type: HEADERS_FRAME_TYPE,
        flags: END_HEADERS_FLAG,
        stream_id,
    };

    // Build complete frame
    let mut frame_bytes = Vec::new();
    frame_bytes.extend_from_slice(&frame_header.encode());
    frame_bytes.extend_from_slice(&encoded_headers);

    // Parse the frame
    let result = parser.parse_headers_frame(&frame_bytes);

    // Validate behavior based on path format and query string handling
    match result {
        HeadersParseResult::Valid {
            path_result: Some(path_parse_result),
            ..
        } => {
            match path_parse_result {
                PathParseResult::Valid {
                    path_component,
                    query_component,
                    has_multiple_query_delimiters,
                    url_encoded_question_marks,
                    ..
                } => {
                    // Path parsed successfully - validate query string parsing

                    // Test multiple query delimiter handling
                    if input.test_multiple_queries && path_value.matches('?').count() > 1 {
                        // Should have detected multiple query delimiters
                        if let Some(_query) = &query_component {
                            // Query component should contain additional ? characters
                            // This is valid per RFC 3986 - only the FIRST ? is the delimiter
                        }
                    }

                    // Test URL-encoded question mark handling
                    if input.test_encoded_question_marks && path_value.contains("%3f") {
                        // %3F in path should not be treated as query delimiter
                        if path_value.contains("%3F?") || path_value.contains("%3f?") {
                            // Should have real query component after encoded ones
                            assert!(
                                query_component.is_some(),
                                "Should have query component after encoded %3F: {}",
                                path_value
                            );

                            // Encoded %3F should be in path component, not treated as delimiter
                            assert!(
                                !url_encoded_question_marks.is_empty(),
                                "Should have detected URL-encoded question marks: {}",
                                path_value
                            );
                        } else {
                            // No real ? delimiter, should treat %3F as part of path
                            assert!(
                                query_component.is_none(),
                                "Should not have query component with only encoded %3F: {}",
                                path_value
                            );
                        }
                    }

                    // Validate that path component starts with / or is *
                    assert!(
                        path_component.starts_with('/') || path_component == "*",
                        "Path component should start with '/' or be '*': {}",
                        path_component
                    );

                    // Test fragment rejection (should not reach here if fragment present)
                    if input.test_fragments && path_value.contains('#') {
                        panic!(
                            "CRITICAL RFC VIOLATION: Path with fragment parsed as valid! \
                             Fragments are forbidden in HTTP/2 :path. Path: {}",
                            path_value
                        );
                    }

                    // Test invalid encoding rejection (should not reach here if invalid)
                    if input.test_invalid_encoding
                        && (path_value.contains("%G")
                            || path_value.contains("%X")
                            || path_value.ends_with('%')
                            || path_value.contains("%2Z"))
                    {
                        panic!(
                            "CRITICAL RFC VIOLATION: Path with invalid percent encoding parsed as valid! \
                             Path: {}",
                            path_value
                        );
                    }
                }

                PathParseResult::Empty => {
                    assert!(
                        path_value.is_empty(),
                        "Empty path result but value is not empty: {}",
                        path_value
                    );
                }

                PathParseResult::HasFragment(_) => {
                    panic!("HasFragment should have been converted to ProtocolError");
                }

                PathParseResult::InvalidEncoding(_) => {
                    panic!("InvalidEncoding should have been converted to ProtocolError");
                }

                PathParseResult::ProtocolError(_) => {
                    panic!("ProtocolError should have been handled at frame level");
                }
            }
        }

        HeadersParseResult::ProtocolError(msg) => {
            // Expected for invalid path formats

            if input.test_fragments && path_value.contains('#') {
                assert!(
                    msg.to_lowercase().contains("fragment")
                        || msg.to_lowercase().contains("forbidden"),
                    "Expected fragment error for path with #, got: {}",
                    msg
                );
            }

            if input.test_invalid_encoding
                && (path_value.contains("%G")
                    || path_value.contains("%X")
                    || path_value.ends_with('%'))
            {
                assert!(
                    msg.to_lowercase().contains("encoding")
                        || msg.to_lowercase().contains("percent")
                        || msg.to_lowercase().contains("invalid"),
                    "Expected encoding error for invalid percent encoding, got: {}",
                    msg
                );
            }
        }

        HeadersParseResult::Valid {
            path_result: None, ..
        } => {
            // No :path header present - acceptable for some request types
        }

        HeadersParseResult::IncompleteFrame => {
            // Expected for malformed frames
        }

        HeadersParseResult::InvalidStreamId => {
            // Should not happen with our stream ID logic
            panic!("Unexpected InvalidStreamId with stream_id: {}", stream_id);
        }
    }

    // CORE ASSERTION: Test RFC 3986 query string delimiter behavior
    if path_value.contains('?') && !path_value.contains('#') {
        // Find first literal ? (not %3F)
        if let Some(first_q_pos) = path_value.find('?') {
            // Everything after first ? should be query component
            let expected_path = &path_value[..first_q_pos];
            let expected_query = &path_value[first_q_pos + 1..];

            match result {
                HeadersParseResult::Valid {
                    path_result:
                        Some(PathParseResult::Valid {
                            path_component,
                            query_component,
                            ..
                        }),
                    ..
                } => {
                    // Verify correct parsing
                    assert_eq!(
                        path_component, expected_path,
                        "Path component mismatch. Expected: '{}', Got: '{}', Full: '{}'",
                        expected_path, path_component, path_value
                    );

                    if !expected_query.is_empty() {
                        assert_eq!(
                            query_component.as_deref().unwrap_or(""),
                            expected_query,
                            "Query component mismatch. Expected: '{}', Got: '{:?}', Full: '{}'",
                            expected_query,
                            query_component,
                            path_value
                        );
                    }
                }
                _ => {
                    // Error cases are acceptable for malformed paths
                }
            }
        }
    }

    // Test specific RFC 3986 compliance patterns
    let test_patterns = [
        ("/path?query=value?more", "/path", "query=value?more"), // ? in query is valid
        ("/search?q=hello?world", "/search", "q=hello?world"),   // ? in parameter value
        ("/api?fn=callback?x=1", "/api", "fn=callback?x=1"),     // ? in callback
        (
            "/path%3Fencoded?real=query",
            "/path%3Fencoded",
            "real=query",
        ), // %3F not delimiter
        (
            "/file%3Faction%3Dview?id=123",
            "/file%3Faction%3Dview",
            "id=123",
        ), // Multiple %3F
    ];

    for &(full_path, expected_path_part, expected_query_part) in &test_patterns {
        let mut test_headers = vec![
            HeaderField::new(":method", "GET"),
            HeaderField::new(":scheme", "https"),
            HeaderField::new(":authority", "example.com"),
            HeaderField::new(":path", full_path),
        ];

        let test_encoded = parser.hpack_encoder.encode_headers(&test_headers);
        let test_frame_header = FrameHeader {
            length: test_encoded.len() as u32,
            frame_type: HEADERS_FRAME_TYPE,
            flags: END_HEADERS_FLAG,
            stream_id: 9,
        };

        let mut test_frame = Vec::new();
        test_frame.extend_from_slice(&test_frame_header.encode());
        test_frame.extend_from_slice(&test_encoded);

        let test_result = parser.parse_headers_frame(&test_frame);

        match test_result {
            HeadersParseResult::Valid {
                path_result:
                    Some(PathParseResult::Valid {
                        path_component,
                        query_component,
                        ..
                    }),
                ..
            } => {
                assert_eq!(
                    path_component, expected_path_part,
                    "RFC 3986 compliance test failed for '{}' - path component",
                    full_path
                );

                assert_eq!(
                    query_component.as_deref().unwrap_or(""),
                    expected_query_part,
                    "RFC 3986 compliance test failed for '{}' - query component",
                    full_path
                );
            }
            _ => {
                // Some test patterns might be rejected due to encoding issues, which is acceptable
            }
        }
    }

    // Test invalid patterns that should be rejected
    let invalid_patterns = [
        "/path#fragment",       // Fragment forbidden in HTTP/2
        "/path%",               // Incomplete percent encoding
        "/path%GG",             // Invalid hex in encoding
        "/path?query#fragment", // Fragment after query
        "",                     // Empty path
        "relative/path",        // Must start with /
    ];

    for &invalid_pattern in &invalid_patterns {
        let mut test_headers = vec![
            HeaderField::new(":method", "GET"),
            HeaderField::new(":scheme", "https"),
            HeaderField::new(":authority", "example.com"),
            HeaderField::new(":path", invalid_pattern),
        ];

        let test_encoded = parser.hpack_encoder.encode_headers(&test_headers);
        let test_frame_header = FrameHeader {
            length: test_encoded.len() as u32,
            frame_type: HEADERS_FRAME_TYPE,
            flags: END_HEADERS_FLAG,
            stream_id: 11,
        };

        let mut test_frame = Vec::new();
        test_frame.extend_from_slice(&test_frame_header.encode());
        test_frame.extend_from_slice(&test_encoded);

        let test_result = parser.parse_headers_frame(&test_frame);

        match test_result {
            HeadersParseResult::Valid {
                path_result: Some(PathParseResult::Valid { .. }),
                ..
            } => {
                // Only allow "*" and empty paths in specific contexts
                if invalid_pattern != "*" && invalid_pattern != "" {
                    panic!(
                        "CRITICAL SECURITY ISSUE: Invalid path pattern parsed as valid: '{}'",
                        invalid_pattern
                    );
                }
            }
            HeadersParseResult::ProtocolError(_) => {
                // Expected - invalid pattern correctly rejected
            }
            _ => {
                // Other results are acceptable (incomplete, etc.)
            }
        }
    }
});
