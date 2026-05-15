#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

/// HTTP/2 frame header length per RFC 9113
const FRAME_HEADER_LEN: usize = 9;

/// HTTP/2 HEADERS frame type per RFC 9113 §6.2
const HEADERS_FRAME_TYPE: u8 = 0x1;

/// HEADERS frame flags per RFC 9113 §6.2
const END_HEADERS_FLAG: u8 = 0x4;
const END_STREAM_FLAG: u8 = 0x1;

/// HTTP/2 header field per RFC 9113 §6.2
#[derive(Debug, Clone, PartialEq)]
struct HeaderField {
    name: String,
    value: String,
    sensitive: bool, // For literal header field with incremental indexing - never indexed
}

impl HeaderField {
    fn new(name: &str, value: &str) -> Self {
        Self {
            name: name.to_string(),
            value: value.to_string(),
            sensitive: false,
        }
    }

    /// Check if this is a pseudo-header
    fn is_pseudo_header(&self) -> bool {
        self.name.starts_with(':')
    }

    /// Validate :path pseudo-header per RFC 9113 §8.3.1
    ///
    /// Key rules from RFC 9113:
    /// - :path MUST NOT be empty for http or https requests
    /// - :path value MUST start with '/' for http/https requests
    /// - :path MUST NOT contain control characters (0x00-0x1F, 0x7F)
    /// - :path MUST NOT contain CRLF sequences
    /// - :path MUST be properly percent-encoded
    fn validate_path_header(&self) -> Result<(), String> {
        if self.name != ":path" {
            return Ok(()); // Not a :path header
        }

        let path = &self.value;

        // RFC 9113 §8.3.1: :path MUST NOT be empty for http/https
        if path.is_empty() {
            return Err("Empty :path pseudo-header is not allowed".to_string());
        }

        // RFC 9113 §8.3.1: :path MUST start with '/' for http/https schemes
        // Note: asterisk-form (*) is allowed for OPTIONS requests to entire server
        if !path.starts_with('/') && path != "*" {
            return Err(format!(
                "Invalid :path '{}' - must start with '/' or be '*'",
                path
            ));
        }

        // RFC 9113: Control characters are forbidden in header field values
        // This includes characters 0x00-0x1F and 0x7F
        for (i, &byte) in path.as_bytes().iter().enumerate() {
            if byte <= 0x1F || byte == 0x7F {
                return Err(format!(
                    "Control character 0x{:02x} at position {} in :path '{}'",
                    byte, i, path
                ));
            }
        }

        // RFC 9113: CRLF sequences are specifically forbidden
        if path.contains("\r\n")
            || path.contains("\n\r")
            || path.contains("\r")
            || path.contains("\n")
        {
            return Err(format!("CRLF or line break characters in :path '{}'", path));
        }

        // RFC 9113: NUL byte (0x00) is forbidden
        if path.contains('\0') {
            return Err(format!("NUL character in :path '{}'", path));
        }

        // Check for other problematic characters that could cause parsing issues
        // Space characters that aren't properly encoded
        if path.contains(' ') {
            return Err(format!(
                "Unencoded space character in :path '{}' - should be %20",
                path
            ));
        }

        // Tab character
        if path.contains('\t') {
            return Err(format!("Tab character in :path '{}' - should be %09", path));
        }

        // Double-encoded sequences could indicate evasion attempts
        if path.contains("%25") {
            // This could be %25xx which would decode to %xx
            // May indicate double-encoding evasion attempt
            return Err(format!(
                "Potentially double-encoded sequence in :path '{}'",
                path
            ));
        }

        Ok(())
    }
}

/// HTTP/2 frame header per RFC 9113 §4.1
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

    fn decode(buf: &[u8]) -> Result<Self, &'static str> {
        if buf.len() < 9 {
            return Err("incomplete header");
        }

        let length = ((buf[0] as u32) << 16) | ((buf[1] as u32) << 8) | (buf[2] as u32);

        let frame_type = buf[3];
        let flags = buf[4];

        let stream_id = ((buf[5] as u32 & 0x7F) << 24)
            | ((buf[6] as u32) << 16)
            | ((buf[7] as u32) << 8)
            | (buf[8] as u32);

        Ok(FrameHeader {
            length,
            frame_type,
            flags,
            stream_id,
        })
    }
}

/// Mock HPACK decoder for testing (simplified)
struct MockHpackDecoder;

impl MockHpackDecoder {
    /// Simplified HPACK decoding - just extracts literal headers for testing
    /// In real implementation, this would handle indexed headers, dynamic table, etc.
    fn decode_headers(&self, encoded: &[u8]) -> Result<Vec<HeaderField>, String> {
        let mut headers = Vec::new();
        let mut pos = 0;

        while pos < encoded.len() {
            // Simplified: assume literal header field with incremental indexing (01)
            // or literal header field never indexed (0001)
            let first_byte = encoded[pos];

            let sensitive = (first_byte & 0xF0) == 0x10; // Never indexed pattern
            pos += 1;

            if pos >= encoded.len() {
                break;
            }

            // Read name length (simplified - assume < 127)
            let name_len = encoded[pos] as usize;
            pos += 1;

            if pos + name_len > encoded.len() {
                return Err("Insufficient data for header name".to_string());
            }

            let name = String::from_utf8_lossy(&encoded[pos..pos + name_len]).to_string();
            pos += name_len;

            if pos >= encoded.len() {
                return Err("Missing header value".to_string());
            }

            // Read value length (simplified - assume < 127)
            let value_len = encoded[pos] as usize;
            pos += 1;

            if pos + value_len > encoded.len() {
                return Err("Insufficient data for header value".to_string());
            }

            let value = String::from_utf8_lossy(&encoded[pos..pos + value_len]).to_string();
            pos += value_len;

            let mut header = HeaderField::new(&name, &value);
            header.sensitive = sensitive;
            headers.push(header);
        }

        Ok(headers)
    }

    /// Encode headers to HPACK format (simplified for testing)
    fn encode_headers(&self, headers: &[HeaderField]) -> Vec<u8> {
        let mut encoded = Vec::new();

        for header in headers {
            // Use literal header field pattern
            let pattern = if header.sensitive { 0x10 } else { 0x40 };
            encoded.push(pattern);

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
        stream_id: u32,
        headers: Vec<HeaderField>,
        end_stream: bool,
        end_headers: bool,
    },
    ProtocolError(String),
    IncompleteFrame,
    InvalidStreamId,
    CompressionError,
}

/// Mock HTTP/2 HEADERS frame parser with :path validation
struct MockH2HeadersParser {
    hpack_decoder: MockHpackDecoder,
}

impl MockH2HeadersParser {
    fn new() -> Self {
        Self {
            hpack_decoder: MockHpackDecoder,
        }
    }

    /// Parse HEADERS frame with strict :path pseudo-header validation
    fn parse_headers_frame(&mut self, buf: &[u8]) -> HeadersParseResult {
        // Parse frame header
        let header = match FrameHeader::decode(buf) {
            Ok(h) => h,
            Err(_) => return HeadersParseResult::IncompleteFrame,
        };

        // Must be HEADERS frame
        if header.frame_type != HEADERS_FRAME_TYPE {
            return HeadersParseResult::ProtocolError(format!(
                "Expected HEADERS frame (0x1), got 0x{:x}",
                header.frame_type
            ));
        }

        // HEADERS frames must have non-zero stream ID per RFC 9113 §6.2
        if header.stream_id == 0 {
            return HeadersParseResult::InvalidStreamId;
        }

        // Check complete frame is present
        let total_len = FRAME_HEADER_LEN + header.length as usize;
        if buf.len() < total_len {
            return HeadersParseResult::IncompleteFrame;
        }

        let payload = &buf[FRAME_HEADER_LEN..total_len];

        // Extract flags
        let end_stream = (header.flags & END_STREAM_FLAG) != 0;
        let end_headers = (header.flags & END_HEADERS_FLAG) != 0;

        // Decode HPACK headers
        let headers = match self.hpack_decoder.decode_headers(payload) {
            Ok(h) => h,
            Err(_) => return HeadersParseResult::CompressionError,
        };

        // Validate pseudo-headers per RFC 9113 §8.3
        let mut has_method = false;
        let mut has_path = false;
        let mut has_scheme = false;
        let mut pseudo_header_done = false;

        for header in &headers {
            if header.is_pseudo_header() {
                // RFC 9113 §8.3: All pseudo-headers must appear before regular headers
                if pseudo_header_done {
                    return HeadersParseResult::ProtocolError(
                        "Pseudo-header after regular header".to_string(),
                    );
                }

                match header.name.as_str() {
                    ":method" => {
                        if has_method {
                            return HeadersParseResult::ProtocolError(
                                "Duplicate :method pseudo-header".to_string(),
                            );
                        }
                        has_method = true;
                    }
                    ":path" => {
                        if has_path {
                            return HeadersParseResult::ProtocolError(
                                "Duplicate :path pseudo-header".to_string(),
                            );
                        }
                        has_path = true;

                        // CRITICAL: Validate :path header per RFC 9113
                        if let Err(validation_error) = header.validate_path_header() {
                            return HeadersParseResult::ProtocolError(format!(
                                "Invalid :path pseudo-header: {}",
                                validation_error
                            ));
                        }
                    }
                    ":scheme" => {
                        if has_scheme {
                            return HeadersParseResult::ProtocolError(
                                "Duplicate :scheme pseudo-header".to_string(),
                            );
                        }
                        has_scheme = true;
                    }
                    ":authority" => {
                        // Optional, can be omitted
                    }
                    _ => {
                        return HeadersParseResult::ProtocolError(format!(
                            "Unknown pseudo-header: {}",
                            header.name
                        ));
                    }
                }
            } else {
                // Regular header - mark that pseudo-header section is done
                pseudo_header_done = true;

                // RFC 9113: Regular headers must not start with ':'
                if header.name.starts_with(':') {
                    return HeadersParseResult::ProtocolError(format!(
                        "Invalid header name starts with colon: {}",
                        header.name
                    ));
                }
            }
        }

        // RFC 9113 §8.3.1: Required pseudo-headers for requests
        if !has_method {
            return HeadersParseResult::ProtocolError(
                "Missing required :method pseudo-header".to_string(),
            );
        }

        if !has_path {
            return HeadersParseResult::ProtocolError(
                "Missing required :path pseudo-header".to_string(),
            );
        }

        if !has_scheme {
            return HeadersParseResult::ProtocolError(
                "Missing required :scheme pseudo-header".to_string(),
            );
        }

        HeadersParseResult::Valid {
            stream_id: header.stream_id,
            headers,
            end_stream,
            end_headers,
        }
    }
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    /// Stream ID for HEADERS frame
    stream_id: u32,
    /// :method pseudo-header value
    method: String,
    /// :path pseudo-header value (the main test target)
    path: PathVariant,
    /// :scheme pseudo-header value
    scheme: String,
    /// :authority pseudo-header (optional)
    authority: Option<String>,
    /// Additional regular headers
    extra_headers: Vec<(String, String)>,
    /// Frame flags
    end_stream: bool,
    end_headers: bool,
    /// Whether to include forbidden characters in path
    include_forbidden_chars: bool,
    /// Whether to include CRLF in path
    include_crlf: bool,
    /// Whether to make path empty (should be invalid)
    make_path_empty: bool,
    /// Whether to duplicate pseudo-headers (should be invalid)
    duplicate_pseudo_headers: bool,
}

#[derive(Arbitrary, Debug, Clone)]
enum PathVariant {
    /// Valid paths
    Valid(ValidPath),
    /// Paths with control characters
    WithControlChars(String),
    /// Paths with CRLF injection
    WithCrlf(String),
    /// Custom invalid path
    Custom(String),
}

#[derive(Arbitrary, Debug, Clone)]
enum ValidPath {
    Root,                      // "/"
    Simple(String),            // "/simple/path"
    WithQuery(String, String), // "/path?query=value"
    Asterisk,                  // "*" (for OPTIONS)
}

impl std::fmt::Display for PathVariant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PathVariant::Valid(valid) => match valid {
                ValidPath::Root => f.write_str("/"),
                ValidPath::Simple(path) => write!(f, "/{}", path),
                ValidPath::WithQuery(path, query) => write!(f, "/{}?{}", path, query),
                ValidPath::Asterisk => f.write_str("*"),
            },
            PathVariant::WithControlChars(base) => {
                // Inject control characters
                write!(f, "/{}\x00\x01\x02{}", base, base)
            }
            PathVariant::WithCrlf(base) => {
                // Inject CRLF sequences
                write!(f, "/path\r\n{}\n\rmore", base)
            }
            PathVariant::Custom(path) => f.write_str(path),
        }
    }
}

fuzz_target!(|input: FuzzInput| {
    let mut parser = MockH2HeadersParser::new();

    // Ensure valid stream ID (non-zero, odd for client-initiated)
    let stream_id = if input.stream_id == 0 {
        1
    } else {
        (input.stream_id & 0x7FFF_FFFF) | 1 // Force odd
    };

    // Build headers list
    let mut headers = Vec::new();

    // Add required pseudo-headers
    headers.push(HeaderField::new(":method", &input.method));

    // Add :path header (the main test target)
    let path_value = if input.make_path_empty {
        String::new()
    } else {
        let mut path = input.path.to_string();

        if input.include_forbidden_chars {
            // Add various control characters
            path.push_str("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F");
            path.push_str("\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F");
            path.push('\x7F'); // DEL character
        }

        if input.include_crlf {
            // Add CRLF injection patterns
            path.push_str("\r\nHost: evil.com\r\n");
            path.push_str("\nSet-Cookie: evil=1\n");
        }

        path
    };

    headers.push(HeaderField::new(":path", &path_value));
    headers.push(HeaderField::new(":scheme", &input.scheme));

    // Add optional :authority
    if let Some(authority) = &input.authority {
        headers.push(HeaderField::new(":authority", authority));
    }

    // Add duplicates if requested (should cause protocol error)
    if input.duplicate_pseudo_headers {
        headers.push(HeaderField::new(":method", "GET"));
        headers.push(HeaderField::new(":path", "/duplicate"));
    }

    // Add regular headers
    for (name, value) in &input.extra_headers {
        headers.push(HeaderField::new(name, value));
    }

    // Create HEADERS frame
    let hpack_encoder = MockHpackDecoder;
    let encoded_headers = hpack_encoder.encode_headers(&headers);

    let mut flags = 0u8;
    if input.end_stream {
        flags |= END_STREAM_FLAG;
    }
    if input.end_headers {
        flags |= END_HEADERS_FLAG;
    }

    let frame_header = FrameHeader {
        length: encoded_headers.len() as u32,
        frame_type: HEADERS_FRAME_TYPE,
        flags,
        stream_id,
    };

    // Build complete frame
    let mut frame_bytes = Vec::new();
    frame_bytes.extend_from_slice(&frame_header.encode());
    frame_bytes.extend_from_slice(&encoded_headers);

    // Parse the frame
    let result = parser.parse_headers_frame(&frame_bytes);

    // Validate behavior based on :path content
    match &result {
        HeadersParseResult::Valid {
            headers: parsed_headers,
            ..
        } => {
            // Frame parsed successfully - validate this is expected

            // Should only be valid if:
            // 1. Path doesn't contain forbidden characters
            // 2. Path is not empty
            // 3. No duplicate pseudo-headers
            // 4. Path starts with '/' or is '*'

            if input.include_forbidden_chars {
                panic!(
                    "CRITICAL RFC VIOLATION: :path with control characters parsed as valid! \
                     Path: {:?}",
                    path_value
                );
            }

            if input.include_crlf {
                panic!(
                    "CRITICAL RFC VIOLATION: :path with CRLF characters parsed as valid! \
                     This enables header injection attacks. Path: {:?}",
                    path_value
                );
            }

            if input.make_path_empty {
                panic!(
                    "CRITICAL RFC VIOLATION: Empty :path pseudo-header parsed as valid! \
                     Per RFC 9113 §8.3.1, this should be PROTOCOL_ERROR"
                );
            }

            if input.duplicate_pseudo_headers {
                panic!(
                    "CRITICAL RFC VIOLATION: Duplicate pseudo-headers parsed as valid! \
                     This should be PROTOCOL_ERROR per RFC 9113 §8.3"
                );
            }

            // Verify :path value was preserved correctly
            let path_header = parsed_headers
                .iter()
                .find(|h| h.name == ":path")
                .expect("Parsed headers should contain :path");
            assert_eq!(
                path_header.value.as_str(),
                path_value.as_str(),
                "Parsed :path value should match encoded input"
            );

            if input.include_forbidden_chars || input.include_crlf {
                panic!("Forbidden characters should have been rejected");
            }
        }

        HeadersParseResult::ProtocolError(msg) => {
            // Expected for problematic :path values

            if input.include_forbidden_chars {
                assert!(
                    msg.contains("Control character") || msg.contains("Invalid :path"),
                    "Expected control character error for forbidden chars, got: {}",
                    msg
                );
            }

            if input.include_crlf {
                assert!(
                    msg.contains("CRLF")
                        || msg.contains("line break")
                        || msg.contains("Invalid :path"),
                    "Expected CRLF error for line breaks, got: {}",
                    msg
                );
            }

            if input.make_path_empty {
                assert!(
                    msg.contains("Empty :path") || msg.contains("Missing required :path"),
                    "Expected empty path error, got: {}",
                    msg
                );
            }

            if input.duplicate_pseudo_headers {
                assert!(
                    msg.contains("Duplicate") || msg.contains("pseudo-header"),
                    "Expected duplicate pseudo-header error, got: {}",
                    msg
                );
            }
        }

        HeadersParseResult::IncompleteFrame => {
            // Expected for truncated data
        }

        HeadersParseResult::InvalidStreamId => {
            // Should not happen with our stream ID logic
            panic!("Unexpected InvalidStreamId with stream_id: {}", stream_id);
        }

        HeadersParseResult::CompressionError => {
            // Expected for malformed HPACK data
        }
    }

    // CORE ASSERTION: Forbidden characters in :path must be rejected
    if input.include_forbidden_chars || input.include_crlf || input.make_path_empty {
        match &result {
            HeadersParseResult::ProtocolError(_) => {
                // Expected - good!
            }
            HeadersParseResult::Valid { .. } => {
                panic!(
                    "CRITICAL RFC 9113 VIOLATION: Invalid :path parsed as valid! \
                     forbidden_chars={}, crlf={}, empty={}, path={:?}",
                    input.include_forbidden_chars,
                    input.include_crlf,
                    input.make_path_empty,
                    path_value
                );
            }
            other => {
                panic!(
                    "Invalid :path should reject as ProtocolError for a locally encoded HEADERS frame: \
                     forbidden_chars={}, crlf={}, empty={}, path={:?}, result={:?}",
                    input.include_forbidden_chars,
                    input.include_crlf,
                    input.make_path_empty,
                    path_value,
                    other
                );
            }
        }
    }

    // Test specific attack patterns
    let attack_patterns = [
        "/\x00admin",                // Null byte injection
        "/\r\nHost: evil.com",       // CRLF injection
        "/\x01\x02\x03",             // Multiple control chars
        "",                          // Empty path
        "/\x7F",                     // DEL character
        "/\x09admin",                // Tab injection
        "/path\nSet-Cookie: evil=1", // Newline injection
    ];

    for &attack_pattern in &attack_patterns {
        let attack_headers = vec![
            HeaderField::new(":method", "GET"),
            HeaderField::new(":path", attack_pattern),
            HeaderField::new(":scheme", "https"),
        ];

        let attack_encoded = hpack_encoder.encode_headers(&attack_headers);
        let attack_frame_header = FrameHeader {
            length: attack_encoded.len() as u32,
            frame_type: HEADERS_FRAME_TYPE,
            flags: END_HEADERS_FLAG,
            stream_id: 3,
        };

        let mut attack_frame = Vec::new();
        attack_frame.extend_from_slice(&attack_frame_header.encode());
        attack_frame.extend_from_slice(&attack_encoded);

        let attack_result = parser.parse_headers_frame(&attack_frame);

        match attack_result {
            HeadersParseResult::Valid { .. } => {
                panic!(
                    "CRITICAL SECURITY ISSUE: Attack pattern in :path parsed as valid: {:?}",
                    attack_pattern
                );
            }
            HeadersParseResult::ProtocolError(_) => {
                // Expected - attack pattern correctly rejected
            }
            other => {
                panic!(
                    "Attack pattern in locally encoded :path should reject as ProtocolError: \
                     pattern={:?}, result={:?}",
                    attack_pattern, other
                );
            }
        }
    }
});
