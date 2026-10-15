#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

/// HTTP/2 frame header length per RFC 7540 §4.1
const FRAME_HEADER_LEN: usize = 9;

/// HTTP/2 HEADERS frame type per RFC 7540 §6.2
const HEADERS_FRAME_TYPE: u8 = 0x1;

/// HEADERS frame flags
const END_HEADERS_FLAG: u8 = 0x4;

/// Maximum port number per RFC 3986
const MAX_PORT_NUMBER: u32 = 65535;

/// Authority parsing result per RFC 3986 + RFC 7540
#[derive(Debug, PartialEq)]
enum AuthorityParseResult {
    /// Valid authority with parsed components
    Valid {
        host: String,
        port: Option<u16>,
        is_ipv6_literal: bool,
        is_idn_punycode: bool,
    },
    /// Protocol error - invalid format
    ProtocolError(String),
    /// Invalid port number
    InvalidPort(String),
    /// Invalid IPv6 literal format
    InvalidIpv6(String),
    /// Invalid IDN/punycode format
    InvalidIdn(String),
    /// Empty authority (may be valid in some contexts)
    Empty,
}

/// HTTP/2 header field per RFC 7540 §6.2
#[derive(Debug, Clone, PartialEq, Eq)]
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

    /// Validate :authority pseudo-header per RFC 7540 §8.3.1 + RFC 3986 §3.2
    ///
    /// Key rules from RFC 3986 §3.2 (Authority):
    /// authority = [ userinfo "@" ] host [ ":" port ]
    /// host = IP-literal / IPv4address / reg-name
    /// IP-literal = "[" ( IPv6address / IPvFuture ) "]"
    /// port = *DIGIT (0-65535)
    ///
    /// RFC 7540 §8.3.1: :authority MUST NOT include userinfo@
    fn validate_authority_header(&self) -> AuthorityParseResult {
        if self.name != ":authority" {
            return AuthorityParseResult::ProtocolError("Not an :authority header".to_string());
        }

        let authority = &self.value;

        // RFC 7540 §8.3.1: :authority may be omitted (e.g., for CONNECT requests)
        if authority.is_empty() {
            return AuthorityParseResult::Empty;
        }

        // RFC 7540 §8.3.1: :authority MUST NOT include userinfo
        if authority.contains('@') {
            return AuthorityParseResult::ProtocolError(
                "Authority contains forbidden userinfo component".to_string(),
            );
        }

        // Parse authority into host and port components
        let (host_part, port_part) = if authority.starts_with('[') {
            // IPv6 literal case: [IPv6address]:port
            if let Some(closing_bracket) = authority.find(']') {
                let ipv6_part = &authority[..closing_bracket + 1];
                let remaining = &authority[closing_bracket + 1..];

                if remaining.is_empty() {
                    // Just IPv6, no port
                    (ipv6_part, None)
                } else if let Some(port) = remaining.strip_prefix(':') {
                    // IPv6 + port
                    (ipv6_part, Some(port))
                } else {
                    return AuthorityParseResult::InvalidIpv6(
                        "Invalid characters after IPv6 literal".to_string(),
                    );
                }
            } else {
                return AuthorityParseResult::InvalidIpv6(
                    "IPv6 literal missing closing bracket".to_string(),
                );
            }
        } else {
            // Regular host:port or just host
            if let Some(colon_pos) = authority.rfind(':') {
                // Check if this is actually a port (not part of IPv6)
                let potential_port = &authority[colon_pos + 1..];
                if potential_port.chars().all(|c| c.is_ascii_digit()) {
                    (&authority[..colon_pos], Some(potential_port))
                } else {
                    // Colon but no valid port - treat as part of host
                    (authority.as_str(), None)
                }
            } else {
                (authority.as_str(), None)
            }
        };

        // Validate IPv6 literal format if present
        let is_ipv6_literal = host_part.starts_with('[') && host_part.ends_with(']');
        if is_ipv6_literal {
            let ipv6_content = &host_part[1..host_part.len() - 1];

            // Basic IPv6 format validation
            if ipv6_content.is_empty() {
                return AuthorityParseResult::InvalidIpv6("Empty IPv6 literal".to_string());
            }

            // Check for valid IPv6 characters: hexdigit, colon, dot (for IPv4-embedded)
            if !ipv6_content
                .chars()
                .all(|c| c.is_ascii_hexdigit() || c == ':' || c == '.')
            {
                return AuthorityParseResult::InvalidIpv6(format!(
                    "Invalid characters in IPv6 literal: {}",
                    ipv6_content
                ));
            }

            // Check for too many consecutive colons (more than 2 is invalid)
            if ipv6_content.contains(":::") {
                return AuthorityParseResult::InvalidIpv6(
                    "Too many consecutive colons in IPv6".to_string(),
                );
            }

            // Basic structural validation - should not start or end with single colon
            // unless it's part of :: compression
            if (ipv6_content.starts_with(':') && !ipv6_content.starts_with("::"))
                || (ipv6_content.ends_with(':') && !ipv6_content.ends_with("::"))
            {
                return AuthorityParseResult::InvalidIpv6(
                    "IPv6 address cannot start/end with single colon".to_string(),
                );
            }
        }

        // Check for IDN punycode
        let is_idn_punycode = host_part.to_lowercase().contains("xn--");

        // Validate IDN punycode format if present
        if is_idn_punycode && !is_ipv6_literal {
            // Basic punycode validation
            for label in host_part.split('.') {
                if label.to_lowercase().starts_with("xn--") {
                    let punycode_part = &label[4..]; // Remove "xn--" prefix

                    // Punycode should contain only ASCII letters, digits, and hyphens
                    if !punycode_part
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '-')
                    {
                        return AuthorityParseResult::InvalidIdn(format!(
                            "Invalid punycode format in label: {}",
                            label
                        ));
                    }

                    // Punycode cannot be empty after xn-- prefix
                    if punycode_part.is_empty() {
                        return AuthorityParseResult::InvalidIdn(
                            "Empty punycode after xn-- prefix".to_string(),
                        );
                    }

                    // Punycode cannot start or end with hyphen
                    if punycode_part.starts_with('-') || punycode_part.ends_with('-') {
                        return AuthorityParseResult::InvalidIdn(
                            "Punycode cannot start or end with hyphen".to_string(),
                        );
                    }
                }
            }
        }

        // Validate regular hostname format if not IPv6
        if !is_ipv6_literal {
            // Check for valid hostname characters per RFC 3986
            if !host_part
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
            {
                return AuthorityParseResult::ProtocolError(format!(
                    "Invalid characters in hostname: {}",
                    host_part
                ));
            }

            // Hostname cannot start or end with hyphen
            if host_part.starts_with('-') || host_part.ends_with('-') {
                return AuthorityParseResult::ProtocolError(
                    "Hostname cannot start or end with hyphen".to_string(),
                );
            }

            // Check for consecutive dots
            if host_part.contains("..") {
                return AuthorityParseResult::ProtocolError(
                    "Hostname cannot contain consecutive dots".to_string(),
                );
            }

            // Hostname cannot start or end with dot
            if host_part.starts_with('.') || host_part.ends_with('.') {
                return AuthorityParseResult::ProtocolError(
                    "Hostname cannot start or end with dot".to_string(),
                );
            }
        }

        // Validate port number if present
        let parsed_port = if let Some(port_str) = port_part {
            if port_str.is_empty() {
                return AuthorityParseResult::InvalidPort("Empty port number".to_string());
            }

            // Check for leading zeros (not allowed except for "0")
            if port_str.len() > 1 && port_str.starts_with('0') {
                return AuthorityParseResult::InvalidPort(
                    "Port number cannot have leading zeros".to_string(),
                );
            }

            match port_str.parse::<u32>() {
                Ok(port_num) => {
                    if port_num > MAX_PORT_NUMBER {
                        return AuthorityParseResult::InvalidPort(format!(
                            "Port number {} exceeds maximum {}",
                            port_num, MAX_PORT_NUMBER
                        ));
                    }
                    Some(port_num as u16)
                }
                Err(_) => {
                    return AuthorityParseResult::InvalidPort(format!(
                        "Invalid port number: {}",
                        port_str
                    ));
                }
            }
        } else {
            None
        };

        AuthorityParseResult::Valid {
            host: host_part.to_string(),
            port: parsed_port,
            is_ipv6_literal,
            is_idn_punycode,
        }
    }
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

/// Mock HPACK encoder/decoder for testing
struct MockHpackProcessor;

impl MockHpackProcessor {
    fn encode_headers(&self, headers: &[HeaderField]) -> Vec<u8> {
        let mut encoded = Vec::new();

        for header in headers {
            // Simplified HPACK encoding - literal header field
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
        authority_result: Option<AuthorityParseResult>,
    },
    ProtocolError(String),
    IncompleteFrame,
}

/// Mock HTTP/2 HEADERS frame parser with :authority validation
struct MockH2AuthorityParser {
    hpack_processor: MockHpackProcessor,
}

impl MockH2AuthorityParser {
    fn new() -> Self {
        Self {
            hpack_processor: MockHpackProcessor,
        }
    }

    fn parse_headers_frame(&self, buf: &[u8]) -> HeadersParseResult {
        // Simplified frame parsing - assume HEADERS frame format is correct
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

        // Find and validate :authority header
        let authority_result = headers
            .iter()
            .find(|h| h.name == ":authority")
            .map(|h| h.validate_authority_header());

        // Check for protocol errors in authority validation
        if let Some(AuthorityParseResult::ProtocolError(ref msg)) = authority_result {
            return HeadersParseResult::ProtocolError(format!("Invalid :authority: {}", msg));
        }

        if let Some(AuthorityParseResult::InvalidPort(ref msg)) = authority_result {
            return HeadersParseResult::ProtocolError(format!("Invalid :authority port: {}", msg));
        }

        if let Some(AuthorityParseResult::InvalidIpv6(ref msg)) = authority_result {
            return HeadersParseResult::ProtocolError(format!("Invalid :authority IPv6: {}", msg));
        }

        if let Some(AuthorityParseResult::InvalidIdn(ref msg)) = authority_result {
            return HeadersParseResult::ProtocolError(format!("Invalid :authority IDN: {}", msg));
        }

        HeadersParseResult::Valid {
            headers,
            authority_result,
        }
    }
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    /// Stream ID for HEADERS frame
    stream_id: u32,
    /// :authority pseudo-header value (main test target)
    authority: AuthorityVariant,
    /// Additional headers
    extra_headers: Vec<(String, String)>,
    /// Whether to test IPv6 edge cases
    test_ipv6_edge_cases: bool,
    /// Whether to test IDN/punycode edge cases
    test_idn_edge_cases: bool,
    /// Whether to test port number edge cases
    test_port_edge_cases: bool,
}

#[derive(Arbitrary, Debug, Clone)]
enum AuthorityVariant {
    /// Valid authority forms
    Valid(ValidAuthority),
    /// IPv6 literals with various formats
    Ipv6Literal(String),
    /// IDN punycode domains
    IdnPunycode(String),
    /// Invalid port numbers
    InvalidPort(String, String), // host, port
    /// Custom authority string
    Custom(String),
}

#[derive(Arbitrary, Debug, Clone)]
enum ValidAuthority {
    /// Simple hostname
    Hostname(String),
    /// Hostname with port
    HostnamePort(String, u16),
    /// IPv6 literal without port
    Ipv6Simple(String),
    /// IPv6 literal with port
    Ipv6WithPort(String, u16),
    /// IDN punycode domain
    IdnDomain(String),
    /// IDN with port
    IdnDomainPort(String, u16),
    /// Empty (valid for CONNECT)
    Empty,
}

impl std::fmt::Display for AuthorityVariant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthorityVariant::Valid(valid) => match valid {
                ValidAuthority::Hostname(host) => f.write_str(host),
                ValidAuthority::HostnamePort(host, port) => write!(f, "{}:{}", host, port),
                ValidAuthority::Ipv6Simple(addr) => write!(f, "[{}]", addr),
                ValidAuthority::Ipv6WithPort(addr, port) => write!(f, "[{}]:{}", addr, port),
                ValidAuthority::IdnDomain(domain) => f.write_str(domain),
                ValidAuthority::IdnDomainPort(domain, port) => write!(f, "{}:{}", domain, port),
                ValidAuthority::Empty => Ok(()),
            },
            AuthorityVariant::Ipv6Literal(literal) => f.write_str(literal),
            AuthorityVariant::IdnPunycode(punycode) => f.write_str(punycode),
            AuthorityVariant::InvalidPort(host, port) => write!(f, "{}:{}", host, port),
            AuthorityVariant::Custom(custom) => f.write_str(custom),
        }
    }
}

fuzz_target!(|input: FuzzInput| {
    let parser = MockH2AuthorityParser::new();

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
    headers.push(HeaderField::new(":path", "/"));
    headers.push(HeaderField::new(":scheme", "https"));

    // Add :authority header (the main test target)
    let mut authority_value = input.authority.to_string();

    // Add specific test cases for edge conditions
    if input.test_ipv6_edge_cases {
        // Test various IPv6 edge cases
        let ipv6_test_cases = [
            "[::1]",                 // Loopback
            "[::1]:8080",            // Loopback with port
            "[2001:db8::1]",         // Documentation prefix
            "[2001:db8::1]:443",     // With port
            "[::ffff:192.0.2.1]",    // IPv4-mapped IPv6
            "[::ffff:192.0.2.1]:80", // IPv4-mapped with port
            "[",                     // Invalid - no closing bracket
            "[::1",                  // Invalid - no closing bracket
            "[::1]extra",            // Invalid - extra chars after bracket
            "[:::1]",                // Invalid - too many colons
            "[:1]",                  // Invalid - incomplete address
            "[::1]:99999",           // Invalid - port too large
        ];

        authority_value = ipv6_test_cases[stream_id as usize % ipv6_test_cases.len()].to_string();
    }

    if input.test_idn_edge_cases {
        // Test IDN punycode edge cases
        let idn_test_cases = [
            "xn--nxasmq6b.com",       // Valid punycode (Chinese domain)
            "xn--fsq.com",            // Valid short punycode
            "sub.xn--nxasmq6b.com",   // Valid subdomain with punycode
            "xn--nxasmq6b.com:443",   // Valid punycode with port
            "xn--.com",               // Invalid - empty punycode
            "xn---.com",              // Invalid - starts with hyphen
            "xn--abc-.com",           // Invalid - ends with hyphen
            "xn--ab@c.com",           // Invalid - invalid chars
            "xn--123:8080",           // Valid punycode with port
            "normal.xn--example.org", // Mixed normal/punycode
        ];

        authority_value = idn_test_cases[stream_id as usize % idn_test_cases.len()].to_string();
    }

    if input.test_port_edge_cases {
        // Test port number edge cases
        let port_test_cases = [
            "example.com:80",    // Valid standard port
            "example.com:443",   // Valid HTTPS port
            "example.com:8080",  // Valid high port
            "example.com:65535", // Valid maximum port
            "example.com:65536", // Invalid - port too large
            "example.com:99999", // Invalid - port too large
            "example.com:0",     // Edge case - port 0
            "example.com:00080", // Invalid - leading zeros
            "example.com:",      // Invalid - empty port
            "example.com:abc",   // Invalid - non-numeric port
            "[::1]:65535",       // Valid IPv6 with max port
            "[::1]:65536",       // Invalid IPv6 with too-large port
        ];

        authority_value = port_test_cases[stream_id as usize % port_test_cases.len()].to_string();
    }

    headers.push(HeaderField::new(":authority", &authority_value));

    // Add extra headers
    for (name, value) in &input.extra_headers {
        headers.push(HeaderField::new(name, value));
    }

    // Create HEADERS frame
    let encoded_headers = parser.hpack_processor.encode_headers(&headers);

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

    // Validate behavior based on authority format
    match result {
        HeadersParseResult::Valid {
            authority_result: Some(auth_result),
            ..
        } => {
            match auth_result {
                AuthorityParseResult::Valid {
                    host: _,
                    port,
                    is_ipv6_literal,
                    is_idn_punycode,
                } => {
                    // Authority parsed successfully - validate expectations

                    if input.test_port_edge_cases && authority_value.contains(":65536") {
                        panic!(
                            "CRITICAL RFC VIOLATION: Port 65536 parsed as valid! \
                             Maximum port is 65535 per RFC 3986"
                        );
                    }

                    if input.test_port_edge_cases && authority_value.contains(":99999") {
                        panic!(
                            "CRITICAL RFC VIOLATION: Port 99999 parsed as valid! \
                             Maximum port is 65535 per RFC 3986"
                        );
                    }

                    if input.test_ipv6_edge_cases && authority_value.contains("[:::") {
                        panic!(
                            "CRITICAL RFC VIOLATION: Invalid IPv6 with triple colon parsed as valid! \
                             Authority: {}",
                            authority_value
                        );
                    }

                    if input.test_ipv6_edge_cases
                        && (authority_value == "["
                            || authority_value == "[::1"
                            || authority_value.contains("]extra"))
                    {
                        panic!(
                            "CRITICAL RFC VIOLATION: Malformed IPv6 literal parsed as valid! \
                             Authority: {}",
                            authority_value
                        );
                    }

                    if input.test_idn_edge_cases && authority_value.contains("xn--.") {
                        panic!(
                            "CRITICAL RFC VIOLATION: Invalid punycode (empty after xn--) parsed as valid! \
                             Authority: {}",
                            authority_value
                        );
                    }

                    // Verify parsed components match expectations
                    if is_ipv6_literal {
                        assert!(
                            authority_value.starts_with('[') && authority_value.contains(']'),
                            "IPv6 literal flag set but authority format doesn't match: {}",
                            authority_value
                        );
                    }

                    if is_idn_punycode {
                        assert!(
                            authority_value.to_lowercase().contains("xn--"),
                            "IDN punycode flag set but authority doesn't contain xn--: {}",
                            authority_value
                        );
                    }

                    if let Some(parsed_port) = port {
                        assert!(
                            authority_value.contains(&format!(":{}", parsed_port)),
                            "Parsed port {} doesn't match authority format: {}",
                            parsed_port,
                            authority_value
                        );
                    }
                }

                AuthorityParseResult::Empty => {
                    // Empty authority is valid for CONNECT requests
                    assert!(
                        authority_value.is_empty(),
                        "Empty authority result but value is not empty: {}",
                        authority_value
                    );
                }

                AuthorityParseResult::ProtocolError(_)
                | AuthorityParseResult::InvalidPort(_)
                | AuthorityParseResult::InvalidIpv6(_)
                | AuthorityParseResult::InvalidIdn(_) => {
                    panic!(
                        "invalid authority result should be surfaced as HeadersParseResult::ProtocolError: {:?}",
                        auth_result
                    );
                }
            }
        }

        HeadersParseResult::ProtocolError(msg) => {
            // Expected for invalid authority formats

            // Verify specific error cases are caught
            if authority_value.contains("@") {
                assert!(
                    msg.to_lowercase().contains("userinfo")
                        || msg.to_lowercase().contains("forbidden"),
                    "Expected userinfo error for authority with @, got: {}",
                    msg
                );
            }

            if authority_value.contains(":65536") || authority_value.contains(":99999") {
                assert!(
                    msg.to_lowercase().contains("port")
                        && (msg.contains("65535")
                            || msg.contains("maximum")
                            || msg.contains("exceeds")),
                    "Expected port range error for large port, got: {}",
                    msg
                );
            }

            if authority_value.starts_with('[') && !authority_value.contains(']') {
                assert!(
                    msg.to_lowercase().contains("ipv6") || msg.to_lowercase().contains("bracket"),
                    "Expected IPv6 bracket error, got: {}",
                    msg
                );
            }

            if authority_value.contains(":::") {
                assert!(
                    msg.to_lowercase().contains("ipv6") || msg.to_lowercase().contains("colon"),
                    "Expected IPv6 colon error for triple colon, got: {}",
                    msg
                );
            }

            if authority_value.contains("xn--.") || authority_value.contains("xn---.") {
                assert!(
                    msg.to_lowercase().contains("idn")
                        || msg.to_lowercase().contains("punycode")
                        || msg.to_lowercase().contains("hyphen"),
                    "Expected IDN/punycode error for malformed punycode, got: {}",
                    msg
                );
            }
        }

        HeadersParseResult::Valid {
            authority_result: None,
            ..
        } => {
            // No :authority header present - acceptable for some request types
        }

        HeadersParseResult::IncompleteFrame => {
            // Expected for malformed frames
        }
    }

    // Test specific known invalid patterns
    let invalid_patterns = [
        "user:pass@example.com", // Userinfo forbidden
        "example.com:65536",     // Port too large
        "example.com:999999",    // Port way too large
        "[::1",                  // Missing closing bracket
        "[::1]extra",            // Extra chars after IPv6
        "[:::1]",                // Too many colons
        "xn--.com",              // Empty punycode
        "xn---.com",             // Punycode starts with hyphen
        "example..com",          // Double dots
        ".example.com",          // Starts with dot
        "example.com.",          // Ends with dot
        "example.com:00080",     // Leading zero in port
        "example.com:",          // Empty port
        "example.com:abc",       // Non-numeric port
    ];

    for &invalid_pattern in &invalid_patterns {
        let test_headers = vec![
            HeaderField::new(":method", "GET"),
            HeaderField::new(":path", "/"),
            HeaderField::new(":scheme", "https"),
            HeaderField::new(":authority", invalid_pattern),
        ];

        let test_encoded = parser.hpack_processor.encode_headers(&test_headers);
        let test_frame_header = FrameHeader {
            length: test_encoded.len() as u32,
            frame_type: HEADERS_FRAME_TYPE,
            flags: END_HEADERS_FLAG,
            stream_id: 5,
        };

        let mut test_frame = Vec::new();
        test_frame.extend_from_slice(&test_frame_header.encode());
        test_frame.extend_from_slice(&test_encoded);

        let test_result = parser.parse_headers_frame(&test_frame);

        match test_result {
            HeadersParseResult::Valid {
                authority_result: Some(AuthorityParseResult::Valid { .. }),
                ..
            } => {
                panic!(
                    "CRITICAL SECURITY ISSUE: Invalid authority pattern parsed as valid: '{}'",
                    invalid_pattern
                );
            }
            HeadersParseResult::ProtocolError(_) => {
                // Expected - invalid pattern correctly rejected
            }
            HeadersParseResult::Valid {
                authority_result: Some(auth_result),
                ..
            } => {
                panic!(
                    "invalid authority pattern produced non-valid authority result instead of protocol error: pattern='{}', result={:?}",
                    invalid_pattern, auth_result
                );
            }
            HeadersParseResult::Valid {
                authority_result: None,
                ..
            } => {
                panic!(
                    "invalid authority pattern lost the :authority header: '{}'",
                    invalid_pattern
                );
            }
            HeadersParseResult::IncompleteFrame => {
                panic!(
                    "complete invalid-authority HEADERS frame parsed as incomplete: '{}'",
                    invalid_pattern
                );
            }
        }
    }

    // Test specific valid patterns to ensure they're not over-rejected
    let valid_patterns = [
        "example.com",
        "example.com:443",
        "sub.example.com:8080",
        "[::1]",
        "[::1]:8080",
        "[2001:db8::1]",
        "[2001:db8::1]:443",
        "xn--nxasmq6b.com",
        "xn--fsq.com:443",
        "", // Empty authority (valid for CONNECT)
    ];

    for &valid_pattern in &valid_patterns {
        let mut test_headers = vec![
            HeaderField::new(":method", "GET"),
            HeaderField::new(":path", "/"),
            HeaderField::new(":scheme", "https"),
        ];

        // Only add :authority if not empty
        if !valid_pattern.is_empty() {
            test_headers.push(HeaderField::new(":authority", valid_pattern));
        }

        let test_encoded = parser.hpack_processor.encode_headers(&test_headers);
        let test_frame_header = FrameHeader {
            length: test_encoded.len() as u32,
            frame_type: HEADERS_FRAME_TYPE,
            flags: END_HEADERS_FLAG,
            stream_id: 7,
        };

        let mut test_frame = Vec::new();
        test_frame.extend_from_slice(&test_frame_header.encode());
        test_frame.extend_from_slice(&test_encoded);

        let test_result = parser.parse_headers_frame(&test_frame);

        match test_result {
            HeadersParseResult::Valid { .. } => {
                // Expected - valid pattern correctly accepted
            }
            HeadersParseResult::ProtocolError(msg) => {
                panic!(
                    "valid authority pattern should not be rejected: pattern='{}', error={}",
                    valid_pattern, msg
                );
            }
            HeadersParseResult::IncompleteFrame => {
                panic!(
                    "complete valid-authority HEADERS frame parsed as incomplete: '{}'",
                    valid_pattern
                );
            }
        }
    }
});
