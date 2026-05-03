#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};
use std::collections::{HashMap, HashSet};

/// HTTP/2 request pseudo-header duplicate validation testing.
/// Per RFC 7540 §8.1.2.1, all pseudo-headers (:method, :path, :scheme, :authority)
/// must appear exactly once. Duplicates MUST be rejected as PROTOCOL_ERROR.
///
/// Tests:
/// - Duplicate :method pseudo-headers (primary case)
/// - Duplicate :path, :scheme, :authority pseudo-headers
/// - Multiple types of duplicates in same request
/// - Pseudo-headers mixed with regular headers
/// - Missing required pseudo-headers
/// - Unknown pseudo-headers
/// - Case sensitivity (must be lowercase)
/// - Pseudo-headers appearing after regular headers (invalid order)

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    /// HTTP/2 request headers (mix of pseudo and regular)
    headers: Vec<HeaderEntry>,
    /// Stream ID for the request
    stream_id: u32,
}

#[derive(Arbitrary, Debug, Clone)]
struct HeaderEntry {
    /// Header name (may be pseudo-header starting with ':')
    name: String,
    /// Header value
    value: String,
}

/// Known pseudo-headers for HTTP/2 requests
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
enum PseudoHeader {
    Method,
    Path,
    Scheme,
    Authority,
    Unknown(String),
}

impl PseudoHeader {
    fn from_name(name: &str) -> Option<Self> {
        match name {
            ":method" => Some(Self::Method),
            ":path" => Some(Self::Path),
            ":scheme" => Some(Self::Scheme),
            ":authority" => Some(Self::Authority),
            other if other.starts_with(':') => Some(Self::Unknown(other.to_string())),
            _ => None,
        }
    }

    fn is_required(&self) -> bool {
        matches!(self, Self::Method | Self::Path | Self::Scheme)
    }

    fn name(&self) -> &str {
        match self {
            Self::Method => ":method",
            Self::Path => ":path",
            Self::Scheme => ":scheme",
            Self::Authority => ":authority",
            Self::Unknown(name) => name,
        }
    }
}

/// Mock HTTP/2 request header parser with pseudo-header validation
struct MockH2RequestParser {
    pseudo_headers: HashMap<PseudoHeader, String>,
    regular_headers: HashMap<String, Vec<String>>,
    seen_regular_header: bool,
    errors: Vec<String>,
}

impl MockH2RequestParser {
    fn new() -> Self {
        Self {
            pseudo_headers: HashMap::new(),
            regular_headers: HashMap::new(),
            seen_regular_header: false,
            errors: Vec::new(),
        }
    }

    /// Parse request headers with pseudo-header validation
    fn parse_request_headers(&mut self, headers: &[HeaderEntry]) -> Result<(), String> {
        for header in headers {
            self.process_header(&header.name, &header.value)?;
        }

        // Validate required pseudo-headers are present
        self.validate_required_pseudo_headers()?;

        Ok(())
    }

    /// Process individual header
    fn process_header(&mut self, name: &str, value: &str) -> Result<(), String> {
        // Check for empty header name
        if name.is_empty() {
            return Err("PROTOCOL_ERROR: empty header name".into());
        }

        // Check if this is a pseudo-header
        if let Some(pseudo) = PseudoHeader::from_name(name) {
            // Pseudo-header validation
            return self.process_pseudo_header(pseudo, name, value);
        }

        // Regular header
        self.seen_regular_header = true;

        // Validate header name (no uppercase, no colons except for pseudo-headers)
        if name.chars().any(|c| c.is_ascii_uppercase()) {
            return Err(format!("PROTOCOL_ERROR: header name contains uppercase: {}", name));
        }

        if name.contains(':') {
            return Err(format!("PROTOCOL_ERROR: regular header name contains colon: {}", name));
        }

        // Store regular header (multiple values allowed)
        self.regular_headers
            .entry(name.to_string())
            .or_insert_with(Vec::new)
            .push(value.to_string());

        Ok(())
    }

    /// Process pseudo-header with validation
    fn process_pseudo_header(&mut self, pseudo: PseudoHeader, name: &str, value: &str) -> Result<(), String> {
        // RFC 7540 §8.1.2.1: pseudo-headers must appear before regular headers
        if self.seen_regular_header {
            return Err(format!(
                "PROTOCOL_ERROR: pseudo-header {} after regular header", name
            ));
        }

        // Check for case sensitivity - pseudo-headers must be lowercase
        if name != name.to_lowercase() {
            return Err(format!(
                "PROTOCOL_ERROR: pseudo-header not lowercase: {}", name
            ));
        }

        // Check for duplicate pseudo-header
        if self.pseudo_headers.contains_key(&pseudo) {
            return Err(format!(
                "PROTOCOL_ERROR: duplicate pseudo-header {}", name
            ));
        }

        // Validate pseudo-header values
        self.validate_pseudo_header_value(&pseudo, value)?;

        // Store pseudo-header
        self.pseudo_headers.insert(pseudo, value.to_string());

        Ok(())
    }

    /// Validate pseudo-header values
    fn validate_pseudo_header_value(&mut self, pseudo: &PseudoHeader, value: &str) -> Result<(), String> {
        match pseudo {
            PseudoHeader::Method => {
                // Common HTTP methods
                if value.is_empty() {
                    return Err("PROTOCOL_ERROR: empty :method value".into());
                }
                // Method should be uppercase, but we don't enforce specific methods
                if value.chars().any(|c| !c.is_ascii_alphabetic()) {
                    self.errors.push(format!("Unusual :method value: {}", value));
                }
            }
            PseudoHeader::Path => {
                if value.is_empty() {
                    return Err("PROTOCOL_ERROR: empty :path value".into());
                }
                // Path must start with '/' or be '*' for OPTIONS
                if !value.starts_with('/') && value != "*" {
                    return Err(format!("PROTOCOL_ERROR: invalid :path value: {}", value));
                }
            }
            PseudoHeader::Scheme => {
                if value.is_empty() {
                    return Err("PROTOCOL_ERROR: empty :scheme value".into());
                }
                // Common schemes
                if !["http", "https"].contains(&value) {
                    self.errors.push(format!("Uncommon :scheme value: {}", value));
                }
            }
            PseudoHeader::Authority => {
                // Authority is optional for HTTP/2, but if present must be valid
                if value.is_empty() {
                    self.errors.push("Empty :authority value".to_string());
                }
                // Basic validation - should contain host, optionally port
                if value.contains(' ') {
                    return Err("PROTOCOL_ERROR: :authority contains space".into());
                }
            }
            PseudoHeader::Unknown(name) => {
                // Unknown pseudo-headers should be ignored per HTTP/2 spec
                self.errors.push(format!("Unknown pseudo-header: {}", name));
            }
        }

        Ok(())
    }

    /// Validate that all required pseudo-headers are present
    fn validate_required_pseudo_headers(&mut self) -> Result<(), String> {
        let required = [PseudoHeader::Method, PseudoHeader::Path, PseudoHeader::Scheme];

        for required_header in &required {
            if !self.pseudo_headers.contains_key(required_header) {
                return Err(format!(
                    "PROTOCOL_ERROR: missing required pseudo-header {}",
                    required_header.name()
                ));
            }
        }

        Ok(())
    }

    /// Get parsed headers for inspection
    fn get_pseudo_headers(&self) -> &HashMap<PseudoHeader, String> {
        &self.pseudo_headers
    }

    /// Get error messages
    fn get_errors(&self) -> &[String] {
        &self.errors
    }
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let input: FuzzInput = match u.arbitrary() {
        Ok(input) => input,
        Err(_) => return, // Skip invalid inputs
    };

    // Limit header count to prevent timeouts
    if input.headers.len() > 50 {
        return;
    }

    // Limit header name/value lengths
    if input.headers.iter().any(|h| h.name.len() > 200 || h.value.len() > 1000) {
        return;
    }

    // Ensure valid stream ID for requests (must be odd and > 0)
    if input.stream_id == 0 || input.stream_id % 2 == 0 || input.stream_id > 1_000_000 {
        return;
    }

    let mut parser = MockH2RequestParser::new();
    let result = parser.parse_request_headers(&input.headers);

    // Test 1: Detect duplicate pseudo-headers
    let mut pseudo_header_counts: HashMap<String, usize> = HashMap::new();
    for header in &input.headers {
        if header.name.starts_with(':') {
            *pseudo_header_counts.entry(header.name.clone()).or_insert(0) += 1;
        }
    }

    let has_duplicate_pseudo = pseudo_header_counts.values().any(|&count| count > 1);

    if has_duplicate_pseudo {
        assert!(result.is_err(),
            "Duplicate pseudo-headers should be rejected");

        if let Err(error_msg) = &result {
            assert!(error_msg.contains("duplicate pseudo-header") && error_msg.contains("PROTOCOL_ERROR"),
                "Duplicate pseudo-header error should be clear: {}", error_msg);
        }
        return; // No further tests for duplicate error case
    }

    // Test 2: Detect pseudo-headers after regular headers
    let mut seen_regular = false;
    let mut pseudo_after_regular = false;

    for header in &input.headers {
        if header.name.starts_with(':') {
            if seen_regular {
                pseudo_after_regular = true;
                break;
            }
        } else if !header.name.is_empty() {
            seen_regular = true;
        }
    }

    if pseudo_after_regular {
        assert!(result.is_err(),
            "Pseudo-headers after regular headers should be rejected");

        if let Err(error_msg) = &result {
            assert!(error_msg.contains("pseudo-header") && error_msg.contains("after regular"),
                "Ordering error should be clear: {}", error_msg);
        }
        return;
    }

    // Test 3: Check for case sensitivity violations
    let has_uppercase_pseudo = input.headers.iter().any(|h| {
        h.name.starts_with(':') && h.name != h.name.to_lowercase()
    });

    if has_uppercase_pseudo {
        assert!(result.is_err(),
            "Uppercase pseudo-headers should be rejected");

        if let Err(error_msg) = &result {
            assert!(error_msg.contains("not lowercase"),
                "Case sensitivity error should mention lowercase: {}", error_msg);
        }
        return;
    }

    // Test 4: Check for empty header names
    if input.headers.iter().any(|h| h.name.is_empty()) {
        assert!(result.is_err(),
            "Empty header names should be rejected");
        return;
    }

    // Test 5: Check for invalid pseudo-header values
    let has_invalid_values = input.headers.iter().any(|h| {
        match h.name.as_str() {
            ":method" => h.value.is_empty(),
            ":path" => h.value.is_empty() || (!h.value.starts_with('/') && h.value != "*"),
            ":scheme" => h.value.is_empty(),
            ":authority" => h.value.contains(' '),
            _ => false,
        }
    });

    if has_invalid_values {
        assert!(result.is_err(),
            "Invalid pseudo-header values should be rejected");
        return;
    }

    // Test 6: Check for required pseudo-headers
    let required_headers = [":method", ":path", ":scheme"];
    let missing_required = required_headers.iter().any(|&required| {
        !input.headers.iter().any(|h| h.name == required)
    });

    if missing_required {
        assert!(result.is_err(),
            "Missing required pseudo-headers should be rejected");

        if let Err(error_msg) = &result {
            assert!(error_msg.contains("missing required pseudo-header"),
                "Missing header error should be clear: {}", error_msg);
        }
        return;
    }

    // Test 7: Valid requests should succeed
    if result.is_err() {
        // Check for other validation errors
        if let Err(error_msg) = &result {
            // Regular header name validation
            if input.headers.iter().any(|h| {
                !h.name.starts_with(':') && (
                    h.name.chars().any(|c| c.is_ascii_uppercase()) ||
                    h.name.contains(':')
                )
            }) {
                assert!(error_msg.contains("header name") || error_msg.contains("uppercase") || error_msg.contains("colon"),
                    "Regular header validation error: {}", error_msg);
            } else {
                panic!("Unexpected parse error for apparently valid headers: {}", error_msg);
            }
        }
    } else {
        // Successful parse - verify structure
        let pseudo_headers = parser.get_pseudo_headers();
        assert!(pseudo_headers.contains_key(&PseudoHeader::Method),
            "Parsed headers should contain :method");
        assert!(pseudo_headers.contains_key(&PseudoHeader::Path),
            "Parsed headers should contain :path");
        assert!(pseudo_headers.contains_key(&PseudoHeader::Scheme),
            "Parsed headers should contain :scheme");
    }
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_duplicate_method_header() {
        let headers = vec![
            HeaderEntry { name: ":method".to_string(), value: "GET".to_string() },
            HeaderEntry { name: ":path".to_string(), value: "/".to_string() },
            HeaderEntry { name: ":scheme".to_string(), value: "https".to_string() },
            HeaderEntry { name: ":method".to_string(), value: "POST".to_string() }, // Duplicate
        ];

        let mut parser = MockH2RequestParser::new();
        let result = parser.parse_request_headers(&headers);

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("duplicate pseudo-header :method"));
    }

    #[test]
    fn test_duplicate_path_header() {
        let headers = vec![
            HeaderEntry { name: ":method".to_string(), value: "GET".to_string() },
            HeaderEntry { name: ":path".to_string(), value: "/".to_string() },
            HeaderEntry { name: ":path".to_string(), value: "/other".to_string() }, // Duplicate
            HeaderEntry { name: ":scheme".to_string(), value: "https".to_string() },
        ];

        let mut parser = MockH2RequestParser::new();
        let result = parser.parse_request_headers(&headers);

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("duplicate pseudo-header :path"));
    }

    #[test]
    fn test_valid_request_headers() {
        let headers = vec![
            HeaderEntry { name: ":method".to_string(), value: "GET".to_string() },
            HeaderEntry { name: ":path".to_string(), value: "/api/v1/test".to_string() },
            HeaderEntry { name: ":scheme".to_string(), value: "https".to_string() },
            HeaderEntry { name: ":authority".to_string(), value: "example.com".to_string() },
            HeaderEntry { name: "user-agent".to_string(), value: "test-client".to_string() },
        ];

        let mut parser = MockH2RequestParser::new();
        let result = parser.parse_request_headers(&headers);

        assert!(result.is_ok(), "Valid headers should parse successfully");
    }

    #[test]
    fn test_pseudo_header_after_regular() {
        let headers = vec![
            HeaderEntry { name: ":method".to_string(), value: "GET".to_string() },
            HeaderEntry { name: "user-agent".to_string(), value: "test".to_string() }, // Regular header
            HeaderEntry { name: ":path".to_string(), value: "/".to_string() }, // Pseudo after regular
            HeaderEntry { name: ":scheme".to_string(), value: "https".to_string() },
        ];

        let mut parser = MockH2RequestParser::new();
        let result = parser.parse_request_headers(&headers);

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("pseudo-header :path after regular header"));
    }

    #[test]
    fn test_uppercase_pseudo_header() {
        let headers = vec![
            HeaderEntry { name: ":METHOD".to_string(), value: "GET".to_string() }, // Uppercase
            HeaderEntry { name: ":path".to_string(), value: "/".to_string() },
            HeaderEntry { name: ":scheme".to_string(), value: "https".to_string() },
        ];

        let mut parser = MockH2RequestParser::new();
        let result = parser.parse_request_headers(&headers);

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not lowercase"));
    }

    #[test]
    fn test_missing_required_headers() {
        let headers = vec![
            HeaderEntry { name: ":method".to_string(), value: "GET".to_string() },
            // Missing :path and :scheme
        ];

        let mut parser = MockH2RequestParser::new();
        let result = parser.parse_request_headers(&headers);

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing required pseudo-header"));
    }

    #[test]
    fn test_empty_pseudo_header_values() {
        let headers = vec![
            HeaderEntry { name: ":method".to_string(), value: "".to_string() }, // Empty
            HeaderEntry { name: ":path".to_string(), value: "/".to_string() },
            HeaderEntry { name: ":scheme".to_string(), value: "https".to_string() },
        ];

        let mut parser = MockH2RequestParser::new();
        let result = parser.parse_request_headers(&headers);

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("empty :method value"));
    }

    #[test]
    fn test_invalid_path_value() {
        let headers = vec![
            HeaderEntry { name: ":method".to_string(), value: "GET".to_string() },
            HeaderEntry { name: ":path".to_string(), value: "invalid-path".to_string() }, // No leading /
            HeaderEntry { name: ":scheme".to_string(), value: "https".to_string() },
        ];

        let mut parser = MockH2RequestParser::new();
        let result = parser.parse_request_headers(&headers);

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid :path value"));
    }

    #[test]
    fn test_options_asterisk_path() {
        let headers = vec![
            HeaderEntry { name: ":method".to_string(), value: "OPTIONS".to_string() },
            HeaderEntry { name: ":path".to_string(), value: "*".to_string() }, // Valid for OPTIONS
            HeaderEntry { name: ":scheme".to_string(), value: "https".to_string() },
        ];

        let mut parser = MockH2RequestParser::new();
        let result = parser.parse_request_headers(&headers);

        assert!(result.is_ok(), "OPTIONS with * path should be valid");
    }

    #[test]
    fn test_unknown_pseudo_header() {
        let headers = vec![
            HeaderEntry { name: ":method".to_string(), value: "GET".to_string() },
            HeaderEntry { name: ":path".to_string(), value: "/".to_string() },
            HeaderEntry { name: ":scheme".to_string(), value: "https".to_string() },
            HeaderEntry { name: ":unknown".to_string(), value: "value".to_string() }, // Unknown pseudo
        ];

        let mut parser = MockH2RequestParser::new();
        let result = parser.parse_request_headers(&headers);

        // Should succeed but generate warning
        assert!(result.is_ok(), "Unknown pseudo-headers should be ignored");
        assert!(parser.get_errors().iter().any(|e| e.contains("Unknown pseudo-header")));
    }

    #[test]
    fn test_multiple_duplicates() {
        let headers = vec![
            HeaderEntry { name: ":method".to_string(), value: "GET".to_string() },
            HeaderEntry { name: ":method".to_string(), value: "POST".to_string() }, // Duplicate 1
            HeaderEntry { name: ":path".to_string(), value: "/".to_string() },
            HeaderEntry { name: ":path".to_string(), value: "/other".to_string() }, // Duplicate 2
            HeaderEntry { name: ":scheme".to_string(), value: "https".to_string() },
        ];

        let mut parser = MockH2RequestParser::new();
        let result = parser.parse_request_headers(&headers);

        assert!(result.is_err());
        // Should catch the first duplicate
        assert!(result.unwrap_err().contains("duplicate pseudo-header"));
    }
}