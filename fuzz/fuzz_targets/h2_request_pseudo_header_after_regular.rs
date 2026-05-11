#![no_main]
#![allow(dead_code)]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

/// HTTP/2 HEADERS frame pseudo-header ordering validation testing.
/// Per RFC 7540 §8.1.2.1, pseudo-headers must appear before regular headers.
/// Any pseudo-header after a regular header must be rejected as PROTOCOL_ERROR.
/// Tests ordering enforcement and proper error generation.
///
/// Tests:
/// - HEADERS with regular header before pseudo-header (PROTOCOL_ERROR)
/// - HEADERS with proper ordering (pseudo-headers first, then regular)
/// - Various combinations and mixed orderings
/// - Multiple pseudo-headers after regular headers
/// - Specific error detection and PROTOCOL_ERROR generation
/// - Edge cases with valid and invalid sequences

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    /// HTTP/2 request with header ordering to test
    headers_request: HeadersRequest,
}

#[derive(Arbitrary, Debug, Clone)]
struct HeadersRequest {
    /// Stream ID (must be > 0 for request)
    stream_id: u32,
    /// Frame flags
    flags: u8,
    /// Sequence of headers (mix of pseudo and regular)
    headers: Vec<HeaderEntry>,
}

#[derive(Arbitrary, Debug, Clone)]
struct HeaderEntry {
    /// Header name
    name: String,
    /// Header value
    value: String,
}

/// Header classification
#[derive(Debug, PartialEq, Clone)]
enum HeaderType {
    /// Pseudo-header (starts with ':')
    Pseudo(PseudoHeaderType),
    /// Regular header (doesn't start with ':')
    Regular,
    /// Invalid header
    Invalid(String),
}

#[derive(Debug, PartialEq, Clone)]
enum PseudoHeaderType {
    Method,
    Path,
    Scheme,
    Authority,
    Unknown(String),
}

impl HeaderType {
    fn from_name(name: &str) -> Self {
        if name.starts_with(':') {
            let pseudo_type = match name {
                ":method" => PseudoHeaderType::Method,
                ":path" => PseudoHeaderType::Path,
                ":scheme" => PseudoHeaderType::Scheme,
                ":authority" => PseudoHeaderType::Authority,
                _ => PseudoHeaderType::Unknown(name.to_string()),
            };
            Self::Pseudo(pseudo_type)
        } else if name.is_empty()
            || name
                .chars()
                .any(|c| c.is_ascii_uppercase() || c.is_whitespace())
        {
            Self::Invalid(format!("Invalid header name: {}", name))
        } else {
            Self::Regular
        }
    }

    fn is_pseudo(&self) -> bool {
        matches!(self, Self::Pseudo(_))
    }

    fn is_regular(&self) -> bool {
        matches!(self, Self::Regular)
    }
}

/// HTTP/2 HEADERS frame parser with ordering validation
struct MockH2HeadersOrderingParser {
    /// Parsed pseudo-headers
    pseudo_headers: Vec<(String, String)>,
    /// Parsed regular headers
    regular_headers: Vec<(String, String)>,
    /// Whether we've seen any regular header
    seen_regular_header: bool,
    /// Processing errors
    errors: Vec<String>,
}

impl MockH2HeadersOrderingParser {
    fn new() -> Self {
        Self {
            pseudo_headers: Vec::new(),
            regular_headers: Vec::new(),
            seen_regular_header: false,
            errors: Vec::new(),
        }
    }

    /// Parse HEADERS frame with strict ordering validation
    fn parse_headers_frame(&mut self, request: &HeadersRequest) -> Result<(), String> {
        // Validate stream ID
        if request.stream_id == 0 {
            return Err("PROTOCOL_ERROR: HEADERS frame stream ID must not be 0".into());
        }

        // Reset state for new frame
        self.pseudo_headers.clear();
        self.regular_headers.clear();
        self.seen_regular_header = false;
        self.errors.clear();

        // Process each header in order
        for header in &request.headers {
            self.process_header(&header.name, &header.value)?;
        }

        // Validate that required pseudo-headers are present
        self.validate_required_pseudo_headers()?;

        Ok(())
    }

    /// Process individual header with ordering validation
    fn process_header(&mut self, name: &str, value: &str) -> Result<(), String> {
        let header_type = HeaderType::from_name(name);

        match header_type {
            HeaderType::Pseudo(pseudo_type) => {
                // RFC 7540 §8.1.2.1: pseudo-headers must appear before regular headers
                if self.seen_regular_header {
                    return Err(format!(
                        "PROTOCOL_ERROR: pseudo-header {} appears after regular header",
                        name
                    ));
                }

                // Validate pseudo-header specific rules
                self.validate_pseudo_header(&pseudo_type, name, value)?;

                // Store pseudo-header
                self.pseudo_headers
                    .push((name.to_string(), value.to_string()));
            }
            HeaderType::Regular => {
                // Mark that we've seen a regular header
                self.seen_regular_header = true;

                // Validate regular header
                self.validate_regular_header(name, value)?;

                // Store regular header
                self.regular_headers
                    .push((name.to_string(), value.to_string()));
            }
            HeaderType::Invalid(reason) => {
                return Err(format!("PROTOCOL_ERROR: {}", reason));
            }
        }

        Ok(())
    }

    /// Validate pseudo-header specific rules
    fn validate_pseudo_header(
        &mut self,
        pseudo_type: &PseudoHeaderType,
        name: &str,
        value: &str,
    ) -> Result<(), String> {
        // Check for case sensitivity (must be lowercase)
        if name.chars().any(|c| c.is_ascii_uppercase()) {
            return Err(format!(
                "PROTOCOL_ERROR: pseudo-header {} not lowercase",
                name
            ));
        }

        // Check for duplicates
        if self.pseudo_headers.iter().any(|(n, _)| n == name) {
            return Err(format!("PROTOCOL_ERROR: duplicate pseudo-header {}", name));
        }

        // Validate specific pseudo-header values
        match pseudo_type {
            PseudoHeaderType::Method => {
                if value.is_empty() {
                    return Err("PROTOCOL_ERROR: empty :method value".into());
                }
                if !value.chars().all(|c| c.is_ascii_alphabetic()) {
                    self.errors
                        .push(format!("Unusual :method value: {}", value));
                }
            }
            PseudoHeaderType::Path => {
                if value.is_empty() {
                    return Err("PROTOCOL_ERROR: empty :path value".into());
                }
                if !value.starts_with('/') && value != "*" {
                    return Err(format!("PROTOCOL_ERROR: invalid :path value: {}", value));
                }
            }
            PseudoHeaderType::Scheme => {
                if value.is_empty() {
                    return Err("PROTOCOL_ERROR: empty :scheme value".into());
                }
                if !["http", "https"].contains(&value) {
                    self.errors
                        .push(format!("Uncommon :scheme value: {}", value));
                }
            }
            PseudoHeaderType::Authority => {
                if value.contains(' ') {
                    return Err("PROTOCOL_ERROR: :authority contains invalid characters".into());
                }
            }
            PseudoHeaderType::Unknown(_) => {
                self.errors.push(format!("Unknown pseudo-header: {}", name));
            }
        }

        Ok(())
    }

    /// Validate regular header
    fn validate_regular_header(&mut self, name: &str, _value: &str) -> Result<(), String> {
        // Check for invalid characters
        if name.chars().any(|c| c.is_ascii_uppercase()) {
            return Err(format!(
                "PROTOCOL_ERROR: regular header {} contains uppercase",
                name
            ));
        }

        if name.contains(':') {
            return Err(format!(
                "PROTOCOL_ERROR: regular header {} contains colon",
                name
            ));
        }

        if name.is_empty() {
            return Err("PROTOCOL_ERROR: empty header name".into());
        }

        Ok(())
    }

    /// Validate that required pseudo-headers are present
    fn validate_required_pseudo_headers(&self) -> Result<(), String> {
        let required = [":method", ":path", ":scheme"];

        for &required_header in &required {
            if !self
                .pseudo_headers
                .iter()
                .any(|(name, _)| name == required_header)
            {
                return Err(format!(
                    "PROTOCOL_ERROR: missing required pseudo-header {}",
                    required_header
                ));
            }
        }

        Ok(())
    }

    /// Check if ordering violation occurred
    fn has_ordering_violation(&self, headers: &[HeaderEntry]) -> bool {
        let mut seen_regular = false;

        for header in headers {
            let header_type = HeaderType::from_name(&header.name);

            if header_type.is_regular() {
                seen_regular = true;
            } else if header_type.is_pseudo() && seen_regular {
                return true; // Pseudo after regular = violation
            }
        }

        false
    }

    /// Get parsed headers
    fn get_pseudo_headers(&self) -> &[(String, String)] {
        &self.pseudo_headers
    }

    fn get_regular_headers(&self) -> &[(String, String)] {
        &self.regular_headers
    }

    /// Get processing errors
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
    if input.headers_request.headers.len() > 20 {
        return;
    }

    // Limit header name/value lengths
    if input
        .headers_request
        .headers
        .iter()
        .any(|h| h.name.len() > 100 || h.value.len() > 200)
    {
        return;
    }

    // Ensure valid stream ID
    if input.headers_request.stream_id == 0 || input.headers_request.stream_id > 1_000_000 {
        return;
    }

    let mut parser = MockH2HeadersOrderingParser::new();
    let result = parser.parse_headers_frame(&input.headers_request);

    // Test 1: Detect ordering violations
    let has_violation = parser.has_ordering_violation(&input.headers_request.headers);

    if has_violation {
        assert!(
            result.is_err(),
            "Pseudo-header after regular header should be PROTOCOL_ERROR"
        );

        if let Err(error_msg) = &result {
            assert!(
                error_msg.contains("PROTOCOL_ERROR"),
                "Error should mention PROTOCOL_ERROR: {}",
                error_msg
            );
            assert!(
                error_msg.contains("appears after regular header")
                    || error_msg.contains("pseudo-header") && error_msg.contains("after"),
                "Error should indicate ordering violation: {}",
                error_msg
            );
        }
        return; // No further tests needed for violation case
    }

    // Test 2: Check for other validation errors
    let has_invalid_headers = input.headers_request.headers.iter().any(|h| {
        let header_type = HeaderType::from_name(&h.name);
        matches!(header_type, HeaderType::Invalid(_))
    });

    if has_invalid_headers {
        assert!(result.is_err(), "Invalid headers should be rejected");
        return;
    }

    // Test 3: Check for case sensitivity violations
    let has_case_violations = input
        .headers_request
        .headers
        .iter()
        .any(|h| h.name.starts_with(':') && h.name.chars().any(|c| c.is_ascii_uppercase()));

    if has_case_violations {
        assert!(
            result.is_err(),
            "Uppercase pseudo-headers should be rejected"
        );
        return;
    }

    // Test 4: Check for duplicate pseudo-headers
    let pseudo_names: Vec<_> = input
        .headers_request
        .headers
        .iter()
        .filter(|h| h.name.starts_with(':'))
        .map(|h| &h.name)
        .collect();

    let unique_pseudo_names: std::collections::HashSet<_> = pseudo_names.iter().collect();

    if pseudo_names.len() != unique_pseudo_names.len() {
        assert!(
            result.is_err(),
            "Duplicate pseudo-headers should be rejected"
        );
        return;
    }

    // Test 5: Check for empty pseudo-header values
    let has_empty_pseudo =
        input.headers_request.headers.iter().any(|h| {
            matches!(h.name.as_str(), ":method" | ":path" | ":scheme") && h.value.is_empty()
        });

    if has_empty_pseudo {
        assert!(
            result.is_err(),
            "Empty required pseudo-header values should be rejected"
        );
        return;
    }

    // Test 6: Check for invalid :path values
    let has_invalid_path = input.headers_request.headers.iter().any(|h| {
        h.name == ":path" && !h.value.is_empty() && !h.value.starts_with('/') && h.value != "*"
    });

    if has_invalid_path {
        assert!(result.is_err(), "Invalid :path values should be rejected");
        return;
    }

    // Test 7: Check for required pseudo-headers
    let required_pseudo = [":method", ":path", ":scheme"];
    let has_all_required = required_pseudo.iter().all(|&required| {
        input
            .headers_request
            .headers
            .iter()
            .any(|h| h.name == required)
    });

    if !has_all_required {
        assert!(
            result.is_err(),
            "Missing required pseudo-headers should be rejected"
        );
        return;
    }

    // Test 8: Valid requests should succeed
    assert!(
        result.is_ok(),
        "Valid headers request should succeed: {:?}",
        result
    );

    // Verify parsed structure
    let pseudo_count = input
        .headers_request
        .headers
        .iter()
        .filter(|h| h.name.starts_with(':'))
        .count();

    let regular_count = input
        .headers_request
        .headers
        .iter()
        .filter(|h| !h.name.starts_with(':') && !h.name.is_empty())
        .count();

    assert_eq!(
        parser.get_pseudo_headers().len(),
        pseudo_count,
        "Pseudo-header count should match"
    );
    assert_eq!(
        parser.get_regular_headers().len(),
        regular_count,
        "Regular header count should match"
    );
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pseudo_after_regular_error() {
        let request = HeadersRequest {
            stream_id: 1,
            flags: 0,
            headers: vec![
                HeaderEntry {
                    name: ":method".to_string(),
                    value: "GET".to_string(),
                },
                HeaderEntry {
                    name: "content-type".to_string(),
                    value: "text/html".to_string(),
                }, // Regular
                HeaderEntry {
                    name: ":path".to_string(),
                    value: "/".to_string(),
                }, // Pseudo after regular
            ],
        };

        let mut parser = MockH2HeadersOrderingParser::new();
        let result = parser.parse_headers_frame(&request);

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("appears after regular header"));
    }

    #[test]
    fn test_valid_ordering() {
        let request = HeadersRequest {
            stream_id: 1,
            flags: 0,
            headers: vec![
                HeaderEntry {
                    name: ":method".to_string(),
                    value: "GET".to_string(),
                },
                HeaderEntry {
                    name: ":path".to_string(),
                    value: "/api".to_string(),
                },
                HeaderEntry {
                    name: ":scheme".to_string(),
                    value: "https".to_string(),
                },
                HeaderEntry {
                    name: "content-type".to_string(),
                    value: "application/json".to_string(),
                },
                HeaderEntry {
                    name: "user-agent".to_string(),
                    value: "test".to_string(),
                },
            ],
        };

        let mut parser = MockH2HeadersOrderingParser::new();
        let result = parser.parse_headers_frame(&request);

        assert!(result.is_ok());
        assert_eq!(parser.get_pseudo_headers().len(), 3);
        assert_eq!(parser.get_regular_headers().len(), 2);
    }

    #[test]
    fn test_multiple_pseudo_after_regular() {
        let request = HeadersRequest {
            stream_id: 1,
            flags: 0,
            headers: vec![
                HeaderEntry {
                    name: ":method".to_string(),
                    value: "POST".to_string(),
                },
                HeaderEntry {
                    name: "content-type".to_string(),
                    value: "text/plain".to_string(),
                },
                HeaderEntry {
                    name: ":path".to_string(),
                    value: "/submit".to_string(),
                },
                HeaderEntry {
                    name: ":scheme".to_string(),
                    value: "http".to_string(),
                },
            ],
        };

        let mut parser = MockH2HeadersOrderingParser::new();
        let result = parser.parse_headers_frame(&request);

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("appears after regular header"));
    }

    #[test]
    fn test_duplicate_pseudo_header() {
        let request = HeadersRequest {
            stream_id: 1,
            flags: 0,
            headers: vec![
                HeaderEntry {
                    name: ":method".to_string(),
                    value: "GET".to_string(),
                },
                HeaderEntry {
                    name: ":method".to_string(),
                    value: "POST".to_string(),
                }, // Duplicate
                HeaderEntry {
                    name: ":path".to_string(),
                    value: "/".to_string(),
                },
                HeaderEntry {
                    name: ":scheme".to_string(),
                    value: "https".to_string(),
                },
            ],
        };

        let mut parser = MockH2HeadersOrderingParser::new();
        let result = parser.parse_headers_frame(&request);

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("duplicate pseudo-header"));
    }

    #[test]
    fn test_uppercase_pseudo_header() {
        let request = HeadersRequest {
            stream_id: 1,
            flags: 0,
            headers: vec![
                HeaderEntry {
                    name: ":METHOD".to_string(),
                    value: "GET".to_string(),
                },
                HeaderEntry {
                    name: ":path".to_string(),
                    value: "/".to_string(),
                },
                HeaderEntry {
                    name: ":scheme".to_string(),
                    value: "https".to_string(),
                },
            ],
        };

        let mut parser = MockH2HeadersOrderingParser::new();
        let result = parser.parse_headers_frame(&request);

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not lowercase"));
    }

    #[test]
    fn test_missing_required_pseudo_header() {
        let request = HeadersRequest {
            stream_id: 1,
            flags: 0,
            headers: vec![
                HeaderEntry {
                    name: ":method".to_string(),
                    value: "GET".to_string(),
                },
                // Missing :path and :scheme
                HeaderEntry {
                    name: "host".to_string(),
                    value: "example.com".to_string(),
                },
            ],
        };

        let mut parser = MockH2HeadersOrderingParser::new();
        let result = parser.parse_headers_frame(&request);

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("missing required pseudo-header")
        );
    }

    #[test]
    fn test_invalid_path_value() {
        let request = HeadersRequest {
            stream_id: 1,
            flags: 0,
            headers: vec![
                HeaderEntry {
                    name: ":method".to_string(),
                    value: "GET".to_string(),
                },
                HeaderEntry {
                    name: ":path".to_string(),
                    value: "invalid-path".to_string(),
                }, // No leading /
                HeaderEntry {
                    name: ":scheme".to_string(),
                    value: "https".to_string(),
                },
            ],
        };

        let mut parser = MockH2HeadersOrderingParser::new();
        let result = parser.parse_headers_frame(&request);

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid :path value"));
    }

    #[test]
    fn test_uppercase_regular_header() {
        let request = HeadersRequest {
            stream_id: 1,
            flags: 0,
            headers: vec![
                HeaderEntry {
                    name: ":method".to_string(),
                    value: "GET".to_string(),
                },
                HeaderEntry {
                    name: ":path".to_string(),
                    value: "/".to_string(),
                },
                HeaderEntry {
                    name: ":scheme".to_string(),
                    value: "https".to_string(),
                },
                HeaderEntry {
                    name: "Content-Type".to_string(),
                    value: "text/html".to_string(),
                }, // Uppercase
            ],
        };

        let mut parser = MockH2HeadersOrderingParser::new();
        let result = parser.parse_headers_frame(&request);

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("contains uppercase"));
    }

    #[test]
    fn test_options_asterisk_path() {
        let request = HeadersRequest {
            stream_id: 1,
            flags: 0,
            headers: vec![
                HeaderEntry {
                    name: ":method".to_string(),
                    value: "OPTIONS".to_string(),
                },
                HeaderEntry {
                    name: ":path".to_string(),
                    value: "*".to_string(),
                }, // Valid for OPTIONS
                HeaderEntry {
                    name: ":scheme".to_string(),
                    value: "https".to_string(),
                },
            ],
        };

        let mut parser = MockH2HeadersOrderingParser::new();
        let result = parser.parse_headers_frame(&request);

        assert!(result.is_ok());
    }

    #[test]
    fn test_ordering_violation_detection() {
        let headers = vec![
            HeaderEntry {
                name: ":method".to_string(),
                value: "GET".to_string(),
            },
            HeaderEntry {
                name: "user-agent".to_string(),
                value: "test".to_string(),
            },
            HeaderEntry {
                name: ":path".to_string(),
                value: "/".to_string(),
            }, // Violation
        ];

        let parser = MockH2HeadersOrderingParser::new();
        assert!(parser.has_ordering_violation(&headers));

        let valid_headers = vec![
            HeaderEntry {
                name: ":method".to_string(),
                value: "GET".to_string(),
            },
            HeaderEntry {
                name: ":path".to_string(),
                value: "/".to_string(),
            },
            HeaderEntry {
                name: "user-agent".to_string(),
                value: "test".to_string(),
            },
        ];

        assert!(!parser.has_ordering_violation(&valid_headers));
    }

    #[test]
    fn test_invalid_stream_id() {
        let request = HeadersRequest {
            stream_id: 0, // Invalid for HEADERS
            flags: 0,
            headers: vec![
                HeaderEntry {
                    name: ":method".to_string(),
                    value: "GET".to_string(),
                },
                HeaderEntry {
                    name: ":path".to_string(),
                    value: "/".to_string(),
                },
                HeaderEntry {
                    name: ":scheme".to_string(),
                    value: "https".to_string(),
                },
            ],
        };

        let mut parser = MockH2HeadersOrderingParser::new();
        let result = parser.parse_headers_frame(&request);

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("stream ID must not be 0"));
    }
}
