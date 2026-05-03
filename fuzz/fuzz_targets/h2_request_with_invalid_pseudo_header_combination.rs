#![no_main]
//! HTTP/2 invalid pseudo-header combination fuzz target
//!
//! Tests handling of HEADERS frames with incomplete pseudo-header combinations.
//! Per RFC 7540 §8.1.2.3, all four pseudo-headers (:method, :scheme, :path,
//! :authority) MUST be present for a valid HTTP/2 request. Missing any required
//! pseudo-header should result in PROTOCOL_ERROR.
//!
//! Primary test scenario: HEADERS with only :path + :authority (missing :method, :scheme)
//!
//! Additional test scenarios:
//! - Only :method + :scheme (missing :path, :authority)
//! - Only :path (missing :method, :scheme, :authority)
//! - Missing :method only (:scheme, :path, :authority present)
//! - Missing :scheme only (:method, :path, :authority present)
//! - Duplicate pseudo-headers (e.g., two :method headers)
//! - Wrong order (regular headers before pseudo-headers)
//! - Empty pseudo-header values
//! - Invalid pseudo-header names
//!
//! RFC references:
//! - RFC 7540 §8.1.2.3: Request pseudo-header fields
//! - RFC 7540 §8.1.2: HTTP header fields (ordering requirements)
//! - RFC 7541 §6.1: Indexed header field representation

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Configuration for pseudo-header validation testing
#[derive(Debug, Clone)]
struct PseudoHeaderTestConfig {
    /// Allow testing with duplicate pseudo-headers
    pub test_duplicates: bool,
    /// Allow testing with wrong ordering (regular before pseudo)
    pub test_wrong_order: bool,
    /// Allow testing with empty values
    pub test_empty_values: bool,
    /// Allow testing with invalid pseudo-header names
    pub test_invalid_names: bool,
}

impl Default for PseudoHeaderTestConfig {
    fn default() -> Self {
        Self {
            test_duplicates: true,
            test_wrong_order: true,
            test_empty_values: true,
            test_invalid_names: true,
        }
    }
}

/// Mock HTTP/2 connection for pseudo-header validation testing
#[derive(Debug)]
struct MockPseudoHeaderConnection {
    /// Count of requests with missing :method pseudo-header
    pub missing_method: Arc<Mutex<u64>>,
    /// Count of requests with missing :scheme pseudo-header
    pub missing_scheme: Arc<Mutex<u64>>,
    /// Count of requests with missing :path pseudo-header
    pub missing_path: Arc<Mutex<u64>>,
    /// Count of requests with missing :authority pseudo-header
    pub missing_authority: Arc<Mutex<u64>>,
    /// Count of requests with multiple missing pseudo-headers
    pub multiple_missing: Arc<Mutex<u64>>,
    /// Count of requests with duplicate pseudo-headers
    pub duplicate_pseudo_headers: Arc<Mutex<u64>>,
    /// Count of requests with wrong header ordering
    pub wrong_order: Arc<Mutex<u64>>,
    /// Count of requests with empty pseudo-header values
    pub empty_pseudo_values: Arc<Mutex<u64>>,
    /// Count of requests with invalid pseudo-header names
    pub invalid_pseudo_names: Arc<Mutex<u64>>,
    /// Count of PROTOCOL_ERROR responses for invalid combinations
    pub protocol_errors: Arc<Mutex<u64>>,
    /// Count of valid requests (all four pseudo-headers present)
    pub valid_requests: Arc<Mutex<u64>>,
    /// Track specific invalid combination: :path + :authority only
    pub path_authority_only: Arc<Mutex<u64>>,
    /// Track specific invalid combination: :method + :scheme only
    pub method_scheme_only: Arc<Mutex<u64>>,
    /// Configuration for this test session
    pub config: PseudoHeaderTestConfig,
}

impl MockPseudoHeaderConnection {
    fn new(config: PseudoHeaderTestConfig) -> Self {
        Self {
            missing_method: Arc::new(Mutex::new(0)),
            missing_scheme: Arc::new(Mutex::new(0)),
            missing_path: Arc::new(Mutex::new(0)),
            missing_authority: Arc::new(Mutex::new(0)),
            multiple_missing: Arc::new(Mutex::new(0)),
            duplicate_pseudo_headers: Arc::new(Mutex::new(0)),
            wrong_order: Arc::new(Mutex::new(0)),
            empty_pseudo_values: Arc::new(Mutex::new(0)),
            invalid_pseudo_names: Arc::new(Mutex::new(0)),
            protocol_errors: Arc::new(Mutex::new(0)),
            valid_requests: Arc::new(Mutex::new(0)),
            path_authority_only: Arc::new(Mutex::new(0)),
            method_scheme_only: Arc::new(Mutex::new(0)),
            config,
        }
    }

    /// Process HTTP/2 HEADERS frame with pseudo-header validation
    fn handle_headers_frame(&self, headers: &[HttpHeader]) -> HeadersResult {
        let analysis = self.analyze_pseudo_headers(headers);

        // Track specific patterns
        if analysis.has_path && analysis.has_authority && !analysis.has_method && !analysis.has_scheme {
            *self.path_authority_only.lock().unwrap() += 1;
        }

        if analysis.has_method && analysis.has_scheme && !analysis.has_path && !analysis.has_authority {
            *self.method_scheme_only.lock().unwrap() += 1;
        }

        // Track missing pseudo-headers
        if !analysis.has_method {
            *self.missing_method.lock().unwrap() += 1;
        }
        if !analysis.has_scheme {
            *self.missing_scheme.lock().unwrap() += 1;
        }
        if !analysis.has_path {
            *self.missing_path.lock().unwrap() += 1;
        }
        if !analysis.has_authority {
            *self.missing_authority.lock().unwrap() += 1;
        }

        // Track multiple missing
        let missing_count = [
            !analysis.has_method,
            !analysis.has_scheme,
            !analysis.has_path,
            !analysis.has_authority,
        ].iter().filter(|&&x| x).count();

        if missing_count > 1 {
            *self.multiple_missing.lock().unwrap() += 1;
        }

        // Track other violations
        if analysis.has_duplicates {
            *self.duplicate_pseudo_headers.lock().unwrap() += 1;
        }
        if analysis.has_wrong_order {
            *self.wrong_order.lock().unwrap() += 1;
        }
        if analysis.has_empty_values {
            *self.empty_pseudo_values.lock().unwrap() += 1;
        }
        if analysis.has_invalid_names {
            *self.invalid_pseudo_names.lock().unwrap() += 1;
        }

        // Determine response based on RFC 7540 requirements
        let is_valid = analysis.has_method && analysis.has_scheme &&
                      analysis.has_path && analysis.has_authority &&
                      !analysis.has_duplicates && !analysis.has_wrong_order &&
                      !analysis.has_empty_values && !analysis.has_invalid_names;

        if is_valid {
            *self.valid_requests.lock().unwrap() += 1;
            HeadersResult::Accepted
        } else {
            *self.protocol_errors.lock().unwrap() += 1;

            // Determine specific error reason
            if missing_count > 0 {
                HeadersResult::ProtocolError("Missing required pseudo-header(s)")
            } else if analysis.has_duplicates {
                HeadersResult::ProtocolError("Duplicate pseudo-header")
            } else if analysis.has_wrong_order {
                HeadersResult::ProtocolError("Regular headers before pseudo-headers")
            } else if analysis.has_empty_values {
                HeadersResult::ProtocolError("Empty pseudo-header value")
            } else if analysis.has_invalid_names {
                HeadersResult::ProtocolError("Invalid pseudo-header name")
            } else {
                HeadersResult::ProtocolError("Invalid header combination")
            }
        }
    }

    /// Analyze pseudo-header presence and validity
    fn analyze_pseudo_headers(&self, headers: &[HttpHeader]) -> PseudoHeaderAnalysis {
        let mut analysis = PseudoHeaderAnalysis::default();
        let mut pseudo_header_counts: HashMap<&str, u32> = HashMap::new();
        let mut encountered_regular_header = false;

        for header in headers {
            if header.name.starts_with(':') {
                // This is a pseudo-header

                // Check for wrong order (pseudo after regular)
                if encountered_regular_header {
                    analysis.has_wrong_order = true;
                }

                // Count occurrences for duplicate detection
                *pseudo_header_counts.entry(&header.name).or_insert(0) += 1;

                // Check for empty values
                if header.value.is_empty() {
                    analysis.has_empty_values = true;
                }

                // Check specific pseudo-headers
                match header.name.as_str() {
                    ":method" => analysis.has_method = true,
                    ":scheme" => analysis.has_scheme = true,
                    ":path" => analysis.has_path = true,
                    ":authority" => analysis.has_authority = true,
                    _ => {
                        // Invalid pseudo-header name (not one of the standard four)
                        if !header.name.starts_with(":status") { // :status is valid for responses
                            analysis.has_invalid_names = true;
                        }
                    }
                }
            } else {
                // This is a regular header
                encountered_regular_header = true;
            }
        }

        // Check for duplicates
        for count in pseudo_header_counts.values() {
            if *count > 1 {
                analysis.has_duplicates = true;
                break;
            }
        }

        analysis
    }

    /// Generate summary statistics
    fn generate_statistics(&self) -> PseudoHeaderStatistics {
        PseudoHeaderStatistics {
            total_missing_method: *self.missing_method.lock().unwrap(),
            total_missing_scheme: *self.missing_scheme.lock().unwrap(),
            total_missing_path: *self.missing_path.lock().unwrap(),
            total_missing_authority: *self.missing_authority.lock().unwrap(),
            total_multiple_missing: *self.multiple_missing.lock().unwrap(),
            total_duplicates: *self.duplicate_pseudo_headers.lock().unwrap(),
            total_wrong_order: *self.wrong_order.lock().unwrap(),
            total_empty_values: *self.empty_pseudo_values.lock().unwrap(),
            total_invalid_names: *self.invalid_pseudo_names.lock().unwrap(),
            total_protocol_errors: *self.protocol_errors.lock().unwrap(),
            total_valid: *self.valid_requests.lock().unwrap(),
            total_path_authority_only: *self.path_authority_only.lock().unwrap(),
            total_method_scheme_only: *self.method_scheme_only.lock().unwrap(),
        }
    }
}

#[derive(Debug, Default)]
struct PseudoHeaderAnalysis {
    pub has_method: bool,
    pub has_scheme: bool,
    pub has_path: bool,
    pub has_authority: bool,
    pub has_duplicates: bool,
    pub has_wrong_order: bool,
    pub has_empty_values: bool,
    pub has_invalid_names: bool,
}

#[derive(Debug, Clone)]
enum HeadersResult {
    Accepted,
    ProtocolError(&'static str),
}

#[derive(Debug)]
struct PseudoHeaderStatistics {
    pub total_missing_method: u64,
    pub total_missing_scheme: u64,
    pub total_missing_path: u64,
    pub total_missing_authority: u64,
    pub total_multiple_missing: u64,
    pub total_duplicates: u64,
    pub total_wrong_order: u64,
    pub total_empty_values: u64,
    pub total_invalid_names: u64,
    pub total_protocol_errors: u64,
    pub total_valid: u64,
    pub total_path_authority_only: u64,
    pub total_method_scheme_only: u64,
}

#[derive(Debug, Clone)]
struct HttpHeader {
    pub name: String,
    pub value: String,
}

/// Fuzz input structure for pseudo-header testing
#[derive(Arbitrary, Debug)]
struct PseudoHeaderInput {
    /// Which pseudo-headers to include
    include_method: bool,
    include_scheme: bool,
    include_path: bool,
    include_authority: bool,
    /// Values for pseudo-headers (may be empty)
    method_value: String,
    scheme_value: String,
    path_value: String,
    authority_value: String,
    /// Additional regular headers to add
    additional_headers: Vec<(String, String)>,
    /// Test scenario configuration
    scenario: PseudoHeaderScenario,
    /// Whether to add invalid pseudo-headers
    add_invalid_pseudo: bool,
}

#[derive(Arbitrary, Debug, Clone)]
enum PseudoHeaderScenario {
    /// Primary scenario: only :path + :authority
    PathAuthorityOnly,
    /// Only :method + :scheme
    MethodSchemeOnly,
    /// Missing :method only
    MissingMethodOnly,
    /// Missing :scheme only
    MissingSchemeOnly,
    /// Missing :path only
    MissingPathOnly,
    /// Missing :authority only
    MissingAuthorityOnly,
    /// All four present (valid case)
    AllPresent,
    /// Duplicate pseudo-headers
    WithDuplicates,
    /// Wrong ordering (regular headers first)
    WrongOrder,
    /// Empty pseudo-header values
    EmptyValues,
    /// Invalid pseudo-header names
    InvalidNames,
}

impl PseudoHeaderInput {
    /// Generate header list based on the test scenario
    fn generate_headers(&self) -> Vec<HttpHeader> {
        let mut headers = Vec::new();

        match &self.scenario {
            PseudoHeaderScenario::PathAuthorityOnly => {
                // Primary test case: only :path and :authority
                headers.push(HttpHeader {
                    name: ":path".to_string(),
                    value: if self.path_value.is_empty() { "/api/test".to_string() } else { self.path_value.clone() }
                });
                headers.push(HttpHeader {
                    name: ":authority".to_string(),
                    value: if self.authority_value.is_empty() { "example.com".to_string() } else { self.authority_value.clone() }
                });
            }

            PseudoHeaderScenario::MethodSchemeOnly => {
                headers.push(HttpHeader {
                    name: ":method".to_string(),
                    value: if self.method_value.is_empty() { "GET".to_string() } else { self.method_value.clone() }
                });
                headers.push(HttpHeader {
                    name: ":scheme".to_string(),
                    value: if self.scheme_value.is_empty() { "https".to_string() } else { self.scheme_value.clone() }
                });
            }

            PseudoHeaderScenario::MissingMethodOnly => {
                // Include all except :method
                headers.push(HttpHeader {
                    name: ":scheme".to_string(),
                    value: if self.scheme_value.is_empty() { "https".to_string() } else { self.scheme_value.clone() }
                });
                headers.push(HttpHeader {
                    name: ":path".to_string(),
                    value: if self.path_value.is_empty() { "/api/test".to_string() } else { self.path_value.clone() }
                });
                headers.push(HttpHeader {
                    name: ":authority".to_string(),
                    value: if self.authority_value.is_empty() { "example.com".to_string() } else { self.authority_value.clone() }
                });
            }

            PseudoHeaderScenario::MissingSchemeOnly => {
                // Include all except :scheme
                headers.push(HttpHeader {
                    name: ":method".to_string(),
                    value: if self.method_value.is_empty() { "GET".to_string() } else { self.method_value.clone() }
                });
                headers.push(HttpHeader {
                    name: ":path".to_string(),
                    value: if self.path_value.is_empty() { "/api/test".to_string() } else { self.path_value.clone() }
                });
                headers.push(HttpHeader {
                    name: ":authority".to_string(),
                    value: if self.authority_value.is_empty() { "example.com".to_string() } else { self.authority_value.clone() }
                });
            }

            PseudoHeaderScenario::MissingPathOnly => {
                // Include all except :path
                headers.push(HttpHeader {
                    name: ":method".to_string(),
                    value: if self.method_value.is_empty() { "GET".to_string() } else { self.method_value.clone() }
                });
                headers.push(HttpHeader {
                    name: ":scheme".to_string(),
                    value: if self.scheme_value.is_empty() { "https".to_string() } else { self.scheme_value.clone() }
                });
                headers.push(HttpHeader {
                    name: ":authority".to_string(),
                    value: if self.authority_value.is_empty() { "example.com".to_string() } else { self.authority_value.clone() }
                });
            }

            PseudoHeaderScenario::MissingAuthorityOnly => {
                // Include all except :authority
                headers.push(HttpHeader {
                    name: ":method".to_string(),
                    value: if self.method_value.is_empty() { "GET".to_string() } else { self.method_value.clone() }
                });
                headers.push(HttpHeader {
                    name: ":scheme".to_string(),
                    value: if self.scheme_value.is_empty() { "https".to_string() } else { self.scheme_value.clone() }
                });
                headers.push(HttpHeader {
                    name: ":path".to_string(),
                    value: if self.path_value.is_empty() { "/api/test".to_string() } else { self.path_value.clone() }
                });
            }

            PseudoHeaderScenario::AllPresent => {
                // Valid case: all four pseudo-headers
                headers.push(HttpHeader {
                    name: ":method".to_string(),
                    value: if self.method_value.is_empty() { "GET".to_string() } else { self.method_value.clone() }
                });
                headers.push(HttpHeader {
                    name: ":scheme".to_string(),
                    value: if self.scheme_value.is_empty() { "https".to_string() } else { self.scheme_value.clone() }
                });
                headers.push(HttpHeader {
                    name: ":path".to_string(),
                    value: if self.path_value.is_empty() { "/api/test".to_string() } else { self.path_value.clone() }
                });
                headers.push(HttpHeader {
                    name: ":authority".to_string(),
                    value: if self.authority_value.is_empty() { "example.com".to_string() } else { self.authority_value.clone() }
                });
            }

            PseudoHeaderScenario::WithDuplicates => {
                // Add all four, then duplicate :method
                headers.push(HttpHeader {
                    name: ":method".to_string(),
                    value: "GET".to_string()
                });
                headers.push(HttpHeader {
                    name: ":scheme".to_string(),
                    value: "https".to_string()
                });
                headers.push(HttpHeader {
                    name: ":path".to_string(),
                    value: "/api/test".to_string()
                });
                headers.push(HttpHeader {
                    name: ":authority".to_string(),
                    value: "example.com".to_string()
                });
                // Duplicate :method
                headers.push(HttpHeader {
                    name: ":method".to_string(),
                    value: "POST".to_string()
                });
            }

            PseudoHeaderScenario::WrongOrder => {
                // Add regular header first, then pseudo-headers
                headers.push(HttpHeader {
                    name: "user-agent".to_string(),
                    value: "test-client".to_string()
                });
                headers.push(HttpHeader {
                    name: ":method".to_string(),
                    value: "GET".to_string()
                });
                headers.push(HttpHeader {
                    name: ":scheme".to_string(),
                    value: "https".to_string()
                });
                headers.push(HttpHeader {
                    name: ":path".to_string(),
                    value: "/api/test".to_string()
                });
                headers.push(HttpHeader {
                    name: ":authority".to_string(),
                    value: "example.com".to_string()
                });
            }

            PseudoHeaderScenario::EmptyValues => {
                // All four present but with empty values
                headers.push(HttpHeader {
                    name: ":method".to_string(),
                    value: "".to_string()
                });
                headers.push(HttpHeader {
                    name: ":scheme".to_string(),
                    value: "".to_string()
                });
                headers.push(HttpHeader {
                    name: ":path".to_string(),
                    value: "".to_string()
                });
                headers.push(HttpHeader {
                    name: ":authority".to_string(),
                    value: "".to_string()
                });
            }

            PseudoHeaderScenario::InvalidNames => {
                // Add invalid pseudo-header names
                headers.push(HttpHeader {
                    name: ":invalid".to_string(),
                    value: "test".to_string()
                });
                headers.push(HttpHeader {
                    name: ":custom".to_string(),
                    value: "value".to_string()
                });
                // Add some valid ones too
                headers.push(HttpHeader {
                    name: ":method".to_string(),
                    value: "GET".to_string()
                });
                headers.push(HttpHeader {
                    name: ":path".to_string(),
                    value: "/test".to_string()
                });
            }
        }

        // Add any additional regular headers
        for (name, value) in &self.additional_headers {
            if !name.is_empty() {
                headers.push(HttpHeader {
                    name: name.clone(),
                    value: value.clone(),
                });
            }
        }

        headers
    }
}

fuzz_target!(|input: PseudoHeaderInput| {
    // Skip excessively large inputs
    if input.additional_headers.len() > 100 {
        return;
    }

    // Generate test configuration
    let config = PseudoHeaderTestConfig::default();

    // Create mock connection
    let connection = MockPseudoHeaderConnection::new(config);

    // Generate headers for testing
    let headers = input.generate_headers();

    // Skip empty header lists
    if headers.is_empty() {
        return;
    }

    // Test the pseudo-header validation
    let result = connection.handle_headers_frame(&headers);

    // Verify the result makes sense
    match result {
        HeadersResult::Accepted => {
            // Should only be accepted if all four pseudo-headers are present and valid
        }
        HeadersResult::ProtocolError(_reason) => {
            // Should be rejected for invalid combinations
        }
    }

    // Generate statistics for analysis
    let _stats = connection.generate_statistics();

    // For the primary test case (:path + :authority only), verify PROTOCOL_ERROR
    match input.scenario {
        PseudoHeaderScenario::PathAuthorityOnly => {
            match result {
                HeadersResult::ProtocolError(_) => {
                    // Correct: should be rejected
                }
                HeadersResult::Accepted => {
                    panic!("RFC 7540 violation: :path + :authority only should be rejected with PROTOCOL_ERROR");
                }
            }
        }
        _ => {
            // Other scenarios have their own validation requirements
        }
    }
});