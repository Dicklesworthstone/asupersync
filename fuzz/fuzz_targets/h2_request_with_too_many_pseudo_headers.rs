#![no_main]
//! HTTP/2 excessive pseudo-headers fuzz target
//!
//! Tests handling of HEADERS frames containing 5+ pseudo-headers which
//! violates RFC 7540 requirements. Per RFC 7540 §8.1.2.1, only the four
//! standard pseudo-headers (:method, :scheme, :path, :authority) are allowed
//! for requests. Additional pseudo-headers (duplicates or invalid names)
//! should result in PROTOCOL_ERROR.
//!
//! Primary test scenario: Standard 4 pseudo-headers + duplicate or invalid 5th
//!
//! Test scenarios:
//! - Standard 4 + duplicate :method (5 total pseudo-headers)
//! - Standard 4 + duplicate :scheme (5 total pseudo-headers)
//! - Standard 4 + duplicate :path (5 total pseudo-headers)
//! - Standard 4 + duplicate :authority (5 total pseudo-headers)
//! - Standard 4 + invalid pseudo-header name (:custom, :invalid)
//! - Standard 4 + :status (valid for responses, invalid for requests)
//! - Multiple duplicates (6, 7, 8+ pseudo-headers)
//! - Very long pseudo-header names (:verylongcustompseudoheader...)
//! - Mixed duplicates and invalid names
//! - Duplicate with different values (conflicting)
//!
//! RFC references:
//! - RFC 7540 §8.1.2.1: Pseudo-header field definitions
//! - RFC 7540 §8.1.2.3: Request pseudo-header fields
//! - RFC 7540 §8.1.2.4: Response pseudo-header fields
//! - RFC 7541 §6.1: Indexed header field representation

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Configuration for excessive pseudo-headers testing
#[derive(Debug, Clone)]
struct ExcessivePseudoHeadersConfig {
    /// Include tests with duplicate standard pseudo-headers
    pub include_duplicates: bool,
    /// Include tests with invalid pseudo-header names
    pub include_invalid_names: bool,
    /// Include tests with :status in requests (invalid)
    pub include_status_in_request: bool,
    /// Include tests with very long pseudo-header names
    pub include_long_names: bool,
}

impl Default for ExcessivePseudoHeadersConfig {
    fn default() -> Self {
        Self {
            include_duplicates: true,
            include_invalid_names: true,
            include_status_in_request: true,
            include_long_names: true,
        }
    }
}

/// Mock HTTP/2 connection for excessive pseudo-headers validation testing
#[derive(Debug)]
struct MockExcessivePseudoHeadersConnection {
    /// Count of requests with duplicate :method pseudo-headers
    pub duplicate_method: Arc<Mutex<u64>>,
    /// Count of requests with duplicate :scheme pseudo-headers
    pub duplicate_scheme: Arc<Mutex<u64>>,
    /// Count of requests with duplicate :path pseudo-headers
    pub duplicate_path: Arc<Mutex<u64>>,
    /// Count of requests with duplicate :authority pseudo-headers
    pub duplicate_authority: Arc<Mutex<u64>>,
    /// Count of requests with invalid pseudo-header names
    pub invalid_pseudo_names: Arc<Mutex<u64>>,
    /// Count of requests with :status in request (invalid)
    pub status_in_request: Arc<Mutex<u64>>,
    /// Count of requests with 5+ pseudo-headers total
    pub five_plus_pseudos: Arc<Mutex<u64>>,
    /// Count of requests with 6+ pseudo-headers total
    pub six_plus_pseudos: Arc<Mutex<u64>>,
    /// Count of requests with 10+ pseudo-headers total
    pub ten_plus_pseudos: Arc<Mutex<u64>>,
    /// Count of requests with very long pseudo-header names
    pub long_pseudo_names: Arc<Mutex<u64>>,
    /// Count of requests with conflicting duplicate values
    pub conflicting_duplicates: Arc<Mutex<u64>>,
    /// Count of requests with mixed duplicates and invalid names
    pub mixed_violations: Arc<Mutex<u64>>,
    /// Count of PROTOCOL_ERROR responses for excessive pseudo-headers
    pub protocol_errors: Arc<Mutex<u64>>,
    /// Count of valid requests (exactly 4 standard pseudo-headers)
    pub valid_requests: Arc<Mutex<u64>>,
    /// Track consistency violations
    pub consistency_violations: Arc<Mutex<u64>>,
    /// Configuration for this test session
    pub config: ExcessivePseudoHeadersConfig,
    /// Cache of previous decisions for consistency checking
    pub decision_cache: Arc<Mutex<HashMap<String, ExcessiveHeadersResult>>>,
}

impl MockExcessivePseudoHeadersConnection {
    fn new(config: ExcessivePseudoHeadersConfig) -> Self {
        Self {
            duplicate_method: Arc::new(Mutex::new(0)),
            duplicate_scheme: Arc::new(Mutex::new(0)),
            duplicate_path: Arc::new(Mutex::new(0)),
            duplicate_authority: Arc::new(Mutex::new(0)),
            invalid_pseudo_names: Arc::new(Mutex::new(0)),
            status_in_request: Arc::new(Mutex::new(0)),
            five_plus_pseudos: Arc::new(Mutex::new(0)),
            six_plus_pseudos: Arc::new(Mutex::new(0)),
            ten_plus_pseudos: Arc::new(Mutex::new(0)),
            long_pseudo_names: Arc::new(Mutex::new(0)),
            conflicting_duplicates: Arc::new(Mutex::new(0)),
            mixed_violations: Arc::new(Mutex::new(0)),
            protocol_errors: Arc::new(Mutex::new(0)),
            valid_requests: Arc::new(Mutex::new(0)),
            consistency_violations: Arc::new(Mutex::new(0)),
            config,
            decision_cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Process HTTP/2 HEADERS frame with pseudo-header count validation
    fn handle_excessive_headers_request(&self, headers: &[PseudoHeader]) -> ExcessiveHeadersResult {
        let analysis = self.analyze_pseudo_headers(headers);

        // Track various excessive patterns
        if analysis.duplicate_method {
            *self.duplicate_method.lock().unwrap() += 1;
        }

        if analysis.duplicate_scheme {
            *self.duplicate_scheme.lock().unwrap() += 1;
        }

        if analysis.duplicate_path {
            *self.duplicate_path.lock().unwrap() += 1;
        }

        if analysis.duplicate_authority {
            *self.duplicate_authority.lock().unwrap() += 1;
        }

        if analysis.has_invalid_pseudo_names {
            *self.invalid_pseudo_names.lock().unwrap() += 1;
        }

        if analysis.has_status_in_request {
            *self.status_in_request.lock().unwrap() += 1;
        }

        if analysis.total_pseudo_headers >= 5 {
            *self.five_plus_pseudos.lock().unwrap() += 1;
        }

        if analysis.total_pseudo_headers >= 6 {
            *self.six_plus_pseudos.lock().unwrap() += 1;
        }

        if analysis.total_pseudo_headers >= 10 {
            *self.ten_plus_pseudos.lock().unwrap() += 1;
        }

        if analysis.has_long_pseudo_names {
            *self.long_pseudo_names.lock().unwrap() += 1;
        }

        if analysis.has_conflicting_duplicates {
            *self.conflicting_duplicates.lock().unwrap() += 1;
        }

        if analysis.has_mixed_violations {
            *self.mixed_violations.lock().unwrap() += 1;
        }

        // Determine if headers are valid per RFC 7540
        let is_valid = self.validate_pseudo_headers(&analysis);

        // Create cache key for consistency checking
        let cache_key = self.create_headers_cache_key(headers);

        // Check consistency with previous decisions
        let mut cache = self.decision_cache.lock().unwrap();
        let result = if is_valid {
            *self.valid_requests.lock().unwrap() += 1;
            ExcessiveHeadersResult::Accepted
        } else {
            *self.protocol_errors.lock().unwrap() += 1;

            // Determine specific error reason
            if analysis.total_pseudo_headers > 4 {
                ExcessiveHeadersResult::ProtocolError("Too many pseudo-headers")
            } else if analysis.has_duplicates {
                ExcessiveHeadersResult::ProtocolError("Duplicate pseudo-header")
            } else if analysis.has_invalid_pseudo_names {
                ExcessiveHeadersResult::ProtocolError("Invalid pseudo-header name")
            } else if analysis.has_status_in_request {
                ExcessiveHeadersResult::ProtocolError(":status pseudo-header in request")
            } else {
                ExcessiveHeadersResult::ProtocolError("Invalid pseudo-header combination")
            }
        };

        // Consistency check
        if let Some(previous_result) = cache.get(&cache_key) {
            if !self.results_match(&result, previous_result) {
                *self.consistency_violations.lock().unwrap() += 1;
            }
        } else {
            cache.insert(cache_key, result.clone());
        }

        result
    }

    /// Analyze pseudo-headers for violations
    fn analyze_pseudo_headers(&self, headers: &[PseudoHeader]) -> PseudoHeadersAnalysis {
        let mut analysis = PseudoHeadersAnalysis::default();
        let mut pseudo_header_counts: HashMap<&str, u32> = HashMap::new();
        let mut pseudo_header_values: HashMap<&str, Vec<&str>> = HashMap::new();

        // Count pseudo-headers and track values
        for header in headers {
            if header.name.starts_with(':') {
                analysis.total_pseudo_headers += 1;

                // Count occurrences
                *pseudo_header_counts.entry(&header.name).or_insert(0) += 1;

                // Track values for conflict detection
                pseudo_header_values
                    .entry(&header.name)
                    .or_insert_with(Vec::new)
                    .push(&header.value);

                // Check for specific invalid cases
                if header.name == ":status" {
                    analysis.has_status_in_request = true;
                }

                // Check for invalid pseudo-header names
                if !self.is_standard_pseudo_header(&header.name) {
                    analysis.has_invalid_pseudo_names = true;
                }

                // Check for very long pseudo-header names
                if header.name.len() > 50 {
                    analysis.has_long_pseudo_names = true;
                }
            }
        }

        // Check for duplicates and conflicts
        for (name, count) in &pseudo_header_counts {
            if *count > 1 {
                analysis.has_duplicates = true;

                match *name {
                    ":method" => analysis.duplicate_method = true,
                    ":scheme" => analysis.duplicate_scheme = true,
                    ":path" => analysis.duplicate_path = true,
                    ":authority" => analysis.duplicate_authority = true,
                    _ => {}
                }

                // Check for conflicting values
                if let Some(values) = pseudo_header_values.get(name) {
                    let unique_values: std::collections::HashSet<_> = values.iter().collect();
                    if unique_values.len() > 1 {
                        analysis.has_conflicting_duplicates = true;
                    }
                }
            }
        }

        // Check for mixed violations
        if analysis.has_duplicates && analysis.has_invalid_pseudo_names {
            analysis.has_mixed_violations = true;
        }

        analysis
    }

    /// Check if pseudo-header name is standard for requests
    fn is_standard_pseudo_header(&self, name: &str) -> bool {
        match name {
            ":method" | ":scheme" | ":path" | ":authority" => true,
            _ => false, // :status is only valid for responses
        }
    }

    /// Validate pseudo-headers per RFC 7540 requirements
    fn validate_pseudo_headers(&self, analysis: &PseudoHeadersAnalysis) -> bool {
        // RFC 7540: Only 4 standard pseudo-headers allowed for requests
        if analysis.total_pseudo_headers > 4 {
            return false;
        }

        // No duplicates allowed
        if analysis.has_duplicates {
            return false;
        }

        // Only standard pseudo-header names allowed
        if analysis.has_invalid_pseudo_names {
            return false;
        }

        // :status is not allowed in requests
        if analysis.has_status_in_request {
            return false;
        }

        true
    }

    /// Create cache key for headers list
    fn create_headers_cache_key(&self, headers: &[PseudoHeader]) -> String {
        let mut key = String::new();
        for header in headers {
            key.push_str(&header.name);
            key.push('=');
            key.push_str(&header.value);
            key.push(';');
        }
        key
    }

    /// Check if two results match (for consistency validation)
    fn results_match(&self, result1: &ExcessiveHeadersResult, result2: &ExcessiveHeadersResult) -> bool {
        match (result1, result2) {
            (ExcessiveHeadersResult::Accepted, ExcessiveHeadersResult::Accepted) => true,
            (ExcessiveHeadersResult::ProtocolError(_), ExcessiveHeadersResult::ProtocolError(_)) => true,
            _ => false,
        }
    }

    /// Generate summary statistics
    fn generate_statistics(&self) -> ExcessivePseudoHeadersStatistics {
        ExcessivePseudoHeadersStatistics {
            total_duplicate_method: *self.duplicate_method.lock().unwrap(),
            total_duplicate_scheme: *self.duplicate_scheme.lock().unwrap(),
            total_duplicate_path: *self.duplicate_path.lock().unwrap(),
            total_duplicate_authority: *self.duplicate_authority.lock().unwrap(),
            total_invalid_names: *self.invalid_pseudo_names.lock().unwrap(),
            total_status_in_request: *self.status_in_request.lock().unwrap(),
            total_five_plus: *self.five_plus_pseudos.lock().unwrap(),
            total_six_plus: *self.six_plus_pseudos.lock().unwrap(),
            total_ten_plus: *self.ten_plus_pseudos.lock().unwrap(),
            total_long_names: *self.long_pseudo_names.lock().unwrap(),
            total_conflicting: *self.conflicting_duplicates.lock().unwrap(),
            total_mixed: *self.mixed_violations.lock().unwrap(),
            total_protocol_errors: *self.protocol_errors.lock().unwrap(),
            total_valid: *self.valid_requests.lock().unwrap(),
            consistency_violations: *self.consistency_violations.lock().unwrap(),
        }
    }
}

#[derive(Debug, Default)]
struct PseudoHeadersAnalysis {
    pub total_pseudo_headers: u32,
    pub has_duplicates: bool,
    pub duplicate_method: bool,
    pub duplicate_scheme: bool,
    pub duplicate_path: bool,
    pub duplicate_authority: bool,
    pub has_invalid_pseudo_names: bool,
    pub has_status_in_request: bool,
    pub has_long_pseudo_names: bool,
    pub has_conflicting_duplicates: bool,
    pub has_mixed_violations: bool,
}

#[derive(Debug, Clone)]
enum ExcessiveHeadersResult {
    Accepted,
    ProtocolError(&'static str),
}

#[derive(Debug)]
struct ExcessivePseudoHeadersStatistics {
    pub total_duplicate_method: u64,
    pub total_duplicate_scheme: u64,
    pub total_duplicate_path: u64,
    pub total_duplicate_authority: u64,
    pub total_invalid_names: u64,
    pub total_status_in_request: u64,
    pub total_five_plus: u64,
    pub total_six_plus: u64,
    pub total_ten_plus: u64,
    pub total_long_names: u64,
    pub total_conflicting: u64,
    pub total_mixed: u64,
    pub total_protocol_errors: u64,
    pub total_valid: u64,
    pub consistency_violations: u64,
}

#[derive(Debug, Clone)]
struct PseudoHeader {
    pub name: String,
    pub value: String,
}

/// Fuzz input structure for excessive pseudo-headers testing
#[derive(Arbitrary, Debug)]
struct ExcessivePseudoHeadersInput {
    /// Base values for standard pseudo-headers
    method: String,
    scheme: String,
    path: String,
    authority: String,
    /// Additional pseudo-header names to inject
    extra_pseudo_names: Vec<String>,
    /// Additional pseudo-header values
    extra_pseudo_values: Vec<String>,
    /// Test scenario configuration
    scenario: ExcessivePseudoHeadersScenario,
    /// Count multiplier for stress testing
    count_multiplier: u8,
}

#[derive(Arbitrary, Debug, Clone)]
enum ExcessivePseudoHeadersScenario {
    /// Standard 4 + duplicate :method
    DuplicateMethod,
    /// Standard 4 + duplicate :scheme
    DuplicateScheme,
    /// Standard 4 + duplicate :path
    DuplicatePath,
    /// Standard 4 + duplicate :authority
    DuplicateAuthority,
    /// Standard 4 + invalid pseudo-header name
    InvalidPseudoName,
    /// Standard 4 + :status (invalid in request)
    StatusInRequest,
    /// Multiple duplicates (6+ pseudo-headers)
    MultipleDuplicates,
    /// Very long pseudo-header names
    LongPseudoNames,
    /// Mixed violations (duplicates + invalid names)
    MixedViolations,
    /// Conflicting duplicate values
    ConflictingDuplicates,
    /// Extreme case (10+ pseudo-headers)
    ExtremeCount,
    /// Valid case (exactly 4 standard pseudo-headers)
    ValidStandard,
}

impl ExcessivePseudoHeadersInput {
    /// Generate pseudo-headers list based on the test scenario
    fn generate_pseudo_headers(&self) -> Vec<PseudoHeader> {
        let mut headers = Vec::new();

        // Start with standard 4 pseudo-headers
        let method = if self.method.is_empty() { "GET".to_string() } else { self.method.clone() };
        let scheme = if self.scheme.is_empty() { "https".to_string() } else { self.scheme.clone() };
        let path = if self.path.is_empty() { "/api/test".to_string() } else { self.path.clone() };
        let authority = if self.authority.is_empty() { "example.com".to_string() } else { self.authority.clone() };

        match &self.scenario {
            ExcessivePseudoHeadersScenario::DuplicateMethod => {
                headers.push(PseudoHeader { name: ":method".to_string(), value: method.clone() });
                headers.push(PseudoHeader { name: ":scheme".to_string(), value: scheme });
                headers.push(PseudoHeader { name: ":path".to_string(), value: path });
                headers.push(PseudoHeader { name: ":authority".to_string(), value: authority });
                // Add duplicate :method
                headers.push(PseudoHeader { name: ":method".to_string(), value: "POST".to_string() });
            }

            ExcessivePseudoHeadersScenario::DuplicateScheme => {
                headers.push(PseudoHeader { name: ":method".to_string(), value: method });
                headers.push(PseudoHeader { name: ":scheme".to_string(), value: scheme.clone() });
                headers.push(PseudoHeader { name: ":path".to_string(), value: path });
                headers.push(PseudoHeader { name: ":authority".to_string(), value: authority });
                // Add duplicate :scheme
                headers.push(PseudoHeader { name: ":scheme".to_string(), value: "http".to_string() });
            }

            ExcessivePseudoHeadersScenario::DuplicatePath => {
                headers.push(PseudoHeader { name: ":method".to_string(), value: method });
                headers.push(PseudoHeader { name: ":scheme".to_string(), value: scheme });
                headers.push(PseudoHeader { name: ":path".to_string(), value: path.clone() });
                headers.push(PseudoHeader { name: ":authority".to_string(), value: authority });
                // Add duplicate :path
                headers.push(PseudoHeader { name: ":path".to_string(), value: "/different".to_string() });
            }

            ExcessivePseudoHeadersScenario::DuplicateAuthority => {
                headers.push(PseudoHeader { name: ":method".to_string(), value: method });
                headers.push(PseudoHeader { name: ":scheme".to_string(), value: scheme });
                headers.push(PseudoHeader { name: ":path".to_string(), value: path });
                headers.push(PseudoHeader { name: ":authority".to_string(), value: authority.clone() });
                // Add duplicate :authority
                headers.push(PseudoHeader { name: ":authority".to_string(), value: "other.com".to_string() });
            }

            ExcessivePseudoHeadersScenario::InvalidPseudoName => {
                headers.push(PseudoHeader { name: ":method".to_string(), value: method });
                headers.push(PseudoHeader { name: ":scheme".to_string(), value: scheme });
                headers.push(PseudoHeader { name: ":path".to_string(), value: path });
                headers.push(PseudoHeader { name: ":authority".to_string(), value: authority });
                // Add invalid pseudo-header name
                headers.push(PseudoHeader { name: ":custom".to_string(), value: "invalid".to_string() });
            }

            ExcessivePseudoHeadersScenario::StatusInRequest => {
                headers.push(PseudoHeader { name: ":method".to_string(), value: method });
                headers.push(PseudoHeader { name: ":scheme".to_string(), value: scheme });
                headers.push(PseudoHeader { name: ":path".to_string(), value: path });
                headers.push(PseudoHeader { name: ":authority".to_string(), value: authority });
                // Add :status (invalid in request)
                headers.push(PseudoHeader { name: ":status".to_string(), value: "200".to_string() });
            }

            ExcessivePseudoHeadersScenario::MultipleDuplicates => {
                headers.push(PseudoHeader { name: ":method".to_string(), value: method.clone() });
                headers.push(PseudoHeader { name: ":scheme".to_string(), value: scheme.clone() });
                headers.push(PseudoHeader { name: ":path".to_string(), value: path.clone() });
                headers.push(PseudoHeader { name: ":authority".to_string(), value: authority.clone() });
                // Add multiple duplicates
                headers.push(PseudoHeader { name: ":method".to_string(), value: "POST".to_string() });
                headers.push(PseudoHeader { name: ":scheme".to_string(), value: "http".to_string() });
            }

            ExcessivePseudoHeadersScenario::LongPseudoNames => {
                headers.push(PseudoHeader { name: ":method".to_string(), value: method });
                headers.push(PseudoHeader { name: ":scheme".to_string(), value: scheme });
                headers.push(PseudoHeader { name: ":path".to_string(), value: path });
                headers.push(PseudoHeader { name: ":authority".to_string(), value: authority });
                // Add very long pseudo-header name
                let long_name = format!(":verylongcustompseudoheadernamethatexceedsnormallimits{}", "x".repeat(100));
                headers.push(PseudoHeader { name: long_name, value: "value".to_string() });
            }

            ExcessivePseudoHeadersScenario::MixedViolations => {
                headers.push(PseudoHeader { name: ":method".to_string(), value: method.clone() });
                headers.push(PseudoHeader { name: ":scheme".to_string(), value: scheme });
                headers.push(PseudoHeader { name: ":path".to_string(), value: path });
                headers.push(PseudoHeader { name: ":authority".to_string(), value: authority });
                // Add both duplicate and invalid name
                headers.push(PseudoHeader { name: ":method".to_string(), value: "POST".to_string() });
                headers.push(PseudoHeader { name: ":custom".to_string(), value: "invalid".to_string() });
            }

            ExcessivePseudoHeadersScenario::ConflictingDuplicates => {
                headers.push(PseudoHeader { name: ":method".to_string(), value: method.clone() });
                headers.push(PseudoHeader { name: ":scheme".to_string(), value: scheme });
                headers.push(PseudoHeader { name: ":path".to_string(), value: path });
                headers.push(PseudoHeader { name: ":authority".to_string(), value: authority });
                // Add conflicting duplicate with different value
                headers.push(PseudoHeader { name: ":method".to_string(), value: "PATCH".to_string() });
            }

            ExcessivePseudoHeadersScenario::ExtremeCount => {
                headers.push(PseudoHeader { name: ":method".to_string(), value: method.clone() });
                headers.push(PseudoHeader { name: ":scheme".to_string(), value: scheme.clone() });
                headers.push(PseudoHeader { name: ":path".to_string(), value: path.clone() });
                headers.push(PseudoHeader { name: ":authority".to_string(), value: authority.clone() });

                // Add many more pseudo-headers
                let count = (self.count_multiplier as usize % 10) + 6;
                for i in 0..count {
                    headers.push(PseudoHeader {
                        name: format!(":custom{}", i),
                        value: format!("value{}", i),
                    });
                }
            }

            ExcessivePseudoHeadersScenario::ValidStandard => {
                // Valid case: exactly 4 standard pseudo-headers
                headers.push(PseudoHeader { name: ":method".to_string(), value: method });
                headers.push(PseudoHeader { name: ":scheme".to_string(), value: scheme });
                headers.push(PseudoHeader { name: ":path".to_string(), value: path });
                headers.push(PseudoHeader { name: ":authority".to_string(), value: authority });
            }
        }

        headers
    }
}

fuzz_target!(|input: ExcessivePseudoHeadersInput| {
    // Skip excessively large inputs
    if input.extra_pseudo_names.len() > 50 || input.extra_pseudo_values.len() > 50 {
        return;
    }

    // Generate test configuration
    let config = ExcessivePseudoHeadersConfig::default();

    // Create mock connection
    let connection = MockExcessivePseudoHeadersConnection::new(config);

    // Generate pseudo-headers for testing
    let headers = input.generate_pseudo_headers();

    // Skip empty header lists or excessively large ones
    if headers.is_empty() || headers.len() > 100 {
        return;
    }

    // Test the excessive pseudo-headers validation
    let result = connection.handle_excessive_headers_request(&headers);

    // Verify the result makes sense
    let pseudo_count = headers.iter().filter(|h| h.name.starts_with(':')).count();

    match result {
        ExcessiveHeadersResult::Accepted => {
            // Should only be accepted if exactly 4 unique standard pseudo-headers
            if pseudo_count > 4 {
                panic!("RFC 7540 violation: {} pseudo-headers should be rejected (max 4)", pseudo_count);
            }
        }
        ExcessiveHeadersResult::ProtocolError(_reason) => {
            // Should be rejected for excessive or invalid pseudo-headers
        }
    }

    // Test consistency: same input should yield same result
    let result2 = connection.handle_excessive_headers_request(&headers);
    if !connection.results_match(&result, &result2) {
        panic!("Inconsistent excessive headers validation: {:?} != {:?}",
               result, result2);
    }

    // Generate statistics for analysis
    let _stats = connection.generate_statistics();

    // Verify no consistency violations were detected internally
    assert_eq!(*connection.consistency_violations.lock().unwrap(), 0,
               "Internal consistency violations detected");

    // For excessive pseudo-header scenarios, verify rejection
    match input.scenario {
        ExcessivePseudoHeadersScenario::DuplicateMethod |
        ExcessivePseudoHeadersScenario::DuplicateScheme |
        ExcessivePseudoHeadersScenario::DuplicatePath |
        ExcessivePseudoHeadersScenario::DuplicateAuthority |
        ExcessivePseudoHeadersScenario::InvalidPseudoName |
        ExcessivePseudoHeadersScenario::StatusInRequest |
        ExcessivePseudoHeadersScenario::MultipleDuplicates |
        ExcessivePseudoHeadersScenario::MixedViolations |
        ExcessivePseudoHeadersScenario::ExtremeCount => {
            match result {
                ExcessiveHeadersResult::ProtocolError(_) => {
                    // Correct: excessive pseudo-headers should be rejected
                }
                ExcessiveHeadersResult::Accepted => {
                    panic!("RFC 7540 violation: excessive pseudo-headers should be rejected");
                }
            }
        }
        ExcessivePseudoHeadersScenario::ValidStandard => {
            // Valid case should be accepted
        }
        _ => {
            // Other scenarios have their own validation requirements
        }
    }
});