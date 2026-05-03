#![no_main]
//! HTTP/2 :path pseudo-header invalid format fuzz target
//!
//! Tests handling of :path pseudo-headers that do NOT start with "/" which
//! violates RFC 9110 requirements. Per RFC 9110, the path component MUST
//! begin with "/" for origin-form requests or be an absolute URI. Relative
//! paths like "foo/bar" are invalid in HTTP/2 :path pseudo-headers.
//!
//! Primary test scenario: :path with relative paths like "foo/bar", "api/test"
//!
//! Additional test scenarios:
//! - Complex relative paths with ".." components ("../admin", "../../etc")
//! - Paths with query strings but no leading slash ("foo?query=1")
//! - Paths with fragments but no leading slash ("foo#fragment")
//! - Empty path ("")
//! - Single character non-slash paths ("a", ".", "..")
//! - Paths starting with query/fragment markers ("?query", "#fragment")
//! - Very long relative paths (buffer testing)
//! - Relative paths with encoded characters ("foo%2Fbar")
//!
//! RFC references:
//! - RFC 9110 §4.1: Request target must be absolute-form or origin-form
//! - RFC 9110 §4.2.1: Origin-form MUST start with "/"
//! - RFC 7540 §8.1.2.3: :path pseudo-header requirements
//! - RFC 3986 §3.3: Path component syntax

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Configuration for invalid path testing scenarios
#[derive(Debug, Clone)]
struct InvalidPathTestConfig {
    /// Include simple relative paths
    pub include_simple_relative: bool,
    /// Include complex relative paths with ".." components
    pub include_complex_relative: bool,
    /// Include paths with query strings
    pub include_query_paths: bool,
    /// Include paths with fragments
    pub include_fragment_paths: bool,
    /// Include very long relative paths
    pub include_long_paths: bool,
}

impl Default for InvalidPathTestConfig {
    fn default() -> Self {
        Self {
            include_simple_relative: true,
            include_complex_relative: true,
            include_query_paths: true,
            include_fragment_paths: true,
            include_long_paths: true,
        }
    }
}

/// Mock HTTP/2 connection for invalid path validation testing
#[derive(Debug)]
struct MockInvalidPathConnection {
    /// Count of requests with simple relative paths
    pub simple_relative_paths: Arc<Mutex<u64>>,
    /// Count of requests with complex relative paths (containing "..")
    pub complex_relative_paths: Arc<Mutex<u64>>,
    /// Count of requests with query strings but no leading slash
    pub query_without_slash: Arc<Mutex<u64>>,
    /// Count of requests with fragments but no leading slash
    pub fragment_without_slash: Arc<Mutex<u64>>,
    /// Count of requests with empty :path
    pub empty_paths: Arc<Mutex<u64>>,
    /// Count of requests with single character non-slash paths
    pub single_char_paths: Arc<Mutex<u64>>,
    /// Count of requests with directory traversal attempts
    pub traversal_attempts: Arc<Mutex<u64>>,
    /// Count of requests with encoded characters in relative paths
    pub encoded_relative_paths: Arc<Mutex<u64>>,
    /// Count of requests with very long relative paths
    pub long_relative_paths: Arc<Mutex<u64>>,
    /// Count of BAD_REQUEST responses for invalid paths
    pub bad_request_responses: Arc<Mutex<u64>>,
    /// Count of PROTOCOL_ERROR responses for malformed paths
    pub protocol_errors: Arc<Mutex<u64>>,
    /// Count of valid requests (paths starting with "/" or absolute URIs)
    pub valid_requests: Arc<Mutex<u64>>,
    /// Track consistency violations (same input, different response)
    pub consistency_violations: Arc<Mutex<u64>>,
    /// Configuration for this test session
    pub config: InvalidPathTestConfig,
    /// Cache of previous decisions for consistency checking
    pub decision_cache: Arc<Mutex<HashMap<String, PathResult>>>,
}

impl MockInvalidPathConnection {
    fn new(config: InvalidPathTestConfig) -> Self {
        Self {
            simple_relative_paths: Arc::new(Mutex::new(0)),
            complex_relative_paths: Arc::new(Mutex::new(0)),
            query_without_slash: Arc::new(Mutex::new(0)),
            fragment_without_slash: Arc::new(Mutex::new(0)),
            empty_paths: Arc::new(Mutex::new(0)),
            single_char_paths: Arc::new(Mutex::new(0)),
            traversal_attempts: Arc::new(Mutex::new(0)),
            encoded_relative_paths: Arc::new(Mutex::new(0)),
            long_relative_paths: Arc::new(Mutex::new(0)),
            bad_request_responses: Arc::new(Mutex::new(0)),
            protocol_errors: Arc::new(Mutex::new(0)),
            valid_requests: Arc::new(Mutex::new(0)),
            consistency_violations: Arc::new(Mutex::new(0)),
            config,
            decision_cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Process HTTP/2 request with :path validation
    fn handle_path_request(&self, path: &str) -> PathResult {
        // Analyze path characteristics
        let analysis = self.analyze_path(path);

        // Track various path types
        if analysis.is_empty {
            *self.empty_paths.lock().unwrap() += 1;
        }

        if analysis.is_simple_relative {
            *self.simple_relative_paths.lock().unwrap() += 1;
        }

        if analysis.is_complex_relative {
            *self.complex_relative_paths.lock().unwrap() += 1;
        }

        if analysis.has_query_without_slash {
            *self.query_without_slash.lock().unwrap() += 1;
        }

        if analysis.has_fragment_without_slash {
            *self.fragment_without_slash.lock().unwrap() += 1;
        }

        if analysis.is_single_char_non_slash {
            *self.single_char_paths.lock().unwrap() += 1;
        }

        if analysis.has_traversal_attempt {
            *self.traversal_attempts.lock().unwrap() += 1;
        }

        if analysis.has_encoded_chars {
            *self.encoded_relative_paths.lock().unwrap() += 1;
        }

        if analysis.is_long_relative {
            *self.long_relative_paths.lock().unwrap() += 1;
        }

        // Determine if path is valid per RFC 9110
        let is_valid_path = self.validate_path_format(path, &analysis);

        // Check consistency with previous decisions
        let mut cache = self.decision_cache.lock().unwrap();
        let result = if is_valid_path {
            *self.valid_requests.lock().unwrap() += 1;
            PathResult::Accepted
        } else {
            if analysis.is_malformed {
                *self.protocol_errors.lock().unwrap() += 1;
                PathResult::ProtocolError("Malformed path syntax")
            } else {
                *self.bad_request_responses.lock().unwrap() += 1;
                PathResult::BadRequest("Path must start with '/' or be absolute URI")
            }
        };

        // Consistency check
        if let Some(previous_result) = cache.get(path) {
            if !self.results_match(&result, previous_result) {
                *self.consistency_violations.lock().unwrap() += 1;
            }
        } else {
            cache.insert(path.to_string(), result.clone());
        }

        result
    }

    /// Analyze path characteristics for classification
    fn analyze_path(&self, path: &str) -> PathAnalysis {
        let mut analysis = PathAnalysis::default();

        // Basic checks
        analysis.is_empty = path.is_empty();
        analysis.starts_with_slash = path.starts_with('/');
        analysis.is_absolute_uri = path.starts_with("http://") || path.starts_with("https://");

        // Length checks
        analysis.is_long_relative = path.len() > 1024 && !analysis.starts_with_slash && !analysis.is_absolute_uri;

        // Single character checks
        analysis.is_single_char_non_slash = path.len() == 1 && !analysis.starts_with_slash;

        // Relative path detection
        if !analysis.starts_with_slash && !analysis.is_absolute_uri && !analysis.is_empty {
            // Check if it's a simple relative path (no ".." components)
            if !path.contains("..") {
                analysis.is_simple_relative = true;
            } else {
                analysis.is_complex_relative = true;
                analysis.has_traversal_attempt = true;
            }
        }

        // Query and fragment checks (without leading slash)
        if !analysis.starts_with_slash && !analysis.is_absolute_uri {
            if path.contains('?') {
                analysis.has_query_without_slash = true;
            }
            if path.contains('#') {
                analysis.has_fragment_without_slash = true;
            }
        }

        // Encoded character detection
        analysis.has_encoded_chars = path.contains('%');

        // Malformed path detection
        analysis.is_malformed = self.detect_malformed_path(path);

        analysis
    }

    /// Detect malformed path syntax
    fn detect_malformed_path(&self, path: &str) -> bool {
        // Check for invalid percent encoding
        let mut chars = path.chars().peekable();
        while let Some(ch) = chars.next() {
            if ch == '%' {
                // Must be followed by exactly two hex digits
                let hex1 = chars.next();
                let hex2 = chars.next();
                match (hex1, hex2) {
                    (Some(h1), Some(h2)) => {
                        if !h1.is_ascii_hexdigit() || !h2.is_ascii_hexdigit() {
                            return true;
                        }
                    }
                    _ => return true, // Incomplete percent encoding
                }
            }
        }

        // Check for other malformed patterns
        path.contains('\0') || // Null bytes
        path.contains('\r') || path.contains('\n') || // Line breaks
        path.ends_with('%') // Incomplete percent encoding at end
    }

    /// Validate path format per RFC 9110 requirements
    fn validate_path_format(&self, path: &str, analysis: &PathAnalysis) -> bool {
        // RFC 9110: path must be origin-form (starts with "/") or absolute URI
        if analysis.is_empty {
            return false; // Empty path is invalid
        }

        if analysis.is_malformed {
            return false; // Malformed syntax is always invalid
        }

        if analysis.is_absolute_uri {
            return true; // Absolute URIs are valid
        }

        if analysis.starts_with_slash {
            return true; // Origin-form paths are valid
        }

        // All other forms (relative paths) are invalid in HTTP/2 :path
        false
    }

    /// Check if two results match (for consistency validation)
    fn results_match(&self, result1: &PathResult, result2: &PathResult) -> bool {
        match (result1, result2) {
            (PathResult::Accepted, PathResult::Accepted) => true,
            (PathResult::BadRequest(_), PathResult::BadRequest(_)) => true,
            (PathResult::ProtocolError(_), PathResult::ProtocolError(_)) => true,
            _ => false,
        }
    }

    /// Generate summary statistics
    fn generate_statistics(&self) -> InvalidPathStatistics {
        InvalidPathStatistics {
            total_simple_relative: *self.simple_relative_paths.lock().unwrap(),
            total_complex_relative: *self.complex_relative_paths.lock().unwrap(),
            total_query_without_slash: *self.query_without_slash.lock().unwrap(),
            total_fragment_without_slash: *self.fragment_without_slash.lock().unwrap(),
            total_empty_paths: *self.empty_paths.lock().unwrap(),
            total_single_char: *self.single_char_paths.lock().unwrap(),
            total_traversal_attempts: *self.traversal_attempts.lock().unwrap(),
            total_encoded_relative: *self.encoded_relative_paths.lock().unwrap(),
            total_long_relative: *self.long_relative_paths.lock().unwrap(),
            total_bad_requests: *self.bad_request_responses.lock().unwrap(),
            total_protocol_errors: *self.protocol_errors.lock().unwrap(),
            total_valid: *self.valid_requests.lock().unwrap(),
            consistency_violations: *self.consistency_violations.lock().unwrap(),
        }
    }
}

#[derive(Debug, Default)]
struct PathAnalysis {
    pub is_empty: bool,
    pub starts_with_slash: bool,
    pub is_absolute_uri: bool,
    pub is_simple_relative: bool,
    pub is_complex_relative: bool,
    pub has_query_without_slash: bool,
    pub has_fragment_without_slash: bool,
    pub is_single_char_non_slash: bool,
    pub has_traversal_attempt: bool,
    pub has_encoded_chars: bool,
    pub is_long_relative: bool,
    pub is_malformed: bool,
}

#[derive(Debug, Clone)]
enum PathResult {
    Accepted,
    BadRequest(&'static str),
    ProtocolError(&'static str),
}

#[derive(Debug)]
struct InvalidPathStatistics {
    pub total_simple_relative: u64,
    pub total_complex_relative: u64,
    pub total_query_without_slash: u64,
    pub total_fragment_without_slash: u64,
    pub total_empty_paths: u64,
    pub total_single_char: u64,
    pub total_traversal_attempts: u64,
    pub total_encoded_relative: u64,
    pub total_long_relative: u64,
    pub total_bad_requests: u64,
    pub total_protocol_errors: u64,
    pub total_valid: u64,
    pub consistency_violations: u64,
}

/// Fuzz input structure for invalid path testing
#[derive(Arbitrary, Debug)]
struct InvalidPathInput {
    /// Base path component
    base_path: String,
    /// Additional path segments
    path_segments: Vec<String>,
    /// Query string (without leading ?)
    query_string: String,
    /// Fragment (without leading #)
    fragment: String,
    /// Test scenario configuration
    scenario: InvalidPathScenario,
    /// Path length multiplier
    length_multiplier: u8,
}

#[derive(Arbitrary, Debug, Clone)]
enum InvalidPathScenario {
    /// Primary: simple relative path like "foo/bar"
    SimpleRelative,
    /// Complex relative path with ".." like "../admin"
    ComplexRelative,
    /// Path with query but no leading slash
    QueryWithoutSlash,
    /// Path with fragment but no leading slash
    FragmentWithoutSlash,
    /// Empty path
    EmptyPath,
    /// Single character paths
    SingleCharacter,
    /// Directory traversal attempts
    DirectoryTraversal,
    /// Encoded relative paths
    EncodedRelative,
    /// Very long relative paths
    LongRelative,
    /// Valid paths (for comparison)
    ValidPath,
    /// Malformed paths
    MalformedPath,
}

impl InvalidPathInput {
    /// Generate path string based on the test scenario
    fn generate_path(&self) -> String {
        match &self.scenario {
            InvalidPathScenario::SimpleRelative => {
                // Primary test case: relative path without leading slash
                if self.path_segments.is_empty() {
                    format!("api/{}", self.base_path.trim_start_matches('/'))
                } else {
                    let mut path = self.base_path.trim_start_matches('/').to_string();
                    for segment in &self.path_segments {
                        if !segment.is_empty() {
                            path.push('/');
                            path.push_str(segment.trim_start_matches('/'));
                        }
                    }
                    if path.is_empty() {
                        "foo/bar".to_string()
                    } else {
                        path
                    }
                }
            }

            InvalidPathScenario::ComplexRelative => {
                format!("../admin/{}/../../etc/{}",
                       self.base_path.trim_start_matches('/'),
                       self.path_segments.get(0).unwrap_or(&"passwd".to_string()))
            }

            InvalidPathScenario::QueryWithoutSlash => {
                let base = if self.base_path.is_empty() { "api" } else { &self.base_path };
                let query = if self.query_string.is_empty() { "param=value" } else { &self.query_string };
                format!("{}?{}", base.trim_start_matches('/'), query)
            }

            InvalidPathScenario::FragmentWithoutSlash => {
                let base = if self.base_path.is_empty() { "api" } else { &self.base_path };
                let fragment = if self.fragment.is_empty() { "section" } else { &self.fragment };
                format!("{}#{}", base.trim_start_matches('/'), fragment)
            }

            InvalidPathScenario::EmptyPath => {
                String::new()
            }

            InvalidPathScenario::SingleCharacter => {
                let chars = ["a", ".", "..", "?", "#", "%", "~"];
                let index = (self.length_multiplier as usize) % chars.len();
                chars[index].to_string()
            }

            InvalidPathScenario::DirectoryTraversal => {
                let mut path = String::new();
                let repeat_count = (self.length_multiplier as usize % 10) + 1;
                for _ in 0..repeat_count {
                    path.push_str("../");
                }
                path.push_str("etc/passwd");
                path
            }

            InvalidPathScenario::EncodedRelative => {
                format!("{}%2F{}%3F{}%23{}",
                       self.base_path.trim_start_matches('/'),
                       self.path_segments.get(0).unwrap_or(&"encoded".to_string()),
                       self.query_string,
                       self.fragment)
            }

            InvalidPathScenario::LongRelative => {
                let mut path = String::new();
                let repeat_count = (self.length_multiplier as usize).max(1);
                for i in 0..repeat_count {
                    if i > 0 {
                        path.push('/');
                    }
                    path.push_str(&format!("segment{}", i));
                    if path.len() > 2048 {
                        break;
                    }
                }
                path
            }

            InvalidPathScenario::ValidPath => {
                // Valid path for comparison (starts with /)
                let mut path = String::from("/");
                if !self.base_path.is_empty() {
                    path.push_str(self.base_path.trim_start_matches('/'));
                } else {
                    path.push_str("api/valid");
                }
                for segment in &self.path_segments {
                    if !segment.is_empty() {
                        path.push('/');
                        path.push_str(segment);
                    }
                }
                path
            }

            InvalidPathScenario::MalformedPath => {
                // Malformed percent encoding
                format!("{}%GG{}", self.base_path.trim_start_matches('/'),
                       self.path_segments.get(0).unwrap_or(&"malformed".to_string()))
            }
        }
    }
}

fuzz_target!(|input: InvalidPathInput| {
    // Skip excessively large inputs
    if input.path_segments.len() > 100 {
        return;
    }

    // Generate test configuration
    let config = InvalidPathTestConfig::default();

    // Create mock connection
    let connection = MockInvalidPathConnection::new(config);

    // Generate path for testing
    let path = input.generate_path();

    // Limit path length to prevent OOM
    if path.len() > 16384 {
        return;
    }

    // Test the path validation
    let result = connection.handle_path_request(&path);

    // Verify the result makes sense
    match result {
        PathResult::Accepted => {
            // Should only be accepted if path starts with "/" or is absolute URI
            if !path.starts_with('/') && !path.starts_with("http://") && !path.starts_with("https://") {
                panic!("RFC 9110 violation: relative path '{}' should be rejected", path);
            }
        }
        PathResult::BadRequest(_reason) => {
            // Should be rejected for relative paths
        }
        PathResult::ProtocolError(_reason) => {
            // Should be rejected for malformed paths
        }
    }

    // Test consistency: same input should yield same result
    let result2 = connection.handle_path_request(&path);
    if !connection.results_match(&result, &result2) {
        panic!("Inconsistent path validation: {:?} != {:?} for path: '{}'",
               result, result2, path);
    }

    // Generate statistics for analysis
    let _stats = connection.generate_statistics();

    // Verify no consistency violations were detected internally
    assert_eq!(*connection.consistency_violations.lock().unwrap(), 0,
               "Internal consistency violations detected");

    // For the primary test case (simple relative), verify rejection
    match input.scenario {
        InvalidPathScenario::SimpleRelative => {
            if !path.starts_with('/') && !path.starts_with("http") {
                match result {
                    PathResult::BadRequest(_) => {
                        // Correct: relative path should be rejected
                    }
                    PathResult::ProtocolError(_) => {
                        // Also correct if treated as protocol error
                    }
                    PathResult::Accepted => {
                        panic!("RFC 9110 violation: simple relative path '{}' should be rejected", path);
                    }
                }
            }
        }
        _ => {
            // Other scenarios have their own validation requirements
        }
    }
});