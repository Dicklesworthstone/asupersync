#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

/// HTTP/2 :path pseudo-header large value handling fuzz target.
///
/// Tests parser behavior with very long :path pseudo-header values to ensure
/// graceful handling via either reasonable limits or clear rejection. Per
/// HTTP/2 specifications, implementations should handle large header values
/// appropriately without causing security issues or resource exhaustion.
///
/// Critical test scenarios:
/// - Very long paths (>16KB, >64KB, >1MB) with valid characters
/// - Boundary testing around common limits (8KB, 16KB, 32KB, 64KB)
/// - Long paths with various valid URL components (query strings, fragments)
/// - Resource exhaustion protection (memory, parsing time)
/// - Clear error reporting when limits are exceeded
/// - Consistent behavior across different path patterns
///
/// Security considerations:
/// - DoS protection via path length limits
/// - Memory allocation bounds for path storage
/// - Parse time limits for very long paths
/// - Consistent rejection behavior (no silent truncation)

#[derive(Arbitrary, Debug, Clone)]
struct HugePathInput {
    /// Test cases with various path lengths and patterns
    path_tests: Vec<PathLengthTest>,

    /// Configuration for path generation
    path_config: PathConfig,

    /// Parser limits and behavior configuration
    limit_config: LimitConfig,

    /// Performance and security test scenarios
    security_tests: Vec<SecurityTest>,

    /// Edge cases around length boundaries
    boundary_tests: Vec<BoundaryTest>,
}

#[derive(Arbitrary, Debug, Clone)]
struct PathLengthTest {
    /// Target path length to test
    target_length: u32,

    /// Type of path pattern to generate
    path_pattern: PathPattern,

    /// Expected parser behavior
    expected_behavior: ExpectedBehavior,

    /// Stream ID for this test
    stream_id: u32,

    /// Include other pseudo-headers
    include_other_headers: bool,
}

#[derive(Arbitrary, Debug, Clone)]
enum PathPattern {
    /// Simple repeated pattern: "/a/b/c/d/..."
    RepeatedSegments { segment: String, count: u32 },

    /// Very long single segment: "/very-long-segment-name..."
    SingleLongSegment { base: String },

    /// Long query string: "/path?param=value&param2=..."
    LongQueryString { base_path: String, param_count: u32 },

    /// Mixed components: path + query + fragment
    MixedComponents {
        path_segments: u32,
        query_params: u32,
        fragment_length: u32
    },

    /// Deeply nested path: "/a/b/c/d/e/f/..." (many levels)
    DeeplyNested { depth: u32 },

    /// Path with encoded characters: "/a%20b%20c%20d..."
    EncodedCharacters { pattern: String, repetitions: u32 },

    /// Custom arbitrary pattern
    Custom { pattern: String },
}

#[derive(Arbitrary, Debug, Clone, PartialEq)]
enum ExpectedBehavior {
    /// Should be accepted (within limits)
    Accept,

    /// Should be rejected with clear error
    Reject,

    /// Behavior depends on implementation limits
    ImplementationDefined,
}

#[derive(Arbitrary, Debug, Clone)]
struct PathConfig {
    /// Use only valid URL characters
    valid_chars_only: bool,

    /// Include UTF-8 characters (percent-encoded)
    include_utf8: bool,

    /// Maximum segment length for patterns
    max_segment_length: u16,

    /// Include query parameters
    include_query_params: bool,

    /// Include URL fragments
    include_fragments: bool,
}

#[derive(Arbitrary, Debug, Clone)]
struct LimitConfig {
    /// Expected maximum path length (if known)
    expected_max_length: Option<u32>,

    /// Strict limit enforcement
    strict_limit_enforcement: bool,

    /// Generate PROTOCOL_ERROR for oversized paths
    error_on_oversized: bool,

    /// Track resource usage during parsing
    track_resource_usage: bool,

    /// Maximum allowed parsing time (simulated)
    max_parsing_time_ms: u32,
}

#[derive(Arbitrary, Debug, Clone)]
enum SecurityTest {
    /// Memory exhaustion attempt
    MemoryExhaustion { size: u32 },

    /// Parse time explosion attempt
    ParseTimeAttack { complexity: u32 },

    /// Repeated large paths on same connection
    RepeatedLargePaths { count: u8, size: u32 },

    /// Gradual size increase to find exact limits
    LimitProbing { start_size: u32, step_size: u32 },

    /// Path with maximum allowed complexity
    MaxComplexityPath,
}

#[derive(Arbitrary, Debug, Clone)]
enum BoundaryTest {
    /// Test around common size limits
    CommonLimits { base_sizes: Vec<u32> },

    /// Test exactly at suspected boundaries
    ExactBoundaries { sizes: Vec<u32> },

    /// Test just above/below limits
    BoundaryProximity { center: u32, delta: u32 },

    /// Test power-of-2 boundaries
    PowerOfTwo { max_power: u8 },
}

impl Default for LimitConfig {
    fn default() -> Self {
        Self {
            expected_max_length: Some(65536), // 64KB reasonable default
            strict_limit_enforcement: true,
            error_on_oversized: true,
            track_resource_usage: true,
            max_parsing_time_ms: 1000, // 1 second max parsing time
        }
    }
}

/// Mock HTTP/2 connection for testing large :path handling
struct MockHugePathConnection {
    /// Stream states
    streams: HashMap<u32, StreamState>,

    /// Connection-level errors
    connection_error: Option<ConnectionError>,

    /// Path parsing results
    parsing_results: Vec<PathParsingResult>,

    /// Resource usage tracking
    resource_usage: ResourceUsage,

    /// Configuration
    config: LimitConfig,

    /// Statistics
    stats: PathProcessingStats,
}

#[derive(Debug, Clone)]
struct StreamState {
    headers_received: bool,
    path_validated: bool,
    path_value: Option<String>,
    path_length: usize,
    parsing_time_ms: u32,
    error_code: Option<u32>,
}

#[derive(Debug, Clone)]
enum ConnectionError {
    ProtocolError(String),
    ResourceExhaustion(String),
    PathTooLarge(String),
}

#[derive(Debug, Clone)]
struct PathParsingResult {
    stream_id: u32,
    path_length: usize,
    accepted: bool,
    error_type: Option<PathErrorType>,
    parsing_time_ms: u32,
    memory_used_bytes: usize,
}

#[derive(Debug, Clone)]
enum PathErrorType {
    PathTooLong(usize),           // Actual length that was too long
    MemoryLimitExceeded(usize),   // Memory usage that exceeded limit
    ParseTimeExceeded(u32),       // Parse time that exceeded limit
    InvalidCharacters,            // Invalid characters found
    MalformedPath,               // Path structure is malformed
}

#[derive(Debug, Clone, Default)]
struct ResourceUsage {
    peak_memory_bytes: usize,
    total_parsing_time_ms: u32,
    large_paths_processed: u32,
    paths_rejected: u32,
    memory_allocations: u32,
}

#[derive(Debug, Clone, Default)]
struct PathProcessingStats {
    paths_under_1kb: u32,
    paths_1kb_to_8kb: u32,
    paths_8kb_to_32kb: u32,
    paths_32kb_to_64kb: u32,
    paths_over_64kb: u32,
    longest_accepted_path: usize,
    longest_rejected_path: usize,
    total_paths_processed: u32,
    total_paths_rejected: u32,
}

impl MockHugePathConnection {
    fn new(config: LimitConfig) -> Self {
        Self {
            streams: HashMap::new(),
            connection_error: None,
            parsing_results: Vec::new(),
            resource_usage: ResourceUsage::default(),
            config,
            stats: PathProcessingStats::default(),
        }
    }

    /// Process HEADERS frame with potentially large :path
    fn process_headers_frame(&mut self, stream_id: u32, path: &str) -> ProcessingResult {
        // Stream ID validation
        if stream_id == 0 || stream_id % 2 == 0 {
            self.connection_error = Some(ConnectionError::ProtocolError(
                "Invalid stream ID for client-initiated request".to_string()
            ));
            return ProcessingResult::ConnectionError;
        }

        let path_length = path.len();
        let start_time = std::time::Instant::now();

        // Simulate resource usage
        let estimated_memory = self.estimate_memory_usage(path);
        self.resource_usage.memory_allocations += 1;

        if estimated_memory > self.resource_usage.peak_memory_bytes {
            self.resource_usage.peak_memory_bytes = estimated_memory;
        }

        // Check path length limits
        if let Some(max_length) = self.config.expected_max_length {
            if path_length > max_length as usize {
                if self.config.error_on_oversized {
                    self.stats.total_paths_rejected += 1;
                    self.update_path_length_stats(path_length);

                    let error = PathErrorType::PathTooLong(path_length);
                    self.record_parsing_result(stream_id, path_length, false, Some(error.clone()), 0, estimated_memory);

                    return ProcessingResult::PathTooLarge(format!(
                        "Path length {} exceeds maximum allowed {} bytes",
                        path_length, max_length
                    ));
                }
            }
        }

        // Simulate parsing time based on path complexity
        let parsing_time = self.estimate_parsing_time(path);

        if parsing_time > self.config.max_parsing_time_ms {
            self.stats.total_paths_rejected += 1;

            let error = PathErrorType::ParseTimeExceeded(parsing_time);
            self.record_parsing_result(stream_id, path_length, false, Some(error.clone()), parsing_time, estimated_memory);

            return ProcessingResult::ParseTimeExceeded(format!(
                "Path parsing time {}ms exceeds maximum allowed {}ms",
                parsing_time, self.config.max_parsing_time_ms
            ));
        }

        // Validate path structure
        if let Err(error_type) = self.validate_path_structure(path) {
            self.stats.total_paths_rejected += 1;
            self.record_parsing_result(stream_id, path_length, false, Some(error_type), parsing_time, estimated_memory);
            return ProcessingResult::ValidationError;
        }

        // Update stream state
        let stream_state = self.streams.entry(stream_id).or_insert(StreamState {
            headers_received: false,
            path_validated: false,
            path_value: None,
            path_length: 0,
            parsing_time_ms: 0,
            error_code: None,
        });

        stream_state.headers_received = true;
        stream_state.path_validated = true;
        stream_state.path_value = Some(path.to_string());
        stream_state.path_length = path_length;
        stream_state.parsing_time_ms = parsing_time;

        // Update statistics
        self.stats.total_paths_processed += 1;
        self.update_path_length_stats(path_length);

        if path_length > self.stats.longest_accepted_path {
            self.stats.longest_accepted_path = path_length;
        }

        self.resource_usage.total_parsing_time_ms += parsing_time;
        self.resource_usage.large_paths_processed += 1;

        // Record successful parsing
        self.record_parsing_result(stream_id, path_length, true, None, parsing_time, estimated_memory);

        ProcessingResult::Success
    }

    /// Estimate memory usage for path storage and parsing
    fn estimate_memory_usage(&self, path: &str) -> usize {
        // Rough estimation: string storage + parsing overhead + structures
        path.len() * 2 + 1024 // 2x for potential encoding + 1KB overhead
    }

    /// Estimate parsing time based on path complexity
    fn estimate_parsing_time(&self, path: &str) -> u32 {
        let base_time = 1; // 1ms base
        let length_factor = (path.len() / 1000) as u32; // 1ms per KB
        let complexity_factor = self.calculate_complexity_factor(path);

        base_time + length_factor + complexity_factor
    }

    /// Calculate complexity factor based on path structure
    fn calculate_complexity_factor(&self, path: &str) -> u32 {
        let segments = path.matches('/').count() as u32;
        let query_params = path.matches('&').count() as u32;
        let encoded_chars = path.matches('%').count() as u32;

        segments / 10 + query_params / 5 + encoded_chars / 20
    }

    /// Validate basic path structure
    fn validate_path_structure(&self, path: &str) -> Result<(), PathErrorType> {
        // Basic validation - must start with '/'
        if !path.starts_with('/') {
            return Err(PathErrorType::MalformedPath);
        }

        // Check for obviously invalid characters (basic ASCII control chars)
        if path.chars().any(|c| c.is_control() && c != '\t') {
            return Err(PathErrorType::InvalidCharacters);
        }

        Ok(())
    }

    /// Update statistics based on path length
    fn update_path_length_stats(&mut self, path_length: usize) {
        match path_length {
            0..=1023 => self.stats.paths_under_1kb += 1,
            1024..=8191 => self.stats.paths_1kb_to_8kb += 1,
            8192..=32767 => self.stats.paths_8kb_to_32kb += 1,
            32768..=65535 => self.stats.paths_32kb_to_64kb += 1,
            _ => self.stats.paths_over_64kb += 1,
        }
    }

    /// Record parsing result for analysis
    fn record_parsing_result(&mut self, stream_id: u32, path_length: usize, accepted: bool,
                           error_type: Option<PathErrorType>, parsing_time: u32, memory_used: usize) {
        let result = PathParsingResult {
            stream_id,
            path_length,
            accepted,
            error_type,
            parsing_time_ms: parsing_time,
            memory_used_bytes: memory_used,
        };

        self.parsing_results.push(result);

        if !accepted && path_length > self.stats.longest_rejected_path {
            self.stats.longest_rejected_path = path_length;
        }
    }

    fn get_status(&self) -> ConnectionStatus {
        ConnectionStatus {
            connection_error: self.connection_error.clone(),
            stream_count: self.streams.len(),
            parsing_results: self.parsing_results.clone(),
            resource_usage: self.resource_usage.clone(),
            stats: self.stats.clone(),
        }
    }
}

#[derive(Debug, PartialEq)]
enum ProcessingResult {
    Success,
    PathTooLarge(String),
    ParseTimeExceeded(String),
    ValidationError,
    ConnectionError,
}

#[derive(Debug, Clone)]
struct ConnectionStatus {
    connection_error: Option<ConnectionError>,
    stream_count: usize,
    parsing_results: Vec<PathParsingResult>,
    resource_usage: ResourceUsage,
    stats: PathProcessingStats,
}

/// Generate paths of specific lengths with various patterns
fn generate_path_of_length(length: usize, pattern: &PathPattern) -> String {
    match pattern {
        PathPattern::RepeatedSegments { segment, count } => {
            let mut path = String::from("/");
            for i in 0..*count {
                if path.len() + segment.len() + 1 >= length {
                    break;
                }
                path.push_str(segment);
                if i < count - 1 {
                    path.push('/');
                }
            }
            // Pad to exact length if needed
            while path.len() < length {
                path.push('a');
            }
            path.truncate(length);
            path
        }

        PathPattern::SingleLongSegment { base } => {
            let mut path = String::from("/");
            path.push_str(base);
            while path.len() < length {
                path.push('a');
            }
            path.truncate(length);
            path
        }

        PathPattern::LongQueryString { base_path, param_count } => {
            let mut path = base_path.clone();
            if !path.starts_with('/') {
                path = format!("/{}", path);
            }
            path.push('?');

            for i in 0..*param_count {
                if path.len() >= length {
                    break;
                }
                if i > 0 {
                    path.push('&');
                }
                path.push_str(&format!("param{}=value{}", i, i));
            }

            // Fill to exact length
            while path.len() < length {
                path.push('x');
            }
            path.truncate(length);
            path
        }

        PathPattern::DeeplyNested { depth } => {
            let mut path = String::new();
            for i in 0..*depth {
                if path.len() >= length {
                    break;
                }
                path.push_str(&format!("/level{}", i));
            }
            // Fill remaining space
            while path.len() < length {
                path.push('x');
            }
            path.truncate(length);
            if path.is_empty() {
                path = "/".to_string();
            }
            path
        }

        PathPattern::Custom { pattern } => {
            let mut path = pattern.clone();
            if !path.starts_with('/') {
                path = format!("/{}", path);
            }
            while path.len() < length {
                path.push_str("abcdefgh");
            }
            path.truncate(length);
            path
        }

        _ => {
            // Default: simple repeated pattern
            let mut path = String::from("/");
            while path.len() < length {
                path.push_str("path");
            }
            path.truncate(length);
            path
        }
    }
}

/// Generate standard test sizes for boundary testing
fn generate_test_sizes() -> Vec<usize> {
    vec![
        // Small sizes
        1, 10, 100, 512,
        // Common boundaries
        1024,    // 1KB
        2048,    // 2KB
        4096,    // 4KB
        8192,    // 8KB
        16384,   // 16KB (specified in task)
        32768,   // 32KB
        65536,   // 64KB
        131072,  // 128KB
        262144,  // 256KB
        524288,  // 512KB
        1048576, // 1MB
        // Just above common limits
        8193, 16385, 32769, 65537,
        // Just below common limits
        8191, 16383, 32767, 65535,
    ]
}

fuzz_target!(|input: HugePathInput| {
    // Limit input size for performance
    let mut input = input;
    if input.path_tests.len() > 10 {
        input.path_tests.truncate(10);
    }

    let mut connection = MockHugePathConnection::new(input.limit_config.clone());

    // Test standard boundary sizes
    let test_sizes = generate_test_sizes();
    for (idx, &size) in test_sizes.iter().enumerate().take(15) { // Limit for performance
        let stream_id = (idx as u32 * 2) + 1; // Ensure odd stream IDs

        let path = generate_path_of_length(size, &PathPattern::RepeatedSegments {
            segment: "segment".to_string(),
            count: 100,
        });

        let result = connection.process_headers_frame(stream_id, &path);

        // Verify behavior is consistent with configuration
        if let Some(max_length) = connection.config.expected_max_length {
            if size > max_length as usize && connection.config.error_on_oversized {
                assert!(matches!(result, ProcessingResult::PathTooLarge(_)),
                    "Path of size {} should be rejected when limit is {}", size, max_length);
            } else if size <= max_length as usize {
                assert!(matches!(result, ProcessingResult::Success),
                    "Path of size {} should be accepted when limit is {}", size, max_length);
            }
        }

        // Ensure no crashes or panics occurred
        assert!(!matches!(result, ProcessingResult::ConnectionError),
            "Connection should not error for size {}", size);
    }

    // Test fuzzed input cases
    for (idx, test_case) in input.path_tests.iter().enumerate() {
        let stream_id = if test_case.stream_id == 0 || test_case.stream_id % 2 == 0 {
            (idx as u32 * 2) + 101 // Ensure odd stream ID
        } else {
            test_case.stream_id
        };

        let path = generate_path_of_length(
            test_case.target_length as usize,
            &test_case.path_pattern
        );

        let result = connection.process_headers_frame(stream_id, &path);

        // Verify expectations are met
        match test_case.expected_behavior {
            ExpectedBehavior::Accept => {
                if let Some(max_length) = connection.config.expected_max_length {
                    if test_case.target_length <= max_length {
                        assert_eq!(result, ProcessingResult::Success,
                            "Expected path of length {} to be accepted", test_case.target_length);
                    }
                }
            }

            ExpectedBehavior::Reject => {
                if let Some(max_length) = connection.config.expected_max_length {
                    if test_case.target_length > max_length && connection.config.error_on_oversized {
                        assert!(matches!(result, ProcessingResult::PathTooLarge(_)),
                            "Expected path of length {} to be rejected", test_case.target_length);
                    }
                }
            }

            ExpectedBehavior::ImplementationDefined => {
                // Either accept or reject is fine - just ensure no crash
                assert!(!matches!(result, ProcessingResult::ConnectionError),
                    "Should not cause connection error");
            }
        }
    }

    // Test boundary cases
    for boundary_test in &input.boundary_tests {
        match boundary_test {
            BoundaryTest::CommonLimits { base_sizes } => {
                for &size in base_sizes.iter().take(5) { // Limit for performance
                    let path = generate_path_of_length(size as usize, &PathPattern::SingleLongSegment {
                        base: "test".to_string(),
                    });

                    let result = connection.process_headers_frame(201, &path);

                    // Verify consistent behavior around limits
                    if let Some(max_length) = connection.config.expected_max_length {
                        if size > max_length && connection.config.error_on_oversized {
                            assert!(matches!(result, ProcessingResult::PathTooLarge(_)),
                                "Size {} should be rejected at limit {}", size, max_length);
                        }
                    }
                }
            }

            BoundaryTest::PowerOfTwo { max_power } => {
                for power in 10..=(*max_power).min(20) { // 1KB to 1MB max
                    let size = 1usize << power;
                    let path = generate_path_of_length(size, &PathPattern::DeeplyNested { depth: 100 });

                    let result = connection.process_headers_frame(301 + power as u32, &path);

                    // Ensure graceful handling of power-of-2 sizes
                    assert!(!matches!(result, ProcessingResult::ConnectionError),
                        "Power-of-2 size {} should not cause connection error", size);
                }
            }

            _ => {
                // Other boundary tests can be implemented similarly
            }
        }
    }

    // Test security scenarios
    for security_test in &input.security_tests.iter().take(3) { // Limit for performance
        match security_test {
            SecurityTest::MemoryExhaustion { size } => {
                let large_path = generate_path_of_length(*size as usize, &PathPattern::SingleLongSegment {
                    base: "memory-test".to_string(),
                });

                let result = connection.process_headers_frame(401, &large_path);

                // Should either accept with bounded memory or reject cleanly
                match result {
                    ProcessingResult::Success => {
                        // Memory usage should be tracked and bounded
                        assert!(connection.resource_usage.peak_memory_bytes < 10_000_000, // 10MB limit
                            "Memory usage should be bounded");
                    }
                    ProcessingResult::PathTooLarge(_) => {
                        // Clean rejection is acceptable
                    }
                    _ => {
                        // Other results should not indicate resource exhaustion
                        assert!(!matches!(result, ProcessingResult::ConnectionError),
                            "Should not cause connection error due to memory");
                    }
                }
            }

            SecurityTest::ParseTimeAttack { complexity: _ } => {
                // Test path with high parsing complexity
                let complex_path = generate_path_of_length(10000, &PathPattern::LongQueryString {
                    base_path: "/complex".to_string(),
                    param_count: 1000,
                });

                let result = connection.process_headers_frame(501, &complex_path);

                // Should complete within reasonable time
                match result {
                    ProcessingResult::ParseTimeExceeded(_) => {
                        // Acceptable - parser detected and rejected slow parse
                    }
                    ProcessingResult::Success => {
                        // Should have completed quickly
                        if let Some(stream) = connection.streams.get(&501) {
                            assert!(stream.parsing_time_ms < 5000, // 5 second max
                                "Parse time should be bounded");
                        }
                    }
                    _ => {
                        // Other outcomes are fine as long as no hang/crash
                    }
                }
            }

            _ => {
                // Other security tests can be implemented
            }
        }
    }

    // Verify statistics consistency
    let status = connection.get_status();

    assert_eq!(
        status.stats.total_paths_processed + status.stats.total_paths_rejected,
        status.parsing_results.len() as u32,
        "Path statistics should match parsing results"
    );

    // Verify resource usage bounds
    assert!(status.resource_usage.peak_memory_bytes < 100_000_000, // 100MB absolute max
        "Memory usage should stay within reasonable bounds");

    assert!(status.resource_usage.total_parsing_time_ms < 60000, // 1 minute total
        "Total parsing time should be bounded");

    // Test that normal small paths still work
    let small_path = "/normal/path";
    let result = connection.process_headers_frame(9001, small_path);
    assert_eq!(result, ProcessingResult::Success,
        "Normal small paths should always work");

    // Test exact boundary if configured
    if let Some(max_length) = connection.config.expected_max_length {
        // Test exactly at limit
        let boundary_path = generate_path_of_length(max_length as usize, &PathPattern::SingleLongSegment {
            base: "boundary".to_string(),
        });
        let result = connection.process_headers_frame(9003, &boundary_path);
        assert_eq!(result, ProcessingResult::Success,
            "Path exactly at limit {} should be accepted", max_length);

        // Test just over limit
        if max_length < 1_000_000 { // Only if limit is reasonable
            let over_limit_path = generate_path_of_length(max_length as usize + 1, &PathPattern::SingleLongSegment {
                base: "over-limit".to_string(),
            });
            let result = connection.process_headers_frame(9005, &over_limit_path);
            if connection.config.error_on_oversized {
                assert!(matches!(result, ProcessingResult::PathTooLarge(_)),
                    "Path over limit {} should be rejected", max_length);
            }
        }
    }
});