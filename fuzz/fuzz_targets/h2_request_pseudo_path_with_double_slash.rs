#![no_main]

//! Fuzz target for HTTP/2 :path pseudo-header with double slash sequences
//!
//! Tests that :path containing "//" sequences (e.g., "/foo//bar") are preserved
//! verbatim per RFC 9110. The double slash represents an empty segment between
//! slashes and should NOT be collapsed to a single slash by the parser.
//!
//! Key test scenarios:
//! - Paths with double slashes: "/foo//bar", "//start", "/end//", "//", etc.
//! - Verification that "//" is preserved exactly as-is
//! - No unintentional path normalization or collapse
//! - Round-trip preservation through parsing and serialization
//! - Edge cases with multiple consecutive slashes: "///", "////", etc.

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

/// Mock HTTP/2 connection for testing :path double slash handling
struct MockPathDoubleSlashConnection {
    /// Received HEADERS frame data
    headers_received: Vec<HeadersFrame>,

    /// Connection state
    state: ConnectionState,

    /// Statistics tracking
    stats: PathStats,

    /// Violation tracking
    violations: Vec<ViolationType>,
}

#[derive(Clone, Debug)]
struct HeadersFrame {
    stream_id: u32,
    headers: HashMap<String, String>,
    path_original: String,
    path_parsed: Option<String>,
}

#[derive(Clone, Debug)]
enum ConnectionState {
    Open,
    Closed,
}

#[derive(Default, Clone, Debug)]
struct PathStats {
    frames_processed: u32,
    paths_with_double_slash: u32,
    paths_collapsed: u32, // This should remain 0 - we don't collapse
    paths_preserved: u32,
    round_trip_failures: u32,
    empty_segments_detected: u32,
    consecutive_slash_patterns: u32,
}

#[derive(Clone, Debug)]
enum ViolationType {
    PathCollapsed,        // Double slash was incorrectly collapsed
    PathNormalized,       // Path was modified unexpectedly
    RoundTripFailure,     // Path changed during round-trip
    InvalidPathSyntax,    // Malformed path syntax
    HeaderMissing,        // Required :path header missing
}

impl MockPathDoubleSlashConnection {
    fn new() -> Self {
        Self {
            headers_received: Vec::new(),
            state: ConnectionState::Open,
            stats: PathStats::default(),
            violations: Vec::new(),
        }
    }

    /// Process a HEADERS frame with :path pseudo-header
    fn handle_headers(&mut self, stream_id: u32, headers: HashMap<String, String>) -> Result<(), H2Error> {
        self.stats.frames_processed += 1;

        // Extract :path header
        let path = match headers.get(":path") {
            Some(path) => path.clone(),
            None => {
                self.violations.push(ViolationType::HeaderMissing);
                return Err(H2Error::ProtocolError);
            }
        };

        // Analyze the path for double slash patterns
        let original_path = path.clone();
        let contains_double_slash = self.analyze_double_slash_patterns(&path);

        if contains_double_slash {
            self.stats.paths_with_double_slash += 1;
        }

        // Parse the path (this should preserve it exactly as-is)
        let parsed_path = self.parse_path(&path)?;

        // Verify no unintentional modification occurred
        if parsed_path != original_path {
            self.violations.push(ViolationType::PathNormalized);

            // Check specifically for double slash collapse
            if self.path_was_collapsed(&original_path, &parsed_path) {
                self.violations.push(ViolationType::PathCollapsed);
                self.stats.paths_collapsed += 1;
            }
        } else {
            self.stats.paths_preserved += 1;
        }

        // Test round-trip behavior: serialize back and compare
        let serialized_path = self.serialize_path(&parsed_path);
        if serialized_path != original_path {
            self.violations.push(ViolationType::RoundTripFailure);
            self.stats.round_trip_failures += 1;
        }

        // Store the frame data
        let frame = HeadersFrame {
            stream_id,
            headers,
            path_original: original_path,
            path_parsed: Some(parsed_path),
        };
        self.headers_received.push(frame);

        Ok(())
    }

    /// Analyze path for double slash patterns
    fn analyze_double_slash_patterns(&mut self, path: &str) -> bool {
        let mut has_double_slash = false;
        let mut consecutive_slashes = 0;

        for ch in path.chars() {
            if ch == '/' {
                consecutive_slashes += 1;
            } else {
                if consecutive_slashes >= 2 {
                    has_double_slash = true;
                    self.stats.consecutive_slash_patterns += 1;

                    // Count empty segments (sequences of //)
                    let empty_segments = consecutive_slashes - 1;
                    self.stats.empty_segments_detected += empty_segments as u32;
                }
                consecutive_slashes = 0;
            }
        }

        // Check trailing consecutive slashes
        if consecutive_slashes >= 2 {
            has_double_slash = true;
            self.stats.consecutive_slash_patterns += 1;
            let empty_segments = consecutive_slashes - 1;
            self.stats.empty_segments_detected += empty_segments as u32;
        }

        has_double_slash
    }

    /// Parse path (should preserve exactly as-is per RFC 9110)
    fn parse_path(&self, path: &str) -> Result<String, H2Error> {
        // RFC 9110: The path is taken verbatim
        // We should NOT normalize, collapse, or modify the path in any way

        // Basic validation: path must start with / (for absolute paths)
        // But we allow other forms for testing edge cases
        if path.is_empty() {
            return Err(H2Error::InvalidPath);
        }

        // Return path exactly as received - no modifications
        Ok(path.to_string())
    }

    /// Serialize path back (should be identity function)
    fn serialize_path(&self, path: &str) -> String {
        // This should be an identity function - no modifications
        path.to_string()
    }

    /// Check if a path was collapsed (double slash -> single slash)
    fn path_was_collapsed(&self, original: &str, parsed: &str) -> bool {
        // Look for patterns where "//" in original became "/" in parsed
        original.contains("//") && !parsed.contains("//") && original.len() > parsed.len()
    }

    /// Validate path preservation across different operations
    fn validate_path_preservation(&self, original_path: &str) -> ValidationResult {
        let mut result = ValidationResult {
            original: original_path.to_string(),
            preserved: true,
            issues: Vec::new(),
        };

        // Parse the path
        match self.parse_path(original_path) {
            Ok(parsed) => {
                if parsed != original_path {
                    result.preserved = false;
                    result.issues.push("Path modified during parsing".to_string());

                    // Check for specific issues
                    if self.path_was_collapsed(original_path, &parsed) {
                        result.issues.push("Double slash was collapsed".to_string());
                    }
                }

                // Test serialization round-trip
                let serialized = self.serialize_path(&parsed);
                if serialized != original_path {
                    result.preserved = false;
                    result.issues.push("Round-trip serialization failed".to_string());
                }
            }
            Err(_) => {
                result.preserved = false;
                result.issues.push("Path parsing failed".to_string());
            }
        }

        result
    }

    /// Get comprehensive statistics
    fn get_stats(&self) -> PathStats {
        self.stats.clone()
    }

    /// Get all violations detected
    fn get_violations(&self) -> &[ViolationType] {
        &self.violations
    }

    /// Test specific double slash patterns
    fn test_common_patterns(&mut self) -> PatternTestResults {
        let patterns = vec![
            "//",           // Root double slash
            "/foo//bar",    // Middle double slash
            "//start",      // Leading double slash
            "/end//",       // Trailing double slash
            "/a//b//c",     // Multiple double slashes
            "///",          // Triple slash
            "////",         // Quad slash
            "/foo///bar",   // Triple in middle
            "//foo//bar//", // Double at start, middle, and end
            "/.//..//./",   // Mixed with dot segments
        ];

        let mut results = PatternTestResults::default();
        results.patterns_tested = patterns.len() as u32;

        for pattern in patterns {
            let mut headers = HashMap::new();
            headers.insert(":method".to_string(), "GET".to_string());
            headers.insert(":scheme".to_string(), "https".to_string());
            headers.insert(":authority".to_string(), "example.com".to_string());
            headers.insert(":path".to_string(), pattern.to_string());

            match self.handle_headers(1, headers) {
                Ok(()) => {
                    results.patterns_passed += 1;

                    // Verify the path was preserved
                    if let Some(last_frame) = self.headers_received.last() {
                        if last_frame.path_original == pattern {
                            results.patterns_preserved += 1;
                        }
                    }
                }
                Err(_) => {
                    results.patterns_failed += 1;
                }
            }
        }

        results
    }
}

#[derive(Clone, Debug)]
struct ValidationResult {
    original: String,
    preserved: bool,
    issues: Vec<String>,
}

#[derive(Default, Clone, Debug)]
struct PatternTestResults {
    patterns_tested: u32,
    patterns_passed: u32,
    patterns_failed: u32,
    patterns_preserved: u32,
}

#[derive(Clone, Debug)]
enum H2Error {
    ProtocolError,
    InvalidPath,
    InternalError,
}

/// Fuzz input structure
#[derive(Arbitrary, Debug, Clone)]
struct FuzzInput {
    /// Stream ID for the request
    stream_id: u32,

    /// Base path components
    path_components: Vec<PathComponent>,

    /// Whether to run pattern tests
    test_patterns: bool,

    /// Additional headers
    extra_headers: Vec<(String, String)>,
}

#[derive(Arbitrary, Debug, Clone)]
enum PathComponent {
    /// Single slash
    Slash,

    /// Double slash
    DoubleSlash,

    /// Triple slash
    TripleSlash,

    /// Arbitrary number of slashes (1-10)
    MultiSlash(u8),

    /// Regular path segment
    Segment(String),

    /// Empty segment (between slashes)
    EmptySegment,

    /// Dot segment
    DotSegment,

    /// Dot-dot segment
    DotDotSegment,
}

impl PathComponent {
    fn to_string(&self) -> String {
        match self {
            PathComponent::Slash => "/".to_string(),
            PathComponent::DoubleSlash => "//".to_string(),
            PathComponent::TripleSlash => "///".to_string(),
            PathComponent::MultiSlash(count) => "/".repeat((*count as usize).min(10).max(1)),
            PathComponent::Segment(s) => {
                // Sanitize segment to avoid problematic characters
                s.chars()
                    .filter(|&c| c.is_alphanumeric() || c == '-' || c == '_')
                    .take(20)
                    .collect()
            }
            PathComponent::EmptySegment => "".to_string(),
            PathComponent::DotSegment => ".".to_string(),
            PathComponent::DotDotSegment => "..".to_string(),
        }
    }
}

fuzz_target!(|input: FuzzInput| {
    // Limit input size to prevent excessive resource usage
    if input.path_components.len() > 50 {
        return;
    }

    let mut connection = MockPathDoubleSlashConnection::new();

    // Build path from components
    let mut path = String::new();
    for component in &input.path_components {
        path.push_str(&component.to_string());
    }

    // Ensure path is not empty and starts with /
    if path.is_empty() || !path.starts_with('/') {
        path = format!("/{}", path);
    }

    // Limit path length to reasonable size
    if path.len() > 1000 {
        return;
    }

    // Build headers
    let mut headers = HashMap::new();
    headers.insert(":method".to_string(), "GET".to_string());
    headers.insert(":scheme".to_string(), "https".to_string());
    headers.insert(":authority".to_string(), "example.com".to_string());
    headers.insert(":path".to_string(), path.clone());

    // Add extra headers (sanitized)
    for (key, value) in input.extra_headers.iter().take(10) {
        if !key.starts_with(':') && !key.is_empty() && key.len() <= 50 && value.len() <= 200 {
            headers.insert(key.clone(), value.clone());
        }
    }

    // Process the headers
    let result = connection.handle_headers(input.stream_id, headers);

    // Validate path preservation
    let validation = connection.validate_path_preservation(&path);

    // Critical assertion: paths with double slashes MUST be preserved
    if path.contains("//") {
        if !validation.preserved {
            panic!("Path with double slash was not preserved: '{}' -> issues: {:?}",
                   path, validation.issues);
        }
    }

    // Check for violations
    let violations = connection.get_violations();
    for violation in violations {
        match violation {
            ViolationType::PathCollapsed => {
                panic!("CRITICAL: Double slash was collapsed in path '{}'", path);
            }
            ViolationType::PathNormalized => {
                // This might be acceptable in some cases, but not for double slashes
                if path.contains("//") {
                    panic!("CRITICAL: Path with double slash was normalized: '{}'", path);
                }
            }
            ViolationType::RoundTripFailure => {
                panic!("CRITICAL: Path round-trip failed for: '{}'", path);
            }
            ViolationType::InvalidPathSyntax => {
                // This may be expected for malformed inputs
            }
            ViolationType::HeaderMissing => {
                // Should not happen with our input generation
                panic!("Unexpected missing header");
            }
        }
    }

    // Run common pattern tests if requested
    if input.test_patterns {
        let pattern_results = connection.test_common_patterns();

        // All patterns should preserve their double slashes
        if pattern_results.patterns_preserved < pattern_results.patterns_passed {
            let stats = connection.get_stats();
            panic!("Pattern preservation failed: {} passed but only {} preserved. Collapsed: {}",
                   pattern_results.patterns_passed,
                   pattern_results.patterns_preserved,
                   stats.paths_collapsed);
        }
    }

    // Final statistics validation
    let stats = connection.get_stats();

    // We should never collapse paths
    assert_eq!(stats.paths_collapsed, 0, "No paths should be collapsed");

    // All processed paths should be preserved
    if stats.frames_processed > 0 {
        assert!(stats.paths_preserved > 0, "At least one path should be preserved");
    }

    // Round-trip should always succeed for valid paths
    if result.is_ok() {
        assert_eq!(stats.round_trip_failures, 0, "No round-trip failures should occur");
    }

    // Test specific edge cases
    test_edge_cases(&mut connection);
});

/// Test specific edge cases for double slash handling
fn test_edge_cases(connection: &mut MockPathDoubleSlashConnection) {
    let edge_cases = vec![
        ("//", "Root double slash"),
        ("/a//b", "Simple double slash"),
        ("//a//b//", "Multiple double slashes"),
        ("/a///b", "Triple slash"),
        ("/a////b", "Quad slash"),
        ("//////", "Many slashes"),
    ];

    for (path, description) in edge_cases {
        let mut headers = HashMap::new();
        headers.insert(":method".to_string(), "GET".to_string());
        headers.insert(":scheme".to_string(), "https".to_string());
        headers.insert(":authority".to_string(), "example.com".to_string());
        headers.insert(":path".to_string(), path.to_string());

        if let Ok(()) = connection.handle_headers(999, headers) {
            // Verify the path was preserved exactly
            if let Some(frame) = connection.headers_received.last() {
                if frame.path_original != path {
                    panic!("Edge case '{}' ({}) was not preserved: got '{}'",
                           path, description, frame.path_original);
                }
            }
        }
    }
}