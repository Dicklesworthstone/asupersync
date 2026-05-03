#![no_main]
/*
br-asupersync-q94ai8: the original draft below was mock-only and stopwatch
based. It is preserved verbatim for archaeology, but the active fuzz target
appended after this block drives the production HPACK decoder plus HTTP/2
Connection request-header state machine.

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

/// HTTP/2 :authority pseudo-header with extremely long values test input
#[derive(Arbitrary, Debug)]
struct H2HugeAuthorityInput {
    /// Authority value generation strategy
    authority_strategy: AuthorityLengthStrategy,
    /// Additional headers to include
    additional_headers: Vec<AdditionalHeader>,
    /// Test context for parsing
    parsing_context: AuthorityParsingContext,
    /// Performance constraints
    performance_limits: PerformanceLimits,
}

#[derive(Arbitrary, Debug)]
enum AuthorityLengthStrategy {
    /// Small baseline (normal case)
    Small { length: u16 }, // 1-255 chars
    /// Medium size (edge of normal)
    Medium { length: u16 }, // 256-2047 chars
    /// Large size (starts getting problematic)
    Large { length: u16 }, // 2048-8191 chars
    /// Huge size (potential DoS vector)
    Huge { length: u16 }, // 8192-65535 chars
    /// Exactly at common boundaries
    ExactBoundary(BoundarySize),
    /// Progressive growth pattern
    Progressive {
        start_length: u16,
        growth_factor: u8,
        steps: u8,
    },
    /// Random binary data disguised as authority
    BinaryData { length: u16 },
}

#[derive(Arbitrary, Debug)]
enum BoundarySize {
    /// Typical HTTP header limit
    Http1Limit,      // 8192
    /// Common server limits
    Nginx,           // 4096
    /// HTTP/2 frame size default
    H2FrameDefault,  // 16384
    /// Maximum HTTP/2 frame size
    H2FrameMax,      // 16777215 (2^24-1)
    /// Memory page boundary
    PageBoundary,    // 4096, 8192
    /// Powers of 2
    PowerOfTwo(u8),  // 2^n
}

#[derive(Arbitrary, Debug)]
struct AdditionalHeader {
    name: HeaderName,
    value: String,
}

#[derive(Arbitrary, Debug)]
enum HeaderName {
    Method,
    Path,
    Scheme,
    ContentType,
    UserAgent,
    Custom(String),
}

#[derive(Arbitrary, Debug)]
struct AuthorityParsingContext {
    /// Maximum allowed authority length
    max_authority_length: u32,
    /// Whether to enforce hostname validation
    validate_hostname: bool,
    /// Whether to allow IPv6 addresses
    allow_ipv6: bool,
    /// Whether to allow port numbers
    allow_port: bool,
    /// Connection state
    connection_state: ConnectionState,
}

#[derive(Arbitrary, Debug)]
enum ConnectionState {
    Fresh,
    ActiveStreams(u8),
    NearMemoryLimit,
}

#[derive(Arbitrary, Debug)]
struct PerformanceLimits {
    /// Maximum parsing time (microseconds)
    max_parse_time_us: u32,
    /// Maximum memory allocation (bytes)
    max_memory_bytes: u32,
    /// Whether to test for memory leaks
    test_memory_leaks: bool,
}

/// Mock HTTP/2 authority parser with bounds checking
struct MockH2AuthorityParser {
    max_authority_length: usize,
    hostname_validation: bool,
    performance_tracking: PerformanceTracker,
}

#[derive(Debug)]
struct PerformanceTracker {
    parse_start_time: std::time::Instant,
    memory_allocated: usize,
    max_parse_time_us: u32,
    max_memory_bytes: u32,
}

#[derive(Debug, Clone)]
struct ParsedAuthority {
    raw_value: String,
    host: String,
    port: Option<u16>,
    is_ipv6: bool,
    validation_result: AuthorityValidation,
}

#[derive(Debug, Clone, PartialEq)]
enum AuthorityValidation {
    Valid,
    TooLong,
    InvalidHostname,
    InvalidPort,
    InvalidIPv6,
    InvalidCharacters,
    Empty,
}

#[derive(Debug, PartialEq)]
enum AuthorityParsingError {
    /// Authority too long (exceeds configured limit)
    TooLong { length: usize, limit: usize },
    /// Invalid hostname format
    InvalidHostname(String),
    /// Invalid port number
    InvalidPort(String),
    /// Invalid IPv6 address format
    InvalidIPv6(String),
    /// Contains invalid characters
    InvalidCharacters(String),
    /// Empty authority (when required)
    Empty,
    /// Parsing timeout (performance limit)
    Timeout,
    /// Memory limit exceeded
    MemoryLimit,
    /// Malformed authority structure
    Malformed(String),
}

// Common authority length limits in real implementations
const DEFAULT_MAX_AUTHORITY_LENGTH: usize = 8192;      // 8KB common limit
const HTTP1_HEADER_LIMIT: usize = 8192;               // HTTP/1.1 typical limit
const NGINX_SERVER_NAME_LIMIT: usize = 4096;          // nginx server_name limit
const H2_FRAME_DEFAULT_SIZE: usize = 16384;           // HTTP/2 default frame size
const REASONABLE_HOSTNAME_LIMIT: usize = 253;         // DNS hostname limit
const MAX_PORT_NUMBER: u16 = 65535;

impl MockH2AuthorityParser {
    fn new(max_length: usize, validate_hostname: bool, performance_limits: &PerformanceLimits) -> Self {
        Self {
            max_authority_length: max_length,
            hostname_validation: validate_hostname,
            performance_tracking: PerformanceTracker {
                parse_start_time: std::time::Instant::now(),
                memory_allocated: 0,
                max_parse_time_us: performance_limits.max_parse_time_us,
                max_memory_bytes: performance_limits.max_memory_bytes,
            },
        }
    }

    fn parse_authority(&mut self, authority: &str) -> Result<ParsedAuthority, AuthorityParsingError> {
        self.performance_tracking.parse_start_time = std::time::Instant::now();

        // Immediate length check (critical for DoS prevention)
        if authority.len() > self.max_authority_length {
            return Err(AuthorityParsingError::TooLong {
                length: authority.len(),
                limit: self.max_authority_length
            });
        }

        // Check for timeout during parsing
        self.check_performance_limits()?;

        // Memory allocation tracking
        let estimated_memory = authority.len() * 2; // rough estimate
        if estimated_memory > self.performance_tracking.max_memory_bytes as usize {
            return Err(AuthorityParsingError::MemoryLimit);
        }
        self.performance_tracking.memory_allocated += estimated_memory;

        // Handle empty authority (valid in some contexts per RFC 7540 §8.1.2.3)
        if authority.is_empty() {
            return Ok(ParsedAuthority {
                raw_value: String::new(),
                host: String::new(),
                port: None,
                is_ipv6: false,
                validation_result: AuthorityValidation::Empty,
            });
        }

        // Parse host and port
        let (host, port) = self.parse_host_port(authority)?;

        // Performance check after main parsing
        self.check_performance_limits()?;

        // Validate hostname if enabled
        let validation_result = if self.hostname_validation {
            self.validate_hostname(&host)?
        } else {
            AuthorityValidation::Valid
        };

        let is_ipv6 = self.is_ipv6_address(&host);

        Ok(ParsedAuthority {
            raw_value: authority.to_string(),
            host,
            port,
            is_ipv6,
            validation_result,
        })
    }

    fn check_performance_limits(&self) -> Result<(), AuthorityParsingError> {
        let elapsed = self.performance_tracking.parse_start_time.elapsed();
        if elapsed.as_micros() > self.performance_tracking.max_parse_time_us as u128 {
            return Err(AuthorityParsingError::Timeout);
        }
        Ok(())
    }

    fn parse_host_port(&self, authority: &str) -> Result<(String, Option<u16>), AuthorityParsingError> {
        // Handle IPv6 addresses: [::1]:8080 or [2001:db8::1]:443
        if authority.starts_with('[') {
            let close_bracket = authority.find(']')
                .ok_or_else(|| AuthorityParsingError::InvalidIPv6("Missing closing bracket".into()))?;

            let ipv6_part = &authority[1..close_bracket];
            let remaining = &authority[close_bracket + 1..];

            let port = if remaining.starts_with(':') {
                Some(self.parse_port(&remaining[1..])?)
            } else if remaining.is_empty() {
                None
            } else {
                return Err(AuthorityParsingError::InvalidIPv6("Invalid characters after IPv6 address".into()));
            };

            return Ok((ipv6_part.to_string(), port));
        }

        // Handle regular hostname:port or IPv4:port
        if let Some(colon_pos) = authority.rfind(':') {
            // Check if this might be an IPv6 address without brackets (invalid)
            if authority.matches(':').count() > 1 && !authority.starts_with('[') {
                return Err(AuthorityParsingError::InvalidIPv6("IPv6 addresses must be enclosed in brackets".into()));
            }

            let host_part = &authority[..colon_pos];
            let port_part = &authority[colon_pos + 1..];

            // Validate host part isn't empty
            if host_part.is_empty() {
                return Err(AuthorityParsingError::InvalidHostname("Empty hostname".into()));
            }

            let port = Some(self.parse_port(port_part)?);
            Ok((host_part.to_string(), port))
        } else {
            // No port specified
            Ok((authority.to_string(), None))
        }
    }

    fn parse_port(&self, port_str: &str) -> Result<u16, AuthorityParsingError> {
        if port_str.is_empty() {
            return Err(AuthorityParsingError::InvalidPort("Empty port".into()));
        }

        // Check for invalid characters
        if !port_str.chars().all(|c| c.is_ascii_digit()) {
            return Err(AuthorityParsingError::InvalidPort(format!("Non-digit characters: {}", port_str)));
        }

        // Parse and validate range
        let port: u32 = port_str.parse()
            .map_err(|_| AuthorityParsingError::InvalidPort(format!("Unable to parse: {}", port_str)))?;

        if port == 0 || port > MAX_PORT_NUMBER as u32 {
            return Err(AuthorityParsingError::InvalidPort(format!("Port out of range: {}", port)));
        }

        Ok(port as u16)
    }

    fn validate_hostname(&self, host: &str) -> Result<AuthorityValidation, AuthorityParsingError> {
        if host.is_empty() {
            return Ok(AuthorityValidation::Empty);
        }

        // Length check for hostname (DNS limit)
        if host.len() > REASONABLE_HOSTNAME_LIMIT {
            return Ok(AuthorityValidation::TooLong);
        }

        // Check for invalid characters (simplified validation)
        if host.chars().any(|c| c.is_control() || c.is_whitespace()) {
            return Ok(AuthorityValidation::InvalidCharacters);
        }

        // IPv6 address check
        if self.is_ipv6_address(host) {
            return Ok(AuthorityValidation::Valid);
        }

        // IPv4 address check
        if self.is_ipv4_address(host) {
            return Ok(AuthorityValidation::Valid);
        }

        // Basic hostname validation
        if self.is_valid_hostname(host) {
            Ok(AuthorityValidation::Valid)
        } else {
            Ok(AuthorityValidation::InvalidHostname)
        }
    }

    fn is_ipv6_address(&self, host: &str) -> bool {
        // Simplified IPv6 detection
        host.contains(':') && (
            host.contains("::") ||
            host.chars().all(|c| c.is_ascii_hexdigit() || c == ':') &&
            host.matches(':').count() >= 2
        )
    }

    fn is_ipv4_address(&self, host: &str) -> bool {
        // Simplified IPv4 detection
        let parts: Vec<&str> = host.split('.').collect();
        parts.len() == 4 && parts.iter().all(|part| {
            part.parse::<u8>().is_ok()
        })
    }

    fn is_valid_hostname(&self, host: &str) -> bool {
        // Simplified hostname validation
        !host.is_empty() &&
        !host.starts_with('.') &&
        !host.ends_with('.') &&
        !host.contains("..") &&
        host.chars().all(|c| c.is_alphanumeric() || c == '.' || c == '-')
    }

    fn generate_authority_value(strategy: &AuthorityLengthStrategy) -> String {
        match strategy {
            AuthorityLengthStrategy::Small { length } => {
                let len = (*length as usize).min(255);
                format!("{}.example.com:8080", "a".repeat(len.saturating_sub(20)))
            }
            AuthorityLengthStrategy::Medium { length } => {
                let len = (*length as usize).min(2047);
                format!("{}.example.com:8080", "b".repeat(len.saturating_sub(20)))
            }
            AuthorityLengthStrategy::Large { length } => {
                let len = (*length as usize).min(8191);
                format!("{}.example.com:8080", "c".repeat(len.saturating_sub(20)))
            }
            AuthorityLengthStrategy::Huge { length } => {
                let len = *length as usize;
                format!("{}.example.com:8080", "d".repeat(len.saturating_sub(20)))
            }
            AuthorityLengthStrategy::ExactBoundary(boundary) => {
                let len = match boundary {
                    BoundarySize::Http1Limit => HTTP1_HEADER_LIMIT,
                    BoundarySize::Nginx => NGINX_SERVER_NAME_LIMIT,
                    BoundarySize::H2FrameDefault => H2_FRAME_DEFAULT_SIZE,
                    BoundarySize::H2FrameMax => 65535, // Capped for memory
                    BoundarySize::PageBoundary => 4096,
                    BoundarySize::PowerOfTwo(n) => (1 << (*n as u32)).min(65535),
                };
                format!("{}.boundary.test", "x".repeat(len.saturating_sub(15)))
            }
            AuthorityLengthStrategy::Progressive { start_length, growth_factor, steps: _ } => {
                let len = (*start_length as usize) * (*growth_factor as usize);
                format!("{}.progressive.test", "p".repeat(len.saturating_sub(20)))
            }
            AuthorityLengthStrategy::BinaryData { length } => {
                // Generate pseudo-random binary data that might look like authority
                let len = *length as usize;
                let mut result = String::new();
                for i in 0..len {
                    let byte = ((i * 37 + 123) % 256) as u8;
                    if byte.is_ascii() && byte != 0 {
                        result.push(byte as char);
                    } else {
                        result.push('?');
                    }
                }
                result
            }
        }
    }

    fn measure_parse_performance(authority: &str, limits: &PerformanceLimits) -> ParsePerformanceResult {
        let start = std::time::Instant::now();
        let mut parser = MockH2AuthorityParser::new(
            DEFAULT_MAX_AUTHORITY_LENGTH,
            true,
            limits
        );

        let parse_result = parser.parse_authority(authority);
        let parse_time = start.elapsed();

        ParsePerformanceResult {
            parse_time_us: parse_time.as_micros() as u32,
            memory_used: parser.performance_tracking.memory_allocated,
            result: parse_result,
            within_limits: parse_time.as_micros() <= limits.max_parse_time_us as u128 &&
                         parser.performance_tracking.memory_allocated <= limits.max_memory_bytes as usize,
        }
    }
}

#[derive(Debug)]
struct ParsePerformanceResult {
    parse_time_us: u32,
    memory_used: usize,
    result: Result<ParsedAuthority, AuthorityParsingError>,
    within_limits: bool,
}

fuzz_target!(|input: H2HugeAuthorityInput| {
    // Skip excessive test cases that would timeout
    if matches!(input.authority_strategy, AuthorityLengthStrategy::Huge { length } if length > 32768) {
        return;
    }

    // Generate authority value based on strategy
    let authority_value = MockH2AuthorityParser::generate_authority_value(&input.authority_strategy);

    // Apply reasonable limits to prevent fuzzer hanging
    if authority_value.len() > 100_000 {
        return;
    }

    let mut parser = MockH2AuthorityParser::new(
        input.parsing_context.max_authority_length as usize,
        input.parsing_context.validate_hostname,
        &input.performance_limits
    );

    let parse_result = parser.parse_authority(&authority_value);

    // Test performance constraints
    let performance_result = MockH2AuthorityParser::measure_parse_performance(
        &authority_value,
        &input.performance_limits
    );

    // Apply test assertions based on authority length
    match input.authority_strategy {
        AuthorityLengthStrategy::Small { .. } => {
            // Small authorities should always be accepted (if valid)
            match parse_result {
                Ok(parsed) => {
                    assert!(!parsed.raw_value.is_empty() || parsed.validation_result == AuthorityValidation::Empty);
                    assert!(parsed.raw_value.len() <= 2048); // Should be small
                }
                Err(AuthorityParsingError::TooLong { .. }) => {
                    panic!("Small authority incorrectly rejected as too long");
                }
                Err(_) => {
                    // Other errors may be valid (malformed authority, etc.)
                }
            }
        }
        AuthorityLengthStrategy::Medium { .. } => {
            // Medium authorities may be accepted depending on limits
            match parse_result {
                Ok(parsed) => {
                    assert!(parsed.raw_value.len() <= input.parsing_context.max_authority_length as usize);
                }
                Err(AuthorityParsingError::TooLong { length, limit }) => {
                    assert!(length > limit);
                    assert_eq!(limit, input.parsing_context.max_authority_length as usize);
                }
                Err(_) => {
                    // Other validation errors may occur
                }
            }
        }
        AuthorityLengthStrategy::Large { .. } |
        AuthorityLengthStrategy::Huge { .. } => {
            // Large/huge authorities should be rejected if over limit
            if authority_value.len() > input.parsing_context.max_authority_length as usize {
                match parse_result {
                    Ok(_) => {
                        panic!("Huge authority should be rejected but was accepted");
                    }
                    Err(AuthorityParsingError::TooLong { .. }) => {
                        // Expected: authority too long
                    }
                    Err(_) => {
                        // Other errors are acceptable
                    }
                }
            }
        }
        AuthorityLengthStrategy::ExactBoundary(_) => {
            // Boundary tests should help identify exact limits
            match parse_result {
                Ok(parsed) => {
                    assert!(parsed.raw_value.len() <= input.parsing_context.max_authority_length as usize);
                }
                Err(AuthorityParsingError::TooLong { length, limit }) => {
                    assert!(length > limit);
                }
                Err(_) => {
                    // Other validation errors acceptable
                }
            }
        }
        _ => {
            // Other strategies: verify basic parsing behavior
            match parse_result {
                Ok(_) => {
                    // If accepted, should be within limits
                    assert!(authority_value.len() <= input.parsing_context.max_authority_length as usize);
                }
                Err(_) => {
                    // Rejection is acceptable for various reasons
                }
            }
        }
    }

    // Test performance invariants
    test_authority_performance_invariants(&input, &performance_result, &authority_value);
});

fn test_authority_performance_invariants(
    input: &H2HugeAuthorityInput,
    performance: &ParsePerformanceResult,
    authority_value: &str,
) {
    // Invariant: Parsing should not exceed performance limits
    if input.performance_limits.max_parse_time_us > 0 {
        assert!(
            performance.parse_time_us <= input.performance_limits.max_parse_time_us * 2, // Allow some tolerance
            "Parsing took {}μs but limit was {}μs for authority length {}",
            performance.parse_time_us,
            input.performance_limits.max_parse_time_us,
            authority_value.len()
        );
    }

    // Invariant: Memory usage should be reasonable for authority size
    if input.performance_limits.max_memory_bytes > 0 {
        let expected_memory = authority_value.len() * 4; // Rough upper bound
        assert!(
            performance.memory_used <= expected_memory.max(input.performance_limits.max_memory_bytes as usize),
            "Memory usage {} exceeded reasonable bound {} for authority length {}",
            performance.memory_used,
            expected_memory,
            authority_value.len()
        );
    }

    // Invariant: Very long authorities should be rejected
    if authority_value.len() > DEFAULT_MAX_AUTHORITY_LENGTH {
        match &performance.result {
            Ok(_) => {
                // Should not accept authorities over default limit unless explicitly configured
                if input.parsing_context.max_authority_length <= DEFAULT_MAX_AUTHORITY_LENGTH as u32 {
                    panic!("Authority length {} should be rejected with limit {}",
                           authority_value.len(), input.parsing_context.max_authority_length);
                }
            }
            Err(AuthorityParsingError::TooLong { .. }) => {
                // Expected rejection
            }
            Err(_) => {
                // Other errors are acceptable
            }
        }
    }

    // Invariant: Empty authority handling should be consistent
    if authority_value.is_empty() {
        match &performance.result {
            Ok(parsed) => {
                assert_eq!(parsed.validation_result, AuthorityValidation::Empty);
            }
            Err(AuthorityParsingError::Empty) => {
                // Also acceptable depending on parser configuration
            }
            Err(_) => {
                panic!("Empty authority should either be accepted or rejected with Empty error");
            }
        }
    }

    // Invariant: IPv6 addresses should be properly detected
    if authority_value.contains(':') && authority_value.starts_with('[') {
        // This looks like IPv6, should be handled correctly
        match &performance.result {
            Ok(parsed) => {
                assert!(parsed.is_ipv6 || parsed.validation_result != AuthorityValidation::Valid);
            }
            Err(_) => {
                // Rejection is acceptable for malformed IPv6
            }
        }
    }

    // Invariant: Performance should scale reasonably with input size
    let size_factor = (authority_value.len() / 1000).max(1);
    let reasonable_time_bound = (size_factor * 100) as u32; // 100μs per KB
    if performance.parse_time_us > reasonable_time_bound * 10 {
        eprintln!(
            "WARNING: Parse time {}μs seems excessive for {} char authority (expected <{}μs)",
            performance.parse_time_us, authority_value.len(), reasonable_time_bound
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normal_authority_accepted() {
        let limits = PerformanceLimits {
            max_parse_time_us: 10000,
            max_memory_bytes: 65536,
            test_memory_leaks: false,
        };
        let mut parser = MockH2AuthorityParser::new(DEFAULT_MAX_AUTHORITY_LENGTH, true, &limits);

        let result = parser.parse_authority("example.com:8080");
        assert!(result.is_ok());

        let parsed = result.unwrap();
        assert_eq!(parsed.host, "example.com");
        assert_eq!(parsed.port, Some(8080));
        assert!(!parsed.is_ipv6);
    }

    #[test]
    fn test_huge_authority_rejected() {
        let limits = PerformanceLimits {
            max_parse_time_us: 10000,
            max_memory_bytes: 65536,
            test_memory_leaks: false,
        };
        let mut parser = MockH2AuthorityParser::new(1000, true, &limits); // 1KB limit

        let huge_authority = format!("{}.example.com", "x".repeat(2000));
        let result = parser.parse_authority(&huge_authority);

        assert!(matches!(result, Err(AuthorityParsingError::TooLong { .. })));
    }

    #[test]
    fn test_ipv6_authority_parsing() {
        let limits = PerformanceLimits {
            max_parse_time_us: 10000,
            max_memory_bytes: 65536,
            test_memory_leaks: false,
        };
        let mut parser = MockH2AuthorityParser::new(DEFAULT_MAX_AUTHORITY_LENGTH, true, &limits);

        let result = parser.parse_authority("[2001:db8::1]:8080");
        assert!(result.is_ok());

        let parsed = result.unwrap();
        assert_eq!(parsed.host, "2001:db8::1");
        assert_eq!(parsed.port, Some(8080));
        assert!(parsed.is_ipv6);
    }

    #[test]
    fn test_authority_without_port() {
        let limits = PerformanceLimits {
            max_parse_time_us: 10000,
            max_memory_bytes: 65536,
            test_memory_leaks: false,
        };
        let mut parser = MockH2AuthorityParser::new(DEFAULT_MAX_AUTHORITY_LENGTH, true, &limits);

        let result = parser.parse_authority("example.com");
        assert!(result.is_ok());

        let parsed = result.unwrap();
        assert_eq!(parsed.host, "example.com");
        assert_eq!(parsed.port, None);
    }

    #[test]
    fn test_empty_authority() {
        let limits = PerformanceLimits {
            max_parse_time_us: 10000,
            max_memory_bytes: 65536,
            test_memory_leaks: false,
        };
        let mut parser = MockH2AuthorityParser::new(DEFAULT_MAX_AUTHORITY_LENGTH, true, &limits);

        let result = parser.parse_authority("");
        assert!(result.is_ok());

        let parsed = result.unwrap();
        assert_eq!(parsed.validation_result, AuthorityValidation::Empty);
    }

    #[test]
    fn test_boundary_length_authorities() {
        let limits = PerformanceLimits {
            max_parse_time_us: 10000,
            max_memory_bytes: 65536,
            test_memory_leaks: false,
        };

        // Test exactly at limit
        let mut parser = MockH2AuthorityParser::new(100, true, &limits);
        let boundary_authority = format!("{}.test", "a".repeat(95));

        let result = parser.parse_authority(&boundary_authority);
        assert!(result.is_ok());

        // Test just over limit
        let over_limit_authority = format!("{}.test", "a".repeat(96));
        let result = parser.parse_authority(&over_limit_authority);
        assert!(matches!(result, Err(AuthorityParsingError::TooLong { .. })));
    }

    #[test]
    fn test_invalid_port_numbers() {
        let limits = PerformanceLimits {
            max_parse_time_us: 10000,
            max_memory_bytes: 65536,
            test_memory_leaks: false,
        };
        let mut parser = MockH2AuthorityParser::new(DEFAULT_MAX_AUTHORITY_LENGTH, true, &limits);

        // Port too high
        let result = parser.parse_authority("example.com:99999");
        assert!(matches!(result, Err(AuthorityParsingError::InvalidPort(_))));

        // Port zero
        let result = parser.parse_authority("example.com:0");
        assert!(matches!(result, Err(AuthorityParsingError::InvalidPort(_))));

        // Non-numeric port
        let result = parser.parse_authority("example.com:abc");
        assert!(matches!(result, Err(AuthorityParsingError::InvalidPort(_))));
    }

    #[test]
    fn test_performance_timeout() {
        let limits = PerformanceLimits {
            max_parse_time_us: 1, // Very short timeout
            max_memory_bytes: 65536,
            test_memory_leaks: false,
        };
        let mut parser = MockH2AuthorityParser::new(DEFAULT_MAX_AUTHORITY_LENGTH, true, &limits);

        // This should timeout on a slow system, but might not on fast systems
        let long_authority = format!("{}.example.com", "x".repeat(1000));
        let result = parser.parse_authority(&long_authority);

        // Either succeeds or times out, both are acceptable
        match result {
            Ok(_) => {} // Fast parsing
            Err(AuthorityParsingError::Timeout) => {} // Expected timeout
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
    }

    #[test]
    fn test_authority_generation_strategies() {
        // Test each generation strategy
        let small = MockH2AuthorityParser::generate_authority_value(
            &AuthorityLengthStrategy::Small { length: 50 }
        );
        assert!(small.len() <= 100);

        let medium = MockH2AuthorityParser::generate_authority_value(
            &AuthorityLengthStrategy::Medium { length: 1000 }
        );
        assert!(medium.len() >= 500 && medium.len() <= 1500);

        let boundary = MockH2AuthorityParser::generate_authority_value(
            &AuthorityLengthStrategy::ExactBoundary(BoundarySize::Http1Limit)
        );
        assert!(boundary.len() >= HTTP1_HEADER_LIMIT - 100);
    }
}
*/

use arbitrary::Arbitrary;
use asupersync::bytes::{Bytes, BytesMut};
use asupersync::http::h2::{
    Connection, ErrorCode, Frame, Header, HpackEncoder, Settings,
    frame::{HeadersFrame, SettingsFrame},
};
use libfuzzer_sys::fuzz_target;

const STREAM_ID: u32 = 1;
const RAW_STREAM_ID: u32 = 3;
const MAX_AUTHORITY_LEN: usize = 128 * 1024;
const MAX_EXTRA_HEADERS: usize = 16;
const MAX_EXTRA_VALUE_LEN: usize = 2048;
const MAX_RAW_HEADER_BLOCK: usize = 16 * 1024;

#[derive(Arbitrary, Debug)]
struct Scenario {
    authority: AuthorityShape,
    local_max_header_list_size: u32,
    duplicate_authority: bool,
    omit_authority: bool,
    extra_headers: Vec<ExtraHeader>,
    raw_header_block: Vec<u8>,
}

#[derive(Arbitrary, Debug)]
enum AuthorityShape {
    Empty,
    Repeated { byte: u8, len: u32 },
    Boundary(HeaderBoundary),
    DomainLike { labels: Vec<String>, port: u16 },
    BinaryLike { bytes: Vec<u8> },
}

#[derive(Arbitrary, Debug)]
enum HeaderBoundary {
    AroundConfiguredMax,
    H2DefaultFrame,
    HpackDecoderHardCap,
}

#[derive(Arbitrary, Debug)]
struct ExtraHeader {
    name: String,
    value: String,
}

fuzz_target!(|scenario: Scenario| {
    let mut scenario = scenario;
    scenario.extra_headers.truncate(MAX_EXTRA_HEADERS);
    scenario.raw_header_block.truncate(MAX_RAW_HEADER_BLOCK);

    let max_header_list_size = normalize_header_list_size(scenario.local_max_header_list_size);
    let authority = authority_value(&scenario.authority, max_header_list_size);
    let headers = request_headers(
        &authority,
        scenario.duplicate_authority,
        scenario.omit_authority,
        &scenario.extra_headers,
    );

    exercise_encoded_authority(headers, max_header_list_size, scenario.duplicate_authority);
    exercise_raw_header_block(Bytes::from(scenario.raw_header_block), max_header_list_size);
});

fn exercise_encoded_authority(
    headers: Vec<Header>,
    max_header_list_size: usize,
    duplicate_authority: bool,
) {
    let mut connection = open_connection(max_header_list_size);
    let encoded = encode_headers(&headers);
    let expected_size = headers.iter().map(Header::size).sum::<usize>();
    let result = connection.process_frame(Frame::Headers(HeadersFrame::new(
        STREAM_ID, encoded, true, true,
    )));

    match result {
        Ok(Some(asupersync::http::h2::connection::ReceivedFrame::Headers {
            stream_id,
            headers: decoded,
            end_stream,
        })) => {
            assert_eq!(stream_id, STREAM_ID);
            assert!(end_stream);
            assert!(
                expected_size <= max_header_list_size,
                "oversized header list was accepted: {expected_size} > {max_header_list_size}"
            );
            assert!(
                !duplicate_authority,
                "duplicate :authority pseudo-header was accepted"
            );
            assert_eq!(decoded, headers);
        }
        Ok(other) => panic!("HEADERS did not surface as request headers: {other:?}"),
        Err(err) => {
            if duplicate_authority && expected_size <= max_header_list_size {
                assert_eq!(err.code, ErrorCode::ProtocolError);
                assert_eq!(err.stream_id, Some(STREAM_ID));
            } else if expected_size > max_header_list_size {
                assert_eq!(err.code, ErrorCode::CompressionError);
                assert_eq!(err.stream_id, None);
            } else {
                assert!(
                    matches!(
                        err.code,
                        ErrorCode::ProtocolError | ErrorCode::CompressionError
                    ),
                    "unexpected huge-authority rejection: {err:?}"
                );
            }
        }
    }
}

fn exercise_raw_header_block(raw: Bytes, max_header_list_size: usize) {
    if raw.is_empty() {
        return;
    }

    let mut connection = open_connection(max_header_list_size);
    let result = connection.process_frame(Frame::Headers(HeadersFrame::new(
        RAW_STREAM_ID,
        raw,
        true,
        true,
    )));

    match result {
        Ok(Some(asupersync::http::h2::connection::ReceivedFrame::Headers {
            stream_id, ..
        })) => assert_eq!(stream_id, RAW_STREAM_ID),
        Ok(Some(other)) => panic!("raw header block surfaced unexpected frame: {other:?}"),
        Ok(None) => {}
        Err(err) => assert!(
            matches!(
                err.code,
                ErrorCode::CompressionError | ErrorCode::ProtocolError | ErrorCode::EnhanceYourCalm
            ),
            "raw HPACK/header block failed with unexpected error: {err:?}"
        ),
    }
}

fn open_connection(max_header_list_size: usize) -> Connection {
    let mut settings = Settings::default();
    settings.max_header_list_size = max_header_list_size as u32;
    let mut connection = Connection::server(settings);
    connection
        .process_frame(Frame::Settings(SettingsFrame::new(Vec::new())))
        .expect("initial SETTINGS should open the H2 connection");
    while connection.next_frame().is_some() {}
    connection
}

fn encode_headers(headers: &[Header]) -> Bytes {
    let mut encoder = HpackEncoder::new();
    let mut block = BytesMut::new();
    encoder.encode(headers, &mut block);
    block.freeze()
}

fn request_headers(
    authority: &str,
    duplicate_authority: bool,
    omit_authority: bool,
    extra_headers: &[ExtraHeader],
) -> Vec<Header> {
    let mut headers = vec![
        Header::new(":method", "GET"),
        Header::new(":scheme", "https"),
        Header::new(":path", "/huge-authority-fuzz"),
    ];
    if !omit_authority {
        headers.push(Header::new(":authority", authority.to_owned()));
        if duplicate_authority {
            headers.push(Header::new(":authority", format!("{authority}.dup")));
        }
    }
    for extra in extra_headers {
        if let Some(header) = sanitize_extra_header(extra) {
            headers.push(header);
        }
    }
    headers
}

fn sanitize_extra_header(extra: &ExtraHeader) -> Option<Header> {
    let name = extra
        .name
        .bytes()
        .filter(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
        .take(64)
        .map(char::from)
        .collect::<String>();
    if name.is_empty()
        || name.starts_with(':')
        || matches!(
            name.as_str(),
            "connection" | "keep-alive" | "proxy-connection" | "transfer-encoding" | "upgrade"
        )
    {
        return None;
    }

    let mut value = extra
        .value
        .chars()
        .take(MAX_EXTRA_VALUE_LEN)
        .collect::<String>();
    if name == "te" && value != "trailers" {
        value = "trailers".to_owned();
    }
    Some(Header::new(name, value))
}

fn authority_value(shape: &AuthorityShape, max_header_list_size: usize) -> String {
    match shape {
        AuthorityShape::Empty => String::new(),
        AuthorityShape::Repeated { byte, len } => {
            let len = (*len as usize).min(MAX_AUTHORITY_LEN);
            let ch = printable_authority_char(*byte);
            std::iter::repeat_n(ch, len).collect()
        }
        AuthorityShape::Boundary(boundary) => {
            let len = match boundary {
                HeaderBoundary::AroundConfiguredMax => max_header_list_size.saturating_add(1),
                HeaderBoundary::H2DefaultFrame => 16 * 1024,
                HeaderBoundary::HpackDecoderHardCap => MAX_AUTHORITY_LEN,
            }
            .min(MAX_AUTHORITY_LEN);
            "a".repeat(len)
        }
        AuthorityShape::DomainLike { labels, port } => {
            let mut parts = labels
                .iter()
                .map(|label| sanitize_domain_label(label))
                .filter(|label| !label.is_empty())
                .take(12)
                .collect::<Vec<_>>();
            if parts.is_empty() {
                parts.push("fuzz".to_owned());
            }
            format!("{}:{port}", parts.join("."))
        }
        AuthorityShape::BinaryLike { bytes } => bytes
            .iter()
            .take(MAX_AUTHORITY_LEN)
            .map(|byte| printable_authority_char(*byte))
            .collect(),
    }
}

fn sanitize_domain_label(label: &str) -> String {
    label
        .bytes()
        .filter(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
        .take(63)
        .map(char::from)
        .collect()
}

fn printable_authority_char(byte: u8) -> char {
    match byte {
        b'a'..=b'z' | b'0'..=b'9' | b'.' | b'-' | b':' | b'[' | b']' => char::from(byte),
        _ => 'x',
    }
}

fn normalize_header_list_size(raw: u32) -> usize {
    match raw % 8 {
        0 => 0,
        1 => 128,
        2 => 1024,
        3 => 16 * 1024,
        4 => 64 * 1024,
        _ => (raw as usize).min(MAX_AUTHORITY_LEN + 4096),
    }
}

#[cfg(test)]
mod production_regressions {
    use super::*;

    #[test]
    fn huge_authority_over_configured_header_list_limit_is_rejected_before_decode_success() {
        let max = 512;
        let headers = request_headers(&"a".repeat(4096), false, false, &[]);
        let mut connection = open_connection(max);
        let err = connection
            .process_frame(Frame::Headers(HeadersFrame::new(
                STREAM_ID,
                encode_headers(&headers),
                true,
                true,
            )))
            .expect_err("oversized authority must be rejected");
        assert_eq!(err.code, ErrorCode::CompressionError);
        assert_eq!(err.stream_id, None);
    }

    #[test]
    fn duplicate_authority_is_stream_protocol_error_when_within_size_limit() {
        let headers = request_headers("example.test", true, false, &[]);
        let mut connection = open_connection(16 * 1024);
        let err = connection
            .process_frame(Frame::Headers(HeadersFrame::new(
                STREAM_ID,
                encode_headers(&headers),
                true,
                true,
            )))
            .expect_err("duplicate :authority must be rejected");
        assert_eq!(err.code, ErrorCode::ProtocolError);
        assert_eq!(err.stream_id, Some(STREAM_ID));
    }

    #[test]
    fn empty_authority_uses_the_production_validator_decision() {
        let headers = request_headers("", false, false, &[]);
        exercise_encoded_authority(headers, 16 * 1024, false);
    }
}
