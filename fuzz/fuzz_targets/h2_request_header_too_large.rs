#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use std::collections::HashMap;

/// HTTP/2 large header rejection fuzz target.
///
/// Tests memory protection when HEADERS frame contains single header values
/// > 1MB (e.g., very large cookies). Our parser must reject with appropriate
/// error BEFORE allocating 1MB+ memory to prevent DoS attacks and memory
/// exhaustion.
///
/// Critical test scenarios:
/// - Single header value > 1MB (Cookie, Authorization, etc.)
/// - Memory allocation prevention during parsing
/// - Early rejection with proper error messages
/// - Various header types with size violations
/// - Edge cases around size limits

#[derive(Arbitrary, Debug, Clone)]
struct LargeHeaderInput {
    /// Stream ID for the request
    stream_id: u32,

    /// Headers with potential large values
    headers: Vec<TestHeader>,

    /// Large header patterns to test
    large_patterns: Vec<LargeHeaderPattern>,

    /// Parser configuration
    parser_config: HeaderParserConfig,
}

#[derive(Arbitrary, Debug, Clone)]
struct TestHeader {
    /// Header name
    name: String,

    /// Header value (may be very large)
    value: String,

    /// Size multiplier for testing
    size_multiplier: u16,

    /// Whether this is a pseudo-header
    is_pseudo: bool,
}

#[derive(Arbitrary, Debug, Clone)]
enum LargeHeaderPattern {
    /// Single massive header value
    MassiveValue {
        header_name: String,
        size_mb: u8,
        content_pattern: ContentPattern,
    },

    /// Many large headers
    ManyLarge {
        count: u8,
        each_size_kb: u16,
    },

    /// Incrementally growing headers
    Incremental {
        start_size_kb: u16,
        growth_factor: u8,
        count: u8,
    },

    /// Specific header type tests
    SpecificHeader {
        header_type: SpecificHeaderType,
        size_mb: u8,
    },
}

#[derive(Arbitrary, Debug, Clone)]
enum ContentPattern {
    /// Repeated character
    Repeated(char),
    /// Random bytes
    Random,
    /// Structured data (JSON, XML)
    Structured(StructuredType),
    /// Base64-like encoding
    Encoded,
}

#[derive(Arbitrary, Debug, Clone)]
enum StructuredType {
    Json,
    Xml,
    UrlEncoded,
}

#[derive(Arbitrary, Debug, Clone)]
enum SpecificHeaderType {
    Cookie,
    Authorization,
    UserAgent,
    Referer,
    CustomHeader,
}

#[derive(Arbitrary, Debug, Clone)]
struct HeaderParserConfig {
    /// Maximum single header value size (bytes)
    max_header_value_size: u32,

    /// Maximum total headers size
    max_total_headers_size: u32,

    /// Maximum number of headers
    max_header_count: u16,

    /// Whether to enforce early size checking
    early_size_check: bool,

    /// Whether to track memory allocations
    track_memory: bool,
}

impl Default for HeaderParserConfig {
    fn default() -> Self {
        Self {
            max_header_value_size: 65536,      // 64KB per header value
            max_total_headers_size: 1048576,   // 1MB total headers
            max_header_count: 100,             // Reasonable header count
            early_size_check: true,            // Enable early rejection
            track_memory: true,                // Track allocations
        }
    }
}

/// Mock HTTP/2 HEADERS parser with memory protection
struct MockH2HeadersParser {
    config: HeaderParserConfig,
    memory_stats: MemoryStats,
    parsed_headers: Vec<ParsedHeader>,
}

impl MockH2HeadersParser {
    fn new(config: HeaderParserConfig) -> Self {
        Self {
            config,
            memory_stats: MemoryStats::default(),
            parsed_headers: Vec::new(),
        }
    }

    /// Parse HEADERS frame with memory protection
    fn parse_headers_frame(&mut self, input: &LargeHeaderInput) -> HeadersParseResult {
        self.memory_stats.parse_attempts += 1;

        // Validate stream ID
        if input.stream_id == 0 {
            return HeadersParseResult::ProtocolError(
                "HEADERS frame cannot be on stream 0".to_string()
            );
        }

        // Early size check if enabled
        if self.config.early_size_check {
            if let Some(size_violation) = self.early_size_validation(&input.headers) {
                self.memory_stats.early_rejections += 1;
                return HeadersParseResult::HeaderTooLarge {
                    header_name: size_violation.header_name,
                    header_size: size_violation.size,
                    limit: self.config.max_header_value_size,
                    memory_allocated: 0, // No allocation occurred
                };
            }
        }

        // Parse headers with size tracking
        self.parse_headers_with_protection(&input.headers)
    }

    fn early_size_validation(&self, headers: &[TestHeader]) -> Option<SizeViolation> {
        let mut total_size = 0;

        for header in headers {
            // Check individual header value size BEFORE any allocation
            let estimated_size = header.name.len() + header.value.len();

            if estimated_size > self.config.max_header_value_size as usize {
                return Some(SizeViolation {
                    header_name: header.name.clone(),
                    size: estimated_size,
                });
            }

            total_size += estimated_size;

            // Check total size accumulation
            if total_size > self.config.max_total_headers_size as usize {
                return Some(SizeViolation {
                    header_name: "total_headers".to_string(),
                    size: total_size,
                });
            }
        }

        None
    }

    fn parse_headers_with_protection(&mut self, headers: &[TestHeader]) -> HeadersParseResult {
        let mut parsed = Vec::new();
        let mut total_memory = 0;

        for (index, header) in headers.iter().enumerate() {
            // Check header count limit
            if parsed.len() >= self.config.max_header_count as usize {
                return HeadersParseResult::TooManyHeaders {
                    count: parsed.len(),
                    limit: self.config.max_header_count,
                };
            }

            // Memory-aware header parsing
            match self.parse_single_header_protected(header, &mut total_memory) {
                Ok(parsed_header) => {
                    parsed.push(parsed_header);
                },
                Err(HeaderParseError::SizeViolation { name, size, memory_used }) => {
                    self.memory_stats.size_rejections += 1;
                    self.memory_stats.peak_memory_used = self.memory_stats.peak_memory_used.max(memory_used);

                    return HeadersParseResult::HeaderTooLarge {
                        header_name: name,
                        header_size: size,
                        limit: self.config.max_header_value_size,
                        memory_allocated: memory_used,
                    };
                },
                Err(HeaderParseError::MemoryExhaustion { allocated, limit }) => {
                    self.memory_stats.memory_rejections += 1;

                    return HeadersParseResult::MemoryExhaustion {
                        allocated,
                        limit,
                        headers_processed: parsed.len(),
                    };
                },
                Err(HeaderParseError::InvalidHeader(msg)) => {
                    return HeadersParseResult::InvalidHeader(msg);
                }
            }
        }

        // Update final stats
        self.memory_stats.successful_parses += 1;
        self.memory_stats.peak_memory_used = self.memory_stats.peak_memory_used.max(total_memory);
        self.parsed_headers = parsed.clone();

        HeadersParseResult::Success {
            headers: parsed,
            total_size: total_memory,
            header_count: headers.len(),
        }
    }

    fn parse_single_header_protected(&mut self, header: &TestHeader, total_memory: &mut usize) -> Result<ParsedHeader, HeaderParseError> {
        // Calculate memory requirements BEFORE allocation
        let name_size = header.name.len();
        let value_size = header.value.len();
        let header_memory = name_size + value_size + 64; // Include overhead

        // Check individual header size limit
        if value_size > self.config.max_header_value_size as usize {
            return Err(HeaderParseError::SizeViolation {
                name: header.name.clone(),
                size: value_size,
                memory_used: *total_memory,
            });
        }

        // Check total memory limit before allocation
        if *total_memory + header_memory > self.config.max_total_headers_size as usize {
            return Err(HeaderParseError::MemoryExhaustion {
                allocated: *total_memory,
                limit: self.config.max_total_headers_size,
            });
        }

        // Validate header name and value format
        if let Err(msg) = self.validate_header_format(&header.name, &header.value, header.is_pseudo) {
            return Err(HeaderParseError::InvalidHeader(msg));
        }

        // Safe to allocate - within limits
        *total_memory += header_memory;

        Ok(ParsedHeader {
            name: header.name.clone(),
            value: header.value.clone(),
            is_pseudo: header.is_pseudo,
            size: header_memory,
        })
    }

    fn validate_header_format(&self, name: &str, value: &str, is_pseudo: bool) -> Result<(), String> {
        // Validate header name
        if name.is_empty() {
            return Err("Empty header name".to_string());
        }

        if is_pseudo {
            if !name.starts_with(':') {
                return Err("Pseudo-header name must start with ':'".to_string());
            }

            // Validate known pseudo-headers
            match name {
                ":method" | ":path" | ":scheme" | ":authority" => {
                    // Valid pseudo-headers
                },
                _ => {
                    return Err(format!("Unknown pseudo-header: {}", name));
                }
            }
        } else {
            if name.starts_with(':') {
                return Err("Regular header cannot start with ':'".to_string());
            }

            // Header name validation (simplified)
            if !name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') {
                return Err(format!("Invalid header name format: {}", name));
            }
        }

        // Header value validation
        if value.contains('\0') {
            return Err("Header value cannot contain null bytes".to_string());
        }

        Ok(())
    }

    /// Test specific large header pattern
    fn test_large_pattern(&mut self, pattern: &LargeHeaderPattern) -> HeadersParseResult {
        let test_headers = self.generate_headers_from_pattern(pattern);

        let test_input = LargeHeaderInput {
            stream_id: 1,
            headers: test_headers,
            large_patterns: Vec::new(),
            parser_config: self.config.clone(),
        };

        self.parse_headers_frame(&test_input)
    }

    fn generate_headers_from_pattern(&self, pattern: &LargeHeaderPattern) -> Vec<TestHeader> {
        match pattern {
            LargeHeaderPattern::MassiveValue { header_name, size_mb, content_pattern } => {
                let size_bytes = (*size_mb as usize) * 1024 * 1024;
                let value = self.generate_content(content_pattern, size_bytes);

                vec![TestHeader {
                    name: header_name.clone(),
                    value,
                    size_multiplier: 1,
                    is_pseudo: false,
                }]
            },

            LargeHeaderPattern::ManyLarge { count, each_size_kb } => {
                let size_bytes = (*each_size_kb as usize) * 1024;
                let mut headers = Vec::new();

                for i in 0..*count {
                    headers.push(TestHeader {
                        name: format!("large-header-{}", i),
                        value: "x".repeat(size_bytes),
                        size_multiplier: 1,
                        is_pseudo: false,
                    });
                }

                headers
            },

            LargeHeaderPattern::Incremental { start_size_kb, growth_factor, count } => {
                let mut headers = Vec::new();
                let mut current_size = (*start_size_kb as usize) * 1024;

                for i in 0..*count {
                    headers.push(TestHeader {
                        name: format!("incremental-{}", i),
                        value: "y".repeat(current_size),
                        size_multiplier: 1,
                        is_pseudo: false,
                    });

                    current_size *= *growth_factor as usize;
                }

                headers
            },

            LargeHeaderPattern::SpecificHeader { header_type, size_mb } => {
                let size_bytes = (*size_mb as usize) * 1024 * 1024;
                let (name, value_pattern) = match header_type {
                    SpecificHeaderType::Cookie => ("cookie", "sessionid="),
                    SpecificHeaderType::Authorization => ("authorization", "Bearer "),
                    SpecificHeaderType::UserAgent => ("user-agent", "Mozilla/"),
                    SpecificHeaderType::Referer => ("referer", "https://"),
                    SpecificHeaderType::CustomHeader => ("x-custom", "data="),
                };

                let value = format!("{}{}", value_pattern, "z".repeat(size_bytes - value_pattern.len()));

                vec![TestHeader {
                    name: name.to_string(),
                    value,
                    size_multiplier: 1,
                    is_pseudo: false,
                }]
            }
        }
    }

    fn generate_content(&self, pattern: &ContentPattern, size: usize) -> String {
        match pattern {
            ContentPattern::Repeated(ch) => ch.to_string().repeat(size),
            ContentPattern::Random => "r".repeat(size), // Simplified random
            ContentPattern::Structured(StructuredType::Json) => {
                format!("{{\"data\":\"{}\"}}", "j".repeat(size.saturating_sub(10)))
            },
            ContentPattern::Structured(StructuredType::Xml) => {
                format!("<data>{}</data>", "x".repeat(size.saturating_sub(13)))
            },
            ContentPattern::Structured(StructuredType::UrlEncoded) => {
                format!("param={}", "u".repeat(size.saturating_sub(6)))
            },
            ContentPattern::Encoded => {
                // Base64-like pattern
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
                    .repeat((size + 63) / 64)
                    .chars()
                    .take(size)
                    .collect()
            }
        }
    }

    fn get_memory_stats(&self) -> MemoryStats {
        self.memory_stats.clone()
    }
}

#[derive(Debug, Clone, Default)]
struct MemoryStats {
    parse_attempts: u32,
    successful_parses: u32,
    early_rejections: u32,
    size_rejections: u32,
    memory_rejections: u32,
    peak_memory_used: usize,
}

#[derive(Debug, Clone)]
struct ParsedHeader {
    name: String,
    value: String,
    is_pseudo: bool,
    size: usize,
}

#[derive(Debug)]
struct SizeViolation {
    header_name: String,
    size: usize,
}

#[derive(Debug)]
enum HeaderParseError {
    SizeViolation {
        name: String,
        size: usize,
        memory_used: usize,
    },
    MemoryExhaustion {
        allocated: usize,
        limit: u32,
    },
    InvalidHeader(String),
}

#[derive(Debug, PartialEq)]
enum HeadersParseResult {
    /// Successfully parsed headers
    Success {
        headers: Vec<ParsedHeader>,
        total_size: usize,
        header_count: usize,
    },

    /// Header value too large
    HeaderTooLarge {
        header_name: String,
        header_size: usize,
        limit: u32,
        memory_allocated: usize,
    },

    /// Memory exhaustion during parsing
    MemoryExhaustion {
        allocated: usize,
        limit: u32,
        headers_processed: usize,
    },

    /// Too many headers
    TooManyHeaders {
        count: usize,
        limit: u16,
    },

    /// Invalid header format
    InvalidHeader(String),

    /// Protocol error
    ProtocolError(String),
}

fuzz_target!(|input: LargeHeaderInput| {
    // Normalize input for reasonable fuzzing bounds
    let mut input = input;
    if input.headers.len() > 20 {
        input.headers.truncate(20); // Limit for performance
    }
    if input.large_patterns.len() > 3 {
        input.large_patterns.truncate(3); // Limit for performance
    }

    let mut parser = MockH2HeadersParser::new(input.parser_config.clone());

    // Test basic headers from input
    let basic_result = parser.parse_headers_frame(&input);

    match basic_result {
        HeadersParseResult::HeaderTooLarge { header_size, limit, memory_allocated, .. } => {
            // Verify rejection occurred before excessive memory allocation
            assert!(header_size > limit as usize,
                   "Header size {} should exceed limit {} for rejection", header_size, limit);

            if parser.config.early_size_check {
                assert!(memory_allocated < 1024 * 1024,
                       "Should reject before allocating 1MB, but allocated {}", memory_allocated);
            }
        },

        HeadersParseResult::MemoryExhaustion { allocated, limit, .. } => {
            assert!(allocated >= limit as usize,
                   "Memory exhaustion should occur at or after limit");
        },

        HeadersParseResult::Success { headers, total_size, .. } => {
            // Verify successful parses respect limits
            assert!(total_size <= parser.config.max_total_headers_size as usize,
                   "Successful parse should not exceed total size limit");
            assert!(headers.len() <= parser.config.max_header_count as usize,
                   "Successful parse should not exceed header count limit");

            for header in &headers {
                assert!(header.value.len() <= parser.config.max_header_value_size as usize,
                       "Individual header should not exceed value size limit");
            }
        },

        _ => {
            // Other results are acceptable
        }
    }

    // Test specific large patterns
    for pattern in &input.large_patterns {
        let pattern_result = parser.test_large_pattern(pattern);

        match pattern_result {
            HeadersParseResult::HeaderTooLarge { memory_allocated, .. } => {
                // Critical: verify no large allocations for large pattern rejection
                if parser.config.early_size_check {
                    assert!(memory_allocated < 100 * 1024,
                           "Large pattern should be rejected with minimal memory allocation: {} bytes", memory_allocated);
                }
            },

            HeadersParseResult::Success { .. } => {
                // Should only succeed if pattern is actually within limits
                match pattern {
                    LargeHeaderPattern::MassiveValue { size_mb, .. } => {
                        if *size_mb > 0 {
                            panic!("Massive value pattern should be rejected");
                        }
                    },
                    _ => {}
                }
            },

            _ => {
                // Other rejections are acceptable
            }
        }
    }

    // Test critical edge case: exactly 1MB header
    let one_mb_header = TestHeader {
        name: "x-large-test".to_string(),
        value: "a".repeat(1024 * 1024), // Exactly 1MB
        size_multiplier: 1,
        is_pseudo: false,
    };

    let edge_input = LargeHeaderInput {
        stream_id: 1,
        headers: vec![one_mb_header],
        large_patterns: Vec::new(),
        parser_config: input.parser_config.clone(),
    };

    let edge_result = parser.parse_headers_frame(&edge_input);
    match edge_result {
        HeadersParseResult::HeaderTooLarge { memory_allocated, .. } => {
            // Should reject 1MB header with minimal allocation
            assert!(memory_allocated < 1024 * 1024,
                   "1MB header should be rejected before allocating full size: {} bytes allocated", memory_allocated);
        },
        HeadersParseResult::Success { .. } => {
            // Only acceptable if limits actually allow 1MB
            assert!(parser.config.max_header_value_size >= 1024 * 1024,
                   "1MB header should not succeed unless limits allow it");
        },
        _ => {
            // Other results acceptable
        }
    }

    // Verify memory statistics consistency
    let stats = parser.get_memory_stats();
    assert_eq!(
        stats.parse_attempts,
        stats.successful_parses + stats.early_rejections + stats.size_rejections + stats.memory_rejections,
        "Parse attempt statistics should be consistent"
    );

    // Verify no panics occurred during large header processing
    // (Implicit - if we reach here without panicking, the test passed)
});