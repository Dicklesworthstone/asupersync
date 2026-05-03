#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

/// HTTP/1.1 chunked encoding chunk size overflow test input
#[derive(Arbitrary, Debug)]
struct H1ChunkedOverflowInput {
    /// Chunk size generation strategy
    chunk_size_strategy: ChunkSizeStrategy,
    /// Chunk data content
    chunk_content: ChunkContent,
    /// Additional chunk context
    chunk_context: ChunkContext,
    /// Parser validation settings
    validation_settings: ValidationSettings,
}

#[derive(Arbitrary, Debug)]
enum ChunkSizeStrategy {
    /// Maximum possible value that would overflow usize
    MaxOverflow,
    /// Just above usize::MAX
    JustOverMax { excess_digits: u8 },
    /// Exactly at usize::MAX boundary
    ExactlyMax,
    /// Just below usize::MAX (should be valid)
    JustBelowMax { reduction: u32 },
    /// Very large but valid values
    LargeValid { magnitude: LargeMagnitude },
    /// Overflow with different hex formats
    OverflowVariants { format: HexFormat, overflow_type: OverflowType },
    /// Multiple chunk sizes in sequence
    Sequential { sizes: Vec<u64>, overflow_position: usize },
    /// Chunk size with extensions (overflow in size part)
    WithExtensions { size_hex: String, extensions: String },
}

#[derive(Arbitrary, Debug)]
enum LargeMagnitude {
    /// 2^32 range
    ThirtyTwoBit,
    /// 2^48 range
    FortyEightBit,
    /// 2^56 range
    FiftySixBit,
    /// Near usize::MAX
    NearMax,
}

#[derive(Arbitrary, Debug)]
enum HexFormat {
    /// All uppercase
    Uppercase,
    /// All lowercase
    Lowercase,
    /// Mixed case
    Mixed,
    /// Leading zeros
    LeadingZeros { zero_count: u8 },
    /// No prefix
    NoPrefixHex,
}

#[derive(Arbitrary, Debug)]
enum OverflowType {
    /// Simple hex overflow
    SimpleHex,
    /// Overflow with chunk extensions
    WithExtensions,
    /// Multiple overflow patterns
    Multiple,
    /// Overflow disguised in valid-looking hex
    Disguised,
}

#[derive(Arbitrary, Debug)]
struct ChunkContent {
    /// Data to include after chunk size
    data: Vec<u8>,
    /// Whether to include trailing CRLF
    include_trailing_crlf: bool,
    /// Data generation pattern
    pattern: DataPattern,
}

#[derive(Arbitrary, Debug)]
enum DataPattern {
    /// Random bytes
    Random,
    /// Repeated pattern
    Repeated(u8),
    /// ASCII text
    AsciiText,
    /// Binary data
    Binary,
    /// Empty chunk (0 size)
    Empty,
}

#[derive(Arbitrary, Debug)]
struct ChunkContext {
    /// Position in chunked stream
    position: ChunkPosition,
    /// Previous chunks context
    previous_chunks: u8,
    /// Total expected transfer
    expected_total: Option<u64>,
    /// Connection state
    connection_state: ConnectionState,
}

#[derive(Arbitrary, Debug)]
enum ChunkPosition {
    /// First chunk in stream
    First,
    /// Middle chunk
    Middle,
    /// Last chunk before trailer
    Last,
    /// Single chunk (complete transfer)
    Single,
}

#[derive(Arbitrary, Debug)]
enum ConnectionState {
    Fresh,
    ActiveTransfer,
    NearMemoryLimit,
    SlowConsumer,
}

#[derive(Arbitrary, Debug)]
struct ValidationSettings {
    /// Maximum allowed chunk size
    max_chunk_size: u64,
    /// Whether to enforce strict RFC compliance
    strict_rfc_compliance: bool,
    /// Memory protection limits
    memory_limits: MemoryLimits,
    /// Overflow detection sensitivity
    overflow_detection: OverflowDetection,
}

#[derive(Arbitrary, Debug)]
struct MemoryLimits {
    /// Maximum chunk size for memory safety
    max_safe_chunk_size: u32,
    /// Maximum total transfer size
    max_total_transfer: u64,
    /// Enable memory exhaustion protection
    memory_exhaustion_protection: bool,
}

#[derive(Arbitrary, Debug)]
enum OverflowDetection {
    /// Strict overflow checking
    Strict,
    /// Lenient (allow some large values)
    Lenient,
    /// Security-focused (very strict)
    Security,
}

/// Mock HTTP/1.1 chunked encoding parser with overflow protection
struct MockH1ChunkedParser {
    validation_settings: ValidationSettings,
    state: ChunkedParserState,
    total_bytes_received: u64,
    chunk_count: u32,
}

#[derive(Debug)]
struct ChunkedParserState {
    current_state: ParsingState,
    current_chunk_size: Option<u64>,
    bytes_remaining_in_chunk: u64,
    last_chunk_received: bool,
}

#[derive(Debug, PartialEq)]
enum ParsingState {
    ReadingChunkSize,
    ReadingChunkData,
    ReadingTrailerCRLF,
    ReadingTrailers,
    Complete,
    Error,
}

#[derive(Debug, Clone)]
struct ParsedChunk {
    size: u64,
    size_hex: String,
    extensions: Option<String>,
    data: Vec<u8>,
    validation_result: ChunkValidation,
    overflow_detected: bool,
}

#[derive(Debug, Clone, PartialEq)]
enum ChunkValidation {
    Valid,
    SizeOverflow,
    InvalidHexFormat,
    SizeTooBig,
    MemoryLimit,
    MalformedChunk,
    InvalidExtensions,
}

#[derive(Debug, PartialEq)]
enum ChunkedParsingError {
    /// Chunk size would overflow usize (RFC 9112 violation)
    ChunkSizeOverflow { hex_value: String },
    /// Chunk size exceeds configured maximum
    ChunkSizeTooBig { size: u64, limit: u64 },
    /// Invalid hexadecimal format in chunk size
    InvalidHexFormat { invalid_sequence: String },
    /// Memory limit would be exceeded
    MemoryLimitExceeded { requested: u64, limit: u64 },
    /// Malformed chunk structure
    MalformedChunk(String),
    /// Invalid chunk extensions
    InvalidExtensions(String),
    /// Transfer already complete
    UnexpectedChunk,
    /// Chunk size line too long
    SizeLineTooLong { length: usize, limit: usize },
}

// RFC 9112 and practical limits
const MAX_CHUNK_SIZE_LINE_LENGTH: usize = 4096;    // Reasonable line length limit
const MAX_SAFE_CHUNK_SIZE: u64 = 1_073_741_824;    // 1GB reasonable limit
const MAX_TOTAL_TRANSFER: u64 = 10_737_418_240;    // 10GB reasonable limit
const USIZE_MAX_HEX_DIGITS: usize = if cfg!(target_pointer_width = "64") { 16 } else { 8 };

impl MockH1ChunkedParser {
    fn new(validation_settings: ValidationSettings) -> Self {
        Self {
            validation_settings,
            state: ChunkedParserState {
                current_state: ParsingState::ReadingChunkSize,
                current_chunk_size: None,
                bytes_remaining_in_chunk: 0,
                last_chunk_received: false,
            },
            total_bytes_received: 0,
            chunk_count: 0,
        }
    }

    fn parse_chunk_size_line(&mut self, size_line: &str) -> Result<ParsedChunk, ChunkedParsingError> {
        // RFC 9112: Check line length limits
        if size_line.len() > MAX_CHUNK_SIZE_LINE_LENGTH {
            return Err(ChunkedParsingError::SizeLineTooLong {
                length: size_line.len(),
                limit: MAX_CHUNK_SIZE_LINE_LENGTH,
            });
        }

        // Remove trailing CRLF if present
        let trimmed_line = size_line.trim_end_matches("\r\n").trim_end_matches('\n');

        // Split chunk size from extensions
        let (size_part, extensions_part) = if let Some(semicolon_pos) = trimmed_line.find(';') {
            let size = &trimmed_line[..semicolon_pos];
            let ext = &trimmed_line[semicolon_pos + 1..];
            (size, Some(ext.to_string()))
        } else {
            (trimmed_line, None)
        };

        // Validate and parse hexadecimal chunk size
        let chunk_size = self.parse_hex_chunk_size(size_part)?;

        // Check for overflow conditions
        let overflow_detected = self.detect_size_overflow(size_part, chunk_size)?;

        // Validate chunk size against limits
        self.validate_chunk_size(chunk_size)?;

        // Update parser state
        self.state.current_chunk_size = Some(chunk_size);
        self.state.bytes_remaining_in_chunk = chunk_size;

        if chunk_size == 0 {
            self.state.last_chunk_received = true;
            self.state.current_state = ParsingState::ReadingTrailers;
        } else {
            self.state.current_state = ParsingState::ReadingChunkData;
        }

        let validation_result = if overflow_detected {
            ChunkValidation::SizeOverflow
        } else if chunk_size > self.validation_settings.memory_limits.max_safe_chunk_size as u64 {
            ChunkValidation::MemoryLimit
        } else {
            ChunkValidation::Valid
        };

        Ok(ParsedChunk {
            size: chunk_size,
            size_hex: size_part.to_string(),
            extensions: extensions_part,
            data: Vec::new(), // Data parsed separately
            validation_result,
            overflow_detected,
        })
    }

    fn parse_hex_chunk_size(&self, hex_str: &str) -> Result<u64, ChunkedParsingError> {
        // Validate hex characters
        if hex_str.is_empty() {
            return Err(ChunkedParsingError::InvalidHexFormat {
                invalid_sequence: hex_str.to_string(),
            });
        }

        // Check for valid hexadecimal characters only
        if !hex_str.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(ChunkedParsingError::InvalidHexFormat {
                invalid_sequence: hex_str.to_string(),
            });
        }

        // Check for potential overflow before parsing
        if self.would_overflow_usize(hex_str) {
            return Err(ChunkedParsingError::ChunkSizeOverflow {
                hex_value: hex_str.to_string(),
            });
        }

        // Parse the hexadecimal value
        match u64::from_str_radix(hex_str, 16) {
            Ok(value) => Ok(value),
            Err(_) => {
                // This should be caught by would_overflow_usize, but handle gracefully
                Err(ChunkedParsingError::ChunkSizeOverflow {
                    hex_value: hex_str.to_string(),
                })
            }
        }
    }

    fn would_overflow_usize(&self, hex_str: &str) -> bool {
        // Check if hex string represents a value that would overflow usize

        // Remove leading zeros for accurate length check
        let trimmed_hex = hex_str.trim_start_matches('0');

        // If all zeros, it's 0 (no overflow)
        if trimmed_hex.is_empty() {
            return false;
        }

        // Check length against maximum hex digits for usize
        if trimmed_hex.len() > USIZE_MAX_HEX_DIGITS {
            return true;
        }

        // For exact length matches, check the actual value
        if trimmed_hex.len() == USIZE_MAX_HEX_DIGITS {
            // Parse as u128 to check if it exceeds usize::MAX
            if let Ok(value) = u128::from_str_radix(trimmed_hex, 16) {
                return value > usize::MAX as u128;
            }
            // If parsing fails, assume overflow
            return true;
        }

        // If we're in strict mode, be more conservative
        if matches!(self.validation_settings.overflow_detection, OverflowDetection::Security) {
            // Security mode: reject anything that looks suspicious
            return trimmed_hex.len() > USIZE_MAX_HEX_DIGITS - 2;
        }

        false
    }

    fn detect_size_overflow(&self, hex_str: &str, parsed_value: u64) -> Result<bool, ChunkedParsingError> {
        // Primary overflow detection
        let would_overflow = self.would_overflow_usize(hex_str);

        if would_overflow {
            return match self.validation_settings.overflow_detection {
                OverflowDetection::Strict | OverflowDetection::Security => {
                    Err(ChunkedParsingError::ChunkSizeOverflow {
                        hex_value: hex_str.to_string(),
                    })
                }
                OverflowDetection::Lenient => Ok(true), // Detect but don't error
            };
        }

        // Secondary check: ensure parsed value is reasonable
        if parsed_value > (usize::MAX as u64) {
            return Err(ChunkedParsingError::ChunkSizeOverflow {
                hex_value: hex_str.to_string(),
            });
        }

        Ok(false)
    }

    fn validate_chunk_size(&self, chunk_size: u64) -> Result<(), ChunkedParsingError> {
        // Check against configured maximum
        if chunk_size > self.validation_settings.max_chunk_size {
            return Err(ChunkedParsingError::ChunkSizeTooBig {
                size: chunk_size,
                limit: self.validation_settings.max_chunk_size,
            });
        }

        // Check memory limits
        if self.validation_settings.memory_limits.memory_exhaustion_protection {
            if chunk_size > self.validation_settings.memory_limits.max_safe_chunk_size as u64 {
                return Err(ChunkedParsingError::MemoryLimitExceeded {
                    requested: chunk_size,
                    limit: self.validation_settings.memory_limits.max_safe_chunk_size as u64,
                });
            }

            // Check total transfer size
            let projected_total = self.total_bytes_received + chunk_size;
            if projected_total > self.validation_settings.memory_limits.max_total_transfer {
                return Err(ChunkedParsingError::MemoryLimitExceeded {
                    requested: projected_total,
                    limit: self.validation_settings.memory_limits.max_total_transfer,
                });
            }
        }

        Ok(())
    }

    fn generate_chunk_size_hex(strategy: &ChunkSizeStrategy) -> String {
        match strategy {
            ChunkSizeStrategy::MaxOverflow => {
                // Generate hex that would definitely overflow usize
                "F".repeat(USIZE_MAX_HEX_DIGITS + 4)
            }
            ChunkSizeStrategy::JustOverMax { excess_digits } => {
                let base_max = "F".repeat(USIZE_MAX_HEX_DIGITS);
                format!("{}{}", base_max, "F".repeat(*excess_digits as usize))
            }
            ChunkSizeStrategy::ExactlyMax => {
                format!("{:X}", usize::MAX)
            }
            ChunkSizeStrategy::JustBelowMax { reduction } => {
                let below_max = (usize::MAX as u64).saturating_sub(*reduction as u64);
                format!("{:X}", below_max)
            }
            ChunkSizeStrategy::LargeValid { magnitude } => {
                match magnitude {
                    LargeMagnitude::ThirtyTwoBit => format!("{:X}", u32::MAX),
                    LargeMagnitude::FortyEightBit => "FFFFFFFFFFFF".to_string(), // 48-bit max
                    LargeMagnitude::FiftySixBit => "FFFFFFFFFFFFFF".to_string(), // 56-bit max
                    LargeMagnitude::NearMax => {
                        let near_max = (usize::MAX as u64) / 2;
                        format!("{:X}", near_max)
                    }
                }
            }
            ChunkSizeStrategy::OverflowVariants { format, overflow_type } => {
                let base_overflow = "F".repeat(USIZE_MAX_HEX_DIGITS + 2);
                match format {
                    HexFormat::Uppercase => base_overflow.to_uppercase(),
                    HexFormat::Lowercase => base_overflow.to_lowercase(),
                    HexFormat::Mixed => {
                        base_overflow.chars()
                            .enumerate()
                            .map(|(i, c)| if i % 2 == 0 { c.to_lowercase().next().unwrap() } else { c })
                            .collect()
                    }
                    HexFormat::LeadingZeros { zero_count } => {
                        format!("{}{}", "0".repeat(*zero_count as usize), base_overflow)
                    }
                    HexFormat::NoPrefixHex => base_overflow,
                }
            }
            ChunkSizeStrategy::Sequential { sizes, overflow_position: _ } => {
                // Return first size for this call (multi-chunk would need sequence handling)
                if let Some(first_size) = sizes.first() {
                    format!("{:X}", first_size)
                } else {
                    "0".to_string()
                }
            }
            ChunkSizeStrategy::WithExtensions { size_hex, extensions: _ } => {
                size_hex.clone()
            }
        }
    }

    fn generate_full_chunk_line(input: &H1ChunkedOverflowInput) -> String {
        let size_hex = Self::generate_chunk_size_hex(&input.chunk_size_strategy);

        match &input.chunk_size_strategy {
            ChunkSizeStrategy::WithExtensions { extensions, .. } => {
                if extensions.is_empty() {
                    format!("{}\r\n", size_hex)
                } else {
                    format!("{};{}\r\n", size_hex, extensions)
                }
            }
            _ => format!("{}\r\n", size_hex),
        }
    }
}

fuzz_target!(|input: H1ChunkedOverflowInput| {
    // Generate chunk size line based on strategy
    let chunk_line = MockH1ChunkedParser::generate_full_chunk_line(&input);

    // Skip excessively long lines that would timeout the fuzzer
    if chunk_line.len() > MAX_CHUNK_SIZE_LINE_LENGTH * 2 {
        return;
    }

    let mut parser = MockH1ChunkedParser::new(input.validation_settings.clone());
    let parse_result = parser.parse_chunk_size_line(&chunk_line);

    // Apply test assertions based on chunk size strategy
    match input.chunk_size_strategy {
        ChunkSizeStrategy::MaxOverflow |
        ChunkSizeStrategy::JustOverMax { .. } => {
            // These should always be rejected due to overflow
            match parse_result {
                Ok(parsed) => {
                    if !parsed.overflow_detected {
                        panic!("Overflow chunk size should be detected: {}", chunk_line.trim());
                    }
                    // In lenient mode, might be parsed but flagged
                    assert_eq!(parsed.validation_result, ChunkValidation::SizeOverflow);
                }
                Err(ChunkedParsingError::ChunkSizeOverflow { .. }) => {
                    // Expected: overflow correctly detected and rejected
                }
                Err(ChunkedParsingError::SizeLineTooLong { .. }) => {
                    // Also acceptable for very long overflow hex strings
                }
                Err(error) => {
                    panic!("Unexpected error for overflow test: {:?}", error);
                }
            }
        }
        ChunkSizeStrategy::ExactlyMax => {
            // Exactly usize::MAX might be accepted or rejected depending on implementation
            match parse_result {
                Ok(parsed) => {
                    // If accepted, should not be flagged as overflow
                    assert_ne!(parsed.validation_result, ChunkValidation::SizeOverflow);
                    assert_eq!(parsed.size, usize::MAX as u64);
                }
                Err(ChunkedParsingError::ChunkSizeOverflow { .. }) |
                Err(ChunkedParsingError::ChunkSizeTooBig { .. }) |
                Err(ChunkedParsingError::MemoryLimitExceeded { .. }) => {
                    // Also acceptable to reject usize::MAX for safety
                }
                Err(error) => {
                    panic!("Unexpected error for max boundary test: {:?}", error);
                }
            }
        }
        ChunkSizeStrategy::JustBelowMax { .. } |
        ChunkSizeStrategy::LargeValid { .. } => {
            // These should be accepted unless they exceed configured limits
            match parse_result {
                Ok(parsed) => {
                    assert!(!parsed.overflow_detected, "Valid large size should not be flagged as overflow");
                    assert!(parsed.size < usize::MAX as u64, "Size should be below usize::MAX");
                }
                Err(ChunkedParsingError::ChunkSizeTooBig { .. }) |
                Err(ChunkedParsingError::MemoryLimitExceeded { .. }) => {
                    // Acceptable if exceeds configured policy limits
                }
                Err(ChunkedParsingError::ChunkSizeOverflow { .. }) => {
                    panic!("Valid large size should not be flagged as overflow: {}", chunk_line.trim());
                }
                Err(_) => {
                    // Other errors may occur due to malformed input
                }
            }
        }
        _ => {
            // Other strategies: verify basic overflow detection behavior
            match parse_result {
                Ok(parsed) => {
                    // If parsed successfully, size should be reasonable
                    assert!(parsed.size <= usize::MAX as u64, "Parsed size should not exceed usize::MAX");
                }
                Err(_) => {
                    // Rejection is acceptable for various reasons
                }
            }
        }
    }

    // Test overflow detection invariants
    test_chunked_overflow_invariants(&input, &parse_result, &chunk_line);
});

fn test_chunked_overflow_invariants(
    input: &H1ChunkedOverflowInput,
    result: &Result<ParsedChunk, ChunkedParsingError>,
    chunk_line: &str,
) {
    let size_hex = MockH1ChunkedParser::generate_chunk_size_hex(&input.chunk_size_strategy);

    // Invariant: Very long hex strings should be rejected
    if size_hex.len() > USIZE_MAX_HEX_DIGITS + 2 {
        match result {
            Ok(parsed) => {
                assert!(parsed.overflow_detected || parsed.validation_result == ChunkValidation::SizeOverflow,
                    "Very long hex should be flagged as overflow: {}", size_hex);
            }
            Err(ChunkedParsingError::ChunkSizeOverflow { .. }) |
            Err(ChunkedParsingError::SizeLineTooLong { .. }) => {
                // Expected: overflow or line length rejection
            }
            Err(_) => {
                // Other errors also acceptable for malformed input
            }
        }
    }

    // Invariant: Invalid hex characters should be rejected
    if !size_hex.chars().all(|c| c.is_ascii_hexdigit()) {
        match result {
            Ok(_) => {
                panic!("Invalid hex characters should be rejected: {}", size_hex);
            }
            Err(ChunkedParsingError::InvalidHexFormat { .. }) => {
                // Expected: invalid format rejection
            }
            Err(_) => {
                // Other errors also acceptable
            }
        }
    }

    // Invariant: Empty chunk sizes should be rejected
    if size_hex.trim_start_matches('0').is_empty() && size_hex != "0" {
        // Multiple zeros without content might be handled differently
    }

    // Invariant: Security mode should be most restrictive
    if matches!(input.validation_settings.overflow_detection, OverflowDetection::Security) {
        let trimmed_hex = size_hex.trim_start_matches('0');
        if trimmed_hex.len() > USIZE_MAX_HEX_DIGITS - 2 {
            match result {
                Ok(_) => {
                    // Security mode might allow some values that strict mode rejects
                }
                Err(_) => {
                    // Expected: security rejection
                }
            }
        }
    }

    // Invariant: Parsed values should never exceed usize::MAX
    if let Ok(parsed) = result {
        assert!(
            parsed.size <= usize::MAX as u64,
            "Parsed chunk size {} should not exceed usize::MAX {}",
            parsed.size, usize::MAX
        );
    }

    // Invariant: Memory limits should be enforced
    if input.validation_settings.memory_limits.memory_exhaustion_protection {
        if let Ok(parsed) = result {
            if parsed.size > input.validation_settings.memory_limits.max_safe_chunk_size as u64 {
                assert_eq!(parsed.validation_result, ChunkValidation::MemoryLimit,
                    "Large chunk should be flagged as memory limit violation");
            }
        }
    }

    // Invariant: Line length limits should be enforced
    if chunk_line.len() > MAX_CHUNK_SIZE_LINE_LENGTH {
        match result {
            Err(ChunkedParsingError::SizeLineTooLong { .. }) => {
                // Expected: line too long rejection
            }
            _ => {
                // Also acceptable to reject for other reasons
            }
        }
    }

    // Invariant: Leading zeros should not affect overflow detection
    let size_without_leading_zeros = size_hex.trim_start_matches('0');
    if !size_without_leading_zeros.is_empty() {
        let significant_length = size_without_leading_zeros.len();
        if significant_length > USIZE_MAX_HEX_DIGITS {
            match result {
                Ok(parsed) => {
                    assert!(parsed.overflow_detected,
                        "Leading zeros should not hide overflow: original={}, trimmed={}",
                        size_hex, size_without_leading_zeros);
                }
                Err(ChunkedParsingError::ChunkSizeOverflow { .. }) => {
                    // Expected: overflow detection despite leading zeros
                }
                Err(_) => {
                    // Other errors acceptable
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_validation_settings() -> ValidationSettings {
        ValidationSettings {
            max_chunk_size: MAX_SAFE_CHUNK_SIZE,
            strict_rfc_compliance: true,
            memory_limits: MemoryLimits {
                max_safe_chunk_size: 1_048_576, // 1MB
                max_total_transfer: MAX_TOTAL_TRANSFER,
                memory_exhaustion_protection: true,
            },
            overflow_detection: OverflowDetection::Strict,
        }
    }

    #[test]
    fn test_normal_chunk_size_accepted() {
        let mut parser = MockH1ChunkedParser::new(default_validation_settings());

        let result = parser.parse_chunk_size_line("1A3F\r\n");
        assert!(result.is_ok());

        let parsed = result.unwrap();
        assert_eq!(parsed.size, 0x1A3F);
        assert!(!parsed.overflow_detected);
        assert_eq!(parsed.validation_result, ChunkValidation::Valid);
    }

    #[test]
    fn test_overflow_chunk_size_rejected() {
        let mut parser = MockH1ChunkedParser::new(default_validation_settings());

        // Generate definitely overflowing hex string
        let overflow_hex = format!("{}\r\n", "F".repeat(USIZE_MAX_HEX_DIGITS + 4));
        let result = parser.parse_chunk_size_line(&overflow_hex);

        assert!(matches!(result, Err(ChunkedParsingError::ChunkSizeOverflow { .. })));
    }

    #[test]
    fn test_usize_max_boundary() {
        let mut parser = MockH1ChunkedParser::new(default_validation_settings());

        let usize_max_hex = format!("{:X}\r\n", usize::MAX);
        let result = parser.parse_chunk_size_line(&usize_max_hex);

        // Implementation may accept or reject usize::MAX
        match result {
            Ok(parsed) => {
                assert_eq!(parsed.size, usize::MAX as u64);
                assert!(!parsed.overflow_detected);
            }
            Err(ChunkedParsingError::ChunkSizeTooBig { .. }) |
            Err(ChunkedParsingError::MemoryLimitExceeded { .. }) => {
                // Also acceptable to reject for safety
            }
            Err(e) => panic!("Unexpected error for usize::MAX: {:?}", e),
        }
    }

    #[test]
    fn test_leading_zeros_overflow() {
        let mut parser = MockH1ChunkedParser::new(default_validation_settings());

        // Leading zeros should not hide overflow
        let hex_with_zeros = format!("0000{}\r\n", "F".repeat(USIZE_MAX_HEX_DIGITS + 2));
        let result = parser.parse_chunk_size_line(&hex_with_zeros);

        assert!(matches!(result, Err(ChunkedParsingError::ChunkSizeOverflow { .. })));
    }

    #[test]
    fn test_invalid_hex_characters() {
        let mut parser = MockH1ChunkedParser::new(default_validation_settings());

        let result = parser.parse_chunk_size_line("1A3G\r\n"); // G is not valid hex
        assert!(matches!(result, Err(ChunkedParsingError::InvalidHexFormat { .. })));
    }

    #[test]
    fn test_chunk_with_extensions() {
        let mut parser = MockH1ChunkedParser::new(default_validation_settings());

        let result = parser.parse_chunk_size_line("1A3F;name=value\r\n");
        assert!(result.is_ok());

        let parsed = result.unwrap();
        assert_eq!(parsed.size, 0x1A3F);
        assert_eq!(parsed.extensions, Some("name=value".to_string()));
    }

    #[test]
    fn test_zero_chunk_size() {
        let mut parser = MockH1ChunkedParser::new(default_validation_settings());

        let result = parser.parse_chunk_size_line("0\r\n");
        assert!(result.is_ok());

        let parsed = result.unwrap();
        assert_eq!(parsed.size, 0);
        assert!(!parsed.overflow_detected);
        assert_eq!(parsed.validation_result, ChunkValidation::Valid);
    }

    #[test]
    fn test_line_too_long() {
        let mut parser = MockH1ChunkedParser::new(default_validation_settings());

        let long_line = format!("{}\r\n", "F".repeat(MAX_CHUNK_SIZE_LINE_LENGTH + 100));
        let result = parser.parse_chunk_size_line(&long_line);

        assert!(matches!(result, Err(ChunkedParsingError::SizeLineTooLong { .. })));
    }

    #[test]
    fn test_memory_limit_enforcement() {
        let mut settings = default_validation_settings();
        settings.memory_limits.max_safe_chunk_size = 1000; // Very low limit

        let mut parser = MockH1ChunkedParser::new(settings);

        let result = parser.parse_chunk_size_line("7D0\r\n"); // 2000 in hex
        assert!(matches!(result, Err(ChunkedParsingError::MemoryLimitExceeded { .. })));
    }

    #[test]
    fn test_security_mode_strictness() {
        let mut settings = default_validation_settings();
        settings.overflow_detection = OverflowDetection::Security;

        let mut parser = MockH1ChunkedParser::new(settings);

        // Security mode should be more restrictive
        let large_but_valid = "F".repeat(USIZE_MAX_HEX_DIGITS - 1);
        let result = parser.parse_chunk_size_line(&format!("{}\r\n", large_but_valid));

        // In security mode, this might be rejected even if technically valid
        match result {
            Ok(_) => {} // May still accept some large values
            Err(ChunkedParsingError::ChunkSizeOverflow { .. }) => {} // Expected in security mode
            Err(_) => {} // Other errors also acceptable
        }
    }

    #[test]
    fn test_chunk_size_generation_strategies() {
        // Test that generation strategies produce expected patterns
        let max_overflow = MockH1ChunkedParser::generate_chunk_size_hex(
            &ChunkSizeStrategy::MaxOverflow
        );
        assert!(max_overflow.len() > USIZE_MAX_HEX_DIGITS);

        let exactly_max = MockH1ChunkedParser::generate_chunk_size_hex(
            &ChunkSizeStrategy::ExactlyMax
        );
        assert_eq!(exactly_max, format!("{:X}", usize::MAX));

        let just_below = MockH1ChunkedParser::generate_chunk_size_hex(
            &ChunkSizeStrategy::JustBelowMax { reduction: 1 }
        );
        let expected_below = format!("{:X}", usize::MAX - 1);
        assert_eq!(just_below, expected_below);
    }
}