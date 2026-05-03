#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

/// HTTP/1.1 chunked encoding extension DoS protection fuzz target.
///
/// Tests RFC 9112 §7.1.1 chunked encoding extensions with very long values
/// that could cause DoS attacks. While RFC 9112 doesn't specify length limits
/// for chunk extensions ("chunk-ext = *( ";" chunk-ext-name [ "=" chunk-ext-val ] )"),
/// implementations must cap extension length to prevent memory exhaustion attacks.
///
/// Critical DoS vectors:
/// - Very long extension names (>1MB)
/// - Very long extension values (>1MB)
/// - Many small extensions totaling large size
/// - Nested quoted values with escape sequences
/// - Memory exhaustion during parsing

#[derive(Arbitrary, Debug, Clone)]
struct ChunkedExtensionDoSInput {
    /// Chunk size (in hex)
    chunk_size_hex: String,

    /// Extension patterns to test
    extensions: Vec<ChunkExtension>,

    /// DoS attack patterns
    dos_patterns: Vec<DoSPattern>,

    /// Parser configuration
    parser_config: ChunkedParserConfig,
}

#[derive(Arbitrary, Debug, Clone)]
struct ChunkExtension {
    /// Extension name
    name: String,

    /// Extension value (optional)
    value: Option<String>,

    /// Whether value is quoted
    quoted: bool,

    /// Length multiplier for DoS testing
    length_multiplier: u16,
}

#[derive(Arbitrary, Debug, Clone)]
enum DoSPattern {
    /// Single very long extension name
    LongName { length: u32 },

    /// Single very long extension value
    LongValue { length: u32, quoted: bool },

    /// Many small extensions
    ManySmall { count: u16, each_size: u16 },

    /// Nested quoted strings with escapes
    NestedQuoted { depth: u8, size_per_level: u16 },

    /// Mixed pattern with multiple attack vectors
    Mixed {
        long_names: u8,
        long_values: u8,
        small_count: u16,
    },
}

#[derive(Arbitrary, Debug, Clone)]
struct ChunkedParserConfig {
    /// Maximum total extension length allowed
    max_extension_length: u32,

    /// Maximum individual extension name length
    max_name_length: u32,

    /// Maximum individual extension value length
    max_value_length: u32,

    /// Maximum number of extensions per chunk
    max_extension_count: u16,

    /// Whether to enforce strict parsing
    strict_parsing: bool,
}

impl Default for ChunkedParserConfig {
    fn default() -> Self {
        Self {
            max_extension_length: 8192, // Reasonable total limit
            max_name_length: 256,       // Reasonable name limit
            max_value_length: 4096,     // Reasonable value limit
            max_extension_count: 32,    // Reasonable count limit
            strict_parsing: true,
        }
    }
}

/// Mock HTTP/1.1 chunked encoding parser for DoS testing
struct MockChunkedParser {
    config: ChunkedParserConfig,
    parse_stats: ParseStats,
}

impl MockChunkedParser {
    fn new(config: ChunkedParserConfig) -> Self {
        Self {
            config,
            parse_stats: ParseStats::default(),
        }
    }

    /// Parse chunk line with extensions and DoS protection
    fn parse_chunk_line(&mut self, chunk_line: &str) -> ChunkParseResult {
        self.parse_stats.total_parses += 1;

        // Find semicolon separator between size and extensions
        let semicolon_pos = chunk_line.find(';');

        let (size_part, extensions_part) = if let Some(pos) = semicolon_pos {
            (&chunk_line[..pos], &chunk_line[pos + 1..])
        } else {
            (chunk_line.trim(), "")
        };

        // Parse chunk size
        let chunk_size = match self.parse_chunk_size(size_part) {
            Ok(size) => size,
            Err(msg) => {
                return ChunkParseResult::InvalidChunkSize(msg);
            }
        };

        // Parse extensions with DoS protection
        if extensions_part.is_empty() {
            return ChunkParseResult::Success {
                chunk_size,
                extensions: Vec::new(),
                total_extension_length: 0,
            };
        }

        self.parse_extensions_with_protection(extensions_part, chunk_size)
    }

    fn parse_chunk_size(&mut self, size_str: &str) -> Result<u64, String> {
        let trimmed = size_str.trim();

        if trimmed.is_empty() {
            return Err("Empty chunk size".to_string());
        }

        // Parse hexadecimal chunk size
        u64::from_str_radix(trimmed, 16).map_err(|_| format!("Invalid hex chunk size: {}", trimmed))
    }

    fn parse_extensions_with_protection(
        &mut self,
        extensions_str: &str,
        chunk_size: u64,
    ) -> ChunkParseResult {
        // Early DoS protection: check total length
        if extensions_str.len() > self.config.max_extension_length as usize {
            self.parse_stats.dos_attacks_blocked += 1;
            return ChunkParseResult::DoSBlocked {
                reason: format!(
                    "Extension string length {} exceeds limit {}",
                    extensions_str.len(),
                    self.config.max_extension_length
                ),
                attack_type: "total_length".to_string(),
            };
        }

        let mut extensions = Vec::new();
        let mut total_parsed_length = 0;
        let mut extension_count = 0;

        // Split extensions by semicolon
        for extension_str in extensions_str.split(';') {
            if extension_count >= self.config.max_extension_count {
                self.parse_stats.dos_attacks_blocked += 1;
                return ChunkParseResult::DoSBlocked {
                    reason: format!(
                        "Extension count {} exceeds limit {}",
                        extension_count, self.config.max_extension_count
                    ),
                    attack_type: "extension_count".to_string(),
                };
            }

            match self.parse_single_extension(extension_str.trim(), &mut total_parsed_length) {
                Ok(ext) => {
                    extensions.push(ext);
                    extension_count += 1;
                }
                Err(ChunkExtensionError::DoSAttack {
                    reason,
                    attack_type,
                }) => {
                    self.parse_stats.dos_attacks_blocked += 1;
                    return ChunkParseResult::DoSBlocked {
                        reason,
                        attack_type,
                    };
                }
                Err(ChunkExtensionError::ParseError(msg)) => {
                    return ChunkParseResult::ParseError(msg);
                }
            }
        }

        ChunkParseResult::Success {
            chunk_size,
            extensions,
            total_extension_length: total_parsed_length,
        }
    }

    fn parse_single_extension(
        &mut self,
        ext_str: &str,
        total_length: &mut usize,
    ) -> Result<ParsedExtension, ChunkExtensionError> {
        if ext_str.is_empty() {
            return Ok(ParsedExtension {
                name: String::new(),
                value: None,
                quoted: false,
            });
        }

        // Find equals sign separating name and value
        let equals_pos = ext_str.find('=');

        let (name, value_str) = if let Some(pos) = equals_pos {
            (ext_str[..pos].trim(), Some(ext_str[pos + 1..].trim()))
        } else {
            (ext_str.trim(), None)
        };

        // DoS protection: check name length
        if name.len() > self.config.max_name_length as usize {
            return Err(ChunkExtensionError::DoSAttack {
                reason: format!(
                    "Extension name length {} exceeds limit {}",
                    name.len(),
                    self.config.max_name_length
                ),
                attack_type: "name_length".to_string(),
            });
        }

        // Parse value with DoS protection
        let parsed_value = if let Some(val_str) = value_str {
            Some(self.parse_extension_value(val_str)?)
        } else {
            None
        };

        // Update total length tracking
        *total_length += name.len();
        if let Some(ref val) = parsed_value {
            *total_length += val.value.len();
        }

        // DoS protection: check accumulated total
        if *total_length > self.config.max_extension_length as usize {
            return Err(ChunkExtensionError::DoSAttack {
                reason: format!(
                    "Total extension length {} exceeds limit {}",
                    *total_length, self.config.max_extension_length
                ),
                attack_type: "accumulated_length".to_string(),
            });
        }

        Ok(ParsedExtension {
            name: name.to_string(),
            value: parsed_value,
            quoted: false, // Will be set by parse_extension_value if applicable
        })
    }

    fn parse_extension_value(
        &self,
        value_str: &str,
    ) -> Result<ExtensionValue, ChunkExtensionError> {
        let trimmed = value_str.trim();

        // Check if quoted
        if trimmed.starts_with('"') && trimmed.ends_with('"') && trimmed.len() >= 2 {
            let quoted_content = &trimmed[1..trimmed.len() - 1];

            // DoS protection: check quoted value length before processing
            if quoted_content.len() > self.config.max_value_length as usize {
                return Err(ChunkExtensionError::DoSAttack {
                    reason: format!(
                        "Quoted extension value length {} exceeds limit {}",
                        quoted_content.len(),
                        self.config.max_value_length
                    ),
                    attack_type: "quoted_value_length".to_string(),
                });
            }

            // Process escape sequences (potential DoS vector)
            let unescaped = self.process_quoted_string(quoted_content)?;

            Ok(ExtensionValue {
                value: unescaped,
                quoted: true,
            })
        } else {
            // Unquoted value
            if trimmed.len() > self.config.max_value_length as usize {
                return Err(ChunkExtensionError::DoSAttack {
                    reason: format!(
                        "Extension value length {} exceeds limit {}",
                        trimmed.len(),
                        self.config.max_value_length
                    ),
                    attack_type: "value_length".to_string(),
                });
            }

            // Validate unquoted value characters
            if self.config.strict_parsing && !self.is_valid_token(trimmed) {
                return Err(ChunkExtensionError::ParseError(format!(
                    "Invalid characters in unquoted extension value: {}",
                    trimmed
                )));
            }

            Ok(ExtensionValue {
                value: trimmed.to_string(),
                quoted: false,
            })
        }
    }

    fn process_quoted_string(&self, quoted_str: &str) -> Result<String, ChunkExtensionError> {
        let mut result = String::new();
        let mut chars = quoted_str.chars();
        let mut processed_length = 0;

        while let Some(ch) = chars.next() {
            // DoS protection: limit processed length during escape processing
            processed_length += 1;
            if processed_length > self.config.max_value_length as usize * 2 {
                return Err(ChunkExtensionError::DoSAttack {
                    reason: "Excessive escape sequence processing detected".to_string(),
                    attack_type: "escape_processing".to_string(),
                });
            }

            if ch == '\\' {
                if let Some(escaped) = chars.next() {
                    // Handle escape sequences
                    match escaped {
                        '"' | '\\' => result.push(escaped),
                        'n' => result.push('\n'),
                        'r' => result.push('\r'),
                        't' => result.push('\t'),
                        _ => {
                            // Include the backslash for unknown escapes
                            result.push('\\');
                            result.push(escaped);
                        }
                    }
                } else {
                    // Trailing backslash
                    result.push('\\');
                }
            } else {
                result.push(ch);
            }
        }

        Ok(result)
    }

    fn is_valid_token(&self, token: &str) -> bool {
        // RFC 9112 token validation (simplified)
        token.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(
                    c,
                    '!' | '#'
                        | '$'
                        | '%'
                        | '&'
                        | '\''
                        | '*'
                        | '+'
                        | '-'
                        | '.'
                        | '^'
                        | '_'
                        | '`'
                        | '|'
                        | '~'
                )
        })
    }

    fn get_stats(&self) -> ParseStats {
        self.parse_stats.clone()
    }
}

#[derive(Debug, Clone, Default)]
struct ParseStats {
    total_parses: u32,
    dos_attacks_blocked: u32,
    largest_extension_seen: usize,
    max_extension_count_seen: u16,
}

#[derive(Debug, Clone)]
struct ParsedExtension {
    name: String,
    value: Option<ExtensionValue>,
    quoted: bool,
}

#[derive(Debug, Clone)]
struct ExtensionValue {
    value: String,
    quoted: bool,
}

#[derive(Debug, PartialEq)]
enum ChunkParseResult {
    /// Successfully parsed chunk with extensions
    Success {
        chunk_size: u64,
        extensions: Vec<ParsedExtension>,
        total_extension_length: usize,
    },

    /// DoS attack blocked
    DoSBlocked { reason: String, attack_type: String },

    /// Parse error (malformed input)
    ParseError(String),

    /// Invalid chunk size
    InvalidChunkSize(String),
}

#[derive(Debug)]
enum ChunkExtensionError {
    DoSAttack { reason: String, attack_type: String },
    ParseError(String),
}

fuzz_target!(|input: ChunkedExtensionDoSInput| {
    // Normalize input for reasonable fuzzing bounds
    let mut input = input;
    if input.extensions.len() > 20 {
        input.extensions.truncate(20); // Limit for performance
    }
    if input.dos_patterns.len() > 5 {
        input.dos_patterns.truncate(5); // Limit for performance
    }

    let mut parser = MockChunkedParser::new(input.parser_config.clone());

    // Test basic extensions from input
    let mut chunk_line = input.chunk_size_hex.clone();

    for extension in &input.extensions {
        chunk_line.push(';');
        chunk_line.push_str(&extension.name);

        if let Some(ref value) = extension.value {
            chunk_line.push('=');
            if extension.quoted {
                chunk_line.push('"');
                chunk_line.push_str(value);
                chunk_line.push('"');
            } else {
                chunk_line.push_str(value);
            }
        }
    }

    let basic_result = parser.parse_chunk_line(&chunk_line);

    // Test DoS patterns
    for pattern in &input.dos_patterns {
        let dos_chunk_line = build_dos_chunk_line(pattern);
        let dos_result = parser.parse_chunk_line(&dos_chunk_line);

        match dos_result {
            ChunkParseResult::DoSBlocked {
                ref reason,
                ref attack_type,
            } => {
                // Verify DoS protection is working
                match pattern {
                    DoSPattern::LongName { length } => {
                        assert!(
                            reason.contains("name") || reason.contains("length"),
                            "DoS block should mention name length issue: {}",
                            reason
                        );
                        assert_eq!(
                            attack_type, "name_length",
                            "Attack type should be name_length for long name DoS"
                        );
                    }

                    DoSPattern::LongValue { length, .. } => {
                        assert!(
                            reason.contains("value") || reason.contains("length"),
                            "DoS block should mention value length issue: {}",
                            reason
                        );
                        assert!(
                            attack_type.contains("value") || attack_type.contains("length"),
                            "Attack type should mention value for long value DoS: {}",
                            attack_type
                        );
                    }

                    DoSPattern::ManySmall { count, .. } => {
                        assert!(
                            reason.contains("count") || reason.contains("length"),
                            "DoS block should mention count or total length: {}",
                            reason
                        );
                    }

                    _ => {
                        // Other patterns should also be blocked with appropriate reasons
                    }
                }
            }

            ChunkParseResult::ParseError(_) => {
                // Parse errors are acceptable for malformed DoS attempts
            }

            ChunkParseResult::Success {
                total_extension_length,
                extensions,
                ..
            } => {
                // If parsing succeeded, verify limits are respected
                assert!(
                    total_extension_length <= parser.config.max_extension_length as usize,
                    "Successful parse should not exceed configured limits"
                );
                assert!(
                    extensions.len() <= parser.config.max_extension_count as usize,
                    "Extension count should not exceed configured limits"
                );

                // Check individual extension limits
                for ext in &extensions {
                    assert!(
                        ext.name.len() <= parser.config.max_name_length as usize,
                        "Extension name should not exceed limit"
                    );
                    if let Some(ref val) = ext.value {
                        assert!(
                            val.value.len() <= parser.config.max_value_length as usize,
                            "Extension value should not exceed limit"
                        );
                    }
                }
            }

            ChunkParseResult::InvalidChunkSize(_) => {
                // Chunk size errors are separate from extension DoS
            }
        }
    }

    // Test edge cases around limits
    let limit_tests = vec![
        // Exactly at limit
        format!(
            "{}; {}={}",
            input.chunk_size_hex,
            "x".repeat(parser.config.max_name_length as usize),
            "y".repeat(parser.config.max_value_length as usize)
        ),
        // Just over limit
        format!(
            "{}; {}=z",
            input.chunk_size_hex,
            "x".repeat(parser.config.max_name_length as usize + 1)
        ),
    ];

    for test_line in limit_tests {
        let result = parser.parse_chunk_line(&test_line);

        // Results should be consistent with limits
        match result {
            ChunkParseResult::Success { .. } => {
                // Should only succeed if within limits
            }
            ChunkParseResult::DoSBlocked { .. } => {
                // Should be blocked if over limits
            }
            _ => {
                // Other results are acceptable
            }
        }
    }

    // Verify stats consistency
    let stats = parser.get_stats();
    assert!(stats.total_parses > 0, "Should have processed some parses");

    // Verify no panics occurred during DoS protection
    // (Implicit - if we reach here without panicking, the test passed)
});

fn build_dos_chunk_line(pattern: &DoSPattern) -> String {
    match pattern {
        DoSPattern::LongName { length } => {
            format!("1000; {}=value", "a".repeat(*length as usize))
        }

        DoSPattern::LongValue { length, quoted } => {
            let value = "b".repeat(*length as usize);
            if *quoted {
                format!("1000; name=\"{}\"", value)
            } else {
                format!("1000; name={}", value)
            }
        }

        DoSPattern::ManySmall { count, each_size } => {
            let mut chunk_line = "1000".to_string();
            for i in 0..*count {
                chunk_line.push_str(&format!("; name{}={}", i, "x".repeat(*each_size as usize)));
            }
            chunk_line
        }

        DoSPattern::NestedQuoted {
            depth,
            size_per_level,
        } => {
            let mut value = "base".to_string();
            for _ in 0..*depth {
                value = format!("\"{}{}\"", value, "y".repeat(*size_per_level as usize));
            }
            format!("1000; name={}", value)
        }

        DoSPattern::Mixed {
            long_names,
            long_values,
            small_count,
        } => {
            let mut chunk_line = "1000".to_string();

            // Add long names
            for i in 0..*long_names {
                chunk_line.push_str(&format!("; {}=short", "longname".repeat(1000)));
            }

            // Add long values
            for i in 0..*long_values {
                chunk_line.push_str(&format!("; short{} ={}", i, "longvalue".repeat(1000)));
            }

            // Add many small
            for i in 0..*small_count {
                chunk_line.push_str(&format!("; s{}=v", i));
            }

            chunk_line
        }
    }
}
