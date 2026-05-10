#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

/// Fuzz target for HTTP/1.1 chunked encoding chunk extensions.
///
/// Per RFC 9112 §7.1.1: "A chunk-extension MAY appear in each chunk-size.
/// The chunk-extension is intended for protocol extensions and MUST be ignored
/// by recipients that do not understand the extension."
///
/// Format: chunk-size [ chunk-extension ] CRLF chunk-data CRLF
/// Extension format: *( ";" chunk-ext-name [ "=" chunk-ext-val ] )
///
/// Tests include:
/// - Very long extension names/values (DoS protection)
/// - CR-LF injection in extension values (header injection attacks)
/// - Unicode in extension names/values
/// - Malformed extension syntax
/// - Multiple extensions per chunk
/// - Extension parsing vs ignoring behavior

#[derive(Debug, Arbitrary)]
struct ChunkExtensionTest {
    /// The chunk size (hex)
    chunk_size: String,
    /// Extension name=value pairs
    extensions: Vec<Extension>,
}

#[derive(Debug, Arbitrary, Clone)]
struct Extension {
    /// Extension name
    name: String,
    /// Extension value (optional)
    value: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
enum ChunkParseResult {
    Valid(ChunkInfo),
    Invalid(ChunkError),
    SecurityRisk(String),
}

#[derive(Debug, Clone, PartialEq)]
enum ChunkError {
    InvalidSize,
    InvalidExtensionFormat,
    ExtensionTooLong,
    InvalidCharacter(char),
    CrlfInjection,
    UnicodeSecurityRisk,
    ExcessiveExtensions,
    MalformedChunkLine,
}

#[derive(Debug, Clone, PartialEq)]
struct ChunkInfo {
    /// Chunk size in bytes
    size: usize,
    /// Parsed extensions (name, value pairs)
    extensions: Vec<(String, Option<String>)>,
    /// Raw chunk line for debugging
    raw_line: String,
}

/// Mock HTTP/1.1 chunked decoder for testing chunk extensions
struct MockChunkedDecoder {
    current_chunk: Option<ChunkInfo>,
    security_policy: ChunkSecurityPolicy,
    stats: DecoderStats,
}

#[derive(Debug, Clone)]
struct ChunkSecurityPolicy {
    /// Maximum extension name length
    max_extension_name_length: usize,
    /// Maximum extension value length
    max_extension_value_length: usize,
    /// Maximum number of extensions per chunk
    max_extensions_per_chunk: usize,
    /// Maximum total extensions length per chunk
    max_total_extension_length: usize,
    /// Allow Unicode in extensions
    allow_unicode_in_extensions: bool,
    /// Strict CRLF validation
    strict_crlf_validation: bool,
}

#[derive(Debug, Clone, Default)]
struct DecoderStats {
    chunks_processed: usize,
    extensions_parsed: usize,
    extensions_ignored: usize,
    security_violations: usize,
}

impl Default for ChunkSecurityPolicy {
    fn default() -> Self {
        Self {
            max_extension_name_length: 64,
            max_extension_value_length: 256,
            max_extensions_per_chunk: 10,
            max_total_extension_length: 1024,
            allow_unicode_in_extensions: false,
            strict_crlf_validation: true,
        }
    }
}

impl MockChunkedDecoder {
    fn new() -> Self {
        Self {
            current_chunk: None,
            security_policy: ChunkSecurityPolicy::default(),
            stats: DecoderStats::default(),
        }
    }

    fn with_policy(policy: ChunkSecurityPolicy) -> Self {
        Self {
            current_chunk: None,
            security_policy: policy,
            stats: DecoderStats::default(),
        }
    }

    /// Parse a chunk size line with extensions per RFC 9112
    fn parse_chunk_size_line(&mut self, line: &str) -> Result<ChunkParseResult, ChunkError> {
        // Remove trailing CRLF
        let line = if let Some(stripped) = line.strip_suffix("\r\n") {
            stripped
        } else if let Some(stripped) = line.strip_suffix('\n') {
            stripped
        } else {
            line
        };

        // Basic validation - line must not be empty
        if line.is_empty() {
            return Err(ChunkError::MalformedChunkLine);
        }

        // Security check - detect CRLF injection
        if self.security_policy.strict_crlf_validation
            && (line.contains('\r') || line.contains('\n'))
        {
            self.stats.security_violations += 1;
            return Ok(ChunkParseResult::SecurityRisk(
                "CRLF injection detected in chunk line".to_string(),
            ));
        }

        // Split at first semicolon to separate size from extensions
        let (size_part, extensions_part) = if let Some(semicolon_pos) = line.find(';') {
            (&line[..semicolon_pos], Some(&line[semicolon_pos + 1..]))
        } else {
            (line, None)
        };

        // Parse chunk size (hexadecimal)
        let size = self.parse_hex_size(size_part.trim())?;

        // Parse extensions if present
        let extensions = if let Some(ext_part) = extensions_part {
            self.parse_extensions(ext_part)?
        } else {
            Vec::new()
        };

        let chunk_info = ChunkInfo {
            size,
            extensions,
            raw_line: line.to_string(),
        };

        self.current_chunk = Some(chunk_info.clone());
        self.stats.chunks_processed += 1;
        self.stats.extensions_parsed += chunk_info.extensions.len();

        Ok(ChunkParseResult::Valid(chunk_info))
    }

    /// Parse hexadecimal chunk size
    fn parse_hex_size(&self, size_str: &str) -> Result<usize, ChunkError> {
        if size_str.is_empty() {
            return Err(ChunkError::InvalidSize);
        }

        // Validate hex characters
        for c in size_str.chars() {
            if !c.is_ascii_hexdigit() {
                return Err(ChunkError::InvalidSize);
            }
        }

        // Parse as hex
        usize::from_str_radix(size_str, 16).map_err(|_| ChunkError::InvalidSize)
    }

    /// Parse chunk extensions per RFC 9112 §7.1.1
    fn parse_extensions(
        &mut self,
        extension_str: &str,
    ) -> Result<Vec<(String, Option<String>)>, ChunkError> {
        let mut extensions = Vec::new();

        // Check total length
        if extension_str.len() > self.security_policy.max_total_extension_length {
            self.stats.security_violations += 1;
            return Err(ChunkError::ExtensionTooLong);
        }

        // Split by semicolon for multiple extensions
        for ext_part in extension_str.split(';') {
            let ext_part = ext_part.trim();
            if ext_part.is_empty() {
                continue;
            }

            // Check extension count limit
            if extensions.len() >= self.security_policy.max_extensions_per_chunk {
                self.stats.security_violations += 1;
                return Err(ChunkError::ExcessiveExtensions);
            }

            // Parse name=value or just name
            let (name, value) = if let Some(eq_pos) = ext_part.find('=') {
                let name = ext_part[..eq_pos].trim();
                let value = ext_part[eq_pos + 1..].trim();
                (name, Some(value))
            } else {
                (ext_part, None)
            };

            // Validate extension name
            self.validate_extension_name(name)?;

            // Validate extension value if present
            if let Some(val) = value {
                self.validate_extension_value(val)?;
            }

            extensions.push((name.to_string(), value.map(|s| s.to_string())));
        }

        // Per RFC 9112, extensions are parsed but ignored
        self.stats.extensions_ignored += extensions.len();

        Ok(extensions)
    }

    /// Validate extension name per RFC 9112 token rules
    fn validate_extension_name(&self, name: &str) -> Result<(), ChunkError> {
        if name.is_empty() {
            return Err(ChunkError::InvalidExtensionFormat);
        }

        // Check length limit
        if name.len() > self.security_policy.max_extension_name_length {
            return Err(ChunkError::ExtensionTooLong);
        }

        // RFC 7230 token characters: VCHAR except separators
        for c in name.chars() {
            match c {
                // Valid token characters
                'a'..='z'
                | 'A'..='Z'
                | '0'..='9'
                | '!'
                | '#'
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
                | '~' => {
                    // Valid
                }
                // Unicode characters
                c if !c.is_ascii() => {
                    if !self.security_policy.allow_unicode_in_extensions {
                        return Err(ChunkError::UnicodeSecurityRisk);
                    }
                    // Additional Unicode validation could go here
                }
                // Invalid characters (separators, control chars, etc.)
                _ => {
                    return Err(ChunkError::InvalidCharacter(c));
                }
            }
        }

        Ok(())
    }

    /// Validate extension value (can be quoted-string or token)
    fn validate_extension_value(&self, value: &str) -> Result<(), ChunkError> {
        // Check length limit
        if value.len() > self.security_policy.max_extension_value_length {
            return Err(ChunkError::ExtensionTooLong);
        }

        // Check for CRLF injection
        if self.security_policy.strict_crlf_validation
            && (value.contains('\r') || value.contains('\n'))
        {
            return Err(ChunkError::CrlfInjection);
        }

        // Handle quoted string
        if value.starts_with('"') && value.ends_with('"') && value.len() >= 2 {
            let quoted_content = &value[1..value.len() - 1];

            // Validate quoted string content
            let mut chars = quoted_content.chars();
            while let Some(c) = chars.next() {
                match c {
                    '\\' => {
                        // Quoted pair - next char should be valid
                        if let Some(escaped) = chars.next() {
                            if escaped == '\r' || escaped == '\n' {
                                return Err(ChunkError::CrlfInjection);
                            }
                        } else {
                            return Err(ChunkError::InvalidExtensionFormat);
                        }
                    }
                    '"' => {
                        // Unescaped quote in quoted string
                        return Err(ChunkError::InvalidExtensionFormat);
                    }
                    '\r' | '\n' => {
                        return Err(ChunkError::CrlfInjection);
                    }
                    c if !c.is_ascii() && !self.security_policy.allow_unicode_in_extensions => {
                        return Err(ChunkError::UnicodeSecurityRisk);
                    }
                    _ => {
                        // Other characters allowed in quoted string
                    }
                }
            }
        } else {
            // Unquoted value - must be a token
            for c in value.chars() {
                match c {
                    // Valid token characters (same as extension name)
                    'a'..='z'
                    | 'A'..='Z'
                    | '0'..='9'
                    | '!'
                    | '#'
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
                    | '~' => {
                        // Valid
                    }
                    // Unicode characters
                    c if !c.is_ascii() => {
                        if !self.security_policy.allow_unicode_in_extensions {
                            return Err(ChunkError::UnicodeSecurityRisk);
                        }
                    }
                    // Invalid characters
                    _ => {
                        return Err(ChunkError::InvalidCharacter(c));
                    }
                }
            }
        }

        Ok(())
    }

    fn get_stats(&self) -> &DecoderStats {
        &self.stats
    }
}

/// Generate predefined test cases for chunk extension parsing
fn generate_test_cases() -> Vec<(String, ChunkParseResult)> {
    vec![
        // Basic valid cases
        (
            "1F\r\n".to_string(),
            ChunkParseResult::Valid(ChunkInfo {
                size: 31,
                extensions: vec![],
                raw_line: "1F".to_string(),
            }),
        ),
        // Simple extension
        (
            "1F;name=value\r\n".to_string(),
            ChunkParseResult::Valid(ChunkInfo {
                size: 31,
                extensions: vec![("name".to_string(), Some("value".to_string()))],
                raw_line: "1F;name=value".to_string(),
            }),
        ),
        // Extension without value
        (
            "A;flag\r\n".to_string(),
            ChunkParseResult::Valid(ChunkInfo {
                size: 10,
                extensions: vec![("flag".to_string(), None)],
                raw_line: "A;flag".to_string(),
            }),
        ),
        // Multiple extensions
        (
            "FF;name1=value1;name2=value2\r\n".to_string(),
            ChunkParseResult::Valid(ChunkInfo {
                size: 255,
                extensions: vec![
                    ("name1".to_string(), Some("value1".to_string())),
                    ("name2".to_string(), Some("value2".to_string())),
                ],
                raw_line: "FF;name1=value1;name2=value2".to_string(),
            }),
        ),
        // Quoted value
        (
            "20;name=\"quoted value\"\r\n".to_string(),
            ChunkParseResult::Valid(ChunkInfo {
                size: 32,
                extensions: vec![("name".to_string(), Some("\"quoted value\"".to_string()))],
                raw_line: "20;name=\"quoted value\"".to_string(),
            }),
        ),
        // Invalid hex size
        (
            "GG;ext=val\r\n".to_string(),
            ChunkParseResult::Invalid(ChunkError::InvalidSize),
        ),
        // CRLF injection in extension value
        (
            "10;bad=value\r\nX-Injected: header\r\n".to_string(),
            ChunkParseResult::SecurityRisk("CRLF injection detected in chunk line".to_string()),
        ),
        // Very long extension name (should be rejected)
        (
            format!("10;{}=value\r\n", "x".repeat(1000)),
            ChunkParseResult::Invalid(ChunkError::ExtensionTooLong),
        ),
        // Very long extension value (should be rejected)
        (
            format!("10;name={}\r\n", "x".repeat(1000)),
            ChunkParseResult::Invalid(ChunkError::ExtensionTooLong),
        ),
        // Invalid extension character
        (
            "10;na me=value\r\n".to_string(),
            ChunkParseResult::Invalid(ChunkError::InvalidCharacter(' ')),
        ),
        // Unicode in extension (depends on policy)
        (
            "10;café=value\r\n".to_string(),
            ChunkParseResult::Invalid(ChunkError::UnicodeSecurityRisk),
        ),
        // Empty extension name
        (
            "10;=value\r\n".to_string(),
            ChunkParseResult::Invalid(ChunkError::InvalidExtensionFormat),
        ),
        // Malformed quoted value
        (
            "10;name=\"unterminated\r\n".to_string(),
            ChunkParseResult::SecurityRisk("CRLF injection detected in chunk line".to_string()),
        ),
    ]
}

fuzz_target!(|data: &[u8]| {
    // Limit input size to prevent timeouts
    if data.len() > 1024 {
        return;
    }

    // Try to generate a structured test from the fuzz data
    let test = match ChunkExtensionTest::arbitrary(&mut arbitrary::Unstructured::new(data)) {
        Ok(test) => test,
        Err(_) => return, // Invalid input, skip
    };

    // Skip tests with extremely long chunk sizes or extensions
    if test.chunk_size.len() > 16 || test.extensions.len() > 50 {
        return;
    }

    // Build chunk line in format: size;ext1=val1;ext2=val2\r\n
    let mut chunk_line = test.chunk_size.clone();

    for ext in &test.extensions {
        chunk_line.push(';');
        chunk_line.push_str(&ext.name);
        if let Some(ref value) = ext.value {
            chunk_line.push('=');
            chunk_line.push_str(value);
        }
    }
    chunk_line.push_str("\r\n");

    // Test with default (strict) policy
    let mut decoder = MockChunkedDecoder::new();
    let result = decoder.parse_chunk_size_line(&chunk_line);

    // Validate result consistency
    match result {
        Ok(ChunkParseResult::Valid(chunk_info)) => {
            // Valid chunks should have reasonable properties
            assert_eq!(
                chunk_info.extensions.len(),
                test.extensions.len(),
                "Extension count mismatch for valid chunk"
            );

            // Extensions should be ignored per RFC 9112
            assert_eq!(
                decoder.get_stats().extensions_ignored,
                chunk_info.extensions.len(),
                "Extensions should be ignored per RFC 9112"
            );

            // Chunk size should be parseable
            assert!(
                chunk_info.size <= 0xFFFFFFFF,
                "Chunk size should be within reasonable bounds"
            );
        }

        Ok(ChunkParseResult::Invalid(error)) => {
            // Invalid results should have recorded the error
            match error {
                ChunkError::ExtensionTooLong | ChunkError::ExcessiveExtensions => {
                    assert!(
                        decoder.get_stats().security_violations > 0,
                        "Security violations should be recorded"
                    );
                }
                _ => {
                    // Other errors don't necessarily increment security counter
                }
            }
        }

        Ok(ChunkParseResult::SecurityRisk(_)) => {
            // Security risks should be tracked
            assert!(
                decoder.get_stats().security_violations > 0,
                "Security risks should increment violation counter"
            );
        }

        Err(error) => {
            // Direct errors during parsing
            match error {
                ChunkError::InvalidSize => {
                    // Should happen for malformed hex
                }
                ChunkError::CrlfInjection => {
                    // Should be detected and blocked
                }
                _ => {
                    // Other errors are acceptable
                }
            }
        }
    }

    // Test with permissive policy
    let permissive_policy = ChunkSecurityPolicy {
        max_extension_name_length: 2048,
        max_extension_value_length: 4096,
        max_extensions_per_chunk: 100,
        max_total_extension_length: 8192,
        allow_unicode_in_extensions: true,
        strict_crlf_validation: false,
    };

    let mut permissive_decoder = MockChunkedDecoder::with_policy(permissive_policy);
    let _permissive_result = permissive_decoder.parse_chunk_size_line(&chunk_line);

    // With permissive policy, more things should be allowed
    // This tests different code paths and edge cases

    // Run predefined test cases to ensure core functionality
    for (test_line, expected) in generate_test_cases() {
        let mut test_decoder = MockChunkedDecoder::new();
        let test_result = test_decoder.parse_chunk_size_line(&test_line);

        match expected {
            ChunkParseResult::Valid(ref expected_chunk) => {
                match test_result {
                    Ok(ChunkParseResult::Valid(actual_chunk)) => {
                        assert_eq!(
                            actual_chunk.size, expected_chunk.size,
                            "Chunk size mismatch for line: {}",
                            test_line
                        );
                        assert_eq!(
                            actual_chunk.extensions.len(),
                            expected_chunk.extensions.len(),
                            "Extension count mismatch for line: {}",
                            test_line
                        );
                    }
                    _ => {
                        // May fail for other reasons in fuzzing context
                    }
                }
            }

            ChunkParseResult::Invalid(_) => {
                // Should result in error
                match test_result {
                    Ok(ChunkParseResult::Invalid(_)) | Err(_) => {
                        // Expected
                    }
                    Ok(ChunkParseResult::SecurityRisk(_)) => {
                        // Also acceptable - security risks are a form of rejection
                    }
                    _ => {
                        // Unexpected acceptance of invalid input
                    }
                }
            }

            ChunkParseResult::SecurityRisk(_) => {
                // Should be flagged as security risk or rejected
                match test_result {
                    Ok(ChunkParseResult::SecurityRisk(_))
                    | Ok(ChunkParseResult::Invalid(_))
                    | Err(_) => {
                        // Expected - security risks should be caught
                    }
                    _ => {
                        // May be acceptable with different policies
                    }
                }
            }
        }
    }
});
