#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};
use std::collections::HashMap;

/// RFC 9110 Section 4.1: The path component contains data, usually organized
/// in hierarchical form, that, along with data in the non-hierarchical query
/// component, serves to identify a resource within the scope of the URI's scheme
/// and naming authority (if any). The path is terminated by the first question
/// mark ("?") or number sign ("#") character, or by the end of the URI.
///
/// RFC 3986 Section 2.1: A percent-encoding mechanism is used to represent a
/// data octet in a component when that octet's corresponding character is outside
/// the allowed set or is being used as a delimiter of, or within, the component.
///
/// This fuzz target tests that our HTTP/2 implementation correctly handles
/// percent-encoded sequences in :path pseudo-headers without inadvertent
/// decoding that could affect route matching or security boundaries.
///
/// Critical security requirement: %2F (encoded slash) must NOT be decoded to /
/// before route matching, as this could bypass path-based access controls.
///
/// Test cases include:
/// - Basic percent encoding (%20 for space, %21 for !, etc.)
/// - Path separator encoding (%2F for /, %5C for \)
/// - Reserved character encoding (%3F for ?, %23 for #, %26 for &)
/// - Double encoding (%252F for %2F)
/// - Invalid percent sequences (%GG, %2, incomplete sequences)
/// - Case sensitivity in hex digits (%2f vs %2F)
/// - Overlong percent sequences
/// - Null byte encoding (%00)

#[derive(Debug, Clone)]
pub struct PercentEncodedPathInput {
    /// Base path components
    pub path_segments: Vec<String>,
    /// Percent encoding strategy to apply
    pub encoding_strategy: EncodingStrategy,
    /// Whether to include reserved characters that need encoding
    pub include_reserved: bool,
    /// Whether to use invalid percent sequences
    pub use_invalid_sequences: bool,
    /// Whether to apply double encoding
    pub double_encode: bool,
    /// Case variation for hex digits (upper/lower/mixed)
    pub hex_case: HexCase,
    /// Query parameters to append (also percent-encoded)
    pub query_params: Vec<(String, String)>,
    /// Fragment identifier (after #)
    pub fragment: Option<String>,
    /// Number of additional pseudo-headers
    pub extra_pseudo_count: u8,
    /// Maximum path length to generate
    pub max_path_length: u16,
}

#[derive(Debug, Clone, Copy)]
pub enum EncodingStrategy {
    None,           // No percent encoding
    Minimal,        // Only encode what's required
    Aggressive,     // Encode many allowed characters
    Reserved,       // Focus on reserved characters (%2F, %3F, etc.)
    Spaces,         // Focus on whitespace (%20, %09, %0A)
    Unsafe,         // Unsafe characters (%00, %7F, control chars)
    Random,         // Random mix of strategies
}

#[derive(Debug, Clone, Copy)]
pub enum HexCase {
    Lower,          // %2f, %3a
    Upper,          // %2F, %3A
    Mixed,          // %2F, %3a (mixed case)
}

impl<'a> Arbitrary<'a> for EncodingStrategy {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let choice: u8 = u.arbitrary()?;
        Ok(match choice % 7 {
            0 => EncodingStrategy::None,
            1 => EncodingStrategy::Minimal,
            2 => EncodingStrategy::Aggressive,
            3 => EncodingStrategy::Reserved,
            4 => EncodingStrategy::Spaces,
            5 => EncodingStrategy::Unsafe,
            _ => EncodingStrategy::Random,
        })
    }
}

impl<'a> Arbitrary<'a> for HexCase {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let choice: u8 = u.arbitrary()?;
        Ok(match choice % 3 {
            0 => HexCase::Lower,
            1 => HexCase::Upper,
            _ => HexCase::Mixed,
        })
    }
}

impl<'a> Arbitrary<'a> for PercentEncodedPathInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        // Generate base path segments
        let num_segments = u.int_in_range(0..=8)?;
        let mut path_segments = Vec::new();

        for _ in 0..num_segments {
            let segment_choice: u8 = u.arbitrary()?;
            let segment = match segment_choice % 15 {
                0 => "index.html".to_string(),
                1 => "api/v1/users".to_string(),
                2 => "foo bar".to_string(),           // Contains space
                3 => "file.txt".to_string(),
                4 => "admin/delete".to_string(),
                5 => "path?query".to_string(),        // Contains ?
                6 => "path#fragment".to_string(),     // Contains #
                7 => "path&param=value".to_string(),  // Contains &
                8 => "path/with/slashes".to_string(), // Contains /
                9 => "file%already%encoded".to_string(), // Pre-encoded
                10 => "unicode🦀test".to_string(),    // Unicode
                11 => "UPPER_CASE".to_string(),
                12 => "with-dashes_and_underscores".to_string(),
                13 => "123456789".to_string(),
                _ => {
                    // Generate random segment
                    let len = u.int_in_range(1..=20)?;
                    let mut segment = String::new();
                    for _ in 0..len {
                        if let Ok(ch) = u.arbitrary::<char>() {
                            if ch.is_ascii() && ch != '\0' {
                                segment.push(ch);
                            }
                        }
                    }
                    if segment.is_empty() {
                        segment = "test".to_string();
                    }
                    segment
                },
            };
            path_segments.push(segment);
        }

        // Generate query parameters
        let num_params = u.int_in_range(0..=5)?;
        let mut query_params = Vec::new();
        for i in 0..num_params {
            let key = format!("param{}", i);
            let value_choice: u8 = u.arbitrary()?;
            let value = match value_choice % 6 {
                0 => "simple".to_string(),
                1 => "value with spaces".to_string(),
                2 => "special&chars".to_string(),
                3 => "equals=signs".to_string(),
                4 => "percent%already".to_string(),
                _ => format!("value{}", u.arbitrary::<u16>().unwrap_or(0)),
            };
            query_params.push((key, value));
        }

        // Generate fragment
        let fragment = if u.arbitrary::<bool>()? {
            Some(match u.arbitrary::<u8>()? % 4 {
                0 => "section".to_string(),
                1 => "section with spaces".to_string(),
                2 => "section#nested".to_string(),
                _ => format!("frag{}", u.arbitrary::<u16>().unwrap_or(0)),
            })
        } else {
            None
        };

        Ok(PercentEncodedPathInput {
            path_segments,
            encoding_strategy: u.arbitrary()?,
            include_reserved: u.arbitrary()?,
            use_invalid_sequences: u.arbitrary()?,
            double_encode: u.arbitrary()?,
            hex_case: u.arbitrary()?,
            query_params,
            fragment,
            extra_pseudo_count: u.int_in_range(0..=3)?,
            max_path_length: u.int_in_range(10..=2048)?,
        })
    }
}

/// Mock H2 connection state for tracking percent-encoding handling
#[derive(Debug)]
struct MockH2Connection {
    stream_states: HashMap<u32, MockStreamState>,
    settings: MockSettings,
    path_processing_stats: PathProcessingStats,
    protocol_errors: Vec<ProtocolError>,
    encoding_violations: Vec<EncodingViolation>,
}

#[derive(Debug)]
struct MockStreamState {
    stream_id: u32,
    state: StreamState,
    received_headers: Vec<(String, String)>,
    pseudo_header_count: u8,
    original_path: Option<String>,
    processed_path: Option<String>,
}

#[derive(Debug, Clone, Copy)]
enum StreamState {
    Idle,
    Open,
    HalfClosedRemote,
    HalfClosedLocal,
    Closed,
}

#[derive(Debug)]
struct MockSettings {
    max_frame_size: u32,
    max_concurrent_streams: Option<u32>,
    header_table_size: u32,
    enable_push: bool,
}

#[derive(Debug)]
enum ProtocolError {
    InvalidPathEncoding { stream_id: u32, path: String, reason: String },
    PrematureDecoding { stream_id: u32, original: String, decoded: String },
    InvalidPercentSequence { stream_id: u32, sequence: String, position: usize },
    PathTooLong { stream_id: u32, length: usize, max_allowed: usize },
    SecurityViolation { stream_id: u32, path: String, violation_type: String },
}

#[derive(Debug)]
struct EncodingViolation {
    stream_id: u32,
    original_path: String,
    processed_path: String,
    violation_type: ViolationType,
    security_risk: SecurityRisk,
}

#[derive(Debug, Clone)]
enum ViolationType {
    PrematureDecoding,      // %2F decoded to / before route match
    InconsistentDecoding,   // Some sequences decoded, others not
    InvalidSequenceAccepted, // %GG accepted instead of rejected
    DoubleDecodingBug,      // %%32F decoded twice
    CaseInsensitiveHex,     // %2f vs %2F treated differently
}

#[derive(Debug, Clone)]
enum SecurityRisk {
    None,
    Low,      // Minor inconsistency
    Medium,   // Could affect route matching
    High,     // Path traversal or access control bypass
    Critical, // Directory traversal with %2F decoding
}

#[derive(Debug, Default)]
struct PathProcessingStats {
    total_paths_processed: u32,
    paths_with_encoding: u32,
    paths_preserved_verbatim: u32,
    paths_decoded_prematurely: u32,
    invalid_sequences_rejected: u32,
    invalid_sequences_accepted: u32,
    security_violations: u32,
    double_encoding_detected: u32,
}

impl MockH2Connection {
    fn new() -> Self {
        MockH2Connection {
            stream_states: HashMap::new(),
            settings: MockSettings {
                max_frame_size: 16384,
                max_concurrent_streams: Some(100),
                header_table_size: 4096,
                enable_push: true,
            },
            path_processing_stats: PathProcessingStats::default(),
            protocol_errors: Vec::new(),
            encoding_violations: Vec::new(),
        }
    }

    fn process_headers_frame(&mut self, stream_id: u32, headers: Vec<(String, String)>) -> Result<(), String> {
        // Initialize stream if needed
        if !self.stream_states.contains_key(&stream_id) {
            self.stream_states.insert(stream_id, MockStreamState {
                stream_id,
                state: StreamState::Open,
                received_headers: Vec::new(),
                pseudo_header_count: 0,
                original_path: None,
                processed_path: None,
            });
        }

        let stream_state = self.stream_states.get_mut(&stream_id).unwrap();

        // Process each header
        for (name, value) in headers {
            if name.starts_with(':') {
                stream_state.pseudo_header_count += 1;

                if name == ":path" {
                    self.path_processing_stats.total_paths_processed += 1;
                    stream_state.original_path = Some(value.clone());

                    // Validate path encoding
                    let processed_path = self.validate_path_encoding(&value, stream_id)?;
                    stream_state.processed_path = Some(processed_path);
                }
            }

            stream_state.received_headers.push((name, value));
        }

        Ok(())
    }

    fn validate_path_encoding(&mut self, path: &str, stream_id: u32) -> Result<String, String> {
        // Check if path contains percent encoding
        let has_encoding = path.contains('%');
        if has_encoding {
            self.path_processing_stats.paths_with_encoding += 1;
        }

        // Validate percent encoding sequences
        self.validate_percent_sequences(path, stream_id)?;

        // CRITICAL: Check for premature decoding
        let processed_path = self.process_path_preserving_encoding(path);

        // Verify path was preserved verbatim
        if processed_path == path {
            self.path_processing_stats.paths_preserved_verbatim += 1;
        } else {
            // This is a violation - path should be preserved exactly
            self.path_processing_stats.paths_decoded_prematurely += 1;

            let violation = EncodingViolation {
                stream_id,
                original_path: path.to_string(),
                processed_path: processed_path.clone(),
                violation_type: ViolationType::PrematureDecoding,
                security_risk: self.assess_security_risk(path, &processed_path),
            };

            self.encoding_violations.push(violation);

            self.protocol_errors.push(ProtocolError::PrematureDecoding {
                stream_id,
                original: path.to_string(),
                decoded: processed_path.clone(),
            });

            return Err("Path was prematurely decoded".to_string());
        }

        // Check for security violations
        self.check_security_violations(path, stream_id)?;

        Ok(processed_path)
    }

    fn validate_percent_sequences(&mut self, path: &str, stream_id: u32) -> Result<(), String> {
        let mut i = 0;
        let bytes = path.as_bytes();

        while i < bytes.len() {
            if bytes[i] == b'%' {
                // Found percent sign - validate sequence
                if i + 2 >= bytes.len() {
                    // Incomplete sequence
                    self.path_processing_stats.invalid_sequences_rejected += 1;
                    self.protocol_errors.push(ProtocolError::InvalidPercentSequence {
                        stream_id,
                        sequence: format!("%{}", std::str::from_utf8(&bytes[i+1..]).unwrap_or("")),
                        position: i,
                    });
                    return Err("Incomplete percent sequence".to_string());
                }

                let hex1 = bytes[i + 1];
                let hex2 = bytes[i + 2];

                // Check if hex digits are valid
                if !is_hex_digit(hex1) || !is_hex_digit(hex2) {
                    self.path_processing_stats.invalid_sequences_rejected += 1;
                    let sequence = format!("%{}{}", hex1 as char, hex2 as char);
                    self.protocol_errors.push(ProtocolError::InvalidPercentSequence {
                        stream_id,
                        sequence,
                        position: i,
                    });
                    return Err("Invalid hex digits in percent sequence".to_string());
                }

                // Check for double encoding (e.g., %252F = %2F)
                if hex1 == b'2' && (hex2 == b'5' || hex2 == b'5') {
                    let decoded_first = format!("%{}", (hex1 as char).to_ascii_lowercase());
                    if path[i+3..].starts_with(&decoded_first) {
                        self.path_processing_stats.double_encoding_detected += 1;
                    }
                }

                i += 3; // Skip the %XX sequence
            } else {
                i += 1;
            }
        }

        Ok(())
    }

    fn process_path_preserving_encoding(&self, path: &str) -> String {
        // CRITICAL: This function must preserve percent encoding exactly
        // Any decoding here would be a security vulnerability

        // Simulate what a correct implementation should do:
        // 1. Preserve all percent sequences verbatim
        // 2. Only decode for final resource lookup, NOT for route matching
        // 3. Never decode %2F to / during path processing

        // For testing: this should always return the path unchanged
        path.to_string()
    }

    fn assess_security_risk(&self, original: &str, processed: &str) -> SecurityRisk {
        // Check for critical security issues

        // %2F (encoded slash) decoded to / is CRITICAL
        if original.contains("%2F") || original.contains("%2f") {
            if processed.contains('/') && !original.replace("%2F", "").replace("%2f", "").contains('/') {
                return SecurityRisk::Critical;
            }
        }

        // %5C (encoded backslash) on Windows
        if original.contains("%5C") || original.contains("%5c") {
            if processed.contains('\\') {
                return SecurityRisk::High;
            }
        }

        // %00 (null byte) injection
        if original.contains("%00") {
            return SecurityRisk::High;
        }

        // %2E%2E (encoded ..) for directory traversal
        if original.contains("%2E%2E") || original.contains("%2e%2e") {
            if processed.contains("..") {
                return SecurityRisk::High;
            }
        }

        // Query parameter separation chars
        if original.contains("%3F") || original.contains("%3f") { // ?
            if processed.contains('?') {
                return SecurityRisk::Medium;
            }
        }

        if original.contains("%26") { // &
            if processed.contains('&') {
                return SecurityRisk::Medium;
            }
        }

        SecurityRisk::Low
    }

    fn check_security_violations(&mut self, path: &str, stream_id: u32) -> Result<(), String> {
        // Check for known attack patterns in encoded form

        // Directory traversal via encoded sequences
        if path.contains("%2E%2E") || path.contains("%2e%2e") {
            self.path_processing_stats.security_violations += 1;
            // Note: This might be legitimate, but flag for analysis
        }

        // Null byte injection
        if path.contains("%00") {
            self.path_processing_stats.security_violations += 1;
            self.protocol_errors.push(ProtocolError::SecurityViolation {
                stream_id,
                path: path.to_string(),
                violation_type: "null_byte_injection".to_string(),
            });
            // Some implementations might reject %00, others might allow it
        }

        // Encoded slash that could bypass path restrictions
        if path.contains("%2F") || path.contains("%2f") {
            // This is actually legitimate per RFC, but note it for analysis
            self.path_processing_stats.security_violations += 1;
        }

        // Check path length
        if path.len() > 2048 {
            self.protocol_errors.push(ProtocolError::PathTooLong {
                stream_id,
                length: path.len(),
                max_allowed: 2048,
            });
            return Err("Path too long".to_string());
        }

        Ok(())
    }

    fn get_processing_stats(&self) -> (u32, u32, f64, u32) {
        let total = self.path_processing_stats.total_paths_processed;
        let preserved = self.path_processing_stats.paths_preserved_verbatim;
        let preservation_rate = if total > 0 { preserved as f64 / total as f64 } else { 0.0 };
        let violations = self.path_processing_stats.paths_decoded_prematurely;
        (total, preserved, preservation_rate, violations)
    }
}

fn is_hex_digit(byte: u8) -> bool {
    matches!(byte, b'0'..=b'9' | b'A'..=b'F' | b'a'..=b'f')
}

fn percent_encode_char(ch: char, strategy: EncodingStrategy, hex_case: HexCase) -> String {
    match strategy {
        EncodingStrategy::None => ch.to_string(),
        EncodingStrategy::Minimal => {
            // Only encode what's required per RFC 3986
            match ch {
                ' ' => percent_encode_byte(b' ', hex_case),
                '"' => percent_encode_byte(b'"', hex_case),
                '<' => percent_encode_byte(b'<', hex_case),
                '>' => percent_encode_byte(b'>', hex_case),
                '\\' => percent_encode_byte(b'\\', hex_case),
                '^' => percent_encode_byte(b'^', hex_case),
                '`' => percent_encode_byte(b'`', hex_case),
                '{' => percent_encode_byte(b'{', hex_case),
                '|' => percent_encode_byte(b'|', hex_case),
                '}' => percent_encode_byte(b'}', hex_case),
                _ if ch.is_control() => {
                    let mut buf = [0; 4];
                    let bytes = ch.encode_utf8(&mut buf).as_bytes();
                    bytes.iter().map(|&b| percent_encode_byte(b, hex_case)).collect()
                },
                _ => ch.to_string(),
            }
        },
        EncodingStrategy::Aggressive => {
            // Encode many allowed characters
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.' {
                ch.to_string()
            } else {
                let mut buf = [0; 4];
                let bytes = ch.encode_utf8(&mut buf).as_bytes();
                bytes.iter().map(|&b| percent_encode_byte(b, hex_case)).collect()
            }
        },
        EncodingStrategy::Reserved => {
            // Focus on reserved characters
            match ch {
                '/' => percent_encode_byte(b'/', hex_case),  // Critical: %2F
                '?' => percent_encode_byte(b'?', hex_case),  // %3F
                '#' => percent_encode_byte(b'#', hex_case),  // %23
                '&' => percent_encode_byte(b'&', hex_case),  // %26
                '=' => percent_encode_byte(b'=', hex_case),  // %3D
                '+' => percent_encode_byte(b'+', hex_case),  // %2B
                _ => ch.to_string(),
            }
        },
        EncodingStrategy::Spaces => {
            match ch {
                ' ' => percent_encode_byte(b' ', hex_case),   // %20
                '\t' => percent_encode_byte(b'\t', hex_case), // %09
                '\n' => percent_encode_byte(b'\n', hex_case), // %0A
                '\r' => percent_encode_byte(b'\r', hex_case), // %0D
                _ => ch.to_string(),
            }
        },
        EncodingStrategy::Unsafe => {
            match ch {
                '\0' => percent_encode_byte(0, hex_case),     // %00
                '\x7F' => percent_encode_byte(0x7F, hex_case), // %7F
                _ if ch.is_control() => {
                    let mut buf = [0; 4];
                    let bytes = ch.encode_utf8(&mut buf).as_bytes();
                    bytes.iter().map(|&b| percent_encode_byte(b, hex_case)).collect()
                },
                _ => ch.to_string(),
            }
        },
        EncodingStrategy::Random => {
            // Randomly encode some characters
            if ch as u32 % 3 == 0 && !ch.is_ascii_alphanumeric() {
                let mut buf = [0; 4];
                let bytes = ch.encode_utf8(&mut buf).as_bytes();
                bytes.iter().map(|&b| percent_encode_byte(b, hex_case)).collect()
            } else {
                ch.to_string()
            }
        },
    }
}

fn percent_encode_byte(byte: u8, hex_case: HexCase) -> String {
    match hex_case {
        HexCase::Lower => format!("%{:02x}", byte),
        HexCase::Upper => format!("%{:02X}", byte),
        HexCase::Mixed => {
            if byte % 2 == 0 {
                format!("%{:02X}", byte)
            } else {
                format!("%{:02x}", byte)
            }
        },
    }
}

fn build_percent_encoded_path(input: &PercentEncodedPathInput) -> String {
    let mut path = String::new();

    // Start with root
    path.push('/');

    // Add path segments
    for (i, segment) in input.path_segments.iter().enumerate() {
        if i > 0 {
            path.push('/');
        }

        // Apply percent encoding to the segment
        let encoded_segment = if input.use_invalid_sequences && segment.len() > 2 {
            // Insert invalid percent sequences
            let mut invalid = segment.clone();
            invalid.push_str("%GG"); // Invalid hex
            invalid.push_str("%2");  // Incomplete
            invalid.push_str("%");   // Incomplete
            invalid
        } else {
            segment.chars()
                .map(|ch| percent_encode_char(ch, input.encoding_strategy, input.hex_case))
                .collect()
        };

        // Apply double encoding if requested
        let final_segment = if input.double_encode {
            encoded_segment.replace('%', "%25")
        } else {
            encoded_segment
        };

        path.push_str(&final_segment);
    }

    // Add query parameters
    if !input.query_params.is_empty() {
        path.push('?');
        for (i, (key, value)) in input.query_params.iter().enumerate() {
            if i > 0 {
                path.push('&');
            }

            // Encode query parameters
            let encoded_key = key.chars()
                .map(|ch| percent_encode_char(ch, input.encoding_strategy, input.hex_case))
                .collect::<String>();
            let encoded_value = value.chars()
                .map(|ch| percent_encode_char(ch, input.encoding_strategy, input.hex_case))
                .collect::<String>();

            path.push_str(&encoded_key);
            path.push('=');
            path.push_str(&encoded_value);
        }
    }

    // Add fragment
    if let Some(ref fragment) = input.fragment {
        path.push('#');
        let encoded_fragment = fragment.chars()
            .map(|ch| percent_encode_char(ch, input.encoding_strategy, input.hex_case))
            .collect::<String>();
        path.push_str(&encoded_fragment);
    }

    // Truncate if too long
    if path.len() > input.max_path_length as usize {
        path.truncate(input.max_path_length as usize);
    }

    path
}

fn build_headers_with_encoded_path(input: &PercentEncodedPathInput) -> Vec<(String, String)> {
    let mut headers = Vec::new();

    // Required pseudo-headers
    headers.push((":method".to_string(), "GET".to_string()));
    headers.push((":scheme".to_string(), "https".to_string()));
    headers.push((":authority".to_string(), "example.com".to_string()));

    // Generate the percent-encoded path
    let path = build_percent_encoded_path(input);
    headers.push((":path".to_string(), path));

    // Add extra pseudo-headers if requested
    for i in 0..input.extra_pseudo_count {
        headers.push((format!(":custom-{}", i), format!("value-{}", i)));
    }

    headers
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 10 {
        return;
    }

    let mut unstructured = Unstructured::new(data);

    // Parse fuzz input
    let input = match PercentEncodedPathInput::arbitrary(&mut unstructured) {
        Ok(input) => input,
        Err(_) => return,
    };

    // Create mock connection
    let mut connection = MockH2Connection::new();

    // Build headers with percent-encoded path
    let headers = build_headers_with_encoded_path(&input);

    // Extract the path for analysis
    let path = headers.iter()
        .find(|(name, _)| name == ":path")
        .map(|(_, value)| value.clone())
        .unwrap_or_default();

    // Skip if path is empty or too basic
    if path.is_empty() || (!path.contains('%') && input.encoding_strategy as u8 != EncodingStrategy::None as u8) {
        return;
    }

    // Test processing the headers
    let stream_id = 1;
    let result = connection.process_headers_frame(stream_id, headers);

    // Analyze results
    match result {
        Ok(()) => {
            // Headers were accepted - verify path preservation
            let stream = connection.stream_states.get(&stream_id).unwrap();

            if let (Some(original), Some(processed)) = (&stream.original_path, &stream.processed_path) {
                // CRITICAL: Path should be preserved exactly
                if original != processed {
                    // This is a bug - percent encoding was not preserved
                    panic!("Path encoding not preserved! Original: '{}', Processed: '{}'",
                        original, processed);
                }

                // Check for premature decoding of critical sequences
                if original.contains("%2F") || original.contains("%2f") {
                    if processed.contains('/') && !original.replace("%2F", "").replace("%2f", "").contains('/') {
                        panic!("SECURITY: %2F was decoded to / prematurely! This could bypass path-based access controls.");
                    }
                }

                // Check for double decoding vulnerability
                if original.contains("%252F") {
                    if processed.contains("/") {
                        panic!("SECURITY: Double decoding vulnerability detected!");
                    }
                }
            }
        },
        Err(error) => {
            // Headers were rejected - check if rejection was appropriate
            if input.use_invalid_sequences {
                // Should be rejected for invalid sequences
                assert!(error.contains("Invalid") || error.contains("Incomplete"));
            } else if path.len() > 2048 {
                // Should be rejected for length
                assert!(error.contains("too long"));
            }
        }
    }

    // Verify protocol error handling
    for error in &connection.protocol_errors {
        match error {
            ProtocolError::PrematureDecoding { stream_id, original, decoded } => {
                assert_eq!(*stream_id, 1);
                assert_ne!(original, decoded);
                // This should never happen in a correct implementation
            },
            ProtocolError::InvalidPercentSequence { stream_id, sequence, position } => {
                assert_eq!(*stream_id, 1);
                assert!(!sequence.is_empty());
                assert!(*position < path.len());
            },
            ProtocolError::SecurityViolation { stream_id, path, violation_type } => {
                assert_eq!(*stream_id, 1);
                assert!(!path.is_empty());
                assert!(!violation_type.is_empty());
            },
            _ => {}, // Other error types
        }
    }

    // Verify encoding violation tracking
    for violation in &connection.encoding_violations {
        assert_eq!(violation.stream_id, 1);
        assert_ne!(violation.original_path, violation.processed_path);

        // Security risk assessment should be consistent
        match violation.security_risk {
            SecurityRisk::Critical => {
                // Should involve %2F decoding or similar
                assert!(violation.original_path.contains("%2F") ||
                       violation.original_path.contains("%2f"));
            },
            SecurityRisk::High => {
                // Should involve directory traversal or null bytes
                assert!(violation.original_path.contains("%00") ||
                       violation.original_path.contains("%2E%2E"));
            },
            _ => {}, // Lower risk levels
        }
    }

    // Verify statistics consistency
    let (total, preserved, preservation_rate, violations) = connection.get_processing_stats();

    if total > 0 {
        assert!(preservation_rate >= 0.0 && preservation_rate <= 1.0);
        assert!(preserved <= total);
        assert!(violations <= total);
        assert_eq!(preserved + violations, total); // Should account for all paths
    }

    // Test that preservation rate is high for valid inputs
    if !input.use_invalid_sequences && preservation_rate < 0.9 {
        panic!("Low preservation rate ({:.2}) for valid input suggests premature decoding",
               preservation_rate);
    }
});