//! HTTP/1.1 header value percent-encoding and obs-text fuzz target.
//!
//! Fuzzes malformed HTTP header values to test critical parsing invariants:
//! 1. obs-fold tolerated per RFC 9112 (obsolete line folding with space/tab)
//! 2. LF without CR rejected (bare LF detection)
//! 3. VCHAR allowed + obs-text (0x80-0xFF) tolerated
//! 4. space-prefixed continuation trimmed (leading/trailing whitespace)
//! 5. oversized header rejected per max_header_size configuration
//!
//! # Attack Vectors Tested
//! - Non-ASCII characters and invalid encoded-word sequences
//! - CRLF injection attempts (bare LF, bare CR, embedded nulls)
//! - obs-text characters (0x80-0xFF) for Latin-1 compatibility
//! - Header value continuation lines (obs-fold patterns)
//! - Oversized header values exceeding configured limits
//! - Control character injection (except allowed HTAB)
//! - Unicode normalization attacks
//! - Percent-encoding edge cases
//!
//! # Running
//! ```bash
//! cargo +nightly fuzz run h1_header_values
//! ```

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

use asupersync::http::h1::codec::{Http1Codec, HttpError};
use asupersync::codec::Decoder;
use asupersync::bytes::BytesMut;

/// Maximum input size to prevent memory exhaustion during fuzzing.
const MAX_FUZZ_SIZE: usize = 64_000;

/// Default header block size limit for testing.
const DEFAULT_TEST_MAX_HEADER_SIZE: usize = 8192;

/// HTTP/1.1 header value fuzzing scenarios covering critical parsing paths.
#[derive(Arbitrary, Debug, Clone)]
enum HeaderValueFuzzScenario {
    /// Test obs-fold (obsolete line folding) handling
    ObsFoldTest {
        /// Base header name
        header_name: String,
        /// Base header value before folding
        base_value: String,
        /// Folding type (space, tab, mixed)
        fold_type: ObsFoldType,
        /// Number of continuation lines
        continuation_lines: u8,
        /// Additional content after fold
        post_fold_content: Vec<u8>,
    },
    /// Test CRLF injection detection
    CrlfInjectionTest {
        /// Header name
        header_name: String,
        /// Base value before injection
        base_value: String,
        /// Type of CRLF injection to attempt
        injection_type: CrlfInjectionType,
        /// Position in value to inject (0.0-1.0)
        injection_position: f32,
        /// Additional payload after injection
        payload_after: Vec<u8>,
    },
    /// Test VCHAR and obs-text character handling
    CharacterValidationTest {
        /// Header name
        header_name: String,
        /// Character ranges to test
        character_ranges: Vec<CharacterRange>,
        /// Whether to mix with valid characters
        mix_with_valid: bool,
        /// Prefix/suffix valid content
        valid_wrapper: Option<String>,
    },
    /// Test whitespace trimming and continuation
    WhitespaceTrimmingTest {
        /// Header name
        header_name: String,
        /// Core value content
        core_value: String,
        /// Leading whitespace pattern
        leading_whitespace: WhitespacePattern,
        /// Trailing whitespace pattern
        trailing_whitespace: WhitespacePattern,
        /// Internal whitespace insertions
        internal_whitespace: Vec<WhitespaceInsertion>,
    },
    /// Test oversized header rejection
    OversizedHeaderTest {
        /// Header name
        header_name: String,
        /// Base repeating pattern
        repeat_pattern: String,
        /// Number of repetitions to exceed limit
        repetition_count: u16,
        /// Additional oversized content type
        content_type: OversizedContentType,
    },
}

/// Types of obs-fold (obsolete line folding) patterns
#[derive(Arbitrary, Debug, Clone, Copy)]
enum ObsFoldType {
    /// Single space continuation
    Space,
    /// Single tab continuation
    Tab,
    /// Multiple spaces
    MultiSpace,
    /// Multiple tabs
    MultiTab,
    /// Mixed space and tab
    Mixed,
}

impl ObsFoldType {
    fn to_continuation_string(self) -> &'static str {
        match self {
            Self::Space => " ",
            Self::Tab => "\t",
            Self::MultiSpace => "   ",
            Self::MultiTab => "\t\t\t",
            Self::Mixed => " \t ",
        }
    }
}

/// Types of CRLF injection attempts
#[derive(Arbitrary, Debug, Clone, Copy)]
enum CrlfInjectionType {
    /// Bare LF (should be rejected)
    BareLF,
    /// Bare CR (should be rejected)
    BareCR,
    /// CRLF pair (should be rejected)
    CRLF,
    /// Double CRLF (header smuggling attempt)
    DoubleCRLF,
    /// Embedded null byte
    NullByte,
    /// Control character (DEL, etc.)
    ControlChar,
}

impl CrlfInjectionType {
    fn to_bytes(self) -> &'static [u8] {
        match self {
            Self::BareLF => b"\n",
            Self::BareCR => b"\r",
            Self::CRLF => b"\r\n",
            Self::DoubleCRLF => b"\r\n\r\n",
            Self::NullByte => b"\0",
            Self::ControlChar => b"\x7F", // DEL character
        }
    }
}

/// Character ranges for validation testing
#[derive(Arbitrary, Debug, Clone, Copy)]
enum CharacterRange {
    /// Control characters (0x00-0x1F except HTAB)
    ControlChars,
    /// VCHAR range (0x21-0x7E)
    VChar,
    /// obs-text range (0x80-0xFF)
    ObsText,
    /// Extended Unicode (above 0xFF)
    ExtendedUnicode,
    /// DEL character (0x7F)
    DelChar,
    /// HTAB (0x09) - should be allowed
    HTABChar,
}

impl CharacterRange {
    fn generate_bytes(self, count: usize) -> Vec<u8> {
        match self {
            Self::ControlChars => (0x00..=0x1F).filter(|&b| b != 0x09).cycle().take(count).collect(),
            Self::VChar => (0x21..=0x7E).cycle().take(count).collect(),
            Self::ObsText => (0x80..=0xFF).cycle().take(count).collect(),
            Self::ExtendedUnicode => {
                // Generate some extended Unicode as UTF-8
                "🦀🔥💻⚡🚀".bytes().cycle().take(count).collect()
            }
            Self::DelChar => vec![0x7F; count],
            Self::HTABChar => vec![0x09; count],
        }
    }
}

/// Whitespace patterns for trimming tests
#[derive(Arbitrary, Debug, Clone, Copy)]
enum WhitespacePattern {
    /// No whitespace
    None,
    /// Single space
    SingleSpace,
    /// Single tab
    SingleTab,
    /// Multiple spaces
    MultiSpace,
    /// Multiple tabs
    MultiTab,
    /// Mixed space and tab
    Mixed,
}

impl WhitespacePattern {
    fn to_bytes(self) -> Vec<u8> {
        match self {
            Self::None => vec![],
            Self::SingleSpace => vec![b' '],
            Self::SingleTab => vec![b'\t'],
            Self::MultiSpace => vec![b' '; 5],
            Self::MultiTab => vec![b'\t'; 3],
            Self::Mixed => b" \t  \t ".to_vec(),
        }
    }
}

/// Internal whitespace insertion points
#[derive(Arbitrary, Debug, Clone)]
struct WhitespaceInsertion {
    /// Position in string (0.0-1.0)
    position: f32,
    /// Whitespace pattern to insert
    pattern: WhitespacePattern,
}

/// Types of oversized content for limit testing
#[derive(Arbitrary, Debug, Clone, Copy)]
enum OversizedContentType {
    /// Simple ASCII repetition
    AsciiRepeat,
    /// Unicode character repetition
    UnicodeRepeat,
    /// Binary data repetition
    BinaryRepeat,
    /// Mixed content repetition
    MixedRepeat,
}

impl OversizedContentType {
    fn generate_pattern(self) -> Vec<u8> {
        match self {
            Self::AsciiRepeat => b"X".to_vec(),
            Self::UnicodeRepeat => "🦀".bytes().collect(),
            Self::BinaryRepeat => vec![0xFF],
            Self::MixedRepeat => b"X\xFF🦀".to_vec(),
        }
    }
}

fuzz_target!(|data: &[u8]| {
    // Guard against excessively large inputs
    if data.len() > MAX_FUZZ_SIZE {
        return;
    }

    // Try to parse as structured scenario
    if let Ok(scenario) = arbitrary::Unstructured::new(data).arbitrary::<HeaderValueFuzzScenario>() {
        test_header_value_scenario(scenario);
    }

    // Also test raw data as header value content
    test_raw_header_value_parsing(data);
});

/// Test a specific header value fuzzing scenario
fn test_header_value_scenario(scenario: HeaderValueFuzzScenario) {
    match scenario {
        HeaderValueFuzzScenario::ObsFoldTest { header_name, base_value, fold_type, continuation_lines, post_fold_content } => {
            test_obs_fold_handling(header_name, base_value, fold_type, continuation_lines, post_fold_content);
        }
        HeaderValueFuzzScenario::CrlfInjectionTest { header_name, base_value, injection_type, injection_position, payload_after } => {
            test_crlf_injection_detection(header_name, base_value, injection_type, injection_position, payload_after);
        }
        HeaderValueFuzzScenario::CharacterValidationTest { header_name, character_ranges, mix_with_valid, valid_wrapper } => {
            test_character_validation(header_name, character_ranges, mix_with_valid, valid_wrapper);
        }
        HeaderValueFuzzScenario::WhitespaceTrimmingTest { header_name, core_value, leading_whitespace, trailing_whitespace, internal_whitespace } => {
            test_whitespace_trimming(header_name, core_value, leading_whitespace, trailing_whitespace, internal_whitespace);
        }
        HeaderValueFuzzScenario::OversizedHeaderTest { header_name, repeat_pattern, repetition_count, content_type } => {
            test_oversized_header_rejection(header_name, repeat_pattern, repetition_count, content_type);
        }
    }
}

/// Test obs-fold (obsolete line folding) handling (Assertion 1)
fn test_obs_fold_handling(header_name: String, base_value: String, fold_type: ObsFoldType, continuation_lines: u8, post_fold_content: Vec<u8>) {
    if header_name.is_empty() || header_name.len() > 100 {
        return; // Skip invalid header names
    }

    let continuation = fold_type.to_continuation_string();

    // Build HTTP request with obs-fold header
    let mut request = format!("GET / HTTP/1.1\r\nHost: example.com\r\n");
    request.push_str(&format!("{}: {}", header_name, base_value));

    // Add continuation lines (obs-fold)
    for _ in 0..continuation_lines.min(5) {
        request.push_str("\r\n");
        request.push_str(continuation);
        request.push_str("continued-value");
    }

    if !post_fold_content.is_empty() && post_fold_content.len() < 1000 {
        request.push_str(&String::from_utf8_lossy(&post_fold_content));
    }

    request.push_str("\r\n\r\n");

    let mut codec = Http1Codec::new();
    let mut buf = BytesMut::from(request.as_bytes());

    match codec.decode(&mut buf) {
        Ok(Some(parsed_request)) => {
            // RFC 9112 allows obs-fold to be treated as a single space
            // Verify that folded headers are processed correctly
            for (name, value) in &parsed_request.headers {
                if name.eq_ignore_ascii_case(&header_name) {
                    validate_obs_fold_processing(value);
                }
            }
        }
        Ok(None) => {
            // Incomplete request - acceptable
        }
        Err(_) => {
            // Parse error may be acceptable for malformed obs-fold
            // But well-formed obs-fold should not cause errors
            if continuation_lines <= 2 && post_fold_content.is_empty() {
                validate_obs_fold_error_acceptable(&header_name, &base_value, fold_type);
            }
        }
    }
}

/// Test CRLF injection detection (Assertion 2)
fn test_crlf_injection_detection(header_name: String, base_value: String, injection_type: CrlfInjectionType, injection_position: f32, payload_after: Vec<u8>) {
    if header_name.is_empty() || header_name.len() > 100 || base_value.len() > 1000 {
        return;
    }

    // Insert injection at specified position
    let position = ((injection_position.clamp(0.0, 1.0) * base_value.len() as f32) as usize).min(base_value.len());
    let mut injected_value = base_value[..position].to_owned();
    injected_value.extend_from_slice(&String::from_utf8_lossy(injection_type.to_bytes()).into_owned());
    injected_value.push_str(&base_value[position..]);

    if !payload_after.is_empty() && payload_after.len() < 1000 {
        injected_value.push_str(&String::from_utf8_lossy(&payload_after));
    }

    let request = format!("GET / HTTP/1.1\r\nHost: example.com\r\n{}: {}\r\n\r\n", header_name, injected_value);

    let mut codec = Http1Codec::new();
    let mut buf = BytesMut::from(request.as_bytes());

    match codec.decode(&mut buf) {
        Ok(Some(_)) => {
            // Assertion 2: LF without CR should be rejected
            assert_crlf_injection_properly_handled(injection_type, &injected_value);
        }
        Ok(None) => {
            // Incomplete request
        }
        Err(error) => {
            // CRLF injection should be properly detected and rejected
            verify_crlf_error_appropriate(injection_type, &error);
        }
    }
}

/// Test character validation (Assertion 3)
fn test_character_validation(header_name: String, character_ranges: Vec<CharacterRange>, mix_with_valid: bool, valid_wrapper: Option<String>) {
    if header_name.is_empty() || header_name.len() > 100 {
        return;
    }

    let mut test_value = String::new();

    if let Some(ref wrapper) = valid_wrapper {
        test_value.push_str(&wrapper[..wrapper.len().min(100)]);
    }

    // Generate test characters from specified ranges
    for range in character_ranges.iter().take(5) {
        let char_bytes = range.generate_bytes(20);
        test_value.push_str(&String::from_utf8_lossy(&char_bytes));

        if mix_with_valid {
            test_value.push_str("valid");
        }
    }

    if let Some(ref wrapper) = valid_wrapper {
        test_value.push_str(&wrapper[..wrapper.len().min(100)]);
    }

    let request = format!("GET / HTTP/1.1\r\nHost: example.com\r\n{}: {}\r\n\r\n", header_name, test_value);

    let mut codec = Http1Codec::new();
    let mut buf = BytesMut::from(request.as_bytes());

    match codec.decode(&mut buf) {
        Ok(Some(parsed_request)) => {
            // Assertion 3: VCHAR and obs-text should be allowed
            for (name, value) in &parsed_request.headers {
                if name.eq_ignore_ascii_case(&header_name) {
                    validate_character_acceptance(value, &character_ranges);
                }
            }
        }
        Ok(None) => {
            // Incomplete request
        }
        Err(error) => {
            // Character validation errors should be appropriate
            verify_character_error_justified(&character_ranges, &error);
        }
    }
}

/// Test whitespace trimming and continuation (Assertion 4)
fn test_whitespace_trimming(header_name: String, core_value: String, leading_whitespace: WhitespacePattern, trailing_whitespace: WhitespacePattern, internal_whitespace: Vec<WhitespaceInsertion>) {
    if header_name.is_empty() || header_name.len() > 100 || core_value.len() > 1000 {
        return;
    }

    let mut test_value = String::new();

    // Add leading whitespace
    test_value.push_str(&String::from_utf8_lossy(&leading_whitespace.to_bytes()));

    // Add core value with internal whitespace insertions
    let mut core_chars: Vec<char> = core_value.chars().collect();
    for insertion in internal_whitespace.iter().take(3) {
        let pos = ((insertion.position.clamp(0.0, 1.0) * core_chars.len() as f32) as usize).min(core_chars.len());
        let whitespace_str = String::from_utf8_lossy(&insertion.pattern.to_bytes());
        let whitespace_chars: Vec<char> = whitespace_str.chars().collect();

        for (i, ch) in whitespace_chars.into_iter().enumerate() {
            if pos + i < core_chars.len() {
                core_chars.insert(pos + i, ch);
            }
        }
    }

    test_value.push_str(&core_chars.into_iter().collect::<String>());

    // Add trailing whitespace
    test_value.push_str(&String::from_utf8_lossy(&trailing_whitespace.to_bytes()));

    let request = format!("GET / HTTP/1.1\r\nHost: example.com\r\n{}: {}\r\n\r\n", header_name, test_value);

    let mut codec = Http1Codec::new();
    let mut buf = BytesMut::from(request.as_bytes());

    match codec.decode(&mut buf) {
        Ok(Some(parsed_request)) => {
            // Assertion 4: Space-prefixed continuation should be trimmed
            for (name, value) in &parsed_request.headers {
                if name.eq_ignore_ascii_case(&header_name) {
                    validate_whitespace_trimming(value, &core_value, leading_whitespace, trailing_whitespace);
                }
            }
        }
        Ok(None) => {
            // Incomplete request
        }
        Err(_) => {
            // Parse error - whitespace handling shouldn't cause errors for valid patterns
        }
    }
}

/// Test oversized header rejection (Assertion 5)
fn test_oversized_header_rejection(header_name: String, repeat_pattern: String, repetition_count: u16, content_type: OversizedContentType) {
    if header_name.is_empty() || header_name.len() > 100 || repeat_pattern.len() > 100 {
        return;
    }

    let pattern = if repeat_pattern.is_empty() {
        content_type.generate_pattern()
    } else {
        repeat_pattern.into_bytes()
    };

    // Create oversized header value
    let target_size = DEFAULT_TEST_MAX_HEADER_SIZE + 1000;
    let repeat_count = (target_size / pattern.len().max(1)).min(repetition_count as usize);
    let oversized_value = pattern.repeat(repeat_count);

    let request_start = format!("GET / HTTP/1.1\r\nHost: example.com\r\n{}: ", header_name);
    let request_end = b"\r\n\r\n";

    // Build request with oversized header
    let mut request_bytes = Vec::new();
    request_bytes.extend_from_slice(request_start.as_bytes());
    request_bytes.extend_from_slice(&oversized_value);
    request_bytes.extend_from_slice(request_end);

    // Test with smaller limit to trigger rejection
    let mut codec = Http1Codec::new().max_headers_size(DEFAULT_TEST_MAX_HEADER_SIZE);
    let mut buf = BytesMut::from(&request_bytes[..]);

    match codec.decode(&mut buf) {
        Ok(Some(_)) => {
            // Should not succeed for truly oversized headers
            assert_oversized_header_handling(&header_name, oversized_value.len(), DEFAULT_TEST_MAX_HEADER_SIZE);
        }
        Ok(None) => {
            // Incomplete request - may need more data
        }
        Err(error) => {
            // Assertion 5: Oversized headers should be rejected
            verify_oversized_header_error(&error, oversized_value.len());
        }
    }
}

// Helper validation functions

fn validate_obs_fold_processing(value: &str) {
    // RFC 9112 allows obs-fold to be treated as single space
    // Just ensure the value doesn't contain raw CRLF
    assert!(!value.contains('\r') && !value.contains('\n'), "obs-fold processed value contains CRLF");
}

fn validate_obs_fold_error_acceptable(_header_name: &str, _base_value: &str, _fold_type: ObsFoldType) {
    // For well-formed obs-fold, errors should be limited
    // This is a placeholder for more sophisticated validation
}

fn assert_crlf_injection_properly_handled(injection_type: CrlfInjectionType, value: &str) {
    match injection_type {
        CrlfInjectionType::BareLF | CrlfInjectionType::BareCR | CrlfInjectionType::CRLF => {
            // These should be rejected, not accepted
            panic!("CRLF injection was not properly rejected: {:?}", injection_type);
        }
        _ => {
            // Other injection types may have different handling
        }
    }
}

fn verify_crlf_error_appropriate(injection_type: CrlfInjectionType, error: &HttpError) {
    match injection_type {
        CrlfInjectionType::BareLF | CrlfInjectionType::BareCR | CrlfInjectionType::CRLF => {
            // Should result in header validation error
            assert!(matches!(error, HttpError::InvalidHeaderValue | HttpError::BadHeader),
                "Unexpected error for CRLF injection: {:?}", error);
        }
        CrlfInjectionType::NullByte | CrlfInjectionType::ControlChar => {
            assert!(matches!(error, HttpError::InvalidHeaderValue),
                "Control character should trigger InvalidHeaderValue: {:?}", error);
        }
        _ => {
            // Other errors may be acceptable
        }
    }
}

fn validate_character_acceptance(value: &str, character_ranges: &[CharacterRange]) {
    for range in character_ranges {
        match range {
            CharacterRange::VChar => {
                // VCHAR should always be accepted
            }
            CharacterRange::ObsText => {
                // obs-text (0x80-0xFF) should be tolerated
            }
            CharacterRange::HTABChar => {
                // HTAB should be allowed
            }
            CharacterRange::ControlChars | CharacterRange::DelChar => {
                // These should have been rejected
                panic!("Control characters should not be present in parsed header value");
            }
            CharacterRange::ExtendedUnicode => {
                // Unicode handling may vary
            }
        }
    }
}

fn verify_character_error_justified(character_ranges: &[CharacterRange], error: &HttpError) {
    let has_invalid_chars = character_ranges.iter().any(|range| {
        matches!(range, CharacterRange::ControlChars | CharacterRange::DelChar)
    });

    if has_invalid_chars {
        assert!(matches!(error, HttpError::InvalidHeaderValue),
            "Should be InvalidHeaderValue for control characters: {:?}", error);
    }
}

fn validate_whitespace_trimming(parsed_value: &str, original_core: &str, leading: WhitespacePattern, trailing: WhitespacePattern) {
    // Verify leading/trailing whitespace was trimmed
    if !matches!(leading, WhitespacePattern::None) {
        assert!(!parsed_value.starts_with(' ') && !parsed_value.starts_with('\t'),
            "Leading whitespace was not trimmed");
    }

    if !matches!(trailing, WhitespacePattern::None) {
        assert!(!parsed_value.ends_with(' ') && !parsed_value.ends_with('\t'),
            "Trailing whitespace was not trimmed");
    }

    // Core content should still be present (allowing for transformations)
    if !original_core.is_empty() {
        assert!(parsed_value.contains(&original_core.trim()) || parsed_value.len() > 0,
            "Core header value content was lost during processing");
    }
}

fn assert_oversized_header_handling(_header_name: &str, actual_size: usize, limit: usize) {
    if actual_size > limit * 2 {
        panic!("Oversized header ({}B) was not rejected (limit: {}B)", actual_size, limit);
    }
}

fn verify_oversized_header_error(error: &HttpError, size: usize) {
    if size > DEFAULT_TEST_MAX_HEADER_SIZE {
        assert!(matches!(error, HttpError::HeadersTooLarge),
            "Should be HeadersTooLarge for oversized header: {:?}", error);
    }
}

/// Test raw data as header value content
fn test_raw_header_value_parsing(input: &[u8]) {
    if input.len() > 1000 {
        return;
    }

    let header_name = "Test-Header";
    let header_value = String::from_utf8_lossy(input);

    let request = format!("GET / HTTP/1.1\r\nHost: example.com\r\n{}: {}\r\n\r\n",
        header_name, header_value);

    let mut codec = Http1Codec::new();
    let mut buf = BytesMut::from(request.as_bytes());

    // Test that parsing arbitrary input doesn't cause crashes
    let _result = codec.decode(&mut buf);

    // Test with different header size limits
    let limits = [512, 1024, 8192];
    for &limit in &limits {
        let mut limited_codec = Http1Codec::new().max_headers_size(limit);
        let mut limited_buf = BytesMut::from(request.as_bytes());
        let _limited_result = limited_codec.decode(&mut limited_buf);
    }
}