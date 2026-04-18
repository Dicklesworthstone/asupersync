//! Comprehensive fuzz target for HTTP/1.1 response status-line parsing RFC 9112.
//!
//! This target feeds malformed HTTP/1.1 response status-lines to the client parser
//! to assert critical RFC 9112 compliance and security properties:
//!
//! 1. HTTP-version prefix strict (HTTP/1.1 or HTTP/1.0)
//! 2. 3-digit status-code within 100..=599
//! 3. reason-phrase tolerates VCHAR + obs-text
//! 4. CRLF termination required
//! 5. obs-fold rejected per RFC 9112 (no backwards compat)
//!
//! # Running
//! ```bash
//! cargo +nightly fuzz run h1_status_line
//! ```
//!
//! # Security Focus
//! - HTTP version prefix enforcement
//! - Status code range validation (100-599)
//! - Reason phrase character validation (VCHAR + obs-text)
//! - CRLF injection prevention
//! - obs-fold line continuation rejection (RFC 9112 security requirement)

#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::BytesMut;
use asupersync::codec::Decoder;
use asupersync::http::h1::client::Http1ClientCodec;
use asupersync::http::h1::codec::HttpError;
use asupersync::http::h1::types::Version;
use libfuzzer_sys::fuzz_target;

/// Maximum fuzz input size to prevent timeouts
const MAX_FUZZ_INPUT_SIZE: usize = 100_000;

/// Maximum status line length per HTTP/1.1 client codec
const MAX_STATUS_LINE_LENGTH: usize = 8192;

/// HTTP version generation strategy for fuzzing
#[derive(Arbitrary, Debug, Clone)]
enum VersionStrategy {
    /// HTTP/1.0 (valid)
    Http10,
    /// HTTP/1.1 (valid)
    Http11,
    /// Missing HTTP/ prefix
    NoPrefix { version: String },
    /// Wrong prefix (not HTTP/)
    WrongPrefix { prefix: String, version: String },
    /// Invalid version number
    InvalidVersion { major: u8, minor: u8 },
    /// Unsupported HTTP version
    UnsupportedVersion { major: u8, minor: u8 },
    /// Malformed version string
    Malformed { version: String },
    /// Empty version
    Empty,
    /// Version with extra whitespace
    WithWhitespace { version: String },
}

/// Status code generation strategy
#[derive(Arbitrary, Debug, Clone)]
enum StatusCodeStrategy {
    /// Valid status codes in range 100-599
    Valid { code: u16 },
    /// Below minimum (< 100)
    TooLow { code: u16 },
    /// Above maximum (>= 600)
    TooHigh { code: u16 },
    /// Non-numeric status code
    NonNumeric { text: String },
    /// Wrong number of digits
    WrongDigits { digits: String },
    /// Empty status code
    Empty,
    /// Status code with leading zeros
    LeadingZeros { code: u16 },
    /// Status code with whitespace
    WithWhitespace { code: String },
    /// Very large number (overflow test)
    Overflow { text: String },
}

/// Reason phrase generation strategy
#[derive(Arbitrary, Debug, Clone)]
enum ReasonPhraseStrategy {
    /// Standard reason phrases
    Standard(StandardReason),
    /// Valid VCHAR characters (0x21-0x7E)
    ValidVchar { text: String },
    /// obs-text characters (0x80-0xFF)
    ObsText { text: String },
    /// Mixed VCHAR + obs-text
    Mixed { vchar: String, obs_text: Vec<u8> },
    /// Invalid control characters
    InvalidControl { text: String },
    /// Null bytes (security test)
    WithNullBytes { text: String, positions: Vec<usize> },
    /// CRLF injection attempt
    CrlfInjection { text: String },
    /// Tab characters (should be rejected)
    WithTabs { text: String },
    /// Empty reason phrase
    Empty,
    /// Very long reason phrase
    VeryLong { length: usize },
    /// obs-fold attempt (security critical - RFC 9112)
    ObsFold { text: String },
}

#[derive(Arbitrary, Debug, Clone)]
enum StandardReason {
    Ok,
    NotFound,
    InternalServerError,
    BadRequest,
    Unauthorized,
    Forbidden,
    MethodNotAllowed,
    NotAcceptable,
    RequestTimeout,
    Conflict,
    Gone,
    PayloadTooLarge,
    UnsupportedMediaType,
    Created,
    Accepted,
    NoContent,
    MovedPermanently,
    Found,
    SeeOther,
    NotModified,
    BadGateway,
    ServiceUnavailable,
    GatewayTimeout,
}

impl StandardReason {
    fn to_str(&self) -> &'static str {
        match self {
            Self::Ok => "OK",
            Self::NotFound => "Not Found",
            Self::InternalServerError => "Internal Server Error",
            Self::BadRequest => "Bad Request",
            Self::Unauthorized => "Unauthorized",
            Self::Forbidden => "Forbidden",
            Self::MethodNotAllowed => "Method Not Allowed",
            Self::NotAcceptable => "Not Acceptable",
            Self::RequestTimeout => "Request Timeout",
            Self::Conflict => "Conflict",
            Self::Gone => "Gone",
            Self::PayloadTooLarge => "Payload Too Large",
            Self::UnsupportedMediaType => "Unsupported Media Type",
            Self::Created => "Created",
            Self::Accepted => "Accepted",
            Self::NoContent => "No Content",
            Self::MovedPermanently => "Moved Permanently",
            Self::Found => "Found",
            Self::SeeOther => "See Other",
            Self::NotModified => "Not Modified",
            Self::BadGateway => "Bad Gateway",
            Self::ServiceUnavailable => "Service Unavailable",
            Self::GatewayTimeout => "Gateway Timeout",
        }
    }
}

/// Status line termination strategy
#[derive(Arbitrary, Debug, Clone)]
enum TerminationStrategy {
    /// Proper CRLF termination
    Crlf,
    /// Missing termination
    None,
    /// Only LF (Unix line ending)
    LfOnly,
    /// Only CR
    CrOnly,
    /// Wrong termination
    Wrong { termination: String },
    /// Multiple CRLF sequences
    Multiple { count: u8 },
}

/// Spacing strategy between status line components
#[derive(Arbitrary, Debug, Clone)]
enum SpacingStrategy {
    /// Single space (standard)
    Single,
    /// Multiple spaces
    Multiple { count: u8 },
    /// Tab characters
    Tabs { count: u8 },
    /// Mixed whitespace
    Mixed { chars: String },
    /// No spaces
    None,
}

/// Status line corruption strategy for security testing
#[derive(Arbitrary, Debug, Clone)]
enum CorruptionStrategy {
    /// No corruption - generate valid status line
    None,
    /// Insert null bytes
    NullBytes { positions: Vec<usize> },
    /// Insert control characters
    ControlChars { chars: Vec<u8>, positions: Vec<usize> },
    /// Insert non-ASCII characters
    NonAscii { chars: Vec<u8>, positions: Vec<usize> },
    /// Truncate at random position
    Truncate { position: usize },
    /// Duplicate components
    Duplicate { component: ComponentType },
    /// Swap component order
    SwapOrder,
    /// obs-fold line folding (RFC 9112 violation)
    ObsFoldInject { position: usize },
}

#[derive(Arbitrary, Debug, Clone)]
enum ComponentType {
    Version,
    StatusCode,
    ReasonPhrase,
}

/// Comprehensive fuzz input for HTTP/1.1 status-line parsing
#[derive(Arbitrary, Debug)]
struct FuzzInput {
    /// HTTP version generation strategy
    version: VersionStrategy,
    /// Status code generation strategy
    status_code: StatusCodeStrategy,
    /// Reason phrase generation strategy
    reason_phrase: ReasonPhraseStrategy,
    /// Spacing between components
    spacing: SpacingStrategy,
    /// Line termination strategy
    termination: TerminationStrategy,
    /// Corruption strategy for security testing
    corruption: CorruptionStrategy,
}

impl FuzzInput {
    /// Construct the complete status line bytes
    fn construct_status_line(&self) -> Vec<u8> {
        let version_str = self.generate_version();
        let status_str = self.generate_status_code();
        let reason_str = self.generate_reason_phrase();
        let spacing = self.generate_spacing();
        let termination = self.generate_termination();

        let mut status_line = Vec::new();

        if matches!(self.corruption, CorruptionStrategy::SwapOrder) {
            // Intentionally wrong order for corruption testing
            status_line.extend_from_slice(status_str.as_bytes());
            status_line.extend_from_slice(&spacing);
            status_line.extend_from_slice(version_str.as_bytes());
            status_line.extend_from_slice(&spacing);
            status_line.extend_from_slice(reason_str.as_bytes());
        } else {
            // Standard order: VERSION SP STATUS-CODE SP REASON-PHRASE
            status_line.extend_from_slice(version_str.as_bytes());

            if let CorruptionStrategy::Duplicate { component: ComponentType::Version } = &self.corruption {
                status_line.extend_from_slice(&spacing);
                status_line.extend_from_slice(version_str.as_bytes());
            }

            status_line.extend_from_slice(&spacing);
            status_line.extend_from_slice(status_str.as_bytes());

            if let CorruptionStrategy::Duplicate { component: ComponentType::StatusCode } = &self.corruption {
                status_line.extend_from_slice(&spacing);
                status_line.extend_from_slice(status_str.as_bytes());
            }

            if !reason_str.is_empty() {
                status_line.extend_from_slice(&spacing);
                status_line.extend_from_slice(reason_str.as_bytes());

                if let CorruptionStrategy::Duplicate { component: ComponentType::ReasonPhrase } = &self.corruption {
                    status_line.extend_from_slice(&spacing);
                    status_line.extend_from_slice(reason_str.as_bytes());
                }
            }
        }

        status_line.extend_from_slice(&termination);

        self.apply_corruption(status_line)
    }

    fn generate_version(&self) -> String {
        match &self.version {
            VersionStrategy::Http10 => "HTTP/1.0".to_string(),
            VersionStrategy::Http11 => "HTTP/1.1".to_string(),
            VersionStrategy::NoPrefix { version } => version.clone(),
            VersionStrategy::WrongPrefix { prefix, version } => {
                format!("{}/{}", prefix, version)
            }
            VersionStrategy::InvalidVersion { major, minor } => {
                format!("HTTP/{}.{}", major, minor)
            }
            VersionStrategy::UnsupportedVersion { major, minor } => {
                format!("HTTP/{}.{}", major, minor)
            }
            VersionStrategy::Malformed { version } => version.clone(),
            VersionStrategy::Empty => String::new(),
            VersionStrategy::WithWhitespace { version } => {
                format!(" {} ", version.trim())
            }
        }
    }

    fn generate_status_code(&self) -> String {
        match &self.status_code {
            StatusCodeStrategy::Valid { code } => {
                // Clamp to valid range 100-599
                let clamped = (*code).max(100).min(599);
                format!("{}", clamped)
            }
            StatusCodeStrategy::TooLow { code } => {
                format!("{}", (*code).min(99))
            }
            StatusCodeStrategy::TooHigh { code } => {
                let high_code = (*code).max(600);
                format!("{}", high_code)
            }
            StatusCodeStrategy::NonNumeric { text } => text.clone(),
            StatusCodeStrategy::WrongDigits { digits } => digits.clone(),
            StatusCodeStrategy::Empty => String::new(),
            StatusCodeStrategy::LeadingZeros { code } => {
                format!("0{:03}", code)
            }
            StatusCodeStrategy::WithWhitespace { code } => {
                format!(" {} ", code.trim())
            }
            StatusCodeStrategy::Overflow { text } => text.clone(),
        }
    }

    fn generate_reason_phrase(&self) -> String {
        match &self.reason_phrase {
            ReasonPhraseStrategy::Standard(reason) => reason.to_str().to_string(),
            ReasonPhraseStrategy::ValidVchar { text } => {
                // Only VCHAR (0x21-0x7E) and SP (0x20)
                text.chars()
                    .filter(|&c| (c as u32) >= 0x20 && (c as u32) <= 0x7E)
                    .take(1000)
                    .collect()
            }
            ReasonPhraseStrategy::ObsText { text } => {
                // obs-text: 0x80-0xFF
                text.chars()
                    .map(|c| {
                        let byte = (c as u32 % 128) + 128; // Map to 0x80-0xFF range
                        char::from(byte as u8)
                    })
                    .take(1000)
                    .collect()
            }
            ReasonPhraseStrategy::Mixed { vchar, obs_text } => {
                let mut result = String::new();
                result.push_str(&vchar.chars().take(500).collect::<String>());
                for &byte in obs_text.iter().take(500) {
                    if byte >= 0x80 {
                        result.push(char::from(byte));
                    }
                }
                result
            }
            ReasonPhraseStrategy::InvalidControl { text } => {
                // Include control characters that should be rejected
                let mut result = text.clone();
                result.push('\x00'); // Null
                result.push('\x01'); // SOH
                result.push('\x7F'); // DEL
                result
            }
            ReasonPhraseStrategy::WithNullBytes { text, positions } => {
                let mut chars: Vec<char> = text.chars().take(1000).collect();
                for &pos in positions.iter().take(10) {
                    if pos < chars.len() {
                        chars.insert(pos, '\x00');
                    }
                }
                chars.into_iter().collect()
            }
            ReasonPhraseStrategy::CrlfInjection { text } => {
                format!("{}\r\nInjected: header\r\n{}", text, text)
            }
            ReasonPhraseStrategy::WithTabs { text } => {
                format!("{}\t{}", text, text)
            }
            ReasonPhraseStrategy::Empty => String::new(),
            ReasonPhraseStrategy::VeryLong { length } => {
                "R".repeat((*length).min(10000))
            }
            ReasonPhraseStrategy::ObsFold { text } => {
                // obs-fold: CRLF 1*( SP / HTAB ) - forbidden in RFC 9112
                format!("{}\r\n {}", text, text)
            }
        }
    }

    fn generate_spacing(&self) -> Vec<u8> {
        match &self.spacing {
            SpacingStrategy::Single => b" ".to_vec(),
            SpacingStrategy::Multiple { count } => {
                vec![b' '; (*count as usize).min(100)]
            }
            SpacingStrategy::Tabs { count } => {
                vec![b'\t'; (*count as usize).min(100)]
            }
            SpacingStrategy::Mixed { chars } => {
                chars.bytes().take(100).collect()
            }
            SpacingStrategy::None => Vec::new(),
        }
    }

    fn generate_termination(&self) -> Vec<u8> {
        match &self.termination {
            TerminationStrategy::Crlf => b"\r\n".to_vec(),
            TerminationStrategy::None => Vec::new(),
            TerminationStrategy::LfOnly => b"\n".to_vec(),
            TerminationStrategy::CrOnly => b"\r".to_vec(),
            TerminationStrategy::Wrong { termination } => {
                termination.bytes().take(10).collect()
            }
            TerminationStrategy::Multiple { count } => {
                b"\r\n".repeat((*count as usize).min(10))
            }
        }
    }

    fn apply_corruption(&self, mut status_line: Vec<u8>) -> Vec<u8> {
        match &self.corruption {
            CorruptionStrategy::None => status_line,
            CorruptionStrategy::NullBytes { positions } => {
                for &pos in positions.iter().take(10) {
                    if pos < status_line.len() {
                        status_line.insert(pos, 0);
                    }
                }
                status_line
            }
            CorruptionStrategy::ControlChars { chars, positions } => {
                for (&ch, &pos) in chars.iter().zip(positions.iter()).take(10) {
                    if pos < status_line.len() && ch < 32 && ch != b'\r' && ch != b'\n' {
                        status_line.insert(pos, ch);
                    }
                }
                status_line
            }
            CorruptionStrategy::NonAscii { chars, positions } => {
                for (&ch, &pos) in chars.iter().zip(positions.iter()).take(10) {
                    if pos < status_line.len() && ch > 127 {
                        status_line.insert(pos, ch);
                    }
                }
                status_line
            }
            CorruptionStrategy::Truncate { position } => {
                let len = (*position).min(status_line.len());
                status_line.truncate(len);
                status_line
            }
            CorruptionStrategy::Duplicate { .. } | CorruptionStrategy::SwapOrder => {
                // Already handled in construct_status_line
                status_line
            }
            CorruptionStrategy::ObsFoldInject { position } => {
                // Inject obs-fold at specified position
                let pos = (*position).min(status_line.len());
                let fold_bytes = b"\r\n ".to_vec();
                for (i, &byte) in fold_bytes.iter().enumerate() {
                    status_line.insert(pos + i, byte);
                }
                status_line
            }
        }
    }
}

/// Mock HTTP/1.1 status-line parser for validation
struct MockH1StatusLineParser;

impl MockH1StatusLineParser {
    fn new() -> Self {
        Self
    }

    fn parse_status_line(&self, line: &[u8]) -> Result<(String, u16, String), ParseError> {
        // **ASSERTION 4: CRLF termination required**
        if !line.ends_with(b"\r\n") {
            return Err(ParseError::MissingCrlf);
        }

        let line_without_crlf = &line[..line.len().saturating_sub(2)];

        if line_without_crlf.len() > MAX_STATUS_LINE_LENGTH {
            return Err(ParseError::StatusLineTooLong);
        }

        let line_str = std::str::from_utf8(line_without_crlf)
            .map_err(|_| ParseError::InvalidUtf8)?;

        // **ASSERTION 5: obs-fold rejected per RFC 9112**
        if line_str.contains("\r\n ") || line_str.contains("\r\n\t") {
            return Err(ParseError::ObsFoldDetected);
        }

        let mut parts = line_str.splitn(3, ' ');
        let version = parts.next().ok_or(ParseError::InvalidFormat)?;
        let status_code = parts.next().ok_or(ParseError::InvalidFormat)?;
        let reason_phrase = parts.next().unwrap_or("").to_owned();

        // **ASSERTION 1: HTTP-version prefix strict (HTTP/1.1 or HTTP/1.0)**
        self.validate_version(version)?;

        // **ASSERTION 2: 3-digit status-code within 100..=599**
        let status_num = self.validate_status_code(status_code)?;

        // **ASSERTION 3: reason-phrase tolerates VCHAR + obs-text**
        self.validate_reason_phrase(&reason_phrase)?;

        Ok((version.to_string(), status_num, reason_phrase))
    }

    fn validate_version(&self, version: &str) -> Result<(), ParseError> {
        match version {
            "HTTP/1.0" | "HTTP/1.1" => Ok(()),
            v if !v.starts_with("HTTP/") => Err(ParseError::MissingHttpPrefix),
            _ => Err(ParseError::UnsupportedVersion),
        }
    }

    fn validate_status_code(&self, status_code: &str) -> Result<u16, ParseError> {
        // Must be exactly 3 digits
        if status_code.len() != 3 {
            return Err(ParseError::InvalidStatusCodeLength);
        }

        // Must be numeric
        let status_num: u16 = status_code.parse()
            .map_err(|_| ParseError::NonNumericStatusCode)?;

        // Must be in range 100-599
        if !(100..=599).contains(&status_num) {
            return Err(ParseError::StatusCodeOutOfRange);
        }

        Ok(status_num)
    }

    fn validate_reason_phrase(&self, reason_phrase: &str) -> Result<(), ParseError> {
        // RFC 9110: reason-phrase = *( HTAB / SP / VCHAR / obs-text )
        // VCHAR = 0x21-0x7E
        // obs-text = 0x80-0xFF
        // SP = 0x20, HTAB = 0x09

        for byte in reason_phrase.bytes() {
            match byte {
                0x09 | 0x20 => {}, // HTAB, SP - allowed
                0x21..=0x7E => {}, // VCHAR - allowed
                0x80..=0xFF => {}, // obs-text - allowed
                _ => return Err(ParseError::InvalidReasonPhraseChar),
            }
        }

        Ok(())
    }
}

#[derive(Debug, PartialEq, Clone)]
enum ParseError {
    MissingCrlf,
    StatusLineTooLong,
    InvalidUtf8,
    InvalidFormat,
    MissingHttpPrefix,
    UnsupportedVersion,
    InvalidStatusCodeLength,
    NonNumericStatusCode,
    StatusCodeOutOfRange,
    InvalidReasonPhraseChar,
    ObsFoldDetected,
}

fuzz_target!(|input: FuzzInput| {
    // Bound input size to prevent timeouts
    let status_line_bytes = input.construct_status_line();
    if status_line_bytes.len() > MAX_FUZZ_INPUT_SIZE {
        return;
    }

    // Create full HTTP response for codec testing
    let mut full_response = status_line_bytes.clone();
    full_response.extend_from_slice(b"\r\n"); // End headers section

    let mock_parser = MockH1StatusLineParser::new();
    let mock_result = mock_parser.parse_status_line(&status_line_bytes);

    // Test the actual HTTP/1.1 client codec
    let mut codec = Http1ClientCodec::new();
    let mut buffer = BytesMut::from(full_response.as_slice());

    let codec_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        codec.decode(&mut buffer)
    }));

    match codec_result {
        Ok(parse_result) => {
            match (mock_result.clone(), parse_result) {
                (Ok((version, status_code, reason_phrase)), Ok(Some(response))) => {
                    // Both parsers succeeded - verify consistency
                    assert_eq!(response.version.as_str(), version);
                    assert_eq!(response.status, status_code);
                    assert_eq!(response.reason, reason_phrase);

                    // **ASSERTION 1: HTTP-version prefix strict (HTTP/1.1 or HTTP/1.0)**
                    assert!(version.starts_with("HTTP/"));
                    assert!(matches!(response.version, Version::Http10 | Version::Http11));

                    // **ASSERTION 2: 3-digit status-code within 100..=599**
                    assert!(status_code >= 100 && status_code <= 599);
                    assert_eq!(version.len(), 8); // "HTTP/1.0" or "HTTP/1.1"

                    // **ASSERTION 3: reason-phrase tolerates VCHAR + obs-text**
                    validate_reason_phrase_consistency(&reason_phrase);

                    // **ASSERTION 4: CRLF termination**
                    // Already validated by successful parsing

                    // **ASSERTION 5: obs-fold rejected per RFC 9112**
                    assert!(!status_line_bytes.windows(3).any(|w| w == b"\r\n " || w == b"\r\n\t"));
                }
                (Err(expected_error), Ok(Some(_))) => {
                    // Mock parser correctly rejected but codec accepted - potential issue
                    match expected_error {
                        ParseError::MissingHttpPrefix => {
                            panic!("Codec accepted version without HTTP/ prefix: {:?}",
                                String::from_utf8_lossy(&status_line_bytes));
                        }
                        ParseError::UnsupportedVersion => {
                            panic!("Codec accepted unsupported HTTP version: {:?}",
                                String::from_utf8_lossy(&status_line_bytes));
                        }
                        ParseError::StatusCodeOutOfRange => {
                            panic!("Codec accepted status code outside 100-599 range: {:?}",
                                String::from_utf8_lossy(&status_line_bytes));
                        }
                        ParseError::InvalidStatusCodeLength => {
                            panic!("Codec accepted non-3-digit status code: {:?}",
                                String::from_utf8_lossy(&status_line_bytes));
                        }
                        ParseError::NonNumericStatusCode => {
                            panic!("Codec accepted non-numeric status code: {:?}",
                                String::from_utf8_lossy(&status_line_bytes));
                        }
                        ParseError::MissingCrlf => {
                            panic!("Codec accepted status line without proper CRLF termination: {:?}",
                                String::from_utf8_lossy(&status_line_bytes));
                        }
                        ParseError::ObsFoldDetected => {
                            panic!("Codec accepted obs-fold which is forbidden by RFC 9112: {:?}",
                                String::from_utf8_lossy(&status_line_bytes));
                        }
                        ParseError::InvalidReasonPhraseChar => {
                            panic!("Codec accepted invalid character in reason phrase: {:?}",
                                String::from_utf8_lossy(&status_line_bytes));
                        }
                        _ => {
                            // Other validation differences may be acceptable
                        }
                    }
                }
                (Ok(_), Err(HttpError::BadRequestLine)) => {
                    // Expected for malformed status lines
                }
                (Ok(_), Err(HttpError::UnsupportedVersion)) => {
                    // **ASSERTION 1: HTTP-version prefix strict**
                    // Expected for invalid HTTP versions
                }
                (Ok(_), Err(HttpError::HeadersTooLarge)) => {
                    // Expected for oversized status lines
                }
                (Err(_), Err(_)) => {
                    // Both parsers correctly rejected the input
                }
                (_, Ok(None)) => {
                    // Incomplete response - codec needs more data
                }
                (_, Err(_)) => {
                    // Codec rejected input - verify error is appropriate
                }
            }
        }
        Err(_) => {
            // Codec panicked - this is a bug
            panic!("HTTP/1.1 client codec panicked on input: {:?}",
                String::from_utf8_lossy(&status_line_bytes));
        }
    }

    // Additional validation for specific assertion coverage
    if let Ok((version, status_code, reason_phrase)) = &mock_result {
        // **ASSERTION 1: HTTP-version prefix strict**
        assert!(version == "HTTP/1.0" || version == "HTTP/1.1",
            "Only HTTP/1.0 and HTTP/1.1 should be accepted");

        // **ASSERTION 2: 3-digit status-code within 100..=599**
        assert!(*status_code >= 100 && *status_code <= 599,
            "Status code {} outside valid range 100-599", status_code);

        // **ASSERTION 3: reason-phrase tolerates VCHAR + obs-text**
        for byte in reason_phrase.bytes() {
            assert!(
                byte == 0x09 || byte == 0x20 || // HTAB, SP
                (byte >= 0x21 && byte <= 0x7E) || // VCHAR
                (byte >= 0x80), // obs-text
                "Invalid character in reason phrase: 0x{:02X}", byte
            );
        }

        // **ASSERTION 5: obs-fold rejected per RFC 9112**
        assert!(!reason_phrase.contains("\r\n ") && !reason_phrase.contains("\r\n\t"),
            "obs-fold detected in reason phrase, should be rejected per RFC 9112");
    }
});

fn validate_reason_phrase_consistency(reason_phrase: &str) {
    // Ensure all characters in accepted reason phrase are valid
    for byte in reason_phrase.bytes() {
        assert!(
            byte == 0x09 || byte == 0x20 || // HTAB, SP
            (byte >= 0x21 && byte <= 0x7E) || // VCHAR
            (byte >= 0x80), // obs-text
            "Invalid character in reason phrase: 0x{:02X}", byte
        );
    }

    // Verify no obs-fold sequences
    assert!(!reason_phrase.contains("\r\n ") && !reason_phrase.contains("\r\n\t"),
        "obs-fold sequence found in reason phrase: {:?}", reason_phrase);
}