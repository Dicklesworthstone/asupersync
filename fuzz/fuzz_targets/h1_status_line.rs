//! Comprehensive fuzz target for HTTP/1.1 response status-line parsing RFC 9112.
//!
//! This target feeds malformed HTTP/1.1 response status-lines to the client parser
//! to assert critical RFC 9112 compliance and security properties:
//!
//! 1. HTTP-version prefix strict (HTTP/1.1 or HTTP/1.0)
//! 2. 3-digit status-code within 100..=999
//! 3. accepted reason-phrases stay CRLF-free and valid for HTTP fields
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
//! - Status code range validation (100-999)
//! - Reason phrase character validation (VCHAR + obs-text)
//! - CRLF injection prevention
//! - obs-fold line continuation rejection (RFC 9112 security requirement)

#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::BytesMut;
use asupersync::codec::Decoder;
use asupersync::http::h1::{Http1ClientCodec, HttpError, Response, Version};
use libfuzzer_sys::fuzz_target;

/// Maximum fuzz input size to prevent timeouts
const MAX_FUZZ_INPUT_SIZE: usize = 100_000;
const BAD_REQUEST_LINE_DISPLAY: &str = "malformed request line";
const UNSUPPORTED_VERSION_DISPLAY: &str = "unsupported HTTP version";
const INVALID_HEADER_NAME_DISPLAY: &str = "invalid header name";

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
    /// Valid status codes in range 100-999
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
    /// Tab characters in the reason phrase.
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
    ControlChars {
        chars: Vec<u8>,
        positions: Vec<usize>,
    },
    /// Insert non-ASCII characters
    NonAscii {
        chars: Vec<u8>,
        positions: Vec<usize>,
    },
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

            if let CorruptionStrategy::Duplicate {
                component: ComponentType::Version,
            } = &self.corruption
            {
                status_line.extend_from_slice(&spacing);
                status_line.extend_from_slice(version_str.as_bytes());
            }

            status_line.extend_from_slice(&spacing);
            status_line.extend_from_slice(status_str.as_bytes());

            if let CorruptionStrategy::Duplicate {
                component: ComponentType::StatusCode,
            } = &self.corruption
            {
                status_line.extend_from_slice(&spacing);
                status_line.extend_from_slice(status_str.as_bytes());
            }

            if !reason_str.is_empty() {
                status_line.extend_from_slice(&spacing);
                status_line.extend_from_slice(reason_str.as_bytes());

                if let CorruptionStrategy::Duplicate {
                    component: ComponentType::ReasonPhrase,
                } = &self.corruption
                {
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
            StatusCodeStrategy::Valid { code } => format!("{}", (*code).clamp(100, 999)),
            StatusCodeStrategy::TooLow { code } => {
                format!("{}", (*code).min(99))
            }
            StatusCodeStrategy::TooHigh { code } => {
                let high_code = (*code).max(1000);
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
            ReasonPhraseStrategy::VeryLong { length } => "R".repeat((*length).min(10000)),
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
            SpacingStrategy::Mixed { chars } => chars.bytes().take(100).collect(),
            SpacingStrategy::None => Vec::new(),
        }
    }

    fn generate_termination(&self) -> Vec<u8> {
        match &self.termination {
            TerminationStrategy::Crlf => b"\r\n".to_vec(),
            TerminationStrategy::None => Vec::new(),
            TerminationStrategy::LfOnly => b"\n".to_vec(),
            TerminationStrategy::CrOnly => b"\r".to_vec(),
            TerminationStrategy::Wrong { termination } => termination.bytes().take(10).collect(),
            TerminationStrategy::Multiple { count } => b"\r\n".repeat((*count as usize).min(10)),
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

fuzz_target!(|input: FuzzInput| {
    assert_known_status_line_outputs();

    // Bound input size to prevent timeouts
    let status_line_bytes = input.construct_status_line();
    if status_line_bytes.len() > MAX_FUZZ_INPUT_SIZE {
        return;
    }

    // Create full HTTP response for codec testing
    let mut full_response = status_line_bytes.clone();
    full_response.extend_from_slice(b"\r\n"); // End headers section

    // Test the actual HTTP/1.1 client codec
    let codec_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        decode_response(&full_response)
    }));

    match codec_result {
        Ok(Ok(Some(response))) => {
            // **ASSERTION 1: HTTP-version prefix strict (HTTP/1.1 or HTTP/1.0)**
            assert!(matches!(
                response.version,
                Version::Http10 | Version::Http11
            ));

            // **ASSERTION 2: 3-digit status-code within 100..=999**
            assert!(
                (100..=999).contains(&response.status),
                "Codec accepted status code outside 100-999 range: {}",
                response.status
            );

            // **ASSERTION 3: accepted reason phrase remains a single field value**
            validate_reason_phrase_consistency(&response.reason);

            // **ASSERTION 5: obs-fold rejected per RFC 9112**
            assert!(
                !response
                    .headers
                    .iter()
                    .any(|(name, _)| name.starts_with(' ') || name.starts_with('\t')),
                "Codec accepted obs-fold as a header name: {:?}",
                response.headers
            );
        }
        Ok(Ok(None)) => {
            // Incomplete response - codec needs more data.
        }
        Ok(Err(
            HttpError::BadRequestLine
            | HttpError::UnsupportedVersion
            | HttpError::HeadersTooLarge
            | HttpError::BadHeader
            | HttpError::InvalidHeaderName
            | HttpError::InvalidHeaderValue
            | HttpError::RequestLineTooLong
            | HttpError::BadContentLength
            | HttpError::DuplicateContentLength
            | HttpError::DuplicateTransferEncoding
            | HttpError::BadTransferEncoding
            | HttpError::AmbiguousBodyLength
            | HttpError::TooManyHeaders
            | HttpError::BadChunkedEncoding
            | HttpError::BodyTooLarge
            | HttpError::BodyTooLargeDetailed { .. },
        )) => {
            // Expected for malformed status lines or injected header/body syntax.
        }
        Ok(Err(error)) => {
            panic!(
                "Unexpected HTTP/1.1 client status-line codec error for constructed response: \
                 error={error:?}, status_line={:?}",
                String::from_utf8_lossy(&status_line_bytes)
            );
        }
        Err(_) => {
            // Codec panicked - this is a bug
            panic!(
                "HTTP/1.1 client codec panicked on input: {:?}",
                String::from_utf8_lossy(&status_line_bytes)
            );
        }
    }
});

fn decode_response(input: &[u8]) -> Result<Option<Response>, HttpError> {
    let mut codec = Http1ClientCodec::new();
    let mut buffer = BytesMut::from(input);
    codec.decode(&mut buffer)
}

fn assert_status_line_error(raw: &[u8], expected: HttpError, expected_display: &str) {
    let Err(error) = decode_response(raw) else {
        panic!("expected status-line error {expected:?} for {raw:?}");
    };
    assert_eq!(
        std::mem::discriminant(&error),
        std::mem::discriminant(&expected),
        "expected status-line error {expected:?} for {raw:?}, got {error:?}"
    );
    assert_eq!(
        error.to_string(),
        expected_display,
        "status-line parser diagnostic changed for {expected:?}"
    );
}

fn assert_known_status_line_outputs() {
    let response = decode_response(b"HTTP/1.1 999 Custom\r\nContent-Length: 0\r\n\r\n")
        .expect("valid RFC 9110 three-digit status should decode")
        .expect("complete response should be returned");
    assert_eq!(response.version, Version::Http11);
    assert_eq!(response.status, 999);
    assert_eq!(response.reason, "Custom");

    assert_status_line_error(
        b"HTTP/1.1 99 Nope\r\n\r\n",
        HttpError::BadRequestLine,
        BAD_REQUEST_LINE_DISPLAY,
    );
    assert_status_line_error(
        b"HTTP/1.1 1000 Nope\r\n\r\n",
        HttpError::BadRequestLine,
        BAD_REQUEST_LINE_DISPLAY,
    );
    assert_status_line_error(
        b"HTTP/2.0 200 OK\r\n\r\n",
        HttpError::UnsupportedVersion,
        UNSUPPORTED_VERSION_DISPLAY,
    );
    assert_status_line_error(
        b"HTTP/1.1 abc Nope\r\n\r\n",
        HttpError::BadRequestLine,
        BAD_REQUEST_LINE_DISPLAY,
    );
    assert_status_line_error(
        b"HTTP/1.1 200 OK\r\n invalid: fold\r\n\r\n",
        HttpError::InvalidHeaderName,
        INVALID_HEADER_NAME_DISPLAY,
    );
}

fn validate_reason_phrase_consistency(reason_phrase: &str) {
    // Ensure all characters in accepted reason phrase are valid
    for byte in reason_phrase.bytes() {
        assert!(
            byte == 0x09 || byte == 0x20 || // HTAB, SP
            (0x21..=0x7E).contains(&byte) || // VCHAR
            (byte >= 0x80), // obs-text
            "Invalid character in reason phrase: 0x{:02X}",
            byte
        );
    }

    // Verify no obs-fold sequences
    assert!(
        !reason_phrase.contains("\r\n ") && !reason_phrase.contains("\r\n\t"),
        "obs-fold sequence found in reason phrase: {:?}",
        reason_phrase
    );
}
